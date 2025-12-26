//! # passt Integration for MicroVM Networking
//!
//! Provides TCP/UDP/ICMP networking and control protocol for MicroVMs.
//!
//! ## Overview
//!
//! passt (Plug A Simple Socket Transport) is a userspace networking
//! backend that provides full TCP/UDP/ICMP connectivity for VMs.
//! Unlike libkrun's built-in TSI (which only supports TCP), passt
//! enables UDP-based protocols like Korium.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Host                                                           │
//! │  ┌─────────────────────┐    ┌─────────────────────┐             │
//! │  │  MicroVmPodRuntime  │    │  passt              │             │
//! │  │  - spawn_passt()    │───▶│  - TCP forwarding   │             │
//! │  │  - exec/logs via    │    │  - UDP forwarding   │             │
//! │  │    PasstInstance    │    │  - ICMP (ping)      │             │
//! │  └──────────┬──────────┘    └──────────┬──────────┘             │
//! │             │ krun_add_net_unixstream   │                       │
//! │             ▼                           │                       │
//! │  ┌──────────────────────────────────────▼──────────────────┐    │
//! │  │  MicroVM (libkrun)                                      │    │
//! │  │  ┌──────────────────────────────────────────────────┐   │    │
//! │  │  │  vminit (PID 1)                                  │   │    │
//! │  │  │  - Spawns containers from /containers/*/         │   │    │
//! │  │  │  - Listens on TCP :1024 for control              │   │    │
//! │  │  │  - Handles: exec, logs, ping                     │   │    │
//! │  │  │  - Reaps zombies, forwards signals               │   │    │
//! │  │  └──────────────────────────────────────────────────┘   │    │
//! │  │                                                         │    │
//! │  │  virtio-net device (eth0) - TCP/UDP/ICMP transparent    │    │
//! │  └─────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Port Mapping
//!
//! passt supports port mapping via command-line arguments:
//!
//! | Type | Argument | Example |
//! |------|----------|---------|
//! | TCP  | `-t`     | `-t 8080:80` (host 8080 → guest 80) |
//! | UDP  | `-u`     | `-u 51820:51820` (WireGuard) |
//!
//! ## Control Protocol
//!
//! JSON-over-TCP for exec/logs/ping:
//!
//! ```json
//! // Request
//! {"action":"exec","container":"nginx","command":["sh"]}\n
//!
//! // Response (success)
//! {"status":"ok","data":{"type":"exec_session","session_id":"abc"}}\n
//! ```
//!
//! ## Security Considerations
//!
//! - passt runs unprivileged (no root needed)
//! - Network namespace isolation via VM boundary
//! - Port mappings are explicit (no promiscuous forwarding)
//! - Container names validated (max 63 chars, alphanumeric only)
//! - Command arguments bounded in size and count

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::constants::CONTAINER_START_TIMEOUT;

// =============================================================================
// Constants
// =============================================================================

/// Default control channel port inside guest (vminit listens here).
pub const CONTROL_PORT: u16 = 1024;

/// passt socket path prefix.
const PASST_SOCKET_PREFIX: &str = "/tmp/magikrun-passt-";

/// Default timeout for control requests (30 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum container name length.
pub const MAX_CONTAINER_NAME_LEN: usize = 63;

/// Maximum command argument length.
pub const MAX_COMMAND_ARG_LEN: usize = 4096;

/// Maximum number of command arguments.
pub const MAX_COMMAND_ARGS: usize = 256;

/// Maximum tail lines for logs.
pub const MAX_TAIL_LINES: u32 = 100_000;

// =============================================================================
// Exec/Logs Result Types
// =============================================================================

/// Result of executing a command in a container.
#[derive(Debug, Clone)]
pub struct ControlExecResult {
    /// Exit code from the command.
    pub exit_code: i32,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

/// Result of requesting logs from a container.
#[derive(Debug, Clone)]
pub struct ControlLogsResult {
    /// Log lines.
    pub lines: Vec<String>,
}

// =============================================================================
// PasstConfig
// =============================================================================

/// Configuration for a passt instance.
#[derive(Debug, Clone)]
pub struct PasstConfig {
    /// TCP port mappings (host:guest).
    pub tcp_ports: Vec<(u16, u16)>,
    /// UDP port mappings (host:guest).
    pub udp_ports: Vec<(u16, u16)>,
    /// Socket path for libkrun connection.
    pub socket_path: String,
}

impl PasstConfig {
    /// Creates a new passt config with a control channel.
    ///
    /// # Arguments
    /// * `id` - Container ID for unique socket path
    /// * `control_host_port` - Host port for control channel
    #[must_use]
    pub fn new(id: &str, control_host_port: u16) -> Self {
        Self {
            tcp_ports: vec![(control_host_port, CONTROL_PORT)],
            udp_ports: Vec::new(),
            socket_path: format!("{PASST_SOCKET_PREFIX}{id}.sock"),
        }
    }

    /// Adds a TCP port mapping.
    #[must_use]
    pub fn with_tcp_port(mut self, host_port: u16, guest_port: u16) -> Self {
        self.tcp_ports.push((host_port, guest_port));
        self
    }

    /// Adds a UDP port mapping.
    #[must_use]
    pub fn with_udp_port(mut self, host_port: u16, guest_port: u16) -> Self {
        self.udp_ports.push((host_port, guest_port));
        self
    }
}

// =============================================================================
// PasstInstance
// =============================================================================

/// A running passt instance with control channel.
pub struct PasstInstance {
    /// passt child process.
    child: Child,
    /// Socket path.
    socket_path: String,
    /// Connected socket fd for libkrun.
    /// Wrapped in Option to track lifecycle and prevent double-close.
    /// Set to None after close() to ensure the fd is only closed once.
    socket_fd: Option<RawFd>,
    /// Host port for control channel.
    control_port: u16,
    /// Request timeout.
    timeout: Duration,
}

impl PasstInstance {
    /// Spawns a new passt instance.
    ///
    /// # Arguments
    /// * `config` - passt configuration
    ///
    /// # Errors
    /// Returns error if passt cannot be spawned or socket cannot be connected.
    pub fn spawn(config: &PasstConfig) -> io::Result<Self> {
        // Clean up old socket if exists
        let _ = std::fs::remove_file(&config.socket_path);

        // Build passt command
        let mut cmd = Command::new("passt");

        // Use socket mode for libkrun
        cmd.arg("--socket").arg(&config.socket_path);

        // Background mode
        cmd.arg("--foreground");

        // Add TCP port mappings
        for (host, guest) in &config.tcp_ports {
            cmd.arg("-t").arg(format!("{host}:{guest}"));
        }

        // Add UDP port mappings
        for (host, guest) in &config.udp_ports {
            cmd.arg("-u").arg(format!("{host}:{guest}"));
        }

        // Suppress output
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        // Spawn passt
        let child = cmd.spawn().map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to spawn passt: {e} (is passt installed?)"),
            )
        })?;

        // Wait for socket to appear
        let socket_path = Path::new(&config.socket_path);
        let deadline = std::time::Instant::now() + CONTAINER_START_TIMEOUT;

        while !socket_path.exists() {
            if std::time::Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "passt socket did not appear",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Connect to passt socket
        let socket = UnixStream::connect(&config.socket_path)?;
        let socket_fd = socket.as_raw_fd();

        // Prevent socket from being closed when UnixStream drops
        std::mem::forget(socket);

        let control_port = config
            .tcp_ports
            .first()
            .map(|(host, _)| *host)
            .unwrap_or(0);

        Ok(Self {
            child,
            socket_path: config.socket_path.clone(),
            socket_fd: Some(socket_fd),
            control_port,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Returns the socket fd for libkrun.
    ///
    /// Pass this to `krun_add_net_unixstream`.
    ///
    /// # Returns
    /// The raw fd if still open, or -1 if already closed.
    #[must_use]
    pub fn socket_fd(&self) -> RawFd {
        self.socket_fd.unwrap_or(-1)
    }

    /// Returns the host port for the control channel.
    #[must_use]
    pub fn control_port(&self) -> u16 {
        self.control_port
    }

    /// Returns the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Sets the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Stops the passt instance.
    ///
    /// Safe to call multiple times - the socket fd is only closed once.
    pub fn stop(&mut self) -> io::Result<()> {
        // Close the socket fd only if not already closed
        if let Some(fd) = self.socket_fd.take() {
            // SAFETY: fd is a valid file descriptor from UnixStream::connect.
            // We called mem::forget on the UnixStream, so we own this fd.
            // The Option::take() ensures we only close it once, preventing
            // double-close bugs that could affect unrelated file descriptors.
            unsafe {
                libc::close(fd);
            }
        }

        // Kill passt (ignore error if already dead)
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Clean up socket
        let _ = std::fs::remove_file(&self.socket_path);

        Ok(())
    }

    // =========================================================================
    // Control Protocol Operations
    // =========================================================================

    /// Executes a command in a container.
    ///
    /// Returns the execution result with exit code, stdout, and stderr.
    ///
    /// # Arguments
    ///
    /// * `container` - Container name (e.g., "infra", "app-nginx")
    /// * `command` - Command to execute
    /// * `tty` - Whether to allocate a TTY
    ///
    /// # Errors
    ///
    /// Returns error if container not found or connection fails.
    pub async fn exec(
        &self,
        container: &str,
        command: Vec<String>,
        tty: bool,
    ) -> Result<ControlExecResult, ControlError> {
        validate_container_name(container)?;
        validate_command(&command)?;

        let request = Request::Exec(ExecRequest {
            container: container.to_string(),
            command,
            stdin: true,
            stdout: true,
            stderr: true,
            tty,
        });

        let response = self.send_request(&request).await?;

        match response {
            Response::Ok(payload) => match payload.data {
                Some(ResponseData::ExecOutput {
                    exit_code,
                    stdout,
                    stderr,
                }) => Ok(ControlExecResult {
                    exit_code,
                    stdout,
                    stderr,
                }),
                Some(ResponseData::ExecSession { session_id }) => {
                    // Streaming exec session - return as a pseudo-result
                    Ok(ControlExecResult {
                        exit_code: 0,
                        stdout: format!("session_id: {session_id}"),
                        stderr: String::new(),
                    })
                }
                other => Err(ControlError::UnexpectedResponse {
                    expected: "ExecOutput or ExecSession".to_string(),
                    got: format!("{other:?}"),
                }),
            },
            Response::Error(e) => Err(ControlError::VminitError {
                code: e.code,
                message: e.message,
            }),
        }
    }

    /// Requests logs from a container.
    ///
    /// Returns the log lines from the container.
    ///
    /// # Arguments
    ///
    /// * `container` - Container name
    /// * `follow` - Whether to stream logs (currently not supported, ignored)
    /// * `tail` - Number of lines from tail (0 = all)
    ///
    /// # Errors
    ///
    /// Returns error if container not found or connection fails.
    pub async fn logs(
        &self,
        container: &str,
        follow: bool,
        tail: u32,
    ) -> Result<ControlLogsResult, ControlError> {
        validate_container_name(container)?;

        let request = Request::Logs(LogsRequest {
            container: container.to_string(),
            follow,
            tail_lines: tail,
            timestamps: false,
        });

        let response = self.send_request(&request).await?;

        match response {
            Response::Ok(payload) => match payload.data {
                Some(ResponseData::LogOutput { lines }) => Ok(ControlLogsResult { lines }),
                None => Ok(ControlLogsResult { lines: Vec::new() }),
                other => Err(ControlError::UnexpectedResponse {
                    expected: "LogOutput".to_string(),
                    got: format!("{other:?}"),
                }),
            },
            Response::Error(e) => Err(ControlError::VminitError {
                code: e.code,
                message: e.message,
            }),
        }
    }

    /// Pings vminit to check availability.
    ///
    /// Returns the vminit version and container count on success.
    ///
    /// # Errors
    ///
    /// Returns error if connection fails or vminit returns an error.
    pub async fn ping(&self) -> Result<(String, usize), ControlError> {
        let response = self.send_request(&Request::Ping).await?;

        match response {
            Response::Ok(payload) => {
                if let Some(ResponseData::Pong {
                    version,
                    container_count,
                }) = payload.data
                {
                    Ok((version, container_count))
                } else {
                    Err(ControlError::UnexpectedResponse {
                        expected: "Pong".to_string(),
                        got: format!("{payload:?}"),
                    })
                }
            }
            Response::Error(e) => Err(ControlError::VminitError {
                code: e.code,
                message: e.message,
            }),
        }
    }

    /// Checks if vminit is reachable.
    ///
    /// This is a convenience method that calls `ping()` and returns
    /// `true` if successful, `false` otherwise.
    pub async fn is_available(&self) -> bool {
        self.ping().await.is_ok()
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /// Sends a request and receives a response.
    async fn send_request(&self, request: &Request) -> Result<Response, ControlError> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.control_port));

        // Connect to vminit via passt-mapped port
        let stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| ControlError::Timeout(self.timeout))?
            .map_err(|e| ControlError::ConnectionFailed { addr, source: e })?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send request
        let request_line = request.to_json_line()?;
        writer.write_all(request_line.as_bytes()).await?;
        writer.flush().await?;

        // Read response
        let mut response_line = String::new();
        timeout(self.timeout, reader.read_line(&mut response_line))
            .await
            .map_err(|_| ControlError::Timeout(self.timeout))??;

        let response = Response::from_json(&response_line)?;

        // Check for vminit error
        if let Response::Error(err) = &response {
            return Err(ControlError::VminitError {
                code: err.code,
                message: err.message.clone(),
            });
        }

        Ok(response)
    }
}

impl Drop for PasstInstance {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// =============================================================================
// ControlClient (Lightweight client for exec/logs without passt lifecycle)
// =============================================================================

/// Lightweight control client for exec/logs operations.
///
/// Use this when you have the control port but don't need to manage
/// the passt process lifecycle. For example, when the port is stored
/// in pod state and exec/logs are called later.
#[derive(Debug, Clone)]
pub struct ControlClient {
    /// Host address to connect to (passt maps this to guest).
    addr: SocketAddr,
    /// Request timeout.
    timeout: Duration,
}

impl ControlClient {
    /// Creates a new control client for the given host port.
    ///
    /// The port should be the host-side port mapped to guest :1024 via passt.
    #[must_use]
    pub fn new(host_port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], host_port)),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Sets the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Executes a command in a container.
    ///
    /// Returns the execution result with exit code, stdout, and stderr.
    pub async fn exec(
        &self,
        container: &str,
        command: Vec<String>,
        tty: bool,
    ) -> Result<ControlExecResult, ControlError> {
        validate_container_name(container)?;
        validate_command(&command)?;

        let request = Request::Exec(ExecRequest {
            container: container.to_string(),
            command,
            stdin: true,
            stdout: true,
            stderr: true,
            tty,
        });

        let response = self.send_request(&request).await?;

        match response {
            Response::Ok(payload) => match payload.data {
                Some(ResponseData::ExecOutput {
                    exit_code,
                    stdout,
                    stderr,
                }) => Ok(ControlExecResult {
                    exit_code,
                    stdout,
                    stderr,
                }),
                Some(ResponseData::ExecSession { session_id }) => {
                    // Streaming exec session - return as a pseudo-result
                    Ok(ControlExecResult {
                        exit_code: 0,
                        stdout: format!("session_id: {session_id}"),
                        stderr: String::new(),
                    })
                }
                other => Err(ControlError::UnexpectedResponse {
                    expected: "ExecOutput or ExecSession".to_string(),
                    got: format!("{other:?}"),
                }),
            },
            Response::Error(e) => Err(ControlError::VminitError {
                code: e.code,
                message: e.message,
            }),
        }
    }

    /// Requests logs from a container.
    ///
    /// Returns the log lines from the container.
    pub async fn logs(
        &self,
        container: &str,
        follow: bool,
        tail: u32,
    ) -> Result<ControlLogsResult, ControlError> {
        validate_container_name(container)?;

        let request = Request::Logs(LogsRequest {
            container: container.to_string(),
            follow,
            tail_lines: tail,
            timestamps: false,
        });

        let response = self.send_request(&request).await?;

        match response {
            Response::Ok(payload) => match payload.data {
                Some(ResponseData::LogOutput { lines }) => Ok(ControlLogsResult { lines }),
                None => Ok(ControlLogsResult { lines: Vec::new() }),
                other => Err(ControlError::UnexpectedResponse {
                    expected: "LogOutput".to_string(),
                    got: format!("{other:?}"),
                }),
            },
            Response::Error(e) => Err(ControlError::VminitError {
                code: e.code,
                message: e.message,
            }),
        }
    }

    /// Pings vminit to check availability.
    pub async fn ping(&self) -> Result<(String, usize), ControlError> {
        let response = self.send_request(&Request::Ping).await?;

        match response {
            Response::Ok(payload) => {
                if let Some(ResponseData::Pong {
                    version,
                    container_count,
                }) = payload.data
                {
                    Ok((version, container_count))
                } else {
                    Err(ControlError::UnexpectedResponse {
                        expected: "Pong".to_string(),
                        got: format!("{payload:?}"),
                    })
                }
            }
            Response::Error(e) => Err(ControlError::VminitError {
                code: e.code,
                message: e.message,
            }),
        }
    }

    /// Sends a request and receives a response.
    async fn send_request(&self, request: &Request) -> Result<Response, ControlError> {
        // Connect to vminit via passt-mapped port
        let stream = timeout(self.timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| ControlError::Timeout(self.timeout))?
            .map_err(|e| ControlError::ConnectionFailed {
                addr: self.addr,
                source: e,
            })?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send request
        let request_line = request.to_json_line()?;
        writer.write_all(request_line.as_bytes()).await?;
        writer.flush().await?;

        // Read response
        let mut response_line = String::new();
        timeout(self.timeout, reader.read_line(&mut response_line))
            .await
            .map_err(|_| ControlError::Timeout(self.timeout))??;

        let response = Response::from_json(&response_line)?;

        // Check for vminit error
        if let Response::Error(err) = &response {
            return Err(ControlError::VminitError {
                code: err.code,
                message: err.message.clone(),
            });
        }

        Ok(response)
    }
}

// =============================================================================
// Validation Helpers (shared by PasstInstance and ControlClient)
// =============================================================================

/// Validates a container name for safety.
///
/// SECURITY: Defense-in-depth validation - even though vminit also validates,
/// we reject invalid names early to prevent any potential parsing issues.
fn validate_container_name(name: &str) -> Result<(), ControlError> {
    if name.is_empty() {
        return Err(ControlError::InvalidInput(
            "container name cannot be empty".into(),
        ));
    }
    if name.len() > MAX_CONTAINER_NAME_LEN {
        return Err(ControlError::InvalidInput(format!(
            "container name exceeds {MAX_CONTAINER_NAME_LEN} bytes"
        )));
    }
    // SECURITY: Only allow safe characters (alphanumeric, hyphen, underscore)
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ControlError::InvalidInput(
            "container name contains invalid characters (allowed: a-z, A-Z, 0-9, -, _)".into(),
        ));
    }
    // Reject names starting or ending with hyphen
    if name.starts_with('-') || name.ends_with('-') {
        return Err(ControlError::InvalidInput(
            "container name cannot start or end with hyphen".into(),
        ));
    }
    Ok(())
}

/// Validates exec command arguments for safety.
///
/// SECURITY: Prevents memory exhaustion from oversized commands.
fn validate_command(command: &[String]) -> Result<(), ControlError> {
    if command.is_empty() {
        return Err(ControlError::InvalidInput("command cannot be empty".into()));
    }
    if command.len() > MAX_COMMAND_ARGS {
        return Err(ControlError::InvalidInput(format!(
            "too many command arguments ({} > {})",
            command.len(),
            MAX_COMMAND_ARGS
        )));
    }
    for (i, arg) in command.iter().enumerate() {
        if arg.len() > MAX_COMMAND_ARG_LEN {
            return Err(ControlError::InvalidInput(format!(
                "command argument {i} exceeds {MAX_COMMAND_ARG_LEN} bytes"
            )));
        }
    }
    Ok(())
}

// =============================================================================
// Control Protocol Error
// =============================================================================

/// Control protocol error.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Connection failed.
    #[error("failed to connect to vminit at {addr}: {source}")]
    ConnectionFailed {
        /// Target address.
        addr: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Request timeout.
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// vminit returned an error.
    #[error("vminit error ({code:?}): {message}")]
    VminitError {
        /// Error code from vminit.
        code: ErrorCode,
        /// Error message from vminit.
        message: String,
    },

    /// Unexpected response.
    #[error("unexpected response: expected {expected}, got {got}")]
    UnexpectedResponse {
        /// Expected response type.
        expected: String,
        /// Actual response type.
        got: String,
    },

    /// Invalid input.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// =============================================================================
// Control Protocol Types
// =============================================================================

/// Request from host to guest vminit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    /// Execute a command in a container.
    Exec(ExecRequest),

    /// Stream logs from a container.
    Logs(LogsRequest),

    /// Ping to check vminit health.
    Ping,
}

/// Execute a command in a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Container name (e.g., "infra", "app-nginx").
    pub container: String,
    /// Command to execute.
    pub command: Vec<String>,
    /// Attach stdin.
    pub stdin: bool,
    /// Attach stdout.
    pub stdout: bool,
    /// Attach stderr.
    pub stderr: bool,
    /// Allocate TTY.
    pub tty: bool,
}

/// Request container logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsRequest {
    /// Container name.
    pub container: String,
    /// Follow logs (stream).
    pub follow: bool,
    /// Number of lines from tail (0 = all).
    pub tail_lines: u32,
    /// Include timestamps.
    pub timestamps: bool,
}

/// Response from guest vminit to host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Success response.
    Ok(OkPayload),
    /// Error response.
    Error(ErrorPayload),
}

impl Response {
    /// Creates a success response with no data.
    #[must_use]
    pub fn ok() -> Self {
        Self::Ok(OkPayload { data: None })
    }

    /// Creates a success response with data.
    #[must_use]
    pub fn ok_with_data(data: ResponseData) -> Self {
        Self::Ok(OkPayload { data: Some(data) })
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error(ErrorPayload {
            code,
            message: message.into(),
        })
    }

    /// Returns true if this is a success response.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

/// Success payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkPayload {
    /// Optional response data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ResponseData>,
}

/// Response data variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseData {
    /// Pong response.
    Pong {
        /// vminit version string.
        version: String,
        /// Number of running containers.
        container_count: usize,
    },

    /// Exec session ID (for streaming exec - future use).
    ExecSession {
        /// Session identifier for subsequent requests.
        session_id: String,
    },

    /// Exec output (for simple exec).
    ExecOutput {
        /// Exit code from command.
        exit_code: i32,
        /// Captured stdout.
        stdout: String,
        /// Captured stderr.
        stderr: String,
    },

    /// Log output.
    LogOutput {
        /// Log lines.
        lines: Vec<String>,
    },

    /// Log line (for streaming logs - future use).
    LogLine {
        /// Optional timestamp.
        timestamp: Option<String>,
        /// Log content.
        line: String,
    },
}

/// Error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Error code.
    pub code: ErrorCode,
    /// Human-readable message.
    pub message: String,
}

/// Error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Container not found.
    ContainerNotFound,
    /// Container not running.
    ContainerNotRunning,
    /// Exec failed.
    ExecFailed,
    /// Internal vminit error.
    Internal,
    /// Request timeout.
    Timeout,
    /// Invalid request format.
    InvalidRequest,
}

// =============================================================================
// Wire Format Helpers
// =============================================================================

impl Request {
    /// Serializes request to JSON line (with newline).
    ///
    /// # Errors
    ///
    /// Returns error if JSON serialization fails.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Deserializes request from JSON.
    ///
    /// # Errors
    ///
    /// Returns error if JSON deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s.trim())
    }
}

impl Response {
    /// Serializes response to JSON line (with newline).
    ///
    /// # Errors
    ///
    /// Returns error if JSON serialization fails.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Deserializes response from JSON.
    ///
    /// # Errors
    ///
    /// Returns error if JSON deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s.trim())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passt_config_new() {
        let config = PasstConfig::new("test-container", 8080);
        assert_eq!(config.tcp_ports, vec![(8080, CONTROL_PORT)]);
        assert!(config.udp_ports.is_empty());
        assert!(config.socket_path.contains("test-container"));
    }

    #[test]
    fn test_passt_config_builder() {
        let config = PasstConfig::new("test", 8080)
            .with_tcp_port(8443, 443)
            .with_udp_port(51820, 51820);

        assert_eq!(config.tcp_ports.len(), 2);
        assert_eq!(config.udp_ports.len(), 1);
    }

    #[test]
    fn test_response_serialization() {
        let resp = Response::ok();
        let json = resp.to_json_line().unwrap();
        assert!(json.contains("\"status\":\"ok\""));

        let resp = Response::error(ErrorCode::ContainerNotFound, "container 'foo' not found");
        let json = resp.to_json_line().unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("\"code\":\"container_not_found\""));
    }

    #[test]
    fn test_ping_request() {
        let req = Request::Ping;
        let json = req.to_json_line().unwrap();
        assert!(json.contains("\"action\":\"ping\""));

        let parsed = Request::from_json(&json).unwrap();
        assert!(matches!(parsed, Request::Ping));
    }

    #[test]
    fn test_exec_request() {
        let req = Request::Exec(ExecRequest {
            container: "nginx".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "ls".to_string()],
            stdin: true,
            stdout: true,
            stderr: true,
            tty: true,
        });
        let json = req.to_json_line().unwrap();
        assert!(json.contains("\"action\":\"exec\""));
        assert!(json.contains("\"container\":\"nginx\""));
    }

    #[test]
    fn test_logs_request() {
        let req = Request::Logs(LogsRequest {
            container: "app".to_string(),
            follow: true,
            tail_lines: 100,
            timestamps: false,
        });
        let json = req.to_json_line().unwrap();
        assert!(json.contains("\"action\":\"logs\""));
        assert!(json.contains("\"container\":\"app\""));
        assert!(json.contains("\"follow\":true"));
    }

    #[test]
    fn test_pong_response() {
        let resp = Response::ok_with_data(ResponseData::Pong {
            version: "0.2.3".to_string(),
            container_count: 2,
        });
        let json = resp.to_json_line().unwrap();
        assert!(json.contains("\"type\":\"pong\""));
        assert!(json.contains("\"version\":\"0.2.3\""));
        assert!(json.contains("\"container_count\":2"));
    }
}
