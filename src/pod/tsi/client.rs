//! TSI client for host-side communication with guest vminit.
//!
//! This module provides an async client for sending Day-2 commands to
//! vminit running inside a MicroVM via vsock.
//!
//! # Features
//!
//! - Async/await support via tokio
//! - Automatic connection management
//! - Timeout handling for all operations
//! - Container exec and logs operations
//!
//! # Example
//!
//! ```rust,ignore
//! use magikrun::tsi::TsiClient;
//! use std::time::Duration;
//!
//! let client = TsiClient::new(3)
//!     .with_port(1024)
//!     .with_timeout(Duration::from_secs(60));
//!
//! // Ping to verify vminit is running
//! let (version, count) = client.ping().await?;
//! println!("vminit {}, {} containers running", version, count);
//!
//! // Execute command in container
//! let session_id = client.exec("nginx", vec!["sh".into()], true).await?;
//! ```

use super::protocol::{
    ExecRequest, LogsRequest, MAX_COMMAND_ARG_LEN, MAX_COMMAND_ARGS, MAX_CONTAINER_NAME_LEN,
    Request, Response, ResponseData,
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tokio_vsock::{VsockAddr, VsockStream};

/// Default vsock port for vminit.
pub const DEFAULT_VSOCK_PORT: u32 = 1024;

/// Default timeout for TSI requests (30 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// TSI client error.
#[derive(Debug, thiserror::Error)]
pub enum TsiError {
    /// Connection failed.
    #[error("failed to connect to vminit at CID {cid}:{port}: {source}")]
    ConnectionFailed {
        /// Guest CID.
        cid: u32,
        /// Port number.
        port: u32,
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
        code: super::protocol::ErrorCode,
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

    /// vminit not available.
    #[error("vminit not available")]
    NotAvailable,

    /// Invalid input.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Result type for TSI operations.
pub type TsiResult<T> = Result<T, TsiError>;

/// TSI client for communicating with MicroVM vminit.
///
/// The client uses vsock (AF_VSOCK) to communicate with vminit
/// running inside the VM. Each request creates a new connection,
/// sends the request, receives the response, and closes the connection.
#[derive(Debug, Clone)]
pub struct TsiClient {
    /// Guest CID (Context ID).
    cid: u32,
    /// Port number.
    port: u32,
    /// Request timeout.
    timeout: Duration,
}

impl TsiClient {
    /// Creates a new TSI client for the given CID.
    ///
    /// Uses default port (1024) and timeout (30 seconds).
    #[must_use]
    pub fn new(cid: u32) -> Self {
        Self {
            cid,
            port: DEFAULT_VSOCK_PORT,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Sets the port number.
    #[must_use]
    pub fn with_port(mut self, port: u32) -> Self {
        self.port = port;
        self
    }

    /// Sets the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the CID.
    #[must_use]
    pub fn cid(&self) -> u32 {
        self.cid
    }

    /// Returns the port.
    #[must_use]
    pub fn port(&self) -> u32 {
        self.port
    }

    /// Sends a request and receives a response.
    async fn send_request(&self, request: &Request) -> TsiResult<Response> {
        // Connect to vminit
        let addr = VsockAddr::new(self.cid, self.port);
        let stream = timeout(self.timeout, VsockStream::connect(addr))
            .await
            .map_err(|_| TsiError::Timeout(self.timeout))?
            .map_err(|e| TsiError::ConnectionFailed {
                cid: self.cid,
                port: self.port,
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
            .map_err(|_| TsiError::Timeout(self.timeout))??;

        let response = Response::from_json(&response_line)?;

        // Check for vminit error
        if let Response::Error(err) = &response {
            return Err(TsiError::VminitError {
                code: err.code,
                message: err.message.clone(),
            });
        }

        Ok(response)
    }

    // =========================================================================
    // Day-2 Operations
    // =========================================================================

    /// Executes a command in a container.
    ///
    /// Returns a session ID for streaming I/O.
    ///
    /// # Arguments
    ///
    /// * `container` - Container name (e.g., "infra", "app-nginx")
    /// * `command` - Command to execute
    /// * `tty` - Whether to allocate a TTY
    ///
    /// # Errors
    ///
    /// Returns error if container not found.
    pub async fn exec(
        &self,
        container: &str,
        command: Vec<String>,
        tty: bool,
    ) -> TsiResult<String> {
        self.validate_container_name(container)?;
        self.validate_command(&command)?;

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
            Response::Ok(payload) => {
                if let Some(ResponseData::ExecSession { session_id }) = payload.data {
                    Ok(session_id)
                } else {
                    Err(TsiError::UnexpectedResponse {
                        expected: "ExecSession".to_string(),
                        got: format!("{payload:?}"),
                    })
                }
            }
            Response::Error(e) => Err(TsiError::VminitError {
                code: e.code,
                message: e.message,
            }),
        }
    }

    /// Requests logs from a container.
    ///
    /// # Arguments
    ///
    /// * `container` - Container name
    /// * `follow` - Whether to stream logs
    /// * `tail` - Number of lines from tail (0 = all)
    ///
    /// # Errors
    ///
    /// Returns error if container not found.
    pub async fn logs(&self, container: &str, follow: bool, tail: u32) -> TsiResult<()> {
        self.validate_container_name(container)?;

        let request = Request::Logs(LogsRequest {
            container: container.to_string(),
            follow,
            tail_lines: tail,
            timestamps: false,
        });

        self.send_request(&request).await?;
        Ok(())
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /// Pings vminit to check availability.
    ///
    /// Returns the vminit version and container count on success.
    ///
    /// # Errors
    ///
    /// Returns error if connection fails or vminit returns an error.
    pub async fn ping(&self) -> TsiResult<(String, usize)> {
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
                    Err(TsiError::UnexpectedResponse {
                        expected: "Pong".to_string(),
                        got: format!("{payload:?}"),
                    })
                }
            }
            Response::Error(e) => Err(TsiError::VminitError {
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
    // Validation Helpers
    // =========================================================================

    /// Validates a container name for safety.
    ///
    /// SECURITY: Defense-in-depth validation - even though vminit also validates,
    /// we reject invalid names early to prevent any potential parsing issues.
    fn validate_container_name(&self, name: &str) -> TsiResult<()> {
        if name.is_empty() {
            return Err(TsiError::InvalidInput(
                "container name cannot be empty".into(),
            ));
        }
        if name.len() > MAX_CONTAINER_NAME_LEN {
            return Err(TsiError::InvalidInput(format!(
                "container name exceeds {MAX_CONTAINER_NAME_LEN} bytes"
            )));
        }
        // SECURITY: Only allow safe characters (alphanumeric, hyphen, underscore)
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(TsiError::InvalidInput(
                "container name contains invalid characters (allowed: a-z, A-Z, 0-9, -, _)".into(),
            ));
        }
        // Reject names starting or ending with hyphen
        if name.starts_with('-') || name.ends_with('-') {
            return Err(TsiError::InvalidInput(
                "container name cannot start or end with hyphen".into(),
            ));
        }
        Ok(())
    }

    /// Validates exec command arguments for safety.
    ///
    /// SECURITY: Prevents memory exhaustion from oversized commands.
    fn validate_command(&self, command: &[String]) -> TsiResult<()> {
        if command.is_empty() {
            return Err(TsiError::InvalidInput("command cannot be empty".into()));
        }
        if command.len() > MAX_COMMAND_ARGS {
            return Err(TsiError::InvalidInput(format!(
                "too many command arguments ({} > {})",
                command.len(),
                MAX_COMMAND_ARGS
            )));
        }
        for (i, arg) in command.iter().enumerate() {
            if arg.len() > MAX_COMMAND_ARG_LEN {
                return Err(TsiError::InvalidInput(format!(
                    "command argument {} exceeds {} bytes",
                    i, MAX_COMMAND_ARG_LEN
                )));
            }
        }
        Ok(())
    }
}
