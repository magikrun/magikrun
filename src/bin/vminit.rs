//! # vminit - Minimal MicroVM Init Process
//!
//! This binary runs as PID 1 inside MicroVMs. It is intentionally minimal:
//!
//! - **Zombie reaping**: Collects orphaned child processes
//! - **Signal forwarding**: Forwards SIGTERM/SIGINT to children
//! - **Control server**: Handles exec/logs requests from host via TCP
//! - **Container spawning**: Reads baked pod spec and spawns containers
//!
//! ## NOT the infra-container
//!
//! vminit is NOT the infra-container. It's the VM equivalent of systemd/kubelet.
//! The infra-container (with workplane extensions) runs as a regular container
//! inside the pod that vminit spawns.
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │ VM                                                             │
//! │  vminit (PID 1)                                                │
//! │  ├─► zombie reap                                               │
//! │  ├─► signal forward                                            │
//! │  ├─► control server (TCP :1024, exec/logs)                     │
//! │  │                                                             │
//! │  └─► reads /pod/spec.json, spawns:                             │
//! │       ┌──────────────────────────────────────────────────────┐ │
//! │       │ Pod                                                  │ │
//! │       │  ┌────────────────────┐  ┌────────────────────┐      │ │
//! │       │  │ infra-container    │  │ app-container      │      │ │
//! │       │  │ (workplane binary) │  │ (user workload)    │      │ │
//! │       │  └────────────────────┘  └────────────────────┘      │ │
//! │       └──────────────────────────────────────────────────────┘ │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Bundle Layout
//!
//! The VM rootfs is prepared by the host with:
//! ```text
//! /
//! ├── init                    ← symlink to vminit
//! ├── pod/
//! │   └── spec.json           ← baked pod spec
//! ├── containers/
//! │   ├── infra/
//! │   │   ├── rootfs/         ← infra container filesystem
//! │   │   └── config.json     ← OCI runtime config
//! │   └── app-nginx/
//! │       ├── rootfs/         ← app container filesystem
//! │       └── config.json     ← OCI runtime config
//! └── usr/bin/
//!     └── vminit              ← this binary
//! ```
//!
//! ## Building
//!
//! ```bash
//! cargo build --release --bin vminit --target x86_64-unknown-linux-musl
//! ```

// =============================================================================
// Non-Linux Stub
// =============================================================================

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vminit is only available on Linux");
    eprintln!("Build with: cargo build --target x86_64-unknown-linux-musl");
    std::process::exit(1);
}

// =============================================================================
// Linux Implementation
// =============================================================================

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::path::Path;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::RwLock;
    use tracing::{Level, debug, error, info, warn};
    use tracing_subscriber::FmtSubscriber;

    // =========================================================================
    // Constants
    // =========================================================================

    /// Path to baked pod spec.
    const POD_SPEC_PATH: &str = "/pod/spec.json";

    /// Base path for container bundles.
    const CONTAINERS_PATH: &str = "/containers";

    /// Control server port (passt maps host port to this).
    const CONTROL_PORT: u16 = 1024;

    /// Grace period for SIGTERM before SIGKILL (seconds).
    const SHUTDOWN_GRACE_PERIOD_SECS: u64 = 30;

    /// Exit codes.
    const EXIT_SUCCESS: u8 = 0;
    const EXIT_INIT_FAILED: u8 = 1;
    const EXIT_SPAWN_FAILED: u8 = 2;

    // -------------------------------------------------------------------------
    // Control Protocol Constants (security bounds)
    // -------------------------------------------------------------------------

    /// Maximum container name length.
    const MAX_CONTAINER_NAME_LEN: usize = 63;

    /// Maximum command argument length.
    const MAX_COMMAND_ARG_LEN: usize = 4096;

    /// Maximum number of command arguments.
    const MAX_COMMAND_ARGS: usize = 256;

    /// Maximum tail lines for logs.
    const MAX_TAIL_LINES: u32 = 100_000;

    /// Maximum concurrent control connections.
    const MAX_CONNECTIONS: usize = 16;

    /// Request timeout (seconds).
    const REQUEST_TIMEOUT_SECS: u64 = 30;

    /// Maximum request line length (bytes).
    const MAX_REQUEST_LINE_LEN: usize = 65536;

    /// Exec timeout (seconds).
    const EXEC_TIMEOUT_SECS: u64 = 300;

    /// Container state root path.
    const CONTAINER_STATE_ROOT: &str = "/run/containers";

    /// Container log file name (relative to bundle).
    const CONTAINER_LOG_FILE: &str = "container.log";

    // =========================================================================
    // Control Protocol Types (compatible with passt.rs)
    // =========================================================================

    /// Request from host to vminit.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(tag = "action", rename_all = "snake_case")]
    enum Request {
        /// Ping to check health.
        Ping,
        /// Execute command in container.
        Exec(ExecRequest),
        /// Stream logs from container.
        Logs(LogsRequest),
    }

    /// Execute command request.
    #[derive(Debug, Clone, Deserialize)]
    struct ExecRequest {
        /// Container name.
        container: String,
        /// Command to execute.
        command: Vec<String>,
        /// Attach stdin.
        #[serde(default)]
        stdin: bool,
        /// Attach stdout.
        #[serde(default = "default_true")]
        stdout: bool,
        /// Attach stderr.
        #[serde(default = "default_true")]
        stderr: bool,
        /// Allocate TTY.
        #[serde(default)]
        tty: bool,
    }

    fn default_true() -> bool {
        true
    }

    /// Logs request.
    #[derive(Debug, Clone, Deserialize)]
    struct LogsRequest {
        /// Container name.
        container: String,
        /// Follow logs (stream).
        #[serde(default)]
        follow: bool,
        /// Number of lines from tail (0 = all).
        #[serde(default)]
        tail_lines: u32,
        /// Include timestamps.
        #[serde(default)]
        timestamps: bool,
    }

    /// Response from vminit to host.
    #[derive(Debug, Clone, Serialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum Response {
        /// Success response.
        Ok {
            /// Optional response data.
            #[serde(skip_serializing_if = "Option::is_none")]
            data: Option<ResponseData>,
        },
        /// Error response.
        Error {
            /// Error code.
            code: &'static str,
            /// Human-readable message.
            message: String,
        },
    }

    impl Response {
        /// Creates a success response with no data.
        fn ok() -> Self {
            Self::Ok { data: None }
        }

        /// Creates a success response with data.
        fn ok_with_data(data: ResponseData) -> Self {
            Self::Ok { data: Some(data) }
        }

        /// Creates an error response.
        fn error(code: &'static str, message: impl Into<String>) -> Self {
            Self::Error {
                code,
                message: message.into(),
            }
        }

        /// Serializes to JSON line with newline.
        fn to_json_line(&self) -> String {
            let mut json = serde_json::to_string(self).unwrap_or_else(|_| {
                r#"{"status":"error","code":"internal","message":"serialization failed"}"#
                    .to_string()
            });
            json.push('\n');
            json
        }
    }

    /// Response data variants.
    #[derive(Debug, Clone, Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum ResponseData {
        /// Pong response.
        Pong {
            /// vminit version.
            version: String,
            /// Number of running containers.
            container_count: usize,
        },
        /// Exec session created (for streaming exec - future use).
        ExecSession {
            /// Session ID for streaming.
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
            #[serde(skip_serializing_if = "Option::is_none")]
            timestamp: Option<String>,
            /// Log content.
            line: String,
        },
    }

    // =========================================================================
    // Container Info
    // =========================================================================

    /// Container process info.
    #[derive(Debug, Clone)]
    struct ContainerInfo {
        /// Container name.
        name: String,
        /// Process ID.
        pid: u32,
        /// Bundle path.
        bundle_path: String,
    }

    // =========================================================================
    // Main
    // =========================================================================

    #[tokio::main(flavor = "current_thread")]
    pub async fn main() -> ExitCode {
        // Initialize minimal tracing
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .with_target(false)
            .with_ansi(false)
            .compact()
            .finish();

        if tracing::subscriber::set_global_default(subscriber).is_err() {
            eprintln!("Failed to set tracing subscriber");
            return ExitCode::from(EXIT_INIT_FAILED);
        }

        info!(
            version = env!("CARGO_PKG_VERSION"),
            pid = std::process::id(),
            "vminit starting"
        );

        // Verify we're PID 1
        if std::process::id() != 1 {
            warn!(
                pid = std::process::id(),
                "vminit is not PID 1, zombie reaping may not work"
            );
        }

        // Spawn containers from baked spec
        let containers = match spawn_containers().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to spawn containers");
                return ExitCode::from(EXIT_SPAWN_FAILED);
            }
        };

        if containers.is_empty() {
            error!("no containers spawned");
            return ExitCode::from(EXIT_SPAWN_FAILED);
        }

        info!(count = containers.len(), "containers spawned");

        // Run main loop
        match run_init_loop(containers).await {
            Ok(exit_code) => ExitCode::from(exit_code),
            Err(e) => {
                error!(error = %e, "init loop failed");
                ExitCode::from(EXIT_INIT_FAILED)
            }
        }
    }

    // =========================================================================
    // Container Spawning
    // =========================================================================

    /// Spawns containers from baked pod spec.
    async fn spawn_containers() -> anyhow::Result<Vec<ContainerInfo>> {
        let containers_dir = Path::new(CONTAINERS_PATH);

        if !containers_dir.exists() {
            anyhow::bail!("containers directory not found: {}", CONTAINERS_PATH);
        }

        let mut processes = Vec::new();

        // Read container directories
        let mut entries: Vec<_> = std::fs::read_dir(containers_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        // Sort to ensure infra-container starts first (alphabetically "infra" < "app-*")
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let container_name = entry.file_name().to_string_lossy().to_string();
            let bundle_path = entry.path();
            let config_path = bundle_path.join("config.json");

            if !config_path.exists() {
                warn!(container = %container_name, "skipping, no config.json");
                continue;
            }

            info!(container = %container_name, bundle = %bundle_path.display(), "spawning container");

            match spawn_container(&container_name, &bundle_path).await {
                Ok(pid) => {
                    info!(container = %container_name, pid = pid, "container started");
                    processes.push(ContainerInfo {
                        name: container_name,
                        pid,
                        bundle_path: bundle_path.to_string_lossy().to_string(),
                    });
                }
                Err(e) => {
                    error!(container = %container_name, error = %e, "failed to spawn container");
                    // Continue with other containers - partial success is better than total failure
                }
            }
        }

        Ok(processes)
    }

    /// Spawns a single container using libcontainer.
    async fn spawn_container(name: &str, bundle_path: &Path) -> anyhow::Result<u32> {
        use libcontainer::container::builder::ContainerBuilder;
        use libcontainer::syscall::syscall::SyscallType;

        let container = ContainerBuilder::new(name.to_string(), SyscallType::default())
            .with_root_path(Path::new("/run/containers"))?
            .as_init(bundle_path)
            .build()?;

        // Start returns the init PID
        let pid = container
            .pid()
            .ok_or_else(|| anyhow::anyhow!("container started but no PID"))?;

        Ok(pid.as_raw() as u32)
    }

    // =========================================================================
    // Init Loop
    // =========================================================================

    /// Shared state for control server.
    struct ControlState {
        /// Container info by name.
        containers: HashMap<String, ContainerInfo>,
        /// Active connection count.
        active_connections: usize,
    }

    /// Main init loop - zombie reaping, signal handling, control server.
    async fn run_init_loop(containers: Vec<ContainerInfo>) -> anyhow::Result<u8> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::signal::unix::{SignalKind, signal};

        // Set up signal handlers
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigchld = signal(SignalKind::child())?;

        // Track container PIDs (for reaping)
        let mut container_pids: HashMap<u32, String> =
            containers.iter().map(|c| (c.pid, c.name.clone())).collect();

        // Build container map for control server
        let container_map: HashMap<String, ContainerInfo> = containers
            .into_iter()
            .map(|c| (c.name.clone(), c))
            .collect();

        // Shared state for control server
        let state = Arc::new(RwLock::new(ControlState {
            containers: container_map,
            active_connections: 0,
        }));

        // Get infra container PID (for determining when to exit)
        let infra_pid = {
            let s = state.read().await;
            s.containers
                .values()
                .find(|c| c.name == "infra" || c.name.starts_with("infra-"))
                .map(|c| c.pid)
        };

        info!(infra_pid = ?infra_pid, total = container_pids.len(), "init loop starting");

        // Start control server
        let listener = match TcpListener::bind(("0.0.0.0", CONTROL_PORT)).await {
            Ok(l) => {
                info!(port = CONTROL_PORT, "control server listening");
                l
            }
            Err(e) => {
                error!(error = %e, port = CONTROL_PORT, "failed to bind control server");
                anyhow::bail!("failed to bind control server: {e}");
            }
        };

        // Connection counter for rate limiting
        let connection_count = Arc::new(AtomicUsize::new(0));

        loop {
            tokio::select! {
                // SIGTERM - graceful shutdown
                _ = sigterm.recv() => {
                    info!("received SIGTERM, initiating shutdown");
                    shutdown_containers(&container_pids, SHUTDOWN_GRACE_PERIOD_SECS).await;
                    return Ok(EXIT_SUCCESS);
                }

                // SIGINT - graceful shutdown
                _ = sigint.recv() => {
                    info!("received SIGINT, initiating shutdown");
                    shutdown_containers(&container_pids, SHUTDOWN_GRACE_PERIOD_SECS).await;
                    return Ok(EXIT_SUCCESS);
                }

                // Accept control connections
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let current = connection_count.load(Ordering::Relaxed);
                            if current >= MAX_CONNECTIONS {
                                warn!(addr = %addr, max = MAX_CONNECTIONS, "connection rejected: limit reached");
                                // Drop stream to close connection
                                continue;
                            }

                            debug!(addr = %addr, "control connection accepted");
                            let state = Arc::clone(&state);
                            let counter = Arc::clone(&connection_count);
                            counter.fetch_add(1, Ordering::Relaxed);

                            tokio::spawn(async move {
                                if let Err(e) = handle_control_connection(stream, state).await {
                                    debug!(error = %e, "control connection error");
                                }
                                counter.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to accept connection");
                        }
                    }
                }

                // SIGCHLD - child exited, reap zombies
                _ = sigchld.recv() => {
                    loop {
                        match reap_zombie() {
                            Some((pid, status)) => {
                                if let Some(name) = container_pids.remove(&(pid as u32)) {
                                    info!(
                                        container = %name,
                                        pid = pid,
                                        status = status,
                                        "container exited"
                                    );

                                    // Remove from control state
                                    {
                                        let mut s = state.write().await;
                                        s.containers.remove(&name);
                                    }

                                    // If infra container exited, VM should exit
                                    if Some(pid as u32) == infra_pid {
                                        info!("infra container exited, shutting down VM");
                                        shutdown_containers(&container_pids, SHUTDOWN_GRACE_PERIOD_SECS).await;
                                        return Ok(status as u8);
                                    }
                                } else {
                                    debug!(pid = pid, status = status, "reaped orphan process");
                                }
                            }
                            None => break, // No more zombies
                        }
                    }

                    // If all containers exited, exit
                    if container_pids.is_empty() {
                        info!("all containers exited");
                        return Ok(EXIT_SUCCESS);
                    }
                }
            }
        }
    }

    // =========================================================================
    // Control Server
    // =========================================================================

    /// Handles a single control connection.
    async fn handle_control_connection(
        stream: TcpStream,
        state: Arc<RwLock<ControlState>>,
    ) -> anyhow::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Read request with timeout
        let timeout_duration = Duration::from_secs(REQUEST_TIMEOUT_SECS);
        let read_result = tokio::time::timeout(timeout_duration, async {
            reader.read_line(&mut line).await
        })
        .await;

        let response = match read_result {
            Ok(Ok(0)) => {
                // EOF - client disconnected
                return Ok(());
            }
            Ok(Ok(n)) if n > MAX_REQUEST_LINE_LEN => {
                Response::error("invalid_request", "request too large")
            }
            Ok(Ok(_)) => {
                // Parse and handle request
                match serde_json::from_str::<Request>(line.trim()) {
                    Ok(request) => handle_request(request, &state).await,
                    Err(e) => Response::error("invalid_request", format!("JSON parse error: {e}")),
                }
            }
            Ok(Err(e)) => Response::error("internal", format!("read error: {e}")),
            Err(_) => Response::error("timeout", "request timed out"),
        };

        // Send response
        let response_line = response.to_json_line();
        writer.write_all(response_line.as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    /// Handles a parsed request.
    async fn handle_request(request: Request, state: &Arc<RwLock<ControlState>>) -> Response {
        match request {
            Request::Ping => handle_ping(state).await,
            Request::Exec(req) => handle_exec(req, state).await,
            Request::Logs(req) => handle_logs(req, state).await,
        }
    }

    /// Handles ping request.
    async fn handle_ping(state: &Arc<RwLock<ControlState>>) -> Response {
        let s = state.read().await;
        Response::ok_with_data(ResponseData::Pong {
            version: env!("CARGO_PKG_VERSION").to_string(),
            container_count: s.containers.len(),
        })
    }

    /// Handles exec request.
    async fn handle_exec(req: ExecRequest, state: &Arc<RwLock<ControlState>>) -> Response {
        // Validate container name
        if let Err(msg) = validate_container_name(&req.container) {
            return Response::error("invalid_request", msg);
        }

        // Validate command
        if let Err(msg) = validate_command(&req.command) {
            return Response::error("invalid_request", msg);
        }

        // Find container
        let container = {
            let s = state.read().await;
            s.containers.get(&req.container).cloned()
        };

        let Some(container) = container else {
            return Response::error(
                "container_not_found",
                format!("container '{}' not found", req.container),
            );
        };

        // Execute command using nsenter to enter container namespaces
        let result = exec_in_container(&container, &req).await;

        match result {
            Ok(output) => {
                info!(
                    container = %req.container,
                    command = ?req.command,
                    exit_code = output.exit_code,
                    "exec completed"
                );

                // For simple exec, return the output directly
                // Full streaming exec would use session IDs
                Response::ok_with_data(ResponseData::ExecOutput {
                    exit_code: output.exit_code,
                    stdout: output.stdout,
                    stderr: output.stderr,
                })
            }
            Err(e) => {
                error!(
                    container = %req.container,
                    command = ?req.command,
                    error = %e,
                    "exec failed"
                );
                Response::error("exec_failed", e)
            }
        }
    }

    /// Exec output from running a command in a container.
    struct ExecOutput {
        exit_code: i32,
        stdout: String,
        stderr: String,
    }

    /// Executes a command inside a container using nsenter.
    async fn exec_in_container(
        container: &ContainerInfo,
        req: &ExecRequest,
    ) -> Result<ExecOutput, String> {
        use tokio::process::Command;

        // Build nsenter command to enter container namespaces
        // -t <pid>: target process
        // -m: mount namespace
        // -u: UTS namespace
        // -i: IPC namespace
        // -n: network namespace
        // -p: PID namespace
        let mut cmd = Command::new("nsenter");
        cmd.arg("-t")
            .arg(container.pid.to_string())
            .arg("-m")
            .arg("-u")
            .arg("-i")
            .arg("-n")
            .arg("-p")
            .arg("--");

        // Add the actual command
        cmd.args(&req.command);

        // Capture stdout/stderr based on request options
        if req.stdout {
            cmd.stdout(std::process::Stdio::piped());
        } else {
            cmd.stdout(std::process::Stdio::null());
        }

        if req.stderr {
            cmd.stderr(std::process::Stdio::piped());
        } else {
            cmd.stderr(std::process::Stdio::null());
        }

        // Execute with timeout
        let timeout_duration = Duration::from_secs(EXEC_TIMEOUT_SECS);
        let output = tokio::time::timeout(timeout_duration, cmd.output()).await;

        match output {
            Ok(Ok(out)) => {
                let exit_code = out.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();

                Ok(ExecOutput {
                    exit_code,
                    stdout,
                    stderr,
                })
            }
            Ok(Err(e)) => Err(format!("nsenter failed: {e}")),
            Err(_) => Err(format!("exec timed out after {EXEC_TIMEOUT_SECS}s")),
        }
    }

    /// Handles logs request.
    async fn handle_logs(req: LogsRequest, state: &Arc<RwLock<ControlState>>) -> Response {
        // Validate container name
        if let Err(msg) = validate_container_name(&req.container) {
            return Response::error("invalid_request", msg);
        }

        // Validate tail_lines
        if req.tail_lines > MAX_TAIL_LINES {
            return Response::error(
                "invalid_request",
                format!("tail_lines exceeds maximum ({MAX_TAIL_LINES})"),
            );
        }

        // Find container
        let container = {
            let s = state.read().await;
            s.containers.get(&req.container).cloned()
        };

        let Some(container) = container else {
            return Response::error(
                "container_not_found",
                format!("container '{}' not found", req.container),
            );
        };

        // Read logs from container's log file
        let result = read_container_logs(&container, req.tail_lines).await;

        match result {
            Ok(lines) => {
                info!(
                    container = %req.container,
                    line_count = lines.len(),
                    tail_lines = req.tail_lines,
                    "logs retrieved"
                );

                Response::ok_with_data(ResponseData::LogOutput { lines })
            }
            Err(e) => {
                warn!(
                    container = %req.container,
                    error = %e,
                    "failed to read logs"
                );
                // Return empty logs on error (container might not have logs yet)
                Response::ok_with_data(ResponseData::LogOutput { lines: Vec::new() })
            }
        }
    }

    /// Reads logs from a container's log file.
    async fn read_container_logs(
        container: &ContainerInfo,
        tail_lines: u32,
    ) -> Result<Vec<String>, String> {
        use tokio::fs::File;
        use tokio::io::AsyncBufReadExt;

        // Try multiple log locations
        let log_paths = [
            // Standard OCI runtime log location
            format!(
                "{}/{}/{}",
                CONTAINER_STATE_ROOT, container.name, CONTAINER_LOG_FILE
            ),
            // Bundle-relative log
            format!("{}/{}", container.bundle_path, CONTAINER_LOG_FILE),
            // Fallback: read from /proc/<pid>/fd/1 (stdout)
            format!("/proc/{}/fd/1", container.pid),
        ];

        for log_path in &log_paths {
            let path = Path::new(log_path);
            if path.exists() {
                match File::open(path).await {
                    Ok(file) => {
                        let reader = BufReader::new(file);
                        let mut lines_stream = reader.lines();
                        let mut all_lines = Vec::new();

                        while let Ok(Some(line)) = lines_stream.next_line().await {
                            all_lines.push(line);
                        }

                        // Return tail lines
                        if tail_lines == 0 || all_lines.len() <= tail_lines as usize {
                            return Ok(all_lines);
                        }

                        let start = all_lines.len() - tail_lines as usize;
                        return Ok(all_lines[start..].to_vec());
                    }
                    Err(e) => {
                        debug!(path = %log_path, error = %e, "failed to open log file, trying next");
                        continue;
                    }
                }
            }
        }

        // No log file found - try reading from process stdout using nsenter + dmesg style
        // This is a fallback for containers without explicit log files
        Err("no log file found".to_string())
    }

    // =========================================================================
    // Validation Helpers
    // =========================================================================

    /// Validates a container name.
    fn validate_container_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("container name cannot be empty".to_string());
        }
        if name.len() > MAX_CONTAINER_NAME_LEN {
            return Err(format!(
                "container name exceeds {MAX_CONTAINER_NAME_LEN} bytes"
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(
                "container name contains invalid characters (allowed: a-z, A-Z, 0-9, -, _)"
                    .to_string(),
            );
        }
        if name.starts_with('-') || name.ends_with('-') {
            return Err("container name cannot start or end with hyphen".to_string());
        }
        Ok(())
    }

    /// Validates exec command arguments.
    fn validate_command(command: &[String]) -> Result<(), String> {
        if command.is_empty() {
            return Err("command cannot be empty".to_string());
        }
        if command.len() > MAX_COMMAND_ARGS {
            return Err(format!(
                "too many command arguments ({} > {})",
                command.len(),
                MAX_COMMAND_ARGS
            ));
        }
        for (i, arg) in command.iter().enumerate() {
            if arg.len() > MAX_COMMAND_ARG_LEN {
                return Err(format!(
                    "command argument {i} exceeds {MAX_COMMAND_ARG_LEN} bytes"
                ));
            }
        }
        Ok(())
    }

    /// Generates a simple UUID v4-like string (16 hex chars).
    fn uuid_v4_simple() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        format!("{:08x}{:08x}", (nanos & 0xFFFF_FFFF) as u32, pid)
    }

    /// Reaps a zombie process, returns (pid, exit_status) if any.
    fn reap_zombie() -> Option<(i32, i32)> {
        use libc::{WNOHANG, waitpid};

        let mut status: i32 = 0;
        // SAFETY: waitpid with WNOHANG is safe, -1 means any child
        let pid = unsafe { waitpid(-1, &mut status, WNOHANG) };

        if pid > 0 {
            let exit_status = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            };
            Some((pid, exit_status))
        } else {
            None
        }
    }

    /// Sends SIGTERM to all containers, waits, then SIGKILL.
    async fn shutdown_containers(pids: &HashMap<u32, String>, grace_secs: u64) {
        use libc::{SIGKILL, SIGTERM, kill};

        if pids.is_empty() {
            return;
        }

        info!(count = pids.len(), "sending SIGTERM to containers");

        // Send SIGTERM
        for (&pid, name) in pids {
            // SAFETY: kill is safe with valid PID
            let result = unsafe { kill(pid as i32, SIGTERM) };
            if result != 0 {
                debug!(container = %name, pid = pid, "SIGTERM failed (already dead?)");
            }
        }

        // Wait grace period
        tokio::time::sleep(Duration::from_secs(grace_secs)).await;

        // Send SIGKILL to any remaining
        for (&pid, name) in pids {
            // SAFETY: kill is safe with valid PID
            let result = unsafe { kill(pid as i32, SIGKILL) };
            if result == 0 {
                warn!(container = %name, pid = pid, "sent SIGKILL");
            }
        }
    }
}
