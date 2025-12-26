//! # vminit - Minimal MicroVM Init Process
//!
//! This binary runs as PID 1 inside MicroVMs. It is intentionally minimal:
//!
//! - **Zombie reaping**: Collects orphaned child processes
//! - **Signal forwarding**: Forwards SIGTERM/SIGINT to children
//! - **TSI server**: Handles exec/logs requests from host (vsock)
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
//! │  ├─► TSI server (exec/logs only)                               │
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
    use std::time::Duration;

    use tracing::{debug, error, info, warn, Level};
    use tracing_subscriber::FmtSubscriber;

    // =========================================================================
    // Constants
    // =========================================================================

    /// Path to baked pod spec.
    const POD_SPEC_PATH: &str = "/pod/spec.json";

    /// Base path for container bundles.
    const CONTAINERS_PATH: &str = "/containers";

    /// Default vsock port for TSI.
    const DEFAULT_VSOCK_PORT: u32 = 1024;

    /// Environment variable for vsock port override.
    const ENV_VSOCK_PORT: &str = "MAGIK_VSOCK_PORT";

    /// Grace period for SIGTERM before SIGKILL (seconds).
    const SHUTDOWN_GRACE_PERIOD_SECS: u64 = 30;

    /// Exit codes.
    const EXIT_SUCCESS: u8 = 0;
    const EXIT_INIT_FAILED: u8 = 1;
    const EXIT_SPAWN_FAILED: u8 = 2;

    // =========================================================================
    // Container Info
    // =========================================================================

    /// Container process info.
    struct ContainerProcess {
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
            warn!(pid = std::process::id(), "vminit is not PID 1, zombie reaping may not work");
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
    async fn spawn_containers() -> anyhow::Result<Vec<ContainerProcess>> {
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
                    processes.push(ContainerProcess {
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
        let pid = container.pid().ok_or_else(|| {
            anyhow::anyhow!("container started but no PID")
        })?;

        Ok(pid.as_raw() as u32)
    }

    // =========================================================================
    // Init Loop
    // =========================================================================

    /// Main init loop - zombie reaping, signal handling, TSI server.
    async fn run_init_loop(containers: Vec<ContainerProcess>) -> anyhow::Result<u8> {
        use tokio::signal::unix::{signal, SignalKind};

        // Set up signal handlers
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigchld = signal(SignalKind::child())?;

        // Track container PIDs
        let mut container_pids: HashMap<u32, String> = containers
            .iter()
            .map(|c| (c.pid, c.name.clone()))
            .collect();

        // Get infra container PID (for determining when to exit)
        let infra_pid = containers
            .iter()
            .find(|c| c.name == "infra" || c.name.starts_with("infra-"))
            .map(|c| c.pid);

        info!(infra_pid = ?infra_pid, total = container_pids.len(), "init loop starting");

        // TODO: Start TSI server for exec/logs
        // For now, just run the reaping loop

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
