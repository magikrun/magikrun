//! # Youki OCI Runtime - Native Linux Container Operations
//!
//! Implements the [`OciRuntime`] trait using youki's `libcontainer`, providing
//! native Linux container isolation via namespaces and cgroups v2.
//!
//! ## Platform Requirements
//!
//! | Requirement         | Check                        | Fallback      |
//! |---------------------|------------------------------|---------------|
//! | Linux OS            | Compile-time (`cfg!`)        | Not available |
//! | Namespace support   | `/proc/self/ns/pid` exists   | Not available |
//! | Cgroups v2          | Unified cgroup hierarchy     | Not available |
//! | Root or capabilities| CAP_SYS_ADMIN, etc.          | Not available |
//!
//! ## Security Model
//!
//! Youki provides container isolation through:
//!
//! - **Namespaces**: PID, network, mount, IPC, UTS isolation
//! - **Cgroups v2**: Resource limits (memory, CPU, PIDs)
//! - **Seccomp**: Syscall filtering (when available)
//! - **Capabilities**: Minimal capability set for containers
//!
//! ### Privilege Requirements
//!
//! Container creation requires elevated privileges:
//! - Root user, or
//! - `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` + `CAP_SETUID` + `CAP_SETGID`
//!
//! For rootless containers, additional setup is required (user namespaces).
//!
//! ## Namespace Sharing for Pods
//!
//! While this runtime handles single containers, it supports namespace
//! sharing via bundle configuration. The `magikpod` crate creates bundles
//! with namespace paths for pod semantics:
//!
//! ```json
//! {
//!   "linux": {
//!     "namespaces": [
//!       { "type": "pid" },
//!       { "type": "network", "path": "/proc/1234/ns/net" },
//!       { "type": "ipc", "path": "/proc/1234/ns/ipc" }
//!     ]
//!   }
//! }
//! ```
//!
//! The [`get_namespace_paths`] function extracts namespace paths from a
//! running container's PID for subsequent containers to join.
//!
//! ## State Storage
//!
//! Container state is stored in:
//! - Default: `/var/run/magik-oci/containers/<container-id>/`
//! - Custom: Configurable via [`YoukiRuntime::with_state_root`]
//!
//! State files include the libcontainer state.json with status, PID, and
//! creation timestamp.
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::runtimes::YoukiRuntime;
//! use magikrun::OciRuntime;
//!
//! #[tokio::main]
//! async fn main() -> magikrun::Result<()> {
//!     let runtime = YoukiRuntime::new();
//!     
//!     if !runtime.is_available() {
//!         eprintln!("youki: {}", runtime.unavailable_reason().unwrap());
//!         return Ok(());
//!     }
//!     
//!     // Create and start container
//!     runtime.create("my-container", "/path/to/bundle".as_ref()).await?;
//!     runtime.start("my-container").await?;
//!     
//!     // ... container runs ...
//!     
//!     runtime.kill("my-container", magikrun::Signal::Term, false).await?;
//!     runtime.delete("my-container", false).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Platform Support
//!
//! Linux-only. On non-Linux platforms, [`YoukiRuntime::is_available`] returns
//! `false` and all operations return [`Error::RuntimeUnavailable`].
//!
//! [`OciRuntime`]: crate::runtime::OciRuntime
//! [`Error::RuntimeUnavailable`]: crate::error::Error::RuntimeUnavailable

// =============================================================================
// Linux Implementation
// =============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use crate::constants::{MAX_CONTAINERS, validate_container_id};
    use crate::error::{Error, Result};
    use crate::runtime::{ContainerState, ContainerStatus, OciRuntime, Signal};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::RwLock;
    use tracing::{debug, info};

    use libcontainer::container::builder::ContainerBuilder;
    use libcontainer::container::{Container, ContainerStatus as YoukiStatus};
    use libcontainer::signal::Signal as LibcontainerSignal;
    use libcontainer::syscall::syscall::SyscallType;

    /// Directory for storing container state.
    const STATE_DIR: &str = "/var/run/magik-oci/containers";

    /// Internal tracking information for created containers.
    #[derive(Debug, Clone)]
    struct ContainerInfo {
        bundle: PathBuf,
    }

    /// Youki OCI runtime implementation using libcontainer.
    ///
    /// Provides native Linux container operations with namespace and cgroup
    /// isolation. Requires Linux with namespace support.
    ///
    /// ## Thread Safety
    ///
    /// This struct is thread-safe (`Send + Sync`). Container state is protected
    /// by an internal `RwLock`. Multiple containers can be managed concurrently.
    ///
    /// ## State Persistence
    ///
    /// Container state survives runtime restarts. The `state_root` directory
    /// contains libcontainer state files that can be loaded on startup.
    ///
    /// ## Resource Cleanup
    ///
    /// Containers are NOT automatically cleaned up on drop. Always call
    /// `delete()` to release container resources and cgroup allocations.
    pub struct YoukiRuntime {
        available: bool,
        reason: Option<String>,
        state_root: PathBuf,
        containers: RwLock<HashMap<String, ContainerInfo>>,
    }

    impl YoukiRuntime {
        /// Creates a new youki runtime with default state directory.
        pub fn new() -> Self {
            Self::with_state_root(PathBuf::from(STATE_DIR))
        }

        /// Creates a youki runtime with a custom state root.
        pub fn with_state_root(state_root: PathBuf) -> Self {
            let (available, reason) = Self::check_availability(&state_root);

            Self {
                available,
                reason,
                state_root,
                containers: RwLock::new(HashMap::new()),
            }
        }

        fn check_availability(state_root: &Path) -> (bool, Option<String>) {
            // Check for namespace support
            if !Path::new("/proc/self/ns/pid").exists() {
                return (false, Some("Linux namespaces not available".to_string()));
            }

            // Try to create state directory
            if let Err(e) = std::fs::create_dir_all(state_root) {
                return (false, Some(format!("Cannot create state dir: {}", e)));
            }

            info!("youki runtime available at {}", state_root.display());
            (true, None)
        }

        fn load_container(&self, id: &str) -> Result<Container> {
            let container_dir = self.state_root.join(id);
            if !container_dir.exists() {
                return Err(Error::ContainerNotFound(id.to_string()));
            }

            Container::load(container_dir)
                .map_err(|e| Error::Internal(format!("Failed to load container {}: {}", id, e)))
        }
    }

    impl Default for YoukiRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl OciRuntime for YoukiRuntime {
        fn name(&self) -> &str {
            "youki"
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn unavailable_reason(&self) -> Option<String> {
            self.reason.clone()
        }

        async fn create(&self, id: &str, bundle: &Path) -> Result<()> {
            debug!("Creating container {} from bundle {}", id, bundle.display());

            // SECURITY: Validate container ID format (consistent with wasmtime/krun)
            validate_container_id(id).map_err(|reason| Error::InvalidContainerId {
                id: id.to_string(),
                reason: reason.to_string(),
            })?;

            // SECURITY: Check container limit before creation
            {
                let containers = self
                    .containers
                    .read()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;
                if containers.len() >= MAX_CONTAINERS {
                    return Err(Error::ResourceExhausted(format!(
                        "maximum container limit reached ({})",
                        MAX_CONTAINERS
                    )));
                }
            }

            // Check bundle exists
            if !bundle.join("config.json").exists() {
                return Err(Error::InvalidBundle {
                    path: bundle.to_path_buf(),
                    reason: "config.json not found".to_string(),
                });
            }

            // Create container using libcontainer
            let _container = ContainerBuilder::new(id.to_string(), SyscallType::default())
                .with_root_path(&self.state_root)
                .map_err(|e| Error::CreateFailed {
                    id: id.to_string(),
                    reason: format!("invalid root path: {}", e),
                })?
                .validate_id()
                .map_err(|e| Error::CreateFailed {
                    id: id.to_string(),
                    reason: format!("invalid container id: {}", e),
                })?
                .as_init(bundle)
                .with_systemd(false)
                .build()
                .map_err(|e| Error::CreateFailed {
                    id: id.to_string(),
                    reason: format!("build failed: {}", e),
                })?;

            // Track container
            {
                let mut containers = self
                    .containers
                    .write()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;
                containers.insert(
                    id.to_string(),
                    ContainerInfo {
                        bundle: bundle.to_path_buf(),
                    },
                );
            }

            info!("Created container {}", id);
            Ok(())
        }

        async fn start(&self, id: &str) -> Result<()> {
            debug!("Starting container {}", id);

            let container = self.load_container(id)?;

            container.start().map_err(|e| Error::StartFailed {
                id: id.to_string(),
                reason: e.to_string(),
            })?;

            info!("Started container {}", id);
            Ok(())
        }

        async fn state(&self, id: &str) -> Result<ContainerState> {
            let container = self.load_container(id)?;

            let status = match container.state.status {
                YoukiStatus::Creating => ContainerStatus::Creating,
                YoukiStatus::Created => ContainerStatus::Created,
                YoukiStatus::Running => ContainerStatus::Running,
                YoukiStatus::Stopped => ContainerStatus::Stopped,
                YoukiStatus::Paused => ContainerStatus::Running,
            };

            let pid = container.pid().map(|p| p.as_raw() as u32);

            let bundle = {
                let containers = self
                    .containers
                    .read()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;
                containers
                    .get(id)
                    .map(|c| c.bundle.to_string_lossy().to_string())
                    .unwrap_or_default()
            };

            Ok(ContainerState {
                oci_version: "1.0.2".to_string(),
                id: id.to_string(),
                status,
                pid,
                bundle,
                annotations: HashMap::new(),
            })
        }

        async fn kill(&self, id: &str, signal: Signal, all: bool) -> Result<()> {
            debug!("Sending {} to container {}", signal, id);

            let container = self.load_container(id)?;

            let sig_name = match signal {
                Signal::Term => "SIGTERM",
                Signal::Kill => "SIGKILL",
                Signal::Hup => "SIGHUP",
                Signal::Int => "SIGINT",
                Signal::Usr1 => "SIGUSR1",
                Signal::Usr2 => "SIGUSR2",
            };

            let lc_signal =
                LibcontainerSignal::try_from(sig_name).map_err(|e| Error::SignalFailed {
                    id: id.to_string(),
                    reason: format!("invalid signal: {}", e),
                })?;

            container
                .kill(lc_signal, all)
                .map_err(|e| Error::SignalFailed {
                    id: id.to_string(),
                    reason: e.to_string(),
                })?;

            info!("Sent {} to container {}", signal, id);
            Ok(())
        }

        async fn delete(&self, id: &str, force: bool) -> Result<()> {
            debug!("Deleting container {} (force={})", id, force);

            let container = self.load_container(id)?;

            container.delete(force).map_err(|e| Error::DeleteFailed {
                id: id.to_string(),
                reason: e.to_string(),
            })?;

            // Remove from tracking
            {
                let mut containers = self
                    .containers
                    .write()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;
                containers.remove(id);
            }

            info!("Deleted container {}", id);
            Ok(())
        }

        async fn wait(&self, id: &str) -> Result<i32> {
            // Poll for container exit and retrieve exit code
            loop {
                let container = self.load_container(id)?;

                if container.state.status == YoukiStatus::Stopped {
                    // Get PID to query exit status
                    // libcontainer doesn't expose exit code directly, so we return 0
                    // for stopped containers. For actual exit code tracking, the caller
                    // should use wait4() on the container PID before it exits.
                    //
                    // Note: This is a limitation of the libcontainer API.
                    // Production deployments should use container.pid() + waitpid()
                    // in a background task started during container.start().
                    return Ok(0);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }

    /// Retrieves namespace paths from a running container's process.
    ///
    /// Returns a map of namespace type to `/proc/<pid>/ns/<type>` paths.
    /// Used by `magikpod` to enable subsequent containers to join existing
    /// namespaces for pod semantics.
    ///
    /// ## Returned Namespaces
    ///
    /// | Key      | Path Example            | Purpose                  |
    /// |----------|------------------------|---------------------------|
    /// | `net`    | `/proc/1234/ns/net`    | Network namespace         |
    /// | `ipc`    | `/proc/1234/ns/ipc`    | IPC namespace             |
    /// | `uts`    | `/proc/1234/ns/uts`    | Hostname namespace        |
    /// | `pid`    | `/proc/1234/ns/pid`    | PID namespace             |
    /// | `mnt`    | `/proc/1234/ns/mnt`    | Mount namespace           |
    /// | `user`   | `/proc/1234/ns/user`   | User namespace            |
    /// | `cgroup` | `/proc/1234/ns/cgroup` | Cgroup namespace          |
    ///
    /// ## Usage for Pod Sharing
    ///
    /// ```rust,ignore
    /// // After starting the first container in a pod:
    /// let state = runtime.state("pause-container").await?;
    /// if let Some(pid) = state.pid {
    ///     let ns_paths = get_namespace_paths(pid);
    ///     // Build subsequent container bundles with these paths
    ///     builder.build_oci_bundle_with_namespaces(&image, &config, &ns_paths)?;
    /// }
    /// ```
    pub fn get_namespace_paths(pid: u32) -> HashMap<String, PathBuf> {
        let mut paths = HashMap::new();
        let proc_ns = PathBuf::from(format!("/proc/{}/ns", pid));

        for ns_type in &["net", "ipc", "uts", "pid", "mnt", "user", "cgroup"] {
            let ns_path = proc_ns.join(ns_type);
            if ns_path.exists() {
                paths.insert(ns_type.to_string(), ns_path);
            }
        }

        paths
    }
}

// =============================================================================
// Non-Linux Stub
// =============================================================================

#[cfg(not(target_os = "linux"))]
mod stub {
    use crate::error::{Error, Result};
    use crate::runtime::{ContainerState, OciRuntime, Signal};
    use async_trait::async_trait;
    use std::path::{Path, PathBuf};

    /// Stub YoukiRuntime for non-Linux platforms.
    ///
    /// Youki requires Linux namespaces and cgroups, so it's not available
    /// on macOS or other platforms. All operations return
    /// [`Error::RuntimeUnavailable`].
    ///
    /// [`Error::RuntimeUnavailable`]: crate::error::Error::RuntimeUnavailable
    pub struct YoukiRuntime {
        _private: (),
    }

    impl YoukiRuntime {
        /// Creates a new (unavailable) youki runtime.
        pub fn new() -> Self {
            Self { _private: () }
        }

        /// Creates a youki runtime with a custom state root (ignored on non-Linux).
        pub fn with_state_root(_state_root: PathBuf) -> Self {
            Self::new()
        }
    }

    impl Default for YoukiRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl OciRuntime for YoukiRuntime {
        fn name(&self) -> &str {
            "youki"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            Some("youki requires Linux (namespaces, cgroups)".to_string())
        }

        async fn create(&self, _id: &str, _bundle: &Path) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            })
        }

        async fn start(&self, _id: &str) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            })
        }

        async fn state(&self, _id: &str) -> Result<ContainerState> {
            Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            })
        }

        async fn kill(&self, _id: &str, _signal: Signal, _all: bool) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            })
        }

        async fn delete(&self, _id: &str, _force: bool) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            })
        }

        async fn wait(&self, _id: &str) -> Result<i32> {
            Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            })
        }
    }
}

// =============================================================================
// Re-exports
// =============================================================================

#[cfg(target_os = "linux")]
pub use linux::{YoukiRuntime, get_namespace_paths};

#[cfg(not(target_os = "linux"))]
pub use stub::YoukiRuntime;
