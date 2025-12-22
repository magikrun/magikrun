//! Youki OCI Runtime - Pure OCI container operations.
//!
//! This module implements the `OciRuntime` trait using youki's libcontainer.
//! It provides single-container operations without pod awareness - pod
//! semantics (namespace sharing) are handled by the higher-level magik-pod crate.
//!
//! # Namespace Sharing
//!
//! To share namespaces between containers (for pod semantics), the caller
//! should build OCI bundles with namespace paths in config.json:
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

use crate::error::{Error, Result};
use crate::runtime::{ContainerState, ContainerStatus, ExecOptions, ExecResult, OciRuntime, Signal};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
use libcontainer::container::builder::ContainerBuilder;
#[cfg(target_os = "linux")]
use libcontainer::container::{Container, ContainerStatus as YoukiStatus};
#[cfg(target_os = "linux")]
use libcontainer::signal::Signal as LibcontainerSignal;
#[cfg(target_os = "linux")]
use libcontainer::syscall::syscall::SyscallType;

/// Directory for storing container state.
const STATE_DIR: &str = "/var/run/magik-oci/containers";

/// Youki OCI runtime implementation.
pub struct YoukiRuntime {
    available: bool,
    reason: Option<String>,
    state_root: PathBuf,
    /// Tracking created containers for state queries.
    containers: RwLock<HashMap<String, ContainerInfo>>,
}

#[derive(Debug, Clone)]
struct ContainerInfo {
    bundle: PathBuf,
}

impl YoukiRuntime {
    /// Creates a new youki runtime.
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
        #[cfg(not(target_os = "linux"))]
        {
            return (false, Some("youki requires Linux".to_string()));
        }

        #[cfg(target_os = "linux")]
        {
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
    }

    #[cfg(target_os = "linux")]
    fn load_container(&self, id: &str) -> Result<Container> {
        let container_dir = self.state_root.join(id);
        if !container_dir.exists() {
            return Err(Error::ContainerNotFound(id.to_string()));
        }

        Container::load(container_dir).map_err(|e| {
            Error::Internal(format!("Failed to load container {}: {}", id, e))
        })
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
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, bundle);
            return Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            });
        }

        #[cfg(target_os = "linux")]
        {
            debug!("Creating container {} from bundle {}", id, bundle.display());

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
                let mut containers = self.containers.write().map_err(|e| {
                    Error::Internal(format!("lock poisoned: {}", e))
                })?;
                containers.insert(id.to_string(), ContainerInfo {
                    bundle: bundle.to_path_buf(),
                });
            }

            info!("Created container {}", id);
            Ok(())
        }
    }

    async fn start(&self, id: &str) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = id;
            return Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            });
        }

        #[cfg(target_os = "linux")]
        {
            debug!("Starting container {}", id);

            let container = self.load_container(id)?;
            
            container.start().map_err(|e| Error::StartFailed {
                id: id.to_string(),
                reason: e.to_string(),
            })?;

            info!("Started container {}", id);
            Ok(())
        }
    }

    async fn state(&self, id: &str) -> Result<ContainerState> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = id;
            return Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            });
        }

        #[cfg(target_os = "linux")]
        {
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
                let containers = self.containers.read().map_err(|e| {
                    Error::Internal(format!("lock poisoned: {}", e))
                })?;
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
    }

    async fn kill(&self, id: &str, signal: Signal, all: bool) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, signal, all);
            return Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            });
        }

        #[cfg(target_os = "linux")]
        {
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

            let lc_signal = LibcontainerSignal::try_from(sig_name).map_err(|e| {
                Error::SignalFailed {
                    id: id.to_string(),
                    reason: format!("invalid signal: {}", e),
                }
            })?;

            container.kill(lc_signal, all).map_err(|e| Error::SignalFailed {
                id: id.to_string(),
                reason: e.to_string(),
            })?;

            info!("Sent {} to container {}", signal, id);
            Ok(())
        }
    }

    async fn delete(&self, id: &str, force: bool) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, force);
            return Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            });
        }

        #[cfg(target_os = "linux")]
        {
            debug!("Deleting container {} (force={})", id, force);

            let container = self.load_container(id)?;

            container.delete(force).map_err(|e| Error::DeleteFailed {
                id: id.to_string(),
                reason: e.to_string(),
            })?;

            // Remove from tracking
            {
                let mut containers = self.containers.write().map_err(|e| {
                    Error::Internal(format!("lock poisoned: {}", e))
                })?;
                containers.remove(id);
            }

            info!("Deleted container {}", id);
            Ok(())
        }
    }

    async fn wait(&self, id: &str) -> Result<i32> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = id;
            return Err(Error::RuntimeUnavailable {
                runtime: "youki".to_string(),
                reason: "Linux required".to_string(),
            });
        }

        #[cfg(target_os = "linux")]
        {
            // Poll for container exit
            loop {
                let state = self.state(id).await?;
                if state.status == ContainerStatus::Stopped {
                    // TODO: Get actual exit code from container state
                    return Ok(0);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Gets namespace paths from a running container.
///
/// This is useful for pod semantics where subsequent containers need
/// to join the namespaces of the first container.
#[cfg(target_os = "linux")]
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
