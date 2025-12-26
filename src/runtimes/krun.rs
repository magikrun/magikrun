//! # Krun OCI Runtime - MicroVM Execution
//!
//! Implements the [`OciRuntime`] trait using libkrun for microVM-based
//! isolation. Provides the strongest isolation guarantee via hardware
//! virtualization (KVM on Linux, Hypervisor.framework on macOS).
//!
//! ## Platform Requirements
//!
//! | Platform | Hypervisor          | Detection                    |
//! |----------|---------------------|------------------------------|
//! | Linux    | KVM                 | `/dev/kvm` accessible        |
//! | macOS    | Hypervisor.framework| `krun_create_ctx()` succeeds |
//! | Windows  | Not supported       | Always unavailable           |
//!
//! ## Security Model
//!
//! MicroVMs provide hardware-level isolation:
//!
//! - **CPU isolation**: Separate virtual CPU with its own register state
//! - **Memory isolation**: Hardware-enforced memory boundaries (EPT/NPT)
//! - **Device isolation**: No direct hardware access, virtio emulation
//! - **Kernel isolation**: Guest runs its own kernel, not shared with host
//!
//! This is the **strongest isolation** available, suitable for untrusted
//! workloads. The attack surface is limited to the Virtual Machine Monitor.
//!
//! ## Resource Limits
//!
//! VMs are configured with bounded resources:
//!
//! | Resource | Default              | Maximum               |
//! |----------|----------------------|-----------------------|
//! | vCPUs    | `DEFAULT_VCPUS` (1)  | `MAX_VCPUS` (8)       |
//! | Memory   | `DEFAULT_VM_MEMORY_MIB` (512) | `MAX_VM_MEMORY_MIB` (4096) |
//!
//! ## FFI Safety
//!
//! This module uses `krun-sys` for FFI calls to libkrun. All unsafe blocks
//! include SAFETY comments explaining invariants:
//!
//! ```rust,ignore
//! // SAFETY: krun_create_ctx is safe to call, returns < 0 on failure
//! unsafe {
//!     let ctx = krun_sys::krun_create_ctx();
//!     // ...
//! }
//! ```
//!
//! ### Context Lifecycle
//!
//! Each VM has a libkrun context that must be freed:
//! 1. `krun_create_ctx()` - Creates context
//! 2. `krun_set_*()` - Configures VM
//! 3. `krun_start_enter()` - Runs VM (blocks until exit)
//! 4. `krun_free_ctx()` - Releases resources
//!
//! Context cleanup is handled in `kill()` and `delete()` to prevent leaks.
//!
//! ## Pod Semantics
//!
//! For multi-container pods, the `magikpod` crate builds a composite
//! rootfs containing all container bundles plus an init script. The
//! entire VM is treated as a single OCI container.
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::runtimes::KrunRuntime;
//! use magikrun::OciRuntime;
//!
//! #[tokio::main]
//! async fn main() -> magikrun::Result<()> {
//!     let runtime = KrunRuntime::new();
//!     
//!     if !runtime.is_available() {
//!         eprintln!("krun: {}", runtime.unavailable_reason().unwrap());
//!         return Ok(());
//!     }
//!     
//!     runtime.create("my-vm", "/path/to/bundle".as_ref()).await?;
//!     runtime.start("my-vm").await?; // Blocks until VM exits
//!     runtime.delete("my-vm", false).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Platform Support
//!
//! Linux and macOS only. On Windows, [`is_available`](crate::runtime::OciRuntime::is_available) returns
//! `false` and all operations return [`Error::RuntimeUnavailable`].
//!
//! [`OciRuntime`]: crate::runtime::OciRuntime
//! [`Error::RuntimeUnavailable`]: crate::error::Error::RuntimeUnavailable

// =============================================================================
// Linux/macOS Implementation
// =============================================================================

#[cfg(not(target_os = "windows"))]
mod platform {
    use crate::constants::{MAX_CONTAINERS, validate_container_id};
    use crate::error::{Error, Result};
    use crate::runtime::{ContainerState, ContainerStatus, OciRuntime, Signal};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::RwLock;
    use tracing::{debug, info};

    /// Internal state tracking for a microVM container.
    ///
    /// Note: All libkrun operations are delegated to the `magikrun` CLI binary
    /// (`magikrun start`) to avoid multi-threaded fork issues and libkrun's
    /// internal env_logger conflicts. The parent process only tracks
    /// metadata and child process state.
    struct VmContainer {
        bundle: PathBuf,
        status: ContainerStatus,
        /// PID of the magikrun process running krun_start_enter
        child_pid: Option<i32>,
    }

    /// Krun OCI runtime for microVM-based isolation.
    ///
    /// Provides the strongest isolation via hardware virtualization.
    /// Requires KVM (Linux) or Hypervisor.framework (macOS).
    pub struct KrunRuntime {
        available: bool,
        reason: Option<String>,
        containers: RwLock<HashMap<String, VmContainer>>,
    }

    impl KrunRuntime {
        /// Creates a new krun runtime.
        pub fn new() -> Self {
            let (available, reason) = Self::check_availability();

            Self {
                available,
                reason,
                containers: RwLock::new(HashMap::new()),
            }
        }

        fn check_availability() -> (bool, Option<String>) {
            // On Linux, KVM is required for libkrun
            #[cfg(target_os = "linux")]
            {
                use std::path::Path;
                if !Path::new("/dev/kvm").exists() {
                    return (
                        false,
                        Some("KVM not available: /dev/kvm does not exist".to_string()),
                    );
                }
            }

            // On macOS, check for Hypervisor.framework entitlement by verifying
            // the helper binary exists. We avoid calling libkrun here because
            // it uses env_logger::init() which panics if logging is already initialized.
            #[cfg(target_os = "macos")]
            {
                // The helper binary will fail at runtime if HVF is not available
                // For now, assume availability if we're on macOS with ARM64
                #[cfg(target_arch = "aarch64")]
                {
                    info!("krun runtime available (macOS ARM64 with HVF)");
                    (true, None)
                }
                #[cfg(not(target_arch = "aarch64"))]
                {
                    (
                        false,
                        Some("krun requires Apple Silicon (ARM64) on macOS".to_string()),
                    )
                }
            }

            #[cfg(target_os = "linux")]
            {
                info!("krun runtime available (Linux with KVM)");
                (true, None)
            }
        }

        /// Validates that the bundle has the required structure for a microVM.
        fn validate_bundle(bundle: &Path) -> Result<()> {
            let rootfs = bundle.join("rootfs");

            if !rootfs.exists() {
                return Err(Error::InvalidBundle {
                    path: bundle.to_path_buf(),
                    reason: "rootfs not found".to_string(),
                });
            }

            // Check for init or shell (using symlink_metadata to not follow symlinks,
            // since symlinks in container rootfs often point to absolute paths that
            // won't exist on the host but will resolve correctly inside the VM).
            let init_path = rootfs.join("sbin/init");
            let shell_path = rootfs.join("bin/sh");
            let has_init = std::fs::symlink_metadata(&init_path).is_ok()
                || std::fs::symlink_metadata(&shell_path).is_ok();

            if !has_init {
                return Err(Error::InvalidBundle {
                    path: bundle.to_path_buf(),
                    reason: "no init or shell found in rootfs".to_string(),
                });
            }

            Ok(())
        }
    }

    impl Default for KrunRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl OciRuntime for KrunRuntime {
        fn name(&self) -> &str {
            "krun"
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn unavailable_reason(&self) -> Option<String> {
            self.reason.clone()
        }

        async fn create(&self, id: &str, bundle: &Path) -> Result<()> {
            debug!(
                "Creating microVM container {} from bundle {}",
                id,
                bundle.display()
            );

            validate_container_id(id).map_err(|reason| Error::InvalidContainerId {
                id: id.to_string(),
                reason: reason.to_string(),
            })?;

            // Validate bundle structure before storing
            Self::validate_bundle(bundle)?;

            {
                let mut containers = self
                    .containers
                    .write()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

                if containers.len() >= MAX_CONTAINERS {
                    return Err(Error::ResourceExhausted(format!(
                        "maximum container limit reached ({})",
                        MAX_CONTAINERS
                    )));
                }

                if containers.contains_key(id) {
                    return Err(Error::ContainerAlreadyExists(id.to_string()));
                }

                // Just store metadata - all libkrun operations happen in the helper binary
                containers.insert(
                    id.to_string(),
                    VmContainer {
                        bundle: bundle.to_path_buf(),
                        status: ContainerStatus::Created,
                        child_pid: None,
                    },
                );
            }

            info!("Created microVM container {}", id);
            Ok(())
        }

        async fn start(&self, id: &str) -> Result<()> {
            debug!("Starting microVM container {}", id);

            // Validate container exists and is in created state
            {
                let containers = self
                    .containers
                    .read()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

                let container = containers
                    .get(id)
                    .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

                if container.status != ContainerStatus::Created {
                    return Err(Error::InvalidState {
                        id: id.to_string(),
                        state: container.status.to_string(),
                        expected: "created".to_string(),
                    });
                }
            }

            // Spawn the magikrun CLI binary in a fresh process.
            // This is the standard OCI runtime pattern - the CLI process becomes the VM.
            // We call ourselves (magikrun start) which handles krun_start_enter().
            
            // Find the magikrun binary - try various locations
            let magikrun_path = std::env::current_exe()
                .ok()
                .and_then(|exe| {
                    // If we ARE magikrun, use our own path
                    if exe.file_name().is_some_and(|n| n == "magikrun") {
                        return Some(exe);
                    }
                    // Try same directory as current exe
                    exe.parent()
                        .map(|d| d.join("magikrun"))
                        .filter(|p| p.exists())
                        // Try parent directory (if exe is in deps/)
                        .or_else(|| {
                            exe.parent()
                                .and_then(|d| d.parent())
                                .map(|d| d.join("magikrun"))
                                .filter(|p| p.exists())
                        })
                })
                .or_else(|| {
                    // Try CARGO_TARGET_DIR if set
                    std::env::var("CARGO_TARGET_DIR").ok().map(|d| {
                        std::path::PathBuf::from(d)
                            .join("debug")
                            .join("magikrun")
                    }).filter(|p| p.exists())
                })
                .or_else(|| {
                    // Try MAGIKRUN_PATH env var
                    std::env::var("MAGIKRUN_PATH").ok().map(std::path::PathBuf::from).filter(|p| p.exists())
                })
                .or_else(|| {
                    // Fall back to PATH
                    std::env::var("PATH").ok().and_then(|path| {
                        path.split(':')
                            .map(|dir| std::path::Path::new(dir).join("magikrun"))
                            .find(|p| p.exists())
                    })
                })
                .ok_or_else(|| Error::RuntimeUnavailable {
                    runtime: "krun".to_string(),
                    reason: "magikrun binary not found. Set MAGIKRUN_PATH or install to PATH".to_string(),
                })?;

            // Build command: magikrun start <id>
            // The bundle path is already stored in the state file
            let mut cmd = std::process::Command::new(&magikrun_path);
            cmd.arg("start").arg(id);

            // On macOS, set library path for libkrunfw
            #[cfg(target_os = "macos")]
            {
                cmd.env(
                    "DYLD_FALLBACK_LIBRARY_PATH",
                    "/usr/local/lib:/opt/homebrew/lib",
                );
            }

            let child = cmd.spawn().map_err(|e| Error::StartFailed {
                id: id.to_string(),
                reason: format!("failed to spawn magikrun: {}", e),
            })?;

            let child_pid = child.id() as i32;

            // Record the child PID
            {
                let mut containers = self
                    .containers
                    .write()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

                if let Some(container) = containers.get_mut(id) {
                    container.status = ContainerStatus::Running;
                    container.child_pid = Some(child_pid);
                }
            }

            info!("Started microVM container {} with PID {}", id, child_pid);
            Ok(())
        }

        async fn state(&self, id: &str) -> Result<ContainerState> {
            let mut containers = self
                .containers
                .write()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get_mut(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            // Check if child process has exited (non-blocking)
            if let Some(child_pid) = container.child_pid
                && container.status == ContainerStatus::Running
            {
                let mut status: i32 = 0;
                // SAFETY: waitpid with WNOHANG is safe with valid PID
                let ret = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
                if ret == child_pid {
                    // Child has exited
                    container.status = ContainerStatus::Stopped;
                    container.child_pid = None;
                    debug!("Child process {} has exited", child_pid);
                } else if ret == -1 {
                    // Error checking - child may not exist
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ECHILD) {
                        container.status = ContainerStatus::Stopped;
                        container.child_pid = None;
                    }
                }
                // ret == 0 means child still running
            }

            Ok(ContainerState {
                oci_version: "1.0.2".to_string(),
                id: id.to_string(),
                status: container.status,
                pid: container.child_pid.map(|p| p as u32),
                bundle: container.bundle.to_string_lossy().to_string(),
                annotations: HashMap::new(),
            })
        }

        async fn kill(&self, id: &str, signal: Signal, _all: bool) -> Result<()> {
            debug!("Killing microVM container {} with {:?}", id, signal);

            let mut containers = self
                .containers
                .write()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get_mut(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            // Send signal to the child process running the VM
            if let Some(child_pid) = container.child_pid {
                let sig = match signal {
                    Signal::Term => libc::SIGTERM,
                    Signal::Kill => libc::SIGKILL,
                    Signal::Int => libc::SIGINT,
                    Signal::Hup => libc::SIGHUP,
                    Signal::Usr1 => libc::SIGUSR1,
                    Signal::Usr2 => libc::SIGUSR2,
                };
                // SAFETY: kill() is safe to call with a valid PID
                let ret = unsafe { libc::kill(child_pid, sig) };
                if ret != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                    return Err(Error::SignalFailed {
                        id: id.to_string(),
                        reason: format!("kill failed: {}", std::io::Error::last_os_error()),
                    });
                }
            }

            container.status = ContainerStatus::Stopped;

            info!("Killed microVM container {}", id);
            Ok(())
        }

        async fn delete(&self, id: &str, force: bool) -> Result<()> {
            debug!("Deleting microVM container {} (force={})", id, force);

            let mut containers = self
                .containers
                .write()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get_mut(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            if !force && container.status == ContainerStatus::Running {
                return Err(Error::InvalidState {
                    id: id.to_string(),
                    state: "running".to_string(),
                    expected: "stopped".to_string(),
                });
            }

            // Force kill the child process if still running
            if force
                && let Some(child_pid) = container.child_pid
            {
                // SAFETY: kill() is safe with valid PID
                unsafe { libc::kill(child_pid, libc::SIGKILL) };
                // Wait for child to avoid zombie
                unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), libc::WNOHANG) };
            }

            containers.remove(id);

            info!("Deleted microVM container {}", id);
            Ok(())
        }

        async fn wait(&self, id: &str) -> Result<i32> {
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(300); // 5 minute timeout

            loop {
                if start.elapsed() > timeout {
                    return Err(Error::Timeout {
                        operation: format!("wait for container {}", id),
                        duration: timeout,
                    });
                }

                let state = self.state(id).await?;
                if state.status == ContainerStatus::Stopped {
                    return Ok(0);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

// =============================================================================
// Windows Stub Implementation
// =============================================================================

#[cfg(target_os = "windows")]
mod stub {
    use crate::error::{Error, Result};
    use crate::runtime::{ContainerState, OciRuntime, Signal};
    use async_trait::async_trait;
    use std::path::Path;

    /// Stub KrunRuntime for Windows.
    ///
    /// libkrun requires KVM (Linux) or Hypervisor.framework (macOS),
    /// so it's not available on Windows. All operations return
    /// [`Error::RuntimeUnavailable`].
    ///
    /// [`Error::RuntimeUnavailable`]: crate::error::Error::RuntimeUnavailable
    pub struct KrunRuntime {
        _private: (),
    }

    impl KrunRuntime {
        /// Creates a new (unavailable) krun runtime.
        pub fn new() -> Self {
            Self { _private: () }
        }
    }

    impl Default for KrunRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl OciRuntime for KrunRuntime {
        fn name(&self) -> &str {
            "krun"
        }

        fn is_available(&self) -> bool {
            false
        }

        fn unavailable_reason(&self) -> Option<String> {
            Some("libkrun requires KVM (Linux) or Hypervisor.framework (macOS)".to_string())
        }

        async fn create(&self, _id: &str, _bundle: &Path) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "krun".to_string(),
                reason: "Windows not supported".to_string(),
            })
        }

        async fn start(&self, _id: &str) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "krun".to_string(),
                reason: "Windows not supported".to_string(),
            })
        }

        async fn state(&self, _id: &str) -> Result<ContainerState> {
            Err(Error::RuntimeUnavailable {
                runtime: "krun".to_string(),
                reason: "Windows not supported".to_string(),
            })
        }

        async fn kill(&self, _id: &str, _signal: Signal, _all: bool) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "krun".to_string(),
                reason: "Windows not supported".to_string(),
            })
        }

        async fn delete(&self, _id: &str, _force: bool) -> Result<()> {
            Err(Error::RuntimeUnavailable {
                runtime: "krun".to_string(),
                reason: "Windows not supported".to_string(),
            })
        }

        async fn wait(&self, _id: &str) -> Result<i32> {
            Err(Error::RuntimeUnavailable {
                runtime: "krun".to_string(),
                reason: "Windows not supported".to_string(),
            })
        }
    }
}

// =============================================================================
// Re-exports
// =============================================================================

#[cfg(not(target_os = "windows"))]
pub use platform::KrunRuntime;

#[cfg(target_os = "windows")]
pub use stub::KrunRuntime;
