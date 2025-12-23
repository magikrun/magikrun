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
    use crate::constants::{
        DEFAULT_VCPUS, DEFAULT_VM_MEMORY_MIB, MAX_CONTAINERS, validate_container_id,
    };
    use crate::error::{Error, Result};
    use crate::runtime::{ContainerState, ContainerStatus, OciRuntime, Signal};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::path::{Path, PathBuf};
    use std::sync::RwLock;
    use tracing::{debug, info};

    /// libkrun context handle.
    type KrunCtx = u32;

    /// Internal state tracking for a microVM container.
    struct VmContainer {
        bundle: PathBuf,
        status: ContainerStatus,
        ctx: Option<KrunCtx>,
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

            // SAFETY: krun_create_ctx is safe to call
            unsafe {
                let ctx = krun_sys::krun_create_ctx();
                if ctx < 0 {
                    return (false, Some(format!("libkrun unavailable: error {}", ctx)));
                }
                krun_sys::krun_free_ctx(ctx as u32);
            }

            info!("krun runtime available");
            (true, None)
        }

        fn configure_vm(&self, ctx: KrunCtx, bundle: &Path) -> Result<()> {
            let rootfs = bundle.join("rootfs");

            if !rootfs.exists() {
                return Err(Error::InvalidBundle {
                    path: bundle.to_path_buf(),
                    reason: "rootfs not found".to_string(),
                });
            }

            // SAFETY: krun_set_vm_config is safe with valid ctx and params
            let ret = unsafe {
                krun_sys::krun_set_vm_config(ctx, DEFAULT_VCPUS as u8, DEFAULT_VM_MEMORY_MIB)
            };
            if ret < 0 {
                return Err(Error::CreateFailed {
                    id: bundle.to_string_lossy().to_string(),
                    reason: format!("krun_set_vm_config failed: {}", ret),
                });
            }

            let rootfs_cstr = CString::new(rootfs.to_string_lossy().as_bytes()).map_err(|_| {
                Error::CreateFailed {
                    id: bundle.to_string_lossy().to_string(),
                    reason: "invalid rootfs path".to_string(),
                }
            })?;

            // SAFETY: krun_set_root is safe with valid ctx and path
            let ret = unsafe { krun_sys::krun_set_root(ctx, rootfs_cstr.as_ptr()) };
            if ret < 0 {
                return Err(Error::CreateFailed {
                    id: bundle.to_string_lossy().to_string(),
                    reason: format!("krun_set_root failed: {}", ret),
                });
            }

            let init_path = if rootfs.join("sbin/init").exists() {
                "/sbin/init"
            } else if rootfs.join("bin/sh").exists() {
                "/bin/sh"
            } else {
                return Err(Error::InvalidBundle {
                    path: bundle.to_path_buf(),
                    reason: "no init or shell found in rootfs".to_string(),
                });
            };

            let init_cstr = CString::new(init_path).unwrap();

            // SAFETY: krun_set_exec is safe with valid ctx and path
            let ret = unsafe {
                krun_sys::krun_set_exec(ctx, init_cstr.as_ptr(), std::ptr::null(), std::ptr::null())
            };
            if ret < 0 {
                return Err(Error::CreateFailed {
                    id: bundle.to_string_lossy().to_string(),
                    reason: format!("krun_set_exec failed: {}", ret),
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

            // SAFETY: krun_create_ctx is safe to call
            let ctx = unsafe { krun_sys::krun_create_ctx() };
            if ctx < 0 {
                return Err(Error::CreateFailed {
                    id: id.to_string(),
                    reason: format!("krun_create_ctx failed: {}", ctx),
                });
            }
            let ctx = ctx as KrunCtx;

            if let Err(e) = self.configure_vm(ctx, bundle) {
                // SAFETY: Free context on error
                unsafe { krun_sys::krun_free_ctx(ctx) };
                return Err(e);
            }

            {
                let mut containers = self.containers.write().map_err(|e| {
                    unsafe { krun_sys::krun_free_ctx(ctx) };
                    Error::Internal(format!("lock poisoned: {}", e))
                })?;

                if containers.len() >= MAX_CONTAINERS {
                    unsafe { krun_sys::krun_free_ctx(ctx) };
                    return Err(Error::ResourceExhausted(format!(
                        "maximum container limit reached ({})",
                        MAX_CONTAINERS
                    )));
                }

                if containers.contains_key(id) {
                    unsafe { krun_sys::krun_free_ctx(ctx) };
                    return Err(Error::ContainerAlreadyExists(id.to_string()));
                }

                containers.insert(
                    id.to_string(),
                    VmContainer {
                        bundle: bundle.to_path_buf(),
                        status: ContainerStatus::Created,
                        ctx: Some(ctx),
                    },
                );
            }

            info!("Created microVM container {}", id);
            Ok(())
        }

        async fn start(&self, id: &str) -> Result<()> {
            debug!("Starting microVM container {}", id);

            let ctx = {
                let mut containers = self
                    .containers
                    .write()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

                let container = containers
                    .get_mut(id)
                    .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

                if container.status != ContainerStatus::Created {
                    return Err(Error::InvalidState {
                        id: id.to_string(),
                        state: container.status.to_string(),
                        expected: "created".to_string(),
                    });
                }

                container.status = ContainerStatus::Running;
                container
                    .ctx
                    .ok_or_else(|| Error::Internal("no context".to_string()))?
            };

            // SAFETY: krun_start_enter is safe with valid ctx
            let ret = unsafe { krun_sys::krun_start_enter(ctx) };
            if ret < 0 {
                return Err(Error::StartFailed {
                    id: id.to_string(),
                    reason: format!("krun_start_enter failed: {}", ret),
                });
            }

            info!("Started microVM container {}", id);
            Ok(())
        }

        async fn state(&self, id: &str) -> Result<ContainerState> {
            let containers = self
                .containers
                .read()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            Ok(ContainerState {
                oci_version: "1.0.2".to_string(),
                id: id.to_string(),
                status: container.status,
                pid: None,
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

            if let Some(ctx) = container.ctx.take() {
                // SAFETY: krun_free_ctx is safe with valid ctx
                unsafe { krun_sys::krun_free_ctx(ctx) };
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

            if let Some(ctx) = container.ctx.take() {
                // SAFETY: krun_free_ctx is safe with valid ctx
                unsafe { krun_sys::krun_free_ctx(ctx) };
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
