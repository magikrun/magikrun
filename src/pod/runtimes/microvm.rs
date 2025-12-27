//! MicroVM pod runtime using libkrun.
//!
//! This runtime creates pods using microVMs for hardware-level isolation.
//! VM boot is naturally atomic - either the VM starts successfully or it doesn't.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Host                                                          │
//! │  ┌─────────────────────────────────────────────────────────────┐
//! │  │  MicroVmPodRuntime                                         │
//! │  │  - Pulls images, builds composite rootfs                   │
//! │  │  - Creates/manages VMs via libkrun                         │
//! │  └───────────────────────────────────────────────────────────┬─┘
//! │                                                              │
//! │                        ┌─────────────────────────────────────┘
//! │                        ▼
//! │  ┌─────────────────────────────────────────────────────────────┐
//! │  │  MicroVM (libkrun)                                          │
//! │  │  ┌───────────────────────────────────────────────────┐      │
//! │  │  │  Container Processes                              │      │
//! │  │  │  (all containers run inside single VM)            │      │
//! │  │  └───────────────────────────────────────────────────┘      │
//! │  │                                                             │
//! │  │  Kernel: libkrunfw (Linux 6.6.x)                            │
//! │  │  Hypervisor: KVM (Linux) / Hypervisor.framework (macOS)    │
//! │  └─────────────────────────────────────────────────────────────┘
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Atomic Deployment
//!
//! MicroVM provides natural atomicity:
//! - All container images pulled and merged into composite rootfs BEFORE VM boot
//! - VM boot is atomic - either succeeds completely or fails
//! - No intermediate states visible to caller
//!
//! # Isolation Level
//!
//! MicroVM provides the strongest isolation:
//! - Separate kernel instance per pod
//! - Hardware-enforced memory isolation (VT-x/AMD-V/HVF)
//! - Minimal attack surface (no shared kernel)

use crate::error::{Error, Result};
use crate::image::{BundleBuilder, ImageService, OciContainerConfig, Os, Platform};
use crate::pod::{
    ContainerStatus, ExecOptions, ExecResult, LogOptions, PodHandle, PodId,
    PodPhase, PodRuntime, PodSpec, PodStatus, PodSummary,
};
use crate::runtime::{KrunRuntime, OciRuntime, Signal};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::RwLock;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::pod::runtime_base_path;

// =============================================================================
// Passt Port Forwarding (MicroVM Networking)
// =============================================================================
//
// passt creates a Unix socket that provides a virtio-net compatible interface.
// The socket fd is passed to libkrun via `krun_set_passt_fd()`.
//
// | Aspect | passt (VMs) |
// |--------|-------------|
// | Target | qemu/libkrun VMs |
// | Mode | Socket fd for virtio-net |
// | Integration | `krun_set_passt_fd()` |
// | Performance | ~28 Gbps TCP |
// =============================================================================

/// Maximum socket path length (Unix socket limit).
const MAX_SOCKET_PATH_LEN: usize = 108;

/// Poll interval for waiting on process startup.
const PASST_STARTUP_POLL_MS: u64 = 50;

/// Maximum wait time for process startup.
const PASST_STARTUP_TIMEOUT_MS: u64 = 5000;

/// Socket path prefix for passt instances.
const PASST_SOCKET_PREFIX: &str = "/tmp/magikrun-passt-";

/// Subdirectory for MicroVM pod bundles under the base path.
const VM_PODS_SUBDIR: &str = "vm-pods";

/// Poll interval when waiting for stop (milliseconds).
const STOP_POLL_INTERVAL_MS: u64 = 100;

// Use shared port forwarding types
use crate::pod::{extract_port_mappings, PortMapping, Protocol, MAX_PORT_MAPPINGS};

// =============================================================================
// PasstForwarder
// =============================================================================

/// Port forwarder for MicroVMs using passt.
///
/// passt creates a Unix socket that provides a virtio-net compatible
/// interface. The socket fd is passed to libkrun via `krun_set_passt_fd()`.
///
/// # Lifecycle
///
/// 1. Create forwarder with pod ID
/// 2. Add port mappings
/// 3. Call `start()` to spawn passt
/// 4. Get `socket_fd()` and pass to libkrun
/// 5. Forwarder cleaned up on Drop
struct PasstForwarder {
    /// Unique identifier for socket path.
    id: String,
    /// Socket path for passt.
    socket_path: PathBuf,
    /// Port mappings.
    mappings: Vec<PortMapping>,
    /// Mapping set for deduplication.
    mapping_set: HashSet<(u16, Protocol)>,
    /// passt child process.
    child: Option<Child>,
    /// Connected socket fd (after start).
    ///
    /// Uses `OwnedFd` for RAII - fd is automatically closed on drop,
    /// preventing leaks if `stop()` is not called.
    socket_fd: Option<OwnedFd>,
}

impl PasstForwarder {
    /// Creates a new passt forwarder for a pod.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier (pod ID) for socket naming.
    ///
    /// # Errors
    ///
    /// Returns error if socket path would be too long.
    fn new(id: &str) -> io::Result<Self> {
        let socket_path = PathBuf::from(format!("{PASST_SOCKET_PREFIX}{id}.sock"));

        if socket_path.to_string_lossy().len() > MAX_SOCKET_PATH_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("socket path exceeds maximum length of {MAX_SOCKET_PATH_LEN}"),
            ));
        }

        Ok(Self {
            id: id.to_string(),
            socket_path,
            mappings: Vec::new(),
            mapping_set: HashSet::new(),
            child: None,
            socket_fd: None,
        })
    }

    /// Adds a port mapping.
    ///
    /// Must be called before `start()`.
    fn add_port(&mut self, mapping: PortMapping) -> io::Result<()> {
        if self.mappings.len() >= MAX_PORT_MAPPINGS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("maximum port mappings ({MAX_PORT_MAPPINGS}) exceeded"),
            ));
        }

        let key = (mapping.host_port, mapping.protocol);
        if self.mapping_set.contains(&key) {
            // Already exists, no-op
            return Ok(());
        }

        self.mapping_set.insert(key);
        self.mappings.push(mapping);

        tracing::debug!(
            id = %self.id,
            mapping = %mapping,
            "Added port mapping to passt forwarder"
        );

        Ok(())
    }

    /// Adds multiple port mappings.
    fn add_ports(&mut self, mappings: &[PortMapping]) -> io::Result<()> {
        for mapping in mappings {
            self.add_port(*mapping)?;
        }
        Ok(())
    }

    /// Returns the socket fd for libkrun.
    ///
    /// Must be called after `start()`. Used with `krun_set_passt_fd()`.
    #[allow(dead_code)] // Will be used when libkrun FFI integration is complete
    fn socket_fd(&self) -> RawFd {
        self.socket_fd.as_ref().map_or(-1, |fd| fd.as_raw_fd())
    }

    /// Returns the socket path.
    fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Starts the passt forwarder.
    ///
    /// Spawns passt and waits for the socket to be ready.
    fn start(&mut self) -> io::Result<()> {
        if self.child.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "passt forwarder already started",
            ));
        }

        // Clean up old socket if exists
        let _ = std::fs::remove_file(&self.socket_path);

        // Build passt command
        let mut cmd = Command::new("passt");

        // Socket mode for libkrun
        cmd.arg("--socket").arg(&self.socket_path);

        // Foreground mode (we manage the process)
        cmd.arg("--foreground");

        // Add TCP port mappings
        for mapping in &self.mappings {
            match mapping.protocol {
                Protocol::Tcp => {
                    cmd.arg("-t")
                        .arg(format!("{}:{}", mapping.host_port, mapping.container_port));
                }
                Protocol::Udp => {
                    cmd.arg("-u")
                        .arg(mapping.as_arg());
                }
            }
        }

        // Suppress output
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        tracing::debug!(
            id = %self.id,
            socket = %self.socket_path.display(),
            mappings = self.mappings.len(),
            "Spawning passt"
        );

        // Spawn passt
        let child = cmd.spawn().map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to spawn passt: {e} (is passt installed?)"),
            )
        })?;

        self.child = Some(child);

        // Connect to passt socket with retry loop (fixes TOCTOU race)
        // Instead of checking if file exists then connecting, we try to connect
        // directly and retry on NotFound/ConnectionRefused.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(PASST_STARTUP_TIMEOUT_MS);

        let socket = loop {
            match std::os::unix::net::UnixStream::connect(&self.socket_path) {
                Ok(s) => break s,
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound
                        || e.kind() == io::ErrorKind::ConnectionRefused =>
                {
                    if std::time::Instant::now() > deadline {
                        // Kill the process if we can't connect
                        if let Some(ref mut child) = self.child {
                            let _ = child.kill();
                        }
                        self.child = None;
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "failed to connect to passt socket within timeout",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(PASST_STARTUP_POLL_MS));
                }
                Err(e) => {
                    // Unexpected error - clean up and propagate
                    if let Some(ref mut child) = self.child {
                        let _ = child.kill();
                    }
                    self.child = None;
                    return Err(e);
                }
            }
        };

        // Convert UnixStream to OwnedFd for RAII (automatic close on drop)
        // SAFETY: into_raw_fd() gives us ownership of the fd, and from_raw_fd
        // takes ownership. No double-close is possible.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(socket.into_raw_fd()) };
        let fd = owned_fd.as_raw_fd();

        self.socket_fd = Some(owned_fd);

        tracing::info!(
            id = %self.id,
            socket_fd = fd,
            mappings = self.mappings.len(),
            "passt forwarder started"
        );

        Ok(())
    }

    /// Stops the passt forwarder.
    fn stop(&mut self) -> io::Result<()> {
        // Close the socket fd - OwnedFd handles close automatically via Drop
        // Taking the Option ensures we don't try to use it again
        drop(self.socket_fd.take());

        // Kill passt process
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;

        // Clean up socket file
        let _ = std::fs::remove_file(&self.socket_path);

        tracing::info!(id = %self.id, "passt forwarder stopped");

        Ok(())
    }
}

impl Drop for PasstForwarder {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// =============================================================================
// MicroVM Pod Runtime
// =============================================================================

/// MicroVM pod runtime using libkrun.
///
/// Implements atomic pod deployment with hardware-level isolation.
/// Available on Linux (KVM) and macOS (Hypervisor.framework).
pub struct MicroVmPodRuntime {
    /// OCI runtime for VM operations.
    runtime: KrunRuntime,
    /// Image service for pulling images.
    image_service: ImageService,
    /// Bundle builder for creating OCI bundles.
    bundle_builder: BundleBuilder,
    /// Pod ID → VmPodState mapping.
    pods: RwLock<HashMap<PodId, VmPodState>>,
}

/// Internal MicroVM pod state.
///
/// NOTE: This struct intentionally does NOT derive Clone or Serialize because
/// it owns the PasstForwarder which contains a process handle (Child) that
/// cannot be cloned or serialized. The forwarder must be explicitly cleaned
/// up when the pod is deleted.
struct VmPodState {
    /// Pod specification.
    spec: PodSpec,
    /// VM container ID.
    vm_id: String,
    /// Control port for passt-based control protocol (if available).
    control_port: Option<u16>,
    /// Passt forwarder for networking (owns the passt process).
    ///
    /// RESOURCE OWNERSHIP: This field owns the passt child process.
    /// It MUST be explicitly stopped in delete_pod and cleanup_failed_pod
    /// to prevent process leaks.
    passt_forwarder: Option<PasstForwarder>,
    /// Container names in this pod.
    container_names: Vec<String>,
    /// Bundle path (for cleanup).
    bundle_path: PathBuf,
    /// Current phase.
    phase: PodPhase,
    /// Started timestamp.
    started_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl MicroVmPodRuntime {
    /// Creates a new MicroVM pod runtime.
    ///
    /// # Errors
    ///
    /// Returns error if the image service or bundle builder cannot be initialized.
    pub fn new() -> Result<Self> {
        let image_service = ImageService::new()
            .map_err(|e| Error::Internal(format!("failed to create image service: {e}")))?;
        let bundle_builder = BundleBuilder::with_storage(image_service.storage().clone())
            .map_err(|e| Error::Internal(format!("failed to create bundle builder: {e}")))?;

        Ok(Self {
            runtime: KrunRuntime::new(),
            image_service,
            bundle_builder,
            pods: RwLock::new(HashMap::new()),
        })
    }

    /// Returns the Linux target platform for MicroVM images.
    ///
    /// MicroVMs always run Linux kernel regardless of host OS.
    fn linux_target_platform() -> Platform {
        let host = Platform::detect();
        Platform {
            os: Os::Linux,
            arch: host.arch,
            kernel_version: None,
            capabilities: std::collections::HashSet::new(),
        }
    }

    /// Copies a directory recursively, preserving symlinks.
    fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
        if !src.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("source directory does not exist: {}", src.display()),
            ));
        }
        if !dst.exists() {
            std::fs::create_dir_all(dst)?;
        }
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            let file_type = entry.file_type()?;

            if file_type.is_symlink() {
                // Preserve symlinks - read the link target and recreate
                let link_target = std::fs::read_link(&src_path)?;
                // Remove destination if it exists (symlinks need to be recreated)
                let _ = std::fs::remove_file(&dst_path);
                #[cfg(unix)]
                std::os::unix::fs::symlink(&link_target, &dst_path)?;
                #[cfg(not(unix))]
                {
                    // On non-Unix, fall back to copying the target file
                    if let Ok(metadata) = std::fs::metadata(&src_path) {
                        if metadata.is_dir() {
                            Self::copy_dir_recursive(&src_path, &dst_path)?;
                        } else {
                            std::fs::copy(&src_path, &dst_path)?;
                        }
                    }
                }
            } else if file_type.is_dir() {
                Self::copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }

    /// Cleans up all resources for a failed pod.
    ///
    /// Takes ownership of state to ensure passt_forwarder is dropped.
    async fn cleanup_failed_pod(&self, mut state: VmPodState) {
        // Stop passt forwarder first (releases network resources)
        if let Some(mut forwarder) = state.passt_forwarder.take()
            && let Err(e) = forwarder.stop()
        {
            tracing::warn!(vm_id = %state.vm_id, error = %e, "Failed to stop passt forwarder");
        }

        // Kill and delete VM
        let _ = self.runtime.kill(&state.vm_id, Signal::Kill, true).await;
        let _ = self.runtime.delete(&state.vm_id, true).await;

        // Clean up bundle directory
        let _ = std::fs::remove_dir_all(&state.bundle_path);
    }
}

#[async_trait]
impl PodRuntime for MicroVmPodRuntime {
    fn runtime_class(&self) -> &'static str {
        "pod-microvm"
    }

    async fn run_pod(&self, spec: &PodSpec) -> Result<PodHandle> {
        let pod_id = PodId::from_pod(&spec.namespace, &spec.name);
        let vm_id = format!("{}-vm", pod_id.as_str());
        let pod_dir = runtime_base_path().join(VM_PODS_SUBDIR).join(&vm_id);
        let rootfs_path = pod_dir.join("rootfs");

        // Check capacity and reserve slot atomically
        {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;

            if pods.contains_key(&pod_id) {
                return Err(Error::ContainerAlreadyExists(pod_id.to_string()));
            }

            if pods.len() >= crate::pod::MAX_PODS {
                return Err(Error::ResourceExhausted(
                    "maximum pod count reached".to_string(),
                ));
            }

            // Reserve slot
            pods.insert(
                pod_id.clone(),
                VmPodState {
                    spec: spec.clone(),
                    vm_id: vm_id.clone(),
                    control_port: None,
                    passt_forwarder: None,
                    container_names: Vec::new(),
                    bundle_path: pod_dir.clone(),
                    phase: PodPhase::Pending,
                    started_at: None,
                },
            );
        }

        // Create bundle directory
        if let Err(e) = std::fs::create_dir_all(&rootfs_path) {
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::BundleBuildFailed(format!(
                "failed to create VM bundle directory: {e}"
            )));
        }

        let mut state = VmPodState {
            spec: spec.clone(),
            vm_id: vm_id.clone(),
            control_port: None,    // Will be set after passt spawns
            passt_forwarder: None, // Will be set after passt spawns
            container_names: spec.containers.iter().map(|c| c.name.clone()).collect(),
            bundle_path: pod_dir.clone(),
            phase: PodPhase::Pending,
            started_at: None,
        };

        // =========================================================================
        // PHASE 1: PREPARE (Pull ALL images, build composite rootfs)
        // =========================================================================

        // For MicroVM, we always pull Linux images since the VM runs Linux kernel
        let linux_platform = Self::linux_target_platform();

        // Pull all images and merge into composite rootfs
        // The first container's image forms the base, others are overlaid
        for container_spec in &spec.containers {
            tracing::info!(
                pod = %pod_id,
                image = %container_spec.image,
                container = %container_spec.name,
                "Pulling image for MicroVM pod"
            );

            let image = match self
                .image_service
                .pull_for_platform(&container_spec.image, &linux_platform)
                .await
            {
                Ok(img) => img,
                Err(e) => {
                    let image_ref = container_spec.image.clone();
                    let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                    self.cleanup_failed_pod(state).await;
                    return Err(Error::ImagePullFailed {
                        reference: image_ref,
                        reason: e.to_string(),
                    });
                }
            };

            // Build command from spec
            let mut full_command = Vec::new();
            if let Some(ref cmd) = container_spec.command {
                full_command.extend(cmd.clone());
            }
            if let Some(ref args) = container_spec.args {
                full_command.extend(args.clone());
            }

            // VM mode: containers share VM's network (isolated by hardware)
            let config = OciContainerConfig {
                name: container_spec.name.clone(),
                command: if full_command.is_empty() {
                    None
                } else {
                    Some(full_command)
                },
                env: container_spec.env.clone(),
                working_dir: container_spec.working_dir.clone(),
                user_id: None,
                group_id: None,
                hostname: spec.hostname.clone(),
                vm_mode: true, // Skip network namespace - VM provides isolation
            };

            let bundle = match self.bundle_builder.build_oci_bundle(&image, &config) {
                Ok(b) => b,
                Err(e) => {
                    let container_name = container_spec.name.clone();
                    let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                    self.cleanup_failed_pod(state).await;
                    return Err(Error::BundleBuildFailed(format!(
                        "failed to build bundle for {container_name}: {e}"
                    )));
                }
            };

            // Create container bundle structure inside VM rootfs:
            // /rootfs/containers/<name>/rootfs/ + config.json
            let container_bundle_dir = rootfs_path.join("containers").join(&container_spec.name);
            let container_rootfs_dir = container_bundle_dir.join("rootfs");

            if let Err(e) = std::fs::create_dir_all(&container_rootfs_dir) {
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                self.cleanup_failed_pod(state).await;
                return Err(Error::BundleBuildFailed(format!(
                    "failed to create container bundle dir: {e}"
                )));
            }

            // Copy container's rootfs into the bundle structure
            if let Some(src_rootfs) = bundle.rootfs()
                && let Err(e) = Self::copy_dir_recursive(src_rootfs, &container_rootfs_dir)
            {
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                self.cleanup_failed_pod(state).await;
                return Err(Error::BundleBuildFailed(format!(
                    "failed to copy rootfs for {}: {e}",
                    container_spec.name
                )));
            }

            // Copy config.json from the built bundle
            let src_config = bundle.path().join("config.json");
            let dst_config = container_bundle_dir.join("config.json");
            if let Err(e) = std::fs::copy(&src_config, &dst_config) {
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                self.cleanup_failed_pod(state).await;
                return Err(Error::BundleBuildFailed(format!(
                    "failed to copy config.json for {}: {e}",
                    container_spec.name
                )));
            }

            tracing::debug!(
                container = %container_spec.name,
                bundle_dir = %container_bundle_dir.display(),
                "Container bundle prepared inside VM rootfs"
            );
        }

        tracing::info!(
            pod = %pod_id,
            vm_id = %vm_id,
            bundle = %pod_dir.display(),
            "MicroVM bundle prepared with per-container bundles"
        );

        // =========================================================================
        // PHASE 1.5: SPAWN PASST (Network setup before VM boot)
        // =========================================================================

        // Extract port mappings from all containers using shared port_forward module
        let port_result = extract_port_mappings(&spec.containers);

        if port_result.skipped_invalid > 0 {
            tracing::warn!(
                pod = %pod_id,
                skipped = port_result.skipped_invalid,
                "Skipped invalid port mappings (port 0 not allowed)"
            );
        }

        if port_result.skipped_duplicates > 0 {
            tracing::warn!(
                pod = %pod_id,
                skipped = port_result.skipped_duplicates,
                "Skipped duplicate port mappings"
            );
        }

        if port_result.limit_reached {
            tracing::warn!(
                pod = %pod_id,
                max = MAX_PORT_MAPPINGS,
                "Port mapping limit reached, some mappings were dropped"
            );
        }

        let mut port_mappings = port_result.mappings;

        // Always add control port for exec/logs
        const CONTROL_GUEST_PORT: u16 = 1024;
        let control_host_port = 10000 + (std::process::id() as u16 % 50000); // Dynamic port
        port_mappings.insert(0, PortMapping::tcp(control_host_port, CONTROL_GUEST_PORT));

        // Create passt forwarder for MicroVM networking
        let mut passt_forwarder = match PasstForwarder::new(&vm_id) {
            Ok(f) => f,
            Err(e) => {
                let err_vm_id = vm_id.clone();
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                self.cleanup_failed_pod(state).await;
                return Err(Error::StartFailed {
                    id: err_vm_id,
                    reason: format!("failed to create passt forwarder: {e}"),
                });
            }
        };

        // Add all port mappings
        if let Err(e) = passt_forwarder.add_ports(&port_mappings) {
            let err_vm_id = vm_id.clone();
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            self.cleanup_failed_pod(state).await;
            return Err(Error::StartFailed {
                id: err_vm_id,
                reason: format!("failed to add port mappings: {e}"),
            });
        }

        // Start passt forwarder
        if let Err(e) = passt_forwarder.start() {
            let err_vm_id = vm_id.clone();
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            self.cleanup_failed_pod(state).await;
            return Err(Error::StartFailed {
                id: err_vm_id,
                reason: format!("failed to spawn passt: {e}"),
            });
        }

        tracing::info!(
            pod = %pod_id,
            control_port = control_host_port,
            port_mappings = ?port_mappings,
            "passt forwarder started for MicroVM networking"
        );

        // Write passt socket path to a file that the CLI can read
        let passt_info_path = pod_dir.join("passt.sock");
        if let Err(e) = std::fs::write(
            &passt_info_path,
            passt_forwarder.socket_path().to_string_lossy().as_bytes(),
        ) {
            tracing::warn!("Failed to write passt socket path: {e}");
        }

        // Update state with passt info - store forwarder to ensure proper cleanup
        state.control_port = Some(control_host_port);
        state.passt_forwarder = Some(passt_forwarder);

        // =========================================================================
        // PHASE 2: COMMIT (Boot VM - atomic operation)
        // =========================================================================

        if let Err(e) = self.runtime.create(&vm_id, &pod_dir).await {
            let err_vm_id = vm_id.clone();
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            self.cleanup_failed_pod(state).await;
            return Err(Error::CreateFailed {
                id: err_vm_id,
                reason: e.to_string(),
            });
        }

        if let Err(e) = self.runtime.start(&vm_id).await {
            let err_vm_id = vm_id.clone();
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            self.cleanup_failed_pod(state).await;
            return Err(Error::StartFailed {
                id: err_vm_id,
                reason: e.to_string(),
            });
        }

        // VM is now running - pod is running
        state.phase = PodPhase::Running;
        state.started_at = Some(chrono::Utc::now());

        // Update state in registry
        {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            pods.insert(pod_id.clone(), state);
        }

        Ok(PodHandle {
            id: pod_id,
            runtime_class: self.runtime_class().to_string(),
        })
    }

    async fn stop_pod(&self, id: &PodId, grace_period: Duration) -> Result<()> {
        let vm_id = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            let state = pods
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;
            state.vm_id.clone()
        };

        // Send SIGTERM to VM
        let _ = self.runtime.kill(&vm_id, Signal::Term, true).await;

        // Wait for grace period
        let start = std::time::Instant::now();
        while start.elapsed() < grace_period {
            if let Ok(state) = self.runtime.state(&vm_id).await {
                if state.status != crate::runtime::ContainerStatus::Running {
                    break;
                }
            } else {
                // VM is gone
                break;
            }
            tokio::time::sleep(Duration::from_millis(STOP_POLL_INTERVAL_MS)).await;
        }

        // Force kill if still running
        let _ = self.runtime.kill(&vm_id, Signal::Kill, true).await;

        // Update phase
        {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            if let Some(state) = pods.get_mut(id) {
                state.phase = PodPhase::Succeeded;
            }
        }

        Ok(())
    }

    async fn delete_pod(&self, id: &PodId, force: bool) -> Result<()> {
        let mut state = {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            pods.remove(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?
        };

        // Stop passt forwarder first (releases network resources)
        // This must happen before VM deletion to ensure clean shutdown.
        if let Some(mut forwarder) = state.passt_forwarder.take() {
            if let Err(e) = forwarder.stop() {
                tracing::warn!(pod = %id, error = %e, "Failed to stop passt forwarder");
            } else {
                tracing::debug!(pod = %id, "Stopped passt forwarder");
            }
        }

        // Kill and delete VM
        if force {
            let _ = self.runtime.kill(&state.vm_id, Signal::Kill, true).await;
        }
        let _ = self.runtime.delete(&state.vm_id, force).await;

        // Clean up bundle directory
        let _ = std::fs::remove_dir_all(&state.bundle_path);

        Ok(())
    }

    async fn pod_status(&self, id: &PodId) -> Result<PodStatus> {
        // Extract data from lock before any await points
        let (phase, started_at, vm_id, container_names) = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;

            let state = pods
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            (
                state.phase,
                state.started_at,
                state.vm_id.clone(),
                state.container_names.clone(),
            )
        };

        // Check VM status (now outside the lock)
        let vm_status = match self.runtime.state(&vm_id).await {
            Ok(s) => s.status,
            Err(_) => crate::runtime::ContainerStatus::Stopped,
        };

        // All containers in VM share the VM's status
        let container_status = match vm_status {
            crate::runtime::ContainerStatus::Running => ContainerStatus::Running,
            crate::runtime::ContainerStatus::Created
            | crate::runtime::ContainerStatus::Creating => ContainerStatus::Waiting {
                reason: "VMCreated".to_string(),
            },
            crate::runtime::ContainerStatus::Stopped => ContainerStatus::Terminated {
                exit_code: 0,
                reason: "VMStopped".to_string(),
            },
        };

        let mut container_statuses = HashMap::new();
        for name in &container_names {
            container_statuses.insert(name.clone(), container_status.clone());
        }

        Ok(PodStatus {
            phase,
            containers: container_statuses,
            started_at,
            finished_at: None,
            message: None,
        })
    }

    async fn list_pods(&self) -> Result<Vec<PodSummary>> {
        let pods = self
            .pods
            .read()
            .map_err(|_| Error::Internal("lock poisoned".to_string()))?;

        let summaries = pods
            .iter()
            .map(|(id, state)| PodSummary {
                id: id.clone(),
                namespace: state.spec.namespace.clone(),
                name: state.spec.name.clone(),
                phase: state.phase,
                runtime_class: self.runtime_class().to_string(),
                container_count: state.container_names.len(),
                labels: state.spec.labels.clone(),
                created_at: state.started_at,
            })
            .collect();

        Ok(summaries)
    }

    // =========================================================================
    // Day-2 Operations via passt Control Protocol
    // =========================================================================

    async fn exec(
        &self,
        id: &PodId,
        container: &str,
        command: &[String],
        options: ExecOptions,
    ) -> Result<ExecResult> {
        // Get control port from pod state
        let (control_port, container_names) = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;

            let state = pods
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            (state.control_port, state.container_names.clone())
        };

        // Validate container exists in pod
        if !container_names.contains(&container.to_string()) {
            return Err(Error::ContainerNotFound(format!(
                "container '{}' not found in pod",
                container
            )));
        }

        // Check if we have control port
        let port = control_port.ok_or_else(|| {
            Error::NotSupported(
                "exec not available: control port not assigned (vminit may not be running)"
                    .to_string(),
            )
        })?;

        // Create control client and execute
        let client = ControlClient::new(port);

        match client.exec(container, command.to_vec(), options.tty).await {
            Ok(result) => {
                tracing::debug!(
                    pod = %id,
                    container = %container,
                    exit_code = result.exit_code,
                    "exec completed"
                );
                Ok(ExecResult {
                    exit_code: Some(result.exit_code),
                    stdout: Some(result.stdout.into_bytes()),
                    stderr: Some(result.stderr.into_bytes()),
                })
            }
            Err(e) => Err(Error::Internal(format!("control exec failed: {e}"))),
        }
    }

    async fn logs(&self, id: &PodId, container: &str, options: LogOptions) -> Result<Vec<u8>> {
        // Get control port from pod state
        let (control_port, container_names) = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;

            let state = pods
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            (state.control_port, state.container_names.clone())
        };

        // Validate container exists in pod
        if !container_names.contains(&container.to_string()) {
            return Err(Error::ContainerNotFound(format!(
                "container '{}' not found in pod",
                container
            )));
        }

        // Check if we have control port
        let port = control_port.ok_or_else(|| {
            Error::NotSupported(
                "logs not available: control port not assigned (vminit may not be running)"
                    .to_string(),
            )
        })?;

        // Create control client and request logs
        let client = ControlClient::new(port);

        match client
            .logs(container, options.follow, options.tail_lines)
            .await
        {
            Ok(result) => {
                // Join log lines with newlines
                let output = result.lines.join("\n");
                Ok(output.into_bytes())
            }
            Err(e) => Err(Error::Internal(format!("control logs failed: {e}"))),
        }
    }
}

// =============================================================================
// Control Protocol (for exec/logs with vminit inside MicroVMs)
// =============================================================================

/// Default timeout for control requests (30 seconds).
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum container name length.
const MAX_CONTAINER_NAME_LEN: usize = 63;

/// Maximum command argument length.
const MAX_COMMAND_ARG_LEN: usize = 4096;

/// Maximum number of command arguments.
const MAX_COMMAND_ARGS: usize = 256;

/// Control client for exec/logs operations with MicroVM vminit.
struct ControlClient {
    addr: SocketAddr,
    timeout: Duration,
}

impl ControlClient {
    fn new(host_port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], host_port)),
            timeout: CONTROL_TIMEOUT,
        }
    }

    async fn exec(
        &self,
        container: &str,
        command: Vec<String>,
        tty: bool,
    ) -> std::result::Result<ControlExecResult, ControlError> {
        validate_container_name(container)?;
        validate_command(&command)?;

        let request = ControlRequest::Exec(ControlExecRequest {
            container: container.to_string(),
            command,
            stdin: true,
            stdout: true,
            stderr: true,
            tty,
        });

        let response = self.send_request(&request).await?;

        match response {
            ControlResponse::Ok(payload) => match payload.data {
                Some(ControlResponseData::ExecOutput {
                    exit_code,
                    stdout,
                    stderr,
                }) => Ok(ControlExecResult {
                    exit_code,
                    stdout,
                    stderr,
                }),
                Some(ControlResponseData::ExecSession { session_id }) => Ok(ControlExecResult {
                    exit_code: 0,
                    stdout: format!("session_id: {session_id}"),
                    stderr: String::new(),
                }),
                other => Err(ControlError::UnexpectedResponse(format!(
                    "expected ExecOutput, got {other:?}"
                ))),
            },
            ControlResponse::Error(e) => Err(ControlError::VminitError(format!(
                "{:?}: {}",
                e.code, e.message
            ))),
        }
    }

    async fn logs(
        &self,
        container: &str,
        follow: bool,
        tail: u32,
    ) -> std::result::Result<ControlLogsResult, ControlError> {
        validate_container_name(container)?;

        let request = ControlRequest::Logs(ControlLogsRequest {
            container: container.to_string(),
            follow,
            tail_lines: tail,
            timestamps: false,
        });

        let response = self.send_request(&request).await?;

        match response {
            ControlResponse::Ok(payload) => match payload.data {
                Some(ControlResponseData::LogOutput { lines }) => Ok(ControlLogsResult { lines }),
                None => Ok(ControlLogsResult { lines: Vec::new() }),
                other => Err(ControlError::UnexpectedResponse(format!(
                    "expected LogOutput, got {other:?}"
                ))),
            },
            ControlResponse::Error(e) => Err(ControlError::VminitError(format!(
                "{:?}: {}",
                e.code, e.message
            ))),
        }
    }

    async fn send_request(
        &self,
        request: &ControlRequest,
    ) -> std::result::Result<ControlResponse, ControlError> {
        let stream = timeout(self.timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| ControlError::Timeout)?
            .map_err(|e| ControlError::ConnectionFailed(e.to_string()))?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        let mut json = serde_json::to_string(request)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        writer.flush().await?;

        let mut response_line = String::new();
        timeout(self.timeout, reader.read_line(&mut response_line))
            .await
            .map_err(|_| ControlError::Timeout)??;

        let response: ControlResponse = serde_json::from_str(response_line.trim())?;
        Ok(response)
    }
}

fn validate_container_name(name: &str) -> std::result::Result<(), ControlError> {
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
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ControlError::InvalidInput(
            "container name contains invalid characters".into(),
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(ControlError::InvalidInput(
            "container name cannot start or end with hyphen".into(),
        ));
    }
    Ok(())
}

fn validate_command(command: &[String]) -> std::result::Result<(), ControlError> {
    if command.is_empty() {
        return Err(ControlError::InvalidInput("command cannot be empty".into()));
    }
    if command.len() > MAX_COMMAND_ARGS {
        return Err(ControlError::InvalidInput(format!(
            "too many command arguments ({} > {MAX_COMMAND_ARGS})",
            command.len()
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

struct ControlExecResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

struct ControlLogsResult {
    lines: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
enum ControlError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("request timed out")]
    Timeout,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("vminit error: {0}")]
    VminitError(String),
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// Protocol types (must match vminit's definitions)

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum ControlRequest {
    Exec(ControlExecRequest),
    Logs(ControlLogsRequest),
}

#[derive(Serialize, Deserialize)]
struct ControlExecRequest {
    container: String,
    command: Vec<String>,
    stdin: bool,
    stdout: bool,
    stderr: bool,
    tty: bool,
}

#[derive(Serialize, Deserialize)]
struct ControlLogsRequest {
    container: String,
    follow: bool,
    tail_lines: u32,
    timestamps: bool,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ControlResponse {
    Ok(ControlOkPayload),
    Error(ControlErrorPayload),
}

#[derive(Deserialize)]
struct ControlOkPayload {
    data: Option<ControlResponseData>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlResponseData {
    // Note: version and container_count are wire protocol fields for future use
    Pong {
        #[allow(dead_code)]
        version: String,
        #[allow(dead_code)]
        container_count: usize,
    },
    ExecSession {
        session_id: String,
    },
    ExecOutput {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    LogOutput {
        lines: Vec<String>,
    },
    // Note: timestamp and line are wire protocol fields for future use
    LogLine {
        #[allow(dead_code)]
        timestamp: Option<String>,
        #[allow(dead_code)]
        line: String,
    },
}

#[derive(Debug, Deserialize)]
struct ControlErrorPayload {
    code: ControlErrorCode,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlErrorCode {
    ContainerNotFound,
    ContainerNotRunning,
    ExecFailed,
    Internal,
    Timeout,
    InvalidRequest,
}
