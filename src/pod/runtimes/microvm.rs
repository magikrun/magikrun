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
use crate::passt::ControlClient;
use crate::pod::{
    ContainerStatus, ExecOptions, ExecResult, LogOptions, PodHandle, PodId, PodPhase, PodRuntime,
    PodSpec, PodStatus, PodSummary,
};
use crate::runtime::{KrunRuntime, OciRuntime, Signal};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use crate::pod::runtime_base_path;

/// Subdirectory for MicroVM pod bundles under the base path.
const VM_PODS_SUBDIR: &str = "vm-pods";

/// Poll interval when waiting for stop (milliseconds).
const STOP_POLL_INTERVAL_MS: u64 = 100;

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
struct VmPodState {
    /// Pod specification.
    spec: PodSpec,
    /// VM container ID.
    vm_id: String,
    /// Control port for TSI communication via passt (if available).
    control_port: Option<u16>,
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
    async fn cleanup_failed_pod(&self, state: &VmPodState) {
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
            control_port: None, // Will be set after VM boot when passt is ready
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
        for (idx, container_spec) in spec.containers.iter().enumerate() {
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
                    self.cleanup_failed_pod(&state).await;
                    let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                    return Err(Error::ImagePullFailed {
                        reference: container_spec.image.clone(),
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
            };

            let bundle = match self.bundle_builder.build_oci_bundle(&image, &config) {
                Ok(b) => b,
                Err(e) => {
                    self.cleanup_failed_pod(&state).await;
                    let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                    return Err(Error::BundleBuildFailed(format!(
                        "failed to build bundle for {}: {}",
                        container_spec.name, e
                    )));
                }
            };

            // For the first container, copy the full rootfs
            // For subsequent containers, merge/overlay
            if let Some(src_rootfs) = bundle.rootfs() {
                if idx == 0 {
                    // First container: copy entire rootfs
                    if let Err(e) = Self::copy_dir_recursive(src_rootfs, &rootfs_path) {
                        self.cleanup_failed_pod(&state).await;
                        let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                        return Err(Error::BundleBuildFailed(format!(
                            "failed to copy rootfs: {e}"
                        )));
                    }
                } else {
                    // Subsequent containers: merge into existing rootfs
                    // TODO: Proper overlay/union mount or container-specific dirs
                    if let Err(e) = Self::copy_dir_recursive(src_rootfs, &rootfs_path) {
                        tracing::warn!(
                            "Failed to merge rootfs for {}: {} (continuing with base)",
                            container_spec.name,
                            e
                        );
                    }
                }
            }
        }

        tracing::info!(
            pod = %pod_id,
            vm_id = %vm_id,
            bundle = %pod_dir.display(),
            "MicroVM bundle prepared"
        );

        // =========================================================================
        // PHASE 2: COMMIT (Boot VM - atomic operation)
        // =========================================================================

        if let Err(e) = self.runtime.create(&vm_id, &pod_dir).await {
            self.cleanup_failed_pod(&state).await;
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::CreateFailed {
                id: vm_id.clone(),
                reason: e.to_string(),
            });
        }

        if let Err(e) = self.runtime.start(&vm_id).await {
            self.cleanup_failed_pod(&state).await;
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::StartFailed {
                id: vm_id.clone(),
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
        let state = {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            pods.remove(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?
        };

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
    // Day-2 Operations via TSI
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
