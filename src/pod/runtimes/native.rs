//! Native pod runtime using youki + pause container.
//!
//! This runtime creates pods using native Linux containers with the
//! pause container pattern for namespace sharing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Pod (NativePodRuntime)                                        │
//! │                                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  Pause Container (holds namespaces)                       │  │
//! │  │  PID namespace root, network, IPC, UTS                    │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │         ▲           ▲           ▲           ▲                   │
//! │         │           │           │           │ (join namespaces) │
//! │  ┌──────┴──┐  ┌─────┴───┐  ┌────┴────┐  ┌───┴─────┐            │
//! │  │Container│  │Container│  │Container│  │Container│            │
//! │  │   A     │  │   B     │  │   C     │  │   D     │            │
//! │  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Atomic Deployment
//!
//! Unlike the old CRI model (RunPodSandbox → CreateContainer → StartContainer),
//! `run_pod()` is atomic:
//!
//! 1. **Prepare Phase**: Pull all images, build all bundles
//! 2. **Commit Phase**: Start pause container, start all workloads
//! 3. **Rollback on failure**: Delete everything if any step fails
//!
//! The caller never sees intermediate states.

use crate::error::{Error, Result};
use crate::image::{BundleBuilder, ImageService, OciContainerConfig};
use crate::pod::{
    ContainerStatus, DEFAULT_GRACE_PERIOD_SECS, PodHandle, PodId, PodPhase, PodRuntime, PodSpec,
    PodStatus, PodSummary,
};
use crate::runtime::{NativeRuntime, OciRuntime, Signal};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Base path for pod bundles.
const BUNDLE_BASE_PATH: &str = "/var/run/magikrun/pods";

/// Poll interval when waiting for container stop (milliseconds).
const STOP_POLL_INTERVAL_MS: u64 = 100;

/// Native pod runtime using Linux containers.
///
/// Implements atomic pod deployment with namespace sharing via pause containers.
/// Only available on Linux with cgroup v2.
pub struct NativePodRuntime {
    /// OCI runtime for container operations.
    runtime: NativeRuntime,
    /// Image service for pulling images.
    image_service: ImageService,
    /// Bundle builder for creating OCI bundles.
    bundle_builder: BundleBuilder,
    /// Pod ID → PodState mapping.
    pods: RwLock<HashMap<PodId, PodState>>,
}

/// Internal pod state for tracking.
struct PodState {
    /// Pod specification (immutable after creation).
    spec: PodSpec,
    /// Pause container ID.
    pause_container_id: String,
    /// Pause container PID (for namespace paths).
    pause_pid: Option<u32>,
    /// Workload container IDs (name → container ID).
    containers: HashMap<String, String>,
    /// Bundle paths (for cleanup).
    bundle_paths: Vec<PathBuf>,
    /// Current phase.
    phase: PodPhase,
    /// Started timestamp.
    started_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl NativePodRuntime {
    /// Creates a new native pod runtime.
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
            runtime: NativeRuntime::new(),
            image_service,
            bundle_builder,
            pods: RwLock::new(HashMap::new()),
        })
    }

    /// Gets namespace paths from pause container PID.
    #[allow(dead_code)] // Infrastructure for namespace sharing - will be used when container joining is implemented
    fn namespace_paths(pid: u32) -> NamespacePaths {
        let base = format!("/proc/{pid}/ns");
        NamespacePaths {
            network: format!("{base}/net"),
            ipc: format!("{base}/ipc"),
            uts: format!("{base}/uts"),
            pid: format!("{base}/pid"),
        }
    }

    /// Cleans up all resources for a failed pod deployment.
    async fn cleanup_failed_pod(&self, state: &PodState) {
        // Delete all workload containers
        for container_id in state.containers.values() {
            let _ = self.runtime.kill(container_id, Signal::Kill, true).await;
            let _ = self.runtime.delete(container_id, true).await;
        }

        // Delete pause container
        let _ = self
            .runtime
            .kill(&state.pause_container_id, Signal::Kill, true)
            .await;
        let _ = self.runtime.delete(&state.pause_container_id, true).await;

        // Clean up bundle directories
        for path in &state.bundle_paths {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

/// Namespace paths for container joining.
#[allow(dead_code)] // Infrastructure for namespace sharing - will be used when container joining is implemented
struct NamespacePaths {
    network: String,
    ipc: String,
    uts: String,
    pid: String,
}

#[async_trait]
impl PodRuntime for NativePodRuntime {
    fn runtime_class(&self) -> &'static str {
        "pod-containers"
    }

    async fn run_pod(&self, spec: &PodSpec) -> Result<PodHandle> {
        let pod_id = PodId::from_pod(&spec.namespace, &spec.name);
        let pod_dir = Path::new(BUNDLE_BASE_PATH).join(pod_id.as_str());

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
                PodState {
                    spec: spec.clone(),
                    pause_container_id: String::new(),
                    pause_pid: None,
                    containers: HashMap::new(),
                    bundle_paths: Vec::new(),
                    phase: PodPhase::Pending,
                    started_at: None,
                },
            );
        }

        // Create pod directory
        if let Err(e) = std::fs::create_dir_all(&pod_dir) {
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::BundleBuildFailed(format!(
                "failed to create pod directory: {e}"
            )));
        }

        // Build state for tracking (will be updated as we go)
        let mut state = PodState {
            spec: spec.clone(),
            pause_container_id: format!("{}-pause", pod_id.as_str()),
            pause_pid: None,
            containers: HashMap::new(),
            bundle_paths: vec![pod_dir.clone()],
            phase: PodPhase::Pending,
            started_at: None,
        };

        // =========================================================================
        // PHASE 1: PREPARE (Pull images, build bundles - no runtime state created)
        // =========================================================================

        // Build pause container bundle
        // TODO: Use a minimal pause image (gcr.io/google_containers/pause:3.9)
        // For now, we create a minimal bundle manually
        let pause_bundle = pod_dir.join("pause");
        let pause_rootfs = pause_bundle.join("rootfs");
        if let Err(e) = std::fs::create_dir_all(&pause_rootfs) {
            self.cleanup_failed_pod(&state).await;
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::BundleBuildFailed(format!(
                "failed to create pause rootfs: {e}"
            )));
        }

        // Pull all container images and build bundles BEFORE starting anything
        let mut container_bundles: Vec<(String, PathBuf)> = Vec::new();

        for container_spec in &spec.containers {
            tracing::info!(
                pod = %pod_id,
                image = %container_spec.image,
                container = %container_spec.name,
                "Pulling image for pod container"
            );

            let image = match self.image_service.pull(&container_spec.image).await {
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

            let container_id = format!("{}-{}", pod_id.as_str(), container_spec.name);
            container_bundles.push((container_id.clone(), bundle.path().to_path_buf()));
            state.bundle_paths.push(bundle.path().to_path_buf());
        }

        // =========================================================================
        // PHASE 2: COMMIT (Start containers - runtime state created)
        // =========================================================================

        // Create and start pause container
        // TODO: Generate proper config.json for pause container
        // For now, this requires the bundle to exist with config.json
        if let Err(e) = self
            .runtime
            .create(&state.pause_container_id, &pause_bundle)
            .await
        {
            self.cleanup_failed_pod(&state).await;
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::CreateFailed {
                id: state.pause_container_id.clone(),
                reason: e.to_string(),
            });
        }

        if let Err(e) = self.runtime.start(&state.pause_container_id).await {
            self.cleanup_failed_pod(&state).await;
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::StartFailed {
                id: state.pause_container_id.clone(),
                reason: e.to_string(),
            });
        }

        // Get pause container PID for namespace paths
        if let Ok(pause_state) = self.runtime.state(&state.pause_container_id).await {
            state.pause_pid = pause_state.pid;
        }

        // Start all workload containers
        for (container_id, bundle_path) in &container_bundles {
            // TODO: Inject namespace paths into config.json to join pause container's namespaces
            // This requires modifying the OCI spec before container creation

            if let Err(e) = self.runtime.create(container_id, bundle_path).await {
                self.cleanup_failed_pod(&state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::CreateFailed {
                    id: container_id.clone(),
                    reason: e.to_string(),
                });
            }

            if let Err(e) = self.runtime.start(container_id).await {
                self.cleanup_failed_pod(&state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::StartFailed {
                    id: container_id.clone(),
                    reason: e.to_string(),
                });
            }

            // Extract container name from ID
            let name = container_id
                .strip_prefix(&format!("{}-", pod_id.as_str()))
                .unwrap_or(container_id)
                .to_string();
            state.containers.insert(name, container_id.clone());
        }

        // Pod is now running
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
        let state = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            pods.get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;
            // Can't hold the lock across await points, so we need to get container IDs
            let container_ids: Vec<String> = pods
                .get(id)
                .map(|s| s.containers.values().cloned().collect())
                .unwrap_or_default();
            container_ids
        };

        let grace_secs = grace_period
            .as_secs()
            .try_into()
            .unwrap_or(DEFAULT_GRACE_PERIOD_SECS);

        // Stop all workload containers with grace period
        for container_id in &state {
            // Send SIGTERM
            let _ = self.runtime.kill(container_id, Signal::Term, true).await;
        }

        // Wait for grace period
        let start = Instant::now();
        let grace_duration = Duration::from_secs(grace_secs.into());

        while start.elapsed() < grace_duration {
            let all_stopped = {
                let mut stopped = true;
                for container_id in &state {
                    if let Ok(container_state) = self.runtime.state(container_id).await
                        && container_state.status == crate::runtime::ContainerStatus::Running
                    {
                        stopped = false;
                        break;
                    }
                }
                stopped
            };

            if all_stopped {
                break;
            }

            tokio::time::sleep(Duration::from_millis(STOP_POLL_INTERVAL_MS)).await;
        }

        // Send SIGKILL to any remaining containers
        for container_id in &state {
            let _ = self.runtime.kill(container_id, Signal::Kill, true).await;
        }

        // Update phase
        {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            if let Some(pod_state) = pods.get_mut(id) {
                pod_state.phase = PodPhase::Succeeded;
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

        // Delete all workload containers
        for container_id in state.containers.values() {
            if force {
                let _ = self.runtime.kill(container_id, Signal::Kill, true).await;
            }
            let _ = self.runtime.delete(container_id, force).await;
        }

        // Delete pause container
        if force {
            let _ = self
                .runtime
                .kill(&state.pause_container_id, Signal::Kill, true)
                .await;
        }
        let _ = self.runtime.delete(&state.pause_container_id, force).await;

        // Clean up bundle directories
        for path in &state.bundle_paths {
            let _ = std::fs::remove_dir_all(path);
        }

        Ok(())
    }

    async fn pod_status(&self, id: &PodId) -> Result<PodStatus> {
        // Collect data from lock, then drop it before any async operations
        let (phase, started_at, containers_to_query) = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;

            let state = pods
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            let containers: Vec<(String, String)> = state
                .containers
                .iter()
                .map(|(name, cid)| (name.clone(), cid.clone()))
                .collect();

            (state.phase, state.started_at, containers)
        };
        // Lock is dropped here

        let mut container_statuses = HashMap::new();

        for (name, container_id) in containers_to_query {
            let status = match self.runtime.state(&container_id).await {
                Ok(cs) => match cs.status {
                    crate::runtime::ContainerStatus::Running => ContainerStatus::Running,
                    crate::runtime::ContainerStatus::Creating
                    | crate::runtime::ContainerStatus::Created => ContainerStatus::Waiting {
                        reason: "Created".to_string(),
                    },
                    crate::runtime::ContainerStatus::Stopped => ContainerStatus::Terminated {
                        exit_code: 0, // TODO: Get actual exit code
                        reason: "Completed".to_string(),
                    },
                },
                Err(_) => ContainerStatus::Unknown,
            };
            container_statuses.insert(name, status);
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
                container_count: state.containers.len(),
                labels: state.spec.labels.clone(),
                created_at: state.started_at,
            })
            .collect();

        Ok(summaries)
    }
}
