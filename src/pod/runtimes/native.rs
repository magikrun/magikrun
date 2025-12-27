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
//! │  │  Named Namespaces (created before any container)          │  │
//! │  │  /run/magik/ns/pod-{id}-{net,ipc,uts}                     │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │         ▲           ▲           ▲           ▲                   │
//! │         │           │           │           │ (join namespaces) │
//! │  ┌──────┴──┐  ┌─────┴───┐  ┌────┴────┐  ┌───┴─────┐            │
//! │  │ Pause  │  │Container│  │Container│  │Container│            │
//! │  │Container│  │   A     │  │   B     │  │   C     │            │
//! │  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Named Namespaces for True Atomicity
//!
//! Unlike the pause-container-first approach (where namespace paths depend on
//! pause PID), we create **named namespaces** upfront. This enables:
//!
//! 1. **Full atomicity**: All bundles built in PHASE 1 before any container starts
//! 2. **Predictable paths**: `/run/magik/ns/pod-{id}-{net,ipc,uts}`
//! 3. **Clean rollback**: Namespaces deleted on failure, no orphaned resources
//!
//! # Atomic Deployment
//!
//! Unlike the old CRI model (RunPodSandbox → CreateContainer → StartContainer),
//! `run_pod()` is atomic:
//!
//! 1. **Prepare Phase**: Create namespaces, pull images, build ALL bundles
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

use crate::pod::runtime_base_path;

/// Subdirectory for pod bundles under the base path.
const PODS_SUBDIR: &str = "pods";

/// Directory for named namespaces.
const NAMESPACE_DIR: &str = "/run/magik/ns";

/// Poll interval when waiting for container stop (milliseconds).
const STOP_POLL_INTERVAL_MS: u64 = 100;

/// Namespace types shared by pod containers.
/// These are created as named namespaces before any container starts.
const SHARED_NAMESPACE_TYPES: &[(&str, &str)] = &[
    ("network", "net"), // Shared pod IP address and ports
    ("ipc", "ipc"),     // Shared System V IPC and POSIX message queues
    ("uts", "uts"),     // Shared hostname
];

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
    /// Pause container PID (for monitoring).
    pause_pid: Option<u32>,
    /// Workload container IDs (name → container ID).
    containers: HashMap<String, String>,
    /// Bundle paths (for cleanup).
    bundle_paths: Vec<PathBuf>,
    /// Named namespace paths (for cleanup).
    namespace_paths: HashMap<String, PathBuf>,
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

    /// Creates named namespaces for a pod.
    ///
    /// Named namespaces are persistent paths in `/run/magik/ns/` that exist
    /// independently of any process. This enables true atomic pod deployment:
    /// all bundles can be built with known namespace paths BEFORE any container starts.
    ///
    /// # Arguments
    ///
    /// * `pod_id` - Pod identifier for unique namespace names
    ///
    /// # Returns
    ///
    /// Map of namespace type → path for use in bundle config.json
    ///
    /// # Namespace Creation
    ///
    /// Uses `unshare(2)` + bind mount pattern:
    /// 1. Create empty file at target path
    /// 2. Fork child that unshares the namespace
    /// 3. Child bind-mounts its `/proc/self/ns/{type}` to target path
    /// 4. Child exits, namespace persists via bind mount
    ///
    /// # Security
    ///
    /// - Requires CAP_SYS_ADMIN for unshare
    /// - Namespace paths are pod-specific, no collision possible
    /// - Cleaned up on pod deletion or failure
    fn create_named_namespaces(pod_id: &PodId) -> Result<HashMap<String, PathBuf>> {
        use std::fs::{self, File};
        use std::os::unix::fs::OpenOptionsExt;

        // Ensure namespace directory exists
        fs::create_dir_all(NAMESPACE_DIR).map_err(|e| {
            Error::Internal(format!(
                "failed to create namespace directory {NAMESPACE_DIR}: {e}"
            ))
        })?;

        let mut paths: HashMap<String, PathBuf> = HashMap::new();

        for (ns_type, ns_file) in SHARED_NAMESPACE_TYPES {
            let ns_path = PathBuf::from(format!("{NAMESPACE_DIR}/{}-{}", pod_id.as_str(), ns_file));

            // Create empty file for bind mount target
            File::options()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&ns_path)
                .map_err(|e| {
                    // Clean up any namespaces we already created
                    for (_, created_path) in &paths {
                        let _ = Self::delete_named_namespace(created_path);
                    }
                    Error::Internal(format!(
                        "failed to create namespace file {}: {}",
                        ns_path.display(),
                        e
                    ))
                })?;

            // Create namespace via unshare + bind mount
            // This is done in a child process so the parent doesn't change namespaces
            let ns_path_clone = ns_path.clone();
            let ns_file_str = *ns_file;

            // SAFETY: We're forking and the child immediately execs or exits.
            // The child doesn't share memory with parent after fork on Linux.
            let result = std::process::Command::new("unshare")
                .arg(match ns_file_str {
                    "net" => "--net",
                    "ipc" => "--ipc",
                    "uts" => "--uts",
                    _ => unreachable!("unknown namespace type"),
                })
                .arg("--")
                .arg("sh")
                .arg("-c")
                .arg(format!(
                    "mount --bind /proc/self/ns/{} {}",
                    ns_file_str,
                    ns_path_clone.display()
                ))
                .status();

            match result {
                Ok(status) if status.success() => {
                    tracing::debug!(
                        pod = %pod_id,
                        namespace = %ns_type,
                        path = %ns_path.display(),
                        "Created named namespace"
                    );
                    paths.insert(ns_type.to_string(), ns_path);
                }
                Ok(status) => {
                    // Clean up the file we created
                    let _ = fs::remove_file(&ns_path);
                    // Clean up any namespaces we already created
                    for (_, created_path) in &paths {
                        let _ = Self::delete_named_namespace(created_path);
                    }
                    return Err(Error::Internal(format!(
                        "unshare failed for {} namespace: exit code {:?}",
                        ns_type,
                        status.code()
                    )));
                }
                Err(e) => {
                    // Clean up the file we created
                    let _ = fs::remove_file(&ns_path);
                    // Clean up any namespaces we already created
                    for (_, created_path) in &paths {
                        let _ = Self::delete_named_namespace(created_path);
                    }
                    return Err(Error::Internal(format!(
                        "failed to execute unshare for {} namespace: {}",
                        ns_type, e
                    )));
                }
            }
        }

        tracing::info!(
            pod = %pod_id,
            namespaces = ?paths.keys().collect::<Vec<_>>(),
            "Created named namespaces for pod"
        );

        Ok(paths)
    }

    /// Deletes a named namespace by unmounting and removing the file.
    fn delete_named_namespace(path: &Path) -> Result<()> {
        // Unmount the bind mount
        let status = std::process::Command::new("umount").arg(path).status();

        match status {
            Ok(s) if s.success() => {}
            Ok(_) | Err(_) => {
                // umount failed - might already be unmounted, try to remove anyway
                tracing::debug!(path = %path.display(), "umount failed or not mounted");
            }
        }

        // Remove the file
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                Error::Internal(format!(
                    "failed to remove namespace file {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    /// Deletes all named namespaces for a pod.
    fn delete_pod_namespaces(namespace_paths: &HashMap<String, PathBuf>) {
        for (ns_type, path) in namespace_paths {
            if let Err(e) = Self::delete_named_namespace(path) {
                tracing::warn!(
                    namespace = %ns_type,
                    path = %path.display(),
                    error = %e,
                    "Failed to delete named namespace"
                );
            } else {
                tracing::debug!(
                    namespace = %ns_type,
                    path = %path.display(),
                    "Deleted named namespace"
                );
            }
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

        // Clean up named namespaces
        Self::delete_pod_namespaces(&state.namespace_paths);
    }
}

#[async_trait]
impl PodRuntime for NativePodRuntime {
    fn runtime_class(&self) -> &'static str {
        "pod-containers"
    }

    async fn run_pod(&self, spec: &PodSpec) -> Result<PodHandle> {
        let pod_id = PodId::from_pod(&spec.namespace, &spec.name);
        let pod_dir = runtime_base_path().join(PODS_SUBDIR).join(pod_id.as_str());

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
                    namespace_paths: HashMap::new(),
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
            namespace_paths: HashMap::new(),
            phase: PodPhase::Pending,
            started_at: None,
        };

        // =========================================================================
        // PHASE 1: PREPARE (Create namespaces, pull images, build ALL bundles)
        // No runtime state created - fully atomic rollback possible
        // =========================================================================

        // Step 1.1: Create named namespaces FIRST
        // These are persistent paths that don't depend on any container PID
        let namespace_paths = match Self::create_named_namespaces(&pod_id) {
            Ok(paths) => paths,
            Err(e) => {
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(e);
            }
        };
        state.namespace_paths = namespace_paths.clone();

        // Step 1.2: Build pause container bundle with namespace joining
        let pause_bundle = pod_dir.join("pause");
        let pause_rootfs = pause_bundle.join("rootfs");
        if let Err(e) = std::fs::create_dir_all(&pause_rootfs) {
            self.cleanup_failed_pod(&state).await;
            let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
            return Err(Error::BundleBuildFailed(format!(
                "failed to create pause rootfs: {e}"
            )));
        }
        // TODO: Generate proper config.json for pause container with namespace paths
        // The pause container ALSO joins the named namespaces (it doesn't create them)
        state.bundle_paths.push(pause_bundle.clone());

        // Step 1.3: Pull all images and build ALL bundles with namespace paths
        use crate::image::{Bundle, ImageHandle};
        let mut prepared_containers: Vec<(String, Bundle)> = Vec::new();

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

            // Build bundle with named namespace paths (known before any container starts!)
            let bundle = match self.bundle_builder.build_oci_bundle_with_namespaces(
                &image,
                &config,
                &namespace_paths,
            ) {
                Ok(b) => b,
                Err(e) => {
                    self.cleanup_failed_pod(&state).await;
                    let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                    return Err(Error::BundleBuildFailed(format!(
                        "failed to build bundle for {}: {}",
                        config.name, e
                    )));
                }
            };
            state.bundle_paths.push(bundle.path().to_path_buf());

            let container_id = format!("{}-{}", pod_id.as_str(), container_spec.name);
            prepared_containers.push((container_id, bundle));
        }

        tracing::info!(
            pod = %pod_id,
            container_count = prepared_containers.len(),
            "PHASE 1 complete: all images pulled, all bundles built"
        );

        // =========================================================================
        // PHASE 2: COMMIT (Start all containers - runtime state created)
        // All preparation done - now we commit to starting containers
        // =========================================================================

        // Step 2.1: Create and start pause container
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

        // Get pause container PID for monitoring (not for namespaces anymore)
        if let Ok(pause_state) = self.runtime.state(&state.pause_container_id).await {
            state.pause_pid = pause_state.pid;
        }

        // Step 2.2: Create and start all workload containers (bundles already built)
        for (container_id, bundle) in &prepared_containers {
            if let Err(e) = self.runtime.create(container_id, bundle.path()).await {
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

        tracing::info!(
            pod = %pod_id,
            containers = state.containers.len(),
            "PHASE 2 complete: all containers started"
        );

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

        // Clean up named namespaces
        Self::delete_pod_namespaces(&state.namespace_paths);

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
