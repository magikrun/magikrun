//! Native pod runtime using pasta + infra-container pattern.
//!
//! This runtime creates pods using native Linux containers with the
//! pasta infra-container pattern for namespace sharing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Pod (NativePodRuntime)                                         │
//! │                                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  pasta (creates netns, port forwarding)                   │  │
//! │  │   └─► infra-binary (external, e.g., workplane)            │  │
//! │  │        ├─ Infra instance (from magikrun)                  │  │
//! │  │        ├─ Extensions (from external crate)                │  │
//! │  │        └─ holds namespaces for app containers             │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │         ▲           ▲           ▲                               │
//! │         │ (join)    │ (join)    │ (join)                        │
//! │  ┌──────┴──┐  ┌─────┴───┐  ┌────┴────┐                          │
//! │  │Container│  │Container│  │Container│                          │
//! │  │   A     │  │   B     │  │   C     │                          │
//! │  └─────────┘  └─────────┘  └─────────┘                          │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # 2-Process Architecture
//!
//! Unlike the old 3-process model (unshare + pasta + pause), this uses:
//! 1. `pasta`: Creates netns, handles port forwarding, wraps infra binary
//! 2. `infra-binary`: External binary (e.g., workplane) that holds namespaces
//!
//! Benefits:
//! - Correct dependency semantics (pasta parent → infra dies if pasta dies)
//! - Simpler process tree
//! - Extensions run inside infra binary
//!
//! # Atomic Deployment
//!
//! `run_pod()` is atomic:
//! 1. **Prepare Phase**: Spawn infra-container, pull images, build ALL bundles
//! 2. **Commit Phase**: Start all workload containers
//! 3. **Rollback on failure**: Delete everything if any step fails
//!
//! The caller never sees intermediate states.

use crate::error::{Error, Result};
use crate::image::{BundleBuilder, ImageService, OciContainerConfig};
use crate::pod::{
    ContainerStatus, DEFAULT_GRACE_PERIOD_SECS, PodHandle, PodId, PodPhase, PodRuntime, PodSpec,
    PodStatus, PodSummary,
};
use crate::pod::{MAX_PORT_MAPPINGS, PortMapping, Protocol, extract_port_mappings};
use crate::runtime::{NativeRuntime, OciRuntime, Signal};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::pod::runtime_base_path;

/// Subdirectory for pod bundles under the base path.
const PODS_SUBDIR: &str = "pods";

/// Poll interval when waiting for container stop (milliseconds).
const STOP_POLL_INTERVAL_MS: u64 = 100;

// ============================================================================
// INFRA-CONTAINER CONSTANTS
// ============================================================================

/// Default timeout for infra binary to write its PID file.
const INFRA_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval when waiting for PID file.
const PID_FILE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Default path to infra-container binary.
///
/// This is an external binary (e.g., from the workplane crate) that implements
/// `InfraExtension`. Can be overridden via `MAGIK_INFRA_BINARY_PATH` env var.
const DEFAULT_INFRA_BINARY_PATH: &str = "/usr/libexec/magik/workplane";

/// Maximum PID file size (sanity check).
const MAX_PID_FILE_SIZE: u64 = 32;

// ============================================================================
// INFRA-CONTAINER (pasta + external binary)
// ============================================================================

/// Infra-container that spawns pasta wrapping an external binary.
///
/// This manages the lifecycle of:
/// - `pasta`: Creates network namespace, handles port forwarding
/// - External binary (e.g., workplane): Runs inside pasta's netns, holds namespaces
///
/// App containers join `/proc/{infra_pid}/ns/net` to share networking.
struct InfraContainer {
    /// Pasta child process (we spawn this, it spawns the infra binary).
    pasta_child: Child,

    /// PID of infra binary (pasta's child) - discovered via PID file.
    infra_pid: u32,

    /// Path to PID file (for cleanup).
    pid_file_path: PathBuf,
}

impl InfraContainer {
    /// Spawns the infra-container (pasta wrapping external binary).
    ///
    /// # Arguments
    ///
    /// * `pod_id` - Pod identifier
    /// * `pod_name` - Pod name for logging
    /// * `namespace` - Pod namespace
    /// * `pod_root` - Path to pod directory
    /// * `port_mappings` - Ports to forward via pasta
    async fn spawn(
        pod_id: &str,
        pod_name: &str,
        namespace: &str,
        pod_root: &Path,
        port_mappings: &[PortMapping],
    ) -> Result<Self> {
        // Resolve infra binary path
        let infra_binary = std::env::var("MAGIK_INFRA_BINARY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_INFRA_BINARY_PATH));

        if !infra_binary.exists() {
            return Err(Error::Internal(format!(
                "infra binary not found at {}",
                infra_binary.display()
            )));
        }

        let pid_file_path = pod_root.join("infra.pid");

        // Clean up stale PID file if exists
        let _ = tokio::fs::remove_file(&pid_file_path).await;

        // Build pasta command: pasta [port_args] --config-net -- infra_binary [args]
        let mut cmd = Command::new("pasta");

        // Add port mappings
        for mapping in port_mappings {
            match mapping.protocol {
                Protocol::Tcp => {
                    cmd.arg("-t");
                    cmd.arg(mapping.as_arg());
                }
                Protocol::Udp => {
                    cmd.arg("-u");
                    cmd.arg(mapping.as_arg());
                }
            }
        }

        // Auto-configure networking in the new netns
        cmd.arg("--config-net");

        // Separator
        cmd.arg("--");

        // Infra binary command with arguments
        cmd.arg(&infra_binary);
        cmd.arg("--pod-id").arg(pod_id);
        cmd.arg("--pod-name").arg(pod_name);
        cmd.arg("--namespace").arg(namespace);
        cmd.arg("--pid-file").arg(&pid_file_path);
        cmd.arg("--pod-root").arg(pod_root);

        info!(
            pod_id = %pod_id,
            infra_binary = %infra_binary.display(),
            port_count = port_mappings.len(),
            "Spawning pasta infra-container"
        );

        // Spawn pasta (which spawns infra binary as its child)
        let pasta_child = cmd
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::Internal(format!("failed to spawn pasta: {e}")))?;

        debug!(
            pod_id = %pod_id,
            pasta_pid = ?pasta_child.id(),
            "Pasta process spawned, waiting for infra PID file"
        );

        // Wait for infra binary to write its PID file
        let infra_pid = Self::wait_for_pid_file(&pid_file_path, INFRA_STARTUP_TIMEOUT).await?;

        info!(
            pod_id = %pod_id,
            pasta_pid = ?pasta_child.id(),
            infra_pid = infra_pid,
            "Infra-container ready"
        );

        Ok(Self {
            pasta_child,
            infra_pid,
            pid_file_path,
        })
    }

    /// Waits for the PID file to be written and reads the PID.
    async fn wait_for_pid_file(path: &Path, timeout_duration: Duration) -> Result<u32> {
        let result = timeout(timeout_duration, async {
            loop {
                if let Ok(meta) = tokio::fs::metadata(path).await
                    && meta.len() > 0
                    && meta.len() < MAX_PID_FILE_SIZE
                    && let Ok(content) = tokio::fs::read_to_string(path).await
                {
                    let trimmed = content.trim();
                    if !trimmed.is_empty() {
                        return trimmed.parse::<u32>().map_err(|_| {
                            Error::Internal(format!("invalid PID in file: {trimmed}"))
                        });
                    }
                }
                tokio::time::sleep(PID_FILE_POLL_INTERVAL).await;
            }
        })
        .await;

        match result {
            Ok(pid_result) => pid_result,
            Err(_) => Err(Error::Internal(format!(
                "infra startup timed out after {timeout_duration:?}"
            ))),
        }
    }

    /// Returns namespace paths for app containers to join.
    fn namespace_paths(&self) -> HashMap<String, PathBuf> {
        let mut paths = HashMap::new();
        paths.insert(
            "network".to_string(),
            PathBuf::from(format!("/proc/{}/ns/net", self.infra_pid)),
        );
        paths.insert(
            "ipc".to_string(),
            PathBuf::from(format!("/proc/{}/ns/ipc", self.infra_pid)),
        );
        paths.insert(
            "uts".to_string(),
            PathBuf::from(format!("/proc/{}/ns/uts", self.infra_pid)),
        );
        paths
    }

    /// Shuts down the infra-container.
    async fn shutdown(&mut self, grace_period: Duration) {
        // Send SIGTERM first
        #[cfg(unix)]
        if let Some(pid) = self.pasta_child.id() {
            // SAFETY: Sending signal to our own child process
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }

        // Wait for graceful shutdown
        let graceful = timeout(grace_period, self.pasta_child.wait()).await;

        if graceful.is_err() {
            warn!("Graceful shutdown timed out, sending SIGKILL");
            let _ = self.pasta_child.kill().await;
        }

        // Clean up PID file
        let _ = tokio::fs::remove_file(&self.pid_file_path).await;
    }
}

impl Drop for InfraContainer {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.pasta_child.id() {
            // SAFETY: Sending signal to our own child process
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

// ============================================================================
// POD RUNTIME
// ============================================================================

/// Native pod runtime using Linux containers.
///
/// Implements atomic pod deployment with the pasta infra-container pattern.
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
    /// Infra-container (pasta + external binary).
    infra: Option<InfraContainer>,
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

    /// Cleans up all resources for a failed pod deployment.
    async fn cleanup_failed_pod(&self, state: &mut PodState) {
        // Shutdown infra-container if running
        if let Some(ref mut infra) = state.infra {
            infra
                .shutdown(Duration::from_secs(DEFAULT_GRACE_PERIOD_SECS.into()))
                .await;
        }

        // Delete all workload containers
        for container_id in state.containers.values() {
            let _ = self.runtime.kill(container_id, Signal::Kill, true).await;
            let _ = self.runtime.delete(container_id, true).await;
        }

        // Clean up bundle directories
        for path in &state.bundle_paths {
            let _ = std::fs::remove_dir_all(path);
        }
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

            // Reserve slot with initial state
            pods.insert(
                pod_id.clone(),
                PodState {
                    spec: spec.clone(),
                    infra: None,
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
            infra: None,
            containers: HashMap::new(),
            bundle_paths: vec![pod_dir.clone()],
            phase: PodPhase::Pending,
            started_at: None,
        };

        // =========================================================================
        // PHASE 1: PREPARE (Spawn infra, pull images, build ALL bundles)
        // No runtime state created - fully atomic rollback possible
        // =========================================================================

        // Step 1.1: Extract port mappings from all containers (with validation)
        let port_result = extract_port_mappings(&spec.containers);

        if port_result.skipped_invalid > 0 {
            warn!(
                pod = %pod_id,
                skipped = port_result.skipped_invalid,
                "Skipped invalid port mappings (port 0 not allowed)"
            );
        }

        if port_result.skipped_duplicates > 0 {
            warn!(
                pod = %pod_id,
                skipped = port_result.skipped_duplicates,
                "Skipped duplicate port mappings"
            );
        }

        if port_result.limit_reached {
            warn!(
                pod = %pod_id,
                max = MAX_PORT_MAPPINGS,
                "Port mapping limit reached, some mappings were dropped"
            );
        }

        let port_mappings = port_result.mappings;

        // Step 1.2: Spawn infra-container (pasta + infra binary)
        let pod_id_str = pod_id.as_str();
        let infra = match InfraContainer::spawn(
            &pod_id_str,
            &spec.name,
            &spec.namespace,
            &pod_dir,
            &port_mappings,
        )
        .await
        {
            Ok(infra) => infra,
            Err(e) => {
                self.cleanup_failed_pod(&mut state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(e);
            }
        };

        // Get namespace paths from infra-container
        let namespace_paths = infra.namespace_paths();
        state.infra = Some(infra);

        // Step 1.3: Pull all images and build ALL bundles with namespace paths
        use crate::image::Bundle;
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
                    self.cleanup_failed_pod(&mut state).await;
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
                vm_mode: false,
            };

            // Build bundle with namespace paths from infra-container
            let bundle = match self.bundle_builder.build_oci_bundle_with_namespaces(
                &image,
                &config,
                &namespace_paths,
            ) {
                Ok(b) => b,
                Err(e) => {
                    self.cleanup_failed_pod(&mut state).await;
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

        // Create and start all workload containers (bundles already built)
        for (container_id, bundle) in &prepared_containers {
            if let Err(e) = self.runtime.create(container_id, bundle.path()).await {
                self.cleanup_failed_pod(&mut state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::CreateFailed {
                    id: container_id.clone(),
                    reason: e.to_string(),
                });
            }

            if let Err(e) = self.runtime.start(container_id).await {
                self.cleanup_failed_pod(&mut state).await;
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
        let container_ids: Vec<String> = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            pods.get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?
                .containers
                .values()
                .cloned()
                .collect()
        };

        let grace_secs: u32 = grace_period
            .as_secs()
            .try_into()
            .unwrap_or(DEFAULT_GRACE_PERIOD_SECS);

        // Stop all workload containers with grace period
        for container_id in &container_ids {
            // Send SIGTERM
            let _ = self.runtime.kill(container_id, Signal::Term, true).await;
        }

        // Wait for grace period
        let start = Instant::now();
        let grace_duration = Duration::from_secs(grace_secs.into());

        while start.elapsed() < grace_duration {
            let all_stopped = {
                let mut stopped = true;
                for container_id in &container_ids {
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
        for container_id in &container_ids {
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
        let mut state = {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            pods.remove(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?
        };

        // Shutdown infra-container first
        if let Some(ref mut infra) = state.infra {
            let grace = if force {
                Duration::from_secs(0)
            } else {
                Duration::from_secs(DEFAULT_GRACE_PERIOD_SECS.into())
            };
            infra.shutdown(grace).await;
        }

        // Delete all workload containers
        for container_id in state.containers.values() {
            if force {
                let _ = self.runtime.kill(container_id, Signal::Kill, true).await;
            }
            let _ = self.runtime.delete(container_id, force).await;
        }

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
