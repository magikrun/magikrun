//! WASM pod runtime using wasmtime.
//!
//! This runtime creates pods using WebAssembly modules with WASI support.
//! WASM provides natural atomicity since module instantiation is all-or-nothing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Pod (WasmPodRuntime)                                          │
//! │                                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  Wasmtime Engine (shared)                                 │  │
//! │  │                                                           │  │
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │  │
//! │  │  │ Module A    │  │ Module B    │  │ Module C    │       │  │
//! │  │  │ (instance)  │  │ (instance)  │  │ (instance)  │       │  │
//! │  │  └─────────────┘  └─────────────┘  └─────────────┘       │  │
//! │  │                                                           │  │
//! │  │  WASI: filesystem, env, stdio (sandboxed per module)     │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Isolation Model
//!
//! WASM provides capability-based security:
//! - No direct syscall access (all access via WASI)
//! - Memory isolation per module instance
//! - Fuel limits prevent runaway computation
//!
//! # Atomic Deployment
//!
//! WASM module instantiation is naturally atomic - either the module
//! loads and starts successfully, or it fails with no side effects.
//! This aligns perfectly with the PRI model.

use crate::error::{Error, Result};
use crate::image::{BundleBuilder, ImageService, OciContainerConfig};
use crate::pod::{
    ContainerStatus, PodHandle, PodId, PodPhase, PodRuntime, PodSpec, PodStatus, PodSummary,
};
use crate::runtime::{OciRuntime, Signal, WasmtimeRuntime};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

use crate::pod::runtime_base_path;

/// Subdirectory for WASM pod bundles under the base path.
const WASM_PODS_SUBDIR: &str = "wasm-pods";

/// WASM pod runtime using wasmtime.
///
/// Implements atomic pod deployment for WebAssembly workloads.
/// Cross-platform (Linux, macOS, Windows).
pub struct WasmPodRuntime {
    /// OCI runtime for WASM operations.
    runtime: WasmtimeRuntime,
    /// Image service for pulling images.
    image_service: ImageService,
    /// Bundle builder for creating OCI bundles.
    bundle_builder: BundleBuilder,
    /// Pod ID → PodState mapping.
    pods: RwLock<HashMap<PodId, WasmPodState>>,
}

/// Internal WASM pod state.
struct WasmPodState {
    /// Pod specification.
    spec: PodSpec,
    /// Module IDs (container name → module ID).
    modules: HashMap<String, String>,
    /// Module statuses.
    module_statuses: HashMap<String, crate::runtime::ContainerStatus>,
    /// Bundle paths (for cleanup).
    bundle_paths: Vec<PathBuf>,
    /// Current phase.
    phase: PodPhase,
    /// Started timestamp.
    started_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl WasmPodRuntime {
    /// Creates a new WASM pod runtime.
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
            runtime: WasmtimeRuntime::new(),
            image_service,
            bundle_builder,
            pods: RwLock::new(HashMap::new()),
        })
    }

    /// Cleans up all resources for a failed pod.
    async fn cleanup_failed_pod(&self, state: &WasmPodState) {
        // Delete all modules
        for module_id in state.modules.values() {
            let _ = self.runtime.delete(module_id, true).await;
        }

        // Clean up bundle directories
        for path in &state.bundle_paths {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[async_trait]
impl PodRuntime for WasmPodRuntime {
    fn runtime_class(&self) -> &'static str {
        "pod-wasm"
    }

    async fn run_pod(&self, spec: &PodSpec) -> Result<PodHandle> {
        let pod_id = PodId::from_pod(&spec.namespace, &spec.name);
        let pod_dir = runtime_base_path().join(WASM_PODS_SUBDIR).join(pod_id.as_str());

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
                WasmPodState {
                    spec: spec.clone(),
                    modules: HashMap::new(),
                    module_statuses: HashMap::new(),
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

        let mut state = WasmPodState {
            spec: spec.clone(),
            modules: HashMap::new(),
            module_statuses: HashMap::new(),
            bundle_paths: vec![pod_dir.clone()],
            phase: PodPhase::Pending,
            started_at: None,
        };

        // =========================================================================
        // PHASE 1: PREPARE (Pull images, build bundles for init + main containers)
        // =========================================================================

        // Init containers (run sequentially before main containers)
        let mut init_bundles: Vec<(String, String, PathBuf)> = Vec::new();
        for container_spec in &spec.init_containers {
            tracing::info!(
                pod = %pod_id,
                image = %container_spec.image,
                module = %container_spec.name,
                "Pulling WASM image for init container"
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
                        "failed to build WASM bundle for init container {}: {}",
                        container_spec.name, e
                    )));
                }
            };

            let module_id = format!("{}-init-{}", pod_id.as_str(), container_spec.name);
            init_bundles.push((
                container_spec.name.clone(),
                module_id,
                bundle.path().to_path_buf(),
            ));
            state.bundle_paths.push(bundle.path().to_path_buf());
        }

        // Main containers
        let mut module_bundles: Vec<(String, String, PathBuf)> = Vec::new();

        for container_spec in &spec.containers {
            tracing::info!(
                pod = %pod_id,
                image = %container_spec.image,
                module = %container_spec.name,
                "Pulling WASM image for pod"
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
                        "failed to build WASM bundle for {}: {}",
                        container_spec.name, e
                    )));
                }
            };

            let module_id = format!("{}-{}", pod_id.as_str(), container_spec.name);
            module_bundles.push((
                container_spec.name.clone(),
                module_id,
                bundle.path().to_path_buf(),
            ));
            state.bundle_paths.push(bundle.path().to_path_buf());
        }

        // =========================================================================
        // PHASE 2: RUN INIT CONTAINERS (Sequential, wait for completion)
        // =========================================================================

        for (name, module_id, bundle_path) in &init_bundles {
            tracing::info!(
                pod = %pod_id,
                init_container = %name,
                "Running init container"
            );

            // Create init container
            if let Err(e) = self.runtime.create(module_id, bundle_path).await {
                self.cleanup_failed_pod(&state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::CreateFailed {
                    id: module_id.clone(),
                    reason: format!("init container: {e}"),
                });
            }

            // Start init container
            if let Err(e) = self.runtime.start(module_id).await {
                self.cleanup_failed_pod(&state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::StartFailed {
                    id: module_id.clone(),
                    reason: format!("init container: {e}"),
                });
            }

            // Wait for init container to complete
            let exit_code = match self.runtime.wait(module_id).await {
                Ok(code) => code,
                Err(e) => {
                    self.cleanup_failed_pod(&state).await;
                    let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                    return Err(Error::Internal(format!(
                        "init container '{}' wait failed: {}",
                        name, e
                    )));
                }
            };

            // Init containers must exit 0
            if exit_code != 0 {
                self.cleanup_failed_pod(&state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::Internal(format!(
                    "init container '{}' failed with exit code {}",
                    name, exit_code
                )));
            }

            tracing::info!(
                pod = %pod_id,
                init_container = %name,
                "Init container completed successfully"
            );

            // Clean up init container (it's done)
            let _ = self.runtime.delete(module_id, true).await;
        }

        // =========================================================================
        // PHASE 3: COMMIT (Start all main containers)
        // =========================================================================

        for (name, module_id, bundle_path) in &module_bundles {
            if let Err(e) = self.runtime.create(module_id, bundle_path).await {
                self.cleanup_failed_pod(&state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::CreateFailed {
                    id: module_id.clone(),
                    reason: e.to_string(),
                });
            }

            if let Err(e) = self.runtime.start(module_id).await {
                self.cleanup_failed_pod(&state).await;
                let _ = self.pods.write().map(|mut m| m.remove(&pod_id));
                return Err(Error::StartFailed {
                    id: module_id.clone(),
                    reason: e.to_string(),
                });
            }

            state.modules.insert(name.clone(), module_id.clone());
            state
                .module_statuses
                .insert(module_id.clone(), crate::runtime::ContainerStatus::Running);
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

    async fn stop_pod(&self, id: &PodId, _grace_period: Duration) -> Result<()> {
        // WASM modules stop immediately (no grace period needed)
        let module_ids: Vec<String> = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            let state = pods
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;
            state.modules.values().cloned().collect()
        };

        // Stop all modules via fuel exhaustion / trap
        for module_id in &module_ids {
            let _ = self.runtime.kill(module_id, Signal::Kill, true).await;
        }

        // Update phase
        {
            let mut pods = self
                .pods
                .write()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;
            if let Some(state) = pods.get_mut(id) {
                state.phase = PodPhase::Succeeded;
                for (_, status) in state.module_statuses.iter_mut() {
                    *status = crate::runtime::ContainerStatus::Stopped;
                }
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

        // Delete all modules
        for module_id in state.modules.values() {
            let _ = self.runtime.delete(module_id, force).await;
        }

        // Clean up bundle directories
        for path in &state.bundle_paths {
            let _ = std::fs::remove_dir_all(path);
        }

        Ok(())
    }

    async fn pod_status(&self, id: &PodId) -> Result<PodStatus> {
        // Extract data from lock before any await points
        let (phase, started_at, modules) = {
            let pods = self
                .pods
                .read()
                .map_err(|_| Error::Internal("lock poisoned".to_string()))?;

            let state = pods
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            (state.phase, state.started_at, state.modules.clone())
        };

        let mut container_statuses = HashMap::new();

        for (name, module_id) in &modules {
            let status = match self.runtime.state(module_id).await {
                Ok(ms) => match ms.status {
                    crate::runtime::ContainerStatus::Running => ContainerStatus::Running,
                    crate::runtime::ContainerStatus::Created
                    | crate::runtime::ContainerStatus::Creating => ContainerStatus::Waiting {
                        reason: "Created".to_string(),
                    },
                    crate::runtime::ContainerStatus::Stopped => ContainerStatus::Terminated {
                        exit_code: 0,
                        reason: "Completed".to_string(),
                    },
                },
                Err(_) => ContainerStatus::Unknown,
            };
            container_statuses.insert(name.clone(), status);
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
                container_count: state.modules.len(),
                labels: state.spec.labels.clone(),
                created_at: state.started_at,
            })
            .collect();

        Ok(summaries)
    }
}
