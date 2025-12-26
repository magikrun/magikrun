//! # Pod Runtime Interface (PRI) - Atomic Pod Lifecycle
//!
//! This module provides the **Pod Runtime Interface** - a pod-first abstraction
//! that treats pods as the atomic unit of deployment, not containers.
//!
//! ## Philosophy: Cattle, Not Pets
//!
//! Unlike CRI (Container Runtime Interface) which builds pods step-by-step,
//! PRI deploys pods atomically:
//!
//! ```text
//! CRI (Container-first):              PRI (Pod-first):
//! ─────────────────────               ─────────────────
//! RunPodSandbox()                     RunPod(spec)
//! CreateContainer(A)                      │
//! StartContainer(A)                       │
//! CreateContainer(B)       ═══▶           ▼
//! StartContainer(B)                   RUNNING or ERROR
//! ... intermediate states ...         (no intermediate states)
//! ```
//!
//! ## Key Properties
//!
//! - **Atomic**: `run_pod()` either fully succeeds or nothing is created
//! - **Stateless**: No orphaned resources on failure (automatic rollback)
//! - **Immutable**: Replace pods, don't repair them
//! - **Self-healing**: Failed pod = delete + reschedule (simple!)
//!
//! ## The PodRuntime Trait
//!
//! ```rust,ignore
//! #[async_trait]
//! pub trait PodRuntime: Send + Sync {
//!     async fn run_pod(&self, spec: &PodSpec) -> Result<PodHandle>;
//!     async fn stop_pod(&self, id: &PodId, grace: Duration) -> Result<()>;
//!     async fn delete_pod(&self, id: &PodId, force: bool) -> Result<()>;
//!     async fn pod_status(&self, id: &PodId) -> Result<PodStatus>;
//!     async fn list_pods(&self) -> Result<Vec<PodSummary>>;
//! }
//! ```
//!
//! ## Implementations
//!
//! | Runtime Class | Backend | Isolation | Atomicity |
//! |---------------|---------|-----------|-----------|
//! | `pod-containers` | youki + pause | Namespaces | Emulated (rollback on failure) |
//! | `pod-microvm` | libkrun | Hardware VM | Natural (VM boot = atomic) |
//! | `pod-wasm` | wasmtime | WASM sandbox | Natural (store = atomic) |
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::pod::{PodRuntime, PodSpec, NativePodRuntime};
//!
//! let runtime = NativePodRuntime::new()?;
//! let spec = PodSpec::from_yaml(manifest)?;
//!
//! // Atomic: either fully running or error (nothing created)
//! let handle = runtime.run_pod(&spec).await?;
//!
//! // Later: atomic stop
//! runtime.stop_pod(&handle.id, Duration::from_secs(30)).await?;
//! runtime.delete_pod(&handle.id, false).await?;
//! ```

mod spec;
mod state;
mod traits;
mod runtimes;

// TSI protocol for MicroVM communication (internal)
#[cfg(not(target_os = "windows"))]
pub(crate) mod tsi;

// Re-export public API
pub use spec::{
    ContainerPort, ContainerSpec, PodSpec, ResourceRequirements, Volume, VolumeMount, VolumeSource,
    // Constants
    DEFAULT_GRACE_PERIOD_SECS, MAX_ANNOTATIONS_PER_POD, MAX_CONTAINERS_PER_POD,
    MAX_CONTAINER_NAME_LEN, MAX_ENV_VALUE_LEN, MAX_ENV_VARS_PER_CONTAINER, MAX_GRACE_PERIOD_SECS,
    MAX_LABELS_PER_POD, MAX_LABEL_KEY_LEN, MAX_LABEL_VALUE_LEN, MAX_MANIFEST_SIZE, MAX_NAME_LEN,
    MAX_NAMESPACE_LEN, MAX_POD_ID_LEN, MAX_PODS, MAX_VOLUMES_PER_POD,
};
pub use state::{ContainerId, ContainerInfo, ContainerStatus, PodHandle, PodId, PodPhase, PodStatus, PodSummary};
pub use traits::{ExecOptions, ExecResult, LogOptions, PodRuntime, PodRuntimeRegistry};

// Re-export runtime implementations
#[cfg(target_os = "linux")]
pub use runtimes::NativePodRuntime;
pub use runtimes::WasmPodRuntime;
#[cfg(not(target_os = "windows"))]
pub use runtimes::MicroVmPodRuntime;
