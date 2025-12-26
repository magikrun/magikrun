//! Pod Runtime Interface trait definition.
//!
//! This module defines the core `PodRuntime` trait - the atomic pod lifecycle API.

use super::{PodHandle, PodId, PodSpec, PodStatus, PodSummary};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::time::Duration;

// =============================================================================
// Exec/Logs Types
// =============================================================================

/// Options for executing a command in a container.
#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    /// Attach stdin.
    pub stdin: bool,
    /// Attach stdout.
    pub stdout: bool,
    /// Attach stderr.
    pub stderr: bool,
    /// Allocate a TTY.
    pub tty: bool,
}

/// Result of an exec operation.
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Exit code of the command (None if still running or not supported).
    pub exit_code: Option<i32>,
    /// Stdout output (if captured).
    pub stdout: Option<Vec<u8>>,
    /// Stderr output (if captured).
    pub stderr: Option<Vec<u8>>,
}

/// Options for streaming logs.
#[derive(Debug, Clone, Default)]
pub struct LogOptions {
    /// Stream logs (follow mode).
    pub follow: bool,
    /// Number of lines from tail (0 = all).
    pub tail_lines: u32,
    /// Include timestamps.
    pub timestamps: bool,
}

/// Pod Runtime Interface - atomic pod lifecycle management.
///
/// This trait defines the contract for pod runtimes. Unlike CRI's step-by-step
/// approach, PRI treats pods as atomic units:
///
/// - `run_pod()`: Deploys entire pod atomically (all-or-nothing)
/// - `stop_pod()`: Stops all containers with grace period
/// - `delete_pod()`: Removes all pod resources
/// - `pod_status()`: Returns current pod state snapshot
///
/// # Atomicity Guarantees
///
/// Implementations **MUST** ensure:
///
/// 1. `run_pod()` either returns a running pod or an error with NO resources leaked
/// 2. On failure, all partial resources are cleaned up automatically
/// 3. No intermediate states are observable externally
///
/// # Implementation Notes
///
/// Different backends achieve atomicity differently:
///
/// - **MicroVM**: Natural atomicity - VM either boots or doesn't
/// - **Native containers**: Emulated via rollback on failure
/// - **WASM**: Natural atomicity - store creation is all-or-nothing
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` for use in async contexts.
/// Internal state should be protected with appropriate synchronization.
#[async_trait]
pub trait PodRuntime: Send + Sync {
    /// Returns the runtime class name this implementation handles.
    ///
    /// Used for runtime selection based on `runtimeClassName` in PodSpec.
    ///
    /// Standard names:
    /// - `"pod-containers"` - Native Linux containers
    /// - `"pod-microvm"` - MicroVM isolation (libkrun)
    /// - `"pod-wasm"` - WebAssembly modules
    fn runtime_class(&self) -> &str;

    /// Atomically deploys a pod.
    ///
    /// This is the core operation of PRI. It:
    ///
    /// 1. Validates the pod spec
    /// 2. Pulls all container images (in parallel where possible)
    /// 3. Creates the isolation boundary (pause container, VM, WASM store)
    /// 4. Runs init containers sequentially (waiting for each to complete)
    /// 5. Starts main containers in parallel
    /// 6. Returns only when ALL containers are running
    ///
    /// # Atomicity
    ///
    /// If ANY step fails, the implementation MUST:
    /// - Clean up all created resources
    /// - Return an error
    /// - Leave no orphaned containers, namespaces, or other resources
    ///
    /// # Arguments
    ///
    /// * `spec` - The pod specification including containers, volumes, etc.
    ///
    /// # Returns
    ///
    /// A handle containing the pod ID and initial status on success.
    ///
    /// # Errors
    ///
    /// - Image pull failures
    /// - Resource limit violations
    /// - Init container failures (non-zero exit)
    /// - Container start failures
    /// - Platform capability issues
    async fn run_pod(&self, spec: &PodSpec) -> Result<PodHandle>;

    /// Stops a running pod with grace period.
    ///
    /// Sends SIGTERM to all containers, waits up to `grace_period`,
    /// then sends SIGKILL to any remaining containers.
    ///
    /// # Arguments
    ///
    /// * `id` - The pod to stop
    /// * `grace_period` - Time to wait after SIGTERM before SIGKILL
    ///
    /// # Errors
    ///
    /// - Pod not found
    /// - Signal delivery failure (non-fatal for cleanup)
    async fn stop_pod(&self, id: &PodId, grace_period: Duration) -> Result<()>;

    /// Deletes a pod and all its resources.
    ///
    /// Removes all containers, namespaces, bundles, and other resources
    /// associated with the pod.
    ///
    /// # Arguments
    ///
    /// * `id` - The pod to delete
    /// * `force` - If true, force-kill running containers first
    ///
    /// # Errors
    ///
    /// - Pod not found
    /// - Pod still running (if force=false)
    async fn delete_pod(&self, id: &PodId, force: bool) -> Result<()>;

    /// Returns the current status of a pod.
    ///
    /// This is a read-only snapshot of the pod's state, including
    /// the status of all containers.
    ///
    /// # Arguments
    ///
    /// * `id` - The pod to query
    ///
    /// # Returns
    ///
    /// Current pod status including phase, container states, timestamps.
    ///
    /// # Errors
    ///
    /// - Pod not found
    async fn pod_status(&self, id: &PodId) -> Result<PodStatus>;

    /// Lists all pods managed by this runtime.
    ///
    /// Returns lightweight summaries suitable for listing operations.
    /// For full status, call `pod_status()` on individual pods.
    async fn list_pods(&self) -> Result<Vec<PodSummary>>;

    /// Checks if this runtime is available on the current platform.
    ///
    /// Returns `true` if the runtime can be used (e.g., Linux for native,
    /// KVM/HVF for MicroVM). Used for runtime auto-selection.
    fn is_available(&self) -> bool {
        true // Default: assume available, override for platform-specific checks
    }

    // =========================================================================
    // Day-2 Operations (Optional)
    // =========================================================================

    /// Executes a command in a container within the pod.
    ///
    /// This is an optional Day-2 operation for debugging and administration.
    /// Not all runtimes support exec (e.g., WASM modules cannot exec).
    ///
    /// # Arguments
    ///
    /// * `id` - The pod containing the container
    /// * `container` - Container name within the pod
    /// * `command` - Command and arguments to execute
    /// * `options` - Exec options (stdin, stdout, stderr, tty)
    ///
    /// # Returns
    ///
    /// Exec result with exit code and optional captured output.
    ///
    /// # Errors
    ///
    /// - Pod not found
    /// - Container not found
    /// - Exec not supported by this runtime
    async fn exec(
        &self,
        _id: &PodId,
        _container: &str,
        _command: &[String],
        _options: ExecOptions,
    ) -> Result<ExecResult> {
        Err(Error::NotSupported(
            "exec not supported by this runtime".to_string(),
        ))
    }

    /// Streams logs from a container within the pod.
    ///
    /// This is an optional Day-2 operation. Not all runtimes support
    /// log streaming (e.g., WASM modules may not have persistent logs).
    ///
    /// # Arguments
    ///
    /// * `id` - The pod containing the container
    /// * `container` - Container name within the pod
    /// * `options` - Log options (follow, tail, timestamps)
    ///
    /// # Returns
    ///
    /// Log output as bytes. For streaming, this returns a snapshot;
    /// implement follow mode via repeated calls or a stream API.
    ///
    /// # Errors
    ///
    /// - Pod not found
    /// - Container not found
    /// - Logs not supported by this runtime
    async fn logs(&self, _id: &PodId, _container: &str, _options: LogOptions) -> Result<Vec<u8>> {
        Err(Error::NotSupported(
            "logs not supported by this runtime".to_string(),
        ))
    }
}

/// Registry of pod runtimes by runtime class name.
///
/// Allows dynamic dispatch to the appropriate runtime based on
/// the pod's `runtimeClassName` field.
pub struct PodRuntimeRegistry {
    runtimes: Vec<Box<dyn PodRuntime>>,
}

impl PodRuntimeRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runtimes: Vec::new(),
        }
    }

    /// Registers a pod runtime.
    ///
    /// The runtime's `runtime_class()` determines which pods it handles.
    pub fn register(&mut self, runtime: Box<dyn PodRuntime>) {
        self.runtimes.push(runtime);
    }

    /// Gets a runtime by runtime class name.
    ///
    /// Returns `None` if no runtime is registered for the class.
    #[must_use]
    pub fn get(&self, runtime_class: &str) -> Option<&dyn PodRuntime> {
        self.runtimes
            .iter()
            .find(|r| r.runtime_class() == runtime_class)
            .map(|r| r.as_ref())
    }

    /// Returns the default runtime (first registered).
    ///
    /// Used when `runtimeClassName` is not specified in the pod spec.
    #[must_use]
    pub fn default_runtime(&self) -> Option<&dyn PodRuntime> {
        self.runtimes.first().map(|r| r.as_ref())
    }

    /// Lists all registered runtime class names.
    #[must_use]
    pub fn list_runtime_classes(&self) -> Vec<&str> {
        self.runtimes.iter().map(|r| r.runtime_class()).collect()
    }

    /// Lists all available runtimes (those passing `is_available()` check).
    #[must_use]
    pub fn available_runtimes(&self) -> Vec<&dyn PodRuntime> {
        self.runtimes
            .iter()
            .filter(|r| r.is_available())
            .map(|r| r.as_ref())
            .collect()
    }
}

impl Default for PodRuntimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
