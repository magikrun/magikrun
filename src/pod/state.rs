//! Pod state types.
//!
//! This module defines the runtime state types for pods:
//! - `PodId`: Unique pod identifier
//! - `PodPhase`: High-level pod lifecycle state
//! - `PodStatus`: Detailed pod status including container states
//! - `PodHandle`: Return value from `run_pod()`
//! - `PodSummary`: Lightweight pod info for listing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Pod ID
// =============================================================================

/// Unique identifier for a pod.
///
/// Pod IDs are deterministically derived from namespace/name using SHA256.
/// This allows idempotent pod creation - same inputs always produce the same ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PodId(uuid::Uuid);

impl PodId {
    /// Creates a new unique pod ID using UUIDv7.
    ///
    /// UUIDv7 provides time-ordering, making it suitable for database
    /// indexing and log correlation.
    #[must_use]
    pub fn new(name: impl AsRef<str>) -> Self {
        Self::from_pod("default", name.as_ref())
    }

    /// Creates a pod ID from namespace and name (deterministic).
    ///
    /// Uses SHA256 hash of `namespace/name` to generate a stable ID.
    /// This allows idempotent pod creation - same inputs always produce
    /// the same ID.
    #[must_use]
    pub fn from_pod(namespace: &str, name: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(b"/");
        hasher.update(name.as_bytes());
        let hash = hasher.finalize();

        // Use first 16 bytes of hash as UUID
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);

        // Set version (4) and variant (RFC 4122)
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;

        Self(uuid::Uuid::from_bytes(bytes))
    }

    /// Returns the UUID as a string.
    #[must_use]
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl Default for PodId {
    fn default() -> Self {
        Self(uuid::Uuid::now_v7())
    }
}

impl std::fmt::Display for PodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// =============================================================================
// Container ID
// =============================================================================

/// Identifier for a container within a pod.
///
/// The format depends on the runtime:
/// - Native: OCI container ID (e.g., "mypod-nginx")
/// - MicroVM: VM ID + container name (e.g., "vm-abc:nginx")
/// - WASM: Module instance ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerId {
    /// Native Linux container (OCI runtime).
    Native(String),
    /// Container inside a MicroVM.
    MicroVm { vm_id: String, container: String },
    /// WASM module instance.
    Wasm(String),
}

impl std::fmt::Display for ContainerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerId::Native(id) => write!(f, "{id}"),
            ContainerId::MicroVm { vm_id, container } => write!(f, "{vm_id}:{container}"),
            ContainerId::Wasm(id) => write!(f, "wasm:{id}"),
        }
    }
}

// =============================================================================
// Pod Phase
// =============================================================================

/// High-level pod lifecycle phase.
///
/// Simplified state machine:
///
/// ```text
///   Pending ──▶ Running ──▶ Succeeded
///      │           │            │
///      └───────────┴────────────┴──▶ Failed
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PodPhase {
    /// Pod is being created (images pulling, containers starting).
    #[default]
    Pending,
    /// At least one container is running.
    Running,
    /// All containers terminated successfully (exit code 0).
    Succeeded,
    /// At least one container terminated with failure.
    Failed,
    /// Pod phase is unknown.
    Unknown,
}

impl std::fmt::Display for PodPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PodPhase::Pending => write!(f, "Pending"),
            PodPhase::Running => write!(f, "Running"),
            PodPhase::Succeeded => write!(f, "Succeeded"),
            PodPhase::Failed => write!(f, "Failed"),
            PodPhase::Unknown => write!(f, "Unknown"),
        }
    }
}

// =============================================================================
// Container Status
// =============================================================================

/// Status of a single container within a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum ContainerStatus {
    /// Container is waiting to start.
    Waiting { reason: String },
    /// Container is running.
    Running,
    /// Container has terminated.
    Terminated { exit_code: i32, reason: String },
    /// Container status is unknown.
    Unknown,
}

/// Summary information about a container (for lifecycle events).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Container name within the pod.
    pub name: String,
    /// Container ID (runtime-specific).
    pub id: Option<ContainerId>,
    /// Process ID (if running).
    pub pid: Option<u32>,
    /// Current status.
    pub status: ContainerStatus,
    /// Exit code (if terminated).
    pub exit_code: Option<i32>,
}

// =============================================================================
// Pod Status
// =============================================================================

/// Detailed status of a pod.
///
/// Includes phase, all container statuses, and timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodStatus {
    /// High-level phase.
    pub phase: PodPhase,
    /// Status of each container (name → status).
    pub containers: HashMap<String, ContainerStatus>,
    /// When the pod started running.
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the pod finished (if terminated).
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Human-readable message about current state.
    pub message: Option<String>,
}

// =============================================================================
// Pod Handle
// =============================================================================

/// Handle returned by `run_pod()`.
///
/// Contains the pod ID and runtime class.
/// Use `pod_status()` for detailed status.
#[derive(Debug, Clone)]
pub struct PodHandle {
    /// Unique pod identifier.
    pub id: PodId,
    /// Runtime class used.
    pub runtime_class: String,
}

// =============================================================================
// Pod Summary
// =============================================================================

/// Lightweight pod information for listing.
///
/// Contains only essential fields for UI display and filtering.
/// Call `pod_status()` for full details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSummary {
    /// Pod identifier.
    pub id: PodId,
    /// Namespace.
    pub namespace: String,
    /// Pod name.
    pub name: String,
    /// High-level phase.
    pub phase: PodPhase,
    /// Runtime class.
    pub runtime_class: String,
    /// Number of containers.
    pub container_count: usize,
}
