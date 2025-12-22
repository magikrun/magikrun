//! Error types for the OCI runtime layer.

use std::path::PathBuf;

/// Result type alias for OCI runtime operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in the OCI runtime layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // =========================================================================
    // Container Lifecycle Errors
    // =========================================================================
    /// Container not found.
    #[error("container not found: {0}")]
    ContainerNotFound(String),

    /// Container already exists.
    #[error("container already exists: {0}")]
    ContainerAlreadyExists(String),

    /// Container create failed.
    #[error("failed to create container '{id}': {reason}")]
    CreateFailed { id: String, reason: String },

    /// Container start failed.
    #[error("failed to start container '{id}': {reason}")]
    StartFailed { id: String, reason: String },

    /// Container is in wrong state for operation.
    #[error("container '{id}' is in state '{state}', expected '{expected}'")]
    InvalidState {
        id: String,
        state: String,
        expected: String,
    },

    /// Signal delivery failed.
    #[error("failed to send signal to container '{id}': {reason}")]
    SignalFailed { id: String, reason: String },

    /// Container delete failed.
    #[error("failed to delete container '{id}': {reason}")]
    DeleteFailed { id: String, reason: String },

    // =========================================================================
    // Image/Registry Errors
    // =========================================================================
    /// Failed to parse image reference.
    #[error("invalid image reference '{reference}': {reason}")]
    InvalidImageReference { reference: String, reason: String },

    /// Image pull failed.
    #[error("failed to pull image '{reference}': {reason}")]
    ImagePullFailed { reference: String, reason: String },

    /// Layer extraction failed.
    #[error("failed to extract layer {digest}: {reason}")]
    LayerExtractionFailed { digest: String, reason: String },

    /// Image size exceeded limits.
    #[error("image exceeds size limit: {size} > {limit} bytes")]
    ImageTooLarge { size: u64, limit: u64 },

    /// Path traversal attempt detected in tar archive.
    #[error("path traversal detected in layer: {path}")]
    PathTraversal { path: String },

    // =========================================================================
    // Bundle Errors
    // =========================================================================
    /// Failed to build bundle.
    #[error("failed to build bundle: {0}")]
    BundleBuildFailed(String),

    /// Invalid bundle (missing config.json or rootfs).
    #[error("invalid bundle at {path}: {reason}")]
    InvalidBundle { path: PathBuf, reason: String },

    /// OCI spec generation failed.
    #[error("failed to generate OCI spec: {0}")]
    SpecGenerationFailed(String),

    // =========================================================================
    // Runtime Errors
    // =========================================================================
    /// Runtime not available on this platform.
    #[error("runtime '{runtime}' not available: {reason}")]
    RuntimeUnavailable { runtime: String, reason: String },

    /// Operation not supported by this runtime.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Exec failed.
    #[error("exec failed in container '{container}': {reason}")]
    ExecFailed { container: String, reason: String },

    // =========================================================================
    // Platform Errors
    // =========================================================================
    /// Platform capability not available.
    #[error("platform capability not available: {capability} ({reason})")]
    CapabilityUnavailable { capability: String, reason: String },

    /// Hypervisor not available.
    #[error("hypervisor not available: {0}")]
    HypervisorUnavailable(String),

    /// Namespace support not available.
    #[error("namespace support not available (Linux required)")]
    NamespacesUnavailable,

    // =========================================================================
    // Storage Errors
    // =========================================================================
    /// Storage initialization failed.
    #[error("failed to initialize storage at {path}: {reason}")]
    StorageInitFailed { path: PathBuf, reason: String },

    /// Blob not found in storage.
    #[error("blob not found: {digest}")]
    BlobNotFound { digest: String },

    /// Storage write failed.
    #[error("failed to write to storage: {0}")]
    StorageWriteFailed(String),

    // =========================================================================
    // I/O Errors
    // =========================================================================
    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    // =========================================================================
    // FFI Errors
    // =========================================================================
    /// FFI call failed.
    #[error("FFI error in {library}: {message}")]
    Ffi { library: String, message: String },

    // =========================================================================
    // Timeout Errors
    // =========================================================================
    /// Operation timed out.
    #[error("operation timed out after {duration:?}: {operation}")]
    Timeout {
        operation: String,
        duration: std::time::Duration,
    },

    // =========================================================================
    // Internal Errors
    // =========================================================================
    /// Internal error (should not happen).
    #[error("internal error: {0}")]
    Internal(String),
}
