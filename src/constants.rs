//! Constants for the OCI runtime layer.
//!
//! All limits, timeouts, and keys are defined here to ensure
//! consistency and prevent magic numbers throughout the codebase.

use std::time::Duration;

// =============================================================================
// Size Limits
// =============================================================================

/// Maximum OCI image reference length (bytes).
/// Prevents injection attacks via overly long image names.
pub const MAX_IMAGE_REF_LEN: usize = 512;

/// Maximum size of a single OCI layer (512 MiB).
/// Prevents disk exhaustion from malicious images.
pub const MAX_LAYER_SIZE: usize = 512 * 1024 * 1024;

/// Maximum total rootfs size (4 GiB).
/// Prevents disk exhaustion from unpacked images.
pub const MAX_ROOTFS_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum number of layers in an OCI image.
pub const MAX_LAYERS: usize = 128;

/// Maximum manifest size (1 MiB).
pub const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

/// Maximum config blob size (1 MiB).
pub const MAX_CONFIG_SIZE: usize = 1024 * 1024;

// =============================================================================
// Resource Limits
// =============================================================================

/// Default memory limit for containers (256 MiB).
pub const DEFAULT_MEMORY_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum memory limit for containers (8 GiB).
pub const MAX_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Default memory for microVMs (512 MiB).
pub const DEFAULT_VM_MEMORY_MIB: u32 = 512;

/// Maximum memory for microVMs (4 GiB).
pub const MAX_VM_MEMORY_MIB: u32 = 4096;

/// Default vCPUs for microVMs.
pub const DEFAULT_VCPUS: u32 = 1;

/// Maximum vCPUs for microVMs.
pub const MAX_VCPUS: u32 = 8;

/// Default CPU shares for cgroups.
pub const DEFAULT_CPU_SHARES: u64 = 1024;

/// Maximum PIDs per container.
pub const MAX_PIDS: i64 = 4096;

// =============================================================================
// Timeouts
// =============================================================================

/// Timeout for image pull operations.
pub const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for container start operations.
pub const CONTAINER_START_TIMEOUT: Duration = Duration::from_secs(60);

/// Default graceful shutdown period.
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Timeout for exec operations.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(300);

// =============================================================================
// Storage Paths
// =============================================================================

/// Subdirectory for OCI blob storage.
pub const BLOB_STORE_DIR: &str = "blobs";

/// Subdirectory for unpacked bundles.
pub const BUNDLE_DIR: &str = "bundles";

/// Subdirectory for VM state.
pub const VM_STATE_DIR: &str = "vms";

/// Subdirectory for container state.
pub const CONTAINER_STATE_DIR: &str = "containers";

// =============================================================================
// OCI Spec Versions
// =============================================================================

/// OCI Runtime Spec version.
pub const OCI_RUNTIME_SPEC_VERSION: &str = "1.0.2";

/// OCI Image Spec version.
pub const OCI_IMAGE_SPEC_VERSION: &str = "1.0.2";

// =============================================================================
// OCI Media Types
// =============================================================================

/// OCI Image Manifest media type.
pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// OCI Image Index media type.
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// OCI Image Config media type.
pub const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// OCI Layer media type (gzip compressed).
pub const OCI_LAYER_MEDIA_TYPE_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// OCI Layer media type (zstd compressed).
pub const OCI_LAYER_MEDIA_TYPE_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

/// OCI Layer media type (uncompressed).
pub const OCI_LAYER_MEDIA_TYPE_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// WASM content layer media type.
pub const WASM_LAYER_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";

/// WASM config media type.
pub const WASM_CONFIG_MEDIA_TYPE: &str = "application/vnd.wasm.config.v1+json";

/// Annotation key for WASM image variant.
pub const WASM_VARIANT_ANNOTATION: &str = "module.wasm.image/variant";

// =============================================================================
// WASM Configuration
// =============================================================================

/// Maximum WASM module size (256 MiB).
pub const MAX_WASM_MODULE_SIZE: usize = 256 * 1024 * 1024;

/// Maximum WASM memory pages (64 KiB each, 4 GiB total).
pub const MAX_WASM_MEMORY_PAGES: u32 = 65536;

/// WASM fuel limit for bounded execution.
pub const DEFAULT_WASM_FUEL: u64 = 1_000_000_000;

// =============================================================================
// Validation Patterns
// =============================================================================

/// Valid characters for image references.
pub const IMAGE_REF_VALID_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:@";

/// Valid characters for container names.
pub const CONTAINER_NAME_VALID_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
