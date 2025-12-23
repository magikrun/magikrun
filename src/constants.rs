//! # OCI Runtime Constants
//!
//! Defines all resource limits, timeouts, and configuration keys for the
//! OCI runtime layer. These constants are the **single source of truth**
//! for security-critical bounds throughout the codebase.
//!
//! ## Security Rationale
//!
//! All limits are chosen to prevent resource exhaustion attacks while
//! allowing legitimate workloads. Each constant includes:
//! - The bounded value and units
//! - Security rationale for the limit
//! - Attack vectors mitigated
//!
//! ## Modification Guidelines
//!
//! Before modifying any constant:
//! 1. Evaluate the security impact of the change
//! 2. Consider interactions with other limits (e.g., `MAX_LAYERS × MAX_LAYER_SIZE`)
//! 3. Update dependent tests and documentation
//! 4. Document the rationale for the new value
//!
//! ## Cross-References
//!
//! - [`crate::bundle`]: Uses size limits for layer extraction
//! - [`crate::registry`]: Uses size limits and timeouts for image pulling
//! - [`crate::storage`]: Uses digest validation patterns
//! - [`crate::runtimes`]: Uses resource limits for container configuration

use std::time::Duration;

// =============================================================================
// Size Limits
// =============================================================================
//
// These limits prevent disk exhaustion and memory exhaustion attacks from
// malicious or malformed OCI images. The cumulative worst-case is:
//   MAX_LAYERS × MAX_LAYER_SIZE = 128 × 512 MiB = 64 GiB (compressed)
// However, MAX_ROOTFS_SIZE (4 GiB) provides the actual extraction bound.
// =============================================================================

/// Maximum OCI image reference length in bytes.
///
/// **Security**: Prevents buffer overflow and injection attacks via overly long
/// image names. Registry implementations may have lower limits.
///
/// **Attack Vector**: Malicious image refs like `a]×10000` could exploit parsers.
pub const MAX_IMAGE_REF_LEN: usize = 512;

/// Maximum size of a single compressed OCI layer (512 MiB).
///
/// **Security**: Prevents disk exhaustion during layer download. Each layer
/// is validated against this limit before writing to blob storage.
///
/// **Attack Vector**: A malicious registry could serve infinite-length layers.
pub const MAX_LAYER_SIZE: usize = 512 * 1024 * 1024;

/// Maximum total extracted rootfs size (4 GiB).
///
/// **Security**: The ultimate bound on disk usage from a single image.
/// This limit is enforced during tar extraction, accumulating across all layers.
///
/// **Attack Vector**: Compression bombs (small compressed, huge uncompressed).
pub const MAX_ROOTFS_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum number of layers in an OCI image.
///
/// **Security**: Prevents excessive extraction time and disk I/O from images
/// with pathological layer counts.
///
/// **Attack Vector**: 10,000 1-byte layers would overwhelm file descriptors.
pub const MAX_LAYERS: usize = 128;

/// Maximum number of files per layer during extraction.
///
/// **Security**: Prevents inode exhaustion attacks where a malicious image
/// contains millions of tiny files to exhaust filesystem inodes.
///
/// **Rationale**: 100,000 files per layer is generous for legitimate images
/// while preventing pathological cases.
pub const MAX_FILES_PER_LAYER: usize = 100_000;

/// Maximum manifest size (1 MiB).
///
/// **Security**: Prevents memory exhaustion from parsing malformed manifests.
/// Standard OCI manifests are typically under 100 KiB.
pub const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

/// Maximum config blob size (1 MiB).
///
/// **Security**: Prevents memory exhaustion from oversized image configs.
/// Standard configs are typically under 50 KiB.
pub const MAX_CONFIG_SIZE: usize = 1024 * 1024;

/// Maximum number of concurrent containers per runtime.
///
/// **Security**: Prevents unbounded memory growth from container state
/// tracking. Applies to all runtime backends.
///
/// **Rationale**: 1024 containers is sufficient for most deployments
/// while bounding runtime memory usage.
pub const MAX_CONTAINERS: usize = 1024;

// =============================================================================
// Resource Limits
// =============================================================================
//
// Container and VM resource limits prevent runaway workloads from consuming
// host resources. These are enforced by the runtime backends (cgroups for
// youki, wasmtime fuel, libkrun VM config).
// =============================================================================

/// Default memory limit for containers (256 MiB).
///
/// **Security**: Containers without explicit limits get this default to
/// prevent unbounded memory consumption. Operators can override upward.
///
/// **Rationale**: 256 MiB supports most microservices while preventing
/// a single container from exhausting host memory.
pub const DEFAULT_MEMORY_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum memory limit for containers (8 GiB).
///
/// **Security**: Hard ceiling even if operator requests more. This prevents
/// misconfiguration from allocating excessive memory.
pub const MAX_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Default memory for microVMs (512 MiB).
///
/// **Rationale**: VMs need more baseline memory than containers due to
/// guest kernel overhead. 512 MiB allows a minimal Linux guest.
pub const DEFAULT_VM_MEMORY_MIB: u32 = 512;

/// Maximum memory for microVMs (4 GiB).
///
/// **Security**: Prevents a single VM from consuming excessive host RAM.
/// For larger workloads, use multiple VMs or native containers.
pub const MAX_VM_MEMORY_MIB: u32 = 4096;

/// Default vCPUs for microVMs.
///
/// **Rationale**: Single vCPU is sufficient for most workloads and
/// minimizes scheduler overhead.
pub const DEFAULT_VCPUS: u32 = 1;

/// Maximum vCPUs for microVMs.
///
/// **Security**: Prevents a single VM from monopolizing host CPUs.
pub const MAX_VCPUS: u32 = 8;

/// Default CPU shares for cgroups (1024 = normal priority).
///
/// **Rationale**: 1024 is the cgroups default, giving containers equal
/// scheduling weight unless explicitly configured.
pub const DEFAULT_CPU_SHARES: u64 = 1024;

/// Maximum PIDs per container.
///
/// **Security**: Prevents fork bombs and PID exhaustion attacks.
/// 4096 is sufficient for most applications while limiting damage.
pub const MAX_PIDS: i64 = 4096;

// =============================================================================
// Timeouts
// =============================================================================
//
// All network and async operations MUST have timeouts to prevent indefinite
// hangs. These defaults are generous for slow networks but bounded.
//
// For operations that should complete faster, callers can use
// `tokio::time::timeout()` with a shorter duration.
// =============================================================================

/// Timeout for image pull operations (5 minutes).
///
/// **Security**: Prevents indefinite hangs from unresponsive registries
/// or network partitions. Includes manifest fetch and all layer downloads.
///
/// **Rationale**: 5 minutes accommodates large images on slow connections
/// while ensuring eventual failure for truly stuck operations.
pub const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for container start operations (60 seconds).
///
/// **Security**: Prevents hangs during container initialization (e.g.,
/// slow init processes, blocked mounts).
///
/// **Rationale**: Most containers start in under 5 seconds; 60s handles
/// slow image load from cold cache.
pub const CONTAINER_START_TIMEOUT: Duration = Duration::from_secs(60);

/// Default graceful shutdown period (30 seconds).
///
/// **Security**: Time between SIGTERM and SIGKILL during container stop.
/// Allows applications to complete in-flight requests.
///
/// **Rationale**: 30s matches Kubernetes default and industry practice.
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Timeout for exec operations (5 minutes).
///
/// **Security**: Prevents runaway exec sessions from consuming resources.
/// Interactive sessions should use streaming, not exec.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(300);

// =============================================================================
// Storage Paths
// =============================================================================
//
// Default subdirectories for runtime state. The base directory is typically
// `~/.magikrun` for user mode or `/var/lib/magikrun` for system mode.
//
// All paths are relative to the configured base directory.
// =============================================================================

/// Subdirectory for OCI blob storage (content-addressed layers).
///
/// Structure: `blobs/sha256/<2-char-prefix>/<full-hash>`
pub const BLOB_STORE_DIR: &str = "blobs";

/// Subdirectory for unpacked OCI runtime bundles.
///
/// Structure: `bundles/<digest>/rootfs/` + `bundles/<digest>/config.json`
pub const BUNDLE_DIR: &str = "bundles";

/// Subdirectory for microVM state (libkrun contexts).
pub const VM_STATE_DIR: &str = "vms";

/// Subdirectory for native container state (youki containers).
pub const CONTAINER_STATE_DIR: &str = "containers";

// =============================================================================
// OCI Spec Versions
// =============================================================================
//
// Version strings for OCI compliance. These are used in generated config.json
// and state.json files.
// =============================================================================

/// OCI Runtime Spec version for generated `config.json`.
///
/// See: <https://github.com/opencontainers/runtime-spec/releases>
pub const OCI_RUNTIME_SPEC_VERSION: &str = "1.0.2";

/// OCI Image Spec version for manifest parsing.
///
/// See: <https://github.com/opencontainers/image-spec/releases>
pub const OCI_IMAGE_SPEC_VERSION: &str = "1.0.2";

// =============================================================================
// OCI Media Types
// =============================================================================
//
// Standard IANA media types for OCI artifacts. Used for content negotiation
// with registries and manifest parsing.
//
// Reference: <https://github.com/opencontainers/image-spec/blob/main/media-types.md>
// =============================================================================

/// OCI Image Manifest media type (single-platform image).
pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// OCI Image Index media type (multi-platform manifest list).
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// OCI Image Config media type (image configuration blob).
pub const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// OCI Layer media type (gzip-compressed tar archive).
///
/// This is the most common layer format for container images.
pub const OCI_LAYER_MEDIA_TYPE_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// OCI Layer media type (zstd-compressed tar archive).
///
/// Zstd offers better compression ratios and faster decompression than gzip.
pub const OCI_LAYER_MEDIA_TYPE_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

/// OCI Layer media type (uncompressed tar archive).
pub const OCI_LAYER_MEDIA_TYPE_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// WebAssembly content layer media type.
///
/// Used for WASM modules stored in OCI registries.
/// See: <https://github.com/solo-io/wasm/blob/master/spec/spec-compat.md>
pub const WASM_LAYER_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";

/// WebAssembly config media type.
///
/// Configuration blob for WASM images in OCI registries.
pub const WASM_CONFIG_MEDIA_TYPE: &str = "application/vnd.wasm.config.v1+json";

/// Annotation key indicating WASM variant.
///
/// When present on an image, indicates the WASM target (e.g., "compat", "preview2").
pub const WASM_VARIANT_ANNOTATION: &str = "module.wasm.image/variant";

// =============================================================================
// WASM Configuration
// =============================================================================
//
// WebAssembly execution limits for the wasmtime runtime. These bounds prevent
// resource exhaustion from malicious or buggy WASM modules.
//
// The isolation model for WASM differs from containers:
// - No filesystem access unless explicitly granted via WASI
// - No network access unless proxied
// - Execution bounded by fuel (instruction count)
// - Memory bounded by page limits
// =============================================================================

/// Maximum WASM module size (256 MiB).
///
/// **Security**: Prevents memory exhaustion during module compilation.
/// Compilation typically uses 10-20x the module size in memory.
///
/// **Rationale**: 256 MiB accommodates large applications while bounding
/// compilation resources. Most WASM modules are under 10 MiB.
pub const MAX_WASM_MODULE_SIZE: usize = 256 * 1024 * 1024;

/// Maximum WASM memory pages (64 KiB each, 4 GiB total).
///
/// **Security**: Caps the addressable memory for a WASM instance.
/// 65536 pages × 64 KiB = 4 GiB (the 32-bit address space limit).
///
/// **Note**: For wasm64, this would need to be reconsidered.
pub const MAX_WASM_MEMORY_PAGES: u32 = 65536;

/// Default WASM fuel limit (1 billion operations).
///
/// **Security**: Bounds CPU time for WASM execution. Prevents infinite loops
/// and CPU-bound DoS attacks. Each WASM instruction consumes 1 fuel.
///
/// **Rationale**: 1B ops typically corresponds to 1-10 seconds of execution
/// depending on the instruction mix. Adjust based on workload requirements.
///
/// **Recovery**: When fuel is exhausted, the module traps with `OutOfFuel`.
pub const DEFAULT_WASM_FUEL: u64 = 1_000_000_000;

// =============================================================================
// Validation Patterns
// =============================================================================
//
// Character allowlists for input validation. These are used to sanitize
// user-provided strings before using them in filesystem paths, container
// names, or other security-sensitive contexts.
//
// All validation is allowlist-based (only listed characters permitted)
// rather than blocklist-based.
// =============================================================================

/// Valid characters for OCI image references.
///
/// Includes: `a-z`, `A-Z`, `0-9`, `-`, `_`, `.`, `/`, `:`, `@`
///
/// The `@` is for digest references like `nginx@sha256:abc...`.
/// The `:` is for tag references like `nginx:latest`.
pub const IMAGE_REF_VALID_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:@";

/// Valid characters for container names/IDs.
///
/// Includes: `a-z`, `A-Z`, `0-9`, `-`, `_`
///
/// **Security**: Excludes `/`, `.`, and other characters that could be used
/// for path traversal when container names are used in filesystem paths.
pub const CONTAINER_NAME_VALID_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/// Maximum container ID length.
///
/// **Security**: Prevents overly long container IDs that could cause
/// filesystem path issues or be used in DoS attacks.
///
/// **Rationale**: 128 characters accommodates UUIDs and descriptive names.
pub const MAX_CONTAINER_ID_LEN: usize = 128;

// =============================================================================
// Container ID Validation Helper
// =============================================================================

/// Validates a container ID for safety.
///
/// # Security
///
/// This function ensures container IDs:
/// - Are non-empty
/// - Don't exceed `MAX_CONTAINER_ID_LEN`
/// - Only contain characters from `CONTAINER_NAME_VALID_CHARS`
///
/// # Returns
///
/// `Ok(())` if valid, `Err(reason)` with a description of the failure.
#[inline]
#[must_use = "validation result must be checked to ensure container ID is safe"]
pub fn validate_container_id(id: &str) -> std::result::Result<(), &'static str> {
    if id.is_empty() {
        return Err("container ID cannot be empty");
    }
    if id.len() > MAX_CONTAINER_ID_LEN {
        return Err("container ID exceeds maximum length");
    }
    if !id.chars().all(|c| CONTAINER_NAME_VALID_CHARS.contains(c)) {
        return Err("container ID contains invalid characters");
    }
    Ok(())
}
