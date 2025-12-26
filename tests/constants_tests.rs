//! Tests for constants module.
//!
//! Validates that security-critical constants have expected values and
//! that derived limits don't overflow.

// Import from the facade modules (image and runtime)
use magikrun::image::*;
use magikrun::runtime::*;
use std::time::Duration;

// =============================================================================
// Size Limit Tests
// =============================================================================

#[test]
fn test_image_ref_length_reasonable() {
    // Should allow typical image refs like:
    // "registry.example.com:5000/namespace/image:tag@sha256:abc..."
    assert!(MAX_IMAGE_REF_LEN >= 256, "image ref limit too restrictive");
    assert!(MAX_IMAGE_REF_LEN <= 1024, "image ref limit too permissive");
}

#[test]
fn test_layer_size_reasonable() {
    // Layers should support typical base images (100-500 MiB)
    assert!(
        MAX_LAYER_SIZE >= 100 * 1024 * 1024,
        "layer size limit too restrictive for base images"
    );
    assert!(
        MAX_LAYER_SIZE <= 1024 * 1024 * 1024,
        "layer size limit too permissive (> 1 GiB)"
    );
}

#[test]
fn test_rootfs_size_reasonable() {
    // Rootfs should support typical application images
    assert!(
        MAX_ROOTFS_SIZE >= 1024 * 1024 * 1024,
        "rootfs limit too restrictive (< 1 GiB)"
    );
    assert!(
        MAX_ROOTFS_SIZE <= 16 * 1024 * 1024 * 1024,
        "rootfs limit too permissive (> 16 GiB)"
    );
}

#[test]
fn test_layers_count_reasonable() {
    // Should support complex multi-stage builds
    assert!(MAX_LAYERS >= 50, "layer count too restrictive");
    assert!(MAX_LAYERS <= 256, "layer count too permissive");
}

// =============================================================================
// Overflow Safety Tests  
// =============================================================================
//
// Note: MAX_MANIFEST_SIZE and MAX_CONFIG_SIZE tests removed. These constants
// are reserved for future use (when oci_distribution exposes raw bytes) and
// are intentionally not exported from the public API.

#[test]
fn test_cumulative_layer_size_no_overflow() {
    // MAX_LAYERS × MAX_LAYER_SIZE should not overflow u64
    let max_layers = MAX_LAYERS as u64;
    let max_layer_size = MAX_LAYER_SIZE as u64;
    let cumulative = max_layers.checked_mul(max_layer_size);
    assert!(
        cumulative.is_some(),
        "MAX_LAYERS × MAX_LAYER_SIZE overflows u64"
    );
}

#[test]
fn test_rootfs_within_cumulative_layers() {
    // MAX_ROOTFS_SIZE should be <= cumulative layer potential
    // (but typically less due to deduplication and compression)
    let cumulative = (MAX_LAYERS as u64) * (MAX_LAYER_SIZE as u64);
    assert!(
        MAX_ROOTFS_SIZE <= cumulative,
        "MAX_ROOTFS_SIZE exceeds theoretical maximum from layers"
    );
}

// =============================================================================
// Resource Limit Tests
// =============================================================================

#[test]
fn test_memory_limits_ordered() {
    assert!(
        DEFAULT_MEMORY_BYTES < MAX_MEMORY_BYTES,
        "default memory should be less than max"
    );
}

#[test]
fn test_vm_memory_limits_ordered() {
    assert!(
        DEFAULT_VM_MEMORY_MIB < MAX_VM_MEMORY_MIB,
        "default VM memory should be less than max"
    );
}

#[test]
fn test_vcpu_limits_ordered() {
    assert!(DEFAULT_VCPUS <= MAX_VCPUS, "default vCPUs should be <= max");
    assert!(DEFAULT_VCPUS >= 1, "default vCPUs should be at least 1");
}

#[test]
fn test_pids_limit_reasonable() {
    assert!(MAX_PIDS >= 100, "PID limit too restrictive");
    assert!(MAX_PIDS <= 32768, "PID limit too permissive");
}

// =============================================================================
// Timeout Tests
// =============================================================================

#[test]
fn test_image_pull_timeout_reasonable() {
    assert!(
        IMAGE_PULL_TIMEOUT >= Duration::from_secs(60),
        "image pull timeout too short for large images"
    );
    assert!(
        IMAGE_PULL_TIMEOUT <= Duration::from_secs(600),
        "image pull timeout too long (> 10 min)"
    );
}

#[test]
fn test_container_start_timeout_reasonable() {
    assert!(
        CONTAINER_START_TIMEOUT >= Duration::from_secs(10),
        "container start timeout too short"
    );
    assert!(
        CONTAINER_START_TIMEOUT <= Duration::from_secs(120),
        "container start timeout too long"
    );
}

#[test]
fn test_grace_period_reasonable() {
    assert!(
        DEFAULT_GRACE_PERIOD >= Duration::from_secs(5),
        "grace period too short for cleanup"
    );
    assert!(
        DEFAULT_GRACE_PERIOD <= Duration::from_secs(60),
        "grace period too long"
    );
}

#[test]
fn test_exec_timeout_reasonable() {
    assert!(
        EXEC_TIMEOUT >= Duration::from_secs(60),
        "exec timeout too short for diagnostic commands"
    );
    assert!(
        EXEC_TIMEOUT <= Duration::from_secs(600),
        "exec timeout too long"
    );
}

// =============================================================================
// WASM Limit Tests
// =============================================================================

#[test]
fn test_wasm_module_size_reasonable() {
    assert!(
        MAX_WASM_MODULE_SIZE >= 10 * 1024 * 1024,
        "WASM module limit too restrictive (< 10 MiB)"
    );
    assert!(
        MAX_WASM_MODULE_SIZE <= 512 * 1024 * 1024,
        "WASM module limit too permissive (> 512 MiB)"
    );
}

#[test]
fn test_wasm_memory_pages_reasonable() {
    // Each page is 64 KiB
    let max_memory = (MAX_WASM_MEMORY_PAGES as u64) * 65536;
    assert!(
        max_memory >= 256 * 1024 * 1024,
        "WASM memory too restrictive (< 256 MiB)"
    );
    assert!(
        max_memory <= 8 * 1024 * 1024 * 1024,
        "WASM memory too permissive (> 8 GiB)"
    );
}

#[test]
fn test_wasm_fuel_reasonable() {
    assert!(
        DEFAULT_WASM_FUEL >= 100_000_000,
        "WASM fuel too restrictive (< 100M ops)"
    );
    assert!(
        DEFAULT_WASM_FUEL <= 10_000_000_000,
        "WASM fuel too permissive (> 10B ops)"
    );
}

// =============================================================================
// Directory Constants Tests
// =============================================================================

#[test]
fn test_directory_names_valid() {
    // Directory names should be valid path components
    assert!(
        !BLOB_STORE_DIR.contains('/'),
        "blob store dir has path separator"
    );
    assert!(
        !BLOB_STORE_DIR.contains('\\'),
        "blob store dir has backslash"
    );
    assert!(!BLOB_STORE_DIR.is_empty(), "blob store dir is empty");
}

// =============================================================================
// Container Limit Tests
// =============================================================================

#[test]
fn test_max_containers_reasonable() {
    assert!(
        MAX_CONTAINERS >= 100,
        "MAX_CONTAINERS too restrictive (< 100)"
    );
    assert!(
        MAX_CONTAINERS <= 10000,
        "MAX_CONTAINERS too permissive (> 10000)"
    );
}

#[test]
fn test_max_container_id_len_reasonable() {
    assert!(
        MAX_CONTAINER_ID_LEN >= 64,
        "MAX_CONTAINER_ID_LEN too short for UUIDs"
    );
    assert!(
        MAX_CONTAINER_ID_LEN <= 256,
        "MAX_CONTAINER_ID_LEN too permissive"
    );
}

// =============================================================================
// Container ID Validation Tests
// =============================================================================

#[test]
fn test_validate_container_id_valid_cases() {
    // Valid container IDs
    assert!(validate_container_id("my-container").is_ok());
    assert!(validate_container_id("container_123").is_ok());
    assert!(validate_container_id("MyContainer").is_ok());
    assert!(validate_container_id("a").is_ok()); // Single char
    assert!(validate_container_id("0123456789").is_ok()); // All digits
    assert!(validate_container_id("abc-def_ghi").is_ok()); // Mixed
}

#[test]
fn test_validate_container_id_empty() {
    let result = validate_container_id("");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "container ID cannot be empty");
}

#[test]
fn test_validate_container_id_too_long() {
    let long_id = "a".repeat(MAX_CONTAINER_ID_LEN + 1);
    let result = validate_container_id(&long_id);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "container ID exceeds maximum length");

    // At the limit should be OK
    let at_limit = "a".repeat(MAX_CONTAINER_ID_LEN);
    assert!(validate_container_id(&at_limit).is_ok());
}

#[test]
fn test_validate_container_id_invalid_characters() {
    // Path traversal characters
    assert!(validate_container_id("../escape").is_err());
    assert!(validate_container_id("path/to/container").is_err());
    assert!(validate_container_id("container.name").is_err());

    // Special characters
    assert!(validate_container_id("container@host").is_err());
    assert!(validate_container_id("container:tag").is_err());
    assert!(validate_container_id("container name").is_err()); // space

    // Control characters
    assert!(validate_container_id("container\n").is_err());
    assert!(validate_container_id("container\0").is_err());
}
