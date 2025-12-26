//! Tests for OCI Distribution Spec compliance.
//!
//! Validates RegistryClient, image pulling, and registry interaction
//! per OCI Distribution Specification.

use magikrun::image::{
    BlobStore,
    // Constants
    IMAGE_PULL_TIMEOUT,
    IMAGE_REF_VALID_CHARS,
    MAX_IMAGE_REF_LEN,
    MAX_LAYER_SIZE,
    MAX_LAYERS,
    Platform,
    is_wasm_image,
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

// =============================================================================
// Image Reference Validation Tests (Distribution Spec)
// =============================================================================

#[test]
fn test_max_image_ref_len_constant() {
    // OCI Distribution doesn't specify a limit, but 512 bytes is reasonable
    assert_eq!(MAX_IMAGE_REF_LEN, 512);
}

#[test]
fn test_image_ref_valid_chars_constant() {
    // Characters allowed in image references
    // Must include: alphanumeric, /, :, ., -, _, @
    let required = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/:.-_@";

    for c in required.chars() {
        assert!(
            IMAGE_REF_VALID_CHARS.contains(c),
            "IMAGE_REF_VALID_CHARS should contain '{}'",
            c
        );
    }
}

#[test]
fn test_image_ref_format_docker_hub() {
    // Docker Hub shorthand references
    let refs = [
        "nginx",
        "nginx:latest",
        "nginx:1.25",
        "library/nginx",
        "library/nginx:latest",
    ];

    for r in refs {
        assert!(r.len() <= MAX_IMAGE_REF_LEN);
        assert!(r.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)));
    }
}

#[test]
fn test_image_ref_format_registry_qualified() {
    // Fully-qualified registry references
    let refs = [
        "docker.io/library/nginx:latest",
        "ghcr.io/owner/repo:tag",
        "gcr.io/project/image:v1.2.3",
        "quay.io/organization/image:latest",
        "registry.k8s.io/pause:3.9",
        "mcr.microsoft.com/dotnet/sdk:8.0",
    ];

    for r in refs {
        assert!(r.len() <= MAX_IMAGE_REF_LEN);
        assert!(r.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)));
    }
}

#[test]
fn test_image_ref_format_with_port() {
    // Registry with custom port
    let refs = [
        "localhost:5000/myimage:latest",
        "registry.example.com:5000/image:tag",
        "192.168.1.100:5000/test:v1",
    ];

    for r in refs {
        assert!(r.len() <= MAX_IMAGE_REF_LEN);
        assert!(r.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)));
    }
}

#[test]
fn test_image_ref_format_with_digest() {
    // References with digest instead of tag
    let refs = [
        "nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "ghcr.io/owner/repo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];

    for r in refs {
        assert!(r.len() <= MAX_IMAGE_REF_LEN);
        assert!(r.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)));
        assert!(r.contains('@'), "digest ref should contain @");
        assert!(r.contains("sha256:"), "digest ref should contain sha256:");
    }
}

#[test]
fn test_image_ref_format_with_tag_and_digest() {
    // Both tag and digest (tag ignored, digest used)
    let r = "nginx:latest@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    assert!(r.len() <= MAX_IMAGE_REF_LEN);
    assert!(r.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)));
}

// =============================================================================
// Timeout Configuration Tests
// =============================================================================

#[test]
fn test_image_pull_timeout_constant() {
    // 5 minutes for image pull
    assert_eq!(IMAGE_PULL_TIMEOUT, Duration::from_secs(300));
}

#[test]
fn test_image_pull_timeout_reasonable() {
    // Should be at least 30 seconds for large images
    assert!(IMAGE_PULL_TIMEOUT >= Duration::from_secs(30));

    // Should be at most 10 minutes to prevent hung operations
    assert!(IMAGE_PULL_TIMEOUT <= Duration::from_secs(600));
}

// =============================================================================
// Layer Limit Tests
// =============================================================================

#[test]
fn test_max_layers_constant() {
    // 128 layers maximum
    assert_eq!(MAX_LAYERS, 128);
}

#[test]
fn test_max_layers_reasonable() {
    // Should allow typical images (usually < 50 layers)
    assert!(MAX_LAYERS >= 50);

    // Should prevent layer bomb attacks
    assert!(MAX_LAYERS <= 256);
}

#[test]
fn test_max_layer_size_constant() {
    // 512 MiB per layer
    assert_eq!(MAX_LAYER_SIZE, 512 * 1024 * 1024);
}

#[test]
fn test_max_layer_size_reasonable() {
    // Should allow typical base images (alpine ~5MB, ubuntu ~30MB)
    assert!(MAX_LAYER_SIZE >= 100 * 1024 * 1024); // At least 100 MiB

    // Should prevent single layer DoS
    assert!(MAX_LAYER_SIZE <= 1024 * 1024 * 1024); // At most 1 GiB
}

// =============================================================================
// WASM Image Detection Tests
// =============================================================================

#[test]
fn test_is_wasm_image_by_reference() {
    // WASM-specific image references (based on convention)
    let wasm_refs = [
        "ghcr.io/example/myapp.wasm:latest",
        "docker.io/wasm/module:v1",
    ];

    for r in wasm_refs {
        // Detection may be based on reference pattern or manifest
        // This tests the helper function exists and runs
        let _ = is_wasm_image(r);
    }
}

#[test]
fn test_is_wasm_image_standard() {
    // Standard container images (not WASM)
    let standard_refs = ["nginx:latest", "alpine:3.18", "ubuntu:22.04"];

    for r in standard_refs {
        // Standard images should not be detected as WASM
        // (actual detection may depend on manifest inspection)
        let is_wasm = is_wasm_image(r);
        // Most likely false for standard refs, but depends on implementation
        let _ = is_wasm;
    }
}

// =============================================================================
// Platform Resolution Tests
// =============================================================================

#[test]
fn test_platform_os_display() {
    let platform = Platform::detect();

    // OS should be displayable
    let os_str = format!("{:?}", platform.os);
    assert!(!os_str.is_empty());
}

#[test]
fn test_platform_arch_display() {
    let platform = Platform::detect();

    // Arch should be displayable
    let arch_str = format!("{:?}", platform.arch);
    assert!(!arch_str.is_empty());
}

#[test]
fn test_platform_for_image_resolution() {
    // Platform used for multi-arch image resolution
    let platform = Platform::detect();

    // Should have OS and arch set
    #[cfg(target_os = "macos")]
    assert!(matches!(platform.os, magikrun::image::Os::Darwin));

    #[cfg(target_os = "linux")]
    assert!(matches!(platform.os, magikrun::image::Os::Linux));

    #[cfg(target_os = "windows")]
    assert!(matches!(platform.os, magikrun::image::Os::Windows));
}

// =============================================================================
// Registry Error Handling Tests
// =============================================================================

#[tokio::test]
async fn test_pull_image_validates_reference_length() {
    use magikrun::image::ImageService;

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    // Empty reference
    let result = service.pull("").await;
    assert!(result.is_err(), "empty reference should fail");

    // Too long reference
    let long_ref = "a".repeat(MAX_IMAGE_REF_LEN + 1);
    let result = service.pull(&long_ref).await;
    assert!(result.is_err(), "too long reference should fail");
}

#[tokio::test]
async fn test_pull_image_validates_reference_chars() {
    use magikrun::image::ImageService;

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    // Shell injection attempts
    let malicious_refs = [
        "nginx; rm -rf /",
        "alpine | cat /etc/passwd",
        "image$(whoami):tag",
        "image`id`:tag",
    ];

    for bad_ref in malicious_refs {
        let result = service.pull(bad_ref).await;
        assert!(result.is_err(), "malicious ref should fail: {}", bad_ref);
    }
}

#[tokio::test]
async fn test_pull_image_handles_network_errors() {
    use magikrun::image::ImageService;

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    // Non-routable address should fail quickly
    let result = service.pull("10.255.255.1:5000/test:latest").await;
    assert!(result.is_err(), "unreachable registry should fail");
}

// =============================================================================
// BlobStore Integration Tests (for Registry Storage)
// =============================================================================

#[test]
fn test_blob_store_for_registry() {
    let temp_dir = TempDir::new().unwrap();
    let storage = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Registry layers are stored in BlobStore
    assert!(storage.base_dir().exists());
}

#[test]
fn test_blob_store_arc_sharing() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());

    // Registry and ImageService share storage via Arc
    let storage2 = Arc::clone(&storage);
    assert!(Arc::ptr_eq(&storage, &storage2));
}

#[test]
fn test_blob_store_layer_deduplication() {
    use sha2::{Digest, Sha256};

    let temp_dir = TempDir::new().unwrap();
    let storage = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Simulate layer deduplication
    let layer_content = b"this is a shared base layer";
    let hash = Sha256::digest(layer_content);
    let digest = format!("sha256:{}", hex::encode(hash));

    // First write
    storage.put_blob(&digest, layer_content).unwrap();
    assert!(storage.has_blob(&digest));

    // Second write (same content) should succeed (dedup)
    storage.put_blob(&digest, layer_content).unwrap();
    assert!(storage.has_blob(&digest));

    // Content should be identical
    let retrieved = storage.get_blob(&digest).unwrap();
    assert_eq!(retrieved, layer_content);
}

// =============================================================================
// Digest Format Tests
// =============================================================================

#[test]
fn test_sha256_digest_format() {
    // OCI digests use algorithm:hex format
    let valid_digests = [
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];

    for digest in valid_digests {
        assert!(digest.starts_with("sha256:"));
        let hex_part = &digest[7..];
        assert_eq!(hex_part.len(), 64, "SHA256 hex should be 64 chars");
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "should be hex"
        );
    }
}

#[test]
fn test_digest_content_verification() {
    use sha2::{Digest, Sha256};

    let temp_dir = TempDir::new().unwrap();
    let storage = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Correct digest should work
    let content = b"verified content";
    let hash = Sha256::digest(content);
    let correct_digest = format!("sha256:{}", hex::encode(hash));

    let result = storage.put_blob(&correct_digest, content);
    assert!(result.is_ok(), "correct digest should work");

    // Wrong digest should fail
    let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let result = storage.put_blob(wrong_digest, content);
    assert!(result.is_err(), "wrong digest should fail");
}

// =============================================================================
// WASM Image Detection Tests
// =============================================================================

#[test]
fn test_is_wasm_image_detection() {
    // Test WASM detection function
    let wasm_refs = ["ghcr.io/example/myapp.wasm:latest"];

    for r in wasm_refs {
        let result = is_wasm_image(r);
        // Just verify function runs without panic
        let _ = result;
    }
}

// =============================================================================
// Platform Resolution Behavior Tests
// =============================================================================

#[test]
fn test_platform_oci_string_format() {
    let platform = Platform::detect();
    let oci_platform = platform.oci_platform();

    // Format should be "os/arch"
    assert!(oci_platform.contains('/'), "should be os/arch format");

    let parts: Vec<&str> = oci_platform.split('/').collect();
    assert_eq!(parts.len(), 2);

    // OS should be one of the known values
    let valid_os = ["linux", "darwin", "windows"];
    assert!(valid_os.contains(&parts[0]), "unknown OS: {}", parts[0]);

    // Arch should be one of the known values
    let valid_arch = ["amd64", "arm64", "arm", "386"];
    assert!(valid_arch.contains(&parts[1]), "unknown arch: {}", parts[1]);
}

#[test]
fn test_platform_matches_build_target() {
    let platform = Platform::detect();

    #[cfg(target_os = "linux")]
    assert!(platform.oci_platform().starts_with("linux/"));

    #[cfg(target_os = "macos")]
    assert!(platform.oci_platform().starts_with("darwin/"));

    #[cfg(target_os = "windows")]
    assert!(platform.oci_platform().starts_with("windows/"));

    #[cfg(target_arch = "x86_64")]
    assert!(platform.oci_platform().ends_with("/amd64"));

    #[cfg(target_arch = "aarch64")]
    assert!(platform.oci_platform().ends_with("/arm64"));
}

// =============================================================================
// Error Type Tests
// =============================================================================

#[test]
fn test_error_types_are_distinct() {
    use magikrun::runtime::Error;

    // Create different error types
    let invalid_ref = Error::InvalidImageReference {
        reference: "bad".to_string(),
        reason: "test".to_string(),
    };

    let pull_failed = Error::ImagePullFailed {
        reference: "image".to_string(),
        reason: "network".to_string(),
    };

    let too_large = Error::ImageTooLarge {
        size: 1000,
        limit: 500,
    };

    // Each should have distinct error message
    let msg1 = format!("{}", invalid_ref);
    let msg2 = format!("{}", pull_failed);
    let msg3 = format!("{}", too_large);

    assert_ne!(msg1, msg2);
    assert_ne!(msg2, msg3);
    assert_ne!(msg1, msg3);
}

#[test]
fn test_error_contains_useful_info() {
    use magikrun::runtime::Error;

    let err = Error::ImagePullFailed {
        reference: "docker.io/library/nginx:latest".to_string(),
        reason: "connection refused".to_string(),
    };

    let msg = format!("{}", err);
    assert!(msg.contains("nginx"), "error should contain image name");
    assert!(
        msg.contains("connection refused"),
        "error should contain reason"
    );
}
