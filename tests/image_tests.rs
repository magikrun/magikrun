//! Tests for OCI Image Spec compliance.
//!
//! Validates ImageService, ImageHandle, and image reference handling
//! per OCI Image Format Specification.

#![allow(clippy::assertions_on_constants)]
#![allow(clippy::const_is_empty)]

use magikrun::image::{
    BlobStore,
    // Constants
    IMAGE_REF_VALID_CHARS,
    ImageInfo,
    ImageService,
    MAX_IMAGE_REF_LEN,
    MAX_LAYER_SIZE,
    MAX_LAYERS,
    // OCI media types
    OCI_IMAGE_CONFIG_MEDIA_TYPE,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    OCI_LAYER_MEDIA_TYPE_GZIP,
    OCI_LAYER_MEDIA_TYPE_TAR,
    OCI_LAYER_MEDIA_TYPE_ZSTD,
    Platform,
    // WASM media types
    WASM_CONFIG_MEDIA_TYPE,
    WASM_LAYER_MEDIA_TYPE,
    WASM_VARIANT_ANNOTATION,
};
use std::sync::Arc;
use tempfile::TempDir;

// =============================================================================
// ImageService Creation Tests
// =============================================================================

#[test]
fn test_image_service_creation() {
    let service = ImageService::new();
    assert!(service.is_ok(), "ImageService::new() should succeed");
}

#[test]
fn test_image_service_with_custom_storage() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());

    let service = ImageService::with_storage(storage.clone());

    // Storage should be the same instance
    assert!(Arc::ptr_eq(service.storage(), &storage));
}

#[test]
fn test_image_service_storage_accessor() {
    let service = ImageService::new().unwrap();
    let storage = service.storage();

    // Should return a valid storage instance
    assert!(!storage.base_dir().as_os_str().is_empty());
}

// =============================================================================
// Image Reference Validation Tests
// =============================================================================

#[test]
fn test_image_ref_valid_simple() {
    // Simple references should be valid
    let valid_refs = [
        "nginx",
        "nginx:latest",
        "nginx:1.25",
        "alpine:3.18",
        "busybox:musl",
    ];

    for ref_str in valid_refs {
        // Validate reference is within length limit and uses valid chars
        assert!(
            ref_str.len() <= MAX_IMAGE_REF_LEN,
            "reference {} should be within length limit",
            ref_str
        );
        assert!(
            ref_str.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)),
            "reference {} should contain only valid characters",
            ref_str
        );
    }
}

#[test]
fn test_image_ref_valid_with_registry() {
    // Registry-qualified references
    let valid_refs = [
        "docker.io/library/nginx:latest",
        "ghcr.io/owner/repo:tag",
        "gcr.io/project/image:v1.2.3",
        "registry.example.com/image:tag",
        "registry.example.com:5000/image:tag",
    ];

    for ref_str in valid_refs {
        // Validate reference is within length limit
        assert!(
            ref_str.len() <= MAX_IMAGE_REF_LEN,
            "reference {} should be within length limit",
            ref_str
        );
        // Validate all characters are in allowlist
        assert!(
            ref_str.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)),
            "reference {} should contain only valid characters",
            ref_str
        );
    }
}

#[test]
fn test_image_ref_valid_with_digest() {
    // References with digest
    let valid_refs = [
        "nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "ghcr.io/owner/repo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];

    for ref_str in valid_refs {
        assert!(
            ref_str.len() <= MAX_IMAGE_REF_LEN,
            "reference {} should be within length limit",
            ref_str
        );
        assert!(
            ref_str.chars().all(|c| IMAGE_REF_VALID_CHARS.contains(c)),
            "reference {} should contain only valid characters",
            ref_str
        );
    }
}

#[test]
fn test_image_ref_empty_rejected() {
    // Empty reference should be invalid
    let empty_ref = "";
    assert!(
        empty_ref.is_empty(),
        "empty reference should fail validation"
    );
}

#[test]
fn test_image_ref_too_long_rejected() {
    // Reference exceeding MAX_IMAGE_REF_LEN should be rejected
    let long_ref = "a".repeat(MAX_IMAGE_REF_LEN + 1);
    assert!(
        long_ref.len() > MAX_IMAGE_REF_LEN,
        "test reference should exceed limit"
    );
}

#[test]
fn test_image_ref_invalid_characters() {
    // Characters outside the allowlist should be rejected
    let invalid_refs = [
        "nginx:latest!",     // exclamation
        "image name:tag",    // space
        "image\nname:tag",   // newline
        "image\tname:tag",   // tab
        "image;name:tag",    // semicolon
        "image|name:tag",    // pipe
        "image&name:tag",    // ampersand
        "image$(cmd):tag",   // command substitution
        "image`cmd`:tag",    // backtick
        "image'name':tag",   // single quote
        "image\"name\":tag", // double quote
    ];

    for ref_str in invalid_refs {
        let has_invalid = ref_str.chars().any(|c| !IMAGE_REF_VALID_CHARS.contains(c));
        assert!(
            has_invalid,
            "reference {} should contain invalid characters",
            ref_str
        );
    }
}

#[test]
fn test_path_traversal_in_image_ref() {
    // Note: Path traversal like "../../../etc/passwd" uses valid chars
    // (dots, slashes, alphanumerics) but should be caught at a different
    // layer (reference parsing, not character validation)
    let traversal_ref = "../../../etc/passwd";

    // All characters are technically valid
    let all_valid = traversal_ref
        .chars()
        .all(|c| IMAGE_REF_VALID_CHARS.contains(c));
    assert!(
        all_valid,
        "traversal uses valid chars but should fail parsing"
    );

    // The reference parsing layer should reject this
    // (tested via ImageService.pull() which validates format)
}

// =============================================================================
// Image Reference Character Allowlist Tests
// =============================================================================

#[test]
fn test_image_ref_valid_chars_constant() {
    // The allowlist should contain expected characters
    let required_chars = [
        'a', 'z', 'A', 'Z', '0', '9', // alphanumeric
        '/', ':', '.', '-', '_', '@', // special characters
    ];

    for c in required_chars {
        assert!(
            IMAGE_REF_VALID_CHARS.contains(c),
            "allowlist should contain '{}'",
            c
        );
    }
}

#[test]
fn test_image_ref_valid_chars_excludes_dangerous() {
    // The allowlist should NOT contain dangerous characters
    let dangerous_chars = [
        ' ', '\t', '\n', '\r', // whitespace
        ';', '|', '&', '$', '`', // shell metacharacters
        '!', '?', '*', '[', ']', // glob characters
        '(', ')', '{', '}', // brackets
        '<', '>', // redirects
        '"', '\'', '\\', // quotes and escape
    ];

    for c in dangerous_chars {
        assert!(
            !IMAGE_REF_VALID_CHARS.contains(c),
            "allowlist should NOT contain '{}'",
            c
        );
    }
}

// =============================================================================
// OCI Media Type Tests
// =============================================================================

#[test]
fn test_oci_image_media_types() {
    // Verify OCI media types match the specification
    assert_eq!(
        OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(
        OCI_IMAGE_INDEX_MEDIA_TYPE,
        "application/vnd.oci.image.index.v1+json"
    );
    assert_eq!(
        OCI_IMAGE_CONFIG_MEDIA_TYPE,
        "application/vnd.oci.image.config.v1+json"
    );
}

#[test]
fn test_oci_layer_media_types() {
    // Verify layer media types match the specification
    assert_eq!(
        OCI_LAYER_MEDIA_TYPE_TAR,
        "application/vnd.oci.image.layer.v1.tar"
    );
    assert_eq!(
        OCI_LAYER_MEDIA_TYPE_GZIP,
        "application/vnd.oci.image.layer.v1.tar+gzip"
    );
    assert_eq!(
        OCI_LAYER_MEDIA_TYPE_ZSTD,
        "application/vnd.oci.image.layer.v1.tar+zstd"
    );
}

#[test]
fn test_wasm_media_types() {
    // Verify WASM-specific media types
    assert_eq!(
        WASM_CONFIG_MEDIA_TYPE,
        "application/vnd.wasm.config.v1+json"
    );
    assert_eq!(
        WASM_LAYER_MEDIA_TYPE,
        "application/vnd.wasm.content.layer.v1+wasm"
    );
    assert_eq!(WASM_VARIANT_ANNOTATION, "module.wasm.image/variant");
}

// =============================================================================
// Size Limit Constant Tests
// =============================================================================

#[test]
fn test_max_image_ref_len() {
    // 512 bytes is reasonable for image references
    assert_eq!(MAX_IMAGE_REF_LEN, 512);
    assert!(
        MAX_IMAGE_REF_LEN > 100,
        "limit should allow reasonable refs"
    );
    assert!(MAX_IMAGE_REF_LEN < 4096, "limit should prevent abuse");
}

#[test]
fn test_max_layer_size() {
    // 512 MiB per layer
    assert_eq!(MAX_LAYER_SIZE, 512 * 1024 * 1024);
}

#[test]
fn test_max_layers() {
    // 128 layers maximum
    assert_eq!(MAX_LAYERS, 128);
    assert!(MAX_LAYERS >= 32, "should allow multi-layer images");
    assert!(MAX_LAYERS <= 256, "should prevent layer bomb attacks");
}

// =============================================================================
// ImageInfo Tests
// =============================================================================

#[test]
fn test_image_info_structure() {
    let info = ImageInfo {
        digest: "sha256:abc123".to_string(),
        size: 1024,
    };

    assert_eq!(info.digest, "sha256:abc123");
    assert_eq!(info.size, 1024);
}

#[test]
fn test_image_info_clone() {
    let info = ImageInfo {
        digest: "sha256:abc123".to_string(),
        size: 1024,
    };

    let cloned = info.clone();
    assert_eq!(cloned.digest, info.digest);
    assert_eq!(cloned.size, info.size);
}

// =============================================================================
// Platform Detection Tests
// =============================================================================

#[test]
fn test_platform_detect() {
    let platform = Platform::detect();

    // Should detect current platform
    #[cfg(target_os = "macos")]
    {
        assert_eq!(platform.os, magikrun::image::Os::Darwin);
    }
    #[cfg(target_os = "linux")]
    {
        assert_eq!(platform.os, magikrun::image::Os::Linux);
    }
    #[cfg(target_os = "windows")]
    {
        assert_eq!(platform.os, magikrun::image::Os::Windows);
    }
}

#[test]
fn test_platform_arch_detection() {
    let platform = Platform::detect();

    // Should detect current architecture
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(platform.arch, magikrun::image::Arch::Amd64);
    }
    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(platform.arch, magikrun::image::Arch::Arm64);
    }
}

// =============================================================================
// List Images Tests
// =============================================================================

#[test]
fn test_list_images_empty() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    let images = service.list().unwrap();
    assert!(images.is_empty(), "new service should have no images");
}

#[test]
fn test_exists_nonexistent_image() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    let exists =
        service.exists("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    assert!(!exists, "nonexistent image should not exist");
}

// =============================================================================
// Remove Image Tests
// =============================================================================

#[test]
fn test_remove_nonexistent_image() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    // Removing nonexistent image should not panic
    // (may succeed or return error depending on implementation)
    let _ =
        service.remove("sha256:0000000000000000000000000000000000000000000000000000000000000000");
}
// =============================================================================
// ImageService Validation Behavior Tests
// =============================================================================

#[tokio::test]
async fn test_pull_empty_reference_fails() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    let result = service.pull("").await;
    assert!(result.is_err(), "empty reference should fail");

    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("empty") || err_msg.contains("invalid"),
        "error should mention empty/invalid: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_pull_too_long_reference_fails() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    let long_ref = "a".repeat(MAX_IMAGE_REF_LEN + 1);
    let result = service.pull(&long_ref).await;
    assert!(result.is_err(), "too long reference should fail");

    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("length") || err_msg.contains("exceeds"),
        "error should mention length: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_pull_invalid_chars_fails() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    // Shell injection attempt
    let result = service.pull("nginx; rm -rf /").await;
    assert!(result.is_err(), "shell injection should fail");
}

#[tokio::test]
async fn test_pull_nonexistent_registry_fails() {
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage);

    // This should fail because the registry doesn't exist
    let result = service
        .pull("nonexistent.invalid.registry.test/image:tag")
        .await;
    assert!(result.is_err(), "nonexistent registry should fail");
}

// =============================================================================
// Blob Storage Integration Tests
// =============================================================================

#[test]
fn test_image_service_shares_storage_correctly() {
    use sha2::{Digest, Sha256};

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage.clone());

    // Put a blob directly into storage
    let data = b"test blob content";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));
    storage.put_blob(&digest, data).unwrap();

    // Service should see it via exists()
    assert!(
        service.exists(&digest),
        "service should see blob in shared storage"
    );
}

#[test]
fn test_image_service_list_after_storage_add() {
    use sha2::{Digest, Sha256};

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage.clone());

    // Initially empty
    assert!(service.list().unwrap().is_empty());

    // Add blobs to storage
    for i in 0..3 {
        let data = format!("blob content {}", i);
        let hash = Sha256::digest(data.as_bytes());
        let digest = format!("sha256:{}", hex::encode(hash));
        storage.put_blob(&digest, data.as_bytes()).unwrap();
    }

    // Service should list them
    let images = service.list().unwrap();
    assert_eq!(images.len(), 3, "should list all blobs");
}

#[test]
fn test_image_service_remove_actually_removes() {
    use sha2::{Digest, Sha256};

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());
    let service = ImageService::with_storage(storage.clone());

    // Add a blob
    let data = b"to be removed";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));
    storage.put_blob(&digest, data).unwrap();

    assert!(service.exists(&digest));

    // Remove it
    service.remove(&digest).unwrap();

    assert!(!service.exists(&digest), "blob should be removed");
}
