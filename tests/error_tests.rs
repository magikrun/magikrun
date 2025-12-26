//! Tests for error types.
//!
//! Validates error creation, display formatting, and error category coverage.

use magikrun::runtime::Error;
use std::path::PathBuf;
use std::time::Duration;

// =============================================================================
// Container Lifecycle Error Tests
// =============================================================================

#[test]
fn test_container_not_found_display() {
    let err = Error::ContainerNotFound("test-container".to_string());
    let msg = format!("{}", err);

    assert!(
        msg.contains("test-container"),
        "should include container ID"
    );
    assert!(msg.contains("not found"), "should indicate not found");
}

#[test]
fn test_container_already_exists_display() {
    let err = Error::ContainerAlreadyExists("existing-container".to_string());
    let msg = format!("{}", err);

    assert!(
        msg.contains("existing-container"),
        "should include container ID"
    );
    assert!(msg.contains("already exists"), "should indicate exists");
}

#[test]
fn test_invalid_container_id_display() {
    let err = Error::InvalidContainerId {
        id: "bad/../id".to_string(),
        reason: "contains invalid characters".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("bad/../id"), "should include container ID");
    assert!(
        msg.contains("invalid container ID"),
        "should indicate invalid ID"
    );
    assert!(
        msg.contains("contains invalid characters"),
        "should include reason"
    );
}

#[test]
fn test_resource_exhausted_display() {
    let err = Error::ResourceExhausted("maximum container limit reached (1024)".to_string());
    let msg = format!("{}", err);

    assert!(
        msg.contains("resource exhausted"),
        "should indicate resource exhausted"
    );
    assert!(msg.contains("1024"), "should include limit");
}

#[test]
fn test_create_failed_display() {
    let err = Error::CreateFailed {
        id: "my-container".to_string(),
        reason: "rootfs not found".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("my-container"), "should include container ID");
    assert!(msg.contains("rootfs not found"), "should include reason");
}

#[test]
fn test_start_failed_display() {
    let err = Error::StartFailed {
        id: "my-container".to_string(),
        reason: "process already running".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("my-container"), "should include container ID");
    assert!(
        msg.contains("process already running"),
        "should include reason"
    );
}

#[test]
fn test_invalid_state_display() {
    let err = Error::InvalidState {
        id: "my-container".to_string(),
        state: "stopped".to_string(),
        expected: "created".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("my-container"), "should include container ID");
    assert!(msg.contains("stopped"), "should include current state");
    assert!(msg.contains("created"), "should include expected state");
}

#[test]
fn test_signal_failed_display() {
    let err = Error::SignalFailed {
        id: "my-container".to_string(),
        reason: "process not found".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("my-container"), "should include container ID");
    assert!(msg.contains("process not found"), "should include reason");
}

#[test]
fn test_delete_failed_display() {
    let err = Error::DeleteFailed {
        id: "my-container".to_string(),
        reason: "container still running".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("my-container"), "should include container ID");
    assert!(
        msg.contains("container still running"),
        "should include reason"
    );
}

// =============================================================================
// Image/Registry Error Tests
// =============================================================================

#[test]
fn test_invalid_image_reference_display() {
    let err = Error::InvalidImageReference {
        reference: "invalid::ref".to_string(),
        reason: "double colon not allowed".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("invalid::ref"), "should include reference");
    assert!(msg.contains("double colon"), "should include reason");
}

#[test]
fn test_image_pull_failed_display() {
    let err = Error::ImagePullFailed {
        reference: "docker.io/library/alpine:latest".to_string(),
        reason: "connection refused".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("alpine"), "should include image name");
    assert!(msg.contains("connection refused"), "should include reason");
}

#[test]
fn test_layer_extraction_failed_display() {
    let err = Error::LayerExtractionFailed {
        digest: "sha256:abc123".to_string(),
        reason: "corrupt gzip stream".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("sha256:abc123"), "should include digest");
    assert!(msg.contains("corrupt gzip"), "should include reason");
}

#[test]
fn test_image_too_large_display() {
    let err = Error::ImageTooLarge {
        size: 5_000_000_000,
        limit: 4_000_000_000,
    };
    let msg = format!("{}", err);

    assert!(msg.contains("5000000000"), "should include size");
    assert!(msg.contains("4000000000"), "should include limit");
}

#[test]
fn test_path_traversal_display() {
    let err = Error::PathTraversal {
        path: "../../../etc/passwd".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("path traversal"), "should indicate traversal");
    // Note: We include the path for debugging, but in production logs
    // this might be sanitized
}

// =============================================================================
// Bundle Error Tests
// =============================================================================

#[test]
fn test_bundle_build_failed_display() {
    let err = Error::BundleBuildFailed("missing layers".to_string());
    let msg = format!("{}", err);

    assert!(msg.contains("missing layers"), "should include reason");
}

#[test]
fn test_invalid_bundle_display() {
    let err = Error::InvalidBundle {
        path: PathBuf::from("/tmp/bundle"),
        reason: "config.json not found".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("/tmp/bundle"), "should include path");
    assert!(msg.contains("config.json"), "should include reason");
}

#[test]
fn test_spec_generation_failed_display() {
    let err = Error::SpecGenerationFailed("invalid user format".to_string());
    let msg = format!("{}", err);

    assert!(msg.contains("invalid user format"), "should include reason");
}

// =============================================================================
// Runtime Error Tests
// =============================================================================

#[test]
fn test_runtime_unavailable_display() {
    let err = Error::RuntimeUnavailable {
        runtime: "youki".to_string(),
        reason: "Linux namespaces not available".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("youki"), "should include runtime name");
    assert!(msg.contains("not available"), "should indicate unavailable");
}

#[test]
fn test_not_supported_display() {
    let err = Error::NotSupported("checkpoint/restore".to_string());
    let msg = format!("{}", err);

    assert!(
        msg.contains("checkpoint/restore"),
        "should include operation"
    );
    assert!(
        msg.contains("not supported"),
        "should indicate not supported"
    );
}

#[test]
fn test_exec_failed_display() {
    let err = Error::ExecFailed {
        container: "my-container".to_string(),
        reason: "command not found".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("my-container"), "should include container");
    assert!(msg.contains("command not found"), "should include reason");
}

// =============================================================================
// Platform Error Tests
// =============================================================================

#[test]
fn test_capability_unavailable_display() {
    let err = Error::CapabilityUnavailable {
        capability: "namespaces".to_string(),
        reason: "not running as root".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("namespaces"), "should include capability");
    assert!(msg.contains("not running as root"), "should include reason");
}

// =============================================================================
// Storage Error Tests
// =============================================================================

#[test]
fn test_blob_not_found_display() {
    let err = Error::BlobNotFound {
        digest: "sha256:deadbeef".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("sha256:deadbeef"), "should include digest");
}

#[test]
fn test_storage_init_failed_display() {
    let err = Error::StorageInitFailed {
        path: PathBuf::from("/var/lib/storage"),
        reason: "permission denied".to_string(),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("/var/lib/storage"), "should include path");
    assert!(msg.contains("permission denied"), "should include reason");
}

#[test]
fn test_storage_write_failed_display() {
    let err = Error::StorageWriteFailed("disk full".to_string());
    let msg = format!("{}", err);

    assert!(msg.contains("disk full"), "should include reason");
}

// =============================================================================
// Timeout Error Tests
// =============================================================================

#[test]
fn test_timeout_display() {
    let err = Error::Timeout {
        operation: "image pull".to_string(),
        duration: Duration::from_secs(300),
    };
    let msg = format!("{}", err);

    assert!(msg.contains("image pull"), "should include operation");
    assert!(msg.contains("300"), "should include duration");
}

// =============================================================================
// Internal Error Tests
// =============================================================================

#[test]
fn test_internal_error_display() {
    let err = Error::Internal("unexpected state".to_string());
    let msg = format!("{}", err);

    assert!(msg.contains("unexpected state"), "should include message");
}

// =============================================================================
// Error Trait Implementation Tests
// =============================================================================

#[test]
fn test_error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
}

#[test]
fn test_error_is_debug() {
    let err = Error::ContainerNotFound("test".to_string());
    let debug = format!("{:?}", err);

    assert!(!debug.is_empty(), "Debug output should not be empty");
}

#[test]
fn test_error_source() {
    use std::error::Error as StdError;

    let err = Error::ContainerNotFound("test".to_string());
    // Our errors don't wrap other errors, so source is None
    assert!(err.source().is_none());
}
