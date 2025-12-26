//! Tests for runtime trait and container state.
//!
//! Validates OciRuntime trait contract, container state machine,
//! and signal handling.

use magikrun::runtime::{ContainerState, ContainerStatus, Signal};

// =============================================================================
// ContainerStatus Tests
// =============================================================================

#[test]
fn test_container_status_display() {
    assert_eq!(format!("{}", ContainerStatus::Creating), "creating");
    assert_eq!(format!("{}", ContainerStatus::Created), "created");
    assert_eq!(format!("{}", ContainerStatus::Running), "running");
    assert_eq!(format!("{}", ContainerStatus::Stopped), "stopped");
}

#[test]
fn test_container_status_equality() {
    assert_eq!(ContainerStatus::Creating, ContainerStatus::Creating);
    assert_eq!(ContainerStatus::Created, ContainerStatus::Created);
    assert_eq!(ContainerStatus::Running, ContainerStatus::Running);
    assert_eq!(ContainerStatus::Stopped, ContainerStatus::Stopped);

    assert_ne!(ContainerStatus::Creating, ContainerStatus::Created);
    assert_ne!(ContainerStatus::Running, ContainerStatus::Stopped);
}

#[test]
fn test_container_status_clone() {
    let status = ContainerStatus::Running;
    let cloned = status.clone();
    assert_eq!(status, cloned);
}

#[test]
fn test_container_status_copy() {
    let status = ContainerStatus::Running;
    let copied: ContainerStatus = status; // Copy, not move
    assert_eq!(status, copied);
}

#[test]
fn test_container_status_serialization() {
    // JSON serialization should produce lowercase strings
    let json = serde_json::to_string(&ContainerStatus::Running).unwrap();
    assert_eq!(json, "\"running\"");

    let json = serde_json::to_string(&ContainerStatus::Stopped).unwrap();
    assert_eq!(json, "\"stopped\"");
}

#[test]
fn test_container_status_deserialization() {
    let status: ContainerStatus = serde_json::from_str("\"created\"").unwrap();
    assert_eq!(status, ContainerStatus::Created);

    let status: ContainerStatus = serde_json::from_str("\"running\"").unwrap();
    assert_eq!(status, ContainerStatus::Running);
}

// =============================================================================
// ContainerState Tests
// =============================================================================

#[test]
fn test_container_state_minimal() {
    let state = ContainerState {
        oci_version: "1.0.2".to_string(),
        id: "test-container".to_string(),
        status: ContainerStatus::Created,
        pid: None,
        bundle: "/tmp/bundle".to_string(),
        annotations: std::collections::HashMap::new(),
    };

    assert_eq!(state.oci_version, "1.0.2");
    assert_eq!(state.id, "test-container");
    assert_eq!(state.status, ContainerStatus::Created);
    assert!(state.pid.is_none());
}

#[test]
fn test_container_state_with_pid() {
    let state = ContainerState {
        oci_version: "1.0.2".to_string(),
        id: "running-container".to_string(),
        status: ContainerStatus::Running,
        pid: Some(12345),
        bundle: "/var/run/containers/running-container".to_string(),
        annotations: std::collections::HashMap::new(),
    };

    assert_eq!(state.pid, Some(12345));
    assert_eq!(state.status, ContainerStatus::Running);
}

#[test]
fn test_container_state_with_annotations() {
    let mut annotations = std::collections::HashMap::new();
    annotations.insert("org.example.key".to_string(), "value".to_string());
    annotations.insert("another.key".to_string(), "another value".to_string());

    let state = ContainerState {
        oci_version: "1.0.2".to_string(),
        id: "annotated-container".to_string(),
        status: ContainerStatus::Created,
        pid: None,
        bundle: "/tmp/bundle".to_string(),
        annotations,
    };

    assert_eq!(state.annotations.len(), 2);
    assert_eq!(
        state.annotations.get("org.example.key"),
        Some(&"value".to_string())
    );
}

#[test]
fn test_container_state_clone() {
    let state = ContainerState {
        oci_version: "1.0.2".to_string(),
        id: "test".to_string(),
        status: ContainerStatus::Running,
        pid: Some(100),
        bundle: "/bundle".to_string(),
        annotations: std::collections::HashMap::new(),
    };

    let cloned = state.clone();
    assert_eq!(state.id, cloned.id);
    assert_eq!(state.status, cloned.status);
    assert_eq!(state.pid, cloned.pid);
}

#[test]
fn test_container_state_serialization() {
    let state = ContainerState {
        oci_version: "1.0.2".to_string(),
        id: "test-container".to_string(),
        status: ContainerStatus::Running,
        pid: Some(1234),
        bundle: "/tmp/bundle".to_string(),
        annotations: std::collections::HashMap::new(),
    };

    let json = serde_json::to_string(&state).unwrap();

    // OCI spec uses camelCase
    assert!(json.contains("\"ociVersion\"") || json.contains("\"oci_version\""));
    assert!(json.contains("\"1.0.2\""));
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"test-container\""));
    assert!(json.contains("\"status\""));
    assert!(json.contains("\"running\""));
    assert!(json.contains("\"pid\""));
    assert!(json.contains("1234"));
}

#[test]
fn test_container_state_deserialization() {
    // Use camelCase field names per OCI spec
    let json = r#"{
        "ociVersion": "1.0.2",
        "id": "test-container",
        "status": "created",
        "pid": null,
        "bundle": "/tmp/bundle",
        "annotations": {}
    }"#;

    let state: ContainerState = serde_json::from_str(json).unwrap();

    assert_eq!(state.oci_version, "1.0.2");
    assert_eq!(state.id, "test-container");
    assert_eq!(state.status, ContainerStatus::Created);
    assert!(state.pid.is_none());
}

// =============================================================================
// Signal Tests
// =============================================================================

#[test]
fn test_signal_display() {
    assert_eq!(format!("{}", Signal::Term), "SIGTERM");
    assert_eq!(format!("{}", Signal::Kill), "SIGKILL");
    assert_eq!(format!("{}", Signal::Hup), "SIGHUP");
    assert_eq!(format!("{}", Signal::Int), "SIGINT");
    assert_eq!(format!("{}", Signal::Usr1), "SIGUSR1");
    assert_eq!(format!("{}", Signal::Usr2), "SIGUSR2");
}

#[test]
fn test_signal_clone() {
    let signal = Signal::Term;
    let cloned = signal.clone();
    assert_eq!(format!("{}", signal), format!("{}", cloned));
}

#[test]
fn test_signal_copy() {
    let signal = Signal::Kill;
    let copied: Signal = signal; // Copy, not move
    assert_eq!(format!("{}", signal), format!("{}", copied));
}

#[test]
fn test_signal_debug() {
    let signal = Signal::Term;
    let debug = format!("{:?}", signal);
    assert!(debug.contains("Term"));
}

// =============================================================================
// State Machine Validation Tests
// =============================================================================
//
// These tests document the expected state transitions but don't require
// a running runtime to verify.
// =============================================================================

#[test]
fn test_valid_state_transitions_documented() {
    // Document valid transitions as assertions on status values

    // create() -> Creating (transient) -> Created
    let after_create = ContainerStatus::Created;
    assert_eq!(format!("{}", after_create), "created");

    // start() -> Running
    let after_start = ContainerStatus::Running;
    assert_eq!(format!("{}", after_start), "running");

    // kill() or natural exit -> Stopped
    let after_kill = ContainerStatus::Stopped;
    assert_eq!(format!("{}", after_kill), "stopped");
}

#[test]
fn test_all_statuses_covered() {
    // Ensure we have exactly 4 status variants
    let statuses = [
        ContainerStatus::Creating,
        ContainerStatus::Created,
        ContainerStatus::Running,
        ContainerStatus::Stopped,
    ];

    // Each serializes to a unique string
    let mut seen = std::collections::HashSet::new();
    for status in &statuses {
        let s = format!("{}", status);
        assert!(seen.insert(s), "duplicate status string");
    }

    assert_eq!(seen.len(), 4, "should have exactly 4 unique statuses");
}

#[test]
fn test_all_signals_covered() {
    // Ensure common POSIX signals are available
    let signals = [
        Signal::Term, // Graceful termination
        Signal::Kill, // Immediate termination
        Signal::Hup,  // Reload configuration
        Signal::Int,  // Interrupt (Ctrl+C)
        Signal::Usr1, // Application-defined
        Signal::Usr2, // Application-defined
    ];

    // Each has a unique display
    let mut seen = std::collections::HashSet::new();
    for signal in &signals {
        let s = format!("{}", signal);
        assert!(seen.insert(s), "duplicate signal string");
    }

    assert_eq!(seen.len(), 6, "should have exactly 6 unique signals");
}
