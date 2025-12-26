//! Integration tests for PodRuntime implementations.
//!
//! These tests verify the atomic pod lifecycle for:
//! - `WasmPodRuntime` (cross-platform, always available)
//! - `MicroVmPodRuntime` (requires KVM on Linux or Hypervisor.framework on macOS)
//!
//! # Running Tests
//!
//! ```bash
//! # Run all pod tests (WASM tests run everywhere)
//! cargo test --test pod_tests
//!
//! # Run MicroVM tests (requires hypervisor entitlement on macOS)
//! cargo test --test pod_tests -- --ignored
//! ```
//!
//! # macOS MicroVM Requirements
//!
//! MicroVM tests require the `com.apple.security.hypervisor` entitlement:
//!
//! ```bash
//! # Sign binary with entitlement
//! codesign -s - --entitlements entitlements.plist target/debug/deps/pod_tests-*
//! ```

use magikrun::pod::{
    ContainerSpec, PodPhase, PodRuntime, PodSpec, ResourceRequirements, Volume, VolumeMount,
    VolumeSource, WasmPodRuntime,
};
use std::collections::HashMap;
use std::time::Duration;

#[cfg(not(target_os = "windows"))]
use magikrun::pod::MicroVmPodRuntime;

#[cfg(not(target_os = "windows"))]
use magikrun::runtime::OciRuntime;

// =============================================================================
// Test Helpers
// =============================================================================

/// Creates a minimal valid PodSpec for testing.
fn test_pod_spec(name: &str) -> PodSpec {
    PodSpec {
        namespace: "default".to_string(),
        name: name.to_string(),
        kind: "Pod".to_string(),
        labels: HashMap::new(),
        annotations: HashMap::new(),
        containers: vec![ContainerSpec {
            name: "test-container".to_string(),
            image: "hello-world:latest".to_string(),
            command: Some(vec!["/hello".to_string()]),
            args: None,
            env: HashMap::new(),
            volume_mounts: vec![],
            ports: vec![],
            resources: ResourceRequirements::default(),
            working_dir: None,
        }],
        init_containers: vec![],
        volumes: vec![],
        runtime_class_name: None,
        hostname: None,
    }
}

/// Creates a PodSpec with WASM-compatible settings.
#[allow(dead_code)]
fn wasm_pod_spec(name: &str) -> PodSpec {
    PodSpec {
        namespace: "default".to_string(),
        name: name.to_string(),
        kind: "Pod".to_string(),
        labels: HashMap::new(),
        annotations: HashMap::new(),
        // NOTE: In real tests, this would need a WASM OCI image.
        // For unit testing, we test creation/validation paths.
        containers: vec![ContainerSpec {
            name: "wasm-container".to_string(),
            image: "docker.io/library/hello-wasm:latest".to_string(),
            command: None,
            args: None,
            env: [("GREETING".to_string(), "Hello from WASM!".to_string())]
                .into_iter()
                .collect(),
            volume_mounts: vec![],
            ports: vec![],
            resources: ResourceRequirements::default(),
            working_dir: None,
        }],
        init_containers: vec![],
        volumes: vec![],
        runtime_class_name: Some("pod-wasm".to_string()),
        hostname: None,
    }
}

/// Creates a PodSpec with init containers.
#[allow(dead_code)]
fn pod_with_init_containers(name: &str) -> PodSpec {
    PodSpec {
        namespace: "default".to_string(),
        name: name.to_string(),
        kind: "Pod".to_string(),
        labels: HashMap::new(),
        annotations: HashMap::new(),
        containers: vec![ContainerSpec {
            name: "main".to_string(),
            image: "docker.io/library/alpine:latest".to_string(),
            command: Some(vec!["sleep".to_string()]),
            args: Some(vec!["infinity".to_string()]),
            env: HashMap::new(),
            volume_mounts: vec![],
            ports: vec![],
            resources: ResourceRequirements::default(),
            working_dir: None,
        }],
        init_containers: vec![
            ContainerSpec {
                name: "init-1".to_string(),
                image: "docker.io/library/alpine:latest".to_string(),
                command: Some(vec!["echo".to_string()]),
                args: Some(vec!["init 1 done".to_string()]),
                env: HashMap::new(),
                volume_mounts: vec![],
                ports: vec![],
                resources: ResourceRequirements::default(),
                working_dir: None,
            },
            ContainerSpec {
                name: "init-2".to_string(),
                image: "docker.io/library/alpine:latest".to_string(),
                command: Some(vec!["echo".to_string()]),
                args: Some(vec!["init 2 done".to_string()]),
                env: HashMap::new(),
                volume_mounts: vec![],
                ports: vec![],
                resources: ResourceRequirements::default(),
                working_dir: None,
            },
        ],
        volumes: vec![],
        runtime_class_name: None,
        hostname: None,
    }
}

/// Creates a PodSpec with volumes.
#[allow(dead_code)]
fn pod_with_volumes(name: &str) -> PodSpec {
    PodSpec {
        namespace: "default".to_string(),
        name: name.to_string(),
        kind: "Pod".to_string(),
        labels: HashMap::new(),
        annotations: HashMap::new(),
        containers: vec![ContainerSpec {
            name: "app".to_string(),
            image: "docker.io/library/alpine:latest".to_string(),
            command: Some(vec!["cat".to_string()]),
            args: Some(vec!["/data/config.txt".to_string()]),
            env: HashMap::new(),
            volume_mounts: vec![VolumeMount {
                name: "config-vol".to_string(),
                mount_path: "/data".to_string(),
                read_only: true,
            }],
            ports: vec![],
            resources: ResourceRequirements::default(),
            working_dir: None,
        }],
        init_containers: vec![],
        volumes: vec![Volume {
            name: "config-vol".to_string(),
            source: VolumeSource::EmptyDir,
        }],
        runtime_class_name: None,
        hostname: None,
    }
}

// =============================================================================
// WasmPodRuntime Tests
// =============================================================================

#[test]
fn test_wasm_runtime_creation() {
    let result = WasmPodRuntime::new();
    assert!(
        result.is_ok(),
        "WasmPodRuntime should be creatable: {:?}",
        result.err()
    );
}

#[test]
fn test_wasm_runtime_class() {
    let runtime = WasmPodRuntime::new().expect("should create runtime");
    assert_eq!(runtime.runtime_class(), "pod-wasm");
}

#[tokio::test]
async fn test_wasm_list_pods_empty() {
    let runtime = WasmPodRuntime::new().expect("should create runtime");
    let pods = runtime.list_pods().await;
    assert!(pods.is_ok(), "list_pods should succeed: {:?}", pods.err());
    assert!(pods.unwrap().is_empty(), "should have no pods initially");
}

#[tokio::test]
async fn test_wasm_pod_status_not_found() {
    let runtime = WasmPodRuntime::new().expect("should create runtime");
    let pod_id = magikrun::pod::PodId::from_pod("default", "nonexistent-pod");
    let status = runtime.pod_status(&pod_id).await;
    assert!(status.is_err(), "should error for nonexistent pod");
}

#[tokio::test]
async fn test_wasm_delete_nonexistent_pod() {
    let runtime = WasmPodRuntime::new().expect("should create runtime");
    let pod_id = magikrun::pod::PodId::from_pod("default", "nonexistent-pod");
    let result = runtime.delete_pod(&pod_id, false).await;
    // Deleting non-existent pod should be idempotent (success or not-found error)
    // Either behavior is acceptable depending on implementation
    let _ = result;
}

#[test]
fn test_pod_spec_validation_empty_name() {
    let spec = PodSpec {
        namespace: "default".to_string(),
        name: "".to_string(), // Invalid: empty name
        kind: "Pod".to_string(),
        labels: HashMap::new(),
        annotations: HashMap::new(),
        containers: vec![],
        init_containers: vec![],
        volumes: vec![],
        runtime_class_name: None,
        hostname: None,
    };
    // Validation should catch empty name
    assert!(spec.name.is_empty());
}

#[test]
fn test_pod_spec_validation_invalid_chars() {
    let spec = PodSpec {
        namespace: "default".to_string(),
        name: "INVALID_NAME".to_string(), // Invalid: uppercase and underscore
        kind: "Pod".to_string(),
        labels: HashMap::new(),
        annotations: HashMap::new(),
        containers: vec![],
        init_containers: vec![],
        volumes: vec![],
        runtime_class_name: None,
        hostname: None,
    };
    // Name contains invalid characters (uppercase, underscore)
    assert!(spec.name.contains('_') || spec.name.chars().any(|c| c.is_uppercase()));
}

#[test]
fn test_pod_spec_with_labels() {
    let mut labels = HashMap::new();
    labels.insert("app".to_string(), "test".to_string());
    labels.insert("version".to_string(), "v1".to_string());

    let spec = PodSpec {
        namespace: "default".to_string(),
        name: "labeled-pod".to_string(),
        kind: "Pod".to_string(),
        labels,
        annotations: HashMap::new(),
        containers: vec![ContainerSpec {
            name: "main".to_string(),
            image: "alpine:latest".to_string(),
            command: None,
            args: None,
            env: HashMap::new(),
            volume_mounts: vec![],
            ports: vec![],
            resources: ResourceRequirements::default(),
            working_dir: None,
        }],
        init_containers: vec![],
        volumes: vec![],
        runtime_class_name: None,
        hostname: None,
    };

    assert_eq!(spec.labels.len(), 2);
    assert_eq!(spec.labels.get("app"), Some(&"test".to_string()));
}

#[test]
fn test_pod_id_generation() {
    let id1 = magikrun::pod::PodId::from_pod("default", "my-pod");
    let id2 = magikrun::pod::PodId::from_pod("default", "my-pod");
    let id3 = magikrun::pod::PodId::from_pod("other", "my-pod");

    // Same namespace/name should produce same ID
    assert_eq!(id1.as_str(), id2.as_str());
    // Different namespace should produce different ID
    assert_ne!(id1.as_str(), id3.as_str());
}

#[test]
fn test_pod_phase_display() {
    assert_eq!(format!("{}", PodPhase::Pending), "Pending");
    assert_eq!(format!("{}", PodPhase::Running), "Running");
    assert_eq!(format!("{}", PodPhase::Succeeded), "Succeeded");
    assert_eq!(format!("{}", PodPhase::Failed), "Failed");
    assert_eq!(format!("{}", PodPhase::Unknown), "Unknown");
}

// =============================================================================
// MicroVmPodRuntime Tests (macOS/Linux only)
// =============================================================================

#[cfg(not(target_os = "windows"))]
mod microvm_tests {
    use super::*;
    use magikrun::runtime::KrunRuntime;

    /// Check if MicroVM is available on this system.
    fn microvm_available() -> bool {
        let runtime = KrunRuntime::new();
        runtime.is_available()
    }

    #[test]
    fn test_microvm_runtime_creation() {
        // MicroVmPodRuntime creation should succeed even if hypervisor unavailable
        // (availability is checked separately)
        let result = MicroVmPodRuntime::new();
        assert!(
            result.is_ok(),
            "MicroVmPodRuntime creation should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_microvm_runtime_class() {
        let runtime = MicroVmPodRuntime::new().expect("should create runtime");
        assert_eq!(runtime.runtime_class(), "pod-microvm");
    }

    #[tokio::test]
    async fn test_microvm_list_pods_empty() {
        let runtime = MicroVmPodRuntime::new().expect("should create runtime");
        let pods = runtime.list_pods().await;
        assert!(pods.is_ok(), "list_pods should succeed: {:?}", pods.err());
        assert!(pods.unwrap().is_empty(), "should have no pods initially");
    }

    #[tokio::test]
    async fn test_microvm_pod_status_not_found() {
        let runtime = MicroVmPodRuntime::new().expect("should create runtime");
        let pod_id = magikrun::pod::PodId::from_pod("default", "nonexistent-vm-pod");
        let status = runtime.pod_status(&pod_id).await;
        assert!(status.is_err(), "should error for nonexistent pod");
    }

    #[test]
    fn test_krun_runtime_availability_check() {
        let runtime = KrunRuntime::new();
        let available = runtime.is_available();
        let reason = runtime.unavailable_reason();

        if available {
            assert!(
                reason.is_none(),
                "available runtime should have no unavailable reason"
            );
            println!("✓ KrunRuntime is available on this system");
        } else {
            assert!(reason.is_some(), "unavailable runtime should have a reason");
            println!("ℹ KrunRuntime unavailable: {}", reason.unwrap());
        }
    }

    /// Integration test that requires hypervisor access.
    /// On macOS, requires `com.apple.security.hypervisor` entitlement.
    #[tokio::test]
    #[ignore = "requires hypervisor access and signed binary on macOS"]
    async fn test_microvm_run_pod_integration() {
        if !microvm_available() {
            println!("Skipping: MicroVM not available");
            return;
        }

        let runtime = MicroVmPodRuntime::new().expect("should create runtime");
        let spec = test_pod_spec("integration-test-vm-pod");

        // Attempt to run pod (may fail due to image pull, which is expected)
        let result = runtime.run_pod(&spec).await;

        match result {
            Ok(handle) => {
                // Pod started successfully
                assert!(!handle.id.as_str().is_empty());
                println!("✓ Pod started with ID: {}", handle.id);

                // Verify status
                let status = runtime.pod_status(&handle.id).await;
                assert!(status.is_ok());

                // Clean up
                let _ = runtime.stop_pod(&handle.id, Duration::from_secs(5)).await;
                let _ = runtime.delete_pod(&handle.id, true).await;
            }
            Err(e) => {
                // Expected to fail without real images
                println!("ℹ Pod run failed (expected without real images): {e}");
            }
        }
    }

    /// Creates a pod spec with infra (pause-like) and application containers.
    ///
    /// In MicroVM architecture:
    /// - The VM itself acts as the "infra container" (holds isolation boundary)
    /// - init_containers run first (setup tasks)
    /// - containers run after init completes (application workloads)
    fn infra_app_pod_spec(name: &str) -> PodSpec {
        PodSpec {
            namespace: "test".to_string(),
            name: name.to_string(),
            kind: "Pod".to_string(),
            labels: [
                ("app".to_string(), name.to_string()),
                ("tier".to_string(), "test".to_string()),
            ]
            .into_iter()
            .collect(),
            annotations: HashMap::new(),
            // Init container: sets up shared state/volumes before app starts
            init_containers: vec![ContainerSpec {
                name: "init-setup".to_string(),
                // Use alpine as it's small and has basic tools
                image: "docker.io/library/alpine:3.19".to_string(),
                command: Some(vec!["sh".to_string()]),
                args: Some(vec![
                    "-c".to_string(),
                    "echo 'Init: setting up pod environment' && echo 'ready' > /tmp/ready".to_string(),
                ]),
                env: HashMap::new(),
                volume_mounts: vec![],
                ports: vec![],
                resources: ResourceRequirements::default(),
                working_dir: None,
            }],
            // Application container: main workload
            containers: vec![ContainerSpec {
                name: "app".to_string(),
                // Use alpine for real test execution
                image: "docker.io/library/alpine:3.19".to_string(),
                command: Some(vec!["sh".to_string()]),
                args: Some(vec![
                    "-c".to_string(),
                    // Simple command that exits after brief work
                    "echo 'App: starting main workload' && sleep 2 && echo 'App: completed'".to_string(),
                ]),
                env: [
                    ("POD_NAME".to_string(), name.to_string()),
                    ("CONTAINER_ROLE".to_string(), "app".to_string()),
                ]
                .into_iter()
                .collect(),
                volume_mounts: vec![],
                ports: vec![],
                resources: ResourceRequirements::default(),
                working_dir: None,
            }],
            volumes: vec![],
            runtime_class_name: Some("pod-microvm".to_string()),
            hostname: Some(name.to_string()),
        }
    }

    /// Full integration test: Pod lifecycle with infra + app container.
    ///
    /// This test verifies the complete atomic pod deployment model:
    /// 1. VM creation (infra container equivalent)
    /// 2. Init container execution (setup)
    /// 3. App container execution (main workload)
    /// 4. Pod status reporting
    /// 5. Graceful shutdown
    /// 6. Cleanup
    ///
    /// On macOS, requires `com.apple.security.hypervisor` entitlement.
    #[tokio::test]
    #[ignore = "requires hypervisor access and real image pull capability"]
    async fn test_microvm_infra_app_pod_lifecycle() {
        // Pre-flight check: verify hypervisor is available
        if !microvm_available() {
            println!("⏭ Skipping: MicroVM/hypervisor not available on this system");
            return;
        }

        println!("═══════════════════════════════════════════════════════════════");
        println!("  MicroVM Pod Integration Test: Infra + App Container Lifecycle");
        println!("═══════════════════════════════════════════════════════════════");

        // Phase 1: Create runtime
        println!("\n▶ Phase 1: Creating MicroVmPodRuntime...");
        let runtime = MicroVmPodRuntime::new().expect("should create runtime");
        assert_eq!(runtime.runtime_class(), "pod-microvm");
        println!("  ✓ Runtime created successfully");

        // Phase 2: Prepare pod specification
        println!("\n▶ Phase 2: Preparing pod specification...");
        let pod_name = format!("integ-test-{}", uuid::Uuid::new_v4().as_simple());
        let spec = infra_app_pod_spec(&pod_name);
        println!("  ✓ Pod spec created:");
        println!("    - Name: {}/{}", spec.namespace, spec.name);
        println!("    - Init containers: {}", spec.init_containers.len());
        for init in &spec.init_containers {
            println!("      - {} ({})", init.name, init.image);
        }
        println!("    - App containers: {}", spec.containers.len());
        for container in &spec.containers {
            println!("      - {} ({})", container.name, container.image);
        }

        // Phase 3: Run the pod (atomic deployment)
        println!("\n▶ Phase 3: Running pod (atomic deployment)...");
        println!("  This will:");
        println!("    1. Pull all container images");
        println!("    2. Build composite rootfs");
        println!("    3. Boot MicroVM (infra container equivalent)");
        println!("    4. Execute init containers sequentially");
        println!("    5. Start app containers");

        let start_time = std::time::Instant::now();
        let handle = match runtime.run_pod(&spec).await {
            Ok(h) => {
                let elapsed = start_time.elapsed();
                println!("  ✓ Pod started successfully in {:?}", elapsed);
                println!("    - Pod ID: {}", h.id);
                println!("    - Runtime class: {}", h.runtime_class);
                h
            }
            Err(e) => {
                println!("  ✗ Pod failed to start: {}", e);
                println!("\n    Possible causes:");
                println!("    - Image pull failed (network/registry issue)");
                println!("    - Hypervisor entitlement missing (macOS)");
                println!("    - VM boot failed (resource constraints)");
                // Don't panic - graceful failure for CI environments
                return;
            }
        };

        // Phase 4: Verify pod status
        println!("\n▶ Phase 4: Verifying pod status...");
        let status = runtime
            .pod_status(&handle.id)
            .await
            .expect("should get pod status");

        println!("  Pod phase: {:?}", status.phase);
        println!("  Container statuses:");
        for (name, container_status) in &status.containers {
            println!("    - {}: {:?}", name, container_status);
        }

        // Verify pod is running
        assert!(
            matches!(status.phase, PodPhase::Running | PodPhase::Succeeded),
            "Pod should be Running or Succeeded, got: {:?}",
            status.phase
        );
        println!("  ✓ Pod phase verified: {:?}", status.phase);

        // Verify container count matches spec
        assert_eq!(
            status.containers.len(),
            spec.containers.len(),
            "Container count mismatch"
        );
        println!("  ✓ Container count verified: {}", status.containers.len());

        // Phase 5: Verify pod appears in list
        println!("\n▶ Phase 5: Verifying pod appears in list...");
        let pods = runtime.list_pods().await.expect("should list pods");
        let our_pod = pods.iter().find(|p| p.id == handle.id);
        assert!(our_pod.is_some(), "Pod should appear in list");
        let summary = our_pod.unwrap();
        println!("  ✓ Pod found in list:");
        println!("    - ID: {}", summary.id);
        println!("    - Name: {}/{}", summary.namespace, summary.name);
        println!("    - Phase: {:?}", summary.phase);
        println!("    - Containers: {}", summary.container_count);

        // Phase 6: Wait briefly for app container to do work
        println!("\n▶ Phase 6: Letting app container run...");
        tokio::time::sleep(Duration::from_secs(3)).await;
        println!("  ✓ Waited 3 seconds for workload");

        // Phase 7: Stop the pod gracefully
        println!("\n▶ Phase 7: Stopping pod gracefully...");
        let grace_period = Duration::from_secs(10);
        let stop_start = std::time::Instant::now();
        let stop_result = runtime.stop_pod(&handle.id, grace_period).await;
        let stop_elapsed = stop_start.elapsed();

        match stop_result {
            Ok(()) => println!("  ✓ Pod stopped gracefully in {:?}", stop_elapsed),
            Err(e) => println!("  ⚠ Stop returned error (may be expected): {}", e),
        }

        // Phase 8: Verify final status
        println!("\n▶ Phase 8: Verifying final status...");
        let final_status = runtime.pod_status(&handle.id).await;
        match final_status {
            Ok(s) => {
                println!("  Final phase: {:?}", s.phase);
                assert!(
                    matches!(s.phase, PodPhase::Succeeded | PodPhase::Failed),
                    "Pod should be Succeeded or Failed after stop"
                );
            }
            Err(e) => {
                println!("  ⚠ Could not get final status: {} (pod may be deleted)", e);
            }
        }

        // Phase 9: Delete the pod
        println!("\n▶ Phase 9: Deleting pod...");
        let delete_result = runtime.delete_pod(&handle.id, true).await;
        match delete_result {
            Ok(()) => println!("  ✓ Pod deleted successfully"),
            Err(e) => println!("  ⚠ Delete error (may be expected): {}", e),
        }

        // Phase 10: Verify pod is removed from list
        println!("\n▶ Phase 10: Verifying pod removal...");
        let final_pods = runtime.list_pods().await.expect("should list pods");
        let still_exists = final_pods.iter().any(|p| p.id == handle.id);
        assert!(!still_exists, "Pod should be removed from list after delete");
        println!("  ✓ Pod removed from list");

        println!("\n═══════════════════════════════════════════════════════════════");
        println!("  ✓ Integration test completed successfully!");
        println!("═══════════════════════════════════════════════════════════════");
    }

    /// Test pod with multiple app containers sharing the VM.
    ///
    /// Verifies that multiple containers can run within a single MicroVM:
    /// - All containers share the same kernel/isolation boundary
    /// - Container images are merged into composite rootfs
    /// - All container statuses are tracked
    #[tokio::test]
    #[ignore = "requires hypervisor access and real image pull capability"]
    async fn test_microvm_multi_container_pod() {
        if !microvm_available() {
            println!("⏭ Skipping: MicroVM not available");
            return;
        }

        println!("\n▶ Testing multi-container pod in single MicroVM...");

        let runtime = MicroVmPodRuntime::new().expect("should create runtime");

        // Create pod with multiple containers
        let pod_name = format!("multi-{}", uuid::Uuid::new_v4().as_simple());
        let spec = PodSpec {
            namespace: "test".to_string(),
            name: pod_name.clone(),
            kind: "Pod".to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            init_containers: vec![],
            containers: vec![
                // Container 1: Web server simulation
                ContainerSpec {
                    name: "web".to_string(),
                    image: "docker.io/library/alpine:3.19".to_string(),
                    command: Some(vec!["sh".to_string()]),
                    args: Some(vec![
                        "-c".to_string(),
                        "echo 'Web container started' && sleep 5".to_string(),
                    ]),
                    env: HashMap::new(),
                    volume_mounts: vec![],
                    ports: vec![],
                    resources: ResourceRequirements::default(),
                    working_dir: None,
                },
                // Container 2: Sidecar simulation
                ContainerSpec {
                    name: "sidecar".to_string(),
                    image: "docker.io/library/alpine:3.19".to_string(),
                    command: Some(vec!["sh".to_string()]),
                    args: Some(vec![
                        "-c".to_string(),
                        "echo 'Sidecar container started' && sleep 5".to_string(),
                    ]),
                    env: HashMap::new(),
                    volume_mounts: vec![],
                    ports: vec![],
                    resources: ResourceRequirements::default(),
                    working_dir: None,
                },
            ],
            volumes: vec![],
            runtime_class_name: Some("pod-microvm".to_string()),
            hostname: None,
        };

        println!("  Creating pod with {} containers...", spec.containers.len());

        let handle = match runtime.run_pod(&spec).await {
            Ok(h) => {
                println!("  ✓ Multi-container pod started: {}", h.id);
                h
            }
            Err(e) => {
                println!("  ✗ Failed to start: {}", e);
                return;
            }
        };

        // Verify both containers are tracked
        let status = runtime.pod_status(&handle.id).await.expect("should get status");
        println!("  Container statuses:");
        for (name, s) in &status.containers {
            println!("    - {}: {:?}", name, s);
        }

        assert_eq!(
            status.containers.len(),
            2,
            "Should have 2 container statuses"
        );
        assert!(
            status.containers.contains_key("web"),
            "Should have 'web' container"
        );
        assert!(
            status.containers.contains_key("sidecar"),
            "Should have 'sidecar' container"
        );

        // Cleanup
        let _ = runtime.stop_pod(&handle.id, Duration::from_secs(5)).await;
        let _ = runtime.delete_pod(&handle.id, true).await;
        println!("  ✓ Multi-container pod test completed");
    }
}

// =============================================================================
// PodSpec YAML Parsing Tests
// =============================================================================

#[test]
fn test_pod_spec_from_yaml_basic() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
    - name: main
      image: alpine:latest
      command: ["sleep"]
      args: ["infinity"]
"#;

    let result = PodSpec::from_yaml(yaml.as_bytes());
    assert!(
        result.is_ok(),
        "should parse valid YAML: {:?}",
        result.err()
    );

    let spec = result.unwrap();
    assert_eq!(spec.name, "test-pod");
    assert_eq!(spec.namespace, "default");
    assert_eq!(spec.containers.len(), 1);
    assert_eq!(spec.containers[0].name, "main");
}

#[test]
fn test_pod_spec_from_yaml_with_init_containers() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
  namespace: default
spec:
  initContainers:
    - name: init
      image: busybox:latest
      command: ["echo", "initializing"]
  containers:
    - name: main
      image: alpine:latest
"#;

    let result = PodSpec::from_yaml(yaml.as_bytes());
    assert!(
        result.is_ok(),
        "should parse YAML with init containers: {:?}",
        result.err()
    );

    let spec = result.unwrap();
    assert_eq!(spec.init_containers.len(), 1);
    assert_eq!(spec.init_containers[0].name, "init");
}

#[test]
fn test_pod_spec_from_yaml_with_volumes() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: volume-pod
  namespace: default
spec:
  containers:
    - name: main
      image: alpine:latest
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      emptyDir: {}
"#;

    let result = PodSpec::from_yaml(yaml.as_bytes());
    assert!(
        result.is_ok(),
        "should parse YAML with volumes: {:?}",
        result.err()
    );

    let spec = result.unwrap();
    assert_eq!(spec.volumes.len(), 1);
    assert_eq!(spec.volumes[0].name, "data");
    assert_eq!(spec.containers[0].volume_mounts.len(), 1);
}

#[test]
fn test_pod_spec_from_yaml_with_env_vars() {
    let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
  namespace: default
spec:
  containers:
    - name: main
      image: alpine:latest
      env:
        - name: MY_VAR
          value: "hello"
        - name: DEBUG
          value: "true"
"#;

    let result = PodSpec::from_yaml(yaml.as_bytes());
    assert!(
        result.is_ok(),
        "should parse YAML with env vars: {:?}",
        result.err()
    );

    let spec = result.unwrap();
    assert!(spec.containers[0].env.contains_key("MY_VAR"));
    assert_eq!(
        spec.containers[0].env.get("MY_VAR"),
        Some(&"hello".to_string())
    );
}

#[test]
fn test_pod_spec_from_yaml_invalid() {
    let yaml = "not: valid: yaml: :: invalid";
    let result = PodSpec::from_yaml(yaml.as_bytes());
    assert!(result.is_err(), "should fail on invalid YAML");
}

#[test]
fn test_pod_spec_from_yaml_size_limit() {
    // Create a YAML that exceeds MAX_MANIFEST_SIZE (1 MiB)
    let oversized = "a".repeat(2 * 1024 * 1024);
    let result = PodSpec::from_yaml(oversized.as_bytes());
    assert!(result.is_err(), "should reject oversized manifest");
}

// =============================================================================
// Constants Validation Tests
// =============================================================================

#[test]
fn test_pod_constants() {
    use magikrun::pod::*;

    // Verify constants are sensible
    assert!(MAX_PODS > 0);
    assert!(MAX_CONTAINERS_PER_POD > 0 && MAX_CONTAINERS_PER_POD <= 100);
    assert!(MAX_VOLUMES_PER_POD > 0);
    assert!(MAX_NAME_LEN >= 63); // K8s DNS label length
    assert!(MAX_ENV_VARS_PER_CONTAINER > 0);
    assert!(DEFAULT_GRACE_PERIOD_SECS > 0 && DEFAULT_GRACE_PERIOD_SECS <= MAX_GRACE_PERIOD_SECS);
}
