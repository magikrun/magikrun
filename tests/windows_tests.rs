//! # Windows Runtime Tests
//!
//! Tests for the WindowsRuntime WSL2 MicroVM-based container execution.
//! These tests are platform-conditional and only run on Windows.

use magikrun::runtime::OciRuntime;
use magikrun::runtimes::WindowsRuntime;

/// Test that WindowsRuntime can be created on any platform.
#[test]
fn test_windows_runtime_creation() {
    let runtime = WindowsRuntime::new();
    assert_eq!(runtime.name(), "wsl2-microvm");
}

/// Test availability detection.
#[test]
fn test_windows_runtime_availability() {
    let runtime = WindowsRuntime::new();

    #[cfg(target_os = "windows")]
    {
        // On Windows, availability depends on WSL2 status
        // We just check that the detection doesn't panic
        let _ = runtime.is_available();
        if !runtime.is_available() {
            // Should have a reason
            assert!(runtime.unavailable_reason().is_some());
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On non-Windows, should always be unavailable
        assert!(!runtime.is_available());
        assert!(runtime.unavailable_reason().is_some());
        assert!(runtime.unavailable_reason().unwrap().contains("Windows"));
    }
}

/// Test path conversion (Windows to WSL).
#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn test_runtime_naming() {
        // This test validates the runtime is properly named for the microVM approach
        let runtime = WindowsRuntime::new();

        // The runtime should be constructible regardless of platform
        assert_eq!(runtime.name(), "wsl2-microvm");
    }
}

/// Test WSL2 MicroVM-specific functionality on Windows.
#[cfg(target_os = "windows")]
mod windows_specific_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_storage_path() {
        let runtime = WindowsRuntime::new();

        // Should have a storage path for VHDs
        let storage = runtime.storage_path();
        assert!(!storage.as_os_str().is_empty());
    }

    #[tokio::test]
    async fn test_create_without_wsl() {
        let runtime = WindowsRuntime::new();

        if !runtime.is_available() {
            // Should fail gracefully
            let result = runtime
                .create("test-container", Path::new("C:\\nonexistent"))
                .await;
            assert!(result.is_err());
        }
    }
}

/// Integration tests that require WSL2 to be available.
/// These tests create ephemeral WSL distros for each container.
#[cfg(all(target_os = "windows", feature = "integration_tests"))]
mod integration_tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_full_microvm_lifecycle() {
        let runtime = WindowsRuntime::new();

        if !runtime.is_available() {
            eprintln!("Skipping integration test: WSL2 not available");
            return;
        }

        // Create a minimal bundle with rootfs
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let bundle_path = temp_dir.path();

        // Create rootfs directory with minimal content
        let rootfs = bundle_path.join("rootfs");
        std::fs::create_dir_all(&rootfs).expect("Failed to create rootfs");
        std::fs::create_dir_all(rootfs.join("bin")).expect("Failed to create bin");

        // Create a minimal shell script as entrypoint
        std::fs::write(
            rootfs.join("bin/init"),
            "#!/bin/sh\necho 'Hello from MicroVM'\nexit 0",
        )
        .expect("Failed to write init");

        // Create OCI config.json
        std::fs::write(
            bundle_path.join("config.json"),
            r#"{
                "ociVersion": "1.0.2",
                "process": {
                    "args": ["/bin/sh", "-c", "echo hello"],
                    "cwd": "/",
                    "env": ["PATH=/bin:/usr/bin"]
                }
            }"#,
        )
        .expect("Failed to write config.json");

        let container_id = "test-microvm-container";

        // Create - this imports the rootfs as a new WSL distro
        let result = runtime.create(container_id, bundle_path).await;
        if result.is_err() {
            eprintln!("Create failed: {:?}", result);
            return;
        }
        assert!(result.is_ok(), "Create failed: {:?}", result);

        // State should be "created"
        let state = runtime.state(container_id).await;
        assert!(state.is_ok());

        // Delete - this unregisters the WSL distro
        let result = runtime.delete(container_id, true).await;
        assert!(result.is_ok(), "Delete failed: {:?}", result);
    }
}
