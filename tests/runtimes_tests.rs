//! Tests for runtime registry and individual runtime backends.
//!
//! Tests the RuntimeRegistry and availability checks for
//! YoukiRuntime, WasmtimeRuntime, and KrunRuntime.

use magikrun::runtimes::{KrunRuntime, RuntimeRegistry, WasmtimeRuntime, YoukiRuntime};
use magikrun::{OciRuntime, Platform};

// =============================================================================
// RuntimeRegistry Tests
// =============================================================================

#[test]
fn test_registry_creation() {
    let platform = Platform::detect();
    let registry = RuntimeRegistry::new(&platform).unwrap();

    // Registry should be created successfully
    assert!(!registry.all().is_empty());
}

#[test]
fn test_registry_get_by_name() {
    let platform = Platform::detect();
    let registry = RuntimeRegistry::new(&platform).unwrap();

    // Wasmtime should always be gettable
    let wasmtime = registry.get("wasmtime");
    assert!(wasmtime.is_some(), "wasmtime should be registered");
}

#[test]
fn test_registry_wasmtime_always_available() {
    let platform = Platform::detect();
    let registry = RuntimeRegistry::new(&platform).unwrap();

    // Wasmtime is pure Rust, should always be available
    let wasmtime = registry.get("wasmtime");
    assert!(wasmtime.is_some(), "wasmtime should be registered");

    if let Some(rt) = wasmtime {
        assert!(rt.is_available(), "wasmtime should be available");
    }
}

#[test]
fn test_registry_available_runtimes_includes_wasmtime() {
    let platform = Platform::detect();
    let registry = RuntimeRegistry::new(&platform).unwrap();
    let available = registry.available();

    assert!(
        available.iter().any(|r| r.name() == "wasmtime"),
        "available runtimes should include wasmtime"
    );
}

// =============================================================================
// YoukiRuntime Tests
// =============================================================================

#[test]
fn test_youki_runtime_creation() {
    let runtime = YoukiRuntime::new();
    assert_eq!(runtime.name(), "youki");
}

#[test]
fn test_youki_runtime_with_custom_state_root() {
    use std::path::PathBuf;

    let runtime = YoukiRuntime::with_state_root(PathBuf::from("/tmp/custom-youki"));
    assert_eq!(runtime.name(), "youki");
}

#[test]
#[cfg(not(target_os = "linux"))]
fn test_youki_unavailable_on_non_linux() {
    let runtime = YoukiRuntime::new();

    assert!(
        !runtime.is_available(),
        "youki should not be available on non-Linux"
    );
    assert!(runtime.unavailable_reason().is_some());
    assert!(
        runtime.unavailable_reason().unwrap().contains("Linux"),
        "reason should mention Linux"
    );
}

#[cfg(target_os = "linux")]
mod youki_linux_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_youki_checks_namespaces() {
        let runtime = YoukiRuntime::new();

        // If namespaces exist, youki should be available (assuming we have permissions)
        if Path::new("/proc/self/ns/pid").exists() {
            // May or may not be available depending on permissions
            let _ = runtime.is_available();
        }
    }
}

// =============================================================================
// WasmtimeRuntime Tests
// =============================================================================

#[test]
fn test_wasmtime_runtime_creation() {
    let runtime = WasmtimeRuntime::new();
    assert_eq!(runtime.name(), "wasmtime");
}

#[test]
fn test_wasmtime_always_available() {
    let runtime = WasmtimeRuntime::new();

    assert!(
        runtime.is_available(),
        "wasmtime should always be available"
    );
    assert!(runtime.unavailable_reason().is_none());
}

#[test]
fn test_wasmtime_default() {
    let runtime = WasmtimeRuntime::default();
    assert_eq!(runtime.name(), "wasmtime");
    assert!(runtime.is_available());
}

// =============================================================================
// KrunRuntime Tests
// =============================================================================

#[test]
fn test_krun_runtime_creation() {
    let runtime = KrunRuntime::new();
    assert_eq!(runtime.name(), "krun");
}

#[test]
fn test_krun_default() {
    let runtime = KrunRuntime::default();
    assert_eq!(runtime.name(), "krun");
}

#[cfg(target_os = "linux")]
mod krun_linux_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_krun_checks_kvm() {
        let runtime = KrunRuntime::new();

        // If /dev/kvm exists, krun might be available
        if Path::new("/dev/kvm").exists() {
            // May or may not be available depending on permissions
            let _ = runtime.is_available();
        } else {
            assert!(!runtime.is_available());
        }
    }
}

#[cfg(target_os = "macos")]
mod krun_macos_tests {
    use super::*;

    #[test]
    fn test_krun_checks_hypervisor_framework() {
        let runtime = KrunRuntime::new();

        // On macOS, krun uses Hypervisor.framework
        // Availability depends on hardware and entitlements
        let _ = runtime.is_available();
    }
}

// =============================================================================
// OciRuntime Trait Tests
// =============================================================================

#[test]
fn test_runtime_trait_object_safe() {
    // Should be able to use runtimes as trait objects
    fn accept_runtime(_runtime: &dyn OciRuntime) {}

    let wasmtime = WasmtimeRuntime::new();
    accept_runtime(&wasmtime);

    let youki = YoukiRuntime::new();
    accept_runtime(&youki);

    let krun = KrunRuntime::new();
    accept_runtime(&krun);
}

#[test]
fn test_runtime_in_box() {
    // Should be able to box runtimes
    let runtime: Box<dyn OciRuntime> = Box::new(WasmtimeRuntime::new());
    assert_eq!(runtime.name(), "wasmtime");
}

#[test]
fn test_runtime_in_vec() {
    // Should be able to collect runtimes in a Vec
    let runtimes: Vec<Box<dyn OciRuntime>> = vec![
        Box::new(WasmtimeRuntime::new()),
        Box::new(YoukiRuntime::new()),
        Box::new(KrunRuntime::new()),
    ];

    assert_eq!(runtimes.len(), 3);

    let names: Vec<&str> = runtimes.iter().map(|r| r.name()).collect();
    assert!(names.contains(&"wasmtime"));
    assert!(names.contains(&"youki"));
    assert!(names.contains(&"krun"));
}

// =============================================================================
// Async Operation Availability Tests
// =============================================================================

#[tokio::test]
#[cfg(not(target_os = "linux"))]
async fn test_unavailable_runtime_operations_fail() {
    use std::path::Path;

    let youki = YoukiRuntime::new();

    // All operations should fail on non-Linux
    let result = youki.create("test", Path::new("/tmp/bundle")).await;
    assert!(result.is_err());

    let result = youki.start("test").await;
    assert!(result.is_err());

    let result = youki.state("test").await;
    assert!(result.is_err());

    let result = youki.kill("test", magikrun::Signal::Term, false).await;
    assert!(result.is_err());

    let result = youki.delete("test", false).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_wasmtime_create_with_invalid_bundle() {
    let runtime = WasmtimeRuntime::new();

    // Create with nonexistent bundle should fail
    let result = runtime
        .create("test", std::path::Path::new("/nonexistent/bundle"))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_wasmtime_state_nonexistent_container() {
    let runtime = WasmtimeRuntime::new();

    // State on nonexistent container should fail
    let result = runtime.state("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_wasmtime_start_nonexistent_container() {
    let runtime = WasmtimeRuntime::new();

    // Start on nonexistent container should fail
    let result = runtime.start("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_wasmtime_kill_nonexistent_container() {
    let runtime = WasmtimeRuntime::new();

    // Kill on nonexistent container should fail
    let result = runtime
        .kill("nonexistent", magikrun::Signal::Term, false)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_wasmtime_delete_nonexistent_container() {
    let runtime = WasmtimeRuntime::new();

    // Delete on nonexistent container should fail
    let result = runtime.delete("nonexistent", false).await;
    assert!(result.is_err());
}
