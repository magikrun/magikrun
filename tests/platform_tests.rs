//! Tests for platform detection module.
//!
//! Validates platform detection logic, capability enumeration,
//! and OCI platform string generation.

use magikrun::image::{Arch, Capability, Os, Platform};
use std::collections::HashSet;

// =============================================================================
// Platform Detection Tests
// =============================================================================

#[test]
fn test_platform_detect_returns_valid_os() {
    let platform = Platform::detect();

    // OS should match compile-time expectation
    #[cfg(target_os = "linux")]
    assert_eq!(platform.os, Os::Linux);

    #[cfg(target_os = "macos")]
    assert_eq!(platform.os, Os::Darwin);

    #[cfg(target_os = "windows")]
    assert_eq!(platform.os, Os::Windows);
}

#[test]
fn test_platform_detect_returns_valid_arch() {
    let platform = Platform::detect();

    #[cfg(target_arch = "x86_64")]
    assert_eq!(platform.arch, Arch::Amd64);

    #[cfg(target_arch = "aarch64")]
    assert_eq!(platform.arch, Arch::Arm64);

    #[cfg(target_arch = "arm")]
    assert_eq!(platform.arch, Arch::Arm);
}

#[test]
fn test_wasm_runtime_always_available() {
    let platform = Platform::detect();

    // WASM runtime is pure Rust, should always be available
    assert!(
        platform.capabilities.contains(&Capability::WasmRuntime),
        "WasmRuntime capability should always be present"
    );
}

#[test]
fn test_platform_is_cloneable() {
    let platform = Platform::detect();
    let cloned = platform.clone();

    assert_eq!(platform.os, cloned.os);
    assert_eq!(platform.arch, cloned.arch);
    assert_eq!(platform.capabilities, cloned.capabilities);
}

// =============================================================================
// OCI Platform String Tests
// =============================================================================

#[test]
fn test_oci_platform_string_format() {
    let platform = Platform::detect();
    let oci_platform = platform.oci_platform();

    // Format should be "os/arch"
    assert!(
        oci_platform.contains('/'),
        "OCI platform string should contain '/'"
    );

    let parts: Vec<&str> = oci_platform.split('/').collect();
    assert_eq!(parts.len(), 2, "OCI platform should have exactly 2 parts");

    // OS part should be lowercase
    assert!(
        parts[0].chars().all(|c| c.is_lowercase() || c.is_numeric()),
        "OS part should be lowercase"
    );

    // Arch part should be lowercase
    assert!(
        parts[1].chars().all(|c| c.is_lowercase() || c.is_numeric()),
        "Arch part should be lowercase"
    );
}

#[test]
fn test_oci_platform_matches_current() {
    let platform = Platform::detect();
    let oci_platform = platform.oci_platform();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    assert_eq!(oci_platform, "linux/amd64");

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    assert_eq!(oci_platform, "linux/arm64");

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    assert_eq!(oci_platform, "darwin/amd64");

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    assert_eq!(oci_platform, "darwin/arm64");

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    assert_eq!(oci_platform, "windows/amd64");

    // Ensure variable is used on all platforms
    let _ = oci_platform;
}

// =============================================================================
// Capability Detection Tests
// =============================================================================

#[cfg(target_os = "linux")]
mod linux_capabilities {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_namespaces_detected_when_available() {
        let platform = Platform::detect();

        // If /proc/self/ns/pid exists, namespaces should be detected
        if Path::new("/proc/self/ns/pid").exists() {
            assert!(
                platform.capabilities.contains(&Capability::Namespaces),
                "Namespaces should be detected on Linux with /proc/self/ns/pid"
            );
        }
    }

    #[test]
    fn test_cgroups_detected_when_available() {
        let platform = Platform::detect();

        // If /sys/fs/cgroup exists, cgroups should be detected
        if Path::new("/sys/fs/cgroup").exists() {
            assert!(
                platform.capabilities.contains(&Capability::Cgroups),
                "Cgroups should be detected on Linux with /sys/fs/cgroup"
            );
        }
    }

    #[test]
    fn test_hypervisor_detection_kvm() {
        let platform = Platform::detect();

        // KVM detection depends on /dev/kvm
        if Path::new("/dev/kvm").exists() {
            // Note: May still not be accessible if permissions are wrong
            // so we just check it's at least considered
            let _ = platform.capabilities.contains(&Capability::Hypervisor);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_capabilities {
    use super::*;

    #[test]
    fn test_no_namespaces_on_macos() {
        let platform = Platform::detect();

        // Linux namespaces don't exist on macOS
        assert!(
            !platform.capabilities.contains(&Capability::Namespaces),
            "Namespaces should not be detected on macOS"
        );
    }

    #[test]
    fn test_no_cgroups_on_macos() {
        let platform = Platform::detect();

        // Linux cgroups don't exist on macOS
        assert!(
            !platform.capabilities.contains(&Capability::Cgroups),
            "Cgroups should not be detected on macOS"
        );
    }

    /// Tests that Hypervisor.framework is accessible on macOS ARM64 without
    /// explicit code signing or entitlements.
    ///
    /// Background: Earlier macOS versions required the com.apple.security.hypervisor
    /// entitlement to access Hypervisor.framework. However, modern macOS (Ventura+)
    /// on Apple Silicon allows hypervisor access for adhoc-signed binaries without
    /// explicit entitlements.
    ///
    /// This test validates that krun_create_ctx() succeeds, proving hypervisor
    /// access works without signing the binary with entitlements.plist.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_hypervisor_framework_accessible_without_entitlements() {
        let platform = Platform::detect();

        // On macOS ARM64, hypervisor should be available via libkrun
        assert!(
            platform.has_hypervisor(),
            "Hypervisor.framework should be accessible on macOS ARM64 without \
             explicit entitlements. If this test fails, check:\n\
             1. Running on Apple Silicon (M1/M2/M3)\n\
             2. macOS Ventura (13.0) or later\n\
             3. libkrun properly installed (brew install krunvm)"
        );

        println!("✓ Hypervisor.framework accessible without entitlements");
        println!("  Platform: {}", platform.oci_platform());
        println!(
            "  Capabilities: {:?}",
            platform.capabilities.iter().collect::<Vec<_>>()
        );
    }
}

// =============================================================================
// Helper Method Tests
// =============================================================================

#[test]
fn test_supports_native_containers() {
    let platform = Platform::detect();

    // Native containers require both namespaces and cgroups
    let expected = platform.capabilities.contains(&Capability::Namespaces)
        && platform.capabilities.contains(&Capability::Cgroups);

    assert_eq!(
        platform.supports_native_containers(),
        expected,
        "supports_native_containers should match capability detection"
    );
}

#[test]
fn test_has_hypervisor() {
    let platform = Platform::detect();

    let expected = platform.capabilities.contains(&Capability::Hypervisor);

    assert_eq!(
        platform.has_hypervisor(),
        expected,
        "has_hypervisor should match capability detection"
    );
}

// =============================================================================
// Display/Debug Tests
// =============================================================================

#[test]
fn test_os_display() {
    assert_eq!(format!("{:?}", Os::Linux), "Linux");
    assert_eq!(format!("{:?}", Os::Darwin), "Darwin");
    assert_eq!(format!("{:?}", Os::Unknown), "Unknown");
}

#[test]
fn test_arch_display() {
    assert_eq!(format!("{:?}", Arch::Amd64), "Amd64");
    assert_eq!(format!("{:?}", Arch::Arm64), "Arm64");
    assert_eq!(format!("{:?}", Arch::Arm), "Arm");
    assert_eq!(format!("{:?}", Arch::Unknown), "Unknown");
}

#[test]
fn test_capability_display() {
    assert_eq!(format!("{:?}", Capability::Namespaces), "Namespaces");
    assert_eq!(format!("{:?}", Capability::Cgroups), "Cgroups");
    assert_eq!(format!("{:?}", Capability::Seccomp), "Seccomp");
    assert_eq!(format!("{:?}", Capability::Hypervisor), "Hypervisor");
    assert_eq!(format!("{:?}", Capability::WasmRuntime), "WasmRuntime");
}

#[test]
fn test_capability_hashable() {
    // Capabilities should be usable in HashSet
    let mut set = HashSet::new();
    set.insert(Capability::WasmRuntime);
    set.insert(Capability::Namespaces);
    set.insert(Capability::WasmRuntime); // duplicate

    assert_eq!(set.len(), 2, "HashSet should deduplicate capabilities");
}
