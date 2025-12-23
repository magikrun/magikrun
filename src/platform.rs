//! # Platform Detection and Capability Enumeration
//!
//! Detects the host OS, CPU architecture, and available isolation capabilities
//! at runtime. This information drives runtime selection in [`RuntimeRegistry`].
//!
//! ## Detection Strategy
//!
//! Platform detection uses compile-time (`cfg!`) and runtime checks:
//!
//! | Capability    | Detection Method                           | False Positive Risk |
//! |---------------|-------------------------------------------|---------------------|
//! | `Namespaces`  | `/proc/self/ns/pid` exists               | Low                 |
//! | `Cgroups`     | `/sys/fs/cgroup` exists                   | Low                 |
//! | `Seccomp`     | `/proc/self/seccomp` or sysctl exists     | Low                 |
//! | `Hypervisor`  | KVM: `/dev/kvm` accessible; HVF: context  | Medium              |
//! | `WasmRuntime` | Always true (pure Rust)                   | None                |
//!
//! ## Security Considerations
//!
//! ### Capability Spoofing
//!
//! An attacker with filesystem access could create fake capability indicators:
//! - Create `/dev/kvm` as a regular file → `Hypervisor` would be incorrectly detected
//! - However, actual VM creation would fail, so this is a false positive not a security hole
//!
//! **Mitigation**: Always handle runtime unavailability gracefully. Detection is
//! a hint, not a guarantee. The actual runtime constructors perform real checks.
//!
//! ### Race Conditions
//!
//! Capabilities can change between detection and use:
//! - `/dev/kvm` could be removed after detection
//! - Cgroup filesystem could be unmounted
//!
//! **Mitigation**: Runtimes validate availability on each operation, not just
//! at construction time.
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::{Platform, Capability};
//!
//! let platform = Platform::detect();
//!
//! if platform.supports_native_containers() {
//!     println!("Can use YoukiRuntime (Linux namespaces + cgroups)");
//! }
//!
//! if platform.has_hypervisor() {
//!     println!("Can use KrunRuntime (hardware virtualization)");
//! }
//!
//! // WASM is always available
//! assert!(platform.capabilities.contains(&Capability::WasmRuntime));
//! ```
//!
//! [`RuntimeRegistry`]: crate::runtimes::RuntimeRegistry

use std::collections::HashSet;
use std::path::Path;

/// Detected platform information for runtime selection.
///
/// Created by [`Platform::detect`] to capture OS, architecture, and
/// available isolation capabilities.
///
/// ## Thread Safety
///
/// `Platform` is `Clone` and can be shared across threads. The detection
/// is a one-time operation; capabilities don't update automatically if
/// the system changes.
///
/// ## Usage
///
/// ```rust,ignore
/// let platform = Platform::detect();
///
/// // Check capabilities
/// if platform.supports_native_containers() {
///     // YoukiRuntime available
/// }
///
/// // Get OCI platform string for image pulling
/// let oci_platform = platform.oci_platform(); // e.g., "linux/amd64"
/// ```
#[derive(Debug, Clone)]
pub struct Platform {
    /// Operating system.
    pub os: Os,
    /// CPU architecture.
    pub arch: Arch,
    /// Kernel version (if detectable).
    pub kernel_version: Option<String>,
    /// Available capabilities.
    pub capabilities: HashSet<Capability>,
}

/// Detected operating system.
///
/// Determined at compile time via `cfg!` macros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Linux,
    Darwin,
    Windows,
    Unknown,
}

/// Detected CPU architecture.
///
/// Determined at compile time via `cfg!` macros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    Amd64,
    Arm64,
    Arm,
    Unknown,
}

/// Platform capabilities that determine runtime availability.
///
/// Each capability represents an isolation technology or feature.
/// Capabilities are detected at runtime, not compile time.
///
/// ## Detection vs. Usability
///
/// A detected capability does not guarantee usability:
/// - `Namespaces` may require root/CAP_SYS_ADMIN
/// - `Cgroups` may require cgroup v2 unified hierarchy
/// - `Hypervisor` may require KVM module loaded with access
///
/// Runtime constructors perform additional validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Linux namespaces (pid, net, mnt, etc.)
    Namespaces,
    /// Linux control groups (v1 or v2)
    Cgroups,
    /// Seccomp syscall filtering
    Seccomp,
    /// Hardware virtualization (KVM on Linux, HVF on macOS)
    Hypervisor,
    /// WASM runtime available (always true - wasmtime is pure Rust)
    WasmRuntime,
}

impl Platform {
    /// Detects the current platform and its capabilities.
    pub fn detect() -> Self {
        let os = Self::detect_os();
        let arch = Self::detect_arch();
        let kernel_version = Self::detect_kernel_version();
        let capabilities = Self::detect_capabilities(os);

        Self {
            os,
            arch,
            kernel_version,
            capabilities,
        }
    }

    /// Detects the operating system.
    fn detect_os() -> Os {
        #[cfg(target_os = "linux")]
        return Os::Linux;

        #[cfg(target_os = "macos")]
        return Os::Darwin;

        #[cfg(target_os = "windows")]
        return Os::Windows;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        return Os::Unknown;
    }

    /// Detects the CPU architecture.
    fn detect_arch() -> Arch {
        #[cfg(target_arch = "x86_64")]
        return Arch::Amd64;

        #[cfg(target_arch = "aarch64")]
        return Arch::Arm64;

        #[cfg(target_arch = "arm")]
        return Arch::Arm;

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
        return Arch::Unknown;
    }

    /// Detects kernel version.
    fn detect_kernel_version() -> Option<String> {
        #[cfg(unix)]
        {
            use std::process::Command;
            Command::new("uname")
                .arg("-r")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        }

        #[cfg(not(unix))]
        None
    }

    /// Detects available capabilities based on OS.
    fn detect_capabilities(os: Os) -> HashSet<Capability> {
        let mut caps = HashSet::new();

        // WASM is always available (pure Rust wasmtime)
        caps.insert(Capability::WasmRuntime);

        match os {
            Os::Linux => {
                // Check for namespace support
                if Path::new("/proc/self/ns/pid").exists() {
                    caps.insert(Capability::Namespaces);
                }

                // Check for cgroup support
                if Path::new("/sys/fs/cgroup").exists() {
                    caps.insert(Capability::Cgroups);
                }

                // Check for seccomp
                if Path::new("/proc/self/seccomp").exists()
                    || Path::new("/proc/sys/kernel/seccomp").exists()
                {
                    caps.insert(Capability::Seccomp);
                }

                // Check for KVM
                if Self::check_kvm() {
                    caps.insert(Capability::Hypervisor);
                }
            }
            Os::Darwin => {
                // Check for Hypervisor.framework
                if Self::check_hvf() {
                    caps.insert(Capability::Hypervisor);
                }
                // macOS has no namespace/cgroup support
            }
            _ => {
                // Other platforms: minimal capabilities
            }
        }

        caps
    }

    /// Checks if KVM is available on Linux.
    #[cfg(target_os = "linux")]
    fn check_kvm() -> bool {
        use std::fs;
        use std::os::unix::fs::MetadataExt;

        let kvm_path = Path::new("/dev/kvm");
        if !kvm_path.exists() {
            return false;
        }

        // Check if we have read/write access
        match fs::metadata(kvm_path) {
            Ok(meta) => {
                let mode = meta.mode();
                // Check if accessible (very basic check)
                mode & 0o006 != 0 || mode & 0o060 != 0 || mode & 0o600 != 0
            }
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn check_kvm() -> bool {
        false
    }

    /// Checks if Hypervisor.framework is available on macOS.
    #[cfg(target_os = "macos")]
    fn check_hvf() -> bool {
        // Try to create a libkrun context to verify HVF works
        // SAFETY: krun_create_ctx is safe to call and returns < 0 on failure
        unsafe {
            let ctx = krun_sys::krun_create_ctx();
            if ctx >= 0 {
                krun_sys::krun_free_ctx(ctx as u32);
                return true;
            }
        }
        false
    }

    #[cfg(not(target_os = "macos"))]
    fn check_hvf() -> bool {
        false
    }

    /// Returns true if native Linux containers are supported.
    pub fn supports_native_containers(&self) -> bool {
        self.capabilities.contains(&Capability::Namespaces)
            && self.capabilities.contains(&Capability::Cgroups)
    }

    /// Returns true if hardware virtualization is available.
    pub fn has_hypervisor(&self) -> bool {
        self.capabilities.contains(&Capability::Hypervisor)
    }

    /// Returns the OCI platform string (e.g., "linux/amd64").
    pub fn oci_platform(&self) -> String {
        let os = match self.os {
            Os::Linux => "linux",
            Os::Darwin => "darwin",
            Os::Windows => "windows",
            Os::Unknown => "unknown",
        };

        let arch = match self.arch {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
            Arch::Arm => "arm",
            Arch::Unknown => "unknown",
        };

        format!("{}/{}", os, arch)
    }

    /// Returns the target triple for the guest OS in microVMs.
    /// MicroVMs always run Linux, so this returns the Linux target.
    pub fn guest_target(&self) -> &'static str {
        match self.arch {
            Arch::Amd64 => "x86_64-unknown-linux-musl",
            Arch::Arm64 => "aarch64-unknown-linux-musl",
            Arch::Arm => "arm-unknown-linux-musleabi",
            Arch::Unknown => "unknown-unknown-linux-musl",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}/{:?} (capabilities: {:?})",
            self.os, self.arch, self.capabilities
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = Platform::detect();

        // Should detect something
        assert!(platform.os != Os::Unknown || platform.arch != Arch::Unknown);

        // WASM should always be available
        assert!(platform.capabilities.contains(&Capability::WasmRuntime));
    }

    #[test]
    fn test_oci_platform_string() {
        let platform = Platform::detect();
        let oci = platform.oci_platform();

        // Should be in format "os/arch"
        assert!(oci.contains('/'));
    }
}
