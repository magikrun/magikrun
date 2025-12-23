//! # OCI Runtime Implementations
//!
//! This module contains pure OCI runtime implementations that conform
//! to the OCI Runtime Spec. Each runtime handles single-container
//! operations without pod awareness.
//!
//! ## Available Runtimes
//!
//! | Runtime           | Platform     | Isolation       | Availability      |
//! |-------------------|--------------|-----------------|-------------------|
//! | [`YoukiRuntime`]  | Linux only   | Namespaces/cgroups | Requires root/caps |
//! | [`WasmtimeRuntime`]| All platforms| WASM sandbox    | Always available  |
//! | [`KrunRuntime`]   | Linux/macOS  | Hardware VM     | Requires hypervisor|
//!
//! ## Runtime Selection
//!
//! Use [`RuntimeRegistry`] to discover and select runtimes:
//!
//! ```rust,ignore
//! use magikrun::{Platform, RuntimeRegistry};
//!
//! let platform = Platform::detect();
//! let registry = RuntimeRegistry::new(&platform)?;
//!
//! // List available runtimes
//! for runtime in registry.available() {
//!     println!("{}: available", runtime.name());
//! }
//!
//! // Get specific runtime
//! if let Some(youki) = registry.get("youki") {
//!     println!("youki is available");
//! }
//! ```
//!
//! ## Security Hierarchy
//!
//! Runtimes provide different isolation guarantees:
//!
//! ```text
//! Isolation Strength:
//!
//!   KrunRuntime     ██████████  Hardware VM (strongest)
//!   YoukiRuntime    ███████     Linux namespaces/cgroups
//!   WasmtimeRuntime ████        WASM sandbox (weakest, but portable)
//! ```
//!
//! For untrusted workloads, prefer `KrunRuntime`. For trusted internal
//! services, `YoukiRuntime` provides better performance. For portable
//! plugins, `WasmtimeRuntime` works everywhere.
//!
//! ## Implementation Notes
//!
//! All runtimes:
//! - Implement the [`OciRuntime`] trait
//! - Check availability at construction time
//! - Provide `unavailable_reason()` for debugging
//! - Are compiled unconditionally (runtime checks, not compile-time)
//!
//! [`OciRuntime`]: crate::runtime::OciRuntime

pub mod youki;
pub mod wasmtime;
pub mod krun;

pub use self::youki::YoukiRuntime;
pub use self::wasmtime::WasmtimeRuntime;
pub use self::krun::KrunRuntime;

use crate::error::Result;
use crate::platform::Platform;
use crate::runtime::OciRuntime;
use std::sync::Arc;

/// Registry of available OCI runtimes on this platform.
///
/// Automatically detects and registers runtimes based on platform
/// capabilities. Use this to discover and select appropriate runtimes
/// for workloads.
///
/// ## Registration Order
///
/// Runtimes are registered in this order:
/// 1. `wasmtime` - Always available (pure Rust)
/// 2. `youki` - Linux only, requires namespaces/cgroups
/// 3. `krun` - Requires hypervisor (KVM/HVF)
///
/// ## Example
///
/// ```rust,ignore
/// let platform = Platform::detect();
/// let registry = RuntimeRegistry::new(&platform)?;
///
/// // Prefer hardware VM, fall back to containers, then WASM
/// let runtime = registry.get("krun")
///     .or_else(|| registry.get("youki"))
///     .or_else(|| registry.get("wasmtime"))
///     .expect("wasmtime always available");
/// ```
pub struct RuntimeRegistry {
    runtimes: Vec<Arc<dyn OciRuntime>>,
}

impl RuntimeRegistry {
    /// Creates a new runtime registry, detecting available runtimes.
    pub fn new(platform: &Platform) -> Result<Self> {
        let mut runtimes: Vec<Arc<dyn OciRuntime>> = Vec::new();

        // Always add wasmtime (pure Rust, always available)
        runtimes.push(Arc::new(WasmtimeRuntime::new()));

        // Add youki on Linux
        #[cfg(target_os = "linux")]
        {
            runtimes.push(Arc::new(YoukiRuntime::new()));
        }

        // Add krun if hypervisor is available
        if platform.has_hypervisor() {
            runtimes.push(Arc::new(KrunRuntime::new()));
        }

        Ok(Self { runtimes })
    }

    /// Returns all registered runtimes.
    pub fn all(&self) -> &[Arc<dyn OciRuntime>] {
        &self.runtimes
    }

    /// Returns all available runtimes.
    pub fn available(&self) -> Vec<&dyn OciRuntime> {
        self.runtimes
            .iter()
            .filter(|r| r.is_available())
            .map(|r| r.as_ref())
            .collect()
    }

    /// Gets a runtime by name.
    pub fn get(&self, name: &str) -> Option<&dyn OciRuntime> {
        self.runtimes
            .iter()
            .find(|r| r.name() == name)
            .map(|r| r.as_ref())
    }
}
