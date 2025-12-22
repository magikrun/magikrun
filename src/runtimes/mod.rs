//! OCI Runtime implementations.
//!
//! This module contains pure OCI runtime implementations that conform
//! to the OCI Runtime Spec. Each runtime handles single-container
//! operations without pod awareness.

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

/// Registry of available OCI runtimes.
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
