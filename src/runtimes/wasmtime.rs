//! Wasmtime OCI Runtime - WASM module execution.
//!
//! This module implements the `OciRuntime` trait for WebAssembly workloads
//! using wasmtime. Each container is a WASM module with WASI support.

use crate::error::{Error, Result};
use crate::runtime::{ContainerState, ContainerStatus, ExecOptions, ExecResult, OciRuntime, Signal};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, warn};
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};

use crate::constants::{DEFAULT_WASM_FUEL, MAX_WASM_MEMORY_PAGES, MAX_WASM_MODULE_SIZE};

/// Wasmtime OCI runtime implementation.
pub struct WasmtimeRuntime {
    engine: Engine,
    containers: RwLock<HashMap<String, WasmContainer>>,
}

struct WasmContainer {
    bundle: PathBuf,
    status: ContainerStatus,
    started_at: Option<Instant>,
    exit_code: Option<i32>,
}

impl WasmtimeRuntime {
    /// Creates a new wasmtime runtime.
    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true); // Enable fuel for bounded execution
        config.wasm_memory64(false);
        
        let engine = Engine::new(&config).expect("Failed to create wasmtime engine");

        Self {
            engine,
            containers: RwLock::new(HashMap::new()),
        }
    }

    /// Loads a WASM module from a bundle.
    fn load_module(&self, bundle: &Path) -> Result<Module> {
        // Look for module.wasm in bundle
        let module_path = bundle.join("module.wasm");
        
        if !module_path.exists() {
            // Try to find any .wasm file
            let wasm_files: Vec<_> = std::fs::read_dir(bundle)
                .map_err(|e| Error::InvalidBundle {
                    path: bundle.to_path_buf(),
                    reason: e.to_string(),
                })?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "wasm"))
                .collect();

            if wasm_files.is_empty() {
                return Err(Error::InvalidBundle {
                    path: bundle.to_path_buf(),
                    reason: "no .wasm module found".to_string(),
                });
            }

            let module_path = wasm_files[0].path();
            self.load_module_from_file(&module_path)
        } else {
            self.load_module_from_file(&module_path)
        }
    }

    fn load_module_from_file(&self, path: &Path) -> Result<Module> {
        let bytes = std::fs::read(path).map_err(|e| Error::InvalidBundle {
            path: path.to_path_buf(),
            reason: format!("failed to read module: {}", e),
        })?;

        if bytes.len() > MAX_WASM_MODULE_SIZE {
            return Err(Error::InvalidBundle {
                path: path.to_path_buf(),
                reason: format!(
                    "module too large: {} > {} bytes",
                    bytes.len(),
                    MAX_WASM_MODULE_SIZE
                ),
            });
        }

        Module::new(&self.engine, &bytes).map_err(|e| Error::InvalidBundle {
            path: path.to_path_buf(),
            reason: format!("failed to compile module: {}", e),
        })
    }
}

impl Default for WasmtimeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OciRuntime for WasmtimeRuntime {
    fn name(&self) -> &str {
        "wasmtime"
    }

    fn is_available(&self) -> bool {
        true // wasmtime is pure Rust, always available
    }

    fn unavailable_reason(&self) -> Option<String> {
        None
    }

    async fn create(&self, id: &str, bundle: &Path) -> Result<()> {
        debug!("Creating WASM container {} from bundle {}", id, bundle.display());

        // Validate bundle has a WASM module
        let _module = self.load_module(bundle)?;

        // Register container
        {
            let mut containers = self.containers.write().map_err(|e| {
                Error::Internal(format!("lock poisoned: {}", e))
            })?;

            if containers.contains_key(id) {
                return Err(Error::ContainerAlreadyExists(id.to_string()));
            }

            containers.insert(id.to_string(), WasmContainer {
                bundle: bundle.to_path_buf(),
                status: ContainerStatus::Created,
                started_at: None,
                exit_code: None,
            });
        }

        info!("Created WASM container {}", id);
        Ok(())
    }

    async fn start(&self, id: &str) -> Result<()> {
        debug!("Starting WASM container {}", id);

        let bundle = {
            let mut containers = self.containers.write().map_err(|e| {
                Error::Internal(format!("lock poisoned: {}", e))
            })?;

            let container = containers.get_mut(id).ok_or_else(|| {
                Error::ContainerNotFound(id.to_string())
            })?;

            if container.status != ContainerStatus::Created {
                return Err(Error::InvalidState {
                    id: id.to_string(),
                    state: container.status.to_string(),
                    expected: "created".to_string(),
                });
            }

            container.status = ContainerStatus::Running;
            container.started_at = Some(Instant::now());
            container.bundle.clone()
        };

        // Load and run module in background
        let engine = self.engine.clone();
        let id_owned = id.to_string();
        let containers = Arc::new(self.containers.read().map_err(|e| {
            Error::Internal(format!("lock poisoned: {}", e))
        })?.len()); // Placeholder for actual container tracking

        tokio::spawn(async move {
            let result = Self::run_module_blocking(&engine, &bundle);
            
            // TODO: Update container state with exit code
            match result {
                Ok(code) => {
                    debug!("WASM container {} exited with code {}", id_owned, code);
                }
                Err(e) => {
                    warn!("WASM container {} failed: {}", id_owned, e);
                }
            }
        });

        info!("Started WASM container {}", id);
        Ok(())
    }

    async fn state(&self, id: &str) -> Result<ContainerState> {
        let containers = self.containers.read().map_err(|e| {
            Error::Internal(format!("lock poisoned: {}", e))
        })?;

        let container = containers.get(id).ok_or_else(|| {
            Error::ContainerNotFound(id.to_string())
        })?;

        Ok(ContainerState {
            oci_version: "1.0.2".to_string(),
            id: id.to_string(),
            status: container.status,
            pid: None, // WASM has no PID
            bundle: container.bundle.to_string_lossy().to_string(),
            annotations: HashMap::new(),
        })
    }

    async fn kill(&self, id: &str, signal: Signal, _all: bool) -> Result<()> {
        debug!("Killing WASM container {} with {:?}", id, signal);

        let mut containers = self.containers.write().map_err(|e| {
            Error::Internal(format!("lock poisoned: {}", e))
        })?;

        let container = containers.get_mut(id).ok_or_else(|| {
            Error::ContainerNotFound(id.to_string())
        })?;

        // WASM doesn't have signal support, just mark as stopped
        container.status = ContainerStatus::Stopped;
        container.exit_code = Some(137); // Killed

        info!("Killed WASM container {}", id);
        Ok(())
    }

    async fn delete(&self, id: &str, force: bool) -> Result<()> {
        debug!("Deleting WASM container {} (force={})", id, force);

        let mut containers = self.containers.write().map_err(|e| {
            Error::Internal(format!("lock poisoned: {}", e))
        })?;

        let container = containers.get(id).ok_or_else(|| {
            Error::ContainerNotFound(id.to_string())
        })?;

        if !force && container.status == ContainerStatus::Running {
            return Err(Error::InvalidState {
                id: id.to_string(),
                state: "running".to_string(),
                expected: "stopped".to_string(),
            });
        }

        containers.remove(id);

        info!("Deleted WASM container {}", id);
        Ok(())
    }

    async fn wait(&self, id: &str) -> Result<i32> {
        loop {
            let state = self.state(id).await?;
            if state.status == ContainerStatus::Stopped {
                let containers = self.containers.read().map_err(|e| {
                    Error::Internal(format!("lock poisoned: {}", e))
                })?;
                let container = containers.get(id).ok_or_else(|| {
                    Error::ContainerNotFound(id.to_string())
                })?;
                return Ok(container.exit_code.unwrap_or(0));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

impl WasmtimeRuntime {
    /// Runs a WASM module synchronously.
    fn run_module_blocking(engine: &Engine, bundle: &Path) -> Result<i32> {
        // Load module
        let module_path = bundle.join("module.wasm");
        let bytes = std::fs::read(&module_path).map_err(|e| Error::StartFailed {
            id: bundle.to_string_lossy().to_string(),
            reason: format!("failed to read module: {}", e),
        })?;

        let module = Module::new(engine, &bytes).map_err(|e| Error::StartFailed {
            id: bundle.to_string_lossy().to_string(),
            reason: format!("failed to compile: {}", e),
        })?;

        // Build WASI context
        let wasi = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build_p1();

        // Create store with fuel
        let mut store = Store::new(engine, wasi);
        store.set_fuel(DEFAULT_WASM_FUEL).ok();

        // Create linker and add WASI
        let mut linker = Linker::new(engine);
        preview1::add_to_linker_sync(&mut linker, |ctx| ctx).map_err(|e| Error::StartFailed {
            id: bundle.to_string_lossy().to_string(),
            reason: format!("failed to add WASI: {}", e),
        })?;

        // Instantiate and run
        let instance = linker.instantiate(&mut store, &module).map_err(|e| Error::StartFailed {
            id: bundle.to_string_lossy().to_string(),
            reason: format!("failed to instantiate: {}", e),
        })?;

        // Call _start if it exists
        if let Some(start) = instance.get_func(&mut store, "_start") {
            start.call(&mut store, &[], &mut []).map_err(|e| Error::StartFailed {
                id: bundle.to_string_lossy().to_string(),
                reason: format!("_start failed: {}", e),
            })?;
        }

        Ok(0)
    }
}
