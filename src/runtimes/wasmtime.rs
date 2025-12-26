//! # Wasmtime OCI Runtime - WebAssembly Module Execution
//!
//! Implements the [`OciRuntime`] trait for WebAssembly workloads using
//! the wasmtime engine. Provides portable, sandboxed execution with
//! bounded resources.
//!
//! ## Platform Support
//!
//! Wasmtime is pure Rust and available on all platforms:
//! - Linux (x86_64, aarch64)
//! - macOS (x86_64, aarch64)
//! - Windows (x86_64)
//!
//! No kernel features or elevated privileges required.
//!
//! ## Security Model
//!
//! WASM provides a capability-based security model:
//!
//! | Capability      | Default | Notes                              |
//! |-----------------|---------|------------------------------------|
//! | Filesystem      | None    | Must explicitly grant via WASI    |
//! | Network         | None    | Requires WASI networking preview  |
//! | Environment vars| Inherit | Configurable per-container        |
//! | Stdout/Stderr   | Inherit | Output visible to host            |
//! | Memory          | Bounded | `MAX_WASM_MEMORY_PAGES` (4 GiB)   |
//! | CPU             | Bounded | `DEFAULT_WASM_FUEL` (1B ops)      |
//!
//! ### Fuel-Based Execution Limits
//!
//! Every WASM instruction consumes "fuel". When fuel is exhausted, the
//! module traps with `OutOfFuel`. This prevents infinite loops and
//! CPU-bound denial-of-service.
//!
//! ```rust,ignore
//! // 1 billion operations = ~1-10 seconds execution
//! const DEFAULT_WASM_FUEL: u64 = 1_000_000_000;
//! ```
//!
//! ### Module Size Limits
//!
//! WASM modules are validated against `MAX_WASM_MODULE_SIZE` (256 MiB)
//! before compilation. This prevents memory exhaustion during JIT.
//!
//! ## Bundle Format
//!
//! WASM bundles contain:
//! - `module.wasm` or any `.wasm` file
//! - Optional WASI configuration (args, env, directory mappings)
//!
//! ## Lifecycle Mapping
//!
//! OCI operations map to WASM execution:
//!
//! | OCI Operation | WASM Behavior                              |
//! |---------------|--------------------------------------------|
//! | `create()`    | Validate and compile module                |
//! | `start()`     | Instantiate module, call `_start`          |
//! | `state()`     | Return tracked status                     |
//! | `kill()`      | Mark as stopped (no signal support)        |
//! | `delete()`    | Remove from tracking                      |
//!
//! Note: WASM has no signal support. `kill()` simply marks the container
//! as stopped and relies on fuel exhaustion or natural exit.
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::runtimes::WasmtimeRuntime;
//! use magikrun::OciRuntime;
//!
//! #[tokio::main]
//! async fn main() -> magikrun::Result<()> {
//!     let runtime = WasmtimeRuntime::new();
//!     
//!     // Always available
//!     assert!(runtime.is_available());
//!     
//!     runtime.create("my-wasm", "/path/to/bundle".as_ref()).await?;
//!     runtime.start("my-wasm").await?;
//!     
//!     // Wait for completion
//!     let exit_code = runtime.wait("my-wasm").await?;
//!     println!("Exited with code {}", exit_code);
//!     
//!     runtime.delete("my-wasm", false).await?;
//!     Ok(())
//! }
//! ```
//!
//! [`OciRuntime`]: crate::runtime::OciRuntime

use crate::error::{Error, Result};
use crate::runtime::{ContainerState, ContainerStatus, OciRuntime, Signal};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, warn};
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{self, WasiP1Ctx};

use crate::constants::{
    DEFAULT_WASM_FUEL, MAX_CONTAINERS, MAX_WASM_MODULE_SIZE, validate_container_id,
};

/// Wasmtime OCI runtime for WebAssembly module execution.
///
/// Provides portable, sandboxed execution of WASM modules with WASI support.
/// Always available on all platforms (pure Rust implementation).
///
/// ## Thread Safety
///
/// This struct is thread-safe (`Send + Sync`). The wasmtime engine is
/// designed for concurrent use, and container state is protected by
/// an internal `RwLock`.
///
/// ## Engine Configuration
///
/// The wasmtime engine is configured with:
/// - Fuel consumption enabled (bounded execution)
/// - Memory64 disabled (32-bit address space only)
///
/// ## Resource Cleanup
///
/// WASM modules are automatically cleaned up when `delete()` is called.
/// Unlike native containers, there are no kernel resources to leak.
pub struct WasmtimeRuntime {
    engine: Option<Engine>,
    /// Error message if engine creation failed.
    engine_error: Option<String>,
    /// Container state wrapped in Arc for sharing with async execution tasks.
    containers: Arc<RwLock<HashMap<String, WasmContainer>>>,
}

/// Internal state tracking for a WASM container.
///
/// Holds execution state and bundle information for the container.
///
/// # Module Caching
///
/// The compiled [`Module`] is stored during `create()` to avoid double
/// compilation. This reduces memory pressure and CPU usage during `start()`.
struct WasmContainer {
    bundle: PathBuf,
    /// Compiled WASM module (cached from create() to avoid recompilation).
    module: Module,
    /// WASI arguments for the module.
    wasi_args: Vec<String>,
    /// WASI environment variables.
    wasi_env: Vec<(String, String)>,
    /// WASI directory pre-opens (guest_path, host_path).
    wasi_dirs: Vec<(String, String)>,
    /// Optional fuel limit override.
    fuel_limit: Option<u64>,
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

        match Engine::new(&config) {
            Ok(engine) => Self {
                engine: Some(engine),
                engine_error: None,
                containers: Arc::new(RwLock::new(HashMap::new())),
            },
            Err(e) => {
                warn!("Failed to create wasmtime engine: {}", e);
                Self {
                    engine: None,
                    engine_error: Some(format!("engine creation failed: {}", e)),
                    containers: Arc::new(RwLock::new(HashMap::new())),
                }
            }
        }
    }

    /// Loads a WASM module from a bundle.
    /// Returns the compiled module and the resolved path to the WASM file.
    fn load_module(&self, bundle: &Path) -> Result<(Module, PathBuf)> {
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
            let module = self.load_module_from_file(&module_path)?;
            Ok((module, module_path))
        } else {
            let module = self.load_module_from_file(&module_path)?;
            Ok((module, module_path))
        }
    }

    fn load_module_from_file(&self, path: &Path) -> Result<Module> {
        let engine = self
            .engine
            .as_ref()
            .ok_or_else(|| Error::RuntimeUnavailable {
                runtime: "wasmtime".to_string(),
                reason: self
                    .engine_error
                    .clone()
                    .unwrap_or_else(|| "engine not initialized".to_string()),
            })?;

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

        Module::new(engine, &bytes).map_err(|e| Error::InvalidBundle {
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
        self.engine.is_some()
    }

    fn unavailable_reason(&self) -> Option<String> {
        self.engine_error.clone()
    }

    async fn create(&self, id: &str, bundle: &Path) -> Result<()> {
        debug!(
            "Creating WASM container {} from bundle {}",
            id,
            bundle.display()
        );

        // SECURITY: Validate container ID format
        validate_container_id(id).map_err(|reason| Error::InvalidContainerId {
            id: id.to_string(),
            reason: reason.to_string(),
        })?;

        // Compile module once during create() and cache it
        // This avoids double compilation (validate + run) and reduces memory pressure
        let (module, _module_path) = self.load_module(bundle)?;

        // Register container
        {
            let mut containers = self
                .containers
                .write()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            // SECURITY: Enforce container limit to prevent unbounded memory growth
            if containers.len() >= MAX_CONTAINERS {
                return Err(Error::ResourceExhausted(format!(
                    "maximum container limit reached ({})",
                    MAX_CONTAINERS
                )));
            }

            if containers.contains_key(id) {
                return Err(Error::ContainerAlreadyExists(id.to_string()));
            }

            // Load WASI configuration from bundle if present
            let (wasi_args, wasi_env, wasi_dirs, fuel_limit) =
                Self::load_wasi_config(bundle).unwrap_or_default();

            containers.insert(
                id.to_string(),
                WasmContainer {
                    bundle: bundle.to_path_buf(),
                    module,
                    wasi_args,
                    wasi_env,
                    wasi_dirs,
                    fuel_limit,
                    status: ContainerStatus::Created,
                    started_at: None,
                    exit_code: None,
                },
            );
        }

        info!("Created WASM container {}", id);
        Ok(())
    }

    async fn start(&self, id: &str) -> Result<()> {
        debug!("Starting WASM container {}", id);

        let (bundle, module, wasi_args, wasi_env, wasi_dirs, fuel_limit) = {
            let mut containers = self
                .containers
                .write()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get_mut(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            if container.status != ContainerStatus::Created {
                return Err(Error::InvalidState {
                    id: id.to_string(),
                    state: container.status.to_string(),
                    expected: "created".to_string(),
                });
            }

            container.status = ContainerStatus::Running;
            container.started_at = Some(Instant::now());
            // Clone data for use in spawned task
            (
                container.bundle.clone(),
                container.module.clone(),
                container.wasi_args.clone(),
                container.wasi_env.clone(),
                container.wasi_dirs.clone(),
                container.fuel_limit,
            )
        };

        // Get engine reference
        let engine = self
            .engine
            .clone()
            .ok_or_else(|| Error::RuntimeUnavailable {
                runtime: "wasmtime".to_string(),
                reason: self
                    .engine_error
                    .clone()
                    .unwrap_or_else(|| "engine not initialized".to_string()),
            })?;

        // Run module in background using cached compiled module
        let id_owned = id.to_string();
        // Clone Arc for sharing with async task
        let containers_ref = Arc::clone(&self.containers);

        tokio::spawn(async move {
            let result = Self::run_module(
                &engine,
                &module,
                &bundle,
                &wasi_args,
                &wasi_env,
                &wasi_dirs,
                fuel_limit,
            );

            // Update container state with exit code
            let (exit_code, log_msg) = match result {
                Ok(code) => (
                    code,
                    format!("WASM container {} exited with code {}", id_owned, code),
                ),
                Err(e) => (-1, format!("WASM container {} failed: {}", id_owned, e)),
            };

            // Update state in shared container map
            if let Ok(mut guard) = containers_ref.write()
                && let Some(container) = guard.get_mut(&id_owned)
            {
                container.status = ContainerStatus::Stopped;
                container.exit_code = Some(exit_code);
            }

            if exit_code == 0 {
                debug!("{}", log_msg);
            } else {
                warn!("{}", log_msg);
            }
        });

        info!("Started WASM container {}", id);
        Ok(())
    }

    async fn state(&self, id: &str) -> Result<ContainerState> {
        let containers = self
            .containers
            .read()
            .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

        let container = containers
            .get(id)
            .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

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

        let mut containers = self
            .containers
            .write()
            .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

        // WASM doesn't have signal support, just mark as stopped
        container.status = ContainerStatus::Stopped;
        container.exit_code = Some(137); // Killed

        info!("Killed WASM container {}", id);
        Ok(())
    }

    async fn delete(&self, id: &str, force: bool) -> Result<()> {
        debug!("Deleting WASM container {} (force={})", id, force);

        let mut containers = self
            .containers
            .write()
            .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

        let container = containers
            .get(id)
            .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

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
        use crate::constants::CONTAINER_WAIT_TIMEOUT;

        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > CONTAINER_WAIT_TIMEOUT {
                return Err(Error::Timeout {
                    operation: format!("wait for container {}", id),
                    duration: CONTAINER_WAIT_TIMEOUT,
                });
            }

            let state = self.state(id).await?;
            if state.status == ContainerStatus::Stopped {
                let containers = self
                    .containers
                    .read()
                    .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;
                let container = containers
                    .get(id)
                    .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;
                return Ok(container.exit_code.unwrap_or(0));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

impl WasmtimeRuntime {
    /// Runs a pre-compiled WASM module synchronously.
    ///
    /// # Arguments
    /// * `engine` - The wasmtime engine to use
    /// * `module` - The pre-compiled WASM module (cached from create())
    /// * `bundle` - Path to the bundle directory (for error context)
    /// * `wasi_args` - Command-line arguments for the WASM module
    /// * `wasi_env` - Environment variables for the WASM module
    /// * `wasi_dirs` - Directory pre-opens (guest_path, host_path)
    /// * `fuel_limit` - Optional fuel limit override
    fn run_module(
        engine: &Engine,
        module: &Module,
        bundle: &Path,
        wasi_args: &[String],
        wasi_env: &[(String, String)],
        wasi_dirs: &[(String, String)],
        fuel_limit: Option<u64>,
    ) -> Result<i32> {
        // Build WASI context with configuration
        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder.inherit_stdout().inherit_stderr();

        // Add command-line arguments
        if !wasi_args.is_empty() {
            wasi_builder.args(wasi_args);
        }

        // Add environment variables
        for (key, value) in wasi_env {
            wasi_builder.env(key, value);
        }

        // Add directory pre-opens
        // SECURITY: Only directories explicitly listed are accessible to the WASM module
        // SECURITY: Use read-only permissions by default to enforce least privilege.
        // If write access is needed, it must be explicitly configured in wasi.json.
        for (guest_path, host_path) in wasi_dirs {
            // Use the path-based API which handles opening internally
            match wasi_builder.preopened_dir(
                host_path,
                guest_path,
                wasmtime_wasi::DirPerms::READ,
                wasmtime_wasi::FilePerms::READ,
            ) {
                Ok(_) => debug!("Pre-opened WASI directory: {} -> {}", guest_path, host_path),
                Err(e) => {
                    warn!(
                        "Failed to pre-open WASI directory '{}' -> '{}': {}",
                        guest_path, host_path, e
                    );
                }
            }
        }

        let wasi = wasi_builder.build_p1();

        // Create store with fuel (use override or default)
        let mut store: Store<WasiP1Ctx> = Store::new(engine, wasi);
        let fuel = fuel_limit.unwrap_or(DEFAULT_WASM_FUEL);
        store.set_fuel(fuel).ok();

        // Create linker and add WASI
        let mut linker: Linker<WasiP1Ctx> = Linker::new(engine);
        p1::add_to_linker_sync(&mut linker, |ctx| ctx).map_err(|e| Error::StartFailed {
            id: bundle.to_string_lossy().to_string(),
            reason: format!("failed to add WASI: {}", e),
        })?;

        // Instantiate and run (using cached compiled module)
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| Error::StartFailed {
                id: bundle.to_string_lossy().to_string(),
                reason: format!("failed to instantiate: {}", e),
            })?;

        // Call _start if it exists
        if let Some(start) = instance.get_func(&mut store, "_start") {
            start
                .call(&mut store, &[], &mut [])
                .map_err(|e| Error::StartFailed {
                    id: bundle.to_string_lossy().to_string(),
                    reason: format!("_start failed: {}", e),
                })?;
        }

        Ok(0)
    }

    /// Loads WASI configuration from a bundle's wasi.json file.
    ///
    /// The wasi.json file is optional and contains:
    /// ```json
    /// {
    ///   "args": ["arg1", "arg2"],
    ///   "env": [["KEY", "VALUE"]],
    ///   "dirs": [["guest_path", "host_path"]],
    ///   "fuel_limit": 2000000000
    /// }
    /// ```
    #[allow(clippy::type_complexity)] // Internal helper - tuple matches WasmContainer fields directly
    fn load_wasi_config(
        bundle: &Path,
    ) -> Option<(Vec<String>, Vec<(String, String)>, Vec<(String, String)>, Option<u64>)> {
        let config_path = bundle.join("wasi.json");
        if !config_path.exists() {
            return None;
        }

        #[derive(serde::Deserialize, Default)]
        struct WasiConfig {
            #[serde(default)]
            args: Vec<String>,
            #[serde(default)]
            env: Vec<(String, String)>,
            #[serde(default)]
            dirs: Vec<(String, String)>,
            fuel_limit: Option<u64>,
        }

        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read wasi.json at {}: {}", config_path.display(), e);
                return None;
            }
        };

        match serde_json::from_str::<WasiConfig>(&content) {
            Ok(config) => Some((config.args, config.env, config.dirs, config.fuel_limit)),
            Err(e) => {
                warn!(
                    "Failed to parse wasi.json at {}: {}. Using defaults.",
                    config_path.display(),
                    e
                );
                None
            }
        }
    }
}
