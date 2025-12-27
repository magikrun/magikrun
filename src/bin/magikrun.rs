//! MagikRun - OCI Runtime CLI
//!
//! A unified OCI-compliant runtime for containers, WebAssembly, and microVMs.
//! Follows the OCI runtime-spec CLI interface like runc/crun.
//!
//! ## Usage
//!
//! ```sh
//! magikrun create <container-id> --bundle <path>
//! magikrun start <container-id>
//! magikrun state <container-id>
//! magikrun kill <container-id> [signal]
//! magikrun delete <container-id> [--force]
//! ```
//!
//! ## Runtime Selection
//!
//! By default, auto-detects the best available runtime. Override with `--runtime`:
//!
//! - `native` - Linux containers via namespaces/cgroups (Linux only)
//! - `wasm` - WebAssembly via Wasmtime (cross-platform)
//! - `krun` - MicroVMs via libkrun (Linux/macOS)

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

// =============================================================================
// Constants
// =============================================================================

/// Returns the platform-appropriate state root directory.
///
/// - Linux: `/run/magikrun` (tmpfs, fast, ephemeral)
/// - macOS: `~/.magikrun/run` (user-writable, survives reboot)
/// - Windows: `%LOCALAPPDATA%\magikrun\run`
fn default_state_root() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/magikrun")
    }

    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| h.join(".magikrun").join("run"))
            .unwrap_or_else(|| PathBuf::from(".magikrun/run"))
    }

    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir()
            .map(|d| d.join("magikrun").join("run"))
            .unwrap_or_else(|| PathBuf::from("magikrun\\run"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/run/magikrun")
    }
}

/// OCI runtime spec version.
const OCI_VERSION: &str = "1.0.2";

// =============================================================================
// CLI Parsing
// =============================================================================

#[derive(Debug)]
enum Command {
    Create {
        id: String,
        bundle: PathBuf,
        runtime: Option<String>,
    },
    Start {
        id: String,
    },
    State {
        id: String,
    },
    Kill {
        id: String,
        signal: String,
        all: bool,
    },
    Delete {
        id: String,
        force: bool,
    },
    List,
    Version,
    Help,
}

fn parse_args() -> Result<Command, String> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        return Ok(Command::Help);
    }

    match args[1].as_str() {
        "create" => {
            if args.len() < 3 {
                return Err("create requires <container-id>".to_string());
            }
            let id = args[2].clone();
            let mut bundle = PathBuf::from(".");
            let mut runtime = None;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--bundle" | "-b" => {
                        if i + 1 < args.len() {
                            bundle = PathBuf::from(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err("--bundle requires a path".to_string());
                        }
                    }
                    "--runtime" | "-r" => {
                        if i + 1 < args.len() {
                            runtime = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            return Err("--runtime requires a value".to_string());
                        }
                    }
                    _ => i += 1,
                }
            }
            Ok(Command::Create {
                id,
                bundle,
                runtime,
            })
        }
        "start" => {
            if args.len() < 3 {
                return Err("start requires <container-id>".to_string());
            }
            Ok(Command::Start {
                id: args[2].clone(),
            })
        }
        "state" => {
            if args.len() < 3 {
                return Err("state requires <container-id>".to_string());
            }
            Ok(Command::State {
                id: args[2].clone(),
            })
        }
        "kill" => {
            if args.len() < 3 {
                return Err("kill requires <container-id>".to_string());
            }
            let id = args[2].clone();
            let signal = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| "SIGTERM".to_string());
            let all = args.iter().any(|a| a == "--all" || a == "-a");
            Ok(Command::Kill { id, signal, all })
        }
        "delete" => {
            if args.len() < 3 {
                return Err("delete requires <container-id>".to_string());
            }
            let id = args[2].clone();
            let force = args.iter().any(|a| a == "--force" || a == "-f");
            Ok(Command::Delete { id, force })
        }
        "list" => Ok(Command::List),
        "version" | "--version" | "-v" => Ok(Command::Version),
        "help" | "--help" | "-h" => Ok(Command::Help),
        unknown => Err(format!("unknown command: {}", unknown)),
    }
}

// =============================================================================
// State Management
// =============================================================================

/// Container state persisted to disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct ContainerState {
    oci_version: String,
    id: String,
    status: String,
    pid: Option<u32>,
    bundle: String,
    runtime: String,
    #[serde(default)]
    annotations: HashMap<String, String>,
}

fn state_path(id: &str) -> PathBuf {
    default_state_root().join(id).join("state.json")
}

fn load_state(id: &str) -> Result<ContainerState, String> {
    let path = state_path(id);
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("container {} not found: {}", id, e))?;
    serde_json::from_str(&content).map_err(|e| format!("invalid state: {}", e))
}

fn save_state(state: &ContainerState) -> Result<(), String> {
    let dir = default_state_root().join(&state.id);

    // SECURITY: Create directories with restrictive permissions (0o700) to prevent
    // other users from reading container state files which may contain sensitive info.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("failed to create state dir: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create state dir: {}", e))?;
    }

    let path = dir.join("state.json");
    let content = serde_json::to_string_pretty(state).map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(&path, content).map_err(|e| format!("write state: {}", e))
}

fn delete_state(id: &str) -> Result<(), String> {
    let dir = default_state_root().join(id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("delete state: {}", e))?;
    }
    Ok(())
}

// =============================================================================
// Runtime Detection
// =============================================================================

fn detect_runtime(bundle: &std::path::Path) -> String {
    // Check for WASM module
    let rootfs = bundle.join("rootfs");
    if rootfs.join("module.wasm").exists() {
        return "wasm".to_string();
    }

    // Check config.json for hints
    if let Ok(content) = std::fs::read_to_string(bundle.join("config.json")) {
        // Simple heuristic: if config mentions wasm, use wasm runtime
        if content.contains("wasm") || content.contains("wasi") {
            return "wasm".to_string();
        }
    }

    // Platform-specific runtime detection
    detect_platform_runtime()
}

/// Detects the best available runtime for the current platform.
///
/// Priority:
/// 1. krun (microVM) if KVM or Hypervisor.framework available
/// 2. native (Linux only, requires namespaces/cgroups)
/// 3. wasm (fallback, always available)
#[cfg(target_os = "linux")]
fn detect_platform_runtime() -> String {
    // Prefer krun if KVM is available
    if std::path::Path::new("/dev/kvm").exists() {
        return "krun".to_string();
    }
    // Fallback to native Linux containers
    "native".to_string()
}

#[cfg(target_os = "macos")]
fn detect_platform_runtime() -> String {
    // On macOS ARM (Apple Silicon), prefer krun with Hypervisor.framework
    // On macOS x86, fall back to wasm
    #[cfg(target_arch = "aarch64")]
    {
        "krun".to_string()
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        "wasm".to_string()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_platform_runtime() -> String {
    // Unknown platform - wasm is always available
    "wasm".to_string()
}

// =============================================================================
// Command Implementations
// =============================================================================

fn cmd_create(id: String, bundle: PathBuf, runtime: Option<String>) -> Result<(), String> {
    // Validate bundle
    let config_path = bundle.join("config.json");
    if !config_path.exists() {
        return Err(format!("bundle {} missing config.json", bundle.display()));
    }

    // Detect or use specified runtime
    let runtime_name = runtime.unwrap_or_else(|| detect_runtime(&bundle));

    // Validate runtime is available
    match runtime_name.as_str() {
        "native" => {
            #[cfg(not(target_os = "linux"))]
            return Err("native runtime only available on Linux".to_string());
        }
        "krun" => {
            #[cfg(target_os = "windows")]
            return Err("krun runtime not available on Windows".to_string());
        }
        "wasm" => {} // Always available
        other => return Err(format!("unknown runtime: {}", other)),
    }

    // Create state
    let state = ContainerState {
        oci_version: OCI_VERSION.to_string(),
        id: id.clone(),
        status: "created".to_string(),
        pid: None,
        bundle: bundle
            .canonicalize()
            .unwrap_or(bundle)
            .to_string_lossy()
            .to_string(),
        runtime: runtime_name,
        annotations: HashMap::new(),
    };

    save_state(&state)?;
    eprintln!("Created container {}", id);
    Ok(())
}

fn cmd_start(id: String) -> Result<(), String> {
    let mut state = load_state(&id)?;

    if state.status != "created" {
        return Err(format!(
            "container {} is {}, expected created",
            id, state.status
        ));
    }

    let bundle = PathBuf::from(&state.bundle);

    match state.runtime.as_str() {
        "native" => start_native(&id, &bundle, &mut state)?,
        "wasm" => start_wasm(&id, &bundle, &mut state)?,
        "krun" => start_krun(&id, &bundle, &mut state)?,
        other => return Err(format!("unknown runtime: {}", other)),
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn start_native(
    id: &str,
    bundle: &std::path::Path,
    state: &mut ContainerState,
) -> Result<(), String> {
    use libcontainer::container::builder::ContainerBuilder;
    use libcontainer::syscall::syscall::SyscallType;

    let state_root = default_state_root();

    let container = ContainerBuilder::new(id.to_string(), SyscallType::default())
        .with_root_path(&state_root)
        .map_err(|e| format!("invalid root path: {}", e))?
        .validate_id()
        .map_err(|e| format!("invalid container id: {}", e))?
        .as_init(bundle)
        .with_systemd(false)
        .build()
        .map_err(|e| format!("build container: {}", e))?;

    let mut container = container;
    container
        .start()
        .map_err(|e| format!("start failed: {}", e))?;

    state.status = "running".to_string();
    state.pid = container.pid().map(|p| p.as_raw() as u32);
    save_state(state)?;

    eprintln!("Started container {}", id);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn start_native(
    _id: &str,
    _bundle: &std::path::Path,
    _state: &mut ContainerState,
) -> Result<(), String> {
    Err("native runtime only available on Linux".to_string())
}

fn start_wasm(
    id: &str,
    bundle: &std::path::Path,
    state: &mut ContainerState,
) -> Result<(), String> {
    use wasmtime::{Config, Engine, Linker, Module, Store};
    use wasmtime_wasi::WasiCtxBuilder;
    use wasmtime_wasi::p1::{self, WasiP1Ctx};

    let rootfs = bundle.join("rootfs");
    let module_path = if rootfs.join("module.wasm").exists() {
        rootfs.join("module.wasm")
    } else if bundle.join("module.wasm").exists() {
        bundle.join("module.wasm")
    } else {
        return Err(
            "WASM module not found at rootfs/module.wasm or bundle/module.wasm".to_string(),
        );
    };

    // Load module
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(|e| format!("engine: {}", e))?;

    let module_bytes = std::fs::read(&module_path).map_err(|e| format!("read module: {}", e))?;
    let module =
        Module::new(&engine, &module_bytes).map_err(|e| format!("compile module: {}", e))?;

    // Build WASI context
    let wasi = WasiCtxBuilder::new()
        .inherit_stdout()
        .inherit_stderr()
        .build_p1();

    // Create store with fuel
    let mut store: Store<WasiP1Ctx> = Store::new(&engine, wasi);
    store.set_fuel(1_000_000_000).ok(); // 1B ops

    // Create linker and add WASI
    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |ctx| ctx).map_err(|e| format!("link WASI: {}", e))?;

    state.status = "running".to_string();
    state.pid = Some(std::process::id());
    save_state(state)?;

    // Instantiate and run
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("instantiate: {}", e))?;

    // Run _start
    if let Some(start) = instance.get_func(&mut store, "_start") {
        let result = start.call(&mut store, &[], &mut []);
        state.status = "stopped".to_string();
        state.pid = None;
        save_state(state)?;
        result.map_err(|e| format!("wasm trap: {}", e))?;
    }

    eprintln!("Container {} exited", id);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn start_krun(
    id: &str,
    bundle: &std::path::Path,
    state: &mut ContainerState,
) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    let rootfs = bundle.join("rootfs");
    if !rootfs.exists() {
        return Err("rootfs not found".to_string());
    }

    // Find init/shell
    let init_path = if rootfs.join("sbin/init").exists() {
        "/sbin/init"
    } else if rootfs.join("bin/sh").exists() {
        "/bin/sh"
    } else {
        return Err("no init or shell found in rootfs".to_string());
    };

    // Check for passt socket (written by MicroVmPodRuntime)
    let passt_socket_path = bundle.join("passt.sock");
    let passt_socket: Option<UnixStream> = if passt_socket_path.exists() {
        match std::fs::read_to_string(&passt_socket_path) {
            Ok(socket_path) => {
                let socket_path = socket_path.trim();
                match UnixStream::connect(socket_path) {
                    Ok(stream) => {
                        eprintln!("Connected to passt socket: {}", socket_path);
                        Some(stream)
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: failed to connect to passt socket {}: {}",
                            socket_path, e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to read passt socket path: {}", e);
                None
            }
        }
    } else {
        None
    };

    state.status = "running".to_string();
    state.pid = Some(std::process::id());
    save_state(state)?;

    eprintln!("Starting microVM for container {}", id);

    // SAFETY: All krun_sys functions are FFI calls to libkrun.
    // They are safe when called with valid arguments.
    unsafe {
        let ctx = krun_sys::krun_create_ctx();
        if ctx < 0 {
            return Err(format!("krun_create_ctx failed: {}", ctx));
        }
        let ctx = ctx as u32;

        // Configure VM: 1 vCPU, 512 MiB RAM
        let ret = krun_sys::krun_set_vm_config(ctx, 1, 512);
        if ret < 0 {
            krun_sys::krun_free_ctx(ctx);
            return Err(format!("krun_set_vm_config failed: {}", ret));
        }

        // Set rootfs
        let rootfs_str = rootfs.to_string_lossy();
        let rootfs_c = CString::new(rootfs_str.as_ref()).map_err(|_| "rootfs path contains NUL")?;
        let ret = krun_sys::krun_set_root(ctx, rootfs_c.as_ptr());
        if ret < 0 {
            krun_sys::krun_free_ctx(ctx);
            return Err(format!("krun_set_root failed: {}", ret));
        }

        // Configure passt networking if available
        if let Some(ref socket) = passt_socket {
            let fd = socket.as_raw_fd();
            let ret = krun_sys::krun_set_passt_fd(ctx, fd);
            if ret < 0 {
                eprintln!(
                    "Warning: krun_set_passt_fd failed: {} (continuing without passt)",
                    ret
                );
            } else {
                eprintln!("Configured passt networking (fd={})", fd);
            }
        }

        // Set workdir
        let workdir_c = CString::new("/").unwrap();
        let ret = krun_sys::krun_set_workdir(ctx, workdir_c.as_ptr());
        if ret < 0 {
            krun_sys::krun_free_ctx(ctx);
            return Err(format!("krun_set_workdir failed: {}", ret));
        }

        // Set executable
        let cmd_c = CString::new(init_path).unwrap();
        let argv: [*const c_char; 2] = [cmd_c.as_ptr(), std::ptr::null()];
        let envp: [*const c_char; 1] = [std::ptr::null()];
        let ret = krun_sys::krun_set_exec(ctx, cmd_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
        if ret < 0 {
            krun_sys::krun_free_ctx(ctx);
            return Err(format!("krun_set_exec failed: {}", ret));
        }

        // Keep passt socket alive during VM execution.
        // SAFETY: We use ManuallyDrop instead of mem::forget to avoid leaking
        // the socket fd on VM startup failure. The socket must remain open until
        // after krun_start_enter() completes (or fails). ManuallyDrop prevents
        // the destructor from running while still allowing us to access the fd.
        // On success, krun_start_enter never returns (process becomes VM).
        // On failure, the ManuallyDrop will be dropped when the variable goes
        // out of scope, but since Option<UnixStream> was already moved in,
        // we're just dropping a ManuallyDrop wrapper (no actual cleanup needed
        // since the fd ownership was transferred to krun).
        let _passt_socket_guard = std::mem::ManuallyDrop::new(passt_socket);

        // Start VM - THIS NEVER RETURNS ON SUCCESS
        // The process becomes the VM and exits when the VM exits
        let ret = krun_sys::krun_start_enter(ctx);

        // If we get here, the VM failed to start
        krun_sys::krun_free_ctx(ctx);
        Err(format!("krun_start_enter failed: {}", ret))
    }
}

#[cfg(target_os = "windows")]
fn start_krun(
    _id: &str,
    _bundle: &std::path::Path,
    _state: &mut ContainerState,
) -> Result<(), String> {
    Err("krun runtime not available on Windows".to_string())
}

fn cmd_state(id: String) -> Result<(), String> {
    let state = load_state(&id)?;
    let json = serde_json::to_string_pretty(&state).map_err(|e| format!("serialize: {}", e))?;
    println!("{}", json);
    Ok(())
}

fn cmd_kill(id: String, signal: String, _all: bool) -> Result<(), String> {
    let mut state = load_state(&id)?;

    if let Some(pid) = state.pid {
        let sig = match signal.to_uppercase().as_str() {
            "SIGTERM" | "TERM" | "15" => libc::SIGTERM,
            "SIGKILL" | "KILL" | "9" => libc::SIGKILL,
            "SIGINT" | "INT" | "2" => libc::SIGINT,
            "SIGHUP" | "HUP" | "1" => libc::SIGHUP,
            _ => return Err(format!("unknown signal: {}", signal)),
        };

        // SECURITY: Verify the process still belongs to this container before sending signal.
        // This mitigates PID reuse race conditions where the container exits and another
        // process reuses the PID between state read and signal delivery.
        if !verify_process_belongs_to_container(pid, &state.bundle) {
            eprintln!(
                "Warning: PID {} no longer belongs to container {}, skipping signal",
                pid, id
            );
        } else {
            // SAFETY: kill() is safe to call with a valid PID after verification
            let ret = unsafe { libc::kill(pid as i32, sig) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(format!("kill failed: {}", err));
                }
            }
        }
    }

    state.status = "stopped".to_string();
    state.pid = None;
    save_state(&state)?;

    eprintln!("Killed container {}", id);
    Ok(())
}

/// Verifies that a PID still belongs to a container by checking /proc/<pid>/cwd.
///
/// SECURITY: This reduces the race window for PID reuse attacks. If the process
/// has exited or its cwd no longer matches the bundle path, we skip signaling.
/// This is not foolproof but significantly reduces the attack surface.
fn verify_process_belongs_to_container(pid: u32, bundle: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let cwd_link = format!("/proc/{}/cwd", pid);
        match std::fs::read_link(&cwd_link) {
            Ok(cwd) => {
                // Check if the process cwd is within or matches the bundle path
                let cwd_str = cwd.to_string_lossy();
                cwd_str.starts_with(bundle) || bundle.starts_with(&*cwd_str)
            }
            Err(_) => false, // Process doesn't exist or we can't read it
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux, we can't verify - allow the signal but log a warning
        let _ = (pid, bundle);
        true
    }
}

fn cmd_delete(id: String, force: bool) -> Result<(), String> {
    let state = load_state(&id)?;

    if !force && state.status == "running" {
        return Err(format!(
            "container {} is running, use --force to delete",
            id
        ));
    }

    // Force kill if running
    if force && let Some(pid) = state.pid {
        // SAFETY: kill() is safe to call with a valid PID. We're sending SIGKILL
        // to terminate the container process. Note: there's a theoretical race
        // where the PID could have been reused, but --force is an explicit user
        // request to forcefully clean up, accepting this risk.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }

    delete_state(&id)?;
    eprintln!("Deleted container {}", id);
    Ok(())
}

fn cmd_list() -> Result<(), String> {
    let state_root = default_state_root();
    if !state_root.exists() {
        println!("ID\tSTATUS\tRUNTIME\tBUNDLE");
        return Ok(());
    }

    println!("ID\tSTATUS\tRUNTIME\tBUNDLE");
    if let Ok(entries) = std::fs::read_dir(&state_root) {
        for entry in entries.flatten() {
            if entry.path().is_dir()
                && let Some(id) = entry.file_name().to_str()
                && let Ok(state) = load_state(id)
            {
                println!(
                    "{}\t{}\t{}\t{}",
                    state.id, state.status, state.runtime, state.bundle
                );
            }
        }
    }
    Ok(())
}

fn cmd_version() {
    println!("magikrun version {}", env!("CARGO_PKG_VERSION"));
    println!("spec: {}", OCI_VERSION);
}

fn cmd_help() {
    println!(
        r#"magikrun - OCI Runtime for containers, WASM, and microVMs

USAGE:
    magikrun <command> [options]

COMMANDS:
    create <id> --bundle <path>  Create a container
    start <id>                   Start a created container
    state <id>                   Query container state (JSON)
    kill <id> [signal]           Send signal to container
    delete <id> [--force]        Delete a container
    list                         List all containers
    version                      Show version info
    help                         Show this help

OPTIONS:
    --bundle, -b <path>    Bundle directory (default: current dir)
    --runtime, -r <name>   Force runtime: native, wasm, krun
    --force, -f            Force operation

EXAMPLES:
    magikrun create myapp --bundle ./bundle
    magikrun start myapp
    magikrun kill myapp SIGTERM
    magikrun delete myapp
"#
    );
}

// =============================================================================
// Main
// =============================================================================

fn main() -> ExitCode {
    match parse_args() {
        Ok(cmd) => {
            let result = match cmd {
                Command::Create {
                    id,
                    bundle,
                    runtime,
                } => cmd_create(id, bundle, runtime),
                Command::Start { id } => cmd_start(id),
                Command::State { id } => cmd_state(id),
                Command::Kill { id, signal, all } => cmd_kill(id, signal, all),
                Command::Delete { id, force } => cmd_delete(id, force),
                Command::List => cmd_list(),
                Command::Version => {
                    cmd_version();
                    Ok(())
                }
                Command::Help => {
                    cmd_help();
                    Ok(())
                }
            };

            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("error: {}", e);
            cmd_help();
            ExitCode::FAILURE
        }
    }
}
