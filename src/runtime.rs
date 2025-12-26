//! # OCI Runtime Trait - Pure OCI Runtime Spec Compliant Interface
//!
//! This is the **runtime facade module** for magikrun, providing:
//!
//! - **OciRuntime trait**: Standard container lifecycle (create/start/kill/delete)
//! - **ContainerState/ContainerStatus**: Container state machine types
//! - **Signal**: POSIX signals for container processes
//! - **Runtime implementations**: NativeRuntime, WasmtimeRuntime, KrunRuntime
//!
//! ## Operations
//!
//! The OCI Runtime Spec defines five core operations:
//!
//! | Operation | Input                 | Effect                              |
//! |-----------|-----------------------|-------------------------------------|
//! | `create`  | container ID, bundle  | Sets up container without starting  |
//! | `start`   | container ID          | Executes the container process      |
//! | `state`   | container ID          | Returns current container state     |
//! | `kill`    | container ID, signal  | Sends signal to container process   |
//! | `delete`  | container ID          | Removes container resources         |
//!
//! ## Container State Machine
//!
//! ```text
//!                         create()
//!     ┌─────────────────────────────────────────────────────────────┐
//!     │                                                             │
//!     ▼                        start()                              │
//!   ┌───────────┐                                ┌───────────┐      │
//!   │  Creating  │ ───────► ┌─────────┐ ───────► │  Running  │      │
//!   └───────────┘           │ Created │          └─────┬─────┘      │
//!                           └────┬────┘                │            │
//!                                │                     │ kill()     │
//!                                │ delete()            │            │
//!                                │ (if created)        ▼            │
//!                                │              ┌───────────┐       │
//!                                └────────────► │  Stopped  │ ──────┘
//!                                 delete()      └───────────┘
//! ```
//!
//! ## No Pod Semantics
//!
//! This trait intentionally excludes pod-level concepts:
//! - No sandbox creation
//! - No shared namespace configuration
//! - No pause container management
//!
//! Each container is independent. Pod orchestration is handled by the
//! `magikpod` crate, which uses this trait for individual container ops.
//!
//! ## Implementation Requirements
//!
//! Implementations MUST:
//!
//! 1. **Validate inputs**: Check bundle structure before `create()`
//! 2. **Enforce state machine**: Reject operations in wrong state
//! 3. **Handle signals correctly**: Map [`Signal`] to platform signals
//! 4. **Clean up on delete**: Remove all container resources
//! 5. **Report accurate state**: Never return stale [`ContainerStatus`]
//!
//! Implementations SHOULD:
//!
//! 1. Support `exec()` for debugging (optional per spec)
//! 2. Support `wait()` for blocking until exit
//! 3. Include container PID in state when running
//!
//! ## Implementations
//!
//! This crate provides four implementations:
//!
//! | Runtime            | Platform       | Isolation          | Use Case            |
//! |--------------------|----------------|--------------------|---------------------|
//! | [`NativeRuntime`]  | Linux only     | Namespaces+cgroups | Production containers|
//! | [`WasmtimeRuntime`]| Cross-platform | WASM sandbox       | Portable plugins    |
//! | [`KrunRuntime`]    | Linux/macOS    | Hardware VM        | Untrusted workloads |
//! | [`WindowsRuntime`] | Windows only   | WSL2 MicroVM       | Linux on Windows    |

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// =============================================================================
// Re-exports (unified runtime API surface)
// =============================================================================

// Error types
pub use crate::error::{Error, Result};

// Runtime implementations
pub use crate::runtimes::{
    KrunRuntime, NativeRuntime, RuntimeRegistry, WasmtimeRuntime, WindowsRuntime,
};

// Security constants for runtime configuration (public API for consumers)
pub use crate::constants::{
    // Timeouts
    CONTAINER_START_TIMEOUT, DEFAULT_GRACE_PERIOD, EXEC_TIMEOUT,
    // Container resource limits
    DEFAULT_CPU_SHARES, DEFAULT_MEMORY_BYTES, MAX_CONTAINERS, MAX_MEMORY_BYTES, MAX_PIDS,
    // MicroVM limits
    DEFAULT_VCPUS, DEFAULT_VM_MEMORY_MIB, MAX_VCPUS, MAX_VM_MEMORY_MIB,
    // WASM limits
    DEFAULT_WASM_FUEL, MAX_WASM_MODULE_SIZE, MAX_WASM_MEMORY_PAGES,
    // OCI spec version
    OCI_RUNTIME_SPEC_VERSION,
    // Container ID validation
    CONTAINER_NAME_VALID_CHARS, MAX_CONTAINER_ID_LEN,
    // Storage paths
    CONTAINER_STATE_DIR, VM_STATE_DIR,
    // Validation helper
    validate_container_id,
};

// =============================================================================
// Container State (OCI Runtime Spec)
// =============================================================================

/// OCI Runtime Spec container status.
///
/// Represents the lifecycle state of a container. Transitions are strictly
/// controlled by runtime operations.
///
/// ## State Transitions
///
/// | Current   | Operation | Next      | Notes                          |
/// |-----------|-----------|-----------|--------------------------------|
/// | (none)    | create()  | Creating  | Transient during setup         |
/// | Creating  | (finish)  | Created   | Automatic on success           |
/// | Created   | start()   | Running   | Executes container process     |
/// | Created   | delete()  | (deleted) | Remove without running         |
/// | Running   | kill()    | Stopped   | Process terminated             |
/// | Running   | (exit)    | Stopped   | Natural process exit           |
/// | Stopped   | delete()  | (deleted) | Final cleanup                  |
///
/// ## Serialization
///
/// Serializes to lowercase strings per OCI spec: `creating`, `created`,
/// `running`, `stopped`.
///
/// Ref: <https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    /// Container is being created.
    Creating,
    /// Container has been created but not started.
    Created,
    /// Container is running.
    Running,
    /// Container has stopped.
    Stopped,
}

impl std::fmt::Display for ContainerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "creating"),
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

/// OCI Runtime Spec container state.
///
/// Returned by the `state()` operation. Contains all information needed
/// to identify and interact with a container.
///
/// ## Fields
///
/// | Field        | Required | Description                              |
/// |--------------|----------|------------------------------------------|
/// | `oci_version`| Yes      | OCI Runtime Spec version (e.g., "1.0.2") |
/// | `id`         | Yes      | Container identifier                     |
/// | `status`     | Yes      | Current lifecycle status                 |
/// | `pid`        | No       | Host PID of container init process       |
/// | `bundle`     | Yes      | Absolute path to OCI bundle              |
/// | `annotations`| Yes      | Arbitrary key-value metadata             |
///
/// ## PID Field
///
/// The `pid` field is only present when `status` is `Running`. It refers
/// to the container's init process PID on the host. For VMs and WASM,
/// this may be `None` even when running.
///
/// Ref: <https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerState {
    /// OCI version of the state schema.
    pub oci_version: String,
    /// Container ID.
    pub id: String,
    /// Container status.
    pub status: ContainerStatus,
    /// Process ID of the container (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Absolute path to the bundle directory.
    pub bundle: String,
    /// Annotations from the container config.
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

impl ContainerState {
    /// Creates a new container state.
    pub fn new(id: impl Into<String>, bundle: impl Into<String>, status: ContainerStatus) -> Self {
        Self {
            oci_version: "1.0.2".to_string(),
            id: id.into(),
            status,
            pid: None,
            bundle: bundle.into(),
            annotations: HashMap::new(),
        }
    }

    /// Returns true if the container is running.
    pub fn is_running(&self) -> bool {
        self.status == ContainerStatus::Running
    }
}

// =============================================================================
// Signals
// =============================================================================

/// Signal to send to a container process.
///
/// Represents standard POSIX signals that can be delivered to container
/// processes. Not all signals are meaningful for all runtimes:
///
/// | Runtime   | Signal Support                              |
/// |-----------|---------------------------------------------|
/// | NativeRuntime | Full POSIX signal semantics               |
/// | WasmtimeRuntime | Kill only (marks as stopped)           |
/// | KrunRuntime | Kill only (frees VM context)              |
///
/// ## Signal Numbers
///
/// Signal numbers are platform-specific. Use [`Signal::as_i32`] to get
/// the correct value for the current platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// SIGTERM (graceful shutdown).
    Term,
    /// SIGKILL (force kill).
    Kill,
    /// SIGHUP (hangup).
    Hup,
    /// SIGINT (interrupt).
    Int,
    /// SIGUSR1.
    Usr1,
    /// SIGUSR2.
    Usr2,
}

impl Signal {
    /// Returns the signal number.
    #[cfg(unix)]
    pub fn as_i32(&self) -> i32 {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
            Self::Hup => libc::SIGHUP,
            Self::Int => libc::SIGINT,
            Self::Usr1 => libc::SIGUSR1,
            Self::Usr2 => libc::SIGUSR2,
        }
    }

    #[cfg(not(unix))]
    pub fn as_i32(&self) -> i32 {
        match self {
            Self::Term => 15,
            Self::Kill => 9,
            Self::Hup => 1,
            Self::Int => 2,
            Self::Usr1 => 10,
            Self::Usr2 => 12,
        }
    }
}

impl std::str::FromStr for Signal {
    type Err = ();

    /// Parses from signal name (e.g., "SIGTERM", "TERM", "15").
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.to_uppercase();
        let s = s.strip_prefix("SIG").unwrap_or(&s);
        match s {
            "TERM" | "15" => Ok(Self::Term),
            "KILL" | "9" => Ok(Self::Kill),
            "HUP" | "1" => Ok(Self::Hup),
            "INT" | "2" => Ok(Self::Int),
            "USR1" | "10" => Ok(Self::Usr1),
            "USR2" | "12" => Ok(Self::Usr2),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Term => write!(f, "SIGTERM"),
            Self::Kill => write!(f, "SIGKILL"),
            Self::Hup => write!(f, "SIGHUP"),
            Self::Int => write!(f, "SIGINT"),
            Self::Usr1 => write!(f, "SIGUSR1"),
            Self::Usr2 => write!(f, "SIGUSR2"),
        }
    }
}

// =============================================================================
// Exec Options
// =============================================================================

/// Options for executing a command in a running container.
///
/// Used with the optional [`OciRuntime::exec`] operation to run additional
/// processes inside an existing container.
///
/// ## Support Matrix
///
/// | Runtime   | exec() support | TTY support |
/// |-----------|----------------|-------------|
/// | NativeRuntime | Yes         | Yes         |
/// | WasmtimeRuntime | No       | N/A         |
/// | KrunRuntime | No           | N/A         |
///
/// ## Example
///
/// ```rust,ignore
/// let opts = ExecOptions {
///     stdout: true,
///     stderr: true,
///     env: vec![("DEBUG".to_string(), "1".to_string())],
///     ..Default::default()
/// };
///
/// let result = runtime.exec("container-id", &["ls", "-la"], opts).await?;
/// println!("Exit code: {}", result.exit_code);
/// ```
///
/// [`OciRuntime::exec`]: crate::runtime::OciRuntime::exec
#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    /// Attach to stdin.
    pub stdin: bool,
    /// Attach to stdout.
    pub stdout: bool,
    /// Attach to stderr.
    pub stderr: bool,
    /// Allocate TTY.
    pub tty: bool,
    /// Environment variables to add.
    pub env: Vec<(String, String)>,
    /// Working directory override.
    pub working_dir: Option<String>,
    /// Run as user (uid or username).
    pub user: Option<String>,
    /// Run as group (gid or groupname).
    pub group: Option<String>,
}

/// Result of command execution in a container.
///
/// Contains the exit code and captured output streams from an `exec()`
/// operation.
///
/// ## Exit Codes
///
/// | Code | Meaning                      |
/// |------|------------------------------|
/// | 0    | Success                      |
/// | 1-125| Application error            |
/// | 126  | Command not executable       |
/// | 127  | Command not found            |
/// | 128+N| Killed by signal N           |
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Exit code of the command.
    pub exit_code: i32,
    /// Standard output (if captured).
    pub stdout: Vec<u8>,
    /// Standard error (if captured).
    pub stderr: Vec<u8>,
}

impl ExecResult {
    /// Creates a successful result.
    pub fn success() -> Self {
        Self {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    /// Returns true if the command succeeded (exit code 0).
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

// =============================================================================
// OCI Runtime Trait
// =============================================================================

/// OCI Runtime Spec compliant container runtime interface.
///
/// This trait defines the standard OCI runtime operations for a single
/// container. It does NOT include pod concepts - those are handled by
/// the higher-level `magik-pod` crate.
///
/// # Lifecycle
///
/// ```text
/// create(id, bundle) → start(id) → [exec(id, ...)] → kill(id, signal) → delete(id)
/// ```
///
/// # Implementations
///
/// - `NativeRuntime`: Linux containers via libcontainer
/// - `WasmtimeRuntime`: WebAssembly modules via wasmtime
/// - `KrunRuntime`: MicroVMs via libkrun
#[async_trait]
pub trait OciRuntime: Send + Sync {
    /// Returns the runtime name.
    fn name(&self) -> &str;

    /// Checks if this runtime is available on the current platform.
    fn is_available(&self) -> bool;

    /// Returns the reason why this runtime is unavailable (if any).
    fn unavailable_reason(&self) -> Option<String>;

    // =========================================================================
    // OCI Runtime Spec Operations
    // =========================================================================

    /// Creates a container from an OCI bundle.
    ///
    /// The container is created but not started. The bundle must contain
    /// a valid `config.json` and rootfs.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique container identifier
    /// * `bundle` - Path to the OCI runtime bundle directory
    ///
    /// # OCI Spec Reference
    ///
    /// This corresponds to `create <container-id> -b <bundle>`.
    async fn create(&self, id: &str, bundle: &Path) -> Result<()>;

    /// Starts a created container.
    ///
    /// The container must have been created with `create()` first.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    ///
    /// # OCI Spec Reference
    ///
    /// This corresponds to `start <container-id>`.
    async fn start(&self, id: &str) -> Result<()>;

    /// Gets the state of a container.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    ///
    /// # Returns
    ///
    /// Container state including status, PID, and bundle path.
    ///
    /// # OCI Spec Reference
    ///
    /// This corresponds to `state <container-id>`.
    async fn state(&self, id: &str) -> Result<ContainerState>;

    /// Sends a signal to a container.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    /// * `signal` - Signal to send
    /// * `all` - If true, signal all processes in the container
    ///
    /// # OCI Spec Reference
    ///
    /// This corresponds to `kill <container-id> <signal>`.
    async fn kill(&self, id: &str, signal: Signal, all: bool) -> Result<()>;

    /// Deletes a container.
    ///
    /// The container must be stopped before deletion unless `force` is true.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    /// * `force` - If true, force deletion even if running
    ///
    /// # OCI Spec Reference
    ///
    /// This corresponds to `delete <container-id>`.
    async fn delete(&self, id: &str, force: bool) -> Result<()>;

    // =========================================================================
    // Optional Operations
    // =========================================================================

    /// Executes a command in a running container.
    ///
    /// This is an optional operation - not all runtimes support it.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    /// * `command` - Command and arguments to run
    /// * `opts` - Execution options (env, user, tty, etc.)
    async fn exec(&self, id: &str, command: &[String], opts: ExecOptions) -> Result<ExecResult> {
        let _ = (id, command, opts);
        Err(crate::error::Error::NotSupported(format!(
            "exec not supported by {} runtime",
            self.name()
        )))
    }

    /// Waits for a container to exit.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    ///
    /// # Returns
    ///
    /// Exit code of the container's main process.
    async fn wait(&self, id: &str) -> Result<i32> {
        let _ = id;
        Err(crate::error::Error::NotSupported(format!(
            "wait not supported by {} runtime",
            self.name()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_parsing() {
        assert_eq!("SIGTERM".parse::<Signal>(), Ok(Signal::Term));
        assert_eq!("TERM".parse::<Signal>(), Ok(Signal::Term));
        assert_eq!("15".parse::<Signal>(), Ok(Signal::Term));
        assert_eq!("sigkill".parse::<Signal>(), Ok(Signal::Kill));
        assert_eq!("9".parse::<Signal>(), Ok(Signal::Kill));
        assert!("INVALID".parse::<Signal>().is_err());
    }

    #[test]
    fn test_container_state() {
        let state = ContainerState::new(
            "test-container",
            "/path/to/bundle",
            ContainerStatus::Running,
        );
        assert!(state.is_running());
        assert_eq!(state.id, "test-container");
        assert_eq!(state.oci_version, "1.0.2");
    }
}
