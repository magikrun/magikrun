//! OCI Runtime trait - pure OCI Runtime Spec compliant interface.
//!
//! This trait defines the standard OCI container lifecycle operations:
//! - `create`: Create a container from an OCI bundle
//! - `start`: Start a created container
//! - `state`: Get container state
//! - `kill`: Send signal to container
//! - `delete`: Remove a container
//!
//! # OCI Runtime Spec Reference
//!
//! See: https://github.com/opencontainers/runtime-spec/blob/main/runtime.md
//!
//! # No Pod Semantics
//!
//! This trait intentionally excludes pod concepts (sandboxes, shared namespaces).
//! Those are handled by the `magik-pod` crate which uses this trait for
//! individual container operations.

use crate::error::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// =============================================================================
// Container State (OCI Runtime Spec)
// =============================================================================

/// OCI Runtime Spec container status.
///
/// Ref: https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state
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
/// Ref: https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state
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

/// Signal to send to a container.
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

    /// Parses from signal name (e.g., "SIGTERM", "TERM", "15").
    pub fn from_str(s: &str) -> Option<Self> {
        let s = s.to_uppercase();
        let s = s.strip_prefix("SIG").unwrap_or(&s);
        match s {
            "TERM" | "15" => Some(Self::Term),
            "KILL" | "9" => Some(Self::Kill),
            "HUP" | "1" => Some(Self::Hup),
            "INT" | "2" => Some(Self::Int),
            "USR1" | "10" => Some(Self::Usr1),
            "USR2" | "12" => Some(Self::Usr2),
            _ => None,
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

/// Result of command execution.
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
/// - `YoukiRuntime`: Linux containers via libcontainer
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
    async fn exec(
        &self,
        id: &str,
        command: &[String],
        opts: ExecOptions,
    ) -> Result<ExecResult> {
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
        assert_eq!(Signal::from_str("SIGTERM"), Some(Signal::Term));
        assert_eq!(Signal::from_str("TERM"), Some(Signal::Term));
        assert_eq!(Signal::from_str("15"), Some(Signal::Term));
        assert_eq!(Signal::from_str("sigkill"), Some(Signal::Kill));
        assert_eq!(Signal::from_str("9"), Some(Signal::Kill));
        assert_eq!(Signal::from_str("INVALID"), None);
    }

    #[test]
    fn test_container_state() {
        let state = ContainerState::new("test-container", "/path/to/bundle", ContainerStatus::Running);
        assert!(state.is_running());
        assert_eq!(state.id, "test-container");
        assert_eq!(state.oci_version, "1.0.2");
    }
}
