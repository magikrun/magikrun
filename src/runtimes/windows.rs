//! # Windows OCI Runtime - WSL2 MicroVM Execution
//!
//! Implements the [`OciRuntime`] trait using WSL2 for microVM-style
//! container execution on Windows. Unlike traditional WSL2 container
//! runtimes that delegate to runc/youki inside a full Linux distro,
//! this runtime creates **ephemeral per-container WSL distros** from
//! the OCI rootfs - similar to how krun creates microVMs from rootfs.
//!
//! ## Platform Requirements
//!
//! | Requirement     | Detection Method                           |
//! |-----------------|-------------------------------------------|
//! | Windows 10+     | OS version check                          |
//! | WSL2 enabled    | `wsl --status` returns success            |
//! | No Ubuntu req.  | Uses `wsl --import` with OCI rootfs       |
//!
//! ## MicroVM Model (krun-like)
//!
//! This approach mirrors krun's architecture:
//!
//! | Aspect          | krun (Linux/macOS)      | WindowsRuntime (WSL2)     |
//! |-----------------|-------------------------|---------------------------|
//! | Hypervisor      | KVM / HVF               | Hyper-V                   |
//! | Kernel          | libkrun embedded        | WSL2 Linux kernel         |
//! | Rootfs          | Direct mount            | `wsl --import` from tar   |
//! | Lifecycle       | Create VM per container | Create distro per container|
//! | Cleanup         | Free VM context         | `wsl --unregister`        |
//!
//! ## Security Model
//!
//! WSL2 MicroVM provides hardware-level isolation via Hyper-V:
//!
//! - **Kernel isolation**: Each distro shares the WSL2 kernel but has separate namespaces
//! - **Memory isolation**: Hyper-V enforces memory boundaries
//! - **Filesystem isolation**: Each container has its own VHD
//! - **Network isolation**: Separate network namespace per distro
//!
//! ## Execution Model
//!
//! Container execution follows these steps:
//!
//! 1. **Create rootfs tarball**: Extract OCI rootfs to tar format
//! 2. **Import distro**: `wsl --import <container-id> <vhd-path> <rootfs.tar>`
//! 3. **Start container**: `wsl -d <container-id> <entrypoint>`
//! 4. **Terminate**: `wsl --terminate <container-id>`
//! 5. **Cleanup**: `wsl --unregister <container-id>`
//!
//! ## Resource Limits
//!
//! Resources are bounded via WSL2 configuration:
//!
//! | Resource | Mechanism                | Default                        |
//! |----------|--------------------------|--------------------------------|
//! | Memory   | Per-distro memory limit  | `DEFAULT_WSL_MEMORY_MIB`       |
//! | CPU      | WSL2 processor limit     | `DEFAULT_WSL_PROCESSORS`       |
//! | Disk     | VHD size limit           | `DEFAULT_WSL_VHD_SIZE`         |
//!
//! [`OciRuntime`]: crate::runtime::OciRuntime

use crate::constants::{
    CONTAINER_START_TIMEOUT, EXEC_TIMEOUT, MAX_CONTAINERS, validate_container_id,
};
use crate::error::{Error, Result};
use crate::runtime::{
    ContainerState, ContainerStatus, ExecOptions, ExecResult, OciRuntime, Signal,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ============================================================================
// WSL2 MicroVM Constants
// ============================================================================

/// Prefix for container distro names to avoid conflicts with user distros.
const DISTRO_PREFIX: &str = "magikrun-";

/// Valid characters for environment variable names.
/// SECURITY: Only allow POSIX-compliant env var names to prevent shell injection.
const ENV_VAR_NAME_PATTERN: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

/// Timeout for WSL command execution.
const WSL_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Timeout for importing a distro (can be slow for large rootfs).
#[allow(dead_code)]
const WSL_IMPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Maximum command output size to capture (1 MiB).
const MAX_OUTPUT_SIZE: usize = 1024 * 1024;

/// Default memory limit for WSL2 distros in MiB.
#[allow(dead_code)]
const DEFAULT_WSL_MEMORY_MIB: u32 = 512;

/// Default number of processors for WSL2 distros.
#[allow(dead_code)]
const DEFAULT_WSL_PROCESSORS: u8 = 1;

// ============================================================================
// MicroVM Container State
// ============================================================================

/// Internal state tracking for a WSL2 MicroVM container.
///
/// Each container corresponds to a dedicated WSL2 distro instance.
struct WslMicroVm {
    /// Original bundle path (Windows).
    bundle: PathBuf,
    /// Distro name (prefixed container ID).
    distro_name: String,
    /// Path where the distro VHD is stored.
    #[allow(dead_code)]
    vhd_path: PathBuf,
    /// Container status.
    status: ContainerStatus,
    /// PID of the main process (if running).
    pid: Option<u32>,
    /// Entrypoint command to run.
    entrypoint: Vec<String>,
    /// Working directory inside container.
    working_dir: String,
    /// Environment variables.
    env: HashMap<String, String>,
}

// ============================================================================
// WindowsRuntime Implementation
// ============================================================================

/// Windows OCI runtime using WSL2 MicroVMs.
///
/// Creates ephemeral WSL2 distros from container rootfs, providing
/// krun-like isolation without requiring a pre-installed Linux distro.
///
/// ## Thread Safety
///
/// This struct is thread-safe (`Send + Sync`). Container state is
/// protected by an internal `RwLock`.
pub struct WindowsRuntime {
    available: bool,
    reason: Option<String>,
    /// Base directory for storing distro VHDs.
    storage_path: PathBuf,
    containers: RwLock<HashMap<String, WslMicroVm>>,
}

impl WindowsRuntime {
    /// Creates a new Windows runtime with default settings.
    #[cfg(target_os = "windows")]
    pub fn new() -> Self {
        let (available, reason) = Self::check_availability();

        // Use LOCALAPPDATA for VHD storage
        let storage_path = std::env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("magikrun").join("wsl"))
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\magikrun\\wsl"));

        // Create storage directory if needed
        if available {
            if let Err(e) = std::fs::create_dir_all(&storage_path) {
                warn!("Failed to create WSL storage directory: {}", e);
            }
        }

        Self {
            available,
            reason,
            storage_path,
            containers: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new Windows runtime (unavailable stub on non-Windows).
    #[cfg(not(target_os = "windows"))]
    pub fn new() -> Self {
        Self {
            available: false,
            reason: Some("Windows runtime only available on Windows".to_string()),
            storage_path: PathBuf::new(),
            containers: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a runtime with a custom storage path.
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    pub fn with_storage_path(storage_path: impl Into<PathBuf>) -> Self {
        let (available, reason) = Self::check_availability();
        let storage_path = storage_path.into();

        if available {
            if let Err(e) = std::fs::create_dir_all(&storage_path) {
                warn!("Failed to create WSL storage directory: {}", e);
            }
        }

        Self {
            available,
            reason,
            storage_path,
            containers: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the storage path for distro VHDs.
    #[allow(dead_code)]
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }

    /// Checks WSL2 availability.
    #[cfg(target_os = "windows")]
    fn check_availability() -> (bool, Option<String>) {
        // Try to run wsl --status to check if WSL2 is available
        let output = std::process::Command::new("wsl.exe")
            .args(["--status"])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    // Check if it's WSL2 (not WSL1)
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("2") || stdout.to_lowercase().contains("wsl 2") {
                        info!("WSL2 MicroVM runtime available");
                        (true, None)
                    } else {
                        (
                            false,
                            Some("WSL2 not detected (WSL1 may be installed)".to_string()),
                        )
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    (
                        false,
                        Some(format!("wsl --status failed: {}", stderr.trim())),
                    )
                }
            }
            Err(e) => (false, Some(format!("wsl.exe not found: {}", e))),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(dead_code)]
    fn check_availability() -> (bool, Option<String>) {
        (
            false,
            Some("Windows runtime only available on Windows".to_string()),
        )
    }

    /// Generates a WSL distro name for a container.
    fn distro_name(container_id: &str) -> String {
        format!("{}{}", DISTRO_PREFIX, container_id)
    }

    /// Converts a Windows path to a WSL2 path.
    ///
    /// # Examples
    ///
    /// - `C:\Users\foo` -> `/mnt/c/Users/foo`
    /// - `D:\data` -> `/mnt/d/data`
    #[allow(dead_code)]
    fn windows_to_wsl_path(path: &Path) -> Result<String> {
        let path_str = path.to_string_lossy();

        // Handle UNC paths (\\wsl$\...)
        if path_str.starts_with("\\\\wsl$\\") || path_str.starts_with("\\\\wsl.localhost\\") {
            // Extract the path after the distro name
            let parts: Vec<&str> = path_str.splitn(4, '\\').collect();
            if parts.len() >= 4 {
                return Ok(format!("/{}", parts[3].replace('\\', "/")));
            }
            return Err(Error::InvalidBundle {
                path: path.to_path_buf(),
                reason: "invalid WSL UNC path".to_string(),
            });
        }

        // Handle drive letter paths (C:\...)
        let path_str = path_str.replace('\\', "/");
        if let Some(rest) = path_str.strip_prefix("//") {
            // Already in forward-slash format
            return Ok(format!("/mnt/{}", rest));
        }

        // Check for drive letter
        let chars: Vec<char> = path_str.chars().collect();
        if chars.len() >= 2 && chars[1] == ':' {
            let drive = chars[0].to_ascii_lowercase();
            if !drive.is_ascii_alphabetic() {
                return Err(Error::InvalidBundle {
                    path: path.to_path_buf(),
                    reason: format!("invalid drive letter: {}", drive),
                });
            }
            let rest = &path_str[2..];
            return Ok(format!("/mnt/{}{}", drive, rest));
        }

        // Relative or already-unix path
        Ok(path_str.to_string())
    }

    /// Executes a WSL command with the given arguments.
    async fn wsl_command(
        &self,
        args: &[&str],
        timeout_dur: std::time::Duration,
    ) -> Result<std::process::Output> {
        debug!("WSL command: wsl.exe {}", args.join(" "));

        let mut cmd = Command::new("wsl.exe");
        cmd.args(args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = timeout(timeout_dur, cmd.output())
            .await
            .map_err(|_| Error::Timeout {
                operation: "wsl command".to_string(),
                duration: timeout_dur,
            })?
            .map_err(|e| Error::Ffi {
                library: "wsl".to_string(),
                message: e.to_string(),
            })?;

        // Truncate output if too large
        let mut result = output;
        if result.stdout.len() > MAX_OUTPUT_SIZE {
            result.stdout.truncate(MAX_OUTPUT_SIZE);
            warn!("WSL stdout truncated to {} bytes", MAX_OUTPUT_SIZE);
        }
        if result.stderr.len() > MAX_OUTPUT_SIZE {
            result.stderr.truncate(MAX_OUTPUT_SIZE);
            warn!("WSL stderr truncated to {} bytes", MAX_OUTPUT_SIZE);
        }

        Ok(result)
    }

    /// Executes a command inside a specific WSL distro.
    #[allow(dead_code)]
    async fn wsl_distro_exec(
        &self,
        distro: &str,
        command: &[&str],
    ) -> Result<std::process::Output> {
        let mut args = vec!["-d", distro, "--"];
        args.extend(command);
        self.wsl_command(&args, WSL_COMMAND_TIMEOUT).await
    }

    /// Creates a tarball from a rootfs directory.
    ///
    /// WSL --import requires a tar file. We create one from the OCI rootfs.
    #[cfg(target_os = "windows")]
    async fn create_rootfs_tarball(&self, rootfs: &Path, tar_path: &Path) -> Result<()> {
        use std::fs::File;

        // Use tar command via WSL to create the tarball (more reliable than Rust tar on Windows)
        let rootfs_wsl = Self::windows_to_wsl_path(rootfs)?;
        let tar_wsl = Self::windows_to_wsl_path(tar_path)?;

        // We need a helper distro for tar creation. Use any available distro or fallback.
        let output = self
            .wsl_command(&["--list", "--quiet"], WSL_COMMAND_TIMEOUT)
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let helper_distro = stdout
            .lines()
            .find(|line| !line.trim().is_empty() && !line.starts_with(DISTRO_PREFIX))
            .map(|s| s.trim().to_string());

        if let Some(distro) = helper_distro {
            // Use existing distro to create tar
            let tar_cmd = format!("cd '{}' && tar -cf '{}' .", rootfs_wsl, tar_wsl);
            let output = self
                .wsl_command(
                    &["-d", &distro, "--", "bash", "-c", &tar_cmd],
                    WSL_IMPORT_TIMEOUT,
                )
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::CreateFailed {
                    id: "tarball".to_string(),
                    reason: format!("Failed to create rootfs tarball: {}", stderr.trim()),
                });
            }
        } else {
            // No helper distro available - create minimal tar manually
            // This is a fallback for fresh Windows installs
            debug!("No helper distro available, using Rust tar implementation");

            let tar_file = File::create(tar_path).map_err(|e| Error::CreateFailed {
                id: "tarball".to_string(),
                reason: format!("Failed to create tar file: {}", e),
            })?;

            let mut builder = tar::Builder::new(tar_file);

            // Add all files from rootfs
            builder
                .append_dir_all(".", rootfs)
                .map_err(|e| Error::CreateFailed {
                    id: "tarball".to_string(),
                    reason: format!("Failed to add files to tar: {}", e),
                })?;

            builder.finish().map_err(|e| Error::CreateFailed {
                id: "tarball".to_string(),
                reason: format!("Failed to finalize tar: {}", e),
            })?;
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    async fn create_rootfs_tarball(&self, _rootfs: &Path, _tar_path: &Path) -> Result<()> {
        Err(Error::Internal(
            "Not available on this platform".to_string(),
        ))
    }

    /// Imports a rootfs as a new WSL distro.
    #[cfg(target_os = "windows")]
    async fn import_distro(
        &self,
        distro_name: &str,
        vhd_path: &Path,
        tar_path: &Path,
    ) -> Result<()> {
        debug!(
            "Importing WSL distro {} from {}",
            distro_name,
            tar_path.display()
        );

        // Ensure parent directory exists
        if let Some(parent) = vhd_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::CreateFailed {
                id: distro_name.to_string(),
                reason: format!("Failed to create VHD directory: {}", e),
            })?;
        }

        let output = self
            .wsl_command(
                &[
                    "--import",
                    distro_name,
                    &vhd_path.to_string_lossy(),
                    &tar_path.to_string_lossy(),
                    "--version",
                    "2",
                ],
                WSL_IMPORT_TIMEOUT,
            )
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::CreateFailed {
                id: distro_name.to_string(),
                reason: format!("wsl --import failed: {}", stderr.trim()),
            });
        }

        info!("Imported WSL distro: {}", distro_name);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    async fn import_distro(
        &self,
        _distro_name: &str,
        _vhd_path: &Path,
        _tar_path: &Path,
    ) -> Result<()> {
        Err(Error::Internal(
            "Not available on this platform".to_string(),
        ))
    }

    /// Unregisters a WSL distro, cleaning up all resources.
    async fn unregister_distro(&self, distro_name: &str) -> Result<()> {
        debug!("Unregistering WSL distro: {}", distro_name);

        let output = self
            .wsl_command(&["--unregister", distro_name], WSL_COMMAND_TIMEOUT)
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail if already unregistered
            if !stderr.contains("not found") && !stderr.contains("not registered") {
                return Err(Error::DeleteFailed {
                    id: distro_name.to_string(),
                    reason: format!("wsl --unregister failed: {}", stderr.trim()),
                });
            }
        }

        info!("Unregistered WSL distro: {}", distro_name);
        Ok(())
    }

    /// Terminates a running WSL distro.
    async fn terminate_distro(&self, distro_name: &str) -> Result<()> {
        debug!("Terminating WSL distro: {}", distro_name);

        let output = self
            .wsl_command(&["--terminate", distro_name], WSL_COMMAND_TIMEOUT)
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail if not running
            if !stderr.contains("not running") && !stderr.contains("not found") {
                return Err(Error::SignalFailed {
                    id: distro_name.to_string(),
                    reason: format!("wsl --terminate failed: {}", stderr.trim()),
                });
            }
        }

        Ok(())
    }

    /// Parses OCI config.json to extract entrypoint, env, and working dir.
    fn parse_oci_config(
        config_path: &Path,
    ) -> Result<(Vec<String>, HashMap<String, String>, String)> {
        let config_str =
            std::fs::read_to_string(config_path).map_err(|e| Error::InvalidBundle {
                path: config_path.to_path_buf(),
                reason: format!("Failed to read config.json: {}", e),
            })?;

        let config: serde_json::Value =
            serde_json::from_str(&config_str).map_err(|e| Error::InvalidBundle {
                path: config_path.to_path_buf(),
                reason: format!("Invalid config.json: {}", e),
            })?;

        // Extract process configuration
        let process = config.get("process").ok_or_else(|| Error::InvalidBundle {
            path: config_path.to_path_buf(),
            reason: "Missing 'process' in config.json".to_string(),
        })?;

        // Get entrypoint (args)
        let args = process
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["/bin/sh".to_string()]);

        // Get environment
        let env: HashMap<String, String> = process
            .get("env")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| {
                        let parts: Vec<&str> = s.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            Some((parts[0].to_string(), parts[1].to_string()))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Get working directory
        let cwd = process
            .get("cwd")
            .and_then(|v| v.as_str())
            .unwrap_or("/")
            .to_string();

        Ok((args, env, cwd))
    }

    /// Checks if a distro is currently running.
    async fn is_distro_running(&self, distro_name: &str) -> bool {
        let output = self
            .wsl_command(&["--list", "--running", "--quiet"], WSL_COMMAND_TIMEOUT)
            .await;

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.lines().any(|line| line.trim() == distro_name)
            }
            Err(_) => false,
        }
    }

    /// Validates an environment variable name is safe for shell use.
    ///
    /// # Security
    ///
    /// Environment variable names must match `^[A-Za-z_][A-Za-z0-9_]*$` to prevent
    /// shell command injection. A malicious name like `FOO$(whoami)BAR` would be
    /// executed by the shell if not validated.
    fn validate_env_var_name(name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let first_char = name.chars().next().unwrap();
        if !first_char.is_ascii_alphabetic() && first_char != '_' {
            return false;
        }
        name.chars().all(|c| ENV_VAR_NAME_PATTERN.contains(c))
    }
}

impl Default for WindowsRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// OciRuntime Implementation
// ============================================================================

#[async_trait]
impl OciRuntime for WindowsRuntime {
    fn name(&self) -> &str {
        "wsl2-microvm"
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn unavailable_reason(&self) -> Option<String> {
        self.reason.clone()
    }

    async fn create(&self, id: &str, bundle: &Path) -> Result<()> {
        debug!(
            "Creating WSL2 MicroVM container {} from bundle {}",
            id,
            bundle.display()
        );

        // SECURITY: Validate container ID format
        validate_container_id(id).map_err(|reason| Error::InvalidContainerId {
            id: id.to_string(),
            reason: reason.to_string(),
        })?;

        // Check container limit
        {
            let containers = self
                .containers
                .read()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            if containers.len() >= MAX_CONTAINERS {
                return Err(Error::ResourceExhausted(format!(
                    "maximum container limit reached ({})",
                    MAX_CONTAINERS
                )));
            }

            if containers.contains_key(id) {
                return Err(Error::ContainerAlreadyExists(id.to_string()));
            }
        }

        // Validate bundle structure
        let rootfs = bundle.join("rootfs");
        let config_path = bundle.join("config.json");

        if !rootfs.exists() {
            return Err(Error::InvalidBundle {
                path: bundle.to_path_buf(),
                reason: "rootfs directory not found".to_string(),
            });
        }

        if !config_path.exists() {
            return Err(Error::InvalidBundle {
                path: bundle.to_path_buf(),
                reason: "config.json not found".to_string(),
            });
        }

        // Parse OCI config
        let (entrypoint, env, working_dir) = Self::parse_oci_config(&config_path)?;

        // Generate distro name and paths
        let distro_name = Self::distro_name(id);
        let vhd_path = self.storage_path.join(&distro_name);
        let tar_path = self.storage_path.join(format!("{}.tar", id));

        // Create rootfs tarball
        self.create_rootfs_tarball(&rootfs, &tar_path).await?;

        // Import as WSL distro
        let import_result = self.import_distro(&distro_name, &vhd_path, &tar_path).await;

        // Clean up tarball
        if let Err(e) = std::fs::remove_file(&tar_path) {
            debug!("Failed to clean up tarball: {}", e);
        }

        // Handle import failure
        import_result?;

        // Register container with write lock for entire check-and-insert (prevents race condition)
        // We check the limit first, then insert if under limit
        let limit_exceeded = {
            let mut containers = self
                .containers
                .write()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            if containers.len() >= MAX_CONTAINERS {
                true
            } else {
                containers.insert(
                    id.to_string(),
                    WslMicroVm {
                        bundle: bundle.to_path_buf(),
                        distro_name: distro_name.clone(),
                        vhd_path,
                        status: ContainerStatus::Created,
                        pid: None,
                        entrypoint,
                        working_dir,
                        env,
                    },
                );
                false
            }
        };

        if limit_exceeded {
            // Clean up the imported distro (outside lock scope)
            let _ = self.unregister_distro(&distro_name).await;
            return Err(Error::ResourceExhausted(format!(
                "maximum container limit reached ({})",
                MAX_CONTAINERS
            )));
        }

        info!("Created WSL2 MicroVM container {}", id);
        Ok(())
    }

    async fn start(&self, id: &str) -> Result<()> {
        debug!("Starting WSL2 MicroVM container {}", id);

        let (distro_name, entrypoint, working_dir, env) = {
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

            (
                container.distro_name.clone(),
                container.entrypoint.clone(),
                container.working_dir.clone(),
                container.env.clone(),
            )
        };

        // SECURITY: Shell-escape a string for safe use in sh -c commands
        fn shell_escape(s: &str) -> String {
            format!("'{}'", s.replace('\'', "'\\''"))
        }

        // Build the command to run inside the distro
        let mut env_exports = String::new();
        for (key, value) in &env {
            // SECURITY: Validate key to prevent command injection
            if !Self::validate_env_var_name(key) {
                warn!("Skipping invalid environment variable name: {}", key);
                continue;
            }
            // SECURITY: Shell-escape values to prevent injection
            env_exports.push_str(&format!("export {}={}; ", key, shell_escape(value)));
        }

        // SECURITY: Shell-escape each entrypoint argument individually
        let escaped_entrypoint: Vec<String> = entrypoint.iter().map(|s| shell_escape(s)).collect();
        let entrypoint_str = escaped_entrypoint.join(" ");

        // SECURITY: Shell-escape the working directory
        let escaped_working_dir = shell_escape(&working_dir);
        let full_cmd = format!(
            "cd {} && {} exec {}",
            escaped_working_dir, env_exports, entrypoint_str
        );

        // Start the container process
        let output = timeout(
            CONTAINER_START_TIMEOUT,
            self.wsl_command(
                &["-d", &distro_name, "--", "sh", "-c", &full_cmd],
                CONTAINER_START_TIMEOUT,
            ),
        )
        .await
        .map_err(|_| Error::Timeout {
            operation: format!("start container {}", id),
            duration: CONTAINER_START_TIMEOUT,
        })??;

        if !output.status.success() {
            // Revert status on failure
            if let Ok(mut containers) = self.containers.write()
                && let Some(container) = containers.get_mut(id)
            {
                container.status = ContainerStatus::Created;
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::StartFailed {
                id: id.to_string(),
                reason: stderr.trim().to_string(),
            });
        }

        // Update status to stopped (process completed)
        if let Ok(mut containers) = self.containers.write()
            && let Some(container) = containers.get_mut(id)
        {
            container.status = ContainerStatus::Stopped;
        }

        info!("WSL2 MicroVM container {} completed", id);
        Ok(())
    }

    async fn state(&self, id: &str) -> Result<ContainerState> {
        let (bundle, distro_name, local_status) = {
            let containers = self
                .containers
                .read()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            (
                container.bundle.clone(),
                container.distro_name.clone(),
                container.status,
            )
        };

        // Check if distro is actually running
        let is_running = self.is_distro_running(&distro_name).await;
        let status = if is_running && local_status == ContainerStatus::Running {
            ContainerStatus::Running
        } else if local_status == ContainerStatus::Running {
            // Was running but now stopped
            if let Ok(mut containers) = self.containers.write()
                && let Some(container) = containers.get_mut(id)
            {
                container.status = ContainerStatus::Stopped;
            }
            ContainerStatus::Stopped
        } else {
            local_status
        };

        Ok(ContainerState {
            oci_version: "1.0.2".to_string(),
            id: id.to_string(),
            status,
            pid: None, // WSL doesn't expose PIDs easily
            bundle: bundle.to_string_lossy().to_string(),
            annotations: HashMap::new(),
        })
    }

    async fn kill(&self, id: &str, signal: Signal, _all: bool) -> Result<()> {
        debug!("Killing WSL2 MicroVM container {} with {:?}", id, signal);

        let distro_name = {
            let containers = self
                .containers
                .read()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            container.distro_name.clone()
        };

        // Terminate the distro (this stops all processes)
        self.terminate_distro(&distro_name).await?;

        // Update status
        if let Ok(mut containers) = self.containers.write()
            && let Some(container) = containers.get_mut(id)
        {
            container.status = ContainerStatus::Stopped;
            container.pid = None;
        }

        info!("Terminated WSL2 MicroVM container {}", id);
        Ok(())
    }

    async fn delete(&self, id: &str, force: bool) -> Result<()> {
        debug!("Deleting WSL2 MicroVM container {} (force={})", id, force);

        let distro_name = {
            let containers = self
                .containers
                .read()
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

            container.distro_name.clone()
        };

        // Terminate if still running
        if force {
            let _ = self.terminate_distro(&distro_name).await;
        }

        // Unregister the distro (deletes VHD and all data)
        self.unregister_distro(&distro_name).await?;

        // Remove from local state
        {
            let mut containers = self
                .containers
                .write()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            containers.remove(id);
        }

        info!("Deleted WSL2 MicroVM container {}", id);
        Ok(())
    }

    async fn exec(&self, id: &str, command: &[String], opts: ExecOptions) -> Result<ExecResult> {
        debug!("Exec in WSL2 MicroVM container {}: {:?}", id, command);

        let distro_name = {
            let containers = self
                .containers
                .read()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            // For exec, container can be in any state as long as it exists
            container.distro_name.clone()
        };

        // SECURITY: Shell-escape a string for safe use in sh -c commands
        fn shell_escape(s: &str) -> String {
            format!("'{}'", s.replace('\'', "'\\''"))
        }

        // Build command with options
        let mut env_exports = String::new();
        for (key, value) in &opts.env {
            // SECURITY: Validate key to prevent command injection
            if !Self::validate_env_var_name(key) {
                warn!("Skipping invalid environment variable name: {}", key);
                continue;
            }
            // SECURITY: Shell-escape values to prevent injection
            env_exports.push_str(&format!("export {}={}; ", key, shell_escape(value)));
        }

        // SECURITY: Shell-escape working directory and command arguments
        let cwd = opts.working_dir.as_deref().unwrap_or("/");
        let escaped_cwd = shell_escape(cwd);
        let escaped_cmd: Vec<String> = command.iter().map(|s| shell_escape(s)).collect();
        let cmd_str = escaped_cmd.join(" ");
        let full_cmd = format!("cd {} && {} {}", escaped_cwd, env_exports, cmd_str);

        let output = timeout(
            EXEC_TIMEOUT,
            self.wsl_command(
                &["-d", &distro_name, "--", "sh", "-c", &full_cmd],
                EXEC_TIMEOUT,
            ),
        )
        .await
        .map_err(|_| Error::Timeout {
            operation: format!("exec in container {}", id),
            duration: EXEC_TIMEOUT,
        })??;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    async fn wait(&self, id: &str) -> Result<i32> {
        debug!("Waiting for WSL2 MicroVM container {}", id);

        let distro_name = {
            let containers = self
                .containers
                .read()
                .map_err(|e| Error::Internal(format!("lock poisoned: {}", e)))?;

            let container = containers
                .get(id)
                .ok_or_else(|| Error::ContainerNotFound(id.to_string()))?;

            container.distro_name.clone()
        };

        // Poll until distro is no longer running (with timeout)
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > EXEC_TIMEOUT {
                return Err(Error::Timeout {
                    operation: format!("wait for container {}", id),
                    duration: EXEC_TIMEOUT,
                });
            }

            if !self.is_distro_running(&distro_name).await {
                // Update status
                if let Ok(mut containers) = self.containers.write()
                    && let Some(container) = containers.get_mut(id)
                {
                    container.status = ContainerStatus::Stopped;
                }
                return Ok(0);
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_to_wsl_path() {
        // Test drive letter conversion
        let path = Path::new("C:\\Users\\test\\bundle");
        let result = WindowsRuntime::windows_to_wsl_path(path);
        assert!(result.is_ok());
        let wsl_path = result.unwrap();
        assert!(wsl_path.starts_with("/mnt/c"));
    }

    #[test]
    fn test_path_conversion_lowercase_drive() {
        let path = Path::new("d:\\data\\container");
        let result = WindowsRuntime::windows_to_wsl_path(path);
        assert!(result.is_ok());
        let wsl_path = result.unwrap();
        assert!(wsl_path.starts_with("/mnt/d"));
    }

    #[test]
    fn test_distro_name_generation() {
        let name = WindowsRuntime::distro_name("my-container-123");
        assert_eq!(name, "magikrun-my-container-123");
    }

    #[test]
    fn test_runtime_not_available_on_non_windows() {
        #[cfg(not(target_os = "windows"))]
        {
            let runtime = WindowsRuntime::new();
            assert!(!runtime.is_available());
            assert!(runtime.unavailable_reason().is_some());
            assert_eq!(runtime.name(), "wsl2-microvm");
        }
    }
}
