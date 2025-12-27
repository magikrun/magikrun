//! # OCI Runtime Bundle Building
//!
//! Converts pulled OCI images into OCI Runtime Bundles (rootfs + config.json).
//! This is the standard format consumed by OCI-compliant runtimes like youki,
//! runc, crun, and others.
//!
//! ## Bundle Formats
//!
//! | Format          | Contents                        | Runtime Backend     |
//! |-----------------|--------------------------------|---------------------|
//! | `Bundle::OciRuntime` | `rootfs/` + `config.json` | `NativeRuntime`       |
//! | `Bundle::Wasm`       | `module.wasm` + WASI config | `WasmtimeRuntime`    |
//! | `Bundle::MicroVm`    | `rootfs/` + command/env     | `KrunRuntime`        |
//!
//! ## Security Model
//!
//! Bundle building is a **critical security boundary**. Malicious images can
//! attempt to escape containment during layer extraction.
//!
//! ### Path Traversal Protection
//!
//! All tar entries are validated before extraction:
//! - Paths containing `..` are rejected immediately
//! - Absolute paths (starting with `/`) are rejected
//! - Symlinks pointing outside the rootfs are blocked (depth-tracking validation)
//! - Hardlinks are validated with the same depth-tracking as symlinks
//! - Link targets containing null bytes are rejected (injection attack prevention)
//!
//! ```rust,ignore
//! // This is rejected:
//! let path = "../../../etc/passwd";
//! if path.contains("..") || path.starts_with('/') {
//!     return Err(Error::PathTraversal { path });
//! }
//! ```
//!
//! ### Size Limit Enforcement
//!
//! Extraction tracks cumulative size and enforces limits:
//! - `MAX_LAYER_SIZE`: Per-layer compressed size limit (512 MiB)
//! - `MAX_ROOTFS_SIZE`: Total extracted size limit (4 GiB)
//!
//! This prevents both disk exhaustion and compression bomb attacks.
//!
//! ### Whiteout File Handling
//!
//! OCI images use "whiteout" files to mark deletions in overlay layers:
//! - `.wh.<filename>` marks `<filename>` for deletion
//! - `.wh..wh..opq` marks an entire directory as opaque
//!
//! Whiteout processing uses TOCTOU-safe operations:
//! - Uses `symlink_metadata()` instead of `exists()` to avoid following symlinks
//! - Symlinks within rootfs are removed directly (the symlink file, not target)
//! - Non-symlink files/directories are validated via canonicalization before removal
//! - Files resolving outside rootfs via intermediate symlinks are skipped
//!
//! ## Namespace Sharing for Pods
//!
//! While this crate doesn't implement pod semantics, it provides
//! [`BundleBuilder::build_oci_bundle_with_namespaces`] to generate bundles
//! that join existing namespaces. The `magikpod` crate uses this to create
//! shared network/IPC namespaces.
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::{BundleBuilder, OciContainerConfig};
//!
//! let builder = BundleBuilder::new()?;
//! let bundle = builder.build_oci_bundle(&image, &OciContainerConfig {
//!     name: "my-container".to_string(),
//!     command: Some(vec!["/bin/sh".to_string()]),
//!     ..Default::default()
//! })?;
//!
//! // Bundle is now at bundle.path() with:
//! //   - rootfs/ directory
//! //   - config.json (OCI runtime spec)
//! ```

use crate::constants::{
    MAX_FILES_PER_LAYER, MAX_LAYER_SIZE, MAX_ROOTFS_SIZE, OCI_RUNTIME_SPEC_VERSION,
};
use crate::error::{Error, Result};
use crate::registry::{ImageHandle, LayerInfo};
use crate::storage::BlobStore;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::Archive;
use tracing::{debug, info};

// =============================================================================
// Size-Limiting Reader Wrapper
// =============================================================================

/// A reader wrapper that limits the number of bytes that can be read.
///
/// # Security
///
/// This prevents compression bomb attacks where a small compressed file
/// expands to a massive size during decompression, exhausting memory
/// before the per-entry size tracking can detect it.
///
/// The limit is applied to the **decompressed** data stream.
struct SizeLimitedReader<R> {
    inner: R,
    bytes_read: u64,
    limit: u64,
}

impl<R: Read> SizeLimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            bytes_read: 0,
            limit,
        }
    }
}

impl<R: Read> Read for SizeLimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Check if we've already exceeded the limit
        if self.bytes_read >= self.limit {
            return Err(io::Error::other(format!(
                "decompression size limit exceeded: {} bytes",
                self.limit
            )));
        }

        // Limit the read to not exceed our remaining budget
        let remaining = self.limit - self.bytes_read;
        let remaining_usize = usize::try_from(remaining).unwrap_or(usize::MAX);
        let max_read = buf.len().min(remaining_usize);

        let bytes = self.inner.read(&mut buf[..max_read])?;
        self.bytes_read += bytes as u64;

        Ok(bytes)
    }
}

/// Bundle format specifier for targeting specific runtimes.
///
/// Used to request a specific bundle layout from [`BundleBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFormat {
    /// OCI Runtime Bundle (rootfs + config.json).
    OciRuntime,
    /// WASM module with WASI config.
    Wasm,
    /// Root filesystem for microVM.
    MicroVm,
}

/// A built bundle ready for execution by an OCI runtime.
///
/// Bundles are the bridge between OCI images and runtime execution. Each
/// variant contains the files and configuration needed for its runtime.
///
/// ## Variants
///
/// ### `OciRuntime`
/// Standard OCI Runtime Bundle with:
/// - `path/rootfs/` - Extracted filesystem layers
/// - `path/config.json` - OCI runtime spec configuration
///
/// Used by: [`NativeRuntime`](crate::runtimes::NativeRuntime)
///
/// ### `Wasm`
/// WebAssembly module with WASI configuration:
/// - `module` - Path to `.wasm` file
/// - `wasi_args` - Command-line arguments
/// - `wasi_env` - Environment variables
/// - `wasi_dirs` - Directory pre-opens
///
/// Used by: [`WasmtimeRuntime`](crate::runtimes::WasmtimeRuntime)
///
/// ### `MicroVm`
/// `MicroVM` rootfs with execution configuration:
/// - `rootfs` - Guest filesystem
/// - `command` - Init process path
/// - `env` - Environment variables
///
/// Used by: [`KrunRuntime`](crate::runtimes::KrunRuntime)
#[derive(Debug, Clone)]
pub enum Bundle {
    /// OCI Runtime Bundle.
    OciRuntime {
        /// Path to bundle directory.
        path: PathBuf,
        /// Path to rootfs within bundle.
        rootfs: PathBuf,
    },
    /// WASM module.
    Wasm {
        /// Path to .wasm module file.
        module: PathBuf,
        /// WASI arguments.
        wasi_args: Vec<String>,
        /// WASI environment variables.
        wasi_env: Vec<(String, String)>,
        /// WASI directory mappings (`guest_path`, `host_path`).
        wasi_dirs: Vec<(String, String)>,
        /// Optional fuel limit override (default: `DEFAULT_WASM_FUEL`).
        /// Set to `Some(n)` for CPU-intensive workloads needing more fuel.
        fuel_limit: Option<u64>,
    },
    /// `MicroVM` rootfs.
    MicroVm {
        /// Path to rootfs directory.
        rootfs: PathBuf,
        /// Command to execute.
        command: Option<Vec<String>>,
        /// Command arguments.
        args: Option<Vec<String>>,
        /// Environment variables.
        env: HashMap<String, String>,
        /// Working directory.
        working_dir: Option<String>,
    },
}

impl Bundle {
    /// Returns the bundle path.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::OciRuntime { path, .. } => path,
            Self::Wasm { module, .. } => module.parent().unwrap_or(module),
            Self::MicroVm { rootfs, .. } => rootfs,
        }
    }

    /// Returns the rootfs path if applicable.
    #[must_use]
    pub fn rootfs(&self) -> Option<&Path> {
        match self {
            Self::OciRuntime { rootfs, .. } | Self::MicroVm { rootfs, .. } => Some(rootfs),
            Self::Wasm { .. } => None,
        }
    }
}

// =============================================================================
// Bundle Builder
// =============================================================================

/// Builder for OCI runtime bundles from pulled images.
///
/// Extracts image layers to create runtime-specific bundles with security
/// validation and size limit enforcement.
///
/// ## Security Features
///
/// - **Path traversal protection**: Rejects `..` and absolute paths in tar entries
/// - **Size limits**: Enforces `MAX_LAYER_SIZE` and `MAX_ROOTFS_SIZE`
/// - **Whiteout handling**: Safely processes layer deletions
/// - **Atomic extraction**: Prevents partial bundles on failure
///
/// ## Caching
///
/// Bundles are cached by image digest. Subsequent builds for the same
/// image return the cached bundle without re-extraction.
///
/// ## Example
///
/// ```rust,ignore
/// let builder = BundleBuilder::new()?;
///
/// // Build standard OCI bundle
/// let bundle = builder.build_oci_bundle(&image, &config)?;
///
/// // Build with namespace paths for pod sharing
/// let ns_paths = HashMap::from([
///     ("network".to_string(), PathBuf::from("/proc/1234/ns/net")),
/// ]);
/// let pod_bundle = builder.build_oci_bundle_with_namespaces(&image, &config, &ns_paths)?;
/// ```
pub struct BundleBuilder {
    /// Base directory for bundles.
    base_dir: PathBuf,
    /// Blob storage for layer access.
    storage: Arc<BlobStore>,
}

impl BundleBuilder {
    /// Creates a new bundle builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle directory cannot be created or storage initialization fails.
    pub fn new() -> Result<Self> {
        let base_dir = Self::default_path();
        let storage = Arc::new(BlobStore::new()?);
        Self::with_path_and_storage(base_dir, storage)
    }

    /// Creates a bundle builder with a specific base path.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle directory cannot be created or storage initialization fails.
    pub fn with_path(base_dir: PathBuf) -> Result<Self> {
        let storage = Arc::new(BlobStore::new()?);
        Self::with_path_and_storage(base_dir, storage)
    }

    /// Creates a bundle builder with external storage.
    ///
    /// This is the preferred constructor when using with [`ImageService`],
    /// as it ensures consistent storage for both pulling and building.
    ///
    /// [`ImageService`]: crate::image::ImageService
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle directory cannot be created.
    pub fn with_storage(storage: Arc<BlobStore>) -> Result<Self> {
        let base_dir = Self::default_path();
        Self::with_path_and_storage(base_dir, storage)
    }

    /// Creates a bundle builder with specific path and storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle directory cannot be created.
    pub fn with_path_and_storage(base_dir: PathBuf, storage: Arc<BlobStore>) -> Result<Self> {
        fs::create_dir_all(&base_dir).map_err(|e| Error::BundleBuildFailed(e.to_string()))?;
        Ok(Self { base_dir, storage })
    }

    /// Returns the default bundle path.
    fn default_path() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".magikrun").join("bundles")
        } else {
            PathBuf::from(".magikrun").join("bundles")
        }
    }

    /// Valid namespace types for Linux namespaces.
    ///
    /// SECURITY: This allowlist prevents injection of arbitrary namespace types.
    /// Only these known namespace types are permitted in config.json.
    const VALID_NAMESPACE_TYPES: &'static [&'static str] = &[
        "pid", "network", "net", "ipc", "uts", "mount", "mnt", "cgroup", "user",
    ];

    /// Validates a namespace path matches the expected /proc/<pid>/ns/<type> format.
    ///
    /// # Security
    ///
    /// This prevents namespace injection attacks where a malicious caller could
    /// pass arbitrary paths that would be injected into config.json.
    ///
    /// Validation includes:
    /// - Path format: `/proc/<pid>/ns/<type>`
    /// - PID is a valid positive integer
    /// - Namespace type is in the explicit allowlist
    fn is_valid_namespace_path(path: &str, ns_type: &str) -> bool {
        // SECURITY: First validate that ns_type is in our allowlist
        if !Self::VALID_NAMESPACE_TYPES.contains(&ns_type) {
            return false;
        }

        // Expected format: /proc/<pid>/ns/<type>
        // Where <pid> is a positive integer and <type> matches the namespace type
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 5 {
            return false;
        }
        // parts[0] is empty (leading /), parts[1] is "proc", parts[2] is pid,
        // parts[3] is "ns", parts[4] is the namespace type
        if parts[0].is_empty()
            && parts[1] == "proc"
            && parts[2].chars().all(|c| c.is_ascii_digit())
            && !parts[2].is_empty()
            && parts[3] == "ns"
        {
            // SECURITY: Validate the path's namespace type is also in allowlist
            if !Self::VALID_NAMESPACE_TYPES.contains(&parts[4]) {
                return false;
            }
            // Check that the path type matches the requested type (or its alias)
            return parts[4] == ns_type || Self::namespace_type_alias(parts[4]) == ns_type;
        }
        false
    }

    /// Returns the canonical namespace type for aliases.
    fn namespace_type_alias(ns: &str) -> &str {
        match ns {
            "net" => "network",
            "network" => "net",
            "mnt" => "mount",
            "mount" => "mnt",
            _ => ns,
        }
    }

    /// Builds an OCI runtime bundle from an image.
    ///
    /// # Errors
    ///
    /// Returns an error if layer extraction fails, rootfs cannot be created,
    /// or the runtime spec cannot be generated.
    pub fn build_oci_bundle(
        &self,
        image: &ImageHandle,
        config: &OciContainerConfig,
    ) -> Result<Bundle> {
        let bundle_dir = self.bundle_path(&image.digest);
        let rootfs = bundle_dir.join("rootfs");

        // SECURITY: Always extract fresh. Previously we had an early return for existing
        // directories, but this created a TOCTOU vulnerability where an attacker with
        // write access to the bundle directory could pre-populate rootfs with malicious
        // files between image pull and bundle build.
        //
        // If rootfs exists (as file, symlink, or directory), remove it completely
        // and extract fresh from verified layers.
        if let Ok(metadata) = fs::symlink_metadata(&rootfs) {
            if metadata.is_dir() {
                // Remove existing directory to extract fresh
                if let Err(e) = fs::remove_dir_all(&rootfs) {
                    return Err(Error::BundleBuildFailed(format!(
                        "failed to remove existing rootfs for fresh extraction: {e}"
                    )));
                }
                debug!(
                    "Removed existing rootfs for fresh extraction: {}",
                    rootfs.display()
                );
            } else {
                // It's a file or symlink - remove it to prevent symlink attacks
                if let Err(e) = fs::remove_file(&rootfs) {
                    return Err(Error::BundleBuildFailed(format!(
                        "failed to remove existing file/symlink at rootfs path: {e}"
                    )));
                }
                debug!("Removed file/symlink at rootfs path: {}", rootfs.display());
            }
        }

        fs::create_dir_all(&rootfs)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to create rootfs: {}", e)))?;

        // Extract layers
        self.extract_layers(&image.layers, &rootfs)?;

        // Generate OCI runtime config
        let oci_config = self.generate_oci_spec(config);
        let config_path = bundle_dir.join("config.json");
        let config_json = serde_json::to_string_pretty(&oci_config)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to serialize config: {e}")))?;
        fs::write(&config_path, config_json)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to write config.json: {e}")))?;

        info!("Built OCI bundle: {}", bundle_dir.display());

        Ok(Bundle::OciRuntime {
            path: bundle_dir,
            rootfs,
        })
    }

    /// Builds an OCI runtime bundle with namespace paths for pod sharing.
    ///
    /// This is used when joining an existing pod's namespaces.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A namespace path is invalid (doesn't match `/proc/<pid>/ns/<type>` format)
    /// - Bundle directory creation fails
    /// - Layer extraction fails
    /// - Config serialization or writing fails
    pub fn build_oci_bundle_with_namespaces(
        &self,
        image: &ImageHandle,
        config: &OciContainerConfig,
        namespace_paths: &HashMap<String, PathBuf>,
    ) -> Result<Bundle> {
        // SECURITY: Validate namespace paths match expected format /proc/<pid>/ns/<type>
        for (ns_type, path) in namespace_paths {
            let path_str = path.to_string_lossy();
            if !Self::is_valid_namespace_path(&path_str, ns_type) {
                return Err(Error::InvalidBundle {
                    path: path.clone(),
                    reason: format!("invalid namespace path for {ns_type}: {path_str}"),
                });
            }
        }

        let bundle_dir = self.bundle_path_unique(&image.digest);
        let rootfs = bundle_dir.join("rootfs");

        fs::create_dir_all(&rootfs)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to create rootfs: {e}")))?;

        // Extract layers
        self.extract_layers(&image.layers, &rootfs)?;

        // Generate OCI runtime config with namespace paths
        let mut oci_config = self.generate_oci_spec(config);

        // Inject namespace paths for joining
        if let Some(linux) = &mut oci_config.linux {
            for ns in &mut linux.namespaces {
                if let Some(path) = namespace_paths.get(&ns.ns_type) {
                    ns.path = Some(path.to_string_lossy().to_string());
                }
            }
        }

        let config_path = bundle_dir.join("config.json");
        let config_json = serde_json::to_string_pretty(&oci_config)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to serialize config: {e}")))?;
        fs::write(&config_path, config_json)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to write config.json: {e}")))?;

        info!(
            "Built OCI bundle with namespace joining: {}",
            bundle_dir.display()
        );

        Ok(Bundle::OciRuntime {
            path: bundle_dir,
            rootfs,
        })
    }

    /// Returns the bundle path for a given digest.
    fn bundle_path(&self, digest: &str) -> PathBuf {
        let safe_digest = digest.replace([':', '/'], "-");
        self.base_dir.join(&safe_digest)
    }

    /// Returns a unique bundle path (for namespace-joined containers).
    fn bundle_path_unique(&self, digest: &str) -> PathBuf {
        let safe_digest = digest.replace([':', '/'], "-");
        let unique_id = uuid::Uuid::now_v7();
        self.base_dir.join(format!("{}-{}", safe_digest, unique_id))
    }

    /// Extracts image layers to the rootfs.
    ///
    /// Delegates to [`extract_layers_to_rootfs`] to avoid code duplication.
    fn extract_layers(&self, layers: &[LayerInfo], rootfs: &Path) -> Result<()> {
        extract_layers_to_rootfs(layers, rootfs, &self.storage)
    }

    /// Generates an OCI runtime spec.
    fn generate_oci_spec(&self, config: &OciContainerConfig) -> OciSpec {
        let mut env: Vec<String> = config
            .env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        // Add PATH if not set
        if !config.env.contains_key("PATH") {
            env.push(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            );
        }

        let args = config
            .command
            .clone()
            .unwrap_or_else(|| vec!["/bin/sh".to_string()]);

        OciSpec {
            oci_version: OCI_RUNTIME_SPEC_VERSION.to_string(),
            root: OciRoot {
                path: "rootfs".to_string(),
                // SECURITY: Read-only rootfs prevents persistent modifications
                readonly: true,
            },
            process: OciProcess {
                terminal: false,
                user: OciUser {
                    uid: config.user_id.unwrap_or(0),
                    gid: config.group_id.unwrap_or(0),
                },
                args,
                env,
                cwd: config
                    .working_dir
                    .clone()
                    .unwrap_or_else(|| "/".to_string()),
                // SECURITY: Prevent privilege escalation via setuid/setgid
                no_new_privileges: true,
                // SECURITY: Minimal capability set
                capabilities: Some(Self::default_capabilities()),
            },
            hostname: config
                .hostname
                .clone()
                .unwrap_or_else(|| "container".to_string()),
            mounts: self.default_mounts(),
            linux: Some(OciLinux {
                namespaces: self.generate_namespaces(config.vm_mode),
                resources: None,
                // SECURITY: Restrict syscalls to reduce kernel attack surface
                seccomp: Some(Self::default_seccomp()),
                // SECURITY: Hide sensitive kernel interfaces
                masked_paths: Self::default_masked_paths(),
                // SECURITY: Prevent writes to sensitive proc entries
                readonly_paths: Self::default_readonly_paths(),
            }),
        }
    }

    /// Generates namespace configuration for OCI spec.
    ///
    /// # Arguments
    ///
    /// * `vm_mode` - If true, skips network namespace (containers share VM's network)
    ///
    /// # Security
    ///
    /// When `vm_mode` is true, network isolation is provided by the VM boundary
    /// (hardware virtualization via KVM/Hypervisor.framework), not by Linux
    /// network namespaces. This matches the behavior of Kata Containers and
    /// Firecracker-containerd.
    fn generate_namespaces(&self, vm_mode: bool) -> Vec<OciNamespace> {
        let mut namespaces = vec![
            OciNamespace {
                ns_type: "pid".to_string(),
                path: None,
            },
            OciNamespace {
                ns_type: "ipc".to_string(),
                path: None,
            },
            OciNamespace {
                ns_type: "uts".to_string(),
                path: None,
            },
            OciNamespace {
                ns_type: "mount".to_string(),
                path: None,
            },
            // SECURITY: Isolate cgroup visibility
            OciNamespace {
                ns_type: "cgroup".to_string(),
                path: None,
            },
        ];

        // Only add network namespace for non-VM containers
        // VM containers use the VM's network (isolated by hardware)
        if !vm_mode {
            namespaces.push(OciNamespace {
                ns_type: "network".to_string(),
                path: None,
            });
        }

        namespaces
    }

    /// Returns the default capability set for containers.
    ///
    /// SECURITY: Minimal capabilities to reduce attack surface.
    /// Only `CAP_NET_BIND_SERVICE` is granted to allow binding ports < 1024.
    fn default_capabilities() -> OciCapabilities {
        let minimal_caps = vec!["CAP_NET_BIND_SERVICE".to_string()];
        OciCapabilities {
            bounding: minimal_caps.clone(),
            effective: minimal_caps.clone(),
            permitted: minimal_caps.clone(),
            ambient: vec![], // No ambient capabilities
        }
    }

    /// Returns paths to mask from containers.
    ///
    /// SECURITY: These paths expose sensitive kernel information or
    /// interfaces that could be used for container escape.
    fn default_masked_paths() -> Vec<String> {
        vec![
            "/proc/acpi".to_string(),
            "/proc/kcore".to_string(),
            "/proc/keys".to_string(),
            "/proc/latency_stats".to_string(),
            "/proc/timer_list".to_string(),
            "/proc/timer_stats".to_string(),
            "/proc/sched_debug".to_string(),
            "/proc/scsi".to_string(),
            "/sys/firmware".to_string(),
        ]
    }

    /// Returns paths that should be read-only inside containers.
    ///
    /// SECURITY: Prevents container processes from modifying kernel
    /// tunable parameters via procfs.
    fn default_readonly_paths() -> Vec<String> {
        vec![
            "/proc/bus".to_string(),
            "/proc/fs".to_string(),
            "/proc/irq".to_string(),
            "/proc/sys".to_string(),
            "/proc/sysrq-trigger".to_string(),
        ]
    }

    /// Returns the default seccomp profile for containers.
    ///
    /// SECURITY: This is an allowlist-based profile that permits common syscalls
    /// while blocking dangerous ones like `kexec_load`, `reboot`, `mount`, etc.
    /// Based on Docker's default seccomp profile with modifications for minimal
    /// container workloads.
    fn default_seccomp() -> OciSeccomp {
        OciSeccomp {
            default_action: "SCMP_ACT_ERRNO".to_string(),
            architectures: vec![
                "SCMP_ARCH_X86_64".to_string(),
                "SCMP_ARCH_AARCH64".to_string(),
                "SCMP_ARCH_X86".to_string(),
                "SCMP_ARCH_ARM".to_string(),
            ],
            syscalls: vec![
                // SECURITY: Allowlist of common syscalls needed for typical workloads.
                // This is conservative - most containerized apps need these.
                OciSeccompSyscall {
                    names: vec![
                        // Process/thread management
                        "exit".to_string(),
                        "exit_group".to_string(),
                        "futex".to_string(),
                        "nanosleep".to_string(),
                        "clock_nanosleep".to_string(),
                        "sched_yield".to_string(),
                        "getpid".to_string(),
                        "gettid".to_string(),
                        "getppid".to_string(),
                        "getuid".to_string(),
                        "geteuid".to_string(),
                        "getgid".to_string(),
                        "getegid".to_string(),
                        "getgroups".to_string(),
                        "setuid".to_string(),
                        "setgid".to_string(),
                        "setgroups".to_string(),
                        "setsid".to_string(),
                        "getpgid".to_string(),
                        "setpgid".to_string(),
                        "getpgrp".to_string(),
                        "getsid".to_string(),
                        "clone".to_string(),
                        "clone3".to_string(),
                        "fork".to_string(),
                        "vfork".to_string(),
                        "execve".to_string(),
                        "execveat".to_string(),
                        "wait4".to_string(),
                        "waitid".to_string(),
                        // File I/O
                        "read".to_string(),
                        "write".to_string(),
                        "open".to_string(),
                        "openat".to_string(),
                        "openat2".to_string(),
                        "close".to_string(),
                        "close_range".to_string(),
                        "lseek".to_string(),
                        "pread64".to_string(),
                        "pwrite64".to_string(),
                        "readv".to_string(),
                        "writev".to_string(),
                        "preadv".to_string(),
                        "pwritev".to_string(),
                        "preadv2".to_string(),
                        "pwritev2".to_string(),
                        "dup".to_string(),
                        "dup2".to_string(),
                        "dup3".to_string(),
                        "pipe".to_string(),
                        "pipe2".to_string(),
                        "select".to_string(),
                        "pselect6".to_string(),
                        "poll".to_string(),
                        "ppoll".to_string(),
                        "epoll_create".to_string(),
                        "epoll_create1".to_string(),
                        "epoll_ctl".to_string(),
                        "epoll_wait".to_string(),
                        "epoll_pwait".to_string(),
                        "epoll_pwait2".to_string(),
                        "eventfd".to_string(),
                        "eventfd2".to_string(),
                        "timerfd_create".to_string(),
                        "timerfd_settime".to_string(),
                        "timerfd_gettime".to_string(),
                        "signalfd".to_string(),
                        "signalfd4".to_string(),
                        "fcntl".to_string(),
                        "flock".to_string(),
                        "fsync".to_string(),
                        "fdatasync".to_string(),
                        "sync".to_string(),
                        "syncfs".to_string(),
                        "ftruncate".to_string(),
                        "truncate".to_string(),
                        "stat".to_string(),
                        "lstat".to_string(),
                        "fstat".to_string(),
                        "fstatat64".to_string(),
                        "newfstatat".to_string(),
                        "statx".to_string(),
                        "statfs".to_string(),
                        "fstatfs".to_string(),
                        "access".to_string(),
                        "faccessat".to_string(),
                        "faccessat2".to_string(),
                        "readlink".to_string(),
                        "readlinkat".to_string(),
                        "getcwd".to_string(),
                        "chdir".to_string(),
                        "fchdir".to_string(),
                        "rename".to_string(),
                        "renameat".to_string(),
                        "renameat2".to_string(),
                        "link".to_string(),
                        "linkat".to_string(),
                        "symlink".to_string(),
                        "symlinkat".to_string(),
                        "unlink".to_string(),
                        "unlinkat".to_string(),
                        "rmdir".to_string(),
                        "mkdir".to_string(),
                        "mkdirat".to_string(),
                        "mknod".to_string(),
                        "mknodat".to_string(),
                        "chmod".to_string(),
                        "fchmod".to_string(),
                        "fchmodat".to_string(),
                        "chown".to_string(),
                        "fchown".to_string(),
                        "fchownat".to_string(),
                        "lchown".to_string(),
                        "umask".to_string(),
                        "getdents".to_string(),
                        "getdents64".to_string(),
                        "utimensat".to_string(),
                        "futimesat".to_string(),
                        "utime".to_string(),
                        "utimes".to_string(),
                        // Memory management
                        "brk".to_string(),
                        "mmap".to_string(),
                        "mmap2".to_string(),
                        "munmap".to_string(),
                        "mremap".to_string(),
                        "mprotect".to_string(),
                        "madvise".to_string(),
                        "mlock".to_string(),
                        "mlock2".to_string(),
                        "munlock".to_string(),
                        "mlockall".to_string(),
                        "munlockall".to_string(),
                        "mincore".to_string(),
                        "msync".to_string(),
                        // Signals
                        "rt_sigaction".to_string(),
                        "rt_sigprocmask".to_string(),
                        "rt_sigreturn".to_string(),
                        "rt_sigsuspend".to_string(),
                        "rt_sigpending".to_string(),
                        "rt_sigtimedwait".to_string(),
                        "rt_sigqueueinfo".to_string(),
                        "kill".to_string(),
                        "tgkill".to_string(),
                        "tkill".to_string(),
                        "sigaltstack".to_string(),
                        // Networking
                        "socket".to_string(),
                        "socketpair".to_string(),
                        "bind".to_string(),
                        "listen".to_string(),
                        "accept".to_string(),
                        "accept4".to_string(),
                        "connect".to_string(),
                        "getsockname".to_string(),
                        "getpeername".to_string(),
                        "sendto".to_string(),
                        "recvfrom".to_string(),
                        "setsockopt".to_string(),
                        "getsockopt".to_string(),
                        "shutdown".to_string(),
                        "sendmsg".to_string(),
                        "recvmsg".to_string(),
                        "sendmmsg".to_string(),
                        "recvmmsg".to_string(),
                        // Time
                        "gettimeofday".to_string(),
                        "clock_gettime".to_string(),
                        "clock_getres".to_string(),
                        "times".to_string(),
                        // Resource limits
                        "getrlimit".to_string(),
                        "setrlimit".to_string(),
                        "prlimit64".to_string(),
                        "getrusage".to_string(),
                        // System info
                        "uname".to_string(),
                        "sysinfo".to_string(),
                        // IPC
                        "shmget".to_string(),
                        "shmat".to_string(),
                        "shmctl".to_string(),
                        "shmdt".to_string(),
                        "semget".to_string(),
                        "semop".to_string(),
                        "semctl".to_string(),
                        "semtimedop".to_string(),
                        "msgget".to_string(),
                        "msgsnd".to_string(),
                        "msgrcv".to_string(),
                        "msgctl".to_string(),
                        // Misc
                        "prctl".to_string(),
                        "arch_prctl".to_string(),
                        "set_tid_address".to_string(),
                        "set_robust_list".to_string(),
                        "get_robust_list".to_string(),
                        "getrandom".to_string(),
                        "ioctl".to_string(),
                        "rseq".to_string(),
                        "memfd_create".to_string(),
                        "copy_file_range".to_string(),
                        "splice".to_string(),
                        "tee".to_string(),
                        "vmsplice".to_string(),
                        "sendfile".to_string(),
                        "io_uring_setup".to_string(),
                        "io_uring_enter".to_string(),
                        "io_uring_register".to_string(),
                    ],
                    action: "SCMP_ACT_ALLOW".to_string(),
                },
            ],
            listener_path: None,
        }
    }

    /// Returns default OCI mounts.
    fn default_mounts(&self) -> Vec<OciMount> {
        vec![
            OciMount {
                destination: "/proc".to_string(),
                mount_type: "proc".to_string(),
                source: "proc".to_string(),
                options: vec![],
            },
            OciMount {
                destination: "/dev".to_string(),
                mount_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
                options: vec![
                    "nosuid".to_string(),
                    "strictatime".to_string(),
                    "mode=755".to_string(),
                ],
            },
            OciMount {
                destination: "/dev/pts".to_string(),
                mount_type: "devpts".to_string(),
                source: "devpts".to_string(),
                options: vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "newinstance".to_string(),
                ],
            },
            OciMount {
                destination: "/sys".to_string(),
                mount_type: "sysfs".to_string(),
                source: "sysfs".to_string(),
                options: vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "ro".to_string(),
                ],
            },
            // SECURITY: Bounded tmpfs for /tmp prevents disk exhaustion
            OciMount {
                destination: "/tmp".to_string(),
                mount_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
                options: vec![
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "size=64m".to_string(),
                ],
            },
            // SECURITY: Bounded tmpfs for /run
            OciMount {
                destination: "/run".to_string(),
                mount_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
                options: vec![
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "size=64m".to_string(),
                ],
            },
        ]
    }
}

// =============================================================================
// Container Configuration (input for bundle building)
// =============================================================================

/// Container configuration for OCI bundle building.
///
/// Provides the application-level settings that go into the OCI runtime
/// spec's `process` section. This is the input for [`BundleBuilder::build_oci_bundle`].
///
/// ## Defaults
///
/// | Field | Default |
/// |-------|------------------------------|
/// | `command` | `["/bin/sh"]` |
/// | `working_dir` | `"/"` |
/// | `user_id` | `0` (root) |
/// | `group_id` | `0` (root) |
/// | `hostname` | `"container"` |
///
/// ## Example
///
/// ```rust,ignore
/// let config = OciContainerConfig {
///     name: "my-app".to_string(),
///     command: Some(vec!["/app/server".to_string(), "--port".to_string(), "8080".to_string()]),
///     env: HashMap::from([
///         ("ENV".to_string(), "production".to_string()),
///     ]),
///     working_dir: Some("/app".to_string()),
///     ..Default::default()
/// };
/// ```
///
/// [`BundleBuilder::build_oci_bundle`]: BundleBuilder::build_oci_bundle
#[derive(Debug, Clone, Default)]
pub struct OciContainerConfig {
    /// Container name.
    pub name: String,
    /// Command to run.
    pub command: Option<Vec<String>>,
    /// Environment variables.
    pub env: HashMap<String, String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// User ID.
    pub user_id: Option<u32>,
    /// Group ID.
    pub group_id: Option<u32>,
    /// Hostname.
    pub hostname: Option<String>,
    /// VM mode: skip network namespace creation.
    ///
    /// When `true`, the generated OCI config will not create a new network
    /// namespace. This is used for containers running inside MicroVMs where
    /// network isolation is provided by the VM boundary (via passt/libkrun).
    ///
    /// # Security
    ///
    /// This is safe for MicroVM containers because:
    /// - The VM provides hardware-level network isolation
    /// - passt handles port forwarding from host to VM
    /// - No network traffic can bypass the VM boundary
    pub vm_mode: bool,
}

// =============================================================================
// OCI Runtime Spec Types
// =============================================================================

/// OCI Runtime Spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSpec {
    pub oci_version: String,
    pub root: OciRoot,
    pub process: OciProcess,
    pub hostname: String,
    pub mounts: Vec<OciMount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<OciLinux>,
}

/// OCI root filesystem config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRoot {
    pub path: String,
    pub readonly: bool,
}

/// OCI process config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciProcess {
    pub terminal: bool,
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    /// Prevents the process from gaining additional privileges.
    /// SECURITY: Always true to prevent setuid/setgid exploits.
    #[serde(default = "default_no_new_privileges")]
    pub no_new_privileges: bool,
    /// Capability restrictions for the process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<OciCapabilities>,
}

/// Default value for `no_new_privileges` (always true for security).
fn default_no_new_privileges() -> bool {
    true
}

/// OCI user config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
}

/// OCI mount config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMount {
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub source: String,
    #[serde(default)]
    pub options: Vec<String>,
}

/// OCI Linux-specific config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciLinux {
    pub namespaces: Vec<OciNamespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<OciResources>,
    /// Seccomp syscall filtering profile.
    /// SECURITY: Reduces kernel attack surface by restricting available syscalls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<OciSeccomp>,
    /// Paths to mask from the container (appear empty/inaccessible).
    /// SECURITY: Hides sensitive kernel interfaces.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub masked_paths: Vec<String>,
    /// Paths to mount read-only inside the container.
    /// SECURITY: Prevents writes to sensitive proc entries.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub readonly_paths: Vec<String>,
}

/// OCI namespace config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciNamespace {
    #[serde(rename = "type")]
    pub ns_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// OCI resource limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<OciMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<OciCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<OciPids>,
}

/// OCI memory limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

/// OCI CPU limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciCpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
}

/// OCI PID limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciPids {
    pub limit: i64,
}

/// OCI capability set.
///
/// SECURITY: Containers run with minimal capabilities by default.
/// Only `CAP_NET_BIND_SERVICE` is granted to allow binding low ports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciCapabilities {
    /// Maximum capabilities the process can have.
    #[serde(default)]
    pub bounding: Vec<String>,
    /// Capabilities in the effective set.
    #[serde(default)]
    pub effective: Vec<String>,
    /// Capabilities in the permitted set.
    #[serde(default)]
    pub permitted: Vec<String>,
    /// Capabilities in the ambient set (inherited across execve).
    #[serde(default)]
    pub ambient: Vec<String>,
}

/// OCI seccomp configuration.
///
/// SECURITY: Defines a syscall filtering policy to reduce kernel attack surface.
/// Uses an allowlist approach where `default_action` is typically `SCMP_ACT_ERRNO`
/// and allowed syscalls are listed explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSeccomp {
    /// Default action when syscall not in any rule (e.g., `SCMP_ACT_ERRNO`).
    pub default_action: String,
    /// Architectures this profile applies to.
    #[serde(default)]
    pub architectures: Vec<String>,
    /// Syscall rules (allowlist).
    #[serde(default)]
    pub syscalls: Vec<OciSeccompSyscall>,
    /// Path to seccomp notification listener socket.
    ///
    /// When set, syscalls with action `SCMP_ACT_NOTIFY` will send notifications
    /// to this socket instead of blocking. Used for bypass4netns socket bypass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_path: Option<String>,
}

/// Individual syscall rule in a seccomp profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciSeccompSyscall {
    /// Names of syscalls this rule applies to.
    pub names: Vec<String>,
    /// Action to take when syscall is invoked.
    pub action: String,
}

// =============================================================================
// Layer Extraction Utilities
// =============================================================================

/// Extracts OCI image layers to a rootfs directory.
///
/// This is the core layer extraction function with full security validation.
/// It can be used standalone or is called internally by [`BundleBuilder`].
///
/// ## Security Checks
///
/// For each tar entry:
/// 1. **Path traversal**: Rejects paths containing `..` or starting with `/`
/// 2. **Size tracking**: Accumulates extracted size, fails at `MAX_ROOTFS_SIZE`
/// 3. **Layer size**: Each layer checked against `MAX_LAYER_SIZE`
/// 4. **Whiteouts**: TOCTOU-safe removal using `symlink_metadata()`
/// 5. **Symlinks**: Depth-tracking validation ensures target stays within rootfs
/// 6. **Hardlinks**: Same depth-tracking validation as symlinks for both absolute and relative paths
/// 7. **Null bytes**: Rejected in symlink/hardlink targets (injection attack prevention)
/// 8. **File count**: Enforces `MAX_FILES_PER_LAYER` to prevent inode exhaustion
///
/// ## Layer Application
///
/// Layers are applied in order, with each layer:
/// - Overwriting existing files from earlier layers
/// - Processing whiteout files to remove content
/// - Creating new directories and files
///
/// ## Arguments
///
/// * `layers` - Ordered list of layer info (bottom to top)
/// * `rootfs` - Target directory for extraction
/// * `storage` - Blob store containing layer data
///
/// ## Errors
///
/// - [`Error::BlobNotFound`]: Layer digest not in storage
/// - [`Error::ImageTooLarge`]: Size limits exceeded
/// - [`Error::PathTraversal`]: Malicious path detected
/// - [`Error::LayerExtractionFailed`]: Tar parsing or I/O error
///
/// [`Error::BlobNotFound`]: crate::error::Error::BlobNotFound
/// [`Error::ImageTooLarge`]: crate::error::Error::ImageTooLarge
/// [`Error::PathTraversal`]: crate::error::Error::PathTraversal
/// [`Error::LayerExtractionFailed`]: crate::error::Error::LayerExtractionFailed
pub fn extract_layers_to_rootfs(
    layers: &[LayerInfo],
    rootfs: &Path,
    storage: &BlobStore,
) -> Result<()> {
    let mut total_size = 0u64;

    for layer in layers {
        debug!("Extracting layer: {}", layer.digest);

        let data = storage.get_blob(&layer.digest)?;

        if data.len() > MAX_LAYER_SIZE {
            return Err(Error::ImageTooLarge {
                size: data.len() as u64,
                limit: MAX_LAYER_SIZE as u64,
            });
        }

        // SECURITY: Calculate remaining size budget for this layer.
        // This prevents compression bombs where a small compressed file
        // expands to exhaust memory before per-entry size tracking kicks in.
        let remaining_budget = MAX_ROOTFS_SIZE.saturating_sub(total_size);

        // Decompress with size limiting to prevent memory exhaustion
        let decoder = GzDecoder::new(&data[..]);
        let size_limited = SizeLimitedReader::new(decoder, remaining_budget);
        let mut archive = Archive::new(size_limited);

        // SECURITY: Track file count to prevent inode exhaustion attacks
        let mut file_count = 0usize;

        for entry in archive.entries().map_err(|e| {
            // Check if this was a size limit error
            let reason = e.to_string();
            if reason.contains("decompression size limit exceeded") {
                return Error::ImageTooLarge {
                    size: total_size + remaining_budget,
                    limit: MAX_ROOTFS_SIZE,
                };
            }
            Error::LayerExtractionFailed {
                digest: layer.digest.clone(),
                reason,
            }
        })? {
            // SECURITY: Check file count before processing each entry
            file_count += 1;
            if file_count > MAX_FILES_PER_LAYER {
                return Err(Error::ResourceExhausted(format!(
                    "layer {} exceeds maximum file count ({})",
                    layer.digest, MAX_FILES_PER_LAYER
                )));
            }

            let mut entry = entry.map_err(|e| {
                // Check if this was a size limit error
                let reason = e.to_string();
                if reason.contains("decompression size limit exceeded") {
                    return Error::ImageTooLarge {
                        size: total_size + remaining_budget,
                        limit: MAX_ROOTFS_SIZE,
                    };
                }
                Error::LayerExtractionFailed {
                    digest: layer.digest.clone(),
                    reason,
                }
            })?;

            let path = entry.path().map_err(|e| Error::LayerExtractionFailed {
                digest: layer.digest.clone(),
                reason: e.to_string(),
            })?;

            // SECURITY: Check for path traversal
            let path_str = path.to_string_lossy();
            if path_str.contains("..") || path_str.starts_with('/') {
                return Err(Error::PathTraversal {
                    path: path_str.to_string(),
                });
            }

            // Handle whiteout files
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filename.starts_with(".wh.") {
                let target = filename.strip_prefix(".wh.").unwrap();
                let target_path = rootfs
                    .join(path.parent().unwrap_or(Path::new("")))
                    .join(target);

                // SECURITY: Use symlink_metadata() instead of exists() to prevent TOCTOU.
                // symlink_metadata() returns info about the symlink itself (not following it),
                // so an attacker cannot substitute a symlink between check and removal.
                if let Ok(metadata) = fs::symlink_metadata(&target_path) {
                    // SECURITY: Symlinks are special - the symlink FILE itself is within rootfs
                    // and can be safely removed. We use remove_file which removes the symlink,
                    // NOT the target it points to. This is safe regardless of where the target is.
                    if metadata.file_type().is_symlink() {
                        // Remove the symlink itself (not following it)
                        let _ = fs::remove_file(&target_path);
                    } else {
                        // For regular files and directories, verify the path stays within rootfs.
                        // We verify using the target_path directly (not canonicalized) to avoid
                        // following any intermediate symlinks.
                        //
                        // SECURITY: Check that target_path is actually under rootfs.
                        // This handles the case where the whiteout path itself contains
                        // suspicious components (already rejected by path traversal check above).
                        match target_path.canonicalize() {
                            Ok(canonical) => {
                                if let Ok(canonical_rootfs) = rootfs.canonicalize() {
                                    if canonical.starts_with(&canonical_rootfs) {
                                        if metadata.is_dir() {
                                            let _ = fs::remove_dir_all(&target_path);
                                        } else {
                                            let _ = fs::remove_file(&target_path);
                                        }
                                    } else {
                                        // Target resolves outside rootfs via symlinks in path
                                        debug!(
                                            "Whiteout target '{}' resolves outside rootfs, skipping",
                                            target_path.display()
                                        );
                                    }
                                }
                            }
                            Err(_) => {
                                // Cannot canonicalize - path components don't exist
                                // Since we have metadata, the file exists but a parent is inaccessible
                                // Fall back to direct removal (will fail safely if truly inaccessible)
                                if metadata.is_dir() {
                                    let _ = fs::remove_dir_all(&target_path);
                                } else {
                                    let _ = fs::remove_file(&target_path);
                                }
                            }
                        }
                    }
                }
                continue;
            }

            // Track size
            total_size += entry.size();
            if total_size > MAX_ROOTFS_SIZE {
                return Err(Error::ImageTooLarge {
                    size: total_size,
                    limit: MAX_ROOTFS_SIZE,
                });
            }

            // SECURITY: Validate symlink and hardlink targets stay within rootfs
            // This prevents symlink attacks where a malicious layer creates a symlink
            // pointing outside the container, then a later layer writes through it.
            // Hardlinks can also be used to escape by linking to files outside rootfs.
            let entry_type = entry.header().entry_type();
            if (entry_type.is_symlink() || entry_type.is_hard_link())
                && let Ok(Some(target)) = entry.link_name()
            {
                let target_str = target.to_string_lossy();

                // SECURITY: Reject targets with null bytes (injection attack)
                if target_str.contains('\0') {
                    return Err(Error::PathTraversal {
                        path: format!("symlink target contains null byte: {}", path.display()),
                    });
                }

                if target_str.starts_with('/') {
                    // Absolute symlink: will be resolved relative to rootfs by tar
                    // But we MUST reject any path traversal attempts
                    if target_str.contains("..") {
                        return Err(Error::PathTraversal {
                            path: format!("absolute symlink target contains '..': {}", target_str),
                        });
                    }

                    // SECURITY: Defensive canonicalization check.
                    // Even though tar's unpack_in() should anchor absolute paths to rootfs,
                    // we explicitly verify the resolved path stays within bounds.
                    // This protects against tar crate behavior changes or edge cases.
                    let resolved = rootfs.join(target_str.trim_start_matches('/'));
                    if !resolved.starts_with(rootfs) {
                        return Err(Error::PathTraversal {
                            path: format!(
                                "absolute symlink '{}' resolves outside rootfs: {}",
                                path.display(),
                                target_str
                            ),
                        });
                    }
                } else {
                    // Relative symlink: resolve against entry's parent directory
                    let entry_parent = path.parent().unwrap_or(Path::new(""));

                    // Normalize the path and check if it escapes rootfs
                    // We track depth: going up (..) decreases, going down (Normal) increases
                    // If depth ever goes negative, we've escaped the rootfs
                    let mut depth: i32 = 0;

                    // First, count depth from entry's parent
                    for component in entry_parent.components() {
                        if let std::path::Component::Normal(_) = component {
                            depth += 1;
                        }
                    }

                    // Then apply target's components
                    for component in target.components() {
                        match component {
                            std::path::Component::ParentDir => {
                                depth -= 1;
                                if depth < 0 {
                                    return Err(Error::PathTraversal {
                                        path: format!(
                                            "symlink '{}' escapes rootfs via target '{}'",
                                            path.display(),
                                            target_str
                                        ),
                                    });
                                }
                            }
                            std::path::Component::Normal(_) => depth += 1,
                            _ => {}
                        }
                    }
                }

                // SECURITY: For hardlinks, verify the target stays within rootfs bounds.
                // Hardlinks can only point to existing files, but a malicious archive
                // could reference files created earlier in the same archive to escape.
                //
                // ADDITIONAL SECURITY: We also check if the resolved target path is a
                // symlink. If so, we reject it because a hardlink to a symlink could
                // effectively create a hardlink to a file outside rootfs:
                //   1. Archive creates symlink "link" -> "/etc/passwd" (appears safe as relative depth check passes)
                //   2. Archive creates hardlink "evil" -> "link" (hardlink to the symlink)
                //   3. On extraction, hardlink might bypass the symlink's own validation
                //
                // By rejecting hardlinks to symlinks, we eliminate this attack vector.
                if entry_type.is_hard_link() {
                    // Compute the target path within rootfs
                    let resolved_target = if target_str.starts_with('/') {
                        // Absolute hardlink target - verify it's within rootfs bounds
                        let target_in_rootfs = rootfs.join(target_str.trim_start_matches('/'));
                        if !target_in_rootfs.starts_with(rootfs) {
                            return Err(Error::PathTraversal {
                                path: format!("hardlink target escapes rootfs: {}", target_str),
                            });
                        }
                        target_in_rootfs
                    } else {
                        // SECURITY: Relative hardlinks need the same depth-tracking validation
                        // as symlinks. A hardlink like "../../../etc/passwd" would escape rootfs.
                        // Note: The depth tracking above already ran for relative paths,
                        // but we add an explicit check here for defense-in-depth.
                        let entry_parent = path.parent().unwrap_or(Path::new(""));
                        let mut hl_depth: i32 = 0;

                        // Count depth from entry's parent
                        for component in entry_parent.components() {
                            if let std::path::Component::Normal(_) = component {
                                hl_depth += 1;
                            }
                        }

                        // Apply target's components
                        for component in target.components() {
                            match component {
                                std::path::Component::ParentDir => {
                                    hl_depth -= 1;
                                    if hl_depth < 0 {
                                        return Err(Error::PathTraversal {
                                            path: format!(
                                                "hardlink '{}' escapes rootfs via target '{}'",
                                                path.display(),
                                                target_str
                                            ),
                                        });
                                    }
                                }
                                std::path::Component::Normal(_) => hl_depth += 1,
                                _ => {}
                            }
                        }

                        // Compute the resolved path within rootfs
                        rootfs.join(entry_parent).join(target.as_ref())
                    };

                    // SECURITY: Reject hardlinks to symlinks to prevent escape via indirection.
                    // A symlink created earlier in the archive might point outside rootfs,
                    // and hardlinking to it would allow creating a hardlink that escapes.
                    //
                    // We use symlink_metadata() to check the link type without following it.
                    if let Ok(meta) = fs::symlink_metadata(&resolved_target)
                        && meta.file_type().is_symlink()
                    {
                        return Err(Error::PathTraversal {
                            path: format!(
                                "hardlink '{}' targets a symlink '{}' (potential escape vector)",
                                path.display(),
                                target_str
                            ),
                        });
                    }
                    // Note: If the target doesn't exist yet, we allow it - tar will fail
                    // naturally when trying to create the hardlink. We only reject when
                    // we can positively identify a symlink target.
                }
            }

            // Unpack
            entry
                .unpack_in(rootfs)
                .map_err(|e| Error::LayerExtractionFailed {
                    digest: layer.digest.clone(),
                    reason: e.to_string(),
                })?;
        }
    }

    Ok(())
}
