//! OCI Runtime Bundle building.
//!
//! Converts pulled OCI images into OCI Runtime bundles (rootfs + config.json).
//! This is the standard OCI Runtime Spec format consumed by runtimes like
//! youki, runc, crun, etc.

use crate::constants::{MAX_LAYER_SIZE, MAX_ROOTFS_SIZE, OCI_RUNTIME_SPEC_VERSION};
use crate::error::{Error, Result};
use crate::registry::{ImageHandle, LayerInfo};
use crate::storage::BlobStore;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tar::Archive;
use tracing::{debug, info, warn};

/// Bundle format expected by a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFormat {
    /// OCI Runtime Bundle (rootfs + config.json).
    OciRuntime,
    /// WASM module with WASI config.
    Wasm,
    /// Root filesystem for microVM.
    MicroVm,
}

/// A built bundle ready for execution.
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
        /// WASI directory mappings.
        wasi_dirs: Vec<(String, String)>,
    },
    /// MicroVM rootfs.
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
    pub fn path(&self) -> &Path {
        match self {
            Self::OciRuntime { path, .. } => path,
            Self::Wasm { module, .. } => module.parent().unwrap_or(module),
            Self::MicroVm { rootfs, .. } => rootfs,
        }
    }

    /// Returns the rootfs path if applicable.
    pub fn rootfs(&self) -> Option<&Path> {
        match self {
            Self::OciRuntime { rootfs, .. } => Some(rootfs),
            Self::MicroVm { rootfs, .. } => Some(rootfs),
            Self::Wasm { .. } => None,
        }
    }
}

// =============================================================================
// Bundle Builder
// =============================================================================

/// Builder for OCI runtime bundles.
pub struct BundleBuilder {
    /// Base directory for bundles.
    base_dir: PathBuf,
    /// Blob storage for layer access.
    storage: BlobStore,
}

impl BundleBuilder {
    /// Creates a new bundle builder.
    pub fn new() -> Result<Self> {
        let base_dir = Self::default_path();
        Self::with_path(base_dir)
    }

    /// Creates a bundle builder with a specific base path.
    pub fn with_path(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir).map_err(|e| Error::BundleBuildFailed(e.to_string()))?;
        let storage = BlobStore::new()?;
        Ok(Self { base_dir, storage })
    }

    /// Returns the default bundle path.
    fn default_path() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".magik-oci").join("bundles")
        } else {
            PathBuf::from(".magik-oci").join("bundles")
        }
    }

    /// Builds an OCI runtime bundle from an image.
    pub fn build_oci_bundle(
        &self,
        image: &ImageHandle,
        config: &OciContainerConfig,
    ) -> Result<Bundle> {
        let bundle_dir = self.bundle_path(&image.digest);
        let rootfs = bundle_dir.join("rootfs");

        if rootfs.exists() {
            debug!("Bundle already exists: {}", bundle_dir.display());
            return Ok(Bundle::OciRuntime {
                path: bundle_dir,
                rootfs,
            });
        }

        fs::create_dir_all(&rootfs)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to create rootfs: {}", e)))?;

        // Extract layers
        self.extract_layers(&image.layers, &rootfs)?;

        // Generate OCI runtime config
        let oci_config = self.generate_oci_spec(config);
        let config_path = bundle_dir.join("config.json");
        let config_json = serde_json::to_string_pretty(&oci_config)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to serialize config: {}", e)))?;
        fs::write(&config_path, config_json)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to write config.json: {}", e)))?;

        info!("Built OCI bundle: {}", bundle_dir.display());

        Ok(Bundle::OciRuntime {
            path: bundle_dir,
            rootfs,
        })
    }

    /// Builds an OCI runtime bundle with namespace paths for pod sharing.
    ///
    /// This is used when joining an existing pod's namespaces.
    pub fn build_oci_bundle_with_namespaces(
        &self,
        image: &ImageHandle,
        config: &OciContainerConfig,
        namespace_paths: &HashMap<String, PathBuf>,
    ) -> Result<Bundle> {
        let bundle_dir = self.bundle_path_unique(&image.digest);
        let rootfs = bundle_dir.join("rootfs");

        fs::create_dir_all(&rootfs)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to create rootfs: {}", e)))?;

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
            .map_err(|e| Error::BundleBuildFailed(format!("failed to serialize config: {}", e)))?;
        fs::write(&config_path, config_json)
            .map_err(|e| Error::BundleBuildFailed(format!("failed to write config.json: {}", e)))?;

        info!("Built OCI bundle with namespace joining: {}", bundle_dir.display());

        Ok(Bundle::OciRuntime {
            path: bundle_dir,
            rootfs,
        })
    }

    /// Returns the bundle path for a given digest.
    fn bundle_path(&self, digest: &str) -> PathBuf {
        let safe_digest = digest.replace(':', "-").replace('/', "-");
        self.base_dir.join(&safe_digest)
    }

    /// Returns a unique bundle path (for namespace-joined containers).
    fn bundle_path_unique(&self, digest: &str) -> PathBuf {
        let safe_digest = digest.replace(':', "-").replace('/', "-");
        let unique_id = uuid::Uuid::now_v7();
        self.base_dir.join(format!("{}-{}", safe_digest, unique_id))
    }

    /// Extracts image layers to the rootfs.
    fn extract_layers(&self, layers: &[LayerInfo], rootfs: &Path) -> Result<()> {
        let mut total_size = 0u64;

        for layer in layers {
            debug!("Extracting layer: {}", layer.digest);

            let data = self.storage.get_blob(&layer.digest)?;

            if data.len() > MAX_LAYER_SIZE {
                return Err(Error::ImageTooLarge {
                    size: data.len() as u64,
                    limit: MAX_LAYER_SIZE as u64,
                });
            }

            // Decompress and extract
            let decoder = GzDecoder::new(&data[..]);
            let mut archive = Archive::new(decoder);

            for entry in archive.entries().map_err(|e| Error::LayerExtractionFailed {
                digest: layer.digest.clone(),
                reason: e.to_string(),
            })? {
                let mut entry = entry.map_err(|e| Error::LayerExtractionFailed {
                    digest: layer.digest.clone(),
                    reason: e.to_string(),
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

                // Handle whiteout files (deletions)
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if filename.starts_with(".wh.") {
                    let target = filename.strip_prefix(".wh.").unwrap();
                    let target_path = rootfs.join(path.parent().unwrap_or(Path::new(""))).join(target);
                    if target_path.exists() {
                        let _ = fs::remove_file(&target_path);
                        let _ = fs::remove_dir_all(&target_path);
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

                // Unpack
                entry.unpack_in(rootfs).map_err(|e| Error::LayerExtractionFailed {
                    digest: layer.digest.clone(),
                    reason: e.to_string(),
                })?;
            }
        }

        Ok(())
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
            env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
        }

        let args = config
            .command
            .clone()
            .unwrap_or_else(|| vec!["/bin/sh".to_string()]);

        OciSpec {
            oci_version: OCI_RUNTIME_SPEC_VERSION.to_string(),
            root: OciRoot {
                path: "rootfs".to_string(),
                readonly: false,
            },
            process: OciProcess {
                terminal: false,
                user: OciUser {
                    uid: config.user_id.unwrap_or(0),
                    gid: config.group_id.unwrap_or(0),
                },
                args,
                env,
                cwd: config.working_dir.clone().unwrap_or_else(|| "/".to_string()),
            },
            hostname: config.hostname.clone().unwrap_or_else(|| "container".to_string()),
            mounts: self.default_mounts(),
            linux: Some(OciLinux {
                namespaces: vec![
                    OciNamespace { ns_type: "pid".to_string(), path: None },
                    OciNamespace { ns_type: "network".to_string(), path: None },
                    OciNamespace { ns_type: "ipc".to_string(), path: None },
                    OciNamespace { ns_type: "uts".to_string(), path: None },
                    OciNamespace { ns_type: "mount".to_string(), path: None },
                ],
                resources: None,
            }),
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
                options: vec!["nosuid".to_string(), "strictatime".to_string(), "mode=755".to_string()],
            },
            OciMount {
                destination: "/dev/pts".to_string(),
                mount_type: "devpts".to_string(),
                source: "devpts".to_string(),
                options: vec!["nosuid".to_string(), "noexec".to_string(), "newinstance".to_string()],
            },
            OciMount {
                destination: "/sys".to_string(),
                mount_type: "sysfs".to_string(),
                source: "sysfs".to_string(),
                options: vec!["nosuid".to_string(), "noexec".to_string(), "nodev".to_string(), "ro".to_string()],
            },
        ]
    }
}

// =============================================================================
// Container Configuration (input for bundle building)
// =============================================================================

/// Container configuration for bundle building.
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
pub struct OciProcess {
    pub terminal: bool,
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
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
pub struct OciLinux {
    pub namespaces: Vec<OciNamespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<OciResources>,
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

// =============================================================================
// Layer Extraction Utilities
// =============================================================================

/// Extracts layers to a rootfs directory (standalone function).
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

        // Decompress and extract
        let decoder = GzDecoder::new(&data[..]);
        let mut archive = Archive::new(decoder);

        for entry in archive.entries().map_err(|e| Error::LayerExtractionFailed {
            digest: layer.digest.clone(),
            reason: e.to_string(),
        })? {
            let mut entry = entry.map_err(|e| Error::LayerExtractionFailed {
                digest: layer.digest.clone(),
                reason: e.to_string(),
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
                let target_path = rootfs.join(path.parent().unwrap_or(Path::new(""))).join(target);
                if target_path.exists() {
                    let _ = fs::remove_file(&target_path);
                    let _ = fs::remove_dir_all(&target_path);
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

            // Unpack
            entry.unpack_in(rootfs).map_err(|e| Error::LayerExtractionFailed {
                digest: layer.digest.clone(),
                reason: e.to_string(),
            })?;
        }
    }

    Ok(())
}
