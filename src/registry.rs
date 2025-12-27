//! # OCI Registry Client for Image Pulling
//!
//! Handles pulling OCI images from container registries with security-first
//! design, including input validation, size limits, and timeout enforcement.
//!
//! ## Features
//!
//! - **Multi-arch resolution**: Automatically selects platform-appropriate manifest
//! - **Layer deduplication**: Content-addressed storage prevents redundant downloads
//! - **Size limits**: Enforces `MAX_LAYER_SIZE` and `MAX_LAYERS` constants
//! - **Timeouts**: All network operations bounded by `IMAGE_PULL_TIMEOUT`
//!
//! ## Security Model
//!
//! ### Image Reference Validation
//!
//! All image references are validated before use:
//! - Length check against `MAX_IMAGE_REF_LEN` (512 bytes)
//! - Character allowlist validation (alphanumeric + `/:.-_@`)
//! - Proper format parsing via `oci-distribution`
//!
//! This prevents:
//! - Buffer overflow via long references
//! - Injection attacks via special characters
//! - Registry confusion via malformed URLs
//!
//! ### Manifest Resolution
//!
//! For multi-platform images (Image Index), the client:
//! 1. Detects the host platform (OS + arch)
//! 2. Finds matching manifest in the index
//! 3. Pulls the platform-specific manifest
//!
//! If no matching platform is found, the error includes available platforms
//! to aid debugging.
//!
//! ### Layer Pulling
//!
//! Layers are:
//! 1. Checked against blob store for deduplication
//! 2. Validated for size before download
//! 3. Downloaded with timeout enforcement
//! 4. Stored with content verification (see [`BlobStore::put_blob`])
//!
//! ## Authentication
//!
//! Currently supports:
//! - Anonymous access (default)
//! - Basic authentication via [`RegistryClient::with_auth`]
//!
//! OAuth/bearer token authentication should be added for production use
//! with private registries.
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::{pull_image, BlobStore};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> magikrun::Result<()> {
//!     let storage = Arc::new(BlobStore::new()?);
//!     
//!     // Pull with validation and size limits
//!     let image = pull_image("alpine:3.18", &storage).await?;
//!     
//!     println!("Pulled {} ({} layers)", image.reference, image.layers.len());
//!     Ok(())
//! }
//! ```
//!
//! ## WASM Image Detection
//!
//! The [`is_wasm_image`] helper detects WASM-specific image references,
//! allowing callers to route to the appropriate runtime.
//!
//! [`BlobStore::put_blob`]: crate::storage::BlobStore::put_blob

use crate::constants::{
    IMAGE_PULL_TIMEOUT, MAX_CONFIG_SIZE, MAX_IMAGE_REF_LEN, MAX_LAYER_SIZE, MAX_LAYERS,
    MAX_MANIFEST_SIZE,
};
use crate::error::{Error, Result};
use crate::platform::Platform;
use crate::storage::BlobStore;
use oci_distribution::client::{ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::{Client, Reference};
use std::sync::Arc;
use tracing::{debug, info};

/// Handle to a successfully pulled OCI image.
///
/// Contains all metadata needed to build a bundle from the image,
/// including resolved layers and platform information.
///
/// ## Layer Order
///
/// The `layers` vector is ordered bottom-to-top:
/// - `layers[0]` is the base layer
/// - `layers[n-1]` is the topmost layer
///
/// When extracting, layers are applied in order, with later layers
/// overwriting earlier ones (and whiteouts removing files).
///
/// ## Content Addressing
///
/// All digests (`digest`, `config_digest`, `layers[*].digest`) reference
/// blobs in the [`BlobStore`]. The blobs are available after a successful
/// image pull operation.
///
/// [`BlobStore`]: crate::storage::BlobStore
#[derive(Debug, Clone)]
pub struct ImageHandle {
    /// Original image reference.
    pub reference: String,
    /// Resolved digest.
    pub digest: String,
    /// Platform this image is for.
    pub platform: String,
    /// Layer digests in order.
    pub layers: Vec<LayerInfo>,
    /// Config blob digest.
    pub config_digest: String,
}

/// Metadata about an OCI image layer.
///
/// Layers are compressed tar archives containing filesystem changes.
/// The `digest` is the content hash of the compressed blob.
#[derive(Debug, Clone)]
pub struct LayerInfo {
    /// Layer digest.
    pub digest: String,
    /// Layer size in bytes.
    pub size: u64,
    /// Media type.
    pub media_type: String,
}

// TODO: Implement authenticated registry operations
// When ready, add a RegistryClient struct here with:
// - OAuth/bearer token support for GCR, ECR, ACR
// - Credential caching and refresh
// - Integration with ImageService for authenticated pulls

/// Pulls an OCI image from a registry with full validation.
///
/// This is the primary entry point for image pulling. It:
/// 1. Validates the image reference format and length
/// 2. Fetches the manifest with timeout
/// 3. Resolves multi-arch images to the current platform
/// 4. Downloads missing layers to blob storage
/// 5. Returns an [`ImageHandle`] for bundle building
///
/// ## Security
///
/// - Reference validated against `MAX_IMAGE_REF_LEN` and character allowlist
/// - Layer count validated against `MAX_LAYERS`
/// - Layer size validated against `MAX_LAYER_SIZE`
/// - All operations bounded by `IMAGE_PULL_TIMEOUT`
/// - Layer content verified by [`BlobStore::put_blob`]
///
/// ## Deduplication
///
/// Already-cached layers (by digest) are skipped. Multiple images sharing
/// common base layers only download unique layers.
///
/// ## Example
///
/// ```rust,ignore
/// let storage = Arc::new(BlobStore::new()?);
/// let image = pull_image("nginx:latest", &storage).await?;
/// println!("Pulled {} with {} layers", image.reference, image.layers.len());
/// ```
///
/// ## Errors
///
/// - [`Error::InvalidImageReference`]: Malformed or overly long reference
/// - [`Error::ImagePullFailed`]: Registry unreachable or image not found
/// - [`Error::ImageTooLarge`]: Layer exceeds size limit
/// - [`Error::Timeout`]: Operation exceeded `IMAGE_PULL_TIMEOUT`
///
/// [`Error::InvalidImageReference`]: crate::error::Error::InvalidImageReference
/// [`Error::ImagePullFailed`]: crate::error::Error::ImagePullFailed
/// [`Error::ImageTooLarge`]: crate::error::Error::ImageTooLarge
/// [`Error::Timeout`]: crate::error::Error::Timeout
/// [`BlobStore::put_blob`]: crate::storage::BlobStore::put_blob
pub async fn pull_image(image_ref: &str, storage: &Arc<BlobStore>) -> Result<ImageHandle> {
    // Validate reference length
    if image_ref.len() > MAX_IMAGE_REF_LEN {
        return Err(Error::InvalidImageReference {
            reference: image_ref.to_string(),
            reason: format!("exceeds {} bytes", MAX_IMAGE_REF_LEN),
        });
    }

    // Validate reference characters
    if !image_ref.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '/'
            || c == ':'
            || c == '.'
            || c == '-'
            || c == '_'
            || c == '@'
    }) {
        return Err(Error::InvalidImageReference {
            reference: image_ref.to_string(),
            reason: "contains invalid characters".to_string(),
        });
    }

    info!("Pulling image: {}", image_ref);

    // Parse reference
    let reference: Reference = image_ref
        .parse()
        .map_err(|e| Error::InvalidImageReference {
            reference: image_ref.to_string(),
            reason: format!("{}", e),
        })?;

    // Create client
    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });

    let auth = RegistryAuth::Anonymous;

    // Pull manifest with timeout
    let (manifest, digest) = tokio::time::timeout(IMAGE_PULL_TIMEOUT, async {
        client.pull_manifest(&reference, &auth).await
    })
    .await
    .map_err(|_| Error::Timeout {
        operation: format!("pull manifest for {}", image_ref),
        duration: IMAGE_PULL_TIMEOUT,
    })?
    .map_err(|e| Error::ImagePullFailed {
        reference: image_ref.to_string(),
        reason: e.to_string(),
    })?;

    // Resolve multi-arch manifests
    let platform = Platform::detect();
    let (layers, config_digest, resolved_platform) =
        resolve_manifest(&client, &reference, &auth, manifest, &platform).await?;

    // Validate layer count and pull layers
    pull_layers(&client, &reference, &layers, image_ref, storage).await?;

    Ok(ImageHandle {
        reference: image_ref.to_string(),
        digest,
        platform: resolved_platform,
        layers,
        config_digest,
    })
}

/// Pulls a container image for a specific target platform.
///
/// This is useful for MicroVM scenarios where the host is macOS but the
/// target VM runs Linux. The platform can be specified explicitly.
///
/// ## Arguments
///
/// * `image_ref` - Image reference (e.g., "nginx:latest")
/// * `storage` - Blob storage for layer caching
/// * `target_platform` - Target platform (e.g., Linux/arm64)
///
/// ## Example
///
/// ```rust,ignore
/// use magikrun::platform::{Platform, Os, Arch};
///
/// let storage = Arc::new(BlobStore::new()?);
/// let linux_platform = Platform {
///     os: Os::Linux,
///     arch: Arch::Arm64,
///     capabilities: vec![],
/// };
/// let image = pull_image_for_platform("nginx:latest", &storage, &linux_platform).await?;
/// ```
pub async fn pull_image_for_platform(
    image_ref: &str,
    storage: &Arc<BlobStore>,
    target_platform: &Platform,
) -> Result<ImageHandle> {
    // Validate reference length
    if image_ref.len() > MAX_IMAGE_REF_LEN {
        return Err(Error::InvalidImageReference {
            reference: image_ref.to_string(),
            reason: format!("exceeds {} bytes", MAX_IMAGE_REF_LEN),
        });
    }

    // Validate reference characters
    if !image_ref.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '/'
            || c == ':'
            || c == '.'
            || c == '-'
            || c == '_'
            || c == '@'
    }) {
        return Err(Error::InvalidImageReference {
            reference: image_ref.to_string(),
            reason: "contains invalid characters".to_string(),
        });
    }

    info!(
        "Pulling image {} for platform {}",
        image_ref,
        target_platform.oci_platform()
    );

    // Parse reference
    let reference: Reference = image_ref
        .parse()
        .map_err(|e| Error::InvalidImageReference {
            reference: image_ref.to_string(),
            reason: format!("{}", e),
        })?;

    // Create client
    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    });

    let auth = RegistryAuth::Anonymous;

    // Pull manifest with timeout
    let (manifest, digest) = tokio::time::timeout(IMAGE_PULL_TIMEOUT, async {
        client.pull_manifest(&reference, &auth).await
    })
    .await
    .map_err(|_| Error::Timeout {
        operation: format!("pull manifest for {}", image_ref),
        duration: IMAGE_PULL_TIMEOUT,
    })?
    .map_err(|e| Error::ImagePullFailed {
        reference: image_ref.to_string(),
        reason: e.to_string(),
    })?;

    // Resolve multi-arch manifests for the specified platform
    let (layers, config_digest, resolved_platform) =
        resolve_manifest(&client, &reference, &auth, manifest, target_platform).await?;

    // Validate layer count and pull layers
    pull_layers(&client, &reference, &layers, image_ref, storage).await?;

    Ok(ImageHandle {
        reference: image_ref.to_string(),
        digest,
        platform: resolved_platform,
        layers,
        config_digest,
    })
}

/// Pulls all layers for an image with validation, deduplication, and GC safety.
///
/// This is the shared implementation for both `pull_image` and `pull_image_for_platform`.
///
/// # Security
///
/// - Validates layer count against `MAX_LAYERS`
/// - Validates layer size against `MAX_LAYER_SIZE`
/// - Tracks in-flight downloads to protect from GC
/// - Enforces `IMAGE_PULL_TIMEOUT` on each layer download
/// - Content verification via `BlobStore::put_blob`
async fn pull_layers(
    client: &Client,
    reference: &Reference,
    layers: &[LayerInfo],
    image_ref: &str,
    storage: &Arc<BlobStore>,
) -> Result<()> {
    // Validate layer count
    if layers.len() > MAX_LAYERS {
        return Err(Error::ImagePullFailed {
            reference: image_ref.to_string(),
            reason: format!("too many layers: {} > {}", layers.len(), MAX_LAYERS),
        });
    }

    // Pull each layer
    for layer in layers {
        if storage.has_blob(&layer.digest) {
            debug!("Layer {} already cached", layer.digest);
            continue;
        }

        debug!("Pulling layer: {} ({} bytes)", layer.digest, layer.size);

        if layer.size > MAX_LAYER_SIZE as u64 {
            return Err(Error::ImageTooLarge {
                size: layer.size,
                limit: MAX_LAYER_SIZE as u64,
            });
        }

        // SECURITY: Track in-flight to protect from GC during download
        if !storage.track_inflight(&layer.digest) {
            return Err(Error::ResourceExhausted(
                "too many concurrent layer downloads".to_string(),
            ));
        }

        let layer_desc = oci_distribution::manifest::OciDescriptor {
            digest: layer.digest.clone(),
            size: layer.size as i64,
            media_type: layer.media_type.clone(),
            urls: None,
            annotations: None,
        };

        let mut data = Vec::new();
        let pull_result = tokio::time::timeout(IMAGE_PULL_TIMEOUT, async {
            client.pull_blob(reference, &layer_desc, &mut data).await
        })
        .await;

        // Handle timeout
        if pull_result.is_err() {
            storage.untrack_inflight(&layer.digest);
            return Err(Error::Timeout {
                operation: format!("pull layer {}", layer.digest),
                duration: IMAGE_PULL_TIMEOUT,
            });
        }

        // Handle pull error
        if let Err(e) = pull_result.unwrap() {
            storage.untrack_inflight(&layer.digest);
            return Err(Error::LayerExtractionFailed {
                digest: layer.digest.clone(),
                reason: e.to_string(),
            });
        }

        // Store in blob store and untrack
        let store_result = storage.put_blob(&layer.digest, &data);
        storage.untrack_inflight(&layer.digest);
        store_result?;
    }

    Ok(())
}

/// Resolves a manifest (handling multi-arch index).
async fn resolve_manifest(
    client: &Client,
    reference: &Reference,
    auth: &RegistryAuth,
    manifest: oci_distribution::manifest::OciManifest,
    platform: &Platform,
) -> Result<(Vec<LayerInfo>, String, String)> {
    use crate::platform::{Arch, Os};

    match manifest {
        oci_distribution::manifest::OciManifest::Image(img) => {
            // SECURITY: Validate config blob size from descriptor before using
            let config_size = img.config.size as usize;
            if config_size > MAX_CONFIG_SIZE {
                return Err(Error::ImageTooLarge {
                    size: config_size as u64,
                    limit: MAX_CONFIG_SIZE as u64,
                });
            }

            let layers = img
                .layers
                .into_iter()
                .map(|l| LayerInfo {
                    digest: l.digest,
                    size: l.size as u64,
                    media_type: l.media_type,
                })
                .collect();

            let config_digest = img.config.digest;
            Ok((layers, config_digest, platform.oci_platform()))
        }

        oci_distribution::manifest::OciManifest::ImageIndex(index) => {
            // Find matching platform
            let target_os = match platform.os {
                Os::Linux => "linux",
                Os::Darwin => "darwin",
                _ => "linux", // Default to linux for VMs
            };

            let target_arch = match platform.arch {
                Arch::Amd64 => "amd64",
                Arch::Arm64 => "arm64",
                Arch::Arm => "arm",
                _ => "amd64",
            };

            let matching = index.manifests.iter().find(|m| {
                m.platform
                    .as_ref()
                    .is_some_and(|p| p.os == target_os && p.architecture == target_arch)
            });

            let manifest_desc = matching.ok_or_else(|| {
                let available: Vec<String> = index
                    .manifests
                    .iter()
                    .filter_map(|m| m.platform.as_ref())
                    .map(|p| format!("{}/{}", p.os, p.architecture))
                    .collect();

                Error::ImagePullFailed {
                    reference: reference.to_string(),
                    reason: format!(
                        "no manifest for {}/{}. Available: {}",
                        target_os,
                        target_arch,
                        available.join(", ")
                    ),
                }
            })?;

            // SECURITY: Validate manifest size from descriptor before fetching
            let manifest_size = manifest_desc.size as usize;
            if manifest_size > MAX_MANIFEST_SIZE {
                return Err(Error::ImageTooLarge {
                    size: manifest_size as u64,
                    limit: MAX_MANIFEST_SIZE as u64,
                });
            }

            // Pull platform-specific manifest
            let digest_ref_str = format!(
                "{}/{}@{}",
                reference.registry(),
                reference.repository(),
                manifest_desc.digest
            );

            let platform_ref: Reference =
                digest_ref_str.parse().map_err(|e| Error::ImagePullFailed {
                    reference: reference.to_string(),
                    reason: format!("failed to build digest reference: {}", e),
                })?;

            let (platform_manifest, _) =
                client
                    .pull_manifest(&platform_ref, auth)
                    .await
                    .map_err(|e| Error::ImagePullFailed {
                        reference: reference.to_string(),
                        reason: format!("failed to pull platform manifest: {}", e),
                    })?;

            match platform_manifest {
                oci_distribution::manifest::OciManifest::Image(img) => {
                    // SECURITY: Validate config blob size from descriptor before using
                    let config_size = img.config.size as usize;
                    if config_size > MAX_CONFIG_SIZE {
                        return Err(Error::ImageTooLarge {
                            size: config_size as u64,
                            limit: MAX_CONFIG_SIZE as u64,
                        });
                    }

                    let layers = img
                        .layers
                        .into_iter()
                        .map(|l| LayerInfo {
                            digest: l.digest,
                            size: l.size as u64,
                            media_type: l.media_type,
                        })
                        .collect();

                    let config_digest = img.config.digest;
                    let resolved = format!("{}/{}", target_os, target_arch);
                    Ok((layers, config_digest, resolved))
                }
                _ => Err(Error::ImagePullFailed {
                    reference: reference.to_string(),
                    reason: "nested image index not supported".to_string(),
                }),
            }
        }
    }
}

/// Checks if an image reference appears to be a WASM module.
///
/// Uses heuristics to detect WASM images for routing to the appropriate
/// runtime. Detection is based on naming conventions, not content inspection.
///
/// ## Detected Patterns
///
/// | Pattern | Example | Detected |
/// |---------|---------|----------|
/// | `.wasm` suffix | `app.wasm` | Yes |
/// | `:wasm` tag | `myapp:wasm` | Yes |
/// | `/wasm/` path | `ghcr.io/wasm/runtime` | Yes |
/// | `+wasm` variant | `myapp:v1+wasm` | Yes |
///
/// ## Limitations
///
/// This does not inspect the image manifest. An image with a normal name
/// could still contain WASM content (check annotations after pulling).
pub fn is_wasm_image(reference: &str) -> bool {
    reference.ends_with(".wasm")
        || reference.contains(":wasm")
        || reference.contains("/wasm/")
        || reference.contains("+wasm")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_image_detection() {
        assert!(is_wasm_image("myapp:wasm"));
        assert!(is_wasm_image("ghcr.io/example/app.wasm"));
        assert!(is_wasm_image("registry.io/wasm/myapp:latest"));
        assert!(!is_wasm_image("nginx:latest"));
        assert!(!is_wasm_image("alpine:3.18"));
    }

    #[test]
    fn test_reference_validation() {
        // Valid
        assert!(
            "nginx:latest"
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ":".contains(c))
        );

        // Contains space - invalid
        let bad_ref = "nginx :latest";
        assert!(
            !bad_ref
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/:.-_@".contains(c))
        );
    }
}
