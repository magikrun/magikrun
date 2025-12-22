//! OCI registry client for image pulling.
//!
//! Handles pulling OCI images from container registries with:
//! - Multi-arch manifest resolution
//! - Layer deduplication via content-addressed storage
//! - Size limits and validation

use crate::constants::{IMAGE_PULL_TIMEOUT, MAX_IMAGE_REF_LEN, MAX_LAYERS, MAX_LAYER_SIZE};
use crate::error::{Error, Result};
use crate::platform::Platform;
use crate::storage::BlobStore;
use oci_distribution::client::{ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::{Client, Reference};
use std::sync::Arc;
use tracing::{debug, info};

/// Handle to a pulled image.
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

/// Information about an image layer.
#[derive(Debug, Clone)]
pub struct LayerInfo {
    /// Layer digest.
    pub digest: String,
    /// Layer size in bytes.
    pub size: u64,
    /// Media type.
    pub media_type: String,
}

/// OCI registry client wrapper.
pub struct RegistryClient {
    client: Client,
    auth: RegistryAuth,
}

impl RegistryClient {
    /// Creates a new registry client with anonymous auth.
    pub fn new() -> Self {
        Self {
            client: Client::new(ClientConfig {
                protocol: ClientProtocol::Https,
                ..Default::default()
            }),
            auth: RegistryAuth::Anonymous,
        }
    }

    /// Creates a client with basic auth.
    pub fn with_auth(username: &str, password: &str) -> Self {
        Self {
            client: Client::new(ClientConfig {
                protocol: ClientProtocol::Https,
                ..Default::default()
            }),
            auth: RegistryAuth::Basic(username.to_string(), password.to_string()),
        }
    }
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Pulls an image from a registry.
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
    let reference: Reference = image_ref.parse().map_err(|e| Error::InvalidImageReference {
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

    // Validate layer count
    if layers.len() > MAX_LAYERS {
        return Err(Error::ImagePullFailed {
            reference: image_ref.to_string(),
            reason: format!("too many layers: {} > {}", layers.len(), MAX_LAYERS),
        });
    }

    // Pull layers
    for layer in &layers {
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

        let layer_desc = oci_distribution::manifest::OciDescriptor {
            digest: layer.digest.clone(),
            size: layer.size as i64,
            media_type: layer.media_type.clone(),
            urls: None,
            annotations: None,
        };

        let mut data = Vec::new();
        tokio::time::timeout(IMAGE_PULL_TIMEOUT, async {
            client.pull_blob(&reference, &layer_desc, &mut data).await
        })
        .await
        .map_err(|_| Error::Timeout {
            operation: format!("pull layer {}", layer.digest),
            duration: IMAGE_PULL_TIMEOUT,
        })?
        .map_err(|e| Error::LayerExtractionFailed {
            digest: layer.digest.clone(),
            reason: e.to_string(),
        })?;

        // Store in blob store
        storage.put_blob(&layer.digest, &data)?;
    }

    Ok(ImageHandle {
        reference: image_ref.to_string(),
        digest,
        platform: resolved_platform,
        layers,
        config_digest,
    })
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

            // Pull platform-specific manifest
            let digest_ref_str = format!(
                "{}/{}@{}",
                reference.registry(),
                reference.repository(),
                manifest_desc.digest
            );

            let platform_ref: Reference = digest_ref_str.parse().map_err(|e| {
                Error::ImagePullFailed {
                    reference: reference.to_string(),
                    reason: format!("failed to build digest reference: {}", e),
                }
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

/// Checks if an image reference looks like a WASM module.
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
        assert!("nginx:latest"
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":".contains(c)));

        // Contains space - invalid
        let bad_ref = "nginx :latest";
        assert!(!bad_ref
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/:.-_@".contains(c)));
    }
}
