//! # Image Service - CRI-Compatible Image Management
//!
//! This is the **image facade module** for magikrun, providing:
//!
//! - **ImageService**: Pull, list, query, and remove images
//! - **ImageHandle**: Metadata for a pulled image
//! - **BundleBuilder**: Convert pulled images to OCI bundles
//! - **Bundle**: Ready-to-run container bundle
//!
//! ## CRI Alignment
//!
//! | CRI ImageService    | magikrun ImageService     |
//! |---------------------|---------------------------|
//! | `PullImage`         | `pull()` / `pull_for_platform()` |
//! | `ImageStatus`       | `exists()`                |
//! | `ListImages`        | `list()`                  |
//! | `RemoveImage`       | `remove()`                |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                       Image Facade                                  │
//! │                                                                     │
//! │  ImageService            BundleBuilder                              │
//! │  ├── pull() → ImageHandle   ├── build_oci_bundle() → Bundle        │
//! │  ├── exists()               └── build_wasm_bundle() → Bundle       │
//! │  ├── list()                                                         │
//! │  └── remove()                                                       │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                          Internal                                   │
//! │  ┌─────────────────┐  ┌─────────────────┐                           │
//! │  │  RegistryClient │  │    BlobStore    │                           │
//! │  │  (OCI registry) │  │  (layer cache)  │                           │
//! │  └─────────────────┘  └─────────────────┘                           │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use magikrun::image::{ImageService, BundleBuilder, OciContainerConfig};
//!
//! let image_service = ImageService::new()?;
//! let builder = BundleBuilder::with_storage(image_service.storage().clone())?;
//!
//! // Pull image
//! let image = image_service.pull("nginx:1.25").await?;
//!
//! // Build bundle
//! let bundle = builder.build_oci_bundle(&image, &OciContainerConfig {
//!     name: "my-nginx".to_string(),
//!     ..Default::default()
//! })?;
//!
//! // Bundle ready for runtime.create()
//! ```
//!
//! ## Security Model
//!
//! - Image reference length validated against [`MAX_IMAGE_REF_LEN`]
//! - All pulls verify digest integrity via content-addressed storage
//! - Layer sizes bounded by [`MAX_LAYER_SIZE`]
//! - Network operations bounded by [`IMAGE_PULL_TIMEOUT`]
//!
//! [`MAX_IMAGE_REF_LEN`]: crate::constants::MAX_IMAGE_REF_LEN
//! [`MAX_LAYER_SIZE`]: crate::constants::MAX_LAYER_SIZE
//! [`IMAGE_PULL_TIMEOUT`]: crate::constants::IMAGE_PULL_TIMEOUT

use crate::registry::{pull_image, pull_image_for_platform};
use std::sync::Arc;

// =============================================================================
// Re-exports (unified image API surface)
// =============================================================================

// Error types
pub use crate::error::{Error, Result};

// Platform detection (needed for cross-platform image pulls)
pub use crate::platform::{Arch, Capability, Os, Platform};

// Image metadata (returned from pull)
pub use crate::registry::ImageHandle;

// WASM image detection helper
pub use crate::registry::is_wasm_image;

// Storage (for custom storage configurations and testing)
pub use crate::storage::BlobStore;

// Bundle building (converts ImageHandle → Bundle)
pub use crate::bundle::{Bundle, BundleBuilder, BundleFormat, OciContainerConfig};

// Layer extraction (exposed for testing security properties)
// SECURITY: Only available with `testing` feature to prevent production misuse
#[cfg(feature = "testing")]
pub use crate::bundle::extract_layers_to_rootfs;

// Layer metadata (exposed for testing)
// SECURITY: Only available with `testing` feature to prevent production misuse
#[cfg(feature = "testing")]
pub use crate::registry::LayerInfo;

// Security constants for image handling (public API for consumers to reference)
pub use crate::constants::{
    // Storage paths (for custom storage configuration)
    BLOB_STORE_DIR,
    BUNDLE_DIR,
    // Size and count limits
    IMAGE_PULL_TIMEOUT,
    // Validation
    IMAGE_REF_VALID_CHARS,
    MAX_IMAGE_REF_LEN,
    MAX_LAYER_SIZE,
    MAX_LAYERS,
    MAX_ROOTFS_SIZE,
    // OCI media types (for registry interaction)
    OCI_IMAGE_CONFIG_MEDIA_TYPE,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    // OCI spec version
    OCI_IMAGE_SPEC_VERSION,
    OCI_LAYER_MEDIA_TYPE_GZIP,
    OCI_LAYER_MEDIA_TYPE_TAR,
    OCI_LAYER_MEDIA_TYPE_ZSTD,
    // WASM media types
    WASM_CONFIG_MEDIA_TYPE,
    WASM_LAYER_MEDIA_TYPE,
    WASM_VARIANT_ANNOTATION,
};

/// Image metadata for listing.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// Image digest (content-addressed ID).
    pub digest: String,
    /// Size in bytes (sum of layers).
    pub size: u64,
}

/// CRI-compatible image service.
///
/// Manages container images: pull, query, and remove.
/// Thread-safe and designed for shared use.
pub struct ImageService {
    /// Blob storage for layer caching and deduplication.
    storage: Arc<BlobStore>,
}

impl ImageService {
    /// Creates a new image service with default storage paths.
    ///
    /// # Errors
    ///
    /// Returns error if storage directory cannot be created.
    pub fn new() -> Result<Self> {
        let storage = Arc::new(BlobStore::new()?);
        Ok(Self { storage })
    }

    /// Creates an image service with custom storage.
    ///
    /// Useful for sharing storage across multiple services.
    pub fn with_storage(storage: Arc<BlobStore>) -> Self {
        Self { storage }
    }

    /// Returns a reference to the underlying blob storage.
    ///
    /// Needed by [`BundleBuilder`] for layer extraction.
    ///
    /// [`BundleBuilder`]: crate::bundle::BundleBuilder
    pub fn storage(&self) -> &Arc<BlobStore> {
        &self.storage
    }

    /// Pulls an image from a registry.
    ///
    /// Automatically detects the host platform and pulls the matching
    /// image variant.
    ///
    /// # Arguments
    ///
    /// * `image_ref` - Image reference (e.g., `nginx:1.25`, `ghcr.io/foo/bar:latest`)
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidImageReference`] if reference is invalid
    /// - [`Error::ImagePullFailed`] if pull fails
    /// - [`Error::Timeout`] if pull exceeds [`IMAGE_PULL_TIMEOUT`]
    ///
    /// [`IMAGE_PULL_TIMEOUT`]: crate::constants::IMAGE_PULL_TIMEOUT
    pub async fn pull(&self, image_ref: &str) -> Result<ImageHandle> {
        self.validate_image_ref(image_ref)?;
        pull_image(image_ref, &self.storage).await
    }

    /// Pulls an image for a specific platform.
    ///
    /// Use when the target platform differs from the host, e.g.,
    /// when building rootfs for MicroVMs that always run Linux.
    ///
    /// # Arguments
    ///
    /// * `image_ref` - Image reference
    /// * `platform` - Target platform (OS/arch)
    pub async fn pull_for_platform(
        &self,
        image_ref: &str,
        platform: &Platform,
    ) -> Result<ImageHandle> {
        self.validate_image_ref(image_ref)?;
        pull_image_for_platform(image_ref, &self.storage, platform).await
    }

    /// Checks if an image exists in local storage.
    ///
    /// This checks if all layers are present, not just the manifest.
    ///
    /// # Arguments
    ///
    /// * `digest` - Image digest (from [`ImageHandle::digest`])
    pub fn exists(&self, digest: &str) -> bool {
        self.storage.has_blob(digest)
    }

    /// Lists all cached images.
    ///
    /// Returns basic metadata for each cached image.
    /// Note: This lists blobs, not full image metadata.
    pub fn list(&self) -> Result<Vec<ImageInfo>> {
        let blobs = self.storage.list_blobs()?;
        Ok(blobs
            .into_iter()
            .map(|digest| ImageInfo { digest, size: 0 }) // Size requires reading blob
            .collect())
    }

    /// Removes an image from local storage.
    ///
    /// Removes the manifest and any layers not referenced by other images.
    ///
    /// # Arguments
    ///
    /// * `digest` - Image digest to remove
    ///
    /// # Warning
    ///
    /// This may remove shared layers. Use with caution in multi-image
    /// environments. Consider using garbage collection instead.
    pub fn remove(&self, digest: &str) -> Result<()> {
        self.storage.remove_blob(digest)
    }

    /// Validates an image reference.
    fn validate_image_ref(&self, image_ref: &str) -> Result<()> {
        if image_ref.is_empty() {
            return Err(Error::InvalidImageReference {
                reference: image_ref.to_string(),
                reason: "empty image reference".to_string(),
            });
        }
        if image_ref.len() > MAX_IMAGE_REF_LEN {
            return Err(Error::InvalidImageReference {
                reference: image_ref.chars().take(50).collect::<String>() + "...",
                reason: format!("exceeds maximum length of {} bytes", MAX_IMAGE_REF_LEN),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_image_ref_rejects_empty() {
        let service = ImageService::new().unwrap();
        let result = service.validate_image_ref("");
        assert!(result.is_err());
    }

    #[test]
    fn validate_image_ref_rejects_too_long() {
        let service = ImageService::new().unwrap();
        let long_ref = "a".repeat(MAX_IMAGE_REF_LEN + 1);
        let result = service.validate_image_ref(&long_ref);
        assert!(result.is_err());
    }

    #[test]
    fn validate_image_ref_accepts_valid() {
        let service = ImageService::new().unwrap();
        assert!(service.validate_image_ref("nginx:1.25").is_ok());
        assert!(service.validate_image_ref("ghcr.io/foo/bar:latest").is_ok());
        assert!(
            service
                .validate_image_ref("registry.example.com:5000/image@sha256:abc123")
                .is_ok()
        );
    }
}
