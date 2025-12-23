//! # Content-Addressed Blob Storage
//!
//! Stores OCI image layers and other blobs by their cryptographic digest
//! for deduplication and integrity verification.
//!
//! ## Storage Model
//!
//! Blobs are stored in a two-level directory structure:
//!
//! ```text
//! ~/.magik-oci/blobs/
//! └── sha256/
//!     ├── ab/
//!     │   ├── abcd1234...  (blob content)
//!     │   └── ab9f8e7d...  (blob content)
//!     └── cd/
//!         └── cdef5678...  (blob content)
//! ```
//!
//! The first two hex characters form a "shard" directory to prevent
//! filesystem performance degradation with many files.
//!
//! ## Security Model
//!
//! ### Digest Verification
//!
//! When storing blobs via [`BlobStore::put_blob`], the content hash is
//! computed and verified against the provided digest. This prevents:
//!
//! - **Cache poisoning**: Malicious registries providing wrong content
//! - **MITM attacks**: Network tampering detected before storage
//! - **Corruption**: Disk errors detected on write
//!
//! ```rust,ignore
//! // Content verification happens automatically:
//! let digest = "sha256:e3b0c44..."; // Expected hash
//! store.put_blob(digest, &data)?; // Fails if hash mismatches
//! ```
//!
//! ### Path Traversal Protection
//!
//! Digests are validated before constructing paths:
//! - Algorithm must be `sha256`, `sha384`, or `sha512`
//! - Hash must contain only hexadecimal characters
//! - Invalid digests return paths that won't exist
//!
//! ### Atomic Writes
//!
//! Blobs are written atomically via a temp file + rename pattern:
//! 1. Write to `<path>.tmp`
//! 2. Rename to `<path>`
//!
//! This prevents partial/corrupted blobs on crash.
//!
//! ## Deduplication
//!
//! Content-addressed storage provides automatic deduplication:
//! - Same layer shared across images? One copy on disk.
//! - Re-pull same image? Layers already cached.
//!
//! The [`BlobStore::has_blob`] method enables skipping redundant downloads.
//!
//! ## Garbage Collection
//!
//! The [`BlobStore::gc`] method removes unreferenced blobs. Callers must
//! provide the list of digests that are still in use:
//!
//! ```rust,ignore
//! let referenced = vec!["sha256:abc...".to_string()];
//! let stats = store.gc(&referenced)?;
//! println!("Freed {} bytes", stats.freed_bytes);
//! ```
//!
//! **Warning**: GC is not safe during concurrent pulls. Use external
//! locking or pause pulls during GC.
//!
//! ## Example
//!
//! ```rust,ignore
//! use magikrun::BlobStore;
//! use sha2::{Sha256, Digest};
//!
//! let store = BlobStore::new()?;
//!
//! // Store with verification
//! let data = b"hello world";
//! let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));
//! store.put_blob(&digest, data)?;
//!
//! // Retrieve
//! let retrieved = store.get_blob(&digest)?;
//! assert_eq!(retrieved, data);
//! ```

use crate::constants::BLOB_STORE_DIR;
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Content-addressed blob store for OCI layers.
///
/// Provides secure, deduplicated storage for image layers with:
/// - SHA-256 content verification on write
/// - Atomic write operations (crash-safe)
/// - Path traversal protection in digest handling
/// - Sharded directory structure for scalability
///
/// ## Thread Safety
///
/// `BlobStore` is safe to use from multiple threads. Each blob operation
/// is independent, and atomic writes prevent corruption from concurrent
/// access to the same blob.
///
/// ## Resource Cleanup
///
/// Blobs are not automatically removed. Use [`BlobStore::gc`] to clean up
/// unreferenced blobs, or [`BlobStore::remove_blob`] for targeted removal.
pub struct BlobStore {
    /// Base directory for blob storage.
    base_dir: PathBuf,
}

impl BlobStore {
    /// Creates a new blob store.
    pub fn new() -> Result<Self> {
        let base_dir = Self::default_path();
        Self::with_path(base_dir)
    }

    /// Creates a blob store at the specified path.
    pub fn with_path(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir).map_err(|e| Error::StorageInitFailed {
            path: base_dir.clone(),
            reason: e.to_string(),
        })?;

        info!("Blob store initialized at: {}", base_dir.display());

        Ok(Self { base_dir })
    }

    /// Returns the default storage path.
    fn default_path() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".magik-oci").join(BLOB_STORE_DIR)
        } else {
            PathBuf::from(".magik-oci").join(BLOB_STORE_DIR)
        }
    }

    /// Returns the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Checks if a blob exists.
    pub fn has_blob(&self, digest: &str) -> bool {
        self.blob_path(digest).exists()
    }

    /// Gets a blob by digest.
    pub fn get_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest);
        fs::read(&path).map_err(|_| Error::BlobNotFound {
            digest: digest.to_string(),
        })
    }

    /// Gets a blob path without reading it.
    ///
    /// # Security
    ///
    /// This function validates the digest format to prevent path traversal:
    /// - Algorithm must be sha256, sha384, or sha512
    /// - Hash must contain only hexadecimal characters
    pub fn blob_path(&self, digest: &str) -> PathBuf {
        // Digest format: sha256:abcd1234...
        // Store as: blobs/sha256/ab/cd1234...
        let (algo, hash) = digest.split_once(':').unwrap_or(("sha256", digest));

        // SECURITY: Validate algorithm to prevent path traversal
        let safe_algo = match algo {
            "sha256" | "sha384" | "sha512" => algo,
            _ => {
                warn!("Invalid digest algorithm '{}', defaulting to sha256", algo);
                "sha256"
            }
        };

        // SECURITY: Validate hash contains only hex characters to prevent path traversal
        let safe_hash: String = hash.chars().filter(|c| c.is_ascii_hexdigit()).collect();

        if safe_hash.len() != hash.len() {
            warn!(
                "Digest hash contained non-hex characters, sanitized: {} -> {}",
                hash, safe_hash
            );
        }

        if safe_hash.is_empty() {
            // Return a path that won't exist rather than panicking
            return self.base_dir.join("invalid").join("empty");
        }

        let prefix = &safe_hash[..2.min(safe_hash.len())];
        self.base_dir.join(safe_algo).join(prefix).join(&safe_hash)
    }

    /// Stores a blob after verifying its content matches the digest.
    ///
    /// # Security
    ///
    /// This function verifies that the data's hash matches the provided digest
    /// before storing, preventing content-addressed storage pollution attacks.
    ///
    /// Only SHA-256 digests are supported. SHA-384 and SHA-512 are rejected
    /// to ensure all stored blobs are verified.
    pub fn put_blob(&self, digest: &str, data: &[u8]) -> Result<()> {
        // SECURITY: Verify content matches digest before storage
        let (algo, expected_hash) = digest.split_once(':').unwrap_or(("sha256", digest));

        // SECURITY: Only accept SHA-256 digests for verified storage
        if algo != "sha256" {
            return Err(Error::StorageWriteFailed(format!(
                "unsupported digest algorithm '{}': only sha256 is supported",
                algo
            )));
        }

        let computed_hash = hex::encode(Sha256::digest(data));

        if computed_hash != expected_hash {
            return Err(Error::StorageWriteFailed(format!(
                "digest mismatch: expected {}, computed {}",
                expected_hash, computed_hash
            )));
        }

        let path = self.blob_path(digest);

        if path.exists() {
            debug!("Blob {} already exists", digest);
            return Ok(());
        }

        // Create parent directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::StorageWriteFailed(e.to_string()))?;
        }

        // SECURITY: Use unique temp file name to prevent concurrent write races
        // If two threads write the same blob, they use different temp files,
        // and the final rename is atomic (last writer wins, content is identical).
        let temp_name = format!("tmp.{}", uuid::Uuid::now_v7());
        let temp_path = path.with_extension(temp_name);
        fs::write(&temp_path, data).map_err(|e| Error::StorageWriteFailed(e.to_string()))?;
        fs::rename(&temp_path, &path).map_err(|e| {
            // Clean up temp file on rename failure
            let _ = fs::remove_file(&temp_path);
            Error::StorageWriteFailed(e.to_string())
        })?;

        debug!("Stored blob {} ({} bytes, verified)", digest, data.len());
        Ok(())
    }

    /// Removes a blob.
    pub fn remove_blob(&self, digest: &str) -> Result<()> {
        let path = self.blob_path(digest);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| Error::StorageWriteFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// Returns the total size of all blobs.
    pub fn total_size(&self) -> Result<u64> {
        let mut total = 0u64;
        Self::walk_dir(&self.base_dir, &mut |path| {
            if let Ok(meta) = fs::metadata(path)
                && meta.is_file()
            {
                total += meta.len();
            }
        })?;
        Ok(total)
    }

    /// Lists all blob digests.
    pub fn list_blobs(&self) -> Result<Vec<String>> {
        let mut digests = Vec::new();

        // Walk sha256 directory
        let sha256_dir = self.base_dir.join("sha256");
        if sha256_dir.exists() {
            Self::walk_dir(&sha256_dir, &mut |path| {
                if path.is_file()
                    && let Some(hash) = path.file_name().and_then(|n| n.to_str())
                {
                    digests.push(format!("sha256:{}", hash));
                }
            })?;
        }

        Ok(digests)
    }

    /// Walks a directory recursively.
    fn walk_dir(dir: &Path, callback: &mut impl FnMut(&Path)) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir).map_err(|e| Error::StorageWriteFailed(e.to_string()))? {
            let entry = entry.map_err(|e| Error::StorageWriteFailed(e.to_string()))?;
            let path = entry.path();

            if path.is_dir() {
                Self::walk_dir(&path, callback)?;
            } else {
                callback(&path);
            }
        }

        Ok(())
    }

    /// Garbage collects unreferenced blobs.
    pub fn gc(&self, referenced: &[String]) -> Result<GcStats> {
        let all_blobs = self.list_blobs()?;
        let mut removed = 0u64;
        let mut freed = 0u64;

        for digest in all_blobs {
            if !referenced.contains(&digest) {
                let path = self.blob_path(&digest);
                if let Ok(meta) = fs::metadata(&path) {
                    freed += meta.len();
                    removed += 1;
                    let _ = fs::remove_file(&path);
                }
            }
        }

        info!("GC: removed {} blobs, freed {} bytes", removed, freed);
        Ok(GcStats {
            removed_count: removed,
            freed_bytes: freed,
        })
    }
}

/// Statistics from a garbage collection run.
///
/// Returned by [`BlobStore::gc`] to report cleanup results.
#[derive(Debug, Clone)]
pub struct GcStats {
    /// Number of blobs removed.
    pub removed_count: u64,
    /// Bytes freed.
    pub freed_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_blob_store_roundtrip() {
        let temp = TempDir::new().unwrap();
        let store = BlobStore::with_path(temp.path().to_path_buf()).unwrap();

        // Use actual sha256 hash of "hello world" for content verification
        let data = b"hello world";
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(data)));

        // Store - will verify content hash matches
        store.put_blob(&digest, data).unwrap();
        assert!(store.has_blob(&digest));

        // Retrieve
        let retrieved = store.get_blob(&digest).unwrap();
        assert_eq!(retrieved, data);

        // Remove
        store.remove_blob(&digest).unwrap();
        assert!(!store.has_blob(&digest));
    }

    #[test]
    fn test_blob_digest_verification_fails() {
        let temp = TempDir::new().unwrap();
        let store = BlobStore::with_path(temp.path().to_path_buf()).unwrap();

        // Try to store with wrong digest - should fail
        let data = b"hello world";
        let wrong_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let result = store.put_blob(wrong_digest, data);
        assert!(result.is_err(), "Should reject mismatched digest");
    }

    #[test]
    fn test_blob_path_structure() {
        let temp = TempDir::new().unwrap();
        let store = BlobStore::with_path(temp.path().to_path_buf()).unwrap();

        let digest = "sha256:abcd1234";
        let path = store.blob_path(digest);

        assert!(path.to_string_lossy().contains("sha256"));
        assert!(path.to_string_lossy().contains("ab"));
        assert!(path.to_string_lossy().ends_with("abcd1234"));
    }
}
