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
//! ~/.magikrun/blobs/
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

use crate::constants::{BLOB_STORE_DIR, MAX_INFLIGHT_BLOBS};
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

/// Content-addressed blob store for OCI layers.
///
/// Provides secure, deduplicated storage for image layers with:
/// - SHA-256 content verification on write
/// - Atomic write operations (crash-safe)
/// - Path traversal protection in digest handling
/// - Sharded directory structure for scalability
/// - GC-safe in-flight blob tracking
///
/// ## Thread Safety
///
/// `BlobStore` is safe to use from multiple threads. Each blob operation
/// is independent, and atomic writes prevent corruption from concurrent
/// access to the same blob.
///
/// ## GC Safety
///
/// Use [`BlobStore::track_inflight`] before downloading a blob and
/// [`BlobStore::untrack_inflight`] after storing it. The [`BlobStore::gc`]
/// method will skip any digests that are currently in-flight.
///
/// ## Resource Cleanup
///
/// Blobs are not automatically removed. Use [`BlobStore::gc`] to clean up
/// unreferenced blobs, or [`BlobStore::remove_blob`] for targeted removal.
pub struct BlobStore {
    /// Base directory for blob storage.
    base_dir: PathBuf,
    /// Set of digests currently being downloaded (GC-protected).
    ///
    /// SECURITY: Prevents race conditions where GC removes a blob
    /// that is being written by a concurrent pull operation.
    inflight: Arc<RwLock<HashSet<String>>>,
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

        Ok(Self {
            base_dir,
            inflight: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    /// Returns the default storage path.
    fn default_path() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".magikrun").join(BLOB_STORE_DIR)
        } else {
            PathBuf::from(".magikrun").join(BLOB_STORE_DIR)
        }
    }

    /// Returns the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Marks a digest as in-flight (being downloaded).
    ///
    /// Call this BEFORE starting a blob download to protect it from GC.
    /// Call [`Self::untrack_inflight`] after the blob is stored.
    ///
    /// # Returns
    ///
    /// `true` if tracking succeeded, `false` if the limit was reached.
    ///
    /// # Security
    ///
    /// Enforces `MAX_INFLIGHT_BLOBS` to prevent memory exhaustion from
    /// unbounded concurrent downloads.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if !store.track_inflight(&digest) {
    ///     return Err(Error::ResourceExhausted("too many concurrent downloads"));
    /// }
    /// // ... download blob ...
    /// store.put_blob(&digest, &data)?;
    /// store.untrack_inflight(&digest);
    /// ```
    #[must_use = "must check if tracking succeeded before downloading to ensure GC safety"]
    pub fn track_inflight(&self, digest: &str) -> bool {
        if let Ok(mut inflight) = self.inflight.write() {
            // SECURITY: Enforce limit to prevent memory exhaustion
            if inflight.len() >= MAX_INFLIGHT_BLOBS {
                warn!(
                    "Inflight blob limit reached ({}), rejecting {}",
                    MAX_INFLIGHT_BLOBS, digest
                );
                return false;
            }
            inflight.insert(digest.to_string());
            debug!("Tracking in-flight blob: {}", digest);
            return true;
        }
        false
    }

    /// Removes a digest from in-flight tracking.
    ///
    /// Call this after successfully storing a blob or if the download fails.
    pub fn untrack_inflight(&self, digest: &str) {
        if let Ok(mut inflight) = self.inflight.write() {
            inflight.remove(digest);
            debug!("Untracked in-flight blob: {}", digest);
        }
    }

    /// Returns the number of blobs currently in-flight.
    pub fn inflight_count(&self) -> usize {
        self.inflight.read().map(|g| g.len()).unwrap_or(0)
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

    /// Walks a directory recursively with depth limiting.
    ///
    /// # Security
    ///
    /// The depth limit prevents stack overflow from:
    /// - Symlink loops creating infinite recursion
    /// - Extremely deep directory structures (malicious or accidental)
    ///
    /// Uses `MAX_WALK_DEPTH` from constants (default: 64 levels).
    fn walk_dir(dir: &Path, callback: &mut impl FnMut(&Path)) -> Result<()> {
        use crate::constants::MAX_WALK_DEPTH;
        Self::walk_dir_with_depth(dir, callback, 0, MAX_WALK_DEPTH)
    }

    /// Internal recursive directory walker with depth tracking.
    fn walk_dir_with_depth(
        dir: &Path,
        callback: &mut impl FnMut(&Path),
        current_depth: usize,
        max_depth: usize,
    ) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        // SECURITY: Prevent stack overflow from deep/looping directory structures
        if current_depth >= max_depth {
            warn!(
                "Directory walk depth limit ({}) reached at {}, skipping deeper entries",
                max_depth,
                dir.display()
            );
            return Ok(());
        }

        for entry in fs::read_dir(dir).map_err(|e| Error::StorageWriteFailed(e.to_string()))? {
            let entry = entry.map_err(|e| Error::StorageWriteFailed(e.to_string()))?;
            let path = entry.path();

            if path.is_dir() {
                Self::walk_dir_with_depth(&path, callback, current_depth + 1, max_depth)?;
            } else {
                callback(&path);
            }
        }

        Ok(())
    }

    /// Garbage collects unreferenced blobs.
    ///
    /// Removes blobs that are:
    /// - NOT in the `referenced` list
    /// - NOT currently in-flight (being downloaded)
    ///
    /// # GC Safety
    ///
    /// This method is safe to call during concurrent image pulls as long as
    /// callers use [`Self::track_inflight`] / [`Self::untrack_inflight`] around blob downloads.
    /// In-flight blobs are automatically protected from deletion.
    ///
    /// # Arguments
    ///
    /// * `referenced` - List of digests that should be preserved (e.g., from image manifests)
    ///
    /// # Returns
    ///
    /// Statistics about removed blobs and freed space.
    pub fn gc(&self, referenced: &[String]) -> Result<GcStats> {
        // Get current in-flight set (clone to release lock quickly)
        let inflight_set: HashSet<String> =
            self.inflight.read().map(|g| g.clone()).unwrap_or_default();

        if !inflight_set.is_empty() {
            info!(
                "GC: protecting {} in-flight blobs from deletion",
                inflight_set.len()
            );
        }

        let all_blobs = self.list_blobs()?;
        let mut removed = 0u64;
        let mut freed = 0u64;
        let mut skipped_inflight = 0u64;

        for digest in all_blobs {
            // Skip referenced blobs
            if referenced.contains(&digest) {
                continue;
            }

            // SECURITY: Skip in-flight blobs to prevent race conditions
            if inflight_set.contains(&digest) {
                skipped_inflight += 1;
                debug!("GC: skipping in-flight blob {}", digest);
                continue;
            }

            let path = self.blob_path(&digest);
            if let Ok(meta) = fs::metadata(&path) {
                freed += meta.len();
                removed += 1;
                let _ = fs::remove_file(&path);
            }
        }

        info!(
            "GC: removed {} blobs, freed {} bytes, skipped {} in-flight",
            removed, freed, skipped_inflight
        );
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

    #[test]
    fn test_inflight_limit_enforced() {
        let temp = TempDir::new().unwrap();
        let store = BlobStore::with_path(temp.path().to_path_buf()).unwrap();

        // Track up to MAX_INFLIGHT_BLOBS
        for i in 0..MAX_INFLIGHT_BLOBS {
            let digest = format!("sha256:{:064x}", i);
            assert!(
                store.track_inflight(&digest),
                "Should accept inflight #{}",
                i
            );
        }

        // Next one should be rejected
        let overflow_digest = format!("sha256:{:064x}", MAX_INFLIGHT_BLOBS);
        assert!(
            !store.track_inflight(&overflow_digest),
            "Should reject inflight beyond limit"
        );

        // After untracking one, should accept again
        store.untrack_inflight(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(
            store.track_inflight(&overflow_digest),
            "Should accept after untrack"
        );
    }

    #[test]
    fn test_gc_protects_inflight_blobs() {
        let temp = TempDir::new().unwrap();
        let store = BlobStore::with_path(temp.path().to_path_buf()).unwrap();

        // Create some blobs
        let data1 = b"blob one";
        let data2 = b"blob two";
        let digest1 = format!("sha256:{}", hex::encode(Sha256::digest(data1)));
        let digest2 = format!("sha256:{}", hex::encode(Sha256::digest(data2)));

        store.put_blob(&digest1, data1).unwrap();
        store.put_blob(&digest2, data2).unwrap();

        assert!(store.has_blob(&digest1));
        assert!(store.has_blob(&digest2));

        // Mark digest1 as in-flight (simulates concurrent download)
        assert!(store.track_inflight(&digest1));

        // GC with empty referenced list - should delete digest2 but protect digest1
        let stats = store.gc(&[]).unwrap();

        // digest1 should still exist (protected by inflight)
        assert!(
            store.has_blob(&digest1),
            "Inflight blob should be protected from GC"
        );
        // digest2 should be deleted
        assert!(
            !store.has_blob(&digest2),
            "Unreferenced blob should be deleted"
        );
        // Stats should show we removed 1 blob
        assert_eq!(stats.removed_count, 1);

        // Cleanup
        store.untrack_inflight(&digest1);
    }
}
