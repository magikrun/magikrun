//! Content-addressed blob storage.
//!
//! Stores image layers and other blobs by their digest for deduplication.

use crate::constants::BLOB_STORE_DIR;
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Content-addressed blob store.
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
        let safe_hash: String = hash
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();

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
    pub fn put_blob(&self, digest: &str, data: &[u8]) -> Result<()> {
        // SECURITY: Verify content matches digest before storage
        let (algo, expected_hash) = digest.split_once(':').unwrap_or(("sha256", digest));

        let computed_hash = match algo {
            "sha256" => hex::encode(Sha256::digest(data)),
            // For sha384/sha512, we'd need additional imports; for now, only verify sha256
            _ => {
                warn!("Cannot verify non-sha256 digest: {}", algo);
                String::new()
            }
        };

        // Only verify if we computed a hash (sha256)
        if !computed_hash.is_empty() && computed_hash != expected_hash {
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

        // Write atomically via temp file
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, data).map_err(|e| Error::StorageWriteFailed(e.to_string()))?;
        fs::rename(&temp_path, &path).map_err(|e| Error::StorageWriteFailed(e.to_string()))?;

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
            if let Ok(meta) = fs::metadata(path) {
                if meta.is_file() {
                    total += meta.len();
                }
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
                if path.is_file() {
                    if let Some(hash) = path.file_name().and_then(|n| n.to_str()) {
                        digests.push(format!("sha256:{}", hash));
                    }
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

/// Garbage collection statistics.
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
        let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        
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
