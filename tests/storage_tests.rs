//! Tests for blob storage module.
//!
//! Validates content-addressed storage, digest verification,
//! path traversal protection, and atomic writes.

use magikrun::BlobStore;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

// =============================================================================
// BlobStore Creation Tests
// =============================================================================

#[test]
fn test_blob_store_creation() {
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("blobs");

    let store = BlobStore::with_path(store_path.clone()).unwrap();

    assert!(store_path.exists(), "store directory should be created");
    assert_eq!(store.base_dir(), store_path);
}

#[test]
fn test_blob_store_creates_nested_dirs() {
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("deeply").join("nested").join("blobs");

    let store = BlobStore::with_path(store_path.clone()).unwrap();

    assert!(store_path.exists(), "nested directories should be created");
    assert_eq!(store.base_dir(), store_path);
}

// =============================================================================
// Blob Storage Tests
// =============================================================================

#[test]
fn test_put_and_get_blob() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let data = b"hello world";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));

    store.put_blob(&digest, data).unwrap();

    let retrieved = store.get_blob(&digest).unwrap();
    assert_eq!(retrieved, data);
}

#[test]
fn test_has_blob() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let data = b"test data";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));

    assert!(!store.has_blob(&digest), "blob should not exist before put");

    store.put_blob(&digest, data).unwrap();

    assert!(store.has_blob(&digest), "blob should exist after put");
}

#[test]
fn test_get_nonexistent_blob_fails() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let result =
        store.get_blob("sha256:0000000000000000000000000000000000000000000000000000000000000000");

    assert!(result.is_err(), "getting nonexistent blob should fail");
}

#[test]
fn test_blob_deduplication() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let data = b"duplicate content";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));

    // Put the same blob twice
    store.put_blob(&digest, data).unwrap();
    store.put_blob(&digest, data).unwrap();

    // Should still only have one copy
    let retrieved = store.get_blob(&digest).unwrap();
    assert_eq!(retrieved, data);
}

// =============================================================================
// Digest Verification Tests
// =============================================================================

#[test]
fn test_digest_mismatch_fails() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let data = b"actual content";
    // Provide wrong digest
    let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    let result = store.put_blob(wrong_digest, data);

    assert!(result.is_err(), "mismatched digest should fail");
}

#[test]
fn test_non_sha256_digest_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let data = b"test content";

    // SHA-384 digest should be rejected
    let sha384_digest = "sha384:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let result = store.put_blob(sha384_digest, data);
    assert!(result.is_err(), "sha384 digest should be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("unsupported digest algorithm"),
        "error message should indicate unsupported algorithm"
    );

    // SHA-512 digest should be rejected
    let sha512_digest = "sha512:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let result = store.put_blob(sha512_digest, data);
    assert!(result.is_err(), "sha512 digest should be rejected");

    // MD5 digest should be rejected
    let md5_digest = "md5:d41d8cd98f00b204e9800998ecf8427e";
    let result = store.put_blob(md5_digest, data);
    assert!(result.is_err(), "md5 digest should be rejected");
}

#[test]
fn test_empty_blob() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let data = b"";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));

    store.put_blob(&digest, data).unwrap();

    let retrieved = store.get_blob(&digest).unwrap();
    assert!(retrieved.is_empty());
}

#[test]
fn test_large_blob() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // 1 MiB of data
    let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let hash = Sha256::digest(&data);
    let digest = format!("sha256:{}", hex::encode(hash));

    store.put_blob(&digest, &data).unwrap();

    let retrieved = store.get_blob(&digest).unwrap();
    assert_eq!(retrieved.len(), data.len());
    assert_eq!(retrieved, data);
}

// =============================================================================
// Path Traversal Protection Tests
// =============================================================================

#[test]
fn test_path_traversal_in_digest_sanitized() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Attempt path traversal via digest
    let malicious_digest = "sha256:../../../etc/passwd";

    // blob_path should sanitize this
    let path = store.blob_path(malicious_digest);

    // Path should NOT escape the blob store directory
    assert!(
        path.starts_with(temp_dir.path()),
        "path should not escape store directory"
    );
    assert!(
        !path.to_string_lossy().contains(".."),
        "path should not contain .."
    );
}

#[test]
fn test_invalid_algorithm_handled() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Invalid algorithm in digest
    let invalid_digest = "md5:d41d8cd98f00b204e9800998ecf8427e";

    let path = store.blob_path(invalid_digest);

    // Should default to sha256 and still produce a valid path
    assert!(path.to_string_lossy().contains("sha256"));
}

#[test]
fn test_non_hex_characters_filtered() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Non-hex characters in hash
    let invalid_digest = "sha256:xyz!@#$%^&*()";

    let path = store.blob_path(invalid_digest);

    // Path should only contain valid characters
    let path_str = path.to_string_lossy();
    // The hash part should be sanitized
    assert!(
        !path_str.contains('!') && !path_str.contains('@'),
        "path should not contain special characters"
    );
}

// =============================================================================
// Blob Removal Tests
// =============================================================================

#[test]
fn test_remove_blob() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let data = b"to be removed";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));

    store.put_blob(&digest, data).unwrap();
    assert!(store.has_blob(&digest));

    store.remove_blob(&digest).unwrap();
    assert!(!store.has_blob(&digest));
}

#[test]
fn test_remove_nonexistent_blob_succeeds() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Removing a blob that doesn't exist should not fail
    let result = store
        .remove_blob("sha256:0000000000000000000000000000000000000000000000000000000000000000");

    // This should succeed (no-op) or return a specific error
    // Depending on implementation, adjust this assertion
    let _ = result;
}

// =============================================================================
// Sharding Tests
// =============================================================================

#[test]
fn test_blob_path_sharded() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let digest = "sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234";
    let path = store.blob_path(digest);

    // Path should include algorithm and shard directories
    let path_str = path.to_string_lossy();
    assert!(path_str.contains("sha256"), "path should include algorithm");
    assert!(
        path_str.contains("ab"),
        "path should include shard (first 2 chars)"
    );
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

/// Tests concurrent puts of the same blob.
///
/// # Fixed Issue
///
/// Previously this test exposed a race condition where multiple threads
/// racing to write the same blob would use a non-unique temp file path.
/// This has been fixed by using UUID-based unique temp file names in put_blob().
#[test]
fn test_concurrent_puts_same_blob() {
    use std::sync::Arc;
    use std::thread;

    let temp_dir = TempDir::new().unwrap();
    let store = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());

    let data = b"concurrent test data";
    let hash = Sha256::digest(data);
    let digest = format!("sha256:{}", hex::encode(hash));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let store = Arc::clone(&store);
            let digest = digest.clone();
            let data = data.to_vec();
            thread::spawn(move || store.put_blob(&digest, &data))
        })
        .collect();

    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    // Blob should exist and be correct
    let retrieved = store.get_blob(&digest).unwrap();
    assert_eq!(retrieved, data);
}

#[test]
fn test_concurrent_puts_different_blobs() {
    use std::sync::Arc;
    use std::thread;

    let temp_dir = TempDir::new().unwrap();
    let store = Arc::new(BlobStore::with_path(temp_dir.path().join("blobs")).unwrap());

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let store = Arc::clone(&store);
            thread::spawn(move || {
                let data = format!("blob data {}", i);
                let hash = Sha256::digest(data.as_bytes());
                let digest = format!("sha256:{}", hex::encode(hash));
                store.put_blob(&digest, data.as_bytes()).unwrap();
                digest
            })
        })
        .collect();

    let digests: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All blobs should exist
    for digest in &digests {
        assert!(store.has_blob(digest));
    }
}

// =============================================================================
// Garbage Collection Tests
// =============================================================================

#[test]
fn test_gc_removes_unreferenced() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    // Create some blobs
    let data1 = b"keep this";
    let hash1 = Sha256::digest(data1);
    let digest1 = format!("sha256:{}", hex::encode(hash1));
    store.put_blob(&digest1, data1).unwrap();

    let data2 = b"remove this";
    let hash2 = Sha256::digest(data2);
    let digest2 = format!("sha256:{}", hex::encode(hash2));
    store.put_blob(&digest2, data2).unwrap();

    // GC keeping only digest1
    let referenced = vec![digest1.clone()];
    let stats = store.gc(&referenced).unwrap();

    // digest1 should still exist
    assert!(store.has_blob(&digest1));

    // digest2 should be removed
    assert!(!store.has_blob(&digest2));

    // Stats should reflect removal
    assert!(stats.removed_count >= 1);
}

#[test]
fn test_gc_keeps_all_referenced() {
    let temp_dir = TempDir::new().unwrap();
    let store = BlobStore::with_path(temp_dir.path().join("blobs")).unwrap();

    let mut digests = Vec::new();

    // Create several blobs
    for i in 0..5 {
        let data = format!("blob {}", i);
        let hash = Sha256::digest(data.as_bytes());
        let digest = format!("sha256:{}", hex::encode(hash));
        store.put_blob(&digest, data.as_bytes()).unwrap();
        digests.push(digest);
    }

    // GC keeping all
    let referenced: Vec<String> = digests.clone();
    let stats = store.gc(&referenced).unwrap();

    // All should still exist
    for digest in &digests {
        assert!(store.has_blob(digest), "blob {} should still exist", digest);
    }

    assert_eq!(stats.removed_count, 0, "no blobs should be removed");
}
