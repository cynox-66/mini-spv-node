use sha2::{Digest, Sha256};

/// Computes the double SHA-256 hash of the input data.
/// This is the standard hashing algorithm used in Bitcoin (dSHA256).
/// Returns a 32-byte array.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash1);
    let result = hasher.finalize();

    result.into()
}
