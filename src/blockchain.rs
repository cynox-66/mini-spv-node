use crate::crypto::double_sha256;
use crate::utils::{bits_to_target, bytes_to_u32_le, calculate_work};
use num_bigint::BigUint;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Header must be exactly 80 bytes, got {0}")]
    InvalidLength(usize),
    #[error("Parent block not found")]
    ParentNotFound,
    #[error("Invalid Proof-of-Work")]
    InvalidPoW,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// Deserializes a block header from 80 bytes (Little-Endian format)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockError> {
        if bytes.len() != 80 {
            return Err(BlockError::InvalidLength(bytes.len()));
        }

        let version = bytes_to_u32_le(&bytes[0..4]);

        let mut prev_block_hash = [0u8; 32];
        prev_block_hash.copy_from_slice(&bytes[4..36]);

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[36..68]);

        let timestamp = bytes_to_u32_le(&bytes[68..72]);
        let bits = bytes_to_u32_le(&bytes[72..76]);
        let nonce = bytes_to_u32_le(&bytes[76..80]);

        Ok(BlockHeader {
            version,
            prev_block_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    /// Serializes the header
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(80);
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&self.prev_block_hash);
        buffer.extend_from_slice(&self.merkle_root);
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        buffer.extend_from_slice(&self.bits.to_le_bytes());
        buffer.extend_from_slice(&self.nonce.to_le_bytes());
        buffer
    }

    /// Computes double-SHA256 hash
    pub fn hash(&self) -> [u8; 32] {
        double_sha256(&self.serialize())
    }

    /// Validates Proof-of-Work
    pub fn validate_pow(&self) -> bool {
        let target = bits_to_target(self.bits);
        let hash_bytes = self.hash();
        let hash_num = BigUint::from_bytes_le(&hash_bytes);
        hash_num <= target
    }
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub header: BlockHeader,
    pub cumulative_work: BigUint,
    pub height: u64,
}

pub struct HeaderChain {
    headers: HashMap<[u8; 32], ChainEntry>,
    best_tip: Option<[u8; 32]>,
}

impl HeaderChain {
    pub fn new() -> Self {
        HeaderChain {
            headers: HashMap::new(),
            best_tip: None,
        }
    }

    pub fn add_header(&mut self, header: BlockHeader) -> Result<(), BlockError> {
        let hash = header.hash();
        if self.headers.contains_key(&hash) {
            return Ok(());
        }

        if !header.validate_pow() {
            return Err(BlockError::InvalidPoW);
        }

        let work = calculate_work(header.bits);

        // Check parent
        let (cumulative_work, height) = if header.prev_block_hash == [0u8; 32] {
            // Genesis / Start
            (work, 0)
        } else {
            match self.headers.get(&header.prev_block_hash) {
                Some(parent) => (parent.cumulative_work.clone() + work, parent.height + 1),
                None => return Err(BlockError::ParentNotFound),
            }
        };

        let entry = ChainEntry {
            header,
            cumulative_work: cumulative_work.clone(),
            height,
        };

        self.headers.insert(hash, entry);

        // Update best tip using Most Work Rule
        if let Some(current_tip_hash) = &self.best_tip {
            let current_tip = self.headers.get(current_tip_hash).expect("Tip must exist");
            if cumulative_work > current_tip.cumulative_work {
                self.best_tip = Some(hash);
            }
        } else {
            self.best_tip = Some(hash);
        }

        Ok(())
    }

    pub fn get_best_tip(&self) -> Option<[u8; 32]> {
        self.best_tip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    // Helper to create a dummy header with minimal Work that passes valid_pow check?
    // It's hard to mine a real block in unit tests.
    // Instead we can use a very high target (low difficulty) for tests.
    // Max target: bits = 0x207fffff (all ffs)

    fn create_dummy_header(prev: [u8; 32], nonce_start: u32) -> BlockHeader {
        let mut nonce = nonce_start;
        loop {
            // High target (easiest difficulty)
            // 0x207fffff -> Coefficient 0x7fffff, Exp 0x20 (=32) -> Target is huge (approx 2^255)
            // 50% chance of passing PoW.
            let h = BlockHeader {
                version: 1,
                prev_block_hash: prev,
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits: 0x207fffff,
                nonce,
            };
            if h.validate_pow() {
                return h;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    // Helper that accepts bits
    fn create_dummy_header_with_bits(prev: [u8; 32], nonce_start: u32, bits: u32) -> BlockHeader {
        let mut nonce = nonce_start;
        loop {
            let h = BlockHeader {
                version: 1,
                prev_block_hash: prev,
                merkle_root: [0u8; 32],
                timestamp: 1234567890,
                bits,
                nonce,
            };
            if h.validate_pow() {
                return h;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    #[test]
    fn test_shorter_chain_more_work() {
        let mut chain = HeaderChain::new();
        // EASY difficulty: 0x207fffff
        // HARD(er) difficulty: 0x200fffff (smaller target = harder = more work)
        // Note: 0x200fffff target < 0x207fffff target.
        // Work = 2^256 / (target + 1). Smaller target -> More work.

        let easy_bits = 0x207fffff;
        let hard_bits = 0x200fffff;

        let genesis = create_dummy_header_with_bits([0u8; 32], 0, easy_bits);
        let genesis_hash = genesis.hash();
        chain.add_header(genesis).unwrap();

        // Chain A (Easy, Length 2): Gen -> A1 -> A2
        let a1 = create_dummy_header_with_bits(genesis_hash, 10, easy_bits);
        let a1_hash = a1.hash();
        chain.add_header(a1).unwrap();

        let a2 = create_dummy_header_with_bits(a1_hash, 20, easy_bits);
        let a2_hash = a2.hash();
        chain.add_header(a2).unwrap();

        assert_eq!(chain.get_best_tip(), Some(a2_hash));

        // Chain B (Hard, Length 1): Gen -> B1
        // Make sure B1 work > A1 work + A2 work.
        // To ensure this test works deterministically, we need to be careful about the values.
        // calculate_work(easy) ~ 2^256 / 2^255 ~ 2
        // calculate_work(hard).
        // Let's use more distinct values to guarantee the math works out.
        // Easy: 0x207fffff (Exp 32, Coeff 0x7fffff) -> Target ~ 0.5 * 2^256 -> Work ~ 2
        // Hard: 0x1f7fffff (Exp 31, Coeff 0x7fffff) -> Target ~ 0.5 * 2^248 -> Work ~ 2 * 256 = 512

        let very_easy_bits = 0x207fffff;
        let harder_bits = 0x1d00ffff; // Testnet min difficulty approx (Work = 1)
                                      // Wait, 0x207fffff is effectively min difficulty (Work=1) in Bitcoin regtest usually.
                                      // Let's use explicit targets.

        // Let's redefine test values for clarity without mining too hard:
        // Use `create_dummy_header` logic but manually override work calculation in test?
        // No, we must rely on `calculate_work`.

        // Let's use 0x207fffff for "easy" (Target is huge, work is small, ~2).
        // Let's use 0x1f00ffff for "hard" (Target is smaller by factor of 256).
        // Work should be ~256 times larger.

        let easy = 0x207fffff;
        let hard = 0x1f00ffff; // Exp 31.

        // Mining "hard" might be slow in a unit test loop if we are unlucky.
        // Exp 31 is still 2^248. It is very easy to mine.

        let mut chain2 = HeaderChain::new();
        let g = create_dummy_header_with_bits([0u8; 32], 0, easy);
        let gh = g.hash();
        chain2.add_header(g).unwrap();

        // A: 50 blocks of EASY
        let mut prev = gh;
        for i in 0..10 {
            let b = create_dummy_header_with_bits(prev, i * 100, easy);
            prev = b.hash();
            chain2.add_header(b).unwrap();
        }
        let tip_a = prev;
        assert_eq!(chain2.get_best_tip(), Some(tip_a));

        // B: 1 block of HARD
        // 1 hard block (Work ~ 512) > 10 easy blocks (Work ~ 20).
        let b1 = create_dummy_header_with_bits(gh, 5000, hard);
        let tip_b = b1.hash();
        chain2.add_header(b1).unwrap();

        assert_eq!(chain2.get_best_tip(), Some(tip_b));
    }

    #[test]
    fn test_chain_linear_and_work() {
        let mut chain = HeaderChain::new();
        let genesis = create_dummy_header([0u8; 32], 0);
        let genesis_hash = genesis.hash();

        chain.add_header(genesis).expect("Genesis should be added");
        assert_eq!(chain.get_best_tip(), Some(genesis_hash));

        let block1 = create_dummy_header(genesis_hash, 1);
        let block1_hash = block1.hash();
        chain.add_header(block1).expect("Block 1 should be added");
        assert_eq!(chain.get_best_tip(), Some(block1_hash));
    }

    #[test]
    fn test_fork_switching() {
        let mut chain = HeaderChain::new();
        let genesis = create_dummy_header([0u8; 32], 0);
        let genesis_hash = genesis.hash();
        chain.add_header(genesis).unwrap();

        // Branch A: Genesis -> A1 -> A2
        let a1 = create_dummy_header(genesis_hash, 10);
        let a1_hash = a1.hash();
        chain.add_header(a1).unwrap();
        assert_eq!(chain.get_best_tip(), Some(a1_hash));

        let a2 = create_dummy_header(a1_hash, 11);
        let a2_hash = a2.hash();
        chain.add_header(a2).unwrap();
        assert_eq!(chain.get_best_tip(), Some(a2_hash));

        // Branch B: Genesis -> B1 -> B2 -> B3 (More work)
        // Note: All blocks have same difficulty in this test, so length = work
        let b1 = create_dummy_header(genesis_hash, 20);
        let b1_hash = b1.hash();
        chain.add_header(b1).unwrap();
        // Tip still A2 (height 2 vs B1 height 1)
        assert_eq!(chain.get_best_tip(), Some(a2_hash));

        let b2 = create_dummy_header(b1_hash, 21);
        let b2_hash = b2.hash();
        chain.add_header(b2).unwrap();
        // Tip still A2 (height 2 vs B2 height 2).
        // If work is equal, keep current tip (first seen).
        assert_eq!(chain.get_best_tip(), Some(a2_hash));

        let b3 = create_dummy_header(b2_hash, 22);
        let b3_hash = b3.hash();
        chain.add_header(b3).unwrap();
        // Now B3 has height 3, more work. Tip should switch to B3.
        assert_eq!(chain.get_best_tip(), Some(b3_hash));
    }

    #[test]
    fn test_parent_not_found() {
        let mut chain = HeaderChain::new();
        let genesis = create_dummy_header([0u8; 32], 0);
        let genesis_hash = genesis.hash();

        let orphan = create_dummy_header(genesis_hash, 1); // Parent is genesis_hash
                                                           // But genesis not added yet

        let result = chain.add_header(orphan);
        assert!(matches!(result, Err(BlockError::ParentNotFound)));
    }

    #[test]
    fn test_invalid_pow() {
        let mut chain = HeaderChain::new();
        // Create a header with very hard difficulty
        // 0x03000001 -> Target = 1 * 256^(3-3) = 1. Very hard.
        // Unlikely to find a nonce that works.
        let mut hard_header = create_dummy_header([0u8; 32], 0);
        hard_header.bits = 0x03000001;

        let result = chain.add_header(hard_header);
        assert!(matches!(result, Err(BlockError::InvalidPoW)));
    }

    #[test]
    fn test_testnet_genesis() {
        let header_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18";
        let header_bytes = hex::decode(header_hex).unwrap();
        let header = BlockHeader::from_bytes(&header_bytes).unwrap();

        let mut chain = HeaderChain::new();
        chain.add_header(header.clone()).unwrap();

        assert_eq!(chain.get_best_tip(), Some(header.hash()));
    }
}
