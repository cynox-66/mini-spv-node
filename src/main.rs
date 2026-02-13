use mini_spv_node::BlockHeader;

fn main() {
    println!("Mini SPV Node - Block Header Engine");

    // Testnet Genesis Block Header Hex
    let header_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18";

    // Decode safely
    let bytes = match hex::decode(header_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to decode hex: {}", e);
            return;
        }
    };

    match BlockHeader::from_bytes(&bytes) {
        Ok(header) => {
            println!("Parsed Block Header:");
            println!("Version: {}", header.version);
            println!("Prev Hash: {}", hex::encode(header.prev_block_hash));
            println!("Merkle Root: {}", hex::encode(header.merkle_root));
            println!("Timestamp: {}", header.timestamp);
            println!("Bits: {:x}", header.bits);
            println!("Nonce: {}", header.nonce);

            let hash = header.hash();
            // Display hash in Big Endian (Standard Bitcoin format)
            let mut hash_be = hash;
            hash_be.reverse();
            println!("Block Hash (BE): {}", hex::encode(hash_be));

            if header.validate_pow() {
                println!("PoW Validation: SUCCESS");
            } else {
                println!("PoW Validation: FAILED");
            }
        }
        Err(e) => println!("Error parsing header: {}", e),
    }
}
