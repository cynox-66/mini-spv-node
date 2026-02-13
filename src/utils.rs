use num_bigint::{BigUint, ToBigUint};
use num_traits::One;

/// Calculates the work done for a given difficulty (bits).
/// Work = 2^256 / (target + 1)
pub fn calculate_work(bits: u32) -> BigUint {
    let target = bits_to_target(bits);
    let dividend = BigUint::one() << 256;
    let divisor = target + BigUint::one();
    dividend / divisor
}

/// Converts Bitcoin compact difficulty target (bits) to a full 256-bit target.
///
/// The compact format is a 32-bit integer:
/// - The most significant byte is the exponent (base 256).
/// - The lower 3 bytes are the mantissa (coefficient).
///
/// Target = coefficient * 256^(exponent - 3)
pub fn bits_to_target(bits: u32) -> BigUint {
    let exponent = ((bits >> 24) & 0xff) as u32;
    let coefficient = (bits & 0x007fffff) as u32; // Mask out the sign bit if any, though usually 0 in valid blocks.

    let coefficient_big = coefficient.to_biguint().unwrap_or_default();

    if exponent <= 3 {
        // If exponent is small, right shift
        coefficient_big >> (8 * (3 - exponent) as usize)
    } else {
        // If exponent is large, left shift (multiply by 256^(exp-3))
        coefficient_big << (8 * (exponent - 3) as usize)
    }
}

pub fn bytes_to_u32_le(bytes: &[u8]) -> u32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(arr)
}
