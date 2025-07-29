use bytemuck::{Pod, Zeroable};

#[cfg(feature = "solana")]
use solana_program::keccak;

#[cfg(not(feature = "solana"))]
use sha3::{Digest, Keccak256};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct Solution {
    seed: [u8; 8],
    nonces: [[u8; 3]; 64],
}

pub fn serialize(solution: &Solution) -> [u8; 200] {
    let bytes = bytemuck::bytes_of(solution);
    let mut result = [0u8; 200];
    result.copy_from_slice(bytes);
    result
}

pub fn deserialize(solution: &[u8; 200]) -> Solution {
    let mut result = Solution {
        seed: [0; 8],
        nonces: [[0; 3]; 64],
    };
    let bytes = bytemuck::bytes_of_mut(&mut result);
    bytes.copy_from_slice(solution);
    result
}

pub fn solve_with_seed(pubkey: &[u8; 32], data: &[u8; 128], seed: u64) -> Option<Solution> {
    let max_nonce: u32 = (1 << 24) - 1; // u24: 0 to 16777215
    let mut result = Solution {
        seed: seed.to_le_bytes(),
        nonces: [[0; 3]; 64],
    };
    let seed_bytes = result.seed;

    for chunk_idx in 0..64 {
        let offset = chunk_idx * 2;
        let target = &data[offset..offset + 2];
        let chunk_idx_bytes = (chunk_idx as u64).to_le_bytes();
        let mut nonce_buffer: [u8; 4];
        let mut found = false;
        for nonce in 0..=max_nonce {
            nonce_buffer = nonce.to_le_bytes();
            let inputs = [
                pubkey.as_slice(),
                seed_bytes.as_slice(),
                nonce_buffer.as_slice(),
                chunk_idx_bytes.as_slice(),
            ];
            let hash = compute_hash(&inputs);
            if hash[0..2] == *target {
                result.nonces[chunk_idx].copy_from_slice(&nonce_buffer[0..3]);
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
    }

    Some(result)
}

pub fn verify(pubkey: &[u8; 32], data: &[u8; 128], solution: &Solution) -> bool {
    for chunk_idx in 0..64 {
        let offset = chunk_idx * 2;
        let target = &data[offset..offset + 2];

        let mut nonce_bytes = [0u8; 4];
        nonce_bytes[0..3].copy_from_slice(&solution.nonces[chunk_idx]);

        let chunk_idx_bytes = (chunk_idx as u64).to_le_bytes();
        let inputs = [
            pubkey.as_slice(),
            solution.seed.as_slice(),
            nonce_bytes.as_slice(),
            chunk_idx_bytes.as_slice(),
        ];
        let hash = compute_hash(&inputs);
        if hash[0..2] != *target {
            return false;
        }
    }
    true
}

#[inline(always)]
fn compute_hash(inputs: &[&[u8]]) -> [u8; 32] {
    #[cfg(feature = "solana")]
    {
        keccak::hashv(inputs).to_bytes()
    }
    #[cfg(not(feature = "solana"))]
    {
        let mut hasher = Keccak256::new();
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_with_seed_and_verify() {
        let pubkey = [1u8; 32];
        let data = [42u8; 128];
        let mut seed = 0u64;

        let solution = loop {
            if let Some(solution) = solve_with_seed(&pubkey, &data, seed) {
                break solution;
            }
            seed = seed.wrapping_add(1);
        };

        assert!(verify(&pubkey, &data, &solution));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let seed = 0u64;
        let mut solution = Solution {
            seed: seed.to_le_bytes(),
            nonces: [[0; 3]; 64],
        };

        // Fill nonces with deterministic values
        for (i, nonce) in solution.nonces.iter_mut().enumerate() {
            let n = (i as u32) % ((1 << 24) - 1);
            nonce.copy_from_slice(&n.to_le_bytes()[0..3]);
        }

        let serialized = serialize(&solution);
        let deserialized = deserialize(&serialized);

        assert_eq!(solution.seed, deserialized.seed);
        assert_eq!(solution.nonces, deserialized.nonces);
    }

    #[test]
    fn test_verify_failure_wrong_data() {
        let pubkey = [1u8; 32];
        let data = [42u8; 128];
        let mut seed = 0u64;

        let solution = loop {
            if let Some(solution) = solve_with_seed(&pubkey, &data, seed) {
                break solution;
            }
            seed = seed.wrapping_add(1);
        };

        let mut wrong_data = data;
        wrong_data[0] ^= 1; // Flip a bit in data

        assert!(!verify(&pubkey, &wrong_data, &solution));
    }

    #[test]
    fn test_verify_failure_wrong_pubkey() {
        let pubkey = [1u8; 32];
        let data = [42u8; 128];
        let mut seed = 0u64;

        let solution = loop {
            if let Some(solution) = solve_with_seed(&pubkey, &data, seed) {
                break solution;
            }
            seed = seed.wrapping_add(1);
        };

        let mut wrong_pubkey = pubkey;
        wrong_pubkey[0] ^= 1; // Flip a bit in data

        assert!(!verify(&wrong_pubkey, &data, &solution));
    }

    #[test]
    fn test_solve_with_seed_zero_data() {
        let pubkey = [1u8; 32];
        let data = [42u8; 128];
        let mut seed = 0u64;

        let solution = loop {
            if let Some(solution) = solve_with_seed(&pubkey, &data, seed) {
                break solution;
            }
            seed = seed.wrapping_add(1);
        };

        assert!(verify(&pubkey, &data, &solution));
    }
}
