use bytemuck::{Pod, Zeroable};
use sha3::{Digest, Keccak256};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct Solution {
    pub seed: [u8; 8],
    pub nonces: [[u8; 3]; 64],
}

impl Solution {
    pub fn pack(&self) -> [u8; 200] {
        serialize(self)
    }

    pub fn unpack(data: &[u8; 200]) -> Self {
        deserialize(data)
    }
}

/// Finds a nonce for a single chunk that produces a hash matching the target.
pub fn find_nonce_for_chunk(
    pubkey: &[u8; 32],
    seed: u64,
    chunk_idx: u64,
    target: &[u8; 2],
) -> Option<u32> {
    let max_nonce: u32 = (1 << 24) - 1; // u24: 0 to 16777215
    let seed_bytes = seed.to_le_bytes();
    let chunk_idx_bytes = chunk_idx.to_le_bytes();
    let mut nonce_buffer: [u8; 4];

    for nonce in 0..=max_nonce {
        nonce_buffer = nonce.to_le_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        hasher.update(seed_bytes);
        hasher.update(nonce_buffer);
        hasher.update(chunk_idx_bytes);
        let hash = hasher.finalize();
        if hash[0..2] == *target {
            return Some(nonce);
        }
    }
    None
}

/// Constructs a solution by finding nonces for all chunks for a given seed.
pub fn solve_with_seed(pubkey: &[u8; 32], data: &[u8; 128], seed: u64) -> Option<Solution> {
    let mut result = Solution {
        seed: seed.to_le_bytes(),
        nonces: [[0; 3]; 64],
    };

    for chunk_idx in 0..64 {
        let offset = chunk_idx * 2;
        let target = [data[offset], data[offset + 1]];
        if let Some(nonce) = find_nonce_for_chunk(pubkey, seed, chunk_idx as u64, &target) {
            result.nonces[chunk_idx].copy_from_slice(&nonce.to_le_bytes()[0..3]);
        } else {
            return None;
        }
    }
    Some(result)
}

/// Verifies a solution against the provided public key and data.
pub fn verify(pubkey: &[u8; 32], data: &[u8; 128], solution: &Solution) -> bool {
    for chunk_idx in 0..64 {
        let offset = chunk_idx * 2;
        let target = &data[offset..offset + 2];

        let mut nonce_bytes = [0u8; 4];
        nonce_bytes[0..3].copy_from_slice(&solution.nonces[chunk_idx]);

        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        hasher.update(solution.seed);
        hasher.update(nonce_bytes);
        hasher.update((chunk_idx as u64).to_le_bytes());
        let hash = hasher.finalize();
        if hash[0..2] != *target {
            return false;
        }
    }
    true
}

/// Serializes a `Solution` struct into a byte array of length 200.
pub fn serialize(solution: &Solution) -> [u8; 200] {
    let bytes = bytemuck::bytes_of(solution);
    let mut result = [0u8; 200];
    result.copy_from_slice(bytes);
    result
}

/// Deserializes a byte array into a `Solution` struct.
pub fn deserialize(solution: &[u8; 200]) -> Solution {
    let mut result = Solution {
        seed: [0; 8],
        nonces: [[0; 3]; 64],
    };
    let bytes = bytemuck::bytes_of_mut(&mut result);
    bytes.copy_from_slice(solution);
    result
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
        wrong_data[0] = 43;
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
        wrong_pubkey[0] = 2;
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
