use bytemuck::{Pod, Zeroable};

pub const SOLUTION_SIZE: usize = 152; // 8 + 16 + 128 = 152 bytes

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct Solution {
    pub bump: [u8; 8],     // u64 bump stored as bytes for retrying seed sets
    pub seeds: [u8; 16],   // 16 u8 seeds, each for 8 chunks
    pub nonces: [u8; 128], // 128 u8 nonces, one per chunk
}

impl Solution {
    pub fn new(seeds: [u8; 16], nonces: [u8; 128], bump: [u8; 8]) -> Self {
        Solution {
            bump,
            seeds,
            nonces,
        }
    }

    pub fn to_bytes(&self) -> [u8; SOLUTION_SIZE] {
        serialize(self)
    }

    pub fn from_bytes(data: &[u8; SOLUTION_SIZE]) -> Self {
        deserialize(data)
    }

    pub fn unpack(&self, pubkey: &[u8; 32]) -> [u8; 128] {
        unpack(pubkey, self)
    }

    pub fn difficulty(&self) -> u32 {
        let solution_bytes = self.to_bytes();
        let hash = compute_hash(&[&solution_bytes]);
        get_difficulty(hash)
    }
}

/// Reconstructs the data from the solution and public key.
/// If bump is zero, return nonces directly (for difficulty == 0).
pub fn unpack(pubkey: &[u8; 32], solution: &Solution) -> [u8; 128] {
    if solution.bump == [0; 8] {
        return solution.nonces; // Direct return of nonces for difficulty == 0
    }

    let mut data = [0u8; 128];
    for group_idx in 0..16 {
        let chunk_start = group_idx * 8;
        let chunk_end = chunk_start + 8;
        let seed = solution.seeds[group_idx];

        for chunk_idx in chunk_start..chunk_end {
            let chunk_idx_bytes = (chunk_idx as u64).to_le_bytes();
            let hash = compute_hash(&[
                pubkey,
                &solution.bump,
                &[seed],
                &[solution.nonces[chunk_idx]],
                &chunk_idx_bytes,
            ]);
            data[chunk_idx] = hash[0];
        }
    }
    data
}

/// Finds a nonce for a single chunk that produces a hash matching the target.
pub fn find_nonce(pubkey: &[u8; 32], bump: u64, seed: u8, chunk_idx: u64, target: u8) -> Option<u8> {
    let max_nonce: u8 = u8::MAX; // u8: 0 to 255
    let bump_bytes = bump.to_le_bytes();
    let seed_bytes = [seed];
    let chunk_idx_bytes = chunk_idx.to_le_bytes();

    for nonce in 0..=max_nonce {
        let hash = compute_hash(&[pubkey, &bump_bytes, &seed_bytes, &[nonce], &chunk_idx_bytes]);
        if hash[0] == target {
            return Some(nonce);
        }
    }
    None
}

/// Constructs a solution for a group of chunks using a given seed and bump.
pub fn solve_with_seed(
    pubkey: &[u8; 32],
    data: &[u8; 128],
    bump: u64,
    seed: u8,
    group_idx: usize,
) -> Option<[u8; 8]> {
    let chunk_start = group_idx * 8;
    let chunk_end = chunk_start + 8;
    let mut nonces = [0u8; 8];

    for chunk_idx in chunk_start..chunk_end {
        let target = data[chunk_idx];
        if let Some(nonce) = find_nonce(pubkey, bump, seed, chunk_idx as u64, target) {
            nonces[chunk_idx - chunk_start] = nonce;
        } else {
            return None;
        }
    }
    Some(nonces)
}

/// Constructs a solution by finding nonces for all chunks, meeting the difficulty.
/// If difficulty is 0, store data directly in nonces with bump and seeds set to zero.
pub fn solve(pubkey: &[u8; 32], data: &[u8; 128], difficulty: u32) -> Option<Solution> {
    if difficulty == 0 {
        let solution = Solution {
            bump: [0; 8],    // Set bump to zero (u64: 0)
            seeds: [0; 16],  // Set seeds to zero
            nonces: *data,   // Store data directly in nonces
        };
        return Some(solution);
    }

    let mut bump = 1u64; // Start at bump = 1 for non-zero difficulty

    loop {
        let bump_bytes = bump.to_le_bytes();
        let mut result = Solution {
            bump: bump_bytes,
            seeds: [0; 16],
            nonces: [0; 128],
        };

        let mut found = true;
        for group_idx in 0..16 {
            let chunk_start = group_idx * 8;
            let mut seed = 0u8;

            loop {
                if let Some(nonces) = solve_with_seed(pubkey, data, bump, seed, group_idx) {
                    result.seeds[group_idx] = seed;
                    for i in 0..8 {
                        result.nonces[chunk_start + i] = nonces[i];
                    }
                    break;
                }
                seed = seed.wrapping_add(1);
                if seed == 0 {
                    found = false; // Exhausted seeds for this group
                    break;
                }
            }
            if !found {
                break;
            }
        }

        if found {
            if result.difficulty() >= difficulty {
                return Some(result);
            }
        }

        // Try next bump value
        bump = bump.wrapping_add(1);
        if bump == 0 {
            return None; // Exhausted all bump values (skipping 0)
        }
    }
}

/// Verifies a solution against the provided public key, data, and difficulty.
pub fn verify(pubkey: &[u8; 32], data: &[u8; 128], solution: &Solution, difficulty: u32) -> bool {
    if difficulty == 0 {
        return solution.nonces == *data && solution.bump == [0; 8] && solution.seeds == [0; 16];
    }

    // Check data reconstruction
    let reconstructed_data = unpack(pubkey, solution);
    if reconstructed_data != *data {
        return false;
    }

    // Check difficulty
    let solution_bytes = serialize(solution);
    let hash = compute_hash(&[&solution_bytes]);
    get_difficulty(hash) >= difficulty
}

/// Serializes a `Solution` struct into a byte array of length SOLUTION_SIZE.
pub fn serialize(solution: &Solution) -> [u8; SOLUTION_SIZE] {
    let bytes = bytemuck::bytes_of(solution);
    let mut result = [0u8; SOLUTION_SIZE];
    result.copy_from_slice(bytes);
    result
}

/// Deserializes a byte array into a `Solution` struct.
pub fn deserialize(solution: &[u8; SOLUTION_SIZE]) -> Solution {
    let mut result = Solution {
        bump: [0; 8],
        seeds: [0; 16],
        nonces: [0; 128],
    };
    let bytes = bytemuck::bytes_of_mut(&mut result);
    bytes.copy_from_slice(solution);
    result
}

/// Count leading zeros in a 32-byte hash
fn get_difficulty(hash: [u8; 32]) -> u32 {
    let mut count = 0;
    for &b in &hash {
        let lz = b.leading_zeros();
        count += lz;
        if lz < 8 {
            break;
        }
    }
    count
}

#[inline(always)]
/// Computes the hash of the given inputs using BLAKE3.
fn compute_hash(inputs: &[&[u8]]) -> [u8; 32] {
    #[cfg(feature = "solana")]
    {
        solana_program::blake3::hashv(inputs).to_bytes()
    }
    #[cfg(not(feature = "solana"))]
    {
        let mut hasher = blake3::Hasher::new();
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    // Reasonable difficulty for testing
    const TEST_DIFFICULTY: u32 = 1;

    #[test]
    fn test_solve_difficulty_zero() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, 0).expect("Failed to find solution with difficulty 0");

        // Check that nonces contain the input data
        assert_eq!(solution.nonces, data);
        // Check that bump is zero
        assert_eq!(solution.bump, [0; 8]);
        // Check that seeds are zero
        assert_eq!(solution.seeds, [0; 16]);
        // Verify the solution
        assert!(verify(&pubkey, &data, &solution, 0));
        // Check that unpack returns nonces directly
        assert_eq!(unpack(&pubkey, &solution), data);
    }

    #[test]
    fn test_solve_nonzero_difficulty_bump() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");

        // Check that bump is not zero
        assert_ne!(solution.bump, [0; 8], "Bump should not be zero for non-zero difficulty");
        // Convert bump bytes to u64 for additional check
        let bump_value = u64::from_le_bytes(solution.bump);
        assert!(bump_value >= 1, "Bump should be at least 1 for non-zero difficulty");
        // Verify the solution
        assert!(verify(&pubkey, &data, &solution, TEST_DIFFICULTY));
    }

    #[test]
    fn test_unpack_nonzero_bump() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");
        let reconstructed_data = unpack(&pubkey, &solution);

        assert_eq!(reconstructed_data, data);
    }

    #[test]
    fn test_solve_and_verify() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");

        assert!(verify(&pubkey, &data, &solution, TEST_DIFFICULTY));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut solution = Solution {
            bump: [0; 8],
            seeds: [0; 16],
            nonces: [0; 128],
        };
        for (i, seed) in solution.seeds.iter_mut().enumerate() {
            *seed = (i % 256) as u8;
        }
        for (i, nonce) in solution.nonces.iter_mut().enumerate() {
            *nonce = (i % 256) as u8;
        }
        for (i, byte) in solution.bump.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let serialized = serialize(&solution);
        let deserialized = deserialize(&serialized);

        assert_eq!(solution.bump, deserialized.bump);
        assert_eq!(solution.seeds, deserialized.seeds);
        assert_eq!(solution.nonces, deserialized.nonces);
    }

    #[test]
    fn test_verify_failure_wrong_data() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");

        let mut wrong_data = data;
        wrong_data[0] = wrong_data[0].wrapping_add(1); // Modify one byte
        assert!(!verify(&pubkey, &wrong_data, &solution, TEST_DIFFICULTY));
    }

    #[test]
    fn test_verify_failure_wrong_pubkey() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");

        let mut wrong_pubkey = pubkey;
        wrong_pubkey[0] = wrong_pubkey[0].wrapping_add(1); // Modify one byte
        assert!(!verify(&wrong_pubkey, &data, &solution, TEST_DIFFICULTY));
    }

    #[test]
    fn test_verify_failure_insufficient_difficulty() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");

        // Verify with higher difficulty should fail
        assert!(!verify(&pubkey, &data, &solution, TEST_DIFFICULTY + 8));
    }

    #[test]
    fn test_get_difficulty() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");
        let difficulty = solution.difficulty();

        assert!(difficulty >= TEST_DIFFICULTY);
    }

    #[test]
    fn test_reconstruct_data() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve(&pubkey, &data, TEST_DIFFICULTY).expect("Failed to find solution");
        let reconstructed_data = unpack(&pubkey, &solution);

        assert_eq!(reconstructed_data, data);
    }
}
