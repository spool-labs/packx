use bytemuck::{Pod, Zeroable};

pub const SOLUTION_SIZE: usize = 145; // 1 (bump) + 16 (seeds) + 128 (nonces)

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct Solution {
    pub bump: u8,          // single-byte bump
    pub seeds: [u8; 16],   // 16 seeds, one per 8-byte group
    pub nonces: [u8; 128], // 128 nonces (u8), one per byte
}

impl Solution {
    pub fn new(bump: u8, seeds: [u8; 16], nonces: [u8; 128]) -> Self {
        Solution {
            bump,
            seeds,
            nonces,
        }
    }

    /// Leading-zero bits in BLAKE3(serialize(solution)).
    #[inline]
    pub fn difficulty(&self) -> u32 {
        let bytes = serialize(self);
        let h = compute_hash(&[&bytes]);
        get_difficulty(h)
    }

    /// Serialize to 145 bytes.
    pub fn to_bytes(&self) -> [u8; SOLUTION_SIZE] {
        serialize(self)
    }

    /// Deserialize from 145 bytes.
    pub fn from_bytes(data: &[u8; SOLUTION_SIZE]) -> Self {
        deserialize(data)
    }

    /// Reconstruct data using H(pubkey, bump, seed, nonce).
    pub fn unpack(&self, pubkey: &[u8; 32]) -> [u8; 128] {
        unpack(pubkey, self)
    }
}

/// Per-bump table: which targets each seed can produce, and the first nonce.
#[repr(C)]
pub struct SeedTable {
    pub nonces: [[u8; 256]; 256],  // [seed][target] -> nonce
    pub present: [[u8; 32]; 256],  // [seed] -> 256-bit bitset of achievable targets
}

/// All bumps for one pubkey (heap allocated).
pub struct SolverMemory {
    pub tables: Box<[SeedTable]>,
}

#[inline(always)]
fn bit_test(bits: &[u8; 32], target: u8) -> bool {
    let idx = (target >> 3) as usize;
    let mask = 1u8 << (target & 7);
    (bits[idx] & mask) != 0
}

#[inline(always)]
fn bit_set(bits: &mut [u8; 32], target: u8) {
    let idx = (target >> 3) as usize;
    let mask = 1u8 << (target & 7);
    bits[idx] |= mask;
}

#[inline(always)]
fn h0(pubkey: &[u8; 32], bump: u8, seed: u8, nonce: u8) -> u8 {
    let bump_b = [bump];
    let seed_b = [seed];
    let nonce_b = [nonce];
    compute_hash(&[pubkey, &bump_b, &seed_b, &nonce_b])[0]
}

#[inline(always)]
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

#[inline]
fn get_difficulty(hash: [u8; 32]) -> u32 {
    let mut count = 0u32;
    for &b in &hash {
        let lz = b.leading_zeros();
        count += lz;
        if lz < 8 {
            break;
        }
    }
    count
}

#[inline]
pub fn serialize(solution: &Solution) -> [u8; SOLUTION_SIZE] {
    let mut out = [0u8; SOLUTION_SIZE];
    out.copy_from_slice(bytemuck::bytes_of(solution));
    out
}

#[inline]
pub fn deserialize(bytes_in: &[u8; SOLUTION_SIZE]) -> Solution {
    let mut s = Solution {
        bump: 0,
        seeds: [0; 16],
        nonces: [0; 128],
    };
    bytemuck::bytes_of_mut(&mut s).copy_from_slice(bytes_in);
    s
}

/// Build one bump table. About 72 KiB per bump.
pub fn build_one_bump(pubkey: &[u8; 32], bump: u8) -> SeedTable {
    let mut table = SeedTable {
        nonces: [[0u8; 256]; 256],
        present: [[0u8; 32]; 256],
    };

    for seed in 0u8..=u8::MAX {
        let present_row = &mut table.present[seed as usize];
        let nonces_row = &mut table.nonces[seed as usize];

        for nonce in 0u8..=u8::MAX {
            let t = h0(pubkey, bump, seed, nonce);
            if !bit_test(present_row, t) {
                bit_set(present_row, t);
                nonces_row[t as usize] = nonce;
            }
        }
    }

    table
}

/// Build all 256 bump tables. About 18 MiB total.
pub fn build_memory(pubkey: &[u8; 32]) -> SolverMemory {
    let mut vec_tables = Vec::with_capacity(256);
    for bump in 0u8..=u8::MAX {
        vec_tables.push(build_one_bump(pubkey, bump));
    }
    SolverMemory {
        tables: vec_tables.into_boxed_slice(),
    }
}

/// Seed that can cover a group, paired with the 8 nonces to use.
#[derive(Clone, Copy)]
struct SeedCandidate {
    seed: u8,
    nonces8: [u8; 8],
}

/// Build candidates for group g using table.
fn build_group_candidates(data: &[u8; 128], g: usize, table: &SeedTable) -> Vec<SeedCandidate> {
    let cs = g * 8;
    let need = [
        data[cs + 0], data[cs + 1], data[cs + 2], data[cs + 3],
        data[cs + 4], data[cs + 5], data[cs + 6], data[cs + 7],
    ];

    let mut out = Vec::with_capacity(8);

    for seed in 0u8..=u8::MAX {
        let present = &table.present[seed as usize];
        if !(bit_test(present, need[0]) &&
             bit_test(present, need[1]) &&
             bit_test(present, need[2]) &&
             bit_test(present, need[3]) &&
             bit_test(present, need[4]) &&
             bit_test(present, need[5]) &&
             bit_test(present, need[6]) &&
             bit_test(present, need[7])) {
            continue;
        }

        let row = &table.nonces[seed as usize];
        out.push(SeedCandidate {
            seed,
            nonces8: [
                row[need[0] as usize],
                row[need[1] as usize],
                row[need[2] as usize],
                row[need[3] as usize],
                row[need[4] as usize],
                row[need[5] as usize],
                row[need[6] as usize],
                row[need[7] as usize],
            ],
        });
    }

    out
}

/// Iterator over the cartesian product of candidate lists.
struct MixedRadix {
    radices: [usize; 16],
    idx: [usize; 16],
    first: bool,
    done: bool,
}

impl MixedRadix {
    fn new(radices: [usize; 16]) -> Option<Self> {
        if radices.iter().any(|&r| r == 0) {
            return None;
        }
        Some(Self {
            radices,
            idx: [0; 16],
            first: true,
            done: false,
        })
    }
}

impl Iterator for MixedRadix {
    type Item = [usize; 16];
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.first {
            self.first = false;
            return Some(self.idx);
        }
        for pos in 0..16 {
            self.idx[pos] += 1;
            if self.idx[pos] < self.radices[pos] {
                return Some(self.idx);
            } else {
                self.idx[pos] = 0;
            }
        }
        self.done = true;
        None
    }
}

/// Solve for one bump using its table by scanning per-group candidates and trying combinations.
pub fn solve_one_bump(
    data: &[u8; 128],
    bump: u8,
    table: &SeedTable,
    difficulty: u32,
) -> Option<Solution> {
    let mut cands: [Vec<SeedCandidate>; 16] = core::array::from_fn(|_| Vec::new());
    for g in 0..16 {
        cands[g] = build_group_candidates(data, g, table);
        if cands[g].is_empty() {
            return None;
        }
    }

    let mut order: [usize; 16] = core::array::from_fn(|i| i);
    order.sort_by_key(|&g| cands[g].len());

    let radices_ordered: [usize; 16] = core::array::from_fn(|i| cands[order[i]].len());
    let Some(iter) = MixedRadix::new(radices_ordered) else { return None; };

    for idxs_ordered in iter {
        let mut seeds_out = [0u8; 16];
        let mut nonces_out = [0u8; 128];

        for (pos, &g) in order.iter().enumerate() {
            let choice = cands[g][idxs_ordered[pos]];
            seeds_out[g] = choice.seed;
            let cs = g * 8;
            nonces_out[cs..cs + 8].copy_from_slice(&choice.nonces8);
        }

        let solution = Solution { bump, seeds: seeds_out, nonces: nonces_out };
        if solution.difficulty() >= difficulty {
            return Some(solution);
        }
    }

    None
}

/// Solve using a precomputed all-bumps table.
pub fn solve_with_memory(
    data: &[u8; 128],
    mem: &SolverMemory,
    difficulty: u32,
) -> Option<Solution> {
    for bump in 0u8..=u8::MAX {
        let table = &mem.tables[bump as usize];
        if let Some(solution) = solve_one_bump(data, bump, table, difficulty) {
            return Some(solution);
        }
    }
    None
}

/// Solve by first building the precompute for this pubkey, then searching. You may want to use
/// solve_with_memory to avoid rebuilding it for each call.
pub fn solve(
    pubkey: &[u8; 32],
    data: &[u8; 128],
    difficulty: u32,
) -> Option<Solution> {
    let mem = build_memory(pubkey);
    solve_with_memory(data, &mem, difficulty)
}

/// Reconstruct data using H(pubkey, bump, seed, nonce).
pub fn unpack(pubkey: &[u8; 32], solution: &Solution) -> [u8; 128] {
    let mut data = [0u8; 128];
    for g in 0..16 {
        let seed = solution.seeds[g];
        let cs = g * 8;
        for i in 0..8 {
            let nonce = solution.nonces[cs + i];
            data[cs + i] = h0(pubkey, solution.bump, seed, nonce);
        }
    }
    data
}

/// Check reconstruction and difficulty.
pub fn verify(pubkey: &[u8; 32], data: &[u8; 128], solution: &Solution, difficulty: u32) -> bool {
    if unpack(pubkey, solution) != *data {
        return false;
    }
    solution.difficulty() >= difficulty
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    const TEST_DIFFICULTY: u32 = 1;
    const TEST_BUMP_TRIES: u8 = 7;

    fn solve_lightweight(pubkey: &[u8; 32], data: &[u8; 128], difficulty: u32) -> Option<Solution> {
        for bump in 0u8..=TEST_BUMP_TRIES {
            let table = build_one_bump(pubkey, bump);
            if let Some(solution) = solve_one_bump(data, bump, &table, difficulty) {
                return Some(solution);
            }
        }
        None
    }

    #[test]
    fn test_solve_and_verify() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve_lightweight(&pubkey, &data, TEST_DIFFICULTY).expect("solve failed");
        assert!(verify(&pubkey, &data, &solution, TEST_DIFFICULTY));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let solution = Solution { bump: 3, seeds: [9; 16], nonces: [7; 128] };
        let ser = serialize(&solution);
        let de = deserialize(&ser);
        assert_eq!(solution.bump, de.bump);
        assert_eq!(solution.seeds, de.seeds);
        assert_eq!(solution.nonces, de.nonces);
    }

    #[test]
    fn test_verify_failure_wrong_data() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve_lightweight(&pubkey, &data, TEST_DIFFICULTY).expect("solve failed");
        let mut wrong = data;
        wrong[0] = wrong[0].wrapping_add(1);
        assert!(!verify(&pubkey, &wrong, &solution, TEST_DIFFICULTY));
    }

    #[test]
    fn test_verify_failure_wrong_pubkey() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve_lightweight(&pubkey, &data, TEST_DIFFICULTY).expect("solve failed");
        let mut other = pubkey;
        other[0] ^= 1;
        assert!(!verify(&other, &data, &solution, TEST_DIFFICULTY));
    }

    #[test]
    fn test_unpack_roundtrip() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut pubkey);
        rng.fill_bytes(&mut data);

        let solution = solve_lightweight(&pubkey, &data, TEST_DIFFICULTY).expect("solve failed");
        assert_eq!(unpack(&pubkey, &solution), data);
    }
}
