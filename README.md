# PackX

PackX is a Rust library for cryptographically committing 128-byte data segments to a public key. Designed for TAPEDRIVE, it requires node operators to store unique nonce values derived from their pubkey instead of the actual data, while enabling verifiable reconstruction with a specified difficulty.

## Usage

`solve(pubkey: &[u8; 32], data: &[u8; 128], difficulty: u32) -> Option<Solution>` - Generate a solution containing a u64 bump, 16 u8 seeds, and 128 u8 nonces for a 128-byte data segment, meeting the specified difficulty (leading zeros in the hash of the serialized solution).
`verify(pubkey: &[u8; 32], data: &[u8; 128], solution: &Solution, difficulty: u32)` -> bool - Verify the solution against the public key, data segment, and difficulty.
`unpack(pubkey: &[u8; 32], solution: &Solution) -> [u8; 128]` - Reconstruct the original data from the solution and public key.

Store the serialized solution (152 bytes) in a Merkle tree for efficient proof and verification. The find_nonce function allows external parallelization of nonce searches for performance optimization, and the u64 bump field expands the search space for meeting difficulty requirements.

## Example

```rust
use packx::{solve, verify, unpack};
use rand::thread_rng;

let mut rng = thread_rng();
let mut pubkey = [0u8; 32];
let mut data = [0u8; 128];
rng.fill_bytes(&mut pubkey);
rng.fill_bytes(&mut data);
let difficulty = 8; // Example difficulty (8 leading zeros in solution hash)

// Find a solution that matches the data and meets the difficulty
let solution = solve(&pubkey, &data, difficulty).expect("Failed to find solution");

// Verify the solution
assert!(verify(&pubkey, &data, &solution, difficulty));

// Reconstruct the original data
let unpacked_data = unpack(&pubkey, &solution);
assert_eq!(unpacked_data, data);
```

## Notes

- **Storage overhead**: `152 bytes` per `128-byte segment` (~1.1875:1 ratio).
- **Difficulty**: The difficulty is the number of leading zeros in the Keccak256 hash of the serialized solution (152 bytes). Higher difficulties require more computation to find a valid solution.
- **Parallelization**: The library supports parallel nonce searches via `find_nonce` and `solve_with_seed`, which can be used with libraries like Rayon for performance optimization.
- **Solana Compatibility: The library uses a `compute_hash` function that supports both `Solana’s keccak::hashv` (with the solana feature) and the `sha3` crate for non-Solana environments.
