# PackX

PackX is a Rust library for cryptographically committing 128-byte data segments to a public key. Designed for [Tapedrive](https://tapedrive.io), it requires node operators to store unique nonce values derived from their pubkey instead of the actual data, while enabling verifiable reconstruction with a specified difficulty.

## Usage

- `solve(pubkey, data, difficulty) -> Option<Solution>` - Generate a solution containing a u8 bump, 16 u8 seeds, and 128 u8 nonces for a 128-byte data segment, meeting the specified difficulty (leading zeros in the hash of the serialized solution).
- `verify(pubkey, data, solution, difficulty) -> bool` - Verify the solution against the public key, data segment, and difficulty.
- `unpack(pubkey, solution) -> [u8; 128]` - Reconstruct the original data from the solution and public key.


## Example

```rust
use packx::{solve, solve_with_memory, build_memory, verify, unpack};
use rand::RngCore;

// One shot solve that builds the precompute internally
let mut rng = rand::thread_rng();
let mut pubkey = [0u8; 32];
let mut data = [0u8; 128];
rng.fill_bytes(&mut pubkey);
rng.fill_bytes(&mut data);

let difficulty = 8;
let solution = solve(&pubkey, &data, difficulty).expect("no solution");

// Verify and unpack
assert!(verify(&pubkey, &data, &solution, difficulty));
assert_eq!(unpack(&pubkey, &solution), data);

// High throughput path: build once, solve many
let mem = build_memory(&pubkey);
let solution = solve_with_memory(&data, &mem, difficulty).expect("no solution");

assert!(verify(&pubkey, &data, &solution, difficulty));
```

## Notes

- **Storage overhead**: `145 bytes` per `128-byte segment` (~1.1328:1 storage ratio).
- **Difficulty**: The difficulty is the number of leading zeros in the Blake3 hash of the serialized solution. Higher difficulties require more computation to find a valid solution.
- **Solana Compatibility**: The library uses a `compute_hash` function that supports both `Solana’s blake3::hashv` (with the solana feature) and the `blake3` crate for non-Solana environments.
- **Performance**: The `solve` function was designed to be as fast as possible in order to allow multiple megabytes of data to be processed per second.

The algorithm is designed to allow for efficient packing, and verification, it is not GPU hard. It is fully expected that the algorithm will see GPU implementations in the future. This will allow for faster packing of data, making cold starts for new nodes much faster.

## Contributing

The library is open-source and contributions are welcome!
