# PackX

PackX is a Rust library for cryptographically committing 128‑byte data segments to a public key. Designed for TAPEDRIVE, it requires node operators to store unique nonce values derived from their pubkey instead of the actual data, while enabling verifiable reconstruction.

## Usage

- `solve_with_seed(pubkey, data, seed)` - generate a solution containing a seed and 64 nonces for a 128-byte data segment.
- `verify(pubkey, data, packed, commitment)` - verify the solution against the public key and data segment.

Store the packed result (from serialize) in a Merkle tree for efficient proof and verification. The find_nonce_for_chunk function allows external parallelization of nonce searches for performance optimization.

## Example

```rust
let pubkey = [1u8; 32]; // Example pubkey
let data = [42u8; 128]; // Example data
let mut seed = rng.gen::<u64>();

// Find a solution by trying seeds until one works
let solution = loop {
    if let Some(sol) = solve_with_seed(&pubkey, &data, seed) {
        break sol;
    }
    seed = seed.wrapping_add(1);
};

assert!(verify(&pubkey, &data, &solution));
```

## Notes

- **Storage overhead:** 200 bytes per 128-byte segment (~1.56:1)
