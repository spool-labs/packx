# PackX

PackX is a Rust library for cryptographically committing 128‑byte data segments to a public key. Designed for TAPEDRIVE, it requires node operators to store unique nonce values derived from their pubkey instead of the actual data, while enabling verifiable reconstruction.

## Usage

- `packx(pubkey, data)` — generate a seed and 128 nonces
- `serialize(seed, nonces)` — convert the result into a 200-byte array
- `verify(pubkey, data, packed, commitment)` — check integrity of the reconstruction

Store the `packed` result and `commitment` in a Merkle tree for efficient proof and verification.

## Example

```rust
use packx::{packx, serialize, get_commitment, verify};

let pubkey = rand::random::<[u8;32]>();
let data   = rand::random::<[u8;128]>();

let (seed, nonces) = packx(&pubkey, &data);
let packed         = serialize(seed, &nonces);
let commit         = get_commitment(&seed, &nonces);

assert!(verify(&pubkey, &data, &packed, Some(&commit)));
```

## Notes

- **Storage overhead:** 200 bytes per 128-byte segment (~1.56:1)
