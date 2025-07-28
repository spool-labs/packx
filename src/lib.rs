use rayon::prelude::*;
use bytemuck::{Pod, Zeroable};
use sha3::{Digest, Keccak256};
use rand::Rng;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Solution {
    seed: [u8; 8],
    nonces: [[u8; 3]; 64],
}

pub fn get_commitment(packed: &Solution) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(packed.seed); // seed is already [u8; 8]
    for nonce_bytes in packed.nonces.iter() {
        let mut nonce_full = [0u8; 4];
        nonce_full[0..3].copy_from_slice(nonce_bytes);
        hasher.update(&nonce_full);
    }
    hasher.finalize().into()
}

pub fn serialize(packed: &Solution) -> [u8; 200] {
    let bytes = bytemuck::bytes_of(packed);
    let mut result = [0u8; 200];
    result.copy_from_slice(bytes);
    result
}

pub fn deserialize(packed: &[u8; 200]) -> Solution {
    let mut result = Solution {
        seed: [0; 8],
        nonces: [[0; 3]; 64],
    };
    let bytes = bytemuck::bytes_of_mut(&mut result);
    bytes.copy_from_slice(packed);
    result
}

pub fn to_seed_and_nonces(packed: &Solution) -> (u64, Vec<u32>) {
    let seed = u64::from_le_bytes(packed.seed);
    let mut nonces = Vec::with_capacity(64);
    for nonce_bytes in packed.nonces.iter() {
        let mut nonce_full = [0u8; 4];
        nonce_full[0..3].copy_from_slice(nonce_bytes);
        nonces.push(u32::from_le_bytes(nonce_full));
    }
    (seed, nonces)
}

pub fn packx(pubkey: &[u8; 32], data: &[u8; 128]) -> Solution {
    let max_nonce: u32 = (1 << 24) - 1; // u24: 0 to 16777215
    let mut seed: u64 = rand::thread_rng().gen();
    let mut result = Solution { seed: [0; 8], nonces: [[0; 3]; 64] };

    loop {
        result.seed = seed.to_le_bytes();
        let nonces: Vec<Option<u32>> = (0..64)
            .into_par_iter()
            .map(|chunk_idx| {
                let offset = chunk_idx * 2;
                let target = &data[offset..offset + 2];
                for nonce in 0..=max_nonce {
                    let mut hasher = Keccak256::new();
                    hasher.update(pubkey);
                    hasher.update(seed.to_le_bytes());
                    hasher.update(nonce.to_le_bytes());
                    hasher.update((chunk_idx as u64).to_le_bytes());
                    let hash = hasher.finalize();
                    if hash[0..2] == *target {
                        return Some(nonce);
                    }
                }
                None
            })
            .collect();

        if nonces.iter().all(|r| r.is_some()) {
            for (i, nonce) in nonces.into_iter().enumerate() {
                let nonce_bytes = nonce.unwrap().to_le_bytes();
                result.nonces[i].copy_from_slice(&nonce_bytes[0..3]);
            }
            break;
        }
        seed = seed.wrapping_add(1);
    }
    result
}

pub fn verify(
    pubkey: &[u8; 32],
    data: &[u8; 128],
    packed: &Solution,
    commitment: Option<&[u8; 32]>,
) -> bool {
    if let Some(comm) = commitment {
        let computed_comm = get_commitment(packed);
        if computed_comm != *comm {
            return false;
        }
    }
    for chunk_idx in 0..64 {
        let offset = chunk_idx * 2;
        let target = &data[offset..offset + 2];
        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        hasher.update(packed.seed);
        let mut nonce_bytes = [0u8; 4];
        nonce_bytes[0..3].copy_from_slice(&packed.nonces[chunk_idx]);
        hasher.update(&nonce_bytes);
        hasher.update((chunk_idx as u64).to_le_bytes());
        let hash = hasher.finalize();
        if hash[0..2] != *target {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::*;

    #[test]
    fn test_packx_and_verify() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut data);

        let packed = packx(&pubkey, &data);
        let commitment = get_commitment(&packed);
        assert!(verify(&pubkey, &data, &packed, Some(&commitment)));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut rng = rand::thread_rng();
        let seed = rng.gen::<u64>();
        let mut packed = Solution { seed: seed.to_le_bytes(), nonces: [[0; 3]; 64] };
        for nonce in packed.nonces.iter_mut() {
            let n : u32 = rng.gen_range(0..=(1 << 24) - 1);
            nonce.copy_from_slice(&n.to_le_bytes()[0..3]);
        }

        let serialized = serialize(&packed);
        let deserialized = deserialize(&serialized);

        assert_eq!(packed.seed, deserialized.seed);
        assert_eq!(packed.nonces, deserialized.nonces);
    }

    #[test]
    fn test_commitment_consistency() {
        let mut rng = rand::thread_rng();
        let seed = rng.gen::<u64>();
        let mut packed = Solution { seed: seed.to_le_bytes(), nonces: [[0; 3]; 64] };
        for nonce in packed.nonces.iter_mut() {
            let n : u32 = rng.gen_range(0..=(1 << 24) - 1);
            nonce.copy_from_slice(&n.to_le_bytes()[0..3]);
        }

        let commitment1 = get_commitment(&packed);
        let commitment2 = get_commitment(&packed);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_verify_failure_wrong_data() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut data);

        let packed = packx(&pubkey, &data);
        let commitment = get_commitment(&packed);

        let mut wrong_data = data;
        wrong_data[0] ^= 1; // Flip a bit in data

        assert!(!verify(&pubkey, &wrong_data, &packed, Some(&commitment)));
    }

    #[test]
    fn test_verify_failure_wrong_pubkey() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut data);

        let packed = packx(&pubkey, &data);
        let commitment = get_commitment(&packed);

        let mut wrong_pubkey = pubkey;
        wrong_pubkey[0] ^= 1; // Flip a bit in pubkey

        assert!(!verify(&wrong_pubkey, &data, &packed, Some(&commitment)));
    }

    #[test]
    fn test_verify_failure_wrong_commitment() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut data);

        let packed = packx(&pubkey, &data);
        let mut wrong_commitment = get_commitment(&packed);
        wrong_commitment[0] ^= 1; // Flip a bit in commitment

        assert!(!verify(&pubkey, &data, &packed, Some(&wrong_commitment)));
    }

    #[test]
    fn test_packx_zero_data() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let data = [0u8; 128];

        let packed = packx(&pubkey, &data);
        let commitment = get_commitment(&packed);

        assert!(verify(&pubkey, &data, &packed, Some(&commitment)));
    }
}
