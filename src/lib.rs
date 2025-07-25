use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use rand::Rng;

pub fn get_commitment(seed: &u64, nonces: &[u16]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(seed.to_le_bytes());
    for nonce in nonces {
        hasher.update(nonce.to_le_bytes());
    }
    hasher.finalize().into()
}

pub fn serialize(seed: u64, nonces: &[u16]) -> [u8; 200] {
    let mut packed = [0u8; 200];
    packed[0..8].copy_from_slice(&seed.to_le_bytes());
    for i in 0..64 {
        let nonce1 = nonces[2 * i];
        let nonce2 = nonces[2 * i + 1];
        let combined = (nonce1 as u32) | ((nonce2 as u32) << 12);
        let bytes = combined.to_le_bytes();
        packed[8 + i * 3..8 + (i + 1) * 3].copy_from_slice(&bytes[0..3]);
    }
    packed
}

pub fn deserialize(packed: &[u8; 200]) -> (u64, Vec<u16>) {
    let seed = u64::from_le_bytes(packed[0..8].try_into().unwrap());
    let mut nonces = Vec::with_capacity(128);
    for i in 0..64 {
        let start = 8 + i * 3;
        let mut bytes = [0u8; 4];
        bytes[0..3].copy_from_slice(&packed[start..start + 3]);
        let combined = u32::from_le_bytes(bytes);
        let nonce1 = (combined & 0xFFF) as u16;
        let nonce2 = (combined >> 12) as u16;
        nonces.push(nonce1);
        nonces.push(nonce2);
    }
    (seed, nonces)
}

pub fn packx(pubkey: &[u8; 32], data: &[u8; 128]) -> (u64, Vec<u16>) {
    let max_nonce: u16 = (1 << 12) - 1; // u12: 0 to 4095
    let mut seed: u64 = rand::thread_rng().r#gen();
    let mut nonces = Vec::with_capacity(128);

    loop {
        nonces.clear();
        // Parallelize chunk processing
        let results: Vec<Option<u16>> = (0..128)
            .into_par_iter()
            .map(|chunk_idx| {
                let offset = chunk_idx;
                let target = &data[offset..offset + 1];
                for nonce in 0..=max_nonce {
                    let mut hasher = Keccak256::new();
                    hasher.update(pubkey);
                    hasher.update(seed.to_le_bytes());
                    hasher.update(nonce.to_le_bytes());
                    hasher.update((chunk_idx as u64).to_le_bytes());
                    let hash = hasher.finalize();
                    if hash[0..1] == *target {
                        return Some(nonce);
                    }
                }
                None
            })
            .collect();

        // Check if all chunks have a matching nonce
        if results.iter().all(|r| r.is_some()) {
            nonces.extend(results.into_iter().map(|r| r.unwrap()));
            break;
        }
        seed = seed.wrapping_add(1);
    }
    (seed, nonces)
}

pub fn verify(
    pubkey: &[u8; 32],
    data: &[u8; 128],
    packed: &[u8; 200],
    commitment: Option<&[u8; 32]>,
) -> bool {
    let (seed, nonces) = deserialize(packed);
    if nonces.len() != 128 {
        return false;
    }
    if let Some(comm) = commitment {
        let computed_comm = get_commitment(&seed, &nonces);
        if computed_comm != *comm {
            return false;
        }
    }
    for chunk_idx in 0..128 {
        let offset = chunk_idx;
        let target = &data[offset..offset + 1];
        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        hasher.update(seed.to_le_bytes());
        hasher.update(nonces[chunk_idx].to_le_bytes());
        hasher.update((chunk_idx as u64).to_le_bytes());
        let hash = hasher.finalize();
        if hash[0..1] != *target {
            return false;
        }
    }
    true
}



#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_packx_and_verify() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut data);

        let (seed, nonces) = packx(&pubkey, &data);
        let packed = serialize(seed, &nonces);
        let commitment = get_commitment(&seed, &nonces);
        assert!(verify(&pubkey, &data, &packed, Some(&commitment)));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut rng = rand::thread_rng();
        let seed = rng.gen::<u64>();
        let mut nonces = vec![0u16; 128];
        for nonce in nonces.iter_mut() {
            *nonce = rng.gen_range(0..=(1 << 12) - 1);
        }

        let packed = serialize(seed, &nonces);
        let (deserialized_seed, deserialized_nonces) = deserialize(&packed);

        assert_eq!(seed, deserialized_seed);
        assert_eq!(nonces, deserialized_nonces);
    }

    #[test]
    fn test_commitment_consistency() {
        let mut rng = rand::thread_rng();
        let seed = rng.gen::<u64>();
        let mut nonces = vec![0u16; 128];
        rng.fill(&mut nonces[..]);

        let commitment1 = get_commitment(&seed, &nonces);
        let commitment2 = get_commitment(&seed, &nonces);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_verify_failure_wrong_data() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut data);

        let (seed, nonces) = packx(&pubkey, &data);
        let packed = serialize(seed, &nonces);
        let commitment = get_commitment(&seed, &nonces);

        let mut wrong_data = data.clone();
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

        let (seed, nonces) = packx(&pubkey, &data);
        let packed = serialize(seed, &nonces);
        let commitment = get_commitment(&seed, &nonces);

        let mut wrong_pubkey = pubkey.clone();
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

        let (seed, nonces) = packx(&pubkey, &data);
        let packed = serialize(seed, &nonces);
        let mut wrong_commitment = get_commitment(&seed, &nonces);
        wrong_commitment[0] ^= 1; // Flip a bit in commitment

        assert!(!verify(&pubkey, &data, &packed, Some(&wrong_commitment)));
    }

    #[test]
    fn test_packx_zero_data() {
        let mut rng = rand::thread_rng();
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let data = [0u8; 128];

        let (seed, nonces) = packx(&pubkey, &data);
        let packed = serialize(seed, &nonces);
        let commitment = get_commitment(&seed, &nonces);

        assert!(verify(&pubkey, &data, &packed, Some(&commitment)));
    }
}
