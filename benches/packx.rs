use criterion::{criterion_group, criterion_main, Criterion};
use packx::{packx, serialize, verify, get_commitment};
use rand::RngCore;

fn bench_packx_and_verify(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut pubkey = [0u8; 32];
    rng.fill_bytes(&mut pubkey);
    let mut data = [0u8; 128];
    rng.fill_bytes(&mut data);

    c.bench_function("packx", |b| {
        b.iter(|| {
            let packed = packx(&pubkey, &data);
            let _ = serialize(&packed);
        })
    });

    let packed = packx(&pubkey, &data);
    let _packed_bytes = serialize(&packed);
    let commitment = get_commitment(&packed);

    c.bench_function("verify", |b| {
        b.iter(|| {
            verify(&pubkey, &data, &packed, Some(&commitment));
        })
    });
}

criterion_group!(benches, bench_packx_and_verify);
criterion_main!(benches);
