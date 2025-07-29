use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use packx::{find_nonce_for_chunk, solve_with_seed, verify};
use rand::{RngCore, Rng};
use rayon::prelude::*;

fn bench_parallel_nonce_search_and_verify(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut pubkey = [0u8; 32];
    let mut data = [0u8; 128];
    rng.fill_bytes(&mut pubkey);
    rng.fill_bytes(&mut data);

    // Benchmark for solve_with_seed (single-threaded, fewer samples)
    let mut group = c.benchmark_group("solve_with_seed_group");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.bench_function("solve_with_seed", |b| {
        b.iter(|| {
            let mut seed = rng.gen::<u64>();
            let solution = loop {
                if let Some(solution) = solve_with_seed(&pubkey, &data, seed) {
                    break solution;
                }
                seed = seed.wrapping_add(1);
            };
            solution
        })
    });
    group.finish();

    // Benchmark for parallel nonce search
    c.bench_function("parallel_nonce_search", |b| {
        b.iter(|| {
            let mut seed = rng.gen::<u64>();
            let solution = loop {
                let nonces: Vec<Option<u32>> = (0..64)
                    .into_par_iter()
                    .map(|chunk_idx| {
                        let offset = chunk_idx * 2;
                        let target = [data[offset], data[offset + 1]];
                        find_nonce_for_chunk(&pubkey, seed, chunk_idx as u64, &target)
                    })
                    .collect();

                if nonces.iter().all(|r| r.is_some()) {
                    break;
                }
                seed = seed.wrapping_add(1);
            };
            solution
        })
    });

    // Precompute a solution for the verify benchmark
    let mut seed = rng.gen::<u64>();
    let packed = loop {
        if let Some(solution) = solve_with_seed(&pubkey, &data, seed) {
            break solution;
        }
        seed = seed.wrapping_add(1);
    };

    c.bench_function("verify", |b| {
        b.iter(|| {
            verify(&pubkey, &data, &packed)
        })
    });
}

criterion_group!(benches, bench_parallel_nonce_search_and_verify);
criterion_main!(benches);
