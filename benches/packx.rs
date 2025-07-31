use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use packx::{solve, verify};
use rand::RngCore;

fn bench_parallel_nonce_search_and_verify(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    // Benchmark solve for difficulties 0 to 4
    let mut solve_group = c.benchmark_group("solve");
    solve_group.sampling_mode(SamplingMode::Flat);
    solve_group.sample_size(10); // Fewer samples for faster benchmarking

    for difficulty in 0..=4 {
        solve_group.bench_function(format!("solve_difficulty_{}", difficulty), |b| {
            b.iter(|| {
                let mut pubkey = [0u8; 32];
                let mut data = [0u8; 128];
                rng.fill_bytes(&mut pubkey);
                rng.fill_bytes(&mut data);

                solve(&pubkey, &data, difficulty).expect("Failed to find solution")
            })
        });
    }
    solve_group.finish();

    // Precompute a solution for verify benchmark (using difficulty 0)
    let mut pubkey = [0u8; 32];
    let mut data = [0u8; 128];
    rng.fill_bytes(&mut pubkey);
    rng.fill_bytes(&mut data);
    let packed = solve(&pubkey, &data, 0).expect("Failed to find solution");

    // Benchmark verify with a single difficulty
    c.bench_function("verify", |b| {
        b.iter(|| {
            verify(&pubkey, &data, &packed, 0)
        })
    });
}

criterion_group!(benches, bench_parallel_nonce_search_and_verify);
criterion_main!(benches);
