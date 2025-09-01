use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use packx::{build_memory, solve_with_memory, verify};
use rand::RngCore;

fn bench_solve_and_verify(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let mut solve_group = c.benchmark_group("solve");
    solve_group.sampling_mode(SamplingMode::Flat);
    solve_group.sample_size(10);

    for i in 0..=4 {
        let mut pubkey = [0u8; 32];
        rng.fill_bytes(&mut pubkey);
        let mem = build_memory(&pubkey);
        let difficulty = i * 4; // 0, 4, 8, 12

        solve_group.bench_function(format!("solve_difficulty_{difficulty}"), |b| {
            b.iter(|| {
                // Fresh random 128-byte message each iteration
                let mut data = [0u8; 128];
                rng.fill_bytes(&mut data);

                // Time just the solve path (precomp already done)
                let solution = solve_with_memory(
                    black_box(&data), 
                    black_box(&mem),
                    black_box(difficulty))
                    .expect("solve failed");

                // Use the result (avoid being optimized out)
                black_box(solution);
            })
        });
    }
    solve_group.finish();

    // Precompute once more with a fresh pubkey and produce one solution we can reuse.
    let mut pubkey = [0u8; 32];
    let mut data = [0u8; 128];
    rng.fill_bytes(&mut pubkey);
    rng.fill_bytes(&mut data);
    let mem = build_memory(&pubkey);
    let packed = solve_with_memory(&data, &mem, 0)
        .expect("Failed to find solution");

    c.bench_function("verify", |b| {
        b.iter(|| {
            black_box(verify(
                black_box(&pubkey),
                black_box(&data),
                black_box(&packed),
                black_box(0),
            ))
        })
    });
}

criterion_group!(benches, bench_solve_and_verify);
criterion_main!(benches);
