use criterion::{criterion_group, criterion_main, Criterion};
use packx::solve_with_seed;
use rand::{RngCore, Rng};
use rayon::prelude::*;

fn bench_solve_with_seed_and_verify(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut pubkey = [0u8; 32];
    let mut data = [0u8; 128];
    rng.fill_bytes(&mut pubkey);
    rng.fill_bytes(&mut data);

    c.bench_function("solve_with_seed", |b| {
        b.iter(|| {
            // Use rayon to try random seeds in parallel until a valid solution is found
            let solution = (0..rayon::current_num_threads())
                .into_par_iter()
                .find_map_any(|_| {
                    let seed = rand::thread_rng().gen::<u64>();
                    solve_with_seed(&pubkey, &data, seed)
                })
                .expect("No solution found");
            solution
        })
    });
}

criterion_group!(benches, bench_solve_with_seed_and_verify);
criterion_main!(benches);
