use packx::{build_memory, solve_with_memory};
use rand::RngCore;
use rayon::prelude::*;
use std::time::Instant;

fn main() {
    // Generate 100 MiB of random data
    const DATA_SIZE: usize = 100 * 1024 * 1024;
    const CHUNK_SIZE: usize = 128;

    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; DATA_SIZE];
    rng.fill_bytes(&mut data);

    // Random 32-byte pubkey
    let mut pubkey = [0u8; 32];
    rng.fill_bytes(&mut pubkey);

    // Precompute full 18 MiB table (sequential) and time it
    println!("Precomputing full all-bumps table (~18 MiB)...");
    let t0 = Instant::now();
    let mem = build_memory(&pubkey);
    let pre_time = t0.elapsed().as_secs_f64();
    println!("Precompute done in {:.3} s", pre_time);

    // Split data into 128-byte chunks
    let num_chunks = DATA_SIZE / CHUNK_SIZE;
    let chunks: Vec<[u8; 128]> = (0..num_chunks)
        .map(|i| {
            let start = i * CHUNK_SIZE;
            let mut chunk = [0u8; 128];
            chunk.copy_from_slice(&data[start..start + CHUNK_SIZE]);
            chunk
        })
        .collect();

    let total_processed_bytes = num_chunks * CHUNK_SIZE;
    let num_threads = rayon::current_num_threads();
    println!(
        "Processing {:.1} MiB ({} chunks of 128 bytes) across {} threads",
        total_processed_bytes as f64 / (1024.0 * 1024.0),
        num_chunks,
        num_threads
    );

    let start = Instant::now();

    chunks.par_iter().for_each(|chunk| {
        let _ = solve_with_memory(chunk, &mem, 0)
            .expect("No coverage across bumps (unexpected)");
    });

    let duration = start.elapsed().as_secs_f64();
    let speed_mibps = (total_processed_bytes as f64 / (1024.0 * 1024.0)) / duration;

    println!("Solving took {:.3} s", duration);
    println!("Packing speed: {:.1} MiB/s", speed_mibps);
}
