// SPDX-License-Identifier: MIT OR Apache-2.0
//! Timing harness (benches/-style, std-only). Ignored by default because
//! timings are only meaningful in release builds on a quiet machine:
//!
//! ```text
//! cargo test --release --offline --test bench_timing -- --ignored --nocapture
//! ```
//!
//! Environment knobs:
//! * `SEDIMENT_BENCH_SIZE`  data size in bytes (default 8 MiB, max 256 MiB)
//! * `SEDIMENT_BENCH_ITERS` iterations per codec (default 3)
//! * `SEDIMENT_BENCH_DICT`  LZMA dictionary bits (default 22)
//!
//! Each test prints a table and still asserts round-trip correctness, so a
//! regression that breaks a codec fails the run instead of printing a number.
use std::time::Instant;

use sediment_engine::bench::{
    all_codecs, bench_codec, format_codec_table, format_lzma_table, generate_bench_data, lzma_bench_pass,
};
use sediment_engine::cli_bench::BENCH_SEED;
use sediment_engine::cli_hash::{hash_reader, CHUNK};
use sediment_engine::hash_multi::ALL_METHODS;

fn knob(name: &str, default: usize, max: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default).clamp(1, max)
}

fn setup() -> (Vec<u8>, u32, u8) {
    let size = knob("SEDIMENT_BENCH_SIZE", 8 << 20, 256 << 20).max(1024);
    let iters = knob("SEDIMENT_BENCH_ITERS", 3, 1000) as u32;
    let dict = knob("SEDIMENT_BENCH_DICT", 22, 26).max(16) as u8;
    let t = Instant::now();
    let data = generate_bench_data(size, 1 << dict, BENCH_SEED).unwrap();
    eprintln!("generated {size} bytes in {:?} (dict 2^{dict}, {iters} iterations)", t.elapsed());
    (data, iters, dict)
}

#[test]
#[ignore]
fn timing_codec_table() {
    let (data, iters, dict) = setup();
    let results: Vec<_> = all_codecs().into_iter().map(|c| bench_codec(c, &data, iters, dict).unwrap()).collect();
    println!("{}", format_codec_table(&results));
}

#[test]
#[ignore]
fn timing_lzma_rating() {
    let (data, iters, dict) = setup();
    let passes: Vec<_> = (0..iters).map(|_| lzma_bench_pass(&data, dict).unwrap()).collect();
    println!("{}", format_lzma_table(dict, &passes));
}

#[test]
#[ignore]
fn timing_multi_hash_stream() {
    // All methods at once through the `sediment h` streaming path.
    let (data, iters, _) = setup();
    let t = Instant::now();
    for _ in 0..iters {
        let (n, ds) = hash_reader(&mut std::io::Cursor::new(&data), &ALL_METHODS, u64::MAX).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(ds.len(), ALL_METHODS.len());
    }
    let secs = t.elapsed().as_secs_f64().max(1e-9);
    println!(
        "h -scrc* streaming ({} KiB chunks): {:.1} MB/s",
        CHUNK / 1024,
        data.len() as f64 * iters as f64 / 1e6 / secs
    );
}
