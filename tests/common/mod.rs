// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(dead_code)]
//! Shared helpers for the LZMA / LZMA2 / xz fixture tests.

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lzma");
pub const DICT_CAP: u64 = 1 << 27;
pub const OUT_CAP: usize = 1 << 24;
pub const NAMES: [&str; 5] = ["empty", "one", "text", "random", "comp"];

pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Must match `compressible()` in tests/gen/xz.py.
pub fn compressible() -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..2000 {
        v.extend_from_slice(format!("sediment lzma fixture line {i:05}\n").as_bytes());
    }
    v
}

pub fn expected(name: &str) -> Vec<u8> {
    match name {
        "empty" => Vec::new(),
        "one" => b"A".to_vec(),
        "text" => fixture("text.bin"),
        "random" => fixture("random.bin"),
        "comp" => compressible(),
        _ => panic!("unknown input {name}"),
    }
}

/// Run `f` on every truncation and on many single-bit flips of `data`;
/// it must never panic. Returns how many truncations were (wrongly) accepted.
pub fn hostile<F: Fn(&[u8]) -> bool>(data: &[u8], f: F) -> usize {
    let mut accepted = 0;
    let step = (data.len() / 200).max(1);
    for cut in (0..data.len()).step_by(step) {
        if f(&data[..cut]) {
            accepted += 1;
        }
    }
    let mut buf = data.to_vec();
    for i in (0..data.len()).step_by(step) {
        for bit in [0u8, 3, 7] {
            buf[i] ^= 1 << bit;
            let _ = f(&buf);
            buf[i] ^= 1 << bit;
        }
    }
    accepted
}
