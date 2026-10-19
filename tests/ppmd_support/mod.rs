// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared helpers for the PPMd tests: a Rust port of the deterministic input
//! generator in tests/gen/ppmd.py and the fixture manifest reader.
#![allow(dead_code)]

use std::path::PathBuf;

pub struct Lcg(u64);

impl Lcg {
    pub fn new(seed: u64) -> Lcg {
        Lcg(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

pub fn gen_text(seed: u64, n: usize, vocab_size: u64) -> Vec<u8> {
    let mut r = Lcg::new(seed);
    let letters = b"etaoinshrdlucmfwypvbgkjqxz";
    let mut vocab = Vec::new();
    for _ in 0..vocab_size {
        let ln = 1 + r.next() % 9;
        let mut w = Vec::new();
        for _ in 0..ln {
            let a = r.next() % 26;
            let b = r.next() % 26;
            w.push(letters[a.min(b) as usize]);
        }
        vocab.push(w);
    }
    let mut out = Vec::new();
    while out.len() < n {
        let a = r.next() % vocab_size;
        let b = r.next() % vocab_size;
        out.extend_from_slice(&vocab[a.min(b) as usize]);
        match r.next() % 16 {
            0 => out.extend_from_slice(b".\n"),
            1 => out.extend_from_slice(b", "),
            _ => out.push(b' '),
        }
    }
    out.truncate(n);
    out
}

pub fn gen_binary(seed: u64, n: usize) -> Vec<u8> {
    let mut r = Lcg::new(seed);
    let mut out = Vec::new();
    let mut prev: u8 = 0;
    while out.len() < n {
        let k = r.next() % 8;
        if k == 0 {
            let b = (r.next() & 0xFF) as u8;
            let cnt = 1 + r.next() % 20;
            for _ in 0..cnt {
                out.push(b);
            }
        } else if k < 4 {
            prev = (prev as u64 + (r.next() % 7) + 256 - 3) as u8;
            out.push(prev);
        } else {
            out.push((r.next() & 0xFF) as u8);
        }
    }
    out.truncate(n);
    out
}

pub fn gen_cycle(seed: u64, n: usize) -> Vec<u8> {
    let mut r = Lcg::new(seed);
    let mut out = Vec::new();
    let mut i: u64 = 0;
    while out.len() < n {
        let add = if i.is_multiple_of(97) { r.next() % 3 } else { 0 };
        out.push(((i + add) & 0xFF) as u8);
        i += 1;
    }
    out.truncate(n);
    out
}

pub fn make_input(kind: &str, seed: u64, n: usize, param: u64) -> Vec<u8> {
    match kind {
        "text" => gen_text(seed, n, param),
        "bin" => gen_binary(seed, n),
        "cycle" => gen_cycle(seed, n),
        _ => panic!("unknown kind {kind}"),
    }
}

pub struct Case {
    pub name: String,
    pub container: String,
    pub input: Vec<u8>,
    pub order: u32,
    pub mem: u32,
    pub restore: u32,
    pub stream: Vec<u8>,
}

pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ppmd")
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

pub fn load_cases(container: &str) -> Vec<Case> {
    let dir = fixture_dir();
    let manifest = std::fs::read_to_string(dir.join("manifest.txt")).expect("manifest");
    let mut out = Vec::new();
    for line in manifest.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 11, "bad manifest line {line}");
        if f[1] != container {
            continue;
        }
        let input = make_input(
            f[2],
            f[3].parse().unwrap(),
            f[4].parse().unwrap(),
            f[5].parse().unwrap(),
        );
        let crc = u32::from_str_radix(f[9], 16).unwrap();
        assert_eq!(crc32(&input), crc, "generator mismatch for {}", f[0]);
        out.push(Case {
            name: f[0].to_string(),
            container: f[1].to_string(),
            input,
            order: f[6].parse().unwrap(),
            mem: f[7].parse().unwrap(),
            restore: f[8].parse().unwrap(),
            stream: std::fs::read(dir.join(f[10])).expect("stream"),
        });
    }
    assert!(!out.is_empty());
    out
}
