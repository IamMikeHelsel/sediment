// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(dead_code)]
//! Shared helpers for the CAB / LZX / CFB / CHM fixture tests
//! (fixtures from tests/gen/ms.py, cross-checked by tests/gen/ms_oracle.sh).

pub fn fixture(area: &str, name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{area}/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expect {
    pub dir: bool,
    pub path: String,
    pub size: u64,
    pub crc: Option<u32>,
}

/// Parse a `.expect` manifest: `kind \t path \t size \t crc32hex`.
pub fn expect(area: &str, name: &str) -> Vec<Expect> {
    let text = String::from_utf8(fixture(area, &format!("{name}.expect"))).unwrap();
    text.lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 4, "bad expect line {l:?}");
            Expect {
                dir: f[0] == "d",
                path: f[1].to_string(),
                size: f[2].parse().unwrap(),
                crc: if f[3] == "-" { None } else { Some(u32::from_str_radix(f[3], 16).unwrap()) },
            }
        })
        .collect()
}

pub fn crc(data: &[u8]) -> u32 {
    sediment_engine::crc32::crc32(data)
}

/// Deterministic mutations: `rounds` copies of `data`, each with 1..=4 bytes
/// changed (xor with a non-zero value) and sometimes truncated.
pub fn mutations(data: &[u8], rounds: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut s = seed | 1;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let mut out = Vec::new();
    for _ in 0..rounds {
        let mut d = data.to_vec();
        if d.is_empty() {
            break;
        }
        let n = 1 + (next() % 4) as usize;
        for _ in 0..n {
            let i = (next() % d.len() as u64) as usize;
            let x = (next() % 255) as u8 + 1;
            d[i] ^= x;
        }
        if next() % 5 == 0 {
            let cut = (next() % d.len() as u64) as usize;
            d.truncate(cut);
        }
        out.push(d);
    }
    out
}

/// Prefix lengths to try when truncating `len` bytes: every byte of the first
/// 600, then about 300 evenly spaced cut points.
pub fn cut_points(len: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..len.min(600)).collect();
    let step = (len / 300).max(1);
    v.extend((600..len).step_by(step));
    v
}
