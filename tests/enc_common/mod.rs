// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(dead_code)]
//! Shared helpers for the LZMA / LZMA2 / xz encoder tests.

pub const ENC_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lzma_enc");

/// Deterministic xorshift64* byte generator.
pub fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

/// Pseudo-random words: compressible but not trivially (ratio ~0.3).
pub fn wordy(seed: u64, len: usize) -> Vec<u8> {
    const WORDS: [&str; 24] = [
        "sediment", "archive", "stream", "block", "index", "range", "coder", "literal", "match", "rep",
        "dictionary", "window", "chunk", "header", "footer", "check", "filter", "the", "of", "and", "a",
        "to", "in", "is",
    ];
    let r = noise(seed, len / 2 + 16);
    let mut out = Vec::with_capacity(len + 16);
    let mut i = 0;
    while out.len() < len {
        let w = WORDS[r[i % r.len()] as usize % WORDS.len()];
        out.extend_from_slice(w.as_bytes());
        out.push(if r[(i + 7) % r.len()].is_multiple_of(11) { b'\n' } else { b' ' });
        i += 1;
    }
    out.truncate(len);
    out
}

/// One parsed LZMA2 chunk: (control byte, unpacked size, packed size).
pub type Chunk = (u8, usize, usize);

/// Walk the chunk headers of a raw LZMA2 stream. Panics on malformed input
/// (only used on encoder output).
pub fn lzma2_chunks(s: &[u8]) -> Vec<Chunk> {
    let mut v = Vec::new();
    let mut p = 0;
    loop {
        let c = s[p];
        if c == 0 {
            assert_eq!(p + 1, s.len(), "bytes after LZMA2 end marker");
            return v;
        }
        if c < 0x80 {
            assert!(c == 1 || c == 2, "bad control {c:#x}");
            let n = ((s[p + 1] as usize) << 8 | s[p + 2] as usize) + 1;
            v.push((c, n, n));
            p += 3 + n;
        } else {
            let u = (((c & 0x1F) as usize) << 16 | (s[p + 1] as usize) << 8 | s[p + 2] as usize) + 1;
            let k = ((s[p + 3] as usize) << 8 | s[p + 4] as usize) + 1;
            v.push((c, u, k));
            p += 5 + (c >= 0xC0) as usize + k;
        }
    }
}
