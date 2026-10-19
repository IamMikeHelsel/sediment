// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deflate64 decoder tests.
//!
//! Fixtures come from tests/gen/deflate64.py: `.d64` files are hand-assembled
//! by a small spec-based Deflate64 encoder (cross-checked against Info-ZIP
//! `unzip` with `--verify-unzip`), `.deflate` files are RFC 1951 streams from
//! Python's zlib whose data cannot contain the codes that differ in Deflate64.

use sediment_engine::crc32::crc32;
use sediment_engine::deflate64::{
    Deflate64Error, MAX_MATCH, WINDOW_SIZE, distance_spec64, inflate64_raw, inflate64_raw_prefix,
    length_spec64,
};
use sediment_engine::inflate::inflate_raw;
use std::path::PathBuf;

const BIG: usize = 1 << 24;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/deflate64")
}

struct Fixture {
    name: String,
    raw: Vec<u8>,
    size: usize,
    crc: u32,
}

fn fixtures() -> Vec<Fixture> {
    let manifest = std::fs::read_to_string(fixture_dir().join("manifest.txt")).unwrap();
    manifest
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(parts.len(), 3, "bad manifest line {line}");
            Fixture {
                name: parts[0].to_string(),
                raw: std::fs::read(fixture_dir().join(parts[0])).unwrap(),
                size: parts[1].parse().unwrap(),
                crc: u32::from_str_radix(parts[2], 16).unwrap(),
            }
        })
        .collect()
}

fn d64_fixtures() -> Vec<Fixture> {
    fixtures().into_iter().filter(|f| f.name.ends_with(".d64")).collect()
}

fn deflate_fixtures() -> Vec<Fixture> {
    fixtures()
        .into_iter()
        .filter(|f| f.name.ends_with(".deflate") && f.name != "uses_code285.deflate")
        .collect()
}

fn fixture(name: &str) -> Fixture {
    fixtures().into_iter().find(|f| f.name == name).unwrap()
}

// ------------------------------------------------------------ test bit sink
/// LSB-first bit writer for hand-built malformed streams.
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn new() -> Self {
        Bits { out: Vec::new(), acc: 0, n: 0 }
    }
    fn put(&mut self, value: u32, width: u32) -> &mut Self {
        self.acc |= u64::from(value) << self.n;
        self.n += width;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
        self
    }
    /// Huffman code, most significant bit first.
    fn code(&mut self, code: u32, len: u32) -> &mut Self {
        for i in (0..len).rev() {
            self.put((code >> i) & 1, 1);
        }
        self
    }
    fn finish(&mut self) -> Vec<u8> {
        if self.n > 0 {
            let pad = 8 - self.n;
            self.put(0, pad);
        }
        std::mem::take(&mut self.out)
    }
}

/// Fixed-code literal/length symbol writer (RFC 1951 3.2.6).
fn fixed_sym(b: &mut Bits, sym: u32) {
    match sym {
        0..=143 => b.code(0x30 + sym, 8),
        144..=255 => b.code(0x190 + sym - 144, 9),
        256..=279 => b.code(sym - 256, 7),
        _ => b.code(0xC0 + sym - 280, 8),
    };
}

fn fixed_header(b: &mut Bits, last: bool) {
    b.put(last as u32, 1).put(1, 2);
}

// ------------------------------------------------------------ positive
#[test]
fn tables_match_spec() {
    assert_eq!(length_spec64(257), Some((3, 0)));
    assert_eq!(length_spec64(284), Some((227, 5)));
    assert_eq!(length_spec64(285), Some((3, 16)));
    assert_eq!(length_spec64(256), None);
    assert_eq!(length_spec64(286), None);
    assert_eq!(distance_spec64(0), Some((1, 0)));
    assert_eq!(distance_spec64(29), Some((24577, 13)));
    assert_eq!(distance_spec64(30), Some((32769, 14)));
    assert_eq!(distance_spec64(31), Some((49153, 14)));
    assert_eq!(distance_spec64(32), None);
    assert_eq!(49153 + (1 << 14) - 1, WINDOW_SIZE as u32);
    assert_eq!(3 + 0xFFFF, MAX_MATCH);
}

#[test]
fn decodes_all_deflate64_fixtures() {
    let all = d64_fixtures();
    assert!(all.len() >= 13);
    for f in &all {
        let out = inflate64_raw(&f.raw, BIG, 1024).unwrap_or_else(|e| panic!("{}: {e:?}", f.name));
        assert_eq!(out.len(), f.size, "{}", f.name);
        assert_eq!(crc32(&out), f.crc, "{}", f.name);
    }
}

#[test]
fn fixed_hello_exact_bytes() {
    let f = fixture("fixed_hello.d64");
    assert_eq!(inflate64_raw(&f.raw, 100, 1).unwrap(), b"Hello, Deflate64! Hello, Deflate64!");
}

#[test]
fn len285_max_and_min_lengths() {
    let f = fixture("fixed_len285.d64");
    let out = inflate64_raw(&f.raw, BIG, 1).unwrap();
    // "abc" then a 65538-byte copy at distance 3, then 3 at distance 1,
    // then 200 at distance 7, all coded with symbol 285.
    assert_eq!(out.len(), 3 + MAX_MATCH + 3 + 200);
    for (i, &b) in out[..3 + MAX_MATCH].iter().enumerate() {
        assert_eq!(b, b"abc"[i % 3]);
    }
    let last = out[3 + MAX_MATCH - 1];
    assert!(out[3 + MAX_MATCH..3 + MAX_MATCH + 3].iter().all(|&b| b == last));
}

#[test]
fn far_distance_codes_30_31() {
    let f = fixture("fixed_far_dist.d64");
    let out = inflate64_raw(&f.raw, BIG, 1).unwrap();
    assert_eq!(out.len(), f.size);
    // The match at distance 65536 copies the first 1000 bytes of history
    // (the 1200 random head bytes start at 0; output was 67200 long).
    assert_eq!(&out[67200..68200], &out[67200 - 65536..68200 - 65536]);
}

#[test]
fn exact_output_limit_and_one_below() {
    for f in d64_fixtures() {
        assert!(inflate64_raw(&f.raw, f.size, 1024).is_ok(), "{}", f.name);
        if f.size > 0 {
            assert_eq!(
                inflate64_raw(&f.raw, f.size - 1, 1024),
                Err(Deflate64Error::LimitExceeded),
                "{}",
                f.name
            );
        }
    }
}

#[test]
fn block_limit() {
    let f = fixture("stored_multi.d64");
    assert!(inflate64_raw(&f.raw, BIG, 3).is_ok());
    assert_eq!(inflate64_raw(&f.raw, BIG, 2), Err(Deflate64Error::LimitExceeded));
    assert_eq!(inflate64_raw(&f.raw, BIG, 0), Err(Deflate64Error::LimitExceeded));
}

#[test]
fn trailing_data_and_prefix() {
    let f = fixture("dynamic_ext.d64");
    let mut buf = f.raw.clone();
    buf.extend_from_slice(b"PK\x07\x08tail");
    assert_eq!(inflate64_raw(&buf, BIG, 16), Err(Deflate64Error::TrailingData));
    let (out, used) = inflate64_raw_prefix(&buf, BIG, 16).unwrap();
    assert_eq!(used, f.raw.len());
    assert_eq!(crc32(&out), f.crc);
}

// ------------------------------------------------------------ differential
#[test]
fn regular_deflate_streams_decode_identically() {
    let all = deflate_fixtures();
    assert!(all.len() >= 10);
    for f in &all {
        let a = inflate_raw(&f.raw, BIG, 4096).unwrap_or_else(|e| panic!("{} inflate {e:?}", f.name));
        let b = inflate64_raw(&f.raw, BIG, 4096)
            .unwrap_or_else(|e| panic!("{} inflate64 {e:?}", f.name));
        assert_eq!(a, b, "{}", f.name);
        assert_eq!(b.len(), f.size, "{}", f.name);
        assert_eq!(crc32(&b), f.crc, "{}", f.name);
    }
}

#[test]
fn code_285_differs_from_rfc1951() {
    // zlib encodes runs of 'a' with symbol 285 (= length 258 in RFC 1951).
    // In Deflate64 that symbol carries 16 extra bits, so the result must not
    // match the RFC 1951 decoding.
    let f = fixture("uses_code285.deflate");
    let a = inflate_raw(&f.raw, BIG, 16).unwrap();
    assert_eq!(a, vec![b'a'; 1000]);
    assert_ne!(inflate64_raw(&f.raw, BIG, 16).ok(), Some(a));
}

// ------------------------------------------------------------ malformed
#[test]
fn every_truncation_errors() {
    for f in d64_fixtures().iter().chain(deflate_fixtures().iter()) {
        let step = if f.raw.len() > 4000 { 37 } else { 1 };
        let mut cut = 0;
        while cut < f.raw.len() {
            let r = inflate64_raw(&f.raw[..cut], BIG, 1024);
            assert!(r.is_err(), "{} cut at {cut} decoded", f.name);
            cut += step;
        }
        // The final byte always matters for these streams.
        assert!(inflate64_raw(&f.raw[..f.raw.len() - 1], BIG, 1024).is_err(), "{}", f.name);
    }
}

#[test]
fn bit_flips_never_panic() {
    let mut s: u32 = 0x1234_5678;
    for f in d64_fixtures() {
        if f.raw.is_empty() {
            continue;
        }
        let iters = if f.raw.len() > 4000 { 40 } else { 200 };
        for _ in 0..iters {
            let mut buf = f.raw.clone();
            for _ in 0..3 {
                s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
                let pos = (s >> 8) as usize % buf.len();
                buf[pos] ^= 1 << ((s >> 4) & 7);
            }
            // Must return (Ok or Err) without panicking; output stays bounded.
            if let Ok(out) = inflate64_raw(&buf, 1 << 20, 64) {
                assert!(out.len() <= 1 << 20);
            }
        }
    }
}

#[test]
fn random_garbage_never_panics() {
    let mut s: u32 = 99;
    for len in 0..300usize {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            buf.push((s >> 16) as u8);
        }
        let _ = inflate64_raw(&buf, 1 << 18, 64);
        let _ = inflate64_raw_prefix(&buf, 1 << 18, 64);
    }
}

#[test]
fn empty_input() {
    assert_eq!(inflate64_raw(&[], BIG, 1), Err(Deflate64Error::UnexpectedEof));
}

#[test]
fn reserved_block_type() {
    let raw = Bits::new().put(1, 1).put(3, 2).finish();
    assert_eq!(inflate64_raw(&raw, BIG, 1), Err(Deflate64Error::InvalidBlockType));
}

#[test]
fn stored_len_nlen_mismatch() {
    let raw = Bits::new().put(1, 1).put(0, 2).put(0, 5).put(5, 16).put(0, 16).finish();
    assert_eq!(inflate64_raw(&raw, BIG, 1), Err(Deflate64Error::InvalidStoredLength));
}

#[test]
fn stored_truncated_payload() {
    let mut raw = Bits::new().put(1, 1).put(0, 2).put(0, 5).put(5, 16).put(!5u32 & 0xFFFF, 16).finish();
    raw.extend_from_slice(b"abcd");
    assert_eq!(inflate64_raw(&raw, BIG, 1), Err(Deflate64Error::UnexpectedEof));
    raw.push(b'e');
    assert_eq!(inflate64_raw(&raw, BIG, 1).unwrap(), b"abcde");
}

#[test]
fn distance_before_start() {
    // literal 'x' then length 3 at distance 2 (only one byte of history).
    let mut b = Bits::new();
    fixed_header(&mut b, true);
    fixed_sym(&mut b, b'x' as u32);
    fixed_sym(&mut b, 257);
    b.code(1, 5); // distance code 1 -> distance 2
    fixed_sym(&mut b, 256);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidDistance));
}

#[test]
fn match_with_no_history() {
    let mut b = Bits::new();
    fixed_header(&mut b, true);
    fixed_sym(&mut b, 257);
    b.code(0, 5);
    fixed_sym(&mut b, 256);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidDistance));
}

#[test]
fn far_distance_exceeding_history() {
    // 10 literals, then a match at distance code 31 (>= 49153).
    let mut b = Bits::new();
    fixed_header(&mut b, true);
    for _ in 0..10 {
        fixed_sym(&mut b, b'q' as u32);
    }
    fixed_sym(&mut b, 257);
    b.code(31, 5).put(0, 14);
    fixed_sym(&mut b, 256);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidDistance));
}

#[test]
fn fixed_symbols_286_287_are_invalid() {
    for sym in [286u32, 287] {
        let mut b = Bits::new();
        fixed_header(&mut b, true);
        fixed_sym(&mut b, b'x' as u32);
        fixed_sym(&mut b, sym);
        b.code(0, 5);
        fixed_sym(&mut b, 256);
        assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidCode), "{sym}");
    }
}

#[test]
fn len285_truncated_extra_bits() {
    let mut b = Bits::new();
    fixed_header(&mut b, true);
    fixed_sym(&mut b, b'x' as u32);
    fixed_sym(&mut b, 285);
    b.put(0xFF, 8); // only 8 of 16 extra bits
    let raw = b.finish();
    assert_eq!(inflate64_raw(&raw, BIG, 1), Err(Deflate64Error::UnexpectedEof));
}

#[test]
fn len285_max_respects_output_limit() {
    let mut b = Bits::new();
    fixed_header(&mut b, true);
    fixed_sym(&mut b, b'x' as u32);
    fixed_sym(&mut b, 285);
    b.put(0xFFFF, 16);
    b.code(0, 5);
    fixed_sym(&mut b, 256);
    let raw = b.finish();
    assert_eq!(inflate64_raw(&raw, MAX_MATCH, 1), Err(Deflate64Error::LimitExceeded));
    let out = inflate64_raw(&raw, MAX_MATCH + 1, 1).unwrap();
    assert!(out.iter().all(|&c| c == b'x'));
}

/// Writes a dynamic header with the given (hlit, hdist, hclen) and a
/// code-length code where symbols 0..=15 all get length 4 except as given.
fn dyn_header(b: &mut Bits, hlit: u32, hdist: u32, cl_lens: &[u8; 19]) {
    const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    b.put(1, 1).put(2, 2).put(hlit - 257, 5).put(hdist - 1, 5).put(15, 4);
    for &i in ORDER.iter() {
        b.put(u32::from(cl_lens[i]), 3);
    }
}

#[test]
fn dynamic_hlit_too_large() {
    let mut b = Bits::new();
    let cl = [3u8; 19];
    // hlit field 30 -> 287 literal/length codes: invalid.
    b.put(1, 1).put(2, 2).put(30, 5).put(0, 5).put(15, 4);
    for _ in 0..19 {
        b.put(u32::from(cl[0]), 3);
    }
    b.put(0, 32);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidTree));
}

#[test]
fn dynamic_incomplete_code_length_code() {
    let mut cl = [0u8; 19];
    cl[0] = 2;
    cl[8] = 2;
    cl[18] = 2; // three 2-bit codes: incomplete
    let mut b = Bits::new();
    dyn_header(&mut b, 257, 1, &cl);
    b.put(0, 32);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidTree));
}

#[test]
fn dynamic_oversubscribed_code_length_code() {
    let cl = [1u8; 19];
    let mut b = Bits::new();
    dyn_header(&mut b, 257, 1, &cl);
    b.put(0, 32);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidTree));
}

/// Code-length code where symbols 0..=15 have 4-bit codes (16 symbols, a
/// complete code); 16/17/18 are absent.
fn cl_4bit() -> [u8; 19] {
    let mut cl = [0u8; 19];
    cl[..16].fill(4);
    cl
}

#[test]
fn dynamic_repeat_without_previous() {
    let mut cl = [0u8; 19];
    cl[16] = 1;
    cl[8] = 1;
    let mut b = Bits::new();
    dyn_header(&mut b, 257, 1, &cl);
    // canonical: 8 -> '0', 16 -> '1'. First symbol is 16.
    b.code(1, 1).put(0, 2);
    b.put(0, 32);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidTree));
}

#[test]
fn dynamic_repeat_overflows_lengths() {
    let mut cl = [0u8; 19];
    cl[18] = 1;
    cl[8] = 1;
    let mut b = Bits::new();
    dyn_header(&mut b, 257, 1, &cl);
    // 18 with 127 -> 138 zeros, twice = 276 > 258 (257 + 1) lengths.
    b.code(1, 1).put(127, 7);
    b.code(1, 1).put(127, 7);
    b.put(0, 32);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidTree));
}

#[test]
fn dynamic_missing_end_of_block_code() {
    // All 257 literal/length codes length 0 except two literals of length 1;
    // symbol 256 has no code.
    let cl = cl_4bit();
    let mut b = Bits::new();
    dyn_header(&mut b, 257, 1, &cl);
    // codes for 0..=15 are 4-bit canonical: symbol k -> code k.
    for i in 0..258 {
        let len = if i == 0 || i == 1 { 1 } else { 0 };
        b.code(len, 4);
    }
    b.put(0, 32);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidTree));
}

#[test]
fn dynamic_incomplete_literal_code() {
    let cl = cl_4bit();
    let mut b = Bits::new();
    dyn_header(&mut b, 257, 1, &cl);
    // literals 0, 1 and 256 with length 2: incomplete (3 of 4 codes).
    for i in 0..258 {
        let len = if i == 0 || i == 1 || i == 256 { 2 } else { 0 };
        b.code(len, 4);
    }
    b.put(0, 32);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 1), Err(Deflate64Error::InvalidTree));
}

/// Dynamic block: literal 'A' and 256 and 285 with length 2 plus symbol 257
/// with length 2 (complete); distance lengths given; then body bits.
fn dyn_with_dist(dist_lens: &[u8], body: impl FnOnce(&mut Bits)) -> Vec<u8> {
    let cl = cl_4bit();
    let mut b = Bits::new();
    dyn_header(&mut b, 286, dist_lens.len() as u32, &cl);
    for i in 0..286 {
        let len = if i == 65 || i == 256 || i == 257 || i == 285 { 2 } else { 0 };
        b.code(len, 4);
    }
    for &l in dist_lens {
        b.code(u32::from(l), 4);
    }
    body(&mut b);
    b.finish()
}

// Literal/length canonical codes in dyn_with_dist: 'A'=00, 256=01, 257=10, 285=11.

#[test]
fn dynamic_32_distance_codes_decode() {
    // 32 distance codes of length 5 (complete); use code 0 (distance 1).
    let raw = dyn_with_dist(&[5u8; 32], |b| {
        b.code(0, 2); // 'A'
        b.code(3, 2).put(10, 16); // len 13
        b.code(0, 5); // dist 1
        b.code(1, 2); // EOB
    });
    assert_eq!(inflate64_raw(&raw, BIG, 1).unwrap(), vec![b'A'; 14]);
}

#[test]
fn dynamic_match_without_distance_tree() {
    let raw = dyn_with_dist(&[0u8; 1], |b| {
        b.code(0, 2);
        b.code(2, 2); // 257 -> length 3
        b.code(1, 2);
    });
    assert_eq!(inflate64_raw(&raw, BIG, 1), Err(Deflate64Error::InvalidCode));
}

#[test]
fn dynamic_single_distance_code_unused_bit() {
    // One distance code (symbol 0) of length 1: bit '1' has no symbol.
    let ok = dyn_with_dist(&[1u8], |b| {
        b.code(0, 2);
        b.code(2, 2);
        b.code(0, 1);
        b.code(1, 2);
    });
    assert_eq!(inflate64_raw(&ok, BIG, 1).unwrap(), b"AAAA");
    let bad = dyn_with_dist(&[1u8], |b| {
        b.code(0, 2);
        b.code(2, 2);
        b.code(1, 1);
        b.code(1, 2);
        // Enough trailing bits that the decoder exhausts the 15-bit code
        // space instead of running out of input.
        b.put(0, 32);
    });
    assert_eq!(inflate64_raw(&bad, BIG, 1), Err(Deflate64Error::InvalidCode));
}

#[test]
fn dynamic_incomplete_distance_code_rejected() {
    let raw = dyn_with_dist(&[2u8, 2, 2], |b| {
        b.code(1, 2);
    });
    assert_eq!(inflate64_raw(&raw, BIG, 1), Err(Deflate64Error::InvalidTree));
}

#[test]
fn missing_final_block() {
    // A non-final empty fixed block followed by nothing.
    let mut b = Bits::new();
    fixed_header(&mut b, false);
    fixed_sym(&mut b, 256);
    assert_eq!(inflate64_raw(&b.finish(), BIG, 8), Err(Deflate64Error::UnexpectedEof));
}

#[test]
fn many_empty_blocks_bounded_by_max_blocks() {
    let mut b = Bits::new();
    for _ in 0..1000 {
        fixed_header(&mut b, false);
        fixed_sym(&mut b, 256);
    }
    fixed_header(&mut b, true);
    fixed_sym(&mut b, 256);
    let raw = b.finish();
    assert_eq!(inflate64_raw(&raw, BIG, 1000), Err(Deflate64Error::LimitExceeded));
    assert_eq!(inflate64_raw(&raw, BIG, 1001).unwrap(), b"");
}

#[test]
fn error_display() {
    assert!(Deflate64Error::InvalidDistance.to_string().contains("distance"));
}
