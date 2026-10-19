// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZX decoder tests: generator fixture (aligned + uncompressed (odd size) +
//! 1-byte verbatim + verbatim blocks with E8 translation, 7zz-verified via the
//! CAB fixtures built by the same encoder), hand-built streams and hostile
//! input.

mod ms_common;
use ms_common::{cut_points, fixture, mutations};
use sediment_engine::lzx::{FRAME_SIZE, LzxError, lzx_decompress, position_slots};

/// MSB-first writer of 16-bit little-endian words (the LZX bit order).
struct BitW {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitW {
    fn new() -> Self {
        BitW { out: Vec::new(), acc: 0, n: 0 }
    }
    fn put(&mut self, v: u32, bits: u32) {
        for k in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((v >> k) & 1);
            self.n += 1;
            if self.n == 16 {
                self.out.extend_from_slice(&(self.acc as u16).to_le_bytes());
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.put(0, 16 - self.n);
        }
        self.out
    }
}

/// Pretree with symbols {0, 16, 17, 18} at length 2 (codes 00, 01, 10, 11).
fn put_pretree(w: &mut BitW) {
    for s in 0..20 {
        w.put(if [0, 16, 17, 18].contains(&s) { 2 } else { 0 }, 4);
    }
}

/// Encode `count` zero lengths with pretree codes 17/18.
fn zeros(w: &mut BitW, mut count: u32) {
    while count >= 20 {
        let r = count.min(51);
        w.put(0b11, 2);
        w.put(r - 20, 5);
        count -= r;
    }
    while count >= 4 {
        let r = count.min(19);
        w.put(0b10, 2);
        w.put(r - 4, 4);
        count -= r;
    }
    for _ in 0..count {
        w.put(0b00, 2); // delta 0 from previous 0
    }
}

/// Verbatim block (window 2^15) whose main tree has exactly two 1-bit codes:
/// literal 'A' (code 0) and match symbol 256 + 3*8 + 1 = length 3, slot 3 =
/// offset 1 (code 1). `body` is the sequence of 1-bit symbol codes.
fn tiny_verbatim(block_size: u32, body: &[u32]) -> Vec<u8> {
    let mut w = BitW::new();
    tiny_verbatim_into(&mut w, block_size, body);
    w.finish()
}

fn tiny_verbatim_into(w: &mut BitW, block_size: u32, body: &[u32]) {
    w.put(0, 1); // no E8
    w.put(1, 3); // verbatim
    w.put(block_size >> 8, 16);
    w.put(block_size & 0xFF, 8);
    put_pretree(w);
    zeros(w, 65);
    w.put(0b01, 2); // symbol 16: (0 - 16) mod 17 = 1
    zeros(w, 256 - 66);
    put_pretree(w);
    zeros(w, 25);
    w.put(0b01, 2);
    zeros(w, 240 - 26);
    put_pretree(w);
    zeros(w, 249);
    for &b in body {
        w.put(b, 1);
    }
}

#[test]
fn raw_fixture_round_trip() {
    let comp = fixture("cab", "raw16.lzx");
    let want = fixture("cab", "raw16.out");
    let got = lzx_decompress(&comp, 16, want.len(), 0).unwrap();
    assert_eq!(got.len(), want.len());
    assert!(got == want, "raw16 differs");
}

#[test]
fn frame_prefix_decode() {
    // Stopping at a frame boundary yields exactly the first frame.
    let comp = fixture("cab", "raw16.lzx");
    let want = fixture("cab", "raw16.out");
    let got = lzx_decompress(&comp, 16, FRAME_SIZE, 0).unwrap();
    assert!(got[..] == want[..FRAME_SIZE]);
    assert_eq!(lzx_decompress(&comp, 16, 0, 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn wrong_window_is_error_or_different() {
    // The generator stream uses 2^16; 2^15 has fewer main symbols, so the
    // trees no longer line up. It must fail cleanly (or at least not match).
    let comp = fixture("cab", "raw16.lzx");
    let want = fixture("cab", "raw16.out");
    match lzx_decompress(&comp, 15, want.len(), 0) {
        Ok(d) => assert!(d != want),
        Err(_) => {}
    }
}

#[test]
fn hand_built_verbatim_block() {
    let s = tiny_verbatim(4, &[0, 1]);
    assert_eq!(lzx_decompress(&s, 15, 4, 0).unwrap(), b"AAAA");
}

#[test]
fn match_before_any_output_is_rejected() {
    let s = tiny_verbatim(3, &[1]);
    assert_eq!(lzx_decompress(&s, 15, 3, 0), Err(LzxError::InvalidMatch));
}

#[test]
fn match_past_block_end_is_rejected() {
    // block of 2 bytes: 'A' then a 3-byte match overruns the block
    let s = tiny_verbatim(2, &[0, 1]);
    assert_eq!(lzx_decompress(&s, 15, 2, 0), Err(LzxError::InvalidMatch));
}

#[test]
fn uncompressed_block_by_hand() {
    // E8 off, type 3, size 5: 28 header bits, 4 bits of padding to the word
    // boundary, R0..R2, 5 raw bytes, (pad byte omitted at end of stream).
    let mut w = BitW::new();
    w.put(0, 1);
    w.put(3, 3);
    w.put(0, 16);
    w.put(5, 8);
    let mut s = w.finish();
    for r in [1u32, 1, 1] {
        s.extend_from_slice(&r.to_le_bytes());
    }
    s.extend_from_slice(b"hello");
    assert_eq!(lzx_decompress(&s, 15, 5, 0).unwrap(), b"hello");
    // one byte short
    assert_eq!(lzx_decompress(&s[..s.len() - 1], 15, 5, 0), Err(LzxError::Truncated));
}

#[test]
fn uncompressed_block_word_aligned_header_takes_16_pad_bits() {
    // tiny verbatim block: 389 tree/header bits + 16 symbol bits ('A' then
    // fifteen 3-byte matches = 46 bytes); the next block header (27 bits)
    // then ends exactly on a word boundary (432 bits), so a full 16-bit
    // padding word must follow before R0..R2.
    let mut w = BitW::new();
    let mut body = vec![0u32];
    body.extend([1u32; 15]);
    tiny_verbatim_into(&mut w, 46, &body);
    w.put(3, 3);
    w.put(0, 16);
    w.put(3, 8);
    assert_eq!(w.n, 0, "header should end word aligned");
    w.put(0xFFFF, 16); // the padding word (content ignored)
    let mut s = w.finish();
    for r in [1u32, 1, 1] {
        s.extend_from_slice(&r.to_le_bytes());
    }
    s.extend_from_slice(b"xyz");
    let out = lzx_decompress(&s, 15, 49, 0).unwrap();
    assert_eq!(&out[..46], &[b'A'; 46][..]);
    assert_eq!(&out[46..], b"xyz");
}

#[test]
fn invalid_block_types() {
    for t in [0u32, 4, 5, 6, 7] {
        let mut w = BitW::new();
        w.put(0, 1);
        w.put(t, 3);
        w.put(0, 16);
        w.put(9, 8);
        let s = w.finish();
        assert_eq!(lzx_decompress(&s, 15, 9, 0), Err(LzxError::InvalidBlock), "type {t}");
    }
    // zero-sized block
    let mut w = BitW::new();
    w.put(0, 1);
    w.put(1, 3);
    w.put(0, 24);
    assert_eq!(lzx_decompress(&w.finish(), 15, 1, 0), Err(LzxError::InvalidBlock));
}

#[test]
fn oversubscribed_pretree() {
    let mut w = BitW::new();
    w.put(0, 1);
    w.put(1, 3);
    w.put(0, 16);
    w.put(4, 8);
    for _ in 0..20 {
        w.put(1, 4); // twenty 1-bit codes
    }
    w.put(0, 16);
    assert_eq!(lzx_decompress(&w.finish(), 15, 4, 0), Err(LzxError::InvalidTree));
}

#[test]
fn bad_windows() {
    for wb in [0u8, 14, 22, 25, 255] {
        assert_eq!(position_slots(wb), Err(LzxError::InvalidWindow));
        assert_eq!(lzx_decompress(&[0; 16], wb, 1, 0), Err(LzxError::InvalidWindow));
    }
    assert_eq!(position_slots(21), Ok(50));
}

#[test]
fn empty_and_truncated_input() {
    assert_eq!(lzx_decompress(&[], 15, 0, 0).unwrap(), Vec::<u8>::new());
    assert_eq!(lzx_decompress(&[], 15, 1, 0), Err(LzxError::Truncated));
    let comp = fixture("cab", "raw16.lzx");
    let want_len = fixture("cab", "raw16.out").len();
    for cut in cut_points(comp.len()) {
        let r = lzx_decompress(&comp[..cut], 16, want_len, 0);
        assert!(r.is_err(), "cut {cut} decoded");
    }
}

#[test]
fn mutated_input_never_panics() {
    let comp = fixture("cab", "raw16.lzx");
    let want_len = fixture("cab", "raw16.out").len();
    for (i, m) in mutations(&comp, 400, 0x1234_5678).iter().enumerate() {
        let r = lzx_decompress(m, 16, want_len, 0);
        if let Ok(d) = r {
            assert_eq!(d.len(), want_len, "mutation {i}");
        }
        // also with resets every frame, which the stream was not built for
        let _ = lzx_decompress(m, 16, want_len, 1);
    }
}

#[test]
fn output_never_exceeds_request() {
    let comp = fixture("cab", "raw16.lzx");
    for n in [1usize, 2, 3, 100, 9999, 10000, 10001, 20000, 32767, 32769] {
        let d = lzx_decompress(&comp, 16, n, 0).unwrap();
        assert_eq!(d.len(), n);
    }
}
