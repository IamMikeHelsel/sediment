// SPDX-License-Identifier: MIT OR Apache-2.0
//! SHA-1 (FIPS 180-4, section 6.1).
//!
//! Implemented from NIST FIPS PUB 180-4 "Secure Hash Standard". SHA-1 is not
//! collision resistant; it is provided for archive-format compatibility.
//!
//! Streaming: [`Sha1::new`], [`Sha1::update`], [`Sha1::finalize`]. One-shot: [`sha1`].
//! Hashing never fails and never allocates.

/// Digest length in bytes.
pub const SHA1_DIGEST_LEN: usize = 20;
const BLOCK: usize = 64;

/// Streaming SHA-1 state.
#[derive(Clone, Debug)]
pub struct Sha1 {
    state: [u32; 5],
    buf: [u8; BLOCK],
    buf_len: usize,
    /// Total message length in bytes, modulo 2^64.
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buf: [0; BLOCK],
            buf_len: 0,
            total: 0,
        }
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (BLOCK - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < BLOCK {
                return;
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(BLOCK);
        for chunk in &mut chunks {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(chunk);
            compress(&mut self.state, &block);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finalize(mut self) -> [u8; SHA1_DIGEST_LEN] {
        // FIPS 180-4 5.1.1: length is the bit count modulo 2^64.
        let bit_len = self.total.wrapping_mul(8);
        let mut pad = [0u8; BLOCK * 2];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 { 56 - self.buf_len } else { 120 - self.buf_len };
        self.update(&pad[..pad_len]);
        self.update(&bit_len.to_be_bytes());
        let mut out = [0u8; SHA1_DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn compress(state: &mut [u32; 5], block: &[u8; BLOCK]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i / 20 {
            0 => ((b & c) | (!b & d), 0x5A827999),
            1 => (b ^ c ^ d, 0x6ED9EBA1),
            2 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// One-shot SHA-1 of `data`.
pub fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}
