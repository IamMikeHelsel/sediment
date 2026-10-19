// SPDX-License-Identifier: MIT OR Apache-2.0
//! MD5 message digest (RFC 1321).
//!
//! Implemented from RFC 1321 ("The MD5 Message-Digest Algorithm"). MD5 is
//! cryptographically broken; it is provided only for archive-format
//! compatibility (checksums displayed or verified by archivers).
//!
//! Streaming: [`Md5::new`], [`Md5::update`], [`Md5::finalize`]. One-shot: [`md5`].
//! Hashing never fails and never allocates.

/// Digest length in bytes.
pub const MD5_DIGEST_LEN: usize = 16;
const BLOCK: usize = 64;

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

// K[i] = floor(abs(sin(i + 1)) * 2^32), RFC 1321 section 3.4.
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Streaming MD5 state.
#[derive(Clone, Debug)]
pub struct Md5 {
    state: [u32; 4],
    buf: [u8; BLOCK],
    buf_len: usize,
    /// Total message length in bytes, modulo 2^64.
    total: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buf: [0; BLOCK],
            buf_len: 0,
            total: 0,
        }
    }
}

impl Md5 {
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

    pub fn finalize(mut self) -> [u8; MD5_DIGEST_LEN] {
        let bit_len = self.total.wrapping_mul(8);
        let mut pad = [0u8; BLOCK * 2];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 { 56 - self.buf_len } else { 120 - self.buf_len };
        self.update(&pad[..pad_len]);
        self.update(&bit_len.to_le_bytes());
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; MD5_DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

fn compress(state: &mut [u32; 4], block: &[u8; BLOCK]) {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let tmp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]),
        );
        a = tmp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// One-shot MD5 of `data`.
pub fn md5(data: &[u8]) -> [u8; MD5_DIGEST_LEN] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}
