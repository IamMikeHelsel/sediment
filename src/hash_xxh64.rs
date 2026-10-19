// SPDX-License-Identifier: MIT OR Apache-2.0
//! XXH64 non-cryptographic hash.
//!
//! Implemented from the xxHash format specification
//! (`doc/xxhash_spec.md` in the xxHash project, "XXH64 algorithm description").
//! Verified against the published sanity vectors of the xxHash project.
//!
//! Streaming: [`Xxh64::new`] / [`Xxh64::with_seed`], [`Xxh64::update`],
//! [`Xxh64::finalize`]. One-shot: [`xxh64`]. The 64-bit result is returned as
//! a `u64`; [`xxh64_be_bytes`] gives the canonical (big-endian) byte form.

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

const STRIPE: usize = 32;

#[inline]
fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

#[inline]
fn merge(acc: u64, v: u64) -> u64 {
    (acc ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

#[inline]
fn read_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

/// Streaming XXH64 state.
#[derive(Clone, Debug)]
pub struct Xxh64 {
    seed: u64,
    v: [u64; 4],
    buf: [u8; STRIPE],
    buf_len: usize,
    /// Total input length in bytes, modulo 2^64 (as the spec requires).
    total: u64,
}

impl Default for Xxh64 {
    fn default() -> Self {
        Self::with_seed(0)
    }
}

impl Xxh64 {
    /// New state with seed 0.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_seed(seed: u64) -> Self {
        Self {
            seed,
            v: [
                seed.wrapping_add(P1).wrapping_add(P2),
                seed.wrapping_add(P2),
                seed,
                seed.wrapping_sub(P1),
            ],
            buf: [0; STRIPE],
            buf_len: 0,
            total: 0,
        }
    }

    fn stripe(v: &mut [u64; 4], s: &[u8]) {
        v[0] = round(v[0], read_u64(&s[0..]));
        v[1] = round(v[1], read_u64(&s[8..]));
        v[2] = round(v[2], read_u64(&s[16..]));
        v[3] = round(v[3], read_u64(&s[24..]));
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (STRIPE - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < STRIPE {
                return;
            }
            let block = self.buf;
            Self::stripe(&mut self.v, &block);
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(STRIPE);
        for chunk in &mut chunks {
            Self::stripe(&mut self.v, chunk);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finalize(self) -> u64 {
        let mut acc = if self.total >= STRIPE as u64 {
            let [v1, v2, v3, v4] = self.v;
            let mut acc = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
            acc = merge(acc, v1);
            acc = merge(acc, v2);
            acc = merge(acc, v3);
            merge(acc, v4)
        } else {
            self.seed.wrapping_add(P5)
        };
        acc = acc.wrapping_add(self.total);
        let mut rest = &self.buf[..self.buf_len];
        while rest.len() >= 8 {
            acc ^= round(0, read_u64(rest));
            acc = acc.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            let lane = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as u64;
            acc ^= lane.wrapping_mul(P1);
            acc = acc.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
            rest = &rest[4..];
        }
        for &b in rest {
            acc ^= (b as u64).wrapping_mul(P5);
            acc = acc.rotate_left(11).wrapping_mul(P1);
        }
        acc ^= acc >> 33;
        acc = acc.wrapping_mul(P2);
        acc ^= acc >> 29;
        acc = acc.wrapping_mul(P3);
        acc ^= acc >> 32;
        acc
    }
}

/// One-shot XXH64 of `data` with `seed`.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut h = Xxh64::with_seed(seed);
    h.update(data);
    h.finalize()
}

/// One-shot XXH64 in canonical big-endian byte order.
pub fn xxh64_be_bytes(data: &[u8], seed: u64) -> [u8; 8] {
    xxh64(data, seed).to_be_bytes()
}
