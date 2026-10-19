// SPDX-License-Identifier: MIT OR Apache-2.0
//! SHA3-224/256/384/512 (FIPS 202).
//!
//! Implemented from NIST FIPS PUB 202 "SHA-3 Standard: Permutation-Based
//! Hash and Extendable-Output Functions": Keccak-p[1600, 24] (section 3),
//! the sponge construction (section 4), pad10*1 with the SHA-3 domain
//! suffix `01` (section 6.1, byte value 0x06 in little-endian bit order).
//!
//! Streaming: [`Sha3_256`] (and siblings) with `new`, `update`, `finalize`.
//! One-shot: [`sha3_256`] and siblings. Hashing never fails and never allocates.

/// SHA3-256 digest length in bytes.
pub const SHA3_256_DIGEST_LEN: usize = 32;

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Keccak-f[1600] permutation; lane (x, y) is `a[x + 5 * y]`.
pub(crate) fn keccak_f1600(a: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // rho and pi: walk the (x, y) -> (y, 2x + 3y) cycle starting at (1, 0).
        let (mut x, mut y) = (1usize, 0usize);
        let mut current = a[1];
        for t in 0..24u32 {
            let nx = y;
            let ny = (2 * x + 3 * y) % 5;
            x = nx;
            y = ny;
            let tmp = a[x + 5 * y];
            a[x + 5 * y] = current.rotate_left(((t + 1) * (t + 2) / 2) % 64);
            current = tmp;
        }
        // chi
        for y in 0..5 {
            let row = [a[5 * y], a[5 * y + 1], a[5 * y + 2], a[5 * y + 3], a[5 * y + 4]];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // iota
        a[0] ^= rc;
    }
}

/// Generic SHA-3 sponge with rate `R` bytes (R = 200 - 2 * digest_len).
#[derive(Clone, Debug)]
struct Sponge<const R: usize> {
    state: [u64; 25],
    buf: [u8; R],
    buf_len: usize,
}

impl<const R: usize> Sponge<R> {
    const fn new() -> Self {
        Self { state: [0; 25], buf: [0; R], buf_len: 0 }
    }

    fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
        for (lane, chunk) in state.iter_mut().zip(block.chunks_exact(8)) {
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            *lane ^= u64::from_le_bytes(b);
        }
        keccak_f1600(state);
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (R - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < R {
                return;
            }
            let block = self.buf;
            Self::absorb_block(&mut self.state, &block);
            self.buf_len = 0;
        }
        let mut chunks = data.chunks_exact(R);
        for chunk in &mut chunks {
            Self::absorb_block(&mut self.state, chunk);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// Pads, absorbs the final block and squeezes `N` bytes (N <= R).
    fn finish<const N: usize>(mut self) -> [u8; N] {
        let mut block = [0u8; R];
        block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        block[self.buf_len] ^= 0x06;
        block[R - 1] ^= 0x80;
        Self::absorb_block(&mut self.state, &block);
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (self.state[i / 8] >> (8 * (i % 8))) as u8;
        }
        out
    }
}

macro_rules! sha3_variant {
    ($name:ident, $func:ident, $rate:expr, $len:expr, $doc:expr) => {
        #[doc = concat!("Streaming ", $doc, " state.")]
        #[derive(Clone, Debug)]
        #[allow(non_camel_case_types)]
        pub struct $name(Sponge<$rate>);

        impl Default for $name {
            fn default() -> Self {
                Self(Sponge::new())
            }
        }

        impl $name {
            pub fn new() -> Self {
                Self::default()
            }
            pub fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            pub fn finalize(self) -> [u8; $len] {
                self.0.finish::<$len>()
            }
        }

        #[doc = concat!("One-shot ", $doc, " of `data`.")]
        pub fn $func(data: &[u8]) -> [u8; $len] {
            let mut h = $name::new();
            h.update(data);
            h.finalize()
        }
    };
}

sha3_variant!(Sha3_224, sha3_224, 144, 28, "SHA3-224");
sha3_variant!(Sha3_256, sha3_256, 136, 32, "SHA3-256");
sha3_variant!(Sha3_384, sha3_384, 104, 48, "SHA3-384");
sha3_variant!(Sha3_512, sha3_512, 72, 64, "SHA3-512");
