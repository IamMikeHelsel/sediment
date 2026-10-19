// SPDX-License-Identifier: MIT OR Apache-2.0
//! HMAC-SHA1 (RFC 2104) and PBKDF2-HMAC-SHA1 (RFC 8018 section 5.2).
//!
//! Sources: RFC 2104 (HMAC), RFC 8018 / PKCS #5 v2.1 (PBKDF2), RFC 2202 and
//! RFC 6070 test vectors. Used by WinZip AES (AE-1/AE-2): PBKDF2 with 1000
//! iterations for key derivation and a 10-byte truncated HMAC-SHA1 as the
//! authentication code (see [`crate::winzip_aes_kdf`]).
//!
//! SHA-1 comes from [`crate::hash_sha1`]. HMAC never allocates and never
//! fails; PBKDF2 validates its parameters and returns [`Pbkdf2Error`].

use crate::hash_sha1::{SHA1_DIGEST_LEN, Sha1};

/// HMAC-SHA1 output length in bytes.
pub const HMAC_SHA1_LEN: usize = SHA1_DIGEST_LEN;
const BLOCK: usize = 64;

/// Streaming HMAC-SHA1. Cloning after [`HmacSha1::new`] is a cheap way to
/// reuse a key's precomputed pads for several messages.
#[derive(Clone, Debug)]
pub struct HmacSha1 {
    inner: Sha1,
    outer: Sha1,
}

impl HmacSha1 {
    /// Keys longer than the 64-byte block are hashed first (RFC 2104).
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            let d = crate::hash_sha1::sha1(key);
            k[..SHA1_DIGEST_LEN].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha1::new();
        inner.update(&ipad);
        let mut outer = Sha1::new();
        outer.update(&opad);
        // Best-effort wipe of key-derived stack copies.
        k = [0; BLOCK];
        ipad = [0; BLOCK];
        opad = [0; BLOCK];
        std::hint::black_box((&k, &ipad, &opad));
        Self { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; HMAC_SHA1_LEN] {
        let ih = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(&ih);
        outer.finalize()
    }
}

/// One-shot HMAC-SHA1.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA1_LEN] {
    let mut h = HmacSha1::new(key);
    h.update(data);
    h.finalize()
}

/// Constant-time equality for MAC comparison (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbkdf2Error {
    /// Iteration count of zero.
    ZeroIterations,
    /// Iteration count above the caller's `max_iterations`.
    LimitExceeded,
    /// Requested output longer than (2^32 - 1) * 20 bytes (RFC 8018 step 1).
    OutputTooLong,
}

/// PBKDF2-HMAC-SHA1: fill `out` with derived key material.
///
/// `max_iterations` is the caller's cost limit; iteration counts read from
/// untrusted input must be bounded by it. WinZip AES uses 1000.
pub fn pbkdf2_hmac_sha1(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    max_iterations: u32,
    out: &mut [u8],
) -> Result<(), Pbkdf2Error> {
    if iterations == 0 {
        return Err(Pbkdf2Error::ZeroIterations);
    }
    if iterations > max_iterations {
        return Err(Pbkdf2Error::LimitExceeded);
    }
    let blocks = out.len().div_ceil(HMAC_SHA1_LEN);
    if blocks as u64 > u32::MAX as u64 {
        return Err(Pbkdf2Error::OutputTooLong);
    }
    let prf = HmacSha1::new(password);
    for (index, chunk) in out.chunks_mut(HMAC_SHA1_LEN).enumerate() {
        // `blocks <= u32::MAX`, so `index + 1` fits.
        let block_index = (index as u32).wrapping_add(1);
        let mut h = prf.clone();
        h.update(salt);
        h.update(&block_index.to_be_bytes());
        let mut u = h.finalize();
        let mut t = u;
        for _ in 1..iterations {
            let mut h = prf.clone();
            h.update(&u);
            u = h.finalize();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    Ok(())
}
