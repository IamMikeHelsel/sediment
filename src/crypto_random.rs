// SPDX-License-Identifier: MIT OR Apache-2.0
//! Random bytes for salts, IVs and ZipCrypto header bytes, std only.
//!
//! On Unix the bytes come from the kernel CSPRNG (`/dev/urandom`). Where
//! that device is unavailable (non-Unix targets, sandboxes without `/dev`),
//! the fallback hashes a process-wide counter, the clock, and per-call
//! [`std::collections::hash_map::RandomState`] keys (which std seeds from the
//! OS RNG) through SHA-256. The fallback is unpredictable enough for salts
//! and IVs, which only need uniqueness, but key material should not be built
//! from it; no key is ever generated here (all keys come from passwords).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash_sha256::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    /// Requested more than [`MAX_RANDOM_BYTES`] in one call.
    TooLarge,
}

/// Upper bound for one [`fill_random`] call (callers need at most a few
/// dozen bytes).
pub const MAX_RANDOM_BYTES: usize = 1 << 16;

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn os_random(buf: &mut [u8]) -> bool {
    use std::io::Read;
    match std::fs::File::open("/dev/urandom") {
        Ok(mut f) => f.read_exact(buf).is_ok(),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn os_random(_buf: &mut [u8]) -> bool {
    false
}

fn fallback_random(buf: &mut [u8]) {
    for (block, chunk) in (0u64..).zip(buf.chunks_mut(32)) {
        let mut sha = Sha256::new();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        sha.update(&n.to_le_bytes());
        sha.update(&block.to_le_bytes());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        sha.update(&now.to_le_bytes());
        sha.update(&u64::from(std::process::id()).to_le_bytes());
        for _ in 0..4 {
            let mut h = RandomState::new().build_hasher();
            h.write_u64(n);
            sha.update(&h.finish().to_le_bytes());
        }
        let d = sha.finalize();
        chunk.copy_from_slice(&d[..chunk.len()]);
    }
}

/// Fill `buf` with random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<(), RandomError> {
    if buf.len() > MAX_RANDOM_BYTES {
        return Err(RandomError::TooLarge);
    }
    if buf.is_empty() || os_random(buf) {
        return Ok(());
    }
    fallback_random(buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_outputs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
        let mut c = [0u8; 40];
        let mut d = [0u8; 40];
        fallback_random(&mut c);
        fallback_random(&mut d);
        assert_ne!(c, d);
        assert_ne!(c[32..], [0u8; 8]);
    }

    #[test]
    fn limits() {
        let mut big = vec![0u8; MAX_RANDOM_BYTES + 1];
        assert_eq!(fill_random(&mut big), Err(RandomError::TooLarge));
        fill_random(&mut []).unwrap();
    }
}
