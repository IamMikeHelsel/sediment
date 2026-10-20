// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z `7zAES` coder (method ID `06 F1 07 01`): decryption as a
//! [`FolderDecoder`] layer and encryption as a [`PackCoder`] for
//! [`crate::sevenz_write`].
//!
//! Sources: the 7z format documentation (7zFormat.txt: coders, bind pairs,
//! unpack sizes, encoded header) and the public description of the 7zAES
//! coder summarised in [`crate::sevenz_aes_kdf`]: AES-256-CBC over the
//! packed stream, key = SHA-256 iterated `2^NumCyclesPower` times over
//! `salt || UTF-16LE password || counter`, IV from the coder properties.
//! The ciphertext is a whole number of 16-byte blocks; the coder's unpack
//! size (stored in the folder) is the plaintext length, so the trailing
//! padding is simply dropped. No 7-Zip source was consulted.
//!
//! 7z has no password verifier: a wrong password only shows up as a decoder
//! failure or CRC mismatch further down the chain. [`SevenZCryptoDecoder`]
//! therefore records whether an AES coder ran ([`SevenZCryptoDecoder::aes_used`])
//! so callers can report "wrong password" instead of "data error".
//!
//! Limits: the key-derivation cost from untrusted archives is capped by
//! `max_cycles_power`; decrypted output is capped by `max_output`; derived
//! keys are cached (at most [`KEY_CACHE_LEN`] entries) because every folder of
//! a 7-Zip archive normally shares one salt and cost. Cache misses draw on a
//! per-decoder budget of [`KDF_BUDGET_MAX_COST_DERIVATIONS`]` << max_cycles_power`
//! SHA-256 rounds, so an archive whose folders rotate through many salts
//! fails with `LimitExceeded` instead of forcing unbounded CPU work.

use std::cell::{Cell, RefCell};

use crate::aes::{AES_BLOCK_LEN, Aes, AesCbc};
use crate::crypto_random::fill_random;
use crate::sevenz_aes_kdf::{
    SEVENZ_AES_DEFAULT_MAX_CYCLES_POWER, SEVENZ_AES_KEY_LEN, SevenZAesError, SevenZAesProperties,
    parse_sevenz_aes_properties, password_to_utf16le, sevenz_aes_derive_key,
};
use crate::sevenz_read::{FolderDecoder, SevenZReadError};
use crate::sevenz_write::{PackCoder, SevenZWriteError};

/// Method ID of the 7zAES coder.
pub const SEVENZ_AES_METHOD_ID: [u8; 4] = [0x06, 0xf1, 0x07, 0x01];
/// `NumCyclesPower` written by current 7-Zip (2^19 SHA-256 rounds).
pub const SEVENZ_AES_DEFAULT_CYCLES_POWER: u8 = 19;
/// Derived keys kept per decoder.
pub const KEY_CACHE_LEN: usize = 8;
/// Total key-derivation work per decoder, in max-cost derivations
/// (`2^max_cycles_power` SHA-256 rounds each).
pub const KDF_BUDGET_MAX_COST_DERIVATIONS: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZAesCoderError {
    /// Coder properties are malformed.
    InvalidProperties,
    /// Key-derivation cost above the caller's limit.
    CostExceeded,
    /// Password too long for the KDF.
    PasswordTooLong,
    /// The archive is encrypted and no password was supplied.
    PasswordRequired,
    /// Ciphertext shorter than the unpack size requires.
    Truncated,
    /// Output above the caller's limit.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// The random source failed.
    Random,
}

impl From<SevenZAesError> for SevenZAesCoderError {
    fn from(e: SevenZAesError) -> Self {
        match e {
            SevenZAesError::InvalidProperties => Self::InvalidProperties,
            SevenZAesError::CostExceeded => Self::CostExceeded,
            SevenZAesError::PasswordTooLong => Self::PasswordTooLong,
            SevenZAesError::Allocation => Self::Allocation,
        }
    }
}

/// Decrypt the first `unpack_size` bytes of a 7zAES stream with a derived key.
pub fn sevenz_aes_decrypt(
    key: &[u8; SEVENZ_AES_KEY_LEN],
    iv: &[u8; AES_BLOCK_LEN],
    input: &[u8],
    unpack_size: u64,
    max_output: u64,
) -> Result<Vec<u8>, SevenZAesCoderError> {
    if unpack_size > max_output {
        return Err(SevenZAesCoderError::LimitExceeded);
    }
    let size = usize::try_from(unpack_size).map_err(|_| SevenZAesCoderError::LimitExceeded)?;
    let blocks_len = size.div_ceil(AES_BLOCK_LEN).checked_mul(AES_BLOCK_LEN).ok_or(SevenZAesCoderError::LimitExceeded)?;
    let ct = input.get(..blocks_len).ok_or(SevenZAesCoderError::Truncated)?;
    let mut out = Vec::new();
    out.try_reserve_exact(blocks_len).map_err(|_| SevenZAesCoderError::Allocation)?;
    out.extend_from_slice(ct);
    let cipher = Aes::new(key).map_err(|_| SevenZAesCoderError::InvalidProperties)?;
    let mut cbc = AesCbc::new(cipher, iv).map_err(|_| SevenZAesCoderError::InvalidProperties)?;
    cbc.decrypt(&mut out).map_err(|_| SevenZAesCoderError::Truncated)?;
    out.truncate(size);
    Ok(out)
}

/// Decrypt a 7zAES stream given the coder properties and a password
/// (UTF-16LE bytes, see [`password_to_utf16le`]).
pub fn sevenz_aes_decode(
    props: &[u8],
    password_utf16le: &[u8],
    input: &[u8],
    unpack_size: u64,
    max_cycles_power: u8,
    max_output: u64,
) -> Result<Vec<u8>, SevenZAesCoderError> {
    let p = parse_sevenz_aes_properties(props)?;
    let key = sevenz_aes_derive_key(password_utf16le, p.salt(), p.num_cycles_power, max_cycles_power)?;
    sevenz_aes_decrypt(&key, &p.iv, input, unpack_size, max_output)
}

struct CachedKey {
    cycles: u8,
    salt: [u8; 16],
    salt_len: u8,
    key: [u8; SEVENZ_AES_KEY_LEN],
}

impl Drop for CachedKey {
    fn drop(&mut self) {
        self.key = [0; SEVENZ_AES_KEY_LEN];
        std::hint::black_box(&self.key);
    }
}

/// [`FolderDecoder`] that handles 7zAES and delegates every other method to
/// `inner`.
pub struct SevenZCryptoDecoder<D> {
    inner: D,
    password: Option<Vec<u8>>,
    max_cycles_power: u8,
    max_output: u64,
    cache: RefCell<Vec<CachedKey>>,
    /// SHA-256 rounds spent on key derivation so far.
    kdf_rounds: Cell<u64>,
    aes_used: Cell<bool>,
    last_error: Cell<Option<SevenZAesCoderError>>,
}

impl<D> core::fmt::Debug for SevenZCryptoDecoder<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SevenZCryptoDecoder")
            .field("has_password", &self.password.is_some())
            .field("aes_used", &self.aes_used.get())
            .finish_non_exhaustive()
    }
}

impl<D> Drop for SevenZCryptoDecoder<D> {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            p.iter_mut().for_each(|b| *b = 0);
            std::hint::black_box(&p);
        }
    }
}

impl<D: FolderDecoder> SevenZCryptoDecoder<D> {
    /// `password` is the user's password (`None` when none was given).
    /// `max_output` caps the decrypted size of any AES coder.
    pub fn new(inner: D, password: Option<&str>, max_output: u64) -> Result<Self, SevenZAesCoderError> {
        let password = match password {
            Some(p) => Some(password_to_utf16le(p)?),
            None => None,
        };
        Ok(Self {
            inner,
            password,
            max_cycles_power: SEVENZ_AES_DEFAULT_MAX_CYCLES_POWER,
            max_output,
            cache: RefCell::new(Vec::new()),
            kdf_rounds: Cell::new(0),
            aes_used: Cell::new(false),
            last_error: Cell::new(None),
        })
    }

    /// Change the key-derivation cost limit (default 24).
    pub fn with_max_cycles_power(mut self, max: u8) -> Self {
        self.max_cycles_power = max;
        self
    }

    /// True once any 7zAES coder has been decoded (or attempted).
    pub fn aes_used(&self) -> bool {
        self.aes_used.get()
    }

    /// The most recent AES-layer error, if any.
    pub fn last_error(&self) -> Option<SevenZAesCoderError> {
        self.last_error.get()
    }

    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    fn key_for(&self, p: &SevenZAesProperties) -> Result<[u8; SEVENZ_AES_KEY_LEN], SevenZAesCoderError> {
        let pw = self.password.as_deref().ok_or(SevenZAesCoderError::PasswordRequired)?;
        let salt = p.salt();
        {
            let cache = self.cache.borrow();
            if let Some(c) = cache
                .iter()
                .find(|c| c.cycles == p.num_cycles_power && &c.salt[..c.salt_len as usize] == salt)
            {
                return Ok(c.key);
            }
        }
        if p.num_cycles_power <= self.max_cycles_power && p.num_cycles_power <= 62 {
            let budget = KDF_BUDGET_MAX_COST_DERIVATIONS.saturating_mul(1u64 << self.max_cycles_power.min(62));
            let spent = self.kdf_rounds.get().saturating_add(1u64 << p.num_cycles_power);
            if spent > budget {
                return Err(SevenZAesCoderError::LimitExceeded);
            }
            self.kdf_rounds.set(spent);
        }
        let key = sevenz_aes_derive_key(pw, salt, p.num_cycles_power, self.max_cycles_power)?;
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= KEY_CACHE_LEN {
            cache.remove(0);
        }
        let mut s = [0u8; 16];
        s[..salt.len()].copy_from_slice(salt);
        cache.push(CachedKey { cycles: p.num_cycles_power, salt: s, salt_len: salt.len() as u8, key });
        Ok(key)
    }

    fn decode_aes(&self, props: &[u8], input: &[u8], unpack_size: u64) -> Result<Vec<u8>, SevenZAesCoderError> {
        let p = parse_sevenz_aes_properties(props)?;
        let key = self.key_for(&p)?;
        sevenz_aes_decrypt(&key, &p.iv, input, unpack_size, self.max_output)
    }
}

impl<D: FolderDecoder> FolderDecoder for SevenZCryptoDecoder<D> {
    fn decode(&self, method_id: &[u8], props: &[u8], input: &[u8], unpack_size: u64) -> Result<Vec<u8>, SevenZReadError> {
        if method_id != SEVENZ_AES_METHOD_ID {
            return self.inner.decode(method_id, props, input, unpack_size);
        }
        self.aes_used.set(true);
        self.decode_aes(props, input, unpack_size).map_err(|e| {
            self.last_error.set(Some(e));
            match e {
                SevenZAesCoderError::CostExceeded | SevenZAesCoderError::LimitExceeded => SevenZReadError::LimitExceeded,
                SevenZAesCoderError::Allocation => SevenZReadError::Allocation,
                _ => SevenZReadError::DecoderFailed,
            }
        })
    }
}

/// Where per-stream IVs come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvSource {
    /// Fresh random IV per stream (production).
    Random,
    /// Deterministic IVs: SHA-256 of `seed` and the stream content. For
    /// reproducible tests only (equal streams get equal IVs, which leaks
    /// plaintext equality).
    Fixed([u8; AES_BLOCK_LEN]),
}

/// 7zAES encryptor usable as a [`PackCoder`] for the 7z writer.
pub struct SevenZAesEncoder {
    key: [u8; SEVENZ_AES_KEY_LEN],
    num_cycles_power: u8,
    salt: [u8; 16],
    salt_len: usize,
    iv_source: IvSource,
    encrypt_header: bool,
}

impl core::fmt::Debug for SevenZAesEncoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SevenZAesEncoder")
            .field("num_cycles_power", &self.num_cycles_power)
            .field("encrypt_header", &self.encrypt_header)
            .finish_non_exhaustive()
    }
}

impl Drop for SevenZAesEncoder {
    fn drop(&mut self) {
        self.key = [0; SEVENZ_AES_KEY_LEN];
        std::hint::black_box(&self.key);
    }
}

impl SevenZAesEncoder {
    /// Derive the key the way 7-Zip does by default: no salt, 2^19 rounds.
    /// `encrypt_header` corresponds to `-mhe=on`.
    pub fn new(password: &str, encrypt_header: bool) -> Result<Self, SevenZAesCoderError> {
        Self::with_params(password, SEVENZ_AES_DEFAULT_CYCLES_POWER, &[], encrypt_header)
    }

    /// Explicit cost (`num_cycles_power` ≤ 24, or 0x3f for "no hashing") and
    /// salt (≤ 16 bytes).
    pub fn with_params(
        password: &str,
        num_cycles_power: u8,
        salt: &[u8],
        encrypt_header: bool,
    ) -> Result<Self, SevenZAesCoderError> {
        if salt.len() > 16 {
            return Err(SevenZAesCoderError::InvalidProperties);
        }
        let pw = password_to_utf16le(password)?;
        let key = sevenz_aes_derive_key(&pw, salt, num_cycles_power, SEVENZ_AES_DEFAULT_MAX_CYCLES_POWER)?;
        let mut s = [0u8; 16];
        s[..salt.len()].copy_from_slice(salt);
        Ok(Self { key, num_cycles_power, salt: s, salt_len: salt.len(), iv_source: IvSource::Random, encrypt_header })
    }

    pub fn set_iv_source(&mut self, src: IvSource) {
        self.iv_source = src;
    }

    /// Encrypt `data` with `iv`: returns (coder properties, ciphertext
    /// zero-padded to a whole number of blocks).
    pub fn encrypt_with_iv(&self, data: &[u8], iv: &[u8; AES_BLOCK_LEN]) -> Result<(Vec<u8>, Vec<u8>), SevenZAesCoderError> {
        let props = SevenZAesProperties::new(self.num_cycles_power, &self.salt[..self.salt_len], iv)?.encode(AES_BLOCK_LEN)?;
        let padded = data.len().div_ceil(AES_BLOCK_LEN).checked_mul(AES_BLOCK_LEN).ok_or(SevenZAesCoderError::LimitExceeded)?;
        let mut out = Vec::new();
        out.try_reserve_exact(padded).map_err(|_| SevenZAesCoderError::Allocation)?;
        out.extend_from_slice(data);
        out.resize(padded, 0);
        let cipher = Aes::new(&self.key).map_err(|_| SevenZAesCoderError::InvalidProperties)?;
        let mut cbc = AesCbc::new(cipher, iv).map_err(|_| SevenZAesCoderError::InvalidProperties)?;
        cbc.encrypt(&mut out).map_err(|_| SevenZAesCoderError::InvalidProperties)?;
        Ok((props, out))
    }

    fn next_iv(&self, data: &[u8]) -> Result<[u8; AES_BLOCK_LEN], SevenZAesCoderError> {
        let mut iv = [0u8; AES_BLOCK_LEN];
        match self.iv_source {
            IvSource::Random => fill_random(&mut iv).map_err(|_| SevenZAesCoderError::Random)?,
            IvSource::Fixed(seed) => {
                // Mix in the stream content so different streams in one
                // archive get different IVs while staying reproducible.
                let mut sha = crate::hash_sha256::Sha256::new();
                sha.update(&seed);
                sha.update(&(data.len() as u64).to_le_bytes());
                sha.update(data);
                iv.copy_from_slice(&sha.finalize()[..AES_BLOCK_LEN]);
            }
        }
        Ok(iv)
    }
}

impl PackCoder for SevenZAesEncoder {
    fn encode(&self, packed: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), SevenZWriteError> {
        let map = |e| match e {
            SevenZAesCoderError::Allocation => SevenZWriteError::Allocation,
            SevenZAesCoderError::LimitExceeded => SevenZWriteError::LimitExceeded,
            _ => SevenZWriteError::EncoderFailed,
        };
        let iv = self.next_iv(packed).map_err(map)?;
        let (props, ct) = self.encrypt_with_iv(packed, &iv).map_err(map)?;
        Ok((SEVENZ_AES_METHOD_ID.to_vec(), props, ct))
    }

    fn applies_to_header(&self) -> bool {
        self.encrypt_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sevenz_read::NoDecoder;

    #[test]
    fn roundtrip_and_truncation() {
        let enc = SevenZAesEncoder::with_params("pw", 4, b"salt", false).unwrap();
        let data: Vec<u8> = (0..37u8).collect();
        let (props, ct) = enc.encrypt_with_iv(&data, &[7; 16]).unwrap();
        assert_eq!(ct.len(), 48);
        let pw = password_to_utf16le("pw").unwrap();
        let out = sevenz_aes_decode(&props, &pw, &ct, 37, 24, 1 << 20).unwrap();
        assert_eq!(out, data);
        assert_eq!(sevenz_aes_decode(&props, &pw, &ct[..32], 37, 24, 1 << 20), Err(SevenZAesCoderError::Truncated));
        assert_eq!(sevenz_aes_decode(&props, &pw, &ct, 37, 24, 36), Err(SevenZAesCoderError::LimitExceeded));
        assert_eq!(sevenz_aes_decode(&props, &pw, &ct, 37, 3, 1 << 20), Err(SevenZAesCoderError::CostExceeded));
        let wrong = password_to_utf16le("px").unwrap();
        assert_ne!(sevenz_aes_decode(&props, &wrong, &ct, 37, 24, 1 << 20).unwrap(), data);
    }

    #[test]
    fn decoder_tracks_state() {
        let d = SevenZCryptoDecoder::new(NoDecoder, None, 1 << 20).unwrap();
        assert!(!d.aes_used());
        assert_eq!(d.decode(&SEVENZ_AES_METHOD_ID, &[0x04], &[0; 16], 16), Err(SevenZReadError::DecoderFailed));
        assert!(d.aes_used());
        assert_eq!(d.last_error(), Some(SevenZAesCoderError::PasswordRequired));
        assert_eq!(d.decode(&[0x21], &[], &[], 0), Err(SevenZReadError::UnsupportedMethod));
        let d = SevenZCryptoDecoder::new(NoDecoder, Some("x"), 1 << 20).unwrap();
        assert_eq!(d.decode(&SEVENZ_AES_METHOD_ID, &[], &[0; 16], 16), Err(SevenZReadError::DecoderFailed));
        assert_eq!(d.last_error(), Some(SevenZAesCoderError::InvalidProperties));
        assert_eq!(d.decode(&SEVENZ_AES_METHOD_ID, &[0x1f], &[0; 16], 16), Err(SevenZReadError::LimitExceeded));
        // Cached key reuse.
        let ok = d.decode(&SEVENZ_AES_METHOD_ID, &[0x02], &[0; 32], 20).unwrap();
        assert_eq!(ok.len(), 20);
        assert_eq!(d.decode(&SEVENZ_AES_METHOD_ID, &[0x02], &[0; 32], 20).unwrap(), ok);
    }
}
