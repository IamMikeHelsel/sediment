// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z AES coder (`7zAES`, method ID 06 F1 07 01): coder-property parsing and
//! password-to-key derivation.
//!
//! Sources: the 7z format documentation (7zFormat.txt, coder records) and
//! public descriptions of the 7zAES coder properties and key schedule
//! (no 7-Zip source was consulted):
//!
//! - Properties: byte 0 = `NumCyclesPower` in bits 0..5, bit 7 = salt
//!   present, bit 6 = IV present. If either flag is set a second byte
//!   follows: `salt_len = bit7 + (b1 >> 4)`, `iv_len = bit6 + (b1 & 0x0f)`.
//!   Then `salt_len` salt bytes and `iv_len` IV bytes (IV zero-padded to 16).
//! - Key: if `NumCyclesPower == 0x3f`, key = (salt || password) copied into a
//!   zeroed 32-byte buffer (truncated at 32). Otherwise
//!   key = SHA-256 over `2^NumCyclesPower` repetitions of
//!   `salt || password_utf16le || counter_u64_le`, counter = 0, 1, 2, ...
//! - The data is AES-256-CBC ([`crate::aes::AesCbc`]) without padding removal
//!   (the folder's unpack size bounds the plaintext).
//!
//! The cost (`2^NumCyclesPower` SHA-256 updates) comes from untrusted
//! archives, so callers pass `max_cycles_power`; 7-Zip writes 19 (older) or
//! 24 (current), so a limit of 24 is a sensible default.

use crate::hash_sha256::Sha256;

/// Derived key length (AES-256).
pub const SEVENZ_AES_KEY_LEN: usize = 32;
/// The "no hashing" cycles-power marker.
pub const SEVENZ_AES_NO_HASH: u8 = 0x3f;
/// Recommended default limit for `max_cycles_power`.
pub const SEVENZ_AES_DEFAULT_MAX_CYCLES_POWER: u8 = 24;
/// Longest password accepted, in UTF-16 code units (bounds the work per
/// round and the conversion buffer).
pub const SEVENZ_AES_MAX_PASSWORD_UNITS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZAesError {
    /// Properties are truncated or have trailing bytes.
    InvalidProperties,
    /// `NumCyclesPower` above the caller's limit (and not the 0x3f marker),
    /// or above 62.
    CostExceeded,
    /// Password longer than [`SEVENZ_AES_MAX_PASSWORD_UNITS`].
    PasswordTooLong,
    /// Memory reservation failed.
    Allocation,
}

/// Parsed 7zAES coder properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZAesProperties {
    pub num_cycles_power: u8,
    salt: [u8; 16],
    salt_len: u8,
    /// IV, zero-padded to 16 bytes.
    pub iv: [u8; 16],
}

impl SevenZAesProperties {
    pub fn salt(&self) -> &[u8] {
        &self.salt[..self.salt_len as usize]
    }

    /// Build properties (for writers / tests). Salt and IV must be ≤ 16
    /// bytes and the cycles power ≤ 0x3f.
    pub fn new(num_cycles_power: u8, salt: &[u8], iv: &[u8]) -> Result<Self, SevenZAesError> {
        if num_cycles_power > SEVENZ_AES_NO_HASH || salt.len() > 16 || iv.len() > 16 {
            return Err(SevenZAesError::InvalidProperties);
        }
        let mut p = Self { num_cycles_power, salt: [0; 16], salt_len: salt.len() as u8, iv: [0; 16] };
        p.salt[..salt.len()].copy_from_slice(salt);
        p.iv[..iv.len()].copy_from_slice(iv);
        Ok(p)
    }

    /// Serialize with the given IV length (`iv_len` ≤ 16; the IV bytes are
    /// the first `iv_len` bytes of `self.iv`).
    pub fn encode(&self, iv_len: usize) -> Result<Vec<u8>, SevenZAesError> {
        if iv_len > 16 {
            return Err(SevenZAesError::InvalidProperties);
        }
        let salt_len = self.salt_len as usize;
        let mut out = Vec::new();
        out.try_reserve(2 + salt_len + iv_len).map_err(|_| SevenZAesError::Allocation)?;
        let mut b0 = self.num_cycles_power & 0x3f;
        if salt_len == 0 && iv_len == 0 {
            out.push(b0);
            return Ok(out);
        }
        // Encode each length as flag bit (1) + nibble (len - 1), or 0 + 0.
        let (s_flag, s_nib) = if salt_len == 0 { (0, 0) } else { (1, salt_len - 1) };
        let (i_flag, i_nib) = if iv_len == 0 { (0, 0) } else { (1, iv_len - 1) };
        b0 |= (s_flag << 7) | (i_flag << 6);
        out.push(b0);
        out.push(((s_nib as u8) << 4) | i_nib as u8);
        out.extend_from_slice(self.salt());
        out.extend_from_slice(&self.iv[..iv_len]);
        Ok(out)
    }
}

/// Parse 7zAES coder properties.
pub fn parse_sevenz_aes_properties(props: &[u8]) -> Result<SevenZAesProperties, SevenZAesError> {
    let (&b0, rest) = props.split_first().ok_or(SevenZAesError::InvalidProperties)?;
    let num_cycles_power = b0 & 0x3f;
    let mut p = SevenZAesProperties { num_cycles_power, salt: [0; 16], salt_len: 0, iv: [0; 16] };
    if b0 & 0xc0 == 0 {
        // No salt, no IV. 7-Zip tolerates a trailing second byte only when
        // flags are set, so anything else is malformed.
        if !rest.is_empty() {
            return Err(SevenZAesError::InvalidProperties);
        }
        return Ok(p);
    }
    let (&b1, rest) = rest.split_first().ok_or(SevenZAesError::InvalidProperties)?;
    let salt_len = ((b0 >> 7) & 1) as usize + (b1 >> 4) as usize;
    let iv_len = ((b0 >> 6) & 1) as usize + (b1 & 0x0f) as usize;
    if rest.len() != salt_len + iv_len {
        return Err(SevenZAesError::InvalidProperties);
    }
    p.salt[..salt_len].copy_from_slice(&rest[..salt_len]);
    p.salt_len = salt_len as u8;
    p.iv[..iv_len].copy_from_slice(&rest[salt_len..]);
    Ok(p)
}

/// Encode a password as UTF-16LE, as 7-Zip hashes it.
pub fn password_to_utf16le(password: &str) -> Result<Vec<u8>, SevenZAesError> {
    let units = password.encode_utf16().count();
    if units > SEVENZ_AES_MAX_PASSWORD_UNITS {
        return Err(SevenZAesError::PasswordTooLong);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(units * 2).map_err(|_| SevenZAesError::Allocation)?;
    for u in password.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    Ok(out)
}

/// Derive the 32-byte AES key from a UTF-16LE password.
///
/// Fails with [`SevenZAesError::CostExceeded`] if `num_cycles_power` exceeds
/// `max_cycles_power` (the 0x3f no-hash marker is always allowed: it is
/// cheap).
pub fn sevenz_aes_derive_key(
    password_utf16le: &[u8],
    salt: &[u8],
    num_cycles_power: u8,
    max_cycles_power: u8,
) -> Result<[u8; SEVENZ_AES_KEY_LEN], SevenZAesError> {
    if password_utf16le.len() > SEVENZ_AES_MAX_PASSWORD_UNITS * 2 {
        return Err(SevenZAesError::PasswordTooLong);
    }
    if salt.len() > 16 {
        return Err(SevenZAesError::InvalidProperties);
    }
    let mut key = [0u8; SEVENZ_AES_KEY_LEN];
    if num_cycles_power == SEVENZ_AES_NO_HASH {
        for (dst, &src) in key.iter_mut().zip(salt.iter().chain(password_utf16le.iter())) {
            *dst = src;
        }
        return Ok(key);
    }
    if num_cycles_power > max_cycles_power || num_cycles_power > 62 {
        return Err(SevenZAesError::CostExceeded);
    }
    // One contiguous buffer per round: salt || password || counter (LE u64).
    let prefix = salt.len() + password_utf16le.len();
    let mut buf = Vec::new();
    buf.try_reserve_exact(prefix + 8).map_err(|_| SevenZAesError::Allocation)?;
    buf.extend_from_slice(salt);
    buf.extend_from_slice(password_utf16le);
    buf.extend_from_slice(&[0u8; 8]);
    let rounds: u64 = 1u64 << num_cycles_power;
    let mut sha = Sha256::new();
    for _ in 0..rounds {
        sha.update(&buf);
        // Increment the little-endian counter in place.
        for byte in buf[prefix..].iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
    key = sha.finalize();
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    std::hint::black_box(&buf);
    Ok(key)
}

/// Convenience: parse properties and derive the key from a `&str` password.
pub fn sevenz_aes_key_from_properties(
    password: &str,
    props: &SevenZAesProperties,
    max_cycles_power: u8,
) -> Result<[u8; SEVENZ_AES_KEY_LEN], SevenZAesError> {
    let pw = password_to_utf16le(password)?;
    sevenz_aes_derive_key(&pw, props.salt(), props.num_cycles_power, max_cycles_power)
}
