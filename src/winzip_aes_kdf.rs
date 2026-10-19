// SPDX-License-Identifier: MIT OR Apache-2.0
//! WinZip AES (AE-1 / AE-2) key derivation and password verifier.
//!
//! Source: WinZip "AES Encryption Information: Encryption Specification
//! AE-1 and AE-2" (public spec) and PKWARE APPNOTE section 7.2 (extra field
//! 0x9901). Key material = PBKDF2-HMAC-SHA1(password, salt, 1000 iterations,
//! 2 * key_len + 2 bytes), split as: AES key | HMAC-SHA1 key | 2-byte
//! password verification value. Salt length is half the key length
//! (8/12/16 bytes for strength 1/2/3). File data is then AES-CTR
//! ([`crate::aes::AesCtr::winzip`]) and authenticated with the first 10
//! bytes of HMAC-SHA1 over the *encrypted* data.

use crate::hmac_sha1::pbkdf2_hmac_sha1;

/// PBKDF2 iteration count fixed by the WinZip AES specification.
pub const WINZIP_AES_ITERATIONS: u32 = 1000;
/// Length of the truncated HMAC-SHA1 authentication code.
pub const WINZIP_AES_AUTH_LEN: usize = 10;
/// Length of the password verification value.
pub const WINZIP_AES_VERIFIER_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinZipAesError {
    /// Strength byte is not 1, 2 or 3.
    InvalidStrength,
    /// Salt length does not match the strength.
    InvalidSaltLength,
    /// Derived verifier does not match the stored one (wrong password).
    BadPassword,
}

/// AES strength from the 0x9901 extra field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinZipAesStrength {
    Aes128,
    Aes192,
    Aes256,
}

impl WinZipAesStrength {
    /// Parse the extra-field strength byte (1, 2 or 3).
    pub fn from_byte(b: u8) -> Result<Self, WinZipAesError> {
        match b {
            1 => Ok(Self::Aes128),
            2 => Ok(Self::Aes192),
            3 => Ok(Self::Aes256),
            _ => Err(WinZipAesError::InvalidStrength),
        }
    }
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Aes128 => 1,
            Self::Aes192 => 2,
            Self::Aes256 => 3,
        }
    }
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
    pub fn salt_len(self) -> usize {
        self.key_len() / 2
    }
}

/// Keys derived from a password and salt.
#[derive(Clone)]
pub struct WinZipAesKeys {
    pub strength: WinZipAesStrength,
    /// AES key; only the first `strength.key_len()` bytes are meaningful.
    aes_key: [u8; 32],
    /// HMAC-SHA1 key; only the first `strength.key_len()` bytes are meaningful.
    mac_key: [u8; 32],
    pub verifier: [u8; WINZIP_AES_VERIFIER_LEN],
}

impl core::fmt::Debug for WinZipAesKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WinZipAesKeys").field("strength", &self.strength).finish()
    }
}

impl Drop for WinZipAesKeys {
    fn drop(&mut self) {
        self.aes_key = [0; 32];
        self.mac_key = [0; 32];
        std::hint::black_box((&self.aes_key, &self.mac_key));
    }
}

impl WinZipAesKeys {
    pub fn aes_key(&self) -> &[u8] {
        &self.aes_key[..self.strength.key_len()]
    }
    pub fn mac_key(&self) -> &[u8] {
        &self.mac_key[..self.strength.key_len()]
    }
}

/// Derive the AES key, HMAC key and verifier.
pub fn winzip_aes_derive(
    password: &[u8],
    salt: &[u8],
    strength: WinZipAesStrength,
) -> Result<WinZipAesKeys, WinZipAesError> {
    let n = strength.key_len();
    if salt.len() != strength.salt_len() {
        return Err(WinZipAesError::InvalidSaltLength);
    }
    let mut buf = [0u8; 66];
    let out = &mut buf[..2 * n + 2];
    // Iterations are a fixed, non-zero constant within the limit.
    pbkdf2_hmac_sha1(password, salt, WINZIP_AES_ITERATIONS, WINZIP_AES_ITERATIONS, out)
        .map_err(|_| WinZipAesError::InvalidStrength)?;
    let mut keys = WinZipAesKeys { strength, aes_key: [0; 32], mac_key: [0; 32], verifier: [0; 2] };
    keys.aes_key[..n].copy_from_slice(&out[..n]);
    keys.mac_key[..n].copy_from_slice(&out[n..2 * n]);
    keys.verifier.copy_from_slice(&out[2 * n..2 * n + 2]);
    buf = [0; 66];
    std::hint::black_box(&buf);
    Ok(keys)
}

/// Derive keys and check the stored 2-byte password verifier.
pub fn winzip_aes_derive_checked(
    password: &[u8],
    salt: &[u8],
    strength: WinZipAesStrength,
    stored_verifier: [u8; WINZIP_AES_VERIFIER_LEN],
) -> Result<WinZipAesKeys, WinZipAesError> {
    let keys = winzip_aes_derive(password, salt, strength)?;
    if keys.verifier != stored_verifier {
        return Err(WinZipAesError::BadPassword);
    }
    Ok(keys)
}
