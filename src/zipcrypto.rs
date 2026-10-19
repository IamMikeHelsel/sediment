// SPDX-License-Identifier: MIT OR Apache-2.0
//! Traditional PKWARE encryption ("ZipCrypto").
//!
//! Source: PKWARE APPNOTE.TXT section 6.1 "Traditional PKWARE Encryption".
//! Three 32-bit keys are initialised to 0x12345678, 0x23456789, 0x34567890
//! and updated with every plaintext byte via CRC-32 and a linear
//! congruential step. Each entry's data is prefixed with a 12-byte
//! encryption header whose last byte (after decryption) must equal the high
//! byte of the entry CRC-32, or the high byte of the DOS modification time
//! when general-purpose bit 3 (data descriptor) is set.
//!
//! ZipCrypto is cryptographically broken (known-plaintext attack, Biham &
//! Kocher 1994). It is provided only for compatibility with existing
//! archives; the 1-byte header check also accepts about 1 in 256 wrong
//! passwords, so callers must verify the entry CRC after decompression.

/// Length of the encryption header that precedes the file data.
pub const ZIPCRYPTO_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipCryptoError {
    /// Header check byte mismatch: wrong password (or corrupt data).
    BadPassword,
    /// Input shorter than the 12-byte header.
    Truncated,
}

const fn make_crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

const CRC_TABLE: [u32; 256] = make_crc_table();

/// APPNOTE's `crc32(old, c)`: one raw table step, no pre/post inversion.
#[inline(always)]
fn crc_step(crc: u32, b: u8) -> u32 {
    (crc >> 8) ^ CRC_TABLE[((crc ^ b as u32) & 0xff) as usize]
}

/// Cipher state. Encryption and decryption each advance the keys with the
/// *plaintext* byte, so use one instance per direction per entry.
#[derive(Clone)]
pub struct ZipCrypto {
    k0: u32,
    k1: u32,
    k2: u32,
}

impl core::fmt::Debug for ZipCrypto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ZipCrypto { .. }")
    }
}

impl ZipCrypto {
    /// Initialise keys from the password bytes (APPNOTE 6.1.5). ZIP has no
    /// standard password encoding; callers typically pass UTF-8 or CP437.
    pub fn new(password: &[u8]) -> Self {
        let mut z = Self { k0: 0x1234_5678, k1: 0x2345_6789, k2: 0x3456_7890 };
        for &b in password {
            z.update_keys(b);
        }
        z
    }

    #[inline(always)]
    fn update_keys(&mut self, b: u8) {
        self.k0 = crc_step(self.k0, b);
        self.k1 = self.k1.wrapping_add(self.k0 & 0xff).wrapping_mul(134_775_813).wrapping_add(1);
        self.k2 = crc_step(self.k2, (self.k1 >> 24) as u8);
    }

    #[inline(always)]
    fn stream_byte(&self) -> u8 {
        let temp = (self.k2 | 2) & 0xffff;
        (temp.wrapping_mul(temp ^ 1) >> 8) as u8
    }

    /// Decrypt `data` in place.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        for x in data.iter_mut() {
            let p = *x ^ self.stream_byte();
            self.update_keys(p);
            *x = p;
        }
    }

    /// Encrypt `data` in place.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        for x in data.iter_mut() {
            let p = *x;
            *x = p ^ self.stream_byte();
            self.update_keys(p);
        }
    }

    /// Decrypt the 12-byte header at the start of `data` and check its last
    /// byte against `check_byte` (CRC-32 >> 24, or DOS time >> 8 when bit 3
    /// is set). On success the state is positioned at the file data.
    pub fn decrypt_header(&mut self, data: &[u8], check_byte: u8) -> Result<(), ZipCryptoError> {
        let mut header: [u8; ZIPCRYPTO_HEADER_LEN] = data
            .get(..ZIPCRYPTO_HEADER_LEN)
            .and_then(|h| h.try_into().ok())
            .ok_or(ZipCryptoError::Truncated)?;
        self.decrypt(&mut header);
        if header[ZIPCRYPTO_HEADER_LEN - 1] != check_byte {
            return Err(ZipCryptoError::BadPassword);
        }
        Ok(())
    }

    /// Build the encrypted 12-byte header from 11 caller-supplied random
    /// bytes plus `check_byte`. `random` must come from a CSPRNG in
    /// production; this crate does not provide one.
    pub fn encrypt_header(&mut self, random: [u8; 11], check_byte: u8) -> [u8; ZIPCRYPTO_HEADER_LEN] {
        let mut h = [0u8; ZIPCRYPTO_HEADER_LEN];
        h[..11].copy_from_slice(&random);
        h[11] = check_byte;
        self.encrypt(&mut h);
        h
    }
}

/// Check byte for an entry: high byte of the CRC-32, or of the DOS time
/// when general-purpose flag bit 3 is set.
pub fn zipcrypto_check_byte(flags: u16, crc32: u32, dos_time: u16) -> u8 {
    if flags & 0x0008 != 0 { (dos_time >> 8) as u8 } else { (crc32 >> 24) as u8 }
}
