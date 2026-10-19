// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted ZIP entries: decryption of traditional PKWARE ("ZipCrypto")
//! and WinZip AES (AE-1 / AE-2, 128/192/256-bit) entries listed by
//! [`crate::zip_reader2`], and encryption of a finished unencrypted archive
//! (as produced by [`crate::zip_create`]) into either scheme.
//!
//! Spec sources: PKWARE APPNOTE.TXT 6.3.x section 6.1 (traditional
//! encryption: 12-byte header, check byte = CRC-32 high byte, or DOS time
//! high byte when flag bit 3 is set), 4.4.4 (flag bit 0), 4.3.7 / 4.3.12
//! (local / central headers), 4.4.3 (version needed: 5.1 for AES); WinZip
//! "AES Encryption Information: Encryption Specification AE-1 and AE-2":
//! method 99, extra field 0x9901 (`version`, `"AE"`, strength, actual
//! method), payload = salt | 2-byte verifier | AES-CTR ciphertext | 10-byte
//! HMAC-SHA1 over the ciphertext; AE-2 stores CRC-32 = 0 and relies on the
//! HMAC alone.
//!
//! Passwords are byte strings; the CLI passes UTF-8 (what 7-Zip and Info-ZIP
//! use on Unix systems with a UTF-8 locale).
//!
//! The writer follows 7-Zip's choices: directories stay unencrypted, every
//! other entry (including empty files) is encrypted, AES entries are AE-2.
//! ZipCrypto is cryptographically broken and offered only for compatibility.
//!
//! Hostile input: every length is checked before slicing, decrypted and
//! decompressed sizes are capped by the caller, authentication (HMAC or the
//! header check byte plus CRC) is verified before data is returned, and all
//! failures are `Err`, never panics.

use crate::aes::{Aes, AesCtr};
use crate::bzip2_decode::decode_bzip2;
use crate::crc32::crc32;
use crate::crypto_random::fill_random;
use crate::deflate64::inflate64_raw_prefix;
use crate::hmac_sha1::{HmacSha1, ct_eq};
use crate::inflate::{InflateError, inflate_raw};
use crate::winzip_aes_kdf::{
    WINZIP_AES_AUTH_LEN, WINZIP_AES_VERIFIER_LEN, WinZipAesError, WinZipAesStrength, winzip_aes_derive,
    winzip_aes_derive_checked,
};
use crate::zip_extra_read::AES_EXTRA_ID;
use crate::zip_reader2::{
    Compression, Encryption, Entry2, FLAG_DATA_DESCRIPTOR, FLAG_ENCRYPTED, METHOD_AES, Reader2Error, Reader2Limits,
    ZipArchive2,
};
use crate::zipcrypto::{ZIPCRYPTO_HEADER_LEN, ZipCrypto, ZipCryptoError, zipcrypto_check_byte};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipCryptError {
    /// The entry is encrypted and no password was given.
    PasswordRequired,
    /// The password check failed (ZipCrypto check byte, AES verifier).
    BadPassword,
    /// AES authentication code mismatch (wrong password or tampered data).
    AuthFailed,
    /// Decrypted data does not match the stored CRC-32 (ZipCrypto accepts
    /// about 1 in 256 wrong passwords at the header check).
    CrcMismatch,
    /// Payload shorter than the encryption overhead.
    Truncated,
    /// Malformed archive or entry.
    Invalid,
    /// Encryption or compression scheme not supported (strong encryption,
    /// unknown methods, ZIP64 or data-descriptor inputs to the writer).
    Unsupported,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// The random source failed.
    Random,
}

impl From<Reader2Error> for ZipCryptError {
    fn from(e: Reader2Error) -> Self {
        match e {
            Reader2Error::Truncated => Self::Truncated,
            Reader2Error::Invalid => Self::Invalid,
            Reader2Error::Unsupported | Reader2Error::Encrypted => Self::Unsupported,
            Reader2Error::LimitExceeded => Self::LimitExceeded,
            Reader2Error::Allocation => Self::Allocation,
            Reader2Error::CrcMismatch => Self::CrcMismatch,
        }
    }
}

/// Encryption scheme for [`encrypt_zip`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipEncryption {
    /// Traditional PKWARE encryption (weak; 7-Zip's `-mem=ZipCrypto`).
    ZipCrypto,
    /// WinZip AES (AE-2) with the given key size (`-mem=AES128/192/256`).
    Aes(WinZipAesStrength),
}

/// WinZip AES overhead besides the salt: verifier + authentication code.
const AES_FIXED_OVERHEAD: usize = WINZIP_AES_VERIFIER_LEN + WINZIP_AES_AUTH_LEN;

fn copy_vec(data: &[u8]) -> Result<Vec<u8>, ZipCryptError> {
    let mut v = Vec::new();
    v.try_reserve_exact(data.len()).map_err(|_| ZipCryptError::Allocation)?;
    v.extend_from_slice(data);
    Ok(v)
}

/// Remove the encryption layer of entry `e` from its stored payload `raw`,
/// returning the (still compressed) data. Unencrypted entries are copied.
/// For AES the HMAC is verified before anything is decrypted.
pub fn decrypt_payload(e: &Entry2<'_>, raw: &[u8], password: Option<&[u8]>) -> Result<Vec<u8>, ZipCryptError> {
    match e.encryption {
        Encryption::None => copy_vec(raw),
        Encryption::Strong => Err(ZipCryptError::Unsupported),
        Encryption::Traditional => {
            let pw = password.ok_or(ZipCryptError::PasswordRequired)?;
            let mut zc = ZipCrypto::new(pw);
            let check = zipcrypto_check_byte(e.flags, e.crc32, e.dos_time);
            zc.decrypt_header(raw, check).map_err(|x| match x {
                ZipCryptoError::BadPassword => ZipCryptError::BadPassword,
                ZipCryptoError::Truncated => ZipCryptError::Truncated,
            })?;
            let mut out = copy_vec(&raw[ZIPCRYPTO_HEADER_LEN..])?;
            zc.decrypt(&mut out);
            Ok(out)
        }
        Encryption::Aes(info) => {
            let pw = password.ok_or(ZipCryptError::PasswordRequired)?;
            let strength = WinZipAesStrength::from_byte(info.strength).map_err(|_| ZipCryptError::Invalid)?;
            let salt_len = strength.salt_len();
            let min = salt_len + AES_FIXED_OVERHEAD;
            if raw.len() < min {
                return Err(ZipCryptError::Truncated);
            }
            let salt = &raw[..salt_len];
            let verifier = [raw[salt_len], raw[salt_len + 1]];
            let ct = &raw[salt_len + WINZIP_AES_VERIFIER_LEN..raw.len() - WINZIP_AES_AUTH_LEN];
            let mac = &raw[raw.len() - WINZIP_AES_AUTH_LEN..];
            let keys = winzip_aes_derive_checked(pw, salt, strength, verifier).map_err(|x| match x {
                WinZipAesError::BadPassword => ZipCryptError::BadPassword,
                _ => ZipCryptError::Invalid,
            })?;
            let mut h = HmacSha1::new(keys.mac_key());
            h.update(ct);
            let tag = h.finalize();
            if !ct_eq(&tag[..WINZIP_AES_AUTH_LEN], mac) {
                return Err(ZipCryptError::AuthFailed);
            }
            let mut out = copy_vec(ct)?;
            let cipher = Aes::new(keys.aes_key()).map_err(|_| ZipCryptError::Invalid)?;
            AesCtr::winzip(cipher).apply_keystream(&mut out);
            Ok(out)
        }
    }
}

/// Decompress `data` with the entry's method into exactly `size` bytes.
/// Supports Stored, Deflate, Deflate64 and BZip2 (method 12).
pub fn decompress_entry(
    compression: Compression,
    data: &[u8],
    size: usize,
    max_deflate_blocks: usize,
) -> Result<Vec<u8>, ZipCryptError> {
    let out = match compression {
        Compression::Stored => {
            if data.len() != size {
                return Err(ZipCryptError::Invalid);
            }
            copy_vec(data)?
        }
        Compression::Deflate => inflate_raw(data, size, max_deflate_blocks).map_err(|e| match e {
            InflateError::LimitExceeded => ZipCryptError::LimitExceeded,
            InflateError::Allocation => ZipCryptError::Allocation,
            InflateError::UnsupportedBlock => ZipCryptError::Unsupported,
            _ => ZipCryptError::Invalid,
        })?,
        Compression::Deflate64 => inflate64_raw_prefix(data, size, max_deflate_blocks).map_err(|_| ZipCryptError::Invalid)?.0,
        Compression::Other(12) => decode_bzip2(data, size).map_err(|_| ZipCryptError::Invalid)?,
        Compression::Other(_) => return Err(ZipCryptError::Unsupported),
    };
    if out.len() != size {
        return Err(ZipCryptError::Invalid);
    }
    Ok(out)
}

/// Read entry `index` of `archive`: decrypt (when encrypted), decompress,
/// and verify the CRC-32 (skipped only for AE-2 entries, whose HMAC was
/// already verified). Output larger than `max_output` is refused.
pub fn read_entry(
    archive: &ZipArchive2<'_>,
    index: usize,
    password: Option<&[u8]>,
    max_output: usize,
    max_deflate_blocks: usize,
) -> Result<Vec<u8>, ZipCryptError> {
    let e = archive.entries().get(index).ok_or(ZipCryptError::Invalid)?;
    let size = usize::try_from(e.uncompressed_size).map_err(|_| ZipCryptError::LimitExceeded)?;
    if size > max_output {
        return Err(ZipCryptError::LimitExceeded);
    }
    let raw = archive.raw_data(index)?;
    let plain = decrypt_payload(e, raw, password)?;
    let out = decompress_entry(e.compression, &plain, size, max_deflate_blocks).map_err(|x| {
        // Garbage from a wrong ZipCrypto password that slipped past the
        // 1-byte check usually fails to decompress.
        if e.encryption == Encryption::Traditional && x == ZipCryptError::Invalid { ZipCryptError::CrcMismatch } else { x }
    })?;
    let check_crc = !matches!(e.encryption, Encryption::Aes(i) if i.vendor_version == 2);
    if check_crc && crc32(&out) != e.crc32 {
        return Err(ZipCryptError::CrcMismatch);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Limits for [`encrypt_zip`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipEncryptLimits {
    pub max_entries: usize,
    /// Largest output archive (must stay below 4 GiB: no ZIP64).
    pub max_archive_bytes: usize,
}

impl Default for ZipEncryptLimits {
    fn default() -> Self {
        Self { max_entries: 65534, max_archive_bytes: (u32::MAX - 1) as usize }
    }
}

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const VERSION_AES: u16 = 51;
const VERSION_ZIPCRYPTO: u16 = 20;

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Per-entry result of encryption.
struct Sealed<'a> {
    e: &'a Entry2<'a>,
    flags: u16,
    method: u16,
    needed: u16,
    crc: u32,
    payload: Vec<u8>,
    aes_extra: Option<[u8; 11]>,
    local_offset: u32,
}

fn seal_entry<'a>(
    e: &'a Entry2<'a>,
    raw: &[u8],
    password: &[u8],
    enc: ZipEncryption,
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), ZipCryptError>,
) -> Result<Sealed<'a>, ZipCryptError> {
    if e.is_dir() {
        return Ok(Sealed {
            e,
            flags: e.flags,
            method: e.method,
            needed: e.version_needed,
            crc: e.crc32,
            payload: copy_vec(raw)?,
            aes_extra: None,
            local_offset: 0,
        });
    }
    match enc {
        ZipEncryption::ZipCrypto => {
            let mut rnd = [0u8; 11];
            random(&mut rnd)?;
            let mut zc = ZipCrypto::new(password);
            let header = zc.encrypt_header(rnd, zipcrypto_check_byte(0, e.crc32, e.dos_time));
            let mut payload = Vec::new();
            payload.try_reserve_exact(raw.len() + ZIPCRYPTO_HEADER_LEN).map_err(|_| ZipCryptError::Allocation)?;
            payload.extend_from_slice(&header);
            let start = payload.len();
            payload.extend_from_slice(raw);
            zc.encrypt(&mut payload[start..]);
            Ok(Sealed {
                e,
                flags: e.flags | FLAG_ENCRYPTED,
                method: e.method,
                needed: e.version_needed.max(VERSION_ZIPCRYPTO),
                crc: e.crc32,
                payload,
                aes_extra: None,
                local_offset: 0,
            })
        }
        ZipEncryption::Aes(strength) => {
            let salt_len = strength.salt_len();
            let mut salt = [0u8; 16];
            random(&mut salt[..salt_len])?;
            let keys = winzip_aes_derive(password, &salt[..salt_len], strength).map_err(|_| ZipCryptError::Invalid)?;
            let total = raw
                .len()
                .checked_add(salt_len + AES_FIXED_OVERHEAD)
                .ok_or(ZipCryptError::LimitExceeded)?;
            let mut payload = Vec::new();
            payload.try_reserve_exact(total).map_err(|_| ZipCryptError::Allocation)?;
            payload.extend_from_slice(&salt[..salt_len]);
            payload.extend_from_slice(&keys.verifier);
            let start = payload.len();
            payload.extend_from_slice(raw);
            let cipher = Aes::new(keys.aes_key()).map_err(|_| ZipCryptError::Invalid)?;
            AesCtr::winzip(cipher).apply_keystream(&mut payload[start..]);
            let mut h = HmacSha1::new(keys.mac_key());
            h.update(&payload[start..]);
            let tag = h.finalize();
            payload.extend_from_slice(&tag[..WINZIP_AES_AUTH_LEN]);
            let mut extra = [0u8; 11];
            extra[0..2].copy_from_slice(&AES_EXTRA_ID.to_le_bytes());
            extra[2..4].copy_from_slice(&7u16.to_le_bytes());
            extra[4..6].copy_from_slice(&2u16.to_le_bytes()); // AE-2
            extra[6..8].copy_from_slice(b"AE");
            extra[8] = strength.to_byte();
            extra[9..11].copy_from_slice(&e.method.to_le_bytes());
            Ok(Sealed {
                e,
                flags: e.flags | FLAG_ENCRYPTED,
                method: METHOD_AES,
                needed: e.version_needed.max(VERSION_AES),
                crc: 0,
                payload,
                aes_extra: Some(extra),
                local_offset: 0,
            })
        }
    }
}

fn len16(n: usize) -> Result<u16, ZipCryptError> {
    u16::try_from(n).map_err(|_| ZipCryptError::Unsupported)
}

fn len32(n: usize) -> Result<u32, ZipCryptError> {
    match u32::try_from(n) {
        Ok(v) if v != u32::MAX => Ok(v),
        _ => Err(ZipCryptError::Unsupported),
    }
}

/// Encrypt every non-directory entry of the unencrypted ZIP archive `plain`
/// with `password`, using the system random source for salts and headers.
pub fn encrypt_zip(
    plain: &[u8],
    password: &[u8],
    enc: ZipEncryption,
    limits: ZipEncryptLimits,
) -> Result<Vec<u8>, ZipCryptError> {
    let mut rng = |b: &mut [u8]| fill_random(b).map_err(|_| ZipCryptError::Random);
    encrypt_zip_with(plain, password, enc, limits, &mut rng)
}

/// [`encrypt_zip`] with a caller-supplied random source (for reproducible
/// tests). The input must be a plain archive without ZIP64 records, data
/// descriptors or already-encrypted entries.
pub fn encrypt_zip_with(
    plain: &[u8],
    password: &[u8],
    enc: ZipEncryption,
    limits: ZipEncryptLimits,
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), ZipCryptError>,
) -> Result<Vec<u8>, ZipCryptError> {
    let r2 = Reader2Limits { max_entries: limits.max_entries, ..Reader2Limits::default() };
    let archive = ZipArchive2::open(plain, r2)?;
    if archive.is_zip64() || archive.prefix_len() != 0 {
        return Err(ZipCryptError::Unsupported);
    }
    let entries = archive.entries();
    if entries.len() > limits.max_entries {
        return Err(ZipCryptError::LimitExceeded);
    }
    let mut sealed: Vec<Sealed<'_>> = Vec::new();
    sealed.try_reserve_exact(entries.len()).map_err(|_| ZipCryptError::Allocation)?;
    let mut offset = 0usize;
    for (i, e) in entries.iter().enumerate() {
        if e.is_encrypted() || e.flags & FLAG_DATA_DESCRIPTOR != 0 || e.zip64 {
            return Err(ZipCryptError::Unsupported);
        }
        let raw = archive.raw_data(i)?;
        let mut s = seal_entry(e, raw, password, enc, random)?;
        s.local_offset = len32(offset)?;
        let extra_len = e.local_extra.len() + s.aes_extra.map_or(0, |x| x.len());
        len16(extra_len)?;
        offset = offset
            .checked_add(30 + e.raw_name.len() + extra_len)
            .and_then(|o| o.checked_add(s.payload.len()))
            .ok_or(ZipCryptError::LimitExceeded)?;
        if offset > limits.max_archive_bytes {
            return Err(ZipCryptError::LimitExceeded);
        }
        sealed.push(s);
    }
    let cd_start = offset;
    let mut cd_size = 0usize;
    for s in &sealed {
        let extra_len = s.e.central_extra.len() + s.aes_extra.map_or(0, |x| x.len());
        len16(extra_len)?;
        cd_size = cd_size
            .checked_add(46 + s.e.raw_name.len() + extra_len + s.e.comment.len())
            .ok_or(ZipCryptError::LimitExceeded)?;
    }
    let comment = archive.comment();
    let total = cd_start
        .checked_add(cd_size)
        .and_then(|t| t.checked_add(22 + comment.len()))
        .ok_or(ZipCryptError::LimitExceeded)?;
    if total > limits.max_archive_bytes {
        return Err(ZipCryptError::LimitExceeded);
    }
    let (cd_start32, cd_size32) = (len32(cd_start)?, len32(cd_size)?);
    let count = len16(sealed.len())?;
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| ZipCryptError::Allocation)?;
    for s in &sealed {
        let e = s.e;
        put32(&mut out, LOCAL_SIG);
        put16(&mut out, s.needed);
        put16(&mut out, s.flags);
        put16(&mut out, s.method);
        put16(&mut out, e.dos_time);
        put16(&mut out, e.dos_date);
        put32(&mut out, s.crc);
        put32(&mut out, len32(s.payload.len())?);
        put32(&mut out, len32(e.uncompressed_size as usize)?);
        put16(&mut out, len16(e.raw_name.len())?);
        put16(&mut out, len16(e.local_extra.len() + s.aes_extra.map_or(0, |x| x.len()))?);
        out.extend_from_slice(e.raw_name);
        out.extend_from_slice(e.local_extra);
        if let Some(x) = &s.aes_extra {
            out.extend_from_slice(x);
        }
        out.extend_from_slice(&s.payload);
    }
    for s in &sealed {
        let e = s.e;
        put32(&mut out, CENTRAL_SIG);
        put16(&mut out, e.version_made_by);
        put16(&mut out, s.needed);
        put16(&mut out, s.flags);
        put16(&mut out, s.method);
        put16(&mut out, e.dos_time);
        put16(&mut out, e.dos_date);
        put32(&mut out, s.crc);
        put32(&mut out, len32(s.payload.len())?);
        put32(&mut out, len32(e.uncompressed_size as usize)?);
        put16(&mut out, len16(e.raw_name.len())?);
        put16(&mut out, len16(e.central_extra.len() + s.aes_extra.map_or(0, |x| x.len()))?);
        put16(&mut out, len16(e.comment.len())?);
        put16(&mut out, 0); // disk
        put16(&mut out, e.internal_attributes);
        put32(&mut out, e.external_attributes);
        put32(&mut out, s.local_offset);
        out.extend_from_slice(e.raw_name);
        out.extend_from_slice(e.central_extra);
        if let Some(x) = &s.aes_extra {
            out.extend_from_slice(x);
        }
        out.extend_from_slice(e.comment);
    }
    put32(&mut out, EOCD_SIG);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, count);
    put16(&mut out, count);
    put32(&mut out, cd_size32);
    put32(&mut out, cd_start32);
    put16(&mut out, len16(comment.len())?);
    out.extend_from_slice(comment);
    if out.len() != total {
        return Err(ZipCryptError::Invalid);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_helpers() {
        assert_eq!(len16(70000), Err(ZipCryptError::Unsupported));
        assert_eq!(len32(u32::MAX as usize), Err(ZipCryptError::Unsupported));
        assert_eq!(len32(5), Ok(5));
    }

    #[test]
    fn decompress_methods() {
        assert_eq!(decompress_entry(Compression::Stored, b"abc", 3, 16).unwrap(), b"abc");
        assert_eq!(decompress_entry(Compression::Stored, b"abc", 2, 16), Err(ZipCryptError::Invalid));
        assert_eq!(decompress_entry(Compression::Other(14), b"abc", 2, 16), Err(ZipCryptError::Unsupported));
        assert!(decompress_entry(Compression::Deflate, b"\xff\xff", 2, 16).is_err());
    }
}
