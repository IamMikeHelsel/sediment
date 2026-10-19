// SPDX-License-Identifier: MIT OR Apache-2.0
//! RPM packages (format v3 lead + header-style signature + main header +
//! compressed cpio payload) as an [`ArchiveReader`] over the payload's
//! files.
//!
//! Spec sources: rpm.org "RPM Package format" (`docs/manual/format.md`) and
//! LSB 4.1 "Package File Format" (lead, header structure, index entries,
//! data types, signature and header tags). All integers are big-endian.
//!
//! - Lead: 96 bytes, magic `ED AB EE DB`; `signature_type` must be 5
//!   (header-style signature).
//! - Header structure: magic `8E AD E8 01`, 4 reserved bytes, index count,
//!   store size, then 16-byte index entries (tag, type, offset, count) and
//!   the store. The signature header is padded to a multiple of 8 bytes.
//! - Integrity: when present, the signature tags SHA256 (273) and SHA1
//!   (269, hex strings over the main header) and MD5 (1004, 16 bytes over
//!   main header + payload) are verified, as is the main header's
//!   PAYLOADDIGEST (5092) with PAYLOADDIGESTALGO (5093; OpenPGP hash ids
//!   1 MD5, 2 SHA-1, 8 SHA-256, 9 SHA-384, 10 SHA-512) over the compressed
//!   payload. A mismatch is `CrcMismatch`. OpenPGP signatures are not
//!   checked.
//! - Payload: PAYLOADFORMAT (1124) must be `cpio` when present; the
//!   compressor is recognised by magic bytes (gzip, bzip2, xz, plain cpio)
//!   or PAYLOADCOMPRESSOR (1125) `lzma`. Zstandard payloads (`28 B5 2F FD`)
//!   are `Unsupported`.
//!
//! Adapter seam: the forge ticket `rpm_header` covers lead/header parsing
//! and tag accessors; until it is harvested the minimal subset needed here
//! lives in [`RpmHeader`].

use std::borrow::Cow;

use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::archive_open::decompress;
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::cpio_archive::CpioReader;
use crate::extract_plan::PlannedEntry;
use crate::hash_md5::md5;
use crate::hash_sha1::sha1;
use crate::hash_sha256::sha256;
use crate::hash_sha512::{sha384, sha512};
use crate::lzma_decode::decode_lzma_alone;

pub const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
pub const HEADER_MAGIC: [u8; 4] = [0x8E, 0xAD, 0xE8, 0x01];
const LEAD_LEN: usize = 96;

pub mod tag {
    pub const SIG_SHA1: u32 = 269;
    pub const SIG_SHA256: u32 = 273;
    pub const SIG_MD5: u32 = 1004;
    pub const NAME: u32 = 1000;
    pub const VERSION: u32 = 1001;
    pub const RELEASE: u32 = 1002;
    pub const ARCH: u32 = 1022;
    pub const PAYLOADFORMAT: u32 = 1124;
    pub const PAYLOADCOMPRESSOR: u32 = 1125;
    pub const PAYLOADDIGEST: u32 = 5092;
    pub const PAYLOADDIGESTALGO: u32 = 5093;
}

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_BIN: u32 = 7;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmError {
    Truncated,
    BadLeadMagic,
    UnsupportedSignatureType,
    BadHeaderMagic,
    LimitExceeded,
    BadEntry,
    BadString,
    MissingTag,
    DigestMismatch,
    UnsupportedPayload,
    Allocation,
}

impl From<RpmError> for ReaderError {
    fn from(e: RpmError) -> Self {
        match e {
            RpmError::Truncated => ReaderError::Truncated,
            RpmError::UnsupportedSignatureType | RpmError::UnsupportedPayload => ReaderError::Unsupported,
            RpmError::LimitExceeded => ReaderError::LimitExceeded,
            RpmError::DigestMismatch => ReaderError::CrcMismatch,
            RpmError::Allocation => ReaderError::Allocation,
            RpmError::BadLeadMagic
            | RpmError::BadHeaderMagic
            | RpmError::BadEntry
            | RpmError::BadString
            | RpmError::MissingTag => ReaderError::Invalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpmLimits {
    pub max_index_entries: u32,
    pub max_store_bytes: u32,
}

impl Default for RpmLimits {
    fn default() -> Self {
        RpmLimits { max_index_entries: 65_536, max_store_bytes: 64 << 20 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpmIndexEntry {
    pub tag: u32,
    pub kind: u32,
    pub offset: u32,
    pub count: u32,
}

/// A parsed header structure (index + store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmHeader {
    pub entries: Vec<RpmIndexEntry>,
    pub store: Vec<u8>,
}

fn be32(b: &[u8], at: usize) -> Result<u32, RpmError> {
    let s = b.get(at..at.checked_add(4).ok_or(RpmError::Truncated)?).ok_or(RpmError::Truncated)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse a header structure at the start of `data`. Returns the header and
/// the number of bytes it occupies.
pub fn parse_header(data: &[u8], limits: &RpmLimits) -> Result<(RpmHeader, usize), RpmError> {
    if data.len() < 16 {
        return Err(RpmError::Truncated);
    }
    if data[..4] != HEADER_MAGIC {
        return Err(RpmError::BadHeaderMagic);
    }
    let nindex = be32(data, 8)?;
    let hsize = be32(data, 12)?;
    if nindex > limits.max_index_entries || hsize > limits.max_store_bytes {
        return Err(RpmError::LimitExceeded);
    }
    let total = 16u64 + 16 * u64::from(nindex) + u64::from(hsize);
    if total > data.len() as u64 {
        return Err(RpmError::Truncated);
    }
    let total = total as usize;
    let mut entries = Vec::new();
    entries.try_reserve_exact(nindex as usize).map_err(|_| RpmError::Allocation)?;
    for i in 0..nindex as usize {
        let at = 16 + i * 16;
        entries.push(RpmIndexEntry { tag: be32(data, at)?, kind: be32(data, at + 4)?, offset: be32(data, at + 8)?, count: be32(data, at + 12)? });
    }
    let store_start = 16 + 16 * nindex as usize;
    let mut store = Vec::new();
    store.try_reserve_exact(hsize as usize).map_err(|_| RpmError::Allocation)?;
    store.extend_from_slice(&data[store_start..total]);
    Ok((RpmHeader { entries, store }, total))
}

impl RpmHeader {
    pub fn find(&self, tag: u32) -> Option<&RpmIndexEntry> {
        self.entries.iter().find(|e| e.tag == tag)
    }

    fn cstr_at(&self, offset: usize) -> Result<(String, usize), RpmError> {
        let rest = self.store.get(offset..).ok_or(RpmError::BadEntry)?;
        let n = rest.iter().position(|&b| b == 0).ok_or(RpmError::BadString)?;
        let s = std::str::from_utf8(&rest[..n]).map_err(|_| RpmError::BadString)?;
        Ok((s.to_owned(), offset + n + 1))
    }

    /// STRING or I18NSTRING (first translation). Missing tag -> `Ok(None)`.
    pub fn get_string(&self, tag: u32) -> Result<Option<String>, RpmError> {
        let Some(e) = self.find(tag) else { return Ok(None) };
        if e.kind != TYPE_STRING && e.kind != TYPE_I18NSTRING {
            return Err(RpmError::BadEntry);
        }
        let off = e.offset as usize;
        if off >= self.store.len() {
            return Err(RpmError::BadEntry);
        }
        Ok(Some(self.cstr_at(off)?.0))
    }

    /// STRING_ARRAY. Missing tag -> `Ok(None)`.
    pub fn get_string_array(&self, tag: u32) -> Result<Option<Vec<String>>, RpmError> {
        let Some(e) = self.find(tag) else { return Ok(None) };
        if e.kind != TYPE_STRING_ARRAY {
            return Err(RpmError::BadEntry);
        }
        let mut off = e.offset as usize;
        if off > self.store.len() {
            return Err(RpmError::BadEntry);
        }
        let mut out = Vec::new();
        for _ in 0..e.count {
            // Each string takes at least one store byte: bounded by the store.
            if off >= self.store.len() {
                return Err(RpmError::BadString);
            }
            let (s, next) = self.cstr_at(off)?;
            out.try_reserve(1).map_err(|_| RpmError::Allocation)?;
            out.push(s);
            off = next;
        }
        Ok(Some(out))
    }

    /// INT32 array. Missing tag -> `Ok(None)`.
    pub fn get_u32_array(&self, tag: u32) -> Result<Option<Vec<u32>>, RpmError> {
        let Some(e) = self.find(tag) else { return Ok(None) };
        if e.kind != TYPE_INT32 {
            return Err(RpmError::BadEntry);
        }
        let b = self.get_raw(e, 4)?;
        Ok(Some(b.chunks_exact(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect()))
    }

    /// BIN bytes. Missing tag -> `Ok(None)`.
    pub fn get_bin(&self, tag: u32) -> Result<Option<&[u8]>, RpmError> {
        let Some(e) = self.find(tag) else { return Ok(None) };
        if e.kind != TYPE_BIN {
            return Err(RpmError::BadEntry);
        }
        self.get_raw(e, 1).map(Some)
    }

    fn get_raw(&self, e: &RpmIndexEntry, width: u64) -> Result<&[u8], RpmError> {
        let start = u64::from(e.offset);
        let end = start.checked_add(width * u64::from(e.count)).ok_or(RpmError::BadEntry)?;
        if end > self.store.len() as u64 {
            return Err(RpmError::BadEntry);
        }
        Ok(&self.store[start as usize..end as usize])
    }
}

/// Package identity and layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmInfo {
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: Option<String>,
    pub payload_format: Option<String>,
    pub payload_compressor: Option<String>,
    /// Offset of the main header in the file.
    pub header_offset: usize,
    /// Offset of the (compressed) payload in the file.
    pub payload_offset: usize,
}

fn hex_eq(hex: &str, digest: &[u8]) -> bool {
    let h = hex.trim().as_bytes();
    h.len() == digest.len() * 2
        && h.chunks_exact(2).zip(digest).all(|(c, &d)| {
            let v = |x: u8| (x as char).to_digit(16);
            matches!((v(c[0]), v(c[1])), (Some(a), Some(b)) if (a * 16 + b) as u8 == d)
        })
}

/// Parse lead and both headers and verify the digests listed in the module
/// documentation. Returns the package info and the main header.
pub fn parse_rpm(data: &[u8], limits: &RpmLimits) -> Result<(RpmInfo, RpmHeader), RpmError> {
    if data.len() < LEAD_LEN {
        return Err(RpmError::Truncated);
    }
    if data[..4] != LEAD_MAGIC {
        return Err(RpmError::BadLeadMagic);
    }
    let sig_type = u16::from_be_bytes([data[78], data[79]]);
    if sig_type != 5 {
        return Err(RpmError::UnsupportedSignatureType);
    }
    let (sig, sig_len) = parse_header(&data[LEAD_LEN..], limits)?;
    let header_offset = (LEAD_LEN + sig_len).checked_add(7).ok_or(RpmError::Truncated)? / 8 * 8;
    let rest = data.get(header_offset..).ok_or(RpmError::Truncated)?;
    let (header, header_len) = parse_header(rest, limits)?;
    let payload_offset = header_offset + header_len;
    let header_bytes = &data[header_offset..payload_offset];
    let payload = &data[payload_offset..];

    if let Some(h) = sig.get_string(tag::SIG_SHA256)? {
        if !hex_eq(&h, &sha256(header_bytes)) {
            return Err(RpmError::DigestMismatch);
        }
    }
    if let Some(h) = sig.get_string(tag::SIG_SHA1)? {
        if !hex_eq(&h, &sha1(header_bytes)) {
            return Err(RpmError::DigestMismatch);
        }
    }
    if let Some(d) = sig.get_bin(tag::SIG_MD5)? {
        if d != md5(&data[header_offset..]) {
            return Err(RpmError::DigestMismatch);
        }
    }
    if let Some(list) = header.get_string_array(tag::PAYLOADDIGEST)? {
        let algo = header.get_u32_array(tag::PAYLOADDIGESTALGO)?.and_then(|v| v.first().copied()).unwrap_or(8);
        let digest: Vec<u8> = match algo {
            1 => md5(payload).to_vec(),
            2 => sha1(payload).to_vec(),
            8 => sha256(payload).to_vec(),
            9 => sha384(payload).to_vec(),
            10 => sha512(payload).to_vec(),
            _ => Vec::new(),
        };
        if !digest.is_empty() && !list.first().is_some_and(|h| hex_eq(h, &digest)) {
            return Err(RpmError::DigestMismatch);
        }
    }
    let need = |t| header.get_string(t)?.ok_or(RpmError::MissingTag);
    let info = RpmInfo {
        name: need(tag::NAME)?,
        version: need(tag::VERSION)?,
        release: need(tag::RELEASE)?,
        arch: header.get_string(tag::ARCH)?,
        payload_format: header.get_string(tag::PAYLOADFORMAT)?,
        payload_compressor: header.get_string(tag::PAYLOADCOMPRESSOR)?,
        header_offset,
        payload_offset,
    };
    Ok((info, header))
}

/// Decompress the payload to the raw cpio stream (output capped at
/// `max_output`).
fn unpack_payload<'a>(info: &RpmInfo, payload: &'a [u8], max_output: usize) -> Result<Cow<'a, [u8]>, ReaderError> {
    if let Some(f) = &info.payload_format {
        if f != "cpio" {
            return Err(ReaderError::Unsupported);
        }
    }
    if payload.starts_with(b"0707") {
        return Ok(Cow::Borrowed(payload));
    }
    if payload.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Err(ReaderError::Unsupported);
    }
    match detect_format(payload) {
        Detected::Gzip => Ok(Cow::Owned(decompress(ArchiveFormat::Gzip, payload, max_output)?)),
        Detected::Bzip2 => Ok(Cow::Owned(decompress(ArchiveFormat::Bzip2, payload, max_output)?)),
        Detected::Xz => Ok(Cow::Owned(decompress(ArchiveFormat::Xz, payload, max_output)?)),
        _ if info.payload_compressor.as_deref() == Some("lzma") => {
            Ok(Cow::Owned(decode_lzma_alone(payload, 1 << 32, max_output).map_err(|_| ReaderError::Invalid)?))
        }
        _ => Err(ReaderError::Unsupported),
    }
}

/// RPM package reader: lists and reads the files of the cpio payload.
pub struct RpmReader {
    info: RpmInfo,
    cpio: CpioReader<'static>,
}

impl RpmReader {
    pub fn new(bytes: &[u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let (info, _) = parse_rpm(bytes, &RpmLimits::default())?;
        let max_out = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
        // The payload also holds cpio headers and padding; allow some slack
        // over the file-data budget (which CpioReader enforces itself).
        let max_out = max_out.saturating_add(max_out / 4).saturating_add(1 << 20);
        let cpio = unpack_payload(&info, &bytes[info.payload_offset..], max_out)?.into_owned();
        let cpio = CpioReader::with_format(Cow::Owned(cpio), limits, ArchiveFormat::Rpm)?;
        Ok(RpmReader { info, cpio })
    }

    pub fn info(&self) -> &RpmInfo {
        &self.info
    }
}

impl ArchiveReader for RpmReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Rpm
    }
    fn entries(&self) -> &[PlannedEntry] {
        self.cpio.entries()
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        self.cpio.read(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bounds() {
        let mut h = HEADER_MAGIC.to_vec();
        h.extend([0; 4]);
        h.extend(1u32.to_be_bytes());
        h.extend(4u32.to_be_bytes());
        h.extend(1000u32.to_be_bytes());
        h.extend(TYPE_STRING.to_be_bytes());
        h.extend(0u32.to_be_bytes());
        h.extend(1u32.to_be_bytes());
        h.extend(b"abc\0");
        let (hd, n) = parse_header(&h, &RpmLimits::default()).unwrap();
        assert_eq!(n, h.len());
        assert_eq!(hd.get_string(1000).unwrap().as_deref(), Some("abc"));
        for k in 0..h.len() {
            assert!(parse_header(&h[..k], &RpmLimits::default()).is_err());
        }
        assert!(hex_eq("0aFF", &[0x0a, 0xff]));
        assert!(!hex_eq("0aF", &[0x0a, 0xff]));
    }
}
