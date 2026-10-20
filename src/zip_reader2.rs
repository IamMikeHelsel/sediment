// SPDX-License-Identifier: MIT OR Apache-2.0
//! Higher-level ZIP reader: lists and reads entries in classic and ZIP64
//! archives, with or without data descriptors, stored or deflated.
//! Encrypted entries (traditional PKWARE, WinZip AES, strong encryption) are
//! listed and reported but never decrypted.
//!
//! This sits beside the older `zip_*` modules (whose APIs are unchanged) and
//! accepts a much wider range of real-world archives.
//!
//! Spec sources: PKWARE APPNOTE.TXT 6.3.x (4.3.7 local file header, 4.3.9
//! data descriptor, 4.3.12 central directory header, 4.3.13 digital
//! signature, 4.4.4 general purpose flags, 4.5 extra fields), WinZip AES
//! document (method 99 + 0x9901 record), Info-ZIP extrafld.txt.
//!
//! Hostile-input posture: every offset and size is bounds-checked against
//! the input; entry counts and declared sizes are limited by the caller
//! before allocation; local records may not overlap each other or the
//! central directory; decompressed output is capped and CRC-checked.

use std::borrow::Cow;

use crate::crc32::crc32;
use crate::inflate::{inflate_raw, InflateError};
use crate::zip64::{locate_central_directory, parse_zip64_extra, Zip64Error, Zip64Needs};
use crate::zip_descriptor::{match_descriptor, DataDescriptor, DescriptorError, ExpectedDescriptor};
use crate::zip_extra_read::{
    parse_aes, parse_extended_timestamp, parse_ntfs, parse_unicode_path, parse_unix_owner, AesInfo,
    ExtendedTimestamp, ExtraError, NtfsTimes, UnixOwner, AES_EXTRA_ID, EXTENDED_TIMESTAMP_ID, NTFS_EXTRA_ID,
    UNICODE_PATH_ID, UNIX_OWNER_ID, ZIP64_EXTRA_ID,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader2Error {
    /// A structure runs past the end of the input.
    Truncated,
    /// Malformed or inconsistent archive structure.
    Invalid,
    /// Well-formed but not supported (multi-disk, unknown method, ...).
    Unsupported,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// Decoded data does not match the stored CRC-32.
    CrcMismatch,
    /// The entry is encrypted; decryption is not implemented.
    Encrypted,
}

impl From<Zip64Error> for Reader2Error {
    fn from(e: Zip64Error) -> Self {
        match e {
            Zip64Error::Truncated => Reader2Error::Truncated,
            Zip64Error::Invalid => Reader2Error::Invalid,
            Zip64Error::Unsupported => Reader2Error::Unsupported,
            Zip64Error::LimitExceeded => Reader2Error::LimitExceeded,
        }
    }
}

impl From<ExtraError> for Reader2Error {
    fn from(e: ExtraError) -> Self {
        match e {
            ExtraError::Truncated | ExtraError::Invalid => Reader2Error::Invalid,
            ExtraError::Unsupported => Reader2Error::Unsupported,
            ExtraError::LimitExceeded => Reader2Error::LimitExceeded,
        }
    }
}

/// Caller limits. All are enforced before the corresponding allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reader2Limits {
    /// Maximum number of central-directory entries.
    pub max_entries: usize,
    /// Maximum declared uncompressed size of a single entry.
    pub max_entry_size: u64,
    /// Maximum sum of declared uncompressed sizes.
    pub max_total_size: u64,
    /// Maximum DEFLATE blocks per entry when reading.
    pub max_deflate_blocks: usize,
}

impl Default for Reader2Limits {
    /// 1 Mi entries, 4 GiB per entry, 64 GiB total, 1 Mi deflate blocks.
    fn default() -> Self {
        Reader2Limits {
            max_entries: 1 << 20,
            max_entry_size: 4 << 30,
            max_total_size: 64 << 30,
            max_deflate_blocks: 1 << 20,
        }
    }
}

/// Effective compression method of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Stored,
    Deflate,
    Deflate64,
    Other(u16),
}

impl Compression {
    pub fn from_method(method: u16) -> Self {
        match method {
            0 => Compression::Stored,
            8 => Compression::Deflate,
            9 => Compression::Deflate64,
            m => Compression::Other(m),
        }
    }
}

/// Encryption reported for an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    /// PKWARE traditional ("ZipCrypto") encryption.
    Traditional,
    /// WinZip AES (method 99 + 0x9901 record).
    Aes(AesInfo),
    /// PKWARE strong encryption (flag bit 6) or central-directory encryption (bit 13).
    Strong,
}

pub const FLAG_ENCRYPTED: u16 = 0x0001;
pub const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
pub const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;
pub const FLAG_UTF8: u16 = 0x0800;
pub const FLAG_MASKED_HEADER: u16 = 0x2000;
pub const METHOD_AES: u16 = 99;

const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const DIGITAL_SIGNATURE: u32 = 0x0505_4b50;
const CENTRAL_FIXED: usize = 46;
const LOCAL_FIXED: usize = 30;

/// One listed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry2<'a> {
    /// Name bytes exactly as stored in the central directory.
    pub raw_name: &'a [u8],
    /// UTF-8 name from a valid (non-stale) Info-ZIP Unicode Path record.
    pub unicode_name: Option<&'a [u8]>,
    pub comment: &'a [u8],
    pub version_made_by: u16,
    pub version_needed: u16,
    pub flags: u16,
    /// Method field as stored (99 for AES).
    pub method: u16,
    /// Effective compression (AES's inner method for method 99).
    pub compression: Compression,
    pub encryption: Encryption,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// Local header offset as stored (relative to the archive start).
    pub local_header_offset: u64,
    /// Actual position of the local header in the input.
    pub header_start: usize,
    /// Actual position of the (possibly encrypted) compressed data.
    pub data_start: usize,
    pub data_end: usize,
    /// Present when flag bit 3 is set.
    pub descriptor: Option<DataDescriptor>,
    /// True if any ZIP64 extra field was used for this entry.
    pub zip64: bool,
    pub dos_time: u16,
    pub dos_date: u16,
    pub internal_attributes: u16,
    pub external_attributes: u32,
    /// From 0x5455 (local copy preferred: it may carry atime/ctime).
    pub extended_timestamp: Option<ExtendedTimestamp>,
    pub unix_owner: Option<UnixOwner>,
    pub ntfs_times: Option<NtfsTimes>,
    pub central_extra: &'a [u8],
    pub local_extra: &'a [u8],
}

impl Entry2<'_> {
    /// Preferred name: the Unicode Path if present, else the raw name.
    pub fn name(&self) -> &[u8] {
        self.unicode_name.unwrap_or(self.raw_name)
    }

    /// True if `name()` is known to be UTF-8 (flag bit 11 or Unicode Path).
    pub fn name_is_utf8(&self) -> bool {
        self.unicode_name.is_some() || (self.flags & FLAG_UTF8 != 0 && std::str::from_utf8(self.raw_name).is_ok())
    }

    pub fn is_dir(&self) -> bool {
        self.raw_name.last() == Some(&b'/')
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption != Encryption::None
    }

    pub fn has_data_descriptor(&self) -> bool {
        self.flags & FLAG_DATA_DESCRIPTOR != 0
    }

    /// Unix mode bits when the entry was made on a Unix host (upper byte 3).
    pub fn unix_mode(&self) -> Option<u32> {
        if self.version_made_by >> 8 == 3 {
            let mode = self.external_attributes >> 16;
            if mode != 0 {
                return Some(mode);
            }
        }
        None
    }
}

/// A parsed archive borrowing from the input bytes.
#[derive(Debug, Clone)]
pub struct ZipArchive2<'a> {
    bytes: &'a [u8],
    entries: Vec<Entry2<'a>>,
    comment: &'a [u8],
    zip64: bool,
    prefix: usize,
    limits: Reader2Limits,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, Reader2Error> {
    let s = b.get(at..at.checked_add(2).ok_or(Reader2Error::Truncated)?).ok_or(Reader2Error::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Reader2Error> {
    let s = b.get(at..at.checked_add(4).ok_or(Reader2Error::Truncated)?).ok_or(Reader2Error::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn slice(b: &[u8], start: usize, len: usize) -> Result<&[u8], Reader2Error> {
    let end = start.checked_add(len).ok_or(Reader2Error::Truncated)?;
    b.get(start..end).ok_or(Reader2Error::Truncated)
}

/// Known records of one extra block. A trailing fragment shorter than a
/// record header (alignment padding written by some tools) is ignored; a
/// record overrunning the block, or a duplicate known record, is `Invalid`.
#[derive(Default)]
struct KnownExtras<'a> {
    zip64: Option<&'a [u8]>,
    unicode_path: Option<&'a [u8]>,
    timestamp: Option<&'a [u8]>,
    unix_owner: Option<&'a [u8]>,
    ntfs: Option<&'a [u8]>,
    aes: Option<&'a [u8]>,
}

fn scan_extras(block: &[u8]) -> Result<KnownExtras<'_>, Reader2Error> {
    let mut known = KnownExtras::default();
    let mut pos = 0usize;
    while block.len() - pos >= 4 {
        let id = u16::from_le_bytes([block[pos], block[pos + 1]]);
        let len = u16::from_le_bytes([block[pos + 2], block[pos + 3]]) as usize;
        let data = block.get(pos + 4..pos + 4 + len).ok_or(Reader2Error::Invalid)?;
        pos += 4 + len;
        let slot = match id {
            ZIP64_EXTRA_ID => &mut known.zip64,
            UNICODE_PATH_ID => &mut known.unicode_path,
            EXTENDED_TIMESTAMP_ID => &mut known.timestamp,
            UNIX_OWNER_ID => &mut known.unix_owner,
            NTFS_EXTRA_ID => &mut known.ntfs,
            AES_EXTRA_ID => &mut known.aes,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Reader2Error::Invalid);
        }
        *slot = Some(data);
    }
    Ok(known)
}

/// Optional metadata records: malformed or unsupported variants are ignored
/// rather than failing the whole archive.
fn optional<T>(data: Option<&[u8]>, parse: impl Fn(&[u8]) -> Result<T, ExtraError>) -> Option<T> {
    data.and_then(|d| parse(d).ok())
}

struct Central<'a> {
    made_by: u16,
    needed: u16,
    flags: u16,
    method: u16,
    time: u16,
    date: u16,
    crc32: u32,
    csize: u64,
    usize_: u64,
    name: &'a [u8],
    extra: &'a [u8],
    comment: &'a [u8],
    internal: u16,
    external: u32,
    local_offset: u64,
    zip64: bool,
    next: usize,
}

fn parse_central_record(cd: &[u8], at: usize) -> Result<Central<'_>, Reader2Error> {
    if u32_at(cd, at)? != CENTRAL_SIGNATURE {
        return Err(Reader2Error::Invalid);
    }
    slice(cd, at, CENTRAL_FIXED)?;
    let made_by = u16_at(cd, at + 4)?;
    let needed = u16_at(cd, at + 6)?;
    let flags = u16_at(cd, at + 8)?;
    let method = u16_at(cd, at + 10)?;
    let time = u16_at(cd, at + 12)?;
    let date = u16_at(cd, at + 14)?;
    let crc = u32_at(cd, at + 16)?;
    let csize32 = u32_at(cd, at + 20)?;
    let usize32 = u32_at(cd, at + 24)?;
    let name_len = u16_at(cd, at + 28)? as usize;
    let extra_len = u16_at(cd, at + 30)? as usize;
    let comment_len = u16_at(cd, at + 32)? as usize;
    let disk = u16_at(cd, at + 34)?;
    let internal = u16_at(cd, at + 36)?;
    let external = u32_at(cd, at + 38)?;
    let offset32 = u32_at(cd, at + 42)?;
    let name = slice(cd, at + CENTRAL_FIXED, name_len)?;
    let extra = slice(cd, at + CENTRAL_FIXED + name_len, extra_len)?;
    let comment = slice(cd, at + CENTRAL_FIXED + name_len + extra_len, comment_len)?;
    let next = at + CENTRAL_FIXED + name_len + extra_len + comment_len;

    let known = scan_extras(extra)?;
    let needs = Zip64Needs::central(usize32, csize32, offset32, disk);
    let (mut usize_, mut csize, mut local_offset, mut disk32) = (usize32 as u64, csize32 as u64, offset32 as u64, disk as u32);
    let mut zip64 = false;
    if needs.any() {
        let data = known.zip64.ok_or(Reader2Error::Invalid)?;
        let z = parse_zip64_extra(data, needs).map_err(|_| Reader2Error::Invalid)?;
        usize_ = z.uncompressed_size.unwrap_or(usize_);
        csize = z.compressed_size.unwrap_or(csize);
        local_offset = z.local_header_offset.unwrap_or(local_offset);
        disk32 = z.disk_start.unwrap_or(disk32);
        zip64 = true;
    }
    if disk32 != 0 {
        return Err(Reader2Error::Unsupported);
    }
    Ok(Central {
        made_by,
        needed,
        flags,
        method,
        time,
        date,
        crc32: crc,
        csize,
        usize_,
        name,
        extra,
        comment,
        internal,
        external,
        local_offset,
        zip64,
        next,
    })
}

fn classify_encryption(flags: u16, method: u16, aes: Option<&[u8]>) -> Result<(Encryption, Compression), Reader2Error> {
    if method == METHOD_AES {
        if flags & FLAG_ENCRYPTED == 0 {
            // Without the encryption flag and the 0x9901 record, method 99
            // is the LZFSE method (decoded by `archive_reader`).
            if aes.is_none() {
                return Ok((Encryption::None, Compression::Other(METHOD_AES)));
            }
            return Err(Reader2Error::Invalid);
        }
        let info = parse_aes(aes.ok_or(Reader2Error::Invalid)?)?;
        return Ok((Encryption::Aes(info), Compression::from_method(info.actual_method)));
    }
    let compression = Compression::from_method(method);
    if flags & FLAG_MASKED_HEADER != 0 || (flags & FLAG_ENCRYPTED != 0 && flags & FLAG_STRONG_ENCRYPTION != 0) {
        return Ok((Encryption::Strong, compression));
    }
    if flags & FLAG_ENCRYPTED != 0 {
        return Ok((Encryption::Traditional, compression));
    }
    Ok((Encryption::None, compression))
}

impl<'a> ZipArchive2<'a> {
    /// Parse the central directory and every local header.
    pub fn open(bytes: &'a [u8], limits: Reader2Limits) -> Result<Self, Reader2Error> {
        let loc = locate_central_directory(bytes)?;
        if loc.entries > limits.max_entries as u64 {
            return Err(Reader2Error::LimitExceeded);
        }
        let cd = slice(bytes, loc.cd_start, loc.cd_size)?;
        let declared = loc.entries as usize;

        let mut entries: Vec<Entry2<'a>> = Vec::new();
        entries.try_reserve(declared).map_err(|_| Reader2Error::Allocation)?;
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        ranges.try_reserve(declared).map_err(|_| Reader2Error::Allocation)?;
        let mut total: u64 = 0;
        let mut cursor = 0usize;

        while cursor < cd.len() {
            if u32_at(cd, cursor)? == DIGITAL_SIGNATURE {
                let len = u16_at(cd, cursor + 4)? as usize;
                if cursor + 6 + len != cd.len() {
                    return Err(Reader2Error::Invalid);
                }
                break;
            }
            if entries.len() >= limits.max_entries {
                return Err(Reader2Error::LimitExceeded);
            }
            let c = parse_central_record(cd, cursor)?;
            cursor = c.next;
            if c.name.is_empty() {
                return Err(Reader2Error::Invalid);
            }
            if c.usize_ > limits.max_entry_size {
                return Err(Reader2Error::LimitExceeded);
            }
            total = total.checked_add(c.usize_).ok_or(Reader2Error::LimitExceeded)?;
            if total > limits.max_total_size {
                return Err(Reader2Error::LimitExceeded);
            }
            let entry = Self::resolve_entry(bytes, &loc, c)?;
            let range_end = entry.descriptor.map(|d| d.end).unwrap_or(entry.data_end);
            ranges.try_reserve(1).map_err(|_| Reader2Error::Allocation)?;
            ranges.push((entry.header_start, range_end));
            entries.try_reserve(1).map_err(|_| Reader2Error::Allocation)?;
            entries.push(entry);
        }

        let parsed = entries.len();
        // Accept a 16-bit-truncated count from writers that exceed 65535
        // entries without emitting ZIP64 records.
        let count_ok = parsed == declared || (loc.zip64.is_none() && parsed > 0xffff && parsed % 0x1_0000 == declared);
        if !count_ok {
            return Err(Reader2Error::Invalid);
        }

        // Local records may not overlap each other or the directory.
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(Reader2Error::Invalid);
            }
        }
        if let Some(last) = ranges.last() {
            if last.1 > loc.cd_start {
                return Err(Reader2Error::Invalid);
            }
        }

        Ok(ZipArchive2 { bytes, entries, comment: loc.comment, zip64: loc.zip64.is_some(), prefix: loc.prefix, limits })
    }

    fn resolve_entry(
        bytes: &'a [u8],
        loc: &crate::zip64::CentralDirectoryLocation<'a>,
        c: Central<'a>,
    ) -> Result<Entry2<'a>, Reader2Error> {
        let central_known = scan_extras(c.extra)?;
        let (encryption, compression) = classify_encryption(c.flags, c.method, central_known.aes)?;

        let header_start = usize::try_from(c.local_offset)
            .ok()
            .and_then(|o| o.checked_add(loc.prefix))
            .ok_or(Reader2Error::Invalid)?;
        if header_start >= loc.cd_start {
            return Err(Reader2Error::Invalid);
        }
        if u32_at(bytes, header_start)? != LOCAL_SIGNATURE {
            return Err(Reader2Error::Invalid);
        }
        slice(bytes, header_start, LOCAL_FIXED)?;
        let l_flags = u16_at(bytes, header_start + 6)?;
        let l_method = u16_at(bytes, header_start + 8)?;
        let l_crc = u32_at(bytes, header_start + 14)?;
        let l_csize32 = u32_at(bytes, header_start + 18)?;
        let l_usize32 = u32_at(bytes, header_start + 22)?;
        let l_name_len = u16_at(bytes, header_start + 26)? as usize;
        let l_extra_len = u16_at(bytes, header_start + 28)? as usize;
        let l_name = slice(bytes, header_start + LOCAL_FIXED, l_name_len)?;
        let l_extra = slice(bytes, header_start + LOCAL_FIXED + l_name_len, l_extra_len)?;
        let data_start = header_start + LOCAL_FIXED + l_name_len + l_extra_len;

        if l_name != c.name || l_method != c.method {
            return Err(Reader2Error::Invalid);
        }
        if (l_flags ^ c.flags) & (FLAG_ENCRYPTED | FLAG_DATA_DESCRIPTOR) != 0 {
            return Err(Reader2Error::Invalid);
        }
        let local_known = scan_extras(l_extra)?;

        let csize = usize::try_from(c.csize).map_err(|_| Reader2Error::LimitExceeded)?;
        let data_end = data_start.checked_add(csize).ok_or(Reader2Error::Truncated)?;
        if data_end > loc.cd_start {
            return Err(if data_end > bytes.len() { Reader2Error::Truncated } else { Reader2Error::Invalid });
        }

        let mut zip64 = c.zip64;
        let local_needs = Zip64Needs::local(l_usize32, l_csize32);
        let (mut l_usize, mut l_csize) = (l_usize32 as u64, l_csize32 as u64);
        if local_needs.any() {
            let data = local_known.zip64.ok_or(Reader2Error::Invalid)?;
            let z = parse_zip64_extra(data, local_needs).map_err(|_| Reader2Error::Invalid)?;
            l_usize = z.uncompressed_size.unwrap_or(l_usize);
            l_csize = z.compressed_size.unwrap_or(l_csize);
            zip64 = true;
        }

        let masked = c.flags & FLAG_MASKED_HEADER != 0;
        let descriptor = if c.flags & FLAG_DATA_DESCRIPTOR != 0 {
            let expected = ExpectedDescriptor { crc32: c.crc32, compressed_size: c.csize, uncompressed_size: c.usize_ };
            let hint = Some(local_known.zip64.is_some());
            let d = match match_descriptor(bytes, data_end, hint, expected) {
                Ok(d) => d,
                Err(DescriptorError::Truncated) | Err(DescriptorError::Mismatch) => {
                    match_descriptor(bytes, data_end, None, expected).map_err(|e| match e {
                        DescriptorError::Truncated => Reader2Error::Truncated,
                        _ => Reader2Error::Invalid,
                    })?
                }
                Err(_) => return Err(Reader2Error::Invalid),
            };
            if d.end > loc.cd_start {
                return Err(Reader2Error::Invalid);
            }
            // Local values, when not zeroed, must still agree.
            let zeroed = l_crc == 0 && l_csize == 0 && l_usize == 0;
            if !zeroed && !masked && (l_crc != c.crc32 || l_csize != c.csize || l_usize != c.usize_) {
                return Err(Reader2Error::Invalid);
            }
            Some(d)
        } else {
            if !masked && (l_crc != c.crc32 || l_csize != c.csize || l_usize != c.usize_) {
                return Err(Reader2Error::Invalid);
            }
            None
        };

        let unicode_name = match central_known.unicode_path.or(local_known.unicode_path) {
            Some(d) => match parse_unicode_path(d) {
                Ok(up) if up.matches(c.name) => Some(up.name),
                _ => None,
            },
            None => None,
        };
        let extended_timestamp = optional(local_known.timestamp, parse_extended_timestamp)
            .or_else(|| optional(central_known.timestamp, parse_extended_timestamp));
        let unix_owner = optional(central_known.unix_owner.or(local_known.unix_owner), parse_unix_owner);
        let ntfs_times = optional(central_known.ntfs.or(local_known.ntfs), parse_ntfs).flatten();

        Ok(Entry2 {
            raw_name: c.name,
            unicode_name,
            comment: c.comment,
            version_made_by: c.made_by,
            version_needed: c.needed,
            flags: c.flags,
            method: c.method,
            compression,
            encryption,
            crc32: c.crc32,
            compressed_size: c.csize,
            uncompressed_size: c.usize_,
            local_header_offset: c.local_offset,
            header_start,
            data_start,
            data_end,
            descriptor,
            zip64,
            dos_time: c.time,
            dos_date: c.date,
            internal_attributes: c.internal,
            external_attributes: c.external,
            extended_timestamp,
            unix_owner,
            ntfs_times,
            central_extra: c.extra,
            local_extra: l_extra,
        })
    }

    pub fn entries(&self) -> &[Entry2<'a>] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Archive comment from the EOCD record.
    pub fn comment(&self) -> &'a [u8] {
        self.comment
    }

    /// True if the archive uses ZIP64 end-of-central-directory records.
    pub fn is_zip64(&self) -> bool {
        self.zip64
    }

    /// Bytes preceding the archive proper (e.g. an SFX stub).
    pub fn prefix_len(&self) -> usize {
        self.prefix
    }

    /// Index of the first entry whose `name()` equals `name`.
    pub fn find(&self, name: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.name() == name || e.raw_name == name)
    }

    /// The entry's stored payload (compressed, and encrypted if applicable).
    pub fn raw_data(&self, index: usize) -> Result<&'a [u8], Reader2Error> {
        let e = self.entries.get(index).ok_or(Reader2Error::Invalid)?;
        self.bytes.get(e.data_start..e.data_end).ok_or(Reader2Error::Truncated)
    }

    /// Decode an entry, refusing output larger than `max_output`. Stored
    /// entries are borrowed. The CRC-32 is always verified.
    pub fn read(&self, index: usize, max_output: usize) -> Result<Cow<'a, [u8]>, Reader2Error> {
        let e = self.entries.get(index).ok_or(Reader2Error::Invalid)?;
        if e.is_encrypted() {
            return Err(Reader2Error::Encrypted);
        }
        let size = usize::try_from(e.uncompressed_size).map_err(|_| Reader2Error::LimitExceeded)?;
        if size > max_output {
            return Err(Reader2Error::LimitExceeded);
        }
        let raw = self.raw_data(index)?;
        let data: Cow<'a, [u8]> = match e.compression {
            Compression::Stored => {
                if raw.len() != size {
                    return Err(Reader2Error::Invalid);
                }
                Cow::Borrowed(raw)
            }
            Compression::Deflate => {
                let out = inflate_raw(raw, size, self.limits.max_deflate_blocks).map_err(|err| match err {
                    InflateError::LimitExceeded => Reader2Error::LimitExceeded,
                    InflateError::Allocation => Reader2Error::Allocation,
                    InflateError::UnsupportedBlock => Reader2Error::Unsupported,
                    InflateError::UnexpectedEof => Reader2Error::Truncated,
                    InflateError::InvalidData | InflateError::TrailingData => Reader2Error::Invalid,
                })?;
                if out.len() != size {
                    return Err(Reader2Error::Invalid);
                }
                Cow::Owned(out)
            }
            Compression::Deflate64 | Compression::Other(_) => return Err(Reader2Error::Unsupported),
        };
        if crc32(&data) != e.crc32 {
            return Err(Reader2Error::CrcMismatch);
        }
        Ok(data)
    }
}
