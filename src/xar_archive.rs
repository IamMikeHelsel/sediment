// SPDX-License-Identifier: MIT OR Apache-2.0
//! xar archives (eXtensible ARchiver; macOS `.xar`, `.pkg` flat packages)
//! as an [`ArchiveReader`].
//!
//! Spec sources: the xar file format description (xar project wiki
//! "xarformat"; `xar.h` header layout as documented there) and W3C XML 1.0
//! for the table of contents. Layout (big-endian):
//! - Header: magic `xar!`, header size u16 (>= 28), version u16 (1), TOC
//!   compressed length u64, TOC uncompressed length u64, checksum algorithm
//!   u32 (0 none, 1 SHA-1, 2 MD5, 3 "other", 4 SHA-512). For 3 the libxar
//!   layout puts a NUL-terminated algorithm name such as `sha256` inside a
//!   longer header; Apple's `xar --toc-cksum=sha256` instead writes a bare
//!   28-byte header and names the algorithm only in the TOC
//!   `<checksum style="sha256">` (SHA-256 when absent). Both are read.
//! - TOC: zlib-compressed XML right after the header. The heap starts after
//!   the compressed TOC. `<toc><checksum style=..><offset/><size/>` locates
//!   the digest of the compressed TOC in the heap; it is verified.
//! - `<file id=..>` elements (nested for directories) carry `<name>`
//!   (optionally `enctype="base64"`), `<type>` (file, directory, symlink,
//!   hardlink; others are skipped), `<mode>` (octal), `<mtime>` (ISO 8601
//!   UTC), `<link>` (symlink target) and `<data>` with `<offset>` (heap
//!   relative), `<length>` (stored), `<size>` (extracted), `<encoding
//!   style=..>` and `<archived-checksum>` / `<extracted-checksum>`.
//! - Hard links: the first link has `<type link="original">hardlink</type>`
//!   and the data; the others have `link="<id of original>"`.
//! - Encodings: `application/octet-stream`, `application/x-gzip` (a zlib
//!   stream; a gzip stream is also accepted), `application/x-bzip2`,
//!   `application/x-xz`, `application/x-lzma` (LZMA-alone). Others are
//!   `Unsupported` at read time.
//!
//! Member data is decoded and both checksums are verified in
//! [`ArchiveReader::read`]; mismatches are `CrcMismatch`.

use std::collections::HashMap;

use crate::archive_open::decompress;
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::cpio_archive::{MAX_LINK_TARGET, copy_vec};
use crate::extract_plan::{EntryKind, PlannedEntry};
use crate::hash_md5::md5;
use crate::hash_sha1::sha1;
use crate::hash_sha256::sha256;
use crate::hash_sha512::sha512;
use crate::lzma_decode::decode_lzma_alone;
use crate::xml_mini::{XmlDoc, XmlError, XmlLimits, parse_xml};
use crate::zlib_wrapper::{ZlibError, decode_zlib};

pub const XAR_MAGIC: &[u8; 4] = b"xar!";
const MIN_HEADER: usize = 28;
/// Largest uncompressed TOC accepted.
pub const MAX_TOC: u64 = 64 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XarError {
    Truncated,
    BadMagic,
    BadHeader,
    BadToc,
    TocChecksum,
    LimitExceeded,
    Allocation,
    Unsupported,
}

impl From<XarError> for ReaderError {
    fn from(e: XarError) -> Self {
        match e {
            XarError::Truncated => ReaderError::Truncated,
            XarError::TocChecksum => ReaderError::CrcMismatch,
            XarError::LimitExceeded => ReaderError::LimitExceeded,
            XarError::Allocation => ReaderError::Allocation,
            XarError::Unsupported => ReaderError::Unsupported,
            XarError::BadMagic | XarError::BadHeader | XarError::BadToc => ReaderError::Invalid,
        }
    }
}

impl From<XmlError> for XarError {
    fn from(e: XmlError) -> Self {
        match e {
            XmlError::LimitExceeded => XarError::LimitExceeded,
            XmlError::Allocation => XarError::Allocation,
            _ => XarError::BadToc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XarHash {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl XarHash {
    fn from_style(s: &str) -> Option<XarHash> {
        match s.to_ascii_lowercase().as_str() {
            "md5" => Some(XarHash::Md5),
            "sha1" | "sha-1" => Some(XarHash::Sha1),
            "sha256" | "sha-256" => Some(XarHash::Sha256),
            "sha512" | "sha-512" => Some(XarHash::Sha512),
            _ => None,
        }
    }
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            XarHash::Md5 => md5(data).to_vec(),
            XarHash::Sha1 => sha1(data).to_vec(),
            XarHash::Sha256 => sha256(data).to_vec(),
            XarHash::Sha512 => sha512(data).to_vec(),
        }
    }
}

/// Fixed header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarHeader {
    pub header_size: u16,
    pub version: u16,
    pub toc_compressed: u64,
    pub toc_uncompressed: u64,
    pub checksum_alg: u32,
    /// Algorithm name for `checksum_alg == 3` (empty when the header is the
    /// bare 28 bytes Apple's xar writes; the TOC then names the algorithm).
    pub checksum_name: Option<String>,
}

pub fn parse_header(b: &[u8]) -> Result<XarHeader, XarError> {
    if b.len() < MIN_HEADER {
        return Err(if b.len() >= 4 && &b[..4] != XAR_MAGIC { XarError::BadMagic } else { XarError::Truncated });
    }
    if &b[..4] != XAR_MAGIC {
        return Err(XarError::BadMagic);
    }
    let header_size = u16::from_be_bytes([b[4], b[5]]);
    let version = u16::from_be_bytes([b[6], b[7]]);
    let u64_at = |i: usize| u64::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7]]);
    let toc_compressed = u64_at(8);
    let toc_uncompressed = u64_at(16);
    let checksum_alg = u32::from_be_bytes([b[24], b[25], b[26], b[27]]);
    if usize::from(header_size) < MIN_HEADER || version != 1 {
        return Err(XarError::BadHeader);
    }
    let hs = usize::from(header_size);
    if b.len() < hs {
        return Err(XarError::Truncated);
    }
    let checksum_name = if checksum_alg == 3 {
        let raw = &b[MIN_HEADER..hs];
        let n = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        Some(std::str::from_utf8(&raw[..n]).map_err(|_| XarError::BadHeader)?.to_owned())
    } else {
        None
    };
    Ok(XarHeader { header_size, version, toc_compressed, toc_uncompressed, checksum_alg, checksum_name })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Raw,
    Zlib,
    Bzip2,
    Xz,
    Lzma,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DataRef {
    offset: u64,
    length: u64,
    size: u64,
    encoding: Encoding,
    archived: Option<(XarHash, Vec<u8>)>,
    extracted: Option<(XarHash, Vec<u8>)>,
}

/// Seam: tiny RFC 4648 base64 decoder for `enctype="base64"` names (the
/// forge `base64_codec` module replaces it once harvested).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        if c == b'=' {
            break;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.chunks_exact(2)
        .map(|c| Some(((c[0] as char).to_digit(16)? * 16 + (c[1] as char).to_digit(16)?) as u8))
        .collect()
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DDTHH:MM:SS` (fraction and `Z` ignored) to Unix seconds.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let b = s.trim().as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = &b[r];
        if !t.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(t).ok()?.parse().ok()
    };
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

fn num(doc: &XmlDoc, node: usize, name: &str) -> Result<Option<u64>, XarError> {
    match doc.child_text(node, name) {
        None => Ok(None),
        Some(t) => t.trim().parse::<u64>().map(Some).map_err(|_| XarError::BadToc),
    }
}

fn checksum(doc: &XmlDoc, node: usize, name: &str) -> Result<Option<(XarHash, Vec<u8>)>, XarError> {
    let Some(c) = doc.child(node, name) else { return Ok(None) };
    let n = doc.node(c);
    let Some(h) = n.attr("style").and_then(XarHash::from_style) else { return Ok(None) };
    let d = unhex(&n.text).ok_or(XarError::BadToc)?;
    Ok(Some((h, d)))
}

fn data_ref(doc: &XmlDoc, file: usize) -> Result<Option<DataRef>, XarError> {
    let Some(d) = doc.child(file, "data") else { return Ok(None) };
    let offset = num(doc, d, "offset")?.ok_or(XarError::BadToc)?;
    let length = num(doc, d, "length")?.ok_or(XarError::BadToc)?;
    let size = num(doc, d, "size")?.unwrap_or(length);
    let style = doc.child(d, "encoding").and_then(|e| doc.node(e).attr("style")).unwrap_or("application/octet-stream");
    let encoding = match style {
        "application/octet-stream" => Encoding::Raw,
        "application/x-gzip" | "application/x-zlib" => Encoding::Zlib,
        "application/x-bzip2" => Encoding::Bzip2,
        "application/x-xz" => Encoding::Xz,
        "application/x-lzma" => Encoding::Lzma,
        _ => Encoding::Other,
    };
    Ok(Some(DataRef {
        offset,
        length,
        size,
        encoding,
        archived: checksum(doc, d, "archived-checksum")?,
        extracted: checksum(doc, d, "extracted-checksum")?,
    }))
}

/// One `<file>` element in document (pre-)order.
struct Item {
    id: Option<String>,
    path: Vec<u8>,
    kind: String,
    link_attr: Option<String>,
    link: Option<String>,
    mode: Option<u32>,
    mtime: Option<i64>,
    data: Option<DataRef>,
}

fn collect(doc: &XmlDoc, parent: usize, prefix: &[u8], depth: usize, out: &mut Vec<Item>, max: usize) -> Result<(), XarError> {
    if depth > 256 {
        return Err(XarError::LimitExceeded);
    }
    for f in doc.children_named(parent, "file") {
        if out.len() >= max {
            return Err(XarError::LimitExceeded);
        }
        let name_node = doc.child(f, "name").ok_or(XarError::BadToc)?;
        let nn = doc.node(name_node);
        let name: Vec<u8> = if nn.attr("enctype") == Some("base64") {
            base64_decode(&nn.text).ok_or(XarError::BadToc)?
        } else {
            nn.text.as_bytes().to_vec()
        };
        if name.is_empty() || name.contains(&0) {
            return Err(XarError::BadToc);
        }
        let mut path = Vec::new();
        path.try_reserve_exact(prefix.len() + 1 + name.len()).map_err(|_| XarError::Allocation)?;
        if !prefix.is_empty() {
            path.extend_from_slice(prefix);
            path.push(b'/');
        }
        path.extend_from_slice(&name);
        let type_node = doc.child(f, "type");
        let kind = type_node.map_or("file", |t| doc.node(t).text.trim()).to_owned();
        let link_attr = type_node.and_then(|t| doc.node(t).attr("link")).map(str::to_owned);
        let mode = match doc.child_text(f, "mode") {
            Some(m) => Some(u32::from_str_radix(m.trim(), 8).map_err(|_| XarError::BadToc)? & 0o7777),
            None => None,
        };
        let mtime = doc.child_text(f, "mtime").and_then(parse_iso8601);
        let item = Item {
            id: doc.node(f).attr("id").map(str::to_owned),
            path: path.clone(),
            kind,
            link_attr,
            link: doc.child_text(f, "link").map(str::to_owned),
            mode,
            mtime,
            data: data_ref(doc, f)?,
        };
        out.try_reserve(1).map_err(|_| XarError::Allocation)?;
        out.push(item);
        collect(doc, f, &path, depth + 1, out, max)?;
    }
    Ok(())
}

/// xar archive reader.
pub struct XarReader<'a> {
    heap: &'a [u8],
    header: XarHeader,
    entries: Vec<PlannedEntry>,
    data: Vec<Option<DataRef>>,
    max_entry_size: u64,
}

impl<'a> XarReader<'a> {
    pub fn new(bytes: &'a [u8], limits: ReaderLimits) -> Result<Self, ReaderError> {
        let header = parse_header(bytes)?;
        if header.toc_uncompressed > MAX_TOC {
            return Err(ReaderError::LimitExceeded);
        }
        let hs = usize::from(header.header_size);
        let toc_end = u64::try_from(hs)
            .ok()
            .and_then(|h| h.checked_add(header.toc_compressed))
            .filter(|&e| e <= bytes.len() as u64)
            .ok_or(ReaderError::Truncated)? as usize;
        let toc_raw = &bytes[hs..toc_end];
        let heap = &bytes[toc_end..];
        let tu = header.toc_uncompressed as usize;
        let toc = decode_zlib(toc_raw, tu, toc_raw.len().saturating_mul(8) / 3 + 16).map_err(|e| match e {
            ZlibError::LimitExceeded => ReaderError::LimitExceeded,
            ZlibError::Allocation => ReaderError::Allocation,
            ZlibError::ChecksumMismatch => ReaderError::CrcMismatch,
            ZlibError::UnexpectedEof => ReaderError::Truncated,
            _ => ReaderError::Invalid,
        })?;
        if toc.len() != tu {
            return Err(ReaderError::Invalid);
        }
        let doc = parse_xml(&toc, &XmlLimits { max_input: tu, ..XmlLimits::default() }).map_err(XarError::from)?;
        if doc.root().name != "xar" {
            return Err(XarError::BadToc.into());
        }
        let toc_node = doc.child(0, "toc").ok_or(XarError::BadToc)?;
        // TOC checksum. Header ids: 0 none, 1 SHA-1, 2 MD5, 3 "other" and 4
        // SHA-512. For 3, the original libxar layout carries the algorithm
        // name after the 28 fixed bytes (header_size > 28); Apple's xar
        // (`--toc-cksum=sha256`) writes a bare 28-byte header and records the
        // algorithm only in the TOC's `<checksum style=...>`, defaulting to
        // SHA-256. Apple writes id 4 for `--toc-cksum=sha512`.
        let toc_cksum = doc.child(toc_node, "checksum");
        let alg = match (header.checksum_alg, header.checksum_name.as_deref()) {
            (0, _) => None,
            (1, _) => Some(XarHash::Sha1),
            (2, _) => Some(XarHash::Md5),
            (3, Some(n)) if !n.is_empty() => Some(XarHash::from_style(n).ok_or(ReaderError::Unsupported)?),
            (3, _) => match toc_cksum.and_then(|c| doc.node(c).attr("style")) {
                None => Some(XarHash::Sha256),
                Some(st) => match XarHash::from_style(st) {
                    Some(h @ (XarHash::Sha256 | XarHash::Sha512)) => Some(h),
                    _ => return Err(ReaderError::Unsupported),
                },
            },
            (4, _) => Some(XarHash::Sha512),
            _ => return Err(ReaderError::Unsupported),
        };
        if let (Some(alg), Some(c)) = (alg, toc_cksum) {
            let off = num(&doc, c, "offset")?.ok_or(XarError::BadToc)?;
            let size = num(&doc, c, "size")?.ok_or(XarError::BadToc)?;
            let stored = off
                .checked_add(size)
                .filter(|&e| e <= heap.len() as u64)
                .map(|e| &heap[off as usize..e as usize])
                .ok_or(ReaderError::Truncated)?;
            if stored != alg.digest(toc_raw).as_slice() {
                return Err(ReaderError::CrcMismatch);
            }
        }
        let mut items = Vec::new();
        collect(&doc, toc_node, b"", 0, &mut items, limits.max_entries)?;
        // Hard-link originals by id.
        let by_id: HashMap<&str, usize> =
            items.iter().enumerate().filter_map(|(i, it)| it.id.as_deref().map(|id| (id, i))).collect();
        let mut emitted: HashMap<usize, usize> = HashMap::new();
        let mut entries = Vec::new();
        let mut data = Vec::new();
        let mut total: u64 = 0;
        for (i, it) in items.iter().enumerate() {
            let size_of = |d: &Option<DataRef>| d.as_ref().map_or(0, |d| d.size);
            let (kind, dref, size) = match it.kind.as_str() {
                "directory" => (EntryKind::Dir, None, 0),
                "symlink" => {
                    let t = it.link.as_deref().ok_or(XarError::BadToc)?;
                    if t.len() > MAX_LINK_TARGET {
                        return Err(ReaderError::LimitExceeded);
                    }
                    (EntryKind::Symlink { target: t.as_bytes().to_vec() }, None, 0)
                }
                "file" => (EntryKind::File, it.data.clone(), size_of(&it.data)),
                "hardlink" => match it.link_attr.as_deref() {
                    None | Some("original") => (EntryKind::File, it.data.clone(), size_of(&it.data)),
                    Some(id) => {
                        let &o = by_id.get(id).ok_or(XarError::BadToc)?;
                        let src = &items[o];
                        if o == i {
                            (EntryKind::File, it.data.clone(), size_of(&it.data))
                        } else if emitted.contains_key(&o) {
                            (EntryKind::Hardlink { target: src.path.clone() }, None, size_of(&src.data))
                        } else {
                            // Original comes later: materialize the data here.
                            (EntryKind::File, src.data.clone(), size_of(&src.data))
                        }
                    }
                },
                _ => continue,
            };
            if matches!(kind, EntryKind::File) {
                total = total.checked_add(size).ok_or(ReaderError::LimitExceeded)?;
                if total > limits.max_total_size {
                    return Err(ReaderError::LimitExceeded);
                }
                emitted.entry(i).or_insert(entries.len());
            }
            entries.try_reserve(1).map_err(|_| ReaderError::Allocation)?;
            entries.push(PlannedEntry { path: it.path.clone(), kind, size, mode: it.mode, mtime: it.mtime });
            data.push(dref);
        }
        Ok(XarReader { heap, header, entries, data, max_entry_size: limits.max_entry_size })
    }

    pub fn header(&self) -> &XarHeader {
        &self.header
    }
}

fn verify(c: &Option<(XarHash, Vec<u8>)>, data: &[u8]) -> Result<(), ReaderError> {
    match c {
        Some((h, d)) if h.digest(data) != *d => Err(ReaderError::CrcMismatch),
        _ => Ok(()),
    }
}

impl ArchiveReader for XarReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Xar
    }
    fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
    fn read(&self, index: usize) -> Result<Vec<u8>, ReaderError> {
        let d = self.data.get(index).ok_or(ReaderError::OutOfRange)?;
        let Some(d) = d else { return Ok(Vec::new()) };
        if d.size > self.max_entry_size {
            return Err(ReaderError::LimitExceeded);
        }
        let end = d.offset.checked_add(d.length).filter(|&e| e <= self.heap.len() as u64).ok_or(ReaderError::Truncated)?;
        let raw = &self.heap[d.offset as usize..end as usize];
        verify(&d.archived, raw)?;
        let size = d.size as usize;
        let out = match d.encoding {
            Encoding::Raw => copy_vec(raw)?,
            Encoding::Zlib if raw.starts_with(&[0x1f, 0x8b]) => decompress(ArchiveFormat::Gzip, raw, size)?,
            Encoding::Zlib => decode_zlib(raw, size, raw.len().saturating_mul(8) / 3 + 16).map_err(|e| match e {
                ZlibError::LimitExceeded => ReaderError::LimitExceeded,
                ZlibError::Allocation => ReaderError::Allocation,
                ZlibError::ChecksumMismatch => ReaderError::CrcMismatch,
                ZlibError::UnexpectedEof => ReaderError::Truncated,
                _ => ReaderError::Invalid,
            })?,
            Encoding::Bzip2 => decompress(ArchiveFormat::Bzip2, raw, size)?,
            Encoding::Xz => decompress(ArchiveFormat::Xz, raw, size)?,
            Encoding::Lzma => decode_lzma_alone(raw, 1 << 32, size).map_err(|_| ReaderError::Invalid)?,
            Encoding::Other => return Err(ReaderError::Unsupported),
        };
        if out.len() != size {
            return Err(ReaderError::Invalid);
        }
        verify(&d.extracted, &out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601("2024-03-05T06:07:08Z"), Some(1_709_618_828));
        assert_eq!(parse_iso8601("2024-13-05T06:07:08Z"), None);
        assert_eq!(parse_iso8601("bad"), None);
        assert_eq!(base64_decode("aGk=").as_deref(), Some(&b"hi"[..]));
        assert_eq!(unhex("0aff").as_deref(), Some(&[10u8, 255][..]));
        assert!(parse_header(b"xar!").is_err());
    }
}
