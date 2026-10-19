// SPDX-License-Identifier: MIT OR Apache-2.0
//! LHA/LZH archive reader (read-only): header levels 0, 1 and 2, methods
//! `-lh0-` (stored), `-lhd-` (directory) and `-lh4-`..`-lh7-` (static
//! Huffman, see [`crate::lzh_decode`]). Other methods (`-lh1-`, `-lzs-`,
//! `-lz5-`, ...) are listed but `read_lzh_entry` reports `Unsupported`.
//!
//! Spec source: the LHa for UNIX header documentation (header.doc) and the
//! public LZH format notes: level 0/1 headers start with a 1-byte header
//! size and an 8-bit additive checksum; level 2 starts with a 16-bit total
//! header size; extended headers are `[type][data][u16 next size]` chains
//! (0x00 header CRC, 0x01 file name, 0x02 directory name with 0xFF
//! separators, 0x40 MS-DOS attributes, 0x41 Windows timestamps, 0x50 Unix
//! permissions, 0x54 Unix mtime). Member data is checked with CRC-16/ARC.
//! Level-3 headers are rejected as `Unsupported`.
//!
//! Hostile-input posture: every size is bounds-checked against the input,
//! the entry count and per-name length are capped by [`LzhLimits`], header
//! checksums/CRCs are verified, extended-header chains must advance and stay
//! inside their header, and decoding is capped by the caller's output limit.

use crate::crc16_arc::crc16_arc;
use crate::lzh_decode::{LhMethod, LzhDecodeError, decode_lh};
use crate::zip_dos_time::decode_dos;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzhError {
    /// A header or member runs past the end of the input.
    Truncated,
    /// Malformed header structure.
    BadHeader,
    /// Level 0/1 header checksum or level 2 header CRC mismatch.
    BadChecksum,
    /// Unknown header level or compression method.
    Unsupported,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// Decoded data does not match the stored CRC-16.
    CrcMismatch,
    /// The compressed data is malformed.
    InvalidData,
}

impl From<LzhDecodeError> for LzhError {
    fn from(e: LzhDecodeError) -> Self {
        match e {
            LzhDecodeError::Truncated => LzhError::Truncated,
            LzhDecodeError::InvalidData => LzhError::InvalidData,
            LzhDecodeError::LimitExceeded => LzhError::LimitExceeded,
            LzhDecodeError::Allocation => LzhError::Allocation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzhLimits {
    pub max_entries: usize,
    /// Longest accepted path (directory + name) in bytes.
    pub max_name: usize,
    /// How far into the input to look for the first header (self-extracting
    /// archives carry an executable stub first). 0 = header at offset 0 only.
    pub max_scan: usize,
}

impl Default for LzhLimits {
    fn default() -> Self {
        LzhLimits { max_entries: 100_000, max_name: 4096, max_scan: 1 << 20 }
    }
}

/// One member, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzhEntry<'a> {
    /// Method id, e.g. `*b"-lh5-"`.
    pub method: [u8; 5],
    /// Header level (0, 1 or 2).
    pub level: u8,
    /// Path with `/` separators (directory part from 0x02 records or from
    /// `\`/0xFF separators in level 0/1 names). No trailing `/`.
    pub path: Vec<u8>,
    /// Compressed payload.
    pub data: &'a [u8],
    pub original_size: u64,
    pub crc16: u16,
    /// Modification time (Unix seconds); level 0/1 DOS times are taken as UTC.
    pub mtime: Option<i64>,
    /// Unix permission bits (0x50 record or level 0 'U' extension).
    pub unix_mode: Option<u16>,
    /// MS-DOS attribute byte/record.
    pub dos_attr: u16,
    /// Operating-system id from level 1/2 headers (`U`, `M`, `w`, ...).
    pub os_id: Option<u8>,
    /// Offset of the member's header in the input.
    pub header_offset: usize,
}

impl LzhEntry<'_> {
    pub fn is_dir(&self) -> bool {
        &self.method == b"-lhd-"
    }
}

fn le16(b: &[u8], at: usize) -> Result<u16, LzhError> {
    let s = b.get(at..at + 2).ok_or(LzhError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Result<u32, LzhError> {
    let s = b.get(at..at + 4).ok_or(LzhError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// MS-DOS packed date/time (date in the high 16 bits) to Unix seconds, or
/// `None` for an invalid stamp.
pub fn dos_stamp_to_unix(stamp: u32) -> Option<i64> {
    let t = decode_dos((stamp >> 16) as u16, stamp as u16).ok()?;
    let days = days_from_civil(i64::from(t.year), i64::from(t.month), i64::from(t.day));
    Some(days * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second))
}

/// True if `b` starts with something that looks like an LHA header.
pub fn looks_like_lzh(b: &[u8]) -> bool {
    b.len() >= 22
        && b[2] == b'-'
        && b[3] == b'l'
        && (b[4] == b'h' || b[4] == b'z')
        && b[6] == b'-'
        && b[20] <= 3
        && (b[5].is_ascii_alphanumeric())
}

fn push_path_bytes(out: &mut Vec<u8>, src: &[u8]) {
    for &c in src {
        out.push(if c == 0xFF || c == b'\\' { b'/' } else { c });
    }
}

fn normalize_path(mut p: Vec<u8>) -> Vec<u8> {
    while p.last() == Some(&b'/') {
        p.pop();
    }
    p
}

/// Fields collected from an extended-header chain.
#[derive(Default)]
struct Ext<'a> {
    name: Option<&'a [u8]>,
    dir: Option<&'a [u8]>,
    unix_mode: Option<u16>,
    unix_mtime: Option<i64>,
    dos_attr: Option<u16>,
    header_crc: Option<(u16, usize)>,
}

/// Walk an extended-header chain that starts at `at` with size `first`.
/// Returns the position after the chain. `end` bounds the chain.
fn walk_ext<'a>(b: &'a [u8], mut at: usize, first: u16, end: usize, ext: &mut Ext<'a>) -> Result<usize, LzhError> {
    let mut size = usize::from(first);
    let mut guard = 0usize;
    while size != 0 {
        guard += 1;
        if size < 3 || guard > 4096 {
            return Err(LzhError::BadHeader);
        }
        let stop = at.checked_add(size).ok_or(LzhError::BadHeader)?;
        if stop > end {
            return Err(if stop > b.len() { LzhError::Truncated } else { LzhError::BadHeader });
        }
        let rec = &b[at..stop];
        let data = &rec[1..size - 2];
        match rec[0] {
            0x00 if data.len() >= 2 => ext.header_crc = Some((u16::from_le_bytes([data[0], data[1]]), at + 1)),
            0x01 => ext.name = Some(data),
            0x02 => ext.dir = Some(data),
            0x40 if data.len() >= 2 => ext.dos_attr = Some(u16::from_le_bytes([data[0], data[1]])),
            0x41 if data.len() >= 16 => {
                // Windows FILETIMEs: creation, last write, last access.
                let ft = u64::from_le_bytes(data[8..16].try_into().map_err(|_| LzhError::BadHeader)?);
                if ext.unix_mtime.is_none() && ft != 0 {
                    ext.unix_mtime = Some((ft / 10_000_000) as i64 - 11_644_473_600);
                }
            }
            0x50 if data.len() >= 2 => ext.unix_mode = Some(u16::from_le_bytes([data[0], data[1]])),
            0x54 if data.len() >= 4 => {
                ext.unix_mtime = Some(i64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])))
            }
            _ => {}
        }
        size = usize::from(u16::from_le_bytes([rec[size - 2], rec[size - 1]]));
        at = stop;
    }
    Ok(at)
}

struct Parsed<'a> {
    entry: LzhEntry<'a>,
    next: usize,
}

fn build_path(ext: &Ext<'_>, base_name: &[u8], max_name: usize) -> Result<Vec<u8>, LzhError> {
    let name = ext.name.unwrap_or(base_name);
    let dir_len = ext.dir.map_or(0, |d| d.len() + 1);
    if name.len() + dir_len > max_name {
        return Err(LzhError::LimitExceeded);
    }
    let mut p = Vec::new();
    p.try_reserve_exact(name.len() + dir_len).map_err(|_| LzhError::Allocation)?;
    if let Some(d) = ext.dir {
        push_path_bytes(&mut p, d);
        if !p.is_empty() && p.last() != Some(&b'/') && !name.is_empty() {
            p.push(b'/');
        }
    }
    push_path_bytes(&mut p, name);
    Ok(normalize_path(p))
}

fn parse_one<'a>(b: &'a [u8], at: usize, limits: &LzhLimits) -> Result<Parsed<'a>, LzhError> {
    let h = &b[at..];
    if h.len() < 22 {
        return Err(LzhError::Truncated);
    }
    let level = h[20];
    let mut method = [0u8; 5];
    method.copy_from_slice(&h[2..7]);
    if method[0] != b'-' || method[4] != b'-' {
        return Err(LzhError::BadHeader);
    }
    let packed = le32(h, 7)? as usize;
    let original = u64::from(le32(h, 11)?);
    let stamp = le32(h, 15)?;
    let mut ext = Ext::default();
    match level {
        0 | 1 => {
            let hsize = usize::from(h[0]);
            let base_end = hsize + 2;
            if hsize < 22 {
                return Err(LzhError::BadHeader);
            }
            let basic = h.get(..base_end).ok_or(LzhError::Truncated)?;
            let sum = basic[2..].iter().fold(0u8, |a, &x| a.wrapping_add(x));
            if sum != h[1] {
                return Err(LzhError::BadChecksum);
            }
            let attr = basic[19];
            let nlen = usize::from(basic[21]);
            let name_end = 22 + nlen;
            if name_end + 2 > base_end {
                return Err(LzhError::BadHeader);
            }
            let name = &basic[22..name_end];
            let crc = le16(basic, name_end)?;
            let mut unix_mode = None;
            let mut mtime = dos_stamp_to_unix(stamp);
            let mut os_id = None;
            let data_start;
            let data_len;
            if level == 0 {
                // Optional extension: OS id, then for 'U': minor ver, mtime, mode, uid, gid.
                let x = &basic[name_end + 2..];
                if x.len() >= 12 && x[0] == b'U' {
                    os_id = Some(b'U');
                    mtime = Some(i64::from(u32::from_le_bytes([x[2], x[3], x[4], x[5]])));
                    unix_mode = Some(u16::from_le_bytes([x[6], x[7]]));
                }
                data_start = at + base_end;
                data_len = packed;
            } else {
                if name_end + 5 > base_end {
                    return Err(LzhError::BadHeader);
                }
                os_id = Some(basic[name_end + 2]);
                let first = le16(basic, base_end - 2)?;
                let ext_start = at + base_end;
                // Extended headers count toward the "skip size" in level 1.
                let limit = ext_start.checked_add(packed).ok_or(LzhError::BadHeader)?;
                let after = walk_ext(b, ext_start, first, limit.min(b.len()).max(ext_start), &mut ext)?;
                data_start = after;
                data_len = packed - (after - ext_start);
                if let Some(t) = ext.unix_mtime {
                    mtime = Some(t);
                }
                unix_mode = ext.unix_mode;
            }
            let data_end = data_start.checked_add(data_len).ok_or(LzhError::Truncated)?;
            let data = b.get(data_start..data_end).ok_or(LzhError::Truncated)?;
            let path = build_path(&ext, name, limits.max_name)?;
            Ok(Parsed {
                entry: LzhEntry {
                    method,
                    level,
                    path,
                    data,
                    original_size: original,
                    crc16: crc,
                    mtime,
                    unix_mode,
                    dos_attr: ext.dos_attr.unwrap_or(u16::from(attr)),
                    os_id,
                    header_offset: at,
                },
                next: data_end,
            })
        }
        2 => {
            let total = usize::from(le16(h, 0)?);
            if total < 26 {
                return Err(LzhError::BadHeader);
            }
            let hdr = h.get(..total).ok_or(LzhError::Truncated)?;
            let crc = le16(hdr, 21)?;
            let os_id = hdr[23];
            let first = le16(hdr, 24)?;
            let end = walk_ext(b, at + 26, first, at + total, &mut ext)?;
            // LHa may pad a level-2 header by one byte after the chain.
            if end > at + total || at + total - end > 1 {
                return Err(LzhError::BadHeader);
            }
            if let Some((stored, pos)) = ext.header_crc {
                let rel = pos - at;
                let mut c = crc16_arc(&hdr[..rel]);
                c = crate::crc16_arc::crc16_arc_update(c, &[0, 0]);
                c = crate::crc16_arc::crc16_arc_update(c, &hdr[rel + 2..]);
                if c != stored {
                    return Err(LzhError::BadChecksum);
                }
            }
            let data_start = at + total;
            let data_end = data_start.checked_add(packed).ok_or(LzhError::Truncated)?;
            let data = b.get(data_start..data_end).ok_or(LzhError::Truncated)?;
            let path = build_path(&ext, b"", limits.max_name)?;
            Ok(Parsed {
                entry: LzhEntry {
                    method,
                    level,
                    path,
                    data,
                    original_size: original,
                    crc16: crc,
                    mtime: ext.unix_mtime.or(Some(i64::from(stamp))),
                    unix_mode: ext.unix_mode,
                    dos_attr: ext.dos_attr.unwrap_or(0),
                    os_id: Some(os_id),
                    header_offset: at,
                },
                next: data_end,
            })
        }
        3 => Err(LzhError::Unsupported),
        _ => Err(LzhError::BadHeader),
    }
}

/// Find the first plausible header at or after offset 0 (within
/// `limits.max_scan`), checking that it parses.
fn find_start(b: &[u8], limits: &LzhLimits) -> Result<usize, LzhError> {
    if looks_like_lzh(b) {
        return Ok(0);
    }
    let end = b.len().min(limits.max_scan);
    for at in 1..end {
        if looks_like_lzh(&b[at..]) && parse_one(b, at, limits).is_ok() {
            return Ok(at);
        }
    }
    Err(LzhError::BadHeader)
}

/// List all members of an LHA archive.
pub fn parse_lzh<'a>(bytes: &'a [u8], limits: LzhLimits) -> Result<Vec<LzhEntry<'a>>, LzhError> {
    let mut at = find_start(bytes, &limits)?;
    let mut out = Vec::new();
    loop {
        // End of archive: a zero header-size byte, or the end of the input.
        match bytes.get(at) {
            None | Some(0) => break,
            _ => {}
        }
        if out.len() >= limits.max_entries {
            return Err(LzhError::LimitExceeded);
        }
        let p = parse_one(bytes, at, &limits)?;
        out.try_reserve(1).map_err(|_| LzhError::Allocation)?;
        out.push(p.entry);
        at = p.next;
    }
    Ok(out)
}

/// Decode a member's data, refusing output larger than `max_output`, and
/// verify its CRC-16. Directories decode to an empty Vec.
pub fn read_lzh_entry(entry: &LzhEntry<'_>, max_output: usize) -> Result<Vec<u8>, LzhError> {
    let size = usize::try_from(entry.original_size).map_err(|_| LzhError::LimitExceeded)?;
    if size > max_output {
        return Err(LzhError::LimitExceeded);
    }
    let out = match &entry.method {
        b"-lhd-" => return Ok(Vec::new()),
        b"-lh0-" | b"-lz4-" => {
            if entry.data.len() != size {
                return Err(LzhError::InvalidData);
            }
            let mut v = Vec::new();
            v.try_reserve_exact(size).map_err(|_| LzhError::Allocation)?;
            v.extend_from_slice(entry.data);
            v
        }
        m => match LhMethod::from_id(m) {
            Some(lh) => decode_lh(entry.data, lh, size, max_output)?,
            None => return Err(LzhError::Unsupported),
        },
    };
    if crc16_arc(&out) != entry.crc16 {
        return Err(LzhError::CrcMismatch);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_stamp() {
        // 2020-05-17 13:45:30
        let stamp = (40u32 << 25) | (5 << 21) | (17 << 16) | (13 << 11) | (45 << 5) | 15;
        assert_eq!(dos_stamp_to_unix(stamp), Some(1_589_723_130));
        assert_eq!(dos_stamp_to_unix(0), None);
    }

    #[test]
    fn path_building() {
        let ext = Ext { dir: Some(b"a\xffb\xff"), ..Ext::default() };
        assert_eq!(build_path(&ext, b"c.txt", 100).unwrap(), b"a/b/c.txt");
        let ext = Ext::default();
        assert_eq!(build_path(&ext, b"x\\y\\", 100).unwrap(), b"x/y");
        assert_eq!(build_path(&ext, b"long", 3), Err(LzhError::LimitExceeded));
    }
}
