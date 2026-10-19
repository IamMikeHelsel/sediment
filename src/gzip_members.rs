// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multi-member gzip decoding.
//!
//! RFC 1952 section 2.2: "A gzip file consists of a series of members
//! (compressed data sets)". `gzip_wrapper::decode_gzip` handles exactly one
//! member; this module walks every member in turn (header, raw DEFLATE
//! data, CRC-32 and ISIZE trailer) and concatenates their output, as
//! `gzip -d` and 7-Zip do for concatenated `.gz` files.
//!
//! Spec source: RFC 1952 sections 2.2 and 2.3 (member layout, FLG bits
//! FTEXT/FHCRC/FEXTRA/FNAME/FCOMMENT, reserved bits must be zero, CRC16 of
//! the header, CRC32 and ISIZE = length mod 2^32 of the member's data).
//!
//! Hostile input: every field is bounds-checked; output across all members
//! is capped by `max_output`; the DEFLATE block count per member by
//! `max_blocks`; header strings by [`MAX_HEADER_STRING`]; the member count
//! by [`MAX_MEMBERS`]. Bytes after the last member that do not start
//! another member are `TrailingData`.

use crate::crc32::crc32;
use crate::gzip_wrapper::GzipError;
use crate::inflate::{InflateError, inflate_raw_prefix};

/// Longest FNAME/FCOMMENT accepted (bytes, without the terminating NUL).
pub const MAX_HEADER_STRING: usize = 65_535;
/// Most members accepted in one file.
pub const MAX_MEMBERS: usize = 1 << 16;

/// Parse one member header at the start of `b`; returns its length.
pub fn member_header_len(b: &[u8]) -> Result<usize, GzipError> {
    if b.len() < 10 {
        return Err(GzipError::UnexpectedEof);
    }
    if b[0] != 0x1f || b[1] != 0x8b {
        return Err(GzipError::InvalidHeader);
    }
    if b[2] != 8 {
        return Err(GzipError::UnsupportedMethod);
    }
    let flg = b[3];
    if flg & 0xe0 != 0 {
        return Err(GzipError::InvalidHeader);
    }
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        let x = b.get(pos..pos + 2).ok_or(GzipError::UnexpectedEof)?;
        let xlen = usize::from(u16::from_le_bytes([x[0], x[1]]));
        pos += 2 + xlen;
        if pos > b.len() {
            return Err(GzipError::UnexpectedEof);
        }
    }
    for bit in [0x08u8, 0x10] {
        if flg & bit != 0 {
            let rest = &b[pos..];
            let limit = rest.len().min(MAX_HEADER_STRING + 1);
            match rest[..limit].iter().position(|&c| c == 0) {
                Some(n) => pos += n + 1,
                None if rest.len() > MAX_HEADER_STRING => return Err(GzipError::LimitExceeded),
                None => return Err(GzipError::UnexpectedEof),
            }
        }
    }
    if flg & 0x02 != 0 {
        let c = b.get(pos..pos + 2).ok_or(GzipError::UnexpectedEof)?;
        let stored = u16::from_le_bytes([c[0], c[1]]);
        if (crc32(&b[..pos]) & 0xffff) as u16 != stored {
            return Err(GzipError::ChecksumMismatch);
        }
        pos += 2;
    }
    Ok(pos)
}

fn map_inflate(e: InflateError) -> GzipError {
    match e {
        InflateError::UnexpectedEof => GzipError::UnexpectedEof,
        InflateError::InvalidData | InflateError::UnsupportedBlock | InflateError::TrailingData => GzipError::InvalidData,
        InflateError::LimitExceeded => GzipError::LimitExceeded,
        InflateError::Allocation => GzipError::Allocation,
    }
}

/// Decode a gzip file of one or more members. Returns the concatenated
/// output and the number of members.
pub fn decode_gzip_members(input: &[u8], max_output: usize, max_blocks: usize) -> Result<(Vec<u8>, usize), GzipError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut members = 0usize;
    loop {
        let rest = &input[pos..];
        if members > 0 && (rest.is_empty()) {
            return Ok((out, members));
        }
        if members > 0 && !rest.starts_with(&[0x1f, 0x8b]) {
            return Err(GzipError::TrailingData);
        }
        if members == MAX_MEMBERS {
            return Err(GzipError::LimitExceeded);
        }
        let h = member_header_len(rest)?;
        let room = max_output - out.len();
        let (data, used) = inflate_raw_prefix(&rest[h..], room, max_blocks).map_err(map_inflate)?;
        let t = h + used;
        let trailer = rest.get(t..t + 8).ok_or(GzipError::UnexpectedEof)?;
        let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        if crc32(&data) != crc {
            return Err(GzipError::ChecksumMismatch);
        }
        if data.len() as u32 != isize {
            return Err(GzipError::SizeMismatch);
        }
        if out.is_empty() {
            out = data;
        } else {
            out.try_reserve(data.len()).map_err(|_| GzipError::Allocation)?;
            out.extend_from_slice(&data);
        }
        members += 1;
        pos += t + 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // "hi\n" compressed with a fixed-Huffman block, no FNAME, mtime 0.
    fn member(fname: Option<&[u8]>) -> Vec<u8> {
        let mut m = vec![0x1f, 0x8b, 8, if fname.is_some() { 0x08 } else { 0 }, 0, 0, 0, 0, 0, 3];
        if let Some(n) = fname {
            m.extend_from_slice(n);
            m.push(0);
        }
        // Stored block: BFINAL=1, BTYPE=00, LEN=3, NLEN=!3, "hi\n".
        m.extend_from_slice(&[0x01, 3, 0, 0xfc, 0xff, b'h', b'i', b'\n']);
        m.extend_from_slice(&crc32(b"hi\n").to_le_bytes());
        m.extend_from_slice(&3u32.to_le_bytes());
        m
    }

    #[test]
    fn one_and_many_members() {
        assert_eq!(decode_gzip_members(&member(None), 100, 10), Ok((b"hi\n".to_vec(), 1)));
        let mut two = member(Some(b"a"));
        two.extend_from_slice(&member(None));
        assert_eq!(decode_gzip_members(&two, 100, 10), Ok((b"hi\nhi\n".to_vec(), 2)));
        assert_eq!(decode_gzip_members(&two, 5, 10), Err(GzipError::LimitExceeded));
    }

    #[test]
    fn malformed() {
        let m = member(None);
        for n in 0..m.len() {
            assert!(decode_gzip_members(&m[..n], 100, 10).is_err(), "prefix {n}");
        }
        let mut t = m.clone();
        t.push(0);
        assert_eq!(decode_gzip_members(&t, 100, 10), Err(GzipError::TrailingData));
        let mut c = m.clone();
        let l = c.len();
        c[l - 8] ^= 1;
        assert_eq!(decode_gzip_members(&c, 100, 10), Err(GzipError::ChecksumMismatch));
        let mut s = m.clone();
        s[l - 4] ^= 1;
        assert_eq!(decode_gzip_members(&s, 100, 10), Err(GzipError::SizeMismatch));
        let mut r = m;
        r[3] = 0x20;
        assert_eq!(decode_gzip_members(&r, 100, 10), Err(GzipError::InvalidHeader));
    }
}
