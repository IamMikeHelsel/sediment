// SPDX-License-Identifier: MIT OR Apache-2.0
//! `.xz` container decoding: one or more concatenated streams, each with a
//! stream header, blocks (block header, LZMA2 data, block padding, check),
//! an index and a stream footer, optionally separated by stream padding.
//!
//! Spec sources: "The .xz File Format" (Tukaani, public domain), sections on
//! stream header/footer, block header and filter flags, the index, stream
//! padding and check types; FIPS 180-4 for SHA-256.
//!
//! Supported: filter chains consisting of exactly one LZMA2 filter; check
//! types None, CRC32, CRC64 and SHA-256. BCJ/delta and other filters return
//! `XzError::Unsupported`.

use crate::lzma2_decode::{Lzma2Error, decode_lzma2_into, dictionary_size_from_byte};
use crate::xz_stream::{self, CheckId, XzStreamError};
use crate::xz_vli::decode_vli;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XzError {
    UnexpectedEof,
    InvalidMagic,
    InvalidHeader,
    InvalidData,
    InvalidIndex,
    InvalidPadding,
    ChecksumMismatch,
    Unsupported,
    LimitExceeded,
    Allocation,
}

impl From<Lzma2Error> for XzError {
    fn from(e: Lzma2Error) -> Self {
        match e {
            Lzma2Error::UnexpectedEof => XzError::UnexpectedEof,
            Lzma2Error::InvalidControl | Lzma2Error::InvalidData => XzError::InvalidData,
            Lzma2Error::InvalidProperties => XzError::InvalidHeader,
            Lzma2Error::LimitExceeded => XzError::LimitExceeded,
            Lzma2Error::Allocation => XzError::Allocation,
        }
    }
}

impl From<XzStreamError> for XzError {
    fn from(e: XzStreamError) -> Self {
        match e {
            XzStreamError::UnexpectedEof => XzError::UnexpectedEof,
            XzStreamError::TrailingData | XzStreamError::FlagsMismatch => XzError::InvalidHeader,
            XzStreamError::InvalidMagic => XzError::InvalidMagic,
            XzStreamError::ChecksumMismatch => XzError::ChecksumMismatch,
            XzStreamError::Unsupported => XzError::Unsupported,
            XzStreamError::LimitExceeded => XzError::LimitExceeded,
        }
    }
}

const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
const FILTER_LZMA2: u64 = 0x21;

/// Decode a complete `.xz` file (single or concatenated streams with stream
/// padding). `max_dictionary` caps the LZMA2 dictionary size declared by any
/// block; `max_output` caps the total decompressed size.
pub fn decode_xz(input: &[u8], max_dictionary: u64, max_output: usize) -> Result<Vec<u8>, XzError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut first = true;
    loop {
        if !first {
            // Stream padding: zero bytes in multiples of four.
            let start = pos;
            while pos < input.len() && input[pos] == 0 {
                pos += 1;
            }
            if !(pos - start).is_multiple_of(4) {
                return Err(XzError::InvalidPadding);
            }
            if pos == input.len() {
                return Ok(out);
            }
        }
        first = false;
        pos += decode_stream(&input[pos..], max_dictionary, &mut out, max_output)?;
    }
}

/// Decode exactly one `.xz` stream starting at `input[0]`, appending to `out`.
/// Returns the number of bytes consumed (through the stream footer).
pub fn decode_xz_stream_into(
    input: &[u8],
    max_dictionary: u64,
    out: &mut Vec<u8>,
    max_output: usize,
) -> Result<usize, XzError> {
    decode_stream(input, max_dictionary, out, max_output)
}

struct Record {
    unpadded: u64,
    uncompressed: u64,
}

fn decode_stream(input: &[u8], max_dict: u64, out: &mut Vec<u8>, max_output: usize) -> Result<usize, XzError> {
    let header = input.get(0..12).ok_or(XzError::UnexpectedEof)?;
    if header[0..6] != HEADER_MAGIC {
        return Err(XzError::InvalidMagic);
    }
    let flags = xz_stream::parse_header(header)?;
    let check = flags.check;
    let check_len = check_size(check);
    let mut pos = 12usize;
    let mut records: Vec<Record> = Vec::new();

    // Blocks.
    loop {
        let first = *input.get(pos).ok_or(XzError::UnexpectedEof)?;
        if first == 0 {
            break; // Index indicator.
        }
        let block_start = pos;
        let header_size = (first as usize + 1) * 4;
        let bh = input.get(pos..pos + header_size).ok_or(XzError::UnexpectedEof)?;
        let info = parse_block_header(bh, max_dict)?;
        pos += header_size;

        let data_start = out.len();
        let used = decode_lzma2_into(&input[pos..], info.dict_size, max_dict, out, max_output)?;
        let compressed = used as u64;
        if let Some(c) = info.compressed
            && c != compressed
        {
            return Err(XzError::InvalidData);
        }
        let produced = (out.len() - data_start) as u64;
        if let Some(u) = info.uncompressed
            && u != produced
        {
            return Err(XzError::InvalidData);
        }
        pos += used;

        // Block padding.
        let unpadded_wo_check = (pos - block_start) as u64;
        let pad = ((4 - (unpadded_wo_check % 4)) % 4) as usize;
        let padding = input.get(pos..pos + pad).ok_or(XzError::UnexpectedEof)?;
        if padding.iter().any(|&b| b != 0) {
            return Err(XzError::InvalidPadding);
        }
        pos += pad;

        let stored = input.get(pos..pos + check_len).ok_or(XzError::UnexpectedEof)?;
        verify_check(check, &out[data_start..], stored)?;
        pos += check_len;

        records.try_reserve(1).map_err(|_| XzError::Allocation)?;
        records.push(Record { unpadded: unpadded_wo_check + check_len as u64, uncompressed: produced });
    }

    // Index.
    let index_start = pos;
    pos += 1;
    let (count, n) = vli(&input[pos..])?;
    pos += n;
    if count != records.len() as u64 {
        return Err(XzError::InvalidIndex);
    }
    for rec in &records {
        let (unpadded, n) = vli(&input[pos..])?;
        pos += n;
        let (uncompressed, n) = vli(&input[pos..])?;
        pos += n;
        if unpadded != rec.unpadded || uncompressed != rec.uncompressed {
            return Err(XzError::InvalidIndex);
        }
    }
    while !(pos - index_start).is_multiple_of(4) {
        let b = *input.get(pos).ok_or(XzError::UnexpectedEof)?;
        if b != 0 {
            return Err(XzError::InvalidIndex);
        }
        pos += 1;
    }
    let crc_bytes = input.get(pos..pos + 4).ok_or(XzError::UnexpectedEof)?;
    let stored_crc = u32::from_le_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
    if crate::crc32::crc32(&input[index_start..pos]) != stored_crc {
        return Err(XzError::ChecksumMismatch);
    }
    pos += 4;
    let index_size = (pos - index_start) as u64;

    // Footer.
    let footer = input.get(pos..pos + 12).ok_or(XzError::UnexpectedEof)?;
    let f = xz_stream::parse_footer(footer, u64::MAX)?;
    if f.flags != flags {
        return Err(XzError::InvalidHeader);
    }
    if f.index_bytes != index_size {
        return Err(XzError::InvalidIndex);
    }
    pos += 12;
    Ok(pos)
}

fn vli(bytes: &[u8]) -> Result<(u64, usize), XzError> {
    decode_vli(bytes).map_err(|e| match e {
        crate::xz_vli::VliError::UnexpectedEof => XzError::UnexpectedEof,
        _ => XzError::InvalidData,
    })
}

struct BlockInfo {
    compressed: Option<u64>,
    uncompressed: Option<u64>,
    dict_size: u32,
}

fn parse_block_header(bh: &[u8], max_dict: u64) -> Result<BlockInfo, XzError> {
    let n = bh.len();
    let stored = u32::from_le_bytes([bh[n - 4], bh[n - 3], bh[n - 2], bh[n - 1]]);
    if crate::crc32::crc32(&bh[..n - 4]) != stored {
        return Err(XzError::ChecksumMismatch);
    }
    let body = &bh[..n - 4];
    let flags = body[1];
    if flags & 0x3C != 0 {
        return Err(XzError::Unsupported);
    }
    let num_filters = (flags & 0x03) as usize + 1;
    let mut p = 2usize;
    let hv = |p: &mut usize| -> Result<u64, XzError> {
        let (v, k) = decode_vli(body.get(*p..).unwrap_or(&[])).map_err(|_| XzError::InvalidHeader)?;
        *p += k;
        Ok(v)
    };
    let compressed = if flags & 0x40 != 0 {
        let v = hv(&mut p)?;
        if v == 0 {
            return Err(XzError::InvalidHeader);
        }
        Some(v)
    } else {
        None
    };
    let uncompressed = if flags & 0x80 != 0 { Some(hv(&mut p)?) } else { None };

    let mut dict_size = None;
    for i in 0..num_filters {
        let id = hv(&mut p)?;
        let props_len = hv(&mut p)?;
        let props_len = usize::try_from(props_len).map_err(|_| XzError::InvalidHeader)?;
        let props = body.get(p..p.checked_add(props_len).ok_or(XzError::InvalidHeader)?).ok_or(XzError::InvalidHeader)?;
        p += props_len;
        if id != FILTER_LZMA2 || i != num_filters - 1 {
            // Delta (0x03), BCJ family (0x04..=0x0B) and anything else.
            return Err(XzError::Unsupported);
        }
        if props_len != 1 {
            return Err(XzError::InvalidHeader);
        }
        let d = dictionary_size_from_byte(props[0]).map_err(|_| XzError::InvalidHeader)?;
        if d as u64 > max_dict {
            return Err(XzError::LimitExceeded);
        }
        dict_size = Some(d);
    }
    if body[p..].iter().any(|&b| b != 0) {
        return Err(XzError::InvalidHeader);
    }
    Ok(BlockInfo { compressed, uncompressed, dict_size: dict_size.ok_or(XzError::InvalidHeader)? })
}

fn check_size(check: CheckId) -> usize {
    match check {
        CheckId::None => 0,
        CheckId::Crc32 => 4,
        CheckId::Crc64 => 8,
        CheckId::Sha256 => 32,
    }
}

fn verify_check(check: CheckId, data: &[u8], stored: &[u8]) -> Result<(), XzError> {
    let ok = match check {
        CheckId::None => true,
        CheckId::Crc32 => crate::crc32::crc32(data).to_le_bytes() == stored,
        CheckId::Crc64 => crate::crc64_xz::crc64_xz(data).to_le_bytes() == stored,
        CheckId::Sha256 => sha256(data) == stored,
    };
    if ok { Ok(()) } else { Err(XzError::ChecksumMismatch) }
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_block(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes(*c);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(y);
    }
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let (blocks, rem) = data.as_chunks::<64>();
    for block in blocks {
        sha256_block(&mut h, block);
    }
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let tail_len = if rem.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_be_bytes());
    for block in tail[..tail_len].as_chunks::<64>().0 {
        sha256_block(&mut h, block);
    }
    let mut outb = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        outb[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    outb
}

#[cfg(test)]
mod tests {
    use super::sha256;

    #[test]
    fn sha256_known_vectors() {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
