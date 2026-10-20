// SPDX-License-Identifier: MIT OR Apache-2.0
//! `.xz` container writer: stream header, one or more blocks (block header
//! with compressed/uncompressed sizes and a single LZMA2 filter, LZMA2 data,
//! block padding, check), the index and the stream footer.
//!
//! Spec sources: "The .xz File Format" (Tukaani, public domain), sections
//! 2.1 (stream header/footer), 3.1 (block header and filter flags), 3.3
//! (check), 4 (index) and 5.3.1 (LZMA2 filter properties); the
//! variable-length integer encoding from section 1.2; FIPS 180-4 for SHA-256.

use crate::crc32::crc32;
use crate::crc64_xz::crc64_xz;
use crate::lzma2_encode::{Lzma2EncodeError, encode_lzma2};
use crate::lzma_encode::{LzmaEncodeError, LzmaEncoderOptions, MAX_INPUT};
use crate::xz_stream::CheckId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XzEncodeError {
    /// Invalid LZMA options (including lc + lp > 4), or `block_size == 0`.
    InvalidOptions,
    /// A block would exceed [`MAX_INPUT`] (only with an explicit larger
    /// `block_size`; the default splits automatically).
    InputTooLarge,
    Allocation,
}

impl From<Lzma2EncodeError> for XzEncodeError {
    fn from(e: Lzma2EncodeError) -> Self {
        match e {
            Lzma2EncodeError::InvalidOptions => XzEncodeError::InvalidOptions,
            Lzma2EncodeError::InputTooLarge => XzEncodeError::InputTooLarge,
            Lzma2EncodeError::Allocation => XzEncodeError::Allocation,
        }
    }
}

impl From<LzmaEncodeError> for XzEncodeError {
    fn from(e: LzmaEncodeError) -> Self {
        XzEncodeError::from(Lzma2EncodeError::from(e))
    }
}

/// `.xz` writer options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XzOptions {
    pub lzma: LzmaEncoderOptions,
    pub check: CheckId,
    /// Uncompressed bytes per block. `None` = one block, split only at
    /// [`DEFAULT_MAX_BLOCK`]. Every block is an independent LZMA2 stream.
    pub block_size: Option<usize>,
}

/// Largest block written when `block_size` is `None` (1 GiB).
pub const DEFAULT_MAX_BLOCK: usize = 1 << 30;

impl XzOptions {
    /// xz-like preset 0..=9 with a CRC64 check and a single block.
    pub fn preset(level: u32) -> Result<Self, XzEncodeError> {
        Ok(Self { lzma: LzmaEncoderOptions::preset(level)?, check: CheckId::Crc64, block_size: None })
    }
}

const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
const FOOTER_MAGIC: [u8; 2] = [b'Y', b'Z'];
const FILTER_LZMA2: u64 = 0x21;

/// Append `value` as an xz variable-length integer (7 bits per byte, low
/// first, high bit = continuation). Values above 2^63 - 1 are not valid xz
/// VLIs; callers only pass sizes, which are far below that.
pub fn encode_vli(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn check_id_byte(check: CheckId) -> u8 {
    match check {
        CheckId::None => 0x00,
        CheckId::Crc32 => 0x01,
        CheckId::Crc64 => 0x04,
        CheckId::Sha256 => 0x0A,
    }
}

fn check_bytes(check: CheckId, data: &[u8], out: &mut Vec<u8>) {
    match check {
        CheckId::None => {}
        CheckId::Crc32 => out.extend_from_slice(&crc32(data).to_le_bytes()),
        CheckId::Crc64 => out.extend_from_slice(&crc64_xz(data).to_le_bytes()),
        CheckId::Sha256 => out.extend_from_slice(&crate::hash_sha256::sha256(data)),
    }
}

fn reserve(out: &mut Vec<u8>, extra: usize) -> Result<(), XzEncodeError> {
    out.try_reserve(extra).map_err(|_| XzEncodeError::Allocation)
}

/// Compress `input` into a complete single-stream `.xz` file.
pub fn encode_xz(input: &[u8], opts: &XzOptions) -> Result<Vec<u8>, XzEncodeError> {
    encode_xz_mt(input, opts, 1)
}

/// [`encode_xz`] with the blocks' LZMA2 data encoded on up to `threads`
/// workers ([`crate::mt_pool::map_ordered`]). Blocks are independent, so the
/// output is byte-identical for every thread count; set
/// [`XzOptions::block_size`] to get more than one block.
pub fn encode_xz_mt(input: &[u8], opts: &XzOptions, threads: usize) -> Result<Vec<u8>, XzEncodeError> {
    opts.lzma.validate()?;
    if opts.lzma.lc + opts.lzma.lp > 4 {
        return Err(XzEncodeError::InvalidOptions);
    }
    let block_size = match opts.block_size {
        Some(0) => return Err(XzEncodeError::InvalidOptions),
        Some(n) if n > MAX_INPUT => return Err(XzEncodeError::InputTooLarge),
        Some(n) => n,
        None => DEFAULT_MAX_BLOCK,
    };
    let flags = [0x00, check_id_byte(opts.check)];
    let mut out = Vec::new();
    reserve(&mut out, 64)?;
    out.extend_from_slice(&HEADER_MAGIC);
    out.extend_from_slice(&flags);
    out.extend_from_slice(&crc32(&flags).to_le_bytes());

    // (unpadded size, uncompressed size) per block.
    let mut records: Vec<(u64, u64)> = Vec::new();
    let blocks: Vec<&[u8]> = input.chunks(block_size).collect();
    let encoded = crate::mt_pool::map_ordered(&blocks, threads, Lzma2EncodeError::Allocation, |b| encode_lzma2(b, &opts.lzma))?;
    for (block, (lz, dict_byte)) in blocks.iter().copied().zip(encoded) {
        let mut header = Vec::new();
        reserve(&mut header, 32)?;
        header.push(0); // size byte, patched below
        header.push(0x40 | 0x80); // one filter, both sizes present
        encode_vli(lz.len() as u64, &mut header);
        encode_vli(block.len() as u64, &mut header);
        encode_vli(FILTER_LZMA2, &mut header);
        encode_vli(1, &mut header);
        header.push(dict_byte);
        while header.len() % 4 != 0 {
            header.push(0);
        }
        // header.len() + 4 (CRC32) is a multiple of 4 and <= 1024.
        header[0] = ((header.len() + 4) / 4 - 1) as u8;
        let crc = crc32(&header);
        header.extend_from_slice(&crc.to_le_bytes());

        let check_len = match opts.check {
            CheckId::None => 0,
            CheckId::Crc32 => 4,
            CheckId::Crc64 => 8,
            CheckId::Sha256 => 32,
        };
        reserve(&mut out, header.len() + lz.len() + 3 + check_len)?;
        out.extend_from_slice(&header);
        out.extend_from_slice(&lz);
        while (out.len() - 12) % 4 != 0 {
            out.push(0);
        }
        check_bytes(opts.check, block, &mut out);
        records.try_reserve(1).map_err(|_| XzEncodeError::Allocation)?;
        records.push(((header.len() + lz.len() + check_len) as u64, block.len() as u64));
    }

    // Index.
    let mut index = Vec::new();
    reserve(&mut index, 8 + records.len() * 20)?;
    index.push(0x00);
    encode_vli(records.len() as u64, &mut index);
    for &(unpadded, uncompressed) in &records {
        encode_vli(unpadded, &mut index);
        encode_vli(uncompressed, &mut index);
    }
    while index.len() % 4 != 0 {
        index.push(0);
    }
    let crc = crc32(&index);
    index.extend_from_slice(&crc.to_le_bytes());

    // Footer.
    let backward = ((index.len() / 4) - 1) as u32;
    let mut tail = [0u8; 6];
    tail[..4].copy_from_slice(&backward.to_le_bytes());
    tail[4..].copy_from_slice(&flags);
    reserve(&mut out, index.len() + 12)?;
    out.extend_from_slice(&index);
    out.extend_from_slice(&crc32(&tail).to_le_bytes());
    out.extend_from_slice(&tail);
    out.extend_from_slice(&FOOTER_MAGIC);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vli_encoding() {
        let enc = |v| {
            let mut o = Vec::new();
            encode_vli(v, &mut o);
            o
        };
        assert_eq!(enc(0), [0]);
        assert_eq!(enc(0x7F), [0x7F]);
        assert_eq!(enc(0x80), [0x80, 0x01]);
        assert_eq!(enc(300), [0xAC, 0x02]);
        for v in [0u64, 1, 127, 128, 16383, 16384, 1 << 40, (1 << 63) - 1] {
            assert_eq!(crate::xz_vli::decode_vli(&enc(v)), Ok((v, enc(v).len())));
        }
    }
}
