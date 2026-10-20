// SPDX-License-Identifier: MIT OR Apache-2.0

/// Bzip2 block/EOS magic bit-scan: locate block boundaries without decoding,
/// for `-slt` block counts, parallel decode and recovery (like `bzip2recover`).
///
/// Bits are read MSB-first: absolute bit `p` is
/// `(data[p / 8] >> (7 - p % 8)) & 1`.

/// Errors returned by the block scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bz2ScanError {
    /// Not enough bytes left in the buffer.
    Truncated,
    /// Header / magic bytes don't match.
    BadHeader,
    /// No end-of-stream magic was found before data ended.
    MissingEndOfStream,
    /// `max_blocks` limit was reached before EOF.
    LimitExceeded,
    /// Could not allocate enough memory.
    Allocation,
}

/// One bzip2 block within a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bz2Block {
    /// First bit of the block magic (absolute from bit 0 of `data`).
    pub bit_offset: u64,
    /// The 32-bit CRC stored after the block magic.
    pub stored_crc: u32,
}

/// A single bzip2 stream found within `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bz2Stream {
    /// Byte offset of the `"BZh"` header.
    pub byte_offset: usize,
    /// Compression level byte (`1`..=`9`).
    pub level: u8,
    /// Block descriptors, in order.
    pub blocks: Vec<Bz2Block>,
    /// First bit of the end-of-stream magic.
    pub eos_bit_offset: u64,
    /// The 32-bit combined CRC stored after the EOS magic.
    pub stored_combined_crc: u32,
    /// Combined CRC computed from the blocks' stored CRCs.
    pub computed_combined_crc: u32,
    /// `ceil((eos_bit_offset + 80) / 8)`: first byte after the padded stream.
    pub end_byte: usize,
}

const BLOCK_MAGIC: u64 = 0x314159265359; // 48 bits
const EOS_MAGIC: u64 = 0x177245385090;   // 48 bits

/// Read a 48-bit value at the given absolute bit offset (MSB-first).
/// Returns `None` if we don't have enough bytes.
fn read_48(data: &[u8], bit_offset: u64) -> Option<u64> {
    let byte_off = (bit_offset / 8) as usize;
    let bit_rem = (bit_offset % 8) as u32;
    if byte_off + 6 > data.len() {
        return None;
    }
    let mut val: u64 = 0;
    for i in 0..48 {
        let bit = (data[byte_off + (i + bit_rem) as usize / 8]
            >> (7 - ((i + bit_rem) as u32 % 8)))
            & 1;
        val = (val << 1) | (bit as u64);
    }
    Some(val)
}

/// Read a 32-bit value at the given absolute bit offset (MSB-first).
/// Returns `None` if we don't have enough bytes.
fn read_32(data: &[u8], bit_offset: u64) -> Option<u32> {
    let byte_off = (bit_offset / 8) as usize;
    let bit_rem = (bit_offset % 8) as u32;
    if byte_off + 4 > data.len() {
        return None;
    }
    let mut val: u32 = 0;
    for i in 0..32 {
        let bit = (data[byte_off + (i + bit_rem) as usize / 8]
            >> (7 - ((i + bit_rem) as u32 % 8)))
            & 1;
        val = (val << 1) | (bit as u32);
    }
    Some(val)
}

/// Compute the combined CRC from block stored CRCs.
fn compute_combined_crc(blocks: &[Bz2Block]) -> u32 {
    let mut c: u32 = 0;
    for block in blocks {
        c = c.rotate_left(1) ^ block.stored_crc;
    }
    c
}

/// Scan a single bzip2 stream starting at `byte_offset`.
///
/// `max_blocks` limits the number of blocks scanned.
pub fn scan_stream(
    data: &[u8],
    byte_offset: usize,
    max_blocks: usize,
) -> Result<Bz2Stream, Bz2ScanError> {
    // 1. Check header
    if byte_offset + 4 > data.len() {
        return Err(Bz2ScanError::Truncated);
    }
    if &data[byte_offset..byte_offset + 3] != b"BZh" {
        return Err(Bz2ScanError::BadHeader);
    }
    let level = data[byte_offset + 3];
    if level < b'1' || level > b'9' {
        return Err(Bz2ScanError::BadHeader);
    }
    // Convert '1'..='9' to 1..=9
    let level = (level - b'1') + 1;

    // pos = (byte_offset + 4) * 8 — first bit after the 4-byte header
    let mut pos: u64 = ((byte_offset as u64) + 4) * 8;

    let mut blocks: Vec<Bz2Block> = Vec::new();

    // Try to pre-allocate
    if max_blocks > 0 {
        let _ = blocks.try_reserve(max_blocks);
    }

    loop {
        // Check we have 48 bits at pos
        if pos + 48 > (data.len() as u64) * 8 {
            return Err(Bz2ScanError::Truncated);
        }

        let magic = read_48(data, pos).ok_or(Bz2ScanError::Truncated)?;

        if magic == EOS_MAGIC {
            // 4. EOS magic at pos
            if pos + 48 + 32 > (data.len() as u64) * 8 {
                return Err(Bz2ScanError::Truncated);
            }
            let combined_crc = read_32(data, pos + 48).ok_or(Bz2ScanError::Truncated)?;
            let eos_bit_offset = pos;
            let end_byte = ((eos_bit_offset + 80) as usize + 7) / 8;

            let computed_crc = compute_combined_crc(&blocks);

            return Ok(Bz2Stream {
                byte_offset,
                level,
                blocks,
                eos_bit_offset,
                stored_combined_crc: combined_crc,
                computed_combined_crc: computed_crc,
                end_byte,
            });
        }

        if magic != BLOCK_MAGIC {
            return Err(Bz2ScanError::BadHeader);
        }

        // We have a block magic. Check we have 32 bits for CRC.
        if pos + 48 + 32 > (data.len() as u64) * 8 {
            return Err(Bz2ScanError::Truncated);
        }

        if blocks.len() == max_blocks {
            return Err(Bz2ScanError::LimitExceeded);
        }

        let stored_crc = read_32(data, pos + 48).ok_or(Bz2ScanError::Truncated)?;

        blocks.push(Bz2Block {
            bit_offset: pos,
            stored_crc,
        });

        // Search bit by bit from pos + 80 for the next magic
        let mut found = false;
        let mut search_pos = pos + 80;
        while search_pos + 48 <= (data.len() as u64) * 8 {
            let m = read_48(data, search_pos).ok_or(Bz2ScanError::Truncated)?;
            if m == BLOCK_MAGIC || m == EOS_MAGIC {
                pos = search_pos;
                found = true;
                break;
            }
            search_pos += 1;
        }

        if !found {
            return Err(Bz2ScanError::MissingEndOfStream);
        }
    }
}

/// Scan all bzip2 streams in `data`.
///
/// `max_blocks` is the maximum number of blocks to scan per stream.
pub fn scan_all(data: &[u8], max_blocks: usize) -> Result<Vec<Bz2Stream>, Bz2ScanError> {
    let mut results: Vec<Bz2Stream> = Vec::new();
    let mut off: usize = 0;
    let mut total_blocks: usize = 0;

    loop {
        // Need at least 4 bytes to check for header
        if off + 4 > data.len() {
            break;
        }
        // Check if this looks like a bzip2 header
        if &data[off..off + 3] != b"BZh" {
            break;
        }
        let level = data[off + 3];
        if level < b'1' || level > b'9' {
            break;
        }

        let remaining = max_blocks.saturating_sub(total_blocks);
        let s = scan_stream(data, off, remaining)?;
        total_blocks += s.blocks.len();
        results.push(s);
        off = results.last().unwrap().end_byte;
    }

    if results.is_empty() {
        // No streams found — could be empty data or bad header
        if data.is_empty() || off + 4 > data.len() {
            return Err(Bz2ScanError::Truncated);
        }
        return Err(Bz2ScanError::BadHeader);
    }

    Ok(results)
}
