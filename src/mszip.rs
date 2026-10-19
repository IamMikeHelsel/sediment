// SPDX-License-Identifier: MIT OR Apache-2.0
//! MSZIP (CAB compression type 1) block decoding.
//!
//! Spec source: [MS-MCI] Microsoft ZIP (MSZIP) Compression and Decompression
//! Data Structures, and [MS-CAB] section 2.1. Every CFDATA block holds the
//! two signature bytes `CK` followed by a complete RFC 1951 deflate stream
//! (ending in a block with BFINAL set) that decodes to at most 32 KiB. The
//! deflate history is NOT reset between blocks: matches may reach back into
//! the previous block's output (up to 32 KiB).
//!
//! Reuses the crate's deflate building blocks (bit reader, stored/dynamic
//! block readers, Huffman decoder, length/distance tables, LZ77 copy); the
//! only new piece is starting the output with a preset history.

use crate::bit_reader::BitReader;
use crate::deflate_dynamic::{DynamicError, DynamicTrees, read_dynamic_trees};
use crate::deflate_stored::{StoredError, read_stored_block};
use crate::deflate_tables::{distance_spec, length_spec};
use crate::huffman_decode::{DecodeError, HuffmanDecoder};
use crate::lz77::{MatchError, append_match};

/// Largest uncompressed size of one MSZIP block.
pub const MSZIP_BLOCK_MAX: usize = 32768;
const HISTORY: usize = 32768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MszipError {
    /// Block does not start with `CK`.
    MissingSignature,
    /// Input ended inside the deflate stream.
    UnexpectedEof,
    /// Malformed deflate data (bad block type, code, distance, ...).
    InvalidData,
    /// Output would exceed the caller's limit.
    LimitExceeded,
    /// Decoded size differs from the size the container declared.
    SizeMismatch,
    /// Memory reservation failed.
    Allocation,
}

fn huff_err(e: DecodeError) -> MszipError {
    match e {
        DecodeError::UnexpectedEof => MszipError::UnexpectedEof,
        DecodeError::Allocation => MszipError::Allocation,
        _ => MszipError::InvalidData,
    }
}

/// Inflate one raw deflate stream whose back-references may reach into
/// `history` (the last up to 32 KiB of previously decoded data). Returns only
/// the new bytes; at most `max_output` of them. Bytes after the final block
/// are ignored.
pub fn inflate_with_history(input: &[u8], history: &[u8], max_output: usize) -> Result<Vec<u8>, MszipError> {
    let history = &history[history.len().saturating_sub(HISTORY)..];
    let limit = history.len().checked_add(max_output).ok_or(MszipError::LimitExceeded)?;
    let mut reader = BitReader::new(input).map_err(|_| MszipError::LimitExceeded)?;
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(history.len() + max_output.min(MSZIP_BLOCK_MAX)).map_err(|_| MszipError::Allocation)?;
    out.extend_from_slice(history);
    loop {
        let bfinal = reader.read_bits(1).map_err(|_| MszipError::UnexpectedEof)?;
        let btype = reader.read_bits(2).map_err(|_| MszipError::UnexpectedEof)?;
        match btype {
            0 => read_stored_block(&mut reader, &mut out, limit).map_err(|e| match e {
                StoredError::UnexpectedEof => MszipError::UnexpectedEof,
                StoredError::LimitExceeded => MszipError::LimitExceeded,
                StoredError::Allocation => MszipError::Allocation,
                StoredError::InvalidLength => MszipError::InvalidData,
            })?,
            1 | 2 => {
                let trees = if btype == 1 {
                    let mut lit = [8u8; 288];
                    lit[144..256].fill(9);
                    lit[256..280].fill(7);
                    DynamicTrees {
                        literal: HuffmanDecoder::new(&lit, 15).map_err(huff_err)?,
                        distance: Some(HuffmanDecoder::new(&[5u8; 32], 15).map_err(huff_err)?),
                    }
                } else {
                    read_dynamic_trees(&mut reader).map_err(|e| match e {
                        DynamicError::UnexpectedEof => MszipError::UnexpectedEof,
                        DynamicError::Allocation => MszipError::Allocation,
                        DynamicError::InvalidData => MszipError::InvalidData,
                    })?
                };
                loop {
                    let sym = trees.literal.decode(&mut reader).map_err(huff_err)?;
                    if sym < 256 {
                        if out.len() >= limit {
                            return Err(MszipError::LimitExceeded);
                        }
                        out.try_reserve(1).map_err(|_| MszipError::Allocation)?;
                        out.push(sym as u8);
                        continue;
                    }
                    if sym == 256 {
                        break;
                    }
                    let (base, extra) = length_spec(sym).map_err(|_| MszipError::InvalidData)?;
                    let eb = reader.read_bits(extra).map_err(|_| MszipError::UnexpectedEof)?;
                    let length = base as usize + eb as usize;
                    let dist_tree = trees.distance.as_ref().ok_or(MszipError::InvalidData)?;
                    let dsym = dist_tree.decode(&mut reader).map_err(huff_err)?;
                    let (dbase, dextra) = distance_spec(dsym).map_err(|_| MszipError::InvalidData)?;
                    let db = reader.read_bits(dextra).map_err(|_| MszipError::UnexpectedEof)?;
                    let distance = dbase as usize + db as usize;
                    append_match(&mut out, distance, length, limit).map_err(|e| match e {
                        MatchError::InvalidLength | MatchError::InvalidDistance => MszipError::InvalidData,
                        MatchError::LimitExceeded => MszipError::LimitExceeded,
                        MatchError::Allocation => MszipError::Allocation,
                    })?;
                }
            }
            _ => return Err(MszipError::InvalidData),
        }
        if bfinal == 1 {
            break;
        }
    }
    out.drain(..history.len());
    Ok(out)
}

/// Stateful MSZIP decoder for one CAB folder: feed CFDATA payloads in order.
#[derive(Debug, Default, Clone)]
pub struct MszipDecoder {
    history: Vec<u8>,
}

impl MszipDecoder {
    pub fn new() -> Self {
        MszipDecoder { history: Vec::new() }
    }

    /// Decode one CFDATA payload (`CK` + deflate) that must produce exactly
    /// `uncompressed_len` (at most 32 KiB) bytes.
    pub fn decode_block(&mut self, block: &[u8], uncompressed_len: usize) -> Result<Vec<u8>, MszipError> {
        if uncompressed_len > MSZIP_BLOCK_MAX {
            return Err(MszipError::LimitExceeded);
        }
        let body = block.strip_prefix(b"CK").ok_or(MszipError::MissingSignature)?;
        let out = match inflate_with_history(body, &self.history, uncompressed_len) {
            Err(MszipError::LimitExceeded) => return Err(MszipError::SizeMismatch),
            r => r?,
        };
        if out.len() != uncompressed_len {
            return Err(MszipError::SizeMismatch);
        }
        // keep the last 32 KiB as history
        let keep = HISTORY.saturating_sub(out.len()).min(self.history.len());
        let drop = self.history.len() - keep;
        self.history.drain(..drop);
        self.history.try_reserve(out.len()).map_err(|_| MszipError::Allocation)?;
        self.history.extend_from_slice(&out);
        Ok(out)
    }
}
