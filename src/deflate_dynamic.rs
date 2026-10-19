// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::bit_reader::BitReader;
use crate::huffman_decode::HuffmanDecoder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicError {
    UnexpectedEof,
    InvalidData,
    Allocation,
}

#[derive(Debug)]
pub struct DynamicTrees {
    pub literal: HuffmanDecoder,
    pub distance: Option<HuffmanDecoder>,
}

pub fn read_dynamic_trees(reader: &mut BitReader<'_>) -> Result<DynamicTrees, DynamicError> {
    let mut cursor = reader.clone();

    let hlit = cursor.read_bits(5).map_err(|_| DynamicError::UnexpectedEof)? as usize + 257;
    let hdist = cursor.read_bits(5).map_err(|_| DynamicError::UnexpectedEof)? as usize + 1;
    let hclen = cursor.read_bits(4).map_err(|_| DynamicError::UnexpectedEof)? as usize + 4;

    if hlit > 286 || hdist > 30 {
        return Err(DynamicError::InvalidData);
    }

    let mut code_lengths = [0u8; 19];
    let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    for &i in order.iter().take(hclen) {
        code_lengths[i] = cursor.read_bits(3).map_err(|_| DynamicError::UnexpectedEof)? as u8;
    }

    validate_lengths(&code_lengths, 7, false)?;
    let code_tree = HuffmanDecoder::new(&code_lengths, 7).map_err(map_decode_err)?;

    let mut lengths = [0u8; 316];
    let total_len = hlit + hdist;
    let mut i = 0;
    let mut prev_len: u8 = 0;

    while i < total_len {
        let sym = code_tree.decode(&mut cursor).map_err(map_decode_err)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                prev_len = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err(DynamicError::InvalidData);
                }
                let rep = cursor.read_bits(2).map_err(|_| DynamicError::UnexpectedEof)? as usize + 3;
                let l = prev_len;
                if i + rep > total_len {
                    return Err(DynamicError::InvalidData);
                }
                for k in 0..rep {
                    lengths[i + k] = l;
                }
                i += rep;
            }
            17 => {
                let rep = cursor.read_bits(3).map_err(|_| DynamicError::UnexpectedEof)? as usize + 3;
                if i + rep > total_len {
                    return Err(DynamicError::InvalidData);
                }
                for k in 0..rep {
                    lengths[i + k] = 0;
                }
                i += rep;
                prev_len = 0;
            }
            18 => {
                let rep = cursor.read_bits(7).map_err(|_| DynamicError::UnexpectedEof)? as usize + 11;
                if i + rep > total_len {
                    return Err(DynamicError::InvalidData);
                }
                for k in 0..rep {
                    lengths[i + k] = 0;
                }
                i += rep;
                prev_len = 0;
            }
            _ => return Err(DynamicError::InvalidData),
        }
    }

    let lit_slice = &lengths[..hlit];
    let dist_slice = &lengths[hlit..hlit + hdist];

    if lit_slice[256] == 0 {
        return Err(DynamicError::InvalidData);
    }

    validate_lengths(lit_slice, 15, true)?;
    let literal = build_validated(lit_slice, 15)?;
    if dist_slice.iter().any(|&l| l != 0) {
        validate_lengths(dist_slice, 15, true)?;
    }
    let distance = build_validated_opt(dist_slice, 15)?;

    *reader = cursor;
    Ok(DynamicTrees { literal, distance })
}

fn map_decode_err(e: crate::huffman_decode::DecodeError) -> DynamicError {
    match e {
        crate::huffman_decode::DecodeError::UnexpectedEof => DynamicError::UnexpectedEof,
        crate::huffman_decode::DecodeError::Allocation => DynamicError::Allocation,
        _ => DynamicError::InvalidData,
    }
}

fn validate_lengths(lengths: &[u8], max_depth: u8, allow_single: bool) -> Result<(), DynamicError> {
    let mut sum: u32 = 0;
    let mut nonzero_count = 0;
    for &len in lengths.iter() {
        if len > 0 {
            nonzero_count += 1;
            if len > max_depth {
                return Err(DynamicError::InvalidData);
            }
            sum += 1 << (max_depth - len);
        }
    }
    if sum != (1 << max_depth) {
        if !(allow_single && nonzero_count == 1 && lengths.iter().any(|&l| l == 1)) {
            return Err(DynamicError::InvalidData);
        }
    }
    Ok(())
}

fn build_validated(slice: &[u8], max_depth: u8) -> Result<HuffmanDecoder, DynamicError> {
    HuffmanDecoder::new(slice, max_depth).map_err(|e| match e {
        crate::huffman_decode::DecodeError::Allocation => DynamicError::Allocation,
        _ => DynamicError::InvalidData,
    })
}

fn build_validated_opt(slice: &[u8], max_depth: u8) -> Result<Option<HuffmanDecoder>, DynamicError> {
    let all_zero = slice.iter().all(|&x| x == 0);
    if all_zero {
        return Ok(None);
    }
    let decoder = build_validated(slice, max_depth)?;
    Ok(Some(decoder))
}