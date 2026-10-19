// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::bit_reader::BitReader;
use crate::deflate_stored::read_stored_block;
use crate::deflate_tables::{distance_spec, length_spec};
use crate::huffman_decode::HuffmanDecoder;
use crate::lz77::append_match;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    UnexpectedEof,
    InvalidData,
    UnsupportedBlock,
    LimitExceeded,
    Allocation,
    TrailingData,
}

pub fn inflate_raw(input: &[u8], max_output: usize, max_blocks: usize) -> Result<Vec<u8>, InflateError> {
    let mut reader = BitReader::new(input).map_err(|_| InflateError::LimitExceeded)?;
    let mut output = Vec::new();
    let mut block_count: usize = 0;

    loop {
        if block_count.checked_add(1).map(|c| c > max_blocks).unwrap_or(true) {
            return Err(InflateError::LimitExceeded);
        }
        block_count += 1;

        let bfinal = reader.read_bits(1).map_err(|_| InflateError::UnexpectedEof)?;
        let btype = reader.read_bits(2).map_err(|_| InflateError::UnexpectedEof)?;

        if btype == 2 {
            return Err(InflateError::UnsupportedBlock);
        }
        if btype == 3 {
            return Err(InflateError::InvalidData);
        }

        if btype == 0 {
            read_stored_block(&mut reader, &mut output, max_output)
                .map_err(|e| match e {
                    crate::deflate_stored::StoredError::UnexpectedEof => InflateError::UnexpectedEof,
                    crate::deflate_stored::StoredError::LimitExceeded => InflateError::LimitExceeded,
                    crate::deflate_stored::StoredError::Allocation => InflateError::Allocation,
                    crate::deflate_stored::StoredError::InvalidLength => InflateError::InvalidData,
                })?;
        } else {
            let mut lit_lens = [8u8; 288];
            lit_lens[144..256].fill(9);
            lit_lens[256..280].fill(7);
            let dist_lens = [5u8; 32];

            let lit_decoder = HuffmanDecoder::new(&lit_lens, 15)
                .map_err(|e| match e {
                    crate::huffman_decode::DecodeError::Allocation => InflateError::Allocation,
                    _ => InflateError::InvalidData,
                })?;
            let dist_decoder = HuffmanDecoder::new(&dist_lens, 15)
                .map_err(|e| match e {
                    crate::huffman_decode::DecodeError::Allocation => InflateError::Allocation,
                    _ => InflateError::InvalidData,
                })?;

            loop {
                let sym = lit_decoder.decode(&mut reader)
                    .map_err(|e| match e {
                        crate::huffman_decode::DecodeError::UnexpectedEof => InflateError::UnexpectedEof,
                        crate::huffman_decode::DecodeError::Allocation => InflateError::Allocation,
                        _ => InflateError::InvalidData,
                    })?;

                if sym == 256 {
                    break;
                }

                if sym < 256 {
                    if output.len().checked_add(1).map(|l| l > max_output).unwrap_or(true) {
                        return Err(InflateError::LimitExceeded);
                    }
                    output.try_reserve(1).map_err(|_| InflateError::Allocation)?;
                    output.push(sym as u8);
                } else {
                    let (base, extra) = length_spec(sym)
                        .map_err(|_| InflateError::InvalidData)?;
                    let extra_bits = if extra > 0 {
                        reader.read_bits(extra)
                            .map_err(|_| InflateError::UnexpectedEof)?
                    } else {
                        0
                    };
                    let length = (base as usize) + (extra_bits as usize);

                    let dist_sym = dist_decoder.decode(&mut reader)
                        .map_err(|e| match e {
                            crate::huffman_decode::DecodeError::UnexpectedEof => InflateError::UnexpectedEof,
                            crate::huffman_decode::DecodeError::Allocation => InflateError::Allocation,
                            _ => InflateError::InvalidData,
                        })?;

                    let (dist_base, dist_extra) = distance_spec(dist_sym)
                        .map_err(|_| InflateError::InvalidData)?;
                    let dist_bits = if dist_extra > 0 {
                        reader.read_bits(dist_extra)
                            .map_err(|_| InflateError::UnexpectedEof)?
                    } else {
                        0
                    };
                    let distance = (dist_base as usize) + (dist_bits as usize);

                    append_match(&mut output, distance, length, max_output)
                        .map_err(|e| match e {
                            crate::lz77::MatchError::InvalidLength | crate::lz77::MatchError::InvalidDistance => InflateError::InvalidData,
                            crate::lz77::MatchError::LimitExceeded => InflateError::LimitExceeded,
                            crate::lz77::MatchError::Allocation => InflateError::Allocation,
                        })?;
                }
            }
        }

        if bfinal != 0 {
            break;
        }
    }

    reader.align_byte();
    if reader.remaining() != 0 {
        return Err(InflateError::TrailingData);
    }

    Ok(output)
}