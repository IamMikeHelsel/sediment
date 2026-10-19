// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZMA2 encoder: chunk limits, uncompressed fallback, reset sequencing, and
//! round trips through the in-tree LZMA2 decoder.
mod common;
mod enc_common;
use common::*;
use enc_common::*;
use sediment_engine::lzma2_decode::{decode_lzma2, dictionary_size_from_byte};
use sediment_engine::lzma2_encode::*;
use sediment_engine::lzma_encode::{LzmaEncoderOptions, effective_dictionary_size};

fn opts(level: u32) -> LzmaEncoderOptions {
    LzmaEncoderOptions::preset(level).unwrap()
}

/// Encode, check the chunk sequence is well-formed, decode, return chunks.
fn roundtrip(data: &[u8], o: &LzmaEncoderOptions) -> (Vec<u8>, Vec<Chunk>) {
    let (enc, dict_byte) = encode_lzma2(data, o).unwrap();
    let dict = dictionary_size_from_byte(dict_byte).unwrap();
    assert_eq!(dict, effective_dictionary_size(o.dictionary_size, data.len()));
    let (dec, used) = decode_lzma2(&enc, dict, DICT_CAP, OUT_CAP).unwrap();
    assert_eq!(used, enc.len());
    assert_eq!(dec, data);
    let chunks = lzma2_chunks(&enc);
    let mut need_props = true;
    let mut need_state_reset = false;
    for (i, &(c, u, p)) in chunks.iter().enumerate() {
        if i == 0 {
            assert!(c == 0x01 || c >= 0xE0, "first chunk must reset the dictionary: {c:#x}");
        } else {
            assert!(c == 0x02 || (0x80..0xE0).contains(&c), "no later dictionary resets: {c:#x}");
        }
        if c < 0x80 {
            assert!(u <= CHUNK_MAX_PACKED);
            need_state_reset = true;
        } else {
            assert!(u <= CHUNK_MAX_UNPACKED && p <= CHUNK_MAX_PACKED && p < u);
            if need_props {
                assert!(c >= 0xC0, "first LZMA chunk carries properties");
            } else if need_state_reset {
                assert!(c >= 0xA0, "LZMA chunk after an uncompressed chunk resets state");
            }
            need_props = false;
            need_state_reset = false;
        }
    }
    assert_eq!(chunks.iter().map(|c| c.1).sum::<usize>(), data.len());
    (enc, chunks)
}

#[test]
fn small_inputs_all_levels() {
    for name in NAMES {
        let data = expected(name);
        for level in 0..=9 {
            let (enc, chunks) = roundtrip(&data, &opts(level));
            if data.is_empty() {
                assert_eq!(enc, [0x00]);
                assert!(chunks.is_empty());
            }
        }
    }
}

#[test]
fn incompressible_input_uses_uncompressed_chunks() {
    let data = noise(77, 200_000);
    let (enc, chunks) = roundtrip(&data, &opts(1));
    assert!(chunks.iter().all(|c| c.0 == 0x01 || c.0 == 0x02));
    assert_eq!(chunks[0].0, 0x01);
    assert!(chunks.iter().all(|c| c.1 <= 65536));
    // Overhead: 3 bytes per 64 KiB plus the end byte.
    assert!(enc.len() <= data.len() + 3 * chunks.len() + 1);
}

#[test]
fn mixed_input_resets_state_after_uncompressed() {
    let mut data = wordy(1, 150_000);
    data.extend_from_slice(&noise(2, 150_000));
    data.extend_from_slice(&wordy(3, 150_000));
    // Repeat the first part: matches reach back across uncompressed chunks.
    data.extend_from_within(..40_000);
    for level in [0, 6] {
        let (_, chunks) = roundtrip(&data, &opts(level));
        let kinds: Vec<u8> = chunks.iter().map(|c| c.0 & 0xE0).collect();
        assert_eq!(kinds[0], 0xE0);
        assert!(chunks.iter().any(|c| c.0 == 0x02), "{kinds:x?}");
        assert!(kinds.contains(&0xA0), "state reset after raw chunks: {kinds:x?}");
        assert!(kinds.contains(&0x80), "plain continuation chunks: {kinds:x?}");
    }
}

#[test]
fn first_chunk_uncompressed_then_props() {
    let mut data = noise(9, 70_000);
    data.extend_from_slice(&wordy(4, 300_000));
    let (_, chunks) = roundtrip(&data, &opts(3));
    assert_eq!(chunks[0].0, 0x01);
    let first_lzma = chunks.iter().find(|c| c.0 >= 0x80).unwrap();
    assert_eq!(first_lzma.0 & 0xE0, 0xC0, "properties without dictionary reset");
}

#[test]
fn unpacked_chunk_limit() {
    // 5 MiB of zeros: tiny packed size, so the 2 MiB unpacked limit splits it.
    let data = vec![0u8; 5 << 20];
    let (enc, chunks) = roundtrip(&data, &opts(0));
    assert_eq!(chunks.len(), 3, "{chunks:?}");
    assert!(chunks.iter().all(|c| c.0 >= 0x80));
    assert!(chunks[0].1 > CHUNK_MAX_UNPACKED - 300);
    assert!(enc.len() < 2000);
}

#[test]
fn packed_chunk_limit() {
    // ~600 KB of words at ~30% packs to > 64 KiB: several LZMA chunks.
    let data = wordy(8, 600_000);
    let (_, chunks) = roundtrip(&data, &opts(2));
    assert!(chunks.len() >= 2);
    assert!(chunks.iter().all(|c| c.0 >= 0x80));
    assert!(chunks[0].2 > CHUNK_MAX_PACKED - 200, "{chunks:?}");
}

#[test]
fn dictionary_byte_matches_effective_size() {
    for len in [0usize, 1, 4096, 4097, 100_000] {
        let data = wordy(len as u64, len);
        let (_, b) = encode_lzma2(&data, &opts(9)).unwrap();
        let d = dictionary_size_from_byte(b).unwrap();
        assert!(d as usize >= len.max(4096) && (d as usize) < 2 * len.max(4096), "{len}: {d}");
    }
    assert_eq!(dictionary_size_to_byte(4096), 0);
    assert_eq!(dictionary_size_to_byte(1 << 20), 16);
    assert_eq!(dictionary_size_to_byte(3 << 20), 19);
    for b in 0..40u8 {
        assert_eq!(dictionary_size_to_byte(dictionary_size_from_byte(b).unwrap()), b);
    }
}

#[test]
fn rejects_lc_plus_lp_over_four() {
    let o = LzmaEncoderOptions { lc: 4, lp: 1, ..opts(6) };
    assert_eq!(encode_lzma2(b"abc", &o), Err(Lzma2EncodeError::InvalidOptions));
    let o = LzmaEncoderOptions { lc: 0, lp: 4, pb: 4, ..opts(6) };
    roundtrip(&wordy(3, 5000), &o);
    let o = LzmaEncoderOptions { depth: 0, ..opts(6) };
    assert_eq!(encode_lzma2(b"abc", &o), Err(Lzma2EncodeError::InvalidOptions));
}
