// SPDX-License-Identifier: MIT OR Apache-2.0
mod common;
use common::*;
use sediment_engine::lzma_decode::{LzmaError, decode_lzma_alone, decode_lzma_raw, decode_props_byte};
use sediment_engine::lzma_properties::LzmaProperties;

fn raw_props() -> LzmaProperties {
    LzmaProperties { lc: 3, lp: 0, pb: 2, dictionary_size: 1 << 20 }
}

#[test]
fn props_byte() {
    assert_eq!(decode_props_byte(0x5D), Ok((3, 0, 2)));
    assert_eq!(decode_props_byte(0), Ok((0, 0, 0)));
    assert_eq!(decode_props_byte(224), Ok((8, 4, 4)));
    assert_eq!(decode_props_byte(225), Err(LzmaError::InvalidProperties));
}

#[test]
fn alone_matches_oracle() {
    for name in NAMES {
        let got = decode_lzma_alone(&fixture(&format!("{name}.lzma")), DICT_CAP, OUT_CAP).unwrap();
        assert_eq!(got, expected(name), "{name}");
    }
}

#[test]
fn alone_unusual_lc_lp_pb() {
    let text = expected("text");
    for v in ["lc0lp2pb0", "lc4lp0pb4", "lc1lp3pb1"] {
        let got = decode_lzma_alone(&fixture(&format!("text.alone_{v}.lzma")), DICT_CAP, OUT_CAP).unwrap();
        assert_eq!(got, text, "{v}");
    }
}

#[test]
fn raw_lzma1_with_end_marker() {
    for name in NAMES {
        let data = fixture(&format!("{name}.lzma1.raw"));
        let (got, used) = decode_lzma_raw(&data, raw_props(), None, DICT_CAP, OUT_CAP).unwrap();
        assert_eq!(got, expected(name), "{name}");
        assert_eq!(used, data.len(), "{name}");
    }
}

#[test]
fn known_size_header_with_and_without_marker() {
    // Rewrite the .lzma header to declare the size; the marker stays and is accepted.
    let mut data = fixture("text.lzma");
    let text = expected("text");
    data[5..13].copy_from_slice(&(text.len() as u64).to_le_bytes());
    assert_eq!(decode_lzma_alone(&data, DICT_CAP, OUT_CAP).unwrap(), text);
    // Declared size smaller than the real content: must fail.
    data[5..13].copy_from_slice(&(text.len() as u64 - 1).to_le_bytes());
    assert!(decode_lzma_alone(&data, DICT_CAP, OUT_CAP).is_err());
    // Declared size larger than content: marker arrives early -> error.
    data[5..13].copy_from_slice(&(text.len() as u64 + 1).to_le_bytes());
    assert!(decode_lzma_alone(&data, DICT_CAP, OUT_CAP).is_err());
}

#[test]
fn dictionary_cap() {
    let data = fixture("text.lzma"); // preset 6: 8 MiB dictionary
    assert_eq!(decode_lzma_alone(&data, 1 << 20, OUT_CAP), Err(LzmaError::LimitExceeded));
    assert!(decode_lzma_alone(&data, 8 << 20, OUT_CAP).is_ok());
}

#[test]
fn output_cap() {
    let data = fixture("comp.lzma");
    let n = compressible().len();
    assert_eq!(decode_lzma_alone(&data, DICT_CAP, n - 1), Err(LzmaError::LimitExceeded));
    assert!(decode_lzma_alone(&data, DICT_CAP, n).is_ok());
    // Known size larger than cap is rejected up front.
    let mut d2 = data.clone();
    d2[5..13].copy_from_slice(&u64::MAX.wrapping_sub(1).to_le_bytes());
    assert_eq!(decode_lzma_alone(&d2, DICT_CAP, OUT_CAP), Err(LzmaError::LimitExceeded));
}

#[test]
fn malformed_header_and_trailing() {
    assert_eq!(decode_lzma_alone(&[], DICT_CAP, OUT_CAP), Err(LzmaError::UnexpectedEof));
    let mut data = fixture("one.lzma");
    data[0] = 225;
    assert_eq!(decode_lzma_alone(&data, DICT_CAP, OUT_CAP), Err(LzmaError::InvalidProperties));
    let mut data = fixture("one.lzma");
    data.push(0);
    assert_eq!(decode_lzma_alone(&data, DICT_CAP, OUT_CAP), Err(LzmaError::TrailingData));
    // First range-coder byte must be zero.
    let mut data = fixture("one.lzma");
    data[13] = 1;
    assert_eq!(decode_lzma_alone(&data, DICT_CAP, OUT_CAP), Err(LzmaError::InvalidData));
}

#[test]
fn truncated_and_bit_flipped_never_panic() {
    for name in ["text.lzma", "random.lzma", "comp.lzma", "one.lzma"] {
        let data = fixture(name);
        let accepted = hostile(&data, |d| decode_lzma_alone(d, DICT_CAP, 1 << 20).is_ok());
        assert_eq!(accepted, 0, "{name}: truncation accepted");
    }
}

#[test]
fn random_garbage_streams_never_panic() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..2000 {
        let len = (next() % 300) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if buf.len() > 13 {
            buf[0] = 0x5D;
            buf[1..5].copy_from_slice(&(1u32 << 16).to_le_bytes());
            buf[5..13].copy_from_slice(&u64::MAX.to_le_bytes());
            buf[13] = 0;
        }
        let _ = decode_lzma_alone(&buf, DICT_CAP, 1 << 16);
        let _ = sediment_engine::lzma2_decode::decode_lzma2(&buf[buf.len().min(13)..], 1 << 16, DICT_CAP, 1 << 16);
        let _ = sediment_engine::xz_decode::decode_xz(&buf, DICT_CAP, 1 << 16);
    }
}
