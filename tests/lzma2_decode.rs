// SPDX-License-Identifier: MIT OR Apache-2.0
mod common;
use common::*;
use sediment_engine::lzma2_decode::{Lzma2Error, decode_lzma2, decode_lzma2_into, dictionary_size_from_byte};

const RAW_DICT: u32 = 1 << 20;

#[test]
fn dict_byte() {
    assert_eq!(dictionary_size_from_byte(0), Ok(4096));
    assert_eq!(dictionary_size_from_byte(1), Ok(6144));
    assert_eq!(dictionary_size_from_byte(16), Ok(1 << 20));
    assert_eq!(dictionary_size_from_byte(40), Ok(u32::MAX));
    assert_eq!(dictionary_size_from_byte(41), Err(Lzma2Error::InvalidProperties));
    assert_eq!(dictionary_size_from_byte(0x80), Err(Lzma2Error::InvalidProperties));
}

#[test]
fn raw_lzma2_matches_oracle() {
    for name in NAMES {
        let data = fixture(&format!("{name}.lzma2.raw"));
        let (got, used) = decode_lzma2(&data, RAW_DICT, DICT_CAP, OUT_CAP).unwrap();
        assert_eq!(got, expected(name), "{name}");
        assert_eq!(used, data.len(), "{name}");
    }
}

#[test]
fn appends_after_existing_output() {
    let data = fixture("text.lzma2.raw");
    let mut out = b"prefix".to_vec();
    decode_lzma2_into(&data, RAW_DICT, DICT_CAP, &mut out, OUT_CAP).unwrap();
    assert_eq!(&out[..6], b"prefix");
    assert_eq!(&out[6..], &expected("text")[..]);
}

#[test]
fn handcrafted_chunks() {
    // Uncompressed chunk with dict reset, then uncompressed without reset, then end.
    let s = [0x01, 0x00, 0x02, b'a', b'b', b'c', 0x02, 0x00, 0x00, b'd', 0x00];
    assert_eq!(decode_lzma2(&s, RAW_DICT, DICT_CAP, 100), Ok((b"abcd".to_vec(), s.len())));
    // Empty stream.
    assert_eq!(decode_lzma2(&[0x00], RAW_DICT, DICT_CAP, 100), Ok((Vec::new(), 1)));
    // First chunk without dictionary reset.
    assert_eq!(decode_lzma2(&[0x02, 0x00, 0x00, b'x', 0x00], RAW_DICT, DICT_CAP, 100), Err(Lzma2Error::InvalidData));
    // Invalid control bytes.
    assert_eq!(decode_lzma2(&[0x03], RAW_DICT, DICT_CAP, 100), Err(Lzma2Error::InvalidControl));
    assert_eq!(decode_lzma2(&[0x7F], RAW_DICT, DICT_CAP, 100), Err(Lzma2Error::InvalidControl));
    // LZMA chunk without properties after reset.
    assert_eq!(
        decode_lzma2(&[0x01, 0x00, 0x00, b'x', 0x80, 0, 0, 0, 4, 0, 0, 0, 0, 0], RAW_DICT, DICT_CAP, 100),
        Err(Lzma2Error::InvalidData)
    );
    // lc + lp > 4 is invalid in LZMA2.
    let mut bad = vec![0xE0, 0, 0, 0, 4, (2 * 5 + 3) * 9 + 4];
    bad.extend_from_slice(&[0; 5]);
    assert_eq!(decode_lzma2(&bad, RAW_DICT, DICT_CAP, 100), Err(Lzma2Error::InvalidProperties));
    // Missing end byte.
    assert_eq!(decode_lzma2(&[0x01, 0x00, 0x00, b'x'], RAW_DICT, DICT_CAP, 100), Err(Lzma2Error::UnexpectedEof));
}

#[test]
fn caps() {
    let data = fixture("comp.lzma2.raw");
    assert_eq!(decode_lzma2(&data, 1 << 21, 1 << 20, OUT_CAP), Err(Lzma2Error::LimitExceeded));
    let n = compressible().len();
    assert_eq!(decode_lzma2(&data, RAW_DICT, DICT_CAP, n - 1), Err(Lzma2Error::LimitExceeded));
    assert!(decode_lzma2(&data, RAW_DICT, DICT_CAP, n).is_ok());
}

#[test]
fn truncated_and_bit_flipped_never_panic() {
    for name in ["text.lzma2.raw", "random.lzma2.raw", "comp.lzma2.raw", "one.lzma2.raw"] {
        let data = fixture(name);
        let accepted = hostile(&data, |d| decode_lzma2(d, RAW_DICT, DICT_CAP, 1 << 20).is_ok());
        assert_eq!(accepted, 0, "{name}: truncation accepted");
    }
}
