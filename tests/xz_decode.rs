// SPDX-License-Identifier: MIT OR Apache-2.0
mod common;
use common::*;
use sediment_engine::xz_decode::{XzError, decode_xz, decode_xz_stream_into};

fn dec(name: &str) -> Result<Vec<u8>, XzError> {
    decode_xz(&fixture(name), DICT_CAP, OUT_CAP)
}

#[test]
fn presets_match_oracle() {
    for name in NAMES {
        for p in ["p0", "p6", "p9e"] {
            assert_eq!(dec(&format!("{name}.{p}.xz")).unwrap(), expected(name), "{name}.{p}");
        }
    }
}

#[test]
fn check_variants() {
    for c in ["none", "crc32", "crc64", "sha256"] {
        assert_eq!(dec(&format!("comp.check_{c}.xz")).unwrap(), compressible(), "{c}");
        assert_eq!(dec(&format!("text.check_{c}.xz")).unwrap(), expected("text"), "{c}");
    }
}

#[test]
fn unusual_lc_lp_pb() {
    for v in ["lc0lp2pb0", "lc4lp0pb4", "lc1lp3pb1"] {
        assert_eq!(dec(&format!("text.xz_{v}.xz")).unwrap(), expected("text"), "{v}");
    }
}

#[test]
fn multi_stream_and_padding() {
    let mut both = expected("text");
    both.extend_from_slice(&expected("random"));
    assert_eq!(dec("multi.text_random.xz").unwrap(), both);
    assert_eq!(dec("multi.padded.xz").unwrap(), both);
    assert_eq!(dec("multi.badpad.xz"), Err(XzError::InvalidPadding));
    // Single-stream entry point stops after the first stream.
    let data = fixture("multi.text_random.xz");
    let mut out = Vec::new();
    let used = decode_xz_stream_into(&data, DICT_CAP, &mut out, OUT_CAP).unwrap();
    assert_eq!(out, expected("text"));
    assert!(used < data.len());
    let mut rest = Vec::new();
    let used2 = decode_xz_stream_into(&data[used..], DICT_CAP, &mut rest, OUT_CAP).unwrap();
    assert_eq!(rest, expected("random"));
    assert_eq!(used + used2, data.len());
}

#[test]
fn multi_block_with_and_without_sizes() {
    let text = expected("text");
    let random = expected("random");
    let mut want = text[..5000].to_vec();
    want.extend_from_slice(&random[..2000]);
    want.extend_from_slice(&text[5000..]);
    assert_eq!(dec("multiblock.xz").unwrap(), want);
}

#[test]
fn bad_checks_detected() {
    for c in ["crc32", "crc64", "sha256"] {
        assert_eq!(dec(&format!("bad_check_{c}.xz")), Err(XzError::ChecksumMismatch), "{c}");
    }
}

#[test]
fn delta_and_bcj_pre_filters() {
    // Python lzma made these with [Delta|X86, LZMA2] filter chains.
    assert_eq!(dec("text.delta.xz").unwrap(), expected("text"));
    assert_eq!(dec("text.x86.xz").unwrap(), expected("text"));
}

#[test]
fn dictionary_and_output_caps() {
    // Preset 9e declares a 64 MiB dictionary.
    let data = fixture("one.p9e.xz");
    assert_eq!(decode_xz(&data, 1 << 20, OUT_CAP), Err(XzError::LimitExceeded));
    assert!(decode_xz(&data, 64 << 20, OUT_CAP).is_ok());
    let data = fixture("comp.p6.xz");
    let n = compressible().len();
    assert_eq!(decode_xz(&data, DICT_CAP, n - 1), Err(XzError::LimitExceeded));
    assert!(decode_xz(&data, DICT_CAP, n).is_ok());
}

#[test]
fn malformed_containers() {
    assert_eq!(decode_xz(&[], DICT_CAP, OUT_CAP), Err(XzError::UnexpectedEof));
    let mut data = fixture("text.p6.xz");
    data[0] ^= 0xFF;
    assert_eq!(decode_xz(&data, DICT_CAP, OUT_CAP), Err(XzError::InvalidMagic));
    let mut data = fixture("text.p6.xz");
    data[7] ^= 0x01; // stream flags -> header CRC mismatch
    assert_eq!(decode_xz(&data, DICT_CAP, OUT_CAP), Err(XzError::ChecksumMismatch));
    let mut data = fixture("text.p6.xz");
    data.extend_from_slice(&[1, 2, 3, 4]); // garbage after stream
    assert!(decode_xz(&data, DICT_CAP, OUT_CAP).is_err());
    let mut data = fixture("text.p6.xz");
    data.extend_from_slice(&[0, 0, 0, 0]); // valid trailing padding
    assert_eq!(decode_xz(&data, DICT_CAP, OUT_CAP).unwrap(), expected("text"));
    let mut data = fixture("text.p6.xz");
    let n = data.len();
    data[n - 1] = b'X'; // footer magic
    assert_eq!(decode_xz(&data, DICT_CAP, OUT_CAP), Err(XzError::InvalidMagic));
}

#[test]
fn truncated_and_bit_flipped_never_panic() {
    for name in ["text.p6.xz", "random.p0.xz", "comp.check_sha256.xz", "multiblock.xz", "empty.p6.xz"] {
        let data = fixture(name);
        let accepted = hostile(&data, |d| decode_xz(d, DICT_CAP, 1 << 20).is_ok());
        assert_eq!(accepted, 0, "{name}: truncation accepted");
    }
    // Concatenated streams: a cut exactly at a stream or padding boundary is
    // itself a valid file, so only require that nothing panics and that every
    // accepted cut decodes to a prefix of the full output.
    let data = fixture("multi.padded.xz");
    let full = decode_xz(&data, DICT_CAP, OUT_CAP).unwrap();
    hostile(&data, |d| match decode_xz(d, DICT_CAP, 1 << 20) {
        Ok(v) => {
            assert!(full.starts_with(&v));
            true
        }
        Err(_) => false,
    });
}
