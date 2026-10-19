// SPDX-License-Identifier: MIT OR Apache-2.0
//! xz writer: structure, checks, multi-block output, the size comparison
//! against liblzma fixtures, and the committed Rust-produced fixtures that
//! `tests/gen/lzma_enc.py` verifies with Python's `lzma.decompress`.
//!
//! Regenerate the committed fixtures after an intentional encoder change with
//! `SEDIMENT_BLESS=1 cargo test --test xz_encode`, then run
//! `python3 -I tests/gen/lzma_enc.py` to re-verify them with liblzma.
mod common;
mod enc_common;
use common::*;
use enc_common::*;
use sediment_engine::crc32::crc32;
use sediment_engine::lzma_decode::decode_lzma_alone;
use sediment_engine::lzma_encode::{LzmaEncoderOptions, encode_lzma_alone};
use sediment_engine::xz_decode::decode_xz;
use sediment_engine::xz_encode::*;
use sediment_engine::xz_stream::{CheckId, validate_pair};
use sediment_engine::xz_vli::decode_vli;

fn xz(level: u32) -> XzOptions {
    XzOptions::preset(level).unwrap()
}

fn dec(data: &[u8]) -> Vec<u8> {
    decode_xz(data, DICT_CAP, OUT_CAP).unwrap()
}

/// Must match `mixed()` in tests/gen/lzma_enc.py.
fn mixed() -> Vec<u8> {
    let mut v = expected("text");
    v.extend_from_slice(&expected("random"));
    v.extend_from_slice(&expected("random"));
    v.extend_from_slice(&expected("comp"));
    v
}

fn input(name: &str) -> Vec<u8> {
    if name == "mixed" { mixed() } else { expected(name) }
}

#[test]
fn every_level_roundtrips() {
    for name in NAMES {
        let data = expected(name);
        for level in 0..=9 {
            assert_eq!(dec(&encode_xz(&data, &xz(level)).unwrap()), data, "{name} L{level}");
        }
    }
}

#[test]
fn stream_structure() {
    let data = expected("text");
    let out = encode_xz(&data, &xz(6)).unwrap();
    assert_eq!(&out[..6], &[0xFD, b'7', b'z', b'X', b'Z', 0]);
    assert_eq!(&out[6..8], &[0, 4]); // CRC64
    assert_eq!(out.len() % 4, 0);
    assert_eq!(&out[out.len() - 2..], b"YZ");
    let footer = validate_pair(&out[..12], &out[out.len() - 12..], 1 << 20).unwrap();
    assert_eq!(footer.flags.check, CheckId::Crc64);

    // Block header: size byte, flags with both sizes, one LZMA2 filter.
    let hsize = (out[12] as usize + 1) * 4;
    let h = &out[12..12 + hsize];
    assert_eq!(h[1], 0xC0);
    assert_eq!(crc32(&h[..hsize - 4]).to_le_bytes(), h[hsize - 4..]);
    let (comp, a) = decode_vli(&h[2..]).unwrap();
    let (unc, b) = decode_vli(&h[2 + a..]).unwrap();
    assert_eq!(unc, data.len() as u64);
    assert_eq!(&h[2 + a + b..2 + a + b + 2], &[0x21, 0x01]);

    // Index: one record whose unpadded size matches the block.
    let index_len = footer.index_bytes as usize;
    let index = &out[out.len() - 12 - index_len..out.len() - 12];
    assert_eq!(index[0], 0);
    assert_eq!(index[1], 1);
    let (unpadded, k) = decode_vli(&index[2..]).unwrap();
    assert_eq!(unpadded, hsize as u64 + comp + 8);
    assert_eq!(decode_vli(&index[2 + k..]).unwrap().0, data.len() as u64);
    // Header + block (padded) + index + footer account for every byte.
    let padded = (unpadded as usize).div_ceil(4) * 4;
    assert_eq!(12 + padded + index_len + 12, out.len());
}

#[test]
fn empty_input_has_no_blocks() {
    let out = encode_xz(b"", &xz(6)).unwrap();
    assert_eq!(out.len(), 32);
    // Index: indicator 0, zero records, two padding bytes.
    assert_eq!(&out[12..16], &[0, 0, 0, 0]);
    assert!(dec(&out).is_empty());
}

#[test]
fn all_check_types() {
    let data = expected("comp");
    for (check, id, len) in [(CheckId::None, 0, 0), (CheckId::Crc32, 1, 4), (CheckId::Crc64, 4, 8), (CheckId::Sha256, 10, 32)] {
        let o = XzOptions { check, ..xz(6) };
        let out = encode_xz(&data, &o).unwrap();
        assert_eq!(out[7], id);
        assert_eq!(dec(&out), data, "{check:?}");
        let none = encode_xz(&data, &XzOptions { check: CheckId::None, ..xz(6) }).unwrap();
        assert_eq!(out.len(), none.len() + len, "{check:?}");
    }
}

#[test]
fn corrupted_check_is_detected() {
    let data = expected("text");
    for check in [CheckId::Crc32, CheckId::Crc64, CheckId::Sha256] {
        let mut out = encode_xz(&data, &XzOptions { check, ..xz(3) }).unwrap();
        let footer = validate_pair(&out[..12], &out[out.len() - 12..], 1 << 20).unwrap();
        let check_end = out.len() - 12 - footer.index_bytes as usize;
        out[check_end - 1] ^= 0x01;
        assert!(decode_xz(&out, DICT_CAP, OUT_CAP).is_err(), "{check:?}");
    }
}

#[test]
fn multi_block() {
    let data = mixed();
    for bs in [1usize, 1000, 4096, 10_000, data.len() - 1, data.len(), data.len() + 1] {
        let level = if bs == 1 { 0 } else { 6 };
        let o = XzOptions { block_size: Some(bs), ..xz(level) };
        let src = if bs == 1 { &data[..300] } else { &data[..] };
        let out = encode_xz(src, &o).unwrap();
        assert_eq!(dec(&out), src, "bs {bs}");
        let footer = validate_pair(&out[..12], &out[out.len() - 12..], 1 << 24).unwrap();
        let index = &out[out.len() - 12 - footer.index_bytes as usize..];
        assert_eq!(decode_vli(&index[1..]).unwrap().0 as usize, src.len().div_ceil(bs), "bs {bs}");
    }
    assert_eq!(encode_xz(b"x", &XzOptions { block_size: Some(0), ..xz(6) }), Err(XzEncodeError::InvalidOptions));
}

#[test]
fn options_validated() {
    let mut o = xz(6);
    o.lzma.lc = 4;
    o.lzma.lp = 1;
    assert_eq!(encode_xz(b"x", &o), Err(XzEncodeError::InvalidOptions));
    o.lzma.lp = 0;
    o.lzma.nice_len = 1;
    assert_eq!(encode_xz(b"x", &o), Err(XzEncodeError::InvalidOptions));
    assert_eq!(XzOptions::preset(10), Err(XzEncodeError::InvalidOptions));
}

#[test]
fn small_dictionary_for_small_input() {
    // Level 9 asks for 64 MiB but a 20 KB input only declares 24 KiB, so a
    // decoder with a tight dictionary cap accepts it.
    let data = expected("text");
    let out = encode_xz(&data, &xz(9)).unwrap();
    assert_eq!(decode_xz(&out, 32 << 10, OUT_CAP).unwrap(), data);
}

#[test]
fn ratio_close_to_liblzma_preset6() {
    // liblzma preset 6 fixtures were produced by tests/gen/xz.py.
    for name in ["text", "comp", "random"] {
        let ours = encode_xz(&expected(name), &xz(6)).unwrap().len();
        let theirs = fixture(&format!("{name}.p6.xz")).len();
        assert!(ours * 100 <= theirs * 102, "{name}: ours {ours} vs liblzma {theirs}");
    }
}

type Enc = Box<dyn Fn(&[u8]) -> Vec<u8>>;

/// (fixture file, input name, how to encode).
fn fixture_specs() -> Vec<(&'static str, &'static str, Enc)> {
    let x = |o: XzOptions| -> Enc { Box::new(move |d| encode_xz(d, &o).unwrap()) };
    let a = |o: LzmaEncoderOptions, em: bool| -> Enc {
        Box::new(move |d| encode_lzma_alone(d, &o, em).unwrap())
    };
    let l6 = LzmaEncoderOptions::preset(6).unwrap();
    vec![
        ("empty.l6.xz", "empty", x(xz(6))),
        ("one.l6.xz", "one", x(xz(6))),
        ("text.l0.xz", "text", x(xz(0))),
        ("text.l3.xz", "text", x(xz(3))),
        ("text.l6.xz", "text", x(xz(6))),
        ("text.l9.xz", "text", x(xz(9))),
        ("comp.l6.xz", "comp", x(xz(6))),
        ("random.l6.xz", "random", x(xz(6))),
        ("mixed.l6.xz", "mixed", x(xz(6))),
        ("mixed.l1.xz", "mixed", x(xz(1))),
        ("text.none.xz", "text", x(XzOptions { check: CheckId::None, ..xz(6) })),
        ("text.crc32.xz", "text", x(XzOptions { check: CheckId::Crc32, ..xz(6) })),
        ("text.sha256.xz", "text", x(XzOptions { check: CheckId::Sha256, ..xz(6) })),
        ("mixed.blocks.xz", "mixed", x(XzOptions { block_size: Some(5000), ..xz(6) })),
        ("text.lc0lp2pb0.xz", "text", x(XzOptions { lzma: LzmaEncoderOptions { lc: 0, lp: 2, pb: 0, ..l6 }, ..xz(6) })),
        ("text.l6.lzma", "text", a(l6, false)),
        ("text.l6.eopm.lzma", "text", a(l6, true)),
        ("empty.l6.lzma", "empty", a(l6, false)),
        ("comp.l2.lzma", "comp", a(LzmaEncoderOptions::preset(2).unwrap(), false)),
        ("random.l9.eopm.lzma", "random", a(LzmaEncoderOptions::preset(9).unwrap(), true)),
        ("text.lc4lp0pb4.lzma", "text", a(LzmaEncoderOptions { lc: 4, lp: 0, pb: 4, ..l6 }, false)),
    ]
}

#[test]
fn rust_fixtures_match_committed_and_decode() {
    let bless = std::env::var_os("SEDIMENT_BLESS").is_some();
    for (file, name, f) in fixture_specs() {
        let data = input(name);
        let out = f(&data);
        let path = format!("{ENC_FIXTURES}/{file}");
        if bless {
            std::fs::write(&path, &out).unwrap();
        }
        let committed = std::fs::read(&path).unwrap_or_else(|e| panic!("{file}: {e} (run with SEDIMENT_BLESS=1)"));
        assert!(committed == out, "{file}: encoder output changed; re-bless and re-run tests/gen/lzma_enc.py");
        let back = if file.ends_with(".xz") { dec(&out) } else { decode_lzma_alone(&out, DICT_CAP, OUT_CAP).unwrap() };
        assert_eq!(back, data, "{file}");
    }
}

/// Ratio/speed report on caller-supplied corpora (not run by default):
/// `SEDIMENT_CORPUS=a.txt,b.bin cargo test --release --test xz_encode -- --ignored --nocapture`
/// Compare with `python3 -I tests/gen/lzma_enc.py a.txt b.bin` (liblzma preset 6).
#[test]
#[ignore]
fn ratio_report() {
    let Some(list) = std::env::var_os("SEDIMENT_CORPUS") else { return };
    for path in list.to_string_lossy().split(',') {
        let data = std::fs::read(path).unwrap();
        for level in 0..=9 {
            let t = std::time::Instant::now();
            let out = encode_xz(&data, &xz(level)).unwrap();
            let secs = t.elapsed().as_secs_f64();
            assert_eq!(decode_xz(&out, 1 << 30, usize::MAX).unwrap(), data);
            let ratio = out.len() as f64 / data.len().max(1) as f64;
            eprintln!("{path} level {level}: {} -> {} ratio {ratio:.4} {secs:.2}s", data.len(), out.len());
        }
    }
}
