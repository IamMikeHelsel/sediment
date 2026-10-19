// SPDX-License-Identifier: MIT OR Apache-2.0
//! LZMA encoder: round trips through the in-tree decoder for every preset,
//! option corner cases, dictionary-limit enforcement and option validation.
mod common;
mod enc_common;
use common::*;
use enc_common::*;
use sediment_engine::lzma_decode::{decode_lzma_alone, decode_lzma_raw};
use sediment_engine::lzma_encode::*;
use sediment_engine::lzma_properties::LzmaProperties;

fn opts(level: u32) -> LzmaEncoderOptions {
    LzmaEncoderOptions::preset(level).unwrap()
}

fn raw_roundtrip(data: &[u8], o: &LzmaEncoderOptions, end_marker: bool) -> Vec<u8> {
    let enc = encode_lzma_raw(data, o, end_marker).unwrap();
    let props = LzmaProperties {
        lc: o.lc,
        lp: o.lp,
        pb: o.pb,
        dictionary_size: effective_dictionary_size(o.dictionary_size, data.len()),
    };
    let size = if end_marker { None } else { Some(data.len() as u64) };
    let (dec, used) = decode_lzma_raw(&enc, props, size, DICT_CAP, OUT_CAP).unwrap();
    assert_eq!(dec, data);
    assert_eq!(used, enc.len(), "decoder must consume the whole stream");
    enc
}

fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = NAMES.iter().map(|n| (n.to_string(), expected(n))).collect();
    v.push(("two".into(), b"AB".to_vec()));
    v.push(("three".into(), b"ABA".to_vec()));
    v.push(("zeros".into(), vec![0; 70_000]));
    v.push(("aab".into(), b"aab".repeat(5000)));
    v.push(("wordy".into(), wordy(7, 30_000)));
    v.push(("noise".into(), noise(3, 9_000)));
    let mut mix = noise(5, 2000);
    mix.extend_from_slice(&mix.clone());
    mix.extend_from_slice(&wordy(9, 3000));
    v.push(("mix".into(), mix));
    v
}

#[test]
fn every_preset_roundtrips_alone_and_raw() {
    for (name, data) in inputs() {
        for level in 0..=9 {
            let o = opts(level);
            for em in [false, true] {
                let enc = encode_lzma_alone(&data, &o, em).unwrap();
                assert_eq!(decode_lzma_alone(&enc, DICT_CAP, OUT_CAP).as_deref(), Ok(&data[..]), "{name} L{level} em={em}");
            }
            raw_roundtrip(&data, &o, true);
            raw_roundtrip(&data, &o, false);
        }
    }
}

#[test]
fn alone_header_layout() {
    let data = expected("text");
    let o = opts(6);
    let known = encode_lzma_alone(&data, &o, false).unwrap();
    assert_eq!(known[0], 0x5D); // lc=3 lp=0 pb=2
    let dict = u32::from_le_bytes(known[1..5].try_into().unwrap());
    assert_eq!(dict, effective_dictionary_size(o.dictionary_size, data.len()));
    assert!(dict >= data.len() as u32 && dict <= 2 * data.len() as u32);
    assert_eq!(u64::from_le_bytes(known[5..13].try_into().unwrap()), data.len() as u64);
    let marker = encode_lzma_alone(&data, &o, true).unwrap();
    assert_eq!(&marker[5..13], &[0xFF; 8]);
    assert!(marker.len() > known.len(), "end marker costs bytes");
    // The range coder always starts with a zero byte.
    assert_eq!(known[13], 0);
}

#[test]
fn lc_lp_pb_corners() {
    let data = wordy(11, 12_000);
    for (lc, lp, pb) in [(0, 0, 0), (8, 0, 0), (0, 4, 4), (8, 4, 4), (4, 0, 4), (1, 3, 1), (3, 0, 2)] {
        for level in [1, 3, 6] {
            let mut o = opts(level);
            o.lc = lc;
            o.lp = lp;
            o.pb = pb;
            raw_roundtrip(&data, &o, true);
            let enc = encode_lzma_alone(&data, &o, false).unwrap();
            assert_eq!(enc[0], props_byte(lc, lp, pb));
            assert_eq!(decode_lzma_alone(&enc, DICT_CAP, OUT_CAP).unwrap(), data, "lc{lc} lp{lp} pb{pb}");
        }
    }
}

#[test]
fn finder_and_parser_combinations() {
    let data = {
        let mut d = expected("text");
        d.extend_from_slice(&noise(1, 3000));
        d.extend_from_slice(&expected("comp"));
        d
    };
    for mf in [MatchFinder::HashChain, MatchFinder::BinaryTree] {
        for mode in [ParseMode::Greedy, ParseMode::Lazy, ParseMode::Optimal] {
            for (nice, depth) in [(2, 1), (5, 2), (64, 48), (273, 4096)] {
                let o = LzmaEncoderOptions {
                    dictionary_size: 1 << 20,
                    lc: 3,
                    lp: 0,
                    pb: 2,
                    match_finder: mf,
                    mode,
                    nice_len: nice,
                    depth,
                };
                raw_roundtrip(&data, &o, nice % 2 == 0);
            }
        }
    }
}

#[test]
fn distances_respect_small_dictionary() {
    // An 8000-byte random block repeated: the repeat is 8000 bytes back,
    // beyond a 4 KiB dictionary, so it must not be used.
    let block = noise(21, 8000);
    let mut data = block.clone();
    data.extend_from_slice(&block);
    // A 3000-byte block repeated is within reach and must be found.
    let near = noise(22, 3000);
    data.extend_from_slice(&near);
    data.extend_from_slice(&near);
    for level in [0, 3, 6, 9] {
        let mut o = opts(level);
        o.dictionary_size = 4096;
        assert_eq!(effective_dictionary_size(o.dictionary_size, data.len()), 4096);
        let enc = encode_lzma_raw(&data, &o, true).unwrap();
        let props = LzmaProperties { lc: 3, lp: 0, pb: 2, dictionary_size: 4096 };
        // The decoder enforces distance <= dictionary size.
        let (dec, _) = decode_lzma_raw(&enc, props, None, 4096, OUT_CAP).unwrap();
        assert_eq!(dec, data, "L{level}");
        // 16000 random bytes + one 3000-byte random block cannot shrink below
        // ~19000; the near repeat must be found.
        assert!(enc.len() < 19_500 && enc.len() > 18_900, "L{level}: {}", enc.len());
    }
}

#[test]
fn random_lengths_never_panic() {
    for len in (0..64).chain([255, 256, 257, 4095, 4096, 4097]) {
        for seed in 0..3u64 {
            let mut data = noise(seed * 1000 + len as u64, len);
            if seed == 1 {
                data.iter_mut().for_each(|b| *b &= 3); // tiny alphabet: many matches
            }
            if seed == 2 {
                data.iter_mut().enumerate().for_each(|(i, b)| *b = if i % 7 < 5 { b'x' } else { *b });
            }
            for level in [0, 2, 4, 9] {
                raw_roundtrip(&data, &opts(level), true);
            }
        }
    }
}

#[test]
fn deterministic_output() {
    let data = wordy(5, 20_000);
    for level in [0, 6] {
        assert_eq!(encode_lzma_raw(&data, &opts(level), true), encode_lzma_raw(&data, &opts(level), true));
    }
}

#[test]
fn higher_levels_compress_better() {
    let data = wordy(13, 60_000);
    let size = |l| encode_lzma_raw(&data, &opts(l), false).unwrap().len();
    let (s0, s3, s6, s9) = (size(0), size(3), size(6), size(9));
    assert!(s0 >= s3 && s3 > s6 && s6 >= s9, "{s0} {s3} {s6} {s9}");
    assert!(s6 * 100 < data.len() * 40, "wordy should compress to < 40%: {s6}");
}

#[test]
fn invalid_options_rejected() {
    let base = opts(6);
    let bad = [
        LzmaEncoderOptions { lc: 9, ..base },
        LzmaEncoderOptions { lp: 5, ..base },
        LzmaEncoderOptions { pb: 5, ..base },
        LzmaEncoderOptions { dictionary_size: 4095, ..base },
        LzmaEncoderOptions { dictionary_size: MAX_DICTIONARY + 1, ..base },
        LzmaEncoderOptions { nice_len: 1, ..base },
        LzmaEncoderOptions { nice_len: 274, ..base },
        LzmaEncoderOptions { depth: 0, ..base },
        LzmaEncoderOptions { depth: 4097, ..base },
    ];
    for o in bad {
        assert_eq!(o.validate(), Err(LzmaEncodeError::InvalidOptions), "{o:?}");
        assert_eq!(encode_lzma_raw(b"abc", &o, true), Err(LzmaEncodeError::InvalidOptions));
        assert_eq!(encode_lzma_alone(b"abc", &o, false), Err(LzmaEncodeError::InvalidOptions));
    }
    assert_eq!(LzmaEncoderOptions::preset(10), Err(LzmaEncodeError::InvalidOptions));
    assert!(LzmaEncoderOptions { dictionary_size: MAX_DICTIONARY, ..base }.validate().is_ok());
}

#[test]
fn dictionary_helpers() {
    assert_eq!(round_dictionary_size(0), 4096);
    assert_eq!(round_dictionary_size(6 << 10), 6 << 10);
    assert_eq!(round_dictionary_size((6 << 10) + 1), 8 << 10);
    assert_eq!(round_dictionary_size(MAX_DICTIONARY), MAX_DICTIONARY);
    assert_eq!(effective_dictionary_size(64 << 20, 0), 4096);
    assert_eq!(effective_dictionary_size(64 << 20, 20_557), 24 << 10);
    assert_eq!(effective_dictionary_size(1 << 20, usize::MAX), 1 << 20);
}
