// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for the legacy read-only formats: LHA/LZH, ARJ, ZIP Shrink/Implode,
//! the `.Z` seam, and their routing through `archive_open::open_named`.
//!
//! Fixtures: tests/gen/legacy.py (hand-written stdlib-only encoders; every
//! LZH/ARJ/ZIP fixture was verified with `7zz t`, and the .Z fixtures are
//! byte-identical to the system `compress`). Expected member contents are
//! recorded as (length, CRC-32) in tests/fixtures/legacy/MANIFEST.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sediment_engine::archive_open::open_named;
use sediment_engine::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use sediment_engine::arj_read::{ArjError, ArjLimits, parse_arj, read_arj_entry};
use sediment_engine::crc16_arc::crc16_arc;
use sediment_engine::crc32::crc32;
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::legacy_open::{
    ArjReader, LegacyFormat, LzhReader, ZipLegacyReader, detect_legacy, open_legacy, open_z_with, z_member_name,
};
use sediment_engine::lzh_decode::{LhMethod, LzhDecodeError, decode_arj_fastest, decode_arj_huffman, decode_lh};
use sediment_engine::lzh_read::{LzhError, LzhLimits, parse_lzh, read_lzh_entry};
use sediment_engine::zip_legacy::{ZipLegacyError, explode, unshrink};

fn fxp(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy").join(name)
}

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(fxp(name)).unwrap()
}

fn manifest() -> HashMap<String, (usize, u32)> {
    let text = String::from_utf8(fx("MANIFEST")).unwrap();
    text.lines()
        .map(|l| {
            let mut it = l.split_whitespace();
            let k = it.next().unwrap().to_string();
            let n = it.next().unwrap().parse().unwrap();
            let c = u32::from_str_radix(it.next().unwrap(), 16).unwrap();
            (k, (n, c))
        })
        .collect()
}

fn assert_content(data: &[u8], key: &str) {
    let m = manifest();
    let (n, c) = m[key];
    assert_eq!(data.len(), n, "{key} length");
    assert_eq!(crc32(data), c, "{key} crc");
}

fn open<'a>(bytes: &'a [u8], name: &str) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    open_named(bytes, name.as_bytes(), ReaderLimits::default())
}

/// (archive, [(path, manifest key or "" for dirs)])
const LZH_CASES: &[(&str, &[(&str, &str)])] = &[
    ("lh5_l0.lzh", &[("text1.txt", "text1")]),
    ("lh5_l1.lzh", &[("docs/text2.txt", "text2"), ("small.txt", "small")]),
    ("lh6_l2.lzh", &[("dir", ""), ("dir/mixed.bin", "mixed"), ("noise.bin", "noise")]),
    ("lh7_l2.lzh", &[("mixed.bin", "mixed")]),
    ("lh4_l1.lzh", &[("text1.txt", "text1")]),
    ("lh5_rle.lzh", &[("zeros.bin", "zeros5000"), ("one.bin", "A"), ("empty.bin", "empty")]),
];

const ARJ_CASES: &[(&str, &[(&str, &str)])] = &[
    ("m1.arj", &[("text2.txt", "text2"), ("sub/mixed.bin", "mixed40k")]),
    ("m4.arj", &[("text1.txt", "text1"), ("noise.bin", "noise")]),
    ("m0_dir.arj", &[("folder", ""), ("folder/small.txt", "small"), ("m3.bin", "text1")]),
];

const ZIP_CASES: &[(&str, &[(&str, &str)])] = &[
    (
        "shrink.zip",
        &[
            ("text2.txt", "text2"),
            ("mixed.bin", "mixed60k"),
            ("small.txt", "small"),
            ("noise.bin", "noise16k"),
            ("text5.txt", "text5"),
        ],
    ),
    (
        "implode.zip",
        &[("i4k2.txt", "text1"), ("i8k2.bin", "mixed20k"), ("i4k3.txt", "text2"), ("i8k3.bin", "mixed30k")],
    ),
    ("small_legacy.zip", &[("s.txt", "text1_3k"), ("i2.txt", "text1_3k"), ("i3.txt", "text1_3k")]),
];

fn check_reader(r: &dyn ArchiveReader, expect: &[(&str, &str)], archive: &str) {
    let entries = r.entries();
    assert_eq!(entries.len(), expect.len(), "{archive}");
    for (i, (path, key)) in expect.iter().enumerate() {
        assert_eq!(entries[i].path, path.as_bytes(), "{archive} #{i}");
        let data = r.read(i).unwrap_or_else(|e| panic!("{archive} {path}: {e:?}"));
        if key.is_empty() {
            assert_eq!(entries[i].kind, EntryKind::Dir, "{archive} {path}");
            assert!(data.is_empty());
        } else {
            assert_eq!(entries[i].kind, EntryKind::File, "{archive} {path}");
            assert_eq!(entries[i].size, data.len() as u64);
            assert_content(&data, key);
        }
    }
    assert_eq!(r.read(expect.len()), Err(ReaderError::OutOfRange));
}

// ---------------------------------------------------------------------------
// Differential: every fixture decodes to the generator's input
// ---------------------------------------------------------------------------

#[test]
fn lzh_fixtures_via_open_named() {
    for (name, expect) in LZH_CASES {
        let b = fx(name);
        let r = open(&b, name).unwrap();
        assert_eq!(r.format(), ArchiveFormat::Lzh, "{name}");
        check_reader(r.as_ref(), expect, name);
    }
}

#[test]
fn arj_fixtures_via_open_named() {
    for (name, expect) in ARJ_CASES {
        let b = fx(name);
        let r = open(&b, name).unwrap();
        assert_eq!(r.format(), ArchiveFormat::Arj, "{name}");
        check_reader(r.as_ref(), expect, name);
        for i in 0..expect.len() {
            if expect[i].1.is_empty() {
                assert_eq!(r.crc32(i), None);
            } else {
                assert_eq!(r.crc32(i), Some(crc32(&r.read(i).unwrap())));
            }
        }
    }
}

#[test]
fn zip_legacy_fixtures_via_open_named() {
    for (name, expect) in ZIP_CASES {
        let b = fx(name);
        let r = open(&b, name).unwrap();
        assert_eq!(r.format(), ArchiveFormat::Zip, "{name}");
        check_reader(r.as_ref(), expect, name);
        assert_eq!(r.entries()[0].mode, Some(0o644));
        assert!(r.entries()[0].mtime.is_some());
    }
}

#[test]
fn lzh_metadata() {
    let b = fx("lh5_l1.lzh");
    let e = parse_lzh(&b, LzhLimits::default()).unwrap();
    assert_eq!(e.len(), 2);
    assert_eq!(&e[0].method, b"-lh5-");
    assert_eq!(e[0].level, 1);
    assert_eq!(e[0].unix_mode, Some(0o100644));
    assert_eq!(e[0].mtime, Some(1_589_723_130)); // 0x54 record
    assert_eq!(e[0].os_id, Some(b'U'));
    assert_eq!(&e[1].method, b"-lh0-");
    assert_eq!(e[1].mtime, Some(1_589_723_130)); // DOS stamp 2020-05-17 13:45:30
    assert_eq!(read_lzh_entry(&e[1], 100).unwrap(), fx("src_small.bin"));
    assert_eq!(e[1].crc16, crc16_arc(&fx("src_small.bin")));

    let b = fx("lh6_l2.lzh");
    let r = LzhReader::new(&b, ReaderLimits::default(), 0).unwrap();
    let raw = r.raw_entries();
    assert!(raw[0].is_dir());
    assert_eq!(raw[1].level, 2);
    assert_eq!(&raw[1].method, b"-lh6-");
    assert_eq!(r.entries()[0].mode, Some(0o755));
    assert_eq!(r.entries()[1].mode, Some(0o600));
    assert_eq!(r.entries()[1].mtime, Some(1_589_723_130));
    assert_eq!(r.entries()[2].mode, None);
}

#[test]
fn arj_metadata() {
    let b = fx("m0_dir.arj");
    let (main, e) = parse_arj(&b, ArjLimits::default()).unwrap();
    assert_eq!(main.offset, 0);
    assert_eq!(main.name, b"test.arj");
    assert_eq!(e.len(), 3);
    assert!(e[0].is_dir());
    assert_eq!(e[1].method, 0);
    assert_eq!(e[2].method, 3);
    assert_eq!(e[1].mtime, Some(1_589_723_130));
    assert_eq!(e[1].unix_mode(), None); // MS-DOS host
    assert_eq!(read_arj_entry(&e[1], 100).unwrap(), fx("src_small.bin"));
}

// ---------------------------------------------------------------------------
// Self-extractor stubs, detection, routing
// ---------------------------------------------------------------------------

fn with_stub(b: &[u8]) -> Vec<u8> {
    let mut v = b"MZ".to_vec();
    v.extend((0..3000u32).map(|i| (i * 7 + 3) as u8));
    v.extend_from_slice(b);
    v
}

#[test]
fn sfx_archives_by_name() {
    let arj = with_stub(&fx("m4.arj"));
    assert_eq!(detect_legacy(&arj), None);
    assert_eq!(open(&arj, "m4.bin").err(), Some(ReaderError::Unsupported));
    let r = open(&arj, "setup.EXE").unwrap();
    assert_eq!(r.format(), ArchiveFormat::Arj);
    check_reader(r.as_ref(), ARJ_CASES[1].1, "sfx arj");
    let r = open(&arj, "x.arj").unwrap();
    assert_eq!(r.entries().len(), 2);

    let lzh = with_stub(&fx("lh5_l1.lzh"));
    let r = open(&lzh, "setup.exe").unwrap();
    assert_eq!(r.format(), ArchiveFormat::Lzh);
    check_reader(r.as_ref(), LZH_CASES[1].1, "sfx lzh");
    let r = open_legacy(&lzh, b"a.LZH", ReaderLimits::default()).unwrap();
    assert_eq!(r.entries().len(), 2);
}

#[test]
fn detection() {
    assert_eq!(detect_legacy(&fx("lh5_l0.lzh")), Some(LegacyFormat::Lzh));
    assert_eq!(detect_legacy(&fx("m1.arj")), Some(LegacyFormat::Arj));
    assert_eq!(detect_legacy(&fx("text16.Z")), Some(LegacyFormat::CompressZ));
    assert_eq!(detect_legacy(b""), None);
    assert_eq!(detect_legacy(b"\x60\xea\x00\x00"), None);
    assert_eq!(open(b"plain text, not an archive", "x.txt").err(), Some(ReaderError::Unsupported));
}

// ---------------------------------------------------------------------------
// .Z seam (decoder owned by forge lzw_z)
// ---------------------------------------------------------------------------

#[test]
fn z_naming() {
    assert_eq!(z_member_name(b"dir/notes.txt.Z"), (b"notes.txt".to_vec(), false));
    assert_eq!(z_member_name(b"src.tar.Z"), (b"src.tar".to_vec(), true));
    assert_eq!(z_member_name(b"src.taz"), (b"src.tar".to_vec(), true));
    assert_eq!(z_member_name(b"SRC.TZ"), (b"SRC.tar".to_vec(), true));
    assert_eq!(z_member_name(b"plain"), (b"plain".to_vec(), false));
}

#[test]
fn z_seam_with_stub_decoder() {
    fn stub(input: &[u8], max: usize) -> Result<Vec<u8>, ReaderError> {
        let out = input[3..].to_vec();
        if out.len() > max { Err(ReaderError::LimitExceeded) } else { Ok(out) }
    }
    let mut z = vec![0x1f, 0x9d, 0x90];
    z.extend_from_slice(b"payload");
    let r = open_z_with(&z, b"a/notes.txt.Z", ReaderLimits::default(), stub).unwrap();
    assert_eq!(r.format(), ArchiveFormat::CompressZ);
    assert_eq!(r.entries()[0].path, b"notes.txt");
    assert_eq!(r.read(0).unwrap(), b"payload");
    let small = ReaderLimits { max_total_size: 3, ..ReaderLimits::default() };
    assert_eq!(open_z_with(&z, b"n.Z", small, stub).err(), Some(ReaderError::LimitExceeded));
    assert_eq!(open_z_with(b"PK\x03\x04", b"n.Z", ReaderLimits::default(), stub).err(), Some(ReaderError::Invalid));
    // A .tar.Z goes through the tar reader; garbage tar data is an error, not a panic.
    assert!(open_z_with(&z, b"n.tar.Z", ReaderLimits::default(), stub).is_err());
}

#[test]
fn z_fixtures_route_to_seam() {
    // Until forge's lzw_z is harvested the seam reports Unsupported.
    for name in ["text16.Z", "text9.Z", "text12_clear.Z", "noblock12.Z"] {
        let b = fx(name);
        if sediment_engine::legacy_open::Z_DECODER.is_none() {
            assert_eq!(open(&b, name).err(), Some(ReaderError::Unsupported), "{name}");
        } else {
            let r = open(&b, name).unwrap();
            let key = if name == "text16.Z" || name == "text12_clear.Z" { "text2" } else { "text1" };
            assert_content(&r.read(0).unwrap(), key);
        }
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[test]
fn limits_are_enforced() {
    let b = fx("lh5_l1.lzh");
    let few = ReaderLimits { max_entries: 1, ..ReaderLimits::default() };
    assert_eq!(open(&b, "x.lzh").map(|_| ()).err(), None);
    assert_eq!(open_named(&b, b"x.lzh", few).err(), Some(ReaderError::LimitExceeded));
    let tiny_total = ReaderLimits { max_total_size: 100, ..ReaderLimits::default() };
    assert_eq!(open_named(&b, b"x.lzh", tiny_total).err(), Some(ReaderError::LimitExceeded));
    let tiny_entry = ReaderLimits { max_entry_size: 100, ..ReaderLimits::default() };
    let r = open_named(&b, b"x.lzh", tiny_entry).unwrap();
    assert_eq!(r.read(0), Err(ReaderError::LimitExceeded));
    assert_eq!(r.read(1).unwrap(), fx("src_small.bin"));

    let a = fx("m1.arj");
    assert_eq!(open_named(&a, b"x.arj", few).err(), Some(ReaderError::LimitExceeded));
    let r = open_named(&a, b"x.arj", tiny_entry).unwrap();
    assert_eq!(r.read(0), Err(ReaderError::LimitExceeded));

    let z = fx("shrink.zip");
    let r = open_named(&z, b"x.zip", tiny_entry).unwrap();
    assert_eq!(r.read(0), Err(ReaderError::LimitExceeded));
    assert_eq!(r.read(2).unwrap(), fx("src_small.bin"));

    let e = parse_lzh(&b, LzhLimits::default()).unwrap();
    assert_eq!(read_lzh_entry(&e[0], 10), Err(LzhError::LimitExceeded));
    let (_, e) = parse_arj(&a, ArjLimits::default()).unwrap();
    assert_eq!(read_arj_entry(&e[0], 10), Err(ArjError::LimitExceeded));
}

#[test]
fn decoder_output_caps() {
    assert_eq!(decode_lh(&[0; 4], LhMethod::Lh5, 100, 99), Err(LzhDecodeError::LimitExceeded));
    assert_eq!(decode_arj_huffman(&[0; 4], 100, 99), Err(LzhDecodeError::LimitExceeded));
    assert_eq!(decode_arj_fastest(&[0; 4], 100, 99), Err(LzhDecodeError::LimitExceeded));
    assert_eq!(unshrink(&[0; 4], 100, 99), Err(ZipLegacyError::LimitExceeded));
    assert_eq!(explode(&[0; 4], 0, 100, 99), Err(ZipLegacyError::LimitExceeded));
    // Huge declared sizes are refused before any allocation.
    assert_eq!(decode_lh(&[0; 4], LhMethod::Lh7, usize::MAX, usize::MAX - 1), Err(LzhDecodeError::LimitExceeded));
}

// ---------------------------------------------------------------------------
// Malformed input: Err, never panic
// ---------------------------------------------------------------------------

fn exercise(bytes: &[u8], name: &str) {
    let limits = ReaderLimits { max_total_size: 1 << 22, max_entry_size: 1 << 21, ..ReaderLimits::default() };
    if let Ok(r) = open_named(bytes, name.as_bytes(), limits) {
        for i in 0..r.entries().len() {
            let _ = r.read(i);
        }
    }
}

const ALL: &[&str] = &[
    "lh5_l0.lzh",
    "lh5_l1.lzh",
    "lh6_l2.lzh",
    "lh7_l2.lzh",
    "lh4_l1.lzh",
    "lh5_rle.lzh",
    "m1.arj",
    "m4.arj",
    "m0_dir.arj",
    "small_legacy.zip",
];

#[test]
fn truncation_never_panics_and_fails() {
    for name in ALL {
        let b = fx(name);
        let step = (b.len() / 97).max(1);
        let mut cut = 0;
        while cut < b.len() {
            exercise(&b[..cut], name);
            cut += step;
        }
        // Cutting into the last member's payload must not decode cleanly
        // (LZH: drop the end marker and one payload byte; ARJ: the 4-byte
        // end marker and one payload byte).
        let cut = if name.ends_with(".lzh") { 2 } else if name.ends_with(".arj") { 5 } else { continue };
        if let Ok(r) = open(&b[..b.len() - cut], name) {
            let n = r.entries().len();
            assert!((0..n).any(|i| r.read(i).is_err()), "{name}: truncated archive read cleanly");
        }
    }
}

#[test]
fn bit_flips_never_panic() {
    for name in ALL {
        let b = fx(name);
        // Dense near the headers, sparse in the payload.
        let step = (b.len() / 40).max(1);
        let mut i = 0;
        while i < b.len() {
            for mask in [0x01u8, 0xFF] {
                let mut m = b.clone();
                m[i] ^= mask;
                exercise(&m, name);
            }
            i += if i < 96 { 1 } else { step };
        }
    }
}

#[test]
fn payload_corruption_is_detected() {
    // Flip bytes inside compressed payloads: decoding either fails or the
    // CRC check catches it; it never returns wrong data silently.
    for name in ["lh5_l0.lzh", "m4.arj", "m1.arj", "lh7_l2.lzh"] {
        let b = fx(name);
        let good = open(&b, name).unwrap();
        let want: Vec<_> = (0..good.entries().len()).map(|i| good.read(i).unwrap()).collect();
        for at in (200..b.len() - 8).step_by(131) {
            let mut m = b.clone();
            m[at] ^= 0x5A;
            if let Ok(r) = open(&m, name) {
                for (i, w) in want.iter().enumerate().take(r.entries().len()) {
                    if let Ok(d) = r.read(i) {
                        assert_eq!(&d, w, "{name} flip@{at} entry {i}");
                    }
                }
            }
        }
    }
}

#[test]
fn hostile_lzh_headers() {
    let good = fx("lh5_l0.lzh");
    // header checksum
    let mut m = good.clone();
    m[1] ^= 1;
    assert_eq!(parse_lzh(&m, LzhLimits::default()).err(), Some(LzhError::BadChecksum));
    // level 3 is unsupported
    let mut m = good.clone();
    m[20] = 3;
    assert_eq!(parse_lzh(&m, LzhLimits::default()).err(), Some(LzhError::Unsupported));
    // compressed size beyond the input
    let mut m = good.clone();
    m[7..11].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    let sum = m[2..usize::from(m[0]) + 2].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    m[1] = sum;
    assert_eq!(parse_lzh(&m, LzhLimits::default()).err(), Some(LzhError::Truncated));
    // unknown method lists fine but reads Unsupported
    let mut m = good.clone();
    m[2..7].copy_from_slice(b"-lzs-");
    let sum = m[2..usize::from(m[0]) + 2].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    m[1] = sum;
    let e = parse_lzh(&m, LzhLimits::default()).unwrap();
    assert_eq!(read_lzh_entry(&e[0], 1 << 20), Err(LzhError::Unsupported));
    // stored member whose data CRC does not match
    let mut m = fx("lh5_l1.lzh");
    let last = m.len() - 2;
    m[last] ^= 0x20; // inside "small.txt" stored data
    let e = parse_lzh(&m, LzhLimits::default()).unwrap();
    assert_eq!(read_lzh_entry(&e[1], 100), Err(LzhError::CrcMismatch));
    // level-2 header CRC (0x00 record) is verified
    let mut m = fx("lh7_l2.lzh");
    m[11] ^= 1; // original size field
    assert_eq!(parse_lzh(&m, LzhLimits::default()).err(), Some(LzhError::BadChecksum));
    // level-2 extended header with a size < 3 (would not advance)
    let mut m = fx("lh7_l2.lzh");
    m[24] = 1;
    m[25] = 0;
    assert_eq!(parse_lzh(&m, LzhLimits::default()).err(), Some(LzhError::BadHeader));
    // name length limit
    let small = LzhLimits { max_name: 3, ..LzhLimits::default() };
    assert_eq!(parse_lzh(&good, small).err(), Some(LzhError::LimitExceeded));
    let one = LzhLimits { max_entries: 1, ..LzhLimits::default() };
    assert_eq!(parse_lzh(&fx("lh5_l1.lzh"), one).err(), Some(LzhError::LimitExceeded));
}

#[test]
fn hostile_arj_headers() {
    let good = fx("m4.arj");
    // main header CRC
    let mut m = good.clone();
    m[10] ^= 1;
    assert_eq!(parse_arj(&m, ArjLimits::default()).err(), Some(ArjError::BadChecksum));
    // basic header size above 2600
    let mut m = good.clone();
    m[2..4].copy_from_slice(&3000u16.to_le_bytes());
    assert!(parse_arj(&m, ArjLimits::default()).is_err());
    // missing end marker
    assert_eq!(parse_arj(&good[..good.len() - 4], ArjLimits::default()).err(), Some(ArjError::Truncated));
    // garbled member is listed but not decoded
    let (_, mut e) = parse_arj(&good, ArjLimits::default()).unwrap();
    e[0].flags |= 0x01;
    assert_eq!(read_arj_entry(&e[0], 1 << 20), Err(ArjError::Unsupported));
    e[1].method = 7;
    assert_eq!(read_arj_entry(&e[1], 1 << 20), Err(ArjError::Unsupported));
    let one = ArjLimits { max_entries: 1, ..ArjLimits::default() };
    assert_eq!(parse_arj(&good, one).err(), Some(ArjError::LimitExceeded));
    // no scan: a stub hides the header
    let stub = with_stub(&good);
    let no_scan = ArjLimits { max_scan: 0, ..ArjLimits::default() };
    assert!(parse_arj(&stub, no_scan).is_err());
    assert!(ArjReader::new(&stub, ReaderLimits::default(), 0).is_err());
}

#[test]
fn hostile_codec_streams() {
    // Junk streams either fail cleanly or decode to exactly the declared
    // size (all-zero bits are a valid "single symbol" LHA block).
    for fill in [0x00u8, 0xFF, 0x55, 0xA7] {
        let junk = vec![fill; 512];
        let ok_len = |r: Result<Vec<u8>, LzhDecodeError>| r.map_or(true, |v| v.len() == 100_000);
        for m in [LhMethod::Lh4, LhMethod::Lh5, LhMethod::Lh6, LhMethod::Lh7] {
            assert!(ok_len(decode_lh(&junk, m, 100_000, 100_000)));
        }
        assert!(ok_len(decode_arj_huffman(&junk, 100_000, 100_000)));
        assert!(unshrink(&junk, 100_000, 100_000).map_or(true, |v| v.len() == 100_000));
        for flags in [0u16, 2, 4, 6] {
            assert!(explode(&junk, flags, 100_000, 100_000).map_or(true, |v| v.len() == 100_000));
        }
    }
    assert_eq!(decode_lh(&[0; 16], LhMethod::Lh5, 1000, 1000), Ok(vec![0; 1000]));
    assert!(decode_lh(&[0xFF; 16], LhMethod::Lh5, 1000, 1000).is_err());
    // ARJ method 4 on zero bits is a stream of NUL literals: it decodes
    // until the input runs out.
    assert_eq!(decode_arj_fastest(&[0; 9], 8, 8), Ok(vec![0; 8]));
    assert_eq!(decode_arj_fastest(&[0; 9], 9, 9), Err(LzhDecodeError::Truncated));
    // A match before the start of the output is invalid in ARJ/LHA.
    // c=1 (len 3): bits "1" "0" then 1 width bit 0 => value 1; pos: "0" + 9 bits 0 => 0.
    let bits = [0b1000_0000u8, 0, 0];
    assert_eq!(decode_arj_fastest(&bits, 3, 3), Err(LzhDecodeError::InvalidData));
}

#[test]
fn zip_reader_metadata() {
    let b = fx("implode.zip");
    let r = ZipLegacyReader::new(&b, ReaderLimits::default()).unwrap();
    assert_eq!(r.entries().len(), 4);
    for i in 0..4 {
        assert_eq!(r.crc32(i), Some(crc32(&r.read(i).unwrap())));
    }
    // corrupt the stored CRC in both headers => CrcMismatch
    let mut m = b.clone();
    let crc = r.crc32(0).unwrap().to_le_bytes();
    let mut hits = 0;
    for i in 0..m.len() - 4 {
        if m[i..i + 4] == crc {
            m[i] ^= 1;
            hits += 1;
        }
    }
    assert_eq!(hits, 2);
    let r = ZipLegacyReader::new(&m, ReaderLimits::default()).unwrap();
    assert_eq!(r.read(0), Err(ReaderError::CrcMismatch));
}
