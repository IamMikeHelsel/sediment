// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7z writer tests: round trips through the in-tree 7z reader, NUMBER
//! encoding, block planning, determinism, hostile options/limits, the
//! `sediment a x.7z` run function, and committed fixtures.
//!
//! Fixtures (`tests/fixtures/sevenz_write/`): archives produced by this
//! writer from the deterministic inputs in [`fixture_items`]. Each was
//! checked by (a) `tests/gen/sevenz_write.py`, an independent Python-stdlib
//! 7z parser that decodes LZMA/LZMA2/BCJ with the `lzma` module and compares
//! every file against the same inputs, and (b) the pinned 7-Zip 26.04 `7zz`
//! oracle (`7zz t`, `7zz x` byte comparison, `7zz l -slt` committed as
//! `*.slt.txt`; recipe in `tests/gen/sevenz_write_oracle.sh`).
//! Regenerate with `SEVENZ_WRITE_REGEN=<dir> cargo test --test sevenz_write regen`.

use std::ffi::OsString;

use sediment_engine::crc32::crc32;
use sediment_engine::filter_bcj::{BcjArch, bcj_decode};
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::lzma_decode::decode_lzma_raw;
use sediment_engine::lzma_properties::LzmaProperties;
use sediment_engine::lzma2_decode::{decode_lzma2, dictionary_size_from_byte};
use sediment_engine::sevenz_header::{
    FolderDecoder, SevenZLimits, SevenZReadError, parse_archive_header, parse_signature_header, read_number,
};
use sediment_engine::sevenz_read::{SevenZArchive, filetime_to_unix};
use sediment_engine::sevenz_write::{
    SevenZItem, SevenZMethod, SevenZWriteError, SevenZWriteLimits, SevenZWriteOptions, create_7z, unix_attributes,
    unix_to_filetime, write_7z, write_number,
};
use sediment_engine::cli_add_7z::{parse_7z_add_args, run_add_7z};

type E = SevenZWriteError;

// ---------------------------------------------------------------------------
// Test decoder: LZMA, LZMA2 and BCJ through the in-tree decoders.
// ---------------------------------------------------------------------------

struct Dec;

impl FolderDecoder for Dec {
    fn decode(&self, id: &[u8], props: &[u8], input: &[u8], size: u64) -> Result<Vec<u8>, SevenZReadError> {
        fn bad<T>(_: T) -> SevenZReadError {
            SevenZReadError::DecoderFailed
        }
        let n = usize::try_from(size).map_err(|_| SevenZReadError::LimitExceeded)?;
        match id {
            [3, 1, 1] => {
                if props.len() != 5 {
                    return Err(SevenZReadError::Malformed);
                }
                let b = props[0];
                let p = LzmaProperties {
                    lc: b % 9,
                    lp: b / 9 % 5,
                    pb: b / 45,
                    dictionary_size: u32::from_le_bytes([props[1], props[2], props[3], props[4]]),
                };
                Ok(decode_lzma_raw(input, p, Some(size), 1 << 31, n).map_err(bad)?.0)
            }
            [0x21] => {
                let d = dictionary_size_from_byte(*props.first().ok_or(SevenZReadError::Malformed)?).map_err(bad)?;
                let (out, used) = decode_lzma2(input, d, 1 << 31, n).map_err(bad)?;
                if used != input.len() {
                    return Err(SevenZReadError::DecoderFailed);
                }
                Ok(out)
            }
            _ => {
                let mut v = 0u64;
                for &x in id {
                    v = v << 8 | x as u64;
                }
                let arch = BcjArch::from_sevenz_method_id(v).map_err(|_| SevenZReadError::UnsupportedMethod)?;
                bcj_decode(arch, 0, input, n).map_err(bad)
            }
        }
    }
}

fn lim() -> SevenZLimits {
    SevenZLimits::default()
}

/// Open with the in-tree reader and return `(name, is_dir, data, attributes, mtime)`.
type ReadBack = (String, bool, Vec<u8>, Option<u32>, Option<u64>);

fn read_back(bytes: &[u8]) -> Vec<ReadBack> {
    let ar = SevenZArchive::open(bytes, &Dec, lim()).expect("open");
    ar.entries()
        .iter()
        .map(|e| {
            let data = ar.extract_entry(e.index, &Dec).expect("extract");
            (e.name.clone(), e.is_dir, data, e.attributes, e.mtime)
        })
        .collect()
}

fn opts(method: SevenZMethod, solid: bool, hc: bool) -> SevenZWriteOptions {
    let mut o = SevenZWriteOptions::level(5).unwrap();
    o.method = method;
    o.solid = solid;
    o.compress_header = hc;
    o.lzma.dictionary_size = 1 << 16;
    o
}

fn wl() -> SevenZWriteLimits {
    SevenZWriteLimits::default()
}

// ---------------------------------------------------------------------------
// Deterministic fixture inputs
// ---------------------------------------------------------------------------

const MTIME: i64 = 1_709_618_828; // 2024-03-05 06:07:08 UTC

struct Owned {
    name: String,
    kind: EntryKind,
    data: Vec<u8>,
    mode: u32,
    link: Vec<u8>,
}

fn x86_like(n: usize) -> Vec<u8> {
    // Pseudo machine code: CALL rel32 (E8) and JMP rel32 (E9) sprinkled
    // between filler, with targets that repeat so BCJ helps LZMA.
    let mut v = Vec::with_capacity(n);
    let mut i = 0u32;
    while v.len() < n {
        v.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        v.push(if i.is_multiple_of(3) { 0xe9 } else { 0xe8 });
        let target = 0x1000u32.wrapping_add((i % 17) * 64).wrapping_sub(v.len() as u32 + 4);
        v.extend_from_slice(&target.to_le_bytes());
        v.extend_from_slice(&[0x90, 0xc3]);
        i += 1;
    }
    v.truncate(n);
    v
}

fn fixture_items() -> Vec<Owned> {
    let f = |name: &str, data: Vec<u8>, mode: u32| Owned { name: name.into(), kind: EntryKind::File, data, mode, link: vec![] };
    let d = |name: &str| Owned { name: name.into(), kind: EntryKind::Directory, data: vec![], mode: 0o755, link: vec![] };
    let a: String = (0..60).map(|i| format!("line {i:04} alpha beta gamma\n")).collect();
    let b: Vec<u8> = (0..700u32).map(|i| ((i * 7 + 3) & 255) as u8).collect();
    vec![
        d("dir"),
        d("dir/sub"),
        d("emptydir"),
        f("a.txt", a.into_bytes(), 0o644),
        f("b.bin", b, 0o600),
        f("dir/sub/nested.txt", b"nested\n".to_vec(), 0o644),
        f("empty.txt", vec![], 0o644),
        f("hello.txt", b"Hello, 7z!\n".to_vec(), 0o640),
        f("h\u{e9}llo_\u{65e5}\u{672c}.txt", b"unicode name\n".to_vec(), 0o444),
        f("prog.bin", x86_like(5000), 0o755),
        Owned { name: "link".into(), kind: EntryKind::Symlink, data: vec![], mode: 0o777, link: b"hello.txt".to_vec() },
    ]
}

fn entries(v: &[Owned]) -> Vec<ArchiveEntry<'_>> {
    v.iter()
        .map(|o| ArchiveEntry { name: o.name.as_bytes(), kind: o.kind, data: &o.data, mtime: MTIME, mode: o.mode, link_target: &o.link })
        .collect()
}

fn variants() -> Vec<(&'static str, SevenZWriteOptions)> {
    use SevenZMethod::*;
    let mut v = vec![
        ("copy_solid_plain", opts(Copy, true, false)),
        ("copy_nonsolid_hc", opts(Copy, false, true)),
        ("lzma_solid_hc", opts(Lzma, true, true)),
        ("lzma_nonsolid_plain", opts(Lzma, false, false)),
        ("lzma2_solid_hc", opts(Lzma2, true, true)),
        ("lzma2_nonsolid_hc", opts(Lzma2, false, true)),
    ];
    let mut bcj = opts(Lzma2, true, true);
    bcj.filter = Some(BcjArch::X86);
    v.push(("lzma2_bcj_hc", bcj));
    let mut bcj1 = opts(Lzma, false, true);
    bcj1.filter = Some(BcjArch::X86);
    v.push(("lzma_bcj_nonsolid_hc", bcj1));
    let mut blocks = opts(Lzma2, true, true);
    blocks.solid_block_bytes = 1024;
    v.push(("lzma2_blocks_hc", blocks));
    let mut fast = SevenZWriteOptions::level(1).unwrap();
    fast.solid_block_files = 3;
    v.push(("level1_files3", fast));
    v
}

fn build(name: &str) -> Vec<u8> {
    let items = fixture_items();
    let o = variants().into_iter().find(|(n, _)| *n == name).unwrap().1;
    create_7z(&entries(&items), &o, wl()).unwrap()
}

macro_rules! fx {
    ($p:expr) => {
        std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz_write/").to_string() + $p)
    };
}

fn check_fixture_contents(bytes: &[u8]) {
    let items = fixture_items();
    let got = read_back(bytes);
    assert_eq!(got.len(), items.len());
    for (g, o) in got.iter().zip(&items) {
        assert_eq!(g.0, o.name);
        assert_eq!(g.1, o.kind == EntryKind::Directory, "{}", o.name);
        let want: &[u8] = if o.kind == EntryKind::Symlink { &o.link } else { &o.data };
        assert_eq!(g.2, want, "{}", o.name);
        assert_eq!(g.3, Some(unix_attributes(o.kind, o.mode)), "{}", o.name);
        assert_eq!(g.4.map(filetime_to_unix), Some((MTIME, 0)));
    }
}

#[test]
fn roundtrip_all_variants() {
    for (name, _) in variants() {
        let bytes = build(name);
        check_fixture_contents(&bytes);
        // Header parses the same through the structure layer.
        let h = parse_archive_header(&bytes, &Dec, &lim()).unwrap();
        assert_eq!(h.files.len(), fixture_items().len(), "{name}");
    }
}

#[test]
fn committed_fixtures_are_reproduced_byte_for_byte() {
    for (name, _) in variants() {
        let committed = fx!(&format!("{name}.7z")).unwrap_or_else(|_| panic!("missing fixture {name}"));
        assert!(build(name) == committed, "{name}: writer output changed");
        check_fixture_contents(&committed);
    }
}

// ---------------------------------------------------------------------------
// 7zz l -slt comparison
// ---------------------------------------------------------------------------

type Kv = Vec<(String, String)>;

fn slt_items(s: &str) -> (Kv, Vec<Kv>) {
    let mut parts = s.split("\n----------\n");
    let head = parts.next().unwrap();
    let body = parts.next().expect("slt item section");
    let kv = |b: &str| -> Vec<(String, String)> {
        b.lines()
            .filter_map(|l| l.split_once(" = ").or_else(|| l.strip_suffix(" =").map(|k| (k, ""))))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    (kv(head), body.split("\n\n").filter(|b| !b.trim().is_empty()).map(kv).collect())
}

fn fmt_attr(a: Option<u32>) -> String {
    let Some(a) = a else { return String::new() };
    let mut s = String::new();
    for (bit, c) in [(0x1, 'R'), (0x2, 'H'), (0x4, 'S'), (0x10, 'D'), (0x20, 'A')] {
        if a & bit != 0 {
            s.push(c);
        }
    }
    if a & 0x8000 != 0 {
        let m = a >> 16;
        s.push(' ');
        s.push(match m & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            _ => '-',
        });
        for shift in [6, 3, 0] {
            let t = (m >> shift) & 7;
            s.push(if t & 4 != 0 { 'r' } else { '-' });
            s.push(if t & 2 != 0 { 'w' } else { '-' });
            s.push(if t & 1 != 0 { 'x' } else { '-' });
        }
    }
    s
}

#[test]
fn listing_matches_7zz_oracle() {
    for (name, _) in variants() {
        let bytes = fx!(&format!("{name}.7z")).unwrap();
        let slt = String::from_utf8(fx!(&format!("{name}.slt.txt")).unwrap()).unwrap();
        let (head, items) = slt_items(&slt);
        let ar = SevenZArchive::open(&bytes, &Dec, lim()).unwrap();
        assert_eq!(items.len(), ar.entries().len(), "{name}");
        let blocks = head.iter().find(|(k, _)| k == "Blocks").map(|(_, v)| v.clone());
        assert_eq!(blocks, Some(ar.folders().len().to_string()), "{name} blocks");
        let phys = head.iter().find(|(k, _)| k == "Physical Size").map(|(_, v)| v.clone());
        assert_eq!(phys, Some(bytes.len().to_string()), "{name}");
        for (e, item) in ar.entries().iter().zip(&items) {
            for (k, v) in item {
                let ours = match k.as_str() {
                    "Path" => e.name.clone(),
                    "Size" => e.size.to_string(),
                    "Attributes" => fmt_attr(e.attributes),
                    "CRC" => e.crc.map(|c| format!("{c:08X}")).unwrap_or_default(),
                    // 7-Zip shows the enclosing block for an empty file that
                    // sits between two files of one solid block; only
                    // entries with data have a block of their own.
                    "Block" if e.folder_index.is_none() => continue,
                    "Block" => e.folder_index.map(|b| b.to_string()).unwrap_or_default(),
                    "Modified" => {
                        assert_eq!(filetime_to_unix(e.mtime.unwrap()), (MTIME, 0));
                        "2024-03-05 06:07:08.0000000".to_string()
                    }
                    _ => continue,
                };
                assert_eq!(&ours, v, "{name}: {k} of {}", e.name);
            }
        }
    }
}

/// Write the fixtures (and nothing else) when `SEVENZ_WRITE_REGEN` is set.
#[test]
fn regen() {
    let Ok(dir) = std::env::var("SEVENZ_WRITE_REGEN") else { return };
    std::fs::create_dir_all(&dir).unwrap();
    for (name, _) in variants() {
        std::fs::write(format!("{dir}/{name}.7z"), build(name)).unwrap();
    }
    // Raw inputs for the external checkers.
    let items = fixture_items();
    let src = format!("{dir}/src");
    for o in &items {
        let p = format!("{src}/{}", o.name);
        match o.kind {
            EntryKind::Directory => std::fs::create_dir_all(&p).unwrap(),
            EntryKind::File => {
                std::fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap();
                std::fs::write(&p, &o.data).unwrap();
            }
            EntryKind::Symlink => std::fs::write(format!("{p}.symlink-target"), &o.link).unwrap(),
        }
    }
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

#[test]
fn number_encoding_roundtrips() {
    let mut vals = vec![0u64, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1f_ffff, 0x20_0000, u32::MAX as u64, u64::MAX, u64::MAX - 1];
    for s in 0..64 {
        vals.push(1u64 << s);
        vals.push((1u64 << s) - 1);
    }
    for v in vals {
        let mut b = Vec::new();
        write_number(&mut b, v);
        assert_eq!(read_number(&b).unwrap(), (v, b.len()), "{v:#x}");
        // Minimal length: 1 + number of extra bytes needed.
        let bits = 64 - v.leading_zeros() as usize;
        let want = if bits <= 56 { 1 + bits.saturating_sub(1) / 7 } else { 9 };
        assert_eq!(b.len(), want.max(1), "{v:#x}");
    }
}

#[test]
fn signature_header_fields() {
    let bytes = build("lzma2_solid_hc");
    let sig = parse_signature_header(&bytes).unwrap();
    assert_eq!((sig.major_version, sig.minor_version), (0, 4));
    assert_eq!(32 + sig.next_header_offset + sig.next_header_size, bytes.len() as u64);
    let next = &bytes[32 + sig.next_header_offset as usize..];
    assert_eq!(next[0], 0x17, "compressed header is an encoded header");
    assert_eq!(crc32(next), sig.next_header_crc);
    let plain = build("copy_solid_plain");
    let sig = parse_signature_header(&plain).unwrap();
    assert_eq!(plain[32 + sig.next_header_offset as usize], 0x01);
}

#[test]
fn empty_archive() {
    let bytes = write_7z(&[], &SevenZWriteOptions::default(), wl()).unwrap();
    assert_eq!(bytes.len(), 32);
    let sig = parse_signature_header(&bytes).unwrap();
    assert_eq!((sig.next_header_offset, sig.next_header_size, sig.next_header_crc), (0, 0, 0));
    assert!(SevenZArchive::open(&bytes, &Dec, lim()).unwrap().entries().is_empty());
}

#[test]
fn only_empty_entries() {
    let items = [
        SevenZItem { name: "d", data: b"", is_dir: true, attributes: Some(0x10), mtime: None, ctime: None, atime: None },
        SevenZItem { name: "d/e", data: b"", is_dir: false, attributes: None, mtime: Some(5), ctime: None, atime: None },
    ];
    for hc in [false, true] {
        let o = SevenZWriteOptions { compress_header: hc, ..Default::default() };
        let bytes = write_7z(&items, &o, wl()).unwrap();
        let ar = SevenZArchive::open(&bytes, &Dec, lim()).unwrap();
        let e = ar.entries();
        assert_eq!(e.len(), 2);
        assert!(e[0].is_dir && !e[1].is_dir && !e[1].has_stream);
        assert_eq!((e[0].attributes, e[1].attributes), (Some(0x10), None));
        assert_eq!((e[0].mtime, e[1].mtime), (None, Some(5)));
        assert!(ar.folders().is_empty());
    }
}

#[test]
fn all_times_and_partial_definitions() {
    let items = [
        SevenZItem { name: "a", data: b"aaa", is_dir: false, attributes: Some(0x20), mtime: Some(1), ctime: Some(2), atime: Some(3) },
        SevenZItem { name: "b", data: b"bbbb", is_dir: false, attributes: None, mtime: None, ctime: Some(4), atime: None },
        SevenZItem { name: "c", data: b"", is_dir: false, attributes: Some(0x21), mtime: Some(u64::MAX), ctime: None, atime: Some(6) },
    ];
    let bytes = write_7z(&items, &opts(SevenZMethod::Lzma2, true, true), wl()).unwrap();
    let ar = SevenZArchive::open(&bytes, &Dec, lim()).unwrap();
    let e = ar.entries();
    let t: Vec<_> = e.iter().map(|e| (e.mtime, e.ctime, e.atime, e.attributes)).collect();
    assert_eq!(
        t,
        vec![
            (Some(1), Some(2), Some(3), Some(0x20)),
            (None, Some(4), None, None),
            (Some(u64::MAX), None, Some(6), Some(0x21))
        ]
    );
    assert_eq!(ar.extract_entry(1, &Dec).unwrap(), b"bbbb");
    assert_eq!(e[0].crc, Some(crc32(b"aaa")));
}

#[test]
fn solid_block_planning() {
    let datas: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 100 + i]).collect();
    let names: Vec<String> = (0..10).map(|i| format!("f{i}")).collect();
    let items: Vec<SevenZItem<'_>> = names
        .iter()
        .zip(&datas)
        .map(|(n, d)| SevenZItem { name: n, data: d, is_dir: false, attributes: None, mtime: None, ctime: None, atime: None })
        .collect();
    let folders = |o: &SevenZWriteOptions| {
        let b = write_7z(&items, o, wl()).unwrap();
        let ar = SevenZArchive::open(&b, &Dec, lim()).unwrap();
        for (i, d) in datas.iter().enumerate() {
            assert_eq!(&ar.extract_entry(i, &Dec).unwrap(), d);
        }
        ar.entries().iter().map(|e| e.folder_index.unwrap()).collect::<Vec<_>>()
    };
    let mut o = opts(SevenZMethod::Lzma2, true, true);
    assert_eq!(folders(&o), vec![0; 10]);
    o.solid_block_files = 4;
    assert_eq!(folders(&o), vec![0, 0, 0, 0, 1, 1, 1, 1, 2, 2]);
    o.solid_block_files = 0;
    o.solid_block_bytes = 250; // 100+101 fits, +102 does not
    assert_eq!(folders(&o), vec![0, 0, 1, 1, 2, 2, 3, 3, 4, 4]);
    o.solid_block_bytes = 1; // every file alone, never empty blocks
    assert_eq!(folders(&o), (0..10).collect::<Vec<_>>());
    o.solid = false;
    o.solid_block_bytes = 0;
    assert_eq!(folders(&o), (0..10).collect::<Vec<_>>());
}

#[test]
fn output_independent_of_thread_count() {
    let items = fixture_items();
    let e = entries(&items);
    for (name, mut o) in variants() {
        o.solid_block_files = 2;
        o.threads = 1;
        let one = create_7z(&e, &o, wl()).unwrap();
        for t in [2, 3, 8, 0] {
            o.threads = t;
            assert!(create_7z(&e, &o, wl()).unwrap() == one, "{name} threads={t}");
        }
    }
}

#[test]
fn bcj_filter_all_arches_roundtrip() {
    let data = x86_like(20_000);
    for arch in BcjArch::ALL {
        let items =
            [SevenZItem { name: "p", data: &data, is_dir: false, attributes: None, mtime: None, ctime: None, atime: None }];
        let mut o = opts(SevenZMethod::Lzma2, true, true);
        o.filter = Some(arch);
        let bytes = write_7z(&items, &o, wl()).unwrap();
        let ar = SevenZArchive::open(&bytes, &Dec, lim()).unwrap();
        assert_eq!(ar.folders()[0].coders.len(), 2, "{arch:?}");
        assert_eq!(ar.extract_entry(0, &Dec).unwrap(), data, "{arch:?}");
    }
}

#[test]
fn bcj_helps_on_x86_like_code() {
    let data = x86_like(200_000);
    let items = [SevenZItem { name: "p", data: &data, is_dir: false, attributes: None, mtime: None, ctime: None, atime: None }];
    let mut o = opts(SevenZMethod::Lzma2, true, true);
    let plain = write_7z(&items, &o, wl()).unwrap().len();
    o.filter = Some(BcjArch::X86);
    let filtered = write_7z(&items, &o, wl()).unwrap().len();
    assert!(filtered < plain, "bcj {filtered} vs plain {plain}");
}

#[test]
fn compresses_and_header_compression_helps() {
    let names: Vec<String> = (0..200).map(|i| format!("some/long/directory/name/file_{i:04}.txt")).collect();
    let items: Vec<SevenZItem<'_>> = names
        .iter()
        .map(|n| SevenZItem { name: n, data: n.as_bytes(), is_dir: false, attributes: Some(0x20), mtime: Some(1), ctime: None, atime: None })
        .collect();
    let a = write_7z(&items, &opts(SevenZMethod::Lzma2, true, false), wl()).unwrap();
    let b = write_7z(&items, &opts(SevenZMethod::Lzma2, true, true), wl()).unwrap();
    assert!(b.len() < a.len() / 2, "{} vs {}", b.len(), a.len());
    let total: usize = names.iter().map(|n| n.len()).sum();
    assert!(b.len() < total);
    for bytes in [&a, &b] {
        let ar = SevenZArchive::open(bytes, &Dec, lim()).unwrap();
        assert_eq!(ar.extract_entry(199, &Dec).unwrap(), names[199].as_bytes());
    }
}

#[test]
fn incompressible_data_stays_bounded() {
    let mut x = 0x12345678u32;
    let data: Vec<u8> = (0..100_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    let items = [SevenZItem { name: "r", data: &data, is_dir: false, attributes: None, mtime: None, ctime: None, atime: None }];
    for m in [SevenZMethod::Lzma, SevenZMethod::Lzma2, SevenZMethod::Copy] {
        let b = write_7z(&items, &opts(m, true, true), wl()).unwrap();
        assert!(b.len() < data.len() + data.len() / 50 + 200, "{m:?} {}", b.len());
        assert_eq!(SevenZArchive::open(&b, &Dec, lim()).unwrap().extract_entry(0, &Dec).unwrap(), data);
    }
}

#[test]
fn levels_all_roundtrip() {
    let items = fixture_items();
    let e = entries(&items);
    for level in 0..=9u8 {
        let mut o = SevenZWriteOptions::level(level).unwrap();
        o.lzma.dictionary_size = o.lzma.dictionary_size.min(1 << 20);
        let b = create_7z(&e, &o, wl()).unwrap();
        check_fixture_contents(&b);
    }
    assert_eq!(SevenZWriteOptions::level(0).unwrap().method, SevenZMethod::Copy);
    assert_eq!(SevenZWriteOptions::level(10), Err(E::InvalidOptions));
}

// ---------------------------------------------------------------------------
// Invalid input and limits
// ---------------------------------------------------------------------------

#[test]
fn rejects_bad_names_and_entries() {
    let o = SevenZWriteOptions::default();
    let it = |name: &'static str, data: &'static [u8], is_dir: bool| SevenZItem {
        name,
        data,
        is_dir,
        attributes: None,
        mtime: None,
        ctime: None,
        atime: None,
    };
    assert_eq!(write_7z(&[it("", b"x", false)], &o, wl()), Err(E::InvalidName));
    assert_eq!(write_7z(&[it("a\0b", b"x", false)], &o, wl()), Err(E::InvalidName));
    assert_eq!(write_7z(&[it("d", b"x", true)], &o, wl()), Err(E::InvalidEntry));
    let bad_utf8 = ArchiveEntry { name: b"\xff\xfe", kind: EntryKind::File, data: b"x", mtime: 0, mode: 0o644, link_target: b"" };
    assert_eq!(create_7z(&[bad_utf8], &o, wl()), Err(E::InvalidName));
    let dir_with_data = ArchiveEntry { name: b"d", kind: EntryKind::Directory, data: b"x", mtime: 0, mode: 0o755, link_target: b"" };
    assert_eq!(create_7z(&[dir_with_data], &o, wl()), Err(E::InvalidEntry));
    let empty_link = ArchiveEntry { name: b"l", kind: EntryKind::Symlink, data: b"", mtime: 0, mode: 0o777, link_target: b"" };
    assert_eq!(create_7z(&[empty_link], &o, wl()), Err(E::InvalidEntry));
}

#[test]
fn rejects_bad_options() {
    let items = [SevenZItem { name: "a", data: b"abc", is_dir: false, attributes: None, mtime: None, ctime: None, atime: None }];
    let mut o = SevenZWriteOptions::default();
    o.lzma.lc = 9;
    assert_eq!(write_7z(&items, &o, wl()), Err(E::InvalidOptions));
    let mut o = SevenZWriteOptions::default();
    o.lzma.lc = 4;
    o.lzma.lp = 1; // lc + lp > 4 is fine for LZMA, not for LZMA2
    assert_eq!(write_7z(&items, &o, wl()), Err(E::InvalidOptions));
    o.method = SevenZMethod::Lzma;
    let b = write_7z(&items, &o, wl()).unwrap();
    assert_eq!(SevenZArchive::open(&b, &Dec, lim()).unwrap().extract_entry(0, &Dec).unwrap(), b"abc");
    o.method = SevenZMethod::Copy; // LZMA options are ignored for Copy
    o.lzma.dictionary_size = 1;
    assert!(write_7z(&items, &o, wl()).is_ok());
    let mut o = SevenZWriteOptions::default();
    o.lzma.dictionary_size = 1;
    assert_eq!(write_7z(&items, &o, wl()), Err(E::InvalidOptions));
    let mut o = SevenZWriteOptions::default();
    o.lzma.nice_len = 1000;
    assert_eq!(write_7z(&items, &o, wl()), Err(E::InvalidOptions));
}

#[test]
fn enforces_limits() {
    let items = [
        SevenZItem { name: "a", data: &[1u8; 600], is_dir: false, attributes: None, mtime: None, ctime: None, atime: None },
        SevenZItem { name: "b", data: &[2u8; 600], is_dir: false, attributes: None, mtime: None, ctime: None, atime: None },
    ];
    let o = opts(SevenZMethod::Copy, true, false);
    let l = |f: fn(&mut SevenZWriteLimits)| {
        let mut l = wl();
        f(&mut l);
        l
    };
    assert_eq!(write_7z(&items, &o, l(|l| l.max_entries = 1)), Err(E::LimitExceeded));
    assert_eq!(write_7z(&items, &o, l(|l| l.max_input_bytes = 1199)), Err(E::LimitExceeded));
    assert!(write_7z(&items, &o, l(|l| l.max_input_bytes = 1200)).is_ok());
    assert_eq!(write_7z(&items, &o, l(|l| l.max_output_bytes = 1000)), Err(E::LimitExceeded));
    let exact = write_7z(&items, &o, wl()).unwrap().len() as u64;
    let mut lim0 = wl();
    lim0.max_output_bytes = exact;
    assert!(write_7z(&items, &o, lim0).is_ok());
    let mut lim1 = wl();
    lim1.max_output_bytes = exact - 1;
    assert_eq!(write_7z(&items, &o, lim1), Err(E::LimitExceeded));
    assert_eq!(write_7z(&items, &o, l(|l| l.max_name_units = 0)), Err(E::LimitExceeded));
    let ents: Vec<ArchiveEntry<'_>> = (0..3)
        .map(|_| ArchiveEntry { name: b"x", kind: EntryKind::File, data: b"", mtime: 0, mode: 0, link_target: b"" })
        .collect();
    assert_eq!(create_7z(&ents, &o, l(|l| l.max_entries = 2)), Err(E::LimitExceeded));
}

#[test]
fn time_and_attribute_helpers() {
    assert_eq!(unix_to_filetime(0, 0), Some(116_444_736_000_000_000));
    assert_eq!(unix_to_filetime(-11_644_473_600, 0), Some(0));
    assert_eq!(unix_to_filetime(-11_644_473_601, 0), None);
    assert_eq!(unix_to_filetime(i64::MAX, 0), None);
    assert_eq!(unix_to_filetime(0, 1_000_000_000), None);
    assert_eq!(unix_to_filetime(1, 999_999_999), Some(116_444_736_000_000_000 + 19_999_999));
    assert_eq!(unix_attributes(EntryKind::File, 0o644), 0x20 | 0x8000 | (0o100644 << 16));
    assert_eq!(unix_attributes(EntryKind::File, 0o444), 0x21 | 0x8000 | (0o100444 << 16));
    assert_eq!(unix_attributes(EntryKind::Directory, 0o40755), 0x10 | 0x8000 | (0o40755 << 16));
    assert_eq!(unix_attributes(EntryKind::Symlink, 0o777), 0x20 | 0x8000 | (0o120777 << 16));
    // An out-of-range mtime is simply not stored.
    let e = ArchiveEntry { name: b"x", kind: EntryKind::File, data: b"1", mtime: i64::MIN, mode: 0o644, link_target: b"" };
    let b = create_7z(&[e], &SevenZWriteOptions::default(), wl()).unwrap();
    assert_eq!(SevenZArchive::open(&b, &Dec, lim()).unwrap().entries()[0].mtime, None);
}

#[test]
fn many_entries_and_long_names() {
    let names: Vec<String> = (0..3000).map(|i| format!("d{}/{}", i % 7, "n".repeat(i % 300 + 1))).collect();
    let items: Vec<SevenZItem<'_>> = names
        .iter()
        .enumerate()
        .map(|(i, n)| SevenZItem {
            name: n,
            data: if i % 5 == 0 { b"" } else { n.as_bytes() },
            is_dir: false,
            attributes: if i % 3 == 0 { None } else { Some(0x20) },
            mtime: if i % 2 == 0 { Some(i as u64) } else { None },
            ctime: None,
            atime: None,
        })
        .collect();
    let mut o = opts(SevenZMethod::Lzma2, true, true);
    o.solid_block_files = 97;
    let b = write_7z(&items, &o, wl()).unwrap();
    let ar = SevenZArchive::open(&b, &Dec, lim()).unwrap();
    assert_eq!(ar.entries().len(), 3000);
    for (i, e) in ar.entries().iter().enumerate() {
        assert_eq!(e.name, names[i]);
        assert_eq!(e.mtime, if i % 2 == 0 { Some(i as u64) } else { None });
        assert_eq!(e.attributes.is_some(), i % 3 != 0);
    }
    for i in [1, 2, 1234, 2999] {
        assert_eq!(ar.extract_entry(i, &Dec).unwrap(), names[i].as_bytes());
    }
}

#[test]
fn reader_rejects_corrupted_writer_output() {
    // Flipping any byte must give Err from the reader, never a panic or
    // silently wrong data.
    let bytes = build("lzma2_solid_hc");
    let want = read_back(&bytes);
    for i in (0..bytes.len()).step_by(3) {
        let mut b = bytes.clone();
        b[i] ^= 0x41;
        let Ok(ar) = SevenZArchive::open(&b, &Dec, lim()) else { continue };
        for e in ar.entries() {
            if let Ok(d) = ar.extract_entry(e.index, &Dec) {
                assert_eq!(d, want[e.index].2, "byte {i} silently changed data");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CLI run function
// ---------------------------------------------------------------------------

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

#[test]
fn cli_parse_switches() {
    let a = parse_7z_add_args(&os(&["-mx9", "-m0=lzma", "-mf=BCJ", "-ms=4m10f", "-mhc=off", "-mmt=3", "-y", "o.7z", "x"])).unwrap();
    assert_eq!(a.options.method, SevenZMethod::Lzma);
    assert_eq!(a.options.filter, Some(BcjArch::X86));
    assert_eq!((a.options.solid, a.options.solid_block_bytes, a.options.solid_block_files), (true, 4 << 20, 10));
    assert!(!a.options.compress_header);
    assert_eq!(a.options.threads, 3);
    assert!(a.overwrite && !a.follow_symlinks);
    assert_eq!(a.options.lzma, SevenZWriteOptions::level(9).unwrap().lzma);
    let a = parse_7z_add_args(&os(&["-ms=off", "-mx0", "-l", "--", "-o.7z", "-x"])).unwrap();
    assert!(!a.options.solid);
    assert_eq!(a.options.method, SevenZMethod::Copy);
    assert_eq!(a.archive, std::path::PathBuf::from("-o.7z"));
    assert!(a.follow_symlinks);
    let a = parse_7z_add_args(&os(&["-ms=100b", "-mmt=off", "-t7z", "o.7z", "x"])).unwrap();
    assert_eq!((a.options.solid_block_bytes, a.options.threads), (100, 1));
    let d = parse_7z_add_args(&os(&["o.7z", "x"])).unwrap();
    assert_eq!(d.options, SevenZWriteOptions::default());
    for bad in [
        &["-mx10", "o.7z", "x"][..],
        &["-m0=ppmd", "o.7z", "x"],
        &["-mf=zz", "o.7z", "x"],
        &["-ms=4q", "o.7z", "x"],
        &["-ms=99999999999999999999g", "o.7z", "x"],
        &["-mhc=maybe", "o.7z", "x"],
        &["-mmt=0", "o.7z", "x"],
        &["-zz", "o.7z", "x"],
        &["o.7z"],
        &[],
    ] {
        assert!(parse_7z_add_args(&os(bad)).is_err(), "{bad:?}");
    }
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sed-7zw-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn cli_creates_archive() {
    let d = scratch("cli");
    let src = d.join("in");
    std::fs::create_dir_all(src.join("sub/deeper")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha\n".repeat(100)).unwrap();
    std::fs::write(src.join("sub/b.bin"), (0..5000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>()).unwrap();
    std::fs::write(src.join("sub/deeper/empty"), b"").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.txt", src.join("ln")).unwrap();
    let out = d.join("x.7z");
    let arg = |p: &std::path::Path| p.as_os_str().to_os_string();
    assert_eq!(run_add_7z(&[OsString::from("-mmt=2"), arg(&out), arg(&src)]), 0);
    // Refuses to overwrite without -y.
    assert_eq!(run_add_7z(&[arg(&out), arg(&src)]), 1);
    assert_eq!(run_add_7z(&[OsString::from("-y"), OsString::from("-m0=lzma"), arg(&out), arg(&src)]), 0);
    let bytes = std::fs::read(&out).unwrap();
    let ar = SevenZArchive::open(&bytes, &Dec, lim()).unwrap();
    let names: Vec<&str> = ar.entries().iter().map(|e| e.name.as_str()).collect();
    let mut want = vec!["in", "in/a.txt", "in/sub", "in/sub/b.bin", "in/sub/deeper", "in/sub/deeper/empty"];
    if cfg!(unix) {
        want.insert(2, "in/ln");
    }
    assert_eq!(names, want);
    for e in ar.entries() {
        let data = ar.extract_entry(e.index, &Dec).unwrap();
        match e.name.as_str() {
            "in/a.txt" => assert_eq!(data, b"alpha\n".repeat(100)),
            "in/ln" => {
                assert_eq!(data, b"a.txt");
                assert_eq!(e.unix_mode().unwrap() & 0o170000, 0o120000);
            }
            "in/sub/b.bin" => assert_eq!(data.len(), 5000),
            _ => assert!(data.is_empty()),
        }
    }
    assert_eq!(ar.folders()[0].coders[0].method_id, vec![3, 1, 1]);
    // Usage errors.
    assert_eq!(run_add_7z(&os(&["-mx=11", "o.7z", "x"])), 2);
    assert_eq!(run_add_7z(&[arg(&d.join("y.7z")), arg(&d.join("missing"))]), 1);
    let _ = std::fs::remove_dir_all(&d);
}

/// Larger archives for the external oracle when `SEVENZ_WRITE_STRESS=<dir>`
/// is set (see `tests/gen/sevenz_write_oracle.sh`): ~24 MiB of mixed data in
/// many files, several solid blocks, all methods and BCJ, written with the
/// sources under `<dir>/src`.
#[test]
fn stress_regen() {
    let Ok(dir) = std::env::var("SEVENZ_WRITE_STRESS") else { return };
    let mut owned = Vec::new();
    let mut x = 0x9e3779b9u32;
    let mut rnd = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    };
    for i in 0..400usize {
        let name = format!("tree/d{:02}/f{i:04}.{}", i % 23, ["txt", "bin", "exe", "dat"][i % 4]);
        let n = (i * 7919) % 120_000;
        let data = match i % 4 {
            0 => (0..n).map(|k| b"lorem ipsum dolor sit amet "[k % 27]).collect(),
            1 => rnd(n),
            2 => x86_like(n),
            _ => {
                let mut v = rnd(n / 8);
                v.extend(std::iter::repeat_n(7u8, n - n / 8));
                v
            }
        };
        owned.push(Owned { name, kind: EntryKind::File, data, mode: 0o644, link: vec![] });
    }
    owned.push(Owned { name: "tree/big.bin".into(), kind: EntryKind::File, data: x86_like(9 << 20), mode: 0o755, link: vec![] });
    owned.sort_by(|a, b| a.name.cmp(&b.name));
    let e = entries(&owned);
    std::fs::create_dir_all(format!("{dir}/src")).unwrap();
    for o in &owned {
        let p = format!("{dir}/src/{}", o.name);
        std::fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap();
        std::fs::write(&p, &o.data).unwrap();
    }
    let mut cases: Vec<(&str, SevenZWriteOptions)> = Vec::new();
    for (name, level) in [("s_mx1", 1u8), ("s_mx5", 5), ("s_mx9", 9), ("s_mx0", 0)] {
        let mut o = SevenZWriteOptions::level(level).unwrap();
        o.solid_block_bytes = 4 << 20;
        cases.push((name, o));
    }
    let mut o = SevenZWriteOptions::level(5).unwrap();
    o.method = SevenZMethod::Lzma;
    o.filter = Some(BcjArch::X86);
    o.solid = false;
    cases.push(("s_lzma_bcj_nonsolid", o));
    let mut o = SevenZWriteOptions::level(3).unwrap();
    o.filter = Some(BcjArch::Arm64);
    o.compress_header = false;
    cases.push(("s_lzma2_arm64_plain", o));
    for (name, o) in cases {
        let t = std::time::Instant::now();
        let b = create_7z(&e, &o, wl()).unwrap();
        eprintln!("{name}: {} bytes in {:?}", b.len(), t.elapsed());
        check_ok(&b, &owned);
        std::fs::write(format!("{dir}/{name}.7z"), b).unwrap();
    }
}

fn check_ok(b: &[u8], owned: &[Owned]) {
    let ar = SevenZArchive::open(b, &Dec, lim()).unwrap();
    assert_eq!(ar.entries().len(), owned.len());
    for fi in 0..ar.folders().len() {
        ar.extract_folder(fi, &Dec).unwrap();
    }
}
