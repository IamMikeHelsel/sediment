// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multithreaded compression (`mt_pool`, `lzma2_mt`, `encode_xz_mt`,
//! `compress_mt`, `create_zip_mt`, block-parallel 7z LZMA2) and the `-mmt`
//! switch through the CLI.
//!
//! The committed fixtures in `tests/fixtures/mt_compress/` are this crate's
//! own multithreaded output; `python3 -I tests/gen/mt_compress.py` checks that
//! Python's liblzma/libbz2 decode them. After an intentional encoder change,
//! regenerate with `SEDIMENT_BLESS=1 cargo test --test mt_compress` and re-run
//! the Python check.

use std::path::{Path, PathBuf};
use std::process::Command;

use sediment_engine::bzip2_decode::decode_bzip2;
use sediment_engine::compress_wrap::{Compression, compress, compress_bound_for, compress_mt};
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::lzma_encode::LzmaEncoderOptions;
use sediment_engine::lzma2_decode::{decode_lzma2, dictionary_size_from_byte};
use sediment_engine::lzma2_encode::{Lzma2EncodeError, encode_lzma2};
use sediment_engine::lzma2_mt::{encode_lzma2_blocks, encode_lzma2_mt, join_lzma2_parts, lzma2_block_size};
use sediment_engine::mt_pool::{map_ordered, parse_mmt, resolve_threads};
use sediment_engine::xz_decode::decode_xz;
use sediment_engine::xz_encode::{XzOptions, encode_xz, encode_xz_mt};
use sediment_engine::zip_create::{ZipCreateLimits, ZipCreateOptions, create_zip, create_zip_mt};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mt_compress");
const BIN: &str = env!("CARGO_BIN_EXE_sediment");

const WORDS: [&[u8]; 20] = [
    b"sediment", b"archive", b"thread", b"block", b"pool", b"chunk", b"reset", b"dictionary", b"stream", b"parallel",
    b"the", b"of", b"and", b"a", b"to", b"in", b"is", b"xz", b"bzip2", b"7z",
];

/// Must match `mt_input()` in tests/gen/mt_compress.py.
fn mt_input(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x5EDD_1E47;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.extend_from_slice(WORDS[((x >> 33) % WORDS.len() as u64) as usize]);
        out.push(if (x >> 20) & 15 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

/// Incompressible-ish bytes mixed with text, `n` bytes.
fn mixed(n: usize) -> Vec<u8> {
    let text = mt_input(n);
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    text.iter()
        .enumerate()
        .map(|(i, &t)| {
            if (i >> 16) % 3 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s as u8
            } else {
                t
            }
        })
        .collect()
}

fn check_fixture(name: &str, got: &[u8]) {
    let path = Path::new(FIX).join(name);
    if std::env::var_os("SEDIMENT_BLESS").is_some() {
        std::fs::create_dir_all(FIX).unwrap();
        std::fs::write(&path, got).unwrap();
    }
    let want = std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}; bless it"));
    assert!(want == got, "{name} differs from the committed fixture");
}

fn xz_opts_small_blocks() -> XzOptions {
    let mut o = XzOptions::preset(1).unwrap();
    o.block_size = Some(64 << 10);
    o
}

#[test]
fn committed_fixtures_python_verified() {
    let data = mt_input(260_000);
    let xz = encode_xz_mt(&data, &xz_opts_small_blocks(), 4).unwrap();
    check_fixture("mt4.xz", &xz);
    let bound = compress_bound_for(Compression::Bzip2, data.len()).unwrap();
    let bz = compress_mt(Compression::Bzip2, &data, 1, bound, 4).unwrap();
    check_fixture("mt4.bz2", &bz);
    // Three complete streams of one 100 kB block each.
    assert_eq!(bz.windows(4).filter(|w| *w == b"BZh1").count(), 3);
}

#[test]
fn xz_multiblock_is_thread_count_independent() {
    let data = mt_input(260_000);
    let opts = xz_opts_small_blocks();
    let one = encode_xz(&data, &opts).unwrap();
    for t in [1, 2, 4, 8, 64] {
        assert_eq!(encode_xz_mt(&data, &opts, t).unwrap(), one, "threads {t}");
    }
    assert_eq!(decode_xz(&one, 1 << 26, 1 << 24).unwrap(), data);
    // compress_mt: small inputs stay one block (same as single-threaded).
    let bound = compress_bound_for(Compression::Xz, data.len()).unwrap();
    assert_eq!(compress_mt(Compression::Xz, &data, 6, bound, 8).unwrap(), compress(Compression::Xz, &data, 6, bound).unwrap());
    assert_eq!(encode_xz_mt(&[], &opts, 4).unwrap(), encode_xz(&[], &opts).unwrap());
}

#[test]
fn xz_compress_mt_splits_large_inputs() {
    let data = mixed(3 << 20);
    let bound = compress_bound_for(Compression::Xz, data.len()).unwrap();
    // Level 0: 256 KiB dictionary -> 1 MiB blocks -> 3 blocks.
    let a = compress_mt(Compression::Xz, &data, 0, bound, 3).unwrap();
    let b = compress_mt(Compression::Xz, &data, 0, bound, 16).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, compress(Compression::Xz, &data, 0, bound).unwrap());
    assert_eq!(decode_xz(&a, 1 << 26, 1 << 24).unwrap(), data);
    assert!(compress_mt(Compression::Xz, &data, 10, bound, 4).is_err());
    assert!(compress_mt(Compression::Xz, &data, 0, 100, 4).is_err());
}

#[test]
fn bzip2_multistream() {
    let data = mixed(1_000_000);
    let bound = compress_bound_for(Compression::Bzip2, data.len()).unwrap();
    let single = compress(Compression::Bzip2, &data, 9, bound).unwrap();
    assert_eq!(compress_mt(Compression::Bzip2, &data, 9, bound, 1).unwrap(), single);
    let a = compress_mt(Compression::Bzip2, &data, 9, bound, 2).unwrap();
    let b = compress_mt(Compression::Bzip2, &data, 9, bound, 8).unwrap();
    assert_eq!(a, b);
    assert_eq!(decode_bzip2(&a, data.len()).unwrap(), data);
    assert!(compress_mt(Compression::Bzip2, &data, 9, 1000, 4).is_err());
    // gzip ignores threads.
    let gb = compress_bound_for(Compression::Gzip, data.len()).unwrap();
    assert_eq!(compress_mt(Compression::Gzip, &data, 6, gb, 8).unwrap(), compress(Compression::Gzip, &data, 6, gb).unwrap());
}

#[test]
fn zip_parallel_deflate_is_identical() {
    let blobs: Vec<Vec<u8>> = (0..12).map(|i| mixed(20_000 + i * 7_000)).collect();
    let names: Vec<String> = (0..12).map(|i| format!("d/f{i}.bin")).collect();
    let mut entries: Vec<ArchiveEntry<'_>> = vec![ArchiveEntry {
        name: b"d",
        kind: EntryKind::Directory,
        data: b"",
        mtime: 1_700_000_000,
        mode: 0o755,
        link_target: b"",
    }];
    for (n, b) in names.iter().zip(&blobs) {
        entries.push(ArchiveEntry { name: n.as_bytes(), kind: EntryKind::File, data: b, mtime: 1_700_000_000, mode: 0o644, link_target: b"" });
    }
    entries.push(ArchiveEntry { name: b"empty", kind: EntryKind::File, data: b"", mtime: 0, mode: 0o644, link_target: b"" });
    entries.push(ArchiveEntry { name: b"ln", kind: EntryKind::Symlink, data: b"", mtime: 0, mode: 0o777, link_target: b"d" });
    for level in [0u8, 1, 6, 9] {
        let one = create_zip(&entries, ZipCreateOptions { level }, ZipCreateLimits::default()).unwrap();
        for t in [2, 5, 32] {
            assert_eq!(create_zip_mt(&entries, ZipCreateOptions { level }, ZipCreateLimits::default(), t).unwrap(), one);
        }
    }
    let mut bad = entries.clone();
    bad.push(ArchiveEntry { name: b"../x", kind: EntryKind::File, data: b"x", mtime: 0, mode: 0, link_target: b"" });
    assert!(create_zip_mt(&bad, ZipCreateOptions { level: 6 }, ZipCreateLimits::default(), 4).is_err());
    let tight = ZipCreateLimits { max_total_input: 1000, ..ZipCreateLimits::default() };
    assert!(create_zip_mt(&entries, ZipCreateOptions { level: 6 }, tight, 4).is_err());
}

#[test]
fn lzma2_block_mode_decodes_as_one_stream() {
    let data = mixed(3 << 20);
    let opts = LzmaEncoderOptions::preset(1).unwrap();
    let (s, d) = encode_lzma2_mt(&data, &opts, 4).unwrap();
    assert_eq!(lzma2_block_size(opts.dictionary_size, data.len(), 4), 1 << 20);
    let dict = dictionary_size_from_byte(d).unwrap();
    let (out, used) = decode_lzma2(&s, dict, 1 << 26, data.len()).unwrap();
    assert_eq!((out == data, used), (true, s.len()));
    assert_eq!(encode_lzma2_mt(&data, &opts, 7).unwrap(), encode_lzma2_blocks(&data, &opts, 1 << 20, 1).unwrap());
    assert_eq!(encode_lzma2_mt(&data, &opts, 1).unwrap(), encode_lzma2(&data, &opts).unwrap());
    // Joining requires each part to end with the 0x00 end marker.
    assert_eq!(join_lzma2_parts(&[(vec![0x01, 0x00, 0x00, b'x'], 0)]), Err(Lzma2EncodeError::InvalidOptions));
    assert_eq!(join_lzma2_parts(&[]).unwrap(), (vec![0x00], 0));
    // Truncated block-mode streams are rejected, never a panic.
    for cut in [1, s.len() / 2, s.len() - 1] {
        assert!(decode_lzma2(&s[..cut], dict, 1 << 26, data.len()).is_err());
    }
}

#[test]
fn pool_contract() {
    let v: Vec<usize> = (0..500).collect();
    let r = map_ordered(&v, 8, usize::MAX, |&x| if x % 97 == 96 { Err(x) } else { Ok(x + 1) });
    assert_eq!(r, Err(96));
    assert_eq!(map_ordered(&v, 0, 0u8, |&x| Ok::<usize, u8>(x)).unwrap(), v);
    assert_eq!(parse_mmt("=16"), Some(16));
    assert_eq!(parse_mmt("=on"), Some(0));
    assert_eq!(parse_mmt("=-3"), None);
    assert!(resolve_threads(0) >= 1);
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let p = std::env::temp_dir().join(format!("sediment-mt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sediment(args: &[&std::ffi::OsStr], cwd: &Path) -> i32 {
    Command::new(BIN).args(args).current_dir(cwd).output().unwrap().status.code().unwrap_or(-1)
}

#[test]
fn cli_mmt_7z_zip_xz_bz2() {
    let s = Scratch::new("cli");
    let src = s.0.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    let big = mixed(5 << 20);
    std::fs::write(src.join("big.bin"), &big).unwrap();
    std::fs::write(src.join("sub/small.txt"), mt_input(50_000)).unwrap();
    let os = |p: &Path| p.as_os_str().to_owned();
    let dot = std::ffi::OsString::from(".");
    let a7 = |name: &str, mt: &str| {
        let arc = s.0.join(name);
        let code = sediment(&[std::ffi::OsStr::new("a"), std::ffi::OsStr::new(mt), &os(&arc), &dot], &src);
        assert_eq!(code, 0, "{name} {mt}");
        std::fs::read(&arc).unwrap()
    };
    let m4a = a7("m4a.7z", "-mmt=4");
    let m4b = a7("m4b.7z", "-mmt=4");
    let m1 = a7("m1.7z", "-mmt=1");
    assert_eq!(m4a, m4b, "-mmt=4 must be deterministic");
    assert_ne!(m4a, m1, "-mmt=4 splits the 5 MiB folder into blocks");
    for name in ["m4a.7z", "m1.7z"] {
        let out = s.0.join(format!("x-{name}"));
        let mut o = std::ffi::OsString::from("-o");
        o.push(&out);
        let code = sediment(&["x".as_ref(), os(&s.0.join(name)).as_os_str(), &o, "-y".as_ref()], &s.0);
        assert_eq!(code, 0);
        assert!(std::fs::read(out.join("big.bin")).unwrap() == big);
        assert_eq!(std::fs::read(out.join("sub/small.txt")).unwrap(), mt_input(50_000));
    }
    // Other formats accept -mmt; zip is byte-identical across thread counts.
    let z4 = a7("m4.zip", "-mmt=4");
    let z1 = a7("m1.zip", "-mmt=1");
    assert_eq!(z4, z1);
    a7("m.tar.xz", "-mmt");
    a7("m.tar.bz2", "-mmt=3");
    a7("m.tar.gz", "-mmt=off");
    for name in ["m.tar.xz", "m.tar.bz2"] {
        assert_eq!(sediment(&["t".as_ref(), os(&s.0.join(name)).as_os_str()], &s.0), 0, "{name}");
    }
    // Malformed -mmt is a command-line error (exit 7); bench rejects it with 2.
    let bad = s.0.join("bad.zip");
    assert_eq!(sediment(&["a".as_ref(), "-mmt=0".as_ref(), os(&bad).as_os_str(), &dot], &src), 7);
    assert_eq!(sediment(&["a".as_ref(), "-mmt=x".as_ref(), os(&s.0.join("bad.7z")).as_os_str(), &dot], &src), 7);
    assert!(!bad.exists());
    assert_eq!(sediment(&["b".as_ref(), "-mmt=abc".as_ref()], &s.0), 2);
}

#[test]
fn bench_reports_mt_table() {
    let out = Command::new(BIN).args(["b", "1", "-mm=lzma", "-md20", "-ds3m", "-mmt=2"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("LZMA2 block-parallel (-mmt)"), "{text}");
    assert!(text.lines().any(|l| l.trim_start().starts_with("2 ")), "{text}");
}
