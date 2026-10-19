// SPDX-License-Identifier: MIT OR Apache-2.0
//! Regression tests for the Sediment/7-Zip mismatches found by the
//! differential harness (tests/diff/run_diff.py):
//!   * ZIP: BZip2 (12), LZMA (14, with and without end marker), XZ (95) and
//!     Deflate64 (9) methods, data descriptors and ZIP64 records, which the
//!     CLI reader used to refuse as "unsupported archive format";
//!   * multi-member gzip files (RFC 1952 2.2);
//!   * xz Delta/BCJ pre-filter chains;
//!   * empty tar archives (only the end-of-archive zero blocks).
//!
//! Fixtures: tests/gen/difftest.py (Python stdlib oracle) and
//! tests/gen/difftest_7z.sh (pinned 7zz oracle, under 7z/).
use std::path::{Path, PathBuf};
use std::process::Command;

use sediment_engine::archive_open::open_named;
use sediment_engine::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use sediment_engine::crc32::crc32;
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::gzip_members::{decode_gzip_members, member_header_len};
use sediment_engine::gzip_wrapper::GzipError;
use sediment_engine::inflate::{inflate_raw, inflate_raw_prefix};
use sediment_engine::xz_decode::{XzError, decode_xz};

fn fxp(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/difftest").join(name)
}

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(fxp(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn tree(rel: &str) -> Vec<u8> {
    fx(&format!("tree/{rel}"))
}

fn open<'a>(bytes: &'a [u8], name: &str) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    open_named(bytes, name.as_bytes(), ReaderLimits::default())
}

const TREE_FILES: [&str; 4] = ["a.txt", "b.bin", "dir/c.txt", "prog.bin"];

/// Every tree file is listed with the right size and CRC and reads back
/// byte-identical; `dir/` is a directory.
fn check_zip_tree(name: &str) {
    let b = fx(name);
    let r = open(&b, name).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(r.format(), ArchiveFormat::Zip, "{name}");
    let es = r.entries();
    for f in TREE_FILES {
        let i = es.iter().position(|e| e.path == f.as_bytes()).unwrap_or_else(|| panic!("{name}: no {f}"));
        let want = tree(f);
        assert_eq!(es[i].kind, EntryKind::File, "{name}: {f}");
        assert_eq!(es[i].size, want.len() as u64, "{name}: {f}");
        assert_eq!(r.crc32(i), Some(crc32(&want)), "{name}: {f}");
        assert_eq!(r.read(i).unwrap_or_else(|e| panic!("{name}: {f}: {e:?}")), want, "{name}: {f}");
    }
    let d = es.iter().position(|e| e.path.starts_with(b"dir") && e.kind == EntryKind::Dir);
    assert!(d.is_some(), "{name}: dir entry");
}

#[test]
fn zip_methods_and_layouts() {
    for name in [
        "zip_bzip2.zip",
        "zip_lzma.zip",
        "zip_descriptor.zip",
        "zip_stored_descriptor.zip",
        "zip_zip64.zip",
        "7z/zip_deflate64.zip",
        "7z/zip_xz.zip",
        "7z/zip_lzma_eos.zip",
    ] {
        check_zip_tree(name);
    }
}

#[test]
fn zip_entry_limit_and_corruption() {
    let b = fx("zip_lzma.zip");
    let limits = ReaderLimits { max_entry_size: 100, ..ReaderLimits::default() };
    let r = open_named(&b, b"z.zip", limits).unwrap();
    let i = r.entries().iter().position(|e| e.path == b"a.txt").unwrap();
    assert_eq!(r.read(i), Err(ReaderError::LimitExceeded));
    // Flip a byte inside each compressed payload: Err, never a panic or
    // silently wrong data.
    for name in ["zip_bzip2.zip", "zip_lzma.zip", "7z/zip_xz.zip", "7z/zip_deflate64.zip"] {
        let b = fx(name);
        let r = open(&b, name).unwrap();
        let i = r.entries().iter().position(|e| e.path == b"a.txt").unwrap();
        let want = tree("a.txt");
        for at in (200..b.len().min(2000)).step_by(97) {
            let mut c = b.clone();
            c[at] ^= 0x40;
            if let Ok(r) = open(&c, name)
                && let Ok(d) = r.read(i)
            {
                assert_eq!(d, want, "{name}: flip at {at} returned wrong data");
            }
        }
    }
}

#[test]
fn zip_truncations_never_panic() {
    for name in ["zip_lzma.zip", "7z/zip_xz.zip", "zip_zip64.zip", "zip_descriptor.zip"] {
        let b = fx(name);
        for n in (0..b.len()).step_by(37) {
            if let Ok(r) = open(&b[..n], name) {
                for i in 0..r.entries().len() {
                    let _ = r.read(i);
                }
            }
        }
    }
}

#[test]
fn multi_member_gzip() {
    let b = fx("multi.gz");
    let r = open(&b, "multi.gz").unwrap();
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].path, b"a.txt");
    let want = tree("a.txt");
    assert_eq!(r.entries()[0].size, want.len() as u64);
    assert_eq!(r.crc32(0), Some(crc32(&want)));
    assert_eq!(r.read(0).unwrap(), want);
    assert_eq!(decode_gzip_members(&b, usize::MAX, 1 << 20), Ok((want.clone(), 2)));
    assert_eq!(decode_gzip_members(&b, want.len() - 1, 1 << 20), Err(GzipError::LimitExceeded));
    let j = fx("multi_junk.gz");
    assert_eq!(decode_gzip_members(&j, usize::MAX, 1 << 20), Err(GzipError::TrailingData));
    assert!(open(&j, "multi_junk.gz").is_err());
    // Every prefix fails except the one ending exactly after member one.
    let ok: Vec<usize> = (0..b.len()).filter(|&n| decode_gzip_members(&b[..n], usize::MAX, 1 << 20).is_ok()).collect();
    assert_eq!(ok.len(), 1);
    assert_eq!(decode_gzip_members(&b[..ok[0]], usize::MAX, 1 << 20), Ok((want[..7000].to_vec(), 1)));
    assert_eq!(member_header_len(&b), Ok(10 + b"a.txt\0".len()));
}

#[test]
fn inflate_prefix_reports_consumed() {
    // Stored block "abc" followed by unrelated bytes.
    let mut s = vec![0x01, 3, 0, 0xfc, 0xff, b'a', b'b', b'c'];
    assert_eq!(inflate_raw(&s, 10, 4), Ok(b"abc".to_vec()));
    s.extend_from_slice(b"tail");
    assert_eq!(inflate_raw_prefix(&s, 10, 4), Ok((b"abc".to_vec(), 8)));
    assert!(inflate_raw(&s, 10, 4).is_err());
}

#[test]
fn xz_pre_filters() {
    let prog = tree("prog.bin");
    for n in ["x86", "arm", "armthumb", "powerpc", "sparc", "ia64", "x86_start", "delta_x86"] {
        let b = fx(&format!("filter_{n}.xz"));
        assert_eq!(decode_xz(&b, 1 << 26, 1 << 20).unwrap_or_else(|e| panic!("{n}: {e:?}")), prog, "{n}");
    }
    for n in ["arm64", "riscv"] {
        let b = fx(&format!("7z/prog_{n}.bin.xz"));
        assert_eq!(decode_xz(&b, 1 << 26, 1 << 20).unwrap_or_else(|e| panic!("{n}: {e:?}")), prog, "{n}");
    }
    let b = fx("filter_delta.xz");
    assert_eq!(decode_xz(&b, 1 << 26, 1 << 20).unwrap(), tree("b.bin"));
    // Through archive_open as a single-stream file.
    let r = open(&b, "b.bin.xz").unwrap();
    assert_eq!(r.entries()[0].path, b"b.bin");
    assert_eq!(r.read(0).unwrap(), tree("b.bin"));
}

#[test]
fn xz_filter_headers_malformed() {
    let b = fx("filter_x86.xz");
    // Truncations and flips must be Err (or, for flips the checks cannot
    // see, the right data), never a panic.
    for n in 0..b.len() {
        assert!(decode_xz(&b[..n], 1 << 26, 1 << 20).is_err(), "prefix {n}");
    }
    let prog = tree("prog.bin");
    for at in 0..b.len() {
        let mut c = b.clone();
        c[at] ^= 0x01;
        if let Ok(d) = decode_xz(&c, 1 << 26, 1 << 20) {
            assert_eq!(d, prog, "flip at {at}");
        }
    }
    // Swap the filter IDs so LZMA2 is first: the block header CRC is
    // recomputed so the chain itself is what gets rejected.
    let mut c = b.clone();
    let hs = (c[12] as usize + 1) * 4;
    let hdr = &mut c[12..12 + hs];
    // Block header: size, flags (2 filters), [x86 id=0x04, props 0], [0x21, 1, dict].
    assert_eq!(&hdr[1..5], &[0x01, 0x04, 0x00, 0x21]);
    hdr[2] = 0x21;
    hdr[3] = 0x01;
    hdr[4] = hdr[6];
    hdr[5] = 0x04;
    hdr[6] = 0x00;
    let crc = crc32(&hdr[..hs - 4]);
    hdr[hs - 4..].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(decode_xz(&c, 1 << 26, 1 << 20), Err(XzError::InvalidHeader));
    // An unknown filter ID is Unsupported.
    let mut c = b.clone();
    let hdr = &mut c[12..12 + hs];
    hdr[2] = 0x0C;
    let crc = crc32(&hdr[..hs - 4]);
    hdr[hs - 4..].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(decode_xz(&c, 1 << 26, 1 << 20), Err(XzError::Unsupported));
}

#[test]
fn empty_tar_opens() {
    let b = fx("empty.tar");
    let r = open(&b, "empty.tar").unwrap();
    assert_eq!(r.format(), ArchiveFormat::Tar);
    assert!(r.entries().is_empty());
    assert!(open(&b[..512], "half.tar").is_err());
}

fn sediment(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sediment")).args(args).output().unwrap()
}

#[test]
fn cli_extracts_previously_refused_zips() {
    let out = std::env::temp_dir().join(format!("sediment-difftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    for name in ["zip_lzma.zip", "7z/zip_xz.zip", "zip_zip64.zip", "multi.gz", "filter_delta_x86.xz"] {
        let dst = out.join(name.replace('/', "_"));
        let o = sediment(&["x", "-y", &format!("-o{}", dst.display()), fxp(name).to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(0), "{name}: {}", String::from_utf8_lossy(&o.stderr));
        let t = sediment(&["t", fxp(name).to_str().unwrap()]);
        assert_eq!(t.status.code(), Some(0), "{name}");
    }
    assert_eq!(std::fs::read(out.join("zip_lzma.zip/a.txt")).unwrap(), tree("a.txt"));
    assert_eq!(std::fs::read(out.join("7z_zip_xz.zip/prog.bin")).unwrap(), tree("prog.bin"));
    assert_eq!(std::fs::read(out.join("multi.gz/a.txt")).unwrap(), tree("a.txt"));
    assert_eq!(std::fs::read(out.join("filter_delta_x86.xz/filter_delta_x86")).unwrap(), tree("prog.bin"));
    let _ = std::fs::remove_dir_all(&out);
}
