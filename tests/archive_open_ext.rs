// SPDX-License-Identifier: MIT OR Apache-2.0
//! `archive_open_ext`: zstd / tar.zst / WIM through the common
//! `ArchiveReader` interface, and the `sediment` CLI on those formats.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sediment_engine::archive_open_ext::{WimReader, open_named_ext};
use sediment_engine::archive_reader::{ArchiveFormat, ReaderError, ReaderLimits};
use sediment_engine::extract_plan::EntryKind;

fn fx(area: &str, name: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(area).join(name)).unwrap()
}

fn path_of(e: &sediment_engine::extract_plan::PlannedEntry) -> String {
    String::from_utf8(e.path.clone()).unwrap()
}

#[test]
fn tar_zst() {
    let b = fx("zstd", "tree.tar.zst");
    let r = open_named_ext(&b, b"tree.tar.zst", ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), ArchiveFormat::Tar);
    let names: Vec<String> = r.entries().iter().map(path_of).collect();
    assert_eq!(names, ["a/hello.txt", "a/text.txt", "a/empty", "a/sub"]);
    assert_eq!(r.read(0).unwrap(), b"Hello, zstd!\n");
    assert_eq!(r.read(1).unwrap().len(), 24_000);
    assert!(matches!(r.entries()[3].kind, EntryKind::Dir));
    // Same bytes named .tzst; and as a plain .zst whose member is not a tar.
    let r = open_named_ext(&b, b"dir/tree.tzst", ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), ArchiveFormat::Tar);
    let r = open_named_ext(&b, b"tree.zst", ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), ArchiveFormat::Zstd);
    assert_eq!(r.entries()[0].path, b"tree");
}

#[test]
fn single_zst() {
    let b = fx("zstd", "text.l19.zst");
    let r = open_named_ext(&b, b"notes.txt.zst", ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), ArchiveFormat::Zstd);
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].path, b"notes.txt");
    assert_eq!(r.entries()[0].size, 24_000);
    assert_eq!(r.read(0).unwrap().len(), 24_000);
    assert_eq!(r.read(1), Err(ReaderError::OutOfRange));
    let small = ReaderLimits { max_total_size: 1000, ..ReaderLimits::default() };
    assert_eq!(open_named_ext(&b, b"n.zst", small).err(), Some(ReaderError::LimitExceeded));
    let small = ReaderLimits { max_entry_size: 1000, ..ReaderLimits::default() };
    assert_eq!(open_named_ext(&b, b"n.zst", small).err(), Some(ReaderError::LimitExceeded));
    assert_eq!(
        open_named_ext(&fx("zstd", "bad.checksum.zst"), b"x.zst", ReaderLimits::default()).err(),
        Some(ReaderError::CrcMismatch)
    );
    assert_eq!(
        open_named_ext(&fx("zstd", "dict.zst"), b"x.zst", ReaderLimits::default()).err(),
        Some(ReaderError::Unsupported)
    );
    // A hello frame named .tar.zst is not a tar archive.
    assert!(open_named_ext(&fx("zstd", "hello.l3.zst"), b"x.tar.zst", ReaderLimits::default()).is_err());
}

#[test]
fn wim_reader() {
    let b = fx("wim", "xpress_multi.wim");
    let r = WimReader::new(&b, ReaderLimits::default()).unwrap();
    assert_eq!(sediment_engine::archive_reader::ArchiveReader::format(&r), ArchiveFormat::Wim);
    assert_eq!(r.skipped_streams(), 2);
    let ents = sediment_engine::archive_reader::ArchiveReader::entries(&r);
    let pos = |p: &str| ents.iter().position(|e| e.path == p.as_bytes()).unwrap();
    let rd = |i| sediment_engine::archive_reader::ArchiveReader::read(&r, i).unwrap();
    assert_eq!(rd(pos("1/hello.txt")), b"Hello, WIM!\n");
    assert_eq!(rd(pos("2/second.txt")), b"second image\n");
    assert!(matches!(ents[pos("1/dir/sub")].kind, EntryKind::Dir));
    assert_eq!(rd(pos("1/dir/sub")), b"");
    assert_eq!(ents[pos("1/hello.txt")].mtime, Some(1_709_526_400));

    let b = fx("wim", "reparse.wim");
    let r = open_named_ext(&b, b"r.wim", ReaderLimits::default()).unwrap();
    let names: Vec<String> = r.entries().iter().map(path_of).collect();
    assert_eq!(names, ["target.txt", "rel_link"]);
    assert_eq!(r.entries()[1].kind, EntryKind::Symlink { target: b"target.txt".to_vec() });
    let r = WimReader::new(&b, ReaderLimits::default()).unwrap();
    assert_eq!(r.skipped_reparse(), 1);

    let b = fx("wim", "lzx.wim");
    assert_eq!(open_named_ext(&b, b"x.wim", ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
    let b = fx("wim", "xpress.wim");
    let small = ReaderLimits { max_total_size: 1000, ..ReaderLimits::default() };
    assert_eq!(open_named_ext(&b, b"x.wim", small).err(), Some(ReaderError::LimitExceeded));
    let small = ReaderLimits { max_entry_size: 100, ..ReaderLimits::default() };
    let r = open_named_ext(&b, b"x.wim", small).unwrap();
    let t = r.entries().iter().position(|e| e.path == b"text.txt").unwrap();
    assert_eq!(r.read(t), Err(ReaderError::LimitExceeded));
}

#[test]
fn other_formats_fall_through() {
    let b = fx("cli_wire", "bundle.gz");
    let r = open_named_ext(&b, b"bundle.gz", ReaderLimits::default()).unwrap();
    // gzip whose FNAME is a .tar: handled by archive_open as tar.
    assert_eq!(r.format(), ArchiveFormat::Tar);
    assert_eq!(open_named_ext(b"nothing here", b"x", ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
}

const BIN: &str = env!("CARGO_BIN_EXE_sediment");

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("sediment-zw-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn fx_path(area: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(area).join(name)
}

#[test]
fn cli_list_test_extract() {
    let o = Command::new(BIN).arg("l").arg(fx_path("wim", "wimlib_xpress.wim")).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("dir/sub/nested.txt") && s.contains("zeros.bin"), "{s}");
    for (area, name) in [("wim", "xpress.wim"), ("zstd", "tree.tar.zst"), ("zstd", "lines.l19.zst")] {
        let o = Command::new(BIN).arg("t").arg(fx_path(area, name)).output().unwrap();
        assert!(o.status.success(), "{name}: {}", String::from_utf8_lossy(&o.stderr));
    }
    let d = tmp("x");
    let o = Command::new(BIN).arg("x").arg(format!("-o{}", d.display())).arg(fx_path("wim", "xpress.wim")).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(fs::read(d.join("hello.txt")).unwrap(), b"Hello, WIM!\n");
    assert_eq!(fs::read(d.join("dir/sub/nested.txt")).unwrap(), b"nested\n".repeat(3));
    assert_eq!(fs::read(d.join("zeros.bin")).unwrap(), vec![0u8; 34_000]);
    assert!(d.join("emptydir").is_dir());
    let o = Command::new(BIN).arg("x").arg(format!("-o{}", d.display())).arg("-y").arg(fx_path("zstd", "tree.tar.zst")).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(fs::read(d.join("a/hello.txt")).unwrap(), b"Hello, zstd!\n");
    let _ = fs::remove_dir_all(&d);
    let o = Command::new(BIN).arg("t").arg(fx_path("zstd", "bad.checksum.zst")).output().unwrap();
    assert!(!o.status.success());
}

#[test]
fn cli_stdin() {
    use std::io::Write;
    use std::process::Stdio;
    for (area, name, want) in [("zstd", "tree.tar.zst", "a/hello.txt"), ("wim", "xpress.wim", "dir/sub/nested.txt")] {
        let mut c = Command::new(BIN).args(["l", "-si"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        c.stdin.take().unwrap().write_all(&fx(area, name)).unwrap();
        let o = c.wait_with_output().unwrap();
        assert!(o.status.success(), "{name}");
        assert!(String::from_utf8_lossy(&o.stdout).contains(want), "{name}");
    }
    let b = fx("zstd", "text.l3.zst");
    let r = sediment_engine::archive_open_ext::open_stdin_ext(&b, ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), ArchiveFormat::Zstd);
    assert_eq!(r.entries()[0].path, b"data");
}
