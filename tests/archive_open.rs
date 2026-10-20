// SPDX-License-Identifier: MIT OR Apache-2.0
//! Library-level tests for `archive_open`: format routing, entry metadata,
//! limits, and robustness against truncated or bit-flipped input (must
//! return `Err`, never panic). Fixtures: tests/gen/cli_wire.py.
use std::borrow::Cow;
use std::path::{Path, PathBuf};

use sediment_engine::archive_open::{
    SevenZCodecs, SevenZReader, StreamReader, TarReader, decompress, is_compressed_tar_name, open_named,
    parse_gzip_header, stream_member_name,
};
use sediment_engine::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::sevenz_read::{FolderDecoder, SevenZReadError};

fn fxp(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli_wire").join(name)
}

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(fxp(name)).unwrap()
}

fn open<'a>(bytes: &'a [u8], name: &str) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    open_named(bytes, name.as_bytes(), ReaderLimits::default())
}

fn tree_file(rel: &str) -> Vec<u8> {
    fx(&format!("tree/{rel}"))
}

#[test]
fn formats_are_routed_by_magic() {
    let cases = [
        ("tree.zip", ArchiveFormat::Zip, 14),
        ("tree_ustar.tar", ArchiveFormat::Tar, 14),
        ("tree.tar.gz", ArchiveFormat::Tar, 14),
        ("tree.tbz2", ArchiveFormat::Tar, 14),
        ("tree.txz", ArchiveFormat::Tar, 14),
        ("bundle.gz", ArchiveFormat::Tar, 14),
        ("7z/tree_lzma.7z", ArchiveFormat::SevenZ, 14),
        ("words.txt.gz", ArchiveFormat::Gzip, 1),
        ("random.bin.bz2", ArchiveFormat::Bzip2, 1),
        ("readme.md.xz", ArchiveFormat::Xz, 1),
    ];
    for (name, format, n) in cases {
        let b = fx(name);
        let r = open(&b, name).unwrap();
        assert_eq!(r.format(), format, "{name}");
        assert_eq!(r.entries().len(), n, "{name}");
    }
    // Renaming does not change detection, only member naming.
    let b = fx("tree.tar.gz");
    assert_eq!(open(&b, "whatever.bin").unwrap().format(), ArchiveFormat::Tar); // FNAME tree.tar
    let b = fx("tree.tgz"); // no FNAME
    let r = open(&b, "renamed.gz").unwrap();
    assert_eq!(r.format(), ArchiveFormat::Gzip);
    assert_eq!(r.entries()[0].path, b"renamed");
    assert_eq!(open(b"hello", "x").err(), Some(ReaderError::Unsupported));
    assert_eq!(open(b"", "x").err(), Some(ReaderError::Unsupported));
}

#[test]
fn compressed_tar_name_must_hold_a_tar() {
    let b = fx("words.txt.gz");
    assert!(open(&b, "words.tgz").is_err());
    assert!(open(&b, "words.txt.gz").is_ok());
}

#[test]
fn entry_metadata() {
    let b = fx("tree_pax.tar");
    let r = open(&b, "tree_pax.tar").unwrap();
    for (i, e) in r.entries().iter().enumerate() {
        assert_eq!(e.mtime, Some(1_709_618_828));
        match e.kind {
            EntryKind::Dir => assert_eq!(e.mode, Some(0o755)),
            EntryKind::File => {
                assert_eq!(e.mode, Some(0o644));
                let path = String::from_utf8(e.path.clone()).unwrap();
                assert_eq!(r.read(i).unwrap(), tree_file(&path), "{path}");
                assert_eq!(e.size, tree_file(&path).len() as u64);
            }
            _ => panic!("unexpected kind"),
        }
        assert_eq!(r.crc32(i), None);
    }
    assert!(r.read(r.entries().len()).is_err());

    let b = fx("7z/tree_bcj.7z");
    let r = open(&b, "t.7z").unwrap();
    let i = r.entries().iter().position(|e| e.path == b"data/prog.bin").unwrap();
    assert_eq!(r.read(i).unwrap(), tree_file("data/prog.bin"));
    assert_eq!(r.crc32(i), Some(sediment_engine::crc32::crc32(&tree_file("data/prog.bin"))));
    assert_eq!(r.entries()[i].mtime, Some(1_709_618_828));
    assert_eq!(r.read(99), Err(ReaderError::OutOfRange));

    let b = fx("noname.gz");
    let r = open(&b, "dir/noname.gz").unwrap();
    assert_eq!(r.entries()[0].path, b"noname");
    assert_eq!(r.entries()[0].mtime, Some(1_709_618_828));
    assert_eq!(r.crc32(0), Some(sediment_engine::crc32::crc32(b"Hello, sediment!\n")));
    assert_eq!(r.read(1), Err(ReaderError::OutOfRange));
}

#[test]
fn tar_links_and_specials() {
    let b = fx("links.tar");
    let r = open(&b, "links.tar").unwrap();
    let kinds: Vec<_> = r.entries().iter().map(|e| (e.path.clone(), e.kind.clone(), e.size)).collect();
    assert_eq!(kinds[2], (b"sub/up.txt".to_vec(), EntryKind::Symlink { target: b"../target.txt".to_vec() }, 0));
    assert_eq!(kinds[3], (b"hard.txt".to_vec(), EntryKind::Hardlink { target: b"target.txt".to_vec() }, 4));

    let b = fx("7z/links.7z");
    let r = open(&b, "links.7z").unwrap();
    let up = r.entries().iter().find(|e| e.path == b"sub/up.txt").unwrap();
    assert_eq!(up.kind, EntryKind::Symlink { target: b"../target.txt".to_vec() });
    assert_eq!(up.size, 0);

    let b = fx("specials.tar");
    let t = TarReader::new(Cow::Borrowed(&b), ReaderLimits::default()).unwrap();
    assert_eq!(t.skipped_special(), 2);
    assert_eq!(t.entries().len(), 1);
    assert_eq!(t.read(0).unwrap(), b"plain\n");
}

#[test]
fn limits_are_enforced() {
    let few = ReaderLimits { max_entries: 3, ..ReaderLimits::default() };
    for name in ["tree_gnu.tar", "tree.tar.xz", "7z/tree_lzma2.7z"] {
        let b = fx(name);
        assert_eq!(open_named(&b, name.as_bytes(), few).err(), Some(ReaderError::LimitExceeded), "{name}");
    }
    let small = ReaderLimits { max_total_size: 4096, ..ReaderLimits::default() };
    for name in ["tree.tar.gz", "tree.tbz2", "tree.txz", "words.txt.gz", "7z/tree_copy.7z", "7z/tree_lzma.7z"] {
        let b = fx(name);
        assert_eq!(open_named(&b, name.as_bytes(), small).err(), Some(ReaderError::LimitExceeded), "{name}");
    }
    let entry = ReaderLimits { max_entry_size: 1000, ..ReaderLimits::default() };
    for name in ["tree_ustar.tar", "7z/tree_lzma.7z", "tree.zip"] {
        let b = fx(name);
        let r = open_named(&b, name.as_bytes(), entry).unwrap();
        let i = r.entries().iter().position(|e| e.path == b"data/words.txt").unwrap();
        assert_eq!(r.read(i), Err(ReaderError::LimitExceeded), "{name}");
        let j = r.entries().iter().position(|e| e.path == b"hello.txt").unwrap();
        assert!(r.read(j).is_ok());
    }
    let b = fx("words.txt.gz");
    assert_eq!(open_named(&b, b"w.gz", entry).err(), Some(ReaderError::LimitExceeded));
}

#[test]
fn integrity_errors() {
    let b = fx("bad_crc.tar.gz");
    assert_eq!(open(&b, "bad_crc.tar.gz").err(), Some(ReaderError::CrcMismatch));
    let b = fx("truncated.tar.xz");
    assert!(open(&b, "truncated.tar.xz").is_err());
    let b = fx("corrupt.bz2");
    assert!(open(&b, "corrupt.bz2").is_err());
    let b = fx("bad_checksum.tar");
    assert!(open(&b, "bad_checksum.tar").is_err());
    // PPMd (030401) is decoded since sevenz-ppmd-bcj2; every entry must verify its CRC.
    let b = fx("7z/tree_ppmd.7z");
    let r = open(&b, "p.7z").unwrap();
    let i = r.entries().iter().position(|e| e.size > 0).unwrap();
    assert_eq!(r.read(i).map(|d| d.len() as u64), Ok(r.entries()[i].size));
}

#[test]
fn stream_helpers() {
    assert_eq!(stream_member_name(b"a/b/c.txt.xz"), b"c.txt");
    assert_eq!(stream_member_name(b"c.TXZ"), b"c.tar");
    assert!(is_compressed_tar_name(b"x.tar.xz"));
    let b = fx("words.txt.gz");
    let h = parse_gzip_header(&b, 255).unwrap();
    assert_eq!(h.name.as_deref(), Some(&b"words.txt"[..]));
    assert_eq!(decompress(ArchiveFormat::Gzip, &b, 1 << 20).unwrap(), tree_file("data/words.txt"));
    assert_eq!(decompress(ArchiveFormat::Gzip, &b, 100), Err(ReaderError::LimitExceeded));
    assert_eq!(decompress(ArchiveFormat::Zip, &b, 100), Err(ReaderError::Unsupported));
    let r = StreamReader::new(ArchiveFormat::Xz, b"n".to_vec(), b"abc".to_vec(), None, None);
    assert_eq!(r.entries()[0].size, 3);
    assert_eq!(r.read(0).unwrap(), b"abc");
}

#[test]
fn sevenz_codecs_respect_limits() {
    let c = SevenZCodecs::new(100);
    assert_eq!(c.decode(&[0x21], &[0x10], &[0], 101), Err(SevenZReadError::LimitExceeded));
    // LZMA2 end marker only: zero output, but 5 bytes were promised.
    assert_eq!(c.decode(&[0x21], &[0x10], &[0], 5), Err(SevenZReadError::SizeMismatch));
    assert_eq!(c.decode(&[0x21], &[0x10], &[0], 0), Ok(Vec::new()));
    // Delta distance 1 decode of [1,1,1] = [1,2,3].
    assert_eq!(c.decode(&[0x03], &[0], &[1, 1, 1], 3), Ok(vec![1, 2, 3]));
    // Swap2.
    assert_eq!(c.decode(&[0x02, 0x03, 0x02], &[], &[1, 2, 3], 3), Ok(vec![2, 1, 3]));
    let b = fx("7z/tree_copy.7z");
    let r = SevenZReader::new(&b, ReaderLimits::default()).unwrap();
    assert_eq!(r.entries().len(), 14);
}

/// Every prefix (strided) and many single-bit flips of every fixture either
/// open and read cleanly or fail with an error. Never a panic.
#[test]
fn hostile_mutations_never_panic() {
    let names = [
        "tree.zip",
        "tree_ustar.tar",
        "tree_gnu.tar",
        "tree_pax.tar",
        "tree.tar.gz",
        "tree.tar.bz2",
        "tree.tar.xz",
        "words.txt.gz",
        "random.bin.bz2",
        "readme.md.xz",
        "links.tar",
        "specials.tar",
        "7z/tree_lzma.7z",
        "7z/tree_lzma2.7z",
        "7z/tree_bcj.7z",
        "7z/tree_arm64.7z",
        "7z/tree_delta.7z",
        "7z/tree_bzip2.7z",
        "7z/tree_deflate.7z",
        "7z/tree_deflate64.7z",
        "7z/tree_ppmd.7z",
        "7z/slip.7z",
        "7z/links.7z",
    ];
    let limits = ReaderLimits { max_total_size: 1 << 20, max_entry_size: 1 << 20, max_entries: 1000 };
    let exercise = |b: &[u8], name: &str| {
        if let Ok(r) = open_named(b, name.as_bytes(), limits) {
            for i in 0..r.entries().len() {
                let _ = r.read(i);
                let _ = r.crc32(i);
            }
        }
    };
    for name in names {
        let b = fx(name);
        let stride = (b.len() / 300).max(1);
        let mut cut = 0;
        while cut < b.len() {
            exercise(&b[..cut], name);
            cut += stride;
        }
        let mut seed = 0x9e37_79b9u32;
        for _ in 0..300 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let mut m = b.clone();
            let pos = (seed as usize >> 3) % m.len();
            m[pos] ^= 1 << (seed & 7);
            exercise(&m, name);
        }
    }
}
