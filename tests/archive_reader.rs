// SPDX-License-Identifier: MIT OR Apache-2.0
use std::path::Path;

use sediment_engine::archive_reader::*;
use sediment_engine::extract_plan::EntryKind;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extract").join(name)).unwrap()
}

#[test]
fn zip_metadata() {
    let bytes = fixture("basic.zip");
    let r = open_archive(&bytes, ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), ArchiveFormat::Zip);
    let e = r.entries();
    assert_eq!(e.len(), 6);
    assert_eq!(e[0].kind, EntryKind::Dir);
    assert_eq!(e[0].mode, Some(0o755));
    assert_eq!(e[3].path, b"bin/run.sh");
    assert_eq!((e[3].kind.clone(), e[3].size, e[3].mode), (EntryKind::File, 18, Some(0o755)));
    assert_eq!(e[1].mtime, Some(1_577_934_246));
    assert_eq!(r.read(1).unwrap(), b"Sediment extraction fixture.\n".repeat(40));
    assert_eq!(r.read(2).unwrap(), b"hello, world\n");
    assert_eq!(r.crc32(2), Some(0xf424_7453));
    assert_eq!(r.read(6), Err(ReaderError::OutOfRange));
}

#[test]
fn zip_symlink_kind() {
    let bytes = fixture("symlink_ok.zip");
    let r = ZipReader::new(&bytes, ReaderLimits::default()).unwrap();
    assert_eq!(r.entries()[1].kind, EntryKind::Symlink { target: b"target.txt".to_vec() });
    assert_eq!(r.entries()[1].size, 0);
}

#[test]
fn crc_mismatch_reported() {
    let bytes = fixture("badcrc.zip");
    let r = open_archive(&bytes, ReaderLimits::default()).unwrap();
    assert_eq!(r.read(0), Err(ReaderError::CrcMismatch));
}

#[test]
fn limits_enforced() {
    let bytes = fixture("basic.zip");
    let few = ReaderLimits { max_entries: 2, ..ReaderLimits::default() };
    assert!(open_archive(&bytes, few).is_err());
    let small = ReaderLimits { max_entry_size: 100, ..ReaderLimits::default() };
    let r = open_archive(&bytes, small).unwrap();
    assert_eq!(r.read(1), Err(ReaderError::LimitExceeded));
}

#[test]
fn truncated_and_corrupted_never_panic() {
    let bytes = fixture("basic.zip");
    for n in 0..bytes.len() {
        let cut = &bytes[..n];
        if let Ok(r) = open_archive(cut, ReaderLimits::default()) {
            for i in 0..r.entries().len() {
                let _ = r.read(i);
            }
        }
    }
    for pos in 0..bytes.len() {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut b = bytes.clone();
            b[pos] ^= flip;
            if let Ok(r) = open_archive(&b, ReaderLimits::default()) {
                for i in 0..r.entries().len() {
                    let _ = r.read(i);
                }
            }
        }
    }
}

#[test]
fn format_detection() {
    assert_eq!(detect_format(b"PK\x03\x04rest"), Some(ArchiveFormat::Zip));
    assert_eq!(detect_format(b"PK\x05\x06"), Some(ArchiveFormat::Zip));
    assert_eq!(detect_format(b"7z\xbc\xaf\x27\x1c"), Some(ArchiveFormat::SevenZ));
    assert_eq!(detect_format(b"\xfd7zXZ\x00"), Some(ArchiveFormat::Xz));
    assert_eq!(detect_format(b"\x1f\x8b\x08"), Some(ArchiveFormat::Gzip));
    assert_eq!(detect_format(b"BZh9"), Some(ArchiveFormat::Bzip2));
    let mut tar = vec![0u8; 512];
    tar[257..262].copy_from_slice(b"ustar");
    assert_eq!(detect_format(&tar), Some(ArchiveFormat::Tar));
    assert_eq!(detect_format(b"hello"), None);
    assert_eq!(open_archive(b"hello", ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
    assert_eq!(open_archive(&tar, ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
}
