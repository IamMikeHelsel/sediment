//! `.lzma`, `.lzma86`, `.tlz` and `.Z` single-stream files through
//! `archive_open::open_named` (fixtures from tests/gen/single_stream.py).

use std::path::PathBuf;

use sediment_engine::archive_open::open_named;
use sediment_engine::archive_reader::{ArchiveFormat, ReaderLimits};
use sediment_engine::lzma_alone::{decode_lzma, decode_lzma86};

fn fx(name: &str) -> Vec<u8> {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/fixtures/single_stream", name].iter().collect();
    std::fs::read(p).unwrap()
}

fn one_member(name: &str, format: ArchiveFormat) {
    let bytes = fx(name);
    let r = open_named(&bytes, name.as_bytes(), ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), format, "{name}");
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].path, b"payload.bin");
    assert_eq!(r.read(0).unwrap(), fx("payload.bin"));
}

#[test]
fn lzma_alone_file() {
    one_member("payload.bin.lzma", ArchiveFormat::Lzma);
}

#[test]
fn lzma86_x86_file() {
    one_member("payload.bin.lzma86", ArchiveFormat::Lzma86);
}

#[test]
fn compress_z_file() {
    one_member("payload.bin.Z", ArchiveFormat::CompressZ);
}

#[test]
fn tlz_is_tar() {
    let bytes = fx("two.tlz");
    let r = open_named(&bytes, b"two.tlz", ReaderLimits::default()).unwrap();
    assert_eq!(r.format(), ArchiveFormat::Tar);
    let names: Vec<_> = r.entries().iter().map(|e| e.path.clone()).collect();
    assert_eq!(names, vec![b"a.txt".to_vec(), b"dir/b.bin".to_vec()]);
    assert_eq!(r.read(1).unwrap(), (0u8..200).collect::<Vec<_>>());
}

#[test]
fn truncated_and_limits_err() {
    for name in ["payload.bin.lzma", "payload.bin.lzma86"] {
        let b = fx(name);
        for cut in [0, 1, 5, 13, 14, b.len() / 2, b.len() - 1] {
            assert!(open_named(&b[..cut], name.as_bytes(), ReaderLimits::default()).is_err(), "{name} cut {cut}");
        }
    }
    let b = fx("payload.bin.lzma");
    assert!(decode_lzma(&b, 100).is_err());
    let b = fx("payload.bin.lzma86");
    assert!(decode_lzma86(&b, 100).is_err());
    let mut bad = b.clone();
    bad[0] = 7;
    assert!(decode_lzma86(&bad, 1 << 20).is_err());
}

#[test]
fn garbage_never_panics() {
    let mut x: u32 = 0x1234_5678;
    for len in [13usize, 14, 20, 64, 300] {
        for _ in 0..50 {
            let mut b = vec![0x5d, 0, 0, 1, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            b.resize(len.max(13), 0);
            for v in b.iter_mut().skip(13) {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *v = x as u8;
            }
            let _ = open_named(&b, b"g.lzma", ReaderLimits::default());
            let _ = decode_lzma86(&b, 1 << 16);
        }
    }
}
