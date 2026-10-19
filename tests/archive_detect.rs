use sediment_engine::archive_detect::{ArchiveFormat, detect_format};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tar/");

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}{name}")).unwrap()
}

#[test]
fn detects_python_generated_samples() {
    for (name, want) in [
        ("detect/sample.gz", ArchiveFormat::Gzip),
        ("detect/sample.bz2", ArchiveFormat::Bzip2),
        ("detect/sample.xz", ArchiveFormat::Xz),
        ("detect/sample.lzma", ArchiveFormat::LzmaAlone),
        ("detect/sample.zip", ArchiveFormat::Zip),
        ("detect/empty.zip", ArchiveFormat::Zip),
        ("detect/v7.tar", ArchiveFormat::TarHeuristic),
        ("ustar.tar", ArchiveFormat::Tar),
        ("gnu.tar", ArchiveFormat::Tar),
        ("pax.tar", ArchiveFormat::Tar),
    ] {
        assert_eq!(detect_format(&fx(name)), want, "{name}");
    }
}

#[test]
fn sevenz_signature() {
    let mut b = vec![0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4];
    b.resize(32, 0);
    assert_eq!(detect_format(&b), ArchiveFormat::SevenZip);
}

#[test]
fn unknown_and_short_inputs() {
    assert_eq!(detect_format(&[]), ArchiveFormat::Unknown);
    assert_eq!(detect_format(b"PK"), ArchiveFormat::Unknown);
    assert_eq!(detect_format(b"BZh0abc"), ArchiveFormat::Unknown);
    assert_eq!(detect_format(b"hello world, plain text file"), ArchiveFormat::Unknown);
    assert_eq!(detect_format(&[0u8; 2048]), ArchiveFormat::Unknown);
    // Bad tar checksum: not tar.
    assert_eq!(detect_format(&fx("bad_checksum.tar")), ArchiveFormat::Unknown);
    // LZMA-alone heuristic rejects odd dictionary sizes / props.
    let mut l = fx("detect/sample.lzma");
    l[1..5].copy_from_slice(&12345u32.to_le_bytes());
    assert_eq!(detect_format(&l), ArchiveFormat::Unknown);
    let mut l = fx("detect/sample.lzma");
    l[0] = 225;
    assert_eq!(detect_format(&l), ArchiveFormat::Unknown);
    // Every prefix of every sample is handled without panicking.
    for name in ["detect/sample.gz", "detect/sample.lzma", "ustar.tar", "detect/sample.zip"] {
        let b = fx(name);
        for i in 0..b.len().min(700) {
            let _ = detect_format(&b[..i]);
        }
    }
}
