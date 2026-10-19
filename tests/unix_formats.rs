// SPDX-License-Identifier: MIT OR Apache-2.0
//! cpio / ar / deb / rpm / xar readers against the spec-built fixtures in
//! tests/fixtures/unix (tests/gen/unix.py; Python stdlib tarfile, gzip,
//! zlib, bz2, lzma and hashlib are the oracle). Each `X.manifest` lists
//! the members a reader must report, with the SHA-256 of their contents.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use sediment_engine::ar_archive::{ArError, ArReader, DebReader, parse_ar};
use sediment_engine::archive_detect::{ArchiveFormat as Detected, detect_format};
use sediment_engine::archive_open::open_named;
use sediment_engine::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use sediment_engine::cpio_archive::{CpioError, CpioFormat, CpioLimits, parse_cpio};
use sediment_engine::extract_plan::{EntryKind, PlanError, PlanOptions, plan_extraction};
use sediment_engine::hash_sha256::sha256;
use sediment_engine::rpm_archive::{RpmError, RpmLimits, RpmReader, parse_rpm};
use sediment_engine::xar_archive::{XarReader, parse_header as xar_header};
use sediment_engine::xml_mini::{XmlLimits, parse_xml};

const BIN: &str = env!("CARGO_BIN_EXE_sediment");

fn fx(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unix").join(name)
}

fn load(name: &str) -> Vec<u8> {
    fs::read(fx(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn open<'a>(bytes: &'a [u8], name: &str) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    open_named(bytes, name.as_bytes(), ReaderLimits::default())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

const MANIFESTED: [(&str, ArchiveFormat); 17] = [
    ("newc.cpio", ArchiveFormat::Cpio),
    ("crc.cpio", ArchiveFormat::Cpio),
    ("odc.cpio", ArchiveFormat::Cpio),
    ("bin-le.cpio", ArchiveFormat::Cpio),
    ("bin-be.cpio", ArchiveFormat::Cpio),
    ("newc.cpio.gz", ArchiveFormat::Cpio),
    ("gnu.a", ArchiveFormat::Ar),
    ("bsd.a", ArchiveFormat::Ar),
    ("hello-xz.deb", ArchiveFormat::Deb),
    ("hello-bz2.deb", ArchiveFormat::Deb),
    ("hello-plain.deb", ArchiveFormat::Deb),
    ("hello-lzma.deb", ArchiveFormat::Deb),
    ("hello-gzip.rpm", ArchiveFormat::Rpm),
    ("hello-xz.rpm", ArchiveFormat::Rpm),
    ("hello-bzip2.rpm", ArchiveFormat::Rpm),
    ("hello-lzma.rpm", ArchiveFormat::Rpm),
    ("sample-sha1.xar", ArchiveFormat::Xar),
];

/// Every reader reports exactly the oracle's members and contents.
#[test]
fn manifests_match_oracle() {
    let mut names: Vec<(&str, ArchiveFormat)> = MANIFESTED.to_vec();
    names.push(("sample-sha256.xar", ArchiveFormat::Xar));
    for (name, format) in names {
        let bytes = load(name);
        let r = open(&bytes, name).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(r.format(), format, "{name}");
        let text = String::from_utf8(load(&format!("{name}.manifest"))).unwrap();
        let rows: Vec<&str> = text.lines().collect();
        assert_eq!(r.entries().len(), rows.len(), "{name}: entry count");
        for (i, (e, row)) in r.entries().iter().zip(&rows).enumerate() {
            let f: Vec<&str> = row.split('\t').collect();
            let ctx = format!("{name}[{i}] {}", String::from_utf8_lossy(&e.path));
            assert_eq!(hex(&e.path), f[5], "{ctx}: path");
            assert_eq!(e.size.to_string(), f[1], "{ctx}: size");
            assert_eq!(e.mode.map_or("-".into(), |m| format!("{m:o}")), f[2], "{ctx}: mode");
            assert_eq!(e.mtime.map_or("-".into(), |m| m.to_string()), f[3], "{ctx}: mtime");
            match (&e.kind, f[0]) {
                (EntryKind::File, "F") | (EntryKind::Dir, "D") => assert_eq!(f[6], "-", "{ctx}"),
                (EntryKind::Symlink { target }, "L") | (EntryKind::Hardlink { target }, "H") => {
                    assert_eq!(hex(target), f[6], "{ctx}: target")
                }
                (k, want) => panic!("{ctx}: kind {k:?}, want {want}"),
            }
            let data = r.read(i).unwrap_or_else(|e| panic!("{ctx}: read {e:?}"));
            if f[0] == "F" {
                assert_eq!(data.len() as u64, e.size, "{ctx}");
                assert_eq!(hex(&sha256(&data)), f[4], "{ctx}: content");
            }
        }
        assert_eq!(r.read(r.entries().len()), Err(ReaderError::OutOfRange), "{name}");
    }
}

#[test]
fn detection() {
    let cases = [
        ("newc.cpio", Detected::Cpio),
        ("crc.cpio", Detected::Cpio),
        ("odc.cpio", Detected::Cpio),
        ("bin-le.cpio", Detected::Cpio),
        ("bin-be.cpio", Detected::Cpio),
        ("newc.cpio.gz", Detected::Gzip),
        ("gnu.a", Detected::Ar),
        ("hello-xz.deb", Detected::Ar),
        ("hello-gzip.rpm", Detected::Rpm),
        ("sample-sha1.xar", Detected::Xar),
    ];
    for (name, want) in cases {
        assert_eq!(detect_format(&load(name)), want, "{name}");
    }
    // The 2-byte binary magic alone is not enough.
    assert_eq!(detect_format(&[0xC7, 0x71, 0, 0, 0, 0, 0, 0]), Detected::Unknown);
    assert_eq!(detect_format(b"07070"), Detected::Unknown);
}

#[test]
fn cpio_low_level() {
    let b = load("newc.cpio");
    let m = parse_cpio(&b, &CpioLimits::default()).unwrap();
    assert_eq!(m.len(), 10);
    assert!(m.iter().all(|x| x.format == CpioFormat::Newc));
    assert_eq!(m[0].name, b".");
    assert_eq!(m[8].rdev, 0x01 << 32 | 0x03);
    assert_eq!(m[4].data_len, 0, "first hard link carries no data in newc");
    assert_eq!(parse_cpio(&b, &CpioLimits { max_entries: 9, ..CpioLimits::default() }), Err(CpioError::TooManyEntries));
    assert_eq!(parse_cpio(&b, &CpioLimits { max_name_len: 8, ..CpioLimits::default() }), Err(CpioError::LimitExceeded));
    let be = parse_cpio(&load("bin-be.cpio"), &CpioLimits::default()).unwrap();
    assert_eq!(be[2].mtime, 1_709_618_828);
    assert_eq!(be[2].format, CpioFormat::Binary);
    assert_eq!(parse_cpio(&load("crc-bad.cpio"), &CpioLimits::default()), Err(CpioError::ChecksumMismatch));
    assert_eq!(parse_cpio(&load("no-trailer.cpio"), &CpioLimits::default()), Err(CpioError::Truncated));
    assert_eq!(parse_cpio(&load("stripped.cpio"), &CpioLimits::default()), Err(CpioError::Unsupported));
    assert_eq!(parse_cpio(b"070701", &CpioLimits::default()), Err(CpioError::Truncated));
    assert_eq!(parse_cpio(b"garbage!", &CpioLimits::default()), Err(CpioError::BadMagic));
    let mut bad = b.clone();
    bad[10] = b'g';
    assert_eq!(parse_cpio(&bad, &CpioLimits::default()), Err(CpioError::BadNumber));
    // namesize 0.
    let mut z = b.clone();
    z[94..102].copy_from_slice(b"00000000");
    assert_eq!(parse_cpio(&z, &CpioLimits::default()), Err(CpioError::BadName));
    // Huge filesize.
    let mut h = b.clone();
    h[54..62].copy_from_slice(b"FFFFFFFF");
    assert_eq!(parse_cpio(&h, &CpioLimits::default()), Err(CpioError::Truncated));
}

#[test]
fn cpio_errors_via_reader() {
    assert_eq!(open(&load("crc-bad.cpio"), "x.cpio").err(), Some(ReaderError::CrcMismatch));
    assert_eq!(open(&load("no-trailer.cpio"), "x.cpio").err(), Some(ReaderError::Truncated));
    // stripped (07070X) is not detected as cpio at all.
    assert_eq!(open(&load("stripped.cpio"), "x.cpio").err(), Some(ReaderError::Unsupported));
}

#[test]
fn ar_low_level() {
    let m = parse_ar(&load("gnu.a"), 100).unwrap();
    assert_eq!(m.len(), 4);
    assert_eq!(m[0].mode, 0o755);
    assert_eq!(parse_ar(&load("gnu.a"), 3), Err(ArError::TooManyEntries));
    assert_eq!(parse_ar(&load("ar-badname.a"), 10), Err(ArError::BadName));
    assert_eq!(parse_ar(&load("ar-trunc.a"), 10), Err(ArError::Truncated));
    assert_eq!(parse_ar(b"!<thin>\n", 10), Err(ArError::BadMagic));
    assert_eq!(parse_ar(b"!<arch>\n", 10), Ok(vec![]));
    let mut bad = load("bsd.a");
    bad[8 + 58] = b'x';
    assert_eq!(parse_ar(&bad, 10), Err(ArError::BadHeader));
    let mut n = load("bsd.a");
    n[8 + 48] = b'z';
    assert_eq!(parse_ar(&n, 10), Err(ArError::BadNumber));
    // A .deb opened as a plain ar archive shows its three members.
    let deb = load("hello-xz.deb");
    let r = ArReader::new(&deb, ReaderLimits::default()).unwrap();
    let names: Vec<&[u8]> = r.entries().iter().map(|e| e.path.as_slice()).collect();
    assert_eq!(names, [&b"debian-binary"[..], b"control.tar.gz", b"data.tar.xz"]);
    assert_eq!(r.read(0).unwrap(), b"2.0\n");
}

#[test]
fn deb_details() {
    let b = load("hello-xz.deb");
    let d = DebReader::new(&b, ReaderLimits::default()).unwrap();
    assert_eq!(d.format_version(), b"2.0");
    assert_eq!(open(&load("hello-zst.deb"), "x.deb").err(), Some(ReaderError::Unsupported));
    // Not a package: first member is not debian-binary -> plain ar.
    assert_eq!(open(&load("gnu.a"), "x.deb").unwrap().format(), ArchiveFormat::Ar);
    // Wrong package version.
    let mut v = b.clone();
    let i = v.windows(4).position(|w| w == b"2.0\n").unwrap();
    v[i] = b'3';
    assert_eq!(DebReader::new(&v, ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
}

#[test]
fn rpm_details() {
    let b = load("hello-gzip.rpm");
    let r = RpmReader::new(&b, ReaderLimits::default()).unwrap();
    let i = r.info();
    assert_eq!((i.name.as_str(), i.version.as_str(), i.release.as_str()), ("hello", "1.0", "1"));
    assert_eq!(i.arch.as_deref(), Some("noarch"));
    assert_eq!(i.payload_compressor.as_deref(), Some("gzip"));
    assert_eq!(i.header_offset % 8, 0);
    let (_, h) = parse_rpm(&b, &RpmLimits::default()).unwrap();
    assert_eq!(h.get_string_array(1117).unwrap().unwrap(), ["hello", "hi", "README", "data.txt"]);
    assert_eq!(h.get_u32_array(1116).unwrap().unwrap(), [0, 0, 1, 2]);
    assert_eq!(h.get_string(1117), Err(RpmError::BadEntry));
    assert_eq!(h.get_string(9999), Ok(None));
    assert_eq!(parse_rpm(&load("hello-badsum.rpm"), &RpmLimits::default()).err(), Some(RpmError::DigestMismatch));
    assert_eq!(parse_rpm(&load("rpm-trunc.rpm"), &RpmLimits::default()).err(), Some(RpmError::Truncated));
    assert_eq!(parse_rpm(&b[..50], &RpmLimits::default()).err(), Some(RpmError::Truncated));
    assert_eq!(
        parse_rpm(&b, &RpmLimits { max_index_entries: 2, ..RpmLimits::default() }).err(),
        Some(RpmError::LimitExceeded)
    );
    let mut sig = b.clone();
    sig[79] = 1;
    assert_eq!(parse_rpm(&sig, &RpmLimits::default()).err(), Some(RpmError::UnsupportedSignatureType));
    let mut hm = b.clone();
    hm[96] = 0;
    assert_eq!(parse_rpm(&hm, &RpmLimits::default()).err(), Some(RpmError::BadHeaderMagic));
    for (name, want) in [
        ("hello-zstd.rpm", ReaderError::Unsupported),
        ("hello-badsum.rpm", ReaderError::CrcMismatch),
        ("hello-badpayload.rpm", ReaderError::CrcMismatch),
        ("rpm-trunc.rpm", ReaderError::Truncated),
    ] {
        assert_eq!(open(&load(name), name).err(), Some(want), "{name}");
    }
}

#[test]
fn xar_details() {
    let b = load("sample-sha256.xar");
    let h = xar_header(&b).unwrap();
    assert_eq!((h.checksum_alg, h.checksum_name.as_deref()), (3, Some("sha256")));
    assert_eq!(h.header_size, 36);
    assert_eq!(open(&load("bad-toc.xar"), "x.xar").err(), Some(ReaderError::CrcMismatch));
    let bad = load("bad-data.xar");
    let r = XarReader::new(&bad, ReaderLimits::default()).unwrap();
    assert_eq!(r.read(1), Err(ReaderError::CrcMismatch));
    assert!(r.read(2).is_ok());
    let mut v = b.clone();
    v[6] = 9; // version
    assert_eq!(open(&v, "x.xar").err(), Some(ReaderError::Invalid));
    assert_eq!(open(&b[..20], "x.xar").err(), Some(ReaderError::Truncated));
    assert_eq!(open(&b[..100], "x.xar").err(), Some(ReaderError::Truncated));
    // XML parser robustness on the real TOC shape.
    let x = parse_xml(b"<xar><toc><file id=\"1\"><name>a</name></file></toc></xar>", &XmlLimits::default()).unwrap();
    assert_eq!(x.nodes.len(), 4);
}

#[test]
fn reader_limits() {
    for (name, _) in MANIFESTED {
        let b = load(name);
        let n = open(&b, name).unwrap().entries().len();
        let few = ReaderLimits { max_entries: 1, ..ReaderLimits::default() };
        assert_eq!(open_named(&b, name.as_bytes(), few).err(), Some(ReaderError::LimitExceeded), "{name}");
        let small = ReaderLimits { max_total_size: 40, ..ReaderLimits::default() };
        assert!(open_named(&b, name.as_bytes(), small).is_err(), "{name}");
        let entry = ReaderLimits { max_entry_size: 40, ..ReaderLimits::default() };
        let r = open_named(&b, name.as_bytes(), entry).unwrap();
        let big = (0..n).find(|&i| matches!(r.entries()[i].kind, EntryKind::File) && r.entries()[i].size > 40);
        if let Some(i) = big {
            assert_eq!(r.read(i), Err(ReaderError::LimitExceeded), "{name}");
        }
    }
}

/// Every truncation and many byte flips of every fixture: errors only,
/// never a panic.
#[test]
fn mutation_robustness() {
    let mut names: Vec<String> = fs::read_dir(fx(""))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".manifest"))
        .collect();
    names.sort();
    let mut seed = 0x1234_5678u32;
    let exercise = |b: &[u8], name: &str| {
        if let Ok(r) = open(b, name) {
            for i in 0..r.entries().len() {
                let _ = r.read(i);
            }
        }
    };
    for name in &names {
        let b = load(name);
        let step = (b.len() / 300).max(1);
        for k in (0..b.len()).step_by(step) {
            exercise(&b[..k], name);
        }
        for _ in 0..300 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let mut m = b.clone();
            let pos = (seed >> 8) as usize % m.len();
            m[pos] ^= 1 << (seed % 8);
            exercise(&m, name);
        }
    }
}

#[test]
fn hostile_paths_rejected_by_planner() {
    for name in ["evil.cpio", "evil.xar"] {
        let b = load(name);
        let r = open(&b, name).unwrap();
        let f = plan_extraction(r.entries(), &PlanOptions::default()).unwrap_err();
        assert_eq!(f.error, PlanError::ParentTraversal, "{name}");
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

static N: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> TempDir {
        let p = std::env::temp_dir().join(format!("sediment-unix-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `x` writes every manifest file with the oracle's contents; `t` passes.
#[test]
fn cli_extract_and_test() {
    for (name, _) in MANIFESTED {
        let t = Command::new(BIN).arg("t").arg(fx(name)).output().unwrap();
        assert!(t.status.success(), "{name}: {}", String::from_utf8_lossy(&t.stderr));
        let dir = TempDir::new();
        let o = Command::new(BIN).arg("x").arg(format!("-o{}", dir.0.display())).arg("-snl").arg(fx(name)).output().unwrap();
        assert!(o.status.success(), "{name}: {}", String::from_utf8_lossy(&o.stderr));
        let text = String::from_utf8(load(&format!("{name}.manifest"))).unwrap();
        for row in text.lines() {
            let f: Vec<&str> = row.split('\t').collect();
            let rel = String::from_utf8(unhex(f[5])).unwrap();
            let p = dir.0.join(&rel);
            match f[0] {
                "F" => assert_eq!(hex(&sha256(&fs::read(&p).unwrap())), f[4], "{name}: {rel}"),
                "D" => assert!(p.is_dir(), "{name}: {rel}"),
                "H" => {
                    let target = dir.0.join(String::from_utf8(unhex(f[6])).unwrap());
                    assert_eq!(fs::read(&p).unwrap(), fs::read(&target).unwrap(), "{name}: {rel}");
                }
                "L" => {
                    let t = fs::read_link(&p).unwrap();
                    assert_eq!(t.to_string_lossy().as_bytes(), unhex(f[6]), "{name}: {rel}");
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn cli_refuses_hostile_and_corrupt() {
    for name in ["evil.cpio", "evil.xar", "crc-bad.cpio", "hello-badsum.rpm", "bad-toc.xar", "hello-zst.deb"] {
        let dir = TempDir::new();
        let o = Command::new(BIN).arg("x").arg(format!("-o{}", dir.0.display())).arg(fx(name)).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{name}");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0, "{name}: nothing written");
    }
    let o = Command::new(BIN).arg("t").arg(fx("bad-data.xar")).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    let l = Command::new(BIN).arg("l").arg(fx("hello-gzip.rpm")).output().unwrap();
    assert!(String::from_utf8_lossy(&l.stdout).contains("./usr/bin/hello\n"));
}
