// SPDX-License-Identifier: MIT OR Apache-2.0
//! zip `-mm=` methods (Deflate64/BZip2/LZMA/XZ), the Deflate64 encoder and
//! tar `-mf=ustar|gnu|pax` formats. Oracle fixtures come from
//! tests/gen/zip_tar_write_methods.py (Python zipfile/tarfile).
use sediment_engine::archive_reader::{ReaderLimits, open_archive};
use sediment_engine::deflate64::inflate64_raw;
use sediment_engine::deflate64_encode::{Deflate64EncodeError, deflate64_compress};
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::tar_create::*;
use sediment_engine::tar_read::{TarReadLimits, read_entries};
use sediment_engine::zip_create::*;

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/zip_tar_write_methods/");

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FX}{name}")).unwrap()
}

fn file<'a>(name: &'a [u8], data: &'a [u8]) -> ArchiveEntry<'a> {
    ArchiveEntry { name, kind: EntryKind::File, data, mtime: 1_600_000_000, mode: 0o644, link_target: &[] }
}

fn lcg(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

fn read_zip(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let r = open_archive(bytes, ReaderLimits::default()).unwrap();
    (0..r.entries().len()).map(|i| (r.entries()[i].path.clone(), r.read(i).unwrap())).collect()
}

#[test]
fn deflate64_roundtrips_all_levels() {
    let far = {
        let blk = lcg(50_000, 7);
        let mut v = blk.clone();
        v.extend_from_slice(&lcg(5000, 9));
        v.extend_from_slice(&blk);
        v.extend(std::iter::repeat_n(b'z', 70_000)); // longer than 65538
        v
    };
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        b"abcabcabcabc".repeat(100),
        vec![0u8; 258],
        vec![0u8; 259],
        lcg(100_000, 3),
        far,
    ];
    for data in &inputs {
        for level in 0..=9 {
            let c = deflate64_compress(data, level, usize::MAX).unwrap();
            let d = inflate64_raw(&c, data.len() + 1, 1 << 20).unwrap();
            assert_eq!(&d, data, "level {level} len {}", data.len());
        }
    }
    // Long-distance data actually benefits from the 64 KiB window.
    let far = &inputs[6];
    let c9 = deflate64_compress(far, 9, usize::MAX).unwrap();
    assert!(c9.len() < 60_000, "{}", c9.len());
}

#[test]
fn deflate64_errors() {
    assert_eq!(deflate64_compress(b"x", 10, 100), Err(Deflate64EncodeError::InvalidLevel));
    assert_eq!(deflate64_compress(&lcg(10_000, 1), 6, 100), Err(Deflate64EncodeError::LimitExceeded));
}

#[test]
fn zip_methods_roundtrip_and_ids() {
    let payload = fx("payload.bin");
    let rnd = lcg(3000, 5);
    let entries = [file(b"payload.bin", &payload), file(b"rnd", &rnd), file(b"empty", b"")];
    for (m, id, ver) in [
        (ZipMethod::Copy, 0u16, 20u16),
        (ZipMethod::Deflate, 8, 20),
        (ZipMethod::Deflate64, 9, 21),
        (ZipMethod::Bzip2, 12, 46),
        (ZipMethod::Lzma, 14, 63),
        (ZipMethod::Xz, 95, 63),
    ] {
        assert_eq!(m.id(), id);
        let z = create_zip_with_method(&entries, ZipCreateOptions { level: 5 }, m, ZipCreateLimits::default()).unwrap();
        // Compressible payload uses the method; random data and empty files are stored.
        assert_eq!(z.methods, vec![id, 0, 0], "{m:?}");
        assert_eq!(u16::from_le_bytes([z.bytes[4], z.bytes[5]]), if id == 0 { 20 } else { ver });
        let got = read_zip(&z.bytes);
        assert_eq!(got[0], (b"payload.bin".to_vec(), payload.clone()));
        assert_eq!(got[1].1, rnd);
        assert!(got[2].1.is_empty());
        // -mx0 stores everything regardless of method.
        let z0 = create_zip_with_method(&entries, ZipCreateOptions { level: 0 }, m, ZipCreateLimits::default()).unwrap();
        assert_eq!(z0.methods, vec![0, 0, 0]);
    }
}

#[test]
fn zip_lzma_header_matches_python_layout() {
    let payload = fx("payload.bin");
    let py = fx("py_lzma.zip");
    // Our reader accepts Python's LZMA and BZip2 zips (oracle direction 1).
    assert_eq!(read_zip(&py)[0].1, payload);
    assert_eq!(read_zip(&fx("py_bzip2.zip"))[0].1, payload);
    let z = create_zip_with_method(&[file(b"payload.bin", &payload)], ZipCreateOptions { level: 6 }, ZipMethod::Lzma, ZipCreateLimits::default())
        .unwrap();
    let ours = &z.bytes;
    // Local header: flags bit 1 (EOS marker) set, method 14.
    let flags = u16::from_le_bytes([ours[6], ours[7]]);
    assert_eq!(flags & 2, 2);
    assert_eq!(u16::from_le_bytes([ours[8], ours[9]]), 14);
    let data_at = |b: &[u8]| 30 + u16::from_le_bytes([b[26], b[27]]) as usize + u16::from_le_bytes([b[28], b[29]]) as usize;
    let (o, p) = (data_at(ours), data_at(&py));
    // Properties size (2..4) and the lc/lp/pb byte match Python's encoder.
    assert_eq!(ours[o + 2..o + 5], py[p + 2..p + 5]);
}

#[test]
fn zip_method_names() {
    assert_eq!(ZipMethod::from_name("BZip2"), Some(ZipMethod::Bzip2));
    assert_eq!(ZipMethod::from_name("deflate64"), Some(ZipMethod::Deflate64));
    assert_eq!(ZipMethod::from_name("Store"), Some(ZipMethod::Copy));
    assert_eq!(ZipMethod::from_name("PPMd"), None);
}

fn tar_summary(bytes: &[u8]) -> Vec<(Vec<u8>, u64, i64, u32)> {
    read_entries(bytes, TarReadLimits::default())
        .unwrap()
        .into_iter()
        .map(|e| (e.path, e.size, e.mtime, e.mtime_nanos))
        .collect()
}

const LONG: &str = concat!(
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/",
    "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL.txt"
);
const UNI: &str = "caf\u{e9}-\u{65e5}\u{672c}.txt";

#[test]
fn pax_matches_python_tarfile() {
    let entries = [
        ArchiveEntry { mtime: 1_600_000_000, ..file(LONG.as_bytes(), b"long\n") },
        ArchiveEntry { mtime: 1_600_000_001, ..file(UNI.as_bytes(), b"uni\n") },
    ];
    let mut ours = create_tar_with_format(&entries, TarFormat::Pax, TarCreateLimits::default()).unwrap();
    // The third Python entry has a fractional mtime: write it with encode_headers_ext.
    let mut third = Vec::new();
    let spec = TarHeaderSpec { name: b"short.txt", kind: EntryKind::File, size: 3, mtime: 1_600_000_002, mode: 0o644, link_target: b"" };
    encode_headers_ext(&spec, TarFormat::Pax, 500_000_000, &mut third).unwrap();
    assert!(third.windows(18).any(|w| w == b"mtime=1600000002.5"));
    let mut data = b"ns\n".to_vec();
    data.resize(512, 0);
    third.extend_from_slice(&data);
    let end = ours.len() - ours.iter().rev().take_while(|&&b| b == 0).count();
    let end = end.div_ceil(512) * 512;
    ours.splice(end..end, third);
    let py = tar_summary(&fx("py_pax.tar"));
    assert_eq!(tar_summary(&ours), py);
    // Non-ASCII names get a pax path record even though they fit in ustar.
    assert!(ours.windows(5).any(|w| w == b"path="));
    let uni_rec = format!("path={UNI}\n");
    assert!(ours.windows(uni_rec.len()).any(|w| w == uni_rec.as_bytes()));
}

#[test]
fn default_format_is_unchanged_and_pax_only_when_needed() {
    let e = [file(UNI.as_bytes(), b"x")];
    let dflt = create_tar(&e, TarCreateLimits::default()).unwrap();
    assert!(!dflt.windows(5).any(|w| w == b"path="));
    let pax = create_tar_with_format(&e, TarFormat::Pax, TarCreateLimits::default()).unwrap();
    assert!(pax.windows(5).any(|w| w == b"path="));
    let ascii = [file(b"plain.txt", b"x")];
    assert_eq!(
        create_tar(&ascii, TarCreateLimits::default()).unwrap(),
        create_tar_with_format(&ascii, TarFormat::Pax, TarCreateLimits::default()).unwrap()
    );
}

#[test]
fn ustar_is_strict() {
    let long = [file(LONG.as_bytes(), b"x")];
    let fits = [file(b"dir/name.txt", b"x")];
    assert_eq!(create_tar_with_format(&long, TarFormat::Ustar, TarCreateLimits::default()), Err(TarCreateError::InvalidName));
    let u = create_tar_with_format(&fits, TarFormat::Ustar, TarCreateLimits::default()).unwrap();
    assert_eq!(tar_summary(&u)[0].0, b"dir/name.txt");
    let huge = TarHeaderSpec { name: b"big", kind: EntryKind::File, size: 1 << 34, mtime: 0, mode: 0o644, link_target: b"" };
    assert_eq!(encode_headers_ext(&huge, TarFormat::Ustar, 0, &mut Vec::new()), Err(TarCreateError::LimitExceeded));
    assert_eq!(encode_headers_ext(&huge, TarFormat::Pax, 1_000_000_000, &mut Vec::new()), Err(TarCreateError::InvalidEntry));
}

#[test]
fn gnu_longlink_and_base256() {
    let long = [file(LONG.as_bytes(), b"long\n"), file(UNI.as_bytes(), b"uni\n")];
    let g = create_tar_with_format(&long, TarFormat::Gnu, TarCreateLimits::default()).unwrap();
    assert_eq!(&g[..13], b"././@LongLink");
    assert_eq!(g[156], b'L');
    assert_eq!(&g[257..265], b"ustar  \0");
    let s = tar_summary(&g);
    assert_eq!(s[0].0, LONG.as_bytes());
    assert_eq!(s[1].0, UNI.as_bytes());
    // Huge size and negative mtime use base-256 fields the reader accepts.
    let spec = TarHeaderSpec { name: b"big", kind: EntryKind::File, size: 1 << 34, mtime: -5, mode: 0o644, link_target: b"" };
    let mut h = Vec::new();
    encode_headers_ext(&spec, TarFormat::Gnu, 0, &mut h).unwrap();
    assert_eq!(h.len(), 512);
    assert_eq!(h[124], 0x80);
    assert_eq!(h[136], 0xFF);
    let pax_neg = TarHeaderSpec { mtime: -2, size: 0, ..spec };
    let mut p = Vec::new();
    encode_headers_ext(&pax_neg, TarFormat::Pax, 250_000_000, &mut p).unwrap();
    assert!(p.windows(12).any(|w| w == b"mtime=-1.75\n"));
    let e = &read_entries(&{
        let mut a = p.clone();
        a.resize(a.len() + 1024, 0);
        a
    }, TarReadLimits::default())
    .unwrap()[0];
    assert_eq!((e.mtime, e.mtime_nanos), (-2, 250_000_000));
}

#[test]
fn format_names() {
    assert_eq!(TarFormat::from_name("posix"), Some(TarFormat::Pax));
    assert_eq!(TarFormat::from_name("GNU"), Some(TarFormat::Gnu));
    assert_eq!(TarFormat::from_name("v7"), None);
}
