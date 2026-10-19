// SPDX-License-Identifier: MIT OR Apache-2.0
mod zip_ext_common;

use sediment_engine::crc32::crc32;
use sediment_engine::zip_reader2::{Compression, Encryption, Reader2Error, Reader2Limits, ZipArchive2};
use zip_ext_common::*;

fn open(bytes: &[u8]) -> Result<ZipArchive2<'_>, Reader2Error> {
    ZipArchive2::open(bytes, Reader2Limits::default())
}

#[test]
fn differential_against_python_manifest() {
    let rows = manifest();
    assert!(rows.len() > 30);
    for file in FIXTURES {
        let bytes = fixture(file);
        let zip = open(&bytes).unwrap_or_else(|e| panic!("{file}: {e:?}"));
        let expected: Vec<&ManifestRow> = rows.iter().filter(|r| r.file == *file).collect();
        assert_eq!(zip.len(), expected.len(), "{file} entry count");
        for row in expected {
            let e = &zip.entries()[row.idx];
            let ctx = format!("{file}#{}", row.idx);
            assert_eq!(e.raw_name, &row.raw_name[..], "{ctx} raw name");
            if e.unicode_name.is_some() || e.flags & 0x0800 != 0 {
                assert_eq!(e.name(), &row.name[..], "{ctx} name");
                assert!(e.name_is_utf8());
            }
            assert_eq!(e.uncompressed_size, row.file_size, "{ctx} size");
            assert_eq!(e.compressed_size, row.compress_size, "{ctx} csize");
            assert_eq!(e.crc32, row.crc, "{ctx} crc");
            assert_eq!(e.method, row.method, "{ctx} method");
            assert_eq!(e.flags, row.flags, "{ctx} flags");
            assert_eq!(e.header_start, row.header_offset, "{ctx} header offset");
            match row.data {
                Some((crc, len)) => {
                    let data = zip.read(row.idx, 1 << 20).unwrap_or_else(|err| panic!("{ctx}: {err:?}"));
                    assert_eq!(data.len(), len, "{ctx} len");
                    assert_eq!(crc32(&data), crc, "{ctx} data crc");
                }
                None => assert_eq!(zip.read(row.idx, 1 << 20), Err(Reader2Error::Encrypted), "{ctx}"),
            }
        }
    }
}

#[test]
fn zip64_eocd_and_central_extras() {
    let bytes = fixture("zip64_eocd.zip");
    let zip = open(&bytes).unwrap();
    assert!(zip.is_zip64());
    assert_eq!(zip.prefix_len(), 0);
    // ZIP64_LIMIT was lowered to 100, so every entry has a zip64 extra.
    assert!(zip.entries().iter().all(|e| e.zip64));
    assert_eq!(zip.entries()[1].compression, Compression::Stored);
    assert_eq!(zip.entries()[0].compression, Compression::Deflate);
}

#[test]
fn zip64_forced_local_extras_only() {
    let bytes = fixture("zip64_forced.zip");
    let zip = open(&bytes).unwrap();
    assert!(!zip.is_zip64());
    assert_eq!(zip.comment(), b"forced zip64");
    for e in zip.entries() {
        assert!(e.zip64, "local zip64 extra expected");
        assert!(e.descriptor.is_none());
    }
    let dir = &zip.entries()[3];
    assert!(dir.is_dir());
    assert_eq!(dir.unix_mode(), Some(0o100644));
}

#[test]
fn streamed_descriptors() {
    for (file, zip64) in [("stream_desc.zip", false), ("stream_desc64.zip", true)] {
        let bytes = fixture(file);
        let zip = open(&bytes).unwrap();
        for e in zip.entries() {
            assert!(e.has_data_descriptor());
            let d = e.descriptor.expect("descriptor");
            assert!(d.layout.signature);
            assert_eq!(d.layout.zip64, zip64, "{file}");
            assert_eq!(d.crc32, e.crc32);
            assert_eq!(d.compressed_size, e.compressed_size);
            assert_eq!(d.end, e.data_end + d.layout.len());
        }
    }
}

#[test]
fn unsigned_descriptors_and_signature_valued_crc() {
    let bytes = fixture("desc_nosig.zip");
    let zip = open(&bytes).unwrap();
    let e = zip.entries();
    assert!(!e[0].descriptor.unwrap().layout.signature);
    assert!(!e[1].descriptor.unwrap().layout.signature);
    // CRC equals 0x08074b50 and there is no signature: the matcher must not
    // be fooled into a 4-byte shift.
    assert_eq!(e[2].crc32, 0x0807_4b50);
    assert!(!e[2].descriptor.unwrap().layout.signature);
    assert!(e[3].descriptor.unwrap().layout.signature);
    assert!(e[4].descriptor.is_none());
    for i in 0..zip.len() {
        zip.read(i, 4096).unwrap();
    }
}

#[test]
fn extras_are_reported() {
    let bytes = fixture("extras.zip");
    let zip = open(&bytes).unwrap();
    let e = zip.entries();
    assert_eq!(e[0].unicode_name, Some("café.txt".as_bytes()));
    assert_eq!(e[0].name(), "café.txt".as_bytes());
    let ut = e[0].extended_timestamp.unwrap();
    assert_eq!(ut.mtime, Some(1_700_000_000));
    assert_eq!(ut.atime, Some(1_700_000_100), "local copy preferred");
    let owner = e[0].unix_owner.unwrap();
    assert_eq!((owner.uid, owner.gid), (1000, 50));
    // Stale Unicode Path record is ignored.
    assert_eq!(e[1].unicode_name, None);
    assert_eq!(e[1].name(), e[1].raw_name);
    assert!(!e[1].name_is_utf8());
    let nt = e[2].ntfs_times.unwrap();
    let (secs, nanos) = sediment_engine::zip_extra_read::filetime_to_unix(nt.mtime);
    assert_eq!((secs, nanos), (1_700_000_000, 123_456_700));
    assert_eq!(zip.find("café.txt".as_bytes()), Some(0));
    assert_eq!(zip.find(b"ntfs.txt"), Some(2));
    assert_eq!(zip.find(b"missing"), None);
}

#[test]
fn encryption_is_reported_not_decrypted() {
    let bytes = fixture("encrypted.zip");
    let zip = open(&bytes).unwrap();
    let e = zip.entries();
    assert_eq!(e[0].encryption, Encryption::Traditional);
    match e[1].encryption {
        Encryption::Aes(info) => {
            assert_eq!(info.vendor_version, 2);
            assert_eq!(info.key_bits(), 256);
            assert_eq!(info.actual_method, 8);
        }
        other => panic!("expected AES, got {other:?}"),
    }
    assert_eq!(e[1].compression, Compression::Deflate);
    assert_eq!(zip.read(0, 1000), Err(Reader2Error::Encrypted));
    assert_eq!(zip.read(1, 1000), Err(Reader2Error::Encrypted));
    assert_eq!(zip.raw_data(1).unwrap().len(), 58);
    assert_eq!(&zip.read(2, 1000).unwrap()[..], b"not encrypted\n");
}

#[test]
fn prefixed_archives() {
    for file in ["prefixed.zip", "prefixed_zip64.zip"] {
        let bytes = fixture(file);
        let zip = open(&bytes).unwrap();
        assert_eq!(zip.prefix_len(), 512, "{file}");
        assert_eq!(zip.entries()[0].local_header_offset, 0);
        assert_eq!(zip.entries()[0].header_start, 512);
    }
}

#[test]
fn more_than_65535_entries_zip64() {
    let entries: Vec<(Vec<u8>, Vec<u8>)> =
        (0..70_000u32).map(|i| (format!("f{i}").into_bytes(), vec![(i % 251) as u8])).collect();
    let bytes = build_stored(&entries, Tail::Zip64);
    let zip = open(&bytes).unwrap();
    assert!(zip.is_zip64());
    assert_eq!(zip.len(), 70_000);
    assert_eq!(zip.entries()[69_999].raw_name, b"f69999");
    assert_eq!(&zip.read(69_999, 1).unwrap()[..], &[(69_999u32 % 251) as u8]);

    let limited = Reader2Limits { max_entries: 65_535, ..Reader2Limits::default() };
    assert_eq!(ZipArchive2::open(&bytes, limited).unwrap_err(), Reader2Error::LimitExceeded);

    // Writers that overflow the 16-bit count without ZIP64 records.
    let classic = build_stored(&entries, Tail::Classic);
    let zip = open(&classic).unwrap();
    assert_eq!(zip.len(), 70_000);
}

#[test]
fn exactly_65535_entries_without_zip64() {
    let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..65_535u32).map(|i| (format!("{i}").into_bytes(), Vec::new())).collect();
    let bytes = build_stored(&entries, Tail::Classic);
    assert_eq!(open(&bytes).unwrap().len(), 65_535);
}

#[test]
fn limits_are_enforced() {
    let bytes = fixture("stream_desc.zip");
    let small = Reader2Limits { max_entry_size: 1000, ..Reader2Limits::default() };
    assert_eq!(ZipArchive2::open(&bytes, small).unwrap_err(), Reader2Error::LimitExceeded);
    let total = Reader2Limits { max_total_size: 5000, ..Reader2Limits::default() };
    assert_eq!(ZipArchive2::open(&bytes, total).unwrap_err(), Reader2Error::LimitExceeded);
    let zip = open(&bytes).unwrap();
    assert_eq!(zip.read(4, 4999).unwrap_err(), Reader2Error::LimitExceeded);
    let blocks = Reader2Limits { max_deflate_blocks: 0, ..Reader2Limits::default() };
    let zip = ZipArchive2::open(&bytes, blocks).unwrap();
    assert_eq!(zip.read(0, 1 << 20).unwrap_err(), Reader2Error::LimitExceeded);
    assert_eq!(zip.read(99, 1).unwrap_err(), Reader2Error::Invalid);
}

#[test]
fn crc_mismatch_detected() {
    let mut bytes = fixture("prefixed.zip");
    let zip = open(&bytes).unwrap();
    let stored = zip.entries()[1].data_start;
    drop(zip);
    bytes[stored + 5] ^= 0x40;
    let zip = open(&bytes).unwrap();
    assert_eq!(zip.read(1, 1000).unwrap_err(), Reader2Error::CrcMismatch);
}

#[test]
fn descriptor_mismatch_rejected() {
    let mut bytes = fixture("stream_desc.zip");
    let zip = open(&bytes).unwrap();
    let d = zip.entries()[0].descriptor.unwrap();
    let at = d.end - 12; // crc field of a signed 32-bit descriptor
    drop(zip);
    bytes[at] ^= 1;
    assert_eq!(open(&bytes).unwrap_err(), Reader2Error::Invalid);
}

#[test]
fn overlapping_local_records_rejected() {
    // Two central records pointing at the same local header.
    let entries = vec![(b"same".to_vec(), b"x".to_vec()), (b"same".to_vec(), b"x".to_vec())];
    let mut bytes = build_stored(&entries, Tail::Classic);
    let cd2 = {
        let cd = bytes.windows(4).position(|w| w == [0x50, 0x4b, 0x01, 0x02]).unwrap();
        cd + 46 + 4
    };
    bytes[cd2 + 42..cd2 + 46].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(open(&bytes).unwrap_err(), Reader2Error::Invalid);
}

#[test]
fn hostile_eocd_counts_rejected_before_allocation() {
    let entries = vec![(b"a".to_vec(), b"x".to_vec())];
    let mut bytes = build_stored(&entries, Tail::Zip64);
    let n = bytes.len();
    // zip64 record entries fields: record starts at n - 22 - 20 - 56.
    let rec = n - 22 - 20 - 56;
    bytes[rec + 24..rec + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[rec + 32..rec + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(open(&bytes).is_err());
    let mut bytes = build_stored(&entries, Tail::Zip64);
    bytes[rec + 40..rec + 48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(open(&bytes).is_err());
}

#[test]
fn deflate64_listed_but_unsupported() {
    let mut bytes = build_stored(&[(b"d64".to_vec(), b"abc".to_vec())], Tail::Classic);
    // Patch method 0 -> 9 in local and central headers.
    bytes[8] = 9;
    let cd = bytes.windows(4).position(|w| w == [0x50, 0x4b, 0x01, 0x02]).unwrap();
    bytes[cd + 10] = 9;
    let zip = open(&bytes).unwrap();
    assert_eq!(zip.entries()[0].compression, Compression::Deflate64);
    assert_eq!(zip.read(0, 100).unwrap_err(), Reader2Error::Unsupported);
}

#[test]
fn empty_archive() {
    let bytes = build_stored(&[], Tail::Classic);
    let zip = open(&bytes).unwrap();
    assert!(zip.is_empty());
    let bytes = build_stored(&[], Tail::Zip64);
    assert!(open(&bytes).unwrap().is_empty());
}

fn exercise(bytes: &[u8]) {
    let limits = Reader2Limits { max_entries: 1000, max_entry_size: 1 << 20, max_total_size: 1 << 22, max_deflate_blocks: 1000 };
    if let Ok(zip) = ZipArchive2::open(bytes, limits) {
        for i in 0..zip.len() {
            let _ = zip.read(i, 1 << 16);
            let _ = zip.raw_data(i);
            let _ = zip.entries()[i].name();
        }
    }
}

#[test]
fn truncation_never_panics() {
    for file in FIXTURES {
        let bytes = fixture(file);
        for len in 0..bytes.len() {
            exercise(&bytes[..len]);
            exercise(&bytes[bytes.len() - len..]);
        }
    }
}

#[test]
fn single_byte_mutations_never_panic() {
    for file in FIXTURES {
        let bytes = fixture(file);
        let mut m = bytes.clone();
        for i in 0..bytes.len() {
            for x in [0x01u8, 0x80, 0xff] {
                m[i] = bytes[i] ^ x;
                exercise(&m);
            }
            m[i] = bytes[i];
        }
    }
}

#[test]
fn random_mutations_never_panic() {
    let mut rng = Lcg(0x5eed);
    for file in FIXTURES {
        let bytes = fixture(file);
        for _ in 0..400 {
            let mut m = bytes.clone();
            for _ in 0..(1 + rng.next() % 8) {
                let i = (rng.next() as usize) % m.len();
                m[i] = match rng.next() % 4 {
                    0 => 0,
                    1 => 0xff,
                    _ => rng.next() as u8,
                };
            }
            exercise(&m);
        }
    }
}
