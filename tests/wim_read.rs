// SPDX-License-Identifier: MIT OR Apache-2.0
//! WIM reader and XPRESS Huffman tests. Fixtures: tests/gen/wim.py (own
//! spec-based writer, cross-checked by 7-Zip and wimlib in
//! tests/gen/wim_oracle.sh) and third-party WIMs written by wimlib and 7-Zip.
use std::collections::HashMap;

use sediment_engine::hash_sha1::sha1;
use sediment_engine::hash_sha256::sha256;
use sediment_engine::wim_read::{
    FILE_ATTRIBUTE_REPARSE_POINT, IO_REPARSE_TAG_SYMLINK, WimArchive, WimCompression, WimError, WimLimits,
    parse_header, read_resource, resource_flag, symlink_target,
};
use sediment_engine::xpress_huffman::{XpressError, decompress};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wim");
const CAP: u64 = 1 << 24;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Want {
    kind: String,
    size: u64,
    sha: String,
}

fn manifest(name: &str) -> HashMap<(u32, String), Want> {
    let text = String::from_utf8(fixture(&format!("{name}.list"))).unwrap();
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.splitn(5, '\t').collect();
            let w = Want { kind: f[1].to_string(), size: f[2].parse().unwrap(), sha: f[3].to_string() };
            ((f[0].parse().unwrap(), f[4].to_string()), w)
        })
        .collect()
}

fn open(name: &str) -> Result<(), WimError> {
    let data = fixture(name);
    WimArchive::open(&data, WimLimits::default()).map(|_| ())
}

fn check_against_manifest(name: &str) -> usize {
    let data = fixture(name);
    let w = WimArchive::open(&data, WimLimits::default()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let want = manifest(name);
    assert_eq!(w.entries().len(), want.len(), "{name}: entry count");
    for (i, e) in w.entries().iter().enumerate() {
        let m = want.get(&(e.image, e.path.clone())).unwrap_or_else(|| panic!("{name}: unexpected {}", e.path));
        match m.kind.as_str() {
            "dir" => assert!(e.is_dir(), "{name}: {}", e.path),
            "file" => {
                assert!(!e.is_dir() && e.reparse_tag.is_none(), "{name}: {}", e.path);
                assert_eq!(e.size, m.size, "{name}: {}", e.path);
                let d = w.read_entry(i, CAP).unwrap_or_else(|err| panic!("{name}: {}: {err:?}", e.path));
                assert_eq!(hex(&sha256(&d)), m.sha, "{name}: {}", e.path);
            }
            _ => {
                assert!(e.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0);
                let d = w.read_entry(i, CAP).unwrap();
                assert_eq!(hex(&sha256(&d)), m.sha, "{name}: {}", e.path);
            }
        }
    }
    w.entries().len()
}

#[test]
fn generated_wims_match_manifests() {
    for name in ["none.wim", "xpress.wim", "xpress_4k.wim", "xpress_multi.wim", "reparse.wim"] {
        assert!(check_against_manifest(name) >= 3, "{name}");
    }
}

#[test]
fn third_party_wims_match_manifests() {
    // Written by wimlib-imagex capture (none / XPRESS) and 7-Zip `a -twim`.
    for name in ["wimlib_none.wim", "wimlib_xpress.wim", "7zz_none.wim"] {
        assert_eq!(check_against_manifest(name), 9, "{name}");
    }
    let data = fixture("wimlib_xpress.wim");
    let w = WimArchive::open(&data, WimLimits::default()).unwrap();
    assert_eq!(w.header().compression, WimCompression::Xpress);
    assert_eq!(w.header().chunk_size, 32768);
    assert!(w.xml(1 << 20).unwrap().contains("<WIM>"));
}

#[test]
fn header_fields() {
    let h = parse_header(&fixture("xpress_4k.wim")).unwrap();
    assert_eq!(h.compression, WimCompression::Xpress);
    assert_eq!(h.chunk_size, 4096);
    assert_eq!((h.part_number, h.total_parts, h.image_count), (1, 1, 1));
    assert_eq!(h.version, 0x10D00);
    let h = parse_header(&fixture("none.wim")).unwrap();
    assert_eq!(h.compression, WimCompression::None);
    assert_eq!(parse_header(b"MSWIM\0\0"), Err(WimError::Truncated));
    assert_eq!(parse_header(&fixture("none.wim")[..100]), Err(WimError::Truncated));
    assert_eq!(parse_header(b"PK\x03\x04\0\0\0\0\0\0"), Err(WimError::BadMagic));
    let mut b = fixture("none.wim");
    b[8] = 200;
    assert_eq!(parse_header(&b), Err(WimError::BadMagic));
}

#[test]
fn streams_links_and_images() {
    let data = fixture("xpress_multi.wim");
    let w = WimArchive::open(&data, WimLimits::default()).unwrap();
    assert_eq!(w.image_count(), 2);
    let xml = w.xml(1 << 20).unwrap();
    assert!(xml.contains("<NAME>one</NAME>") && xml.contains("<NAME>two</NAME>"), "{xml}");
    let find = |img: u32, p: &str| w.entries().iter().position(|e| e.image == img && e.path == p).unwrap();
    // Named stream.
    let ads = &w.entries()[find(1, "ads.txt")];
    assert_eq!(ads.named_streams.len(), 1);
    assert_eq!(ads.named_streams[0].name, "meta");
    assert_eq!(w.read_stream(&ads.named_streams[0].hash, CAP).unwrap(), b"alternate stream data\n");
    assert_eq!(w.read_entry(find(1, "ads.txt"), CAP).unwrap(), b"main data\n");
    // Unnamed data held in an unnamed stream entry.
    let u = find(1, "unnamed_ads.txt");
    assert_eq!(w.read_entry(u, CAP).unwrap(), b"unnamed in stream entry\n");
    assert_eq!(w.entries()[u].named_streams[0].name, "x");
    // Hard links share a group id and data.
    let (a, b) = (&w.entries()[find(1, "link_a.txt")], &w.entries()[find(1, "link_b.txt")]);
    assert_eq!((a.hard_link_group, b.hard_link_group), (0x1234, 0x1234));
    assert_eq!(a.hash, b.hash);
    // Deduplicated stream shared across images.
    assert_eq!(w.entries()[find(2, "shared.txt")].hash, w.entries()[find(1, "hello.txt")].hash);
    assert_eq!(w.read_entry(find(2, "d/t.txt"), CAP).unwrap().len(), 5000);
    // Unicode name, empty file, directories.
    assert_eq!(w.read_entry(find(1, "h\u{e9}llo_\u{65e5}\u{672c}.txt"), CAP).unwrap(), b"unicode name\n");
    assert_eq!(w.entries()[find(1, "empty.txt")].hash, [0; 20]);
    assert!(w.entries()[find(1, "emptydir")].is_dir());
    assert!(w.entries()[find(1, "dir/sub")].is_dir());
    assert_eq!(w.entries()[find(1, "dir/sub/nested.txt")].last_write_time, 133_540_000_000_000_002);
}

#[test]
fn reparse_points() {
    let data = fixture("reparse.wim");
    let w = WimArchive::open(&data, WimLimits::default()).unwrap();
    let get = |p: &str| w.entries().iter().position(|e| e.path == p).unwrap();
    let rel = get("rel_link");
    assert_eq!(w.entries()[rel].reparse_tag, Some(IO_REPARSE_TAG_SYMLINK));
    let d = w.read_entry(rel, CAP).unwrap();
    assert_eq!(symlink_target(&d).unwrap(), ("target.txt".to_string(), true));
    let d = w.read_entry(get("abs_link"), CAP).unwrap();
    assert_eq!(symlink_target(&d).unwrap(), ("C:/Windows".to_string(), false));
}

#[test]
fn unsupported_variants() {
    assert_eq!(open("lzx.wim"), Err(WimError::Unsupported));
    assert_eq!(open("lzms.wim"), Err(WimError::Unsupported));
    assert_eq!(open("solid.wim"), Err(WimError::Unsupported));
    assert_eq!(open("wimlib_lzx.wim"), Err(WimError::Unsupported));
    // Spanned set (part 1 of 2).
    let mut b = fixture("none.wim");
    b[42] = 2;
    assert_eq!(WimArchive::open(&b, WimLimits::default()).err(), Some(WimError::Unsupported));
}

#[test]
fn raw_xpress_streams() {
    for n in ["text", "zeros", "random", "one"] {
        let x = fixture(&format!("xpress_{n}.xp"));
        let meta = String::from_utf8(fixture(&format!("xpress_{n}.sha"))).unwrap();
        let mut f = meta.split_whitespace();
        let len: usize = f.next().unwrap().parse().unwrap();
        let sha = f.next().unwrap();
        let d = decompress(&x, len, 1 << 20).unwrap_or_else(|e| panic!("{n}: {e:?}"));
        assert_eq!(hex(&sha256(&d)), sha, "{n}");
        // Shorter output requests stop early (or hit a match crossing the
        // end); longer ones run out of input.
        match decompress(&x, len / 2, 1 << 20) {
            Ok(h) => assert_eq!(h[..], d[..len / 2], "{n}"),
            Err(e) => assert_eq!(e, XpressError::InvalidMatch, "{n}"),
        }
        assert!(decompress(&x, len + 70_000, 1 << 20).is_err(), "{n}");
        for cut in [0, 100, 256, 258, x.len() / 2] {
            if cut < x.len() {
                assert!(decompress(&x[..cut], len, 1 << 20).is_err() || len < 3, "{n} cut {cut}");
            }
        }
    }
    assert_eq!(decompress(&[], 5, 4), Err(XpressError::LimitExceeded));
}

#[test]
fn limits() {
    let data = fixture("xpress.wim");
    let small = WimLimits { max_entries: 5, ..WimLimits::default() };
    assert_eq!(WimArchive::open(&data, small).err(), Some(WimError::LimitExceeded));
    let small = WimLimits { max_metadata_size: 500, ..WimLimits::default() };
    assert_eq!(WimArchive::open(&data, small).err(), Some(WimError::LimitExceeded));
    let small = WimLimits { max_depth: 1, ..WimLimits::default() };
    assert_eq!(WimArchive::open(&data, small).err(), Some(WimError::LimitExceeded));
    let w = WimArchive::open(&data, WimLimits::default()).unwrap();
    let t = w.entries().iter().position(|e| e.path == "text.txt").unwrap();
    assert_eq!(w.read_entry(t, 1000), Err(WimError::LimitExceeded));
    assert_eq!(w.read_entry(10_000, CAP), Err(WimError::NotFound));
    assert_eq!(w.read_stream(&[7; 20], CAP), Err(WimError::NotFound));
    assert_eq!(w.read_stream(&[0; 20], CAP), Ok(Vec::new()));
}

#[test]
fn truncation_and_corruption_never_panic() {
    for name in ["xpress.wim", "none.wim", "wimlib_xpress.wim", "xpress_multi.wim"] {
        let f = fixture(name);
        let step = (f.len() / 400).max(1);
        for n in (0..f.len()).step_by(step) {
            assert!(WimArchive::open(&f[..n], WimLimits::default()).is_err(), "{name} prefix {n}");
        }
        for i in (0..f.len()).step_by(step) {
            for x in [0x01u8, 0x80, 0xff] {
                let mut g = f.clone();
                g[i] ^= x;
                if let Ok(w) = WimArchive::open(&g, WimLimits::default()) {
                    for k in 0..w.entries().len() {
                        let _ = w.read_entry(k, 1 << 20);
                    }
                }
            }
        }
    }
}

/// Locate the (single) metadata lookup entry of an uncompressed WIM.
fn metadata_entry(b: &[u8]) -> (usize, usize, usize) {
    let h = parse_header(b).unwrap();
    let lt = h.lookup_table.offset as usize;
    for k in 0..(h.lookup_table.size as usize / 50) {
        let e = lt + 50 * k;
        if b[e + 7] & resource_flag::METADATA != 0 {
            let off = u64::from_le_bytes(b[e + 8..e + 16].try_into().unwrap()) as usize;
            let size = u64::from_le_bytes(b[e + 16..e + 24].try_into().unwrap()) as usize;
            return (e, off, size);
        }
    }
    panic!("no metadata");
}

/// Apply `f` to the metadata of `none.wim` and fix up its SHA-1.
fn patch_metadata(f: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut b = fixture("none.wim");
    let (e, off, size) = metadata_entry(&b);
    f(&mut b[off..off + size]);
    let h = sha1(&b[off..off + size]);
    b[e + 30..e + 50].copy_from_slice(&h);
    b
}

fn le64(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}

#[test]
fn hostile_metadata() {
    // Unpatched copy opens.
    assert!(WimArchive::open(&patch_metadata(|_| {}), WimLimits::default()).is_ok());
    // Metadata hash mismatch.
    let mut b = fixture("none.wim");
    let (_, off, _) = metadata_entry(&b);
    b[off + 40] ^= 1;
    assert_eq!(WimArchive::open(&b, WimLimits::default()).err(), Some(WimError::HashMismatch));
    // Root's child list points back at the root dentry list: the "dir"
    // directory's subdir offset is replaced by the root list offset.
    let b = patch_metadata(|md| {
        let root = 8;
        let root_list = le64(md, root + 16) as usize;
        let mut p = root_list;
        while le64(md, p) != 0 {
            let len = le64(md, p) as usize;
            let attrs = u32::from_le_bytes(md[p + 8..p + 12].try_into().unwrap());
            let nlen = u16::from_le_bytes([md[p + 100], md[p + 101]]) as usize;
            let name = String::from_utf16_lossy(
                &md[p + 102..p + 102 + nlen].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>(),
            );
            if attrs & 0x10 != 0 && name == "dir" {
                md[p + 16..p + 24].copy_from_slice(&(root_list as u64).to_le_bytes());
            }
            let ads = u16::from_le_bytes([md[p + 96], md[p + 97]]) as usize;
            p += len;
            for _ in 0..ads {
                p += le64(md, p) as usize;
            }
        }
    });
    assert_eq!(WimArchive::open(&b, WimLimits::default()).err(), Some(WimError::Invalid));
    // Path traversal in a name: first child renamed to "..".
    let b = patch_metadata(|md| {
        let p = le64(md, 8 + 16) as usize;
        md[p + 100..p + 102].copy_from_slice(&4u16.to_le_bytes());
        md[p + 102..p + 106].copy_from_slice(&[b'.', 0, b'.', 0]);
    });
    assert_eq!(WimArchive::open(&b, WimLimits::default()).err(), Some(WimError::Invalid));
    // Dentry length running past the metadata.
    let b = patch_metadata(|md| {
        let p = le64(md, 8 + 16) as usize;
        md[p..p + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    });
    assert_eq!(WimArchive::open(&b, WimLimits::default()).err(), Some(WimError::Invalid));
    // Security block length larger than the resource.
    let b = patch_metadata(|md| md[0..4].copy_from_slice(&u32::MAX.to_le_bytes()));
    assert_eq!(WimArchive::open(&b, WimLimits::default()).err(), Some(WimError::Invalid));
}

#[test]
fn hostile_resources() {
    let data = fixture("xpress.wim");
    let h = parse_header(&data).unwrap();
    let w = WimArchive::open(&data, WimLimits::default()).unwrap();
    // A compressed multi-chunk resource (text.txt: 34000 bytes, 2 chunks).
    let e = w.lookup_table().iter().find(|e| e.resource.original_size == 34_000 && e.resource.is_compressed()).unwrap();
    let r = e.resource;
    assert_eq!(read_resource(&data, &h, &r, CAP).unwrap().len(), 34_000);
    // Chunk table offset beyond the data.
    let mut bad = data.clone();
    let t = r.offset as usize;
    bad[t..t + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(read_resource(&bad, &h, &r, CAP), Err(WimError::Invalid));
    // Corrupt chunk data: decoding fails or the SHA-1 check catches it.
    let mut bad = data.clone();
    bad[t + 4 + 300] ^= 0x55;
    let wb = WimArchive::open(&bad, WimLimits::default()).unwrap();
    let k = wb.entries().iter().position(|e| e.path == "text.txt").unwrap();
    assert!(matches!(wb.read_entry(k, CAP), Err(WimError::HashMismatch | WimError::Invalid)));
    // Resource past the end of the file; claimed sizes over the cap.
    let mut r2 = r;
    r2.offset = data.len() as u64 - 10;
    assert_eq!(read_resource(&data, &h, &r2, CAP), Err(WimError::Truncated));
    let mut r3 = r;
    r3.original_size = u64::MAX;
    assert_eq!(read_resource(&data, &h, &r3, CAP), Err(WimError::LimitExceeded));
    let mut r4 = r;
    r4.flags |= resource_flag::SOLID;
    assert_eq!(read_resource(&data, &h, &r4, CAP), Err(WimError::Unsupported));
}
