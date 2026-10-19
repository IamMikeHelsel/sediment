// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disc image readers: UDF, ISO-9660 + Rock Ridge, detection and partition
//! entries. Fixtures come from tests/gen/disc.py (hand-built from the
//! specs) and tests/gen/disc_oracle.sh (hdiutil / xorriso images).

use sediment_engine::disc_image::{
    DiscEntryKind, DiscError, DiscKind, DiscLimits, DiscSource, PartitionSpan, detect_disc, list_disc,
    partition_entries, planned_entries, read_entry,
};
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::hash_sha256::sha256;
use sediment_engine::iso_rockridge::{self, IsoDirRef, RrError, RrKind, RrLimits};
use sediment_engine::udf_read::{self, UdfError, UdfLimits, crc_ccitt};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/disc/");

fn load(name: &str) -> Vec<u8> {
    let gz = std::fs::read(format!("{DIR}{name}.gz")).unwrap();
    decode_gzip(&gz, 64 << 20, 1 << 20).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Row {
    kind: String,
    path: String,
    size: u64,
    mode: Option<u32>,
    mtime: Option<i64>,
    tail: String,
}

fn manifest(name: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(format!("{DIR}{name}.manifest")).unwrap();
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 6, "{name}: {l}");
            Row {
                kind: f[0].into(),
                path: f[1].into(),
                size: f[2].parse().unwrap(),
                mode: (f[3] != "-").then(|| u32::from_str_radix(f[3], 8).unwrap()),
                mtime: (f[4] != "-").then(|| f[4].parse().unwrap()),
                tail: f[5].into(),
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Check {
    ordered: bool,
    mode: bool,
    mtime: bool,
}

const STRICT: Check = Check { ordered: true, mode: true, mtime: true };

fn kind_char(k: &DiscEntryKind) -> &'static str {
    match k {
        DiscEntryKind::File => "f",
        DiscEntryKind::Dir => "d",
        DiscEntryKind::Symlink { .. } => "l",
        DiscEntryKind::Other => "o",
    }
}

/// List through the front end and compare every entry (kind, size, mode,
/// mtime, content hash / link target) with the manifest `manifest_name`.
fn check_listing(name: &str, manifest_name: &str, kind: DiscKind, c: Check) {
    let img = load(name);
    assert_eq!(detect_disc(&img), Some(kind), "{name}");
    let lim = DiscLimits::default();
    let listing = list_disc(&img, &lim).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let rows = manifest(manifest_name);
    let mut idx: Vec<usize> = (0..listing.entries.len()).collect();
    if !c.ordered {
        idx.retain(|&i| rows.iter().any(|r| r.path == listing.entries[i].path));
        idx.sort_by(|&a, &b| listing.entries[a].path.cmp(&listing.entries[b].path));
    }
    let mut rows_sorted: Vec<&Row> = rows.iter().collect();
    if !c.ordered {
        rows_sorted.sort_by(|a, b| a.path.cmp(&b.path));
    }
    let got: Vec<&str> = idx.iter().map(|&i| listing.entries[i].path.as_str()).collect();
    let want: Vec<&str> = rows_sorted.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(got, want, "{manifest_name}: paths");
    for (&i, r) in idx.iter().zip(&rows_sorted) {
        let e = &listing.entries[i];
        assert_eq!(kind_char(&e.kind), r.kind, "{manifest_name}: {}", r.path);
        assert_eq!(e.size, r.size, "{manifest_name}: {} size", r.path);
        if c.mode && r.mode.is_some() {
            assert_eq!(e.mode, r.mode, "{manifest_name}: {} mode", r.path);
        }
        if c.mtime && r.mtime.is_some() {
            assert_eq!(e.mtime, r.mtime, "{manifest_name}: {} mtime", r.path);
        }
        match &e.kind {
            DiscEntryKind::File => {
                let data = read_entry(&img, &listing, i, &lim).unwrap();
                assert_eq!(data.len() as u64, r.size);
                assert_eq!(hex(&sha256(&data)), r.tail, "{manifest_name}: {} content", r.path);
            }
            DiscEntryKind::Symlink { target } => assert_eq!(target, &r.tail, "{manifest_name}: {}", r.path),
            _ => assert!(read_entry(&img, &listing, i, &lim).unwrap().is_empty()),
        }
    }
}

// ------------------------------------------------------------ fixtures

#[test]
fn rock_ridge_hand_built() {
    check_listing("rr_hand.iso", "rr_hand.iso", DiscKind::Iso, STRICT);
}

#[test]
fn rock_ridge_extended_attribute_record() {
    check_listing("rr_xa.iso", "rr_xa.iso", DiscKind::Iso, STRICT);
}

#[test]
fn plain_iso_primary_names() {
    check_listing("plain.iso", "plain.iso", DiscKind::Iso, STRICT);
}

#[test]
fn udf_102_short_ads() {
    check_listing("udf102.img", "udf102.img", DiscKind::Udf, STRICT);
    check_listing("udf102_nolink.img", "udf102_nolink.img", DiscKind::Udf, STRICT);
}

#[test]
fn udf_201_efe_long_ads_512_byte_blocks() {
    check_listing("udf201_512.img", "udf201_512.img", DiscKind::Udf, STRICT);
}

/// hdiutil (macOS) UDF 1.02 image vs. the source tree it was made from.
#[test]
fn oracle_hdiutil_udf() {
    check_listing("hdiutil_udf.img", "hdiutil_udf.img", DiscKind::Udf, Check { ordered: false, mode: true, mtime: true });
}

/// xorriso Rock Ridge image vs. the source tree (modes, times, links, FIFO).
#[test]
fn oracle_xorriso_rock_ridge() {
    check_listing("xorriso_rr.iso", "xorriso_rr.iso", DiscKind::Iso, Check { ordered: false, mode: true, mtime: true });
}

/// What 7-Zip 26.04 extracts from the hand-built images (it skips files with
/// sparse extents or allocation extent chains; modes come from its umask).
#[test]
fn oracle_7zz_extracts_hand_built() {
    let loose = Check { ordered: false, mode: false, mtime: false };
    check_listing("udf102_nolink.img", "udf102_nolink.img.7zz", DiscKind::Udf, loose);
    check_listing("plain.iso", "plain.iso.7zz", DiscKind::Iso, loose);
    let rows = manifest("udf102_nolink.img.7zz");
    assert_eq!(rows.len() + 2, manifest("udf102_nolink.img").len());
    for r in rows.iter().filter(|r| r.kind == "f") {
        let ours = manifest("udf102_nolink.img").into_iter().find(|m| m.path == r.path).unwrap();
        assert_eq!(ours.mtime, r.mtime, "{}", r.path);
    }
}

#[test]
fn udf_volume_fields() {
    let img = load("udf102.img");
    let v = udf_read::open_volume(&img).unwrap();
    assert_eq!(v.block_size, 2048);
    assert_eq!(v.revision, 0x0102);
    assert_eq!(v.volume_id, "SEDUDFVOL");
    assert_eq!(v.logical_volume_id, "SEDLV");
    assert_eq!(v.file_set_id, "SEDFS");
    assert_eq!(v.partitions.len(), 1);
    let v = udf_read::open_volume(&load("udf201_512.img")).unwrap();
    assert_eq!((v.block_size, v.revision), (512, 0x0201));
}

#[test]
fn udf_signature_detection() {
    assert!(udf_read::has_udf_signature(&load("udf102.img")));
    assert!(udf_read::has_udf_signature(&load("udf201_512.img")));
    assert!(!udf_read::has_udf_signature(&load("rr_hand.iso")));
    assert!(!udf_read::has_udf_signature(&[]));
}

#[test]
fn udf_metadata_partition_is_unsupported() {
    let img = load("udf_metadata_map.img");
    assert_eq!(detect_disc(&img), Some(DiscKind::Udf));
    assert_eq!(udf_read::open_volume(&img), Err(UdfError::Unsupported));
    assert_eq!(list_disc(&img, &DiscLimits::default()).unwrap_err(), DiscError::Unsupported);
}

#[test]
fn udf_anchor_fallback_to_last_sector() {
    let mut img = load("udf102.img");
    let at = 256 * 2048;
    img[at..at + 2048].fill(0);
    let v = udf_read::open_volume(&img).unwrap();
    assert_eq!(udf_read::list_entries(&img, &v, &UdfLimits::default()).unwrap().len(), manifest("udf102.img").len());
}

#[test]
fn udf_reserve_vds_used_when_main_is_damaged() {
    let mut img = load("udf102.img");
    // Main VDS starts at sector 32: corrupt its LVD (sector 34) CRC area.
    img[34 * 2048 + 100] ^= 0xFF;
    let v = udf_read::open_volume(&img).unwrap();
    assert_eq!(v.logical_volume_id, "SEDLV");
}

#[test]
fn udf_limits() {
    let img = load("udf102.img");
    let v = udf_read::open_volume(&img).unwrap();
    let base = UdfLimits::default();
    let n = manifest("udf102.img").len();
    assert_eq!(udf_read::list_entries(&img, &v, &UdfLimits { max_entries: n, ..base }).unwrap().len(), n);
    assert_eq!(
        udf_read::list_entries(&img, &v, &UdfLimits { max_entries: n - 1, ..base }),
        Err(UdfError::LimitExceeded)
    );
    assert_eq!(udf_read::list_entries(&img, &v, &UdfLimits { max_depth: 2, ..base }), Err(UdfError::LimitExceeded));
    assert!(udf_read::list_entries(&img, &v, &UdfLimits { max_depth: 3, ..base }).is_ok());
    assert_eq!(udf_read::list_entries(&img, &v, &UdfLimits { max_dir_bytes: 64, ..base }), Err(UdfError::LimitExceeded));
    let entries = udf_read::list_entries(&img, &v, &base).unwrap();
    let frag = entries.iter().find(|e| e.path == "frag.bin").unwrap();
    assert_eq!(udf_read::read_file(&img, &v, frag.icb, &UdfLimits { max_extents: 3, ..base }), Err(UdfError::LimitExceeded));
    assert_eq!(udf_read::read_file(&img, &v, frag.icb, &UdfLimits { max_file_size: 100, ..base }), Err(UdfError::LimitExceeded));
    assert!(udf_read::read_file(&img, &v, frag.icb, &UdfLimits { max_extents: 7, ..base }).is_ok());
}

#[test]
fn udf_crc_ccitt_check_value() {
    // CRC-16/XMODEM check value (poly 0x1021, init 0).
    assert_eq!(crc_ccitt(b"123456789"), 0x31C3);
    assert_eq!(crc_ccitt(b""), 0);
}

#[test]
fn udf_directory_loop_detected() {
    let img = load("udf102.img");
    let v = udf_read::open_volume(&img).unwrap();
    let entries = udf_read::list_entries(&img, &v, &UdfLimits::default()).unwrap();
    let sub = entries.iter().find(|e| e.path == "sub").unwrap();
    let big = entries.iter().find(|e| e.path == "sub/big").unwrap();
    // Point sub/big's FID at sub's ICB: rewrite the ICB block number inside
    // sub's directory data and fix the FID tag checksum / CRC.
    let mut img2 = img.clone();
    let part_start = v.partitions[0].start as usize;
    let needle = big.icb.block.to_le_bytes();
    let mut patched = false;
    // Scan blocks for a FID (tag 257) whose ICB block == big.icb.block.
    let mut off = part_start * 2048;
    while off + 64 < img2.len() && !patched {
        let mut pos = off;
        while pos + 40 <= off + 2048 {
            if img2[pos..pos + 2] == [1, 1] && img2[pos + 24..pos + 28] == needle {
                img2[pos + 24..pos + 28].copy_from_slice(&sub.icb.block.to_le_bytes());
                let crc_len = u16::from_le_bytes([img2[pos + 10], img2[pos + 11]]) as usize;
                let crc = crc_ccitt(&img2[pos + 16..pos + 16 + crc_len]);
                img2[pos + 8..pos + 10].copy_from_slice(&crc.to_le_bytes());
                let sum = (0..16).filter(|&i| i != 4).fold(0u8, |a, i| a.wrapping_add(img2[pos + i]));
                img2[pos + 4] = sum;
                patched = true;
                break;
            }
            pos += 4;
        }
        off += 2048;
    }
    assert!(patched);
    assert_eq!(udf_read::list_entries(&img2, &v, &UdfLimits::default()), Err(UdfError::LoopDetected));
}

#[test]
fn rock_ridge_module_api() {
    let img = load("rr_hand.iso");
    let root = iso_rockridge::primary_root(&img).unwrap();
    assert!(iso_rockridge::has_rock_ridge(&img, root));
    assert_eq!(iso_rockridge::detect_susp(&img, root), Ok(Some(0)));
    let entries = iso_rockridge::list_entries(&img, root, &RrLimits::default()).unwrap();
    let multi = entries.iter().find(|e| e.path == "multi.bin").unwrap();
    assert_eq!(multi.extents.len(), 2);
    assert_eq!(multi.size, 5000);
    assert!(entries.iter().all(|e| !e.path.contains("MOVED") && e.path != "rr_moved/moved_dir"));
    let link = entries.iter().find(|e| e.path == "link_rel").unwrap();
    assert_eq!(link.kind, RrKind::Symlink { target: "./../many".into() });
    assert!(link.extents.is_empty());
    let plain = load("plain.iso");
    let proot = iso_rockridge::primary_root(&plain).unwrap();
    assert!(!iso_rockridge::has_rock_ridge(&plain, proot));
    assert_eq!(iso_rockridge::primary_root(&load("udf102.img")), Err(RrError::NoPrimaryDescriptor));
}

#[test]
fn rock_ridge_limits() {
    let img = load("rr_hand.iso");
    let root = iso_rockridge::primary_root(&img).unwrap();
    let base = RrLimits::default();
    let n = manifest("rr_hand.iso").len();
    assert_eq!(iso_rockridge::list_entries(&img, root, &RrLimits { max_entries: n, ..base }).unwrap().len(), n);
    assert_eq!(iso_rockridge::list_entries(&img, root, &RrLimits { max_entries: n - 1, ..base }), Err(RrError::LimitExceeded));
    assert_eq!(iso_rockridge::list_entries(&img, root, &RrLimits { max_depth: 2, ..base }), Err(RrError::LimitExceeded));
    assert!(iso_rockridge::list_entries(&img, root, &RrLimits { max_depth: 3, ..base }).is_ok());
    assert_eq!(iso_rockridge::list_entries(&img, root, &RrLimits { max_ce_hops: 1, ..base }), Err(RrError::LimitExceeded));
    assert_eq!(iso_rockridge::list_entries(&img, root, &RrLimits { max_extents: 1, ..base }), Err(RrError::LimitExceeded));
    let entries = iso_rockridge::list_entries(&img, root, &base).unwrap();
    let multi = entries.iter().find(|e| e.path == "multi.bin").unwrap();
    assert_eq!(iso_rockridge::read_file(&img, multi, 4999), Err(RrError::LimitExceeded));
}

#[test]
fn rock_ridge_loop_detected() {
    let mut img = load("rr_hand.iso");
    let root = iso_rockridge::primary_root(&img).unwrap();
    // Make the CL placeholder in deep/ point back at the root directory.
    let entries = iso_rockridge::list_entries(&img, root, &RrLimits::default()).unwrap();
    assert!(entries.iter().any(|e| e.path == "deep/moved_dir"));
    let hay = img.clone();
    let cl = hay.windows(4).position(|w| w == b"CL\x0c\x01").unwrap();
    img[cl + 4..cl + 8].copy_from_slice(&root.extent.to_le_bytes());
    img[cl + 8..cl + 12].copy_from_slice(&root.extent.to_be_bytes());
    assert_eq!(iso_rockridge::list_entries(&img, root, &RrLimits::default()), Err(RrError::LoopDetected));
}

// ----------------------------------------------------------- detection

#[test]
fn detect_partition_tables() {
    assert_eq!(detect_disc(&load("mbr.img")), Some(DiscKind::Mbr));
    assert_eq!(detect_disc(&load("gpt.img")), Some(DiscKind::Gpt));
    assert_eq!(list_disc(&load("mbr.img"), &DiscLimits::default()).unwrap_err(), DiscError::Unsupported);
    // A boot signature with a bad status byte is not an MBR.
    let mut m = load("mbr.img");
    m[446] = 0x12;
    assert_eq!(detect_disc(&m), None);
    // Boot signature but no used entry.
    let mut z = vec![0u8; 512];
    z[510] = 0x55;
    z[511] = 0xAA;
    assert_eq!(detect_disc(&z), None);
    assert_eq!(detect_disc(&[]), None);
    assert_eq!(list_disc(b"not a disc", &DiscLimits::default()).unwrap_err(), DiscError::NotADisc);
}

#[test]
fn detect_bridge_disc() {
    // Put an ISO PVD + terminator in front of the UDF VRS: ISO/UDF bridge.
    let udf = load("udf102.img");
    let mut img = udf.clone();
    let iso = load("plain.iso");
    img[16 * 2048..17 * 2048].copy_from_slice(&iso[16 * 2048..17 * 2048]);
    // The VRS of the UDF image starts at sector 16; shift it by 2 sectors.
    img[18 * 2048..21 * 2048].copy_from_slice(&udf[16 * 2048..19 * 2048]);
    img[17 * 2048..18 * 2048].copy_from_slice(&iso[17 * 2048..18 * 2048]);
    assert_eq!(detect_disc(&img), Some(DiscKind::IsoUdf));
    let listing = list_disc(&img, &DiscLimits::default()).unwrap();
    assert!(listing.udf.is_some());
    assert_eq!(listing.entries.len(), manifest("udf102.img").len());
}

// ---------------------------------------------------------- partitions

#[test]
fn partition_entries_from_spans() {
    let img = load("gpt.img");
    let spans = [
        PartitionSpan { number: 1, first_lba: 6, sector_count: 4, label: Some("boot".into()) },
        PartitionSpan { number: 2, first_lba: 10, sector_count: 6, label: Some("../x/y".into()) },
        PartitionSpan { number: 3, first_lba: 16, sector_count: 1, label: None },
    ];
    let lim = DiscLimits::default();
    let entries = partition_entries(&spans, 512, img.len() as u64, &lim).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(names, ["1.boot.img", "2..._x_y.img", "3.img"]);
    assert_eq!(entries[0].source, DiscSource::Range { offset: 3072, len: 2048 });
    assert_eq!(entries[1].size, 3072);
    // Beyond the image, overlapping, bad sector size, too many.
    let far = [PartitionSpan { number: 1, first_lba: 60, sector_count: 10, label: None }];
    assert_eq!(partition_entries(&far, 512, img.len() as u64, &lim), Err(DiscError::Truncated));
    let huge = [PartitionSpan { number: 1, first_lba: u64::MAX / 2, sector_count: 4, label: None }];
    assert_eq!(partition_entries(&huge, 512, u64::MAX, &lim), Err(DiscError::Truncated));
    let overlap = [spans[0].clone(), PartitionSpan { number: 2, first_lba: 9, sector_count: 2, label: None }];
    assert_eq!(partition_entries(&overlap, 512, img.len() as u64, &lim), Err(DiscError::Invalid));
    assert_eq!(partition_entries(&spans, 3, img.len() as u64, &lim), Err(DiscError::Invalid));
    assert_eq!(
        partition_entries(&spans, 512, img.len() as u64, &DiscLimits { max_entries: 2, ..lim }),
        Err(DiscError::LimitExceeded)
    );
    let label_dots = [PartitionSpan { number: 4, first_lba: 1, sector_count: 1, label: Some("..".into()) }];
    assert_eq!(partition_entries(&label_dots, 512, img.len() as u64, &lim).unwrap()[0].path, "4.__.img");
}

#[test]
fn planned_entries_skip_specials() {
    let img = load("rr_hand.iso");
    let listing = list_disc(&img, &DiscLimits::default()).unwrap();
    let planned = planned_entries(&listing);
    assert_eq!(planned.len(), listing.entries.len() - 1); // the FIFO
    let (i, link) = planned.iter().find(|(_, p)| p.path == b"link_abs").unwrap();
    assert_eq!(link.kind, EntryKind::Symlink { target: b"/etc/hosts".to_vec() });
    assert_eq!(listing.entries[*i].path, "link_abs");
    assert!(planned.iter().all(|(_, p)| p.path != b"fifo"));
    assert_eq!(read_entry(&img, &listing, usize::MAX, &DiscLimits::default()), Err(DiscError::OutOfRange));
}

// ------------------------------------------------------------- hostile

fn exercise(img: &[u8]) {
    let lim = DiscLimits { max_entries: 10_000, max_depth: 32, max_entry_size: 1 << 20 };
    let _ = detect_disc(img);
    if let Ok(listing) = list_disc(img, &lim) {
        for i in 0..listing.entries.len() {
            let _ = read_entry(img, &listing, i, &lim);
        }
    }
    if let Ok(v) = udf_read::open_volume(img)
        && let Ok(es) = udf_read::list_entries(img, &v, &UdfLimits::default())
    {
        for e in es {
            let _ = udf_read::read_file(img, &v, e.icb, &UdfLimits { max_file_size: 1 << 20, ..UdfLimits::default() });
        }
    }
    if let Ok(root) = iso_rockridge::primary_root(img) {
        let _ = iso_rockridge::list_entries(img, root, &RrLimits::default());
    }
    let _ = iso_rockridge::list_entries(img, IsoDirRef { extent: 18, size: u32::MAX }, &RrLimits::default());
}

#[test]
fn truncation_never_panics() {
    for name in ["rr_hand.iso", "plain.iso", "udf102.img", "udf201_512.img"] {
        let img = load(name);
        let mut cuts: Vec<usize> = (0..img.len()).step_by(509).collect();
        cuts.extend([0, 1, 2047, 2048, 32768, 34816, img.len() - 1]);
        for cut in cuts {
            exercise(&img[..cut.min(img.len())]);
        }
    }
}

#[test]
fn truncated_images_error() {
    let img = load("udf102.img");
    let v = udf_read::open_volume(&img).unwrap();
    // Cut inside the partition: listing must fail cleanly.
    let cut = (v.partitions[0].start as usize + 3) * 2048;
    assert!(udf_read::list_entries(&img[..cut], &v, &UdfLimits::default()).is_err());
    let iso = load("rr_hand.iso");
    let root = iso_rockridge::primary_root(&iso).unwrap();
    assert_eq!(
        iso_rockridge::list_entries(&iso[..(root.extent as usize * 2048 + 100)], root, &RrLimits::default()),
        Err(RrError::Truncated)
    );
}

/// Deterministic xorshift byte flips over the metadata regions.
#[test]
fn corruption_never_panics() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for name in ["rr_hand.iso", "plain.iso", "udf102.img", "udf201_512.img"] {
        let base = load(name);
        // Metadata lives in the first ~40 sectors of the ISO images and in
        // the VDS / partition head of the UDF images.
        let hot = base.len().min(300 * 2048);
        for _ in 0..400 {
            let mut img = base.clone();
            for _ in 0..1 + (next() % 8) as usize {
                let at = (next() as usize) % hot;
                img[at] = next() as u8;
            }
            exercise(&img);
        }
    }
}

#[test]
fn udf_bad_checksum_and_crc_rejected() {
    let img = load("udf102.img");
    let v = udf_read::open_volume(&img).unwrap();
    let fsd_sector = v.partitions[0].start as usize * 2048;
    let mut a = img.clone();
    a[fsd_sector + 4] ^= 1; // tag checksum byte
    assert_eq!(udf_read::open_volume(&a), Err(UdfError::NoFileSet));
    // Root FE body byte: CRC mismatch surfaces when listing.
    let root_fe = (v.partitions[0].start as usize + v.root.block as usize) * 2048;
    let mut b = img.clone();
    b[root_fe + 40] ^= 0x55;
    assert_eq!(udf_read::list_entries(&b, &v, &UdfLimits::default()), Err(UdfError::BadCrc));
}
