use sediment_engine::archive_reader::{ReaderError, ReaderLimits};
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::reader_vhd::open_vhd;
use sediment_engine::vhd_footer::vhd_checksum;

const FIXED: &[u8] = include_bytes!("reader_vhd_fixtures/fixed.vhd");
const DYNAMIC: &[u8] = include_bytes!("reader_vhd_fixtures/dynamic.vhd");
const QEMU_FIXED_GZ: &[u8] = include_bytes!("reader_vhd_fixtures/qemu_fixed.vhd.gz");
const QEMU_DYNAMIC_GZ: &[u8] = include_bytes!("reader_vhd_fixtures/qemu_dynamic.vhd.gz");

fn gunzip(b: &[u8]) -> Vec<u8> {
    decode_gzip(b, 1 << 23, 1 << 16).unwrap()
}

/// Same pattern as gen/reader_vhd.sh writes into raw.bin.
fn qemu_raw() -> Vec<u8> {
    let mut d = vec![0u8; 65536];
    for i in 0..4096usize {
        d[i] = ((i * 13 + 7) & 255) as u8;
        d[40960 + i] = ((i * 5 + 3) & 255) as u8;
    }
    d
}

fn block(seed: u32) -> Vec<u8> {
    (0..4096u32).map(|i| ((i * 7 + seed) & 0xff) as u8).collect()
}

/// Patch the trailing footer field at `off` and refresh its checksum.
fn patch_footer(img: &mut [u8], off: usize, val: &[u8]) {
    let at = img.len() - 512;
    img[at + off..at + off + val.len()].copy_from_slice(val);
    img[at + 64..at + 68].fill(0);
    let c = vhd_checksum(&img[at..], 64);
    img[at + 64..at + 68].copy_from_slice(&c.to_be_bytes());
}

#[test]
fn fixed_single_entry() {
    let r = open_vhd(FIXED.to_vec(), ReaderLimits::default()).unwrap();
    let e = r.entries();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].path, b"disk.img".to_vec());
    assert_eq!(e[0].kind, EntryKind::File);
    assert_eq!(e[0].size, 2048);
    assert_eq!(e[0].mode, None);
    assert_eq!(e[0].mtime, Some(946_684_800 + 0x2C5B_3A10));
    let want: Vec<u8> = (0..2048u32).map(|i| ((i * 3 + 1) & 0xff) as u8).collect();
    assert_eq!(r.read(0).unwrap(), want);
}

#[test]
fn dynamic_handmade_zero_fills_holes() {
    let r = open_vhd(DYNAMIC.to_vec(), ReaderLimits::default()).unwrap();
    assert_eq!(r.entries().len(), 1);
    assert_eq!(r.entries()[0].size, 16384);
    let mut want = block(5);
    want.extend(vec![0u8; 4096]);
    want.extend(block(9));
    want.extend(vec![0u8; 4096]);
    assert_eq!(r.read(0).unwrap(), want);
}

#[test]
fn qemu_fixed_matches_raw() {
    let r = open_vhd(gunzip(QEMU_FIXED_GZ), ReaderLimits::default()).unwrap();
    assert_eq!(r.entries()[0].size, 65536);
    assert_eq!(r.read(0).unwrap(), qemu_raw());
}

#[test]
fn qemu_dynamic_matches_raw() {
    let img = gunzip(QEMU_DYNAMIC_GZ);
    let r = open_vhd(img, ReaderLimits::default()).unwrap();
    assert_eq!(r.entries()[0].path, b"disk.img".to_vec());
    assert_eq!(r.entries()[0].size, 65536);
    assert_eq!(r.read(0).unwrap(), qemu_raw());
    assert_eq!(r.read(0).unwrap(), qemu_raw());
}

#[test]
fn read_out_of_range_index() {
    let r = open_vhd(FIXED.to_vec(), ReaderLimits::default()).unwrap();
    assert_eq!(r.read(1).unwrap_err(), ReaderError::OutOfRange);
    assert_eq!(r.crc32(0), None);
}

#[test]
fn differencing_is_unsupported() {
    let mut img = DYNAMIC.to_vec();
    patch_footer(&mut img, 60, &4u32.to_be_bytes());
    assert_eq!(open_vhd(img, ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
}

#[test]
fn bad_version_is_unsupported() {
    let mut img = FIXED.to_vec();
    patch_footer(&mut img, 12, &0x0002_0000u32.to_be_bytes());
    assert_eq!(open_vhd(img, ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
}

#[test]
fn corrupt_footer_is_invalid() {
    let mut img = FIXED.to_vec();
    let n = img.len();
    img[n - 512 + 100] ^= 0xff; // checksum no longer matches
    assert_eq!(open_vhd(img, ReaderLimits::default()).err(), Some(ReaderError::Invalid));
    let mut img = FIXED.to_vec();
    let n = img.len();
    img[n - 512] = b'X'; // cookie
    assert_eq!(open_vhd(img, ReaderLimits::default()).err(), Some(ReaderError::Invalid));
}

#[test]
fn truncated_inputs() {
    assert_eq!(open_vhd(Vec::new(), ReaderLimits::default()).err(), Some(ReaderError::Truncated));
    assert_eq!(open_vhd(FIXED[..300].to_vec(), ReaderLimits::default()).err(), Some(ReaderError::Truncated));
    // fixed disk claiming more data than precedes the footer
    let img = FIXED[1024..].to_vec();
    assert_eq!(open_vhd(img, ReaderLimits::default()).err(), Some(ReaderError::Truncated));
    // dynamic: drop the header copy at the front so data_offset points past the header
    let img = DYNAMIC[2048..].to_vec();
    assert!(open_vhd(img, ReaderLimits::default()).is_err());
}

#[test]
fn limits_enforced() {
    let lim = ReaderLimits { max_entries: 0, ..ReaderLimits::default() };
    assert_eq!(open_vhd(FIXED.to_vec(), lim).err(), Some(ReaderError::LimitExceeded));
    let lim = ReaderLimits { max_total_size: 2047, ..ReaderLimits::default() };
    assert_eq!(open_vhd(FIXED.to_vec(), lim).err(), Some(ReaderError::LimitExceeded));
    let lim = ReaderLimits { max_entry_size: 2047, ..ReaderLimits::default() };
    let r = open_vhd(FIXED.to_vec(), lim).unwrap();
    assert_eq!(r.entries()[0].size, 2048);
    assert_eq!(r.read(0).unwrap_err(), ReaderError::LimitExceeded);
    let lim = ReaderLimits { max_entries: 1, max_total_size: 2048, max_entry_size: 2048 };
    assert_eq!(open_vhd(FIXED.to_vec(), lim).unwrap().read(0).unwrap().len(), 2048);
}

#[test]
fn hostile_bytes_never_panic() {
    let mut seed = 0x1234_5678u32;
    for n in [0usize, 1, 511, 512, 513, 1536, 4096] {
        let mut v = DYNAMIC.to_vec();
        for _ in 0..64 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (seed as usize) % v.len();
            v[i] = (seed >> 16) as u8;
        }
        v.truncate(v.len().saturating_sub(n));
        if let Ok(r) = open_vhd(v, ReaderLimits::default()) {
            let _ = r.read(0);
        }
    }
}
