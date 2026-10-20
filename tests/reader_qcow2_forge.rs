use sediment_engine::archive_reader::{ReaderError, ReaderLimits};
use sediment_engine::extract_plan::EntryKind;
use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::reader_qcow2::open_qcow2;

const V2_GZ: &[u8] = include_bytes!("reader_qcow2_fixtures/v2.qcow2.gz");
const V3_GZ: &[u8] = include_bytes!("reader_qcow2_fixtures/v3.qcow2.gz");
const COMP_GZ: &[u8] = include_bytes!("reader_qcow2_fixtures/comp.qcow2.gz");
const BACK_GZ: &[u8] = include_bytes!("reader_qcow2_fixtures/back.qcow2.gz");
const HAND_V2: &[u8] = include_bytes!("reader_qcow2_fixtures/hand_v2.qcow2");
const HAND_V3: &[u8] = include_bytes!("reader_qcow2_fixtures/hand_v3.qcow2");

fn gunzip(b: &[u8]) -> Vec<u8> {
    decode_gzip(b, 1 << 22, 1 << 16).unwrap()
}

/// Same pattern as gen/reader_qcow2.sh writes into raw.bin.
fn qemu_raw() -> Vec<u8> {
    let mut d = vec![0u8; 65536];
    for i in 0..4096usize {
        d[i] = ((i * 13 + 7) & 255) as u8;
        d[40960 + i] = ((i * 5 + 3) & 255) as u8;
    }
    d
}

fn pattern(seed: usize) -> Vec<u8> {
    (0..512).map(|i| ((i * 13 + seed) & 0xff) as u8).collect()
}

fn hand_expected(v3: bool) -> Vec<u8> {
    let mut d = vec![0u8; 40960];
    d[0..512].copy_from_slice(&pattern(1));
    d[70 * 512..71 * 512].copy_from_slice(&pattern(70));
    if v3 {
        d[512..1024].copy_from_slice(&pattern(2));
    }
    d
}

#[test]
fn qemu_v3_small_clusters() {
    let r = open_qcow2(gunzip(V3_GZ), ReaderLimits::default()).unwrap();
    let e = r.entries();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].path, b"disk.img".to_vec());
    assert_eq!(e[0].kind, EntryKind::File);
    assert_eq!(e[0].size, 65536);
    assert_eq!((e[0].mode, e[0].mtime), (None, None));
    assert_eq!(r.read(0).unwrap(), qemu_raw());
}

#[test]
fn qemu_v2_4k_clusters() {
    let r = open_qcow2(gunzip(V2_GZ), ReaderLimits::default()).unwrap();
    assert_eq!(r.entries()[0].size, 65536);
    assert_eq!(r.read(0).unwrap(), qemu_raw());
}

#[test]
fn handmade_images_with_zero_and_holes() {
    let r = open_qcow2(HAND_V3.to_vec(), ReaderLimits::default()).unwrap();
    assert_eq!(r.entries()[0].size, 40960);
    assert_eq!(r.read(0).unwrap(), hand_expected(true));
    let r = open_qcow2(HAND_V2.to_vec(), ReaderLimits::default()).unwrap();
    assert_eq!(r.read(0).unwrap(), hand_expected(false));
}

#[test]
fn compressed_clusters_unsupported_on_read() {
    let r = open_qcow2(gunzip(COMP_GZ), ReaderLimits::default()).unwrap();
    assert_eq!(r.entries()[0].size, 65536);
    assert_eq!(r.read(0).unwrap_err(), ReaderError::Unsupported);
}

#[test]
fn backing_file_unsupported() {
    assert_eq!(open_qcow2(gunzip(BACK_GZ), ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
}

#[test]
fn header_errors_mapped() {
    let mut img = HAND_V2.to_vec();
    img[35] = 1; // crypt_method = 1 (AES)
    assert_eq!(open_qcow2(img, ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
    let mut img = HAND_V2.to_vec();
    img[7] = 4; // version 4
    assert_eq!(open_qcow2(img, ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
    let mut img = HAND_V2.to_vec();
    img[0] = b'X';
    assert_eq!(open_qcow2(img, ReaderLimits::default()).err(), Some(ReaderError::Invalid));
    let mut img = HAND_V2.to_vec();
    img[23] = 30; // cluster_bits 30
    assert_eq!(open_qcow2(img, ReaderLimits::default()).err(), Some(ReaderError::Invalid));
    let mut img = HAND_V3.to_vec();
    img[79] = 2; // incompatible feature bit 1 (corrupt)
    assert_eq!(open_qcow2(img, ReaderLimits::default()).err(), Some(ReaderError::Unsupported));
}

#[test]
fn truncated_inputs() {
    assert_eq!(open_qcow2(Vec::new(), ReaderLimits::default()).err(), Some(ReaderError::Truncated));
    assert_eq!(open_qcow2(HAND_V2[..50].to_vec(), ReaderLimits::default()).err(), Some(ReaderError::Truncated));
    // L1 table (2 entries at 1536) cut short
    assert_eq!(open_qcow2(HAND_V3[..1540].to_vec(), ReaderLimits::default()).err(), Some(ReaderError::Truncated));
    // L2 tables gone: opening works, reading fails cleanly
    let r = open_qcow2(HAND_V3[..2048].to_vec(), ReaderLimits::default()).unwrap();
    assert_eq!(r.read(0).unwrap_err(), ReaderError::Truncated);
}

#[test]
fn bad_l2_entry_is_invalid() {
    let mut img = HAND_V3.to_vec();
    img[4 * 512 + 7] |= 0x02; // reserved bit 1 in L2 entry for guest cluster 0
    let r = open_qcow2(img, ReaderLimits::default()).unwrap();
    assert_eq!(r.read(0).unwrap_err(), ReaderError::Invalid);
}

#[test]
fn index_and_limits() {
    let r = open_qcow2(HAND_V3.to_vec(), ReaderLimits::default()).unwrap();
    assert_eq!(r.read(1).unwrap_err(), ReaderError::OutOfRange);
    assert_eq!(r.crc32(0), None);
    let lim = ReaderLimits { max_entries: 0, ..ReaderLimits::default() };
    assert_eq!(open_qcow2(HAND_V3.to_vec(), lim).err(), Some(ReaderError::LimitExceeded));
    let lim = ReaderLimits { max_total_size: 40959, ..ReaderLimits::default() };
    assert_eq!(open_qcow2(HAND_V3.to_vec(), lim).err(), Some(ReaderError::LimitExceeded));
    let lim = ReaderLimits { max_entry_size: 40959, ..ReaderLimits::default() };
    let r = open_qcow2(HAND_V3.to_vec(), lim).unwrap();
    assert_eq!(r.read(0).unwrap_err(), ReaderError::LimitExceeded);
    let lim = ReaderLimits { max_entries: 1, max_total_size: 40960, max_entry_size: 40960 };
    assert_eq!(open_qcow2(HAND_V3.to_vec(), lim).unwrap().read(0).unwrap().len(), 40960);
}

#[test]
fn huge_virtual_size_rejected_before_allocating() {
    let mut img = HAND_V3.to_vec();
    img[24..32].copy_from_slice(&(1u64 << 50).to_be_bytes()); // size 1 PiB, l1_size 2 -> BadL1
    assert_eq!(open_qcow2(img, ReaderLimits::default()).err(), Some(ReaderError::Invalid));
}

#[test]
fn hostile_bytes_never_panic() {
    let base = gunzip(V3_GZ);
    let mut seed = 0x9e37_79b9u32;
    for round in 0..40 {
        let mut v = base.clone();
        for _ in 0..8 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (seed as usize) % 2048.min(v.len());
            v[i] = (seed >> 16) as u8;
        }
        v.truncate(v.len() - (round * 97) % v.len());
        if let Ok(r) = open_qcow2(v, ReaderLimits::default()) {
            let _ = r.read(0);
        }
    }
}
