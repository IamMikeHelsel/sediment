use sediment_engine::vmdk_sparse::{VmdkError, VmdkMapping, descriptor, open_vmdk, parse_header};

// Metadata prefix of a `qemu-img convert -O vmdk` monolithicSparse image, trailing zeros stripped (gen/vmdk_sparse.py).
const META: &[u8] = include_bytes!("vmdk_sparse_fixtures/sparse.meta");
// First 512 bytes of a qemu streamOptimized image (compressed grains).
const STREAM: &[u8] = include_bytes!("vmdk_sparse_fixtures/stream.hdr");
const G: usize = 65536;

fn raw() -> Vec<u8> {
    let mut d = vec![0u8; 2 << 20];
    for i in 0..70000 {
        d[i] = ((i * 7 + 3) & 0xff) as u8;
    }
    for i in 1_500_000..1_500_300 {
        d[i] = ((i * 13 + 1) & 0xff) as u8;
    }
    d
}

// overhead (128 sectors) then grains 0, 1, 22 in file order (generator asserts this layout).
fn image() -> Vec<u8> {
    let r = raw();
    let mut v = META.to_vec();
    v.resize(G, 0);
    for g in [0usize, 1, 22] {
        v.extend_from_slice(&r[g * G..(g + 1) * G]);
    }
    v
}

fn gt_entry_pos(img: &[u8], grain: usize) -> usize {
    let gde = u32::from_le_bytes(img[26 * 512..26 * 512 + 4].try_into().unwrap()) as usize;
    gde * 512 + grain * 4
}

#[test]
fn header_fields() {
    let h = parse_header(META).unwrap();
    assert_eq!((h.version, h.flags), (1, 3));
    assert_eq!((h.capacity, h.grain_size), (4096, 128));
    assert_eq!((h.descriptor_offset, h.descriptor_size), (1, 20));
    assert_eq!(h.num_gtes_per_gt, 512);
    assert_eq!((h.rgd_offset, h.gd_offset, h.overhead), (21, 26, 128));
    assert!(!h.unclean_shutdown);
    assert_eq!(h.compress_algorithm, 0);
}

#[test]
fn descriptor_text() {
    let img = image();
    let h = parse_header(&img).unwrap();
    let d = descriptor(&img, &h).unwrap();
    let s = std::str::from_utf8(d).unwrap();
    assert!(s.starts_with("# Disk DescriptorFile\n"));
    assert!(s.contains("createType=\"monolithicSparse\""));
    assert!(s.contains("RW 4096 SPARSE"));
    assert!(!d.contains(&0));
    assert!(d.len() < 20 * 512);
}

#[test]
fn grain_mapping() {
    let img = image();
    let v = open_vmdk(&img, 8).unwrap();
    assert_eq!(v.gd.len(), 1);
    assert_eq!(v.gd[0], 27);
    assert_eq!(v.disk_size(), 2 << 20);
    assert_eq!(v.map_offset(&img, 0).unwrap(), VmdkMapping::Data(65536));
    assert_eq!(v.map_offset(&img, 65536 + 9).unwrap(), VmdkMapping::Data(131072 + 9));
    assert_eq!(v.map_offset(&img, 1_500_000).unwrap(), VmdkMapping::Data(196608 + 1_500_000 - 22 * 65536));
    assert_eq!(v.map_offset(&img, 5 * 65536).unwrap(), VmdkMapping::Unallocated);
    assert_eq!(v.map_offset(&img, 2 << 20), Err(VmdkError::OutOfRange));
}

#[test]
fn read_whole_disk_matches_raw() {
    let img = image();
    let v = open_vmdk(&img, 8).unwrap();
    assert_eq!(v.read_at(&img, 0, 2 << 20).unwrap(), raw());
}

#[test]
fn read_across_grains() {
    let img = image();
    let r = raw();
    let v = open_vmdk(&img, 8).unwrap();
    for &(off, len) in &[(G - 5, 10), (69_990, 20), (1_499_990, 400), (22 * G - 1, G + 2), ((2 << 20) - 1, 1)] {
        assert_eq!(v.read_at(&img, off as u64, len).unwrap(), &r[off..off + len], "{off}+{len}");
    }
    assert_eq!(v.read_at(&img, 2 << 20, 0).unwrap(), Vec::<u8>::new());
    assert_eq!(v.read_at(&img, (2 << 20) - 1, 2), Err(VmdkError::OutOfRange));
    assert_eq!(v.read_at(&img, u64::MAX - 1, 4), Err(VmdkError::OutOfRange));
}

#[test]
fn zeroed_grain_entry() {
    let mut img = image();
    let p = gt_entry_pos(&img, 1);
    img[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
    let plain = open_vmdk(&img, 8).unwrap();
    assert_eq!(plain.map_offset(&img, 65536 + 3).unwrap(), VmdkMapping::Data(512 + 3));
    img[8] |= 4; // zeroed-grain GTEs enabled
    let v = open_vmdk(&img, 8).unwrap();
    assert_eq!(v.map_offset(&img, 65536).unwrap(), VmdkMapping::Zero);
    assert_eq!(v.read_at(&img, 65530, 12).unwrap(), {
        let mut e = raw()[65530..65536].to_vec();
        e.extend([0u8; 6]);
        e
    });
}

#[test]
fn missing_grain_table() {
    let mut img = image();
    img[26 * 512..26 * 512 + 4].fill(0);
    let v = open_vmdk(&img, 8).unwrap();
    assert_eq!(v.map_offset(&img, 0).unwrap(), VmdkMapping::Unallocated);
    assert_eq!(v.read_at(&img, 0, 1000).unwrap(), vec![0u8; 1000]);
}

#[test]
fn stream_optimized_rejected() {
    assert_eq!(parse_header(STREAM), Err(VmdkError::Compressed));
    let mut h = META[..512].to_vec();
    h[77] = 1; // compressAlgorithm deflate
    assert_eq!(parse_header(&h), Err(VmdkError::Compressed));
}

#[test]
fn header_errors() {
    assert_eq!(parse_header(&META[..511]), Err(VmdkError::Truncated));
    let patch = |off: usize, val: &[u8]| {
        let mut h = META[..512].to_vec();
        h[off..off + val.len()].copy_from_slice(val);
        parse_header(&h)
    };
    assert_eq!(patch(0, b"KDMW"), Err(VmdkError::BadMagic));
    assert_eq!(patch(4, &4u32.to_le_bytes()), Err(VmdkError::UnsupportedVersion));
    assert_eq!(patch(4, &0u32.to_le_bytes()), Err(VmdkError::UnsupportedVersion));
    assert_eq!(patch(4, &3u32.to_le_bytes()).unwrap().version, 3);
    assert_eq!(patch(20, &100u64.to_le_bytes()), Err(VmdkError::BadGrainSize));
    assert_eq!(patch(20, &4u64.to_le_bytes()), Err(VmdkError::BadGrainSize));
    assert_eq!(patch(44, &256u32.to_le_bytes()), Err(VmdkError::BadHeader));
    assert_eq!(patch(56, &u64::MAX.to_le_bytes()), Err(VmdkError::BadHeader));
}

#[test]
fn open_and_read_errors() {
    let img = image();
    assert_eq!(open_vmdk(&img, 0), Err(VmdkError::LimitExceeded));
    assert_eq!(open_vmdk(&img[..13000], 8), Err(VmdkError::Truncated));
    let mut far = img.clone();
    far[26 * 512..26 * 512 + 4].copy_from_slice(&100_000u32.to_le_bytes());
    let v = open_vmdk(&far, 8).unwrap();
    assert_eq!(v.map_offset(&far, 0), Err(VmdkError::Truncated));
    let cut = &img[..G + 100];
    let v = open_vmdk(cut, 8).unwrap();
    assert_eq!(v.read_at(cut, 0, 50).unwrap(), &raw()[..50]);
    assert_eq!(v.read_at(cut, 0, 200), Err(VmdkError::Truncated));
    let mut huge = META[..512].to_vec();
    huge[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(open_vmdk(&huge, u32::MAX), Err(VmdkError::LimitExceeded));
}
