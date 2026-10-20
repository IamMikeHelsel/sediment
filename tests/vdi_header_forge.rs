use sediment_engine::vdi_header::{VdiError, VdiImageType, VdiMapping, open_vdi, parse_header};

// Metadata prefixes [0, offset_data) written by `qemu-img convert -O vdi` (see gen/vdi_header.py).
const DYN_META: &[u8] = include_bytes!("vdi_header_fixtures/dyn.meta");
const FIXED_META: &[u8] = include_bytes!("vdi_header_fixtures/fixed.meta");
const MIB: usize = 1 << 20;

fn raw() -> Vec<u8> {
    let mut d = vec![0u8; 4 * MIB];
    for i in 0..65536 {
        d[i] = ((i * 7 + 3) & 0xff) as u8;
    }
    for i in 2 * MIB..2 * MIB + 4096 {
        d[i] = ((i * 13 + 1) & 0xff) as u8;
    }
    d
}

// qemu stores allocated blocks after the metadata in block-map order (generator asserts this).
fn dyn_image() -> Vec<u8> {
    let r = raw();
    let mut v = DYN_META.to_vec();
    v.extend_from_slice(&r[..MIB]);
    v.extend_from_slice(&r[2 * MIB..3 * MIB]);
    v
}

fn fixed_image() -> Vec<u8> {
    let mut v = FIXED_META.to_vec();
    v.extend_from_slice(&raw());
    v
}

#[test]
fn dynamic_header_fields() {
    let h = parse_header(DYN_META).unwrap();
    assert_eq!(h.version, 0x0001_0001);
    assert_eq!(h.header_size, 0x180);
    assert_eq!(h.image_type, VdiImageType::Dynamic);
    assert_eq!((h.offset_bmap, h.offset_data, h.sector_size), (512, 1024, 512));
    assert_eq!(h.disk_size, 4 << 20);
    assert_eq!((h.block_size, h.block_extra), (1 << 20, 0));
    assert_eq!((h.blocks_in_image, h.blocks_allocated), (4, 2));
    assert_eq!(&h.uuid_image[..], &DYN_META[0x188..0x198]);
    assert_eq!(h.uuid_parent, [0u8; 16]);
    assert!(h.description.is_empty());
}

#[test]
fn fixed_header_and_map() {
    let img = fixed_image();
    let v = open_vdi(&img, 16).unwrap();
    assert_eq!(v.header.image_type, VdiImageType::Fixed);
    assert_eq!(v.header.blocks_allocated, 4);
    assert_eq!(v.bmap, vec![0, 1, 2, 3]);
    assert_eq!(v.map_offset(3 * MIB as u64 + 7).unwrap(), VdiMapping::Data(1024 + 3 * MIB as u64 + 7));
}

#[test]
fn dynamic_block_map() {
    let img = dyn_image();
    let v = open_vdi(&img, 16).unwrap();
    assert_eq!(v.bmap, vec![0, 0xFFFF_FFFF, 1, 0xFFFF_FFFF]);
    assert_eq!(v.map_offset(0).unwrap(), VdiMapping::Data(1024));
    assert_eq!(v.map_offset(MIB as u64).unwrap(), VdiMapping::Unallocated);
    assert_eq!(v.map_offset(2 * MIB as u64 + 5).unwrap(), VdiMapping::Data(1024 + MIB as u64 + 5));
    assert_eq!(v.map_offset(4 * MIB as u64), Err(VdiError::OutOfRange));
}

#[test]
fn read_whole_disks_match_raw() {
    let r = raw();
    let d = dyn_image();
    assert_eq!(open_vdi(&d, 16).unwrap().read_at(&d, 0, 4 * MIB).unwrap(), r);
    let f = fixed_image();
    assert_eq!(open_vdi(&f, 16).unwrap().read_at(&f, 0, 4 * MIB).unwrap(), r);
}

#[test]
fn read_across_blocks() {
    let r = raw();
    let d = dyn_image();
    let v = open_vdi(&d, 16).unwrap();
    for &(off, len) in &[(MIB - 10, 20), (2 * MIB - 3, 4100), (65530, 12), (4 * MIB - 1, 1)] {
        assert_eq!(v.read_at(&d, off as u64, len).unwrap(), &r[off..off + len], "{off}+{len}");
    }
    assert_eq!(v.read_at(&d, 4 * MIB as u64, 0).unwrap(), Vec::<u8>::new());
    assert_eq!(v.read_at(&d, 4 * MIB as u64 - 1, 2), Err(VdiError::OutOfRange));
    assert_eq!(v.read_at(&d, u64::MAX, 2), Err(VdiError::OutOfRange));
}

#[test]
fn zero_block_entry() {
    let mut d = dyn_image();
    d[512 + 8..512 + 12].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    let v = open_vdi(&d, 16).unwrap();
    assert_eq!(v.map_offset(2 * MIB as u64).unwrap(), VdiMapping::Zero);
    assert_eq!(v.read_at(&d, 2 * MIB as u64, 4096).unwrap(), vec![0u8; 4096]);
}

#[test]
fn block_extra_and_description() {
    let mut m = DYN_META.to_vec();
    m[0x54..0x5A].copy_from_slice(b"hello\0");
    m[0x17C..0x180].copy_from_slice(&512u32.to_le_bytes());
    let mut d = m.clone();
    let r = raw();
    d.extend(vec![0xEEu8; 512]);
    d.extend_from_slice(&r[..MIB]);
    d.extend(vec![0xEEu8; 512]);
    d.extend_from_slice(&r[2 * MIB..3 * MIB]);
    let v = open_vdi(&d, 16).unwrap();
    assert_eq!(v.header.description, b"hello".to_vec());
    assert_eq!(v.header.block_extra, 512);
    assert_eq!(v.map_offset(2 * MIB as u64).unwrap(), VdiMapping::Data(1024 + MIB as u64 + 512 + 512));
    assert_eq!(v.read_at(&d, 0, 4 * MIB).unwrap(), r);
}

#[test]
fn header_errors() {
    assert_eq!(parse_header(&DYN_META[..400]), Err(VdiError::Truncated));
    let patch = |off: usize, val: u32| {
        let mut m = DYN_META.to_vec();
        m[off..off + 4].copy_from_slice(&val.to_le_bytes());
        parse_header(&m)
    };
    assert_eq!(patch(0x40, 0xBEDA_1070), Err(VdiError::BadSignature));
    assert_eq!(patch(0x44, 0x0002_0000), Err(VdiError::UnsupportedVersion));
    assert_eq!(patch(0x48, 0x100), Err(VdiError::BadHeader));
    assert_eq!(patch(0x4C, 5), Err(VdiError::UnsupportedImageType));
    assert_eq!(patch(0x4C, 4).unwrap().image_type, VdiImageType::Differencing);
    assert_eq!(patch(0x168, 4096), Err(VdiError::BadHeader));
    assert_eq!(patch(0x178, 1000), Err(VdiError::BadBlockSize));
    assert_eq!(patch(0x178, 256), Err(VdiError::BadBlockSize));
    assert_eq!(patch(0x180, 3), Err(VdiError::BadHeader));
    assert_eq!(patch(0x184, 5), Err(VdiError::BadHeader));
}

#[test]
fn open_errors() {
    let d = dyn_image();
    assert_eq!(open_vdi(&d, 3), Err(VdiError::LimitExceeded));
    assert_eq!(open_vdi(&d[..520], 16), Err(VdiError::Truncated));
    let mut bad = d.clone();
    bad[512 + 8..512 + 12].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(open_vdi(&bad, 16), Err(VdiError::BadBlockMap));
    let mut huge = DYN_META.to_vec();
    huge[0x154..0x158].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(open_vdi(&huge, 16), Err(VdiError::Truncated));
}

#[test]
fn truncated_data_region() {
    let d = dyn_image();
    let cut = &d[..1024 + 100];
    let v = open_vdi(cut, 16).unwrap();
    assert_eq!(v.read_at(cut, 0, 50).unwrap(), &raw()[..50]);
    assert_eq!(v.read_at(cut, 0, 200), Err(VdiError::Truncated));
    assert_eq!(v.read_at(cut, MIB as u64, 200).unwrap(), vec![0u8; 200]);
}
