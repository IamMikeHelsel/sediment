use sediment_engine::vhd_footer::{VhdDiskType, VhdError, VhdMapping, open_vhd, parse_dynamic_header, parse_footer, vhd_checksum};

const FIXED: &[u8] = include_bytes!("vhd_footer_fixtures/fixed.vhd");
const DYNAMIC: &[u8] = include_bytes!("vhd_footer_fixtures/dynamic.vhd");

fn block(seed: u32) -> Vec<u8> {
    (0..4096u32).map(|i| ((i * 7 + seed) & 0xff) as u8).collect()
}

fn dynamic_virtual() -> Vec<u8> {
    let mut v = block(5);
    v.extend(vec![0u8; 4096]);
    v.extend(block(9));
    v.extend(vec![0u8; 4096]);
    v
}

fn refix_footer(img: &mut [u8], at: usize) {
    img[at + 64..at + 68].fill(0);
    let c = vhd_checksum(&img[at..at + 512], 64);
    img[at + 64..at + 68].copy_from_slice(&c.to_be_bytes());
}

#[test]
fn fixed_footer_fields() {
    let f = parse_footer(&FIXED[2048..]).unwrap();
    assert_eq!(f.disk_type, VhdDiskType::Fixed);
    assert_eq!(f.features, 2);
    assert_eq!(f.version, 0x0001_0000);
    assert_eq!(f.data_offset, u64::MAX);
    assert_eq!(f.timestamp, 0x2C5B_3A10);
    assert_eq!(&f.creator_app, b"sedi");
    assert_eq!(f.creator_version, 0x0001_0000);
    assert_eq!(&f.creator_os, b"Wi2k");
    assert_eq!((f.original_size, f.current_size), (2048, 2048));
    assert_eq!((f.cylinders, f.heads, f.sectors_per_track), (1, 1, 4));
    assert_eq!(f.unique_id, core::array::from_fn(|i| i as u8 + 1));
    assert_eq!(f.saved_state, 0);
    assert_eq!(f.checksum, vhd_checksum(&FIXED[2048..], 64));
}

#[test]
fn fixed_image_reads() {
    let img = open_vhd(FIXED, 16).unwrap();
    assert!(img.dynamic.is_none());
    assert!(img.bat.is_empty());
    assert_eq!(img.map_offset(0), Ok(VhdMapping::Data(0)));
    assert_eq!(img.map_offset(2047), Ok(VhdMapping::Data(2047)));
    assert_eq!(img.map_offset(2048), Err(VhdError::OutOfRange));
    assert_eq!(img.read_at(FIXED, 0, 2048).unwrap(), FIXED[..2048].to_vec());
    assert_eq!(img.read_at(FIXED, 2040, 9), Err(VhdError::OutOfRange));
    assert_eq!(img.read_at(FIXED, u64::MAX, 2), Err(VhdError::OutOfRange));
    assert_eq!(img.read_at(FIXED, 2048, 0), Ok(vec![]));
}

#[test]
fn dynamic_headers() {
    let f = parse_footer(&DYNAMIC[DYNAMIC.len() - 512..]).unwrap();
    assert_eq!(f.disk_type, VhdDiskType::Dynamic);
    assert_eq!(f.data_offset, 512);
    assert_eq!(f.current_size, 16384);
    assert_eq!((f.cylinders, f.heads, f.sectors_per_track), (1, 2, 16));
    assert_eq!(parse_footer(&DYNAMIC[..512]).unwrap(), f);
    let h = parse_dynamic_header(&DYNAMIC[512..1536]).unwrap();
    assert_eq!(h.table_offset, 1536);
    assert_eq!(h.header_version, 0x0001_0000);
    assert_eq!(h.max_table_entries, 4);
    assert_eq!(h.block_size, 4096);
    assert_eq!(h.checksum, vhd_checksum(&DYNAMIC[512..1536], 36));
    assert_eq!(h.parent_unique_id, [0u8; 16]);
    assert_eq!(h.parent_timestamp, 0);
}

#[test]
fn dynamic_mapping_and_reads() {
    let img = open_vhd(DYNAMIC, 16).unwrap();
    assert_eq!(img.bat, vec![4, 0xFFFF_FFFF, 13, 0xFFFF_FFFF]);
    assert_eq!(img.dynamic.as_ref().unwrap().block_size, 4096);
    assert_eq!(img.map_offset(0), Ok(VhdMapping::Data(2560)));
    assert_eq!(img.map_offset(4095), Ok(VhdMapping::Data(2560 + 4095)));
    assert_eq!(img.map_offset(4096), Ok(VhdMapping::Zero));
    assert_eq!(img.map_offset(8192 + 5), Ok(VhdMapping::Data(13 * 512 + 512 + 5)));
    assert_eq!(img.map_offset(16383), Ok(VhdMapping::Zero));
    assert_eq!(img.map_offset(16384), Err(VhdError::OutOfRange));
    let want = dynamic_virtual();
    assert_eq!(img.read_at(DYNAMIC, 0, 16384).unwrap(), want);
    assert_eq!(img.read_at(DYNAMIC, 4000, 200).unwrap(), want[4000..4200].to_vec());
    assert_eq!(img.read_at(DYNAMIC, 8000, 4500).unwrap(), want[8000..12500].to_vec());
    assert_eq!(img.read_at(DYNAMIC, 16000, 385), Err(VhdError::OutOfRange));
}

#[test]
fn differencing_maps_like_dynamic() {
    let mut d = DYNAMIC.to_vec();
    let end = d.len() - 512;
    d[end + 63] = 4;
    refix_footer(&mut d, end);
    let img = open_vhd(&d, 16).unwrap();
    assert_eq!(img.footer.disk_type, VhdDiskType::Differencing);
    assert_eq!(img.map_offset(4096), Ok(VhdMapping::Zero));
    assert_eq!(img.map_offset(1), Ok(VhdMapping::Data(2561)));
}

#[test]
fn checksum_function() {
    assert_eq!(vhd_checksum(&[], 0), 0xFFFF_FFFF);
    assert_eq!(vhd_checksum(&[1, 2, 3], 0), 0xFFFF_FFFF);
    assert_eq!(vhd_checksum(&[1, 2, 3, 4, 5, 6], 1), !(1u32 + 6));
    assert_eq!(vhd_checksum(&[0xff; 8], 100), !(8u32 * 255));
}

#[test]
fn malformed_footers() {
    let f = &FIXED[2048..];
    assert_eq!(parse_footer(&f[..511]), Err(VhdError::Truncated));
    let mut b = f.to_vec();
    b[0] = b'C';
    assert_eq!(parse_footer(&b), Err(VhdError::BadCookie));
    let mut b = f.to_vec();
    b[100] ^= 1;
    assert_eq!(parse_footer(&b), Err(VhdError::BadChecksum));
    let mut b = f.to_vec();
    b[13] = 2;
    refix_footer(&mut b, 0);
    assert_eq!(parse_footer(&b), Err(VhdError::UnsupportedVersion));
    let mut b = f.to_vec();
    b[63] = 5;
    refix_footer(&mut b, 0);
    assert_eq!(parse_footer(&b), Err(VhdError::UnsupportedDiskType));
}

#[test]
fn malformed_dynamic() {
    let h = &DYNAMIC[512..1536];
    assert_eq!(parse_dynamic_header(&h[..1023]), Err(VhdError::Truncated));
    let mut b = h.to_vec();
    b[2] = b'X';
    assert_eq!(parse_dynamic_header(&b), Err(VhdError::BadDynamicHeader));
    let mut b = h.to_vec();
    b[600] = 1;
    assert_eq!(parse_dynamic_header(&b), Err(VhdError::BadChecksum));
    let fix = |b: &mut Vec<u8>| {
        b[36..40].fill(0);
        let c = vhd_checksum(b, 36);
        b[36..40].copy_from_slice(&c.to_be_bytes());
    };
    let mut b = h.to_vec();
    b[25] = 2;
    fix(&mut b);
    assert_eq!(parse_dynamic_header(&b), Err(VhdError::UnsupportedVersion));
    for bs in [0u32, 256, 3000, 4097] {
        let mut b = h.to_vec();
        b[32..36].copy_from_slice(&bs.to_be_bytes());
        fix(&mut b);
        assert_eq!(parse_dynamic_header(&b), Err(VhdError::BadBlockSize), "bs={bs}");
    }
    assert_eq!(open_vhd(DYNAMIC, 3).err(), Some(VhdError::LimitExceeded));
    // max_table_entries too small to cover current_size
    let mut d = DYNAMIC.to_vec();
    d[512 + 31] = 3;
    let mut hb = d[512..1536].to_vec();
    fix(&mut hb);
    d[512..1536].copy_from_slice(&hb);
    assert_eq!(open_vhd(&d, 16).err(), Some(VhdError::BadDynamicHeader));
    // BAT outside the file
    let mut d = DYNAMIC.to_vec();
    d[512 + 16..512 + 24].copy_from_slice(&(u64::MAX - 8).to_be_bytes());
    let mut hb = d[512..1536].to_vec();
    fix(&mut hb);
    d[512..1536].copy_from_slice(&hb);
    assert_eq!(open_vhd(&d, 16).err(), Some(VhdError::Truncated));
    // header offset outside the file
    let mut d = DYNAMIC.to_vec();
    let end = d.len() - 512;
    d[end + 16..end + 24].copy_from_slice(&(u64::MAX - 100).to_be_bytes());
    refix_footer(&mut d, end);
    assert_eq!(open_vhd(&d, 16).err(), Some(VhdError::Truncated));
}

#[test]
fn bat_entry_past_end_of_file() {
    let mut d = DYNAMIC.to_vec();
    d[1536 + 8..1536 + 12].copy_from_slice(&0x7FFF_FFF0u32.to_be_bytes());
    let img = open_vhd(&d, 16).unwrap();
    assert_eq!(img.map_offset(8192), Ok(VhdMapping::Data(0x7FFF_FFF0u64 * 512 + 512)));
    assert_eq!(img.read_at(&d, 8192, 1), Err(VhdError::Truncated));
    assert_eq!(img.read_at(&d, 0, 4).unwrap(), block(5)[..4].to_vec());
}

#[test]
fn truncated_images_never_panic() {
    for img in [FIXED, DYNAMIC] {
        for n in 0..img.len() {
            assert!(open_vhd(&img[..n], 16).is_err(), "len {n}");
        }
    }
}
