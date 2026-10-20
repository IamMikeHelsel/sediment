use sediment_engine::gzip_slt_info::{gzip_info, host_os_name, GzipInfoError};

const FULL: &[u8] = include_bytes!("gzip_slt_info_fixtures/full.gz");
const PLAIN: &[u8] = include_bytes!("gzip_slt_info_fixtures/plain.gz");
const MULTI: &[u8] = include_bytes!("gzip_slt_info_fixtures/multi.gz");
const JUNK: &[u8] = include_bytes!("gzip_slt_info_fixtures/junk.gz");

// Expected values: `7zz l -slt` (7-Zip 26.04), see gen/oracle-7zz.txt.
#[test]
fn all_optional_fields() {
    let g = gzip_info(FULL, 1024).unwrap();
    assert_eq!(g.headers_size, 40);
    assert_eq!(g.name.as_deref(), Some("näme.txt".as_bytes()));
    assert_eq!(g.comment.as_deref(), Some(&b"a comment"[..]));
    assert_eq!((g.mtime, g.xfl, g.host_os), (Some(1_000_000_000), 2, 11));
    assert_eq!(host_os_name(g.host_os), "NTFS");
    assert_eq!((g.crc32, g.size, g.packed_size), (0x0559_FA25, 340, 72));
}

#[test]
fn plain_and_multi_and_junk() {
    let g = gzip_info(PLAIN, 1024).unwrap();
    assert_eq!((g.headers_size, g.mtime, g.name.clone(), g.comment.clone()), (10, None, None, None));
    assert_eq!((g.crc32, g.size, g.packed_size, host_os_name(g.host_os).as_str()), (0x0559_FA25, 340, 42, "Unix"));
    let g = gzip_info(MULTI, 1024).unwrap();
    assert_eq!((g.headers_size, g.crc32, g.size, g.packed_size), (10, 0x731B_405A, 40, 48));
    let g = gzip_info(JUNK, 1024).unwrap();
    assert_eq!((g.crc32, g.size, g.packed_size), (0x4B4E_554A, 1_263_424_842, 32));
}

#[test]
fn host_os_table() {
    let want = ["FAT", "AMIGA", "VMS", "Unix", "VM/CMS", "Atari", "HPFS", "Macintosh", "Z-System", "CP/M",
                "TOPS-20", "NTFS", "SMS/QDOS", "Acorn", "VFAT", "MVS", "BeOS", "Tandem", "OS/400", "OS/X"];
    for (i, w) in want.iter().enumerate() {
        assert_eq!(host_os_name(i as u8), *w);
    }
    assert_eq!(host_os_name(20), "20");
    assert_eq!(host_os_name(255), "255");
}

#[test]
fn header_crc_not_verified() {
    let mut v = FULL.to_vec();
    v[38] ^= 1; // FHCRC low byte
    assert_eq!(gzip_info(&v, 1024).unwrap().headers_size, 40);
}

#[test]
fn errors() {
    assert_eq!(gzip_info(&PLAIN[..9], 99).err(), Some(GzipInfoError::Truncated));
    let mut v = PLAIN.to_vec(); v[1] = 0x8C;
    assert_eq!(gzip_info(&v, 99).err(), Some(GzipInfoError::BadSignature));
    let mut v = PLAIN.to_vec(); v[2] = 7;
    assert_eq!(gzip_info(&v, 99).err(), Some(GzipInfoError::BadHeader));
    let mut v = PLAIN.to_vec(); v[3] |= 0x20;
    assert_eq!(gzip_info(&v, 99).err(), Some(GzipInfoError::BadHeader));
    assert_eq!(gzip_info(&FULL[..11], 99).err(), Some(GzipInfoError::Truncated)); // XLEN cut
    assert_eq!(gzip_info(&FULL[..15], 99).err(), Some(GzipInfoError::Truncated)); // extra cut
    assert_eq!(gzip_info(&FULL[..24], 99).err(), Some(GzipInfoError::Truncated)); // name unterminated
    assert_eq!(gzip_info(&FULL[..39], 99).err(), Some(GzipInfoError::Truncated)); // FHCRC cut
    assert_eq!(gzip_info(&FULL[..47], 99).err(), Some(GzipInfoError::Truncated)); // < header + 8
    assert_eq!(gzip_info(&FULL[..48], 99).unwrap().headers_size, 40);
    assert_eq!(gzip_info(FULL, 8).err(), Some(GzipInfoError::LimitExceeded)); // name is 9 bytes
    assert_eq!(gzip_info(FULL, 9).unwrap().comment.unwrap().len(), 9);
}

#[test]
fn hostile_never_panics() {
    let mut seed = 77u32;
    for _ in 0..2000 {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let mut v = FULL.to_vec();
        v[(seed as usize >> 4) % 40] = (seed >> 20) as u8;
        let _ = gzip_info(&v[..(seed as usize >> 8) % v.len()], 16);
    }
}
