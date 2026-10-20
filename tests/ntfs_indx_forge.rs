use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::ntfs_indx::{apply_fixups, parse_index_block, parse_index_root, IndxError};

const ROOT_IR: &[u8] = include_bytes!("ntfs_indx_fixtures/n_root_ir.bin");
const EXT_IR: &[u8] = include_bytes!("ntfs_indx_fixtures/ext_ir.bin");
const INDX_GZ: &[u8] = include_bytes!("ntfs_indx_fixtures/n_indx.bin.gz");
fn blocks() -> Vec<Vec<u8>> { decode_gzip(INDX_GZ, 1 << 16, 64).unwrap().chunks(4096).map(|c| c.to_vec()).collect() }
// Root names `7zz l` shows for n.img (system files under [SYSTEM]/), plus the root's own "." entry.
const SYSTEM: [&str; 12] = [".", "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", "$Bitmap", "$Boot", "$BadClus",
                            "$Secure", "$UpCase", "$Extend"];

#[test]
fn root_btree_node() {
    let n = parse_index_root(ROOT_IR, 1000).unwrap();
    assert_eq!(n.vcn, None);
    assert!(n.has_children);
    let got: Vec<(&str, Option<u64>)> = n.entries.iter().map(|e| (e.name.as_str(), e.subnode_vcn)).collect();
    assert_eq!(got, [("f_06_naïve_name.txt", Some(0)), ("f_23_naïve_name.txt", Some(1)), ("f_40_naïve_name.txt", Some(2))]);
    assert_eq!(n.end_subnode_vcn, Some(3));
    assert!(n.entries.iter().all(|e| e.parent_record == 5 && !e.is_dir));
    assert_eq!(n.entries[0].mft_record, 69); // ntfscp created f_01..f_60 as records 64..123
}

#[test]
fn whole_directory_matches_7zz() {
    let mut names: Vec<String> = parse_index_root(ROOT_IR, 1000).unwrap().entries.into_iter().map(|e| e.name).collect();
    for (v, b) in blocks().iter().enumerate() {
        let n = parse_index_block(b, 1000).unwrap();
        assert_eq!(n.vcn, Some(v as u64));
        assert!(!n.has_children && n.end_subnode_vcn.is_none());
        for e in &n.entries {
            assert_eq!(e.parent_record, 5);
            if let Some(i) = e.name.strip_prefix("f_") {
                let k: u64 = i[..2].parse().unwrap();
                assert_eq!((e.mft_record, e.namespace, e.is_dir), (63 + k, 0, false));
            } else {
                assert_eq!(e.namespace, 3);
            }
            names.push(e.name.clone());
        }
    }
    let mut want: Vec<String> = (1..=60).map(|i| format!("f_{i:02}_naïve_name.txt")).collect();
    want.extend(SYSTEM.iter().map(|s| s.to_string()));
    names.sort();
    want.sort();
    assert_eq!(names, want);
}

#[test]
fn resident_leaf_root() {
    let n = parse_index_root(EXT_IR, 10).unwrap();
    assert!(!n.has_children);
    let got: Vec<(&str, u64, u64)> = n.entries.iter().map(|e| (e.name.as_str(), e.mft_record, e.parent_record)).collect();
    assert_eq!(got, [("$ObjId", 25, 11), ("$Quota", 24, 11), ("$Reparse", 26, 11)]);
    assert_eq!(n.end_subnode_vcn, None);
    assert_eq!(parse_index_root(EXT_IR, 2), Err(IndxError::LimitExceeded));
}

#[test]
fn fixups() {
    let b = &blocks()[1];
    let mut r = b.clone();
    apply_fixups(&mut r, b"INDX").unwrap();
    let uo = u16::from_le_bytes([b[4], b[5]]) as usize;
    assert_eq!(&r[510..512], &b[uo + 2..uo + 4]);
    assert_eq!(&r[4094..4096], &b[uo + 16..uo + 18]);
    assert_eq!(apply_fixups(&mut b.clone(), b"FILE"), Err(IndxError::BadMagic));
    let mut bad = b.clone();
    bad[1022] ^= 1; // sector 2 trailer no longer equals the update sequence number
    assert_eq!(apply_fixups(&mut bad, b"INDX"), Err(IndxError::BadFixup));
    assert_eq!(parse_index_block(&bad, 1000), Err(IndxError::BadFixup));
    assert_eq!(apply_fixups(&mut b[..2048].to_vec(), b"INDX"), Err(IndxError::BadFixup));
    assert_eq!(apply_fixups(&mut b[..6].to_vec(), b"INDX"), Err(IndxError::Truncated));
}

#[test]
fn malformed() {
    assert_eq!(parse_index_root(&ROOT_IR[..20], 10), Err(IndxError::Truncated));
    assert_eq!(parse_index_block(&[0u8; 30], 10), Err(IndxError::Truncated));
    let mut ir = ROOT_IR.to_vec();
    ir[0] = 0x80; // indexes something other than $FILE_NAME
    assert_eq!(parse_index_root(&ir, 10), Err(IndxError::BadHeader));
    let mut ir = ROOT_IR.to_vec();
    ir[20..24].copy_from_slice(&5000u32.to_le_bytes()); // index_length past the value
    assert_eq!(parse_index_root(&ir, 10), Err(IndxError::BadHeader));
    let mut ir = ROOT_IR.to_vec();
    let first = 16 + u32::from_le_bytes(ir[16..20].try_into().unwrap()) as usize;
    ir[first + 8] = 12; // entry length < 16
    assert_eq!(parse_index_root(&ir, 10), Err(IndxError::BadEntry));
    let mut ir = EXT_IR.to_vec();
    let first = 16 + u32::from_le_bytes(ir[16..20].try_into().unwrap()) as usize;
    ir[first + 16 + 64] = 200; // name longer than the key
    assert_eq!(parse_index_root(&ir, 10), Err(IndxError::BadEntry));
}

#[test]
fn hostile_never_panics() {
    let mut seed = 0x2468_ace1u32;
    for _ in 0..400 {
        let mut ir = ROOT_IR.to_vec();
        let mut bl = blocks()[0].clone();
        for _ in 0..6 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = (seed >> 8) as usize;
            let n = ir.len();
            ir[i % n] = (seed >> 24) as u8;
            bl[i % 4096] = (seed >> 16) as u8;
        }
        let _ = parse_index_root(&ir, 100);
        let _ = parse_index_block(&bl, 100);
    }
}
