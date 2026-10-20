use sediment_engine::cramfs_dir::{CramError, CramKind, CramLimits, Endian, list_cramfs, parse_super, read_data};
use sediment_engine::crc32::crc32;

// Built by gen/cramfs_dir.py with util-linux mkfs.cramfs (block 4096), uid 1000, gid 1000 (stored as 232).
const LE: &[u8] = include_bytes!("cramfs_dir_fixtures/tree_le.cramfs");
const BE: &[u8] = include_bytes!("cramfs_dir_fixtures/tree_be.cramfs");
const PAD: &[u8] = include_bytes!("cramfs_dir_fixtures/tree_pad.cramfs");

const PATHS: [&str; 9] = ["big.txt", "dir", "dir/empty", "dir/holey.bin", "dir/nested.bin", "dir/sub", "dir/sub/deep.txt", "hello.txt", "link"];

fn expected(path: &str) -> Option<Vec<u8>> {
    Some(match path {
        "hello.txt" => b"hello, sediment\n".to_vec(),
        "big.txt" => b"cram me please ".repeat(400),
        "dir/nested.bin" => (0..10000u32).map(|i| ((i * 7 + 3) & 255) as u8).collect(),
        "dir/holey.bin" => [vec![b'A'; 4096], vec![0; 4096], vec![b'B'; 100]].concat(),
        "dir/empty" => Vec::new(),
        "dir/sub/deep.txt" => b"deep\n".to_vec(),
        "link" => b"hello.txt".to_vec(),
        _ => return None,
    })
}

/// Recompute the fsid CRC (superblock at `off`) after editing an image.
fn refix(img: &mut [u8], off: usize, big: bool) {
    let size = img.len() - off;
    img[off + 32..off + 36].fill(0);
    let c = crc32(&img[off..off + size]);
    img[off + 32..off + 36].copy_from_slice(&if big { c.to_be_bytes() } else { c.to_le_bytes() });
}

#[test]
fn superblock_little_endian() {
    let s = parse_super(LE).unwrap();
    assert_eq!((s.endian, s.offset), (Endian::Little, 0));
    assert_eq!(s.size as usize, LE.len());
    assert_eq!(s.flags, 0x103);
    assert_eq!(s.edition, 7);
    assert_eq!(s.files, 10);
    assert_eq!(&s.name[..8], b"sediment");
    assert_eq!(s.root.mode, 0o40775);
    assert_eq!(s.root.offset * 4, 76);
}

#[test]
fn superblock_big_endian_and_padded() {
    let s = parse_super(BE).unwrap();
    assert_eq!((s.endian, s.offset), (Endian::Big, 0));
    assert_eq!(s.root.mode, 0o40775);
    let p = parse_super(PAD).unwrap();
    assert_eq!((p.endian, p.offset), (Endian::Little, 512));
}

fn check_tree(img: &[u8]) {
    let (s, entries) = list_cramfs(img, &CramLimits::default()).unwrap();
    assert_eq!(entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), PATHS);
    for e in &entries {
        assert_eq!((e.inode.uid, e.inode.gid), (1000, 232), "{}", e.path);
        let (k, mode) = match e.path.as_str() {
            "dir" => (CramKind::Dir, 0o40755),
            "dir/sub" => (CramKind::Dir, 0o40700),
            "dir/nested.bin" => (CramKind::File, 0o100600),
            "link" => (CramKind::Symlink, 0o120777),
            _ => (CramKind::File, 0o100644),
        };
        assert_eq!((e.kind, e.inode.mode), (k, mode), "{}", e.path);
        if let Some(d) = expected(&e.path) {
            assert_eq!(e.inode.size as usize, d.len(), "{}", e.path);
            assert_eq!(read_data(img, &s, e, 1 << 20).unwrap(), d, "{}", e.path);
        }
    }
}

#[test]
fn tree_little_endian_with_holes() {
    check_tree(LE);
}

#[test]
fn tree_big_endian() {
    check_tree(BE);
}

#[test]
fn tree_padded_boot_area() {
    check_tree(PAD);
}

#[test]
fn read_errors_and_limits() {
    let (s, entries) = list_cramfs(LE, &CramLimits::default()).unwrap();
    let dir = entries.iter().find(|e| e.path == "dir").unwrap();
    assert_eq!(read_data(LE, &s, dir, 1 << 20), Err(CramError::BadInode));
    let nb = entries.iter().find(|e| e.path == "dir/nested.bin").unwrap();
    assert_eq!(read_data(LE, &s, nb, 9999), Err(CramError::LimitExceeded));
    let lim = CramLimits { max_entries: 4, ..CramLimits::default() };
    assert_eq!(list_cramfs(LE, &lim).unwrap_err(), CramError::LimitExceeded);
    let lim = CramLimits { max_depth: 1, ..CramLimits::default() };
    assert_eq!(list_cramfs(LE, &lim).unwrap_err(), CramError::LimitExceeded);
}

#[test]
fn header_errors() {
    assert_eq!(parse_super(&LE[..40]).unwrap_err(), CramError::Truncated);
    assert_eq!(parse_super(&[0u8; 1024]).unwrap_err(), CramError::BadMagic);
    let mut b = LE.to_vec();
    b[20] = b'x';
    assert_eq!(parse_super(&b).unwrap_err(), CramError::BadSignature);
    let mut b = LE.to_vec();
    b[2000] ^= 1;
    assert_eq!(parse_super(&b).unwrap_err(), CramError::BadCrc);
    let mut b = LE.to_vec();
    b[9] |= 0x08; // EXT_BLOCK_POINTERS (0x800)
    refix(&mut b, 0, false);
    assert_eq!(parse_super(&b).unwrap_err(), CramError::UnsupportedFlags);
    assert_eq!(parse_super(&LE[..LE.len() - 1]).unwrap_err(), CramError::Truncated);
}

#[test]
fn self_loop_detected() {
    // Point dir/sub at the children of "dir" (its own parent listing) -> Loop.
    let (s, entries) = list_cramfs(LE, &CramLimits::default()).unwrap();
    let dir = entries.iter().find(|e| e.path == "dir").unwrap().inode;
    let mut b = LE.to_vec();
    let mut p = dir.offset as usize * 4;
    loop {
        let nl = (b[p + 8] & 0x3f) as usize * 4;
        if &b[p + 12..p + 15] == b"sub" {
            let w2 = (dir.offset << 6) | (nl as u32 / 4);
            b[p + 8..p + 12].copy_from_slice(&w2.to_le_bytes());
            let w1 = (u32::from(b[p + 7]) << 24) | dir.size;
            b[p + 4..p + 8].copy_from_slice(&w1.to_le_bytes());
            break;
        }
        p += 12 + nl;
    }
    refix(&mut b, s.offset, false);
    assert_eq!(list_cramfs(&b, &CramLimits::default()).unwrap_err(), CramError::Loop);
}

#[test]
fn hostile_inputs_never_panic() {
    for i in 64..LE.len() {
        for x in [0x01u8, 0x80, 0xff] {
            let mut b = LE.to_vec();
            b[i] ^= x;
            refix(&mut b, 0, false);
            if let Ok((s, entries)) = list_cramfs(&b, &CramLimits::default()) {
                for e in &entries {
                    let _ = read_data(&b, &s, e, 1 << 20);
                }
            }
        }
    }
    for cut in [76, 100, 300, 1000, 3000] {
        let _ = list_cramfs(&LE[..cut], &CramLimits::default());
    }
}
