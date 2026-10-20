use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::iso_joliet::{joliet_root, list_joliet, JolietError, JolietLimits};

const J_GZ: &[u8] = include_bytes!("iso_joliet_fixtures/joliet.iso.gz");
const P_GZ: &[u8] = include_bytes!("iso_joliet_fixtures/plain.iso.gz");
fn img(gz: &[u8]) -> Vec<u8> { decode_gzip(gz, 1 << 20, 1 << 12).unwrap() }

// (path, is_dir, size) as listed by `7zz l -slt joliet.iso` (sizes of dirs not compared).
const WANT: &[(&str, bool, u32)] = &[
    ("A long file name with spaces and more than thirty chars.txt", false, 6),
    ("EmptyDir", true, 0), ("Sub", true, 0), ("Sub/Inner", true, 0),
    ("Sub/Inner/日本語.txt", false, 1), ("Sub/b.TXT", false, 2), ("Sub/data.bin", false, 5000),
    ("empty.bin", false, 0), ("Ünïcödé dir", true, 0), ("Ünïcödé dir/naïve.txt", false, 3),
];

#[test]
fn finds_joliet_svd() {
    let im = img(J_GZ);
    let r = joliet_root(&im).unwrap();
    assert_eq!(r.level, 3);
    assert_eq!(r.size % 2048, 0);
    assert!(r.extent > 17);
}

#[test]
fn lists_like_7zz() {
    let im = img(J_GZ);
    let e = list_joliet(&im, joliet_root(&im).unwrap(), &JolietLimits::default()).unwrap();
    let mut got: Vec<(String, bool, u32)> =
        e.iter().map(|x| (x.path.clone(), x.is_dir, if x.is_dir { 0 } else { x.size })).collect();
    got.sort();
    let mut want: Vec<(String, bool, u32)> = WANT.iter().map(|w| (w.0.to_string(), w.1, w.2)).collect();
    want.sort();
    assert_eq!(got, want);
    // preorder: a directory comes immediately before its first child
    let i = e.iter().position(|x| x.path == "Sub/Inner").unwrap();
    assert_eq!(e[i + 1].path, "Sub/Inner/日本語.txt");
    assert!(e.iter().filter(|x| x.is_dir).all(|x| x.size % 2048 == 0 && x.size > 0));
}

#[test]
fn file_extent_holds_data() {
    let im = img(J_GZ);
    let e = list_joliet(&im, joliet_root(&im).unwrap(), &JolietLimits::default()).unwrap();
    let d = e.iter().find(|x| x.path == "Sub/data.bin").unwrap();
    let off = d.extent as usize * 2048;
    let want: Vec<u8> = (0..5000u32).map(|i| (i * 7 & 255) as u8).collect();
    assert_eq!(&im[off..off + 5000], &want[..]);
}

#[test]
fn plain_iso_has_no_joliet() {
    assert_eq!(joliet_root(&img(P_GZ)), Err(JolietError::NoJoliet));
    assert_eq!(joliet_root(&vec![0u8; 40 * 2048]), Err(JolietError::NoJoliet));
}

#[test]
fn truncated() {
    let im = img(J_GZ);
    assert_eq!(joliet_root(&im[..16 * 2048 + 100]), Err(JolietError::Truncated));
    assert_eq!(joliet_root(&[]), Err(JolietError::Truncated));
    let r = joliet_root(&im).unwrap();
    let cut = r.extent as usize * 2048 + 10;
    assert_eq!(list_joliet(&im[..cut], r, &JolietLimits::default()), Err(JolietError::Truncated));
}

#[test]
fn limits() {
    let im = img(J_GZ);
    let r = joliet_root(&im).unwrap();
    let l = JolietLimits { max_entries: 3, ..JolietLimits::default() };
    assert_eq!(list_joliet(&im, r, &l), Err(JolietError::LimitExceeded));
    let l = JolietLimits { max_depth: 1, ..JolietLimits::default() };
    assert_eq!(list_joliet(&im, r, &l), Err(JolietError::LimitExceeded));
    let l = JolietLimits { max_depth: 2, max_entries: 10 };
    assert_eq!(list_joliet(&im, r, &l).unwrap().len(), 10);
}

/// Point the root's "Sub" record at the root directory itself.
#[test]
fn loop_detected_and_bad_records() {
    let mut im = img(J_GZ);
    let r = joliet_root(&im).unwrap();
    let base = r.extent as usize * 2048;
    let name: Vec<u8> = "Sub".encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    let mut p = base;
    while im[p] != 0 {
        let len = im[p] as usize;
        let nl = im[p + 32] as usize;
        if im[p + 33..p + 33 + nl] == name[..] { break; }
        p += len;
    }
    assert_ne!(im[p], 0, "Sub record not found");
    let mut a = im.clone();
    a[p + 2..p + 6].copy_from_slice(&r.extent.to_le_bytes());
    a[p + 10..p + 14].copy_from_slice(&r.size.to_le_bytes());
    assert_eq!(list_joliet(&a, r, &JolietLimits::default()), Err(JolietError::LoopDetected));
    let mut b = im.clone();
    b[p] = 20; // record shorter than 34
    assert_eq!(list_joliet(&b, r, &JolietLimits::default()), Err(JolietError::BadRecord));
    im[p + 32] = 5; // odd UCS-2 name length
    assert_eq!(list_joliet(&im, r, &JolietLimits::default()), Err(JolietError::BadName));
}

#[test]
fn hostile_never_panics() {
    let im = img(J_GZ);
    let r = joliet_root(&im).unwrap();
    let base = r.extent as usize * 2048;
    let mut seed = 0x9e37_79b9u32;
    for _ in 0..300 {
        let mut v = im.clone();
        for _ in 0..8 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let i = base + (seed as usize >> 4) % 6144;
            v[i] = (seed >> 24) as u8;
        }
        let _ = list_joliet(&v, r, &JolietLimits::default());
        let _ = joliet_root(&v);
    }
}
