use sediment_engine::qcow2_header::{ClusterMapping, Qcow2Error, open_qcow2, parse_header};

const V2: &[u8] = include_bytes!("qcow2_header_fixtures/v2.qcow2");
const V3: &[u8] = include_bytes!("qcow2_header_fixtures/v3.qcow2");

fn pattern(seed: u32) -> Vec<u8> {
    (0..512u32).map(|i| ((i * 13 + seed) & 0xff) as u8).collect()
}

fn guest(v3: bool) -> Vec<u8> {
    let mut g = vec![0u8; 40960];
    g[..512].copy_from_slice(&pattern(1));
    g[70 * 512..71 * 512].copy_from_slice(&pattern(70));
    if v3 {
        g[512..1024].copy_from_slice(&pattern(2));
    }
    g
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_be_bytes());
}

#[test]
fn header_fields_v3() {
    let h = parse_header(V3).unwrap();
    assert_eq!(h.version, 3);
    assert_eq!((h.backing_file_offset, h.backing_file_size), (0, 0));
    assert_eq!(h.cluster_bits, 9);
    assert_eq!(h.size, 40960);
    assert_eq!(h.crypt_method, 0);
    assert_eq!(h.l1_size, 2);
    assert_eq!(h.l1_table_offset, 1536);
    assert_eq!(h.refcount_table_offset, 512);
    assert_eq!(h.refcount_table_clusters, 1);
    assert_eq!((h.nb_snapshots, h.snapshots_offset), (0, 0));
    assert_eq!((h.incompatible_features, h.compatible_features, h.autoclear_features), (0, 0, 0));
    assert_eq!(h.refcount_order, 4);
    assert_eq!(h.header_length, 104);
}

#[test]
fn header_fields_v2_defaults() {
    let h = parse_header(V2).unwrap();
    assert_eq!(h.version, 2);
    assert_eq!(h.size, 40960);
    assert_eq!(h.refcount_order, 4);
    assert_eq!(h.header_length, 72);
    assert_eq!((h.incompatible_features, h.compatible_features, h.autoclear_features), (0, 0, 0));
    assert_eq!(parse_header(&V2[..72]).unwrap(), h);
}

#[test]
fn mapping_v3() {
    let img = open_qcow2(V3, 1024).unwrap();
    assert_eq!(img.cluster_size(), 512);
    assert_eq!(img.l1, vec![2048 | 1 << 63, 2560 | 1 << 63]);
    assert_eq!(img.map_offset(V3, 0), Ok(ClusterMapping::Data(3072)));
    assert_eq!(img.map_offset(V3, 513), Ok(ClusterMapping::Data(3585)));
    assert_eq!(img.map_offset(V3, 70 * 512 + 511), Ok(ClusterMapping::Data(4096 + 511)));
    assert_eq!(img.map_offset(V3, 3 * 512), Ok(ClusterMapping::Zero));
    assert_eq!(img.map_offset(V3, 5 * 512 + 7), Ok(ClusterMapping::Zero));
    assert_eq!(img.map_offset(V3, 2 * 512), Ok(ClusterMapping::Unallocated));
    assert_eq!(img.map_offset(V3, 40959), Ok(ClusterMapping::Unallocated));
    assert_eq!(img.map_offset(V3, 40960), Err(Qcow2Error::OutOfRange));
    let map = img.cluster_map(V3, 80).unwrap();
    assert_eq!(map.len(), 80);
    for (i, m) in map.iter().enumerate() {
        let want = match i {
            0 => ClusterMapping::Data(3072),
            1 => ClusterMapping::Data(3584),
            3 | 5 => ClusterMapping::Zero,
            70 => ClusterMapping::Data(4096),
            _ => ClusterMapping::Unallocated,
        };
        assert_eq!(*m, want, "cluster {i}");
    }
    assert_eq!(img.cluster_map(V3, 79), Err(Qcow2Error::LimitExceeded));
}

#[test]
fn reads_match_qemu_img_convert() {
    for (data, v3) in [(V3, true), (V2, false)] {
        let img = open_qcow2(data, 16).unwrap();
        let g = guest(v3);
        assert_eq!(img.read_at(data, 0, 40960).unwrap(), g);
        assert_eq!(img.read_at(data, 500, 600).unwrap(), g[500..1100].to_vec());
        assert_eq!(img.read_at(data, 1500, 800).unwrap(), g[1500..2300].to_vec());
        assert_eq!(img.read_at(data, 40960, 0), Ok(vec![]));
        assert_eq!(img.read_at(data, 40900, 61), Err(Qcow2Error::OutOfRange));
        assert_eq!(img.read_at(data, u64::MAX, 1), Err(Qcow2Error::OutOfRange));
    }
}

#[test]
fn bad_headers() {
    assert_eq!(parse_header(&V3[..71]), Err(Qcow2Error::Truncated));
    assert_eq!(parse_header(&V3[..103]), Err(Qcow2Error::Truncated));
    let mut b = V3.to_vec();
    b[3] = 0xfa;
    assert_eq!(parse_header(&b), Err(Qcow2Error::BadMagic));
    for v in [0u8, 1, 4] {
        let mut b = V3.to_vec();
        b[7] = v;
        assert_eq!(parse_header(&b), Err(Qcow2Error::UnsupportedVersion));
    }
    let mut b = V3.to_vec();
    b[103] = 100;
    assert_eq!(parse_header(&b), Err(Qcow2Error::BadHeader));
    for cb in [0u8, 8, 22, 63] {
        let mut b = V3.to_vec();
        b[23] = cb;
        assert_eq!(parse_header(&b), Err(Qcow2Error::BadClusterBits), "cb={cb}");
    }
    let mut b = V3.to_vec();
    b[35] = 1;
    assert_eq!(parse_header(&b), Err(Qcow2Error::Encrypted));
    let mut b = V3.to_vec();
    b[79] = 2;
    assert_eq!(parse_header(&b), Err(Qcow2Error::UnsupportedFeature));
    let mut b = V3.to_vec();
    b[79] = 1; // dirty bit is fine
    assert!(parse_header(&b).is_ok());
    let mut b = V2.to_vec();
    b[79] = 0xff; // v2 has no feature fields: byte 79 is not a header field
    assert_eq!(parse_header(&b).unwrap().incompatible_features, 0);
}

#[test]
fn bad_tables() {
    assert_eq!(open_qcow2(V3, 1).err(), Some(Qcow2Error::LimitExceeded));
    let mut b = V3.to_vec();
    b[39] = 1; // l1_size 1 cannot cover 40960 bytes
    assert_eq!(open_qcow2(&b, 16).err(), Some(Qcow2Error::BadL1));
    let mut b = V3.to_vec();
    put64(&mut b, 40, 1537); // unaligned L1
    assert_eq!(open_qcow2(&b, 16).err(), Some(Qcow2Error::BadL1));
    let mut b = V3.to_vec();
    put64(&mut b, 40, 1 << 40); // L1 beyond EOF
    assert_eq!(open_qcow2(&b, 16).err(), Some(Qcow2Error::Truncated));
    let mut b = V3.to_vec();
    put64(&mut b, 40, u64::MAX - 511); // overflow
    assert!(open_qcow2(&b, 16).is_err());

    let mut b = V3.to_vec();
    put64(&mut b, 1536 + 8, 2561); // reserved L1 bit 0 set
    let img = open_qcow2(&b, 16).unwrap();
    assert_eq!(img.map_offset(&b, 70 * 512), Err(Qcow2Error::BadL1));
    assert_eq!(img.map_offset(&b, 0), Ok(ClusterMapping::Data(3072)));
    let mut b = V3.to_vec();
    put64(&mut b, 1536 + 8, 1 << 40); // L2 table beyond EOF
    let img = open_qcow2(&b, 16).unwrap();
    assert_eq!(img.map_offset(&b, 70 * 512), Err(Qcow2Error::Truncated));

    let mut b = V3.to_vec();
    put64(&mut b, 2048, 1 << 62 | 3072); // compressed cluster descriptor
    let img = open_qcow2(&b, 16).unwrap();
    assert_eq!(img.map_offset(&b, 0), Err(Qcow2Error::Compressed));
    assert_eq!(img.read_at(&b, 0, 1), Err(Qcow2Error::Compressed));
    let mut b = V3.to_vec();
    put64(&mut b, 2048, 3073); // bit 0 set with host -> zero cluster
    let img = open_qcow2(&b, 16).unwrap();
    assert_eq!(img.map_offset(&b, 0), Ok(ClusterMapping::Zero));
    let mut b = V3.to_vec();
    put64(&mut b, 2048, 3072 + 256); // reserved L2 bit 8 set
    let img = open_qcow2(&b, 16).unwrap();
    assert_eq!(img.map_offset(&b, 0), Err(Qcow2Error::BadL2));
    let mut b = V3.to_vec();
    put64(&mut b, 2048, 1 << 63 | 5120); // host cluster at EOF
    let img = open_qcow2(&b, 16).unwrap();
    assert_eq!(img.map_offset(&b, 0), Err(Qcow2Error::Truncated));
}

#[test]
fn truncated_files_never_panic() {
    for data in [V2, V3] {
        for n in 0..data.len() {
            let cut = &data[..n];
            if let Ok(img) = open_qcow2(cut, 16) {
                let _ = img.read_at(cut, 0, 40960);
                let _ = img.cluster_map(cut, 80);
            }
        }
        assert!(open_qcow2(&data[..1543], 16).is_err());
    }
}
