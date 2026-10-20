use sediment_engine::gzip_wrapper::decode_gzip;
use sediment_engine::qcow2_compressed::{parse_compressed_entry, read_compressed_cluster, CompressedCluster, Qcow2CompError};

const C4K: &[u8] = include_bytes!("qcow2_compressed_fixtures/c4k.qcow2.gz");
const C64K: &[u8] = include_bytes!("qcow2_compressed_fixtures/c64k.qcow2.gz");

fn be64(b: &[u8], o: usize) -> u64 { u64::from_be_bytes(b[o..o + 8].try_into().unwrap()) }

/// Same pattern as gen/qcow2_compressed.sh writes into raw.img (cluster 2 of 64 KiB stays zero).
fn raw() -> Vec<u8> {
    let mut d = vec![0u8; 262144];
    let mut line = 0;
    for c in [0usize, 1, 3] {
        let mut s = Vec::new();
        for i in 0..4000 { s.extend(format!("cluster {:05} line {:06}\n", c, line + i).bytes()); }
        line += 4000;
        d[c * 65536..(c + 1) * 65536].copy_from_slice(&s[..65536]);
    }
    d
}

/// Every L2 entry of the first L2 table (images are < 2 MiB of guest data).
fn l2_entries(img: &[u8]) -> (u32, Vec<u64>) {
    let cb = u32::from_be_bytes(img[20..24].try_into().unwrap());
    let l2 = (be64(img, be64(img, 40) as usize) & 0x00ff_ffff_ffff_fe00) as usize;
    let n = 262144 >> cb;
    (cb, (0..n).map(|i| be64(img, l2 + 8 * i)).collect())
}

fn check_image(gz: &[u8], want_compressed: usize) {
    let img = decode_gzip(gz, 1 << 20, 1 << 16).unwrap();
    let (cb, ents) = l2_entries(&img);
    let cs = 1usize << cb;
    let r = raw();
    let mut n = 0;
    for (i, &e) in ents.iter().enumerate() {
        if e == 0 { assert!(r[i * cs..(i + 1) * cs].iter().all(|&b| b == 0)); continue; }
        assert_eq!(read_compressed_cluster(&img, e, cb).unwrap(), r[i * cs..(i + 1) * cs].to_vec(), "cluster {i}");
        n += 1;
    }
    assert_eq!(n, want_compressed);
}

#[test]
fn qemu_4k_clusters() { check_image(C4K, 48); }

#[test]
fn qemu_64k_clusters() { check_image(C64K, 3); }

#[test]
fn descriptor_bit_layout() {
    // Values decoded from the qemu-img fixtures by the Python generator check.
    assert_eq!(parse_compressed_entry(0x4400_0000_0000_5179, 12).unwrap(),
               CompressedCluster { host_offset: 0x5179, extra_sectors: 1, compressed_len: 1024 - 0x179 });
    assert_eq!(parse_compressed_entry(0x42c0_0000_0005_0000, 16).unwrap(),
               CompressedCluster { host_offset: 0x50000, extra_sectors: 11, compressed_len: 12 * 512 });
    // cluster_bits 9: x = 61, one sector-count bit.
    assert_eq!(parse_compressed_entry((1 << 62) | (1 << 61) | 0x1234, 9).unwrap(),
               CompressedCluster { host_offset: 0x1234, extra_sectors: 1, compressed_len: 1024 - 0x34 });
    // cluster_bits 21: x = 49.
    assert_eq!(parse_compressed_entry((1 << 62) | (0x1fff << 49) | 0x1_0000_0001, 21).unwrap(),
               CompressedCluster { host_offset: 0x1_0000_0001, extra_sectors: 0x1fff, compressed_len: 0x2000 * 512 - 1 });
}

#[test]
fn descriptor_errors() {
    assert_eq!(parse_compressed_entry(1 << 62, 8), Err(Qcow2CompError::BadClusterBits));
    assert_eq!(parse_compressed_entry(1 << 62, 22), Err(Qcow2CompError::BadClusterBits));
    assert_eq!(parse_compressed_entry(0x8000_0000_0005_0000, 16), Err(Qcow2CompError::NotCompressed));
    assert_eq!(parse_compressed_entry(0, 16), Err(Qcow2CompError::NotCompressed));
    assert_eq!(parse_compressed_entry(0xC000_0000_0000_1000, 16), Err(Qcow2CompError::BadEntry));
}

#[test]
fn handmade_stored_block() {
    // RFC 1951 stored final block of 512 bytes 'A' at an unaligned offset, then junk padding.
    let mut img = vec![0xEEu8; 300];
    img.extend([0x01, 0x00, 0x02, 0xff, 0xfd]);
    img.extend([b'A'; 512]);
    img.extend([0x55u8; 40]);
    let e = (1u64 << 62) | (1 << 61) | 300; // cluster_bits 9, 1 extra sector
    assert_eq!(read_compressed_cluster(&img, e, 9).unwrap(), vec![b'A'; 512]);
    // Same stream decoded as a 1 KiB cluster: too short.
    let e10 = (1u64 << 62) | (1 << 60) | 300;
    assert_eq!(read_compressed_cluster(&img, e10, 10), Err(Qcow2CompError::SizeMismatch));
    // Range end clamped to the image: still decodes when the image ends right after the stream.
    let short = img[..300 + 5 + 512].to_vec();
    let big = (1u64 << 62) | (1 << 61) | 300;
    assert_eq!(read_compressed_cluster(&short, big, 9).unwrap().len(), 512);
    // Non-final stored block of 512 + final stored block of 1: inflates past cluster_size.
    let mut over = vec![0x00, 0x00, 0x02, 0xff, 0xfd];
    over.extend([b'B'; 512]);
    over.extend([0x01, 0x01, 0x00, 0xfe, 0xff, b'C']);
    assert_eq!(read_compressed_cluster(&over, (1u64 << 62) | (1 << 61), 9), Err(Qcow2CompError::SizeMismatch));
}

#[test]
fn bad_inputs() {
    let img = decode_gzip(C4K, 1 << 20, 1 << 16).unwrap();
    let (cb, ents) = l2_entries(&img);
    let e = ents[1];
    // Offset past the end.
    assert_eq!(read_compressed_cluster(&img[..0x5000], ents[0], cb), Err(Qcow2CompError::OutOfRange));
    // Stream cut short.
    let off = (e & ((1 << 58) - 1)) as usize;
    assert_eq!(read_compressed_cluster(&img[..off + 20], e, cb), Err(Qcow2CompError::Corrupt));
    // Garbage instead of deflate data (block type 3 is invalid).
    let mut bad = img.clone();
    bad[off] = 0x07;
    assert_eq!(read_compressed_cluster(&bad, e, cb), Err(Qcow2CompError::Corrupt));
    assert_eq!(read_compressed_cluster(&[], 1 << 62, 12), Err(Qcow2CompError::OutOfRange));
}
