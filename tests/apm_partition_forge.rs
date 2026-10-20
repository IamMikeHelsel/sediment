use sediment_engine::apm_partition::{ApmDriver, ApmError, is_apm, read_apm};

// Heads of hdiutil-created 2 MiB images (gen/apm_partition.py); expectations match `hdiutil pmap`.
const HD: &[u8] = include_bytes!("apm_partition_fixtures/hd.head");
const CD: &[u8] = include_bytes!("apm_partition_fixtures/cd.head");

fn disk(head: &[u8]) -> Vec<u8> {
    let mut d = head.to_vec();
    d.resize(2 << 20, 0);
    d
}

#[test]
fn hard_disk_layout() {
    let d = disk(HD);
    assert!(is_apm(&d));
    let m = read_apm(&d, 64).unwrap();
    assert_eq!((m.block_size, m.block_count, m.sector_size), (512, 4096, 512));
    assert!(m.drivers.is_empty());
    assert_eq!(m.partitions.len(), 2);
    let p = &m.partitions[0];
    assert_eq!((p.index, p.map_entries, p.start_block, p.block_count), (1, 2, 1, 63));
    assert_eq!((p.name.as_str(), p.kind.as_str()), ("Apple", "Apple_partition_map"));
    assert_eq!((p.data_start, p.data_count, p.status), (0, 63, 3));
    let p = &m.partitions[1];
    assert_eq!((p.index, p.start_block, p.block_count), (2, 64, 4032));
    assert_eq!((p.name.as_str(), p.kind.as_str()), ("disk image", "Apple_HFS"));
    assert_eq!((p.data_start, p.data_count, p.status), (0, 4032, 0x4000_0033));
    assert_eq!((p.byte_offset, p.byte_len), (32768, 4032 * 512));
}

#[test]
fn cd_layout_prefers_512_map() {
    let d = disk(CD);
    let m = read_apm(&d, 64).unwrap();
    assert_eq!((m.block_size, m.block_count, m.sector_size), (2048, 1024, 512));
    let kinds: Vec<&str> = m.partitions.iter().map(|p| p.kind.as_str()).collect();
    assert_eq!(kinds, ["Apple_partition_map", "Apple_HFS"]);
    assert_eq!((m.partitions[1].byte_offset, m.partitions[1].byte_len), (32768, 4032 * 512));
}

#[test]
fn cd_layout_2048_map_only() {
    let mut d = disk(CD);
    d[512..2048].fill(0);
    assert!(!is_apm(&d));
    let m = read_apm(&d, 64).unwrap();
    assert_eq!(m.sector_size, 2048);
    assert_eq!(m.partitions.len(), 1);
    let p = &m.partitions[0];
    assert_eq!((p.start_block, p.block_count, p.kind.as_str()), (1, 15, "Apple_partition_map"));
    assert_eq!((p.byte_offset, p.byte_len), (2048, 15 * 2048));
}

#[test]
fn drivers_and_latin1_names() {
    let mut d = disk(HD);
    d[16..18].copy_from_slice(&2u16.to_be_bytes());
    d[18..26].copy_from_slice(&[0, 0, 0, 64, 0, 32, 0, 1]);
    d[26..34].copy_from_slice(&[0, 0, 0, 96, 0, 8, 0x70, 0x1F]);
    d[1024 + 16..1024 + 22].copy_from_slice(b"Caf\xe9!\0");
    let m = read_apm(&d, 64).unwrap();
    assert_eq!(m.drivers, vec![ApmDriver { block: 64, size: 32, kind: 1 }, ApmDriver { block: 96, size: 8, kind: 0x701F }]);
    assert_eq!(m.partitions[1].name, "Caf\u{e9}!");
}

#[test]
fn full_width_name_without_nul() {
    let mut d = disk(HD);
    d[1024 + 48..1024 + 80].copy_from_slice(&[b'X'; 32]);
    assert_eq!(read_apm(&d, 64).unwrap().partitions[1].kind, "X".repeat(32));
}

#[test]
fn limits() {
    let d = disk(HD);
    assert_eq!(read_apm(&d, 1), Err(ApmError::TooManyPartitions));
    assert_eq!(read_apm(&d, 2).unwrap().partitions.len(), 2);
    let mut big = disk(HD);
    big[512 + 4..512 + 8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(read_apm(&big, usize::MAX), Err(ApmError::Truncated));
}

#[test]
fn errors() {
    assert_eq!(read_apm(&HD[..511], 8), Err(ApmError::Truncated));
    assert_eq!(read_apm(&HD[..1000], 8), Err(ApmError::Truncated));
    assert_eq!(read_apm(&HD[..1500], 8), Err(ApmError::Truncated));
    let patch = |off: usize, v: &[u8]| {
        let mut d = disk(HD);
        d[off..off + v.len()].copy_from_slice(v);
        read_apm(&d, 8)
    };
    assert_eq!(patch(0, b"EX"), Err(ApmError::BadSignature));
    assert_eq!(patch(2, &[0x03, 0x00]), Err(ApmError::BadBlockSize));
    assert_eq!(patch(1024, b"QM"), Err(ApmError::BadSignature));
    assert_eq!(patch(1024 + 4, &3u32.to_be_bytes()), Err(ApmError::BadEntry));
    assert_eq!(patch(512 + 4, &0u32.to_be_bytes()), Err(ApmError::BadEntry));
    assert_eq!(patch(16, &62u16.to_be_bytes()), Err(ApmError::BadEntry));
    assert_eq!(patch(512 + 4, &3u32.to_be_bytes()), Err(ApmError::BadEntry));
    let mut cd = disk(CD);
    cd[512..2048].fill(0);
    cd[2048..2050].copy_from_slice(b"XX");
    assert_eq!(read_apm(&cd, 8), Err(ApmError::BadSignature));
}
