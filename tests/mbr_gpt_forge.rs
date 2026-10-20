use sediment_engine::crc32::crc32;
use sediment_engine::mbr_gpt::{GptPartition, MbrPartition, PartError, read_gpt, read_mbr};

// Built with Python struct/zlib.crc32 and checked with util-linux sfdisk (see gen_fixtures.py).
const MBR: &[u8] = include_bytes!("mbr_gpt_fixtures/mbr.img"); // 9 sectors, EBRs at LBA 1,3,5,7
const GPT512: &[u8] = include_bytes!("mbr_gpt_fixtures/gpt512.img"); // LBA 0..2 of a 64-sector disk
const GPT4K: &[u8] = include_bytes!("mbr_gpt_fixtures/gpt4k.img"); // LBA 0..2, 4096-byte sectors

const ESP: [u8; 16] = [0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b];
const LINUX: [u8; 16] = [0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4];
const DISK: [u8; 16] = [0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];

fn p(number: u32, kind: u8, bootable: bool, logical: bool, first_lba: u64, sector_count: u64) -> MbrPartition {
    MbrPartition { number, kind, bootable, logical, first_lba, sector_count }
}
fn guid_int(n: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[15] = n;
    g
}

#[test]
fn mbr_with_extended_chain() {
    let v = read_mbr(MBR, 64).unwrap();
    assert_eq!(
        v,
        vec![
            p(1, 0x83, true, false, 2048, 4096),
            p(3, 0x0f, false, false, 1, 100),
            p(4, 0x07, false, false, 10000, 50),
            p(5, 0x83, false, true, 2, 1),
            p(6, 0x07, true, true, 4, 1),
            p(7, 0x0c, false, true, 8, 1),
        ]
    );
}

#[test]
fn protective_mbr_is_a_normal_entry() {
    assert_eq!(read_mbr(GPT512, 8).unwrap(), vec![p(1, 0xee, false, false, 1, 63)]);
}

#[test]
fn mbr_basic_errors() {
    assert_eq!(read_mbr(&MBR[..511], 64), Err(PartError::Truncated));
    let mut m = MBR.to_vec();
    m[511] = 0;
    assert_eq!(read_mbr(&m, 64), Err(PartError::BadSignature));
    let mut s = MBR.to_vec();
    s[446] = 0x01; // status of slot 1
    assert_eq!(read_mbr(&s, 64), Err(PartError::BadEntry));
    let mut e = MBR.to_vec();
    e[462] = 0x33; // garbage status on the EMPTY slot 2 is ignored
    assert_eq!(read_mbr(&e, 64).unwrap().len(), 6);
}

#[test]
fn ebr_errors() {
    assert_eq!(read_mbr(&MBR[..3 * 512 + 100], 64), Err(PartError::Truncated));
    let mut m = MBR.to_vec();
    m[5 * 512 + 510] = 0; // EBR at LBA 5
    assert_eq!(read_mbr(&m, 64), Err(PartError::BadSignature));
    let mut k = MBR.to_vec();
    k[3 * 512 + 462 + 4] = 0x83; // next-EBR link with a non-extended kind
    assert_eq!(read_mbr(&k, 64), Err(PartError::BadEntry));
    let mut st = MBR.to_vec();
    st[3 * 512 + 446] = 0x7f; // bad status on a logical entry
    assert_eq!(read_mbr(&st, 64), Err(PartError::BadEntry));
}

#[test]
fn ebr_loop_is_bounded() {
    // EBR at LBA 7 links back to E + 0 = LBA 1: an endless cycle 1,3,5,7,1,...
    let mut m = MBR.to_vec();
    m[7 * 512 + 462 + 4] = 0x05;
    assert_eq!(read_mbr(&m, 1000), Err(PartError::ChainTooLong));
    assert_eq!(read_mbr(&m, 50), Err(PartError::TooManyPartitions));
}

#[test]
fn mbr_partition_limit() {
    assert_eq!(read_mbr(MBR, 5), Err(PartError::TooManyPartitions));
    assert_eq!(read_mbr(MBR, 6).unwrap().len(), 6);
    assert_eq!(read_mbr(MBR, 2), Err(PartError::TooManyPartitions));
}

#[test]
fn gpt_512() {
    let t = read_gpt(GPT512, 512, 128).unwrap();
    assert_eq!((t.disk_guid, t.first_usable_lba, t.last_usable_lba), (DISK, 3, 61));
    assert_eq!(
        t.partitions,
        vec![
            GptPartition {
                index: 1, type_guid: ESP, unique_guid: guid_int(1), first_lba: 3, last_lba: 20,
                attributes: 1, name: "EFI system".to_string(),
            },
            GptPartition {
                index: 3, type_guid: LINUX, unique_guid: guid_int(2), first_lba: 21, last_lba: 60,
                attributes: 1 << 60, name: "données".to_string(),
            },
        ]
    );
}

#[test]
fn gpt_4096() {
    let t = read_gpt(GPT4K, 4096, 128).unwrap();
    assert_eq!((t.first_usable_lba, t.last_usable_lba), (3, 5));
    assert_eq!(t.partitions.len(), 1);
    assert_eq!((t.partitions[0].index, t.partitions[0].type_guid), (1, LINUX));
    assert_eq!((t.partitions[0].first_lba, t.partitions[0].last_lba), (3, 5));
    assert_eq!(t.partitions[0].name, "x");
    assert_eq!(t.partitions[0].unique_guid, guid_int(3));
}

#[test]
fn gpt_sector_size_and_signature() {
    assert_eq!(read_gpt(GPT512, 1024, 8), Err(PartError::BadSectorSize));
    assert_eq!(read_gpt(GPT512, 0, 8), Err(PartError::BadSectorSize));
    assert_eq!(read_gpt(&GPT512[..1023], 512, 8), Err(PartError::Truncated));
    assert_eq!(read_gpt(GPT512, 4096, 8), Err(PartError::Truncated));
    assert_eq!(read_gpt(GPT4K, 512, 8), Err(PartError::BadSignature));
    assert_eq!(read_gpt(MBR, 512, 8), Err(PartError::BadSignature));
}

fn fix_header_crc(v: &mut [u8], ss: usize) {
    let hs = u32::from_le_bytes(v[ss + 12..ss + 16].try_into().unwrap()) as usize;
    v[ss + 16..ss + 20].fill(0);
    let c = crc32(&v[ss..ss + hs]);
    v[ss + 16..ss + 20].copy_from_slice(&c.to_le_bytes());
}
fn fix_entries_crc(v: &mut [u8]) {
    // gpt512: 4 entries of 128 bytes at LBA 2
    let c = crc32(&v[1024..1024 + 512]);
    v[512 + 88..512 + 92].copy_from_slice(&c.to_le_bytes());
    fix_header_crc(v, 512);
}

#[test]
fn gpt_header_crc_and_fields() {
    let mut a = GPT512.to_vec();
    a[512 + 60] ^= 1; // disk guid byte
    assert_eq!(read_gpt(&a, 512, 8), Err(PartError::BadHeaderCrc));
    let mut b = GPT512.to_vec();
    b[512 + 12] = 91; // header_size 91
    assert_eq!(read_gpt(&b, 512, 8), Err(PartError::BadGptHeader));
    let mut c = GPT512.to_vec();
    c[512 + 12..512 + 16].copy_from_slice(&513u32.to_le_bytes());
    assert_eq!(read_gpt(&c, 512, 8), Err(PartError::BadGptHeader));
    let mut d = GPT512.to_vec();
    d[512 + 24] = 2; // my_lba
    fix_header_crc(&mut d, 512);
    assert_eq!(read_gpt(&d, 512, 8), Err(PartError::BadGptHeader));
    let mut e = GPT512.to_vec();
    e[512 + 84..512 + 88].copy_from_slice(&100u32.to_le_bytes()); // entry_size
    fix_header_crc(&mut e, 512);
    assert_eq!(read_gpt(&e, 512, 8), Err(PartError::BadGptHeader));
    let mut f = GPT512.to_vec();
    f[512 + 84..512 + 88].copy_from_slice(&132u32.to_le_bytes()); // not a multiple of 8
    fix_header_crc(&mut f, 512);
    assert_eq!(read_gpt(&f, 512, 8), Err(PartError::BadGptHeader));
}

#[test]
fn gpt_entry_array_bounds() {
    let mut a = GPT512.to_vec();
    a[512 + 80..512 + 84].copy_from_slice(&u32::MAX.to_le_bytes());
    fix_header_crc(&mut a, 512);
    assert_eq!(read_gpt(&a, 512, 8), Err(PartError::Truncated));
    let mut b = GPT512.to_vec();
    b[512 + 72..512 + 80].copy_from_slice(&u64::MAX.to_le_bytes());
    fix_header_crc(&mut b, 512);
    assert_eq!(read_gpt(&b, 512, 8), Err(PartError::Truncated));
    assert_eq!(read_gpt(&GPT512[..1535], 512, 8), Err(PartError::Truncated));
}

#[test]
fn gpt_entries_crc_and_entry_errors() {
    let mut a = GPT512.to_vec();
    a[1024 + 60] ^= 0x40; // name byte of entry 1
    assert_eq!(read_gpt(&a, 512, 8), Err(PartError::BadEntriesCrc));
    let mut b = GPT512.to_vec();
    b[1024 + 40..1024 + 48].copy_from_slice(&2u64.to_le_bytes()); // last_lba 2 < first_lba 3
    fix_entries_crc(&mut b);
    assert_eq!(read_gpt(&b, 512, 8), Err(PartError::BadEntry));
    // an unused slot (zero type GUID) may hold anything
    let mut c = GPT512.to_vec();
    c[1024 + 128 + 32] = 0xff;
    c[1024 + 128 + 56] = 0xff;
    fix_entries_crc(&mut c);
    assert_eq!(read_gpt(&c, 512, 8).unwrap().partitions.len(), 2);
}

#[test]
fn gpt_name_lossy_and_limit() {
    let mut a = GPT512.to_vec();
    a[1024 + 56..1024 + 58].copy_from_slice(&0xd800u16.to_le_bytes()); // lone surrogate
    fix_entries_crc(&mut a);
    assert_eq!(read_gpt(&a, 512, 8).unwrap().partitions[0].name, "\u{fffd}FI system");
    assert_eq!(read_gpt(GPT512, 512, 1), Err(PartError::TooManyPartitions));
    assert_eq!(read_gpt(GPT512, 512, 2).unwrap().partitions.len(), 2);
}
