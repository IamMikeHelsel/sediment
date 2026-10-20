use sediment_engine::rpm_header::{RpmError, RpmLimits, parse_header, parse_lead, parse_rpm};

const RPM: &[u8] = include_bytes!("rpm_header_fixtures/hello.rpm");
const MAIN: usize = 168; // 96 lead + 68 signature header + 4 padding
const PAYLOAD: usize = 522;

fn be32(b: &[u8], at: usize) -> usize {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize
}

/// Position of the 16-byte index entry for `tag` in the header starting at `hdr`.
fn entry_pos(b: &[u8], hdr: usize, tag: u32) -> usize {
    let n = be32(b, hdr + 8);
    (0..n).map(|i| hdr + 16 + 16 * i).find(|&p| be32(b, p) == tag as usize).unwrap()
}

/// Absolute position of `tag`'s data in the store of the header starting at `hdr`.
fn data_pos(b: &[u8], hdr: usize, tag: u32) -> usize {
    hdr + 16 + 16 * be32(b, hdr + 8) + be32(b, entry_pos(b, hdr, tag) + 8)
}

fn raw_header(entries: &[(u32, u32, u32, u32)], store: &[u8]) -> Vec<u8> {
    let mut v = vec![0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
    v.extend((entries.len() as u32).to_be_bytes());
    v.extend((store.len() as u32).to_be_bytes());
    for &(t, k, o, c) in entries {
        for x in [t, k, o, c] {
            v.extend(x.to_be_bytes());
        }
    }
    v.extend(store);
    v
}

#[test]
fn lead_fields() {
    let l = parse_lead(RPM).unwrap();
    assert_eq!((l.major, l.minor, l.kind, l.arch_num), (3, 0, 0, 1));
    assert_eq!(l.name, "hello-2.10-3.fc40");
    assert_eq!((l.os_num, l.signature_type), (1, 5));
    assert_eq!(parse_lead(&RPM[..95]), Err(RpmError::Truncated));
}

#[test]
fn package_summary() {
    let p = parse_rpm(RPM, &RpmLimits::default()).unwrap();
    assert_eq!(p.lead.name, "hello-2.10-3.fc40");
    assert_eq!((p.name.as_str(), p.version.as_str(), p.release.as_str()), ("hello", "2.10", "3.fc40"));
    assert_eq!(p.arch.as_deref(), Some("x86_64"));
    assert_eq!(p.payload_format.as_deref(), Some("cpio"));
    assert_eq!(p.payload_compressor.as_deref(), Some("gzip"));
    assert_eq!(p.files, vec!["/usr/bin/hello", "/usr/share/doc/hello/hello.1.gz", "/usr/share/doc/hello/README"]);
    assert_eq!(p.payload_offset, PAYLOAD as u64);
    assert_eq!(&RPM[PAYLOAD..PAYLOAD + 2], &[0x1f, 0x8b]);
    assert_eq!(p.signature.entries.len(), 2);
    assert_eq!(p.header.entries.len(), 12);
    assert_eq!(p.header.store.len(), 354 - 16 - 12 * 16);
}

#[test]
fn header_accessors() {
    let lim = RpmLimits::default();
    let (sig, used) = parse_header(&RPM[96..], &lim).unwrap();
    assert_eq!(used, 68);
    assert_eq!(sig.get_u32_array(1000), Ok(Some(vec![(354 + 40) as u32])));
    let md5 = sig.find(1004).unwrap();
    assert_eq!((md5.tag, md5.kind, md5.count), (1004, 7, 16));
    let (h, used) = parse_header(&RPM[MAIN..], &lim).unwrap();
    assert_eq!(used, 354);
    assert_eq!(h.entries[0].tag, 1000);
    assert_eq!(h.entries[0].kind, 6);
    assert_eq!(h.get_string(1004), Ok(Some("Prints a familiar greeting".to_string())));
    assert_eq!(h.get_u32_array(1009), Ok(Some(vec![41234])));
    assert_eq!(h.get_u32_array(1116), Ok(Some(vec![0, 1, 1])));
    assert_eq!(h.get_string_array(1118), Ok(Some(vec!["/usr/bin/".to_string(), "/usr/share/doc/hello/".to_string()])));
    assert_eq!(h.get_string(4242), Ok(None));
    assert_eq!(h.get_string_array(4242), Ok(None));
    assert_eq!(h.get_u32_array(4242), Ok(None));
    assert!(h.find(4242).is_none());
    assert_eq!(h.get_string(1009), Err(RpmError::BadEntry));
    assert_eq!(h.get_u32_array(1000), Err(RpmError::BadEntry));
    assert_eq!(h.get_string_array(1000), Err(RpmError::BadEntry));
}

#[test]
fn hostile_store_entries() {
    let lim = RpmLimits::default();
    let parse = |v: &[u8]| parse_header(v, &lim).unwrap().0;
    assert_eq!(parse(&raw_header(&[(1000, 6, 0, 1)], b"abc")).get_string(1000), Err(RpmError::BadString));
    assert_eq!(parse(&raw_header(&[(1000, 6, 0, 1)], &[0xff, 0])).get_string(1000), Err(RpmError::BadString));
    assert_eq!(parse(&raw_header(&[(1000, 6, 3, 1)], b"ab\0")).get_string(1000), Err(RpmError::BadEntry));
    assert_eq!(parse(&raw_header(&[(1000, 6, u32::MAX, 1)], b"ab\0")).get_string(1000), Err(RpmError::BadEntry));
    assert_eq!(parse(&raw_header(&[(1000, 6, 1, 1)], b"ab\0")).get_string(1000), Ok(Some("b".to_string())));
    let h = parse(&raw_header(&[(1, 8, 0, 3)], b"a\0b\0"));
    assert_eq!(h.get_string_array(1), Err(RpmError::BadString));
    let h = parse(&raw_header(&[(1, 8, 0, 0)], b""));
    assert_eq!(h.get_string_array(1), Ok(Some(vec![])));
    let h = parse(&raw_header(&[(1, 8, 0, u32::MAX)], b"a\0"));
    assert_eq!(h.get_string_array(1), Err(RpmError::BadString));
    let h = parse(&raw_header(&[(1, 4, 0, 0x4000_0001)], &[0; 8]));
    assert_eq!(h.get_u32_array(1), Err(RpmError::BadEntry));
    let h = parse(&raw_header(&[(1, 4, 6, 1)], &[0; 8]));
    assert_eq!(h.get_u32_array(1), Err(RpmError::BadEntry));
    let h = parse(&raw_header(&[(1, 4, 4, 1)], &[0, 0, 0, 0, 0, 0, 1, 2]));
    assert_eq!(h.get_u32_array(1), Ok(Some(vec![0x0102])));
    assert_eq!(parse_header(&raw_header(&[], b"")[..15], &lim).err(), Some(RpmError::Truncated));
    assert_eq!(parse_header(&raw_header(&[(1, 4, 0, 1)], &[0; 4])[..35], &lim).err(), Some(RpmError::Truncated));
    let mut big = raw_header(&[], b"");
    big[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    big[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    let huge = RpmLimits { max_index_entries: u32::MAX, max_store_bytes: u32::MAX, max_files: 10 };
    assert_eq!(parse_header(&big, &huge).err(), Some(RpmError::Truncated));
}

#[test]
fn malformed_packages() {
    let lim = RpmLimits::default();
    let mut b = RPM.to_vec();
    b[0] = 0xee;
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::BadLeadMagic));
    let mut b = RPM.to_vec();
    b[79] = 1;
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::UnsupportedSignatureType));
    let mut b = RPM.to_vec();
    b[97] = 0;
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::BadHeaderMagic));
    let mut b = RPM.to_vec();
    b[MAIN + 3] = 2;
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::BadHeaderMagic));
    let mut b = RPM.to_vec();
    let p = entry_pos(&b, MAIN, 1000);
    b[p..p + 4].copy_from_slice(&1999u32.to_be_bytes());
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::MissingTag));
    let mut b = RPM.to_vec();
    let p = entry_pos(&b, MAIN, 1001);
    b[p + 8..p + 12].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::BadEntry));
    let mut b = RPM.to_vec();
    let p = entry_pos(&b, MAIN, 1118);
    b[p..p + 4].copy_from_slice(&1999u32.to_be_bytes());
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::BadFileList));
    let mut b = RPM.to_vec();
    let d = data_pos(&b, MAIN, 1116);
    b[d + 8..d + 12].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::BadFileList));
    let mut b = RPM.to_vec();
    let p = entry_pos(&b, MAIN, 1116);
    b[p + 12..p + 16].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(parse_rpm(&b, &lim).err(), Some(RpmError::BadFileList));
}

#[test]
fn optional_tags_and_limits() {
    let lim = RpmLimits::default();
    let mut b = RPM.to_vec();
    for tag in [1022u32, 1124, 1125, 1117] {
        let p = entry_pos(&b, MAIN, tag);
        b[p..p + 4].copy_from_slice(&(tag + 5000).to_be_bytes());
    }
    let p = parse_rpm(&b, &lim).unwrap();
    assert_eq!((p.arch, p.payload_format, p.payload_compressor), (None, None, None));
    assert!(p.files.is_empty());
    let l = |e: u32, s: u32, f: usize| RpmLimits { max_index_entries: e, max_store_bytes: s, max_files: f };
    assert!(parse_rpm(RPM, &l(12, 354, 3)).is_ok());
    assert_eq!(parse_rpm(RPM, &l(11, 1 << 20, 100)).err(), Some(RpmError::LimitExceeded));
    assert_eq!(parse_rpm(RPM, &l(100, 145, 100)).err(), Some(RpmError::LimitExceeded));
    assert_eq!(parse_rpm(RPM, &l(100, 1 << 20, 2)).err(), Some(RpmError::LimitExceeded));
    let d = RpmLimits::default();
    assert_eq!((d.max_index_entries, d.max_store_bytes, d.max_files), (4096, 16 << 20, 65536));
}

#[test]
fn truncation_is_an_error_not_a_panic() {
    let lim = RpmLimits::default();
    for n in 0..PAYLOAD {
        assert!(parse_rpm(&RPM[..n], &lim).is_err(), "len {n}");
    }
    assert_eq!(parse_rpm(&RPM[..PAYLOAD], &lim).unwrap().payload_offset, PAYLOAD as u64);
}
