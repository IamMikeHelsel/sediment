use sediment_engine::tar_read::{
    TarEntry, TarEntryKind, TarReadError, TarReadLimits, parse_numeric_field, read_entries,
};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tar/");

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}{name}")).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn lim() -> TarReadLimits {
    TarReadLimits::default()
}

fn kind_char(k: TarEntryKind) -> &'static str {
    match k {
        TarEntryKind::File => "f",
        TarEntryKind::Directory => "d",
        TarEntryKind::Symlink => "l",
        TarEntryKind::HardLink => "h",
        TarEntryKind::CharDevice => "c",
        TarEntryKind::BlockDevice => "b",
        TarEntryKind::Fifo => "p",
    }
}

/// Differential check against the Python tarfile manifest.
fn check_against_manifest(name: &str) -> (Vec<u8>, Vec<TarEntry>) {
    let tar = fx(&format!("{name}.tar"));
    let entries = read_entries(&tar, lim()).unwrap();
    let manifest = std::fs::read_to_string(format!("{DIR}{name}.manifest")).unwrap();
    let lines: Vec<&str> = manifest.lines().collect();
    assert_eq!(entries.len(), lines.len(), "{name}: entry count");
    for (e, line) in entries.iter().zip(&lines) {
        let c: Vec<&str> = line.split('\t').collect();
        let ctx = format!("{name}: {}", String::from_utf8_lossy(&e.path));
        assert_eq!(kind_char(e.kind), c[0], "{ctx} kind");
        assert_eq!(e.path, unhex(c[1]), "{ctx} path");
        assert_eq!(e.size, c[2].parse::<u64>().unwrap(), "{ctx} size");
        assert_eq!(e.mode, c[3].parse::<u32>().unwrap(), "{ctx} mode");
        assert_eq!(e.mtime, c[4].parse::<i64>().unwrap(), "{ctx} mtime");
        assert_eq!(e.mtime_nanos, c[5].parse::<u32>().unwrap(), "{ctx} nanos");
        assert_eq!(e.uid, c[6].parse::<u64>().unwrap(), "{ctx} uid");
        assert_eq!(e.gid, c[7].parse::<u64>().unwrap(), "{ctx} gid");
        assert_eq!(e.uname, unhex(c[8]), "{ctx} uname");
        assert_eq!(e.gname, unhex(c[9]), "{ctx} gname");
        let link = if c[10] == "-" { None } else { Some(unhex(c[10])) };
        assert_eq!(e.link_target, link, "{ctx} link");
        assert_eq!(e.dev_major, c[11].parse::<u32>().unwrap(), "{ctx} major");
        assert_eq!(e.dev_minor, c[12].parse::<u32>().unwrap(), "{ctx} minor");
        assert_eq!(e.data_range.start, c[13].parse::<usize>().unwrap(), "{ctx} offset");
        assert_eq!(e.data_range.len() as u64, e.size, "{ctx} range len");
    }
    (tar, entries)
}

fn find<'a>(entries: &'a [TarEntry], path: &[u8]) -> &'a TarEntry {
    entries.iter().find(|e| e.path == path).unwrap()
}

#[test]
fn ustar_matches_python() {
    let (tar, e) = check_against_manifest("ustar");
    assert_eq!(&tar[find(&e, b"d/hello.txt").data_range.clone()], b"hello\n");
    let split = find(&e, format!("{}/{}", "p".repeat(90), "q".repeat(59)).as_bytes());
    assert_eq!(&tar[split.data_range.clone()], b"ok");
    let big = find(&e, b"d/block-cross.bin");
    let want: Vec<u8> = (0..1000u32).map(|i| ((i * 7 + 3) % 251) as u8).collect();
    assert_eq!(&tar[big.data_range.clone()], &want[..]);
    assert_eq!(find(&e, b"d").kind, TarEntryKind::Directory);
    let uni = find(&e, "ünï/日本語.txt".as_bytes());
    assert_eq!(&tar[uni.data_range.clone()], b"uni");
}

#[test]
fn gnu_matches_python() {
    let (tar, e) = check_against_manifest("gnu");
    let long = format!("{}/{}/file.txt", "L".repeat(60), "N".repeat(120));
    assert_eq!(&tar[find(&e, long.as_bytes()).data_range.clone()], b"long");
    assert_eq!(find(&e, b"longlink").link_target.as_deref(), Some("T".repeat(150).as_bytes()));
    assert_eq!(find(&e, b"longhard").link_target.as_deref(), Some(long.as_bytes()));
    assert_eq!(find(&e, b"negmtime").mtime, -1000);
    let b = find(&e, b"bigid");
    assert_eq!((b.uid, b.gid), (8u64.pow(7) + 5, 8u64.pow(8)));
}

#[test]
fn pax_matches_python() {
    let (_, e) = check_against_manifest("pax");
    let f = find(&e, b"frac");
    assert_eq!((f.mtime, f.mtime_nanos), (1_700_000_000, 500_000_000));
    let n = find(&e, b"negfrac");
    assert_eq!((n.mtime, n.mtime_nanos), (-2, 750_000_000));
    let b = find(&e, b"bigid");
    assert_eq!(b.uname, "u".repeat(40).as_bytes());
    assert_eq!(b.gname, "ünïgrp".as_bytes());
}

#[test]
fn pax_global_header_applies() {
    let (_, e) = check_against_manifest("pax_global");
    assert_eq!(e.len(), 2);
    assert!(e.iter().all(|x| x.gname == b"globalgrp"));
}

#[test]
fn record_padding_and_hardlink_kinds() {
    let (_, e) = check_against_manifest("ustar_record");
    assert_eq!(e.len(), 1);
    let (_, g) = check_against_manifest("gnu");
    for (p, k) in [
        (&b"link"[..], TarEntryKind::Symlink),
        (b"hard", TarEntryKind::HardLink),
        (b"fifo", TarEntryKind::Fifo),
        (b"chr", TarEntryKind::CharDevice),
        (b"blk", TarEntryKind::BlockDevice),
        (b"empty", TarEntryKind::File),
    ] {
        assert_eq!(find(&g, p).kind, k);
    }
    let c = find(&g, b"chr");
    assert_eq!((c.dev_major, c.dev_minor), (4, 64));
    assert!(find(&g, b"empty").data_range.is_empty());
}

/// Byte offset just past the last entry's data block padding.
fn content_end(tar: &[u8]) -> usize {
    let e = read_entries(tar, lim()).unwrap();
    let last = e.last().unwrap();
    let end = last.data_range.end.div_ceil(512) * 512;
    end.max(last.data_range.start)
}

#[test]
fn end_marker_variants() {
    let tar = fx("ustar.tar");
    let full = read_entries(&tar, lim()).unwrap();
    let end = content_end(&tar);
    // No end-of-archive blocks at all.
    assert_eq!(read_entries(&tar[..end], lim()).unwrap(), full);
    // A single zero block.
    assert_eq!(read_entries(&tar[..end + 512], lim()).unwrap(), full);
    // Trailing partial zero block.
    assert_eq!(read_entries(&tar[..end + 100], lim()).unwrap(), full);
    // Garbage after the end marker is ignored.
    let mut g = tar[..end + 1024].to_vec();
    g.extend_from_slice(&[0xAB; 700]);
    assert_eq!(read_entries(&g, lim()).unwrap(), full);
    // Empty archive and an all-zero archive.
    assert_eq!(read_entries(&[], lim()).unwrap(), vec![]);
    assert_eq!(read_entries(&[0; 1024], lim()).unwrap(), vec![]);
}

#[test]
fn truncation_everywhere_is_an_error_or_prefix() {
    for name in ["ustar.tar", "gnu.tar", "pax.tar", "pax_global.tar"] {
        let tar = fx(name);
        let full = read_entries(&tar, lim()).unwrap();
        // Every block boundary neighbourhood plus a stride through the rest.
        let cuts = (0..tar.len()).filter(|c| matches!(c % 512, 0 | 1 | 100 | 155 | 156 | 157 | 511) || c % 37 == 0);
        for cut in cuts {
            match read_entries(&tar[..cut], lim()) {
                Ok(v) => {
                    // A clean cut can only yield a prefix of the entries.
                    assert!(v.len() <= full.len());
                    assert_eq!(&full[..v.len()], &v[..], "{name} cut {cut}");
                }
                Err(e) => assert_eq!(e, TarReadError::Truncated, "{name} cut {cut}"),
            }
        }
    }
}

#[test]
fn cut_inside_header_or_data_is_truncated() {
    let tar = fx("ustar.tar");
    assert_eq!(read_entries(&tar[..100], lim()), Err(TarReadError::Truncated));
    let e = read_entries(&tar, lim()).unwrap();
    let big = find(&e, b"d/block-cross.bin");
    assert_eq!(read_entries(&tar[..big.data_range.start + 10], lim()), Err(TarReadError::Truncated));
    // GNU long-name header followed by nothing.
    let gnu = fx("gnu.tar");
    let ge = read_entries(&gnu, lim()).unwrap();
    let long = ge.iter().find(|x| x.path.len() > 150).unwrap();
    // The L header + its one data block precede the real header.
    let l_end = long.data_range.start - 512;
    assert_eq!(read_entries(&gnu[..l_end], lim()), Err(TarReadError::Truncated));
    let mut zeroed = gnu[..l_end].to_vec();
    zeroed.extend_from_slice(&[0; 1024]);
    assert_eq!(read_entries(&zeroed, lim()), Err(TarReadError::Truncated));
}

#[test]
fn malformed_fixtures() {
    for (name, want) in [
        ("bad_checksum.tar", TarReadError::BadChecksum),
        ("negative_size.tar", TarReadError::InvalidSize),
        ("overflow_size.tar", TarReadError::NumericOverflow),
        ("bad_octal_size.tar", TarReadError::InvalidNumber),
        ("bad_pax.tar", TarReadError::InvalidPax),
        ("sparse.tar", TarReadError::UnsupportedType),
    ] {
        assert_eq!(read_entries(&fx(name), lim()), Err(want), "{name}");
    }
}

#[test]
fn v7_header_without_magic() {
    let e = read_entries(&fx("v7.tar"), lim()).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].path, b"v7.txt");
    assert_eq!(e[0].size, 3);
    assert!(e[0].uname.is_empty());
}

fn huge() -> u64 {
    std::fs::read_to_string(format!("{DIR}huge.txt")).unwrap().trim().parse().unwrap()
}

#[test]
fn base256_size_header_only() {
    let hdr = fx("gnu_huge.hdr");
    assert_eq!(hdr.len(), 512);
    assert_eq!(hdr[124], 0x80, "python wrote base-256");
    assert_eq!(parse_numeric_field(&hdr[124..136]).unwrap() as u64, huge());
    // Data is not materialized: the exact limit check proves the parsed size.
    let at = |max| read_entries(&hdr, TarReadLimits { max_total_size: max, ..lim() });
    assert_eq!(at(huge() - 1), Err(TarReadError::LimitExceeded));
    assert_eq!(at(huge()), Err(TarReadError::Truncated));
}

#[test]
fn pax_size_header_only() {
    let hdr = fx("pax_huge.hdr");
    let at = |max| read_entries(&hdr, TarReadLimits { max_total_size: max, ..lim() });
    assert_eq!(at(huge() - 1), Err(TarReadError::LimitExceeded));
    assert_eq!(at(huge()), Err(TarReadError::Truncated));
}

#[test]
fn numeric_field_forms() {
    assert_eq!(parse_numeric_field(b"0000644\0"), Ok(0o644));
    assert_eq!(parse_numeric_field(b"   644 \0"), Ok(0o644));
    assert_eq!(parse_numeric_field(b"\0\0\0\0"), Ok(0));
    assert_eq!(parse_numeric_field(b""), Ok(0));
    assert_eq!(parse_numeric_field(b"77777777777\0"), Ok(0o77777777777));
    assert_eq!(parse_numeric_field(b"0008"), Err(TarReadError::InvalidNumber));
    assert_eq!(parse_numeric_field(b"7777777777777777777777777"), Err(TarReadError::NumericOverflow));
    // Base-256 positive / negative, 8- and 12-byte fields.
    let mut f = [0u8; 12];
    f[0] = 0x80;
    f[4..].copy_from_slice(&(8u64 << 30).to_be_bytes());
    assert_eq!(parse_numeric_field(&f), Ok(8 << 30));
    let mut n = [0xffu8; 12];
    n[11] = 0xfb;
    assert_eq!(parse_numeric_field(&n), Ok(-5));
    assert_eq!(parse_numeric_field(&[0xff; 8]), Ok(-1));
    assert_eq!(parse_numeric_field(&[0x80, 0, 0, 0, 0, 0, 0, 7]), Ok(7));
    let mut ovf = [0xffu8; 12];
    ovf[0] = 0x80;
    assert_eq!(parse_numeric_field(&ovf), Err(TarReadError::NumericOverflow));
    // i64::MAX fits.
    let mut m = [0u8; 12];
    m[0] = 0x80;
    m[4..].copy_from_slice(&i64::MAX.to_be_bytes());
    assert_eq!(parse_numeric_field(&m), Ok(i64::MAX));
}

#[test]
fn limits_enforced() {
    let tar = fx("gnu.tar");
    let n = read_entries(&tar, lim()).unwrap().len();
    let l = |f: fn(&mut TarReadLimits)| {
        let mut x = lim();
        f(&mut x);
        read_entries(&tar, x)
    };
    assert_eq!(read_entries(&tar, TarReadLimits { max_entries: n, ..lim() }).unwrap().len(), n);
    assert_eq!(read_entries(&tar, TarReadLimits { max_entries: n - 1, ..lim() }), Err(TarReadError::LimitExceeded));
    assert_eq!(l(|x| x.max_name_len = 100), Err(TarReadError::LimitExceeded));
    assert_eq!(l(|x| x.max_total_size = 100), Err(TarReadError::LimitExceeded));
    assert_eq!(l(|x| x.max_meta_size = 64), Err(TarReadError::LimitExceeded));
    let pax = fx("pax.tar");
    assert_eq!(read_entries(&pax, TarReadLimits { max_name_len: 100, ..lim() }), Err(TarReadError::LimitExceeded));
}

fn with_checksum(mut b: [u8; 512]) -> [u8; 512] {
    b[148..156].copy_from_slice(b"        ");
    let s: u32 = b.iter().map(|&x| x as u32).sum();
    b[148..156].copy_from_slice(format!("{s:06o}\0 ").as_bytes());
    b
}

fn header(name: &[u8], typeflag: u8, size: u64) -> [u8; 512] {
    let mut b = [0u8; 512];
    b[..name.len()].copy_from_slice(name);
    b[100..108].copy_from_slice(b"0000644\0");
    b[108..116].copy_from_slice(b"0000000\0");
    b[116..124].copy_from_slice(b"0000000\0");
    b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    b[136..148].copy_from_slice(b"00000000000\0");
    b[156] = typeflag;
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    with_checksum(b)
}

fn pax_archive(records: &[u8]) -> Vec<u8> {
    let mut v = header(b"PaxHeader", b'x', records.len() as u64).to_vec();
    v.extend_from_slice(records);
    v.resize(v.len().div_ceil(512) * 512, 0);
    v.extend_from_slice(&header(b"real", b'0', 0));
    v.extend_from_slice(&[0; 1024]);
    v
}

#[test]
fn pax_record_edge_cases() {
    let ok = pax_archive(b"12 path=abc\n8 uid=7\n");
    let e = read_entries(&ok, lim()).unwrap();
    assert_eq!((e[0].path.as_slice(), e[0].uid), (&b"abc"[..], 7));
    // Unknown keys are skipped; empty value means "use header field".
    let e = read_entries(&pax_archive(b"8 path=\n11 foo=bar\n"), lim()).unwrap();
    assert_eq!(e[0].path, b"real");
    for bad in [
        &b"5 path=abc\n"[..],
        b"x path=abc\n",
        b"12 pathabc\n\n",
        b"13 path=abc!",
        b"99999999999999999999999 path=abc\n",
        b"11 mtime=x\n",
        b"10 uid=-1\n",
        b"12 size=1.5\n",
        b"7 =abc\n",
    ] {
        assert_eq!(read_entries(&pax_archive(bad), lim()), Err(TarReadError::InvalidPax), "{:?}", String::from_utf8_lossy(bad));
    }
    assert_eq!(
        read_entries(&pax_archive(b"22 GNU.sparse.major=1\n"), lim()),
        Err(TarReadError::UnsupportedType)
    );
    // pax header with no following entry.
    let mut dangling = header(b"PaxHeader", b'x', 0).to_vec();
    dangling.extend_from_slice(&[0; 1024]);
    assert_eq!(read_entries(&dangling, lim()), Err(TarReadError::Truncated));
}

#[test]
fn checksum_signed_and_unsigned() {
    let mut b = header(b"\xe9t\xe9", b'0', 0);
    let mut v = b.to_vec();
    v.extend_from_slice(&[0; 1024]);
    assert_eq!(read_entries(&v, lim()).unwrap()[0].path, b"\xe9t\xe9");
    // Historic signed-char checksum.
    b[148..156].copy_from_slice(b"        ");
    let s: i64 = b.iter().map(|&x| x as i8 as i64).sum();
    b[148..156].copy_from_slice(format!("{s:06o}\0 ").as_bytes());
    v[..512].copy_from_slice(&b);
    assert_eq!(read_entries(&v, lim()).unwrap().len(), 1);
    // Blank checksum field.
    b[148..156].copy_from_slice(b"        ");
    v[..512].copy_from_slice(&b);
    assert_eq!(read_entries(&v, lim()), Err(TarReadError::BadChecksum));
}

#[test]
fn empty_name_is_invalid() {
    let mut v = header(b"", b'0', 0).to_vec();
    v.extend_from_slice(&[0; 1024]);
    assert_eq!(read_entries(&v, lim()), Err(TarReadError::InvalidHeader));
}

#[test]
fn hostile_mutations_never_panic() {
    // Deterministic xorshift fuzz over real fixtures; every result must be
    // Ok or Err without panicking, and ranges must stay in bounds.
    let mut seed: u64 = 0x9e3779b97f4a7c15;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for name in ["ustar.tar", "gnu.tar", "pax.tar", "pax_global.tar"] {
        let base = fx(name);
        for _ in 0..1500 {
            let mut t = base.clone();
            let block = (rnd() as usize % (t.len() / 512)) * 512;
            for _ in 0..(1 + rnd() % 4) {
                let off = block + rnd() as usize % 512;
                t[off] = rnd() as u8;
            }
            // Re-sign half of the mutants so parsing goes past the checksum.
            if rnd() % 2 == 0 {
                let mut b = [0u8; 512];
                b.copy_from_slice(&t[block..block + 512]);
                t[block..block + 512].copy_from_slice(&with_checksum(b));
            }
            if let Ok(es) = read_entries(&t, lim()) {
                for e in es {
                    assert!(e.data_range.end <= t.len());
                }
            }
        }
    }
}
