// SPDX-License-Identifier: MIT OR Apache-2.0
use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::zip_create::*;
use sediment_engine::zip_decode::entry_data;
use sediment_engine::zip_index::{ZipLimits, parse_entries};

fn file<'a>(name: &'a [u8], data: &'a [u8]) -> ArchiveEntry<'a> {
    ArchiveEntry { name, kind: EntryKind::File, data, mtime: 1_600_000_000, mode: 0o644, link_target: &[] }
}

const L: ZipLimits = ZipLimits { max_entries: 100_000, max_total_size: 1 << 26 };

#[test]
fn dos_time_conversion_and_clamping() {
    // 2020-09-13T12:26:40Z
    let (t, d) = dos_time_from_unix(1_600_000_000);
    assert_eq!(d, ((2020 - 1980) << 9) | (9 << 5) | 13);
    assert_eq!(t, (12 << 11) | (26 << 5) | 20);
    // odd seconds round down
    assert_eq!(dos_time_from_unix(1_600_000_001), dos_time_from_unix(1_600_000_000));
    // clamps
    assert_eq!(dos_time_from_unix(0), (0, (1 << 5) | 1));
    assert_eq!(dos_time_from_unix(i64::MIN), (0, (1 << 5) | 1));
    let (t, d) = dos_time_from_unix(i64::MAX);
    assert_eq!(d, (127 << 9) | (12 << 5) | 31);
    assert_eq!(t, (23 << 11) | (59 << 5) | 29);
    // leap day
    let (_, d) = dos_time_from_unix(951_782_400); // 2000-02-29
    assert_eq!(d, (20 << 9) | (2 << 5) | 29);
}

#[test]
fn empty_archive_is_valid() {
    let z = create_zip(&[], ZipCreateOptions { level: 6 }, ZipCreateLimits::default()).unwrap();
    assert_eq!(z.bytes.len(), 22);
    assert!(parse_entries(&z.bytes, L).unwrap().is_empty());
}

#[test]
fn chooses_stored_when_deflate_does_not_shrink() {
    let mut x = 1u32;
    let rnd: Vec<u8> = (0..3000)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect();
    let txt = b"hello hello hello hello hello hello hello hello".repeat(20);
    let e = [file(b"r", &rnd), file(b"t", &txt), file(b"z", b""), file(b"one", b"x")];
    let z = create_zip(&e, ZipCreateOptions { level: 9 }, ZipCreateLimits::default()).unwrap();
    assert_eq!(z.methods, vec![0, 8, 0, 0]);
    let parsed = parse_entries(&z.bytes, L).unwrap();
    for (p, e) in parsed.iter().zip(&e) {
        assert_eq!(&*entry_data(&z.bytes, p, p.size, 1000).unwrap(), e.data);
    }
}

#[test]
fn flags_attrs_and_symlinks() {
    let entries = [
        ArchiveEntry { name: b"d", kind: EntryKind::Directory, data: &[], mtime: 0, mode: 0o750, link_target: &[] },
        file("d/\u{e9}t\u{e9}.txt".as_bytes(), b"x"),
        ArchiveEntry { name: b"lnk", kind: EntryKind::Symlink, data: &[], mtime: 0, mode: 0o777, link_target: b"d" },
        file(b"plain\xff", b"y"),
    ];
    let z = create_zip(&entries, ZipCreateOptions { level: 6 }, ZipCreateLimits::default()).unwrap();
    assert_eq!(z.skipped, vec![2]);
    let b = &z.bytes;
    let parsed = parse_entries(b, L).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0].name, b"d/");
    // Inspect raw local headers: flags at +6.
    let flags = |off: usize| u16::from_le_bytes([b[off + 6], b[off + 7]]);
    assert_eq!(flags(0), 0);
    let off1 = parsed[1].data_offset - 30 - parsed[1].name.len() - 9;
    assert_eq!(flags(off1), 0x0800, "UTF-8 flag for non-ASCII UTF-8 name");
    let off2 = parsed[2].data_offset - 30 - parsed[2].name.len() - 9;
    assert_eq!(flags(off2), 0, "no UTF-8 flag for invalid UTF-8");
    // Central directory external attributes for the directory.
    let cd = b.windows(4).position(|w| w == [0x50, 0x4b, 1, 2]).unwrap();
    let ext = u32::from_le_bytes(b[cd + 38..cd + 42].try_into().unwrap());
    assert_eq!(ext >> 16, 0o040750);
    assert_eq!(ext & 0x10, 0x10);
    assert_eq!(u16::from_le_bytes([b[cd + 4], b[cd + 5]]) >> 8, 3, "made by Unix");
}

#[test]
fn rejects_bad_input() {
    let bad: [&[u8]; 7] = [b"", b"/abs", b"a//b", b"a/./b", b"../x", b"a\0b", b"a/.."];
    for n in bad {
        assert_eq!(
            create_zip(&[file(n, b"")], ZipCreateOptions { level: 0 }, ZipCreateLimits::default()).unwrap_err(),
            ZipCreateError::InvalidName,
            "{n:?}"
        );
    }
    let dir = ArchiveEntry { name: b"d", kind: EntryKind::Directory, data: b"x", mtime: 0, mode: 0, link_target: &[] };
    assert_eq!(create_zip(&[dir], ZipCreateOptions { level: 0 }, ZipCreateLimits::default()).unwrap_err(), ZipCreateError::InvalidEntry);
    assert_eq!(create_zip(&[], ZipCreateOptions { level: 10 }, ZipCreateLimits::default()).unwrap_err(), ZipCreateError::InvalidLevel);
    let big = vec![0u8; 1000];
    let e = [file(b"a", &big), file(b"b", &big)];
    let lim = |max_entries, max_total_input, max_archive_bytes| ZipCreateLimits { max_entries, max_total_input, max_archive_bytes };
    let o = ZipCreateOptions { level: 0 };
    assert_eq!(create_zip(&e, o, lim(1, 1 << 20, 1 << 20)).unwrap_err(), ZipCreateError::LimitExceeded);
    assert_eq!(create_zip(&e, o, lim(10, 1999, 1 << 20)).unwrap_err(), ZipCreateError::LimitExceeded);
    assert_eq!(create_zip(&e, o, lim(10, 1 << 20, 2000)).unwrap_err(), ZipCreateError::LimitExceeded);
    let many: Vec<_> = (0..65535).map(|_| file(b"x", b"")).collect();
    assert_eq!(create_zip(&many, o, lim(100_000, 1, usize::MAX)).unwrap_err(), ZipCreateError::Unsupported);
}

#[test]
fn many_entries_round_trip() {
    let names: Vec<String> = (0..2000).map(|i| format!("dir{}/file{i:05}.txt", i % 7)).collect();
    let datas: Vec<Vec<u8>> = (0..2000).map(|i| format!("content {i}\n").repeat(i % 50).into_bytes()).collect();
    let e: Vec<_> = names.iter().zip(&datas).map(|(n, d)| file(n.as_bytes(), d)).collect();
    let z = create_zip(&e, ZipCreateOptions { level: 5 }, ZipCreateLimits::default()).unwrap();
    let parsed = parse_entries(&z.bytes, L).unwrap();
    assert_eq!(parsed.len(), 2000);
    for (p, d) in parsed.iter().zip(&datas) {
        assert_eq!(&*entry_data(&z.bytes, p, p.size, 1000).unwrap(), d.as_slice());
    }
}
