// SPDX-License-Identifier: MIT OR Apache-2.0
#[path = "create_common/mod.rs"]
mod common;

use sediment_engine::fs_collect::{ArchiveEntry, EntryKind};
use sediment_engine::tar_create::*;
use sediment_engine::ustar_header::{TarKind, parse_header};

fn spec<'a>(name: &'a [u8], kind: EntryKind, size: u64, mtime: i64, link: &'a [u8]) -> TarHeaderSpec<'a> {
    TarHeaderSpec { name, kind, size, mtime, mode: 0o644, link_target: link }
}

fn pax_records(out: &[u8]) -> String {
    assert_eq!(out[156], b'x');
    let size = usize::from_str_radix(std::str::from_utf8(&out[124..135]).unwrap(), 8).unwrap();
    String::from_utf8_lossy(&out[512..512 + size]).into_owned()
}

#[test]
fn plain_headers_parse_with_existing_reader() {
    let mut out = Vec::new();
    encode_headers(&spec(b"dir", EntryKind::Directory, 0, 5, &[]), &mut out).unwrap();
    encode_headers(&spec(b"dir/f.txt", EntryKind::File, 1234, 5, &[]), &mut out).unwrap();
    assert_eq!(out.len(), 1024);
    let d = parse_header(&out[..512]).unwrap().unwrap();
    assert_eq!((d.name, d.kind), (&b"dir/"[..], TarKind::Directory));
    let f = parse_header(&out[512..]).unwrap().unwrap();
    assert_eq!((f.name, f.size, f.kind), (&b"dir/f.txt"[..], 1234, TarKind::File));
}

#[test]
fn prefix_split_and_pax_path() {
    let name = format!("{}/{}", "p".repeat(150), "n".repeat(99));
    let mut out = Vec::new();
    encode_headers(&spec(name.as_bytes(), EntryKind::File, 0, 0, &[]), &mut out).unwrap();
    assert_eq!(out.len(), 512, "fits ustar prefix/name split");
    let h = parse_header(&out).unwrap().unwrap();
    assert_eq!(h.prefix, "p".repeat(150).as_bytes());
    assert_eq!(h.name, "n".repeat(99).as_bytes());

    for long in ["c".repeat(101), format!("{}/{}", "p".repeat(156), "n"), "a/".repeat(130) + "z"] {
        let mut out = Vec::new();
        encode_headers(&spec(long.as_bytes(), EntryKind::File, 0, 0, &[]), &mut out).unwrap();
        assert!(pax_records(&out).contains(&format!(" path={long}\n")));
        assert_eq!(out.len() % 512, 0);
    }
}

#[test]
fn pax_for_size_mtime_and_linkpath() {
    let mut out = Vec::new();
    encode_headers(&spec(b"huge", EntryKind::File, 1 << 33, 1 << 34, &[]), &mut out).unwrap();
    let r = pax_records(&out);
    assert!(r.contains(" size=8589934592\n"), "{r}");
    assert!(r.contains(" mtime=17179869184\n"), "{r}");
    let mut out = Vec::new();
    encode_headers(&spec(b"old", EntryKind::File, 0, -86400, &[]), &mut out).unwrap();
    assert!(pax_records(&out).contains(" mtime=-86400\n"));
    let target = "t/".repeat(60);
    let mut out = Vec::new();
    encode_headers(&spec(b"l", EntryKind::Symlink, 0, 0, target.as_bytes()), &mut out).unwrap();
    assert!(pax_records(&out).contains(&format!(" linkpath={target}\n")));
    // Boundary: exactly 8 GiB - 1 still fits ustar.
    let mut out = Vec::new();
    encode_headers(&spec(b"edge", EntryKind::File, (1 << 33) - 1, 0o777_7777_7777, &[]), &mut out).unwrap();
    assert_eq!(out.len(), 512);
}

#[test]
fn rejects_invalid_entries() {
    let mut out = Vec::new();
    for n in [&b""[..], b"/a", b"a/../b", b"a\0"] {
        assert_eq!(encode_headers(&spec(n, EntryKind::File, 0, 0, &[]), &mut out), Err(TarCreateError::InvalidName));
    }
    assert_eq!(encode_headers(&spec(b"d", EntryKind::Directory, 1, 0, &[]), &mut out), Err(TarCreateError::InvalidEntry));
    assert_eq!(encode_headers(&spec(b"l", EntryKind::Symlink, 0, 0, &[]), &mut out), Err(TarCreateError::InvalidEntry));
    assert_eq!(encode_headers(&spec(b"f", EntryKind::File, 0, 0, b"x"), &mut out), Err(TarCreateError::InvalidEntry));
    assert_eq!(encode_headers(&spec(b"l", EntryKind::Symlink, 0, 0, b"a\0"), &mut out), Err(TarCreateError::InvalidEntry));
    assert!(out.is_empty());
}

#[test]
fn archive_layout_limits_and_determinism() {
    let e = |name: &'static [u8], data: &'static [u8]| ArchiveEntry { name, kind: EntryKind::File, data, mtime: 1, mode: 0o600, link_target: &[] };
    let entries = [e(b"a", b""), e(b"b", &[7; 513]), e(b"c", b"hi")];
    let t = create_tar(&entries, TarCreateLimits::default()).unwrap();
    assert_eq!(t.len(), 10240);
    assert_eq!(t, create_tar(&entries, TarCreateLimits::default()).unwrap());
    let items = common::read_tar(&t);
    assert_eq!(items.len(), 3);
    assert_eq!(items[1].data, vec![7; 513]);
    assert_eq!(items[0].mode, 0o600);
    assert_eq!(create_tar(&[], TarCreateLimits::default()).unwrap(), vec![0; 10240]);
    let lim = |a, b, c| TarCreateLimits { max_entries: a, max_total_input: b, max_archive_bytes: c };
    assert_eq!(create_tar(&entries, lim(2, 1 << 20, 1 << 20)), Err(TarCreateError::LimitExceeded));
    assert_eq!(create_tar(&entries, lim(9, 514, 1 << 20)), Err(TarCreateError::LimitExceeded));
    assert_eq!(create_tar(&entries, lim(9, 1 << 20, 4096)), Err(TarCreateError::LimitExceeded));
    let bad = [ArchiveEntry { name: b"d", kind: EntryKind::Directory, data: b"x", mtime: 0, mode: 0, link_target: &[] }];
    assert_eq!(create_tar(&bad, TarCreateLimits::default()), Err(TarCreateError::InvalidEntry));
}
