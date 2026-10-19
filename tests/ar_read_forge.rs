use sediment_engine::ar_read::{ArEntry, ArError, read_ar};

const GNU: &[u8] = include_bytes!("ar_read_fixtures/gnu.a");
const BSD: &[u8] = include_bytes!("ar_read_fixtures/bsd.a");
const LONG: &[u8] = b"a_rather_long_member_name.txt";

/// Build a 60-byte header (test helper; fields left-justified, space padded).
fn hdr(name: &str, size: &str) -> Vec<u8> {
    let h = format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{size:<10}`\n", 1, 2, 3, 644).into_bytes();
    assert_eq!(h.len(), 60);
    h
}
fn arch(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = b"!<arch>\n".to_vec();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

fn check(e: &[ArEntry], input: &[u8], offs: [usize; 3]) {
    assert_eq!(e.len(), 3);
    let names: Vec<&[u8]> = e.iter().map(|x| x.name.as_slice()).collect();
    assert_eq!(names, vec![&b"a.txt"[..], b"odd", LONG]);
    let lens = [6, 5, 15];
    let bodies: [&[u8]; 3] = [b"hello\n", b"12345", b"long name body\n"];
    for i in 0..3 {
        assert_eq!((e[i].data_offset, e[i].data_len), (offs[i], lens[i]));
        assert_eq!(&input[offs[i]..offs[i] + lens[i]], bodies[i]);
        assert_eq!((e[i].mtime, e[i].uid, e[i].gid, e[i].mode), (1_700_000_000, 501, 20, 0o100644));
    }
}

#[test]
fn gnu_archive_with_symtab_and_long_names() {
    check(&read_ar(GNU, 10).unwrap(), GNU, [224, 290, 356]);
}

#[test]
fn bsd_archive_with_hash1_names() {
    check(&read_ar(BSD, 10).unwrap(), BSD, [68, 134, 232]);
}

#[test]
fn magic() {
    assert_eq!(read_ar(b"", 10), Err(ArError::BadMagic));
    assert_eq!(read_ar(b"!<arch>", 10), Err(ArError::BadMagic));
    assert_eq!(read_ar(b"!<thin>\n", 10), Err(ArError::BadMagic));
    assert_eq!(read_ar(b"!<arch>\n", 10), Ok(vec![]));
}

#[test]
fn missing_final_pad_byte_is_accepted() {
    assert_eq!(read_ar(&GNU[..GNU.len() - 1], 10).unwrap().len(), 3);
}

#[test]
fn truncation() {
    assert_eq!(read_ar(&GNU[..8 + 59], 10), Err(ArError::Truncated));
    assert_eq!(read_ar(&GNU[..227], 10), Err(ArError::Truncated));
    assert_eq!(read_ar(&BSD[..230], 10), Err(ArError::Truncated));
    // cut exactly at a member boundary is a shorter valid archive
    assert_eq!(read_ar(&BSD[..140], 10).unwrap().len(), 2);
    for cut in 8..GNU.len() {
        match read_ar(&GNU[..cut], 10) {
            // member boundaries, plus boundaries missing only a final pad byte
            Ok(_) => assert!([8, 72, 163, 164, 230, 295, 296, 371].contains(&cut), "cut {cut}"),
            Err(e) => assert_eq!(e, ArError::Truncated, "cut {cut}"),
        }
    }
}

#[test]
fn bad_fmag() {
    let mut m = BSD.to_vec();
    m[8 + 58] = b'x';
    assert_eq!(read_ar(&m, 10), Err(ArError::BadHeader));
}

#[test]
fn numbers() {
    let mut m = BSD.to_vec();
    m[8 + 48..8 + 51].copy_from_slice(b"1a ");
    assert_eq!(read_ar(&m, 10), Err(ArError::BadNumber));
    assert_eq!(read_ar(&arch(&[&hdr("x", "")]), 10), Err(ArError::BadNumber));
    let mut o = BSD.to_vec();
    o[8 + 40] = b'9'; // mode is octal
    assert_eq!(read_ar(&o, 10), Err(ArError::BadNumber));
    // blank uid/gid/mtime/mode are zero
    let mut h = hdr("blank", "2");
    h[16..48].fill(b' ');
    let e = read_ar(&arch(&[&h, b"ok"]), 10).unwrap();
    assert_eq!((e[0].mtime, e[0].uid, e[0].gid, e[0].mode, e[0].data_len), (0, 0, 0, 0, 2));
    assert_eq!(e[0].name, b"blank");
}

#[test]
fn gnu_long_name_errors() {
    let tab: &[u8] = b"name_one/\nname_two/\n";
    let ok = arch(&[&hdr("//", "20"), tab, &hdr("/10", "1"), b"z\n"]);
    let e = read_ar(&ok, 10).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].name, b"name_two");
    assert_eq!(e[0].data_offset, 8 + 60 + 20 + 60);
    // no table
    assert_eq!(read_ar(&arch(&[&hdr("/0", "0")]), 10), Err(ArError::BadName));
    // offset past table
    assert_eq!(read_ar(&arch(&[&hdr("//", "20"), tab, &hdr("/20", "0")]), 10), Err(ArError::BadName));
    // no newline terminator
    assert_eq!(read_ar(&arch(&[&hdr("//", "4"), b"abcd", &hdr("/0", "0")]), 10), Err(ArError::BadName));
    // unknown slash name
    assert_eq!(read_ar(&arch(&[&hdr("/abc", "0")]), 10), Err(ArError::BadName));
}

#[test]
fn bsd_long_name_errors() {
    assert_eq!(read_ar(&arch(&[&hdr("#1/9", "4"), b"abcd"]), 10), Err(ArError::BadName));
    assert_eq!(read_ar(&arch(&[&hdr("#1/x", "4"), b"abcd"]), 10), Err(ArError::BadName));
    assert_eq!(read_ar(&arch(&[&hdr("#1/2", "4"), b"\0\0cd"]), 10), Err(ArError::BadName));
    let e = read_ar(&arch(&[&hdr("#1/4", "5"), b"ab\0\0X\n"]), 10).unwrap();
    assert_eq!((e[0].name.as_slice(), e[0].data_offset, e[0].data_len), (&b"ab"[..], 8 + 60 + 4, 1));
}

#[test]
fn symbol_tables_are_skipped_but_symdef_is_not() {
    let v = arch(&[&hdr("/", "4"), b"\0\0\0\0", &hdr("/SYM64/", "2"), b"..", &hdr("__.SYMDEF", "2"), b"xx"]);
    let e = read_ar(&v, 10).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].name, b"__.SYMDEF");
}

#[test]
fn entry_limit() {
    assert_eq!(read_ar(GNU, 2), Err(ArError::TooManyEntries));
    assert_eq!(read_ar(GNU, 3).unwrap().len(), 3);
    assert_eq!(read_ar(BSD, 0), Err(ArError::TooManyEntries));
}

#[test]
fn hostile_never_panics() {
    assert_eq!(read_ar(&arch(&[&hdr("big", "9999999999")]), 10), Err(ArError::Truncated));
    let mut x: u32 = 7;
    for round in 0..300usize {
        let mut v = GNU.to_vec();
        for _ in 0..(1 + round % 5) {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            let i = 8 + (x as usize >> 4) % (v.len() - 8);
            v[i] = (x >> 20) as u8;
        }
        let _ = read_ar(&v, 10);
        let _ = read_ar(&v[..(x as usize % v.len())], 10);
    }
}
