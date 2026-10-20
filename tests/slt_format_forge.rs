use sediment_engine::slt_format::{SltEntry, format_attributes, format_entries, format_entry, format_filetime, unix_mode_string};

include!("fragments/slt_format_cases.rs");

#[test]
fn matches_real_7zz_listings() {
    for (expected, entries) in cases() {
        assert_eq!(format_entries(&entries), expected);
        let joined: String = entries.iter().map(format_entry).collect();
        assert_eq!(joined, expected);
    }
}

#[test]
fn filetime_values() {
    assert_eq!(format_filetime(0), "1601-01-01 00:00:00.0000000");
    assert_eq!(format_filetime(1), "1601-01-01 00:00:00.0000001");
    assert_eq!(format_filetime(116444736000000000), "1970-01-01 00:00:00.0000000");
    assert_eq!(format_filetime(133537247990000000), "2024-02-29 23:59:59.0000000");
    assert_eq!(format_filetime(126226944010000000), "2000-12-31 00:00:01.0000000");
    assert_eq!(format_filetime(94405824000000000), "1900-03-01 00:00:00.0000000");
    assert_eq!(format_filetime(2650467743990000000 + 9999999), "9999-12-31 23:59:59.9999999");
    assert_eq!(format_filetime(2650467743990000000 + 10000000), "10000-01-01 00:00:00.0000000");
    assert_eq!(format_filetime(u64::MAX), "60056-05-28 05:36:10.9551615");
}

#[test]
fn attribute_strings() {
    assert_eq!(format_attributes(0x20), "A");
    assert_eq!(format_attributes(0x10), "D");
    assert_eq!(format_attributes(0x01 | 0x02 | 0x04 | 0x20), "RHSA");
    assert_eq!(format_attributes(0x10 | 0x20 | 0x02), "HDA");
    assert_eq!(format_attributes(0), "");
    assert_eq!(format_attributes(0x80 | 0x100 | 0x08 | 0x40), "");
    assert_eq!(format_attributes(0x8020 | (0o100644 << 16)), "A -rw-r--r--");
    assert_eq!(format_attributes(0x8010 | (0o040755 << 16)), "D drwxr-xr-x");
    assert_eq!(format_attributes(0x8000 | (0o120777 << 16)), "lrwxrwxrwx");
    assert_eq!(format_attributes(0x8001 | (0o100444 << 16)), "R -r--r--r--");
}

#[test]
fn mode_strings() {
    assert_eq!(unix_mode_string(0o100644), "-rw-r--r--");
    assert_eq!(unix_mode_string(0o040700), "drwx------");
    assert_eq!(unix_mode_string(0o120777), "lrwxrwxrwx");
    assert_eq!(unix_mode_string(0o104755), "-rwsr-xr-x");
    assert_eq!(unix_mode_string(0o104644), "-rwSr--r--");
    assert_eq!(unix_mode_string(0o102755), "-rwxr-sr-x");
    assert_eq!(unix_mode_string(0o102745), "-rwxr-Sr-x");
    assert_eq!(unix_mode_string(0o041777), "drwxrwxrwt");
    assert_eq!(unix_mode_string(0o041776), "drwxrwxrwT");
    assert_eq!(unix_mode_string(0o020666), "crw-rw-rw-");
    assert_eq!(unix_mode_string(0o060660), "brw-rw----");
    assert_eq!(unix_mode_string(0o010600), "prw-------");
    assert_eq!(unix_mode_string(0o140755), "srwxr-xr-x");
    assert_eq!(unix_mode_string(0o000644), "-rw-r--r--");
    assert_eq!(unix_mode_string(0xFFFF_FFFF), "?rwsrwsrwt");
}

#[test]
fn optional_lines() {
    let e = SltEntry {
        path: "a/b.txt".to_string(),
        folder: Some(false),
        size: 5,
        packed_size: Some(7),
        modified: None,
        created: Some(116444736000000000),
        accessed: None,
        attributes: None,
        crc: Some(0xAB),
        encrypted: true,
        method: "AES-256 Deflate".to_string(),
        block: Some(12),
    };
    let want = "Path = a/b.txt\nFolder = -\nSize = 5\nPacked Size = 7\nModified = \nCreated = 1970-01-01 00:00:00.0000000\n\
Attributes = \nCRC = 000000AB\nEncrypted = +\nMethod = AES-256 Deflate\nBlock = 12\n\n";
    assert_eq!(format_entry(&e), want);
    let d = SltEntry { path: "d".to_string(), folder: Some(true), ..Default::default() };
    let want = "Path = d\nFolder = +\nSize = 0\nPacked Size = \nModified = \nAttributes = \nCRC = \nEncrypted = -\nMethod = \nBlock = \n\n";
    assert_eq!(format_entry(&d), want);
    assert_eq!(format_entries(&[]), "");
    assert_eq!(format_entries(&[d.clone(), d.clone()]), format!("{want}{want}"));
    let big = SltEntry { path: "x".into(), size: u64::MAX, crc: Some(0xFFFF_FFFF), block: Some(u64::MAX), ..Default::default() };
    let s = format_entry(&big);
    assert!(s.contains("\nSize = 18446744073709551615\n"));
    assert!(s.contains("\nCRC = FFFFFFFF\n"));
    assert!(s.contains("\nBlock = 18446744073709551615\n"));
}
