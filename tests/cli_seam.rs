// SPDX-License-Identifier: MIT OR Apache-2.0
//! Contract tests for the FORGE leaf-module APIs as provided by `cli_seam`
//! (cases copied from the FORGE tickets wildcard, listfile and slt-format).
mod wildcard {
use sediment_engine::cli_seam::wildcard::{match_name, match_path};

#[test]
fn name_basics() {
    let cases: &[(&str, &str, bool)] = &[
        ("", "", true), ("", "a", false), ("*", "", true), ("*", "anything", true), ("**", "", true),
        ("?", "", false), ("?", "a", true), ("?", "ab", false), ("??", "ab", true),
        ("abc", "abc", true), ("abc", "abd", false), ("abc", "ab", false), ("ab", "abc", false),
        ("a*c", "ac", true), ("a*c", "abbc", true), ("a*c", "abcd", false), ("a*c*", "abcd", true),
        ("*.txt", "notes.txt", true), ("*.txt", "notes.txt.bak", false), ("*.txt", ".txt", true),
        ("*.*", "noext", false), ("*.*", "a.b", true), ("*a*b", "xaxxb", true), ("*a*b", "xaxxbx", false),
        ("a?c", "abc", true), ("a?c", "ac", false), ("*?", "", false), ("*?", "x", true),
        ("a*b*c", "aXbYbZc", true), ("a*b*c", "aXbYbZ", false), ("*x", "xxxx", true),
        ("a/b", "a/b", true), ("a\\b", "a\\b", true), ("a?b", "a/b", true),
    ];
    for &(p, n, want) in cases {
        assert_eq!(match_name(p, n, true), want, "pattern {p:?} name {n:?}");
    }
}

#[test]
fn name_unicode_chars_not_bytes() {
    assert!(match_name("?pfel", "äpfel", true));
    assert!(match_name("??", "日本", true));
    assert!(!match_name("???", "日本", true));
    assert!(match_name("*本", "日本", true));
    assert!(match_name("caf?", "café", true));
}

#[test]
fn name_case_folding() {
    assert!(match_name("*.TXT", "x.txt", false));
    assert!(!match_name("*.TXT", "x.txt", true));
    assert!(match_name("README", "readme", false));
    assert!(!match_name("README", "readme", true));
    assert!(match_name("Ä*", "äpfel", false));
    assert!(!match_name("Ä*", "äpfel", true));
    assert!(match_name("ΣΟΦΙΑ", "σοφια", false));
    assert!(!match_name("abc", "abd", false));
}

#[test]
fn name_pathological_is_fast() {
    let long = "a".repeat(2000);
    assert!(!match_name("*a*a*a*a*a*a*a*b", &long, true));
    assert!(match_name("*a*a*a*a*a*a*a*a", &long, true));
    let mixed = "ab".repeat(1500) + "c";
    assert!(match_name("*a*b*a*b*a*b*c", &mixed, false));
    assert!(!match_name("*a*b*a*b*a*b*d", &mixed, false));
}

#[test]
fn path_non_recursive_is_anchored() {
    let cases: &[(&str, &str, bool)] = &[
        ("*.txt", "b.txt", true), ("*.txt", "a/b.txt", false), ("*.txt", "b.txt/inner.bin", true),
        ("*", "anything/at/all", true), ("*", "", false), ("", "a", false), ("/", "a", false),
        ("docs", "docs", true), ("docs", "docs/a/b.txt", true), ("docs", "src/docs", false),
        ("docs", "documents", false), ("a/*.txt", "a/b.txt", true), ("a/*.txt", "a/b/c.txt", false),
        ("a/*/c", "a/b/c", true), ("a/*/c", "a/b/x/c", false), ("a/*", "a", false),
        ("a*c", "ab/c", false), ("*/*", "a/b", true), ("*/*", "a", false),
    ];
    for &(p, path, want) in cases {
        assert_eq!(match_path(p, path, false, true), want, "pattern {p:?} path {path:?}");
    }
}

#[test]
fn path_recursive_name_patterns_match_at_any_depth() {
    let cases: &[(&str, &str, bool)] = &[
        ("*.txt", "b.txt", true), ("*.txt", "a/b.txt", true), ("*.txt", "a/b/c/d.txt", true),
        ("*.txt", "a/b.txt.bak", false), ("*.txt", "x.txt/y.bin", true), ("*.txt", "a/b", false),
        ("docs", "src/docs", true), ("docs", "src/docs/readme", true), ("docs", "src/mydocs", false),
        ("?", "a/bb/c", true), ("?", "aa/bb", false),
        // a separator anywhere in the pattern anchors it
        ("a/*.txt", "a/b.txt", true), ("a/*.txt", "x/a/b.txt", false), ("./b.txt", "b.txt", true),
        ("./b.txt", "a/b.txt", false), ("a\\b", "x/a/b", false), ("a\\b", "a/b/c", true),
    ];
    for &(p, path, want) in cases {
        assert_eq!(match_path(p, path, true, true), want, "pattern {p:?} path {path:?}");
    }
}

#[test]
fn path_separators_and_dot_components() {
    assert!(match_path("dir\\*.c", "dir/x.c", false, true));
    assert!(match_path("dir/*.c", "dir\\x.c", false, true));
    assert!(match_path("dir//*.c", "./dir/./x.c", false, true));
    assert!(match_path("/dir/x.c", "dir/x.c/", false, true));
    assert!(match_path("../x", "../x", false, true));
    assert!(!match_path("x", "../x", false, true));
    assert!(match_path("x", "../x", true, true));
    assert!(!match_path(".", "a", true, true));
    assert!(!match_path("a", "", true, true));
    assert!(!match_path("a", "./", true, true));
}

#[test]
fn path_case_insensitive() {
    assert!(match_path("SRC/*.RS", "src/lib.rs", false, false));
    assert!(!match_path("SRC/*.RS", "src/lib.rs", false, true));
    assert!(match_path("*.RS", "a/B/lib.rs", true, false));
}
}
mod listfile {
use sediment_engine::cli_seam::listfile::{ListFileError, parse_listfile};

// UTF-16LE bytes produced by Python: "﻿a.txt\r\n  dir/b c.txt\t\r\n\r\n日本/ファイル.txt\n😀.bin".encode("utf-16-le")
const UTF16: &[u8] = b"\xff\xfe\x61\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x0d\x00\x0a\x00\x20\x00\x20\x00\x64\x00\x69\x00\x72\x00\x2f\x00\x62\x00\x20\x00\x63\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x09\x00\x0d\x00\x0a\x00\x0d\x00\x0a\x00\xe5\x65\x2c\x67\x2f\x00\xd5\x30\xa1\x30\xa4\x30\xeb\x30\x2e\x00\x74\x00\x78\x00\x74\x00\x0a\x00\x3d\xd8\x00\xde\x2e\x00\x62\x00\x69\x00\x6e\x00";

fn v(items: &[&str]) -> Vec<String> { items.iter().map(|s| s.to_string()).collect() }

#[test]
fn utf8_basic_lf_crlf_blank_and_trim() {
    assert_eq!(parse_listfile(b"a\r\nb\n\n  c d \n", 1000).unwrap(), v(&["a", "b", "c d"]));
    assert_eq!(parse_listfile(b"one", 1000).unwrap(), v(&["one"]));
    assert_eq!(parse_listfile(b"\t x/y z.txt\t \r\n", 1000).unwrap(), v(&["x/y z.txt"]));
    assert_eq!(parse_listfile(b"dup\ndup\n", 1000).unwrap(), v(&["dup", "dup"]));
    assert_eq!(parse_listfile(b"./a/../b\\c\n", 1000).unwrap(), v(&["./a/../b\\c"]));
}

#[test]
fn empty_and_blank_inputs() {
    assert_eq!(parse_listfile(b"", 0).unwrap(), Vec::<String>::new());
    assert_eq!(parse_listfile(b"\n\r\n \t\n", 100).unwrap(), Vec::<String>::new());
    assert_eq!(parse_listfile(b"\xef\xbb\xbf", 100).unwrap(), Vec::<String>::new());
    assert_eq!(parse_listfile(b"\xff\xfe", 100).unwrap(), Vec::<String>::new());
}

#[test]
fn only_one_cr_is_removed_and_lone_cr_is_kept() {
    assert_eq!(parse_listfile(b"a\r\r\nb\rc\n", 100).unwrap(), v(&["a\r", "b\rc"]));
}

#[test]
fn utf8_with_bom_and_non_ascii() {
    assert_eq!(parse_listfile(b"\xef\xbb\xbf\xc3\xa9\x0a", 100).unwrap(), v(&["é"]));
    assert_eq!(parse_listfile("日本/ファイル.txt\n".as_bytes(), 100).unwrap(), v(&["日本/ファイル.txt"]));
    // a second BOM is an ordinary character
    assert_eq!(parse_listfile(b"\xef\xbb\xbf\xef\xbb\xbfx", 100).unwrap(), v(&["\u{feff}x"]));
    // non-ASCII whitespace is not trimmed (U+00A0)
    assert_eq!(parse_listfile(b"\xc2\xa0a\n", 100).unwrap(), v(&["\u{a0}a"]));
}

#[test]
fn utf16le_with_bom() {
    assert_eq!(
        parse_listfile(UTF16, 1000).unwrap(),
        v(&["a.txt", "dir/b c.txt", "日本/ファイル.txt", "😀.bin"])
    );
}

#[test]
fn invalid_utf8() {
    assert_eq!(parse_listfile(b"ok\n\xff\n", 100), Err(ListFileError::InvalidUtf8));
    assert_eq!(parse_listfile(b"\xc3", 100), Err(ListFileError::InvalidUtf8));
    assert_eq!(parse_listfile(b"\xef\xbb\xbf\xed\xa0\x80", 100), Err(ListFileError::InvalidUtf8));
    assert_eq!(parse_listfile(b"\xef\xbb", 100), Err(ListFileError::InvalidUtf8));
}

#[test]
fn invalid_utf16() {
    assert_eq!(parse_listfile(b"\xff\xfex\x00y", 100), Err(ListFileError::InvalidUtf16));
    assert_eq!(parse_listfile(b"\xff\xfe\x3d\xd8\x0a\x00", 100), Err(ListFileError::InvalidUtf16));
    assert_eq!(parse_listfile(b"\xff\xfe\x00\xde", 100), Err(ListFileError::InvalidUtf16));
    assert_eq!(parse_listfile(&UTF16[..UTF16.len() - 1], 1000), Err(ListFileError::InvalidUtf16));
}

#[test]
fn utf16be_is_unsupported() {
    assert_eq!(parse_listfile(b"\xfe\xff\x00x\x00\n", 100), Err(ListFileError::UnsupportedEncoding));
}

#[test]
fn nul_is_rejected() {
    assert_eq!(parse_listfile(b"a\0b\n", 100), Err(ListFileError::NulCharacter));
    assert_eq!(parse_listfile(b"\xff\xfex\x00\x00\x00", 100), Err(ListFileError::NulCharacter));
    // a UTF-32LE BOM reads as UTF-16LE BOM + U+0000
    assert_eq!(parse_listfile(b"\xff\xfe\x00\x00x\x00\x00\x00", 100), Err(ListFileError::NulCharacter));
}

#[test]
fn size_cap_is_checked_first() {
    assert_eq!(parse_listfile(b"abc", 2), Err(ListFileError::LimitExceeded));
    assert_eq!(parse_listfile(b"\xff", 0), Err(ListFileError::LimitExceeded));
    assert_eq!(parse_listfile(b"abc", 3).unwrap(), v(&["abc"]));
    assert_eq!(parse_listfile(UTF16, UTF16.len() - 1), Err(ListFileError::LimitExceeded));
    assert!(parse_listfile(UTF16, UTF16.len()).is_ok());
}
}
mod slt {
use sediment_engine::cli_seam::slt_format::{SltEntry, format_attributes, format_entries, format_entry, format_filetime, unix_mode_string};

include!("fixtures/cli_compat/slt_cases.rs");

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
}
