use sediment_engine::listfile::{ListFileError, parse_listfile};

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
