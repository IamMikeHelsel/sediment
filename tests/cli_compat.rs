// SPDX-License-Identifier: MIT OR Apache-2.0
//! Table-driven tests for the 7-Zip command-line parser (`cli_compat`) and
//! the pure helpers of `cli_run` / `cli_slt`.
use std::ffi::OsString;
use std::path::PathBuf;

use sediment_engine::cli_compat::{
    ArchiveType, Charset, Command, CommandLine, NameItem, NameRule, OverwriteMode, Recurse, StreamTarget, has_wildcard,
    parse_command_line,
};
use sediment_engine::cli_run::{AddTarget, AddTargetError, NameSpec, Selector, add_target, decode_listfile};
use sediment_engine::cli_seam::listfile::ListFileError;
use sediment_engine::cli_slt::{dictionary_name, slt_path, unix_to_filetime};
use sediment_engine::compress_wrap::Compression;

fn args(a: &[&str]) -> Vec<OsString> {
    a.iter().map(OsString::from).collect()
}

fn parse(cmd: Command, a: &[&str]) -> Result<CommandLine, String> {
    parse_command_line(cmd, &args(a)).map_err(|e| e.message)
}

fn ok(cmd: Command, a: &[&str]) -> CommandLine {
    parse(cmd, a).unwrap_or_else(|e| panic!("{a:?}: {e}"))
}

fn wild(s: &str) -> NameItem {
    NameItem::Wildcard(OsString::from(s))
}

#[test]
fn commands_by_letter() {
    let table = [
        ("l", Some(Command::List)),
        ("L", Some(Command::List)),
        ("t", Some(Command::Test)),
        ("x", Some(Command::Extract)),
        ("X", Some(Command::Extract)),
        ("e", Some(Command::ExtractFlat)),
        ("a", Some(Command::Add)),
        ("A", Some(Command::Add)),
        ("list", None),
        ("test", None),
        ("d", None),
        ("", None),
        ("xx", None),
    ];
    for (name, want) in table {
        assert_eq!(Command::from_name(name.as_ref()), want, "{name}");
    }
}

#[test]
fn defaults() {
    let cl = ok(Command::List, &["a.zip"]);
    assert_eq!(cl.archive, Some(PathBuf::from("a.zip")));
    assert!(cl.names.is_empty() && cl.includes.is_empty() && cl.excludes.is_empty());
    assert_eq!(cl.recurse, None);
    assert_eq!(cl.archive_type, None);
    assert_eq!(cl.output_dir, None);
    assert!(!cl.yes && !cl.no_headers && !cl.technical && !cl.full_paths && !cl.delete_after && !cl.symlinks);
    assert_eq!(cl.overwrite, None);
    assert_eq!(cl.log_level, 0);
    assert_eq!(cl.charset, Charset::Utf8);
    assert_eq!((cl.stdout_to, cl.stderr_to, cl.progress_to), (StreamTarget::Stdout, StreamTarget::Stderr, StreamTarget::Stdout));
    assert_eq!(cl.level, None);
    assert_eq!(cl.wildcard_case_sensitive(), !cfg!(windows));
}

/// (arguments, check) for every switch, including case-insensitive names.
#[test]
fn switch_table() {
    type Check = fn(&CommandLine) -> bool;
    let table: &[(&[&str], Check)] = &[
        (&["-r", "a"], |c| c.recurse == Some(Recurse::On)),
        (&["-R", "a"], |c| c.recurse == Some(Recurse::On)),
        (&["-r-", "a"], |c| c.recurse == Some(Recurse::Off)),
        (&["-r0", "a"], |c| c.recurse == Some(Recurse::WildcardOnly)),
        (&["-tzip", "a"], |c| c.archive_type == Some(ArchiveType::Zip)),
        (&["-T7Z", "a"], |c| c.archive_type == Some(ArchiveType::SevenZ)),
        (&["-ttar", "a"], |c| c.archive_type == Some(ArchiveType::Tar)),
        (&["-tgzip", "a"], |c| c.archive_type == Some(ArchiveType::Gzip)),
        (&["-tgz", "a"], |c| c.archive_type == Some(ArchiveType::Gzip)),
        (&["-tbzip2", "a"], |c| c.archive_type == Some(ArchiveType::Bzip2)),
        (&["-tbz2", "a"], |c| c.archive_type == Some(ArchiveType::Bzip2)),
        (&["-txz", "a"], |c| c.archive_type == Some(ArchiveType::Xz)),
        (&["-oout", "a"], |c| c.output_dir == Some(PathBuf::from("out"))),
        (&["-oOut Dir/x", "a"], |c| c.output_dir == Some(PathBuf::from("Out Dir/x"))),
        (&["-O/abs", "a"], |c| c.output_dir == Some(PathBuf::from("/abs"))),
        (&["-y", "a"], |c| c.yes),
        (&["-Y", "a"], |c| c.yes),
        (&["-aoa", "a"], |c| c.overwrite == Some(OverwriteMode::All)),
        (&["-aos", "a"], |c| c.overwrite == Some(OverwriteMode::Skip)),
        (&["-aot", "a"], |c| c.overwrite == Some(OverwriteMode::RenameExisting)),
        (&["-aou", "a"], |c| c.overwrite == Some(OverwriteMode::RenameNew)),
        (&["-AOU", "a"], |c| c.overwrite == Some(OverwriteMode::RenameNew)),
        (&["-bb", "a"], |c| c.log_level == 1),
        (&["-bb0", "a"], |c| c.log_level == 0),
        (&["-bb2", "a"], |c| c.log_level == 2),
        (&["-bb3", "a"], |c| c.log_level == 3),
        (&["-ba", "a"], |c| c.no_headers),
        (&["-slt", "a"], |c| c.technical),
        (&["-SLT", "a"], |c| c.technical),
        (&["-scsUTF-8", "a"], |c| c.charset == Charset::Utf8),
        (&["-scsutf8", "a"], |c| c.charset == Charset::Utf8),
        (&["-scsUTF-16LE", "a"], |c| c.charset == Charset::Utf16Le),
        (&["-scsUTF-16BE", "a"], |c| c.charset == Charset::Utf16Be),
        (&["-spf", "a"], |c| c.full_paths),
        (&["-spf2", "a"], |c| c.full_paths),
        (&["-sdel", "a"], |c| c.delete_after),
        (&["-bso0", "a"], |c| c.stdout_to == StreamTarget::Off),
        (&["-bso2", "a"], |c| c.stdout_to == StreamTarget::Stderr),
        (&["-bse1", "a"], |c| c.stderr_to == StreamTarget::Stdout),
        (&["-bse0", "a"], |c| c.stderr_to == StreamTarget::Off),
        (&["-bsp0", "a"], |c| c.progress_to == StreamTarget::Off),
        (&["-ssc", "a"], |c| c.case_sensitive == Some(true) && c.wildcard_case_sensitive()),
        (&["-ssc-", "a"], |c| c.case_sensitive == Some(false) && !c.wildcard_case_sensitive()),
        (&["-snl", "a"], |c| c.symlinks),
        (&["-mx0", "a"], |c| c.level == Some(0)),
        (&["-mx9", "a"], |c| c.level == Some(9)),
        (&["-mx=7", "a"], |c| c.level == Some(7)),
        (&["-l", "a"], |c| c.follow_symlinks),
        // later switches win
        (&["-bb3", "-bb1", "a"], |c| c.log_level == 1),
        (&["-tzip", "-ttar", "a"], |c| c.archive_type == Some(ArchiveType::Tar)),
        // switches may follow the archive and names
        (&["a", "n1", "-y", "n2"], |c| c.yes && c.names == [wild("n1"), wild("n2")]),
    ];
    for (a, check) in table {
        let cl = ok(Command::Extract, a);
        assert!(check(&cl), "{a:?} -> {cl:?}");
        assert_eq!(cl.archive, Some(PathBuf::from("a")), "{a:?}");
    }
}

#[test]
fn include_exclude_rules() {
    let cl = ok(
        Command::Extract,
        &["a.zip", "-i!*.txt", "-ir!docs", "-ir-!x", "-ir0@l.lst", "-x!*.bin", "-xr!deep", "-x@ex.lst", "-iR!Y"],
    );
    let rule = |item, recurse| NameRule { item, recurse };
    assert_eq!(
        cl.includes,
        vec![
            rule(wild("*.txt"), None),
            rule(wild("docs"), Some(Recurse::On)),
            rule(wild("x"), Some(Recurse::Off)),
            rule(NameItem::ListFile("l.lst".into()), Some(Recurse::WildcardOnly)),
            rule(wild("Y"), Some(Recurse::On)),
        ]
    );
    assert_eq!(
        cl.excludes,
        vec![
            rule(wild("*.bin"), None),
            rule(wild("deep"), Some(Recurse::On)),
            rule(NameItem::ListFile("ex.lst".into()), None),
        ]
    );
    // values keep their case and may contain '!' or '@'
    let cl = ok(Command::Add, &["a.zip", "-i!A!b@C"]);
    assert_eq!(cl.includes[0].item, wild("A!b@C"));
}

#[test]
fn positional_names_and_listfiles() {
    let cl = ok(Command::Add, &["out.zip", "dir", "@list.txt", "@", "*.c"]);
    assert_eq!(cl.archive, Some(PathBuf::from("out.zip")));
    assert_eq!(cl.names, vec![wild("dir"), NameItem::ListFile("list.txt".into()), wild("@"), wild("*.c")]);
}

#[test]
fn end_of_switches() {
    let cl = ok(Command::Extract, &["-y", "--", "-a.zip", "-r", "--"]);
    assert!(cl.yes);
    assert_eq!(cl.archive, Some(PathBuf::from("-a.zip")));
    assert_eq!(cl.names, vec![wild("-r"), wild("--")]);
    assert_eq!(cl.recurse, None);
    // a lone "-" is a name, not a switch
    let cl = ok(Command::List, &["-"]);
    assert_eq!(cl.archive, Some(PathBuf::from("-")));
}

/// Every malformed command line is an error (exit code 7), never a panic.
#[test]
fn command_line_errors() {
    let table: &[&[&str]] = &[
        &[],
        &["-y"],
        &["--"],
        &[""],
        &["a.zip", ""],
        &["-q", "a.zip"],
        &["-o", "a.zip"],
        &["-ao", "a.zip"],
        &["-aox", "a.zip"],
        &["-aoaa", "a.zip"],
        &["-bb4", "a.zip"],
        &["-bbx", "a.zip"],
        &["-ba1", "a.zip"],
        &["-bso", "a.zip"],
        &["-bso3", "a.zip"],
        &["-bse9", "a.zip"],
        &["-bs", "a.zip"],
        &["-i", "a.zip"],
        &["-i!", "a.zip"],
        &["-i@", "a.zip"],
        &["-ir", "a.zip"],
        &["-ir!", "a.zip"],
        &["-ix", "a.zip"],
        &["-x*.txt", "a.zip"],
        &["-xr1!a", "a.zip"],
        &["-r1", "a.zip"],
        &["-r+", "a.zip"],
        &["-t", "a.zip"],
        &["-trar", "a.zip"],
        &["-t*", "a.zip"],
        &["-scs", "a.zip"],
        &["-scsWIN", "a.zip"],
        &["-scs1251", "a.zip"],
        &["-spf3", "a.zip"],
        &["-sdelx", "a.zip"],
        &["-sltx", "a.zip"],
        &["-ssc+", "a.zip"],
        &["-snlx", "a.zip"],
        &["-mx", "a.zip"],
        &["-mx=", "a.zip"],
        &["-mx10", "a.zip"],
        &["-m", "a.zip"],
        &["-v", "a.zip"],
        &["-v0", "a.zip"],
        &["-vx", "a.zip"],
        &["-so", "-v1k", "a.zip"],
        &["-an", "a.zip"],
        &["-sox", "a.zip"],
        &["-anx", "-so"],
        &["-si", "-si", "a.zip"],
        &["-yy", "a.zip"],
        &["-lx", "a.zip"],
        &["-s", "a.zip"],
        &["-p", "a.zip"],
    ];
    for a in table {
        for cmd in [Command::List, Command::Test, Command::Extract, Command::ExtractFlat, Command::Add] {
            assert!(parse(cmd, a).is_err(), "{cmd:?} {a:?} should fail");
        }
    }
}

/// Deterministic pseudo-random switch soup: the parser must never panic.
#[test]
fn parser_never_panics() {
    let alphabet: &[u8] = b"-!@rR0x iabsotyl23mx=-/\\*?";
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..20_000 {
        let mut argv = Vec::new();
        for _ in 0..(seed % 5) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 9) as usize;
            let s: String = (0..len).map(|k| alphabet[((seed >> (k * 5)) % alphabet.len() as u64) as usize] as char).collect();
            argv.push(OsString::from(s));
        }
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let _ = parse_command_line(Command::Extract, &argv);
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_values_survive() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let argv = vec![
        OsStr::from_bytes(b"-o\xffdir").to_os_string(),
        OsStr::from_bytes(b"\xfe.zip").to_os_string(),
        OsStr::from_bytes(b"-i!\xfd*").to_os_string(),
    ];
    let cl = parse_command_line(Command::Extract, &argv).unwrap();
    assert_eq!(cl.output_dir.unwrap().as_os_str().as_bytes(), b"\xffdir");
    assert_eq!(cl.archive.unwrap().as_os_str().as_bytes(), b"\xfe.zip");
    assert_eq!(cl.includes[0].item, NameItem::Wildcard(OsStr::from_bytes(b"\xfd*").to_os_string()));
}

#[test]
fn recurse_modes() {
    let table = [
        (Recurse::Off, "*.txt", false),
        (Recurse::Off, "docs", false),
        (Recurse::On, "*.txt", true),
        (Recurse::On, "docs", true),
        (Recurse::WildcardOnly, "*.txt", true),
        (Recurse::WildcardOnly, "a?c", true),
        (Recurse::WildcardOnly, "docs", false),
    ];
    for (mode, name, want) in table {
        assert_eq!(mode.applies_to(name), want, "{mode:?} {name}");
    }
    assert!(has_wildcard("a*") && has_wildcard("?") && !has_wildcard("abc"));
}

#[test]
fn archive_type_names() {
    for t in [ArchiveType::Zip, ArchiveType::SevenZ, ArchiveType::Tar, ArchiveType::Gzip, ArchiveType::Bzip2, ArchiveType::Xz] {
        assert_eq!(ArchiveType::from_name(t.name()), Some(t));
        assert_eq!(ArchiveType::from_name(&t.name().to_uppercase()), Some(t));
    }
    assert_eq!(ArchiveType::from_name("rar"), None);
    assert_eq!(ArchiveType::from_name(""), None);
}

#[test]
fn selector_semantics() {
    let spec = |n: &str, r| NameSpec { name: n.into(), recursive: r };
    let s = Selector::new(&[], &[], true);
    assert!(s.selects(b"anything/at/all"));
    let s = Selector::new(&[spec("*.txt", false)], &[], true);
    assert!(s.selects(b"hello.txt") && !s.selects(b"docs/readme.txt") && !s.selects(b"x.bin"));
    let s = Selector::new(&[spec("*.txt", true)], &[spec("deep", true)], true);
    assert!(s.selects(b"docs/a.txt"));
    assert!(!s.selects(b"docs/deep/nested/leaf.txt"));
    assert!(s.excludes(b"x/deep") && !s.excludes(b"x/deeper"));
    let s = Selector::new(&[spec("DOCS", false)], &[], false);
    assert!(s.selects(b"docs/") && s.selects(b"docs/x/y"));
    let s = Selector::new(&[spec("DOCS", false)], &[], true);
    assert!(!s.selects(b"docs/x"));
    // non-UTF-8 member names are matched lossily, never panic
    let s = Selector::new(&[spec("*", false)], &[], true);
    assert!(s.selects(b"\xff\xfe"));
}

#[test]
fn listfile_charsets() {
    let le_nobom: Vec<u8> = "a.txt\r\nb c\n".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let be_nobom: Vec<u8> = "a.txt\r\nb c\n".encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    let mut be_bom = vec![0xfe, 0xff];
    be_bom.extend_from_slice(&be_nobom);
    let want = vec!["a.txt".to_string(), "b c".to_string()];
    assert_eq!(decode_listfile(b"a.txt\r\nb c\n", Charset::Utf8).unwrap(), want);
    assert_eq!(decode_listfile(&le_nobom, Charset::Utf16Le).unwrap(), want);
    assert_eq!(decode_listfile(&be_nobom, Charset::Utf16Be).unwrap(), want);
    assert_eq!(decode_listfile(&be_bom, Charset::Utf16Be).unwrap(), want);
    // A BOM wins over -scs.
    assert_eq!(decode_listfile(b"\xef\xbb\xbfa.txt\nb c", Charset::Utf16Le).unwrap(), want);
    let mut le_bom = vec![0xff, 0xfe];
    le_bom.extend_from_slice(&le_nobom);
    assert_eq!(decode_listfile(&le_bom, Charset::Utf8).unwrap(), want);
    assert_eq!(decode_listfile(&le_bom, Charset::Utf16Be).unwrap(), want);
    // Errors
    assert_eq!(decode_listfile(&be_bom, Charset::Utf8), Err(ListFileError::UnsupportedEncoding));
    assert_eq!(decode_listfile(b"\xff", Charset::Utf8), Err(ListFileError::InvalidUtf8));
    assert_eq!(decode_listfile(b"abc", Charset::Utf16Le), Err(ListFileError::InvalidUtf16));
    assert_eq!(decode_listfile(b"abc", Charset::Utf16Be), Err(ListFileError::InvalidUtf16));
    assert_eq!(decode_listfile(&[0x00, 0xd8], Charset::Utf16Le), Err(ListFileError::InvalidUtf16));
    assert_eq!(decode_listfile(b"a\0b", Charset::Utf8), Err(ListFileError::NulCharacter));
    let big = vec![b'a'; (16 << 20) + 1];
    assert_eq!(decode_listfile(&big, Charset::Utf8), Err(ListFileError::LimitExceeded));
    assert_eq!(decode_listfile(&big, Charset::Utf16Le), Err(ListFileError::LimitExceeded));
}

#[test]
fn add_targets() {
    let table: &[(&str, Option<ArchiveType>, Result<AddTarget, AddTargetError>)] = &[
        ("x.zip", None, Ok(AddTarget::Zip)),
        ("x.ZIP", None, Ok(AddTarget::Zip)),
        ("x.tar", None, Ok(AddTarget::Tar(Compression::None))),
        ("x.tar.gz", None, Ok(AddTarget::Tar(Compression::Gzip))),
        ("x.tgz", None, Ok(AddTarget::Tar(Compression::Gzip))),
        ("x.tar.xz", None, Ok(AddTarget::Tar(Compression::Xz))),
        ("x.tbz2", None, Ok(AddTarget::Tar(Compression::Bzip2))),
        ("x.gz", None, Ok(AddTarget::Stream(Compression::Gzip))),
        ("x.bz2", None, Ok(AddTarget::Stream(Compression::Bzip2))),
        ("x.xz", None, Ok(AddTarget::Stream(Compression::Xz))),
        ("x.7z", None, Ok(AddTarget::SevenZ)),
        ("x.bin", None, Err(AddTargetError::UnknownName)),
        (".zip", None, Err(AddTargetError::UnknownName)),
        ("x.bin", Some(ArchiveType::Zip), Ok(AddTarget::Zip)),
        ("x.zip", Some(ArchiveType::Tar), Ok(AddTarget::Tar(Compression::None))),
        ("x", Some(ArchiveType::Gzip), Ok(AddTarget::Stream(Compression::Gzip))),
        ("x", Some(ArchiveType::Bzip2), Ok(AddTarget::Stream(Compression::Bzip2))),
        ("x", Some(ArchiveType::Xz), Ok(AddTarget::Stream(Compression::Xz))),
        ("x.zip", Some(ArchiveType::SevenZ), Ok(AddTarget::SevenZ)),
    ];
    for (name, t, want) in table {
        assert_eq!(add_target(name.as_ref(), *t), *want, "{name} {t:?}");
    }
}

#[test]
fn slt_helpers() {
    assert_eq!(unix_to_filetime(0), Some(116_444_736_000_000_000));
    assert_eq!(unix_to_filetime(1_709_618_828), Some(133_540_924_280_000_000));
    assert_eq!(unix_to_filetime(-11_644_473_600), Some(0));
    assert_eq!(unix_to_filetime(-11_644_473_601), None);
    assert_eq!(unix_to_filetime(i64::MAX), None);
    assert_eq!(unix_to_filetime(i64::MIN), None);
    for (d, want) in [(4096u64, "12"), (1 << 24, "24"), (3 << 20, "3m"), (1536 << 10, "1536k"), (1000, "1000"), (u64::from(u32::MAX), "4294967295")] {
        assert_eq!(dictionary_name(d), want);
    }
    assert_eq!(slt_path(b"dir/"), "dir");
    assert_eq!(slt_path(b"caf\xc3\xa9.txt"), "café.txt");
    assert_eq!(slt_path(b"a\nb"), "a\\nb");
    assert_eq!(slt_path(b"\xff"), "\\xff");
    assert_eq!(slt_path(b"/"), "/");
    assert_eq!(slt_path(b""), "");
}

#[test]
fn stream_volume_and_method_switches() {
    // -si while reading: no archive name, every positional is a name.
    let cl = ok(Command::Extract, &["-si", "a.txt", "b/*"]);
    assert_eq!(cl.stdin, Some(OsString::new()));
    assert_eq!(cl.archive, None);
    assert_eq!(cl.names, vec![wild("a.txt"), wild("b/*")]);
    let cl = ok(Command::List, &["-SI"]);
    assert_eq!((cl.stdin.is_some(), cl.archive.is_none(), cl.names.len()), (true, true, 0));
    // -si for a carries the member name; the archive stays positional.
    let cl = ok(Command::Add, &["-sinotes.txt", "out.tar"]);
    assert_eq!((cl.stdin, cl.archive), (Some(OsString::from("notes.txt")), Some(PathBuf::from("out.tar"))));
    let cl = ok(Command::Add, &["-so", "-an", "-tgzip"]);
    assert!(cl.to_stdout && cl.no_archive_name && cl.archive.is_none());
    let cl = ok(Command::Add, &["-v1k", "-v2M", "-v100b", "-v7", "o.tar"]);
    assert_eq!(cl.volumes, vec![1024, 2 << 20, 100, 7]);
    let cl = ok(Command::Add, &["-m0=LZMA", "-mf=BCJ", "-ms=off", "-mhc=on", "-mmt=2", "-mx=3", "o.7z"]);
    assert_eq!(cl.methods, args(&["-m0=LZMA", "-mf=BCJ", "-ms=off", "-mhc=on", "-mmt=2"]));
    assert_eq!(cl.level, Some(3));
    let cl = ok(Command::Extract, &["-so", "a.zip"]);
    assert!(cl.to_stdout && cl.archive == Some(PathBuf::from("a.zip")));
}
