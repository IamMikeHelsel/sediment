use sediment_engine::wildcard::{match_name, match_path};

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
