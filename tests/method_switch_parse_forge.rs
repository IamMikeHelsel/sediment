use sediment_engine::method_switch_parse::{effective_dict, method_string, parse_method, MethodError, MethodId};

fn ms(s: &str, level: u8) -> String {
    method_string(&parse_method(s).unwrap_or_else(|e| panic!("{s}: {e:?}")), level)
}

// Expected strings: `7zz l -slt` Method of archives made with `7zz a -m0=<spec> [-mx=N]` (gen/oracle-7zz.txt).
#[test]
fn method_strings_match_7zz() {
    let cases = [("lzma2:d=64m", 5, "LZMA2:26"), ("LZMA2:d=1m", 5, "LZMA2:20"), ("lzma2:d=20", 5, "LZMA2:20"),
        ("lzma:d=1536k:lc=4", 5, "LZMA:1536k"), ("lzma:d=5k", 5, "LZMA:6k"), ("lzma:d=7k", 5, "LZMA:13"),
        ("lzma:d=1k", 5, "LZMA:12"), ("lzma2:d=0", 5, "LZMA2:12"), ("lzma2:d=3m", 5, "LZMA2:3m"), (":d=1m", 5, "LZMA2:20"),
        ("lzma:d=1m:d=7k", 5, "LZMA:13"), ("ppmd:o=8:mem=24", 5, "PPMD"), ("bzip2:d=900k", 5, "BZip2"),
        ("deflate:fb=64:pass=3", 5, "Deflate"), ("Deflate64", 5, "Deflate64"), ("copy", 5, "Copy"),
        ("lzma2", 0, "LZMA2:16"), ("lzma", 3, "LZMA:22"), ("lzma:d=2m", 3, "LZMA:21")];
    for (s, l, want) in cases {
        assert_eq!(ms(s, l), want, "{s} -mx={l}");
    }
    let want = ["16", "18", "20", "22", "24", "25", "26", "27", "28", "28"];
    for (l, w) in want.iter().enumerate() {
        assert_eq!(ms("lzma2", l as u8), format!("LZMA2:{w}"), "level {l}");
    }
}

#[test]
fn parsed_fields() {
    let m = parse_method("LZMA2:d=64m:fb=64:MF=BT4:lc=3:lp=0:pb=2:mt=4").unwrap();
    assert_eq!(m.id, MethodId::Lzma2);
    let p = &m.params;
    assert_eq!((p.dict, p.fast_bytes, p.match_finder.as_deref()), (Some(64 << 20), Some(64), Some("bt4")));
    assert_eq!((p.lc, p.lp, p.pb, p.threads), (Some(3), Some(0), Some(2), Some(4)));
    let m = parse_method("PPMd:o=8:mem=24").unwrap();
    assert_eq!((m.id, m.params.order, m.params.mem), (MethodId::Ppmd, Some(8), Some(1 << 24)));
    assert_eq!(parse_method("bzip2:d=900k:pass=2").unwrap().params.dict, Some(900 << 10));
    assert_eq!(effective_dict(&parse_method("ppmd").unwrap(), 5), None);
    assert_eq!(effective_dict(&parse_method("lzma2:d=3840m").unwrap(), 5), Some(1 << 32));
    assert_eq!(effective_dict(&parse_method("lzma").unwrap(), 12), Some(256 << 20));
}

#[test]
fn validity_matches_7zz() {
    let ok = ["lzma2:lc=4", "lzma2:lc=0:lp=4", "lzma:lc=8", "lzma:pb=4", "ppmd:o=2", "ppmd:o=32", "ppmd:mem=65536b",
              "ppmd:mem=16", "ppmd:mem=4g", "lzma2:d=4g", "lzma2:d=32", "lzma2:mf=hc5", "lzma2:d=1m:d=2m"];
    for s in ok {
        assert!(parse_method(s).is_ok(), "{s}");
    }
    use MethodError::*;
    let bad = [("lzma2:lc=5", BadValue), ("lzma2:lc=3:lp=2", BadValue), ("lzma2:pb=5", BadValue), ("lzma:lc=9", BadValue),
        ("lzma:lp=5", BadValue), ("ppmd:o=1", BadValue), ("ppmd:o=33", BadValue), ("ppmd:mem=65535b", BadValue),
        ("ppmd:mem=5g", BadValue), ("ppmd:mem=2048", BadValue), ("lzma2:d=33", BadValue), ("lzma2:d=4097m", BadValue),
        ("lzma2:d=64x", BadValue), ("lzma2:d=64mb", BadValue), ("lzma2:d=1.5m", BadValue), ("lzma2:fb=abc", BadValue),
        ("lzma2:mt=-1", BadValue), ("lzma2:mf=hc3", BadValue), ("lzma:mf=xx", BadValue), ("lzma2:d", BadParam),
        ("lzma2:d=", BadParam), ("lzma2::", BadParam), ("lzma2:d=1m:", BadParam), ("foo", UnknownMethod),
        ("lzma2:q=1", UnknownParam), ("ppmd:fb=5", UnknownParam), ("ppmd:d=1m", UnknownParam), ("bzip2:lc=3", UnknownParam),
        ("deflate:d=1m", UnknownParam), ("copy:d=1m", UnknownParam), ("lzma:mem=1m", UnknownParam)];
    for (s, e) in bad {
        assert_eq!(parse_method(s).err(), Some(e), "{s}");
    }
}
