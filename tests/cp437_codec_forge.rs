use sediment_engine::cp437_codec::{decode, decode_zip_name, encode, CodePage, CodePageError};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// Spot values from Python: bytes([b]).decode('cp437' / 'cp850').
#[test]
fn table_spot_values() {
    let cases: &[(u8, char, char)] = &[
        (0x80, 'Ç', 'Ç'), (0x9B, '¢', 'ø'), (0x9D, '¥', 'Ø'), (0x9E, '₧', '×'), (0xB5, '╡', 'Á'),
        (0xD5, '╒', 'ı'), (0xE1, 'ß', 'ß'), (0xE6, 'µ', 'µ'), (0xF0, '≡', '\u{ad}'), (0xFE, '■', '■'),
        (0xFF, '\u{a0}', '\u{a0}'), (0x41, 'A', 'A'), (0x00, '\0', '\0'), (0x7F, '\u{7f}', '\u{7f}'),
    ];
    for &(b, c437, c850) in cases {
        assert_eq!(decode(&[b], CodePage::Cp437), c437.to_string(), "cp437 {b:02x}");
        assert_eq!(decode(&[b], CodePage::Cp850), c850.to_string(), "cp850 {b:02x}");
    }
}

#[test]
fn full_round_trip_both_pages() {
    let all: Vec<u8> = (0..=255u8).collect();
    for cp in [CodePage::Cp437, CodePage::Cp850] {
        let s = decode(&all, cp);
        assert_eq!(s.chars().count(), 256);
        assert_eq!(encode(&s, cp).unwrap(), all);
    }
    assert_eq!(decode(&[], CodePage::Cp437), "");
    assert_eq!(encode("", CodePage::Cp850).unwrap(), Vec::<u8>::new());
}

#[test]
fn python_encode_vectors() {
    // s.encode('cp437') / s.encode('cp850') from gen/cp437_codec.py
    for cp in [CodePage::Cp437, CodePage::Cp850] {
        assert_eq!(encode("Grüße.txt", cp).unwrap(), hex("477281e1652e747874"));
        assert_eq!(encode("café/naïve.doc", cp).unwrap(), hex("636166822f6e618b76652e646f63"));
        assert_eq!(encode("½ price ±5°.txt", cp).unwrap(), hex("ab20707269636520f135f82e747874"));
        assert_eq!(encode("Ñandú", cp).unwrap(), hex("a5616e64a3"));
    }
    assert_eq!(encode("ÆØÅ æøå", CodePage::Cp850).unwrap(), hex("929d8f20919b86"));
    assert_eq!(decode(&hex("929d8f20919b86"), CodePage::Cp850), "ÆØÅ æøå");
}

#[test]
fn unmappable_chars_rejected() {
    assert_eq!(encode("ÆØÅ", CodePage::Cp437), Err(CodePageError::Unmappable));
    assert_eq!(encode("€", CodePage::Cp437), Err(CodePageError::Unmappable));
    assert_eq!(encode("日本", CodePage::Cp850), Err(CodePageError::Unmappable));
    assert_eq!(encode("₧", CodePage::Cp850), Err(CodePageError::Unmappable));
}

#[test]
fn zip_name_flag_bit_11() {
    let utf8 = "Grüße.txt".as_bytes();
    assert_eq!(decode_zip_name(utf8, 0x0800), "Grüße.txt");
    assert_eq!(decode_zip_name(utf8, 0x0808), "Grüße.txt");
    // same bytes without the flag: CP437 (what Python zipfile does)
    assert_eq!(decode_zip_name(utf8, 0x0000), "Gr├╝├ƒe.txt");
    let dos = hex("477281e1652e747874");
    assert_eq!(decode_zip_name(&dos, 0), "Grüße.txt");
    // flag set but not valid UTF-8 -> CP437 fallback
    assert_eq!(decode_zip_name(&dos, 0x0800), "Grüße.txt");
    assert_eq!(decode_zip_name(b"plain/ascii.txt", 0x0001), "plain/ascii.txt");
}
