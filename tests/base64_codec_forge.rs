use sediment_engine::base64_codec::{Alphabet, Base64Error, DecodeOptions, Padding, decode, encode};

// Vectors: RFC 4648 section 10, plus outputs of Python's base64 module.
const RFC: [(&str, &str); 7] = [
    ("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"),
    ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy"),
];
const ALL_STD: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==";
const ALL_URL: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w==";

fn opts(alphabet: Alphabet, padding: Padding, ws: bool) -> DecodeOptions {
    DecodeOptions { alphabet, padding, ignore_whitespace: ws, max_output: 1 << 20 }
}
fn std_req() -> DecodeOptions { opts(Alphabet::Standard, Padding::Required, false) }
fn d(s: &str, o: DecodeOptions) -> Result<Vec<u8>, Base64Error> { decode(s.as_bytes(), &o) }

#[test]
fn rfc_vectors_encode_decode() {
    for (plain, enc) in RFC {
        assert_eq!(encode(plain.as_bytes(), Alphabet::Standard, true), enc);
        assert_eq!(encode(plain.as_bytes(), Alphabet::Standard, false), enc.trim_end_matches('='));
        assert_eq!(d(enc, std_req()).unwrap(), plain.as_bytes());
        let unpadded = enc.trim_end_matches('=');
        assert_eq!(d(unpadded, opts(Alphabet::Standard, Padding::Forbidden, false)).unwrap(), plain.as_bytes());
        assert_eq!(d(unpadded, opts(Alphabet::Standard, Padding::Optional, false)).unwrap(), plain.as_bytes());
        assert_eq!(d(enc, opts(Alphabet::Standard, Padding::Optional, false)).unwrap(), plain.as_bytes());
    }
}

#[test]
fn all_bytes_both_alphabets() {
    let all: Vec<u8> = (0..=255u8).collect();
    assert_eq!(encode(&all, Alphabet::Standard, true), ALL_STD);
    assert_eq!(encode(&all, Alphabet::UrlSafe, true), ALL_URL);
    assert_eq!(d(ALL_STD, std_req()).unwrap(), all);
    assert_eq!(d(ALL_URL, opts(Alphabet::UrlSafe, Padding::Required, false)).unwrap(), all);
    assert_eq!(encode(&[0xfb, 0xff, 0xbf], Alphabet::Standard, true), "+/+/");
    assert_eq!(encode(&[0xfb, 0xff, 0xbf], Alphabet::UrlSafe, true), "-_-_");
    assert_eq!(encode(&[0xff, 0xee], Alphabet::Standard, true), "/+4=");
}

#[test]
fn alphabet_mixing_is_invalid() {
    assert_eq!(d("+/+/", opts(Alphabet::UrlSafe, Padding::Required, false)), Err(Base64Error::InvalidByte));
    assert_eq!(d("-_-_", std_req()), Err(Base64Error::InvalidByte));
    assert_eq!(d(ALL_URL, std_req()), Err(Base64Error::InvalidByte));
}

#[test]
fn invalid_bytes() {
    assert_eq!(d("Zm9v*", std_req()), Err(Base64Error::InvalidByte));
    assert_eq!(decode(b"Zm9v\xc3\xa9", &std_req()), Err(Base64Error::InvalidByte));
    assert_eq!(decode(b"Zm\0v", &std_req()), Err(Base64Error::InvalidByte));
    // filtering happens over the whole input before any padding checks
    assert_eq!(d("Zh=*", std_req()), Err(Base64Error::InvalidByte));
}

#[test]
fn whitespace_policy() {
    assert_eq!(d("Zm9v\nYmFy", std_req()), Err(Base64Error::InvalidByte));
    assert_eq!(d("Zm9v YmFy", std_req()), Err(Base64Error::InvalidByte));
    let ws = opts(Alphabet::Standard, Padding::Required, true);
    assert_eq!(d("Zm9v\nYmFy", ws).unwrap(), b"foobar");
    assert_eq!(d(" Zm9v\r\n\tYg== \n", ws).unwrap(), b"foob");
    assert_eq!(d("Zg=\n=", ws).unwrap(), b"f");
    assert_eq!(d(" \r\n\t", ws).unwrap(), b"");
    // other control bytes are never whitespace
    assert_eq!(d("Zm9v\x0bYmFy", ws), Err(Base64Error::InvalidByte));
}

#[test]
fn padding_placement() {
    assert_eq!(d("Zg=a", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Z=g=", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zm9vYg==Zm9v", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Z===", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("====", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zm9vY===", std_req()), Err(Base64Error::InvalidPadding));
}

#[test]
fn length_rules() {
    assert_eq!(d("Z", std_req()), Err(Base64Error::InvalidLength));
    assert_eq!(d("Zm9vY", std_req()), Err(Base64Error::InvalidLength));
    assert_eq!(d("Zm9vY", opts(Alphabet::Standard, Padding::Optional, false)), Err(Base64Error::InvalidLength));
    assert_eq!(d("Zm9vY=", opts(Alphabet::Standard, Padding::Optional, false)), Err(Base64Error::InvalidLength));
}

#[test]
fn padding_modes() {
    let opt = opts(Alphabet::Standard, Padding::Optional, false);
    let forb = opts(Alphabet::Standard, Padding::Forbidden, false);
    assert_eq!(d("Zg", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zm8", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zg", opt).unwrap(), b"f");
    assert_eq!(d("Zg==", forb), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zm8=", forb), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zg=", opt), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zm9v=", opt), Err(Base64Error::InvalidPadding));
    assert_eq!(d("Zm9v==", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("=", opt), Err(Base64Error::InvalidPadding));
    assert_eq!(d("==", std_req()), Err(Base64Error::InvalidPadding));
    assert_eq!(d("", std_req()).unwrap(), b"");
    assert_eq!(d("", forb).unwrap(), b"");
}

#[test]
fn non_canonical_trailing_bits() {
    assert_eq!(d("Zh==", std_req()), Err(Base64Error::NonCanonical));
    assert_eq!(d("Zm9=", std_req()), Err(Base64Error::NonCanonical));
    assert_eq!(d("Zh", opts(Alphabet::Standard, Padding::Optional, false)), Err(Base64Error::NonCanonical));
    assert_eq!(d("/w==", std_req()).unwrap(), vec![0xff]);
    assert_eq!(d("/+4=", std_req()).unwrap(), vec![0xff, 0xee]);
    assert_eq!(d("/+5=", std_req()), Err(Base64Error::NonCanonical));
}

#[test]
fn output_limit() {
    let mut o = std_req();
    o.max_output = 6;
    assert_eq!(d("Zm9vYmFy", o).unwrap(), b"foobar");
    o.max_output = 5;
    assert_eq!(d("Zm9vYmFy", o), Err(Base64Error::LimitExceeded));
    o.max_output = 3;
    assert_eq!(d("Zm9vYg==", o), Err(Base64Error::LimitExceeded));
    o.max_output = 0;
    assert_eq!(d("", o).unwrap(), b"");
    // limit is checked before canonical bits
    o.max_output = 0;
    assert_eq!(d("Zh==", o), Err(Base64Error::LimitExceeded));
}

#[test]
fn roundtrip_lengths() {
    for len in 0..70usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        for a in [Alphabet::Standard, Alphabet::UrlSafe] {
            for pad in [true, false] {
                let e = encode(&data, a, pad);
                assert_eq!(e.len(), if pad { len.div_ceil(3) * 4 } else { (len * 4).div_ceil(3) });
                let p = if pad { Padding::Required } else { Padding::Forbidden };
                assert_eq!(d(&e, opts(a, p, false)).unwrap(), data);
            }
        }
    }
}
