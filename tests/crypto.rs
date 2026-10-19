// SPDX-License-Identifier: MIT OR Apache-2.0
//! HMAC-SHA1 / PBKDF2 / WinZip AES KDF / 7zAES KDF / ZipCrypto tests.
//!
//! Known answers: RFC 2202 (HMAC-SHA1), RFC 6070 (PBKDF2-HMAC-SHA1).
//! Differential fixtures: tests/gen/crypto.py (Python hmac, hashlib,
//! zipfile as oracles) -> tests/fixtures/crypto/.

use sediment_engine::aes::{Aes, AesCtr};
use sediment_engine::crc32::crc32;
use sediment_engine::hmac_sha1::{HmacSha1, Pbkdf2Error, ct_eq, hmac_sha1, pbkdf2_hmac_sha1};
use sediment_engine::inflate::inflate_raw;
use sediment_engine::sevenz_aes_kdf::{
    SEVENZ_AES_MAX_PASSWORD_UNITS, SevenZAesError, SevenZAesProperties,
    parse_sevenz_aes_properties, password_to_utf16le, sevenz_aes_derive_key,
    sevenz_aes_key_from_properties,
};
use sediment_engine::winzip_aes_kdf::{
    WinZipAesError, WinZipAesStrength, winzip_aes_derive, winzip_aes_derive_checked,
};
use sediment_engine::zipcrypto::{ZIPCRYPTO_HEADER_LEN, ZipCrypto, ZipCryptoError, zipcrypto_check_byte};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/crypto");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rows(name: &str) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(format!("{FIX}/{name}")).unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(' ').map(str::to_owned).collect())
        .collect()
}

fn gen_bytes(n: usize, seed: u32) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (s >> 24) as u8
        })
        .collect()
}

// --------------------------------------------------------------------------- HMAC

#[test]
fn hmac_rfc2202() {
    let cases: [(Vec<u8>, Vec<u8>, &str); 7] = [
        (vec![0x0b; 20], b"Hi There".to_vec(), "b617318655057264e28bc0b6fb378c8ef146be00"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        (vec![0xaa; 20], vec![0xdd; 50], "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
        (
            unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            vec![0xcd; 50],
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        ),
        (vec![0x0c; 20], b"Test With Truncation".to_vec(), "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"),
        (
            vec![0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        ),
        (
            vec![0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".to_vec(),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        ),
    ];
    for (key, data, mac) in cases {
        assert_eq!(hex(&hmac_sha1(&key, &data)), mac);
    }
}

#[test]
fn hmac_differential_and_streaming() {
    let rs = rows("hmac_sha1.txt");
    assert_eq!(rs.len(), 64);
    for r in rs {
        let (key, data) = (unhex(&r[0]), unhex(&r[1]));
        assert_eq!(hex(&hmac_sha1(&key, &data)), r[2]);
        let base = HmacSha1::new(&key);
        for split in [1usize, 7, 64] {
            let mut h = base.clone();
            for c in data.chunks(split) {
                h.update(c);
            }
            assert_eq!(hex(&h.finalize()), r[2]);
        }
    }
}

#[test]
fn ct_eq_behaviour() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
}

// --------------------------------------------------------------------------- PBKDF2

fn pbkdf2(pw: &[u8], salt: &[u8], it: u32, len: usize) -> String {
    let mut out = vec![0u8; len];
    pbkdf2_hmac_sha1(pw, salt, it, u32::MAX, &mut out).unwrap();
    hex(&out)
}

#[test]
fn pbkdf2_rfc6070() {
    assert_eq!(pbkdf2(b"password", b"salt", 1, 20), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    assert_eq!(pbkdf2(b"password", b"salt", 2, 20), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    assert_eq!(pbkdf2(b"password", b"salt", 4096, 20), "4b007901b765489abead49d926f721d065a429c1");
    assert_eq!(
        pbkdf2(b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25),
        "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
    );
    assert_eq!(pbkdf2(b"pass\0word", b"sa\0lt", 4096, 16), "56fa6aa75548099dcc37d7f03425e0c3");
}

/// RFC 6070's 16,777,216-iteration vector; slow in debug builds.
#[test]
#[ignore]
fn pbkdf2_rfc6070_16m() {
    assert_eq!(pbkdf2(b"password", b"salt", 16_777_216, 20), "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
}

#[test]
fn pbkdf2_differential() {
    let rs = rows("pbkdf2_sha1.txt");
    assert!(rs.len() >= 8);
    for r in rs {
        let it: u32 = r[2].parse().unwrap();
        let len: usize = r[3].parse().unwrap();
        assert_eq!(pbkdf2(&unhex(&r[0]), &unhex(&r[1]), it, len), r[4]);
    }
}

#[test]
fn pbkdf2_errors_and_limits() {
    let mut out = [0u8; 20];
    assert_eq!(pbkdf2_hmac_sha1(b"p", b"s", 0, 10, &mut out), Err(Pbkdf2Error::ZeroIterations));
    assert_eq!(pbkdf2_hmac_sha1(b"p", b"s", 11, 10, &mut out), Err(Pbkdf2Error::LimitExceeded));
    assert_eq!(pbkdf2_hmac_sha1(b"p", b"s", 10, 10, &mut out), Ok(()));
    // Empty output is valid and does nothing.
    assert_eq!(pbkdf2_hmac_sha1(b"p", b"s", 1, 1, &mut []), Ok(()));
}

// --------------------------------------------------------------------------- WinZip AES

#[test]
fn winzip_kdf_differential() {
    let rs = rows("winzip_kdf.txt");
    assert_eq!(rs.len(), 12);
    for r in rs {
        let strength = WinZipAesStrength::from_byte(r[0].parse().unwrap()).unwrap();
        let (pw, salt) = (unhex(&r[1]), unhex(&r[2]));
        let k = winzip_aes_derive(&pw, &salt, strength).unwrap();
        assert_eq!(hex(k.aes_key()), r[3]);
        assert_eq!(hex(k.mac_key()), r[4]);
        assert_eq!(hex(&k.verifier), r[5]);
        let v: [u8; 2] = unhex(&r[5]).try_into().unwrap();
        assert!(winzip_aes_derive_checked(&pw, &salt, strength, v).is_ok());
        let bad = [v[0] ^ 1, v[1]];
        assert_eq!(
            winzip_aes_derive_checked(&pw, &salt, strength, bad).unwrap_err(),
            WinZipAesError::BadPassword
        );
        // The derived key is usable with AES-CTR (WinZip counter mode).
        let mut data = b"winzip aes payload".to_vec();
        AesCtr::winzip(Aes::new(k.aes_key()).unwrap()).apply_keystream(&mut data);
        AesCtr::winzip(Aes::new(k.aes_key()).unwrap()).apply_keystream(&mut data);
        assert_eq!(data, b"winzip aes payload");
    }
}

#[test]
fn winzip_errors() {
    for b in [0u8, 4, 255] {
        assert_eq!(WinZipAesStrength::from_byte(b), Err(WinZipAesError::InvalidStrength));
    }
    for (s, ok) in [(WinZipAesStrength::Aes128, 8), (WinZipAesStrength::Aes192, 12), (WinZipAesStrength::Aes256, 16)] {
        assert_eq!(WinZipAesStrength::from_byte(s.to_byte()), Ok(s));
        for n in [0usize, 7, 8, 12, 16, 17] {
            let r = winzip_aes_derive(b"pw", &vec![0; n], s);
            assert_eq!(r.is_ok(), n == ok, "{s:?} salt {n}");
            if n != ok {
                assert_eq!(r.unwrap_err(), WinZipAesError::InvalidSaltLength);
            }
        }
    }
    let dbg = format!("{:?}", winzip_aes_derive(b"pw", &[0; 8], WinZipAesStrength::Aes128).unwrap());
    assert!(!dbg.contains("aes_key"), "{dbg}");
}

// --------------------------------------------------------------------------- 7zAES

#[test]
fn sevenz_kdf_differential() {
    let rs = rows("sevenz_kdf.txt");
    assert!(rs.len() >= 90);
    for r in rs {
        let pw = String::from_utf8(unhex(&r[0])).unwrap();
        let salt = unhex(&r[1]);
        let power: u8 = r[2].parse().unwrap();
        let pw16 = password_to_utf16le(&pw).unwrap();
        let key = sevenz_aes_derive_key(&pw16, &salt, power, 24).unwrap();
        assert_eq!(hex(&key), r[3], "pw {pw:?} power {power}");
        let props = SevenZAesProperties::new(power, &salt, &[]).unwrap();
        assert_eq!(hex(&sevenz_aes_key_from_properties(&pw, &props, 24).unwrap()), r[3]);
    }
}

#[test]
fn sevenz_utf16_surrogates() {
    assert_eq!(password_to_utf16le("a\u{1F600}").unwrap(), vec![0x61, 0, 0x3d, 0xd8, 0x00, 0xde]);
    assert_eq!(password_to_utf16le("").unwrap(), Vec::<u8>::new());
}

#[test]
fn sevenz_cost_and_length_limits() {
    let pw = password_to_utf16le("pw").unwrap();
    assert_eq!(sevenz_aes_derive_key(&pw, &[], 25, 24), Err(SevenZAesError::CostExceeded));
    assert_eq!(sevenz_aes_derive_key(&pw, &[], 62, 24), Err(SevenZAesError::CostExceeded));
    assert_eq!(sevenz_aes_derive_key(&pw, &[], 63, 255), Ok({
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&pw);
        k
    }));
    // Powers 0x40.. never reach the hashing loop (0x3f marker aside).
    assert_eq!(sevenz_aes_derive_key(&pw, &[], 64, 255), Err(SevenZAesError::CostExceeded));
    assert_eq!(sevenz_aes_derive_key(&pw, &[0; 17], 1, 24), Err(SevenZAesError::InvalidProperties));
    let long = "x".repeat(SEVENZ_AES_MAX_PASSWORD_UNITS + 1);
    assert_eq!(password_to_utf16le(&long), Err(SevenZAesError::PasswordTooLong));
    assert!(password_to_utf16le(&long[1..]).is_ok());
    assert_eq!(
        sevenz_aes_derive_key(&vec![0; 2 * SEVENZ_AES_MAX_PASSWORD_UNITS + 2], &[], 0, 24),
        Err(SevenZAesError::PasswordTooLong)
    );
    // No-hash marker truncates salt||password to 32 bytes.
    let k = sevenz_aes_derive_key(&[0xaa; 40], &[1; 16], 0x3f, 0).unwrap();
    assert_eq!(&k[..16], &[1; 16]);
    assert_eq!(&k[16..], &[0xaa; 16]);
}

#[test]
fn sevenz_properties_parse_and_encode() {
    // 7-Zip's usual properties: power 19 (0x13), 16-byte IV, no salt.
    let iv = gen_bytes(16, 5);
    let mut raw = vec![0x40 | 0x13, 0x0f];
    raw.extend_from_slice(&iv);
    let p = parse_sevenz_aes_properties(&raw).unwrap();
    assert_eq!(p.num_cycles_power, 0x13);
    assert_eq!(p.salt(), &[] as &[u8]);
    assert_eq!(p.iv.to_vec(), iv);
    assert_eq!(p.encode(16).unwrap(), raw);

    // Power 24, 8-byte IV (zero-padded), 5-byte salt.
    let mut raw = vec![0xc0 | 24, (4 << 4) | 7];
    raw.extend_from_slice(&[9; 5]);
    raw.extend_from_slice(&[7; 8]);
    let p = parse_sevenz_aes_properties(&raw).unwrap();
    assert_eq!(p.num_cycles_power, 24);
    assert_eq!(p.salt(), &[9; 5]);
    assert_eq!(&p.iv[..8], &[7; 8]);
    assert_eq!(&p.iv[8..], &[0; 8]);
    assert_eq!(p.encode(8).unwrap(), raw);

    // Single byte: no salt, no IV.
    let p = parse_sevenz_aes_properties(&[0x05]).unwrap();
    assert_eq!((p.num_cycles_power, p.salt().len(), p.iv), (5, 0, [0; 16]));
    assert_eq!(p.encode(0).unwrap(), vec![0x05]);

    // Malformed: empty, missing second byte, truncated, trailing bytes.
    for bad in [
        &[][..],
        &[0x80][..],
        &[0x40, 0x00][..],
        &[0x40, 0x0f, 1, 2, 3][..],
        &[0x05, 0x00][..],
        &[0xc0, 0xff][..],
    ] {
        assert_eq!(parse_sevenz_aes_properties(bad), Err(SevenZAesError::InvalidProperties), "{bad:?}");
    }
    // Exhaustive two-byte headers with exactly the right amount of data parse, and
    // never panic with arbitrary trailing lengths.
    for b0 in 0..=255u8 {
        for b1 in 0..=255u8 {
            let s = ((b0 >> 7) & 1) as usize + (b1 >> 4) as usize;
            let i = ((b0 >> 6) & 1) as usize + (b1 & 15) as usize;
            let mut v = vec![b0, b1];
            v.resize(2 + s + i, 0x11);
            let ok = parse_sevenz_aes_properties(&v);
            assert_eq!(ok.is_ok(), b0 & 0xc0 != 0, "{b0:02x} {b1:02x}");
            v.push(0);
            assert!(parse_sevenz_aes_properties(&v).is_err());
        }
    }
    assert!(SevenZAesProperties::new(0x40, &[], &[]).is_err());
    assert!(SevenZAesProperties::new(1, &[0; 17], &[]).is_err());
    assert!(SevenZAesProperties::new(1, &[], &[0; 17]).is_err());
    assert!(SevenZAesProperties::new(1, &[], &[]).unwrap().encode(17).is_err());
}

// --------------------------------------------------------------------------- ZipCrypto

struct Entry {
    flags: u16,
    method: u16,
    dos_time: u16,
    crc: u32,
    usize_: usize,
    payload: Vec<u8>,
}

/// Minimal local-header walk for the single-entry fixtures; sizes and CRC
/// come from the central directory (fixtures may use a data descriptor).
fn read_entry(zip: &[u8]) -> Entry {
    let u16_at = |o: usize| u16::from_le_bytes([zip[o], zip[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes(zip[o..o + 4].try_into().unwrap());
    let eocd = zip.len() - 22;
    assert_eq!(u32_at(eocd), 0x0605_4b50);
    let cd = u32_at(eocd + 16) as usize;
    assert_eq!(u32_at(cd), 0x0201_4b50);
    let flags = u16_at(cd + 8);
    let method = u16_at(cd + 10);
    let dos_time = u16_at(cd + 12);
    let crc = u32_at(cd + 16);
    let csize = u32_at(cd + 20) as usize;
    let usize_ = u32_at(cd + 24) as usize;
    let data = 30 + u16_at(26) as usize + u16_at(28) as usize;
    Entry { flags, method, dos_time, crc, usize_, payload: zip[data..data + csize].to_vec() }
}

#[test]
fn zipcrypto_fixtures_decrypt() {
    let plain: Vec<u8> =
        (0..300).flat_map(|i| format!("sediment zipcrypto line {i:04}\n").into_bytes()).collect();
    let rs = rows("zipcrypto.txt");
    assert_eq!(rs.len(), 3);
    for r in rs {
        let zip = std::fs::read(format!("{FIX}/{}", r[0])).unwrap();
        let pw = unhex(&r[1]);
        let e = read_entry(&zip);
        assert_eq!(e.flags & 1, 1);
        assert_eq!(e.flags & 8 != 0, r[4] == "1");
        let check = zipcrypto_check_byte(e.flags, e.crc, e.dos_time);

        let mut zc = ZipCrypto::new(&pw);
        zc.decrypt_header(&e.payload, check).unwrap();
        let mut body = e.payload[ZIPCRYPTO_HEADER_LEN..].to_vec();
        zc.decrypt(&mut body);
        let compressed = body.clone();
        let out = if e.method == 8 { inflate_raw(&body, 1 << 20, 1 << 10).unwrap() } else { body };
        assert_eq!(out.len(), e.usize_);
        assert_eq!(crc32(&out), e.crc);
        assert_eq!(out, plain, "{}", r[0]);

        // Encryption with the same header randomness reproduces the payload
        // byte for byte.
        let rnd: [u8; 11] = unhex(&r[2]).try_into().unwrap();
        let mut enc = ZipCrypto::new(&pw);
        let hdr = enc.encrypt_header(rnd, check);
        assert_eq!(hdr.to_vec(), e.payload[..12].to_vec());
        let mut b = compressed.clone();
        enc.encrypt(&mut b);
        assert_eq!(b, e.payload[12..].to_vec());

        // Chunked decryption matches.
        let mut zc = ZipCrypto::new(&pw);
        let mut all = e.payload.clone();
        for c in all.chunks_mut(5) {
            zc.decrypt(c);
        }
        assert_eq!(all[11], check);

        // Wrong password: header check rejects nearly all; count false accepts.
        let mut accepted = 0;
        for i in 0..512u32 {
            let wrong = format!("wrong{i}");
            if ZipCrypto::new(wrong.as_bytes()).decrypt_header(&e.payload, check).is_ok() {
                accepted += 1;
            }
        }
        assert!(accepted < 16, "{accepted} false accepts");
        assert_eq!(
            ZipCrypto::new(b"definitely wrong").decrypt_header(&e.payload[..11], check),
            Err(ZipCryptoError::Truncated)
        );
    }
}

#[test]
fn zipcrypto_round_trip_and_check_byte() {
    let data = gen_bytes(5000, 3);
    let mut e = ZipCrypto::new(b"pw");
    let hdr = e.encrypt_header([1; 11], 0xab);
    let mut c = data.clone();
    e.encrypt(&mut c);
    assert_ne!(c, data);
    let mut d = ZipCrypto::new(b"pw");
    d.decrypt_header(&hdr, 0xab).unwrap();
    d.decrypt(&mut c);
    assert_eq!(c, data);
    assert_eq!(ZipCrypto::new(b"pw").decrypt_header(&hdr, 0xac), Err(ZipCryptoError::BadPassword));
    assert_eq!(ZipCrypto::new(b"pw").decrypt_header(&[], 0), Err(ZipCryptoError::Truncated));
    assert_eq!(zipcrypto_check_byte(0x0001, 0x1234_5678, 0xabcd), 0x12);
    assert_eq!(zipcrypto_check_byte(0x0009, 0x1234_5678, 0xabcd), 0xab);
    assert!(!format!("{:?}", ZipCrypto::new(b"pw")).contains("k0"));
}
