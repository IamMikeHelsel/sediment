// SPDX-License-Identifier: MIT OR Apache-2.0
//! hash_multi: method parsing, published test vectors, digest arithmetic and
//! a differential check against tests/fixtures/hash_cli/digests.txt
//! (tests/gen/hash_cli.py, Python stdlib oracles).
use std::path::Path;

use sediment_engine::hash_multi::{
    ALL_METHODS, Digest, HashMethod, HashSelectError, Hasher, MAX_DIGEST_LEN, MultiHasher, digest, parse_method_list,
};

fn fx(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hash_cli").join(rel)
}

#[test]
fn parse_names() {
    use HashMethod::*;
    for (s, m) in [
        ("crc32", Crc32),
        ("CRC64", Crc64),
        ("xxh64", Xxh64),
        ("Md5", Md5),
        ("sha1", Sha1),
        ("SHA-1", Sha1),
        ("sha224", Sha224),
        ("SHA256", Sha256),
        ("sha-384", Sha384),
        ("sha512", Sha512),
        ("SHA3-256", Sha3_256),
        ("sha3_256", Sha3_256),
        ("sha3256", Sha3_256),
        ("blake2sp", Blake2sp),
        ("BLAKE2sp", Blake2sp),
    ] {
        assert_eq!(HashMethod::parse(s), Ok(m), "{s}");
    }
    for bad in ["", "crc", "sha3", "sha3-512", "blake2s", "sha 256", "ÿ", "crc32crc32crc32crc32", "*"] {
        assert_eq!(HashMethod::parse(bad), Err(HashSelectError::UnknownMethod), "{bad:?}");
    }
    for m in ALL_METHODS {
        assert_eq!(HashMethod::parse(m.name()), Ok(m));
        assert!(m.digest_len() <= MAX_DIGEST_LEN);
    }
}

#[test]
fn method_lists() {
    use HashMethod::*;
    assert_eq!(parse_method_list(&[]), Ok(vec![Crc32]));
    assert_eq!(parse_method_list(&["*"]), Ok(ALL_METHODS.to_vec()));
    assert_eq!(parse_method_list(&["sha256", "*"]), Ok(ALL_METHODS.to_vec()));
    assert_eq!(parse_method_list(&["sha256,crc64", "md5"]), Ok(vec![Sha256, Crc64, Md5]));
    assert_eq!(parse_method_list(&["sha256", "SHA-256"]), Err(HashSelectError::Duplicate));
    assert_eq!(parse_method_list(&[""]), Err(HashSelectError::Empty));
    assert_eq!(parse_method_list(&["sha1,"]), Err(HashSelectError::Empty));
    assert_eq!(parse_method_list(&["nope"]), Err(HashSelectError::UnknownMethod));
}

#[test]
fn published_vectors() {
    use HashMethod::*;
    let check = "123456789".as_bytes();
    assert_eq!(digest(Crc32, check).to_hex(), "CBF43926");
    assert_eq!(digest(Crc64, check).to_hex(), "995DC9BBDF1939FA");
    assert_eq!(digest(Xxh64, b"").to_hex(), "EF46DB3751D8E999");
    assert_eq!(digest(Md5, b"abc").to_hex(), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(digest(Sha1, b"abc").to_hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(digest(Sha224, b"abc").to_hex(), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    assert_eq!(
        digest(Sha256, b"abc").to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        digest(Sha384, b"abc").to_hex(),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(
        digest(Sha512, b"abc").to_hex(),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        digest(Sha3_256, b"abc").to_hex(),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    for m in ALL_METHODS {
        let d = digest(m, b"abc");
        assert_eq!(d.method(), m);
        assert_eq!(d.as_bytes().len(), m.digest_len());
        assert_eq!(d.to_hex().len(), 2 * m.digest_len());
    }
}

#[test]
fn numeric_byte_order() {
    let d = digest(HashMethod::Crc32, b"123456789");
    assert_eq!(d.as_bytes(), &0xCBF4_3926u32.to_le_bytes());
    let d = digest(HashMethod::Xxh64, b"");
    assert_eq!(d.as_bytes(), &0xEF46_DB37_51D8_E999u64.to_le_bytes());
}

#[test]
fn digest_addition() {
    let mut a = digest(HashMethod::Crc32, b"123456789"); // CBF43926
    let b = digest(HashMethod::Crc32, b"123456789");
    assert!(a.add(&b));
    assert_eq!(a.to_hex(), format!("{:08X}", 0xCBF4_3926u32.wrapping_add(0xCBF4_3926)));
    let mut z = Digest::zero(HashMethod::Md5);
    let x = digest(HashMethod::Md5, b"abc");
    assert!(z.add(&x));
    assert_eq!(z, x);
    // Carry propagates from byte 0 upwards and is dropped past the end.
    let mut ff = Digest::from_bytes(HashMethod::Sha1, &[0xFF; 20]).unwrap();
    let mut one = [0u8; 20];
    one[0] = 1;
    let one = Digest::from_bytes(HashMethod::Sha1, &one).unwrap();
    assert!(ff.add(&one));
    assert_eq!(ff, Digest::zero(HashMethod::Sha1));
    let mut p = Digest::from_bytes(HashMethod::Sha1, &[0xFF, 0x00, 0x7F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    p.add(&one);
    assert_eq!(&p.as_bytes()[..3], &[0x00, 0x01, 0x7F]);
    // Numeric CRC32 wraps like u32 addition.
    let mut c = Digest::from_bytes(HashMethod::Crc32, &u32::MAX.to_le_bytes()).unwrap();
    c.add(&Digest::from_bytes(HashMethod::Crc32, &2u32.to_le_bytes()).unwrap());
    assert_eq!(c.to_hex(), "00000001");
    // Mismatched methods are refused and leave the accumulator unchanged.
    let mut c = Digest::zero(HashMethod::Sha256);
    assert!(!c.add(&x));
    assert_eq!(c, Digest::zero(HashMethod::Sha256));
    // from_bytes length checks.
    assert!(Digest::from_bytes(HashMethod::Sha256, &[0; 31]).is_none());
    assert!(Digest::from_bytes(HashMethod::Crc64, &[0; 64]).is_none());
    assert!(Digest::from_bytes(HashMethod::Sha512, &[0; 64]).is_some());
}

#[test]
fn streaming_matches_one_shot_and_multi() {
    let data: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let mut multi = MultiHasher::new(&ALL_METHODS);
    for chunk in data.chunks(97) {
        multi.update(chunk);
    }
    let multi = multi.finalize();
    for (m, md) in ALL_METHODS.iter().zip(&multi) {
        let one = digest(*m, &data);
        assert_eq!(*md, one);
        for split in [0, 1, 63, 64, 65, 511, 512, 513, 4999, 5000] {
            let mut h = Hasher::new(*m);
            assert_eq!(h.method(), *m);
            h.update(&data[..split]);
            h.update(&[]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), one, "{} split {split}", m.name());
        }
    }
}

#[test]
fn differential_against_python_oracle() {
    let text = std::fs::read_to_string(fx("digests.txt")).unwrap();
    let mut n = 0;
    for line in text.lines() {
        let mut f = line.split('\t');
        let (rel, name, hex) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        let data = std::fs::read(fx("tree").join(rel)).unwrap();
        let m = HashMethod::parse(name).unwrap();
        assert_eq!(digest(m, &data).to_hex(), hex, "{rel} {name}");
        n += 1;
    }
    assert_eq!(n, 5 * ALL_METHODS.len());
}
