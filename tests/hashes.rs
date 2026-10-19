// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hash library tests: published known answers (NIST FIPS 180-4 / 202
//! examples, RFC 1321, RFC 7693, BLAKE2sp KAT, xxHash sanity vectors),
//! differential fixtures from Python hashlib (tests/gen/hashes.py), and
//! chunked-update equivalence.

use sediment_engine::hash_blake2sp::{
    Blake2Error, Blake2s, Blake2sParams, Blake2sp, blake2s, blake2s_256, blake2sp,
    blake2sp_keyed,
};
use sediment_engine::hash_md5::{Md5, md5};
use sediment_engine::hash_sha1::{Sha1, sha1};
use sediment_engine::hash_sha3::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, sha3_224, sha3_256, sha3_384, sha3_512,
};
use sediment_engine::hash_sha256::{Sha224, Sha256, sha224, sha256};
use sediment_engine::hash_sha512::{Sha384, Sha512, sha384, sha512};
use sediment_engine::hash_xxh64::{Xxh64, xxh64, xxh64_be_bytes};

const VECTORS: &str = include_str!("fixtures/hashes/vectors.txt");
const BLAKE2SP_KAT: &str = include_str!("fixtures/hashes/blake2sp_kat.txt");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Same LCG as `gen_bytes` in tests/gen/hashes.py.
fn gen_bytes(n: usize) -> Vec<u8> {
    let mut state: u32 = 0x1234_5678;
    (0..n)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (state >> 24) as u8
        })
        .collect()
}

const ALGS: &[&str] = &[
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384",
    "sha3_512", "blake2s", "blake2s_k32_o16", "blake2s_node", "blake2sp", "xxh64_0", "xxh64_s",
];

fn node_params() -> Blake2sParams {
    Blake2sParams {
        digest_length: 20,
        fanout: 3,
        depth: 4,
        leaf_length: 0x0102_0304,
        node_offset: 0x0000_A0B0_C0D0_E0F,
        node_depth: 5,
        inner_length: 24,
        salt: *b"saltsalt",
        personal: *b"personal",
        last_node: true,
    }
}

fn key32() -> Vec<u8> {
    (0u8..32).collect()
}

/// Hashes `data` by feeding the given chunks (in order) through the streaming API.
fn stream(alg: &str, chunks: &[&[u8]]) -> String {
    macro_rules! run {
        ($state:expr) => {{
            let mut h = $state;
            for c in chunks {
                h.update(c);
            }
            hex(&h.finalize())
        }};
    }
    match alg {
        "md5" => run!(Md5::new()),
        "sha1" => run!(Sha1::new()),
        "sha224" => run!(Sha224::new()),
        "sha256" => run!(Sha256::new()),
        "sha384" => run!(Sha384::new()),
        "sha512" => run!(Sha512::new()),
        "sha3_224" => run!(Sha3_224::new()),
        "sha3_256" => run!(Sha3_256::new()),
        "sha3_384" => run!(Sha3_384::new()),
        "sha3_512" => run!(Sha3_512::new()),
        "blake2sp" => run!(Blake2sp::new()),
        "blake2s" | "blake2s_k32_o16" | "blake2s_node" => {
            let mut h = match alg {
                "blake2s" => Blake2s::new(),
                "blake2s_k32_o16" => Blake2s::new_keyed(&key32(), 16).unwrap(),
                _ => Blake2s::with_params(&node_params(), b"sediment").unwrap(),
            };
            for c in chunks {
                h.update(c);
            }
            hex(h.finalize().as_bytes())
        }
        "xxh64_0" | "xxh64_s" => {
            let seed = if alg == "xxh64_0" { 0 } else { 0x0123_4567_89AB_CDEF };
            let mut h = Xxh64::with_seed(seed);
            for c in chunks {
                h.update(c);
            }
            format!("{:016x}", h.finalize())
        }
        _ => panic!("unknown alg {alg}"),
    }
}

fn one_shot(alg: &str, data: &[u8]) -> String {
    match alg {
        "md5" => hex(&md5(data)),
        "sha1" => hex(&sha1(data)),
        "sha224" => hex(&sha224(data)),
        "sha256" => hex(&sha256(data)),
        "sha384" => hex(&sha384(data)),
        "sha512" => hex(&sha512(data)),
        "sha3_224" => hex(&sha3_224(data)),
        "sha3_256" => hex(&sha3_256(data)),
        "sha3_384" => hex(&sha3_384(data)),
        "sha3_512" => hex(&sha3_512(data)),
        "blake2s" => hex(&blake2s_256(data)),
        "blake2s_k32_o16" => hex(blake2s(data, &key32(), 16).unwrap().as_bytes()),
        "blake2sp" => hex(&blake2sp(data)),
        "xxh64_0" => hex(&xxh64_be_bytes(data, 0)),
        "xxh64_s" => format!("{:016x}", xxh64(data, 0x0123_4567_89AB_CDEF)),
        other => stream(other, &[data]),
    }
}

fn chunk_by<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    let mut i = 0;
    while !rest.is_empty() {
        let n = sizes[i % sizes.len()].min(rest.len());
        out.push(&rest[..n]);
        rest = &rest[n..];
        i += 1;
    }
    out
}

#[test]
fn differential_fixtures_one_shot_and_streamed() {
    let mut checked = 0;
    let mut cache: Option<(usize, Vec<u8>)> = None;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let mut parts = line.split(' ');
        let alg = parts.next().unwrap();
        let len: usize = parts.next().unwrap().parse().unwrap();
        let want = parts.next().unwrap();
        if cache.as_ref().map(|c| c.0) != Some(len) {
            cache = Some((len, gen_bytes(len)));
        }
        let data = &cache.as_ref().unwrap().1;
        assert!(ALGS.contains(&alg), "{alg}");
        assert_eq!(one_shot(alg, data), want, "one-shot {alg} len {len}");
        let odd = chunk_by(data, &[1, 7, 64, 13, 500, 3, 129, 0x1000]);
        assert_eq!(stream(alg, &odd), want, "chunked {alg} len {len}");
        // Interleave empty updates as well.
        let mut with_empty: Vec<&[u8]> = vec![&[]];
        for c in chunk_by(data, &[64]) {
            with_empty.push(c);
            with_empty.push(&[]);
        }
        assert_eq!(stream(alg, &with_empty), want, "64-chunks {alg} len {len}");
        checked += 1;
    }
    assert_eq!(checked, ALGS.len() * 50);
}

#[test]
fn every_two_way_split_matches() {
    let data = gen_bytes(1100);
    for alg in ALGS {
        let want = one_shot(alg, &data);
        for split in 0..=data.len() {
            let (a, b) = data.split_at(split);
            assert_eq!(stream(alg, &[a, b]), want, "{alg} split {split}");
        }
    }
}

#[test]
fn byte_at_a_time_matches() {
    let data = gen_bytes(1500);
    for alg in ALGS {
        let chunks: Vec<&[u8]> = data.chunks(1).collect();
        assert_eq!(stream(alg, &chunks), one_shot(alg, &data), "{alg}");
    }
}

#[test]
fn nist_and_rfc_examples() {
    let abc = b"abc";
    let s448 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let s896 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(&md5(abc)), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hex(&md5(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
    assert_eq!(hex(&sha1(abc)), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hex(&sha1(s448)), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    assert_eq!(hex(&sha224(abc)), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    assert_eq!(
        hex(&sha256(abc)),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(s448)),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(
        hex(&sha384(abc)),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(
        hex(&sha384(s896)),
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
    );
    assert_eq!(
        hex(&sha512(abc)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        hex(&sha512(s896)),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    );
    assert_eq!(
        hex(&sha3_256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
    assert_eq!(
        hex(&sha3_256(abc)),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    // RFC 7693 Appendix B.
    assert_eq!(
        hex(&blake2s_256(abc)),
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
    );
    // Published unkeyed BLAKE2sp of the empty message.
    assert_eq!(
        hex(&blake2sp(b"")),
        "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
    );
}

#[test]
fn million_a() {
    let m = vec![b'a'; 1_000_000];
    assert_eq!(hex(&md5(&m)), "7707d6ae4e027c70eea2a935c2296f21");
    assert_eq!(hex(&sha1(&m)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    assert_eq!(
        hex(&sha256(&m)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
    assert_eq!(
        hex(&sha512(&m)),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
    assert_eq!(
        hex(&sha3_256(&m)),
        "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"
    );
}

#[test]
fn blake2sp_published_keyed_kat() {
    let key = key32();
    let input: Vec<u8> = (0u8..=255).collect();
    let hashes: Vec<&str> = BLAKE2SP_KAT.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(hashes.len(), 256);
    for (len, want) in hashes.iter().enumerate() {
        let data = &input[..len];
        assert_eq!(hex(&blake2sp_keyed(data, &key).unwrap()), *want, "one-shot len {len}");
        let mut h = Blake2sp::new_keyed(&key).unwrap();
        for c in data.chunks(5) {
            h.update(c);
        }
        assert_eq!(hex(&h.finalize()), *want, "chunked len {len}");
    }
}

/// xxHash project sanity vectors (cli/xsum_sanity_check.c, XSUM_XXH64_testdata).
#[test]
fn xxh64_published_sanity_vectors() {
    const PRIME32: u64 = 2_654_435_761;
    const PRIME64: u64 = 11_400_714_785_074_694_797;
    let mut buf = vec![0u8; 222];
    let mut byte_gen: u64 = PRIME32;
    for b in buf.iter_mut() {
        *b = (byte_gen >> 56) as u8;
        byte_gen = byte_gen.wrapping_mul(PRIME64);
    }
    let cases: [(usize, u64, u64); 9] = [
        (0, 0, 0xEF46DB3751D8E999),
        (0, PRIME32, 0xAC75FDA2929B17EF),
        (1, 0, 0xE934A84ADB052768),
        (1, PRIME32, 0x5014607643A9B4C3),
        (4, 0, 0x9136A0DCA57457EE),
        (14, 0, 0x8282DCC4994E35C8),
        (14, PRIME32, 0xC3BD6BF63DEB6DF0),
        (222, 0, 0xB641AE8CB691C174),
        (222, PRIME32, 0x20CB8AB7AE10C14A),
    ];
    for (len, seed, want) in cases {
        assert_eq!(xxh64(&buf[..len], seed), want, "len {len} seed {seed}");
        let mut h = Xxh64::with_seed(seed);
        for b in &buf[..len] {
            h.update(std::slice::from_ref(b));
        }
        assert_eq!(h.finalize(), want);
    }
    assert_eq!(Xxh64::new().finalize(), 0xEF46DB3751D8E999);
}

#[test]
fn blake2_parameter_validation() {
    assert_eq!(Blake2s::new_keyed(&[], 0).err(), Some(Blake2Error::InvalidDigestLength));
    assert_eq!(Blake2s::new_keyed(&[], 33).err(), Some(Blake2Error::InvalidDigestLength));
    assert_eq!(Blake2s::new_keyed(&[0; 33], 32).err(), Some(Blake2Error::KeyTooLong));
    assert_eq!(blake2s(b"x", &[0; 64], 32).err(), Some(Blake2Error::KeyTooLong));
    assert_eq!(blake2s(b"x", &[], usize::MAX).err(), Some(Blake2Error::InvalidDigestLength));
    let p = |f: fn(&mut Blake2sParams)| {
        let mut p = Blake2sParams::default();
        f(&mut p);
        Blake2s::with_params(&p, &[]).err()
    };
    assert_eq!(p(|p| p.digest_length = 0), Some(Blake2Error::InvalidDigestLength));
    assert_eq!(p(|p| p.digest_length = 255), Some(Blake2Error::InvalidDigestLength));
    assert_eq!(p(|p| p.depth = 0), Some(Blake2Error::InvalidDepth));
    assert_eq!(p(|p| p.node_offset = 1 << 48), Some(Blake2Error::NodeOffsetTooLarge));
    assert_eq!(p(|p| p.node_offset = u64::MAX), Some(Blake2Error::NodeOffsetTooLarge));
    assert_eq!(p(|p| p.inner_length = 33), Some(Blake2Error::InvalidInnerLength));
    assert_eq!(p(|p| p.node_offset = (1 << 48) - 1), None);
    assert_eq!(Blake2sp::new_keyed(&[0; 33]).err(), Some(Blake2Error::KeyTooLong));
    assert_eq!(blake2sp_keyed(b"", &[0; 1000]).err(), Some(Blake2Error::KeyTooLong));
    // Empty key on the keyed constructors means unkeyed.
    assert_eq!(blake2sp_keyed(b"abc", &[]).unwrap(), blake2sp(b"abc"));
    assert_eq!(blake2s(b"abc", &[], 32).unwrap().as_bytes(), &blake2s_256(b"abc"));
    let d = blake2s(b"abc", &[], 7).unwrap();
    assert_eq!(d.len(), 7);
    assert!(!d.is_empty());
}

#[test]
fn states_are_cloneable_mid_stream() {
    let data = gen_bytes(3000);
    let mut a = Sha256::new();
    a.update(&data[..1234]);
    let mut b = a.clone();
    a.update(&data[1234..]);
    b.update(&data[1234..]);
    assert_eq!(a.finalize(), b.finalize());
    let mut s = Blake2sp::new();
    s.update(&data[..700]);
    let mut t = s.clone();
    s.update(&data[700..]);
    t.update(&data[700..]);
    assert_eq!(s.finalize(), blake2sp(&data));
    assert_eq!(t.finalize(), blake2sp(&data));
}
