// SPDX-License-Identifier: MIT OR Apache-2.0
//! AES tests: FIPS-197 appendix C known answers, NIST SP 800-38A CBC/CTR
//! vectors (F.2, F.5), WinZip counter behaviour, streaming equivalence, and
//! a differential check against an independent byte-oriented textbook AES
//! implemented below (no tables, straight from FIPS-197 section 5).

use sediment_engine::aes::{
    AES_BLOCK_LEN, Aes, AesCbc, AesCtr, AesError, CounterOrder, aes_cbc_decrypt, aes_cbc_encrypt,
    aes_ctr_apply,
};

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn block(s: &str) -> [u8; 16] {
    unhex(s).try_into().unwrap()
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

// ---------------------------------------------------------------------------
// Reference AES, deliberately naive (FIPS-197 section 5.1 / 5.3).

fn xt(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xt(a);
        b >>= 1;
    }
    p
}
fn sbox(x: u8) -> u8 {
    // Inverse by brute force, then affine transform.
    let inv = if x == 0 { 0 } else { (1..=255u8).find(|&y| mul(x, y) == 1).unwrap() };
    let mut r = 0x63u8;
    for i in 0..8 {
        let bit = ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8)) ^ (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8))) & 1;
        r ^= bit << i;
    }
    r
}

struct RefAes {
    w: Vec<[u8; 4]>,
    nr: usize,
    s: [u8; 256],
    si: [u8; 256],
}

impl RefAes {
    fn new(key: &[u8]) -> Self {
        static TABLES: std::sync::OnceLock<([u8; 256], [u8; 256])> = std::sync::OnceLock::new();
        let (s, si) = *TABLES.get_or_init(|| {
            let mut s = [0u8; 256];
            for x in 0..=255u8 {
                s[x as usize] = sbox(x);
            }
            let mut si = [0u8; 256];
            for x in 0..=255u8 {
                si[s[x as usize] as usize] = x;
            }
            (s, si)
        });
        let nk = key.len() / 4;
        let nr = nk + 6;
        let mut w: Vec<[u8; 4]> = key.chunks(4).map(|c| [c[0], c[1], c[2], c[3]]).collect();
        let mut rcon = 1u8;
        for i in nk..4 * (nr + 1) {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = [s[t[1] as usize] ^ rcon, s[t[2] as usize], s[t[3] as usize], s[t[0] as usize]];
                rcon = xt(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|v| s[v as usize]);
            }
            let p = w[i - nk];
            w.push([p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]]);
        }
        Self { w, nr, s, si }
    }
    fn ark(&self, st: &mut [u8; 16], r: usize) {
        for c in 0..4 {
            for row in 0..4 {
                st[4 * c + row] ^= self.w[4 * r + c][row];
            }
        }
    }
    fn enc(&self, inp: [u8; 16]) -> [u8; 16] {
        let mut st = inp;
        self.ark(&mut st, 0);
        for r in 1..=self.nr {
            st = st.map(|v| self.s[v as usize]);
            let old = st;
            for c in 0..4 {
                for row in 0..4 {
                    st[4 * c + row] = old[4 * ((c + row) % 4) + row];
                }
            }
            if r != self.nr {
                let old = st;
                for c in 0..4 {
                    let a = &old[4 * c..4 * c + 4];
                    st[4 * c] = mul(a[0], 2) ^ mul(a[1], 3) ^ a[2] ^ a[3];
                    st[4 * c + 1] = a[0] ^ mul(a[1], 2) ^ mul(a[2], 3) ^ a[3];
                    st[4 * c + 2] = a[0] ^ a[1] ^ mul(a[2], 2) ^ mul(a[3], 3);
                    st[4 * c + 3] = mul(a[0], 3) ^ a[1] ^ a[2] ^ mul(a[3], 2);
                }
            }
            self.ark(&mut st, r);
        }
        st
    }
    fn dec(&self, inp: [u8; 16]) -> [u8; 16] {
        let mut st = inp;
        self.ark(&mut st, self.nr);
        for r in (0..self.nr).rev() {
            let old = st;
            for c in 0..4 {
                for row in 0..4 {
                    st[4 * ((c + row) % 4) + row] = old[4 * c + row];
                }
            }
            st = st.map(|v| self.si[v as usize]);
            self.ark(&mut st, r);
            if r != 0 {
                let old = st;
                for c in 0..4 {
                    let a = &old[4 * c..4 * c + 4];
                    st[4 * c] = mul(a[0], 14) ^ mul(a[1], 11) ^ mul(a[2], 13) ^ mul(a[3], 9);
                    st[4 * c + 1] = mul(a[0], 9) ^ mul(a[1], 14) ^ mul(a[2], 11) ^ mul(a[3], 13);
                    st[4 * c + 2] = mul(a[0], 13) ^ mul(a[1], 9) ^ mul(a[2], 14) ^ mul(a[3], 11);
                    st[4 * c + 3] = mul(a[0], 11) ^ mul(a[1], 13) ^ mul(a[2], 9) ^ mul(a[3], 14);
                }
            }
        }
        st
    }
}

// ---------------------------------------------------------------------------

#[test]
fn fips197_appendix_c() {
    let pt = block("00112233445566778899aabbccddeeff");
    let cases = [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ];
    for (key, ct) in cases {
        let aes = Aes::new(&unhex(key)).unwrap();
        let mut b = pt;
        aes.encrypt_block(&mut b);
        assert_eq!(b, block(ct), "encrypt key {key}");
        aes.decrypt_block(&mut b);
        assert_eq!(b, pt, "decrypt key {key}");
    }
}

#[test]
fn fips197_appendix_b() {
    let aes = Aes::new(&unhex("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
    let mut b = block("3243f6a8885a308d313198a2e0370734");
    aes.encrypt_block(&mut b);
    assert_eq!(b, block("3925841d02dc09fbdc118597196a0b32"));
}

#[test]
fn key_bits_and_bad_keys() {
    assert_eq!(Aes::new(&[0; 16]).unwrap().key_bits(), 128);
    assert_eq!(Aes::new(&[0; 24]).unwrap().key_bits(), 192);
    assert_eq!(Aes::new(&[0; 32]).unwrap().key_bits(), 256);
    for n in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
        assert_eq!(Aes::new(&vec![0; n]).unwrap_err(), AesError::InvalidKeyLength, "{n}");
    }
    // Debug output must not contain key material.
    let dbg = format!("{:?}", Aes::new(&[0xab; 16]).unwrap());
    assert!(!dbg.to_lowercase().contains("ab, "), "{dbg}");
}

const SP_PT: &str = "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
                     30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710";
const SP_IV: &str = "000102030405060708090a0b0c0d0e0f";
const SP_CTR: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const K128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const K192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const K256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

#[test]
fn sp800_38a_cbc() {
    let cases = [
        (K128, "7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2
                73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7"),
        (K192, "4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a
                571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd"),
        (K256, "f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d
                39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b"),
    ];
    for (key, ct) in cases {
        let mut buf = unhex(SP_PT);
        aes_cbc_encrypt(&unhex(key), &unhex(SP_IV), &mut buf).unwrap();
        assert_eq!(buf, unhex(ct), "cbc enc {key}");
        aes_cbc_decrypt(&unhex(key), &unhex(SP_IV), &mut buf).unwrap();
        assert_eq!(buf, unhex(SP_PT), "cbc dec {key}");

        // Streaming block-by-block equals one-shot.
        let mut s = AesCbc::new(Aes::new(&unhex(key)).unwrap(), &unhex(SP_IV)).unwrap();
        let mut buf = unhex(SP_PT);
        for chunk in buf.chunks_mut(16) {
            s.encrypt(chunk).unwrap();
        }
        assert_eq!(buf, unhex(ct));
        assert_eq!(s.chain().to_vec(), unhex(ct)[48..].to_vec());
        let mut d = AesCbc::new(Aes::new(&unhex(key)).unwrap(), &unhex(SP_IV)).unwrap();
        d.decrypt(&mut buf[..32]).unwrap();
        d.decrypt(&mut buf[32..48]).unwrap();
        d.decrypt(&mut buf[48..]).unwrap();
        assert_eq!(buf, unhex(SP_PT));
    }
}

#[test]
fn sp800_38a_ctr() {
    let cases = [
        (K128, "874d6191b620e3261bef6864990db6ce 9806f66b7970fdff8617187bb9fffdff
                5ae4df3edbd5d35e5b4f09020db03eab 1e031dda2fbe03d1792170a0f3009cee"),
        (K192, "1abc932417521ca24f2b0459fe7e6e0b 090339ec0aa6faefd5ccc2c6f4ce8e94
                1e36b26bd1ebc670d1bd1d665620abf7 4f78a7f6d29809585a97daec58c6b050"),
        (K256, "601ec313775789a5b7a7f504bbf3d228 f443e3ca4d62b59aca84e990cacaf5c5
                2b0930daa23de94ce87017ba2d84988d dfc9c58db67aada613c2dd08457941a6"),
    ];
    for (key, ct) in cases {
        let mut buf = unhex(SP_PT);
        aes_ctr_apply(&unhex(key), &unhex(SP_CTR), CounterOrder::BigEndian, &mut buf).unwrap();
        assert_eq!(buf, unhex(ct), "ctr {key}");
        // Odd chunk sizes, crossing block boundaries.
        for split in [1usize, 3, 7, 15, 16, 17, 33] {
            let mut s =
                AesCtr::new(Aes::new(&unhex(key)).unwrap(), &unhex(SP_CTR), CounterOrder::BigEndian)
                    .unwrap();
            let mut buf = unhex(ct);
            for chunk in buf.chunks_mut(split) {
                s.apply_keystream(chunk);
            }
            assert_eq!(buf, unhex(SP_PT), "ctr split {split}");
        }
        // Partial final block: prefix of the full output.
        let mut short = unhex(SP_PT)[..37].to_vec();
        aes_ctr_apply(&unhex(key), &unhex(SP_CTR), CounterOrder::BigEndian, &mut short).unwrap();
        assert_eq!(short, unhex(ct)[..37].to_vec());
    }
}

#[test]
fn ctr_counter_increment_and_wrap() {
    let aes = Aes::new(&[7; 16]).unwrap();
    // Big-endian: ff..ff wraps to 00..00; carry propagates.
    let mut be = AesCtr::new(aes.clone(), &[0xff; 16], CounterOrder::BigEndian).unwrap();
    be.apply_keystream(&mut [0u8; 16]);
    assert_eq!(be.counter(), [0; 16]);
    let mut c = [0u8; 16];
    c[15] = 0xff;
    let mut be = AesCtr::new(aes.clone(), &c, CounterOrder::BigEndian).unwrap();
    be.apply_keystream(&mut [0u8; 1]);
    let mut want = [0u8; 16];
    want[14] = 1;
    assert_eq!(be.counter(), want);

    // WinZip: little-endian, starts at 1.
    let mut wz = AesCtr::winzip(aes.clone());
    let mut want = [0u8; 16];
    want[0] = 1;
    assert_eq!(wz.counter(), want);
    let mut data = vec![0u8; 16 * 300];
    wz.apply_keystream(&mut data);
    let mut want = [0u8; 16];
    want[0] = 0x2d; // 301 = 0x012d
    want[1] = 0x01;
    assert_eq!(wz.counter(), want);
    // Keystream block i equals E(LE128(i+1)).
    for i in [0usize, 1, 254, 255, 256, 299] {
        let mut ctr = [0u8; 16];
        ctr[..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
        aes.encrypt_block(&mut ctr);
        assert_eq!(&data[16 * i..16 * i + 16], &ctr, "winzip block {i}");
    }
    let mut le = AesCtr::new(aes, &[0xff; 16], CounterOrder::LittleEndian).unwrap();
    le.apply_keystream(&mut [0u8; 5]);
    assert_eq!(le.counter(), [0; 16]);
}

#[test]
fn mode_length_errors() {
    let k = [0u8; 16];
    for n in [1usize, 15, 17, 31] {
        let mut d = vec![0u8; n];
        assert_eq!(aes_cbc_encrypt(&k, &[0; 16], &mut d), Err(AesError::InvalidDataLength));
        assert_eq!(aes_cbc_decrypt(&k, &[0; 16], &mut d), Err(AesError::InvalidDataLength));
    }
    for n in [0usize, 8, 15, 17, 32] {
        assert_eq!(aes_cbc_encrypt(&k, &vec![0; n], &mut []), Err(AesError::InvalidIvLength));
        assert_eq!(
            aes_ctr_apply(&k, &vec![0; n], CounterOrder::BigEndian, &mut []),
            Err(AesError::InvalidIvLength)
        );
    }
    assert_eq!(aes_cbc_encrypt(&[0; 20], &[0; 16], &mut []), Err(AesError::InvalidKeyLength));
    // Empty data is fine.
    aes_cbc_decrypt(&k, &[0; 16], &mut []).unwrap();
    aes_ctr_apply(&k, &[0; 16], CounterOrder::LittleEndian, &mut []).unwrap();
}

#[test]
fn differential_against_reference() {
    for (i, klen) in [16usize, 24, 32].iter().cycle().take(90).enumerate() {
        let key = gen_bytes(*klen, 100 + i as u32);
        let r = RefAes::new(&key);
        let aes = Aes::new(&key).unwrap();
        for j in 0..8 {
            let pt: [u8; AES_BLOCK_LEN] = gen_bytes(16, 1000 * i as u32 + j).try_into().unwrap();
            let mut b = pt;
            aes.encrypt_block(&mut b);
            assert_eq!(b, r.enc(pt), "enc key {i} block {j}");
            assert_eq!(r.dec(b), pt, "ref round trip");
            aes.decrypt_block(&mut b);
            assert_eq!(b, pt, "dec key {i} block {j}");
            // Decrypt of arbitrary input also matches the reference.
            let mut x = pt;
            aes.decrypt_block(&mut x);
            assert_eq!(x, r.dec(pt));
        }
    }
}

#[test]
fn cbc_round_trip_large() {
    let key = gen_bytes(32, 9);
    let iv = gen_bytes(16, 10);
    let pt = gen_bytes(16 * 1000, 11);
    let mut buf = pt.clone();
    aes_cbc_encrypt(&key, &iv, &mut buf).unwrap();
    assert_ne!(buf, pt);
    aes_cbc_decrypt(&key, &iv, &mut buf).unwrap();
    assert_eq!(buf, pt);
}
