// SPDX-License-Identifier: MIT OR Apache-2.0
//! Benchmark engine behind `sediment b`: a deterministic test-data generator,
//! an LZMA compress/decompress pass with MIPS-style ratings, and a per-codec
//! throughput table (every `hash_multi` method, AES-256-CBC, Deflate, BZip2,
//! LZMA).
//!
//! # Data generator
//! [`generate_bench_data`] produces LZ-shaped data from a xorshift64* stream:
//! a mix of short literal runs drawn from a skewed alphabet and back-references
//! whose distance is log-uniform within the dictionary window. The same
//! `(len, window, seed)` always gives the same bytes on every platform, so
//! compressed sizes are reproducible; only timings vary.
//!
//! # Ratings
//! Sediment's ratings are a CPU-independent "work done per second" figure in
//! the spirit of 7-Zip's MIPS rating, but with Sediment's own cost model
//! (they are not numerically comparable with 7-Zip results):
//!
//! * compression: `unpacked * (COMPRESS_BASE + COMPRESS_PER_DICT_BIT * (dict_bits - 16))`
//!   instructions;
//! * decompression: `unpacked * DECOMPRESS_PER_BYTE + packed * DECOMPRESS_PER_PACKED_BYTE`
//!   instructions;
//!
//! divided by elapsed seconds and 10^6. Every pass verifies the round trip;
//! a mismatch is an error, never a rating.
//!
//! All work is single-threaded. Sizes are capped by [`MAX_DATA_SIZE`] and
//! dictionaries by [`MIN_DICT_BITS`]..=[`MAX_DICT_BITS`].

use std::time::{Duration, Instant};

use crate::aes::{Aes, AesCbc};
use crate::bzip2_decode::decode_bzip2;
use crate::bzip2_encode::encode_bzip2;
use crate::deflate_compress::{deflate_bound, deflate_compress};
use crate::hash_multi::{ALL_METHODS, HashMethod, Hasher};
use crate::inflate::inflate_raw;
use crate::lzma_decode::decode_lzma_raw;
use crate::lzma_encode::{effective_dictionary_size, encode_lzma_raw, LzmaEncoderOptions};
use crate::lzma_properties::LzmaProperties;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchError {
    /// Dictionary size, data size, iteration count or codec name out of range.
    InvalidOptions,
    /// A configured limit was exceeded.
    LimitExceeded,
    Allocation,
    /// A codec reported an error on benchmark data.
    Codec,
    /// Decoded data differs from the input.
    Mismatch,
}

/// Largest benchmark data buffer.
pub const MAX_DATA_SIZE: usize = 256 << 20;
/// Smallest benchmark data buffer.
pub const MIN_DATA_SIZE: usize = 1 << 10;
/// Dictionary size range, as powers of two.
pub const MIN_DICT_BITS: u8 = 16;
pub const MAX_DICT_BITS: u8 = 26;
/// Maximum passes per run.
pub const MAX_ITERATIONS: u32 = 1000;

/// Rating cost model (see the module docs).
pub const COMPRESS_BASE: u64 = 800;
pub const COMPRESS_PER_DICT_BIT: u64 = 25;
pub const DECOMPRESS_PER_BYTE: u64 = 12;
pub const DECOMPRESS_PER_PACKED_BYTE: u64 = 160;

/// xorshift64* pseudo-random generator (deterministic, not cryptographic).
#[derive(Debug, Clone)]
pub struct BenchRng(u64);

impl BenchRng {
    pub fn new(seed: u64) -> BenchRng {
        // Zero is a fixed point of xorshift; remap it.
        BenchRng(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Deterministic compressible data: `len` bytes whose back-references stay
/// within `window` bytes. `len` must be in [`MIN_DATA_SIZE`]..=[`MAX_DATA_SIZE`]
/// and `window` at least 1.
pub fn generate_bench_data(len: usize, window: usize, seed: u64) -> Result<Vec<u8>, BenchError> {
    if !(MIN_DATA_SIZE..=MAX_DATA_SIZE).contains(&len) || window == 0 {
        return Err(BenchError::InvalidOptions);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| BenchError::Allocation)?;
    let mut rng = BenchRng::new(seed);
    while out.len() < len {
        let r = rng.next_u64();
        let pos = out.len();
        if pos >= 16 && r & 1 != 0 {
            // Back-reference: distance log-uniform in 1..=min(pos, window).
            let limit = pos.min(window) as u64;
            let max_bits = 64 - limit.leading_zeros() as u64; // 1..=64
            let bits = 1 + (r >> 2) % max_bits;
            let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
            let dist = (1 + ((r >> 16) & mask)).min(limit) as usize;
            // Lengths skew short: 2..=33, sometimes up to 273.
            let mut mlen = 2 + ((r >> 8) & 31) as usize;
            if (r >> 13) & 7 == 0 {
                mlen += ((r >> 40) & 0xFF) as usize;
            }
            let mlen = mlen.min(len - pos);
            for i in 0..mlen {
                let b = out[pos + i - dist];
                out.push(b);
            }
        } else {
            let run = 1 + ((r >> 2) & 15) as usize;
            for _ in 0..run.min(len - pos) {
                let x = rng.next_u64();
                // Skewed alphabet: AND of two uniform bytes favours low bits,
                // offset into the printable range most of the time.
                let b = (x as u8) & ((x >> 8) as u8);
                out.push(if x >> 63 == 0 { b'a'.wrapping_add(b % 26) } else { b });
            }
        }
    }
    Ok(out)
}

/// Timings of one LZMA round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzmaPass {
    pub unpacked: u64,
    pub packed: u64,
    pub compress: Duration,
    pub decompress: Duration,
}

/// Encoder options used by the benchmark: preset 5 (binary tree, optimal
/// parsing) with the dictionary set to `2^dict_bits`.
pub fn bench_lzma_options(dict_bits: u8) -> Result<LzmaEncoderOptions, BenchError> {
    if !(MIN_DICT_BITS..=MAX_DICT_BITS).contains(&dict_bits) {
        return Err(BenchError::InvalidOptions);
    }
    let mut opts = LzmaEncoderOptions::preset(5).map_err(|_| BenchError::InvalidOptions)?;
    opts.dictionary_size = 1u32 << dict_bits;
    Ok(opts)
}

/// Compress and decompress `data` once with raw LZMA, verifying the result.
pub fn lzma_bench_pass(data: &[u8], dict_bits: u8) -> Result<LzmaPass, BenchError> {
    if data.len() > MAX_DATA_SIZE {
        return Err(BenchError::LimitExceeded);
    }
    let opts = bench_lzma_options(dict_bits)?;
    let t0 = Instant::now();
    let packed = encode_lzma_raw(data, &opts, false).map_err(|e| match e {
        crate::lzma_encode::LzmaEncodeError::Allocation => BenchError::Allocation,
        _ => BenchError::Codec,
    })?;
    let compress = t0.elapsed();
    let props = LzmaProperties {
        lc: opts.lc,
        lp: opts.lp,
        pb: opts.pb,
        dictionary_size: effective_dictionary_size(opts.dictionary_size, data.len()),
    };
    let t1 = Instant::now();
    let (out, _) = decode_lzma_raw(&packed, props, Some(data.len() as u64), 1u64 << MAX_DICT_BITS, data.len())
        .map_err(|_| BenchError::Codec)?;
    let decompress = t1.elapsed();
    if out != data {
        return Err(BenchError::Mismatch);
    }
    Ok(LzmaPass { unpacked: data.len() as u64, packed: packed.len() as u64, compress, decompress })
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64().max(1e-9)
}

/// Compression rating in MIPS (see the module docs).
pub fn compress_rating(dict_bits: u8, unpacked: u64, elapsed: Duration) -> u64 {
    let per = COMPRESS_BASE + COMPRESS_PER_DICT_BIT * (dict_bits.saturating_sub(16) as u64);
    ((unpacked as f64 * per as f64) / secs(elapsed) / 1e6) as u64
}

/// Decompression rating in MIPS (see the module docs).
pub fn decompress_rating(unpacked: u64, packed: u64, elapsed: Duration) -> u64 {
    let work = unpacked as f64 * DECOMPRESS_PER_BYTE as f64 + packed as f64 * DECOMPRESS_PER_PACKED_BYTE as f64;
    (work / secs(elapsed) / 1e6) as u64
}

/// Throughput in KiB/s.
pub fn speed_kib(bytes: u64, elapsed: Duration) -> u64 {
    (bytes as f64 / 1024.0 / secs(elapsed)) as u64
}

/// Throughput in MB/s (10^6 bytes).
pub fn speed_mb(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 / 1e6 / secs(elapsed)
}

/// Render the LZMA rating table for `passes` (one row per pass, then the
/// average and the combined total rating).
pub fn format_lzma_table(dict_bits: u8, passes: &[LzmaPass]) -> String {
    let mut s = String::new();
    let data_len = passes.first().map(|p| p.unpacked).unwrap_or(0);
    s.push_str(&format!(
        "LZMA: 1 thread, dictionary 2^{dict_bits} ({} KiB), {data_len} bytes per pass\n\n",
        (1u64 << dict_bits) / 1024
    ));
    let row = |label: &str, cs: &str, cr: &str, ds: &str, dr: &str| {
        let line = format!("{label:<4} {cs:>10} {cr:>7}  | {ds:>10} {dr:>7}");
        format!("{}\n", line.trim_end())
    };
    s.push_str(&format!("{:<25}| Decompressing\n", "      Compressing"));
    s.push_str(&row("Dict", "Speed", "Rating", "Speed", "Rating"));
    s.push_str(&row("", "KiB/s", "MIPS", "KiB/s", "MIPS"));
    s.push('\n');
    let mut sum = [0u64; 4];
    for p in passes {
        let v = [
            speed_kib(p.unpacked, p.compress),
            compress_rating(dict_bits, p.unpacked, p.compress),
            speed_kib(p.unpacked, p.decompress),
            decompress_rating(p.unpacked, p.packed, p.decompress),
        ];
        for (a, b) in sum.iter_mut().zip(v) {
            *a = a.saturating_add(b);
        }
        let t = v.map(|x| x.to_string());
        s.push_str(&row(&format!("{dict_bits}:"), &t[0], &t[1], &t[2], &t[3]));
    }
    let n = passes.len().max(1) as u64;
    let avg = sum.map(|x| x / n);
    let t = avg.map(|x| x.to_string());
    s.push_str(&"-".repeat(46));
    s.push('\n');
    s.push_str(&row("Avr:", &t[0], &t[1], &t[2], &t[3]));
    s.push_str(&format!("Tot: {:>10} {:>7}\n", "", (avg[1] + avg[3]) / 2));
    if let Some(p) = passes.first()
        && p.unpacked > 0
    {
        s.push_str(&format!("Ratio: {:.2}% ({} -> {} bytes)\n", p.packed as f64 * 100.0 / p.unpacked as f64, p.unpacked, p.packed));
    }
    s
}

/// A codec in the throughput table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Hash(HashMethod),
    Aes256Cbc,
    Deflate,
    Bzip2,
    Lzma,
}

/// Every codec, in table order.
pub fn all_codecs() -> Vec<Codec> {
    let mut v: Vec<Codec> = ALL_METHODS.iter().map(|&m| Codec::Hash(m)).collect();
    v.extend([Codec::Aes256Cbc, Codec::Deflate, Codec::Bzip2, Codec::Lzma]);
    v
}

impl Codec {
    pub fn name(self) -> &'static str {
        match self {
            Codec::Hash(m) => m.name(),
            Codec::Aes256Cbc => "AES256CBC",
            Codec::Deflate => "Deflate",
            Codec::Bzip2 => "BZip2",
            Codec::Lzma => "LZMA",
        }
    }

    /// Case-insensitive name lookup (hash names as in `hash_multi`; also
    /// `AES256CBC`/`AES`, `Deflate`, `BZip2`, `LZMA`).
    pub fn parse(name: &str) -> Result<Codec, BenchError> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "aes" | "aes256cbc" | "aes-256-cbc" => Ok(Codec::Aes256Cbc),
            "deflate" => Ok(Codec::Deflate),
            "bzip2" => Ok(Codec::Bzip2),
            "lzma" => Ok(Codec::Lzma),
            _ => HashMethod::parse(name).map(Codec::Hash).map_err(|_| BenchError::InvalidOptions),
        }
    }
}

/// Accumulated timings of one codec over all iterations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecResult {
    pub codec: Codec,
    /// Input bytes per iteration.
    pub unpacked: u64,
    /// Output bytes per iteration for compressors.
    pub packed: Option<u64>,
    pub iterations: u32,
    /// Total encode (or hash) time.
    pub encode: Duration,
    /// Total decode time, for reversible codecs.
    pub decode: Option<Duration>,
}

fn check_eq(a: &[u8], b: &[u8]) -> Result<(), BenchError> {
    if a == b { Ok(()) } else { Err(BenchError::Mismatch) }
}

/// Run `codec` over `data` `iterations` times, verifying round trips.
/// `dict_bits` sets the LZMA dictionary.
pub fn bench_codec(codec: Codec, data: &[u8], iterations: u32, dict_bits: u8) -> Result<CodecResult, BenchError> {
    if !(1..=MAX_ITERATIONS).contains(&iterations) || !(MIN_DICT_BITS..=MAX_DICT_BITS).contains(&dict_bits) {
        return Err(BenchError::InvalidOptions);
    }
    if data.len() > MAX_DATA_SIZE {
        return Err(BenchError::LimitExceeded);
    }
    let mut res = CodecResult {
        codec,
        unpacked: data.len() as u64,
        packed: None,
        iterations,
        encode: Duration::ZERO,
        decode: None,
    };
    let mut decode = Duration::ZERO;
    let mut first_digest = None;
    for _ in 0..iterations {
        match codec {
            Codec::Hash(m) => {
                let t = Instant::now();
                let mut h = Hasher::new(m);
                h.update(data);
                let d = h.finalize();
                res.encode += t.elapsed();
                // Repeated runs must agree (guards against a broken state).
                if *first_digest.get_or_insert(d) != d {
                    return Err(BenchError::Mismatch);
                }
            }
            Codec::Aes256Cbc => {
                let n = data.len() & !15;
                let mut buf = Vec::new();
                buf.try_reserve_exact(n).map_err(|_| BenchError::Allocation)?;
                buf.extend_from_slice(&data[..n]);
                let key: [u8; 32] = core::array::from_fn(|i| i as u8);
                let iv = [0x5Au8; 16];
                let t = Instant::now();
                let cipher = Aes::new(&key).map_err(|_| BenchError::Codec)?;
                AesCbc::new(cipher.clone(), &iv).and_then(|mut c| c.encrypt(&mut buf)).map_err(|_| BenchError::Codec)?;
                res.encode += t.elapsed();
                let t = Instant::now();
                AesCbc::new(cipher, &iv).and_then(|mut c| c.decrypt(&mut buf)).map_err(|_| BenchError::Codec)?;
                decode += t.elapsed();
                check_eq(&buf, &data[..n])?;
                res.unpacked = n as u64;
                res.packed = Some(n as u64);
            }
            Codec::Deflate => {
                let bound = deflate_bound(data.len()).ok_or(BenchError::LimitExceeded)?;
                let t = Instant::now();
                let packed = deflate_compress(data, 6, bound).map_err(|_| BenchError::Codec)?;
                res.encode += t.elapsed();
                let t = Instant::now();
                let out = inflate_raw(&packed, data.len(), usize::MAX).map_err(|_| BenchError::Codec)?;
                decode += t.elapsed();
                check_eq(&out, data)?;
                res.packed = Some(packed.len() as u64);
            }
            Codec::Bzip2 => {
                let bound = data.len().checked_add(data.len() / 2 + 1024).ok_or(BenchError::LimitExceeded)?;
                let t = Instant::now();
                let packed = encode_bzip2(data, 9, bound).map_err(|_| BenchError::Codec)?;
                res.encode += t.elapsed();
                let t = Instant::now();
                let out = decode_bzip2(&packed, data.len()).map_err(|_| BenchError::Codec)?;
                decode += t.elapsed();
                check_eq(&out, data)?;
                res.packed = Some(packed.len() as u64);
            }
            Codec::Lzma => {
                let p = lzma_bench_pass(data, dict_bits)?;
                res.encode += p.compress;
                decode += p.decompress;
                res.packed = Some(p.packed);
            }
        }
    }
    if !matches!(codec, Codec::Hash(_)) {
        res.decode = Some(decode);
    }
    Ok(res)
}

/// Render the per-codec throughput table.
pub fn format_codec_table(results: &[CodecResult]) -> String {
    let mut s = String::from("Codec           Size   Ratio  Encode MB/s  Decode MB/s\n");
    s.push_str("--------- ---------- ------- ------------ ------------\n");
    for r in results {
        let total = r.unpacked.saturating_mul(r.iterations as u64);
        let ratio = match r.packed {
            Some(p) if r.unpacked > 0 => format!("{:.1}%", p as f64 * 100.0 / r.unpacked as f64),
            _ => String::new(),
        };
        let enc = format!("{:.1}", speed_mb(total, r.encode));
        let dec = r.decode.map(|d| format!("{:.1}", speed_mb(total, d))).unwrap_or_default();
        let line = format!("{:<9} {:>10} {:>7} {:>12} {:>12}", r.codec.name(), r.unpacked, ratio, enc, dec);
        s.push_str(line.trim_end());
        s.push('\n');
    }
    s
}
