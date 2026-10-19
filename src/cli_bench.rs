// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sediment b`: benchmark.
//!
//! ```text
//! sediment b [ITERATIONS] [-md<DICT>] [-ds<SIZE>] [-mm=<CODEC|lzma|*>]...
//! ```
//!
//! * `ITERATIONS`: passes per test, 1..=1000 (default 2).
//! * `-md<DICT>`: LZMA dictionary, either a power-of-two exponent (`-md22`) or
//!   a size with a `b`/`k`/`m` suffix rounded up to a power of two
//!   (`-md4m`); 2^16..=2^26 (default 2^22).
//! * `-ds<SIZE>`: benchmark data size (`b`/`k`/`m` suffix allowed),
//!   1 KiB..=256 MiB (default: the dictionary size).
//! * `-mm=<NAME>` (or `-mm<NAME>`), repeatable: `lzma` selects the LZMA rating
//!   table, a codec name from [`crate::bench::Codec::parse`] selects a row of
//!   the throughput table, `*` selects everything. Default: everything.
//!
//! Output: the LZMA rating table ([`crate::bench::format_lzma_table`])
//! followed by the codec throughput table
//! ([`crate::bench::format_codec_table`]). Exit codes: 0 success, 1 a codec
//! failed or did not round-trip, 2 usage error or output failure.

use std::ffi::OsString;
use std::io::{self, Write};

use crate::bench::{
    all_codecs, bench_codec, format_codec_table, format_lzma_table, generate_bench_data, lzma_bench_pass, BenchError,
    Codec, MAX_DATA_SIZE, MAX_DICT_BITS, MAX_ITERATIONS, MIN_DATA_SIZE, MIN_DICT_BITS,
};

/// Seed for the benchmark data generator.
pub const BENCH_SEED: u64 = 0x5EDD_1E47_B3AC_0001;

/// Parsed `b` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchArgs {
    pub iterations: u32,
    pub dict_bits: u8,
    pub data_size: usize,
    /// Run the LZMA rating table.
    pub lzma_rating: bool,
    /// Rows of the codec table, in table order.
    pub codecs: Vec<Codec>,
}

fn parse_size(s: &str) -> Option<u64> {
    let (digits, mult) = match s.as_bytes().last()? {
        b'b' | b'B' => (&s[..s.len() - 1], 1u64),
        b'k' | b'K' => (&s[..s.len() - 1], 1 << 10),
        b'm' | b'M' => (&s[..s.len() - 1], 1 << 20),
        _ => return None,
    };
    if digits.is_empty() || digits.len() > 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

fn parse_dict(s: &str) -> Result<u8, BenchError> {
    let bits = if !s.is_empty() && s.len() <= 2 && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse::<u8>().map_err(|_| BenchError::InvalidOptions)?
    } else {
        let n = parse_size(s).ok_or(BenchError::InvalidOptions)?;
        if n == 0 {
            return Err(BenchError::InvalidOptions);
        }
        let bits = 64 - (n - 1).leading_zeros();
        u8::try_from(bits).map_err(|_| BenchError::InvalidOptions)?
    };
    if (MIN_DICT_BITS..=MAX_DICT_BITS).contains(&bits) { Ok(bits) } else { Err(BenchError::InvalidOptions) }
}

/// Parse the arguments after `b`.
pub fn parse_bench_args(args: &[OsString]) -> Result<BenchArgs, BenchError> {
    let mut iterations: Option<u32> = None;
    let mut dict_bits = 22u8;
    let mut data_size: Option<usize> = None;
    let mut selectors: Vec<String> = Vec::new();
    for a in args {
        let s = a.to_str().ok_or(BenchError::InvalidOptions)?;
        if let Some(rest) = s.strip_prefix("-md") {
            dict_bits = parse_dict(rest)?;
        } else if let Some(rest) = s.strip_prefix("-ds") {
            let n = parse_size(rest)
                .or_else(|| if rest.bytes().all(|b| b.is_ascii_digit()) && rest.len() <= 12 { rest.parse().ok() } else { None })
                .ok_or(BenchError::InvalidOptions)?;
            let n = usize::try_from(n).map_err(|_| BenchError::InvalidOptions)?;
            if !(MIN_DATA_SIZE..=MAX_DATA_SIZE).contains(&n) {
                return Err(BenchError::InvalidOptions);
            }
            data_size = Some(n);
        } else if let Some(rest) = s.strip_prefix("-mm") {
            let rest = rest.strip_prefix('=').unwrap_or(rest);
            if rest.is_empty() {
                return Err(BenchError::InvalidOptions);
            }
            selectors.push(rest.to_string());
        } else if !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit()) && iterations.is_none() {
            let n: u32 = s.parse().map_err(|_| BenchError::InvalidOptions)?;
            if !(1..=MAX_ITERATIONS).contains(&n) {
                return Err(BenchError::InvalidOptions);
            }
            iterations = Some(n);
        } else {
            return Err(BenchError::InvalidOptions);
        }
    }
    let (lzma_rating, codecs) = if selectors.is_empty() || selectors.iter().any(|s| s == "*") {
        (true, all_codecs())
    } else {
        let mut rating = false;
        let mut wanted = Vec::new();
        for s in &selectors {
            let c = Codec::parse(s)?;
            if c == Codec::Lzma {
                rating = true;
            }
            if !wanted.contains(&c) {
                wanted.push(c);
            }
        }
        (rating, all_codecs().into_iter().filter(|c| wanted.contains(c)).collect())
    };
    Ok(BenchArgs {
        iterations: iterations.unwrap_or(2),
        dict_bits,
        data_size: data_size.unwrap_or(1usize << dict_bits),
        lzma_rating,
        codecs,
    })
}

fn describe(e: BenchError) -> &'static str {
    match e {
        BenchError::InvalidOptions => "invalid benchmark options",
        BenchError::LimitExceeded => "limit exceeded",
        BenchError::Allocation => "out of memory",
        BenchError::Codec => "codec error",
        BenchError::Mismatch => "round-trip mismatch",
    }
}

/// Run `sediment b` and return its exit code. Results are written to stdout
/// as each table completes.
pub fn run_bench(args: &[OsString]) -> i32 {
    let mut err = io::stderr().lock();
    let a = match parse_bench_args(args) {
        Ok(a) => a,
        Err(_) => {
            let _ = writeln!(err, "sediment: usage: sediment b [ITERATIONS] [-md<DICT>] [-ds<SIZE>] [-mm=<CODEC|lzma|*>]...");
            return 2;
        }
    };
    let data = match generate_bench_data(a.data_size, 1usize << a.dict_bits, BENCH_SEED) {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(err, "sediment: {}", describe(e));
            return 2;
        }
    };
    let mut out = io::stdout().lock();
    let mut emit = |text: &str| out.write_all(text.as_bytes()).and_then(|_| out.flush()).is_ok();
    let mut code = 0;
    if a.lzma_rating {
        let mut passes = Vec::new();
        for _ in 0..a.iterations {
            match lzma_bench_pass(&data, a.dict_bits) {
                Ok(p) => passes.push(p),
                Err(e) => {
                    let _ = writeln!(err, "sediment: LZMA: {}", describe(e));
                    code = 1;
                    break;
                }
            }
        }
        if !passes.is_empty() && !emit(&(format_lzma_table(a.dict_bits, &passes) + "\n")) {
            return 2;
        }
    }
    if !a.codecs.is_empty() {
        let mut results = Vec::new();
        for &c in &a.codecs {
            match bench_codec(c, &data, a.iterations, a.dict_bits) {
                Ok(r) => results.push(r),
                Err(e) => {
                    let _ = writeln!(err, "sediment: {}: {}", c.name(), describe(e));
                    code = 1;
                }
            }
        }
        if !emit(&format_codec_table(&results)) {
            return 2;
        }
    }
    code
}
