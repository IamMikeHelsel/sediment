// SPDX-License-Identifier: MIT OR Apache-2.0
//! BZip2 (`.bz2`) encoder.
//!
//! Implemented from the publicly documented bzip2 format (the bzip2 manual,
//! Joe Tsai's "BZip2 format specification" write-up) and the Burrows-Wheeler
//! 1994 report. No bzip2 or 7-Zip source code was consulted. See
//! `bzip2_decode` for the bitstream layout.
//!
//! Pipeline per block: RLE1 (runs of 4..=255 equal bytes become four bytes
//! plus a count byte), BWT over the cyclic rotations of the block using
//! prefix doubling with counting sorts (O(n log n)), move-to-front with
//! RUNA/RUNB zero-run coding, then Huffman coding with 2..=6 tables chosen
//! by a few rounds of iterative refinement over 50-symbol groups. Code
//! lengths are limited to 17 bits. The output aims for correctness, not the
//! best compression ratio.
//!
//! Levels 1..=9 select a block size of `level * 100_000` bytes (the RLE1
//! output of each block is kept below that size, minus a small margin).

use crate::crc32_bzip2::crc32_bzip2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bzip2EncodeError {
    /// Level outside 1..=9.
    InvalidLevel,
    /// Output would exceed the caller's `max_output`.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
}

type R<T> = Result<T, Bzip2EncodeError>;

const GROUP_SIZE: usize = 50;
const MAX_CODE_LEN: u8 = 17;
const REFINE_ITERS: usize = 4;

struct MsbWriter {
    out: Vec<u8>,
    acc: u64,
    nbits: u32,
    max: usize,
}

impl MsbWriter {
    fn put(&mut self, n: u32, v: u64) -> R<()> {
        debug_assert!(n <= 32);
        self.acc = (self.acc << n) | (v & ((1u64 << n) - 1));
        self.nbits += n;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.push((self.acc >> self.nbits) as u8)?;
        }
        Ok(())
    }

    fn push(&mut self, b: u8) -> R<()> {
        if self.out.len() >= self.max {
            return Err(Bzip2EncodeError::LimitExceeded);
        }
        self.out.try_reserve(1).map_err(|_| Bzip2EncodeError::Allocation)?;
        self.out.push(b);
        Ok(())
    }

    fn put48(&mut self, v: u64) -> R<()> {
        self.put(24, v >> 24)?;
        self.put(24, v)
    }

    fn finish(mut self) -> R<Vec<u8>> {
        if self.nbits > 0 {
            let b = (self.acc << (8 - self.nbits)) as u8;
            self.nbits = 0;
            self.push(b)?;
        }
        Ok(self.out)
    }
}

fn alloc<T: Clone>(n: usize, v: T) -> R<Vec<T>> {
    let mut x = Vec::new();
    x.try_reserve_exact(n).map_err(|_| Bzip2EncodeError::Allocation)?;
    x.resize(n, v);
    Ok(x)
}

/// Compresses `input` into a single bzip2 stream at `level` (1..=9),
/// producing at most `max_output` bytes.
pub fn encode_bzip2(input: &[u8], level: u8, max_output: usize) -> R<Vec<u8>> {
    if !(1..=9).contains(&level) {
        return Err(Bzip2EncodeError::InvalidLevel);
    }
    let block_max = level as usize * 100_000 - 19;
    let mut w = MsbWriter { out: Vec::new(), acc: 0, nbits: 0, max: max_output };
    w.put(24, 0x425A68)?;
    w.put(8, (b'0' + level) as u64)?;
    let mut combined: u32 = 0;
    let mut block: Vec<u8> = Vec::new();
    block.try_reserve_exact(block_max.min(input.len() + 8)).map_err(|_| Bzip2EncodeError::Allocation)?;
    let mut pos = 0;
    while pos < input.len() {
        // RLE1 into `block` until full.
        block.clear();
        let start = pos;
        while pos < input.len() {
            let b = input[pos];
            let mut run = 1;
            while run < 255 && pos + run < input.len() && input[pos + run] == b {
                run += 1;
            }
            let cost = if run >= 4 { 5 } else { run };
            if block.len() + cost > block_max {
                break;
            }
            if run >= 4 {
                block.extend_from_slice(&[b, b, b, b, (run - 4) as u8]);
            } else {
                block.resize(block.len() + run, b);
            }
            pos += run;
        }
        let crc = crc32_bzip2(&input[start..pos]);
        combined = combined.rotate_left(1) ^ crc;
        w.put48(0x3141_5926_5359)?;
        w.put(32, crc as u64)?;
        encode_block(&mut w, &block)?;
    }
    w.put48(0x1772_4538_5090)?;
    w.put(32, combined as u64)?;
    w.finish()
}

/// Sorts the cyclic rotations of `s` (prefix doubling, counting sorts).
/// Returns the rotation start indices in sorted order.
fn sort_rotations(s: &[u8]) -> R<Vec<u32>> {
    let n = s.len();
    let mut sa = alloc(n, 0u32)?;
    let mut rank = alloc(n, 0u32)?;
    let mut tmp = alloc(n, 0u32)?;
    let mut cnt = alloc(n.max(256) + 1, 0u32)?;
    // Initial sort by first byte.
    for &b in s {
        cnt[b as usize + 1] += 1;
    }
    for i in 1..=256 {
        cnt[i] += cnt[i - 1];
    }
    for (i, &b) in s.iter().enumerate() {
        let c = &mut cnt[b as usize];
        sa[*c as usize] = i as u32;
        *c += 1;
    }
    // Ranks are bucket numbers (dense).
    let mut classes = 0u32;
    for i in 0..n {
        if i > 0 && s[sa[i] as usize] != s[sa[i - 1] as usize] {
            classes += 1;
        }
        rank[sa[i] as usize] = classes;
    }
    classes += 1;
    let mut k = 1usize;
    while (classes as usize) < n && k < n {
        // Order by second key rank[i + k]: shift the current order back by k.
        for i in 0..n {
            tmp[i] = ((sa[i] as usize + n - k) % n) as u32;
        }
        // Stable counting sort of tmp by rank (first key).
        for c in cnt.iter_mut().take(classes as usize + 1) {
            *c = 0;
        }
        for &t in tmp.iter() {
            cnt[rank[t as usize] as usize + 1] += 1;
        }
        for i in 1..=classes as usize {
            cnt[i] += cnt[i - 1];
        }
        for &t in tmp.iter() {
            let c = &mut cnt[rank[t as usize] as usize];
            sa[*c as usize] = t;
            *c += 1;
        }
        // Recompute ranks into tmp.
        let key = |i: u32| (rank[i as usize], rank[(i as usize + k) % n]);
        let mut c = 0u32;
        tmp[sa[0] as usize] = 0;
        for i in 1..n {
            if key(sa[i]) != key(sa[i - 1]) {
                c += 1;
            }
            tmp[sa[i] as usize] = c;
        }
        std::mem::swap(&mut rank, &mut tmp);
        classes = c + 1;
        k *= 2;
    }
    Ok(sa)
}

/// Builds Huffman code lengths (each >= 1, <= MAX_CODE_LEN) for `freq`.
fn code_lengths(freq: &[u32], out: &mut [u8]) {
    let n = freq.len();
    let mut f: Vec<u64> = freq.iter().map(|&x| x.max(1) as u64).collect();
    loop {
        // Simple O(n^2) Huffman build; n <= 258.
        let mut weight: Vec<u64> = f.clone();
        let mut parent: Vec<usize> = vec![usize::MAX; 2 * n];
        let mut active: Vec<usize> = (0..n).collect();
        weight.resize(2 * n, 0);
        let mut next = n;
        while active.len() > 1 {
            let mut a = 0;
            let mut b = 1;
            if weight[active[b]] < weight[active[a]] {
                std::mem::swap(&mut a, &mut b);
            }
            for i in 2..active.len() {
                let wi = weight[active[i]];
                if wi < weight[active[a]] {
                    b = a;
                    a = i;
                } else if wi < weight[active[b]] {
                    b = i;
                }
            }
            let (na, nb) = (active[a], active[b]);
            weight[next] = weight[na] + weight[nb];
            parent[na] = next;
            parent[nb] = next;
            let (hi, lo) = if a > b { (a, b) } else { (b, a) };
            active.swap_remove(hi);
            active.swap_remove(lo);
            active.push(next);
            next += 1;
        }
        let mut max = 0u8;
        for (i, o) in out.iter_mut().enumerate().take(n) {
            let mut d = 0u8;
            let mut x = i;
            while parent[x] != usize::MAX {
                x = parent[x];
                d += 1;
            }
            *o = d.max(1);
            max = max.max(*o);
        }
        if max <= MAX_CODE_LEN {
            return;
        }
        for x in f.iter_mut() {
            *x = 1 + *x / 2;
        }
    }
}

/// Canonical codes from lengths, matching the decoder's assignment.
fn canonical(lengths: &[u8]) -> Vec<u32> {
    let mut codes = vec![0u32; lengths.len()];
    let mut code = 0u32;
    for len in 1..=MAX_CODE_LEN {
        for (sym, &l) in lengths.iter().enumerate() {
            if l == len {
                codes[sym] = code;
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

fn encode_block(w: &mut MsbWriter, block: &[u8]) -> R<()> {
    let n = block.len();
    let sa = sort_rotations(block)?;
    let mut orig_ptr = 0usize;
    let mut last = alloc(n, 0u8)?;
    for (i, &start) in sa.iter().enumerate() {
        let s = start as usize;
        if s == 0 {
            orig_ptr = i;
        }
        last[i] = block[(s + n - 1) % n];
    }
    drop(sa);

    // Symbol map.
    let mut in_use = [false; 256];
    for &b in block {
        in_use[b as usize] = true;
    }
    let mut unseq_to_seq = [0u8; 256];
    let mut n_in_use = 0usize;
    for i in 0..256 {
        if in_use[i] {
            unseq_to_seq[i] = n_in_use as u8;
            n_in_use += 1;
        }
    }
    let alpha = n_in_use + 2;
    let eob = (alpha - 1) as u16;

    // MTF + RUNA/RUNB.
    let mut syms: Vec<u16> = Vec::new();
    syms.try_reserve_exact(n + 1).map_err(|_| Bzip2EncodeError::Allocation)?;
    let mut mtf: Vec<u8> = (0..n_in_use as u32).map(|x| x as u8).collect();
    let mut zrun = 0usize;
    let flush_run = |syms: &mut Vec<u16>, zrun: &mut usize| {
        if *zrun > 0 {
            let mut z = *zrun - 1;
            loop {
                syms.push((z & 1) as u16);
                if z < 2 {
                    break;
                }
                z = (z - 2) / 2;
            }
            *zrun = 0;
        }
    };
    for &b in last.iter() {
        let s = unseq_to_seq[b as usize];
        if mtf[0] == s {
            zrun += 1;
            continue;
        }
        flush_run(&mut syms, &mut zrun);
        let idx = mtf.iter().position(|&x| x == s).unwrap_or(0);
        mtf.copy_within(0..idx, 1);
        mtf[0] = s;
        syms.push(idx as u16 + 1);
    }
    flush_run(&mut syms, &mut zrun);
    syms.push(eob);
    drop(last);

    // Huffman tables.
    let n_mtf = syms.len();
    let n_groups = match n_mtf {
        0..200 => 2,
        200..600 => 3,
        600..1200 => 4,
        1200..2400 => 5,
        _ => 6,
    };
    let n_sel = n_mtf.div_ceil(GROUP_SIZE);
    let mut total = vec![0u32; alpha];
    for &s in &syms {
        total[s as usize] += 1;
    }
    // Initial tables: contiguous symbol ranges of roughly equal frequency.
    let mut lens = vec![[0u8; 258]; n_groups];
    {
        let mut lo = 0usize;
        let mut remaining = n_mtf as u64;
        for (g, table) in lens.iter_mut().enumerate() {
            let parts_left = (n_groups - g) as u64;
            let target = remaining / parts_left;
            let mut acc = 0u64;
            let mut hi = lo;
            while hi < alpha && (acc < target || hi == lo) && alpha - hi > n_groups - g - 1 {
                acc += total[hi] as u64;
                hi += 1;
            }
            if g == n_groups - 1 {
                while hi < alpha {
                    acc += total[hi] as u64;
                    hi += 1;
                }
            }
            for (s, l) in table.iter_mut().enumerate().take(alpha) {
                *l = if (lo..hi).contains(&s) { 1 } else { 15 };
            }
            remaining = remaining.saturating_sub(acc);
            lo = hi;
        }
    }
    let mut selectors = vec![0u8; n_sel];
    for _ in 0..REFINE_ITERS {
        let mut freqs = vec![vec![0u32; alpha]; n_groups];
        for (gi, chunk) in syms.chunks(GROUP_SIZE).enumerate() {
            let mut best = 0;
            let mut best_cost = u32::MAX;
            for (t, l) in lens.iter().enumerate() {
                let cost: u32 = chunk.iter().map(|&s| l[s as usize] as u32).sum();
                if cost < best_cost {
                    best_cost = cost;
                    best = t;
                }
            }
            selectors[gi] = best as u8;
            for &s in chunk {
                freqs[best][s as usize] += 1;
            }
        }
        for (t, f) in freqs.iter().enumerate() {
            code_lengths(f, &mut lens[t][..alpha]);
        }
    }

    // Header fields.
    w.put(1, 0)?; // not randomised
    w.put(24, orig_ptr as u64)?;
    let mut ranges = 0u64;
    for i in 0..16 {
        if in_use[i * 16..i * 16 + 16].iter().any(|&x| x) {
            ranges |= 1 << (15 - i);
        }
    }
    w.put(16, ranges)?;
    for i in 0..16 {
        if ranges & (1 << (15 - i)) != 0 {
            let mut bits = 0u64;
            for j in 0..16 {
                if in_use[i * 16 + j] {
                    bits |= 1 << (15 - j);
                }
            }
            w.put(16, bits)?;
        }
    }
    w.put(3, n_groups as u64)?;
    w.put(15, n_sel as u64)?;
    let mut mtf_g: Vec<u8> = (0..n_groups as u8).collect();
    for &s in &selectors {
        let j = mtf_g.iter().position(|&x| x == s).unwrap_or(0);
        mtf_g.copy_within(0..j, 1);
        mtf_g[0] = s;
        for _ in 0..j {
            w.put(1, 1)?;
        }
        w.put(1, 0)?;
    }
    for l in &lens {
        let mut curr = l[0] as i32;
        w.put(5, curr as u64)?;
        for &target in &l[..alpha] {
            let target = target as i32;
            while curr < target {
                w.put(2, 0b10)?;
                curr += 1;
            }
            while curr > target {
                w.put(2, 0b11)?;
                curr -= 1;
            }
            w.put(1, 0)?;
        }
    }
    let codes: Vec<Vec<u32>> = lens.iter().map(|l| canonical(&l[..alpha])).collect();
    for (gi, chunk) in syms.chunks(GROUP_SIZE).enumerate() {
        let t = selectors[gi] as usize;
        for &s in chunk {
            w.put(lens[t][s as usize] as u32, codes[t][s as usize] as u64)?;
        }
    }
    Ok(())
}
