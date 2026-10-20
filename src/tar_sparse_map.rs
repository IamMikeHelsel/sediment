// SPDX-License-Identifier: MIT OR Apache-2.0

//! GNU tar sparse-file map parsing and sparse expansion.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseError {
    Truncated,
    BadNumber,
    BadMap,
    LimitExceeded,
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseRegion {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMap {
    pub regions: Vec<SparseRegion>,
    pub real_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapText {
    Pax01,
    Pax10,
}

fn parse_sparse_numeric(field: &[u8]) -> Result<u64, SparseError> {
    let Some(&first) = field.first() else {
        return Ok(0);
    };
    if first & 0x80 != 0 {
        if field.len() > 15 {
            return Err(SparseError::BadNumber);
        }
        let bits = field.len() as u32 * 8 - 1;
        let mut u: i128 = (first & 0x7f) as i128;
        for &b in &field[1..] {
            u = (u << 8) | b as i128;
        }
        let v = if u & (1i128 << (bits - 1)) != 0 {
            u - (1i128 << bits)
        } else {
            u
        };
        return u64::try_from(v).map_err(|_| SparseError::BadNumber);
    }
    let mut i = 0;
    let len = field.len();
    while i < len && field[i] == b' ' {
        i += 1;
    }
    let mut val: u64 = 0;
    while i < len {
        let b = field[i];
        match b {
            b'0'..=b'7' => {
                val = val
                    .checked_mul(8)
                    .and_then(|v| v.checked_add((b - b'0') as u64))
                    .ok_or(SparseError::BadNumber)?;
            }
            b' ' | 0 => break,
            _ => return Err(SparseError::BadNumber),
        }
        i += 1;
    }
    Ok(val)
}

pub fn parse_old_gnu(
    header: &[u8],
    after: &[u8],
    max_regions: usize,
) -> Result<(SparseMap, usize), SparseError> {
    if header.len() < 512 {
        return Err(SparseError::Truncated);
    }
    let real_size = parse_sparse_numeric(&header[483..495])?;
    let mut regions: Vec<SparseRegion> = Vec::new();
    regions.try_reserve(max_regions).map_err(|_| SparseError::Allocation)?;

    // block_num: 0 = header, 1 = first extension block, 2 = second, ...
    let mut block_num: usize = 0;

    loop {
        // Determine which block to read.
        let block: &[u8] = if block_num == 0 {
            header
        } else {
            let offset = (block_num - 1) * 512;
            if after.len() < offset + 512 {
                return Err(SparseError::Truncated);
            }
            &after[offset..offset + 512]
        };

        let nslots = if block_num == 0 { 4 } else { 21 };
        let slot_base = if block_num == 0 { 386 } else { 0 };

        for si in 0..nslots {
            let off = slot_base + si * 24;
            if off + 24 > 512 {
                return Err(SparseError::Truncated);
            }
            let offset_field = &block[off..off + 12];

            // Terminator: offset field starts with NUL byte.
            if offset_field.first() == Some(&0) {
                break;
            }

            let length_field = &block[off + 12..off + 24];
            let offset = parse_sparse_numeric(offset_field)?;
            let length = parse_sparse_numeric(length_field)?;

            // Drop zero-length entries (GNU tar writes a final (realsize, 0)).
            if length == 0 {
                continue;
            }

            regions.push(SparseRegion { offset, length });
            if regions.len() > max_regions {
                return Err(SparseError::LimitExceeded);
            }
        }

        // isextended byte: 482 for header, 504 for extension blocks.
        let is_ext = if block_num == 0 { block[482] } else { block[504] };
        if is_ext == 0 {
            break;
        }
        block_num += 1;
    }

    let ext_bytes = block_num * 512;
    validate_regions(&regions, real_size)?;
    Ok((SparseMap { regions, real_size }, ext_bytes))
}

pub fn parse_map_text(
    text: &[u8],
    kind: MapText,
    real_size: u64,
    max_regions: usize,
) -> Result<(SparseMap, usize), SparseError> {
    match kind {
        MapText::Pax01 => parse_pax01(text, real_size, max_regions),
        MapText::Pax10 => parse_pax10(text, real_size, max_regions),
    }
}

fn parse_pax01(
    text: &[u8],
    real_size: u64,
    max_regions: usize,
) -> Result<(SparseMap, usize), SparseError> {
    if text.is_empty() {
        return Ok((SparseMap { regions: Vec::new(), real_size }, 0));
    }
    let mut pairs: Vec<SparseRegion> = Vec::new();
    pairs.try_reserve(max_regions).map_err(|_| SparseError::Allocation)?;

    let mut pos = 0;
    let len = text.len();
    let mut field_idx: usize = 0;

    loop {
        let comma = text[pos..].iter().position(|&b| b == b',');
        let end = match comma {
            Some(c) => c,
            None => len - pos,
        };
        if end == 0 {
            return Err(SparseError::BadMap);
        }
        let num = parse_decimal_u64(&text[pos..pos + end])?;
        pos += end;

        if field_idx % 2 == 0 {
            pairs.push(SparseRegion { offset: num, length: 0 });
        } else {
            let last = pairs.pop().unwrap();
            pairs.push(SparseRegion { offset: last.offset, length: num });
        }
        field_idx += 1;

        if comma.is_none() {
            break;
        }
        pos += 1;
    }

    if field_idx % 2 != 0 {
        return Err(SparseError::BadMap);
    }

    let mut filtered: Vec<SparseRegion> = Vec::new();
    filtered.try_reserve(pairs.len()).map_err(|_| SparseError::Allocation)?;
    for r in &pairs {
        if r.length == 0 {
            continue;
        }
        filtered.push(*r);
        if filtered.len() > max_regions {
            return Err(SparseError::LimitExceeded);
        }
    }

    validate_regions(&filtered, real_size)?;
    Ok((SparseMap { regions: filtered, real_size }, len))
}

fn parse_pax10(
    text: &[u8],
    real_size: u64,
    max_regions: usize,
) -> Result<(SparseMap, usize), SparseError> {
    let (count, consumed) = parse_count_line(text)?;

    let mut pos = consumed;
    let mut total_nums: usize = 0;
    let expected_nums = count as usize * 2;

    let mut pairs: Vec<SparseRegion> = Vec::new();
    pairs.try_reserve(max_regions).map_err(|_| SparseError::Allocation)?;

    while total_nums < expected_nums {
        let nl = text[pos..].iter().position(|&b| b == b'\n');
        let line_end = match nl {
            Some(n) => n,
            None => return Err(SparseError::Truncated),
        };
        if line_end == 0 {
            return Err(SparseError::BadMap);
        }
        let num = parse_decimal_u64(&text[pos..pos + line_end])?;
        pos += line_end + 1;
        total_nums += 1;

        if total_nums % 2 == 1 {
            pairs.push(SparseRegion { offset: num, length: 0 });
        } else {
            let last = pairs.pop().unwrap();
            pairs.push(SparseRegion { offset: last.offset, length: num });
        }
    }

    let mut filtered: Vec<SparseRegion> = Vec::new();
    filtered.try_reserve(pairs.len()).map_err(|_| SparseError::Allocation)?;
    for r in &pairs {
        if r.length > 0 {
            filtered.push(*r);
            if filtered.len() > max_regions {
                return Err(SparseError::LimitExceeded);
            }
        }
    }

    validate_regions(&filtered, real_size)?;

    let rounded = if pos == 0 {
        512
    } else {
        ((pos + 511) / 512) * 512
    };
    Ok((SparseMap { regions: filtered, real_size }, rounded))
}

fn parse_count_line(text: &[u8]) -> Result<(u64, usize), SparseError> {
    let nl = text.iter().position(|&b| b == b'\n');
    let end = match nl {
        Some(n) => n,
        None => return Err(SparseError::Truncated),
    };
    if end == 0 {
        return Err(SparseError::BadMap);
    }
    let count = parse_decimal_u64(&text[..end])?;
    Ok((count, end + 1))
}

fn parse_decimal_u64(s: &[u8]) -> Result<u64, SparseError> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return Err(SparseError::BadMap);
    }
    let mut v: u64 = 0;
    for &d in s {
        v = v
            .checked_mul(10)
            .and_then(|val| val.checked_add((d - b'0') as u64))
            .ok_or(SparseError::BadMap)?;
    }
    Ok(v)
}

fn validate_regions(regions: &[SparseRegion], real_size: u64) -> Result<(), SparseError> {
    let mut prev_end: u64 = 0;
    for r in regions {
        if r.offset < prev_end {
            return Err(SparseError::BadMap);
        }
        let end = r.offset.checked_add(r.length).ok_or(SparseError::BadMap)?;
        if end > real_size {
            return Err(SparseError::BadMap);
        }
        prev_end = end;
    }
    Ok(())
}

pub fn expand(map: &SparseMap, packed: &[u8], max_output: usize) -> Result<Vec<u8>, SparseError> {
    if map.real_size > max_output as u64 {
        return Err(SparseError::LimitExceeded);
    }
    let output_len: usize = map
        .real_size
        .try_into()
        .map_err(|_| SparseError::LimitExceeded)?;
    if output_len > max_output {
        return Err(SparseError::LimitExceeded);
    }

    let mut total: u64 = 0;
    for r in &map.regions {
        total = total.checked_add(r.length).ok_or(SparseError::Truncated)?;
    }
    if total > packed.len() as u64 {
        return Err(SparseError::Truncated);
    }

    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(output_len).map_err(|_| SparseError::Allocation)?;
    out.resize(output_len, 0);

    let mut packed_pos: usize = 0;
    for r in &map.regions {
        let len = r.length as usize;
        let end = packed_pos.checked_add(len).ok_or(SparseError::Truncated)?;
        if end > packed.len() {
            return Err(SparseError::Truncated);
        }
        let dst_start = r.offset as usize;
        let dst_end = dst_start.checked_add(len).ok_or(SparseError::BadMap)?;
        if dst_end > out.len() {
            return Err(SparseError::BadMap);
        }
        out[dst_start..dst_end].copy_from_slice(&packed[packed_pos..end]);
        packed_pos = end;
    }

    Ok(out)
}
