// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::zip::ZipError;

pub fn validate_ranges(ranges: &[(usize, usize)], end: usize, max_ranges: usize) -> Result<(), ZipError> {
    if ranges.len() > max_ranges {
        return Err(ZipError::LimitExceeded);
    }

    if ranges.is_empty() {
        if end == 0 {
            return Ok(());
        } else {
            return Err(ZipError::Invalid);
        }
    }

    let mut sorted: Vec<(usize, usize)> = Vec::new();
    if let Err(_) = sorted.try_reserve(ranges.len()) {
        return Err(ZipError::LimitExceeded);
    }

    for &(start, stop) in ranges {
        if start >= stop {
            return Err(ZipError::Invalid);
        }
        if stop > end {
            return Err(ZipError::Invalid);
        }
        sorted.push((start, stop));
    }

    sorted.sort_unstable_by_key(|&(start, _)| start);

    if sorted[0].0 != 0 {
        return Err(ZipError::Invalid);
    }

    if sorted[sorted.len() - 1].1 != end {
        return Err(ZipError::Invalid);
    }

    for i in 0..sorted.len() - 1 {
        let current_end = sorted[i].1;
        let next_start = sorted[i + 1].0;

        if current_end != next_start {
            return Err(ZipError::Invalid);
        }
    }

    Ok(())
}