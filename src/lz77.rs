// SPDX-License-Identifier: MIT OR Apache-2.0

use std::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchError {
    InvalidLength,
    InvalidDistance,
    LimitExceeded,
    Allocation,
}

pub fn append_match(
    output: &mut Vec<u8>,
    distance: usize,
    length: usize,
    max_output: usize,
) -> Result<(), MatchError> {
    if !(3..=258).contains(&length) {
        return Err(MatchError::InvalidLength);
    }
    if distance == 0 || distance > 32768 || distance > output.len() {
        return Err(MatchError::InvalidDistance);
    }
    let new_len = output.len().checked_add(length).ok_or(MatchError::LimitExceeded)?;
    if new_len > max_output {
        return Err(MatchError::LimitExceeded);
    }
    output.try_reserve(length).map_err(|_| MatchError::Allocation)?;
    let start = output.len() - distance;
    for i in 0..length {
        let src_idx = start + (i % distance);
        output.push(output[src_idx]);
    }
    Ok(())
}