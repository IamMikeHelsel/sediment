// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaxWriteError {
    InvalidKeyword,
    LimitExceeded,
}

pub fn encode_record(
    keyword: &[u8],
    value: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, PaxWriteError> {
    // 1. Validate keyword
    if keyword.is_empty() {
        return Err(PaxWriteError::InvalidKeyword);
    }
    for &b in keyword {
        if b == 0 || b == b'\n' || b == b'=' {
            return Err(PaxWriteError::InvalidKeyword);
        }
    }

    // 2. Compute exact canonical output extent
    // Format: <length><space><keyword>=<value><newline>
    // Length is the decimal representation of the total byte count.
    // Let L be the length of the decimal string of the total size.
    // Total size = L + 1 (space) + keyword.len() + 1 (equals) + value.len() + 1 (newline)
    // Let P = 1 + keyword.len() + 1 + value.len() + 1 = keyword.len() + value.len() + 3
    // Total size = L + P
    // We need to find the smallest L such that the number of digits in (L + P) is L.
    // Let N = L + P. We need digits(N) == L.
    // Since L = N - P, we need digits(N) == N - P => N - digits(N) == P.
    // We can iterate to find the correct N.
    // P is fixed. We need to find N such that N - digits(N) == P.
    // digits(N) is roughly log10(N). So N is roughly P + log10(P).
    // We can start checking from N = P + 1 upwards.

    let payload_len = value.len()
        .checked_add(keyword.len())
        .and_then(|s| s.checked_add(3))
        .ok_or(PaxWriteError::LimitExceeded)?;

    // Find the canonical length L.
    // L is the number of digits in the total size S = L + payload_len.
    // We need to find S such that digits(S) == S - payload_len.
    // Let L_candidate = digits(S). Then S = L_candidate + payload_len.
    // We need digits(L_candidate + payload_len) == L_candidate.
    // Since digits(S) is monotonic and S is monotonic with L_candidate,
    // we can just iterate L_candidate starting from 1.

    let mut l_candidate: usize = 1;
    loop {
        let s = l_candidate.checked_add(payload_len).ok_or(PaxWriteError::LimitExceeded)?;
        let digits = num_digits(s);
        if digits == l_candidate {
            // Found the canonical L
            let total_size = s;
            if total_size > max_output_bytes {
                return Err(PaxWriteError::LimitExceeded);
            }

            // 3. Check cap before allocating
            // Allocate only the final output buffer
            let mut output = Vec::new();
            output.try_reserve_exact(total_size).map_err(|_| PaxWriteError::LimitExceeded)?;

            // Write the length digits
            // Use a small stack buffer for formatting
            let mut buf = [0u8; 20]; // usize fits in 20 digits
            let len_str = format_decimal(total_size, &mut buf);
            output.extend_from_slice(len_str);

            // Write space
            output.push(b' ');

            // Write keyword
            output.extend_from_slice(keyword);

            // Write equals
            output.push(b'=');

            // Write value
            output.extend_from_slice(value);

            // Write newline
            output.push(b'\n');

            return Ok(output);
        }
        l_candidate += 1;
        // Safety: l_candidate will not overflow because payload_len is bounded by usize::MAX
        // and digits(s) grows very slowly. If payload_len is huge, l_candidate will be small.
        // If payload_len is close to usize::MAX, s might overflow, handled by checked_add.
    }
}

fn num_digits(mut n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut count = 0;
    while n > 0 {
        n /= 10;
        count += 1;
    }
    count
}

fn format_decimal(mut n: usize, buf: &mut [u8]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[0..1];
    }
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}