// SPDX-License-Identifier: MIT OR Apache-2.0
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    TooLong,
    Allocation,
}

pub fn escape_name(bytes: &[u8]) -> Result<String, NameError> {
    if bytes.len() > 65535 {
        return Err(NameError::TooLong);
    }
    let mut s = String::new();
    s.try_reserve(bytes.len().saturating_mul(4)).map_err(|_| NameError::Allocation)?;
    for &b in bytes {
        match b {
            0x20..=0x7e if b != b'\\' => s.push(b as char),
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\r' => s.push_str("\\r"),
            b'\n' => s.push_str("\\n"),
            _ => {
                s.push_str("\\x");
                let hex = b"0123456789abcdef";
                s.push(hex[(b >> 4) as usize] as char);
                s.push(hex[(b & 0x0f) as usize] as char);
            }
        }
    }
    Ok(s)
}