/// 7-Zip command-line size/switch parser.
/// Spec: 7-Zip docs for `-v{Size}[b|k|m|g]`, `-mx`, `-md`, `-mmt`.
use std::char;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeError {
    Empty,
    BadNumber,
    BadSuffix,
    Overflow,
    Zero,
    BadValue,
    BadSwitch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threads {
    On,
    Off,
    Count(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switch {
    Volume(u64),
    Level(u8),
    Dictionary(u64),
    Threads(Threads),
}

/// Parse a 7-Zip size string (bytes unless suffix).
pub fn parse_size(s: &str) -> Result<u64, SizeError> {
    let (num, suffix) = split_num_suffix(s)?;
    let multiplier = match suffix {
        None => 1u64,
        Some(c) => match c.to_ascii_lowercase() {
            'b' => 1,
            'k' => 1024,
            'm' => 1024 * 1024,
            'g' => 1024 * 1024 * 1024,
            _ => return Err(SizeError::BadSuffix),
        },
    };
    num.checked_mul(multiplier).ok_or(SizeError::Overflow)
}

/// Parse a 7-Zip dictionary size string.
/// No suffix => exponent (1<<N). Suffix => bytes with multiplier.
pub fn parse_dict_size(s: &str) -> Result<u64, SizeError> {
    let (num, suffix) = split_num_suffix(s)?;
    match suffix {
        None => {
            if num > 63 {
                Err(SizeError::Overflow)
            } else {
                Ok(1u64 << num)
            }
        }
        Some(c) => {
            let multiplier = match c.to_ascii_lowercase() {
                'b' => 1u64,
                'k' => 1024,
                'm' => 1024 * 1024,
                'g' => 1024 * 1024 * 1024,
                _ => return Err(SizeError::BadSuffix),
            };
            num.checked_mul(multiplier).ok_or(SizeError::Overflow)
        }
    }
}

/// Parse a 7-Zip switch argument.
pub fn parse_switch(arg: &str) -> Result<Switch, SizeError> {
    if arg.is_empty() {
        return Err(SizeError::BadSwitch);
    }
    let lower = arg.to_ascii_lowercase();

    // Try prefixes in order: -mmt, -mx, -md, -v
    if lower.starts_with("-mmt") {
        return parse_mmt(&arg[4..]);
    }
    if lower.starts_with("-mx") {
        return parse_mx(&arg[3..]);
    }
    if lower.starts_with("-md") {
        return parse_md(&arg[3..]);
    }
    if lower.starts_with("-v") {
        return parse_v(&arg[2..]);
    }
    Err(SizeError::BadSwitch)
}

fn split_num_suffix(s: &str) -> Result<(u64, Option<char>), SizeError> {
    if s.is_empty() {
        return Err(SizeError::Empty);
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return Err(SizeError::BadNumber);
    }
    let num_str = &s[..i];
    let num: u64 = num_str
        .parse()
        .map_err(|_| SizeError::Overflow)?;
    let suffix = if i < bytes.len() {
        let rest = &s[i..];
        // rest must be exactly one char
        if rest.len() != 1 {
            return Err(SizeError::BadSuffix);
        }
        let ch = rest.chars().next().unwrap();
        // must be ASCII letter
        if !ch.is_ascii_alphabetic() {
            return Err(SizeError::BadSuffix);
        }
        Some(ch)
    } else {
        None
    };
    Ok((num, suffix))
}

fn parse_mmt(rest: &str) -> Result<Switch, SizeError> {
    let value = if rest.starts_with('=') { &rest[1..] } else { rest };
    let vl = value.to_ascii_lowercase();
    if vl.is_empty() || vl == "on" || vl == "+" {
        return Ok(Switch::Threads(Threads::On));
    }
    if vl == "off" || vl == "-" {
        return Ok(Switch::Threads(Threads::Off));
    }
    // digits only
    if value.is_empty() {
        return Err(SizeError::Empty);
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_digit() {
        return Err(SizeError::BadNumber);
    }
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i != bytes.len() {
        return Err(SizeError::BadValue);
    }
    let n: u32 = value.parse().map_err(|_| SizeError::Overflow)?;
    if n == 0 {
        Err(SizeError::Zero)
    } else {
        Ok(Switch::Threads(Threads::Count(n)))
    }
}

fn parse_mx(rest: &str) -> Result<Switch, SizeError> {
    let value = if rest.starts_with('=') { &rest[1..] } else { rest };
    if value.is_empty() {
        return Err(SizeError::Empty);
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_digit() {
        return Err(SizeError::BadNumber);
    }
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i != bytes.len() {
        return Err(SizeError::BadValue);
    }
    let n: u64 = value.parse().map_err(|_| SizeError::Overflow)?;
    if n > 9 {
        Err(SizeError::BadValue)
    } else {
        Ok(Switch::Level(n as u8))
    }
}

fn parse_md(rest: &str) -> Result<Switch, SizeError> {
    let value = if rest.starts_with('=') { &rest[1..] } else { rest };
    let val = parse_dict_size(value)?;
    if val == 0 {
        Err(SizeError::Zero)
    } else {
        Ok(Switch::Dictionary(val))
    }
}

fn parse_v(rest: &str) -> Result<Switch, SizeError> {
    // -v takes no '='; value is rest as-is
    let val = parse_size(rest)?;
    if val == 0 {
        Err(SizeError::Zero)
    } else {
        Ok(Switch::Volume(val))
    }
}
