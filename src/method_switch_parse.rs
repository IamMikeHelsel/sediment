//! 7-Zip `-m0=` / `-m=` method spec parser + `method_string` (7zz -slt output).

// ── public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodError {
    UnknownMethod,
    UnknownParam,
    BadParam,
    BadValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodId {
    Copy,
    Lzma,
    Lzma2,
    Ppmd,
    BZip2,
    Deflate,
    Deflate64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoderParams {
    pub dict: Option<u64>,
    pub fast_bytes: Option<u32>,
    pub match_finder: Option<String>,
    pub lc: Option<u8>,
    pub lp: Option<u8>,
    pub pb: Option<u8>,
    pub threads: Option<u32>,
    pub order: Option<u8>,
    pub mem: Option<u64>,
    pub passes: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSpec {
    pub id: MethodId,
    pub params: CoderParams,
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn parse_u32(s: &str) -> Result<u32, MethodError> {
    if s.is_empty() {
        return Err(MethodError::BadValue);
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_digit() {
        return Err(MethodError::BadValue);
    }
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(MethodError::BadValue);
        }
    }
    s.parse::<u32>().map_err(|_| MethodError::BadValue)
}

fn parse_u8_val(s: &str) -> Result<u8, MethodError> {
    let v = parse_u32(s)?;
    if v > 255 {
        Err(MethodError::BadValue)
    } else {
        Ok(v as u8)
    }
}

/// Parse a size value. `no_suffix_is_exponent`: no suffix means 1 << n.
fn parse_size_value(s: &str, no_suffix_is_exponent: bool) -> Result<u64, MethodError> {
    if s.is_empty() {
        return Err(MethodError::BadValue);
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return Err(MethodError::BadValue);
    }
    let num_str = &s[..i];
    let num: u64 = num_str.parse().map_err(|_| MethodError::BadValue)?;

    if i == bytes.len() {
        if no_suffix_is_exponent {
            if num > 63 {
                return Err(MethodError::BadValue);
            }
            return Ok(1u64 << num);
        }
        return Ok(num);
    }

    let rest = &s[i..];
    if rest.len() != 1 {
        return Err(MethodError::BadValue);
    }
    let suffix = rest.as_bytes()[0];
    let multiplier = match suffix.to_ascii_lowercase() {
        b'b' => 1u64,
        b'k' => 1024u64,
        b'm' => 1024 * 1024,
        b'g' => 1024 * 1024 * 1024,
        _ => return Err(MethodError::BadValue),
    };
    num.checked_mul(multiplier).ok_or(MethodError::BadValue)
}

fn parse_kv(segment: &str) -> Result<(String, String), MethodError> {
    let eq = segment.find('=').ok_or(MethodError::BadParam)?;
    let key = &segment[..eq];
    let value = &segment[eq + 1..];
    if key.is_empty() || value.is_empty() {
        return Err(MethodError::BadParam);
    }
    Ok((key.to_ascii_lowercase(), value.to_string()))
}

fn method_name(name: &str) -> Option<MethodId> {
    match name {
        "" => Some(MethodId::Lzma2),
        "copy" => Some(MethodId::Copy),
        "lzma" => Some(MethodId::Lzma),
        "lzma2" => Some(MethodId::Lzma2),
        "ppmd" => Some(MethodId::Ppmd),
        "bzip2" => Some(MethodId::BZip2),
        "deflate" => Some(MethodId::Deflate),
        "deflate64" => Some(MethodId::Deflate64),
        _ => None,
    }
}

fn allowed_keys(id: MethodId) -> &'static [&'static str] {
    match id {
        MethodId::Lzma | MethodId::Lzma2 => &["d", "fb", "mf", "lc", "lp", "pb", "mt"],
        MethodId::Ppmd => &["o", "mem", "mt"],
        MethodId::BZip2 => &["d", "mt", "pass"],
        MethodId::Deflate | MethodId::Deflate64 => &["fb", "pass", "mt"],
        MethodId::Copy => &[],
    }
}

fn is_allowed(id: MethodId, key: &str) -> bool {
    allowed_keys(id).contains(&key)
}

fn parse_mf(s: &str) -> Result<String, MethodError> {
    let lower = s.to_ascii_lowercase();
    match lower.as_str() {
        "bt2" | "bt3" | "bt4" | "bt5" | "hc4" | "hc5" => Ok(lower),
        _ => Err(MethodError::BadValue),
    }
}

// ── parse_method ────────────────────────────────────────────────────────────

const MAX_DICT: u64 = 1u64 << 32; // 4 GiB

pub fn parse_method(s: &str) -> Result<MethodSpec, MethodError> {
    let segments: Vec<&str> = s.split(':').collect();
    if segments.is_empty() {
        return Err(MethodError::UnknownMethod);
    }

    let id = method_name(&segments[0].to_ascii_lowercase())
        .ok_or(MethodError::UnknownMethod)?;
    let mut params = CoderParams::default();

    for seg in &segments[1..] {
        let (key, value) = parse_kv(seg)?;
        if !is_allowed(id, &key) {
            return Err(MethodError::UnknownParam);
        }
        match key.as_str() {
            "d" => {
                let v = parse_size_value(&value, true)?;
                if v > MAX_DICT {
                    return Err(MethodError::BadValue);
                }
                params.dict = Some(v);
            }
            "fb" => {
                params.fast_bytes = Some(parse_u32(&value)?);
            }
            "mf" => {
                params.match_finder = Some(parse_mf(&value)?);
            }
            "lc" => {
                params.lc = Some(parse_u8_val(&value)?);
            }
            "lp" => {
                params.lp = Some(parse_u8_val(&value)?);
            }
            "pb" => {
                params.pb = Some(parse_u8_val(&value)?);
            }
            "mt" => {
                params.threads = Some(parse_u32(&value)?);
            }
            "o" => {
                let v = parse_u32(&value)?;
                if (2..=32).contains(&v) {
                    params.order = Some(v as u8);
                } else {
                    return Err(MethodError::BadValue);
                }
            }
            "mem" => {
                let v = parse_size_value(&value, true)?;
                if (65536..=1u64 << 32).contains(&v) {
                    params.mem = Some(v);
                } else {
                    return Err(MethodError::BadValue);
                }
            }
            "pass" => {
                params.passes = Some(parse_u32(&value)?);
            }
            _ => {
                return Err(MethodError::UnknownParam);
            }
        }
    }

    // post-parse validation for Lzma / Lzma2
    if id == MethodId::Lzma || id == MethodId::Lzma2 {
        let lc = params.lc.unwrap_or(3);
        let lp = params.lp.unwrap_or(0);
        let pb = params.pb.unwrap_or(2);

        let max_lc = if id == MethodId::Lzma { 8 } else { 4 };
        if lc > max_lc || lp > 4 || pb > 4 {
            return Err(MethodError::BadValue);
        }
        if id == MethodId::Lzma2 && lc + lp > 4 {
            return Err(MethodError::BadValue);
        }
    }

    Ok(MethodSpec { id, params })
}

// ── effective_dict ──────────────────────────────────────────────────────────

fn default_dict_by_level(level: u8) -> u64 {
    let lvl = if level > 9 { 9 } else { level };
    match lvl {
        0 => 64 << 10,
        1 => 256 << 10,
        2 => 1 << 20,
        3 => 4 << 20,
        4 => 16 << 20,
        5 => 32 << 20,
        6 => 64 << 20,
        7 => 128 << 20,
        _ => 256 << 20,
    }
}

fn round_up_dict(v: u64) -> u64 {
    if v < 4096 {
        return 4096;
    }
    let mut best = u64::MAX;
    for n in 0..62 {
        let two_n = 1u64 << n;
        if two_n >= v && two_n < best {
            best = two_n;
        }
        if let Some(three_n) = two_n.checked_mul(3) {
            if three_n >= v && three_n < best {
                best = three_n;
            }
        }
    }
    best
}

pub fn effective_dict(spec: &MethodSpec, level: u8) -> Option<u64> {
    match spec.id {
        MethodId::Lzma | MethodId::Lzma2 => {}
        _ => return None,
    }
    let base = spec.params.dict.unwrap_or_else(|| default_dict_by_level(level));
    Some(round_up_dict(base))
}

// ── method_string ───────────────────────────────────────────────────────────

fn format_dict(d: u64) -> String {
    if d != 0 && d & (d - 1) == 0 {
        return d.trailing_zeros().to_string();
    }
    if d % (1 << 20) == 0 {
        return format!("{}m", d >> 20);
    }
    format!("{}k", d >> 10)
}

pub fn method_string(spec: &MethodSpec, level: u8) -> String {
    let name = match spec.id {
        MethodId::Copy => "Copy",
        MethodId::Lzma => "LZMA",
        MethodId::Lzma2 => "LZMA2",
        MethodId::Ppmd => "PPMD",
        MethodId::BZip2 => "BZip2",
        MethodId::Deflate => "Deflate",
        MethodId::Deflate64 => "Deflate64",
    };

    match spec.id {
        MethodId::Lzma | MethodId::Lzma2 => {
            if let Some(d) = effective_dict(spec, level) {
                return format!("{}:{}", name, format_dict(d));
            }
            name.to_string()
        }
        _ => name.to_string(),
    }
}
