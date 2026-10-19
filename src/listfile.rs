use std::str;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFileError {
    LimitExceeded,
    InvalidUtf8,
    InvalidUtf16,
    UnsupportedEncoding,
    NulCharacter,
}

pub fn parse_listfile(data: &[u8], max_bytes: usize) -> Result<Vec<String>, ListFileError> {
    // Step 1: size cap check before anything else
    if data.len() > max_bytes {
        return Err(ListFileError::LimitExceeded);
    }

    // Step 2: detect encoding by BOM
    let text: String = if data.starts_with(b"\xef\xbb\xbf") {
        // UTF-8 with BOM: drop 3 bytes, decode strictly
        let decoded = str::from_utf8(&data[3..]).map_err(|_| ListFileError::InvalidUtf8)?;
        decoded.to_string()
    } else if data.starts_with(b"\xff\xfe") {
        // UTF-16LE with BOM: drop 2 BOM bytes, decode as UTF-16LE
        let remaining = &data[2..];
        // Length must be even (each u16 is 2 bytes)
        if remaining.len() % 2 != 0 {
            return Err(ListFileError::InvalidUtf16);
        }
        let words: Vec<u16> = remaining
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&words).map_err(|_| ListFileError::InvalidUtf16)?
    } else if data.starts_with(b"\xfe\xff") {
        // UTF-16BE BOM: unsupported
        return Err(ListFileError::UnsupportedEncoding);
    } else {
        // UTF-8 without BOM (including empty input)
        let decoded = str::from_utf8(data).map_err(|_| ListFileError::InvalidUtf8)?;
        decoded.to_string()
    };

    // Step 3: check for NUL characters
    if text.contains('\0') {
        return Err(ListFileError::NulCharacter);
    }

    // Step 4: split on '\n', trim trailing '\r' if present, trim leading/trailing ASCII space/tab, skip empty
    let mut result = Vec::new();
    for line in text.split('\n') {
        // Remove one trailing '\r' if present
        let line = line.strip_suffix('\r').unwrap_or(line);
        // Trim leading and trailing ASCII spaces and tabs only
        let trimmed = trim_ascii_spaces(line);
        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }
        result.push(trimmed.to_string());
    }

    Ok(result)
}

/// Trim leading and trailing ASCII space (' ') and tab ('\t') characters only.
/// Other whitespace characters (like U+00A0) are preserved.
fn trim_ascii_spaces(s: &str) -> &str {
    let mut start = 0;
    let bytes = s.as_bytes();
    while start < bytes.len() && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}
