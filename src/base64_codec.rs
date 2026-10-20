/// Base64 alphabet selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    Standard,
    UrlSafe,
}

/// Padding mode for decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    Required,
    Optional,
    Forbidden,
}

/// Options for base64 decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    pub alphabet: Alphabet,
    pub padding: Padding,
    pub ignore_whitespace: bool,
    pub max_output: usize,
}

/// Errors that can occur during base64 decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    InvalidByte,
    InvalidPadding,
    InvalidLength,
    LimitExceeded,
    NonCanonical,
}

// RFC 4648 section 4: Standard alphabet
const STANDARD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// RFC 4648 section 5: URL-safe alphabet
const URL_SAFE_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode input bytes as base64.
/// If `pad` is true, output length is a multiple of 4 with `=` padding.
/// If `pad` is false, trailing `=` are omitted.
pub fn encode(input: &[u8], alphabet: Alphabet, pad: bool) -> String {
    if input.is_empty() {
        return String::new();
    }

    let alphabet_bytes = match alphabet {
        Alphabet::Standard => STANDARD_ALPHABET,
        Alphabet::UrlSafe => URL_SAFE_ALPHABET,
    };

    let mut result = String::new();
    let mut i = 0;
    let len = input.len();

    while i < len {
        let remaining = len - i;
        let b0 = input[i] as u32;
        let b1 = if remaining > 1 { input[i + 1] as u32 } else { 0 };
        let b2 = if remaining > 2 { input[i + 2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(alphabet_bytes[((triple >> 18) & 0x3F) as usize] as char);
        result.push(alphabet_bytes[((triple >> 12) & 0x3F) as usize] as char);

        if remaining > 1 {
            result.push(alphabet_bytes[((triple >> 6) & 0x3F) as usize] as char);
        }

        if remaining > 2 {
            result.push(alphabet_bytes[(triple & 0x3F) as usize] as char);
        } else if pad {
            // remaining == 2: one '='
            // remaining == 1: two '='
            result.push('=');
            if remaining == 1 {
                result.push('=');
            }
        }

        i += 3;
    }

    result
}

/// Decode base64 input according to the given options.
pub fn decode(input: &[u8], opts: &DecodeOptions) -> Result<Vec<u8>, Base64Error> {
    let reverse_table = make_reverse_table(opts.alphabet);

    // Step 1: Filter - walk all input bytes
    let mut s: Vec<u8> = Vec::with_capacity(input.len());
    for &byte in input {
        if opts.ignore_whitespace && is_whitespace(byte) {
            continue;
        }
        if byte == b'=' {
            s.push(b'=');
        } else {
            let idx = reverse_table[byte as usize];
            if idx == 255 {
                return Err(Base64Error::InvalidByte);
            }
            s.push(byte);
        }
    }

    // Empty input (or only whitespace) decodes to empty Vec
    if s.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Pad placement
    let p = count_trailing_equals(&s);
    if p > 2 {
        return Err(Base64Error::InvalidPadding);
    }
    // Check that no '=' occurs before the trailing run
    for &byte in &s[..s.len() - p] {
        if byte == b'=' {
            return Err(Base64Error::InvalidPadding);
        }
    }

    // Step 3: Length
    let n = s.len() - p; // number of data symbols
    if n % 4 == 1 {
        return Err(Base64Error::InvalidLength);
    }

    // Step 4: Pad rules
    if p > 0 {
        if opts.padding == Padding::Forbidden || (n + p) % 4 != 0 {
            return Err(Base64Error::InvalidPadding);
        }
    } else {
        if n % 4 != 0 && opts.padding == Padding::Required {
            return Err(Base64Error::InvalidPadding);
        }
    }

    // Step 5: Limit
    let output_len = output_length(n);
    if output_len > opts.max_output {
        return Err(Base64Error::LimitExceeded);
    }

    // Step 6: Canonical - check trailing bits
    if n % 4 == 2 {
        // Low 4 bits of last data symbol must be 0
        let last_byte = s[n - 1];
        let last_value = reverse_table[last_byte as usize] as u32;
        if last_value & 0xF != 0 {
            return Err(Base64Error::NonCanonical);
        }
    } else if n % 4 == 3 {
        // Low 2 bits of last data symbol must be 0
        let last_byte = s[n - 1];
        let last_value = reverse_table[last_byte as usize] as u32;
        if last_value & 0x3 != 0 {
            return Err(Base64Error::NonCanonical);
        }
    }

    // Step 7: Decode symbols big-endian 6 bits at a time
    let mut output = Vec::with_capacity(output_len);
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;

    for i in 0..n {
        let byte = s[i];
        let value = reverse_table[byte as usize] as u32;
        bits = (bits << 6) | value;
        bit_count += 6;

        while bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }

    Ok(output)
}

fn is_whitespace(byte: u8) -> bool {
    byte == b' ' || byte == b'\t' || byte == b'\r' || byte == b'\n'
}

fn count_trailing_equals(s: &[u8]) -> usize {
    let mut count = 0;
    for byte in s.iter().rev() {
        if *byte == b'=' {
            count += 1;
        } else {
            break;
        }
    }
    count
}

fn output_length(n: usize) -> usize {
    n / 4 * 3 + match n % 4 {
        2 => 1,
        3 => 2,
        _ => 0,
    }
}

fn make_reverse_table(alphabet: Alphabet) -> [u8; 256] {
    let table_bytes = match alphabet {
        Alphabet::Standard => STANDARD_ALPHABET,
        Alphabet::UrlSafe => URL_SAFE_ALPHABET,
    };
    let mut table = [255u8; 256];
    for (i, &byte) in table_bytes.iter().enumerate() {
        table[byte as usize] = i as u8;
    }
    table
}
