#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzwError {
    Truncated,
    BadMagic,
    BadHeader,
    InvalidCode,
    LimitExceeded,
}

/// Decompress a Unix compress (.Z) LZW stream.
pub fn decompress_z(input: &[u8], max_output: usize) -> Result<Vec<u8>, LzwError> {
    // Header validation
    if input.len() < 3 {
        return Err(LzwError::Truncated);
    }
    if input[0] != 0x1F || input[1] != 0x9D {
        return Err(LzwError::BadMagic);
    }
    let flags = input[2];
    let maxbits = (flags & 0x1F) as u32;
    if maxbits < 9 || maxbits > 16 {
        return Err(LzwError::BadHeader);
    }
    let reserved = flags & 0x60;
    if reserved != 0 {
        return Err(LzwError::BadHeader);
    }
    let block_mode = (flags & 0x80) != 0;

    let mut pos: u32 = 3 * 8;
    let mut n: u32 = 9;
    let mut maxcode: u32 = (1 << n) - 1;
    let free_ent_start: u32 = if block_mode { 257 } else { 256 };
    let max_entries: u32 = 1 << maxbits;

    let mut table_prefix: Vec<u32> = vec![0; 65536];
    let mut table_byte: Vec<u8> = vec![0; 65536];
    for i in 0..=255u32 {
        table_prefix[i as usize] = 0;
        table_byte[i as usize] = i as u8;
    }

    let mut free_ent = free_ent_start;
    let mut prev_code: Option<u32> = None;
    let mut count: u32 = 0;

    let mut output = Vec::with_capacity(max_output.min(65536));
    let mut total_len: usize = 0;
    let mut scratch: Vec<u8> = Vec::with_capacity(65536);

    loop {
        // Step 1: If table is full, expand width
        if free_ent > maxcode {
            let pad = ((8 - (count % 8)) % 8) * n;
            pos += pad;
            if pos > (input.len() as u32) * 8 {
                pos = (input.len() as u32) * 8;
            }
            count = 0;
            n += 1;
            if n == maxbits {
                maxcode = 1 << maxbits;
            } else {
                maxcode = (1 << n) - 1;
            }
        }

        // Step 2: Check if enough bits remain
        if pos + n > (input.len() as u32) * 8 {
            break;
        }

        // Read code
        let code = {
            let mut c: u32 = 0;
            for i in 0..n {
                let bit_pos = pos + i;
                let byte_idx = (bit_pos / 8) as usize;
                let bit_idx = (bit_pos % 8) as u32;
                let bit = ((input[byte_idx] >> bit_idx) & 1) as u32;
                c |= bit << i;
            }
            pos += n;
            c
        };
        count += 1;

        // Step 3: CLEAR code in block mode
        if block_mode && code == 256 {
            let pad = ((8 - (count % 8)) % 8) * n;
            pos += pad;
            if pos > (input.len() as u32) * 8 {
                pos = (input.len() as u32) * 8;
            }
            count = 0;
            n = 9;
            maxcode = 511;
            free_ent = 257;
            prev_code = None;
            for i in 0..=255u32 {
                table_prefix[i as usize] = 0;
                table_byte[i as usize] = i as u8;
            }
            continue;
        }

        // Step 4: First code must be literal
        if prev_code.is_none() {
            if code >= 256 {
                return Err(LzwError::InvalidCode);
            }
            if total_len + 1 > max_output {
                return Err(LzwError::LimitExceeded);
            }
            output.push(code as u8);
            total_len += 1;
            prev_code = Some(code);
            continue;
        }

        // Step 5: Decode the code
        let string_bytes: Vec<u8>;
        if code < free_ent {
            scratch.clear();
            let mut c = code;
            loop {
                scratch.push(table_byte[c as usize]);
                if c < 256 {
                    break;
                }
                c = table_prefix[c as usize];
            }
            scratch.reverse();
            string_bytes = scratch.clone();
        } else if code == free_ent {
            scratch.clear();
            let mut c = prev_code.unwrap();
            loop {
                scratch.push(table_byte[c as usize]);
                if c < 256 {
                    break;
                }
                c = table_prefix[c as usize];
            }
            scratch.reverse();
            let first = scratch[0];
            // Don't move scratch, clone it
            let mut s = scratch.clone();
            s.push(first);
            string_bytes = s;
        } else {
            return Err(LzwError::InvalidCode);
        }

        // Step 6: Output and add new entry
        if total_len + string_bytes.len() > max_output {
            return Err(LzwError::LimitExceeded);
        }
        output.extend_from_slice(&string_bytes);
        total_len += string_bytes.len();

        if free_ent < max_entries {
            let prev = prev_code.unwrap();
            let first_byte = string_bytes[0];
            table_prefix[free_ent as usize] = prev;
            table_byte[free_ent as usize] = first_byte;
            free_ent += 1;
        }

        prev_code = Some(code);
    }

    Ok(output)
}
