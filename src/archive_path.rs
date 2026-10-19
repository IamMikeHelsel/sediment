// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    InvalidUtf8,
    InvalidPath,
    LimitExceeded,
}

pub fn validate_path(name: &[u8]) -> Result<(), PathError> {
    // Check UTF-8 validity first
    if std::str::from_utf8(name).is_err() {
        return Err(PathError::InvalidUtf8);
    }

    // Check total length limit
    if name.len() > 4096 {
        return Err(PathError::LimitExceeded);
    }

    // Reject empty path
    if name.is_empty() {
        return Err(PathError::InvalidPath);
    }

    // Reject leading slash
    if name[0] == b'/' {
        return Err(PathError::InvalidPath);
    }

    // Handle trailing slash for directory indicator
    let path = if name.last() == Some(&b'/') {
        if name.len() == 1 {
            // Just a single slash
            return Err(PathError::InvalidPath);
        }
        &name[..name.len() - 1]
    } else {
        name
    };

    // Split into components
    let components: Vec<&[u8]> = path.split(|&b| b == b'/').collect();

    // Check component count limit
    if components.len() > 64 {
        return Err(PathError::LimitExceeded);
    }

    // Validate each component
    for component in &components {
        // Reject empty components (including repeated slashes)
        if component.is_empty() {
            return Err(PathError::InvalidPath);
        }

        // Check component length limit
        if component.len() > 255 {
            return Err(PathError::LimitExceeded);
        }

        // Check for invalid bytes
        for &byte in component.iter() {
            match byte {
                b'\\' | b':' | 0 => return Err(PathError::InvalidPath),
                0x01..=0x1F | 0x7F => return Err(PathError::InvalidPath),
                _ => {}
            }
        }

        // Reject components ending in ASCII space or period
        if *component.last().unwrap() == b' ' || *component.last().unwrap() == b'.' {
            return Err(PathError::InvalidPath);
        }

        // Reject '.' and '..' components
        if component == b"." || component == b".." {
            return Err(PathError::InvalidPath);
        }

        // Check Windows device names (case-insensitive stem before first '.')
        let stem_end = component.iter().position(|&b| b == b'.').unwrap_or(component.len());
        let stem = &component[..stem_end];
        
        // Convert stem to uppercase for comparison
        let stem_upper = stem
            .iter()
            .map(|&b| if b'a' <= b && b <= b'z' { b - 32 } else { b })
            .collect::<Vec<_>>();
        
        match stem_upper.as_slice() {
            b"CON" | b"PRN" | b"AUX" | b"NUL" => return Err(PathError::InvalidPath),
            b"CONIN$" | b"CONOUT$" => return Err(PathError::InvalidPath),
            _ => {
                // Check COM1..COM9 and LPT1..LPT9 (only when stem length is exactly 4)
                if stem_upper.len() == 4 {
                    if stem_upper[0..3] == [b'C', b'O', b'M'] || stem_upper[0..3] == [b'L', b'P', b'T'] {
                        let digit = stem_upper[3];
                        if b'1' <= digit && digit <= b'9' {
                            return Err(PathError::InvalidPath);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
