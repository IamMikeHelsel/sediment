/// Split a string into path components by splitting on `/` and `\`,
/// then dropping empty components and components equal to `.`.
/// `..` is kept as a literal component.
fn split_components(s: &str) -> Vec<&str> {
    // Iterate bytes: '/' and '\\' are ASCII, so every split point is a
    // char boundary even when components contain multibyte UTF-8.
    let mut components = Vec::new();
    let mut start = 0;
    let bytes = s.as_bytes();
    let len = bytes.len();

    for i in 0..len {
        if bytes[i] == b'/' || bytes[i] == b'\\' {
            let component = &s[start..i];
            if !component.is_empty() && component != "." {
                components.push(component);
            }
            start = i + 1;
        }
    }

    // Handle the last component
    if start < len {
        let component = &s[start..];
        if !component.is_empty() && component != "." {
            components.push(component);
        }
    }

    components
}

/// Match a single pattern component against a single name component.
/// Uses the standard greedy algorithm with O(pattern_len * name_len) worst case.
pub fn match_name(pattern: &str, name: &str, case_sensitive: bool) -> bool {
    let pat_chars: Vec<char> = pattern.chars().collect();
    let name_chars: Vec<char> = name.chars().collect();

    let pat_len = pat_chars.len();
    let name_len = name_chars.len();

    let mut p = 0; // pattern index
    let mut n = 0; // name index

    // star_p and star_n track the position after the last '*' seen
    let mut star_p: Option<usize> = None;
    let mut star_n: Option<usize> = None;

    while n < name_len {
        // Check if current pattern char matches current name char
        let matches = if p < pat_len {
            let pc = pat_chars[p];
            if pc == '*' {
                // '*' matches any sequence including empty
                star_p = Some(p);
                star_n = Some(n);
                p += 1;
                continue;
            } else if pc == '?' {
                // '?' matches exactly one character
                true
            } else {
                // Exact match or case-insensitive match
                if case_sensitive {
                    pc == name_chars[n]
                } else {
                    pc.to_lowercase().eq(name_chars[n].to_lowercase())
                }
            }
        } else {
            false
        };

        if matches {
            p += 1;
            n += 1;
        } else {
            // Mismatch: try to backtrack to the last '*'
            if let (Some(sp), Some(sn)) = (star_p, star_n) {
                // Advance star_n by one character in the name
                star_n = Some(sn + 1);
                n = sn + 1;
                p = sp + 1;
            } else {
                return false;
            }
        }
    }

    // Skip trailing '*' in pattern
    while p < pat_len && pat_chars[p] == '*' {
        p += 1;
    }

    p == pat_len
}

/// Match a pattern against a full path.
/// `recursive`: if true, the pattern can match at any depth (unless anchored by separators).
/// `case_sensitive`: if false, matching is case-insensitive.
pub fn match_path(pattern: &str, path: &str, recursive: bool, case_sensitive: bool) -> bool {
    let pat_components = split_components(pattern);
    let path_components = split_components(path);

    // If pattern has no components, it doesn't match anything
    if pat_components.is_empty() {
        return false;
    }

    // If pattern has more components than the path, it can't match
    if pat_components.len() > path_components.len() {
        return false;
    }

    // Determine if the pattern is anchored:
    // Anchored if recursive is false OR the pattern contains '/' or '\'
    let anchored = !recursive || pattern.contains('/') || pattern.contains('\\');

    // Determine the range of start indices for matching
    let start_range = if anchored {
        0..=0
    } else {
        0..=path_components.len().saturating_sub(pat_components.len())
    };

    // Try each possible start index
    for s in start_range {
        let mut all_match = true;
        for i in 0..pat_components.len() {
            if !match_name(pat_components[i], path_components[s + i], case_sensitive) {
                all_match = false;
                break;
            }
        }
        if all_match {
            return true;
        }
    }

    false
}
