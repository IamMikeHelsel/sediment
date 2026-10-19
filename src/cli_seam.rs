// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adapter seam for the FORGE-owned leaf modules the 7-Zip CLI layer needs:
//! `wildcard`, `listfile` and `slt_format`.
//!
//! The capability registry assigns `src/wildcard.rs`, `src/listfile.rs` and
//! `src/slt_format.rs` to FORGE. They were not harvested into
//! `sprint/integration` when the CLI layer was built, so this module carries
//! minimal implementations with the **exact public APIs** of those tickets.
//! The CLI only calls them through `crate::cli_seam::{wildcard, listfile,
//! slt_format}`; once the FORGE modules land, each submodule body below is
//! replaced by a re-export (`pub use crate::wildcard::*;` etc.) and nothing
//! else changes.
//!
//! Spec sources: 7-Zip command line documentation (wildcards, `@listfile`,
//! `-slt`), RFC 3629 (UTF-8), RFC 2781 (UTF-16), Microsoft FILETIME (100 ns
//! ticks since 1601-01-01 UTC) and FILE_ATTRIBUTE_* values, POSIX `ls -l`
//! mode strings. Implemented from those descriptions; no 7-Zip source used.

/// `*` / `?` wildcard matching per path component (7-Zip style).
pub mod wildcard {
    fn eq_char(a: char, b: char, case_sensitive: bool) -> bool {
        a == b || (!case_sensitive && a.to_lowercase().eq(b.to_lowercase()))
    }

    /// Match one path component. `*` = any run (also empty), `?` = one char.
    /// Greedy backtracking, O(pattern * name) worst case.
    pub fn match_name(pattern: &str, name: &str, case_sensitive: bool) -> bool {
        let p: Vec<char> = pattern.chars().collect();
        let n: Vec<char> = name.chars().collect();
        let (mut pi, mut ni) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while ni < n.len() {
            if pi < p.len() && p[pi] == '*' {
                star = Some((pi, ni));
                pi += 1;
            } else if pi < p.len() && (p[pi] == '?' || eq_char(p[pi], n[ni], case_sensitive)) {
                pi += 1;
                ni += 1;
            } else if let Some((sp, sn)) = star {
                pi = sp + 1;
                ni = sn + 1;
                star = Some((sp, sn + 1));
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == '*' {
            pi += 1;
        }
        pi == p.len()
    }

    fn components(s: &str) -> Vec<&str> {
        s.split(['/', '\\']).filter(|c| !c.is_empty() && *c != ".").collect()
    }

    /// Match a pattern against an archive path. Anchored at the first
    /// component unless `recursive` and the pattern has no separator; a
    /// match of a leading part also selects everything below it.
    pub fn match_path(pattern: &str, path: &str, recursive: bool, case_sensitive: bool) -> bool {
        let p = components(pattern);
        let n = components(path);
        if p.is_empty() || p.len() > n.len() {
            return false;
        }
        let anchored = !recursive || pattern.contains(['/', '\\']);
        let last_start = if anchored { 0 } else { n.len() - p.len() };
        (0..=last_start).any(|s| p.iter().zip(&n[s..]).all(|(pc, nc)| match_name(pc, nc, case_sensitive)))
    }
}

/// `@listfile` parsing: one path per line, UTF-8 (optional BOM) or UTF-16LE with BOM.
pub mod listfile {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ListFileError {
        LimitExceeded,
        InvalidUtf8,
        InvalidUtf16,
        UnsupportedEncoding,
        NulCharacter,
    }

    pub fn parse_listfile(data: &[u8], max_bytes: usize) -> Result<Vec<String>, ListFileError> {
        if data.len() > max_bytes {
            return Err(ListFileError::LimitExceeded);
        }
        let text = if data.starts_with(b"\xfe\xff") {
            return Err(ListFileError::UnsupportedEncoding);
        } else if let Some(rest) = data.strip_prefix(b"\xff\xfe") {
            if rest.len() % 2 != 0 {
                return Err(ListFileError::InvalidUtf16);
            }
            let mut units = Vec::new();
            units.try_reserve_exact(rest.len() / 2).map_err(|_| ListFileError::LimitExceeded)?;
            units.extend(rest.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])));
            String::from_utf16(&units).map_err(|_| ListFileError::InvalidUtf16)?
        } else {
            let body = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
            std::str::from_utf8(body).map_err(|_| ListFileError::InvalidUtf8)?.to_owned()
        };
        if text.contains('\0') {
            return Err(ListFileError::NulCharacter);
        }
        let mut out = Vec::new();
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            let line = line.trim_matches([' ', '\t']);
            if !line.is_empty() {
                out.try_reserve(1).map_err(|_| ListFileError::LimitExceeded)?;
                out.push(line.to_owned());
            }
        }
        Ok(out)
    }
}

/// 7-Zip `-slt` technical listing blocks.
pub mod slt_format {
    use std::fmt::Write;

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct SltEntry {
        pub path: String,
        pub folder: Option<bool>,
        pub size: u64,
        pub packed_size: Option<u64>,
        /// FILETIME (100 ns ticks since 1601-01-01 UTC).
        pub modified: Option<u64>,
        pub created: Option<u64>,
        pub accessed: Option<u64>,
        pub attributes: Option<u32>,
        pub crc: Option<u32>,
        pub encrypted: bool,
        pub method: String,
        pub block: Option<u64>,
    }

    fn is_leap(y: u64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }

    /// `YYYY-MM-DD HH:MM:SS.fffffff` (UTC) for any u64 FILETIME.
    pub fn format_filetime(ft: u64) -> String {
        let frac = ft % 10_000_000;
        let secs = ft / 10_000_000;
        let mut days = secs / 86_400;
        let sod = secs % 86_400;
        let mut year = 1601 + (days / 146_097) * 400;
        days %= 146_097;
        loop {
            let len = if is_leap(year) { 366 } else { 365 };
            if days < len {
                break;
            }
            days -= len;
            year += 1;
        }
        let feb = if is_leap(year) { 29 } else { 28 };
        let months = [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut month = 1;
        for m in months {
            if days < m {
                break;
            }
            days -= m;
            month += 1;
        }
        format!(
            "{year:04}-{month:02}-{:02} {:02}:{:02}:{:02}.{frac:07}",
            days + 1,
            sod / 3600,
            (sod / 60) % 60,
            sod % 60
        )
    }

    /// POSIX `ls -l` style 10-character mode string.
    pub fn unix_mode_string(mode: u32) -> String {
        let kind = match mode & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            0o100000 | 0 => '-',
            0o020000 => 'c',
            0o060000 => 'b',
            0o010000 => 'p',
            0o140000 => 's',
            _ => '?',
        };
        let mut s = String::with_capacity(10);
        s.push(kind);
        let triplets = [(0o400, 0o200, 0o100, 0o4000, 's', 'S'), (0o040, 0o020, 0o010, 0o2000, 's', 'S'), (0o004, 0o002, 0o001, 0o1000, 't', 'T')];
        for (r, w, x, special, on, off) in triplets {
            s.push(if mode & r != 0 { 'r' } else { '-' });
            s.push(if mode & w != 0 { 'w' } else { '-' });
            s.push(match (mode & special != 0, mode & x != 0) {
                (true, true) => on,
                (true, false) => off,
                (false, true) => 'x',
                (false, false) => '-',
            });
        }
        s
    }

    /// Windows attribute letters (`RHSDA`), plus the Unix mode when bit 0x8000 is set.
    pub fn format_attributes(attrib: u32) -> String {
        let mut s = String::new();
        for (bit, c) in [(0x01, 'R'), (0x02, 'H'), (0x04, 'S'), (0x10, 'D'), (0x20, 'A')] {
            if attrib & bit != 0 {
                s.push(c);
            }
        }
        if attrib & 0x8000 != 0 {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(&unix_mode_string(attrib >> 16));
        }
        s
    }

    pub fn format_entry(e: &SltEntry) -> String {
        fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
            v.map(|x| x.to_string()).unwrap_or_default()
        }
        let mut s = String::new();
        let _ = writeln!(s, "Path = {}", e.path);
        if let Some(f) = e.folder {
            let _ = writeln!(s, "Folder = {}", if f { '+' } else { '-' });
        }
        let _ = writeln!(s, "Size = {}", e.size);
        let _ = writeln!(s, "Packed Size = {}", opt(e.packed_size));
        let _ = writeln!(s, "Modified = {}", e.modified.map(format_filetime).unwrap_or_default());
        if let Some(c) = e.created {
            let _ = writeln!(s, "Created = {}", format_filetime(c));
        }
        if let Some(a) = e.accessed {
            let _ = writeln!(s, "Accessed = {}", format_filetime(a));
        }
        let _ = writeln!(s, "Attributes = {}", e.attributes.map(format_attributes).unwrap_or_default());
        let _ = writeln!(s, "CRC = {}", e.crc.map(|c| format!("{c:08X}")).unwrap_or_default());
        let _ = writeln!(s, "Encrypted = {}", if e.encrypted { '+' } else { '-' });
        let _ = writeln!(s, "Method = {}", e.method);
        let _ = writeln!(s, "Block = {}", opt(e.block));
        s.push('\n');
        s
    }

    pub fn format_entries(entries: &[SltEntry]) -> String {
        entries.iter().map(format_entry).collect()
    }
}
