// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sediment h`: hash files and directory trees, 7-Zip `h` style.
//!
//! ```text
//! sediment h [-scrc<METHOD>[,<METHOD>...]]... [--] PATH...
//! ```
//!
//! `METHOD` is one of CRC32 (default), CRC64, XXH64, MD5, SHA1, SHA224,
//! SHA256, SHA384, SHA512, SHA3-256, BLAKE2sp, or `*` for all of them
//! (case-insensitive; see [`crate::hash_multi`]). Directories are walked
//! recursively with [`crate::fs_collect`] (symlinks followed, loops skipped),
//! entries sorted by name. File contents are streamed in 1 MiB chunks, so file
//! size is bounded only by [`HashLimits::max_total_bytes`].
//!
//! Output layout (one column per method, digest width or name width,
//! whichever is wider):
//!
//! ```text
//! CRC32         Size  Name
//! -------- -------------  ------------
//! 3610A686            5  a.txt
//!                        dir
//! ...
//! -------- -------------  ------------
//! 3610A686            5
//!
//! Size: 5
//!
//! CRC32  for data:              3610A686
//! ```
//!
//! Directory rows have blank digest and size cells. The totals row and the
//! "for data" lines carry the per-file digests summed as little-endian
//! integers ([`crate::hash_multi::Digest::add`]). When more than one entry is
//! listed the summary has `Folders:`/`Files:` lines and an extra "for data and
//! names" line: that total additionally adds, for every listed entry, the
//! digest of its displayed name bytes (UTF-8, `/` separators). Names follow
//! the `fs_collect` convention: an input contributes its final path component
//! as the root (`h /x/dir` lists `dir`, `dir/a`, ...). Trailing whitespace is
//! trimmed from every line.
//!
//! Exit codes: 0 success; 1 warning (an input was missing or a file or
//! directory could not be read; the rest is still reported); 2 usage or fatal
//! error (bad switch, limit exceeded, output write failure).

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use crate::archive_name::escape_name;
use crate::fs_collect::{collect, CollectLimits, CollectOptions, EntryKind, WarningKind};
use crate::hash_multi::{digest, parse_method_list, Digest, HashMethod, MultiHasher};

pub const EXIT_OK: i32 = 0;
pub const EXIT_WARNING: i32 = 1;
pub const EXIT_FATAL: i32 = 2;

/// Read buffer size used when streaming files.
pub const CHUNK: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashCliError {
    /// Bad command line (unknown switch, unknown method, no paths).
    Usage,
    /// Entry-count, depth or total-size limit exceeded.
    LimitExceeded,
    /// A name could not be represented.
    InvalidName,
    Allocation,
    /// Writing the report failed.
    Output,
}

/// Explicit caps for one `h` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashLimits {
    /// Maximum number of listed entries (files plus directories).
    pub max_entries: usize,
    /// Maximum directory nesting depth.
    pub max_depth: usize,
    /// Maximum bytes hashed in total.
    pub max_total_bytes: u64,
}

impl Default for HashLimits {
    fn default() -> Self {
        HashLimits { max_entries: 1_000_000, max_depth: 256, max_total_bytes: 1 << 44 }
    }
}

/// One listed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashRow {
    /// Display name (`/` separators, no leading slash).
    pub name: Vec<u8>,
    pub is_dir: bool,
    /// Bytes hashed (0 for directories).
    pub size: u64,
    /// One digest per method (empty for directories).
    pub digests: Vec<Digest>,
}

/// A non-fatal problem encountered while hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashWarning {
    pub path: PathBuf,
    pub message: &'static str,
}

/// Complete result of hashing a set of inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashReport {
    pub methods: Vec<HashMethod>,
    pub rows: Vec<HashRow>,
    pub files: u64,
    pub folders: u64,
    pub total_size: u64,
    /// Sum of file digests, one per method.
    pub data_sum: Vec<Digest>,
    /// Sum of file digests plus digests of every listed name.
    pub data_and_names_sum: Vec<Digest>,
    pub warnings: Vec<HashWarning>,
}

/// Stream `reader` through every method, reading at most `max_bytes` bytes.
/// Returns the byte count and digests. A stream longer than `max_bytes` is
/// reported as an `io::ErrorKind::InvalidData` error.
pub fn hash_reader<R: Read>(reader: &mut R, methods: &[HashMethod], max_bytes: u64) -> io::Result<(u64, Vec<Digest>)> {
    let mut buf = Vec::new();
    buf.try_reserve_exact(CHUNK).map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    buf.resize(CHUNK, 0);
    let mut mh = MultiHasher::new(methods);
    let mut total: u64 = 0;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        total = total.checked_add(n as u64).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if total > max_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "size limit exceeded"));
        }
        mh.update(&buf[..n]);
    }
    Ok((total, mh.finalize()))
}

fn add_all(acc: &mut [Digest], ds: &[Digest]) {
    for (a, d) in acc.iter_mut().zip(ds) {
        a.add(d);
    }
}

/// Hash every input (files or directories). Missing inputs and unreadable
/// entries become warnings; limits are fatal.
pub fn hash_inputs(inputs: &[PathBuf], methods: &[HashMethod], limits: HashLimits) -> Result<HashReport, HashCliError> {
    if methods.is_empty() {
        return Err(HashCliError::Usage);
    }
    let zero: Vec<Digest> = methods.iter().map(|&m| Digest::zero(m)).collect();
    let mut rep = HashReport {
        methods: methods.to_vec(),
        rows: Vec::new(),
        files: 0,
        folders: 0,
        total_size: 0,
        data_sum: zero.clone(),
        data_and_names_sum: zero,
        warnings: Vec::new(),
    };
    let mut names_sum: Vec<Digest> = methods.iter().map(|&m| Digest::zero(m)).collect();
    let options = CollectOptions { follow_symlinks: true, ..CollectOptions::default() };
    for input in inputs {
        if std::fs::metadata(input).is_err() {
            rep.warnings.push(HashWarning { path: input.clone(), message: "cannot find the file" });
            continue;
        }
        let remaining = limits.max_entries.saturating_sub(rep.rows.len());
        let cl = CollectLimits {
            max_entries: remaining,
            max_total_bytes: limits.max_total_bytes.saturating_sub(rep.total_size),
            max_depth: limits.max_depth,
            max_name_bytes: 65535,
        };
        let collected = match collect(std::slice::from_ref(input), &options, cl) {
            Ok(c) => c,
            Err(crate::fs_collect::CollectError::NotFound) => {
                rep.warnings.push(HashWarning { path: input.clone(), message: "cannot find the file" });
                continue;
            }
            Err(crate::fs_collect::CollectError::LimitExceeded) => return Err(HashCliError::LimitExceeded),
            Err(crate::fs_collect::CollectError::Allocation) => return Err(HashCliError::Allocation),
            Err(_) => return Err(HashCliError::InvalidName),
        };
        for w in collected.warnings {
            let message = match w.kind {
                WarningKind::UnreadableDirectory => "cannot read directory",
                WarningKind::UnreadableFile => "cannot open the file",
                WarningKind::SpecialFile => "skipped special file",
                WarningKind::SymlinkLoop => "skipped symbolic link loop",
                WarningKind::ExcludedOutput => "excluded",
            };
            rep.warnings.push(HashWarning { path: w.path, message });
        }
        for e in collected.entries {
            if rep.rows.len() >= limits.max_entries {
                return Err(HashCliError::LimitExceeded);
            }
            rep.rows.try_reserve(1).map_err(|_| HashCliError::Allocation)?;
            let row = match e.kind {
                EntryKind::Directory => {
                    rep.folders += 1;
                    HashRow { name: e.name, is_dir: true, size: 0, digests: Vec::new() }
                }
                EntryKind::File => {
                    let budget = limits.max_total_bytes - rep.total_size;
                    let res = std::fs::File::open(&e.source).and_then(|mut f| hash_reader(&mut f, methods, budget));
                    let (size, digests) = match res {
                        Ok(v) => v,
                        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                            return Err(HashCliError::LimitExceeded);
                        }
                        Err(_) => {
                            rep.warnings.push(HashWarning { path: e.source, message: "cannot read the file" });
                            continue;
                        }
                    };
                    rep.files += 1;
                    rep.total_size += size; // bounded by max_total_bytes via budget
                    add_all(&mut rep.data_sum, &digests);
                    HashRow { name: e.name, is_dir: false, size, digests }
                }
                // follow_symlinks is set, so links are resolved by fs_collect.
                EntryKind::Symlink => continue,
            };
            for (acc, &m) in names_sum.iter_mut().zip(methods) {
                acc.add(&digest(m, &row.name));
            }
            rep.rows.push(row);
        }
    }
    rep.data_and_names_sum = rep.data_sum.clone();
    add_all(&mut rep.data_and_names_sum, &names_sum);
    Ok(rep)
}

fn show_name(name: &[u8]) -> String {
    escape_name(name).unwrap_or_else(|_| String::from_utf8_lossy(name).into_owned())
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line.trim_end());
    out.push('\n');
}

/// Render a report as text (see the module docs for the layout).
pub fn format_report(rep: &HashReport) -> String {
    let widths: Vec<usize> = rep.methods.iter().map(|m| (m.digest_len() * 2).max(m.name().len())).collect();
    let mut out = String::new();
    let mut line = String::new();
    for (m, &w) in rep.methods.iter().zip(&widths) {
        line.push_str(&format!("{:<w$} ", m.name()));
    }
    line.push_str(&format!("{:>13}  Name", "Size"));
    push_line(&mut out, &line);
    let mut sep = String::new();
    for &w in &widths {
        sep.push_str(&"-".repeat(w));
        sep.push(' ');
    }
    sep.push_str(&"-".repeat(13));
    sep.push_str("  ");
    sep.push_str(&"-".repeat(12));
    push_line(&mut out, &sep);
    for row in &rep.rows {
        line.clear();
        for (i, &w) in widths.iter().enumerate() {
            let cell = row.digests.get(i).map(Digest::to_hex).unwrap_or_default();
            line.push_str(&format!("{cell:<w$} "));
        }
        if row.is_dir {
            line.push_str(&" ".repeat(13));
        } else {
            line.push_str(&format!("{:>13}", row.size));
        }
        line.push_str("  ");
        line.push_str(&show_name(&row.name));
        push_line(&mut out, &line);
    }
    push_line(&mut out, &sep);
    line.clear();
    for (d, &w) in rep.data_sum.iter().zip(&widths) {
        line.push_str(&format!("{:<w$} ", d.to_hex()));
    }
    line.push_str(&format!("{:>13}", rep.total_size));
    push_line(&mut out, &line);
    out.push('\n');
    let multi = rep.rows.len() != 1;
    if multi {
        push_line(&mut out, &format!("Folders: {}", rep.folders));
        push_line(&mut out, &format!("Files: {}", rep.files));
    }
    push_line(&mut out, &format!("Size: {}", rep.total_size));
    out.push('\n');
    for (i, m) in rep.methods.iter().enumerate() {
        let label = format!("{:<6} for data:", m.name());
        push_line(&mut out, &format!("{label:<29} {}", rep.data_sum[i].to_hex()));
        if multi {
            let label = format!("{:<6} for data and names:", m.name());
            push_line(&mut out, &format!("{label:<29} {}", rep.data_and_names_sum[i].to_hex()));
        }
    }
    out
}

/// Parsed `h` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashArgs {
    pub methods: Vec<HashMethod>,
    pub inputs: Vec<PathBuf>,
}

/// Parse the arguments after `h`.
pub fn parse_hash_args(args: &[OsString]) -> Result<HashArgs, HashCliError> {
    let mut specs: Vec<String> = Vec::new();
    let mut inputs = Vec::new();
    let mut switches = true;
    for a in args {
        let bytes = a.as_encoded_bytes();
        if switches && bytes == b"--" {
            switches = false;
            continue;
        }
        if switches && bytes.len() > 1 && bytes[0] == b'-' {
            let s = a.to_str().ok_or(HashCliError::Usage)?;
            // Compare on bytes: a multi-byte character may straddle byte 5,
            // so slicing the str there could panic.
            if bytes.len() > 5 && bytes[..5].eq_ignore_ascii_case(b"-scrc") {
                let spec = s.get(5..).ok_or(HashCliError::Usage)?;
                specs.push(spec.to_string());
                continue;
            }
            return Err(HashCliError::Usage);
        }
        inputs.push(PathBuf::from(a));
    }
    if inputs.is_empty() {
        return Err(HashCliError::Usage);
    }
    let refs: Vec<&str> = specs.iter().map(String::as_str).collect();
    let methods = parse_method_list(&refs).map_err(|_| HashCliError::Usage)?;
    Ok(HashArgs { methods, inputs })
}

/// Run `sediment h` and return its exit code. Report goes to stdout,
/// warnings and errors to stderr.
pub fn run_hash(args: &[OsString]) -> i32 {
    let mut err = io::stderr().lock();
    let parsed = match parse_hash_args(args) {
        Ok(p) => p,
        Err(_) => {
            let _ = writeln!(
                err,
                "sediment: usage: sediment h [-scrc<CRC32|CRC64|XXH64|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3-256|BLAKE2sp|*>]... PATH..."
            );
            return EXIT_FATAL;
        }
    };
    let rep = match hash_inputs(&parsed.inputs, &parsed.methods, HashLimits::default()) {
        Ok(r) => r,
        Err(e) => {
            let msg = match e {
                HashCliError::LimitExceeded => "limit exceeded",
                HashCliError::Allocation => "out of memory",
                HashCliError::InvalidName => "invalid file name",
                _ => "hashing failed",
            };
            let _ = writeln!(err, "sediment: {msg}");
            return EXIT_FATAL;
        }
    };
    for w in &rep.warnings {
        let _ = writeln!(err, "sediment: warning: {}: {}", w.message, w.path.display());
    }
    let text = format_report(&rep);
    let mut out = io::stdout().lock();
    if out.write_all(text.as_bytes()).and_then(|_| out.flush()).is_err() {
        let _ = writeln!(err, "sediment: write error");
        return EXIT_FATAL;
    }
    if rep.warnings.is_empty() { EXIT_OK } else { EXIT_WARNING }
}
