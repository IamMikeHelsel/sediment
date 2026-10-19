// SPDX-License-Identifier: MIT OR Apache-2.0
//! Single-file compression for `sediment a out.gz|out.xz|out.bz2 FILE`.
//!
//! The output name selects the stream format (case-insensitive `.gz`, `.xz`,
//! `.bz2`; the compressed-tar names `.tar.gz`, `.tgz`, `.tar.xz`, ... are
//! handled by `cli_add` as tar archives first). Exactly one regular input
//! file is compressed into one stream with `compress_wrap::compress`, using
//! the same `-mx` level mapping as compressed tar archives. Output is
//! deterministic: the gzip header carries no name and MTIME 0.
//!
//! Spec sources: RFC 1952 (gzip), "The .xz File Format", the bzip2 stream
//! format as documented in the bzip2 manual (see the encoder modules).

use std::io::{Read, Write};
use std::path::Path;

use crate::compress_wrap::{Compression, WrapError, compress, compress_bound_for};

/// Largest input file accepted for single-file compression (1 GiB, the same
/// as the default archive collection limit).
pub const MAX_SINGLE_INPUT: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleError {
    /// Not exactly one input path.
    InputCount,
    /// The input does not exist or cannot be opened/read.
    Unreadable,
    /// The input is a directory or a special file.
    NotRegularFile,
    /// The input and the output are the same file.
    SameFile,
    /// The input is larger than the limit, or the output would be.
    LimitExceeded,
    /// The input changed size while it was read.
    Changed,
    Allocation,
    InvalidLevel,
}

/// Stream format for a single-file output name, or `None` when the name is
/// not `*.gz`, `*.xz` or `*.bz2` (a bare extension such as `.gz` is not a name).
pub fn single_format_from_name(path: &Path) -> Option<Compression> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    [(".gz", Compression::Gzip), (".xz", Compression::Xz), (".bz2", Compression::Bzip2)]
        .iter()
        .find(|(ext, _)| name.len() > ext.len() && name.ends_with(ext))
        .map(|&(_, c)| c)
}

/// Human-readable message for an error.
pub fn single_error_message(e: SingleError) -> &'static str {
    match e {
        SingleError::InputCount => "single-file compression takes exactly one input file (use .tar.gz, .tar.xz or .tar.bz2 for several)",
        SingleError::Unreadable => "input not readable",
        SingleError::NotRegularFile => "input is not a regular file (use .tar.gz, .tar.xz or .tar.bz2 for directories)",
        SingleError::SameFile => "input is the output file",
        SingleError::LimitExceeded => "input exceeds limits",
        SingleError::Changed => "input changed while reading",
        SingleError::Allocation => "out of memory",
        SingleError::InvalidLevel => "invalid compression level",
    }
}

/// Read one regular file of at most `max_input` bytes (symlinks are followed).
pub fn read_single_input(path: &Path, max_input: u64) -> Result<Vec<u8>, SingleError> {
    let meta = std::fs::metadata(path).map_err(|_| SingleError::Unreadable)?;
    if !meta.is_file() {
        return Err(SingleError::NotRegularFile);
    }
    if meta.len() > max_input {
        return Err(SingleError::LimitExceeded);
    }
    let f = std::fs::File::open(path).map_err(|_| SingleError::Unreadable)?;
    let opened = f.metadata().map_err(|_| SingleError::Unreadable)?;
    if !opened.is_file() {
        return Err(SingleError::NotRegularFile);
    }
    let expect = opened.len();
    if expect > max_input {
        return Err(SingleError::LimitExceeded);
    }
    let cap = usize::try_from(expect).map_err(|_| SingleError::LimitExceeded)?;
    let mut data = Vec::new();
    data.try_reserve_exact(cap).map_err(|_| SingleError::Allocation)?;
    // Read one byte past the expected size to detect growth.
    f.take(expect.saturating_add(1)).read_to_end(&mut data).map_err(|_| SingleError::Unreadable)?;
    if data.len() as u64 != expect {
        return Err(SingleError::Changed);
    }
    Ok(data)
}

/// Compress `data` as one `kind` stream at `-mx` `level`, bounded by the
/// format's worst-case expansion.
pub fn compress_single(kind: Compression, data: &[u8], level: u8) -> Result<Vec<u8>, SingleError> {
    let bound = compress_bound_for(kind, data.len()).ok_or(SingleError::LimitExceeded)?;
    compress(kind, data, level, bound).map_err(|e| match e {
        WrapError::InvalidLevel => SingleError::InvalidLevel,
        WrapError::Allocation => SingleError::Allocation,
        WrapError::LimitExceeded | WrapError::Unsupported => SingleError::LimitExceeded,
    })
}

#[cfg(unix)]
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Read `inputs[0]` and compress it for `archive`. The caller has already
/// checked that `archive` may be (over)written.
pub fn build_single(archive: &Path, inputs: &[std::path::PathBuf], kind: Compression, level: u8) -> Result<(Vec<u8>, usize), SingleError> {
    let [input] = inputs else {
        return Err(SingleError::InputCount);
    };
    if same_file(input, archive) {
        return Err(SingleError::SameFile);
    }
    let data = read_single_input(input, MAX_SINGLE_INPUT)?;
    let out = compress_single(kind, &data, level)?;
    Ok((out, data.len()))
}

/// Report a finished single-file compression on stdout.
pub fn report_single(archive: &Path, input_len: usize, output_len: usize) {
    let _ = writeln!(
        std::io::stdout().lock(),
        "Created {} (1 file, {} bytes in, {} bytes out)",
        archive.display(),
        input_len,
        output_len
    );
}
