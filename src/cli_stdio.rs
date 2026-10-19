// SPDX-License-Identifier: MIT OR Apache-2.0
//! Standard-stream and split-volume support for the CLI.
//!
//! Extraction side (used by `x`/`e`/`l`/`t` in `src/bin/sediment.rs`):
//! * `-si` reads the archive from standard input, bounded by
//!   [`stdin_limit`] (default [`DEFAULT_STDIN_LIMIT`]; the environment
//!   variable `SEDIMENT_STDIN_LIMIT=<size>` may lower it, see
//!   [`crate::volume_io::parse_size`] for the syntax). The format is detected
//!   from magic bytes; a gzip/bzip2/xz stream whose payload is a tar archive
//!   is opened as tar ([`open_stdin_bytes`]).
//! * `-so` writes the data of every regular-file member, in archive order,
//!   to standard output and nothing to disk ([`write_files`]).
//! * An archive path ending in `.001` is read as a split archive (the
//!   concatenation of `.001`, `.002`, ...; [`crate::volume_io`]).
//!
//! Creation side ([`run_add_stdio`], selected by [`wants_stdio`]):
//! `sediment a [switches] [ARCHIVE] [PATHS...]` with
//! * `-si[NAME]`: the input is standard input instead of PATHS. For
//!   gz/bz2/xz the bytes are compressed as one stream; for tar/zip they
//!   become one member named NAME (default `stdin`).
//! * `-so`: write the archive to standard output (refused when standard
//!   output is a terminal). The ARCHIVE name then only selects the format;
//!   with `-an` (implied by `-si -so` without positionals) no ARCHIVE name
//!   is given and `-t` must name the type.
//! * `-t<type>`: `gz`/`gzip`, `bz2`/`bzip2`, `xz`, `tar`, `tgz`/`tar.gz`,
//!   `tbz2`/`tbz`/`tar.bz2`, `txz`/`tar.xz`, `zip`. Default: from the
//!   ARCHIVE name.
//! * `-v<size>[b|k|m|g]` (repeatable; the last size repeats): write the
//!   archive as volumes ARCHIVE.001, ARCHIVE.002, ...
//! * `-mx0..9`, `-y`, `-l`: as for plain `a` (see [`crate::cli_add`]).
//!
//! Single-stream outputs (gz/bz2/xz) from PATHS take exactly one regular
//! file. Exit codes match `cli_add`: 0 success, 1 fatal error, 2 usage
//! error, 3 written but inputs were skipped. A closed standard output
//! (broken pipe) ends the command silently with exit code 1.
//!
//! Spec sources: RFC 1952 (gzip), the xz file format specification, the
//! bzip2 format as documented, POSIX ustar; switch spellings follow the
//! documented 7-Zip command line. Everything is held in memory with
//! explicit caps: input is bounded by the stdin limit or the collection
//! limits (1 GiB), output by the encoders' bounds.

use std::ffi::{OsStr, OsString};
use std::io::{self, ErrorKind, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::archive_open::{
    StreamReader, TarReader, decompress, open_named, parse_gzip_header, stream_member_name,
};
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::bzip2_encode::encode_bzip2;
use crate::cli_add::{ArchiveFormat as AddFormat, format_from_name};
use crate::compress_wrap::{Compression, gzip_compress};
use crate::extract_plan::EntryKind as PlanKind;
use crate::fs_collect::{
    ArchiveEntry, CollectError, CollectLimits, CollectOptions, EntryKind, WarningKind, collect, read_entry_data,
};
use crate::tar_create::{TarCreateLimits, create_tar};
use crate::volume_io::{VolumeError, existing_volumes, parse_size, write_volumes};
use crate::xz_encode::{XzOptions, encode_xz};
use crate::zip_create::{ZipCreateLimits, ZipCreateOptions, create_zip};

/// Default and maximum number of bytes accepted on standard input (1 GiB).
pub const DEFAULT_STDIN_LIMIT: u64 = 1 << 30;
/// Environment variable that may lower the standard-input limit.
pub const STDIN_LIMIT_ENV: &str = "SEDIMENT_STDIN_LIMIT";
/// Read granularity for standard input.
const CHUNK: usize = 64 * 1024;
/// Member name for `-si` input when none is given.
const DEFAULT_STDIN_NAME: &[u8] = b"stdin";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioError {
    /// Input exceeds the limit.
    LimitExceeded,
    Allocation,
    /// Reading or writing failed.
    Io,
    /// The reader of standard output went away.
    BrokenPipe,
    /// A member could not be decoded.
    Source(ReaderError),
    /// A member's data length differs from its recorded size.
    SizeMismatch,
}

/// The standard-input limit: [`DEFAULT_STDIN_LIMIT`], lowered by `env` (the
/// value of [`STDIN_LIMIT_ENV`]) when set. A malformed value is an error.
pub fn stdin_limit(env: Option<&OsStr>) -> Result<u64, VolumeError> {
    match env {
        None => Ok(DEFAULT_STDIN_LIMIT),
        Some(v) => Ok(parse_size(v.as_encoded_bytes())?.min(DEFAULT_STDIN_LIMIT)),
    }
}

/// Read all of `r` into memory, failing with `LimitExceeded` as soon as more
/// than `max` bytes arrive. Memory grows in bounded chunks.
pub fn read_limited<R: Read>(mut r: R, max: u64) -> Result<Vec<u8>, StdioError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; CHUNK];
    loop {
        let n = match r.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::OutOfMemory => return Err(StdioError::Allocation),
            Err(_) => return Err(StdioError::Io),
        };
        if (buf.len() as u64).saturating_add(n as u64) > max {
            return Err(StdioError::LimitExceeded);
        }
        buf.try_reserve(n).map_err(|_| StdioError::Allocation)?;
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn sanitize_member(raw: &[u8]) -> Option<Vec<u8>> {
    let base = raw.rsplit(|&b| b == b'/' || b == b'\\').next().unwrap_or(raw);
    if base.is_empty() || base.len() > 255 || base.iter().all(|&c| c == b'.' || c == b' ') {
        return None;
    }
    Some(base.to_vec())
}

/// Open archive bytes that arrived without a file name (standard input).
/// gzip/bzip2/xz streams are decompressed once; the result is opened as tar
/// when it starts with a valid tar header, otherwise as a one-member archive
/// named from the gzip FNAME (last component) or `data`. Other formats go
/// through [`open_named`].
pub fn open_stdin_bytes<'a>(bytes: &'a [u8], limits: ReaderLimits) -> Result<Box<dyn ArchiveReader + 'a>, ReaderError> {
    let format = match detect_format(bytes) {
        Detected::Gzip => ArchiveFormat::Gzip,
        Detected::Bzip2 => ArchiveFormat::Bzip2,
        Detected::Xz => ArchiveFormat::Xz,
        _ => return open_named(bytes, b"", limits),
    };
    let (name, mtime, crc) = if format == ArchiveFormat::Gzip {
        let h = parse_gzip_header(bytes, 4096)?;
        let crc = bytes
            .len()
            .checked_sub(8)
            .map(|t| u32::from_le_bytes([bytes[t], bytes[t + 1], bytes[t + 2], bytes[t + 3]]));
        (h.name.as_deref().and_then(sanitize_member), h.mtime, crc)
    } else {
        (None, None, None)
    };
    let max = usize::try_from(limits.max_total_size).unwrap_or(usize::MAX);
    let data = decompress(format, bytes, max)?;
    if matches!(detect_format(&data), Detected::Tar | Detected::TarHeuristic) {
        return Ok(Box::new(TarReader::new(std::borrow::Cow::Owned(data), limits)?));
    }
    if data.len() as u64 > limits.max_entry_size {
        return Err(ReaderError::LimitExceeded);
    }
    let name = name.unwrap_or_else(|| stream_member_name(b""));
    Ok(Box::new(StreamReader::new(format, name, data, mtime, crc)))
}

/// Totals reported by [`write_files`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamStats {
    pub files: usize,
    pub bytes: u64,
}

fn write_err(e: &io::Error) -> StdioError {
    if e.kind() == ErrorKind::BrokenPipe { StdioError::BrokenPipe } else { StdioError::Io }
}

/// Write the data of every regular-file member, in archive order, to `out`.
/// Directories, links and other members are skipped. One member is held in
/// memory at a time.
pub fn write_files<W: Write>(reader: &dyn ArchiveReader, out: &mut W) -> Result<StreamStats, StdioError> {
    let mut stats = StreamStats::default();
    for (i, e) in reader.entries().iter().enumerate() {
        if !matches!(e.kind, PlanKind::File) {
            continue;
        }
        let data = reader.read(i).map_err(StdioError::Source)?;
        if data.len() as u64 != e.size {
            return Err(StdioError::SizeMismatch);
        }
        out.write_all(&data).map_err(|e| write_err(&e))?;
        stats.files += 1;
        stats.bytes = stats.bytes.saturating_add(data.len() as u64);
    }
    out.flush().map_err(|e| write_err(&e))?;
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

/// Output format of `a` in the stdio path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// One compressed stream (gzip, bzip2 or xz; never `None`).
    Stream(Compression),
    Tar(Compression),
    Zip,
}

/// Parse a `-t` type name (case-insensitive).
pub fn output_format_from_type(t: &str) -> Option<OutputFormat> {
    let t = t.to_ascii_lowercase();
    Some(match t.as_str() {
        "gz" | "gzip" => OutputFormat::Stream(Compression::Gzip),
        "bz2" | "bzip2" => OutputFormat::Stream(Compression::Bzip2),
        "xz" => OutputFormat::Stream(Compression::Xz),
        "tar" => OutputFormat::Tar(Compression::None),
        "tgz" | "tar.gz" => OutputFormat::Tar(Compression::Gzip),
        "tbz2" | "tbz" | "tar.bz2" => OutputFormat::Tar(Compression::Bzip2),
        "txz" | "tar.xz" => OutputFormat::Tar(Compression::Xz),
        "zip" => OutputFormat::Zip,
        _ => return None,
    })
}

/// Output format from an archive file name (tar/zip names first, then the
/// single-stream suffixes `.gz`, `.bz2`, `.xz`).
pub fn output_format_from_name(path: &Path) -> Option<OutputFormat> {
    match format_from_name(path) {
        Some(AddFormat::Zip) => return Some(OutputFormat::Zip),
        Some(AddFormat::Tar(c)) => return Some(OutputFormat::Tar(c)),
        None => {}
    }
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    [(".gz", Compression::Gzip), (".bz2", Compression::Bzip2), (".xz", Compression::Xz)]
        .iter()
        .find(|(ext, _)| name.len() > ext.len() && name.ends_with(ext))
        .map(|&(_, c)| OutputFormat::Stream(c))
}

/// Compress `input` as one gzip, bzip2 or xz stream at `level` (0..=9; 0
/// means stored gzip blocks, the fastest bzip2 and xz presets otherwise).
pub fn compress_stream(kind: Compression, input: &[u8], level: u8, max_output: usize) -> Result<Vec<u8>, StdioError> {
    let level = level.min(9);
    let out = match kind {
        Compression::None => {
            let mut v = Vec::new();
            v.try_reserve_exact(input.len()).map_err(|_| StdioError::Allocation)?;
            v.extend_from_slice(input);
            v
        }
        Compression::Gzip => gzip_compress(input, level, max_output).map_err(|e| match e {
            crate::compress_wrap::WrapError::Allocation => StdioError::Allocation,
            _ => StdioError::LimitExceeded,
        })?,
        Compression::Bzip2 => encode_bzip2(input, level.max(1), max_output).map_err(|e| match e {
            crate::bzip2_encode::Bzip2EncodeError::Allocation => StdioError::Allocation,
            _ => StdioError::LimitExceeded,
        })?,
        Compression::Xz => {
            let opts = XzOptions::preset(u32::from(level)).map_err(|_| StdioError::LimitExceeded)?;
            encode_xz(input, &opts).map_err(|e| match e {
                crate::xz_encode::XzEncodeError::Allocation => StdioError::Allocation,
                _ => StdioError::LimitExceeded,
            })?
        }
    };
    if out.len() > max_output {
        return Err(StdioError::LimitExceeded);
    }
    Ok(out)
}

/// Parsed `a` arguments for the stdio path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddStdioArgs {
    pub archive: Option<PathBuf>,
    pub inputs: Vec<PathBuf>,
    pub format: OutputFormat,
    /// `Some(member name)` when the input is standard input.
    pub stdin_name: Option<Vec<u8>>,
    pub to_stdout: bool,
    pub volumes: Vec<u64>,
    pub level: u8,
    pub overwrite: bool,
    pub follow_symlinks: bool,
}

fn switch_bytes(a: &OsStr) -> &[u8] {
    a.as_encoded_bytes()
}

/// True when `a` arguments use a switch handled here (`-si`, `-so`, `-v`,
/// `-t`, `-an`) rather than by [`crate::cli_add::run_add`].
pub fn wants_stdio(args: &[OsString]) -> bool {
    for a in args {
        let b = switch_bytes(a);
        if b == b"--" {
            return false;
        }
        if b.starts_with(b"-si") || b == b"-so" || b == b"-an" || (b.len() > 2 && (b.starts_with(b"-v") || b.starts_with(b"-t")))
        {
            return true;
        }
    }
    false
}

/// Parse the arguments after `a` for the stdio path.
pub fn parse_add_stdio_args(args: &[OsString]) -> Result<AddStdioArgs, String> {
    let mut level = 5u8;
    let mut overwrite = false;
    let mut follow = false;
    let mut stdin_name = None;
    let mut to_stdout = false;
    let mut no_name = false;
    let mut type_ = None;
    let mut volumes = Vec::new();
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut switches = true;
    for a in args {
        let b = switch_bytes(a);
        if switches && b == b"--" {
            switches = false;
            continue;
        }
        if switches && b.len() > 1 && b[0] == b'-' {
            let s = a.to_string_lossy();
            if let Some(rest) = b.strip_prefix(b"-si") {
                if stdin_name.is_some() {
                    return Err("-si given twice".into());
                }
                if rest.contains(&0) || rest.len() > 4096 {
                    return Err("invalid -si name".into());
                }
                stdin_name = Some(if rest.is_empty() { DEFAULT_STDIN_NAME.to_vec() } else { rest.to_vec() });
            } else if b == b"-so" {
                to_stdout = true;
            } else if b == b"-an" {
                no_name = true;
            } else if let Some(rest) = s.strip_prefix("-t") {
                type_ = Some(output_format_from_type(rest).ok_or_else(|| format!("unsupported archive type: {rest}"))?);
            } else if let Some(rest) = b.strip_prefix(b"-v") {
                volumes.push(parse_size(rest).map_err(|_| format!("invalid volume size: {s}"))?);
            } else if let Some(rest) = s.strip_prefix("-mx") {
                let rest = rest.strip_prefix('=').unwrap_or(rest);
                match rest.parse::<u8>() {
                    Ok(n) if n <= 9 && rest.len() == 1 => level = n,
                    _ => return Err(format!("invalid compression level switch: {s}")),
                }
            } else if b == b"-y" {
                overwrite = true;
            } else if b == b"-l" {
                follow = true;
            } else {
                return Err(format!("unknown switch: {s}"));
            }
            continue;
        }
        positional.push(PathBuf::from(a));
    }
    let archive = if no_name || (to_stdout && stdin_name.is_some() && positional.is_empty()) {
        if !to_stdout {
            return Err("-an requires -so".into());
        }
        None
    } else {
        if positional.is_empty() {
            return Err("missing archive name".into());
        }
        Some(positional.remove(0))
    };
    if to_stdout && !volumes.is_empty() {
        return Err("-v cannot be combined with -so".into());
    }
    if stdin_name.is_some() && !positional.is_empty() {
        return Err("input paths cannot be combined with -si".into());
    }
    if stdin_name.is_none() && positional.is_empty() {
        return Err("missing input paths".into());
    }
    let format = match (type_, archive.as_deref()) {
        (Some(f), _) => f,
        (None, Some(p)) => output_format_from_name(p).ok_or_else(|| {
            String::from("cannot infer archive format from name (use -t or .zip, .tar, .tgz, .tbz2, .txz, .gz, .bz2, .xz)")
        })?,
        (None, None) => return Err("-an requires -t<type>".into()),
    };
    Ok(AddStdioArgs {
        archive,
        inputs: positional,
        format,
        stdin_name,
        to_stdout,
        volumes,
        level,
        overwrite,
        follow_symlinks: follow,
    })
}

fn collect_msg(e: CollectError) -> &'static str {
    match e {
        CollectError::NotFound => "input not found",
        CollectError::Unreadable => "input not readable",
        CollectError::InvalidName => "invalid or duplicate entry name",
        CollectError::LimitExceeded => "input exceeds limits",
        CollectError::Allocation => "out of memory",
        CollectError::Changed => "input changed while reading",
    }
}

fn stdio_msg(e: StdioError) -> &'static str {
    match e {
        StdioError::LimitExceeded => "input exceeds the size limit",
        StdioError::Allocation => "out of memory",
        StdioError::Io => "read error",
        StdioError::BrokenPipe => "broken pipe",
        StdioError::Source(_) => "data error",
        StdioError::SizeMismatch => "size mismatch",
    }
}

fn volume_msg(e: VolumeError) -> &'static str {
    match e {
        VolumeError::InvalidSize => "invalid volume size",
        VolumeError::TooManyVolumes => "too many volumes (raise the -v size)",
        VolumeError::NotFound => "volume not found",
        VolumeError::Exists => "volume exists (use -y to overwrite)",
        VolumeError::NotAFile => "volume path is not a regular file",
        VolumeError::LimitExceeded => "volumes exceed the size limit",
        VolumeError::Allocation => "out of memory",
        VolumeError::Io => "cannot write volume",
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0)
}

/// Upper bound for an encoded archive of `n` input bytes (generous for
/// incompressible data in every container used here).
fn output_cap(n: usize) -> usize {
    n.saturating_add(n / 8).saturating_add(1 << 20)
}

struct Built {
    bytes: Vec<u8>,
    entries: usize,
    input_bytes: u64,
    warned: bool,
}

fn build_from_bytes(format: OutputFormat, name: &[u8], data: &[u8], level: u8) -> Result<Vec<u8>, String> {
    let entry = ArchiveEntry { name, kind: EntryKind::File, data, mtime: now_secs(), mode: 0o644, link_target: b"" };
    container(format, &[entry], level)
}

fn container(format: OutputFormat, entries: &[ArchiveEntry<'_>], level: u8) -> Result<Vec<u8>, String> {
    match format {
        OutputFormat::Stream(c) => {
            let data = entries.first().map(|e| e.data).unwrap_or(b"");
            compress_stream(c, data, level, output_cap(data.len())).map_err(|e| format!("compression failed: {}", stdio_msg(e)))
        }
        OutputFormat::Tar(c) => {
            let tar = create_tar(entries, TarCreateLimits::default()).map_err(|e| format!("cannot build tar: {e:?}"))?;
            compress_stream(c, &tar, level, output_cap(tar.len())).map_err(|e| format!("compression failed: {}", stdio_msg(e)))
        }
        OutputFormat::Zip => create_zip(entries, ZipCreateOptions { level }, ZipCreateLimits::default())
            .map(|z| z.bytes)
            .map_err(|e| format!("cannot build zip: {e:?}")),
    }
}

fn build_from_paths(a: &AddStdioArgs, err: &mut dyn Write) -> Result<Built, String> {
    let mut exclude = Vec::new();
    if let Some(p) = &a.archive
        && !a.to_stdout
    {
        exclude.push(p.clone());
        if !a.volumes.is_empty() {
            exclude.extend(existing_volumes(p));
        }
    }
    let options = CollectOptions { follow_symlinks: a.follow_symlinks, strict: false, exclude };
    let limits = CollectLimits::default();
    if let OutputFormat::Stream(c) = a.format {
        if a.inputs.len() != 1 {
            return Err("a single-stream archive takes exactly one input file".into());
        }
        let src = &a.inputs[0];
        let f = std::fs::File::open(src).map_err(|_| format!("{}: input not readable", src.display()))?;
        if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Err(format!("{}: a single-stream archive takes a regular file", src.display()));
        }
        let data = read_limited(f, limits.max_total_bytes).map_err(|e| format!("{}: {}", src.display(), stdio_msg(e)))?;
        let bytes =
            compress_stream(c, &data, a.level, output_cap(data.len())).map_err(|e| format!("compression failed: {}", stdio_msg(e)))?;
        return Ok(Built { bytes, entries: 1, input_bytes: data.len() as u64, warned: false });
    }
    let collected = collect(&a.inputs, &options, limits).map_err(|e| collect_msg(e).to_string())?;
    let mut warned = false;
    for w in &collected.warnings {
        let msg = match w.kind {
            WarningKind::UnreadableDirectory => "cannot list directory; contents skipped",
            WarningKind::UnreadableFile => "cannot read; skipped",
            WarningKind::SpecialFile => "special file; skipped",
            WarningKind::SymlinkLoop => "symlink loop; skipped",
            WarningKind::ExcludedOutput => "is the output archive; skipped",
        };
        let _ = writeln!(err, "sediment: warning: {}: {msg}", w.path.display());
        if w.kind != WarningKind::ExcludedOutput {
            warned = true;
        }
    }
    let mut datas: Vec<Vec<u8>> = Vec::new();
    datas.try_reserve_exact(collected.entries.len()).map_err(|_| String::from("out of memory"))?;
    for e in &collected.entries {
        datas.push(read_entry_data(e, limits.max_total_bytes).map_err(|x| format!("{}: {}", e.source.display(), collect_msg(x)))?);
    }
    let entries: Vec<_> = collected.entries.iter().zip(datas.iter()).map(|(e, d)| e.as_archive_entry(d)).collect();
    if a.format == OutputFormat::Zip {
        for e in collected.entries.iter().filter(|e| e.kind == EntryKind::Symlink) {
            let _ = writeln!(err, "sediment: note: {}: symlink not stored in zip (use -l to store its target)", e.source.display());
        }
    }
    let bytes = container(a.format, &entries, a.level)?;
    Ok(Built { bytes, entries: collected.entries.len(), input_bytes: collected.total_bytes, warned })
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".sediment-tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let res = (|| -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    Ok(())
}

/// Run `sediment a` with stdio/volume switches. `args` follow the command.
pub fn run_add_stdio(args: &[OsString]) -> i32 {
    let mut err = io::stderr().lock();
    let a = match parse_add_stdio_args(args) {
        Ok(a) => a,
        Err(m) => {
            let _ = writeln!(
                err,
                "sediment: {m}\nUsage: sediment a [-mx0..9] [-y] [-l] [-t<type>] [-v<size>] [-si[NAME]] [-so] [-an] [ARCHIVE] [PATH...]"
            );
            return 2;
        }
    };
    if a.to_stdout && io::stdout().is_terminal() {
        let _ = writeln!(err, "sediment: refusing to write archive data to a terminal");
        return 2;
    }
    if !a.to_stdout {
        let archive = a.archive.as_deref().unwrap_or(Path::new(""));
        if a.volumes.is_empty() && std::fs::symlink_metadata(archive).is_ok() {
            if std::fs::metadata(archive).map(|m| m.is_dir()).unwrap_or(false) {
                let _ = writeln!(err, "sediment: archive path is a directory");
                return 1;
            }
            if !a.overwrite {
                let _ = writeln!(err, "sediment: archive exists (use -y to overwrite; update is not supported)");
                return 1;
            }
        }
    }
    let built = match &a.stdin_name {
        Some(name) => {
            let limit = match stdin_limit(std::env::var_os(STDIN_LIMIT_ENV).as_deref()) {
                Ok(l) => l,
                Err(_) => {
                    let _ = writeln!(err, "sediment: invalid {STDIN_LIMIT_ENV}");
                    return 2;
                }
            };
            let data = match read_limited(io::stdin().lock(), limit) {
                Ok(d) => d,
                Err(e) => {
                    let _ = writeln!(err, "sediment: standard input: {}", stdio_msg(e));
                    return 1;
                }
            };
            match build_from_bytes(a.format, name, &data, a.level) {
                Ok(bytes) => Built { bytes, entries: 1, input_bytes: data.len() as u64, warned: false },
                Err(m) => {
                    let _ = writeln!(err, "sediment: {m}");
                    return 1;
                }
            }
        }
        None => match build_from_paths(&a, &mut err) {
            Ok(b) => b,
            Err(m) => {
                let _ = writeln!(err, "sediment: {m}");
                return 1;
            }
        },
    };
    let done = if built.warned { 3 } else { 0 };
    if a.to_stdout {
        let mut out = io::stdout().lock();
        return match out.write_all(&built.bytes).and_then(|_| out.flush()) {
            Ok(()) => done,
            Err(e) if e.kind() == ErrorKind::BrokenPipe => 1,
            Err(_) => {
                let _ = writeln!(err, "sediment: write error");
                1
            }
        };
    }
    let archive = a.archive.as_deref().unwrap_or(Path::new(""));
    let summary = if a.volumes.is_empty() {
        if let Err(m) = write_atomically(archive, &built.bytes) {
            let _ = writeln!(err, "sediment: {m}");
            return 1;
        }
        String::new()
    } else {
        match write_volumes(archive, &built.bytes, &a.volumes, a.overwrite) {
            Ok(n) => format!(" in {n} volumes"),
            Err(e) => {
                let _ = writeln!(err, "sediment: {}", volume_msg(e));
                return 1;
            }
        }
    };
    let _ = writeln!(
        io::stdout().lock(),
        "Created {}{summary} ({} entries, {} bytes in, {} bytes out)",
        archive.display(),
        built.entries,
        built.input_bytes,
        built.bytes.len()
    );
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn routing() {
        assert!(wants_stdio(&os(&["-si", "x.gz"])));
        assert!(wants_stdio(&os(&["-so", "x.tar", "d"])));
        assert!(wants_stdio(&os(&["-v1m", "x.zip", "d"])));
        assert!(wants_stdio(&os(&["-txz", "x", "d"])));
        assert!(!wants_stdio(&os(&["x.zip", "d"])));
        assert!(!wants_stdio(&os(&["--", "-si", "d"])));
        assert!(!wants_stdio(&os(&["-y", "x.zip", "-v"])));
    }

    #[test]
    fn parsing() {
        let a = parse_add_stdio_args(&os(&["-so", "-an", "-ttgz", "d"])).unwrap();
        assert_eq!(a.format, OutputFormat::Tar(Compression::Gzip));
        assert_eq!(a.archive, None);
        let a = parse_add_stdio_args(&os(&["-sinote.txt", "o.tar"])).unwrap();
        assert_eq!(a.stdin_name.as_deref(), Some(&b"note.txt"[..]));
        let a = parse_add_stdio_args(&os(&["-v10k", "-v1m", "o.zip", "d"])).unwrap();
        assert_eq!(a.volumes, vec![10240, 1 << 20]);
        assert_eq!(parse_add_stdio_args(&os(&["-si", "o.gz"])).unwrap().format, OutputFormat::Stream(Compression::Gzip));
        assert_eq!(parse_add_stdio_args(&os(&["-si", "-so", "-txz"])).unwrap().archive, None);
        for bad in [
            &["-an", "d"][..],
            &["-so", "-an", "d"],
            &["-si", "-so"],
            &["-so", "-v1k", "x.tar", "d"],
            &["-si", "x.tar", "d"],
            &["-v0", "x.tar", "d"],
            &["-tfoo", "x", "d"],
            &["-so", "x.unknown", "d"],
            &["x.tar"],
        ] {
            assert!(parse_add_stdio_args(&os(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn limited_reads() {
        assert_eq!(read_limited(&b"abc"[..], 3), Ok(b"abc".to_vec()));
        assert_eq!(read_limited(&b"abcd"[..], 3), Err(StdioError::LimitExceeded));
        assert_eq!(stdin_limit(None), Ok(DEFAULT_STDIN_LIMIT));
        assert_eq!(stdin_limit(Some(OsStr::new("2k"))), Ok(2048));
        assert_eq!(stdin_limit(Some(OsStr::new("99g"))), Ok(DEFAULT_STDIN_LIMIT));
        assert!(stdin_limit(Some(OsStr::new("x"))).is_err());
    }

    #[test]
    fn stream_round_trip() {
        let input: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        for c in [Compression::Gzip, Compression::Bzip2, Compression::Xz] {
            let z = compress_stream(c, &input, 6, output_cap(input.len())).unwrap();
            let r = open_stdin_bytes(&z, ReaderLimits::default()).unwrap();
            let mut out = Vec::new();
            let s = write_files(r.as_ref(), &mut out).unwrap();
            assert_eq!((s.files, out), (1, input.clone()), "{c:?}");
        }
        assert_eq!(compress_stream(Compression::Xz, &input, 6, 10), Err(StdioError::LimitExceeded));
    }
}
