// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sediment command line.
//!
//! Commands (7-Zip style names):
//!   l ARCHIVE                 list members
//!   t ARCHIVE                 test integrity
//!   x [switches] ARCHIVE      extract with full paths
//!   e [switches] ARCHIVE      extract without directory structure
//!   a [switches] ARCHIVE PATHS...  create an archive (see `cli_add`)
//!   h [-scrc<METHOD>]... PATHS...  hash files (see `cli_hash`)
//!   b [ITERATIONS] [switches]      benchmark (see `cli_bench`)
//!   list|test ARCHIVE         original ZIP-only commands (frozen output)
//! Readable formats for l/t/x/e: zip, tar, gzip/bzip2/xz single streams,
//!   tar.gz/tgz, tar.bz2/tbz2/tbz, tar.xz/txz, 7z, cpio, ar, deb, rpm and
//!   xar (see `archive_open`).
//! Switches for x/e: -o<dir> output directory, -y assume yes (overwrite),
//!   -aoa overwrite all, -aos skip existing, -aou auto-rename new files,
//!   -snl create symbolic links (default: skip them with a warning),
//!   -- end of switches.
//! Streams and volumes (see `cli_stdio`): `-si` reads the archive from
//!   standard input (l/t/x/e), `-so` writes file data to standard output
//!   instead of disk (x/e), and an archive named `*.001` is read as split
//!   volumes. `a` with -si/-so/-v/-t/-an is handled by `cli_stdio`.
//! Exit codes: 0 success; 1 warning (some members not extracted) or, for
//!   `list`/`test`, any failure; 2 fatal error or usage error. `a` keeps the
//!   codes documented in `cli_add` (1 fatal, 2 usage, 3 inputs skipped).
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use sediment_engine::archive_name::escape_name;
use sediment_engine::archive_open::open_named;
use sediment_engine::archive_reader::{ArchiveReader, ReaderError, ReaderLimits};
use sediment_engine::cli_add::run_add;
use sediment_engine::cli_bench::run_bench;
use sediment_engine::cli_hash::run_hash;
use sediment_engine::cli_stdio::{
    STDIN_LIMIT_ENV, StdioError, open_stdin_bytes, read_limited, run_add_stdio, stdin_limit, wants_stdio, write_files,
};
use sediment_engine::volume_io::{VolumeError, first_volume_base, read_volumes};
use sediment_engine::extract_fs::{execute_plan, ExtractOptions, OverwritePolicy, SymlinkPolicy};
use sediment_engine::extract_plan::{
    normalize_path, plan_extraction, EntryKind, Plan, PlanKind, PlanOptions, PlanWarning, PlannedEntry,
};
use sediment_engine::zip_decode::entry_data;
use sediment_engine::zip_index::{parse_entries, ZipLimits};

const EXIT_WARNING: i32 = 1;
const EXIT_FATAL: i32 = 2;
const MAX_ARCHIVE: u64 = 1 << 30;

fn err(msg: &'static str, code: i32) -> ! {
    let _ = writeln!(io::stderr().lock(), "sediment: {msg}");
    process::exit(code);
}

fn err_entry(msg: &str, name: &[u8], code: i32) -> ! {
    let shown = escape_name(name).unwrap_or_else(|_| String::from("?"));
    let _ = writeln!(io::stderr().lock(), "sediment: {msg}: {shown}");
    process::exit(code);
}

fn warn(msg: &str, name: &[u8]) {
    let shown = escape_name(name).unwrap_or_else(|_| String::from("?"));
    let _ = writeln!(io::stderr().lock(), "sediment: warning: {msg}: {shown}");
}

fn main() {
    let mut args = std::env::args_os();
    args.next();
    let cmd = args.next();
    if cmd.as_deref() == Some(OsStr::new("--help")) {
        if args.next().is_some() {
            err("too many arguments", 2);
        }
        let mut out = io::stdout().lock();
        if out.write_all(b"Usage: sediment <list|test> ARCHIVE\n").is_err() {
            err("write error", 1);
        }
        if out.flush().is_err() {
            err("flush error", 1);
        }
        return;
    }
    let cmd = match cmd {
        Some(c) => c,
        None => err("missing command", 2),
    };
    let rest: Vec<OsString> = args.collect();
    if cmd == "list" || cmd == "test" {
        legacy(&cmd, rest);
    } else if cmd == "l" || cmd == "t" {
        let src = parse_source_args(rest);
        let (buf, name) = load_archive(src.as_deref());
        let reader = open_input(&buf, &name, src.is_none());
        if cmd == "l" {
            cmd_list(reader.as_ref());
        } else {
            cmd_test(reader.as_ref());
        }
    } else if cmd == "x" || cmd == "e" {
        cmd_extract(cmd == "e", rest);
    } else if cmd == "a" {
        process::exit(if wants_stdio(&rest) { run_add_stdio(&rest) } else { run_add(&rest) });
    } else if cmd == "h" {
        process::exit(run_hash(&rest));
    } else if cmd == "b" {
        process::exit(run_bench(&rest));
    } else {
        err("unknown command", 2);
    }
}

fn single_path(rest: Vec<OsString>) -> OsString {
    let mut it = rest.into_iter();
    let path = match it.next() {
        Some(p) => p,
        None => err("missing archive path", 2),
    };
    if it.next().is_some() {
        err("too many arguments", 2);
    }
    path
}

/// Original `list`/`test` behavior, byte-identical output and exit codes.
fn legacy(cmd: &OsStr, rest: Vec<OsString>) {
    let path = single_path(rest);
    let p = Path::new(&path);
    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(_) => err("cannot access file", 1),
    };
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        err("invalid file or size limit", 1);
    }
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => err("cannot open file", 1),
    };
    let m = match f.metadata() {
        Ok(m) => m,
        Err(_) => err("cannot read file metadata", 1),
    };
    if !m.is_file() || m.len() > 64 * 1024 * 1024 {
        err("invalid file or size limit", 1);
    }
    let max = 64 * 1024 * 1024;
    let mut buf = Vec::new();
    if buf.try_reserve_exact(max + 1).is_err() {
        err("allocation failed", 1);
    }
    if f.take(max as u64 + 1).read_to_end(&mut buf).is_err() {
        err("read error", 1);
    }
    if buf.len() > max {
        err("file too large", 1);
    }
    let limits = ZipLimits { max_entries: 10000, max_total_size: 64 * 1024 * 1024 };
    let entries = match parse_entries(&buf, limits) {
        Ok(e) => e,
        Err(_) => err("parse error", 1),
    };
    let mut out = io::stdout().lock();
    if cmd == "list" {
        if out.write_all(b"SIZE\tCRC32\tNAME\n").is_err() {
            err("write error", 1);
        }
        for e in &entries {
            let esc = match escape_name(e.name) {
                Ok(s) => s,
                Err(_) => err("escape error", 1),
            };
            if writeln!(out, "{}\t{:08x}\t{}", e.size, e.crc32, esc).is_err() {
                err("write error", 1);
            }
        }
    } else {
        let count = entries.len();
        let per_entry_blocks = 100000usize.checked_div(count).unwrap_or(100000);
        let mut total: u64 = 0;
        for e in &entries {
            let data = match entry_data(&buf, e, e.size, per_entry_blocks) {
                Ok(d) => d,
                Err(_) => err("payload error", 1),
            };
            drop(data);
            total = match total.checked_add(e.size as u64) {
                Some(v) => v,
                None => err("overflow", 1),
            };
        }
        if writeln!(out, "OK\t{count}\t{total}").is_err() {
            err("write error", 1);
        }
    }
    if out.flush().is_err() {
        err("flush error", 1);
    }
}

fn read_archive(p: &Path, max: u64) -> Vec<u8> {
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => err("cannot open file", EXIT_FATAL),
    };
    let m = match f.metadata() {
        Ok(m) => m,
        Err(_) => err("cannot read file metadata", EXIT_FATAL),
    };
    if !m.is_file() || m.len() > max {
        err("invalid file or size limit", EXIT_FATAL);
    }
    let mut buf = Vec::new();
    if buf.try_reserve_exact(m.len() as usize + 1).is_err() {
        err("allocation failed", EXIT_FATAL);
    }
    if f.take(max + 1).read_to_end(&mut buf).is_err() {
        err("read error", EXIT_FATAL);
    }
    if buf.len() as u64 > max {
        err("file too large", EXIT_FATAL);
    }
    buf
}

fn file_name_bytes(p: &Path) -> Vec<u8> {
    p.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default()
}

/// Archive arguments for `l`/`t`: one path, or `-si` for standard input.
/// Returns `None` for standard input.
fn parse_source_args(rest: Vec<OsString>) -> Option<OsString> {
    let mut stdin = false;
    let mut path = None;
    let mut switches = true;
    for a in rest {
        let b = a.as_encoded_bytes();
        if switches && b == b"--" {
            switches = false;
        } else if switches && b == b"-si" {
            stdin = true;
        } else if switches && b.len() > 1 && b[0] == b'-' {
            err("unknown switch", 2);
        } else if path.replace(a).is_some() {
            err("too many arguments", 2);
        }
    }
    match (stdin, path) {
        (true, None) => None,
        (false, Some(p)) => Some(p),
        (true, Some(_)) => err("archive path cannot be combined with -si", 2),
        (false, None) => err("missing archive path", 2),
    }
}

/// Read the archive bytes and its file name: standard input when `path` is
/// `None` (bounded by the stdin limit), split volumes for `*.001`, else the
/// file itself.
fn load_archive(path: Option<&OsStr>) -> (Vec<u8>, Vec<u8>) {
    let Some(path) = path else {
        let limit = match stdin_limit(std::env::var_os(STDIN_LIMIT_ENV).as_deref()) {
            Ok(l) => l,
            Err(_) => err("invalid SEDIMENT_STDIN_LIMIT", EXIT_FATAL),
        };
        return match read_limited(io::stdin().lock(), limit) {
            Ok(b) => (b, Vec::new()),
            Err(StdioError::LimitExceeded) => err("standard input exceeds the size limit", EXIT_FATAL),
            Err(StdioError::Allocation) => err("allocation failed", EXIT_FATAL),
            Err(_) => err("read error", EXIT_FATAL),
        };
    };
    let p = Path::new(path);
    if let Some(base) = first_volume_base(p) {
        return match read_volumes(&base, MAX_ARCHIVE) {
            Ok((b, _)) => (b, file_name_bytes(&base)),
            Err(VolumeError::NotFound) => err("cannot open file", EXIT_FATAL),
            Err(VolumeError::LimitExceeded | VolumeError::TooManyVolumes) => err("file too large", EXIT_FATAL),
            Err(VolumeError::Allocation) => err("allocation failed", EXIT_FATAL),
            Err(VolumeError::NotAFile) => err("invalid file or size limit", EXIT_FATAL),
            Err(_) => err("read error", EXIT_FATAL),
        };
    }
    (read_archive(p, MAX_ARCHIVE), file_name_bytes(p))
}

fn open_input<'a>(buf: &'a [u8], name: &[u8], stdin: bool) -> Box<dyn ArchiveReader + 'a> {
    let r = if stdin { open_stdin_bytes(buf, ReaderLimits::default()) } else { open_named(buf, name, ReaderLimits::default()) };
    match r {
        Ok(r) => r,
        Err(ReaderError::Unsupported) => err("unsupported archive format", EXIT_FATAL),
        Err(ReaderError::CrcMismatch) => err("data error (checksum mismatch)", EXIT_FATAL),
        Err(ReaderError::LimitExceeded) => err("archive exceeds limits", EXIT_FATAL),
        Err(ReaderError::Allocation) => err("allocation failed", EXIT_FATAL),
        Err(_) => err("parse error", EXIT_FATAL),
    }
}

fn cmd_list(reader: &dyn ArchiveReader) {
    let mut out = io::stdout().lock();
    if out.write_all(b"SIZE\tCRC32\tNAME\n").is_err() {
        err("write error", EXIT_FATAL);
    }
    for (i, e) in reader.entries().iter().enumerate() {
        let esc = match escape_name(&e.path) {
            Ok(s) => s,
            Err(_) => err("escape error", EXIT_FATAL),
        };
        let crc = match reader.crc32(i) {
            Some(c) => format!("{c:08x}"),
            None => String::from("--------"),
        };
        let size = match &e.kind {
            EntryKind::Symlink { target } => target.len() as u64,
            _ => e.size,
        };
        if writeln!(out, "{size}\t{crc}\t{esc}").is_err() {
            err("write error", EXIT_FATAL);
        }
    }
    if out.flush().is_err() {
        err("flush error", EXIT_FATAL);
    }
}

fn cmd_test(reader: &dyn ArchiveReader) {
    let mut total: u64 = 0;
    let entries = reader.entries();
    for (i, e) in entries.iter().enumerate() {
        match reader.read(i) {
            Ok(d) if !matches!(e.kind, EntryKind::File) || d.len() as u64 == e.size => {}
            Err(ReaderError::Unsupported) => err_entry("unsupported compression method", &e.path, EXIT_FATAL),
            _ => err_entry("data error", &e.path, EXIT_FATAL),
        }
        total = match total.checked_add(e.size) {
            Some(v) => v,
            None => err("overflow", EXIT_FATAL),
        };
    }
    let mut out = io::stdout().lock();
    if writeln!(out, "OK\t{}\t{total}", entries.len()).is_err() || out.flush().is_err() {
        err("write error", EXIT_FATAL);
    }
}

struct ExtractArgs {
    /// `None` with `-si`.
    archive: Option<OsString>,
    to_stdout: bool,
    out_dir: PathBuf,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
}

#[cfg(unix)]
fn os_tail(arg: &OsStr, skip: usize) -> Option<OsString> {
    use std::os::unix::ffi::OsStrExt;
    Some(OsStr::from_bytes(&arg.as_bytes()[skip..]).to_os_string())
}

#[cfg(not(unix))]
fn os_tail(arg: &OsStr, skip: usize) -> Option<OsString> {
    arg.to_str().map(|s| OsString::from(&s[skip..]))
}

fn parse_extract_args(rest: Vec<OsString>) -> ExtractArgs {
    let mut archive = None;
    let mut out_dir = PathBuf::from(".");
    let mut overwrite = None;
    let mut yes = false;
    let mut symlinks = SymlinkPolicy::Skip;
    let mut switches = true;
    let mut stdin = false;
    let mut to_stdout = false;
    for a in rest {
        let bytes = a.as_encoded_bytes();
        if switches && bytes.first() == Some(&b'-') && bytes.len() > 1 {
            match bytes {
                b"--" => switches = false,
                b"-si" => stdin = true,
                b"-so" => to_stdout = true,
                b"-y" => yes = true,
                b"-aoa" => overwrite = Some(OverwritePolicy::Overwrite),
                b"-aos" => overwrite = Some(OverwritePolicy::Skip),
                b"-aou" => overwrite = Some(OverwritePolicy::Rename),
                b"-snl" => symlinks = SymlinkPolicy::Create,
                _ if bytes.starts_with(b"-o") => {
                    if bytes.len() == 2 {
                        err("missing output directory", 2);
                    }
                    match os_tail(&a, 2) {
                        Some(d) => out_dir = PathBuf::from(d),
                        None => err("invalid output directory", 2),
                    }
                }
                _ => err("unknown switch", 2),
            }
            continue;
        }
        if archive.is_some() {
            err("too many arguments", 2);
        }
        archive = Some(a);
    }
    let archive = match (stdin, archive) {
        (true, None) => None,
        (false, Some(a)) => Some(a),
        (true, Some(_)) => err("archive path cannot be combined with -si", 2),
        (false, None) => err("missing archive path", 2),
    };
    let overwrite = overwrite.unwrap_or(if yes { OverwritePolicy::Overwrite } else { OverwritePolicy::Error });
    ExtractArgs { archive, to_stdout, out_dir, overwrite, symlinks }
}

fn last_component(path: &[u8]) -> Vec<u8> {
    path.split(|&b| b == b'/' || b == b'\\').rfind(|c| !c.is_empty())
        .unwrap_or(b"")
        .to_vec()
}

/// For `e`: drop directories, keep only file names. Returns the flattened
/// entries plus the map back to original indices.
fn flatten(entries: &[PlannedEntry]) -> (Vec<PlannedEntry>, Vec<usize>) {
    let mut out = Vec::new();
    let mut map = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if matches!(e.kind, EntryKind::Dir) {
            continue;
        }
        let mut f = e.clone();
        f.path = last_component(&e.path);
        if let EntryKind::Hardlink { target } = &e.kind {
            f.kind = EntryKind::Hardlink { target: last_component(target) };
        }
        out.push(f);
        map.push(i);
    }
    (out, map)
}

fn remap(plan: &mut Plan, map: &[usize]) {
    for it in &mut plan.items {
        it.index = map[it.index];
        if let PlanKind::Hardlink { source } = &mut it.kind {
            *source = map[*source];
        }
    }
    for w in &mut plan.warnings {
        match w {
            PlanWarning::NonPortableName { index } => *index = map[*index],
            PlanWarning::CaseCollision { index, other } | PlanWarning::DuplicatePath { index, other } => {
                *index = map[*index];
                *other = map[*other];
            }
        }
    }
}

fn cmd_extract(flat: bool, rest: Vec<OsString>) {
    let args = parse_extract_args(rest);
    let (buf, name) = load_archive(args.archive.as_deref());
    let reader = open_input(&buf, &name, args.archive.is_none());
    if args.to_stdout {
        let mut out = io::stdout().lock();
        match write_files(reader.as_ref(), &mut out) {
            Ok(_) => return,
            Err(StdioError::BrokenPipe) => process::exit(EXIT_WARNING),
            Err(StdioError::Source(ReaderError::Unsupported)) => err("unsupported compression method", EXIT_FATAL),
            Err(StdioError::Source(_) | StdioError::SizeMismatch) => err("data error", EXIT_FATAL),
            Err(StdioError::Allocation) => err("allocation failed", EXIT_FATAL),
            Err(_) => err("write error", EXIT_FATAL),
        }
    }
    let entries = reader.entries();
    let (planned, map) = if flat {
        flatten(entries)
    } else {
        (entries.to_vec(), (0..entries.len()).collect())
    };
    let mut plan = match plan_extraction(&planned, &PlanOptions::default()) {
        Ok(p) => p,
        Err(f) => match f.index {
            Some(i) => err_entry(&format!("unsafe entry rejected ({:?})", f.error), &entries[map[i]].path, EXIT_FATAL),
            None => err_entry(&format!("archive rejected ({:?})", f.error), b"", EXIT_FATAL),
        },
    };
    remap(&mut plan, &map);
    // Flat mode neutralizes hostile directory parts; still say so.
    let mut flattened_unsafe = false;
    if flat {
        for it in &plan.items {
            if normalize_path(&entries[it.index].path, &PlanOptions::default().limits).is_err() {
                warn("unsafe path flattened", &entries[it.index].path);
                flattened_unsafe = true;
            }
        }
    }
    for w in &plan.warnings {
        match *w {
            PlanWarning::NonPortableName { index } => warn("non-portable name", &entries[index].path),
            PlanWarning::CaseCollision { index, .. } => warn("names differ only by case", &entries[index].path),
            PlanWarning::DuplicatePath { index, .. } => warn("duplicate name", &entries[index].path),
        }
    }
    let opts = ExtractOptions { overwrite: args.overwrite, symlinks: args.symlinks, ..ExtractOptions::default() };
    let report = match execute_plan(&plan, reader.as_ref(), &args.out_dir, &opts) {
        Ok(r) => r,
        Err(f) => match f.index {
            Some(i) => err_entry(&format!("cannot extract ({:?})", f.error), &entries[i].path, EXIT_FATAL),
            None => err_entry(&format!("cannot extract ({:?})", f.error), b"", EXIT_FATAL),
        },
    };
    for &i in &report.skipped_existing {
        warn("skipped existing", &entries[i].path);
    }
    for &i in &report.skipped_symlinks {
        warn("symbolic link not extracted (use -snl)", &entries[i].path);
    }
    if flattened_unsafe || !report.skipped_symlinks.is_empty() {
        process::exit(EXIT_WARNING);
    }
}
