// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execution of the 7-Zip compatible commands `l`, `t`, `x`, `e` and `a`
//! parsed by [`crate::cli_compat`].
//!
//! Behaviour follows the public 7-Zip command-line documentation (switch
//! semantics, wildcard/listfile selection, `-slt` field names, exit codes);
//! no 7-Zip source was used. Archive access goes through
//! [`crate::archive_open`], extraction through [`crate::extract_plan`] /
//! [`crate::extract_fs`] (all path-safety guards stay in force), creation
//! through [`crate::fs_collect`], [`crate::zip_create`], [`crate::tar_create`]
//! and [`crate::compress_wrap`]. Wildcards, list files and `-slt` blocks use
//! the FORGE APIs via [`crate::cli_seam`].
//!
//! Output conventions (`-bb` levels):
//! * `l`: default output is the frozen `SIZE\tCRC32\tNAME` table (`-ba`
//!   drops the header row); `-slt` prints 7-Zip technical blocks (`-ba`
//!   drops the archive header block).
//! * `t`: `OK\t<count>\t<bytes>` (dropped by `-ba`); `-bb1` adds `T <name>`.
//! * `x`/`e`: silent by default; `-bb1` prints `- <name>` per file/link,
//!   `-bb2` also directories and skipped files, `-bb3` also renamed
//!   targets; with `-bb1`+ a `Folders/Files/Size` footer (dropped by `-ba`).
//! * `a`: `Created ...` summary (dropped by `-ba`); `-bb1` prints `+ <name>`.
//!
//! Messages go to the error stream (`-bse`), listings to the output stream
//! (`-bso`); `0` discards a stream. With `-so` standard output carries data
//! only and the output stream moves to standard error. The overwrite prompt
//! (only when standard input is a terminal and not used by `-si`) is
//! written to the error stream.
//!
//! Streams and volumes: `-si` reads the archive from standard input
//! (bounded by `SEDIMENT_STDIN_LIMIT`, see [`crate::cli_stdio`]); an
//! archive named `*.001` is read as split volumes ([`crate::volume_io`]);
//! `x`/`e -so` write the selected files' data to standard output; `a -so`
//! writes the archive to standard output and `a -v<size>` writes volumes.
//! `a -si` / `a -an` (data from standard input) run [`run_add_stdio`] with
//! its exit codes mapped to the 7-Zip ones. `a` to `.7z` (or `-t7z`) uses
//! [`crate::sevenz_write`] with the `-m` switches of [`crate::cli_add_7z`].
//!
//! Limits: archives up to [`MAX_ARCHIVE`] bytes, list files up to
//! [`MAX_LISTFILE`] bytes, wildcard expansion up to [`MAX_WILDCARD_DEPTH`]
//! directory levels and [`MAX_WILDCARD_MATCHES`] matches; per-format limits
//! come from the reader/collector defaults.

use std::ffi::{OsStr, OsString};
use std::io::{BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::archive_detect::{ArchiveFormat as Detected, detect_format};
use crate::archive_name::escape_name;
use crate::archive_open::{StreamReader, decompress, parse_gzip_header, stream_member_name};
use crate::archive_open_crypt::{OpenCryptError, OpenedArchive, PasswordProblem, open_named_with_password};
use crate::archive_open_ext::open_stdin_ext;
use crate::cli_crypt::{CryptSwitches, run_add_crypt, take_crypt_switches};
use crate::archive_reader::{ArchiveFormat, ArchiveReader, ReaderError, ReaderLimits};
use crate::cli_add::{ArchiveFormat as AddFormat, format_from_name};
use crate::cli_add_7z::parse_7z_add_args;
use crate::wim_write::{WimWriteCompression, WimWriteError, WimWriteLimits, WimWriteOptions, create_wim};
use crate::cli_stdio::{STDIN_LIMIT_ENV, StdioError, read_limited, run_add_stdio, stdin_limit, wants_stdio};
use crate::cli_compat::{
    ArchiveType, Charset, CmdLineError, Command, CommandLine, EXIT_CMDLINE, EXIT_FATAL, EXIT_MEMORY, EXIT_OK,
    EXIT_USER_STOP, EXIT_WARNING, NameItem, OverwriteMode, Recurse, StreamTarget, has_wildcard, parse_command_line,
};
use crate::cli_seam::listfile::{ListFileError, parse_listfile};
use crate::cli_seam::slt_format::{SltEntry, format_entry};
use crate::cli_slt::{archive_header, generic_entry, listed_size, sevenz_details};
use crate::cli_seam::wildcard::{match_name, match_path};
use crate::compress_wrap::{Compression, WrapError, compress, compress_bound_for};
use crate::extract_fs::{ExtractError, ExtractOptions, OverwritePolicy, SymlinkPolicy, execute_plan};
use crate::extract_plan::{
    EntryKind, Plan, PlanKind, PlanOptions, PlanWarning, PlannedEntry, normalize_path, plan_extraction,
};
use crate::fs_collect::{
    CollectError, CollectLimits, CollectOptions, CollectedEntry, EntryKind as FsKind, WarningKind, collect,
    read_entry_data,
};
use crate::sevenz_write::{SevenZWriteError, SevenZWriteLimits, SevenZWriteOptions, create_7z};
use crate::tar_create::{TarCreateError, TarCreateLimits, create_tar};
use crate::volume_io::{VolumeError, first_volume_base, read_volumes, write_volumes};
use crate::zip_create::{ZipCreateError, ZipCreateLimits, ZipCreateOptions, create_zip};

/// Largest archive read by `l`/`t`/`x`/`e`.
pub const MAX_ARCHIVE: u64 = 1 << 30;
/// Largest `@listfile`.
pub const MAX_LISTFILE: usize = 16 << 20;
/// Deepest directory level searched when expanding a wildcard for `a`.
pub const MAX_WILDCARD_DEPTH: usize = 256;
/// Most paths a single wildcard may expand to for `a`.
pub const MAX_WILDCARD_MATCHES: usize = 1_000_000;

/// Streams the command talks to.
pub struct Console<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    /// Standard input: the archive for `-si`, and the answers to the
    /// overwrite prompt when `interactive`.
    pub stdin: Option<&'a mut dyn BufRead>,
    /// Ask before overwriting (standard input is a terminal). When false,
    /// conflicts are errors unless `-y` / `-ao` say otherwise.
    pub interactive: bool,
    /// Standard output is a terminal: `a -so` refuses to write there.
    pub stdout_is_terminal: bool,
}

/// True when `a` takes its data from standard input (`-si`, `-an`); that
/// path is [`run_add_stdio`].
fn add_reads_stdin(args: &[OsString]) -> bool {
    for a in args {
        let b = a.as_encoded_bytes();
        if b == b"--" {
            return false;
        }
        if b.len() >= 3 && b[0] == b'-' && (b[1..3].eq_ignore_ascii_case(b"si") || b[1..].eq_ignore_ascii_case(b"an")) {
            return true;
        }
    }
    false
}

/// `cli_add`-style codes of [`run_add_stdio`] to 7-Zip codes.
fn stdio_add_code(code: i32) -> i32 {
    match code {
        0 => EXIT_OK,
        1 => EXIT_FATAL,
        2 => EXIT_CMDLINE,
        3 => EXIT_WARNING,
        c => c,
    }
}

/// Parse `args` for `command` and run it. Returns the 7-Zip exit code.
pub fn run_args(command: Command, args: &[OsString], con: &mut Console<'_>) -> i32 {
    // Encryption switches (-p, -mem=, -mhe) belong to `cli_crypt`.
    let (sw, args) = match take_crypt_switches(args) {
        Ok(v) => v,
        Err(m) => {
            let _ = writeln!(con.stderr, "sediment: {m}");
            return EXIT_CMDLINE;
        }
    };
    let args = &args[..];
    if command == Command::Add && sw != CryptSwitches::default() {
        if wants_stdio(args) {
            let _ = writeln!(con.stderr, "sediment: encryption switches cannot be combined with -si/-so/-v/-t/-an");
            return EXIT_CMDLINE;
        }
        let _ = con.stdout.flush();
        let _ = con.stderr.flush();
        return stdio_add_code(run_add_crypt(args, &sw));
    }
    if command == Command::Add && add_reads_stdin(args) {
        let _ = con.stdout.flush();
        let _ = con.stderr.flush();
        return stdio_add_code(run_add_stdio(args));
    }
    match parse_command_line(command, args) {
        Ok(mut cl) => {
            cl.password = sw.password;
            run(&cl, con)
        }
        Err(CmdLineError { message }) => {
            let _ = writeln!(con.stderr, "sediment: {message}");
            EXIT_CMDLINE
        }
    }
}

/// Run a parsed command line. Returns the 7-Zip exit code.
pub fn run(cl: &CommandLine, con: &mut Console<'_>) -> i32 {
    // With -so, standard output carries data only.
    let out_to = if cl.to_stdout && cl.stdout_to == StreamTarget::Stdout { StreamTarget::Stderr } else { cl.stdout_to };
    let mut ui = Ui { con, out_to, err_to: cl.stderr_to, write_failed: false };
    let code = match cl.command {
        Command::List | Command::Test => run_read(cl, &mut ui),
        Command::Extract | Command::ExtractFlat => run_extract(cl, &mut ui),
        Command::Add => run_add(cl, &mut ui),
    };
    ui.flush();
    if ui.write_failed && code < EXIT_FATAL { EXIT_FATAL } else { code }
}

// ---------------------------------------------------------------------------
// Output routing
// ---------------------------------------------------------------------------

struct Ui<'c, 'a> {
    con: &'c mut Console<'a>,
    out_to: StreamTarget,
    err_to: StreamTarget,
    write_failed: bool,
}

impl Ui<'_, '_> {
    fn write(&mut self, to: StreamTarget, s: &str) {
        let w: &mut dyn Write = match to {
            StreamTarget::Off => return,
            StreamTarget::Stdout => &mut *self.con.stdout,
            StreamTarget::Stderr => &mut *self.con.stderr,
        };
        if w.write_all(s.as_bytes()).is_err() {
            self.write_failed = true;
        }
    }
    fn out(&mut self, s: &str) {
        self.write(self.out_to, s);
    }
    fn err(&mut self, msg: &str) {
        self.write(self.err_to, &format!("sediment: {msg}\n"));
    }
    fn err_entry(&mut self, msg: &str, name: &[u8]) {
        self.err(&format!("{msg}: {}", shown(name)));
    }
    fn warn(&mut self, msg: &str, name: &[u8]) {
        self.err(&format!("warning: {msg}: {}", shown(name)));
    }
    fn flush(&mut self) {
        if self.con.stdout.flush().is_err() || self.con.stderr.flush().is_err() {
            self.write_failed = true;
        }
    }
}

fn shown(name: &[u8]) -> String {
    escape_name(name).unwrap_or_else(|_| String::from("?"))
}

fn os_display(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Name selection: wildcards, list files, -i / -x
// ---------------------------------------------------------------------------

/// A resolved name: text plus whether it is matched recursively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameSpec {
    pub name: OsString,
    pub recursive: bool,
}

/// Why a name list could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// List file missing or unreadable.
    ListFileUnreadable(PathBuf),
    /// List file too large or badly encoded.
    ListFileInvalid(PathBuf, ListFileError),
}

impl NameError {
    fn message(&self) -> String {
        match self {
            NameError::ListFileUnreadable(p) => format!("cannot open list file: {}", os_display(p)),
            NameError::ListFileInvalid(p, e) => format!("invalid list file ({e:?}): {}", os_display(p)),
        }
    }
}

/// Decode a list file with the `-scs` charset (a BOM, when present, wins).
pub fn decode_listfile(data: &[u8], charset: Charset) -> Result<Vec<String>, ListFileError> {
    if data.len() > MAX_LISTFILE {
        return Err(ListFileError::LimitExceeded);
    }
    let le_bom: &[u8] = b"\xff\xfe";
    let with_bom = |body: &mut dyn Iterator<Item = u8>, n: usize| -> Result<Vec<u8>, ListFileError> {
        let mut v = Vec::new();
        v.try_reserve_exact(n + 2).map_err(|_| ListFileError::LimitExceeded)?;
        v.extend_from_slice(le_bom);
        v.extend(body);
        Ok(v)
    };
    let max = MAX_LISTFILE + 2;
    match charset {
        Charset::Utf8 => parse_listfile(data, MAX_LISTFILE),
        Charset::Utf16Le if data.starts_with(le_bom) || data.starts_with(b"\xef\xbb\xbf") => parse_listfile(data, max),
        Charset::Utf16Le => parse_listfile(&with_bom(&mut data.iter().copied(), data.len())?, max),
        Charset::Utf16Be => {
            if data.starts_with(le_bom) || data.starts_with(b"\xef\xbb\xbf") {
                return parse_listfile(data, max);
            }
            let body = data.strip_prefix(b"\xfe\xff").unwrap_or(data);
            if !body.len().is_multiple_of(2) {
                return Err(ListFileError::InvalidUtf16);
            }
            let mut swapped = body.chunks_exact(2).flat_map(|c| [c[1], c[0]]);
            parse_listfile(&with_bom(&mut swapped, body.len())?, max)
        }
    }
}

fn read_capped(path: &Path, max: u64) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn expand_items<'i>(
    items: impl Iterator<Item = (&'i NameItem, Option<Recurse>)>,
    cl: &CommandLine,
) -> Result<Vec<NameSpec>, NameError> {
    let global = cl.recurse.unwrap_or(Recurse::Off);
    let mut out = Vec::new();
    let mut push = |name: OsString, rule: Option<Recurse>| {
        let recursive = rule.unwrap_or(global).applies_to(&name.to_string_lossy());
        out.push(NameSpec { name, recursive });
    };
    for (item, rule) in items {
        match item {
            NameItem::Wildcard(w) => push(w.clone(), rule),
            NameItem::ListFile(p) => {
                let data = read_capped(p, MAX_LISTFILE as u64).ok_or_else(|| NameError::ListFileUnreadable(p.clone()))?;
                let names = decode_listfile(&data, cl.charset).map_err(|e| NameError::ListFileInvalid(p.clone(), e))?;
                for n in names {
                    push(OsString::from(n), rule);
                }
            }
        }
    }
    Ok(out)
}

/// Include names (positional + `-i`) and exclude names (`-x`), resolved.
pub fn resolve_names(cl: &CommandLine) -> Result<(Vec<NameSpec>, Vec<NameSpec>), NameError> {
    let inc = expand_items(
        cl.names.iter().map(|n| (n, None)).chain(cl.includes.iter().map(|r| (&r.item, r.recurse))),
        cl,
    )?;
    let exc = expand_items(cl.excludes.iter().map(|r| (&r.item, r.recurse)), cl)?;
    Ok((inc, exc))
}

/// Member selection for archive commands.
#[derive(Debug, Clone)]
pub struct Selector {
    include: Vec<(String, bool)>,
    exclude: Vec<(String, bool)>,
    case_sensitive: bool,
}

impl Selector {
    pub fn new(include: &[NameSpec], exclude: &[NameSpec], case_sensitive: bool) -> Selector {
        let conv = |v: &[NameSpec]| v.iter().map(|s| (s.name.to_string_lossy().into_owned(), s.recursive)).collect();
        Selector { include: conv(include), exclude: conv(exclude), case_sensitive }
    }

    /// True when `path` is included (no includes = everything) and not excluded.
    pub fn selects(&self, path: &[u8]) -> bool {
        let p = String::from_utf8_lossy(path);
        let hit = |list: &[(String, bool)]| list.iter().any(|(pat, rec)| match_path(pat, &p, *rec, self.case_sensitive));
        (self.include.is_empty() || hit(&self.include)) && !hit(&self.exclude)
    }

    /// True when only `-x` names apply.
    pub fn excludes(&self, path: &[u8]) -> bool {
        let p = String::from_utf8_lossy(path);
        self.exclude.iter().any(|(pat, rec)| match_path(pat, &p, *rec, self.case_sensitive))
    }
}

fn build_selector(cl: &CommandLine, ui: &mut Ui<'_, '_>) -> Result<(Vec<NameSpec>, Selector), i32> {
    match resolve_names(cl) {
        Ok((inc, exc)) => {
            let sel = Selector::new(&inc, &exc, cl.wildcard_case_sensitive());
            Ok((inc, sel))
        }
        Err(e) => {
            ui.err(&e.message());
            Err(EXIT_CMDLINE)
        }
    }
}

// ---------------------------------------------------------------------------
// Opening archives
// ---------------------------------------------------------------------------

/// Archive bytes plus the file name used for format hints.
struct Input {
    bytes: Vec<u8>,
    name: Vec<u8>,
    from_stdin: bool,
}

fn file_name_bytes(p: &Path) -> Vec<u8> {
    p.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default()
}

fn load_input(cl: &CommandLine, ui: &mut Ui<'_, '_>) -> Result<Input, i32> {
    let Some(path) = cl.archive.as_deref() else {
        let limit = match stdin_limit(std::env::var_os(STDIN_LIMIT_ENV).as_deref()) {
            Ok(l) => l,
            Err(_) => {
                ui.err("invalid SEDIMENT_STDIN_LIMIT");
                return Err(EXIT_FATAL);
            }
        };
        let Some(stdin) = ui.con.stdin.as_mut() else {
            ui.err("standard input is not available");
            return Err(EXIT_FATAL);
        };
        return match read_limited(&mut **stdin, limit) {
            Ok(bytes) => Ok(Input { bytes, name: Vec::new(), from_stdin: true }),
            Err(e) => {
                let (m, c) = match e {
                    StdioError::LimitExceeded => ("standard input exceeds the size limit", EXIT_FATAL),
                    StdioError::Allocation => ("allocation failed", EXIT_MEMORY),
                    _ => ("read error", EXIT_FATAL),
                };
                ui.err(m);
                Err(c)
            }
        };
    };
    if let Some(base) = first_volume_base(path) {
        return match read_volumes(&base, MAX_ARCHIVE) {
            Ok((bytes, _)) => Ok(Input { bytes, name: file_name_bytes(&base), from_stdin: false }),
            Err(e) => {
                let (m, c) = match e {
                    VolumeError::NotFound => ("cannot open file", EXIT_FATAL),
                    VolumeError::LimitExceeded | VolumeError::TooManyVolumes => ("file too large", EXIT_FATAL),
                    VolumeError::Allocation => ("allocation failed", EXIT_MEMORY),
                    VolumeError::NotAFile => ("invalid file or size limit", EXIT_FATAL),
                    _ => ("read error", EXIT_FATAL),
                };
                ui.err(m);
                Err(c)
            }
        };
    }
    let bytes = read_archive(path, ui)?;
    Ok(Input { bytes, name: file_name_bytes(path), from_stdin: false })
}

fn read_archive(p: &Path, ui: &mut Ui<'_, '_>) -> Result<Vec<u8>, i32> {
    let fail = |ui: &mut Ui<'_, '_>, m: &str, code| {
        ui.err(m);
        Err(code)
    };
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => return fail(ui, "cannot open file", EXIT_FATAL),
    };
    let m = match f.metadata() {
        Ok(m) => m,
        Err(_) => return fail(ui, "cannot read file metadata", EXIT_FATAL),
    };
    if !m.is_file() || m.len() > MAX_ARCHIVE {
        return fail(ui, "invalid file or size limit", EXIT_FATAL);
    }
    let mut buf = Vec::new();
    if buf.try_reserve_exact(m.len() as usize + 1).is_err() {
        return fail(ui, "allocation failed", EXIT_MEMORY);
    }
    if f.take(MAX_ARCHIVE + 1).read_to_end(&mut buf).is_err() {
        return fail(ui, "read error", EXIT_FATAL);
    }
    if buf.len() as u64 > MAX_ARCHIVE {
        return fail(ui, "file too large", EXIT_FATAL);
    }
    Ok(buf)
}

fn reader_error(ui: &mut Ui<'_, '_>, e: ReaderError) -> i32 {
    match e {
        ReaderError::Unsupported => ui.err("unsupported archive format"),
        ReaderError::CrcMismatch => ui.err("data error (checksum mismatch)"),
        ReaderError::LimitExceeded => ui.err("archive exceeds limits"),
        ReaderError::Allocation => {
            ui.err("allocation failed");
            return EXIT_MEMORY;
        }
        _ => ui.err("parse error"),
    }
    EXIT_FATAL
}

fn type_matches(t: ArchiveType, d: Detected) -> bool {
    // Formats without a magic in `archive_detect` are checked after opening.
    if matches!(t, ArchiveType::Lzh | ArchiveType::Arj | ArchiveType::CompressZ) {
        return true;
    }
    matches!(
        (t, d),
        (ArchiveType::Zip, Detected::Zip)
            | (ArchiveType::SevenZ, Detected::SevenZip)
            | (ArchiveType::Tar, Detected::Tar | Detected::TarHeuristic)
            | (ArchiveType::Gzip, Detected::Gzip)
            | (ArchiveType::Bzip2, Detected::Bzip2)
            | (ArchiveType::Xz, Detected::Xz)
    )
}

/// Base name of a gzip FNAME, if it is a usable file name.
fn gzip_member_name(raw: &[u8]) -> Option<Vec<u8>> {
    let base = raw.rsplit(|&b| b == b'/' || b == b'\\').next().unwrap_or(raw);
    if base.is_empty() || base.len() > 255 || base.iter().all(|&c| c == b'.' || c == b' ') || base.contains(&0) {
        return None;
    }
    Some(base.to_vec())
}

/// Open `bytes` as exactly one compressed stream (`-tgzip` etc.): the
/// decompressed data is a single member, even when it is a tar archive.
fn open_stream(bytes: &[u8], t: ArchiveType, file_name: &[u8], limits: ReaderLimits) -> Result<StreamReader, ReaderError> {
    let format = match t {
        ArchiveType::Gzip => ArchiveFormat::Gzip,
        ArchiveType::Bzip2 => ArchiveFormat::Bzip2,
        _ => ArchiveFormat::Xz,
    };
    let (name, mtime, crc) = if format == ArchiveFormat::Gzip {
        let h = parse_gzip_header(bytes, 4096)?;
        let crc = bytes.len().checked_sub(8).map(|t| u32::from_le_bytes([bytes[t], bytes[t + 1], bytes[t + 2], bytes[t + 3]]));
        (h.name.as_deref().and_then(gzip_member_name), h.mtime, crc)
    } else {
        (None, None, None)
    };
    let name = name.unwrap_or_else(|| stream_member_name(file_name));
    let max = usize::try_from(limits.max_entry_size.min(limits.max_total_size)).unwrap_or(usize::MAX);
    let data = decompress(format, bytes, max)?;
    Ok(StreamReader::new(format, name, data, mtime, crc))
}

fn open_reader<'b>(input: &'b Input, cl: &CommandLine, ui: &mut Ui<'_, '_>) -> Result<OpenedArchive<'b>, i32> {
    let buf = &input.bytes;
    let limits = ReaderLimits::default();
    if let Some(t) = cl.archive_type {
        if !type_matches(t, detect_format(buf)) {
            ui.err(&format!("cannot open the file as {} archive", t.name()));
            return Err(EXIT_FATAL);
        }
        if matches!(t, ArchiveType::Gzip | ArchiveType::Bzip2 | ArchiveType::Xz) {
            return match open_stream(buf, t, &input.name, limits) {
                Ok(r) => Ok(OpenedArchive::plain(Box::new(r))),
                Err(e) => Err(reader_error(ui, e)),
            };
        }
    }
    // Only zip and 7z can be encrypted; everything else read from standard
    // input goes through the stdin opener (member-name recovery, zstd, WIM).
    let opened = if input.from_stdin && !matches!(detect_format(buf), Detected::Zip | Detected::SevenZip) {
        open_stdin_ext(buf, limits).map(OpenedArchive::plain).map_err(OpenCryptError::Reader)
    } else {
        open_named_with_password(buf, &input.name, limits, cl.password.as_deref())
    };
    let opened = match opened {
        Ok(o) => o,
        Err(OpenCryptError::PasswordRequired) => {
            ui.err("cannot open encrypted archive: password required (use -pPASSWORD)");
            return Err(EXIT_FATAL);
        }
        Err(OpenCryptError::WrongPassword) => {
            ui.err("cannot open encrypted archive. Wrong password?");
            return Err(EXIT_FATAL);
        }
        Err(OpenCryptError::Reader(e)) => return Err(reader_error(ui, e)),
    };
    let expected = match cl.archive_type {
        Some(ArchiveType::Lzh) => Some(ArchiveFormat::Lzh),
        Some(ArchiveType::Arj) => Some(ArchiveFormat::Arj),
        Some(ArchiveType::CompressZ) => Some(ArchiveFormat::CompressZ),
        _ => None,
    };
    if let (Some(t), Some(f)) = (cl.archive_type, expected)
        && opened.reader.format() != f
    {
        ui.err(&format!("cannot open the file as {} archive", t.name()));
        return Err(EXIT_FATAL);
    }
    Ok(opened)
}

/// 7-Zip reports password trouble as a fatal error (exit 2).
fn password_error(ui: &mut Ui<'_, '_>, opened: &OpenedArchive<'_>, name: &[u8]) -> Option<i32> {
    let msg = match opened.password_problem()? {
        PasswordProblem::Required => "password required (use -pPASSWORD)",
        PasswordProblem::Wrong => "wrong password",
    };
    ui.err_entry(msg, name);
    Some(EXIT_FATAL)
}

fn format_name(f: ArchiveFormat) -> &'static str {
    match f {
        ArchiveFormat::Zip => "zip",
        ArchiveFormat::Tar => "tar",
        ArchiveFormat::Gzip => "gzip",
        ArchiveFormat::Xz => "xz",
        ArchiveFormat::Bzip2 => "bzip2",
        ArchiveFormat::SevenZ => "7z",
        ArchiveFormat::Lzh => "lzh",
        ArchiveFormat::Arj => "arj",
        ArchiveFormat::CompressZ => "Z",
        ArchiveFormat::Cpio => "cpio",
        ArchiveFormat::Ar => "ar",
        ArchiveFormat::Deb => "deb",
        ArchiveFormat::Rpm => "rpm",
        ArchiveFormat::Xar => "xar",
        ArchiveFormat::Zstd => "zstd",
        ArchiveFormat::Wim => "wim",
    }
}

// ---------------------------------------------------------------------------
// l / t
// ---------------------------------------------------------------------------

fn run_read(cl: &CommandLine, ui: &mut Ui<'_, '_>) -> i32 {
    let (_, sel) = match build_selector(cl, ui) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let input = match load_input(cl, ui) {
        Ok(b) => b,
        Err(c) => return c,
    };
    let opened = match open_reader(&input, cl, ui) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let reader = opened.reader.as_ref();
    let chosen: Vec<usize> = (0..reader.entries().len()).filter(|&i| sel.selects(&reader.entries()[i].path)).collect();
    if cl.command == Command::List {
        list(cl, ui, reader, &chosen, &input.bytes);
        EXIT_OK
    } else {
        test(cl, ui, &opened, &chosen)
    }
}

fn list(cl: &CommandLine, ui: &mut Ui<'_, '_>, reader: &dyn ArchiveReader, chosen: &[usize], buf: &[u8]) {
    if cl.technical {
        let mut extra = Vec::new();
        let mut detailed: Option<Vec<SltEntry>> = None;
        if reader.format() == ArchiveFormat::SevenZ
            && let Ok((h, e)) = sevenz_details(buf, ReaderLimits::default())
            && e.len() == reader.entries().len()
        {
            extra = h;
            detailed = Some(e);
        }
        if !cl.no_headers {
            let name = cl.archive.as_deref().map_or_else(|| String::from("stdin"), os_display);
            ui.out(&archive_header(&name, format_name(reader.format()), buf.len() as u64, &extra));
        }
        for &i in chosen {
            let entry = match &detailed {
                Some(d) => d[i].clone(),
                None => generic_entry(reader, i),
            };
            ui.out(&format_entry(&entry));
        }
        return;
    }
    if !cl.no_headers {
        ui.out("SIZE\tCRC32\tNAME\n");
    }
    for &i in chosen {
        let e = &reader.entries()[i];
        let crc = match reader.crc32(i) {
            Some(c) => format!("{c:08x}"),
            None => String::from("--------"),
        };
        ui.out(&format!("{}\t{crc}\t{}\n", listed_size(e), shown(&e.path)));
    }
}

fn test(cl: &CommandLine, ui: &mut Ui<'_, '_>, opened: &OpenedArchive<'_>, chosen: &[usize]) -> i32 {
    let reader = opened.reader.as_ref();
    let mut total: u64 = 0;
    let mut code = EXIT_OK;
    for &i in chosen {
        let e = &reader.entries()[i];
        if cl.log_level >= 1 {
            ui.out(&format!("T {}\n", shown(&e.path)));
        }
        match reader.read(i) {
            Ok(d) if !matches!(e.kind, EntryKind::File) || d.len() as u64 == e.size => {}
            Err(_) if opened.password_problem().is_some() => {
                // A missing or wrong password stops the whole test, as in 7-Zip.
                return password_error(ui, opened, &e.path).unwrap_or(EXIT_FATAL);
            }
            Err(ReaderError::Unsupported) => {
                ui.err_entry("unsupported compression method", &e.path);
                code = code.max(EXIT_FATAL);
            }
            Err(ReaderError::Allocation) => {
                ui.err_entry("allocation failed", &e.path);
                code = EXIT_MEMORY;
            }
            _ => {
                ui.err_entry("data error", &e.path);
                code = code.max(EXIT_FATAL);
            }
        }
        total = total.saturating_add(e.size);
    }
    if code == EXIT_OK && !cl.no_headers {
        ui.out(&format!("OK\t{}\t{total}\n", chosen.len()));
    }
    code
}

// ---------------------------------------------------------------------------
// x / e
// ---------------------------------------------------------------------------

fn last_component(path: &[u8]) -> Vec<u8> {
    path.split(|&b| b == b'/' || b == b'\\').rfind(|c| !c.is_empty()).unwrap_or(b"").to_vec()
}

/// For `e`: drop directories, keep only file names.
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

/// Rewrite plan indices from positions in the planned slice to reader indices.
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

#[cfg(unix)]
fn bytes_os(b: &[u8]) -> Option<OsString> {
    use std::os::unix::ffi::OsStrExt;
    Some(OsStr::from_bytes(b).to_os_string())
}

#[cfg(not(unix))]
fn bytes_os(b: &[u8]) -> Option<OsString> {
    std::str::from_utf8(b).ok().map(OsString::from)
}

/// Existing non-directory at `root/components`, reached only through real
/// directories (never through a symlink). `None` when absent or unsafe.
fn existing_target(root: &Path, components: &[Vec<u8>]) -> Option<PathBuf> {
    let (last, dirs) = components.split_last()?;
    let mut p = root.to_path_buf();
    for c in dirs {
        p.push(bytes_os(c)?);
        let m = std::fs::symlink_metadata(&p).ok()?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return None;
        }
    }
    p.push(bytes_os(last)?);
    let m = std::fs::symlink_metadata(&p).ok()?;
    if m.is_dir() { None } else { Some(p) }
}

fn conflicts(plan: &Plan, root: &Path) -> Vec<(usize, PathBuf)> {
    plan.items
        .iter()
        .filter(|it| !matches!(it.kind, PlanKind::Dir))
        .filter_map(|it| existing_target(root, &it.components).map(|p| (it.index, p)))
        .collect()
}

/// `-aot`: move existing files out of the way as `name_N.ext`.
fn rename_existing(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default();
    let dot = name.iter().rposition(|&b| b == b'.').filter(|&p| p > 0);
    let (stem, ext) = match dot {
        Some(p) => (&name[..p], &name[p..]),
        None => (&name[..], &b""[..]),
    };
    for n in 1..10_000u32 {
        let mut candidate = stem.to_vec();
        candidate.extend_from_slice(format!("_{n}").as_bytes());
        candidate.extend_from_slice(ext);
        let target = path.with_file_name(bytes_os(&candidate).ok_or(std::io::ErrorKind::InvalidInput)?);
        match std::fs::symlink_metadata(&target) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::rename(path, &target)?;
                return Ok(target);
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }
    }
    Err(std::io::ErrorKind::AlreadyExists.into())
}

enum Answer {
    Mode(OverwriteMode),
    Quit,
}

/// Ask once how to treat existing files.
fn prompt_overwrite(ui: &mut Ui<'_, '_>, first: &Path, count: usize) -> Answer {
    for _ in 0..5 {
        ui.write(
            ui.err_to,
            &format!(
                "File already exists: {} ({count} existing)\n(A)lways overwrite / (S)kip all / A(u)to rename all / Rename existing (t) / (Q)uit? ",
                os_display(first)
            ),
        );
        ui.flush();
        let Some(input) = ui.con.stdin.as_mut() else { return Answer::Quit };
        let mut line = String::new();
        match input.read_line(&mut line) {
            Ok(0) | Err(_) => return Answer::Quit,
            Ok(_) => {}
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "a" | "y" | "yes" | "always" => return Answer::Mode(OverwriteMode::All),
            "s" | "n" | "no" | "skip" => return Answer::Mode(OverwriteMode::Skip),
            "u" => return Answer::Mode(OverwriteMode::RenameNew),
            "t" => return Answer::Mode(OverwriteMode::RenameExisting),
            "q" | "quit" => return Answer::Quit,
            _ => {}
        }
    }
    Answer::Quit
}

fn extract_error_code(e: ExtractError) -> i32 {
    match e {
        ExtractError::Allocation | ExtractError::Source(ReaderError::Allocation) => EXIT_MEMORY,
        _ => EXIT_FATAL,
    }
}

/// One output root and the members extracted below it.
struct Group {
    root: PathBuf,
    planned: Vec<PlannedEntry>,
    map: Vec<usize>,
}

fn split_groups(cl: &CommandLine, entries: &[PlannedEntry], chosen: &[usize]) -> Vec<Group> {
    let out_dir = cl.output_dir.clone().unwrap_or_else(|| PathBuf::from("."));
    let flat = cl.command == Command::ExtractFlat;
    let mut rel = Group { root: out_dir, planned: Vec::new(), map: Vec::new() };
    let mut abs = Group { root: PathBuf::from("/"), planned: Vec::new(), map: Vec::new() };
    for &i in chosen {
        let e = &entries[i];
        // `..` in an absolute name is never honoured: such members stay in
        // the relative group, where the planner rejects them.
        let dotdot = e.path.split(|&b| b == b'/' || b == b'\\').any(|c| c == b"..");
        let absolute = cl.full_paths && cfg!(unix) && !flat && e.path.first() == Some(&b'/') && !dotdot;
        if absolute {
            let mut s = e.clone();
            let start = s.path.iter().position(|&b| b != b'/').unwrap_or(s.path.len());
            s.path.drain(..start);
            abs.planned.push(s);
            abs.map.push(i);
        } else {
            rel.planned.push(e.clone());
            rel.map.push(i);
        }
    }
    if flat {
        let (planned, m) = flatten(&rel.planned);
        rel.map = m.iter().map(|&k| rel.map[k]).collect();
        rel.planned = planned;
    }
    [rel, abs].into_iter().filter(|g| !g.planned.is_empty()).collect()
}

#[derive(Default)]
struct Totals {
    files: usize,
    dirs: usize,
    bytes: u64,
}

/// `x`/`e -so`: the data of every selected regular file, in archive order,
/// to standard output; nothing touches the disk. A closed pipe ends quietly
/// with [`EXIT_WARNING`].
fn extract_to_stdout(cl: &CommandLine, ui: &mut Ui<'_, '_>, opened: &OpenedArchive<'_>, chosen: &[usize]) -> i32 {
    let reader = opened.reader.as_ref();
    let entries = reader.entries();
    for &i in chosen {
        let e = &entries[i];
        if !matches!(e.kind, EntryKind::File) {
            continue;
        }
        let data = match reader.read(i) {
            Ok(d) if d.len() as u64 == e.size => d,
            Err(_) if opened.password_problem().is_some() => {
                return password_error(ui, opened, &e.path).unwrap_or(EXIT_FATAL);
            }
            Err(ReaderError::Unsupported) => {
                ui.err_entry("unsupported compression method", &e.path);
                return EXIT_FATAL;
            }
            Err(ReaderError::Allocation) => {
                ui.err_entry("allocation failed", &e.path);
                return EXIT_MEMORY;
            }
            _ => {
                ui.err_entry("data error", &e.path);
                return EXIT_FATAL;
            }
        };
        if let Err(err) = ui.con.stdout.write_all(&data) {
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                return EXIT_WARNING;
            }
            ui.err("write error");
            return EXIT_FATAL;
        }
        if cl.log_level >= 1 {
            ui.out(&format!("- {}\n", shown(&e.path)));
        }
    }
    match ui.con.stdout.flush() {
        Ok(()) => EXIT_OK,
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => EXIT_WARNING,
        Err(_) => {
            ui.err("write error");
            EXIT_FATAL
        }
    }
}

fn run_extract(cl: &CommandLine, ui: &mut Ui<'_, '_>) -> i32 {
    let (_, sel) = match build_selector(cl, ui) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let input = match load_input(cl, ui) {
        Ok(b) => b,
        Err(c) => return c,
    };
    let opened = match open_reader(&input, cl, ui) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let reader = &opened.reader;
    let entries = reader.entries();
    let chosen: Vec<usize> = (0..entries.len()).filter(|&i| sel.selects(&entries[i].path)).collect();
    if cl.to_stdout {
        return extract_to_stdout(cl, ui, &opened, &chosen);
    }
    let mut plans = Vec::new();
    for g in split_groups(cl, entries, &chosen) {
        let mut plan = match plan_extraction(&g.planned, &PlanOptions::default()) {
            Ok(p) => p,
            Err(f) => {
                match f.index {
                    Some(i) => ui.err_entry(&format!("unsafe entry rejected ({:?})", f.error), &entries[g.map[i]].path),
                    None => ui.err_entry(&format!("archive rejected ({:?})", f.error), b""),
                }
                return EXIT_FATAL;
            }
        };
        remap(&mut plan, &g.map);
        plans.push((g.root, plan));
    }
    let mut code = EXIT_OK;
    if cl.command == Command::ExtractFlat {
        for (_, plan) in &plans {
            for it in &plan.items {
                if normalize_path(&entries[it.index].path, &PlanOptions::default().limits).is_err() {
                    ui.warn("unsafe path flattened", &entries[it.index].path);
                    code = EXIT_WARNING;
                }
            }
        }
    }
    for (_, plan) in &plans {
        for w in &plan.warnings {
            match *w {
                PlanWarning::NonPortableName { index } => ui.warn("non-portable name", &entries[index].path),
                PlanWarning::CaseCollision { index, .. } => ui.warn("names differ only by case", &entries[index].path),
                PlanWarning::DuplicatePath { index, .. } => ui.warn("duplicate name", &entries[index].path),
            }
        }
    }

    // Overwrite mode: -ao wins, then -y, then the interactive prompt.
    let mut mode = cl.overwrite.or(if cl.yes { Some(OverwriteMode::All) } else { None });
    if mode.is_none() && ui.con.interactive && cl.stdin.is_none() && ui.con.stdin.is_some() {
        let existing: Vec<PathBuf> = plans.iter().flat_map(|(root, plan)| conflicts(plan, root)).map(|(_, p)| p).collect();
        if let Some(first) = existing.first() {
            match prompt_overwrite(ui, first, existing.len()) {
                Answer::Mode(m) => mode = Some(m),
                Answer::Quit => {
                    ui.err("operation stopped by user");
                    return EXIT_USER_STOP;
                }
            }
        }
    }
    let policy = match mode {
        None | Some(OverwriteMode::RenameExisting) => OverwritePolicy::Error,
        Some(OverwriteMode::All) => OverwritePolicy::Overwrite,
        Some(OverwriteMode::Skip) => OverwritePolicy::Skip,
        Some(OverwriteMode::RenameNew) => OverwritePolicy::Rename,
    };
    let symlinks = if cl.symlinks { SymlinkPolicy::Create } else { SymlinkPolicy::Skip };
    let opts = ExtractOptions { overwrite: policy, symlinks, ..ExtractOptions::default() };
    let mut totals = Totals::default();
    for (root, plan) in &plans {
        if mode == Some(OverwriteMode::RenameExisting) {
            for (index, path) in conflicts(plan, root) {
                match rename_existing(&path) {
                    Ok(to) if cl.log_level >= 3 => {
                        ui.out(&format!("! {} -> {}\n", os_display(&path), os_display(&to)));
                    }
                    Ok(_) => {}
                    Err(_) => {
                        ui.err_entry("cannot rename existing file", &entries[index].path);
                        return EXIT_FATAL;
                    }
                }
            }
        }
        let report = match execute_plan(plan, reader.as_ref(), root, &opts) {
            Ok(r) => r,
            Err(f) => {
                let name = f.index.map(|i| entries[i].path.as_slice()).unwrap_or(b"");
                if let Some(c) = password_error(ui, &opened, name) {
                    return c;
                }
                ui.err_entry(&format!("cannot extract ({:?})", f.error), name);
                return extract_error_code(f.error);
            }
        };
        for &i in &report.skipped_existing {
            ui.warn("skipped existing", &entries[i].path);
        }
        for &i in &report.skipped_symlinks {
            ui.warn("symbolic link not extracted (use -snl)", &entries[i].path);
        }
        if !report.skipped_symlinks.is_empty() {
            code = EXIT_WARNING;
        }
        if cl.log_level >= 1 {
            for it in &plan.items {
                let skipped = report.skipped_existing.contains(&it.index) || report.skipped_symlinks.contains(&it.index);
                let is_dir = matches!(it.kind, PlanKind::Dir);
                if (skipped || is_dir) && cl.log_level < 2 {
                    continue;
                }
                let tag = if skipped { "skipped " } else { "" };
                let suffix = if is_dir { "/" } else { "" };
                ui.out(&format!("- {tag}{}{suffix}\n", shown(&it.joined())));
            }
            if cl.log_level >= 3 {
                for (i, p) in &report.renamed {
                    ui.out(&format!("  {} -> {}\n", shown(&entries[*i].path), os_display(p)));
                }
            }
        }
        totals.files += report.files + report.symlinks;
        totals.dirs += report.dirs;
        totals.bytes = totals.bytes.saturating_add(report.bytes);
    }
    if cl.log_level >= 1 && !cl.no_headers {
        ui.out(&format!("Folders: {}\nFiles: {}\nSize: {}\n", totals.dirs, totals.files, totals.bytes));
    }
    code
}

// ---------------------------------------------------------------------------
// a
// ---------------------------------------------------------------------------

/// Output layout chosen for `a`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddTarget {
    Zip,
    Tar(Compression),
    /// One file compressed as a bare stream (`.gz`, `.bz2`, `.xz`).
    Stream(Compression),
    SevenZ,
    /// Single-image WIM (`.wim`; uncompressed with `-mx0`, else XPRESS).
    Wim,
}

/// Why [`add_target`] found no output layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddTargetError {
    /// No `-t` and the name has no known extension (command line, exit 7).
    UnknownName,
    /// `-t` names a read-only type (lzh, arj, Z; command line, exit 7).
    ReadOnlyType,
}

/// Pick the output layout from `-t` or the archive name.
pub fn add_target(archive: &Path, t: Option<ArchiveType>) -> Result<AddTarget, AddTargetError> {
    match t {
        Some(ArchiveType::Zip) => return Ok(AddTarget::Zip),
        Some(ArchiveType::Tar) => return Ok(AddTarget::Tar(Compression::None)),
        Some(ArchiveType::Gzip) => return Ok(AddTarget::Stream(Compression::Gzip)),
        Some(ArchiveType::Bzip2) => return Ok(AddTarget::Stream(Compression::Bzip2)),
        Some(ArchiveType::Xz) => return Ok(AddTarget::Stream(Compression::Xz)),
        Some(ArchiveType::SevenZ) => return Ok(AddTarget::SevenZ),
        Some(ArchiveType::Lzh | ArchiveType::Arj | ArchiveType::CompressZ) => return Err(AddTargetError::ReadOnlyType),
        None => {}
    }
    if let Some(f) = format_from_name(archive) {
        return Ok(match f {
            AddFormat::Zip => AddTarget::Zip,
            AddFormat::Tar(c) => AddTarget::Tar(c),
        });
    }
    let name = archive.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let ends = |ext: &str| name.len() > ext.len() && name.ends_with(ext);
    if ends(".gz") {
        Ok(AddTarget::Stream(Compression::Gzip))
    } else if ends(".bz2") {
        Ok(AddTarget::Stream(Compression::Bzip2))
    } else if ends(".xz") {
        Ok(AddTarget::Stream(Compression::Xz))
    } else if ends(".7z") {
        Ok(AddTarget::SevenZ)
    } else if ends(".wim") {
        Ok(AddTarget::Wim)
    } else {
        Err(AddTargetError::UnknownName)
    }
}

/// Error from compressing output; `Memory` maps to exit code 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildError {
    Memory,
    Fatal,
}

/// Compress one stream with `compress_wrap` (level mapping per format).
fn compress_stream(c: Compression, data: &[u8], level: u8) -> Result<Vec<u8>, BuildError> {
    let bound = compress_bound_for(c, data.len()).ok_or(BuildError::Fatal)?;
    compress(c, data, level, bound).map_err(|e| if e == WrapError::Allocation { BuildError::Memory } else { BuildError::Fatal })
}

/// A concrete input path and the archive directory its entries go under.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AddInput {
    path: PathBuf,
    prefix: Vec<u8>,
}

fn path_bytes(p: &OsStr) -> Vec<u8> {
    p.as_encoded_bytes().to_vec()
}

fn join_name(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        return name.to_vec();
    }
    let mut v = prefix.to_vec();
    if !name.is_empty() {
        v.push(b'/');
        v.extend_from_slice(name);
    }
    v
}

/// Archive prefix for `-spf`: the absolute directory the input's entries
/// are stored under (its parent, or itself for `.`-like inputs whose
/// children go to the root), lexically normalized, without root or drive.
fn full_path_prefix(path: &Path) -> Option<Vec<u8>> {
    let abs = std::path::absolute(path).ok()?;
    let named = matches!(path.components().next_back(), Some(Component::Normal(_)));
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for c in abs.components() {
        match c {
            Component::Normal(n) => parts.push(path_bytes(n)),
            Component::ParentDir => {
                parts.pop();
            }
            _ => {}
        }
    }
    if named {
        parts.pop();
    }
    Some(parts.join(&b'/'))
}

struct Expansion {
    inputs: Vec<AddInput>,
    missing: Vec<OsString>,
}

/// Split `name` into the literal directory before the first wildcard and the
/// pattern after it (`src/*.rs` -> (`src`, `*.rs`)).
fn split_wildcard(name: &str) -> (&str, &str) {
    let first = name.find(['*', '?']).unwrap_or(name.len());
    match name[..first].rfind(['/', '\\']) {
        Some(0) => ("/", &name[1..]),
        Some(p) => (&name[..p], &name[p + 1..]),
        None => ("", name),
    }
}

fn pattern_parts(p: &str) -> Vec<&str> {
    p.split(['/', '\\']).filter(|c| !c.is_empty() && *c != ".").collect()
}

/// Expand one wildcard (or recursive literal) name against the file system.
/// Matched directories are added whole; symlinked directories are not
/// searched.
fn expand_wildcard(spec: &NameSpec, case_sensitive: bool, out: &mut Vec<AddInput>) -> Result<usize, CollectError> {
    let text = spec.name.to_string_lossy().into_owned();
    let (base, pattern) = split_wildcard(&text);
    let parts = pattern_parts(pattern);
    if parts.is_empty() {
        return Ok(0);
    }
    let base_dir = if base.is_empty() { PathBuf::from(".") } else { PathBuf::from(base) };
    // Single-component patterns may match at any depth with -r.
    let anywhere = spec.recursive && parts.len() == 1;
    let mut found = 0usize;
    let mut stack: Vec<(PathBuf, Vec<u8>, usize)> = vec![(base_dir, Vec::new(), 0)];
    while let Some((dir, rel, depth)) = stack.pop() {
        if depth > MAX_WILDCARD_DEPTH {
            return Err(CollectError::LimitExceeded);
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut children: Vec<(OsString, PathBuf)> = rd.filter_map(|e| e.ok()).map(|e| (e.file_name(), e.path())).collect();
        children.sort();
        // Push in reverse so the stack visits names in order.
        let mut descend = Vec::new();
        for (name, path) in children {
            let lossy = name.to_string_lossy();
            let level = if anywhere { 0 } else { depth };
            let is_real_dir = std::fs::symlink_metadata(&path).map(|m| m.is_dir()).unwrap_or(false);
            let child_rel = join_name(&rel, &path_bytes(&name));
            if match_name(parts[level], &lossy, case_sensitive) {
                if level + 1 == parts.len() {
                    if out.len() >= MAX_WILDCARD_MATCHES {
                        return Err(CollectError::LimitExceeded);
                    }
                    out.push(AddInput { path, prefix: rel.clone() });
                    found += 1;
                    continue;
                }
                if is_real_dir {
                    descend.push((path, child_rel, depth + 1));
                }
            } else if anywhere && is_real_dir {
                descend.push((path, child_rel, depth + 1));
            }
        }
        stack.extend(descend.into_iter().rev());
    }
    Ok(found)
}

fn expand_inputs(specs: &[NameSpec], cl: &CommandLine) -> Result<Expansion, CollectError> {
    let cs = cl.wildcard_case_sensitive();
    let mut exp = Expansion { inputs: Vec::new(), missing: Vec::new() };
    for spec in specs {
        let text = spec.name.to_string_lossy();
        let simple_name = !text.contains(['/', '\\']);
        if has_wildcard(&text) || (spec.recursive && simple_name) {
            if expand_wildcard(spec, cs, &mut exp.inputs)? == 0 {
                exp.missing.push(spec.name.clone());
            }
        } else if std::fs::symlink_metadata(&spec.name).is_ok() {
            exp.inputs.push(AddInput { path: PathBuf::from(&spec.name), prefix: Vec::new() });
        } else {
            exp.missing.push(spec.name.clone());
        }
    }
    if cl.full_paths {
        for i in &mut exp.inputs {
            i.prefix = full_path_prefix(&i.path).ok_or(CollectError::NotFound)?;
        }
    }
    Ok(exp)
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

fn collect_code(e: CollectError) -> i32 {
    if e == CollectError::Allocation { EXIT_MEMORY } else { EXIT_FATAL }
}

fn warn_msg(k: WarningKind) -> &'static str {
    match k {
        WarningKind::UnreadableDirectory => "cannot list directory; contents skipped",
        WarningKind::UnreadableFile => "cannot read; skipped",
        WarningKind::SpecialFile => "special file; skipped",
        WarningKind::SymlinkLoop => "symlink loop; skipped",
        WarningKind::ExcludedOutput => "is the output archive; skipped",
    }
}

fn name_key(name: &[u8]) -> Vec<&[u8]> {
    name.split(|&c| c == b'/').collect()
}

struct Gathered {
    entries: Vec<CollectedEntry>,
    warned: bool,
    total_bytes: u64,
}

/// Collect every input, prefix names, apply `-x`, sort and de-duplicate.
fn gather(cl: &CommandLine, ui: &mut Ui<'_, '_>, inputs: &[AddInput], sel: &Selector) -> Result<Gathered, i32> {
    let options = CollectOptions {
        follow_symlinks: cl.follow_symlinks,
        strict: false,
        exclude: cl.archive.iter().cloned().collect(),
    };
    let mut limits = CollectLimits::default();
    let mut out = Gathered { entries: Vec::new(), warned: false, total_bytes: 0 };
    for input in inputs {
        let c = match collect(std::slice::from_ref(&input.path), &options, limits) {
            Ok(c) => c,
            Err(e) => {
                ui.err(&format!("{}: {}", os_display(&input.path), collect_msg(e)));
                return Err(collect_code(e));
            }
        };
        for w in &c.warnings {
            ui.err(&format!("warning: {}: {}", os_display(&w.path), warn_msg(w.kind)));
            if w.kind != WarningKind::ExcludedOutput {
                out.warned = true;
            }
        }
        limits.max_entries = limits.max_entries.saturating_sub(c.entries.len());
        limits.max_total_bytes = limits.max_total_bytes.saturating_sub(c.total_bytes);
        for mut e in c.entries {
            e.name = join_name(&input.prefix, &e.name);
            if e.name.len() > limits.max_name_bytes {
                ui.err_entry("name too long", &e.name);
                return Err(EXIT_FATAL);
            }
            if sel.excludes(&e.name) {
                continue;
            }
            if out.entries.try_reserve(1).is_err() {
                ui.err("out of memory");
                return Err(EXIT_MEMORY);
            }
            if e.kind == FsKind::File {
                out.total_bytes = out.total_bytes.saturating_add(e.size);
            }
            out.entries.push(e);
        }
    }
    out.entries.sort_by(|a, b| name_key(&a.name).cmp(&name_key(&b.name)));
    let mut deduped: Vec<CollectedEntry> = Vec::with_capacity(out.entries.len());
    for e in out.entries.drain(..) {
        if let Some(prev) = deduped.last()
            && prev.name == e.name
        {
            if prev.source == e.source || prev.kind == FsKind::Directory && e.kind == FsKind::Directory {
                continue;
            }
            ui.err_entry("duplicate entry name", &e.name);
            return Err(EXIT_FATAL);
        }
        deduped.push(e);
    }
    out.entries = deduped;
    Ok(out)
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp_name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    tmp_name.push(format!(".sediment-tmp-{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let res = (|| -> std::io::Result<()> {
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

fn build_archive(
    target: AddTarget,
    level: u8,
    sevenz: &SevenZWriteOptions,
    g: &Gathered,
    ui: &mut Ui<'_, '_>,
) -> Result<Vec<u8>, i32> {
    let mut datas: Vec<Vec<u8>> = Vec::new();
    for e in &g.entries {
        match read_entry_data(e, CollectLimits::default().max_total_bytes) {
            Ok(d) => datas.push(d),
            Err(x) => {
                ui.err(&format!("{}: {}", os_display(&e.source), collect_msg(x)));
                return Err(collect_code(x));
            }
        }
    }
    let entries: Vec<_> = g.entries.iter().zip(datas.iter()).map(|(e, d)| e.as_archive_entry(d)).collect();
    let built = match target {
        AddTarget::Zip => match create_zip(&entries, ZipCreateOptions { level }, ZipCreateLimits::default()) {
            Ok(z) => {
                for &i in &z.skipped {
                    ui.err(&format!(
                        "note: {}: symlink not stored in zip (use -l to store its target)",
                        os_display(&g.entries[i].source)
                    ));
                }
                Ok(z.bytes)
            }
            Err(ZipCreateError::Allocation) => Err(BuildError::Memory),
            Err(e) => {
                ui.err(&format!("cannot build zip: {e:?}"));
                return Err(EXIT_FATAL);
            }
        },
        AddTarget::Tar(c) => match create_tar(&entries, TarCreateLimits::default()) {
            Ok(t) if c == Compression::None => Ok(t),
            Ok(t) => compress_stream(c, &t, level),
            Err(TarCreateError::Allocation) => Err(BuildError::Memory),
            Err(e) => {
                ui.err(&format!("cannot build tar: {e:?}"));
                return Err(EXIT_FATAL);
            }
        },
        AddTarget::SevenZ => match create_7z(&entries, sevenz, SevenZWriteLimits::default()) {
            Ok(b) => Ok(b),
            Err(SevenZWriteError::Allocation) => Err(BuildError::Memory),
            Err(e) => {
                ui.err(&format!("cannot build 7z: {e:?}"));
                return Err(EXIT_FATAL);
            }
        },
        AddTarget::Wim => {
            let compression = if level == 0 { WimWriteCompression::None } else { WimWriteCompression::Xpress };
            let opts = WimWriteOptions { compression, ..WimWriteOptions::default() };
            match create_wim(&entries, &opts, WimWriteLimits::default()) {
                Ok(b) => Ok(b),
                Err(WimWriteError::Allocation) => Err(BuildError::Memory),
                Err(e) => {
                    ui.err(&format!("cannot build wim: {e:?}"));
                    return Err(EXIT_FATAL);
                }
            }
        }
        AddTarget::Stream(c) => {
            let files: Vec<usize> = (0..g.entries.len()).filter(|&i| g.entries[i].kind == FsKind::File).collect();
            if files.len() != 1 || g.entries.len() != 1 {
                ui.err("this archive type holds exactly one file");
                return Err(EXIT_FATAL);
            }
            compress_stream(c, &datas[files[0]], level)
        }
    };
    built.map_err(|e| match e {
        BuildError::Memory => {
            ui.err("out of memory");
            EXIT_MEMORY
        }
        BuildError::Fatal => {
            ui.err("compression failed");
            EXIT_FATAL
        }
    })
}

/// `-sdel`: remove added files, then directories that became empty.
fn delete_sources(entries: &[CollectedEntry], ui: &mut Ui<'_, '_>) -> bool {
    let mut ok = true;
    for e in entries.iter().filter(|e| e.kind != FsKind::Directory) {
        if std::fs::remove_file(&e.source).is_err() {
            ui.err(&format!("warning: {}: cannot delete", os_display(&e.source)));
            ok = false;
        }
    }
    for e in entries.iter().rev().filter(|e| e.kind == FsKind::Directory) {
        // Directories still holding unlisted (e.g. excluded) files stay.
        let _ = std::fs::remove_dir(&e.source);
    }
    ok
}

/// 7z writer options from `-mx` and the `-m` switches (parsed by
/// [`parse_7z_add_args`], so the spellings match `cli_add_7z`).
fn sevenz_options(cl: &CommandLine) -> Result<SevenZWriteOptions, String> {
    let mut args: Vec<OsString> = Vec::new();
    if let Some(l) = cl.level {
        args.push(format!("-mx{l}").into());
    }
    args.extend(cl.methods.iter().cloned());
    args.push("--".into());
    args.push("x.7z".into());
    args.push(".".into());
    parse_7z_add_args(&args).map(|a| a.options)
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

fn run_add(cl: &CommandLine, ui: &mut Ui<'_, '_>) -> i32 {
    // -an / -si never reach here (see `run_args`), so the name is present.
    let Some(archive) = cl.archive.as_deref() else {
        ui.err("missing archive name");
        return EXIT_CMDLINE;
    };
    let target = match add_target(archive, cl.archive_type) {
        Ok(t) => t,
        Err(AddTargetError::UnknownName) => {
            ui.err("cannot infer archive format from name (use -t or .zip, .7z, .wim, .tar, .tar.gz, .tgz, .tar.xz, .tar.bz2, .gz, .bz2, .xz)");
            return EXIT_CMDLINE;
        }
        Err(AddTargetError::ReadOnlyType) => {
            ui.err("this archive type can be read but not created");
            return EXIT_CMDLINE;
        }
    };
    let sevenz = if target == AddTarget::SevenZ {
        match sevenz_options(cl) {
            Ok(o) => o,
            Err(m) => {
                ui.err(&m);
                return EXIT_CMDLINE;
            }
        }
    } else if let Some(m) = cl.methods.first() {
        ui.err(&format!("method switch applies to 7z archives only: {}", m.to_string_lossy()));
        return EXIT_CMDLINE;
    } else {
        SevenZWriteOptions::default()
    };
    if cl.to_stdout && ui.con.stdout_is_terminal {
        ui.err("refusing to write archive data to a terminal (-so)");
        return EXIT_CMDLINE;
    }
    let (specs, sel) = match build_selector(cl, ui) {
        Ok(s) => s,
        Err(c) => return c,
    };
    // 7-Zip would add `*` here; an explicit name is required so a forgotten
    // argument never archives the whole working directory.
    if specs.is_empty() {
        ui.err("missing file names (use * to add everything in the current directory)");
        return EXIT_CMDLINE;
    }
    let writes_file = !cl.to_stdout && cl.volumes.is_empty();
    if let Ok(m) = std::fs::symlink_metadata(archive) {
        if writes_file && m.is_dir() {
            ui.err("archive path is a directory");
            return EXIT_FATAL;
        }
        if writes_file && !cl.yes {
            ui.err("archive exists (use -y to overwrite; update is not supported)");
            return EXIT_FATAL;
        }
    }
    let exp = match expand_inputs(&specs, cl) {
        Ok(e) => e,
        Err(e) => {
            ui.err(collect_msg(e));
            return collect_code(e);
        }
    };
    let mut warned = false;
    for m in &exp.missing {
        ui.err(&format!("warning: {}: no such file or no match", m.to_string_lossy()));
        warned = true;
    }
    let g = match gather(cl, ui, &exp.inputs, &sel) {
        Ok(g) => g,
        Err(c) => return c,
    };
    warned |= g.warned;
    if g.entries.is_empty() {
        ui.err("warning: no files to add; archive not written");
        return EXIT_WARNING;
    }
    let level = cl.level.unwrap_or(5);
    let bytes = match build_archive(target, level, &sevenz, &g, ui) {
        Ok(b) => b,
        Err(c) => return c,
    };
    let mut where_ = String::new();
    if cl.to_stdout {
        let res = ui.con.stdout.write_all(&bytes).and_then(|_| ui.con.stdout.flush());
        match res {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return EXIT_WARNING,
            Err(_) => {
                ui.err("write error");
                return EXIT_FATAL;
            }
        }
    } else if !cl.volumes.is_empty() {
        match write_volumes(archive, &bytes, &cl.volumes, cl.yes) {
            Ok(n) => where_ = format!(" in {n} volumes"),
            Err(e) => {
                ui.err(volume_msg(e));
                return if e == VolumeError::Allocation { EXIT_MEMORY } else { EXIT_FATAL };
            }
        }
    } else if let Err(m) = write_atomically(archive, &bytes) {
        ui.err(&m);
        return EXIT_FATAL;
    }
    if cl.log_level >= 1 {
        for e in &g.entries {
            ui.out(&format!("+ {}\n", shown(&e.name)));
        }
    }
    if !cl.no_headers {
        let files = g.entries.iter().filter(|e| e.kind == FsKind::File).count();
        ui.out(&format!(
            "Created {}{where_} ({} entries, {} files, {} bytes in, {} bytes out)\n",
            archive.display(),
            g.entries.len(),
            files,
            g.total_bytes,
            bytes.len()
        ));
    }
    if cl.delete_after && !delete_sources(&g.entries, ui) {
        warned = true;
    }
    if warned { EXIT_WARNING } else { EXIT_OK }
}
