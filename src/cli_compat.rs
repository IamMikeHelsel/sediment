// SPDX-License-Identifier: MIT OR Apache-2.0
//! 7-Zip compatible command-line parsing for the `l`, `t`, `x`, `e` and `a`
//! commands (the frozen `list`/`test` commands keep their own parser).
//!
//! Spec source: the public 7-Zip command-line documentation (switch syntax,
//! wildcard and `@listfile` rules, exit codes). Written from that
//! description; no 7-Zip source code was consulted.
//!
//! Syntax: `sediment <command> [<switches>...] <archive> [<names>...]`.
//! Switches may appear anywhere until `--`; switch names are
//! case-insensitive, their values are not. Supported switches:
//!
//! | switch | meaning |
//! |---|---|
//! | `-r`, `-r-`, `-r0` | recurse names: always / never (default) / wildcard names only |
//! | `-i[r[-\|0]]{!wildcard\|@listfile}` | include names (repeatable) |
//! | `-x[r[-\|0]]{!wildcard\|@listfile}` | exclude names (repeatable) |
//! | `-t{zip\|7z\|tar\|gzip\|gz\|bzip2\|bz2\|xz}` | archive type |
//! | `-o{dir}` | output directory (`x`, `e`) |
//! | `-y` | assume Yes (overwrite on extract, replace archive on add) |
//! | `-ao{a\|s\|t\|u}` | overwrite all / skip / rename existing / rename new |
//! | `-bb[0-3]` | output log level (`-bb` = 1) |
//! | `-ba` | suppress headers and footers |
//! | `-slt` | technical listing (`l`) |
//! | `-scs{UTF-8\|UTF-16LE\|UTF-16BE}` | charset of `@listfile`s |
//! | `-spf`, `-spf2` | fully qualified paths |
//! | `-sdel` | delete files after adding them (`a`) |
//! | `-bso{0\|1\|2}`, `-bse{..}`, `-bsp{..}` | route output / error / progress stream: off, stdout, stderr |
//! | `-ssc`, `-ssc-` | case-sensitive / insensitive wildcards |
//! | `-snl` | create symbolic links on extract |
//! | `-mx{0-9}`, `-mx={0-9}` | compression level (`a`) |
//! | `-l` | follow symlinks on add |
//! | `-si[NAME]` | read the archive (`l`/`t`/`x`/`e`) or the data to add (`a`) from standard input |
//! | `-so` | write extracted data (`x`/`e`) or the archive (`a`) to standard output |
//! | `-an` | no archive name (`a -si -so`) |
//! | `-v{size}[b\|k\|m\|g]` | create volumes (`a`, repeatable) |
//! | `-m{...}` | method switches, passed to the 7z writer (`a` to `.7z`) |
//! | `--` | end of switches |
//!
//! Names starting with `@` are list files. Exit codes are the 7-Zip ones
//! ([`EXIT_OK`] .. [`EXIT_USER_STOP`]).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::volume_io::parse_size;

/// No error.
pub const EXIT_OK: i32 = 0;
/// Warning (non-fatal errors, e.g. some files skipped).
pub const EXIT_WARNING: i32 = 1;
/// Fatal error.
pub const EXIT_FATAL: i32 = 2;
/// Command line error.
pub const EXIT_CMDLINE: i32 = 7;
/// Not enough memory for the operation.
pub const EXIT_MEMORY: i32 = 8;
/// User stopped the process.
pub const EXIT_USER_STOP: i32 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `l`
    List,
    /// `t`
    Test,
    /// `x` (full paths)
    Extract,
    /// `e` (no directory structure)
    ExtractFlat,
    /// `a`
    Add,
}

impl Command {
    /// Command letter, case-insensitive like 7-Zip.
    pub fn from_name(name: &OsStr) -> Option<Command> {
        match name.as_encoded_bytes() {
            b"l" | b"L" => Some(Command::List),
            b"t" | b"T" => Some(Command::Test),
            b"x" | b"X" => Some(Command::Extract),
            b"e" | b"E" => Some(Command::ExtractFlat),
            b"a" | b"A" => Some(Command::Add),
            _ => None,
        }
    }
}

/// Recursion type (`-r`, `-r-`, `-r0`, or the `r` modifier of `-i`/`-x`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recurse {
    /// `-r-`: names match from the archive root / given directory only.
    Off,
    /// `-r`: names match at any depth.
    On,
    /// `-r0`: only names containing wildcards match at any depth.
    WildcardOnly,
}

impl Recurse {
    /// Whether `name` is matched recursively under this mode.
    pub fn applies_to(self, name: &str) -> bool {
        match self {
            Recurse::Off => false,
            Recurse::On => true,
            Recurse::WildcardOnly => has_wildcard(name),
        }
    }
}

/// True when `s` contains `*` or `?`.
pub fn has_wildcard(s: &str) -> bool {
    s.contains(['*', '?'])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    Zip,
    SevenZ,
    Tar,
    Gzip,
    Bzip2,
    Xz,
}

impl ArchiveType {
    /// `-t` value (case-insensitive) to type.
    pub fn from_name(name: &str) -> Option<ArchiveType> {
        let table: [(&str, ArchiveType); 8] = [
            ("zip", ArchiveType::Zip),
            ("7z", ArchiveType::SevenZ),
            ("tar", ArchiveType::Tar),
            ("gzip", ArchiveType::Gzip),
            ("gz", ArchiveType::Gzip),
            ("bzip2", ArchiveType::Bzip2),
            ("bz2", ArchiveType::Bzip2),
            ("xz", ArchiveType::Xz),
        ];
        table.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|&(_, t)| t)
    }

    /// Name as shown in `Type = ...` of a technical listing.
    pub fn name(self) -> &'static str {
        match self {
            ArchiveType::Zip => "zip",
            ArchiveType::SevenZ => "7z",
            ArchiveType::Tar => "tar",
            ArchiveType::Gzip => "gzip",
            ArchiveType::Bzip2 => "bzip2",
            ArchiveType::Xz => "xz",
        }
    }
}

/// `-ao` modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwriteMode {
    /// `-aoa`
    All,
    /// `-aos`
    Skip,
    /// `-aot`: rename the existing file, then extract.
    RenameExisting,
    /// `-aou`: extract under a new name.
    RenameNew,
}

/// Destination of an output stream (`-bso`, `-bse`, `-bsp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTarget {
    Off,
    Stdout,
    Stderr,
}

/// `-scs` charset of list files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// A name argument: a path / wildcard or an `@listfile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameItem {
    Wildcard(OsString),
    ListFile(PathBuf),
}

/// An `-i` / `-x` item with its own recursion override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRule {
    pub item: NameItem,
    /// `None`: use the global `-r` setting.
    pub recurse: Option<Recurse>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    pub command: Command,
    /// `None` only with `-si` (`l`/`t`/`x`/`e`) or `-an`.
    pub archive: Option<PathBuf>,
    /// Names after the archive (wildcards or list files).
    pub names: Vec<NameItem>,
    pub includes: Vec<NameRule>,
    pub excludes: Vec<NameRule>,
    /// Global `-r` (None = not given; treated as [`Recurse::Off`]).
    pub recurse: Option<Recurse>,
    pub archive_type: Option<ArchiveType>,
    pub output_dir: Option<PathBuf>,
    pub yes: bool,
    pub overwrite: Option<OverwriteMode>,
    /// `-bb` level 0..=3.
    pub log_level: u8,
    /// `-ba`
    pub no_headers: bool,
    /// `-slt`
    pub technical: bool,
    pub charset: Charset,
    /// `-spf` / `-spf2`
    pub full_paths: bool,
    /// `-sdel`
    pub delete_after: bool,
    pub stdout_to: StreamTarget,
    pub stderr_to: StreamTarget,
    pub progress_to: StreamTarget,
    /// `-ssc` / `-ssc-`; None = platform default.
    pub case_sensitive: Option<bool>,
    /// `-snl`
    pub symlinks: bool,
    /// `-mx`
    pub level: Option<u8>,
    /// `-l`
    pub follow_symlinks: bool,
    /// `-si[NAME]`: `Some(NAME)` (possibly empty).
    pub stdin: Option<OsString>,
    /// `-so`
    pub to_stdout: bool,
    /// `-an`
    pub no_archive_name: bool,
    /// `-v` volume sizes in bytes (the last repeats).
    pub volumes: Vec<u64>,
    /// Other `-m` switches, verbatim (for the 7z writer).
    pub methods: Vec<OsString>,
}

impl CommandLine {
    fn new(command: Command) -> CommandLine {
        CommandLine {
            command,
            archive: None,
            names: Vec::new(),
            includes: Vec::new(),
            excludes: Vec::new(),
            recurse: None,
            archive_type: None,
            output_dir: None,
            yes: false,
            overwrite: None,
            log_level: 0,
            no_headers: false,
            technical: false,
            charset: Charset::Utf8,
            full_paths: false,
            delete_after: false,
            stdout_to: StreamTarget::Stdout,
            stderr_to: StreamTarget::Stderr,
            progress_to: StreamTarget::Stdout,
            case_sensitive: None,
            symlinks: false,
            level: None,
            follow_symlinks: false,
            stdin: None,
            to_stdout: false,
            no_archive_name: false,
            volumes: Vec::new(),
            methods: Vec::new(),
        }
    }

    /// Effective wildcard case sensitivity (`-ssc`; default: case-sensitive
    /// except on Windows).
    pub fn wildcard_case_sensitive(&self) -> bool {
        self.case_sensitive.unwrap_or(!cfg!(windows))
    }
}

/// Command line error (exit code [`EXIT_CMDLINE`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdLineError {
    pub message: String,
}

fn bad(message: impl Into<String>) -> CmdLineError {
    CmdLineError { message: message.into() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sw {
    Overwrite,
    NoHeaders,
    LogLevel,
    StderrTo,
    StdoutTo,
    ProgressTo,
    Include,
    Exclude,
    Follow,
    Level,
    Output,
    Recurse,
    Charset,
    Delete,
    Technical,
    Symlinks,
    FullPaths,
    CaseSensitive,
    Type,
    Yes,
    StdIn,
    StdOut,
    NoArchiveName,
    Volume,
    Method,
}

/// Switch table: name (lower case) and id. The longest matching name wins.
const SWITCHES: [(&str, Sw); 25] = [
    ("an", Sw::NoArchiveName),
    ("ao", Sw::Overwrite),
    ("ba", Sw::NoHeaders),
    ("bb", Sw::LogLevel),
    ("bse", Sw::StderrTo),
    ("bso", Sw::StdoutTo),
    ("bsp", Sw::ProgressTo),
    ("i", Sw::Include),
    ("x", Sw::Exclude),
    ("l", Sw::Follow),
    ("m", Sw::Method),
    ("mx", Sw::Level),
    ("o", Sw::Output),
    ("r", Sw::Recurse),
    ("scs", Sw::Charset),
    ("sdel", Sw::Delete),
    ("si", Sw::StdIn),
    ("slt", Sw::Technical),
    ("snl", Sw::Symlinks),
    ("so", Sw::StdOut),
    ("spf", Sw::FullPaths),
    ("ssc", Sw::CaseSensitive),
    ("t", Sw::Type),
    ("v", Sw::Volume),
    ("y", Sw::Yes),
];

fn lookup(body: &[u8]) -> Option<(Sw, usize)> {
    SWITCHES
        .iter()
        .filter(|(n, _)| body.len() >= n.len() && body[..n.len()].eq_ignore_ascii_case(n.as_bytes()))
        .max_by_key(|(n, _)| n.len())
        .map(|&(n, id)| (id, n.len()))
}

/// Bytes after `skip` as an OS string (switch values may be paths).
#[cfg(unix)]
fn os_tail(arg: &OsStr, skip: usize) -> Option<OsString> {
    use std::os::unix::ffi::OsStrExt;
    arg.as_bytes().get(skip..).map(|b| OsStr::from_bytes(b).to_os_string())
}

#[cfg(not(unix))]
fn os_tail(arg: &OsStr, skip: usize) -> Option<OsString> {
    arg.to_str().and_then(|s| s.get(skip..)).map(OsString::from)
}

fn no_param(param: &[u8], shown: &str) -> Result<(), CmdLineError> {
    if param.is_empty() { Ok(()) } else { Err(bad(format!("unsupported switch: {shown}"))) }
}

fn stream_target(param: &[u8], shown: &str) -> Result<StreamTarget, CmdLineError> {
    match param {
        b"0" => Ok(StreamTarget::Off),
        b"1" => Ok(StreamTarget::Stdout),
        b"2" => Ok(StreamTarget::Stderr),
        _ => Err(bad(format!("invalid stream switch: {shown}"))),
    }
}

/// `r`, `r-`, `r0` prefix of `-i`/`-x`; returns the override and the rest.
fn rule_recurse(param: &[u8]) -> (Option<Recurse>, &[u8]) {
    match param {
        [b'r' | b'R', b'-', rest @ ..] => (Some(Recurse::Off), rest),
        [b'r' | b'R', b'0', rest @ ..] => (Some(Recurse::WildcardOnly), rest),
        [b'r' | b'R', rest @ ..] => (Some(Recurse::On), rest),
        _ => (None, param),
    }
}

fn name_rule(arg: &OsStr, start: usize, shown: &str) -> Result<NameRule, CmdLineError> {
    let bytes = arg.as_encoded_bytes();
    let (recurse, rest) = rule_recurse(&bytes[start..]);
    let consumed = bytes.len() - rest.len();
    let value = || os_tail(arg, consumed + 1).filter(|v| !v.is_empty());
    let item = match rest.first() {
        Some(b'!') => NameItem::Wildcard(value().ok_or_else(|| bad(format!("empty wildcard: {shown}")))?),
        Some(b'@') => NameItem::ListFile(PathBuf::from(value().ok_or_else(|| bad(format!("empty list file name: {shown}")))?)),
        _ => return Err(bad(format!("incorrect wildcard type marker: {shown}"))),
    };
    Ok(NameRule { item, recurse })
}

fn positional_name(arg: OsString) -> NameItem {
    let bytes = arg.as_encoded_bytes();
    if bytes.len() > 1
        && bytes[0] == b'@'
        && let Some(rest) = os_tail(&arg, 1)
    {
        return NameItem::ListFile(PathBuf::from(rest));
    }
    NameItem::Wildcard(arg)
}

fn apply_switch(cl: &mut CommandLine, arg: &OsStr) -> Result<(), CmdLineError> {
    let bytes = arg.as_encoded_bytes();
    let shown = arg.to_string_lossy().into_owned();
    let body = &bytes[1..];
    let (id, len) = lookup(body).ok_or_else(|| bad(format!("unknown switch: {shown}")))?;
    let param = &body[len..];
    let value_start = 1 + len;
    match id {
        Sw::Overwrite => {
            cl.overwrite = Some(match param {
                b"a" | b"A" => OverwriteMode::All,
                b"s" | b"S" => OverwriteMode::Skip,
                b"t" | b"T" => OverwriteMode::RenameExisting,
                b"u" | b"U" => OverwriteMode::RenameNew,
                _ => return Err(bad(format!("invalid overwrite mode: {shown}"))),
            })
        }
        Sw::NoHeaders => {
            no_param(param, &shown)?;
            cl.no_headers = true;
        }
        Sw::LogLevel => {
            cl.log_level = match param {
                b"" => 1,
                [d @ b'0'..=b'3'] => d - b'0',
                _ => return Err(bad(format!("invalid log level: {shown}"))),
            }
        }
        Sw::StderrTo => cl.stderr_to = stream_target(param, &shown)?,
        Sw::StdoutTo => cl.stdout_to = stream_target(param, &shown)?,
        Sw::ProgressTo => cl.progress_to = stream_target(param, &shown)?,
        Sw::Include => cl.includes.push(name_rule(arg, value_start, &shown)?),
        Sw::Exclude => cl.excludes.push(name_rule(arg, value_start, &shown)?),
        Sw::Follow => {
            no_param(param, &shown)?;
            cl.follow_symlinks = true;
        }
        Sw::Level => {
            let p = param.strip_prefix(b"=").unwrap_or(param);
            cl.level = match p {
                [d @ b'0'..=b'9'] => Some(d - b'0'),
                _ => return Err(bad(format!("invalid compression level switch: {shown}"))),
            }
        }
        Sw::Output => {
            let dir = os_tail(arg, value_start).filter(|d| !d.is_empty());
            cl.output_dir = Some(PathBuf::from(dir.ok_or_else(|| bad("missing output directory"))?));
        }
        Sw::Recurse => {
            cl.recurse = Some(match param {
                b"" => Recurse::On,
                b"-" => Recurse::Off,
                b"0" => Recurse::WildcardOnly,
                _ => return Err(bad(format!("invalid recurse switch: {shown}"))),
            })
        }
        Sw::Charset => {
            let v = String::from_utf8_lossy(param).to_ascii_uppercase();
            cl.charset = match v.as_str() {
                "UTF-8" | "UTF8" => Charset::Utf8,
                "UTF-16LE" | "UTF16LE" => Charset::Utf16Le,
                "UTF-16BE" | "UTF16BE" => Charset::Utf16Be,
                "" => return Err(bad("missing charset")),
                _ => return Err(bad(format!("unsupported charset: {shown}"))),
            }
        }
        Sw::Delete => {
            no_param(param, &shown)?;
            cl.delete_after = true;
        }
        Sw::Technical => {
            no_param(param, &shown)?;
            cl.technical = true;
        }
        Sw::Symlinks => {
            no_param(param, &shown)?;
            cl.symlinks = true;
        }
        Sw::FullPaths => match param {
            b"" | b"2" => cl.full_paths = true,
            _ => return Err(bad(format!("unsupported switch: {shown}"))),
        },
        Sw::CaseSensitive => {
            cl.case_sensitive = Some(match param {
                b"" => true,
                b"-" => false,
                _ => return Err(bad(format!("unsupported switch: {shown}"))),
            })
        }
        Sw::Type => {
            let v = String::from_utf8_lossy(param);
            if v.is_empty() {
                return Err(bad("missing archive type"));
            }
            cl.archive_type = Some(ArchiveType::from_name(&v).ok_or_else(|| bad(format!("unsupported archive type: {v}")))?);
        }
        Sw::Yes => {
            no_param(param, &shown)?;
            cl.yes = true;
        }
        Sw::StdIn => {
            if cl.stdin.is_some() {
                return Err(bad("-si given twice"));
            }
            let name = os_tail(arg, value_start).ok_or_else(|| bad(format!("invalid -si name: {shown}")))?;
            if name.as_encoded_bytes().contains(&0) || name.len() > 4096 {
                return Err(bad(format!("invalid -si name: {shown}")));
            }
            cl.stdin = Some(name);
        }
        Sw::StdOut => {
            no_param(param, &shown)?;
            cl.to_stdout = true;
        }
        Sw::NoArchiveName => {
            no_param(param, &shown)?;
            cl.no_archive_name = true;
        }
        Sw::Volume => cl.volumes.push(parse_size(param).map_err(|_| bad(format!("invalid volume size: {shown}")))?),
        Sw::Method => {
            if param.is_empty() {
                return Err(bad(format!("unsupported switch: {shown}")));
            }
            cl.methods.push(arg.to_os_string());
        }
    }
    Ok(())
}

/// Parse the arguments that follow a 7-Zip style command.
pub fn parse_command_line(command: Command, args: &[OsString]) -> Result<CommandLine, CmdLineError> {
    let mut cl = CommandLine::new(command);
    let mut positional: Vec<&OsString> = Vec::new();
    let mut switches = true;
    for a in args {
        let bytes = a.as_encoded_bytes();
        if switches && bytes == b"--" {
            switches = false;
            continue;
        }
        if switches && bytes.len() > 1 && bytes[0] == b'-' {
            apply_switch(&mut cl, a)?;
            continue;
        }
        positional.push(a);
    }
    // With -si (reading) or -an there is no archive name: every positional is a name.
    let nameless = cl.no_archive_name || (cl.stdin.is_some() && command != Command::Add);
    let mut rest = positional.into_iter();
    if !nameless {
        let a = rest.next().ok_or_else(|| bad("missing archive name"))?;
        if a.is_empty() {
            return Err(bad("empty archive name"));
        }
        cl.archive = Some(PathBuf::from(a));
    }
    for a in rest {
        if a.is_empty() {
            return Err(bad("empty file name"));
        }
        cl.names.push(positional_name(a.clone()));
    }
    if cl.to_stdout && !cl.volumes.is_empty() {
        return Err(bad("-so cannot be combined with -v"));
    }
    if cl.no_archive_name && !cl.to_stdout {
        return Err(bad("-an requires -so"));
    }
    Ok(cl)
}
