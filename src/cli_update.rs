// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command-line front ends for archive updates (7-Zip style names):
//!
//! * `sediment u [-mx0..9] [-l] ARCHIVE PATH...`: add files that are not in
//!   the archive and replace archived files that are older than the file on
//!   disk. Creates the archive (format from its name) when it is missing.
//!   `-l` follows symlinks.
//! * `sediment d [-r] [-mx0..9] ARCHIVE PATTERN...`: delete entries matching
//!   wildcard patterns (`*`, `?`); deleting a directory deletes its
//!   contents. `-r` lets a pattern without `/` match at any depth.
//! * `sediment rn [-mx0..9] ARCHIVE OLD NEW [OLD NEW...]`: rename entries;
//!   renaming a directory renames everything below it.
//!
//! Supported archives: ZIP, tar, tar.gz/tgz, tar.bz2/tbz2/tbz, tar.xz/txz
//! and 7z (see [`crate::archive_edit`]). `-mx` (default 5) only affects new
//! or re-encoded members and the re-compression of compressed tar.
//!
//! The new archive is written to a temporary sibling file, synced, given the
//! old file's permissions and renamed over the original (through a symlink
//! to the archive, the link target is replaced). When nothing changes the
//! archive is not rewritten.
//!
//! Tail switches ([`run_with_tail`]): `-w[{dir}]` writes the temporary
//! archive in `dir` (empty: the system temp directory) and moves it into
//! place, `-stl` sets the archive's mtime to its newest entry's, `-bt`
//! prints the elapsed time, `-ad`/`-bd`/`-ssw` are accepted. A malformed
//! tail switch is a usage error.
//!
//! Exit codes: 0 success, 1 fatal error (archive unchanged), 2 usage error,
//! 3 archive written but some inputs were skipped (warnings on stderr).

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::archive_edit::{EditSource, apply_plan, format_for_new, list_source, open_source};
use crate::archive_name::escape_name;
use crate::archive_update::{EditPlan, UpdateError, UpdateLimits, plan_delete, plan_rename, plan_update};
use crate::fs_collect::{CollectError, CollectLimits, CollectOptions, WarningKind, collect, read_entry_data};

const EXIT_FATAL: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_SKIPPED: i32 = 3;
/// Largest archive file read into memory.
const MAX_ARCHIVE: u64 = 1 << 30;

thread_local! {
    /// `-w` directory for [`replace_atomically`]'s temporary file.
    static WORK_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Switches handled around `u`/`d`/`rn` by [`run_with_tail`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EditTail {
    pub work_dir: Option<PathBuf>,
    pub stl: bool,
    pub timing: bool,
}

/// Remove the tail switches (`-w`, `-stl`, `-bt`, `-ad`, `-bd`, `-ssw`)
/// from `args`; the rest goes to the command's own parser.
pub fn take_edit_tail(args: &[OsString]) -> Result<(EditTail, Vec<OsString>), String> {
    let mut tail = EditTail::default();
    let mut rest = Vec::new();
    let mut switches = true;
    for a in args {
        let b = a.as_encoded_bytes();
        if switches && b == b"--" {
            switches = false;
        }
        if !switches || b.len() < 2 || b[0] != b'-' {
            rest.push(a.clone());
            continue;
        }
        let body = &b[1..];
        if body[0].eq_ignore_ascii_case(&b'w') {
            let dir = std::path::Path::new(a).to_string_lossy().into_owned();
            let dir = &dir[2..];
            tail.work_dir = Some(if dir.is_empty() { std::env::temp_dir() } else { PathBuf::from(dir) });
        } else if body.eq_ignore_ascii_case(b"stl") {
            tail.stl = true;
        } else if body.eq_ignore_ascii_case(b"bt") {
            tail.timing = true;
        } else if body.eq_ignore_ascii_case(b"ad") || body.eq_ignore_ascii_case(b"bd") || body.eq_ignore_ascii_case(b"ssw") {
        } else if [&b"stl"[..], b"bt", b"ad", b"bd", b"ssw"].iter().any(|p| body.len() > p.len() && body[..p.len()].eq_ignore_ascii_case(p)) {
            return Err(format!("unsupported switch: {}", a.to_string_lossy()));
        } else {
            rest.push(a.clone());
        }
    }
    Ok((tail, rest))
}

/// The archive operand of `u`/`d`/`rn` arguments (first positional).
fn archive_operand(args: &[OsString]) -> Option<PathBuf> {
    let mut switches = true;
    for a in args {
        let b = a.as_encoded_bytes();
        if switches && b == b"--" {
            switches = false;
            continue;
        }
        if switches && b.len() > 1 && b[0] == b'-' {
            continue;
        }
        return Some(PathBuf::from(a));
    }
    None
}

/// Run `u`/`d`/`rn` (`run`) with the tail switches of [`take_edit_tail`].
pub fn run_with_tail(args: &[OsString], run: fn(&[OsString]) -> i32) -> i32 {
    let started = std::time::Instant::now();
    let (tail, rest) = match take_edit_tail(args) {
        Ok(v) => v,
        Err(m) => return usage(&m, "see sediment u/d/rn"),
    };
    if let Some(d) = &tail.work_dir
        && !d.is_dir()
    {
        return fail(&format!("working directory not found: {}", d.display()));
    }
    WORK_DIR.with(|w| *w.borrow_mut() = tail.work_dir.clone());
    let mut code = run(&rest);
    WORK_DIR.with(|w| *w.borrow_mut() = None);
    if tail.stl
        && (code == 0 || code == EXIT_SKIPPED)
        && let Some(a) = archive_operand(&rest)
        && let Err(m) = crate::cli_run::apply_stl(&a, None)
    {
        code = fail(&m);
    }
    if tail.timing {
        let _ = write!(std::io::stdout().lock(), "{}", crate::cli_run::timing_report(started.elapsed()));
    }
    code
}

/// Human-readable message for an update error.
pub fn update_error_message(e: UpdateError) -> &'static str {
    match e {
        UpdateError::InvalidArchive => "archive is damaged or not in a supported format",
        UpdateError::Unsupported => "archive uses a feature that cannot be updated",
        UpdateError::InvalidName => "invalid entry name",
        UpdateError::NameCollision => "rename would create duplicate names",
        UpdateError::LimitExceeded => "archive exceeds limits",
        UpdateError::Allocation => "out of memory",
        UpdateError::EncodeFailed => "cannot encode new entries",
    }
}

/// Switches shared by the three commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditArgs {
    pub archive: PathBuf,
    pub operands: Vec<OsString>,
    pub level: u8,
    pub recursive: bool,
    pub follow_symlinks: bool,
}

/// Parse arguments after the command. `allowed` lists the accepted
/// single-letter switches besides `-mx`.
pub fn parse_edit_args(args: &[OsString], allowed: &[&str]) -> Result<EditArgs, String> {
    let mut level = 5u8;
    let mut recursive = false;
    let mut follow = false;
    let mut positional: Vec<OsString> = Vec::new();
    let mut switches = true;
    for a in args {
        let s = a.to_string_lossy();
        if switches && s == "--" {
            switches = false;
            continue;
        }
        if switches && s.starts_with('-') && s.len() > 1 {
            if let Some(rest) = s.strip_prefix("-mx") {
                let rest = rest.strip_prefix('=').unwrap_or(rest);
                match rest.parse::<u8>() {
                    Ok(n) if n <= 9 && rest.len() == 1 => level = n,
                    _ => return Err(format!("invalid compression level switch: {s}")),
                }
            } else {
                match &*s {
                    "-r" if allowed.contains(&"-r") => recursive = true,
                    "-l" if allowed.contains(&"-l") => follow = true,
                    _ => return Err(format!("unknown switch: {s}")),
                }
            }
            continue;
        }
        positional.push(a.clone());
    }
    if positional.is_empty() {
        return Err("missing archive name".into());
    }
    let archive = PathBuf::from(positional.remove(0));
    Ok(EditArgs { archive, operands: positional, level, recursive, follow_symlinks: follow })
}

fn read_file(p: &Path) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(p).map_err(|e| format!("cannot open {}: {e}", p.display()))?;
    let m = f.metadata().map_err(|e| format!("cannot read {}: {e}", p.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a regular file", p.display()));
    }
    if m.len() > MAX_ARCHIVE {
        return Err(format!("{} exceeds the size limit", p.display()));
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(m.len() as usize + 1).map_err(|_| "out of memory".to_string())?;
    f.take(MAX_ARCHIVE + 1).read_to_end(&mut buf).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
    if buf.len() as u64 > MAX_ARCHIVE {
        return Err(format!("{} exceeds the size limit", p.display()));
    }
    Ok(buf)
}

/// Write `bytes` to `path` via a synced temporary sibling and a rename.
/// Through a symlink, the link's target is replaced. Permissions of an
/// existing file are kept.
pub fn replace_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let target = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            std::fs::canonicalize(path).map_err(|e| format!("cannot resolve {}: {e}", path.display()))?
        }
        _ => path.to_path_buf(),
    };
    let perms = std::fs::metadata(&target).ok().map(|m| m.permissions());
    let mut tmp_name = target.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    tmp_name.push(format!(".sediment-tmp-{}", std::process::id()));
    let tmp = match WORK_DIR.with(|w| w.borrow().clone()) {
        Some(d) => d.join(&tmp_name),
        None => target.with_file_name(&tmp_name),
    };
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        if let Some(p) = &perms {
            f.set_permissions(p.clone())?;
        }
        f.sync_all()?;
        drop(f);
        crate::cli_run::move_into_place(&tmp, &target)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", target.display()));
    }
    Ok(())
}

fn fail(msg: &str) -> i32 {
    let _ = writeln!(std::io::stderr().lock(), "sediment: {msg}");
    EXIT_FATAL
}

fn usage(msg: &str, synopsis: &str) -> i32 {
    let _ = writeln!(std::io::stderr().lock(), "sediment: {msg}\nUsage: {synopsis}");
    EXIT_USAGE
}

fn show(name: &[u8]) -> String {
    escape_name(name).unwrap_or_else(|_| String::from("?"))
}

/// Load and list an existing archive.
fn load(path: &Path) -> Result<Vec<u8>, String> {
    read_file(path)
}

fn source<'a>(bytes: &'a [u8], limits: &UpdateLimits) -> Result<EditSource<'a>, String> {
    let max = usize::try_from(limits.max_total_bytes).unwrap_or(usize::MAX);
    open_source(bytes, max).map_err(|e| update_error_message(e).to_string())
}

fn commit(path: &Path, src: &EditSource<'_>, plan: &EditPlan<'_>, level: u8, limits: &UpdateLimits) -> Result<usize, String> {
    let r = apply_plan(src, plan, level, limits).map_err(|e| update_error_message(e).to_string())?;
    let mut err = std::io::stderr().lock();
    for s in &r.skipped {
        let _ = writeln!(err, "sediment: note: {}: symlink not stored in zip (use -l to store its target)", show(s));
    }
    replace_atomically(path, &r.bytes)?;
    Ok(r.skipped.len())
}

/// Run `sediment d`. `args` are the arguments after the command.
pub fn run_delete(args: &[OsString]) -> i32 {
    const SYN: &str = "sediment d [-r] [-mx0..9] ARCHIVE PATTERN...";
    let a = match parse_edit_args(args, &["-r"]) {
        Ok(a) => a,
        Err(m) => return usage(&m, SYN),
    };
    if a.operands.is_empty() {
        return usage("missing patterns", SYN);
    }
    let patterns: Vec<String> = a.operands.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    let pats: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let limits = UpdateLimits::default();
    let bytes = match load(&a.archive) {
        Ok(b) => b,
        Err(m) => return fail(&m),
    };
    let src = match source(&bytes, &limits) {
        Ok(s) => s,
        Err(m) => return fail(&m),
    };
    let existing = match list_source(&src, &limits) {
        Ok(e) => e,
        Err(e) => return fail(update_error_message(e)),
    };
    let plan = plan_delete(&existing, &pats, a.recursive);
    let n = plan.deleted();
    if n == 0 {
        let _ = writeln!(std::io::stdout().lock(), "No entries matched; {} unchanged", a.archive.display());
        return 0;
    }
    if let Err(m) = commit(&a.archive, &src, &plan, a.level, &limits) {
        return fail(&m);
    }
    let _ = writeln!(
        std::io::stdout().lock(),
        "Deleted {n} of {} entries from {}",
        existing.len(),
        a.archive.display()
    );
    0
}

/// Run `sediment rn`. `args` are the arguments after the command.
pub fn run_rename(args: &[OsString]) -> i32 {
    const SYN: &str = "sediment rn [-mx0..9] ARCHIVE OLD NEW [OLD NEW...]";
    let a = match parse_edit_args(args, &[]) {
        Ok(a) => a,
        Err(m) => return usage(&m, SYN),
    };
    if a.operands.is_empty() || a.operands.len() % 2 != 0 {
        return usage("rename needs OLD NEW pairs", SYN);
    }
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = a
        .operands
        .chunks(2)
        .map(|c| (c[0].as_encoded_bytes().to_vec(), c[1].as_encoded_bytes().to_vec()))
        .collect();
    let limits = UpdateLimits::default();
    let bytes = match load(&a.archive) {
        Ok(b) => b,
        Err(m) => return fail(&m),
    };
    let src = match source(&bytes, &limits) {
        Ok(s) => s,
        Err(m) => return fail(&m),
    };
    let existing = match list_source(&src, &limits) {
        Ok(e) => e,
        Err(e) => return fail(update_error_message(e)),
    };
    let rp = match plan_rename(&existing, &pairs) {
        Ok(r) => r,
        Err(e) => return fail(update_error_message(e)),
    };
    {
        let mut err = std::io::stderr().lock();
        for ((old, _), &m) in pairs.iter().zip(&rp.matches) {
            if m == 0 {
                let _ = writeln!(err, "sediment: warning: no entry named {}", show(old));
            }
        }
    }
    let n = rp.plan.renamed();
    if n == 0 {
        let _ = writeln!(std::io::stdout().lock(), "Nothing renamed; {} unchanged", a.archive.display());
        return if rp.matches.iter().all(|&m| m == 0) { EXIT_FATAL } else { 0 };
    }
    if let Err(m) = commit(&a.archive, &src, &rp.plan, a.level, &limits) {
        return fail(&m);
    }
    let _ = writeln!(std::io::stdout().lock(), "Renamed {n} entries in {}", a.archive.display());
    0
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

fn warn_msg(k: WarningKind) -> &'static str {
    match k {
        WarningKind::UnreadableDirectory => "cannot list directory; contents skipped",
        WarningKind::UnreadableFile => "cannot read; skipped",
        WarningKind::SpecialFile => "special file; skipped",
        WarningKind::SymlinkLoop => "symlink loop; skipped",
        WarningKind::ExcludedOutput => "is the archive itself; skipped",
    }
}

/// Run `sediment u`. `args` are the arguments after the command.
pub fn run_update(args: &[OsString]) -> i32 {
    const SYN: &str = "sediment u [-mx0..9] [-l] ARCHIVE PATH...";
    let a = match parse_edit_args(args, &["-l"]) {
        Ok(a) => a,
        Err(m) => return usage(&m, SYN),
    };
    if a.operands.is_empty() {
        return usage("missing input paths", SYN);
    }
    let limits = UpdateLimits::default();
    let exists = std::fs::symlink_metadata(&a.archive).is_ok();
    let bytes = if exists {
        match load(&a.archive) {
            Ok(b) => b,
            Err(m) => return fail(&m),
        }
    } else {
        Vec::new()
    };
    let src = if exists {
        match source(&bytes, &limits) {
            Ok(s) => s,
            Err(m) => return fail(&m),
        }
    } else {
        match format_for_new(&a.archive) {
            Some(f) => EditSource { format: f, data: std::borrow::Cow::Borrowed(&[]) },
            None => {
                return usage(
                    "cannot infer archive format from name (use .zip, .7z, .tar, .tar.gz/.tgz, .tar.xz/.txz, .tar.bz2/.tbz2)",
                    SYN,
                );
            }
        }
    };
    let existing = match list_source(&src, &limits) {
        Ok(e) => e,
        Err(e) => return fail(update_error_message(e)),
    };

    let inputs: Vec<PathBuf> = a.operands.iter().map(PathBuf::from).collect();
    let options = CollectOptions { follow_symlinks: a.follow_symlinks, strict: false, exclude: vec![a.archive.clone()] };
    let climits = CollectLimits::default();
    let collected = match collect(&inputs, &options, climits) {
        Ok(c) => c,
        Err(e) => return fail(collect_msg(e)),
    };
    let mut warned = false;
    {
        let mut err = std::io::stderr().lock();
        for w in &collected.warnings {
            let _ = writeln!(err, "sediment: warning: {}: {}", w.path.display(), warn_msg(w.kind));
            if w.kind != WarningKind::ExcludedOutput {
                warned = true;
            }
        }
    }
    // Plan on metadata first, then read only the files that are needed.
    let meta: Vec<_> = collected.entries.iter().map(|e| e.as_archive_entry(&[])).collect();
    let (meta_plan, _) = match plan_update(&existing, &meta) {
        Ok(p) => p,
        Err(e) => return fail(update_error_message(e)),
    };
    let mut needed: Vec<&[u8]> = meta_plan
        .actions
        .iter()
        .filter_map(|x| match x {
            crate::archive_update::EntryAction::Replace(e) => Some(e.name),
            _ => None,
        })
        .chain(meta_plan.additions.iter().map(|e| e.name))
        .collect();
    needed.sort_unstable();
    let mut datas: Vec<Vec<u8>> = Vec::new();
    for e in &collected.entries {
        if needed.binary_search(&e.name.as_slice()).is_ok() {
            match read_entry_data(e, climits.max_total_bytes) {
                Ok(d) => datas.push(d),
                Err(x) => return fail(&format!("{}: {}", e.source.display(), collect_msg(x))),
            }
        } else {
            datas.push(Vec::new());
        }
    }
    drop(meta_plan);
    let entries: Vec<_> = collected.entries.iter().zip(&datas).map(|(e, d)| e.as_archive_entry(d)).collect();
    let (plan, summary) = match plan_update(&existing, &entries) {
        Ok(p) => p,
        Err(e) => return fail(update_error_message(e)),
    };
    let mut out = std::io::stdout().lock();
    if plan.is_noop() && exists {
        let _ = writeln!(out, "{} is up to date ({} unchanged)", a.archive.display(), summary.unchanged);
        return if warned { EXIT_SKIPPED } else { 0 };
    }
    if !exists && plan.is_noop() {
        return fail("nothing to add");
    }
    if let Err(m) = commit(&a.archive, &src, &plan, a.level, &limits) {
        return fail(&m);
    }
    let _ = writeln!(
        out,
        "Updated {}: {} added, {} replaced, {} unchanged",
        a.archive.display(),
        summary.added,
        summary.replaced,
        summary.unchanged
    );
    if warned { EXIT_SKIPPED } else { 0 }
}
