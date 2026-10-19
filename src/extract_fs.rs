// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execute an [`extract_plan::Plan`](crate::extract_plan::Plan) into a
//! destination directory with `std::fs` only.
//!
//! Guarantees:
//! - Every path is built component by component under `dest`; each existing
//!   component is inspected with `symlink_metadata` and a pre-existing
//!   symlink anywhere below `dest` is refused (never followed).
//! - Regular files are written to a fresh temp file (`create_new`, which
//!   never follows a symlink) in the target directory, then `rename`d into
//!   place, so a partially written file is never visible under its name and
//!   a symlink sitting at the final name is replaced, not followed.
//! - Unix permission bits are applied masked to `0o777` (no setuid, setgid
//!   or sticky). Directory modes and mtimes are applied last, deepest first.
//! - Symlinks are refused unless [`SymlinkPolicy::Create`] is chosen.
//! - Hardlinks are materialized as copies of their source member's data.
//!
//! Limitation: checks and writes are not atomic with respect to other
//! processes concurrently modifying the destination (no `openat` in std).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive_reader::{ArchiveReader, ReaderError};
use crate::extract_plan::{Plan, PlanItem, PlanKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePolicy {
    /// Fail when the target exists (default; non-interactive "ask").
    Error,
    /// Keep the existing file (`-aos`).
    Skip,
    /// Replace the existing file (`-aoa`, `-y`).
    Overwrite,
    /// Write as `name_1.ext`, `name_2.ext`, ... (`-aou`).
    Rename,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    /// Fail before writing anything if the plan contains a symlink.
    Refuse,
    /// Leave symlinks out and count them in the report.
    Skip,
    /// Create them (Unix only; elsewhere they are reported as skipped).
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractOptions {
    pub overwrite: OverwritePolicy,
    pub symlinks: SymlinkPolicy,
    pub apply_mtime: bool,
    pub apply_mode: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions {
            overwrite: OverwritePolicy::Error,
            symlinks: SymlinkPolicy::Refuse,
            apply_mtime: true,
            apply_mode: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractError {
    Io,
    DestinationNotDir,
    SymlinkInDestination,
    PathConflict,
    Exists,
    SymlinksNotAllowed,
    SizeMismatch,
    InvalidName,
    Source(ReaderError),
    Allocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractFailure {
    /// Input entry index (see `PlanItem::index`) when an entry is at fault.
    pub index: Option<usize>,
    pub error: ExtractError,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractReport {
    pub files: usize,
    pub dirs: usize,
    pub symlinks: usize,
    pub bytes: u64,
    /// Entry indices skipped because the target existed (`Skip` policy).
    pub skipped_existing: Vec<usize>,
    /// Entry indices of symlinks left out (`Skip` policy / unsupported OS).
    pub skipped_symlinks: Vec<usize>,
    /// (entry index, path actually written) for `Rename` policy.
    pub renamed: Vec<(usize, PathBuf)>,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn io_fail(index: Option<usize>) -> impl Fn(std::io::Error) -> ExtractFailure {
    move |_| ExtractFailure { index, error: ExtractError::Io }
}

#[cfg(unix)]
fn component_os(c: &[u8]) -> Result<&std::ffi::OsStr, ExtractError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(std::ffi::OsStr::from_bytes(c))
}

#[cfg(not(unix))]
fn component_os(c: &[u8]) -> Result<&std::ffi::OsStr, ExtractError> {
    std::str::from_utf8(c).map(std::ffi::OsStr::new).map_err(|_| ExtractError::InvalidName)
}

/// Ensure the parent directories of `components` exist under `dest`
/// without following any symlink. Returns the parent path.
fn ensure_parents(
    dest: &Path,
    components: &[Vec<u8>],
    report: &mut ExtractReport,
) -> Result<PathBuf, ExtractError> {
    let mut cur = dest.to_path_buf();
    for c in &components[..components.len() - 1] {
        cur.push(component_os(c)?);
        ensure_dir(&cur, report)?;
    }
    Ok(cur)
}

fn ensure_dir(p: &Path, report: &mut ExtractReport) -> Result<(), ExtractError> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => Err(ExtractError::SymlinkInDestination),
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(ExtractError::PathConflict),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(p).map_err(|_| ExtractError::Io)?;
            report.dirs += 1;
            Ok(())
        }
        Err(_) => Err(ExtractError::Io),
    }
}

fn to_system_time(secs: i64) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

#[cfg(unix)]
fn set_mode(f: &File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(fs::Permissions::from_mode(mode & 0o777))
}

#[cfg(not(unix))]
fn set_mode(_f: &File, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn temp_path(dir: &Path) -> PathBuf {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".sediment-tmp-{}-{n}", std::process::id()))
}

/// Pick `stem_N.ext` that does not exist (checked without following links).
fn rename_target(dir: &Path, name: &[u8]) -> Result<PathBuf, ExtractError> {
    let dot = name.iter().rposition(|&b| b == b'.').filter(|&p| p > 0);
    let (stem, ext) = match dot {
        Some(p) => (&name[..p], &name[p..]),
        None => (name, &b""[..]),
    };
    for n in 1..10_000u32 {
        let mut candidate = Vec::new();
        candidate.extend_from_slice(stem);
        candidate.extend_from_slice(format!("_{n}").as_bytes());
        candidate.extend_from_slice(ext);
        let p = dir.join(component_os(&candidate)?);
        match fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(p),
            Err(_) => return Err(ExtractError::Io),
            Ok(_) => {}
        }
    }
    Err(ExtractError::Exists)
}

enum Slot {
    Write(PathBuf),
    Renamed(PathBuf),
    Skip,
}

/// Decide where a non-directory item goes given what is already there.
fn resolve_slot(dir: &Path, name: &[u8], policy: OverwritePolicy) -> Result<Slot, ExtractError> {
    let target = dir.join(component_os(name)?);
    match fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Slot::Write(target)),
        Err(_) => Err(ExtractError::Io),
        Ok(m) if m.is_dir() => Err(ExtractError::PathConflict),
        Ok(_) => match policy {
            OverwritePolicy::Error => Err(ExtractError::Exists),
            OverwritePolicy::Skip => Ok(Slot::Skip),
            // rename() replaces a file or a symlink itself; it never
            // writes through the link.
            OverwritePolicy::Overwrite => Ok(Slot::Write(target)),
            OverwritePolicy::Rename => Ok(Slot::Renamed(rename_target(dir, name)?)),
        },
    }
}

fn write_atomic(dir: &Path, final_path: &Path, data: &[u8], item: &PlanItem, opts: &ExtractOptions) -> Result<(), ExtractError> {
    let tmp = temp_path(dir);
    let result = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(data)?;
        if opts.apply_mode
            && let Some(mode) = item.mode {
                set_mode(&f, mode)?;
            }
        if opts.apply_mtime
            && let Some(t) = item.mtime.and_then(to_system_time) {
                f.set_modified(t)?;
            }
        drop(f);
        fs::rename(&tmp, final_path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(ExtractError::Io);
    }
    Ok(())
}

#[cfg(unix)]
fn make_symlink(dir: &Path, final_path: &Path, target: &[u8]) -> Result<bool, ExtractError> {
    use std::os::unix::ffi::OsStrExt;
    let tmp = temp_path(dir);
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(target), &tmp).map_err(|_| ExtractError::Io)?;
    if fs::rename(&tmp, final_path).is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(ExtractError::Io);
    }
    Ok(true)
}

#[cfg(not(unix))]
fn make_symlink(_dir: &Path, _final_path: &Path, _target: &[u8]) -> Result<bool, ExtractError> {
    Ok(false)
}

/// Write `plan` under `dest`, pulling data from `reader`.
pub fn execute_plan(
    plan: &Plan,
    reader: &dyn ArchiveReader,
    dest: &Path,
    opts: &ExtractOptions,
) -> Result<ExtractReport, ExtractFailure> {
    let whole = |error| ExtractFailure { index: None, error };
    if opts.symlinks == SymlinkPolicy::Refuse
        && let Some(it) = plan.items.iter().find(|it| matches!(it.kind, PlanKind::Symlink { .. })) {
            return Err(ExtractFailure { index: Some(it.index), error: ExtractError::SymlinksNotAllowed });
        }
    match fs::metadata(dest) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(whole(ExtractError::DestinationNotDir)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dest).map_err(io_fail(None))?;
        }
        Err(_) => return Err(whole(ExtractError::Io)),
    }

    let mut report = ExtractReport::default();
    // Explicit directory entries: (path, depth, item) for final metadata.
    let mut dir_meta: Vec<(PathBuf, usize, &PlanItem)> = Vec::new();

    for item in &plan.items {
        let at = |error| ExtractFailure { index: Some(item.index), error };
        let parent = ensure_parents(dest, &item.components, &mut report).map_err(at)?;
        let name = &item.components[item.components.len() - 1];
        match &item.kind {
            PlanKind::Dir => {
                let p = parent.join(component_os(name).map_err(at)?);
                ensure_dir(&p, &mut report).map_err(at)?;
                dir_meta.push((p, item.components.len(), item));
            }
            PlanKind::File | PlanKind::Hardlink { .. } => {
                let src = match item.kind {
                    PlanKind::Hardlink { source } => source,
                    _ => item.index,
                };
                let slot = resolve_slot(&parent, name, opts.overwrite).map_err(at)?;
                let path = match slot {
                    Slot::Skip => {
                        report.skipped_existing.push(item.index);
                        continue;
                    }
                    Slot::Write(p) => p,
                    Slot::Renamed(p) => {
                        report.renamed.push((item.index, p.clone()));
                        p
                    }
                };
                let data = reader.read(src).map_err(|e| at(ExtractError::Source(e)))?;
                if data.len() as u64 != item.size {
                    return Err(at(ExtractError::SizeMismatch));
                }
                write_atomic(&parent, &path, &data, item, opts).map_err(at)?;
                report.files += 1;
                report.bytes = report.bytes.saturating_add(item.size);
            }
            PlanKind::Symlink { target } => {
                if opts.symlinks != SymlinkPolicy::Create {
                    report.skipped_symlinks.push(item.index);
                    continue;
                }
                let path = match resolve_slot(&parent, name, opts.overwrite).map_err(at)? {
                    Slot::Skip => {
                        report.skipped_existing.push(item.index);
                        continue;
                    }
                    Slot::Write(p) => p,
                    Slot::Renamed(p) => {
                        report.renamed.push((item.index, p.clone()));
                        p
                    }
                };
                if make_symlink(&parent, &path, target).map_err(at)? {
                    report.symlinks += 1;
                } else {
                    report.skipped_symlinks.push(item.index);
                }
            }
        }
    }

    // Directory metadata last, deepest first, so writing children does not
    // bump mtimes and read-only modes do not block extraction.
    dir_meta.sort_by_key(|d| std::cmp::Reverse(d.1));
    for (p, _, item) in dir_meta {
        apply_dir_meta(&p, item, opts).map_err(|error| ExtractFailure { index: Some(item.index), error })?;
    }
    Ok(report)
}

#[cfg(unix)]
fn apply_dir_meta(p: &Path, item: &PlanItem, opts: &ExtractOptions) -> Result<(), ExtractError> {
    // Re-check: never touch metadata through a symlink.
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {}
        _ => return Err(ExtractError::SymlinkInDestination),
    }
    let f = File::open(p).map_err(|_| ExtractError::Io)?;
    if opts.apply_mtime
        && let Some(t) = item.mtime.and_then(to_system_time) {
            f.set_modified(t).map_err(|_| ExtractError::Io)?;
        }
    if opts.apply_mode
        && let Some(mode) = item.mode {
            // Keep the owner able to traverse and modify.
            set_mode(&f, (mode & 0o777) | 0o700).map_err(|_| ExtractError::Io)?;
        }
    Ok(())
}

#[cfg(not(unix))]
fn apply_dir_meta(_p: &Path, _item: &PlanItem, _opts: &ExtractOptions) -> Result<(), ExtractError> {
    Ok(())
}
