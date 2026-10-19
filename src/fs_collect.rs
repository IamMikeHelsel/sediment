// SPDX-License-Identifier: MIT OR Apache-2.0
//! Walk filesystem inputs into a deterministic, sorted entry list for archive
//! creation, plus the in-memory [`ArchiveEntry`] model shared by the ZIP and
//! tar writers.
//!
//! Naming follows the common archiver convention: an input path contributes its
//! final component as the archive root (`a b/c` stores `c/...`); an input with
//! no final component (`.`, `/`) stores its children at the archive root.
//! Names use `/` separators, no leading slash, and never contain `.`/`..`
//! components. Entries are sorted component-wise by raw bytes so parents always
//! precede children and output is independent of directory iteration order.
//! Symlinks are recorded as links unless `follow_symlinks` is set (cycles are
//! detected when following). Unreadable entries are skipped with a warning, or
//! rejected when `strict` is set.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectError {
    /// A root input does not exist or its metadata cannot be read.
    NotFound,
    /// An entry could not be read (only returned when `strict`).
    Unreadable,
    /// Two inputs map to the same archive name, or a name is unusable.
    InvalidName,
    /// A configured limit was exceeded.
    LimitExceeded,
    Allocation,
    /// A file changed size between collection and reading.
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

/// One collected filesystem entry. `name` is archive-relative without a
/// trailing slash (writers add `/` for directories where the format needs it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedEntry {
    pub name: Vec<u8>,
    pub source: PathBuf,
    pub kind: EntryKind,
    /// File size in bytes (0 for directories and symlinks).
    pub size: u64,
    /// Modification time in seconds since the Unix epoch (may be negative).
    pub mtime: i64,
    /// Permission bits (`mode & 0o7777`).
    pub mode: u32,
    /// Symlink target bytes (empty unless `kind == Symlink`).
    pub link_target: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningKind {
    /// Directory could not be listed; it is stored but its contents are not.
    UnreadableDirectory,
    /// File could not be opened or its metadata read; skipped.
    UnreadableFile,
    /// Special file (fifo, socket, device); skipped.
    SpecialFile,
    /// Symlink loop detected while following symlinks; skipped.
    SymlinkLoop,
    /// Excluded because it is the output archive itself.
    ExcludedOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectWarning {
    pub path: PathBuf,
    pub kind: WarningKind,
}

#[derive(Debug, Clone, Copy)]
pub struct CollectLimits {
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_depth: usize,
    pub max_name_bytes: usize,
}

impl Default for CollectLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_total_bytes: 1 << 30,
            max_depth: 256,
            max_name_bytes: 65535,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CollectOptions {
    pub follow_symlinks: bool,
    /// Turn every warning about an unreadable entry into `CollectError::Unreadable`.
    pub strict: bool,
    /// Files to leave out (typically the output archive); compared canonically.
    pub exclude: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct Collected {
    pub entries: Vec<CollectedEntry>,
    pub warnings: Vec<CollectWarning>,
    pub total_bytes: u64,
}

/// In-memory entry consumed by the archive writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveEntry<'a> {
    /// Archive-relative name without trailing slash.
    pub name: &'a [u8],
    pub kind: EntryKind,
    /// File contents (must be empty for directories and symlinks).
    pub data: &'a [u8],
    pub mtime: i64,
    pub mode: u32,
    pub link_target: &'a [u8],
}

impl CollectedEntry {
    /// View this entry as an [`ArchiveEntry`] with the given file contents.
    pub fn as_archive_entry<'a>(&'a self, data: &'a [u8]) -> ArchiveEntry<'a> {
        ArchiveEntry {
            name: &self.name,
            kind: self.kind,
            data,
            mtime: self.mtime,
            mode: self.mode,
            link_target: &self.link_target,
        }
    }
}

/// Collect `inputs` into a sorted entry list.
pub fn collect(inputs: &[PathBuf], options: &CollectOptions, limits: CollectLimits) -> Result<Collected, CollectError> {
    let mut st = State {
        out: Collected::default(),
        options,
        limits,
        exclude: options
            .exclude
            .iter()
            .filter_map(|p| canonical_file(p).map(|c| (p.file_name().map(|n| n.to_os_string()), c)))
            .collect(),
        ancestors: Vec::new(),
    };
    for input in inputs {
        let meta = if options.follow_symlinks {
            std::fs::metadata(input)
        } else {
            std::fs::symlink_metadata(input)
        }
        .map_err(|_| CollectError::NotFound)?;
        let base = match input.file_name() {
            Some(n) if !is_dot_component(input) => os_bytes(n)?,
            _ => Vec::new(),
        };
        if base.is_empty() {
            if !meta.is_dir() {
                return Err(CollectError::InvalidName);
            }
            st.walk_dir(input, &base, 0)?;
        } else {
            st.visit(input, base, meta, 0)?;
        }
    }
    let entries = &mut st.out.entries;
    entries.sort_by(|a, b| a.name.split(|&c| c == b'/').cmp(b.name.split(|&c| c == b'/')));
    for w in entries.windows(2) {
        if w[0].name == w[1].name {
            return Err(CollectError::InvalidName);
        }
    }
    Ok(st.out)
}

fn is_dot_component(p: &Path) -> bool {
    matches!(
        p.components().next_back(),
        Some(std::path::Component::CurDir | std::path::Component::ParentDir | std::path::Component::RootDir)
    )
}

fn canonical_file(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

#[cfg(unix)]
fn os_bytes(s: &OsStr) -> Result<Vec<u8>, CollectError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(s.as_bytes().to_vec())
}

#[cfg(not(unix))]
fn os_bytes(s: &OsStr) -> Result<Vec<u8>, CollectError> {
    s.to_str().map(|x| x.as_bytes().to_vec()).ok_or(CollectError::InvalidName)
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() {
        0o755
    } else if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    match meta.modified() {
        Ok(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(e) => {
                let d = e.duration();
                // Floor toward negative infinity for pre-epoch times.
                let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                if d.subsec_nanos() > 0 { -secs - 1 } else { -secs }
            }
        },
        Err(_) => 0,
    }
}

struct State<'o> {
    out: Collected,
    options: &'o CollectOptions,
    limits: CollectLimits,
    exclude: Vec<(Option<std::ffi::OsString>, PathBuf)>,
    ancestors: Vec<PathBuf>,
}

impl State<'_> {
    fn warn(&mut self, path: &Path, kind: WarningKind) -> Result<(), CollectError> {
        if self.options.strict && kind != WarningKind::ExcludedOutput {
            return Err(CollectError::Unreadable);
        }
        self.out.warnings.try_reserve(1).map_err(|_| CollectError::Allocation)?;
        self.out.warnings.push(CollectWarning {
            path: path.to_path_buf(),
            kind,
        });
        Ok(())
    }

    fn push(&mut self, e: CollectedEntry) -> Result<(), CollectError> {
        if self.out.entries.len() >= self.limits.max_entries {
            return Err(CollectError::LimitExceeded);
        }
        if e.name.len() > self.limits.max_name_bytes || e.name.is_empty() || e.name.contains(&0) {
            return Err(if e.name.len() > self.limits.max_name_bytes {
                CollectError::LimitExceeded
            } else {
                CollectError::InvalidName
            });
        }
        self.out.total_bytes = self.out.total_bytes.checked_add(e.size).ok_or(CollectError::LimitExceeded)?;
        if self.out.total_bytes > self.limits.max_total_bytes {
            return Err(CollectError::LimitExceeded);
        }
        self.out.entries.try_reserve(1).map_err(|_| CollectError::Allocation)?;
        self.out.entries.push(e);
        Ok(())
    }

    fn is_excluded(&self, path: &Path) -> bool {
        if self.exclude.is_empty() {
            return false;
        }
        let name = path.file_name().map(|n| n.to_os_string());
        self.exclude
            .iter()
            .any(|(n, c)| *n == name && canonical_file(path).as_deref() == Some(c.as_path()))
    }

    fn visit(&mut self, path: &Path, name: Vec<u8>, meta: std::fs::Metadata, depth: usize) -> Result<(), CollectError> {
        if depth > self.limits.max_depth {
            return Err(CollectError::LimitExceeded);
        }
        let ft = meta.file_type();
        let mtime = mtime_of(&meta);
        let mode = mode_of(&meta);
        if ft.is_symlink() {
            let target = match std::fs::read_link(path) {
                Ok(t) => os_bytes(t.as_os_str())?,
                Err(_) => return self.warn(path, WarningKind::UnreadableFile),
            };
            return self.push(CollectedEntry {
                name,
                source: path.to_path_buf(),
                kind: EntryKind::Symlink,
                size: 0,
                mtime,
                mode: 0o777,
                link_target: target,
            });
        }
        if ft.is_dir() {
            let canon = std::fs::canonicalize(path).ok();
            if self.options.follow_symlinks {
                if let Some(c) = &canon {
                    if self.ancestors.contains(c) {
                        return self.warn(path, WarningKind::SymlinkLoop);
                    }
                }
            }
            self.push(CollectedEntry {
                name: name.clone(),
                source: path.to_path_buf(),
                kind: EntryKind::Directory,
                size: 0,
                mtime,
                mode,
                link_target: Vec::new(),
            })?;
            if let Some(c) = canon.clone() {
                self.ancestors.push(c);
            }
            let r = self.walk_dir(path, &name, depth + 1);
            if canon.is_some() {
                self.ancestors.pop();
            }
            return r;
        }
        if ft.is_file() {
            if self.is_excluded(path) {
                return self.warn(path, WarningKind::ExcludedOutput);
            }
            if std::fs::File::open(path).is_err() {
                return self.warn(path, WarningKind::UnreadableFile);
            }
            return self.push(CollectedEntry {
                name,
                source: path.to_path_buf(),
                kind: EntryKind::File,
                size: meta.len(),
                mtime,
                mode,
                link_target: Vec::new(),
            });
        }
        self.warn(path, WarningKind::SpecialFile)
    }

    fn walk_dir(&mut self, dir: &Path, prefix: &[u8], depth: usize) -> Result<(), CollectError> {
        if depth > self.limits.max_depth {
            return Err(CollectError::LimitExceeded);
        }
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return self.warn(dir, WarningKind::UnreadableDirectory),
        };
        let mut children: Vec<(Vec<u8>, PathBuf)> = Vec::new();
        for ent in rd {
            let ent = match ent {
                Ok(e) => e,
                Err(_) => {
                    self.warn(dir, WarningKind::UnreadableDirectory)?;
                    continue;
                }
            };
            if children.len() >= self.limits.max_entries {
                return Err(CollectError::LimitExceeded);
            }
            children.try_reserve(1).map_err(|_| CollectError::Allocation)?;
            children.push((os_bytes(&ent.file_name())?, ent.path()));
        }
        children.sort();
        for (child, path) in children {
            let meta = if self.options.follow_symlinks {
                std::fs::metadata(&path)
            } else {
                std::fs::symlink_metadata(&path)
            };
            let meta = match meta {
                Ok(m) => m,
                Err(_) => {
                    self.warn(&path, WarningKind::UnreadableFile)?;
                    continue;
                }
            };
            let mut name = Vec::new();
            let len = prefix.len() + 1 + child.len();
            if len > self.limits.max_name_bytes {
                return Err(CollectError::LimitExceeded);
            }
            name.try_reserve_exact(len).map_err(|_| CollectError::Allocation)?;
            if !prefix.is_empty() {
                name.extend_from_slice(prefix);
                name.push(b'/');
            }
            name.extend_from_slice(&child);
            self.visit(&path, name, meta, depth)?;
        }
        Ok(())
    }
}

/// Read the contents of a collected file, verifying its size is unchanged and
/// at most `max_bytes`. Directories and symlinks yield an empty vector.
pub fn read_entry_data(entry: &CollectedEntry, max_bytes: u64) -> Result<Vec<u8>, CollectError> {
    use std::io::Read;
    if entry.kind != EntryKind::File {
        return Ok(Vec::new());
    }
    if entry.size > max_bytes {
        return Err(CollectError::LimitExceeded);
    }
    let f = std::fs::File::open(&entry.source).map_err(|_| CollectError::Unreadable)?;
    let cap = usize::try_from(entry.size).map_err(|_| CollectError::LimitExceeded)?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(cap).map_err(|_| CollectError::Allocation)?;
    f.take(entry.size + 1)
        .read_to_end(&mut buf)
        .map_err(|_| CollectError::Unreadable)?;
    if buf.len() as u64 != entry.size {
        return Err(CollectError::Changed);
    }
    Ok(buf)
}
