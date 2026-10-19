// SPDX-License-Identifier: MIT OR Apache-2.0
//! Format-agnostic extraction planner.
//!
//! Takes the entry list of any archive (`PlannedEntry`) and either returns a
//! validated [`Plan`] (normalized relative paths, resolved hardlink sources,
//! portability warnings) or rejects the whole archive before a single byte is
//! written. The rules follow the "zip slip" / path traversal guidance in the
//! PKWARE APPNOTE (section 4.4.17: paths are relative, no drive letters, `/`
//! separators), POSIX pathname resolution (IEEE Std 1003.1, 4.13) for symlink
//! targets, and the Win32 file naming rules ("Naming Files, Paths, and
//! Namespaces") for reserved device names.
//!
//! Security policy (always enforced, no option disables it):
//! - `/` and `\` are both treated as separators.
//! - Absolute paths, UNC paths (`//x`, `\\x`), drive letters (`C:`), NUL
//!   bytes and `..` components (including Win32 aliases such as `...` or
//!   `.. `) are rejected.
//! - A symlink target must be relative and resolve, lexically, inside the
//!   destination. A target that walks *through* another symlink of the same
//!   archive is rejected (lexical resolution cannot be trusted there).
//! - No entry may have an ancestor that is a symlink in the archive (checked
//!   case-insensitively, so case-insensitive file systems are covered too).
//! - Hardlink targets must name a regular file that appears earlier.
//!
//! Portability findings (Windows reserved names, case collisions) are
//! reported as warnings or promoted to errors via [`PlanOptions`].
//! `archive_path::validate_path` is reused as the "portable name" check.

use std::collections::{HashMap, HashSet};

use crate::archive_path::validate_path;

/// Entry type as seen by the planner. Targets are raw archive bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink { target: Vec<u8> },
    Hardlink { target: Vec<u8> },
}

/// One archive member, independent of the container format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEntry {
    pub path: Vec<u8>,
    pub kind: EntryKind,
    /// Uncompressed size in bytes (0 for dirs and links).
    pub size: u64,
    /// Unix permission bits (and possibly file-type bits), if known.
    pub mode: Option<u32>,
    /// Modification time in seconds since the Unix epoch (UTC), if known.
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    EmptyPath,
    AbsolutePath,
    UncPath,
    DriveLetter,
    NulByte,
    ParentTraversal,
    PathTooLong,
    TooDeep,
    SymlinkEscape,
    ThroughSymlink,
    HardlinkTarget,
    PathConflict,
    WindowsName,
    CaseCollision,
    TooManyEntries,
    TooManyBytes,
    Allocation,
}

/// Plan rejection, with the offending entry index when there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanFailure {
    pub index: Option<usize>,
    pub error: PlanError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanWarning {
    /// Name is not portable (Windows device name, trailing dot/space, `:`,
    /// control characters, ...). `index` is the entry index.
    NonPortableName { index: usize },
    /// Two different entry paths that differ only by case.
    CaseCollision { index: usize, other: usize },
    /// Same exact path appears twice (non-directory).
    DuplicatePath { index: usize, other: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    Report,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanLimits {
    pub max_entries: usize,
    /// Sum of `size` over regular files and hardlinks.
    pub max_total_bytes: u64,
    /// Maximum normalized path length in bytes.
    pub max_path_len: usize,
    /// Maximum number of path components.
    pub max_depth: usize,
}

impl Default for PlanLimits {
    fn default() -> Self {
        PlanLimits {
            max_entries: 100_000,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_path_len: 4096,
            max_depth: 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanOptions {
    pub limits: PlanLimits,
    pub windows_names: Strictness,
    pub case_collisions: Strictness,
}

impl Default for PlanOptions {
    fn default() -> Self {
        PlanOptions {
            limits: PlanLimits::default(),
            windows_names: if cfg!(windows) { Strictness::Reject } else { Strictness::Report },
            case_collisions: Strictness::Report,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanKind {
    File,
    Dir,
    /// Target bytes with `\` rewritten to `/`; validated to stay inside.
    Symlink { target: Vec<u8> },
    /// Index (into the input entries) of the regular file to copy/link from.
    Hardlink { source: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItem {
    /// Index of the source entry in the input slice.
    pub index: usize,
    /// Normalized, non-empty components; none is empty, `.` or `..`.
    pub components: Vec<Vec<u8>>,
    pub kind: PlanKind,
    pub size: u64,
    pub mode: Option<u32>,
    pub mtime: Option<i64>,
}

impl PlanItem {
    /// Components joined with `/`.
    pub fn joined(&self) -> Vec<u8> {
        join(&self.components)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Same order as the input.
    pub items: Vec<PlanItem>,
    pub warnings: Vec<PlanWarning>,
    pub total_bytes: u64,
}

fn fail(index: usize, error: PlanError) -> PlanFailure {
    PlanFailure { index: Some(index), error }
}

fn is_sep(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

fn join(components: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    out
}

/// True for components that Win32 would collapse into `.` or `..`
/// (trailing dots and spaces are stripped there), or that are only dots.
fn is_dot_alias(c: &[u8]) -> bool {
    let trimmed_len = c.iter().rposition(|&b| b != b'.' && b != b' ').map_or(0, |p| p + 1);
    let trimmed = &c[..trimmed_len];
    trimmed.is_empty() || trimmed == b"." || trimmed == b".."
}

/// Normalize an archive path into components. Shared by entry paths and
/// hardlink targets (which are archive-root relative).
pub fn normalize_path(path: &[u8], limits: &PlanLimits) -> Result<Vec<Vec<u8>>, PlanError> {
    if path.contains(&0) {
        return Err(PlanError::NulByte);
    }
    if path.len() > limits.max_path_len {
        return Err(PlanError::PathTooLong);
    }
    if path.len() >= 2 && is_sep(path[0]) && is_sep(path[1]) {
        return Err(PlanError::UncPath);
    }
    if path.first().is_some_and(|&b| is_sep(b)) {
        return Err(PlanError::AbsolutePath);
    }
    if path.len() >= 2 && path[0].is_ascii_alphabetic() && path[1] == b':' {
        return Err(PlanError::DriveLetter);
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    for c in path.split(|&b| is_sep(b)) {
        if c.is_empty() || c == b"." {
            continue;
        }
        if is_dot_alias(c) {
            return Err(PlanError::ParentTraversal);
        }
        if c.len() > 255 {
            return Err(PlanError::PathTooLong);
        }
        if out.len() >= limits.max_depth {
            return Err(PlanError::TooDeep);
        }
        out.try_reserve(1).map_err(|_| PlanError::Allocation)?;
        let mut v = Vec::new();
        v.try_reserve_exact(c.len()).map_err(|_| PlanError::Allocation)?;
        v.extend_from_slice(c);
        out.push(v);
    }
    if out.is_empty() {
        return Err(PlanError::EmptyPath);
    }
    Ok(out)
}

/// Case-folded key used for collision and symlink-ancestor checks.
fn fold(components: &[Vec<u8>]) -> Vec<u8> {
    let joined = join(components);
    match std::str::from_utf8(&joined) {
        Ok(s) => s.to_lowercase().into_bytes(),
        Err(_) => joined.to_ascii_lowercase(),
    }
}

/// Lexically resolve a symlink target relative to the link's parent.
/// Returns the resolved components, or an error if it leaves the root or
/// passes through another archive symlink.
fn resolve_link(
    link: &[Vec<u8>],
    target: &[u8],
    symlinks: &HashSet<Vec<u8>>,
    limits: &PlanLimits,
) -> Result<Vec<Vec<u8>>, PlanError> {
    if target.is_empty() {
        return Err(PlanError::SymlinkEscape);
    }
    if target.contains(&0) {
        return Err(PlanError::NulByte);
    }
    if target.len() > limits.max_path_len {
        return Err(PlanError::PathTooLong);
    }
    if is_sep(target[0]) || (target.len() >= 2 && target[0].is_ascii_alphabetic() && target[1] == b':') {
        return Err(PlanError::SymlinkEscape);
    }
    let mut cur: Vec<Vec<u8>> = link[..link.len() - 1].to_vec();
    let parts: Vec<&[u8]> = target.split(|&b| is_sep(b)).filter(|c| !c.is_empty() && *c != b".").collect();
    for (i, c) in parts.iter().enumerate() {
        if *c == b".." {
            if cur.pop().is_none() {
                return Err(PlanError::SymlinkEscape);
            }
        } else if is_dot_alias(c) {
            return Err(PlanError::SymlinkEscape);
        } else {
            if cur.len() >= limits.max_depth {
                return Err(PlanError::TooDeep);
            }
            cur.push(c.to_vec());
            // Walking through another archive symlink: its real location is
            // not what the lexical path says, so refuse.
            if i + 1 < parts.len() && symlinks.contains(&fold(&cur)) {
                return Err(PlanError::SymlinkEscape);
            }
        }
    }
    Ok(cur)
}

fn portable(components: &[Vec<u8>]) -> bool {
    components.iter().all(|c| validate_path(c).is_ok())
}

/// Validate `entries` and build an extraction plan. All-or-nothing: any
/// hostile entry rejects the whole archive.
pub fn plan_extraction(entries: &[PlannedEntry], options: &PlanOptions) -> Result<Plan, PlanFailure> {
    let limits = &options.limits;
    if entries.len() > limits.max_entries {
        return Err(PlanFailure { index: None, error: PlanError::TooManyEntries });
    }
    let alloc = |_| PlanFailure { index: None, error: PlanError::Allocation };

    // Pass 1: normalize every path, sum sizes.
    let mut normalized: Vec<Vec<Vec<u8>>> = Vec::new();
    normalized.try_reserve_exact(entries.len()).map_err(alloc)?;
    let mut total: u64 = 0;
    for (i, e) in entries.iter().enumerate() {
        normalized.push(normalize_path(&e.path, limits).map_err(|err| fail(i, err))?);
        if matches!(e.kind, EntryKind::File | EntryKind::Hardlink { .. }) {
            total = total.checked_add(e.size).ok_or(fail(i, PlanError::TooManyBytes))?;
            if total > limits.max_total_bytes {
                return Err(fail(i, PlanError::TooManyBytes));
            }
        }
    }

    // Index structures (all keyed by case-folded path).
    let mut symlinks: HashSet<Vec<u8>> = HashSet::new();
    let mut implicit_dirs: HashSet<Vec<u8>> = HashSet::new(); // exact-case
    let mut explicit_dirs: HashSet<Vec<u8>> = HashSet::new(); // exact-case
    let mut nondir: HashMap<Vec<u8>, usize> = HashMap::new(); // exact-case -> first index
    for (i, e) in entries.iter().enumerate() {
        let comps = &normalized[i];
        match e.kind {
            EntryKind::Symlink { .. } => {
                symlinks.insert(fold(comps));
            }
            EntryKind::Dir => {
                explicit_dirs.insert(join(comps));
            }
            _ => {}
        }
        if !matches!(e.kind, EntryKind::Dir) {
            nondir.entry(join(comps)).or_insert(i);
        }
        for depth in 1..comps.len() {
            implicit_dirs.insert(join(&comps[..depth]));
        }
    }

    let mut warnings: Vec<PlanWarning> = Vec::new();
    let mut items: Vec<PlanItem> = Vec::new();
    items.try_reserve_exact(entries.len()).map_err(alloc)?;
    let mut folded_first: HashMap<Vec<u8>, (usize, Vec<u8>)> = HashMap::new();
    let mut seen_files: HashMap<Vec<u8>, usize> = HashMap::new(); // exact path -> regular file index

    for (i, e) in entries.iter().enumerate() {
        let comps = &normalized[i];
        let exact = join(comps);

        // No ancestor may be a symlink (case-insensitive) or a non-directory.
        for depth in 1..comps.len() {
            let anc = &comps[..depth];
            if symlinks.contains(&fold(anc)) {
                return Err(fail(i, PlanError::ThroughSymlink));
            }
            if nondir.contains_key(&join(anc)) {
                return Err(fail(i, PlanError::PathConflict));
            }
        }

        let is_dir = matches!(e.kind, EntryKind::Dir);
        if !is_dir && (implicit_dirs.contains(&exact) || explicit_dirs.contains(&exact)) {
            return Err(fail(i, PlanError::PathConflict));
        }
        if !is_dir {
            if let Some(&first) = nondir.get(&exact) {
                if first != i {
                    // A symlink duplicated with anything else is ambiguous.
                    if matches!(e.kind, EntryKind::Symlink { .. })
                        || matches!(entries[first].kind, EntryKind::Symlink { .. })
                    {
                        return Err(fail(i, PlanError::PathConflict));
                    }
                    warnings.push(PlanWarning::DuplicatePath { index: i, other: first });
                }
            }
        }

        // Case collisions between distinct exact paths.
        let folded = fold(comps);
        match folded_first.get(&folded) {
            Some((other, other_exact)) if *other_exact != exact => {
                if options.case_collisions == Strictness::Reject {
                    return Err(fail(i, PlanError::CaseCollision));
                }
                warnings.push(PlanWarning::CaseCollision { index: i, other: *other });
            }
            Some(_) => {}
            None => {
                folded_first.insert(folded, (i, exact.clone()));
            }
        }

        if !portable(comps) {
            if options.windows_names == Strictness::Reject {
                return Err(fail(i, PlanError::WindowsName));
            }
            warnings.push(PlanWarning::NonPortableName { index: i });
        }

        let kind = match &e.kind {
            EntryKind::File => {
                seen_files.insert(exact.clone(), i);
                PlanKind::File
            }
            EntryKind::Dir => PlanKind::Dir,
            EntryKind::Symlink { target } => {
                resolve_link(comps, target, &symlinks, limits).map_err(|err| fail(i, err))?;
                let t: Vec<u8> = target.iter().map(|&b| if b == b'\\' { b'/' } else { b }).collect();
                PlanKind::Symlink { target: t }
            }
            EntryKind::Hardlink { target } => {
                let tc = normalize_path(target, limits).map_err(|_| fail(i, PlanError::HardlinkTarget))?;
                let tj = join(&tc);
                match seen_files.get(&tj) {
                    Some(&src) if tj != exact => PlanKind::Hardlink { source: src },
                    _ => return Err(fail(i, PlanError::HardlinkTarget)),
                }
            }
        };
        items.push(PlanItem {
            index: i,
            components: comps.clone(),
            kind,
            size: if matches!(e.kind, EntryKind::File | EntryKind::Hardlink { .. }) { e.size } else { 0 },
            mode: e.mode,
            mtime: e.mtime,
        });
    }

    Ok(Plan { items, warnings, total_bytes: total })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_alias() {
        assert!(is_dot_alias(b".."));
        assert!(is_dot_alias(b"..."));
        assert!(is_dot_alias(b".. "));
        assert!(is_dot_alias(b" "));
        assert!(!is_dot_alias(b".a"));
        assert!(!is_dot_alias(b"a.."));
    }
}
