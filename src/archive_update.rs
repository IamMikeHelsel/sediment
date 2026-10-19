// SPDX-License-Identifier: MIT OR Apache-2.0
//! Format-neutral planning for archive update operations: `u` (add new
//! files, replace changed ones), `d` (delete by wildcard) and `rn` (rename
//! pairs). The planners turn an archive listing ([`ExistingEntry`]) plus the
//! user's request into an [`EditPlan`]: one [`EntryAction`] per existing
//! entry (in archive order) and a list of additions. The per-format
//! rewriters (`zip_update`, `tar_update`, `sevenz_update`) apply a plan
//! while copying untouched entries byte for byte where the format allows.
//!
//! Semantics (modelled on the documented behaviour of 7-Zip's `u`, `d` and
//! `rn` commands, implemented from their user documentation only):
//!
//! * `u`: an input whose archive name is absent is added; one whose name
//!   exists is replaced when the file on disk is newer than the archived
//!   copy (compared at the archive's timestamp resolution), or when one is a
//!   directory and the other is not. Archive entries without a counterpart on
//!   disk are kept. Duplicate archive names: the first is replaced, the rest
//!   are deleted.
//! * `d`: a pattern (`*`, `?` wildcards via [`crate::wildcard`]) selects an
//!   entry when it matches the entry's path or one of its parent directories,
//!   so deleting a directory deletes its contents. Without `recursive` a
//!   pattern is anchored at the archive root; with it, a pattern without a
//!   separator matches at any depth.
//! * `rn OLD NEW`: renames the entry named `OLD` and, when `OLD` is a
//!   directory, everything under `OLD/`. The first matching pair wins. A
//!   rename that would collide with another entry's final name is an error.
//!
//! Names are compared as raw bytes without trailing `/`.

use crate::fs_collect::{ArchiveEntry, EntryKind};
use crate::wildcard::match_path;
use crate::zip_create::validate_entry_name;

/// Errors shared by the planners and the format rewriters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    /// The existing archive is malformed or could not be parsed.
    InvalidArchive,
    /// A feature of the existing archive (or the request) is not supported
    /// for rewriting (e.g. masked ZIP headers, encrypted 7z headers).
    Unsupported,
    /// A new name is empty, absolute, contains NUL, `.` or `..` components,
    /// or is not valid for the target format.
    InvalidName,
    /// A rename would give two entries the same name.
    NameCollision,
    /// A caller limit was exceeded.
    LimitExceeded,
    /// Memory reservation failed.
    Allocation,
    /// Building new entries failed (compression or writer error).
    EncodeFailed,
}

/// One entry of the existing archive, as seen by the planners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingEntry {
    /// Archive path without trailing `/`.
    pub name: Vec<u8>,
    pub is_dir: bool,
    /// Modification time in Unix seconds, when the archive records one.
    pub mtime: Option<i64>,
    /// Resolution of `mtime` in seconds (1, or 2 for MS-DOS times).
    pub time_resolution: u32,
}

/// What to do with one existing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryAction<'a> {
    /// Copy unchanged.
    Keep,
    /// Leave out of the new archive.
    Delete,
    /// Copy with a new archive path (no trailing `/`).
    Rename(Vec<u8>),
    /// Replace with new contents at the same position (where the format
    /// keeps positions).
    Replace(ArchiveEntry<'a>),
}

/// A complete edit of an archive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EditPlan<'a> {
    /// One action per existing entry, in archive order.
    pub actions: Vec<EntryAction<'a>>,
    /// New entries, appended in order.
    pub additions: Vec<ArchiveEntry<'a>>,
}

impl EditPlan<'_> {
    /// True when applying the plan would not change the archive contents.
    pub fn is_noop(&self) -> bool {
        self.additions.is_empty() && self.actions.iter().all(|a| matches!(a, EntryAction::Keep))
    }

    /// Number of entries the plan deletes.
    pub fn deleted(&self) -> usize {
        self.actions.iter().filter(|a| matches!(a, EntryAction::Delete)).count()
    }

    /// Number of entries the plan renames.
    pub fn renamed(&self) -> usize {
        self.actions.iter().filter(|a| matches!(a, EntryAction::Rename(_))).count()
    }

    /// Number of entries the plan replaces.
    pub fn replaced(&self) -> usize {
        self.actions.iter().filter(|a| matches!(a, EntryAction::Replace(_))).count()
    }
}

/// Explicit limits for the rewriters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateLimits {
    /// Maximum entries in the existing or the new archive.
    pub max_entries: usize,
    /// Maximum total uncompressed bytes held in memory (decoded archive
    /// data, re-encoded members, new members).
    pub max_total_bytes: u64,
    /// Maximum size of the rewritten archive.
    pub max_output_bytes: u64,
}

impl Default for UpdateLimits {
    fn default() -> Self {
        Self { max_entries: 1_000_000, max_total_bytes: 4 << 30, max_output_bytes: (4 << 30) - 1 }
    }
}

/// Strip trailing `/` (a lone `/` stays).
pub fn normalize_name(name: &[u8]) -> &[u8] {
    let mut n = name;
    while n.len() > 1 && n.ends_with(b"/") {
        n = &n[..n.len() - 1];
    }
    n
}

/// Plan `d`: delete every entry matched by any of `patterns`.
pub fn plan_delete(existing: &[ExistingEntry], patterns: &[&str], recursive: bool) -> EditPlan<'static> {
    let actions = existing
        .iter()
        .map(|e| {
            let name = String::from_utf8_lossy(&e.name);
            if patterns.iter().any(|p| match_path(p, &name, recursive, true)) {
                EntryAction::Delete
            } else {
                EntryAction::Keep
            }
        })
        .collect();
    EditPlan { actions, additions: Vec::new() }
}

/// Result of [`plan_rename`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenamePlan {
    pub plan: EditPlan<'static>,
    /// Number of entries each pair renamed (same order as the pairs).
    pub matches: Vec<usize>,
}

/// Apply `old -> new` (exact entry or directory prefix) to `name`.
fn rename_one(name: &[u8], old: &[u8], new: &[u8]) -> Option<Vec<u8>> {
    if name == old {
        return Some(new.to_vec());
    }
    if name.len() > old.len() && name.starts_with(old) && name[old.len()] == b'/' {
        let mut v = new.to_vec();
        v.extend_from_slice(&name[old.len()..]);
        return Some(v);
    }
    None
}

/// Plan `rn`: rename entries by `(old, new)` pairs. Errors when a new name
/// is invalid or when two entries would end up with the same name (unless
/// they already shared it).
pub fn plan_rename(existing: &[ExistingEntry], pairs: &[(Vec<u8>, Vec<u8>)]) -> Result<RenamePlan, UpdateError> {
    let mut norm: Vec<(&[u8], &[u8])> = Vec::new();
    for (o, n) in pairs {
        let (o, n) = (normalize_name(o), normalize_name(n));
        if o.is_empty() || !validate_entry_name(n) {
            return Err(UpdateError::InvalidName);
        }
        norm.push((o, n));
    }
    let mut matches = vec![0usize; pairs.len()];
    let mut actions = Vec::new();
    actions.try_reserve_exact(existing.len()).map_err(|_| UpdateError::Allocation)?;
    let mut finals: Vec<(Vec<u8>, bool)> = Vec::new();
    finals.try_reserve_exact(existing.len()).map_err(|_| UpdateError::Allocation)?;
    for e in existing {
        let mut act = EntryAction::Keep;
        for (k, (o, n)) in norm.iter().enumerate() {
            if let Some(v) = rename_one(&e.name, o, n) {
                matches[k] += 1;
                if v != e.name {
                    act = EntryAction::Rename(v);
                }
                break;
            }
        }
        match &act {
            EntryAction::Rename(v) => finals.push((v.clone(), true)),
            _ => finals.push((e.name.clone(), false)),
        }
        actions.push(act);
    }
    // Collisions: a renamed entry may not share its final name with any
    // other entry.
    let mut order: Vec<usize> = (0..finals.len()).collect();
    order.sort_by(|&a, &b| finals[a].0.cmp(&finals[b].0));
    for w in order.windows(2) {
        let (a, b) = (&finals[w[0]], &finals[w[1]]);
        if a.0 == b.0 && (a.1 || b.1) {
            return Err(UpdateError::NameCollision);
        }
    }
    Ok(RenamePlan { plan: EditPlan { actions, additions: Vec::new() }, matches })
}

/// Counts reported by [`plan_update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpdateSummary {
    pub added: usize,
    pub replaced: usize,
    pub unchanged: usize,
}

/// Is the file on disk newer than the archived copy?
fn newer(disk: i64, archived: Option<i64>, resolution: u32) -> bool {
    let Some(a) = archived else { return true };
    let r = i64::from(resolution.max(1));
    disk - disk.rem_euclid(r) > a
}

/// Plan `u` for `incoming` entries (typically from `fs_collect`).
pub fn plan_update<'a>(
    existing: &[ExistingEntry],
    incoming: &[ArchiveEntry<'a>],
) -> Result<(EditPlan<'a>, UpdateSummary), UpdateError> {
    let mut actions: Vec<EntryAction<'a>> = Vec::new();
    actions.try_reserve_exact(existing.len()).map_err(|_| UpdateError::Allocation)?;
    actions.resize(existing.len(), EntryAction::Keep);
    // Sorted index of existing names for lookups.
    let mut idx: Vec<usize> = (0..existing.len()).collect();
    idx.sort_by(|&a, &b| existing[a].name.cmp(&existing[b].name).then(a.cmp(&b)));
    let mut additions = Vec::new();
    let mut s = UpdateSummary::default();
    for inc in incoming {
        let name = normalize_name(inc.name);
        let lo = idx.partition_point(|&i| existing[i].name.as_slice() < name);
        let hi = idx.partition_point(|&i| existing[i].name.as_slice() <= name);
        if lo == hi {
            additions.try_reserve(1).map_err(|_| UpdateError::Allocation)?;
            additions.push(*inc);
            s.added += 1;
            continue;
        }
        let first = idx[lo];
        let ex = &existing[first];
        let inc_dir = inc.kind == EntryKind::Directory;
        let replace = if ex.is_dir != inc_dir { true } else { !inc_dir && newer(inc.mtime, ex.mtime, ex.time_resolution) };
        if replace {
            actions[first] = EntryAction::Replace(*inc);
            for &dup in &idx[lo + 1..hi] {
                actions[dup] = EntryAction::Delete;
            }
            s.replaced += 1;
        } else {
            s.unchanged += 1;
        }
    }
    Ok((EditPlan { actions, additions }, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(name: &str, dir: bool, mtime: Option<i64>) -> ExistingEntry {
        ExistingEntry { name: name.as_bytes().to_vec(), is_dir: dir, mtime, time_resolution: 1 }
    }

    #[test]
    fn rename_prefix_rules() {
        assert_eq!(rename_one(b"a/b", b"a", b"x"), Some(b"x/b".to_vec()));
        assert_eq!(rename_one(b"ab", b"a", b"x"), None);
        assert_eq!(rename_one(b"a", b"a", b"x"), Some(b"x".to_vec()));
    }

    #[test]
    fn newer_respects_resolution() {
        assert!(!newer(101, Some(100), 2));
        assert!(newer(102, Some(100), 2));
        assert!(newer(101, Some(100), 1));
        assert!(newer(-5, None, 1));
        assert!(!newer(-5, Some(-5), 1));
    }

    #[test]
    fn collision_detected() {
        let e = [ex("a", false, None), ex("b", false, None)];
        assert_eq!(plan_rename(&e, &[(b"a".to_vec(), b"b".to_vec())]), Err(UpdateError::NameCollision));
        // Swapping via two pairs is fine.
        let r = plan_rename(&e, &[(b"a".to_vec(), b"b".to_vec()), (b"b".to_vec(), b"a".to_vec())]).unwrap();
        assert_eq!(r.matches, vec![1, 1]);
    }
}
