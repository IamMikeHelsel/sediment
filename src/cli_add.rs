// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sediment a <archive> <paths...>`: create an archive from files.
//!
//! The archive format follows the output extension (case-insensitive):
//! `.zip`, `.tar`, `.tar.gz`/`.tgz` (`.tar.xz`/`.txz`, `.tar.bz2`/`.tbz2`/`.tbz`
//! are recognised but not yet supported). Switches (anywhere before `--`):
//!
//! * `-mx0` .. `-mx9` (also `-mx=N`): 0 stores, 1..=9 select the DEFLATE
//!   level (default 5). For `.tar` the level is ignored.
//! * `-y`: overwrite an existing archive (otherwise it is an error; in-place
//!   update is not supported).
//! * `-l`: follow symlinks instead of storing them as links.
//!
//! Exit codes: 0 success, 1 fatal error (nothing written), 2 usage error,
//! 3 archive written but some inputs were skipped (warnings on stderr).
//! The archive is written to a temporary sibling file and renamed into place.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::compress_wrap::{Compression, WrapError, compress, compress_bound};
use crate::fs_collect::{CollectError, CollectLimits, CollectOptions, EntryKind, WarningKind, collect, read_entry_data};
use crate::tar_create::{TarCreateLimits, create_tar};
use crate::zip_create::{ZipCreateLimits, ZipCreateOptions, create_zip};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar(Compression),
}

/// Detect the output format from the archive file name.
pub fn format_from_name(path: &Path) -> Option<ArchiveFormat> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let table: [(&str, ArchiveFormat); 9] = [
        (".zip", ArchiveFormat::Zip),
        (".tar.gz", ArchiveFormat::Tar(Compression::Gzip)),
        (".tgz", ArchiveFormat::Tar(Compression::Gzip)),
        (".tar.xz", ArchiveFormat::Tar(Compression::Xz)),
        (".txz", ArchiveFormat::Tar(Compression::Xz)),
        (".tar.bz2", ArchiveFormat::Tar(Compression::Bzip2)),
        (".tbz2", ArchiveFormat::Tar(Compression::Bzip2)),
        (".tbz", ArchiveFormat::Tar(Compression::Bzip2)),
        (".tar", ArchiveFormat::Tar(Compression::None)),
    ];
    table
        .iter()
        .find(|(ext, _)| name.len() > ext.len() && name.ends_with(ext))
        .map(|&(_, f)| f)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddArgs {
    pub archive: PathBuf,
    pub inputs: Vec<PathBuf>,
    pub level: u8,
    pub overwrite: bool,
    pub follow_symlinks: bool,
}

/// Parse the arguments that follow the `a` command.
pub fn parse_add_args(args: &[OsString]) -> Result<AddArgs, String> {
    let mut level = 5u8;
    let mut overwrite = false;
    let mut follow = false;
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut switches_done = false;
    for a in args {
        let s = a.to_string_lossy();
        if !switches_done && s == "--" {
            switches_done = true;
            continue;
        }
        if !switches_done && s.starts_with('-') && s.len() > 1 {
            if let Some(rest) = s.strip_prefix("-mx") {
                let rest = rest.strip_prefix('=').unwrap_or(rest);
                match rest.parse::<u8>() {
                    Ok(n) if n <= 9 && rest.len() == 1 => level = n,
                    _ => return Err(format!("invalid compression level switch: {s}")),
                }
            } else if s == "-y" {
                overwrite = true;
            } else if s == "-l" {
                follow = true;
            } else {
                return Err(format!("unknown switch: {s}"));
            }
            continue;
        }
        positional.push(PathBuf::from(a));
    }
    if positional.is_empty() {
        return Err("missing archive name".into());
    }
    let archive = positional.remove(0);
    if positional.is_empty() {
        return Err("missing input paths".into());
    }
    Ok(AddArgs {
        archive,
        inputs: positional,
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

fn warn_msg(k: WarningKind) -> &'static str {
    match k {
        WarningKind::UnreadableDirectory => "cannot list directory; contents skipped",
        WarningKind::UnreadableFile => "cannot read; skipped",
        WarningKind::SpecialFile => "special file; skipped",
        WarningKind::SymlinkLoop => "symlink loop; skipped",
        WarningKind::ExcludedOutput => "is the output archive; skipped",
    }
}

/// Run `sediment a`. `args` are the arguments after the `a` command.
pub fn run_add(args: &[OsString]) -> i32 {
    let mut err = std::io::stderr().lock();
    let a = match parse_add_args(args) {
        Ok(a) => a,
        Err(m) => {
            let _ = writeln!(err, "sediment: {m}\nUsage: sediment a [-mx0..9] [-y] [-l] ARCHIVE PATH...");
            return 2;
        }
    };
    let format = match format_from_name(&a.archive) {
        Some(f) => f,
        None => {
            let _ = writeln!(err, "sediment: cannot infer archive format from name (use .zip, .tar, .tar.gz or .tgz)");
            return 2;
        }
    };
    if let ArchiveFormat::Tar(c @ (Compression::Xz | Compression::Bzip2)) = format {
        let n = if c == Compression::Xz { "xz" } else { "bzip2" };
        let _ = writeln!(err, "sediment: {n} compression is not supported yet");
        return 1;
    }
    let exists = std::fs::symlink_metadata(&a.archive).is_ok();
    if exists {
        if std::fs::metadata(&a.archive).map(|m| m.is_dir()).unwrap_or(false) {
            let _ = writeln!(err, "sediment: archive path is a directory");
            return 1;
        }
        if !a.overwrite {
            let _ = writeln!(err, "sediment: archive exists (use -y to overwrite; update is not supported)");
            return 1;
        }
    }

    let options = CollectOptions {
        follow_symlinks: a.follow_symlinks,
        strict: false,
        exclude: vec![a.archive.clone()],
    };
    let limits = CollectLimits::default();
    let collected = match collect(&a.inputs, &options, limits) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "sediment: {}", collect_msg(e));
            return 1;
        }
    };
    let mut warned = false;
    for w in &collected.warnings {
        let _ = writeln!(err, "sediment: warning: {}: {}", w.path.display(), warn_msg(w.kind));
        if w.kind != WarningKind::ExcludedOutput {
            warned = true;
        }
    }

    let mut datas: Vec<Vec<u8>> = Vec::new();
    for e in &collected.entries {
        match read_entry_data(e, limits.max_total_bytes) {
            Ok(d) => datas.push(d),
            Err(x) => {
                let _ = writeln!(err, "sediment: {}: {}", e.source.display(), collect_msg(x));
                return 1;
            }
        }
    }
    let entries: Vec<_> = collected
        .entries
        .iter()
        .zip(datas.iter())
        .map(|(e, d)| e.as_archive_entry(d))
        .collect();

    let bytes = match format {
        ArchiveFormat::Zip => match create_zip(&entries, ZipCreateOptions { level: a.level }, ZipCreateLimits::default()) {
            Ok(z) => {
                for &i in &z.skipped {
                    let _ = writeln!(
                        err,
                        "sediment: note: {}: symlink not stored in zip (use -l to store its target)",
                        collected.entries[i].source.display()
                    );
                }
                z.bytes
            }
            Err(e) => {
                let _ = writeln!(err, "sediment: cannot build zip: {e:?}");
                return 1;
            }
        },
        ArchiveFormat::Tar(c) => {
            let tar = match create_tar(&entries, TarCreateLimits::default()) {
                Ok(t) => t,
                Err(e) => {
                    let _ = writeln!(err, "sediment: cannot build tar: {e:?}");
                    return 1;
                }
            };
            if c == Compression::None {
                tar
            } else {
                let bound = compress_bound(tar.len()).unwrap_or(usize::MAX);
                match compress(c, &tar, a.level, bound) {
                    Ok(v) => v,
                    Err(WrapError::Unsupported) => {
                        let _ = writeln!(err, "sediment: compression not supported");
                        return 1;
                    }
                    Err(e) => {
                        let _ = writeln!(err, "sediment: compression failed: {e:?}");
                        return 1;
                    }
                }
            }
        }
    };
    drop(entries);
    drop(datas);

    if let Err(m) = write_atomically(&a.archive, &bytes) {
        let _ = writeln!(err, "sediment: {m}");
        return 1;
    }
    let files = collected.entries.iter().filter(|e| e.kind == EntryKind::File).count();
    let _ = writeln!(
        std::io::stdout().lock(),
        "Created {} ({} entries, {} files, {} bytes in, {} bytes out)",
        a.archive.display(),
        collected.entries.len(),
        files,
        collected.total_bytes,
        bytes.len()
    );
    if warned { 3 } else { 0 }
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
