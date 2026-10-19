// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sediment a ARCHIVE.7z PATH...`: create a 7z archive from files with
//! [`crate::sevenz_write`]. Exposed as [`run_add_7z`] so the command line can
//! route `.7z` outputs here (the arguments are those after the `a` command).
//!
//! Switches (7-Zip style, anywhere before `--`):
//!
//! * `-mx0`..`-mx9` (also `-mx=N`): level; 0 stores (Copy), default 5.
//! * `-m0=LZMA2|LZMA|Copy` (case-insensitive; also `-m=`): main method.
//! * `-mf=BCJ|x86|ARM64|ARM|ARMT|PPC|SPARC|IA64|RISCV|off`: branch filter
//!   before the codec (default off).
//! * `-ms=on|off`, `-ms=<N>[b|k|m|g]` (solid block bytes, default unit MiB
//!   per 7-Zip; `b` = bytes), `-ms=<N>f` (files per block); several values may
//!   be combined, e.g. `-ms=64m100f`.
//! * `-mhc=on|off`: compress the header (default on).
//! * `-mmt=N|on|off` (also `-mmt`): worker threads (default all cores).
//! * `-t7z`: accepted (format is 7z anyway).
//! * `-y`: overwrite an existing archive. `-l`: follow symlinks (otherwise
//!   symlinks are stored as links, like 7-Zip `-snl`).
//!
//! Exit codes: 0 success, 1 fatal error (nothing written), 2 usage error,
//! 3 archive written but some inputs were skipped. The archive is written to
//! a temporary sibling file, synced and renamed into place.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::filter_bcj::BcjArch;
use crate::fs_collect::{CollectError, CollectLimits, CollectOptions, EntryKind, WarningKind, collect, read_entry_data};
use crate::sevenz_write::{SevenZMethod, SevenZWriteLimits, SevenZWriteOptions, create_7z};

/// Parsed `a` arguments for a 7z output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenZAddArgs {
    pub archive: PathBuf,
    pub inputs: Vec<PathBuf>,
    pub options: SevenZWriteOptions,
    pub overwrite: bool,
    pub follow_symlinks: bool,
}

fn on_off(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "on" | "+" | "" => Some(true),
        "off" | "-" => Some(false),
        _ => None,
    }
}

fn parse_filter(v: &str) -> Option<Option<BcjArch>> {
    Some(Some(match v.to_ascii_lowercase().as_str() {
        "off" | "-" => return Some(None),
        "on" | "bcj" | "x86" => BcjArch::X86,
        "arm64" => BcjArch::Arm64,
        "arm" => BcjArch::Arm,
        "armt" => BcjArch::ArmThumb,
        "ppc" => BcjArch::PowerPc,
        "sparc" => BcjArch::Sparc,
        "ia64" => BcjArch::Ia64,
        "riscv" => BcjArch::RiscV,
        _ => return None,
    }))
}

/// Parse a `-ms=` value into `(solid, block_bytes, block_files)` updates.
fn parse_solid(v: &str, o: &mut SevenZWriteOptions) -> Option<()> {
    if let Some(b) = on_off(v) {
        o.solid = b;
        return Some(());
    }
    if v.eq_ignore_ascii_case("e") {
        o.solid = true;
        return Some(());
    }
    let s = v.as_bytes();
    let mut i = 0;
    while i < s.len() {
        let start = i;
        while i < s.len() && s[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            return None;
        }
        let n: u64 = v[start..i].parse().ok()?;
        let unit = s.get(i).map(|c| c.to_ascii_lowercase());
        let mult: u64 = match unit {
            Some(b'f') => {
                o.solid_block_files = usize::try_from(n).ok()?;
                i += 1;
                continue;
            }
            Some(b'b') => 1,
            Some(b'k') => 1 << 10,
            Some(b'm') => 1 << 20,
            Some(b'g') => 1 << 30,
            Some(b't') => 1 << 40,
            None => 1 << 20,
            _ => return None,
        };
        if unit.is_some() {
            i += 1;
        }
        o.solid_block_bytes = n.checked_mul(mult)?;
    }
    o.solid = true;
    Some(())
}

/// Parse the arguments that follow the `a` command for a 7z output.
pub fn parse_7z_add_args(args: &[OsString]) -> Result<SevenZAddArgs, String> {
    let mut level = 5u8;
    let mut method: Option<SevenZMethod> = None;
    let mut filter: Option<Option<BcjArch>> = None;
    let mut solid_switches: Vec<String> = Vec::new();
    let mut hc: Option<bool> = None;
    let mut threads: Option<usize> = None;
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
        if switches_done || !s.starts_with('-') || s.len() == 1 {
            positional.push(PathBuf::from(a));
            continue;
        }
        let bad = || format!("invalid switch: {s}");
        let lower = s.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("-mx") {
            let rest = rest.strip_prefix('=').unwrap_or(rest);
            match rest.parse::<u8>() {
                Ok(n) if n <= 9 && rest.len() == 1 => level = n,
                _ => return Err(bad()),
            }
        } else if let Some(v) = lower.strip_prefix("-m0=").or_else(|| lower.strip_prefix("-m=")) {
            method = Some(match v {
                "lzma2" => SevenZMethod::Lzma2,
                "lzma" => SevenZMethod::Lzma,
                "copy" => SevenZMethod::Copy,
                _ => return Err(format!("unsupported method: {s}")),
            });
        } else if let Some(v) = lower.strip_prefix("-mf=") {
            filter = Some(parse_filter(v).ok_or_else(bad)?);
        } else if let Some(v) = lower.strip_prefix("-ms=") {
            solid_switches.push(v.to_string());
        } else if lower == "-ms" {
            solid_switches.push("on".into());
        } else if let Some(v) = lower.strip_prefix("-mhc=") {
            hc = Some(on_off(v).ok_or_else(bad)?);
        } else if lower == "-mhc" {
            hc = Some(true);
        } else if let Some(v) = lower.strip_prefix("-mmt") {
            let v = v.strip_prefix('=').unwrap_or(v);
            threads = Some(match on_off(v) {
                Some(true) => 0,
                Some(false) => 1,
                None => match v.parse::<usize>() {
                    Ok(n) if (1..=256).contains(&n) => n,
                    _ => return Err(bad()),
                },
            });
        } else if lower == "-t7z" {
        } else if lower == "-y" {
            overwrite = true;
        } else if lower == "-l" {
            follow = true;
        } else {
            return Err(format!("unknown switch: {s}"));
        }
    }
    let mut options = SevenZWriteOptions::level(level).map_err(|_| "invalid level".to_string())?;
    if let Some(m) = method {
        options.method = m;
    }
    if let Some(f) = filter {
        options.filter = f;
    }
    for v in &solid_switches {
        parse_solid(v, &mut options).ok_or_else(|| format!("invalid switch: -ms={v}"))?;
    }
    if let Some(h) = hc {
        options.compress_header = h;
    }
    if let Some(t) = threads {
        options.threads = t;
    }
    if positional.is_empty() {
        return Err("missing archive name".into());
    }
    let archive = positional.remove(0);
    if positional.is_empty() {
        return Err("missing input paths".into());
    }
    Ok(SevenZAddArgs { archive, inputs: positional, options, overwrite, follow_symlinks: follow })
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

/// Run `sediment a` for a 7z archive. `args` are the arguments after `a`.
pub fn run_add_7z(args: &[OsString]) -> i32 {
    let mut err = std::io::stderr().lock();
    let a = match parse_7z_add_args(args) {
        Ok(a) => a,
        Err(m) => {
            let _ = writeln!(
                err,
                "sediment: {m}\nUsage: sediment a [-mx0..9] [-m0=LZMA2|LZMA|Copy] [-mf=BCJ|off] [-ms=on|off|SIZE] [-mhc=on|off] [-mmt=N] [-y] [-l] ARCHIVE.7z PATH..."
            );
            return 2;
        }
    };
    if std::fs::symlink_metadata(&a.archive).is_ok() {
        if std::fs::metadata(&a.archive).map(|m| m.is_dir()).unwrap_or(false) {
            let _ = writeln!(err, "sediment: archive path is a directory");
            return 1;
        }
        if !a.overwrite {
            let _ = writeln!(err, "sediment: archive exists (use -y to overwrite; update is not supported)");
            return 1;
        }
    }
    let options = CollectOptions { follow_symlinks: a.follow_symlinks, strict: false, exclude: vec![a.archive.clone()] };
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
    let entries: Vec<_> = collected.entries.iter().zip(datas.iter()).map(|(e, d)| e.as_archive_entry(d)).collect();
    let bytes = match create_7z(&entries, &a.options, SevenZWriteLimits::default()) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(err, "sediment: cannot build 7z: {e:?}");
            return 1;
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
