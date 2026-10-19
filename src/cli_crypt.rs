// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command-line support for encrypted archives (7-Zip compatible switches):
//!
//! * `-p<password>`: password for `x`/`e`/`t`/`l` (decrypt) and `a`
//!   (encrypt). A bare `-p` (7-Zip's interactive prompt) is rejected: this
//!   command line never reads secrets from the terminal.
//! * `-mem=ZipCrypto|AES128|AES192|AES256` (`a`, `.zip` only): ZIP
//!   encryption method; default ZipCrypto, as in 7-Zip.
//! * `-mhe=on|off` (also `-mhe`; `a`, `.7z` only): encrypt the 7z header
//!   (file names) too.
//!
//! [`take_crypt_switches`] strips these switches so the remaining arguments
//! can go to the existing parsers; [`run_add_crypt`] creates encrypted
//! `.7z` (7zAES, [`crate::sevenz_aes_coder`]) and `.zip`
//! ([`crate::zip_crypt`]) archives. Passwords are taken as UTF-8: UTF-16LE
//! for 7z (format rule), the UTF-8 bytes for ZIP (7-Zip/Info-ZIP on Unix).
//!
//! Exit codes of `a` follow [`crate::cli_add`]: 0 ok, 1 fatal, 2 usage,
//! 3 written with skipped inputs.

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use crate::cli_add::{ArchiveFormat, format_from_name, parse_add_args};
use crate::cli_add_7z::{parse_7z_add_args, run_add_7z};
use crate::fs_collect::{
    ArchiveEntry, CollectError, CollectLimits, CollectOptions, Collected, EntryKind, WarningKind, collect,
    read_entry_data,
};
use crate::sevenz_aes_coder::SevenZAesEncoder;
use crate::sevenz_write::{SevenZWriteLimits, create_7z_with};
use crate::winzip_aes_kdf::WinZipAesStrength;
use crate::zip_create::{ZipCreateLimits, ZipCreateOptions, create_zip};
use crate::zip_crypt::{ZipEncryptLimits, ZipEncryption, encrypt_zip};

/// Longest accepted password, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// Encryption switches found on a command line.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CryptSwitches {
    pub password: Option<String>,
    pub zip_method: Option<ZipEncryption>,
    pub header_encryption: Option<bool>,
}

impl core::fmt::Debug for CryptSwitches {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptSwitches")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("zip_method", &self.zip_method)
            .field("header_encryption", &self.header_encryption)
            .finish()
    }
}

/// Parse a `-mem=` value.
pub fn parse_zip_method(v: &str) -> Option<ZipEncryption> {
    Some(match v.to_ascii_lowercase().as_str() {
        "zipcrypto" => ZipEncryption::ZipCrypto,
        "aes128" => ZipEncryption::Aes(WinZipAesStrength::Aes128),
        "aes192" => ZipEncryption::Aes(WinZipAesStrength::Aes192),
        "aes256" | "aes" => ZipEncryption::Aes(WinZipAesStrength::Aes256),
        _ => return None,
    })
}

/// Remove `-p…`, `-mem=…` and `-mhe…` switches (before `--`) from `args`.
pub fn take_crypt_switches(args: &[OsString]) -> Result<(CryptSwitches, Vec<OsString>), String> {
    let mut sw = CryptSwitches::default();
    let mut rest = Vec::new();
    let mut switches = true;
    for a in args {
        if !switches {
            rest.push(a.clone());
            continue;
        }
        if a == "--" {
            switches = false;
            rest.push(a.clone());
            continue;
        }
        let bytes = a.as_encoded_bytes();
        if bytes.starts_with(b"-p") {
            let pw = std::str::from_utf8(&bytes[2..]).map_err(|_| "password is not valid UTF-8".to_string())?;
            if pw.is_empty() {
                return Err("password prompt is not supported; give the password as -pPASSWORD".into());
            }
            if pw.len() > MAX_PASSWORD_BYTES {
                return Err("password too long".into());
            }
            sw.password = Some(pw.to_string());
            continue;
        }
        let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("-mem=") {
            sw.zip_method = Some(parse_zip_method(v).ok_or_else(|| format!("unsupported encryption method: {v}"))?);
            continue;
        }
        if lower == "-mhe" || lower == "-mhe=on" || lower == "-mhe=+" {
            sw.header_encryption = Some(true);
            continue;
        }
        if lower == "-mhe=off" || lower == "-mhe=-" {
            sw.header_encryption = Some(false);
            continue;
        }
        if lower.starts_with("-mhe") {
            return Err(format!("invalid switch: {lower}"));
        }
        rest.push(a.clone());
    }
    Ok((sw, rest))
}

fn is_7z_name(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|n| n.len() > 3 && n.ends_with(".7z"))
}

/// The archive argument of an `a` command line (first positional).
fn archive_arg(rest: &[OsString]) -> Option<&OsString> {
    let mut switches = true;
    for a in rest {
        if switches && a == "--" {
            switches = false;
            continue;
        }
        let b = a.as_encoded_bytes();
        if switches && b.len() > 1 && b[0] == b'-' {
            continue;
        }
        return Some(a);
    }
    None
}

/// True when `a` must go through [`run_add_crypt`]: any encryption switch
/// was given, or the output is a 7z archive.
pub fn add_needs_crypt(sw: &CryptSwitches, rest: &[OsString]) -> bool {
    sw.password.is_some()
        || sw.zip_method.is_some()
        || sw.header_encryption.is_some()
        || archive_arg(rest).is_some_and(|a| is_7z_name(Path::new(a)))
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

struct Inputs {
    collected: Collected,
    datas: Vec<Vec<u8>>,
    warned: bool,
}

fn gather(archive: &Path, inputs: &[std::path::PathBuf], follow: bool, overwrite: bool) -> Result<Inputs, (i32, String)> {
    if std::fs::symlink_metadata(archive).is_ok() {
        if std::fs::metadata(archive).map(|m| m.is_dir()).unwrap_or(false) {
            return Err((1, "archive path is a directory".into()));
        }
        if !overwrite {
            return Err((1, "archive exists (use -y to overwrite; update is not supported)".into()));
        }
    }
    let options = CollectOptions { follow_symlinks: follow, strict: false, exclude: vec![archive.to_path_buf()] };
    let limits = CollectLimits::default();
    let collected = collect(inputs, &options, limits).map_err(|e| (1, collect_msg(e).to_string()))?;
    let mut warned = false;
    let mut err = std::io::stderr().lock();
    for w in &collected.warnings {
        let _ = writeln!(err, "sediment: warning: {}: {}", w.path.display(), warn_msg(w.kind));
        if w.kind != WarningKind::ExcludedOutput {
            warned = true;
        }
    }
    let mut datas = Vec::new();
    for e in &collected.entries {
        match read_entry_data(e, limits.max_total_bytes) {
            Ok(d) => datas.push(d),
            Err(x) => return Err((1, format!("{}: {}", e.source.display(), collect_msg(x)))),
        }
    }
    Ok(Inputs { collected, datas, warned })
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

fn finish(archive: &Path, inputs: &Inputs, bytes: &[u8]) -> i32 {
    if let Err(m) = write_atomically(archive, bytes) {
        let _ = writeln!(std::io::stderr().lock(), "sediment: {m}");
        return 1;
    }
    let c = &inputs.collected;
    let files = c.entries.iter().filter(|e| e.kind == EntryKind::File).count();
    let _ = writeln!(
        std::io::stdout().lock(),
        "Created {} ({} entries, {} files, {} bytes in, {} bytes out, encrypted)",
        archive.display(),
        c.entries.len(),
        files,
        c.total_bytes,
        bytes.len()
    );
    if inputs.warned { 3 } else { 0 }
}

fn entries_of(inputs: &Inputs) -> Vec<ArchiveEntry<'_>> {
    inputs.collected.entries.iter().zip(inputs.datas.iter()).map(|(e, d)| e.as_archive_entry(d)).collect()
}

/// Run `sediment a` with the encryption switches already taken out of
/// `rest`. Without a password a `.7z` output goes to
/// [`crate::cli_add_7z::run_add_7z`] unchanged.
pub fn run_add_crypt(rest: &[OsString], sw: &CryptSwitches) -> i32 {
    let mut err = std::io::stderr().lock();
    let usage = |err: &mut std::io::StderrLock<'_>, m: &str| {
        let _ = writeln!(
            err,
            "sediment: {m}\nUsage: sediment a -pPASSWORD [-mhe=on] [7z switches] ARCHIVE.7z PATH...\n       sediment a -pPASSWORD [-mem=ZipCrypto|AES128|AES192|AES256] [-mx0..9] [-y] [-l] ARCHIVE.zip PATH..."
        );
        2
    };
    let Some(archive) = archive_arg(rest) else {
        return usage(&mut err, "missing archive name");
    };
    let is_7z = is_7z_name(Path::new(archive));
    let Some(password) = sw.password.as_deref() else {
        if sw.zip_method.is_some() || sw.header_encryption == Some(true) {
            return usage(&mut err, "-mem and -mhe need a password (-pPASSWORD)");
        }
        if !is_7z {
            drop(err);
            return crate::cli_add::run_add(rest);
        }
        drop(err);
        return run_add_7z(rest);
    };
    if is_7z {
        if sw.zip_method.is_some() {
            return usage(&mut err, "-mem applies to .zip archives; 7z always uses AES-256");
        }
        let a = match parse_7z_add_args(rest) {
            Ok(a) => a,
            Err(m) => return usage(&mut err, &m),
        };
        let enc = match SevenZAesEncoder::new(password, sw.header_encryption.unwrap_or(false)) {
            Ok(e) => e,
            Err(e) => {
                let _ = writeln!(err, "sediment: invalid password: {e:?}");
                return 2;
            }
        };
        let inputs = match gather(&a.archive, &a.inputs, a.follow_symlinks, a.overwrite) {
            Ok(i) => i,
            Err((code, m)) => {
                let _ = writeln!(err, "sediment: {m}");
                return code;
            }
        };
        let bytes = match create_7z_with(&entries_of(&inputs), &a.options, SevenZWriteLimits::default(), Some(&enc)) {
            Ok(b) => b,
            Err(e) => {
                let _ = writeln!(err, "sediment: cannot build 7z: {e:?}");
                return 1;
            }
        };
        drop(err);
        return finish(&a.archive, &inputs, &bytes);
    }
    if sw.header_encryption == Some(true) {
        return usage(&mut err, "-mhe applies to .7z archives only");
    }
    let a = match parse_add_args(rest) {
        Ok(a) => a,
        Err(m) => return usage(&mut err, &m),
    };
    if format_from_name(&a.archive) != Some(ArchiveFormat::Zip) {
        let _ = writeln!(err, "sediment: encryption is supported only for .7z and .zip archives");
        return 2;
    }
    let inputs = match gather(&a.archive, &a.inputs, a.follow_symlinks, a.overwrite) {
        Ok(i) => i,
        Err((code, m)) => {
            let _ = writeln!(err, "sediment: {m}");
            return code;
        }
    };
    let entries = entries_of(&inputs);
    let plain = match create_zip(&entries, ZipCreateOptions { level: a.level }, ZipCreateLimits::default()) {
        Ok(z) => {
            for &i in &z.skipped {
                let _ = writeln!(
                    err,
                    "sediment: note: {}: symlink not stored in zip (use -l to store its target)",
                    inputs.collected.entries[i].source.display()
                );
            }
            z.bytes
        }
        Err(e) => {
            let _ = writeln!(err, "sediment: cannot build zip: {e:?}");
            return 1;
        }
    };
    drop(entries);
    let method = sw.zip_method.unwrap_or(ZipEncryption::ZipCrypto);
    let bytes = match encrypt_zip(&plain, password.as_bytes(), method, ZipEncryptLimits::default()) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(err, "sediment: cannot encrypt zip: {e:?}");
            return 1;
        }
    };
    drop(plain);
    drop(err);
    finish(&a.archive, &inputs, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn switches() {
        let (sw, rest) = take_crypt_switches(&os(&["-psecret", "-mem=AES256", "-mhe=on", "-y", "a.7z", "--", "-pfile"])).unwrap();
        assert_eq!(sw.password.as_deref(), Some("secret"));
        assert_eq!(sw.zip_method, Some(ZipEncryption::Aes(WinZipAesStrength::Aes256)));
        assert_eq!(sw.header_encryption, Some(true));
        assert_eq!(rest, os(&["-y", "a.7z", "--", "-pfile"]));
        assert!(!format!("{sw:?}").contains("secret"));
        assert!(take_crypt_switches(&os(&["-p"])).is_err());
        assert!(take_crypt_switches(&os(&["-mem=rot13"])).is_err());
        assert!(take_crypt_switches(&os(&["-mhe=maybe"])).is_err());
        let (sw, _) = take_crypt_switches(&os(&["-mhe=off", "-mem=zipcrypto"])).unwrap();
        assert_eq!(sw.header_encryption, Some(false));
        assert_eq!(sw.zip_method, Some(ZipEncryption::ZipCrypto));
    }

    #[test]
    fn routing() {
        let none = CryptSwitches::default();
        assert!(add_needs_crypt(&none, &os(&["-mx9", "out.7z", "x"])));
        assert!(!add_needs_crypt(&none, &os(&["out.zip", "x"])));
        let pw = CryptSwitches { password: Some("x".into()), ..CryptSwitches::default() };
        assert!(add_needs_crypt(&pw, &os(&["out.zip", "x"])));
        assert_eq!(archive_arg(&os(&["-y", "--", "-odd.zip"])), Some(&OsString::from("-odd.zip")));
    }
}
