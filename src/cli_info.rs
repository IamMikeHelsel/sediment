// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `i` command: supported formats, codecs and hashers, laid out in the
//! sections of 7-Zip's `7z i` report (`Formats:`, `Codecs:`, `Hashers:`).
//!
//! Spec sources: the public 7-Zip command-line documentation (the `i`
//! command), the 7z format document's method ID list (7zFormat.txt /
//! Methods.txt) for codec IDs. The rows describe what the Sediment binary
//! actually does through `l`/`t`/`x`/`e`/`a`/`h`: every format row is a
//! format `archive_open` can open (and, with `W`, `a` can create), and the
//! (`.Z` is left out until the forge `lzw_z` decoder is wired.) The
//! hasher rows come straight from [`crate::hash_multi::ALL_METHODS`]. No
//! 7-Zip source was used.
//!
//! Row layouts:
//! * format: ` R W  name      ext ext ...` (`W` replaced by a space when
//!   read only),
//! * codec: ` D E  id        name` (method ID in hex, `-` when the codec has
//!   no 7z ID),
//! * hasher: `  size  name` (digest size in bytes).

use std::ffi::OsString;
use std::io::Write;

use crate::cli_compat::{EXIT_CMDLINE, EXIT_FATAL, EXIT_OK};
use crate::hash_multi::ALL_METHODS;

/// One archive format row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatInfo {
    pub name: &'static str,
    /// File name extensions, without dots.
    pub extensions: &'static [&'static str],
    pub read: bool,
    pub write: bool,
}

/// One codec row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecInfo {
    pub name: &'static str,
    /// 7z method ID, when the codec has one.
    pub id: Option<u64>,
    pub decode: bool,
    pub encode: bool,
}

const fn fmt(name: &'static str, extensions: &'static [&'static str], write: bool) -> FormatInfo {
    FormatInfo { name, extensions, read: true, write }
}

/// Formats reachable through the CLI (see `archive_open`,
/// `archive_open_ext`, `legacy_open`, `volume_io` and `cli_run::add_target`).
pub const FORMATS: [FormatInfo; 16] = [
    fmt("7z", &["7z"], true),
    fmt("zip", &["zip", "zipx", "jar", "xpi", "odt", "ods", "docx", "xlsx", "epub", "apk"], true),
    fmt("tar", &["tar"], true),
    fmt("gzip", &["gz", "gzip", "tgz"], true),
    fmt("bzip2", &["bz2", "bzip2", "tbz2", "tbz"], true),
    fmt("xz", &["xz", "txz"], true),
    fmt("Split", &["001"], true),
    fmt("zstd", &["zst", "tzst"], false),
    fmt("wim", &["wim", "esd"], false),
    fmt("Cpio", &["cpio"], false),
    fmt("Ar", &["ar", "a", "lib"], false),
    fmt("deb", &["deb"], false),
    fmt("Rpm", &["rpm"], false),
    fmt("Xar", &["xar", "pkg"], false),
    fmt("Lzh", &["lzh", "lha"], false),
    fmt("Arj", &["arj"], false),
];

const fn codec(name: &'static str, id: Option<u64>, encode: bool) -> CodecInfo {
    CodecInfo { name, id, decode: true, encode }
}

/// Codecs (7z method IDs from the public method list).
pub const CODECS: [CodecInfo; 23] = [
    codec("Copy", Some(0x00), true),
    codec("Delta", Some(0x03), false),
    codec("BCJ", Some(0x0303_0103), true),
    codec("PPC", Some(0x0303_0205), true),
    codec("IA64", Some(0x0303_0401), true),
    codec("ARM", Some(0x0303_0501), true),
    codec("ARMT", Some(0x0303_0701), true),
    codec("SPARC", Some(0x0303_0805), true),
    codec("ARM64", Some(0x0A), true),
    codec("RISCV", Some(0x0B), true),
    codec("Swap2", Some(0x02_0302), false),
    codec("Swap4", Some(0x02_0304), false),
    codec("LZMA", Some(0x03_0101), true),
    codec("LZMA2", Some(0x21), true),
    codec("Deflate", Some(0x04_0108), true),
    codec("Deflate64", Some(0x04_0109), false),
    codec("BZip2", Some(0x04_0202), true),
    codec("7zAES", Some(0x06F1_0701), true),
    codec("ZSTD", None, false),
    codec("LZX", None, false),
    codec("XPRESS", None, false),
    codec("LZMS", None, false),
    codec("LZH", None, false),
];

/// The whole `i` report.
pub fn info_text() -> String {
    let mut s = format!("Sediment {} : 7-Zip compatible archiver\n\n", env!("CARGO_PKG_VERSION"));
    s.push_str("Formats:\n");
    for f in &FORMATS {
        let r = if f.read { 'R' } else { ' ' };
        let w = if f.write { 'W' } else { ' ' };
        s.push_str(&format!(" {r} {w}  {:<9} {}\n", f.name, f.extensions.join(" ")));
    }
    s.push_str("\nCodecs:\n");
    for c in &CODECS {
        let d = if c.decode { 'D' } else { ' ' };
        let e = if c.encode { 'E' } else { ' ' };
        let id = c.id.map_or_else(|| String::from("-"), |v| format!("{v:X}"));
        s.push_str(&format!(" {d} {e}  {id:>9}  {}\n", c.name));
    }
    s.push_str("\nHashers:\n");
    for m in ALL_METHODS {
        s.push_str(&format!(" {:>4}  {}\n", m.digest_len(), m.name()));
    }
    s
}

/// Run `sediment i`. Takes no names; `-ba` is accepted (the report has no
/// banner to drop). Returns the 7-Zip exit code.
pub fn run_info(args: &[OsString], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    for a in args {
        if !a.as_encoded_bytes().eq_ignore_ascii_case(b"-ba") {
            let _ = writeln!(err, "sediment: unsupported argument for i: {}", a.to_string_lossy());
            return EXIT_CMDLINE;
        }
    }
    if out.write_all(info_text().as_bytes()).and_then(|_| out.flush()).is_err() {
        let _ = writeln!(err, "sediment: write error");
        return EXIT_FATAL;
    }
    EXIT_OK
}
