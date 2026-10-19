// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sediment command line.
//!
//! Commands (7-Zip style names, see `cli_compat` for the switches):
//!   l [switches] ARCHIVE [NAMES...]   list members (`-slt` technical listing)
//!   t [switches] ARCHIVE [NAMES...]   test integrity
//!   x [switches] ARCHIVE [NAMES...]   extract with full paths
//!   e [switches] ARCHIVE [NAMES...]   extract without directory structure
//!   a [switches] ARCHIVE [NAMES...]   create an archive
//!   h [-scrc<METHOD>]... PATHS...      hash files (see `cli_hash`)
//!   b [ITERATIONS] [switches]          benchmark (see `cli_bench`)
//!   u [switches] ARCHIVE PATHS...      add new / replace newer files (see `cli_update`)
//!   d [-r] ARCHIVE PATTERNS...         delete entries by wildcard (see `cli_update`)
//!   rn ARCHIVE OLD NEW [OLD NEW...]    rename entries (see `cli_update`)
//!   list|test ARCHIVE         original ZIP-only commands (frozen output)
//! Readable formats for l/t/x/e: zip, tar, gzip/bzip2/xz single streams,
//!   tar.gz/tgz, tar.bz2/tbz2/tbz, tar.xz/txz, 7z, cpio, ar, deb, rpm and
//!   xar (see `archive_open`), zstd single streams, tar.zst/tzst and WIM
//!   (see `archive_open_ext`).
//! Encryption (see `cli_crypt`): -p<password> for l/t/x/e/a; for `a`,
//!   -mem=ZipCrypto|AES128|AES192|AES256 (.zip) and -mhe=on (.7z). A
//!   missing or wrong password is a fatal error (exit 2), as in 7-Zip.
//! Streams and volumes: -si / -so, `*.001` split archives and `a -v<size>`
//!   (see `cli_run` and `cli_stdio`).
//! Exit codes for l/t/x/e/a (7-Zip): 0 ok, 1 warning, 2 fatal error,
//!   7 command line error, 8 out of memory, 255 stopped by the user.
//!   `list`/`test`/`--help` keep their frozen codes (1 failure, 2 usage),
//!   as does a missing or unknown command (2). h/b/u/d/rn keep the codes
//!   documented in their modules.
use std::ffi::{OsStr, OsString};
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process;

use sediment_engine::archive_name::escape_name;
use sediment_engine::cli_bench::run_bench;
use sediment_engine::cli_hash::run_hash;
use sediment_engine::cli_update::{run_delete, run_rename, run_update};
use sediment_engine::cli_compat::Command;
use sediment_engine::cli_run::{Console, run_args};
use sediment_engine::zip_decode::entry_data;
use sediment_engine::zip_index::{parse_entries, ZipLimits};

fn err(msg: &'static str, code: i32) -> ! {
    let _ = writeln!(io::stderr().lock(), "sediment: {msg}");
    process::exit(code);
}

fn main() {
    let mut args = std::env::args_os();
    args.next();
    let cmd = args.next();
    if cmd.as_deref() == Some(OsStr::new("--help")) {
        if args.next().is_some() {
            err("too many arguments", 2);
        }
        let mut out = io::stdout().lock();
        if out.write_all(b"Usage: sediment <list|test> ARCHIVE\n").is_err() {
            err("write error", 1);
        }
        if out.flush().is_err() {
            err("flush error", 1);
        }
        return;
    }
    let cmd = match cmd {
        Some(c) => c,
        None => err("missing command", 2),
    };
    let rest: Vec<OsString> = args.collect();
    if cmd == "list" || cmd == "test" {
        legacy(&cmd, rest);
    } else if let Some(command) = Command::from_name(&cmd) {
        let stdin = io::stdin();
        let interactive = stdin.is_terminal();
        let stdout_is_terminal = io::stdout().is_terminal();
        // Unlocked: `a -si` hands standard input to `cli_stdio`, which locks it itself.
        let mut input = io::BufReader::new(stdin);
        let mut stdout = io::stdout().lock();
        let mut stderr = io::stderr().lock();
        let mut con = Console {
            stdout: &mut stdout,
            stderr: &mut stderr,
            stdin: Some(&mut input),
            interactive,
            stdout_is_terminal,
        };
        let code = run_args(command, &rest, &mut con);
        process::exit(code);
    } else if cmd == "h" {
        process::exit(run_hash(&rest));
    } else if cmd == "b" {
        process::exit(run_bench(&rest));
    } else if cmd == "u" {
        process::exit(run_update(&rest));
    } else if cmd == "d" {
        process::exit(run_delete(&rest));
    } else if cmd == "rn" {
        process::exit(run_rename(&rest));
    } else {
        err("unknown command", 2);
    }
}

fn single_path(rest: Vec<OsString>) -> OsString {
    let mut it = rest.into_iter();
    let path = match it.next() {
        Some(p) => p,
        None => err("missing archive path", 2),
    };
    if it.next().is_some() {
        err("too many arguments", 2);
    }
    path
}

/// Original `list`/`test` behavior, byte-identical output and exit codes.
fn legacy(cmd: &OsStr, rest: Vec<OsString>) {
    let path = single_path(rest);
    let p = Path::new(&path);
    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(_) => err("cannot access file", 1),
    };
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        err("invalid file or size limit", 1);
    }
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => err("cannot open file", 1),
    };
    let m = match f.metadata() {
        Ok(m) => m,
        Err(_) => err("cannot read file metadata", 1),
    };
    if !m.is_file() || m.len() > 64 * 1024 * 1024 {
        err("invalid file or size limit", 1);
    }
    let max = 64 * 1024 * 1024;
    let mut buf = Vec::new();
    if buf.try_reserve_exact(max + 1).is_err() {
        err("allocation failed", 1);
    }
    if f.take(max as u64 + 1).read_to_end(&mut buf).is_err() {
        err("read error", 1);
    }
    if buf.len() > max {
        err("file too large", 1);
    }
    let limits = ZipLimits { max_entries: 10000, max_total_size: 64 * 1024 * 1024 };
    let entries = match parse_entries(&buf, limits) {
        Ok(e) => e,
        Err(_) => err("parse error", 1),
    };
    let mut out = io::stdout().lock();
    if cmd == "list" {
        if out.write_all(b"SIZE\tCRC32\tNAME\n").is_err() {
            err("write error", 1);
        }
        for e in &entries {
            let esc = match escape_name(e.name) {
                Ok(s) => s,
                Err(_) => err("escape error", 1),
            };
            if writeln!(out, "{}\t{:08x}\t{}", e.size, e.crc32, esc).is_err() {
                err("write error", 1);
            }
        }
    } else {
        let count = entries.len();
        let per_entry_blocks = 100000usize.checked_div(count).unwrap_or(100000);
        let mut total: u64 = 0;
        for e in &entries {
            let data = match entry_data(&buf, e, e.size, per_entry_blocks) {
                Ok(d) => d,
                Err(_) => err("payload error", 1),
            };
            drop(data);
            total = match total.checked_add(e.size as u64) {
                Some(v) => v,
                None => err("overflow", 1),
            };
        }
        if writeln!(out, "OK\t{count}\t{total}").is_err() {
            err("write error", 1);
        }
    }
    if out.flush().is_err() {
        err("flush error", 1);
    }
}
