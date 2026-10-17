# sediment

A small, local-first archive utility written in Rust. A compact cassette-inspired desktop interface for opening archives, checking their contents, extracting into a fresh folder, and creating ZIP files. Includes a CLI using the same archive engine.

**0.1.3 preview:** ZIP, TAR, and TAR.GZ. RAR, 7z, encrypted archives, split archives, recovery records, archive editing, and Finder integration are not supported. This is an independently written archive manager, not a feature-complete WinRAR replacement or a newly authored compression codec. It uses third-party Rust libraries; see the clean-room scope and dependency notices.

## Run

```sh
cargo run --release
cargo run --release -- /path/to/archive.zip
```

Choose System, Light, or Dark appearance from the header. The app starts at 600 × 420 and expands for archive browsing.

Open an archive or drop it onto the window. Use **Extract** to select a parent folder; sediment creates a new child folder and never replaces existing contents. Use **Create ZIP** to package files or a folder.

```sh
sediment list archive.zip
sediment test archive.zip
sediment extract archive.zip new-folder
sediment create bundle.zip file.txt folder/
```

### Short commands

Enable a shortcut in Bash or Zsh after building/installing the updated executable:

```sh
eval "$(sediment shell-init)"             # sdm
# Or choose the requested sed shortcut:
eval "$(sediment shell-init --alias sed)"
sed l photos.zip                         # list
sed t photos.zip                         # verify
sed x photos.zip                         # extract into photos/ beside the archive
sed c backup.zip Documents/              # create
```

`sed` shadows the system text utility in this shell. Use `command sed` for text processing, or `unset -f sed` to remove the shortcut. `sdm` avoids that collision. Nothing edits your shell configuration automatically; add the chosen eval line to your `.zshrc` or `.bashrc` if you want it in future sessions. The generated function points to the exact executable; regenerate it after moving that executable. This setup targets Bash and Zsh.

Extraction without a destination removes `.zip`, `.tar`, `.tar.gz`, or `.tgz` (case-insensitively) and creates a sibling folder. Existing paths are never replaced or silently renamed; supply another destination on a collision. Unusual names without a usable suffix require an explicit destination. Success output names the destination; JSON adds `destination` for extraction and `output` for creation. Use `--` before paths beginning with a dash. To open an archive named like a command in the GUI, use an explicit relative path, such as `sediment ./x`.

All operations run locally. There are no accounts, telemetry, or network services. The GUI reports operation phases and byte counts. Cancel stops the worker and cleans staging files before acknowledging completion; closing a busy window requests cancellation and waits for cleanup. Once an archive has been committed, a late cancel cannot undo it.

## Standalone CLI and diagnostics

Build without any GUI dependencies:

```sh
cargo build --release --locked --no-default-features --target-dir target/cli
./target/cli/release/sediment list archive.zip --json
./target/cli/release/sediment --trace test archive.zip
```

Use `--help` on each subcommand. Exit codes: 0 success, 1 operation failure, 2 invalid usage or GUI unavailable, 130 cancellation. Ctrl+C requests cooperative cancellation with staging cleanup. Results go to stdout; errors and diagnostics go to stderr. Human-readable listing escapes terminal control characters in archive names. `--json` gives structured results and operation errors. Combining `--json` and `--trace` produces newline-delimited diagnostic JSON on stderr, followed by an error object if the operation fails; stdout remains a single result object on success.

`--trace` or `SEDIMENT_TRACE=1` enables local JSON diagnostics with operation phases, counts, durations and outcomes. Diagnostic events exclude filenames, paths, file contents and raw error strings. Ordinary user-facing errors can include paths. No trace is written to disk unless you redirect stderr. Core library callers use `OperationControl` for cancellation and progress.

```sh
./scripts/package-cli.sh
python3 scripts/trace-smoke.py --binary target/cli/release/sediment --output docs/evidence/trace-cancellation-0.1.2.json
```

The CLI archive contains a standalone `sediment` executable; place it in a directory on your PATH. The CLI package does not install or launch the desktop app.

## Build and validate

```sh
./scripts/check.sh
cargo test --locked --features gui-test render_cassette_previews -- --ignored
cargo build --release --locked
./scripts/package-macos.sh
```

The macOS packaging script creates an app bundle and distribution ZIP. Default packaging is ad-hoc signed for local use; public distribution needs Developer ID signing and Apple notarization. Other platforms have not been validated.

See [clean-room scope](docs/CLEAN_ROOM.md), [release checklist](docs/RELEASE_CHECKLIST.md), and [release notes](CHANGELOG.md).

Style and test policy: [STYLE_AND_TESTING.md](docs/STYLE_AND_TESTING.md). Host-specific performance reports and synthetic trace evidence live in `docs/evidence/`. The archive engine has conservative entry, expanded-size, path-depth and metadata limits. Links, special files, sparse TAR entries, multiple gzip members, nonzero TAR trailers, and existing output paths are rejected. These restrictions favor safe, predictable extraction over full format compatibility.

The 0.1.3 candidate requires signature verification and notarization before public release. Gatekeeper acceptance and clean-machine installation are still open; do not treat this preview as a public-ready release. The separate CLI package is built from the GUI-free feature set.
