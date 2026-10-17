# sediment CLI 0.1.3 preview

A standalone, local Rust archive utility. Supports ZIP creation and ZIP/TAR/TAR.GZ listing, verification and extraction. No desktop dependencies, accounts or network services. RAR, 7z, encryption, split volumes, archive editing and recovery are unsupported.

Place `sediment` in a directory on your PATH. This candidate targets Apple Silicon macOS; older macOS and clean-machine installation remain unverified. Developer ID signing does not imply notarization or Gatekeeper acceptance.

```sh
sediment list photos.zip
sediment test photos.zip
sediment extract photos.zip
sediment extract photos.zip another-new-folder
sediment create backup.zip Documents/
sediment list photos.zip --json
```

Extraction without a destination creates a folder beside the archive, removing its ZIP/TAR/TAR.GZ/TGZ suffix case-insensitively. Existing destinations are never overwritten; choose another name to resolve a conflict. Names without a usable suffix require an explicit destination. Extraction publishes the new folder only after validation succeeds. Symbolic links and special files are rejected.

## Optional Bash/Zsh shortcut

```sh
eval "$(sediment shell-init)"             # sdm
eval "$(sediment shell-init --alias sed)" # optional sed
sed l photos.zip
sed t photos.zip
sed x photos.zip
sed c backup.zip Documents/
```

`sed` shadows the system text utility in this shell; `command sed` still invokes that utility. `unset -f sed` removes the shortcut. Use `sdm` to avoid the collision. Nothing changes your shell files. To persist, add the chosen eval line to `.zshrc` or `.bashrc`. Regenerate after moving the executable.

Use `--help` on every command. Use `--` before paths beginning with a dash. Ctrl+C cancels cooperatively and waits for cleanup. Exit codes: 0 success, 1 operation failure, 2 invalid usage, 130 cancellation. This executable cannot launch the desktop app.

Results go to stdout, errors to stderr. `--json` emits machine-readable results; extraction reports `destination`, creation reports `output`. `--trace` emits local JSON diagnostics to stderr without filenames or contents. When combined, diagnostic events and any error object are newline-delimited JSON on stderr. Nothing is written to a trace file unless redirected.

The archive includes LICENSE, CHANGELOG.md, THIRD_PARTY_NOTICES.md and docs/UPSTREAM_LICENSES.md. See release notes for the candidate's distribution and verification status.
