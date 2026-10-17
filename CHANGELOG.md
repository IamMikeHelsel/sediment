# Release notes

## 0.1.3 — workflow preview

- Enable an optional `sed` or `sdm` Bash/Zsh shortcut without editing shell configuration.
- Use `l`, `t`, `x`, and `c` for list, test, extract, and create.
- Extract into a new folder beside the archive when no destination is supplied.
- Report output paths in human and JSON success results.
- Preserve existing destinations and provide examples in command help.
- Name GUI extraction folders correctly for uppercase archive suffixes and skip existing links.
- Add a ZIP extension when saving, distinguish empty archives from empty searches, and clear unrelated errors when starting a collection.
- Validate package executable versions and architecture; include standalone CLI instructions.

## 0.1.2 — hardening preview

- Cancel archive operations and wait for staging cleanup before closing.
- See operation phases, processed bytes, and completion or cancellation outcomes.
- Browse large archives with cached search and virtualized file rows.
- Recover gracefully from worker failures and distinguish a saved ZIP from a failed preview.
- Use a separate CLI-only build, command help, JSON results, and predictable exit codes.
- Enable local structured diagnostics without logging filenames or contents.
- Buffer archive I/O and strengthen source, metadata, trailer, and extraction checks.
- Upgrade ZIP parsing to a patched dependency release.
- Add reproducible correctness/performance checks and a shared style/test gate.

This remains a preview. Formats are ZIP, TAR, and TAR.GZ; public signing, notarization, and native acceptance are still separate gates.

## 0.1.1 — cassette preview

- Compact desktop layout with graphite and warm-gray surfaces inspired by the drift cassette design language.
- System, light, and dark appearance choices.
- Restrained orange status accents and monospace utility labels.
- Smaller first-use window that expands for archive browsing.
- Archive operations and CLI commands retain the existing preview format support.

Public distribution signing and notarization remain open.

## 0.1.0 — preview

- Open ZIP, TAR, and TAR.GZ archives and browse their contents.
- Filter entry names and inspect archive totals.
- Extract into a new folder without overwriting existing files.
- Create ZIP archives from local files and folders.
- Verify archive readability and ZIP checksums.
- Use the same operations from a command line.
- Run archive work in the background while the interface stays responsive.

This preview does not support RAR, 7z, password-protected archives, split archives, recovery records, editing existing archives, or Finder integration. macOS Apple Silicon is the initial validation target. Public distribution requires signing/notarization and the remaining release checks.
