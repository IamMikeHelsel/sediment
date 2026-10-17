# sediment 0.1.3 — workflow preview

Draft GitHub release copy. Intended as a prerelease until notarization and native acceptance are complete. No publication is implied by this file.

sediment is a compact, local archive utility with light and dark cassette-inspired styling and a separate Rust CLI.

## What's included

- Open, browse, filter, verify and extract ZIP, TAR and TAR.GZ archives.
- Create ZIP files from files and folders, with cancellable background work and cleanup.
- Extract into fresh folders without replacing existing files.
- Use the independent CLI with JSON output, local tracing and short l/t/x/c commands.
- Opt into a Bash/Zsh `sed` or `sdm` shortcut. `sed` shadows the text utility in that shell; `command sed` remains available.
- Improved archive naming, empty-state messages and recovery after errors.

## Downloads

- `sediment-0.1.3-macos-arm64.zip`: desktop app for Apple Silicon Macs.
- `sediment-0.1.3-cli-darwin-arm64.tar.gz`: standalone CLI, no desktop dependencies.
- Matching `.sha256` checksum files.

Desktop: unzip and move sediment.app into Applications. CLI: unpack and place sediment on PATH. Run `sediment --help`; enable the optional shortcut with `eval "$(sediment shell-init --alias sed)"` in Bash or Zsh.

## Preview limits

RAR, 7z, encrypted/split archives, archive editing, recovery records and Finder file associations are unsupported. This is an independently implemented archive manager using third-party codec libraries, not WinRAR compatibility or a newly implemented compression codec. No accounts or telemetry.

This candidate is intended for Apple Silicon macOS. Older macOS versions, Intel, Windows and Linux packages have not been accepted. Developer ID signing is separate from notarization. Do not mark this release public-ready until its final artifact passes notarization, Gatekeeper and clean-machine/native workflow acceptance.

## Maintainer handoff

1. Confirm the GitHub destination. Local checkout has no remote or commits; existing private IamMikeHelsel/sediments contains a Python implementation and must retain its history. No force-push or replacement has been authorized.
2. Integrate reviewed Rust source without overwriting the existing project, commit it, run hosted CI on that exact commit, and record the source commit in the release manifest.
3. Complete native acceptance in USER_JOURNEYS.md and declare the tested macOS range.
4. Submit signed artifacts using an existing authorized notarization profile. Staple the app ticket, rebuild its ZIP/checksum, and assess the final downloaded app with Gatekeeper. Notarize the CLI distribution as well; assess its downloaded executable.
5. Refresh the release manifest and attach only final reviewed ZIP/tar.gz files and checksums to a draft GitHub prerelease. Review this copy against actual results before publishing.

The local 0.1.3 evidence is in USER_JOURNEYS.md and evidence/check-workflows-0.1.3.log. A draft release description is not a hosted GitHub release.
