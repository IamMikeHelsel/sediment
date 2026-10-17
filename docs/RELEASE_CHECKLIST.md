# sediment macOS preview release checklist

Current target: 0.1.3 local macOS preview, 2026-10-17. Historical results below remain dated. This checklist does not itself certify completion. Keep command output and evidence with the candidate. A built or signed bundle is not evidence of notarization or public availability.

## Before packaging

- [ ] `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --locked --all-targets -- -D warnings` pass.
- [ ] `cargo build --release --locked` succeeds on the intended architecture.
- [ ] Verify ZIP creation, browse, integrity check, extraction, Unicode paths, empty directories, corrupted archives, and unsupported formats.
- [ ] Verify traversal, absolute paths, symlinks, special files, existing destination conflicts, and decompression limits fail safely.
- [ ] Launch the release GUI; verify file dialog cancellation, drag/drop, error presentation, long names, keyboard navigation, window resizing, and a complete create/open/check/extract journey.
- [ ] Confirm cancellation and operation-in-progress UI; explicitly disclose any unsupported cancellation.
- [ ] Review README and interface format claims against implemented capabilities.
- [ ] Inventory locked dependencies, ship required license notices, and review vulnerability advisories. Supplemental exact-commit notices are in UPSTREAM_LICENSES.md. `dispatch 0.2.0` declares MIT but has no standalone license file; supplemental notices reproduce MIT terms and the author named in Cargo.toml, without inventing a copyright year.

## Package

Run `./scripts/package-macos.sh` after the tested release build. It creates `dist/sediment.app`, a versioned architecture-specific ZIP, and a SHA-256 checksum. Its default ad-hoc signature is suitable for a local preview only. The bundle includes project docs and notices when present.

A Developer ID Application signing identity was found in the local keychain during initial inspection. No signing credentials were read. A Developer ID signing attempt stalled for over two minutes and was terminated; no successful distribution signature or notarization is claimed. No notarization profile was assumed. For a distribution candidate, explicitly set `SEDIMENT_SIGN_IDENTITY` to the intended Developer ID Application identity when invoking the packaging script. The script signs with hardened runtime and a timestamp when that variable is set.

## Public distribution gate

- [ ] Decide tested minimum macOS version and supported architecture; test that combination. Do not label a single-architecture build Universal.
- [x] Sign the final bundle with Developer ID; verify with `codesign --verify --deep --strict --verbose=2`.
- [ ] Submit the final ZIP using an existing authorized notarization profile; wait for acceptance.
- [ ] Staple the accepted ticket to the app; recreate ZIP and checksum after stapling.
- [ ] Verify `spctl --assess --type execute --verbose=2 dist/sediment.app` and a clean downloaded/quarantined copy on another Mac.
- [ ] Ensure privacy/support information and release notes describe limitations plainly.
- [ ] Publish only the reviewed artifact and matching checksum at the intended destination.

Not included in the preview acceptance: Windows/Linux packaged builds, RAR compression/decompression, encrypted archives, archive repair, split volumes, shell integrations, fuzzing at scale, or equivalence to WinRAR's mature compatibility corpus.

## Recorded dependency audit

2026-10-15: `cargo-audit 0.22.2 audit --json` completed successfully against 418 locked dependencies. RustSec database commit `edb58f5974b83eb8302332821cb6d389777aa351`, updated 2026-10-14, reported **0 known vulnerabilities** and one informational unmaintained warning for `ttf-parser 0.25.1` (`RUSTSEC-2026-0192`). `cargo tree --locked --target aarch64-apple-darwin -i ttf-parser` reported no reverse dependencies for the macOS target. Track the warning for future targets/dependency upgrades; this result is not a guarantee that no vulnerabilities exist.

Evidence: [cargo-audit JSON](evidence/cargo-audit-2026-10-15.json). Audited Cargo.lock SHA-256: `7556a41283680329d0910083b1251ce3ad0c11458cb548fec2ac42292ea64495`. Re-run after any lockfile change.


## 0.1.2 local hardening evidence

- `scripts/check.sh` passes formatting, strict Clippy, default/GUI-test/CLI-only tests, Ruff and ShellCheck. 26 archive tests, 7 GUI behavior tests, and 7 CLI-only integration tests cover distinct cases (default CLI runs 6 of these). GPU render and 100k-entry release benchmark were explicitly run separately.
- ZIP dependency upgraded from 6.0.0 to 9.0.4 after the current audit identified RUSTSEC-2026-0367, 0368 and 0369. Sediment never used the implicated upstream extraction helpers; the upgrade removes the flagged version.
- Fresh audit: 0 known vulnerabilities, four unmaintained-package warnings (ttf-parser, zbus_names, zvariant, zvariant_derive). These warnings have no reverse dependency in the macOS ARM64 runtime target tested here. Audit database commit `999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b`, lock SHA-256 `560870ca0281138a8faa626b34260e2ee0b7f81965972e68fb667cd2530d1764`.
- Evidence: `evidence/check-hardening-0.1.2.log`, `evidence/cargo-audit-2026-10-17.json`, `evidence/trace-cancellation-0.1.2.json`, `evidence/ui-performance-0.1.2.json`.
- Native CUA inspection still fails at service startup. Linux CI is configured but not executed remotely; no hosted-green claim. Intel/Windows and clean-Mac installation remain unverified.


### Final distribution status, 2026-10-17

Developer ID signing succeeded for the final 0.1.2 app with hardened runtime and a timestamp; `codesign --verify --deep --strict` passes. This supersedes the earlier stalled attempt. Gatekeeper assessment remains rejected as `Unnotarized Developer ID`. No existing notarization profile was found in checked project configuration or environment; credentials were not read or created. Notarization submission, stapling, clean-download acceptance and publication remain open. Native UI reinspection remains blocked by the CUA service startup failure.

## 0.1.3 workflow candidate

See [journey review](USER_JOURNEYS.md) and [draft GitHub release copy](RELEASE_0.1.3.md). This supersedes the 0.1.2 target without changing historical evidence. Repository selection, hosted CI, notarization and native acceptance remain separate gates.
