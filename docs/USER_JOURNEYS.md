# 0.1.3 user journey review

Review scope: production GUI control flow, egui behavior tests, actual archive workers, CLI subprocesses, and GPU-rendered layouts. Native computer-use inspection was attempted again and failed before connecting: `Sky Computer Use native pipe startup failed`. Native dialogs and a clean downloaded installation are not accepted by these tests.

| Journey | Expected behavior | Evidence / result |
| --- | --- | --- |
| First launch | Compact window, visible Open/Create choices, supported formats | Source review and light/dark/minimum GPU layouts; native first launch pending |
| Open or drop a supported archive | Inspect contents without extracting; retain previous archive if opening another fails | Shared inspect worker, source review; unsupported drop behavior tested |
| Browse/search | Filter quickly without changing archive contents or extraction scope | Cached search/virtualized rows tested; action explicitly says Extract all |
| Empty archive or no search matches | Different messages, no misleading search failure for an empty archive | New GUI behavior test |
| Test archive | Read/verify archive and report completion or actionable error | Real worker round trip plus corrupt-archive CLI test |
| Extract | Choose parent; create a fresh named child; never replace existing contents; show final path | Real GUI worker test preserves existing directory and checks extracted bytes |
| Extract unusual names | Uppercase compound suffix removed; suffix-only names use Extracted; dangling links count as occupied | New extraction naming/collision tests |
| Create ZIP | Add/remove/deduplicate inputs, save, append .zip if needed, browse saved archive | Real worker create→preview→verify→extract test with Unicode input |
| Cancel file chooser | Leave archive/draft and filesystem unchanged | Source guards only start work for Some(path); native chooser behavior pending |
| Save/open fails | Explain failure and retain retry context; successful save with failed preview remains a success | Preview-failure, panic recovery, corruption/rollback tests |
| Start a new collection after failure | Clear unrelated error, retain collection draft | New button-driven GUI test |
| Cancel operation or close while busy | Request cancellation; wait for worker cleanup before close | GUI behavior tests, core cancellation tests, real CLI SIGINT smoke |
| Use terminal only | No GUI dependency; help, aliases, JSON, tracing and predictable exits | CLI-only build and 10 subprocess integration tests |
| Use sed shortcut | Explicit Bash/Zsh setup; preserve argument quoting; system sed accessible via command sed | Actual shell execution with spaces/apostrophe in executable path |
| Install downloaded release | Verify architecture/signature, pass Gatekeeper, launch app, operate native dialogs | Still open: notarization and clean-Mac/native acceptance |

## Resolved during review

- GUI extraction previously mishandled uppercase `.TAR.GZ` names and used an existence check that missed dangling symlinks.
- Save ZIP could accept a name without a ZIP suffix.
- Empty archives showed the same message as an unsuccessful search.
- Starting a new collection could retain an unrelated previous error.
- Package scripts could label an older executable as the current version; now they check version and macOS architecture.
- CLI package instructions linked to absent project documents; it now includes a self-contained CLI README and release notes. Archive output is staged before replacing a prior package.

## Deliberate scope

Filtering only affects browsing. Extraction always extracts all entries. GUI collisions choose numbered new folders; CLI collisions fail so scripts retain predictable destinations. Existing files are never replaced. RAR, 7z, encryption, split archives, archive editing and Finder file associations remain unsupported. Theme choice is session-local. Opening an archive from Finder by file association is not advertised.

## Native acceptance before public release

On a clean Apple Silicon Mac: download the final notarized ZIP, verify checksum, drag the app to Applications, launch through Gatekeeper, open/cancel each native chooser, drop an archive and a folder, create/test/extract a Unicode fixture, cancel a large operation and close while busy, exercise keyboard navigation and minimum window size in both themes, and confirm extracted bytes independently. Test the proposed oldest supported macOS version before claiming compatibility with it. The binary deployment target alone does not establish that support.
