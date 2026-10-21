# sediment components

Each component is a few classes in [`sediment.css`](sediment.css). Markup for every state is in [`samples/components.html`](samples/components.html).

## StrataMark

Three stacked chevrons — sediment's only mark — drawn inline at `mark-header` beside the `wordmark`.

**Provide** nothing but a size and, rarely, the `signal` variant. Inline it so it takes `ink` and flips with the theme; outside the app use the Marks SVGs.

- Lockup: mark, `space-8`, lowercase "sediment" in `wordmark`.
- Strokes stay 6.5% of the box at every size; do not thicken small marks.
- Orange only when nothing else in the view is.

```html
<div class="sd-row" style="gap:var(--space-16)">
  <div class="sd-row"><svg class="sd-mark" viewBox="0 0 100 100" aria-hidden="true"><polyline points="8,22 50,38 92,22"/><polyline points="8,45 50,61 92,45"/><polyline points="8,68 50,84 92,68"/></svg><span class="sd-wordmark">sediment</span></div>
  <svg class="sd-mark signal" viewBox="0 0 100 100" aria-hidden="true"><polyline points="8,22 50,38 92,22"/><polyline points="8,45 50,61 92,45"/><polyline points="8,68 50,84 92,68"/></svg>
</div>
```

## Button

A short verb in a `field` well, `control-height` tall; the primary variant fills with `signal`.

**Provide** the label text and the action. Add `primary` for the one action a view exists for (`Extract all…`, `Open archive…`), `small` for the status bar's Details.

- Exactly one primary per view; every other button is default.
- Sentence case, no icons. End the label with `…` when a dialog follows.
- Primary text is `on-signal` in both themes; never white.
- Disabled keeps its label and drops opacity; it is never hidden while a job runs.
- Hover raises the border to `ink`; focus draws a 2px `ink` ring offset 2px.

```html
<div class="sd-row">
  <button class="sd-btn primary">Extract all…</button>
  <button class="sd-btn">Test archive</button>
  <button class="sd-btn">Create ZIP</button>
  <button class="sd-btn" disabled>Cancel</button>
  <button class="sd-btn small">Details</button>
</div>
```

## UtilityLabel

Mono capitals in `utility` and `muted`: how sediment labels formats, counts, sizes and sections.

**Provide** the text; the label uppercases it. Use `keep` for status lines and sizes, which keep their own case.

- Join facts with a spaced slash: `ZIP / TAR / TAR.GZ`.
- Never for sentences addressed to the person; those are `body`.
- Right-align numbers so units stack in a column.

```html
<div style="display:grid;gap:var(--space-8)">
  <span class="sd-util">LOCAL ARCHIVE UTILITY</span>
  <span class="sd-util">ZIP / 4 ENTRIES / 18.1 MB UNPACKED / 12.2 MB STORED</span>
  <span class="sd-util keep">4 entries · archive opened</span>
</div>
```

## ArchiveHeader

The top of an open archive: its file name in `title`, one `utility` line of facts, then actions with the filter pushed right.

**Provide** the file name (full path on hover), format, entry count, unpacked and stored sizes, and the two actions.

- The name truncates with an ellipsis; it never wraps.
- Facts read format first, then count, then sizes, each `/`-separated.
- Followed by a `line` hairline at `space-2` below.

```html
<div style="display:grid;gap:var(--space-8)">
  <h1 class="sd-title">Field recordings.zip</h1>
  <span class="sd-util">ZIP / 4 ENTRIES / 18.1 MB UNPACKED / 12.2 MB STORED</span>
  <div class="sd-row">
    <button class="sd-btn primary">Extract all…</button>
    <button class="sd-btn">Test archive</button>
    <input class="sd-field sd-push" placeholder="Filter files…">
  </div>
</div>
```

## EntryList

The archive's contents: `row-height` rows of glyph, full path in `body`, size right-aligned in `utility`.

**Provide** entries with name, directory flag, size and stored size (shown on hover).

- `+` for a directory, `·` for a file, `—` for a directory's size.
- Paths are shown whole and truncate at the end; never indent to fake a tree.
- Empty states are one `muted` sentence: "This archive is empty." / "No matching files."
- Rows virtualize; do not stripe or zebra them.

```html
<div class="sd-entries">
  <hr class="sd-rule">
  <div class="head"><span class="sd-util">CONTENTS</span><span class="sd-util">SIZE</span></div>
  <hr class="sd-rule">
  <div class="sd-entry"><span class="glyph sd-util">+</span><span class="name">Field recordings/</span><span class="size sd-util keep">—</span></div>
  <div class="sd-entry"><span class="glyph sd-util">·</span><span class="name">Field recordings/01 — Morning static.wav</span><span class="size sd-util keep">15.6 MB</span></div>
  <div class="sd-entry"><span class="glyph sd-util">·</span><span class="name">Field recordings/02 — Night drive.wav</span><span class="size sd-util keep">2.5 MB</span></div>
  <div class="sd-entry"><span class="glyph sd-util">·</span><span class="name">Field recordings/session-notes.txt</span><span class="size sd-util keep">1.2 KB</span></div>
</div>
```

## StatusBar

The window's bottom line: a 5px dot, one `utility` message, and Details; it is the only place progress and errors appear.

**Provide** the message, an error flag, and while a job runs a Cancel action. Details opens the full, copyable text.

- Idle: a `muted` dot. Busy: an orange `…` in place of the dot, plus Cancel. Error: a `signal` dot and the message starts `ERROR /`.
- One line, truncated; the whole text lives in Details.
- Never a toast, banner or modal for routine outcomes.

```html
<div style="display:grid;gap:var(--space-8)">
  <div class="sd-status"><span class="sd-dot"></span><span class="msg sd-util keep">Ready when you are.</span><button class="sd-btn small">Details</button></div>
  <div class="sd-status"><span class="sd-util sd-busy">…</span><span class="msg sd-util keep">Extracting · 9.4 MB of 18.1 MB</span><button class="sd-btn small">Cancel</button><button class="sd-btn small">Details</button></div>
  <div class="sd-status"><span class="sd-dot error"></span><span class="msg sd-util keep">ERROR / checksum mismatch in 02 — Night drive.wav</span><button class="sd-btn small">Details</button></div>
</div>
```

## AppearanceSelect

A 73px select in the header's right corner choosing System, Light or Dark, its value in `utility` capitals.

**Provide** the current preference and a change handler. The menu items are sentence case ("System", "Light", "Dark").

- Last item in the header row, after the actions.
- It changes the theme immediately; there is no Apply.

```html
<div class="sd-row"><span class="sd-select sd-util" tabindex="0">LIGHT</span><span class="sd-select sd-util" tabindex="0">SYSTEM</span></div>
```

## FilterField

A 160px single-line field that narrows the entry list as you type, placeholder "Filter files…".

**Provide** the query and an on-change handler; matching is case-insensitive on the full path.

- Right-aligned in the ArchiveHeader action row.
- No search icon, no clear button, no submit.

```html
<div class="sd-row"><input class="sd-field" placeholder="Filter files…"><input class="sd-field" value="night"></div>
```

## TapeLabel

A `paper` label on a `tape` band with a rotated `utility` side marker — a cassette J-card for naming one archive.

**Provide** a title, one `utility` facts line and a side marker (`SIDE A`, `0.1.3`, `ZIP`).

- Intentional addition: not in the shipped app. Use it on release pages, empty states and docs, at most once per view.
- The ruled lines are `line` at the `body` leading; keep exactly two lines of text.
- Never put actions on it; it is a label, not a card.

```html
<div class="sd-tape">
  <span class="side">SIDE A</span>
  <div class="label"><b>Field recordings.zip</b><i>ZIP / 4 ENTRIES / 12.2 MB</i></div>
</div>
```
