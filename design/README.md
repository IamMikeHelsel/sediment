# sediment design system

sediment is a local archive utility with the manners of a good tape deck: graphite and white, one orange, and labels that tell you exactly what is inside. Build anything for it — the desktop app, the CLI's docs, a release page — from these rules.

## What is here

| Path | What |
| --- | --- |
| [`tokens.json`](tokens.json) | Every token with its value per theme and a usage note. The source of truth. |
| [`tokens.css`](tokens.css) | The same tokens as CSS custom properties, light by default, dark by `data-theme="dark"` or system preference. Keep it in step with `tokens.json`. |
| [`sediment.css`](sediment.css) | Component classes (`.sd-btn`, `.sd-entry`, `.sd-status`, `.sd-tape`…), built only on the tokens. |
| [`COMPONENTS.md`](COMPONENTS.md) | Each component: what it is, what you provide, the rules, and its markup. |
| [`marks/`](marks/) | The StrataMark as SVG in graphite, paper and signal. |
| [`samples/`](samples/index.html) | Reference screens in light and dark: the empty window, an open archive (idle, busy, error), every component, and the cover. Open `samples/index.html` in a browser. |

Fonts are not checked in. The desktop app uses egui's bundled Ubuntu Light and Hack (the `epaint_default_fonts` crate). For the web, load Ubuntu 300 from Google Fonts and Hack from the `hack-font` package, as the samples do.

## In the desktop app

The tokens come from [`src/gui.rs`](../src/gui.rs). When you change one, change both.

| Token | `gui.rs` |
| --- | --- |
| `signal` | `ORANGE` |
| `on-signal` | `CONTROL_INK` |
| `surface`, `ink`, `muted`, `line`, `field` | `Palette::for_theme` |
| `radius-control`, `radius-window` | `widget.corner_radius`, `window_corner_radius` |
| `space-8`, `space-7` × `space-12`, `control-height` | `item_spacing`, `button_padding`, `interact_size.y` |
| `body`, `control`, `utility` | `TextStyle::Body`, `TextStyle::Button`, `utility()` |

`paper`, `tape` and `TapeLabel` are not in the app yet.

> Less space. Everything in place.

## Principles

- **One ground.** Every region fills with `surface`. Depth comes from recesses (`field`) and 1px `line` hairlines, never shadows or raised cards.
- **One orange.** `signal` marks the single primary action in a view, the selection, and anything busy or wrong. If two things are orange, one of them is lying.
- **Hierarchy by size and ink, not weight.** The sans exists in one weight (Ubuntu Light, 300). Emphasis is a larger style or `ink` over `muted`. Never bold.
- **Two voices.** The sans speaks to the person; the mono (`utility`) labels the machine — formats, counts, sizes, states.
- **Restraint, then one detail.** A view earns at most one flourish: a `TapeLabel`, a StrataMark, a `/` that lines up. Leave the rest quiet.

## Content fundamentals

- The name is always lowercase: **sediment**, also mid-sentence and in the wordmark.
- Buttons are short verbs in sentence case: "Open…", "Create ZIP", "Test archive", "Cancel", "Details". End with an ellipsis exactly when a dialog follows ("Extract all…", "Open archive…").
- Utility labels are capitals in `utility`, joined by a spaced slash: `ZIP / TAR / TAR.GZ`, `ZIP / 4 ENTRIES / 18.1 MB UNPACKED / 12.2 MB STORED`, `LOCAL ARCHIVE UTILITY`.
- Status lines are lowercase fragments with a middle dot: "4 entries · archive opened". Idle is "Ready when you are." Errors lead with `ERROR /` so the word, not only the orange, carries the state.
- Speak plainly about what happens to files: "Files are extracted into a new archive-named subfolder." Say what sediment will not do before it surprises anyone (it never overwrites).
- Sizes are one decimal with a space and a unit: `15.6 MB`, `1.2 KB`. A directory's size is an em dash `—`. In lists a directory is marked `+`, a file `·`.
- No emoji, no exclamation marks, no "Oops".

## Visual foundations

**Color.** `surface` is the ground; `field` fills controls; `ink` is text; `muted` is metadata. `signal` fills the primary button with `on-signal` text in both themes. `line` draws separators and resting control borders; on hover a control's border becomes `ink`. `paper` and `tape` are the cassette label: use them together, once, on a `TapeLabel` or the cover — never as panel fills.

**Type.** Set copy in `body`, buttons in `control`, the archive name in `title`, the empty-state line in `display`, the header name in `wordmark`. Set everything machine-shaped in `utility`, in capitals. Right-align sizes in `utility` so the units stack.

**Spacing.** `space-16` insets every panel; `space-8` separates every sibling. Buttons pad `space-7` × `space-12` and stand `control-height` tall; entry rows are `row-height`. The status bar pads `space-10` × `space-16`. Odd steps (`space-2`, `space-6`, `space-7`) are deliberate; keep them.

**Borders and radii.** One stroke weight, `stroke-hair`. Controls round at `radius-control`, windows at `radius-window`, the app icon at `radius-icon`. Nothing is a pill.

**Layout.** Header (mark, wordmark, actions right-aligned), body, status bar — each separated by a `line` hairline. The window opens at 600 × 420 and grows to at least 760 × 540 once an archive is open.

**States.** Hover: border to `ink`. Disabled: the whole control at reduced opacity, label unchanged. Busy: an orange `…` in the status bar and a Cancel button. Error: the status dot turns `signal` and the line starts `ERROR /`. Focus: a 2px `ink` ring offset 2px from the control — solid, at least 13:1 on `surface` in both themes. Never a `signal` ring: it reads 2.5:1 on the light ground.

**Motion.** None beyond what the platform does. sediment does not animate.

**Imagery.** None. No photographs, illustrations or gradients.

## Iconography

The only mark is the **StrataMark**: three stacked chevrons, strokes 6.5% of the box, inset 8% at the sides, rows 23% apart, each dipping 16%. It is the app's own geometry (`strata()` in [`src/gui.rs`](../src/gui.rs)). Use the SVGs in [`marks/`](marks/): `strata-mark-graphite.svg` on light grounds, `strata-mark-paper.svg` on dark, `strata-mark-signal.svg` sparingly as the single orange in a view.

The lockup is a 23px mark, `space-8`, then "sediment" in `wordmark`. There is no outlined wordmark file; set it live in Ubuntu Light.

Inside the UI, glyphs stand in for icons: `+` directory, `·` file, `—` no size, `…` working, a 5px dot for status. There is no icon set; do not add one.

The current app icon ([`assets/sediment.png`](../assets/sediment.png)) still draws the strata in a legacy green (`#246757`) on `paper`. New work uses graphite or `signal` instead.

## Intentional additions

Not in the shipped UI, added for this direction:

- `paper` and `tape` (the white label and its beige J-card) and the `TapeLabel` component — the one place sediment allows itself some funk.
