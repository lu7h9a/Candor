# GUI redesign audit

Written before the redesign (branch `gui-redesign`), against
docs/design/GUI_REDESIGN_SPEC.md. Updated as deviations are found.

## Toolkit

- `candor-gui` is **egui 0.37 / eframe 0.37** (glow renderer, X11 and
  Wayland), with `egui_extras` (tables) and `egui_plot` (charts).
- Immediate mode: the UI is a pure function of a view-model
  (`model.rs`) that returns `Action`s. Every behaviour is unit-tested on
  the model; the window is tested headless with `egui_kittest`
  (`tests/ui.rs`, `tests/stress.rs`).
- Custom drawing (the Access map, sparklines, status dots) is done with
  egui's `Painter`; nothing in the spec needs a second toolkit.

## Screens before the redesign

Screenshots: `docs/design/before/` (made by `scripts/gui-shots.sh`).

| Screen | Code | Notes |
|---|---|---|
| Top bar | `ui.rs::top_bar` | page buttons, daemon status, mode, filter, Pause, Export, loss counters, multi-user note, unavailable features, notices: all on one wrapped line |
| Loss banner | `ui.rs::loss_banner` | red, dismissible until more events are lost |
| Process table / tree | `ui.rs::procs` | 10 columns, 20 px rows |
| Detail panel | `ui.rs::detail` | right-hand panel, 7 tabs: Overview (two plots), Files, Network, Syscalls, Children, Memory maps, Findings (findings as monospace text) |
| Alerts | `ui.rs::alerts` | bottom panel, one line per alert |
| Daemon down / permission / protocol | `ui.rs::conn_state` | warning box with the fix command |
| Follow confirmation | `ui.rs::confirm_follow` | modal window |
| Act controls | `ui.rs::act_controls` | only when the daemon enables act mode |
| Glasshouse | `ghui.rs` | limitation text, form, file picker, decoy tiles, report with before/after table, timeline, export, all on one scrolling page |

## Where styles live today

- Colours: `Color32::from_rgb` literals scattered through `ui.rs` (12) and
  `ghui.rs` (8); everything else is egui's default dark theme.
- Fonts: egui's built-in fonts; `.monospace()` and `.small()` in places.
- Spacing: egui defaults, a few `add_space` / `inner_margin` literals.

After the redesign every colour, font size, spacing value and radius is a
token in `crates/candor-gui/src/theme.rs`; `scripts/check-theme.sh` fails if
a colour literal or a numeric size appears elsewhere in the GUI crate.

## Data available to the GUI

- `Snapshot` (2 Hz): every process row (CPU, memory, threads, opens,
  connections, execs, children, syscalls, score, top rule, followed),
  loss counters, mode. No system totals: CPU, memory and events per second
  for the stat cards are computed in the client (sum of process CPU / CPU
  count; sum of resident memory; growth of exec+open+connect counts per
  second).
- `Detail` for one process on request: CPU/memory series, the last events
  (`recent`), files (path, opens, read/write flags, last time),
  connections (address, port, count, last time), syscalls, direct
  children, memory maps, findings.
- `Alert` messages (findings), `GhStatus` / `GhReport` for Glasshouse.

## What the spec asks that the toolkit or data cannot do exactly

Each item is built as the nearest equivalent; nothing blocks the Access map
or the Glasshouse flow.

1. **Access map for descendants.** `Detail` is per process. The map asks
   the daemon for the details of the centre process and of its
   descendants (as many as the client's detail cache holds, 16), and
   merges them. Descendants beyond that are drawn as process nodes without
   their files, and the map says so.
2. **Rename, delete and ptrace edges.** `FileStat` only records read and
   write. Renames, deletes, ptrace and listening sockets come from the
   `recent` events in `Detail`, which are bounded, so older ones may be
   missing. The side panel says counts come from what the daemon kept.
3. **First time per node.** Files and connections carry only a last time;
   the first time is taken from `recent` events when present, otherwise
   shown as unknown. The time window slider uses the last time.
4. **Drag-and-drop anywhere on the window** (Glasshouse). eframe delivers
   dropped files to the window; the path is put in the form. Works on
   X11 and Wayland where the compositor supports file drops.
5. **Wayland check.** This machine runs X11; Wayland is checked by
   building with the wayland feature and running under a headless Weston
   only if one is installed. Otherwise listed as not verified.
6. **Inter / JetBrains Mono coverage.** The bundled fonts are the Latin
   subsets; other scripts fall back to egui's built-in fonts.
7. **Decoy choice chips** (SSH keys, Documents, Photos). The daemon always
   places its full decoy set and the protocol has no option for it. The
   chips are shown as information (what is placed), not as toggles.
8. **"Earlier runs" list.** The daemon keeps saved reports but the
   protocol has no call to list them; the GUI lists runs made in this
   window session. Listing saved reports would need a new read-only
   request (not added).
9. **"Try an example".** The README's three-line `try.sh` (reads the decoy
   SSH key, writes a note) is compiled into the GUI; the button uploads
   those bytes directly, so no file is written or shipped.

## Tests whose navigation changes

The redesign moves elements, so `tests/ui.rs` changes how it reaches them.
No assertion is removed or weakened:

- The detail tabs Files, Network, Syscalls, Children and Memory maps move
  under the **Events** view of the detail page; the test opens Events
  before looking for them. Overview, Map, Events and Findings are checked
  on the detail page itself.
- Alerts move to the **Findings** tab; the test opens it before clicking
  the R001 finding, and still checks that the click selects the process
  and shows its findings.
- Sort headers keep the labels `sort-<column>`.
