# GUI redesign audit

Written before the redesign (branch `gui-redesign`), against
docs/design/GUI_REDESIGN_SPEC.md, and updated at the end with every
deviation found while building it.

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

## Deviations found while building

10. **Live Glasshouse counters.** While a run is going the daemon sends
    decoy states but no connection counts, so the running page shows Read,
    Changed and Deleted live and "Connection attempts: counted in the
    report". The "last few events" list shows the decoys touched so far
    (the daemon does not stream the sandbox's raw events to clients).
11. **Changed count.** "Changed" counts each decoy once even if it was
    both modified and renamed, plus new files. The older report line
    ("20 modified, 20 renamed") is kept under the summary sentence so the
    exact counts stay visible.
12. **Glasshouse limitation.** The spec's short caution line is shown with
    an amber dot, and the full limitation statement (plan 6.4) follows it
    in every state, unchanged. Nothing was shortened.
13. **Findings in "What it did".** A flagged step's words are the finding's
    title ("Credential file read") rather than a shorter paraphrase, so
    the GUI never words a finding differently from the rule.
14. **Detail views and the old tabs.** Overview holds the charts, the flow
    and the findings; Events holds a second switch with Event list, Files,
    Connections, Syscalls, Children and Memory maps.
15. **Status and settings menu.** Daemon status, unavailable features and
    "Hide personal details in paths" live in the menu at the top right. The
    "Monitoring all users on this machine" notice stays on the Processes
    page itself (plan 9.1): it is not a setting and must not be hidden.
16. **Map performance numbers** are measured in the headless test harness
    (layout and tessellation on the CPU; `tests/stress.rs`), plus a live
    run on this machine under load (`--frame-stats`). GPU drawing time is
    not part of those numbers.
17. **Wayland.** The GUI is built with the Wayland backend, but no
    Wayland compositor is installed on the build machine and installing
    one writes outside the allowed paths, so Wayland is not verified.
18. **Spec "Show 1 events"**: the button reads "Show 1 event behind this"
    for one event (grammar).

## Owner's changes after the first review (2026-11-15)

The owner asked for these after using the app; they override the spec
where they differ.

19. **Map shapes and colours.** Processes are squares; files, folders and
    connections are circles. Kinds are colour coded (processes light, files
    blue, folders darker blue, connections violet) and lines take the
    colour of the action (started, read, wrote, renamed, deleted,
    connected, ptrace). Red stays reserved for findings. This goes beyond
    the spec's "only teal, red and amber" rule, on purpose; every colour is
    still a token in theme.rs and the legend names each one.
20. **Map layout.** Processes stay in the middle, files on a ring around
    them, connections on an outer ring; files and connections only move
    along their ring, and rings grow with the number of nodes so neighbours
    keep a minimum gap. A cooling schedule ends the layout in bounded time.
21. **Process tree collapsed by default.** Tree view shows top-level
    processes with "N below"; arrows open a branch, Expand all / Collapse
    all open everything; the choice survives updates; a search shows every
    match.
22. **Joining the follow group from the window.** The menu shows whether
    the user may follow processes and offers "Add me to candor-act", which
    runs `pkexec /usr/sbin/usermod -aG candor-act USER`: the system asks
    for the password, the window never sees it. The permission-denied page
    offers the same for the `candor` group. There is no "closed" line: the
    daemon does not record file closes.
23. **Start at login and start minimised** (menu, Settings): an XDG
    autostart entry in ~/.config/autostart, and ~/.config/candor/gui.json.
    A tray icon ("minimise to the tray") needs a StatusNotifierItem library;
    the one that fits (ksni) is under the Unlicense, which deny.toml does
    not allow yet. Waiting for the owner's decision.
24. **All columns shown, each hideable.** The owner asked for every column
    from the start with a checkbox in its header to hide it (the spec had
    five columns and a picker); the Columns menu restores hidden ones.
25. **Folded sub-processes in the table.** A process whose parent runs the
    same executable folds under the topmost one (Brave's renderers under
    Brave), with an arrow and a count; other programs stay listed.
26. **Command-line guide and join command** in the menu, with Copy
    buttons. The menu text is left-aligned (it had been justified, which
    stretched the words) and the checkboxes are drawn so they show on the
    dark theme.

