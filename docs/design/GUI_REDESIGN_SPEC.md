# Candor GUI redesign spec

Audience: the coding agent (Opus in Claude Code) working in the Candor repo.
Owner: Anshul. Written 2026-11-15.

This spec was written from the README and a set of mockups, without access to
the GUI source. Where it conflicts with what the code or toolkit can do, follow
section 2 ("Before you change anything").

## 1. Goal

Make `candor-gui` calm, minimal and easy to use, and restyle the CLI output to
match. The data and features already work. The owner's complaints are:

- The GUI looks cluttered and is cumbersome to use.
- Glasshouse is not self-explanatory. Even the owner does not know how to use
  it from the GUI.
- There is no visual way to see what one process touched.

Three outcomes:

1. A new visual system (section 3) applied to every screen.
2. A new **Access map**: an Obsidian-graph-style view of everything one
   process touched (section 6).
3. A Glasshouse flow a first-time user can complete without reading docs
   (section 7).

### Not in scope

- No changes to eBPF probes, rules, scoring, or the daemon's privileges.
- No light theme. Keep all colours in one theme module so one can be added later.
- No new network access of any kind. Fonts are bundled, never downloaded.
- Do not soften or remove any safety or limitation wording (Glasshouse is not
  containment; events not recorded are always shown).

## 2. Before you change anything

1. Read the GUI crate and identify the toolkit, how styles are set, and how
   screens are structured. Write a short `docs/design/AUDIT.md`: toolkit, list
   of current screens, where colours and fonts are defined, and anything in
   this spec the toolkit cannot do.
2. Take "before" screenshots of every screen into `docs/design/before/`.
3. Create one theme module holding every token from section 3. No colour,
   font size or spacing literal may appear outside it when you finish.
4. If the toolkit cannot do something here (for example a custom-drawn graph),
   build the nearest equivalent, and record the difference in `AUDIT.md`.
   Ask the owner only if the Access map or Glasshouse flow cannot be built at all.
5. If the Access map needs data the client protocol does not expose, prefer
   building it from what `candor detail PID` already returns. Extend the
   protocol only if needed, read-only, with tests, and note it in the CHANGELOG.

## 3. Visual system

### Colour tokens

| Token | Hex | Use |
|---|---|---|
| `bg` | `#0E1113` | Window background, input fields |
| `surface` | `#151A1D` | Cards and panels |
| `surface-raised` | `#222A2E` | Selected segment, secondary buttons, borders |
| `hairline` | `#1A2023` | Row dividers |
| `text` | `#C9D1D5` | Body text |
| `text-strong` | `#FFFFFF` | Names, headings, the value in focus |
| `text-dim` | `#9AA5AB` | Labels, column headers, hints |
| `accent` | `#2DD4BF` | Active tab, selection, follow mode, primary button, chart line |
| `accent-bg` | `#17201F` | Background of an active tab or chip |
| `alert` | `#F47C7C` | Findings only |
| `caution` | `#E8B45A` | "Worth a look" and warnings only |
| `node-process` | `#E6ECEF` | Process dots in the map |
| `node-file` | `#7C8A91` | File dots in the map |
| `node-minor` | `#56636A` | Low-activity dots |
| `edge` | `#3A464C` | Map lines, flow connectors |

Rules:

- Teal means "selected or active". Red means "finding". Amber means "caution".
  Nothing else is coloured. No gradients, no shadows, no coloured borders on cards.
- Never rely on colour alone: a finding always has a dot plus a text label or score.
- Body text must keep at least 4.5:1 contrast on its background.

### Type

- **Inter** (400, 500, 600) for all labels and prose.
- **JetBrains Mono** (400, 500) only for numbers, PIDs, paths, commands, syscalls.
- Bundle both fonts in the binary (both are OFL licensed; add the licence files).
- Sizes: 12 labels and column headers, 13 table numbers and secondary text,
  14 body, 15 section titles, 20 page title, 32 big stat numbers.

### Spacing and shape

- Spacing scale: 4, 8, 12, 16, 24, 32, 40. Page padding 40 horizontal, 28 top.
- Card radius 12, button and input radius 8, chips fully round.
- Table rows at least 52 tall. Buttons and inputs at least 44 tall.
- Cards have no border; they are separated from the background by colour only.
- Roomy by default: fewer things per screen, more space between them.

### Shared components

- **Status dot**: 8 px circle, `alert` or `caution`, placed before a name. Rows
  without a finding keep an empty 8 px slot so names stay aligned.
- **Stat card**: dim label, 32 px mono number, 120x40 sparkline on the right.
- **Sparkline**: 1.5 px line, no axes, no fill. `accent` in stat cards,
  `text-dim` inside table rows.
- **Line chart**: one series, 2 px `accent` line, three faint horizontal
  gridlines, mono axis labels in `text-dim`, value shown on hover.
- **Segmented switch**: `surface` track, `surface-raised` selected segment.
- **Chip**: round filter toggle with a count, `accent-bg` + `accent` when on.
- **Primary button**: `accent` fill, `bg` text. One per screen at most.
- **Secondary button**: `surface-raised` fill, white text.
- **Text button**: `accent` text, no background.

## 4. Navigation

Top bar, left to right: the word "candor", three tabs (**Processes**,
**Findings**, **Glasshouse**), a search field on the right. Settings and
daemon status move behind a small menu at the far right. If the daemon is not
reachable, replace the page with one centred message and the exact command to
fix it (`sudo systemctl enable --now candord`).

Keyboard: `/` focuses search, `Esc` goes back one level, arrow keys move in
the table, `Enter` opens the selected process, `f` follows it.

## 5. Processes

### 5.1 Overview (default screen)

- **Stat strip**: three stat cards: CPU, Memory, Events / sec. Under Events,
  a dim line "N not recorded" that turns `caution` when N > 0.
- **Heading**: "142 processes · 2 flagged", with a Table / Tree switch on the right.
- **Table**: five columns only: Process (dot, name, dim PID), CPU (sparkline
  and %), Memory, Connections, Score. Threads, files opened and children move
  to a column picker and are off by default.
- Default sort: score descending, then CPU. Click a header to sort.
- Score colour: `alert` when it has a finding, `caution` when worth a look,
  `text-dim` otherwise.
- **Tree** shows the same columns with indentation and thin `edge` connectors.
- Clicking a row opens the process detail. Updates must not move the row
  under the pointer or lose the selection.

### 5.2 Process detail

Header: back link "Processes", dot, name, PID, and a "Follow this process"
outlined button (becomes a filled teal "Following" state with "Stop").
Below it a three-way switch: **Overview**, **Map**, **Events**.

**Overview** contains:

- A chart card with tabs CPU / Memory / Syscalls, one chart visible at a time.
- A "What it did" card: a short vertical flow of the most important steps, in
  time order, as small mono boxes joined by thin lines, each with a few words
  beside it ("started", "which ran", "SSH key read"). Show at most 6 steps:
  parent, the process, then flagged actions first, then the highest-volume
  actions. A "See everything in the map" text button at the bottom.
- One card per finding with three short columns: **What happened**,
  **Why it is flagged**, **Harmless explanation**, and a text button
  "Show N events behind this" that expands the evidence in place.

**Events** is the existing raw event list, restyled: mono, one line per
event, filter chips for kind (exec, file, network, other).

## 6. Access map

This is the main new feature. It answers "what did this process touch?" at a
glance and supports real analysis.

### 6.1 What is drawn

- **Centre node**: the selected process, teal ring.
- **Process nodes**: its parent and every descendant.
- **File nodes**: files it or its descendants opened, wrote, renamed or deleted.
- **Network nodes**: outbound endpoints (`ip:port`) and listening sockets.
- **Edges**: from the process that acted to the thing acted on, with a short
  label: started, read, wrote, renamed, deleted, connected, listening, ptrace.
- **Size**: dot radius grows with the log of the event count.
- **Colour**: `node-process`, `node-file`, `accent` outline for network,
  `node-minor` for low-activity, `alert` for anything tied to a finding.
  A flagged node also gets a thin outer ring and its edge is drawn in `alert`.
- **Legend** under the map, including "Bigger dot = more activity".

### 6.2 Layout and motion

- Force-directed layout (repulsion between nodes, springs on edges, gentle
  pull to centre), like Obsidian's graph view.
- Run the simulation until it settles, then stop. The map must not drift or
  jitter while idle.
- When new nodes arrive, place them near the node they connect to, fade them
  in, and relax only the neighbourhood. Never re-shuffle the whole map.
- Dragging a node pins it. Double-click on empty space resets the view.

### 6.3 Interaction

- Drag background to pan, scroll to zoom. Labels hide below a zoom threshold
  except for the centre, flagged and hovered nodes.
- **Hover** a node: it and its direct neighbours stay bright, everything else
  dims to 25%.
- **Click** a node: select it and fill the side panel (6.4).
- **Double-click a process node**: re-centre the map on that process.
- **Filter chips** with counts: Files, Processes, Network, Flagged only.
- **"Hide common system files"** toggle, on by default: collapses shared
  libraries, locale files, `/proc`, `/sys`, `/dev` and loader caches into one
  "System files (N)" node that expands on click.
- **Grouping**: when a directory holds more than 8 touched files, draw one
  folder node "dir/ (N files)" that expands on click.
- **Time window**: a slider from process start to now. Nodes and edges outside
  the window fade out. This is how a user replays what happened in order.
- **Search in map**: typing highlights matching nodes and dims the rest.
- Keyboard: Tab cycles nodes in order of activity, Enter selects, `+`/`-` zoom.

### 6.4 Side panel

For the selected node show: full path or address, Kind, Touched by (process
and PID), Action with count, first and last time. If it is tied to a finding,
show the finding title, one line of why, and an "Open finding" text button.
Then the last 20 events for that node, with "Open in Events".
With nothing selected, show a summary: counts by kind, and the top 5 nodes by activity.

### 6.5 Limits

- Cap at 150 visible nodes. Beyond that, group the least-active nodes into
  "+N more" cluster nodes. State the cap on screen when it applies.
- 60 fps while idle and while panning with 150 nodes on the dev machine.
  Layout work must not block the UI thread.
- Paths shown in the map obey the same redaction rules as exports when
  redaction is enabled.
- Empty state: "This process has not opened any files or connections yet."

## 7. Glasshouse

The current screen has the right data but nobody can tell what to do. Rebuild
it as three states of one page.

### 7.1 Start

- Title "Glasshouse" and one sentence: "Run a program in a room full of fake
  files and see exactly what it touches."
- Three numbered steps in a row, always visible:
  1. **Choose a program**: a script or binary on this computer.
  2. **Candor runs it**: with a fake home folder and no network.
  3. **Read the report**: what it read, changed, deleted and tried to reach.
- One form card:
  - "Program to run": path field, Browse button, and drag-and-drop anywhere
    on the window.
  - "Arguments (optional)".
  - "Stop after": 30 seconds (default), 2 minutes, 10 minutes.
  - "Decoys placed in the fake home": chips for SSH keys, Documents, Photos.
  - The caution line, with an amber dot, always visible, not dismissible:
    "Glasshouse shows behaviour. It does not contain malware. The program
    shares this computer's kernel, so only run things you would accept losing
    this machine to. For real samples, use a separate virtual machine."
  - Primary button "Run in Glasshouse", disabled until a valid executable is chosen.
- "Earlier runs" list below: name, time, and "N read · N changed · N deleted
  · N connections". Clicking one opens its report.
- A "Try an example" text button that fills the form with the bundled demo
  script from the README, so a new user can see a full run in one click.

### 7.2 Running

Replace the form with: program name, elapsed time, a Stop button, and four
live counters (Read, Changed, Deleted, Connection attempts). Below, the last
few events as they happen. When it ends, go straight to the report.

### 7.3 Report

- Header: "Glasshouse / name", "ran 4.2s · exit 0 · time", and buttons
  **Open map**, **Export**, **Run again**.
- **Summary sentence** in plain language at the top, generated from the
  counts, for example: "It read a decoy SSH key and created one file. It did
  not delete anything or try to reach the network."
- Four count cards: Read, Changed, Deleted, Connection attempts. A count is
  `alert` when it involves a decoy secret, white when non-zero, dim when zero.
- **Before / After**: two columns listing the fake home. In After, mark each
  touched file on the right with read, changed, deleted or new. Unchanged
  files stay in normal text. Long lists collapse unchanged files behind
  "N unchanged".
- Connection attempts, if any, as a list of address, port and count.
- Findings raised during the run, using the same finding card as 5.2.
- A dim note at the bottom: "The program could tell it was in a sandbox and
  may behave differently outside it."
- **Open map** shows the section 6 map for the sandboxed process tree.

### 7.4 Unavailable

If Glasshouse cannot run (bubblewrap missing, or user namespaces blocked as on
Ubuntu 24.04), show the Start page with the form disabled and one card saying
why, in plain words, with the exact reason the daemon reports. Do not offer to
change system settings.

## 8. Findings tab

A list of finding cards, newest first, each with dot, title, process name and
PID, time, and the three-column explanation collapsed to its first line.
Filter chips by rule. Clicking the process name opens its detail.
Empty state: "Nothing flagged so far."

## 9. Terminal output

Restyle the existing commands. Do not change flags, exit codes, JSON output
or column meaning.

- Aligned columns, dim header row, names in bright white.
- A leading `●` in red for a finding and amber for worth a look; two spaces otherwise.
- Score coloured the same way. Teal for the followed process.
- A dim one-line footer on `top`: "142 processes · 2 flagged · 0 events not recorded".
- `findings` prints each finding as a title line then three indented labelled
  lines (What happened, Why flagged, Harmless explanation).
- `glasshouse run` ends with the same summary sentence and four counts as 7.3.
- Colour only when stdout is a terminal. Respect `NO_COLOR` and add
  `--color=auto|always|never`. Piped output must be plain text with no escape codes.

## 10. Wording

Plain words, short sentences, sentence case. No jargon where a common word
works ("connections" not "sockets" in headings). Every empty state says what
will appear there and how to make it appear. Every error says what happened
and the one thing to do next.

## 11. Acceptance checklist

- [ ] `docs/design/AUDIT.md` exists and lists any deviations from this spec.
- [ ] All colours, fonts and spacing come from the single theme module.
- [ ] Only teal, red and amber appear as colours, used as defined in section 3.
- [ ] Default process table shows exactly five columns; others are in the picker.
- [ ] Access map works for a process with 0, 5, 150 and 2,000 touched objects.
- [ ] Map stops moving when settled and does not reshuffle on updates.
- [ ] Hover dimming, click selection, double-click re-centre, filters, system
      files toggle, folder grouping, time window and search all work.
- [ ] A new user can run the bundled example in Glasshouse with one click and
      reach a report.
- [ ] Glasshouse caution text and the "events not recorded" count are present
      and unchanged in meaning.
- [ ] Glasshouse unavailable state shows the reason.
- [ ] CLI output is plain when piped, and `NO_COLOR` is respected.
- [ ] No new network access; fonts bundled with licences.
- [ ] Existing tests pass. New tests cover: map graph building from events
      (grouping, cap, redaction), the summary sentence generator, and CLI
      colour switching.
- [ ] GUI stays responsive (no visible stutter) with the daemon under the
      load used in `docs/BENCH.md`.
- [ ] Works at 1280x720 and at 1920x1080, on X11 and Wayland.
- [ ] "After" screenshots of every screen saved to `docs/design/after/`, and
      the three README images in `docs/img/` replaced.
- [ ] CHANGELOG updated.

## 12. Order of work

1. Audit and theme module (section 2).
2. Shared components and navigation (sections 3 and 4).
3. Processes overview and detail (section 5).
4. Glasshouse (section 7).
5. Access map (section 6).
6. Findings tab and CLI (sections 8 and 9).
7. Tests, screenshots, CHANGELOG.

Commit after each step on a branch named `gui-redesign`. Do not merge to
`main`; the owner reviews screenshots first.
