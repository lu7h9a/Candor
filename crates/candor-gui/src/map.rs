//! The access map (spec section 6): what one process and its descendants
//! touched, as a graph. This module is pure data: it builds the graph from
//! what the daemon sent (`Detail` replies or a Glasshouse timeline), runs a
//! small force-directed layout one bounded step at a time, and keeps the
//! view state (pan, zoom, hover, selection, filters). `mapview.rs` draws it.
//!
//! Rules from the spec, and where they live:
//! - system files collapse into one node, folders with more than
//!   `FOLDER_MIN` files into one node each, until expanded (`build`);
//! - at most `CAP` nodes; the least active are grouped into "+N more"
//!   (`build`);
//! - the layout stops when settled and never reshuffles: new nodes start
//!   next to a neighbour and only their neighbourhood moves (`MapState::sync`,
//!   `MapState::step`).

use candor_core::display::{safe, safe_str};
use candor_proto::{DaemonMsg, Event, EventKind, Finding, ProcKey};
use std::collections::{BTreeMap, BTreeSet};

/// Most nodes drawn.
pub const CAP: usize = 150;
/// A folder with more touched files than this becomes one node.
pub const FOLDER_MIN: usize = 8;
/// Layout iterations per frame (bounded work on the UI thread).
pub const STEPS_PER_FRAME: usize = 6;
/// Below this zoom, only the centre, flagged and hovered nodes are labelled.
pub const LABEL_ZOOM: f32 = 0.8;

/// What a node stands for.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeId {
    /// A process.
    Proc(ProcKey),
    /// A file (escaped path).
    File(String),
    /// An outbound endpoint "addr:port".
    Net(String),
    /// A listening socket "addr:port".
    Listen(String),
    /// A folder group (escaped directory path).
    Dir(String),
    /// Common system files.
    System,
    /// "+N more" of one kind.
    More(Kind),
}

/// Kind of node, for colour, filters and counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Processes.
    Process,
    /// Files and folder groups.
    File,
    /// Endpoints and listening sockets.
    Network,
}

/// One action of a process on an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Act {
    /// Started a process.
    Started,
    /// Read a file.
    Read,
    /// Wrote a file.
    Wrote,
    /// Renamed a file.
    Renamed,
    /// Deleted a file.
    Deleted,
    /// Connected to an endpoint.
    Connected,
    /// Listened on a port.
    Listening,
    /// Attached to another process with ptrace.
    Ptrace,
}

impl Act {
    /// The edge label.
    pub fn word(self) -> &'static str {
        match self {
            Act::Started => "started",
            Act::Read => "read",
            Act::Wrote => "wrote",
            Act::Renamed => "renamed",
            Act::Deleted => "deleted",
            Act::Connected => "connected",
            Act::Listening => "listening",
            Act::Ptrace => "ptrace",
        }
    }
}

/// One fact: `actor` did `act` to `object`, `count` times.
#[derive(Clone, Debug, PartialEq)]
pub struct Touch {
    /// The process that acted.
    pub actor: ProcKey,
    /// What it acted on.
    pub object: NodeId,
    /// What it did.
    pub act: Act,
    /// How many times.
    pub count: u64,
    /// First time seen (boot ns), if known.
    pub first: Option<u64>,
    /// Last time seen (boot ns).
    pub last: u64,
    /// Event ids behind it, if known (bounded).
    pub events: Vec<u64>,
}

/// A process the map knows about: name and parent.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcInfo {
    /// Display name (escaped).
    pub name: String,
    /// Parent, if known.
    pub parent: Option<ProcKey>,
}

/// A node as drawn.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    /// Identity.
    pub id: NodeId,
    /// Kind.
    pub kind: Kind,
    /// Short label (file name, process name, endpoint).
    pub label: String,
    /// Full path or address.
    pub full: String,
    /// Events behind it (sum of its touches).
    pub count: u64,
    /// Tied to a finding.
    pub flagged: bool,
    /// The finding's title and first reason, if flagged.
    pub finding: Option<(String, String, u64)>,
    /// First and last time, if known.
    pub first: Option<u64>,
    /// Last time (boot ns), 0 if unknown.
    pub last: u64,
    /// Processes that touched it, and the actions with counts.
    pub by: BTreeMap<ProcKey, BTreeMap<Act, u64>>,
    /// Members of a group node (folder, system files, "+N more").
    pub members: usize,
    /// Event ids behind it (bounded).
    pub events: Vec<u64>,
}

/// An edge as drawn.
#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    /// From (the actor).
    pub from: NodeId,
    /// To (the object).
    pub to: NodeId,
    /// Label (the most frequent action).
    pub act: Act,
    /// Tied to a finding.
    pub flagged: bool,
    /// Last time (boot ns).
    pub last: u64,
}

/// The graph for one centre.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Graph {
    /// Nodes, centre first.
    pub nodes: Vec<Node>,
    /// Edges.
    pub edges: Vec<Edge>,
    /// Objects folded into "+N more" because of the cap (0 if none).
    pub capped: usize,
    /// Descendants drawn without their files (no detail received).
    pub without_detail: usize,
}

impl Graph {
    /// Index of a node.
    pub fn index(&self, id: &NodeId) -> Option<usize> {
        self.nodes.iter().position(|n| &n.id == id)
    }
    /// Number of nodes of a kind (for the filter chips).
    pub fn count(&self, k: Kind) -> usize {
        self.nodes.iter().filter(|n| n.kind == k).count()
    }
}

/// Options that change which nodes are built.
#[derive(Clone, Debug, PartialEq)]
pub struct BuildOpts {
    /// Collapse common system files into one node.
    pub hide_system: bool,
    /// Folder groups and the system node the user expanded.
    pub expanded: BTreeSet<NodeId>,
    /// Kinds shown.
    pub kinds: BTreeSet<Kind>,
    /// Only flagged nodes (and the processes that reach them).
    pub flagged_only: bool,
    /// Node cap.
    pub cap: usize,
}

impl Default for BuildOpts {
    fn default() -> Self {
        BuildOpts {
            hide_system: true,
            expanded: BTreeSet::new(),
            kinds: [Kind::Process, Kind::File, Kind::Network].into(),
            flagged_only: false,
            cap: CAP,
        }
    }
}

/// True for files the spec calls "common system files": shared
/// libraries, locale files, /proc, /sys, /dev and loader caches.
pub fn is_system_file(path: &str) -> bool {
    const PREFIXES: [&str; 9] = [
        "/proc/",
        "/sys/",
        "/dev/",
        "/usr/lib/locale/",
        "/usr/share/locale/",
        "/usr/share/zoneinfo/",
        "/etc/ld.so.",
        "/usr/lib/x86_64-linux-gnu/gconv/",
        "/usr/share/fonts/",
    ];
    let lib_dir = [
        "/lib/",
        "/lib64/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/local/lib/",
    ]
    .iter()
    .any(|d| path.starts_with(d));
    let shared_lib = path.ends_with(".so") || path.contains(".so.");
    PREFIXES.iter().any(|p| path.starts_with(p))
        || path == "/etc/localtime"
        || path == "/etc/nsswitch.conf"
        || (lib_dir && shared_lib)
        || path.ends_with("/locale-archive")
}

fn parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => path.get(..i).unwrap_or(path),
        None => "",
    }
}

fn leaf(path: &str) -> &str {
    path.rsplit('/').find(|s| !s.is_empty()).unwrap_or(path)
}

/// Facts from one process's `Detail` reply: files (read/write), connections,
/// direct children, and renames, deletes, listens and ptrace from its
/// recent events.
pub fn touches_from_detail(d: &DaemonMsg) -> Vec<Touch> {
    let DaemonMsg::Detail {
        proc,
        files,
        conns,
        children,
        recent,
        ..
    } = d
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in files {
        let act = if f.write { Act::Wrote } else { Act::Read };
        out.push(Touch {
            actor: *proc,
            object: NodeId::File(safe(&f.path)),
            act,
            count: f.opens.max(1),
            first: None,
            last: f.last_ts,
            events: Vec::new(),
        });
    }
    for c in conns {
        out.push(Touch {
            actor: *proc,
            object: NodeId::Net(format!("{}:{}", safe_str(&c.addr), c.port)),
            act: Act::Connected,
            count: c.count.max(1),
            first: None,
            last: c.last_ts,
            events: Vec::new(),
        });
    }
    for c in children {
        out.push(Touch {
            actor: *proc,
            object: NodeId::Proc(*c),
            act: Act::Started,
            count: 1,
            first: None,
            last: 0,
            events: Vec::new(),
        });
    }
    // Recent events: what FileStat does not record, plus first times.
    for t in touches_from_events(recent) {
        if matches!(
            t.act,
            Act::Read | Act::Wrote | Act::Connected | Act::Started
        ) {
            // Already counted above; only refine the first time.
            if let Some(o) = out
                .iter_mut()
                .find(|o| o.actor == t.actor && o.object == t.object)
            {
                o.first = match (o.first, t.first) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                o.events.extend(t.events.iter().take(20));
            }
            continue;
        }
        out.push(t);
    }
    out
}

/// Facts from a list of events (a Glasshouse timeline, or recent events).
pub fn touches_from_events(events: &[Event]) -> Vec<Touch> {
    let mut acc: BTreeMap<(ProcKey, NodeId, Act), Touch> = BTreeMap::new();
    let mut add = |actor: ProcKey, object: NodeId, act: Act, e: &Event| {
        let t = acc
            .entry((actor, object.clone(), act))
            .or_insert_with(|| Touch {
                actor,
                object,
                act,
                count: 0,
                first: Some(e.ts_ns),
                last: e.ts_ns,
                events: Vec::new(),
            });
        t.count += 1;
        t.first = t.first.map(|f| f.min(e.ts_ns));
        t.last = t.last.max(e.ts_ns);
        if t.events.len() < 50 {
            t.events.push(e.id);
        }
    };
    for e in events {
        match &e.kind {
            EventKind::Open { path, write, .. } => {
                let act = if *write { Act::Wrote } else { Act::Read };
                add(e.proc, NodeId::File(safe(path)), act, e);
            }
            EventKind::Rename { old, .. } => add(e.proc, NodeId::File(safe(old)), Act::Renamed, e),
            EventKind::Unlink { path, .. } => {
                add(e.proc, NodeId::File(safe(path)), Act::Deleted, e)
            }
            EventKind::Connect { addr, port, .. } => add(
                e.proc,
                NodeId::Net(format!("{}:{port}", safe_str(addr))),
                Act::Connected,
                e,
            ),
            EventKind::Listen { addr, port } => add(
                e.proc,
                NodeId::Listen(format!("{}:{port}", safe_str(addr))),
                Act::Listening,
                e,
            ),
            EventKind::Fork { child } => add(e.proc, NodeId::Proc(*child), Act::Started, e),
            EventKind::Ptrace { target, .. } => add(e.proc, NodeId::Proc(*target), Act::Ptrace, e),
            EventKind::Exec { .. } | EventKind::Exit {} => {}
        }
    }
    acc.into_values().collect()
}

/// What each finding points at: the objects in its evidence, and its process.
pub fn flagged_objects(findings: &[Finding]) -> BTreeMap<NodeId, (String, String, u64)> {
    let mut out = BTreeMap::new();
    for f in findings {
        let why = f.why.first().map(|w| safe_str(w)).unwrap_or_default();
        let info = (safe_str(&f.title), why, f.id);
        out.entry(NodeId::Proc(f.proc))
            .or_insert_with(|| info.clone());
        for e in &f.evidence_events {
            let id = match &e.kind {
                EventKind::Open { path, .. } | EventKind::Unlink { path, .. } => {
                    NodeId::File(safe(path))
                }
                EventKind::Rename { old, .. } => NodeId::File(safe(old)),
                EventKind::Connect { addr, port, .. } => {
                    NodeId::Net(format!("{}:{port}", safe_str(addr)))
                }
                EventKind::Listen { addr, port } => {
                    NodeId::Listen(format!("{}:{port}", safe_str(addr)))
                }
                EventKind::Ptrace { target, .. } => NodeId::Proc(*target),
                EventKind::Fork { child } => NodeId::Proc(*child),
                EventKind::Exec { .. } | EventKind::Exit {} => NodeId::Proc(e.proc),
            };
            out.entry(id).or_insert_with(|| info.clone());
        }
    }
    out
}

fn kind_of(id: &NodeId) -> Kind {
    match id {
        NodeId::Proc(_) => Kind::Process,
        NodeId::File(_) | NodeId::Dir(_) | NodeId::System => Kind::File,
        NodeId::Net(_) | NodeId::Listen(_) => Kind::Network,
        NodeId::More(k) => *k,
    }
}

/// Builds the graph around `center`.
///
/// `procs` names the processes (and their parents); `touches` are the
/// facts; `flags` marks what findings point at; `shown` applies redaction
/// to paths. Group nodes absorb their members' counts and edges.
pub fn build(
    center: ProcKey,
    procs: &BTreeMap<ProcKey, ProcInfo>,
    touches: &[Touch],
    flags: &BTreeMap<NodeId, (String, String, u64)>,
    opts: &BuildOpts,
    shown: &dyn Fn(&str) -> String,
) -> Graph {
    // 1. The process tree: centre, its parent, every descendant reached
    // through "started" facts or the parent links in `procs`.
    let mut tree: BTreeSet<ProcKey> = BTreeSet::from([center]);
    let mut frontier = vec![center];
    let mut started: Vec<(ProcKey, ProcKey)> = Vec::new();
    while let Some(p) = frontier.pop() {
        let kids = procs
            .iter()
            .filter(|(_, i)| i.parent == Some(p))
            .map(|(k, _)| *k)
            .chain(touches.iter().filter_map(|t| match (&t.object, t.act) {
                (NodeId::Proc(c), Act::Started) if t.actor == p => Some(*c),
                _ => None,
            }))
            .collect::<BTreeSet<_>>();
        for c in kids {
            if c != p && tree.insert(c) {
                started.push((p, c));
                frontier.push(c);
            }
        }
    }
    let parent = procs.get(&center).and_then(|i| i.parent);

    // 2. Facts by object, only for actors in the tree.
    let mut objs: BTreeMap<NodeId, Node> = BTreeMap::new();
    let mut edges: BTreeMap<(NodeId, NodeId), Edge> = BTreeMap::new();
    let name_of = |k: &ProcKey| {
        procs
            .get(k)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| format!("pid {}", k.tgid))
    };
    let proc_node = |k: ProcKey| Node {
        id: NodeId::Proc(k),
        kind: Kind::Process,
        label: leaf(&shown(&name_of(&k))).to_string(),
        full: format!("{} (pid {})", shown(&name_of(&k)), k.tgid),
        count: 0,
        flagged: false,
        finding: None,
        first: None,
        last: 0,
        by: BTreeMap::new(),
        members: 1,
        events: Vec::new(),
    };
    for k in tree.iter().copied().chain(parent) {
        objs.insert(NodeId::Proc(k), proc_node(k));
    }
    if let Some(p) = parent {
        edges.insert(
            (NodeId::Proc(p), NodeId::Proc(center)),
            Edge {
                from: NodeId::Proc(p),
                to: NodeId::Proc(center),
                act: Act::Started,
                flagged: false,
                last: 0,
            },
        );
    }
    for (p, c) in &started {
        edges.insert(
            (NodeId::Proc(*p), NodeId::Proc(*c)),
            Edge {
                from: NodeId::Proc(*p),
                to: NodeId::Proc(*c),
                act: Act::Started,
                flagged: false,
                last: 0,
            },
        );
    }
    // Per-object facts (files and network); ptrace targets become processes.
    let mut facts: BTreeMap<NodeId, Vec<&Touch>> = BTreeMap::new();
    for t in touches.iter().filter(|t| tree.contains(&t.actor)) {
        match &t.object {
            NodeId::Proc(_) if t.act == Act::Started => {}
            _ => facts.entry(t.object.clone()).or_default().push(t),
        }
    }
    // 3. Grouping: system files, then big folders. Flagged objects are
    // never hidden in a group.
    let flagged = |id: &NodeId| flags.contains_key(id);
    let mut group_of: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    if opts.hide_system && !opts.expanded.contains(&NodeId::System) {
        for id in facts.keys() {
            if let NodeId::File(p) = id
                && is_system_file(p)
                && !flagged(id)
            {
                group_of.insert(id.clone(), NodeId::System);
            }
        }
    }
    let mut per_dir: BTreeMap<String, Vec<NodeId>> = BTreeMap::new();
    for id in facts.keys().filter(|id| !group_of.contains_key(*id)) {
        if let NodeId::File(p) = id
            && !flagged(id)
        {
            per_dir
                .entry(parent_dir(p).to_string())
                .or_default()
                .push(id.clone());
        }
    }
    for (dir, files) in per_dir {
        let gid = NodeId::Dir(dir);
        if files.len() > FOLDER_MIN && !opts.expanded.contains(&gid) {
            for f in files {
                group_of.insert(f, gid.clone());
            }
        }
    }
    // 4. Fold facts into nodes and edges.
    for (id, ts) in &facts {
        let target = group_of.get(id).cloned().unwrap_or_else(|| id.clone());
        let n = objs.entry(target.clone()).or_insert_with(|| {
            let (label, full) = match &target {
                NodeId::File(p) => (leaf(&shown(p)).to_string(), shown(p)),
                NodeId::Dir(d) => (format!("{}/", leaf(&shown(d))), shown(d)),
                NodeId::System => ("System files".into(), "Common system files".into()),
                NodeId::Net(a) => (a.clone(), a.clone()),
                NodeId::Listen(a) => (format!("listening {a}"), a.clone()),
                NodeId::Proc(k) => (leaf(&shown(&name_of(k))).to_string(), name_of(k)),
                NodeId::More(_) => (String::new(), String::new()),
            };
            Node {
                id: target.clone(),
                kind: kind_of(&target),
                label,
                full,
                count: 0,
                flagged: false,
                finding: None,
                first: None,
                last: 0,
                by: BTreeMap::new(),
                members: 0,
                events: Vec::new(),
            }
        });
        n.members += 1;
        if let Some(f) = flags.get(id) {
            n.flagged = true;
            n.finding.get_or_insert_with(|| f.clone());
        }
        for t in ts {
            n.count = n.count.saturating_add(t.count);
            n.first = match (n.first, t.first) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            n.last = n.last.max(t.last);
            *n.by.entry(t.actor).or_default().entry(t.act).or_insert(0) += t.count;
            if n.events.len() < 50 {
                n.events.extend(t.events.iter().take(50 - n.events.len()));
            }
            let e = edges
                .entry((NodeId::Proc(t.actor), target.clone()))
                .or_insert(Edge {
                    from: NodeId::Proc(t.actor),
                    to: target.clone(),
                    act: t.act,
                    flagged: false,
                    last: 0,
                });
            // Label with the most telling action: delete > rename > write > read.
            if t.act > e.act {
                e.act = t.act;
            }
            e.last = e.last.max(t.last);
            e.flagged |= flags.contains_key(id);
        }
    }
    for (id, f) in flags {
        if let Some(n) = objs.get_mut(id) {
            n.flagged = true;
            n.finding.get_or_insert_with(|| f.clone());
        }
    }
    // Processes count what they did.
    for n in objs.values_mut().filter(|n| n.kind == Kind::Process) {
        if let NodeId::Proc(k) = n.id {
            n.count = touches
                .iter()
                .filter(|t| t.actor == k)
                .map(|t| t.count)
                .sum::<u64>()
                .max(1);
        }
    }
    // 5. Filters.
    let keep_kind = |n: &Node| opts.kinds.contains(&n.kind) || n.id == NodeId::Proc(center);
    let mut nodes: Vec<Node> = objs.into_values().filter(|n| keep_kind(n)).collect();
    if opts.flagged_only {
        let wanted: BTreeSet<NodeId> = nodes
            .iter()
            .filter(|n| n.flagged)
            .map(|n| n.id.clone())
            .collect();
        let actors: BTreeSet<NodeId> = edges
            .values()
            .filter(|e| wanted.contains(&e.to))
            .map(|e| e.from.clone())
            .collect();
        nodes.retain(|n| {
            wanted.contains(&n.id) || actors.contains(&n.id) || n.id == NodeId::Proc(center)
        });
    }
    // 6. Cap: keep the centre, processes and flagged nodes first, then the
    // most active; group the rest into "+N more" per kind.
    let mut capped = 0;
    if nodes.len() > opts.cap {
        nodes.sort_by(|a, b| {
            let rank = |n: &Node| {
                (
                    n.id != NodeId::Proc(center),
                    !n.flagged,
                    n.kind != Kind::Process,
                )
            };
            rank(a).cmp(&rank(b)).then(b.count.cmp(&a.count))
        });
        let keep = opts.cap.saturating_sub(2).max(1); // room for "+N more" nodes
        let rest = nodes.split_off(keep.min(nodes.len()));
        let mut more: BTreeMap<Kind, Node> = BTreeMap::new();
        let mut folded: BTreeMap<NodeId, NodeId> = BTreeMap::new();
        for n in rest {
            capped += n.members.max(1);
            let id = NodeId::More(n.kind);
            folded.insert(n.id.clone(), id.clone());
            let m = more.entry(n.kind).or_insert_with(|| Node {
                id: id.clone(),
                kind: n.kind,
                label: String::new(),
                full: String::new(),
                count: 0,
                flagged: false,
                finding: None,
                first: None,
                last: 0,
                by: BTreeMap::new(),
                members: 0,
                events: Vec::new(),
            });
            m.members += n.members.max(1);
            m.count = m.count.saturating_add(n.count);
            m.last = m.last.max(n.last);
        }
        for m in more.values_mut() {
            m.label = format!("+{} more", m.members);
            m.full = m.label.clone();
        }
        nodes.extend(more.into_values());
        // Re-point edges at the "+N more" nodes, merging duplicates.
        let mut merged: BTreeMap<(NodeId, NodeId), Edge> = BTreeMap::new();
        for (_, mut e) in std::mem::take(&mut edges) {
            if let Some(t) = folded.get(&e.to) {
                e.to = t.clone();
            }
            if let Some(f) = folded.get(&e.from) {
                e.from = f.clone();
            }
            let key = (e.from.clone(), e.to.clone());
            merged
                .entry(key)
                .and_modify(|x| {
                    x.last = x.last.max(e.last);
                    x.flagged |= e.flagged;
                })
                .or_insert(e);
        }
        edges = merged;
    }
    // Centre first, then a stable order.
    nodes.sort_by(|a, b| {
        (a.id != NodeId::Proc(center))
            .cmp(&(b.id != NodeId::Proc(center)))
            .then(a.id.cmp(&b.id))
    });
    let present: BTreeSet<&NodeId> = nodes.iter().map(|n| &n.id).collect();
    let edges: Vec<Edge> = edges
        .into_values()
        .filter(|e| present.contains(&e.from) && present.contains(&e.to) && e.from != e.to)
        .collect();
    Graph {
        nodes,
        edges,
        capped,
        without_detail: 0,
    }
}

/// A point.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct P {
    /// x.
    pub x: f32,
    /// y.
    pub y: f32,
}

#[derive(Clone, Debug, PartialEq)]
struct Body {
    pos: P,
    vel: P,
    pinned: bool,
    /// Frames since the node appeared (fade-in).
    age: u32,
}

/// Interactions with the map (from the view or the keyboard).
#[derive(Clone, Debug, PartialEq)]
pub enum MapAction {
    /// The pointer is over a node (or none).
    Hover(Option<NodeId>),
    /// A node was clicked: select it.
    Click(NodeId),
    /// Empty space was clicked: clear the selection.
    ClickEmpty,
    /// A node was double-clicked: re-centre on processes, expand groups.
    DoubleClick(NodeId),
    /// Empty space was double-clicked: reset the view.
    ResetView,
    /// A node was dragged by (dx, dy) in map units: it is pinned.
    Drag(NodeId, P),
    /// The background was dragged (screen pixels).
    Pan(P),
    /// Scroll: zoom by a factor.
    Zoom(f32),
    /// A kind filter chip.
    ToggleKind(Kind),
    /// "Flagged only".
    FlaggedOnly,
    /// "Hide common system files".
    HideSystem,
    /// Time window end, 0..=1 of the span.
    Time(f32),
    /// Search text.
    Search(String),
    /// Tab: focus the next node by activity.
    FocusNext,
    /// Enter: select the focused node.
    SelectFocused,
}

/// The map's state: graph, positions, view and filters.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MapState {
    /// The process in the centre.
    pub center: Option<ProcKey>,
    /// The current graph.
    pub graph: Graph,
    /// Build options (filters, grouping).
    pub opts: BuildOpts,
    bodies: BTreeMap<NodeId, Body>,
    /// Nodes still moving; empty when settled.
    active: BTreeSet<NodeId>,
    /// Pan offset (screen pixels) and zoom.
    pub pan: P,
    /// Zoom factor.
    pub zoom: f32,
    /// Node under the pointer.
    pub hover: Option<NodeId>,
    /// Selected node (side panel).
    pub selected: Option<NodeId>,
    /// Node focused with Tab.
    pub focus: Option<NodeId>,
    /// Time window end (0..=1); 1 shows everything.
    pub time: f32,
    /// Search text.
    pub search: String,
    /// Inputs changed: rebuild before the next frame.
    dirty: bool,
    /// Signature of the inputs the graph was built from.
    built_from: u64,
}

impl MapState {
    /// Marks the graph for a rebuild (e.g. redaction changed).
    pub fn invalidate(&mut self) {
        self.dirty = true;
    }

    /// True while nodes are still moving.
    pub fn moving(&self) -> bool {
        !self.active.is_empty()
    }

    /// Position of a node (map units).
    pub fn pos(&self, id: &NodeId) -> Option<P> {
        self.bodies.get(id).map(|b| b.pos)
    }

    /// Fade-in factor of a node, 0..=1.
    pub fn fade_in(&self, id: &NodeId) -> f32 {
        self.bodies
            .get(id)
            .map(|b| (b.age as f32 / 20.0).min(1.0))
            .unwrap_or(1.0)
    }

    /// Time span of the graph (first, last) for the time window.
    pub fn span(&self) -> Option<(u64, u64)> {
        let ts: Vec<u64> = self
            .graph
            .nodes
            .iter()
            .flat_map(|n| n.first.into_iter().chain(Some(n.last)))
            .filter(|t| *t > 0)
            .collect();
        Some((*ts.iter().min()?, *ts.iter().max()?))
    }

    /// True if a node is inside the time window.
    pub fn in_window(&self, n: &Node) -> bool {
        if self.time >= 1.0 || n.last == 0 {
            return true;
        }
        match self.span() {
            Some((a, b)) => {
                let cut = a as f64 + (b - a) as f64 * f64::from(self.time);
                (n.first.unwrap_or(n.last) as f64) <= cut
            }
            None => true,
        }
    }

    /// True if a node matches the search text.
    pub fn matches(&self, n: &Node) -> bool {
        let q = self.search.trim().to_lowercase();
        q.is_empty() || n.full.to_lowercase().contains(&q) || n.label.to_lowercase().contains(&q)
    }

    /// Sets the centre; a new centre resets the view.
    pub fn set_center(&mut self, k: ProcKey) {
        if self.center != Some(k) {
            self.center = Some(k);
            self.bodies.clear();
            self.active.clear();
            self.pan = P::default();
            self.zoom = 1.0;
            self.selected = None;
            self.hover = None;
            self.focus = None;
            self.time = 1.0;
            self.dirty = true;
        }
    }

    /// Rebuilds the graph if its inputs changed. `sig` identifies the
    /// inputs (it changes when new data arrives).
    pub fn sync(&mut self, sig: u64, make: impl FnOnce(&BuildOpts) -> Graph) {
        if self.zoom == 0.0 {
            self.zoom = 1.0;
            self.time = 1.0;
        }
        if !self.dirty && sig == self.built_from && !self.graph.nodes.is_empty() {
            return;
        }
        self.dirty = false;
        self.built_from = sig;
        let g = make(&self.opts);
        // Place new nodes near a neighbour that already has a position;
        // keep everyone else where they are. Only new nodes and their
        // neighbours relax.
        let neighbours = |id: &NodeId| -> Vec<NodeId> {
            g.edges
                .iter()
                .filter_map(|e| {
                    if &e.from == id {
                        Some(e.to.clone())
                    } else if &e.to == id {
                        Some(e.from.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };
        let n = g.nodes.len().max(1) as f32;
        for (i, node) in g.nodes.iter().enumerate() {
            if self.bodies.contains_key(&node.id) {
                continue;
            }
            let near = neighbours(&node.id)
                .into_iter()
                .find_map(|nb| self.bodies.get(&nb).map(|b| b.pos));
            // Deterministic spread: golden-angle spiral (no randomness, so
            // the same data gives the same picture).
            let a = i as f32 * 2.399_963;
            let r = if near.is_some() {
                40.0
            } else {
                30.0 * (i as f32).sqrt()
            };
            let base = near.unwrap_or_default();
            let pos = if i == 0 && self.bodies.is_empty() {
                P::default()
            } else {
                P {
                    x: base.x + r * a.cos(),
                    y: base.y + r * a.sin(),
                }
            };
            self.bodies.insert(
                node.id.clone(),
                Body {
                    pos,
                    vel: P::default(),
                    pinned: false,
                    age: 0,
                },
            );
            self.active.insert(node.id.clone());
            for nb in neighbours(&node.id) {
                self.active.insert(nb);
            }
            let _ = n;
        }
        // Drop bodies of nodes that left the graph.
        let present: BTreeSet<&NodeId> = g.nodes.iter().map(|n| &n.id).collect();
        self.bodies.retain(|id, _| present.contains(id));
        self.active.retain(|id| present.contains(id));
        if let Some(s) = &self.selected
            && !present.contains(s)
        {
            self.selected = None;
        }
        self.graph = g;
    }

    /// One bounded layout step for the active nodes: repulsion between
    /// nodes, springs on edges, a gentle pull to the centre. Nodes whose
    /// movement falls below a threshold leave the active set; when it is
    /// empty the map is settled and nothing moves.
    pub fn step(&mut self) {
        for b in self.bodies.values_mut() {
            b.age = b.age.saturating_add(1);
        }
        if self.active.is_empty() {
            return;
        }
        const REPULSE: f32 = 600.0;
        const SPRING: f32 = 0.04;
        const LENGTH: f32 = 70.0;
        const GRAVITY: f32 = 0.004;
        const DAMP: f32 = 0.82;
        const REST: f32 = 0.05;
        let ids: Vec<NodeId> = self.active.iter().cloned().collect();
        let all: Vec<(NodeId, P)> = self
            .bodies
            .iter()
            .map(|(k, b)| (k.clone(), b.pos))
            .collect();
        let mut force: BTreeMap<NodeId, P> = BTreeMap::new();
        for id in &ids {
            let Some(p) = self.bodies.get(id).map(|b| b.pos) else {
                continue;
            };
            let mut f = P {
                x: -p.x * GRAVITY,
                y: -p.y * GRAVITY,
            };
            for (other, q) in &all {
                if other == id {
                    continue;
                }
                let (dx, dy) = (p.x - q.x, p.y - q.y);
                let d2 = (dx * dx + dy * dy).max(25.0);
                f.x += REPULSE * dx / d2;
                f.y += REPULSE * dy / d2;
            }
            force.insert(id.clone(), f);
        }
        for e in &self.graph.edges {
            let (Some(a), Some(b)) = (
                self.bodies.get(&e.from).map(|b| b.pos),
                self.bodies.get(&e.to).map(|b| b.pos),
            ) else {
                continue;
            };
            let (dx, dy) = (b.x - a.x, b.y - a.y);
            let d = (dx * dx + dy * dy).sqrt().max(0.01);
            let k = SPRING * (d - LENGTH) / d;
            if let Some(f) = force.get_mut(&e.from) {
                f.x += k * dx;
                f.y += k * dy;
            }
            if let Some(f) = force.get_mut(&e.to) {
                f.x -= k * dx;
                f.y -= k * dy;
            }
        }
        let centre = self.center.map(NodeId::Proc);
        for (id, f) in force {
            let Some(b) = self.bodies.get_mut(&id) else {
                continue;
            };
            if b.pinned || Some(&id) == centre.as_ref() {
                b.vel = P::default();
                self.active.remove(&id);
                continue;
            }
            b.vel.x = (b.vel.x + f.x) * DAMP;
            b.vel.y = (b.vel.y + f.y) * DAMP;
            let speed = (b.vel.x * b.vel.x + b.vel.y * b.vel.y).sqrt();
            let max = 20.0;
            if speed > max {
                b.vel.x *= max / speed;
                b.vel.y *= max / speed;
            }
            b.pos.x += b.vel.x;
            b.pos.y += b.vel.y;
            if speed < REST {
                b.vel = P::default();
                self.active.remove(&id);
            }
        }
    }

    /// Applies an interaction. Returns a process to re-centre on, if any.
    pub fn on_action(&mut self, a: MapAction) -> Option<ProcKey> {
        match a {
            MapAction::Hover(h) => self.hover = h,
            MapAction::Click(id) => {
                self.selected = Some(id.clone());
                self.focus = Some(id);
            }
            MapAction::ClickEmpty => self.selected = None,
            MapAction::DoubleClick(id) => match &id {
                NodeId::Proc(k) => return Some(*k),
                NodeId::Dir(_) | NodeId::System => {
                    self.opts.expanded.insert(id);
                    self.dirty = true;
                }
                _ => {}
            },
            MapAction::ResetView => {
                self.pan = P::default();
                self.zoom = 1.0;
            }
            MapAction::Drag(id, d) => {
                if let Some(b) = self.bodies.get_mut(&id) {
                    b.pos.x += d.x;
                    b.pos.y += d.y;
                    b.pinned = true;
                    b.vel = P::default();
                }
                // Its neighbours follow gently.
                for e in &self.graph.edges {
                    if e.from == id {
                        self.active.insert(e.to.clone());
                    } else if e.to == id {
                        self.active.insert(e.from.clone());
                    }
                }
            }
            MapAction::Pan(d) => {
                self.pan.x += d.x;
                self.pan.y += d.y;
            }
            MapAction::Zoom(f) => self.zoom = (self.zoom * f).clamp(0.2, 4.0),
            MapAction::ToggleKind(k) => {
                if !self.opts.kinds.remove(&k) {
                    self.opts.kinds.insert(k);
                }
                self.dirty = true;
            }
            MapAction::FlaggedOnly => {
                self.opts.flagged_only = !self.opts.flagged_only;
                self.dirty = true;
            }
            MapAction::HideSystem => {
                self.opts.hide_system = !self.opts.hide_system;
                self.opts.expanded.remove(&NodeId::System);
                self.dirty = true;
            }
            MapAction::Time(t) => self.time = t.clamp(0.0, 1.0),
            MapAction::Search(s) => self.search = s,
            MapAction::FocusNext => {
                let mut order: Vec<&Node> = self.graph.nodes.iter().collect();
                order.sort_by(|a, b| b.count.cmp(&a.count).then(a.id.cmp(&b.id)));
                let at = self
                    .focus
                    .as_ref()
                    .and_then(|f| order.iter().position(|n| &n.id == f));
                let next = at.map_or(0, |i| (i + 1) % order.len().max(1));
                self.focus = order.get(next).map(|n| n.id.clone());
            }
            MapAction::SelectFocused => self.selected = self.focus.clone(),
        }
        None
    }

    /// Ids of a node and its direct neighbours (hover highlighting).
    pub fn neighbourhood(&self, id: &NodeId) -> BTreeSet<NodeId> {
        let mut s = BTreeSet::from([id.clone()]);
        for e in &self.graph.edges {
            if &e.from == id {
                s.insert(e.to.clone());
            } else if &e.to == id {
                s.insert(e.from.clone());
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(t: u32) -> ProcKey {
        ProcKey {
            tgid: t,
            start_ticks: 1,
        }
    }

    fn file(actor: u32, path: &str, act: Act, count: u64) -> Touch {
        Touch {
            actor: k(actor),
            object: NodeId::File(path.into()),
            act,
            count,
            first: Some(10),
            last: 20,
            events: vec![],
        }
    }

    fn procs(list: &[(u32, Option<u32>, &str)]) -> BTreeMap<ProcKey, ProcInfo> {
        list.iter()
            .map(|(t, p, n)| {
                (
                    k(*t),
                    ProcInfo {
                        name: (*n).into(),
                        parent: p.map(k),
                    },
                )
            })
            .collect()
    }

    fn plain(s: &str) -> String {
        s.to_string()
    }

    fn build_with(touches: &[Touch], opts: &BuildOpts) -> Graph {
        let p = procs(&[
            (1, None, "/bin/bash"),
            (2, Some(1), "/tmp/try.sh"),
            (3, Some(2), "/bin/cat"),
        ]);
        build(k(2), &p, touches, &BTreeMap::new(), opts, &plain)
    }

    #[test]
    fn empty_process_has_only_its_tree() {
        let g = build_with(&[], &BuildOpts::default());
        // Centre, parent and child; no objects.
        assert_eq!(g.nodes.len(), 3);
        assert_eq!(g.nodes[0].id, NodeId::Proc(k(2)));
        assert_eq!(g.count(Kind::File), 0);
        assert_eq!(g.edges.len(), 2);
    }

    #[test]
    fn five_files_are_drawn_one_by_one_with_actions() {
        let t: Vec<Touch> = (0..5)
            .map(|i| file(3, &format!("/home/u/f{i}"), Act::Read, 1))
            .chain([file(2, "/home/u/f0", Act::Deleted, 1)])
            .collect();
        let g = build_with(&t, &BuildOpts::default());
        assert_eq!(g.count(Kind::File), 5);
        let f0 = &g.nodes[g.index(&NodeId::File("/home/u/f0".into())).unwrap()];
        assert_eq!(f0.by.len(), 2);
        let e = g
            .edges
            .iter()
            .find(|e| e.from == NodeId::Proc(k(2)) && e.to == f0.id)
            .unwrap();
        assert_eq!(e.act.word(), "deleted");
    }

    #[test]
    fn system_files_and_big_folders_are_grouped_until_expanded() {
        let mut t: Vec<Touch> = (0..20)
            .map(|i| file(2, &format!("/home/u/pics/p{i}.jpg"), Act::Read, 1))
            .collect();
        t.push(file(2, "/usr/lib/x86_64-linux-gnu/libc.so.6", Act::Read, 3));
        t.push(file(2, "/proc/self/status", Act::Read, 1));
        t.push(file(2, "/etc/ld.so.cache", Act::Read, 1));
        let g = build_with(&t, &BuildOpts::default());
        let sys = &g.nodes[g.index(&NodeId::System).unwrap()];
        assert_eq!(sys.members, 3);
        let dir = &g.nodes[g.index(&NodeId::Dir("/home/u/pics".into())).unwrap()];
        assert_eq!((dir.members, dir.label.as_str()), (20, "pics/"));
        assert_eq!(g.count(Kind::File), 2);
        // Expanding both shows every file.
        let mut o = BuildOpts::default();
        o.expanded.insert(NodeId::System);
        o.expanded.insert(NodeId::Dir("/home/u/pics".into()));
        let g = build_with(&t, &o);
        assert_eq!(g.count(Kind::File), 23);
        // Turning the toggle off also shows the system files.
        let o = BuildOpts {
            hide_system: false,
            ..BuildOpts::default()
        };
        assert!(build_with(&t, &o).index(&NodeId::System).is_none());
    }

    #[test]
    fn flagged_files_are_never_hidden_in_a_group() {
        let mut t: Vec<Touch> = (0..20)
            .map(|i| file(2, &format!("/home/u/.ssh/k{i}"), Act::Read, 1))
            .collect();
        t.push(file(2, "/usr/lib/libx.so.1", Act::Read, 1));
        let mut flags = BTreeMap::new();
        flags.insert(
            NodeId::File("/home/u/.ssh/k3".into()),
            ("Read an SSH private key".to_string(), "why".to_string(), 7),
        );
        flags.insert(
            NodeId::File("/usr/lib/libx.so.1".into()),
            ("odd".to_string(), "why".to_string(), 8),
        );
        let p = procs(&[(2, None, "/tmp/try.sh")]);
        let g = build(k(2), &p, &t, &flags, &BuildOpts::default(), &plain);
        let n = &g.nodes[g.index(&NodeId::File("/home/u/.ssh/k3".into())).unwrap()];
        assert!(n.flagged && n.finding.as_ref().unwrap().2 == 7);
        assert!(
            g.index(&NodeId::File("/usr/lib/libx.so.1".into()))
                .is_some()
        );
        let e = g.edges.iter().find(|e| e.to == n.id).unwrap();
        assert!(e.flagged);
        // Flagged only keeps the flagged nodes and who touched them.
        let o = BuildOpts {
            flagged_only: true,
            ..BuildOpts::default()
        };
        let g = build(k(2), &p, &t, &flags, &o, &plain);
        assert_eq!(g.nodes.len(), 3);
    }

    #[test]
    fn the_cap_holds_with_2000_objects_and_states_how_many_were_folded() {
        // 2000 files in 2000 different folders (no folder grouping applies).
        let t: Vec<Touch> = (0..2000)
            .map(|i| file(2, &format!("/data/d{i}/f"), Act::Read, (i % 50) as u64 + 1))
            .collect();
        let start = std::time::Instant::now();
        let g = build_with(&t, &BuildOpts::default());
        assert!(g.nodes.len() <= CAP, "{} nodes", g.nodes.len());
        let files = g.count(Kind::File);
        let more = &g.nodes[g.index(&NodeId::More(Kind::File)).unwrap()];
        assert_eq!(g.capped, more.members);
        assert_eq!(files - 1 + more.members, 2000);
        assert!(more.label.starts_with('+') && more.label.ends_with("more"));
        // The most active files are the ones kept.
        let kept_min = g
            .nodes
            .iter()
            .filter(|n| matches!(n.id, NodeId::File(_)))
            .map(|n| n.count)
            .min()
            .unwrap();
        assert!(kept_min >= 40);
        assert!(start.elapsed().as_millis() < 500, "{:?}", start.elapsed());
    }

    #[test]
    fn redaction_applies_to_labels_and_paths() {
        let t = vec![file(2, "/home/alice/secret.txt", Act::Read, 1)];
        let p = procs(&[(2, None, "/home/alice/bin/tool")]);
        let red = |s: &str| s.replace("/home/alice", "~");
        let g = build(k(2), &p, &t, &BTreeMap::new(), &BuildOpts::default(), &red);
        let f = &g.nodes[g
            .index(&NodeId::File("/home/alice/secret.txt".into()))
            .unwrap()];
        assert_eq!(f.full, "~/secret.txt");
        assert!(
            g.nodes
                .iter()
                .all(|n| !n.full.contains("alice") && !n.label.contains("alice"))
        );
    }

    #[test]
    fn layout_settles_and_updates_do_not_reshuffle() {
        let t: Vec<Touch> = (0..30)
            .map(|i| file(2, &format!("/x/{i}/f"), Act::Read, 1))
            .collect();
        let mut m = MapState::default();
        m.set_center(k(2));
        let g = build_with(&t, &BuildOpts::default());
        m.sync(1, |_| g.clone());
        let mut steps = 0;
        while m.moving() && steps < 5000 {
            m.step();
            steps += 1;
        }
        assert!(!m.moving(), "not settled after {steps} steps");
        let before: Vec<P> = m
            .graph
            .nodes
            .iter()
            .map(|n| m.pos(&n.id).unwrap())
            .collect();
        // Idle: nothing moves.
        for _ in 0..100 {
            m.step();
        }
        let idle: Vec<P> = m
            .graph
            .nodes
            .iter()
            .map(|n| m.pos(&n.id).unwrap())
            .collect();
        assert_eq!(before, idle);
        // One new file: old nodes far from it stay where they were.
        let mut t2 = t.clone();
        t2.push(file(2, "/x/new/f", Act::Wrote, 1));
        let g2 = build_with(&t2, &BuildOpts::default());
        m.sync(2, |_| g2.clone());
        assert!(m.pos(&NodeId::File("/x/new/f".into())).is_some());
        let mut steps = 0;
        while m.moving() && steps < 5000 {
            m.step();
            steps += 1;
        }
        let moved = m
            .graph
            .nodes
            .iter()
            .zip(&before)
            .filter(|(n, p)| {
                let q = m.pos(&n.id).unwrap();
                ((q.x - p.x).powi(2) + (q.y - p.y).powi(2)).sqrt() > 1.0
            })
            .count();
        // Only the new node's neighbourhood (the centre is fixed, so at most
        // the new node itself) may move.
        assert!(moved <= 2, "{moved} old nodes moved");
    }

    #[test]
    fn time_window_search_and_double_click() {
        let mut t = vec![file(2, "/a", Act::Read, 1), file(2, "/b", Act::Read, 1)];
        t[0].first = Some(100);
        t[0].last = 100;
        t[1].first = Some(1000);
        t[1].last = 1000;
        let mut m = MapState::default();
        m.set_center(k(2));
        let g = build_with(&t, &BuildOpts::default());
        m.sync(1, |_| g.clone());
        let a = m.graph.nodes[m.graph.index(&NodeId::File("/a".into())).unwrap()].clone();
        let b = m.graph.nodes[m.graph.index(&NodeId::File("/b".into())).unwrap()].clone();
        m.on_action(MapAction::Time(0.5));
        assert!(m.in_window(&a) && !m.in_window(&b));
        m.on_action(MapAction::Search("/b".into()));
        assert!(m.matches(&b) && !m.matches(&a));
        assert_eq!(
            m.on_action(MapAction::DoubleClick(NodeId::Proc(k(3)))),
            Some(k(3))
        );
        m.on_action(MapAction::DoubleClick(NodeId::System));
        assert!(m.opts.expanded.contains(&NodeId::System));
    }

    #[test]
    fn hover_neighbourhood_filters_and_focus() {
        let t = vec![
            file(2, "/a", Act::Read, 5),
            file(3, "/b", Act::Wrote, 1),
            file(2, "/usr/lib/libc.so.6", Act::Read, 9),
        ];
        let mut m = MapState::default();
        m.set_center(k(2));
        let p = procs(&[
            (1, None, "/bin/bash"),
            (2, Some(1), "/tmp/try.sh"),
            (3, Some(2), "/bin/cat"),
        ]);
        let build_now = |m: &mut MapState, sig| {
            let t = t.clone();
            let p = p.clone();
            m.sync(sig, |o| build(k(2), &p, &t, &BTreeMap::new(), o, &plain));
        };
        build_now(&mut m, 1);
        // Hover: the node and its direct neighbours stay bright.
        let hood = m.neighbourhood(&NodeId::File("/a".into()));
        assert_eq!(hood, [NodeId::Proc(k(2)), NodeId::File("/a".into())].into());
        m.on_action(MapAction::Hover(Some(NodeId::File("/a".into()))));
        assert_eq!(m.hover, Some(NodeId::File("/a".into())));
        // Kind filter: files off leaves processes only.
        m.on_action(MapAction::ToggleKind(Kind::File));
        build_now(&mut m, 1);
        assert_eq!(m.graph.count(Kind::File), 0);
        m.on_action(MapAction::ToggleKind(Kind::File));
        build_now(&mut m, 1);
        assert!(m.graph.index(&NodeId::System).is_some());
        // The system-files toggle shows the library itself.
        m.on_action(MapAction::HideSystem);
        build_now(&mut m, 1);
        assert!(
            m.graph
                .index(&NodeId::File("/usr/lib/libc.so.6".into()))
                .is_some()
        );
        // Tab cycles by activity; Enter selects; empty click clears.
        m.on_action(MapAction::FocusNext);
        let first = m.focus.clone().unwrap();
        let top = m
            .graph
            .nodes
            .iter()
            .max_by_key(|n| n.count)
            .unwrap()
            .id
            .clone();
        assert_eq!(first, top);
        m.on_action(MapAction::SelectFocused);
        assert_eq!(m.selected, Some(first));
        m.on_action(MapAction::ClickEmpty);
        assert_eq!(m.selected, None);
        // Zoom is bounded; reset restores it.
        m.on_action(MapAction::Zoom(100.0));
        assert!(m.zoom <= 4.0);
        m.on_action(MapAction::ResetView);
        assert_eq!(m.zoom, 1.0);
    }

    #[test]
    fn touches_from_a_glasshouse_timeline() {
        use candor_proto::{BStr, Family, SockType};
        let ev = |id, kind| Event {
            id,
            ts_ns: id * 10,
            proc: k(2),
            tid: 2,
            uid: 1000,
            kind,
        };
        let events = vec![
            ev(
                1,
                EventKind::Open {
                    path: BStr::from("/home/u/.ssh/id_ed25519"),
                    dev: 1,
                    ino: 1,
                    read: true,
                    write: false,
                    create: false,
                    trunc: false,
                    path_trunc: false,
                },
            ),
            ev(
                2,
                EventKind::Unlink {
                    path: BStr::from("/home/u/Documents/a"),
                    dev: 1,
                    ino: 2,
                    approx: false,
                },
            ),
            ev(
                3,
                EventKind::Connect {
                    family: Family::Inet,
                    addr: "10.0.0.1".into(),
                    port: 443,
                    sock: SockType::Stream,
                },
            ),
            ev(4, EventKind::Fork { child: k(3) }),
        ];
        let t = touches_from_events(&events);
        let acts: BTreeSet<Act> = t.iter().map(|t| t.act).collect();
        assert_eq!(
            acts,
            [Act::Started, Act::Read, Act::Deleted, Act::Connected].into()
        );
        let g = build(
            k(2),
            &procs(&[(2, None, "/tmp/try.sh")]),
            &t,
            &BTreeMap::new(),
            &BuildOpts::default(),
            &plain,
        );
        assert!(g.index(&NodeId::Net("10.0.0.1:443".into())).is_some());
        assert!(g.index(&NodeId::Proc(k(3))).is_some());
    }
}
