//! The GUI's view-model: everything the window shows, and nothing else.
//!
//! The UI code only reads a `Model` and turns clicks into `Action`s; it
//! never talks to the daemon itself. `apply` takes what the reader thread
//! delivers (daemon messages and connection changes); `on_action` changes
//! the view state and returns requests to send. Because the model is plain
//! data, every behaviour (sorting, filtering, pausing, selection) is tested
//! here without a window.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use sysscope_core::display::{safe, safe_str};
use sysscope_proto::{
    ClientMsg, DaemonMsg, DecoyStatus, Finding, GhReport, GhState, Loss, Mode, ProcKey, ProcRow,
};

/// Alerts kept in the list (newest first).
pub const MAX_ALERTS: usize = 256;
/// Detail replies kept.
pub const MAX_DETAILS: usize = 16;

/// State of the connection to the daemon.
#[derive(Clone, Debug, PartialEq)]
pub enum ConnState {
    /// Trying to connect.
    Connecting,
    /// Connected; daemon version and kernel.
    Connected {
        /// Daemon version.
        version: String,
        /// Kernel release.
        kernel: String,
        /// boot -> wall clock offset.
        boot_to_wall_ns: u64,
        /// Act mode available.
        act_enabled: bool,
    },
    /// Socket missing / connection refused.
    DaemonDown(String),
    /// Socket exists but we may not open it.
    PermissionDenied(String),
    /// Daemon speaks another protocol version.
    ProtoMismatch(String),
    /// Showing a recording, not a live daemon.
    Replay(String),
}

/// What the reader thread delivers.
#[derive(Clone, Debug)]
pub enum Incoming {
    /// A message from the daemon (or a replay file). Boxed: messages are
    /// large and the enum is moved through a channel.
    Msg(Box<DaemonMsg>),
    /// The connection changed.
    Conn(ConnState),
}

/// Sortable columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    /// Executable.
    Exe,
    /// Process id.
    Pid,
    /// User id.
    User,
    /// CPU percent.
    Cpu,
    /// Resident memory.
    Mem,
    /// Threads.
    Threads,
    /// Opens.
    Opens,
    /// Connections.
    Conns,
    /// Children.
    Children,
    /// Score.
    Score,
}

/// Detail tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// CPU/memory charts.
    Overview,
    /// Files.
    Files,
    /// Network.
    Network,
    /// Syscalls.
    Syscalls,
    /// Children.
    Children,
    /// Memory maps.
    Maps,
    /// Findings.
    Findings,
}

impl Tab {
    /// Stable name used in labels and --tab.
    pub fn name(self) -> &'static str {
        match self {
            Tab::Overview => "overview",
            Tab::Files => "files",
            Tab::Network => "network",
            Tab::Syscalls => "syscalls",
            Tab::Children => "children",
            Tab::Maps => "maps",
            Tab::Findings => "findings",
        }
    }

    /// All tabs in display order.
    pub fn all() -> [Tab; 7] {
        [
            Tab::Overview,
            Tab::Files,
            Tab::Network,
            Tab::Syscalls,
            Tab::Children,
            Tab::Maps,
            Tab::Findings,
        ]
    }

    /// Tab from its name.
    pub fn from_name(s: &str) -> Option<Tab> {
        Tab::all().into_iter().find(|t| t.name() == s)
    }
}

/// Top-level page of the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// Process table, details, alerts.
    Processes,
    /// Glasshouse sandbox runs.
    Glasshouse,
}

/// A directory listing for the in-window file picker (filled by the app).
#[derive(Clone, Debug, PartialEq)]
pub struct Browse {
    /// Directory shown.
    pub dir: std::path::PathBuf,
    /// (escaped name, is a directory), directories first.
    pub entries: Vec<(String, bool)>,
    /// Entries left out (cap) or why the directory could not be read.
    pub note: Option<String>,
}

/// State of the Glasshouse page.
#[derive(Clone, Debug, PartialEq)]
pub struct GhView {
    /// Program file to run (typed or picked).
    pub path: String,
    /// Arguments, separated by spaces.
    pub args: String,
    /// Timeout in seconds (1..600).
    pub timeout_s: u32,
    /// The daemon offers Glasshouse on this system (Welcome features).
    pub offered: bool,
    /// Current or last run id (escaped).
    pub run_id: String,
    /// Current or last state.
    pub state: Option<GhState>,
    /// Last status text (escaped).
    pub message: String,
    /// Decoy states: live while running, final from the report.
    pub decoys: Vec<DecoyStatus>,
    /// Final report.
    pub report: Option<Box<GhReport>>,
    /// Open file picker.
    pub browse: Option<Browse>,
}

impl Default for GhView {
    fn default() -> Self {
        GhView {
            path: String::new(),
            args: String::new(),
            timeout_s: 60,
            offered: false,
            run_id: String::new(),
            state: None,
            message: String::new(),
            decoys: Vec::new(),
            report: None,
            browse: None,
        }
    }
}

impl GhView {
    /// A run is in progress (upload, start or running).
    pub fn running(&self) -> bool {
        matches!(
            self.state,
            Some(GhState::Uploading | GhState::Starting | GhState::Running)
        )
    }
}

/// What the user did.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Click on a column header: sort by it (again = reverse).
    Sort(Column),
    /// New filter text.
    Filter(String),
    /// Pause or resume the display.
    TogglePause,
    /// Table or tree view.
    ToggleTree,
    /// Select a process (None = clear).
    Select(Option<ProcKey>),
    /// Select by pid (command line --select).
    SelectPid(u32),
    /// Switch the detail tab.
    ShowTab(Tab),
    /// Click on an alert: select its process.
    ClickAlert(usize),
    /// Ask to follow a process tree: opens the confirmation (WP21).
    RequestFollow(ProcKey),
    /// The user confirmed: send the follow request.
    ConfirmFollow,
    /// The user cancelled the confirmation.
    CancelFollow,
    /// Ask the daemon to follow a process tree (no confirmation).
    Follow(ProcKey),
    /// Back to system-wide.
    Unfollow,
    /// Export the table (handled by the app, which writes the file).
    Export,
    /// Hide the loss banner until more events are lost.
    DismissLoss,
    /// Switch the top-level page.
    ShowPage(Page),
    /// Glasshouse: program path typed.
    GhSetPath(String),
    /// Glasshouse: arguments typed.
    GhSetArgs(String),
    /// Glasshouse: timeout changed.
    GhSetTimeout(u32),
    /// Glasshouse: open the picker at a directory (the app lists it).
    GhBrowse(std::path::PathBuf),
    /// Glasshouse: picker entry chosen (a file path).
    GhPick(String),
    /// Glasshouse: close the picker.
    GhCloseBrowse,
    /// Glasshouse: run (the app reads the file and uploads it).
    GhRun,
    /// Glasshouse: cancel the run.
    GhCancel,
    /// Glasshouse: export the report (the app writes the files).
    GhExport,
    /// Act (experimental): pause a process.
    ActPause(ProcKey),
    /// Act: resume a process (also the undo of a pause).
    ActResume(ProcKey),
    /// Act: the text typed to confirm a kill.
    ActKillText(String),
    /// Act: kill, only if the typed text is the pid.
    ActKill(ProcKey),
}

/// One row as displayed (already escaped, with tree depth).
#[derive(Clone, Debug, PartialEq)]
pub struct RowView {
    /// The row data.
    pub row: ProcRow,
    /// Display name (exe, or [comm] for kernel threads), escaped.
    pub name: String,
    /// Indentation level in tree mode (0 in table mode).
    pub depth: usize,
    /// Band text: "", "low", "suspicious", "high" (never colour alone).
    pub band: &'static str,
}

/// The whole view state.
#[derive(Clone, Debug)]
pub struct Model {
    /// Connection state.
    pub conn: ConnState,
    /// Rows of the snapshot being displayed.
    pub rows: Vec<ProcRow>,
    /// Mode of the displayed snapshot.
    pub mode: Mode,
    /// Loss counters of the displayed snapshot.
    pub loss: Loss,
    /// Sequence number of the displayed snapshot.
    pub seq: u64,
    /// While paused, the newest snapshot that arrived (shown on resume).
    pending: Option<(Vec<ProcRow>, Mode, Loss, u64)>,
    /// Snapshots skipped while paused.
    pub skipped: u64,
    /// Display frozen.
    pub paused: bool,
    /// Tree instead of table.
    pub tree: bool,
    /// Sort column and descending flag.
    pub sort: (Column, bool),
    /// Filter text.
    pub filter: String,
    /// Selected process.
    pub selected: Option<ProcKey>,
    /// Detail tab.
    pub tab: Tab,
    /// Detail replies by process (bounded).
    details: BTreeMap<ProcKey, DaemonMsg>,
    detail_order: VecDeque<ProcKey>,
    /// Alerts, newest first (bounded).
    pub alerts: VecDeque<Finding>,
    /// Last message from a follow/unfollow request.
    pub notice: Option<String>,
    /// Optional features the daemon does not offer, as display lines
    /// ("<feature>: not available on this kernel: <reason>", plan WP31).
    pub unavailable: Vec<String>,
    /// The reason Glasshouse is not offered, if the daemon gave one.
    pub gh_unavailable: Option<String>,
    /// Process waiting for the follow confirmation.
    pub confirm_follow: Option<ProcKey>,
    /// Loss total already acknowledged by the user (banner hides until it grows).
    pub loss_seen: u64,
    /// Rows as displayed, recomputed only when data or view settings change
    /// (not every frame: 2000 rows at 60 fps would cost too much, WP21).
    visible: Vec<RowView>,
    multi_user_cached: bool,
    /// Top-level page.
    pub page: Page,
    /// Glasshouse page state.
    pub gh: GhView,
    /// Act: text typed to confirm a kill.
    pub act_kill_text: String,
    /// Act: the last process paused from this window (offers undo).
    pub act_paused: Option<ProcKey>,
}

impl Default for Model {
    fn default() -> Self {
        Model::new()
    }
}

fn act_msg(k: ProcKey, action: sysscope_proto::ActAction) -> Vec<ClientMsg> {
    vec![ClientMsg::Act {
        proc: k,
        action,
        nonce: "gui".into(),
    }]
}

/// True when the daemon runs with act mode enabled.
pub fn act_enabled(m: &Model) -> bool {
    matches!(
        m.conn,
        ConnState::Connected {
            act_enabled: true,
            ..
        }
    )
}

fn band(score: u8) -> &'static str {
    match score {
        0 => "",
        1..=29 => "low",
        30..=59 => "suspicious",
        _ => "high",
    }
}

fn display_name(r: &ProcRow) -> String {
    if r.exe.as_bytes().is_empty() {
        format!("[{}]", safe(&r.comm))
    } else {
        sysscope_core::display::exe_shown(r)
    }
}

impl Model {
    /// An empty model, connecting.
    pub fn new() -> Model {
        Model {
            conn: ConnState::Connecting,
            rows: Vec::new(),
            mode: Mode::System(sysscope_proto::SystemMode::System),
            loss: Loss::default(),
            seq: 0,
            pending: None,
            skipped: 0,
            paused: false,
            tree: false,
            sort: (Column::Cpu, true),
            filter: String::new(),
            selected: None,
            tab: Tab::Overview,
            details: BTreeMap::new(),
            detail_order: VecDeque::new(),
            alerts: VecDeque::new(),
            notice: None,
            unavailable: Vec::new(),
            gh_unavailable: None,
            confirm_follow: None,
            loss_seen: 0,
            visible: Vec::new(),
            multi_user_cached: false,
            page: Page::Processes,
            gh: GhView::default(),
            act_kill_text: String::new(),
            act_paused: None,
        }
    }

    /// The cached display rows (see `visible_rows` for how they are built).
    pub fn visible(&self) -> &[RowView] {
        &self.visible
    }

    fn refresh(&mut self) {
        self.visible = self.visible_rows();
        self.multi_user_cached = self.multi_user();
    }

    /// `multi_user` as of the last data or view change (cheap per frame).
    pub fn multi_user_now(&self) -> bool {
        self.multi_user_cached
    }

    /// Events lost in the kernel so far (all reasons).
    pub fn loss_total(&self) -> u64 {
        // Saturating: hostile counters near u64::MAX must not wrap (and hide
        // the banner) or panic.
        self.loss
            .ringbuf
            .saturating_add(self.loss.budget)
            .saturating_add(self.loss.scratch)
            .saturating_add(self.loss.decode)
            .saturating_add(self.loss.untracked)
    }

    /// True when new losses happened since the user last dismissed the banner.
    pub fn loss_banner(&self) -> bool {
        self.loss_total() > self.loss_seen
    }

    /// Detail of the selected process, if received.
    pub fn detail(&self) -> Option<&DaemonMsg> {
        self.selected.and_then(|k| self.details.get(&k))
    }

    /// Takes one delivery from the reader thread.
    pub fn apply(&mut self, inc: Incoming) {
        match inc {
            Incoming::Conn(c) => self.conn = c,
            Incoming::Msg(m) => self.apply_msg(*m),
        }
    }

    fn apply_msg(&mut self, m: DaemonMsg) {
        match m {
            DaemonMsg::Welcome {
                daemon_version,
                kernel,
                boot_to_wall_ns,
                act_enabled,
                features,
                unavailable,
                ..
            } => {
                self.gh.offered = features.iter().any(|f| f == "glasshouse");
                self.unavailable = unavailable
                    .iter()
                    .map(sysscope_core::display::feature_note)
                    .collect();
                self.gh_unavailable = unavailable
                    .iter()
                    .find(|n| n.feature == "glasshouse")
                    .map(|n| safe_str(&n.reason));
                if !matches!(self.conn, ConnState::Replay(_)) {
                    self.conn = ConnState::Connected {
                        version: safe_str(&daemon_version),
                        kernel: safe_str(&kernel),
                        boot_to_wall_ns,
                        act_enabled,
                    };
                }
            }
            DaemonMsg::Snapshot {
                seq,
                procs,
                mode,
                loss,
                ..
            } => {
                if self.paused {
                    // Keep receiving, but only the newest (bounded) is kept.
                    if self.pending.is_some() {
                        self.skipped += 1;
                    }
                    self.pending = Some((procs, mode, loss, seq));
                } else {
                    self.show(procs, mode, loss, seq);
                }
            }
            DaemonMsg::Alert { finding } => {
                if self.alerts.len() >= MAX_ALERTS {
                    self.alerts.pop_back();
                }
                self.alerts.push_front(finding);
            }
            d @ DaemonMsg::Detail { .. } => {
                if let DaemonMsg::Detail { proc, .. } = &d {
                    let k = *proc;
                    if !self.details.contains_key(&k) {
                        self.detail_order.push_back(k);
                        if self.detail_order.len() > MAX_DETAILS
                            && let Some(old) = self.detail_order.pop_front()
                        {
                            self.details.remove(&old);
                        }
                    }
                    self.details.insert(k, d);
                }
            }
            DaemonMsg::ActResult { message, .. } => self.notice = Some(safe_str(&message)),
            DaemonMsg::GhStatus {
                state,
                run_id,
                message,
                decoys,
            } => {
                self.gh.run_id = safe_str(&run_id);
                self.gh.state = Some(state);
                if !message.is_empty() {
                    self.gh.message = safe_str(&message);
                }
                if !decoys.is_empty() {
                    self.gh.decoys = decoys;
                }
            }
            DaemonMsg::GhReport { report } => {
                self.gh.run_id = safe_str(&report.run_id);
                self.gh.decoys = report.decoys.clone();
                self.gh.report = Some(Box::new(report));
            }
            DaemonMsg::Error { code, message } => {
                if self.gh.running()
                    && matches!(code.as_str(), "busy" | "bad_request" | "glasshouse_failed")
                {
                    // A refused upload or run ends the run on the page.
                    self.gh.state = Some(GhState::Failed);
                    self.gh.message = format!("{}: {}", safe_str(&code), safe_str(&message));
                } else if code == "proto_mismatch" {
                    self.conn = ConnState::ProtoMismatch(safe_str(&message));
                } else {
                    self.notice = Some(format!("{}: {}", safe_str(&code), safe_str(&message)));
                }
            }
            _ => {}
        }
    }

    fn show(&mut self, procs: Vec<ProcRow>, mode: Mode, loss: Loss, seq: u64) {
        self.rows = procs;
        self.mode = mode;
        self.loss = loss;
        self.seq = seq;
        // A selected process that is no longer reported is deselected.
        if let Some(k) = self.selected
            && !self.rows.iter().any(|r| r.key == k)
        {
            self.selected = None;
            self.details.remove(&k);
        }
        self.refresh();
    }

    /// Applies a user action; returns requests to send to the daemon.
    pub fn on_action(&mut self, a: Action) -> Vec<ClientMsg> {
        let view_change = matches!(a, Action::Sort(_) | Action::Filter(_) | Action::ToggleTree);
        let out = self.on_action_inner(a);
        if view_change {
            self.refresh();
        }
        out
    }

    fn on_action_inner(&mut self, a: Action) -> Vec<ClientMsg> {
        match a {
            Action::Sort(c) => {
                self.sort = if self.sort.0 == c {
                    (c, !self.sort.1)
                } else {
                    (c, !matches!(c, Column::Exe | Column::Pid | Column::User))
                };
            }
            Action::Filter(f) => self.filter = f,
            Action::TogglePause => {
                self.paused = !self.paused;
                if !self.paused
                    && let Some((p, m, l, s)) = self.pending.take()
                {
                    self.show(p, m, l, s);
                }
            }
            Action::ToggleTree => self.tree = !self.tree,
            Action::Select(k) => return self.select(k),
            Action::SelectPid(pid) => {
                let k = self
                    .rows
                    .iter()
                    .filter(|r| r.key.tgid == pid)
                    .map(|r| r.key)
                    .max();
                return self.select(k);
            }
            Action::ShowTab(t) => {
                self.tab = t;
                if t == Tab::Maps
                    && let Some(k) = self.selected
                {
                    return vec![ClientMsg::GetDetail {
                        proc: k,
                        maps: true,
                    }];
                }
            }
            Action::ClickAlert(i) => {
                if let Some(f) = self.alerts.get(i) {
                    let k = f.proc;
                    self.tab = Tab::Findings;
                    return self.select(Some(k));
                }
            }
            Action::RequestFollow(k) => self.confirm_follow = Some(k),
            Action::ConfirmFollow => {
                if let Some(k) = self.confirm_follow.take() {
                    return vec![ClientMsg::Follow { root: k }];
                }
            }
            Action::CancelFollow => self.confirm_follow = None,
            Action::DismissLoss => self.loss_seen = self.loss_total(),
            Action::Follow(k) => return vec![ClientMsg::Follow { root: k }],
            Action::Unfollow => return vec![ClientMsg::Unfollow {}],
            Action::Export => {}
            Action::ShowPage(p) => self.page = p,
            Action::GhSetPath(p) => self.gh.path = p,
            Action::GhSetArgs(a) => self.gh.args = a,
            Action::GhSetTimeout(t) => self.gh.timeout_s = t.clamp(1, 600),
            Action::GhPick(p) => {
                self.gh.path = p;
                self.gh.browse = None;
            }
            Action::GhCloseBrowse => self.gh.browse = None,
            // Done by the app (file system access): GhBrowse, GhRun, GhExport.
            Action::GhBrowse(_) | Action::GhRun | Action::GhExport => {}
            Action::ActPause(k) => {
                self.act_paused = Some(k);
                return act_msg(k, sysscope_proto::ActAction::Pause);
            }
            Action::ActResume(k) => {
                if self.act_paused == Some(k) {
                    self.act_paused = None;
                }
                return act_msg(k, sysscope_proto::ActAction::Resume);
            }
            Action::ActKillText(t) => self.act_kill_text = t,
            Action::ActKill(k) => {
                // Typing the pid is the confirmation.
                if self.act_kill_text.trim() == k.tgid.to_string() {
                    self.act_kill_text.clear();
                    return act_msg(k, sysscope_proto::ActAction::Kill);
                }
                self.notice = Some("type the pid to confirm the kill".into());
            }
            Action::GhCancel => {
                if self.gh.running() {
                    return vec![ClientMsg::GhCancel {}];
                }
            }
        }
        Vec::new()
    }

    fn select(&mut self, k: Option<ProcKey>) -> Vec<ClientMsg> {
        self.selected = k;
        match k {
            Some(k) => vec![ClientMsg::GetDetail {
                proc: k,
                maps: self.tab == Tab::Maps,
            }],
            None => Vec::new(),
        }
    }

    fn matches(&self, r: &ProcRow, name: &str) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let f = self.filter.to_lowercase();
        name.to_lowercase().contains(&f)
            || r.key.tgid.to_string().contains(&f)
            || r.uid.to_string() == f
            || r.top_rule
                .as_ref()
                .is_some_and(|t| t.to_lowercase().contains(&f))
    }

    fn cmp(&self, a: &RowView, b: &RowView) -> std::cmp::Ordering {
        let (x, y) = (&a.row, &b.row);
        let o = match self.sort.0 {
            Column::Exe => a.name.cmp(&b.name),
            Column::Pid => x.key.cmp(&y.key),
            Column::User => x.uid.cmp(&y.uid),
            Column::Cpu => x.cpu_pct.total_cmp(&y.cpu_pct),
            Column::Mem => x.rss.cmp(&y.rss),
            Column::Threads => x.threads.cmp(&y.threads),
            Column::Opens => x.n_open.cmp(&y.n_open),
            Column::Conns => x.n_conn.cmp(&y.n_conn),
            Column::Children => x.n_child.cmp(&y.n_child),
            Column::Score => (x.score, x.tree_score).cmp(&(y.score, y.tree_score)),
        };
        // Ties keep a stable order by key so rows do not jump around.
        let o = if self.sort.1 { o.reverse() } else { o };
        o.then_with(|| x.key.cmp(&y.key))
    }

    /// Rows to display: filtered, sorted, and in tree mode nested.
    pub fn visible_rows(&self) -> Vec<RowView> {
        let views: Vec<RowView> = self
            .rows
            .iter()
            .map(|r| RowView {
                name: display_name(r),
                row: r.clone(),
                depth: 0,
                band: band(r.score),
            })
            .filter(|v| self.matches(&v.row, &v.name))
            .collect();
        if !self.tree {
            let mut v = views;
            v.sort_by(|a, b| self.cmp(a, b));
            return v;
        }
        // Tree: roots are rows whose parent is missing (or filtered out).
        let present: BTreeSet<ProcKey> = views.iter().map(|v| v.row.key).collect();
        let mut children: BTreeMap<ProcKey, Vec<&RowView>> = BTreeMap::new();
        let mut roots: Vec<&RowView> = Vec::new();
        for v in &views {
            match v
                .row
                .parent
                .filter(|p| present.contains(p) && *p != v.row.key)
            {
                Some(p) => children.entry(p).or_default().push(v),
                None => roots.push(v),
            }
        }
        roots.sort_by(|a, b| self.cmp(a, b));
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack: Vec<(&RowView, usize)> = roots.into_iter().rev().map(|r| (r, 0)).collect();
        while let Some((v, d)) = stack.pop() {
            if !seen.insert(v.row.key) {
                continue; // defensive: never loop on bad parent links
            }
            let mut rv = v.clone();
            rv.depth = d;
            out.push(rv);
            if let Some(kids) = children.get(&v.row.key) {
                let mut kids = kids.clone();
                kids.sort_by(|a, b| self.cmp(a, b));
                for k in kids.into_iter().rev() {
                    stack.push((k, d + 1));
                }
            }
        }
        out
    }

    /// True if more than one human user has processes (9.1 notice).
    pub fn multi_user(&self) -> bool {
        let humans: BTreeSet<u32> = self
            .rows
            .iter()
            .filter(|r| r.uid >= 1000 && r.uid != u32::MAX - 1 && !r.kthread)
            .map(|r| r.uid)
            .collect();
        humans.len() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysscope_proto::{BStr, SystemMode};

    fn key(t: u32) -> ProcKey {
        ProcKey {
            tgid: t,
            start_ticks: 1,
        }
    }

    fn row(t: u32, parent: Option<u32>, exe: &str, cpu: f32, uid: u32) -> ProcRow {
        ProcRow {
            key: key(t),
            parent: parent.map(key),
            exe: BStr::from(exe),
            cpu_pct: cpu,
            uid,
            ..ProcRow::default()
        }
    }

    fn snap(seq: u64, procs: Vec<ProcRow>) -> Incoming {
        Incoming::Msg(Box::new(DaemonMsg::Snapshot {
            seq,
            ts_ns: seq,
            mode: Mode::System(SystemMode::System),
            procs,
            loss: Loss::default(),
        }))
    }

    #[test]
    fn unavailable_features_are_shown_with_their_reason() {
        let mut m = Model::new();
        m.apply(Incoming::Msg(Box::new(DaemonMsg::Welcome {
            proto: 1,
            daemon_version: "t".into(),
            kernel: "k".into(),
            boot_to_wall_ns: 0,
            features: vec!["exec".into()],
            unavailable: vec![
                sysscope_proto::FeatureNote {
                    feature: "ptrace".into(),
                    kernel: true,
                    reason: "no ptrace hook".into(),
                },
                sysscope_proto::FeatureNote {
                    feature: "glasshouse".into(),
                    kernel: false,
                    reason: "AppArmor blocks user namespaces".into(),
                },
            ],
            act_enabled: false,
        })));
        assert_eq!(
            m.unavailable,
            vec![
                "ptrace: not available on this kernel: no ptrace hook".to_string(),
                "glasshouse: not available: AppArmor blocks user namespaces".to_string(),
            ]
        );
        assert!(!m.gh.offered);
        assert_eq!(
            m.gh_unavailable.as_deref(),
            Some("AppArmor blocks user namespaces")
        );
    }

    #[test]
    fn glasshouse_status_and_report_update_the_page() {
        use sysscope_proto::{BStr, DecoyState};
        let mut m = Model::new();
        m.apply(Incoming::Msg(Box::new(DaemonMsg::Welcome {
            proto: 1,
            daemon_version: "t".into(),
            kernel: "k".into(),
            boot_to_wall_ns: 0,
            features: vec!["glasshouse".into()],
            unavailable: Vec::new(),
            act_enabled: false,
        })));
        assert!(m.gh.offered);
        let decoy = DecoyStatus {
            path: BStr::from("/home/victim/.ssh/id_ed25519"),
            dev: 1,
            ino: 2,
            states: vec![DecoyState::Read],
            new_path: None,
            size_before: 3,
            size_after: None,
            entropy_before: 1.0,
            entropy_after: None,
        };
        m.apply(Incoming::Msg(Box::new(DaemonMsg::GhStatus {
            state: GhState::Running,
            run_id: "r\u{1b}1".into(),
            message: "sample started".into(),
            decoys: vec![decoy.clone()],
        })));
        assert!(m.gh.running());
        assert!(!m.gh.run_id.contains('\u{1b}'));
        assert_eq!(m.gh.decoys, vec![decoy]);
        // An empty live update keeps the message and the decoys.
        m.apply(Incoming::Msg(Box::new(DaemonMsg::GhStatus {
            state: GhState::Running,
            run_id: "r1".into(),
            message: String::new(),
            decoys: vec![],
        })));
        assert_eq!(m.gh.message, "sample started");
        assert_eq!(m.gh.decoys.len(), 1);
        assert_eq!(m.on_action(Action::GhCancel), vec![ClientMsg::GhCancel {}]);
        m.apply(Incoming::Msg(Box::new(DaemonMsg::Error {
            code: "glasshouse_failed".into(),
            message: "x".into(),
        })));
        assert_eq!(m.gh.state, Some(GhState::Failed));
        assert!(m.on_action(Action::GhCancel).is_empty());
        m.on_action(Action::GhSetTimeout(0));
        assert_eq!(m.gh.timeout_s, 1);
    }

    #[test]
    fn act_kill_needs_the_typed_pid_and_pause_offers_undo() {
        let mut m = Model::new();
        let k = key(4242);
        assert_eq!(m.on_action(Action::ActKill(k)), vec![]);
        assert!(m.notice.as_deref().unwrap_or("").contains("type the pid"));
        m.on_action(Action::ActKillText("4241".into()));
        assert_eq!(m.on_action(Action::ActKill(k)), vec![]);
        m.on_action(Action::ActKillText(" 4242 ".into()));
        assert_eq!(m.on_action(Action::ActKill(k)).len(), 1);
        assert!(m.act_kill_text.is_empty());
        assert_eq!(m.on_action(Action::ActPause(k)).len(), 1);
        assert_eq!(m.act_paused, Some(k));
        assert_eq!(m.on_action(Action::ActResume(k)).len(), 1);
        assert_eq!(m.act_paused, None);
    }

    fn pids(m: &Model) -> Vec<u32> {
        m.visible_rows().iter().map(|v| v.row.key.tgid).collect()
    }

    fn sample() -> Vec<ProcRow> {
        vec![
            row(1, None, "/usr/lib/systemd/systemd", 1.0, 0),
            row(10, Some(1), "/usr/bin/bash", 5.0, 1000),
            row(11, Some(10), "/usr/bin/vim", 5.0, 1000),
            row(12, Some(10), "/tmp/x", 50.0, 1000),
            row(20, Some(99), "/usr/bin/orphan", 0.0, 1001),
        ]
    }

    #[test]
    fn sort_is_stable_and_toggles() {
        let mut m = Model::new();
        m.apply(snap(1, sample()));
        // CPU descending by default; ties (10, 11 at 5.0) ordered by key.
        assert_eq!(pids(&m), vec![12, 10, 11, 1, 20]);
        m.on_action(Action::Sort(Column::Cpu));
        assert_eq!(pids(&m), vec![20, 1, 10, 11, 12]);
        m.on_action(Action::Sort(Column::Exe));
        assert_eq!(pids(&m)[0], 12); // "/tmp/x" sorts first ascending
        // Same data again: same order (no jumping between refreshes).
        let before = pids(&m);
        m.apply(snap(2, sample()));
        assert_eq!(pids(&m), before);
    }

    #[test]
    fn filter_matches_exe_pid_uid_and_rule_case_insensitively() {
        let mut m = Model::new();
        let mut rows = sample();
        rows[3].top_rule = Some("R002".into());
        m.apply(snap(1, rows));
        m.on_action(Action::Filter("VIM".into()));
        assert_eq!(pids(&m), vec![11]);
        m.on_action(Action::Filter("20".into()));
        assert_eq!(pids(&m), vec![20]);
        m.on_action(Action::Filter("1001".into()));
        assert_eq!(pids(&m), vec![20]);
        m.on_action(Action::Filter("r002".into()));
        assert_eq!(pids(&m), vec![12]);
        m.on_action(Action::Filter(String::new()));
        assert_eq!(pids(&m).len(), 5);
    }

    #[test]
    fn pause_freezes_display_but_keeps_only_the_latest() {
        let mut m = Model::new();
        m.apply(snap(1, sample()));
        m.on_action(Action::TogglePause);
        for s in 2..=5 {
            m.apply(snap(s, vec![row(s as u32 * 100, None, "/x", 0.0, 0)]));
        }
        assert_eq!(m.seq, 1);
        assert_eq!(pids(&m).len(), 5);
        assert_eq!(m.skipped, 3);
        m.on_action(Action::TogglePause);
        assert_eq!(m.seq, 5);
        assert_eq!(pids(&m), vec![500]);
    }

    #[test]
    fn selection_survives_resort_and_clears_on_eviction() {
        let mut m = Model::new();
        m.apply(snap(1, sample()));
        let req = m.on_action(Action::SelectPid(11));
        assert_eq!(
            req,
            vec![ClientMsg::GetDetail {
                proc: key(11),
                maps: false
            }]
        );
        m.on_action(Action::Sort(Column::Mem));
        m.apply(snap(2, sample()));
        assert_eq!(m.selected, Some(key(11)));
        let mut rows = sample();
        rows.retain(|r| r.key.tgid != 11);
        m.apply(snap(3, rows));
        assert_eq!(m.selected, None);
        assert!(m.detail().is_none());
    }

    #[test]
    fn tree_nests_children_and_handles_missing_parents() {
        let mut m = Model::new();
        m.apply(snap(1, sample()));
        m.on_action(Action::ToggleTree);
        let v = m.visible_rows();
        let got: Vec<(u32, usize)> = v.iter().map(|r| (r.row.key.tgid, r.depth)).collect();
        // 20's parent 99 is missing: it is a root. Children follow parents.
        assert_eq!(got, vec![(1, 0), (10, 1), (12, 2), (11, 2), (20, 0)]);
        // A self-parented or cyclic row does not loop.
        let mut rows = sample();
        rows.push(row(30, Some(30), "/self", 0.0, 0));
        m.apply(snap(2, rows));
        assert_eq!(m.visible_rows().len(), 6);
    }

    #[test]
    fn alerts_are_bounded_newest_first_and_clickable() {
        let mut m = Model::new();
        m.apply(snap(1, sample()));
        for i in 0..(MAX_ALERTS as u32 + 10) {
            let f = Finding {
                id: u64::from(i),
                rule: "R002".into(),
                title: "t".into(),
                subject: "/tmp/".into(),
                attack: None,
                proc: key(12),
                exe: BStr::from("/tmp/x"),
                ts_ns: 0,
                weight: 0.4,
                confidence: 1.0,
                summary: String::new(),
                why: vec![],
                benign: vec![],
                evidence: vec![1],
                evidence_events: vec![],
            };
            m.apply(Incoming::Msg(Box::new(DaemonMsg::Alert { finding: f })));
        }
        assert_eq!(m.alerts.len(), MAX_ALERTS);
        assert_eq!(m.alerts[0].id, u64::from(MAX_ALERTS as u32 + 9));
        let req = m.on_action(Action::ClickAlert(0));
        assert_eq!(m.selected, Some(key(12)));
        assert_eq!(m.tab, Tab::Findings);
        assert_eq!(req.len(), 1);
    }

    #[test]
    fn follow_needs_confirmation_and_loss_banner_reappears_on_new_loss() {
        let mut m = Model::new();
        m.apply(snap(1, sample()));
        assert!(m.on_action(Action::RequestFollow(key(10))).is_empty());
        assert_eq!(m.confirm_follow, Some(key(10)));
        assert!(m.on_action(Action::CancelFollow).is_empty());
        m.on_action(Action::RequestFollow(key(10)));
        assert_eq!(
            m.on_action(Action::ConfirmFollow),
            vec![ClientMsg::Follow { root: key(10) }]
        );
        assert_eq!(m.confirm_follow, None);
        m.loss.budget = 5;
        assert!(m.loss_banner());
        m.on_action(Action::DismissLoss);
        assert!(!m.loss_banner());
        m.loss.budget = 6;
        assert!(m.loss_banner());
    }

    #[test]
    fn hostile_names_are_escaped_and_states_tracked() {
        let mut m = Model::new();
        let mut r = row(5, None, "", 0.0, 0);
        r.exe = BStr::new("/tmp/\u{202e}gpj.exe\x1b[2J".as_bytes().to_vec());
        m.apply(snap(1, vec![r]));
        let name = &m.visible_rows()[0].name;
        assert!(
            !name.contains('\u{202e}') && !name.contains('\x1b'),
            "{name}"
        );
        m.apply(Incoming::Msg(Box::new(DaemonMsg::Error {
            code: "proto_mismatch".into(),
            message: "x".into(),
        })));
        assert!(matches!(m.conn, ConnState::ProtoMismatch(_)));
        assert!(!m.multi_user());
        m.apply(snap(
            2,
            vec![row(1, None, "/a", 0.0, 1000), row(2, None, "/b", 0.0, 1001)],
        ));
        assert!(m.multi_user());
    }
}
