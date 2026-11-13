//! One tracked process and its bounded per-process history.
//!
//! A `Proc` keeps counters, the last few thousand events, a CPU/memory
//! series and summaries of the files and connections it touched. Every
//! collection is capped by a constant in `limits.rs` (invariant I8); when a
//! summary is full, new distinct items are only counted as "other".

use crate::limits;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use sysscope_proto::{
    BStr, ConnStat, Event, EventKind, Family, FileStat, ProcKey, ProcRow, SockType, SysStat,
};

/// Key of a connection summary: one destination of one process.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConnKey {
    /// Family as text ("inet", ...), for ordering.
    pub family: String,
    /// Address.
    pub addr: String,
    /// Port.
    pub port: u16,
    /// Socket type as text.
    pub sock: String,
}

/// Connection summary value (the key holds the destination).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnEntry {
    /// Family.
    pub family: Family,
    /// Socket type.
    pub sock: SockType,
    /// Number of connects.
    pub count: u64,
    /// Last connect time (boot ns).
    pub last_ts: u64,
}

/// A tracked process.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Proc {
    /// Identity.
    pub key: ProcKey,
    /// Parent, if known and still in the state.
    pub parent: Option<ProcKey>,
    /// True if the parent has gone (exited and evicted).
    pub orphan: bool,
    /// Children still in the state.
    pub children: BTreeSet<ProcKey>,
    /// True while we only know this process from an event, not from exec or /proc.
    pub placeholder: bool,
    /// Executable path.
    pub exe: BStr,
    /// comm.
    pub comm: BStr,
    /// uid.
    pub uid: u32,
    /// Kernel thread.
    pub kthread: bool,
    /// Executable verified root-owned and not group/world-writable (5.3).
    pub exe_trusted: bool,
    /// Executable lives in a root-owned system directory.
    pub exe_system: bool,
    /// Home directory of the process's user, for "~/" path classes.
    pub home: BStr,
    /// CPU percent from the last two samples.
    pub cpu_pct: f32,
    /// (time, cpu ticks) of the previous sample.
    pub last_cpu: Option<(u64, u64)>,
    /// RSS bytes.
    pub rss: u64,
    /// Threads.
    pub threads: u32,
    /// IO read bytes.
    pub io_r: u64,
    /// IO written bytes.
    pub io_w: u64,
    /// Opens observed.
    pub n_open: u64,
    /// Connects observed.
    pub n_conn: u64,
    /// Execs observed.
    pub n_exec: u64,
    /// Children observed (FORK events).
    pub n_child: u64,
    /// Syscalls counted.
    pub n_sys: u64,
    /// Exit time, if exited.
    pub exited_ts: Option<u64>,
    /// Inside the followed tree.
    pub followed: bool,
    /// Kernel budget drops for this process.
    pub ev_dropped: u64,
    /// Consecutive full scans that did not contain this live process.
    pub missed_scans: u32,
    /// Time of the last event or sample (boot ns).
    pub last_seen: u64,
    /// Recent events, oldest first.
    pub recent: VecDeque<Event>,
    /// (time, cpu %, rss) samples, oldest first.
    pub series: VecDeque<(u64, f32, u64)>,
    /// Files by (dev, ino).
    pub files: BTreeMap<(u64, u64), FileStat>,
    /// Distinct files not kept because `files` was full.
    pub files_other: u64,
    /// Connections by destination.
    pub conns: BTreeMap<ConnKey, ConnEntry>,
    /// Distinct destinations not kept because `conns` was full.
    pub conns_other: u64,
    /// Syscall statistics by number.
    pub syscalls: BTreeMap<u32, SysStat>,
}

fn family_text(f: Family) -> &'static str {
    match f {
        Family::Inet => "inet",
        Family::Inet6 => "inet6",
        Family::Unix => "unix",
        Family::Other => "other",
    }
}

fn sock_text(s: SockType) -> &'static str {
    match s {
        SockType::Stream => "stream",
        SockType::Dgram => "dgram",
        SockType::Other => "other",
    }
}

impl Proc {
    /// A process known only by its key.
    pub fn placeholder(key: ProcKey, uid: u32, ts: u64) -> Proc {
        Proc {
            key,
            uid,
            placeholder: true,
            last_seen: ts,
            ..Proc::default()
        }
    }

    /// True if the process has not exited.
    pub fn is_live(&self) -> bool {
        self.exited_ts.is_none()
    }

    /// Adds an event to the bounded recent list.
    pub fn push_recent(&mut self, ev: &Event) {
        if self.recent.len() >= limits::PER_PROC_RECENT_EVENTS {
            self.recent.pop_front();
        }
        self.recent.push_back(ev.clone());
    }

    /// Records a file open in the bounded file summary.
    pub fn note_file(&mut self, path: &BStr, dev: u64, ino: u64, read: bool, write: bool, ts: u64) {
        if let Some(f) = self.files.get_mut(&(dev, ino)) {
            f.opens += 1;
            f.read |= read;
            f.write |= write;
            f.last_ts = ts;
            f.path = path.clone();
            return;
        }
        if self.files.len() >= limits::PER_PROC_FILES {
            self.files_other += 1;
            return;
        }
        self.files.insert(
            (dev, ino),
            FileStat {
                path: path.clone(),
                dev,
                ino,
                opens: 1,
                read,
                write,
                rbytes: 0,
                wbytes: 0,
                last_ts: ts,
            },
        );
    }

    /// Updates the displayed path of a known file (rename).
    pub fn rename_file(&mut self, dev: u64, ino: u64, new: &BStr) {
        if let Some(f) = self.files.get_mut(&(dev, ino)) {
            f.path = new.clone();
        }
    }

    /// Records a connect in the bounded connection summary.
    pub fn note_conn(&mut self, family: Family, addr: &str, port: u16, sock: SockType, ts: u64) {
        let key = ConnKey {
            family: family_text(family).to_string(),
            addr: addr.to_string(),
            port,
            sock: sock_text(sock).to_string(),
        };
        if let Some(c) = self.conns.get_mut(&key) {
            c.count += 1;
            c.last_ts = ts;
            return;
        }
        if self.conns.len() >= limits::PER_PROC_CONNS {
            self.conns_other += 1;
            return;
        }
        self.conns.insert(
            key,
            ConnEntry {
                family,
                sock,
                count: 1,
                last_ts: ts,
            },
        );
    }

    /// Adds a sample to the bounded series.
    pub fn push_series(&mut self, ts: u64, cpu: f32, rss: u64) {
        if self.series.len() >= limits::SERIES_POINTS {
            self.series.pop_front();
        }
        self.series.push_back((ts, cpu, rss));
    }

    /// Connection summaries in protocol form.
    pub fn conn_stats(&self) -> Vec<ConnStat> {
        self.conns
            .iter()
            .map(|(k, v)| ConnStat {
                family: v.family,
                addr: k.addr.clone(),
                port: k.port,
                sock: v.sock,
                count: v.count,
                last_ts: v.last_ts,
            })
            .collect()
    }

    /// Updates counters for one event (the caller has already routed it here).
    pub fn count_event(&mut self, ev: &Event) {
        self.last_seen = self.last_seen.max(ev.ts_ns);
        match &ev.kind {
            EventKind::Exec { exe, .. } => {
                self.exe = exe.clone();
                // A new executable is untrusted until the daemon checks it.
                self.exe_trusted = false;
                self.exe_system = false;
                self.placeholder = false;
                self.n_exec += 1;
            }
            EventKind::Fork { .. } => self.n_child += 1,
            EventKind::Exit {} => {
                if self.exited_ts.is_none() {
                    self.exited_ts = Some(ev.ts_ns);
                }
            }
            EventKind::Open {
                path,
                dev,
                ino,
                read,
                write,
                ..
            } => {
                self.n_open += 1;
                self.note_file(path, *dev, *ino, *read, *write, ev.ts_ns);
            }
            EventKind::Rename { new, dev, ino, .. } => self.rename_file(*dev, *ino, new),
            EventKind::Unlink { .. } | EventKind::Listen { .. } | EventKind::Ptrace { .. } => {}
            EventKind::Connect {
                family,
                addr,
                port,
                sock,
            } => {
                self.n_conn += 1;
                self.note_conn(*family, addr, *port, *sock, ev.ts_ns);
            }
        }
        self.push_recent(ev);
    }

    /// The snapshot row for this process. `parent` must already be checked
    /// to exist in the state (the caller passes `None` otherwise).
    pub fn row(&self, parent: Option<ProcKey>) -> ProcRow {
        ProcRow {
            key: self.key,
            parent,
            exe: self.exe.clone(),
            comm: self.comm.clone(),
            uid: self.uid,
            kthread: self.kthread,
            cpu_pct: self.cpu_pct,
            rss: self.rss,
            threads: self.threads,
            io_r: self.io_r,
            io_w: self.io_w,
            n_open: self.n_open,
            n_conn: self.n_conn,
            n_exec: self.n_exec,
            n_child: self.n_child,
            n_sys: self.n_sys,
            score: 0,
            tree_score: 0,
            top_rule: None,
            exited_ts: self.exited_ts,
            followed: self.followed,
            ev_dropped: self.ev_dropped,
        }
    }
}
