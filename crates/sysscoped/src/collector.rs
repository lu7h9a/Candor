//! Loads the BPF object, attaches the programs and reads the kernel side.
//!
//! `Collector` owns the loaded skeleton. Only the poller thread (T1) touches
//! it: it drains the ring buffer, applies follow/unfollow requests and once a
//! second reads the loss counters, per-process budget drops and syscall
//! totals. Everything it learns goes to the core thread as `PollerMsg`s over
//! a bounded channel; when that channel is full the poller blocks, the ring
//! buffer fills and the kernel counts the drops (D10: one place of loss).

use crate::abi::{self, skel};
use crate::convert;
use crate::mounts::Mounts;
use crate::syscalls::SysTotals;
use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sysscope_proto::{Event, Loss, ProcKey};

/// Default per-tgid event budget (events per second) and burst (plan 4.3).
pub const BUDGET_RATE: u32 = 2000;
/// Default per-tgid burst.
pub const BUDGET_BURST: u32 = 4000;

/// What the poller tells the core thread.
#[derive(Debug)]
pub enum PollerMsg {
    /// One kernel event, already converted.
    Event(Event),
    /// Kernel loss counters (cumulative).
    Loss(Loss),
    /// Budget + ring-buffer drops per process during the last second.
    Drops {
        /// Boot ns.
        ts_ns: u64,
        /// (process, events dropped in that second).
        per_proc: Vec<(ProcKey, u64)>,
    },
    /// Cumulative syscall totals per (process, nr).
    Sys {
        /// Boot ns.
        ts_ns: u64,
        /// Totals.
        totals: BTreeMap<(ProcKey, u32), SysTotals>,
    },
    /// Result of a follow/unfollow request.
    FollowResult(Result<String, String>),
}

/// Requests the core thread sends to the poller.
#[derive(Debug, Clone, Copy)]
pub enum PollerCmd {
    /// Follow the tree of this process.
    Follow(ProcKey),
    /// Back to system-wide.
    Unfollow,
}

/// Load-time options.
#[derive(Debug, Clone, Copy)]
pub struct LoadOpts {
    /// Ring buffer size override (tests).
    pub ringbuf_bytes: Option<u32>,
    /// Count syscalls.
    pub syscalls: bool,
    /// Budget events/s per tgid (0 = off).
    pub budget_rate: u32,
    /// Budget burst.
    pub budget_burst: u32,
}

/// The loaded and attached BPF object.
pub struct Collector<'obj> {
    skel: skel::SysscopeSkel<'obj>,
    cfg: abi::Cfg,
}

/// Sum of the per-CPU `drops` counters for one reason index.
fn read_drop(map: &dyn MapCore, reason: u32) -> Result<u64> {
    let per_cpu = map
        .lookup_percpu(&reason.to_le_bytes(), MapFlags::ANY)
        .context("reading drops map")?
        .unwrap_or_default();
    let mut total = 0u64;
    for v in per_cpu {
        let mut a = [0u8; 8];
        if let Some(s) = v.get(..8) {
            a.copy_from_slice(s);
        }
        total = total.saturating_add(u64::from_le_bytes(a));
    }
    Ok(total)
}

fn u64_at(v: &[u8], off: usize) -> u64 {
    v.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

impl<'obj> Collector<'obj> {
    /// Opens, loads and attaches; the daemon's own tgid is ignored.
    pub fn load(
        storage: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        o: LoadOpts,
    ) -> Result<Collector<'obj>> {
        let builder = skel::SysscopeSkelBuilder::default();
        let mut open = builder.open(storage).context("opening BPF object")?;
        if let Some(bytes) = o.ringbuf_bytes {
            open.maps
                .events
                .set_max_entries(bytes)
                .context("setting ring buffer size")?;
        }
        let mut skel = open.load().context("loading BPF programs")?;
        let me = std::process::id();
        skel.maps
            .ignored_tgid
            .update(&me.to_le_bytes(), &1u32.to_le_bytes(), MapFlags::ANY)
            .context("adding the daemon to ignored_tgid")?;
        let cfg = abi::Cfg {
            mode: abi::MODE_SYSTEM,
            budget_rate: o.budget_rate,
            budget_burst: o.budget_burst,
            flags: if o.syscalls {
                abi::CFG_SYSCALLS_COUNT
            } else {
                0
            },
        };
        skel.maps
            .cfg
            .update(&0u32.to_le_bytes(), &cfg.to_bytes(), MapFlags::ANY)
            .context("writing cfg")?;
        skel.attach().context("attaching BPF programs")?;
        Ok(Collector { skel, cfg })
    }

    /// The loaded skeleton.
    pub fn skel(&self) -> &skel::SysscopeSkel<'obj> {
        &self.skel
    }

    /// Follows the tree of `root`; returns how many processes were added.
    /// On failure tracing goes back to system-wide (never a silent filter).
    pub fn follow(&mut self, root: ProcKey) -> Result<usize> {
        match crate::follow::start(&self.skel, root, self.cfg) {
            Ok(n) => {
                self.cfg.mode = abi::MODE_FOLLOW;
                Ok(n)
            }
            Err(e) => {
                self.unfollow()?;
                Err(e)
            }
        }
    }

    /// Back to system-wide tracing; clears the followed set.
    pub fn unfollow(&mut self) -> Result<()> {
        self.cfg.mode = abi::MODE_SYSTEM;
        self.skel
            .maps
            .cfg
            .update(&0u32.to_le_bytes(), &self.cfg.to_bytes(), MapFlags::ANY)
            .context("writing cfg")?;
        crate::follow::clear(&self.skel);
        Ok(())
    }

    /// Cumulative kernel loss counters.
    pub fn loss(&self) -> Result<Loss> {
        Ok(Loss {
            ringbuf: read_drop(&self.skel.maps.drops, abi::DROP_RINGBUF)?,
            budget: read_drop(&self.skel.maps.drops, abi::DROP_BUDGET)?,
            scratch: read_drop(&self.skel.maps.drops, abi::DROP_SCRATCH)?,
            decode: 0,
            since_ts_ns: 0,
        })
    }

    /// (process, budget dropped, ring-buffer dropped), cumulative.
    pub fn budget(&self) -> Vec<(ProcKey, u64, u64)> {
        let mut out = Vec::new();
        for k in self.skel.maps.budget.keys() {
            let Some(tgid) = k
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
            else {
                continue;
            };
            let key = ProcKey {
                tgid,
                start_ticks: convert::start_ticks(u64_at(&k, 8)),
            };
            if let Ok(Some(v)) = self.skel.maps.budget.lookup(&k, MapFlags::ANY) {
                out.push((key, u64_at(&v, 16), u64_at(&v, 24)));
            }
        }
        out
    }
}

/// The poller loop (T1): ring buffer, commands, 1 Hz counters, until `stop`.
pub fn run_poller(
    col: &mut Collector<'_>,
    tx: &Sender<PollerMsg>,
    cmds: &Receiver<PollerCmd>,
    stop: &AtomicBool,
) -> Result<()> {
    // The mount table is shared with the ring-buffer callback and reloaded
    // every 10 s so mounts made after startup get the right prefix.
    let mounts = std::rc::Rc::new(std::cell::RefCell::new(Mounts::load()));
    let mounts_cb = std::rc::Rc::clone(&mounts);
    let next_id = Cell::new(1u64);
    let decode_errors = std::rc::Rc::new(Cell::new(0u64));
    let decode_errors_cb = std::rc::Rc::clone(&decode_errors);
    let mut rb = RingBufferBuilder::new();
    let tx_rb = tx.clone();
    rb.add(&col.skel.maps.events, move |data: &[u8]| {
        match abi::decode(data) {
            Ok(raw) => {
                let ev = convert::to_event(next_id.get(), &raw, &mounts_cb.borrow());
                next_id.set(next_id.get() + 1);
                // Blocks when the core is behind: the kernel then counts drops.
                if tx_rb.send(PollerMsg::Event(ev)).is_err() {
                    return -1; // core gone: stop polling
                }
            }
            Err(_) => decode_errors_cb.set(decode_errors_cb.get() + 1),
        }
        0
    })
    .context("adding ring buffer")?;
    let rb = rb.build().context("building ring buffer")?;
    let mut last_budget: BTreeMap<ProcKey, u64> = BTreeMap::new();
    let mut next_tick = Instant::now();
    let mut tick_count = 0u64;
    while !stop.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_millis(100)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => {}
            // A signal that asks us to stop can interrupt the poll: not an error.
            Err(_) if stop.load(Ordering::Relaxed) => break,
            Err(e) => return Err(e).context("polling ring buffer"),
        }
        while let Ok(cmd) = cmds.try_recv() {
            let res = match cmd {
                PollerCmd::Follow(root) => col
                    .follow(root)
                    .map(|n| format!("following pid {} ({n} processes)", root.tgid))
                    .map_err(|e| format!("{e:#}")),
                PollerCmd::Unfollow => col
                    .unfollow()
                    .map(|()| "following stopped".to_string())
                    .map_err(|e| format!("{e:#}")),
            };
            let _ = tx.send(PollerMsg::FollowResult(res));
        }
        if Instant::now() >= next_tick {
            next_tick += Duration::from_secs(1);
            let ts_ns = crate::sampler::boot_ns();
            if tick_count.is_multiple_of(10) {
                *mounts.borrow_mut() = Mounts::load();
            }
            tick_count += 1;
            let mut loss = col.loss()?;
            loss.decode = decode_errors.get();
            let _ = tx.send(PollerMsg::Loss(loss));
            let mut per_proc = Vec::new();
            let mut seen = BTreeMap::new();
            for (key, b, r) in col.budget() {
                let total = b.saturating_add(r);
                let prev = last_budget.get(&key).copied().unwrap_or(0);
                // An LRU-evicted and re-created entry restarts from zero.
                let delta = if total >= prev { total - prev } else { total };
                if delta > 0 {
                    per_proc.push((key, delta));
                }
                seen.insert(key, total);
            }
            last_budget = seen; // forget entries the kernel no longer has
            if !per_proc.is_empty() {
                let _ = tx.send(PollerMsg::Drops { ts_ns, per_proc });
            }
            if let Ok(totals) = crate::syscalls::read_all(&col.skel) {
                let _ = tx.send(PollerMsg::Sys { ts_ns, totals });
            }
        }
    }
    let _ = rb.consume();
    Ok(())
}
