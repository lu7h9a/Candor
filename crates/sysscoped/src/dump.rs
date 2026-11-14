//! `sysscoped --dev --dump`: trace and print, without the socket server.
//!
//! Every event is printed as one JSON line; about once a second a full
//! /proc scan is printed as a core `Samples` input; at exit one `sysstat`
//! line per (tgid, syscall) and one `budget` line per tgid. The integration
//! tests read this output. Loss counters go to stderr.

use crate::collector::{self, Collector, LoadOpts, PollerMsg};
use anyhow::Result;
use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

/// Runs dump mode until `stop` is set.
pub fn run(o: LoadOpts, follow: Option<u32>, stop: &AtomicBool) -> Result<()> {
    let follow = follow.map(|pid| sysscope_proto::ProcKey {
        tgid: pid,
        start_ticks: crate::follow::start_of(pid).unwrap_or(0),
    });
    let mut storage = MaybeUninit::uninit();
    let mut col = Collector::load(&mut storage, o)?;
    // Dump mode has no viewers and always counts syscalls.
    col.want_sys = true;
    if let Some(root) = follow {
        let n = col.follow(root)?;
        eprintln!("sysscoped: following pid {} ({n} processes)", root.tgid);
    }
    let (tx, rx) = crossbeam_channel::bounded::<PollerMsg>(65536);
    let (_cmd_tx, cmd_rx) = crossbeam_channel::bounded(1);
    let printer = std::thread::spawn(move || {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        let mut received = 0u64;
        let mut next_sample = Instant::now();
        loop {
            if Instant::now() >= next_sample {
                next_sample += Duration::from_secs(1);
                let input = sysscope_core::Input::Samples {
                    ts_ns: crate::sampler::boot_ns(),
                    samples: crate::sampler::sample_all(),
                };
                if let Ok(line) = serde_json::to_string(&input) {
                    let _ = writeln!(out, "{line}");
                }
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(PollerMsg::Event(ev)) => {
                    received += 1;
                    if let Ok(line) = serde_json::to_string(&ev) {
                        let _ = writeln!(out, "{line}");
                    }
                }
                Ok(_) => {}
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    let _ = out.flush();
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = out.flush();
        received
    });
    eprintln!("sysscoped: tracing (dump mode); Ctrl-C to stop");
    collector::run_poller(&mut col, &tx, &cmd_rx, stop)?;
    drop(tx);
    let received = printer.join().unwrap_or(0);

    let mut out = std::io::stdout().lock();
    for ((key, nr), t) in crate::syscalls::read_all(col.skel())? {
        let line = serde_json::json!({"sysstat": {
            "tgid": key.tgid, "start": key.start_ticks, "nr": nr, "name": crate::syscalls::name(nr), "count": t.count,
            "lat_count": t.lat_count, "lat_total_ns": t.lat_total_ns, "lat_max_ns": t.lat_max_ns,
        }});
        let _ = writeln!(out, "{line}");
    }
    for (key, dropped, rb_dropped) in col.budget() {
        let line = serde_json::json!({"budget": {
            "tgid": key.tgid, "start": key.start_ticks, "dropped": dropped, "rb_dropped": rb_dropped,
        }});
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();
    let loss = col.loss()?;
    eprintln!(
        "sysscoped: received={received} dropped ringbuf={} budget={} scratch={} missed={}",
        loss.ringbuf, loss.budget, loss.scratch, loss.missed
    );
    // Global loss counters as a line too, for tests (I3 identity).
    let line = serde_json::json!({"loss": {
        "ringbuf": loss.ringbuf, "budget": loss.budget, "scratch": loss.scratch, "missed": loss.missed,
    }});
    let _ = writeln!(std::io::stdout().lock(), "{line}");
    Ok(())
}
