//! Loads the BPF object, attaches the programs and reads the ring buffer.
//!
//! In WP04 the collector only supports dump mode: every record is decoded
//! (`abi::decode`), converted to a protocol event and printed as one JSON
//! line. The daemon's own tgid is put into `ignored_tgid` so it never traces
//! itself. On exit the kernel drop counters are printed to stderr, so the
//! loss identity (emitted = received + dropped) can be checked (I3).

use crate::abi::{self, skel};
use crate::convert;
use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use std::cell::{Cell, RefCell};
use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Default per-tgid event budget (events per second) and burst (plan 4.3).
pub const BUDGET_RATE: u32 = 2000;
/// Default per-tgid burst.
pub const BUDGET_BURST: u32 = 4000;

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

/// Runs dump mode until `stop` is set.
pub fn dump(ringbuf_bytes: Option<u32>, stop: &AtomicBool) -> Result<()> {
    let builder = skel::SysscopeSkelBuilder::default();
    let mut storage = MaybeUninit::uninit();
    let mut open = builder.open(&mut storage).context("opening BPF object")?;
    if let Some(bytes) = ringbuf_bytes {
        open.maps
            .events
            .set_max_entries(bytes)
            .context("setting ring buffer size")?;
    }
    let mut loaded = open.load().context("loading BPF programs")?;

    let me = std::process::id();
    loaded
        .maps
        .ignored_tgid
        .update(&me.to_le_bytes(), &1u32.to_le_bytes(), MapFlags::ANY)
        .context("adding the daemon to ignored_tgid")?;
    let cfg = abi::Cfg {
        mode: 0,
        budget_rate: BUDGET_RATE,
        budget_burst: BUDGET_BURST,
        flags: 0,
    };
    loaded
        .maps
        .cfg
        .update(&0u32.to_le_bytes(), &cfg.to_bytes(), MapFlags::ANY)
        .context("writing cfg")?;
    loaded.attach().context("attaching BPF programs")?;

    // SYSSCOPE_DEBUG_RAW=1 prints every decoded kernel record to stderr.
    let debug_raw = std::env::var_os("SYSSCOPE_DEBUG_RAW").is_some();
    let next_id = Cell::new(1u64);
    let decode_errors = Cell::new(0u64);
    let out = RefCell::new(std::io::BufWriter::new(std::io::stdout().lock()));
    let mut rb = RingBufferBuilder::new();
    rb.add(&loaded.maps.events, |data: &[u8]| {
        match abi::decode(data) {
            Ok(raw) => {
                if debug_raw {
                    eprintln!("raw: {raw:?}");
                }
                let ev = convert::to_event(next_id.get(), &raw);
                next_id.set(next_id.get() + 1);
                if let Ok(line) = serde_json::to_string(&ev) {
                    let _ = writeln!(out.borrow_mut(), "{line}");
                }
            }
            Err(_) => decode_errors.set(decode_errors.get() + 1),
        }
        0
    })
    .context("adding ring buffer")?;
    let rb = rb.build().context("building ring buffer")?;

    eprintln!("sysscoped: tracing (dump mode); Ctrl-C to stop");
    while !stop.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_millis(100)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("polling ring buffer"),
        }
        let _ = out.borrow_mut().flush();
    }
    let _ = rb.consume();
    let _ = out.borrow_mut().flush();
    let ringbuf = read_drop(&loaded.maps.drops, abi::DROP_RINGBUF)?;
    let budget = read_drop(&loaded.maps.drops, abi::DROP_BUDGET)?;
    let scratch = read_drop(&loaded.maps.drops, abi::DROP_SCRATCH)?;
    eprintln!(
        "sysscoped: received={} decode_errors={} dropped ringbuf={ringbuf} budget={budget} scratch={scratch}",
        next_id.get() - 1,
        decode_errors.get()
    );
    Ok(())
}
