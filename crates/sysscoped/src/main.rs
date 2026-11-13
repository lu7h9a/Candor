//! `sysscoped`: the root daemon.
//!
//! It loads the eBPF programs, samples /proc, owns all state, runs the
//! detection rules and serves clients over a Unix socket. It is the only
//! SysScope process that runs as root (invariant I1). The only `unsafe`
//! code in the whole project lives in `abi.rs` (invariant I14).
//!
//! At this stage (WP04) it supports `--dev --dump`: load the lifecycle
//! programs and print every decoded event as one JSON line on stdout.
#![deny(unsafe_code)]

mod abi;
mod collector;
mod convert;
mod startup;

use anyhow::{Context, Result, bail};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Command-line options.
struct Opts {
    dev: bool,
    dump: bool,
    ringbuf_bytes: Option<u32>,
}

fn parse_args() -> Result<Opts> {
    let mut opts = Opts {
        dev: false,
        dump: false,
        ringbuf_bytes: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dev" => opts.dev = true,
            "--dump" => opts.dump = true,
            "--ringbuf-bytes" => {
                let v = args.next().context("--ringbuf-bytes needs a value")?;
                opts.ringbuf_bytes = Some(v.parse().context("--ringbuf-bytes must be a number")?);
            }
            "--version" => {
                println!("sysscoped {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => bail!("unknown argument {other:?}"),
        }
    }
    Ok(opts)
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("sysscoped: {e:#}");
            std::process::exit(2);
        }
    };
    if let Err(e) = startup::check() {
        eprintln!("sysscoped: {e}");
        std::process::exit(e.exit_code());
    }
    if let Err(e) = run(&opts) {
        eprintln!("sysscoped: {e:#}");
        std::process::exit(1);
    }
}

fn run(opts: &Opts) -> Result<()> {
    if !opts.dump {
        bail!("only --dump mode exists so far (use: sysscoped --dev --dump)");
    }
    let _ = opts.dev;
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    collector::dump(opts.ringbuf_bytes, &stop)?;
    let _ = stop.load(Ordering::Relaxed);
    Ok(())
}
