//! `sysscoped`: the root daemon.
//!
//! It loads the eBPF programs, samples /proc, owns all state, runs the
//! detection rules and serves clients over a Unix socket. It is the only
//! SysScope process that runs as root (invariant I1). The only `unsafe`
//! code in the whole project lives in `abi.rs` (invariant I14).
//!
//! Usage: `sysscoped [--dev] [--record FILE]` serves clients on the Unix
//! socket; `sysscoped --dev --dump` prints events as JSON lines instead
//! (used by the integration tests).
#![deny(unsafe_code)]

mod abi;
mod collector;
mod convert;
mod daemon;
mod dump;
mod follow;
mod glasshouse;
mod hostinfo;
mod mounts;
mod sampler;
mod server;
mod sockaddr;
mod startup;
mod syscalls;

use anyhow::{Context, Result, bail};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Command-line options.
struct Opts {
    dev: bool,
    dump: bool,
    ringbuf_bytes: Option<u32>,
    syscalls: bool,
    follow: Option<u32>,
    budget_rate: u32,
    budget_burst: u32,
    record: Option<std::path::PathBuf>,
}

fn parse_args() -> Result<Opts> {
    let mut opts = Opts {
        dev: false,
        dump: false,
        ringbuf_bytes: None,
        syscalls: true,
        follow: None,
        budget_rate: collector::BUDGET_RATE,
        budget_burst: collector::BUDGET_BURST,
        record: None,
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
            "--syscalls" => match args.next().as_deref() {
                Some("count") => opts.syscalls = true,
                Some("off") => opts.syscalls = false,
                _ => bail!("--syscalls must be \"count\" or \"off\""),
            },
            "--follow" => {
                let v = args.next().context("--follow needs a pid")?;
                opts.follow = Some(v.parse().context("--follow must be a pid")?);
            }
            "--budget" => {
                let v = args.next().context("--budget needs RATE/BURST")?;
                let (r, b) = v.split_once('/').context("--budget must be RATE/BURST")?;
                opts.budget_rate = r.parse().context("budget rate")?;
                opts.budget_burst = b.parse().context("budget burst")?;
            }
            "--record" => {
                opts.record = Some(args.next().context("--record needs a file")?.into());
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
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    let load = collector::LoadOpts {
        ringbuf_bytes: opts.ringbuf_bytes,
        syscalls: opts.syscalls,
        budget_rate: opts.budget_rate,
        budget_burst: opts.budget_burst,
    };
    if opts.dump {
        return dump::run(load, opts.follow, &stop);
    }
    if opts.follow.is_some() {
        bail!("--follow is only for --dump; clients request follow mode over the socket");
    }
    daemon::run(
        daemon::RunOpts {
            load,
            dev: opts.dev,
            record: opts.record.clone(),
        },
        stop,
    )
}
