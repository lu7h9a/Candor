//! Executable and script checks (stat, canonicalize) off the core thread.
//!
//! The paths come from traced processes, so a check can block for ever (a
//! FUSE or network mount that never answers). The core still waits for the
//! answer, because the allowlist needs it before the process's next event,
//! but only up to META_TIMEOUT. A check that takes longer counts as "not
//! trusted" (the conservative answer), its worker is written off and a new
//! one takes the next check. At most MAX_META_WORKERS threads exist; when
//! all of them are stuck, checks answer "not trusted" at once (bounded, I8).
//! Review finding: a hung stat on the core thread stalled all detection.

use candor_proto::{BStr, ProcKey};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Longest the core waits for one check.
pub const META_TIMEOUT: Duration = Duration::from_millis(50);
/// Most worker threads, stuck ones included.
pub const MAX_META_WORKERS: usize = 4;

/// One check to do.
#[derive(Clone, Debug)]
pub struct Job {
    id: u64,
    /// The process.
    pub key: ProcKey,
    /// Its executable path (display bytes from the kernel).
    pub exe: BStr,
    /// Its start time as /proc reports it now (pid reuse check).
    pub start: Option<u64>,
    /// The interpreter's script, if any.
    pub script: Option<BStr>,
}

/// Answer to a check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Executable root-owned and not writable by others, in such a directory.
    pub trusted: bool,
    /// Trusted and in a system directory.
    pub system_dir: bool,
    /// Its directory is world-writable.
    pub world_writable_dir: bool,
    /// The script passes the same check.
    pub script_trusted: bool,
    /// The exe path is the process's private view (hostinfo::private_view).
    pub private_view: bool,
}

/// What a worker runs for one job.
pub type CheckFn = fn(&Job) -> Facts;

/// The real check (hostinfo).
pub fn host_check(j: &Job) -> Facts {
    let (trusted, system_dir, world_writable_dir) =
        crate::hostinfo::exe_facts(j.key, &j.exe, j.start);
    let script_trusted = j
        .script
        .as_ref()
        .is_some_and(|s| crate::hostinfo::script_trusted(j.key.tgid, s));
    Facts {
        trusted,
        system_dir,
        world_writable_dir,
        script_trusted,
        private_view: crate::hostinfo::private_view(j.key, &j.exe, j.start),
    }
}

/// The worker pool, owned by the core thread.
pub struct MetaPool {
    check: CheckFn,
    jobs_tx: Sender<Job>,
    jobs_rx: Receiver<Job>,
    done_tx: Sender<(u64, Facts)>,
    done_rx: Receiver<(u64, Facts)>,
    busy: Arc<AtomicUsize>,
    workers: usize,
    next_id: u64,
    /// Checks answered "not trusted" because they took too long or every
    /// worker was stuck.
    pub timed_out: u64,
}

impl MetaPool {
    /// A pool with one worker.
    pub fn new(check: CheckFn) -> MetaPool {
        let (jobs_tx, jobs_rx) = bounded(MAX_META_WORKERS);
        let (done_tx, done_rx) = bounded(MAX_META_WORKERS * 2);
        let mut p = MetaPool {
            check,
            jobs_tx,
            jobs_rx,
            done_tx,
            done_rx,
            busy: Arc::new(AtomicUsize::new(0)),
            workers: 0,
            next_id: 1,
            timed_out: 0,
        };
        p.spawn();
        p
    }

    fn spawn(&mut self) {
        let (rx, tx, busy, check) = (
            self.jobs_rx.clone(),
            self.done_tx.clone(),
            Arc::clone(&self.busy),
            self.check,
        );
        let ok = std::thread::Builder::new()
            .name("candord-meta".into())
            .spawn(move || {
                for j in rx {
                    busy.fetch_add(1, Ordering::SeqCst);
                    let f = check(&j);
                    busy.fetch_sub(1, Ordering::SeqCst);
                    // The core may have given up on this id: try_send, and a
                    // full channel only means nobody waits for it.
                    let _ = tx.try_send((j.id, f));
                }
            })
            .is_ok();
        if ok {
            self.workers += 1;
        }
    }

    /// Number of worker threads (stuck ones included).
    #[cfg(test)]
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Checks one process; never blocks longer than META_TIMEOUT.
    pub fn check(
        &mut self,
        key: ProcKey,
        exe: BStr,
        start: Option<u64>,
        script: Option<BStr>,
    ) -> Facts {
        // Every worker busy for longer than a check should take: add one.
        if self.busy.load(Ordering::SeqCst) >= self.workers && self.workers < MAX_META_WORKERS {
            self.spawn();
        }
        if self.busy.load(Ordering::SeqCst) >= self.workers {
            self.timed_out += 1;
            return Facts::default();
        }
        // Answers to checks the core gave up on are dropped here.
        while self.done_rx.try_recv().is_ok() {}
        let id = self.next_id;
        self.next_id += 1;
        let job = Job {
            id,
            key,
            exe,
            start,
            script,
        };
        if self.jobs_tx.try_send(job).is_err() {
            self.timed_out += 1;
            return Facts::default();
        }
        let deadline = Instant::now() + META_TIMEOUT;
        loop {
            match self
                .done_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok((got, f)) if got == id => return f,
                Ok(_) => continue, // a late answer to an abandoned check
                Err(_) => {
                    self.timed_out += 1;
                    return Facts::default();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(t: u32) -> ProcKey {
        ProcKey {
            tgid: t,
            start_ticks: 1,
        }
    }

    /// "/hang/..." never answers (a FUSE mount that does not reply);
    /// anything else is trusted at once.
    fn fake(j: &Job) -> Facts {
        if j.exe.as_bytes().starts_with(b"/hang/") {
            loop {
                std::thread::park();
            }
        }
        Facts {
            trusted: true,
            system_dir: true,
            world_writable_dir: false,
            script_trusted: false,
            private_view: false,
        }
    }

    #[test]
    fn a_hung_check_costs_at_most_the_timeout_and_workers_are_capped() {
        let mut p = MetaPool::new(fake);
        assert!(
            p.check(key(1), BStr::from("/usr/bin/ls"), Some(1), None)
                .trusted
        );
        for i in 0..10u32 {
            let t0 = Instant::now();
            let f = p.check(key(100 + i), BStr::from("/hang/x"), Some(1), None);
            assert!(!f.trusted, "a hung check is not trusted");
            assert!(t0.elapsed() < META_TIMEOUT * 3, "{:?}", t0.elapsed());
            assert!(p.workers() <= MAX_META_WORKERS);
        }
        assert_eq!(p.workers(), MAX_META_WORKERS);
        assert_eq!(p.timed_out, 10);
        // Every worker is stuck now: the answer is immediate and untrusted.
        let t0 = Instant::now();
        assert!(
            !p.check(key(2), BStr::from("/usr/bin/ls"), Some(1), None)
                .trusted
        );
        assert!(t0.elapsed() < Duration::from_millis(5));
    }

    #[test]
    fn answers_match_their_own_check() {
        let mut p = MetaPool::new(fake);
        for i in 0..100u32 {
            let f = p.check(key(i), BStr::from("/usr/bin/ls"), Some(1), None);
            assert!(f.trusted && f.system_dir);
        }
        assert_eq!(p.timed_out, 0);
        assert_eq!(p.workers(), 1);
    }
}
