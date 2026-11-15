//! Unix socket server (plan 4.2, 4.5, 4.7): acceptor, per-client reader and
//! writer threads, and the bounded per-client queues.
//!
//! The core thread never writes to a socket. It only puts messages into a
//! client's queue: one snapshot slot (latest wins), an event queue (4096,
//! oldest dropped first, counted) and an alert queue (256, same), plus a
//! small reply queue. A writer thread per client drains the queue; a write
//! that stalls for 5 s disconnects the client, so one slow client can never
//! slow the core or other clients. Client frames are untrusted: size-limited
//! and parsed into strict enums (they never become paths or commands, I12).

use anyhow::{Context, Result, bail};
use candor_proto::{
    ClientMsg, DaemonMsg, Event, Finding, FrameError, MAX_CLIENT_FRAME, MAX_DAEMON_FRAME,
    decode_client, encode, read_frame, write_frame,
};
use crossbeam_channel::Sender;
use std::collections::VecDeque;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Maximum simultaneous clients (plan 4.2).
pub const MAX_CLIENTS: usize = 8;
/// Connections one non-root uid may hold, so one member of the socket group
/// cannot take every slot (review 2 finding 7). Root is not limited.
pub const MAX_CLIENTS_PER_UID: usize = 4;
/// A connection must send Hello within this time; otherwise it would hold
/// one of the MAX_CLIENTS slots without ever being a client.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Events queued per client before the oldest are dropped.
pub const CLIENT_EVENTS: usize = 4096;
/// Alerts queued per client before the oldest are dropped.
pub const CLIENT_ALERTS: usize = 256;
/// Replies (Welcome, Detail, Pong, Error, ...) queued per client.
pub const CLIENT_REPLIES: usize = 64;
/// A socket write that takes longer than this disconnects the client.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Events sent per Events message.
const EVENTS_PER_FRAME: usize = 512;

/// What a client's queues hold.
#[derive(Default)]
struct Queues {
    snapshot: Option<Arc<Vec<u8>>>,
    events: VecDeque<Event>,
    events_dropped: u64,
    alerts: VecDeque<Finding>,
    alerts_dropped: u64,
    replies: VecDeque<DaemonMsg>,
    close_after_replies: bool,
    closed: bool,
}

/// One client's bounded outgoing queues, shared by the core and the writer.
pub struct ClientQueue {
    q: Mutex<Queues>,
    ready: Condvar,
}

impl ClientQueue {
    fn new() -> Arc<ClientQueue> {
        Arc::new(ClientQueue {
            q: Mutex::new(Queues::default()),
            ready: Condvar::new(),
        })
    }

    fn with<R>(&self, f: impl FnOnce(&mut Queues) -> R) -> Option<R> {
        let mut g = self.q.lock().ok()?;
        let r = f(&mut g);
        self.ready.notify_one();
        Some(r)
    }

    /// Replaces the pending snapshot (latest wins).
    pub fn put_snapshot(&self, frame: Arc<Vec<u8>>) {
        self.with(|q| q.snapshot = Some(frame));
    }

    /// Queues an event, dropping the oldest when full.
    pub fn put_event(&self, ev: &Event) {
        self.with(|q| {
            if q.events.len() >= CLIENT_EVENTS {
                q.events.pop_front();
                q.events_dropped += 1;
            }
            q.events.push_back(ev.clone());
        });
    }

    /// Queues an alert, dropping the oldest when full.
    pub fn put_alert(&self, f: &Finding) {
        self.with(|q| {
            if q.alerts.len() >= CLIENT_ALERTS {
                q.alerts.pop_front();
                q.alerts_dropped += 1;
                // Surface the loss (I3): one coalesced notice per backlog.
                if q.alerts_dropped == 1 || q.alerts_dropped.is_multiple_of(256) {
                    let n = q.alerts_dropped;
                    if q.replies.len() < CLIENT_REPLIES {
                        q.replies.push_back(DaemonMsg::Error {
                            code: "alerts_dropped".into(),
                            message: format!(
                                "{n} alerts were dropped because this client read too slowly"
                            ),
                        });
                    }
                }
            }
            q.alerts.push_back(f.clone());
        });
    }

    /// Queues a reply. A client that lets 64 replies pile up is closed.
    pub fn put_reply(&self, m: DaemonMsg) {
        self.with(|q| {
            if q.replies.len() >= CLIENT_REPLIES {
                q.closed = true;
            } else {
                q.replies.push_back(m);
            }
        });
    }

    /// Sends this reply, then closes the connection.
    pub fn reply_and_close(&self, m: DaemonMsg) {
        self.with(|q| {
            q.replies.push_back(m);
            q.close_after_replies = true;
        });
    }

    /// Closes the connection.
    pub fn close(&self) {
        self.with(|q| q.closed = true);
    }

    fn is_closed(&self) -> bool {
        self.q.lock().map(|q| q.closed).unwrap_or(true)
    }
}

/// Messages from the server threads to the core thread.
pub enum ClientCmd {
    /// A client connected.
    New {
        /// Connection id.
        id: u64,
        /// Its queues.
        queue: Arc<ClientQueue>,
        /// Peer uid from SO_PEERCRED.
        uid: u32,
        /// Peer pid from SO_PEERCRED.
        pid: u32,
    },
    /// A decoded message from a client.
    Msg {
        /// Connection id.
        id: u64,
        /// The message.
        msg: ClientMsg,
    },
    /// The client is gone.
    Gone {
        /// Connection id.
        id: u64,
    },
}

/// Where the socket lives and who may use it.
#[derive(Clone, Debug)]
pub struct SocketSpec {
    /// Socket path.
    pub path: PathBuf,
    /// Group that owns the socket (mode 0660).
    pub gid: u32,
}

impl SocketSpec {
    /// Dev mode: /run/candor-dev/candor.sock, group = SUDO_GID (or root).
    pub fn dev() -> SocketSpec {
        let gid = std::env::var("SUDO_GID")
            .ok()
            .and_then(|g| g.parse().ok())
            .unwrap_or(0);
        SocketSpec {
            path: PathBuf::from("/run/candor-dev/candor.sock"),
            gid,
        }
    }

    /// Installed: /run/candor/candor.sock, group `candor`.
    pub fn installed() -> Result<SocketSpec> {
        let gid = group_gid("candor")
            .context("group 'candor' not found (create it with systemd-sysusers or groupadd)")?;
        Ok(SocketSpec {
            path: PathBuf::from("/run/candor/candor.sock"),
            gid,
        })
    }
}

/// gid of a group from /etc/group.
pub fn group_gid(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then_some(())?;
        f.nth(1)?.parse().ok()
    })
}

/// Creates the socket: directory 0750 root:gid, socket 0660 root:gid, mode
/// set before listen(). A stale socket file is removed only if nothing answers.
pub fn bind(spec: &SocketSpec) -> Result<UnixListener> {
    use rustix::fs::{Gid, Mode, Uid, chmod, chown};
    let dir = spec.path.parent().context("socket path has no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    chown(dir, Some(Uid::ROOT), Some(Gid::from_raw(spec.gid))).with_context(|| {
        format!(
            "giving {} to group {} (needs CAP_CHOWN)",
            dir.display(),
            spec.gid
        )
    })?;
    chmod(dir, Mode::from_raw_mode(0o750))?;
    if spec.path.exists() {
        if UnixStream::connect(&spec.path).is_ok() {
            bail!("another candord is already serving {}", spec.path.display());
        }
        std::fs::remove_file(&spec.path).context("removing stale socket")?;
    }
    let fd: OwnedFd = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    let addr = rustix::net::SocketAddrUnix::new(&spec.path)?;
    rustix::net::bind(&fd, &addr).context("binding the socket")?;
    chown(&spec.path, Some(Uid::ROOT), Some(Gid::from_raw(spec.gid))).with_context(|| {
        format!(
            "giving {} to group {} (needs CAP_CHOWN)",
            spec.path.display(),
            spec.gid
        )
    })?;
    chmod(&spec.path, Mode::from_raw_mode(0o660))?;
    rustix::net::listen(&fd, 16).context("listen")?;
    Ok(UnixListener::from(fd))
}

fn write_msg(stream: &mut UnixStream, m: &DaemonMsg) -> Result<()> {
    let body = encode(m)?;
    write_frame(stream, &body, MAX_DAEMON_FRAME)?;
    Ok(())
}

/// Writer thread: drains one client's queues to its socket.
fn writer(mut stream: UnixStream, queue: Arc<ClientQueue>) {
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    loop {
        // Take everything that is ready, then write without holding the lock.
        let (snapshot, events, ev_dropped, alerts, replies, close_after, closed) = {
            let Ok(mut q) = queue.q.lock() else { return };
            while q.snapshot.is_none()
                && q.events.is_empty()
                && q.alerts.is_empty()
                && q.replies.is_empty()
                && !q.closed
            {
                let Ok((g, _)) = queue.ready.wait_timeout(q, Duration::from_millis(200)) else {
                    return;
                };
                q = g;
            }
            let n = q.events.len().min(EVENTS_PER_FRAME);
            let events: Vec<Event> = q.events.drain(..n).collect();
            let dropped = q.events_dropped;
            (
                q.snapshot.take(),
                events,
                dropped,
                std::mem::take(&mut q.alerts),
                std::mem::take(&mut q.replies),
                q.close_after_replies,
                q.closed,
            )
        };
        // Replies already queued (e.g. the Error explaining why we close)
        // are always written before closing.
        let mut ok = true;
        for r in &replies {
            ok &= write_msg(&mut stream, r).is_ok();
        }
        if closed || close_after {
            break;
        }
        if let Some(frame) = snapshot {
            ok &= stream.write_all(&frame).is_ok();
        }
        for f in alerts {
            ok &= write_msg(&mut stream, &DaemonMsg::Alert { finding: f }).is_ok();
        }
        if !events.is_empty() {
            let m = DaemonMsg::Events {
                events,
                client_dropped: ev_dropped,
            };
            ok &= write_msg(&mut stream, &m).is_ok();
        }
        if !ok {
            break; // write error or 5 s write timeout: disconnect
        }
    }
    queue.close();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Reader thread: decodes frames and forwards them to the core.
fn reader(mut stream: UnixStream, id: u64, queue: Arc<ClientQueue>, core: Sender<ClientCmd>) {
    let mut greeted = false;
    let _ = stream.set_read_timeout(Some(HELLO_TIMEOUT));
    loop {
        if queue.is_closed() {
            break;
        }
        match read_frame(&mut stream, MAX_CLIENT_FRAME) {
            Ok(Some(body)) => match decode_client(&body) {
                Ok(msg) => {
                    // After Hello a client may stay quiet for as long as it
                    // likes (a GUI that only watches).
                    if !greeted && matches!(msg, ClientMsg::Hello { .. }) {
                        greeted = true;
                        let _ = stream.set_read_timeout(None);
                    }
                    // A client that floods commands faster than the core can
                    // take them is disconnected rather than buffered.
                    if core.try_send(ClientCmd::Msg { id, msg }).is_err() {
                        queue.reply_and_close(DaemonMsg::Error {
                            code: "busy".into(),
                            message: "too many requests".into(),
                        });
                        break;
                    }
                }
                Err(e) => {
                    queue.reply_and_close(DaemonMsg::Error {
                        code: e.code().into(),
                        message: e.to_string(),
                    });
                    break;
                }
            },
            Ok(None) => break,
            Err(e) if !greeted && is_timeout(&e) => {
                queue.reply_and_close(DaemonMsg::Error {
                    code: "no_hello".into(),
                    message: format!("no Hello within {} s", HELLO_TIMEOUT.as_secs()),
                });
                break;
            }
            Err(e) => {
                queue.reply_and_close(DaemonMsg::Error {
                    code: "bad_frame".into(),
                    message: e.to_string(),
                });
                break;
            }
        }
    }
    let _ = core.send(ClientCmd::Gone { id });
}

/// True if a read failed because the read timeout expired.
fn is_timeout(e: &FrameError) -> bool {
    matches!(e, FrameError::Io(io) if matches!(io.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
}

/// Acceptor thread: accepts until `stop`, enforcing MAX_CLIENTS.
pub fn accept_loop(
    listener: UnixListener,
    core: Sender<ClientCmd>,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    let mut next_id = 1u64;
    let per_uid: Arc<Mutex<std::collections::HashMap<u32, usize>>> = Arc::default();
    while !stop.load(Ordering::Relaxed) {
        let mut stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(_) => continue,
        };
        let _ = stream.set_nonblocking(false);
        let cred = rustix::net::sockopt::socket_peercred(&stream).ok();
        let (uid, pid) = cred
            .map(|c| (c.uid.as_raw(), c.pid.as_raw_nonzero().get()))
            .unwrap_or((u32::MAX, 0));
        if count.load(Ordering::SeqCst) >= MAX_CLIENTS {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = write_msg(
                &mut stream,
                &DaemonMsg::Error {
                    code: "too_many_clients".into(),
                    message: format!("at most {MAX_CLIENTS} clients"),
                },
            );
            eprintln!("candord: refused client uid={uid} pid={pid}: {MAX_CLIENTS} connected");
            continue;
        }
        let held = per_uid
            .lock()
            .map(|m| m.get(&uid).copied().unwrap_or(0))
            .unwrap_or(0);
        if uid != 0 && held >= MAX_CLIENTS_PER_UID {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = write_msg(
                &mut stream,
                &DaemonMsg::Error {
                    code: "too_many_clients".into(),
                    message: format!("at most {MAX_CLIENTS_PER_UID} clients per user"),
                },
            );
            eprintln!(
                "candord: refused client uid={uid} pid={pid}: {MAX_CLIENTS_PER_UID} already connected for that user"
            );
            continue;
        }
        if let Ok(mut m) = per_uid.lock() {
            *m.entry(uid).or_insert(0) += 1;
        }
        count.fetch_add(1, Ordering::SeqCst);
        let id = next_id;
        next_id += 1;
        eprintln!("candord: client {id} connected uid={uid} pid={pid}");
        let queue = ClientQueue::new();
        let release = {
            let per_uid = Arc::clone(&per_uid);
            move || {
                if let Ok(mut m) = per_uid.lock()
                    && let Some(n) = m.get_mut(&uid)
                {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        m.remove(&uid);
                    }
                }
            }
        };
        let (Ok(r), w) = (stream.try_clone(), stream) else {
            count.fetch_sub(1, Ordering::SeqCst);
            release();
            continue;
        };
        let _ = core.send(ClientCmd::New {
            id,
            queue: Arc::clone(&queue),
            uid,
            pid: u32::try_from(pid).unwrap_or(0),
        });
        let q2 = Arc::clone(&queue);
        let core2 = core.clone();
        let count2 = Arc::clone(&count);
        std::thread::spawn(move || {
            reader(r, id, q2, core2);
            count2.fetch_sub(1, Ordering::SeqCst);
            release();
        });
        std::thread::spawn(move || writer(w, queue));
    }
}

/// Removes the socket file at shutdown.
pub fn remove_socket(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Encodes a snapshot once for all clients, as a ready-to-write frame.
pub fn snapshot_frame(m: &DaemonMsg) -> Option<Arc<Vec<u8>>> {
    let body = encode(m).ok()?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    write_frame(&mut frame, &body, MAX_DAEMON_FRAME).ok()?;
    Some(Arc::new(frame))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding 5: dropped alerts are reported to the client.
    #[test]
    fn dropped_alerts_are_reported() {
        let q = ClientQueue::new();
        let f = Finding {
            id: 1,
            rule: "R002".into(),
            title: "t".into(),
            subject: "s".into(),
            attack: None,
            proc: candor_proto::ProcKey::default(),
            exe: candor_proto::BStr::default(),
            ts_ns: 0,
            weight: 0.4,
            confidence: 1.0,
            summary: String::new(),
            why: vec![],
            benign: vec![],
            evidence: vec![1],
            evidence_events: vec![],
        };
        for _ in 0..(CLIENT_ALERTS + 1) {
            q.put_alert(&f);
        }
        let g = q.q.lock().unwrap();
        assert_eq!(g.alerts.len(), CLIENT_ALERTS);
        assert_eq!(g.alerts_dropped, 1);
        assert!(
            g.replies
                .iter()
                .any(|m| matches!(m, DaemonMsg::Error { code, .. } if code == "alerts_dropped"))
        );
    }
}
