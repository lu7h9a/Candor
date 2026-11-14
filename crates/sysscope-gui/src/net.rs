//! Where the GUI's data comes from: a live daemon or a recording.
//!
//! A reader thread connects to the daemon's socket, says Hello, subscribes
//! and forwards every message to the UI through a bounded channel; if the
//! daemon is down it reports why and retries with a growing delay (0.5 s up
//! to 5 s). Requests from the UI (Detail, Follow) go the other way through a
//! second channel. A replay source reads `*.frames.jsonl` (daemon messages,
//! one per line) instead, at the recorded pace or a fixed interval.

use crate::model::{ConnState, Incoming};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use sysscope_proto::{
    ClientKind, ClientMsg, DaemonMsg, EventSub, EventSubMode, MAX_CLIENT_FRAME, MAX_DAEMON_FRAME,
    PROTO_VERSION, decode_daemon, encode, read_frame, write_frame,
};

/// Messages waiting for the UI before the reader thread blocks (bounded:
/// 32 frames of at most 16 MiB each).
pub const UI_QUEUE: usize = 32;

/// Handles of a running source.
pub struct Source {
    /// Messages for the model.
    pub rx: Receiver<Incoming>,
    /// Requests for the daemon (ignored by replay).
    pub tx: Sender<ClientMsg>,
    /// Set to the egui context once the window exists; the reader thread
    /// then asks for a repaint whenever it delivers something, so the UI
    /// redraws on data instead of polling (WP21 CPU budget).
    pub waker: Waker,
}

/// Shared slot for the egui context used to wake the UI.
pub type Waker = std::sync::Arc<std::sync::Mutex<Option<egui::Context>>>;

fn wake(w: &Waker) {
    if let Ok(g) = w.lock()
        && let Some(ctx) = g.as_ref()
    {
        ctx.request_repaint();
    }
}

/// Sends to the UI and wakes it; false if the UI is gone.
fn deliver(out: &Sender<Incoming>, w: &Waker, inc: Incoming) -> bool {
    let ok = out.send(inc).is_ok();
    wake(w);
    ok
}

fn send_msg(stream: &mut UnixStream, m: &ClientMsg) -> bool {
    match encode(m) {
        Ok(body) => write_frame(stream, &body, MAX_CLIENT_FRAME).is_ok(),
        Err(_) => false,
    }
}

/// Connects to the first socket that answers; Err gives the UI state to show.
fn connect(sockets: &[PathBuf]) -> Result<UnixStream, ConnState> {
    let mut state = ConnState::DaemonDown("no socket found".into());
    for p in sockets {
        match UnixStream::connect(p) {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                state = ConnState::PermissionDenied(p.display().to_string());
            }
            Err(e) => {
                if !matches!(state, ConnState::PermissionDenied(_)) {
                    state = ConnState::DaemonDown(format!("{}: {e}", p.display()));
                }
            }
        }
    }
    Err(state)
}

/// One connected session: Hello, Subscribe, then forward until EOF/error.
fn session(
    mut stream: UnixStream,
    out: &Sender<Incoming>,
    req: &Receiver<ClientMsg>,
    w: &Waker,
) -> bool {
    let hello = ClientMsg::Hello {
        proto: PROTO_VERSION,
        client: ClientKind::Gui,
        version: env!("CARGO_PKG_VERSION").into(),
    };
    let sub = ClientMsg::Subscribe {
        snapshots: true,
        alerts: true,
        events: EventSub::Simple(EventSubMode::None),
    };
    if !send_msg(&mut stream, &hello) || !send_msg(&mut stream, &sub) {
        return true;
    }
    let Ok(mut writer) = stream.try_clone() else {
        return true;
    };
    let req = req.clone();
    let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let writer_alive = std::sync::Arc::clone(&alive);
    // Requests go out on their own thread so reading never waits on them.
    // It stops (and is joined) when this session ends, so reconnects never
    // leave old writers behind that could take a new session's requests.
    let writer_thread = std::thread::spawn(move || {
        while writer_alive.load(std::sync::atomic::Ordering::SeqCst) {
            match req.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(m) => {
                    if !send_msg(&mut writer, &m) {
                        break;
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
    });
    let mut ui_alive = true;
    while let Ok(Some(body)) = read_frame(&mut stream, MAX_DAEMON_FRAME) {
        let Ok(m) = decode_daemon(&body) else { break };
        if !deliver(out, w, Incoming::Msg(Box::new(m))) {
            ui_alive = false; // UI gone
            break;
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
    alive.store(false, std::sync::atomic::Ordering::SeqCst);
    let _ = writer_thread.join();
    ui_alive
}

/// Starts the live reader thread with reconnect and backoff.
pub fn live(sockets: Vec<PathBuf>) -> Source {
    let (out_tx, out_rx) = bounded(UI_QUEUE);
    let (req_tx, req_rx) = bounded::<ClientMsg>(64);
    let waker: Waker = Default::default();
    let w = std::sync::Arc::clone(&waker);
    std::thread::spawn(move || {
        let mut delay = Duration::from_millis(500);
        loop {
            match connect(&sockets) {
                Ok(stream) => {
                    delay = Duration::from_millis(500);
                    if !session(stream, &out_tx, &req_rx, &w) {
                        return;
                    }
                    let lost = Incoming::Conn(ConnState::DaemonDown("connection lost".into()));
                    if !deliver(&out_tx, &w, lost) {
                        return;
                    }
                }
                Err(state) => {
                    if !deliver(&out_tx, &w, Incoming::Conn(state)) {
                        return;
                    }
                }
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    });
    Source {
        rx: out_rx,
        tx: req_tx,
        waker,
    }
}

/// Pace of a replay.
#[derive(Clone, Copy, Debug)]
pub enum Pace {
    /// As recorded (snapshot timestamps).
    Recorded,
    /// One snapshot per interval.
    Fixed(Duration),
    /// As fast as the UI takes them.
    Max,
}

/// Starts a replay of a `*.frames.jsonl` file. Lines that do not parse are
/// skipped (the file may come from someone else; it is never trusted).
pub fn replay(path: PathBuf, pace: Pace) -> Source {
    let (out_tx, out_rx) = bounded(UI_QUEUE);
    let (req_tx, _req_rx) = bounded::<ClientMsg>(64);
    let waker: Waker = Default::default();
    let w = std::sync::Arc::clone(&waker);
    std::thread::spawn(move || {
        let _ = out_tx.send(Incoming::Conn(ConnState::Replay(
            path.display().to_string(),
        )));
        let Ok(file) = std::fs::File::open(&path) else {
            let _ = out_tx.send(Incoming::Conn(ConnState::DaemonDown(format!(
                "cannot open {}",
                path.display()
            ))));
            return;
        };
        let mut last_ts: Option<u64> = None;
        let mut reader = std::io::BufReader::new(file);
        // Lines are capped at the daemon frame limit and read without ever
        // holding a longer line; bad lines (too long, not UTF-8, not a
        // message) are skipped, never the rest of the file.
        while let Ok(Some(line)) =
            sysscope_proto::read_line_bounded(&mut reader, MAX_DAEMON_FRAME as usize)
        {
            let sysscope_proto::Line::Text(line) = line else {
                continue;
            };
            let Ok(m) = decode_daemon(&line) else {
                continue;
            };
            if let DaemonMsg::Snapshot { ts_ns, .. } = &m {
                let wait = match pace {
                    Pace::Recorded => last_ts
                        .map(|t| Duration::from_nanos(ts_ns.saturating_sub(t).min(5_000_000_000))),
                    Pace::Fixed(d) => last_ts.map(|_| d),
                    Pace::Max => None,
                };
                if let Some(w) = wait {
                    std::thread::sleep(w);
                }
                last_ts = Some(*ts_ns);
            }
            if !deliver(&out_tx, &w, Incoming::Msg(Box::new(m))) {
                return;
            }
        }
    });
    Source {
        rx: out_rx,
        tx: req_tx,
        waker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn live_reports_down_then_connects_and_reconnects() {
        let dir = std::env::temp_dir().join(format!("sysscope-gui-net-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s.sock");
        let src = live(vec![sock.clone()]);
        match src.rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Incoming::Conn(ConnState::DaemonDown(_)) => {}
            other => panic!("{other:?}"),
        }
        // A fake daemon: read Hello + Subscribe, send Welcome, close.
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let hello = read_frame(&mut s, MAX_CLIENT_FRAME).unwrap().unwrap();
            assert!(String::from_utf8_lossy(&hello).contains("\"gui\""));
            let _ = read_frame(&mut s, MAX_CLIENT_FRAME).unwrap().unwrap();
            let w = DaemonMsg::Welcome {
                proto: 1,
                daemon_version: "t".into(),
                kernel: "k".into(),
                boot_to_wall_ns: 0,
                features: vec![],
                unavailable: Vec::new(),
                act_enabled: false,
            };
            write_frame(&mut s, &encode(&w).unwrap(), MAX_DAEMON_FRAME).unwrap();
        });
        let mut got_welcome = false;
        let mut got_lost = false;
        for _ in 0..20 {
            match src.rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                Incoming::Msg(m) if matches!(*m, DaemonMsg::Welcome { .. }) => got_welcome = true,
                Incoming::Conn(ConnState::DaemonDown(m)) if got_welcome => {
                    got_lost = m.contains("lost");
                    break;
                }
                _ => {}
            }
        }
        server.join().unwrap();
        assert!(got_welcome && got_lost);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_skips_garbage_and_delivers_messages() {
        let path = std::env::temp_dir().join(format!(
            "sysscope-gui-replay-{}.frames.jsonl",
            std::process::id()
        ));
        let pong = serde_json::to_string(&DaemonMsg::Pong { n: 7 }).unwrap();
        std::fs::write(
            &path,
            format!("not json\n{pong}\n{{\"t\":\"Nope\"}}\n{pong}\n"),
        )
        .unwrap();
        let src = replay(path.clone(), Pace::Max);
        let mut pongs = 0;
        while let Ok(m) = src.rx.recv_timeout(Duration::from_secs(2)) {
            if let Incoming::Msg(m) = m
                && matches!(*m, DaemonMsg::Pong { n: 7 })
            {
                pongs += 1;
            }
        }
        assert_eq!(pongs, 2);
        let _ = std::fs::remove_file(&path);
    }
}
