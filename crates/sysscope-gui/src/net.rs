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
use std::io::BufRead;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use sysscope_proto::{
    ClientKind, ClientMsg, DaemonMsg, EventSub, EventSubMode, MAX_CLIENT_FRAME, MAX_DAEMON_FRAME,
    PROTO_VERSION, decode_daemon, encode, read_frame, write_frame,
};

/// Messages waiting for the UI before the reader thread blocks.
pub const UI_QUEUE: usize = 256;

/// Handles of a running source.
pub struct Source {
    /// Messages for the model.
    pub rx: Receiver<Incoming>,
    /// Requests for the daemon (ignored by replay).
    pub tx: Sender<ClientMsg>,
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
fn session(mut stream: UnixStream, out: &Sender<Incoming>, req: &Receiver<ClientMsg>) -> bool {
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
    // Requests go out on their own thread so reading never waits on them.
    let writer_thread = std::thread::spawn(move || {
        while let Ok(m) = req.recv() {
            if !send_msg(&mut writer, &m) {
                break;
            }
        }
    });
    loop {
        match read_frame(&mut stream, MAX_DAEMON_FRAME) {
            Ok(Some(body)) => match decode_daemon(&body) {
                Ok(m) => {
                    if out.send(Incoming::Msg(m)).is_err() {
                        return false; // UI gone
                    }
                }
                Err(_) => break,
            },
            _ => break,
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
    drop(writer_thread);
    true
}

/// Starts the live reader thread with reconnect and backoff.
pub fn live(sockets: Vec<PathBuf>) -> Source {
    let (out_tx, out_rx) = bounded(UI_QUEUE);
    let (req_tx, req_rx) = bounded::<ClientMsg>(64);
    std::thread::spawn(move || {
        let mut delay = Duration::from_millis(500);
        loop {
            match connect(&sockets) {
                Ok(stream) => {
                    delay = Duration::from_millis(500);
                    if !session(stream, &out_tx, &req_rx) {
                        return;
                    }
                    if out_tx
                        .send(Incoming::Conn(ConnState::DaemonDown(
                            "connection lost".into(),
                        )))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(state) => {
                    if out_tx.send(Incoming::Conn(state)).is_err() {
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
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            // Each line is at most what a daemon frame may be.
            if line.len() > MAX_DAEMON_FRAME as usize {
                continue;
            }
            let Ok(m) = decode_daemon(line.as_bytes()) else {
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
            if out_tx.send(Incoming::Msg(m)).is_err() {
                return;
            }
        }
    });
    Source {
        rx: out_rx,
        tx: req_tx,
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
                act_enabled: false,
            };
            write_frame(&mut s, &encode(&w).unwrap(), MAX_DAEMON_FRAME).unwrap();
        });
        let mut got_welcome = false;
        let mut got_lost = false;
        for _ in 0..20 {
            match src.rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                Incoming::Msg(DaemonMsg::Welcome { .. }) => got_welcome = true,
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
            if let Incoming::Msg(DaemonMsg::Pong { n: 7 }) = m {
                pongs += 1;
            }
        }
        assert_eq!(pongs, 2);
        let _ = std::fs::remove_file(&path);
    }
}
