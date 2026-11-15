//! Talking to the daemon over its Unix socket.
//!
//! Finds the socket (dev path first, then the installed one, or --socket),
//! says Hello and maps every failure to an error with a clear message and a
//! distinct exit code, so scripts can tell "daemon not running" from
//! "permission denied" from "protocol mismatch".

use candor_proto::{
    ClientKind, ClientMsg, DaemonMsg, MAX_CLIENT_FRAME, MAX_DAEMON_FRAME, PROTO_VERSION,
    decode_daemon, encode, read_frame, write_frame,
};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Why a command failed; each kind has its own exit code.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Bad command line (exit 2).
    #[error("{0}")]
    Usage(String),
    /// Daemon not running (exit 3).
    #[error(
        "the Candor daemon is not running ({0}). Start it with: sudo systemctl start candord   (or for development: sudo ./target/debug/candord --dev)"
    )]
    NotRunning(String),
    /// No permission on the socket (exit 4).
    #[error(
        "permission denied on {0}. Join the group with: sudo usermod -aG candor $USER   then log out and back in"
    )]
    Permission(String),
    /// Daemon speaks another protocol or reported an error (exit 5).
    #[error("daemon error: {0}")]
    Daemon(String),
    /// Anything else (exit 1).
    #[error("{0}")]
    Other(String),
}

impl CliError {
    /// Process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Other(_) => 1,
            CliError::Usage(_) => 2,
            CliError::NotRunning(_) => 3,
            CliError::Permission(_) => 4,
            CliError::Daemon(_) => 5,
        }
    }
}

/// Daemon-supplied error text made safe for the terminal (I10).
fn daemon_text(code: &str, message: &str) -> String {
    let safe = candor_core::display::safe_str;
    format!("{}: {}", safe(code), safe(message))
}

/// Messages `recv_until` reads before giving up (a chatty or broken daemon
/// that never sends the awaited reply must not hang the CLI forever).
const MAX_WAIT_MESSAGES: usize = 100_000;

/// A connected, greeted client.
pub struct Conn {
    stream: UnixStream,
    /// The daemon's Welcome.
    pub welcome: DaemonMsg,
}

/// Socket paths tried in order when --socket is not given.
pub fn default_sockets() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/run/candor-dev/candor.sock"),
        PathBuf::from("/run/candor/candor.sock"),
    ]
}

impl Conn {
    /// Connects to the first reachable socket and says Hello.
    pub fn open(socket: Option<&PathBuf>) -> Result<Conn, CliError> {
        let candidates = match socket {
            Some(p) => vec![p.clone()],
            None => default_sockets(),
        };
        let mut last = CliError::NotRunning("no socket found".into());
        for path in candidates {
            match UnixStream::connect(&path) {
                Ok(stream) => return Conn::greet(stream),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    last = CliError::Permission(path.display().to_string());
                }
                Err(e) => {
                    if !matches!(last, CliError::Permission(_)) {
                        last = CliError::NotRunning(format!("{}: {e}", path.display()));
                    }
                }
            }
        }
        Err(last)
    }

    fn greet(stream: UnixStream) -> Result<Conn, CliError> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut c = Conn {
            stream,
            welcome: DaemonMsg::Pong { n: 0 },
        };
        c.send(&ClientMsg::Hello {
            proto: PROTO_VERSION,
            client: ClientKind::Cli,
            version: env!("CARGO_PKG_VERSION").into(),
        })?;
        match c.recv()? {
            w @ DaemonMsg::Welcome { .. } => c.welcome = w,
            DaemonMsg::Error { code, message } => {
                return Err(CliError::Daemon(daemon_text(&code, &message)));
            }
            other => return Err(CliError::Daemon(format!("unexpected reply {other:?}"))),
        }
        Ok(c)
    }

    /// Sends one message.
    pub fn send(&mut self, m: &ClientMsg) -> Result<(), CliError> {
        let body = encode(m).map_err(|e| CliError::Other(e.to_string()))?;
        write_frame(&mut self.stream, &body, MAX_CLIENT_FRAME)
            .map_err(|e| CliError::Other(format!("sending to the daemon: {e}")))
    }

    /// Receives one message; a daemon Error becomes `CliError::Daemon`.
    pub fn recv(&mut self) -> Result<DaemonMsg, CliError> {
        match read_frame(&mut self.stream, MAX_DAEMON_FRAME) {
            Ok(Some(body)) => match decode_daemon(&body) {
                Ok(DaemonMsg::Error { code, message }) => {
                    Err(CliError::Daemon(daemon_text(&code, &message)))
                }
                Ok(m) => Ok(m),
                Err(e) => Err(CliError::Daemon(e.to_string())),
            },
            Ok(None) => Err(CliError::Daemon("the daemon closed the connection".into())),
            Err(e) => Err(CliError::Other(format!("reading from the daemon: {e}"))),
        }
    }

    /// Waits up to `timeout` for a message to start arriving; None on
    /// timeout. Waiting uses poll(), so an idle wait never interrupts a
    /// frame; the 10 s socket read timeout remains only as a guard against a
    /// daemon that stops in the middle of a frame.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<DaemonMsg>, CliError> {
        let ts = rustix::time::Timespec {
            tv_sec: timeout.as_secs() as i64,
            tv_nsec: i64::from(timeout.subsec_nanos()),
        };
        let mut fds = [rustix::event::PollFd::new(
            &self.stream,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut fds, Some(&ts)) {
            Ok(0) => Ok(None),
            Ok(_) => self.recv().map(Some),
            Err(rustix::io::Errno::INTR) => Ok(None),
            Err(e) => Err(CliError::Other(format!("waiting for the daemon: {e}"))),
        }
    }

    /// Receives messages until `f` matches one.
    pub fn recv_until(&mut self, f: impl Fn(&DaemonMsg) -> bool) -> Result<DaemonMsg, CliError> {
        for _ in 0..MAX_WAIT_MESSAGES {
            let m = self.recv()?;
            if f(&m) {
                return Ok(m);
            }
        }
        Err(CliError::Daemon(
            "the daemon did not send the expected reply".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn daemon_error_text_is_escaped() {
        let t = super::daemon_text("bad\x1b]0;x\x07", "line1\nline2");
        assert!(!t.chars().any(|c| c.is_control()), "{t:?}");
    }
}
