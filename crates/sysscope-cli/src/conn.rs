//! Talking to the daemon over its Unix socket.
//!
//! Finds the socket (dev path first, then the installed one, or --socket),
//! says Hello and maps every failure to an error with a clear message and a
//! distinct exit code, so scripts can tell "daemon not running" from
//! "permission denied" from "protocol mismatch".

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use sysscope_proto::{
    ClientKind, ClientMsg, DaemonMsg, MAX_CLIENT_FRAME, MAX_DAEMON_FRAME, PROTO_VERSION,
    decode_daemon, encode, read_frame, write_frame,
};

/// Why a command failed; each kind has its own exit code.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Bad command line (exit 2).
    #[error("{0}")]
    Usage(String),
    /// Daemon not running (exit 3).
    #[error(
        "the SysScope daemon is not running ({0}). Start it with: sudo systemctl start sysscoped   (or for development: sudo ./target/debug/sysscoped --dev)"
    )]
    NotRunning(String),
    /// No permission on the socket (exit 4).
    #[error(
        "permission denied on {0}. Join the group with: sudo usermod -aG sysscope $USER   then log out and back in"
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

/// A connected, greeted client.
pub struct Conn {
    stream: UnixStream,
    /// The daemon's Welcome.
    pub welcome: DaemonMsg,
}

/// Socket paths tried in order when --socket is not given.
pub fn default_sockets() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/run/sysscope-dev/sysscope.sock"),
        PathBuf::from("/run/sysscope/sysscope.sock"),
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
                return Err(CliError::Daemon(format!("{code}: {message}")));
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
                    Err(CliError::Daemon(format!("{code}: {message}")))
                }
                Ok(m) => Ok(m),
                Err(e) => Err(CliError::Daemon(e.to_string())),
            },
            Ok(None) => Err(CliError::Daemon("the daemon closed the connection".into())),
            Err(e) => Err(CliError::Other(format!("reading from the daemon: {e}"))),
        }
    }

    /// Waits up to `timeout` for a message; None on timeout.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<DaemonMsg>, CliError> {
        let _ = self.stream.set_read_timeout(Some(timeout));
        let r = self.recv();
        let _ = self.stream.set_read_timeout(Some(Duration::from_secs(10)));
        match r {
            Err(CliError::Other(e))
                if e.contains("timed out") || e.contains("Resource temporarily") =>
            {
                Ok(None)
            }
            other => other.map(Some),
        }
    }

    /// Receives messages until `f` matches one.
    pub fn recv_until(&mut self, f: impl Fn(&DaemonMsg) -> bool) -> Result<DaemonMsg, CliError> {
        loop {
            let m = self.recv()?;
            if f(&m) {
                return Ok(m);
            }
        }
    }
}
