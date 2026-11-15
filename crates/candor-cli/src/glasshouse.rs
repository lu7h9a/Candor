//! `candor glasshouse run [--timeout N] FILE [ARGS...]`: uploads the file
//! (D25: bytes, never a path), runs it in Glasshouse, prints the report.
//!
//! The plan 6.4 limitation is printed before every run. Everything the
//! daemon sends back about the sample is escaped before it is printed.

use crate::conn::{CliError, Conn};
use candor_core::display::safe_str;
use candor_core::ghreport::{LIMITATION, render_text};
use candor_proto::{BStr, ClientMsg, DaemonMsg, GhState};
use std::io::Read;
use std::time::{Duration, Instant};

/// Raw bytes per upload chunk (the protocol maximum).
const CHUNK: usize = 64 * 1024;

/// Parses `run [--timeout N] FILE [ARGS...]`; arguments after FILE are the
/// sample's own, even if they look like options.
fn parse(rest: &[String]) -> Result<(u32, String, Vec<String>), CliError> {
    let usage = || CliError::Usage("glasshouse run [--timeout SECONDS] FILE [ARGS...]".into());
    if rest.first().map(String::as_str) != Some("run") {
        return Err(usage());
    }
    let mut timeout = 60u32;
    let mut i = 1;
    while let Some(a) = rest.get(i) {
        if a == "--timeout" {
            timeout = rest
                .get(i + 1)
                .and_then(|v| v.parse().ok())
                .filter(|t| (1..=600).contains(t))
                .ok_or_else(|| CliError::Usage("--timeout must be 1 to 600 seconds".into()))?;
            i += 2;
        } else {
            break;
        }
    }
    let file = rest.get(i).cloned().ok_or_else(usage)?;
    Ok((timeout, file, rest.get(i + 1..).unwrap_or(&[]).to_vec()))
}

/// `glasshouse report FILE`: prints a saved report (strictly parsed, at
/// most 64 MiB, everything escaped). Works without a daemon.
pub fn show(rest: &[String]) -> Result<(), CliError> {
    let file = rest
        .get(1)
        .ok_or_else(|| CliError::Usage("glasshouse report FILE.json".into()))?;
    let mut body = Vec::new();
    std::fs::File::open(file)
        .and_then(|f| f.take(64 << 20).read_to_end(&mut body))
        .map_err(|e| CliError::Other(format!("{file}: {e}")))?;
    let r: candor_proto::GhReport = serde_json::from_slice(&body).map_err(|e| {
        CliError::Other(format!(
            "{file}: not a Glasshouse report: {}",
            safe_str(&e.to_string())
        ))
    })?;
    print!("{}", render_text(&r));
    Ok(())
}

/// Runs a sample and prints the report (text, or JSON with --json).
pub fn run(c: &mut Conn, rest: &[String], json: bool) -> Result<(), CliError> {
    let (timeout_s, file, args) = parse(rest)?;
    let offered = matches!(&c.welcome, DaemonMsg::Welcome { features, .. } if features.iter().any(|f| f == "glasshouse"));
    if !offered {
        let why = match &c.welcome {
            DaemonMsg::Welcome { unavailable, .. } => unavailable
                .iter()
                .find(|n| n.feature == "glasshouse")
                .map(|n| safe_str(&n.reason)),
            _ => None,
        }
        .unwrap_or_else(|| "the daemon does not offer it".into());
        return Err(CliError::Other(format!(
            "Glasshouse is not available on this system: {why}"
        )));
    }
    let mut f = std::fs::File::open(&file).map_err(|e| CliError::Other(format!("{file}: {e}")))?;
    let meta = f
        .metadata()
        .map_err(|e| CliError::Other(format!("{file}: {e}")))?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > 256 * 1024 * 1024 {
        return Err(CliError::Other(format!(
            "{file}: must be a regular file of 1 byte to 256 MiB"
        )));
    }
    eprintln!("{LIMITATION}\n");
    let name = std::path::Path::new(&file)
        .file_name()
        .map(|n| BStr(std::os::unix::ffi::OsStrExt::as_bytes(n).to_vec()))
        .unwrap_or_else(|| BStr::from("sample"));
    c.send(&ClientMsg::GhUploadBegin {
        name,
        size: meta.len(),
    })?;
    let mut buf = vec![0u8; CHUNK];
    let mut seq = 0u32;
    let mut sent = 0u64;
    while sent < meta.len() {
        let n = f
            .read(&mut buf)
            .map_err(|e| CliError::Other(format!("{file}: {e}")))?;
        if n == 0 {
            return Err(CliError::Other(format!("{file}: shrank while reading")));
        }
        let n = n.min((meta.len() - sent) as usize);
        c.send(&ClientMsg::GhUploadChunk {
            seq,
            b64: candor_proto::b64::encode(buf.get(..n).unwrap_or(&[])),
        })?;
        seq += 1;
        sent += n as u64;
    }
    // Uploading status at begin, then "sample received" (errors end it).
    let mut received = false;
    for _ in 0..4 {
        if let DaemonMsg::GhStatus { message, .. } = c.recv()?
            && message == "sample received"
        {
            received = true;
            break;
        }
    }
    if !received {
        return Err(CliError::Daemon(
            "the daemon did not confirm the upload".into(),
        ));
    }
    c.send(&ClientMsg::GhRun {
        args: args.iter().map(|a| BStr::from(a.as_str())).collect(),
        timeout_s,
    })?;
    // Starting the sandbox takes a few seconds; the run at most timeout_s;
    // killing, waiting for the box to empty and diffing at most ~60 s more.
    let deadline = Instant::now() + Duration::from_secs(u64::from(timeout_s) + 180);
    let mut report = None;
    let mut touched_shown = 0usize;
    while Instant::now() < deadline {
        let Some(m) = c.recv_timeout(Duration::from_secs(1))? else {
            continue;
        };
        match m {
            DaemonMsg::GhStatus {
                state,
                message,
                decoys,
                ..
            } => {
                if !decoys.is_empty() {
                    let touched = decoys
                        .iter()
                        .filter(|d| d.states != vec![candor_proto::DecoyState::Untouched])
                        .count();
                    if touched != touched_shown && !json {
                        eprintln!(
                            "glasshouse: {touched} of {} decoys touched so far",
                            decoys.len()
                        );
                        touched_shown = touched;
                    }
                }
                if !message.is_empty() && !json {
                    eprintln!("glasshouse: {}", safe_str(&message));
                }
                match state {
                    GhState::Failed => {
                        return Err(CliError::Daemon(format!(
                            "Glasshouse run failed: {}",
                            safe_str(&message)
                        )));
                    }
                    GhState::Finished => break,
                    _ => {}
                }
            }
            DaemonMsg::GhReport { report: r } => report = Some(r),
            _ => {}
        }
    }
    let Some(r) = report else {
        return Err(CliError::Daemon("no report arrived in time".into()));
    };
    if json {
        println!("{}", crate::out::json(&r));
    } else {
        print!("{}", render_text(&r));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn arguments_after_the_file_belong_to_the_sample() {
        let (t, f, a) = parse(&s(&["run", "--timeout", "30", "x.py", "--timeout", "5"])).unwrap();
        assert_eq!((t, f.as_str(), a), (30, "x.py", s(&["--timeout", "5"])));
        assert!(parse(&s(&["run", "--timeout", "0", "x"])).is_err());
        assert!(parse(&s(&["run"])).is_err());
        assert!(parse(&s(&["walk", "x"])).is_err());
    }
}
