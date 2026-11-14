//! Act mode (D19, WP27, experimental): pause, resume or kill one process on
//! a user's explicit request. Never automatic. Off unless the daemon runs
//! with `--enable-act`; then only root or members of `sysscope-act` may ask.
//!
//! Order matters: the pidfd is opened first and the start time is checked
//! after, so the signal reaches exactly the process the client saw (a pid
//! recycled before the open has another start time; a process that exits
//! after it makes pidfd_send_signal fail).

use sysscope_proto::{ActAction, ProcKey};

/// Command names treated as the display server or session manager of the
/// requester's session (never signalled).
const SESSION_CRITICAL: &[&str] = &[
    "Xorg",
    "Xwayland",
    "X",
    "gnome-shell",
    "gnome-session-b",
    "gnome-session",
    "kwin_wayland",
    "kwin_x11",
    "plasmashell",
    "ksmserver",
    "startplasma-x11",
    "startplasma-way",
    "xfce4-session",
    "xfwm4",
    "lxsession",
    "mutter",
    "sway",
    "weston",
    "Hyprland",
    "systemd",
    "sysscope-gui",
];

/// Who is asking (from SO_PEERCRED at connect).
#[derive(Clone, Copy, Debug)]
pub struct Requester {
    /// Peer uid.
    pub uid: u32,
    /// Peer pid.
    pub pid: u32,
}

/// Fields of /proc/<pid>/stat that matter here.
#[derive(Debug, Default, PartialEq)]
pub struct Stat {
    /// Command name (field 2).
    pub comm: String,
    /// Parent pid (field 4).
    pub ppid: u32,
    /// Session id (field 6).
    pub session: u32,
    /// Kernel flags (field 9).
    pub flags: u64,
    /// Start time in clock ticks (field 22).
    pub start: u64,
}

/// Parses /proc/<pid>/stat text (the name may hold spaces and ')').
pub fn parse_stat(text: &[u8]) -> Option<Stat> {
    let open = text.iter().position(|&b| b == b'(')?;
    let close = text.iter().rposition(|&b| b == b')')?;
    let comm = String::from_utf8_lossy(text.get(open + 1..close)?).into_owned();
    let rest = std::str::from_utf8(text.get(close + 1..)?).ok()?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(Stat {
        comm,
        ppid: f.get(1)?.parse().ok()?,
        session: f.get(3)?.parse().ok()?,
        flags: f.get(6)?.parse().ok()?,
        start: f.get(19)?.parse().ok()?,
    })
}

fn stat_of(pid: u32) -> Option<Stat> {
    parse_stat(&std::fs::read(format!("/proc/{pid}/stat")).ok()?)
}

/// (real, saved) uid of a process from /proc/<pid>/status.
fn uids_of(pid: u32) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = text.lines().find(|l| l.starts_with("Uid:"))?;
    let f: Vec<u32> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    Some((*f.first()?, *f.get(2)?))
}

/// gid of a group from /etc/group.
fn group_id(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(name)).then(|| f.nth(1).and_then(|g| g.parse().ok()))?
    })
}

/// May this client use act mode at all?
pub fn authorised(r: Requester) -> Result<(), String> {
    authorised_for(r, "act mode")
}

/// Root, or a member of `sysscope-act`: needed for act mode and for follow
/// mode, which limits detection for every client (owner's Q6 answer B).
/// `what` names the feature in the refusal.
pub fn authorised_for(r: Requester, what: &str) -> Result<(), String> {
    if r.uid == 0 {
        return Ok(());
    }
    let Some(gid) = group_id("sysscope-act") else {
        return Err(format!(
            "only root may use {what}: the group sysscope-act does not exist"
        ));
    };
    let status = std::fs::read_to_string(format!("/proc/{}/status", r.pid)).unwrap_or_default();
    let member = status
        .lines()
        .filter(|l| l.starts_with("Groups:") || l.starts_with("Gid:"))
        .flat_map(|l| l.split_whitespace().skip(1))
        .any(|g| g.parse() == Ok(gid));
    if member {
        Ok(())
    } else {
        Err(format!(
            "not authorised: {what} needs membership in the group sysscope-act"
        ))
    }
}

/// Why `target` must not be touched by `r`, if it must not.
pub fn protected(r: Requester, target: ProcKey, st: &Stat) -> Option<String> {
    const PF_KTHREAD: u64 = 0x0020_0000;
    if target.tgid == 1 {
        return Some("pid 1 (the init system) is protected".into());
    }
    if st.flags & PF_KTHREAD != 0 || target.tgid == 2 {
        return Some("kernel threads are protected".into());
    }
    if target.tgid == std::process::id() {
        return Some("the SysScope daemon itself is protected".into());
    }
    if target.tgid == r.pid {
        return Some("that is the client that asked".into());
    }
    // Any ancestor of the requesting client (its shell, terminal, session).
    let mut p = r.pid;
    for _ in 0..4096 {
        let Some(s) = stat_of(p) else { break };
        if s.ppid == target.tgid {
            return Some("that process is an ancestor of the client that asked".into());
        }
        if s.ppid <= 1 {
            break;
        }
        p = s.ppid;
    }
    if let Some(me) = stat_of(r.pid)
        && me.session == st.session
        && SESSION_CRITICAL.contains(&st.comm.as_str())
    {
        return Some(format!(
            "{} is the display server, session manager or GUI of your session",
            st.comm
        ));
    }
    if r.uid != 0 {
        match uids_of(target.tgid) {
            Some((real, saved)) if real == r.uid || saved == r.uid => {}
            _ => {
                return Some(
                    "you could not signal that process yourself (another user owns it)".into(),
                );
            }
        }
    }
    None
}

/// Performs one checked action; Ok/Err text is shown to the user.
pub fn act(r: Requester, target: ProcKey, action: ActAction) -> Result<String, String> {
    authorised(r)?;
    let pid = rustix::process::Pid::from_raw(target.tgid as i32)
        .ok_or_else(|| "no such process".to_string())?;
    let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        .map_err(|_| format!("process {} is gone", target.tgid))?;
    let st = stat_of(target.tgid).ok_or_else(|| format!("process {} is gone", target.tgid))?;
    if st.start != target.start_ticks {
        return Err(format!(
            "pid {} now belongs to another process (the one you saw has exited)",
            target.tgid
        ));
    }
    if let Some(why) = protected(r, target, &st) {
        return Err(format!("refused: {why}"));
    }
    let (sig, word) = match action {
        ActAction::Pause => (rustix::process::Signal::STOP, "paused"),
        ActAction::Resume => (rustix::process::Signal::CONT, "resumed"),
        ActAction::Kill => (rustix::process::Signal::KILL, "killed"),
    };
    rustix::process::pidfd_send_signal(&fd, sig).map_err(|e| format!("signal failed: {e}"))?;
    Ok(format!("{word} pid {} ({})", target.tgid, st.comm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_hostile_name_parses() {
        let s =
            parse_stat(b"42 (a) b) c) S 7 42 42 0 -1 4194560 0 0 0 0 1 2 0 0 20 0 1 0 12345 0 0")
                .unwrap();
        assert_eq!(s.comm, "a) b) c");
        assert_eq!(
            (s.ppid, s.session, s.flags, s.start),
            (7, 42, 4194560, 12345)
        );
    }

    #[test]
    fn own_process_and_pid1_are_protected() {
        let me = std::process::id();
        let st = stat_of(me).unwrap();
        let r = Requester { uid: 0, pid: me };
        let key = ProcKey {
            tgid: me,
            start_ticks: st.start,
        };
        assert!(protected(r, key, &st).is_some());
        let one = stat_of(1).unwrap_or_default();
        assert!(
            protected(
                r,
                ProcKey {
                    tgid: 1,
                    start_ticks: one.start
                },
                &one
            )
            .is_some()
        );
    }
}
