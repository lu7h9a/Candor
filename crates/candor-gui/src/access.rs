//! Group membership for the window's user: may it follow processes
//! (`candor-act`), and does this login session already have the group?
//!
//! Joining a group is done by the system, not by Candor: the window runs
//! `pkexec /usr/sbin/usermod -aG GROUP USER`, and the desktop's own
//! authentication dialog asks for the password. The window never sees it.

use std::process::Command;

/// Membership of one group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupState {
    /// This login session has the group.
    Active,
    /// The user is in the group, but this session started before: log out
    /// and back in.
    NeedsRelogin,
    /// The user is not in the group.
    NotMember,
    /// The group does not exist on this system (Candor not installed?).
    NoGroup,
}

/// Parses `/etc/group` text: (gid, members) of `group`.
pub fn group_entry(etc_group: &str, group: &str) -> Option<(u32, Vec<String>)> {
    etc_group.lines().find_map(|l| {
        let mut f = l.split(':');
        if f.next()? != group {
            return None;
        }
        let _pw = f.next()?;
        let gid = f.next()?.parse().ok()?;
        let members = f
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .collect();
        Some((gid, members))
    })
}

/// The supplementary groups of this process, from `/proc/self/status` text.
pub fn session_groups(status: &str) -> Vec<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .map(|g| {
            g.split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The user name for a uid, from `/etc/passwd` text.
pub fn user_name(etc_passwd: &str, uid: u32) -> Option<String> {
    etc_passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let _pw = f.next()?;
        (f.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

/// Decides the state from the three inputs (testable without a system).
pub fn decide(
    entry: Option<(u32, Vec<String>)>,
    user: &str,
    primary_gid: u32,
    session: &[u32],
) -> GroupState {
    match entry {
        None => GroupState::NoGroup,
        Some((gid, _)) if session.contains(&gid) || primary_gid == gid => GroupState::Active,
        Some((_, members)) if members.iter().any(|m| m == user) => GroupState::NeedsRelogin,
        Some(_) => GroupState::NotMember,
    }
}

fn primary_gid(status: &str) -> u32 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Gid:"))
        .and_then(|g| g.split_whitespace().next()?.parse().ok())
        .unwrap_or(u32::MAX)
}

/// The window user's name.
pub fn me() -> Option<String> {
    let uid = crate::model::my_uid()?;
    user_name(&std::fs::read_to_string("/etc/passwd").ok()?, uid)
}

/// The state of `group` for the user running this window.
pub fn state(group: &str) -> GroupState {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let etc = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let user = me().unwrap_or_default();
    decide(
        group_entry(&etc, group),
        &user,
        primary_gid(&status),
        &session_groups(&status),
    )
}

/// The command that adds the user to a group (shown to the user too).
pub fn join_command(group: &str, user: &str) -> Vec<String> {
    vec![
        "/usr/bin/pkexec".into(),
        "/usr/sbin/usermod".into(),
        "-aG".into(),
        group.into(),
        user.into(),
    ]
}

/// Runs the join command and waits for it. `Ok` when usermod succeeded.
pub fn join(group: &str) -> Result<(), String> {
    let user = me().ok_or("cannot tell which user this window runs as")?;
    let cmd = join_command(group, &user);
    let (prog, args) = cmd.split_first().ok_or("no command")?;
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("could not start pkexec: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(()),
        // pkexec: 126 = the dialog was dismissed or the password refused,
        // 127 = no authentication agent is running.
        Some(126) => Err("the request was cancelled or not authorised".into()),
        Some(127) => Err(format!(
            "no password dialog is available in this session; run this in a terminal instead: sudo usermod -aG {group} {user}"
        )),
        _ => Err(candor_core::display::safe_str(
            String::from_utf8_lossy(&out.stderr).trim(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "root:x:0:\ncandor:x:965:alice\ncandor-act:x:964:bob,alice\nwheel:x:10:\n";

    #[test]
    fn reads_group_passwd_and_status() {
        assert_eq!(
            group_entry(GROUP, "candor-act"),
            Some((964, vec!["bob".to_string(), "alice".to_string()]))
        );
        assert_eq!(group_entry(GROUP, "nope"), None);
        assert_eq!(
            user_name(
                "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/zsh\n",
                1000
            ),
            Some("alice".into())
        );
        assert_eq!(
            session_groups("Name:\tx\nGroups:\t4 27 965 \n"),
            vec![4, 27, 965]
        );
    }

    #[test]
    fn decides_the_state() {
        let e = || group_entry(GROUP, "candor-act");
        assert_eq!(decide(e(), "alice", 1000, &[964]), GroupState::Active);
        // Member in /etc/group but this session predates it.
        assert_eq!(decide(e(), "alice", 1000, &[27]), GroupState::NeedsRelogin);
        assert_eq!(decide(e(), "carol", 1000, &[27]), GroupState::NotMember);
        assert_eq!(decide(None, "alice", 1000, &[]), GroupState::NoGroup);
    }

    #[test]
    fn the_join_command_is_fixed() {
        assert_eq!(
            join_command("candor-act", "alice"),
            [
                "/usr/bin/pkexec",
                "/usr/sbin/usermod",
                "-aG",
                "candor-act",
                "alice"
            ]
        );
    }
}
