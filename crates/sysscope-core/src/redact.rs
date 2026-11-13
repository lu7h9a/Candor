//! Redaction of exports, reports and recordings meant for sharing (plan 9.2).
//!
//! Best effort, on by default: the user's home becomes `~`, other users'
//! homes `~user1`, `~user2`...; the username and hostname become `<user>`
//! and `<host>`; values of secret-looking flags (`--password`, `--token`,
//! `--secret`, `--key`, `-p`) and `KEY=VALUE` pairs with secret-like keys
//! become `<redacted>`; `user:pass@` is removed from URLs. IP addresses are
//! kept unless `ips` is set, then each one becomes a stable `ip1`, `ip2`...

use std::collections::BTreeMap;

/// What to redact and the local names to hide.
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    /// Home directory of the exporting user (e.g. "/home/anshul").
    pub home: String,
    /// The exporting user's name.
    pub user: String,
    /// This machine's hostname.
    pub host: String,
    /// Also replace IP addresses with pseudonyms.
    pub ips: bool,
    other_homes: BTreeMap<String, String>,
    ip_names: BTreeMap<String, String>,
}

const SECRET_FLAGS: &[&str] = &[
    "--password",
    "--passwd",
    "--token",
    "--secret",
    "--key",
    "-p",
];
const SECRET_WORDS: &[&str] = &["pass", "token", "secret", "key", "auth", "cred"];

impl Redactor {
    /// A redactor for this user and host.
    pub fn new(home: &str, user: &str, host: &str, ips: bool) -> Redactor {
        Redactor {
            home: home.trim_end_matches('/').to_string(),
            user: user.to_string(),
            host: host.to_string(),
            ips,
            ..Redactor::default()
        }
    }

    fn other_home(&mut self, name: &str) -> String {
        let n = self.other_homes.len() + 1;
        self.other_homes
            .entry(name.to_string())
            .or_insert_with(|| format!("~user{n}"))
            .clone()
    }

    /// Redacts paths, names and URL credentials in one piece of text.
    pub fn text(&mut self, s: &str) -> String {
        let mut out = s.to_string();
        if !self.home.is_empty() {
            out = out.replace(&self.home, "~");
        }
        // Other users' homes: /home/<name> -> ~userN.
        let mut result = String::new();
        let mut rest = out.as_str();
        while let Some(i) = rest.find("/home/") {
            result.push_str(rest.get(..i).unwrap_or(""));
            let after = rest.get(i + 6..).unwrap_or("");
            let end = after.find(['/', ' ', '"', '\'']).unwrap_or(after.len());
            let name = after.get(..end).unwrap_or("");
            if name.is_empty() {
                result.push_str("/home/");
            } else {
                let alias = self.other_home(name);
                result.push_str(&alias);
            }
            rest = after.get(end..).unwrap_or("");
        }
        result.push_str(rest);
        let mut out = strip_userinfo(&result);
        if !self.user.is_empty() && self.user.len() > 2 {
            out = out.replace(&self.user, "<user>");
        }
        if !self.host.is_empty() && self.host.len() > 2 {
            out = out.replace(&self.host, "<host>");
        }
        out
    }

    /// Redacts a command line given as NUL-separated arguments; returns the
    /// arguments joined by spaces.
    pub fn argv(&mut self, argv: &str) -> String {
        let args: Vec<&str> = argv.split(['\0', ' ']).filter(|a| !a.is_empty()).collect();
        let mut out = Vec::new();
        let mut hide_next = false;
        for a in args {
            if hide_next {
                out.push("<redacted>".to_string());
                hide_next = false;
                continue;
            }
            if SECRET_FLAGS.contains(&a) {
                out.push(a.to_string());
                hide_next = true;
                continue;
            }
            if let Some((k, _)) = a.split_once('=') {
                let lk = k.trim_start_matches('-').to_ascii_lowercase();
                if SECRET_FLAGS.contains(&k) || SECRET_WORDS.iter().any(|w| lk.contains(w)) {
                    out.push(format!("{k}=<redacted>"));
                    continue;
                }
            }
            out.push(self.text(a));
        }
        out.join(" ")
    }

    /// Replaces an IP address with a stable pseudonym when `ips` is set.
    pub fn ip(&mut self, addr: &str) -> String {
        if !self.ips || addr.is_empty() {
            return addr.to_string();
        }
        let n = self.ip_names.len() + 1;
        self.ip_names
            .entry(addr.to_string())
            .or_insert_with(|| format!("ip{n}"))
            .clone()
    }
}

/// Removes "user:pass@" from every "scheme://user:pass@host" in the text.
fn strip_userinfo(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        out.push_str(rest.get(..i + 3).unwrap_or(""));
        let after = rest.get(i + 3..).unwrap_or("");
        let host_end = after.find(['/', ' ', '"']).unwrap_or(after.len());
        let authority = after.get(..host_end).unwrap_or("");
        match authority.rfind('@') {
            Some(at) => out.push_str(authority.get(at + 1..).unwrap_or("")),
            None => out.push_str(authority),
        }
        rest = after.get(host_end..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homes_names_secrets_and_urls() {
        let mut r = Redactor::new("/home/anshul", "anshul", "kali-box", false);
        assert_eq!(r.text("/home/anshul/.ssh/id_rsa"), "~/.ssh/id_rsa");
        assert_eq!(
            r.text("/home/bob/x and /home/carol/y and /home/bob/z"),
            "~user1/x and ~user2/y and ~user1/z"
        );
        assert_eq!(r.text("ssh anshul@kali-box"), "ssh <user>@<host>");
        assert_eq!(
            r.argv("mysql\0-p\0hunter2\0--password=hunter2\0API_TOKEN=abc\0-v"),
            "mysql -p <redacted> --password=<redacted> API_TOKEN=<redacted> -v"
        );
        assert_eq!(
            r.text("curl https://bob:pw@example.com/x"),
            "curl https://example.com/x"
        );
        assert_eq!(r.ip("10.0.0.1"), "10.0.0.1");
        let mut r = Redactor::new("/root", "root", "h", true);
        assert_eq!(
            (r.ip("10.0.0.1"), r.ip("10.0.0.2"), r.ip("10.0.0.1")),
            ("ip1".into(), "ip2".into(), "ip1".into())
        );
    }
}
