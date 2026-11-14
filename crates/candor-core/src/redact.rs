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
    "--pass",
    "--token",
    "--secret",
    "--key",
    "-p",
    "--api-key",
    "--apikey",
    "--access-token",
    "--auth-token",
    "--client-secret",
    "--auth",
    "-u",
    "--user",
    "--private-key",
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
        if !self.user.is_empty() {
            out = replace_word(&out, &self.user, "<user>");
        }
        if !self.host.is_empty() {
            out = replace_word(&out, &self.host, "<host>");
        }
        if self.ips {
            out = self.ips_in(&out);
        }
        out
    }

    /// Replaces every IP address (alone or as addr:port, [v6]:port) in text.
    fn ips_in(&mut self, s: &str) -> String {
        let is_ip_char = |c: char| c.is_ascii_hexdigit() || c == '.' || c == ':';
        let mut out = String::new();
        let mut token = String::new();
        let flush = |tok: &mut String, out: &mut String, me: &mut Redactor| {
            if tok.is_empty() {
                return;
            }
            let t = tok.trim_end_matches(':').to_string();
            let tail = &tok[t.len()..];
            if t.parse::<std::net::IpAddr>().is_ok() {
                out.push_str(&me.ip(&t));
            } else if let Some((addr, port)) = t.rsplit_once(':')
                && addr.parse::<std::net::Ipv4Addr>().is_ok()
                && port.parse::<u16>().is_ok()
            {
                let alias = me.ip(addr);
                out.push_str(&format!("{alias}:{port}"));
            } else {
                out.push_str(&t);
            }
            out.push_str(tail);
            tok.clear();
        };
        for c in s.chars() {
            if is_ip_char(c) {
                token.push(c);
            } else {
                flush(&mut token, &mut out, self);
                out.push(c);
            }
        }
        flush(&mut token, &mut out, self);
        out
    }

    /// Redacts a command line given as NUL-separated arguments (one argument
    /// may contain spaces); returns the arguments joined by spaces.
    pub fn argv(&mut self, argv: &str) -> String {
        let args: Vec<&str> = argv.split('\0').filter(|a| !a.is_empty()).collect();
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
            // Attached values: -psecret (mysql style).
            if a.len() > 2 && a.starts_with("-p") && !a.starts_with("--") {
                out.push("-p<redacted>".to_string());
                continue;
            }
            // Header values such as "Authorization: Bearer x".
            if let Some((k, _)) = a.split_once(':')
                && [
                    "authorization",
                    "cookie",
                    "x-api-key",
                    "proxy-authorization",
                ]
                .contains(&k.trim().to_ascii_lowercase().as_str())
            {
                out.push(format!("{k}: <redacted>"));
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

/// Replaces `word` only where it stands alone (not inside a longer name),
/// so a user called "bin" does not turn "/usr/bin" into "/usr/<user>".
fn replace_word(s: &str, word: &str, with: &str) -> String {
    if word.is_empty() {
        return s.to_string();
    }
    // '/' and '.' count as part of a word: path components are not names
    // (home directories are handled before this).
    let is_word = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | '/' | '.');
    let mut out = String::new();
    let mut i = 0;
    while let Some(pos) = s.get(i..).and_then(|r| r.find(word)) {
        let start = i + pos;
        let end = start + word.len();
        let before = s.get(..start).and_then(|b| b.chars().last());
        let after = s.get(end..).and_then(|a| a.chars().next());
        out.push_str(s.get(i..start).unwrap_or(""));
        if before.is_none_or(|c| !is_word(c)) && after.is_none_or(|c| !is_word(c)) {
            out.push_str(with);
        } else {
            out.push_str(word);
        }
        i = end;
    }
    out.push_str(s.get(i..).unwrap_or(""));
    out
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
        // Review fixes: short names only as whole words; attached and header secrets.
        let mut r = Redactor::new("/home/bin", "bin", "box1", false);
        assert_eq!(
            r.text("/usr/bin/ls run by bin on box1"),
            "/usr/bin/ls run by <user> on <host>"
        );
        assert_eq!(r.argv("mysql\0-psecret\0--api-key\0k1\0-H\0Authorization: Bearer tok\0--password\0two words"),
            "mysql -p<redacted> --api-key <redacted> -H Authorization: <redacted> --password <redacted>");
        let mut r = Redactor::new("/root", "root", "h", true);
        assert_eq!(
            r.text("Connect 10.1.2.3:443 then 10.1.2.3 and ::1"),
            "Connect ip1:443 then ip1 and ip2"
        );
        let mut r = Redactor::new("/root", "root", "h", true);
        assert_eq!(
            (r.ip("10.0.0.1"), r.ip("10.0.0.2"), r.ip("10.0.0.1")),
            ("ip1".into(), "ip2".into(), "ip1".into())
        );
    }
}
