//! Terminal colour (redesign spec section 9): the same three meanings as
//! the GUI. Red is a finding, amber is worth a look, teal is the followed
//! process; headers and footers are dim and names bright. Colour is used
//! only when stdout is a terminal, never when `NO_COLOR` is set, and
//! `--color=auto|always|never` overrides the terminal check. Piped output
//! is plain text with no escape codes. The `●` marker is text, so the
//! meaning survives without colour.

use std::io::IsTerminal;

/// The `--color` setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// Colour if stdout is a terminal and NO_COLOR is not set.
    Auto,
    /// Always colour (still not if NO_COLOR is set).
    Always,
    /// Never colour.
    Never,
}

impl When {
    /// Parses the value of `--color=`.
    pub fn parse(s: &str) -> Option<When> {
        match s {
            "auto" => Some(When::Auto),
            "always" => Some(When::Always),
            "never" => Some(When::Never),
            _ => None,
        }
    }
}

/// Decides colour from the setting, NO_COLOR and whether stdout is a tty.
pub fn decide(when: When, no_color: bool, tty: bool) -> bool {
    !no_color
        && match when {
            When::Always => true,
            When::Never => false,
            When::Auto => tty,
        }
}

/// Output style: colour on or off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    /// Emit ANSI colour.
    pub color: bool,
}

impl Style {
    /// From the command line setting and the environment.
    pub fn from_env(when: When) -> Style {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Style {
            color: decide(when, no_color, std::io::stdout().is_terminal()),
        }
    }

    fn paint(self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    /// Dim (headers, footers, labels).
    pub fn dim(self, s: &str) -> String {
        self.paint("2", s)
    }
    /// Bright (names).
    pub fn bright(self, s: &str) -> String {
        self.paint("1;97", s)
    }
    /// Red: findings.
    pub fn alert(self, s: &str) -> String {
        self.paint("38;2;244;124;124", s)
    }
    /// Amber: worth a look.
    pub fn caution(self, s: &str) -> String {
        self.paint("38;2;232;180;90", s)
    }
    /// Teal: the followed process.
    pub fn accent(self, s: &str) -> String {
        self.paint("38;2;45;212;191", s)
    }

    /// The leading marker: a red `●` for a finding (score 60+), an amber
    /// one for worth a look (30-59), two spaces otherwise.
    pub fn marker(self, score: u8) -> String {
        match score {
            60.. => format!("{} ", self.alert("●")),
            30..=59 => format!("{} ", self.caution("●")),
            _ => "  ".to_string(),
        }
    }

    /// A score in its band colour.
    pub fn score(self, score: u8, text: &str) -> String {
        match score {
            60.. => self.alert(text),
            30..=59 => self.caution(text),
            _ => self.dim(text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colour_is_used_only_when_allowed() {
        // auto: only on a terminal
        assert!(decide(When::Auto, false, true));
        assert!(!decide(When::Auto, false, false));
        // NO_COLOR always wins
        assert!(!decide(When::Auto, true, true));
        assert!(!decide(When::Always, true, true));
        // explicit settings
        assert!(decide(When::Always, false, false));
        assert!(!decide(When::Never, false, true));
        assert_eq!(When::parse("always"), Some(When::Always));
        assert_eq!(When::parse("sometimes"), None);
    }

    #[test]
    fn plain_style_has_no_escape_codes() {
        let p = Style { color: false };
        let s = [
            p.dim("a"),
            p.bright("b"),
            p.alert("c"),
            p.marker(90),
            p.score(40, "40"),
        ]
        .concat();
        assert!(!s.contains('\x1b'), "{s:?}");
        assert_eq!(p.marker(90), "● ");
        assert_eq!(p.marker(0), "  ");
        let c = Style { color: true };
        assert!(c.alert("x").starts_with("\x1b["));
    }
}
