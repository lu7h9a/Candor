//! Window settings the user changes from the menu: start at login and
//! start minimised. Stored for this user only:
//! - `$XDG_CONFIG_HOME/candor/gui.json` (default `~/.config/candor`);
//! - start at login is a standard XDG autostart entry,
//!   `$XDG_CONFIG_HOME/autostart/candor.desktop`, which every desktop
//!   (XFCE, GNOME, KDE...) reads. Turning it off deletes that file.
//!
//! Nothing here needs root, and the daemon is not involved: the daemon is
//! started at boot by systemd (`systemctl enable candord`), separately.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Settings kept in gui.json.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Start minimised (also used by the autostart entry).
    pub start_minimised: bool,
}

/// The user's config directory.
pub fn config_home() -> Option<PathBuf> {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")),
    }
}

fn settings_path(base: &Path) -> PathBuf {
    base.join("candor").join("gui.json")
}

fn autostart_path(base: &Path) -> PathBuf {
    base.join("autostart").join("candor.desktop")
}

/// Reads the settings (defaults if missing or unreadable).
pub fn load(base: &Path) -> Settings {
    std::fs::read_to_string(settings_path(base))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Writes the settings, and the autostart entry if it is on, so the entry
/// starts the window the way the settings say.
pub fn save(base: &Path, s: &Settings) -> Result<(), String> {
    let p = settings_path(base);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))?;
    if autostart_enabled(base) {
        set_autostart(base, true, s.start_minimised)?;
    }
    Ok(())
}

/// True if the autostart entry exists.
pub fn autostart_enabled(base: &Path) -> bool {
    autostart_path(base).is_file()
}

/// Quotes a path for a desktop entry's Exec key (spec: double quotes, and
/// `"`, `` ` ``, `$` and `\` escaped).
fn exec_quote(p: &str) -> String {
    let mut o = String::from("\"");
    for c in p.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('"');
    o
}

/// The autostart entry for the program at `exe`.
pub fn desktop_entry(exe: &str, minimised: bool) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=Candor\nComment=See what the programs on this computer are doing\nExec={}{}\nIcon=candor\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        exec_quote(exe),
        if minimised { " --minimised" } else { "" }
    )
}

/// Turns start at login on (writes the entry) or off (deletes it).
pub fn set_autostart(base: &Path, on: bool, minimised: bool) -> Result<(), String> {
    let p = autostart_path(base);
    if !on {
        return match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", p.display())),
        };
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.to_str().ok_or("the program's path is not valid text")?;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(&p, desktop_entry(exe, minimised)).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "candor-settings-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn autostart_entry_is_written_and_removed() {
        let base = tmp();
        assert!(!autostart_enabled(&base));
        set_autostart(&base, true, false).unwrap();
        assert!(autostart_enabled(&base));
        let text = std::fs::read_to_string(base.join("autostart/candor.desktop")).unwrap();
        assert!(text.starts_with("[Desktop Entry]\nType=Application\n"));
        assert!(!text.contains("--minimised"));
        // Start minimised is carried into the entry when saved.
        save(
            &base,
            &Settings {
                start_minimised: true,
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(base.join("autostart/candor.desktop")).unwrap();
        assert!(text.contains(" --minimised\n"));
        assert_eq!(
            load(&base),
            Settings {
                start_minimised: true
            }
        );
        set_autostart(&base, false, false).unwrap();
        assert!(!autostart_enabled(&base));
        // Turning off twice is fine.
        set_autostart(&base, false, false).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn exec_paths_are_quoted() {
        let e = desktop_entry("/home/a b/$x/candor-gui", true);
        assert!(
            e.contains("Exec=\"/home/a b/\\$x/candor-gui\" --minimised\n"),
            "{e}"
        );
    }

    #[test]
    fn missing_or_bad_settings_give_defaults() {
        let base = tmp();
        assert_eq!(load(&base), Settings::default());
        std::fs::create_dir_all(base.join("candor")).unwrap();
        std::fs::write(base.join("candor/gui.json"), "not json").unwrap();
        assert_eq!(load(&base), Settings::default());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
