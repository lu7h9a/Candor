//! Startup checks that must pass before anything is loaded.
//!
//! The daemon refuses to start with a clear one-paragraph message (exit
//! code 3 for "this kernel cannot run SysScope") instead of letting a raw
//! libbpf or verifier error reach the user.

use std::fs;

/// Why the daemon cannot start.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// Not running as root.
    #[error(
        "sysscoped must run as root (effective uid is {0}). Start it with sudo or as the systemd service."
    )]
    NotRoot(u32),
    /// Kernel has no BTF.
    #[error(
        "this kernel does not provide BTF type information (/sys/kernel/btf/vmlinux is missing). SysScope needs a kernel built with CONFIG_DEBUG_INFO_BTF=y, which all supported distributions ship."
    )]
    NoBtf,
    /// Running inside a container or other pid namespace.
    #[error(
        "sysscoped must run in the initial PID namespace (its namespace {own} differs from PID 1's {init}). Process ids would not match the kernel's."
    )]
    NotInitPidNs {
        /// Our namespace link.
        own: String,
        /// PID 1's namespace link.
        init: String,
    },
    /// Could not read a /proc file needed for the checks.
    #[error("cannot read {path}: {err}")]
    Proc {
        /// The file.
        path: String,
        /// The error.
        err: String,
    },
}

impl StartupError {
    /// Process exit code for this error (3 = kernel cannot run SysScope).
    pub fn exit_code(&self) -> i32 {
        match self {
            StartupError::NoBtf => 3,
            _ => 1,
        }
    }
}

/// Effective uid of this process, read from /proc/self/status.
pub fn effective_uid() -> Result<u32, StartupError> {
    let path = "/proc/self/status";
    let text = fs::read_to_string(path).map_err(|e| StartupError::Proc {
        path: path.into(),
        err: e.to_string(),
    })?;
    // Line format: "Uid:\treal\teffective\tsaved\tfs".
    text.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|e| e.parse().ok())
        .ok_or(StartupError::Proc {
            path: path.into(),
            err: "no Uid line".into(),
        })
}

fn ns_link(path: &str) -> Result<String, StartupError> {
    fs::read_link(path)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| StartupError::Proc {
            path: path.into(),
            err: e.to_string(),
        })
}

/// Runs all checks; returns the first failure.
pub fn check() -> Result<(), StartupError> {
    let euid = effective_uid()?;
    if euid != 0 {
        return Err(StartupError::NotRoot(euid));
    }
    if fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        return Err(StartupError::NoBtf);
    }
    let own = ns_link("/proc/self/ns/pid")?;
    let init = ns_link("/proc/1/ns/pid")?;
    if own != init {
        return Err(StartupError::NotInitPidNs { own, init });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_uid_is_readable() {
        assert!(effective_uid().is_ok());
    }

    #[test]
    fn missing_btf_maps_to_exit_code_3() {
        assert_eq!(StartupError::NoBtf.exit_code(), 3);
        assert_eq!(StartupError::NotRoot(1000).exit_code(), 1);
    }
}
