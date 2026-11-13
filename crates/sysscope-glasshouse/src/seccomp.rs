//! The Glasshouse seccomp filters (plan 6.2), compiled with `seccompiler`.
//!
//! Default allow; high-risk syscalls return EPERM; `clone` with any
//! CLONE_NEW* flag returns EPERM; `clone3` returns ENOSYS so libc falls back
//! to `clone`; `personality` other than 0 / 0xffffffff returns EPERM;
//! syscalls of other architectures (i386 via the arch check, x32 via the
//! 0x40000000 bit) kill the process. Each action needs its own filter, so
//! there are three programs; bubblewrap stacks them with --add-seccomp-fd.
//! A program file is the raw array of `struct sock_filter` (8 bytes each).

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

/// Why a filter could not be built.
#[derive(Debug, thiserror::Error)]
#[error("building the seccomp filter: {0}")]
pub struct SeccompError(String);

/// Syscalls that always return EPERM inside the box.
const DENIED: &[i64] = &[
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_acct,
    libc::SYS_quotactl,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_modify_ldt,
    libc::SYS_vhangup,
    libc::SYS_syslog,
    libc::SYS_lookup_dcookie,
    libc::SYS_kcmp,
];

/// CLONE_NEW* flags refused for `clone`.
const CLONE_NEW: &[u64] = &[
    libc::CLONE_NEWNS as u64,
    libc::CLONE_NEWCGROUP as u64,
    libc::CLONE_NEWUTS as u64,
    libc::CLONE_NEWIPC as u64,
    libc::CLONE_NEWUSER as u64,
    libc::CLONE_NEWPID as u64,
    libc::CLONE_NEWNET as u64,
];

fn err<E: std::fmt::Display>(e: E) -> SeccompError {
    SeccompError(e.to_string())
}

fn cond(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, SeccompError> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Qword, op, value).map_err(err)
}

/// Filter 1: everything that returns EPERM.
pub fn eperm_program() -> Result<BpfProgram, SeccompError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in DENIED {
        rules.insert(*nr, Vec::new()); // empty rule list = always matches
    }
    // clone: one rule per namespace flag (rules of a syscall are ORed).
    let mut clone_rules = Vec::new();
    for flag in CLONE_NEW {
        clone_rules.push(
            SeccompRule::new(vec![cond(0, SeccompCmpOp::MaskedEq(*flag), *flag)?]).map_err(err)?,
        );
    }
    rules.insert(libc::SYS_clone, clone_rules);
    // personality: anything but 0 and 0xffffffff (conditions are ANDed).
    rules.insert(
        libc::SYS_personality,
        vec![
            SeccompRule::new(vec![
                cond(0, SeccompCmpOp::Ne, 0)?,
                cond(0, SeccompCmpOp::Ne, 0xffff_ffff)?,
            ])
            .map_err(err)?,
        ],
    );
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        TargetArch::x86_64,
    )
    .map_err(err)?;
    BpfProgram::try_from(filter).map_err(err)
}

/// Filter 2: clone3 returns ENOSYS (libc then uses clone, which filter 1 checks).
pub fn enosys_program() -> Result<BpfProgram, SeccompError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_clone3, Vec::new());
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        TargetArch::x86_64,
    )
    .map_err(err)?;
    BpfProgram::try_from(filter).map_err(err)
}

/// Filter 3 (hand-built): kill the process on any x32-ABI syscall number.
pub fn x32_program() -> BpfProgram {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const X32_BIT: u32 = 0x4000_0000;
    vec![
        seccompiler::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        }, // seccomp_data.nr
        seccompiler::sock_filter {
            code: BPF_JGE_K,
            jt: 0,
            jf: 1,
            k: X32_BIT,
        },
        seccompiler::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        seccompiler::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ]
}

/// The raw bytes bubblewrap reads from a seccomp fd.
pub fn to_bytes(p: &BpfProgram) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len() * 8);
    for ins in p {
        out.extend_from_slice(&ins.code.to_le_bytes());
        out.push(ins.jt);
        out.push(ins.jf);
        out.extend_from_slice(&ins.k.to_le_bytes());
    }
    out
}

/// All three programs, in the order they are stacked.
pub fn all_programs() -> Result<Vec<BpfProgram>, SeccompError> {
    Ok(vec![eperm_program()?, enosys_program()?, x32_program()])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Applies the filters in a fresh thread and runs `f` there.
    fn in_filtered_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(move || {
            rustix::thread::set_no_new_privs(true).unwrap();
            for p in all_programs().unwrap() {
                seccompiler::apply_filter(&p).unwrap();
            }
            f()
        })
        .join()
        .unwrap()
    }

    #[test]
    fn programs_serialize_to_eight_bytes_per_instruction() {
        for p in all_programs().unwrap() {
            assert!(!p.is_empty());
            assert_eq!(to_bytes(&p).len(), p.len() * 8);
        }
    }

    #[test]
    fn namespaces_refused_and_clone3_falls_back() {
        // Without the filter, unprivileged user namespaces work on this host.
        assert!(
            std::process::Command::new("unshare")
                .args(["-U", "true"])
                .status()
                .unwrap()
                .success()
        );
        let (ns, plain) = in_filtered_thread(|| {
            // Children inherit the thread's filter. Spawning at all needs the
            // clone3 -> ENOSYS -> clone fallback to work.
            let ns = std::process::Command::new("unshare")
                .args(["-U", "true"])
                .status()
                .unwrap();
            let plain = std::process::Command::new("true").status().unwrap();
            (ns.success(), plain.success())
        });
        assert!(!ns, "unshare(CLONE_NEWUSER) must be refused");
        assert!(plain, "ordinary process creation must still work");
    }

    #[test]
    fn ordinary_syscalls_still_work() {
        let pid = in_filtered_thread(|| {
            let _ = std::fs::read("/proc/self/status").unwrap();
            rustix::process::getpid().as_raw_nonzero().get()
        });
        assert!(pid > 0);
    }
}
