/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * sysscope.h - ABI shared between the BPF programs and the daemon (abi.rs).
 *
 * Every struct that crosses into Rust has a _Static_assert on its size here
 * and a matching const assertion in crates/sysscoped/src/abi.rs. All
 * integers are little-endian native x86_64. Constants (map sizes, caps) live
 * only in this file on the kernel side (SKILL.md section 5).
 */
#ifndef SYSSCOPE_H
#define SYSSCOPE_H

/* Caps (plan 4.3). */
#define PATH_CAP 512
#define ARGV_CAP 256
#define DENTRY_WALK_MAX 16

/* Map sizes (plan 4.3). */
#define RINGBUF_BYTES (8 * 1024 * 1024)
#define FOLLOWED_TGID_MAX 16384
#define FOLLOWED_CGROUP_MAX 64
#define IGNORED_TGID_MAX 16
#define BUDGET_MAX 16384
#define DROPS_MAX 8
#define EXEC_STASH_MAX 4096

/* Event kinds. */
#define EV_EXEC 1
#define EV_FORK 2
#define EV_EXIT 3
#define EV_OPEN 4
#define EV_RENAME 5
#define EV_UNLINK 6
#define EV_CONNECT 7
#define EV_LISTEN 8

/* Header flags. */
#define F_PATH_TRUNCATED (1 << 0)
#define F_ARGV_TRUNCATED (1 << 1)
#define F_FILELESS (1 << 2)
#define F_KTHREAD (1 << 3)
/* Exec path could not be resolved by the kernel; it is the execve() argument. */
#define F_PATH_FROM_ARG (1 << 4)

/* Indexes into the `drops` per-CPU array. */
#define DROP_RINGBUF 0
#define DROP_BUDGET 1
#define DROP_SCRATCH 2

/* cfg.mode values. */
#define MODE_SYSTEM 0
#define MODE_FOLLOW 1

struct cfg {
	__u32 mode;
	__u32 budget_rate;  /* events per second per tgid */
	__u32 budget_burst; /* bucket size */
	__u32 flags;
};
_Static_assert(sizeof(struct cfg) == 16, "cfg size");

struct ev_hdr {
	__u64 ts_boot_ns;    /* bpf_ktime_get_boot_ns() */
	__u64 start_boot_ns; /* group leader start_boottime */
	__u32 tgid;
	__u32 pid; /* thread id */
	__u32 uid;
	__u16 kind;
	__u16 flags;
};
_Static_assert(sizeof(struct ev_hdr) == 32, "ev_hdr size");

struct ev_exec {
	struct ev_hdr h;
	__u64 dev; /* kernel dev_t of the executable's superblock */
	__u64 ino;
	__u64 parent_start_boot_ns;
	__u32 parent_tgid;
	__u16 path_len; /* bytes used in path, no NUL */
	__u16 argv_len; /* bytes used in argv, NUL separated */
	char path[PATH_CAP];
	char argv[ARGV_CAP];
};
_Static_assert(sizeof(struct ev_exec) == 64 + PATH_CAP + ARGV_CAP, "ev_exec size");

struct ev_fork {
	struct ev_hdr h;
	__u64 child_start_boot_ns;
	__u32 child_tgid;
	__u32 _pad;
};
_Static_assert(sizeof(struct ev_fork) == 48, "ev_fork size");

struct ev_exit {
	struct ev_hdr h;
	__s32 exit_code;
	__u32 _pad;
};
_Static_assert(sizeof(struct ev_exit) == 40, "ev_exit size");

/* Key of exec_stash: the exec'ing thread and the opened file. Exec opens
 * several files (the binary, a script interpreter, ld.so); the exec
 * tracepoint looks up exactly the one that became bprm->file. */
struct exec_key {
	__u64 dev;
	__u64 ino;
	__u32 tid;
	__u32 _pad;
};
_Static_assert(sizeof(struct exec_key) == 24, "exec_key size");

/* Exec path stashed by the open hook for the thread that is exec'ing. */
struct exec_stash {
	__u64 dev;
	__u64 ino;
	__u32 path_len;
	__u32 flags;
	char path[PATH_CAP];
};
_Static_assert(sizeof(struct exec_stash) == 24 + PATH_CAP, "exec_stash size");

#endif /* SYSSCOPE_H */
