/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * lifecycle.bpf.h - EXEC, FORK and EXIT (plan 4.3, WP04).
 *
 * Exec path: bpf_d_path is not allowed in tp_btf programs, so the open hook
 * (fentry/security_file_open, which is on the d_path allowlist) stashes the
 * resolved path of every exec-open (__FMODE_EXEC) keyed by (thread id,
 * dev, ino); one exec opens the binary, ld.so and maybe a script
 * interpreter. The exec tracepoint looks up (old_pid, bprm->file's dev and
 * ino). If there is no entry it falls back to bprm->filename
 * (F_PATH_FROM_ARG).
 *
 * Exit: sched_process_exit fires per thread. EXIT is emitted only when the
 * last thread of the group exits (signal->live == 0), which is the moment
 * the process is gone. A leader exiting before its threads emits nothing.
 */

static __always_inline __u64 file_dev(struct file *f)
{
	return BPF_CORE_READ(f, f_inode, i_sb, s_dev);
}

static __always_inline __u64 file_ino(struct file *f)
{
	return BPF_CORE_READ(f, f_inode, i_ino);
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct file *f = BPF_CORE_READ(bprm, file);
	struct exec_key k = {
		.dev = file_dev(f),
		.ino = file_ino(f),
		.tid = (__u32)old_pid,
		._pad = 0,
	};

	if (!gate_emit(tgid)) {
		bpf_map_delete_elem(&exec_stash, &k);
		return 0;
	}
	struct ev_exec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_rb_drop(tgid);
		bpf_map_delete_elem(&exec_stash, &k);
		return 0;
	}
	fill_hdr(&e->h, p, EV_EXEC);
	e->dev = k.dev;
	e->ino = k.ino;
	if (BPF_CORE_READ(f, f_inode, __i_nlink) == 0)
		e->h.flags |= F_FILELESS;

	struct task_struct *parent = BPF_CORE_READ(p, real_parent);
	e->parent_tgid = BPF_CORE_READ(parent, tgid);
	e->parent_start_boot_ns = leader_start(parent);

	/* Path: stashed kernel-resolved path if it is for this very file. */
	struct exec_stash *s = bpf_map_lookup_elem(&exec_stash, &k);
	e->path_len = 0;
	if (s) {
		__u32 n = s->path_len;
		if (n > PATH_CAP)
			n = PATH_CAP;
		bpf_probe_read_kernel(e->path, n & (2 * PATH_CAP - 1), s->path);
		e->path_len = n;
		e->h.flags |= (__u16)(s->flags & F_PATH_TRUNCATED);
	} else {
		const char *fname = BPF_CORE_READ(bprm, filename);
		long n = bpf_probe_read_kernel_str(e->path, PATH_CAP, fname);
		if (n > 0) {
			e->path_len = n - 1; /* drop the NUL */
			if (n == PATH_CAP)
				e->h.flags |= F_PATH_TRUNCATED;
		}
		e->h.flags |= F_PATH_FROM_ARG;
	}
	bpf_map_delete_elem(&exec_stash, &k);

	/* argv: first ARGV_CAP bytes of the new image's argument area. */
	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	unsigned long a0 = BPF_CORE_READ(mm, arg_start);
	unsigned long a1 = BPF_CORE_READ(mm, arg_end);
	__u64 alen = a1 > a0 ? a1 - a0 : 0;
	e->argv_len = 0;
	if (alen > ARGV_CAP) {
		alen = ARGV_CAP;
		e->h.flags |= F_ARGV_TRUNCATED;
	}
	if (alen > 0 && bpf_probe_read_user(e->argv, alen & (2 * ARGV_CAP - 1), (void *)a0) == 0)
		e->argv_len = alen;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 child_pid = BPF_CORE_READ(child, pid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);
	if (child_pid != child_tgid)
		return 0; /* a new thread, not a new process */

	/* Follow inheritance (D9) happens at fork time, keyed on the parent's
	 * tgid (not the forking thread), before any gate, so a daemonising
	 * double fork stays followed. */
	__u32 tgid = BPF_CORE_READ(parent, tgid);
	__u32 *fid = bpf_map_lookup_elem(&followed_tgid, &tgid);
	if (fid) {
		__u32 id = *fid;
		bpf_map_update_elem(&followed_tgid, &child_tgid, &id, BPF_ANY);
	}
	if (!gate_emit(tgid))
		return 0;
	struct ev_fork *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_rb_drop(tgid);
		return 0;
	}
	fill_hdr(&e->h, parent, EV_FORK);
	e->child_tgid = child_tgid;
	e->child_start_boot_ns = BPF_CORE_READ(child, start_boottime);
	e->_pad = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	/* Only the last thread of the group means "process gone". */
	if (BPF_CORE_READ(p, signal, live.counter) != 0)
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!gate_emit(tgid)) {
		bpf_map_delete_elem(&followed_tgid, &tgid);
		return 0;
	}
	struct ev_exit *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_rb_drop(tgid);
		bpf_map_delete_elem(&followed_tgid, &tgid);
		return 0;
	}
	fill_hdr(&e->h, p, EV_EXIT);
	e->exit_code = BPF_CORE_READ(p, exit_code);
	e->_pad = 0;
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&followed_tgid, &tgid);
	return 0;
}
