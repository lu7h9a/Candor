/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * file.bpf.h - file events (plan D6, WP06).
 *
 * OPEN: fentry/security_file_open sees the kernel-resolved file, so the
 * path comes from bpf_d_path (no user-memory race, relative paths and
 * symlinks already resolved). Exec-opens (__FMODE_EXEC: the binary, its
 * interpreter, ld.so) are not emitted as OPEN; they feed the exec-path stash
 * and are represented by the EXEC event.
 * RENAME/UNLINK: fentry/security_inode_{rename,unlink} have only dentries,
 * so the path is a bounded walk of d_parent (DENTRY_WALK_MAX components).
 * Kernel threads (no mm) are skipped.
 */

#ifndef __FMODE_EXEC
#define __FMODE_EXEC 0x20 /* include/uapi/asm-generic/fcntl.h */
#endif

static __always_inline int is_kthread(void)
{
	struct task_struct *t = bpf_get_current_task_btf();
	return t->mm == NULL;
}

static __always_inline void stash_exec_path(struct file *file)
{
	__u32 zero = 0;
	struct exec_stash *s = bpf_map_lookup_elem(&scratch, &zero);
	if (!s) {
		count_drop(DROP_SCRATCH);
		return;
	}
	s->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
	s->ino = BPF_CORE_READ(file, f_inode, i_ino);
	s->flags = 0;
	long n = bpf_d_path(&file->f_path, s->path, PATH_CAP);
	if (n > 0) {
		s->path_len = n - 1; /* bpf_d_path counts the NUL */
	} else {
		/* Too long or unresolvable: keep the leaf name, flag truncation. */
		const unsigned char *leaf = BPF_CORE_READ(file, f_path.dentry, d_name.name);
		long m = bpf_probe_read_kernel_str(s->path, PATH_CAP, leaf);
		s->path_len = m > 0 ? m - 1 : 0;
		s->flags = F_PATH_TRUNCATED;
	}
	struct exec_key k = {
		.dev = s->dev,
		.ino = s->ino,
		.tid = (__u32)bpf_get_current_pid_tgid(),
		._pad = 0,
	};
	bpf_map_update_elem(&exec_stash, &k, s, BPF_ANY);
}

SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	__u32 flags = BPF_CORE_READ(file, f_flags);
	if (flags & __FMODE_EXEC) {
		stash_exec_path(file);
		return 0;
	}
	if (is_kthread())
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!gate_pass(tgid))
		return 0;
	struct ev_open *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF);
		return 0;
	}
	fill_hdr(&e->h, bpf_get_current_task_btf(), EV_OPEN);
	e->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
	e->ino = BPF_CORE_READ(file, f_inode, i_ino);
	e->f_flags = flags;
	e->f_mode = BPF_CORE_READ(file, f_mode);
	e->_pad[0] = e->_pad[1] = e->_pad[2] = 0;
	long n = bpf_d_path(&file->f_path, e->path, PATH_CAP);
	if (n > 0) {
		e->path_len = n - 1;
	} else {
		const unsigned char *leaf = BPF_CORE_READ(file, f_path.dentry, d_name.name);
		long m = bpf_probe_read_kernel_str(e->path, PATH_CAP, leaf);
		e->path_len = m > 0 ? m - 1 : 0;
		e->h.flags |= F_PATH_TRUNCATED;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Writes the components of `d` and its parents into buf, leaf first, each
 * followed by NUL. Returns the bytes used; sets *trunc if the walk stopped
 * early (too many components or the buffer was full).
 */
static __always_inline __u32 dentry_walk(struct dentry *d, char *buf, int *trunc)
{
	__u32 off = 0;
	*trunc = 0;
	for (int i = 0; i < DENTRY_WALK_MAX; i++) {
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (!parent || parent == d)
			return off; /* reached the filesystem root */
		if (off >= PATH_CAP) {
			*trunc = 1;
			return off;
		}
		const unsigned char *name = BPF_CORE_READ(d, d_name.name);
		long n = bpf_probe_read_kernel_str(&buf[off & (PATH_CAP - 1)], NAME_CHUNK, name);
		if (n <= 0) {
			*trunc = 1;
			return off;
		}
		off += n;
		d = parent;
	}
	/* Loop ended without reaching the root. */
	struct dentry *parent = BPF_CORE_READ(d, d_parent);
	if (parent && parent != d)
		*trunc = 1;
	return off;
}

SEC("fentry/security_inode_rename")
int BPF_PROG(on_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	if (is_kthread())
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!gate_pass(tgid))
		return 0;
	struct ev_rename *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF);
		return 0;
	}
	fill_hdr(&e->h, bpf_get_current_task_btf(), EV_RENAME);
	e->dev = BPF_CORE_READ(old_dentry, d_inode, i_sb, s_dev);
	e->ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
	e->_pad = 0;
	int t1 = 0, t2 = 0;
	e->old_len = dentry_walk(old_dentry, e->old_walk, &t1);
	e->new_len = dentry_walk(new_dentry, e->new_walk, &t2);
	if (t1 || t2)
		e->h.flags |= F_PATH_TRUNCATED;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/security_inode_unlink")
int BPF_PROG(on_unlink, struct inode *dir, struct dentry *dentry)
{
	if (is_kthread())
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!gate_pass(tgid))
		return 0;
	struct ev_unlink *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF);
		return 0;
	}
	fill_hdr(&e->h, bpf_get_current_task_btf(), EV_UNLINK);
	e->dev = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);
	e->ino = BPF_CORE_READ(dentry, d_inode, i_ino);
	e->_pad[0] = e->_pad[1] = e->_pad[2] = 0;
	int t = 0;
	e->walk_len = dentry_walk(dentry, e->walk, &t);
	if (t)
		e->h.flags |= F_PATH_TRUNCATED;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
