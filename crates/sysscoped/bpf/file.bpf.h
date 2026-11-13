/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * file.bpf.h - file events (plan D6). In WP04 this only stashes the
 * kernel-resolved path of exec-opens for the exec tracepoint; OPEN, RENAME
 * and UNLINK events are added in WP06.
 */

#ifndef __FMODE_EXEC
#define __FMODE_EXEC 0x20 /* include/uapi/asm-generic/fcntl.h */
#endif

SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	__u32 flags = BPF_CORE_READ(file, f_flags);
	if (!(flags & __FMODE_EXEC))
		return 0;

	__u32 zero = 0;
	struct exec_stash *s = bpf_map_lookup_elem(&scratch, &zero);
	if (!s) {
		count_drop(DROP_SCRATCH);
		return 0;
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
	return 0;
}
