/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * ptrace.bpf.h - process access attempts (rule R011, WP28; optional).
 *
 * fentry/security_ptrace_access_check(struct task_struct *child,
 * unsigned int mode) runs for ptrace attach, /proc/<pid>/mem and
 * process_vm_readv/writev, before any LSM (Yama, AppArmor) decides, so a
 * refused attempt is still seen. Only ATTACH-mode checks are emitted:
 * READ-mode checks happen on every /proc read by ps and would flood.
 */

#ifndef PTRACE_MODE_ATTACH
#define PTRACE_MODE_ATTACH 0x02
#endif

SEC("fentry/security_ptrace_access_check")
int BPF_PROG(on_ptrace_check, struct task_struct *child, unsigned int mode)
{
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	if (is_kthread())
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 target = BPF_CORE_READ(child, tgid);
	if (target == tgid)
		return 0; /* a process looking at itself */
	if (!gate_emit(tgid))
		return 0;
	struct ev_ptrace *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_rb_drop(tgid);
		return 0;
	}
	fill_hdr(&e->h, bpf_get_current_task_btf(), EV_PTRACE);
	e->target_start_boot_ns = BPF_CORE_READ(child, group_leader, start_boottime);
	e->target_tgid = target;
	e->mode = mode;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
