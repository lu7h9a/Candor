/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * gate.h - the cheap check at the top of every program (plan 4.3):
 * (1) skip ignored tgids, (2) in follow mode skip anything not followed.
 * The per-tgid budget (step 3) is added in WP09.
 */
#ifndef SYSSCOPE_GATE_H
#define SYSSCOPE_GATE_H

static __always_inline void count_drop(__u32 reason)
{
	__u64 *c = bpf_map_lookup_elem(&drops, &reason);
	if (c)
		__sync_fetch_and_add(c, 1);
}

static __always_inline struct cfg *get_cfg(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&cfg, &zero);
}

/* Returns 1 if events of the current task should be recorded. */
static __always_inline int gate_pass(__u32 tgid)
{
	if (bpf_map_lookup_elem(&ignored_tgid, &tgid))
		return 0;
	struct cfg *c = get_cfg();
	if (c && c->mode == MODE_FOLLOW) {
		if (bpf_map_lookup_elem(&followed_tgid, &tgid))
			return 1;
		__u64 cg = bpf_get_current_cgroup_id();
		if (bpf_map_lookup_elem(&followed_cgroup, &cg))
			return 1;
		return 0;
	}
	return 1;
}

/* Start time of the thread group leader, the start half of a ProcKey. */
static __always_inline __u64 leader_start(struct task_struct *t)
{
	return BPF_CORE_READ(t, group_leader, start_boottime);
}

static __always_inline void fill_hdr(struct ev_hdr *h, struct task_struct *t, __u16 kind)
{
	__u64 id = bpf_get_current_pid_tgid();
	h->ts_boot_ns = bpf_ktime_get_boot_ns();
	h->start_boot_ns = leader_start(t);
	h->tgid = id >> 32;
	h->pid = (__u32)id;
	h->uid = (__u32)bpf_get_current_uid_gid();
	h->kind = kind;
	h->flags = (BPF_CORE_READ(t, flags) & PF_KTHREAD) ? F_KTHREAD : 0;
}

#endif
