/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * gate.h - the cheap check at the top of every program (plan 4.3):
 * (1) skip ignored tgids, (2) in follow mode skip anything not followed,
 * (3) for event-emitting programs take one token from the tgid's budget.
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

/* Start time of the current process (group leader), boot ns. */
static __always_inline __u64 current_start_ns(void)
{
	struct task_struct *t = bpf_get_current_task_btf();
	return t->group_leader->start_boottime;
}

/* Returns 1 if events of the current task should be recorded (`c` is the
 * cfg, possibly NULL). In follow mode the followed set is checked first: an
 * unrelated process costs one hash miss, plus the cgroup lookup only while
 * a Glasshouse box is registered (CFG_HAS_CGROUPS). WP14 lever "move gates
 * earlier". */
static __always_inline int gate_pass_cfg(struct cfg *c, __u32 tgid)
{
	if (c && c->mode == MODE_FOLLOW) {
		struct follow_val *fv = bpf_map_lookup_elem(&followed_tgid, &tgid);
		/* Same tgid AND same start time: a recycled pid is not followed. */
		int in = fv && fv->start_ticks == current_start_ns() / NS_PER_TICK;
		if (!in && (c->flags & CFG_HAS_CGROUPS)) {
			__u64 cg = bpf_get_current_cgroup_id();
			in = bpf_map_lookup_elem(&followed_cgroup, &cg) != NULL;
		}
		if (!in)
			return 0;
	}
	return bpf_map_lookup_elem(&ignored_tgid, &tgid) == NULL;
}

static __always_inline int gate_pass(__u32 tgid)
{
	return gate_pass_cfg(get_cfg(), tgid);
}

/* Takes one token from tgid's bucket (refilled at cfg budget_rate per
 * second up to budget_burst). Returns 1 if the event may be emitted. On
 * refusal the drop is counted per process and in drops[DROP_BUDGET]. */
static __always_inline int take_token(__u32 tgid)
{
	struct cfg *c = get_cfg();
	if (!c || c->budget_rate == 0)
		return 1; /* budget disabled */
	__u64 now = bpf_ktime_get_boot_ns();
	struct proc_key pk = {.tgid = tgid, ._pad = 0, .start_boot_ns = current_start_ns()};
	struct budget *b = bpf_map_lookup_elem(&budget, &pk);
	if (!b) {
		struct budget init = {.tokens = c->budget_burst,
				      .last_refill_ns = now,
				      .dropped = 0,
				      .rb_dropped = 0};
		bpf_map_update_elem(&budget, &pk, &init, BPF_NOEXIST);
		b = bpf_map_lookup_elem(&budget, &pk);
		if (!b)
			return 1; /* map full and LRU could not evict: do not lose silently */
	}
	/* Refill. Elapsed time is capped at the time to fill the bucket, so the
	 * multiplication cannot overflow. Fractions of a token carry over by only
	 * advancing last_refill_ns by the time the added tokens represent. */
	__u64 last = b->last_refill_ns;
	if (now > last) {
		__u64 elapsed = now - last;
		__u64 cap_ns = (__u64)c->budget_burst * 1000000000ULL / c->budget_rate + 1;
		if (elapsed > cap_ns)
			elapsed = cap_ns;
		__u64 add = elapsed * c->budget_rate / 1000000000ULL;
		if (add > 0) {
			__u64 t = b->tokens + add;
			if (t > c->budget_burst)
				t = c->budget_burst;
			b->tokens = t; /* plain store: a lost update only loses tokens */
			b->last_refill_ns = (elapsed == cap_ns)
						    ? now
						    : last + add * 1000000000ULL / c->budget_rate;
		}
	}
	__u64 old = b->tokens;
	if (old == 0) {
		__sync_fetch_and_add(&b->dropped, 1);
		count_drop(DROP_BUDGET);
		return 0;
	}
	/* Never below zero: only decrement if nobody changed it meanwhile; if the
	 * swap fails, emit anyway (a lost update, never a negative count). */
	__sync_val_compare_and_swap(&b->tokens, old, old - 1);
	return 1;
}

/* Counts a ring-buffer-full loss for tgid (per process and globally). The
 * per-process entry is created here if the process has none yet: EXEC and
 * EXIT take no budget token, so an EXEC lost to a full ring can be a
 * process's first event; without the entry that drop was counted only
 * globally (found by the exact identity test, WP31; I3). */
static __always_inline void count_rb_drop(__u32 tgid)
{
	count_drop(DROP_RINGBUF);
	struct proc_key pk = {.tgid = tgid, ._pad = 0, .start_boot_ns = current_start_ns()};
	struct budget *b = bpf_map_lookup_elem(&budget, &pk);
	if (!b) {
		struct cfg *c = get_cfg();
		struct budget init = {.tokens = c ? c->budget_burst : 0,
				      .last_refill_ns = bpf_ktime_get_boot_ns(),
				      .dropped = 0,
				      .rb_dropped = 0};
		bpf_map_update_elem(&budget, &pk, &init, BPF_NOEXIST);
		b = bpf_map_lookup_elem(&budget, &pk);
	}
	if (b)
		__sync_fetch_and_add(&b->rb_dropped, 1);
}

/* Gate for programs that emit an event: steps (1), (2) and (3). */
static __always_inline int gate_emit(__u32 tgid)
{
	return gate_pass(tgid) && take_token(tgid);
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
