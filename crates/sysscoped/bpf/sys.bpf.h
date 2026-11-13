/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * sys.bpf.h - syscall statistics (plan D8, WP08). Optional programs.
 *
 * raw_tp/sys_enter counts every syscall per (tgid, nr) in a per-CPU map;
 * no ring-buffer output ever comes from here (this is the hottest path).
 * The first instructions are the cheap gate. Latency (enter -> exit) is
 * measured only in follow mode, for followed processes. execve/exit have no
 * matching sys_exit; their sys_start entries age out of the LRU map.
 */

SEC("raw_tp/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long id)
{
	struct cfg *c = get_cfg();
	if (!c || !(c->flags & CFG_SYSCALLS_COUNT) || id < 0)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (!gate_pass(tgid))
		return 0;
	struct sys_key k = {
		.tgid = tgid, .nr = (__u32)id, .start_ticks = current_start_ns() / NS_PER_TICK};
	__u64 *n = bpf_map_lookup_elem(&sys_count, &k);
	if (n) {
		*n += 1; /* per-CPU value: no atomic needed */
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&sys_count, &k, &one, BPF_NOEXIST);
	}
	if (c->mode == MODE_FOLLOW) {
		__u64 now = bpf_ktime_get_boot_ns();
		bpf_map_update_elem(&sys_start, &pid_tgid, &now, BPF_ANY);
	}
	return 0;
}

SEC("raw_tp/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret)
{
	struct cfg *c = get_cfg();
	if (!c || c->mode != MODE_FOLLOW)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *start = bpf_map_lookup_elem(&sys_start, &pid_tgid);
	if (!start)
		return 0;
	__u64 delta = bpf_ktime_get_boot_ns() - *start;
	bpf_map_delete_elem(&sys_start, &pid_tgid);
	/* The syscall number is in orig_ax on x86_64. */
	long id = BPF_CORE_READ(regs, orig_ax);
	if (id < 0)
		return 0;
	struct sys_key k = {.tgid = pid_tgid >> 32,
			    .nr = (__u32)id,
			    .start_ticks = current_start_ns() / NS_PER_TICK};
	struct sys_lat_val *v = bpf_map_lookup_elem(&sys_lat, &k);
	if (!v) {
		struct sys_lat_val init = {.count = 0, .total_ns = 0, .max_ns = 0};
		bpf_map_update_elem(&sys_lat, &k, &init, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&sys_lat, &k);
		if (!v)
			return 0;
	}
	__sync_fetch_and_add(&v->count, 1);
	__sync_fetch_and_add(&v->total_ns, delta);
	if (delta > v->max_ns)
		v->max_ns =
			delta; /* racy max across CPUs: may miss a larger value, never corrupts */
	return 0;
}
