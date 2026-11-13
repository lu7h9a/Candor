/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/* maps.h - every BPF map, with its size constant from sysscope.h (plan 4.3). */
#ifndef SYSSCOPE_MAPS_H
#define SYSSCOPE_MAPS_H

/* One ring buffer for all events; size can be changed before load (tests). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FOLLOWED_TGID_MAX);
	__type(key, __u32);
	__type(value, __u32);
} followed_tgid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FOLLOWED_CGROUP_MAX);
	__type(key, __u64);
	__type(value, __u32);
} followed_cgroup SEC(".maps");

/* Processes whose events are never recorded (the daemon itself). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, IGNORED_TGID_MAX);
	__type(key, __u32);
	__type(value, __u32);
} ignored_tgid SEC(".maps");

/* Lost-event counters by reason (DROP_*). Per-CPU, summed by the daemon. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROPS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

/* Exec path resolved at open time, keyed by thread id and file. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, EXEC_STASH_MAX);
	__type(key, struct exec_key);
	__type(value, struct exec_stash);
} exec_stash SEC(".maps");

/* Per-CPU scratch for values too large for the 512-byte BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_stash);
} scratch SEC(".maps");

#endif
