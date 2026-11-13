/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * sysscope.bpf.c - the single BPF object loaded by sysscoped.
 *
 * Each concern lives in its own file and is included here so that all
 * programs share one set of maps and one skeleton. Programs only observe
 * (invariant I2): no bpf_probe_write_user, bpf_override_return or
 * bpf_send_signal anywhere.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sysscope.h"

#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#include "maps.h"
#include "gate.h"
#include "lifecycle.bpf.h"
#include "file.bpf.h"
#include "net.bpf.h"
#include "sys.bpf.h"
