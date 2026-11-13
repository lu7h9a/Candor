/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * net.bpf.h - network events (plan D7, WP07).
 *
 * CONNECT: fentry/security_socket_connect runs in the caller's context
 * with the address already copied into kernel memory, for every family and
 * also for non-blocking connects. The address parameter is declared as
 * void * because its type name differs between kernels; it is read as raw
 * bytes, bounded by min(addrlen, SOCKADDR_CAP).
 * LISTEN (optional): fentry/security_socket_listen reads the bound address
 * from the socket. Inbound accepts and unconnected UDP sends are not seen.
 */

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

SEC("fentry/security_socket_connect")
int BPF_PROG(on_connect, struct socket *sock, void *address, int addrlen)
{
	if (is_kthread())
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!gate_pass(tgid))
		return 0;
	struct ev_connect *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF);
		return 0;
	}
	fill_hdr(&e->h, bpf_get_current_task_btf(), EV_CONNECT);
	e->sock_type = BPF_CORE_READ(sock, type);
	e->_pad = 0;
	/* Constant-size copy: the verifier cannot always see a bound on a
	 * computed length after clang optimises it. The syscall path keeps the
	 * address in a 128-byte sockaddr_storage; only addrlen bytes are used. */
	if (bpf_probe_read_kernel(e->addr, SOCKADDR_CAP, address) == 0)
		e->addrlen = addrlen < 0 ? 0 : (addrlen > SOCKADDR_CAP ? SOCKADDR_CAP : addrlen);
	else
		e->addrlen = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/security_socket_listen")
int BPF_PROG(on_listen, struct socket *sock, int backlog)
{
	if (is_kthread())
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!gate_pass(tgid))
		return 0;
	struct ev_listen *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(DROP_RINGBUF);
		return 0;
	}
	fill_hdr(&e->h, bpf_get_current_task_btf(), EV_LISTEN);
	struct sock *sk = BPF_CORE_READ(sock, sk);
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->family = family;
	e->port = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->_pad = 0;
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	if (family == AF_INET) {
		__u32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(e->addr, &a, 4);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&e->addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}
