# VERIFIED.md

One row per `[VERIFY]` claim in docs/MASTER_PLAN.md.

| Claim | How checked | Result | WP |
|---|---|---|---|
| WP03: on kernels >= 6.12 KVM may hold VT-x and VirtualBox and KVM cannot run VMs at once | QEMU with `-machine q35,accel=kvm -enable-kvm` booted debian12/ubuntu2204/ubuntu2404 guests on the host while `vboxdrv` was loaded and `VBoxManage list runningvms` was empty | QEMU-KVM works with VirtualBox modules loaded and no VBox VM running. Running a VBox VM at the same time was not tested (the harness refuses to start then) | WP03 |
| WP06: `bpf_d_path` is legal at `fentry/security_file_open` | read `btf_allowlist_d_path` in kernel/trace/bpf_trace.c at tags v5.15 and v6.19 (GitHub torvalds/linux) | `security_file_open` is in the allowlist on both (under CONFIG_SECURITY). Runtime load still to be confirmed in WP04/WP06 | WP04 |
| WP04: tp_btf prototypes on the host | `bpftool btf dump file /sys/kernel/btf/vmlinux format c`, typedefs `btf_trace_*` | exec `(task_struct *, pid_t, linux_binprm *)`; fork `(task_struct *parent, task_struct *child)`; exit `(task_struct *, bool group_dead)` on 6.19 - the bool is absent on older kernels, so the program only uses the first argument | WP04 |
