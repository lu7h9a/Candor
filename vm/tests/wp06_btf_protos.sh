#!/usr/bin/env bash
# Prints the guest kernel's prototypes of the hooked kernel functions, so the
# fentry argument lists can be compared with the host's (SKILL.md 7).
set -eu  # no pipefail: awk stops reading early on purpose
if ! command -v bpftool >/dev/null; then
    (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpftool) >/dev/null 2>&1 || true
    # Ubuntu ships bpftool in linux-tools for the running kernel.
    command -v bpftool >/dev/null || ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1 | xargs -r -I{} ln -sf {} /usr/local/bin/bpftool
    command -v bpftool >/dev/null || (DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "linux-tools-$(uname -r)" >/dev/null 2>&1 && ln -sf "$(ls /usr/lib/linux-tools/*/bpftool | head -1)" /usr/local/bin/bpftool) || true
fi
command -v bpftool >/dev/null || { echo "bpftool not available in this guest"; exit 0; }
echo "kernel $(uname -r)"
for f in security_file_open security_inode_rename security_inode_unlink security_socket_connect security_socket_listen; do
    id=$(bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -E "FUNC '$f'" | sed -E 's/.*type_id=([0-9]+).*/\1/')
    printf '%s:' "$f"
    bpftool btf dump file /sys/kernel/btf/vmlinux format raw | awk -v id="[$id]" '$1==id{p=1;next} p&&/^\t/{printf " %s", $1;next} p{exit}'
    echo
done
