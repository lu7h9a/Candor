#!/usr/bin/env bash
# `ssh localhost true` with a key made in setup. TEST VM ONLY (setup adds
# that key to ~/.ssh/authorized_keys); skipped without sshd.
source "$(dirname "$0")/_common.sh"
[ -f /etc/sysscope-test-vm ] || { echo "ssh_localhost: runs only in a SysScope test VM, skipped"; exit 0; }
if ! ss -ltn 2>/dev/null | grep -q ':22 '; then echo "ssh_localhost: no sshd listening, skipped"; exit 0; fi
if [ "$step" = setup ]; then
    rm -f key key.pub; ssh-keygen -q -t ed25519 -N '' -f key
    mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat key.pub >> ~/.ssh/authorized_keys
    exit 0
fi
ssh -i key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost true
