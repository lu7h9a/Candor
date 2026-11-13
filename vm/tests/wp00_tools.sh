#!/usr/bin/env bash
# Installs test tools (strace) inside the throw-away guest; runs first.
# Uses the distro package manager: apt, dnf or pacman.
set -eu
if ! command -v strace >/dev/null || ! command -v bwrap >/dev/null; then
    if command -v apt-get >/dev/null; then
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq strace bubblewrap >/dev/null
    elif command -v dnf >/dev/null; then
        dnf install -y -q strace python3 bubblewrap >/dev/null
    elif command -v pacman >/dev/null; then
        pacman -Sy --noconfirm --needed strace python bubblewrap >/dev/null
    fi
fi
strace -V | head -1
bwrap --version
