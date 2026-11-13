#!/usr/bin/env bash
# Installs strace inside the throw-away guest (needed by the WP12 itest).
set -eu
command -v strace >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq strace >/dev/null; }
strace -V | head -1
