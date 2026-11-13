#!/usr/bin/env bash
# rsync a tree of 500 files, change 50, rsync again.
source "$(dirname "$0")/_common.sh"
if [ "$step" = setup ]; then
    rm -rf tree copy; mkdir -p tree
    for f in $(seq 1 500); do head -c 4096 /dev/urandom > "tree/f$f"; done
    exit 0
fi
rsync -a tree/ copy/ && for f in $(seq 1 50); do echo x >> "tree/f$f"; done && rsync -a --delete tree/ copy/ && rm -rf copy
