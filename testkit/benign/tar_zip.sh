#!/usr/bin/env bash
# tar and zip a tree of 500 files, then unpack both.
source "$(dirname "$0")/_common.sh"
if [ "$step" = setup ]; then
    rm -rf tree out; mkdir -p tree
    for d in $(seq 1 10); do mkdir -p "tree/d$d"; for f in $(seq 1 50); do head -c 2048 /dev/urandom > "tree/d$d/f$f.bin"; done; done
    exit 0
fi
mkdir -p out && tar czf out/t.tgz tree && zip -qr out/t.zip tree
mkdir -p out/x1 out/x2 && tar xzf out/t.tgz -C out/x1 && unzip -q out/t.zip -d out/x2 && rm -rf out
