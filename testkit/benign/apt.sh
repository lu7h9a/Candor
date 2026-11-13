#!/usr/bin/env bash
# apt-get update + install + remove of one small package. TEST VM ONLY.
source "$(dirname "$0")/_common.sh"
[ -f /etc/sysscope-test-vm ] || { echo "apt.sh: runs only in a SysScope test VM, skipped"; exit 0; }
[ "$step" = setup ] && exit 0
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update && apt-get -qq install -y hello > /dev/null && hello > /dev/null && apt-get -qq remove -y hello > /dev/null
