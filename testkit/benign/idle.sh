#!/usr/bin/env bash
# Idle desktop: nothing but the time (default 30 minutes; FP_IDLE_S overrides).
source "$(dirname "$0")/_common.sh"
[ "$step" = setup ] && exit 0
sleep "${FP_IDLE_S:-1800}"
