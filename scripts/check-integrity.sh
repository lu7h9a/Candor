#!/usr/bin/env bash
# check-integrity.sh - guards against the two ways an autonomous builder can
# quietly lower the bar (docs/MASTER_PLAN.md WP01, risk 2):
#   1. a test marked #[ignore] (or cfg_attr(..., ignore)) anywhere in the repo;
#   2. a change to a threshold file without a new line under
#      "## Deviations from the plan" in docs/DEVIATIONS.md (tracked) in the
#      same range. PROGRESS.md is the builder's local log and not tracked
#      (owner, 2026-11-14), so it cannot serve as the record.
# Usage: scripts/check-integrity.sh [<base-commit>]
#   Compares <base-commit> with the working tree. Default base: HEAD~1
#   (or the empty tree when the repository has a single commit).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

# --- 1. ignored tests -------------------------------------------------------
ignored=$(grep -rnE '#\[(cfg_attr\([^]]*)?ignore' --include='*.rs' . \
    --exclude-dir=target --exclude-dir=.git || true)
if [ -n "$ignored" ]; then
    echo "integrity: ignored tests are not allowed:"
    echo "$ignored"
    fail=1
fi

# --- 2. threshold changes need a Deviations entry ---------------------------
THRESHOLD_FILES=(
    crates/candor-core/src/limits.rs
    crates/candor-core/rules.toml
    bench/thresholds.toml
)
empty_tree=$(git hash-object -t tree /dev/null)
base="${1:-}"
if [ -z "$base" ]; then
    if git rev-parse -q --verify HEAD~1 >/dev/null; then base=HEAD~1; else base=$empty_tree; fi
fi

DEVIATIONS=docs/DEVIATIONS.md
deviations_section() { # prints the Deviations section of DEVIATIONS from stdin
    awk '/^## Deviations from the plan/{on=1; next} /^## /{on=0} on'
}

changed_thresholds=()
for f in "${THRESHOLD_FILES[@]}"; do
    # Only modifications count; creating the file is not a change of a threshold.
    if git cat-file -e "$base:$f" 2>/dev/null && [ -e "$f" ]; then
        if ! git diff --quiet "$base" -- "$f"; then changed_thresholds+=("$f"); fi
    elif git cat-file -e "$base:$f" 2>/dev/null; then
        changed_thresholds+=("$f (deleted)")
    fi
done

if [ ${#changed_thresholds[@]} -gt 0 ]; then
    old=$(git show "$base:$DEVIATIONS" 2>/dev/null | deviations_section | sort -u || true)
    new=$(deviations_section < "$DEVIATIONS" | sort -u)
    added=$(comm -13 <(echo "$old") <(echo "$new") | grep -E '^- .*WP[0-9]+' || true)
    if [ -z "$added" ]; then
        echo "integrity: threshold file(s) changed since $base without a new"
        echo "'## Deviations from the plan' entry in $DEVIATIONS:"
        printf '  %s\n' "${changed_thresholds[@]}"
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then echo "integrity: OK"; fi
exit "$fail"
