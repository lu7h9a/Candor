#!/usr/bin/env bash
# check-claims.sh - fails when user-facing docs overclaim what Candor does
# (detection or sandbox safety) or point at builder-internal files that are
# not in the repository. Run by `make lint`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
files=(README.md SECURITY.md CHANGELOG.md docs/PRIVACY.md docs/LIMITATIONS.md
       docs/ARCHITECTURE.md docs/DEMO.md docs/PACKAGING.md docs/COMPAT.md
       docs/THREAT_MODEL.md packaging/postinstall-message.txt packaging/man/*)
fail=0
claims='undetectable|military[- ]grade|bullet-?proof|unhackable|100 ?%|guarantee|complete protection|full protection|protects you from|stops malware|blocks malware|removes malware|zero false positives|secure sandbox|safe to run (any|untrusted)|contains malware safely'
if out=$(grep -nEi "$claims" "${files[@]}"); then
    echo "claims: overclaiming wording in user-facing docs:"; echo "$out"; fail=1
fi
if out=$(grep -nE 'NEEDS_USER|MASTER_PLAN|PROGRESS\.md|SKILL\.md' "${files[@]}"); then
    echo "claims: references to builder-internal files:"; echo "$out"; fail=1
fi
[ "$fail" = 0 ] && echo "claims: OK (${#files[@]} files)"
exit "$fail"
