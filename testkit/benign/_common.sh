# Shared by the benign workloads (plan 5.7(3), WP18). Each workload is
# called as `<name>.sh setup DIR` (not recorded) and `<name>.sh run DIR`
# (recorded by scripts/fp-eval.sh) and works only inside DIR, except apt.sh,
# which installs and removes one small package and runs only in a test VM.
set -eu
step="${1:?setup|run}"; dir="${2:?DIR}"
mkdir -p "$dir"
cd "$dir"
