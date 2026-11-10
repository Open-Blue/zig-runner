#!/usr/bin/env bash
# Where native jobs' time goes: the runner's "job N 'NAME': native phases (ms): ..." lines
# (runner/src/native/phases.zig) from its log, as per-phase medians. Each line holds every phase
# of one job, a phase's samples joined by commas: the set-up's and teardown's once a job, each
# sandbox's (spawn ... exit) and each publish's (unshift ... rename) once each time.
#
#   native-phases.sh [LOG...]           a runner's log, or stdin
#   journalctl -u zig-runner@bench.service --since '-1 hour' | native-phases.sh
#   NATIVE_PHASES_BY_JOB=1 native-phases.sh LOG    one table per job name as well
#
# Per phase: how many samples, their median, the 90th percentile and the largest, and the median
# of each job's total for the phase (what it adds to a job). Then the median job's set-up (store
# to base) and teardown (services to collect). The e2e harness prints it after a native pass
# (e2e.sh check); on razorbill, from the bench instance's journal after a run of the suite.
set -euo pipefail

order="store sweep dir cgroup resolver slot nat netns image provision caches actions base claim
spawn namespaces idmap overlay binds root run exit unshift size record sync sync_wb sync_fsync sync_meta syncfs rename flatten
services cgroup_rm veth_rm tree_rm collect"

table() {
	awk -v order="$order" '
	function sort(a, n,   i, j, t) {
		for (i = 2; i <= n; i++) {
			t = a[i]
			for (j = i - 1; j >= 1 && a[j] > t; j--) a[j + 1] = a[j]
			a[j + 1] = t
		}
	}
	function pct(list, p,   a, n) {
		n = split(list, a, " ")
		if (n == 0) return 0
		sort(a, n)
		return a[int((n - 1) * p + 0.5) + 1]
	}
	function count(list,   a) { return split(list, a, " ") }
	BEGIN { setup = "store sweep dir cgroup resolver slot nat netns image provision caches actions base"
		teardown = "services cgroup_rm veth_rm tree_rm collect" }
	{
		at = index($0, "native phases (ms): ")
		if (at == 0) next
		jobs++
		rest = substr($0, at + 20)
		n = split(rest, kv, " ")
		su = 0; td = 0
		for (i = 1; i <= n; i++) {
			eq = index(kv[i], "=")
			if (eq == 0) continue
			name = substr(kv[i], 1, eq - 1)
			m = split(substr(kv[i], eq + 1), v, ",")
			total = 0
			for (k = 1; k <= m; k++) { samples[name] = samples[name] " " v[k]; total += v[k] }
			totals[name] = totals[name] " " total
			if (index(" " setup " ", " " name " ")) su += total
			if (index(" " teardown " ", " " name " ")) td += total
		}
		setups = setups " " su
		teardowns = teardowns " " td
	}
	END {
		if (jobs == 0) { print "no native phases lines"; exit }
		printf "%d jobs\n", jobs
		printf "%-11s %7s %9s %9s %9s %12s\n", "phase (ms)", "samples", "median", "p90", "max", "per job"
		n = split(order, names, /[ \n]+/)
		for (i = 1; i <= n; i++) {
			p = names[i]
			if (!(p in samples)) continue
			printf "%-11s %7d %9.1f %9.1f %9.1f %12.1f\n", p, count(samples[p]), pct(samples[p], 0.5),
				pct(samples[p], 0.9), pct(samples[p], 1), pct(totals[p], 0.5)
		}
		printf "set-up median %.1f ms, teardown median %.1f ms\n", pct(setups, 0.5), pct(teardowns, 0.5)
	}'
}

input=$(cat "$@")
printf '%s\n' "$input" | table
if [[ ${NATIVE_PHASES_BY_JOB:-} == 1 ]]; then
	names=$(printf '%s\n' "$input" | sed -nE "s/.*job [^ ]+ '([^']*)': native phases.*/\1/p" | sort -u)
	while IFS= read -r name; do
		[[ -n $name ]] || continue
		printf '\n%s: ' "$name"
		printf '%s\n' "$input" | grep -F "'$name': native phases" | table
	done <<<"$names"
fi
