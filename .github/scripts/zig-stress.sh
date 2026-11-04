#!/usr/bin/env bash
# The runner's concurrency-sensitive tests (zig-race-tests.sh) run again and again under CPU and
# memory load (the `analysis` workflow's Stress job): a test whose outcome hangs on which thread
# gets there first, or on a deadline it only meets on an idle machine, fails here before it fails
# on a busy runner.
#
#   zig-stress.sh ROUNDS OUT
#
# stress-ng keeps every CPU busy (one worker each, so the tests' threads are preempted and wait
# their turn) and two workers dirtying half the memory (so the kernel reclaims and the tests'
# pages fault) the whole time. Each round runs every one of the tests once, in one process, with a
# time limit (a round that hangs fails too); the first round that fails ends the run, and its
# output is kept in OUT, which the job uploads. The tests compile in Debug, as zig-test.sh's do.
set -euo pipefail
rounds=${1:?usage: zig-stress.sh ROUNDS OUT}
out=${2:?usage: zig-stress.sh ROUNDS OUT}
cd "$(dirname "$0")/../../runner"

# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh
# shellcheck source=.github/scripts/zig-race-tests.sh
. ../.github/scripts/zig-race-tests.sh

scratch=$(mktemp -d)
load=
end() {
	# stress-ng's whole process group: its workers too.
	if [[ -n $load ]]; then kill -- "-$load" 2>/dev/null || true; fi
	wait
	rm -rf "$scratch"
}
trap end EXIT
race_build "$scratch"
mkdir -p "$out"

# In a session of its own, whose id is its pid, so `end` can stop its workers with it.
setsid "${STRESS_NG:-stress-ng}" --cpu "$(nproc)" --vm 2 --vm-bytes 50% --timeout 0 --quiet &
load=$!
sleep 2
kill -0 "$load" || {
	echo "::error title=Stress::stress-ng did not start"
	exit 1
}

# A round takes about 11 s on an idle 4-core runner; 300 s is a hang.
stop="stress-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
started=$SECONDS
for ((round = 1; round <= rounds; round++)); do
	log=$scratch/round-$round.log
	t=$SECONDS
	status=0
	timeout --kill-after=10 300 "$race_test" >"$log" 2>&1 || status=$?
	echo "round $round/$rounds: exit $status in $((SECONDS - t)) s, $(tail -n 1 "$log")"
	((status == 0)) && continue
	cp "$log" "$out/"
	echo "::stop-commands::$stop"
	cat "$log"
	echo "::$stop::"
	# The test each `FAIL (...)` belongs to, as zig-valgrind.sh finds it.
	failed=$(awk '/^[0-9]+\/[0-9]+ /{t=$0; sub(/\.\.\..*/, "", t)} /FAIL \(/{print t}' "$log" | paste -sd ';' -)
	((status == 124)) && failed="a test hung past 300 s (the last one started above)"
	echo "::error title=Stress::round $round of $rounds failed under load (exit $status): ${failed:-see the log}"
	exit 1
done
echo "Stress: $rounds rounds passed under load in $((SECONDS - started)) s"
