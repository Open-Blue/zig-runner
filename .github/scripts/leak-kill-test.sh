#!/usr/bin/env bash
# A test killed in the middle cannot clean up after itself: the next run must. Run as the test
# command of zig-test.sh with ZIG_TEST_KILL_CHECK=1 (which compiles only the deep-chain eviction
# test), it gets the test_shards program and the test binary:
#
#   1. the binary runs in a directory of its own, and is killed (SIGKILL) once its chain of
#      directories is a few hundred deep, so that a tmp directory with the chain in it is left;
#   2. test_shards runs the binary again there, with ZIG_TEST_SWEEP_AGE_S=0, and must remove what
#      the first left (and say so), pass, and leave nothing under .zig-cache/tmp.
#
# Where the chain cannot be made (overlayfs refuses it, and the test skips), there is nothing to kill.
set -euo pipefail
shards=$1
bin=$2
scratch=$(mktemp -d)
pid=
cleanup() {
	[[ -z $pid ]] || kill -9 "$pid" 2>/dev/null || true
	# find's -delete walks by descriptor: the chain is too deep to name.
	find "$scratch" -mindepth 1 -delete 2>/dev/null || true
	rmdir "$scratch" 2>/dev/null || true
}
trap cleanup EXIT
cd "$scratch"

"$bin" >"$scratch/first.log" 2>&1 &
pid=$!
tries=0
until [[ -n $(find .zig-cache/tmp -mindepth 300 -maxdepth 300 -type d -print -quit 2>/dev/null) ]]; do
	if ! kill -0 "$pid" 2>/dev/null; then
		echo "leak-kill-test: the test ended before its chain was deep (skipped here?); nothing to kill" >&2
		pid=
		exit 0
	fi
	tries=$((tries + 1))
	if ((tries > 3000)); then
		echo "leak-kill-test: no chain of 300 directories after 10 minutes" >&2
		exit 1
	fi
	sleep 0.2
done
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
pid=
if [[ -z $(find .zig-cache/tmp -mindepth 1 -maxdepth 1 -print -quit) ]]; then
	echo "leak-kill-test: the killed test left nothing, so the check checks nothing" >&2
	exit 1
fi

if ! ZIG_TEST_SWEEP_AGE_S=0 "$shards" "$bin" >"$scratch/second.log" 2>&1; then
	cat "$scratch/second.log" >&2
	echo "leak-kill-test: the run after the kill failed" >&2
	exit 1
fi
if ! grep -q 'left by an earlier run' "$scratch/second.log"; then
	cat "$scratch/second.log" >&2
	echo "leak-kill-test: the run after the kill did not remove what it left" >&2
	exit 1
fi
if [[ -n $(find .zig-cache/tmp -mindepth 1 -print -quit) ]]; then
	echo "leak-kill-test: something is left under .zig-cache/tmp after the second run" >&2
	exit 1
fi
echo "leak-kill-test: a killed test's chain was removed by the next run" >&2
