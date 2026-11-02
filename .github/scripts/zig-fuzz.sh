#!/usr/bin/env bash
# One fuzz target of runner/src/fuzz.zig, for a bounded number of runs (the `fuzz` workflow):
#
#   zig-fuzz.sh TARGET RUNS MINUTES [OUT]
#
# TARGET is a test's name after "fuzz: " ("OCI layer"), RUNS what Zig's fuzzer takes (`100K`,
# `2M`), MINUTES the time it gets. Zig's fuzzer (`zig build test --fuzz=RUNS`) mutates the test's
# seed corpus, guided by coverage, and keeps what it found in runner/.zig-cache/f, which the
# workflow carries from one night to the next. Its instrumentation needs LLVM (`-Dllvm`): Zig's own
# x86_64 backend instruments nothing, and the run then fails on an empty coverage file.
#
# The fuzzer has no time limit of its own, and none per input, so RUNS is the bound and MINUTES
# catches an input that hangs the target: RUNS should take well under MINUTES. Outcomes:
#
#   exit 0  all RUNS done, no failure; the coverage report is printed
#   exit 1  a crash, a failed check or a leak: the input is copied to OUT/crash (Zig saves it as
#           .zig-cache/f/crash); a hang (MINUTES ran out): the inputs in flight (.zig-cache/f/in*)
#           are copied to OUT; or the build failed
#
# Each failure is a `::error` naming the target. A crash's input reproduces as a corpus entry of
# its test (`@embedFile` it into the test's `.corpus`), which `zig build test` then runs every time.
set -euo pipefail
cd "$(dirname "$0")/../../runner"

target=${1:?usage: zig-fuzz.sh TARGET RUNS MINUTES [OUT]}
runs=${2:?usage: zig-fuzz.sh TARGET RUNS MINUTES [OUT]}
minutes=${3:?usage: zig-fuzz.sh TARGET RUNS MINUTES [OUT]}
out=${4:-${RUNNER_TEMP:-/tmp}/fuzz}
mkdir -p "$out"
rm -f .zig-cache/f/crash .zig-cache/f/in*

# The tests' output is only text to the job (zig-test.sh): an input can hold `::` lines.
stop="fuzz-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
echo "::stop-commands::$stop"
status=0
# GNU timeout signals the whole process group: the build runner and the test it runs.
timeout --kill-after=30 "$((minutes * 60))" \
	zig build test -Dllvm -Dtest-filter="fuzz: $target" --fuzz="$runs" 2>&1 | tee "$out/log" ||
	status=$?
echo "::$stop::"

if ((status == 0)); then
	echo "fuzz: $target: $runs runs, nothing found"
	exit 0
fi
if ((status == 124 || status == 137)); then
	cp .zig-cache/f/in* "$out/" 2>/dev/null || true
	echo "::error title=fuzz: $target::did not finish $runs runs in $minutes minutes: an input hangs it, or the runs are too many for the time (the inputs in flight are in the artifact)"
elif [[ -e .zig-cache/f/crash ]]; then
	cp .zig-cache/f/crash "$out/crash"
	echo "::error title=fuzz: $target::found a crash, failed check or leak (the input is the artifact's crash file; the log above has the trace)"
else
	echo "::error title=fuzz: $target::failed (exit $status) without a crashing input: see the log above"
fi
exit 1
