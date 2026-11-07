#!/usr/bin/env bash
# The runner's tests under Valgrind's memcheck (the `analysis` workflow's Valgrind job): reads of
# memory never written, and reads or writes outside what was allocated, which Debug's safety
# checks miss (they check bounds of slices and `undefined` they can see, not raw pointers, C's
# allocations or the kernel's buffers).
#
#   zig-valgrind.sh [TEST_FILTER...]
#
# With filters, only the tests whose names contain one: a pull request's own new tests
# (changed-tests.sh), where the whole run is the nightly's.
#
# The tests compile as zig-test.sh compiles them (the compiler directly, the module graph
# zig-modules.sh gives), in Debug, where Zig tells Valgrind which memory is `undefined`
# (std.valgrind's client requests, on by default for Debug on Linux), so a read of it is reported
# even though Zig filled it with 0xaa. What it takes for Valgrind 3.26 to run them at all:
#
# - `-mcpu=x86_64_v3`: Zig compiles for the machine it runs on, and GitHub's runners have AVX-512,
#   which Valgrind cannot decode (it stops at AVX2: "unhandled instruction bytes").
# - Zig's own x86_64 backend, the default for Debug, or LLVM with ZIG_VALGRIND_LLVM=1: both run.
#   Valgrind warns about the debug line tables Zig's own backend writes ("Badly formed extended
#   line op", some 300000 times a run, `-q` or not): those lines are left out of the log.
# - `--aspace-minaddr=0x200000000`: Valgrind maps the program's memory from about 72 MiB up, and
#   std.heap.PageAllocator hints each new mapping just below the last one, so after some 70 MiB
#   the hint wraps below zero (0xfffffffffc840000). The kernel ignores a hint it cannot use;
#   Valgrind fails the mmap with EINVAL, which std takes for unreachable and panics (the first
#   test to allocate 64 MiB, sink.zig's spool near its cap). From 8 GiB up, the hints have room.
#
# What fails the job is memcheck's: a report not suppressed in .github/valgrind.supp (whose
# entries say why each is benign) exits 99, and a crash ends the run before every test was
# checked. Tests that only fail are a warning: Valgrind runs them many times slower, one thread
# at a time, and the tests of deadlines (a silent connection dropped, a server that never answers)
# then see their deadlines pass; the tests' own job runs them at full speed. The tests' output,
# Valgrind's included, is only text to the job (zig-test.sh).
#
# A test that does not finish would hold the job to its time limit with nothing said. ZIG_VALGRIND_TIMEOUT
# (`timeout`'s duration, 35m by default: the whole suite takes about 25, with the build before it)
# ends the run instead, and names the test that was running, the last the log started.
set -euo pipefail
cd "$(dirname "$0")/../../runner"

# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh

valgrind=${VALGRIND:-valgrind}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git describe --tags --always --dirty --abbrev=8 >"$scratch/version"

flags=(-mcpu=x86_64_v3)
[[ ${ZIG_VALGRIND_LLVM:-} == 1 ]] && flags+=(-fllvm)
zig_modules "$scratch" "$scratch/version" "${flags[@]}"
filter=()
for name in "$@"; do filter+=(--test-filter "$name"); done

# The native backend's tests run steps through the runner binary (zig-test.sh); it is not what is
# checked here, so it runs as compiled, outside Valgrind (--trace-children=no, the default).
zig build-exe "${modules[@]}" --name runner -femit-bin="$scratch/runner"
zig test "${modules[@]}" "${filter[@]}" --test-no-exec -femit-bin="$scratch/test"
export ZIG_RUNNER_TEST_EXE="$scratch/runner"

stop="valgrind-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
echo "::stop-commands::$stop"
set +e
# Valgrind writes to a file and the log is read from it (`tail --pid` ends with Valgrind), not
# through a pipe: a process the tests left running (a setsid child) would hold a pipe open past
# the timeout, and the job would wait on it to its own limit with nothing said.
: >"$scratch/raw"
timeout --kill-after=30s "${ZIG_VALGRIND_TIMEOUT:-35m}" "$valgrind" -q --tool=memcheck --error-exitcode=99 --track-origins=yes --num-callers=40 \
	--aspace-minaddr=0x200000000 --suppressions=../.github/valgrind.supp --gen-suppressions=all \
	"$scratch/test" >"$scratch/raw" 2>&1 &
checking=$!
tail -n +1 -f --pid="$checking" "$scratch/raw" 2>/dev/null |
	grep --line-buffered -v 'Warning: DWARF2 reader: Badly formed extended line op' >"$scratch/log" &
reading=$!
# The log as it grows, so a long run shows its progress.
tail -n +1 -f --pid="$reading" "$scratch/log" 2>/dev/null &
showing=$!
wait "$checking"
status=$?
wait "$reading" "$showing"
set -e
echo "::$stop::"
case $status in
0) echo "Valgrind: no reports, every test passed" ;;
1)
	echo "Valgrind: no reports"
	# Also for a filtered run (a pull request's own tests): ci ran them at full speed and passed
	# them, so what fails here is Valgrind's slowdown on a deadline, not the test; the warning
	# names each. Memcheck's own reports are the failure (99).
	# The test each `FAIL (...)` belongs to: the last `N/M name...` line before it (a test's own
	# output can come between the two).
	failed=$(awk '/^[0-9]+\/[0-9]+ /{t=$0; sub(/\.\.\..*/, "", t)} /FAIL \(/{print t}' "$scratch/log" | paste -sd ';' -)
	echo "::warning title=Valgrind::memcheck reported nothing, but tests failed under it (timing, most likely: see the script): ${failed:-see the log}"
	status=0
	;;
124 | 137)
	# The last `N/M name...` the log started, with no result after it.
	running=$(awk '/^[0-9]+\/[0-9]+ /{t=$0} END{print t}' "$scratch/log")
	echo "::error title=Valgrind::still running after ${ZIG_VALGRIND_TIMEOUT:-35m}, stopped: a test that does not finish, or a run too slow for its limit. The last test started: ${running:-none}"
	;;
99) echo "::error title=Valgrind::memcheck reported errors in the tests (above; each with a suppression to copy if it is benign)" ;;
*) echo "::error title=Valgrind::the tests crashed under Valgrind (exit $status), before all were checked" ;;
esac
exit "$status"
