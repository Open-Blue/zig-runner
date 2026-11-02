#!/usr/bin/env bash
# The runner's tests under Valgrind's memcheck (the `analysis` workflow's Valgrind job): reads of
# memory never written, and reads or writes outside what was allocated, which Debug's safety
# checks miss (they check bounds of slices and `undefined` they can see, not raw pointers, C's
# allocations or the kernel's buffers).
#
#   zig-valgrind.sh [TEST_FILTER]
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
[[ -n ${1:-} ]] && filter=(--test-filter "$1")

# The native backend's tests run steps through the runner binary (zig-test.sh); it is not what is
# checked here, so it runs as compiled, outside Valgrind (--trace-children=no, the default).
zig build-exe "${modules[@]}" --name runner -femit-bin="$scratch/runner"
zig test "${modules[@]}" "${filter[@]}" --test-no-exec -femit-bin="$scratch/test"
export ZIG_RUNNER_TEST_EXE="$scratch/runner"

stop="valgrind-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
echo "::stop-commands::$stop"
set +e
"$valgrind" -q --tool=memcheck --error-exitcode=99 --track-origins=yes --num-callers=40 \
	--aspace-minaddr=0x200000000 --suppressions=../.github/valgrind.supp --gen-suppressions=all \
	"$scratch/test" 2>&1 | grep --line-buffered -v 'Warning: DWARF2 reader: Badly formed extended line op' |
	tee "$scratch/log"
status=${PIPESTATUS[0]}
set -e
echo "::$stop::"
case $status in
0) echo "Valgrind: no reports, every test passed" ;;
1)
	echo "Valgrind: no reports"
	failed=$(grep -oE '^[0-9]+/[0-9]+ [^ ].*\.\.\.' "$scratch/log" | sed -n 's/\.\.\.$//p' |
		while IFS= read -r t; do grep -qF "$t...OK" "$scratch/log" || grep -qF "$t...SKIP" "$scratch/log" || echo "$t"; done |
		paste -sd ';' -) || true
	echo "::warning title=Valgrind::memcheck reported nothing, but tests failed under it (timing, most likely: see the script): ${failed:-see the log}"
	status=0
	;;
99) echo "::error title=Valgrind::memcheck reported errors in the tests (above; each with a suppression to copy if it is benign)" ;;
*) echo "::error title=Valgrind::the tests crashed under Valgrind (exit $status), before all were checked" ;;
esac
exit "$status"
