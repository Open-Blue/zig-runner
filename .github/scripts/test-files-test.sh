#!/usr/bin/env bash
# test-files.sh's verdicts, with no compile: a fixture runner/src and a list of the binary's test
# names in place of the binary. A file whose tests are all missing, and one with fewer in the binary
# than in the source, each fail naming that file and no other; a file without tests is not asked
# for; a full list passes and says how many tests it saw.
#
#   test-files-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fail() {
	echo "test-files-test: $*" >&2
	exit 1
}

mkdir -p "$scratch/runner/src/sub"
printf 'test "one" {}\ntest "two" {}\n' >"$scratch/runner/src/a.zig"
printf 'const x = 1;\n    test "nested" {}\n' >"$scratch/runner/src/sub/b.zig"
printf 'const s =\n    \\\\test "in a string"\n;\n' >"$scratch/runner/src/none.zig"
full='a.test.one
a.test.two
sub.b.test.nested'
run() {
	printf '%s\n' "$1" >"$scratch/names"
	TEST_FILES_ROOT=$scratch/runner TEST_FILES_NAMES=$scratch/names ./test-files.sh >"$scratch/out" 2>&1
}

run "$full" || fail "a full list failed: $(cat "$scratch/out")"
grep -q 'every test in runner/src is in the test binary (3 tests)' "$scratch/out" ||
	fail "no success line: $(cat "$scratch/out")"

if run "$(grep -v '^sub\.b\.' <<<"$full")"; then fail "a file with none of its tests in the binary passed"; fi
grep -q '^::error file=runner/src/sub/b.zig::1 tests in the source, 0 in the test binary' "$scratch/out" ||
	fail "the missing file not named: $(cat "$scratch/out")"
(($(grep -c '^::error' "$scratch/out") == 1)) || fail "another file named too: $(cat "$scratch/out")"

if run "$(grep -v 'two$' <<<"$full")"; then fail "a file with fewer tests in the binary passed"; fi
grep -q '^::error file=runner/src/a.zig::2 tests in the source, 1 in the test binary' "$scratch/out" ||
	fail "the short count not named: $(cat "$scratch/out")"
(($(grep -c '^::error' "$scratch/out") == 1)) || fail "another file named too: $(cat "$scratch/out")"
echo "test-files-test: a missing file and a short count fail naming the file; a full list passes"
