#!/usr/bin/env bash
# The runner's line coverage under its tests, with kcov (the `analysis` workflow's Coverage job):
#
#   zig-coverage.sh OUT
#
# Leaves in OUT:
#
#   html/            kcov's report of every pass merged (html/index.html; html/kcov-merged/ holds
#                    its cobertura.xml and coverage.json)
#   cobertura.xml    the merged coverage, Cobertura XML
#   coverage.json    the merged coverage, kcov's JSON: per file and in total
#   summary.json     the total, per area (runner/src's directories) and per security-relevant file
#   summary.md       the same for a job summary, the least-covered security-relevant files first
#
# What is measured, merged into one report:
#
#   rootless   every test, as zig-test.sh runs them (rootless; the native backend's tests take the
#              rootless sandbox's path where ZIG_RUNNER_REQUIRE_NATIVE=1)
#   root       with ZIG_COVERAGE_ROOT=1, the native backend's tests as root (sudo), as zig-test.sh's
#              ZIG_TEST_NATIVE_AS_ROOT=1 pass: each job its own range of ids and its own network
#   helpers    the runner binary the native tests start for their steps and networks (`zig-runner
#              native-step`, `native-net`, ...: the sandbox's own side of sandbox.zig, net.zig and
#              nft.zig, which no test process runs), each run under kcov too
#
# Each pass runs its tests twice: under kcov with the helpers as compiled, then as compiled with
# each helper under kcov. kcov cannot run inside a process kcov traces (the helper's kcov fails to
# start it), and the tests themselves take seconds without it.
#
# kcov sets a breakpoint on each line the DWARF line table names and counts the lines hit. What it
# takes for kcov 43 to read Zig 0.17's tests:
#
# - LLVM (-fllvm). Zig's own x86_64 backend, the default for Debug, writes a line table kcov finds
#   no lines in at all (0 of 0; Valgrind warns about the same table, zig-valgrind.sh).
# - Not position-independent (-fno-PIE, after zig-modules.sh's -fPIE). kcov 43 reads a static PIE's
#   lines but sets its breakpoints at the unrelocated addresses: every line is reported, none hit.
#
# Neither changes what the tests test. A test's own lines count as covered lines of its file, as
# kcov cannot tell them from the code's; the per-file numbers are for finding what no test reaches,
# not a measure of how well it is tested. Tests that fail under kcov are a warning: what judges
# them is the tests' own job, at full speed (kcov runs each line's first hit through a trap). What
# fails is a report that did not come out.
set -euo pipefail
out=$(realpath -m "${1:?usage: zig-coverage.sh OUT}")
cd "$(dirname "$0")/../../runner"

# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh

kcov=$(command -v "${KCOV:-kcov}")
src=$PWD/src
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
raw=$out/raw
rm -rf "$out"
mkdir -p "$raw"

zig_modules "$scratch" "$scratch/version" -fllvm
build=("${modules[@]}" -fno-PIE)
zig build-exe "${build[@]}" --name runner -femit-bin="$scratch/runner"
zig test "${build[@]}" --test-no-exec -femit-bin="$scratch/test"
if [[ ${ZIG_COVERAGE_ROOT:-} == 1 ]]; then
	zig test "${build[@]}" --test-filter native --test-no-exec -femit-bin="$scratch/test-native"
fi

# The helpers: each run of the runner binary under kcov, into a report of its own (two at once
# would race on one), merged with the rest below.
cat >"$scratch/runner-kcov" <<EOF
#!/bin/sh
exec "$kcov" --include-path="$src" "$raw/helper-\$\$" "$scratch/runner" "\$@"
EOF
chmod +x "$scratch/runner-kcov"

# pass NAME [PREFIX...] TEST: TEST under kcov into raw/NAME, then TEST with each helper under kcov.
# The output is only text to the job (zig-test.sh), and failed tests a warning.
pass() {
	local name=$1 stop status=0
	shift
	stop="coverage-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
	echo "::stop-commands::$stop"
	ZIG_RUNNER_TEST_EXE="$scratch/runner" "${@:1:$#-1}" \
		"$kcov" --include-path="$src" "$raw/$name" "${@: -1}" 2>&1 || status=$?
	ZIG_RUNNER_TEST_EXE="$scratch/runner-kcov" "$@" 2>&1 || status=$?
	echo "::$stop::"
	if ((status != 0)); then
		echo "::warning title=Coverage::tests failed in the $name pass under kcov (exit $status; the tests' own job judges them): its coverage still counts"
	fi
}

pass rootless "$scratch/test"
if [[ ${ZIG_COVERAGE_ROOT:-} == 1 ]]; then
	pass root sudo --preserve-env=ZIG_RUNNER_TEST_EXE,ZIG_RUNNER_REQUIRE_NATIVE,ZIG_RUNNER_SERVICE_IMAGES \
		"$scratch/test-native"
	sudo chown -R "$(id -u):$(id -g)" "$raw"
fi

helpers=$(find "$raw" -maxdepth 1 -name 'helper-*' | wc -l)
echo "Coverage: $helpers helper runs measured"
"$kcov" --merge "$out/html" "$raw"/*
merged=$out/html/kcov-merged
if [[ ! -s $merged/coverage.json ]]; then
	echo "::error title=Coverage::kcov wrote no merged report ($merged/coverage.json)"
	exit 1
fi
cp "$merged/coverage.json" "$merged/cobertura.xml" "$out/"
rm -rf "$raw"

# The summary. Paths relative to runner/src; an area is a file's directory (`.` for runner/src's
# own files). The security-relevant files: what reads input a job, a workflow, a registry or a
# server controls, or what keeps a job in its sandbox and its secrets out of logs. Test-only
# servers and registries are left out of that list.
jq --arg src "$src/" '
	def pct(c; t): if t == 0 then 0 else (c * 10000 / t | round) / 100 end;
	def relevant: test("^(dagger/JobLog|commands|expr|yaml|native/Store|native/sandbox|native/nft|native/net|minisign)\\.zig$")
		or (test("^(native/oci|github)/") and (test("test(server|registry)\\.zig$") | not));
	[.files[] | {file: (.file | ltrimstr($src)), covered: (.covered_lines | tonumber), total: (.total_lines | tonumber)}
		| .percent = pct(.covered; .total)] as $files
	| {
		total: {covered: .covered_lines, total: .total_lines, percent: pct(.covered_lines; .total_lines)},
		areas: ($files | group_by(.file | if test("/") then sub("/[^/]*$"; "") else "." end)
			| map({area: (.[0].file | if test("/") then sub("/[^/]*$"; "") else "." end),
				covered: (map(.covered) | add), total: (map(.total) | add), files: length})
			| map(.percent = pct(.covered; .total))),
		relevant: ($files | map(select(.file | relevant)) | sort_by(.percent, .file)),
		files: ($files | sort_by(.file))
	}' "$out/coverage.json" >"$out/summary.json"

jq -r '
	"## Coverage\n",
	"Lines covered by the tests (rootless and the native root pass, merged; kcov): **\(.total.percent)%** (\(.total.covered) of \(.total.total)).\n",
	"### Least-covered security-relevant files\n",
	"| File | Coverage | Lines |", "|---|---:|---:|",
	(.relevant[] | "| `\(.file)` | \(.percent)% | \(.covered) / \(.total) |"),
	"\n### Per area (directories of `runner/src`)\n",
	"| Area | Coverage | Lines | Files |", "|---|---:|---:|---:|",
	(.areas[] | "| `\(.area)` | \(.percent)% | \(.covered) / \(.total) | \(.files) |"),
	"\n<details><summary>Every file</summary>\n",
	"| File | Coverage | Lines |", "|---|---:|---:|",
	(.files[] | "| `\(.file)` | \(.percent)% | \(.covered) / \(.total) |"),
	"\n</details>"' "$out/summary.json" >"$out/summary.md"
jq -r '"Coverage: \(.total.percent)% of \(.total.total) lines"' "$out/summary.json"

# COVERAGE_MIN=N: fail below N% in total (unset: report only).
if [[ -n ${COVERAGE_MIN:-} ]]; then
	jq -e --argjson min "$COVERAGE_MIN" '.total.percent >= $min' "$out/summary.json" >/dev/null || {
		echo "::error title=Coverage::$(jq -r .total.percent "$out/summary.json")% of lines covered, below COVERAGE_MIN=$COVERAGE_MIN%"
		exit 1
	}
fi
