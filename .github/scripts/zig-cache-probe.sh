#!/usr/bin/env bash
# EXPERIMENT, not for merging. Times the compile of what zig-test.sh compiles (the tests, the runner
# and test_shards, together as it does) and nothing else, twice in a row on this machine, each with a
# local cache of its own that is thrown away: first from an empty global cache (the cold control),
# then from the global cache as the job has it (restored: a hit; empty: a miss, so a second cold
# compile that shows the noise). `tsan` adds -fsanitize-thread, as the Database tests job does;
# `maker` is `zig build --help` on an empty build.zig, which compiles Zig's build runner.
set -euo pipefail
cd "$(dirname "$0")/../../runner"
# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh

mode=${1:-plain}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
job_global=${ZIG_GLOBAL_CACHE_DIR:-}

# compile LABEL GLOBAL: one compile under that global cache and a fresh local one; prints its seconds.
compile() {
	local label=$1 global=$2 start end
	rm -rf "$scratch/local"
	start=$(date +%s.%N)
	if [[ $mode == maker ]]; then
		(cd "$scratch/mini" && ZIG_GLOBAL_CACHE_DIR=$global ZIG_LOCAL_CACHE_DIR="$scratch/local" zig build --help >/dev/null)
	else
		local pids=() p
		export ZIG_GLOBAL_CACHE_DIR=$global ZIG_LOCAL_CACHE_DIR="$scratch/local"
		zig test "${modules[@]}" --test-no-exec -femit-bin="$scratch/test" &
		pids+=($!)
		zig build-exe tools/test_shards.zig -femit-bin="$scratch/test_shards" &
		pids+=($!)
		zig build-exe "${modules[@]}" --name runner -femit-bin="$scratch/runner" &
		pids+=($!)
		for p in "${pids[@]}"; do wait "$p"; done
	fi
	end=$(date +%s.%N)
	printf 'zig-cache probe: %s, %s: %.1f s (loadavg %s)\n' "$mode" "$label" "$(awk -v a="$end" -v b="$start" 'BEGIN{print a-b}')" "$(cut -d' ' -f1 /proc/loadavg)"
}

if [[ $mode == maker ]]; then
	mkdir "$scratch/mini"
	echo 'pub fn build(b: *@import("std").Build) void { _ = b; }' >"$scratch/mini/build.zig"
else
	flags=()
	[[ $mode == tsan ]] && flags=(-fsanitize-thread)
	zig_modules "$scratch" "$scratch/version" "${flags[@]}"
fi

echo "zig-cache probe: the job's global cache is a ${ZR_ZIG_CACHE_STATE:-unset}, $(find "$job_global/o" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l) output entries"
compile "empty global cache (cold control)" "$scratch/g-empty"
compile "the job's global cache (${ZR_ZIG_CACHE_STATE:-unset})" "$job_global"
echo "zig-cache probe: cold control left $(du -sh "$scratch/g-empty" | cut -f1) in its global cache; the job's has $(du -sh "$job_global" | cut -f1)"
