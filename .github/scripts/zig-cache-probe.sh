#!/usr/bin/env bash
# EXPERIMENT, not for merging. Times the compile of what zig-test.sh compiles (the tests, the runner
# and test_shards, together as it does) and nothing else, with a local cache of its own that is
# thrown away, so the time is the cost of a compile that starts from the global cache as it is: empty
# (a miss) or restored (a hit). `tsan` adds -fsanitize-thread, as the Database tests job does.
set -euo pipefail
cd "$(dirname "$0")/../../runner"
# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh

mode=${1:-plain}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
flags=()
[[ $mode == tsan ]] && flags=(-fsanitize-thread)

start=$(date +%s.%N)
zig_modules "$scratch" "$scratch/version" "${flags[@]}"
archive=$(date +%s.%N)
export ZIG_LOCAL_CACHE_DIR="$scratch/local"
pids=()
zig test "${modules[@]}" --test-no-exec -femit-bin="$scratch/test" &
pids+=($!)
zig build-exe tools/test_shards.zig -femit-bin="$scratch/test_shards" &
pids+=($!)
zig build-exe "${modules[@]}" --name runner -femit-bin="$scratch/runner" &
pids+=($!)
for p in "${pids[@]}"; do wait "$p"; done
end=$(date +%s.%N)
printf 'zig-cache probe: %s, global cache %s: Rust archive %.1f s, Zig compile of tests+runner+test_shards %.1f s (local cache empty)\n' \
	"$mode" "${ZR_ZIG_CACHE_STATE:-unset}" "$(awk -v a="$archive" -v b="$start" 'BEGIN{print a-b}')" "$(awk -v a="$end" -v b="$archive" 'BEGIN{print a-b}')"
du -sh "$ZIG_GLOBAL_CACHE_DIR" | sed 's/^/zig-cache probe: global cache after: /'
