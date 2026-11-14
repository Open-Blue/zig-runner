#!/usr/bin/env bash
# After the tests: fails if anything is left under runner/.zig-cache/tmp (what std.testing.tmpDir
# makes: each test's own directory, removed when it ends), or if a directory there is deeper than
# 32 levels. The offenders are printed, and removed (find's -delete walks by descriptor, so it
# takes a chain too deep to name). tools/test_shards.zig makes the same check per run, naming the
# tests; this is CI's and the pre-push hook's own, whatever started the tests. A chain tens of
# thousands deep crashed `du` (Ubuntu's Rust coreutils) and loaded editors' file watchers.
set -euo pipefail
tmp=${1:-"$(dirname "$0")/../../runner/.zig-cache/tmp"}
[[ -d $tmp ]] || exit 0
status=0
left=$(find "$tmp" -mindepth 1 -maxdepth 1 -printf '%P\n' | head -10)
if [[ -n $left ]]; then
	echo "tmp-leaks: left under $tmp (the first ten):" >&2
	sed 's/^/  /' <<<"$left" >&2
	status=1
fi
# Levels below the tmp directory: a test's own is level 1, its content from level 2.
deep=$(find "$tmp" -mindepth 33 -type d -printf '%d %P\n' | cut -c1-120 | head -10)
if [[ -n $deep ]]; then
	echo "tmp-leaks: directories deeper than 32 levels (depth, then the start of the path):" >&2
	sed 's/^/  /' <<<"$deep" >&2
	status=1
fi
((status == 0)) || find "$tmp" -mindepth 1 -delete
exit "$status"
