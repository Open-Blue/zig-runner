#!/usr/bin/env bash
# Tests runner/src/dagger/tool_trees.sh, the runner's check of the tool cache's trees, on a small
# fake tree in a fake tool cache, and install-zig.sh's reading of its verdict: CI's "Workflows"
# job runs this.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
check="$root/runner/src/dagger/tool_trees.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cache="$work/toolcache" lists="$work/lists"
tree="$cache/zig/0.17.0/zig-x86_64-linux-0.17.0"
failures=0

# A fresh tree, no lists, and the tree's digest computed the way install-zig.sh pins it.
fresh() {
	rm -rf "$cache" "$lists"
	mkdir -p "$tree/lib/std" "$tree/doc"
	printf 'zig binary\n' >"$tree/zig"
	printf 'pub fn main() void {}\n' >"$tree/lib/std/std.zig"
	printf 'with space\n' >"$tree/doc/a b.txt"
	seq 1 2000 >"$tree/lib/big"
	sum=$(cd "$tree" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-64)
	# Later writes must land in a later kernel clock tick than these, as they would a job later.
	sleep 0.1
}

# expect NAME PATTERN: the check's output matches PATTERN (grep -E), against the variables above.
# The window for racy files is 0 s unless RACY is set: the tests would otherwise wait it out.
expect() {
	local out
	out=$(TOOL_TREES_RACY_S="${RACY:-0}" "$check" "$cache" "$lists" 2>&1)
	if grep -qE "$2" <<<"$out"; then
		echo "ok: $1"
	else
		echo "FAIL: $1 (wanted /$2/): $out"
		failures=$((failures + 1))
	fi
}
ok() {
	if "${@:2}"; then
		echo "ok: $1"
	else
		echo "FAIL: $1"
		failures=$((failures + 1))
	fi
}
not() { ! "$@"; }
# The check's output, and whether it gives the tree its pinned digest.
lines() { TOOL_TREES_RACY_S=0 "$check" "$cache" "$lists"; }
pinned() { lines | grep -q "^$sum $tree "; }

fresh
expect "first check reads every file" "^$sum $tree 4 4\$"
ok "and leaves a list outside the tool cache" test -s "$lists/zig/0.17.0/zig-x86_64-linux-0.17.0.stat"
expect "second check re-hashes nothing" "^$sum $tree 4 0\$"
touch "$tree/doc/a b.txt"
expect "a touched file is re-hashed, alone" "^$sum $tree 4 1\$"

fresh
RACY=60 expect "files written just before a check are racy" "^$sum $tree 4 4\$"
expect "and re-hashed by the next one" "^$sum $tree 4 4\$"
expect "after which they are not" "^$sum $tree 4 0\$"

fresh
expect "list written" "^$sum "
mtime=$(stat -c %y "$tree/zig")
printf 'zig bjnary\n' >"$tree/zig"
touch -d "$mtime" "$tree/zig"
expect "same size and mtime, new content: another digest" "^[0-9a-f]{64} $tree 4 1\$"
ok "...not the pinned one" not pinned

# The attack the lists' volume is for: a job in the tree's trust scope replaces a file and writes
# a list that records the file's new stat line with its old hash. Where the PR first kept the list,
# beside the tree, the check took it; the runner's check reads lists only from a volume no step
# mounts, so the job's list is never read and the file is re-hashed.
fresh
expect "list written" "^$sum "
good=$(sha256sum "$tree/lib/std/std.zig" | cut -c1-64)
printf 'pub fn main() void { evil(); }\n' >"$tree/lib/std/std.zig"
(cd "$tree" && find . -type f -printf '%p\t%s\t%i\t%T@\t%C@\n' | LC_ALL=C sort -t "$(printf '\t')" -k1,1 |
	while IFS=$(printf '\t') read -r p rest; do
		h=$(sha256sum "$p" | cut -c1-64)
		[ "$p" != ./lib/std/std.zig ] || h=$good
		printf '%s\t%s\t%s\n' "$p" "$rest" "$h"
	done) >"$tree.stat"
expect "a forged list in the tool cache does not let a changed file through" "^[0-9a-f]{64} $tree 4 1\$"
ok "...whose digest is not the pinned one" not pinned

fresh
expect "list written" "^$sum "
rm "$tree/lib/std/std.zig"
expect "a deleted file means another digest, every file read" "^[0-9a-f]{64} $tree 3 3\$"

fresh
expect "list written" "^$sum "
printf 'extra\n' >"$tree/lib/extra"
expect "an added file means every file read" "^[0-9a-f]{64} $tree 5 5\$"

fresh
expect "list written" "^$sum "
l="$lists/zig/0.17.0/zig-x86_64-linux-0.17.0.stat"
sed -i '2s/\t[0-9a-f]*$/\tnot-a-hash/' "$l"
expect "a corrupted list means every file read" "^$sum $tree 4 4\$"
sed -i '2d' "$l"
expect "a list missing a line too" "^$sum $tree 4 4\$"
printf 'garbage' >"$l"
expect "a garbage list too" "^$sum $tree 4 4\$"
expect "and is rewritten" "^$sum $tree 4 0\$"

fresh
printf 'x\n' >"$tree/doc/back\\slash"
sum=$(cd "$tree" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-64)
expect "a name sha256sum escapes: the same digest" "^$sum $tree 5 5\$"
ok "...and no list" test ! -e "$lists/zig/0.17.0/zig-x86_64-linux-0.17.0.stat"

fresh
mkdir -p "$cache/zig/0.17.0/.zig-x86_64-linux-0.17.0.part" "$cache/node/22/x64"
ln -s "$tree" "$cache/zig/0.17.0/link"
printf 'node\n' >"$cache/node/22/x64/node"
expect "another tool's tree is checked too" "^[0-9a-f]{64} $cache/node/22/x64 1 1\$"
count() { [ "$(lines | wc -l)" = "$1" ]; }
ok "...but not a dot-named or symlinked one" count 2
rm -rf "$cache/node"
expect "a tree that is gone" "^$sum "
ok "...loses its list" test ! -e "$lists/node/22/x64.stat"

# install-zig.sh skips its own check only for its own tree with its pinned digest.
verdict() {
	# shellcheck disable=SC2034 # read by install-zig.sh's checked(), defined by the eval below
	local tree_sum=$1 tree=$2 ZIG_RUNNER_TOOL_TREES=$3
	eval "$(grep '^checked()' "$root/.github/scripts/install-zig.sh")"
	checked
}
ok "install-zig.sh takes the runner's verdict for its tree" verdict "$sum" "$tree" "$(printf 'aa %s\n%s %s' "$cache/x" "$sum" "$tree")"
ok "...not another digest" not verdict "$sum" "$tree" "0$sum $tree"
ok "...nor another tree's" not verdict "$sum" "$tree" "$sum $tree-x"
ok "...nor a line that only contains it" not verdict "$sum" "$tree" "x$sum $tree"
ok "...nor no verdict" not verdict "$sum" "$tree" ""

if [ "$failures" != 0 ]; then
	echo "$failures failures" >&2
	exit 1
fi
echo "tool-trees: all passed"
