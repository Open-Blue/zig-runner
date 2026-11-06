#!/usr/bin/env bash
# Installs Zig for this job and puts it on the job's PATH. The download is checked against the
# checksum ziglang.org publishes (https://ziglang.org/download/index.json), pinned here, so a
# changed or replaced tarball fails the job instead of building the release. A new Zig version
# means new checksums from that index, the same version in runner/build.zig.zon, and a new
# RUNNER_ZIG_SEED for runners that seed Zig caches (deploy/runner.env.example).
#
# Zig is unpacked into RUNNER_TOOL_CACHE, which a self-hosted runner keeps between jobs, and the
# unpacked tree is checked against a digest of all its files, pinned here too: a tree that another
# job changed is unpacked afresh, never used. On a Raspberry Pi, unpacking costs 9-16 s in a job
# and writes 588 MB to its disk; the check costs 2-10 s, depending on how much of the tree the page
# cache still holds, and writes nothing. The tree's digest is
#
#   find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
#
# run inside the tree unpacked from the checked tarball.
#
# zig-runner computes the same digest of every tree in the tool cache in "Set up job", before any
# step of the job can write there, from lists no step can reach (runner/src/dagger/tool_trees.sh),
# and passes each tree's path and digest in ZIG_RUNNER_TOOL_TREES. When it names this tree with the
# pinned digest, the tree is the one checked and this script does not read it again (0.7-1 s on
# the laptop, 10-19 s on razorbill under load). Anything else, the variable unset on GitHub's
# runners included, means the check here. Either way a tree with an entry that is not a file or a
# directory is not used (`plain`).
set -euo pipefail

version=0.17.0
arch=$(uname -m)
case $arch in
x86_64)
	sum=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
	tree_sum=310d0a4a95f328f94a350c4339226a4796daee589472b23f2a816d18874efaed
	;;
aarch64)
	sum=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
	tree_sum=aff98cd78f2569e83921f68c455fbfa81218d24718f8c24698f0ec10de4e9db8
	;;
*)
	echo "no Zig $version checksum for $arch" >&2
	exit 1
	;;
esac

dir="zig-$arch-linux-$version"
cache="${RUNNER_TOOL_CACHE:-${RUNNER_TEMP:-/tmp}}/zig/$version"
tarball="$cache/$dir.tar.xz"
tree="$cache/$dir"
verified() { echo "$sum  $tarball" | sha256sum --check --quiet --status; }
digest() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); }

checked() { grep -qxF "$tree_sum $tree" <<<"${ZIG_RUNNER_TOOL_TREES:-}"; }
# The digest is of regular files only, so a link, a pipe or a device in the tree is in no digest,
# and a job that planted one beside the files (zig -> a tool of its own) would have it on PATH
# with the pinned digest still matching. Zig's tarballs hold none (checked for x86_64 and aarch64
# at 0.17.0): a tree with one is not the tree, whoever says it was checked.
plain() { [ -z "$(find "$1" ! -type f ! -type d -print -quit 2>/dev/null)" ]; }

if checked && [ -d "$tree" ] && plain "$tree"; then
	echo "Zig $version: $tree is the tree zig-runner checked in Set up job"
elif [ ! -d "$tree" ] || ! plain "$tree" || [ "$(digest "$tree" 2>/dev/null)" != "$tree_sum" ]; then
	if ! verified 2>/dev/null; then
		mkdir -p "$cache"
		curl -fsSL -o "$tarball.part" "https://ziglang.org/download/$version/$dir.tar.xz"
		mv "$tarball.part" "$tarball"
		if ! verified; then
			echo "Zig $version for $arch does not match its pinned checksum" >&2
			rm -f "$tarball"
			exit 1
		fi
	fi
	# Unpacked beside the tree and moved into place whole, so a job running at the same time never
	# sees half a tree.
	part=$(mktemp -d "$cache/.$dir.XXXXXX")
	tar -xJf "$tarball" -C "$part"
	if [ "$(digest "$part/$dir")" != "$tree_sum" ]; then
		echo "Zig $version for $arch unpacked to files that do not match their pinned digest" >&2
		rm -rf "$part"
		exit 1
	fi
	rm -rf "$tree"
	mv -T "$part/$dir" "$tree" || { plain "$tree" && [ "$(digest "$tree")" = "$tree_sum" ]; }
	rm -rf "$part"
fi

echo "$tree" >>"$GITHUB_PATH"
