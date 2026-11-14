#!/usr/bin/env bash
# The nightly Rust of the ThreadSanitizer builds (build-zr-net.sh with `tsan`): runner/rust/zr-net
# built with `-Zsanitizer=thread -Zbuild-std`, so TSan sees the library's atomics and locks and its
# standard library's, which Zig's own TSan cannot see in an uninstrumented archive (docs/rust-net.md,
# "ThreadSanitizer"). The nightly of 2026-11-10 (rustc 1.102.0-nightly, ac8310ba6), installed the way
# install-rust.sh installs the stable one: dated tarballs (immutable, unlike `nightly`), each checked
# against the SHA-256 that day's manifest gives
# (https://static.rust-lang.org/dist/2026-11-10/channel-rust-nightly.toml), no rustup, the unpacked
# tree checked against a digest. rust-src is in it for -Zbuild-std; only the gnu host target's
# standard library, the one TSan builds use, is installed (build-std rebuilds it instrumented).
# A new nightly means new hashes from the manifest of its date and a new cargo cache key.
#
#   . install-rust-nightly.sh   sets RUST_NIGHTLY_HOME and puts its bin on PATH
#   install-rust-nightly.sh     prints RUST_NIGHTLY_HOME
set -euo pipefail

date=2026-11-10
arch=${ZR_RUST_ARCH:-$(uname -m)}
case $arch in
x86_64)
	tree_sum=1fd8f1c16174bc3a2d7a85fed3b9b8062a37a990b23400063ee862964e28e869
	sums=(
		cargo-nightly-x86_64-unknown-linux-gnu=b13b89ba39c5b472dc7457656f8bd72ad08f5c7d6f9bae8ba9fb82bc61059a7b
		rustc-nightly-x86_64-unknown-linux-gnu=4c34c8b44af403999f591758df471babc25b3996b546e82305fe882e9b31a3ee
		rust-std-nightly-x86_64-unknown-linux-gnu=4deaeefece150b68c57e0db83be5861c88fc4471f549726c7d56fe7b6577c85b
	)
	;;
aarch64)
	tree_sum=4dcd4b8533f570dd811a5f137d0d059a47871eb509e197f5b720d66df8b1e8f1
	sums=(
		cargo-nightly-aarch64-unknown-linux-gnu=0317e754aa7ea5c2f5fa10f2aef00007812fbd53290a9b449d164d06016550e4
		rustc-nightly-aarch64-unknown-linux-gnu=3684589e77c60bba13fe9fff825aa2143d0a45d9375caa29f4153b6a195a3ee0
		rust-std-nightly-aarch64-unknown-linux-gnu=0bbfe33850652cbfdf557c1d7d23ae9e86ad0d8272bc2ed30a16899b8faaef8d
	)
	;;
*)
	echo "no nightly Rust checksums for $arch" >&2
	exit 1
	;;
esac
sums+=(rust-src-nightly=cecf04d03254f8d42935eab3f1d8fa427b2135f9f9acd1f6d1c8860614571868)

# actions/tool-cache's layout, TOOL/VERSION/NAME, which zig-runner's "Set up job" digests (the tool
# cache is the one place that lasts between jobs on a self-hosted runner, jobs can write it, and the
# tree is checked below as install-zig.sh checks Zig's). Outside a runner: ~/.cache.
root=${RUNNER_TOOL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/zig-runner-rust}
tool=$root/rust-nightly/$date
RUST_NIGHTLY_HOME=$tool/$arch
digest() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); }
# Only regular files and directories are in the digest: a link planted in the tree would not be.
plain() { [[ -z $(find "$1" ! -type f ! -type d -print -quit 2>/dev/null) ]]; }
if ! { [[ -x $RUST_NIGHTLY_HOME/bin/cargo ]] && plain "$RUST_NIGHTLY_HOME" && [[ $(digest "$RUST_NIGHTLY_HOME") == "$tree_sum" ]]; }; then
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	for entry in "${sums[@]}"; do
		file=${entry%%=*} sum=${entry#*=}
		for attempt in 1 2 3; do
			curl -fsSL --retry 3 -o "$work/$file.tar.xz" "https://static.rust-lang.org/dist/$date/$file.tar.xz" && break
			((attempt < 3)) || exit 1
			sleep $((attempt * 5))
		done
		echo "$sum  $work/$file.tar.xz" | sha256sum -c --quiet - >&2
		tar -xJf "$work/$file.tar.xz" -C "$work"
		# A fixed prefix, so the manifests hold no temporary path and the tree's digest is the same
		# on every machine; the files land under --destdir.
		"$work/$file/install.sh" --prefix=/rust --destdir="$work/home" --disable-ldconfig >&2
		rm -rf "${work:?}/$file" "$work/$file.tar.xz"
	done
	# install.log and uninstall.sh name the temporary directory, and the manifests the destdir.
	sed -i "s|file:$work/home|file:|" "$work"/home/rust/lib/rustlib/manifest-*
	rm -f "$work/home/rust/lib/rustlib/install.log" "$work/home/rust/lib/rustlib/uninstall.sh"
	got=$(digest "$work/home/rust")
	if [[ $got != "$tree_sum" ]]; then
		echo "Nightly Rust $date for $arch unpacked to files that hash to $got, not $tree_sum: update tree_sum" >&2
		exit 1
	fi
	mkdir -p "$tool"
	rm -rf "$RUST_NIGHTLY_HOME"
	mv -T "$work/home/rust" "$RUST_NIGHTLY_HOME"
fi
export RUST_NIGHTLY_HOME
export PATH=$RUST_NIGHTLY_HOME/bin:$PATH
if ! (return 0 2>/dev/null); then echo "$RUST_NIGHTLY_HOME"; fi
