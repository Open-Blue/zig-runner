#!/usr/bin/env bash
# Rust 1.99.1 for building runner/rust/zr-net (docs/rust-net.md), without rustup: cargo, rustc and
# the standard library for this machine and for both musl targets, from static.rust-lang.org, each
# tarball checked against the SHA-256 the release's manifest
# (https://static.rust-lang.org/dist/channel-rust-1.99.1.toml) gives, pinned here, so a changed
# tarball fails the job. A new Rust version means new hashes from that manifest, the same version in
# runner/rust/rust-toolchain.toml (what rustup follows on a developer's machine), and a new cargo
# cache key. Unpacked into RUNNER_TOOL_CACHE (or ~/.cache/zig-runner-rust), once per version, and
# the unpacked tree checked against a digest of its files (`tree_sum`, the way install-zig.sh does).
#
#   . install-rust.sh         sets RUST_HOME and puts RUST_HOME/bin on PATH
#   install-rust.sh           prints RUST_HOME
#
# build-zr-net.sh and cargo-test.sh always source this (never the cargo already on PATH), so no job's steps change.
#
# Sourced, its variables are the caller's: each is `rust_`-prefixed, so none takes a name a caller
# uses. Its `arch` was the machine's and replaced build-zr-net.sh's own, so on a runner without
# this Rust an aarch64 build built x86_64 again and copied it under the aarch64 name.
set -euo pipefail

rust_version=1.99.1
rust_arch=${ZR_RUST_ARCH:-$(uname -m)}
case $rust_arch in
x86_64)
	rust_tree_sum=ddbc0eb9ae4347f627aacc9d09cee807e027c7327abbfc3d578fa177b8171a69
	rust_host_sums=(
		cargo-1.99.1-x86_64-unknown-linux-gnu=53f3521949404d595efb06a55c12c5658d4ed1c75566f33d3d514eaebe70bd8a
		rustc-1.99.1-x86_64-unknown-linux-gnu=2ff05ff9c08a90861e7f6e4065b40a8b87463b4576186fd613871c3e37f2091f
		rust-std-1.99.1-x86_64-unknown-linux-gnu=109b074225bf5b9ea3820890876bfdf4ed161adbfaf94b2b4b5984c85ee5d958
	)
	;;
aarch64)
	rust_tree_sum=2c2919ea635ff54cddfaf237b19bd49651463ec3167160131ee04355b496ab4c
	rust_host_sums=(
		cargo-1.99.1-aarch64-unknown-linux-gnu=5156832e0c1254e9b49a79edabdc6d4c35f32f8fc1cf3ca700f268ff96087ab0
		rustc-1.99.1-aarch64-unknown-linux-gnu=acdcdfe09ae1f103aa9a2b7f88903a9588bc2e99288af10e6fbf5514e2e49f25
		rust-std-1.99.1-aarch64-unknown-linux-gnu=e25668477083d6a9ddb87b9beb9c00742225f38233ccb4bfba3afa7a07427f52
	)
	;;
*)
	echo "no Rust $rust_version checksums for $rust_arch" >&2
	exit 1
	;;
esac
rust_sums=("${rust_host_sums[@]}"
	rust-std-1.99.1-x86_64-unknown-linux-musl=1dd241eaeb19ff3b5180461c77bdee93d6cafc669eda9de834e7c06b0ec3ca95
	rust-std-1.99.1-aarch64-unknown-linux-musl=2f3eb0d0610e2b7f6b2121d106e2490ac648decfa0c09b30873bdfc60de6c1ab)

# actions/tool-cache's layout, TOOL/VERSION/NAME, which zig-runner's "Set up job" digests (the tool
# cache is the one place that lasts between jobs on a self-hosted runner, jobs can write it, and the
# tree is checked below as install-zig.sh checks Zig's). Outside a runner: ~/.cache.
rust_root=${RUNNER_TOOL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/zig-runner-rust}
rust_tool=$rust_root/rust/$rust_version
RUST_HOME=$rust_tool/$rust_arch
rust_digest() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); }
# Only regular files and directories are in the digest: a link planted in the tree would not be.
rust_plain() { [[ -z $(find "$1" ! -type f ! -type d -print -quit 2>/dev/null) ]]; }
rust_how="reused $RUST_HOME, its files matching their digest"
if ! { [[ -x $RUST_HOME/bin/cargo ]] && rust_plain "$RUST_HOME" && [[ $(rust_digest "$RUST_HOME") == "$rust_tree_sum" ]]; }; then
	rust_work=$(mktemp -d)
	rust_how="unpacked into $RUST_HOME from checked tarballs"
	trap 'rm -rf "$rust_work"' EXIT
	for rust_entry in "${rust_sums[@]}"; do
		rust_file=${rust_entry%%=*} rust_sum=${rust_entry#*=}
		for rust_attempt in 1 2 3; do
			curl -fsSL --retry 3 -o "$rust_work/$rust_file.tar.xz" "https://static.rust-lang.org/dist/$rust_file.tar.xz" && break
			((rust_attempt < 3)) || exit 1
			sleep $((rust_attempt * 5))
		done
		echo "$rust_sum  $rust_work/$rust_file.tar.xz" | sha256sum -c --quiet - >&2
		tar -xJf "$rust_work/$rust_file.tar.xz" -C "$rust_work"
		# A fixed prefix, so the manifests hold no temporary path and the tree's digest is the same
		# on every machine; the files land under --destdir.
		"$rust_work/$rust_file/install.sh" --prefix=/rust --destdir="$rust_work/home" --disable-ldconfig >&2
		rm -rf "${rust_work:?}/$rust_file" "$rust_work/$rust_file.tar.xz"
	done
	# install.log and uninstall.sh name the temporary directory, and the manifests the destdir.
	sed -i "s|file:$rust_work/home|file:|" "$rust_work"/home/rust/lib/rustlib/manifest-*
	rm -f "$rust_work/home/rust/lib/rustlib/install.log" "$rust_work/home/rust/lib/rustlib/uninstall.sh"
	rust_got=$(rust_digest "$rust_work/home/rust")
	if [[ $rust_got != "$rust_tree_sum" ]]; then
		echo "Rust $rust_version for $rust_arch unpacked to files that hash to $rust_got, not $rust_tree_sum: update tree_sum" >&2
		exit 1
	fi
	mkdir -p "$rust_tool"
	rm -rf "$RUST_HOME"
	mv -T "$rust_work/home/rust" "$RUST_HOME"
fi
echo "install-rust.sh: Rust $rust_version for $rust_arch: $rust_how" >&2
export RUST_HOME
export PATH=$RUST_HOME/bin:$PATH
if ! (return 0 2>/dev/null); then echo "$RUST_HOME"; fi
