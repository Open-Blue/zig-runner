#!/usr/bin/env bash
# Rust 1.99.1 for building runner/rust/zr-net (docs/rust-net.md), without rustup: cargo, rustc and
# the standard library for this machine and for both musl targets, from static.rust-lang.org, each
# tarball checked against the SHA-256 the release's manifest
# (https://static.rust-lang.org/dist/channel-rust-1.99.1.toml) gives, pinned here, so a changed
# tarball fails the job. A new Rust version means new hashes from that manifest, the same version in
# runner/rust/rust-toolchain.toml (what rustup follows on a developer's machine), and a new cargo
# cache key. Unpacked into RUNNER_TOOL_CACHE (or ~/.cache/zig-runner-rust), once per version.
#
#   . install-rust.sh         sets RUST_HOME and puts RUST_HOME/bin on PATH
#   install-rust.sh           prints RUST_HOME
#
# build-zr-net.sh runs this itself when `cargo` is not this version, so no job's steps change.
set -euo pipefail

version=1.99.1
arch=$(uname -m)
case $arch in
x86_64)
	host_sums=(
		cargo-1.99.1-x86_64-unknown-linux-gnu=53f3521949404d595efb06a55c12c5658d4ed1c75566f33d3d514eaebe70bd8a
		rustc-1.99.1-x86_64-unknown-linux-gnu=2ff05ff9c08a90861e7f6e4065b40a8b87463b4576186fd613871c3e37f2091f
		rust-std-1.99.1-x86_64-unknown-linux-gnu=109b074225bf5b9ea3820890876bfdf4ed161adbfaf94b2b4b5984c85ee5d958
	)
	;;
aarch64)
	host_sums=(
		cargo-1.99.1-aarch64-unknown-linux-gnu=5156832e0c1254e9b49a79edabdc6d4c35f32f8fc1cf3ca700f268ff96087ab0
		rustc-1.99.1-aarch64-unknown-linux-gnu=acdcdfe09ae1f103aa9a2b7f88903a9588bc2e99288af10e6fbf5514e2e49f25
		rust-std-1.99.1-aarch64-unknown-linux-gnu=e25668477083d6a9ddb87b9beb9c00742225f38233ccb4bfba3afa7a07427f52
	)
	;;
*)
	echo "no Rust $version checksums for $arch" >&2
	exit 1
	;;
esac
sums=("${host_sums[@]}"
	rust-std-1.99.1-x86_64-unknown-linux-musl=1dd241eaeb19ff3b5180461c77bdee93d6cafc669eda9de834e7c06b0ec3ca95
	rust-std-1.99.1-aarch64-unknown-linux-musl=2f3eb0d0610e2b7f6b2121d106e2490ac648decfa0c09b30873bdfc60de6c1ab)

root=${RUNNER_TOOL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/zig-runner-rust}
RUST_HOME=$root/rust-$version-$arch
if [[ ! -x $RUST_HOME/bin/cargo ]]; then
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	for entry in "${sums[@]}"; do
		file=${entry%%=*} sum=${entry#*=}
		for attempt in 1 2 3; do
			curl -fsSL --retry 3 -o "$work/$file.tar.xz" "https://static.rust-lang.org/dist/$file.tar.xz" && break
			((attempt < 3)) || exit 1
			sleep $((attempt * 5))
		done
		echo "$sum  $work/$file.tar.xz" | sha256sum -c --quiet - >&2
		tar -xJf "$work/$file.tar.xz" -C "$work"
		"$work/$file/install.sh" --prefix="$work/home" --disable-ldconfig >&2
		rm -rf "${work:?}/$file" "$work/$file.tar.xz"
	done
	mkdir -p "$root"
	rm -rf "$RUST_HOME"
	mv "$work/home" "$RUST_HOME"
fi
export RUST_HOME
export PATH=$RUST_HOME/bin:$PATH
if ! (return 0 2>/dev/null); then echo "$RUST_HOME"; fi
