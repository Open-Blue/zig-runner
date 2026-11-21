#!/usr/bin/env bash
# clippy over the network library (runner/rust/zr-net), with the pinned Rust (install-rust.sh) and a
# clippy of the same version, whose tarball is checked against a digest here. The library's policy
# (docs/rust-net.md, "Risks"): `-D warnings`, and the crate itself denies `unwrap_used`, `expect_used`
# and `indexing_slicing` outside its tests (src/lib.rs), so a regression fails here.
#
# The pinned tree is checked against a digest by install-rust.sh and is not changed: clippy's two
# binaries go in a directory of their own, beside a link to the toolchain's libraries (they find
# librustc_driver through `../lib`).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=.github/scripts/install-rust.sh
. "$here/install-rust.sh"
case $rust_arch in
x86_64)
	clippy_sum=458339712a058e52cc4522ff9ef8b59cd1ea1340312216cd94194c464a3f6dc5
	clippy_bins_sum=73fe0820179ef2e5964bbe499f1f748bd9a9775ea1fcff2c16a923205402bda3
	;;
aarch64)
	clippy_sum=3bea76c26dcf30c176c0a8a8cc283eb59fabd754e24a68b4ca0701e5f3245f6b
	clippy_bins_sum=b68c6510e1de4d1331d7b5dbb64814cfafe1eaa1ffca7c89c3bc925cdb518c1d
	;;
*)
	echo "clippy.sh: no clippy checksum for $rust_arch" >&2
	exit 1
	;;
esac
clippy_file=clippy-$rust_version-$rust_arch-unknown-linux-gnu
clippy_home=$rust_tool/clippy-$rust_arch
# What is in the tool cache is checked on every use, as the toolchain's tree is: the digest of the two
# binaries (cargo-clippy then clippy-driver, concatenated) is pinned here, and a mismatch installs again.
clippy_have() { [[ -x $clippy_home/bin/cargo-clippy && -x $clippy_home/bin/clippy-driver && $(cat "$clippy_home/bin/cargo-clippy" "$clippy_home/bin/clippy-driver" | sha256sum | cut -d' ' -f1) == "$clippy_bins_sum" ]]; }
if ! clippy_have; then
	clippy_work=$(mktemp -d)
	trap 'rm -rf "$clippy_work"' EXIT
	for clippy_attempt in 1 2 3; do
		curl -fsSL --retry 3 -o "$clippy_work/$clippy_file.tar.xz" "https://static.rust-lang.org/dist/$clippy_file.tar.xz" && break
		((clippy_attempt < 3)) || exit 1
		sleep $((clippy_attempt * 5))
	done
	echo "$clippy_sum  $clippy_work/$clippy_file.tar.xz" | sha256sum -c --quiet - >&2
	tar -xJf "$clippy_work/$clippy_file.tar.xz" -C "$clippy_work"
	rm -rf "$clippy_home"
	mkdir -p "$clippy_home/bin"
	cp "$clippy_work/$clippy_file/clippy-preview/bin/cargo-clippy" "$clippy_work/$clippy_file/clippy-preview/bin/clippy-driver" "$clippy_home/bin/"
	ln -s "$RUST_HOME/lib" "$clippy_home/lib"
	clippy_have || {
		echo "clippy.sh: the binaries of $clippy_file are not the ones whose digest is pinned: update clippy_bins_sum" >&2
		exit 1
	}
fi
# In a job, cargo's registry goes in the job's temp directory, as in cargo-test.sh (#543).
if [[ -n ${RUNNER_TEMP:-} && -z ${CARGO_HOME:-} ]]; then
	export CARGO_HOME=$RUNNER_TEMP/cargo-home
fi
cd "$here/../../runner/rust/zr-net"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/../target}
# The pinned cargo and rustc first on PATH (install-rust.sh), clippy's binaries before any rustup shim.
PATH=$RUST_HOME/bin:$clippy_home/bin:$PATH
echo "clippy.sh: $(cargo --version), clippy from $clippy_home" >&2
cargo clippy --locked --lib -- -D warnings
