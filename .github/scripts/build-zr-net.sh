#!/usr/bin/env bash
# The network library (runner/rust/zr-net, docs/rust-net.md) as a static archive for one
# architecture, built with cargo and `zig cc` (zig-cc.sh) for the musl targets. runner/build.zig's
# `addZrNet` runs this same script, and the release (build-binaries.sh) too, so the three agree.
#
#   build-zr-net.sh x86_64|aarch64 OUT.a
#
# Cargo.lock is committed and `--locked` makes a stale one an error. CARGO_TARGET_DIR defaults to
# runner/rust/target (gitignored), so cargo's own cache serves every build on the machine.
set -euo pipefail
arch=${1:?usage: build-zr-net.sh ARCH OUT.a}
out=$(realpath -m "${2:?usage: build-zr-net.sh ARCH OUT.a}")
here=$(cd "$(dirname "$0")" && pwd)
# The pinned Rust (install-rust.sh): rustup's, when the machine has it and rust-toolchain.toml
# picks this version, or one unpacked into the tool cache.
if [[ $(cargo --version 2>/dev/null | cut -d' ' -f2) != 1.99.1 ]]; then
	# shellcheck source=.github/scripts/install-rust.sh
	. "$here/install-rust.sh"
fi
cd "$here/../../runner/rust"
case $arch in
x86_64 | aarch64) ;;
*)
	echo "build-zr-net.sh: x86_64 or aarch64, not $arch" >&2
	exit 1
	;;
esac
triple=$arch-unknown-linux-musl
upper=$(tr a-z- A-Z_ <<<"$triple")
export ZR_ZIG_TARGET=$arch-linux-musl
export "CC_${triple//-/_}=$here/zig-cc.sh"
export "AR_${triple//-/_}=${AR_ZIG:-ar}"
export "CARGO_TARGET_${upper}_LINKER=$here/zig-cc.sh"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/target}
cargo build --release --locked --manifest-path zr-net/Cargo.toml --target "$triple" >&2
mkdir -p "$(dirname "$out")"
cp "$CARGO_TARGET_DIR/$triple/release/libzr_net.a" "$out"
