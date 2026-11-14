#!/usr/bin/env bash
# The network library (runner/rust/zr-net, docs/rust-net.md) as a static archive for one
# architecture, built with cargo and `zig cc` (zig-cc.sh) for the musl targets. runner/build.zig's
# `addZrNet` runs this same script, and the release (build-binaries.sh) too, so the three agree.
#
#   build-zr-net.sh x86_64|aarch64 OUT.a [musl|gnu|tsan]
#
# musl, except for the ThreadSanitizer builds, whose runtime needs glibc (zig-test.sh): those take
# `tsan`, the gnu target built with `-Zsanitizer=thread -Zbuild-std` by a pinned nightly
# (install-rust-nightly.sh), so TSan sees the library's atomics and its standard library's
# (docs/rust-net.md, "ThreadSanitizer"). `gnu` is the same target uninstrumented, with the stable Rust.
#
# Cargo.lock is committed and `--locked` makes a stale one an error. CARGO_TARGET_DIR defaults to
# runner/rust/target (gitignored), so cargo's own cache serves every build on the machine.
set -euo pipefail
arch=${1:?usage: build-zr-net.sh ARCH OUT.a}
out=$(realpath -m "${2:?usage: build-zr-net.sh ARCH OUT.a}")
here=$(cd "$(dirname "$0")" && pwd)
libc=${3:-musl}
case $libc in
musl | gnu | tsan) ;;
*)
	echo "build-zr-net.sh: musl, gnu or tsan, not $libc" >&2
	exit 1
	;;
esac
# The pinned Rust (install-rust.sh): rustup's, when the machine has it and rust-toolchain.toml
# picks this version, or one unpacked into the tool cache. `tsan`: the pinned nightly, always from
# the tool cache (rustup's shims would follow rust-toolchain.toml to the stable one).
if [[ $libc == tsan ]]; then
	# shellcheck source=.github/scripts/install-rust-nightly.sh
	. "$here/install-rust-nightly.sh"
elif [[ $(cargo --version 2>/dev/null | cut -d' ' -f2) != 1.99.1 ]]; then
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
triple=$arch-unknown-linux-${libc/tsan/gnu}
upper=$(tr a-z- A-Z_ <<<"$triple")
export ZR_ZIG_TARGET=$arch-linux-${libc/tsan/gnu}
export "CC_${triple//-/_}=$here/zig-cc.sh"
export "AR_${triple//-/_}=${AR_ZIG:-ar}"
export "CARGO_TARGET_${upper}_LINKER=$here/zig-cc.sh"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/target}
# In a job, cargo's registry and crate cache go in the job's own temp directory: a self-hosted
# runner's $HOME/.cargo can belong to another user (main's first Rust build failed there with
# "Permission denied"), and one job's downloaded crates are not meant to reach another's build.
if [[ -n ${RUNNER_TEMP:-} && -z ${CARGO_HOME:-} ]]; then
	export CARGO_HOME=$RUNNER_TEMP/cargo-home
fi
if [[ $libc == tsan ]]; then
	# With --target, RUSTFLAGS reach the target's crates and not the build scripts (host tools), and
	# -Zbuild-std rebuilds std, core and alloc with the sanitizer: an uninstrumented std would hide
	# the synchronisation of every lock and channel from TSan. Its own target directory: the
	# instrumented std must not be mixed with the plain one.
	export CARGO_TARGET_DIR=$CARGO_TARGET_DIR/tsan
	export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=thread"
	cargo build --release --locked --manifest-path zr-net/Cargo.toml --target "$triple" \
		-Zbuild-std=std,panic_abort >&2
else
	cargo build --release --locked --manifest-path zr-net/Cargo.toml --target "$triple" >&2
fi
mkdir -p "$(dirname "$out")"
cp "$CARGO_TARGET_DIR/$triple/release/libzr_net.a" "$out"
