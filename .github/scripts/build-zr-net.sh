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
# runner/rust/target (gitignored), so cargo's own cache serves every build on the machine; the
# runner sets it for jobs of a trusted scope (RUNNER_CARGO_TARGET_CACHE), so a fresh checkout's
# build does not start from nothing.
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
# Unless ~/.cargo/registry is a mount of its own: zig-runner mounts it from a volume of the job's
# trust scope (`cargo-registry`, docs/OPERATIONS.md), so its crates reach only jobs the runner
# trusts as much, and they are kept for the next build.
if [[ -n ${RUNNER_TEMP:-} && -z ${CARGO_HOME:-} ]] &&
	! awk -v p="$HOME/.cargo/registry" '$5 == p { found = 1 } END { exit !found }' /proc/self/mountinfo 2>/dev/null; then
	export CARGO_HOME=$RUNNER_TEMP/cargo-home
fi
# Build offline first when the registry already holds crates: with every crate of Cargo.lock
# present (`--frozen` is `--locked --offline`) the build needs no network at all, and so does not
# fail when index.crates.io cannot be resolved (it did, in one of main's runs). Cargo does not
# check a crate it finds unpacked in the registry's `src/` again: the registry is only ever one
# trust scope's. "Holds crates" is only that registry/cache has a .crate file, so a registry
# missing some of them fails the offline build and the retry fetches them. Missing crates, or any other failure, repeat the build online, which prints the
# real error; the first attempt's output is kept for that case only.
cargo_release() {
	local cache=${CARGO_HOME:-$HOME/.cargo}/registry/cache log
	if compgen -G "$cache/*/*.crate" >/dev/null; then
		log=$(mktemp)
		if cargo build --release --frozen "$@" >"$log" 2>&1; then
			cat "$log" >&2
			rm -f "$log"
			return 0
		fi
		echo "build-zr-net.sh: not buildable offline, trying again with the network" >&2
		rm -f "$log"
	fi
	cargo build --release --locked "$@" >&2
}
if [[ $libc == tsan ]]; then
	# With --target, RUSTFLAGS reach the target's crates and not the build scripts (host tools), and
	# -Zbuild-std rebuilds std, core and alloc with the sanitizer: an uninstrumented std would hide
	# the synchronisation of every lock and channel from TSan. Its own target directory: the
	# instrumented std must not be mixed with the plain one.
	export CARGO_TARGET_DIR=$CARGO_TARGET_DIR/tsan
	export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=thread"
	cargo_release --manifest-path zr-net/Cargo.toml --target "$triple" -Zbuild-std=std,panic_abort
else
	cargo_release --manifest-path zr-net/Cargo.toml --target "$triple"
fi
mkdir -p "$(dirname "$out")"
cp "$CARGO_TARGET_DIR/$triple/release/libzr_net.a" "$out"
