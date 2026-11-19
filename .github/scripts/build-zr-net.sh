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
# What this build was asked for cannot change under it: a script sourced below that assigns one of
# these fails at once, naming it (install-rust.sh's own `arch` once replaced this one silently).
readonly arch out libc
# Said before anything is sourced, so the log has the request as it came, whatever follows.
echo "build-zr-net.sh: asked for $arch ($libc), out $out" >&2
# The pinned Rust, always: `tsan` the pinned nightly (install-rust-nightly.sh), the others
# install-rust.sh's hash-pinned 1.99.1, from the tool cache. Never the cargo that happens to be on
# PATH (rustup's, on a hosted runner image that has 1.99.1 and not on one that has not: the image
# must not choose the path), so cargo and rustc are RUST_HOME's below, checked.
if [[ $libc == tsan ]]; then
	rust_from="the pinned nightly (install-rust-nightly.sh)"
	# shellcheck source=.github/scripts/install-rust-nightly.sh
	. "$here/install-rust-nightly.sh"
else
	# shellcheck source=.github/scripts/install-rust.sh
	. "$here/install-rust.sh"
	rust_from="install-rust.sh ($rust_how)"
	if [[ $(command -v cargo) != "$RUST_HOME/bin/cargo" || $(command -v rustc) != "$RUST_HOME/bin/rustc" ]]; then
		echo "build-zr-net.sh: cargo is $(command -v cargo) and rustc $(command -v rustc), not the ones in $RUST_HOME/bin" >&2
		exit 1
	fi
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
# CI restores the toolchain and the target directory from a cache (.github/actions/rust-cache,
# docs/rust-net.md): what it restored, and under which key, is in ZR_RUST_CACHE.
echo "build-zr-net.sh: rust cache: ${ZR_RUST_CACHE:-none (not CI, or a job without it)}" >&2
# In the job's log, what the build is and what it builds with: cargo's target (beside the request
# logged above), which Rust and from where, and where it builds.
# Asked here in runner/rust, where a rustup shim would follow rust-toolchain.toml: the stable
# build's cargo is install-rust.sh's own (checked above), the tsan build's the pinned nightly's.
echo "build-zr-net.sh: building $arch ($libc): cargo target $triple; $(cargo --version) at $(command -v cargo), $(rustc --version) at $(command -v rustc), from $rust_from, in $PWD; CARGO_TARGET_DIR $CARGO_TARGET_DIR" >&2
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
# fail when index.crates.io cannot be resolved (it did, in one of main's runs).
# Cargo does not check a crate it finds unpacked in the registry's `src/` again: the registry is
# only ever one trust scope's. "Holds crates" is only that registry/cache has a .crate file, so a
# registry missing some of them fails the offline build and the retry fetches them. That retry
# also follows any other failure; it prints the real error, and the first attempt's output is shown
# only when it succeeds.
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
# The archive is for $arch, checked by the ELF machine of its first object (e_machine, at offset 18:
# 62 x86_64, 183 aarch64): built for another, it fails here, by name, not as the link's hundreds of
# "incompatible with" lines.
case $arch in
x86_64) want=62 ;;
aarch64) want=183 ;;
esac
# Neither read stops early in a pipe (`grep -m1`, `od -N2` on `ar p`): `ar` would die of SIGPIPE,
# and pipefail would fail the build for it.
member=$(ar t "$out" | awk '/\.o$/ && !seen { print; seen = 1 }')
if [[ -z $member ]]; then
	echo "build-zr-net.sh: $out has no object (.o) member to check its architecture by" >&2
	exit 1
fi
# No trap of its own: it would replace the one a sourced installer set for its work directory.
object=$(mktemp)
ar p "$out" "$member" >"$object" || {
	rm -f "$object"
	exit 1
}
got=$(od -An -tu2 -j18 -N2 "$object" | tr -d ' ')
rm -f "$object"
if [[ $got != "$want" ]]; then
	echo "build-zr-net.sh: $out is not for $arch: $member has ELF machine $got, not $want" >&2
	exit 1
fi
echo "build-zr-net.sh: $out: for $arch (ELF machine $got in $member), $(ar t "$out" | wc -l) members, sha256 $(sha256sum "$out" | cut -d' ' -f1)" >&2
