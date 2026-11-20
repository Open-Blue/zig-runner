#!/usr/bin/env bash
# The proof behind the Rust build cache's keys (docs/rust-net.md, "The build cache"): the keys do not
# hold the runner image, so no build may read its C toolchain. Builds the musl and the gnu archive
# in a fresh target directory with shims on PATH named cc, gcc, c++, clang, ld, ld.bfd, ld.gold,
# ld.lld, ar, ranlib and the like, each failing loudly: a cargo, cc-rs or rustc that reaches for one
# fails the build and names it. Zig (install-zig.sh) must be on PATH.
#
#   rust-image-free-check.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/shims"
for tool in cc gcc g++ c++ cpp clang clang++ ld ld.bfd ld.gold ld.lld ar ranlib nm objcopy strip as; do
	# shellcheck disable=SC2016 # $0 and $* are the shim's own, expanded when it runs
	printf '#!/bin/sh\necho "SHIM: the system tool %s was used: $0 $*" >&2\nexit 99\n' "$tool" >"$work/shims/$tool"
	chmod +x "$work/shims/$tool"
done
# What a build script or cc-rs would pick up from the environment instead.
unset CC CXX AR LD CFLAGS RUSTFLAGS
export PATH="$work/shims:$PATH"
echo "rust-image-free-check.sh: cc is $(command -v cc), ar is $(command -v ar): both fail on use"
arch=$(uname -m)
for libc in musl gnu; do
	CARGO_TARGET_DIR=$work/target "$here/build-zr-net.sh" "$arch" "$work/$libc.a" "$libc"
	echo "rust-image-free-check.sh: $libc built with failing system tools: $(sha256sum "$work/$libc.a" | cut -c1-16)"
done
