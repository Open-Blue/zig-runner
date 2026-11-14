#!/usr/bin/env bash
# `zig cc` as the C compiler and linker of cargo's musl builds (build-zr-net.sh): the C in Rust
# crates (ring's) is built for the target by Zig's bundled clang and musl, with no cross toolchain
# installed. ZR_ZIG_TARGET names the target (x86_64-linux-musl). Two flags that rustc and cc-rs pass
# are not Zig's: `--target=...` (the target is ours) and `--fix-cortex-a53-843419` (a linker flag
# for old Cortex-A53 cores; zig's lld takes it as `-z`-less unknown, so it is dropped: a staticlib
# is not linked here anyway, the runner's link is Zig's).
set -euo pipefail
args=()
for a in "$@"; do
	case $a in
	--target=* | --fix-cortex-a53-843419 | -Wl,--fix-cortex-a53-843419) ;;
	*) args+=("$a") ;;
	esac
done
exec zig cc -target "${ZR_ZIG_TARGET:?}" "${args[@]}"
