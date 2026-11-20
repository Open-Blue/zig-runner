#!/usr/bin/env bash
# `zig cc` for the host side of cargo's builds (build scripts, proc-macros, their C): the same Zig
# as zig-cc.sh, for ZR_ZIG_HOST_TARGET (x86_64-linux-gnu.2.28, set by zig-cc-env.sh), so what the
# host side makes does not depend on the machine's cc, ld or glibc (docs/rust-net.md, "The build
# cache").
set -euo pipefail
ZR_ZIG_TARGET=${ZR_ZIG_HOST_TARGET:?} exec "$(dirname "$0")/zig-cc.sh" "$@"
