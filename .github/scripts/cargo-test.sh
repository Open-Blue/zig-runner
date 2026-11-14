#!/usr/bin/env bash
# The network library's own tests (runner/rust/zr-net, docs/rust-net.md): `cargo test` on the
# machine's target, with the pinned Rust (install-rust.sh, as build-zr-net.sh finds it). They cover
# what the Zig tests cannot see from outside the ABI: the TLS state machine against an in-process
# rustls server (names, CAs, client certificates), the roots loader, malformed input.
#
#   cargo-test.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
if [[ $(cargo --version 2>/dev/null | cut -d' ' -f2) != 1.99.1 ]]; then
	# shellcheck source=.github/scripts/install-rust.sh
	. "$here/install-rust.sh"
fi
cd "$here/../../runner/rust/zr-net"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/../target}
# In a job, cargo's registry goes in the job's temp directory, as in build-zr-net.sh (#543).
if [[ -n ${RUNNER_TEMP:-} && -z ${CARGO_HOME:-} ]]; then
	export CARGO_HOME=$RUNNER_TEMP/cargo-home
fi
cargo test --locked
