#!/usr/bin/env bash
# The network library's own tests (runner/rust/zr-net, docs/rust-net.md): `cargo test` on the
# machine's target, with the pinned Rust (install-rust.sh, as build-zr-net.sh finds it). They cover
# what the Zig tests cannot see from outside the ABI: the TLS state machine against an in-process
# rustls server (names, CAs, client certificates), the roots loader, malformed input.
#
#   cargo-test.sh          the tests, on the pinned stable Rust
#   cargo-test.sh tsan     the same under ThreadSanitizer: the pinned nightly (install-rust-nightly.sh)
#                          with -Zsanitizer=thread and -Zbuild-std, so races among the library's own
#                          threads (tokio's workers, the client's pool and timers) are found where Zig's
#                          TSan never looks. x86_64 only (the host's gnu target); the one report that is
#                          not a race is suppressed by .github/tsan.supp, as in the Zig tests.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mode=${1:-}
case $mode in
"")
	if [[ $(cargo --version 2>/dev/null | cut -d' ' -f2) != 1.99.1 ]]; then
		# shellcheck source=.github/scripts/install-rust.sh
		. "$here/install-rust.sh"
	fi
	cd "$here/../../runner/rust/zr-net"
	export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/../target}
	cargo test --locked
	;;
tsan)
	# shellcheck source=.github/scripts/install-rust-nightly.sh
	. "$here/install-rust-nightly.sh"
	triple=$(uname -m)-unknown-linux-gnu
	cd "$here/../../runner/rust/zr-net"
	export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/../target}/tsan-test
	export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=thread"
	# Optimised: the handshakes of the TLS tests are slow enough at -O0 with TSan's slowdown on top.
	export CARGO_PROFILE_DEV_OPT_LEVEL=2
	export TSAN_OPTIONS="suppressions=$(realpath ../../../.github/tsan.supp) ${TSAN_OPTIONS:-}"
	# The test profile, not release: release is panic=abort, which the test harness cannot be. Not
	# the doctests (rustdoc would need the same flag, and the crate has none).
	# Skipped: the one test that asserts wall-clock bounds on each phase of a request (getaddrinfo of
	# `localhost` alone took 262 ms in one run under TSan, the bound is 50): it measures phases, not
	# threads, and runs in the plain cargo test.
	cargo test --locked --lib --tests -Zbuild-std --target "$triple" -- --skip each_phase_is_measured_where_it_happens
	;;
*)
	echo "usage: cargo-test.sh [tsan]" >&2
	exit 1
	;;
esac
