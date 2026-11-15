#!/usr/bin/env bash
# cargo-fuzz's targets for the network library (runner/rust/zr-net/fuzz; docs/rust-net.md): what an
# HTTP server answers the client with, what a caller's request becomes on the wire, and what a TLS
# server sends. They share the C ABI Zig calls, and Zig's own fuzz targets (runner/src/fuzz.zig,
# "HTTP responses", "TLS records") run the same code from the other side, in analysis.yml's Fuzz
# job; these are libFuzzer with AddressSanitizer, which needs the nightly Rust (install-rust-nightly.sh).
#
#   zr-net-fuzz.sh build            builds every target (a pull request that changes the library)
#   zr-net-fuzz.sh run SECONDS      runs each target for SECONDS, from the seeds in fuzz/seeds and
#                                   the corpus in fuzz/corpus (kept from night to night by the
#                                   workflow); a crash, a failed check or a hang fails it, leaving
#                                   the input under fuzz/artifacts
#
# cargo-fuzz is built from crates.io at its pinned version (--locked, its own lock file).
set -euo pipefail

version=0.13.2
cd "$(dirname "$0")/../../runner/rust/zr-net/fuzz"

# shellcheck source=.github/scripts/install-rust-nightly.sh
. ../../../../.github/scripts/install-rust-nightly.sh

tools=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cargo-fuzz-$version
if [[ ! -x $tools/bin/cargo-fuzz ]]; then
	cargo install cargo-fuzz --version "$version" --locked --root "$tools" >&2
fi
export PATH=$tools/bin:$PATH

targets=(http_response request_spec tls_records)

# cargo-fuzz has no --locked of its own: this fails when fuzz/Cargo.lock does not satisfy the
# manifests, which the build would otherwise rewrite (fuzz/Cargo.lock started as zr-net's lock file,
# so the library's dependencies are the versions the library is tested with).
cargo fetch --locked

case ${1:-} in
build)
	cargo fuzz build
	;;
run)
	seconds=${2:?run needs the seconds each target runs}
	for t in "${targets[@]}"; do
		mkdir -p "corpus/$t"
		# -timeout: a call that hangs is a finding; every wait inside it has its own limit below this.
		cargo fuzz run "$t" "corpus/$t" "seeds/$t" -- \
			-max_total_time="$seconds" -timeout=30 -rss_limit_mb=2048 -max_len=65536
	done
	;;
*)
	echo "usage: zr-net-fuzz.sh build | run SECONDS" >&2
	exit 2
	;;
esac
