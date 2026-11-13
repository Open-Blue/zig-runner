#!/usr/bin/env bash
# Builds runner/src/implbench.zig as the release builds the runner (ReleaseSafe, musl, the same C
# flags; for x86_64 unless IMPL_BENCH_TARGET says, e.g. aarch64-linux-musl on the Pi, where it
# builds for the machine it runs on) and runs it with the arguments given. Its modes are in that file's header; the
# results are in docs/BENCHMARKS.md. The laptop's load average should be low, and is printed.
#
#   impl-bench.sh zstd|libzstd|gzip|sha-dispatch|sha-baseline FILE [ROUNDS]
#   impl-bench.sh apply BLOB EMPTY_DIR [0|1]
#   impl-bench.sh redact LOG SECRETS [ROUNDS]
set -euo pipefail
cd "$(dirname "$0")/../../runner"
# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
zig_libzstd_args
zig build-exe -OReleaseSafe -fstrip -target "${IMPL_BENCH_TARGET:-x86_64-linux-musl}" src/implbench.zig \
	"${libzstd_args[@]}" -femit-bin="$scratch/implbench"
echo "load: $(cut -d' ' -f1-3 /proc/loadavg)"
"$scratch/implbench" "$@"
