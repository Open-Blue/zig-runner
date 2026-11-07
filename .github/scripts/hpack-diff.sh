#!/usr/bin/env bash
# Compares the runner's HPACK decoder (runner/src/hpack.zig) with golang.org/x/net/http2/hpack on
# random connections: runner/tools/hpackdiff (Go) encodes random header lists block after block,
# with table size changes and evictions, and now and then a broken block that Go's decoder answers;
# runner/tools/hpackcorpus.zig decodes the same blocks with hpack.zig and prints every block that
# decodes differently. Needs Go.
#
#   hpack-diff.sh [connections] [seed]     defaults: 2000, 1
set -euo pipefail
cd "$(dirname "$0")/../../runner"

s=$(mktemp -d)
trap 'rm -rf "$s"' EXIT
zig build-exe -OReleaseSafe --dep hpack --dep corpus -Mroot=tools/hpackcorpus.zig -Mhpack=src/hpack.zig -Mcorpus=tools/corpus.zig \
	--name hpackcorpus -femit-bin="$s/hpackcorpus" &
(cd tools/hpackdiff && go run . -out "$s/cases.jsonl" -n "${1:-2000}" -seed "${2:-1}")
wait
"$s/hpackcorpus" "$s/cases.jsonl"
