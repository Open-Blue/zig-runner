#!/usr/bin/env bash
# Compares the runner's RS256 signing (runner/src/github/rsa_sign.zig, for the JIT runner's JWT)
# with Go's crypto/rsa SignPKCS1v15 on random keys and messages: runner/tools/rsadiff (Go) makes
# the keys and signs, runner/tools/rsacorpus.zig signs the same messages with rsa_sign.zig and
# prints every signature that is not the same byte for byte, with its key. Needs Go.
#
#   rsa-diff.sh [messages] [seed]     defaults: 2000, 1
set -euo pipefail
cd "$(dirname "$0")/../../runner"

s=$(mktemp -d)
trap 'rm -rf "$s"' EXIT
zig build-exe -OReleaseSafe --dep rsa_sign --dep corpus -Mroot=tools/rsacorpus.zig -Mrsa_sign=src/github/rsa_sign.zig -Mcorpus=tools/corpus.zig \
	--name rsacorpus -femit-bin="$s/rsacorpus" &
(cd tools/rsadiff && go run . -out "$s/cases.jsonl" -n "${1:-2000}" -seed "${2:-1}")
wait
"$s/rsacorpus" "$s/cases.jsonl"
