#!/usr/bin/env bash
# image-preflight.sh's failure path, with no root: a PATH holding only some tools must fail naming
# each missing one and no other, an optional tool's absence must not fail, and a full set passes.
#
#   image-preflight-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fail() {
	echo "image-preflight-test: $*" >&2
	exit 1
}

# Only the commands the script itself runs, plus fake tools named below.
mkdir "$scratch/bin"
for c in bash uname getconf stat head; do
	ln -s "$(command -v "$c")" "$scratch/bin/$c"
done
for t in python3 unshare; do
	printf '#!/bin/sh\necho "%s 9.9 (fake)"\n' "$t" >"$scratch/bin/$t"
	chmod +x "$scratch/bin/$t"
done
run() { PATH=$scratch/bin ./image-preflight.sh "$@"; }

status=0
run python3 unshare ip nsenter >"$scratch/out" 2>"$scratch/err" || status=$?
((status == 1)) || fail "two missing tools gave status $status"
grep -q 'preflight: ip MISSING' "$scratch/out" || fail "ip not named: $(cat "$scratch/out")"
grep -q 'preflight: nsenter MISSING' "$scratch/out" || fail "nsenter not named"
grep -q 'preflight: python3 /.*: python3 9.9' "$scratch/out" || fail "present tool not reported with path and version"
grep -q 'missing: ip nsenter$' "$scratch/err" || fail "the list is not exactly ip nsenter: $(cat "$scratch/err")"
grep -q '^::error title=Runner image lacks a tool::ip nsenter ' "$scratch/out" || fail "no error annotation"
grep -q 'preflight: kernel ' "$scratch/out" || fail "no kernel line"
grep -q 'preflight: page size [0-9]' "$scratch/out" || fail "no page size line"

run python3 nft? >"$scratch/out" 2>&1 || fail "an optional tool's absence failed: $(cat "$scratch/out")"
grep -q 'nft not installed (optional)' "$scratch/out" || fail "optional absence not said"

run python3 unshare >"$scratch/out" 2>&1 || fail "all present failed"
grep -q 'all required tools present' "$scratch/out" || fail "no success line"
echo "image-preflight-test: missing tools named, optional ones allowed, a full set passes"
