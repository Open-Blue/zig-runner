#!/usr/bin/env bash
# mmap-rnd-bits.sh against a fake /proc/sys: a missing key, a refused write, a value that did not
# take and a good write each end as they should, with the before and after said.
#
#   mmap-rnd-bits-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fail() {
	echo "mmap-rnd-bits-test: $*" >&2
	exit 1
}
mkdir -p "$scratch/sys/vm"
printf '#!/bin/sh\nexit 1\n' >"$scratch/refuse"
printf '#!/bin/sh\nexit 0\n' >"$scratch/ignore"
# shellcheck disable=SC2016 # the fake's own variables
printf '#!/bin/sh\necho "${3#vm.mmap_rnd_bits=}" > "$PROC_SYS/vm/mmap_rnd_bits"\n' >"$scratch/accept"
chmod +x "$scratch/refuse" "$scratch/ignore" "$scratch/accept"
run() { PROC_SYS=$scratch/sys SYSCTL=$scratch/$1 ./mmap-rnd-bits.sh 28 >"$scratch/out" 2>&1; }

if run accept; then fail "a missing key passed"; fi
grep -q "::error title=vm.mmap_rnd_bits::.*mmap_rnd_bits cannot be read" "$scratch/out" || fail "missing key not named: $(cat "$scratch/out")"
echo 32 >"$scratch/sys/vm/mmap_rnd_bits"
if run refuse; then fail "a refused write passed"; fi
grep -q 'mmap_rnd_bits: before: 32' "$scratch/out" || fail "before not said"
grep -q 'was refused' "$scratch/out" || fail "refusal not said: $(cat "$scratch/out")"
if run ignore; then fail "a value that did not take passed"; fi
grep -q 'wrote 28 and read back 32' "$scratch/out" || fail "mismatch not said: $(cat "$scratch/out")"
run accept || fail "a good write failed: $(cat "$scratch/out")"
grep -q 'mmap_rnd_bits: after: 28 (wanted 28)' "$scratch/out" || fail "after not said"
echo "mmap-rnd-bits-test: missing, refused and ignored writes fail naming why; a good write passes"
