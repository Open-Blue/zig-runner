#!/usr/bin/env bash
# Compares hashFiles()'s search (runner/src/glob.zig) with the Lean model of it in proofs/, on
# random trees and pattern sets: both must find the same files, in the same order.
#
#   - the model's: `globoracle` (proofs/Oracle.lean), which runs the walk proofs/Glob/Walk.lean
#     proves yields exactly the files the patterns match (`Glob.walk_eq_full`);
#   - the runner's: glob.zig on the same cases (runner/tools/globleancorpus.zig).
#
# So the proof is about the code that ships, as far as these cases reach: the walk's batching by
# level, its pruning, search paths, implicit descendants and order. Segment matching in full is
# compared with GitHub's own by hashfiles-diff.sh. Needs Zig, Lean (lake) and jq.
#
#   glob-lean-diff.sh [cases] [seed]     defaults: 20000, 1
set -euo pipefail
cd "$(dirname "$0")/../.."
s=$(mktemp -d)
trap 'rm -rf "$s"' EXIT

(cd runner && zig build-exe --dep glob -Mroot=tools/globleancorpus.zig -Mglob=src/glob.zig \
	--name globleancorpus -femit-bin="$s/globleancorpus") &
zig_build=$!
(cd proofs && lake build globoracle >/dev/null) &
lean_build=$!
wait "$zig_build"
wait "$lean_build"

echo "== running glob.zig and the Lean model"
"$s/globleancorpus" gen "${1:-20000}" "${2:-1}" >"$s/cases.jsonl"
"$s/globleancorpus" run "$s/cases.jsonl" | jq -cS . >"$s/zig.jsonl"
proofs/.lake/build/bin/globoracle <"$s/cases.jsonl" | jq -cS . >"$s/lean.jsonl"

cases=$(wc -l <"$s/cases.jsonl")
found=$(grep -c '"files":\[[^]]' "$s/zig.jsonl" || true)
if cmp -s "$s/zig.jsonl" "$s/lean.jsonl"; then
	echo "glob.zig and the Lean model agree on all $cases cases ($found find files)"
	exit 0
fi
echo "glob.zig and the Lean model differ:"
paste -d '\n' "$s/zig.jsonl" "$s/lean.jsonl" | paste - - | awk -F'\t' '$1 != $2' | head -5 |
	while IFS=$'\t' read -r zig lean; do
		id=$(jq .id <<<"$zig")
		echo "case: $(sed -n "${id}p" "$s/cases.jsonl")"
		echo "  glob.zig: $zig"
		echo "  Lean:     $lean"
	done
exit 1
