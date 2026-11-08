#!/usr/bin/env bash
# Model-checks the native store's locking protocol with SPIN: proofs/spin/StoreLockingModel.pml, the
# Promela port of proofs/tla/StoreLocking.tla (proofs/README.md, "The store's locking, in SPIN").
# SPIN is 6.5.2, Ubuntu's spin 6.5.2+dfsg-2build1 (store-model.yml pins the package), and any other
# version fails here, so a changed SPIN is a change made on purpose.
#
# Each proofs/spin/StoreLocking*.pml is a configuration written from the proofs/tla .cfg of the same
# name (proofs/spin/cfg.py; a stale one fails the job). A configuration of the protocol as the code has
# it must hold, and must reach exactly the states its `spin-states:` line says: TLC's count without
# symmetry, and SPIN's first state. A different count means the two models have drifted apart. A
# mutant, the code with one guard taken away, says "must fail: <invariant>" in its first line and must
# fail with that invariant's assertion.
#
# The search is exhaustive: no bitstate or hash compaction, which may miss states, and no partial
# order reduction, which reduces nothing here (every step touches the shared store) and costs time.
# The configurations run side by side, one a core, each in its own directory under $SPIN_DIR.
#
# Locally: .github/scripts/spin.sh (spin 6.5.2, gcc and python3 on the PATH).
set -euo pipefail

version="Spin Version 6.5.2 -- 6 December 2019"
here=$(cd "$(dirname "$0")/../../proofs/spin" && pwd)
dir="${SPIN_DIR:-${RUNNER_TEMP:-/tmp}/spin}"

if [[ $(spin -V 2>&1) != "$version" ]]; then
	echo "spin -V says '$(spin -V 2>&1)', not '$version'" >&2
	exit 1
fi
python3 -I "$here/cfg.py" --check

# check <name>: compiles and runs one configuration in $dir/<name>; the verdict is in result.
check() {
	local name=$1 w="$dir/$1"
	rm -rf "${w:?}"
	mkdir -p "$w"
	cp "$here"/*.pml "$w"/
	(
		cd "$w"
		spin -a "$name.pml" >spin.out 2>&1 &&
			gcc -O2 -w -DSAFETY -DNOREDUCE -o pan pan.c >gcc.out 2>&1 &&
			{ ./pan -m100000 -w26 >pan.out 2>&1 || true; }
	) || {
		echo "$name: spin -a or gcc failed" >"$w/result"
		return
	}
	local first want stored
	first=$(head -n 1 "$here/$name.pml")
	stored=$(sed -n 's/^ *\([0-9]*\) states, stored.*/\1/p' "$w/pan.out")
	if grep -q 'must fail:' <<<"$first"; then
		want=$(sed -n 's/.*must fail: \([A-Za-z]*\).*/\1/p' <<<"$first")
		if grep -q "^pan:1: assertion violated $want " "$w/pan.out"; then
			echo "ok: fails with $want (${stored:-?} states to the first violation)" >"$w/result"
		else
			echo "$name: SPIN did not fail with $want" >"$w/result"
		fi
	else
		want=$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$here/$name.pml")
		if ! grep -q 'errors: 0$' "$w/pan.out" || grep -qE 'max search depth too small|violated|out of memory' "$w/pan.out"; then
			echo "$name: SPIN found an error, or did not finish" >"$w/result"
		elif [[ $stored != "$want" ]]; then
			echo "$name: $stored states, not the $want of its spin-states line: the Promela and the TLA+ differ" >"$w/result"
		else
			echo "ok: holds, $stored states, $(sed -n 's/^pan: elapsed time \(.*\)/\1/p' "$w/pan.out")" >"$w/result"
		fi
	fi
}

names=()
for f in "$here"/StoreLocking*.pml; do
	f=$(basename "$f" .pml)
	[[ $f == StoreLockingModel ]] || names+=("$f")
done
# The largest first, so the long ones start at once.
mapfile -t names < <(for n in "${names[@]}"; do
	printf '%s %s\n' "$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$here/$n.pml")" "$n"
done | sort -k1,1nr | cut -d' ' -f2)
jobs=$(nproc)
running=0
for n in "${names[@]}"; do
	if ((running >= jobs)); then
		wait -n
		running=$((running - 1))
	fi
	check "$n" &
	running=$((running + 1))
done
wait

status=0
for n in "${names[@]}"; do
	r=$(cat "$dir/$n/result")
	echo "== $n: ${r#ok: }"
	if [[ $r != ok:* ]]; then
		cat "$dir/$n/spin.out" "$dir/$n/gcc.out" "$dir/$n/pan.out" 2>/dev/null | tail -n 40
		status=1
	fi
done
exit "$status"
