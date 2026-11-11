#!/usr/bin/env bash
# Model-checks the native store's locking protocol with SPIN: proofs/spin/StoreLockingModel.pml, the
# Promela port of proofs/tla/StoreLocking.tla (proofs/README.md, "The store's locking, in SPIN").
# SPIN is 6.5.2, Ubuntu's spin 6.5.2+dfsg-2build1 (store-model.yml pins the package), and any other
# version fails here, so a changed SPIN is a change made on purpose.
#
# Each proofs/spin/<Module>*.pml but <Module>Model.pml is a configuration written from the proofs/tla
# .cfg of the same name (proofs/spin/cfg.py; a stale one fails the job). A configuration of the
# protocol as the code has it must hold, and must reach exactly the states its `spin-states:` line
# says: TLC's count without symmetry, and SPIN's first state. A different count means the two models
# have drifted apart. A configuration with temporal properties (its `spin-ltl:` line) then checks
# each of them alone, with SPIN's weak fairness (pan -a -f), on the model built with LIVENESS. A
# mutant, the code with one guard taken away, says "must fail: <property>" in its first line and must
# fail with that invariant's assertion, or, for a temporal property, with that property's claim.
#
# The search is exhaustive: no bitstate or hash compaction, which may miss states, and no partial
# order reduction, which reduces nothing here (every step touches the shared store) and costs time.
# The configurations run side by side, one a core, each in its own directory under $SPIN_DIR. Their
# output is not interleaved: pan prints its report once, at the end, so each configuration says when
# it starts and, with its verdict, when it ends (a line naming it, in the order they finish), and a
# heartbeat line says every minute which are still running. The ordered verdicts follow at the end.
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

# build <name> safety|liveness: spin -a and gcc in the current directory, pan-<kind> the verifier.
# The safety one has no never claim; the liveness one has the stutter of LIVENESS and the claims.
build() {
	local name=$1 kind=$2
	if [[ $kind == safety ]]; then
		spin -a "$name.pml" >spin-safety.out 2>&1 &&
			gcc -O2 -w -DSAFETY -DNOREDUCE -DNOCLAIM -o pan-safety pan.c >gcc-safety.out 2>&1
	else
		spin -DLIVENESS -a "$name.pml" >spin-liveness.out 2>&1 &&
			gcc -O2 -w -DNOREDUCE -o pan-liveness pan.c >gcc-liveness.out 2>&1
	fi
}

# live <property>: pan-liveness on one claim, its report in pan-<property>.out.
live() {
	./pan-liveness -m1000000 -w26 -a -f -N "$1" >"pan-$1.out" 2>&1 || true
}

stored() { sed -n 's/^ *\([0-9]*\) states, stored.*/\1/p' "$1"; }
elapsed() { sed -n 's/^pan: elapsed time \(.*\)/\1/p' "$1"; }

# check <name>: compiles and runs one configuration in $dir/<name>; the verdict is in result.
check() {
	local name=$1 w="$dir/$1" started=$SECONDS first want ltl p verdict
	rm -rf "${w:?}"
	mkdir -p "$w"
	cp "$here"/*.pml "$w"/
	cd "$w"
	echo "[$name] spin, gcc and pan started"
	first=$(head -n 1 "$name.pml")
	want=$(sed -n 's/.*must fail: \([A-Za-z]*\).*/\1/p' <<<"$first")
	ltl=$(sed -n 's/^ \* spin-ltl: \([A-Za-z ]*\).*/\1/p' "$name.pml")
	if [[ -n $want && " $ltl " == *" $want "* ]]; then
		# A mutant that must fail a temporal property: its claim's violation, under fairness.
		if ! build "$name" liveness; then
			verdict="$name: spin -a or gcc failed"
		elif live "$want" && grep -qE '^pan:1: (acceptance cycle|claim violated)' "pan-$want.out"; then
			verdict="ok: fails $want ($(stored "pan-$want.out") states to the first violation)"
		else
			verdict="$name: SPIN did not fail $want"
		fi
	elif ! build "$name" safety; then
		verdict="$name: spin -a or gcc failed"
	else
		./pan-safety -m100000 -w26 >pan.out 2>&1 || true
		if [[ -n $want ]]; then
			if grep -q "^pan:1: assertion violated $want " pan.out; then
				verdict="ok: fails with $want ($(stored pan.out) states to the first violation)"
			else
				verdict="$name: SPIN did not fail with $want"
			fi
		else
			want=$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$name.pml")
			if ! grep -q 'errors: 0$' pan.out || grep -qE 'max search depth too small|violated|out of memory' pan.out; then
				verdict="$name: SPIN found an error, or did not finish"
			elif [[ $(stored pan.out) != "$want" ]]; then
				verdict="$name: $(stored pan.out) states, not the $want of its spin-states line: the Promela and the TLA+ differ"
			else
				verdict="ok: holds, $(stored pan.out) states, $(elapsed pan.out)"
				if [[ -n $ltl ]] && ! build "$name" liveness; then
					verdict="$name: spin -a or gcc failed (LIVENESS)"
				fi
				for p in $ltl; do
					[[ $verdict == ok:* ]] || break
					live "$p"
					if ! grep -q 'errors: 0$' "pan-$p.out" ||
						grep -qE 'max search depth too small|violated|acceptance cycle|out of memory' "pan-$p.out"; then
						verdict="$name: SPIN found $p violated, or did not finish"
					else
						verdict+="; $p holds ($(stored "pan-$p.out") states with its claim, $(elapsed "pan-$p.out"))"
					fi
				done
			fi
		fi
	fi
	echo "$verdict" >result
	echo "[$name] ended after $((SECONDS - started)) s: $verdict"
	echo "$name" >>"$dir/finished"
}

names=()
for f in "$here"/*.pml; do
	f=$(basename "$f" .pml)
	[[ $f == *Model ]] || names+=("$f")
done
# The largest first, so the long ones start at once.
mapfile -t names < <(for n in "${names[@]}"; do
	printf '%s %s\n' "$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$here/$n.pml")" "$n"
done | sort -k1,1nr | cut -d' ' -f2)
jobs=$(nproc)
running=0
mkdir -p "$dir"
: >"$dir/finished"
(
	trap 'kill "$nap" 2>/dev/null; exit 0' TERM
	while :; do
		sleep 60 &
		nap=$!
		wait "$nap"
		echo "spin: $SECONDS s, $(wc -l <"$dir/finished") of ${#names[@]} configurations finished"
	done
) &
heartbeat=$!
pids=()
for n in "${names[@]}"; do
	if ((running >= jobs)); then
		wait -n
		running=$((running - 1))
	fi
	(check "$n") &
	pids+=($!)
	running=$((running + 1))
done
wait "${pids[@]}" || true
kill "$heartbeat" 2>/dev/null || true

status=0
for n in "${names[@]}"; do
	r=$(cat "$dir/$n/result")
	echo "== $n: ${r#ok: }"
	if [[ $r != ok:* ]]; then
		cat "$dir/$n"/spin-*.out "$dir/$n"/gcc-*.out "$dir/$n"/pan*.out 2>/dev/null | tail -n 40
		status=1
	fi
done
exit "$status"
