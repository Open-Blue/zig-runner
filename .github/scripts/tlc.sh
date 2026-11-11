#!/usr/bin/env bash
# Model-checks with TLC the TLA+ modules under proofs/tla that SPIN does not: a configuration with a
# Promela one beside it (proofs/spin, spin.sh: StoreLocking.tla, StoreEviction.tla and
# ReleasePipeline.tla, proofs/README.md "The store's locking, in TLA+" and "The release pipeline, in
# TLA+") is SPIN's, unless TLC_ALL=1. tla2tools.jar is the TLA+ project's v1.7.4 release,
# checked against the sha256 pinned here, so a changed or replaced jar fails the job instead of
# checking the model. A new version means a new checksum from that release's asset.
#
# The configurations under proofs/tla are of two kinds: the protocol as the code has it
# (<Module>.cfg, -crash, -liveness and the like) must hold; a mutant, the code with one guard taken away,
# says "must fail: <invariant>" in its first line and must fail with that invariant, so a model
# that could no longer see a broken protocol fails the job too. A temporal property TLC does not
# name when it fails, so a configuration that must fail one checks that property alone.
# A finding (the code as it is, failing a property it should have) is a configuration of the same
# kind, so it fails the job once the code is fixed, and the configuration with it.
#
# Locally: .github/scripts/tlc.sh (Java 11 or later on the PATH; the jar is kept in $TLC_DIR).
set -euo pipefail

version=1.7.4
sum=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88

here=$(cd "$(dirname "$0")/../../proofs/tla" && pwd)
dir="${TLC_DIR:-${RUNNER_TEMP:-/tmp}/tlc}"
mkdir -p "$dir"
jar="$dir/tla2tools-$version.jar"
if [[ ! -f $jar ]]; then
	curl -fsSL -o "$jar.part" "https://github.com/tlaplus/tlaplus/releases/download/v$version/tla2tools.jar"
	mv "$jar.part" "$jar"
fi
if ! echo "$sum  $jar" | sha256sum --check --quiet --status; then
	echo "tla2tools.jar $version does not match its pinned checksum" >&2
	rm -f "$jar"
	exit 1
fi

# A configuration's module is its name up to the first `-` or `.`. TLC's output goes to the job's
# log as it comes (its progress lines, and a counterexample), in a group of its own, and to $out for
# the checks below; TLC's exit status is the function's (pipefail), not tee's.
tlc() {
	local cfg=$1 out=$2 module=${1%%[-.]*} rc=0 started=$SECONDS
	rm -rf "$dir/states"
	echo "::group::TLC $cfg"
	(cd "$here" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -cleanup \
		-metadir "$dir/states" -config "$cfg" "$module.tla") 2>&1 | tee "$out" || rc=$?
	echo "::endgroup::"
	echo "== $cfg: TLC ended (exit $rc) after $((SECONDS - started)) s"
	return "$rc"
}

# A configuration that SPIN checks (proofs/spin/<name>.pml, written from the .cfg,
# .github/scripts/spin.sh) is left to SPIN, unless TLC_ALL=1 (TLC then checks it too, in minutes;
# the .cfg's `states without symmetry:` or `states without the view:` is TLC's count without its
# SYMMETRY or VIEW, which SPIN has to find).
#
# TLC_PART=K/N checks part K of N, so N jobs share the configurations: each is given to the part
# with the least expected time so far, the longest first (its `tlc-seconds:` comment, or a few
# seconds without one). Every configuration is in exactly one part, whatever N.
mapfile -t all < <(cd "$here" && for cfg in *.cfg; do
	[[ ${TLC_ALL:-} != 1 && -f ../spin/${cfg%.cfg}.pml ]] || echo "$cfg"
done)
selected=("${all[@]}")
if [[ -n ${TLC_PART:-} ]]; then
	if ! [[ $TLC_PART =~ ^([0-9]+)/([0-9]+)$ ]] || ((BASH_REMATCH[1] < 1 || BASH_REMATCH[1] > BASH_REMATCH[2])); then
		echo "TLC_PART=$TLC_PART: K/N, with 1 <= K <= N" >&2
		exit 2
	fi
	k=${BASH_REMATCH[1]} n=${BASH_REMATCH[2]}
	mapfile -t selected < <(
		for cfg in "${all[@]}"; do
			sec=$(sed -n 's/^\\\* tlc-seconds: \([0-9]*\).*/\1/p' "$here/$cfg" | head -n 1)
			printf '%s %s\n' "${sec:-3}" "$cfg"
		done | sort -k1,1nr -k2,2 | awk -v k="$k" -v n="$n" '{
			best = 1
			for (i = 2; i <= n; i++) if (load[i] < load[best]) best = i
			load[best] += $1
			if (best == k) print $2
		}'
	)
	echo "part $k of $n: ${#selected[@]} of ${#all[@]} configurations"
fi
in_part() {
	local c
	for c in "${selected[@]}"; do [[ $c == "$1" ]] && return 0; done
	return 1
}

status=0
for cfg in "${all[@]}"; do
	in_part "$cfg" || continue
	grep -q 'must fail:' "$here/$cfg" && continue
	echo "== $cfg: must hold"
	out="$dir/${cfg%.cfg}.out"
	if tlc "$cfg" "$out" && grep -q '^Model checking completed. No error has been found.' "$out"; then
		grep -E '^[0-9,]+ states generated|^The depth|^Finished in' "$out"
	else
		tail -n 60 "$out"
		echo "$cfg: TLC found an error, or did not finish" >&2
		status=1
	fi
done

for cfg in "${all[@]}"; do
	[[ $cfg == *-* ]] || continue
	in_part "$cfg" || continue
	grep -q 'must fail:' "$here/$cfg" || continue
	want=$(sed -n '1s/.*must fail: \([A-Za-z]*\).*/\1/p' "$here/$cfg")
	echo "== $cfg: must fail with $want"
	out="$dir/${cfg%.cfg}.out"
	if tlc "$cfg" "$out"; then
		tail -n 60 "$out"
		echo "$cfg: TLC found no error in a mutant" >&2
		status=1
	elif [[ -z $want ]] || ! { grep -q "^Error: Invariant $want is violated" "$out" ||
		{ [[ $(sed -n 's/^PROPERT\(Y\|IES\)[[:space:]]*//p' "$here/$cfg") == "$want" ]] &&
			grep -q "^Error: Temporal properties were violated" "$out"; }; }; then
		tail -n 60 "$out"
		echo "$cfg: TLC did not fail with $want" >&2
		status=1
	else
		grep -E "^Error: (Invariant|Temporal)|^[0-9,]+ states generated" "$out"
	fi
done
exit "$status"
