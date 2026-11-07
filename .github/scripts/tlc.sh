#!/usr/bin/env bash
# Model-checks the native store's locking protocols (proofs/tla/StoreLocking.tla and
# StoreEviction.tla, proofs/README.md "The store's locking, in TLA+") and the release pipeline
# (proofs/tla/ReleasePipeline.tla, "The release pipeline, in TLA+") with TLC. tla2tools.jar is the TLA+ project's v1.7.4 release,
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

# A configuration's module is its name up to the first `-` or `.`.
tlc() {
	local cfg=$1 out=$2 module=${1%%[-.]*}
	rm -rf "$dir/states"
	(cd "$here" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -cleanup \
		-metadir "$dir/states" -config "$cfg" "$module.tla") >"$out" 2>&1
}

status=0
for cfg in "$here"/*.cfg; do
	cfg=$(basename "$cfg")
	grep -q 'must fail:' "$here/$cfg" && continue
	echo "== $cfg: must hold"
	out="$dir/${cfg%.cfg}.out"
	if tlc "$cfg" "$out" && grep -q '^Model checking completed. No error has been found.' "$out"; then
		grep -E '^[0-9,]+ states generated|^The depth|^Finished in' "$out"
	else
		cat "$out"
		echo "$cfg: TLC found an error, or did not finish" >&2
		status=1
	fi
done

for cfg in "$here"/*-*.cfg; do
	cfg=$(basename "$cfg")
	grep -q 'must fail:' "$here/$cfg" || continue
	want=$(sed -n '1s/.*must fail: \([A-Za-z]*\).*/\1/p' "$here/$cfg")
	echo "== $cfg: must fail with $want"
	out="$dir/${cfg%.cfg}.out"
	if tlc "$cfg" "$out"; then
		cat "$out"
		echo "$cfg: TLC found no error in a mutant" >&2
		status=1
	elif [[ -z $want ]] || ! { grep -q "^Error: Invariant $want is violated" "$out" ||
		{ [[ $(sed -n 's/^PROPERT\(Y\|IES\)[[:space:]]*//p' "$here/$cfg") == "$want" ]] &&
			grep -q "^Error: Temporal properties were violated" "$out"; }; }; then
		cat "$out"
		echo "$cfg: TLC did not fail with $want" >&2
		status=1
	else
		grep -E "^Error: (Invariant|Temporal)|^[0-9,]+ states generated" "$out"
	fi
done
exit "$status"
