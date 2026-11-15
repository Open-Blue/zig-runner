#!/usr/bin/env bash
# The heartbeat of spin.sh must end with the script, on every path: found orphaned after four hours
# once, when the pre-push hook that ran the script ended. This runs a parent of the structure
# spin.sh has (spin-heartbeat.sh's loop, the EXIT/INT/TERM traps, a `wait` for its work), kills the
# parent with each of SIGKILL, SIGTERM and SIGINT, and checks the heartbeat is gone within one tick.
# Only the processes it starts are signalled. Locally: .github/scripts/spin-heartbeat-test.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tick=2
scratch=$(mktemp -d)
parent=
heartbeat=
cleanup() {
	[[ -z $parent ]] || kill -9 "$parent" 2>/dev/null || true
	[[ -z $heartbeat ]] || kill -9 "$heartbeat" 2>/dev/null || true
	rm -rf "$scratch"
}
trap cleanup EXIT

# Background jobs get the default signals, SIGINT included, as a script run by hand has them.
set -m

# one <signal>: starts the parent, kills it with the signal, waits for the heartbeat to be gone.
one() {
	local sig=$1 pidfile="$scratch/hb-$1" i
	SPIN_HEARTBEAT_S=$tick bash -c '
		source "$1"
		heartbeat=
		trap '\''kill "$heartbeat" 2>/dev/null || true'\'' EXIT
		trap '\''exit 130'\'' INT
		trap '\''exit 143'\'' TERM
		heartbeat_loop "$$" "$SPIN_HEARTBEAT_S" echo beat >/dev/null &
		heartbeat=$!
		echo "$heartbeat" >"$2"
		sleep 10 &
		wait
	' _ "$here/spin-heartbeat.sh" "$pidfile" &
	parent=$!
	i=0
	while [[ ! -s $pidfile ]] && ((i++ < 50)); do sleep 0.1; done
	[[ -s $pidfile ]] || {
		echo "ERROR $sig: the parent never started its heartbeat" >&2
		return 1
	}
	heartbeat=$(<"$pidfile")
	kill -0 "$heartbeat" || {
		echo "ERROR $sig: the heartbeat is not running before the kill" >&2
		return 1
	}
	kill "-$sig" "$parent"
	wait "$parent" 2>/dev/null || true
	parent=
	# Within one tick of the parent's death, and a little for the process table.
	for ((i = 0; i < (tick + 1) * 10; i++)); do
		kill -0 "$heartbeat" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$heartbeat" 2>/dev/null; then
		echo "ERROR $sig: the heartbeat $heartbeat outlived its parent by more than one tick ($tick s)" >&2
		return 1
	fi
	heartbeat=
	echo "ok $sig: the heartbeat ended with its parent"
}

failed=0
for sig in KILL TERM INT; do
	one "$sig" || failed=1
done
if ((failed)); then
	echo "spin-heartbeat-test: failed" >&2
	exit 1
fi
echo "spin-heartbeat-test: 3 passed; 0 failed"
