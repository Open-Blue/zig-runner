#!/usr/bin/env bash
# Nothing spin.sh starts may outlive it: its heartbeat was found orphaned after four hours once, when
# the pre-push hook that ran the script ended, and its workers (and the spin, gcc and pan they run)
# kept writing into SPIN_DIR after an interrupt. This runs a parent of the structure spin.sh has
# (spin-heartbeat.sh's loop and spin_stop, job control, the EXIT/INT/TERM traps, workers that each
# run a child and a `wait`), kills the parent with each of SIGKILL, SIGTERM and SIGINT, and checks the
# heartbeat, every worker and every worker's child are gone within one tick.
# Only the processes it starts are signalled. Locally: .github/scripts/spin-heartbeat-test.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tick=2
scratch=$(mktemp -d)
parent=
pidfiles=()
cleanup() {
	local f p
	[[ -z $parent ]] || kill -9 "$parent" 2>/dev/null || true
	for f in "${pidfiles[@]}"; do
		[[ ! -s $f ]] || while read -r p; do kill -9 "$p" 2>/dev/null || true; done < <(tr -s ' ' '\n' <"$f")
	done
	rm -rf "$scratch"
}
trap cleanup EXIT

# Background jobs get the default signals, SIGINT included, as a script run by hand has them.
set -m

# running <pid>: alive, a zombie not counted.
running() {
	local s
	{ s=$(<"/proc/$1/stat"); } 2>/dev/null || return 1
	[[ ${s##*) } != Z* ]]
}

# one <signal>: starts the parent, kills it with the signal, waits for everything it started to go.
one() {
	local sig=$1 pidfile="$scratch/pids-$1" i p left=0
	local -a started=()
	pidfiles+=("$pidfile")
	SPIN_HEARTBEAT_S=$tick bash -c '
		source "$1"
		set -m
		heartbeat=
		pids=()
		trap '\''spin_stop "$heartbeat" "${pids[@]}"'\'' EXIT
		trap '\''exit 130'\'' INT
		trap '\''exit 143'\'' TERM
		: >"$2.workers"
		heartbeat_loop "$$" "$SPIN_HEARTBEAT_S" "$2.workers" echo beat >/dev/null &
		heartbeat=$!
		echo "$heartbeat" >>"$2"
		for k in 1 2; do
			(
				sleep 60 &
				echo "$BASHPID $!" >>"$2"
				wait
			) &
			pids+=($!)
			echo "$!" >>"$2.workers"
		done
		wait
	' _ "$here/spin-heartbeat.sh" "$pidfile" &
	parent=$!
	i=0
	# The heartbeat, two workers and their two children.
	while (($({ cat "$pidfile" 2>/dev/null || true; } | wc -w) < 5)) && ((i++ < 50)); do sleep 0.1; done
	mapfile -t started < <(tr -s ' ' '\n' <"$pidfile")
	if ((${#started[@]} != 5)); then
		echo "ERROR $sig: the parent started ${#started[@]} of 5 processes" >&2
		return 1
	fi
	for p in "${started[@]}"; do
		running "$p" || {
			echo "ERROR $sig: process $p is not running before the kill" >&2
			return 1
		}
	done
	kill "-$sig" "$parent"
	wait "$parent" 2>/dev/null || true
	parent=
	# Within one tick of the parent's death, and a little for the process table.
	for ((i = 0; i < (tick + 2) * 10; i++)); do
		left=0
		for p in "${started[@]}"; do
			if running "$p"; then left=1; fi
		done
		((left)) || break
		sleep 0.1
	done
	for p in "${started[@]}"; do
		if running "$p"; then
			echo "ERROR $sig: process $p outlived its parent by more than one tick ($tick s)" >&2
		fi
	done
	((! left)) || return 1
	echo "ok $sig: the heartbeat and the workers ended with their parent"
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
