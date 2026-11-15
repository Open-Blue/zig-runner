#!/usr/bin/env bash
# The progress heartbeat of spin.sh and the cleanup of its workers, apart so that
# spin-heartbeat-test.sh can run them as they are. Sourced, not run.

# proc_start <pid>: the start time of the process, field 22 of /proc/<pid>/stat (clock ticks since
# boot), empty if it is gone. With the pid it names one process: a pid reused is another start time.
proc_start() {
	local s f
	{ s=$(<"/proc/$1/stat"); } 2>/dev/null || return 0
	s=${s##*) } # after the command name, which may hold spaces and parentheses
	read -ra f <<<"$s"
	echo "${f[19]:-}"
}

# stop_groups <pgid...>: ends the process groups, each the pid of the job that leads it (spin.sh runs
# its workers with job control, so a worker and the spin, gcc and pan it runs share one group): TERM,
# a wait for the ones that are children of this shell, KILL for what is left after two seconds.
stop_groups() {
	local g i alive
	for g; do kill -TERM -- "-$g" 2>/dev/null || true; done
	wait "$@" 2>/dev/null || true
	for ((i = 0; i < 20; i++)); do
		alive=0
		for g; do ! kill -s 0 -- "-$g" 2>/dev/null || alive=1; done
		((alive)) || return 0
		sleep 0.1
	done
	for g; do kill -KILL -- "-$g" 2>/dev/null || true; done
	wait "$@" 2>/dev/null || true
}

# spin_stop <heartbeat-pid> <worker-pid...>: nothing started by spin.sh outlives it.
spin_stop() {
	local heartbeat=$1
	shift
	[[ -z $heartbeat ]] || kill "$heartbeat" 2>/dev/null || true
	((! $#)) || stop_groups "$@"
}

# heartbeat_loop <parent-pid> <seconds> <groups-file> <command...>: runs <command...> every <seconds>
# until the process <parent-pid> is gone or the loop is sent TERM. The parent's own traps cannot
# cover its death by SIGKILL, so the loop asks after it at every tick, by pid and start time (a pid
# reused is not the parent), and ends within one of the death. Then it ends the workers the parent
# left, the process groups listed in <groups-file>, one pid a line.
heartbeat_loop() {
	local parent=$1 tick=$2 groups=$3 nap='' start g
	local -a left=()
	shift 3
	start=$(proc_start "$parent")
	trap 'kill "$nap" 2>/dev/null; exit 0' TERM
	while [[ -n $start && $(proc_start "$parent") == "$start" ]]; do
		sleep "$tick" &
		nap=$!
		wait "$nap" || true
		[[ $(proc_start "$parent") == "$start" ]] || break
		"$@"
	done
	trap - TERM
	if [[ -r $groups ]]; then
		while read -r g; do [[ -z $g ]] || left+=("$g"); done <"$groups"
		((! ${#left[@]})) || stop_groups "${left[@]}"
	fi
}
