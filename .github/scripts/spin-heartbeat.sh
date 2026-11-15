#!/usr/bin/env bash
# The progress heartbeat of spin.sh, apart so that spin-heartbeat-test.sh can run it as it is.
# Sourced, not run.

# heartbeat_loop <parent-pid> <seconds> <command...>: runs <command...> every <seconds> until the
# process <parent-pid> is gone or the loop is sent TERM. The parent's own traps cannot cover its
# death by SIGKILL, so the loop asks after it at every tick, and ends within one of the death.
heartbeat_loop() {
	local parent=$1 tick=$2 nap=
	shift 2
	trap 'kill "$nap" 2>/dev/null; exit 0' TERM
	while kill -0 "$parent" 2>/dev/null; do
		sleep "$tick" &
		nap=$!
		wait "$nap" || true
		kill -0 "$parent" 2>/dev/null || break
		"$@"
	done
}
