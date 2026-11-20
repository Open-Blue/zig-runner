#!/usr/bin/env bash
# memory-peak.sh's `proc` source (no cgroup file, no GNU time: the Pi's native steps) starts a
# sampler beside the command. A signal to the script must end the sampler, remove its temp file and
# stop the command, and an ordinary run must report a peak and leave nothing either:
#
#   memory-peak-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
pid=
cleanup() {
	[[ -z $pid ]] || kill -s KILL "$pid" 2>/dev/null || true
	rm -rf "$scratch"
}
trap cleanup EXIT
mkdir "$scratch/tmp"
export TMPDIR=$scratch/tmp MEMORY_PEAK_FILE=none MEMORY_PEAK_NO_TIME=1

fail() {
	echo "memory-peak-test: $*" >&2
	exit 1
}

# An ordinary run: a peak from /proc, the command's status, no temp file.
status=0
# shellcheck disable=SC2016 # the child shell's variables, not this one's
./memory-peak.sh t -- bash -c 'x=$(head -c 20000000 /dev/zero | tr "\0" a); sleep 1; exit 3' 2>"$scratch/err" || status=$?
((status == 3)) || fail "the command's status 3 became $status"
grep -q 'peak_mb=[0-9][0-9]* source=proc' "$scratch/err" || fail "no proc peak: $(cat "$scratch/err")"
[[ -z $(ls -A "$scratch/tmp") ]] || fail "a temp file is left after a run: $(ls -A "$scratch/tmp")"

# Each signal: the script ends with 128+signal, and so do the command and the sampler.
for sig in TERM INT; do
	# The command renames itself (its argv0), so that pgrep -f "^name " finds it and not the script.
	marker="mpk$sig$$"
	# A background job starts with INT ignored; python restores the default before the script's own.
	python3 -I -c 'import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execvp(sys.argv[1], sys.argv[1:])' \
		./memory-peak.sh t -- bash -c "exec -a $marker sleep 30" 2>"$scratch/err" &
	pid=$!
	for _ in $(seq 100); do
		pgrep -f "^$marker " >/dev/null && break
		sleep 0.1
	done
	pgrep -f "^$marker " >/dev/null || fail "$sig: the command did not start"
	sleep 0.5
	kill -s "$sig" "$pid"
	status=0
	start=$SECONDS
	wait "$pid" || status=$?
	pid=
	((status == 128 + $(kill -l "$sig"))) || fail "$sig: the script's status was $status"
	# Promptly: the command sleeps 30 s, so a signal that did not reach it shows as a long wait.
	((SECONDS - start <= 5)) || fail "$sig: the script took $((SECONDS - start)) s to end, so the command did not get the $sig"
	sleep 0.5
	pgrep -f "^$marker " >/dev/null && fail "$sig: the command is still running"
	[[ -z $(ls -A "$scratch/tmp") ]] || fail "$sig: a temp file is left: $(ls -A "$scratch/tmp")"
	# The sampler is the script's subshell: it holds the script's command line.
	pgrep -f "memory-peak.sh t -- bash -c exec -a $marker" >/dev/null && fail "$sig: the script or its sampler is left behind"
done
echo "memory-peak-test: a run reports a peak; TERM and INT leave no command, sampler or temp file"
