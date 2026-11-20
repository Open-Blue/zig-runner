#!/usr/bin/env bash
# Runs a command and prints, on stderr, the memory its phase peaked at, as one greppable line:
#
#   memory-peak: phase=compile peak_mb=2405 source=cgroup
#
#   memory-peak.sh PHASE -- COMMAND...
#
# The command's exit status is this script's; a peak that cannot be read never fails it. Sources, in
# order:
#   cgroup  the step's own cgroup (/proc/self/cgroup, then memory.peak): the whole cgroup's peak
#           since this phase began, page cache and tmpfs included, which is what a job's memory limit
#           kills at. The peak is reset first by writing to the file (Linux 6.12 and later: a
#           watermark per open file description, so the file is held open throughout). A file that cannot be
#           reset reports its total since the cgroup began, as source=cgroup-total.
#   time    GNU time's largest resident set of any one process of the command (`-f %M`), where there
#           is no readable cgroup memory.peak. Smaller than the cgroup's number: one process, not
#           the sum, and no cache.
#   proc    where neither works (a native step on the Pi: its sandbox hides the cgroup's files and
#           the image has no GNU time): the largest sum of resident sets (VmRSS) of the command and
#           everything it started, sampled five times a second from /proc. It misses a peak shorter
#           than that and counts shared pages once per process; the runner's own "this step's
#           memory peak" line, from the cgroup, is the authority, and this agrees with it to within
#           the page cache.
#           It also misses a process that double-forked (reparented to init, so no longer the
#           command's descendant), and a command that ends within one sample reports "unavailable".
#   none    "unavailable".
# Why: the Pi's compile of the tests has peaked within a few percent of its job's 3.1 GB limit and
# killed one run (docs: #565); one sample a minute in the runner's journal cannot see the top.
set -uo pipefail

phase=${1:?usage: memory-peak.sh PHASE -- COMMAND...}
shift
[[ ${1:-} == -- ]] || {
	echo "memory-peak.sh: missing -- before the command" >&2
	exit 2
}
shift
(($# > 0)) || {
	echo "memory-peak.sh: no command" >&2
	exit 2
}

report() {
	echo "memory-peak: phase=$phase peak_mb=$1 source=$2" >&2
}

# The step's cgroup (v2: one line, "0::/path"). MEMORY_PEAK_FILE names another memory.peak, or
# "none" for no cgroup, MEMORY_PEAK_NO_TIME=1 for no GNU time: how this script's fallbacks are tried.
file=
if [[ -n ${MEMORY_PEAK_FILE:-} ]]; then
	[[ $MEMORY_PEAK_FILE == none || ! -r $MEMORY_PEAK_FILE ]] || file=$MEMORY_PEAK_FILE
elif [[ -r /proc/self/cgroup ]]; then
	path=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null | head -n 1)
	if [[ -n $path && -r /sys/fs/cgroup$path/memory.peak ]]; then
		file=/sys/fs/cgroup$path/memory.peak
	fi
fi

# perl reads the peak back (below); without it, the cgroup path would lose the number, so use time.
if [[ -n $file ]] && command -v perl >/dev/null && { exec 3<>"$file"; } 2>/dev/null; then
	source=cgroup-total
	# A write that works makes fd 3's peak count from here. Its answer is read from fd 3 again
	# (reading the file by name would open a new watermark, the whole cgroup's).
	if echo reset >&3 2>/dev/null; then
		source=cgroup
	fi
	"$@"
	status=$?
	# The write left the offset past the start; the shell cannot seek back, perl (always with
	# Debian and Ubuntu) can.
	peak=$(perl -e 'sysseek(STDIN, 0, 0) or exit 1; sysread(STDIN, $b, 64); print $b' <&3 2>/dev/null | tr -d '[:space:]')
	exec 3>&-
	if [[ $peak =~ ^[0-9]+$ ]]; then
		report $((peak / 1048576)) "$source"
	else
		report unavailable none
	fi
	exit "$status"
fi

if [[ -x /usr/bin/time && -z ${MEMORY_PEAK_NO_TIME:-} ]]; then
	out=$(mktemp 2>/dev/null) || out=
	if [[ -n $out ]] && /usr/bin/time -f %M -o "$out" true 2>/dev/null; then
		/usr/bin/time -f %M -o "$out" "$@"
		status=$?
		kb=$(tail -n 1 "$out" 2>/dev/null)
		rm -f "$out"
		if [[ $kb =~ ^[0-9]+$ ]]; then
			report $((kb / 1024)) time
		else
			report unavailable none
		fi
		exit "$status"
	fi
	[[ -z $out ]] || rm -f "$out"
fi

# Sampled: the sum of the resident sets of this script's descendants other than the sampler's own.
# The sampler writes the highest sum to a file when it grows, and is killed by its PID afterwards.
if [[ -r /proc/self/status ]] && command -v awk >/dev/null; then
	out=$(mktemp 2>/dev/null) || out=
	if [[ -n $out ]]; then
		me=$$
		(
			skip=$BASHPID
			max=0
			while :; do
				sum=$(awk -v root="$me" -v skip="$skip" '
					/^Pid:/ { pid = $2 }
					/^PPid:/ { parent[pid] = $2 }
					/^VmRSS:/ { kb[pid] = $2 }
					END {
						for (p in parent) {
							q = p
							for (n = 0; n < 64 && q != "" && q != 0; n++) {
								if (q == skip) break
								if (q == root) { if (p != root) total += kb[p]; break }
								q = parent[q]
							}
						}
						print total + 0
					}' /proc/[0-9]*/status 2>/dev/null)
				if [[ $sum =~ ^[0-9]+$ ]] && ((sum > max)); then
					max=$sum
					echo "$max" >"$out"
				fi
				sleep 0.2
			done
		) &
		sampler=$!
		cmd=
		# A signal to this script ends the sampler and removes the temp file, and reaches the
		# command, so that a cancelled step's command stops too; the status is 128 plus the signal.
		# shellcheck disable=SC2329 # run by the traps below
		stop() {
			kill "$sampler" 2>/dev/null
			wait "$sampler" 2>/dev/null
			rm -f "$out"
		}
		# shellcheck disable=SC2329 # run by the traps below
		forward() {
			[[ -z $cmd ]] || kill -s "$1" "$cmd" 2>/dev/null
			wait "$cmd" 2>/dev/null
			stop
			trap - EXIT
			exit "$2"
		}
		trap stop EXIT
		trap 'forward TERM 143' TERM
		trap 'forward INT 130' INT
		# Not "$@" & alone: bash starts a background command with SIGINT and SIGQUIT ignored, so the
		# INT forwarded to it (GitHub's first signal on a cancel) did nothing, and the step ran on
		# until its command ended by itself or the TERM after (memory-peak-test.sh's INT case
		# waited out its 30 s sleep). The subshell puts their default actions back before the exec.
		(
			trap - INT QUIT
			exec "$@"
		) <&0 &
		cmd=$!
		wait "$cmd"
		status=$?
		kill "$sampler" 2>/dev/null
		wait "$sampler" 2>/dev/null
		kb=$(tail -n 1 "$out" 2>/dev/null)
		rm -f "$out"
		if [[ $kb =~ ^[0-9]+$ ]] && ((kb > 0)); then
			report $((kb / 1024)) proc
		else
			report unavailable none
		fi
		exit "$status"
	fi
fi

"$@"
status=$?
report unavailable none
exit "$status"
