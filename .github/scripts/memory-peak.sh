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
# "none" for no cgroup: how this script's fallbacks are tried.
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

if [[ -x /usr/bin/time ]]; then
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

"$@"
status=$?
report unavailable none
exit "$status"
