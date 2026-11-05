#!/usr/bin/env bash
# The native layer store (runner/src/native/Store.zig) across a crash and on a disk that fails
# writes, on Linux's device-mapper, which root on a throwaway VM can use (the `analysis`
# workflow's Store crash job). Until this the store's durability was only read: the order of its
# fsyncs, its `syncfs`, its rename and the check once per boot were reviewed (#298), never run.
#
#   store-crash.sh build DIR     compiles the Zig half (runner/src/native/store_crash.zig) and
#                                replay-log, into DIR
#   store-crash.sh crash DIR     as root: a sequence of store operations on ext4 over dm-log-writes,
#                                then the disk put back as it was at each flush, each FUA and each
#                                mark of the log, mounted, and the store checked
#   store-crash.sh errors DIR    as root: a publish on ext4 over dm-flakey while it fails writes
#
# The crash points. dm-log-writes records every write the block layer sees, and where the
# filesystem flushed or wrote with FUA, in order. The disk is put back, by xfstests' own replay-log
# (src/log-writes: the prior art, built here from the commit pinned below, as no Ubuntu package
# has it), to what it held up to each of those entries: what a power cut at that moment leaves,
# the writes that had reached the disk's cache before it all in order. Each is mounted (ext4
# replays its journal, as at a boot), `e2fsck -n` checks the filesystem, and the Zig half
# checks the store: the first job after the crash is the first of a boot (checkOncePerBoot); then
# no layer that `open` accepts differs from what was published, nothing a job had finished and
# synced is missing, and the same holds for `oci.Store.ensure`'s directory and `volumes.adoptSeed`'s
# seed. The last mark the log passed says which jobs had finished.
#
# Two checks of the check: the finished disk with a layer cut a byte short and with a byte changed
# must fail it, or it would pass whatever the store did.
#
# The write errors. dm-flakey is switched to fail every write (error_writes) around the call
# that must notice: `syncTree` itself, a publish of a small layer (its fsyncs) and of a large one
# (`syncfs`), and a publish whose own writes succeed but whose job saw another write fail
# (`Store.sync_fd`, the descriptor opened at the job's start: a `syncfs` on one opened at the
# publish would not report an error another job's `syncfs` had already). Each must fail, with
# error.Sync, and leave no layer published, also once the disk is mounted again.
set -euo pipefail
cd "$(dirname "$0")/../.."

# xfstests' replay-log, by commit (a fetch of one commit checks it: git names it by its hash).
fstests_url=https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git
fstests_rev=22348afe338c0f6d540c0d7ef0db749eaa51b218

build() {
	local out=$1
	mkdir -p "$out"
	git init -q "$out/fstests"
	git -C "$out/fstests" fetch -q --depth 1 "$fstests_url" "$fstests_rev"
	git -C "$out/fstests" checkout -q FETCH_HEAD
	local src=$out/fstests/src/log-writes
	gcc -O2 -Wall -D_FILE_OFFSET_BITS=64 -o "$out/replay-log" "$src/replay-log.c" "$src/log-writes.c"

	# shellcheck source=.github/scripts/zig-modules.sh
	. .github/scripts/zig-modules.sh
	cd runner
	git describe --tags --always --dirty --abbrev=8 >"$out/version"
	zig_modules "$out" "$out/version"
	# shellcheck disable=SC2154 # zig_modules sets it
	zig test "${modules[@]}" --test-filter "native store crash" --test-no-exec -femit-bin="$out/test"
}

# The Zig half: store_test MODE ROOT ARG, with ZIG_TEST_STORE_CRASH_MARK and _FLIP set by the caller.
store_test() {
	ZIG_TEST_STORE_CRASH="$1 $2 $work/scratch ${3:-}" "$work/test"
}

# mkdev NAME SIZE: a loop device on a new SIZE disk image with ext4 on it, in `dev`; `sectors`
# its size. The kernel's modules the targets need are loaded by their first use.
mkdev() {
	truncate -s "$2" "$work/$1.img"
	dev=$(losetup --find --show "$work/$1.img")
	loops+=("$dev")
	# Written now, not by the kernel while the test runs: the log holds the test's writes only.
	mkfs.ext4 -q -F -E lazy_itable_init=0,lazy_journal_init=0 "$dev"
	blockdev --flushbufs "$dev"
	sectors=$(blockdev --getsz "$dev")
}

# Everything mounted, mapped and attached since, in the reverse order.
loops=()
mapped=()
mounted=()
cleanup() {
	local m
	for ((i = ${#mounted[@]} - 1; i >= 0; i--)); do umount "${mounted[i]}" 2>/dev/null || true; done
	for m in "${mapped[@]}"; do dmsetup remove --retry "$m" 2>/dev/null || true; done
	for m in "${loops[@]}"; do losetup -d "$m" 2>/dev/null || true; done
}

mount_at() {
	mount -t ext4 "$@"
	mounted+=("${@: -1}")
}

# The module the kernel may not have: a clear error, where CI's job says what it found.
need_target() {
	modprobe "$1" || {
		echo "::error title=Store crash::this kernel ($(uname -r)) has no $1: $(modprobe -n -v "$1" 2>&1 | tail -n 1)"
		exit 1
	}
}

crash() {
	need_target dm-log-writes
	local w=$work
	mkdir -p "$w/mnt" "$w/check" "$w/scratch"
	mkdev disk 128M
	local disk=$dev
	cp --sparse=always "$w/disk.img" "$w/base.img"
	truncate -s 1G "$w/log.img"
	local logdev
	logdev=$(losetup --find --show "$w/log.img")
	loops+=("$logdev")
	dmsetup create store-log --table "0 $sectors log-writes $disk $logdev"
	mapped+=(store-log)
	# Marks into the log, in order: the log says where a mark is, not what it is called.
	: >"$w/marks.txt"
	printf '#!/bin/sh\ndmsetup message store-log 0 "mark $1" && echo "$1" >>%s\n' "$w/marks.txt" >"$w/mark"
	chmod +x "$w/mark"
	export ZIG_TEST_STORE_CRASH_MARK=$w/mark
	mount_at /dev/mapper/store-log "$w/mnt"
	"$w/mark" start
	mkdir "$w/mnt/w"
	local step
	for step in 1 2 3 4 5 6; do
		store_test write "$w/mnt/w" "$step" >"$w/step.log" 2>&1 || {
			cat "$w/step.log"
			echo "::error title=Store crash::step $step of the sequence failed"
			return 1
		}
		tail -n 1 "$w/step.log"
	done
	"$w/mark" end
	umount "$w/mnt"
	dmsetup remove store-log
	mapped=()
	unset ZIG_TEST_STORE_CRASH_MARK

	# Every entry of the log: its number, and flags.
	cp --sparse=always "$w/base.img" "$w/point.img"
	local l
	l=$(losetup --find --show "$w/point.img")
	loops+=("$l")
	"$work/replay-log" --log "$w/log.img" --replay "$l" -vv >"$w/entries.txt"
	losetup -d "$l"
	# Where to put the disk back to: after each mark, each flush and each FUA before the end.
	# LIMIT MARK KIND, MARK the last the log had passed.
	awk -v marks="$w/marks.txt" '
		BEGIN { while ((getline line < marks) > 0) name[++n] = line; last = "none" }
		/^(replaying|skipping) [0-9]+@/ {
			split($2, at, "@")
			flags = $0
			sub(/.*flags 0x[0-9a-f]+\(/, "", flags)
			sub(/\)$/, "", flags)
			if (flags ~ /MARK/) {
				last = name[++seen]
				if (last == "end") exit
				print at[1] + 1, last, "mark"
			} else if (flags ~ /FLUSH|FUA/) {
				print at[1] + 1, last, (flags ~ /FUA/ ? "fua" : "flush")
			}
		}' "$w/entries.txt" >"$w/points.txt"
	local points
	points=$(wc -l <"$w/points.txt")
	echo "the log has $(grep -c '^replaying\|^skipping' "$w/entries.txt") entries, $points crash points: $(awk '{n[$3]++} END {for (k in n) printf "%d %s ", n[k], k}' "$w/points.txt")"
	((points >= 20)) || {
		echo "::error title=Store crash::only $points crash points; the log should hold far more"
		return 1
	}

	local limit mark kind bad=0 count=0 started=$SECONDS
	: >"$w/outcomes.txt"
	mkdir -p "$w/failures"
	while read -r limit mark kind; do
		count=$((count + 1))
		if ! point "$limit" "$mark" "$kind"; then bad=$((bad + 1)); fi
	done <"$w/points.txt"
	echo "$count crash points in $((SECONDS - started)) s, $bad failed"
	echo "disks seen, by layers a hit found and directories published whole (points):"
	sort "$w/outcomes.txt" | uniq -c | sed 's/^/  /'
	echo "the last mark each point had passed (points):"
	awk '{print $2}' "$w/points.txt" | sort | uniq -c | sed 's/^/  /'
	((bad == 0)) || {
		echo "::error title=Store crash::$bad of $count crash points failed the store's checks"
		return 1
	}
	controls "$(tail -n 1 "$w/points.txt" | cut -d' ' -f1)"
}

# point LIMIT MARK KIND: the disk as it was after LIMIT entries of the log, mounted and checked.
point() {
	local limit=$1 mark=$2 kind=$3 w=$work why=
	restore "$limit"
	if ! mount_point; then
		why="would not mount"
	elif ! store_test verify "$w/check/w" "$mark" >"$w/verify.log" 2>&1; then
		why="the store: $(grep -m 3 'VIOLATION\|error' "$w/verify.log" | tr '\n' ';')"
	fi
	umount "$w/check" 2>/dev/null || true
	if [[ -z $why ]] && ! e2fsck -fn "$point_dev" >"$w/fsck.log" 2>&1; then
		why="e2fsck: $(grep -m 3 -v '^$' "$w/fsck.log" | tr '\n' ';')"
	fi
	[[ -n $why ]] || grep -o '[0-9]* layers hit, [0-9]* directories' "$w/verify.log" >>"$w/outcomes.txt" || true
	losetup -d "$point_dev"
	if [[ -n $why ]]; then
		echo "FAIL after $limit entries ($kind, last mark $mark): $why"
		cp "$w/verify.log" "$w/failures/verify-$limit.log" 2>/dev/null || true
		return 1
	fi
}

# restore LIMIT: `point_dev` a loop device on the base disk with the first LIMIT entries replayed.
restore() {
	cp --sparse=always "$work/base.img" "$work/point.img"
	point_dev=$(losetup --find --show "$work/point.img")
	"$work/replay-log" --log "$work/log.img" --replay "$point_dev" --limit "$1"
}

mount_point() {
	mount -t ext4 "$point_dev" "$work/check"
}

# controls LIMIT: the disk as it ended, with a layer the store should refuse changed on purpose:
# the check must fail, or it checks nothing.
controls() {
	local how
	for how in truncate flip; do
		restore "$1"
		mount_point
		store_test corrupt "$work/check/w" "$how" >/dev/null 2>&1
		if store_test verify "$work/check/w" after-6 >"$work/control.log" 2>&1; then
			umount "$work/check"
			losetup -d "$point_dev"
			echo "::error title=Store crash::the check passed a layer changed on purpose ($how)"
			return 1
		fi
		echo "control ($how): the check fails, as it must: $(grep -m 1 VIOLATION "$work/control.log")"
		umount "$work/check"
		losetup -d "$point_dev"
	done
}

errors() {
	need_target dm-flakey
	local w=$work arg failed=0
	mkdir -p "$w/mnt" "$w/scratch"
	for arg in sync-tree small large cursor no-cursor; do
		echo "--- $arg"
		if ! error_case "$arg"; then
			failed=$((failed + 1))
			echo "::error title=Store crash::the write-error case $arg failed"
			dmesg | tail -n 30 || true
		fi
		cleanup
		loops=()
		mapped=()
		mounted=()
	done
	((failed == 0))
}

# error_case ARG: a new disk, the Zig half's `fail` with the disk failing writes when it says so,
# and then the disk mounted again, which must hold no layer.
error_case() {
	local arg=$1 w=$work
	mkdev fail 64M
	local up="0 $sectors linear $dev 0"
	local down="0 $sectors flakey $dev 0 0 1 1 error_writes"
	dmsetup create store-fail --table "$up"
	mapped+=(store-fail)
	# Switched with no sync of the filesystem (--nolockfs): that would write what the test needs
	# written later, and nothing is queued behind a suspend of a device nothing is writing.
	printf '#!/bin/sh\nset -e\ncase $1 in\non) t="%s" ;;\n*) t="%s" ;;\nesac\n' "$down" "$up" >"$w/flip"
	printf 'dmsetup suspend --nolockfs --noflush store-fail\ndmsetup load store-fail --table "$t"\ndmsetup resume store-fail\n' >>"$w/flip"
	chmod +x "$w/flip"
	export ZIG_TEST_STORE_CRASH_FLIP=$w/flip
	# commit=300: no journal commit while the disk fails, which would end the filesystem.
	mount_at -o commit=300 /dev/mapper/store-fail "$w/mnt"
	mkdir "$w/mnt/w"
	local rc=0
	store_test fail "$w/mnt/w" "$arg" >"$w/case.log" 2>&1 || rc=1
	grep 'native store crash' "$w/case.log" || true
	((rc == 0)) || cat "$w/case.log"
	unset ZIG_TEST_STORE_CRASH_FLIP
	umount "$w/mnt" || true
	mounted=()
	mount_at /dev/mapper/store-fail "$w/mnt"
	if [[ $arg != no-cursor ]]; then
		store_test absent "$w/mnt/w" >"$w/case.log" 2>&1 || rc=1
		grep 'native store crash' "$w/case.log" || cat "$w/case.log"
	fi
	return "$rc"
}

# What a failure leaves for the job to upload: the log of writes and the disk it started from, to
# put a crash point back by hand (replay-log --log log.img --replay DEVICE --limit N), and what
# each point found.
keep() {
	mkdir -p "$work/keep"
	cp -r "$work/failures" "$work"/{points,marks,entries}.txt "$work/keep/" 2>/dev/null || true
	cp "$work"/*.log "$work/keep/" 2>/dev/null || true
	gzip -c "$work/base.img" >"$work/keep/base.img.gz" 2>/dev/null || true
	gzip -c "$work/log.img" >"$work/keep/log.img.gz" 2>/dev/null || true
	dmesg | tail -n 200 >"$work/keep/dmesg.txt" || true
}

cmd=${1:-}
work=${2:?usage: store-crash.sh build|crash|errors DIR}
mkdir -p "$work"
work=$(realpath "$work")
case $cmd in
build) build "$work" ;;
crash | errors)
	((EUID == 0)) || {
		echo "store-crash.sh $cmd needs root (sudo)" >&2
		exit 1
	}
	trap 'rc=$?; ((rc == 0)) || keep; cleanup' EXIT
	"$cmd"
	;;
*)
	echo "usage: store-crash.sh build|crash|errors DIR" >&2
	exit 1
	;;
esac
