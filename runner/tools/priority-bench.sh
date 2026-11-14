#!/usr/bin/env bash
# Job priority measurements (#549). Run inside a scope the caller capped (`agent-run NAME -- ...`);
# needs a delegated cgroup with cpu and memory (a systemd user scope), python3, and the harness:
#   zig build-exe runner/src/priobench.zig -O ReleaseSafe -femit-bin=$PRIOBENCH
#
#   priority-bench.sh cpu    two CPU-bound jobs on the same CPUs, one high and one low
#   priority-bench.sh cache  a job re-reading its files while a low one streams through a big file
#
# Prints one line a run: variant, the high job's wall time in seconds. Variants run interleaved, so
# that drift in what else the machine does hits each alike.
set -euo pipefail
mode=${1:?cpu|cache}; runs=${RUNS:-5}
bench=${PRIOBENCH:?path of the priobench binary}
root=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
work=${WORK:-/home/lement/.cache/priobench}; mkdir -p "$work"
cd "$root"; mkdir -p leaf
# The scope may hold only leaves to give its children controllers: this shell moves out first.
echo $$ > leaf/cgroup.procs 2>/dev/null || true
echo "+cpu +memory" > cgroup.subtree_control 2>/dev/null || true
mkdir -p p; echo "+cpu +memory" > p/cgroup.subtree_control
P=$root/p

spin='
import sys
n=int(sys.argv[1])
x=0
for i in range(n): x+=i*i
'
# hi re-reads a 200 MB file 25 times; lo streams a 1.5 GB file for ever.
reader='
import sys
f=open(sys.argv[1],"rb"); passes=int(sys.argv[2])
for _ in range(passes):
    f.seek(0)
    while f.read(1<<20): pass
'

start_in() { # dir cmd... : starts cmd in cgroup dir; its pid is PID
  local dir=$1; shift
  ( echo $BASHPID > "$dir/cgroup.procs"; exec "$@" ) &
  PID=$!
}

now() { date +%s.%N; }

run_cpu() { # variant
  local v=$1 hi=$P/hi lo=$P/lo
  mkdir -p "$hi" "$lo"
  case $v in
    flat) echo 100 > "$hi/cpu.weight"; echo 100 > "$lo/cpu.weight" ;;
    prio) "$bench" weights "$hi" high >/dev/null; "$bench" weights "$lo" low >/dev/null ;;
  esac
  local t0; t0=$(now)
  local hp=() lp=()
  for _ in 1 2; do
    start_in "$hi" taskset -c 6,7 python3 -c "$spin" 12000000; hp+=("$PID")
    start_in "$lo" taskset -c 6,7 python3 -c "$spin" 12000000; lp+=("$PID")
  done
  wait "${hp[@]}"; local t1; t1=$(now)
  wait "${lp[@]}"; local t2; t2=$(now)
  rmdir "$hi" "$lo"
  echo "$v hi=$(echo "$t1 - $t0" | bc) lo=$(echo "$t2 - $t0" | bc)"
}

run_cache() { # variant
  local v=$1 hi=$P/hi lo=$P/lo
  mkdir -p "$hi" "$lo"
  echo 420M > "$P/memory.max"; echo 0 > "$P/memory.swap.max" 2>/dev/null || true
  local gov=()
  case $v in
    flat) ;;
    prio) "$bench" weights "$hi" high 260 >/dev/null; "$bench" weights "$lo" low >/dev/null ;;
    freeze) "$bench" weights "$hi" high 260 >/dev/null; "$bench" weights "$lo" low >/dev/null ;;
  esac
  local mode=nofreeze; [[ $v == freeze ]] && mode=freeze
  # The governor reads the pressure of the cgroup both jobs share, and freezes in `lo/steps`.
  mkdir -p "$hi/steps" "$lo/steps"
  "$bench" govern "$P/memory.pressure" $mode "$hi:7:260" "$lo:1:300" & local gp=$!
  sync; echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true
  start_in "$lo/steps" python3 -c "$reader" "$work/big" 100000; local lp=$PID
  sleep 2
  local t0; t0=$(now)
  start_in "$hi/steps" python3 -c "$reader" "$work/small" 25; local hp=$PID
  wait "$hp"; local t1; t1=$(now)
  echo 0 > "$lo/steps/cgroup.freeze" 2>/dev/null || true
  kill "$lp" "$gp" 2>/dev/null || true; wait "$lp" "$gp" 2>/dev/null || true
  rmdir "$hi/steps" "$lo/steps" "$hi" "$lo"
  echo "$v hi=$(echo "$t1 - $t0" | bc)"
}

case $mode in
  cpu) variants="flat prio"; fn=run_cpu ;;
  cache)
    variants="flat prio freeze"; fn=run_cache
    [[ -f $work/small ]] || head -c 200M /dev/urandom > "$work/small"
    [[ -f $work/big ]] || head -c 1500M /dev/urandom > "$work/big" ;;
esac
echo "# load $(cut -d' ' -f1-3 /proc/loadavg) at start; cpus $(nproc); $(date -Is)"
for r in $(seq "$runs"); do for v in $variants; do $fn "$v"; done; done
echo "# load $(cut -d' ' -f1-3 /proc/loadavg) at end"
rmdir "$P" 2>/dev/null || true
