#!/usr/bin/env bash
# Model-checks the TLA+ modules with SPIN, on their Promela ports: proofs/spin/<Module>Model.pml for
# proofs/tla/<Module>.tla, StoreLocking's, StoreDeferred's, StoreEviction's and ReleasePipeline's
# (proofs/README.md, "The store's locking, in SPIN").
# SPIN is 6.5.2, Ubuntu's spin 6.5.2+dfsg-2build1 (store-model.yml pins the package), and any other
# version fails here, so a changed SPIN is a change made on purpose.
#
# Each proofs/spin/<Module>*.pml but <Module>Model.pml is a configuration written from the proofs/tla
# .cfg of the same name (proofs/spin/cfg.py; a stale one fails the job). A configuration of the
# protocol as the code has it must hold, and must reach exactly the states its `spin-states:` line
# says, the reference (cfg.py copies it from the .cfg). A different count means the Promela changed
# in a way the TLA+ module, its documentation, does not say: change both, and the count with them. A configuration with temporal properties (its `spin-ltl:` line) then checks
# each of them alone, with SPIN's weak fairness (pan -a -f), on the model built with LIVENESS. A
# mutant, the code with one guard taken away, says "must fail: <property>" in its first line and must
# fail with that invariant's assertion, or, for a temporal property, with that property's claim.
#
# The search is exhaustive: no bitstate or hash compaction, which may miss states, and no partial
# order reduction, which reduces nothing here (every step touches the shared store) and costs time.
# The configurations run side by side, each in its own directory under $SPIN_DIR, as many at once as
# the machine gives this script (see "Concurrency" below). Their
# output is not interleaved: pan prints its report once, at the end, so each configuration says when
# it starts and, with its verdict, when it ends (a line naming it, in the order they finish), and a
# heartbeat line says every minute which are still running. The ordered verdicts follow at the end.
#
# Locally: .github/scripts/spin.sh (spin 6.5.2, gcc and python3 on the PATH).
set -euo pipefail
# Job control: each worker below leads a process group of its own, so that the EXIT trap, or the
# heartbeat after a SIGKILL, ends it with the spin, gcc and pan it runs.
set -m

version="Spin Version 6.5.2 -- 6 December 2019"
here=$(cd "$(dirname "$0")/../../proofs/spin" && pwd)
dir="${SPIN_DIR:-${RUNNER_TEMP:-/tmp}/spin}"
# shellcheck source=.github/scripts/spin-heartbeat.sh
source "$(dirname "$0")/spin-heartbeat.sh"

if [[ $(spin -V 2>&1) != "$version" ]]; then
	echo "spin -V says '$(spin -V 2>&1)', not '$version'" >&2
	exit 1
fi
python3 -I "$here/cfg.py" --check

# build <name> safety|liveness: spin -a and gcc in the current directory, pan-<kind> the verifier.
# The safety one has no never claim; the liveness one has the stutter of LIVENESS and the claims.
# A variable no step reads (a ghost a mutant does not check) stays in the state (-o2), as it is in
# the TLA+ module's.
build() {
	local name=$1 kind=$2
	if [[ $kind == safety ]]; then
		spin -o2 -a "$name.pml" >spin-safety.out 2>&1 &&
			gcc -O2 -w -DSAFETY -DNOREDUCE -DNOCLAIM -o pan-safety pan.c >gcc-safety.out 2>&1
	else
		spin -o2 -DLIVENESS -a "$name.pml" >spin-liveness.out 2>&1 &&
			gcc -O2 -w -DNOREDUCE -o pan-liveness pan.c >gcc-liveness.out 2>&1
	fi
}

# live <property>: pan-liveness on one claim, its report in pan-<property>.out.
live() {
	./pan-liveness -m1000000 -w"$hw" -a -f -N "$1" >"pan-$1.out" 2>&1 || true
}

# table_bits <states>: pan's -w, the hash table's size as a power of two; <states> is the spin-states
# line, empty for a mutant. The table is 2^bits slots of 8 bytes: 32 MB for a mutant (2^22), not the
# 512 MB of -w26. The size is only speed, never which states are found (each slot is a chain): about
# twice the states, at most 2^26.
table_bits() {
	local ns=$1 hw=22
	if [[ -n $ns ]]; then
		hw=19
		while ((hw < 26 && (1 << (hw - 1)) < ns)); do hw=$((hw + 1)); done
	fi
	echo "$hw"
}

# Concurrency. A worker is a core and the memory of its pan: the hash table, 8 bytes a slot, and every
# state it stores (the state vector and pan's overhead). Memory, not cores, ran out on a laptop with
# 16 cores in a 4 GB scope: the biggest checks would have held 2 GB at once each, and the kernel
# killed one, and systemd then the whole scope. So the script starts a configuration only while
# both fit what it is given:
#   cores   the smaller of nproc (affinity) and the CPU quota (cpu.max, cgroup v2) of its cgroup or
#           any ancestor, rounded down, at least 1;
#   memory  70% of what is left under the smallest memory.max or memory.high of its cgroup and its
#           ancestors (their limit minus what they hold now) and of MemAvailable, against the sum of
#           the running configurations' estimates (est_mb). One configuration always runs, however
#           large its estimate.
# SPIN_JOBS=N overrides both: N at a time, the memory not looked at. SPIN_MEM_MB=M overrides the
# memory it may use. Only the number running at once changes, never a configuration or its verdict.

# cgroup_limits: cg_cpus (a count) and cg_mem (MB left), set to the cgroup's limits, empty without.
# SPIN_CGROUP_ROOT is for tests.
cgroup_limits() {
	local root=${SPIN_CGROUP_ROOT:-/sys/fs/cgroup} rel d f q p v cur c
	cg_cpus='' cg_mem=''
	rel=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null) || rel=''
	d="$root${rel%/}"
	while [[ -d $d ]]; do
		if [[ -r $d/cpu.max ]] && { read -r q p <"$d/cpu.max"; } 2>/dev/null &&
			[[ $q =~ ^[0-9]+$ && $p =~ ^[0-9]+$ ]] && ((p > 0)); then
			c=$((q / p))
			((c >= 1)) || c=1
			if [[ -z $cg_cpus ]] || ((c < cg_cpus)); then cg_cpus=$c; fi
		fi
		for f in memory.max memory.high; do
			{ read -r v <"$d/$f"; } 2>/dev/null || continue
			[[ $v =~ ^[0-9]+$ ]] || continue
			{ read -r cur <"$d/memory.current"; } 2>/dev/null || cur=0
			[[ $cur =~ ^[0-9]+$ ]] || cur=0
			c=$(((v - cur) / 1048576))
			((c >= 0)) || c=0
			if [[ -z $cg_mem ]] || ((c < cg_mem)); then cg_mem=$c; fi
		done
		[[ $d == "$root" ]] && break
		d=${d%/*}
	done
}

# est_mb <name>: the megabytes pan peaks at on this configuration, from its spin-states line and
# table_bits: 150 for the compile, the report and a mutant's states to its violation, the hash table,
# and the states times bytes each, measured on 2026-11-15 (peak RSS of each pan, run alone) and
# rounded up by 10 to 20%: StoreLocking 2025 MB for 16.5 M states, -crash 1719 for 14.7 M, -faults
# 1330 for 10.8 M, StoreEviction-crash 1260 for 7.4 M, StoreEviction 593 for 3.1 M, ReleasePipeline
# 313 for 2.0 M; the mutants and the rest 12 to 230 MB.
est_mb() {
	local ns bytes
	ns=$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$here/$1.pml")
	case $1 in
	StoreLocking*) bytes=110 ;;
	ReleasePipeline*) bytes=140 ;;
	*) bytes=175 ;; # StoreEviction measured about 170; a module not measured is taken at least that
	esac
	echo $((150 + (8 << $(table_bits "$ns")) / 1048576 + ${ns:-0} * bytes / 1048576))
}

# plan_jobs: jobs, how many at once, and mem_mb, the budget their estimates must fit.
plan_jobs() {
	local avail cpus mem
	cpus=$(nproc)
	cgroup_limits
	[[ -z $cg_cpus ]] || ((cg_cpus >= cpus)) || cpus=$cg_cpus
	mem=$(sed -n 's/^MemAvailable: *\([0-9]*\) kB/\1/p' /proc/meminfo)
	avail=''
	if [[ -n $mem ]]; then
		avail=$((mem / 1024))
	else
		echo "spin: no MemAvailable in /proc/meminfo; the memory limit is the cgroup's, if any" >&2
	fi
	if [[ -n $cg_mem ]] && { [[ -z $avail ]] || ((cg_mem < avail)); }; then avail=$cg_mem; fi
	mem_mb=-1 # not looked at
	if [[ -n $avail ]]; then mem_mb=$((avail * 70 / 100)); fi
	jobs=$cpus
	if [[ -n ${SPIN_MEM_MB:-} ]]; then mem_mb=$SPIN_MEM_MB; fi
	if [[ -n ${SPIN_JOBS:-} ]]; then
		jobs=$SPIN_JOBS
		mem_mb=-1
	fi
}

# check_env: SPIN_JOBS and SPIN_MEM_MB, when set, are positive decimal integers.
check_env() {
	local v
	for v in SPIN_JOBS SPIN_MEM_MB; do
		if [[ -n ${!v:-} && ! ${!v} =~ ^[1-9][0-9]*$ ]]; then
			echo "spin: $v='${!v}' is not a positive decimal integer" >&2
			exit 1
		fi
	done
}

stored() { sed -n 's/^ *\([0-9]*\) states, stored.*/\1/p' "$1"; }
elapsed() { sed -n 's/^pan: elapsed time \(.*\)/\1/p' "$1"; }

# check <name>: compiles and runs one configuration in $dir/<name>; the verdict is in result.
check() {
	local name=$1 w="$dir/$1" started=$SECONDS first want ltl p verdict ns hw
	rm -rf "${w:?}"
	mkdir -p "$w"
	cp "$here"/*.pml "$w"/
	cd "$w"
	echo "[$name] spin, gcc and pan started"
	first=$(head -n 1 "$name.pml")
	want=$(sed -n 's/.*must fail: \([A-Za-z]*\).*/\1/p' <<<"$first")
	ltl=$(sed -n 's/^ \* spin-ltl: \([A-Za-z ]*\).*/\1/p' "$name.pml")
	ns=$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$name.pml")
	hw=$(table_bits "$ns")
	if [[ -n $want && " $ltl " == *" $want "* ]]; then
		# A mutant that must fail a temporal property: its claim's violation, under fairness.
		if ! build "$name" liveness; then
			verdict="$name: spin -a or gcc failed"
		elif live "$want" && grep -qE '^pan:1: (acceptance cycle|claim violated)' "pan-$want.out"; then
			verdict="ok: fails $want ($(stored "pan-$want.out") states to the first violation)"
		else
			verdict="$name: SPIN did not fail $want"
		fi
	elif ! build "$name" safety; then
		verdict="$name: spin -a or gcc failed"
	else
		./pan-safety -m100000 -w"$hw" >pan.out 2>&1 || true
		if [[ -n $want ]]; then
			if grep -q "^pan:1: assertion violated $want " pan.out; then
				verdict="ok: fails with $want ($(stored pan.out) states to the first violation)"
			else
				verdict="$name: SPIN did not fail with $want"
			fi
		else
			want=$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$name.pml")
			if ! grep -q 'errors: 0$' pan.out || grep -qE 'max search depth too small|violated|out of memory' pan.out; then
				verdict="$name: SPIN found an error, or did not finish"
			elif [[ $(stored pan.out) != "$want" ]]; then
				verdict="$name: $(stored pan.out) states, not the $want of its spin-states line: the Promela and the TLA+ differ"
			else
				verdict="ok: holds, $(stored pan.out) states, $(elapsed pan.out)"
				if [[ -n $ltl ]] && ! build "$name" liveness; then
					verdict="$name: spin -a or gcc failed (LIVENESS)"
				fi
				for p in $ltl; do
					[[ $verdict == ok:* ]] || break
					live "$p"
					if ! grep -q 'errors: 0$' "pan-$p.out" ||
						grep -qE 'max search depth too small|violated|acceptance cycle|out of memory' "pan-$p.out"; then
						verdict="$name: SPIN found $p violated, or did not finish"
					else
						verdict+="; $p holds ($(stored "pan-$p.out") states with its claim, $(elapsed "pan-$p.out"))"
					fi
				done
			fi
		fi
	fi
	echo "$verdict" >result
	echo "[$name] ended after $((SECONDS - started)) s: $verdict"
	echo "$name" >>"$dir/finished"
}

names=()
for f in "$here"/*.pml; do
	f=$(basename "$f" .pml)
	[[ $f == *Model ]] || names+=("$f")
done
# The largest first, so the long ones start at once.
mapfile -t names < <(for n in "${names[@]}"; do
	printf '%s %s\n' "$(sed -n 's/^ \* spin-states: \([0-9]*\).*/\1/p' "$here/$n.pml")" "$n"
done | sort -k1,1nr | cut -d' ' -f2)
check_env
running=0
used=0
declare -A cost
mkdir -p "$dir"
# One run at a time in a directory: the pre-push hooks of two worktrees share one, and a second run
# would delete the first's configurations under it. The lock is on this file, held through fd 9,
# which every worker inherits: workers that outlive a SIGKILLed script still hold it until they end,
# so a later run waits for them.
exec 9>"$dir/lock"
if ! flock -n 9; then
	echo "spin: $dir is in use by another run; waiting for it"
	flock 9
fi
plan_jobs
: >"$dir/finished"
: >"$dir/workers"
# Nothing outlives this script, on any path. The EXIT trap ends the heartbeat and every worker's
# process group (INT and TERM exit, so the trap runs); for the death no trap sees, the heartbeat asks
# after this script at every tick and, when it is gone, ends the groups listed in $dir/workers.
heartbeat=
pids=()
trap 'spin_stop "$heartbeat" "${pids[@]}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# shellcheck disable=SC2329 # run by heartbeat_loop, by name
progress() {
	echo "spin: $SECONDS s, $(wc -l <"$dir/finished") of ${#names[@]} configurations finished"
}
heartbeat_loop "$$" "${SPIN_HEARTBEAT_S:-60}" "$dir/workers" progress &
heartbeat=$!
if ((mem_mb < 0)); then budget="its memory not looked at"; else budget="estimates within $mem_mb MB"; fi
echo "spin: ${#names[@]} configurations, $jobs at a time, $budget"
pending=("${names[@]}")
while ((${#pending[@]})); do
	pick=-1
	if ((running < jobs)); then
		# The first, the largest, that fits; with none running, the first however large.
		for i in "${!pending[@]}"; do
			e=$(est_mb "${pending[$i]}")
			if ((running == 0 || mem_mb < 0 || used + e <= mem_mb)); then
				pick=$i
				break
			fi
		done
	fi
	if ((pick < 0)); then
		done_pid=''
		wait -n -p done_pid || true
		# Only a worker frees its share (not the heartbeat, say).
		if [[ -n $done_pid && -n ${cost[$done_pid]:-} ]]; then
			used=$((used - cost[$done_pid]))
			unset "cost[$done_pid]"
			running=$((running - 1))
		fi
		continue
	fi
	n=${pending[$pick]}
	unset "pending[$pick]"
	pending=("${pending[@]}")
	(check "$n") &
	pids+=($!)
	cost[$!]=$e
	used=$((used + e))
	echo "$!" >>"$dir/workers"
	running=$((running + 1))
done
wait "${pids[@]}" || true
spin_stop "$heartbeat"
heartbeat=
pids=()

status=0
for n in "${names[@]}"; do
	r=$(cat "$dir/$n/result")
	echo "== $n: ${r#ok: }"
	if [[ $r != ok:* ]]; then
		cat "$dir/$n"/spin-*.out "$dir/$n"/gcc-*.out "$dir/$n"/pan*.out 2>/dev/null | tail -n 40
		status=1
	fi
done
exit "$status"
