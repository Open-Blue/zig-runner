#!/usr/bin/env bash
# The end-to-end suite: real workflows through the real runner, GitHub's broker protocol and a real
# Dagger engine, which no unit test reaches (dagger.zig's run against a fake session). The
# workflows are runner-bench's e2e.yml and e2e-cancel.yml (Open-Blue/runner-bench), dispatched with
# a runner label of their own; this waits for them and checks the jobs' and steps' conclusions and
# their logs through GitHub's API: a script installing into the tool cache (v0.22.0 broke that), a
# service, a docker:// step, a JavaScript action, the file commands, a masked secret, a cancelled
# run, and a rerun replayed from the step cache. Each job's queue and run times go to
# $E2E_OUT/timings.tsv, with the backend it ran on, so one harness also compares Dagger and native.
# In CI the Dagger pass (where it runs: not on a pull request) comes first, on an engine just
# started: its times include the pulls and the pre-warm. The native pass's jobs that native hands
# to Dagger (ran_on dagger) then find the engine warm, so compare them with a Dagger job run
# again, not with the first pass; without the Dagger pass, those jobs find it cold.
#
#   e2e.sh check LABEL [BACKEND]    the suite, on the runners already serving LABEL
#
# By hand, before a release, against the laptop pool or razorbill (a runner of runner-bench whose
# RUNNER_TRUSTED_REFS has refs/heads/main): `e2e.sh check laptop`. gh's own login is used, or
# E2E_GH_TOKEN (Actions: read and write on runner-bench) when set. BACKEND only labels the timings.
#
# CI's "End to end" job (ci.yml) builds the runner and serves the suite itself, on GitHub's runner,
# root through sudo, once on Dagger and once native:
#
#   e2e.sh build BIN [tsan]         the runner, x86_64 ReleaseSafe, compiled directly (zig-modules.sh);
#                                   with tsan, under ThreadSanitizer (analysis.yml)
#   e2e.sh engine                   start the pinned engine, as deploy/compose.yaml runs it
#   e2e.sh rootfs BIN               the native backend's rootfs: ubuntu:24.04, provisioned
#   e2e.sh start BIN BACKEND LABEL  a pool of the runner, in the background, serving LABEL
#   e2e.sh stop                     stop it, as a deployment stops it (SIGTERM)
#   e2e.sh races BACKEND            fails on a ThreadSanitizer report in that pass's runner log or
#                                   job logs (a tsan build's; stop the runner first)
#
# Settings: E2E_REPO (Open-Blue/runner-bench), E2E_REF (main: the workflows' ref, and the one ref
# CI's runner trusts), E2E_TIMEOUT (seconds to wait for each run, or for the native rootfs, 600),
# E2E_SUITE_LIMIT (seconds `check` as a whole may wait for the runs, 300 in CI; a hang ends there
# with a message instead of at the step's or the job's limit, so that the logs survive; the
# reads after it get 90 s more), E2E_OUT (where the
# timings and the runner's log go), E2E_ZIG_RUNNER_REF (the zig-runner commit whose
# install-zig.sh the tool cache job runs, main). `start` also takes GH_APP_ID and
# GH_APP_PRIVATE_KEY_FILE, the runner's own (deploy/runner.env.example).
#
# After a native pass, where the native jobs' time went, per phase (native-phases.sh), from the
# runner's log when `start` started it. On razorbill, after `e2e.sh check pi-bench`:
# `journalctl -u zig-runner@bench.service --since '-15 min' | .github/scripts/native-phases.sh`.
set -euo pipefail
cd "$(dirname "$0")/../.."

repo=${E2E_REPO:-Open-Blue/runner-bench}
ref=${E2E_REF:-main}
timeout=${E2E_TIMEOUT:-600}
# `check`'s own clock, from the script's start: every wait ends by suite_end, and the reads after
# it (the jobs' lists and logs) by hard_end, so that the step's limit in ci.yml is never what ends it.
suite_end=$((SECONDS + ${E2E_SUITE_LIMIT:-1800}))
hard_end=$((suite_end + 90))
out=$(realpath -m "${E2E_OUT:-${RUNNER_TEMP:-/tmp}/e2e}")
mkdir -p "$out"
# The engine the runner speaks to (runner/src/engine.zig, client_version), pinned by digest;
# `start` checks it is the runner's.
engine_image=registry.dagger.io/engine:v0.21.10@sha256:2a7c054e0864e297671c24a0726ebf1c9747d70291b8843b1726daaff200a334
engine_name=zig-runner-e2e-engine
# The engine's socket, on the host: the runner reaches it as compose's runner does, with no Docker.
engine_dir=/run/zig-runner-e2e
rootfs=/var/lib/zig-runner-e2e/rootfs
# The container make_rootfs provisions in; wait_rootfs looks into it for its status lines.
rootfs_container=zig-runner-e2e-rootfs

usage() {
	sed -n 's/^#   \(e2e\.sh .*\)/\1/p' "$0" >&2
	exit 2
}

# --- the runner, its engine and rootfs (CI) -------------------------------------------------------

build() {
	local bin scratch target=(-target x86_64-linux-musl)
	bin=$(realpath -m "${1:?}")
	# ThreadSanitizer's runtime needs glibc's dynamic loader: built for the native target (glibc,
	# dynamic, a PIE still), as zig-test.sh's are, since the release's static PIE (musl, #283)
	# crashes at startup with it. The runner re-executes itself for the native backend's steps
	# (`zig-runner native-step`), so the helpers run under it too, their reports on their stderr,
	# which the runner writes into the job's log as the sandbox's failure.
	if [[ ${2:-} == tsan ]]; then target=(-fsanitize-thread); fi
	mkdir -p "$(dirname "$bin")"
	scratch=$(mktemp -d)
	cd runner
	# shellcheck source=.github/scripts/zig-modules.sh
	. ../.github/scripts/zig-modules.sh
	printf '%s' "e2e-$(git rev-parse --short HEAD)" >"$scratch/version"
	zig_modules "$scratch" "$scratch/version" -OReleaseSafe "${target[@]}"
	zig build-exe "${modules[@]}" --name runner -femit-bin="$bin"
	rm -rf "$scratch"
	"$bin" --version
	# A tsan build that is not one would pass `races` with nothing to report.
	if [[ ${2:-} == tsan ]] && ! grep -qaF __tsan_init "$bin"; then
		echo "the runner was built without ThreadSanitizer" >&2
		exit 1
	fi
}

engine() {
	sudo mkdir -p "$engine_dir"
	docker run -d --name "$engine_name" --privileged -e GOGC=400 \
		-v zig-runner-e2e-engine:/var/lib/dagger -v "$engine_dir:/run/dagger" \
		-v "$PWD/deploy/engine.json:/etc/dagger/engine.json:ro" \
		"$engine_image" --addr unix:///run/dagger/engine.sock >/dev/null
	for _ in $(seq 120); do
		if sudo test -S "$engine_dir/engine.sock"; then
			echo "engine up: $engine_image"
			return 0
		fi
		sleep 1
	done
	echo "the engine's socket did not appear within 2 minutes" >&2
	docker logs "$engine_name" >&2 || true
	exit 1
}

# The default image, provisioned for steps run as the runner user, exported into a directory
# (docs/native-backend.md, "The rootfs"): the image is the runner's own pin (default_image), the
# script its own (--provision-script). Writes $rootfs.ok, or $rootfs.failed, which `start` waits on,
# and its pid to $out/rootfs.pid, so that `start` can tell a build that is slow from one that died.
make_rootfs() {
	local bin image prefix script
	mkdir -p "$out"
	echo $$ >"$out/rootfs.pid"
	bin=$(realpath "${1:?}")
	image=$(tr -d '\n' <runner/src/dagger.zig |
		grep -oE '"ubuntu:[A-Za-z0-9._-]+" *\+\+ *"@sha256:[a-f0-9]{64}"' | tr -d '" +')
	script=$("$bin" --provision-script)
	echo "rootfs: building from $image for $(dpkg --print-architecture), with the runner's provision script (apt-get, quiet: its progress is the waiting job's status lines)"
	# With Ubuntu's archive down, the container's sources point at a mirror first (apt.sh, which says
	# on stderr, here in rootfs.log, what it probed and chose); the runner's script is otherwise the
	# one it ships.
	prefix=$(.github/scripts/apt.sh mirror-prefix "$(dpkg --print-architecture)" noble)
	if [[ -n $prefix ]]; then
		script="$prefix$script$(.github/scripts/apt.sh mirror-suffix)"
	fi
	sudo rm -rf "$rootfs" "$rootfs.ok" "$rootfs.failed"
	sudo mkdir -p "$rootfs"
	echo "rootfs: provisioning in container $rootfs_container"
	if docker run --name "$rootfs_container" "$image" sh -c "$script" &&
		docker export "$rootfs_container" | sudo tar -x -C "$rootfs"; then
		# The provisioning stamp, as the recipe makes it (docs/native-backend.md, "The rootfs").
		sudo touch "$rootfs/.zig-runner-provisioned" "$rootfs.ok"
		echo "rootfs: $image, provisioned, in $rootfs"
	else
		sudo touch "$rootfs.failed"
		echo "rootfs: provisioning $image failed" >&2
	fi
	docker rm "$rootfs_container" >/dev/null || true
}

# rootfs_status: one line on where the rootfs build is, for the job's log: the container's state, how
# much apt has fetched (its index lists, and its package archives with the partial downloads), its
# apt and dpkg processes with how long each has run, and how Ubuntu's archive answers the runner now.
# The provision script is quiet (apt-get -qq), so these are what tell a slow archive from a hang.
rootfs_status() {
	local state fetched="" procs=""
	state=$(docker inspect -f '{{.State.Status}}' "$rootfs_container" 2>/dev/null) || state="not made yet"
	if [[ $state == running ]]; then
		fetched=$(docker exec "$rootfs_container" sh -c 'du -sk /var/lib/apt/lists /var/cache/apt/archives/partial /var/cache/apt/archives 2>/dev/null' |
			awk '{ printf "%s%s %d KiB", sep, $2, $1; sep = ", " }')
		# `docker top` needs the pid column; it is dropped, and so is the `sh -c` around the whole
		# provision script (its arguments are the script).
		procs=$(docker top "$rootfs_container" -eo pid,etime,args 2>/dev/null |
			awk 'NR > 1 { $1 = ""; sub(/^ +/, "") } NR > 1 && !/^[0-9:-]+ sh -c/ && /apt|dpkg|http/ {
				gsub(/ +/, " "); printf "%s[%s]", sep, substr($0, 1, 100); sep = " " }')
	fi
	echo "container $state; fetched: ${fetched:-nothing yet}; running: ${procs:-no apt or dpkg}; archive now: $(.github/scripts/apt.sh probe "$(dpkg --print-architecture)" noble)"
}

# wait_rootfs: until `e2e.sh rootfs` has left $rootfs.ok, or $rootfs.failed, at most $timeout s (the
# suite's own limit). The build runs apt against Ubuntu's archive, so how long it takes depends on
# the network: it is waited for as long as its process (the pid in $out/rootfs.pid) is alive, and
# one that exited without a marker is reported at once. Every minute it prints the build's last log
# line and its status (rootfs_status); a timeout says the last status. Time is the clock's, not the
# loop's: the status's archive probe can take up to 30 s.
wait_rootfs() {
	local start=$SECONDS deadline=$((SECONDS + timeout)) pid="" waited=0 next=60 status="none taken yet"
	while ((SECONDS < deadline)); do
		waited=$((SECONDS - start))
		sudo test -e "$rootfs.ok" -o -e "$rootfs.failed" && break
		[[ -z $pid && -e $out/rootfs.pid ]] && pid=$(<"$out/rootfs.pid")
		# Not started yet: the step that starts it runs well before this one, so 30 s is plenty.
		if [[ -z $pid ]] && ((waited >= 30)); then
			echo "no native rootfs: e2e.sh rootfs never started (no $out/rootfs.pid)" >&2 && exit 1
		fi
		if [[ -n $pid ]] && ! kill -0 "$pid" 2>/dev/null; then
			# It may have finished between the two checks.
			sudo test -e "$rootfs.ok" -o -e "$rootfs.failed" && break
			echo "no native rootfs: e2e.sh rootfs (pid $pid) exited without a result; its log:" >&2
			tail -n 5 "$out/rootfs.log" >&2 2>/dev/null || true
			exit 1
		fi
		if ((waited >= next)); then
			status=$(rootfs_status)
			echo "waiting for the native rootfs, ${waited} s so far; rootfs.log: $(tail -n 1 "$out/rootfs.log" 2>/dev/null)"
			echo "  rootfs build at ${waited} s: $status"
			next=$((next + 60))
		fi
		sleep 1
	done
	waited=$((SECONDS - start))
	sudo test -e "$rootfs.ok" ||
		{ echo "no native rootfs (e2e.sh rootfs): ${waited} s, and the build $(sudo test -e "$rootfs.failed" && echo failed || echo "is still running: $(rootfs_status)"); the last status before: $status" >&2 && exit 1; }
}

start() {
	local bin=${2:?} backend=${3:?} label=${4:?} log
	bin=$(realpath "$bin")
	: "${GH_APP_ID:?}" "${GH_APP_PRIVATE_KEY_FILE:?}"
	[[ $backend == dagger || $backend == native ]] || usage
	local version=${engine_image%@*}
	version=${version##*:}
	[[ $("$bin" --version) == *"Dagger $version)"* ]] ||
		{ echo "the runner does not speak engine $version: $("$bin" --version)" >&2 && exit 1; }
	# `engine` may still be pulling, in the background.
	for _ in $(seq 180); do
		sudo test -S "$engine_dir/engine.sock" && break
		sleep 1
	done
	sudo test -S "$engine_dir/engine.sock" || { echo "no engine (e2e.sh engine)" >&2 && exit 1; }
	local native=()
	if [[ $backend == native ]]; then
		wait_rootfs
		# Ubuntu's AppArmor (24.04 on) blocks unprivileged user namespaces; the helper lifts it, as ci.yml's Test does.
		.github/scripts/allow-userns.sh
		native=(RUNNER_NATIVE_ROOTFS="$rootfs")
	fi
	log=$out/runner-$backend.log
	# One runner per job the suite runs at once (eight), on a machine that is the suite's alone:
	# the memory gate is off, so how fast the jobs start depends on GitHub, not on a reservation.
	# The Zig cache seed is not built: it costs 104 s of one core, and only the tool cache job runs
	# Zig. Only the dispatches of the workflows' ref are trusted; jobs from anywhere else fail.
	nohup sudo env TSAN_OPTIONS="suppressions=$PWD/.github/tsan.supp" GH_SCOPE="$repo" GH_APP_ID="$GH_APP_ID" \
		GH_APP_PRIVATE_KEY_FILE="$GH_APP_PRIVATE_KEY_FILE" \
		RUNNER_LABELS="self-hosted,linux,zig,$label" RUNNER_NAME_PREFIX="e2e-$backend" \
		RUNNER_COUNT=8 RUNNER_ADMISSION=false RUNNER_ZIG_SEED_VERSIONS= \
		RUNNER_ENGINE_HOST="unix://$engine_dir/engine.sock" \
		RUNNER_TRUSTED_REFS="refs/heads/$ref" RUNNER_TRUSTED_EVENTS=workflow_dispatch \
		RUNNER_STOP_GRACE_SECS=30 RUNNER_BACKEND="$backend" "${native[@]}" \
		"$bin" >"$log" 2>&1 &
	echo $! >"$out/runner.pid"
	# For `stop`, which runs as its own invocation and has no $backend (stuck_runner reads it).
	echo "$backend" >"$out/runner.backend"
	echo "runner ($backend) started, serving $label on $repo; its log: $log"
}

stop() {
	local pid
	[[ -e $out/runner.pid ]] || return 0
	pid=$(<"$out/runner.pid")
	rm -f "$out/runner.pid"
	# sudo passes the signal on to the runner.
	sudo kill -TERM "$pid" 2>/dev/null || return 0
	for _ in $(seq 60); do
		sudo kill -0 "$pid" 2>/dev/null || { echo "runner stopped" && return 0; }
		sleep 1
	done
	echo "::warning::the runner did not stop within 60 s: killed (#628: the facts below say why)" >&2
	stuck_runner "$pid" || true
	sudo kill -KILL "$pid" 2>/dev/null || true
}

# What a runner that ignored SIGTERM looks like (#628), printed before it is killed; never fails.
# PID is the process `start` launched (sudo, which passes signals on to its command): whether sudo
# is still there and the runner is its child, each thread's state, kernel stack and signal masks
# (SigBlk blocked, SigPnd/ShdPnd pending for the thread/process, SigCgt caught), the userspace
# stacks if gdb is on the image (it is not installed if missing), and the end of the runner's log.
stuck_runner() {
	local pid=${1:?} runner t f
	# `check` has $backend; `stop` runs as an invocation of its own and reads what `start` recorded.
	# With neither, "" (set -u stopped the 2026-11-20 nightly's diagnostics here, failing the step).
	local backend=${backend:-$(cat "$out/runner.backend" 2>/dev/null || true)}
	echo "::group::${2:-why the runner did not stop}"
	# Every process under PID, by walking parent links: sudo may run its command through a monitor
	# process of its own (sudo-rs with a pty), so the runner need not be PID's child.
	local tree
	tree=$(ps -eo pid=,ppid= | awk -v root="$pid" '{ parent[$1] = $2 } END {
		for (p in parent) { q = p; while (q != "" && q != root && q != 1 && q != 0) q = parent[q]; if (q == root) print p }
		print root }' | sort -nu | paste -sd, -)
	echo "== process tree (PID $pid signalled)"
	sudo ps -o pid,ppid,pgid,stat,wchan:20,etime,args -p "$tree" 2>&1 || true
	# The runner: the process under PID that runs the runner's binary (`zig-runner`, as `build` names
	# it), else PID itself.
	runner=$(ps -o pid=,comm= -p "$tree" 2>/dev/null | awk '$2 ~ /^zig-runner/ { print $1; exit }')
	runner=${runner:-$pid}
	echo "== the runner is PID $runner"
	echo "== runner PID $runner: signal state and kernel stack of each thread"
	for t in /proc/"$runner"/task/*; do
		echo "-- thread ${t##*/}: $(sudo cat "$t/comm" 2>&1) state=$(sudo awk '{print $3}' "$t/stat" 2>&1) wchan=$(sudo cat "$t/wchan" 2>&1)"
		sudo grep -E '^(SigPnd|ShdPnd|SigBlk|SigIgn|SigCgt):' "$t/status" 2>&1 || true
		sudo cat "$t/stack" 2>&1 | head -n 8 || true
	done
	if command -v gdb >/dev/null; then
		echo "== userspace stacks"
		sudo gnutimeout 30 gdb -p "$runner" -batch -ex 'thread apply all bt' 2>&1 | tail -n 300 || true
	else
		echo "== gdb is not installed on this image: no userspace stacks"
	fi
	if [[ $backend == dagger ]] && docker inspect "$engine_name" >/dev/null 2>&1; then
		echo "== the engine's container: its state and the last 60 lines of its log"
		docker ps -a --filter "name=$engine_name" --format '{{.Status}}' 2>&1 || true
		docker logs --tail 60 "$engine_name" 2>&1 | sed -E 's/(gh[opsu]|github_pat)_[A-Za-z0-9_]{20,}/***/g' || true
	fi
	for f in "$out"/runner-*.log; do
		[[ -e $f ]] || continue
		echo "== the last 40 lines of $(basename "$f")"
		tail -n 40 "$f" | sed -E 's/(gh[opsu]|github_pat)_[A-Za-z0-9_]{20,}/***/g'
	done
	echo "::endgroup::"
}

# A ThreadSanitizer report anywhere in a pass's logs: the runner's own (its threads), and the
# jobs' (a helper's report is the step's failure). Each report is printed, with any token-shaped
# string masked, as ci.yml's log step does, and only as text: the jobs' logs hold their workflow
# commands.
races() {
	local backend=${1:?} f n total=0 stop
	stop="races-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
	echo "::stop-commands::$stop"
	for f in "$out/runner-$backend.log" "$out/logs/$backend-"*.log; do
		[[ -e $f ]] || continue
		n=$(grep -c 'WARNING: ThreadSanitizer' "$f" || true)
		((n > 0)) || continue
		total=$((total + n))
		echo "== $(basename "$f"): $n"
		awk '/WARNING: ThreadSanitizer/ { p = 1 } p { print } /^SUMMARY: ThreadSanitizer/ { p = 0; print "" }' "$f" |
			sed -E 's/(gh[opsu]|github_pat)_[A-Za-z0-9_]{20,}/***/g'
	done
	echo "::$stop::"
	if ((total > 0)); then
		echo "::error::e2e ($backend): $total ThreadSanitizer reports (above)"
		return 1
	fi
	echo "e2e ($backend): no ThreadSanitizer reports"
}

# --- the suite ----------------------------------------------------------------------------------

api() { gh api -H 'X-GitHub-Api-Version: 2022-11-28' "$@"; }
# gh 2.103 refuses a response with terminal escape sequences (a job's log with colour) unless told
# to allow them; an older gh has no such flag and does not refuse.
escapes=()
if gh api --help 2>&1 | grep -q -- --allow-escape-sequences; then escapes=(--allow-escape-sequences); fi
failures=0
fail() {
	echo "::error::e2e ($backend): $*"
	failures=$((failures + 1))
}

# dispatch WORKFLOW KEY=VALUE...
dispatch() {
	local wf=$1 kv args=()
	shift
	for kv; do args+=(-f "inputs[${kv%%=*}]=${kv#*=}"); done
	api -X POST "repos/$repo/actions/workflows/$wf/dispatches" -f ref="$ref" "${args[@]}" >/dev/null
}

# find_run WORKFLOW TITLE: the run's ID, once it is listed (a few seconds after the dispatch).
# On giving up it says why on stderr: the suite's time ran out, or the last API error (a rate limit
# or an outage reads the same as a run that was never made without it), or no run of that title.
find_run() {
	local id err='' tries ef
	ef=$(mktemp)
	for tries in $(seq 60); do
		((SECONDS < suite_end)) || { echo "find_run $1 \"$2\": the suite's time ran out after $((tries - 1)) tries" >&2 && rm -f "$ef" && return 1; }
		if id=$(api "repos/$repo/actions/workflows/$1/runs?event=workflow_dispatch&per_page=50" \
			--jq ".workflow_runs[] | select(.display_title == \"$2\") | .id" 2>"$ef" | head -n1); then
			err=''
		else
			err=$(head -c 300 "$ef")
		fi
		[[ -n $id ]] && { rm -f "$ef" && echo "$id" && return 0; }
		sleep 3
	done
	rm -f "$ef"
	if [[ -n $err ]]; then
		echo "find_run $1 \"$2\": not found in 60 tries; the last API call failed: $err" >&2
	else
		echo "find_run $1 \"$2\": no run of that title among the 50 newest dispatches after 60 tries" >&2
	fi
	return 1
}

# runner_exit_check: when the runner `start` left running has exited, fails the suite at once with
# the last of its log. Its jobs would only stay queued: on 2026-11-19 the runner exited at its first
# App call, and the suite spent 240 s on each run before saying so, never naming the cause.
runner_exit_check() {
	local pid
	[[ -e $out/runner.pid ]] || return 0
	pid=$(<"$out/runner.pid")
	sudo kill -0 "$pid" 2>/dev/null && return 0
	fail "the runner (pid $pid) exited while its jobs were queued or running; the last of its log:"
	tail -n 20 "$out/runner-$backend.log" >&2 2>/dev/null || true
	exit 1
}

# wait_run ID [ATTEMPT]: until that attempt of the run has completed, at most $timeout s, and not
# past the suite's own limit. Stops the suite once the runner has exited (`runner_exit_check`).
# On giving up it says on stderr what it last saw: the attempt and status GitHub reported, how many
# polls failed and the last API error, and whether the suite's limit or $timeout ended it (#611's
# 2026-11-21 run waited 240 s for an attempt GitHub had marked completed 4 minutes earlier, and the
# log could not say whether the API failed or answered stale).
wait_run() {
	local deadline=$((SECONDS + timeout)) state="" last="" err="" errors=0 polls=0 ef why
	((deadline <= suite_end)) || deadline=$suite_end
	ef=$(mktemp)
	while ((SECONDS < deadline)); do
		runner_exit_check
		polls=$((polls + 1))
		if state=$(api "repos/$repo/actions/runs/$1" --jq '"\(.run_attempt) \(.status)"' 2>"$ef"); then
			last=$state
		else
			errors=$((errors + 1))
			err=$(head -c 300 "$ef")
			state=""
		fi
		[[ $state == "${2:-1} completed" ]] && {
			rm -f "$ef"
			return 0
		}
		sleep 5
	done
	rm -f "$ef"
	((deadline == suite_end)) && why="the suite's ${E2E_SUITE_LIMIT:-1800} s" || why="$timeout s"
	echo "wait_run $1, attempt ${2:-1}: gave up after $why; $polls polls, last answer '${last:-none}' (attempt status), $errors failed${err:+, the last: $err}" >&2
	return 1
}

jobs_of() { api "repos/$repo/actions/runs/$1/attempts/${2:-1}/jobs?per_page=50"; }
# jobs_settled ID [ATTEMPT]: the run's jobs once each has a conclusion. The run being completed does
# not mean the jobs list says so yet: during an incident it showed `null` for jobs that had
# succeeded. Nor does it mean the step lists are there: the runner had reported every step of a
# cancelled job (#437) while the list, read 10 s after the job completed, still showed `Always` with no
# conclusion and no `On cancel` (the job's API page showed all of them minutes later), and for the
# native runner showed no steps at all. So a job that ran also needs its steps, each concluded.
# Re-reads for up to a minute; what it last read, if some job never settles.
jobs_settled() {
	local jobs="" raw="" ghosts
	for _ in $(seq 20); do
		raw=$(jobs_of "$@" 2>/dev/null) || raw=""
		jobs=$(distinct_jobs <<<"$raw" 2>/dev/null) || jobs=$raw
		jq -e '(.jobs | length) > 0 and all(.jobs[]; .status == "completed" and .conclusion != null and
			(.conclusion == "skipped" or ((.steps | length) > 0 and all(.steps[]; .conclusion != null))))' \
			<<<"$jobs" >/dev/null 2>&1 && break
		((SECONDS < hard_end)) || break
		sleep 3
	done
	ghosts=$(jq -rn --argjson raw "${raw:-null}" --argjson kept "${jobs:-null}" \
		'[($raw.jobs // [])[] | select(.id as $i | ([($kept.jobs // [])[] | .id] | index($i)) == null)
		 | "\(.name) (job \(.id), \(.status), no runner)"] | join(", ")' 2>/dev/null || true)
	[[ -z $ghosts ]] || echo "e2e: GitHub also lists, for jobs that ran: $ghosts; ignored (see distinct_jobs)" >&2
	printf '%s\n' "$jobs"
}

# distinct_jobs: a jobs list (stdin) without the records GitHub made of a job twice. A run's list can
# hold two jobs of one name, one that ran and one that never had a runner and stays `queued` with no
# steps for good, while the run completes successfully (runner-bench run 44306203521, 2026-11-18: two
# `toolcache`, 2 s apart, the first queued still two days later; 1 run of the 120 e2e runs listed).
# Left in, it keeps the jobs from settling and `e2e/toolcache` reads "null" and "success". A record
# is dropped only when it has no runner and no conclusion and another of its name has either: a job
# that never started and has no twin still fails the run's checks.
distinct_jobs() {
	jq -c '.jobs |= (. as $all | map(. as $j | select(
		((.runner_name // "") != "" or .conclusion != null) or
		([$all[] | select(.name == $j.name and ((.runner_name // "") != "" or .conclusion != null))] | length) == 0)))'
}

# run_conclusion ID: the run's conclusion, re-read while it is still null.
run_conclusion() {
	local c=""
	for _ in $(seq 20); do
		c=$(api "repos/$repo/actions/runs/$1" --jq '.conclusion // empty' 2>/dev/null) || c=""
		[[ -n $c ]] && break
		((SECONDS < hard_end)) || break
		sleep 3
	done
	echo "$c"
}

# uploads_failed JOB_ID: what the runner under test says of the job's log uploads that failed
# ("error: kind=upload_failed job=123 what=job_log name=… detail=NameServerFailure"), from its log
# when `start` started it.
uploads_failed() {
	grep -hF -- "kind=upload_failed job=$1 " "$out/runner-$backend.log" 2>/dev/null |
		sed -E 's/^error: kind=upload_failed job=[0-9]+ //' | tr '\n' ';' || true
}

# job_log JOB_ID [CONCLUSION]: its log, which GitHub may take a few seconds after the job ends to
# serve. GitHub answers 404 for a log it does not have (a job that never started has none, nor has
# one still running, nor one whose upload failed: the runner makes one try for the job's whole
# log, and a DNS failure there left a job that had succeeded with none), so the wait is bounded
# three times: a skipped job is asked once, so is one whose runner says its upload failed, and
# every other job's waits draw on one budget for the whole suite ($log_budget s), so a lagging API
# costs at most that, not half a minute per job. The placeholder says why, and what the runner said.
log_budget=${E2E_LOG_WAIT:-60}
job_log() {
	local log why="" i tries=8 said
	said=$(uploads_failed "$1")
	[[ ${2:-} == skipped || $said == *"what=job_log"* ]] && tries=1
	for ((i = 1; i <= tries; i++)); do
		if log=$(api "${escapes[@]}" "repos/$repo/actions/jobs/$1/logs" 2>"$out/log.err") && [[ -n $log ]]; then
			printf '%s\n' "$log"
			return 0
		fi
		why=$(tr '\n' ' ' <"$out/log.err")
		((i < tries && log_budget >= 3 && SECONDS < hard_end)) || break
		sleep 3
		log_budget=$((log_budget - 3))
	done
	echo "(no log: ${why:-empty}${said:+; the runner: $said})"
}

# record WORKFLOW ATTEMPT JOBS_JSON: a row of timings.tsv for each job, with its log in $out/logs.
record() {
	local wf=$1 attempt=$2 jobs=$3 id name conclusion queue run on
	while IFS=$'\t' read -r id name conclusion queue run; do
		job_log "$id" "$conclusion" >"$out/logs/$backend-$wf-$name-$attempt.log"
		# Native only where "Set up job" says so ("Engine: native"); a job native cannot run yet
		# says "This job runs on Dagger: ..." instead.
		on=dagger
		grep -qF 'Engine: native' "$out/logs/$backend-$wf-$name-$attempt.log" && on=native
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$backend" "$wf" "$name" "$attempt" \
			"$conclusion" "$on" "$queue" "$run" >>"$out/timings.tsv"
	done < <(jq -r 'def secs(a; b): try ((b | fromdateiso8601) - (a | fromdateiso8601)) catch "";
		.jobs[] | [.id, .name, .conclusion // "none", secs(.created_at; .started_at),
		secs(.started_at; .completed_at)] | @tsv' <<<"$jobs")
}

# rerun_cache ATTEMPT: reruns the `cache` job of the e2e run, as that attempt, and records it.
rerun_cache() {
	local job
	job=$(jobs_of "$main" $(($1 - 1)) | jq -r '[.jobs[] | select(.name == "cache")] | max_by(.id) | .id')
	if [[ -z $job ]] || ! api -X POST "repos/$repo/actions/jobs/$job/rerun" >/dev/null; then
		fail "e2e/cache: could not rerun it"
		return 0
	fi
	wait_run "$main" "$1" || { fail "e2e/cache, attempt $1: not done within $timeout s" && return 0; }
	# The attempt's own `cache` job: the newest of that name.
	record e2e "$1" "$(jobs_settled "$main" "$1" | jq '{jobs: [[.jobs[] | select(.name == "cache")] | max_by(.id)]}')"
}

# check_attempt ATTEMPT: that attempt of `cache` succeeded.
check_attempt() {
	local state
	state=$(awk -F'\t' -v b="$backend" -v a="$1" '$1 == b && $3 == "cache" && $4 == a { print $5 }' "$out/timings.tsv")
	[[ $state == success ]] || fail "e2e/cache, attempt $1: ${state:-missing}, not success"
}

# check_replay ATTEMPT: that attempt of `cache` succeeded with its steps replayed.
check_replay() {
	local log=$out/logs/$backend-e2e-cache-$1.log
	check_attempt "$1"
	expect "$log" "Reused from" "e2e/cache, attempt $1"
	echo "rerun (attempt $1): $(grep -cF 'Reused from' "$log" || true) steps replayed"
}

# stuck_run ID: where a run that did not finish is, per job: its status, and the step it is in.
stuck_run() {
	jobs_of "$1" 2>/dev/null | jq -r '.jobs[]? | "  \(.name): \(.status) \(.conclusion // "")" +
		(([.steps[]? | select(.status == "in_progress") | .name] | join(", ")) as $s | if $s == "" then "" else " (in step: \($s))" end)' >&2 || true
}

# The suite's runs, cancelled if still going, when it ends early.
cancel_runs() {
	local r
	for r in ${main:-} ${cancel:-}; do
		api -X POST "repos/$repo/actions/runs/$r/cancel" >/dev/null 2>&1 || true
	done
}

# expect FILE TEXT [WHAT]: the log has the line.
expect() {
	grep -qF -- "$2" "$1" && return 0
	if [[ $(head -c 8 "$1") == "(no log:" ]]; then
		fail "${3:-$(basename "$1" .log)}: no \"$2\", for the log is missing: $(<"$1")"
	else
		fail "${3:-$(basename "$1" .log)}: no \"$2\" in its log"
	fi
}

check() {
	label=${2:?}
	backend=${3:-dagger}
	local nonce tag jobs jobid state started running log=$out/runner-$backend.log
	if [[ -n ${E2E_GH_TOKEN:-} ]]; then
		export GH_TOKEN=$E2E_GH_TOKEN
	else
		unset GH_TOKEN GITHUB_TOKEN
	fi
	nonce=${E2E_NONCE:-${GITHUB_RUN_ID:-$(date +%s)}-${GITHUB_RUN_ATTEMPT:-0}-$backend-$RANDOM}
	tag="$label-$nonce"
	mkdir -p "$out/logs"
	[[ -e $out/timings.tsv ]] ||
		printf 'backend\tworkflow\tjob\tattempt\tconclusion\tran_on\tqueue_s\tjob_s\n' >"$out/timings.tsv"

	echo "dispatching e2e.yml and e2e-cancel.yml at $repo@$ref for label $label (tag $tag)"
	dispatch e2e.yml label="$label" tag="$tag" nonce="$nonce" \
		zig_runner_ref="${E2E_ZIG_RUNNER_REF:-main}"
	dispatch e2e-cancel.yml label="$label" tag="$tag"
	# Nothing of this suite may stay queued for a label no runner will serve again.
	main="" cancel=""
	trap cancel_runs EXIT
	main=$(find_run e2e.yml "e2e $tag") || { fail "the e2e run never appeared" && exit 1; }
	cancel=$(find_run e2e-cancel.yml "e2e-cancel $tag") || { fail "the e2e-cancel run never appeared" && exit 1; }
	echo "runs: https://github.com/$repo/actions/runs/$main and .../$cancel"

	# The cancel, once its long step has started. The runner's own log says so exactly: it holds each
	# step's output as "[job ID step N stdout] ...", ID being this run's job. No other run's Hog can
	# write that line for this ID: the job is this dispatch's own, and the log is this pass's own.
	# GitHub's step list says so too, but it can lag behind the job (during an incident `hog`
	# started in 3 s and the list never showed it), so either counts. The job merely running does
	# not: when "Set up job" alone takes over 30 s, a cancel on that clock lands before Hog starts
	# and skips it. The last resort, a tenth of $timeout (5 minutes by default) of the job running
	# without either signal, cannot let a Hog that never started pass: the checks below need the step
	# cancelled and its output.
	started="" running=0
	local hog_end=$((SECONDS + timeout)) last_resort=$((timeout / 10))
	((hog_end <= suite_end)) || hog_end=$suite_end
	while ((SECONDS < hog_end)); do
		runner_exit_check
		jobs=$(jobs_of "$cancel" 2>/dev/null) || jobs=""
		state=$(jq -r '.jobs[0].steps[]? | select(.name == "Hog") | .status' <<<"$jobs" 2>/dev/null) || state=""
		[[ $state == in_progress || $state == completed ]] && { started=1 && break; }
		jobid=$(jq -r '.jobs[0].id // empty' <<<"$jobs" 2>/dev/null) || jobid=""
		if [[ -n $jobid ]] && grep -qE "^\[job $jobid step [0-9]+ stdout\] e2e-hog started\r?$" "$log" 2>/dev/null; then
			started=1 && break
		fi
		if jq -e '.jobs[0] | .status == "in_progress" and ((.runner_name // "") != "")' <<<"$jobs" >/dev/null 2>&1; then
			running=$((running + 1))
		else
			running=0
		fi
		if ((running >= last_resort)); then
			echo "e2e-cancel: neither the runner's log nor the step list shows Hog after $((running * 5)) s of the job running; cancelling anyway"
			# A job that sets up in 2 to 10 s (the suite's jobs under ThreadSanitizer, 16 passes of
			# 2026-11-20) is not slow here but stuck (2026-11-19, Dagger: all eight jobs assigned to
			# runners, none reported a step in 15 minutes, until GitHub cancelled them, and the runner's
			# own log was 300 lines of 400s by the time anyone looked). The runner is alive and stuck
			# now, which is when its threads can be read: say where each run is, and the runner's state.
			stuck_run "$main" >&2
			stuck_run "$cancel" >&2
			[[ ! -e $out/runner.pid ]] || stuck_runner "$(<"$out/runner.pid")" "the runner's jobs report no step"
			started=1 && break
		fi
		sleep 5
	done
	if [[ -n $started ]]; then
		sleep 3
	else
		fail "e2e-cancel: its Hog step never started, within $timeout s or the suite's ${E2E_SUITE_LIMIT:-1800} s"
		stuck_run "$cancel"
	fi
	# gh's answer to the cancel is said, not trusted: GitHub accepts it with a 202 whose body has come
	# back empty, which gh calls a failure ("unexpected end of JSON input", 2026-11-20) though the run
	# was cancelled, and under set -e the suite then ended with no reason given. Whether the cancel
	# took is checked below: the run's conclusion must be cancelled, and its steps' outcomes.
	api -X POST "repos/$repo/actions/runs/$cancel/cancel" >/dev/null ||
		echo "e2e-cancel: gh said the cancel request failed (above); the run's conclusion decides"

	# A run that does not finish is a hang, not a failed check: say where it is, and stop, so that the
	# step ends here with the runner's log, not at its limit.
	wait_run "$main" || { fail "e2e: not done within $timeout s (the suite's limit is ${E2E_SUITE_LIMIT:-1800} s)" && stuck_run "$main" && exit 1; }
	wait_run "$cancel" || { fail "e2e-cancel: not done within $timeout s (the suite's limit is ${E2E_SUITE_LIMIT:-1800} s)" && stuck_run "$cancel" && exit 1; }

	jobs=$(jobs_settled "$main")
	record e2e 1 "$jobs"
	local job
	for job in toolcache service docker js files secret cache; do
		state=$(jq -r --arg j "$job" '.jobs[] | select(.name == $j) | .conclusion' <<<"$jobs")
		[[ $state == success ]] || fail "e2e/$job: ${state:-missing}, not success"
		expect "$out/logs/$backend-e2e-$job-1.log" "e2e-ok $job" "e2e/$job"
	done
	expect "$out/logs/$backend-e2e-service-1.log" "redis: +PONG" e2e/service
	expect "$out/logs/$backend-e2e-docker-1.log" "docker-step-ok" e2e/docker
	expect "$out/logs/$backend-e2e-js-1.log" "js-action-ok" e2e/js
	expect "$out/logs/$backend-e2e-files-1.log" "path-ok" e2e/files
	expect "$out/logs/$backend-e2e-secret-1.log" "secret=***" e2e/secret
	expect "$out/logs/$backend-e2e-secret-1.log" "added=***" e2e/secret
	! grep -qE 'added-[0-9a-f]{16}' "$out/logs/$backend-e2e-secret-1.log" ||
		fail "e2e/secret: a value given to ::add-mask:: is in its log unmasked"

	jobs=$(jobs_settled "$cancel")
	record e2e-cancel 1 "$jobs"
	state=$(run_conclusion "$cancel")
	[[ $state == cancelled ]] || fail "e2e-cancel: the run is $state, not cancelled"
	state=$(jq -r '[.jobs[0].steps[] | "\(.name)=\(.conclusion)"] | join(" ")' <<<"$jobs")
	[[ $state == *"Hog=cancelled"* && $state == *"Always=success"* && $state == *"On cancel=success"* && $state != *"After=success"* ]] ||
		fail "e2e-cancel: steps $state; expected Hog cancelled, Always and On cancel to succeed, After not to run"
	expect "$out/logs/$backend-e2e-cancel-hog-1.log" "e2e-hog started" e2e-cancel
	expect "$out/logs/$backend-e2e-cancel-hog-1.log" "e2e-always ran" e2e-cancel
	expect "$out/logs/$backend-e2e-cancel-hog-1.log" "e2e-cancelled ran" e2e-cancel

	# The rerun of `cache`: the same steps with the same nonce, so the step cache replays them, and
	# the runner notes each one "Reused from Dagger's cache" or "... the native step store".
	# Natively in whichever slot the rerun lands: a stored layer has the canonical ids, which every
	# slot's job sees as its own (docs/native-backend.md, "A layer has the canonical ids").
	#
	# Attempt 2 only has to succeed. The run's jobs share one tool cache, and `toolcache` installs
	# into it while `cache` runs: a tree added between two attempts changes the tree list that
	# every step's key carries (`ZIG_RUNNER_TOOL_TREES`), so the next attempt runs its steps
	# again, once. By attempt 3 nothing is changing it.
	rerun_cache 2
	check_attempt 2
	rerun_cache 3
	check_replay 3

	trap - EXIT
	echo "timings ($backend):"
	awk -F'\t' -v b="$backend" '$1 == b' "$out/timings.tsv" | cut -f2- | column -t -s $'\t'
	# Where the native jobs' time went, from the runner's log when `start` started it.
	if [[ $backend == native && -e $out/runner-native.log ]]; then
		echo "phases (native):"
		NATIVE_PHASES_BY_JOB=1 .github/scripts/native-phases.sh "$out/runner-native.log" || true
	fi
	if ((failures > 0)); then
		# On stdout, after the table: GitHub merges the two streams out of order.
		echo "e2e ($backend): $failures failed; job logs in $out/logs"
		exit 1
	fi
	echo "e2e ($backend): every check passed"
}

case ${1:-} in
build) build "${2:?}" "${3:-}" ;;
engine) engine ;;
rootfs) make_rootfs "${2:?}" ;;
start) start "$@" ;;
stop) stop ;;
distinct-jobs) distinct_jobs ;;
races) races "${2:?}" ;;
check) check "$@" ;;
*) usage ;;
esac
