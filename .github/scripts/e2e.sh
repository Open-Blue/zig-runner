#!/usr/bin/env bash
# The end-to-end suite: real workflows through the real runner, GitHub's broker protocol and a real
# Dagger engine, which no unit test reaches (dagger.zig's run against a fake session). The
# workflows are runner-bench's e2e.yml and e2e-cancel.yml (Open-Blue/runner-bench), dispatched with
# a runner label of their own; this waits for them and checks the jobs' and steps' conclusions and
# their logs through GitHub's API: a script installing into the tool cache (v0.22.0 broke that), a
# service, a docker:// step, a JavaScript action, the file commands, a masked secret, a cancelled
# run, and a rerun replayed from the step cache. Each job's queue and run times go to
# $E2E_OUT/timings.tsv, with the backend it ran on, so one harness also compares Dagger and native.
# In CI the Dagger pass comes first, on an engine just started: its times include the pulls and
# the pre-warm. The native pass's jobs that native hands to Dagger (ran_on dagger) then find the
# engine warm, so compare them with a Dagger job run again, not with the first pass.
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
#   e2e.sh build BIN                the runner, x86_64 ReleaseSafe, compiled directly (zig-modules.sh)
#   e2e.sh engine                   start the pinned engine, as deploy/compose.yaml runs it
#   e2e.sh rootfs BIN               the native backend's rootfs: ubuntu:24.04, provisioned
#   e2e.sh start BIN BACKEND LABEL  a pool of the runner, in the background, serving LABEL
#   e2e.sh stop                     stop it, as a deployment stops it (SIGTERM)
#
# Settings: E2E_REPO (Open-Blue/runner-bench), E2E_REF (main: the workflows' ref, and the one ref
# CI's runner trusts), E2E_TIMEOUT (seconds to wait for each run, 600), E2E_OUT (where the
# timings and the runner's log go), E2E_ZIG_RUNNER_REF (the zig-runner commit whose
# install-zig.sh the tool cache job runs, main). `start` also takes GH_APP_ID and
# GH_APP_PRIVATE_KEY_FILE, the runner's own (deploy/runner.env.example).
set -euo pipefail
cd "$(dirname "$0")/../.."

repo=${E2E_REPO:-Open-Blue/runner-bench}
ref=${E2E_REF:-main}
timeout=${E2E_TIMEOUT:-600}
out=$(realpath -m "${E2E_OUT:-${RUNNER_TEMP:-/tmp}/e2e}")
mkdir -p "$out"
# The engine the runner speaks to (runner/src/engine.zig, client_version), pinned by digest;
# `start` checks it is the runner's.
engine_image=registry.dagger.io/engine:v0.21.10@sha256:2a7c054e0864e297671c24a0726ebf1c9747d70291b8843b1726daaff200a334
engine_name=zig-runner-e2e-engine
# The engine's socket, on the host: the runner reaches it as compose's runner does, with no Docker.
engine_dir=/run/zig-runner-e2e
rootfs=/var/lib/zig-runner-e2e/rootfs

usage() {
	sed -n 's/^#   \(e2e\.sh .*\)/\1/p' "$0" >&2
	exit 2
}

# --- the runner, its engine and rootfs (CI) -------------------------------------------------------

build() {
	local bin scratch
	bin=$(realpath -m "${1:?}")
	mkdir -p "$(dirname "$bin")"
	scratch=$(mktemp -d)
	cd runner
	# shellcheck source=.github/scripts/zig-modules.sh
	. ../.github/scripts/zig-modules.sh
	printf '%s' "e2e-$(git rev-parse --short HEAD)" >"$scratch/version"
	zig_modules "$scratch" "$scratch/version" -OReleaseSafe -target x86_64-linux-musl
	zig build-exe "${modules[@]}" --name runner -femit-bin="$bin"
	rm -rf "$scratch"
	"$bin" --version
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
# script its own (--provision-script). Writes $rootfs.ok, or $rootfs.failed, which `start` waits on.
make_rootfs() {
	local bin image script
	bin=$(realpath "${1:?}")
	image=$(tr -d '\n' <runner/src/dagger.zig |
		grep -oE '"ubuntu:[A-Za-z0-9._-]+" *\+\+ *"@sha256:[a-f0-9]{64}"' | tr -d '" +')
	script=$("$bin" --provision-script)
	sudo rm -rf "$rootfs" "$rootfs.ok" "$rootfs.failed"
	sudo mkdir -p "$rootfs"
	if docker run --name zig-runner-e2e-rootfs "$image" sh -c "$script" &&
		docker export zig-runner-e2e-rootfs | sudo tar -x -C "$rootfs"; then
		# The provisioning stamp, as the recipe makes it (docs/native-backend.md, "The rootfs").
		sudo touch "$rootfs/.zig-runner-provisioned" "$rootfs.ok"
		echo "rootfs: $image, provisioned, in $rootfs"
	else
		sudo touch "$rootfs.failed"
		echo "rootfs: provisioning $image failed" >&2
	fi
	docker rm zig-runner-e2e-rootfs >/dev/null || true
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
		for _ in $(seq 300); do
			sudo test -e "$rootfs.ok" -o -e "$rootfs.failed" && break
			sleep 1
		done
		sudo test -e "$rootfs.ok" || { echo "no native rootfs (e2e.sh rootfs)" >&2 && exit 1; }
		# Ubuntu 24.04's AppArmor blocks unprivileged user namespaces; ci.yml's Test lifts it too.
		sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
		native=(RUNNER_NATIVE_ROOTFS="$rootfs")
	fi
	log=$out/runner-$backend.log
	# One runner per job the suite runs at once (eight), on a machine that is the suite's alone:
	# the memory gate is off, so how fast the jobs start depends on GitHub, not on a reservation.
	# The Zig cache seed is not built: it costs 104 s of one core, and only the tool cache job runs
	# Zig. Only the dispatches of the workflows' ref are trusted; jobs from anywhere else fail.
	nohup sudo env GH_SCOPE="$repo" GH_APP_ID="$GH_APP_ID" \
		GH_APP_PRIVATE_KEY_FILE="$GH_APP_PRIVATE_KEY_FILE" \
		RUNNER_LABELS="self-hosted,linux,zig,$label" RUNNER_NAME_PREFIX="e2e-$backend" \
		RUNNER_COUNT=8 RUNNER_ADMISSION=false RUNNER_ZIG_SEED_VERSIONS= \
		RUNNER_ENGINE_HOST="unix://$engine_dir/engine.sock" \
		RUNNER_TRUSTED_REFS="refs/heads/$ref" RUNNER_TRUSTED_EVENTS=workflow_dispatch \
		RUNNER_STOP_GRACE_SECS=30 RUNNER_BACKEND="$backend" "${native[@]}" \
		"$bin" >"$log" 2>&1 &
	echo $! >"$out/runner.pid"
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
	echo "the runner did not stop within 60 s: killed" >&2
	sudo kill -KILL "$pid" 2>/dev/null || true
}

# --- the suite ----------------------------------------------------------------------------------

api() { gh api -H 'X-GitHub-Api-Version: 2022-11-28' "$@"; }
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
find_run() {
	local id
	for _ in $(seq 60); do
		id=$(api "repos/$repo/actions/workflows/$1/runs?event=workflow_dispatch&per_page=50" \
			--jq ".workflow_runs[] | select(.display_title == \"$2\") | .id" 2>/dev/null | head -n1)
		[[ -n $id ]] && { echo "$id" && return 0; }
		sleep 3
	done
	return 1
}

# wait_run ID [ATTEMPT]: until that attempt of the run has completed, at most $timeout s.
wait_run() {
	local deadline=$((SECONDS + timeout)) state
	while ((SECONDS < deadline)); do
		state=$(api "repos/$repo/actions/runs/$1" --jq '"\(.run_attempt) \(.status)"' 2>/dev/null) || state=""
		[[ $state == "${2:-1} completed" ]] && return 0
		sleep 5
	done
	return 1
}

jobs_of() { api "repos/$repo/actions/runs/$1/attempts/${2:-1}/jobs?per_page=50"; }
# job_log JOB_ID: its log, which GitHub may take a few seconds after the job ends to serve.
job_log() {
	local log
	for _ in $(seq 10); do
		log=$(api "repos/$repo/actions/jobs/$1/logs" 2>/dev/null) && [[ -n $log ]] &&
			{ printf '%s\n' "$log" && return 0; }
		sleep 3
	done
	echo "(no log)"
}

# record WORKFLOW ATTEMPT JOBS_JSON: a row of timings.tsv for each job, with its log in $out/logs.
record() {
	local wf=$1 attempt=$2 jobs=$3 id name conclusion queue run on
	while IFS=$'\t' read -r id name conclusion queue run; do
		job_log "$id" >"$out/logs/$backend-$wf-$name-$attempt.log"
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
	record e2e "$1" "$(jobs_of "$main" "$1" | jq '{jobs: [[.jobs[] | select(.name == "cache")] | max_by(.id)]}')"
}

# check_replay ATTEMPT: that attempt of `cache` succeeded with its steps replayed.
check_replay() {
	local log=$out/logs/$backend-e2e-cache-$1.log state
	state=$(awk -F'\t' -v b="$backend" -v a="$1" '$1 == b && $3 == "cache" && $4 == a { print $5 }' "$out/timings.tsv")
	[[ $state == success ]] || fail "e2e/cache, attempt $1: ${state:-missing}, not success"
	expect "$log" "Reused from" "e2e/cache, attempt $1"
	echo "rerun (attempt $1): $(grep -cF 'Reused from' "$log" || true) steps replayed"
}

# The suite's runs, cancelled if still going# The suite's runs, cancelled if still going, when it ends early.
cancel_runs() {
	local r
	for r in ${main:-} ${cancel:-}; do
		api -X POST "repos/$repo/actions/runs/$r/cancel" >/dev/null 2>&1 || true
	done
}

# expect FILE TEXT [WHAT]: the log has the line.
expect() { grep -qF -- "$2" "$1" || fail "${3:-$(basename "$1" .log)}: no \"$2\" in its log"; }

check() {
	label=${2:?}
	backend=${3:-dagger}
	local nonce tag jobs state started
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

	# The cancel, once its long step has started (its step list says so).
	started=""
	for _ in $(seq $((timeout / 5))); do
		state=$(jobs_of "$cancel" | jq -r '.jobs[0].steps[]? | select(.name == "Hog") | .status')
		[[ $state == in_progress || $state == completed ]] && { started=1 && break; }
		sleep 5
	done
	if [[ -n $started ]]; then sleep 3; else fail "e2e-cancel: its Hog step never started"; fi
	api -X POST "repos/$repo/actions/runs/$cancel/cancel" >/dev/null

	wait_run "$main" || fail "e2e: not done within $timeout s"
	wait_run "$cancel" || fail "e2e-cancel: not done within $timeout s"

	jobs=$(jobs_of "$main")
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

	jobs=$(jobs_of "$cancel")
	record e2e-cancel 1 "$jobs"
	state=$(api "repos/$repo/actions/runs/$cancel" --jq .conclusion)
	[[ $state == cancelled ]] || fail "e2e-cancel: the run is $state, not cancelled"
	state=$(jq -r '[.jobs[0].steps[] | "\(.name)=\(.conclusion)"] | join(" ")' <<<"$jobs")
	[[ $state == *"Always=success"* && $state == *"On cancel=success"* && $state != *"After=success"* ]] ||
		fail "e2e-cancel: steps $state; expected Always and On cancel to succeed, After not to run"
	expect "$out/logs/$backend-e2e-cancel-hog-1.log" "e2e-always ran" e2e-cancel
	expect "$out/logs/$backend-e2e-cancel-hog-1.log" "e2e-cancelled ran" e2e-cancel

	# The rerun of `cache`: the same steps with the same nonce, so the step cache replays them, and
	# the runner notes each one "Reused from Dagger's cache" or "... the native step store".
	# Natively in whichever slot the rerun lands: a stored layer has the canonical ids, which every
	# slot's job sees as its own (docs/native-backend.md, "A layer has the canonical ids").
	rerun_cache 2
	check_replay 2

	trap - EXIT
	echo "timings ($backend):"
	awk -F'\t' -v b="$backend" '$1 == b' "$out/timings.tsv" | cut -f2- | column -t -s $'\t'
	if ((failures > 0)); then
		# On stdout, after the table: GitHub merges the two streams out of order.
		echo "e2e ($backend): $failures failed; job logs in $out/logs"
		exit 1
	fi
	echo "e2e ($backend): every check passed"
}

case ${1:-} in
build) build "${2:?}" ;;
engine) engine ;;
rootfs) make_rootfs "${2:?}" ;;
start) start "$@" ;;
stop) stop ;;
check) check "$@" ;;
*) usage ;;
esac
