#!/usr/bin/env bash
# Memory soak: runs many jobs through ONE runner process and checks that its resident and anonymous
# memory, its heap and the network library's counters, and its descriptors, threads, mounts and
# zombies come back to where they were (memory_soak.py, which also says how the check is made).
#
# The runner is the real binary, native backend, no engine, polling a local Gitea (or Forgejo)
# instance that has a runner-less repo for it; the jobs are the shapes in memory_soak.py (run steps,
# checkout, a container job, a failing job, a cancelled job, a large log, a step timeout), one at a
# time. The native backend needs root and user namespaces, so the runner runs in one privileged
# container with a memory cap, under the same lock the root tests take (so nothing else that needs
# root runs meanwhile); the container is removed when the script ends.
#
#   memory-soak.sh [--jobs N] [--warmup N] [--mem SIZE] [--bin PATH] [--out DIR]
#       --jobs     500 (the long run: 2 to 3 hours, 3 on the laptop's first); 50 is the short one (about 12 minutes)
#       --warmup   the samples left out of the fit (20)
#       --mem      the container's memory limit (6g)
#       --bin      the runner (runner/zig-out/bin/runner, a static musl build)
#       --out      where samples.csv and the runner's log go (a new directory under $ZR_SOAK_DIR)
#       --shapes   only these shapes, comma-separated (run,checkout,container,fail,cancel,biglog,timeout)
#       --own-instance  start a throwaway Gitea (ZR_SOAK_GITEA_IMAGE) for the run, as CI does,
#                  instead of using one that is already running
#
# Environment: ZR_SOAK_URL (http://127.0.0.1:3300), ZR_SOAK_TOKEN_FILE (a user token of the
# instance's admin, ~/.cache/zr-forge-tokens/gitea.token), ZR_SOAK_GITEA_CONTAINER (zr-gitea, for
# `actions generate-runner-token`), ZR_SOAK_DIR (~/.cache/zr-soak: the runner copy and run results; the
# native store is the docker volume zr-soak-store, root's as the native backend requires: `docker
# volume rm zr-soak-store` forgets the pulled images), ZR_SOAK_LOCK (~/.cache/zig-runner-locks/root-tests.lock), ZR_SOAK_ALLOW_ANON_KB
# (a flat allowance for memory a library keeps in a bounded cache, 0). The repo zradmin/soak is
# made if it is missing. Exit status 1 when a counter grew past its margin, or a shape of job did not
# end as it should (and an idle sample) in 90% of its jobs. The runner's registration (a user-scope
# token, for zradmin) is deleted from the instance and the token files are removed when it ends.
set -euo pipefail
# All of it in a function, read before any of it runs: editing this file while a run is under way
# must not change the run (bash reads a script as it executes it).
main() {

	jobs=500 warmup=20 mem=6g own=0 shapes=
	bin=$(cd "$(dirname "$0")/../.." && pwd)/runner/zig-out/bin/runner
	dir=${ZR_SOAK_DIR:-$HOME/.cache/zr-soak}
	out=""
	while (($#)); do
		case $1 in
		--jobs)
			jobs=$2
			shift 2
			;;
		--warmup)
			warmup=$2
			shift 2
			;;
		--mem)
			mem=$2
			shift 2
			;;
		--bin)
			bin=$2
			shift 2
			;;
		--out)
			out=$2
			shift 2
			;;
		--shapes)
			shapes=$2
			shift 2
			;;
		--own-instance)
			own=1
			shift
			;;
		--locked) shift ;;
		*) sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//' | head -n -1 && exit 2 ;;
		esac
	done
	out=${out:-$dir/run-$(date +%Y%m%d-%H%M%S)}
	url=${ZR_SOAK_URL:-http://127.0.0.1:3300}
	token_file=${ZR_SOAK_TOKEN_FILE:-$HOME/.cache/zr-forge-tokens/gitea.token}
	forge=${ZR_SOAK_GITEA_CONTAINER:-zr-gitea}
	lock=${ZR_SOAK_LOCK:-$HOME/.cache/zig-runner-locks/root-tests.lock}
	name=zr-soak
	script_dir=$(cd "$(dirname "$0")" && pwd)

	# Under the root tests' lock, for the whole run.
	own_flag=()
	((! own)) || own_flag=(--own-instance)
	if [[ ${ZR_SOAK_LOCKED:-} != 1 ]]; then
		mkdir -p "$(dirname "$lock")"
		ZR_SOAK_LOCKED=1 exec flock "$lock" "$0" --jobs "$jobs" --warmup "$warmup" --mem "$mem" --bin "$bin" --out "$out" --shapes "$shapes" \
			"${own_flag[@]}"
	fi

	[[ -x $bin ]] || { echo "no runner at $bin (zig build -Doptimize=ReleaseSafe in runner/)" >&2 && exit 1; }
	mkdir -p "$out" "$dir"
	# The runner's container first (nothing registers again), then its registrations are deleted
	# from the instance (a persistent one would collect one per run), then the throwaway Gitea, and
	# the token files.
	# shellcheck disable=SC2329 # run by the trap
	cleanup() {
		trap - EXIT INT TERM
		docker rm -f "$name" >/dev/null 2>&1 || true
		if [[ -f ${token_file:-/nonexistent} ]] && curl -fsS -o /dev/null --max-time 5 "$url/api/v1/version" 2>/dev/null; then
			python3 -I "$script_dir/memory_soak.py" unregister --url "$url" --token-file "$token_file" ||
				echo "memory-soak: could not unregister the soak runner from $url" >&2
		fi
		docker rm -f zr-soak-gitea >/dev/null 2>&1 || true
		rm -f "$dir/reg-token" "$dir/own-token"
	}
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	docker rm -f "$name" zr-soak-gitea >/dev/null 2>&1 || true

	if ((own)); then
		image=${ZR_SOAK_GITEA_IMAGE:-gitea/gitea@sha256:8967bf9deaf3c5c4adae13519436dc1b20c646ac83fe37ae810c933a1045227d}
		url=http://127.0.0.1:3399 forge=zr-soak-gitea token_file=$dir/own-token
		docker run -d --name "$forge" -p 127.0.0.1:3399:3000 -e GITEA__security__INSTALL_LOCK=true \
			-e GITEA__actions__ENABLED=true -e GITEA__server__ROOT_URL="$url/" "$image" >/dev/null
		for _ in $(seq 120); do
			if curl -fsS -o /dev/null "$url/api/v1/version" 2>/dev/null; then break; fi
			sleep 1
		done
		docker exec -u git "$forge" gitea admin user create --admin --username zradmin --email zr@localhost \
			--password "$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" --must-change-password=false >/dev/null
		umask 077
		docker exec -u git "$forge" gitea admin user generate-access-token --username zradmin --scopes all --raw >"$token_file"
		umask 022
	fi

	# The repo, and a registration token for the runner (kept in a file only the container reads).
	api() { curl -fsS -H "Authorization: token $(<"$token_file")" -H 'Content-Type: application/json' "$@"; }
	if ! api -o /dev/null "$url/api/v1/repos/zradmin/soak" 2>/dev/null; then
		api -X POST -d '{"name":"soak","auto_init":true,"default_branch":"main"}' -o /dev/null "$url/api/v1/user/repos"
	fi
	umask 077
	docker exec -u git "$forge" gitea actions generate-runner-token --scope zradmin | tail -n1 >"$dir/reg-token"
	umask 022

	cat >"$dir/inner.sh" <<'EOF'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq nftables iproute2 util-linux procps ca-certificates >/dev/null
mkdir -p /sys/fs/cgroup/init
# Every process out of the container's root cgroup, so that it can hand controllers to a child
# (a cgroup with processes of its own cannot), and the jobs' cgroup under it.
for p in $(</sys/fs/cgroup/cgroup.procs); do echo "$p" >/sys/fs/cgroup/init/cgroup.procs || true; done
echo "+cpu +memory +pids +io" >/sys/fs/cgroup/cgroup.subtree_control
mkdir -p /sys/fs/cgroup/zr.slice
nft add table ip filter
nft add chain ip filter FORWARD '{ type filter hook forward priority 0; policy drop; }'
mkdir -p /store/tmp /store/state /store/native
export TMPDIR=/store/tmp
export RUNNER_BACKEND=native RUNNER_ENGINE=none RUNNER_PREWARM=false RUNNER_COUNT=1
export RUNNER_TRUSTED_REFS=refs/heads/main RUNNER_TRUSTED_EVENTS=workflow_dispatch RUNNER_LABELS=soak
export RUNNER_PLATFORM=gitea RUNNER_GITEA_URL="$SOAK_URL" RUNNER_GITEA_FETCH_INTERVAL=1
export RUNNER_GITEA_REGISTRATION_TOKEN="$(</soak/reg-token)"
export RUNNER_STATE_DIR=/store/state RUNNER_NATIVE_STORE=/store/native RUNNER_NAME_PREFIX=soak
export RUNNER_NATIVE_CGROUP=/sys/fs/cgroup/zr.slice RUNNER_HEALTH_IDLE_INTERVAL=2 RUNNER_HEALTH_INTERVAL=3600
exec /soak/runner
EOF
	chmod 755 "$dir/inner.sh"
	cp "$bin" "$dir/runner"

	# A registration the runner saved in the store by an earlier run is forgotten, so this run
	# registers its own (user scope, with the token above) and deletes it at the end.
	docker run --rm -v zr-soak-store:/store ubuntu:24.04 rm -f /store/state/gitea-runner-soak.json

	# The container's cgroup namespace is its own, so the runner's jobs sit under the memory cap.
	docker run -d --name "$name" --privileged --network host --cgroupns private --memory "$mem" --memory-swap "$mem" \
		-e SOAK_URL="$url" -v "$dir:/soak:ro" -v "$out:/out" -v zr-soak-store:/store ubuntu:24.04 \
		bash -c '/soak/inner.sh >>/out/runner.log 2>&1' >/dev/null
	pid=$(docker inspect -f '{{.State.Pid}}' "$name")
	# `bash -c` is the container's first process, and runs the script as a child: the runner is the
	# newest descendant, so find it (its pid is what /proc is read for).
	for _ in $(seq 120); do
		rpid=$(docker top "$name" -eo pid,comm 2>/dev/null | awk '$2 == "runner" { print $1; exit }') || true
		[[ -n ${rpid:-} ]] && break
		sleep 1
	done
	[[ -n ${rpid:-} ]] || { echo "the runner did not start; its log:" >&2 && tail -n 20 "$out/runner.log" >&2 && exit 1; }
	echo "runner pid $rpid (container main pid $pid), log $out/runner.log, results $out"

	# The runner's mappings before and after, to say where a growth is (ZR_SOAK_SMAPS=1).
	smaps() {
		[[ ${ZR_SOAK_SMAPS:-} == 1 ]] || return 0
		docker exec "$name" sh -c 'cat /proc/$(pgrep -o -x runner)/smaps' >"$out/smaps-$1.txt" || true
	}
	smaps before
	rc=0
	python3 -I "$script_dir/memory_soak.py" run --url "$url" --token-file "$token_file" --log "$out/runner.log" \
		--pid "$rpid" --out "$out" --jobs "$jobs" ${shapes:+--shapes "$shapes"} \
		${ZR_SOAK_SMAPS_AT:+--smaps-at "$ZR_SOAK_SMAPS_AT"} || rc=$?
	smaps after
	# Whatever was sampled is judged, even when the run itself broke off.
	python3 -I "$script_dir/memory_soak.py" analyze "$out/samples.csv" --warmup "$warmup" \
		--allow-anon-kb "${ZR_SOAK_ALLOW_ANON_KB:-0}" | tee "$out/verdict.txt" || ((rc)) || rc=$?
	exit "$rc"
}
main "$@"
# shellcheck disable=SC2317
exit
