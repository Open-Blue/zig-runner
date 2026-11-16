#!/usr/bin/env bash
# Live checks of the Gitea and Forgejo support (#520) against a real instance: a throwaway Gitea or
# Forgejo (a container, published on 127.0.0.1), the real runner binary (native backend, no engine)
# in a privileged container with a memory limit, as memory-soak.sh runs it, and workflows
# dispatched through the instance's API. What they check:
#
#   actions    `uses:` as Gitea's model reads it: a bare owner/repo@ref (the instance's default
#              actions URL, configured as the instance itself here), `self:`, an absolute URL, a directory of the
#              action's repository, and `$/path` of the workflow's own repository
#   env        the variables the instance's own runner sets (GITEA_*, FORGEJO_*, no trailing slash
#              on GITHUB_SERVER_URL, no token in the environment; docs/GITEA.md)
#   services   a service reached by name and on localhost, and started with the workflow's `cmd:`
#   features   the checkout of the workflow's repository, outputs, a masked secret, a failing step
#              (the run must end `failure`)
#
#   forge-live.sh --forge gitea|forgejo --bin PATH [--out DIR] [--setup-only]
#       --forge       which instance to start (ZR_FORGE_IMAGE overrides its image)
#       --bin         the runner (a static musl build: e2e.sh build)
#       --out         where the runner's log and the run logs go (a new directory under $ZR_FORGE_DIR)
#       --setup-only  start the instance, make the repositories and the registration token, check
#                     that they are there and stop (no runner, nothing privileged)
#
# Environment: ZR_FORGE_HOST (the instance's address; the VM's own address, or the loopback for --setup-only),
# ZR_FORGE_DIR (~/.cache/zr-forge-live), ZR_FORGE_PORT (3398), ZR_FORGE_LOCK
# (~/.cache/zig-runner-locks/root-tests.lock, held while the runner's container runs). The
# containers and the token files are removed when it ends. The steps reach the instance at
# 127.0.0.1:<port>, which the runner makes reachable from a job's network (gitea/reach.zig); a
# container's name does not resolve there.
set -euo pipefail
main() {
	forge=gitea bin="" out="" setup_only=0
	dir=${ZR_FORGE_DIR:-$HOME/.cache/zr-forge-live}
	while (($#)); do
		case $1 in
		--forge) forge=$2 && shift 2 ;;
		--bin) bin=$2 && shift 2 ;;
		--out) out=$2 && shift 2 ;;
		--setup-only) setup_only=1 && shift ;;
		*) sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//' | head -n -1 && exit 2 ;;
		esac
	done
	case $forge in
	gitea)
		image=${ZR_FORGE_IMAGE:-gitea/gitea@sha256:8967bf9deaf3c5c4adae13519436dc1b20c646ac83fe37ae810c933a1045227d}
		cli=gitea prefix=GITEA
		# Gitea takes `github` or `self`; Forgejo any URL.
		default_actions=self
		;;
	forgejo)
		image=${ZR_FORGE_IMAGE:-data.forgejo.org/forgejo/forgejo@sha256:d05b9e587f02a746784d42c815c486b1d4f138646128f990a841833f513fe088}
		cli=forgejo prefix=FORGEJO
		default_actions=
		;;
	*) echo "forge-live: --forge is gitea or forgejo" >&2 && exit 2 ;;
	esac
	# The runner's container: Ubuntu 24.04 by digest. It is privileged (the native backend makes
	# namespaces, mounts and cgroups, and its network rules, `nft`, are for this ephemeral VM only:
	# a FORWARD chain that drops, as Docker leaves one; never on a machine that routes).
	base=${ZR_FORGE_BASE:-ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5}
	port=${ZR_FORGE_PORT:-3398}
	# The instance's address as a job reaches it: the VM's own, not the loopback, so that the
	# addresses the instance puts in its answers (the artifact service's upload URLs are made from
	# its ROOT_URL) are ones a job's network reaches too (`gitea/reach.zig` opens them).
	# A local --setup-only keeps to the loopback (it runs no job); a run with the runner needs the
	# address, and does not go on with a loopback ROOT_URL when it finds none.
	host=${ZR_FORGE_HOST:-}
	if [[ -z $host ]]; then
		if ((setup_only)); then
			host=127.0.0.1
		else
			host=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')
			[[ -n $host ]] || { echo "forge-live: no route out, so no address for the instance; set ZR_FORGE_HOST" >&2 && exit 1; }
		fi
	fi
	url=http://$host:$port
	[[ $forge == gitea ]] || default_actions=$url
	lock=${ZR_FORGE_LOCK:-$HOME/.cache/zig-runner-locks/root-tests.lock}
	instance=zr-forge-live-$forge runner=zr-forge-live-runner-$forge store=zr-forge-live-store-$forge
	script_dir=$(cd "$(dirname "$0")" && pwd)
	out=${out:-$dir/run-$forge-$(date +%Y%m%d-%H%M%S)}

	if ((! setup_only)) && [[ ${ZR_FORGE_LOCKED:-} != 1 ]]; then
		mkdir -p "$(dirname "$lock")"
		ZR_FORGE_LOCKED=1 exec flock "$lock" "$0" --forge "$forge" --bin "$bin" --out "$out"
	fi
	((setup_only)) || [[ -x $bin ]] || { echo "no runner at $bin" >&2 && exit 1; }
	mkdir -p "$out" "$dir"
	chmod 700 "$dir"
	token_file=$dir/token-$forge reg_file=$dir/reg-token-$forge

	# shellcheck disable=SC2329 # run by the trap
	cleanup() {
		trap - EXIT INT TERM
		docker rm -f "$runner" "$instance" >/dev/null 2>&1 || true
		docker volume rm "$store" >/dev/null 2>&1 || true
		rm -f "$token_file" "$reg_file"
	}
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	docker rm -f "$runner" "$instance" >/dev/null 2>&1 || true
	docker volume rm "$store" >/dev/null 2>&1 || true

	# The instance: its default actions URL is itself, so that a bare `owner/repo@ref`
	# resolves to the repositories made below.
	# On the host's network, listening on its address: a port Docker publishes is NATed to the
	# container, and the jobs' firewall rules (native/nft.zig) match the address as the job dials
	# it, which after the NAT is not the one they were given.
	docker run -d --name "$instance" --memory=1g --oom-score-adj=800 --network host \
		-e "${prefix}__server__HTTP_ADDR=$host" -e "${prefix}__server__HTTP_PORT=$port" \
		-e "${prefix}__security__INSTALL_LOCK=true" -e "${prefix}__actions__ENABLED=true" \
		-e "${prefix}__actions__DEFAULT_ACTIONS_URL=$default_actions" -e "${prefix}__server__ROOT_URL=$url/" \
		-e "${prefix}__server__DISABLE_SSH=true" "$image" >/dev/null
	for _ in $(seq 180); do
		curl -fsS -o /dev/null "$url/api/v1/version" 2>/dev/null && break
		sleep 1
	done
	curl -fsS -o /dev/null "$url/api/v1/version" || { docker logs "$instance" 2>&1 | tail -20 >&2 && exit 1; }
	docker exec -u git "$instance" "$cli" admin user create --admin --username zradmin --email zr@localhost \
		--password "$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" --must-change-password=false >/dev/null
	umask 077
	docker exec -u git "$instance" "$cli" admin user generate-access-token --username zradmin --scopes all --raw >"$token_file"
	docker exec -u git "$instance" "$cli" actions generate-runner-token --scope zradmin | tail -n1 >"$reg_file"
	umask 022
	api() { curl -fsS -H "Authorization: token $(<"$token_file")" -H 'Content-Type: application/json' "$@"; }
	put() { # repository path text
		api -o /dev/null -X POST \
			-d "{\"content\":\"$(printf '%s' "$3" | base64 -w0)\",\"message\":\"m\",\"branch\":\"main\"}" \
			"$url/api/v1/repos/zradmin/$1/contents/$2"
	}
	for r in act main; do
		api -o /dev/null -X POST -d "{\"name\":\"$r\",\"auto_init\":true,\"default_branch\":\"main\"}" "$url/api/v1/user/repos"
	done
	# shellcheck source=/dev/null
	source "$script_dir/forge-live-workflows.sh"
	# shellcheck disable=SC2154 # defined by the file above
	put act action.yml "$act_action"
	put act sub/action.yml "$act_action"
	put main .gitea/actions/mine/action.yml "$act_action"
	api -o /dev/null -X POST -d '{"tag_name":"v1","target":"main"}' "$url/api/v1/repos/zradmin/act/tags"
	for w in actions env services artifacts features; do
		put main ".gitea/workflows/$w.yml" "$(workflow "$w" "$url" "$port" "$prefix")"
	done
	api "$url/api/v1/repos/zradmin/main/contents/.gitea/workflows/actions.yml" >/dev/null
	if ((setup_only)); then
		echo "forge-live: $forge is up at $url, repositories and workflows made, registration token made"
		exit 0
	fi

	# What the privileged runner container sees: the runner, its script and the registration token,
	# and not the admin API token beside them.
	rdir=$dir/runner-$forge
	mkdir -p "$rdir"
	cat >"$rdir/inner.sh" <<'IN'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq nftables iproute2 util-linux procps ca-certificates git >/dev/null
mkdir -p /sys/fs/cgroup/init
for p in $(</sys/fs/cgroup/cgroup.procs); do echo "$p" >/sys/fs/cgroup/init/cgroup.procs || true; done
echo "+cpu +memory +pids +io" >/sys/fs/cgroup/cgroup.subtree_control
mkdir -p /sys/fs/cgroup/zr.slice
nft add table ip filter
nft add chain ip filter FORWARD '{ type filter hook forward priority 0; policy drop; }'
mkdir -p /store/tmp /store/state /store/native
export TMPDIR=/store/tmp
export RUNNER_BACKEND=native RUNNER_ENGINE=none RUNNER_PREWARM=false RUNNER_COUNT=1
export RUNNER_TRUSTED_REFS=refs/heads/main RUNNER_TRUSTED_EVENTS=workflow_dispatch RUNNER_LABELS=live
export RUNNER_PLATFORM="$FORGE_PLATFORM" RUNNER_GITEA_URL="$FORGE_URL" RUNNER_GITEA_FETCH_INTERVAL=1
export RUNNER_GITEA_REGISTRATION_TOKEN="$(</live/reg-token)"
export RUNNER_STATE_DIR=/store/state RUNNER_NATIVE_STORE=/store/native RUNNER_NAME_PREFIX=live
export RUNNER_NATIVE_CGROUP=/sys/fs/cgroup/zr.slice RUNNER_HEALTH_IDLE_INTERVAL=2 RUNNER_HEALTH_INTERVAL=3600
exec /live/runner
IN
	chmod 755 "$rdir/inner.sh"
	cp "$bin" "$rdir/runner"
	cp "$reg_file" "$rdir/reg-token"
	# shellcheck disable=SC2064
	trap "rm -rf '$rdir'; cleanup" EXIT
	docker run -d --name "$runner" --privileged --network host --cgroupns private --memory 4g --memory-swap 4g \
		--oom-score-adj=800 -e FORGE_URL="$url" -e FORGE_PLATFORM="$forge" -v "$rdir:/live:ro" -v "$out:/out" -v "$store:/store" \
		"$base" bash -c '/live/inner.sh >>/out/runner.log 2>&1' >/dev/null
	for _ in $(seq 360); do
		grep -aq "registered runner\|registered earlier" "$out/runner.log" 2>/dev/null && break
		sleep 1
	done
	grep -aq "registered runner\|registered earlier" "$out/runner.log" || {
		echo "forge-live: the runner did not register; its log:" >&2
		tail -n 30 "$out/runner.log" >&2
		docker logs "$runner" 2>&1 | tail -n 20 >&2
		docker ps -a --filter "name=$runner" --format '{{.Status}}' >&2
		exit 1
	}

	failed=0
	for w in actions env services artifacts features; do
		before=$(api "$url/api/v1/repos/zradmin/main/actions/runs?limit=1" | python3 -I -c 'import json,sys; r=json.load(sys.stdin)["workflow_runs"]; print(max([x["id"] for x in r], default=0))')
		api -o /dev/null -X POST -d '{"ref":"main"}' "$url/api/v1/repos/zradmin/main/actions/workflows/$w.yml/dispatches"
		rid=0
		for _ in $(seq 60); do
			rid=$(api "$url/api/v1/repos/zradmin/main/actions/runs?limit=1" | python3 -I -c 'import json,sys; r=json.load(sys.stdin)["workflow_runs"]; print(max([x["id"] for x in r], default=0))')
			((rid > before)) && break
			sleep 1
		done
		((rid > before)) || { echo "forge-live: $w: no run appeared" >&2 && failed=1 && continue; }
		# Gitea says `completed` and the conclusion; Forgejo, the conclusion as the status.
		state=""
		for _ in $(seq 150); do
			state=$(api "$url/api/v1/repos/zradmin/main/actions/runs/$rid" | python3 -I -c 'import json,sys; r=json.load(sys.stdin); s=r["status"]; print((r.get("conclusion") or "") if s == "completed" else s)')
			case $state in success | failure | cancelled | skipped) break ;; esac
			sleep 2
		done
		want=success
		[[ $w == features ]] && want=failure # its last step fails on purpose
		echo "forge-live: $forge $w: ${state:-no result} (wanted $want)"
		[[ $state == "$want" ]] || failed=1
	done
	cp "$out/runner.log" "$out/runner.log.keep" 2>/dev/null || true
	if ((failed)); then
		echo "forge-live: a run did not end as it should; the runner's log:" >&2
		tail -n 80 "$out/runner.log" >&2
		exit 1
	fi
	echo "forge-live: $forge: all runs ended as they should"
}
main "$@"
