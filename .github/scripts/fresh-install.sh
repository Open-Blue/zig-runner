#!/usr/bin/env bash
# A fresh install, end to end, on a machine with nothing of ours on it (#377): the one script a
# throwaway cloud VM runs. It is what the README says, in order, and finds where the README alone
# was not enough:
#
#   1. the packages the build and the sandbox need (apt or dnf; the README lists none)
#   2. Zig, from install-zig.sh: pinned, checked against ziglang.org's published checksum
#   3. `zig build -Doptimize=ReleaseSafe` in runner/, the README's own command
#   4. the native tests as root, ZIG_RUNNER_REQUIRE_NATIVE=1 (CI's "Native tests as root", both parts)
#   5. a real job through the built binary: `--exec-job` on a saved job, native backend, no Dagger
#      engine, so it needs no credentials, no Docker and no GitHub (it pulls ubuntu:24.04 itself)
#   6. optionally, a runner registered with GitHub (below)
#
# Run it as root, from a checkout of the commit to test (`git clone` it first, so it is the clean
# tree a new user has):
#
#   sudo .github/scripts/fresh-install.sh
#
# Settings:
#   FRESH_INSTALL_WORK        where the Zig tarball and the job's files go (default /var/tmp/zig-runner-fresh)
#   FRESH_INSTALL_STORE       the native store (default /var/lib/zig-runner-fresh/store). Keep it under
#                             root-owned directories, or the job stage falls back to Dagger and fails.
#   FRESH_INSTALL_SKIP_TESTS  1: skip step 4 (the build and the job still run)
#   FRESH_INSTALL_LIFT_APPARMOR
#                             1: set kernel.apparmor_restrict_unprivileged_userns=0 for the run and
#                             restore it after, as CI does on Ubuntu. Never in a container: the
#                             sysctl is the host's.
#   FRESH_INSTALL_REGISTER    1: step 6. Needs GH_SCOPE and either GH_TOKEN or GH_APP_ID with
#                             GH_APP_PRIVATE_KEY_FILE (deploy/runner.env.example). It starts the
#                             runner for FRESH_INSTALL_REGISTER_SECONDS (default 90) with a label of
#                             its own, checks that GitHub accepted it, and stops it, which removes
#                             the registration. Dispatch a workflow with `runs-on: [self-hosted,
#                             <the label it prints>]` meanwhile to run a job through GitHub.
#                             Never on a public repository (docs/OPERATIONS.md, "A fresh install").
#
# The native tests start sandboxes as root with cgroups and nftables: run this on a machine that is
# safe to lose, and delete it after. Each step's output goes to $FRESH_INSTALL_WORK/log, and the
# script ends with what passed and how long each part took.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=${FRESH_INSTALL_WORK:-/var/tmp/zig-runner-fresh}
# The native store must sit under directories only root can write: the runner refuses to run a job
# natively when anything above the store belongs to another user. So it does not follow $work, which
# may be on a user-owned volume.
store=${FRESH_INSTALL_STORE:-/var/lib/zig-runner-fresh/store}
log=$work/log
passed=()

if [[ $(id -u) != 0 ]]; then
	echo "fresh-install.sh runs as root (the native tests need it): sudo $0" >&2
	exit 1
fi
mkdir -p "$work" "$log"

# stage NAME CMD...: runs CMD with its output in $log/NAME.log, echoing the tail on failure.
stage() {
	local name=$1 start=$SECONDS
	shift
	echo "== $name"
	# The function runs in a subshell with `set -e` of its own, and its status is read on the next
	# line. Inside `if ! cmd` or `cmd ||`, bash switches `set -e` off for everything cmd calls, so a
	# failing test part would not have failed its stage.
	local rc=0
	set +e
	(
		set -e
		"$@"
	) >"$log/$name.log" 2>&1
	rc=$?
	set -e
	if ((rc != 0)); then
		tail -n 40 "$log/$name.log" >&2
		echo "== $name FAILED after $((SECONDS - start)) s (full output: $log/$name.log)" >&2
		exit 1
	fi
	passed+=("$name $((SECONDS - start)) s")
	echo "== $name ok, $((SECONDS - start)) s"
}

do_packages() {
	# git for the version, curl and xz for Zig, util-linux for unshare and flock, iproute2 and
	# nftables for the sandbox network, procps for the tests (ps), sudo because zig-test.sh runs the
	# root tests through it, ca-certificates for TLS.
	if command -v apt-get >/dev/null; then
		# apt.sh falls back to a mirror when Ubuntu's archive is down.
		"$root/.github/scripts/apt.sh" install git curl xz-utils ca-certificates util-linux iproute2 nftables procps sudo \
			openssl python3
	elif command -v dnf >/dev/null; then
		dnf install -y git curl xz sudo ca-certificates util-linux iproute nftables procps-ng openssl python3
	else
		echo "no apt-get or dnf: install git, curl, xz, util-linux, iproute2, nftables, procps" >&2
		exit 1
	fi
}

do_zig() {
	touch "$work/github-path"
	GITHUB_PATH=$work/github-path RUNNER_TOOL_CACHE=$work/tools "$root/.github/scripts/install-zig.sh"
}

do_build() {
	(cd "$root/runner" && zig build -Doptimize=ReleaseSafe)
	test -x "$root/runner/zig-out/bin/runner"
}

do_tests() {
	cd "$root/runner"
	# CI runs the suite in two parts; one machine runs them in turn. Both run even when the first
	# fails, so one run reports every failure, and the stage fails if either did.
	local rc=0 part
	for part in 1/2 2/2; do
		ZIG_RUNNER_REQUIRE_NATIVE=1 ZIG_TEST_NATIVE_AS_ROOT=1 ZIG_TEST_PART=$part ../.github/scripts/zig-test.sh || rc=1
	done
	return $rc
}

# The job a runner is handed (an `acquirejob` response), as small as one can be: two script steps.
# The github context is a push to main, which the trust settings below vouch for, so the steps run
# in the native sandbox and not (as an untrusted job would) in Dagger.
write_job() {
	cat >"$work/job.json" <<'JSON'
{"plan":{"planId":"fresh-install"},"jobId":"fresh-install",
 "contextData":{"github":{"t":2,"d":[{"k":"repository","v":"fresh/install"},{"k":"sha","v":"0123456789012345678901234567890123456789"},{"k":"ref","v":"refs/heads/main"},{"k":"ref_name","v":"main"},{"k":"event_name","v":"push"},{"k":"workflow_ref","v":"fresh/install/.github/workflows/fresh.yml@refs/heads/main"}]}},
 "resources":{"endpoints":[{"name":"SystemVssConnection","url":"https://pipelines.invalid/","authorization":{"parameters":{"AccessToken":"none"},"scheme":"OAuth"},"data":{}}]},
 "steps":[
  {"type":"action","reference":{"type":"script"},"id":"s1","name":"Where it runs","contextName":"s1","condition":"success()",
   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"set -e; grep PRETTY_NAME /etc/os-release; id -u; echo \"cwd=$PWD\"; echo hello > greeting"}}]}},
  {"type":"action","reference":{"type":"script"},"id":"s2","name":"A later step sees the first","contextName":"s2","condition":"success()",
   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"test \"$(cat greeting)\" = hello && echo fresh-install-job-ok"}}]}}
 ]}
JSON
}

do_job() {
	write_job
	mkdir -p "$store"
	# The native backend, no engine (docs/native-backend.md), and the trust a runner needs to run a
	# job natively. RUNNER_NATIVE_STORE keeps the pulled image and layers under root-owned directories.
	env RUNNER_BACKEND=native RUNNER_ENGINE=none RUNNER_NATIVE_STORE="$store" \
		RUNNER_TRUSTED_REFS=refs/heads/main RUNNER_TRUSTED_EVENTS=push \
		"$root/runner/zig-out/bin/runner" --exec-job "$work/job.json" 2>&1 | tee "$work/job.out"
	grep -q '^job succeeded' "$work/job.out"
	# Not a run that quietly went through Dagger instead.
	grep -q 'Engine: native' "$work/job.out"
	grep -q 'fresh-install-job-ok' "$work/job.out"
}

do_register() {
	: "${GH_SCOPE:?FRESH_INSTALL_REGISTER=1 needs GH_SCOPE (owner/repo or an org)}"
	if [[ -z ${GH_TOKEN:-} && -z ${GH_APP_ID:-} ]]; then
		echo "FRESH_INSTALL_REGISTER=1 needs GH_TOKEN, or GH_APP_ID with GH_APP_PRIVATE_KEY_FILE" >&2
		exit 1
	fi
	local label seconds=${FRESH_INSTALL_REGISTER_SECONDS:-90}
	label=fresh-install-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
	echo "registering with label $label for $seconds s; dispatch a job with runs-on: [self-hosted, $label]"
	env RUNNER_BACKEND=native RUNNER_ENGINE=none RUNNER_NATIVE_STORE="$store" RUNNER_COUNT=1 \
		RUNNER_LABELS="self-hosted,linux,$label" RUNNER_NAME_PREFIX=fresh \
		RUNNER_TRUSTED_REFS=refs/heads/main RUNNER_TRUSTED_EVENTS=push,workflow_dispatch \
		timeout -s TERM "$seconds" "$root/runner/zig-out/bin/runner" 2>&1 | tee "$work/register.out" || true
	grep -q "listening for jobs" "$work/register.out"
}

cd "$root"
# shellcheck source=/dev/null
os=$(. /etc/os-release && echo "$PRETTY_NAME")
echo "fresh install of $(git rev-parse --short HEAD) on $os, $(uname -m), kernel $(uname -r)"

stage packages do_packages
# Zig lands on the PATH the way a workflow step's does: install-zig.sh appends its directory to
# GITHUB_PATH, here a file this script reads back.
stage zig do_zig
PATH=$(tail -n 1 "$work/github-path"):$PATH
export PATH
stage build do_build

restrict=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [[ -r $restrict && $(cat "$restrict") == 1 ]]; then
	if [[ ${FRESH_INSTALL_LIFT_APPARMOR:-} == 1 ]]; then
		trap 'echo 1 >"$restrict"' EXIT
		echo 0 >"$restrict"
	else
		echo "note: AppArmor restricts unprivileged user namespaces here; rootless native tests may fail" \
			"(FRESH_INSTALL_LIFT_APPARMOR=1, or the README's profile)"
	fi
fi

# The runner warns when the host forwards packets for its neighbours (FORWARD policy ACCEPT), and
# the store stress test fails any run in which a worker logged a warning. CI's hosts have Docker's
# DROP policy; a bare machine has none, so give it the one the warning asks for. Only when there is
# no filter FORWARD chain yet, so a machine with a firewall keeps its own.
if ! nft list chain ip filter FORWARD >/dev/null 2>&1; then
	nft add table ip filter
	nft add chain ip filter FORWARD '{ type filter hook forward priority 0; policy drop; }'
	echo "note: added an nftables FORWARD chain with policy drop (ip filter), as the runner asks"
fi

if [[ ${FRESH_INSTALL_SKIP_TESTS:-} != 1 ]]; then
	stage native-tests-as-root do_tests
	grep -E 'tests? passed|passed;|skipped|failed' "$log/native-tests-as-root.log" | tail -n 5 || true
fi
stage job do_job
if [[ ${FRESH_INSTALL_REGISTER:-} == 1 ]]; then
	stage register do_register
fi

echo
echo "fresh install: all stages passed"
printf '  %s\n' "${passed[@]}"
