#!/usr/bin/env bash
# What `zig build test` does, by calling the compiler directly: the runner's tests, and the runner
# itself compiled (as build.zig's test step does, since the tests never reach its main loop).
#
# For GitHub's hosted runners, whose caches always start empty: `zig build` first compiles Zig's own
# build system, about 100 s on one core with an empty cache (Zig 0.17; 0.14.1 took 12 s), before it
# builds anything. Directly, the tests took 14.5 s instead of 118.7 s on a laptop, and the hosted
# test jobs spent 81-116 s on that step. The project's own runners keep the cache in a volume and use
# `zig build test`, as developers do. The module graph is zig-modules.sh's.
set -euo pipefail
cd "$(dirname "$0")/../../runner"

# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh

scratch=$(mktemp -d)
# The tests' output is only text to the job running this, never its workflow commands: the native
# backend's tests write `##[error]` lines into their jobs' logs (the process and memory limits),
# which would otherwise become CI's own annotations. On stderr, where the tests write, so each
# lands before and after their output; the exit status is the tests' still.
stop="tests-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
echo "::stop-commands::$stop" >&2
trap 'echo "::$stop::" >&2; rm -rf "$scratch"' EXIT
git describe --tags --always --dirty --abbrev=8 >"$scratch/version"

zig_modules "$scratch" "$scratch/version"
plain=("${modules[@]}")
# ZIG_TEST_SANITIZE_THREAD=1: the tests under ThreadSanitizer (build.zig's -Dsanitize-thread), which
# fails them on a data race they run into; and the runner binary below, the native backend's helper
# (one `zig-runner native-step` per step), whose report lands on its stderr, which the runner takes
# for the sandbox's failure. TSan's runtime needs glibc's dynamic loader: the native target links
# it, a PIE still, where the release's static PIE (musl, #283) crashes at startup.
tests=("${plain[@]}")
runner=("${plain[@]}")
if [[ ${ZIG_TEST_SANITIZE_THREAD:-} == 1 ]]; then
	zig_modules "$scratch" "$scratch/version" -fsanitize-thread
	tests=("${modules[@]}")
	runner=("${modules[@]}")
fi

# ZIG_TEST_WAIT_FOR_DB=1: between compiling the tests and running them, wait for the database
# ci-database.sh started, which comes up while they compile (CI's Database tests job).
run=()
if [[ ${ZIG_TEST_WAIT_FOR_DB:-} == 1 ]]; then
	# shellcheck disable=SC2016 # expanded by that bash, not this one
	run=(--test-cmd bash --test-cmd -c --test-cmd '"$0" wait && exec "$@"'
		--test-cmd "$(realpath ../.github/scripts/ci-database.sh)")
fi

# The native backend's tests run steps through the runner binary (`zig-runner native-step`), as
# build.zig's test step gives it to them. It compiles beside the tests; they start once it is
# there, or once its compile failed (the tests then fail on the missing binary).
export ZIG_RUNNER_TEST_EXE="$scratch/runner"
(
	rc=0
	zig build-exe tools/test_shards.zig -femit-bin="$scratch/test_shards" &
	shards_exe=$!
	zig build-exe "${runner[@]}" --name runner -femit-bin="$scratch/runner" || rc=$?
	wait "$shards_exe" || rc=$?
	echo "$rc" >"$scratch/runner.rc"
) &
exe=$!
# shellcheck disable=SC2016 # expanded by that bash, not this one
run+=(--test-cmd bash --test-cmd -c --test-cmd 'until [ -e "$0" ]; do sleep 0.2; done; exec "$@"'
	--test-cmd "$scratch/runner.rc")
# ZIG_TEST_NATIVE_AS_ROOT=1: only the native backend's tests, as root (sudo), where they take the
# root runner's path: each job its own range of ids and its own network. The store's stress test
# (src/native/store_stress.zig) keeps its settings under sudo.
# ZIG_TEST_FILTER: only the tests whose names contain it (with ZIG_TEST_NATIVE_AS_ROOT=1, it
# should name native tests only), as the nightly analysis workflow runs the stress test alone.
filter=()
if [[ ${ZIG_TEST_NATIVE_AS_ROOT:-} == 1 ]]; then
	filter=(--test-filter native)
	run+=(--test-cmd sudo
		--test-cmd '--preserve-env=ZIG_RUNNER_TEST_EXE,ZIG_RUNNER_REQUIRE_NATIVE,ZIG_RUNNER_SERVICE_IMAGES,ZIG_TEST_STORE_STRESS_SECONDS,ZIG_TEST_STORE_STRESS_PROCS,ZIG_TEST_STORE_STRESS_SEED,ZIG_TEST_SHARDS,ZIG_TEST_PART')
fi
if [[ -n ${ZIG_TEST_FILTER:-} ]]; then
	filter=(--test-filter "$ZIG_TEST_FILTER")
fi
# ZIG_TEST_IN_CONTAINER=1: the tests run in a Docker container of the default job image
# (runner/src/dagger.zig), as the project's own runner runs them on a push to main, where the
# working directory is the container's overlayfs: not the host's ext4 or tmpfs, which pull
# requests test on. Overlayfs differs where tests can notice (it grants a read lease over a
# writable mapping, #332's test relied on the opposite). The user is the host's, not root; Docker's default seccomp refuses the namespaces
# the native backend needs, so its tests skip, as on that runner. The tests write into the
# container's /tmp (their `.zig-cache/tmp` is relative to it); the scratch directory and the test
# binary's are mounted read-only at their own paths.
if [[ ${ZIG_TEST_IN_CONTAINER:-} == 1 ]]; then
	image=$(tr -d '\n' <../runner/src/dagger.zig | grep -oE '"ubuntu:[A-Za-z0-9._-]+" *\+\+ *"@sha256:[a-f0-9]{64}"' | tr -d '" +')
	[[ -n $image ]] || {
		echo "zig-test.sh: no default_image in runner/src/dagger.zig" >&2
		exit 1
	}
	for attempt in 1 2 3; do
		docker pull -q "$image" >/dev/null && break
		((attempt < 3)) || exit 1
		sleep $((attempt * 10))
	done
	# The test binary's path is the compiler's, relative; the container needs it whole.
	cat >"$scratch/in-container" <<'SCRIPT'
#!/usr/bin/env bash
set -uo pipefail
image=$1 scratch=$2 shards=$3 bin=$(realpath "$4")
# ZIG_TEST_CONTAINER_ARGS: more arguments for `docker run`, such as memory limits.
read -ra extra <<<"${ZIG_TEST_CONTAINER_ARGS:-}"
# --init: a step's timeout sends SIGTERM, which a container's PID 1 would otherwise ignore.
docker run --rm --init --user "$(id -u):$(id -g)" -w /tmp "${extra[@]}" \
	-v "$scratch:$scratch:ro" -v "$(dirname "$bin"):$(dirname "$bin"):ro" \
	-e ZIG_RUNNER_TEST_EXE -e ZIG_TEST_SHARDS "$image" "$shards" "$bin" 2>&1 | tee "$scratch/container.log"
status=${PIPESTATUS[0]}
# ZIG_TEST_MIN_PASSED: a floor on the tests that passed, so a mistake that skips nearly all of
# them (the container's directory, the runner binary) cannot stay green.
passed=$(sed -n 's/^\([0-9][0-9]*\) passed;.*/\1/p' "$scratch/container.log" | tail -n 1)
if ((status == 0)) && ((${passed:-0} < ${ZIG_TEST_MIN_PASSED:-1})); then
	echo "zig-test.sh: ${passed:-0} tests passed in the container, fewer than the ${ZIG_TEST_MIN_PASSED:-1} expected" >&2
	exit 1
fi
exit "$status"
SCRIPT
	chmod +x "$scratch/in-container"
	run+=(--test-cmd "$scratch/in-container" --test-cmd "$image" --test-cmd "$scratch")
fi
# The tests run in several processes (tools/test_shards.zig), which this starts; the same program
# `zig build test` runs. ZIG_TEST_SHARDS=1 runs the test binary itself.
run+=(--test-cmd "$scratch/test_shards" --test-cmd-bin)
zig test "${tests[@]}" "${filter[@]}" "${run[@]}"
wait "$exe"
exit "$(cat "$scratch/runner.rc")"
