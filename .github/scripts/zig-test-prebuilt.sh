#!/usr/bin/env bash
# The runner's tests compiled on one machine and run on another: what zig-test.sh does in one go,
# in two halves, so that a Raspberry Pi can run tests that a fast machine compiled (CI's prebuild
# job and the Test step of "Tests (x86_64)" on prod).
#
#   zig-test-prebuilt.sh build ARCH TAR   compile for ARCH (x86_64 or aarch64, Linux, musl) into
#                                         TAR; prints TAR's sha256 on stdout
#   zig-test-prebuilt.sh run TAR SHA256   check TAR against SHA256 and the commit checked out,
#                                         unpack it and run the tests as `zig build test` does
#
# The tar holds what `zig build test` would have put in the cache and run: the tests (the same
# graph as zig-test.sh and build.zig, so the same modules, flags and zr-net archive, compiled by
# LLVM with debug info: a failure on the Pi still names file and line), the runner executable the
# native backend's tests start (ZIG_RUNNER_TEST_EXE), tools/test_shards.zig, which runs the tests
# in several processes, and that program's own tests. `zig build test` runs them from runner/ with
# the source tree beside (testdata paths are relative to it), so `run` does too: this directory's
# runner/ in the checkout of the same commit, and needs no Zig at all.
#
# The code is compiled for the architecture's baseline CPU, not the machine's own (the compiler
# cannot know the Pi's): what runs on any 64-bit Arm. The tar is the unit that is checked: the
# build job prints its sha256 as a job output, which the job that runs it compares with the digest
# of the file it downloaded (a channel apart from the artifact store).
set -euo pipefail
cd "$(dirname "$0")/../../runner"

mode=${1:-}
case $mode in
build) [[ $# == 3 ]] || mode= ;;
run) [[ $# == 3 ]] || mode= ;;
unpack) [[ $# == 4 ]] || mode= ;;
*) mode= ;;
esac
[[ -n $mode ]] || {
	echo "usage: zig-test-prebuilt.sh build ARCH TAR | run TAR SHA256 | unpack TAR SHA256 DIR" >&2
	exit 2
}

if [[ $mode == build ]]; then
	arch=$2
	tar_path=$(realpath -m "$3")
	case $arch in
	x86_64 | aarch64) ;;
	*)
		echo "zig-test-prebuilt.sh: x86_64 or aarch64, not $arch" >&2
		exit 2
		;;
	esac
	# shellcheck source=.github/scripts/zig-modules.sh
	. ../.github/scripts/zig-modules.sh

	scratch=$(mktemp -d)
	trap 'rm -rf "$scratch"' EXIT
	out=$scratch/out
	mkdir "$out"
	git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
	# -fllvm: what the Pi's compiler picks for aarch64 in a Debug build, and what x86_64 gets here
	# too, so one backend compiles both; Zig's own aarch64 backend crashes on this code (0.17.0).
	llvm=(-fllvm)
	target=(-target "$arch-linux-musl")
	zig_modules "$scratch" "$scratch/version" "${target[@]}"

	# Side by side, as zig-test.sh does: the tests and the runner are the two long compiles. Each
	# one's failure is the script's, after the other has finished.
	(
		rc=0
		zig test "${llvm[@]}" "${modules[@]}" --test-no-exec -femit-bin="$out/tests" || rc=$?
		echo "$rc" >"$scratch/tests.rc"
	) &
	tests_job=$!
	rc=0
	zig build-exe "${llvm[@]}" "${modules[@]}" --name runner -femit-bin="$out/runner" || rc=$?
	zig build-exe "${llvm[@]}" "${target[@]}" tools/test_shards.zig -femit-bin="$out/test_shards" || rc=$?
	zig test "${llvm[@]}" "${target[@]}" tools/test_shards.zig --test-no-exec -femit-bin="$out/shards_tests" || rc=$?
	wait "$tests_job"
	((rc == 0 && $(cat "$scratch/tests.rc") == 0)) || {
		echo "zig-test-prebuilt.sh: the compile failed" >&2
		exit 1
	}
	printf '%s\n' "$arch" >"$out/arch"
	git rev-parse HEAD >"$out/commit"
	# A tar, not the artifact store's zip, which would drop the executable bits. A fixed order
	# and no owner, so the same files make the same tar.
	tar --sort=name --owner=0 --group=0 --numeric-owner -C "$out" -cf "$tar_path" \
		arch commit runner shards_tests test_shards tests
	sha256sum "$tar_path" | cut -d' ' -f1
	exit 0
fi

tar_path=$(realpath -m "$2")
expected=$3
# EXPERIMENT: `unpack` checks and unpacks once (DIR, kept), so that several steps of a job run
# from it (ZIG_PREBUILT_DIR=DIR: `run` then skips the checks and the unpacking).
if [[ $mode == unpack ]]; then
	dir=$(realpath -m "$4")
	mkdir -p "$dir"
elif [[ -n ${ZIG_PREBUILT_DIR:-} ]]; then
	dir=$ZIG_PREBUILT_DIR
else
	dir=$(mktemp -d)
	trap 'rm -rf "$dir"' EXIT
fi
if [[ $mode == unpack || -z ${ZIG_PREBUILT_DIR:-} ]]; then
	[[ $expected =~ ^[0-9a-f]{64}$ ]] || {
		echo "zig-test-prebuilt.sh: '$expected' is not a sha256" >&2
		exit 1
	}
	actual=$(sha256sum "$tar_path" | cut -d' ' -f1)
	[[ $actual == "$expected" ]] || {
		echo "zig-test-prebuilt.sh: $tar_path is $actual, not the $expected the build job made" >&2
		exit 1
	}
	# Only the six files the build puts in, none with a path of its own.
	tar -C "$dir" -xf "$tar_path" --no-same-owner
	[[ $(find "$dir" -mindepth 1 -printf "%f\n" | LC_ALL=C sort | tr '\n' ' ') == "arch commit runner shards_tests test_shards tests " ]] || {
		echo "zig-test-prebuilt.sh: the tar does not hold what the build puts in" >&2
		exit 1
	}
	[[ $(cat "$dir/arch") == "$(uname -m)" ]] || {
		echo "zig-test-prebuilt.sh: built for $(cat "$dir/arch"), this machine is $(uname -m)" >&2
		exit 1
	}
	[[ $(cat "$dir/commit") == "$(git rev-parse HEAD)" ]] || {
		echo "zig-test-prebuilt.sh: built from $(cat "$dir/commit"), this checkout is $(git rev-parse HEAD)" >&2
		exit 1
	}
fi
[[ $mode != unpack ]] || {
	echo "zig-test-prebuilt.sh: unpacked into $dir" >&2
	exit 0
}
echo "zig-test-prebuilt.sh: ran prebuilt binaries from $(cat "$dir/commit"), built for $(cat "$dir/arch")" >&2
export ZIG_RUNNER_TEST_EXE=$dir/runner
if [[ -n ${ZIG_PREBUILT_DIR:-} ]]; then
	# EXPERIMENT: the tests' output is only text to the job, never its workflow commands (as
	# zig-test.sh does; the non-hosted caller of this script does it itself).
	stop="tests-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
	echo "::stop-commands::$stop" >&2
	trap 'echo "::$stop::" >&2' EXIT
fi
status=0
if [[ ${ZIG_TEST_IN_CONTAINER:-} == 1 ]]; then
	# As zig-test.sh's container run: the same image the project's runner runs on, the working
	# directory the container's overlayfs, the native backend's tests skipping (Docker's seccomp).
	image=$(tr -d '\n' <src/dagger.zig | grep -oE '"ubuntu:[A-Za-z0-9._-]+" *\+\+ *"@sha256:[a-f0-9]{64}"' | tr -d '" +')
	[[ -n $image ]] || {
		echo "zig-test-prebuilt.sh: no default_image in runner/src/dagger.zig" >&2
		exit 1
	}
	for attempt in 1 2 3; do
		docker pull -q "$image" >/dev/null && break
		((attempt < 3)) || exit 1
		sleep $((attempt * 10))
	done
	log=$(mktemp)
	docker run --rm --init --user "$(id -u):$(id -g)" -w /tmp -v "$dir:$dir:ro" \
		-e ZIG_RUNNER_TEST_EXE -e ZIG_TEST_SHARDS -e ZIG_TEST_FULL -e ZIG_TEST_TIMES \
		"$image" "$dir/test_shards" "$dir/tests" 2>&1 | tee "$log" || status=${PIPESTATUS[0]}
	passed=$(sed -n 's/^\([0-9][0-9]*\) passed;.*/\1/p' "$log" | tail -n 1)
	rm -f "$log"
	if ((status == 0)) && ((${passed:-0} < ${ZIG_TEST_MIN_PASSED:-1})); then
		echo "zig-test-prebuilt.sh: ${passed:-0} tests passed in the container, fewer than the ${ZIG_TEST_MIN_PASSED:-1} expected" >&2
		exit 1
	fi
	exit "$status"
fi
if [[ ${ZIG_TEST_NATIVE_AS_ROOT:-} == 1 ]]; then
	# As zig-test.sh's root run: only the native backend's tests (a name filter at run time, as the
	# compile-time one it passes there), as root, with the variables they read.
	export ZIG_TEST_NAME_FILTER=native
	sudo --preserve-env=ZIG_RUNNER_TEST_EXE,ZIG_RUNNER_REQUIRE_NATIVE,ZIG_RUNNER_SERVICE_IMAGES,ZIG_RUNNER_DOCKERFILE_ORACLE,ZIG_RUNNER_DOCKERFILE_ORACLE_ONLY,ZIG_TEST_STORE_STRESS_SECONDS,ZIG_TEST_STORE_STRESS_PROCS,ZIG_TEST_STORE_STRESS_SEED,ZIG_TEST_SHARDS,ZIG_TEST_PART,ZIG_TEST_TIMES,ZIG_TEST_FULL,ZIG_TEST_NAME_FILTER,TSAN_OPTIONS \
		"$dir/test_shards" "$dir/tests" || status=$?
	exit "$status"
fi
# The shard runner's own tests first (build.zig's run_shards_tests), so the tests' count is the
# last "N passed" line, which CI's floor reads.
"$dir/shards_tests" || status=$?
# Where `zig build test` runs them: this directory (runner/), with the source tree around it.
"$dir/test_shards" "$dir/tests" || status=$?
exit "$status"
