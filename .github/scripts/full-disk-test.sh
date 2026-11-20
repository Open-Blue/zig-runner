#!/usr/bin/env bash
# Eviction's floor on a disk that is really full (src/native/evict.zig), not a simulated shortage:
# the test binary runs in a mount namespace of its own (bubblewrap, so no root) with a 64 MiB tmpfs,
# which the test fills until a write fails with ENOSPC. Where bubblewrap or unprivileged user
# namespaces are not there, it says so and exits 0, as the test skips without ZIG_RUNNER_FULL_DISK;
# with FULL_DISK_REQUIRED=1 (CI, which installs bubblewrap) it fails instead.
#
#   full-disk-test.sh        from anywhere
set -euo pipefail
cd "$(dirname "$0")/../../runner"

if ! command -v bwrap >/dev/null || ! bwrap --ro-bind / / true 2>/dev/null; then
	[[ ${FULL_DISK_REQUIRED:-} == 1 ]] && { echo "::error::full-disk-test.sh: no bubblewrap, or no user namespaces" >&2 && exit 1; }
	echo "full-disk-test.sh: no bubblewrap, or no user namespaces: skipped" >&2
	exit 0
fi
scratch=$(mktemp -d)
trap 'rm -rf "${scratch:?}"' EXIT
if [[ -n ${ZIG_PREBUILT_DIR:-} ]]; then
	# EXPERIMENT: the tests compiled once for the job (zig-test-prebuilt.sh unpack); only this one runs.
	export ZIG_TEST_NAME_FILTER="really full" ZIG_TEST_SHARDS=1 ZIG_RUNNER_TEST_EXE=$ZIG_PREBUILT_DIR/runner
	run=("$ZIG_PREBUILT_DIR/test_shards" "$ZIG_PREBUILT_DIR/tests")
else
	git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
	# shellcheck source=.github/scripts/zig-modules.sh
	. ../.github/scripts/zig-modules.sh
	zig_modules "$scratch" "$scratch/version"
	zig test "${modules[@]}" --test-filter "really full" -femit-bin="$scratch/tests" --test-no-exec
	run=("$scratch/tests")
fi
# The tmpfs is a mount of the sandbox; the test's own scratch directory stays on the real disk.
bwrap --bind / / --dev /dev --proc /proc --size 67108864 --tmpfs /mnt \
	--setenv ZIG_RUNNER_FULL_DISK /mnt "${run[@]}"
