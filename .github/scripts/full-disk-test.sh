#!/usr/bin/env bash
# Eviction's floor on a disk that is really full (src/native/evict.zig), not a simulated shortage:
# the test binary runs in a mount namespace of its own (bubblewrap, so no root) with a 64 MiB tmpfs,
# which the test fills until a write fails with ENOSPC. Where bubblewrap or unprivileged user
# namespaces are not there, it says so and exits 0, as the test skips without ZIG_RUNNER_FULL_DISK.
#
#   full-disk-test.sh        from anywhere
set -euo pipefail
cd "$(dirname "$0")/../../runner"

if ! command -v bwrap >/dev/null || ! bwrap --ro-bind / / true 2>/dev/null; then
	echo "full-disk-test.sh: no bubblewrap, or no user namespaces: skipped" >&2
	exit 0
fi
scratch=$(mktemp -d)
trap 'rm -rf "${scratch:?}"' EXIT
git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh
zig_modules "$scratch" "$scratch/version"
zig test "${modules[@]}" --test-filter "really full" -femit-bin="$scratch/tests" --test-no-exec
# The tmpfs is a mount of the sandbox; the test's own scratch directory stays on the real disk.
bwrap --bind / / --dev /dev --proc /proc --size 67108864 --tmpfs /mnt \
	--setenv ZIG_RUNNER_FULL_DISK /mnt "$scratch/tests"
