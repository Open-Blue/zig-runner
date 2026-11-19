#!/usr/bin/env bash
# apt-pinned.sh when the pin fails: it must fail with apt.sh's status, print what apt-cache says
# for each pinned package (and not for options), and succeed silently when apt.sh does.
#
#   apt-pinned-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fail() {
	echo "apt-pinned-test: $*" >&2
	exit 1
}
mkdir "$scratch/bin"
printf '#!/bin/sh\nexit 7\n' >"$scratch/apt-fail"
printf '#!/bin/sh\nexit 0\n' >"$scratch/apt-ok"
printf '#!/bin/sh\necho "fake apt-cache $*"\n' >"$scratch/bin/apt-cache"
chmod +x "$scratch/apt-fail" "$scratch/apt-ok" "$scratch/bin/apt-cache"

status=0
PATH=$scratch/bin:$PATH APT_SH=$scratch/apt-fail ./apt-pinned.sh --no-install-recommends spin=1.0 kcov=2.0 >"$scratch/out" 2>&1 || status=$?
((status == 7)) || fail "status 7 became $status"
for want in 'fake apt-cache policy spin' 'fake apt-cache madison spin' 'fake apt-cache policy kcov' '::error title=Pinned apt package failed to install::spin=1.0 kcov=2.0 (exit 7)'; do
	grep -qF "$want" "$scratch/out" || fail "missing '$want': $(cat "$scratch/out")"
done
! grep -q 'apt-cache policy --no' "$scratch/out" || fail "an option was looked up as a package"

PATH=$scratch/bin:$PATH APT_SH=$scratch/apt-ok ./apt-pinned.sh spin=1.0 >"$scratch/out" 2>&1 || fail "success failed"
[[ ! -s $scratch/out ]] || fail "success printed: $(cat "$scratch/out")"
echo "apt-pinned-test: a failed pin prints the archive's versions and keeps the status"
