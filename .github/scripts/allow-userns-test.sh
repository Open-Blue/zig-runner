#!/usr/bin/env bash
# allow-userns.sh's branches, against a made-up /proc/sys and a stand-in for sudo, so that no root
# and no kernel setting is involved: the key absent (a note, success, the other switches printed),
# present as 1 (written, read back, success), a write that does not take (failure that says so), and
# a write that is refused (failure that says so).
#
#   allow-userns-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fake=$scratch/sys
mkdir -p "$fake/kernel" "$fake/user"
export ALLOW_USERNS_PROC_SYS=$fake
key=$fake/kernel/apparmor_restrict_unprivileged_userns

fail() {
	echo "allow-userns-test: $*" >&2
	exit 1
}

# run SUDO: the helper's status in $status, its output in $scratch/out.
run() {
	status=0
	ALLOW_USERNS_SUDO=$1 ./allow-userns.sh >"$scratch/out" 2>&1 || status=$?
}
expect() {
	grep -qF -- "$1" "$scratch/out" || fail "no \"$1\" in: $(cat "$scratch/out")"
}

# Key absent: success, says so, prints the other two switches.
echo 1 >"$fake/kernel/unprivileged_userns_clone"
echo 15000 >"$fake/user/max_user_namespaces"
run env
((status == 0)) || fail "key absent: status $status: $(cat "$scratch/out")"
expect "does not exist"
expect "kernel.unprivileged_userns_clone=1 user.max_user_namespaces=15000"
[[ ! -e $key ]] || fail "key absent: the helper created the key"

# The other switches absent too.
rm "$fake/kernel/unprivileged_userns_clone" "$fake/user/max_user_namespaces"
run env
((status == 0)) || fail "no switches: status $status"
expect "kernel.unprivileged_userns_clone=absent user.max_user_namespaces=absent"

# Key 1 to 0: written and read back.
echo 1 >"$key"
run env
((status == 0)) || fail "key 1: status $status: $(cat "$scratch/out")"
expect "before: 1"
expect "after: 0"
[[ $(cat "$key") == 0 ]] || fail "key 1: the file holds $(cat "$key")"

# Already 0: still success.
run env
((status == 0)) || fail "key 0: status $status"
expect "before: 0"

# A write that does not take (the stand-in does nothing): failure that names the value.
echo 1 >"$key"
run true
((status != 0)) || fail "write that did not take: status 0"
expect "after: 1"
expect "still says 1"

# A write that is refused.
run false
((status != 0)) || fail "refused write: status 0"
expect "could not write 0"

echo "allow-userns-test: ok"
