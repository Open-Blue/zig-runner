#!/usr/bin/env bash
# The hardening every release binary must have, checked with checksec (slimm609/checksec, the Go
# rewrite), which fails on any it lacks (README, "Hardening"):
#
#   nx             a non-executable stack
#   separate_code  W^X: no segment both writable and executable, code apart from data
#   pie            a position-independent executable (static PIE), so the kernel loads it at a
#                  random address
#   relro          full RELRO: what the loader relocates is read-only before the runner's own code
#                  runs (static PIE, BIND_NOW)
#
# Run on both binaries by CI's Release builds, on every change that can affect them, and by the
# release before anything is published. The download is checked against the checksum checksec's
# release publishes (checksec_checksums.sha512), pinned here, so a changed or replaced tarball fails
# the job; a new version (Renovate's) fails until its checksum is updated.
#
#   checksec.sh BINARY...
set -euo pipefail
(($# > 0)) || { echo "usage: checksec.sh BINARY..." >&2; exit 2; }

version=3.2.0
# checksec_<version>_linux_<arch>.tar.gz in the release's checksec_checksums.sha512.
case $(uname -m) in
x86_64)
	arch=amd64
	sum=a5bdee9f82c9e0ee2c57fbbea7f64c4bec139cec989122145412827ca2f54a74614d568125f2f37e75c7931d50ecf9d4d80535b227563e4b2ca2ee23f588e146
	;;
aarch64)
	arch=arm64
	sum=9dfc017bbbca96d5d1bab4eb04d776a0b27bdb1a49b6e201eaec70e66d09eeec784ba54a779ea066eef81235ec95c04e4308a9c87c28b3908e30af4c0f0d11f3
	;;
*)
	echo "no checksec checksum for $(uname -m)" >&2
	exit 1
	;;
esac

dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/checksec.XXXXXX")
trap 'rm -rf "$dir"' EXIT
curl -fsSL --retry 3 -o "$dir/checksec.tar.gz" \
	"https://github.com/slimm609/checksec/releases/download/$version/checksec_${version}_linux_$arch.tar.gz"
if ! echo "$sum  $dir/checksec.tar.gz" | sha512sum --check --quiet --status; then
	echo "checksec $version does not match its pinned checksum: update it from the release's checksec_checksums.sha512" >&2
	exit 1
fi
tar -xzf "$dir/checksec.tar.gz" -C "$dir" checksec
"$dir/checksec" --version

status=0
for bin in "$@"; do
	# --no-warnings: the aarch64 binary, read on x86_64, draws "missing libc", for FORTIFY alone.
	"$dir/checksec" file "$bin" --no-banner --no-warnings --color never \
		--fail-if nx,separate_code,pie,relro || status=1
done
exit "$status"
