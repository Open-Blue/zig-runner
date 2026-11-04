#!/usr/bin/env bash
# Checks the format of every shell script shellcheck.sh checks with shfmt
# (https://github.com/mvdan/sh): CI's "Workflows" job. A script that is not formatted fails, with
# the diff that would format it; `shfmt.sh -w` writes it instead.
#
# shfmt's defaults (tabs, no other options) are the style the scripts had before it ran: of the
# option sets tried, they changed the fewest lines (21; -ci 461, -bn 143, -sr 293).
#
# The binary is the release's, checked against the SHA-256 pinned here (GitHub's own digest of the
# release asset; the release publishes no checksum file), as zlint.sh checks ZLint. A new version
# (Renovate's) fails here until its checksums are updated, from the `digest` of each asset in
# `gh api repos/mvdan/sh/releases/tags/vX.Y.Z`.
set -euo pipefail
cd "$(dirname "$0")/../.."

mode=-d
[[ ${1:-} == -w ]] && mode=-w

version=3.14.1
case $(uname -m) in
x86_64) sum=76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf asset=shfmt_v${version}_linux_amd64 ;;
aarch64) sum=5f2db09dae91fca848f7adbdd014632e921a383863a2ad7e0450ad3aba0c6489 asset=shfmt_v${version}_linux_arm64 ;;
*)
	echo "no shfmt $version checksum for $(uname -m)" >&2
	exit 1
	;;
esac

dir="${RUNNER_TOOL_CACHE:-${RUNNER_TEMP:-/tmp}}/shfmt/$version"
bin="$dir/$asset"
verified() { echo "$sum  $bin" | sha256sum --check --quiet --status; }
if ! verified &>/dev/null; then
	mkdir -p "$dir"
	curl -fsSL -o "$bin.part" "https://github.com/mvdan/sh/releases/download/v$version/$asset"
	mv "$bin.part" "$bin"
	if ! verified; then
		echo "shfmt $version ($asset) does not match its pinned checksum" >&2
		rm -f "$bin"
		exit 1
	fi
fi
chmod +x "$bin"

# The scripts shellcheck.sh finds: by their #! line, so a new one is checked without being listed.
mapfile -t scripts < <(
	git ls-files -z | xargs -0 grep -lsE '^#!/usr/bin/env (bash|sh)|^#!/bin/(ba)?sh' -- 2>/dev/null
	echo .githooks/common.sh
)
if ! "$bin" "$mode" "${scripts[@]}"; then
	echo "shfmt: not formatted (the diff above); .github/scripts/shfmt.sh -w formats them" >&2
	exit 1
fi
echo "shfmt: ${#scripts[@]} scripts formatted"
