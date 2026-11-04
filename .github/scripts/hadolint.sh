#!/usr/bin/env bash
# Lints the repository's Dockerfiles with hadolint (https://github.com/hadolint/hadolint): CI's
# "Workflows" job. Every rule is on, at its own level, and any finding fails; one that is meant is
# kept with `# hadolint ignore=DLxxxx` on the line before its instruction, after a comment that
# says why (runner/Dockerfile has the examples).
#
# The binary is the release's, checked against the SHA-256 pinned here (the release's
# checksums.sha256, which GitHub's own digest of each asset matches), as zlint.sh checks ZLint. A
# new version (Renovate's) fails here until its checksums are updated, from
# `gh release view vX.Y.Z -R hadolint/hadolint --json assets`.
set -euo pipefail
cd "$(dirname "$0")/../.."

version=2.15.1
case $(uname -m) in
x86_64) sum=c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507 asset=hadolint-linux-x86_64 ;;
aarch64) sum=f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d asset=hadolint-linux-arm64 ;;
*)
	echo "no hadolint $version checksum for $(uname -m)" >&2
	exit 1
	;;
esac

dir="${RUNNER_TOOL_CACHE:-${RUNNER_TEMP:-/tmp}}/hadolint/$version"
bin="$dir/$asset"
verified() { echo "$sum  $bin" | sha256sum --check --quiet --status; }
if ! verified &>/dev/null; then
	mkdir -p "$dir"
	curl -fsSL -o "$bin.part" "https://github.com/hadolint/hadolint/releases/download/v$version/$asset"
	mv "$bin.part" "$bin"
	if ! verified; then
		echo "hadolint $version ($asset) does not match its pinned checksum" >&2
		rm -f "$bin"
		exit 1
	fi
fi
chmod +x "$bin"

mapfile -t dockerfiles < <(git ls-files ':(glob)**/Dockerfile' ':(glob)**/Dockerfile.*' ':(glob)**/*.Dockerfile')
"$bin" "${dockerfiles[@]}"
echo "hadolint: ${#dockerfiles[@]} Dockerfiles, no findings"
