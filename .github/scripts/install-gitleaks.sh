#!/usr/bin/env bash
# Installs gitleaks, which scans the repository's commits for secrets (security.yml), and puts it on
# the job's PATH. The download is checked against the checksum its release publishes
# (gitleaks_<version>_checksums.txt), pinned here, so a changed or replaced tarball fails the job
# instead of scanning with it. A new version (Renovate's) fails on its pull request until its
# checksum is updated.
set -euo pipefail

version=8.30.1
# gitleaks_<version>_linux_x64.tar.gz in the release's checksums file.
sum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

dir="${RUNNER_TEMP:-/tmp}/gitleaks-$version"
tarball="$dir/gitleaks.tar.gz"
mkdir -p "$dir"
curl -fsSL -o "$tarball" \
	"https://github.com/gitleaks/gitleaks/releases/download/v$version/gitleaks_${version}_linux_x64.tar.gz"
if ! echo "$sum  $tarball" | sha256sum --check --quiet --status; then
	echo "gitleaks $version does not match its pinned checksum: update it from the release's checksums file" >&2
	exit 1
fi
tar -xzf "$tarball" -C "$dir" gitleaks
"$dir/gitleaks" version
echo "$dir" >>"${GITHUB_PATH:-/dev/null}"
