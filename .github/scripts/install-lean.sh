#!/usr/bin/env bash
# Installs Lean for this job, for the proofs in proofs/, and puts it (with lake) on the job's PATH.
# The release tarball is checked against the checksum the Lean project publishes for it on GitHub,
# pinned here, so a changed or replaced tarball fails the job instead of checking the proofs. A new
# Lean version means new checksums from that release, and the same version in proofs/lean-toolchain.
# No elan: the version is the one pinned, never one a toolchain file names.
set -euo pipefail

version=4.36.0
case $(uname -m) in
x86_64)
	asset="lean-$version-linux"
	sum=7289597a44543246c9227b8cae501767e095ce17f6d448b95fc4a8dc97268f6d
	;;
aarch64)
	asset="lean-$version-linux_aarch64"
	sum=c8f0f8a3920e839718b1343e6781fd80a3e9b1024fbcd7078eb30f54e806b028
	;;
*)
	echo "no Lean $version checksum for $(uname -m)" >&2
	exit 1
	;;
esac

want=$(cat "$(dirname "$0")/../../proofs/lean-toolchain")
if [[ $want != "leanprover/lean4:v$version" ]]; then
	echo "proofs/lean-toolchain names $want, and this script installs Lean $version" >&2
	exit 1
fi

dir="${RUNNER_TEMP:-/tmp}/lean"
mkdir -p "$dir"
curl -fsSL -o "$dir/$asset.tar.zst" "https://github.com/leanprover/lean4/releases/download/v$version/$asset.tar.zst"
if ! echo "$sum  $dir/$asset.tar.zst" | sha256sum --check --quiet --status; then
	echo "Lean $version ($asset) does not match its pinned checksum" >&2
	exit 1
fi
tar --zstd -xf "$dir/$asset.tar.zst" -C "$dir"
rm "$dir/$asset.tar.zst"
echo "$dir/$asset/bin" >>"$GITHUB_PATH"
