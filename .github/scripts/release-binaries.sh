#!/usr/bin/env bash
# Downloads a published release's binaries and SHA256SUMS into a directory and checks them as
# deploy/zig-runner-deploy does: each binary against SHA256SUMS, and its provenance, built by
# release.yml from that tag on GitHub's own runners (gh attestation verify). With --complete, also
# that the release has every file the binaries job attaches, so a run that finds it published
# (a re-run) can trust it is whole. Needs gh with GH_TOKEN and GH_REPO.
#
#   release-binaries.sh [--complete] <tag> <dir>      e.g. release-binaries.sh v0.14.0 dist
set -euo pipefail

complete=
if [[ ${1:-} == --complete ]]; then
	complete=1
	shift
fi
tag=${1:?usage: release-binaries.sh [--complete] TAG DIR}
dir=${2:?usage: release-binaries.sh [--complete] TAG DIR}
: "${GH_REPO:?GH_REPO must be set}"

binaries=(zig-runner-linux-x86_64 zig-runner-linux-aarch64)
if [[ -n $complete ]]; then
	want=("${binaries[@]}" SHA256SUMS zig-runner.spdx.json zig-runner.provenance.intoto.jsonl zig-runner.sbom.jsonl)
	have=$(gh release view "$tag" --json assets --jq '.assets[].name')
	for name in "${want[@]}"; do
		# Releases up to v0.28.1 carry the provenance bundle under its old name.
		[[ $name == zig-runner.provenance.intoto.jsonl ]] && grep -qxF zig-runner.provenance.jsonl <<<"$have" && continue
		grep -qxF "$name" <<<"$have" || {
			echo "::error::$tag is published without $name" >&2
			exit 1
		}
	done
fi

mkdir -p "$dir"
gh release download "$tag" -D "$dir" --clobber -p 'zig-runner-linux-*' -p SHA256SUMS
(cd "$dir" && sha256sum --check --strict SHA256SUMS)
for name in "${binaries[@]}"; do
	gh attestation verify "$dir/$name" --repo "$GH_REPO" \
		--signer-workflow "$GH_REPO/.github/workflows/release.yml" \
		--source-ref "refs/tags/$tag" --deny-self-hosted-runners >/dev/null
done
echo "$tag: ${binaries[*]} match SHA256SUMS and their provenance${complete:+; every file is attached}"
