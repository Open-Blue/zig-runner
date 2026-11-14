#!/usr/bin/env bash
# Deletes the main candidates' GitHub releases (and their tags) but the newest KEEP (default 20),
# newest by the run number in their tag (main-N-SHA12): candidate.yml runs it after publishing one.
# Release candidates and releases are never touched. Needs gh, with GH_REPO set and a token that
# can delete releases. A release another run deleted first is not an error.
#
#   prune-candidates.sh [keep]
set -euo pipefail

keep=${1:-20}
: "${GH_REPO:?GH_REPO must be set}"
[[ $keep =~ ^[1-9][0-9]*$ ]] || {
	echo "keep must be a positive number: $keep" >&2
	exit 1
}

mapfile -t old < <(
	gh release list --limit 1000 --json tagName,isPrerelease --jq '.[] | select(.isPrerelease) | .tagName' |
		sed -nE 's/^main-([0-9]+)-[0-9a-f]{12}$/\1 &/p' | sort -rn | tail -n +$((keep + 1)) | cut -d' ' -f2
)
for tag in "${old[@]}"; do
	echo "pruning $tag"
	gh release delete "$tag" --cleanup-tag --yes || echo "could not delete $tag (gone already?)" >&2
done
echo "main candidates: kept the newest $keep, pruned ${#old[@]}"
