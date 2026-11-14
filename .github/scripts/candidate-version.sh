#!/usr/bin/env bash
# Prints the names of a candidate build, "VERSION RELEASE_TAG", for candidate.yml and
# deploy/zig-runner-deploy (docs/OPERATIONS.md, "Channels"):
#
#   a release candidate, from its tag (vX.Y.Z-rcN):   vX.Y.Z-rcN  vX.Y.Z-rcN
#   a main candidate, from its run number N and commit SHA:
#                                     vX.Y.Z-main.N+SHA12  main-N-SHA12
#
# X.Y.Z of a main candidate is the newest release's with the patch raised by one: semver puts a
# pre-release before its release, and the next release is at least that. The deploy agent orders main
# candidates by N, so a base that is too low costs nothing. The binary says VERSION (`--version`);
# the GitHub release is named RELEASE_TAG, which holds no "+" and does not start with "v", so the
# release workflow's `v*` tags and its tag ruleset never see it.
#
#   candidate-version.sh tag    <tag>
#   candidate-version.sh main   <run-number> <sha>     (with gh logged in, GH_REPO set)
set -euo pipefail

case ${1:?usage: candidate-version.sh tag TAG | main RUN_NUMBER SHA} in
tag)
	tag=${2:?usage: candidate-version.sh tag TAG}
	[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$ ]] || {
		echo "not a release candidate tag (vX.Y.Z-rcN): $tag" >&2
		exit 1
	}
	echo "$tag $tag"
	;;
main)
	n=${2:?usage: candidate-version.sh main RUN_NUMBER SHA}
	sha=${3:?usage: candidate-version.sh main RUN_NUMBER SHA}
	[[ $n =~ ^[1-9][0-9]*$ && $sha =~ ^[0-9a-f]{40}$ ]] || {
		echo "bad run number or commit: $n $sha" >&2
		exit 1
	}
	: "${GH_REPO:?GH_REPO must be set}"
	newest=$(gh api --paginate "repos/$GH_REPO/git/matching-refs/tags/v" --jq '.[].ref' |
		sed -n 's|^refs/tags/v\([0-9]*\.[0-9]*\.[0-9]*\)$|\1|p' | sort -V | tail -n1)
	[[ -n $newest ]] || {
		echo "no version tag to base the candidate on" >&2
		exit 1
	}
	IFS=. read -r major minor patch <<<"$newest"
	short=${sha:0:12}
	echo "v$major.$minor.$((patch + 1))-main.$n+$short main-$n-$short"
	;;
*)
	echo "usage: candidate-version.sh tag TAG | main RUN_NUMBER SHA" >&2
	exit 1
	;;
esac
