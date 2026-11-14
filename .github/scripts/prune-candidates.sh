#!/usr/bin/env bash
# Deletes candidate pre-releases (and their tags) that are past their retention: main candidates
# (main-N-SHA12) and release candidates (vX.Y.Z-rcN) published more than DAYS ago (default 14),
# except
#   - the newest KEEP of each kind (default 20), newest by the run number N, or by version for a
#     release candidate;
#   - the refs of the newest PROTECT_DEPLOYMENTS (default 3) deployments of each environment in
#     PROTECT_ENVIRONMENTS (default razorbill-rc): what a pool runs, and what it rolls back to. A
#     main candidate has no deployment; a machine on `main` takes the newest, which KEEP holds;
#   - any tag named with --protect.
# Never touched: releases, drafts (a run still building), anything that is not a pre-release, and
# any tag that is not exactly a candidate's name. candidate.yml runs it after publishing a main
# candidate, and candidate-prune.yml daily. Needs gh and jq, with GH_REPO set and a token that can
# delete releases and read deployments. A release another run deleted first is not an error.
#
#   prune-candidates.sh [--dry-run] [--days N] [--keep N] [--protect TAG]...
#
# --dry-run lists what would be deleted and what is held back, and deletes nothing. NOW (epoch
# seconds) stands in for the clock, for tests.
set -euo pipefail

dry_run=
days=14
keep=20
protect=()
while (($# > 0)); do
	case $1 in
	--dry-run) dry_run=1 ;;
	--days)
		days=${2:?--days needs a number}
		shift
		;;
	--keep)
		keep=${2:?--keep needs a number}
		shift
		;;
	--protect)
		protect+=("${2:?--protect needs a tag}")
		shift
		;;
	*)
		echo "usage: prune-candidates.sh [--dry-run] [--days N] [--keep N] [--protect TAG]..." >&2
		exit 1
		;;
	esac
	shift
done
: "${GH_REPO:?GH_REPO must be set}"
[[ $days =~ ^[0-9]+$ && $keep =~ ^[1-9][0-9]*$ ]] || {
	echo "--days must be a number and --keep a positive one: $days $keep" >&2
	exit 1
}
protect_deployments=${PROTECT_DEPLOYMENTS:-3}
read -ra environments <<<"${PROTECT_ENVIRONMENTS:-razorbill-rc}"
now=${NOW:-$(date +%s)}
cutoff=$((now - days * 86400))

# The pre-releases that are published, as "TAG EPOCH"; whatever else a release is, it is no candidate.
listing=$(gh release list --limit 1000 --json tagName,isPrerelease,isDraft,publishedAt)
candidates=$(jq -r '.[] | select(.isPrerelease and (.isDraft | not))
	| "\(.tagName) \(.publishedAt | fromdateiso8601)"' <<<"$listing")

main_re='^main-([0-9]+)-[0-9a-f]{12}$'
rc_re='^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$'

held=$'\n'
hold() { held+="$1"$'\n'; }
is_held() { [[ $held == *$'\n'"$1"$'\n'* ]]; }

for tag in "${protect[@]}"; do hold "$tag"; done
for environment in "${environments[@]}"; do
	# A failed read must not turn into "nothing is deployed": nothing is deleted then.
	refs=$(gh api "repos/$GH_REPO/deployments?environment=$environment&per_page=$protect_deployments" --jq '.[].ref') || {
		echo "could not read the deployments of $environment; nothing pruned" >&2
		exit 1
	}
	while read -r ref; do [[ -n $ref ]] && hold "$ref"; done <<<"$refs"
done

# The newest KEEP of each kind.
while read -r tag; do hold "$tag"; done < <(
	awk '{print $1}' <<<"$candidates" | sed -nE 's/^main-([0-9]+)-[0-9a-f]{12}$/\1 &/p' |
		sort -rn | head -n "$keep" | cut -d' ' -f2
)
while read -r tag; do hold "$tag"; done < <(
	awk '{print $1}' <<<"$candidates" | grep -E "$rc_re" | sort -rV | head -n "$keep" || true
)

pruned=0 kept=0
while read -r tag published; do
	[[ -n $tag ]] || continue
	[[ $tag =~ $main_re || $tag =~ $rc_re ]] || continue
	if ((published >= cutoff)) || is_held "$tag"; then
		kept=$((kept + 1))
		continue
	fi
	pruned=$((pruned + 1))
	if [[ -n $dry_run ]]; then
		echo "would prune $tag (published $(date -u -d "@$published" +%F))"
	else
		echo "pruning $tag"
		gh release delete "$tag" --cleanup-tag --yes || echo "could not delete $tag (gone already?)" >&2
	fi
done <<<"$candidates"
echo "candidates: ${dry_run:+would have }pruned $pruned, kept $kept (older than $days days, past the newest $keep of each kind, and not deployed)"
