#!/usr/bin/env bash
# Whether a merge group's ci.yml run can reuse a pull request's pass. The queue tests the last
# queued pull request on top of main (or on the group before it); when that is the very tree a
# `pull_request` run of ci.yml already passed, on the very base the group is built on, running the
# heavy jobs again finds nothing new and costs about 49 job-minutes and a wait for runners.
#
#   ci-reuse.sh        env: GH_TOKEN, REPO (owner/name), HEAD_SHA (the group's head commit),
#                      BASE_SHA (the group's base commit), HEAD_REF (refs/heads/gh-readonly-queue/
#                      <branch>/pr-<number>-<sha>), GITHUB_OUTPUT
#
# Sets `reuse=true` only when ALL hold, for a ci.yml run:
#   - its event is pull_request, its conclusion success, and it is of this repository (no fork);
#   - the tree of its head commit is the tree of HEAD_SHA (the tree covers .github, so the
#     workflows are the same too);
#   - its base commit (the pull request's base when the run started) is BASE_SHA.
# Anything else, and any failed lookup, is `reuse=false`: the run goes on as it always did. It
# says in the log what it compared and why it decided.
#
# A re-run is no concern: a run's conclusion is that of its latest attempt over all its jobs (a
# re-run of failed jobs keeps the passed ones), and the run's head commit is the same in each
# attempt. The jobs a pull request's run skips are skipped by ci-scope.sh from the same diff the
# group would make, and the reuse job itself never runs on pull_request, so no run holds a skip it
# did not earn.
set -uo pipefail

: "${REPO:?}" "${HEAD_SHA:?}" "${BASE_SHA:?}" "${HEAD_REF:?}"
out=${GITHUB_OUTPUT:-/dev/stdout}

finish() {
	echo "reuse=$1" >>"$out"
	echo "reuse=$1: $2"
	exit 0
}

echo "merge group head $HEAD_SHA, base $BASE_SHA, ref $HEAD_REF"

[[ $HEAD_REF =~ /pr-([0-9]+)-[0-9a-f]+$ ]] || finish false "no pull request number in the ref"
pr=${BASH_REMATCH[1]}

# The group's head commit is the last queued pull request on top of its base; its tree is what the
# queue tests. (The commit's tree through the API: no checkout of the code, and one fewer thing to wait for.)
group_tree=$(gh api "repos/$REPO/git/commits/$HEAD_SHA" --jq .tree.sha) || finish false "cannot read the group's commit"
[[ $group_tree =~ ^[0-9a-f]{40,64}$ ]] || finish false "no tree for the group's commit"
echo "group tree $group_tree"

pull=$(gh api "repos/$REPO/pulls/$pr" --jq '[.head.sha, .head.repo.full_name // "", .state] | @tsv') || finish false "cannot read pull request #$pr"
IFS=$'\t' read -r pr_sha pr_repo _ <<<"$pull"
[[ $pr_sha =~ ^[0-9a-f]{40,64}$ ]] || finish false "no head commit for pull request #$pr"
echo "pull request #$pr head $pr_sha from ${pr_repo:-a deleted repository}"
[[ $pr_repo == "$REPO" ]] || finish false "pull request #$pr is from ${pr_repo:-a deleted repository}, not from $REPO"

pr_tree=$(gh api "repos/$REPO/git/commits/$pr_sha" --jq .tree.sha) || finish false "cannot read the pull request's commit"
echo "pull request tree $pr_tree"
[[ $pr_tree == "$group_tree" ]] || finish false "the trees differ: the group tests something the pull request's run did not"

runs=$(gh api "repos/$REPO/actions/workflows/ci.yml/runs?head_sha=$pr_sha&event=pull_request&per_page=100" \
	--jq '.workflow_runs[] | [.id, .conclusion // "", (.head_repository.full_name // ""), ([.pull_requests[].base.sha] | first // ""), .html_url, .run_attempt] | @tsv') ||
	finish false "cannot list ci.yml's runs for $pr_sha"

found=
while IFS=$'\t' read -r id conclusion run_repo run_base url attempt; do
	[[ -n $id ]] || continue
	echo "run $id (attempt $attempt) $url: conclusion ${conclusion:-none}, repository ${run_repo:-none}, base ${run_base:-none}"
	[[ $conclusion == success ]] || continue
	[[ $run_repo == "$REPO" ]] || continue
	[[ $run_base == "$BASE_SHA" ]] || continue
	found=$url
	break
done <<<"$runs"

[[ -n $found ]] || finish false "no successful pull_request run of the same tree on base $BASE_SHA"
finish true "same tree $group_tree and base $BASE_SHA passed in $found"
