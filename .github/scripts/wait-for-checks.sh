#!/usr/bin/env bash
# Waits until every check named in .github/checks-on-main, and in EXTRA_CHECKS (one per line), has
# succeeded on a commit, for up to WAIT_MINUTES (default 40). The file is read from the working tree,
# the commit the job checked out, not from the workflow that runs this: a run that waited for
# approval through a rename waits for the current names. A check that completed without success
# fails at once. One that never started fails as soon as every workflow run on the commit has
# finished, other than the runs that wait (version.yml's and release.yml's, this one among them),
# after a short grace for runs not created yet, naming it; one still queued or running
# fails at the end of the wait. Each is named, followed by what its
# failure means (the second argument). Only GitHub Actions' check runs count (another app could
# name one the same), from every page, and for each name the latest (the highest id): a re-run is a
# new check run under the same name. A failed request counts as none found yet, so a passing
# GitHub hiccup costs a poll. release.yml's deploy job waits so for the tagged commit, and
# version.yml's tag job for main's, before tagging it. Needs gh with GH_TOKEN, and
# GITHUB_REPOSITORY.
#
#   wait-for-checks.sh <commit> <consequence>
#   e.g. wait-for-checks.sh "$GITHUB_SHA" "v1.2.3 is not deployed (docs/OPERATIONS.md, \"Deploying releases\")"
set -euo pipefail

sha=${1:?usage: wait-for-checks.sh COMMIT CONSEQUENCE}
consequence=${2:?usage: wait-for-checks.sh COMMIT CONSEQUENCE}
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
wait_minutes=${WAIT_MINUTES:-40}
# Runs on the commit that GitHub may not have created yet when this starts (a push just made).
grace_seconds=${GRACE_SECONDS:-120}

mapfile -t checks < <(
	{
		sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$(dirname "$0")/../checks-on-main"
		printf '%s\n' "${EXTRA_CHECKS:-}"
	} | sed -e 's/^[[:space:]]*//' -e '/^$/d'
)
((${#checks[@]} > 0)) || {
	echo "::error::no checks to wait for (.github/checks-on-main is empty)"
	exit 1
}
deadline=$((SECONDS + wait_minutes * 60))
while :; do
	runs=$(gh api --paginate "repos/$GITHUB_REPOSITORY/commits/$sha/check-runs?per_page=100" \
		--jq '.check_runs[] | select(.app.slug == "github-actions") | {id, name, status, conclusion}' |
		jq -s .) || {
		echo "::warning::could not list the check runs on $sha"
		runs='[]'
	}
	waiting=()
	missing=()
	for name in "${checks[@]}"; do
		state=$(jq -r --arg name "$name" '[.[] | select(.name == $name)] | max_by(.id)
			// {status: "missing"} | if .status == "completed" then .conclusion else .status end' <<<"$runs")
		case $state in
		success) ;;
		missing)
			missing+=("$name")
			waiting+=("$name ($state)")
			;;
		queued | in_progress | waiting | requested | pending) waiting+=("$name ($state)") ;;
		*)
			echo "::error::$name: $state on $sha, so $consequence"
			exit 1
			;;
		esac
	done
	((${#waiting[@]} > 0)) || break
	# A check that never started, on a commit whose runs have all finished, will not start now.
	if ((${#missing[@]} > 0)) && ((SECONDS >= grace_seconds)); then
		# Not the runs that wait (version.yml's, release.yml's): the job running this is one, open
		# while it waits, and on the commit whenever nothing merged since its run was created, the
		# usual case; a version run waiting for approval is another. What they wait for comes from
		# the other workflows. (Found by proofs/tla/ReleasePipeline.tla, `-own-run`.)
		runs=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs?head_sha=$sha&per_page=100" \
			--jq '[.workflow_runs[] | select(.path | test("^\\.github/workflows/(version|release)\\.yml") | not)
				| .status]' 2>/dev/null) || runs='["unknown"]'
		open=$(jq '[.[] | select(. != "completed")] | length' <<<"$runs")
		total=$(jq 'length' <<<"$runs")
		if ((open == 0 && total > 0)); then
			echo "::error::never ran on $sha, whose workflow runs have all finished: ${missing[*]}; $consequence (a name in .github/checks-on-main or EXTRA_CHECKS that is not a job run on a push to main?)"
			exit 1
		fi
	fi
	if ((SECONDS >= deadline)); then
		echo "::error::still waiting after $wait_minutes minutes for: ${waiting[*]}; $consequence"
		exit 1
	fi
	echo "waiting for: ${waiting[*]}"
	sleep 30
done
echo "passed on $sha: ${checks[*]}"
