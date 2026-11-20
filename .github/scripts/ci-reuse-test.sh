#!/usr/bin/env bash
# ci-reuse.sh's decision, against a stub `gh` that answers from fixture files (no network):
# same tree and base reuse; a different base, a failed run, a fork's run, a different tree, a
# ref without a pull request and any failed lookup do not.
#
#   ci-reuse-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin"

# The stub: `gh api <endpoint> [--jq <filter>]` prints $FIX/<endpoint with / ? & = as _> and runs
# the filter through jq if there is one; a missing fixture is an API error.
cat >"$scratch/bin/gh" <<'STUB'
#!/usr/bin/env bash
[[ $1 == api ]] || exit 2
f=$FIX/$(tr '/?&=' '____' <<<"$2")
[[ -f $f ]] || {
	echo "gh: HTTP 404 $2" >&2
	exit 1
}
if [[ ${3:-} == --jq ]]; then jq -r "$4" "$f"; else cat "$f"; fi
STUB
chmod +x "$scratch/bin/gh"

R=o/r
GROUP=1111111111111111111111111111111111111111
PRHEAD=2222222222222222222222222222222222222222
BASE=3333333333333333333333333333333333333333
OTHER=4444444444444444444444444444444444444444
TREE=5555555555555555555555555555555555555555
TREE2=6666666666666666666666666666666666666666

fixtures() { # fixtures <dir> <pr tree> <run conclusion> <run repo> <run base> <pr repo>
	local d=$1
	mkdir -p "$d"
	echo "{\"tree\":{\"sha\":\"$TREE\"}}" >"$d/repos_${R/\//_}_git_commits_$GROUP"
	echo "{\"tree\":{\"sha\":\"$2\"}}" >"$d/repos_${R/\//_}_git_commits_$PRHEAD"
	echo "{\"head\":{\"sha\":\"$PRHEAD\",\"repo\":{\"full_name\":\"$6\"}},\"state\":\"open\"}" >"$d/repos_${R/\//_}_pulls_7"
	echo "{\"workflow_runs\":[{\"id\":9,\"conclusion\":\"$3\",\"head_repository\":{\"full_name\":\"$4\"},\"pull_requests\":[{\"base\":{\"sha\":\"$5\"}}],\"html_url\":\"https://example/run/9\",\"run_attempt\":1}]}" \
		>"$d/repos_${R/\//_}_actions_workflows_ci.yml_runs_head_sha_${PRHEAD}_event_pull_request_per_page_100"
}

passed=0
failed=0
# check <name> <expected> <fixture args...>; HEAD_REF and DROP (a fixture to delete) may be set.
check() {
	local name=$1 want=$2 d="$scratch/fix-$1"
	shift 2
	fixtures "$d" "$@"
	[[ -z ${DROP:-} ]] || rm -f "$d/$DROP"
	local got
	got=$(FIX=$d PATH="$scratch/bin:$PATH" REPO=$R HEAD_SHA=$GROUP BASE_SHA=$BASE \
		HEAD_REF=${HEAD_REF:-refs/heads/gh-readonly-queue/main/pr-7-$PRHEAD} GITHUB_OUTPUT=/dev/stdout \
		./ci-reuse.sh 2>&1) || true
	if grep -qx "reuse=$want" <<<"$got"; then
		passed=$((passed + 1))
	else
		failed=$((failed + 1))
		echo "ERROR $name: wanted reuse=$want, got:" >&2
		printf '    %s\n' "${got//$'\n'/$'\n'    }" >&2
	fi
}

check same-tree-same-base true "$TREE" success $R "$BASE" $R
check same-tree-other-base false "$TREE" success $R "$OTHER" $R
check failed-run false "$TREE" failure $R "$BASE" $R
check cancelled-run false "$TREE" cancelled $R "$BASE" $R
check unfinished-run false "$TREE" "" $R "$BASE" $R
check fork-run false "$TREE" success fork/r "$BASE" $R
check fork-pull-request false "$TREE" success $R "$BASE" fork/r
check other-tree false "$TREE2" success $R "$BASE" $R
HEAD_REF=refs/heads/gh-readonly-queue/main/nonsense check no-pr-number false "$TREE" success $R "$BASE" $R
DROP=repos_o_r_git_commits_$GROUP check api-error-group-commit false "$TREE" success $R "$BASE" $R
DROP=repos_o_r_pulls_7 check api-error-pull false "$TREE" success $R "$BASE" $R
DROP=repos_o_r_git_commits_$PRHEAD check api-error-pr-commit false "$TREE" success $R "$BASE" $R
DROP=repos_o_r_actions_workflows_ci.yml_runs_head_sha_${PRHEAD}_event_pull_request_per_page_100 check api-error-runs false "$TREE" success $R "$BASE" $R

echo "ci-reuse-test: $passed passed; $failed failed"
((failed == 0))
