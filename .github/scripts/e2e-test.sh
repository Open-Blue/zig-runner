#!/usr/bin/env bash
# e2e.sh's reading of a run's jobs list, with no GitHub: `distinct-jobs` drops the record GitHub made
# of a job twice (one that never had a runner) and nothing else.
#
#   e2e-test.sh
set -euo pipefail
cd "$(dirname "$0")"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
fail() {
	echo "e2e-test: $*" >&2
	exit 1
}
names() { E2E_OUT=$scratch/out ./e2e.sh distinct-jobs | jq -r '[.jobs[] | "\(.id):\(.name)"] | join(" ")'; }

# runner-bench run 44306203521 (2026-11-18): toolcache twice, the first never assigned.
got=$(names <<'JSON'
{"total_count":3,"jobs":[
 {"id":1,"name":"docker","status":"completed","conclusion":"success","runner_name":"r1","steps":[{}]},
 {"id":2,"name":"toolcache","status":"queued","conclusion":null,"runner_name":null,"steps":[]},
 {"id":3,"name":"toolcache","status":"completed","conclusion":"success","runner_name":"r2","steps":[{}]}]}
JSON
)
[[ $got == "1:docker 3:toolcache" ]] || fail "a queued twin was kept or the job that ran dropped: $got"

# A job that never started and has no twin stays: the run's checks must fail on it.
got=$(names <<'JSON'
{"jobs":[{"id":5,"name":"cache","status":"queued","conclusion":null,"runner_name":null,"steps":[]}]}
JSON
)
[[ $got == "5:cache" ]] || fail "a lone queued job was dropped: $got"

# Two that ran (a rerun's jobs are listed per attempt, but if two meet) both stay.
got=$(names <<'JSON'
{"jobs":[{"id":7,"name":"cache","status":"completed","conclusion":"failure","runner_name":"r1","steps":[{}]},
 {"id":8,"name":"cache","status":"completed","conclusion":"success","runner_name":"r2","steps":[{}]}]}
JSON
)
[[ $got == "7:cache 8:cache" ]] || fail "two jobs that ran were not both kept: $got"
echo "e2e-test: ok"
