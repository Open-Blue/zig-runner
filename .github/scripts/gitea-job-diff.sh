#!/usr/bin/env bash
# Compares the job the runner builds from a Gitea or Forgejo task (runner/src/gitea/job.zig) with
# what Gitea's own workflow model (gitea.dev/actionslib, the model Gitea and act read workflows with)
# reads from the same task's payload:
#
#   - runner/tools/gitea-jobdiff (Go) reads each task of runner/src/gitea/testdata/corpus and
#     writes what the model makes of its job: steps with their kind, `uses`, `run`, `if`, `with` and
#     `env`, the job's env, container, services, defaults, outputs and matrix;
#   - runner/tools/giteajobcorpus.zig builds the job.Job from the same tasks and compares: every
#     text by what it evaluates to (the model's through expr.interpolate, the job's template
#     through expr.evalString), every other field as it is.
#
# The corpus is the answers of FetchTask from a real Gitea (28.3) and a real Forgejo (13.0) for the
# workflows of runner-bench (the e2e suite's among them) and runner/tools/gitea-jobdiff/features.yml,
# secrets and tokens replaced and each event cut down to its inputs. Make more with
# runner/tools/gitea-jobdiff/collect.py (it pushes workflows to a throwaway instance, dispatches
# them and saves what FetchTask answers). The same comparison runs in the
# unit tests over the model's committed answers (testdata/corpus-model.jsonl); this one asks the
# model afresh, so it is the one to run after the model's version moves. Needs Go. CI runs it
# weekly (compare.yml), not on pull requests.
#
#   gitea-job-diff.sh
set -euo pipefail
cd "$(dirname "$0")/../../runner"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
zig build-exe -OReleaseSafe --dep runner -Mroot=tools/giteajobcorpus.zig -Mrunner=src/gitea_job_corpus.zig \
	--name giteajobcorpus -femit-bin="$scratch/giteajobcorpus" &
(cd tools/gitea-jobdiff && go run . -out "$scratch/answers.jsonl" ../../src/gitea/testdata/corpus)
wait
"$scratch/giteajobcorpus" src/gitea/testdata/corpus "$scratch/answers.jsonl"
