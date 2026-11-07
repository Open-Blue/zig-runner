#!/usr/bin/env bash
# Checks that the check names the pipeline waits for are names of jobs that run when it waits:
#
#   - each name in .github/checks-on-main, and each one release.yml's deploy job adds, is a job of
#     a workflow that runs on a push to main, and not a job that skips itself there
#     (`github.event_name != 'push'`);
#   - each check a branch ruleset requires is a job of a workflow that runs on pull requests and in
#     the merge queue (read from the API; skipped, saying so, where the rulesets cannot be read).
#
# A job's name is its `name:`, or its id, with `${{ matrix.KEY }}` filled in from its matrix (a
# name this cannot fill in fails, so it is never silently skipped). A check renamed or removed in
# one place and not the others held a release for 30 minutes and failed it (2026-11-07). CI's
# Workflows job and the pre-push hook run this.
#
#   check-names.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

rulesets=''
if command -v gh >/dev/null && repo=${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)}; then
	ids=$(gh api "repos/$repo/rulesets" --jq '.[] | select(.target == "branch") | .id' 2>/dev/null) || ids=''
	for id in $ids; do
		# shellcheck disable=SC2016 # $n is jq's, not the shell's
		rulesets+=$(gh api "repos/$repo/rulesets/$id" --jq '.name as $n | .rules[] |
			select(.type == "required_status_checks") | .parameters.required_status_checks[] |
			"\($n)\t\(.context)"' 2>/dev/null)$'\n' || true
	done
fi
export RULESETS=$rulesets

python3 -I - <<'PY'
import itertools, os, re, sys

def workflows():
    d = ".github/workflows"
    for f in sorted(os.listdir(d)):
        if f.endswith((".yml", ".yaml")):
            yield f, open(os.path.join(d, f)).read().splitlines()

def triggers(lines):
    """The events in a workflow's `on:`, block or inline form."""
    out = set()
    for i, l in enumerate(lines):
        m = re.match(r"^on:\s*(.*)$", l)
        if not m:
            continue
        rest = m.group(1).strip()
        if rest:
            out |= set(re.findall(r"[a-z_]+", rest))
            return out
        for l2 in lines[i + 1:]:
            if l2 and not l2.startswith(" ") and not l2.startswith("#"):
                break
            m2 = re.match(r"^  ([a-z_]+):", l2)
            if m2:
                out.add(m2.group(1))
        return out
    return out

def jobs(lines):
    """(display names, if-condition) per job, matrix filled in."""
    try:
        start = lines.index("jobs:")
    except ValueError:
        return
    body = lines[start + 1:]
    keys = [i for i, l in enumerate(body) if re.match(r"^  [A-Za-z0-9_-]+:\s*$", l)]
    for n, k in enumerate(keys):
        end = keys[n + 1] if n + 1 < len(keys) else len(body)
        for j in range(k + 1, end):
            if body[j] and not body[j].startswith(" ") and not body[j].startswith("#"):
                end = j
                break
        job = body[k:end]
        jid = job[0].strip()[:-1]
        name, cond, matrix = jid, "", {}
        for i, l in enumerate(job):
            m = re.match(r"^    name:\s*(.+?)\s*$", l)
            if m:
                name = m.group(1).strip("'\"")
            m = re.match(r"^    if:\s*(.*)$", l)
            if m:
                cond = m.group(1)
                for l2 in job[i + 1:]:
                    if re.match(r"^      \S", l2):
                        cond += " " + l2.strip()
                    else:
                        break
            if re.match(r"^      matrix:\s*$", l):
                for i2 in range(i + 1, len(job)):
                    l2 = job[i2]
                    if not l2.startswith("        ") and l2.strip():
                        break
                    m2 = re.match(r"^        ([A-Za-z0-9_-]+):\s*\[(.*)\]\s*$", l2)
                    if m2:
                        matrix[m2.group(1)] = [v.strip().strip("'\"") for v in m2.group(2).split(",")]
                        continue
                    m2 = re.match(r"^        ([A-Za-z0-9_-]+):\s*$", l2)
                    if m2:
                        vals = []
                        for l3 in job[i2 + 1:]:
                            m3 = re.match(r"^          - (.+?)\s*$", l3)
                            if not m3:
                                break
                            vals.append(m3.group(1).strip("'\""))
                        matrix[m2.group(1)] = vals
        used = re.findall(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}", name)
        if re.search(r"\$\{\{", re.sub(r"\$\{\{\s*matrix\.[A-Za-z0-9_-]+\s*\}\}", "", name)):
            yield None, (jid, name), cond
            continue
        if any(u not in matrix or not matrix[u] for u in used):
            yield None, (jid, name), cond
            continue
        keys_used = sorted(set(used))
        for combo in itertools.product(*(matrix[u] for u in keys_used)):
            out = name
            for u, v in zip(keys_used, combo):
                out = re.sub(r"\$\{\{\s*matrix\." + re.escape(u) + r"\s*\}\}", str(v), out)
            yield out, (jid, name), cond

on_push, on_pr = {}, {}
errors = []
unfilled = []
for f, lines in workflows():
    t = triggers(lines)
    for name, (jid, raw), cond in jobs(lines):
        if name is None:
            unfilled.append(f"{f}: job {jid}: name {raw!r} cannot be filled in from its matrix")
            continue
        skips_push = re.search(r"github\.event_name\s*!=\s*'push'", cond) is not None
        if "push" in t and not skips_push:
            on_push.setdefault(name, []).append(f)
        if "pull_request" in t and "merge_group" in t:
            on_pr.setdefault(name, []).append(f)

def names_in(path):
    return [l.strip() for l in open(path) if l.strip() and not l.lstrip().startswith("#")]

main = names_in(".github/checks-on-main")
for n in main:
    if n not in on_push:
        errors.append(f".github/checks-on-main: {n!r} is not a job that runs on a push to main")

# release.yml's own additions, in its deploy job's run step.
rel = open(".github/workflows/release.yml").read()
m = re.search(r"\n( +)EXTRA_CHECKS:\s*\|-\n((?:\1  +\S.*\n)+)", rel)
if not m:
    errors.append("release.yml: no EXTRA_CHECKS list in the deploy job")
else:
    for n in [l.strip() for l in m.group(2).splitlines() if l.strip()]:
        if n not in on_push:
            errors.append(f"release.yml: EXTRA_CHECKS {n!r} is not a job that runs on a push")

rs = [l.split("\t", 1) for l in os.environ.get("RULESETS", "").splitlines() if "\t" in l]
if rs:
    for ruleset, ctx in rs:
        if ctx not in on_pr:
            errors.append(f"ruleset {ruleset!r} requires {ctx!r}, which is not a job run on pull requests and in the merge queue")
else:
    print("check-names: the rulesets could not be read, so their required checks were not checked", file=sys.stderr)

# Only names something waits for must be fillable; say the others once.
for u in unfilled:
    print(f"check-names: {u} (not checked)", file=sys.stderr)
for e in errors:
    print(f"::error::{e}")
if errors:
    sys.exit(1)
print(f"check-names: {len(main)} names main waits for, {len(rs)} required by rulesets: all are jobs that run then")
PY
