#!/usr/bin/env python3
"""Makes corpus tasks: pushes workflows to a throwaway Gitea or Forgejo, dispatches them, and saves
what FetchTask answers a runner that has the labels they ask for, as runner/src/gitea/testdata/corpus
holds them (secrets and tokens replaced, each event cut down to its inputs). The instance must be one
you can throw away: this registers runners on it and takes tasks it never reports.

    ZR_FLAVOR=gitea|forgejo ZR_URL=http://127.0.0.1:3300 ZR_ADMIN=user:password \\
    ZR_CONTAINER=<docker container> ZR_REPO=owner/repo \\
        collect.py <workflow.yml>... <output dir>

ZR_CONTAINER is the instance's container, for `docker exec -u git <it> <gitea|forgejo> actions
generate-runner-token`. Workflows go to `.gitea/workflows` (Gitea) or `.forgejo/workflows`, with
`workflow_dispatch` inputs given their defaults, `label` as `e2e`, and anything else `x1`. The runner
has the labels self-hosted, laptop, pi-bench, e2e and ubuntu-latest. Then regenerate INDEX
(`ls *.json | LC_ALL=C sort > INDEX`) and corpus-model.jsonl (`go run . -out
../../src/gitea/testdata/corpus-model.jsonl ../../src/gitea/testdata/corpus`).
"""
import base64, hashlib, json, os, re, subprocess, sys, time, urllib.error, urllib.request

flavor = os.environ["ZR_FLAVOR"]
url = os.environ["ZR_URL"].rstrip("/")
repo = os.environ["ZR_REPO"]
auth = "Basic " + base64.b64encode(os.environ["ZR_ADMIN"].encode()).decode()
workflows, out_dir = sys.argv[1:-1], sys.argv[-1]
labels = ["self-hosted", "laptop", "pi-bench", "e2e", "ubuntu-latest"]


def call(method, path, body=None, headers=None):
    h = {"Authorization": auth, "Content-Type": "application/json", **(headers or {})}
    h = {k: v for k, v in h.items() if v}
    req = urllib.request.Request(url + path, method=method, headers=h,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read()
            return r.status, json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def connect(method, body, headers=None):
    return call("POST", "/api/actions/runner.v1.RunnerService/" + method, body,
                {"Connect-Protocol-Version": "1", "Authorization": "", **(headers or {})})


token = subprocess.run(
    ["docker", "exec", "-u", "git", os.environ["ZR_CONTAINER"], flavor, "actions", "generate-runner-token"],
    capture_output=True, text=True, check=True).stdout.split()[-1]
status, reg = connect("Register", {"name": "corpus", "token": token, "version": "corpus", "labels": labels})
assert status == 200, "Register failed"
runner = {"x-runner-uuid": reg["runner"]["uuid"], "x-runner-token": reg["runner"]["token"]}

folder = ".gitea/workflows/" if flavor == "gitea" else ".forgejo/workflows/"
for path in workflows:
    name, text = os.path.basename(path), open(path).read()
    b64 = base64.b64encode(text.encode()).decode()
    status, current = call("GET", f"/api/v1/repos/{repo}/contents/{folder}{name}")
    call("PUT" if status == 200 else "POST", f"/api/v1/repos/{repo}/contents/{folder}{name}",
         {"content": b64, "message": "corpus " + name, **({"sha": current["sha"]} if status == 200 else {})})
time.sleep(2)
for path in workflows:
    name, text = os.path.basename(path), open(path).read()
    inputs = {}
    block = re.search(r"^on:\s*\n\s+workflow_dispatch:\s*\n\s+inputs:\n((?:\s{6,}.*\n?)*)", text, re.M)
    current = None
    for line in (block.group(1).splitlines() if block else []):
        key = re.match(r"^ {6}([A-Za-z0-9_-]+):\s*$", line)
        if key:
            current = key.group(1)
            inputs[current] = "e2e" if current == "label" else "x1"
        elif current and (d := re.match(r"^ {8}default:\s*(.*)$", line)):
            inputs[current] = d.group(1).strip("\"' ")
    status, why = call("POST", f"/api/v1/repos/{repo}/actions/workflows/{name}/dispatches", {"ref": "main", "inputs": inputs})
    if status != 204:
        print(name, "not dispatched:", status, why)

os.makedirs(out_dir, exist_ok=True)
seen, idle = set(), 0
while idle < 6:
    status, answer = connect("FetchTask", {}, runner)
    if status != 200 or not answer.get("task"):
        idle += 1
        time.sleep(1.5)
        continue
    idle = 0
    task = answer["task"]
    payload = base64.b64decode(task["workflowPayload"]).decode()
    digest = hashlib.sha1(payload.encode()).hexdigest()
    if digest in seen:
        continue
    seen.add(digest)
    for key in task.get("secrets", {}):
        task["secrets"][key] = "ci-secret-" + key
    ctx = task["context"]
    for key, value in ctx.items():
        if "token" in key.lower() and isinstance(value, str) and value:
            ctx[key] = "ctx-" + key
    event = ctx.get("event", {})
    ctx["event"] = {"inputs": event["inputs"]} if "inputs" in event else {}
    workflow = re.search(r"^name:\s*(.*)$", payload, re.M).group(1).strip("\"' ")
    job = re.search(r"jobs:\n\s+([A-Za-z0-9_-]+):", payload).group(1)
    name = f"{flavor}-{workflow}-{job}"
    n = 1
    while os.path.exists(f"{out_dir}/{name}.json"):
        n += 1
        name = f"{flavor}-{workflow}-{job}-{n}"
    with open(f"{out_dir}/{name}.json", "w") as f:
        json.dump(answer, f, indent=1)
    print("saved", name)
