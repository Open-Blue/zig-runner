#!/usr/bin/env python3
"""Memory soak driver: feeds many jobs, one at a time, through ONE runner process and checks that
the process's memory and handles return to where they were (`memory-soak.sh` starts the runner and
runs this; read its header first).

The runner is a real process (native backend, `RUNNER_PLATFORM=gitea`) polling a Gitea instance.
This script queues each job by dispatching a workflow, waits for the run to end, waits until the
runner has been idle for `--settle` seconds, then takes a sample:

  - the runner's own `health: proc rss=.. anon=.. thr=.. fds=.. mounts=.. zombies=.. heap=../N
    rust=..` line (`runner/src/proc_stats.zig`), the first one printed after the settle time (the
    runner says it every `RUNNER_HEALTH_IDLE_INTERVAL` seconds while idle). Its sizes are rounded
    to whole MiB from 10 MiB up, so the exact heap block count (`N`) is the heap's leak signal, and
  - /proc/<pid>/status of the runner, for exact VmRSS and RssAnon (`--pid`).

The jobs are a fixed cycle of shapes (`SHAPES`): run steps, checkout, a container job, a failing
job, a cancelled job, a large log, a step that times out. The first `--warmup` samples are
excluded (caches fill, the first job of each shape pulls and compiles things); the rest are fitted
with a line per counter, and the run fails when a counter grows by more than its margin (`LIMITS`).

  memory_soak.py run      (samples only; `analyze` judges them) --url URL --token-file F --log runner.log --pid PID --out DIR [--jobs N]
  memory_soak.py analyze  DIR/samples.csv [--warmup N] [--allow-anon-kb K]
  memory_soak.py selftest
"""
import argparse, base64, csv, json, os, re, statistics, subprocess, sys, time, urllib.error, urllib.request

# --- the jobs ------------------------------------------------------------------------------------

LABEL = "soak"
HEAD = f"on: workflow_dispatch\njobs:\n  j:\n    runs-on: {LABEL}\n"

# name -> (workflow text, seconds the run may take, how it should end)
SHAPES = {
    "run": (f"name: soak-run\n{HEAD}" + """    env:
      A: one
    steps:
      - id: a
        run: |
          echo "hello $A"
          echo "x=1" >> "$GITHUB_OUTPUT"
          echo "B=two" >> "$GITHUB_ENV"
          echo "::notice::soak notice"
          echo "::add-mask::sekrit"
          echo "sekrit is masked"
      - run: |
          echo "$B ${{ steps.a.outputs.x }}"
          echo "### summary" >> "$GITHUB_STEP_SUMMARY"
      - run: for i in $(seq 200); do echo "line $i"; done
""", 120, "success"),
    "checkout": (f"name: soak-checkout\n{HEAD}" + """    steps:
      - uses: actions/checkout@v4
      - run: ls -a && git log --oneline -1
""", 120, "success"),
    "container": (f"name: soak-container\n{HEAD}" + """    container: alpine:3.20
    steps:
      - run: cat /etc/alpine-release && echo in-container
      - run: echo second step
""", 180, "success"),
    "fail": (f"name: soak-fail\n{HEAD}" + """    steps:
      - name: allowed
        continue-on-error: true
        run: echo before; exit 3
      - name: fails
        run: echo failing; exit 1
      - name: cleanup
        if: always()
        run: echo cleanup ran
""", 120, "failure"),
    "cancel": (f"name: soak-cancel\n{HEAD}" + """    steps:
      - run: echo started; sleep 600
      - name: cleanup
        if: always()
        run: echo cleanup after cancel
""", 120, "cancelled"),
    "biglog": (f"name: soak-biglog\n{HEAD}" + """    steps:
      - run: seq 1 100000 | sed 's/^/soak large log line /'
      - run: echo done
""", 300, "success"),
    "timeout": (f"name: soak-timeout\n{HEAD}" + """    steps:
      - run: echo started; sleep 600
        timeout-minutes: 1
      - name: cleanup
        if: always()
        run: echo cleanup after timeout
""", 240, "failure"),
}

# One cycle of 25 jobs. The step timeout takes a minute by itself, so it is one in 25.
CYCLE = (["run"] * 10 + ["checkout"] * 4 + ["container"] * 3 + ["fail"] * 3 + ["cancel"] * 2 +
         ["biglog"] * 2 + ["timeout"])
assert len(CYCLE) == 25

# --- the counters and their margins ------------------------------------------------------------

# name -> (unit, kind, max growth per job, max end-minus-start). `kind` "bytes" counters are fitted
# with a line and bounded in both ways; "count" counters (handles, threads) must not rise at all.
#
# Where the numbers come from (500 jobs, 2026-11-14, laptop, x86_64, the first run of this soak):
#   - Resident and anonymous memory (7.8 and 2.6 MiB at job 20) rose by 1.5 MiB over the run, in
#     steps at first use, not per job: the runner's threads (13 of them) each touch about 250 KiB
#     of their 16 MiB stacks the first time they run a deep path (a registry pull, a checkout),
#     which /proc/<pid>/smaps shows as new anonymous mappings of that size. So the flat allowance
#     for end-minus-start is 2048 KiB (13 threads x 250 KiB = 3.2 MiB at the most, and 1.5 was
#     seen), not 0. What is left once the threads have been through every shape (from about job
#     250) is 0.87 KiB/job (OLS standard error 0.05), in every shape alike; a run of 220 `run`
#     jobs alone gave 0.9 KiB/job, and smaps of its jobs 100 and 219 shows it in a few small
#     anonymous mappings growing (80 KiB over 120 jobs), outside the counted heap. It is not
#     attributed (the Zig allocators `smp_allocator` and `page_allocator` are used directly in
#     `native/collector.zig`, `native/reaper.zig`, `c_alloc.zig` and others, and no counter sees
#     them). It is below the 2.0 KiB/job margin, so a leak of more than 2 KiB/job (1 MiB over 500
#     jobs) is what this soak can tell from it.
#   - The thread count rises by one or two when the pool first needs another thread, in the first
#     jobs (13 by job 14 in the mixed run, 10 to 11 after job 20 in a run of `run` jobs): 2 allowed.
#   - The page-sized noise: samples move in steps of 4 KiB.
#   - Counts, the heap's block count and the network library's bytes did not move at all (they
#     are exact), so their margins are as tight as can be written: none for handles, mounts
#     and zombies; 8 blocks / 512 KiB / 64 KiB for the heap and `rust=` as room for a
#     cache that fills once.
LIMITS = {
    "proc_rss_kb": ("KiB", "bytes", 2.0, 2048),
    "proc_anon_kb": ("KiB", "bytes", 2.0, 2048),
    "heap_blocks": ("blocks", "count", 0.01, 8),
    "heap_kb": ("KiB", "bytes", 1.0, 512),
    "rust_kb": ("KiB", "bytes", 0.5, 64),
    "threads": ("threads", "count", 0.0, 2),
    "fds": ("fds", "count", 0.0, 0),
    "mounts": ("mounts", "count", 0.0, 0),
    "zombies": ("zombies", "count", 0.0, 0),
}
# Counters the memory a library may keep, in a bounded cache, makes larger by a flat amount at
# most (`--allow-anon-kb`: R4's block cache in runner/rust/src/alloc.rs holds up to 8 MiB and is
# not in `rust=`). It raises the end-minus-start margin of the resident counters; the per-job
# margin is not raised, since a cache that has filled stays the same size.
CACHE_COUNTERS = ("proc_rss_kb", "proc_anon_kb")

HEALTH = re.compile(r"health: proc rss=(\S+) anon=(\S+) thr=(\S+) fds=(\S+) mounts=(\S+) zombies=(\S+) "
                    r"heap=(\S+)/(\d+) rust=(\S+)")


def kb(text):
    """`310K` or `63M` as KiB, None for `?`."""
    if text == "?":
        return None
    return int(text[:-1]) * (1024 if text[-1] == "M" else 1)


def num(text):
    return None if text == "?" else int(text)


def parse_health(line):
    m = HEALTH.search(line)
    if not m:
        return None
    g = m.groups()
    heap = g[6].rstrip("0123456789")  # "41M"
    return {"log_rss_kb": kb(g[0]), "log_anon_kb": kb(g[1]), "threads": num(g[2]), "fds": num(g[3]),
            "mounts": num(g[4]), "zombies": num(g[5]), "heap_kb": kb(heap), "heap_blocks": int(g[7]),
            "rust_kb": kb(g[8])}


def proc_status(pid):
    """VmRSS and RssAnon of /proc/<pid>/status in KiB: the exact values the health line rounds."""
    out = {}
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                out["proc_rss_kb"] = int(line.split()[1])
            elif line.startswith("RssAnon:"):
                out["proc_anon_kb"] = int(line.split()[1])
    return out


# --- the fit -------------------------------------------------------------------------------------

def ols(ys):
    """Least-squares slope of `ys` against 0..n-1 and the standard error of that slope."""
    n = len(ys)
    if n < 3:
        return 0.0, 0.0
    mx, my = (n - 1) / 2, sum(ys) / n
    sxx = sum((i - mx) ** 2 for i in range(n))
    slope = sum((i - mx) * (y - my) for i, y in enumerate(ys)) / sxx
    resid = sum((y - my - slope * (i - mx)) ** 2 for i, y in enumerate(ys))
    return slope, (resid / (n - 2) / sxx) ** 0.5


def theil_sen(ys):
    """The median of the slopes between all pairs of points (every k-th pair above 400 points):
    one outlier, a step that is not growth, does not move it."""
    step = max(1, len(ys) // 400)
    pts = list(range(0, len(ys), step))
    slopes = [(ys[j] - ys[i]) / (j - i) for a, i in enumerate(pts) for j in pts[a + 1:]]
    return statistics.median(slopes) if slopes else 0.0


def judge(rows, warmup, allow_cache_kb=0, window=20):
    """The verdicts of `rows` (a list of dicts, one per job) after `warmup`: a list of
    (counter, ok, text)."""
    rows = rows[warmup:]
    out = []
    for name, (unit, kind, per_job, total) in LIMITS.items():
        ys = [r[name] for r in rows if r.get(name) is not None]
        if len(ys) < 3 * window // 2:
            out.append((name, False, f"only {len(ys)} samples after the warm-up, need {3 * window // 2}"))
            continue
        w = min(window, len(ys) // 3)
        start, end = statistics.median(ys[:w]), statistics.median(ys[-w:])
        slope, se = ols(ys)
        ts = theil_sen(ys[len(ys) // 2:])
        limit_total = total + (allow_cache_kb if name in CACHE_COUNTERS else 0)
        # Growth is real when the whole run's line and the robust Theil-Sen slope of its second half
        # are both above the margin (a step early on, a cache filling, leaves the second half flat),
        # or when the end is above the start by more than its margin (a step is a rise).
        grows = slope > per_job and ts > per_job
        rises = end - start > limit_total
        ok = not grows and not rises
        why = []
        if grows:
            why.append(f"grows {slope:+.3f} {unit}/job (second half {ts:+.3f}) over the {per_job} margin")
        if rises:
            why.append(f"ends {end - start:+.0f} {unit} above its start over the {limit_total} margin")
        out.append((name, ok, f"{'ok' if ok else 'FAIL'}: start {start:.0f} end {end:.0f} {unit} "
                    f"(min {min(ys)} max {max(ys)}), slope {slope:+.3f}+-{se:.3f} {unit}/job, "
                    f"Theil-Sen (second half) {ts:+.3f}" + ("; " + "; ".join(why) if why else "")))
    return out


# --- the instance --------------------------------------------------------------------------------

class Instance:
    def __init__(self, url, token, repo):
        self.url, self.token, self.repo = url.rstrip("/"), token, repo

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            f"{self.url}/api/v1{path}", method=method, data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"token {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                text = r.read()
                return r.status, json.loads(text) if text else None
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")[:300]

    def put_file(self, path, text, message="soak"):
        body = {"content": base64.b64encode(text.encode()).decode(), "message": message, "branch": "main"}
        status, cur = self.call("GET", f"/repos/{self.repo}/contents/{path}?ref=main")
        if status == 200:
            body["sha"] = cur["sha"]
        status, _ = self.call("PUT" if status == 200 else "POST", f"/repos/{self.repo}/contents/{path}", body)
        assert status in (200, 201), f"cannot write {path}: {status}"

    def newest_run(self):
        status, d = self.call("GET", f"/repos/{self.repo}/actions/runs?limit=5")
        runs = d["workflow_runs"] if status == 200 else []
        return max((r["id"] for r in runs), default=0)

    def dispatch(self, workflow):
        before = self.newest_run()
        status, _ = self.call("POST", f"/repos/{self.repo}/actions/workflows/{workflow}/dispatches", {"ref": "main"})
        assert status in (200, 204), f"dispatch {workflow}: {status}"
        for _ in range(60):
            now = self.newest_run()
            if now > before:
                return now
            time.sleep(0.5)
        raise RuntimeError(f"no run appeared for {workflow}")

    def run(self, rid):
        status, r = self.call("GET", f"/repos/{self.repo}/actions/runs/{rid}")
        return r if status == 200 else {"status": "unknown"}

    def running(self, rid):
        status, d = self.call("GET", f"/repos/{self.repo}/actions/runs/{rid}/jobs")
        return status == 200 and any(j.get("status") == "in_progress" for j in d.get("jobs", []))


PENDING = ("queued", "waiting", "in_progress", "running", "pending", "blocked", "unknown")


class Tail:
    """The runner's log, read as it grows: (time received, line)."""

    def __init__(self, path):
        self.f = open(path, "r", errors="replace")
        self.f.seek(0, os.SEEK_END)
        self.partial = ""
        self.job_ends = 0

    def poll(self):
        out = []
        data = self.f.read()
        if data:
            *lines, self.partial = (self.partial + data).split("\n")
            now = time.time()
            out = [(now, l) for l in lines]
            self.job_ends += sum(1 for _, l in out if "job-end: " in l)
        return out


def wait_idle_sample(tail, pid, settle, patience=90):
    """Waits for the runner's job-end line, then for the first idle health line `settle` seconds
    after it, and returns that line's counters with the exact /proc ones; None when it never came."""
    t_end = None
    deadline = time.time() + patience
    while time.time() < deadline:
        for t, line in tail.poll():
            if "job-end: " in line:
                t_end = t
            elif t_end is not None and t >= t_end + settle:
                h = parse_health(line)
                if h:
                    return {**h, **proc_status(pid)}
        time.sleep(0.5)
    return None


def drive(args):
    token = open(args.token_file).read().strip()
    inst = Instance(args.url, token, args.repo)
    folder = ".gitea/workflows"
    for name, (text, _, _) in SHAPES.items():
        inst.put_file(f"{folder}/soak-{name}.yml", text)
    tail = Tail(args.log)
    os.makedirs(args.out, exist_ok=True)
    fields = ["job", "shape", "conclusion", "seconds"] + list(LIMITS) + ["log_rss_kb", "log_anon_kb"]
    out = open(os.path.join(args.out, "samples.csv"), "w", newline="")
    w = csv.DictWriter(out, fieldnames=fields)
    w.writeheader()
    time.sleep(2)
    cycle = [s for s in CYCLE if s in args.shapes.split(",")] if args.shapes else CYCLE
    for i in range(args.jobs):
        shape = cycle[(i + args.shape_offset) % len(cycle)]
        _, limit, want = SHAPES[shape]
        t0 = time.time()
        rid = inst.dispatch(f"soak-{shape}.yml")
        cancelled = False
        while time.time() - t0 < limit:
            r = inst.run(rid)
            if shape == "cancel" and not cancelled and inst.running(rid):
                time.sleep(4)
                inst.call("POST", f"/repos/{args.repo}/actions/runs/{rid}/cancel")
                cancelled = True
            if r["status"] not in PENDING:
                break
            time.sleep(1)
        r = inst.run(rid)
        got = r.get("conclusion") or r["status"]
        if got != want:
            print(f"job {i} ({shape}, run {rid}): ended {got!r}, expected {want!r}", file=sys.stderr)
        sample = wait_idle_sample(tail, args.pid, args.settle)
        if sample is None:
            print(f"job {i} ({shape}): no idle sample", file=sys.stderr)
            continue
        if i == args.smaps_at:
            subprocess.run(["docker", "exec", "zr-soak", "sh", "-c", "cat /proc/$(pgrep -o -x runner)/smaps"],
                           stdout=open(os.path.join(args.out, "smaps-mid.txt"), "w"), check=False)
        row = {"job": i, "shape": shape, "conclusion": got, "seconds": round(time.time() - t0, 1), **sample}
        w.writerow(row)
        out.flush()
        print(f"{i:4d} {shape:9s} {got:9s} {row['seconds']:6.1f}s rss={row['proc_rss_kb']} anon={row['proc_anon_kb']} "
              f"thr={row['threads']} fds={row['fds']} mounts={row['mounts']} z={row['zombies']} "
              f"heap={row['heap_kb']}K/{row['heap_blocks']} rust={row['rust_kb']}K", flush=True)


def analyze(args):
    with open(args.csv) as f:
        rows = [{k: (int(v) if re.fullmatch(r"-?\d+", v or "") else v) for k, v in r.items()} for r in csv.DictReader(f)]
    print(f"{len(rows)} samples, first {args.warmup} excluded")
    bad = 0
    for name, ok, text in judge(rows, args.warmup, args.allow_anon_kb):
        print(f"  {name:14s} {text}")
        bad += not ok
    shapes = {}
    for r in rows:
        shapes.setdefault((r["shape"], r["conclusion"]), 0)
        shapes[(r["shape"], r["conclusion"])] += 1
    print("  shapes:", ", ".join(f"{s}/{c} x{n}" for (s, c), n in sorted(shapes.items())))
    return 1 if bad else 0


def selftest():
    import random
    rng = random.Random(7)
    flat = [{k: 1000 + rng.randint(-40, 40) if k.endswith("_kb") else 5 for k in LIMITS} for _ in range(120)]
    assert all(ok for _, ok, _ in judge(flat, 20)), "noise alone must pass"
    leak = [dict(r, proc_anon_kb=r["proc_anon_kb"] + i * 5) for i, r in enumerate(flat)]
    bad = {n for n, ok, _ in judge(leak, 20) if not ok}
    assert bad == {"proc_anon_kb"}, bad
    fd = [dict(r, fds=5 + i // 40) for i, r in enumerate(flat)]
    assert {n for n, ok, _ in judge(fd, 20) if not ok} == {"fds"}
    step = [dict(r, proc_rss_kb=r["proc_rss_kb"] + (6000 if i > 50 else 0)) for i, r in enumerate(flat)]
    assert not dict((n, ok) for n, ok, _ in judge(step, 20))["proc_rss_kb"], "a step is a rise"
    assert dict((n, ok) for n, ok, _ in judge(step, 20, allow_cache_kb=8192))["proc_rss_kb"], "a cache's allowance"
    assert parse_health("x health: proc rss=63M anon=60M thr=24 fds=71 mounts=29 zombies=0 heap=41M/41200 rust=310K")[
        "heap_blocks"] == 41200
    print("selftest ok")


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--url", required=True)
    r.add_argument("--token-file", required=True)
    r.add_argument("--repo", default="zradmin/soak")
    r.add_argument("--log", required=True)
    r.add_argument("--pid", type=int, required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--jobs", type=int, default=500)
    r.add_argument("--settle", type=float, default=4.0)
    r.add_argument("--shape-offset", type=int, default=0)
    r.add_argument("--smaps-at", type=int, default=-1,
                   help="after this job, save the runner's /proc smaps (a docker container named zr-soak)")
    r.add_argument("--shapes", default="", help="only these shapes, comma-separated")
    a = sub.add_parser("analyze")
    a.add_argument("csv")
    a.add_argument("--warmup", type=int, default=20)
    a.add_argument("--allow-anon-kb", type=int, default=0)
    sub.add_parser("selftest")
    args = p.parse_args()
    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "analyze":
        return analyze(args)
    drive(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
