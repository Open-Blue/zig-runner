#!/usr/bin/env python3
"""Mutation testing of the runner's own code: changes one thing at a time in a module's source and
runs the tests that cover it, to find what the tests let through (docs/CI.md, "Mutation testing").

A mutant the tests fail on is killed; one they pass is a survivor, and points at a missing test (or,
sometimes, at a change that means the same thing). Each mutant is one of:

    cmp       a comparison flipped: < and <=, > and >=, == and !=
    logic     `and` for `or`, and the other way round
    bool      `true` for `false`, and the other way round
    guard     a `return error.X` taken away (its `if` line, or the bare return)
    int       a decimal integer constant changed by one, up and down (0 only up)
    delete    a statement on a line of its own taken out (not a declaration, return or break)

Only code outside `test` blocks, comments and string literals is changed. Each mutant is compiled
from a copy of runner/src (the checkout is never touched) with only the module's tests
(`zig test --test-filter`), by Zig's own backend, then run with a timeout. A mutant that does not
compile is counted apart: the compiler killed it, not the tests.

    python3 runner/tools/mutate.py masking                 one module, its report on stdout
    python3 runner/tools/mutate.py --all --out DIR         every module: DIR/report.md, results.json
    python3 runner/tools/mutate.py minisign --list         the mutants, none run
    python3 runner/tools/mutate.py expr --sample 200       a seeded sample of the module's mutants

Needs `zig build --fetch` run once in runner/ (the tls package, which the module graph imports).

Mull and other LLVM-level tools were tried first: they instrument through a clang pass plugin
(mull-ir-frontend), which `zig` has no way to load, and are built against an LLVM other than
Zig's. Changing the source keeps every mutant a line of Zig a reader can find.
"""
import argparse
import concurrent.futures
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

RUNNER = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# Each module: the files mutated, and the test filters that select the tests covering them (a test
# runs when its fully qualified name, "dagger.JobLog.test.<name>", contains any of them). The
# jobs dagger.zig's tests run through a fake engine count: they are where most of a job's
# commands and masks are checked end to end.
MODULES = {
    "masking": {
        "files": ["src/redact.zig", "src/dagger/JobLog.zig"],
        "filters": ["redact", "JobLog.test", "sink.test", "mask", "dagger.test.workflow commands",
                    "dagger.test.stop-commands", "dagger.test.job outputs",
                    "dagger.test.environment.url", "dagger.test.a replay logs"],
    },
    "commands": {
        "files": ["src/commands.zig"],
        "filters": ["commands", "JobLog.test", "dagger.test.workflow commands",
                    "dagger.test.stop-commands", "dagger.test.set-env", "dagger.test.file commands",
                    "fuzz: workflow commands"],
    },
    # Also GitHub's own expression cases, with --expr-cases (expr-conformance.sh's).
    "expr": {
        "files": ["src/expr.zig"],
        "filters": ["expr.test", "Evaluator.test", "fuzz: expressions"],
    },
    "store": {
        "files": ["src/native/Store.zig"],
        "filters": ["native.Store.test", "native.key_vectors.test", "native.layers.test"],
    },
    "minisign": {
        "files": ["src/minisign.zig"],
        "filters": ["minisign", "zig_release.test"],
    },
}

CMP_FLIP = {"<": "<=", "<=": "<", ">": ">=", ">=": ">", "==": "!=", "!=": "=="}
# Longest first, so `<<=` is not read as `<` then `<=`.
OPERATOR = re.compile(r"<<\|=|<<=|>>=|<<\||<<|>>|<=|>=|==|!=|=>|<|>")
WORD = re.compile(r"\b(and|or|true|false)\b")
INTEGER = re.compile(r"(?<![\w.])(\d+)(?![\w.])")
GUARD_IF = re.compile(r"^\s*if \(.*\) return error\.\w+;\s*$")
GUARD_BARE = re.compile(r"^\s*return error\.\w+;\s*$")
NOT_A_STATEMENT = re.compile(
    r"^\s*(const|var|pub|fn|return|break|continue|unreachable|else|test|comptime)\b")


def blank_literals(line):
    """`line` with comments, strings and character literals turned to spaces, so a mutation never
    lands in them (positions are kept: the result is as long as the line)."""
    out = list(line)
    stripped = line.lstrip()
    if stripped.startswith("\\\\") or stripped.startswith("//"):
        return " " * len(line)
    i = 0
    while i < len(line):
        c = line[i]
        if c == "/" and line.startswith("//", i):
            for j in range(i, len(line)):
                out[j] = " "
            break
        if c in "\"'":
            j = i + 1
            while j < len(line) and line[j] != c:
                j += 2 if line[j] == "\\" else 1
            for k in range(i, min(j + 1, len(line))):
                out[k] = " "
            i = j + 1
            continue
        if c == "@" and line.startswith('@"', i):
            out[i] = " "
        i += 1
    return "".join(out)


def top_level(lines):
    """(first, last, name) of each top-level declaration, `test` blocks with no name."""
    first = name = None
    for i, line in enumerate(lines):
        if first is None:
            m = re.match(r"^(?:pub )?(?:inline )?(?:fn (\w+)|(?:const|var) (\w+)\b.*[{(]$)", line)
            if m and not line.rstrip().endswith(";"):
                first, name = i, m.group(1) or m.group(2)
            elif re.match(r"^test\b", line):
                first, name = i, None
        elif line in ("}", "};", "});"):
            yield first, i, name
            first = None


def code_lines(text):
    """(line number, line, its code alone) for each line of code the runner itself runs: outside
    `test` blocks and the private declarations only they use (fixtures such as minisign's)."""
    lines = text.split("\n")
    skip = set()
    decls = list(top_level(lines))
    for first, last, name in decls:
        # `pub const testing = struct { ... }`: what a module hands other modules' tests.
        if name is None or name == "testing":
            skip.update(range(first, last + 1))
    # Until none is left: a fixture may be used only by another fixture.
    changed = True
    while changed:
        changed = False
        for first, last, name in decls:
            if name is None or first in skip or re.match(r"^pub\b", lines[first]):
                continue
            word = re.compile(rf"\b{name}\b")
            if not any(word.search(blank_literals(lines[i])) for i in range(len(lines))
                       if i not in skip and not first <= i <= last):
                skip.update(range(first, last + 1))
                changed = True
    for i, line in enumerate(lines):
        if i not in skip:
            yield i + 1, line, blank_literals(line)


def mutants_of(path, text):
    lines = text.split("\n")
    prev_code = ""
    for n, line, code in code_lines(text):
        def at(start, end, new, op):
            return {"file": path, "line": n, "op": op, "old": line.strip(),
                    "new": (line[:start] + new + line[end:]).strip(),
                    "start": start, "end": end, "text": new}

        if "@import" not in code:
            for m in OPERATOR.finditer(code):
                if m.group() in CMP_FLIP:
                    yield at(m.start(), m.end(), CMP_FLIP[m.group()], "cmp")
            for m in WORD.finditer(code):
                w = m.group()
                new = {"and": "or", "or": "and", "true": "false", "false": "true"}[w]
                yield at(m.start(), m.end(), new, "logic" if w in ("and", "or") else "bool")
            # Not in array types (`[32]u8`) or alignments, where a changed size is a type error.
            if not re.search(r"\b(align|u\d+|i\d+)\b\s*\(", code):
                for m in INTEGER.finditer(code):
                    if code[max(0, m.start() - 1)] == "[" and code[m.end():m.end() + 1] == "]":
                        continue
                    v = int(m.group())
                    yield at(m.start(), m.end(), str(v + 1), "int")
                    if v > 0:
                        yield at(m.start(), m.end(), str(v - 1), "int")
        if GUARD_IF.match(code) or GUARD_BARE.match(code):
            yield at(0, len(line), "", "guard")
        elif (code.rstrip().endswith(";") and not NOT_A_STATEMENT.match(code)
              and code.count("(") == code.count(")")
              and prev_code.rstrip().endswith(("{", ";", "}"))
              and "return error." not in code):
            yield at(0, len(line), "", "delete")
        if code.strip():
            prev_code = code


def apply(text, mutant):
    lines = text.split("\n")
    line = lines[mutant["line"] - 1]
    lines[mutant["line"] - 1] = line[:mutant["start"]] + mutant["text"] + line[mutant["end"]:]
    return "\n".join(lines)


def tls_root():
    with open(os.path.join(RUNNER, "build.zig.zon")) as f:
        zon = f.read()
    h = re.search(r'\.hash = "([^"]*)"', zon).group(1)
    root = os.path.join(RUNNER, "zig-pkg", h, "src", "root.zig")
    if not os.path.exists(root):
        sys.exit(f"{root} is missing: run `zig build --fetch` in runner/ first")
    return root


def output(cmd, **kw):
    """`cmd` run to its end, what it wrote kept as text: a failed test may print any bytes."""
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                          stdin=subprocess.DEVNULL, **kw)


class Worker:
    """A copy of runner/src to mutate, and a cache of its own."""

    def __init__(self, base, filters, timeout, expr_cases=None):
        self.dir = tempfile.mkdtemp(prefix="w", dir=base)
        shutil.copytree(os.path.join(RUNNER, "src"), os.path.join(self.dir, "src"))
        with open(os.path.join(self.dir, "version"), "w") as f:
            f.write("mutant")
        self.filters = filters
        self.timeout = timeout
        self.tls = tls_root()
        self.expr_cases = expr_cases

    def build(self):
        cmd = ["zig", "test", "-fPIE", "--dep", "build_version", "--dep", "tls",
               "-Mroot=src/main.zig", "-Mbuild_version=version", f"-Mtls={self.tls}",
               "--cache-dir", "cache", "--test-no-exec", "-femit-bin=t"]
        for f in self.filters:
            cmd += ["--test-filter", f]
        return output(cmd, cwd=self.dir, timeout=600)

    def run(self):
        """'passed', 'failed' or 'timeout', and what the tests wrote."""
        env = dict(os.environ, ZIG_RUNNER_TEST_EXE="/nonexistent")
        try:
            p = output([os.path.join(self.dir, "t")], cwd=self.dir, timeout=self.timeout, env=env)
        except subprocess.TimeoutExpired:
            return "timeout", ""
        return ("passed" if p.returncode == 0 else "failed"), p.stderr

    def cases_agree(self):
        """Whether expr.zig fails exactly the GitHub cases it is known to fail
        (tools/exprcorpus-failing.txt), as expr-conformance.sh checks."""
        b = output(["zig", "build-exe", "--dep", "expr", f"-Mroot={RUNNER}/tools/exprcorpus.zig",
                    "-Mexpr=src/expr.zig", "--cache-dir", "cache", "-femit-bin=exprcorpus"],
                   cwd=self.dir, timeout=600)
        if b.returncode != 0:
            return False
        try:
            p = output([os.path.join(self.dir, "exprcorpus"), self.expr_cases, "--failing"],
                       timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return False
        with open(os.path.join(RUNNER, "tools", "exprcorpus-failing.txt")) as f:
            want = sorted(line for line in f.read().split("\n") if line)
        return sorted(line for line in p.stdout.split("\n") if line) == want

    def trial(self, mutant):
        path = os.path.join(self.dir, mutant["file"])
        with open(path) as f:
            original = f.read()
        with open(path, "w") as f:
            f.write(apply(original, mutant))
        try:
            if self.build().returncode != 0:
                return "uncompiled"
            outcome, _ = self.run()
            if outcome == "passed" and self.expr_cases and not self.cases_agree():
                return "killed"
            return {"passed": "survived", "failed": "killed", "timeout": "timeout"}[outcome]
        except subprocess.TimeoutExpired:
            return "timeout"
        finally:
            with open(path, "w") as f:
                f.write(original)
            # The cache keeps each build; mutants never share one, so it would only grow.
            shutil.rmtree(os.path.join(self.dir, "cache", "o"), ignore_errors=True)


def run_module(name, args, base):
    spec = MODULES[name]
    mutants = []
    for path in spec["files"]:
        with open(os.path.join(RUNNER, path)) as f:
            mutants += list(mutants_of(path, f.read()))
    if args.ops:
        mutants = [m for m in mutants if m["op"] in args.ops]
    if args.at:
        mutants = [m for m in mutants if f'{m["file"]}:{m["line"]}' in args.at]
    if args.sample and args.sample < len(mutants):
        mutants = sorted(random.Random(args.seed).sample(mutants, args.sample),
                         key=lambda m: (m["file"], m["line"], m["start"]))
    if args.shard:
        k, n = args.shard
        mutants = mutants[k - 1::n]
    if args.list:
        for m in mutants:
            print(f'{m["file"]}:{m["line"]} [{m["op"]}] {m["new"] or "(line removed)"}')
        return None

    cases = args.expr_cases if name == "expr" else None
    workers = [Worker(base, spec["filters"], args.timeout, cases) for _ in range(args.jobs)]
    # The unchanged code must pass its tests, and how long they take bounds a mutant's run: ten
    # times as long, and at least 10 s (a loop a mutant never leaves is a timeout, not a hang).
    b = workers[0].build()
    if b.returncode != 0:
        sys.exit(f"{name}: the unchanged code does not compile:\n{b.stderr}")
    t0 = time.monotonic()
    outcome, out = workers[0].run()
    took = time.monotonic() - t0
    if outcome != "passed":
        sys.exit(f"{name}: the unchanged code fails its tests ({outcome}):\n{out[-4000:]}")
    if cases and not workers[0].cases_agree():
        sys.exit(f"{name}: the unchanged code does not fail exactly the cases in "
                 "tools/exprcorpus-failing.txt (expr-conformance.sh says which)")
    for w in workers:
        w.timeout = args.timeout or max(10.0, 10 * took)
    ran = len(re.findall(r"\.\.\.OK", out))
    skipped = len(re.findall(r"\.\.\.SKIP", out))
    print(f"{name}: {len(mutants)} mutants; {ran} tests pass unchanged ({skipped} skipped) in "
          f"{took:.1f} s, a mutant's get {workers[0].timeout:.0f} s; {args.jobs} at a time",
          file=sys.stderr)

    free = list(workers)
    lock = threading.Lock()
    done = [0]

    def one(m):
        with lock:
            w = free.pop()
        try:
            m["result"] = w.trial(m)
        except Exception as e:  # one mutant's trouble is reported, not the run's end
            m["result"] = "error"
            print(f"{name}: {m['file']}:{m['line']}: {e!r}", file=sys.stderr)
        finally:
            with lock:
                free.append(w)
                done[0] += 1
                if m["result"] == "survived" or done[0] % 25 == 0:
                    print(f"{name}: {done[0]}/{len(mutants)} {m['file']}:{m['line']} "
                          f"{m['result']}", file=sys.stderr)
        return m

    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        results = list(pool.map(one, mutants))
    return {"module": name, "files": spec["files"], "filters": spec["filters"], "tests": ran,
            "skipped": skipped, "mutants": results}


def summary(r):
    counts = {k: sum(1 for m in r["mutants"] if m["result"] == k)
              for k in ("killed", "survived", "timeout", "uncompiled")}
    tried = counts["killed"] + counts["survived"] + counts["timeout"]
    score = (counts["killed"] + counts["timeout"]) / tried if tried else 1.0
    return counts, score


def report(results):
    out = ["| Module | Mutants | Killed | Survived | Timed out | Didn't compile | Score |",
           "|---|---:|---:|---:|---:|---:|---:|"]
    for r in results:
        c, s = summary(r)
        out.append(f'| {r["module"]} | {len(r["mutants"])} | {c["killed"]} | {c["survived"]} | '
                   f'{c["timeout"]} | {c["uncompiled"]} | {s:.0%} |')
    out.append("")
    out.append("Score: killed and timed out over those that compiled.")
    for r in results:
        survivors = [m for m in r["mutants"] if m["result"] == "survived"]
        out.append("")
        out.append(f'### {r["module"]}: {len(survivors)} surviving')
        out.append("")
        out.append(f'Files: {", ".join(r["files"])}; tests: {r["tests"]} ({r["skipped"]} more '
                   f'skipped), by filter {", ".join("`" + f + "`" for f in r["filters"])}.')
        if not survivors:
            continue
        out.append("")
        for m in survivors:
            change = f'`{m["new"]}`' if m["new"] else "line removed"
            out.append(f'- `{m["file"]}:{m["line"]}` {m["op"]}: `{m["old"]}` → {change}')
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("modules", nargs="*", metavar="MODULE",
                   help=f'one or more of: {", ".join(MODULES)}')
    p.add_argument("--all", action="store_true", help="every module")
    p.add_argument("--ops", nargs="+", choices=["cmp", "logic", "bool", "guard", "int", "delete"])
    p.add_argument("--at", nargs="+", metavar="FILE:LINE",
                   help="only the mutants on these lines (src/redact.zig:174), to see a new "
                   "test kill them")
    p.add_argument("--sample", type=int, help="this many mutants per module, picked at random")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--jobs", "-j", type=int, default=4, help="mutants built and run at once")
    p.add_argument("--timeout", type=float, help="seconds a mutant's tests may run "
                   "(default: 10 times the unchanged code's, at least 10)")
    p.add_argument("--shard", type=shard, metavar="K/N",
                   help="only the Kth of every N mutants (for runs on several machines)")
    p.add_argument("--merge", nargs="+", metavar="JSON",
                   help="no mutants: one report from these results.json files (of shards)")
    p.add_argument("--list", action="store_true", help="print the mutants and run none")
    p.add_argument("--expr-cases", metavar="DIR", help="GitHub's expression cases "
                   "(actions/languageservices' expressions/testdata, at expr-conformance.sh's "
                   "commit): expr's mutants must also fail exactly the known ones")
    p.add_argument("--out", help="write report.md and results.json here, not the report to stdout")
    args = p.parse_args()
    if args.merge:
        return write(merge(args.merge), args.out)
    names = list(MODULES) if args.all else args.modules
    if not names:
        p.error("name a module, or --all")
    for n in names:
        if n not in MODULES:
            p.error(f'no module {n!r}: one of {", ".join(MODULES)}')

    base = tempfile.mkdtemp(prefix="mutate-")
    try:
        results = [r for r in (run_module(n, args, base) for n in names) if r]
    finally:
        # A test a mutant stopped halfway can leave a directory it took every permission from
        # (the store's walk test does), which must be given them back before it can go.
        for root, dirs, _ in os.walk(base):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o700)
                except OSError:
                    pass
        shutil.rmtree(base, ignore_errors=True)
    if results:
        write(results, args.out)
    # A survivor is a finding to read, not a failure of the run.


def shard(text):
    k, _, n = text.partition("/")
    if not (k.isdigit() and n.isdigit() and 1 <= int(k) <= int(n)):
        raise argparse.ArgumentTypeError(f"{text!r} is not K/N with 1 <= K <= N")
    return int(k), int(n)


def merge(paths):
    """The results of several runs (shards) as one, a module's mutants together in file order."""
    modules = {}
    for path in paths:
        with open(path) as f:
            for r in json.load(f):
                if r["module"] in modules:
                    modules[r["module"]]["mutants"] += r["mutants"]
                else:
                    modules[r["module"]] = r
    for r in modules.values():
        r["mutants"].sort(key=lambda m: (m["file"], m["line"], m["start"], m["new"]))
    return [modules[n] for n in MODULES if n in modules]


def write(results, out):
    text = report(results)
    if not out:
        sys.stdout.write(text)
        return
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "report.md"), "w") as f:
        f.write(text)
    with open(os.path.join(out, "results.json"), "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()
