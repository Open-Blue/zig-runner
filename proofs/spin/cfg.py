#!/usr/bin/env python3
"""Writes proofs/spin/<Module>*.pml, SPIN's configurations, from proofs/tla/<Module>*.cfg.

One .pml for each configuration of each module ported (MODULES): the .cfg's comment, its
constants as #defines, its invariants as CHK_ defines and its temporal properties as LTL_ defines
(with a `spin-ltl:` line naming them, for spin.sh), and, for one that must hold, the number of
states SPIN must find (the .cfg's `states without symmetry:`, TLC's count, plus SPIN's first
state, before init has run). The .cfg files stay the configurations' source, so TLC and SPIN
check the same bounds.

    proofs/spin/cfg.py           write them
    proofs/spin/cfg.py --check   fail if one is missing, stale or left over (spin.sh runs this)
"""
import pathlib
import re
import sys

spin = pathlib.Path(__file__).resolve().parent
tla = spin.parent / "tla"


class Cfg:
    def __init__(self, path):
        self.name = path.name
        lines = path.read_text().splitlines()
        self.comments = [l[3:].rstrip() for l in lines if l.startswith("\\* ")]
        self.body = " ".join(l for l in lines if not l.startswith("\\*"))

    def value(self, name):
        m = re.search(r"\b" + name + r'\s*=\s*"?(\w+)', self.body)
        if not m:
            sys.exit(f"{self.name}: no {name}")
        return m.group(1)

    def members(self, name):
        m = re.search(r"\b" + name + r"\s*=\s*\{([^}]*)\}", self.body)
        if not m:
            sys.exit(f"{self.name}: no {name}")
        return [x.strip() for x in m.group(1).split(",") if x.strip()]

    def size(self, name):
        return len(self.members(name))

    def flags(self, names):
        return [f"#define {m} {1 if self.value(n) == 'TRUE' else 0}" for n, m in names.items()]

    def section(self, word):
        m = re.search(r"\b" + word + r"\b(.*?)(?:\b[A-Z]{4,}\b|$)", self.body, re.S)
        return m.group(1).split() if m else []


def store_locking(c):
    return [
        f"#define NP {c.size('Procs')}",
        f"#define NSK {c.size('StepKeys')}",
        f"#define NBK {c.size('BuildKeys')}",
        f"#define NS {c.value('Steps')}",
        f"#define MAXCRASH {c.value('MaxCrashes')}",
        f"#define MC {c.value('MachineCrashes')}",
        f"#define MAXCORR {c.value('MaxCorrupts')}",
        f"#define MAXWERR {c.value('MaxWriteErrors')}",
    ] + c.flags({
        "OldEntry": "OLDENTRY",
        "BuildHoldsKeyLock": "BUILDHOLDS",
        "SyncBeforePublish": "SYNCBEFORE",
        "HeedSyncErrors": "HEEDSYNC",
        "SyncLayersAtEnd": "SYNCLAYERS",
        "CheckAfterBoot": "CHECKBOOT",
        "EvictRechecks": "EVRECHECK",
        "BuildLooksUpFirst": "LOOKUPFIRST",
        "EvictUnlocks": "EVUNLOCK",
    })


def store_eviction(c):
    # The keys in TLC's order of model values, by name (and so the order the .cfg files declare
    # them in), which is what its CHOOSE over keys and over dead trees follows.
    volumes, trees = c.members("Volumes"), c.members("Trees")
    keys = sorted(volumes + trees)
    index = {k: i for i, k in enumerate(keys)}
    outer, inner = c.value("Outer"), c.value("Inner")
    return [
        f"#define NP {c.size('Procs')}",
        f"#define ROUNDS {c.value('Rounds')}",
        f"#define MAXCRASH {c.value('MaxCrashes')}",
        f"#define MC {c.value('MachineCrashes')}",
        f"#define MAXPLANT {c.value('MaxPlants')}",
        f"#define MAXSTUCK {c.value('MaxStuck')}",
        f"#define NK {len(keys)}",
        f"#define VOLS {sum(1 << index[v] for v in volumes)}",
        f"#define OUTER {index.get(outer, len(keys))}",
        f"#define INNER {index.get(inner, len(keys))}",
    ] + c.flags({
        "OpenRechecks": "OPENRECHECK",
        "DowngradeRechecks": "DOWNRECHECK",
        "EvictLocks": "EVLOCKS",
        "EvictRechecks": "EVRECHECK",
        "TakesInnerLock": "INNERLOCK",
        "RenameFirst": "RENAMEFIRST",
        "SyncsRename": "SYNCRENAME",
        "SyncsFilesystem": "SYNCFS",
        "ClearsPlanted": "CLEARPLANT",
        "StuckStopsNothing": "STUCKGOES",
    })


def release_pipeline(c):
    counted = c.value("RunsCounted")
    if counted not in ("others", "all"):
        sys.exit(f"{c.name}: RunsCounted is {counted}")
    return [
        f"#define MAXMERGES {c.value('MaxMerges')}",
        f"#define MAXRUNS {c.value('MaxRuns')}",
        f"#define MAXRENAMES {c.value('MaxRenames')}",
        f"#define MAXLOST {c.value('MaxLost')}",
        f"#define MAXFAILS {c.value('MaxFails')}",
        f"#define WAITTICKS {c.value('WaitTicks')}",
        f"#define GRACE {c.value('Grace')}",
        f"#define COUNTALL {1 if counted == 'all' else 0}",
    ] + c.flags({
        "ListFromCommit": "LISTFROMCOMMIT",
        "FastFails": "FASTFAILS",
        "OtherWf": "OTHERWF",
        "DeployIfExplicit": "DEPLOYEXPLICIT",
        "AtomicPush": "ATOMICPUSH",
        "ApprovalHoldsGroup": "APPROVALHOLDS",
    })


# The modules ported to Promela (proofs/spin/<Module>Model.pml), and how a configuration's
# constants become its #defines.
MODULES = {
    "StoreLocking": store_locking,
    "StoreEviction": store_eviction,
    "ReleasePipeline": release_pipeline,
}


def render(module, path):
    c = Cfg(path)
    prose = [l for l in c.comments if not re.match(r"(tlc-seconds|states without (symmetry|the view)):", l)]
    out = ["/* " + prose[0]] + [" * " + l for l in prose[1:]]
    out.append(f" * Written from proofs/tla/{c.name} by proofs/spin/cfg.py: change the .cfg, not this.")
    properties = c.section("PROPERT(?:Y|IES)")
    if properties:
        out.append(" * spin-ltl: " + " ".join(properties))
    states = [l for l in c.comments if re.match("states without (symmetry|the view):", l)]
    if states:
        n = int(re.sub(r"[^0-9]", "", states[0].split("(", 1)[0].split(":", 1)[1]))
        out.append(f" * spin-states: {n + 1} */")
    elif "must fail:" not in prose[0]:
        sys.exit(f"{c.name}: must hold, and has no `states without symmetry:` (or `the view:`) line")
    else:
        out[-1] += " */"
    out += MODULES[module](c)
    out += [f"#define CHK_{i}" for i in c.section("INVARIANTS?")]
    out += [f"#define LTL_{p}" for p in properties]
    out.append(f'#include "{module}Model.pml"')
    return "\n".join(out) + "\n"


def main():
    check = sys.argv[1:] == ["--check"]
    want = {}
    for module in MODULES:
        for path in sorted(tla.glob(module + "*.cfg")):
            if re.fullmatch(module + r"(-.*)?\.cfg", path.name):
                want[path.stem + ".pml"] = render(module, path)
    have = {p.name for p in spin.glob("*.pml")} - {m + "Model.pml" for m in MODULES}
    bad = sorted(n for n in want if not (spin / n).exists() or (spin / n).read_text() != want[n])
    bad += sorted(have - set(want))
    if check:
        if bad:
            sys.exit("proofs/spin: run proofs/spin/cfg.py, as these differ from proofs/tla's .cfg files: " + " ".join(bad))
        return
    for n in have - set(want):
        (spin / n).unlink()
    for n, text in want.items():
        (spin / n).write_text(text)


main()
