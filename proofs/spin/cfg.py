#!/usr/bin/env python3
"""Writes proofs/spin/StoreLocking*.pml, SPIN's configurations, from proofs/tla/StoreLocking*.cfg.

One .pml for each of StoreLocking's safety configurations (the liveness one stays TLC's): the
.cfg's comment, its constants as #defines, its invariants as CHK_ defines, and, for one that must
hold, the number of states SPIN must find (the .cfg's `states without symmetry:`, TLC's count,
plus SPIN's first state, before init has run). The .cfg files stay the configurations' source, so
TLC and SPIN check the same bounds.

    proofs/spin/cfg.py           write them
    proofs/spin/cfg.py --check   fail if one is missing, stale or left over (spin.sh runs this)
"""
import pathlib
import re
import sys

spin = pathlib.Path(__file__).resolve().parent
tla = spin.parent / "tla"
model = "StoreLockingModel.pml"
booleans = {
    "OldEntry": "OLDENTRY",
    "BuildHoldsKeyLock": "BUILDHOLDS",
    "SyncBeforePublish": "SYNCBEFORE",
    "HeedSyncErrors": "HEEDSYNC",
    "SyncLayersAtEnd": "SYNCLAYERS",
    "CheckAfterBoot": "CHECKBOOT",
    "EvictRechecks": "EVRECHECK",
    "BuildLooksUpFirst": "LOOKUPFIRST",
}


def render(cfg):
    lines = cfg.read_text().splitlines()
    comments = [l[3:].rstrip() for l in lines if l.startswith("\\* ")]
    body = " ".join(l for l in lines if not l.startswith("\\*"))

    def value(name):
        m = re.search(r"\b" + name + r"\s*=\s*(\w+)", body)
        if not m:
            sys.exit(f"{cfg.name}: no {name}")
        return m.group(1)

    def size(name):
        m = re.search(r"\b" + name + r"\s*=\s*\{([^}]*)\}", body)
        if not m:
            sys.exit(f"{cfg.name}: no {name}")
        return len([x for x in m.group(1).split(",") if x.strip()])

    prose = [c for c in comments if not re.match(r"(tlc-seconds|states without symmetry):", c)]
    out = ["/* " + prose[0]] + [" * " + c for c in prose[1:]]
    out.append(f" * Written from proofs/tla/{cfg.name} by proofs/spin/cfg.py: change the .cfg, not this.")
    states = [c for c in comments if c.startswith("states without symmetry:")]
    if states:
        n = int(re.sub(r"[^0-9]", "", states[0].split(":", 1)[1]))
        out.append(f" * spin-states: {n + 1} */")
    elif "must fail:" not in prose[0]:
        sys.exit(f"{cfg.name}: must hold, and has no `states without symmetry:` line")
    else:
        out[-1] += " */"
    out += [
        f"#define NP {size('Procs')}",
        f"#define NSK {size('StepKeys')}",
        f"#define NBK {size('BuildKeys')}",
        f"#define NS {value('Steps')}",
        f"#define MAXCRASH {value('MaxCrashes')}",
        f"#define MC {value('MachineCrashes')}",
        f"#define MAXCORR {value('MaxCorrupts')}",
        f"#define MAXWERR {value('MaxWriteErrors')}",
    ]
    out += [f"#define {m} {1 if value(n) == 'TRUE' else 0}" for n, m in booleans.items()]
    invariants = re.search(r"\bINVARIANTS\b(.*?)(?:\b[A-Z]{4,}\b|$)", body, re.S).group(1).split()
    out += [f"#define CHK_{i}" for i in invariants]
    out.append(f'#include "{model}"')
    return "\n".join(out) + "\n"


def main():
    check = sys.argv[1:] == ["--check"]
    want = {}
    for cfg in sorted(tla.glob("StoreLocking*.cfg")):
        if re.search(r"^PROPERT(Y|IES)", cfg.read_text(), re.M):
            continue  # liveness: TLC's
        want[cfg.stem + ".pml"] = render(cfg)
    have = {p.name for p in spin.glob("StoreLocking*.pml")} - {model}
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
