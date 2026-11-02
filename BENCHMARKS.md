# Benchmarks

Everything here was measured on the reference machine, **razorbill**, except where a section says
otherwise:

- a Raspberry Pi 5 with 8 GB of memory and a 117 GB SD card, which also runs other home services
- the Dagger engine v0.21.10 in Docker, capped at 3 CPUs and 4 GB, with its cache capped at 20 GB
  ([`deploy/engine.json`](deploy/engine.json))

If a fast machine were the yardstick, a slow design could pass. Measuring on a Pi keeps the fixed
costs visible.

## Where a job's time goes

*2026-10-25, zig-runner v0.4.1.* The `test` job of this repository's CI (checkout, Install Zig,
`zig fmt --check`, `zig build test`), first run after a reboot. CPU time and disk I/O come from the
cgroups of the runner's systemd unit and of the engine's container, sampled every second; step times
come from GitHub's API.

| Phase | Wall | Runner CPU | Engine CPU | Engine writes |
| --- | --- | --- | --- | --- |
| Set up job | 40 s | 0.03 s | 23.0 s | 622 MB |
| Install Zig | 20 s | 0.01 s | 6.3 s | 421 MB |
| Format check | 1 s | 0.00 s | 0.4 s | 5 MB |
| Test | 185 s | 0.03 s | 175.8 s | 295 MB |
| **Whole job** | **249 s** | **0.11 s** | **205.8 s** | **1,344 MB** |

The runner process accounts for 0.05% of the job's CPU. With no jobs, both runner pools on the
machine together used 21 s of CPU in almost 12 hours, under 0.05% of one core, in 5-10 MB of memory
each (14 MB peak).

**So rewriting the runner, in Rust or anything else, cannot speed a job up.** The runner's own work
is 0.11 s of CPU, so a faster language could save at most that. The rest of its share of a job is
waiting on GitHub and the engine, which no rewrite changes. Jobs are made faster by the engine doing
less, by its caches surviving, and by the disk.

## Restarting the engine keeps its cache, if it is allowed to stop

*2026-10-25.* After razorbill rebooted, the engine logged `dagql persistence store marked unclean;
wiping and cold-starting`, and its cache went from 21.4 GB to 0. Docker kills a container 10 s
after asking it to stop, but the engine needs longer to stop.

| The same `test` job | Result |
| --- | --- |
| Before the reboot, new commit, cache warm | 56 s |
| After the reboot (engine killed at 10 s) | cache wiped; 249 s |
| Re-run straight after, same commit | 1 s: every step answered from the step cache |
| `docker stop -t 300` | clean stop in 21.6 s, no wipe on start; re-run 3 s from cache |
| Engine recreated with `--stop-timeout 80` | no wipe; re-run 3 s from cache |

The engine now gets 80 s (`stop_grace_period` in [`deploy/compose.yaml`](deploy/compose.yaml)). The
limit is 90 s, the point at which systemd kills Docker itself during a shutdown. This corrects E4.5
below: on v0.21.10 the step cache survives a restart, unless the stop was cut short.

## Installing Zig

*2026-10-25.* CI used to unpack Zig into each job's temporary directory. It now keeps the unpacked
tree in the tool cache and checks it against a pinned digest of all its files
([`.github/scripts/install-zig.sh`](.github/scripts/install-zig.sh)). Times are taken inside the
script, and the engine's disk I/O is sampled every second.

| | Time | Engine CPU | Read | Written |
| --- | --- | --- | --- | --- |
| Before: unpack every job | 9-16 s | 5.6 s | 37 MB | 214 MB (588 MB once flushed) |
| After: page cache cold | 9-10 s | 1.7 s | 309 MB | 0 |
| After: jobs back to back | 2-5 s | 0.6-1.0 s | 36-141 MB | 0 |

Hashing the tree's 19,505 files takes 0.3-0.9 s when they are in memory. When they are not, the
check is limited by reading 309 MB from the SD card, so the gain depends on how recently the last
job ran. The check stays: without it the script would trust a tree that another job may have
changed.

## Zig compiles its build runner first, on one core

*2026-10-26, Zig 0.17.0, on a laptop rather than razorbill: a Ryzen 5 PRO 4650U, 12 threads, on
battery.* Zig's build summary accounts for 7 s of a cold `test` job's Test step (compile 2 s, tests
5 s), but the step took 110 s, and `zig build test` itself 109 s real against 104 s user: one core,
the whole time. Sampling the host's processes every second shows where it goes. Before building
anything, `zig build` compiles Zig's own build runner (`maker`), and only then runs it.

| `zig build --help`, which only compiles the build runner | Time | CPU |
| --- | --- | --- |
| This repository, empty global cache | 121 s | one core (116 s user) |
| The same, warm | 0.02 s | |
| After a comment-only change to `build.zig` | 1.8 s | |
| A three-line `build.zig`, empty global cache | 108 s | one core |
| The same with `-fincremental` | 105 s | one core |
| Zig 0.14.1, the three-line `build.zig` | 12 s | |

A cold hello world takes 5-10 s on 0.17.0 and 3-4 s on 0.14.1, so it is the build runner, not
compiling in general.

**So the cost belongs to Zig, not to this project or the runner**, and it is paid once per Zig
version per global cache. In a job that cache is the `zig` cache volume, keyed by repository, by
whether the pull request comes from a fork and by the step user, so each of those pays it once per
Zig version, and again whenever the engine's cache is lost: it is part of the 249 s after the reboot
above. On razorbill's slower cores it is likely most of the 185 s Test phase in the first table,
though that run was not split this way. GitHub's runners start with no cache, so CI's test jobs
there and the release paid it on every run: the hosted test steps took 81-116 s, and a release
compiled it three times (the image twice from source, 175 s and 187 s; the binaries once more,
110 s). Both now call the compiler directly with `build.zig`'s module graph instead
(`.github/scripts/zig-test.sh`, `build-binaries.sh`): the tests took 14.5 s cold on the laptop
against 118.7 s through `zig build`. Only a pull request that touches the packaging still pays it,
once, to check that `zig build` makes the same binary.

## How many jobs a Pi can run at once

*2026-10-27 to 2026-10-30, zig-runner v0.14.0 to v0.18.0.* A stress harness, kept in a private bench
repository, drove a third pool of 6 runners on razorbill, beside the production pools on the same
engine, with a mix of `zig build test` and `uv sync` jobs. The Pi's memory, pressure and the
engine's cgroup were sampled every second. The harness stops a run, cancels its jobs and stops its
pool when the Pi falls under 1.5 GB of available memory or adds 1 GB of swap.

**Without a limit, four jobs thrash the Pi.** On v0.14.0, four `zig build test` jobs at once pushed
the engine to its 4 GB cap and into swap on the SD card, and razorbill thrashed for six hours,
until the engine was restarted. Runners now take a job only while the machine and the engine's
cgroup have room for it: the memory gate (#126), which reserves memory for every job that may start
before it shows.

| Run | Jobs | Result |
| --- | --- | --- |
| Churn, v0.16.0: tiny jobs as fast as GitHub hands them out, 10 min | 208 | 20.8 jobs/min; median 0.35 s from a job's end to its wrap-up, 0.78 s to listening again |
| Soak, v0.16.0: 4 jobs at a time, 1 GB a job | 144 in 93 min | all passed, run times flat (median 133-144 s); ended by a laptop reboot, not the Pi |
| The same soak, restarted on an idle engine | 5 | safety stop after 80 s: swap +1.07 GB |
| 1.5 GB a job, 15 min | 28 | all passed; 1.64 jobs/min |
| 1.5 GB a job, engine cap 5.5 GB, 15 min | 7 | safety stop after 3.5 min: 1.4 GB available |
| Learned estimates, v0.17.0, engine cap 5.5 GB, 15 min | 32 | all passed; 1.98 jobs/min |
| Learned from runs alone, v0.18.0, engine cap 5.5 GB, 60 min | 124 | all passed; 2.02 jobs/min; at least 1.8 GB available, swap +858 MB, pressure peak 8.9% |

The restart failed because two `zig build test` jobs, started 9 s apart, took the engine from 1.5 GB
to its cap. The gate had let them both through, as each was reserved 1 GB, but a job peaks at about
1.6 GB of the engine's memory within 45 s of starting. The steady soak had survived because its jobs
started at different times. With a 5.5 GB cap the engine held, and the Pi ran out of memory
instead: two such jobs leave razorbill about 1.5 GB.

From v0.17.0 the gate reserves for each job what jobs of its name have been seen to take: about 1.6
GB for `zig build test`, 0.1 GB for `uv sync`. On v0.17.0 the first `zig build test` runs had
shared the engine with another and were learned at 2.9 and 3.1 GB. A job is now learned from its
runs alone, and a run beside other jobs only bounds it from above (#144).

**So this Pi runs one `zig build test` at a time, safely, at about 2 jobs a minute in this mix.**
That is not a limit of the runner: a runner cannot know which job it will get before it asks for
one, so every runner that asks must have room for the heaviest. Light jobs wait behind a heavy one
(`uv sync` waited a median of 94 s to run for 10). Production asks far less: razorbill ran 40 jobs
in the 30 days before, all `zig build test`. The runner itself stayed between 24 and 38 MB over the
hour-long soak, and flat after the first 20 minutes.

## Against GitHub's hosted runner

*2026-10-31, zig-runner at main (after v0.19.0).* The same job, this repository's CI test steps
(checkout, Install Zig, format check, the tests), run alternately on GitHub's `ubuntu-latest` (4
vCPUs) and on zig-runner on a laptop (Ryzen 5 PRO 4650U, 6 cores and 12 threads, 30 GB, on the
balanced power profile), five times each per scenario, one job at a time. The laptop's runners keep
Zig's local cache between jobs (`RUNNER_ZIG_LOCAL_CACHE=true`). Times come from GitHub's API; the
job and its driver are in the private bench repository.

| Scenario (medians) | Hosted job | Hosted tests | zig-runner job | zig-runner tests |
| --- | --- | --- | --- | --- |
| Cold, each at its fastest: the compiler called directly (`zig-test.sh`), Zig's cache empty | 49 s | 36 s | 35 s | 31 s |
| Cold, `zig build test` on both, Zig's cache empty | 148 s | 134 s | 131 s | 128 s |
| A new commit, each as its CI runs it | 46 s | 36 s | 31 s | 27 s |
| The same commit again | 54 s | 41 s | 1 s | 0 s |

- **zig-runner is faster in every scenario**: 29% cold, 11% when both take `zig build`'s slow path,
  33% on a new commit, and about 50 times on the same commit again, where every step replays from
  the step cache.
- **"Set up job" takes about 1 s on both.** The first job after a new runner image took 27 s, while
  the engine built the job's base container again; that run is left out.
- **Install Zig takes 1-2 s against 7-10 s,** as Zig stays in zig-runner's tool cache.
- **`zig build test` cold** spends most of its time compiling Zig's build runner on one core: GitHub
  calls the compiler directly on its own runners for that reason (`zig-test.sh`). On a new commit,
  with the caches warm, the direct path is no faster on zig-runner (28 s against 27 s for the
  tests), so zig-runner keeps `zig build test`.
- **GitHub's times vary more:** its cold `zig build test` took 110-158 s across five runs, the
  laptop's 131-132 s.
- **Waiting for a runner** took 1 s against 2 s.

This is one job at a time on a quiet machine. GitHub runs as many jobs at once as a plan allows; a
laptop runs as many as its cores and memory do, and its lead shrinks as they fill.

On 2026-10-30, before the fair cold scenario existed and with Zig's local cache off, the cold
`zig build test` case was a tie (136 s against 137 s).

A step whose script names a run-specific variable (`GITHUB_RUN_ID`, `GITHUB_SHA` and the rest of
`volatile_env` in `runner/src/dagger.zig`) is never replayed, and the check reads the script's text,
comments included: the first attempts at the third scenario replayed nothing because a comment named
the run's ID.

On razorbill the same new-commit job takes about 76 s, against 41 s on GitHub's runner: the Pi, not
the runner, is the difference (the runner's own work is 0.11 s of CPU a job, see above).

## Position-independent executable

*2026-11-01, zig-runner at main (after v0.23.0).* The release's binaries became static
position-independent executables (README, "Hardened binaries"), which the rule allowed only if it
cost no more than about 3%. Measured on the laptop (Ryzen 5 PRO 4650U, on AC and the balanced power
profile, sampled every 2 s throughout; not a quiet machine: load average 5-6 from other work), both
builds ReleaseSafe for x86_64-linux-musl as the release builds them, run alternately so drift falls
on both.

**The runner's hot paths** (`.github/scripts/hotbench.sh 21 10`, `runner/tools/hotbench.zig`): 210
timed rounds per benchmark and build, from 10 runs of each binary in turn. Milliseconds a round;
"change" is the PIE median against no-PIE's.

| Benchmark (one round) | no-PIE median (IQR) | PIE median (IQR) | Change |
| --- | --- | --- | --- |
| Expressions: 10 workflow expressions and an interpolation, 4,000 times | 90.6 (84.8-99.9) | 91.3 (85.2-97.7) | +0.9% |
| YAML: ci.yml and release.yml parsed, 200 times | 51.8 (48.2-55.4) | 49.7 (46.1-53.2) | -4.1% |
| HPACK: RFC 7541's request and response examples, a decoder each, 16,000 times | 116.4 (107.8-123.3) | 113.9 (106.8-122.0) | -2.2% |
| hashFiles() glob: 4 patterns over a 5,500-entry in-memory workspace, 6 times | 93.0 (88.7-97.6) | 94.6 (88.1-101.8) | +1.7% |
| SHA-256 of 32 MiB | 144.9 (135.4-154.6) | 146.8 (133.1-159.8) | +1.4% |

**The test suite** (`zig-test.sh`, compiles cached, so this is the tests running; the native
backend's root tests not included), five runs of each, alternately: no-PIE median 45.6 s
(44.9-47.5 s), PIE 44.4 s (44.2-45.3 s), 2.6% faster.

- **PIE costs nothing measurable.** No median moved by more than 1.7% the slow way, each well
  inside its own interquartile range (5-10% wide on this machine), and two of the five moved the
  other way. On x86_64 Zig's code already addresses its data relative to the instruction pointer; a
  static PIE adds only its own relocation, once, at startup.
- **The first run is not in the table:** the battery was at 18% and the laptop had moved itself to
  the low-power profile (not by hand). Its medians agreed (+2.4% to -5.6%), with wider spread.
- The binaries grew by 0.6% (x86_64, 3,533,136 to 3,554,000 bytes) and 1.6% (aarch64), for the
  relocations.

## Earlier measurements

These come from the study in
[zig-actions-runner](https://github.com/Lementknight/zig-actions-runner/tree/7641a69/docs), where
the runner was developed. The IDs and verdicts are those of its claim registry,
[CLAIMS.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/CLAIMS.md). There,
*verified* means the claim was repeated, with a control, and *under-powered* means it is a real
reading taken too few times to rule out noise.

| ID | Finding | Verdict |
| --- | --- | --- |
| E4.1 | An empty job takes 2-4 s and 0.1 s of engine CPU | verified |
| E7.3 | A job's floor is GitHub's protocol, not the engine: 2-4 s a job against 0.6 s a session | verified |
| E7.1 | Overhead per step: raw overlayfs 17 ms, Dagger 60-62 ms | under-powered |
| E7.5 | 100 steps grow the engine's heap by 279 MB, mostly garbage; the live set is a few hundred MB | verified |
| E7.7 | `GOGC=400` saves about 15% of engine CPU on a job of 40 steps (0.90 s of 5.93 s) | verified |
| E4.3 | Uncapped, the cache grew to 67 GB in 17,000 snapshots and its inode cache crowded out the page cache | under-powered |
| E4.4 | A fresh engine did the same work about 15× faster: chi job 5 s against 23-55 s | under-powered |
| E4.5 | Every engine restart empties the step cache | verified then; corrected above |
| E4.7 | A restart keeps every cache volume: toolchains, Go modules, uv's cache | verified |
| E6.1 | Each cache volume is its own filesystem, so no hardlink can cross into it | verified |
| E6.2 | A warm `uv sync` takes 27.0 s from a cache volume against 0.2 s on the workspace's filesystem | under-powered |
| E6.3 | With uv's environment in its cache volume, `uv sync` on a new ref drops from 28.6 s to 9.2 s | under-powered |
| E6.6 | hugo against a hosted runner with its cache on: 9 s against 151 s on a new branch | under-powered |
| W.5 | "sqlalchemy installs faster here than on a hosted runner": the hosted runner is faster, 2.2 s against 3.1 s | refuted |
| E6.4 | "A warm `uv sync` is faster than GitHub's": the hosted runner is faster, 0.011 s against 0.015 s | refuted |
| S.4 | CI here is I/O-bound end to end: CPU 85-97% idle-waiting, at most 3 runnable while 26 were blocked | verified |
| S.2 | A forced-copy install takes 2.7× longer with three at once: 24.6 s alone against 66.6 s | verified |
| S.3 | flask's tests take 1.45× longer with three at once: 4.36 s against 6.30 s | verified |
| S.5 | No I/O scheduler is measurably better on this card | no effect found |
| S.6 | The SD card intermittently drops to a quarter of its write throughput, with 135 ms stalls | under-powered |

Together they explain the numbers above. The runner is cheap. The engine's fixed cost per step is
small next to real work. What decides a job's time on this machine is whether the engine's caches
survive and how fast the SD card is.
