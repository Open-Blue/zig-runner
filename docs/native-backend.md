# The native step backend

The plan for running a job's steps in the runner itself, with Linux namespaces, overlayfs and
chroot, in place of the Dagger engine (BuildKit). It is a living document: each phase updates its
section when it lands and adds what it taught to "Learnings" at the end.

## Goal and decision

Today every step is a `withExec` in a Dagger session (`dagger.zig`, `dagger/`). The engine costs
about 240 ms of wall time and 290 ms of CPU per cold trivial step, and about 95 ms per step
replayed from its cache. A prototype that runs steps itself (runner-bench
`tools/native/nstep.c`, with its design note `DESIGN.md`) measured 12 ms per cold trivial step and
0.04 ms per replay on the laptop.

**Decision: build the full native backend, with a hybrid as the fallback.** "Full" means native
covers everything Dagger does for this runner today: run steps, checkout, the step cache and
replay, images, cache volumes, trust scopes, the memory gate, services and Docker actions, with
Dagger retired at the end. "Hybrid" is where we stop if the measurements say the rest is not worth
it: native for the jobs it covers, Dagger for the others, chosen per job.

The project rule holds throughout: native ports, not dependencies. The OCI pull, the layer store
and the sandbox are Zig in this repository. No runc, containerd, skopeo or fuse-overlayfs at
runtime. External tools may serve as test oracles only, as Node and .NET do elsewhere.

## Architecture

### The Backend boundary

The runner has two halves that today live together in `dagger.zig`:

- **Job orchestration**: evaluating expressions, conditions, `continue-on-error` and timeouts
  (`Evaluator`, `runStep`); the job log, markers, masking and workflow commands (`JobLog`,
  `redact`); file commands and outputs (`Exec.collect`); results and the observer.
- **Step execution**: building the base container (`set_up.zig`), running one script in it with
  its env and mounts (`Exec.execScript`), and reading back the exit code and the step's combined
  file-command file.

The boundary goes between them. A backend is asked for two things:

1. **The job's base**: the filesystem every step starts from (the provisioned image, the workspace,
   the step user, the event file) and its environment (the image's, the runner's `GITHUB_*`
   defaults, the job's `env:`).
2. **One exec**: run the `sh -c` script that `scripts.stepScriptFc` builds, on top of what the
   previous exec left, with the env the previous steps' `GITHUB_ENV` and `GITHUB_PATH` produced;
   stream its output lines into `JobLog` as they are printed; return the exit code and the
   contents of `/github/file_commands/all_<n>`.

Everything above that, including the script text itself, stays shared. Both backends run the same
script, so the markers, the file commands, `exec 2>&1`, the shells and their arguments, the script
file and the `env -u ...` command are byte-identical across them. The Dagger implementation is what
`dagger.zig` does today, unchanged. The native implementation lives in `runner/src/native/`.

### The knob

`RUNNER_BACKEND=dagger|native`, default `dagger`.

With `native`, each job is checked before it starts (`native.supports`). A job that uses something
the native backend cannot do yet runs on Dagger, and "Set up job" says so in one line, naming the
first reason: "This job runs on Dagger: native steps do not support `services:` yet". So the
migration is a hybrid by construction, and each phase shrinks the list of reasons. The choice is
per job, never per step: switching mid-job would mean exporting native layers into Dagger at each
switch and splitting the step cache's key chain across two stores (DESIGN.md, "Per job").

### Running with no engine

`RUNNER_ENGINE=none` (or `--engine=none`), with `RUNNER_BACKEND=native` (any other backend is a
configuration error, `EngineNoneNeedsNative`), is a runner with no Dagger engine at all. It is a
setting, not a detection: a runner that noticed the engine's absence and changed what it does would
turn a stopped engine, which today makes a job wait, into failed jobs nobody asked for, so the
default (`direct`) behaves exactly as before. With `none`:

- **Start-up.** No engine is looked for. The engine's pre-warm is not run, so there is no socket
  to poll every 5 s and no lock on the engine's directory ("pre-warm: RUNNER_ENGINE=none, there
  is no engine to warm; warming the native store"). The native store is warmed instead, in the
  background, once, after the runners start listening (`loop.Warmer.onceNative`,
  `dagger.warmNative`, `Backend.warm`; `RUNNER_PREWARM=false` turns it off): the default image's
  provisioning (about 25 s on the laptop, which the first job on an empty store otherwise pays
  while the others wait for it) and the Zig cache seeds (127 s on the laptop, paid by the first
  job that runs Zig), by the code and under the locks a job uses, so a job that comes while it
  runs waits for the piece being made and one that comes later finds all of it. (The image's
  pull is already done before start-up, by the probe below.) It runs in a job directory and
  cgroup of its own, so `memory.max` and `pids.max` hold it, and through the memory gate as a job
  of its own (the pool's extra slot); a failure is said ("pre-warm failed ...") and the first
  job makes what it needs, as it always did. A native pool with an engine warms the native
  store too, before the engine's.
  `RUNNER_PREWARM=before-listen` (`--prewarm=before-listen`) makes the native warm finish
  before any runner registers or polls (`loop.Warmer.beforeListen`, called by `pool`), so a
  machine added for scaling takes jobs only once warm: on razorbill (Pi 5, empty store) the
  warm takes 209 s, a Zig job sent during it took 284 s and one after it 6-13 s. Nothing registers
  before the pool's runners start, so no runner is held online and idle meanwhile. A failed warm is
  said and the runners listen; a warm over 15 minutes (`before_listen_max_ms_default`) is
  cancelled, said, and the runners listen; a stop ends the wait with no "ready". The engine's warm
  (Dagger) keeps its background behaviour. No systemd or compose readiness signal is involved
  (no `Type=notify` or healthcheck exists), so "started" still means the process is up. The memory gate has no engine source (as `RUNNER_ENGINE_CGROUP=none`): it holds on the
  machine and on each job's cgroup, and logs nothing about an engine cgroup. The silence-timeout
  line is not printed.
- **Jobs.** A job native can run runs natively as always. One it cannot (`Backend.unsupported` or
  `usable` give a reason, or the set-up falls back) fails before any step, in "Set up job", with
  "this job needs the Dagger engine, and this runner has none (RUNNER_ENGINE=none). This job runs on
  Dagger: <the reason native gave>." It does not start a `dagger` child or connect to a socket.
- **Start-up.** The native probe runs before the runner registers (`Backend.reprobe`, which
  forgets the five minutes of back-off that would otherwise answer from memory). A failure may be
  transient (nftables busy, a module not loaded, no network yet for the image it pulls), so it is
  tried five times with pauses doubling from 5 s (about 75 s). A machine that still cannot run
  native steps exits 4 with "native error: RUNNER_ENGINE=none, and native steps cannot run here:
  <reason>", a code `zig-runner.service` restarts on (`RestartPreventExitStatus=1 2` does not
  list it) and compose's `restart: unless-stopped` too, so it starts by itself once the machine
  can, and until then refuses again, clearly, every 10 s plus the retries. A bad native
  configuration (a store path that cannot be resolved) is a config error, exit 1. Without the
  probe, every job in its back-off would fail with the reason. `RUNNER_DAGGER_NESTING=true` with
  `none` is a configuration error (`EngineNoneNoNesting`): a step could never get its engine.
- **Deploy.** `deploy/compose.engineless.yaml` layered over `compose.yaml` drops the engine service
  and its volumes and the runner's `depends_on`, and gives the runner what the native backend needs
  ("Under `deploy/compose.yaml`", P1): `privileged: true`, `network_mode: host`, `cgroup: private`
  with `RUNNER_NATIVE_CGROUP=self`, the store on a `native-store` volume
  (`RUNNER_NATIVE_STORE`) and the host's `/run/zig-runner`. Checked with `docker compose config`
  only; a job has not been run through it.

What still needs an engine: steps that use the Dagger engine (`RUNNER_DAGGER_NESTING`, which `none` refuses), and
whatever native lists as unsupported at the time. This is the list the fallbacks are being retired
from; a job on it fails fast instead of waiting.

## Phases

Each phase lands behind the knob with the default unchanged, its tests green, its measurements in
the pull request, and its learnings below. "Exit" is what must be true to call the phase done.

### P1: run-only jobs

Jobs whose steps are all `run:` scripts (and the built-in checkout, if it is small to port), on the
default image, with no `container:`, `services:`, `uses:` actions, output keys or cache volumes.

- Rootfs: the provisioned default image, exported to a host directory once by the existing Dagger
  path until P3's native pull.
- Per step: an overlay on the previous step's layer, fresh mount, PID, UTS and IPC namespaces,
  chroot, the step's env and shell as the Dagger path builds them.
- File commands, masking, live log streaming with timestamps, exit codes, `continue-on-error`,
  `if:`, cancellation and timeouts through the shared code.
- Rootless through a user namespace when the runner is not root.
- Exit: a parity test runs the same run-only job through both backends and compares results and
  log lines; existing tests pass unchanged.
- Measure: wall time per cold trivial step, against Dagger's ~224 ms on the laptop.

**Status: landed (behind the knob), reviewed, and hardened.** What it covers, as built:

- `runner/src/native/Backend.zig` is the job side: the fallback decision (`unsupported`), the
  machine's capability (`usable`, probed once, and again five minutes after a failure), the job's
  directory, slot, ids and network, the base, the container's env between steps, `execScript`, and
  the checkout. `runner/src/native/sandbox.zig` is one step's sandbox: the runner's own binary
  started as `zig-runner native-step`, reading the step's spec as one line of JSON on stdin (never
  on a command line: it holds the step's secrets), with stdin kept open as its lifeline.
  `runner/src/native/net.zig` is a job's network, over rtnetlink.
- The boundary in the shared code is three lines: `dagger.run` sends a job native can run to
  `runNative`; `runSteps` asks the native backend for the base instead of `baseContainerId`; and
  `Exec.execScript` hands each exec to `Backend.execScript`. The Dagger path is unchanged, and so
  are its tests.
- Covered: `run:` steps with any shell, `defaults.run`, step and job `env:`, expressions, `if:`,
  `continue-on-error`, `timeout-minutes` and cancellation (the same `Watch`, with GitHub's
  SIGINT, SIGTERM and kill: see "Stopping a step"), every file command, `::add-mask::` and the other workflow commands,
  problem matchers (read from the layers, relative to the working directory), step summaries,
  `id-token: write`, secrets in env, in scripts and in working directories, and the built-in
  checkout, submodules included (git in the job's image, then the same step script Dagger's
  checkout runs). `submodules: true` fetches the first level and `recursive` all, as GitHub's
  checkout does (Dagger's path always recurses), each to the commit the tree records, as shallow as
  `fetch-depth`, with `git@<host>:` read as HTTPS; the flags are in the step's script, so in its key. With tags (`fetch-depth: 0` or `fetch-tags`)
  the key holds a digest of the top repository's tags, which move with the commit staying; a
  submodule's tags are not listed (its URL is known only once fetched), so a checkout with both is
  not replayed at all. Not handled: a submodule's clone fetches its own tags whatever `fetch-tags`
  says, so a tag added later to a submodule's same commit is stale in the replay of any checkout
  with `submodules:` that has no tags of its own to fetch. That rarely matters to a build, and
  gating every submodule checkout would cost its replay.
- Falls back to Dagger, with "This job runs on Dagger: ..." in "Set up job": a job the runner
  does not vouch for (`trust.vouches`, for `--exec-job` too), a rootless runner unless
  `RUNNER_NATIVE_ROOTLESS=1`, a job container's `ports:`, a `volumes:` entry the native job does not carry out
  (a host path it does not allow fails instead), or an `options:` flag the native job does not carry out (all below, "Job container options"), `services:`
  on a rootless runner or with an image given by an expression (native since P6, below, their
  images pulled by P3), JavaScript and local `uses:` actions (P7, `actions.preload`), remote `uses:` actions in an
  image with no git to fetch them with, `docker://` images
  that cannot be pulled or run as a non-root `USER` (P7), Dagger in steps
  (`RUNNER_DAGGER_NESTING`), and a
  machine whose probe fails (no user namespaces, nftables refusing the jobs' rules, no default
  route, the jobs' ids taken on the host, the jobs' subnet overlapping a route of the host's). A
  failed probe is tried again after five minutes, not kept for the process's life. (Until P3
  also: no rootfs configured, `container:` and a custom image.)
- Off on native, as caches: output keys. Results do not depend on them. (The step cache was off
  in P1; P2's layer store gives it. The package caches, uv's environment in its cache, and Zig's
  local cache and seed came with P4.) The tool cache is never off: a step may install into it, and
  the step user cannot make it under /opt. It is the job's `toolcache` volume (P4), bound at
  `/opt/hostedtoolcache` and owned by the step user as Dagger mounts it in every job; a job with no
  volumes (package caches off, or no repository) has the base make it instead (#274), and what a
  step puts there is then in its layer.
- "Set up job" says what the job got: "Native steps: ids 0-65535 are host ids N-N+65535, and the
  job's network is its own (10.211.1.x on zr0)", or the rootless warning.

#### Isolation: what P1 provides, and what it does not

On a root runner, each step runs:

- in a **user namespace of the job's own**, ids 0-65535 mapped to a range of host ids no host user
  has (`RUNNER_NATIVE_SUBID_BASE`, by default 1,900,000,000 plus 65,536 per slot). The default
  lies past systemd's container range (systemd-nspawn's private users and nsresourced's,
  524288-1879048191) and the last slot's ids (up to 1,916,383,999), and the cache volumes' range
  after them (P4, up to 1,916,449,535), stay below its foreign range (from 2,147,352,576) and
  below 2^31, which some tools take as signed. The probe refuses a base
  below 100,000, a range past 2^32, and a range that overlaps one in /etc/subuid or /etc/subgid
  or holds an id from /etc/passwd or /etc/group (users only a directory service knows are not
  seen; the 100,000 floor is above their usual ranges). The step's root and its uid 1001 are
  nobody on the host: a breakout, sudo or a setuid program gains no host privilege. A full range
  is mapped, so apt's `_apt`, `chown` and `tar` with owners work. The rootfs is seen through an
  idmapped mount (Linux 5.19), not copied per range.
- in a **network namespace of the job's own** (all its steps share it): its own `lo` and port space,
  a veth on the runner's bridge `zr0` (`RUNNER_NATIVE_SUBNET`, by default 10.211.0.0/16 with the
  bridge at 10.211.0.1 and slot n's job at 10.211.1.(n+2); not podman's 10.88.0.0/16 or Docker's
  ranges, and refused when it overlaps a route of the host's), a default route out through NAT. Two
  jobs can both listen on :5432. The job reaches nothing on the host: not its 127.0.0.1, and not a
  service on any of its addresses (the bridge's included), since `INPUT` drops whatever comes from
  `zr0` and is not a reply. Nor does anything reach the job that it did not ask for: `OUTPUT` and
  `FORWARD` drop what goes to `zr0` and is not a reply (added in P6, when services began to listen
  there). Jobs cannot reach each other: each veth is an isolated bridge port
  (`IFLA_BRPORT_ISOLATED`), and `FORWARD` drops traffic from `zr0` back to `zr0`. IPv6 is off on the
  job's `eth0` and on the bridge, so no link-local address slips past those IPv4 rules (`lo` keeps
  its ::1). Ports below 1024 and ping work without capabilities on the host's
  (`ip_unprivileged_port_start=0`, `ping_group_range`, set in the job's namespace only). Its
  resolver is a resolv.conf of its own, made from the host's as Docker makes a container's on its
  default bridge (`net.Resolver`): the loopback's nameservers left out (systemd-resolved's
  127.0.0.53 is the host's loopback; its upstream list, `/run/systemd/resolve/resolv.conf`, is
  used behind its stub) and IPv6 ones too (the job has none), search domains and options kept, and
  Google's 8.8.8.8 and 8.8.4.4 when nothing else is left, as Docker and BuildKit do ("Set up job"
  says so). The jobs' rules let UDP and TCP to port 53 of those nameservers through, out of
  whichever interface the host routes them by, and on to the host itself when one is its own
  address: a resolver that is not behind the default route answers a job (Tailscale's MagicDNS,
  100.100.100.100 through `tailscale0`, on razorbill, where jobs had no DNS before this), and
  nothing else on that network is reached. The resolver is read again for each job and the rules
  follow it when it changes.
- in **mount, PID, UTS and IPC namespaces** of its own, with the overlay as `/` by `pivot_root`
  and the host's root detached (no chroot to climb out of), a /dev of six nodes plus devpts, shm
  and mqueue, /proc with runc's masked paths (`kcore`, `keys`, `timer_list`, `sched_debug`,
  `interrupts`, ...) and read-only ones (`/proc/sys`, `sysrq-trigger`, `irq`, `bus`, `fs`),
  cloned from the step's own /proc with every mount under them, and /sys read-only with every
  mount under it. A mask or a read-only path the kernel has but that cannot be applied fails the
  step's set-up; only a path the kernel does not have is skipped.
- with **Docker's default capabilities** (the bounding set cut to them, ambient cleared),
  **no_new_privs** for root steps and rootless ones (not for the runner user on a root runner,
  whose sudo works as on GitHub and reaches only the job's own root, within the same capabilities
  and filter), and a **seccomp filter**: P1's refused Docker's default profile's dangerous calls
  (a deny list); since P5 it is Docker's allow list itself ("P5" below).
- with a script that holds a secret written to a **tmpfs of the step's own** and bound at its
  path over an empty file, so the secret never reaches the store's disk (the empty file goes
  when the step ends).
- with every path inside the overlay resolved inside it (`openat2(RESOLVE_IN_ROOT)`), by the
  helper and by the runner, so a symlink a step plants never leads them to the host's files.

- in a **cgroup v2 of the job's own** (since P4) with `memory.max` and `pids.max`, under a parent
  that bounds all jobs together, with no swap ("Bounded jobs" below). A job that cannot have one
  does not run natively unless the operator accepts that with `RUNNER_NATIVE_CGROUP=none`.

What it does not provide yet:

- **Resource limits on a rootless runner without delegation.** P4's cgroup needs root or a
  delegated cgroup (`RUNNER_NATIVE_CGROUP=self`); without one a job goes to Dagger, or fails saying
  so with `RUNNER_ENGINE=none`, unless `RUNNER_NATIVE_CGROUP=none` accepts it. A job the runner
  does not vouch for never runs without one (P5).
- **Rootless runners.** Only one id is mapped and steps share the host's network: off unless
  `RUNNER_NATIVE_ROOTLESS=1`, for tests and the laptop. A rootless job network needs a userspace
  stack (a Zig port of the parts of pasta or slirp4netns it needs), and full ids need
  `newuidmap`.
- **Kernel attack surface.** Steps run on the host's kernel, as containers do; a kernel bug is a
  breakout.

#### Running it

```
RUNNER_BACKEND=native              # default dagger
RUNNER_NATIVE_ROOTFS=/var/lib/zig-runner/rootfs   # optional since P3; absolute
RUNNER_NATIVE_STORE=/var/lib/zig-runner/native    # default as root
RUNNER_NATIVE_SUBID_BASE=1900000000               # default; at least 100000
RUNNER_NATIVE_SUBNET=10.211.0.0/16                # default; a prefix of 8 to 23 bits
RUNNER_NATIVE_STORE_MAX_MB=10240                  # default; the layer store's cap (P2)
RUNNER_NATIVE_VOLUMES_MAX_MB=16384                # default; the cache volumes' cap, 0 for none ("Eviction")
RUNNER_NATIVE_IMAGES_MAX_MB=8192                  # default; images', rootfs' and seeds' cap, 0 for none ("Eviction")
RUNNER_NATIVE_MIN_FREE_PCT=10                     # default; the disk's floor, 0 for none ("Eviction")
RUNNER_NATIVE_ROOTLESS=0                          # default; 1 for a rootless runner
RUNNER_NATIVE_CGROUP=                             # default: /sys/fs/cgroup/zig-runner as root;
                                                  # `self`, a path, or `none`: no limits at all
RUNNER_NATIVE_MEMORY_TOTAL_MB=                    # all jobs' together; default a third kept for
                                                  # the machine ("Bounded jobs"); 0 for no limit
RUNNER_NATIVE_MEMORY_MAX_MB=                      # each job's; default 2/3 of the total; 0 for no
                                                  # limit
RUNNER_NATIVE_SWAP=false                          # default; true lets jobs swap
RUNNER_NATIVE_PIDS_MAX=8192                       # each job's, default, and 4 times it for all
                                                  # jobs; 0 for no limit
RUNNER_NATIVE_HASHFILES_MEMORY_MB=                # default min(1 GiB, MemTotal/8), for all jobs'
                                                  # hashFiles() together; 0 for no limit
RUNNER_NATIVE_HASHFILES_TIMEOUT_S=120             # default, GitHub's; 0 for no limit
RUNNER_NATIVE_MEM_PER_JOB_MB=256                  # default; the memory gate's reservation for a
                                                  # native job not learned yet (P4); 0 for none
```

**Bounded jobs (#367).** All native jobs under one parent cgroup stay under a limit written on that
parent, with no setting and no host tuning, and each job under a limit of its own:

| Machine | Kept for the rest | All jobs (`memory.max` on the parent) | One job |
|---|---|---|---|
| 8 GiB Pi | 2.7 GiB | 5.3 GiB | 3.6 GiB |
| razorbill with `self` under `MemoryMax=90%` (7.09 GiB) | 2.4 GiB | 4.72 GiB | 3.15 GiB |
| 16 GiB | 5.3 GiB | 10.7 GiB | 7.1 GiB |
| 30 GiB laptop | 10 GiB | 20 GiB | 13.3 GiB |
| 128 GiB | 12 GiB | 116 GiB | 77.3 GiB |

- **Why these.** A third of the machine is kept, at least 2 GiB and at most 12 GiB, and jobs get at
  least half whatever that says. Three quarters per job, as it was, left a laptop's desktop 7.5 GiB
  beside one job, and nothing at all beside two. One job gets two thirds of the total, so a
  runaway still leaves its neighbours a third. A job that needs more than this fails where it
  passed before: its step says which limit and which setting.
- **razorbill, worked through.** Under `self` its unit's `MemoryMax` of 7608549376 bytes is the
  machine: 5.07e9 for all jobs (4.72 GiB), 3.38e9 for one (3.15 GiB). Its build reaches about 2.4 GB
  of anonymous memory, so one has about 0.9 GiB to spare. Two at once are 4.8e9 of 5.07e9, which is
  tight; a third is killed, where three used to swap.
- **"The machine"** is `MemTotal`, or the tightest `memory.max` above the parent where the runner is
  in a container or a slice with a limit of its own, which `MemTotal` does not show. The parent's
  own is left out, since it is written from this number. A third of that is kept as of any machine,
  so `MemoryMax=4G` on a named path gives jobs 2 GiB; `RUNNER_NATIVE_MEMORY_TOTAL_MB` says otherwise.
- **What the total does not cover.** Other parents, below, and anything else on the machine: above
  all a Dagger engine beside the jobs, in a cgroup of its own. On razorbill the bench pool's 4.72 GiB,
  the engine's 4 GB cap and the machine's baseline add up to more than its RAM, so a global OOM
  stays reachable on a machine shared with an engine. The total does not take it off: an engine's
  cap is the gate's to find, may be absent, and taken off here would leave a job on razorbill about 1.1 GiB,
  under its build. Where that matters, set `RUNNER_NATIVE_MEMORY_TOTAL_MB` or cap the engine lower.
- **Swap.** `memory.swap.max` is 0 on the parent: page cache is reclaimed at a limit, anonymous
  memory stays in RAM, and a job past its limit is killed instead of taking the machine into swap
  death. A swapped-out job also looks small to the gate, which held `memory.high` down
  (`Admission.growHigh`) on the job razorbill's compressed swap slowed for an hour.
  `RUNNER_NATIVE_SWAP=true` gives swap back, as a kernel without swap accounting does ("Set up job"
  says which); the memory limits hold either way.
- **`memory.high` goes with swap.** With nothing to reclaim anonymous memory into, `memory.high`
  does not slow a job, it stops it, and nothing kills it: at a 50 MiB `memory.high` under a 300 MiB
  `memory.max`, swap 0, a hog reached 50 MiB in 7 s and not 55 in the next 100, with 1328 `high`
  events and no OOM. The gate's `growHigh` stops at the `MemAvailable` floor, so two unlearned builds
  on razorbill could have held each other until `timeout-minutes`. So where jobs cannot swap
  (`cgroup.canSwap`) no `memory.high` is set, `memory.max` decides, and "Set up job" says so. What
  goes with it: a job that outgrows its estimate is no longer held to it for its neighbours' sake.
  They are protected by its `memory.max` and by the total instead, and the gate by `MemAvailable`,
  which falls as the job grows, and by reserving more: a job not learned yet reserves the most any
  native job took, up to its own `memory.max`, while it ramps up (`Gate.noHigh`), since nothing
  holds it to 256 MB. Until a heavy job has finished once there is nothing to go on, so a first
  burst of heavy names still comes in at 256 MB each, under their limits. What is gained: a job past its estimate runs at full speed or fails,
  it is learned at what it really took on the first run, not by doubling, and page cache is
  reclaimed at the limits or under pressure, as `MemAvailable` counts it. With swap, all of #306 stands.
- **Processes.** `pids.max` on the parent is four jobs' (32768 by default), and neither it nor a
  job's goes above the kernel's 4194304.
- **The operator's numbers win.** `RUNNER_NATIVE_MEMORY_TOTAL_MB` sets the total, and the default job
  is two thirds of it. An explicit `RUNNER_NATIVE_MEMORY_MAX_MB` above the default total raises the
  total with it, and `0` leaves all jobs without a limit too, unless a total is set. A total below a
  job's limit holds: limits are hierarchical.
- **Several runners.** The default total depends on the machine alone, so every runner sharing a
  parent, which root runners do by default (`/sys/fs/cgroup/zig-runner`), asks for the same numbers,
  and their jobs together stay under one bound, whichever started last. They must use the same
  settings, as they must the same `RUNNER_NATIVE_SUBNET`. With a job's cgroup under the parent, in a
  step or between steps (`nr_descendants`), a runner set otherwise only tightens, down to what is in
  use (`memory.current`, `pids.current`), or puts a limit on where there was none, as in a rolling
  upgrade beside an older runner's job: a lower `memory.max` over what jobs hold kills them there
  and then, and `max` from a pool with `RUNNER_NATIVE_MEMORY_MAX_MB=0` takes the bound from another's.
  Otherwise what stands is kept, and "Set up job" and the log say so and give the limits really in
  force. A job the runner does not vouch for does not run under no total. A hand writing a lower
  value on the parent still kills what is over it.
  What does not hold: runners with **different parents**, such as units each with
  `RUNNER_NATIVE_CGROUP=self`, get a bound each, and cannot see each other. Give them one parent (a
  path), or a slice with its own `MemoryMax=`, which then counts as the machine for all of them.
- **A named parent stays the operator's.** With `RUNNER_NATIVE_CGROUP=<path>` the jobs go in
  `<path>/jobs`, which is the runner's and has all jobs' limits. The path's `memory.max` and
  `memory.swap.max` (a slice's `MemoryMax=`) are not written, and hold over everything under it.
- **The memory gate** (`admission.zig`) still decides on `MemAvailable`, and does not know the total.
  On a 30 GiB machine it may let in a job when the parent is full and the machine is not; the parent
  then kills the largest process under it.
- **An OOM kill says which limit it came from** in the step's log: the job's, all jobs', or the
  machine's or one above the parent, told apart by where `memory.events` counts `oom`.
- **An OOM kill takes every process of the steps, not one** (#378). The steps run in a `steps` child
  of the job's cgroup with `memory.oom.group` 1, so when the job's `memory.max` runs out the kernel
  kills the whole group (the step's shell, its helper and the hog, not only the largest process,
  which left the rest of the step running in a damaged state), and the step ends 137. The flag is
  on the child, not the job, because services and the ports' relay run in a `services` child
  without it: on the job it would take a database with the step that overran, and an `always()`
  cleanup step would find it gone. A service that is the victim is killed alone, as before. The
  job's `memory.max`, `memory.high`, `memory.peak` and `memory.events` are the job's, counting both
  children, so the limits, the gate's reading and the "reached its memory limit" line (whose count
  is now the whole group) are unchanged. The flag is best effort: a kernel without it (before
  Linux 4.19) leaves the job in one cgroup, bounded by the same limits. GitHub's runner has no
  equivalent.
- **Job processes prefer to die before the runner** (#378). Each step's helper sets
  `oom_score_adj` to 500 before it forks, which its children inherit, so a machine-wide OOM picks
  a job's process over the runner's. GitHub's runner does the same (`ProcessInvoker.cs`,
  `WriteProcessOomScoreAdj`: 500, or `PIPELINE_JOB_OOMSCOREADJ` when it is -1000 to 1000). Here
  the override is read from the step's environment (workflow or step `env:`), and it is never
  below the runner's own value: lowering needs CAP_SYS_RESOURCE, which a root runner's helper
  has, and a workflow must not make its processes the last the kernel kills. Raising needs no
  privilege, and neither seccomp (installed later, in the step's init) nor no_new_privs stops a
  write to /proc. It is best effort and never fails a step. The ports' relay is not set.
- **A job that cannot be bounded is refused**, by default: a rootless runner without delegation, or
  a parent that cannot be made or limited. It goes to Dagger, whose engine holds it, or fails saying
  why with `RUNNER_ENGINE=none`. `RUNNER_NATIVE_CGROUP=none` is the operator accepting the risk, and
  "Set up job" then says the job runs UNBOUNDED. A runner in a container with a memory limit of its
  own is bounded by it, jobs and runner alike, and `none` is the setting for it where no cgroup can
  be written.
- **A root runner in a container finds its own place.** The default parent cannot be made below a
  root that holds processes. A root runner at the root of its cgroup namespace then does what
  `self` does, without being told: only the namespace's own processes move. Any non-initial cgroup
  namespace qualifies, not only a container's (`unshare --cgroup` with cgroup2 mounted in it): the
  initial one's root may hold processes and still give controllers. That needs a
  writable cgroup mount: Docker's is read-only without `privileged: true`
  (moby's `daemon/oci_linux.go`: `writableCgroups := c.HostConfig.Privileged`), whatever `cap_add`
  says, or with `security_opt: [writable-cgroups=true]` (checked on Docker 29.9, with
  `cap_add: [SYS_ADMIN]` alone reading `ro` and with the option `rw`). Without it, the job is refused
  with that reason.
- **Not a per-process limit in place of the cgroup.** `RLIMIT_AS` or `RLIMIT_DATA` in the helper would
  keep rootless jobs running: measured on a 30 GiB laptop, Go, Node, Bun and .NET start under an
  `RLIMIT_AS` of 4 GiB, and only the JVM needs more (it reserves a quarter of the machine and starts
  at 8 GiB), and all of them run under `RLIMIT_DATA`. But it is a limit on each process, which every
  process of a job gets in full: the incident's were several `python3` at once, and an RLIMIT at a
  job's share would have let through what took the machine down. It bounds no job, and nothing
  bounds how many processes a rootless job has.

**The rootfs.** Since P3 the runner pulls and provisions the image itself (see P3), and this
directory is an optional override for the provisioned default image. P1 took a directory holding
`ubuntu:24.04` with the runner's provisioning applied
(`set_up.provision_script`, or `provision_runner_script` when steps run as the runner user), owned
as the image has it (root's files root's). It is not yet exported by the runner through Dagger at
startup: the direct engine session (`engine.zig`) implements the client's side of file sync for
reads only, and an export needs its receiving side, which is as much work as P3's pull it would be
thrown away for. Until P3, an operator makes it once, for example with Docker on a machine that may
use it (`zig-runner --provision-script` prints the script; CI's end-to-end job does this,
`.github/scripts/e2e.sh rootfs`):

```
docker run --name zr-rootfs ubuntu:24.04 sh -c "$(zig-runner --provision-script)"
mkdir -p /var/lib/zig-runner/rootfs
docker export zr-rootfs | tar -x -C /var/lib/zig-runner/rootfs
touch /var/lib/zig-runner/rootfs/.zig-runner-provisioned
```

To provision it again, make a new directory and rename it over the old one between jobs, or, if
it is changed in place, touch `.zig-runner-provisioned` in it afterwards. The step store's layers
were made over the old rootfs: every job checks the rootfs's root and that stamp before it trusts
the fingerprint it found once (`Store.rootfsFingerprint`), and a change neither shows (an
in-place change, the stamp not touched) is found when the runner restarts, by the walk's ctimes.

**What the runner needs.** As root (the supported mode): `CAP_SYS_ADMIN` (namespaces, mounts,
idmapped mounts, `pivot_root`), `CAP_NET_ADMIN` (the bridge, veths, addresses, routes, NAT),
`CAP_SETUID`/`CAP_SETGID` (writing the job's id maps), Linux 5.19 or later (idmapped overlay
layers), nftables in the kernel (`nf_tables`, `nft_ct`, `nft_masq`, `nft_chain_nat`; no `nft` or
`iptables` binary since P5), a default route, a free
`RUNNER_NATIVE_SUBNET`, and a writable `/run/zig-runner`. The runner makes `zr0` and its rules
itself on its first native job, and removes each job's namespace when the job ends, or at the
next start after a crash (`sweep`, by the jobs' locks).

What it changes on the host, which is shared by every runner on it:

- **Slots.** A job's slot names the veth `zrh<n>`, its address and its range of ids, all of them
  the host's, so slots are locked host-wide: an flock on `/run/zig-runner/slots/<n>.lock`, in a
  directory only root may enter, never under a runner's store. Two runners with different
  `RUNNER_NATIVE_STORE`s on one host take different slots, and a slot's veth is removed (a dead
  job's) only by the runner that now holds its lock. Every runner on a host must use the same
  `RUNNER_NATIVE_SUBNET`, since `zr0` is one bridge.
- **Cgroups.** As root, by default, the jobs' cgroups go under `/sys/fs/cgroup/zig-runner` (made
  on the first job, with the memory and pids controllers for its children, as Docker's cgroupfs
  driver makes `/sys/fs/cgroup/docker`). It is the host's, like the slots: each job's cgroup is
  named by its directory, and only the runner holding a job's lock removes it. All jobs' limits go
  on it ("Bounded jobs"). Under a unit with `Delegate=yes`, `RUNNER_NATIVE_CGROUP=self` keeps them
  in the unit's own tree instead, and a path keeps them in a `jobs` child of that path, whose own
  limits stay the operator's.
- **IPv4 forwarding** (`net.ipv4.ip_forward`) is turned on if it is off, and stays on: other
  runners' jobs need it, and turning it off under them would cut their network. The runner logs
  a warning when it turns it on, and another when the FORWARD policy is ACCEPT, since the host
  would then route for any neighbour; set that policy to DROP (Docker does).
- **nftables rules** (since P5, over netlink; P1 made the same with `iptables`): a table of the
  runner's own, `ip zig_runner`, replaced atomically whenever the rules are made. It masquerades
  the subnet; drops what comes from `zr0` to the host and is not a reply; drops what the host's own
  processes send to `zr0` and is not a reply (`output`, P6); forwards from `zr0` only
  out through an uplink (the interfaces of the default routes; a job remakes the rules for a new
  one, a laptop moving from cable to Wi-Fi), so never `zr0` to `zr0`, to Docker's containers or to
  the host's other networks; and forwards to `zr0` replies only. Since every base chain on a hook
  must accept a packet, the host's iptables-nft `filter FORWARD` chain, and `DOCKER-USER` on a
  Docker host (both drop by policy under Docker and ufw), get `-i zr0 -j ACCEPT` and `-o zr0 -j
  ACCEPT` at their heads, in iptables-nft's own encoding, so `iptables -S` shows them and Docker
  keeps working the table; the runner's table does the deciding. The rules stay when the runner
  stops. A host whose own nftables tables (firewalld's) drop forwarded traffic must let `zr0`'s
  through; iptables-legacy rules are not seen (the runner warns when it finds legacy tables).

- Under `deploy/compose.yaml` (not changed by P1): the runner image is `FROM scratch` and runs as
  root. It needs `privileged: true` (as the engine service has), or `cap_add: [SYS_ADMIN,
  NET_ADMIN]` with `security_opt: [seccomp=unconfined, apparmor=unconfined,
  systempaths=unconfined, writable-cgroups=true]` (without the last, Docker mounts cgroups
  read-only and every native job is refused), and `network_mode: host` for the bridge to be the
  host's. The store
  must be a volume, not the container's own overlay filesystem (overlayfs cannot take an upper
  directory on overlayfs), and the rootfs another volume. The slots' locks must be the host's:
  bind `/run/zig-runner:/run/zig-runner` from the host into every runner container (the
  container's own /run would give each its own slot 0 on the shared bridge). The image has no
  `iptables`, and needs none since P5: the rules are made over netlink. For the jobs' cgroups,
  `cgroup: private` (the default on cgroup v2): the container's root is then its own cgroup, and
  the runner moves itself into a leaf of it, as `RUNNER_NATIVE_CGROUP=self` does ("Bounded jobs").
- Under `deploy/zig-runner.service` on razorbill (not changed by P1): the unit runs as root with
  `ProtectSystem=strict`, which makes the store's default and `/run` read-only. It needs
  `StateDirectory=zig-runner` (or `ReadWritePaths=/var/lib/zig-runner`) for the store, and
  `RuntimeDirectory=zig-runner` with `RuntimeDirectoryPreserve=yes` for the slots' locks.
  Preserve matters when several units share the directory: without it, systemd removes
  `/run/zig-runner` when any one of them stops, the others' locks go with their files, and the
  next runner would take a slot a live job holds. `NoNewPrivileges` and `PrivateTmp` are
  compatible; a `RestrictNamespaces=`, a capability bounding set without `CAP_SYS_ADMIN` and
  `CAP_NET_ADMIN`, or `PrivateNetwork=` would not be. The jobs' cgroups need `/sys/fs/cgroup`
  writable (`ProtectControlGroups=` off), or `Delegate=yes` with `RUNNER_NATIVE_CGROUP=self`.
- Rootless (tests, the laptop): a user namespace mapping the runner's user to root, with overlay's
  `userxattr` (Linux 5.11). Per-job cgroups need the runner started in a delegated cgroup:
  `systemd-run --user --scope -p Delegate=yes zig-runner ...` with `RUNNER_NATIVE_CGROUP=self`. Where AppArmor restricts unprivileged user namespaces
  (`kernel.apparmor_restrict_unprivileged_userns=1`), the sandbox is started under util-linux's
  `unshare` where its profile allows it (the laptop), and needs the restriction lifted where it
  does not (GitHub's hosted runner).
  Ubuntu's narrow alternative to lifting it is a profile for the runner binary granting `userns`
  (`deploy/apparmor/usr.local.bin.zig-runner`, installed by the operator with `apparmor_parser -r`;
  README; optional). It attaches by path, so it covers the runner and its
  self-exec helpers (`--exec-job`, the sandbox helper: one binary at one path), not `unshare` or
  anything else, and it is `flags=(unconfined)`: it grants `userns` and no other rule. When
  the restriction is what stops the probe's sandbox, `Backend.usable`'s reason names the profile.
  Whether the runner using it directly, instead of through `unshare`, works is not yet
  measured; `launch` still starts under `unshare` while the sysctl is 1.

#### Measured (laptop "cowbird", balanced profile, 2026-10-31, another agent benchmarking)

The runner binary built `ReleaseSafe`, `--exec-job` on a run-only job of 50 trivial steps (`true`)
and on a job of one, rootless (under `unshare`), the rootfs plain `ubuntu:24.04`. Per step is
(50-step job − 1-step job) / 49, which leaves out process start and "Set up job".

| | native | Dagger |
|---|---|---|
| cold trivial step, first cut (chroot, no hardening), median of 7 | 18.1 ms | ~224 ms |
| cold trivial step, hardened, median of 5 | **32.7 ms** | ~224 ms |
| 1-step job, whole, hardened (with the once-per-process probe) | 58–80 ms | |

That is the whole runner path, not the backend alone. The hardened figure was taken under more
load (3.2 against 2.4) and pays, per step, a second mount namespace and about 20 mounts (/dev and
its nodes, /proc and its masks, /sys's tree, the binds, `pivot_root`), besides the 6 ms of making a
user namespace that the first cut already paid. Both are per step only because the helper is: P2's
per-job helper makes the namespaces and the static mounts once.

### P2: the layer store, cache, replay and GC

- ~~First, from P1: one sandbox helper per job instead of per step.~~ **Deferred, by the user's
  decision, to a follow-up of its own**: the store is built on P1's per-step sandbox, whose
  in-namespace code P2 does not change. The per-job helper (namespaces, /dev, /proc and its masks
  made once, steps over a pipe, about 15 ms a step on the laptop) is a speed-up of cold steps
  only; replays never start a sandbox.
- A content-addressed layer store: key `sha256(parent key, script, stable env)`, the model's
  `Key = parent · script · stable env`, without `volatile_env`.
- Replay of stored logs and file commands, so a replayed step costs well under a millisecond.
  Failures are not replayed (#69), which the model allows.
- Deterministic layer digests (a sorted walk of paths, modes, xattrs and content), standing in for
  `changes(from:).layer.digest`, which output keys need.
- Atomic publish by rename, a flock per key so pool runners sharing the store do not run one key
  twice, flattening past ~100 lowers, and LRU eviction under a byte cap.
- Exit: the step-cache tests that run through `dagger.run` pass on native too; replays are
  byte-identical to the live log. Measure: replay per step against ~95 ms; store size over 50 jobs.

**Status: the store, replay and GC landed (behind the knob); the per-job helper is deferred.**
What it covers, as built:

- `runner/src/native/Store.zig` is the store, under `RUNNER_NATIVE_STORE` (mode 0700):
  `layers/<key>/{fs,log,fc,meta,lock,digest}`, `keys/<key>.lock`, and the running jobs' `jobs/`.
  `meta` holds the store's format, the entry's kind (base, step, fetch), its bytes on disk, and
  its log's and file commands' lengths and sha256s.
  `Backend.zig` keys each exec (`keyFor`), claims the key (`claimKey`), replays a hit (`replay`)
  and publishes a success (`publishTop`).
- **Keys** are P8's preimage format (proofs/Runner/Native.lean, `stepPreimage`): a u64 tag (0 a
  base, 1 a step's container, 2 output-keyed), the parent's key, the script, the count of stable
  bindings and each name and value in the container's order, every field length-prefixed as a
  u64 little-endian (`Store.KeyHasher.core`). Stable means not in `volatile_env`, not the event,
  the ran marker or the markers' secret (volatile under Dagger too), and no secret alias
  (`Store.stableEnv`). After the core come what P8's model does not have yet: the step's uid,
  gid and working directory, and the files written for it that stay (the event file when it is
  not a variable). A base has no parent; in its place goes a digest of what every layer depends
  on (`Backend.below`): the store's format (`Store.store_format`), the job's cache scope and
  repository, the rootfs's fingerprint (a walk of its metadata, ctimes and inodes among it, kept
  per process and checked again for every job against the root's and the provisioning stamp's
  identity and ctime), how ids are mapped (the userns mode: a root runner's and a rootless one's
  layers never meet), and the binds' places (never their content). Not the slot: a stored layer has
  the canonical ids (below), so a job in any slot replays what a job in another stored. Under step caching the event payload is a variable each step
  writes to the file, as `set_up.writeRunEnv` gives it, so the base is the same for every run.
- **A key stands on keys.** `keyFor` has a key only on a keyed top (or on an empty stack, the
  digest below a base), and every other way a layer joins the stack leaves it unkeyed: a Docker
  action's step, a JavaScript action's mount points, a step that always ran or failed. What an image
  or a mount holds is in no key, so nothing above such a layer is keyed, replayed or published: a
  job's later steps run, however little changed (`Native.ops_keep_chained`). The price of that is
  cached steps, never a wrong replay.
- **The store's format** (`Store.store_format`) is bumped with any change to what a layer or its
  record means: the sandbox's trees, the record's files and how they replay, the key's extras.
  A runner upgraded across a bump finds none of the older runner's layers, and its first job's
  end removes them: an older format's `meta` is not whole to `collect`.
- **Forks**: a fork's pull request that `trust.vouches` accepts still runs natively, with caching,
  in a key space of its own: the scope is `set_up.packageCacheScope`'s (`untrusted` when the
  pull request's head repository is another), the same test that keeps its package cache volumes
  apart on Dagger. It never replays or leaves a layer its repository's own jobs use. It does
  share the store's disk and its cap.
- **Publish**: only a step that exited 0 with its file commands taken, that does not always run
  (no secret, no OIDC token, no run-specific value) and whose parent is in the store. So a failure
  is never replayed (#69), nothing after an always-run step is kept (its parent is not stored, as
  under Dagger its new parent makes every later key new), and no layer or log holds a secret. A
  step that printed more than `dagger.max_recorded_bytes` is not kept, nor a record its kind may
  not have (a step's file commands without their ran marker, a base's or a fetch's not empty),
  nor a layer whose size cannot be counted whole (a directory it cannot read). On a root runner the
  layer is first given the canonical ids (`Store.unshift`, below). A commit's checkout
  (a fetch of a full SHA) is a layer like a step's, keyed on its script and never on the token;
  a branch or tag moves, so its fetch always runs, and with `fetch-tags` the key also holds a digest
  of the remote's tags (`ls-remote --tags`, one more sandbox before the fetch), which move where a
  commit does not; if they cannot be listed the fetch runs. The upper is moved under `layers/.tmp-<key>-<n>`
  with its record, held, written to disk (its own files' data, then its meta, then one fsync of
  each file and directory, which ext4 serves with one journal commit; a large layer's `syncfs`
  instead), and published by one `renameat2(RENAME_NOREPLACE)`. An upper that cannot be put back after a failure is left there
  and logged, never deleted.
- **Replay**: the stored raw output (markers and all) and combined file commands go through
  `Exec.collect` as Dagger's answer for a cached exec does, with the earlier job's ran marker, so
  the log is `JobLog.replayNotLive`'s, byte-identical by construction, and outputs, env, PATH,
  summaries and state are applied again. The step's log ends with "Reused from the native step
  store", which the runner counts as it counts Dagger's note. Every hit is checked whole first
  (`meta`'s lengths and sha256s, and the record its kind may have): one that is not is evicted
  under its exclusive lock and is a miss, so the step runs and is published again; its last use
  is touched only once it passed.
- **Locks**: one flock per key while its exec runs (polled, so a cancel or a timeout ends the
  wait), so two jobs sharing the store do not run one key at once: the second replays the
  first's, on a root runner too, whatever their slots. A job holds a shared flock on each store
  layer it uses until it ends. Every publish, a Dockerfile build layer's too (`layers.zig`), runs
  under its key's lock, which is how `collect` tells a live runner's `.tmp-` entry from a dead
  one's. The protocol (these locks, the renames, `collect`, crashes at any point) is model-checked
  with TLC: proofs/tla/StoreLocking.tla, proofs/README.md "The store's locking, in TLA+". It
  found the build layers' unlocked publish and an eviction that renamed away an entry published
  after the one it locked, both fixed.
- **GC** (`Store.collect`, after each job): past `RUNNER_NATIVE_STORE_MAX_MB` (default 10240),
  the layers no job holds go, least recently used first (the lock file's mtime is the last use),
  each renamed away under its lock taken exclusively, then deleted. A layer counts as its tree, its
  record and 16 KiB for its own files, so steps that change nothing but print much are not free.
  Half-built and half-evicted entries of dead runners, idle key locks, and entries that are not
  whole (by `meta` and their files' lengths, without reading them) go too; so an upgrade across a
  `store_format` bump empties `layers/` at its first job's end, as an older format's meta is not
  whole to it. What is beside the layers is the next section's ("Eviction").
- **Flattening**: before a step on a stack of 100 layers (`default_flatten_at`), the stack is
  merged into one (`Store.flatten`): later entries win, whiteouts are kept (they hide the
  rootfs), opaque directories stay opaque, files are hard links and directories are made with
  their owner, mode, xattrs and times. The merged layer stands for the top: its key is the top's.
  Overlay's redirects and metacopy, off by default and never turned on here, are refused.
- **Digests** (`Store.treeDigest`, `layerDigest`, kept beside the layer once computed): sha256 over
  a walk in byte order of each entry's path, type, mode, owner as the job's namespace sees it
  (other host ids as the overflow id), the xattrs that say what it is (overlay's bookkeeping left
  out), and its content (a file's bytes, a link's target, a device's numbers, so whiteouts too).
  No times, inodes, link counts or host ids. Nothing asks for them yet: output keys stay off on
  native. A layer's digest is the same before and after its ids are shifted (`Store.unshift`
  maps owners as the digest does), but for the ids inside xattrs, which the digest hashes raw: a
  file capability's root id and ACL entries' named users and groups are host ids, shifted with the
  layer, so a layer with either digests differently after. Before the shift they named the slot,
  so such a digest was never the same across slots either.
- **The canonical ids (layers shared across slots).** On a root runner each job has a slot, its
  own 65536 host ids, and a step's upper is written in them. A layer is published with the ids
  the job's namespace saw (`Store.unshift`, as `ImageStore.flatten` shifts a provisioned rootfs):
  the slot's host ids become 0 to 65535, any other host id the overflow id (65534, as the digest
  maps it), set-id bits (which `chown` clears) put back, file capabilities put back with their
  root's id shifted (dropped when it is outside the range), ACL entries' ids shifted; through no
  symlink (directories opened with `openat2`'s `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, each entry
  changed through an `O_PATH` descriptor checked against the walk's inode), with no depth limit,
  each inode once. It relies on nothing writing the tree meanwhile (the step's processes are gone)
  but does not trust it. A failure ends the job, and the layer is never shifted again, rather than
  leave a layer half one range's or shift it twice. Each step mounts every lower with the canonical ids (the rootfs, the
  seeds, the stored layers, a flattened stack) idmapped onto its job's range
  (`sandbox.idmapLowers`, `Spec.canonical`), read-only, nosuid and nodev; the step's upper is
  not idmapped (an idmapped upper is newer and unverified here, and not needed), so what a step
  writes, copy-ups included, has its slot's ids until it is published. A job's own unpublished
  uppers keep the slot's ids; flattening gives them the canonical ids first, so the merged layer
  is one tree with one set of ids. Rootless runners have no slots and shift nothing.
- **The store is a security boundary, so the runner checks it.** With the canonical ids, a
  job's set-uid-root file or file capability is the host's root's on disk. Whoever can reach the
  store, or replace it or a directory on the way to it, has the host's root. So every start
  (`Store.prepare`, and the probe, which keeps native off and says why) makes the store directory
  the runner's own (root on a root runner, set through a descriptor opened `O_NOFOLLOW`) and mode
  0700. It refuses a store it cannot make so, a store that is a symlink, and one under any
  directory (along the path as given and as it resolves) that another user owns or that others (or
  a group other than root) can write without the sticky bit. A rootless runner's store must be its own user's,
  under directories that are root's or its own.

#### Measured (laptop "cowbird", balanced profile, 2026-11-01, load about 5.5)

`ZIG_RUNNER_NATIVE_BENCH=1 zig build test -Doptimize=ReleaseSafe` (the test "native step cache:
measured"), rootless, on the tests' rootfs (a few directories with the host's `/usr` bound in).
Per step is (50-step job − 1-step job) / 49.

| | native | Dagger |
|---|---|---|
| replayed trivial step | **0.37 ms** | ~95 ms |
| replayed 50-step job, whole (base, 50 replays, log) | 20 ms | |
| cold trivial step, with its layer published | 68 ms | ~224 ms |

The cold figure is P1's per-step sandbox (32.7 ms on a quieter laptop) plus publishing, under
twice P1's load; the per-job helper is what would cut it.

Store size over 50 jobs of one workflow, as 50 commits: ten steps, five that never change (one
writes 1 MiB), one that changes every job and four after it. 306 layers (with the benchmark's
own) in 15.1 MiB: the 1 MiB file once, and about 48 KiB per small layer, which is the
directories and the step's file-command files at a 4 KiB block each.

### P3: the OCI image pull, a native port

- Registry protocol with token auth and private-registry credentials, manifest lists and the
  platform pick (amd64, arm64 for the Pi), gzip and zstd layers, the `.wh.` whiteout conversion,
  and content-addressed blobs.
- Provisioning becomes a native step of its own, keyed like any other.
- `container:` jobs move to native.
- Services' images (P6) come from the store: `services.startOne` calls `images.find(dir, ref)` for
  an `Image` (a rootfs directory and the configuration a container takes), and
  `Backend.servicesUnsupported` calls `images.has`. The store answers the same question by
  pulling, with the service's `credentials:` (`username`, `password`, which P6 does not use), and
  `RUNNER_NATIVE_IMAGES` goes.
- Exit: no Dagger session is needed to make the rootfs. Measure: cold pull of `ubuntu:24.04`
  against Dagger's.

**Status: landed (behind the knob).** What it covers, as built:

- `runner/src/native/oci/registry.zig`: image references normalized as Docker's (`ubuntu:24.04` is
  `docker.io/library/ubuntu:24.04` at `registry-1.docker.io`; anything that is not a reference is
  refused, since its parts go into URLs); manifests and blobs over the distribution API; token
  auth answered once per pull (a `401` naming a Bearer realm, or Basic), with a `container:` job's
  `credentials:` (`docker.registryCredentials`, as the Dagger path hands them to
  `withRegistryAuth`). Plain HTTP only to a registry on the loopback, as Docker allows; a token
  realm elsewhere must be HTTPS. The token goes to the registry's own origin only, never where a
  redirect leads (a blob's CDN).
- `runner/src/native/oci/image.zig`: an index narrowed to linux/amd64, or linux/arm64 (`v8` first,
  then no variant) on the Pi; attestations never match. The platform's manifest and config, each
  blob checked against its digest and size as it arrives, then kept content-addressed; the
  layers applied in order into one directory, flattened, kept under the manifest's digest. A
  digest-pinned reference seen before (the default image) needs no request at all; a tag is
  resolved at the registry each time, as Dagger does.
- `runner/src/native/oci/layer.zig`: one layer applied safely (gzip, zstd or plain by the blob's
  first bytes; ustar, GNU long names, PAX; whiteouts and opaque directories; the diff id
  checked). See its comment for the rules: no `..`, parents resolved inside the rootfs
  (`openat2(RESOLVE_IN_ROOT)`, so `/bin -> usr/bin` works and `etc -> /etc` stays inside), the last
  component never followed, hard links from a descriptor and never to a directory, device nodes
  left out, xattrs only `security.capability` (root) and non-overlay `user.*`, size and entry caps.
- `runner/src/native/oci/Store.zig`: blobs, images, `ensure` (a keyed directory made once) and
  `flatten`, beside P2's layer store (below).
- `runner/src/native/Backend.zig`: `prepareRootfs` pulls the job's image, or takes the operator's
  rootfs for the provisioned default image (`RUNNER_NATIVE_ROOTFS`, now optional). `provision`
  runs `set_up.provision_script` (or `provision_runner_script`) as a native step on the pulled
  image, in the job's sandbox and network, its layer keyed by P2's `Store.KeyHasher` (the
  image's manifest as the parent, the script, the env in the container's order) and flattened
  onto a hard-linked clone of the image, so it runs once per store and a later job starts from
  it at once. `container:` jobs are native, with the image's env and
  `USER` (looked up in the image's own `/etc/passwd` and `/etc/group`), the container's `env:`
  over it, its PATH as `Exec.container_path`, and "Initialize containers" showing the digest. Any
  image may be native. Without the operator's rootfs, the probe pulls the default image (so it
  also says whether this machine can pull).
- "Set up job" says what the job got: "Image: pulled natively in N ms (L layers, K KB fetched)" or
  "Image: from the native store", and "Provisioned natively in N ms (layer <key>)" or "...made
  before".
- Falls back to Dagger: a job container's `ports:`, `volumes:` the native job does not carry out
  and `options:` flags the native job does not carry out ("Job container options", below), and on a rootless runner without
  `RUNNER_NATIVE_ROOTFS` the provisioned default image (below).

The store, under `RUNNER_NATIVE_STORE`, each directory only the runner's (mode 0700: a rootfs
holds the image's set-uid files with the image's owners, the host's root's on a root runner):

```
oci/blobs/sha256/<hex>                a blob, renamed into place once its digest checked
oci/refs/<hex>.<platform>             which manifest a pinned index gives this platform
oci/images/<hex>[.rootless]/          rootfs/ and config.json, by the manifest's digest
rootfs/<key>/rootfs/                  a rootfs a native step made (provisioning; apart from P2's layers/)
```

A rootless runner's images are kept apart (`.rootless`, and `:rootless` in a layer's parent key):
its files are all its own, not the image's owners'.

**On P2: what was swapped, and what stays.** P3 was written against a stand-in for P2's store;
on top of P2 the provisioning key is P2's (`Store.KeyHasher`, P8's preimage: the image's manifest
and whether its files are a rootless runner's as the parent, the script, the stable env in the
container's order), and P3's own `layerKey` is gone. `ImageStore.ensure` ("the directory under
key K, made by `make` once, under K's lock, published by rename") and `ImageStore.flatten` (an
upper merged onto a hard-linked clone of its lower) stay: a provisioned rootfs is one whole tree
with the image's ids, shared by every slot, while P2's layers belong to one slot's range of ids
and stack as lowers, of which the sandbox idmaps only the lowest (the rootfs). It lives under
`rootfs/`, not P2's `layers/`: there P2's `collect`, seeing a `.tmp-<key>` whose
`keys/<key>.lock` nobody held, removed a provisioning under way. Provisioning becomes an
ordinary keyed step once the sandbox can idmap more than one lower.

What it does not do yet (debt, with the phase that pays it):

- **Each image is flattened whole.** Two images that share layers share their blobs on disk but
  not their unpacked files. P2's stacked layers could keep layers apart.
- **Layers are fetched three at a time, in order, while the earlier ones unpack**, and a broken
  download starts over. A blob still goes into the store whole and synced, as before
  (`image.zig`, `Prefetch`).
- **A layer's inflating and hashing run on a thread beside its unpacking** (`layer.zig`, `Pipe`),
  and a large file's writeback is started as it is written (`sync_file_range`, advisory) so the
  `syncfs` before the rename has little left to write. The publish order is unchanged: nothing is
  durable by the early writeback, only by that `syncfs`.
- **zstd is the runner's own decoder** (`oci/zstd.zig`), because std's took 19 s for a 500 MB layer
  (one bit at a time through the Huffman tree) and this one 1 s; std's decoder is its test
  oracle. Frame checksums are not checked; the blob's digest is checked before and the diff id
  after, which covers it. Dictionaries are refused, and so is a window over 128 MiB.
- **Rootless** (tests, the laptop): only root is mapped, so every file is the runner's,
  directories keep their owner's write bit, an image whose `USER` is not root cannot run, and the
  default image cannot be provisioned (dpkg gives files to other ids, `root:adm`, which fails with
  `EINVAL`): such a job goes to Dagger unless `RUNNER_NATIVE_ROOTFS` is set. Phase 5's
  subordinate ids pay this.
- **The image's `WorkingDir` and `Entrypoint`** are not used: steps start in the workspace, as on
  Dagger. Docker actions (phase 7) need the entrypoint.

#### Measured (laptop "cowbird", balanced profile, 2026-11-01)

A cold pull of the pinned `ubuntu:24.04` (one layer, 29.8 MB), ReleaseSafe, into an empty store,
from Docker Hub over the same connection, three runs each. Native is `image.pull` (the opt-in test
`ZIG_RUNNER_TEST_PULL=1`): the token, the index, the manifest, the config, the blob and unpacking.
Dagger is a fresh engine container (v1.0.0-beta.21, empty cache, warmed with an unrelated
`alpine` exec) timing `from(ubuntu:24.04@sha256:...) | withExec(true)` cold, less the same query
warm (the CLI, the session and the exec: 0.41-0.59 s).

| | native | Dagger |
|---|---|---|
| cold pull, whole | **2.10-2.46 s** | 4.45-4.70 s |
| of which fetch and unpack | 1.59-1.96 s | |
| warm (pinned, in the store) | 0-1 ms | |

About twice as fast cold, and a pinned image already in the store costs no request at all.

The exit, checked on a root runner: in CI (run 41317094266, GitHub's hosted runner as root, a
debug build) a job with no operator rootfs pulled the default image natively (7.5 s), provisioned
it with a native step (20.2 s, `apt-get` the whole of it), and ran a step in it (git 2.43, Python
3.12, jq 1.7, Ubuntu 24.04.5), with no Dagger session. That test is opt-in
(`ZIG_RUNNER_TEST_PULL=1`, root), as it needs Docker Hub and the Ubuntu archive.

### P4: cache volumes, trust scopes and cgroup memory accounting

- Package cache volumes as host directories bound in, never part of a key (`Input.mounts`). The
  `repo` and `untrusted` scopes of `packageCacheScope` become separate directory trees. Dagger's
  sharing modes are reimplemented with flock; the default stays shared. The tool cache's volume
  takes the place of the directory the base makes (`Backend.base`); what a step installs there is
  then in no layer, so replay needs Dagger's check of the trees it found (#229, `Exec.tool_cache`).
- Zig's local cache generations and the cache seed move over.
- A cgroup v2 per job: `memory.max`, `memory.peak`, `memory.events`, `pids.max`. The admission
  gate (`admission.zig`) reads per-job working sets instead of the engine's cgroup. Rootless, this
  needs systemd delegation (`Delegate=yes`, or `systemd-run --user --scope`).
- **Debt from P1, paid here:** P1 has no per-job cgroup and no pids limit, so one native job's
  fork bomb or memory hog reaches the host's limits and every other job's. The same cgroup that
  gives the gate its accounting gives each job its `pids.max` and `memory.max`.
- Services (P6) go in the job's cgroup with its steps: each service's helper (`services.serve`,
  through `sandbox.run`) and the port relay (`forward.start`) are spawned into it, and "Stop
  containers" and `Backend.deinit` stop them with `cgroup.kill` instead of each helper's lifeline.
- Exit: a runaway job is OOM-killed in its own cgroup without touching its neighbours. Measure:
  gate accuracy against the engine-wide reading.

**Status: landed (behind the knob).** What it covers, as built:

- `runner/src/native/volumes.zig` is the job's caches. The volumes are the Dagger backend's by
  name, path and rule (`set_up.cachesUsed`: one per package manager the job names, the tool cache
  always, Zig's package tarballs as `p/` under its global cache, Zig's local cache in `repo` only,
  uv's environment inside uv's volume), as directories under the store at
  `volumes/<owner>/<repository>/<scope>/<name>[/<image>][/runner]`, each part sanitized to a name
  of its own. They are bound into every step and are never in a layer. The `repo` and `untrusted`
  scopes (`set_up.packageCacheScope`) are separate trees. Each volume has an flock beside it
  (`<volume>.lock`), held for the job: shared (Dagger's default, every volume's here), locked
  (exclusive, jobs take turns) or private (exclusive when free, else a fresh copy of the job's
  own, removed after it).
- On a root runner a volume's files are owned on disk by a range of ids of their own, the one just
  past the last slot's (`Backend.volumeIdBase`, which `idsClash` checks with the slots'), and each
  step sees them as its own ids through an idmapped mount (`sandbox.bindVolumeIn`, a userns
  mapping that range onto the job's), nosuid and nodev. A volume filled by one slot's job is the
  next slot's, and a setuid file a job leaves in one is nobody's on the host. A missing mount point
  is made owned by the job's root, as Dagger makes a cache mount's missing parents.
- Zig's local cache rolls its generations with the Dagger backend's own script
  (`set_up.zig_local_roll_script`), run in a sandbox of its own whose layer is dropped.
- The Zig cache seed (minisign-verified releases, `Options.zig_seeds`) is built once per release,
  architecture and step user, with the Dagger backend's script (the tarball checked against its
  pinned sha256 before it runs), under a lock, in a sandbox without the job's volumes; its cache
  is moved into `seeds/<arch>-<version>-<user>` with the directories above it as the rootfs has
  them, its files owned as the image's files are and no setuid bit, and published by rename. It is an image layer
  between the rootfs and the job's layers, seen through the job's ids as the rootfs is
  (`sandbox.idmapLowers`), so a job's own writes to its global cache stay in its layers.
- `runner/src/native/cgroup.zig` is the job's cgroup: `memory.max` (`RUNNER_NATIVE_MEMORY_MAX_MB`,
  two thirds of all jobs' by default, "Bounded jobs"), `pids.max` (`RUNNER_NATIVE_PIDS_MAX`, 8192), and
  `memory.peak`, `memory.events` and `pids.events` read back. Each step's helper joins it before
  anything else (`sandbox.joinCgroup`), so every process of the step is born in it and the runner
  never is. It is kept, empty, between steps, and killed (`cgroup.kill`) and removed when the job
  ends, or by the sweep after a crash. Its `steps` and `services` children are described under
  "Bounded jobs". When a step's processes were OOM-killed or refused a fork,
  its log says so in an error line. Where it goes: `/sys/fs/cgroup/zig-runner` as root; the
  runner's own delegated cgroup with `self` (the runner moves its processes into a `runner` leaf and
  makes the jobs' under `jobs`, systemd's rule for delegation); a path; or none, with
  `RUNNER_NATIVE_CGROUP=none`, where the job runs as in P1 and "Set up job" says it is unbounded.
- The memory gate (`admission.zig`) is told of a native job's cgroup (`Gate.native`) and measures
  the job there, from nothing, with the engine's own definition of a working set
  (`workingSetMb`: `memory.current` less `inactive_file` and `slab_reclaimable`), so the same
  bytes count on either backend (though an engine reading also holds what the engine grew by for
  the job, which is why the two are learned apart, below). A native job is never measured beside another
  (its cgroup is its own), its last sample is taken just before its cgroup goes
  (`Gate.nativeDone`), and its reservation is left out of the engine's cap
  (`Reservation.native_mb`). A native job without a cgroup is not measured, as a job without an
  engine signal is not.
- **What a native job reserves** (after razorbill, 2026-11-02): its estimates are learned per job
  name in a table of their own (`Admission.learned_native`), apart from the same name's on the
  engine, whose reading is the job plus what the engine grew by for it. A job a native pool sends
  to Dagger, unsupported or after a native set-up (`Gate.backToEngine`), is measured on the engine
  from then and learned there. A native job not learned yet reserves `RUNNER_NATIVE_MEM_PER_JOB_MB`
  (256 MB), and a native pool's runner polling reserves the same 256 MB (since #361; it reserved
  the most of that and any native job's estimate, so one `zig build test` learned at 2.6 GB made
  six pollers reserve 15.8 GB and hold small jobs behind a heavy one that was not there), where both used `RUNNER_MEM_PER_JOB_MB`'s 1.5 GB, sized for `zig build test` on the
  engine: razorbill's six native bench runners held e2e jobs of a few MB for 87-150 s ("3 job(s)
  needing 4.5 GB would leave under 1536 MB" with 5533 MB available). A native job is always
  learned as alone, and a job on the engine is no longer taken as beside a native one: the overlap
  mark a native job sets as it starts is taken back once it is known to be native
  (`Admission.shareEngine`).
- **A native job waits for room once it is named, not before it is handed out** (#361, after the
  v0.26.0 measurement on razorbill: queue median 4.5 s, largest 12 s, 32 s in the first pass after
  a learned build, `holding back` 69 times in 25 minutes; about 1 s before the gate). A runner
  cannot know its job before it asks for one, and on the engine that decided everything: the job
  started the moment it was handed out, so every runner polling had to have room for the heaviest.
  A native job has a cgroup of its own under a parent with `memory.max` (#372), and nothing of it
  runs before its set-up, so the gate can look after the acquire, when the name is known. A
  polling runner reserves `RUNNER_NATIVE_MEM_PER_JOB_MB`; the named job (`Gate.assigned`) waits
  in `Gate.start` for `MemAvailable` above the floor, less what the jobs started in the last two
  minutes and the runners polling reserve, less its own estimate (what its name took natively,
  or on the engine, or for a name not seen the most any native job took, which is what
  `Gate.noHigh` reserves where jobs cannot swap). The decision and the job's reservation are one
  step under the pool's lock, so jobs named in the same moment pass one at a time, each counting
  the ones before it: of six `zig build test` jobs learned at 2.6 GB with 7.4 GB available, two
  start (1.5 GB floor + 5.2 GB) and four wait. Jobs waiting do not count each other, which would
  hold them all for ever; the runners polling count the one that has waited longest, not the rest
  (#415: counting all of them held small jobs at GitHub for 182-266 s behind heavy jobs waiting
  for room), so no new job is taken while the first in line waits unless there is room for both.
  A job named meanwhile that is not first in line must leave that room too (`Admission.withHead`),
  so the first in line is never delayed by a job that began waiting after it did.
  - *Short jobs go ahead* (#415). Counting the first in line still held small jobs at GitHub while
    it waited for a heavy job to end. The pool now learns how long each name runs (the longest of
    its last five runs, kept with its memory: a job that is sometimes long is not taken for a
    short one). A job named while another waits, that does not fit beside it but fits without it,
    starts anyway when its name ran at most 60 s (`short_run_ms`) in each of those runs; a name not
    learned, or learned longer, waits behind the first in line as before. A runner polling cannot
    know its job, so it passes on the same room test (it fits without the first in line) and the
    job it is handed is then told at start; the cost of a wrong guess is a runner holding a job,
    so no poller passes once half the pool's runners hold waiting jobs. The first in line is
    protected by when this is allowed: only while it would not fit even with every job that went
    ahead gone (it waits for jobs not expected to end soon), and while some job that did not go
    ahead runs (when only those do, it is the one forced when they end, #386). Once it would fit
    without them no more go ahead, so a stream of short jobs delays it only by the ones in flight,
    each for as long as it was learned to run: 60 s at most, and nothing like the 182-266 s the
    e2e burst waited. A job learned short that runs long (a `short_run_ms` guess gone wrong) delays
    it by that run, once: after 120 s (`overdue_ms`) no more go ahead on the word of a learned time
    while it runs, and when it ends its run is learned, so its name is long for its next five runs.
  - The runners polling on a native pool count natively for the engine's cap: a busy engine does not hold
  runners whose jobs never run in it (#414). The wait is in the job's own log ("Waiting for room in memory before starting")
  and ends when a reservation drops (`Admission.changes`, within 50 ms) or at the next recheck.
  - *A machine that cannot fit one job* (#406). At start the runner compares one job's reservation
    plus the floor (`RUNNER_NATIVE_MEM_PER_JOB_MB` or `RUNNER_MEM_PER_JOB_MB`, and
    `RUNNER_MIN_MEM_AVAILABLE_MB`) with the machine's memory, or the memory limit of the cgroup it
    runs under if that is less, and on the engine with the engine's cap less
    `RUNNER_MIN_ENGINE_HEADROOM_MB`; if no job could ever start it exits with a message naming the
    settings and the numbers (`Admission.misfit`). While running, when nothing runs, no job waits
    and no other runner polls, one runner polls whatever the room (said in the log): a machine
    that has less memory than at start does not idle in silence.
  - *The estimates survive a restart* (#407). `Admission.learned` and `learned_native` are kept in
    `memory-gate-<RUNNER_NAME_PREFIX>` in the native store's directory (`RUNNER_NATIVE_STORE`,
    `Config.nativeStore`; written there for a Dagger pool too; one file for each pool, as pools on
    one machine share the directory), one text line a name, versioned (`zig-runner memory gate
    v2`), with the machine id, `MemTotal` and the backend they were measured on. It is written
    atomically (temp file, fsync, rename, fsync of the directory) when something was learned, at
    most every 10 s and when the pool ends, and read at start, where the log says how many were
    loaded. A file from another machine, another amount of memory (more than 1/16 apart), another
    backend or format version, or a damaged one, is not used and is warned of; the next write
    replaces it (v1 had no run times: it is not used). The table keeps the last five runs of a name, and how long each ran (#415), and the 64 used most recently, as
    before: a name's estimate is the most of those runs, so one learned low (a warm `zig build
    test` at 64 MB) still reserves little for a cold one until a heavy run has been seen, restart
    or not.
  - *No deadlock.* When every runner holds a job and none has room, nothing is running to free
    any: the job that came first starts regardless (said in its log), the others wait for it, and
    the next oldest follows as each ends. The machine cannot get freer, and a job over
    `memory.max` is the kernel's to end, not the machine's. A job handed out and not named yet
    counts as running, so the escape waits for the acquire to finish.
  - *GitHub keeps the job.* The runner renews the job's lock every 60 s from the acquire
    (`Renewer`), as GitHub's runner does from its first moment and for as long as the job runs
    (`JobDispatcher.RenewJobRequestAsync`, 60 s). The lock lasts 10 minutes without a renewal. So
    a wait holds the job for as long as it takes, and no timeout is added to it; a job that waits
    for hours behind a hung one is ended by its own `timeout-minutes`, which GitHub enforces by
    cancelling it.
  - *A cancel ends the wait.* GitHub's cancel, the job's timeout or a 404 from the renewal sets
    the same flag as during the steps; the job then starts (and is reserved) to run what survives
    a cancel, `if: always()` steps and post scripts. A runner told to stop keeps waiting for
    `StopDeadline` to cancel the job once its grace has passed.
  - *The engine is unchanged.* A pool on Dagger, and the pre-warm, are never marked waiting; the
    poll's worst case is theirs as before. A native pool's job that goes to the engine after its
    set-up (`Gate.backToEngine`) was let in as a native job and is not checked again.
- **`memory.high` per native job** (`Job.setHigh`, `admission.nativeHighMb`): twice the job's
  estimate (learned, or the native default) plus 512 MB, so 1 GB for a job not learned yet; "Set
  up job" says it, as the kernel holds it. Past it the kernel reclaims the job's page cache, then
  slows its allocations; it never kills, so a job that outgrows its estimate is throttled in its
  own cgroup instead of taking memory its neighbours were admitted against, or meeting the OOM
  killer. Since #367 only where jobs can swap: with none it stops a job dead, and `memory.max`
  decides alone ("Bounded jobs"). `memory.max` stays the hard cap above it (a `memory.high` above it
  is simply never reached), and the host's `MemAvailable` floor
  (`RUNNER_MIN_MEM_AVAILABLE_MB`), pressure and swap growth still hold every runner. The headroom
  is for what `memory.high` counts and the estimate does not: page cache and reclaimable slab. A
  job that outgrew its estimate and went over `memory.high` (memory.events `high`) is learned at
  no less than that limit, since what it was seen to take is what the throttle let it, so its
  next limit doubles until a run fits. A job near its limit gets 256 MB more a second while the
  host has that above its floor and the reservations of jobs still ramping up
  (`Admission.growHigh`): the limit protects neighbours, and it held a first `zig build test` on
  razorbill at 1 GB, three times under what it needed, for over an hour with 4 GB free. Without
  the gate (`RUNNER_ADMISSION=false`) or with `RUNNER_NATIVE_MEM_PER_JOB_MB=0`, no `memory.high`
  is set.
- On P2's step store: the digest below a base (`Backend.belowKey`) holds the seeds' layers and
  which binds are cache volumes, after the model's fields and only when the job has either, so a
  stored layer is never replayed over a different seed and a job with neither keys as before (the
  model's `belowTail`; P8's vectors gained `below-seed` and friends, the old ones unchanged). The
  tool cache is the `toolcache` volume, keyed by the job's image as on Dagger; the base makes
  `/opt/hostedtoolcache` only for a job with no volumes (#274). What a step installs there is in no
  layer, so a stored step whose `$GITHUB_PATH` or `$GITHUB_ENV` points into it replays only when
  "Set up job" checked a tree that holds the directory, and otherwise runs again
  (`Exec.tool_cache`, `toolDirNotHeld`, #229). The check is `native/tool_trees.zig`, a port of
  `dagger/tool_trees.sh` (below, "The tool cache's trees").
- Debt: a step whose processes still hold all of `pids.max` when its script
  ends fails with exit 2 and loses its file commands: the wrapper's `sh`, the step's PID 1, cannot
  fork its epilogue (its log says the job reached its process limit). Fixing that needs a PID 1
  that reaps and kills a step's leftovers before the epilogue. The seed registry's discovery from the tool cache's trees
  (`zig_release.Registry.discover`) is off natively. Rootless runners without delegation have no
  limits (P5 must refuse untrusted jobs there).

#### The tool cache's trees

A rerun of a job that installs a tool took 49 s natively and 2 s on Dagger (razorbill, v0.25.0, a
real `zig build test` job): the `Install Zig` step names a directory in the tool cache, a volume in
no layer, so its record was never trusted. On Dagger "Set up job" checks the trees of the tool cache
(`tool_trees.sh`, `set_up.verifyToolTrees`) and a record is replayed when a checked tree holds the
directory it names. Natively the same check runs in the runner (`native/tool_trees.zig`,
`Backend.checkToolTrees`), after the volumes are open, and gives the same two things:

- `ZIG_RUNNER_TOOL_TREES`, one `DIGEST TREE` line per directory `TOOL/VERSION/NAME` of the tool
  cache, TREE as the step sees it, DIGEST what `install-zig.sh` pins (`find . -type f -print0 |
  LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum` in the tree; the port's tests compare it with
  those commands, and with the digest pinned for Zig 0.17.0). A script that pins a tree's digest
  skips its own read of the tree when the two match.
- `Exec.toolDirNotHeld` with a tree list, so a replayed step that names a held tree's directory
  replays. A record naming a directory no tree holds (a tree that was removed, an unfinished one,
  `..`) runs again, as before.

**What replay can rely on.** The pinned digest is over regular files, and nothing else: not a
link, a mode, a pipe, an empty directory. A tree whose link `gcc -> ../../.evil/gcc` was changed,
or whose `zig` was made set-uid, has the same pinned digest, and `install-zig.sh` (and Dagger's
check, which is the same) takes it as checked. So the native check makes a second variable,
`ZIG_RUNNER_TOOL_TREES_FULL` (`FULL TREE` lines), over every entry: type, mode, path, a regular
file's sha256 and a link's target. Both variables are in the key of every step (neither is
volatile, so `Store.stableEnv` hashes them), hence in the base's key and every layer above it. A
tree that changed in any of these ways is a tree no record was made against, so the step that
installs runs again and repairs it. A tree with a link that may leave it is left out of both: what a link
points at outside the tree is in no digest, so no record naming such a tree is replayed. "May
leave" is judged from the link's text and is strict: an absolute target, more leading `..` than
there are directories above the link inside the tree, or any `..` after a name. The last is
refused because a name can be a link itself (`lib/d -> ..` then `gcc -> lib/d/../../.evil/gcc`
leaves the tree, though the text of `gcc` goes up no more than the tree is deep). With `..` only
first, a link that stays in the tree from where it is can only reach a place in the tree, whatever
links lie on its way, since each of those was judged the same. A real tool tree with a link of the
second kind (`../lib/x/../y`) is left out too, and its steps run as they did before this change. This holds for the native
backend. On Dagger the second variable does not exist and the claim does not hold: a modified link
or mode in a tree with the same pinned digest is replayed against, and what it would take there is
the same second digest in `tool_trees.sh` and in `Exec.tool_trees`' parser. `install-zig.sh`'s own
check is of regular files too, so it is blind to a link planted in its tree whoever says the tree
was checked: that put a planted tool on PATH with no replay involved. The script now uses a tree
only if nothing in it is neither a file nor a directory (`plain`; Zig 0.17.0's tarballs hold
neither a link nor anything else of the kind, for x86_64 and aarch64, checked against the pinned
checksums), and `tool-trees-test.sh` covers it.

The cost is also Dagger's: a tree added, removed or changed makes every step of every job of the
scope new once. Narrowing it (a key of only the trees a step puts on PATH) was considered and not
done. A step's key is made before it runs, and which trees it names is only in its record, so it
needs the digests the tree had when the step finished stored in the record and compared at replay,
which means hashing the tree again after every step that names one, and a change to the record's
format. A job's first rerun after an install is the one that pays: job 1 finds no tree and
installs, job 2 sees the tree (new keys) and finds it installed, job 3 replays.

The check differs from the script where it runs. The script runs as root in the job's image, in a
container; the port runs in the runner's process, on a directory a job can write, so it is confined
and bounded:

- Every look at the volume is relative to a directory descriptor, through `sandbox.openIn` with
  `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_XDEV`, so a link a job planted (a tree that is a link to
  `/`, a file that is one) is never taken and the check cannot be made to read outside the volume.
  Only directories and regular files are opened, the latter `O_NONBLOCK` and checked to be regular
  after opening, so a pipe or a device cannot hold the check. A link is read, not followed.
- A tree whose names have a control character or a backslash (`sha256sum` escapes those), a name
  over 255 bytes or a path over 4,000, is left out, and a step checks it itself. So is a tree the
  check gave up on for a limit, one with unreadable files, and one with a link that leaves it.
  "Set up job" says which and why ("left out: zig/0.17.0/x (too many entries)").
- Limits (`tool_trees.Limits`). Each tree: 65,536 regular files, 100,000 entries, 8 MiB of paths,
  1 GiB read, 60 s (the check's, because a tree that gives up keeps no list and the next job
  starts cold: Zig's cold check is 10-19 s on razorbill, and a loaded one must not give up at
  20). The check: 400,000 entries and 4 GiB read, past which no more files are read; 60 s of
  reading, past which none are either; 48 directories deep, 512 trees, 1,024 names a level. The
  job's cancel (seen at every file and every 64 KiB read) and 90 s end the check itself. A tree
  over a limit of its own is left out and the others are checked. A budget that is spent ends the
  reading, not the check: trees whose lists are whole need none and are still reported. Zig 0.17.0 has 19,505 files and 1.2 MB of paths. Both variables are
  capped at 64 KiB (one string of an environment may not pass 128 KiB, and one over it made every
  later job's `exec` fail with E2BIG); a tree that does not fit is left out, and so is one that
  would not fit the Dagger path's variable (`set_up.toolTreesVerdict`, the same 64 KiB).
- Memory: a tree is held in memory while it is checked (a path, an entry and a list line each:
  about 7 MB for Zig). Every byte is charged to the process's `Budget.held`
  (`native/hash_files.zig`), the one number of what checks and `hashFiles()` calls hold now, and
  to `Budget.checks`, the part the checks hold. A tree is left out when `checks` would pass
  `Limits.memory` (128 MiB), so concurrent checks of hostile trees hold 128 MiB between them, not
  each their own, and what `hashFiles()` calls hold (up to a gigabyte each in turn) never takes
  from it. A check never waits and a call is never refused for what checks hold, so neither can
  fail a job through the other; a call meets checks that are gone in seconds.
- Order, and what one job can starve. Each tree has a `<tree>.born` file in the lists: when this
  runner first saw it. Trees are checked oldest first (ties in byte order); at each level of the
  walk to them the names that have a `.born` come first, so a level full of planted names does not
  hide the trees seen before (among those, in byte order). What a job adds to the volume is
  younger than the tools installed before it, so it spends the budgets, and the room in the
  environment, after them: an earlier cut ordered by "has a list", which a job's own trees get
  too, and two attacks showed it (six trees grown to 2 GiB of holes after a check listed them,
  which spent the reading budget before the honest tree; 380 trees that filled the environment's
  64 KiB first, so `install` reran in every job). What is left is what age cannot tell: a job that
  makes its trees before the honest tool is installed, or a new version of a tool installed after
  a job's trees, is younger than them, and can be left out for as long as the volume holds them.
  Its steps then run, as before this change; it cannot make a job fail. "Set up job" counts every
  tree left out ("left out 382: ...") and names as many as fit in 4 KiB.
- The lists are in the store beside `volumes/` (`tool-trees/<digest of the volume's path>/`), never
  in a volume a step mounts. They are a cache of what a check read: store eviction may remove all of
  `tool-trees/` at any time, and a check without them reads the trees again. A list that would be
  over 32 MiB (the most that is read) is not written. A list of a tree that is gone, its `.born`,
  and the directories that leaves empty, are removed by the next complete check; half-written
  lists (`*.stat.<random>`, `*.born.<random>`) older than five minutes by every check. A check is
  not complete when a level holds more names than are looked at (17,000 top-level directories do
  it), so a job that does that stops the removal and the lists of gone trees stay and grow, for
  as long as the volume holds the names; eviction of `tool-trees/` is what bounds them.

The cost is the script's lists, kept: one line per regular file (path, size, inode, mtime, ctime,
sha256), and only files whose line changed are read again. A write sets the file's ctime to now and
a step cannot set it back (that takes the clock); a file whose ctime is within 2 s of the check is
listed as racy and read next time; a list that does not name exactly the tree's files in order is
not believed. That is not enough alone: a writable shared mapping, once its page is dirty, writes
again without changing ctime or mtime, whatever the descriptor (it can be closed). So the check
takes a read lease (`F_SETLEASE`, `F_RDLCK`) on each file it reads, which the kernel refuses while
any writer or writable mapping holds the file, and lists a refused file as racy. That holds only
where it was seen to, ext4 and tmpfs: overlayfs grants the lease over a writable mapping, as the
mapping's file is the one beneath, so a file on any other filesystem is racy too, and read at every
check (the test failed on main's job in a Dagger container, whose `/tmp` is overlayfs on the host's
disk, and passed on hosted runners). A lease is broken
with a signal to the process, SIGIO by default, which ends a process that does not handle it and
which `std.Io` uses to interrupt blocked calls (a job's cancel, a timeout): the check must not
ignore it (an earlier cut did, and a native end-to-end job never got its cancel). `F_SETSIG` makes
it SIGURG, whose default is to be ignored. The writer's open then waits until the check lets go of
the file, or fails with EAGAIN if it does not wait. On the
laptop, for the real Zig 0.17.0 tree (19,505 files), a check is 0.5 s with no list and 0.1 s with
one, with 22 MiB of peak memory in the test process; the script reads the same tree in about 1 s,
by its own comment. A tree of 65,532 hard links of 3.8 KB paths (the case that took 1.5 GB, or 6.1
GB with four checks at once) is left out in 8 ms with 9 MiB, and 27 MiB with four at once.

Not proven or not done: lists written by a runner before the lease was limited to filesystems
known to refuse it (a runner of an earlier release, on overlayfs) hold non-racy lines for files the
lease could not vouch for, and are trusted until those files change; the list's format carries no
version, and a bump would also have to teach the leftover cleanup the old name, so it is not done:
delete the store's `tool-trees/` once after upgrading a runner that ran on overlayfs (the next
checks read every tree again). The lease needs the file's owner to be the runner's user or CAP_LEASE
(a refused lease only makes the file racy, so the cost is a read, never trust); lists of Dagger's
check are unchanged; the seed registry's discovery from the trees
(`zig_release.Registry.discover`) is off natively.

### Eviction

`runner/src/native/evict.zig` keeps what is beside `layers/` within limits of its own: the cache
volumes, and together the blobs, images, provisioned rootfs and Zig cache seeds, each directory of
which has a lock file beside it. It runs at the end of every job's `Store.collect`, under `gc.lock`,
so one runner at a time does it and another finding it busy goes on; the proof of its locks is
proofs/tla/StoreEviction.tla.

- **The cap.** Past `RUNNER_NATIVE_VOLUMES_MAX_MB` (16 GiB) of volumes, those no job holds go, the
  longest unused first. The last use is the mtime of the volume's lock file (`<volume>.lock`), set
  by `volumes.open`. The size is `<volume>.size`, from a walk at the end of some job: one volume a
  job, never measured first, a volume in use again at most once an hour, for at most a second (10 s
  when it was never measured), never holding a lock, what it could not see left out. So the size
  lags, and only ever matters at the margin.
- **Trees.** Past `RUNNER_NATIVE_IMAGES_MAX_MB` (8 GiB) of images, rootfs and seeds together, the
  blobs go first, oldest first, as they only save a download of what is unpacked already or not
  wanted since, and then the trees no job holds, the longest unused first. A tree's size is measured
  as a volume's is, but only once; a file a rootfs shares with its image counts half to each. A job
  holds its image and its rootfs from the moment it asks for them to its end (`oci.Store.hold`,
  `ensure`, each in `Backend.held`), as it does each seed (`Backend.holdSeed`), and a service's or an
  action's image.
- **A job of an older runner.** A runner from before these trees had locks holds none of them,
  touches no mtime, and unpacks without `oci/blobs.lock`, so a tree or blob it is using looks unused,
  and instances of a unit restart one at a time (`restart_all`), so such a job can share a store
  with this code. Every job of this code has a mark, `jobs/<id>/holds-trees`, written before the
  directory gets its name, so no job of this code is seen without it. While any `jobs/<id>` lacks
  the mark and its `lock` is held, a pass leaves the trees and blobs alone, with what it tidies
  there and `oci/refs/` (`evict.jobsInTheWay`, a scan of at most 4096 directories, under `gc.lock`,
  run before the walks and again just before the tree half, logged once a pass at info with what it
  found; past 4096 it does not know, and waits). Volumes are not affected: older runners hold those. There is no age
  limit, as a job may run for days: a lock is free only once its runner has let go or died, so a
  dead runner's directory stops nothing from that moment, and the next job's `sweep` removes it.
  `jobs/` is out of a job's reach: a step sees the overlay and its binds, after `pivot_root`, and
  none of them is the job's directory. This narrows the mixed-version window, and does not close
  it: a job of an older runner that starts after the second scan, and takes a tree the same pass
  evicts, still loses it. That gap is the time the evictions take, up to the walk of a tree never
  measured (10 s) under the disk's floor. Also left as it is: the preflight of an older runner
  (`docker_action.unsupported`) pulls before any job directory exists, so an unpack's `.tmp-` blob
  can be lost to a pass, which sends that job to Dagger. It is survivable, and needs no fix.
- **An image outlives its rootfs.** A rootfs is its image's files, by hard link, and a job that uses
  a rootfs pulls its image first. So an image counts as used an hour later than it was, and the
  rootfs goes first: an image evicted under a living rootfs would cost the next job a pull for
  nothing. The rootfs itself loses nothing: an inode lives as long as one name does. The links an
  eviction drops move those files' ctimes, a little at each pass as a tree goes in pieces, so a rootfs
  in the store is not fingerprinted by walking it: what it holds is in its key, and only making it
  again changes its root (`Store.rootfsFingerprint`).
- **What a job sees after.** An evicted image is pulled again, needing the registry; an evicted
  rootfs is provisioned again, under the same key; a rebuilt one has a new root directory, so a new
  fingerprint, and every layer on it misses once and ages out under the cap. An evicted seed is
  built again, needing its tarball, and a job that cannot build it runs unseeded with a note, as it
  always could. A seed built again is not the same tree, so keys know it by its path and which build
  it is (`volumes.seedId`), and layers on the old one miss too. These cost minutes, not results.
- **An entry stays a day.** An entry used in the last 24 hours stays though its area is over its cap,
  with a line in the runner's log. The cap is a target: a working set over it costs disk, where
  evicting it would cost each job its caches or its base image, on a loop.
- **The disk's floor.** With less than `RUNNER_NATIVE_MIN_FREE_PCT` of the store's filesystem free
  (10), layers go first, as `Store.collect` runs before this and they are the cheapest to make again,
  then blobs, then entries of either kind, the longest unused first, whatever the caps say, until
  that much is free or all that is left was used in the last hour. An entry never measured is
  measured first, as one counted as 0 would take them all. This is what bounds the store on a
  machine smaller than its caps, with no setting: 10 GiB of layers, 16 of volumes and 8 of images fit
  a 128 GB card, and on a 32 GB one the floor does the work.
- **A job in progress loses nothing.** A job holds each of its volumes' locks shared from
  `volumes.open` to its end. An eviction takes the lock exclusively and non-blocking, so a volume in
  use is skipped, on this runner or any other sharing the store; a `locked` one is in use the same
  way. A `private` copy (`<volume>.private-<n>`) has a lock of its own, so one a dead runner left is
  told from one in use, and goes at the next collect.
- **What a job sees after.** A new, empty directory at the same path, owned as `volumes.open` owns
  it, as on a machine that never ran the repository: every package manager's cache is only a cache.
  A stored step whose `$GITHUB_PATH` or `$GITHUB_ENV` names a directory in the tool cache runs again
  rather than replay (`toolDirNotHeld`, #229), so a replay never counts on what eviction took. A step
  replayed whose script left something else in a volume, and a later step that needs it without
  saying so, would not find it, as on any other runner's first run of that step's successor: that
  rests on a job's own steps, and is the same case as Dagger's own GC of a volume.
- **A crash at any point.** The entry is renamed to `<area>/.dead-<n>` and both directories synced
  before anything of it is deleted; a later pass finding a dead name syncs the filesystem first, as
  the runner that renamed it may have died before it could, and which directory it came from is not
  known. So an entry is what was left there or is gone, on a filesystem that orders its journal or
  not. A dead maker's `.tmp-<key>` or `<name>.new-<n>` goes under the entry's free lock, which a live
  maker holds exclusively; a blob's under `oci/blobs.lock`, which an unpack holds shared. The lock
  file goes last, so whoever takes a lock checks it is the file the path names
  (`Store.sameFile`), as `lockKey` does.
- **A job writes what is in a volume**, so eviction believes nothing in there. The walk never enters
  a volume, a size and a lock are beside it, where no job reaches, and every file the store looks
  for is opened through no symlink and without waiting on a FIFO. A volume inside another (`<key>`
  and `<key>/runner`, when one store has had both step users) is no entry of its own: it goes with
  the outer one, whose eviction takes the inner lock through a descriptor and removes whatever else
  is at that name, and a job opening the inner one meanwhile waits, finds the path gone and starts
  over. A job in the outer volume can delete the inner lock, but it can as well delete the inner
  volume, which is the same repository's.
- **What will not go.** Removing a dead tree goes down by name and back by the descriptors it came
  through, at most 32, never by `..`, so it cannot reach above the tree whatever moves meanwhile.
  Deeper than that it moves what is below to the tree's top, as `.cut-<random>` (random, as a job can
  read its inodes and plant any name it can work out), so a chain of directories of any depth loses
  some of itself each pass. A dead name that still cannot be removed is logged, and stops nothing.
  Going down a level counts against a pass's 64 entries like removing one (a chain of directories
  with no files used to be walked to its end whatever the clock said: 2.9 s against 1.5 s at a
  depth of 250,000), and a pass the budget stops in the middle of a chain moves the directory it
  had reached up to the top too, so the next pass does not walk the same levels again. A level
  costs a descent and a removal, so a pass that is late from the start clears about 32.
- **Time and memory.** Deleting has a budget of 1.5 s a job, which evicting counts against too, and
  which starts after the sync below. A pass removes at least 64 entries whatever the clock says, so
  the worse the disk, the less goes, but something does. What is left stays under its dead name, the
  next job's end goes on with it, and nothing more is evicted until it is gone. A pass holds no
  entry's lock while it walks or deletes, so a job starting waits at most for one rename's sync. It
  looks at up to 16,384 volumes, and a walk keeps at most 16 MiB of paths. Under the floor, layers
  have a budget too: a pass takes one, and more while it has time.
- **What no budget bounds.** The `syncfs` before deleting from a dead name, once a pass, takes what the
  disk takes; each eviction's two directory fsyncs likewise, and one layer's delete. All of them are
  at a job's end, before its result is reported. A dead tree that will not go costs that `syncfs` at
  every job's end, for as long as it stays.
- **When a sync fails.** A pass stops there: nothing more is evicted until what went is gone, or a
  disk that fails writes would take entry after entry and free nothing.
- **Costs left.** Deleting and measuring are at a job's end, before its result is reported
  (`Backend.deinit`), so a job can end up to 1.5 s plus a walk later. A size is the runner's own
  estimate, not the filesystem's: a file with several links counts its share per link.
- **A really full disk.** The floor is tested on a 64 MiB tmpfs filled until a write fails with
  `ENOSPC`, in a mount namespace of bubblewrap's (`.github/scripts/full-disk-test.sh`; no root, and
  skipped where bubblewrap or user namespaces are not allowed): with a volume never measured among
  them, the pass frees a fifth of the disk and the store takes writes again. A plain
  `unshare -rm` is refused on hosts that restrict unprivileged user namespaces (Ubuntu's AppArmor).

### P5: isolation for untrusted jobs

P1 already gives each job on a root runner its own ids, its own network, pivot_root, masked
/proc, Docker's capabilities, no_new_privs and a seccomp deny list ("Isolation" under P1). What
remains before native steps may run jobs the runner does not vouch for:

- Resource limits came with phase 4's cgroups; P5 must refuse an untrusted job on a runner where
  the job would get no cgroup (a rootless runner without delegation, `RUNNER_NATIVE_CGROUP=none`).
- Seccomp as Docker's allow list rather than its deny list.
- The NAT and forwarding rules over nftables netlink instead of `iptables` (P1's debt), with P6's
  rule among them: nothing goes to `zr0` that is not a reply, from the host (`OUTPUT`) or routed
  (`FORWARD`, `DOCKER-USER`).
- Rootless: a userspace network stack for the job's network (the parts of pasta or slirp4netns it
  needs, ported) and subordinate ids through `newuidmap`.
- `trust.zig` is unchanged: it decides before any step. Until P5 lands, native runs only jobs the
  runner vouches for (`trust.vouches`); others fall back.
- Exit: the hostile-job tests (fork bomb, memory hog, mount escape attempts, network to the host's
  services, a kernel-interface sweep) are contained.

**Status: in progress.** Landed in the first pull request:

- **Seccomp as Docker's allow list** (`runner/src/native/seccomp.zig`): moby/profiles'
  `seccomp/default.json` at 6fe7deb1b9fb (2026-09-17), as Docker applies it to a container with
  its default capabilities (of the capability-gated rules only `chroot`; `ptrace` and
  `process_vm_*` as on Linux 4.8 and later). A call the profile does not name gets EPERM; one
  numbered past every call it names gets ENOSYS, as runc gives it, so a C library falls back. Its
  argument conditions stay: `clone` without namespace flags, `clone3` ENOSYS, `personality` with
  Docker's five values, `socket` with Docker's address families. The calls are named, and numbered
  from std's x86_64 and aarch64 tables; a test runs both filters in a small BPF interpreter, and
  another fails when a call std knows is neither named by the profile nor known to be refused (a
  name spelt otherwise would drop out quietly).
- **The rules over nftables netlink** (`runner/src/native/nft.zig`), no binary: "What it changes on
  the host" under P1 has them. `zig-runner native-nft <subnet> [uplink...]` makes them in the
  caller's network namespace.
- **The gate for untrusted jobs** (`Backend.untrustedRefusal`): a job the runner does not vouch for
  runs natively only when `Config.job_limits` is set, on a root runner. Phase 4 sets it once each
  job's cgroup has `memory.max` and `pids.max`; until then such jobs keep falling back.

Still to do in P5: the hostile-job tests (the fork bomb and the memory hog need P4's cgroups), and
the rootless part (a userspace network stack for the job's network, subordinate ids through
`newuidmap`), each its own pull request. Until the rootless part, a rootless runner never runs an
untrusted job natively.

### P6: services

- A job network namespace shared by steps and service containers, services as long-running
  namespace processes from the image store, health checks, `/etc/hosts` aliases, port mapping for
  host-mode jobs, and teardown with `cgroup.kill`.
- Exit: the services tests pass on native. Measure: "Initialize containers" time.

**Status: landed (behind the knob), on a root runner.** What it covers, as built:

- `runner/src/native/services.zig` is the runner's side: "Initialize containers" (`start`) and
  "Stop containers" (`stop`), which `dagger/services.zig` hands over when the job is native (two
  lines), with the Dagger path's log lines and its spec evaluation (`serviceSpec`) reused.
  `native/health.zig` is the helper's side of readiness, `native/images.zig` the image source,
  `native/forward.zig` the port relay. `sandbox.zig` gained a `service` field on its spec, an
  `exec` field (an image's entrypoint is looked up in its PATH; a step's shell stays `/bin/sh`),
  and `Running.stop`, which stops a helper that has not started yet as soon as it does.
- **A service is a sandbox like a step's, run until stopped**: the same helper, a fresh overlay
  over the image's filesystem (its writes go with the job), its own mount, PID, UTS and IPC
  namespaces, the job's range of ids (its root is nobody on the host), Docker's capabilities, the
  seccomp filter and `no_new_privs` as for a root step, a /dev, /proc and /sys as a step's. Its
  first process is PID 1 of its namespace: its entrypoint and command as the image says, its env
  the image's, then `GITHUB_ACTIONS` and `CI` (as the Dagger path sets them), then `env:`, its user
  the image's `USER` resolved in the image's own /etc/passwd and /etc/group, its working directory
  the image's (made when missing).
- **The job's network is shared**: services join the job's namespace, as steps do. A step reaches
  a service by name (`postgres:5432`: the job's hosts file, the host's with a line naming the
  loopback for every service, bound over the image's in every step and every service) and on
  `localhost` at each published port. A port published as itself (`5432:5432`, `6379`) is the
  service's own listener; one published under another number (`15432:5432`) is relayed by
  `forward.zig`, a helper in the job's namespace that binds 127.0.0.1 and ::1 and then becomes the
  job's `nobody` with `no_new_privs`. A bare port keeps its own number, as on the Dagger path (on
  GitHub it gets a random one, which `job.services.<id>.ports` reports either way).
- **Ready** as on GitHub when a health check passes: `--health-cmd` with `--health-interval`,
  `-timeout`, `-retries` and `-start-period`, over the image's `HEALTHCHECK` (`CMD` and
  `CMD-SHELL`; `NONE` and `--no-healthcheck` turn it off). The check runs inside the service: the
  helper forks it, so it is in the service's PID namespace (a fork fails once the service is gone,
  so no other process can be joined), its mount namespace and root, with its user, env,
  capabilities and filter, its output dropped as Docker keeps it out of the logs. Failures count
  as Docker counts them (once an interval, after the start period, unhealthy after `retries` in a
  row), but the helper tries from 10 ms, doubling up to the interval, so a database up after
  three seconds is ready after three seconds. Without a health check a service is ready when its
  published ports accept connections on the job's loopback (the Dagger path's `start` waits so;
  5 minutes at most); with neither, once started. The answer is one line the helper writes to a
  file of the job's, outside the service's root, which the runner reads every 10 ms. An unhealthy
  service, or one that ends first, fails the job before its steps, with its output so far.
- **Stopped** in "Stop containers" (after the post scripts), all at once, then each one's output
  printed, as GitHub prints `docker logs`. Stopping closes the helper's lifeline and the helper
  kills the service's PID 1, and with it everything in its PID namespace, as `docker rm --force`
  does. However the job ends, `Backend.deinit` stops them first, so their layers and the job's
  network go with the job; the runner dying closes every lifeline too.
- **The images** are pulled by P3 (`Backend.pullImage`, with the service's `credentials:`), the
  configuration read from the store's `config.json` (`images.fromPulled`). Before P3 they came
  from a directory an operator filled (`RUNNER_NATIVE_IMAGES`, now gone); the tests and the
  real-images root test still use such a directory (`Config.images`), one entry per reference
  with each `/` as `+`, holding `rootfs/` and `config.json`.
  `.github/scripts/native-service-images.sh <dir>` makes one for CI, and shows how:

  ```
  docker create --name x postgres:17-alpine
  sudo mkdir -p images/postgres:17-alpine/rootfs
  docker export x | sudo tar -x -C images/postgres:17-alpine/rootfs   # owners kept
  docker image inspect --format '{{json .}}' postgres:17-alpine > images/postgres:17-alpine/config.json
  ```

  An overlay layer's path may not hold a `:` (overlay's separator): the service's layer is a link
  in the job's directory (`V<n>/I`), so the image's own path never reaches overlay's options.
- Falls back to Dagger, with the reason in "Set up job": a rootless runner (services there would
  share the host's network, so it is not configurable; the tests have a switch of their own), no
  `RUNNER_NATIVE_IMAGES`, an image given by an expression, or one the directory does not have.
  `options:` the native path does not carry out are reported as on the Dagger path ("Service
  options not supported and ignored"); `volumes:` too.
- Tests (`services.zig`): the end-to-end job (two services, reached by name, relayed and plain, a
  health check and a port probe, env, the log, teardown) runs rootless and as root; an unhealthy
  service and one that ends first fail the job; as root, the host knocks on the job's addresses
  while a service listens and is not let in; and as root on CI, `postgres:17-alpine` and
  `redis:7-alpine` from real images, health-checked with `pg_isready` and `redis-cli ping`, reached
  by name, on `localhost` and through the relay.

What it does not do yet, and where it is paid:

- **Resource limits and `cgroup.kill`**: services, like steps, have no cgroup before phase 4,
  which puts them in the job's and stops them with `cgroup.kill` (the lifeline does it now).
- **The image pull**: phase 3. Until then a missing image sends the job to Dagger, and private
  registries' credentials are not used.
- **Rootless services**: they need the job's own network, phase 5's userspace stack.
- **One port space per job**: services and steps share the job's loopback, so two services that
  listen on one port cannot both run (the second fails to start, and the job with it), and a step
  cannot listen on a service's port. On GitHub each container has its own. A namespace per service
  joined by a bridge inside the job would lift it; no workflow of ours needs it yet.
- **Smaller ones**: the health check stops once it has decided (GitHub reads it only at start;
  Docker keeps checking); `job.services.<id>.network` says `dagger`, as on the Dagger path;
  `--health-start-interval` is read as nothing (the quick tries cover it).

#### Measured (laptop "cowbird", balanced profile, 2026-11-01, other agents building alongside)

"Initialize containers", from its start to every service ready, through the whole runner path
(`dagger.run`), the runner built `Debug`:

| | native | Dagger |
|---|---|---|
| `traefik/whoami`, ready on its port, rootless (median of 5, load average about 6) | **21 ms** | not yet taken (below) |
| two fixture services, a health check and a port probe, rootless | 67–78 ms | |
| `postgres:17-alpine` and `redis:7-alpine`, health-checked, root, GitHub's hosted runner | 3.1 s | |

The postgres figure is mostly postgres's own first start (`initdb`, its set-up server, then the
real one); the sandbox's part is about the 21 ms above. Dagger's side is the test "Initialize
containers against Dagger's", run by hand with a v0.21.10 engine container
(`ZIG_RUNNER_MEASURE_SERVICES=<images> ZIG_RUNNER_MEASURE_ENGINE=<container>`); the agent that
built this phase was not allowed to start one on the laptop, so that figure is still to be taken.

### Job container options

What a `container:` job's `ports:`, `volumes:` and `options:` do on GitHub's runner, and what a
native job does with them. GitHub's runner builds `docker create` for the job container (name,
network, `--workdir /__w`, `-e` for the container's `env:`, `-p` for `ports:`, `-v` for `volumes:`
and its own mounts), appends the `options:` string after those, and runs every step with
`docker exec -w <directory>`. The runner waits for health on service containers only. (That is the
runner's behaviour as remembered, not re-read for this change.)

`runner/src/native/container_options.zig` reads `options:`. A native job carries out or accepts only
the flags below; **any other flag, a stray word, or an `options:` with an expression in it sends
the job to Dagger, naming the flag in "Set up job"**. Dagger reads none of `options:`, so a flag
sent there is dropped, not carried out, and the note says so (it also logs a warning, #368). A
`--user` the image does not know (a name or group missing from its `/etc/passwd` or `/etc/group`)
fails the job, as `docker create` does, instead of falling back to run as root.

| Flag | Native job |
|---|---|
| `--env`/`-e NAME=value` (also `--env=`, `-eNAME=value`) | Carried out: set in the base environment before the container's `env:`, which wins over it (`DockerCommandManager.DockerCreate` puts the `options:` string on the command line first and the `-e` of `env:` after it), and so does the job's own `env:`, as over `docker exec -e`. `-e HOME=...` has no effect: GitHub's runner sets `HOME=/github/home` after the options (`ContainerOperationProvider.cs`); natively a step's HOME is the image's (as on Dagger, which does not set `/github/home` either), and the flag is counted among those without effect. A container's own `env: HOME` is honoured natively, where GitHub overwrites it with `/github/home` too: not matched. A bare `-e NAME` is refused: it copies the *runner's* variable. |
| `--user`/`-u` (`name`, `uid`, `name:group`, `uid:gid`) | Carried out: resolved in the image's own `/etc/passwd` and `/etc/group` as its `USER` is, over it. Refused on the runner's default image, whose step user is `RUNNER_STEP_USER`'s choice (that provisioning is not the container's). A rootless runner maps only root, so there it fails as an image `USER` does. The base makes `/__w` (workspace, `_temp`, the tool cache) as root and gives it to that user (the tool cache only when it is not that user's already, so an image's large `/opt/hostedtoolcache` is not copied up): GitHub mounts `/__w` from the host, so an image never has to carry a writable one. |
| `--workdir`/`-w` | Understood, no effect: every step is `docker exec -w`, native steps take the same directory. Counted in "Set up job". |
| `--health-cmd`, `--health-interval`, `--health-timeout`, `--health-start-period`, `--health-start-interval`, `--health-retries`, `--no-healthcheck` | Understood, no effect: nothing waits for a job container's health. Durations and counts are checked as Docker reads them; one it would refuse is refused. |
| Everything else: `--cpus`, `--memory`, `--privileged`, `--cap-add`, `--security-opt`, `--device`, `--gpus`, `--ulimit`, `--shm-size`, `--network`, `--add-host`, `--dns`, `--hostname`, `--init`, `-t`/`-i`, `--entrypoint`, `--name`, `--label`, `--platform`, `--pull`, `--read-only`, `--tmpfs`, `--sysctl`, `--pid`, `--ipc`, `--userns`, `-v`/`--mount`, `-p`, `--env-file`, `--group-add` | Refused (Dagger). Each changes the container: limits, privileges, devices, networks and mounts are the sandbox's (`sandbox.zig`, `seccomp.zig`, `nft.zig`, the cgroup code), which this does not touch. |

`volumes:` and `ports:` are read from GitHub's runner (`ContainerInfo.cs`, `DockerCommandManager.DockerCreate`
and `ContainerOperationProvider.cs` at actions/runner 5ba50443, read with `gh api` for #352): a
`volumes:` entry is `target`, `source:target` or `source:target:ro` (and `target:ro`; any other
third part is dropped, never passed on), handed to `docker create` as `-v`, and a `ports:` entry
is handed to it as `-p`. The runner always adds `/var/run/docker.sock`, the work, tool, temp,
actions and externals directories and `/github/home` and `/github/workflow` itself. A volume at
`/` only gets a warning from the runner.

**`volumes:` carried out: anonymous.** An anonymous volume (`- /data`) is a directory of the job's
filesystem: the base makes its mount point (`Backend.containerVolumes`, one `mkdir -p` after the
work root is made and handed to the step user, in the base's key), root's as Docker makes a new
volume's mount point, and what the image has there stays, which is where a Docker volume starts.
Every step sees it, so a file one step writes is there for the next, and it goes with the job (the
job's layers are removed when it ends). No mount is made.

**`volumes:` carried out: named, kept between jobs as Docker's are** (decided 2026-11-08). A named
volume (`- cache:/cache`, `- cache:/cache:rw`, `- cache:/cache:ro`) is a directory of the native
store beside the cache volumes, `volumes/<owner>/<repository>/<scope>/named/<name>`
(`volumes.namedKey`, `openNamed`), bound at its target in every step:

- **Trusted jobs only, scoped by repository.** Docker's volumes are one namespace for the whole
  host. Here a name is its repository's, and only a job the runner vouches for, in scope `repo`
  (`set_up.packageCacheScope`), gets one, because a volume holds what one job left for the next,
  which reads it as its own. **A job the runner does not vouch for, and a fork's pull request on a
  runner that vouches for pull requests (scope `untrusted`), fail** in "Set up job", naming the
  volume and saying that an anonymous volume (`- /path`) lasts as long as the job: kept per
  repository in an `untrusted` scope, one fork's pull request could plant files the next fork's runs,
  and each would hold store space no review let in (refused rather than keyed per fork and pull
  request number, as #420 refuses host paths and #423 ports to those jobs). A workflow that shares
  a volume between repositories on Docker gets one per repository.
- **Filled from the image when new**, as Docker copies the image's files into a volume
  (moby `daemon/create_unix.go`, `populateVolume`, and `daemon/container/container_unix.go`,
  `copyExistingContents`): what the image has at the target (its files, owner and mode, by `cp -a`
  in a sandbox of the job's image, as the job's root, whose layer is dropped) goes into a volume
  this job made, and never into one that exists, so what an earlier job left is never written over.
  Docker copies into any *empty* volume; here only a new one is filled, so a volume a job emptied
  stays empty. An image without `cp` and with files at the target fails the job in "Set up job",
  and the volume is removed again so the next job fills it.
- **Shared by jobs at once, as Docker's are.** Each job holds the volume's lock shared to its end,
  as a cache volume's (an eviction takes only one no job holds). A new volume is held exclusively
  while it is filled, so a second job opening it meanwhile waits for it whole; an open never waits
  for a job that holds it shared, and never for good: it polls the lock (`LOCK_NB`) for at most the
  filling's limit plus a minute, and gives up at once when the job is cancelled (`volumes.Wait`),
  failing the job saying why. The filling itself is stopped after 10 minutes, or at the job's
  cancel (`Backend.SeedWatch`), the volume removed so the next job fills it. Two jobs writing the
  same files at once race as two containers on one Docker volume do.
- **Ids**: a cache volume's (`Bind.volume`): owned on disk by the volumes' range on a root runner
  and seen through an idmapped mount as the job's own ids, the same in every slot, never the host's;
  nosuid and nodev. `:ro` binds it read-only (`MOUNT_ATTR_RDONLY` with the rest, in one
  `mount_setattr`), checked in `/proc/self/mountinfo` by the tests.
- **Evicted as a cache volume is: unlike Docker's, a named volume can disappear.** It counts
  toward `RUNNER_NATIVE_VOLUMES_MAX_MB`, and goes, least recently used first, when the volumes are
  over that cap and it has not been used for a day, or when the disk is under its floor
  (`RUNNER_NATIVE_MIN_FREE_PCT`) and it has not been used for an hour ("Eviction", above). The next
  job then gets it new, filled from its image again. What a workflow keeps in one must be something
  it can make again; anything that must last belongs in an artifact, a cache action or a host path
  an operator allows. **No cap of its own**, on purpose: a job that fills a named volume can evict
  only volumes no job holds that were not used for a day (over the cap) or an hour (under the
  disk's floor), never one in use, exactly as it could by filling one of its cache volumes (`pip`,
  `npm`, a tool cache), which every trusted job already has. A separate cap would not stop that,
  and only untrusted jobs could make the difference, which now get no named volume.
- **Nesting**: a named volume may not be inside another named volume, nor be nested with a host
  path (the job fails in "Set up job", naming both): the inner one's mount point would be made by
  the step's helper through the outer bind, in a directory jobs write (with `RESOLVE_NO_XDEV` it
  would fail the step anyway). An anonymous volume inside a named one, or a named one inside an
  anonymous one, nests as Docker's do.
- **Step caching is off** for a job with a named volume: what a step read from it or wrote to it
  is in no key and no layer, so a replay would stand for a run against other contents and leave the
  volume as it was. "Set up job" says so.

"Set up job" says how many volumes were made as directories, how many are named, in which scope,
and how many were new.

**`volumes:` carried out: host paths, off by default** (`/srv/data:/data`, `/srv/data:/data:ro`;
`runner/src/native/host_paths.zig`, `Backend.hostVolumes`, `sandbox.bindHostIn`). A job may bind a
host directory only when the operator allows it, and only on a root runner:

- **`RUNNER_NATIVE_HOST_PATHS`** (`--native-host-paths`): colon- or comma-separated absolute
  directories; empty, the default, allows none. A job may bind one of them or a directory below
  one. Each is canonicalised with `realpath` when the runner starts, and **the runner refuses to
  start** (`config error: RUNNER_NATIVE_HOST_PATHS: ...`, naming the entry) when one does not
  exist, is not a directory, is `/`, resolves under `/proc`, `/sys`, `/dev` or `/run` (the Docker
  and systemd sockets live there), is, holds or lies inside one of the runner's own paths
  (`RUNNER_NATIVE_STORE`, which holds every job's layers and volumes, `RUNNER_NATIVE_ROOTFS`, the
  log spool `RUNNER_LOG_SPOOL_DIR/zig-runner-<uid>`, the runner's own executable, the directory of
  `GH_APP_PRIVATE_KEY_FILE`, systemd's `$CREDENTIALS_DIRECTORY`, and the env files the deploy files
  use, `/etc/zig-runner.env` and `/etc/zig-runner-deploy.env`), or **is on a mount without
  `nosuid` and `nodev`**. A job reading or writing the runner's paths could read its secrets or
  change other jobs. The mount must be `nosuid,nodev` on the host, not only in the job: the job's
  root can make a setuid file in a directory it writes, and a host user running it from the host's
  mount would get the volumes' ids (which own every job's cache volumes). Mount the filesystem
  with `-o nosuid,nodev`, or bind the directory onto itself so (`mount --bind /srv/data /srv/data
  && mount -o remount,bind,nosuid,nodev /srv/data`, or `Options=bind,nosuid,nodev` in a systemd
  mount unit). A **rootless runner refuses to start** with the setting, and fails a job that asks
  for one: its jobs' root is the runner's own user on the host, with no idmapping, so a job would
  write as the runner and could change its files.
- **The list is the one checked at start.** Each job holds it to what the runner checked then
  (`host_paths.recheck`): an entry whose path now resolves elsewhere (a symlink repointed), or is
  another directory (its device and inode changed: moved, replaced, remounted), or whose mount
  lost `nosuid`/`nodev`, is closed for that job, and "Set up job" names it. The setting is never
  read again, so a list can never become wider than the one the runner started with.
- **Untrusted jobs never get one**, whatever the list says: a job the runner does not vouch for
  (`trust.vouches` false), and a fork's pull request on a runner that vouches for pull requests
  (scope `untrusted`, `set_up.packageCacheScope`), fail.
- **What a refusal says.** The job's source is checked as written, lexically (`.` and `..` taken
  out), against the list before anything of it is looked at on the host, and every refusal of a
  source (outside the list, through a link out of it, missing, not a directory) is the same
  sentence naming the source and the allowed list only, so a job cannot use it to learn what
  exists on the host or where a link points.
- **Symlinks**: the job's source is then resolved with `realpath` and checked against the list
  again, so a link inside an allowed directory that points out of it is refused. The step's helper
  then opens that canonical path from `/` with `openat2(RESOLVE_NO_SYMLINKS)`, so a link swapped in
  after the check fails the step instead of escaping, and checks with `fstatfs` that what it
  opened is on a `nosuid,nodev` mount.
- **Targets**: a host path may not be nested with another volume of the job, anonymous, named or
  another host path (one inside the other, as written: the job fails, naming both), nor overlap
  the runner's own mounts (as every volume). A job may list host paths and named volumes side by
  side. The helper, still the host's root on a root runner, makes every bind's mount point in
  the job's overlay before the first bind, through no mount (`RESOLVE_NO_XDEV`), and then finds
  each cache volume's and host path's target through no mount either: one that resolves into
  another bind, through a symlink of the image's (`/y -> /x`, with `/x` a host path and `/y/z`
  another), fails the step. Otherwise it would make and `chown` a directory inside the host
  directory on the job's behalf.
- **The mount**: an `open_tree(OPEN_TREE_CLONE)` of that directory alone (no mount below it comes
  along), `nosuid` and `nodev` always, `ro` for `:ro`, set in one `mount_setattr` and moved into the
  step's mount namespace only (the host's mount table never has it). Directories only: a file (a
  socket) is refused. On a root runner it is made before the job's user namespace is entered, so
  the job cannot remount it writable, suid or dev (the kernel locks those flags; the tests try).
- **Ids** (the decision): on a root runner the mount is **idmapped as a cache volume's**, through
  the volumes' range (`Backend.volumeIdBase`, `RUNNER_NATIVE_SUBID_BASE + 250 * 65536`, by default
  1916384000): a file owned on disk by that id plus *n* is the job's id *n*, the same in every slot,
  and **every other id, host root's and the host users' included, is `nobody` (65534) to the job**.
  So a job reads what the modes let others read, and writes only where the operator gave a
  directory to that range (`chown -R 1916384000:1916384000 /srv/data` makes it the jobs' root's);
  what it writes is owned by the range, never by a host user, so it can never leave a file a host
  user owns. Not Docker's default, where the container's root is the host's root; that is not
  given to a job here. Where the filesystem cannot be idmapped (the kernel refuses with `EINVAL`:
  NFS, ramfs; ext4, xfs, btrfs and tmpfs can on the Ubuntu 24.04+ and Raspberry Pi kernels this
  supports) **the step fails**, naming `RUNNER_NATIVE_HOST_PATHS_UNMAPPED`, and is not sent to
  Dagger. **`RUNNER_NATIVE_HOST_PATHS_UNMAPPED=true`** (`--native-host-paths-unmapped`; off by
  default, said in "Set up job" either way) binds such a filesystem with the host's ids as they
  are instead: host ids are still `nobody`, and what a job writes is owned by its slot's ids
  (`RUNNER_NATIVE_SUBID_BASE + slot * 65536 + n`), which the next job in that slot has too.
- **Refused natively, not sent to Dagger**: a host path the list does not allow fails the job in
  "Set up job" with the reason, naming `RUNNER_NATIVE_HOST_PATHS`, and so does a refusal of the
  step's helper while it binds one. This follows the convention of this section for what the
  native job understands and will not do (an unknown `--user`, a volume over the workspace: both
  fail the job), not the one for what it does not carry out (those go to Dagger). Sent to Dagger,
  the volume would be ignored with a warning and the job would run without the directory it asked
  for.
- **Step caching is off** for a job with a host path: its contents are in no key and no layer.

**Refused (the job goes to Dagger, with the volume named in "Set up job", as an `options:` flag is).**

| `volumes:` entry | Why |
|---|---|
| `:ro` on an anonymous volume (`/data:ro`), in either spelling | An anonymous volume is a directory of the job's overlay, not a mount, so it cannot be read-only on its own. A named one and a host path's can (above). |
| A named volume the job's `services:` list a volume for | A native service mounts no volume (it logs "Service volumes are not supported and were ignored"), so the volume would not be shared as it is on GitHub. An anonymous volume is the job container's alone, and is native whatever the services list. |
| One name at two targets, or two volumes at one target | Docker refuses the second; the first would need a bind to be one directory in two places. |
| A target that is relative, has a `..`, is `/`, is under `/proc`, `/sys` or `/dev`, or is a directory the runner mounts itself (`/__w`, `/__t`, `/__e`, `/github/home`, `/github/workflow`, `/var/run/docker.sock`) | Docker refuses them or they are the sandbox's. |
| A source that is not a Docker volume name (`[a-zA-Z0-9][a-zA-Z0-9_.-]+`), a part that is empty, more than three parts, or a list with an expression in it | Docker refuses them, or the list is decided before expressions are evaluated. |

A volume where the runner binds or makes something itself (the workspace, `RUNNER_TEMP`, a cache
volume's mount) fails the job in "Set up job", naming both, as it would hide one or the other.

**`ports:` stay on Dagger.** On GitHub they publish the container's ports on the *host* (`-p`), so a
client outside the container can reach them. Checked whether they can reuse what services use
(`startRelay`, `forward.zig`): they cannot. The relay listens *inside* the job's network namespace
and forwards to a service's port, which is how a non-container job on GitHub reaches a service
published on the host; for a job container the steps run inside the container and reach their own
ports on loopback already, and what `-p` adds is a way in from outside the job. The runner's table
refuses that by design (`nft.zig`: `output` is "to the bridge, replies only. No process of the
host's reaches a job"), so carrying it out means a DNAT or a listener in the host's network
namespace, an `nft` rule that admits it, and a policy for which host addresses and ports a
workflow may take. That is new isolation and network logic, and is not done here: the job goes to
Dagger, with the reason in "Set up job".

- **An `options:` that is an expression** (`${{ matrix.options }}`): decided before expressions
  are evaluated. Reading it after, with the same parser, is possible; not done here. The same for a
  `volumes:` list with an expression in it.
- **The Dagger path carries out none of the three on a job container** (`job.container`'s
  `options`, `ports` and `volumes` are read nowhere under `runner/src/dagger/`), but since #370 it
  logs a `##[warning]Job container options/ports/volumes not supported here and ignored: ...` for
  each one set. The reasons above end with the same fact, "Dagger ignores a job container's
  `volumes:`", so a reader of "Set up job" does not take them for applied. With
  `RUNNER_ENGINE=none` such a job fails with the reason instead.

Services' `options:` are unchanged: they still log the flags they do not carry out and go on
(`services.zig`), as the Dagger path does. Making them refuse as the job container's do is a
separate change.

Tests: the flag table, in every spelling Docker reads, and a refusal for each of 35 flags in three
spellings (`container_options.zig`); the volume grammar as GitHub's runner reads it, a refusal for
each entry above, and `unsupported`'s reasons for ports, volumes (with and without services),
options and expressions (`container_options.zig`, `Backend.zig`); a native job with `--user app -e
... --workdir ... --health-*` that runs as the image's `app` user with the options' env over the
container's, a native job whose anonymous and named volumes are there for every step, and one whose
volume clashes with the workspace fails in "Set up job" (root runner, in CI). Named volumes
(`volumes.zig`, `evict.zig`, `Backend.zig`): kept between opens and new only the first time, apart
for another scope or repository; a second open waits while a new one is filled and then shares it,
but only so long and not past a cancel,
and one whose filling failed is made again; one in use survives an eviction and an unused one goes;
and as root, across real jobs: kept between jobs, filled from the image (owner and mode too) only
when new, apart for another repository, refused for a fork's pull request and for a job whose ref
the runner does not vouch for (`Config.vouched` false) with nothing left in the store, `:ro`
refusing writes, remounts (`ro` to `rw`, to `suid,dev`) refused, both mounts nosuid and nodev in
`/proc/self/mountinfo`, and a filling that does not end stopped at its limit and the volume filled
by the next job. Host paths
(`host_paths.zig`, `Backend.zig`): the setting's separators, symlinks resolved, and each refusal
(relative, missing, a file, `/`, `/proc`, `/sys`, `/dev`, `/run`, the store, inside it, above it);
a job's source allowed in the list and below it, through a link that stays inside, refused through
one that leaves, outside it, and with none allowed; and as root, real jobs: an allowed directory
read and written (the host's file `nobody`'s to the job, the job's file the volumes' range's on the
host), a second bind `:ro` refusing writes, both `nosuid,nodev` in `/proc/self/mountinfo`, and
remount attempts (`ro` to `rw`, `nosuid,nodev` to `suid,dev`) refused and the mounts unchanged, and
failures naming the setting for a path outside the list, a link out of it (saying the same, naming
not where it points), a mount below the list without `nosuid`/`nodev`, a host path nested with
another volume, a fork's pull request and a job whose ref the runner does not vouch for
(`Config.vouched` false, as `configFor` makes it), and an empty list; a host path reached through
the image's symlink into another one fails, and nothing is made in the first; a ramfs (no
idmapping) refused without `RUNNER_NATIVE_HOST_PATHS_UNMAPPED`, and written as the slot's ids with
it; and rootless, any host path refused. Unprivileged: a symlink swapped in after the check fails
the helper's open, an entry on a mount without `nosuid,nodev` is refused at start, an entry
repointed or replaced since the start is closed for the job, and the runner's App key directory
and executable directory are refused. Both kinds in one job (root): a named volume and a host path
side by side, each with its own contents, and a host path inside the named volume refused, naming
both.

### P7: Docker actions

- Image-based actions as a run in their image with an entrypoint, on the P3 image store.
- Dockerfile actions need a builder. Options to weigh then: a native Dockerfile interpreter for the
  common subset (`FROM`, `RUN`, `COPY`, `ENV`, `WORKDIR`, `ENTRYPOINT`) on the layer store, or
  keeping Dagger for that case alone.
- JavaScript actions move over here too, since they are scripts plus a runtime mount.
- Exit: the actions tests pass on native.

**Status: `docker://` steps landed (behind the knob); `uses:` Docker actions still go to
Dagger.** What it covers, as built:

- `runner/src/native/docker_action.zig` runs a `docker://` step as a sandbox in its image:
  `sandbox.Spec.Container` gives the helper a second overlay (the image's filesystem, idmapped on
  a root runner as the job's rootfs is, under a layer of the container's own that goes when the
  step ends, as `docker run --rm`), and binds into it, from the job's overlay, the four
  directories GitHub binds (`ContainerActionHandler.cs`): the workspace at `/github/workspace`,
  and `/github/home`, `/github/file_commands` and `/github/workflow`. The job's overlay gets a
  new layer as for any step, so what the action writes in the workspace, deletions included, is
  in the job's next step without a copy. The command is started as `docker run` starts it (the
  action's or the image's entrypoint, then its args or the image's command,
  `Exec.containerArgv`, looked up in the image's PATH; 127 with Docker's message when it is not
  there), in `/github/workspace`, as root, in the job's network, with the same capabilities,
  seccomp filter and `no_new_privs` as a root step.
- Everything the action is given is the Dagger path's, shared: `runImageStep` (inputs, `with:
  args` split as a command line, `with: entrypoint`), the log group with its `image:` line,
  `Exec.containerEnv` (the job's env without what GitHub sets again, the step's and the action's
  env, INPUT_*, `HOME=/github/home`, the runtime's variables and the OIDC token), and
  `Exec.collect` for the file commands. On top of the image's own `ENV`, as the container Dagger
  starts from has it. The shared code changed in two lines: `runContainer` hands the run to
  `docker_action.run` after the log group, and `dagger.run` asks `docker_action.unsupported`.
- `runner/src/native/images.zig` is the narrowest image interface the actions need: for a
  reference, its rootfs and the parts of its OCI config an action starts from (entrypoint, command,
  env, user). Since the integration with P3 a `docker://` image is pulled natively
  (`docker_action.find`, `Backend.pullAt`, before the job for `unsupported`). Before, and still in
  the tests (`Config.images`), it read a directory (`RUNNER_NATIVE_IMAGES`, now gone), one image
  per reference, keyed by the normalised reference with every byte outside `[A-Za-z0-9._-]`
  percent-encoded (`alpine:3.22` is `docker.io%2Flibrary%2Falpine%3A3.22`):

  ```
  k='docker.io%2Flibrary%2Falpine%3A3.22'
  mkdir -p "/var/lib/zig-runner/images/$k/rootfs"
  docker create --name zr-img alpine:3.22 && docker export zr-img |
    tar -x -C "/var/lib/zig-runner/images/$k/rootfs" && docker rm zr-img
  docker image inspect --format '{"config":{{json .Config}}}' alpine:3.22 \
    > "/var/lib/zig-runner/images/$k/config.json"
  ```

- Falls back to Dagger, with "This job runs on Dagger: ..." in "Set up job": a `docker://` image
  that is not in the store (or no store), and an image whose `USER` is not root (GitHub's
  documentation requires root for Docker actions; Dagger's path gives another user the
  directories it writes, which here needs an idmapped share, below). For `uses:` actions, see
  "The action loader" below.
- Parity kept explicitly: on a root runner with steps as the runner user, what the action made or
  changed in the workspace is given to the runner user afterwards (the files in the step's layer
  under the workspace, through no symlink), as Dagger copies the workspace back owned by it; a
  later step can change what the action wrote. The runner's markers and the event variable are
  not in the action's env, as the script's `env -u` leaves them out.

What it does not do yet, and who pays:

- **Local actions built from a Dockerfile.** Their tree is only in the workspace, spread over
  the job's layers, where the builder needs one host directory. They send the job to Dagger;
  debt of P7 (a build context read from the layers).
- **A local action that differs at run time from the job's commit** (a step rewrote it): the
  pre-flight judged the commit's. With every kind of action native, the only way that bites is an
  image the commit's version did not need and the store lacks: the step fails saying so, where
  Dagger would have pulled it. Gone with P3's pull.
- **Images with a non-root `USER`, and a `RUN` as one.** They need the shares idmapped so the
  image's user owns them, as Dagger's `owner:` does. Debt of P7.
- **The pull.** Images come from the operator's directory until P3's store replaces
  `images.lookup`.
- **Small differences from Dagger's path**, none visible to an action that follows GitHub's
  documentation: `/github/home` is in the job's filesystem (Dagger keeps it beside the job's
  container), `/github/file_commands` holds the earlier steps' files (Dagger's is empty per
  action, as is GitHub's per step), and a command that cannot be found prints Docker's message
  where busybox's `env` printed its own; both exit 127.
- **A secret in `with: args`** is in the action's own command line, readable by the host's users
  through `/proc/<pid>/cmdline`, as under Dagger (where busybox expands it into the command) and
  on GitHub (`docker run`). Nothing the runner does can hide a program's own arguments; secrets
  belong in `env:`.

**The Dockerfile builder** (`runner/src/native/dockerfile.zig`). `parse` reads a Dockerfile as Docker's parser
does (comments, parser directives, `\` continuations, either case, JSON and shell forms); `plan`
evaluates `FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `ENTRYPOINT`, `CMD`, `ARG`, `USER` and
`LABEL` into the image's config and one key per instruction, chained from the base's:
`sha256(parent key, instruction as evaluated, what it reads)`, where a `RUN` reads the env and
build arguments it sees and a `COPY` the content of its sources (`contextDigest`: a sorted walk
of paths, kinds, modes, link targets and contents, through no symlink). A config-only
instruction gets a key and no layer, so the `RUN` after it is keyed on it. `build` takes each
layer from the store by its key, or makes it (`COPY`/`ADD` by the runner, as Docker places
sources; `RUN` through a `Runner`, the sandbox) and publishes it (`layers.zig`, the stand-in for
P2's store: "the layer under K, or store this directory under K", by rename). It refuses, with
the line and why: multi-stage builds, `COPY --from`, wildcards, `ADD` of a URL or an archive,
`SHELL`, `ONBUILD`, heredocs, sources outside the context, and `--chown` by name.

The `Runner` is the sandbox (`docker_action.BuildRunner`): a `RUN` runs as a container whose
lowers are the image's layers so far, each idmapped on a root runner, and whose upper is the
build's new layer in the store (`Backend.execBuild`: the job gets no layer). What it writes has
the job's host ids; they are shifted back to the image's own afterwards (`unshift`), so a stored
layer is the same whichever job's range built it and can be idmapped into any job, as the
`COPY` layers the runner writes are. The built image runs as a `docker://` one does, with its
layers as the container's lowers. Layers live under `RUNNER_NATIVE_STORE/layers`, in P2's store,
each under the builder's key hashed with the store's format, the job's trust scope and how ids are
mapped (`layers.layerKey`): a job the runner does not vouch for, or a vouched fork's pull request,
builds its own layers and never leaves one a trusted job takes, and a root and a rootless runner's
layers never meet.

Such a layer is replayed: `build` takes it by key and nothing runs, whatever the action's step
does. So its key holds all it was made from. The chain starts from the base's reference and what
the image is (`docker_action.baseId`: the platform's manifest's digest, or the tree's fingerprint
for an image that was not pulled), since every pull asks the registry what a tag names and a tag
moves. Each instruction adds its kind, its text as evaluated and what it reads, in P8's format
(`dockerfile.fromKey`, `stepKey`, `contextDigest`): every field length-prefixed and every list
counted, so a source's content cannot pass for the entries after it.

**The action loader** (`runner/src/native/actions.zig`). The backend stays chosen per job, never
per step (a switch would need the native layers exported into Dagger). What a `uses:` action is
is in its `action.yml`, so before "Set up job", with nothing logged, `preload` fetches every
remote action of the job, composite actions' nested ones too, by git in the job's image into
the job's layers at the path Dagger mounts them (`/github/_actions/<owner>/<repo>/<ref>`): only
the commit, the job's token for its own repository and none for others, as Dagger's `git` does.
It runs in the base (`Backend.base`), once the job's image is pulled and provisioned and before
the base's own layer, so any image fetches with its own git (an image with none sends the job to
Dagger, whose git is its own). Each fetched tree is keyed by its repository, place and resolved
commit (`Backend.keyFetched`), not by when it was fetched: under step caching it is stored or
taken from the store like a step's layer, and the base and the steps above it keep their keys
from job to job. If one is something native cannot run yet (below), the job goes to Dagger with
the reason (`error.NativeToDagger`), and Dagger fetches again; otherwise "Set up job" takes them from the Backend (`Exec.loadAction`) and
logs "Download action repository ... (SHA:...)" as on Dagger. An action that cannot be fetched
is not a reason: native "Set up job" fails with it, as Dagger's does. Native runs Docker actions
(a `docker://` image, or built from the Dockerfile in the fetched tree, the context opened
through no symlink) and composite actions (their steps are the shared code's: scripts, nested
`uses:`, nested checkouts through `Backend.fetchCheckout`, `docker://` steps). In a container,
the job's binds go only where the image has the path.

**JavaScript actions.** The Dagger path's own code runs them (`js.zig`: `runJs`, `runJsScript`,
`jsEnv`, pre, main, post and `post-if`, `STATE_*`, the node, npx and npm shims, Node when Bun
refuses an action). What changed is where the runtime comes from: `js.runtimeFiles` answers the
runtime's files from the native image store (`oven/bun:1.4.3`'s or `node:24-bookworm-slim`'s
rootfs, as `js.runtimes` names them) as `host:<path>` ids, and the native backend now applies
Dagger's mounts (`Backend.applyMounts`): a new file (a shim) written into the step's layer, a
host file or directory bound read-only, nosuid and nodev into that step and every later one, as
Dagger's copy stays in the container. The runtime is pulled by P3 (`docker_action.find`). In a
musl image (`container: alpine`, told by an `ld-musl-*` in its /lib, `Backend.isMusl`) it is the
musl build of `js.runtimes_musl`, with the C++ runtime it needs copied from that image's
/usr/lib (`libstdc++.so*`, `libgcc_s.so*`), as Dagger's query filters it. A job whose
JavaScript action's runtime cannot be pulled goes to Dagger (`actions.preload`).

**Local actions.** `preload` judges a local action (top level or nested) from the job's own
repository at the job's commit, which is what a checkout of it gives: a blobless fetch of that
one commit by git in the job's image (the job's token, as the checkout's), and only its
`action.yml` read (`git cat-file`), then the look's layer dropped, so no unkeyed layer is left
below the base (`Backend.dropTop`). One that is not there (made by a step, another
repository checked out there) sends the job to Dagger. At run time the step reads the workspace,
as on Dagger (`actions.loadLocal`, through `Backend.readFile`).

**For P3 and P2, what to swap when they land:**

- P3's pull also serves the JavaScript runtimes: `js.runtimeFiles` calls `images.lookup` for
  `js.runtimes`' images; with the pull it gets them on a miss, and `preload`'s runtime check goes.
- P3's image store replaces `images.lookup(arena, io, dir, ref)`: return `Image{ rootfs, entrypoint,
  cmd, env, user }` for the reference, pulled when missing. `docker_action.unsupported` then needs
  no store check (an image is pulled, not refused) but keeps the `USER` check until the idmapped
  shares; `Config.images` and `RUNNER_NATIVE_IMAGES` go.
- P2's per-job helper: `sandbox.Spec.Container` is a field of the step's spec; the per-job helper
  takes it with the step and mounts the container's overlay in the step's own namespace (the
  job's overlay and its layer as for any step). Its layer store: the action's step always runs
  (it has the job token) and is never keyed or replayed, as on Dagger; its layer is the job's
  next one as any step's. The Dockerfile builder stores each instruction's layer under its key
  there: `layers.Store.get`, `begin` and `publish` become the store's lookup, a directory to
  build in under the key's flock, and the atomic publish.

**Measured** (laptop "cowbird", balanced profile, 2026-11-01, load about 3, rootless under
`unshare`, the runner built `ReleaseSafe`, `--exec-job`, plain `ubuntu:24.04` as the rootfs and
`alpine:3.22` in the image store, per step = (20-step job − 1-step job) / 19, median of 7):

| | native | Dagger |
|---|---|---|
| `docker://alpine:3.22` with `entrypoint: true` | **11.3 ms** a step (1-step job 32 ms) | not measured here, see below |
| `run: true`, same machine and load, for scale | 21.3 ms a step (1-step job 41 ms) | ~224 ms (P1) |

A Docker action costs less than a `run:` step natively: no bash and no step script, and the
image is a single small layer. On Dagger the same step is three queries (the workspace's
directory, the exec with the busybox script, the copy back) besides the image's `from`, so it is
at least the cold `run:` step's ~224 ms. Dagger could not be timed for this pull request: the
laptop's engine for this runner's Dagger version was stopped, and starting one was not done
without the user (the PR says how to take the figure).

### P8: remapping the Lean proofs

- The theorems keep their shape; the code they cite changes. The "a container *is* its recipe"
  row points at the native key chain instead of Dagger's lazy container id, and the runner now owns
  the obligation BuildKit discharged: the key is computed from exactly what the model says.
- `Output.digest` becomes the native layer digest; `OutputKeys.lean` needs it deterministic.
- `Logs.lean`'s hypothesis that the engine records stdout and stderr apart no longer applies if
  the native store records the interleaved stream; `exec 2>&1` may become optional.
- `Input.mounts` absent from the key holds by construction.
- Exit: `proofs/README.md` and the Lean files name native functions where they named Dagger's.

**Status: proved of P2's key format as P2 builds it (#268, with its review fixes in #272 at `28a9dd1`); the
Zig check runs P2's own code: `Store.KeyHasher` and `Store.stableEnv` for keys, `Backend.belowKey`
for the digest below a base, and `Store.treeDigestTo` on fixture trees for layer digests.**
`proofs/Runner/Native.lean` is the native backend's refinement of the model, beside Dagger's rather
than replacing it, since both backends ship (proofs/README.md, "On the native backend"):

- **The key.** A key is sha256 of `keyPreimage`, as P2's `Store.KeyHasher` and `Backend.keyFor`
  build it: a u64 tag (1 for a step's exec or a checkout's fetch, 0 for a base, 2 for an
  output-keyed container), the parent's key, the script's text, the count and bindings of the stable
  environment in the container's order (`Store.stableEnv`: the volatile names, `ZIG_RUNNER_EVENT`,
  `ZIG_RUNNER_RAN`, `ZIG_RUNNER_MARK` and `ZIG_SECRET_*` dropped), then the uid, gid, working
  directory and kept files, each field prefixed with its length as a u64 little-endian. A base has
  no parent: in its place is the untagged digest below it (`Backend.below`: the store's format
  `Store.store_format`, the trust scope, the repository, the rootfs's fingerprint, the userns mode,
  the binds; the slot's first id until stored layers took the canonical ids). `fork_keys_apart`: a
  fork's pull request (scope `untrusted`) and the repository's own jobs (`repo`) never ask the same
  key, so neither replays what the other stored; `userns_apart`: nor do a root and a rootless
  runner's jobs.
  The extras are not new inputs: a step's are its job's, fixed with the base (`Format.stepExtra`), and a base's are part of what the
  model's base is (`BaseSpec`). `encState_injective`, `belowPreimage_inj`, `encKey_injective` and
  `native_key_iff`: the format keeps exactly what the model's key keeps, so P2 and P3 hold of it;
  mounts and the event payload are no argument of it. `Ambiguous` is what plain concatenation would
  cost.
- **Replay.** The store records a success of an unmarked step and nothing else. Then every hit is
  honest, succeeded and unmarked by construction, and `native_replay_eq_run` is P1 under
  `Disciplined` alone: no `Numbered`, no `Ahead`, whatever other runners publish or evict between
  steps, and whichever reads fail. `native_eq_dagger`: the two backends give the same answers.
- **Concurrency.** Whole-entry operations in any order keep the store honest (`ops_keep_honest`);
  which of two racing writers wins does not matter (`race_irrelevant`), so the flock per key is
  about cost; an entry is read whole or is a miss (`readWhole_agrees`, `Torn`).
- **Layer digests.** A sorted walk of what a later step can see, nothing that differs between runs:
  `digest_deterministic` and `digest_injective`, which are what output keys need. `walk_injective`
  proves it of P2's walk as written (`Store.treeDigest`: paths, modes, owners, xattrs, a file's
  sha256, a link's target, a device's numbers, `..` after a directory), given one change P8 made
  to it: the xattrs are now counted, since without the count the last xattr and the content after
  it could not be told apart.
- **Logs.** A store that records the one pipe the step writes to replays the run without
  `exec 2>&1` (`Logs.native_replay`). The scripts keep it: one script for both backends.
- **The tie to the code.** `keyoracle` (`proofs/KeyOracle.lean`) writes
  `runner/src/native/testdata/step_keys.tsv`, `.github/scripts/key-vectors.sh` checks in the proofs
  workflow that it is the model's, and `runner/src/native/key_vectors.zig` checks the preimages
  (key vectors: steps, bases, the digest below a base, a Dockerfile build's keys; 4 layer vectors:
  modes, an xattr and a symlink, an opaque directory, a whiteout) and the equal/differ relation
  against it.
- **Keys on keys, and builds.** `ops_keep_chained`: no order of the stack's operations puts a key
  above a layer with none, so what an image or a mount added cannot be behind a replay.
  `encBuild_injective`, `encBuildLayer_injective`: a Dockerfile build's keys tell apart everything
  they hash; `build_base_matters`: a base image that changed under its reference changes every key
  of the build.

**What is left**: if P2's format changes, change `Native.encState` (and `keyPreimage`,
`belowPreimage`, `walkPreimage`) and `KeyOracle.lean` to match, keep `Format.Sound` proved, and
regenerate the vectors (`key-vectors.sh --write`). A format that sorts the environment, or drops a
length, a count or a tag, fails the vectors on purpose.

### P9: Pi validation, then the decision

- Run the full pool on the Pi (aarch64) and the laptop on native for a soak period: real workloads,
  hostile-job tests, cache growth, memory gate behaviour.
- Then decide: retire Dagger, or keep the hybrid. The revert criterion below makes that call
  mechanical.

## Revert criterion

We stop at the hybrid (native for what it covers, Dagger for the rest, nothing further ported) if,
after P2 and measured on real workloads on the laptop and the Pi:

- the median job's wall time improves by less than 10% against Dagger, and the replayed job by
  less than 50%; or
- runner CPU per job (engine plus runner) improves by less than 20% on the Pi; or
- native shows a correctness gap against Dagger that cannot be closed without reimplementing a
  BuildKit behaviour we cannot test (a parity failure with no clear fix), or a containment gap
  under P5's hostile-job tests.

We also stop porting any single phase whose cost, in the estimate it is given when it starts,
exceeds twice that estimate before it is half done; the jobs it would have covered stay on Dagger.

## Learnings

A running log. Each phase appends what Dagger did implicitly that had to be made explicit, what
surprised us, and the measured gains against Dagger.

### P0: the plan

- What the engine does for the runner is narrower than its API: one base container, one exec per
  step, and a file read per step. The runner already builds every step as a self-contained
  `sh -c` script (`scripts.stepScriptFc`) that brings its own markers and file commands, and reads
  the result back as one combined file. That is why the boundary can sit below the script: a
  native backend runs the same bytes and the shared code cannot tell the difference.
- The engine's cache key covers the script text, so the script builder was already written as if
  it were a public format (its comment says changing a byte re-keys every step). The native store
  inherits that discipline for free.
- Dagger's secrets (`setSecret`, `withSecretVariable`) exist to keep plaintext out of the engine's
  cache metadata (#101, #102). Natively there is no engine to leak into, but the step cache of P2
  will be: the same rule (secret-bearing values never in a key or a stored log) has to be kept
  explicitly by the native store.

### P1: run-only jobs

What Dagger (BuildKit and runc under it) did implicitly, now explicit in `native/`:

- **HOME.** runc sets HOME from the image's `/etc/passwd` when the env has none, so every root step
  under Dagger had `HOME=/root` without the runner ever setting it. The sandbox now reads it
  (`sandbox.homeOf`).
- **The resolver.** BuildKit puts the host's `/etc/resolv.conf` and `/etc/hosts` into every exec.
  Without them a step in the image's filesystem has no DNS. The sandbox binds them, only over
  files the image already has, since making the file would put it in the step's layer.
- **/dev, /proc, /sys.** runc builds a `/dev` of a few nodes, mounts `/proc` for the exec's PID
  namespace and `/sys` read-only. Binding the host's `/dev` (as the prototype did) would hand a
  root step the host's disks; the sandbox builds the small one.
- **Killing a step.** A BuildKit exec's processes die with it. Natively that comes from the step's
  first process being PID 1 of its own PID namespace, with `PR_SET_PDEATHSIG` tying it to the
  helper: killing the helper (through a pidfd, so a reused pid is never hit) takes everything the
  step started with it, background processes included, and closes the output pipe. The cancel test
  checks this with a backgrounded `sleep 60`. That kill is now the end of a ladder: see "Stopping a
  step".
- **Stopping a step.** A cancel, a `timeout-minutes` and a runner's stop all take one route,
  `dagger.Watch`, and on this backend it warns the step before it kills it (#379). What GitHub's
  runner does, read from actions/runner at 5ba5044:
  - `src/Runner.Sdk/ProcessInvoker.cs`: `_sigintTimeout` 7500 ms and `_sigtermTimeout` 2500 ms
    (lines 32-33), fixed: no setting or environment variable changes them.
    `CancelAndKillProcessTree` (443-465) sends SIGINT, waits for the process to exit or the
    timeout, sends SIGTERM, waits, and kills; it stops as soon as the process has exited.
    `SendSignal` (829-853) is `kill(_proc.Id, signal)`: the entry process alone, not its
    group. `NixKillProcessTree` (855-869) despite its name is `_proc.Kill()`, one process again:
    the tree goes only at the job's end ("Cleaning up orphan processes", `JobExtension.cs` 891-935,
    by `RUNNER_TRACKING_ID`). So `bash -e` waiting on a foreground child holds its SIGINT until the
    child ends, and the child never hears anything.
  - `ScriptHandler.cs:346` and `NodeScriptActionHandler.cs:173` pass `killProcessOnCancel: false`,
    so steps get the ladder. After it `cancellationToken.ThrowIfCancellationRequested()`
    (`ProcessInvoker.cs:369`) makes the step cancelled whatever the exit code; on a timeout it
    failed instead (`StepsRunner.cs` 322-337).
  - `always()` steps do not run on a cancelled token: each step has a token of its own, which the
    job's cancel cancels only when the condition, evaluated again, no longer holds
    (`StepsRunner.cs` 149-185). The worker itself is killed 15 s before the job's cancel limit,
    which is raised to 60 s first (`JobDispatcher.cs` 1280-1285).

  What this runner does:
  - **The ladder and its timing** are `Watch`'s (`sigint_ms`, `sigterm_ms`), on its 200 ms tick:
    SIGINT, SIGTERM 7500 ms on, the kill 2500 ms after that, each only while the step runs. The
    whole fits inside the job's cancel limit (`ladderMs`): with less time left it shrinks in
    proportion, a job past its limit gets the kill alone, an `if: always()` step at the limit
    starts its ladder early enough to end by it, and a second cancel, which can only bring
    `Cancel.hard_deadline_ms` forward, shortens a ladder under way and cannot lengthen it. The
    runner holds the time and not the helper for that reason. A SIGTERM or a kill that finds nothing,
    between two execs of a step, stays due. The ladder runs on the awake clock, so a wall clock stepped
    back cannot put it off. If the runner dies the lifeline closes, which is the kill. Nothing here
    is configurable, as on GitHub. GitHub's limit is taken as its runner takes it
    (`CancelWatch.cancelLimitMs`): 60 s at the least, less 15 s. One difference: there a later
    cancel can move the limit out (`CancelAfter`), and here it cannot.
  - **Who hears it** differs from GitHub on purpose: every process of the step, not one. A signal
    from outside to PID 1 is dropped unless PID 1 has a handler (`SIGNAL_UNKILLABLE`), and no call
    from outside reaches a namespace, so the helper forks one process, which lands in the step's
    PID namespace, for `kill(-1, sig)`: all but PID 1, sessions and process groups of their own
    included, in one act the kernel holds forks off from (`sandbox.Warning`). It lasts one system
    call, is not dumpable, and holds capabilities the step's bounding set does not, so a root step
    cannot trace it (no job can add one: `--cap-add` and `--privileged` are refused,
    `container_options.zig`). Its zombie is reaped at once, because PID 1 cannot finish exiting while one is
    left. A `bash` step's foreground child therefore dies of SIGINT, and the shell's trap runs
    straight away, where on GitHub it waits for that child. The cost: a wrapper that passes
    signals on (`timeout`, `npm`, `make`) has its child hear SIGINT twice, once from each, as
    Ctrl-C in a terminal does to a foreground group. A program that counts them, as Terraform's
    second interrupt means "exit now", then skips its clean exit. No choice of who to signal avoids
    it without losing the foreground child under a shell, which is the point of signalling all.
  - **PID 1** of a `run:` step is the `sh -c` around the step's shell, which is left alone: it
    reports the step's end, and where `sh` is bash it would act on the signal and end the namespace
    under a step still cleaning up. A Docker action's PID 1 is the action's own and is signalled as
    well, which is what `docker stop` does, including its being ignored without a handler.
  - **The end** is the kill that was always there: the lifeline closes and the helper SIGKILLs PID
    1. The kernel then stops the namespace's forks and kills all of it (`zap_pid_ns_processes`), so
    neither a process that forked away nor a fork bomb outlives it. A fork bomb at `pids.max` may
    leave the helper no process to warn with: it tries again every 20 ms and the kill needs no
    fork. `cgroup.kill` remains what it was, the job's end (`cgroup.Job.remove`): the cgroup is the
    job's, shared with its service containers and the next steps, so it cannot stop one step, and a
    step's cgroup of its own would hide `memory.max` from what a step reads there, for no process
    the namespace's end does not already reach.
  - **Once the step's shell has ended** the namespace goes, so a background process still cleaning
    up is killed then. On GitHub it would be left until the end of the job. A step that ends
    during the ladder is still cancelled, or failed on a timeout, whatever it exited with, as on
    GitHub, and its file commands are not read. Its layer stays, so what a trap wrote is there for
    `always()` steps. Every exec stopped ends with a code other than 0 (`sandbox.Ended`), whatever
    its script exited with, so nothing that keeps an exec's work on its code keeps a stopped one's:
    a `RUN` whose script exits 0 during a stop stores no layer, and a Zig seed or an action's
    fetch fails as a killed one did.
  - **The log** says why, in the step's own log, before `##[error]The operation was canceled.`:
    the reason (`Cancel.Why`: GitHub's cancel, the runner stopping, GitHub no longer having the
    job, or `Watch.reason` for a timeout or the job's limit), then each stage reached. It names
    the plan, not delivery: a warning the helper cannot fork for at `pids.max` is not sent. A job
    cancelled during a timeout's ladder reports the step cancelled, as GitHub does. Written once
    `Watch` has let go of its lock, so a stuck sink does not hold up a step's end, though the next
    stage waits behind it. Pre scripts
    have no log step of `Watch`'s. Each pre and post script gets a ladder of its own, and one
    stopped near the limit fails as a post script does, so the next still runs.
  - **After a cancel** nothing runs on a cancelled context: `dagger.Cancel` is a flag, read where
    work should stop (`Watch`, `hashFiles`, the tool tree check), and a call begun after it is not
    cut short. A job's cancel never cancels the job's task, so `if: always()` steps, post scripts,
    the log's flush, `completejob` and the uploads run on as they would. A task's cancel is
    another matter, and only a pool failing to start its runners sends one to a job: `std.Io`
    delivers it once, and two places lost it. `sandbox.finish` took it for the end of the step's
    output, then waited for the step, however long it ran; it now stops the step and delivers it
    again once the helper has gone. A sink's write and the spec's run protected from it, so the
    read gets it. `Backend.deinit` could lose its cgroup or its directory to it, and now runs
    protected from it.
  - **A second cancel from GitHub** is read: `CancelWatch` used to stop at the first, so a shorter
    limit in a second message never reached `Cancel.request`.
  - **Dagger and `RUNNER_ENGINE=cli` cannot do this.** A step there is a BuildKit exec: cancelling
    its context SIGKILLs the container's process (`runcProcessHandle` and `doKillProc` in
    `executor/runcexecutor/executor.go`, moby/buildkit at cedaeca), and `process.Signal`, the one
    way to send another signal, is the gateway API's: a Dagger `withExec` has no way to reach it.
    The script cannot stand in, since the step's text is its cache key and nothing reaches a running
    exec from the runner. `Transport.warnFn` is null there, so `Watch` aborts at once as before,
    and with `RUNNER_ENGINE=cli` (#315) the same, by dropping the query. A step on those backends
    still gets no warning; its `always()` steps run as they did.
- **Secrets out of command lines.** Under Dagger the reason for `withSecretVariable` and secret
  mounts was the engine's cache metadata. Natively the same discipline matters for another reason:
  `/proc/<pid>/cmdline` is readable by every user on the host. Keeping the identical script
  (aliases in `$ZIG_SECRET_<n>`, a script holding a secret written as a file, the spec over a pipe)
  keeps secrets out of every command line.
- **The container's env between steps.** Dagger's container carried `GITHUB_ENV` and `GITHUB_PATH`
  forward, with `$PATH` expanded by the engine (`withEnvVariable(expand: true)`). That state is
  now the backend's (`applyPendingEnv`), and the parity test checks the base env against Dagger's
  base query, variable by variable.
- **Overlay's work directory.** Overlay leaves `work/work` with mode 0; rootless, nothing can
  delete it until the runner gives the permissions back. Every leftover job directory in the first
  runs was this.

Surprises:

- The boundary was smaller than planned: three call sites in the shared code, plus `Secrets.local`
  (secrets named without a session) and an optional field on `Fetched` for the checkout's log line.
  No Dagger code path changed behaviour, and no existing test changed.
- Making a user namespace is the cost that matters. `unshare -r -m true` costs 6.3 ms on the
  laptop, a third of a native step. The prototype paid it once per job by re-executing itself under
  `unshare`; P1 pays it per step. P2 starts by keeping one helper per job.
- Ubuntu's AppArmor restriction on unprivileged user namespaces means a rootless runner cannot make
  a usable one itself: the namespace is created, but writing its uid and gid maps is refused
  (EPERM, checked on the laptop), so the runner's user never becomes root inside and owns none of
  the image's files. Borrowing `unshare` works because of the stock profiles; a profile of our own
  is the clean answer and a deploy decision.
- Tests needed the runner binary, because the sandbox is the runner started as a helper, and Zig's
  test runner refuses arguments of ours. The build copies the binary to a fixed place for the tests
  (`ZIG_RUNNER_TEST_EXE`), and the tests build a rootfs of a few directories with the host's `/usr`
  bound in, so CI needs no image.
- The engine's direct session cannot export a container's filesystem: it implements file sync for
  reads only. That is why P1's rootfs is made by the operator, and it is a reason to move P3 (the
  native pull) before the cache-volume work.

Measured against Dagger: a cold trivial step 18.1 ms against ~224 ms, about 12 times faster, about
206 ms saved per step, through the whole runner. Replays come in P2.

### P1, after review: what the first cut got wrong, and the hardening

An independent review of the first cut found two merge blockers and a dozen smaller faults; the
user then pulled the job's ids, its network and the sandbox hardening into P1. What it taught:

- **The kernel clears the parent-death signal on a change of credentials.** The first cut set
  `PR_SET_PDEATHSIG` in the step's PID 1 and then called `setuid`: on a root runner with the runner
  user, a timeout killed the helper and left the step running on the host, holding the log pipe,
  so the job hung. The fix is not to depend on it: the helper itself kills PID 1 when its lifeline
  (stdin) closes, which also covers the runner dying (M6), and PID 1 re-arms the signal after
  `setuid` and checks, through a pipe, that the helper is still there. Lesson: a death signal is a
  backstop, never the mechanism.
- **Root on the host is the wrong default for a step.** Running steps as host root (in a chroot)
  or as host uid 1001 made every escape a host privilege. A dedicated range per job, as Docker's
  userns-remap does, makes the step's root nobody outside; the cost was learning that only a
  process outside a user namespace may write a map wider than its own id (a child unshares, the
  parent maps it, the namespace is kept by its file descriptor).
- **Idmapped mounts beat a copy per range.** Each slot's range needs the rootfs owned by that
  range. A shifted copy would be 600 MB per slot; an idmapped mount of the rootfs (Linux 5.19 lets
  overlay take one as a layer) costs nothing, with the overlay mounted as the host's root and the
  helper entering the job's namespace afterwards. Mounting the overlay inside the namespace instead
  would have needed the files owned by the range.
- **Locked mounts.** In a user namespace, a read-only remount must keep the flags a more
  privileged namespace set (nosuid, nodev, noexec, the atime ones), or it is refused; and a bind
  of a mount without its submounts is refused, since it would uncover what they hide. /sys is
  therefore cloned whole (`open_tree`) and made read-only in one recursive `mount_setattr`.
  Neither shows up until the remount's result is checked, which the first cut did not do.
- **Every host path a step can influence must be resolved inside the step's root.** The runner,
  as root, read file commands and matcher files from the layers by plain path, and the helper wrote
  the event file and secret scripts the same way: a symlink a step planted could point them at the
  host's files. `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`, with mounts aimed at
  `/proc/self/fd/N` of the opened target, closes that for the helper; the runner also refuses
  symlinks outright and respects whiteouts (a character device in an upper hides the layers
  below).
- **What a namespace's owner decides.** The job's network namespace is made by the host's root, so
  the job's root has no `CAP_NET_BIND_SERVICE` there: ports below 1024 and ping need the
  namespace's own sysctls (`ip_unprivileged_port_start`, `ping_group_range`). Owning the namespace
  from the job's user namespace would avoid that, at the price of a namespace made per job inside
  it.
- **The resolver Dagger got for free.** BuildKit's CNI network hands each exec a working
  resolv.conf. A job's own namespace cannot reach systemd-resolved on the host's 127.0.0.53; the
  runner binds the upstream list systemd-resolved keeps (`/run/systemd/resolve/resolv.conf`).
  Nor, with rules that forward a job's traffic out of the uplinks only, a resolver behind another
  interface: razorbill's is Tailscale's MagicDNS (100.100.100.100 through `tailscale0`), and its
  first native jobs could not resolve anything. CI never saw it: GitHub's runners resolve through
  their uplink. Each job now gets its resolver made from the host's as Docker does, and the rules
  let DNS to its nameservers out of any interface.
- **A kept-alive connection the registry closed.** The pull uses the runner's process-wide HTTP
  client, whose pool keeps connections between pulls; Docker Hub closes one idle for about a
  minute, and std's client hands it out again, so a pull minutes after the last one failed at
  once with `HttpConnectionClosing` (razorbill). The tests' clients were fresh each time. A
  request that meets such a connection is now sent again on another (`registry.Client.once`),
  as the GitHub API's requests already were (`http.staleRetries`).
- **A native set-up that fails is not the job's failure.** Before any step, a failed pull,
  provisioning or base, or a job sandbox that could not be made, sends the job to Dagger with the
  reason in "Set up job" (`dagger.setUpFallback`), as an unsupported job goes there; razorbill's
  first native jobs failed instead.
- **NAT on a Docker host.** Docker sets the FORWARD policy to drop; a rule in another table cannot
  overturn it, only `DOCKER-USER` can. P1 makes its NAT and forwarding rules with `iptables` (debt:
  links, addresses and routes are rtnetlink already; nftables over netlink is phase 5's), not
  `nft`: the hosted runner has no `nft`, and `iptables` writes into the same tables as Docker's
  own rules, whichever backend the host uses.
- **Smaller ones.** `--exec-job` bypassed the trusted refs; it no longer does. Overlay's
  work directory and a step's `chmod 000` both defeat a plain recursive delete, so removal gives
  directories their permissions back and logs what still fails, and a sweep at each job's start
  removes the directories of runners that died (each job holds a lock on its own). A step killed
  before the helper removed a secret script's file left it in the layer for later steps; the runner
  removes it too. BuildKit makes a missing working directory, so the sandbox does; the helper's
  environment is empty, not the runner's; files get umask 022.
- **Tests that cannot run are not coverage.** The first CI run skipped every native test (the
  test runner was never told where the runner binary was), and nothing failed. CI now sets
  `ZIG_RUNNER_REQUIRE_NATIVE=1`, which turns a native test's skip into a failure. GitHub's hosted
  runner, unlike the laptop, refuses even util-linux's `unshare` a user namespace's id maps, so CI
  lifts AppArmor's restriction on its throwaway VM.

Measured: hardened, a cold trivial step costs 32.7 ms on the laptop (rootless, busier than for the
first cut's 18.1 ms), still about 7 times faster than Dagger's ~224 ms. The difference is per-step
setup that P2's per-job helper does once.
- **no_new_privs and sudo, decided.** With no_new_privs on, sudo as the runner user did nothing,
  and jobs that call it (most that install packages) had to go to Dagger. Once each job has its
  own range of ids, sudo can only become the job's own root, which is nobody on the host and is
  still held to Docker's capabilities and the seccomp filter: the user dropped no_new_privs for
  the runner user on a root runner, and kept it for root steps and rootless ones. The catch was
  ordering: without no_new_privs, installing a seccomp filter takes CAP_SYS_ADMIN, so the filter
  now goes in while PID 1 is still the namespace's root, before `setuid`. The root test checks
  that sudo gives uid 0 inside and nothing outside: a host-only file stays unreadable, the
  capabilities stay Docker's, and the uid map stays the job's.
- **The root pass's first runs, one kernel rule each.** Four bugs no rootless run could show:
  a link looked up by name through a socket opened after `unshare(NEWNET)` was looked up in the
  job's namespace, not the host's (a socket stays in the namespace it was made in, so each
  netlink socket now keeps its own lookup socket); joining a user namespace with `setns` changes
  no ids, so the helper was still the host's root, unmapped there, and what it made belonged to no
  one (EOVERFLOW: it now becomes the namespace's root, as runc does); the overlay, mounted in the
  host's root's mount namespace, is locked in the job's, and `pivot_root` refuses a locked new
  root (EINVAL: it is bound onto itself first, as runc does); and the hosted runner has no `nft`.
  Also a file descriptor closed twice on `init`'s error path, which Zig's I/O caught.

### P1, after the re-review: what is the host's, what the firewall already says, what fails quietly

An independent re-review of the hardened P1 found one major fault and several gaps. What it
taught:

- **A resource named on the host must be locked on the host.** The slots were locked under the
  runner's store, but what a slot names is the host's: the veth `zrh<n>`, the address, the range
  of ids. Two runners with different `RUNNER_NATIVE_STORE`s both took slot 0, and the second's
  set-up deleted the first's veth as a dead job's, cutting a running job's network; both jobs
  also got one address and one range of ids. The locks now live at a fixed host path
  (`/run/zig-runner/slots`), and only the slot's holder removes its veth. The rule for every
  later phase: before keying anything by the store (the layer store, cache volumes, cgroups),
  ask whether the kernel object it names is per store or per host. It also reaches the deploy:
  systemd's `RuntimeDirectory=` removes the directory when any unit sharing it stops unless
  `RuntimeDirectoryPreserve=yes`, which would quietly free a live job's slot, and a container
  needs the host's `/run/zig-runner` bound in, not its own.
- **iptables rules land among others'.** An `ACCEPT` for "anything from `zr0`" at the head of
  `FORWARD` and `DOCKER-USER` got the jobs out, and also opened Docker's unpublished container ports
  and every other network the host routes to, and overrode ufw's forward policy: the first matching
  rule wins whoever wrote it. The rules now say exactly the traffic they are for (from `zr0` out
  through an uplink, replies back) and leave the rest to the host's policy. `INPUT` was never
  considered: a job had its own loopback, but the host's services on the bridge's address (and every
  other address of the host's) were one hop away. Isolation between jobs needed two layers, since
  one does not imply the other: the bridge forwards between ports unless they are isolated, and the
  host routes between jobs through the gateway unless `FORWARD` drops it. IPv6 link-local addresses
  come up on every interface by themselves and pass every IPv4 rule; IPv6 is now off on the bridge
  and on the jobs' `eth0`. Host-wide sysctls (`ip_forward`) cannot be restored by one runner of
  several, so they are checked, logged and documented instead.
- **A mount that fails quietly is a hole with a passing test.** `/proc/sys` was made read-only by
  binding the helper's `/proc/sys` (the host's, with `binfmt_misc` mounted under it on GitHub's
  runner and many hosts) without its submounts, which a user namespace refuses; the call's result
  was ignored, so steps ran with `/proc/sys` writable and nothing said so. The masks had the same
  shape. Now each read-only path is cloned from the step's own /proc with its submounts and made
  read-only in one `mount_setattr`, as /sys already was, and a mask or read-only path the kernel
  has but cannot apply fails the set-up. The tests check the result from inside the step (a write
  refused, `ro` in mountinfo), not the call. Same lesson as the remounts in the first review:
  check every mount's result, and test what the step sees.
- **Smaller ones.** A script holding a secret was written into the step's layer, on the store's
  disk, and unlinked afterwards, which leaves it in free blocks: it is now on a tmpfs of the
  step's own, bound at its path. io_uring bypasses seccomp for the calls it runs and Docker has
  refused it since moby 25; `personality` can turn off ASLR (`ADDR_NO_RANDOMIZE`) and Docker
  allows only four values. The default id range sat inside systemd-nspawn's private-users range,
  and the checks read /etc/subuid only, not /etc/subgid or the host's own users and groups. The
  default subnet was podman's. A failed capability probe turned native off until the runner
  restarted; it is now tried again after five minutes. And one the root pass found at once: /proc
  reports its files' sizes as 0, so a read sized by `stat` (Zig's `readFileAlloc`) returns
  nothing, and `/proc/net/route` looked like a host with no default route; /proc files are now
  read to their end (`net.readProc`).

### P2: the layer store, replay and GC

What BuildKit's cache did implicitly, now explicit in `native/Store.zig`:

- **The key is the runner's to get right.** BuildKit keyed an exec on its recipe; natively the
  runner computes it, so the model's `Key` is now code (`KeyHasher.core`, in P8's format) and what
  the model does not have (uid, working directory, kept files, the rootfs, the id range, the
  binds' places) is listed beside it for P8 to add. The ran marker, the markers' secret and the
  event were volatile variables under Dagger; natively they are plain variables, so the key must
  leave them out by name, or every job would miss.
- **A layer has the canonical ids** (it first belonged to an id range). On a root runner a
  layer's files were owned by its job's host ids and, unlike the rootfs, which an idmapped mount
  shifts per slot, a stored layer was not shifted: it was keyed by the slot's first id. In a busy
  pool reruns mostly missed (the end-to-end job's rerun landed in slot 0 after the first run used
  slot 2, and needed a third try). Now a layer is shifted to the canonical ids when published and
  idmapped onto each job's range when mounted, the rootfs's own arrangement, and the slot left
  the key (store format 3). Lessons: every piece was already there (the provisioning's shift back,
  the seeds' idmapped lowers), so the cost of the first cut was one key field and a doc line, and
  the price of keeping it was paid in misses no test saw, since tests run one job at a time and
  take slot 0. And a shift by `chown` is lossy unless told otherwise: it clears set-id bits and
  file capabilities, misses ACLs, and sees a hard link twice.
- **Masks are secrets for the cache.** A step that names a value an earlier step masked always
  runs (`holdsSecret` counts masks), on native as on Dagger; the first replay test tripped on it.
- **Publish must never replace, and a reader must never trust a half.** `RENAME_NOREPLACE` keeps a
  concurrent or broken entry; an entry missing a part, or whose file commands lack their ran
  marker, is a miss. Holding the new layer's shared lock before it is visible keeps an eviction
  from taking it between the rename and the job's use.
- **The store's mode is a security boundary.** Its layers hold job-written files owned by the
  jobs' ids, setuid ones among them: at 0755 a host user could run one as the job's root's host id.
  The store is 0700 (P1's job directories, under it, were exposed the same way). Since layers have
  the canonical ids, a job's set-uid-root file is one of the host's root on disk, as the pulled
  images' `sudo` already was: the 0700 store is what keeps every host user from it, and `prepare`
  sets the mode on every start.
- **What the review found (after merge, fixed in a follow-up).** A fingerprint kept per process
  by path missed a rootfs provisioned again in place: `tar -x` restores mtimes, so size and mtime
  match; ctimes do not, and every job now checks the root and a stamp. Layers outlived runner
  upgrades that change their meaning: the store's format is now in every key. A record that
  could not be replayed was still published and then shadowed its key forever, every lookup
  keeping it fresh: records are now checked at publish and on every hit, with sha256s in a
  `meta`, and a broken entry is evicted. Nothing was synced before the rename that publishes,
  so a crash could leave a whole-looking empty entry: `syncfs` first. A vouched fork's pull
  request shared the trusted jobs' key space: its cache scope is now in the key. And walks that
  stopped at depth 256 or skipped unreadable directories undercounted a layer: they now have no
  depth limit and fail closed. Lesson: an entry in a cache shared between jobs is input the next
  job trusts, so every way it can be partial, stale or someone else's has to be in its key or
  checked on read.
- **Every publisher holds the key's lock, or a collect deletes its work.** `collect` tells a dead
  runner's half-built entry from a live one by the key's lock, which steps held while publishing
  and P7's Dockerfile builds (`layers.zig`) did not. Another runner's collect then removed a
  build's entry mid-publish: the build lost its layer, or the rename that publishes moved the
  directory the delete was walking, and a whole-looking entry with part of its tree gone was
  published for the next job to mount (the record's checks do not read the tree). The one-job and
  two-job tests could not see it; a stress test (`store_stress.zig`: several processes, one
  store, a cap small enough that every job's end evicts) found it in seconds, as the TLA+ model
  did on its own the same day (proofs/tla/StoreLocking.tla). `publish` now
  refuses without the lock. Lessons: a precondition another function relies on belongs in a check,
  not a doc comment; and a store shared between processes needs a test with processes, many, for
  long enough, checking every invariant at once. Its first ten-minute nightly run found the
  same mistake one level up, in P1's job directories: a job's removal took its lock file first,
  and another runner's sweep made a new one, found it free and removed the directory alongside
  its owner. A job's directory now goes lock last, and the sweep opens a lock without making
  one and checks it is still the file its path names, as `lockKey` does. A lock that lives
  inside what it guards has to be the last thing removed, and whoever finds it must never make
  it.
- **Dagger's replay limit is not ours.** Dagger replays a step past 4 MiB of output with a warning
  instead of its log; natively such a step is not published and runs again.

Surprises:

- The boundary held: replay is one `Exec.collect` call with an answer built as values (a log need
  not be UTF-8, so no JSON round trip), and the shared code cannot tell it from Dagger's.
- `lgetxattr` on `/proc/self/fd/N` reads the magic link's xattrs, not the directory's; through
  `/proc/self/fd/N/.` it reads the directory's.
- Flattening needs no copies and no `mknod`: whiteouts are hard-linked from the layer that has
  them, which also works rootless.

Measured against Dagger: a replayed step 0.37 ms against ~95 ms, about 250 times faster.

### P3: the image pull

What Dagger (BuildKit and containerd under it) did implicitly, now explicit in `native/oci/`:

- **The platform.** BuildKit picks the image of an index for the engine's platform without being
  asked. Natively the pick is ours, and an index lists attestations as manifests of platform
  `unknown/unknown`, which a careless "first linux one" could have taken for the image.
- **Where an extracted path may land.** containerd's archive code walks every path inside the
  rootfs. A plain tar extractor writing as root would follow `etc -> /etc` planted by one entry
  when writing the next, and a hard link to `../../etc/shadow` would link the host's file in.
  `RESOLVE_IN_ROOT` gave the right semantics in one flag: absolute symlinks inside the image
  (usrmerge's `/bin -> usr/bin`) work, and nothing reaches out.
- **Overlay's metadata in a layer used as a lower.** BuildKit's snapshotter keeps layers apart.
  Flattening an overlay upper (provisioning) meant reading overlay's own records: whiteouts as
  0/0 character devices, opaque directories as `trusted.overlay.opaque` (root) or
  `user.overlay.opaque` (`userxattr`), and overlay's xattrs left on files that would mislead
  overlay when the result is a lower. An image's own `trusted.*` and `user.overlay.*` xattrs are
  refused for the same reason.
- **Owners per range.** Dagger's layers belong to the engine. A root runner's provisioning layer
  belongs to the job's range of host ids; it is shifted back to the image's ids before it is
  shared, or the next job (another slot, another range) would see every file owned by nobody.

Surprises:

- **std 0.17's HTTP client never sends `privileged_headers`**, the headers meant to be dropped on
  a redirect to another host, and keeps `headers.authorization` across such a redirect. The first
  test against a token-auth registry failed because the token never left; using
  `headers.authorization` instead would have sent it to the blob's CDN. Redirects are followed by
  hand, and the token goes to the registry's own origin only; a test registry's CDN route refuses
  any request that carries one.
- **std's zstd decoder panics when asked to verify a frame checksum while streaming** ("TODO all
  those bytes written needed to go through the hasher too"). The digests cover it.
- **Zig 0.17 removed `**` array repetition**; `@splat` in a container's constant does the same at
  compile time.
- **Rootless provisioning cannot work with one id.** apt cannot drop to `_apt` to download (its
  methods exit 112), and once told to download as root, dpkg's `chown root:adm` fails. A rootless
  runner without the operator's rootfs sends default-image jobs to Dagger, rather than failing
  them where P1 sent them to Dagger. And apt's own last line ("dpkg returned an error code") says
  nothing: a failed provisioning now reports its last eight lines.
- The pull is not where the time goes: cold, about 0.5 s of auth and manifests and 1.6-2 s of
  fetch and unpack for ubuntu, against Dagger's 4.5 s. Provisioning (apt) is the minute, and it
  now runs once per store, as Dagger's cached exec did once per engine.
- **Two stores in one directory need one owner per subdirectory.** On top of P2, provisioning
  under `layers/` was P2's to collect: its `.tmp-<key>`, with no `keys/<key>.lock` held, looked
  like a dead publisher's and was removed while apt ran. Provisioned rootfs now live under
  `rootfs/`, which P2's GC never walks.

Measured against Dagger: a cold pull of `ubuntu:24.04` 2.1-2.5 s against 4.5-4.7 s, about twice as
fast; warm, a pinned image costs nothing.

### P4: cache volumes, trust scopes and cgroup memory accounting

What Dagger did implicitly, now explicit in `native/`:

- **A cache volume is not the job's ids.** The engine owned its volumes and gave each mount the
  owner it was asked for; natively, each job's ids are its slot's, so a directory filled by slot 0
  is nobody's to slot 1. The volumes are owned by a range of their own and seen through an
  idmapped mount per step, the same mechanism as the rootfs with a different map (`inside` ids
  starting at the volumes' range, outside the job's). Host ids would have been simpler and wrong:
  a setuid-root file a job left in a volume would have been a real one on the host.
- **The seed's isolation came from the engine's recipe cache.** Dagger built the seed by its recipe
  and mounted it as a directory whose writes went with the container. Natively that is a layer:
  built by trusted inputs only, its owners rewritten to the image's and setuid bits cleared before
  it is published, and stacked under the job's layers so the job's writes copy up into its own.
- **Dagger's mount points.** BuildKit makes a cache mount's missing parents as root. The sandbox
  does the same, owned by the job's root (the helper is still the host's root when it binds, so it
  chowns what it makes).
- **The engine's one cgroup was the gate's only view.** It charged every job running for all of
  them; per-job cgroups give each job its own working set, and the gate reads a native job's with
  the same definition. The same definition is not the same quantity, though (below).

Surprises:

- **The cgroup is the host's, like the slots.** P1's rule ("ask whether the kernel object is per
  store or per host") applied at once: the jobs' cgroups live in one host-wide tree, named by the
  job's random directory, and removed only by the runner that holds the job's lock.
- **Delegation cannot be detected reliably.** systemd marks delegated cgroups with a
  `trusted.delegate` xattr, but the user manager does not (Ubuntu 24.04's systemd: no xattr on a
  `Delegate=yes` user scope), and a rootless runner can write its whole user@ subtree whether it
  was delegated or not. So delegation is opt-in (`RUNNER_NATIVE_CGROUP=self`), not guessed:
  guessing would have moved, for example, an editor's every process into a leaf of its scope.
- **A cgroup that gives its children controllers holds no process.** `self` has to move the
  runner (and whatever else shares its cgroup) into a leaf before enabling the memory and pids
  controllers: the same dance systemd documents and Docker-in-Docker does at a container's root.
- **`zig build test` does not pass the environment to the tests.** A variable the tests read
  (`ZIG_RUNNER_TEST_CGROUP`) reaches them through `.github/scripts/zig-test.sh` (the compiler
  directly), not through the build system, which is how CI already runs them.
- **Bash's `-e`** ends a step at the OOM-killed command, so a test that wants to see the exit code
  says `|| echo exit=$?`; the step's log carries the runner's own line about the limit either way.

Measured (laptop "cowbird", rootless in a delegated `systemd-run --user --scope`): two overlapping
native jobs each holding 300 MB, the second starting 3 s into the first. The gate learned **304
MB and 305 MB** from each job's own cgroup; the engine-wide reading (the jobs' parent cgroup, read
as the engine's is) charged the first job **610 MB**, both jobs' memory, and the second 306 MB. That
is razorbill's soak in miniature (1.7 GB learned for a job that takes about 0.9 GB alone). CI's
root pass (GitHub's hosted runner, `/sys/fs/cgroup/zig-runner-test`) measured the same: 304 and 304
MB own, 609 and 304 MB engine-wide. A runaway job capped at 256 MB was OOM-killed (exit 137) in its
own cgroup while its neighbour held 200 MB untouched, and a fork bomb capped at 64 processes was
refused 125 forks there and the job went on. A cap near the size of the step's own shell and helper
is a trap: at 64 MB the root pass's kernel killed the shell with the hog.

After the first Pi run (razorbill, six native bench runners, 2026-11-02):

- **The engine's default was the wrong default for native jobs.** The gate learned native jobs
  from their own cgroups, but reserved `RUNNER_MEM_PER_JOB_MB` (1.5 GB on razorbill) for any name
  it had not learned, and for every runner polling. That number exists because a `zig build test`
  on the engine grows the engine's one cgroup by 1.6 GB, and nothing stops a job there from taking
  more. On a native pool it held e2e jobs of a few MB for 87-150 s each: three runners asking
  "needed" 4.5 GB of the 5.5 GB available. What makes a low native default safe is the thing the
  engine lacks: a cgroup per job, where a `memory.high` from the job's estimate slows a job that
  outgrows it instead of letting it take memory its neighbours were admitted against. So the
  default and the throttle came together (`RUNNER_NATIVE_MEM_PER_JOB_MB`, 256 MB; `memory.high`
  twice the estimate plus 512 MB).
- **One quantity per table.** An engine reading of a job is the job and the engine's growth for
  it; a native reading is the job. Kept in one table under one name, a job that went to Dagger
  once (a set-up that fell back) would have mixed them, so each backend learns its own.
- **A throttle that is learned from teaches itself.** A job held at `memory.high` is seen to take
  about `memory.high`, and an estimate from that sets the same limit again. A run that outgrew its
  estimate and went over its limit (memory.events `high`) is learned at no less than the limit,
  which doubles it for the next run. Going over on page cache alone (a checkout) does not count:
  the working set the gate learns leaves the cache out, so it stays within the estimate.
- **`memory.peak` is not what to learn.** It is the cgroup's high-water mark, page cache included,
  and a cgroup keeps its cache until something presses on it: a job that writes a checkout and a
  build's output would be learned at its cache, up to the very `memory.high` set from the last
  estimate. The working set sampled each second (`workingSetMb`) and read a last time as the
  cgroup goes stays the measure; `memory.peak` is still read (`cgroup.Usage`), and not learned.

### P8: remapping the proofs

Written against P2's specification while P2 was being built, so what it taught is about the
specification:

- **What BuildKit discharged is three obligations, not one.** "The key is computed from exactly
  what the model says" splits into: the preimage is unambiguous (every field length-prefixed, a
  count before the environment, a tag per kind of container), the environment keeps the order the
  step sees, and the script text tells apart the scripts the model does. The last was always
  assumed under Dagger too, and unstated; the first is new, and plain concatenation fails it with a
  four-byte example (`Ambiguous`: script `x` with `Y=1`, and script `xY=1` with nothing).
- **Not storing what cannot be replayed removes the model's bookkeeping.** `Build` needs `Numbered`
  and `Ahead` because the engine records marked steps and failures, and the proof has to show
  nothing ever finds them. A store that publishes only successes of unmarked steps never holds
  them, so native P1 needs `Disciplined` and nothing else. It also keeps a marked step's log, which
  may hold a secret, off the store's disk, which P0 asked for.
- **The flock is for cost, not correctness.** Two honest entries for one unmarked key are equal
  under `Disciplined`, so which racing writer wins does not matter. What correctness needs is that
  the store changes by whole entries (one rename) and that a reader treats a missing or short part
  as a miss: either one alone closes torn reads, and an eviction part-way is the same case as a
  write part-way.
- **Comparing the walk byte for byte found an ambiguity.** P2's layer walk wrote an entry's xattrs
  with no count before them, so where the last xattr ends and the content begins was not in the
  bytes: a symlink's target is a field just as an xattr's name is. The proof of `walk_injective`
  could not go through without it, and two different layers could have shared a digest, which output
  keys would have taken for early cutoff. The fix was one count. Nothing asked for a layer digest
  yet, so no stored digest changed meaning; the rootfs's fingerprint, the same walk, changed once,
  which costs one round of misses.
- **What P2 hashes beyond the model added no input to it.** P2's key carries the uid, gid, working
  directory and kept files, and the digest below a base (store format, rootfs, id mapping, binds;
  the slot too, until stored layers took the canonical ids and it left the key). Each is
  either part of what the model's base is or fixed with it for every step of the job, so the proof
  needed a richer `Format`, not a richer model: the base became a `BaseSpec` and a step's extras its
  base's (`stepExtra`). One consequence worth knowing: when the event payload is too large for a
  variable, P2 writes it as a kept file of the base, so the base and every key above it are per run.
  That costs only misses. The store's format, which P2 put below every base after review, is the
  format version P8 asked for: it makes every key new when what a layer means changes, and the
  rootfs's fingerprint is an opaque atom to the model however P2 computes it.
- **The stable environment is a predicate, and the model never needed it to be `volatile_env`.**
  P2 also drops the runner's own per-job variables and the secret aliases (`Store.stableEnv`); the
  model's `vol` is any predicate, so nothing changed but the vectors.
- **Some entries no one can ask for.** With output keys off for a marked step, every step after it
  starts from a container whose key names the job, so its entry, though honest, can only ever be
  found by that job. Publishing it is safe and useless; P2 may skip it.
- **A miss is always safe, and the proof says why in one line**: every invariant is "every entry
  that is there is honest", which removing entries or failing a read cannot break. LRU eviction and
  a read cut short need no argument of their own.
- **The layer digest must hash namespace ids, not host ids.** P1 gives each slot its own range of
  host ids, so the same layer written in two slots has different owners on the host. Hashing those
  would make the digest, which is part of a step's output, differ between runs: no early cutoff,
  and `Disciplined` false in letter. The same holds of times and inodes, and of the order readdir
  returns. Whiteouts must be in the walk, or a layer that deletes a file has the digest of one that
  does not.
- **`exec 2>&1` is now Dagger's need only.** The native helper already gives the step one pipe for
  both streams (`dup2(1, 2)` before `execve` in `sandbox.zig`), so a store that records that pipe
  replays the run without merging. The script keeps the line because both backends run the same
  script, and its text is in the key.

### P5: Docker's allow list, the rules over netlink

- **A filter of names is only as good as its table.** Docker's profile names calls; the filter
  needs numbers, per architecture. A name std spells otherwise (`_sysctl`, `newfstatat`) would be
  left out without a sound, so the test walks every call of both architectures' tables and
  requires each to be named by the profile or known refused. Unknown calls get ENOSYS, not EPERM,
  as runc found: a C library falls back on ENOSYS only.
- **Long filters need short jumps.** Classic BPF's conditional jumps reach 255 instructions; an
  allow list of about 370 calls compared one by one would need longer ones. Runs of consecutive
  numbers, each block ending in its own returns, keep every jump short, and a call costs two
  comparisons per run below its own rather than one per allowed call.
- **An accept in our table cannot overturn a drop in theirs.** nftables runs every base chain on a
  hook and a packet must pass them all. So the deciding moves into the runner's own table, where a
  drop holds whatever else the host has, and the host's iptables-nft chains only get the two
  plainest accepts (`-i zr0`, `-o zr0`). The reply-only rule needs no conntrack match in their
  table, since ours enforces it.
- **Write into iptables' table only as iptables would.** A rule iptables-nft cannot translate makes
  it call the whole table incompatible and refuse to change it, which would break Docker. The rules
  there are iptables' own encoding (meta, cmp with the name's terminating zero, a counter, an
  immediate), checked against `iptables-nft -S` and `nft --debug=netlink` in an unprivileged
  `unshare -rn` namespace, which needs no root: nftables works in a network namespace a user
  namespace owns.
- **Kernel modules.** `nft_masq`, `nft_ct` and `nft_chain_nat` may not be loaded on a host whose
  firewall is iptables-nft (Docker's MASQUERADE uses the xtables target). The root runner's first
  batch loads them; a test that makes the rules in an unprivileged namespace first may find them
  missing.

### P6: services

What Docker and Dagger did implicitly for services, now explicit in `native/`:

- **A container's entrypoint is looked up in its PATH.** Steps always ran `/bin/sh`; an image's
  `docker-entrypoint.sh` is a name, found in the image's own PATH once inside its root
  (`sandbox.lookPath`), as runc finds it. Some images have no shell at all (`traefik/whoami`).
- **`USER` is a name in the image's files**, not the host's: resolved in the image's /etc/passwd
  and /etc/group, read inside it.
- **Readiness was Docker's state machine.** GitHub's runner polls Docker's health status; Dagger
  waited for ports. Natively the helper that holds the service's first process is the place to
  decide it: a check forked there is in the service's namespaces without a `setns`, and the pid it
  joins cannot be another process's, since the helper has not reaped it. A separate helper joining
  by pid would have raced pid reuse, as the host's root.
- **Published ports were Docker's proxy.** In one shared namespace a port published as itself
  needs nothing, which is most of them; the rest take a relay of ours, which binds as root in the
  job's namespace and then drops to the job's `nobody`.
- **Docker's bridge kept the host out.** P1's rules kept jobs from the host and from each other,
  but not the host from the jobs: any process on the host could connect to a job's address over
  `zr0`. Harmless while only steps listened; a database whose password is `postgres` is another
  matter. `OUTPUT` and `FORWARD` now drop what goes to `zr0` and is not a reply, and the root test
  knocks while a service listens.

Surprises:

- **The first readiness try's delay was the whole cost.** A service up in 5 ms was ready at
  122 ms: 100 ms of first delay in the helper and 20 ms of the runner's polling. From 10 ms,
  doubling, and read every 10 ms, it is 21 ms.
- **`pg_isready` passes against postgres's set-up server**, which the image's entrypoint starts on
  its socket alone and stops again before the real one listens on TCP; workflows on GitHub have
  the same race. The test checks over TCP (`pg_isready -h 127.0.0.1`).
- **An image's path can hold overlay's separator.** `postgres:17-alpine` is a fine directory name
  and an impossible `lowerdir=`; the layer is a link in the job's directory instead.
- **The boundary held again**: two lines in `dagger/services.zig` hand "Initialize containers"
  and "Stop containers" over, and `JobLog.serviceLine` became public. No Dagger path changed.

### P7: Docker actions (`docker://` steps)

- **The script was the busybox's, not the action's.** Dagger's path starts a Docker action's
  command under a static busybox it copies into the image, because the step script (markers, file
  commands, the event, `env -u`) needs a shell and the image may have none. Natively the runner is
  already outside the container with the output pipe in hand, so it writes the markers into the
  log itself and makes and reads the file-command files from the job's layer; the action's own
  command is PID 1's exec. It is also what GitHub's runner does: it binds host files in and reads
  them afterwards, and runs no shell in the image.
- **A bind is the copy back, for free.** Dagger copies the workspace into the action's container
  and the result back over the job's (`withoutDirectory` + `withDirectory`). Mounting the job's
  overlay with a new layer and binding its workspace into the container makes the action's writes,
  deletions included, the job's next layer directly, as GitHub's `docker run -v` does.
- **Two overlays in one helper.** On a root runner the job's overlay and the image's are both
  mounted by the host's root before the helper enters the job's user namespace (the image's
  filesystem idmapped like the rootfs), and the shares are bound in the step's own mount
  namespace, recursively: a non-recursive bind of part of a mount made in a more privileged
  namespace is refused.
- **Ownership was Dagger's implicit gift.** `withDirectory(owner:)` gave the runner user every
  file a root action wrote in the workspace; GitHub leaves them root's (a known annoyance). The
  native path keeps Dagger's behaviour by walking only the step's layer under the workspace,
  which holds exactly what the action changed, rather than the whole workspace.
- **Deciding per job limits what can move.** `docker://` steps name their image in the job, so
  the decision can be made before the job starts; a `uses:` action's kind is in its `action.yml`.
  Moving `uses:` actions (Docker and JavaScript alike) needs their metadata fetched before the
  choice, which is why the loader is the next piece, not the builder.
- **`GITHUB_ACTION`, exit codes and logs follow Dagger's path, not GitHub's.** Dagger's path sets
  `GITHUB_ACTION` to the step's label (`docker://alpine:3.22`) and logs no "Process completed with
  exit code" for a Docker action; the native path does the same, so a job's results do not depend
  on the backend.

Measured: 11.3 ms a `docker://` step natively on the laptop (rootless), against a cold `run:` step
at 21.3 ms on the same machine and Dagger's ~224 ms for the latter.

### P7: the action loader and the builder's runner

- **Per job, still.** The request was to choose the backend per step where needed. A step that
  switched would start from layers the other backend does not have, so the choice stays per job,
  and what needed per step was only the knowledge: fetching the actions before the choice gives
  it. The fetch is not wasted when native runs: the trees are in the job's layers already, where
  composite steps and Dockerfile contexts read them.
- **Stored layers must not carry a job's ids.** On a root runner what a sandbox writes has the
  job's host range; a layer stored that way would be another job's nobody. Overlay cannot idmap
  its upper, so a build's `RUN` layer is shifted back to the image's ids when it ends and every
  stored layer is idmapped when mounted, as the rootfs is.
- **The job's binds are for the job's image.** Binding them into a Docker action's image, where
  the target may not exist, failed the build's first `RUN` (a test bind at `/srv/git`); GitHub
  gives an action's container none of the host's paths but the four it documents.
- **Testing a fetch without a network.** The job's `server_url` can be a `file://` URL inside
  the sandbox, with the test's bare repositories bound there, so the loader's tests run the real
  git fetch in both native passes and never reach Dagger.

### P7: JavaScript and local actions

- **Mounts were the whole difference.** Dagger's JavaScript path is a script plus mounts: the
  runtime's binary, its shims and npm, and the action's directory. Once the native backend
  applied mounts (binds for host files, files written for new ones, nothing for trees already in
  the layers) the shared code ran pre, main and post unchanged. The one fault was the native
  backend's own: it removed every file it wrote after a step, which was right for a script holding
  a secret and wrong for a shim that must outlive it.
- **Judging a local action needs one blob, not the repository.** A blobless fetch of the job's
  commit and `git cat-file` of one path costs a commit and its trees, and leaves nothing in the
  job but an empty layer; the checkout still does its own fetch.

### hashFiles()

- **The merged view is read without mounting it.** `hashFiles()` is evaluated between steps, in
  conditions, `env:`, names, `with:` and scripts, and at the job's end for its outputs. The runner
  merges the layers by lookup (`native/hash_files.zig`): the topmost entry decides, a whiteout
  deletes, a non-directory hides what is below, an opaque directory stops the ones below it. A
  mount would need privilege a rootless runner lacks and would cost more than the walk. glob.zig,
  the search compared with GitHub's script, runs over it as it runs over Dagger's API.
- **Links are resolved on the merged paths, never on the host's.** Each look at a layer is
  `sandbox.openIn` with no symlink followed. A link `hashFiles()` finds is hashed as what it leads
  to, as GitHub's `statSync` does and `sha256sum` does in a Dagger job: with `/` the job's root and
  `..` taken on the path already resolved, so a link to `/etc/shadow` or to `../../../..` names the
  job's file, or nothing, and never the host's. A link to a missing file or a loop fails the call.
- **No new key.** A `hashFiles()` result is a function of the layers below the step, which the
  step's key already holds through its parent, and wherever it affects the step it is in the
  script or the env that the key hashes (`env:`, `with:`, the script, the shell and the working
  directory are all in the script). A condition, a name, a timeout and `continue-on-error` do not
  change what a step that ran left. The test runs a job, replays it, and runs it with another first
  file: the replay prints the same hash, and the other file's hash is not served from it.
- **What is not read.** Mounts (the cache volumes, an action's runtime) are in no layer, as
  Dagger's `rootfs` leaves them out. A job-level `env:` is evaluated before any container exists, so
  `hashFiles()` there is an error and the variable stays unset, on both backends (GitHub does not
  allow it there either).
- **The job decides how much work a call is, so a call has limits** (`hash_files.Limits`, the
  walk's in `glob.zig`). Only the native path has them; the Dagger path's walk has none, as before.
  - *Files and directories:* at most 1,000,000 a walk. With `--follow-symbolic-links` two links
    per directory, twenty-five deep, name one directory by 2^25 paths (72 inodes took 4 GB), and
    @actions/glob only breaks cycles through a directory's own ancestors. A monorepo with its
    `node_modules` is a few hundred thousand entries (the Linux kernel about 90,000 files), so a
    million leaves room.
  - *Memory, and the turn:* an allocator under each call's arena counts every byte and refuses a
    request the call may not have, wherever the call is (matching, listing, building paths), so
    the call fails with a message where it stands. The memory is the runner's, outside the job's
    cgroup, and one process serves all slots, so it is limited for all of them; but a call that
    waits for memory while it holds memory others need could wait in a circle with them, so it is
    not shared out by the byte. Each call has an allowance of its own (64 MiB, or a quarter of the
    limit) that nothing else's use touches, so a small call never waits. A call that goes past it
    takes a ticket and waits for its turn, in the order calls asked, and then has the whole limit
    to itself until it returns. While it waits it holds only its allowance, and the call whose
    turn it is waits for nothing, so there is nothing to wait on in a circle: a big call is delayed
    by the big calls before it, one turn each, and is failed only when it is too big alone (at
    once, naming the setting). One job that holds the turn (a big walk, then a huge file) delays a
    neighbour by that one turn, not fails it, and its next call queues behind the neighbour's. A
    wait fails only when the queue stops moving for twice the timeout: each call ahead may hold the
    turn for its own timeout, so a wait is bounded by the calls ahead (6 minutes behind 3 of them,
    at the default), and a cancel ends it. The limit is the smaller of 1 GiB and an eighth of `MemTotal` (the host's, in a container too: the
    runner has no reading of its own cgroup's limit), or `RUNNER_NATIVE_HASHFILES_MEMORY_MB` (0
    for none); in all the process holds one limit and an allowance for each call running. What a
    walk keeps is 32 bytes a node and its path; the rest of what it needs is reset per path and
    per level. Measured (counted bytes, which run about twice the resident ones): a 900,000-entry
    monorepo with `hashFiles('**/package-lock.json', '!**/node_modules/**')` takes under 1 GiB
    counted and 450 MB resident, in 15 s; `**` over it takes 1.4 GiB counted, about 1.5 KB an
    entry (the earlier "1 KB each" was a guess), so it needs the setting raised on a big host and
    is refused at once, with the message, on a small one. Four such calls on a 300,000-entry
    monorepo, and two on the 900,000-entry one, all succeed, in turn.
  - *Steps:* at most 200 million path components, and each path name is looked up in place, each
    followed link remembered (with the links it took, as the kernel counts them: 40 in one path,
    nested ones too) and a directory resolved once for its files, so a path 1,900 deep or a chain
    of 4 KB links costs what it holds, not a copy of the path for every name of it.
  - *Time:* GitHub's own limit. actions/runner's `HashFilesFunction.cs` has
    `_hashFileTimeoutSeconds = 120` and throws "hashFiles(...) couldn't finish within 120
    seconds", so a file that takes hours does not on GitHub either (an earlier version of this
    note said it did). The clock is read every 1,024 steps (every 64 MiB of a file), and
    `RUNNER_NATIVE_HASHFILES_TIMEOUT_S` sets the seconds (0 for none), since a Pi on an SD card is
    far slower. A step's `timeout-minutes` does not reach an expression, so this is the bound. A
    file is read in full however large and sparse: the hash is GitHub's, which has no shortcut for
    holes. The 120 seconds are the call's own work, as on GitHub, so the time it waits for its turn
    is not counted in them; the wait has a limit of its own, as long again, which is the longest a
    call may hold the turn it waits for (so waiting behind one call is covered, behind several
    may not be), and the job's cancel ends it.
  - *Cancel:* the job's cancel (`dagger.Cancel`, handed to the backend) is seen at every step, the
    walk's included (`glob.Fs.poll`), so a cancelled job stops within a second in the middle of
    matching, listing or a file; `Watch` cannot, as no sandbox runs while expressions are
    evaluated. A call that *begins* after the cancel (an `if: always()` or `if: cancelled()`
    cleanup step, the job's outputs) is not cut short, as on GitHub in the grace period: it ends
    at the cancel's `hard_deadline_ms`, or at the time limit.
- **Overlay's redirects and metacopy fail the call.** `Merged` does not follow them, and a hash
  of what they hide would be wrong without a word, so a layer entry that has either attribute
  fails `hashFiles()` with a message. The runner turns both off, whatever the host's kernel
  defaults to: `overlayFeatures` in `sandbox.zig` passes `redirect_dir=off,metacopy=off` on a root
  runner; a rootless one's `userxattr` already has neither, and refuses that option beside it.
  `Store.flatten` checks only directories, which is enough with metacopy off.
- **A file is hashed only if the step's user could read it (#360).** The runner reads as itself
  (root, or the rootless user), so without a check a non-root `container:` job could hash a file
  its own user cannot read (`ln -s /etc/shadow s`) from within its own tree. The owner decided
  that it must match Dagger, whose two halves ran as different users, and this keeps them apart.
  - *What each half is.* The search was the engine's (`exists`, `entries` on `rootfs`), so it sees
    past permissions, and still does: a name in a directory the user cannot enter is found, and
    so is what a followed link leads to. Only `sha256sum` and `realpath` ran as the step's user,
    and they are what the check stands for (`Merged.checked`).
  - *A failure, not a skip.* `sha256sum` exited non-zero, so the call fails with its words,
    `sha256sum: <name>: Permission denied`, and `realpath: <path>: Permission denied` for a
    directory reached with links followed. `[ -d ]` could not `stat` under a directory the user
    cannot enter, so a directory there failed too, where one the user can reach is skipped.
  - *Directories.* Each directory walked needs search permission, those a link leads through
    and `..` included, and that is asked before the name is looked up, as the kernel does. So to
    `sha256sum`, a link to what is behind such a directory reads the same whether it is there or
    not.
  - *What a job can still learn.* The search tells them apart, as Dagger's did (`exists` followed
    links, as the engine). With `--follow-symbolic-links`, a link to a file behind such a
    directory fails in `sha256sum:`'s words, one to a directory in `realpath:`'s, and one to
    nothing is left out, so the call succeeds; and `entries` and a failure name what is in it. So
    existence, type and names can be learned, one glob at a time, in the job's own tree: the same
    as Dagger, and none of a file's content.
  - *Ids.* A layer's ids are compared as the job sees them, by layer: the job's own uppers have
    the slot's host ids, stored and flattened layers and the image's have the canonical ids
    (`Backend.hashStep`). An id the job does not reach matches no one, not `nobody`. A root step
    on a root runner has `CAP_DAC_OVERRIDE`, and a rootless runner's steps are all root, so
    neither is checked.
  - *Groups.* The primary group, and the supplementary groups BuildKit's `GetUser` gave: those of
    `/etc/group` that name the user, for a name or a uid `/etc/passwd` has, and none with an
    explicit group or a uid not there. They are read once, from the image, when the job starts
    (`Backend.stepGroups`), and that one list is what the step's processes have and what the call
    counts, so `hashFiles()` says yes only where the step could read. The engine read them at each
    exec; here a step that edits `/etc/group`, or `usermod -aG`, changes nothing for the steps after
    it, and a gid past the job's 65,536 ids is left out. A link in them stays in the image. The list
    is in a step's key when it has one, so the same ids without a group never replay what it read.
  - *ACLs and capabilities.* An ACL decides as the kernel's `posix_acl_permission` does, on the
    file and on each directory, with its ids shifted like the owner's. `sha256sum` as a non-root
    user had no capability to use, so none is modelled.
  - *What is not matched.* `sha256sum` went on and named every file it could not read; this stops
    at the first, and reads nothing of it. A workspace the user cannot reach fails with
    `sha256sum:`'s words, not `cd`'s. The words are coreutils', also in an image whose `sha256sum`
    is busybox's. The engine read the user's uid and gid again at each exec, and a step's are
    settled when the job starts, so a step that edits its own /etc/passwd changes its groups
    here, but not its ids. A rootless step's root can read a file of mode 000, and the runner, as
    itself, cannot: that call fails, as it did before this check. ACLs in an image are not kept
    by the native pull (`oci/layer.zig`), so the step cannot use them either. A line of
    /etc/group whose gid is not a number is skipped, where the engine read it as 0.
- **A file is looked at before it is opened.** Its type is read from an `O_PATH` descriptor and
  the file opened through that descriptor, so a pipe is refused and not waited for.

### Bounded jobs (#367)

- **The incident was not the limit being too high.** The kills were `python3` of 22.6 GB (01:41),
  22.4 GB (16:22), 11.6 GB (16:28) and 25.9 GB (16:29). The first looked like the 22.5 GiB `memory.max`
  of a 30 GiB machine, but 25.9 is over it, and the kernel's own line says otherwise: `global_oom`,
  `task_memcg=/system.slice/docker-<id>.scope`. Those processes were in their containers' cgroups, in
  no job's. A container alone is not the condition: at 15:54 a limit held inside a Docker scope.
  That no parent could be made, `cgroup.resolve` said `none`, and the runaway test's `while True`
  went on with no limit until the machine ran out, is inferred from the code and that line; it was
  not reproduced. Runs where the parent worked show up as `CONSTRAINT_MEMCG` in
  `/zig-runner-test/<job>`, and hurt nothing.
- **`memory.high` was a safe throttle only with swap.** Turning swap off to bound a job turned the
  throttle into a stall (#372's review, "Bounded jobs"). A limit that holds a job with no kill needs
  a way for the job to go on, or the job only holds its runner until its timeout.
- **A limit the operator wrote is not ours to rewrite,** and neither is one a running job depends
  on. Each job's start writing the parent looked idempotent; it was not once settings could differ.
- **Parallel tests did not undo each other's limits.** Each job's cgroup is its own and written once;
  the one shared write was the gate test's 64 GiB on the parent, which bounded nothing. Limits on
  the parent changed that, so a test that sets them now has a parent of its own (`testCgroup`).
- **Tests must not lean on what they test.** The runaway and the bomb end by themselves now
  (`hogStep`, `bombStep`), at 1 GiB and 1023 processes, and `testCgroup` skips before any step runs
  if there is no parent. A test of a limit whose failure mode is the host's outage is a hazard.
- **`native/cgroup.zig` was not in the test root,** so its tests had never run: a file's tests count
  only when `main.zig`'s test block imports it.

### Running with no engine

- **A setting beats a probe.** "No engine reachable" cannot tell an engine that is restarting (jobs
  should wait, as they do) from one that was never there. `RUNNER_ENGINE=none` says it, and the
  default path is not touched: the only new branch on it is a boolean that is false.
- **Everything that waited for the engine was already off the native path.** A native job never
  opened an engine session, so the cost of a missing engine was in the background and in the
  fallback: the pre-warm polling the socket and queueing for the engine's turn, the gate looking
  for the engine's cgroup, and a job sent to Dagger (`backToEngine`) hanging on a socket that is
  not there. The last is the one that mattered: it now fails at once with the reason native gave.
