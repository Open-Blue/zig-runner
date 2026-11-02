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
  `continue-on-error`, `timeout-minutes` and cancellation (the same `Watch`; the helper kills the
  step's PID 1 when told), every file command, `::add-mask::` and the other workflow commands,
  problem matchers (read from the layers, relative to the working directory), step summaries,
  `id-token: write`, secrets in env, in scripts and in working directories, and the built-in
  checkout without submodules (git in the job's image, then the same step script Dagger's
  checkout runs).
- Falls back to Dagger, with "This job runs on Dagger: ..." in "Set up job": a job the runner
  does not vouch for (`trust.vouches`, for `--exec-job` too), a rootless runner unless
  `RUNNER_NATIVE_ROOTLESS=1`, a job container's `ports:`, `volumes:` or `options:`, `services:`
  on a rootless runner or with an image given by an expression (native since P6, below, their
  images pulled by P3), JavaScript and local `uses:` actions (P7, `actions.preload`), remote `uses:` actions in an
  image with no git to fetch them with, `docker://` images
  that cannot be pulled or run as a non-root `USER` (P7), Dagger in steps
  (`RUNNER_DAGGER_NESTING`), `hashFiles()`
  anywhere in the job (it reads the container through Dagger), a checkout with submodules, and a
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
  resolver is the host's upstream servers (`/run/systemd/resolve/resolv.conf`, or the host's
  resolv.conf when it names no loopback server), since systemd-resolved's 127.0.0.53 is the host's
  loopback; a resolver on one of the host's own addresses is out of reach too.
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

- in a **cgroup v2 of the job's own** (since P4) with `memory.max` and `pids.max`, where the runner
  is root or has a cgroup delegated to it ("P4" below).

What it does not provide yet:

- **Resource limits on a rootless runner without delegation.** P4's cgroup needs root or a
  delegated cgroup (`RUNNER_NATIVE_CGROUP=self`); without one a job runs as P1 did, and "Set up
  job" says so. A job the runner does not vouch for never runs without one (P5).
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
RUNNER_NATIVE_ROOTLESS=0                          # default; 1 for a rootless runner
RUNNER_NATIVE_CGROUP=                             # default: /sys/fs/cgroup/zig-runner as root,
                                                  # none rootless; `self`, `none`, or a path
RUNNER_NATIVE_MEMORY_MAX_MB=                      # default 3/4 of MemTotal; 0 for no limit
RUNNER_NATIVE_PIDS_MAX=8192                       # default; 0 for no limit
```

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
  named by its directory, and only the runner holding a job's lock removes it. Under a unit with
  `Delegate=yes`, `RUNNER_NATIVE_CGROUP=self` keeps them in the unit's own tree instead.
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
  systempaths=unconfined]`, and `network_mode: host` for the bridge to be the host's. The store
  must be a volume, not the container's own overlay filesystem (overlayfs cannot take an upper
  directory on overlayfs), and the rootfs another volume. The slots' locks must be the host's:
  bind `/run/zig-runner:/run/zig-runner` from the host into every runner container (the
  container's own /run would give each its own slot 0 on the shared bridge). The image has no
  `iptables`, and needs none since P5: the rules are made over netlink. For the jobs' cgroups,
  `cgroup: private` (the default on cgroup v2) with `RUNNER_NATIVE_CGROUP=self`: the container's
  root is then its own cgroup, and the runner moves itself into a leaf of it.
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
- **The store's format** (`Store.store_format`) is bumped with any change to what a layer or its
  record means: the sandbox's trees, the record's files and how they replay, the key's extras.
  A runner upgraded across a bump finds none of the older runner's layers; they age out under
  the cap.
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
  a branch or tag moves, so its fetch always runs. The upper is moved under `layers/.tmp-<key>-<n>`
  with its record, held, written to disk (`syncfs`), and published by one
  `renameat2(RENAME_NOREPLACE)`. An upper that cannot be put back after a failure is left there
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
  layer it uses until it ends.
- **GC** (`Store.collect`, after each job): past `RUNNER_NATIVE_STORE_MAX_MB` (default 10240),
  the layers no job holds go, least recently used first (the lock file's mtime is the last use),
  each renamed away under its lock taken exclusively, then deleted. Half-built and half-evicted
  entries of dead runners, idle key locks, and entries that are not whole (by `meta` and their
  files' lengths, without reading them) go too.
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
- Falls back to Dagger: a job container's `ports:`, `volumes:` and `options:` (phase 6 brings the
  network that ports and volumes need), and on a rootless runner without `RUNNER_NATIVE_ROOTFS`
  the provisioned default image (below).

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

- **No eviction.** Blobs, images and provisioned rootfs are kept for ever: P2's LRU under a byte
  cap (`collect`) sees only `layers/`, and should cover `oci/` and `rootfs/` too.
- **Each image is flattened whole.** Two images that share layers share their blobs on disk but
  not their unpacked files. P2's stacked layers could keep layers apart.
- **Layers are fetched one at a time**, and a broken download starts over. Parallel fetches are a
  measured optimisation for later (P9's real workloads); ubuntu has one layer.
- **zstd frame checksums are not checked** (std's streaming zstd cannot yet); the blob's digest is
  checked before and the diff id after, which covers it.
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
  three quarters of `MemTotal` by default), `pids.max` (`RUNNER_NATIVE_PIDS_MAX`, 8192), and
  `memory.peak`, `memory.events` and `pids.events` read back. Each step's helper joins it before
  anything else (`sandbox.joinCgroup`), so every process of the step is born in it and the runner
  never is. It is kept, empty, between steps, and killed (`cgroup.kill`) and removed when the job
  ends, or by the sweep after a crash. When a step's processes were OOM-killed or refused a fork,
  its log says so in an error line. Where it goes: `/sys/fs/cgroup/zig-runner` as root; the
  runner's own delegated cgroup with `self` (the runner moves its processes into a `runner` leaf and
  makes the jobs' under `jobs`, systemd's rule for delegation); a path; or none, rootless without
  `self`, where the job runs as in P1 and "Set up job" says why.
- The memory gate (`admission.zig`) is told of a native job's cgroup (`Gate.native`) and measures
  the job there, from nothing, with the engine's own definition of a working set
  (`workingSetMb`: `memory.current` less `inactive_file` and `slab_reclaimable`), so what it
  learns of a job means the same on either backend. A native job is never measured beside another
  (its cgroup is its own), its last sample is taken just before its cgroup goes
  (`Gate.nativeDone`), and its reservation is left out of the engine's cap
  (`Reservation.native_mb`). A native job without a cgroup is not measured, as a job without an
  engine signal is not.
- On P2's step store: the digest below a base (`Backend.belowKey`) holds the seeds' layers and
  which binds are cache volumes, after the model's fields and only when the job has either, so a
  stored layer is never replayed over a different seed and a job with neither keys as before (the
  model's `belowTail`; P8's vectors gained `below-seed` and friends, the old ones unchanged). The
  tool cache is the `toolcache` volume, keyed by the job's image as on Dagger; the base makes
  `/opt/hostedtoolcache` only for a job with no volumes (#274). What a step installs there is in no
  layer, so a stored step whose `$GITHUB_PATH` or `$GITHUB_ENV` points into it runs again instead
  of replaying (`Exec.tool_cache`, `toolDirNotHeld`, #229): natively no tree is checked, so every
  such record does.
- Debt: volumes and seeds are never evicted (the engine's GC prunes Dagger's). P2's `collect`
  walks only `layers/`, whose entries carry their size in `meta`; a volume has no size record, and
  walking every volume at each job's end to learn one would cost more than the eviction saves. The
  fix: a size written beside each volume when its job releases it (`<volume>.size`), a cap of its
  own (`RUNNER_NATIVE_VOLUMES_MAX_MB`; the layers' 10 GiB would be gone in one Zig job), and
  eviction least recently used first under the volume's lock taken exclusively and non-blocking, as
  `evict` does for a layer. A step whose processes still hold all of `pids.max` when its script
  ends fails with exit 2 and loses its file commands: the wrapper's `sh`, the step's PID 1, cannot
  fork its epilogue (its log says the job reached its process limit). Fixing that needs a PID 1
  that reaps and kills a step's leftovers before the epilogue. The tool cache's checked trees (`set_up.verifyToolTrees`) and the seed
  registry's discovery from them are off natively: steps check the trees they use themselves, as on
  Dagger without the check. A Dagger job that overlapped only native jobs is still learned as "beside
  others", an upper bound (small; the gate's overlap marks are set before a job is known to be
  native). Rootless runners without delegation have no limits (P5 must refuse untrusted jobs
  there).

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
each under the builder's key hashed with the store's format and the job's trust scope
(`layers.Store.key`): a job the runner does not vouch for, or a vouched fork's pull request,
builds its own layers and never leaves one a trusted job takes.

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
  (29 key vectors: steps, bases, the digest below a base; 4 layer vectors: modes, an xattr and a
  symlink, an opaque directory, a whiteout) and the equal/differ relation against it.

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
  checks this with a backgrounded `sleep 60`.
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
- **NAT on a Docker host.** Docker sets the FORWARD policy to drop; a rule in another table cannot
  overturn it, only `DOCKER-USER` can. P1 makes its NAT and forwarding rules with `iptables` (debt:
  links, addresses and routes are rtnetlink already; nftables over netlink is phase 5's), not
  `nft`: the hosted runner has no `nft`, and `iptables` writes into the same tables as Docker's
  own rules, whichever backend the host uses.
- **Smaller ones.** `hashFiles()` reads the container through Dagger, so it routes a job to Dagger
  until it is native. `--exec-job` bypassed the trusted refs; it no longer does. Overlay's
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
  the same definition, so learned estimates mean the same across backends.

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
