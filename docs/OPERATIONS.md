# Operations

Running zig-runner: how it splits jobs by trust, what it caches, how releases reach a machine, and
how it keeps a machine from running out of memory. Every setting named here is described in
[deploy/runner.env.example](../deploy/runner.env.example).

## Environments

A pull request can change any workflow and name any runner in `runs-on`, so jobs are split by
trust, and the runner itself enforces the split.

- **prod**, the runner on the maintainer's machine (`runs-on: [self-hosted, prod]`), runs only jobs
  from pushes to `main`, version tags and `workflow_dispatch` there, whose workflow file comes from
  one of those refs too (`RUNNER_TRUSTED_REFS`, `RUNNER_TRUSTED_EVENTS`; `src/trust.zig`). Any other
  job fails before a step runs, with the reason in its log. The protection fails closed: an unset or
  empty `RUNNER_TRUSTED_REFS` trusts no ref, so every job fails, and a runner whose `RUNNER_LABELS`
  include `prod` refuses to start without it. `RUNNER_TRUSTED_REFS=*` trusts every ref (prod starts
  with it, but logs a warning). `RUNNER_TRUSTED_EVENTS` defaults to `push,workflow_dispatch`, and
  `*` trusts every event. The runner logs what it trusts when it starts. The `prod` GitHub
  environment holds the release's deploy key, deploys only from `main`, and waits for the
  maintainer's approval.
- **pre-prod**, where pull requests and the merge queue run, is GitHub's hosted `ubuntu-26.04`.
  Nothing there is trusted or holds a secret. A self-hosted pre-prod is possible (`PREPROD_RUNNER`,
  and `deploy/runner.preprod.env.example` for a runner that trusts every ref and event, with no
  secrets and no access to its Dagger engine from steps), but the project leaves it unset.

Workflows name `prod` (or `pre-prod`, should one exist), never just `zig`, which every one of this
project's runners carries.

### Cache volumes and trust

Package caches (Go's modules, Zig's packages, cargo's sources, the tool cache and the rest) are
cache volumes, keyed by repository and by trust, and several are not checked again when used. A
job shares the repository's `repo` volumes only when the runner vouches for it: it passes the trust
gate on `RUNNER_TRUSTED_REFS` and `RUNNER_TRUSTED_EVENTS` lists that name what they trust
(`trust.vouches`), and it is not a fork's pull request. Every other job gets the `untrusted`
volumes, including a same-repository pull request, a `workflow_run` or `issue_comment` a fork set
off, and a fork's pull request whose repository was deleted. A `*` in either list lets every job
through without vouching for any, so all of a pre-prod runner's jobs share the `untrusted` volumes,
and none can write what prod reads.

With step caching, these volumes are the runner's own, and what they hold is outside every step's
key (their identity, repository and trust scope are in it). A replayed step doesn't write into them
again, so a step that installs a tool into the tool cache itself (not through a setup action, which
runs every time) and is replayed after the volume was pruned leaves a later step a PATH to a
directory that is gone (proofs/README.md, "Against today's code"; #102).

### The Zig cache seed

Zig jobs' global cache is seeded by default. Zig 0.17's `zig build` first compiles a build runner
that is the same for every project: 104 s on one core and about 1 GB. The runner builds it once, with
`zig build --help` on a `build.zig` it writes itself, for each release in
`RUNNER_ZIG_SEED_VERSIONS` (comma-separated; by default the Zig the runner is built with) and each
Zig version the tool-cache check finds in a `repo` job's tool cache (`zig/<version>/`), at most 3
in all.

A version only picks which official, signed release is seeded, never its content. The runner
downloads the release's tarball and `.minisig` from ziglang.org and checks the signature and its
trusted comment against Zig's public key, pinned in `runner/src/zig_release.zig` (Ed25519 over
BLAKE2b-512, natively). Only then does the seed build get the tarball's sha256, which it checks the
tarball it downloads against. A release that doesn't verify isn't seeded, and "Set up job" says so.
`RUNNER_ZIG_SEED=<version>=<sha256>` pins one release by digest instead. The seed never takes
anything from a job, so one seed safely serves `repo` and `untrusted` jobs in every repository.

On the laptop, a seed cut a cold `zig build test` of zig-runner from 146 s to 49 s, and the engine's
working-set rise per job from 0.98 to 0.55 GB (runner-bench `zig-seed.yml`). A seed that can't be
built leaves the job unseeded, and "Set up job" says which happened.

Zig's global cache is never shared between jobs: Zig runs what it finds in `o/` without checking
it, so each job gets its own copy of the seed (or an empty cache), and what it adds is gone when it
ends. Only the package tarballs (`p/`, which Zig hashes again when it unpacks them) stay in the
scope's volume. Zig's local cache volume (`RUNNER_ZIG_LOCAL_CACHE`) is kept only for jobs the
runner vouches for.

### Running jobs through the dagger CLI

`RUNNER_ENGINE=cli` runs each job as `dagger run --progress=logs sh -c ...` (`DAGGER_CMD`, default
`dagger`) and reads the session's port and token from it, instead of opening a session itself. It
needs the dagger CLI, `sh` and `cat` on `PATH`. The release image is built `FROM scratch` and has
none of them, so cli mode suits a runner installed on the host, or an image you extend with them.
The runner checks for the three once at start-up and exits with a config error naming the ones it
cannot find, so a pool without them never takes a job. If one goes missing later, "Set up job"
names it as well, instead of blaming the Docker daemon.

### Dagger inside steps

Steps get the Dagger engine (privileged nesting, for `dagger call` inside a step) only when a pool
turns it on with `RUNNER_DAGGER_NESTING=true` (off by default; the runner logs which at startup),
and then only in jobs the runner vouches for. A step's own Dagger client can open any cache volume
by its key, which is no secret, so in any other job it could write what trusted jobs read (#228). A
step there that uses Dagger and fails is told why, and "Set up job" says `Dagger in steps: off`.

The native backend refuses nesting for good, because `dagger call` needs a Dagger engine and native
steps run without one. A pool that needs it keeps an engine (`RUNNER_ENGINE` not `none`), and its
jobs run on Dagger; `RUNNER_ENGINE=none` with nesting on stops at start-up, saying so. Otherwise
turn nesting off.

Run **one engine per trust level**. Untrusted jobs on one engine share its `untrusted` volumes; the
engine's other state (its layer cache, and through a trusted job's nesting the engine itself) is
not scoped at all; and nesting is control of the host. A second instance on prod's machine
(`zig-runner@sandbox.service`) gets its own engine, or none.

## Deploying releases

A release deploys itself to razorbill. Once its binaries and image are built and CI has passed on
the tagged commit, `release` records a GitHub deployment of the version to the `razorbill`
environment.

The tagged commit is the release commit `version` pushes to `main`, which the merge queue never
checked; the push starts `ci` on it, on prod, at the same time as `release`. So the deploy job
waits, up to 40 minutes, until the checks in `.github/checks-on-main`, "Binaries", "Image" and
"Image (publish)" have each completed on that commit. It fails, naming the check, as soon as one
hasn't succeeded or once the wait runs out. (The deployment can't list them as
`required_contexts`: GitHub matches those against commit statuses only, not Actions check runs.)
Once the check passes (re-run it), re-run the release's failed jobs, which is the deploy job alone.
Re-running all of its jobs works too: the binaries job finds the release published, checks it is
complete and attested, and leaves it alone.

To rebuild one tag's image, run `release` by hand from `main` with the tag (v0.14.0 or later). It
waits for approval in `prod`, and moves `latest` only for the newest version tag.

When CI can't pass for a reason that isn't the release's (a prod runner that is down, perhaps
because the release before broke it), a maintainer deploys by hand, with a token that can write
deployments and no checks required. The agent on razorbill still checks the binary's checksum and
provenance.

```sh
jq -n --arg ref v1.2.3 '{ref: $ref, environment: "razorbill", auto_merge: false,
  required_contexts: [], description: ("zig-runner " + $ref + ", by hand")}' |
  gh api -X POST repos/Open-Blue/zig-runner/deployments --input -
```

### The deploy agent

On razorbill, `zig-runner-deploy.timer` asks GitHub every minute. For a new deployment,
`deploy/zig-runner-deploy`:

1. refuses a version older than the one installed, unless `ALLOW_DOWNGRADE` in
   `/etc/zig-runner-deploy.env` names it (a deliberate rollback);
2. downloads the release's binary, checks it against `SHA256SUMS`, and checks its provenance: built
   by `release.yml`, from that tag, on GitHub's own runners (`gh attestation verify`, offline, on
   the attestations and Sigstore trust root it fetched). A fetch that fails for a passing reason (no
   network, a rate limit, a timeout, Sigstore's CDN) reports nothing, and the timer tries again a
   minute later, up to `ATTEMPTS` (30) times before it reports failure. A check that fails reports
   failure at once;
3. installs it and restarts every runner instance (`zig-runner.service` and
   `zig-runner@*.service`, or `UNITS`), each finishing its running jobs first;
4. reports success once each instance is listening for jobs again, or puts the previous binary back
   and reports failure.

The outcome shows on the deployment, under the repository's Environments. The `razorbill`
environment takes deployments of `v*` tags only. Nothing reaches into the machine: it asks GitHub,
with a token that can only read and report deployments.

To set it up on a machine, you need `gh` 2.68 or later from [cli.github.com](https://cli.github.com)
(Debian's package can't verify provenance) and a fine-grained token for this repository with
Deployments read and write, and Attestations and Contents read:

```sh
sudo install -m 0755 deploy/zig-runner-deploy /usr/local/bin/
sudo install -m 0600 deploy/zig-runner-deploy.env.example /etc/zig-runner-deploy.env   # GH_TOKEN
sudo cp deploy/zig-runner-deploy.service deploy/zig-runner-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now zig-runner-deploy.timer
```

## A fresh install

`.github/scripts/fresh-install.sh` tests what the README says on a machine with nothing of ours on
it (#377). As root, from a fresh `git clone`, it installs the packages the build and the sandbox
need, installs Zig with `install-zig.sh` (pinned, checked against ziglang.org's checksum), builds
with `zig build -Doptimize=ReleaseSafe`, runs the native tests as root with
`ZIG_RUNNER_REQUIRE_NATIVE=1`, and runs a real job through the built binary: `--exec-job` on a saved
job, native backend, no Dagger engine. That job needs no credentials, no Docker and no GitHub, only
a registry to pull `ubuntu:24.04` from. Each stage's output is in `$FRESH_INSTALL_WORK/log`
(`/var/tmp/zig-runner-fresh` by default), and the script ends with the time each took.

On a cloud VM (#377's suggestion): a Spot `e2-standard-4` (4 vCPU, 16 GB) with a 60 GB balanced
disk, Debian 13, no snapshot schedule, SSH only, and a billing budget alert set first.

```sh
git clone https://github.com/Open-Blue/zig-runner && cd zig-runner
sudo .github/scripts/fresh-install.sh
```

**Delete the VM afterwards**: a stopped VM still charges for its disk. The root tests start
sandboxes with cgroups and nftables and can take down the machine they run on, which is why this is
a machine to lose. On Ubuntu, AppArmor stops unprivileged user namespaces; `FRESH_INSTALL_LIFT_APPARMOR=1`
lifts the sysctl for the run, as CI does, and restores it after (never do that in a container: the
sysctl is the host's).

To also try a runner registered with GitHub, set `FRESH_INSTALL_REGISTER=1`, `GH_SCOPE`, and either
`GH_TOKEN` or `GH_APP_ID` with `GH_APP_PRIVATE_KEY_FILE`. The script starts one runner with a label
of its own for `FRESH_INSTALL_REGISTER_SECONDS` (90), checks that it was accepted and listens, and
stops it, which removes the registration. Dispatch a workflow with `runs-on: [self-hosted,
<the label it prints>]` in that time. **Don't register it on a public repository**: a fork's pull
request could run code on the VM. Use a private repository or a test organization, and delete the
token or the App's installation after.

## Rebooting the machine

The engine keeps its cache across a restart only if it can mark the cache clean first (see
[docs/BENCHMARKS.md](BENCHMARKS.md)), and Docker gives a container 10 s at shutdown. So stop the
runner instances (each finishes its running jobs), then the engine with time to spare, then reboot:

```sh
sudo systemctl stop zig-runner.service 'zig-runner@*.service'
docker stop -t 300 <engine container>
sudo reboot
```

The engine's restart policy is `unless-stopped`, and Docker counts a `docker stop` as stopped on
purpose: after the reboot the engine stays down while the runners come back, and every job fails
with no engine socket. Start it again (`docker start <engine container>`), then check that
`/run/dagger/engine.sock` exists and the engine's log has no `unclean` or `wiping` line.

## Memory

Four heavy jobs taken at once on razorbill filled the engine's 4 GB, then the Pi's 2 GB of swap, and
the machine thrashed for hours (#126). Two things keep that from happening again.

**The runner's memory gate**, on by default (`RUNNER_ADMISSION=false` turns it off):

- A runner asks GitHub for a job only while the machine has the memory for it, reserving room for
  the jobs its pool's other runners may be handed at the same moment. It stops while memory
  pressure or swap growth says the machine is struggling. A held runner removes its registration,
  so GitHub gives the job to another runner. Running jobs are never touched.
- Where it can find the engine container's cgroup (a runner on the host, reaching the engine over a
  unix socket), it also holds on the engine's own memory cap and swap, since the engine can fill
  its cap while the machine still has memory (#142). It learns what each job (by repository,
  workflow and name) takes, so a light job reserves less than a heavy one once it has run (#144).
- A native job (`RUNNER_BACKEND=native`) is measured in a cgroup of its own and learned apart from
  Dagger's. It reserves 256 MB until it has run (`RUNNER_NATIVE_MEM_PER_JOB_MB`), as does a runner
  polling: the job it is handed waits, kept, for room for its own estimate once it is named (#361).
  The runners polling count only the job that has waited longest, so small jobs aren't held behind
  a queue of heavy ones, and a job whose name has run for 60 s at most each time starts beside the
  one waiting if it fits without it (#415).
- Pools on one machine share one budget (`RUNNER_SHARED_MEMORY_BUDGET`, on for a root runner): each
  writes what its jobs still ramping up have reserved to `/run/zig-runner/memory-budget`, and every
  gate takes the other pools' live lines off `MemAvailable`, so two pools don't admit a job each
  into the same free memory. The directory must be writable: under `ProtectSystem=strict` the unit
  needs `RuntimeDirectory=zig-runner` and `RuntimeDirectoryPreserve=yes`.
- What jobs took, and how long they ran, is kept across restarts in the native store's directory
  (#407). A pool whose one job could never fit the machine doesn't start, and names the setting
  (#406).
- Where jobs may swap, a job gets a `memory.high` from its estimate, so one that outgrows it is
  slowed in its own cgroup rather than taking its neighbours' memory. All native jobs together stay
  under the machine's memory less a third, with no swap, each under two thirds of that, and a job
  that can't be held to it doesn't run natively ([docs/native-backend.md](native-backend.md),
  "Bounded jobs").
- The gate sees only its own process's runners: run one pool per machine. The limits, and why they
  are what they are, are in `deploy/runner.env.example` (`RUNNER_MIN_MEM_AVAILABLE_MB` and the
  rest).

**No swap for the engine**, optional. With `--memory 4g` alone, Docker lets a container swap as
much again; `--memory-swap` equal to `--memory` (`memswap_limit` in Compose) gives it none. A job
that outgrows the engine then fails inside it, killed by the kernel, instead of the whole machine
slowing to a crawl. The trade-off is a failed job in place of a slow one, and the risk that the
process killed is the engine itself, whose unclean restart wipes its cache: check which process the
kernel picks before relying on it. razorbill doesn't use it today.

### The health line

While a job runs or waits, the runner logs one `health:` line a minute (`RUNNER_HEALTH_INTERVAL`
seconds, 0 for none): `MemAvailable` and `SwapFree`, memory PSI
(`some`/`full` avg10), I/O PSI (`some` avg10), the load averages, what the gate has reserved, the
jobs running and waiting, and for each running job its name, elapsed time and working set (with a
`~` when it is the engine's, which every job on it shares). After a machine drops off, the last
`health:` lines in the journal show what it looked like (`journalctl -u <unit> | grep health:`).

Each `health:` line is followed by the runner process's own, `health: proc rss=… anon=… thr=… fds=…
mounts=… zombies=… heap=…/blocks`: its resident and anonymous memory, threads, open descriptors,
mounts in its namespace, children that exited and were never waited for, and what its allocator has
handed out and not taken back (bytes and blocks). Each job also ends with one `job-end:` line: the
same figures once its teardown ran, and how they changed while it ran (`dheap`, `dblocks`, `dfds`,
`dthr`, `dmounts`). Other jobs of the process change them too, so read them as a trend: a heap,
descriptor count or mount count that only climbs across jobs is a leak
(`journalctl -u <unit> | grep job-end:`). A zombie child is logged as a warning at the job's end.

While no job runs or waits, only the process's own line is logged, `health: proc …`, every 15
minutes (`RUNNER_HEALTH_IDLE_INTERVAL` seconds, or `--health-idle-interval`; 0 for none, and
`RUNNER_HEALTH_INTERVAL=0` turns it off too). It counts from the last health line of either kind, so
growth between jobs shows, and the first one is said when the runner starts, as a baseline.

### The runner's warnings and errors

The runner's own warnings and errors, on its stderr (the journal), have one format, so that a grep
or an alert can key on it:

```
warn: kind=cgroup_not_removed path=/sys/fs/cgroup/zig-runner/job-7 err=Busy
error: kind=upload_failed job=123 what=job_log name="" detail=NameServerFailure
```

- The line starts `warn:` (something went wrong that the runner worked around, or may repeat) or
  `error:` (the runner or a job's step gave up on it).
- `kind=` follows, a short snake_case name for what happened: the same kind for the same event, so
  `grep 'kind=upload_failed'` finds every one.
- The rest are `key=value` pairs. A value with a space, a quote, an `=`, a backslash or a control
  character is double-quoted, with `\"`, `\\`, `\n` and `\xNN` escapes, so a line is one line
  and a value never reads as a key. `err=` is a Zig error's name or a system error's (`Busy`,
  `FileNotFound`), `job=` a check run id, `path=` a path.
- A warning from a part of the runner that has not named its kind is `kind=<its prefix>
  msg="…"`: `native: cannot remove /x: Busy` is `warn: kind=native msg="cannot remove /x: Busy"`.
  One with no prefix is `kind=log msg="…"`.
- `info` lines (`info(scope): …`) and the lines with formats of their own are not warnings and
  keep them: `health:`, `job-end:`, `step-end:`, `request:`, and the plain `job N: …` progress
  lines. What a job's log shows to the user (GitHub's `##[warning]`, an action's `Warning:`) is
  the job's, and stays as GitHub shows it.

`journalctl -u <unit> | grep -E '^(warn|error):'` lists them all; `grep ' kind=zombie_children '`
finds one kind.

### An engine that stops answering

An engine that stops answering altogether (frozen, deadlocked) would hold a step for good. So a
step's query with nothing heard from the engine for `RUNNER_ENGINE_SILENCE_TIMEOUT` seconds (600 by
default) is aborted and the step failed, saying why (#100). "Nothing heard" means no health check
(the engine sends one every 5 s), no byte of an answer and no log line; a swapping engine answers
late, but not that late, and keeps logging. It applies only while a step runs, and the runner logs
the timeout when it starts. Raise it for an engine that is often that slow; `0` turns it off.
