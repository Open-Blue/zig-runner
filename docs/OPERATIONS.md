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

### Cargo's caches

Two caches keep a Rust build from starting over in every job, each in the scope of the job's other
caches (`repo` or `untrusted`, never across them), on the Dagger and the native backends:

* The crate registry and git checkouts (`~/.cargo/registry`, `~/.cargo/git`) are cache volumes of the
  scope, as before. In the `repo` scope they are now mounted for jobs that run Zig as well as those
  that name cargo, because Zig's build system runs cargo for a project with Rust in it
  (zig-runner's own `zr-net`). An untrusted Zig job does not get them: it keeps `CARGO_HOME` in its
  temp directory and downloads and checks every crate, because one untrusted job could plant
  unpacked source (below) that another untrusted job's offline build compiles.
  Cargo checks a `.crate` file's checksum against `Cargo.lock` only when it downloads it; the
  unpacked `src/` it finds later is used unchecked, so the registry stays inside one scope and is
  not shared more widely.
* `RUNNER_CARGO_TARGET_CACHE=true` (needs `RUNNER_ZIG_LOCAL_CACHE`) sets `CARGO_TARGET_DIR` to
  `cargo-target/` inside Zig's local cache volume. Cargo's compiled output and build-script binaries
  run in later jobs without being checked, as Zig's `o/` does, so they have the same scope (only
  jobs the runner vouches for; an untrusted job's directory is its own and goes with the job), the
  same size limit (`RUNNER_ZIG_LOCAL_CACHE_MAX_MB`, counted with Zig's) and the same generations
  (the cache starts over, whole, past the limit). Off by default because `target/` leaves the
  workspace for jobs that run cargo: a workflow that reads `target/release/...` sets its own
  `CARGO_TARGET_DIR`, which wins. Cargo locks the directory, so jobs that build at once take turns. With a size limit the
  path is the generation `current` pointed at when the job started (`.../gen-N/cargo-target`), not
  `current`: cargo resolves it on every file operation, so a roll another job starts does not move a
  running job's output.

`.github/scripts/build-zr-net.sh` (zig-runner's own Rust library) uses both: it keeps cargo's home in
the job's temp directory unless `~/.cargo/registry` is a mount of its own, and builds with
`--frozen` first when the registry has crates, so a job whose crates.io lookup fails still builds
from the cache; if a crate is missing it builds again with `--locked` and the network.

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

### A Docker API for native jobs (stage 1a of #448)

`RUNNER_NATIVE_DOCKER_API=true` (`--native-docker-api`; off by default) gives every native job a
Docker-compatible API of its own: a unix socket in the job's directory, bound into each step at
`/var/run/docker.sock`, with `DOCKER_HOST=unix:///var/run/docker.sock` and `DOCKER_BUILDKIT=0` in
the step's environment (a workflow's own `env:` wins). It is the runner's thread that answers, not
the host's Docker daemon and not a Dagger engine, and only that job's steps have the socket; it is
removed with the job. Nothing changes for a job while the option is off.

This first stage answers `/_ping`, `/version` and `/info`, so a `docker` CLI in the step (an image
that has one, or a setup action; the runner does not provide it) finds a server and says what it
is. Every other endpoint, `docker build` included for now, gets HTTP 501 with
`{"message":"not supported by zig-runner yet: <METHOD> <path>"}`, and BuildKit's (`docker buildx`,
`docker/build-push-action`) a hint that they need a later stage. A job that uses the API logs one
`info: kind=native_docker_api job=.. connections=.. requests=.. unsupported=.. refused=..
timeouts=.. busy=..` line when it ends. Each job's API answers at most 100 requests a second (429 past that), and a step that makes any
request beyond those three is not stored for replay in the step cache. A job container whose
`volumes:` are at or around `/var/run/docker.sock` gets no API, and says so in "Set up job". Sending a job that needs more than this to an engine
ahead of time, so that no Docker job is lost, is a later stage (#448, decision 2).

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
   `zig-runner@*.service`, or `UNITS`), each finishing its running jobs first. That needs
   `KillMode=mixed` in the unit (deploy/zig-runner.service has it since v0.36.0): with systemd's
   default, the stop's SIGTERM also reaches a native job's processes, which share the unit's cgroup,
   and their step dies at once. A unit installed before it takes the setting with
   `sudo systemctl edit zig-runner.service` (and `zig-runner@.service`): `[Service]` and
   `KillMode=mixed`, then `sudo systemctl daemon-reload`;
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

## Channels

A machine follows a channel: which builds its runner binary comes from. The release is the unit of
trust for production (every merge since the last, built once, attested, deployed after CI passed on
it), but a change should run somewhere real before it is one. Channels (#550) put it there without
touching what stable machines get.

| Channel | Installs | Built by | Feed |
| --- | --- | --- | --- |
| `stable` (default) | releases only | `release.yml`, at the tag | the `razorbill` deployment, as above |
| `rc` | release candidates `vX.Y.Z-rcN`, and releases, the newest by version | `candidate.yml` at the tag; `release.yml` for a release | GitHub's releases |
| `main` | the candidate built from each commit on `main` | `candidate.yml`, at `main` | GitHub's releases |

**Candidates.** `candidate` builds the release's binaries, both architectures, with the same
script, hardening check and attested provenance and SBOM as a release, on every push to `main` and
every tag `vX.Y.Z-rcN`, and publishes them as a pre-release. A main candidate is the release
`main-N-SHA12` (N is the workflow's run number, so it only grows) whose binaries say
`vX.Y.Z-main.N+SHA12`, X.Y.Z being the latest release with its patch raised by one. It is never
"latest", so nothing that follows the latest release sees it, and `release` ignores any tag with a
hyphen, so a release candidate never takes the release path (stable releases are tagged, built,
published and signed as before). Release tags are created only by the version workflow's deploy key
(the "release tags" ruleset), so an `-rc` tag is too. Why releases and not workflow artifacts or one rolling
`channel-main` release: a release is public, so the agent needs no more access than for a release,
and each candidate is immutable with its own checksum and attestation (the repository's releases are
immutable), where artifacts expire and need a token that reads Actions, and a rolling release would
be overwritten under a machine that was reading it.

**Retention.** Candidates are pre-releases, so they are never "latest", and they are pruned:
`prune-candidates.sh` deletes a main candidate or release candidate (and its tag) published more
than `CANDIDATE_RETENTION_DAYS` ago (14), unless it is among the newest `CANDIDATE_KEEP` (20) of its
kind (main candidates by run number, release candidates by version), the ref of one of the newest
three deployments of `razorbill-rc` (what the rc pool runs, and what it rolls back to), or named
with `--protect`. Releases, drafts and anything not named exactly like a candidate are never
touched. `candidate` runs it after publishing, and `candidate-prune` daily (the days nothing
merged); a run of the latter by hand defaults to a dry run, which lists what would go and deletes
nothing (`GH_REPO=... prune-candidates.sh --dry-run --days 14 --keep 20` does the same by hand).
What a unit on `main` runs is not recorded anywhere GitHub can read, so it is held only by being
among the newest; keep `CANDIDATE_KEEP` above the number of merges a day times the days a machine
might be offline. The image of a pruned release candidate stays in the registry.

**The release candidate's image and deployment.** A tag `vX.Y.Z-rcN` also builds, scans (Trivy,
as a release's) and pushes `ghcr.io/<owner>/zig-runner:vX.Y.Z-rcN` for both architectures, from the
candidate's own binaries (checked against `SHA256SUMS` and their `candidate.yml` provenance), with
the image's provenance and SBOM attested, and `:rc` while it is the newest release candidate. It
never pushes `:latest` or a release's tag (`:vX.Y.Z`), so `latest` and the stable versions are what
only `release.yml` makes. Once CI has passed on the tagged commit, a deployment is recorded to
the environment `razorbill-rc` (a release's goes to `razorbill`, whose deployments stable machines
install): a pool is an environment name, so another pool on `rc` is another environment and a line
in `candidate.yml`. A main candidate gets neither image nor deployment record: one image per merge
would fill the registry, and a machine on `main` reads the releases feed anyway.

**To set up (maintainer).** Nothing is needed for the workflows to run. Optional: repository
variables `CANDIDATE_RETENTION_DAYS` and `CANDIDATE_KEEP`; the `razorbill-rc` environment is created
by the first deployment (add protection rules to it, or a name for another pool, by hand if wanted);
if the "release tags" ruleset also restricts deleting tags, pruning an `-rc` tag fails (the release
is deleted, the tag stays, logged) until the ruleset lets `github-actions` delete tags matching
`v*-rc*`; GHCR packages may need the repository's Actions access to push (as for releases).

**The agent.** `CHANNEL` in the agent's env file picks the channel (`stable` if unset, which is
everything described under "The deploy agent", unchanged). On `rc` and `main` it reads the releases
feed instead of deployments, picks the newest candidate of its channel and runs the same checks:
the binary against `SHA256SUMS`, then provenance (`gh attestation verify`) from the right workflow
at the right ref, and the binary says the version the candidate is named for:

- `release`: `release.yml`, `refs/tags/<tag>`, as on `stable`;
- `rc`: `candidate.yml`, `refs/tags/<tag>`;
- `main`: `candidate.yml`, `refs/heads/main`, and the commit the tag points at.

The version is monotonic within a channel: a main candidate is ordered by its base version
(X.Y.Z of its release's name), then its run number N, so a restart of the run numbers under a higher
base still advances; one that restarts under the same base cannot be ordered, and the agent says so
in its journal (`kind=main_candidate_stalled`) instead of waiting silently. A main candidate that is not above the
installed one, or an rc or release older than the installed one, is not installed (logged, not a
failure; `ALLOW_DOWNGRADE` is `stable`'s). Installing, restarting, the health check and the
`$BIN.prev` rollback are the same. A `stable` machine never installs a candidate: it takes a
deployment's ref only if it is `vX.Y.Z`, and checks it against `release.yml`, so a candidate in a
deployment is refused and a candidate in the feed is never read. A channel has no deployment to
report to (any number of machines read the feed): outcomes are in the agent's journal. A candidate
that fails a check is written to `rejected` in the agent's state directory and not fetched again;
a newer one is tried as usual. A fetch that fails for the moment is retried every minute.

**Switching.** Changing `CHANNEL` is a decision made on the machine, so the first install after
it replaces the binary whatever its version, and logs `channel switch: stable -> main`; the order is
checked again from then on. The channel is recorded in the state directory after a successful
install. Moving back to `stable` installs the newest deployment that went well, though it is
handled.

**One binary has one channel.** Every instance on a machine runs `/usr/local/bin/zig-runner`, so a
pool on another channel gets its own binary and its own agent: `zig-runner-deploy@<name>.timer`
reads `/etc/zig-runner-deploy-<name>.env` and keeps its own state. The pool's runner unit runs
that binary (a drop-in with `ExecStart=` and the path). Name the stable agent's `UNITS` (left empty it
restarts every `zig-runner@*.service`) and keep the pool's instance out of it, or the stable agent
restarts it onto the stable binary.

```sh
# A pool "qa" on main candidates, beside the stable pools:
sudo install -m 0755 deploy/zig-runner-deploy /usr/local/bin/
sudo cp deploy/zig-runner-deploy@.service deploy/zig-runner-deploy@.timer /etc/systemd/system/
sudo install -m 0600 deploy/zig-runner-deploy.env.example /etc/zig-runner-deploy-qa.env
# edit it: GH_TOKEN (Contents and Attestations read; no Deployments needed),
#   CHANNEL=main  BIN=/usr/local/bin/zig-runner-qa  UNITS=zig-runner@qa.service
sudo systemctl edit zig-runner@qa.service   # [Service] ExecStart= / ExecStart=/usr/local/bin/zig-runner-qa
sudo systemctl daemon-reload && sudo systemctl enable --now zig-runner-deploy@qa.timer
```

To see what an agent would do without installing: `DRY_RUN=1 CHANNEL=main BIN=/tmp/zr
STATE_DIR=/tmp/zr-state UNITS=<any loaded unit> GH_TOKEN=... deploy/zig-runner-deploy`. To put a
pool on `rc`, the same with `CHANNEL=rc`; to take it off, set `CHANNEL=stable` (or remove the
line) and let the stable agent's unit own the binary again.

**Progressive environments (#550).** Channels are the ground for the rings: a razorbill `qa` pool on
`main` runs every main commit's own build before it is a release; the bench pool on `rc` runs the
release candidate (and then the release itself) before stable pools, which get the release only
once it is deployed. Cutting a release candidate, the QA verdict that gates a release, and health
checks are later pieces. The `rc` channel takes a release as soon as it is published, a few minutes
before `release` records its deployment (which waits for CI on the tagged commit): the canary is
the first ring, not the last check.

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

### Job priority (#549)

A zig-runner extension that GitHub Actions does not have (shipped as a prototype in v0.35.0; the
extension is named `ZIG_RUNNER_PRIORITY`). A job has a level 0 to 9, named `low` 1, `normal` 4 and
`high` 7. The level comes, first match wins, from a policy file (`RUNNER_PRIORITY_POLICY`), from
the job's own `env: ZIG_RUNNER_PRIORITY` (a literal in a workflow- or job-level `env:`, capped at
`RUNNER_PRIORITY_ENV_MAX`, and at `RUNNER_PRIORITY_DEFAULT` for a job the runner does not vouch
for: on a pool with `RUNNER_TRUSTED_REFS=*` no job's own marker rises above the default, and only
the policy file raises a job), or from `RUNNER_PRIORITY_DEFAULT`. Jobs waiting at the memory gate
start in order of level, rising one level for each `RUNNER_PRIORITY_AGE_SECS` (60 s by default,
per pool: a `low` job reaches the top within 8 minutes); native jobs get `cpu.weight`,
`io.weight` and, for a high one, `memory.low` from the level.

**The policy file's format is experimental** until it has run on real pools: its fields, its
globs and its first-match order may change between releases. A level in `ZIG_RUNNER_PRIORITY` and
the `RUNNER_PRIORITY_*` settings are not part of that note.

**Freezing is opt-in and bounded** (`RUNNER_PRIORITY_FREEZE`, off by default): under memory
pressure a lower native job's steps are frozen (`cgroup.freeze`) for a higher job, for at most
`RUNNER_PRIORITY_FREEZE_MAX_SECS` (90 s) at a time. The runner itself is in no job's cgroup, so
the job's hold and log go on while its steps are paused; a cancel, a timeout or a shutdown thaws
the steps before it signals them.

**A pause does not eat a timeout.** The time a job was paused (on the monotonic clock, all its
pauses added, the one under way included) moves the deadline of the step that was running, and of
the job's `timeout-minutes` where the runner enforces it. A step with `timeout-minutes: 10` that
was paused for 80 s runs out 10 minutes and 80 s after it began, counting only what it ran. The
step's `step-end:` line carries `paused_ms=<ms>` when it was paused, "Set up job" says that a pool
may pause, and "Complete job" says how long the job was paused. What is not extended: the readiness waits of services and image pulls (set-up, before the steps run, so before a pause can happen), and a pre or post script, which has no timeout of its own and no `step-end:` line (its pause is only in the job's total, in "Complete job"). Two limits: a step that began in
the middle of a pause counts only what came after its start, and a job's own `timeout-minutes` on
GitHub is enforced by GitHub itself (it cancels the job through the session, and the job
definition does not carry the limit), so there a pause moves the step timeouts but not the job's;
on Gitea and Forgejo, where the runner enforces the job's limit, both move.

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

### The memory soak

`.github/scripts/memory-soak.sh` runs jobs one at a time through one runner process and checks that
what the health line shows comes back to where it was. The runner is the real binary (native
backend, no engine, `RUNNER_PLATFORM=gitea`) in a privileged container with a memory limit, under
the root tests' lock, polling a local Gitea; the jobs cycle through seven shapes (run steps with
outputs, env and a summary, checkout, a container job, a failing job, a cancelled job, a 100,000-line
log, a step that times out). After each job the script waits for the runner's `job-end:` line and
for the first idle `health: proc` line four seconds later, and reads the runner's exact `VmRSS` and
`RssAnon` from `/proc`. The first 20 samples are left out, and each counter is judged on the rest:
it fails when the fitted line and the robust (Theil-Sen) slope of the run's second half are both
above its per-job margin, or when the median of its last 20 samples is above the median of its
first 20 by more than its total margin. Handles, threads, mounts and zombies must not rise at all.
The margins are `LIMITS` in `.github/scripts/memory_soak.py`. Each shape of job must also have done
its job: at least 90% of its jobs must end as the shape says (success, failure or cancelled) and
leave an idle sample, or the run fails, naming the shape and the cause the runner's log gave (a
container job refused by Docker Hub's rate limit is "container: 0 of 3 jobs ended 'success' ...
HTTP 429"), so a run in which a shape tested nothing is not a pass.

    .github/scripts/memory-soak.sh --jobs 500      # 2 to 3 hours (3 on the laptop, below): the long run, for a machine of one's own
    .github/scripts/memory-soak.sh --jobs 50 --own-instance   # the nightly analysis job's: about 20 minutes

The first 500-job run (laptop, x86_64, native, 2026-11-14, 3 hours) ended with the heap at 510 KiB in
9 blocks, `rust=` at 0K (the network library is a skeleton on main and takes no part in these
jobs, so `rust=` covers nothing today; it becomes meaningful once the library's allocator is in use,
when R4 and R5 merge, and its margins in `LIMITS` are unmeasured until then), and 11 descriptors, 13 threads, 14 mounts and no zombies, all exactly as at job 20; resident
and anonymous memory rose from 7.8 and 2.6 MiB to 9.3 and 4.1 MiB, in steps at first use (threads
touching their stacks) and then 0.87 KiB a job, which the margins of `memory_soak.py` allow and
explain. The container shape asks Docker Hub about its image once per `RUNNER_IMAGE_TAG_TTL` (a `HEAD`, which
Docker Hub does not count), where before #551's fix it asked on every job, and Docker Hub's
unauthenticated limit is 100 pulls in 6 hours from one address: a runner without that fix failed those jobs ("HTTP
429") and the run says so (`ended 'failure', expected 'success'`). `--shapes` narrows a run to some
shapes, `ZR_SOAK_SMAPS=1` saves the runner's `/proc/<pid>/smaps` before and after (`ZR_SOAK_SMAPS_AT=N`
after job N as well), to say which mappings grew.

What the soak can tell. The runner's counted heap (its health line's `heap=` bytes and blocks, exact
KiB) is resolved to under 1 KiB a job: `memory_soak.py selftest` pins that a synthetic leak of 1 KiB
a job in the counted heap fails, and that 0.25 KiB a job (under the margin) does not. Memory that
the counted heap does not see (`smp_allocator`, `page_allocator`, a C library's) shows only in
resident and anonymous memory, which grow 0.87 KiB a job unexplained (not attributed); an uncounted
leak below the 2.0 KiB a job margin, or below the 2048 KiB end-minus-start allowance, cannot be told
from that growth, and the selftest pins that too (1.5 KiB a job passes, 3 KiB a job fails). A runner
older than this check prints the heap rounded to MiB from 10 MiB up, which cannot resolve its margin.

The script removes its token files and deletes the runner's registration from the instance when it
ends (the registration is user-scope, for `zradmin`, so a persistent Gitea does not collect one per
run). `memory_soak.py selftest` also runs in ci on a change to the soak's files.

`ZR_SOAK_ALLOW_ANON_KB` is a flat allowance for memory a library keeps in a bounded cache that the
`rust=` counter does not count (the network library's block cache, up to 8 MiB once it lands): it
raises the end-minus-start margin of `rss` and `anon`, not the per-job one. `memory_soak.py
selftest` checks the judging on made-up series (noise passes; a leak, a rising handle count, a step
and a shape that did nothing are caught).

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

- Name lookups (#522): once a root native job's network exists, the runner asks each nameserver the job gets for
  `github.com`, from a thread inside the job's network namespace (so the query takes the job's veth, NAT and
  forward rules) and off the job's path, and logs `warn: kind=dns_lookup_slow name=github.com ms=3120 rcode=0
  server=100.100.100.100 source=probe` when the first reply took over 2 s, or `kind=dns_lookup_failed` when the
  reply's `rcode` was an error (`rcode=2` is SERVFAIL) or none came in 5 s (`err=Timeout`, `rcode=?`). A reply counts
  only with the query's random id and question. The runner's own requests log the same two kinds with
  `source=request` when their `dns_ms` is over 2 s (`ms` is the whole lookup, in the host's namespace) or they end in
  a resolver error (`DnsFailed`, `UnknownHostName`, `TemporaryNameServerFailure`, `NameServerFailure`,
  `HostLacksNetworkAddresses`; with no lookup time the line has `total_ms`). Nothing about the job's resolver
  changes; the thresholds are fixed. A job's resolv.conf holds the host's IPv4 nameservers off the loopback
  (razorbill: Tailscale's 100.100.100.100 only, its IPv6 one is dropped). Rootless jobs have no namespace and no probe.
- Image pulls (#551): `warn: kind=image_tag_reused image=alpine:3.20 digest=sha256:.. status=429 reason=HttpStatus`
  when a native container job's registry could not answer (a 429, a 5xx, the network) and the tag's last known
  digest, still in the store, ran instead of failing the job. A tag is asked about at most once per
  `RUNNER_IMAGE_TAG_TTL` seconds (default 300), by a `HEAD` that Docker Hub does not count; a digest-pinned image
  never. The warning also has `age_s` (seconds since the registry last confirmed the tag) and `moved=false`; when a
  `HEAD` had already shown that the tag names another digest and only the manifest fetch then failed, it is
  `moved=true new_digest=sha256:..` and the old image still runs (chosen for availability, within the age limit below).
  `RUNNER_IMAGE_TAG_MAX_STALE` (`--image-tag-max-stale`, seconds, default 86400, 0 never falls back) bounds that cover,
  counted from the last successful manifest or `HEAD`: past it a registry that cannot answer fails the job, naming the
  registry's error (`HTTP 429`, ...) and how long ago the stored image was confirmed, so a deleted or replaced tag is not run
  for ever. A day rides out an outage or a rate limit's window and a weekend's neglect, and bounds a CVE-fixed tag's life.
  A `HEAD` that confirms the tag also says so in the job's "Set up job" (`Image: from the native store; <tag> is still
  <digest>: the registry confirmed it by a HEAD`). See docs/native-backend.md.
- Bridge option (#616): `warn: kind=bridge_no_linklocal_learn_unsupported bridge=zr0 err=OPNOTSUPP` (or `INVAL`),
  once per job network made, when the kernel (before 5.12) cannot set `no_linklocal_learn` on the jobs'
  bridge. The job's network is made anyway: each job port already learns nothing, which is what stops a
  job's link-local frames from filling the bridge's table; the option is the second layer.
- Link-local frames (#642): `warn: kind=netdev_linklocal_drop_unsupported slot=3 err=AFNOSUPPORT` (or `OPNOTSUPP`,
  `NOENT`), once per job network made, when the kernel has no nftables netdev family
  (`CONFIG_NF_TABLES_NETDEV` off), so the job's port has no ingress rule dropping frames to link-local group
  addresses. The job's network is made anyway: the runner's `ip` table drops what `zrh*` sends the host's
  stack in IPv4, and the port has IPv6 off.
- `info` lines (`info(scope): …`) and the lines with formats of their own are not warnings and
  keep them: `health:`, `job-end:`, `step-end:`, `request:`, and the plain `job N: …` progress
  lines. What a job's log shows to the user (GitHub's `##[warning]`, an action's `Warning:`) is
  the job's, and stays as GitHub shows it.

`journalctl -u <unit> | grep -E '^(warn|error):'` lists them all; `grep ' kind=zombie_children '`
finds one kind.

### The step-end and request lines

Two more kinds of line say where a job's time and resources go (`journalctl -u <unit> | grep
step-end:`). Both are `key=value`, space separated; sizes are in bytes, times in milliseconds to a
tenth, and `?` is a figure that could not be read.

Each step ends with one `step-end:` line, logged with the job's `native phases`:

```
step-end: job=<check_run_id> step=<n> name='<display name>' result=<success|failure|cancelled|skipped> wall_ms=.. cpu_ms=.. mem_peak=.. io_read=.. io_write=.. majflt=.. minflt=.. spawn_ms=.. namespaces_ms=.. overlay_ms=.. binds_ms=.. root_ms=.. exit_ms=..
```

A native step's figures are what its cgroup gained between the step's start and its end:
`cpu.stat`'s `usage_usec` (`cpu_ms`), `memory.peak` (`mem_peak`), `io.stat`'s `rbytes` and `wbytes`
(`io_read`, `io_write`), and `memory.stat`'s `pgmajfault` and `pgfault` (`majflt`, `minflt`).
`memory.peak` is reset when the step starts where the kernel allows it (Linux 6.12 and later);
elsewhere it is the peak since the job started and the line ends with `peak_scope=job`. `io_read`
and `io_write` are `?` where the cgroup has no io controller. The six `*_ms` fields are the step's
samples of the same phases `native phases` shows (its helper's start, namespaces, overlay, binds,
root and exit); a step replayed from the store has none, so they are 0.0. A step run by Dagger has
its `wall_ms` and `result` only. A step skipped has `wall_ms=0.0` and `?` for the rest. A quote in
the name is shown as `"` and a control character as a space.

Each HTTP request to GitHub, Gitea or Forgejo (not the Dagger engine's) makes one `request:` line,
written when it ends:

```
request: host=<host> method=<GET|POST|..> path=<path> status=<code|error name> dns_ms=.. connect_ms=.. tls_ms=.. ttfb_ms=.. total_ms=.. bytes_in=.. retry=<n> reused=<0|1> rl_remaining=.. rl_limit=.. rl_reset=<unix s> rl_resource=..
```

`host` has the port when it is not the scheme's. `status` is the HTTP status, or the error that ended
the request (`Timeout`, `ConnectionRefused`, ...). `dns_ms`, `connect_ms` (the TCP connect) and
`tls_ms` are of a new connection and 0.0 for a reused one (`reused=1`); `ttfb_ms` runs from the
request being written to its response's head, which for the broker's long poll is the wait for a
message; `total_ms` is the whole request to the last byte. `bytes_in` is the body, decompressed.
`retry` is 0 for the first attempt, then 1, 2, ... for each time the runner sent the request
again (a connection the server had closed, a timeout, a stale certificate clock). A redirect's
every hop is a request. `rl_*` are the `x-ratelimit-*` headers, `?` when absent. A 403 or 429 also
logs a warning with the response's `retry-after`. The calls that go through `fetch` (the GitHub
App's and the OAuth token's) have `?` for everything but the status and `total_ms`.

The line never holds a token, a query string or a body: the path is cut at its `?`, and each
segment that could be a secret is shown as `*`. A segment stays when it is at most 40 bytes of
letters, digits, `.`, `_`, `-` and `~` and does not look like a credential: it is replaced when it
holds anything else, starts as a token does (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`,
`eyJ`, `glpat-`), or is 20 bytes or more of letters and digits holding both, without a `.`, unless
it is a UUID. Numbers, names, UUIDs and endpoint names (`generate-jitconfig`) stay.
`RUNNER_LOG_REQUESTS=0` turns the lines off (on by default).

### An engine that stops answering

An engine that stops answering altogether (frozen, deadlocked) would hold a step for good. So a
step's query with nothing heard from the engine for `RUNNER_ENGINE_SILENCE_TIMEOUT` seconds (600 by
default) is aborted and the step failed, saying why (#100). "Nothing heard" means no health check
(the engine sends one every 5 s), no byte of an answer and no log line; a swapping engine answers
late, but not that late, and keeps logging. It applies only while a step runs, and the runner logs
the timeout when it starts. Raise it for an engine that is often that slow; `0` turns it off.
