# zig-runner

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Open-Blue/zig-runner/badge)](https://scorecard.dev/viewer/?uri=github.com/Open-Blue/zig-runner)

A self-hosted GitHub Actions runner in Zig. One small process runs many runners; each job's
steps run in a [Dagger](https://dagger.io) engine, which caches them across runs.

This repository holds only what the runner needs to be built, run and deployed:

- `runner/`: the source, `build.zig`, and the `Dockerfile` for the runner image
- `deploy/`: a systemd unit, a Docker Compose file, the engine's configuration, an example env file
- `db/migrations/`: the schema for the optional Postgres mode (run state and logs)

Build and run, with Zig 0.17 and Docker on the machine:

```sh
cd runner
zig build -Doptimize=ReleaseSafe
cp ../deploy/runner.env.example /etc/zig-runner.env   # then fill in GH_TOKEN (or a GitHub App) and GH_SCOPE
zig-out/bin/runner
```

Or install `deploy/zig-runner.service` and run it under systemd, or `docker compose -f deploy/compose.yaml up`.

Instead of `GH_TOKEN`, the runner can manage its registrations as a GitHub App, which reaches only
the repositories it is installed on: `GH_APP_ID` (the App's ID or Client ID) and
`GH_APP_PRIVATE_KEY_FILE` (or `GH_APP_PRIVATE_KEY`), with the permission "Administration: read and
write" for a repository ("Self-hosted runners: read and write" for an organization). It mints
installation tokens itself and refreshes them before they expire. `deploy/runner.env.example` has
the details, including mounting the key under Compose.

## Versioning

Releases follow [semantic versioning](https://semver.org/) and are cut by CI, not by hand. Pull
requests merge on their own once their checks pass, and once a day (or when `version` is run by
hand) everything merged into `main` since the last release becomes one new version, its binaries
and its image, after the maintainer approves it. What it bumps comes from the branches' prefixes,
which CI checks; the largest bump among them wins:

| Branch | Bumps |
| --- | --- |
| `bugfix/*`, `hotfix/*`, `ci/*`, and Renovate's `renovate/*` | patch: `v1.2.3` → `v1.2.4` |
| `feature/*`, `feat/*`, `release/*`, `docs/*`, `perf/*`, `refactor/*` | minor: `v1.2.3` → `v1.3.0` |
| any of them, labelled `breaking` | major: `v1.2.3` → `v2.0.0` |

`feature/*` is for larger features, `feat/*` for small ones; neither breaks anything unless the
pull request carries the `breaking` label. In a stack, each pull request merged into `main`
counts toward the next release; one merged into another's branch instead counts toward that one's
bump when it reaches `main`. The release commits the version to `runner/build.zig.zon`
and the changelog on `main`, and tags that commit. It does so only once `main`'s own checks have
passed on the commit it releases ("Format, build and test", "Database tests", "Workflows" and
"Proofs" on the push to `main`), waiting up to 30 minutes for them. When they cannot pass because of
what the release fixes (prod's runner, broken by the release before), run `version` by hand with
`skip_main_checks`; it still waits for approval.

[semantic-release](https://github.com/semantic-release/semantic-release) and
[release-please](https://github.com/googleapis/release-please) do this job from
[Conventional Commits](https://www.conventionalcommits.org) in commit messages instead (`feat:`,
`fix:`, `feat!:`). They are not used here: the version comes from the branch, and either would
decide the version, write the changelog and tag the release alongside this, disagreeing with it.

## Pipeline

`ci` checks every pull request: the branch name, the workflows (actionlint, and
[zizmor](https://docs.zizmor.sh) for security), the format, build and tests, the database tests
against TimescaleDB, and the release's own builds, for both targets in ReleaseSafe ("Release
builds"), so code that does not compile for aarch64 fails here rather than after the tag;
`proofs` checks the Lean proofs and `release` the packaging (below). Every one of these is a
required check, and reports on every pull request and in the merge queue: on a change that cannot
affect what a job checks, it reports without running its steps
(`.github/scripts/ci-scope.sh tests|binaries|proofs|packaging`, each with the list of files that
can; the build and tests run for any file it does not know, the others only for the files they
read). A path filter would instead leave the check unreported, and the merge queue waiting for
it. The GitHub client's tests run over real connections to a local server
(`src/github/testserver.zig`), so how it handles redirects and tokens is tested, not described. A merge into
`main` goes through the merge queue, which runs these checks again on top of `main`; `automerge` turns on
auto-merge for every pull request from a branch of this repository, so it joins the queue once its
checks pass (Renovate does the same for its own). Once a day, `version` releases what merged since
the last release, if anything did: it waits for approval in the `prod` environment, commits and
tags the release, and the tag runs `release`: the binaries (compiled directly,
`.github/scripts/build-binaries.sh`), the image from those same binaries after a
[Trivy](https://trivy.dev) scan, each with signed build provenance. On pull requests and in the
merge queue, `release` builds and scans the same, publishing nothing ("Binaries (check)", "Binaries
(same as zig build)" and "Image"), when the change touches the packaging. `scorecard` grades the
repository weekly with [OpenSSF Scorecard](https://scorecard.dev). `codeql` runs
[CodeQL](https://codeql.github.com) with its `security-extended` queries over what it has a
language for (the workflows, the Go comparison tools under `runner/tools`, the Python generator),
one job per language, on every pull request, in the merge queue, on `main` and weekly; it is a
checked-in workflow rather than the repository's default setup, which must stay off for its
uploads to be accepted.
"End to end" (`ci`, `.github/scripts/e2e.sh`) runs the runner built from the pull request for
real, on GitHub's runner: it starts the pinned Dagger engine as `deploy/compose.yaml` does,
registers the runner's just-in-time runners on the private `Open-Blue/runner-bench` under a label
of the run's own, dispatches that repository's `e2e.yml` and `e2e-cancel.yml` at it, and checks the
jobs, steps and logs through GitHub's API: a script installing into the tool cache, a service, a
`docker://` step, a JavaScript action, the file commands, a masked secret, a cancelled run, and a
rerun replayed from the step cache. It does it twice, on Dagger and with `RUNNER_BACKEND=native`,
and leaves each job's queue and run times for both in the `e2e-timings` artifact. Everything on
runner-bench is done as the GitHub App `zig-runner-e2e`, whose key is the `e2e` environment's
secret: a pull request from a fork, which does not get it, skips the job's steps, still reporting.
It is not a required check yet. Before a release, run the same suite by hand against a pool from
`main` (the laptop's, or razorbill's when it serves runner-bench, trusting `refs/heads/main`):
`.github/scripts/e2e.sh check <its label>`, with gh logged in.
`compare` runs the comparison tools weekly
(`.github/scripts/*-diff.sh`): the expression evaluator, YAML reader, `hashFiles()`, problem
matcher regular expressions, HPACK decoder and RS256 signing against the implementations they
follow, on fresh random cases.
`proofs` checks the [Lean proofs](proofs/README.md) (the step cache, the regex matcher's loops, and
the `hashFiles()` walk) and compares the walk's model with `runner/src/glob.zig` on random cases,
when either changes and weekly ("Proofs"). The workflows are written to be hard to turn against the
repository:

- **Least privilege.** Each workflow grants nothing by default; each job asks for only what it
  needs, with a comment saying why. Checkouts keep no credentials for later steps. Only the
  release's own jobs can publish: pull requests' and the merge queue's checks hold read access
  alone ("Image" scans and builds; "Image (publish)", on a tag, pushes and attests).
- **Pinned inputs.** Actions are pinned by commit and images by digest, not by tag, which their
  owner (or whoever takes their repository) can move, BuildKit and its SBOM scanner included, and
  the busybox the runner itself puts into job containers (`runner/src/dagger.zig`), pinned by its
  multi-arch index digest so one pin serves amd64 and arm64; the Workflows job checks on every
  pull request that this pin is a pullable index with the applets the runner uses
  (`.github/scripts/busybox-pin.sh`). [Renovate](https://docs.renovatebot.com)
  proposes updates a week after their release. The exceptions are the Dagger engine in
  `deploy/compose.yaml`, pinned by tag and held there on purpose: the runner speaks one engine
  version's protocol, and a new engine starts with an empty cache; and, still by tag, the
  JavaScript runtimes for actions (`oven/bun` and `node`, `runner/src/dagger/js.zig`), tracked in
  #107. The job base image `ubuntu:24.04` (`RUNNER_IMAGE`) is pinned by its multi-arch index digest
  (`runner/src/dagger.zig`, checked by `.github/scripts/ubuntu-pin.sh`); the packages provisioning
  installs into it come from the Ubuntu archive on the day the engine builds them, and the pre-warm
  logs their fingerprint. tls.zig and GitHub's expression
  test cases are pinned by commit. Zig, changie and checksec are checked against pinned checksums
  before they run, tls.zig against its `.hash` as well; a Renovate pull request for a new Zig, tls.zig or
  changie fails until its checksums are updated (changie's by the Workflows job, which downloads
  it on every pull request, though only the release runs it).
- **Verifiable releases.** Every binary and image has a signed provenance attestation saying which
  workflow built it from which commit. Check a binary as razorbill does, built by `release.yml` from
  its tag on GitHub's own runners:

  ```sh
  gh attestation verify zig-runner-linux-x86_64 --repo Open-Blue/zig-runner \
    --signer-workflow Open-Blue/zig-runner/.github/workflows/release.yml \
    --source-ref refs/tags/<tag> --deny-self-hosted-runners
  ```

  and the image the same way (`oci://ghcr.io/open-blue/zig-runner:<tag>`); an image rebuilt by hand
  was built from `main`, so its `--source-ref` is `refs/heads/main`.
  The binaries' release also carries their SBOM (`zig-runner.spdx.json`: tls.zig and Zig's
  standard library, the only code compiled in besides the runner's own), attested too, and both
  attestations' bundles for checking offline (`--bundle zig-runner.provenance.jsonl`). A release is
  published only once all of it is attached.
- **Hardened binaries.** The runner runs as root on prod and parses what GitHub, the engine and
  jobs send it, so its binaries are made hard to exploit, and the release checks that they are
  before publishing them. Both are static position-independent executables (`-fPIE`;
  `runner/build.zig`'s `pie`, on by default, so `zig build`, the image and the release make the
  same binary): the kernel loads each at a random address, where before they sat at the fixed
  0x1000000. They have full RELRO (what is relocated at startup is read-only before the runner's
  code runs), a non-executable stack, and no segment both writable and executable (W^X). PIE costs
  nothing measurable ([BENCHMARKS.md](BENCHMARKS.md), "Position-independent executable"). Intel CET
  (IBT and shadow stacks) is not available: Zig 0.17 has no `-fcf-protection` for Zig code, so the
  binaries carry no CET note. [checksec](https://github.com/slimm609/checksec) 3.2
  (`.github/scripts/checksec.sh`, pinned by version and checksum) fails the release, and on pull
  requests "Release builds" and "Binaries (check)", on any binary without PIE, full RELRO, NX or
  W^X:

  ```sh
  .github/scripts/checksec.sh zig-runner-linux-x86_64 zig-runner-linux-aarch64
  ```
- **Scanned.** Trivy checks the Dockerfile and the image before a push, with its vulnerability
  database fetched once, with retries, from Google's mirror first; accepted findings are in
  `.trivyignore.yaml`, each with why. GitHub's secret scanning blocks pushes carrying credentials.
- **Checked.** actionlint and zizmor check the workflows, shellcheck every shell script
  (`.github/scripts/shellcheck.sh`), `busybox-pin.sh` the runner's busybox pin, and CodeQL the
  workflows, the Go tools and the Python generators; every job has a time limit. The Database
  tests job runs every test under
  ThreadSanitizer (`zig build test -Dsanitize-thread` locally). Vulnerabilities are reported privately ([docs/SECURITY.md](docs/SECURITY.md)).
- **One secret, one step.** The deploy key that may push to `main` is the `prod` environment's,
  which deploys only from `main` and waits for approval; it is loaded only in the step that pushes,
  and pushes only to GitHub's pinned host key.
- **No pull request code with secrets.** The one workflow on `pull_request_target`, `automerge`,
  runs `main`'s copy and checks out and runs nothing of the pull request; its app key only turns on
  auto-merge. The release starts from `version`, `main`'s workflow on a schedule or by hand, and
  waits for the maintainer's approval. No person reviews a merge: for now each pull request has an
  automated review by the assistant, what reaches `main` is what passed CI, and approving the
  release is the human check (#104).

### Code style

[docs/STYLE.md](docs/STYLE.md): Zig's style guide for names, semantic compression for when to make
an abstraction, Locality of Behaviour for where code lives, and TigerStyle for the rest, in that
order when they disagree.

### Git hooks

`.githooks` runs CI's pull-request checks before code leaves your machine. Turn them on once per
clone:

```sh
git config core.hooksPath .githooks
```

- **pre-commit** refuses a commit on `main`, and checks that what is staged is formatted (`zig fmt`,
  `gofmt`) and that staged workflows pass actionlint.
- **pre-push** runs, on exactly the commits being pushed (in a temporary worktree): the branch
  name's prefix, `zig fmt` over the project, GitHub's expression cases, and the build and tests
  (`.github/scripts/zig-test.sh`; the database tests too when `PG*` or `ZIG_TEST_PG_URL` point at
  one); actionlint and zizmor when workflows changed; `gofmt` and `go vet` for changed Go tools;
  the Lean proofs and the `hashFiles()` model against `glob.zig` when either changed. It takes
  about 20 s.

They need the project's Zig (`minimum_zig_version` in `runner/build.zig.zon`) first on `PATH`, or
`ZIG=/path/to/zig`; Go for actionlint; pipx or uv for zizmor when workflows change; and Lean
(`lake`, from [elan](https://github.com/leanprover/elan)) when the proofs or `glob.zig` change.
`--no-verify` skips them; CI checks the same things regardless.

## Environments

A pull request can change any workflow and name any runner in `runs-on`, so jobs are split by
trust, and the runner itself enforces it:

- **prod**, the runner on the maintainer's machine (`runs-on: [self-hosted, prod]`), runs only jobs
  from pushes to `main`, version tags and `workflow_dispatch` there, whose workflow file comes from
  one of those refs too (`RUNNER_TRUSTED_REFS`, `RUNNER_TRUSTED_EVENTS`; `src/trust.zig`). Any
  other job fails before a step runs, with the reason in its log. The protection fails closed: an
  unset or empty `RUNNER_TRUSTED_REFS` trusts no ref, so every job fails, and a runner whose
  `RUNNER_LABELS` include `prod` refuses to start without it. Trusting every ref takes
  `RUNNER_TRUSTED_REFS=*` (prod starts with it, but logs a warning). `RUNNER_TRUSTED_EVENTS`
  defaults to `push,workflow_dispatch`, and `*` trusts every event. The runner logs what it
  trusts when it starts ("trusting refs refs/heads/main,refs/tags/v* and events
  push,workflow_dispatch"). The `prod` GitHub environment holds the release's deploy key, deploys
  only from `main`, and waits for the maintainer's approval.
- **pre-prod**, where pull requests and the merge queue run, is GitHub's `ubuntu-26.04`, on
  purpose: a hosted runner starts cold every time, so every pull request builds and tests the
  project in the worst case, with no caches to hide a slow or broken first build. Nothing there is
  trusted or holds a secret.

Package caches (Go's modules, Zig's packages, cargo's sources, the tool cache and the rest) are
Dagger cache volumes, keyed by repository and by trust, and several are not checked again when
used. A job shares the repository's `repo` volumes only when the runner vouches for it: it passes
the trust gate on `RUNNER_TRUSTED_REFS` and `RUNNER_TRUSTED_EVENTS` lists that name what they trust
(`trust.vouches`), and it is not a fork's pull request. Every other job, including a
same-repository pull request, a `workflow_run` or `issue_comment` a fork set off, and a fork's pull
request whose repository was deleted, gets the `untrusted` volumes. A `*` in either list lets every
job through without vouching for any, so all of a pre-prod runner's jobs share the `untrusted`
volumes with each other, and none can write what prod reads. With step caching, these volumes are
the runner's own, and what they hold is outside every step's key (their identity, repository and
trust scope included, is in it): a replayed step does not write into them again, so a step that
installs a tool into the tool cache itself (not through a setup action, which runs every time) and
is replayed after the volume was pruned leaves a later step a PATH to a directory that is gone
(proofs/README.md, "Against today's code"; #102).

Zig jobs' global cache is seeded by default. Zig 0.17's `zig build` first compiles a build runner
that is the same for every project: 104 s on one core and about 1 GB. The runner builds it once per
engine, with `zig build --help` on a `build.zig` it writes itself, for each release in
`RUNNER_ZIG_SEED_VERSIONS` (comma-separated; by default the Zig the runner is built with) and each
Zig version the runner's tool-cache check finds in a `repo` job's tool cache (`zig/<version>/`), at
most 3 in all. A version only picks which official, signed release is seeded, never its content.
Before seeding from a release, the runner downloads its tarball and `.minisig` from ziglang.org
and checks the signature, and its trusted comment, against Zig's public key, pinned in
`runner/src/zig_release.zig`, natively (Ed25519 over BLAKE2b-512). Only then does the seed build get
the tarball's sha256, which its exec checks the tarball it downloads against. A release that does
not verify is not seeded, and "Set up job" says so. `RUNNER_ZIG_SEED=<version>=<sha256>` pins one
release by digest instead. The seed never takes anything from a job, so one seed safely goes to
`repo` and `untrusted` jobs in every repository. Copying such a seed into an empty global cache on
the laptop cut a cold `zig build test` of zig-runner from 146 s to 49 s. It also cut the engine's
working-set rise per job from 0.98 to 0.55 GB (runner-bench `zig-seed.yml`, `zig_cache=seeded`).
A seed that cannot be built leaves the job unseeded, and "Set up job" says which happened. Zig's
global cache is never shared between jobs: Zig runs what it finds in `o/` without checking it, so
each job gets the seed (or, without one, an empty cache) as its own copy, and what it adds there is
gone when it ends. Only the package tarballs (`p/`, which Zig hashes again when it unpacks them)
stay in the scope's volume. Zig's local cache volume (`RUNNER_ZIG_LOCAL_CACHE`) is kept only for
jobs the runner vouches for; an untrusted job's is its own.

Steps get the Dagger engine (`RUNNER_DAGGER_NESTING`, privileged nesting, for `dagger call` inside
a step) only when a pool turns it on (`RUNNER_DAGGER_NESTING=true`; off by default, and the runner
logs which at startup), and then only in jobs the runner vouches for, the same jobs that get the
`repo` volumes. A step's
own Dagger client is in the runner's namespace and can open any cache volume by its key, which is
no secret, so in any other job it could write what trusted jobs read (#228). A step there that
names Dagger and fails is told why, and "Set up job" says so (`Dagger in steps: off`). Still, run
**one engine per trust level**: untrusted jobs on one engine share its `untrusted` volumes, the
engine's other state (its layer cache, and through a trusted job's nesting the engine itself) is
not scoped at all, and nesting is control of the host. A second instance on prod's machine
(`zig-runner@sandbox.service`) gets its own engine, or none.

Pushes to `main` run CI on prod, so every merge exercises the runner; the repository variable
`PROD_RUNNER` holds prod's `runs-on` labels as JSON (unset, GitHub's runner stands in):

```sh
gh variable set PROD_RUNNER --body '["self-hosted","prod"]'
```

Pull requests therefore do not exercise the runner itself, which is the price of the cold builds.
Most do not run `zig build` either: on GitHub's runners CI calls the compiler directly
(`.github/scripts/zig-test.sh`), and only a pull request that touches the packaging runs "Binaries
(same as zig build)" in `release.yml`, which builds the x86_64 binary with `zig build` and checks it
is byte for byte the release's. A self-hosted pre-prod remains possible (`PREPROD_RUNNER`, and
`deploy/runner.preprod.env.example` for a runner that trusts every ref and event
(`RUNNER_TRUSTED_REFS=*`, `RUNNER_TRUSTED_EVENTS=*`), with no secrets and no access to its Dagger
engine from steps; the engine is built for `linux/amd64` and `linux/arm64` only), but the project
leaves it unset. The release still builds on GitHub's runners.

Workflows name `prod` (or `pre-prod`, should one exist), never just `zig`, which any of this project's
runners carries. Workflows from
outside contributors' pull requests also wait for approval before they run at all.

## Deploying releases

A release deploys itself to razorbill. Once its binaries and image are built, and CI has passed on
the tagged commit, `release` records a GitHub deployment of the version to the `razorbill`
environment. The tagged commit is the release commit `version` pushes to `main`, which the merge
queue never checked; the push starts `ci` on it, on prod, at the same time as `release`. So the
deploy job waits, up to 40 minutes, until "Format, build and test", "Database tests", "Workflows",
"Binaries", "Image" and "Image (publish)" have each completed on that commit, and fails, naming the check, as soon as
one has not succeeded or once the wait runs out. (The deployment cannot list them as
`required_contexts`: GitHub matches those against commit statuses only, not Actions check runs.)
Once the check passes (re-run it), re-run the release's failed jobs: that is the deploy job alone.
Re-running all of its jobs works too: the binaries job finds the release published, checks that
it is complete and attested, and leaves it alone. To rebuild one tag's image, run `release` by hand
from `main` with the tag (v0.14.0 or later): it waits for approval in `prod`, and moves `latest`
only for the newest version tag.

When CI cannot pass for a reason that is not the release's (a prod runner that is down, perhaps
because the release before broke it), a maintainer deploys by hand, with a token that can write
deployments and no checks required; the agent on razorbill still checks the binary's checksum and
provenance:

```sh
jq -n --arg ref v1.2.3 '{ref: $ref, environment: "razorbill", auto_merge: false,
  required_contexts: [], description: ("zig-runner " + $ref + ", by hand")}' |
  gh api -X POST repos/Open-Blue/zig-runner/deployments --input -
```

On razorbill,
`zig-runner-deploy.timer` asks every minute; for a new deployment `deploy/zig-runner-deploy`:

1. refuses a version older than the one installed, unless `ALLOW_DOWNGRADE` in
   `/etc/zig-runner-deploy.env` names it (a rollback on purpose);
2. downloads the release's binary, checks it against `SHA256SUMS`, and checks its provenance:
   built by `release.yml`, from that tag, on GitHub's own runners (`gh attestation verify`, offline,
   on the attestations and Sigstore trust root it fetched). A fetch that fails for a reason of the
   moment (no network, a rate limit, a timeout, Sigstore's CDN) reports nothing, and the timer
   tries again a minute later, up to `ATTEMPTS` (30) times before it reports failure; a check that
   fails reports failure at once;
3. installs it and restarts every runner instance (`zig-runner.service` and `zig-runner@*.service`,
   or `UNITS`), each finishing its running jobs first;
4. reports success once each instance is listening for jobs again, or puts the previous binary
   back and reports failure.

The outcome shows under the repository's Environments, on the deployment. The `razorbill`
environment takes deployments of `v*` tags only (its deployment tag policy). Nothing reaches into the
machine: it asks GitHub, with a token that can only read and report deployments. To set it up, on
the machine, with `gh` 2.68 or later from [cli.github.com](https://cli.github.com) (Debian's
package cannot verify provenance) and a fine-grained token for this repository with Deployments
read and write, Attestations and Contents read:

```sh
sudo install -m 0755 deploy/zig-runner-deploy /usr/local/bin/
sudo install -m 0600 deploy/zig-runner-deploy.env.example /etc/zig-runner-deploy.env   # GH_TOKEN
sudo cp deploy/zig-runner-deploy.service deploy/zig-runner-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now zig-runner-deploy.timer
```

### Rebooting the machine

The engine keeps its cache across a restart only if it is allowed to mark it clean first (see
[BENCHMARKS.md](BENCHMARKS.md)), and Docker gives a container 10 s at shutdown. So stop the runner
instances (each finishes its running jobs), then the engine with time to spare, then reboot:

```sh
sudo systemctl stop zig-runner.service 'zig-runner@*.service'
docker stop -t 300 <engine container>
sudo reboot
```

The engine's restart policy is `unless-stopped`, and Docker counts a `docker stop` as stopped on
purpose: after the reboot the engine stays down while the runners come back, and every job fails
with no engine socket. Start it again (`docker start <engine container>`), then check that
`/run/dagger/engine.sock` exists and the engine's log has no `unclean` or `wiping` line.

### Memory

Four heavy jobs taken at once on razorbill filled the engine's 4 GB, then the Pi's 2 GB of swap, and
the machine thrashed for hours (#126). Two things keep that from happening again:

- **The runner's memory gate**, on by default. A runner asks GitHub for a job only while the
  machine has the memory for it, reserving room for the jobs its pool's other runners may be
  handed at the same moment, and stops while memory pressure or swap growth says the machine is
  struggling. A held runner removes its registration, so GitHub gives the job to another runner;
  running jobs are never touched. Where it can find the engine container's cgroup (a runner on
  the host, reaching the engine over a unix socket), it holds on the engine's own memory cap and
  swap too, since the engine can fill its cap while the machine still has memory (#142), and
  learns from it what each job (by repository, workflow and name) takes, so that a light job
  reserves less than a heavy one once it has run (#144). The limits and why they are what they
  are are in `deploy/runner.env.example` (`RUNNER_MIN_MEM_AVAILABLE_MB` and the rest;
  `RUNNER_ADMISSION=false` turns it off). The gate sees only its own process's runners: run one
  pool per machine.
- **No swap for the engine**, optional. With `--memory 4g` alone, Docker lets a container swap as
  much again; `--memory-swap` equal to `--memory` (`memswap_limit` in compose) gives it none. A
  job that outgrows the engine then fails inside it, killed by the kernel, instead of the whole
  machine slowing to a crawl. The trade-off is a failed job in place of a slow one, and the risk
  that the process killed is the engine itself, whose unclean restart wipes its cache: check which
  process the kernel picks before relying on it. razorbill does not use it today.

An engine that stops answering altogether (frozen, deadlocked) would hold a step for good, so a
step's query with nothing at all heard from the engine for `RUNNER_ENGINE_SILENCE_TIMEOUT` seconds
(600 by default) is aborted and the step failed, saying why (#100). Nothing heard means no health
check (the engine sends one every 5 s), no byte of an answer and no log line; a swapping engine
answers late but not that late, and keeps logging. It applies only while a step runs, and the
runner logs the timeout when it starts. Raise it for an engine that is often that slow; `0` turns
it off.

## Benchmarks

[BENCHMARKS.md](BENCHMARKS.md) has what was measured on the reference machine, a Raspberry Pi 5:
where a job's time goes (the engine, not the runner), what an engine restart does to its cache, what
installing Zig costs, and the earlier study's results with their verdicts.

## Changelog

[CHANGELOG.md](CHANGELOG.md) is kept with [changie](https://changie.dev): each change is a file
under `.changes/unreleased/`, written with `changie new` in the pull request that makes it. The
release batches them into the version's notes (`changie batch <version> && changie merge`), which
are also its GitHub release's notes.

## Origin

The runner was developed in
[Lementknight/zig-actions-runner](https://github.com/Lementknight/zig-actions-runner), together
with a read API and a frontend by [@philgutowski](https://github.com/philgutowski), the Tiger Data
schema by [@rafayet-git](https://github.com/rafayet-git), and the design documents, specification,
deployment guide, measurements and Agda proofs. Releases v0.1.0 and v0.2.0 were made there. This
repository carries the runner's history from that work and continues it with only what the runner
needs to build, run and deploy; the rest stays in the original repository.

Licence: see [LICENSE](LICENSE); the vendored third-party code is listed in
[THIRD_PARTY.md](THIRD_PARTY.md).
