# CI pipeline

What each workflow checks, and how the workflows are hardened. For making a change, see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Where jobs run

Pull requests and the merge queue run on GitHub's hosted `ubuntu-26.04` runners, which hold no
secrets and are trusted with nothing. Pushes to `main` run `ci` on the project's own runner, prod
(the repository variable `PROD_RUNNER` holds its `runs-on` labels as JSON; unset, a hosted runner
stands in), so every merge exercises the runner itself. Prod is arm64 with 16 KiB pages and
overlayfs, which hosted runners don't cover: check `main`'s CI after a merge.

```sh
gh variable set PROD_RUNNER --body '["self-hosted","prod"]'
```

CI may cache, split and parallelise for speed. The cost of a cold build is measured on the bench
([docs/BENCHMARKS.md](BENCHMARKS.md)), not kept in CI. See
[docs/OPERATIONS.md](OPERATIONS.md), "Environments", for the trust split.

## Required checks

The ruleset for `main` requires these, and each reports on every pull request and in the merge
queue: "Branch name", "Workflows", "Tests (x86_64)", "Tests (arm64)", "Native tests as root (…)" in
two parts per architecture, "Database tests", "Release builds", "Release builds (arm64)", "End to
end", "Proofs", and `release`'s "Binaries (check)", "Binaries (same as zig build)" and "Image".

On a change that can't affect what a job checks, the job reports without running its steps
(`.github/scripts/ci-scope.sh tests|binaries|proofs|packaging`, each with the files that can). The
build and tests run for any file the script doesn't know. A path filter would leave the check
unreported instead, and the merge queue waiting for it.

## Workflows

| Workflow | When | What |
| --- | --- | --- |
| `ci` | pull requests, merge queue, `main` | branch name, workflows, format, build, tests, release builds, end to end |
| `proofs` | pull requests, merge queue, `main`, weekly | the Lean proofs, and the `hashFiles()` model against `glob.zig` |
| `store model` | changes to the store or release pipeline, weekly | the TLA+ models, with SPIN on their Promela ports |
| `release` | tags; pull requests touching the packaging | binaries, image, provenance, deploy |
| `provisioned image` | pull requests (build only), `main`, by hand | the default job image with the runner's packages installed, both architectures |
| `version` | daily, or by hand | cuts the release, after approval |
| `security` | pull requests, weekly | gitleaks and dependency review |
| `codeql` | pull requests, `main`, weekly (not the merge queue) | CodeQL `security-extended` |
| `analysis` | nightly; a lighter run on pull requests | fuzzing, Valgrind, ThreadSanitizer, stress, coverage |
| `compare` | weekly | the comparison tools against the implementations they follow |
| `mutation` | by hand | mutation testing of one module |
| `scorecard` | weekly | [OpenSSF Scorecard](https://scorecard.dev) |
| `automerge` | pull requests | turns on auto-merge |
| `close-linked-issues` | merged pull requests | closes `Closes #N` issues the merge app left open |

### ci

- **Branch name**: the prefix that decides the version ([CONTRIBUTING.md](../CONTRIBUTING.md),
  "Versioning").
- **Workflows**: actionlint and [zizmor](https://docs.zizmor.sh), shellcheck and shfmt, hadolint,
  the busybox pin, the check names the release waits for (`check-names.sh`), and the unsafe
  constructs ratchet.
- **Tests (x86_64)** and **Tests (arm64)**: format, build and tests, natively on each architecture
  as on prod; on x86_64 also the tests on overlayfs, in Docker ("Test, on overlayfs"), and GitHub's
  own expression test cases. On hosted runners CI calls the compiler directly
  (`.github/scripts/zig-test.sh`) rather than `zig build`, which first spends about 100 s compiling
  Zig's build system.
- **Native tests as root**: the native backend's root-only tests, in two parts per architecture.
- **Database tests**: against TimescaleDB, every test under ThreadSanitizer.
- **Release builds** and **Release builds (arm64)**: the release's own builds for both targets in
  ReleaseSafe, so code that doesn't compile for aarch64 fails here rather than after the tag; on
  arm64 the aarch64 binary is run.
- **Lint (ZLint)**: [ZLint](https://github.com/DonIsaac/zlint), pinned and checked against its
  release's checksum, with the rules that find bugs (`runner/zlint.json`; the script says why each
  other rule is off), and its suppressed-errors rule against a baseline of `catch {}` sites that
  were read and meant. CodeQL and Semgrep read no Zig, so this is the runner's static analysis.
- **Go tools**: `go vet`, staticcheck and the race detector, on a change to `runner/tools`.

The GitHub client's tests run over real connections to a local server
(`src/github/testserver.zig`), so how it handles redirects and tokens is tested, not described.

### End to end

"End to end" (`.github/scripts/e2e.sh`) runs the runner built from the pull request for real, on a
hosted runner. It starts the pinned Dagger engine as `deploy/compose.yaml` does, registers
just-in-time runners on the private `Open-Blue/runner-bench` under a label of the run's own,
dispatches that repository's `e2e.yml` and `e2e-cancel.yml`, and checks the jobs, steps and logs
through GitHub's API: a script installing into the tool cache, a service, a `docker://` step, a
JavaScript action, the file commands, a masked secret, a cancelled run, and a rerun replayed from
the step cache. On a pull request and in the merge queue it runs with `RUNNER_BACKEND=native` only
(the engine is still started, since native hands some jobs to Dagger); the Dagger pass, which is
reported rather than a gate, is not run there. The nightly `analysis` run's "ThreadSanitizer, end to
end" runs the same suite on both backends. Each pass leaves its queue and run times in the
`e2e-timings` artifact.

Everything on runner-bench is done as the GitHub App `zig-runner-e2e`, whose key is the `e2e`
environment's secret. A pull request from a fork doesn't get it, so the job skips its steps and
still reports. Before a release, run the same suite by hand
against a pool from `main`: `.github/scripts/e2e.sh check <its label>`, with gh logged in.

### release and version

Once a day, `version` releases what merged since the last release, if anything did. It waits for
approval in the `prod` environment, commits and tags the release, and the tag runs `release`: the
binaries (compiled directly, `.github/scripts/build-binaries.sh`), and the image from those same
binaries after a [Trivy](https://trivy.dev) scan, each with signed build provenance. On pull
requests and in the merge queue, `release` builds and scans the same and publishes nothing
("Binaries (check)", "Binaries (same as zig build)" and "Image"), when the change touches the
packaging. "Binaries (same as zig build)" checks that `zig build` makes the release's x86_64 binary
byte for byte. The release then deploys itself: see [docs/OPERATIONS.md](OPERATIONS.md),
"Deploying releases".

### security

Neither check is required yet.

- **Secrets** runs [gitleaks](https://github.com/gitleaks/gitleaks)
  (`.github/scripts/install-gitleaks.sh`, pinned by version and checksum) over the pull request's
  own commits, and weekly over `main`'s whole history, failing on any finding. The log names the
  rule, file, line and commit, never the value. A finding that isn't a secret (a test fixture, an
  example key, a hash) is allowed in `.gitleaks.toml`, as narrowly as it can be, with a comment
  saying why. `gitleaks:allow` comments in the code are ignored, so every exception is in that file.
- **Dependency review** runs
  [`actions/dependency-review-action`](https://github.com/actions/dependency-review-action) on the
  dependencies a pull request adds or changes. It fails on a known vulnerability of moderate
  severity or worse, or on a license outside the permissive ones an MIT project can take in (the
  list and its one exception are in `security.yml`). It reads GitHub's dependency graph, which sees
  the Go tools' modules under `runner/tools/` and the actions the workflows use. It doesn't see
  `runner/build.zig.zon` (tls.zig, the one dependency compiled into the runner, is followed by
  Renovate and listed in [docs/THIRD_PARTY.md](THIRD_PARTY.md)), the images the Dockerfile, Compose
  file and scripts pin (Trivy scans the release's image), or the .NET reference program, which has
  no packages.

### codeql

[CodeQL](https://codeql.github.com) with its `security-extended` queries, over what it has a
language for: the workflows, the Go comparison tools under `runner/tools`, and the Python
generator, one job per language. It is a checked-in workflow rather than the repository's default
setup, which must stay off for its uploads to be accepted. The `actions` analysis runs for every
change; `go` and `python` run only when a change touches Go sources or modules under `runner/tools`,
a `.py` file, or the workflow itself (`ci-scope.sh codeql-go`, `codeql-python`), and otherwise
report green after the checkout, skipping their steps. The weekly run analyzes all three.

### analysis

Nightly, at full length, for the runner's own code. A draft pull request gets none: it runs once the
pull request is marked ready, and on each push after. A pull request gets a lighter run, because the
whole suite costs about 6 runner-hours (34 jobs): a pull request that adds or edits a test runs just
those tests under Valgrind (`.github/scripts/changed-tests.sh`), and one that changes the workflow,
its scripts or the zstd decoder (`ci-scope.sh analysis`) also runs Fuzz at 50K runs a target, one
Stress job of 5 rounds; one that changes the runner's code (`ci-scope.sh tsan`) runs both
ThreadSanitizer jobs, native and end to end; one that changes the native store (`ci-scope.sh
store`) runs Store stress for 90 seconds a pass, and Store crash. None of these is a required check.
What a pull request leaves to the night: every test under Valgrind, the full fuzz budgets, 100
stress rounds, ten-minute store stress passes, and Coverage (a change to Coverage's own tooling
runs its four parts, uploading and merging nothing).

- **Fuzz** runs each of `runner/src/fuzz.zig`'s targets with Zig's coverage-guided fuzzer
  (`.github/scripts/zig-fuzz.sh`, LLVM-built, for a bounded number of runs): an image layer's tar,
  PAX and paths applied beside a directory it must not reach; image references, registry challenges
  and manifests; expressions, YAML, regular expressions, HPACK, `hashFiles()` patterns, minisign
  signatures, workflow commands and problem matchers; and the runner's zstd decoder against std's,
  input for input. Each target's corpus is kept in the Actions cache. A crash, failed check, leak
  or hang fails the job, named after the target, with the input as an artifact. `zig build test`
  runs the same targets over their seed corpus every time. Locally: `zig build test -Dllvm --fuzz`,
  with `-Dtest-filter='fuzz: YAML'` for one target.
- **Valgrind** runs every test under memcheck (`.github/scripts/zig-valgrind.sh`), for reads of
  memory never written and accesses outside an allocation, which Debug's safety checks miss.
  Known-benign reports are suppressed in `.github/valgrind.supp`, each with why. A run that stops
  making progress is stopped, naming the test it was in.
- **ThreadSanitizer, native** runs the native backend's tests under ThreadSanitizer on x86_64 and
  arm64, rootless and as root, with the runner binary they start for each step built with it too
  (`ZIG_TEST_SANITIZE_THREAD=1`). **ThreadSanitizer, end to end** runs the end-to-end suite on both
  backends with a runner built under it (`e2e.sh build BIN tsan`), failing on any report in the
  runner's log or the jobs'. TSan's runtime needs glibc's dynamic loader, so these builds are
  dynamically linked PIEs, not the release's static PIE.
- **Stress** runs the concurrency-sensitive tests (cancels, deadlines, the memory gate, the native
  store's locks, the database, the broker's long-poll, log uploads;
  `.github/scripts/zig-race-tests.sh` names them) 100 times under stress-ng's CPU and memory load,
  and fails on the first round that fails, with its output as an artifact
  (`.github/scripts/zig-stress.sh`). It runs as four jobs of 25 rounds, "Stress (1/4)" to "(4/4)".
- **Coverage** (`.github/scripts/zig-coverage.sh`) measures which lines the tests reach with
  [kcov](https://github.com/SimonKagstrom/kcov): the rootless tests, the native tests as root, and
  the runner binary those tests start, merged into one report from four parts. The `coverage`
  artifact holds the HTML report, Cobertura XML and JSON (`summary.json` has the total, and each
  directory's and file's coverage); the job summary lists the security-relevant files,
  least-covered first. Nothing is sent to a coverage service. It runs at night, reporting without
  failing (a pull request would upload about 1 GB of raw reports a part); `COVERAGE_MIN=<percent>`
  on its step makes it fail below a total. Locally, with kcov installed: `.github/scripts/zig-coverage.sh
  /tmp/coverage`, then open `/tmp/coverage/html/index.html`.

### compare

Weekly, the comparison tools (`.github/scripts/*-diff.sh`) check the expression evaluator, YAML
reader, `hashFiles()`, problem matcher regular expressions, HPACK decoder and RS256 signing against
the implementations they follow, on fresh random cases. It also lints the tools' own Go
(`.github/scripts/go-lint.sh`: `go vet`, a pinned staticcheck, the race detector, and govulncheck
for information).

### Mutation testing

`mutation` asks whether the tests would notice the code being wrong. `runner/tools/mutate.py`
changes a module's code one thing at a time (a comparison flipped, `and` for `or`, `true` for
`false`, a `return error.X` guard removed, an integer constant off by one, a statement deleted),
compiles each change with only that module's tests, runs them with a timeout, and counts each
mutant killed, survived, timed out or not compiled. Its report lists every survivor by file, line
and change: most are a missing test, a few a change that means the same thing.

The modules are the security-critical ones: secret masking (`masking`: `redact.zig`,
`dagger/JobLog.zig`), workflow commands (`commands`), expressions (`expr`), the native store's keys
and publishing (`store`), and `minisign`. Together they make about 2,400 mutants, each a compile:
hours of every core, too slow for a pull request. Run it by hand (Actions, "Run workflow"), for one
module, over four hosted runners; the report is in the last job's summary and the
`mutation-report` artifact.

Locally, after `zig build --fetch` in `runner/`: `python3 runner/tools/mutate.py masking`.
`--all --out DIR` runs every module, `--sample N` gives a quicker look, `--list` lists the mutants,
`--shard K/N` and `--merge` split a run and join its results, and `--expr-cases DIR` holds `expr`'s
mutants to GitHub's own expression cases too. Mull and other LLVM-level tools can't be used: they
instrument through a clang pass plugin, which Zig can't load.

### proofs and store model

`proofs` checks the [Lean proofs](../proofs/README.md) (the step cache, the regex matcher's loops,
and the `hashFiles()` walk) and compares the walk's model with `runner/src/glob.zig` on random
cases. `store model` checks the TLA+ models of the native store's locking and eviction and of the
release pipeline with SPIN, on their Promela ports, which reached the same states as TLC in every
configuration before TLC was removed; SPIN's counts are now the reference, and the TLA+ modules
the documentation ([proofs/README.md](../proofs/README.md)). Each model's mutants must fail.

## Hardening

The workflows are written to be hard to turn against the repository.

- **Least privilege.** Each workflow grants nothing by default, and each job asks for only what it
  needs, with a comment saying why. Checkouts keep no credentials for later steps. Only the
  release's own jobs can publish: pull requests' and the merge queue's checks have read access
  alone ("Image" scans and builds; "Image (publish)", on a tag, pushes and attests).
- **Pinned inputs.** Actions are pinned by commit and images by digest, not by tag, which their
  owner can move. That covers BuildKit and its SBOM scanner, the busybox the runner puts into job
  containers (`runner/src/dagger.zig`, a multi-arch index digest checked by
  `.github/scripts/busybox-pin.sh`), the JavaScript runtimes for actions (`oven/bun` and `node`,
  `runner/src/dagger/js.zig`), and the job base image `ubuntu:24.04` (`RUNNER_IMAGE`, checked by
  `.github/scripts/ubuntu-pin.sh`). The packages provisioning installs come from the Ubuntu archive
  on the day they are installed, and the pre-warm logs their fingerprint. Where one is pinned
  (`runner/src/dagger/provisioned_pin.zig`, checked by `.github/scripts/provisioned-pin.sh`), the
  runner pulls the default image already provisioned, built by `provisioned image` from the
  runner's own script, signed and by digest, instead of installing the packages (22-45 s, and
  Ubuntu's mirrors) on every new machine and empty store. A pull that fails provisions as before,
  and `RUNNER_PROVISIONED_IMAGE=false` never pulls it. zizmor is installed
  from PyPI by hash. tls.zig and GitHub's expression test cases are pinned by commit. Zig, changie,
  checksec and gitleaks are checked against pinned checksums before they run, tls.zig against its
  `.hash` too; a Renovate pull request for a new one fails until its checksums are updated.
  [Renovate](https://docs.renovatebot.com) proposes updates a week after their release. The one
  exception is the Dagger engine in `deploy/compose.yaml`, pinned by tag and held on purpose: the
  runner speaks one engine version's protocol, and a new engine starts with an empty cache.
- **Verifiable releases.** Every binary and image has a signed provenance attestation saying which
  workflow built it from which commit. Check a binary as razorbill does, built by `release.yml`
  from its tag on GitHub's own runners:

  ```sh
  gh attestation verify zig-runner-linux-x86_64 --repo Open-Blue/zig-runner \
    --signer-workflow Open-Blue/zig-runner/.github/workflows/release.yml \
    --source-ref refs/tags/<tag> --deny-self-hosted-runners
  ```

  Check the image the same way (`oci://ghcr.io/open-blue/zig-runner:<tag>`); an image rebuilt by
  hand was built from `main`, so its `--source-ref` is `refs/heads/main`. The release also carries
  its SBOM (`zig-runner.spdx.json`: tls.zig and Zig's standard library, the only code compiled in
  besides the runner's own), attested too, and both attestations' bundles for checking offline
  (`--bundle zig-runner.provenance.intoto.jsonl`; `zig-runner.provenance.jsonl` up to v0.28.1). A
  release is published only once all of it is attached.
- **Hardened binaries.** The runner runs as root on prod and parses what GitHub, the engine and
  jobs send it, so its binaries are hard to exploit, and the release checks that they are before
  publishing them. Both are static position-independent executables (`runner/build.zig`'s `pie`,
  on by default, so `zig build`, the image and the release make the same binary), loaded at a
  random address. They have full RELRO, a non-executable stack, and no segment both writable and
  executable (W^X). PIE costs 0-3% on the hot paths ([docs/BENCHMARKS.md](BENCHMARKS.md),
  "Position-independent executable"). Intel CET is not available: Zig 0.17 has no
  `-fcf-protection` for Zig code. [checksec](https://github.com/slimm609/checksec) 3.2
  (`.github/scripts/checksec.sh`, pinned by version and checksum) fails the release, and on pull
  requests "Release builds", "Release builds (arm64)" and "Binaries (check)", on any binary without
  PIE, full RELRO, NX or W^X:

  ```sh
  .github/scripts/checksec.sh zig-runner-linux-x86_64 zig-runner-linux-aarch64
  ```

- **Scanned.** Trivy checks the Dockerfile and the image before a push, with its vulnerability
  database fetched once, with retries, from Google's mirror first; accepted findings are in
  `.trivyignore.yaml`, each with why. GitHub's push protection blocks pushes carrying credentials,
  and gitleaks and dependency review run as above.
- **Checked.** Every job has a time limit. The workflows, shell scripts, Dockerfile, Go tools and
  Python generators are linted (above), and the runner's Zig is fuzzed, run under Valgrind and
  ThreadSanitizer, stressed and measured for coverage. Vulnerabilities are reported privately
  ([docs/SECURITY.md](SECURITY.md)).
- **One secret, one step.** The deploy key that may push to `main` is the `prod` environment's,
  which deploys only from `main` and waits for approval. It is loaded only in the step that pushes,
  and pushes only to GitHub's pinned host key.
- **No pull request code with secrets.** The workflows on `pull_request_target` (`automerge`,
  `close-linked-issues`) run `main`'s copy and check out and run nothing of the pull request;
  `automerge`'s app key only turns on auto-merge. The release starts from `version`, `main`'s
  workflow, and waits for the maintainer's approval. No person reviews a merge yet: each pull
  request has an automated review, what reaches `main` is what passed CI, and approving the release
  is the human check (#104).
