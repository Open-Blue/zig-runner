# Contributing

Thanks for helping. This page covers setting up, making a change, and how a change reaches a
release. The CI pipeline itself is in [docs/CI.md](docs/CI.md).

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

Report a vulnerability privately, as [docs/SECURITY.md](docs/SECURITY.md) says, not in an issue.
Report a bug in an issue with the runner's version (`zig-runner --version`), its backend
(`RUNNER_BACKEND`, and `RUNNER_ENGINE` if set), what the job did and what you expected, the
runner's log around it with secrets removed, and the machine (OS, kernel, architecture). The bug
form asks for each.

## Set-up

You need:

- The project's Zig (`minimum_zig_version` in `runner/build.zig.zon`) first on `PATH`, or
  `ZIG=/path/to/zig`.
- Docker, for the Dagger backend and the overlayfs test run.
- Optional, for the hooks when the matching files change: Go (actionlint and the Go tools), python3
  with venv (zizmor), Lean's `lake` from [elan](https://github.com/leanprover/elan) (the proofs),
  and `spin` (the store's and the release pipeline's models).

Build and test:

```sh
cd runner
zig build test
```

`.github/scripts/zig-test.sh` runs the same tests the way CI does, by calling the compiler
directly. `ZIG_TEST_FILTER="native eviction"` runs a subset, and `ZIG_TEST_PART=K/N` one part of N.

Tests that need something extra skip without it and say why:

- **Native backend tests** need user namespaces. Some need root (`ZIG_TEST_NATIVE_AS_ROOT=1`); run
  those in a privileged container with a memory cap (`docker run --privileged --memory=6g
  --memory-swap=6g`), one at a time, as CI's "Native tests as root" job does.
- **Database tests** run when `PG*` or `ZIG_TEST_PG_URL` point at a Postgres.

## Git hooks

`.githooks` runs CI's pull-request checks before code leaves your machine. Turn them on once per
clone:

```sh
git config core.hooksPath .githooks
```

- **pre-commit** refuses a commit on `main`, and checks that what is staged holds no secret
  (gitleaks, with CI's `.gitleaks.toml`; skipped with a note when gitleaks is not installed), is
  formatted (`zig fmt`, `gofmt`), and that staged workflows pass actionlint.
- **pre-push** checks exactly the commits being pushed, in a temporary worktree. Always: the branch
  name's prefix, `zig fmt`, GitHub's expression cases, the build and tests, and the unsafe
  constructs ratchet. When runner code changed: the tests again on overlayfs (in Docker) and ZLint.
  When the matching files changed: actionlint, zizmor and the check names the release waits for;
  shellcheck and shfmt; hadolint; `gofmt` and `go vet`; the Lean proofs and the `hashFiles()` model;
  SPIN. A small change takes under a minute.

CI checks the same things whatever the hooks did. Don't push with `--no-verify`.

## Making a change

1. **Branch from `main`** with a prefix. The prefix decides the release's version bump (below), and
   CI refuses a branch without one.
2. **Add a changelog entry** with `changie new` (below).
3. **Open a pull request.** A draft until it's ready. Its checks run on GitHub's hosted runners;
   once they pass, it joins the merge queue, which runs them again on top of `main`.
4. **After the merge,** `main`'s own CI runs on the project's runner (prod), which the hosted
   runners can't stand in for: arm64, 16 KiB pages and overlayfs. Check it is green.

Every pull request bumps the version, refactors included: the version count is a count of work done.

## Versioning

Releases follow [semantic versioning](https://semver.org/) and are cut by CI, never by hand. Once a
day (or when `version` is run by hand), everything merged into `main` since the last release becomes
one new version, its binaries and its image, after the maintainer approves it. The bump comes from
the merged branches' prefixes, and the largest one wins:

| Branch | Bump |
| --- | --- |
| `bugfix/*`, `hotfix/*`, `ci/*`, Renovate's `renovate/*` | patch: `v1.2.3` → `v1.2.4` |
| `feature/*`, `feat/*`, `release/*`, `docs/*`, `perf/*`, `refactor/*` | minor: `v1.2.3` → `v1.3.0` |
| any of them, labelled `breaking` | major: `v1.2.3` → `v2.0.0` |

`feature/*` is for larger features and `feat/*` for small ones. Neither breaks anything unless the
pull request has the `breaking` label. Changie's kinds (Added, Changed, Fixed…) only choose the
changelog section; they never change the bump.

In a stack, each pull request merged into `main` counts toward the next release. One merged into
another's branch counts toward that one's bump when it reaches `main`.

The release commits the version to `runner/build.zig.zon` and the changelog to `main`, and tags
that commit. It does so only once `main`'s own checks have passed on the commit it releases (the
names in `.github/checks-on-main`), waiting up to 30 minutes. A check that never runs there fails
the wait as soon as the commit's runs have finished. When the checks can't pass because of what the
release fixes (prod's runner broken by the release before), run `version` by hand with
`skip_main_checks`; it still waits for approval.

The version comes from the branch, not from commit messages, so
[Conventional Commits](https://www.conventionalcommits.org) tools such as
[semantic-release](https://github.com/semantic-release/semantic-release) and
[release-please](https://github.com/googleapis/release-please) are not used: they would decide the
version, write the changelog and tag the release alongside this, and disagree with it.

## Changelog

[docs/CHANGELOG.md](docs/CHANGELOG.md) is kept with [changie](https://changie.dev). Each change is a
file under `.changes/unreleased/`, made in the pull request that makes the change:

```sh
changie new --interactive=false --kind Fixed --body "What changed, for someone running the runner"
```

Use the command rather than writing the YAML by hand, so the file names don't collide across pull
requests. The release batches the entries into the version's notes (`changie batch <version> &&
changie merge`), which are also its GitHub release's notes.

## Code style

[docs/STYLE.md](docs/STYLE.md): Zig's style guide for names, semantic compression for when to make
an abstraction, Locality of Behaviour for where code lives, and TigerStyle for the rest, in that
order when they disagree.

Two project rules:

- **Native ports, not dependencies.** GitHub runner features are reimplemented in Zig here. Node,
  .NET and other tools appear only as test oracles, which the `compare` workflow checks the Zig code
  against.
- **Fixes live in the runner.** Performance and portability come from the runner's own code, never
  from tuning the host it runs on.

## Review and merging

For now, each pull request gets an automated review, and what reaches `main` is what passed CI.
Approving the release is the human check (#104). `automerge` turns on auto-merge for every pull
request from a branch of this repository based on `main`, so it joins the merge queue once its
checks pass. Workflows from outside contributors' pull requests wait for approval before they run.
