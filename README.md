# zig-runner

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Open-Blue/zig-runner/badge)](https://scorecard.dev/viewer/?uri=github.com/Open-Blue/zig-runner)

A self-hosted GitHub Actions runner written in Zig. One small process runs many runners, and each
job's steps run in one of two backends:

- **Dagger** (the default): each step runs in a [Dagger](https://dagger.io) engine, which caches
  steps across runs.
- **Native** (`RUNNER_BACKEND=native`): the runner runs steps itself, with Linux namespaces,
  overlayfs, cgroup v2 and seccomp. The image pull, layer store and sandbox are Zig in this
  repository, with no runc or containerd. See [docs/native-backend.md](docs/native-backend.md).

It is built for trusted jobs on machines you own. It splits jobs by trust, keeps untrusted jobs
away from trusted caches, and takes a job only when the machine has the memory for it.

## Quick start

You need Zig 0.17 and, on a bare machine, `git curl xz-utils sudo nftables iproute2 util-linux procps`
(the native backend needs the last four). To get Zig, run `.github/scripts/install-zig.sh`, which
installs the pinned version after checking ziglang.org's published checksum (it appends the
directory to the file `GITHUB_PATH` names), or download it from
[ziglang.org](https://ziglang.org/download/) and check the checksum yourself. The Dagger backend also
needs Docker; the native backend with `RUNNER_ENGINE=none` needs none. A cold build takes about five
minutes. [.github/scripts/fresh-install.sh](.github/scripts/fresh-install.sh) does all of this on a
throwaway machine ([docs/OPERATIONS.md](docs/OPERATIONS.md), "A fresh install").

```sh
cd runner
zig build -Doptimize=ReleaseSafe
cp ../deploy/runner.env.example /etc/zig-runner.env   # then set GH_TOKEN (or a GitHub App) and GH_SCOPE
zig-out/bin/runner
```

To run it as a service, install `deploy/zig-runner.service` under systemd, or run
`docker compose -f deploy/compose.yaml up`. Release binaries and images are on the
[releases page](https://github.com/Open-Blue/zig-runner/releases), each with signed build
provenance ([docs/CI.md](docs/CI.md), "Hardening", shows how to check one).

## Configuration

Every setting is in [deploy/runner.env.example](deploy/runner.env.example), with what it does and
why its default is what it is. The ones most setups touch:

- **Authentication.** Either `GH_TOKEN`, or a GitHub App, which reaches only the repositories it is
  installed on: `GH_APP_ID` (the App's ID or Client ID) and `GH_APP_PRIVATE_KEY_FILE` (or
  `GH_APP_PRIVATE_KEY`). The App needs "Administration: read and write" on a repository, or
  "Self-hosted runners: read and write" on an organization. The runner mints installation tokens
  and refreshes them before they expire.
- **Trust.** `RUNNER_TRUSTED_REFS` and `RUNNER_TRUSTED_EVENTS` say which jobs a runner runs, and
  which of them share the repository's trusted caches. An unset `RUNNER_TRUSTED_REFS` trusts
  nothing. See [docs/OPERATIONS.md](docs/OPERATIONS.md), "Environments".
- **Memory.** The memory gate is on by default: a runner asks GitHub for a job only while the
  machine has room for it. See [docs/OPERATIONS.md](docs/OPERATIONS.md), "Memory".

### Rootless native runners on Ubuntu

On Ubuntu 23.10 and later, AppArmor lets only programs with a `userns` rule make user namespaces
(`kernel.apparmor_restrict_unprivileged_userns=1`), and a rootless native runner needs one. Rather
than lift the sysctl for the whole machine, install the profile in `deploy/apparmor/`, which grants
it to `/usr/local/bin/zig-runner` alone and confines nothing else:

```sh
sudo install -m 0644 deploy/apparmor/usr.local.bin.zig-runner /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.zig-runner
```

The profile attaches by path, so edit it if the runner is installed elsewhere. Root runners and the
Dagger backend don't need it. The runner never installs it, but when the restriction stops its
sandbox, the error names it.

## Documentation

| Document | For |
| --- | --- |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Running it: trust and environments, caches, deploying releases, rebooting, memory |
| [docs/native-backend.md](docs/native-backend.md) | The native backend's design, its phases and what each one taught |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Measurements on the reference machine, a Raspberry Pi 5 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Changing it: set-up, hooks, branches and versions, tests, the changelog |
| [docs/CI.md](docs/CI.md) | The CI pipeline, workflow by workflow, and how it is hardened |
| [docs/STYLE.md](docs/STYLE.md) | Code style |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | How we treat each other, and how to report a problem |
| [proofs/README.md](proofs/README.md) | The Lean proofs and the TLA+ and SPIN models |
| [docs/SECURITY.md](docs/SECURITY.md) | Reporting a vulnerability |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | What changed in each release |

## Repository layout

- `runner/`: the source, `build.zig`, and the `Dockerfile` for the runner image
- `deploy/`: systemd units, Compose files, the engine's configuration, example env files, the
  AppArmor profile, and the release deploy agent
- `db/migrations/`: the schema for the optional Postgres mode (run state and logs)
- `proofs/`: Lean proofs, TLA+ specifications and SPIN models

## Origin

The runner was developed in
[Lementknight/zig-actions-runner](https://github.com/Lementknight/zig-actions-runner), together
with a read API and a frontend by [@philgutowski](https://github.com/philgutowski), the Tiger Data
schema by [@rafayet-git](https://github.com/rafayet-git), and the design documents, specification,
deployment guide, measurements and Agda proofs. Releases v0.1.0 and v0.2.0 were made there. This
repository carries the runner's history, and only what it needs to build, run and deploy.

Comments in `runner/src`, `db` and `proofs` cite three documents from that work ("SPEC §3",
"DESIGN §6", "STUDY.md §3.6"). They are at the commit the runner was split from, so the section
numbers match:
[SPEC.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/SPEC.md)
(configuration, the GitHub protocol, the database, what differs from GitHub's runner),
[DESIGN.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/DESIGN.md) (the
design) and
[STUDY.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/STUDY.md) (the
experiments).

## License

See [LICENSE](LICENSE). Vendored third-party code is listed in
[docs/THIRD_PARTY.md](docs/THIRD_PARTY.md).
