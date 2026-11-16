# Gitea and Forgejo (#520)

zig-runner can serve a Gitea or Forgejo instance instead of GitHub: the same runner, its native or
Dagger backend, its step cache and its trust rules, for the tasks an instance hands out. This page
is how to set it up and what a job from an instance sees. Linux only, as everywhere else.

Tested live against Gitea 28.3 and Forgejo 13.0 (register, fetch, run, report, cancel), and the
weekly oracle run compares 79 real tasks from both with what Gitea's own workflow model reads
([CI.md](CI.md)).

## Install

Build or download the runner as the [README](../README.md#quick-start) says. The native backend
with `RUNNER_ENGINE=none` needs no Docker and no GitHub credentials; the instance's runner token is
the only secret. In `/etc/zig-runner.env` (or the unit's environment):

```sh
RUNNER_PLATFORM=gitea                      # or forgejo
RUNNER_GITEA_URL=https://git.example.com   # the instance's address: http(s)://host[:port], no path
RUNNER_GITEA_REGISTRATION_TOKEN=...        # only until the runner is registered
RUNNER_LABELS=self-hosted,linux,zig        # what workflows name in runs-on
RUNNER_BACKEND=native
RUNNER_ENGINE=none
RUNNER_TRUSTED_REFS=refs/heads/main        # see Trust, below
```

Then run `zig-runner` (or the systemd unit in `deploy/`). `GH_TOKEN` and `GH_APP_*` are not used.

## Registration

Get a registration token from the instance: Site administration, Actions, Runners (every
repository), or the same page of an organization, a user or one repository. The runner registers
once, with `RUNNER_GITEA_REGISTRATION_TOKEN`, and keeps the credentials the instance gives it in
`gitea-runner-<RUNNER_NAME_PREFIX>.json` in `RUNNER_STATE_DIR` (`/var/lib/zig-runner` for root, else
the user's state directory), readable by its user alone. After that the token is not needed and can
be removed from the environment. Starting again declares the labels again, so a changed
`RUNNER_LABELS` takes effect on restart. A runner the instance has forgotten stops with the
instance's reason; delete the state file to register a new one. A state file left from another
instance is not used.

`RUNNER_COUNT` pollers share the one registration (act_runner's `capacity`), each running one task at
a time; `RUNNER_GITEA_FETCH_INTERVAL` and `RUNNER_GITEA_FETCH_INTERVAL_MAX` set how often an idle
runner asks (2 s, growing to 60 s). The runner stops cleanly on SIGTERM and cancels a job the instance
cancels (the job's `timeout-minutes` too).

A job's steps reach the instance, if it is on the host's loopback, LAN or tailnet, through an
address the runner opens for them (`gitea/reach.zig`), so `github.server_url` works from a step.

## Labels

`RUNNER_LABELS` is a comma-separated list; the instance matches a job's `runs-on` against it, and
sends the runner only jobs whose labels it all has. Write plain names (`self-hosted,linux,zig`,
`ubuntu-latest`). A label with a scheme, as act_runner's `ubuntu-latest:docker://node:20`, is passed
to the instance as written, and the runner does not read the part after the name: a job runs on the runner's
backend (the native rootfs, or `container:` when the workflow names one). Name a label for what a
job needs (`zig`, `arm64`), and keep `prod`-style labels for runners with trust rules.

## Trust

A workflow can be changed by a pull request, so the trust rules of
[OPERATIONS.md](OPERATIONS.md#environments) apply to instance jobs as to GitHub's:
`RUNNER_TRUSTED_REFS` and `RUNNER_TRUSTED_EVENTS` (default `push,workflow_dispatch`) say which jobs
run, and an untrusted job fails before a step runs, with the reason in its log. The instance does
not send GitHub's `workflow_ref`, so the runner builds it from the ref the run is for, which is the
ref the instance read the workflow at. Unset `RUNNER_TRUSTED_REFS` trusts nothing. A runner of a
public repository should trust only `refs/heads/main` and its tags: `pull_request` runs are then
refused, and nothing a fork sends reaches the runner's caches or secrets.

## Where actions come from

A step's `uses:` is read as Gitea's workflow model reads it (`model.ParseActionUses`):

| `uses:` | fetched from |
|---|---|
| `owner/repo[/path]@ref` | the instance's default actions URL, which the task carries as `gitea_default_actions_url` (`https://github.com` on a default Gitea, `https://data.forgejo.org` on Forgejo; the instance's own address when it is configured `self`) |
| `self:owner/repo[/path]@ref` | the instance the job runs on, with the task's `GITHUB_TOKEN` secret (what the instance sends as the task's token; the `gitea_runtime_token` is for its artifact and cache services, and git refuses it) |
| `https://host/owner/repo[/path]@ref` | that host, anonymously; the instance's own address is the instance |
| `$/path` | the workflow's own repository at the job's commit (no `@ref`, no `..`), with the same token |
| `./path` | the workspace, as on GitHub |

`ssh://` and credentials in the URL (`https://token@host/...`) are refused, with the reason in the step's log. A composite action's own
`uses: owner/repo@ref` steps come from the default actions URL too. `actions/checkout@v4` stays the built-in checkout; `self:actions/checkout` is the instance's action of that name.
GitHub jobs are not changed by any of this.

## Environment variables

Every step of a job gets GitHub's variables from the task's `github` context (`GITHUB_REPOSITORY`,
`GITHUB_SHA`, `GITHUB_SERVER_URL` and the rest of `Evaluator.defaultEnv`), `CI`, `GITHUB_ACTIONS`
and `RUNNER_*`, as a GitHub job does. What the two instances' own runners add, and what this runner
does, taken from `gitea/act_runner` (`internal/app/run/runner.go`, `gitea/act` `run_context.go`)
and `forgejo/runner` (`internal/app/run/runner.go`, `act/runner/run_context.go`):

| Variable | act_runner (Gitea) | forgejo-runner | zig-runner |
|---|---|---|---|
| `GITHUB_*` from the context, `CI`, `GITHUB_ACTIONS` | yes | yes | yes |
| `GITHUB_SERVER_URL` | the instance, no trailing slash | the same | the same: the task's `server_url` is trimmed, `github.server_url` too |
| `GITHUB_API_URL` | instance + `/api/v1` | the same | the task's `api_url` (the same value) |
| `GITHUB_GRAPHQL_URL` | empty | not set | empty |
| `GITEA_ACTIONS` | `true` | not set | `true` on Gitea |
| `GITEA_ACTIONS_RUNNER_VERSION` | the runner's version | not set | this runner's version, on Gitea |
| `GITEA_RUN_ID` | the context's `run_id` | not set | the same, on Gitea |
| `GITEA_ACTIONS_CAPABILITIES` | the `Declare` header, when there is one | not set | not set |
| `FORGEJO_ACTIONS` | not set | `true` | `true` on Forgejo |
| `FORGEJO_ACTIONS_RUNNER_VERSION` | not set | the runner's version | this runner's version, on Forgejo |
| `FORGEJO_<X>` for `<X>` in `WORKFLOW RUN_ATTEMPT RUN_ID RUN_NUMBER ACTOR REPOSITORY EVENT_NAME EVENT_PATH WORKSPACE SHA REF REF_NAME REF_TYPE JOB REPOSITORY_OWNER RETENTION_DAYS BASE_REF HEAD_REF SERVER_URL API_URL WORKFLOW_REF` | not set | the same value as `GITHUB_<X>` | the same, on Forgejo |
| `FORGEJO_ACTION`, `_ACTION_PATH`, `_ACTION_REPOSITORY`, `_ACTION_REF` | not set | twins of `GITHUB_ACTION*` | not set (known gap) |
| `GITHUB_TOKEN`, `FORGEJO_TOKEN` in the environment | not set | both, the job's token | not set: a step gets the token only where the workflow passes `${{ secrets.GITHUB_TOKEN }}`, as on GitHub (a difference on purpose for `GITHUB_TOKEN` itself: it is not in an action's environment. An action step does get `ACTIONS_RUNTIME_TOKEN`, in the next row, as act_runner gives it, and on Gitea that token also authenticates API requests while the task runs; see "Artifacts and the cache") |
| `ACTIONS_RUNTIME_URL`, `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_RESULTS_URL` | the instance's artifact service, the task's runtime token | the same | set for the steps that run an action (not for `run:` steps, as on GitHub): `ACTIONS_RUNTIME_URL` is the instance's `/api/actions_pipeline/`, `ACTIONS_RESULTS_URL` the instance, `ACTIONS_RUNTIME_TOKEN` the task's runtime token, which the log masks |
| `ACTIONS_CACHE_URL`, `ACTIONS_CACHE_MODE` | the runner's cache proxy | the same | not set: the instance has no cache service, and the runner serves none (see "Artifacts and the cache") |
| `ACTIONS_ID_TOKEN_REQUEST_URL`, `_TOKEN` | from the task's context, when it has them | from `forgejo_actions_id_token_request_*` | not set |
| `ACT`, `ACT_SKIP_CHECKOUT`, `JOB_CONTAINER_NAME`, `ImageOS` | set by act | set by act | not set: they name the runner's implementation |
| `RUNNER_PERFLOG`, `RUNNER_TRACKING_ID` | not set | from the task | not set |

The runner's own variables (`RUNNER_OS`, `RUNNER_ARCH`, `RUNNER_TEMP`, `RUNNER_TOOL_CACHE`, `RUNNER_NAME`...)
are GitHub's, set the same on every platform. The first rows are tested over a Gitea-style and a
Forgejo-style job (`Evaluator.zig`, "a Gitea or Forgejo job's steps see what act_runner and
forgejo-runner set besides GitHub's"), and the trailing slash in `gitea/job.zig`.

## Services

A job's `services:` run as they do for a GitHub job, on either backend's rules (the native backend
runs them in sandboxes of their own, reachable from the steps by name and on `localhost` at the
published ports, with `options: --health-cmd ...` health checks, and stopped with the job). The
workflow is read as Gitea's model reads it: a service is an image, or a mapping with `image`, `env`,
`ports`, `volumes`, `options` and `credentials`, and Gitea's own `cmd`.

- `cmd: [a, b]` starts the image's entrypoint with these arguments in place of the image's default
  command (Docker's `create IMAGE COMMAND`). Each element may be an expression. The native backend
  does it; the Dagger backend logs "Service cmd is not supported by the Dagger backend and was
  ignored".
- `volumes` and the options the native backend does not carry out are logged and ignored, as for a
  GitHub job.
- A `container:` job with `services:` is the same job as on GitHub.

Tested end to end on the native backend (`native/services.zig`, "native services from a Gitea
task"): a task's YAML goes through `gitea/job.zig`, the services start from a fixture image with the
task's own `cmd`, the step reaches one by name and by `localhost:<published port>`, and it is gone
with the job. Services from real postgres and redis images run in the existing
`ZIG_RUNNER_SERVICE_IMAGES` test.

## Reaching the instance from a job

A job's network reaches the instance's address and port, and nothing else of the host's
(`native/nft.zig`). That holds for an instance on the host's loopback (the runner forwards it, so the
job's `github.server_url` works), on another machine, and on the host's own address when it listens
there. It did **not** hold in the live jobs' first run for an instance in a Docker container with a
published port, dialled at the host's own address: the jobs' connections timed out. The probable
cause is that Docker's NAT rewrites the destination before the runner's rule sees it; the live jobs
run the instance on the host's network (`--network host`), where it works. An instance on the
loopback also cannot hand a job URLs made from its `ROOT_URL` (artifact uploads, for one): the job's
`127.0.0.1` is its own. Give `ROOT_URL` the address the host has on its network.

## Artifacts and the cache

**Artifacts** go through the instance, as with its own runner: an action that uploads or downloads one
talks to the instance's artifact service with `ACTIONS_RESULTS_URL` and `ACTIONS_RUNTIME_TOKEN`
(artifacts v4, a Twirp service) or `ACTIONS_RUNTIME_URL` (v3, the pipelines API), which every
action step gets. The runner serves nothing of its own. The instance's addresses are the ones the job
reaches it by (the runner makes a loopback or LAN instance reachable from the job's network;
`gitea/reach.zig`), and the runtime token is a different, narrower token than `GITHUB_TOKEN` (it
reaches the artifact services only), masked in the log.

GitHub's own `actions/upload-artifact@v4` and `download-artifact@v4` refuse to run when
`GITHUB_SERVER_URL` is not github.com ("not currently supported on GHES"), on Gitea and Forgejo as on
any server that is not GitHub's. Use `forgejo/upload-artifact@v4` and `forgejo/download-artifact@v4`
(`uses: https://code.forgejo.org/forgejo/upload-artifact@v4`, which Gitea's service takes too) or
`actions/upload-artifact@v3` where the instance still serves v3. The live jobs
([CI.md](CI.md)) upload and download one with the first, on a real Gitea and a real Forgejo.

**`actions/cache` does nothing** here: act_runner and forgejo-runner run a cache server of their own
(the runner's, not the instance's), which zig-runner does not, so `ACTIONS_CACHE_URL` is not set and
the action reports that the cache service is unavailable and carries on (a restore finds no entry, a
save is skipped; the step does not fail). What the runner offers in its place needs no action: the
step cache replays a step whose inputs have not changed, and the Zig, Cargo and package caches are
volumes the runner keeps for a repository's trusted jobs (`RUNNER_ZIG_LOCAL_CACHE`,
`RUNNER_CARGO_TARGET_CACHE`; [OPERATIONS.md](OPERATIONS.md#cache-volumes-and-trust)), the same as for
a GitHub job. A workflow that relies on `actions/cache` for something else (a dependency directory)
rebuilds it each job.
