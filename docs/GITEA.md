# Gitea and Forgejo (#520)

This page is what a job from a Gitea or Forgejo instance sees. Where its actions come from is in
[OPERATIONS.md](OPERATIONS.md#where-a-gitea-or-forgejo-jobs-actions-come-from-520).

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
| `GITHUB_TOKEN`, `FORGEJO_TOKEN` in the environment | not set | both, the job's token | not set: a step gets the token only where the workflow passes `${{ secrets.GITHUB_TOKEN }}`, as on GitHub (a difference on purpose for `GITHUB_TOKEN` itself: it is not in an action's environment. An action step does get `ACTIONS_RUNTIME_TOKEN`, in the next row, as act_runner gives it, and on Gitea that token also authenticates API requests while the task runs) |
| `ACTIONS_RUNTIME_URL`, `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_RESULTS_URL` | the instance's artifact service, the task's runtime token | the same | not set until artifacts go through the instance (#520, G5) |
| `ACTIONS_CACHE_URL`, `ACTIONS_CACHE_MODE` | the runner's cache proxy | the same | not set until `actions/cache` does (#520, G6) |
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
