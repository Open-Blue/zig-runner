# Security policy

## Reporting a vulnerability

Please report it privately, through GitHub's
[private vulnerability reporting](https://github.com/Open-Blue/zig-runner/security/advisories/new)
("Report a vulnerability" on the Security tab), not in a public issue. Say what is affected, how
to reproduce it, and what an attacker gains. The maintainer reads every report and responds
within 14 days. After that, a fix is released as soon as it is ready, and the advisory published
with it.

## What is in scope

The runner runs other people's workflows, so these matter most:

- **Trust enforcement** (`runner/src/trust.zig`): a job from an untrusted ref or event that runs
  on a runner configured to refuse it (docs/OPERATIONS.md, "Environments").
- **Secrets**: a secret, token or credential that reaches a log, an annotation, the database or a
  step that should not see it (`runner/src/redact.zig`, `runner/src/sink.zig`).
- **Escaping a job**: a step that reaches the runner's own process, its credentials, its Dagger
  engine, or another job.
- **Crashing or exhausting the runner** from a workflow, an action or a step's output (a panic, a
  stack overflow, unbounded memory): one job taking down every job on the machine.
- **The release and deployment path**: the workflows, the release artifacts and their provenance,
  and `deploy/zig-runner-deploy`.

## Supported versions

The latest release. Older ones get no fixes; the deployment script installs the latest release a
deployment records.
