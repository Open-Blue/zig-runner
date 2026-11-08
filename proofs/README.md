# The proofs, in Lean

Audience: whoever changes the caching, the regex matcher or `hashFiles()`, or doubts them ·
Companion: [MEASURE.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/MEASURE.md),
[CLAIMS.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/CLAIMS.md),
[RELATED.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/RELATED.md),
[SPEC.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/SPEC.md) §6

```
cd proofs
lake build --wfail
lake env leanchecker Runner Glob Oracle KeyOracle
lake env lean -DwarningAsError=true Axioms.lean
```

That checks two libraries: `Runner` (the step cache and the regex matcher's loops) and `Glob` (the
`hashFiles()` walk), plus the `globoracle` and `keyoracle` executables. They use Lean core only — no Mathlib, no
Batteries — and the toolchain is pinned by `lean-toolchain`. Nothing in `Runner/` uses `sorry`,
`axiom`, `native_decide`, `unsafe` or `partial`; every declaration in `Runner` and `Glob` depends on at
most `propext` and `Quot.sound`. The three commands are the whole claim, and CI (`proofs.yml`) runs
each as its own step:

| Gate | Fails when |
|---|---|
| `lake build --wfail` | a theorem does not check, or anything logs a warning: a `sorry` is a warning, so is an unused variable or a deprecated name. There is no `set_option` silencing a linter; a warning that has to stay takes a targeted option on that declaration, with the reason beside it |
| `leanchecker` | the kernel, replaying every declaration of those modules from the `.olean` files into the environment it was elaborated in, rejects one: what the build wrote is what the kernel accepts, so a tactic or elaborator that added a declaration without checking it is caught. It ships with Lean (since v4.28; the standalone lean4checker is archived), and it is not an independent kernel |
| `Axioms.lean` | a declaration in a module under `Runner` or `Glob` depends on an axiom outside its allow list (`propext`, `Quot.sound`), a module there declares an axiom, or a main theorem it names is missing. It prints `#print axioms` for each of the main theorems — those the tables below name |

The allow list is what the proofs use now; `Classical.choice` is not used, so it is not on it. `sorryAx`
(a `sorry`), `Lean.ofReduceBool` (`native_decide`, which trusts the compiler) and `Lean.trustCompiler`
never go on it. Widening it is a reviewed change to `Axioms.lean`, never a side effect of a proof.
The executables' roots (`Oracle.lean`, `KeyOracle.lean`) use `partial` and prove nothing, so the
kernel replays them but the axioms gate does not cover them.

The `Runner` library is a port of the Agda proofs in
[zig-actions-runner](https://github.com/Lementknight/zig-actions-runner) at commit
`1158524d2346fa8936352c21f9a63ef52d1f54dc`, theorem for theorem; the Agda names map to Lean ones by
replacing `-` with `_` and `⇒`/`≡` with words (`replay≡run` is `replay_eq_run`,
`recorded⇒not-run` is `recorded_not_run`). [Formulation changes](#formulation-changes-in-the-port)
lists where the encoding differs.

| Module | What |
|---|---|
| `Runner/Prelude.lean` | where the Agda prelude went in Lean core, and the few lemmas core lacks |
| `Runner/Model.lean` | the vocabulary: scripts, containers, keys, the cache |
| `Runner/Build.lean` | the scheduler and rebuilder, P1–P4, P6, failures not replayed, pruning, a shared cache |
| `Runner/OutputKeys.lean` | output keys and early cutoff |
| `Runner/Declared.lean` | P5, enforcement over guessing |
| `Runner/Enforce.lean` | the volatile clause of `Disciplined`, discharged, and P1 under enforcement |
| `Runner/Counterexamples.lean` | twelve computing jobs |
| `Runner/Logs.lean` | why a replayed log needs one output stream |
| `Runner/Native.lean` | the native backend's store as a refinement of the model: the key's bytes, replay, concurrency, eviction, layer digests |
| `Runner/Regex.lean` | why the regex matcher's loops terminate |
| `Glob/Match.lean`, `Glob/Walk.lean` | the `hashFiles()` matcher and walk |
| `Axioms.lean` | the axioms gate: the allow list, and the main theorems it prints |

One model here is not Lean: `tla/StoreLocking.tla`, the native store's locking protocol at the level
of system calls, model-checked with TLC in `store-model.yml` ([The store's locking, in
TLA+](#the-stores-locking-in-tla)). It checks what `Runner/Native.lean` assumes when it takes store
operations as whole entries.

## The step cache

[MEASURE.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/MEASURE.md) §4 lists
six properties the caching must *have* rather than merely measure. No benchmark can establish one of
them: a measurement says a step was replayed quickly, not that replaying it was right. These modules
state them and prove them, and for each hypothesis a proof needs, they give a concrete job where
dropping it makes the cache hand back an answer that running would not have given.

### What is modelled, and what it is in the code

| In the model | In the runner |
|---|---|
| `State`: a container *is* the recipe that built it | Dagger's container id is a lazy description; two containers built the same way have the same key |
| `State.afterCopy before digest` | `outputKeyed`: the container before an always-run step, with what it produced copied in by content digest |
| `Script.body text num` | the script text *and* the step's position, which `containerScript` writes in as `echo '<marker>begin <n>'` |
| `Script.stamped t s` | the always-run marker, `: 'zig-runner runs this step every time: … (run <nonce>)'`, written into the script so it lands in the key |
| `Trial` | one job's nonce: `run_nonce` is the run id, the attempt **and** the job |
| `Key = parent · script · stable env` | the exec recipe: `loadContainerFromID` + `withEnvVariable` + `withExec` |
| `stable` drops volatile names | `withVolatileVariable` for the names in `volatile_env` |
| `Progress.env`, and `Output.sets` feeding it | the container's variables, and what a step exported through `$GITHUB_ENV` / `$GITHUB_PATH`, which the runner reads from the step's file commands — a replayed step's included |
| `Input.mounts`, absent from the key | `withMountedCache`: what a cache volume holds is in no exec's key. Since Dagger v0.21.0 an exec is reused by DagQL's recipe digest, the call chain and its arguments, and a `cacheVolume` enters it as its key string, namespace, sharing and owner, never as its content. The volume's identity is in the real key, then, and the model drops it: see the `Key` row under "Against today's code" |
| `Output = log · digest · sets · code` | the step's output, `changes(from:).layer.digest`, its file commands, and its exit code |
| `Input.event`, `Progress.event`, absent from the key | the event payload the runner writes to `$GITHUB_EVENT_PATH` from a variable of its own |
| `replayable`: a hit counts only if it succeeded | `execScript`: a failure the cache answers with (`failedEarlier`: `ranThisRun == false`, or no marker and nothing of the step in the live log) is discarded and the step runs again |
| `Enforce.enforced exec`: an unmarked step handed `withhold i` | `RUNNER_ENFORCE_VOLATILE`: `zig-runner-withheld` for the volatile variables, `withheld_event` at `$GITHUB_EVENT_PATH` |
| `Logs.merged`, `Logs.replay` | `exec 2>&1` at the top of every step's script, and `replayRecorded` |
| `mark st = .everyRun` | `readsRunSpecific` (a volatile name, `GITHUB_EVENT_PATH` or the event file), plus the secret and OIDC reasons, which are the same case |
| `Mode = Nat → Keys` | `RUNNER_OUTPUT_KEYS`, **per step**: `outputKeyed` falls back to the step's own container whenever anything fails, which is `.off` for that step |
| `Subset` | the output store's pruning by age (`output_keys_days`) |
| `Elsewhere` | a cache a pool of runners shares, written by other jobs |
| `Runner.Declared` | the shelved `ZIG_RUNNER_INPUTS` prototype, which is *not* in the shipped runner |

Two choices are deliberate and worth arguing with. The key is modelled as a *projection*, not a hash,
so collisions are out of scope rather than silently assumed away. And `exec` takes the trial as well
as the input, so a step is **not** forced to be a function of its inputs — a flaky test is a
well-typed inhabitant, which is why determinism has to be asked for by name.

### What is proved

All names are under `Runner.`; `Build.`, `OutputKeys.` and so on are the modules' namespaces.

| MEASURE.md | Statement | Where |
|---|---|---|
| **P1** replay equals run | `Build.replay_eq_run`, for every mode — output keys on, off, or falling back per step — with failures in the cache | `Runner/Build.lean` |
| **P1 under enforcement** | `Enforce.replay_eq_run_enforced`: the same, for the step as the enforcing runner runs it, assuming only determinism and mount-blindness | `Runner/Enforce.lean` |
| a failure is not replayed (#69) | `Build.replayed_succeeds`: a step that was not run contributed a success; `recorded_failure_runs`: a step the cache answers with a failure runs | `Runner/Build.lean` |
| a replay's log is the run's (#71) | `Build.replay_logs_eq_run`; `Logs.replay_merged`, `live_merged`, and `Logs.TwoStreams` for the two streams before the fix | `Runner/Build.lean`, `Runner/Logs.lean` |
| **P2** a changed input invalidates | `Build.text_matters`, `position_matters`, `parent_matters`, `stable_env_matters` | `Runner/Build.lean` |
| **P3** an excluded input does not | `Build.mounts_invisible`, `volatile_invisible`, `event_invisible` | `Runner/Build.lean` |
| **P4** volatile ⇒ always-run | `Build.marked_misses`, and `Counterexamples.Marked` for the whole mechanism | `Runner/Build.lean`, `Runner/Counterexamples.lean` |
| **P5** enforcement over guessing | `Declared.undeclared_absent`, `enforced_depends_only_on_the_declaration`, and `Declared.Guessing` for what the alternative costs | `Runner/Declared.lean` |
| **P6** minimality | `Build.hit_keeps_ran`, `warm_runs_nothing`, `recorded_not_run`, `step_runs_at_most_once` | `Runner/Build.lean` |
| early cutoff | `OutputKeys.cutoff`, `cutoff_needs_only_the_digest` (both for a marked step that succeeded), `no_cutoff_without_keys`, `failure_is_a_wall`, `different_bytes_different_container` | `Runner/OutputKeys.lean` |
| pruning is safe | `Build.coherent_subset`, `ahead_subset`: both of P1's hypotheses survive dropping entries, so pruning can only cause misses | `Runner/Build.lean` |
| **P1 on the native backend** | `Native.native_replay_eq_run`, and `native_eq_dagger`: both backends give what the job gives with the cache off | `Runner/Native.lean` |
| a fork's pull request never shares a key with the repository's own jobs | `Native.scope_apart`, `fork_keys_apart` | `Runner/Native.lean` |
| the native key keeps what `Key` keeps | `Native.encState_injective`, `belowPreimage_inj` (with `belowTail_inj`), `encKey_injective`, `native_key_iff`, `native_mounts_invisible`, `native_volatile_invisible`, `native_event_invisible`; `Native.Ambiguous` without the lengths | `Runner/Native.lean` |
| a key stands on keys: nothing is keyed above a layer with none (a Docker action's, a JavaScript action's mount points) | `Native.ops_keep_chained` | `Runner/Native.lean` |
| a Dockerfile build's keys hold what its layers were made from, the base image's identity first | `Native.encBuild_injective`, `build_base_matters`, `encBuildLayer_injective` | `Runner/Native.lean` |
| native concurrency and eviction | `Native.ops_keep_honest`, `race_irrelevant`, `readWhole_agrees`, `Native.Torn`; a lost read in `nbuild` | `Runner/Native.lean` |
| native layer digests | `Native.walk_injective` (P2's walk as written), `digest_deterministic`, `digest_injective`, `same_layer_same_container`, `different_layer_different_container` | `Runner/Native.lean` |
| a shared cache is safe | `Build.elsewhere_ahead`: no other job can write under this job's nonce, which is why a pool may share one cache | `Runner/Build.lean` |
| **the volatile clause, discharged** | `Enforce.input_determined_by_key`, `volatile_clause_discharged`, `nothing_volatile_survives`, `no_payload_survives`, `enforced_disciplined` | `Runner/Enforce.lean` |

P1 is the one that matters: *a job run against a cache left by other jobs produces what the same job
produces with the step cache off, step for step.* It needs one real hypothesis.

**`Disciplined`** — for a step the runner does not mark, inputs agreeing on everything the key keeps
give the same result. It bundles three obligations: the step is deterministic, it does not consult a
volatile variable, and it does not depend on the content of a mounted cache volume. The runner
enforces none of them; it marks the steps it can detect and relies on this for the rest.

**One of the three can be discharged rather than assumed**, and `Runner/Enforce.lean` proves it.
Detection cannot be made sound — a script can reach a volatile value through a file it sources, a
program that reads the environment, or a name it builds from pieces, which is counterexample 1 and
the live B1 check. So apply what P5 does for files: hand an unmarked step **only what its key keeps**.
Then `input_determined_by_key` says its input is a function of its key, and
`volatile_clause_discharged` says equal keys give equal results as soon as the step is deterministic
— nothing need be assumed about what it reads, because nothing in its environment varies between
runs. `Counterexamples.Enforced` is counterexample 1's own `exec` against the same two jobs, no
longer able to tell them apart. The event payload is the same case (`no_payload_survives`,
`Counterexamples.EventEnforced`).

And it composes with the cache. `Enforce.enforced exec` is the step as the enforcing runner runs it
— withheld input if unmarked, the real one if marked — and `enforced_disciplined` says it is
`Disciplined` as soon as `exec` is `Deterministic` and `MountBlind` on unmarked inputs. So
`replay_eq_run_enforced` is P1 for the runner as it ships, with the volatile clause proved rather
than assumed.

What that leaves to assume is determinism and mount-blindness: two obligations instead of three.
**It is in the runner**, on by default, as `RUNNER_ENFORCE_VOLATILE` — a step that did not name a
run-specific value is given the constant `zig-runner-withheld` in its own `env` prefix, and the
same constant, as a JSON string, at `$GITHUB_EVENT_PATH` in place of the event payload (#68; until
then the payload was written to every step, and a script reading it from a file was replayed with
an earlier run's). One way around it is left: the parent shell's environment still holds the real
values, so a step that reads `/proc/$PPID/environ` can see them (see "Against today's code"). See
[SPEC.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/SPEC.md) §9, the first
entry in "Where this runner differs from GitHub's". Early cutoff turns out to need it too, and that
is new: what a step exports through `$GITHUB_ENV` is in the next step's container, so an unmarked
step that exported different variables in two jobs would part the keys after it
(`OutputKeys.keys_job_independent` takes `Disciplined`).

Everything else the proof uses is bookkeeping the implementation already does: `Coherent` (entries
are honest), `Ahead` and `Numbered` (the cache holds nothing yet for the steps still to come).

### What the counterexamples establish

Each is a complete, computing job in `Runner/Counterexamples.lean`, checked by `rfl` (the model
running) or `decide` (two concrete answers differ).

| # | The step | What happens | Hypothesis |
|---|---|---|---|
| 1 | reads `GITHUB_RUN_ID` without naming it (`VolatileRead`) | job 2 is handed job 1's answer and runs nothing; **8** closes this | `Disciplined` |
| 3 | a flaky test, unmarked (`Flaky`) | job 1 passed, so job 2 "passes" without running | `Disciplined` |
| 4 | reads a cache volume, unmarked (`MountedCache`) | replayed although the volume changed between jobs | `Disciplined` |
| 9 | reads the event payload from a file, unmarked (`EventRead`), as the runner did before #68 | run 2 is handed run 1's payload; **11** closes this | `Disciplined` |
| `Guessing` | keyed on a guessed input set, run in the whole workspace | replayed with a stale answer; enforced, it sees nothing instead | P5 |

The others are positive: **2** (`Marked`) declares the read and the marker makes the key new; **5**
(`SameStepTwice`) is a correction (below); **6** (`OutputKeys`) computes experiment 7.6's four
numbers — cold 2 runs, warm with keys 1, warm without keys 2, warm with a noisy output 2, which is
why `outputs_ignored` exists; **7** (`Exported`) shows a replayed setup step still exporting its
variable, so the step after it is replayed too; **8** (`Enforced`) runs counterexample 1's own
`exec`, unchanged, against an unmarked step's enforced input and finds it can no longer tell the two
jobs apart (`cannot_tell_them_apart`); **3b** (`FlakyFailure`) is a step that failed once and passes
after, which the cache recorded and, since #69, runs again rather than replays; **10**
(`EventMarked`) names the payload and runs every time; **11** (`EventEnforced`) is 9's `exec` under
enforcement, replayed and right.

**1 and 8 are a pair, and only 1 of them is still the runner's behaviour.** Counterexample 1 is why
`RUNNER_ENFORCE_VOLATILE` exists and what it would cost to turn off; 8 is what the runner does by
default (SPEC.md §9). The live counterpart, B1 in
[properties/](https://github.com/Lementknight/zig-actions-runner/blob/main/properties/README.md),
asserts both: still undetected and still replayed, as 1 has it, and told nothing rather than told
wrongly, as 8 has it. 3 and 4 have no 8 of their own — they are open.

### Three things this turned up

- **A claim of the first version of this model was wrong, and the model refuted it.** With `State`
  opaque, `exec` chose the container it left, so a step could leave the chain where it found it, and
  two marked steps in one job then shared a key — which made the step number in the log marker look
  load-bearing for correctness. It is not. A container's identity is the recipe that built it, so
  every step starts one deeper than the last (`depth_advances`), and that is what keeps two
  occurrences apart. `SameStepTwice` computes the miss. What *is* true of the marker is narrower and
  still worth knowing: the script text is in the key, so changing the marker format gives every step
  of every job a new key. (The Agda `Script` comment still calls the position load-bearing and
  points at the counterexamples; the port keeps that comment and marks the disagreement.)
- **Replay hides flakiness by construction**, not by omission. `disciplined_deterministic` derives
  determinism from the hypothesis P1 needs, so the step cache is sound only for jobs with no flaky
  unmarked step — a replayed step gives the result it recorded, a pass staying a pass. (A failure
  is not replayed: the runner runs a step again when the cache answers with one, #69.)
  [RELATED.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/RELATED.md) noted we
  had never measured flakiness; this says measuring it needs the cache off.
- **The documented gap is a correctness gap.**
  [SPEC.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/SPEC.md) §6 already
  says a script that reads run-specific values from a file in the repository is "not detected".
  Counterexample 1 shows what that costs: not a slower job, a wrong one.

### Obligations for the harness

What a proof of a property buys is a *test that is worth generating*: the model says which cases
matter and what must hold in each, so
[MEASURE.md](https://github.com/Lementknight/zig-actions-runner/blob/7641a69/docs/MEASURE.md) stage 3
does not have to guess. Each row is one generated family, against a real engine rather than the fake
session.

| From | Generate | Assert |
|---|---|---|
| P1 | any job, twice at the same commit: `RUNNER_STEP_CACHE=false`, then on | the same step logs, file commands and conclusions; and `N of M steps replayed` is M the second time. One known exception: with the cache off nothing is withheld, so a step that prints a run-specific value it did not name prints the real one off and `zig-runner-withheld` on (the model's `uncached` keeps the stamping and withholding). A replay printing stdout before stderr was a second one until #71 |
| P2 | four jobs, each changing exactly one keyed input: the script text, the step's position in the job, a file in the workspace, a non-volatile variable | the step ran — the `ZIG_RUNNER_RAN` marker is this job's |
| P3 | two jobs differing only in a volatile value (run id, actor, commit), and two differing only in a cache volume's content | the step was replayed |
| P4 | one job per name in `volatile_env`, whose script names it; and one using a secret, and one with `id-token: write` | the step ran, every time |
| P5 | on `feat/declared-inputs-v2`: a step whose declaration omits a file it reads | the step **fails**; it does not replay |
| P6 | a job whose every step hits | no step ran, and `N of M` is M |
| early cutoff | a marked step with a stable output, followed by unmarked steps; then the same with an output that changes every run | the marked step runs both times; the steps after it are replayed in the first case and run in the second |
| pruning | fill the output store, prune it (`RUNNER_OUTPUT_KEYS_DAYS`), re-run | results identical to the unpruned run; only the replay counts differ |
| shared cache | two jobs of the same workflow at once, on a pool sharing one engine | the same results as running them one after the other |
| `$GITHUB_ENV` | a setup step that exports a variable, replayed, and a step after it that reads it | the second step sees the same value and is itself replayed |

Three of these cannot be made to pass, and that is the point of having them: counterexample 1's
indirect volatile read, counterexample 3's flaky step, and counterexample 4's cache-volume read are
what the design *cannot* detect. Generate them as **expected failures**, so that the day one starts
passing, something has changed.

### What this does not model

Not proof of anything about: hash collisions (the key is a projection, so two different recipes never
collide here); the *interleaving* of concurrent jobs, only the shared cache they end up with
(`Elsewhere`), and for the native store whole-entry operations in any order (`Native.Op`), which
atomic publish is what justifies (model-checked below the Lean model, in [The store's locking, in
TLA+](#the-stores-locking-in-tla)) — Dagger's output store's first-writer-wins `mv -T` is not
modelled; anything bash does; and every
question of *cost* — nothing here says a replay is faster, only that it is right. Experiment 5's +28%
and +85% are why `Runner.Declared`'s mechanism is shelved, and no theorem in it argues otherwise.

`Step.reads` is the set of names a script really consults. `readsRunSpecific` approximates it by
looking for the name in the text, so the model's `mark` is an idealisation of the runner's, and
counterexample 1 is exactly the distance between them.

### Against today's code

The model was written against `runner/src/dagger.zig` on 2026-10-16; on 2026-10-27 it was audited
against the code again, element by element. The cache mechanism itself has barely changed since,
and the theorems still hold of the model. On 2026-10-31 the mount rows were checked against Dagger
v0.21.10, where reuse is decided by DagQL's recipe digest rather than BuildKit: a volume's content
stays out of the key and its identity stays in, as before, so no theorem changed. Where the runner
does not do what the model assumes:

| Where | What the runner does | Consequence | Issue |
|---|---|---|---|
| `Enforce`, `Input.event` | Withheld the 16 `volatile_env` variables but wrote the event payload in full to every step's `$GITHUB_EVENT_PATH`, from a volatile variable outside the key. Now a replayable step finds the withheld constant there instead, and a script naming `GITHUB_EVENT_PATH` or the file runs every time. The parent shell still keeps the real values in its environment | Was: a step whose script read the payload from a file was replayed with an earlier run's payload (#68, fixed; `Counterexamples.EventRead` computes it, `Enforce.no_payload_survives` and `EventEnforced` are the fix). Left: reading `/proc/$PPID/environ`, which the model does not have | #68 |
| `Output.code`, `replayable` | Failed steps are recorded (`withExec(expect: ANY)`), and were replayed; `GITHUB_RUN_ATTEMPT` is volatile. Now a failure the cache answers with is discarded and the step runs again, stamped with the run's nonce | Was: a flaky failure was replayed on every re-run (#69, fixed; `Counterexamples.FlakyFailure`). Modelled since: `Build.replayed_succeeds`, and `replay_eq_run` with failures in the cache. The model reruns the step under its own key rather than stamped, so it records the rerun where the runner keeps the failure: only which later jobs hit differs, not what any step produces | #69 |
| `Input.mounts`, `Disciplined` | Put uv's venv in a per-ref cache volume by default (`uv_env_in_cache`), step caching or not. Now that happens only in jobs whose steps are not cached; with step caching the venv stays in the workspace, part of each step's output, and the volume holds only uv's content-addressed download and wheel cache | Was: a replayed `uv sync` left the venv another commit's job synced, so later steps ran against its dependencies (#70, fixed). Left: mount-blindness is still assumed, not enforced, for what workflows themselves put in cache volumes | #70 |
| `Input.mounts`, `Disciplined` | Mounts the runner's own cache volumes on every step, step caching or not: the tool cache (`/opt/hostedtoolcache`, `RUNNER_TOOL_CACHE`) and the package managers' download caches (`package_cache_dirs`). They are runner-owned: the runner chose them, and mount-blindness is assumed of every step for them, not enforced | A step that writes into one and is replayed does not write again, and the volume may have been pruned or filled by another job since. The download caches are refilled by the tools that read them, so a later step only fetches again (unless it runs offline, as `cargo build --offline` does). The tool cache is not: a replayed tool install whose PATH comes back from its record (`$GITHUB_PATH`) points a later step at a directory the volume may no longer hold (`protoc: not found`). setup-* actions are JavaScript actions and run every time when the job has a token, so this takes a `run:` step that installs into the tool cache itself, or a job without a token. With `tool_trees` (`set_up.verifyToolTrees`), the paths and digests of the trees in the tool cache at "Set up job" are a stable variable of every step (`ZIG_RUNNER_TOOL_TREES`), so a tree removed or changed since the recorded run gives every step a new key; the lists that check keeps are in a volume no step mounts, so they are in no key either. That key does not cover a tree that was absent when the install was recorded too (the cold run that put it there, and any later job after a prune or a wipe, have the same variable), so a replayed answer whose `$GITHUB_PATH` entries or `$GITHUB_ENV` values name a directory in the tool cache that no tree checked in this job's "Set up job" holds (or any, when the trees were not checked) is discarded, and the step runs again, stamped, as a failure is (`Exec.toolDirNotHeld`). Like #69's, this adds runs only, so no theorem changes; the model's `replayable` has no such clause, and the runner is the refinement. Left: the download caches; a tree pruned after "Set up job", during the job; `::add-path`, which is off unless a job allows unsecure commands | #102, #229 |
| `Output.log` | Printed a replay's stdout, then its stderr, without blank lines, and took any in-range `::zig-step::` marker a step printed as the runner's. Now a step's script sends its stderr to its stdout (`exec 2>&1`), so the recorded stdout is the log in the order it was written and a replay logs it line for line, blank lines included, through the same workflow-command processing; and the runner's markers carry a per-job secret (`ZIG_RUNNER_MARK`, volatile, hidden from the step with `env -u`), so marker text a step prints is its output, live and in a replay | Was: masks, stop-commands, `::set-output` and problem matchers could apply differently in a replay, and a forged marker could make a later replayed step's output go unprocessed (#71, fixed; `Runner.Logs` models the two streams, `Logs.TwoStreams` the old order, `Build.replay_logs_eq_run` the log as one thing). Left: a step's programs see one pipe for stdout and stderr; a step that reads `/proc/$PPID/environ` can learn the secret; under `engine: cli`, a line a step prints that looks like a Dagger span header still names the step | #71 |
| `uncached` | `RUNNER_STEP_CACHE=false` turns off stamping and withholding too | P1 compares with a hypothetical stamped run, not with the cache-off runner; `replay_eq_run_enforced` with one that is withheld as well. They differ only for a step that reads what it did not name, which with the cache off sees the real value | — |
| `Script`, `Numbered`, `Ahead` | Composite inner steps and JavaScript pre/main/post share a step number; what keeps their scripts apart is the file-command directory in the text, plus the container's depth | The bookkeeping hypotheses are false in letter, true in substance: no two executions in a job share a stamped script | — |
| `Subset` | Models the engine's cache pruning (since Dagger v0.21.0 the step cache is DagQL's persisted result store, with its own GC; BuildKit's blob pruning is beneath it); the output store (`output_keys_days`) is a separate digest-to-bytes map the model has no object for | Store pruning is safe for another reason: the apply copies from the store and fails (so falls back) if the content is gone. A prune renames a directory out of the way before deleting it, and the apply checks the directory is still there after its copy, so a copy that overlapped another job's prune fails rather than ending with status 0 on part of the output (until #102, `rm -rf` in place could empty it under the copy) | #102 |
| `Key` | The real key holds more: cache volume identities (the `cacheVolume(key:)` string, so the repository and the trust scope, with the mount path and owner), the helper and runtime image addresses, action code, user and directory, the nesting flag, secret variables, the file-command paths | Only extra misses, so safe. A job the trust gate (#105) moves between `repo` and `untrusted` mounts other volumes, so every step of it misses once (no measured figure; the cold run in docs/BENCHMARKS.md is a full wipe, not this). The provisioned base container every step descends from is built before the cache mounts, so it is shared across `repo` and `untrusted`: today's one cross-scope seed, from the image tag and the provisioning script, never from a job's output. The runner passes no `source:`. The Zig seed is mounted as a directory (not a volume) at Zig's global cache, so its Directory ID is in every Zig step's key; it comes from a trusted, pinned input, never a job's output, and what a job writes there stays in that job's container | — |
| `mark` | The runner also marks every Docker action, every JavaScript action when a job token exists, and every step when the job has `id-token: write`. A variable holding a secret or an `::add-mask::` value (the workflow's, the job's, the container's, or one exported through `$GITHUB_ENV`) reaches the container as a Dagger secret, so its value is not in the key, and every step that has it is marked. A script holding one is mounted as a Dagger secret too, so its text is not in the key either, and its step is marked; so is a working directory holding one, the step's own or `defaults.run`'s, which the script changes to through a secret's alias | Only extra runs, so safe: a step whose key lacks such a value is stamped with the job's nonce | #101, #102 |

`Enforce` is composed with `Build` since #89: `Enforce.replay_eq_run_enforced` is P1 for `exec`
instantiated with the withheld input.

### On the native backend (P8)

The native backend (docs/native-backend.md) keeps its own step store, so the obligations the engine
discharged under Dagger are the runner's, and `Runner/Native.lean` states and proves each one. The
model above is unchanged; `Build` and its theorems describe both backends, and `Native` is the
second refinement of it: `native_replay_eq_run` is P1 against the same `uncached`, and
`native_eq_dagger` says the two backends give the same answers. The theorems of `OutputKeys` about
the keys a job asks (`keysFrom`, `cutoff`, `cutoff_needs_only_the_digest`, `nonced_stays`) hold
natively as they stand, because the native job hands on the same `nextState` and `nextEnv`. Of the
ones about what a cache can answer (`Clean`, `no_cutoff_without_keys`), only a marked step's own
miss is proved natively (`Native.marked_misses`). An unmarked step after it, whose parent names the
job, is still published, though no other job can ask for that key: P2 may skip it, as a saving.

The right-hand column names P2's code (`runner/src/native/`, merged in #268, with its review fixes
in #272 at `28a9dd1`, which add the store's format, the trust scope and the repository to
`Backend.below`), whose
key format is the one proved here.

| In the model | In the native runner (P2) |
|---|---|
| `State`: a container *is* the recipe that built it | the key chain: `Backend.keyFor` hashes, through `Store.KeyHasher` (`init(tag)`, `core`), the tag, the parent's key, the script, the stable env, then the uid, gid, working directory and kept files (`Native.keyPreimage`); the key of an exec is the key of the layer it leaves (`encKey`) |
| `State.base b` | the job's base layer (`Backend.base`): tag 0, with the digest below it (`Backend.below`: the store's format `Store.store_format`, the trust scope (`set_up.packageCacheScope`: `repo`, or `untrusted` for a fork's pull request), the repository, the rootfs's fingerprint (`Store.rootfsFingerprint`, an opaque digest to the model, checked again for every job), the userns mode (not the slot: a root runner's stored layers have the canonical ids, which every slot's job sees as its own; `userns_apart` keeps root and rootless runners apart), the binds, then P4's Zig cache seeds and which binds are cache volumes, only when the job has either (`belowTail`, so a job with neither has the bytes it had before); untagged, `KeyHasher.plain("below a base")`) in the parent's place. `Native.BaseSpec`, `belowPreimage`, and `Format.Sound.base_inj`: the model's base is what P2 hashes for it |
| `Key = parent · script · stable env` | `KeyHasher.core`, with `Store.stableEnv` as `stable vol`: `dagger.volatile_env`, the runner's own per-job values (`ZIG_RUNNER_EVENT`, `ZIG_RUNNER_RAN`, `ZIG_RUNNER_MARK`) and the secret aliases (`ZIG_SECRET_*`) are dropped. The mounts and the event payload are no argument of it, so `Input.mounts` and `Input.event` absent from the key hold by construction |
| no input of its own | `keyFor`'s tail after the core: for a step, the job's uid, gid and workspace (set with the base, `Backend.baseEnv`) and no kept file (`execScript` gives none, and a step with a file to write has no key), so a function of its parent's base (`Format.stepExtra`); for the base, root, `/`, and the event file when the payload is too large for a variable (then the base, and every key above it, is per run: only misses) |
| `Script` | a `run:` step's script (`scripts.stepScriptFc`), or a checkout's fetch of a commit (tag 1 too; a branch or a tag moves and is never keyed) |
| `State.afterCopy before digest` | tag 2 (`Store.Tag.output_keyed`), the parent's key and the layer's digest; P2 defines the tag, and output keys come later |
| `Output.digest` | `Store.layerDigest`: `Store.treeDigest`'s walk of the layer, entries in byte order of names, ids as the job's namespace sees them (`Store.Ids`), xattrs counted (P8's addition), content by type, `..` after a directory's entries: `Native.walkPreimage`, byte for byte (the `layer` vectors) |
| `Output.log`, `Logs` | `layers/<key>/log`, the step's output as the one pipe recorded it, so a replay is the run without `exec 2>&1` (`Logs.native_replay`); the script keeps it, since both backends run one script |
| `Cache`, `look` | `Store.open`: `layers/<key>` for the key's sha256 (`Native.Store`, `slook`) |
| `replayable`, `mark st = .everyRun` | `Backend.execScript` publishes (`publishTop`) only a step that exited 0, does not always run, and whose parent is in the store (`keyFor` is null otherwise): `Native.record`, so every hit is a success of an unmarked step (`hit_succeeds`, `marked_misses`) |
| `Stack`, `StackOp` | the job's `Backend.layers`: `execIn` adds a layer with no key, `claimKey` and `publishTop` give one a key only on a keyed top (`keyFor`), `keyFetched`, `dropTop`, `flatten` |
| `BuildState`, `encBuild`, `encBuildLayer` | `dockerfile.fromKey`, `stepKey` (each instruction's layer, `dockerfile.build`) and `layers.layerKey`; `.from`'s `id` is `docker_action.baseId`, `evaluated` and `reads` a digest where they are lists (`listDigest`, `contextDigest`) |
| `Subset` | `Store.collect`, LRU under `max_bytes` (`Native.evict`), and an entry `open` will not take (`lost`) |
| `Elsewhere` | a store a pool's runners share, `Store.lockKey` per key: what they do between steps is `Native.Op`s (`ops_keep_honest`) |

What the proofs need of the code, each a hypothesis or a definition the code has to match, and
where P2 meets it:

| Obligation | Where in the model | In P2 |
|---|---|---|
| The key's bytes are unambiguous: a fixed-width length before every field, counts before lists, a tag per kind of key, the store's format in every key | `Format.Sound`, `encState`, `belowPreimage`, `walkPreimage`; `Native.Ambiguous` is the cost without it | `KeyHasher.field` and `int` (u64 little-endian), `Store.Tag`; the digest below a base is untagged, but only ever a parent field. `Store.store_format` is in every base's parent, so in every key: a change of format, bumped there, makes every key new |
| The environment is spelt in the container's order, not sorted | `encEnv`, the `env-order` vector | `core` walks `b.env` in order |
| The script text tells apart the scripts the model tells apart | `Format.Sound.text_inj` | the same hypothesis the Dagger mapping relies on, unstated there |
| What is hashed beyond the model's key is determined by it | `Format.stepExtra`, `BaseSpec` | above: uid, gid and workspace are the job's, kept files are the base's |
| Only successes of unmarked steps are published | `record` | `execScript`, `publishTop` |
| A publish is one rename of a complete entry | `Op`, `publish` | built under `layers/.tmp-<key>-<n>` and renamed |
| A reader takes an entry whole or misses: a missing or short part is a miss, never empty | `readWhole`, `readWhole_agrees`, `Native.Torn` | `Store.open` takes the entry's lock shared and checks `Store.whole` (`fs`, `log`, `fc`, `size`) |
| The layer digest hashes the sorted walk of what a later step can see (path, type, mode, ids inside the job's namespace, xattrs, symlink target, whiteouts, content) and nothing else (times, inodes, host ids, readdir order) | `walkPreimage`, `walk_injective`; `layerPreimage`, `digest_deterministic`, `digest_injective` for the flattened form | `Store.treeDigest` with `Store.Ids`; `Store.listDir` sorts each directory; the xattrs are counted since P8 (without the count the walk was ambiguous) |

The flock per key is not among them: `race_irrelevant` shows two honest entries for an unmarked key
are equal, so which writer wins does not matter, and the lock only saves running a key twice.

`keyoracle` (`KeyOracle.lean`) ties the model to the Zig code as `globoracle` does for
`hashFiles()`: it writes `runner/src/native/testdata/step_keys.tsv`, pairs of inputs with the
model's verdict (equal or not: `Build.K` for steps, the `BaseSpec` for bases, the `Below` itself)
and the preimages (`keyPreimage`, `belowPreimage`, `walkPreimage`; u64 little-endian words,
UTF-8).
`.github/scripts/key-vectors.sh` checks the file is its output, and
`runner/src/native/key_vectors.zig` checks the Zig preimages and the relation against it: keys
through P2's own `Store.KeyHasher` and `Store.stableEnv`, the digest below a base through
`Backend.belowKey` (which `below` calls), and layer digests by making each tree and running
`Store.treeDigestTo` on it.

## The store's locking, in TLA+

`Runner/Native.lean` takes a store operation as one step on whole entries, in any order: a publish is
one rename of a complete entry, an eviction one entry removed, a reader takes an entry whole or
misses (`Native.Op`, `ops_keep_honest`, `Torn`), and `race_irrelevant` shows which of two racing
writers wins does not matter. Those are hypotheses about the system calls under it, with several
runners sharing one store and any of them dying between any two calls. `tla/StoreLocking.tla` is a
TLA+ model of that layer, and what it shows is what lets the Lean model have whole entries. Its
safety configurations are checked with SPIN, on a Promela port of the module that reaches exactly
the same states ("The store's locking, in SPIN", below), and its liveness with TLC:

```
.github/scripts/spin.sh   # SPIN 6.5.2: StoreLocking's safety configurations and its mutants
.github/scripts/tlc.sh    # fetches tla2tools.jar v1.7.4, checks its sha256, runs the rest
TLC_ALL=1 .github/scripts/tlc.sh   # ... and StoreLocking's safety with TLC too
```

CI runs them (`store-model.yml`) on pull requests and pushes that touch `runner/src/native/Store.zig`,
`Backend.zig`, `layers.zig`, `evict.zig`, `volumes.zig`, `oci/Store.zig` or the model, and weekly with
the proofs. It is not a proof: SPIN and TLC
explore every state of a bounded instance, and the bounds are below.

**What is modelled**, each action citing the code it stands for (file:line, in the module):

- `Store.lockKey`: `keys/<key>.lock` made if missing, `LOCK_EX | LOCK_NB`, polled, the lock kept
  only on the inode the path names now (`sameFile`), a step's wait ended by a cancel. A lock file
  is an inode with an identity, so a file `collect` deleted and a runner made again is a new one.
- `Store.open`: the entry's lock opened, `LOCK_SH` (blocking: it waits out an eviction), the path
  checked again, the entry read (`readEntry`); a broken one closed and evicted by name, and
  `error.Invalid` (the step runs uncached, `Backend.claimKey`) when another job holds it.
- `Store.publishTimed`: `layers/.tmp-<key>-<n>` made, the record written, the lock made and held
  shared, the upper renamed in, the tree's data written back (`writeBack`), the meta written, every
  file and directory fsynced (`syncEntries`, or `syncfs` for a large tree: one step, as they promise
  the same), `renameat2(RENAME_NOREPLACE)`, and its `errdefer` (the upper put back, the temporary
  entry removed, or left when it cannot be). A sync may fail, and the publish then fails with it.
- `Store.syncLayers`, at the end of a job that published a step's layer: `layers/` fsynced, so the
  renames so far survive a crash. Nothing else syncs them, so until then a crash may lose one, and
  the entry is a `.tmp-` again. A build layer's publish does not ask for it (`Backend.published` is
  a step's), so a crash may lose that rename: a miss, not a fault.
- `Store.checkOncePerBoot`, before a job's first step: the `boot` mark looked at, and for the first
  job of a boot `gc.lock` waited for, every entry's tree held against its meta, one that differs
  evicted, the mark written. The other jobs wait for it.
- `Store.evict`: the lock by name, `LOCK_EX | LOCK_NB`, the path checked again (`sameFile`),
  renamed to `.dead-<n>` by name, removed under the lock; an entry without a lock file taken
  without one.
- `Store.collect`: `gc.lock`; `.dead-` removed; `.tmp-` removed only when its key's lock is free
  (taken, and held while it is removed); an entry that does not look whole (`entryLooksWhole`, an
  older `store_format`'s among them, since #317 the last bump) evicted; past the cap any entry no
  job holds (the LRU order is over-approximated: any may go); `dropKeyLocks`.
- `removeTree` as `std.Io.Dir.deleteTree` does it: entries deleted one at a time, in any order,
  through the descriptor it opened (so a directory renamed meanwhile is emptied where it went), the
  tree's contents before the tree, the directory removed by its old name last, a missing name no
  error.
- The callers: `Backend.claimKey` and `publishTop` (a step's key held from the claim through its
  publish), the job's end (its layers let go, then `collect`), and `layers.zig` (a Dockerfile
  build's layer: `open` without the key's lock, a publish, and on a lost race `open` again).
- Flocks per open file description, not per process: a job that holds a layer and opens it again
  holds two locks, and closing one keeps the other.
- A process crash between any two actions (its flocks released by the kernel, its files left), a
  machine crash (every process; the data no one synced: the record and meta are taken to survive
  and the tree not, the worst case for a reader; any publish's rename no `syncLayers` covered, in
  any subset; other metadata is kept in order, as a journal keeps it, so a crash keeping less is a
  crash at an earlier state), after which each runner starts one job of one step, the first of a
  new boot, and a hand changing a published entry's record without changing its length (seen only
  by `open`'s sha256).

**What is checked**:

| Property | Says |
|---|---|
| `NoBadRead` | a job never takes (replays, or stacks as a build layer) an entry that is not published, every file there, its tree whole |
| `HeldIntact` | an entry a job holds stays published and whole until the job lets go: never evicted, renamed or emptied under it |
| `KeyMutex` | at most one process runs a step's key at a time |
| `NoWrongValid` | in no state, after any crash, is there an entry `readEntry` would accept whose tree is not whole |
| `NoLostUpper` | a step's upper is never deleted under it by another process |
| `OnePub` | one entry per key |
| `NoBuildLost` | a build that built its layer gets one: its own published, or the one another builder stored |
| `NoLostPublish` | a crash loses no rename of a step's layer whose job had finished (`syncLayers`) |
| `OldGoes` | an entry an older format left is gone once the jobs have ended, no key reaching it |
| `WaitEnds` | a claim waiting on its key's lock gets it, is cancelled, or its process dies: a holder that finishes or crashes lets it go on (weak fairness of each process) |
| `AllEnd` | every job ends, so no blocking flock waits for ever |

And seven mutants, each the code with one guard taken away, which SPIN (and TLC) must reject with the
invariant the configuration's first line names (`spin.sh` fails if it does not, so a model that
could no longer see a broken protocol fails CI): `StoreLocking-unlocked-build.cfg` (`layers.zig`'s
publish without the key's lock, as it was: `NoWrongValid`), `StoreLocking-unchecked-evict.cfg`
(`Store.evict` without `sameFile` after its exclusive lock, as it was: `HeldIntact`),
`StoreLocking-no-sync.cfg` (`publishTimed` without its sync: `NoWrongValid`),
`StoreLocking-sync-ignored.cfg` (`publishTimed` going on after a sync failed: `NoWrongValid`),
`StoreLocking-no-dir-sync.cfg` (a job's end without `syncLayers`: `NoLostPublish`),
`StoreLocking-no-boot-check.cfg` (`StoreLocking-boot-check.cfg`, which must hold, without
`checkOncePerBoot`: `NoBadRead`) and `StoreLocking-publish-first.cfg` (`layers.zig`'s publish under
the key's lock but publishing before it looks the key up, as #299 had it: `NoBuildLost`).

**Bounds** (the processes run one job each; a job's steps pick their keys freely):

| Configuration | Runners | Keys | Steps a job | Process crashes | Machine crashes | Hand's changes | Sync errors | Checks |
|---|---|---|---|---|---|---|---|---|
| `StoreLocking.cfg` | 3 | a step's, a build's | 1 | 1 | 0 | 0 | 0 | safety, with the runners' symmetry |
| `StoreLocking-crash.cfg` | 2 | a step's | 1, and 1 after the crash | 1 | 1 | 1 | 0 | safety, with the runners' symmetry |
| `StoreLocking-faults.cfg` | 2 | a step's, a build's, an older format's | 2 | 1 | 0 | 1 | 1 | safety, with the runners' symmetry |
| `StoreLocking-boot-check.cfg` | 2 | a step's | 1, and 1 after the crash | 0 | 1 | 0 | 0 | that the check after a boot is what keeps a job from a lost tree, with the publish's sync off |
| `StoreLocking-liveness.cfg` | 2 | a step's, a build's | 1 | 1 | 0 | 1 | 0 | safety and liveness, no symmetry |

One step key is enough for the protocol: keys share nothing but `collect` and `gc.lock`, so a
second step key adds interleavings, not cases. The build key is there for `layers.zig`'s path, which
holds no key lock while it builds; a crash sees nothing in it a step's publish does not show. Two
steps a job give a job a layer it holds while it goes on (and opens again: two flocks on one file).
Everything at once would be too large to check in CI (over 30 million states, unfinished after 10
minutes, with a build key and two steps a job beside a machine's crash), so `-crash` has the
machine's crash with one key and one step, and `-faults` the two steps, the build key, a sync error
and an older format's entry without it: no run has two steps a job and a machine's crash together.
Each configuration is two minutes or less on a laptop ("cowbird", 12 threads, `-workers auto`,
`-Xmx8g`, 2026-11-07), and on GitHub's 4-core runner about 1.5 times that:

| Configuration | Distinct states | Depth | Time | Without the symmetry |
|---|---|---|---|---|
| `StoreLocking.cfg` | 2,754,585 | 112 | 56 s | 16,495,442 (5.99 times: 3 runners, 6 orders) |
| `StoreLocking-crash.cfg` | 7,337,252 | 140 | 1 min 53 s | 14,674,008 (2.00 times) |
| `StoreLocking-faults.cfg` | 5,379,277 | 142 | 1 min 28 s | 10,758,378 (2.00 times) |
| `StoreLocking-boot-check.cfg` | 191,178 | 136 | 5 s | 382,279 (2.00 times) |
| `StoreLocking-liveness.cfg` | 167,362 | 74 | 23 s | (no symmetry) |
| the seven mutants | under 50,000 each, to the first violation | | seconds | |

**The runners' symmetry** (`ProcSymmetry`, safety only): TLC keeps one state of each set of states
that differ only in which runner is which, which is sound only if nothing in the model tells the
runners apart. Before the times above it did not hold: `collect` and the check after a
boot took the next directory of their listing with a `CHOOSE` over its ids, which name the runner
that made it, so readdir's order was by the runners' names. `StoreLocking-boot-check.cfg` then had
536,011 states without the symmetry and 205,674 with it, fewer than the 268,006 sets of at most two
that two runners leave: TLC left behaviours of the model unexplored, and `-crash` (19,218,025
states without it, 6,545,285 with) and `-faults` the same way; their counts even varied from run to
run (`-crash` 6,543,505 to 6,547,430, `-faults` 4,582,934 to 4,610,311), as which state of a set TLC
kept depended on which its workers found first. The order is now the lister's
(`First`): by the step that made a directory, its epoch, and the lister's own before the other
runners', with two other runners' directories alike in all three in either order. Nothing else names a
runner: the `CHOOSE`s left are over keys, or over `Pub(k)`, which has one entry at most (`OnePub`). The
counts above show it: without the symmetry, every configuration has twice its states with it (two
runners), less the few hundred states that swapping the runners leaves as they are (77 to 496), or
six times (three). Two
other fixed orders were measured and left: by step and epoch alone, ties in either order (9,206,560
states for `-crash`), and each runner's directories in order but the runners' interleaved
(15,031,366, more than the model without the symmetry takes). Each is as arbitrary as readdir's, and
the one taken is the cheapest that is sound. The mutants have no symmetry, and each still fails with
its invariant. A bug only the runner `p1` has (`evict` without its `sameFile`, in
`StoreLocking-unchecked-evict.cfg`'s bounds with the check on for the others) is found with the
symmetry too (`HeldIntact`, 19,826 states; 39,506 without).

Two larger runs were made while the model was written and are left out of CI for its time: three
runners with a hand's change (6.7 million states, 3 minutes, no error), and three runners with two
steps each, stopped unfinished at 3 million states with no error. The
model folds a process's purely local steps (choosing the next key, the poll's sleep) into the
actions around them, which removes interleavings without removing a behaviour.

It says nothing of what a publish's order among its own files buys since #309 (the tree's data, then
the meta, then the fsyncs, in one journal commit): nothing of a `.tmp-` entry is visible, so the
order before the rename cannot change a safety property, which is what the model confirms by
modelling it. Its cost is measured in #309; the disk's side of it is the store's crash test, on a
real ext4 (`.github/scripts/store-crash.sh`).

**What it found**: two races, both in the code since P2 and P7, both fixed with a test that fails
without the fix.

1. *A build layer's publish without its key's lock.* `collect` takes a `.tmp-` entry whose key's
   lock is free for a dead runner's, but `layers.Store.publish` (a Dockerfile build's layer, P7 on
   P2's store) held no key lock. TLC's trace (16 states, `StoreLocking-unlocked-build.cfg`): runner
   1 builds a layer, and `Store.publish` has written the record and meta and made and locked the
   lock file in `layers/.tmp-<key>-<n>`; runner 2's job ends, its `collect` finds the key's lock
   free and starts `removeTree` on the entry, deleting its lock file; runner 1 moves its upper in,
   syncs, and `renameat2` makes the entry visible. It is published without a lock file, so no job
   can hold it (the builder's shared lock is on the unlinked file) and the next eviction removes
   it from under the builder; with the deletions in another order the entry is visible with a
   half-deleted tree, which `readEntry` (it does not look inside the tree) accepts, or the
   builder's upper is deleted under it. Fixed by taking the key's lock around
   `layers.Store.publish`, as `claimKey` does for a step; `Store.publish` now says its caller holds
   it. Test: "a layer is published under its key's lock" (layers.zig).
2. *An eviction that renamed away the wrong entry.* `Store.evict` opened the entry's lock file by
   path, took it `LOCK_EX | LOCK_NB`, and renamed `layers/<key>` by name, without checking the lock
   was still on the file the path names, as `open` and `lockKey` do. TLC's trace (48 states,
   `StoreLocking-unchecked-evict.cfg`): runner 1 publishes a build layer and its job ends; a hand
   changes the entry's record; runner 1's `collect` opens the entry's lock file to evict it (the
   cap); runner 2's `open` finds the record broken and evicts the entry itself; runner 2 builds the
   layer again, publishes it and holds it; runner 1's exclusive lock on the old, unlinked lock file
   succeeds (no one holds that file), and its rename takes runner 2's new entry. Any reason
   `readEntry` fails (a disk that filled, a part cut short) does as well as the hand. Fixed:
   `evict` checks `sameFile` after the lock (`Store.evictOpened`). Test: "an eviction whose entry
   went meanwhile leaves the one published since" (Store.zig).

A third race the store's stress test (`runner/src/native/store_stress.zig`) found, and the model
then took in. With the key's lock, `layers.Store.publish` still published first and looked the key
up only once `renameat2` refused, as the code had it before the lock: the model counted a build
that then found nothing as a legal outcome. But the key's lock does not keep `collect` out: runner
1 publishes a build layer and its job ends; runner 2 builds it too, takes the key's lock, and its
rename is refused; runner 1's `collect` evicts the layer, which no job holds; runner 2's lookup
misses, and its build fails with a layer it built and none stored (TLC's trace,
`StoreLocking-publish-first.cfg`, under 4,000 states). `NoBuildLost` is the property, and
`BuildLooksUpFirst` the fix: under the key's lock, the key is looked up first, so a layer that is
there is used and one that is not cannot appear before the publish.

Bringing the model up to #309, #310 and #317, with the machine's crash now losing renames and the
jobs after it running through `checkOncePerBoot`, found no new race in the layers' protocol, which
is the result: every configuration holds. It found three things worth saying. An older format's
entry does not "age out under the cap", as the docs said: it is not whole to `collect`, so an
upgrade across a bump empties `layers/` at its first job's end (`OldGoes`; the docs are fixed). A
Dockerfile build layer's rename is not synced by `syncLayers`, as `Backend.published` is set only by
`publishTop`: a crash can lose it, which is a miss and not a fault, and `NoLostPublish` covers steps
alone. And `Rt`, the model's `removeTree`, left an evicted entry `dead` and empty for ever, as it
compared against the name before the rename; nothing looked at that state until `OldGoes` did.

A fourth thing it turned up is about the model, not the code: a flock belongs to an open file
description, and the first version of the model, which kept one lock per process, reported a
held layer evicted that the kernel would have protected.

**What it does not model**: the keys' meaning and the record's content (the Lean model's); a
step's parent being in the store (each key here stands alone); the bytes a meta counts (the stress
test found `publish` measuring a tree while the kernel still wrote it back, a block short: a
tree whole on disk, counted low against the cap, and now measured after the `syncfs`); the LRU
order and the byte cap
(over-approximated by "any entry may go"); `layerDigest`'s file (written aside and renamed, never
read by `open`); the rootfs, the provisioning store (`oci/Store.zig`) and flattening, which write
into the job's own directory; a hand deleting an entry's lock file (`evict` would then remove an
entry a job holds: the store is the runner's alone, `Store.prepare`); readdir returning an entry
twice; and more runners, keys or steps than the bounds.

### The store's locking, in SPIN

CI checks `StoreLocking`'s safety with SPIN 6.5.2, not TLC: `proofs/spin/StoreLockingModel.pml`
is the module in Promela, action for action, and `.github/scripts/spin.sh` checks every safety
configuration and every mutant with it, side by side on the machine's cores. TLC still checks
`StoreLocking-liveness.cfg` (SPIN's weak fairness is per process, and would force the crashes and
the hand's changes, which the module never forces). `StoreLocking.tla` stays the documented model:
the actions above, their comments and the code they cite are the module's, and the port says only
how it encodes them.

**Kept in step.** A change to one is a change to the other, in the same pull request:

- The configurations are the `.cfg` files. `proofs/spin/cfg.py` writes each
  `proofs/spin/StoreLocking*.pml` from the `.cfg` of the same name (constants as `#define`s, the
  invariants it lists, the "must fail" line), and `spin.sh` fails when one is stale, missing or left
  over, so the two have the same configurations and mutants. A new mutant is a new `.cfg`, then
  `cfg.py`.
- Each configuration that must hold says how many states it has without the symmetry
  (`states without symmetry:`, TLC's count), and SPIN must find exactly that many and one more
  (SPIN's first state, before `init` sets the variables): a change to the Promela that the TLA+
  does not have, or the other way round, changes one count and not the other. After a change to
  the module, run `TLC_ALL=1 .github/scripts/tlc.sh` with `SYMMETRY` taken out of the
  configurations for the new counts, change the Promela, and the counts must agree.

**Faithful, by the counts.** With partial order reduction off and no symmetry (SPIN has none),
SPIN's states are TLC's without the symmetry, plus one, in every configuration, including each
mutant run to the end with its invariant off:

| Configuration | TLC, no symmetry | SPIN |
|---|---|---|
| `StoreLocking.cfg` | 16,495,442 | 16,495,443 |
| `StoreLocking-crash.cfg` | 14,674,008 | 14,674,009 |
| `StoreLocking-faults.cfg` | 10,758,378 | 10,758,379 |
| `StoreLocking-boot-check.cfg` | 382,279 | 382,280 |
| the seven mutants, no invariant | 521,379, 1,593, 1,034, 6,683, 3,814, 46,604, 8,040 | each one more |

And every mutant fails with the assertion of the invariant its first line names. What makes the
counts equal: each variable of the module is a variable here, its sets bit masks over the same
elements and its strings numbers (the encoding is in the port's header), nothing else is in SPIN's
state (the runners' and the environment's program counters stay at their loops' heads between
steps, and the temporaries a step uses are `hidden` or set back to 0), and each action is one
step: a `d_step`, or for a choice the module makes with `\E` over directories or subsets, an
`atomic` that chooses and then does the rest in one `d_step`. A deadlock is the same to both: the
runners are never at an end label, and the module's step of a terminated system is the
environment's. Where the module's `CHOOSE` picks among more than one value (`dropKeyLocks`' next
key, with two keys), SPIN takes the least; the counts for `StoreLocking.cfg` and `-faults` show
that TLC's choice gives the same graph.

**Time**, `StoreLocking-crash.cfg` on the laptop (cowbird, 12 threads, 2026-11-07, load under 4):

| | laptop | 4 cores (`taskset -c 0-3`) |
|---|---|---|
| TLC, with the symmetry (7,337,252 states), `-workers auto`/`4`, `-Xmx8g` | 111 s | 217 s |
| SPIN, one core, exhaustive (14,674,009 states) | 22 s | 22 s |
| SPIN, `-DNCORE=4` (`spin -DNOHIDDEN`) | 11 s | 12 s |
| SPIN, `-DNCORE=8` | 8 s | |
| compiling `pan.c` (gcc 15.2, `-O2`) | 10 to 14 s | |

The whole of `spin.sh`, the four configurations that must hold and the seven mutants, compiles
included, takes 61 s on the laptop and 75 s on 4 cores; TLC took 4 min 22 s for the four
configurations alone, one after another on the laptop. `spin.sh` runs the configurations side by
side, one a core, rather than SPIN's multi-core search, which is faster for one configuration but
needs every temporary in the state. Partial order reduction is off: it reduces nothing (every step
reads or writes the shared store) and costs a quarter of the time. Bitstate and hash compaction
(`-DBITSTATE`, `-DHC4`) are not used: on `-crash` they missed 470 and 134,163 states.


### Eviction beside the layers

`tla/StoreEviction.tla` is the protocol of `runner/src/native/evict.zig` and what it shares with
`volumes.open`, `oci.Store.hold` and `ensure`: entries whose lock is beside them (`<dir>.lock`), held
shared by a job for as long as it uses the path, and which an eviction removes, so that whoever
takes one must check it is still the file the path names. A volume is made in place, a tree aside
and renamed in. One volume can be inside another's directory (`<key>` and `<key>/runner`), whose lock
file then goes with the outer one's rename and is in a place a job can write: the job holding the
outer volume may leave anything at that name (`Plant`). A `-nested` configuration has that case. It
does not plant over a lock a job holds: that job's volume is inside this one's, which can delete it
whatever a lock says, so no protocol here can keep it. A rename to a dead name has two directories,
and the model tells them apart: where it went, and where it came from, which for a volume is
another. And a dead tree may fail to go.

| Property | Says |
|---|---|
| `HeldWhole` | what a job holds is what the path names, and nothing of it was deleted, until the job ends |
| `NamedWhole` | no name ever names a tree something was deleted from, whatever crashes |
| `OneMaker` | two jobs do not make one tree at once |
| `NotPinned` | nothing a job leaves at the inner lock's name keeps a volume from going |
| `PassGoesOn` | a dead tree that will not go ends no pass |
| `LocksExclude` | flocks as the kernel gives them, the model's own check |
| `AllEnd` | every job ends |

Mutants, each with a guard taken away: `-no-recheck` (no `sameFile` after a job's lock:
`HeldWhole`), `-no-down-check` (`ensure` taking what it made to be there, once exclusive became
shared, which `flock` does not do atomically: `HeldWhole`), `-no-lock` (an eviction by age alone:
`HeldWhole`), `-no-inner-lock` (an eviction without the inner volume's lock: `HeldWhole`),
`-delete-first` (deleting before the rename: `NamedWhole`), `-no-rename-sync` (deleting before the
rename is on disk: `NamedWhole`), `-area-sync` (a later pass syncing only the area's directory:
`NamedWhole`), `-planted` (stopping at what a job left at the inner lock's name: `NotPinned`),
`-stuck-stops` (a pass that ends at a dead tree it cannot remove: `PassGoesOn`).

**What it found.** A runner renames a tree to `.dead-<n>` and dies before it syncs that rename;
another runner's pass finds the dead tree and starts deleting; a machine crash keeps the deletes and
loses the rename, and the name comes back on a tree half gone. On ext4 the journal's order rules that
out; on a filesystem that does not promise it, nothing else did. `removeDead` now syncs the filesystem
before it deletes anything there, whoever made the dead name (`StoreEviction-crash.cfg` found it, in
24 states). Syncing the area's directory alone, the first fix, was not enough: a volume's rename has
another source directory, which a model that told the two apart showed in 25 states.

**What it does not model**: how `removeSome` goes through a dead tree (a tree goes in any order here;
its descriptors, and the `.cut-` names that move what is deep to the top, are the code's and its
tests'); time (a sync of any length is one step, so the budget is not here); sizes, the caps and the
order of eviction (any entry may go, which over-approximates the LRU); the blobs, whose lock is a plain reader-writer lock; a volume's content,
which no one synced and which is only a cache; and a published tree's data, synced before its rename
as a layer's is, which `StoreLocking.tla` models for layers and the store's crash test runs on ext4.
The bounds are small: three runners, one job each and a process crash, and two runners with a
machine's crash. It is not a proof beyond them.

Its runners' symmetry is sound: no expression names a runner (its `CHOOSE`s are over keys and dead
trees, which name none), and the counts agree. Without the symmetry `StoreEviction.cfg` has 3,109,886
states (5.58 times its 557,195; three runners, at most six), `-nested` 955,704 (5.57 times 171,460) and
`-crash` 7,379,839 (1.98 times 3,727,288; two runners).

## The release pipeline, in TLA+

`tla/ReleasePipeline.tla` models how a merge into `main` becomes a tag and a deployment, at the
level of GitHub's runs and jobs, **as #408 has it** (with its 85dc4e8): `.github/checks-on-main`
read from the commit the job checked out, and `wait-for-checks.sh` failing at once on a check that
never started, once every workflow run on the commit has finished, leaving out the waiting
workflows' own runs. Until #408 merges, `main`'s own pipeline is the mutant
`ReleasePipeline-inline-list.cfg` (and has no fast fail at all, `-no-fast-fail.cfg`). It is checked
by the same `.github/scripts/tlc.sh`, in `store-model.yml`, which also runs on changes to
`version.yml`, `release.yml`, `next-version.sh`, `wait-for-checks.sh`, `check-names.sh` and
`.github/checks-on-main`. As for the store, TLC explores every state of a bounded instance; it is
not a proof for every size.

**What is modelled**, and what it is in the workflows:

| In the model | In the workflows |
|---|---|
| `main`, a line of commits; `Merge` | the merge queue's merges; each may rename or add a check (as #405 renamed one), and `checks-on-main` changes with it (`check-names.sh` holds in the queue, so the names at a commit are the jobs it runs on a push: one function, `jobsOf`) |
| `wf[c]["A"]`, `wf[c]["B"]`; `CreateWf`, `FinishWf` | `ci.yml`'s and `proofs.yml`'s push runs on a commit: created, or never (`lost`: GitHub did not start it), then passing or failing. A run's jobs end together; "t" stands for the checks no merge renames, "old"/"new" for the one renamed |
| `wf[c]["C"]` (`OtherWf`) | a run on the commit that reports none of the checks: `codeql.yml`'s and `scorecard.yml`'s push runs, or a scheduled run made at the commit (`analysis.yml`'s, jobs of up to 75 minutes). The fast fail waits for it too. One is enough: the script only counts them |
| `Create`, `StartPending`, `InGroup` | a scheduled or dispatched `version` run, made from `main` as it is (its `head_sha` and the `version.yml` it runs), entering `concurrency: group: version`, `cancel-in-progress: false` |
| `Check` | the `check` job, `next-version.sh` on `main`: nothing merged since the last tag, nothing to do |
| `Approve`, `ApprovalTimeout` | the `tag` job's `environment: prod`: approved late or never (unfair); with no approval the run fails when the environment's wait runs out |
| `Approve`'s read of `main`; `list` | the tag job's checkout of `main` and `next-version.sh` again; the names it will wait for: `checks-on-main` at that commit (#408), or the run's own `version.yml` (before #408, `ListFromCommit = FALSE`) |
| `Poll`, `Outcome`, `CanPoll`, `ScriptSeesDone` | one poll of `wait-for-checks.sh`: a failed check fails at once, all passed goes on, a check that never started fails once `open == 0 && total > 0` over `actions/runs?head_sha=` without `version.yml`'s and `release.yml`'s runs (`RunsCounted = "others"`) and the grace has passed, the deadline fails the rest. `el` counts polls (`WaitTicks` is `WAIT_MINUTES`, `Grace` is `GRACE_SECONDS`) |
| `Push` | `Commit and tag` and `Push`: the release commit on the commit checked out, `git push --atomic HEAD:main refs/tags/$TAG`, refused whole when `main` moved |
| `rel[i]`, `Build` | `release.yml` on the tag: Binaries, Image and Image (publish), one step (a failure of any is the same to the deploy job); Binaries (check) is skipped on a tag |
| `DeployStart`, `DeployPoll` | the deploy job's `if:` (explicit results; `DeployIfExplicit = FALSE` is v0.14.0's implicit `success()`), then `wait-for-checks.sh` on the tag commit with `checks-on-main` read from the tag, then the deployment recorded |

The fast fail leaves out the runs of `version.yml` and `release.yml` because they are the ones
that wait. The job running the script is in one of them, open while it waits. A `version` run's
`head_sha` is `main` when GitHub made it, so it is on the commit its tag job checks out whenever
nothing merged in between, the usual case. `release.yml`'s run is always on the tag commit. A
pending `version` run made at the commit is open too. Counting them, as the script did before
85dc4e8 (`ReleasePipeline-own-run.cfg`), the fast fail never fired in the deploy job, and in the
tag job only when a merge came between the run's creation and the approval. What the waits wait
for comes from the other workflows; the release run's own Binaries and Image are done before its
deploy job starts.

GitHub's concurrency is taken from [Control the concurrency of workflows and
jobs](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency):
at most one run in progress in the group and, with the default `queue: single`, at most one
pending; a run queued while one is in progress is pending, and a pending one already there is
cancelled; with `cancel-in-progress: false` the one in progress is kept. The page does not say
whether a run whose job waits for an environment's approval is in progress. The model takes it
so (it has started; `ApprovalHoldsGroup = TRUE`), and checks the weaker reading too
(`ReleasePipeline-approval-outside.cfg`: a newer run starts beside it).

**What is checked**:

| Property | Says |
|---|---|
| `TagChecked` | no tag unless every check in `checks-on-main` succeeded on the commit the release commit goes on (the release commit adds only the version and the changelog; its own checks are the deploy's) |
| `DeployChecked` | no deployment unless the tag commit's checks and the release's own jobs passed |
| `OneTagJob` | never two tag jobs (approved, waiting or pushing) at once |
| `TagOnMain` | a tag is always on `main`'s history |
| `FreshList` | the tag job waits for the names current at the commit it checked out, never a stale list |
| `Includes` | the release includes every merge on `main` when its tag job read it |
| `WaitBounded` | a wait ends within `WAIT_MINUTES`, and a failure names its reason |
| `FastFail` | once every run on the commit but the waiting workflows' has finished, a check that never started ends the wait at the first poll past the grace, not at the deadline, in the tag job and in the deploy job |
| `FastFailOnChecks` | sooner: once the runs that report the checks (`ci`'s, `proofs`') have finished, whatever else runs. Does not hold, by design (below) |
| `TagJobEnds` | an approved tag job ends: it tags, or fails naming a reason (weak fairness of GitHub's and the jobs' steps) |
| `DeployEnds` | a release that tagged deploys, or fails where it shows (a job failed) |

**Bounds and results** (cowbird, 12 threads, `-Xmx8g`, 2026-11-07): `WaitTicks = 2`, `Grace = 1`,
`MaxRenames = 1` everywhere. The safety configurations are checked under `LiveView` (below); the
states without it are the model's own.

| Configuration | Merges | Version runs | Push runs | Lost runs | Failures | Checks | Distinct states | Without the view | Depth | Time |
|---|---|---|---|---|---|---|---|---|---|---|
| `ReleasePipeline.cfg` | 1 | 3 (one in progress, one pending, one replacing it) | ci, proofs, other | 1 | 1 | safety, `FastFail` | 156,279 | 2,002,482 | 30 | 6 s |
| `ReleasePipeline-merges.cfg` | 2 (one may come while a tag job waits) | 2 | ci, proofs | 0 | 0 | safety (`FastFail` trivially: no check goes missing) | 59,935 | 1,474,773 | 39 | 4 s |
| `ReleasePipeline-liveness.cfg` | 1 | 2 | ci, proofs, other | 1 | 1 | safety, `FastFail`, `TagJobEnds` | 373,471 | (no view) | 33 | 37 s |
| `ReleasePipeline-liveness-deploy.cfg` | the same | | | | | safety, `FastFail`, `DeployEnds` | 373,471 | (no view) | 33 | 41 s |
| `ReleasePipeline-approval-outside.cfg` | 1 | 2 | ci, proofs, other | 1 | 1 | safety but `OneTagJob`, under the weaker reading of the concurrency docs | 105,604 | 1,445,110 | 29 | 4 s |
| the mutants and the finding | | | | | | to the first violation | under 20,000 each, `-v0.14.0` 234,337 (a liveness search, no view) | | | seconds, `-v0.14.0` 24 s |

**The view** (`VIEW LiveView`, in every configuration without a temporal property): TLC takes two
states as one when their views are equal, so a view is sound when it keeps everything any action or
property will still read. `LiveView` is the state without what no action and no invariant reads
again: a run's `at` (its `head_sha`, read only by `Approve` without `ListFromCommit` and by the count
of `RunsCounted = "all"`, so kept in those mutants); a wait's `el` once it has ended (a run never
waits again, and only `WaitBounded`'s `el <= WaitTicks` is kept); a failure's `why` but for whether
it is empty (all `WaitBounded` reads); and the checkout, the list and the `main` seen by a run that
is not in its tag job and has no tag (`Approve` writes them before they are read again;
`TagChecked`, `Includes` and `FreshList` read them only while it waits, pushes or has tagged). The
module says which action reads each. Every state the model reaches has one view in the run, the
invariants are functions of the view, and two states with one view have successors with one view
each, so the run sees what the model has; it has 8 to 25 times fewer states. Every action TLC
takes without the view it takes with it, and every expression it evaluates without it it evaluates
with it (`-coverage`, in the three configurations); in `-merges` a pending run's start
(`StartPending`) finds no state of its own any more, as the run it starts is one created when the
group was free, but for its `at`. Every mutant still fails with its property under the view. A bug in a field the view leaves out is still found: `Approve` reading the list
from `at` whatever `ListFromCommit` says, in `ReleasePipeline.cfg`, fails `FreshList` with the view
(5,907 states) as without it (1,048). Liveness has no view (TLC's reduction of it is unsound for
temporal properties), and is in two configurations, one property each: `TagJobEnds` and
`DeployEnds` together took 1 min 8 s, each alone half of it, as TLC checks each property's tableau
branches (two each, four together) beside every state, and the two run in different CI parts.

A merge before the first run is needed for it to have anything to release, so the one-merge
configurations cover a rename between a run's creation and its wait, and `-merges` one while a tag
job waits (`main` moved: the push refused). Two merges with two runs, a lost run and a failure
were stopped unfinished at 9 million states (3 minutes, no error, without the third push run) and
are left out of CI; a third version run is what gives the cancellation of a pending run, and two
runs what gives two releases. TLC reaches the fast fail in both waits under these bounds (in the
tag job on the commit its run was made at, and in the deploy job), which it did not before 85dc4e8.

**Mutants and the finding**, each of which TLC must reject with the property its first line names
(`tlc.sh` fails if it does not; a temporal property, which TLC does not name, is checked alone):

- `ReleasePipeline-own-run.cfg`, `wait-for-checks.sh` as #408 had it before 85dc4e8, counting
  every run on the commit, the waiting job's own among them (`RunsCounted = "all"`): `FastFail`,
  in 12 states. This model found it: a merge; a scheduled run made at it; the commit's `ci` run
  created and passed, its `proofs` run never created, the other run passed; the check job finds
  something to release; the approval; the tag job checks out the commit its run was made at; a poll
  inside the grace; the next finds `proofs`' check missing and every other run finished but its own,
  and goes on to the deadline.
- `ReleasePipeline-no-fast-fail.cfg`, `wait-for-checks.sh` as before #408: a check that never
  started holds the wait to its deadline. `FastFail`.
- `ReleasePipeline-inline-list.cfg`, the names inline in `version.yml` as before #408 (the run's own
  file, from `main` when the run was made): a rename merged before the approval is waited for under
  its old name. `FreshList`, in 6 states.
- `ReleasePipeline-v0.14.0.cfg`, the deploy job's `if:` as v0.14.0 had it, the implicit
  `success()`: Binaries (check) is skipped on a tag, so the deploy is skipped and the release ends
  green, never deployed and failing nowhere. `DeployEnds`.
- `ReleasePipeline-non-atomic.cfg`, the push without `--atomic`: when `main` moved since the
  checkout, its update is refused and the tag goes, on a commit off `main`. `TagOnMain`.
- `ReleasePipeline-other-wf.cfg`, a finding about the design rather than a bug: `FastFailOnChecks`,
  in 11 states. The fast fail waits for every run but the waiting workflows', so a run that reports
  no check holds it after `ci`'s and `proofs`' have finished: the trace is the one above with the
  other run still queued at the poll past the grace, and the wait goes on. Such a run ends (CodeQL's
  job within 30 minutes, scorecard's 15), so the cost is a later fast fail, and the deadline when a
  scheduled `analysis.yml` run made at the commit runs longer than the wait. Counting only `ci.yml`'s
  and `proofs.yml`' runs instead would have it, but would need the list of producing workflows kept
  in step, and would see no run at all when both were lost. If the script changes to that, this
  configuration fails CI and goes.

Under the weaker reading of the concurrency docs, two tag jobs can run at once, and everything else
still holds: the atomic push, not the group, keeps a tag on `main` and checked (the second push is
refused, or the second tag job finds nothing to release).

**Not modelled**: GitHub's own bugs (a check run reported wrong, a lost approval, an API that
lies rather than fails: a failed request counts as a poll with nothing found, which the model's
"not yet" covers, and the fast fail's failed request counts as a run still open); runner
availability and queueing (a job that never gets a runner is a check still queued, which the
deadline covers); more than 100 runs on a commit (the query reads one page); `skip_main_checks` (a
dispatch that tags without the wait, on purpose); re-runs of a failed check (the wait has failed by
then; the README says run `version` again); the bump `next-version.sh` computes (only whether there
is one); the deploy agent on razorbill and its report; `release.yml` by hand (a rebuild); jobs' own
`timeout-minutes` beyond the wait's (45 against 30 and 40); and real time: the grace is an
assumption that GitHub creates a push's runs within `GRACE_SECONDS` (`CanPoll`), and a run that is
created later than that is a lost one to the model.

## Why the regex matcher terminates

`Runner/Regex.lean` is about a different part of the runner: the backtracking matcher that problem
matchers need (`runner/src/regex.zig`). Backtracking does not terminate for free — a loop whose body
matches the empty string repeats at one position for ever — and the engine stops that with two
instructions, `mark` recording where an iteration began and `progress` leaving the loop when the
iteration consumed nothing.

| What | Statement |
|---|---|
| `Regex.bounded` | `iterations r + pos ≤ n` — the iterations taken plus the starting position cannot exceed the input |
| `Regex.bounded_from_zero` | so a loop over the whole input runs at most `n` times |
| `Regex.bounded_back` | the same backwards: a loop inside a lookbehind, matched right to left as .NET does, runs at most as many times as the position it started from |
| `Regex.stall`, `Regex.unbounded` | weaken the strict advance to `pos ≤ pos'` and runs of *every* length exist, so no bound can hold |

So the step budget in the engine is a safety net, not the reason it stops. And `stall` is the shape
of a bug that shipped twice: the guard was missing on stars (38 patterns reached the budget that
Python answers) and then missing on *bounded* repeats (an empty iteration followed by a non-empty one
captured the wrong text). Both were found by the differential test that checks the engine against
Python's `re` and Perl on patterns generated from the grammar it claims to accept (here
`.github/scripts/regex-diff.sh`) — the proof says why the fix is the right one, the test says the
fix is actually there.

## `hashFiles()`: the walk

`Glob/Match.lean` models minimatch's `matchOne` as `runner/src/glob.zig` has it, for any segment
matcher, and `Glob/Walk.lean` the directory walk that `hashFiles()` does.

| What | Statement |
|---|---|
| `Glob.partial_of_match` | partial matching never wrongly says no: if a path below a directory matches, the directory partially matches, so the walk is right to skip what partial matching rejects |
| `Glob.walk_eq_full` | the pruned walk yields exactly what the full walk does — the same files, in the same order — for any patterns and any tree |

`.github/scripts/glob-lean-diff.sh` ties the model to the code that ships: `globoracle`
(`Oracle.lean`) runs the walk `Glob.walk_eq_full` is proved of, and the script compares its answers
with `runner/src/glob.zig`'s on random trees and pattern sets.

## Formulation changes in the port

Every Agda theorem, lemma and counterexample has a Lean counterpart with the same meaning. Where the
encoding differs:

- **Parameterised modules.** `Runner.Build (vol) (exec)`, `Runner.OutputKeys (vol) (exec)` and
  `Runner.Enforce (vol)` become section variables, so the definitions take them as their first
  explicit arguments (`build vol exec md t p job`), and the counterexamples apply them directly
  instead of `module V = B vol execV`.
- **`Set` used as a proposition becomes `Prop`.** `Honest`, `Coherent`, `Ahead`, `Disciplined`,
  `Warm`, `Numbered`, `Clean`, `Subset`, `Elsewhere`, `Nonced` and `AllPlain` are `Prop`s; the Agda
  `Σ` in them and in `look-found` is `∃`, `⊎` is `∨`, `⊤`/`⊥` are `True`/`False`. `Run` and
  `Stalling` stay `Type`-valued so `iterations` can count them, and `unbounded`'s `Σ` is a
  `Subtype`, so the run is still data.
- **`All P xs`** is `∀ x ∈ xs, P x`, in `keys_stay_nonced`, `no_cutoff_without_keys` and `AllPlain`.
- **Decidable equality.** `_≟Script_`, `_≟State_`, `_≟Key_`, `_≟Env_` and the prelude's `_≟ℕ_`,
  `×-dec`, `List-dec` are derived or core `DecidableEq` instances; `with x ≟ y` is `if x = y`.
  The counterexamples compute through them with `rfl` and `decide`; the Agda's absurd pattern `()`
  on a concrete equation is `by decide` on `≠`.
- **The prelude** is Lean core (`Runner/Prelude.lean` has the mapping); `filter-idempotent`,
  `≤-loosen`, `suc≰`, `+-mono`, `+-zero` and `+-suc` keep Agda-named copies. Lean's `+` recurses on
  the right, so `+-zero`/`+-suc` are definitional and `bounded` uses `omega` for the rearrangement
  Agda got by reduction.
- **Renames forced by Lean.** `Nonced.below` is `Nonced.beneath` (Lean reserves `below`); `_∈?_` is
  `mem?`, with a scoped `∈?` notation; `true≢false` is `true_ne_false`. `OutputKeys.parent_inputFor`
  is one lemma for what the Agda did with a local `parent-nonced` split on the mark at each use.

## Changes since the port

The model has changed since the Agda port, to cover the runner's fixes for #68, #69 and #71 (#89).
Every theorem of the port is still here; some take more arguments or hypotheses:

- **`Output.code`**, the exit code, and **`Build.replayable`**: a hit counts only if it succeeded.
  `stepOnce` looks the key up through it; `step_ok` takes `replayable (look …) = r`; `Warm` and
  `hit_keeps_ran` are about `replayable` hits; `recorded_not_run` needs what the cache holds for the
  key to have succeeded (otherwise it runs, `recorded_failure_runs`). `Counterexamples.Flaky` now
  passes in job 1 and fails in job 2, which the replay still hides.
- **A failed marked step is not output-keyed** (`nextState`), as `execScript` asks `out.code == 0`.
  So `cutoff` needs the marked step to have succeeded, and `cutoff_needs_only_the_digest` both runs.
- **`Input.event`, `Progress.event`, `Step.readsEvent`**: the event payload, outside the key, and
  whether a script reads it. `inputFor`, `nextState`, `uncached`, `keysFrom`, `Replays`,
  `marked_misses`, `unmarked_replays` and the Enforce definitions take the payload as an argument;
  `mark` marks a step that reads it.
- **The rerun of a recorded failure** is modelled as a miss under the step's own mark, not stamped
  as the runner does it. With the stamp, the rerun's result would be recorded under a key no input
  of the unstamped step has, the next container would differ from `uncached`'s in identity though
  not in content, and P1 against `uncached` could not be stated without a notion of content the
  model does not have. What the simplification changes is which keys are recorded and asked — hits
  and misses — not what any step produces.
