# The proofs, in Lean

Audience: whoever changes the caching, the regex matcher or `hashFiles()`, or doubts them ·
Companion: [MEASURE.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/MEASURE.md),
[CLAIMS.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/CLAIMS.md),
[RELATED.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/RELATED.md),
[SPEC.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/SPEC.md) §6

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

## The step cache

[MEASURE.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/MEASURE.md) §4 lists
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
[SPEC.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/SPEC.md) §9, the first
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
  [RELATED.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/RELATED.md) noted we
  had never measured flakiness; this says measuring it needs the cache off.
- **The documented gap is a correctness gap.**
  [SPEC.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/SPEC.md) §6 already
  says a script that reads run-specific values from a file in the repository is "not detected".
  Counterexample 1 shows what that costs: not a slower job, a wrong one.

### Obligations for the harness

What a proof of a property buys is a *test that is worth generating*: the model says which cases
matter and what must hold in each, so
[MEASURE.md](https://github.com/Lementknight/zig-actions-runner/blob/main/docs/MEASURE.md) stage 3
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
atomic publish is what justifies — Dagger's output store's first-writer-wins `mv -T` is not
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
| `Key` | The real key holds more: cache volume identities (the `cacheVolume(key:)` string, so the repository and the trust scope, with the mount path and owner), the helper and runtime image addresses, action code, user and directory, the nesting flag, secret variables, the file-command paths | Only extra misses, so safe. A job the trust gate (#105) moves between `repo` and `untrusted` mounts other volumes, so every step of it misses once (no measured figure; the cold run in BENCHMARKS.md is a full wipe, not this). The provisioned base container every step descends from is built before the cache mounts, so it is shared across `repo` and `untrusted`: today's one cross-scope seed, from the image tag and the provisioning script, never from a job's output. The runner passes no `source:`. The Zig seed is mounted as a directory (not a volume) at Zig's global cache, so its Directory ID is in every Zig step's key; it comes from a trusted, pinned input, never a job's output, and what a job writes there stays in that job's container | — |
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
