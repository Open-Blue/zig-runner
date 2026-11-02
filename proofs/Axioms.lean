import Lean
import Runner
import Glob

/-!
# The axioms gate

`lake env lean -DwarningAsError=true Axioms.lean`, after `lake build`, fails unless every
declaration in the `Runner` and `Glob` libraries depends on no axiom outside `allowed`, and no axiom
is declared in them. It prints `#print axioms` for each of `mainTheorems`, the theorems
proofs/README.md names as the claims; each is written with a double backtick, so a renamed or
removed one fails here instead of dropping out.

A new axiom on the list is a reviewed change to this file, never a side effect of a proof: `sorryAx`
(a `sorry`, which `lake build --wfail` already refuses), `Lean.ofReduceBool` (`native_decide`,
which trusts the compiler) and `Lean.trustCompiler` are not on it.
-/

open Lean Elab Command

/-- What the proofs rely on today: propositional extensionality and quotient soundness, the two
axioms `simp`, `funext` and quotients bring in. -/
def allowed : List Lean.Name := [``propext, ``Quot.sound]

/-- The libraries the gate covers: every declaration in a module under one of these. -/
def libraries : List Lean.Name := [`Runner, `Glob]

/-- The main theorems, as proofs/README.md's tables name them. -/
def mainTheorems : List Lean.Name := [
  -- The step cache on the Dagger backend: P1–P6, failures, logs, pruning, a shared cache.
  ``Runner.Build.replay_eq_run,
  ``Runner.Build.replayed_succeeds,
  ``Runner.Build.recorded_failure_runs,
  ``Runner.Build.replay_logs_eq_run,
  ``Runner.Build.text_matters,
  ``Runner.Build.position_matters,
  ``Runner.Build.parent_matters,
  ``Runner.Build.stable_env_matters,
  ``Runner.Build.mounts_invisible,
  ``Runner.Build.volatile_invisible,
  ``Runner.Build.event_invisible,
  ``Runner.Build.marked_misses,
  ``Runner.Build.hit_keeps_ran,
  ``Runner.Build.warm_runs_nothing,
  ``Runner.Build.recorded_not_run,
  ``Runner.Build.step_runs_at_most_once,
  ``Runner.Build.coherent_subset,
  ``Runner.Build.ahead_subset,
  ``Runner.Build.elsewhere_ahead,
  ``Runner.Logs.replay_merged,
  ``Runner.Logs.live_merged,
  ``Runner.Declared.undeclared_absent,
  ``Runner.Declared.enforced_depends_only_on_the_declaration,
  ``Runner.OutputKeys.cutoff,
  ``Runner.OutputKeys.cutoff_needs_only_the_digest,
  ``Runner.OutputKeys.no_cutoff_without_keys,
  ``Runner.OutputKeys.failure_is_a_wall,
  ``Runner.OutputKeys.different_bytes_different_container,
  -- The volatile clause, discharged, and P1 under enforcement.
  ``Runner.Enforce.replay_eq_run_enforced,
  ``Runner.Enforce.input_determined_by_key,
  ``Runner.Enforce.volatile_clause_discharged,
  ``Runner.Enforce.nothing_volatile_survives,
  ``Runner.Enforce.no_payload_survives,
  ``Runner.Enforce.enforced_disciplined,
  -- The native backend (P8): P1, the key, trust scopes, concurrency, layer digests.
  ``Runner.Native.native_replay_eq_run,
  ``Runner.Native.native_eq_dagger,
  ``Runner.Native.scope_apart,
  ``Runner.Native.userns_apart,
  ``Runner.Native.fork_keys_apart,
  ``Runner.Native.encState_injective,
  ``Runner.Native.belowPreimage_inj,
  ``Runner.Native.belowTail_inj,
  ``Runner.Native.encKey_injective,
  ``Runner.Native.native_key_iff,
  ``Runner.Native.native_mounts_invisible,
  ``Runner.Native.native_volatile_invisible,
  ``Runner.Native.native_event_invisible,
  ``Runner.Native.ops_keep_honest,
  ``Runner.Native.race_irrelevant,
  ``Runner.Native.readWhole_agrees,
  ``Runner.Native.walk_injective,
  ``Runner.Native.digest_deterministic,
  ``Runner.Native.digest_injective,
  ``Runner.Native.same_layer_same_container,
  ``Runner.Native.different_layer_different_container,
  -- The regex matcher terminates.
  ``Runner.Regex.bounded,
  ``Runner.Regex.bounded_from_zero,
  ``Runner.Regex.bounded_back,
  ``Runner.Regex.stall_length,
  -- hashFiles(): the walk.
  ``Glob.partial_of_match,
  ``Glob.walk_eq_full
]

def axiomsText (axs : Array Lean.Name) : String :=
  if axs.isEmpty then "none" else ", ".intercalate (axs.toList.map toString)

run_cmd do
  let env ← getEnv
  let mut checked : Nat := 0
  let mut bad : Nat := 0
  for h : i in [0:env.header.moduleNames.size] do
    let mod := env.header.moduleNames[i]
    unless libraries.any (·.isPrefixOf mod) do continue
    for c in env.header.moduleData[i]!.constNames do
      checked := checked + 1
      if let some (.axiomInfo _) := env.find? c then
        logError m!"{mod} declares the axiom {c}"
        bad := bad + 1
      let outside := (← collectAxioms c).filter (!allowed.contains ·)
      unless outside.isEmpty do
        logError m!"{c} ({mod}) depends on {axiomsText outside}, outside the allow list"
        bad := bad + 1
  let mut table := ""
  for t in mainTheorems do
    unless env.find? t matches some (.thmInfo _) do
      logError m!"{t} is not a theorem"
      bad := bad + 1
    table := table ++ s!"{t}: {axiomsText ((← collectAxioms t).qsort Lean.Name.lt)}\n"
  logInfo m!"{table}{checked} declarations in {libraries}, {mainTheorems.length} main theorems; \
    allowed: {axiomsText allowed.toArray}"
  if checked == 0 then logError "no declarations found: is the build missing?"
  if bad != 0 then logError m!"{bad} problem(s): see above"
