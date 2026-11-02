import Runner.Build

/-!
# The native backend's step cache (P8)

`Runner.Build` is the model; the Dagger backend refines it with the engine's own cache, and this
module is the native backend's refinement: the content-addressed layer store of
docs/native-backend.md, P2. Under Dagger, BuildKit and then DagQL computed the key and kept the
store, and the model only had to say what they keyed on. Natively the runner does both, so what the
engine discharged becomes the runner's obligation, and each one is stated and proved here:

* **The key is computed from exactly what the model says.** `keyPreimage` is what P2's store hashes
  (`Store.KeyHasher`, `Backend.keyFor`): a tag, the parent's key, the script text, the stable
  environment, then the uid, gid, working directory and kept files, each length-prefixed. A base has
  the digest below it (`Backend.below`: store format, trust scope, repository, rootfs, id mapping,
  binds, and the Zig cache seeds and which binds are cache volumes when there are any) in its
  parent's place. Not the slot: a stored layer has the canonical ids, which every slot's job sees as
  its own, so jobs in different slots share keys and layers. `fork_keys_apart`: a fork's pull request and the repository's
  own jobs never share a key. The
  extras are no new input: a base's are part of what the model's base is (`BaseSpec`), and a step's
  are its base's (`Format.stepExtra`), so determined by its key's parent. `encKey_injective` says no
  two model keys share bytes, so sha256 of them collides only when sha256 does (`native_key_iff`);
  the mounts, the volatile variables and the event payload are no argument of it
  (`native_mounts_invisible`, `native_volatile_invisible`, `native_event_invisible`). `Ambiguous`
  is the job where plain concatenation, without the lengths, hands one step another's answer.

* **A hit replays the stored entry, and only successes of unmarked steps are stored.** The store
  never publishes a failure (#69) or a marked step (whose key names the job, and whose log may hold
  a secret: P0's rule), so `SHonest` holds by construction and needs none of `Build`'s
  bookkeeping (`Ahead`, `Numbered`): `native_replay_eq_run` is P1 under `Disciplined` alone, against
  the same `uncached` as `Build.replay_eq_run`, whatever other runners publish or evict between the
  steps and whichever reads fail. `native_eq_dagger`: both backends give the same answers.

* **Concurrency.** A publish is one rename and a reader takes an entry whole or not at all, so the
  store changes by whole entries (`Op`); any interleaving of honest operations keeps it honest
  (`ops_keep_honest`). Which of two racing writers wins does not matter (`race_irrelevant`): the
  flock per key saves running a key twice, it is not what makes a replay right. `Torn` is a reader
  that defaults a missing part, and what it replays.

* **Eviction is a miss, and a miss is always safe**: `evict` only removes entries, and P1 holds for
  every pattern of lost reads (`lost` in `nbuild`).

* **Layer digests** (`layerDigest`): a sorted walk of what a later step can see of each file,
  nothing else. `digest_deterministic`: the same layer gives the same digest whatever order the
  directory was read in and whatever the times and inodes; `digest_injective`: different layers give
  different digests. Those are the two properties `OutputKeys.cutoff_needs_only_the_digest` and
  `OutputKeys.different_bytes_different_container` need of `Output.digest`.

The hash is modelled as the identity on its preimage, as `Key` is a projection in `Runner.Model`:
collisions stay out of scope, and what is left is the runner's own part, that the preimage is
unambiguous. The byte format is a parameter (`Format`), so the proofs hold of any word size and any
spelling of atoms, scripts and digests that satisfy `Format.Sound`; `KeyOracle.lean` instantiates it
with P2's format (u64 little-endian words, UTF-8) and writes the vectors that
runner/src/native/key_vectors.zig checks the Zig key against.
-/

namespace Runner.Native

open Runner Runner.Build

/-! ## The bytes a key is made of -/

/-- A byte string: what sha256 is given. A number per byte, as everything in the model is. -/
abbrev Bytes := List Nat

/-- A file written for an exec that stays in its layer (`sandbox.Spec.File` with `keep`): its path,
its contents and its mode. Only a base has one, the event file when the payload is too large for a
variable; a step with a file to write (a script holding a secret) has no key at all. -/
structure Kept where
  path : Nat
  contents : Nat
  mode : Nat
  deriving DecidableEq, Repr

/-- What the store hashes after the model's core (`Backend.keyFor`): the ids the exec runs as, its
working directory, and the files kept. -/
structure Extra where
  uid : Nat
  gid : Nat
  workdir : Nat
  files : List Kept
  deriving DecidableEq, Repr

/-- A bind into every step (`Backend.binds`): where from, where to, and how. Where, not what: a
mount's content is in no key. -/
structure Bind where
  host : Nat
  place : Nat
  readOnly : Bool
  optional : Bool
  deriving DecidableEq, Repr

/-- What every layer of a job depends on below its base (`Backend.below`): the store's format
(`Store.store_format`, bumped when what a layer or its record means changes), the trust scope
(`set_up.packageCacheScope`: `repo`, or `untrusted` for a fork's pull request or a job the runner
does not vouch for), the repository, the rootfs's fingerprint (`Store.rootfsFingerprint`), how ids
are mapped (the userns mode's name: a root runner's layers have the canonical ids, which every
slot's job sees as its own, a rootless one's are its user's, so the two never share a key), and the
binds; then, from P4, the Zig cache seeds' layers between the rootfs and the job's (by path) and,
per bind, whether it is a cache volume (`Bind.volume`), empty when none is. A job with neither has
the bytes it had before P4 (`belowTail`). -/
structure Below where
  format : Nat
  scope : Nat
  repository : Nat
  fingerprint : Nat
  userns : Nat
  binds : List Bind
  seeds : List Nat := []
  volumes : List Bool := []
  deriving DecidableEq, Repr

/-- A job's base as the store keys it (`Backend.base`): what lies below it, the script that makes the
workspace, the base's stable environment and its `Extra` (root, `/`, and the event file when the
payload is not a variable). The model's `State.base b` is this, named by `b`. -/
structure BaseSpec where
  below : Below
  script : Nat
  env : Env
  extra : Extra
  deriving DecidableEq, Repr

/-- How the store spells things: a fixed-width word for lengths, counts, tags and numbers; the
bytes of an atom (a variable's name or value, a path, a digest); a script's text, which
`scripts.stepScriptFc` builds and both backends hash; the label of the digest below a base
(`plain("below a base")`); what each base of the model is (`base`); and the `Extra` of the steps
above a base (`stepExtra`): a step runs as the job's user in the job's workspace, both set with the
base (`Backend.baseEnv`), and keeps no file. -/
structure Format where
  word : Nat → Bytes
  width : Nat
  str : Nat → Bytes
  text : Script → Bytes
  label : Bytes
  base : Nat → BaseSpec
  stepExtra : Nat → Extra

/-- What the proofs need of the spelling. `text_inj` is the one hypothesis the Dagger mapping has
too, unstated there: two scripts the model tells apart have different texts (the step's number and
file-command paths, and the always-run line with its nonce, are written into the text). `base_inj`
says the model's bases are the store's: two bases the model tells apart differ in something the
store hashes. For a u64 word, `word_inj` holds below 2^64, which is the size of the largest script
considered. -/
structure Format.Sound (f : Format) : Prop where
  word_width : ∀ n, (f.word n).length = f.width
  word_inj : ∀ {n m}, f.word n = f.word m → n = m
  str_inj : ∀ {a b}, f.str a = f.str b → a = b
  text_inj : ∀ {s s'}, f.text s = f.text s' → s = s'
  base_inj : ∀ {b b'}, f.base b = f.base b' → b = b'

/-- The base a container's chain starts from. -/
def root : State → Nat
  | .base b => b
  | .afterExec s _ _ => root s
  | .afterCopy s _ => root s

section
variable (f : Format)

/-- A length-prefixed field: no field is a prefix of another, so fields concatenate unambiguously. -/
def lp (bs : Bytes) : Bytes := f.word bs.length ++ bs

/-- A list's items one after another (its count goes before it). -/
def encList {α : Type} (g : α → Bytes) : List α → Bytes
  | [] => []
  | a :: as => g a ++ encList g as

def encBinding (b : Binding) : Bytes := lp f (f.str b.1) ++ lp f (f.str b.2)

def encBindings : Env → Bytes
  | [] => []
  | b :: e => encBinding f b ++ encBindings e

/-- An environment: its count, then each name and value in the order the container has them, which
is the order the step sees in its environment. -/
def encEnv (e : Env) : Bytes := f.word e.length ++ encBindings f e

def encBool (x : Bool) : Bytes := f.word (if x then 1 else 0)

def encKept (k : Kept) : Bytes := lp f (f.str k.path) ++ (lp f (f.str k.contents) ++ f.word k.mode)

/-- `keyFor`'s tail: uid, gid, the working directory, then the count of kept files and each one's
path, contents and mode. -/
def encExtra (x : Extra) : Bytes :=
  f.word x.uid ++ (f.word x.gid ++ (lp f (f.str x.workdir) ++
    (f.word x.files.length ++ encList (encKept f) x.files)))

def encBind (b : Bind) : Bytes :=
  lp f (f.str b.host) ++ (lp f (f.str b.place) ++ (encBool f b.readOnly ++ encBool f b.optional))

/-- What follows the binds below a base: nothing for a job with no seed and no volume, else the
seeds, counted, and the volume flags, counted. -/
def belowTail (seeds : List Nat) (volumes : List Bool) : Bytes :=
  if seeds = [] ∧ volumes = [] then [] else
    f.word seeds.length ++ (encList (fun s => lp f (f.str s)) seeds ++
      (f.word volumes.length ++ encList (encBool f) volumes))

/-- **The digest below a base** (`Backend.below`), untagged (`KeyHasher.plain`): the label, the
store's format, the scope, the repository, the rootfs's fingerprint, the userns mode, the binds,
counted, and the tail (`belowTail`). -/
def belowPreimage (w : Below) : Bytes :=
  lp f f.label ++ (lp f (f.str w.format) ++ (lp f (f.str w.scope) ++ (lp f (f.str w.repository) ++
    (lp f (f.str w.fingerprint) ++ (lp f (f.str w.userns) ++
    (f.word w.binds.length ++ (encList (encBind f) w.binds ++
      belowTail f w.seeds w.volumes)))))))

/-- **What the store hashes for a key** (`KeyHasher.init(tag)`, `core`, then `keyFor`'s tail): the
tag, the parent's key, the script's text, the stable environment, then the `Extra`. -/
def keyPreimage (tag : Nat) (parent script : Bytes) (e : Env) (x : Extra) : Bytes :=
  f.word tag ++ (lp f parent ++ (lp f script ++ (encEnv f e ++ encExtra f x)))

/-- A container's key, as the store spells it before hashing. A base is tag 0, over the digest below
it in the parent's place; a step's container (a `run:` step's exec or a checkout's fetch) is tag 1,
its parent's key, its script, its stable environment and its base's `stepExtra`; an output-keyed
container is tag 2, its parent's key and the digest of the layer copied in. Each parent's key is a
field of its own, where the real store has the 32 bytes of the parent's sha256 (`stepPreimage`). -/
def encState : State → Bytes
  | .base b => keyPreimage f 0 (belowPreimage f (f.base b).below) (f.str (f.base b).script)
      (f.base b).env (f.base b).extra
  | .afterExec s sc e => keyPreimage f 1 (encState s) (f.text sc) e (f.stepExtra (root s))
  | .afterCopy s c => f.word 2 ++ (lp f (encState s) ++ lp f (f.str c))

/-- A step's key is its container's: the key of the exec and the identity of what it leaves are the
same bytes, as `stateOf` says they are the same information. -/
def encKey (k : Key) : Bytes := encState f (stateOf k)

/-- What the native store hashes for a step, given its parent's key as bytes (in the store, the
parent's sha256). `KeyOracle.lean` and runner/src/native/key_vectors.zig compute this. -/
def stepPreimage (parent : Bytes) (sc : Script) (e : Env) (x : Extra) : Bytes :=
  keyPreimage f 1 parent (f.text sc) e x

/-- The model's key is `stepPreimage` with the parent's preimage where the store has its hash, and
the extras of the job's base: they are determined by the key's parent. -/
theorem encKey_stepPreimage (k : Key) :
    encKey f k = stepPreimage f (encState f k.kParent) k.kScript k.kEnv (f.stepExtra (root k.kParent)) :=
  rfl

/-- The native key of a step's input: the model's `keyOf`, spelt out. -/
def nativeKey (vol : Volatile) (i : Input) : Bytes := encKey f (keyOf vol i)

variable {f}

theorem Format.Sound.word_split (h : f.Sound) {n m : Nat} {r s : Bytes}
    (e : f.word n ++ r = f.word m ++ s) : n = m ∧ r = s := by
  obtain ⟨w, rs⟩ := List.append_inj e (by rw [h.word_width, h.word_width])
  exact ⟨h.word_inj w, rs⟩

theorem lp_split (h : f.Sound) {x y r s : Bytes} (e : lp f x ++ r = lp f y ++ s) :
    x = y ∧ r = s := by
  simp only [lp, List.append_assoc] at e
  obtain ⟨hl, e'⟩ := h.word_split e
  exact List.append_inj e' hl

theorem lp_inj (h : f.Sound) {x y : Bytes} (e : lp f x = lp f y) : x = y :=
  (lp_split h (r := []) (s := []) (by simpa using e)).1

/-- Items that split off a stream one at a time split a list of them off, given its count. -/
theorem list_split {α : Type} {g : α → Bytes}
    (hg : ∀ {a a' : α} {r s : Bytes}, g a ++ r = g a' ++ s → a = a' ∧ r = s) :
    ∀ {as as' : List α} {r s : Bytes}, as.length = as'.length →
      encList g as ++ r = encList g as' ++ s → as = as' ∧ r = s
  | [], [], _, _, _, eq => ⟨rfl, by simpa [encList] using eq⟩
  | [], _ :: _, _, _, hl, _ => absurd hl.symm (Nat.succ_ne_zero _)
  | _ :: _, [], _, _, hl, _ => absurd hl (Nat.succ_ne_zero _)
  | _ :: _, _ :: _, _, _, hl, eq => by
    simp only [encList, List.append_assoc] at eq
    obtain ⟨ha, eq⟩ := hg eq
    obtain ⟨has, hr⟩ := list_split hg (Nat.succ.inj hl) eq
    exact ⟨by rw [ha, has], hr⟩

theorem bindings_split (h : f.Sound) :
    ∀ {e e' : Env} {r s : Bytes}, e.length = e'.length →
      encBindings f e ++ r = encBindings f e' ++ s → e = e' ∧ r = s
  | [], [], _, _, _, eq => ⟨rfl, by simpa [encBindings] using eq⟩
  | [], _ :: _, _, _, hl, _ => absurd hl.symm (Nat.succ_ne_zero _)
  | _ :: _, [], _, _, hl, _ => absurd hl (Nat.succ_ne_zero _)
  | (a, c) :: e, (a', c') :: e', _, _, hl, eq => by
    simp only [encBindings, encBinding, List.append_assoc] at eq
    obtain ⟨ha, eq⟩ := lp_split h eq
    obtain ⟨hc, eq⟩ := lp_split h eq
    obtain ⟨he, hr⟩ := bindings_split h (Nat.succ.inj hl) eq
    exact ⟨by rw [h.str_inj ha, h.str_inj hc, he], hr⟩

theorem encEnv_split (h : f.Sound) {e e' : Env} {r s : Bytes}
    (eq : encEnv f e ++ r = encEnv f e' ++ s) : e = e' ∧ r = s := by
  simp only [encEnv, List.append_assoc] at eq
  obtain ⟨hl, eq⟩ := h.word_split eq
  exact bindings_split h hl eq

theorem encEnv_inj (h : f.Sound) {e e' : Env} (eq : encEnv f e = encEnv f e') : e = e' :=
  (encEnv_split h (r := []) (s := []) (by simpa using eq)).1

theorem bool_split (h : f.Sound) {x y : Bool} {r s : Bytes}
    (e : encBool f x ++ r = encBool f y ++ s) : x = y ∧ r = s := by
  obtain ⟨hx, hr⟩ := h.word_split e
  refine ⟨?_, hr⟩
  cases x <;> cases y <;> first | rfl | exact absurd hx (by decide)

theorem kept_split (h : f.Sound) {k k' : Kept} {r s : Bytes}
    (e : encKept f k ++ r = encKept f k' ++ s) : k = k' ∧ r = s := by
  obtain ⟨p, c, m⟩ := k
  obtain ⟨p', c', m'⟩ := k'
  simp only [encKept, List.append_assoc] at e
  obtain ⟨hp, e⟩ := lp_split h e
  obtain ⟨hc, e⟩ := lp_split h e
  obtain ⟨hm, hr⟩ := h.word_split e
  exact ⟨by rw [h.str_inj hp, h.str_inj hc, hm], hr⟩

theorem bind_split (h : f.Sound) {b b' : Bind} {r s : Bytes}
    (e : encBind f b ++ r = encBind f b' ++ s) : b = b' ∧ r = s := by
  obtain ⟨o, p, ro, op⟩ := b
  obtain ⟨o', p', ro', op'⟩ := b'
  simp only [encBind, List.append_assoc] at e
  obtain ⟨ho, e⟩ := lp_split h e
  obtain ⟨hp, e⟩ := lp_split h e
  obtain ⟨hro, e⟩ := bool_split h e
  obtain ⟨hop, hr⟩ := bool_split h e
  exact ⟨by rw [h.str_inj ho, h.str_inj hp, hro, hop], hr⟩

theorem encExtra_inj (h : f.Sound) {x x' : Extra} (e : encExtra f x = encExtra f x') : x = x' := by
  obtain ⟨u, g, w, fs⟩ := x
  obtain ⟨u', g', w', fs'⟩ := x'
  simp only [encExtra] at e
  obtain ⟨hu, e⟩ := h.word_split e
  obtain ⟨hg, e⟩ := h.word_split e
  obtain ⟨hw, e⟩ := lp_split h e
  obtain ⟨hl, e⟩ := h.word_split e
  obtain ⟨hfs, _⟩ := list_split (kept_split h) hl (r := []) (s := []) (by simpa using e)
  rw [hu, hg, h.str_inj hw, hfs]

theorem seed_split (h : f.Sound) {a a' : Nat} {r s : Bytes}
    (e : lp f (f.str a) ++ r = lp f (f.str a') ++ s) : a = a' ∧ r = s := by
  obtain ⟨ha, hr⟩ := lp_split h e
  exact ⟨h.str_inj ha, hr⟩

theorem Format.Sound.word_ne_nil (h : f.Sound) (n : Nat) : f.word n ≠ [] := by
  intro e
  have nil : ∀ k, f.word k = [] := fun k => by
    rw [← List.length_eq_zero_iff, h.word_width, ← h.word_width n, e, List.length_nil]
  exact absurd (h.word_inj ((nil 0).trans (nil 1).symm)) (by decide)

/-- The tail is unambiguous: none for a job with neither seeds nor volumes, and else counted. -/
theorem belowTail_inj (h : f.Sound) {sd sd' : List Nat} {v v' : List Bool}
    (e : belowTail f sd v = belowTail f sd' v') : sd = sd' ∧ v = v' := by
  unfold belowTail at e
  by_cases c : sd = [] ∧ v = []
  · by_cases c' : sd' = [] ∧ v' = []
    · exact ⟨c.1.trans c'.1.symm, c.2.trans c'.2.symm⟩
    · rw [ite_eq_left c, ite_eq_right c'] at e
      exact absurd e.symm (by simp [h.word_ne_nil])
  · by_cases c' : sd' = [] ∧ v' = []
    · rw [ite_eq_right c, ite_eq_left c'] at e
      exact absurd e (by simp [h.word_ne_nil])
    rw [ite_eq_right c, ite_eq_right c'] at e
    obtain ⟨hl, e⟩ := h.word_split e
    obtain ⟨hsd, e⟩ := list_split (seed_split h) hl e
    obtain ⟨hvl, e⟩ := h.word_split e
    obtain ⟨hv, _⟩ := list_split (bool_split h) hvl (r := []) (s := []) (by simpa using e)
    exact ⟨hsd, hv⟩

/-- **The digest below a base is unambiguous**: equal preimages, the same store format, scope,
repository, rootfs, mapping, binds, seeds and volume flags. -/
theorem belowPreimage_inj (h : f.Sound) {w w' : Below} (e : belowPreimage f w = belowPreimage f w') :
    w = w' := by
  obtain ⟨fm, sc, rp, fp, u, bs, sd, v⟩ := w
  obtain ⟨fm', sc', rp', fp', u', bs', sd', v'⟩ := w'
  simp only [belowPreimage] at e
  obtain ⟨_, e⟩ := lp_split h e
  obtain ⟨hfm, e⟩ := lp_split h e
  obtain ⟨hsc, e⟩ := lp_split h e
  obtain ⟨hrp, e⟩ := lp_split h e
  obtain ⟨hfp, e⟩ := lp_split h e
  obtain ⟨hu, e⟩ := lp_split h e
  obtain ⟨hl, e⟩ := h.word_split e
  obtain ⟨hbs, e⟩ := list_split (bind_split h) hl e
  obtain ⟨hsd, hv⟩ := belowTail_inj h e
  rw [h.str_inj hfm, h.str_inj hsc, h.str_inj hrp, h.str_inj hfp, h.str_inj hu, hbs, hsd, hv]

theorem tag_ne (h : f.Sound) {n m : Nat} {r s : Bytes} (ne : n ≠ m) : f.word n ++ r ≠ f.word m ++ s :=
  fun e => ne (h.word_split e).1

/-- **No two containers share a key's bytes.** The tags keep the three kinds apart, the lengths
keep each field's bytes from running into the next's, and a base's fields are its `BaseSpec`. The
`Extra` of a step is its base's, so it adds bytes but never parts two keys the model keeps
together. -/
theorem encState_injective (h : f.Sound) : ∀ {s s' : State}, encState f s = encState f s' → s = s'
  | .base b, .base b', e => by
    simp only [encState, keyPreimage] at e
    obtain ⟨hw, e⟩ := lp_split h (h.word_split e).2
    obtain ⟨hsc, e⟩ := lp_split h e
    obtain ⟨he, e⟩ := encEnv_split h e
    have hx := encExtra_inj h e
    have hb : f.base b = f.base b' := by
      revert hw hsc he hx
      cases f.base b; cases f.base b'
      intro hw hsc he hx
      simp only at hw hsc he hx
      rw [belowPreimage_inj h hw, h.str_inj hsc, he, hx]
    rw [h.base_inj hb]
  | .afterExec s sc en, .afterExec s' sc' en', e => by
    simp only [encState, keyPreimage] at e
    obtain ⟨hs, e⟩ := lp_split h (h.word_split e).2
    obtain ⟨hsc, e⟩ := lp_split h e
    rw [encState_injective h hs, h.text_inj hsc, (encEnv_split h e).1]
  | .afterCopy s c, .afterCopy s' c', e => by
    simp only [encState] at e
    obtain ⟨hs, e⟩ := lp_split h (h.word_split e).2
    rw [encState_injective h hs, h.str_inj (lp_inj h e)]
  | .base _, .afterExec _ _ _, e => by
    simp only [encState, keyPreimage] at e; exact absurd e (tag_ne h (by decide))
  | .base _, .afterCopy _ _, e => by
    simp only [encState, keyPreimage] at e; exact absurd e (tag_ne h (by decide))
  | .afterExec _ _ _, .base _, e => by
    simp only [encState, keyPreimage] at e; exact absurd e (tag_ne h (by decide))
  | .afterExec _ _ _, .afterCopy _ _, e => by
    simp only [encState, keyPreimage] at e; exact absurd e (tag_ne h (by decide))
  | .afterCopy _ _, .base _, e => by
    simp only [encState, keyPreimage] at e; exact absurd e (tag_ne h (by decide))
  | .afterCopy _ _, .afterExec _ _ _, e => by
    simp only [encState, keyPreimage] at e; exact absurd e (tag_ne h (by decide))

theorem encKey_injective (h : f.Sound) {k k' : Key} (e : encKey f k = encKey f k') : k = k' := by
  have hs := encState_injective h e
  cases k; cases k'
  simp only [stateOf, State.afterExec.injEq] at hs
  obtain ⟨rfl, rfl, rfl⟩ := hs
  rfl

/-- **Scopes never share a container.** Two containers whose bases are in different trust scopes
have different keys, however alike everything else is: the scope is below every base, so in every
key above it. -/
theorem scope_apart (h : f.Sound) {s s' : State}
    (ne : (f.base (root s)).below.scope ≠ (f.base (root s')).below.scope) :
    encState f s ≠ encState f s' :=
  fun e => ne (by rw [encState_injective h e])

/-- **Root and rootless runners never share a container.** A root runner's stored layers have the
canonical ids (0 to 65535, seen through each job's own range of host ids, whichever slot it has), a
rootless runner's are owned by its one user: the userns mode is below every base, so two containers
whose bases differ in it have different keys. The slot is in no key, so jobs in different slots of
one root runner share every layer (docs/native-backend.md, "A layer has the canonical ids"). -/
theorem userns_apart (h : f.Sound) {s s' : State}
    (ne : (f.base (root s)).below.userns ≠ (f.base (root s')).below.userns) :
    encState f s ≠ encState f s' :=
  fun e => ne (by rw [encState_injective h e])

/-- **A fork's pull request keys its layers apart.** A step of a job in the `untrusted` scope (a
fork's pull request, or a job the runner does not vouch for) and one in `repo` never ask the same
key, so neither ever replays what the other stored: a fork cannot plant a layer, a log or file
commands that the repository's own jobs then replay, and the repository's layers are never handed
to a fork. -/
theorem fork_keys_apart (h : f.Sound) (vol : Volatile) {i j : Input}
    (ne : (f.base (root i.parent)).below.scope ≠ (f.base (root j.parent)).below.scope) :
    encKey f (keyOf vol i) ≠ encKey f (keyOf vol j) :=
  scope_apart h ne

/-! ## P2 and P3 for the native key -/

variable (f)

/-- **The native key keeps exactly what the model's key keeps.** So every theorem of `Build` about
which inputs part keys (P2) or do not (P3) is a theorem about the native key. -/
theorem native_key_iff (h : f.Sound) (vol : Volatile) (i j : Input) :
    nativeKey f vol i = nativeKey f vol j ↔ K vol i = K vol j :=
  ⟨encKey_injective h, fun e => congrArg (encKey f) e⟩

/-- P2 natively: inputs whose model keys differ (`text_matters`, `position_matters`,
`parent_matters`, `stable_env_matters`) have different native keys. -/
theorem native_keys_differ (h : f.Sound) (vol : Volatile) {i j : Input} (ne : K vol i ≠ K vol j) :
    nativeKey f vol i ≠ nativeKey f vol j :=
  fun e => ne ((native_key_iff f h vol i j).1 e)

/-- P3 natively, by construction: the mounts are no argument of the key. P4's cache volumes are
host directories bound in, and their content, unlike under Dagger their identity too, is in no key. -/
theorem native_mounts_invisible (vol : Volatile) {s : State} {sc : Script} {e : Env} {ev : Content}
    {m m' : Mounts} : nativeKey f vol ⟨s, sc, e, ev, m⟩ = nativeKey f vol ⟨s, sc, e, ev, m'⟩ :=
  rfl

/-- P3 natively: a volatile binding is filtered out before the environment is spelt. -/
theorem native_volatile_invisible (vol : Volatile) (n : Name) (c c' : Content) {e : Env} {s : State}
    {sc : Script} {ev : Content} {m m' : Mounts} (v : vol n = true) :
    nativeKey f vol ⟨s, sc, (n, c) :: e, ev, m⟩ = nativeKey f vol ⟨s, sc, (n, c') :: e, ev, m'⟩ :=
  congrArg (encKey f) (volatile_invisible vol n c c' v)

/-- P3 natively: the event payload is no argument of the key. -/
theorem native_event_invisible (vol : Volatile) {s : State} {sc : Script} {e : Env}
    {ev ev' : Content} {m : Mounts} :
    nativeKey f vol ⟨s, sc, e, ev, m⟩ = nativeKey f vol ⟨s, sc, e, ev', m⟩ :=
  rfl

end

/-! ## Without the lengths: one step handed another's answer

The obvious spelling, the fields one after another, is ambiguous: a script `x` with `Y=1` in its
environment and a script `xY=1` with nothing are the same bytes. Concretely, with ASCII for the
bytes. -/

namespace Ambiguous

/-- The fields concatenated, a name and its value joined by `=`. -/
def naive (parent : Bytes) (script : Bytes) (e : List (Bytes × Bytes)) : Bytes :=
  parent ++ script ++ e.flatMap (fun b => b.1 ++ [61] ++ b.2)

def x : Bytes := [120]
def Y : Bytes := [89]
def one : Bytes := [49]

theorem collide : naive [] x [(Y, one)] = naive [] (x ++ Y ++ [61] ++ one) [] := rfl

/-- The spelling in `Format`, with one-byte words, keeps them apart. -/
def f : Format where
  word n := [n]
  width := 1
  str n := [n]
  text
    | .body b _ => [b]
    | .stamped t _ => [t]
  label := []
  base _ := ⟨⟨0, 0, 0, 0, 0, [], [], []⟩, 0, [], ⟨0, 0, 0, []⟩⟩
  stepExtra _ := ⟨0, 0, 0, []⟩

theorem apart :
    stepPreimage f [] (.body 120 1) [(89, 49)] ⟨0, 0, 0, []⟩
      ≠ stepPreimage f [] (.body 5 1) [] ⟨0, 0, 0, []⟩ := by decide

/-- And what the collision costs: a step that prints `$Y` and one that prints nothing would share an
entry, so whichever ran second would replay the first's log. -/
def exec (e : Env) : Log := match e with
  | [] => 0
  | (_, c) :: _ => c

theorem wrong_answer : exec [(89, 49)] ≠ exec [] := by decide

end Ambiguous

/-! ## The store -/

/-- The store's entries: a key's bytes and what was recorded under it. On disk each is a directory
named by the key's sha256, holding the log, the file commands, the layer and its digest. -/
abbrev Store := List (Bytes × Output)

def slook (b : Bytes) : Store → Option Output
  | [] => none
  | e :: s => if b = e.1 then some e.2 else slook b s

theorem slook_sound (b : Bytes) : ∀ (s : Store) {o : Output}, slook b s = some o → (b, o) ∈ s
  | [], _, h => nomatch h
  | e :: s, o, h => by
    by_cases hb : b = e.1
    · simp only [slook, hb, ite_true, Option.some.injEq] at h
      subst h; subst hb; exact List.Mem.head _
    · simp only [slook, hb, ite_false] at h
      exact List.Mem.tail _ (slook_sound b s h)

/-- Publishing is a rename onto the key's name, which fails when the name is taken: the first
writer's entry stays (renameat2 with `RENAME_NOREPLACE`). `race_irrelevant` is why it does not
matter which writer that was. -/
def publish (b : Bytes) (o : Output) (s : Store) : Store :=
  match slook b s with
  | some _ => s
  | none => (b, o) :: s

/-- **What the native store records**: a success of an unmarked step, and nothing else. Not a
failure, which would not be replayed anyway (#69), and not a marked step, whose key names the job so
no one could ever ask for it, and whose log may hold a secret (P0: a secret-bearing value is never
in a key or a stored log). -/
def record (b : Bytes) (m : Mark) (o : Output) (s : Store) : Store :=
  if m = .plain ∧ o.code = 0 then publish b o s else s

/-- Eviction (LRU under a byte cap, or a wipe) removes entries. -/
def evict (b : Bytes) (s : Store) : Store := s.filter (fun e => e.1 != b)

section
variable (f : Format) (vol : Volatile) (exec : Input → Trial → Output)

/-- Every entry that some key's bytes name was really produced by running an input with that key,
succeeded, and is of a step that was not marked. Entries under bytes no key spells (another
format's, or garbage) are harmless: no step asks for them. -/
def SHonest (s : Store) : Prop :=
  ∀ {k : Key} {o : Output}, (encKey f k, o) ∈ s → Honest vol exec k o ∧ o.code = 0 ∧ Unstamped k.kScript

theorem shonest_nil : SHonest f vol exec [] := fun mem => nomatch mem

theorem shonest_publish {s : Store} {b : Bytes} {o : Output}
    (new : ∀ k, b = encKey f k → Honest vol exec k o ∧ o.code = 0 ∧ Unstamped k.kScript)
    (sh : SHonest f vol exec s) : SHonest f vol exec (publish b o s) := by
  unfold publish
  split
  · exact sh
  · intro k o' mem
    cases mem with
    | head => exact new k rfl
    | tail _ m => exact sh m

theorem shonest_evict {s : Store} (b : Bytes) (sh : SHonest f vol exec s) :
    SHonest f vol exec (evict b s) :=
  fun mem => sh (List.mem_filter.1 mem).1

/-- A hit is a success: the #69 rule holds of the store itself, not only of the reading of it. -/
theorem hit_succeeds {s : Store} (sh : SHonest f vol exec s) {k : Key} {o : Output}
    (hit : slook (encKey f k) s = some o) : o.code = 0 :=
  (sh (slook_sound _ _ hit)).2.1

/-- A marked step never hits: its script is stamped, and the store holds only unstamped ones. -/
theorem marked_misses {s : Store} (sh : SHonest f vol exec s) (t : Trial) (st : State)
    (e : Env) (ev : Content) (step : Step) :
    slook (nativeKey f vol (inputFor t st e ev step .everyRun)) s = none := by
  cases hit : slook (nativeKey f vol (inputFor t st e ev step .everyRun)) s with
  | none => rfl
  | some o => exact absurd (sh (slook_sound _ _ hit)).2.2 id

/-! ## Other runners: concurrency at the granularity of whole entries -/

/-- What another runner can do to a shared store between two of this job's steps. A publish is one
rename and an eviction one directory removed (renamed out of the way first, as the Dagger output
store's prune does), and a reader takes an entry whole or misses (`Torn`), so whole entries are the
granularity: any interleaving of pool runners is some list of these. -/
inductive Op where
  | publish (b : Bytes) (o : Output)
  | evict (b : Bytes)

def Op.apply : Op → Store → Store
  | .publish b o, s => Native.publish b o s
  | .evict b, s => Native.evict b s

/-- Another runner publishes as this one does: only what it ran under that key, if it succeeded and
was not marked. That runner must use the same `vol`, `exec` and `Format`, which the pool's single
runner version gives; a key format's version belongs in the tag so that another version's entries
are under bytes this one never spells. -/
def HonestOp : Op → Prop
  | .publish b o => ∀ k, b = encKey f k → Honest vol exec k o ∧ o.code = 0 ∧ Unstamped k.kScript
  | .evict _ => True

def applyAll (ops : List Op) (s : Store) : Store := ops.foldl (fun s op => op.apply s) s

/-- **Any interleaving of honest runners keeps the store honest.** -/
theorem ops_keep_honest (h : f.Sound) :
    ∀ (ops : List Op) {s : Store}, (∀ op ∈ ops, HonestOp f vol exec op) →
      SHonest f vol exec s → SHonest f vol exec (applyAll ops s)
  | [], _, _, sh => sh
  | op :: ops, s, hon, sh => by
    have hop := hon op (List.mem_cons_self ..)
    have sh' : SHonest f vol exec (op.apply s) := by
      cases op with
      | publish b o =>
        show SHonest f vol exec (publish b o s)
        exact shonest_publish f vol exec hop sh
      | evict b =>
        show SHonest f vol exec (evict b s)
        exact shonest_evict f vol exec b sh
    exact ops_keep_honest h ops (fun x hx => hon x (List.mem_cons_of_mem _ hx)) sh'

/-- **It does not matter which of two racing writers wins.** Two honest results for an unmarked
key are equal once the step is disciplined, so first-writer-wins and last-writer-wins store the same
thing. The flock per key is about cost (a pool runs a key once, not twice), not soundness. -/
theorem race_irrelevant (d : Disciplined vol exec) {k : Key} {o o' : Output}
    (ho : Honest vol exec k o) (ho' : Honest vol exec k o') (u : Unstamped k.kScript) : o = o' := by
  obtain ⟨i, t, ki, rfl⟩ := ho
  obtain ⟨j, t', kj, rfl⟩ := ho'
  exact d i j t t' (ki.trans kj.symm) (by rw [← ki] at u; exact u)

end

/-! ## A job on the native backend -/

structure NProgress where
  state : State
  env : Env
  event : Content
  store : Store
  ran : Nat
  outs : List Output

section
variable (f : Format) (vol : Volatile) (exec : Input → Trial → Output)

def ninput (t : Trial) (p : NProgress) (st : Step) : Input :=
  inputFor t p.state p.env p.event st (mark vol st)

/-- The store as this step finds it: what other runners did since the last step (`others`), and
whether the read fails (`lost`: the entry was evicted under it, or a part of it could not be read).
A failed read is a miss. -/
def nlook (others : List Op) (lost : Bool) (b : Bytes) (s : Store) : Option Output :=
  if lost then none else slook b (applyAll others s)

def nproduced (t : Trial) (p : NProgress) (st : Step) : Option Output → Output
  | some o => o
  | none => exec (ninput vol t p st) t

def nstore (t : Trial) (p : NProgress) (st : Step) (others : List Op) : Option Output → Store
  | some _ => applyAll others p.store
  | none => record (nativeKey f vol (ninput vol t p st)) (mark vol st) (exec (ninput vol t p st) t)
      (applyAll others p.store)

def nran (p : NProgress) : Option Output → Nat
  | some _ => p.ran
  | none => p.ran + 1

/-- One step: the same `nextState` and `nextEnv` as `Build.advance`, so output keys and
`$GITHUB_ENV` are the model's; the store in place of the cache. -/
def nadvance (md : Mode) (t : Trial) (p : NProgress) (st : Step) (others : List Op)
    (r : Option Output) : NProgress :=
  ⟨nextState vol (md st.num) t p.state p.env p.event st (mark vol st) (nproduced vol exec t p st r),
   nextEnv p.env (nproduced vol exec t p st r),
   p.event,
   nstore f vol exec t p st others r,
   nran p r,
   nproduced vol exec t p st r :: p.outs⟩

def nstepOnce (md : Mode) (t : Trial) (others : List Op) (lost : Bool) (p : NProgress) (st : Step) :
    NProgress :=
  nadvance f vol exec md t p st others
    (nlook others lost (nativeKey f vol (ninput vol t p st)) p.store)

/-- A job: before each step, whatever the pool did (`others`), and whether the step's read fails
(`lost`), both chosen by an adversary, per step. -/
def nbuild (md : Mode) (t : Trial) (others : Nat → List Op) (lost : Nat → Bool) :
    NProgress → List Step → NProgress
  | p, [] => p
  | p, st :: sts => nbuild md t others lost (nstepOnce f vol exec md t (others st.num) (lost st.num) p st) sts

/-- One step: what it contributes is what running it contributes, and the store stays honest. -/
theorem nstep_ok (h : f.Sound) (d : Disciplined vol exec) (t : Trial) (p : NProgress) (st : Step)
    (others : List Op) (hon : ∀ op ∈ others, HonestOp f vol exec op) (r : Option Output)
    (heq : nlook others lost (nativeKey f vol (ninput vol t p st)) p.store = r)
    (sh : SHonest f vol exec p.store) :
    nproduced vol exec t p st r = exec (ninput vol t p st) t ∧
      SHonest f vol exec (nstore f vol exec t p st others r) := by
  have sh' : SHonest f vol exec (applyAll others p.store) := ops_keep_honest f vol exec h others hon sh
  cases r with
  | none =>
    refine ⟨rfl, ?_⟩
    simp only [nstore, record]
    split
    · next c =>
      refine shonest_publish f vol exec (fun k hk => ?_) sh'
      have kk := (encKey_injective h hk).symm
      subst kk
      refine ⟨⟨_, t, rfl, rfl⟩, c.2, ?_⟩
      have hm := c.1
      simp only [keyOf, ninput, hm, inputFor]
      trivial
    · exact sh'
  | some o =>
    refine ⟨?_, sh'⟩
    have hit : slook (nativeKey f vol (ninput vol t p st)) (applyAll others p.store) = some o := by
      simp only [nlook] at heq
      split at heq
      · exact nomatch heq
      · exact heq
    obtain ⟨⟨j, t', kj, ej⟩, _, u⟩ := sh' (slook_sound _ _ hit)
    exact ((d _ j t t' kj.symm u).trans ej).symm

/-- **P1 on the native backend.** A job run against a store that other runners share produces what
the same job produces with the step cache off, step for step, if the steps the runner does not mark
are disciplined, the key's spelling is sound, and the store starts honest (an empty one is:
`shonest_nil`). It holds for every mode, whatever honest runners publish or evict between steps, and
whichever reads fail: a miss is always safe. Unlike `Build.replay_eq_run` it needs no `Numbered` and
no `Ahead`, because a marked step is never stored. -/
theorem native_replay_eq_run (h : f.Sound) (d : Disciplined vol exec) (md : Mode) (t : Trial)
    (others : Nat → List Op) (lost : Nat → Bool)
    (hon : ∀ n, ∀ op ∈ others n, HonestOp f vol exec op) :
    ∀ (p : NProgress) (job : List Step), SHonest f vol exec p.store →
      (nbuild f vol exec md t others lost p job).outs
        = uncached vol exec md t p.event p.state p.env p.outs job
  | _, [], _ => rfl
  | p, st :: sts, sh => by
    obtain ⟨out_eq, sh'⟩ :=
      nstep_ok f vol exec h d t p st (others st.num) (hon st.num) _ rfl sh (lost := lost st.num)
    have ih := native_replay_eq_run h d md t others lost hon
      (nstepOnce f vol exec md t (others st.num) (lost st.num) p st) sts sh'
    refine ih.trans (uncached_cong vol exec md t p.event sts ?_ ?_ ?_)
    · exact congrArg (nextState vol (md st.num) t p.state p.env p.event st (mark vol st)) out_eq
    · exact congrArg (nextEnv p.env) out_eq
    · exact congrArg (· :: p.outs) out_eq

/-- A replayed step contributed exactly the stored entry, and the entry is a success. -/
theorem replay_is_stored (h : f.Sound) (md : Mode) (t : Trial) (others : List Op) (p : NProgress)
    (st : Step) (hon : ∀ op ∈ others, HonestOp f vol exec op) (sh : SHonest f vol exec p.store)
    (same : (nstepOnce f vol exec md t others false p st).ran = p.ran) :
    ∃ o, slook (nativeKey f vol (ninput vol t p st)) (applyAll others p.store) = some o ∧
      (nstepOnce f vol exec md t others false p st).outs = o :: p.outs ∧ o.code = 0 := by
  revert same
  simp only [nstepOnce, nadvance, nlook, Bool.false_eq_true, ite_false]
  cases hit : slook (nativeKey f vol (ninput vol t p st)) (applyAll others p.store) with
  | none => intro e; exact absurd e (Nat.succ_ne_self _)
  | some o =>
    intro _
    exact ⟨o, rfl, rfl, hit_succeeds f vol exec (ops_keep_honest f vol exec h others hon sh) hit⟩

/-- **Both backends satisfy the same model.** Started from the same place, a job on the native
backend and the same job on the Dagger backend (`Build.build`, under its own hypotheses) produce the
same outputs, because each produces what the job does with the step cache off. -/
theorem native_eq_dagger (h : f.Sound) (d : Disciplined vol exec) (md : Mode) (t : Trial)
    (others : Nat → List Op) (lost : Nat → Bool) (hon : ∀ n, ∀ op ∈ others n, HonestOp f vol exec op)
    (np : NProgress) (p : Progress) (job : List Step) (n : Nat)
    (hs : np.state = p.state) (he : np.env = p.env) (hev : np.event = p.event) (ho : np.outs = p.outs)
    (sh : SHonest f vol exec np.store) (nums : Numbered n job) (co : Coherent vol exec p.cache)
    (ah : Ahead t n p.cache) :
    (nbuild f vol exec md t others lost np job).outs = (build vol exec md t p job).outs := by
  rw [native_replay_eq_run f vol exec h d md t others lost hon np job sh,
    replay_eq_run vol exec d md t n p job nums co ah, hs, he, hev, ho]

end

/-! ## An entry is read whole, or it is a miss

An entry is several parts on disk: the log, the file commands, the layer's digest, the exit code. A
writer makes them one at a time and an eviction removes them one at a time, so without care a reader
could find some and not others. Two rules close that, and either one is enough: the entry appears
and disappears by one rename (then every state a reader can see is whole or absent), and a reader
that finds a part missing or short takes the entry as a miss (`readWhole`), never as empty. -/

/-- An entry as a reader may find it: each part there or not. -/
structure Parts where
  log : Option Log
  digest : Option Content
  sets : Option Env
  code : Option Nat

/-- Every part that is there is the entry's: what a writer or an eviction leaves part-way, in any
order. -/
def Agrees (p : Parts) (o : Output) : Prop :=
  (∀ x, p.log = some x → x = o.log) ∧ (∀ x, p.digest = some x → x = o.digest) ∧
    (∀ x, p.sets = some x → x = o.sets) ∧ (∀ x, p.code = some x → x = o.code)

/-- The reader the store must have: all of the entry, or a miss. -/
def readWhole (p : Parts) : Option Output :=
  match p.log, p.digest, p.sets, p.code with
  | some l, some d, some s, some c => some ⟨l, d, s, c⟩
  | _, _, _, _ => none

/-- Whatever part-way state it meets, the whole-or-nothing reader returns the entry or a miss. -/
theorem readWhole_agrees {p : Parts} {o : Output} (a : Agrees p o) :
    readWhole p = none ∨ readWhole p = some o := by
  obtain ⟨hl, hd, hs, hc⟩ := a
  unfold readWhole
  split
  · next l d s c el ed es ec =>
    right
    rw [hl l el, hd d ed, hs s es, hc c ec]
  · left; rfl

/-! The reader the store must not have: one that takes a missing part as empty. Here the step
exported `X=1` and the reader came in after the log and the digest were written and before the file
commands: the replay exports nothing, and the step after it runs without `X`. -/

namespace Torn

def readDefaulting (p : Parts) : Output :=
  ⟨p.log.getD 0, p.digest.getD 0, p.sets.getD [], p.code.getD 0⟩

def ran : Output := ⟨7, 3, [(1, 1)], 0⟩

def halfWritten : Parts := ⟨some 7, some 3, none, none⟩

theorem agrees : Agrees halfWritten ran := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> intro x hx <;> simp_all [halfWritten, ran]

theorem replays_something_else : readDefaulting halfWritten ≠ ran := by decide

theorem whole_reader_misses : readWhole halfWritten = none := rfl

end Torn

/-! ## Layer digests -/

/-- What a later step can see of one path in a layer: its path; its metadata (type, mode, owner and
group as the step sees them, inside the job's user namespace, extended attributes, a symlink's
target, and a whiteout or opaque directory, which is how a layer says something was removed); and a
regular file's content. -/
structure Entry where
  path : Name
  attrs : Content
  data : Content
  deriving DecidableEq, Repr

/-- What the walk reads of a path: the entry, and what it must not hash. A file's times and inode
differ between two runs that wrote the same bytes, and so do the host's ids of a job's files, which
depend on the slot (P1's id ranges): hashing those would make every digest new, and the step's
output differ in `digest` though not in anything a step can see. -/
structure Seen where
  entry : Entry
  mtime : Nat
  inode : Nat
  hostIds : Nat

def byPath (a b : Entry) : Bool := decide (a.path ≤ b.path)

/-- The walk sorted by path. -/
def canon (l : List Entry) : List Entry := l.mergeSort byPath

section
variable (f : Format)

def encEntry (e : Entry) : Bytes := lp f (f.str e.path) ++ (lp f (f.str e.attrs) ++ lp f (f.str e.data))

def encEntries : List Entry → Bytes
  | [] => []
  | e :: es => encEntry f e ++ encEntries es

/-- **The layer digest's preimage**: the count, then each entry in path order. -/
def layerPreimage (walk : List Seen) : Bytes :=
  f.word walk.length ++ encEntries f (canon (walk.map Seen.entry))

variable {f}

theorem entries_split (h : f.Sound) :
    ∀ {es es' : List Entry} {r s : Bytes}, es.length = es'.length →
      encEntries f es ++ r = encEntries f es' ++ s → es = es' ∧ r = s
  | [], [], _, _, _, eq => ⟨rfl, by simpa [encEntries] using eq⟩
  | [], _ :: _, _, _, hl, _ => absurd hl.symm (Nat.succ_ne_zero _)
  | _ :: _, [], _, _, hl, _ => absurd hl (Nat.succ_ne_zero _)
  | ⟨p, m, c⟩ :: es, ⟨p', m', c'⟩ :: es', _, _, hl, eq => by
    simp only [encEntries, encEntry, List.append_assoc] at eq
    obtain ⟨hp, eq⟩ := lp_split h eq
    obtain ⟨hm, eq⟩ := lp_split h eq
    obtain ⟨hc, eq⟩ := lp_split h eq
    obtain ⟨he, hr⟩ := entries_split h (Nat.succ.inj hl) eq
    exact ⟨by rw [h.str_inj hp, h.str_inj hm, h.str_inj hc, he], hr⟩

/-- **Different layers, different digests.** Equal preimages mean the same entries, path for path. -/
theorem digest_injective (h : f.Sound) {w w' : List Seen}
    (eq : layerPreimage f w = layerPreimage f w') :
    canon (w.map Seen.entry) = canon (w'.map Seen.entry) := by
  obtain ⟨hl, eq⟩ := h.word_split eq
  refine (entries_split h ?_ (r := []) (s := []) (by simpa using eq)).1
  simp [canon, List.length_mergeSort, hl]

theorem eq_of_path {l : List Entry} (nd : (l.map Entry.path).Nodup) :
    ∀ {a b : Entry}, a ∈ l → b ∈ l → a.path = b.path → a = b := by
  induction l with
  | nil => intro _ _ ha; nomatch ha
  | cons x l ih =>
    intro a b ha hb hp
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at nd
    obtain ⟨notin, nd⟩ := nd
    cases ha with
    | head =>
      cases hb with
      | head => rfl
      | tail _ hb => exact absurd ⟨b, hb, hp.symm⟩ notin
    | tail _ ha =>
      cases hb with
      | head => exact absurd ⟨a, ha, hp⟩ notin
      | tail _ hb => exact ih nd ha hb hp

variable (f)

/-- **The same layer gives the same digest**: walks that saw the same entries, in whatever order the
directories were read and whatever the times, inodes and host ids, have one preimage. A layer has
one entry per path. -/
theorem digest_deterministic {w w' : List Seen} (nd : ((w.map Seen.entry).map Entry.path).Nodup)
    (same : (w.map Seen.entry).Perm (w'.map Seen.entry)) : layerPreimage f w = layerPreimage f w' := by
  have trans : ∀ a b c : Entry, byPath a b → byPath b c → byPath a c := by
    intro a b c h1 h2; simp only [byPath, decide_eq_true_eq] at *; exact Nat.le_trans h1 h2
  have total : ∀ a b : Entry, (byPath a b || byPath b a) = true := by
    intro a b; simp only [byPath, Bool.or_eq_true, decide_eq_true_eq]; exact Nat.le_total _ _
  have hc : canon (w.map Seen.entry) = canon (w'.map Seen.entry) := by
    refine List.Perm.eq_of_pairwise ?_ (List.pairwise_mergeSort trans total _)
      (List.pairwise_mergeSort trans total _)
      (((List.mergeSort_perm _ _).trans same).trans (List.mergeSort_perm _ _).symm)
    intro a b ha hb hab hba
    simp only [byPath, decide_eq_true_eq] at hab hba
    have ha' := (List.mergeSort_perm _ _).mem_iff.1 ha
    have hb' := same.mem_iff.2 ((List.mergeSort_perm _ _).mem_iff.1 hb)
    exact eq_of_path nd ha' hb' (Nat.le_antisymm hab hba)
  have hl : w.length = w'.length := by simpa using same.length_eq
  simp only [layerPreimage, hl, hc]

/-- So output keys get what they need of `Output.digest` from the native digest, with `atom` the
digest read as the model's atom (sha256 of the preimage, modelled as injective): the same layer is
the same next container (`OutputKeys.cutoff_needs_only_the_digest`), and a different layer a
different one (`OutputKeys.different_bytes_different_container`). -/
theorem same_layer_same_container (atom : Bytes → Content) (s : State) {w w' : List Seen}
    (nd : ((w.map Seen.entry).map Entry.path).Nodup) (same : (w.map Seen.entry).Perm (w'.map Seen.entry)) :
    State.afterCopy s (atom (layerPreimage f w)) = State.afterCopy s (atom (layerPreimage f w')) := by
  rw [digest_deterministic f nd same]

theorem different_layer_different_container (h : f.Sound) (atom : Bytes → Content)
    (ai : ∀ {x y}, atom x = atom y → x = y) (s : State) {w w' : List Seen}
    (ne : canon (w.map Seen.entry) ≠ canon (w'.map Seen.entry)) :
    State.afterCopy s (atom (layerPreimage f w)) ≠ State.afterCopy s (atom (layerPreimage f w')) :=
  fun eq => ne (digest_injective h (ai (afterCopy_injective₂ eq)))

end

/-! ## P2's walk (`Store.treeDigest`)

What P2's store hashes for a layer's digest, as it writes it: under the label `tree`, each entry of
a directory in the byte order of its name (`Store.listDir` sorts), with its path from the layer's
root (`/a/b`), its mode, its owner as the job's namespace sees it (`Store.Ids`), the count of its
xattrs and each one's name and value (sorted, overlay's bookkeeping left out), then by its type: a
regular file's sha256, a symlink's target, a device's numbers (an overlay whiteout is the device
0/0), or a directory's entries followed by the field `..`. The model's `Entry` above is the same
information flattened; this is the byte layout, and `walk_injective` is `digest_injective` for it.

The count before the xattrs is P8's addition to P2's walk: without it the last xattr and the
content that follows cannot be told apart (a symlink's target is a field like an xattr's name), so
two different layers could give one preimage. -/

mutual
/-- An entry of a layer: its name, mode, owner (uid, gid as the job's namespace sees them), xattrs,
and what its type says it holds. -/
inductive Node where
  | mk (name mode uid gid : Nat) (xattrs : List (Nat × Nat)) (body : Body)
inductive Body where
  | file (hash : Nat)
  | link (target : Nat)
  | dev (major minor : Nat)
  | dir (children : List Node)
  | other
end

def Body.kind : Body → Nat
  | .file _ => 0
  | .link _ => 1
  | .dev _ _ => 2
  | .dir _ => 3
  | .other => 4

/-- The `..` that ends a directory's entries. -/
def dotdot : Bytes := [46, 46]

section
variable (f : Format)

def encXattr (x : Nat × Nat) : Bytes := lp f (f.str x.1) ++ lp f (f.str x.2)

/-- An entry's path, mode, owner and xattrs: what `digestIn` writes before its content. -/
def nodeHead (rel : Bytes) (n m u g : Nat) (xs : List (Nat × Nat)) : Bytes :=
  lp f (rel ++ 47 :: f.str n) ++ (f.word m ++ (f.word u ++ (f.word g ++
    (f.word xs.length ++ encList (encXattr f) xs))))

mutual
def encNode (rel : Bytes) : Node → Bytes
  | .mk n m u g xs b => nodeHead f rel n m u g xs ++ encBody (rel ++ 47 :: f.str n) b
def encBody (path : Bytes) : Body → Bytes
  | .file h => lp f (f.str h)
  | .link t => lp f (f.str t)
  | .dev a b => f.word a ++ f.word b
  | .dir cs => encNodes path cs ++ lp f dotdot
  | .other => []
def encNodes (rel : Bytes) : List Node → Bytes
  | [] => []
  | c :: cs => encNode rel c ++ encNodes rel cs
end

/-- **A layer's preimage as P2 writes it** (`treeDigest`): the label, then the root's entries. -/
def walkPreimage (label : Bytes) (cs : List Node) : Bytes := lp f label ++ encNodes f [] cs

end

mutual
/-- The type the mode says (`S_IFMT`), as P2 dispatches on it, is the type the entry has: a real
tree's entries always satisfy it. -/
def WF (kindOf : Nat → Nat) : Node → Prop
  | .mk _ m _ _ _ b => kindOf m = b.kind ∧ WFBody kindOf b
def WFBody (kindOf : Nat → Nat) : Body → Prop
  | .dir cs => WFs kindOf cs
  | _ => True
def WFs (kindOf : Nat → Nat) : List Node → Prop
  | [] => True
  | c :: cs => WF kindOf c ∧ WFs kindOf cs
end

/-- A path from the layer's root: empty, or starting with `/`. -/
def RelPath (rel : Bytes) : Prop := ∀ x t, rel = x :: t → x = 47

theorem relPath_nil : RelPath [] := fun _ _ h => nomatch h

theorem relPath_child {rel : Bytes} (h : RelPath rel) (name : Bytes) : RelPath (rel ++ 47 :: name) := by
  intro x t e
  cases rel with
  | nil => simp only [List.nil_append, List.cons.injEq] at e; exact e.1.symm
  | cons y r => simp only [List.cons_append, List.cons.injEq] at e; rw [← e.1]; exact h y r rfl

theorem path_ne_dotdot {rel : Bytes} (h : RelPath rel) (name : Bytes) : rel ++ 47 :: name ≠ dotdot := by
  intro e
  have := relPath_child h name 46 [46] e
  exact absurd this (by decide)

/-- Where a list of entries may end: the stream's end, or a directory's `..`. -/
def Stop (f : Format) (r : Bytes) : Prop := r = [] ∨ ∃ t, r = lp f dotdot ++ t

section
variable {f : Format} {kindOf : Nat → Nat}

theorem nodeHead_ne_nil (rel : Bytes) (n m u g : Nat) (xs : List (Nat × Nat)) (r : Bytes) :
    nodeHead f rel n m u g xs ++ r ≠ [] := by
  simp [nodeHead, lp]

theorem xattr_split (h : f.Sound) {a a' : Nat × Nat} {r s : Bytes}
    (eq : encXattr f a ++ r = encXattr f a' ++ s) : a = a' ∧ r = s := by
  obtain ⟨x1, x2⟩ := a
  obtain ⟨y1, y2⟩ := a'
  simp only [encXattr, List.append_assoc] at eq
  obtain ⟨e1, eq⟩ := lp_split h eq
  obtain ⟨e2, eq⟩ := lp_split h eq
  exact ⟨by rw [h.str_inj e1, h.str_inj e2], eq⟩

mutual
theorem node_split (h : f.Sound) {rel : Bytes} (hr : RelPath rel) :
    ∀ {a a' : Node} {r s : Bytes}, WF kindOf a → WF kindOf a' →
      encNode f rel a ++ r = encNode f rel a' ++ s → a = a' ∧ r = s
  | .mk n m u g xs b, .mk n' m' u' g' xs' b', r, s, ⟨hk, hb⟩, ⟨hk', hb'⟩, e => by
    simp only [encNode, nodeHead, List.append_assoc] at e
    obtain ⟨hp, e⟩ := lp_split h e
    have hn : n = n' := h.str_inj (List.cons.inj (List.append_cancel_left hp)).2
    subst hn
    obtain ⟨hm, e1⟩ := h.word_split e
    obtain ⟨hu, e2⟩ := h.word_split e1
    obtain ⟨hg, e3⟩ := h.word_split e2
    obtain ⟨hl, e4⟩ := h.word_split e3
    obtain ⟨hxs, e5⟩ := list_split (xattr_split h) hl e4
    subst hm hu hg hxs
    obtain ⟨hbb, hrs⟩ := body_split h (relPath_child hr (f.str n)) (hk.symm.trans hk') hb hb' e5
    exact ⟨by rw [hbb], hrs⟩

theorem body_split (h : f.Sound) {path : Bytes} (hp : RelPath path) :
    ∀ {b b' : Body} {r s : Bytes}, b.kind = b'.kind → WFBody kindOf b → WFBody kindOf b' →
      encBody f path b ++ r = encBody f path b' ++ s → b = b' ∧ r = s
  | .file x, .file y, _, _, _, _, _, e => by
    simp only [encBody] at e
    obtain ⟨hx, hrs⟩ := lp_split h e
    exact ⟨by rw [h.str_inj hx], hrs⟩
  | .link x, .link y, _, _, _, _, _, e => by
    simp only [encBody] at e
    obtain ⟨hx, hrs⟩ := lp_split h e
    exact ⟨by rw [h.str_inj hx], hrs⟩
  | .dev a b, .dev a' b', _, _, _, _, _, e => by
    simp only [encBody, List.append_assoc] at e
    obtain ⟨ha, e⟩ := h.word_split e
    obtain ⟨hb, hrs⟩ := h.word_split e
    exact ⟨by rw [ha, hb], hrs⟩
  | .dir cs, .dir cs', r, s, _, hw, hw', e => by
    simp only [encBody, List.append_assoc] at e
    obtain ⟨hcs, e⟩ := nodes_split h hp hw hw' (Or.inr ⟨r, rfl⟩) (Or.inr ⟨s, rfl⟩) e
    exact ⟨by rw [hcs], (lp_split h e).2⟩
  | .other, .other, _, _, _, _, _, e => ⟨rfl, by simpa [encBody] using e⟩
  | .file _, .link _, _, _, k, _, _, _ | .file _, .dev _ _, _, _, k, _, _, _
  | .file _, .dir _, _, _, k, _, _, _ | .file _, .other, _, _, k, _, _, _
  | .link _, .file _, _, _, k, _, _, _ | .link _, .dev _ _, _, _, k, _, _, _
  | .link _, .dir _, _, _, k, _, _, _ | .link _, .other, _, _, k, _, _, _
  | .dev _ _, .file _, _, _, k, _, _, _ | .dev _ _, .link _, _, _, k, _, _, _
  | .dev _ _, .dir _, _, _, k, _, _, _ | .dev _ _, .other, _, _, k, _, _, _
  | .dir _, .file _, _, _, k, _, _, _ | .dir _, .link _, _, _, k, _, _, _
  | .dir _, .dev _ _, _, _, k, _, _, _ | .dir _, .other, _, _, k, _, _, _
  | .other, .file _, _, _, k, _, _, _ | .other, .link _, _, _, k, _, _, _
  | .other, .dev _ _, _, _, k, _, _, _ | .other, .dir _, _, _, k, _, _, _ =>
    absurd k (by simp [Body.kind])

theorem nodes_split (h : f.Sound) {rel : Bytes} (hr : RelPath rel) :
    ∀ {cs cs' : List Node} {r s : Bytes}, WFs kindOf cs → WFs kindOf cs' → Stop f r → Stop f s →
      encNodes f rel cs ++ r = encNodes f rel cs' ++ s → cs = cs' ∧ r = s
  | [], [], _, _, _, _, _, _, e => ⟨rfl, by simpa [encNodes] using e⟩
  | [], .mk n m u g xs b :: _, r, _, _, _, sr, _, e => by
    simp only [encNodes, encNode, List.nil_append, List.append_assoc] at e
    rcases sr with rfl | ⟨t, rfl⟩
    · exact absurd e.symm (by simp [nodeHead, lp])
    · simp only [nodeHead, List.append_assoc] at e
      exact absurd (lp_split h e).1 (Ne.symm (path_ne_dotdot hr _))
  | .mk n m u g xs b :: _, [], _, s, _, _, _, ss, e => by
    simp only [encNodes, encNode, List.nil_append, List.append_assoc] at e
    rcases ss with rfl | ⟨t, rfl⟩
    · exact absurd e (by simp [nodeHead, lp])
    · simp only [nodeHead, List.append_assoc] at e
      exact absurd (lp_split h e).1 (path_ne_dotdot hr _)
  | c :: cs, c' :: cs', _, _, ⟨hc, hcs⟩, ⟨hc', hcs'⟩, sr, ss, e => by
    simp only [encNodes, List.append_assoc] at e
    obtain ⟨hcc, e⟩ := node_split h hr hc hc' e
    obtain ⟨hl, hrs⟩ := nodes_split h hr hcs hcs' sr ss e
    exact ⟨by rw [hcc, hl], hrs⟩
end

/-- **Different layers, different digests, as P2 writes them.** Equal preimages of two real trees
mean the same entries, path for path: names, modes, owners, xattrs, contents, link targets, device
numbers (so whiteouts) and the opaque xattr alike. -/
theorem walk_injective (h : f.Sound) {label : Bytes} {cs cs' : List Node}
    (w : WFs kindOf cs) (w' : WFs kindOf cs')
    (e : walkPreimage f label cs = walkPreimage f label cs') : cs = cs' := by
  have e' : encNodes f [] cs = encNodes f [] cs' := (lp_split h e).2
  exact (nodes_split h relPath_nil w w' (Or.inl rfl) (Or.inl rfl) (by simpa using e')).1

end

end Runner.Native
