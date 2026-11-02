---------------------------- MODULE StoreLocking ----------------------------
(***************************************************************************)
(* The native layer store's locking protocol at the level of system calls *)
(* (runner/src/native/Store.zig, its callers in Backend.zig and layers.zig; *)
(* docs/native-backend.md, P2).  proofs/Runner/Native.lean treats a store  *)
(* operation as one step on whole entries; this module is what lets it:    *)
(* the flocks, the temporary and dead names, the renames, the half-removed *)
(* trees and the processes that die between any two system calls.         *)
(*                                                                         *)
(* Several runner processes share one store.  Each runs one job of `Steps` *)
(* steps; a step is either a cached `run:` step (a key in StepKeys: the    *)
(* key's flock while it runs, Backend.claimKey and publishTop) or a        *)
(* Dockerfile build layer (a key in BuildKeys: layers.zig, which publishes *)
(* the same way but runs nothing under the key's lock).  At the job's end  *)
(* the process lets go of its layers and collects (Store.collect).  Any    *)
(* process may die between any two of its actions (the kernel releases its *)
(* flocks; its files stay), and the machine may die (every process, and    *)
(* the data no one synced).                                                *)
(*                                                                         *)
(* Every action cites the code it stands for as file:line.  Paths below   *)
(* are relative to runner/src/native/.                                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,          \* the runner processes sharing the store
    StepKeys,       \* keys of steps run under their key's lock (claimKey)
    BuildKeys,      \* keys of Dockerfile build layers (layers.zig)
    Steps,          \* steps per job
    MaxCrashes,     \* process crashes, all told
    MachineCrashes, \* machine crashes (0 or 1)
    MaxCorrupts,    \* entries a hand changes behind the store's back
    BuildHoldsKeyLock, \* layers.zig takes the key's lock around its publish (the fix)
    SyncBeforePublish, \* Store.publish calls syncfs before the rename (Store.zig:462)
    EvictRechecks      \* evict checks its lock is on the file the path names (the fix)

ASSUME StepKeys \cap BuildKeys = {} /\ Steps \in Nat \ {0}

Keys == StepKeys \cup BuildKeys

(* A layers/ directory, by who made it: process p's step i builds at most *)
(* one entry (Store.publish's `.tmp-<key>-<random>`), so <<p, i>> names a *)
(* directory for its whole life, whatever it is renamed to.              *)
Ids == Procs \X (1..Steps)
NoDir == <<>>
NoFd == <<>>

(* An entry's files (Store.zig:10-15): `meta`, the record (`log` and `fc`, *)
(* checked together against meta), the layer's `lock` and the tree `fs`.   *)
Parts == {"meta", "rec", "lock", "fs"}

VARIABLES
    st,      \* each process's program counter and locals
    dirs,    \* layers/: each directory's name, key, files and their state
    sh,      \* the descriptors (Fd) holding each entry's lock file shared
    ex,      \* ... and exclusively (at most one)
    kino,    \* keys/<k>.lock: the generation of the file the path names, 0 for none
    kgen,    \* the last generation made, so a file made again is a new inode
    gc,      \* who holds gc.lock (Store.zig:485-489)
    crashes, mcrashes, corrupts,
    badRead,   \* ghost: a job took an entry that was not whole and right
    lostUpper  \* ghost: a step's upper was deleted under it

vars == <<st, dirs, sh, ex, kino, kgen, gc, crashes, mcrashes, corrupts, badRead, lostUpper>>
fsVars == <<dirs, sh, ex, kino, kgen, gc>>
ghost == <<crashes, mcrashes, corrupts, badRead, lostUpper>>

(* A process's locals.  `kfd` is its open keys/<k>.lock (an inode, <<key, *)
(* generation>>) and `klk` whether it holds that inode's flock; `owns`,   *)
(* that it passed lockKey's check and is running the key.  `od` is open's *)
(* lock file, `evd` evict's, `held` the job's layers (Backend.held).      *)
Idle == [pc |-> "start", step |-> 1, key |-> CHOOSE k \in Keys : TRUE, mode |-> "step",
         after |-> "op_file", kfd |-> NoFd, klk |-> FALSE, owns |-> FALSE, keyed |-> FALSE,
         od |-> NoDir, moved |-> FALSE, held |-> {}, evk |-> CHOOSE k \in Keys : TRUE,
         evd |-> NoDir, evRet |-> "open", rtd |-> NoDir, rtOrig |-> "none", rtRet |-> "start",
         todo |-> {}, ktodo |-> {}]

Dead == [Idle EXCEPT !.pc = "crashed"]

(* Step i begins, the job's layers `h` held: a cached step's key goes     *)
(* through claimKey (Backend.zig:1242, 1574, 1129, 2058 -> 1949), a build *)
(* layer's through layers.Store.get (dockerfile.zig:578 -> layers.zig:44- *)
(* 48, open without the key's lock).  After the last step, the job's end. *)
(* Choosing the key touches nothing shared, so it is folded into the step *)
(* before (StepEnd) and Init: fewer interleavings, the same behaviours.   *)
Begin(i, h) ==
    IF i > Steps
    THEN {[Idle EXCEPT !.step = i, !.held = h, !.pc = "end"]}
    ELSE {[Idle EXCEPT !.step = i, !.held = h, !.key = k,
                       !.mode = IF k \in StepKeys THEN "step" ELSE "build",
                       !.pc = IF k \in StepKeys THEN "lk_create" ELSE "op_file",
                       !.after = "op_file"] : k \in Keys}

NoEntry == [name |-> "none", key |-> CHOOSE k \in Keys : TRUE, parts |-> {},
            fsOk |-> FALSE, recOk |-> FALSE, synced |-> FALSE]

Pub(k) == {d \in Ids : dirs[d].name = "pub" /\ dirs[d].key = k}
(* No key lock inode is held by anyone.                                   *)
KFree(i) == \A q \in Procs : ~(st[q].klk /\ st[q].kfd = i)

(* readEntry (Store.zig:356-373) passes: meta parses, the tree is a       *)
(* directory, the record's lengths and sha256s are meta's.  It does not   *)
(* look inside the tree.  One check at one instant: a published entry     *)
(* changes only under its lock taken exclusively, which excludes a reader *)
(* holding it shared, so in the protocol as fixed nothing changes during  *)
(* the read.                                                              *)
Validates(d) == dirs[d].name = "pub" /\ {"meta", "rec", "fs"} \subseteq dirs[d].parts
                /\ dirs[d].recOk
(* entryLooksWhole (Store.zig:382-397): meta, the tree, the lengths.  The *)
(* hand's change keeps lengths, so only open's sha256 sees it.            *)
LooksWhole(d) == {"meta", "rec", "fs"} \subseteq dirs[d].parts
(* What a job may use: published, every file there, the tree whole.       *)
Intact(d) == dirs[d].name = "pub" /\ dirs[d].parts = Parts /\ dirs[d].fsOk

TypeOK ==
    /\ \A d \in Ids : dirs[d].name \in {"none", "tmp", "pub", "dead"}
                      /\ dirs[d].parts \subseteq Parts
    /\ \A d \in Ids : sh[d] \subseteq Ids /\ ex[d] \subseteq Procs /\ Cardinality(ex[d]) <= 1
    /\ \A k \in Keys : kino[k] \in Nat /\ kino[k] <= kgen[k]
    /\ gc \subseteq Procs /\ Cardinality(gc) <= 1

Init ==
    /\ st \in [Procs -> Begin(1, {})]
    /\ dirs = [d \in Ids |-> NoEntry]
    /\ sh = [d \in Ids |-> {}]
    /\ ex = [d \in Ids |-> {}]
    /\ kino = [k \in Keys |-> 0]
    /\ kgen = [k \in Keys |-> 0]
    /\ gc = {}
    /\ crashes = 0 /\ mcrashes = 0 /\ corrupts = 0
    /\ badRead = FALSE /\ lostUpper = FALSE

S(p) == st[p]
Me(p) == <<p, st[p].step>>   \* the directory this step publishes from
Put(p, r) == st' = [st EXCEPT ![p] = r]
(* A flock belongs to an open file description, not to a process: a job  *)
(* holding a layer that opens it again holds two locks, and closing one   *)
(* keeps the other.  A process opens at most one lock file per step, so   *)
(* <<p, step>> names the descriptor.                                      *)
Fd(p) == <<p, st[p].step>>
DropSh(p, d) == sh' = [sh EXCEPT ![d] = @ \ {Fd(p)}]
Others(p, holders) == {t \in holders : t[1] # p}

(* Calls, with the return label in the locals.                            *)
RemoveTree(r, d, ret) == [r EXCEPT !.pc = "rt", !.rtd = d, !.rtOrig = dirs[d].name, !.rtRet = ret]
Evict(r, k, ret) == [r EXCEPT !.pc = "ev_open", !.evk = k, !.evRet = ret]

(* open found nothing to replay.  Backend.zig:1963-1969 (`orelse return   *)
(* .{ .key = k, .lock = lock }`): the step runs keyed.  A build runs      *)
(* (dockerfile.zig:578-582); after its publish lost, nothing is there to  *)
(* take and the build fails (layers.zig:75, `orelse return e`).           *)
Missed(r) == CASE r.mode = "step"  -> [r EXCEPT !.pc = "run", !.keyed = TRUE]
               [] r.mode = "build" -> [r EXCEPT !.pc = "run"]
               [] r.mode = "retry" -> [r EXCEPT !.pc = "step_end"]

(* open's error.Invalid: the entry is broken and another job holds it.    *)
(* Backend.zig:1963-1969: the key's lock let go, the step runs uncached.  *)
(* A build's `try s.store.open` fails the build (layers.zig:45, 75).      *)
Invalid(r) == IF r.mode = "step"
              THEN [r EXCEPT !.pc = "run", !.keyed = FALSE, !.klk = FALSE, !.kfd = NoFd,
                             !.owns = FALSE]
              ELSE [r EXCEPT !.pc = "step_end"]

-----------------------------------------------------------------------------
(* The job's steps.                                                       *)


(* lockKey (Store.zig:227-246).  createFile(truncate = false) makes the  *)
(* file when the path names none (Store.zig:236).                         *)
LkCreate(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "lk_create"
    /\ IF kino[k] = 0
       THEN /\ kgen' = [kgen EXCEPT ![k] = @ + 1]
            /\ kino' = [kino EXCEPT ![k] = kgen[k] + 1]
            /\ Put(p, [S(p) EXCEPT !.kfd = <<k, kgen[k] + 1>>, !.pc = "lk_flock"])
       ELSE /\ Put(p, [S(p) EXCEPT !.kfd = <<k, kino[k]>>, !.pc = "lk_flock"])
            /\ UNCHANGED <<kino, kgen>>
    /\ UNCHANGED <<dirs, sh, ex, gc, ghost>>

(* flock(LOCK_EX | LOCK_NB) (Store.zig:237); on failure the file is      *)
(* closed (Store.zig:242), and the poll (Store.zig:243-244, folded in, as *)
(* it touches nothing shared) tries again, or a step's wait ends on a     *)
(* cancel or a timeout (`stop`, Backend.zig:1953-1957 and 1655-1661) and  *)
(* the step fails (Backend.zig:1242-1247).  A build's publish waits only  *)
(* for another publish of its layer, and is not cancelled (layers.zig:28- *)
(* 30, 70).                                                               *)
LkFlock(p) ==
    /\ S(p).pc = "lk_flock"
    /\ IF KFree(S(p).kfd)
       THEN Put(p, [S(p) EXCEPT !.klk = TRUE, !.pc = "lk_same"])
       ELSE \/ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.pc = "lk_create"])
            \/ /\ S(p).mode = "step"
               /\ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.pc = "step_end"])
    /\ UNCHANGED <<fsVars, ghost>>

(* sameFile (Store.zig:238-240, 602-612): the lock counts only on the    *)
(* file the path names now; else closed (its flock with it) and again.    *)
LkSame(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "lk_same"
    /\ IF kino[k] # 0 /\ S(p).kfd = <<k, kino[k]>>
       THEN Put(p, [S(p) EXCEPT !.owns = (S(p).mode = "step"), !.pc = S(p).after])
       ELSE Put(p, [S(p) EXCEPT !.klk = FALSE, !.kfd = NoFd, !.pc = "lk_create"])
    /\ UNCHANGED <<fsVars, ghost>>

(* Store.open (Store.zig:267-284): the entry's lock file opened          *)
(* (Store.zig:270; no entry or no lock file: a miss).                     *)
OpFile(p) ==
    LET P == {d \in Pub(S(p).key) : "lock" \in dirs[d].parts} IN
    /\ S(p).pc = "op_file"
    /\ IF P # {}
       THEN Put(p, [S(p) EXCEPT !.od = CHOOSE d \in P : TRUE, !.pc = "op_flock"])
       ELSE Put(p, Missed(S(p)))
    /\ UNCHANGED <<fsVars, ghost>>

(* flock(LOCK_SH), blocking (Store.zig:272): waits out an eviction.       *)
OpFlock(p) ==
    LET d == S(p).od IN
    /\ S(p).pc = "op_flock"
    /\ ex[d] = {}
    /\ sh' = [sh EXCEPT ![d] = @ \cup {Fd(p)}]
    /\ Put(p, [S(p) EXCEPT !.pc = "op_same"])
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, ghost>>

(* sameFile (Store.zig:272-275): an entry evicted meanwhile leaves the   *)
(* path naming nothing, or another entry's lock: a miss.                  *)
OpSame(p) ==
    LET d == S(p).od IN
    /\ S(p).pc = "op_same"
    /\ IF d \in Pub(S(p).key) /\ "lock" \in dirs[d].parts
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "op_read"])
            /\ UNCHANGED sh
       ELSE /\ DropSh(p, d)
            /\ Put(p, Missed([S(p) EXCEPT !.od = NoDir]))
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, ghost>>

(* readEntry (Store.zig:276).  Whole: the job holds it to its end         *)
(* (Backend.zig:1970-1989 `held`; layers.zig:45-47) and the step replays  *)
(* (Backend.zig:1249-1262) or the build stacks it (dockerfile.zig:578-    *)
(* 581).  Not whole: closed, then evicted by name (Store.zig:276-279).    *)
OpRead(p) ==
    LET d == S(p).od IN
    /\ S(p).pc = "op_read"
    /\ IF Validates(d)
       THEN /\ badRead' = (badRead \/ ~Intact(d))
            /\ Put(p, [S(p) EXCEPT !.held = @ \cup {d}, !.od = NoDir, !.pc = "step_end"])
            /\ UNCHANGED sh
       ELSE /\ DropSh(p, d)
            /\ Put(p, Evict([S(p) EXCEPT !.od = NoDir], S(p).key, "open"))
            /\ UNCHANGED badRead
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, crashes, mcrashes, corrupts, lostUpper>>

(* The step's exec (Backend.zig:1278-1308, 1586-1596, 1135-1137) or the  *)
(* build's RUN or COPY (dockerfile.zig:582-594).  A success is published  *)
(* when the claim has a key (Backend.zig:1309-1310): publishTop           *)
(* (Backend.zig:1999-2026) moves the top layer with Store.publish while   *)
(* the key's lock is held (the claim is released by the step's `defer`,   *)
(* Backend.zig:1248).  A build publishes through layers.Store.publish     *)
(* (dockerfile.zig:595), which takes the key's lock first when            *)
(* BuildHoldsKeyLock (layers.zig:70-71, the fix) and did not before.      *)
Run(p) ==
    /\ S(p).pc = "run"
    /\ \E ok \in BOOLEAN :
         Put(p, IF ok /\ S(p).mode = "build" /\ BuildHoldsKeyLock
                THEN [S(p) EXCEPT !.pc = "lk_create", !.after = "pb_mkdir"]
                ELSE IF ok /\ (S(p).mode = "build" \/ S(p).keyed)
                THEN [S(p) EXCEPT !.pc = "pb_mkdir"]
                ELSE [S(p) EXCEPT !.pc = "step_end"])
    /\ UNCHANGED <<fsVars, ghost>>

(* Store.publish (Store.zig:413-474).  layers/.tmp-<key>-<n> made        *)
(* (Store.zig:426-434).  Its tree is unsynced until syncfs.               *)
PbMkdir(p) ==
    /\ S(p).pc = "pb_mkdir"
    /\ dirs' = [dirs EXCEPT ![Me(p)] = [name |-> "tmp", key |-> S(p).key, parts |-> {},
                                        fsOk |-> TRUE, recOk |-> TRUE, synced |-> FALSE]]
    /\ Put(p, [S(p) EXCEPT !.moved = FALSE, !.pc = "pb_write"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, ghost>>

Gone(p) == dirs[Me(p)].name = "none"

(* log, fc and meta written (Store.zig:453-455); into a directory that   *)
(* is gone they fail, and the errdefer runs (Store.zig:435-442).          *)
PbWrite(p) ==
    /\ S(p).pc = "pb_write"
    /\ IF Gone(p)
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED dirs
       ELSE /\ dirs' = [dirs EXCEPT ![Me(p)].parts = @ \cup {"meta", "rec"}]
            /\ Put(p, [S(p) EXCEPT !.pc = "pb_lock"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, ghost>>

(* The lock file made and held shared before the entry is visible        *)
(* (Store.zig:456-457).                                                   *)
PbLock(p) ==
    /\ S(p).pc = "pb_lock"
    /\ IF Gone(p)
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED <<dirs, sh>>
       ELSE /\ ex[Me(p)] = {}
            /\ dirs' = [dirs EXCEPT ![Me(p)].parts = @ \cup {"lock"}]
            /\ sh' = [sh EXCEPT ![Me(p)] = @ \cup {Fd(p)}]
            /\ Put(p, [S(p) EXCEPT !.pc = "pb_move"])
    /\ UNCHANGED <<ex, kino, kgen, gc, ghost>>

(* The upper renamed in as fs (Store.zig:458-459).                        *)
PbMove(p) ==
    /\ S(p).pc = "pb_move"
    /\ IF Gone(p)
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED dirs
       ELSE /\ dirs' = [dirs EXCEPT ![Me(p)].parts = @ \cup {"fs"}, ![Me(p)].fsOk = TRUE]
            /\ Put(p, [S(p) EXCEPT !.moved = TRUE, !.pc = "pb_sync"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, ghost>>

(* syncfs before the entry is visible (Store.zig:460-462).  It syncs the *)
(* whole filesystem; the model credits only this entry.                   *)
PbSync(p) ==
    /\ S(p).pc = "pb_sync"
    /\ IF SyncBeforePublish /\ ~Gone(p)
       THEN dirs' = [dirs EXCEPT ![Me(p)].synced = TRUE]
       ELSE UNCHANGED dirs
    /\ Put(p, [S(p) EXCEPT !.pc = "pb_rename"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, ghost>>

(* renameat2(RENAME_NOREPLACE) (Store.zig:463-473): visible whole, or    *)
(* not at all when the key has an entry.  The job holds it from here      *)
(* (Backend.zig:2024; layers.zig:80).                                     *)
PbRename(p) ==
    /\ S(p).pc = "pb_rename"
    /\ IF dirs[Me(p)].name = "tmp" /\ Pub(S(p).key) = {}
       THEN /\ dirs' = [dirs EXCEPT ![Me(p)].name = "pub"]
            /\ Put(p, [S(p) EXCEPT !.held = @ \cup {Me(p)}, !.moved = FALSE, !.pc = "step_end"])
       ELSE /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED dirs
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, ghost>>

(* publish's errdefer (Store.zig:435-442): the lock closed, the upper    *)
(* renamed back when it moved, and the temporary entry removed; an upper *)
(* that cannot be put back is left there and logged.  A step goes on     *)
(* uncached (Backend.zig:2019-2023); a build takes the entry that won     *)
(* (layers.zig:74-78: open again).                                        *)
PbFail(p) ==
    LET d == Me(p)
        next == IF S(p).mode = "build" THEN "op_file" ELSE "step_end"
        r == [S(p) EXCEPT !.moved = FALSE,
                          !.mode = IF S(p).mode = "build" THEN "retry" ELSE @]
        back == ~S(p).moved \/ "fs" \in dirs[d].parts
    IN
    /\ S(p).pc = "pb_fail"
    /\ DropSh(p, d)
    /\ lostUpper' = (lostUpper \/ (S(p).moved /\ ~("fs" \in dirs[d].parts /\ dirs[d].fsOk)))
    /\ IF S(p).moved /\ "fs" \in dirs[d].parts
       THEN dirs' = [dirs EXCEPT ![d].parts = @ \ {"fs"}]
       ELSE UNCHANGED dirs
    /\ Put(p, IF back /\ ~Gone(p) THEN RemoveTree(r, d, next) ELSE [r EXCEPT !.pc = next])
    /\ UNCHANGED <<ex, kino, kgen, gc, crashes, mcrashes, corrupts, badRead>>

(* The claim released (Backend.zig:1248, 1580, 1132, 2063 `defer         *)
(* claim.release`; layers.zig:71, the key's lock's `defer`).              *)
StepEnd(p) ==
    /\ S(p).pc = "step_end"
    /\ \E r \in Begin(S(p).step + 1, S(p).held) : Put(p, r)
    /\ UNCHANGED <<fsVars, ghost>>

(* The job's end (Backend.zig:997-1002): its layers let go, then collect. *)
End(p) ==
    /\ S(p).pc = "end"
    /\ sh' = [d \in Ids |-> IF d \in S(p).held THEN Others(p, sh[d]) ELSE sh[d]]
    /\ Put(p, [S(p) EXCEPT !.held = {}, !.pc = "gc_lock"])
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, ghost>>

-----------------------------------------------------------------------------
(* Store.collect (Store.zig:483-549).                                     *)

(* gc.lock, exclusive and non-blocking (Store.zig:485-489); layers/      *)
(* listed (Store.zig:492-498).  An entry made after the listing may be    *)
(* missed, as readdir allows.                                             *)
GcLock(p) ==
    /\ S(p).pc = "gc_lock"
    /\ IF gc = {}
       THEN /\ gc' = {p}
            /\ Put(p, [S(p) EXCEPT !.todo = {d \in Ids : dirs[d].name # "none"},
                                   !.pc = "gc_next"])
       ELSE /\ Put(p, [S(p) EXCEPT !.pc = "done"]) /\ UNCHANGED gc
    /\ UNCHANGED <<dirs, sh, ex, kino, kgen, ghost>>

(* One entry, by the name it has now (readdir's order is fixed here:     *)
(* every interleaving with the other processes is still explored).        *)
GcNext(p) ==
    /\ S(p).pc = "gc_next"
    /\ IF S(p).todo = {}
       THEN /\ Put(p, [S(p) EXCEPT !.ktodo = {k \in Keys : kino[k] # 0}, !.pc = "dk_next"])
            /\ UNCHANGED <<kino, kgen>>
       ELSE LET d == CHOOSE x \in S(p).todo : TRUE
                k == dirs[d].key
                r == [S(p) EXCEPT !.todo = @ \ {d}]
                new == kino[k] = 0
                i == IF new THEN <<k, kgen[k] + 1>> ELSE <<k, kino[k]>>
            IN CASE dirs[d].name = "none" ->
                      Put(p, r) /\ UNCHANGED <<kino, kgen>>
                 \* .dead-: removed (Store.zig:500-502)
                 [] dirs[d].name = "dead" ->
                      Put(p, RemoveTree(r, d, "gc_next")) /\ UNCHANGED <<kino, kgen>>
                 \* .tmp-: removed only when its key's lock is free, under that
                 \* lock (Store.zig:504-514: createFile, LOCK_EX | LOCK_NB, removeTree,
                 \* then the deferred close).
                 [] dirs[d].name = "tmp" ->
                      /\ kino' = IF new THEN [kino EXCEPT ![k] = kgen[k] + 1] ELSE kino
                      /\ kgen' = IF new THEN [kgen EXCEPT ![k] = @ + 1] ELSE kgen
                      /\ IF new \/ KFree(i)
                         THEN Put(p, RemoveTree([r EXCEPT !.kfd = i, !.klk = TRUE], d, "gc_unlock"))
                         ELSE Put(p, r)
                 \* An entry: not whole is evicted (Store.zig:516-520); past the cap, the
                 \* layers no job holds go (Store.zig:537-547), any of them here.
                 [] dirs[d].name = "pub" ->
                      /\ IF LooksWhole(d)
                         THEN \/ Put(p, r)
                              \/ Put(p, Evict(r, k, "gc"))
                         ELSE Put(p, Evict(r, k, "gc"))
                      /\ UNCHANGED <<kino, kgen>>
    /\ UNCHANGED <<dirs, sh, ex, gc, ghost>>

GcUnlock(p) ==
    /\ S(p).pc = "gc_unlock"
    /\ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.klk = FALSE, !.pc = "gc_next"])
    /\ UNCHANGED <<fsVars, ghost>>

(* dropKeyLocks (Store.zig:586-599): keys/ listed, each lock file taken  *)
(* exclusively and non-blocking, then its path deleted.                    *)
DkNext(p) ==
    /\ S(p).pc = "dk_next"
    /\ IF S(p).ktodo = {}
       THEN /\ gc' = {} /\ Put(p, [S(p) EXCEPT !.pc = "done"])
       ELSE LET k == CHOOSE x \in S(p).ktodo : TRUE
                r == [S(p) EXCEPT !.ktodo = @ \ {k}]
            IN /\ IF kino[k] # 0 /\ KFree(<<k, kino[k]>>)
                  THEN Put(p, [r EXCEPT !.kfd = <<k, kino[k]>>, !.klk = TRUE, !.pc = "dk_del"])
                  ELSE Put(p, r)
               /\ UNCHANGED gc
    /\ UNCHANGED <<dirs, sh, ex, kino, kgen, ghost>>

DkDel(p) ==
    /\ S(p).pc = "dk_del"
    /\ kino' = [kino EXCEPT ![S(p).kfd[1]] = 0]
    /\ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.klk = FALSE, !.pc = "dk_next"])
    /\ UNCHANGED <<dirs, sh, ex, kgen, gc, ghost>>

-----------------------------------------------------------------------------
(* Store.evict (Store.zig:553-583), from open (a broken entry) or from   *)
(* collect.  It returns whether it removed the entry.                     *)

EvReturn(r, ok) ==
    LET q == [r EXCEPT !.evd = NoDir] IN
    CASE r.evRet = "gc" -> [q EXCEPT !.pc = "gc_next"]
      [] r.evRet = "open" /\ ok -> Missed(q)       \* Store.zig:278
      [] r.evRet = "open" /\ ~ok -> Invalid(q)     \* Store.zig:279

(* The lock file opened by the entry's name (Store.zig:555-557); an      *)
(* entry without one is taken without a lock.  No entry: the rename below *)
(* fails, and so does the eviction.                                       *)
EvOpen(p) ==
    LET P == Pub(S(p).evk) IN
    /\ S(p).pc = "ev_open"
    /\ IF P = {}
       THEN Put(p, EvReturn(S(p), FALSE))
       ELSE LET d == CHOOSE x \in P : TRUE IN
            IF "lock" \in dirs[d].parts
            THEN Put(p, [S(p) EXCEPT !.evd = d, !.pc = "ev_flock"])
            ELSE Put(p, [S(p) EXCEPT !.evd = NoDir, !.pc = "ev_rename"])
    /\ UNCHANGED <<fsVars, ghost>>

(* LOCK_EX | LOCK_NB (Store.zig:569-570): a job holding it keeps it.            *)
EvFlock(p) ==
    LET d == S(p).evd IN
    /\ S(p).pc = "ev_flock"
    /\ IF sh[d] = {} /\ ex[d] = {}
       THEN /\ ex' = [ex EXCEPT ![d] = {p}]
            /\ Put(p, [S(p) EXCEPT !.pc = IF EvictRechecks THEN "ev_same" ELSE "ev_rename"])
       ELSE /\ Put(p, EvReturn(S(p), FALSE)) /\ UNCHANGED ex
    /\ UNCHANGED <<dirs, sh, kino, kgen, gc, ghost>>

(* sameFile on the lock (Store.zig:571, the fix): an entry evicted by       *)
(* another runner since its lock file was opened left that file unlinked *)
(* and free, and the path may name an entry published since.  The lock,  *)
(* on a file no path names, is kept until the deferred close (evict).     *)
EvSame(p) ==
    LET d == S(p).evd IN
    /\ S(p).pc = "ev_same"
    /\ IF d \in Pub(S(p).evk) /\ "lock" \in dirs[d].parts
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "ev_rename"]) /\ UNCHANGED ex
       ELSE /\ ex' = [ex EXCEPT ![d] = {}]
            /\ Put(p, EvReturn(S(p), FALSE))
    /\ UNCHANGED <<dirs, sh, kino, kgen, gc, ghost>>

(* Renamed to .dead-<n> by name (Store.zig:573-579), then removed under   *)
(* the lock (Store.zig:580, the close deferred at Store.zig:558).         *)
EvRename(p) ==
    LET P == Pub(S(p).evk) IN
    /\ S(p).pc = "ev_rename"
    /\ IF P # {}
       THEN LET d == CHOOSE x \in P : TRUE IN
            /\ dirs' = [dirs EXCEPT ![d].name = "dead"]
            /\ Put(p, RemoveTree(S(p), d, "ev_done"))
            /\ UNCHANGED ex
       ELSE /\ ex' = IF S(p).evd = NoDir THEN ex ELSE [ex EXCEPT ![S(p).evd] = {}]
            /\ Put(p, EvReturn(S(p), FALSE))
            /\ UNCHANGED dirs
    /\ UNCHANGED <<sh, kino, kgen, gc, ghost>>

EvDone(p) ==
    /\ S(p).pc = "ev_done"
    /\ ex' = IF S(p).evd = NoDir THEN ex ELSE [ex EXCEPT ![S(p).evd] = {}]
    /\ Put(p, EvReturn(S(p), TRUE))
    /\ UNCHANGED <<dirs, sh, kino, kgen, gc, ghost>>

(* removeTree (Store.zig:616-623 over std.Io.Dir.deleteTree): the        *)
(* directory's entries deleted one at a time in readdir's order through   *)
(* the descriptor it opened, so a directory renamed meanwhile is emptied  *)
(* where it went; the tree's contents go before the tree itself.  Then    *)
(* the directory is removed by the name it had, and a name that names     *)
(* nothing now is no error (deleteTree's FileNotFound).                   *)
Rt(p) ==
    LET d == S(p).rtd IN
    /\ S(p).pc = "rt"
    /\ IF dirs[d].parts # {}
       THEN \E x \in dirs[d].parts :
              /\ dirs' = IF x = "fs" /\ dirs[d].fsOk
                         THEN [dirs EXCEPT ![d].fsOk = FALSE]
                         ELSE [dirs EXCEPT ![d].parts = @ \ {x}]
              /\ UNCHANGED st
       ELSE /\ dirs' = IF dirs[d].name = S(p).rtOrig
                       THEN [dirs EXCEPT ![d] = NoEntry]
                       ELSE dirs
            /\ Put(p, [S(p) EXCEPT !.rtd = NoDir, !.rtOrig = "none", !.pc = S(p).rtRet])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, ghost>>

-----------------------------------------------------------------------------
(* What happens to the processes.                                         *)

(* A process dies between two system calls: the kernel closes its files, *)
(* so its flocks go; what it made stays.                                  *)
Crash(p) ==
    /\ crashes < MaxCrashes
    /\ S(p).pc \notin {"done", "crashed"}
    /\ crashes' = crashes + 1
    /\ Put(p, Dead)
    /\ sh' = [d \in Ids |-> Others(p, sh[d])]
    /\ ex' = [d \in Ids |-> ex[d] \ {p}]
    /\ gc' = gc \ {p}
    /\ UNCHANGED <<dirs, kino, kgen, mcrashes, corrupts, badRead, lostUpper>>

(* The machine dies: every process, and every file's data not synced.     *)
(* Metadata (creates, renames, unlinks) is taken as kept in order, as a   *)
(* journal keeps it: a crash keeping less is a crash at an earlier state, *)
(* with no more synced data, which this action also explores.  Lost data  *)
(* is taken at its worst for a reader: the record and meta survive (so the *)
(* entry still validates) and the tree does not.                          *)
MachineCrash ==
    /\ mcrashes < MachineCrashes
    /\ mcrashes' = mcrashes + 1
    /\ st' = [p \in Procs |-> Dead]
    /\ sh' = [d \in Ids |-> {}]
    /\ ex' = [d \in Ids |-> {}]
    /\ gc' = {}
    /\ dirs' = [d \in Ids |-> IF dirs[d].name # "none" /\ ~dirs[d].synced
                              THEN [dirs[d] EXCEPT !.fsOk = FALSE]
                              ELSE dirs[d]]
    /\ UNCHANGED <<kino, kgen, crashes, corrupts, badRead, lostUpper>>

(* A hand changes an entry's record, its length kept: only open's sha256 *)
(* sees it, and evicts it (Store.zig:276-279).                            *)
Corrupt ==
    /\ corrupts < MaxCorrupts
    /\ \E d \in Ids :
         /\ dirs[d].name = "pub" /\ dirs[d].recOk
         /\ dirs' = [dirs EXCEPT ![d].recOk = FALSE]
    /\ corrupts' = corrupts + 1
    /\ UNCHANGED <<st, sh, ex, kino, kgen, gc, crashes, mcrashes, badRead, lostUpper>>

Terminated == \A p \in Procs : S(p).pc \in {"done", "crashed"}

Proc(p) ==
    \/ LkCreate(p) \/ LkFlock(p) \/ LkSame(p)
    \/ OpFile(p) \/ OpFlock(p) \/ OpSame(p) \/ OpRead(p) \/ Run(p)
    \/ PbMkdir(p) \/ PbWrite(p) \/ PbLock(p) \/ PbMove(p) \/ PbSync(p) \/ PbRename(p)
    \/ PbFail(p) \/ StepEnd(p) \/ End(p)
    \/ GcLock(p) \/ GcNext(p) \/ GcUnlock(p) \/ DkNext(p) \/ DkDel(p)
    \/ EvOpen(p) \/ EvFlock(p) \/ EvSame(p) \/ EvRename(p) \/ EvDone(p) \/ Rt(p)

Next ==
    \/ \E p \in Procs : Proc(p) \/ Crash(p)
    \/ MachineCrash
    \/ Corrupt
    \/ (Terminated /\ UNCHANGED vars)

(* Every process that can take a step takes one; crashes, the machine's  *)
(* and the hand's changes are never forced.                               *)
Spec == Init /\ [][Next]_vars /\ \A p \in Procs : WF_vars(Proc(p))

-----------------------------------------------------------------------------
(* Safety.                                                                *)

(* A job never takes an entry half published, half evicted or wrong.      *)
NoBadRead == ~badRead

(* What a job holds stays published and whole until it lets go: a held    *)
(* layer is never evicted, renamed or emptied under it.                   *)
HeldIntact ==
    \A p \in Procs : \A d \in S(p).held : Intact(d)

(* At most one process runs a step's key at a time (lockKey's purpose).   *)
KeyMutex ==
    \A k \in StepKeys : Cardinality({p \in Procs : S(p).owns /\ S(p).key = k}) <= 1

(* No crash, of a process or the machine, leaves an entry that open would *)
(* take whose tree is not whole.                                          *)
NoWrongValid == \A d \in Ids : Validates(d) => dirs[d].fsOk /\ dirs[d].parts = Parts

(* A step's upper is never deleted under it by another process.           *)
NoLostUpper == ~lostUpper

(* One entry per key (renameat2's NOREPLACE).                             *)
OnePub == \A k \in Keys : Cardinality(Pub(k)) <= 1

-----------------------------------------------------------------------------
(* Liveness, under weak fairness of each process.                         *)

LockPcs == {"lk_create", "lk_flock", "lk_same"}

(* A claim waiting on its key's lock gets it, or is cancelled, or its     *)
(* process dies: a holder that finishes or crashes lets it go on.         *)
WaitEnds == \A p \in Procs : (S(p).pc \in LockPcs) ~> (S(p).pc \notin LockPcs)

(* Every job ends (and with it every blocking flock).                     *)
AllEnd == <>Terminated

(* The processes are interchangeable (safety checks only: TLC's symmetry  *)
(* reduction is unsound for liveness).                                    *)
ProcSymmetry == Permutations(Procs)
=============================================================================
