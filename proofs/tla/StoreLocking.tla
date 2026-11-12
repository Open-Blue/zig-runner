---------------------------- MODULE StoreLocking ----------------------------
(***************************************************************************)
(* Documentation, no longer machine-checked: SPIN checks this module's     *)
(* Promela port, proofs/spin/StoreLockingModel.pml, action for action, and *)
(* the .cfg files' spin-states lines are SPIN's counts, the reference      *)
(* (proofs/README.md).                                                     *)
(*                                                                         *)
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
(* flocks; its files stay), and the machine may die (every process, the    *)
(* data no one synced and the renames no one synced); the jobs after that  *)
(* are the first of a boot (Store.checkOncePerBoot).                       *)
(*                                                                         *)
(* Every action names the code it stands for by function, as line numbers *)
(* do not last.  Paths are relative to runner/src/native/.                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs,          \* the runner processes sharing the store
    StepKeys,       \* keys of steps run under their key's lock (claimKey)
    BuildKeys,      \* keys of Dockerfile build layers (layers.zig)
    Steps,          \* steps per job
    MaxCrashes,     \* process crashes, all told
    MachineCrashes, \* machine crashes (0 or 1); a job after one is the first of a boot
    MaxCorrupts,    \* entries a hand changes behind the store's back
    MaxWriteErrors, \* syncs the disk fails during a publish
    OldEntry,       \* the store starts with an entry an older store_format left
    BuildHoldsKeyLock, \* layers.zig takes the key's lock around its publish (the fix)
    SyncBeforePublish, \* publishTimed syncs the entry before the rename
    HeedSyncErrors,    \* publishTimed fails when a sync fails (error.Sync)
    SyncLayersAtEnd,   \* a job that published fsyncs layers/ at its end (syncLayers)
    CheckAfterBoot,    \* the first job of a boot checks every tree (checkOncePerBoot)
    EvictRechecks,     \* evict checks its lock is on the file the path names (the fix)
    BuildLooksUpFirst, \* layers.zig looks its key up under the key's lock before it publishes
    EvictUnlocks       \* evict's deferred close lets its exclusive lock go

ASSUME StepKeys \cap BuildKeys = {} /\ Steps \in Nat \ {0}

Keys == StepKeys \cup BuildKeys

(* The entry an older store_format left: every key holds the format, so   *)
(* no job's key finds it, and to collect it is not whole (Meta.parse       *)
(* refuses the format), whichever bump left it (#317 the last).            *)
OldKey == "old"
AllKeys == Keys \cup {OldKey}

(* A layers/ directory, by who made it: in one life of the machine (an    *)
(* epoch, one more for each crash) process p's step i builds at most one  *)
(* entry (publishTimed's `.tmp-<key>-<random>`), so <<p, i, e>> names a   *)
(* directory for its whole life, whatever it is renamed to.  A job after  *)
(* a crash has one step: it is there to see what the crash left.          *)
Ids == (Procs \X (1..Steps) \X {0}) \cup
       (Procs \X {1} \X (1..MachineCrashes)) \cup {<<OldKey, 1, 0>>}
OldId == <<OldKey, 1, 0>>
NoDir == <<>>
NoFd == <<>>

(* An entry's files (Store.zig's header): `meta`, the record (`log` and   *)
(* `fc`, checked together against meta), the layer's `lock` and the tree  *)
(* `fs`.                                                                  *)
Parts == {"meta", "rec", "lock", "fs"}

VARIABLES
    st,      \* each process's program counter and locals
    dirs,    \* layers/: each directory's name, key, files and their state
    sh,      \* the descriptors (Fd) holding each entry's lock file shared
    ex,      \* ... and exclusively (at most one)
    kino,    \* keys/<k>.lock: the generation of the file the path names, 0 for none
    kgen,    \* the last generation made, so a file made again is a new inode
    gc,      \* who holds gc.lock (collect, checkOncePerBoot)
    booted,  \* the store's `boot` mark names this boot (checkOncePerBoot finished)
    crashes, mcrashes, corrupts, werrors,
    badRead,   \* ghost: a job took an entry that was not whole and right
    lostUpper, \* ghost: a step's upper was deleted under it
    promised   \* ghost: entries a job that ended had published

vars == <<st, dirs, sh, ex, kino, kgen, gc, booted, crashes, mcrashes, corrupts, werrors,
          badRead, lostUpper, promised>>
fsVars == <<dirs, sh, ex, kino, kgen, gc, booted>>
ghost == <<crashes, mcrashes, corrupts, werrors, badRead, lostUpper, promised>>

(* A process's locals.  `kfd` is its open keys/<k>.lock (an inode, <<key, *)
(* generation>>) and `klk` whether it holds that inode's flock; `owns`,   *)
(* that it passed lockKey's check and is running the key.  `od` is open's *)
(* lock file, `evd` evict's, `held` the job's layers (Backend.held),      *)
(* `pubd` the steps' entries it published (Backend.published), `life` the *)
(* epoch it runs in.                                                      *)
Idle == [pc |-> "start", step |-> 1, key |-> CHOOSE k \in Keys : TRUE, mode |-> "step",
         after |-> "op_file", kfd |-> NoFd, klk |-> FALSE, owns |-> FALSE, keyed |-> FALSE,
         od |-> NoDir, moved |-> FALSE, held |-> {}, evk |-> CHOOSE k \in Keys : TRUE,
         evd |-> NoDir, evRet |-> "open", rtd |-> NoDir, rtOrig |-> "none", rtRet |-> "start",
         todo |-> {}, ktodo |-> {}, lost |-> FALSE, werr |-> FALSE, life |-> 0, pubd |-> {}]

Dead == [Idle EXCEPT !.pc = "crashed"]

(* Step i begins, the job's layers `h` held: a cached step's key goes     *)
(* through claimKey, a build layer's through layers.Store.get (open       *)
(* without the key's lock).  After the last step, the job's end.  Choosing *)
(* the key touches nothing shared, so it is folded into the step before   *)
(* (StepEnd) and Init: fewer interleavings, the same behaviours.          *)
Begin(i, h, life, pubd) ==
    IF i > (IF life = 0 THEN Steps ELSE 1)
    THEN {[Idle EXCEPT !.step = i, !.held = h, !.life = life, !.pubd = pubd, !.pc = "end"]}
    ELSE {[Idle EXCEPT !.step = i, !.held = h, !.life = life, !.pubd = pubd, !.key = k,
                       !.mode = IF k \in StepKeys THEN "step" ELSE "build",
                       !.pc = IF k \in StepKeys THEN "lk_create" ELSE "op_file",
                       !.after = "op_file"] : k \in Keys}

(* `linked`: the rename that published it is on disk: a publish does not  *)
(* sync it, the job's end does (syncLayers), and until then a crash may   *)
(* lose it, and the entry is a `.tmp-` again.                             *)
NoEntry == [name |-> "none", key |-> CHOOSE k \in Keys : TRUE, parts |-> {},
            fsOk |-> FALSE, recOk |-> FALSE, synced |-> FALSE, linked |-> FALSE, old |-> FALSE]
AnOldEntry == [name |-> "pub", key |-> OldKey, parts |-> Parts, fsOk |-> TRUE,
               recOk |-> TRUE, synced |-> TRUE, linked |-> TRUE, old |-> TRUE]

Pub(k) == {d \in Ids : dirs[d].name = "pub" /\ dirs[d].key = k}
(* No key lock inode is held by anyone.                                   *)
KFree(i) == \A q \in Procs : ~(st[q].klk /\ st[q].kfd = i)

(* readEntry passes: meta parses, this format's, the tree is a directory, *)
(* the record's lengths and sha256s are meta's.  It does not look inside  *)
(* the tree.  One check at one instant: a published entry changes only    *)
(* under its lock taken exclusively, which excludes a reader holding it   *)
(* shared, so in the protocol as fixed nothing changes during the read.   *)
Validates(d) == dirs[d].name = "pub" /\ {"meta", "rec", "fs"} \subseteq dirs[d].parts
                /\ dirs[d].recOk /\ ~dirs[d].old
(* entryLooksWhole: meta, this format's, the tree, the lengths.  The      *)
(* hand's change keeps lengths, so only open's sha256 sees it.            *)
LooksWhole(d) == {"meta", "rec", "fs"} \subseteq dirs[d].parts /\ ~dirs[d].old
(* treeAsCounted: meta parses and the tree takes the bytes it counted.    *)
AsCounted(d) == {"meta", "fs"} \subseteq dirs[d].parts /\ dirs[d].fsOk /\ ~dirs[d].old
(* What a job may use: published, every file there, the tree whole.       *)
Intact(d) == dirs[d].name = "pub" /\ dirs[d].parts = Parts /\ dirs[d].fsOk

TypeOK ==
    /\ \A d \in Ids : dirs[d].name \in {"none", "tmp", "pub", "dead"}
                      /\ dirs[d].parts \subseteq Parts
    /\ \A d \in Ids : sh[d] \subseteq Ids /\ ex[d] \subseteq Procs /\ Cardinality(ex[d]) <= 1
    /\ \A k \in Keys : kino[k] \in Nat /\ kino[k] <= kgen[k]
    /\ gc \subseteq Procs /\ Cardinality(gc) <= 1
    /\ booted \in BOOLEAN

Init ==
    /\ st \in [Procs -> Begin(1, {}, 0, {})]
    /\ dirs = [d \in Ids |-> IF d = OldId /\ OldEntry THEN AnOldEntry ELSE NoEntry]
    /\ sh = [d \in Ids |-> {}]
    /\ ex = [d \in Ids |-> {}]
    /\ kino = [k \in Keys |-> 0]
    /\ kgen = [k \in Keys |-> 0]
    /\ gc = {}
    /\ booted = TRUE
    /\ crashes = 0 /\ mcrashes = 0 /\ corrupts = 0 /\ werrors = 0
    /\ badRead = FALSE /\ lostUpper = FALSE /\ promised = {}

S(p) == st[p]
Me(p) == <<p, st[p].step, st[p].life>>   \* the directory this step publishes from
Put(p, r) == st' = [st EXCEPT ![p] = r]
(* A flock belongs to an open file description, not to a process: a job  *)
(* holding a layer that opens it again holds two locks, and closing one   *)
(* keeps the other.  A process opens at most one lock file per step, so   *)
(* <<p, step, life>> names the descriptor.                                *)
Fd(p) == <<p, st[p].step, st[p].life>>
DropSh(p, d) == sh' = [sh EXCEPT ![d] = @ \ {Fd(p)}]
Others(p, holders) == {t \in holders : t[1] # p}

(* Calls, with the return label in the locals.                            *)
RemoveTree(r, d, ret) == [r EXCEPT !.pc = "rt", !.rtd = d, !.rtOrig = dirs[d].name, !.rtRet = ret]
Evict(r, k, ret) == [r EXCEPT !.pc = "ev_open", !.evk = k, !.evRet = ret]

(* open found nothing to replay.  claimKey (`orelse return .{ .key = k,   *)
(* .lock = lock }`): the step runs keyed.  A build runs (dockerfile.build). *)
(* Its lookup under the key's lock missing (`lookup`, BuildLooksUpFirst): *)
(* it publishes.  Publishing first, a refused rename looks again (`retry`); *)
(* finding nothing, the build fails (`orelse return e`) though a layer was *)
(* there a moment before: `lost`.                                         *)
Missed(r) == CASE r.mode = "step"   -> [r EXCEPT !.pc = "run", !.keyed = TRUE]
               [] r.mode = "build"  -> [r EXCEPT !.pc = "run"]
               [] r.mode = "lookup" -> [r EXCEPT !.pc = "pb_mkdir"]
               [] r.mode = "retry"  -> [r EXCEPT !.pc = "step_end", !.lost = TRUE]

(* open's error.Invalid: the entry is broken and another job holds it.    *)
(* claimKey: the key's lock let go, the step runs uncached.  A build's    *)
(* `try s.store.open` fails the build (layers.Store.get and publish).     *)
Invalid(r) == IF r.mode = "step"
              THEN [r EXCEPT !.pc = "run", !.keyed = FALSE, !.klk = FALSE, !.kfd = NoFd,
                             !.owns = FALSE]
              ELSE [r EXCEPT !.pc = "step_end"]

-----------------------------------------------------------------------------
(* The job's steps.                                                       *)


(* lockKey.  createFile(truncate = false) makes the file when the path    *)
(* names none.                                                            *)
LkCreate(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "lk_create"
    /\ IF kino[k] = 0
       THEN /\ kgen' = [kgen EXCEPT ![k] = @ + 1]
            /\ kino' = [kino EXCEPT ![k] = kgen[k] + 1]
            /\ Put(p, [S(p) EXCEPT !.kfd = <<k, kgen[k] + 1>>, !.pc = "lk_flock"])
       ELSE /\ Put(p, [S(p) EXCEPT !.kfd = <<k, kino[k]>>, !.pc = "lk_flock"])
            /\ UNCHANGED <<kino, kgen>>
    /\ UNCHANGED <<dirs, sh, ex, gc, booted, ghost>>

(* lockKey's flock(LOCK_EX | LOCK_NB); on failure the file is closed, and *)
(* the poll (folded in, as it touches nothing shared) tries again, or a   *)
(* step's wait ends on a cancel or a timeout (`stop`, Backend.abort) and  *)
(* the step fails.  A build's publish waits only for another publish of   *)
(* its layer, and is not cancelled (layers.Store.stop).                   *)
LkFlock(p) ==
    /\ S(p).pc = "lk_flock"
    /\ IF KFree(S(p).kfd)
       THEN Put(p, [S(p) EXCEPT !.klk = TRUE, !.pc = "lk_same"])
       ELSE \/ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.pc = "lk_create"])
            \/ /\ S(p).mode = "step"
               /\ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.pc = "step_end"])
    /\ UNCHANGED <<fsVars, ghost>>

(* sameFile in lockKey: the lock counts only on the file the path names   *)
(* now; else closed (its flock with it) and again.                        *)
LkSame(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "lk_same"
    /\ IF kino[k] # 0 /\ S(p).kfd = <<k, kino[k]>>
       THEN Put(p, [S(p) EXCEPT !.owns = (S(p).mode = "step"), !.pc = S(p).after])
       ELSE Put(p, [S(p) EXCEPT !.klk = FALSE, !.kfd = NoFd, !.pc = "lk_create"])
    /\ UNCHANGED <<fsVars, ghost>>

(* Store.open: the entry's lock file opened (no entry or no lock file: a  *)
(* miss).                                                                 *)
OpFile(p) ==
    LET P == {d \in Pub(S(p).key) : "lock" \in dirs[d].parts} IN
    /\ S(p).pc = "op_file"
    /\ IF P # {}
       THEN Put(p, [S(p) EXCEPT !.od = CHOOSE d \in P : TRUE, !.pc = "op_flock"])
       ELSE Put(p, Missed(S(p)))
    /\ UNCHANGED <<fsVars, ghost>>

(* open's flock(LOCK_SH), blocking: waits out an eviction.                *)
OpFlock(p) ==
    LET d == S(p).od IN
    /\ S(p).pc = "op_flock"
    /\ ex[d] = {}
    /\ sh' = [sh EXCEPT ![d] = @ \cup {Fd(p)}]
    /\ Put(p, [S(p) EXCEPT !.pc = "op_same"])
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, booted, ghost>>

(* open's sameFile: an entry evicted meanwhile leaves the path naming     *)
(* nothing, or another entry's lock: a miss.                              *)
OpSame(p) ==
    LET d == S(p).od IN
    /\ S(p).pc = "op_same"
    /\ IF d \in Pub(S(p).key) /\ "lock" \in dirs[d].parts
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "op_read"])
            /\ UNCHANGED sh
       ELSE /\ DropSh(p, d)
            /\ Put(p, Missed([S(p) EXCEPT !.od = NoDir]))
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, booted, ghost>>

(* open's readEntry.  Whole: the job holds it to its end (Backend.held,   *)
(* layers.Store.held) and the step replays or the build stacks it.  Not   *)
(* whole: closed, then evicted by name.                                   *)
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
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, booted, crashes, mcrashes, corrupts, werrors,
                   lostUpper, promised>>

(* The step's exec or the build's RUN or COPY.  A success is published    *)
(* when the claim has a key: publishTop moves the top layer with          *)
(* Store.publish while the key's lock is held (the claim is released at   *)
(* the step's end).  A build publishes through layers.Store.publish,      *)
(* which takes the key's lock first when BuildHoldsKeyLock and did not    *)
(* before, and under it looks the key up before it publishes when         *)
(* BuildLooksUpFirst (`lookup`), or publishes first (`retry`) as #299 did. *)
Run(p) ==
    /\ S(p).pc = "run"
    /\ \E ok \in BOOLEAN :
         Put(p, IF ok /\ S(p).mode = "build" /\ BuildHoldsKeyLock /\ BuildLooksUpFirst
                THEN [S(p) EXCEPT !.pc = "lk_create", !.after = "op_file", !.mode = "lookup"]
                ELSE IF ok /\ S(p).mode = "build" /\ BuildHoldsKeyLock
                THEN [S(p) EXCEPT !.pc = "lk_create", !.after = "pb_mkdir"]
                ELSE IF ok /\ (S(p).mode = "build" \/ S(p).keyed)
                THEN [S(p) EXCEPT !.pc = "pb_mkdir"]
                ELSE [S(p) EXCEPT !.pc = "step_end"])
    /\ UNCHANGED <<fsVars, ghost>>

(* Store.publishTimed.  layers/.tmp-<key>-<n> made.  Nothing of it is on  *)
(* disk until its sync.                                                   *)
PbMkdir(p) ==
    /\ S(p).pc = "pb_mkdir"
    /\ dirs' = [dirs EXCEPT ![Me(p)] = [NoEntry EXCEPT !.name = "tmp", !.key = S(p).key,
                                                       !.fsOk = TRUE, !.recOk = TRUE]]
    /\ Put(p, [S(p) EXCEPT !.moved = FALSE, !.pc = "pb_write"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, ghost>>

Gone(p) == dirs[Me(p)].name = "none"

(* log and fc written; into a directory that is gone they fail, and the   *)
(* errdefer runs.                                                         *)
PbWrite(p) ==
    /\ S(p).pc = "pb_write"
    /\ IF Gone(p)
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED dirs
       ELSE /\ dirs' = [dirs EXCEPT ![Me(p)].parts = @ \cup {"rec"}]
            /\ Put(p, [S(p) EXCEPT !.pc = "pb_lock"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, ghost>>

(* The lock file made and held shared before the entry is visible.        *)
PbLock(p) ==
    /\ S(p).pc = "pb_lock"
    /\ IF Gone(p)
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED <<dirs, sh>>
       ELSE /\ ex[Me(p)] = {}
            /\ dirs' = [dirs EXCEPT ![Me(p)].parts = @ \cup {"lock"}]
            /\ sh' = [sh EXCEPT ![Me(p)] = @ \cup {Fd(p)}]
            /\ Put(p, [S(p) EXCEPT !.pc = "pb_move"])
    /\ UNCHANGED <<ex, kino, kgen, gc, booted, ghost>>

(* The upper renamed in as fs.                                            *)
PbMove(p) ==
    /\ S(p).pc = "pb_move"
    /\ IF Gone(p)
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED dirs
       ELSE /\ dirs' = [dirs EXCEPT ![Me(p)].parts = @ \cup {"fs"}, ![Me(p)].fsOk = TRUE]
            /\ Put(p, [S(p) EXCEPT !.moved = TRUE, !.pc = "pb_back"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, ghost>>

(* A sync that fails (`syncFails`, a write the disk refused): publishTimed *)
(* fails with error.Sync, unless HeedSyncErrors is off, the mutant.       *)
SyncFails == werrors < MaxWriteErrors /\ werrors' = werrors + 1

(* writeBack: the tree's data written and waited for, no journal commit,  *)
(* so nothing here is durable yet (a large tree's syncDisk is the same    *)
(* step and the next one at once; the model takes the fsyncs' promise     *)
(* only in pb_sync, and a syncfs keeps it).  Since #309 the meta comes     *)
(* after this, so it counts a tree that is written (treeBytes).           *)
PbBack(p) ==
    /\ S(p).pc = "pb_back"
    /\ \/ /\ werrors' = werrors
          /\ Put(p, [S(p) EXCEPT !.pc = "pb_meta"])
       \/ /\ SyncFails
          /\ Put(p, [S(p) EXCEPT !.werr = TRUE,
                                 !.pc = IF HeedSyncErrors THEN "pb_fail" ELSE "pb_meta"])
    /\ UNCHANGED <<fsVars, crashes, mcrashes, corrupts, badRead, lostUpper, promised>>

(* The meta written and its writeback started, after the tree: one journal *)
(* commit takes the entry whole (#309).  Into a directory that is gone it *)
(* fails.                                                                 *)
PbMeta(p) ==
    /\ S(p).pc = "pb_meta"
    /\ IF Gone(p)
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED dirs
       ELSE /\ dirs' = [dirs EXCEPT ![Me(p)].parts = @ \cup {"meta"}]
            /\ Put(p, [S(p) EXCEPT !.pc = "pb_sync"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, ghost>>

(* syncEntries, every file and directory fsynced from its threads, and    *)
(* the meta's fsync (or syncDisk).  Everything the rename will name is on *)
(* disk.  A failed one is error.Sync.  The model credits only this entry. *)
PbSync(p) ==
    /\ S(p).pc = "pb_sync"
    /\ \/ /\ IF SyncBeforePublish /\ ~Gone(p)
             THEN dirs' = [dirs EXCEPT ![Me(p)].synced = TRUE]
             ELSE UNCHANGED dirs
          /\ werrors' = werrors
          /\ Put(p, [S(p) EXCEPT !.pc = "pb_rename"])
       \/ /\ SyncFails
          /\ UNCHANGED dirs
          /\ Put(p, [S(p) EXCEPT !.werr = TRUE,
                                 !.pc = IF HeedSyncErrors THEN "pb_fail" ELSE "pb_rename"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, crashes, mcrashes, corrupts, badRead,
                   lostUpper, promised>>

(* renameat2(RENAME_NOREPLACE): visible whole, or not at all when the key *)
(* has an entry.  The job holds it from here (publishTop; layers.Store),  *)
(* and a step's goes on the job's list for syncLayers (Backend.published; *)
(* a build layer's does not, so a crash may lose its rename: a miss).     *)
PbRename(p) ==
    /\ S(p).pc = "pb_rename"
    /\ IF dirs[Me(p)].name = "tmp" /\ Pub(S(p).key) = {}
       THEN /\ dirs' = [dirs EXCEPT ![Me(p)].name = "pub"]
            /\ Put(p, [S(p) EXCEPT !.held = @ \cup {Me(p)}, !.moved = FALSE, !.pc = "step_end",
                                   !.pubd = IF S(p).mode = "step" THEN @ \cup {Me(p)} ELSE @])
       ELSE /\ Put(p, [S(p) EXCEPT !.pc = "pb_fail"]) /\ UNCHANGED dirs
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, ghost>>

(* publish's errdefer: the lock closed, the upper renamed back when it    *)
(* moved, and the temporary entry removed; an upper that cannot be put    *)
(* back is left there and logged.  A step goes on uncached (publishTop);  *)
(* a build takes the entry that won (layers.Store.publish: open again).   *)
PbFail(p) ==
    LET d == Me(p)
        next == IF S(p).mode = "build" THEN "op_file" ELSE "step_end"
        \* After a lookup under the lock missed, a refused publish fails the build (`try`);
        \* a disk that failed the sync fails it honestly.
        r == [S(p) EXCEPT !.moved = FALSE,
                          !.mode = IF S(p).mode = "build" THEN "retry" ELSE @,
                          !.lost = (S(p).mode = "lookup" /\ ~S(p).werr)]
        back == ~S(p).moved \/ "fs" \in dirs[d].parts
    IN
    /\ S(p).pc = "pb_fail"
    /\ DropSh(p, d)
    /\ lostUpper' = (lostUpper \/ (S(p).moved /\ ~("fs" \in dirs[d].parts /\ dirs[d].fsOk)))
    /\ IF S(p).moved /\ "fs" \in dirs[d].parts
       THEN dirs' = [dirs EXCEPT ![d].parts = @ \ {"fs"}]
       ELSE UNCHANGED dirs
    /\ Put(p, IF back /\ ~Gone(p) THEN RemoveTree(r, d, next) ELSE [r EXCEPT !.pc = next])
    /\ UNCHANGED <<ex, kino, kgen, gc, booted, crashes, mcrashes, corrupts, werrors, badRead,
                   promised>>

(* The claim released (`defer claim.release`; layers.Store.publish's key  *)
(* lock's `defer`).                                                       *)
StepEnd(p) ==
    /\ S(p).pc = "step_end"
    /\ \E r \in Begin(S(p).step + 1, S(p).held, S(p).life, S(p).pubd) : Put(p, r)
    /\ UNCHANGED <<fsVars, ghost>>

(* The job's end (Backend.deinit): its layers let go, layers/ fsynced if  *)
(* it published (syncLayers: every rename so far is on disk, and the      *)
(* model credits what the directory held), then collect.                 *)
End(p) ==
    /\ S(p).pc = "end"
    /\ sh' = [d \in Ids |-> IF d \in S(p).held THEN Others(p, sh[d]) ELSE sh[d]]
    /\ Put(p, [S(p) EXCEPT !.held = {}, !.pc = "end_sync"])
    /\ UNCHANGED <<dirs, ex, kino, kgen, gc, booted, ghost>>

EndSync(p) ==
    /\ S(p).pc = "end_sync"
    /\ IF S(p).pubd # {} /\ SyncLayersAtEnd
       THEN dirs' = [d \in Ids |-> IF dirs[d].name = "pub"
                                   THEN [dirs[d] EXCEPT !.linked = TRUE] ELSE dirs[d]]
       ELSE UNCHANGED dirs
    /\ promised' = promised \cup {d \in S(p).pubd : dirs[d].name = "pub"}
    /\ Put(p, [S(p) EXCEPT !.pubd = {}, !.pc = "gc_lock"])
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, crashes, mcrashes, corrupts, werrors,
                   badRead, lostUpper>>

-----------------------------------------------------------------------------
(* Store.collect.                                                         *)

(* gc.lock, exclusive and non-blocking; layers/ listed.  An entry made    *)
(* after the listing may be missed, as readdir allows.                    *)
GcLock(p) ==
    /\ S(p).pc = "gc_lock"
    /\ IF gc = {}
       THEN /\ gc' = {p}
            /\ Put(p, [S(p) EXCEPT !.todo = {d \in Ids : dirs[d].name # "none"},
                                   !.pc = "gc_next"])
       ELSE /\ Put(p, [S(p) EXCEPT !.pc = "done"]) /\ UNCHANGED gc
    /\ UNCHANGED <<dirs, sh, ex, kino, kgen, booted, ghost>>

(* readdir's order, fixed here (every interleaving with the other         *)
(* processes is still explored), as the lister p sees it: by the step     *)
(* that made a directory, then its epoch, then p's own before the other   *)
(* runners'; directories of two other runners alike in all three come in  *)
(* either order.  An order by the runners' names (a CHOOSE over the ids,  *)
(* which name them, as the model had it before) tells the runners apart,  *)
(* and ProcSymmetry then leaves behaviours unexplored: with that CHOOSE,  *)
(* StoreLocking-boot-check.cfg has 536,011 states without the symmetry    *)
(* and 205,674 with it, fewer than the 268,006 orbits at least that two   *)
(* runners' symmetry leaves.  With First the two counts are 382,279 and   *)
(* 191,178: every orbit.                                                  *)
Rank(p, d) == (d[2] * (MachineCrashes + 1) + d[3]) * 2 + (IF d[1] = p THEN 0 ELSE 1)
First(p, T) == {d \in T : \A x \in T : Rank(p, d) <= Rank(p, x)}

(* One entry, by the name it has now, the first of the listing left.      *)
GcNext(p) ==
    /\ S(p).pc = "gc_next"
    /\ IF S(p).todo = {}
       THEN /\ Put(p, [S(p) EXCEPT !.ktodo = {k \in Keys : kino[k] # 0}, !.pc = "dk_next"])
            /\ UNCHANGED <<kino, kgen>>
       ELSE \E d \in First(p, S(p).todo) : LET
                k == dirs[d].key
                r == [S(p) EXCEPT !.todo = @ \ {d}]
                new == kino[k] = 0
                i == IF new THEN <<k, kgen[k] + 1>> ELSE <<k, kino[k]>>
            IN CASE dirs[d].name = "none" ->
                      Put(p, r) /\ UNCHANGED <<kino, kgen>>
                 \* .dead-: removed
                 [] dirs[d].name = "dead" ->
                      Put(p, RemoveTree(r, d, "gc_next")) /\ UNCHANGED <<kino, kgen>>
                 \* .tmp-: removed only when its key's lock is free, under that lock
                 \* (createFile, LOCK_EX | LOCK_NB, removeTree, then the deferred close).
                 [] dirs[d].name = "tmp" ->
                      /\ kino' = IF new THEN [kino EXCEPT ![k] = kgen[k] + 1] ELSE kino
                      /\ kgen' = IF new THEN [kgen EXCEPT ![k] = @ + 1] ELSE kgen
                      /\ IF new \/ KFree(i)
                         THEN Put(p, RemoveTree([r EXCEPT !.kfd = i, !.klk = TRUE], d, "gc_unlock"))
                         ELSE Put(p, r)
                 \* An entry: not whole (an older format's among them) is evicted; past
                 \* the cap, the layers no job holds go, any of them here.
                 [] dirs[d].name = "pub" ->
                      /\ IF LooksWhole(d)
                         THEN \/ Put(p, r)
                              \/ Put(p, Evict(r, k, "gc"))
                         ELSE Put(p, Evict(r, k, "gc"))
                      /\ UNCHANGED <<kino, kgen>>
    /\ UNCHANGED <<dirs, sh, ex, gc, booted, ghost>>

GcUnlock(p) ==
    /\ S(p).pc = "gc_unlock"
    /\ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.klk = FALSE, !.pc = "gc_next"])
    /\ UNCHANGED <<fsVars, ghost>>

(* dropKeyLocks: keys/ listed, each lock file taken exclusively and       *)
(* non-blocking, then its path deleted.                                   *)
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
    /\ UNCHANGED <<dirs, sh, ex, kino, kgen, booted, ghost>>

DkDel(p) ==
    /\ S(p).pc = "dk_del"
    /\ kino' = [kino EXCEPT ![S(p).kfd[1]] = 0]
    /\ Put(p, [S(p) EXCEPT !.kfd = NoFd, !.klk = FALSE, !.pc = "dk_next"])
    /\ UNCHANGED <<dirs, sh, ex, kgen, gc, booted, ghost>>

-----------------------------------------------------------------------------
(* Store.checkOncePerBoot, before a job's first step (Backend.init): a job *)
(* that finds the mark goes on; else it waits for gc.lock (blocking, as a *)
(* collect holds it a moment), looks at the mark again, and evicts every  *)
(* entry whose tree is not what meta counted.  A job waits for the check, *)
(* so no job holds a layer it could evict.                                *)
Boot(p) ==
    /\ S(p).pc = "boot"
    /\ IF booted \/ ~CheckAfterBoot
       THEN /\ \E r \in Begin(1, {}, S(p).life, {}) : Put(p, r)
            /\ UNCHANGED gc
       ELSE /\ gc = {}
            /\ gc' = {p}
            /\ Put(p, [S(p) EXCEPT !.todo = {d \in Ids : dirs[d].name = "pub"}, !.pc = "bc_next"])
    /\ UNCHANGED <<dirs, sh, ex, kino, kgen, booted, ghost>>

BcNext(p) ==
    /\ S(p).pc = "bc_next"
    /\ IF S(p).todo = {}
       THEN /\ booted' = TRUE
            /\ gc' = {}
            /\ \E r \in Begin(1, {}, S(p).life, {}) : Put(p, r)
       ELSE \E d \in First(p, S(p).todo) : LET
                r == [S(p) EXCEPT !.todo = @ \ {d}]
            IN /\ IF dirs[d].name = "pub" /\ ~AsCounted(d)
                  THEN Put(p, Evict(r, dirs[d].key, "bc"))
                  ELSE Put(p, r)
               /\ UNCHANGED <<booted, gc>>
    /\ UNCHANGED <<dirs, sh, ex, kino, kgen, ghost>>

-----------------------------------------------------------------------------
(* Store.evict, from open (a broken entry), from collect or from the check *)
(* after a boot.  It returns whether it removed the entry.                *)

EvReturn(r, ok) ==
    LET q == [r EXCEPT !.evd = NoDir] IN
    CASE r.evRet = "gc" -> [q EXCEPT !.pc = "gc_next"]
      [] r.evRet = "bc" -> [q EXCEPT !.pc = "bc_next"]
      [] r.evRet = "open" /\ ok -> Missed(q)       \* open: null, a miss
      [] r.evRet = "open" /\ ~ok -> Invalid(q)     \* open: error.Invalid

(* The lock file opened by the entry's name; an entry without one is      *)
(* taken without a lock.  No entry: the rename below fails, and so does   *)
(* the eviction.                                                          *)
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

(* evictOpened's LOCK_EX | LOCK_NB: a job holding it keeps it.            *)
EvFlock(p) ==
    LET d == S(p).evd IN
    /\ S(p).pc = "ev_flock"
    /\ IF sh[d] = {} /\ ex[d] = {}
       THEN /\ ex' = [ex EXCEPT ![d] = {p}]
            /\ Put(p, [S(p) EXCEPT !.pc = IF EvictRechecks THEN "ev_same" ELSE "ev_rename"])
       ELSE /\ Put(p, EvReturn(S(p), FALSE)) /\ UNCHANGED ex
    /\ UNCHANGED <<dirs, sh, kino, kgen, gc, booted, ghost>>

(* sameFile on the lock (the fix): an entry evicted by another runner     *)
(* since its lock file was opened left that file unlinked and free, and   *)
(* the path may name an entry published since.  The lock, on a file no    *)
(* path names, is kept until the deferred close (evict).                  *)
EvSame(p) ==
    LET d == S(p).evd IN
    /\ S(p).pc = "ev_same"
    /\ IF d \in Pub(S(p).evk) /\ "lock" \in dirs[d].parts
       THEN /\ Put(p, [S(p) EXCEPT !.pc = "ev_rename"]) /\ UNCHANGED ex
       ELSE /\ ex' = [ex EXCEPT ![d] = {}]
            /\ Put(p, EvReturn(S(p), FALSE))
    /\ UNCHANGED <<dirs, sh, kino, kgen, gc, booted, ghost>>

(* Renamed to .dead-<n> by name, then removed under the lock (the close   *)
(* is evict's `defer`).                                                   *)
EvRename(p) ==
    LET P == Pub(S(p).evk) IN
    /\ S(p).pc = "ev_rename"
    /\ IF P # {}
       THEN LET d == CHOOSE x \in P : TRUE IN
            /\ dirs' = [dirs EXCEPT ![d].name = "dead"]
            \* Removed by the dead name, which it has from here on.
            /\ Put(p, [RemoveTree(S(p), d, "ev_done") EXCEPT !.rtOrig = "dead"])
            /\ UNCHANGED ex
       ELSE /\ ex' = IF S(p).evd = NoDir THEN ex ELSE [ex EXCEPT ![S(p).evd] = {}]
            /\ Put(p, EvReturn(S(p), FALSE))
            /\ UNCHANGED dirs
    /\ UNCHANGED <<sh, kino, kgen, gc, booted, ghost>>

(* The deferred close.  Without it (~EvictUnlocks, a liveness mutant) the *)
(* lock stays on the unlinked file, and open's blocking LOCK_SH on it,     *)
(* opened before the rename, waits for ever.                               *)
EvDone(p) ==
    /\ S(p).pc = "ev_done"
    /\ ex' = IF S(p).evd = NoDir \/ ~EvictUnlocks THEN ex ELSE [ex EXCEPT ![S(p).evd] = {}]
    /\ Put(p, EvReturn(S(p), TRUE))
    /\ UNCHANGED <<dirs, sh, kino, kgen, gc, booted, ghost>>

(* removeTree over std.Io.Dir.deleteTree: the directory's entries deleted *)
(* one at a time in readdir's order through the descriptor it opened, so  *)
(* a directory renamed meanwhile is emptied where it went; the tree's     *)
(* contents go before the tree itself.  Then the directory is removed by  *)
(* the name it had, and a name that names nothing now is no error         *)
(* (deleteTree's FileNotFound).                                           *)
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
    /\ UNCHANGED <<sh, ex, kino, kgen, gc, booted, ghost>>

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
    /\ UNCHANGED <<dirs, kino, kgen, booted, mcrashes, corrupts, werrors, badRead, lostUpper,
                   promised>>

(* The machine dies: every process, every file's data no one synced, and  *)
(* any publish's rename no directory sync covered (syncLayers), which     *)
(* leaves the entry a `.tmp-` again.  Other metadata (creates, renames,   *)
(* unlinks) is taken as kept in order, as a journal keeps it: a crash     *)
(* keeping less is a crash at an earlier state, with no more synced data, *)
(* which this action also explores.  Lost data is taken at its worst for  *)
(* a reader: the record and meta survive (so the entry still validates)   *)
(* and the tree does not.  Every process starts again, a job of one step  *)
(* of the new boot, whose mark is not there yet.                          *)
MachineCrash ==
    /\ mcrashes < MachineCrashes
    /\ mcrashes' = mcrashes + 1
    /\ st' = [p \in Procs |-> [Idle EXCEPT !.pc = "boot", !.life = mcrashes + 1]]
    /\ sh' = [d \in Ids |-> {}]
    /\ ex' = [d \in Ids |-> {}]
    /\ gc' = {}
    /\ booted' = FALSE
    /\ \E lost \in SUBSET {d \in Ids : dirs[d].name = "pub" /\ ~dirs[d].linked} :
         dirs' = [d \in Ids |->
                    LET e == IF d \in lost THEN [dirs[d] EXCEPT !.name = "tmp"] ELSE dirs[d]
                    IN IF e.name # "none" /\ ~e.synced THEN [e EXCEPT !.fsOk = FALSE] ELSE e]
    /\ UNCHANGED <<kino, kgen, crashes, corrupts, werrors, badRead, lostUpper, promised>>

(* A hand changes an entry's record, its length kept: only open's sha256 *)
(* sees it, and evicts it.                                                *)
Corrupt ==
    /\ corrupts < MaxCorrupts
    /\ \E d \in Ids :
         /\ dirs[d].name = "pub" /\ dirs[d].recOk
         /\ dirs' = [dirs EXCEPT ![d].recOk = FALSE]
    /\ corrupts' = corrupts + 1
    /\ UNCHANGED <<st, sh, ex, kino, kgen, gc, booted, crashes, mcrashes, werrors, badRead,
                   lostUpper, promised>>

Terminated == \A p \in Procs : S(p).pc \in {"done", "crashed"}

Proc(p) ==
    \/ LkCreate(p) \/ LkFlock(p) \/ LkSame(p)
    \/ OpFile(p) \/ OpFlock(p) \/ OpSame(p) \/ OpRead(p) \/ Run(p)
    \/ PbMkdir(p) \/ PbWrite(p) \/ PbLock(p) \/ PbMove(p) \/ PbBack(p) \/ PbMeta(p)
    \/ PbSync(p) \/ PbRename(p) \/ PbFail(p) \/ StepEnd(p) \/ End(p) \/ EndSync(p)
    \/ GcLock(p) \/ GcNext(p) \/ GcUnlock(p) \/ DkNext(p) \/ DkDel(p)
    \/ Boot(p) \/ BcNext(p)
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

(* A build that built its layer gets one: its own published, or the one  *)
(* another builder stored.  Publishing first, a refused rename then a    *)
(* collect evicting the other builder's layer before the lookup failed   *)
(* the build for nothing (found by store_stress.zig, after #299).         *)
NoBuildLost == \A p \in Procs : ~S(p).lost

(* syncLayers' promise: a step's entry a finished job published is not    *)
(* lost by a crash.  An eviction may take it; a crash may not put it back *)
(* to a `.tmp-`.                                                          *)
NoLostPublish == \A d \in promised : dirs[d].name # "tmp"

(* An older format's entry does not stay: no key reaches it, so nothing   *)
(* but collect can take it, and every job's end does.  Under the cap it   *)
(* goes all the same: it is not whole to collect (entryLooksWhole), so an *)
(* upgrade across store_format empties layers/ at its first job's end,     *)
(* not "under the cap".                                                   *)
OldGoes == (Terminated /\ crashes = 0) => dirs[OldId].name = "none"

-----------------------------------------------------------------------------
(* Liveness, under weak fairness of each process.                         *)

LockPcs == {"lk_create", "lk_flock", "lk_same"}

(* A claim waiting on its key's lock gets it, or is cancelled, or its     *)
(* process dies: a holder that finishes or crashes lets it go on.         *)
WaitEnds == \A p \in Procs : (S(p).pc \in LockPcs) ~> (S(p).pc \notin LockPcs)

(* Every job ends (and with it every blocking flock).                     *)
AllEnd == <>Terminated

(* The processes are interchangeable (safety checks only: TLC's symmetry  *)
(* reduction is unsound for liveness).  No expression names one, and the  *)
(* CHOOSEs left are over keys, which name none, or over Pub(k), one entry *)
(* at most (OnePub), so they choose the same whatever the runners' names. *)
(* The listings' order is First's.                                         *)
ProcSymmetry == Permutations(Procs)
=============================================================================
