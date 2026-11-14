---------------------------- MODULE StoreDeferred ----------------------------
(***************************************************************************)
(* Documentation, no longer machine-checked: SPIN checks this module's     *)
(* Promela port, proofs/spin/StoreDeferredModel.pml, action for action,    *)
(* and the .cfg files' spin-states lines are SPIN's counts, the reference  *)
(* (proofs/README.md).                                                     *)
(*                                                                         *)
(* The native layer store's deferred sync (runner/src/native/Store.zig,   *)
(* `publishTimed`, `settlePending`, `readEntry`; Backend.zig, `deinit`;    *)
(* docs/native-backend.md, "A job's last layer is made durable after its   *)
(* result").  A publish does not wait for its layer's data: it renames the *)
(* entry in with a meta that says `pending` and names the boot (the        *)
(* kernel's boot_id).  The job makes the previous layer durable when it    *)
(* publishes the next one, and the last at its end, after its result was   *)
(* reported: the data synced, then the meta written again as durable       *)
(* (meta.new, fsynced, renamed over meta, its directory fsynced).          *)
(*                                                                         *)
(* StoreLocking.tla models the locking and an entry that is durable when   *)
(* it is renamed in; this module models what that one cannot, the entry    *)
(* that is not: one runner's job a process, its entries its own (no key    *)
(* contention: that is StoreLocking's).  A machine crash keeps the data    *)
(* that was synced and the meta file that was committed, and loses any     *)
(* rename no directory sync covered.  Within a boot, write-back may lose a *)
(* pending layer's data (EIO, the pages then clean and dropped: WbLoss);   *)
(* the writer's settle finds out (the job's descriptor), refuses the layer *)
(* at once whoever holds it, and no other job may take a pending layer at  *)
(* all (OwnerOnly): a runner killed before its settle leaves one nobody    *)
(* vouches for, and `collect` evicts it when no job holds it.  Readers     *)
(* are other jobs: they hold what they open.                               *)
(*                                                                         *)
(* The ends' settles may share one syncfs (BatchAtEnd; Store.settleEnd):  *)
(* a job's end joins the batch being gathered (JoinBatch), the batch's     *)
(* syncfs begins for those that joined (BatchStart, one batch at a time,   *)
(* and a job may join the next while it runs), and ends (BatchEnd): it     *)
(* fails if any layer of the batch lost its data or the disk fails it, and *)
(* then every job of the batch poisons its layer, as SettleD's failure     *)
(* does; it succeeds only with every layer's data on disk, and each job    *)
(* then writes its own durable meta (SettleM, SettleC).  That the settle   *)
(* descriptor reports what each job's own would (it took the superblock's  *)
(* error state no later than any job's, Store.end_batch) is what the       *)
(* model's syncfs relies on, as SettleD relies on the job's descriptor.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Procs,          \* the runners
    Readers,        \* other jobs, which open and hold layers
    MaxRunnerCrashes, \* runners killed between two steps (0 or 1)
    Steps,          \* layers a job publishes, one a step
    MachineCrashes, \* machine crashes, 0 or 1
    MaxWriteErrors, \* deferred syncs the disk fails
    SyncBeforeMark, \* the mark durable is written after the data's fsyncs (the fix)
    CheckBoot,      \* a pending mark of another boot or mount is refused
    OwnerOnly,      \* only the publishing job takes its pending layer (the fix)
    PoisonOnFail,   \* a failed settle refuses the layer at once, whoever holds it (the fix)
    SettleAtEnd,    \* the job's end makes its last layer durable
    BatchAtEnd,     \* the ends' settles share a batch's syncfs
    BatchSyncFirst  \* a batch's jobs are marked durable after its syncfs (the fix)

ASSUME Steps \in Nat \ {0} /\ MachineCrashes \in 0..1

Ents == Procs \X (1..Steps)

VARIABLES
    pc,       \* each runner: "step", "settle_d", "settle_m", "settle_c", "dirsync", "done", "batch"
    cur,      \* the layer of the runner's job not yet durable, <<>> for none
    vis,      \* the entry is renamed into layers/ and not evicted
    linked,   \* its rename is on disk (layers/ was fsynced after it)
    meta,     \* what the meta file says: "none", "pending" or "durable"
    pboot,    \* the boot a pending meta names
    mcommit,  \* the durable meta is on disk
    ddata,    \* the tree's data is on disk
    tree,     \* what a read of the tree gives: "whole" or "broken"
    boot,     \* the machine's boot id, as a number
    werrors,
    poisoned, \* the layer's meta was renamed away: no lookup takes it
    held,     \* each reader's layers
    alive,    \* the runner has not been killed
    rcrashes,
    badHold,  \* ghost: a reader took a layer whose tree was not whole
    evicted,  \* ghost: an entry taken out after a failed sync
    promised, \* ghost: the entries of jobs whose end has finished
    inb,      \* the runners whose ends joined the batch not yet syncing
    flying    \* the runners of the batch whose syncfs runs

vars == <<pc, cur, vis, linked, meta, pboot, mcommit, ddata, tree, boot, werrors, poisoned, held,
          alive, rcrashes, badHold, evicted, promised, inb, flying>>
others == <<poisoned, held, alive, rcrashes, badHold, inb, flying>>

TypeOK ==
    /\ pc \in [Procs -> {"step", "settle_d", "settle_m", "settle_c", "dirsync", "done", "batch"}]
    /\ meta \in [Ents -> {"none", "pending", "durable"}]
    /\ tree \in [Ents -> {"whole", "broken"}]

Init ==
    /\ pc = [p \in Procs |-> "step"]
    /\ cur = [p \in Procs |-> <<>>]
    /\ vis = [e \in Ents |-> FALSE]
    /\ linked = [e \in Ents |-> FALSE]
    /\ meta = [e \in Ents |-> "none"]
    /\ pboot = [e \in Ents |-> 0]
    /\ mcommit = [e \in Ents |-> FALSE]
    /\ ddata = [e \in Ents |-> FALSE]
    /\ tree = [e \in Ents |-> "whole"]
    /\ boot = 0
    /\ werrors = 0
    /\ poisoned = [e \in Ents |-> FALSE]
    /\ held = [r \in Readers |-> {}]
    /\ alive = [p \in Procs |-> TRUE]
    /\ rcrashes = 0
    /\ badHold = FALSE
    /\ evicted = {}
    /\ promised = {}
    /\ inb = {}
    /\ flying = {}

(* The entries of p's job made so far, by step: the next is Done(p) + 1.   *)
Done(p) == Cardinality({e \in Ents : e[1] = p /\ meta[e] # "none"})
Mine(p) == {e \in Ents : e[1] = p}

Settling == IF SyncBeforeMark THEN "settle_d" ELSE "settle_m"

(* A runner's own: its job's layer not yet durable, if it is still alive. *)
Owned(e) == \E p \in Procs : alive[p] /\ cur[p] = e

(* The job's next step, the previous layer made durable first (the data's  *)
(* sync, then the mark; a failure of the sync poisons it and the job goes  *)
(* on uncached).  After the last publish, the job's result is reported     *)
(* (nothing to model) and its end makes the last layer durable: or does    *)
(* not, in the mutant.                                                     *)
Step(p) ==
    /\ pc[p] = "step"
    /\ alive[p]
    /\ IF Done(p) < Steps
       THEN IF cur[p] # <<>>
            THEN /\ pc' = [pc EXCEPT ![p] = Settling]
                 /\ UNCHANGED <<cur, vis, meta, pboot, inb>>
            ELSE \* publishTimed: the entry renamed in, pending, naming this boot.
                 LET e == <<p, Done(p) + 1>> IN
                 /\ vis' = [vis EXCEPT ![e] = TRUE]
                 /\ meta' = [meta EXCEPT ![e] = "pending"]
                 /\ pboot' = [pboot EXCEPT ![e] = boot]
                 /\ cur' = [cur EXCEPT ![p] = e]
                 /\ UNCHANGED <<pc, inb>>
       ELSE IF cur[p] # <<>> /\ SettleAtEnd /\ BatchAtEnd
            THEN \* JoinBatch: the end waits for a batch's syncfs (the mutant marks first).
                 /\ inb' = inb \cup {p}
                 /\ pc' = [pc EXCEPT ![p] = IF BatchSyncFirst THEN "batch" ELSE "settle_m"]
                 /\ UNCHANGED <<cur, vis, meta, pboot>>
            ELSE /\ pc' = [pc EXCEPT ![p] = IF cur[p] # <<>> /\ SettleAtEnd THEN Settling ELSE "dirsync"]
                 /\ UNCHANGED <<cur, vis, meta, pboot, inb>>
    /\ UNCHANGED <<linked, mcommit, ddata, tree, boot, werrors, evicted, promised, poisoned, held,
                    alive, rcrashes, badHold, flying>>

(* The data synced through the job's descriptor, which reports a loss of   *)
(* the layer's pages (WbLoss) or a failed write.  A failure poisons the    *)
(* layer at once (the meta renamed away); a layer no reader holds is also  *)
(* evicted by the end (`dropUnsynced`), one held waits.                    *)
SettleD(p) ==
    /\ pc[p] = "settle_d"
    /\ alive[p]
    /\ LET e == cur[p]
           held_by_other == \E r \in Readers : e \in held[r]
       IN
       \/ /\ tree[e] = "whole"
          /\ ddata' = [ddata EXCEPT ![e] = TRUE]
          /\ pc' = [pc EXCEPT ![p] = IF SyncBeforeMark THEN "settle_m" ELSE "step"]
          /\ cur' = IF SyncBeforeMark THEN cur ELSE [cur EXCEPT ![p] = <<>>]
          /\ UNCHANGED <<vis, evicted, werrors, poisoned>>
       \/ /\ \/ tree[e] = "broken"
             \/ werrors < MaxWriteErrors
          /\ werrors' = IF tree[e] = "broken" THEN werrors ELSE werrors + 1
          /\ poisoned' = [poisoned EXCEPT ![e] = PoisonOnFail \/ @]
          /\ vis' = [vis EXCEPT ![e] = held_by_other]
          /\ evicted' = IF held_by_other THEN evicted ELSE evicted \cup {e}
          /\ cur' = [cur EXCEPT ![p] = <<>>]
          /\ pc' = [pc EXCEPT ![p] = "step"]
          /\ UNCHANGED ddata
    /\ UNCHANGED <<linked, meta, pboot, mcommit, tree, boot, promised, held, alive, rcrashes, badHold,
                    inb, flying>>

(* meta.new written with `durable`, fsynced, and renamed over meta: in the *)
(* page cache at once, on disk once the directory is synced (SettleC).     *)
SettleM(p) ==
    /\ pc[p] = "settle_m"
    /\ alive[p]
    /\ meta' = [meta EXCEPT ![cur[p]] = "durable"]
    /\ pc' = [pc EXCEPT ![p] = "settle_c"]
    /\ UNCHANGED <<cur, vis, linked, pboot, mcommit, ddata, tree, boot, werrors, evicted, promised, others>>

(* The entry's directory fsynced: the durable meta is on disk.  (The       *)
(* mutants' data sync comes after: SettleD's, or the batch's.)              *)
SettleC(p) ==
    /\ pc[p] = "settle_c"
    /\ alive[p]
    /\ mcommit' = [mcommit EXCEPT ![cur[p]] = TRUE]
    /\ LET waits == SyncBeforeMark /\ p \in inb \cup flying IN
       /\ pc' = [pc EXCEPT ![p] = IF waits THEN "batch" ELSE IF SyncBeforeMark THEN "step" ELSE "settle_d"]
       /\ cur' = IF SyncBeforeMark /\ ~waits THEN [cur EXCEPT ![p] = <<>>] ELSE cur
    /\ UNCHANGED <<vis, linked, meta, pboot, ddata, tree, boot, werrors, evicted, promised, others>>

(* The batch's syncfs begins, for the runners that joined it: one at a    *)
(* time, and a runner that joins now waits for the next.                  *)
BatchStart ==
    /\ flying = {} /\ inb # {}
    /\ flying' = inb
    /\ inb' = {}
    /\ UNCHANGED <<pc, cur, vis, linked, meta, pboot, mcommit, ddata, tree, boot, werrors, poisoned,
                    held, alive, rcrashes, badHold, evicted, promised>>

(* The batch's syncfs ends, once every live runner of it waits.  It fails  *)
(* if any of its layers lost its data, or the disk fails it: then each     *)
(* live runner of it poisons its layer, as SettleD does.  Or it succeeds,  *)
(* every layer's data on disk, and each runner writes its durable meta     *)
(* (the mutant's was written already).  A killed runner's layer stays     *)
(* pending, its data synced or not.                                        *)
BatchEnd ==
    /\ flying # {}
    /\ \A p \in flying : alive[p] => pc[p] = "batch"
    /\ LET live == {p \in flying : alive[p]}
           mine == {cur[p] : p \in flying}
           lost == \E p \in flying : tree[cur[p]] = "broken"
           held_by_other(e) == \E r \in Readers : e \in held[r]
       IN
       \/ /\ ~lost
          /\ ddata' = [e \in Ents |-> ddata[e] \/ e \in mine]
          /\ pc' = [p \in Procs |-> IF p \in live THEN (IF BatchSyncFirst THEN "settle_m" ELSE "step") ELSE pc[p]]
          /\ cur' = [p \in Procs |-> IF p \in live /\ ~BatchSyncFirst THEN <<>> ELSE cur[p]]
          /\ UNCHANGED <<vis, evicted, werrors, poisoned>>
       \/ /\ lost \/ werrors < MaxWriteErrors
          /\ werrors' = IF lost THEN werrors ELSE werrors + 1
          /\ LET bad == {cur[p] : p \in live} IN
             /\ poisoned' = [e \in Ents |-> IF e \in bad THEN PoisonOnFail \/ poisoned[e] ELSE poisoned[e]]
             /\ vis' = [e \in Ents |-> IF e \in bad THEN held_by_other(e) ELSE vis[e]]
             /\ evicted' = evicted \cup {e \in bad : ~held_by_other(e)}
          /\ cur' = [p \in Procs |-> IF p \in live THEN <<>> ELSE cur[p]]
          /\ pc' = [p \in Procs |-> IF p \in live THEN "step" ELSE pc[p]]
          /\ UNCHANGED ddata
    /\ flying' = {}
    /\ UNCHANGED <<linked, meta, pboot, mcommit, tree, boot, promised, held, alive, rcrashes, badHold,
                    inb>>

(* syncLayers: layers/ fsynced, every rename so far on disk.  The job's    *)
(* end has finished: its layers are promised.                              *)
DirSync(p) ==
    /\ pc[p] = "dirsync"
    /\ alive[p]
    /\ linked' = [e \in Ents |-> IF vis[e] THEN TRUE ELSE linked[e]]
    /\ promised' = promised \cup {e \in Mine(p) : vis[e]}
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<cur, vis, meta, pboot, mcommit, ddata, tree, boot, werrors, evicted, others>>

(* The runner is killed between two steps: its layer stays pending, with   *)
(* no one to settle or refuse it.                                          *)
RunnerCrash(p) ==
    /\ rcrashes < MaxRunnerCrashes
    /\ alive[p] /\ pc[p] # "done"
    /\ alive' = [alive EXCEPT ![p] = FALSE]
    /\ rcrashes' = rcrashes + 1
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<cur, vis, linked, meta, pboot, mcommit, ddata, tree, boot, werrors, poisoned,
                    held, badHold, evicted, promised, inb, flying>>

(* Within a boot, a pending layer's write-back fails and its pages are     *)
(* dropped clean: later reads come from the disk (zeros).  Only before its *)
(* data is synced.                                                         *)
WbLoss(e) ==
    /\ vis[e] /\ meta[e] = "pending" /\ ~ddata[e] /\ tree[e] = "whole"
    /\ tree' = [tree EXCEPT ![e] = "broken"]
    /\ UNCHANGED <<pc, cur, vis, linked, meta, pboot, mcommit, ddata, boot, werrors, poisoned,
                    held, alive, rcrashes, badHold, evicted, promised, inb, flying>>

(* What another job's lookup takes (`open`): published, not poisoned, and  *)
(* durable, or pending in this boot (and this mount) where the pending is  *)
(* not refused to jobs other than the writer (OwnerOnly).                  *)
OtherLookup(e) ==
    /\ vis[e] /\ ~poisoned[e]
    /\ \/ meta[e] = "durable"
       \/ /\ meta[e] = "pending"
          /\ ~OwnerOnly
          /\ (~CheckBoot \/ pboot[e] = boot)

ReaderOpen(r, e) ==
    /\ OtherLookup(e)
    /\ held' = [held EXCEPT ![r] = @ \cup {e}]
    /\ badHold' = (badHold \/ tree[e] # "whole")
    /\ UNCHANGED <<pc, cur, vis, linked, meta, pboot, mcommit, ddata, tree, boot, werrors, poisoned,
                    alive, rcrashes, evicted, promised, inb, flying>>

ReaderRelease(r, e) ==
    /\ e \in held[r]
    /\ held' = [held EXCEPT ![r] = @ \ {e}]
    /\ UNCHANGED <<pc, cur, vis, linked, meta, pboot, mcommit, ddata, tree, boot, werrors, poisoned,
                    alive, rcrashes, badHold, evicted, promised, inb, flying>>

(* `collect` (and `open`, for a poisoned one): a layer pending or poisoned *)
(* that no job holds and no live runner owns is taken out.                 *)
CollectOrphan(e) ==
    /\ vis[e] /\ ~Owned(e)
    /\ \/ meta[e] = "pending" /\ OwnerOnly
       \/ poisoned[e]
    /\ \A r \in Readers : e \notin held[r]
    /\ vis' = [vis EXCEPT ![e] = FALSE]
    /\ evicted' = evicted \cup {e}
    /\ UNCHANGED <<pc, cur, linked, meta, pboot, mcommit, ddata, tree, boot, werrors, poisoned,
                    held, alive, rcrashes, badHold, promised, inb, flying>>

(* The machine dies.  A rename no directory sync covered may be lost (a    *)
(* miss).  The tree is what was synced; the meta is the committed one, or  *)
(* a durable one not yet committed when the kernel kept it; a pending meta *)
(* stays and names a boot that has ended.  Every runner and reader is      *)
(* gone: the first job of the next boot is the lookups the invariants      *)
(* stand for.                                                              *)
MachineCrash ==
    /\ boot < MachineCrashes
    /\ boot' = boot + 1
    /\ \E lost \in SUBSET {e \in Ents : vis[e] /\ ~linked[e]},
          kept \in SUBSET {e \in Ents : meta[e] = "durable" /\ ~mcommit[e]} :
         /\ vis' = [e \in Ents |-> vis[e] /\ e \notin lost]
         /\ meta' = [e \in Ents |-> IF meta[e] = "durable" /\ ~mcommit[e] /\ e \notin kept
                                    THEN "pending" ELSE meta[e]]
    /\ tree' = [e \in Ents |-> IF ddata[e] THEN tree[e] ELSE "broken"]
    /\ mcommit' = [e \in Ents |-> mcommit[e] \/ meta'[e] = "durable"]
    /\ pc' = [p \in Procs |-> "done"]
    /\ cur' = [p \in Procs |-> <<>>]
    /\ held' = [r \in Readers |-> {}]
    /\ alive' = [p \in Procs |-> FALSE]
    /\ inb' = {}
    /\ flying' = {}
    /\ UNCHANGED <<linked, pboot, ddata, werrors, poisoned, rcrashes, badHold, evicted, promised>>

Proc(p) == Step(p) \/ SettleD(p) \/ SettleM(p) \/ SettleC(p) \/ DirSync(p) \/ RunnerCrash(p)

Terminated == \A p \in Procs : pc[p] = "done"

Next == \/ \E p \in Procs : Proc(p)
        \/ \E e \in Ents : WbLoss(e) \/ CollectOrphan(e)
        \/ \E r \in Readers, e \in Ents : ReaderOpen(r, e) \/ ReaderRelease(r, e)
        \/ BatchStart \/ BatchEnd
        \/ MachineCrash
        \/ (Terminated /\ boot = MachineCrashes /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What `open` returns for the layer's own job (readEntry): the same plus  *)
(* its own pending.  After a boot every pending layer names a boot that    *)
(* has ended.  Used by the lookups after a crash, as OtherLookup is.       *)
Usable(e) ==
    /\ vis[e] /\ ~poisoned[e]
    /\ \/ meta[e] = "durable"
       \/ /\ meta[e] = "pending"
          /\ (~CheckBoot \/ pboot[e] = boot)

(* No lookup of a job other than the writer takes, at any instant, a layer *)
(* whose tree is not whole; and the writer's own is whole or its settle    *)
(* will find out (its pending layer with a broken tree is not a durable    *)
(* one's parent: SettleD cannot pass over it).                             *)
NoWrongValid == /\ \A e \in Ents : OtherLookup(e) => tree[e] = "whole"
                /\ \A e \in Ents : (Usable(e) /\ meta[e] = "durable") => tree[e] = "whole"
                /\ ~badHold

(* The guarantee after a job's end has finished: its layers survive any    *)
(* crash that follows, unless a failed sync evicted one.  (Between the     *)
(* result and the end's sync they may not: a clean miss.)                  *)
NoLostPublish == \A e \in promised : e \in evicted \/ poisoned[e] \/ Usable(e)

(* A durable mark is on disk only with its data.                            *)
MarkedHasData == \A e \in Ents : (mcommit[e] /\ meta[e] = "durable") => ddata[e]
=============================================================================
