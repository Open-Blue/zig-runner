---------------------------- MODULE StoreDeferred ----------------------------
(***************************************************************************)
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
(* rename no directory sync covered.                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Procs,          \* the runners
    Steps,          \* layers a job publishes, one a step
    MachineCrashes, \* machine crashes, 0 or 1
    MaxWriteErrors, \* deferred syncs the disk fails
    SyncBeforeMark, \* the mark durable is written after the data's fsyncs (the fix)
    CheckBoot,      \* a pending mark of another boot is refused (the boot id)
    SettleAtEnd     \* the job's end makes its last layer durable

ASSUME Steps \in Nat \ {0} /\ MachineCrashes \in 0..1

Ents == Procs \X (1..Steps)

VARIABLES
    pc,       \* each runner: "step", "settle_d", "settle_m", "settle_c", "dirsync", "done"
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
    evicted,  \* ghost: an entry taken out after a failed sync
    promised  \* ghost: the entries of jobs whose end has finished

vars == <<pc, cur, vis, linked, meta, pboot, mcommit, ddata, tree, boot, werrors, evicted, promised>>

TypeOK ==
    /\ pc \in [Procs -> {"step", "settle_d", "settle_m", "settle_c", "dirsync", "done"}]
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
    /\ evicted = {}
    /\ promised = {}

(* The entries of p's job made so far, by step: the next is Done(p) + 1.   *)
Done(p) == Cardinality({e \in Ents : e[1] = p /\ meta[e] # "none"})
Mine(p) == {e \in Ents : e[1] = p}

Settling == IF SyncBeforeMark THEN "settle_d" ELSE "settle_m"

(* The job's next step, the previous layer made durable first (the data's  *)
(* sync, then the mark; a failure of the sync evicts it and the job goes   *)
(* on uncached).  After the last publish, the job's result is reported     *)
(* (nothing to model) and its end makes the last layer durable: or does    *)
(* not, in the mutant.                                                     *)
Step(p) ==
    /\ pc[p] = "step"
    /\ IF Done(p) < Steps
       THEN IF cur[p] # <<>>
            THEN /\ pc' = [pc EXCEPT ![p] = Settling]
                 /\ UNCHANGED <<cur, vis, meta, pboot>>
            ELSE \* publishTimed: the entry renamed in, pending, naming this boot.
                 LET e == <<p, Done(p) + 1>> IN
                 /\ vis' = [vis EXCEPT ![e] = TRUE]
                 /\ meta' = [meta EXCEPT ![e] = "pending"]
                 /\ pboot' = [pboot EXCEPT ![e] = boot]
                 /\ cur' = [cur EXCEPT ![p] = e]
                 /\ UNCHANGED pc
       ELSE /\ pc' = [pc EXCEPT ![p] = IF cur[p] # <<>> /\ SettleAtEnd THEN Settling ELSE "dirsync"]
            /\ UNCHANGED <<cur, vis, meta, pboot>>
    /\ UNCHANGED <<linked, mcommit, ddata, tree, boot, werrors, evicted, promised>>

(* The data synced: writeBack, syncEntries or syncfs.  A failure evicts    *)
(* the layer (#483's rule) and the job goes on without it.                 *)
SettleD(p) ==
    /\ pc[p] = "settle_d"
    /\ LET e == cur[p] IN
       \/ /\ ddata' = [ddata EXCEPT ![e] = TRUE]
          /\ pc' = [pc EXCEPT ![p] = IF SyncBeforeMark THEN "settle_m" ELSE "step"]
          /\ cur' = IF SyncBeforeMark THEN cur ELSE [cur EXCEPT ![p] = <<>>]
          /\ UNCHANGED <<vis, evicted, werrors>>
       \/ /\ werrors < MaxWriteErrors
          /\ werrors' = werrors + 1
          /\ vis' = [vis EXCEPT ![e] = FALSE]
          /\ evicted' = evicted \cup {e}
          /\ cur' = [cur EXCEPT ![p] = <<>>]
          /\ pc' = [pc EXCEPT ![p] = "step"]
          /\ UNCHANGED ddata
    /\ UNCHANGED <<linked, meta, pboot, mcommit, tree, boot, promised>>

(* meta.new written with `durable`, fsynced, and renamed over meta: in the *)
(* page cache at once, on disk once the directory is synced (SettleC).     *)
SettleM(p) ==
    /\ pc[p] = "settle_m"
    /\ meta' = [meta EXCEPT ![cur[p]] = "durable"]
    /\ pc' = [pc EXCEPT ![p] = "settle_c"]
    /\ UNCHANGED <<cur, vis, linked, pboot, mcommit, ddata, tree, boot, werrors, evicted, promised>>

(* The entry's directory fsynced: the durable meta is on disk.  (The       *)
(* mutant's data sync comes after.)                                        *)
SettleC(p) ==
    /\ pc[p] = "settle_c"
    /\ mcommit' = [mcommit EXCEPT ![cur[p]] = TRUE]
    /\ pc' = [pc EXCEPT ![p] = IF SyncBeforeMark THEN "step" ELSE "settle_d"]
    /\ cur' = IF SyncBeforeMark THEN [cur EXCEPT ![p] = <<>>] ELSE cur
    /\ UNCHANGED <<vis, linked, meta, pboot, ddata, tree, boot, werrors, evicted, promised>>

(* syncLayers: layers/ fsynced, every rename so far on disk.  The job's    *)
(* end has finished: its layers are promised.                              *)
DirSync(p) ==
    /\ pc[p] = "dirsync"
    /\ linked' = [e \in Ents |-> IF vis[e] THEN TRUE ELSE linked[e]]
    /\ promised' = promised \cup {e \in Mine(p) : vis[e]}
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ UNCHANGED <<cur, vis, meta, pboot, mcommit, ddata, tree, boot, werrors, evicted>>

(* The machine dies.  A rename no directory sync covered may be lost (a    *)
(* miss).  The tree is what was synced; the meta is the committed one, or  *)
(* a durable one not yet committed when the kernel kept it; a pending meta *)
(* stays and names a boot that has ended.  Every runner is gone: the first *)
(* job of the next boot is the lookups the invariants stand for.           *)
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
    /\ UNCHANGED <<linked, pboot, ddata, werrors, evicted, promised>>

Proc(p) ==  Step(p) \/ SettleD(p) \/ SettleM(p) \/ SettleC(p) \/ DirSync(p)

Terminated == \A p \in Procs : pc[p] = "done"

Next == \/ \E p \in Procs : Proc(p)
        \/ MachineCrash
        \/ (Terminated /\ boot = MachineCrashes /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What `open` returns (readEntry): published, and either marked durable   *)
(* or pending in this boot.  A pending mark of another boot is refused,    *)
(* the boot id being the kernel's and new at each boot.                    *)
Usable(e) ==
    /\ vis[e]
    /\ \/ meta[e] = "durable"
       \/ /\ meta[e] = "pending"
          /\ (~CheckBoot \/ pboot[e] = boot)

(* No lookup, at any instant, takes a layer whose tree is not whole.       *)
NoWrongValid == \A e \in Ents : Usable(e) => tree[e] = "whole"

(* The guarantee after a job's end has finished: its layers survive any    *)
(* crash that follows, unless a failed sync evicted one.  (Between the     *)
(* result and the end's sync they may not: a clean miss.)                  *)
NoLostPublish == \A e \in promised : e \in evicted \/ Usable(e)

(* A durable mark is on disk only with its data.                            *)
MarkedHasData == \A e \in Ents : (mcommit[e] /\ meta[e] = "durable") => ddata[e]
=============================================================================
