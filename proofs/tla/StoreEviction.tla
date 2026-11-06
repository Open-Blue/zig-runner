---------------------------- MODULE StoreEviction ----------------------------
(***************************************************************************)
(* Eviction beside the layers, at the level of system calls               *)
(* (runner/src/native/evict.zig, volumes.open, and oci/Store.zig's hold    *)
(* and ensure; docs/native-backend.md, "Eviction").  StoreLocking.tla is   *)
(* the layers', whose lock is inside each entry.  Here the lock is beside  *)
(* the entry (`<dir>.lock`), and an eviction removes it.                   *)
(*                                                                         *)
(* An entry is a directory a job uses by its path until the job ends:      *)
(* a volume, made in place by whoever opens it first, or a tree (a rootfs, *)
(* an image, a seed), made aside under the lock taken exclusively and      *)
(* published by a rename.  `Outer` and `Inner` are the one case of an      *)
(* entry inside another's directory (a step user's volume under the same   *)
(* key as a root's, volumes.plan), whose lock file goes with the outer's   *)
(* rename; a job holding the outer one can write what is at the inner      *)
(* lock's name, so anything may be there (`planted`), and could delete a   *)
(* real lock, which is no worse than the rm -r of the inner volume that   *)
(* job can do anyway.  Each runner process runs `Rounds` jobs of one entry *)
(* each, then                                                              *)
(* a collect.  Any process may die between any two actions, and the        *)
(* machine may die; the jobs after that find what the crash left.          *)
(*                                                                         *)
(* Actions name the code by function.  Paths are relative to               *)
(* runner/src/native/.                                                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Procs, Rounds,
    Volumes,        \* entries made in place (volumes.open)
    Trees,          \* entries made aside and renamed in (ensure, Backend.seed)
    Outer, Inner,   \* an entry in Volumes and the one inside it; NoKey when there is none
    NoKey,
    MaxCrashes,
    MachineCrashes,
    MaxPlants,      \* things jobs leave at the inner lock's name
    MaxStuck,       \* dead trees that cannot be removed
    OpenRechecks,      \* whoever takes a lock checks it is the file the path names (sameFile)
    DowngradeRechecks, \* ensure looks again after it gives up exclusive for shared
    EvictLocks,        \* an eviction takes the lock exclusively, non-blocking
    EvictRechecks,     \* an eviction checks its lock is on the file the path names
    TakesInnerLock,    \* an eviction takes the lock of the entry inside the one it takes
    RenameFirst,       \* the tree goes to a dead name before anything of it is deleted
    SyncsRename,       \* that rename is on disk before anything of it is deleted
    SyncsFilesystem,   \* removeDead syncs the filesystem, as it cannot know a rename's source
    ClearsPlanted,     \* innerLock removes what is no regular file at the lock's name
    StuckStopsNothing  \* a dead tree that cannot be removed does not end the pass

Keys == Volumes \cup Trees
NoFd == <<>>

VARIABLES
    st,       \* each process's program counter and locals
    lockIno,  \* <k>.lock: the generation of the file the path names, 0 for none
    lockGen,  \* the last generation made, so a file made again is a new inode
    locks,    \* flocks: <<<<key, generation>>, process, "sh" or "ex">>
    dirOf,    \* the tree the name k names: its id, 0 for none
    nextId,   \* the last tree id
    half,     \* ids of trees something was deleted from
    tmp,      \* keys with a tree being made aside (`.tmp-<key>`), by a live or dead maker
    dead,     \* trees under a dead name: [id, key, synced, src, stuck]; `synced` its directory,
              \* `src` the directory it came from, which for a volume is another
    gc,       \* who holds gc.lock
    planted,  \* something no regular file is at the inner lock's name
    crashes, mcrashes, plants, stucks,
    pinned,   \* ghost: what a job planted kept a volume from going
    stopped   \* ghost: a dead tree that would not go ended a pass

vars == <<st, lockIno, lockGen, locks, dirOf, nextId, half, tmp, dead, gc, planted, crashes,
          mcrashes, plants, stucks, pinned, stopped>>
fsVars == <<lockIno, lockGen, locks, dirOf, nextId, half, tmp, dead, gc, planted>>
counts == <<crashes, mcrashes, plants, stucks, pinned, stopped>>

(* `fd` the open lock file; `held` the tree the job's mounts name.        *)
Idle == [pc |-> "open", round |-> 1, key |-> CHOOSE k \in Keys : TRUE, fd |-> NoFd,
         fd2 |-> NoFd, held |-> 0, todo |-> {}, evk |-> CHOOSE k \in Keys : TRUE]
Begin(i) ==
    IF i > Rounds THEN {[Idle EXCEPT !.pc = "done"]}
    ELSE {[Idle EXCEPT !.round = i, !.key = k] : k \in Keys}

Init ==
    /\ st \in [Procs -> Begin(1)]
    /\ lockIno = [k \in Keys |-> 0]
    /\ lockGen = [k \in Keys |-> 0]
    /\ locks = {}
    /\ dirOf = [k \in Keys |-> 0]
    /\ nextId = 0
    /\ half = {}
    /\ tmp = {}
    /\ dead = {}
    /\ gc = {}
    /\ planted = FALSE
    /\ crashes = 0 /\ mcrashes = 0 /\ plants = 0 /\ stucks = 0
    /\ pinned = FALSE /\ stopped = FALSE

S(p) == st[p]
Put(p, r) == st' = [st EXCEPT ![p] = r]
Goto(p, pc) == Put(p, [S(p) EXCEPT !.pc = pc])

Holders(i) == {l \in locks : l[1] = i}
Add(i, p, m) == locks' = locks \cup {<<i, p, m>>}
Drop(i, p) == locks' = locks \ {l \in locks : l[1] = i /\ l[2] = p}
Mine(p) == {l \in locks : l[2] = p}

(* The file the path names, made if none (lockBeside).  The entry inside  *)
(* another's directory: createDirPath makes the directory first, a prefix *)
(* of a key if no job opens it as a volume.                               *)
Fresh(k) ==
    /\ lockGen' = [lockGen EXCEPT ![k] = @ + 1]
    /\ lockIno' = [lockIno EXCEPT ![k] = lockGen[k] + 1]

-----------------------------------------------------------------------------
(* A job (volumes.open, oci.Store.hold and ensure, Backend.seed).          *)

Open(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "open"
    /\ IF lockIno[k] = 0
       THEN /\ Fresh(k)
            /\ Put(p, [S(p) EXCEPT !.fd = <<k, lockGen[k] + 1>>, !.pc = "flock_sh"])
       ELSE /\ Put(p, [S(p) EXCEPT !.fd = <<k, lockIno[k]>>, !.pc = "flock_sh"])
            /\ UNCHANGED <<lockIno, lockGen>>
    \* lockBeside removes what is no regular file.
    /\ planted' = (planted /\ k # Inner)
    /\ UNCHANGED <<locks, dirOf, nextId, half, tmp, dead, gc, counts>>

(* flock(LOCK_SH), blocking: waits out a maker and an eviction.           *)
FlockSh(p) ==
    /\ S(p).pc = "flock_sh"
    /\ \A l \in Holders(S(p).fd) : l[3] # "ex"
    /\ Add(S(p).fd, p, "sh")
    /\ Goto(p, "same")
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

(* sameFile: an eviction removed the file: closed, and again.             *)
Same(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "same"
    /\ IF OpenRechecks /\ lockIno[k] # S(p).fd[2]
       THEN /\ Drop(S(p).fd, p)
            /\ Put(p, [S(p) EXCEPT !.fd = NoFd, !.pc = "open"])
       ELSE /\ Goto(p, "look")
            /\ UNCHANGED locks
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

(* The directory, under the lock held shared.  A volume is made here      *)
(* (mkdir, EEXIST fine); a tree missing is ensure's to make, so the lock  *)
(* goes exclusive; flock gives the shared one up first, so another may    *)
(* come between.                                                          *)
Look(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "look"
    /\ IF dirOf[k] # 0
       THEN /\ Put(p, [S(p) EXCEPT !.held = dirOf[k], !.pc = "use"])
            /\ UNCHANGED <<dirOf, nextId, locks>>
       ELSE IF k \in Volumes
       THEN /\ nextId' = nextId + 1
            /\ dirOf' = [dirOf EXCEPT ![k] = nextId + 1]
            /\ Put(p, [S(p) EXCEPT !.held = nextId + 1, !.pc = "use"])
            /\ UNCHANGED locks
       ELSE /\ Drop(S(p).fd, p)
            /\ Goto(p, "flock_ex")
            /\ UNCHANGED <<dirOf, nextId>>
    /\ UNCHANGED <<lockIno, lockGen, half, tmp, dead, gc, planted, counts>>

FlockEx(p) ==
    /\ S(p).pc = "flock_ex"
    /\ Holders(S(p).fd) = {}
    /\ Add(S(p).fd, p, "ex")
    /\ Goto(p, "same_ex")
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

(* Looked at again under the lock: a maker came first, or the file went.  *)
SameEx(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "same_ex"
    /\ IF OpenRechecks /\ lockIno[k] # S(p).fd[2]
       THEN /\ Drop(S(p).fd, p)
            /\ Put(p, [S(p) EXCEPT !.fd = NoFd, !.pc = "open"])
            /\ UNCHANGED tmp
       ELSE IF dirOf[k] # 0
       THEN /\ Goto(p, "down") /\ UNCHANGED <<tmp, locks>>
       ELSE /\ tmp' = tmp \cup {k}
            /\ Goto(p, "make")
            /\ UNCHANGED locks
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, dead, gc, planted, counts>>

(* The maker's rename, its tree synced first (ensure, adoptSeed).         *)
Make(p) ==
    LET k == S(p).key IN
    /\ S(p).pc = "make"
    /\ nextId' = nextId + 1
    /\ dirOf' = [dirOf EXCEPT ![k] = nextId + 1]
    /\ tmp' = tmp \ {k}
    /\ Goto(p, "down")
    /\ UNCHANGED <<lockIno, lockGen, locks, half, dead, gc, planted, counts>>

(* Exclusive given up for shared, for the job: flock's conversion is not  *)
(* atomic, so an eviction may come between (`down`, then `flock_sh2`).    *)
Down(p) ==
    /\ S(p).pc = "down"
    /\ Drop(S(p).fd, p)
    /\ Goto(p, "flock_sh2")
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

FlockSh2(p) ==
    /\ S(p).pc = "flock_sh2"
    /\ \A l \in Holders(S(p).fd) : l[3] # "ex"
    /\ Add(S(p).fd, p, "sh")
    /\ Goto(p, IF DowngradeRechecks THEN "same" ELSE "assume")
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

(* The mutant: what it made is taken to be there.                         *)
Assume(p) ==
    /\ S(p).pc = "assume"
    /\ Put(p, [S(p) EXCEPT !.held = IF dirOf[S(p).key] # 0 THEN dirOf[S(p).key] ELSE nextId,
                           !.pc = "use"])
    /\ UNCHANGED <<fsVars, counts>>

(* A job holding the outer volume leaves something at the inner lock's     *)
(* name: a symlink, a FIFO, anything.  Not over a lock a job holds: that   *)
(* job's volume is inside this one's, which can rm -r it whatever a lock  *)
(* says, so that is outside what any protocol here can keep.              *)
Plant(p) ==
    /\ S(p).pc = "use" /\ S(p).key = Outer
    /\ Holders(<<Inner, lockIno[Inner]>>) = {}
    /\ plants < MaxPlants
    /\ plants' = plants + 1
    /\ planted' = TRUE
    /\ lockIno' = [lockIno EXCEPT ![Inner] = 0]
    /\ UNCHANGED <<st, lockGen, locks, dirOf, nextId, half, tmp, dead, gc, crashes, mcrashes,
                   stucks, pinned, stopped>>

(* The job's steps run on the path, then its end lets the lock go.        *)
Use(p) ==
    /\ S(p).pc = "use"
    /\ Drop(S(p).fd, p)
    /\ Put(p, [S(p) EXCEPT !.fd = NoFd, !.held = 0, !.pc = "gc_lock"])
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

-----------------------------------------------------------------------------
(* evict.run, at the job's end, under gc.lock, non-blocking.              *)

Next1(p) == \E r \in Begin(S(p).round + 1) : Put(p, r)

GcLock(p) ==
    /\ S(p).pc = "gc_lock"
    /\ IF gc = {}
       THEN /\ gc' = {p}
            /\ Put(p, [S(p) EXCEPT !.todo = Keys, !.pc = "gc_dead"])
       ELSE Next1(p) /\ UNCHANGED gc
    /\ UNCHANGED <<lockIno, lockGen, locks, dirOf, nextId, half, tmp, dead, planted, counts>>

(* removeDead: the filesystem synced first, as the runner that renamed a   *)
(* tree there may have died before its own sync (TLC found the other      *)
(* order: another runner's pass deleted from a rename a crash then lost,  *)
(* and the name came back on a tree half gone).  The filesystem, not the  *)
(* area's directory: a volume came from a directory no one here can name  *)
(* (TLC again, in 25 states).  Then one tree at a time, a deadline         *)
(* anywhere, and one that will not go is passed over.                     *)
GcDead(p) ==
    LET live == {x \in dead : ~x.stuck} IN
    /\ S(p).pc = "gc_dead"
    /\ IF live = {}
       THEN IF dead # {} /\ ~StuckStopsNothing
            THEN /\ stopped' = TRUE
                 /\ Goto(p, "gc_end")
                 /\ UNCHANGED <<dead, half, stucks>>
            ELSE Goto(p, "gc_next") /\ UNCHANGED <<dead, half, stucks, stopped>>
       ELSE IF SyncsRename /\ \E x \in dead : ~x.synced \/ (SyncsFilesystem /\ ~x.src)
       THEN /\ dead' = {[x EXCEPT !.synced = TRUE,
                                  !.src = SyncsFilesystem \/ x.key \in Trees \/ @] : x \in dead}
            /\ UNCHANGED <<st, half, stucks, stopped>>
       ELSE LET d == CHOOSE x \in live : TRUE IN
            \/ /\ IF d.id \in half
                  THEN dead' = dead \ {d} /\ UNCHANGED half
                  ELSE half' = half \cup {d.id} /\ UNCHANGED dead
               /\ UNCHANGED <<st, stucks, stopped>>
            \/ /\ stucks < MaxStuck
               /\ stucks' = stucks + 1
               /\ dead' = (dead \ {d}) \cup {[d EXCEPT !.stuck = TRUE]}
               /\ UNCHANGED <<st, half, stopped>>
            \/ Goto(p, "gc_next") /\ UNCHANGED <<dead, half, stucks, stopped>>
    /\ UNCHANGED <<lockIno, lockGen, locks, dirOf, nextId, tmp, gc, planted, crashes, mcrashes,
                   plants, pinned>>

GcEnd(p) ==
    /\ S(p).pc = "gc_end"
    /\ gc' = {}
    /\ Next1(p)
    /\ UNCHANGED <<lockIno, lockGen, locks, dirOf, nextId, half, tmp, dead, planted, counts>>

(* One key: a stray `.tmp-` under its free lock, a stray lock file, or    *)
(* the entry evicted, which any entry here may be, but the volume inside  *)
(* a volume: the walk does not look in there, and it goes with the outer. *)
GcNext(p) ==
    /\ S(p).pc = "gc_next"
    /\ IF S(p).todo = {}
       THEN /\ gc' = {}
            /\ Next1(p)
       ELSE LET k == CHOOSE x \in S(p).todo : TRUE
                r == [S(p) EXCEPT !.todo = @ \ {k}]
            IN /\ UNCHANGED gc
               /\ IF (lockIno[k] = 0 /\ dirOf[k] = 0) \/ (k = Inner /\ dirOf[Outer] # 0)
                  THEN Put(p, r)
                  ELSE \/ Put(p, r)
                       \/ Put(p, [r EXCEPT !.evk = k, !.pc = "ev_open"])
    /\ UNCHANGED <<lockIno, lockGen, locks, dirOf, nextId, half, tmp, dead, planted, counts>>

EvFail(p) == Put(p, [S(p) EXCEPT !.fd = NoFd, !.fd2 = NoFd, !.pc = "gc_next"])

(* The lock file opened by name, none: nothing to do.                     *)
EvOpen(p) ==
    LET k == S(p).evk IN
    /\ S(p).pc = "ev_open"
    /\ IF lockIno[k] = 0
       THEN Goto(p, "gc_next")
       ELSE Put(p, [S(p) EXCEPT !.fd = <<k, lockIno[k]>>,
                                !.pc = IF EvictLocks THEN "ev_flock" ELSE "ev_inner"])
    /\ UNCHANGED <<fsVars, counts>>

(* LOCK_EX | LOCK_NB: a job holding it keeps it.                          *)
EvFlock(p) ==
    /\ S(p).pc = "ev_flock"
    /\ IF Holders(S(p).fd) = {}
       THEN Add(S(p).fd, p, "ex") /\ Goto(p, "ev_same")
       ELSE EvFail(p) /\ UNCHANGED locks
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

EvSame(p) ==
    LET k == S(p).evk IN
    /\ S(p).pc = "ev_same"
    /\ IF EvictRechecks /\ lockIno[k] # S(p).fd[2]
       THEN Drop(S(p).fd, p) /\ EvFail(p)
       ELSE Goto(p, "ev_inner") /\ UNCHANGED locks
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

(* A dead maker's tree goes here too: the lock is free, so it is no one's. *)
(* innerLock: the lock of the entry that may be inside this one, made if  *)
(* there is none, so a job starting now waits and then finds its path     *)
(* gone.  What was planted there is removed first.  The mutant gives up.  *)
EvInner(p) ==
    LET k == S(p).evk IN
    /\ S(p).pc = "ev_inner"
    /\ tmp' = tmp \ {k}
    /\ IF k = Outer /\ planted /\ ~ClearsPlanted
       THEN /\ pinned' = TRUE
            /\ locks' = locks \ Mine(p)
            /\ EvFail(p)
            /\ UNCHANGED <<lockIno, lockGen, planted>>
       ELSE IF k = Outer /\ TakesInnerLock
       THEN /\ planted' = FALSE
            /\ UNCHANGED pinned
            /\ IF lockIno[Inner] = 0
               THEN /\ Fresh(Inner)
                    /\ Add(<<Inner, lockGen[Inner] + 1>>, p, "ex")
                    /\ Put(p, [S(p) EXCEPT !.fd2 = <<Inner, lockGen[Inner] + 1>>, !.pc = "ev_rename"])
               ELSE IF Holders(<<Inner, lockIno[Inner]>>) = {}
               THEN /\ Add(<<Inner, lockIno[Inner]>>, p, "ex")
                    /\ Put(p, [S(p) EXCEPT !.fd2 = <<Inner, lockIno[Inner]>>, !.pc = "ev_rename"])
                    /\ UNCHANGED <<lockIno, lockGen>>
               ELSE /\ locks' = locks \ Mine(p)
                    /\ EvFail(p)
                    /\ UNCHANGED <<lockIno, lockGen>>
       ELSE /\ Goto(p, "ev_rename")
            /\ UNCHANGED <<lockIno, lockGen, locks, planted, pinned>>
    /\ UNCHANGED <<dirOf, nextId, half, dead, gc, crashes, mcrashes, plants, stucks, stopped>>

(* The rename to `.dead-<n>`.  What is inside goes with it: the inner     *)
(* entry's directory and lock file.  The mutant deletes first.            *)
EvRename(p) ==
    LET k == S(p).evk
        id == dirOf[k]
        inner == IF k = Outer THEN {Inner} ELSE {}
        gone == {dirOf[i] : i \in inner} \ {0}
    IN
    /\ S(p).pc = "ev_rename"
    /\ IF id = 0
       THEN /\ Goto(p, "ev_unlink")
            /\ UNCHANGED <<dirOf, lockIno, half, dead>>
       ELSE IF ~RenameFirst /\ id \notin half
       THEN /\ half' = half \cup {id}
            /\ UNCHANGED <<dirOf, lockIno, dead, st>>
       ELSE /\ dirOf' = [x \in Keys |-> IF x = k \/ x \in inner THEN 0 ELSE dirOf[x]]
            /\ lockIno' = [x \in Keys |-> IF x \in inner THEN 0 ELSE lockIno[x]]
            /\ dead' = dead \cup {[id |-> i, key |-> k, synced |-> FALSE, src |-> FALSE, stuck |-> FALSE] : i \in {id} \cup gone}
            /\ Goto(p, "ev_sync")
            /\ UNCHANGED half
    /\ UNCHANGED <<lockGen, locks, nextId, tmp, gc, planted, counts>>

(* syncDirOf, both directories: where it went and where it came from.     *)
EvSync(p) ==
    /\ S(p).pc = "ev_sync"
    /\ IF SyncsRename
       THEN dead' = {[d EXCEPT !.synced = TRUE, !.src = TRUE] : d \in dead}
       ELSE UNCHANGED dead
    /\ Goto(p, "ev_unlink")
    /\ UNCHANGED <<lockIno, lockGen, locks, dirOf, nextId, half, tmp, gc, planted, counts>>

(* `forget`: the lock file's path gone, then every lock let go, so a job  *)
(* that waited finds no file at that path.                                *)
EvUnlink(p) ==
    LET k == S(p).evk IN
    /\ S(p).pc = "ev_unlink"
    /\ lockIno' = [lockIno EXCEPT ![k] = IF lockIno[k] = S(p).fd[2] THEN 0 ELSE @]
    /\ locks' = locks \ Mine(p)
    /\ Put(p, [S(p) EXCEPT !.fd = NoFd, !.fd2 = NoFd, !.pc = "gc_next"])
    /\ UNCHANGED <<lockGen, dirOf, nextId, half, tmp, dead, gc, planted, counts>>

-----------------------------------------------------------------------------
(* What happens to the processes.                                         *)

Crash(p) ==
    /\ crashes < MaxCrashes
    /\ S(p).pc \notin {"done", "crashed"}
    /\ crashes' = crashes + 1
    /\ Put(p, [Idle EXCEPT !.pc = "crashed"])
    /\ locks' = locks \ Mine(p)
    /\ gc' = gc \ {p}
    /\ UNCHANGED <<lockIno, lockGen, dirOf, nextId, half, tmp, dead, planted, mcrashes, plants,
                   stucks, pinned, stopped>>

(* The machine dies: every process, and a rename to a dead name no sync   *)
(* covered, whose tree comes back under its name with whatever was        *)
(* deleted of it.  Lock files are files: they stay.  A published tree was *)
(* synced before its rename (ensure), a volume has no such promise, and   *)
(* neither is modelled further here: StoreLocking.tla has the data's      *)
(* order, and the store's crash test the disk's.  The processes start     *)
(* over.                                                                  *)
MachineCrash ==
    /\ mcrashes < MachineCrashes
    /\ mcrashes' = mcrashes + 1
    /\ \E back \in SUBSET {d \in dead : ~d.src /\ dirOf[d.key] = 0} :
         /\ dirOf' = [k \in Keys |-> IF \E d \in back : d.key = k
                                     THEN (CHOOSE d \in back : d.key = k).id ELSE dirOf[k]]
         /\ dead' = dead \ back
    /\ locks' = {}
    /\ gc' = {}
    /\ st' \in [Procs -> Begin(Rounds)]
    /\ UNCHANGED <<lockIno, lockGen, nextId, half, tmp, planted, crashes, plants, stucks, pinned,
                   stopped>>

Terminated == \A p \in Procs : S(p).pc \in {"done", "crashed"}

Proc(p) ==
    \/ Open(p) \/ FlockSh(p) \/ Same(p) \/ Look(p) \/ FlockEx(p) \/ SameEx(p) \/ Make(p)
    \/ Down(p) \/ FlockSh2(p) \/ Assume(p) \/ Use(p) \/ Plant(p)
    \/ GcLock(p) \/ GcDead(p) \/ GcEnd(p) \/ GcNext(p)
    \/ EvOpen(p) \/ EvFlock(p) \/ EvSame(p) \/ EvInner(p) \/ EvRename(p) \/ EvSync(p) \/ EvUnlink(p)

Next ==
    \/ \E p \in Procs : Proc(p) \/ Crash(p)
    \/ MachineCrash
    \/ (Terminated /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ \A p \in Procs : WF_vars(Proc(p))

-----------------------------------------------------------------------------
(* Safety.                                                                *)

TypeOK ==
    /\ \A k \in Keys : lockIno[k] <= lockGen[k]
    /\ gc \subseteq Procs /\ Cardinality(gc) <= 1

(* What a job uses, it uses by its path: the name still names that tree,  *)
(* and nothing of it was deleted, until the job ends.                     *)
HeldWhole ==
    \A p \in Procs : S(p).held # 0 =>
        /\ \E k \in Keys : dirOf[k] = S(p).held
        /\ S(p).held \notin half

(* No name ever names a tree something was deleted from: an entry is      *)
(* whole or gone, whatever crashes.                                       *)
NamedWhole == \A k \in Keys : dirOf[k] \notin half

(* Two jobs of one tree do not make it twice.                             *)
OneMaker == \A p, q \in Procs :
    (p # q /\ S(p).pc = "make" /\ S(q).pc = "make") => S(p).key # S(q).key

(* Nothing a job leaves at the inner lock's name keeps a volume from going. *)
NotPinned == ~pinned

(* A dead tree that will not go ends no pass: it would end every pass.    *)
PassGoesOn == ~stopped

(* At most one flock exclusive on an inode, none beside it shared.        *)
LocksExclude == \A l, m \in locks : (l[1] = m[1] /\ l # m) => l[3] = "sh" /\ m[3] = "sh"

-----------------------------------------------------------------------------
(* Liveness: no job waits for ever, and what a collect finds dead goes.   *)

AllEnd == <>Terminated

ProcSymmetry == Permutations(Procs)
=============================================================================
