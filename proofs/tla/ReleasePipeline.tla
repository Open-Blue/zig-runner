--------------------------- MODULE ReleasePipeline ---------------------------
(***************************************************************************)
(* The release pipeline, at the level of GitHub's runs and jobs, as #408   *)
(* has it (proofs/README.md, "The release pipeline, in TLA+"):             *)
(* .github/workflows/version.yml (a scheduled or dispatched run in the     *)
(* `version` concurrency group; its check job; its tag job in the prod     *)
(* environment, which waits for approval, reads main again, waits for      *)
(* main's checks, commits the release, tags it and pushes both with        *)
(* `git push --atomic`), .github/scripts/next-version.sh (nothing merged   *)
(* since the last tag: no tag), .github/workflows/release.yml (on the      *)
(* tag: Binaries, Image and Image (publish), and the deploy job, whose     *)
(* `if:` names its needs' results, waiting for the tag commit's checks),   *)
(* and .github/scripts/wait-for-checks.sh, which both waits run: the names *)
(* in .github/checks-on-main read from the commit the job checked out, a   *)
(* failed check failing the wait at once, a check that never started      *)
(* failing it once every workflow run on the commit but the waiting        *)
(* workflows' (version.yml's and release.yml's, since 85dc4e8) has         *)
(* finished and the grace has passed, anything else at the end of the      *)
(* wait.                                                                   *)
(*                                                                         *)
(* main is a line of commits: merges (the merge queue's; each may rename   *)
(* or add a check, as #405 renamed one) and release commits.  A commit     *)
(* pushed to main starts ci.yml's and proofs.yml's push runs ("A" and      *)
(* "B"), whose jobs are the checks: "t" one no merge renames (Tests        *)
(* (x86_64), Database tests, Workflows), "old" and "new" the one a merge   *)
(* renames or adds; with OtherWf, also a run that reports none of them     *)
(* ("C": codeql.yml's, scorecard.yml's, or a scheduled run made at the     *)
(* commit, as analysis.yml's).  A run's jobs end together, passing or      *)
(* failing: a run with one failed job is the same to the wait as one with  *)
(* several.                                                                *)
(* check-names.sh holds in the merge queue, so the names in checks-on-main *)
(* at a commit are the jobs that commit runs on a push: one function,      *)
(* `jobsOf`.  GitHub may never create a run (`lost`): then its checks      *)
(* never start.                                                            *)
(*                                                                         *)
(* Time is the wait's polls: `el` counts them, WaitTicks is WAIT_MINUTES   *)
(* and Grace GRACE_SECONDS.  That GitHub creates a push's runs within the  *)
(* grace is an assumption (`CanPoll`).                                     *)
(*                                                                         *)
(* Concurrency, as https://docs.github.com/en/actions/how-tos/write-       *)
(* workflows/choose-when-workflows-run/control-workflow-concurrency says   *)
(* ("Control the concurrency of workflows and jobs"): in a group, at most  *)
(* one run in progress and, with the default `queue: single`, at most one  *)
(* pending; a run queued while one is in progress is pending, and a        *)
(* pending one already there is cancelled; with cancel-in-progress false   *)
(* the run in progress is kept.  The page does not say whether a run whose *)
(* job waits for an environment's approval is in progress; it has started, *)
(* and ApprovalHoldsGroup = TRUE takes it so.  The weaker reading (FALSE:  *)
(* a newer run may start beside it) is ReleasePipeline-approval-outside's. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    MaxMerges,          \* merges into main
    MaxRuns,            \* version runs, scheduled or dispatched
    MaxRenames,         \* merges that change the checks' names
    MaxLost,            \* push runs GitHub never creates
    MaxFails,           \* push runs or releases' jobs that fail
    WaitTicks,          \* WAIT_MINUTES, in polls
    Grace,              \* GRACE_SECONDS, in polls
    ListFromCommit,     \* #408: the names from the commit checked out; FALSE: the run's own file
    FastFails,          \* #408: a check that never started fails the wait once the runs finished
    RunsCounted,        \* "others": every workflow run on the commit but the waiting workflows'
                        \* (version.yml's, release.yml's), as #408 has it since 85dc4e8;
                        \* "all": every run, the waiting job's own among them, as before it
    OtherWf,            \* a third push run on every commit, reporting none of the checks
                        \* (codeql.yml's, scorecard.yml's), which the fast fail waits for too
    DeployIfExplicit,   \* release.yml's deploy `if:` names its needs' results; FALSE: success()
    AtomicPush,         \* `git push --atomic HEAD:main refs/tags/$TAG`
    ApprovalHoldsGroup  \* a run waiting for approval is in progress in the group

Wfs == IF OtherWf THEN {"A", "B", "C"} ELSE {"A", "B"}
Producers == {"A", "B"}
Names == {"t", "old", "new"}
Configs == {{"t", "old"}, {"t", "new"}, {"t", "old", "new"}}
MaxCommits == 1 + MaxMerges + MaxRuns
Commits == 1..MaxCommits
Runs == 1..MaxRuns

VARIABLES
    main,     \* main's commits, oldest first
    ncommits, \* commits made
    parent, isRel, jobsOf,
    wf,       \* wf[c][w]: "none" (not pushed), "creating", "lost", "queued", "pass", "fail"
    vr,       \* the version runs
    rel,      \* rel[i]: the release run of the tag vr[i] pushed
    merges, renames, lost, fails, nruns,
    lateOthers, \* ghost: a wait went on, a check missing, once every run on the commit but the
                \* waiting workflows' had finished
    lateChecks  \* ghost: ... once the runs that report the checks (ci's, proofs') had finished

vars == <<main, ncommits, parent, isRel, jobsOf, wf, vr, rel, merges, renames, lost, fails, nruns,
          lateOthers, lateChecks>>

Tip == main[Len(main)]
OnMain == {main[k] : k \in 1..Len(main)}

(* The jobs a push run on c defines: ci.yml's do not change, the renamed  *)
(* one is proofs.yml's.                                                   *)
WfJobs(c, w) == CASE w = "A" -> {"t"} [] w = "B" -> jobsOf[c] \ {"t"} [] OTHER -> {}

(* A check's latest run on c: "none" when it never started.               *)
Chk(c, n) ==
    IF \E w \in Wfs : n \in WfJobs(c, w) /\ wf[c][w] \in {"queued", "pass", "fail"}
    THEN LET w == CHOOSE w \in Wfs : n \in WfJobs(c, w) IN wf[c][w]
    ELSE "none"

(* st: "unborn", "pending", "check" (Anything to release), "approval"    *)
(* (the tag job waiting for prod's approval), "wait" (Wait for main's     *)
(* checks), "push" (Commit and tag, Push), "done", "failed", "cancelled". *)
(* at: main when GitHub made the run (its head_sha, and the version.yml   *)
(* it runs); co: the commit the tag job checked out; list: the names it   *)
(* waits for; seen: main when it read it.                                 *)
NoRun == [st |-> "unborn", at |-> 1, co |-> 1, el |-> 0, why |-> "", list |-> {}, seen |-> {}]
(* jobs: Binaries, Image and Image (publish); dep: the deploy job, "wait" *)
(* (for its needs), "checks", "deployed", "failed", "skipped".            *)
NoRel == [on |-> FALSE, c |-> 1, jobs |-> "queued", dep |-> "wait", el |-> 0, why |-> ""]
Live == {"pending", "check", "approval", "wait", "push"}
InGroup == IF ApprovalHoldsGroup THEN {"check", "approval", "wait", "push"}
           ELSE {"check", "wait", "push"}
TagJob == {"wait", "push"}

Init ==
    /\ main = <<1>>
    /\ ncommits = 1
    /\ parent = [c \in Commits |-> 0]
    /\ isRel = [c \in Commits |-> c = 1]   \* the last release
    /\ jobsOf = [c \in Commits |-> {"t", "old"}]
    /\ wf = [c \in Commits |-> [w \in Wfs |-> IF c = 1 THEN "pass" ELSE "none"]]
    /\ vr = [i \in Runs |-> NoRun]
    /\ rel = [i \in Runs |-> NoRel]
    /\ merges = 0 /\ renames = 0 /\ lost = 0 /\ fails = 0 /\ nruns = 0
    /\ lateOthers = FALSE /\ lateChecks = FALSE

-----------------------------------------------------------------------------
(* What wait-for-checks.sh sees of a commit.                              *)

Creating(c) == \E w \in Wfs : wf[c][w] = "creating"
RelEnded(i) == rel[i].dep \in {"deployed", "failed", "skipped"}

(* actions/runs?head_sha=c: the push runs, the version runs GitHub made   *)
(* at c (pending ones too), and the release run of a tag on c.            *)
CIRuns(c) == {w \in Wfs : wf[c][w] \in {"queued", "pass", "fail"}}
CIOpen(c) == {w \in Wfs : wf[c][w] = "queued"}
VRuns(c) == {i \in Runs : vr[i].st # "unborn" /\ vr[i].at = c}
VOpen(c) == {i \in VRuns(c) : vr[i].st \in Live}
RRuns(c) == {i \in Runs : rel[i].on /\ rel[i].c = c}
ROpen(c) == {i \in RRuns(c) : ~RelEnded(i)}
Total(c) == Cardinality(CIRuns(c)) + Cardinality(VRuns(c)) + Cardinality(RRuns(c))
Open(c) == Cardinality(CIOpen(c)) + Cardinality(VOpen(c)) + Cardinality(ROpen(c))

(* `open == 0 && total > 0`, over what the query counts: since 85dc4e8,   *)
(* every run but version.yml's and release.yml's, the push runs here;     *)
(* before it, every run, the waiting job's own among them.                *)
ScriptSeesDone(c) ==
    IF RunsCounted = "all" THEN Open(c) = 0 /\ Total(c) > 0
    ELSE CIOpen(c) = {} /\ CIRuns(c) # {}
(* What a wait could be waiting on has finished: every run but the        *)
(* waiting workflows' (OthersDone), or the runs that report the checks    *)
(* (ChecksDone).                                                          *)
OthersDone(c) == CIOpen(c) = {} /\ CIRuns(c) # {} /\ ~Creating(c)
ChecksDone(c) ==
    /\ CIOpen(c) \cap Producers = {} /\ CIRuns(c) \cap Producers # {}
    /\ \A w \in Producers : wf[c][w] # "creating"

Missing(c, L) == {n \in L : Chk(c, n) = "none"}

(* One poll: each name's latest check run, then the fast fail, then the   *)
(* deadline.                                                              *)
Outcome(c, L, el) ==
    IF \E n \in L : Chk(c, n) = "fail" THEN "a check failed"
    ELSE IF \A n \in L : Chk(c, n) = "pass" THEN "pass"
    ELSE IF FastFails /\ Missing(c, L) # {} /\ el >= Grace /\ ScriptSeesDone(c) THEN "never ran"
    ELSE IF el >= WaitTicks THEN "timed out"
    ELSE "wait"

(* GitHub creates a push's runs within the grace: a poll past it comes    *)
(* after them.                                                            *)
CanPoll(c, el) == el < Grace \/ ~Creating(c)

Late(c, L, el, out) == Missing(c, L) # {} /\ el >= Grace /\ out \in {"wait", "timed out"}
Ghosts(c, L, el, out) ==
    /\ lateOthers' = (lateOthers \/ (Late(c, L, el, out) /\ OthersDone(c)))
    /\ lateChecks' = (lateChecks \/ (Late(c, L, el, out) /\ ChecksDone(c)))

-----------------------------------------------------------------------------
(* main and its push runs.                                                *)

NewCommit(c, p, jobs, release) ==
    /\ parent' = [parent EXCEPT ![c] = p]
    /\ isRel' = [isRel EXCEPT ![c] = release]
    /\ jobsOf' = [jobsOf EXCEPT ![c] = jobs]
    /\ wf' = [wf EXCEPT ![c] = [w \in Wfs |-> "creating"]]
    /\ ncommits' = c

(* A merge from the merge queue, which may rename or add a check (and     *)
(* checks-on-main with it, check-names.sh).                               *)
Merge ==
    /\ merges < MaxMerges /\ ncommits < MaxCommits
    /\ \E jobs \in Configs :
        /\ (jobs # jobsOf[Tip]) => renames < MaxRenames
        /\ renames' = IF jobs # jobsOf[Tip] THEN renames + 1 ELSE renames
        /\ NewCommit(ncommits + 1, Tip, jobs, FALSE)
    /\ main' = Append(main, ncommits + 1)
    /\ merges' = merges + 1
    /\ UNCHANGED <<vr, rel, lost, fails, nruns, lateOthers, lateChecks>>

(* GitHub creates a push run, its jobs queued, or never does.             *)
CreateWf(c, w) ==
    /\ wf[c][w] = "creating"
    /\ \/ wf' = [wf EXCEPT ![c][w] = "queued"] /\ UNCHANGED lost
       \/ lost < MaxLost /\ wf' = [wf EXCEPT ![c][w] = "lost"] /\ lost' = lost + 1
    /\ UNCHANGED <<main, ncommits, parent, isRel, jobsOf, vr, rel, merges, renames, fails, nruns,
                   lateOthers, lateChecks>>

FinishWf(c, w) ==
    /\ wf[c][w] = "queued"
    /\ \/ wf' = [wf EXCEPT ![c][w] = "pass"] /\ UNCHANGED fails
       \/ /\ w \in Producers   \* how the others end does not matter to the wait
          /\ fails < MaxFails /\ wf' = [wf EXCEPT ![c][w] = "fail"] /\ fails' = fails + 1
    /\ UNCHANGED <<main, ncommits, parent, isRel, jobsOf, vr, rel, merges, renames, lost, nruns,
                   lateOthers, lateChecks>>

-----------------------------------------------------------------------------
(* version.yml.                                                           *)

SetRun(i, r) == vr' = [vr EXCEPT ![i] = r]
Fail(r, why) == [r EXCEPT !.st = "failed", !.why = why]
UnchangedButRuns == UNCHANGED <<main, ncommits, parent, isRel, jobsOf, wf, merges, renames, lost,
                                fails, lateOthers, lateChecks>>

InProgress == {i \in Runs : vr[i].st \in InGroup}
Pending == {i \in Runs : vr[i].st = "pending"}

(* The schedule's or a dispatch's run, made from main as it is, enters    *)
(* the group: it starts, or is pending and cancels the pending one.  A    *)
(* pending run starts as the group frees (StartPending comes first).      *)
Create ==
    /\ nruns < MaxRuns
    /\ ~(InProgress = {} /\ Pending # {})
    /\ LET i == nruns + 1 IN
       vr' = [j \in Runs |->
                IF j = i THEN [NoRun EXCEPT !.st = IF InProgress = {} THEN "check" ELSE "pending",
                                            !.at = Tip]
                ELSE IF j \in Pending THEN [vr[j] EXCEPT !.st = "cancelled"]
                ELSE vr[j]]
    /\ nruns' = nruns + 1
    /\ UNCHANGED rel /\ UnchangedButRuns

StartPending(i) ==
    /\ vr[i].st = "pending" /\ InProgress = {}
    /\ SetRun(i, [vr[i] EXCEPT !.st = "check"])
    /\ UNCHANGED <<rel, nruns>> /\ UnchangedButRuns

(* Anything to release: next-version.sh on main.                          *)
Check(i) ==
    /\ vr[i].st = "check"
    /\ SetRun(i, [vr[i] EXCEPT !.st = IF isRel[Tip] THEN "done" ELSE "approval"])
    /\ UNCHANGED <<rel, nruns>> /\ UnchangedButRuns

(* The maintainer approves, late or never; the tag job checks out main    *)
(* and works the version out again (next-version.sh).                     *)
Approve(i) ==
    /\ vr[i].st = "approval"
    /\ SetRun(i, [vr[i] EXCEPT !.st = IF isRel[Tip] THEN "done" ELSE "wait", !.co = Tip,
                   !.list = IF ListFromCommit THEN jobsOf[Tip] ELSE jobsOf[vr[i].at],
                   !.seen = OnMain])
    /\ UNCHANGED <<rel, nruns>> /\ UnchangedButRuns

(* No approval: the environment's wait runs out (after 30 days).          *)
ApprovalTimeout(i) ==
    /\ vr[i].st = "approval"
    /\ SetRun(i, Fail(vr[i], "approval timed out"))
    /\ UNCHANGED <<rel, nruns>> /\ UnchangedButRuns

(* Wait for main's checks: one poll of wait-for-checks.sh.                *)
Poll(i) ==
    LET r == vr[i]
        out == Outcome(r.co, r.list, r.el) IN
    /\ r.st = "wait" /\ CanPoll(r.co, r.el)
    /\ SetRun(i, CASE out = "pass" -> [r EXCEPT !.st = "push"]
                  [] out = "wait" -> [r EXCEPT !.el = @ + 1]
                  [] OTHER -> Fail(r, out))
    /\ Ghosts(r.co, r.list, r.el, out)
    /\ UNCHANGED <<main, ncommits, parent, isRel, jobsOf, wf, rel, merges, renames, lost, fails,
                   nruns>>

(* Commit and tag, Push: the release commit on the commit checked out,    *)
(* pushed with its tag at once; if main moved, both are refused.  Without *)
(* --atomic the tag goes and main's update is refused.  The tag starts     *)
(* release.yml, and the push to main ci.yml's and proofs.yml's runs.      *)
Push(i) ==
    LET r == vr[i]
        c == ncommits + 1
        moved == Tip # r.co IN
    /\ r.st = "push"
    /\ IF moved /\ AtomicPush
       THEN /\ SetRun(i, Fail(r, "main moved"))
            /\ UNCHANGED <<main, ncommits, parent, isRel, jobsOf, wf, rel>>
       ELSE /\ NewCommit(c, r.co, jobsOf[r.co], TRUE)
            /\ main' = IF moved THEN main ELSE Append(main, c)
            /\ SetRun(i, IF moved THEN Fail(r, "main moved") ELSE [r EXCEPT !.st = "done"])
            /\ rel' = [rel EXCEPT ![i] = [NoRel EXCEPT !.on = TRUE, !.c = c]]
    /\ UNCHANGED <<merges, renames, lost, fails, nruns, lateOthers, lateChecks>>

-----------------------------------------------------------------------------
(* release.yml, on the tag.                                               *)

SetRel(i, r) == rel' = [rel EXCEPT ![i] = r]
UnchangedButRel == UNCHANGED <<main, ncommits, parent, isRel, jobsOf, wf, vr, merges, renames,
                               lost, nruns, lateOthers, lateChecks>>

(* Binaries, Image (`!contains(needs.*.result, 'failure')`) and Image      *)
(* (publish), one step: a failure of any is the same to the deploy job.    *)
(* Binaries (check), pull requests' only, is skipped.                      *)
Build(i) ==
    /\ rel[i].on /\ rel[i].jobs = "queued"
    /\ \/ SetRel(i, [rel[i] EXCEPT !.jobs = "pass"]) /\ UNCHANGED fails
       \/ fails < MaxFails /\ SetRel(i, [rel[i] EXCEPT !.jobs = "fail"]) /\ fails' = fails + 1
    /\ UnchangedButRel

(* The deploy job's `if:`.  The implicit success() wants every job before *)
(* it to have succeeded, Binaries (check) too, which is skipped on a tag.  *)
DeployStart(i) ==
    LET r == rel[i]
        go == DeployIfExplicit /\ r.jobs = "pass" IN
    /\ r.on /\ r.dep = "wait" /\ r.jobs # "queued"
    /\ SetRel(i, [r EXCEPT !.dep = IF go THEN "checks" ELSE "skipped"])
    /\ UNCHANGED fails /\ UnchangedButRel

(* Wait for the tagged commit's checks (checks-on-main, read from the     *)
(* tag; its own Binaries and Image passed, as its `needs:` say), then     *)
(* record the deployment.                                                 *)
DeployPoll(i) ==
    LET r == rel[i]
        out == Outcome(r.c, jobsOf[r.c], r.el) IN
    /\ r.on /\ r.dep = "checks" /\ CanPoll(r.c, r.el)
    /\ SetRel(i, CASE out = "pass" -> [r EXCEPT !.dep = "deployed"]
                  [] out = "wait" -> [r EXCEPT !.el = @ + 1]
                  [] OTHER -> [r EXCEPT !.dep = "failed", !.why = out])
    /\ Ghosts(r.c, jobsOf[r.c], r.el, out)
    /\ UNCHANGED <<main, ncommits, parent, isRel, jobsOf, wf, vr, merges, renames, lost, fails,
                   nruns>>

-----------------------------------------------------------------------------

GitHub == \E c \in Commits, w \in Wfs : CreateWf(c, w) \/ FinishWf(c, w)
Job(i) ==
    \/ StartPending(i) \/ Check(i) \/ ApprovalTimeout(i) \/ Poll(i) \/ Push(i)
    \/ Build(i) \/ DeployStart(i) \/ DeployPoll(i)

(* Every run made and ended, and GitHub has nothing left to do: any other *)
(* state without a step is stuck, and TLC reports it as a deadlock.       *)
Ended ==
    /\ nruns = MaxRuns
    /\ \A i \in Runs : vr[i].st \notin Live /\ (rel[i].on => RelEnded(i))
    /\ \A c \in Commits : CIOpen(c) = {} /\ ~Creating(c)

Next ==
    \/ Merge \/ Create \/ GitHub
    \/ \E i \in Runs : Approve(i) \/ Job(i)
    \/ (Ended /\ UNCHANGED vars)

(* GitHub's steps and the jobs' are fair; merges, new runs and the        *)
(* maintainer's approval are not (an approval may never come).            *)
Spec == Init /\ [][Next]_vars /\ WF_vars(GitHub) /\ \A i \in Runs : WF_vars(Job(i))

-----------------------------------------------------------------------------
(* Safety.                                                                *)

TypeOK ==
    /\ \A i \in Runs : vr[i].st \in Live \cup {"unborn", "done", "failed", "cancelled"}
    /\ Cardinality(Pending) <= 1
    /\ fails <= MaxFails /\ lost <= MaxLost

Tagged == {i \in Runs : rel[i].on}

(* Never two tag jobs at once.                                             *)
OneTagJob == Cardinality({i \in Runs : vr[i].st \in TagJob}) <= 1

(* A tag is always on main's history.                                      *)
TagOnMain == \A i \in Tagged : rel[i].c \in OnMain

(* No tag unless every check main must pass (checks-on-main at the commit) *)
(* succeeded on the commit the release commit goes on, which adds only the *)
(* version and the changelog to it; the release commit's own are the       *)
(* deploy's (DeployChecked).                                               *)
TagChecked == \A i \in Tagged :
    LET c == parent[rel[i].c] IN c = vr[i].co /\ \A n \in jobsOf[c] : Chk(c, n) = "pass"

(* No deployment unless the tag commit's checks and the release's own jobs *)
(* passed.                                                                 *)
DeployChecked == \A i \in Tagged : rel[i].dep = "deployed" =>
    rel[i].jobs = "pass" /\ \A n \in jobsOf[rel[i].c] : Chk(rel[i].c, n) = "pass"

(* Freshness: the tag job waits for the list current at the commit it     *)
(* checked out, never a stale one.                                        *)
FreshList == \A i \in Runs : vr[i].st \in TagJob => vr[i].list = jobsOf[vr[i].co]

RECURSIVE Anc(_)
Anc(c) == IF c = 0 THEN {} ELSE {c} \cup Anc(parent[c])

(* Freshness: the release includes every merge on main when its tag job   *)
(* read it.                                                               *)
Includes == \A i \in Tagged : vr[i].seen \subseteq Anc(rel[i].c)

(* A wait ends within its WAIT_MINUTES, and a failure names its reason.   *)
WaitBounded == \A i \in Runs :
    /\ vr[i].el <= WaitTicks /\ rel[i].el <= WaitTicks
    /\ vr[i].st = "failed" => vr[i].why # ""
    /\ rel[i].dep = "failed" => rel[i].why # ""

(* The fast fail: once every workflow run on the commit but the waiting   *)
(* workflows' (version.yml's, release.yml's) has finished, a check that   *)
(* never started ends the wait at the first poll past the grace, not at   *)
(* the deadline.                                                          *)
FastFail == ~lateOthers

(* Sooner: once the runs that report the checks have finished, whatever   *)
(* else runs on the commit (codeql, scorecard).  The script waits for     *)
(* those too, so this fails with OtherWf: ReleasePipeline-other-wf.cfg.   *)
FastFailOnChecks == ~lateChecks

-----------------------------------------------------------------------------
(* Liveness, under Spec's fairness.                                       *)

(* An approved tag job ends: it tags, finds nothing to release, or fails   *)
(* naming a reason.                                                       *)
TagJobEnds == \A i \in Runs : vr[i].st \in TagJob ~> vr[i].st \in {"done", "failed"}

(* A release that tagged deploys, or fails where it shows: a job failed.   *)
Visible(i) == rel[i].jobs = "fail" \/ rel[i].dep = "failed"
DeployEnds == \A i \in Runs : rel[i].on ~> (rel[i].dep = "deployed" \/ Visible(i))
=============================================================================
