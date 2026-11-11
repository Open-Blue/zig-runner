/*
 * proofs/tla/ReleasePipeline.tla in Promela, for SPIN (proofs/README.md, "The release pipeline, in
 * TLA+"). The TLA+ module is the documented model and this is the same model, action for action,
 * in the way StoreLockingModel.pml is StoreLocking.tla's (its header says how a module becomes
 * Promela with the same states): a change to one is a change to the other.
 *
 * A configuration (ReleasePipeline*.pml, written from the .cfg of the same name by cfg.py) defines
 * the constants, the invariants and the temporal properties it checks, then includes this file:
 *   MAXMERGES MAXRUNS MAXRENAMES MAXLOST MAXFAILS WAITTICKS GRACE   the module's numbers
 *   LISTFROMCOMMIT FASTFAILS COUNTALL OTHERWF DEPLOYEXPLICIT ATOMICPUSH APPROVALHOLDS
 *                       its Booleans, 0 or 1 (COUNTALL: RunsCounted = "all")
 *   CHK_<Invariant>, LTL_<Property>          one for each the .cfg lists
 * and spin.sh defines LIVENESS when it checks the properties (spin -DLIVENESS).
 *
 * SPIN checks the module's own states: there is no VIEW here, so a safety configuration's count is
 * TLC's without its `VIEW LiveView`, and LiveView's soundness is not needed.
 *
 * The module's values, encoded:
 *   Commits    1 .. MAXC; main is mainSeq[0 .. mainLen-1]; a set of commits is a bit mask.
 *   Wfs        "A", "B", "C" are WA, WB, WC; wf[c][w] is WF(c, w). Without OtherWf the module's
 *              wf[c] has no "C", and WF(c, WC) stays 0 ("none").
 *   Names      "t", "old", "new" are the bits NT, NOLD, NNEW; a set of names (jobsOf, list) a mask.
 *   strings    a run's st, a release's jobs and dep, a failure's why: the numbers below.
 *   vr, rel    indexed by run, 1 .. MAXRUNS; slot 0 is not the module's and stays 0.
 *
 * The processes, by the module's fairness (WF_vars(GitHub) and WF_vars(Job(i)) for each run):
 * GitHub is one process (every CreateWf and FinishWf), each run's Job(i) one, and the rest (Merge,
 * Create, Approve, which are not fair, and Next's step of an ended system) is Env's; with
 * LIVENESS, Env can also stutter, as in StoreLockingModel.pml. So SPIN's weak fairness of processes
 * (pan -f) is the module's fairness. Each step of GitHub and of Job(i) changes the state.
 */

#define MAXC (1 + MAXMERGES + MAXRUNS)
#define BIT(x) (1 << (x))
#define HAS(s, x) (((s) >> (x)) & 1)

/* Wfs */
#define WA 0
#define WB 1
#define WC 2
/* wf[c][w] */
#define W_NONE 0
#define W_CREATING 1
#define W_LOST 2
#define W_QUEUED 3
#define W_PASS 4
#define W_FAIL 5
/* Names: bits */
#define NT 0
#define NOLD 1
#define NNEW 2
/* a run's st */
#define UNBORN 0
#define PENDING 1
#define CHECK 2
#define APPROVAL 3
#define WAIT 4
#define PUSH 5
#define DONE 6
#define FAILED 7
#define CANCELLED 8
/* why, and an Outcome */
#define Y_NONE 0
#define Y_APPROVAL 1
#define Y_MOVED 2
#define Y_CHECKFAILED 3
#define Y_NEVERRAN 4
#define Y_TIMEDOUT 5
#define O_PASS 6
#define O_WAIT 7
/* a release's jobs */
#define J_QUEUED 0
#define J_PASS 1
#define J_FAIL 2
/* its dep */
#define D_WAIT 0
#define D_CHECKS 1
#define D_DEPLOYED 2
#define D_FAILED 3
#define D_SKIPPED 4

typedef Run {
	unsigned st : 4;
	unsigned at : 3;
	unsigned co : 3;
	byte el;
	unsigned why : 3;
	unsigned list : 3;
	byte seen
};

typedef Rel {
	bit on;
	unsigned c : 3;
	unsigned jobs : 2;
	unsigned dep : 3;
	byte el;
	unsigned why : 3
};

byte mainSeq[7];
byte mainLen;
byte ncommits;
byte parent[7];
bit isRel[7];
byte jobsOf[7];
byte wf[21];
Run vr[4];
Rel rel[4];
byte merges, renames, lost, fails, nruns;
bit lateOthers, lateChecks;

#ifdef NOHIDDEN
#define HIDDEN
#else
#define HIDDEN hidden
#endif
HIDDEN byte ix, jx, cx, lx, ex, out, mv, late, anc, oc, ol, oe, nj;
HIDDEN byte TypeOK, OneTagJob, TagOnMain, TagChecked, DeployChecked, FreshList, Includes,
	WaitBounded, FastFail, FastFailOnChecks;

#define WF(cc, w) wf[(cc) * 3 + (w)]
#define TIP mainSeq[mainLen - 1]
#define ME (_pid - 2)
#define R vr[ME]
#define L rel[ME]
#define LIVE(s) ((s) >= PENDING && (s) <= PUSH)
#define INGROUP(s) ((s) == CHECK || (s) == WAIT || (s) == PUSH || (APPROVALHOLDS && (s) == APPROVAL))
#define TAGJOB(s) ((s) == WAIT || (s) == PUSH)
#define RELENDED(i) (rel[i].dep == D_DEPLOYED || rel[i].dep == D_FAILED || rel[i].dep == D_SKIPPED)
#define RAN(x) ((x) == W_QUEUED || (x) == W_PASS || (x) == W_FAIL)

/* Chk(c, n): "t" is ci.yml's (A), "old" and "new" proofs.yml's (B), when the commit defines them. */
#define CHK(cc, n) ((n) == NT -> (RAN(WF(cc, WA)) -> WF(cc, WA) : W_NONE) : \
                   (HAS(jobsOf[cc], n) && RAN(WF(cc, WB)) -> WF(cc, WB) : W_NONE))
#define CREATING(cc) (WF(cc, WA) == W_CREATING || WF(cc, WB) == W_CREATING || WF(cc, WC) == W_CREATING)
#define CIRUNS(cc) (RAN(WF(cc, WA)) || RAN(WF(cc, WB)) || RAN(WF(cc, WC)))
#define CIOPEN(cc) (WF(cc, WA) == W_QUEUED || WF(cc, WB) == W_QUEUED || WF(cc, WC) == W_QUEUED)
/* Version and release runs on c, and the open ones, for RunsCounted = "all". */
#define VRUN(i, cc) (MAXRUNS >= (i) && vr[i].st != UNBORN && vr[i].at == (cc))
#define VOPEN(i, cc) (VRUN(i, cc) && LIVE(vr[i].st))
#define RRUN(i, cc) (MAXRUNS >= (i) && rel[i].on && rel[i].c == (cc))
#define ROPEN(i, cc) (RRUN(i, cc) && !RELENDED(i))
#define TOTAL(cc) (CIRUNS(cc) || VRUN(1, cc) || VRUN(2, cc) || VRUN(3, cc) || RRUN(1, cc) || RRUN(2, cc) || RRUN(3, cc))
#define OPENS(cc) (CIOPEN(cc) || VOPEN(1, cc) || VOPEN(2, cc) || VOPEN(3, cc) || ROPEN(1, cc) || ROPEN(2, cc) || ROPEN(3, cc))
#define SEESDONE(cc) (COUNTALL -> !OPENS(cc) && TOTAL(cc) : !CIOPEN(cc) && CIRUNS(cc))
#define OTHERSDONE(cc) (!CIOPEN(cc) && CIRUNS(cc) && !CREATING(cc))
#define CHECKSDONE(cc) (WF(cc, WA) != W_QUEUED && WF(cc, WB) != W_QUEUED && (RAN(WF(cc, WA)) || RAN(WF(cc, WB))) && \
                       WF(cc, WA) != W_CREATING && WF(cc, WB) != W_CREATING)
#define MISSING(cc, ll) ((HAS(ll, NT) && CHK(cc, NT) == W_NONE) || (HAS(ll, NOLD) && CHK(cc, NOLD) == W_NONE) || \
                       (HAS(ll, NNEW) && CHK(cc, NNEW) == W_NONE))
#define ANYFAIL(cc, ll) ((HAS(ll, NT) && CHK(cc, NT) == W_FAIL) || (HAS(ll, NOLD) && CHK(cc, NOLD) == W_FAIL) || \
                       (HAS(ll, NNEW) && CHK(cc, NNEW) == W_FAIL))
#define ALLPASS(cc, ll) ((!HAS(ll, NT) || CHK(cc, NT) == W_PASS) && (!HAS(ll, NOLD) || CHK(cc, NOLD) == W_PASS) && \
                       (!HAS(ll, NNEW) || CHK(cc, NNEW) == W_PASS))
#define CANPOLL(cc, el) ((el) < GRACE || !CREATING(cc))

/* out := Outcome(oc, ol, oe): the caller sets the three (an inline's argument may not be a
 * record's field). */
inline outcome() {
	if
	:: ANYFAIL(oc, ol) -> out = Y_CHECKFAILED
	:: !ANYFAIL(oc, ol) && ALLPASS(oc, ol) -> out = O_PASS
	:: !ANYFAIL(oc, ol) && !ALLPASS(oc, ol) && FASTFAILS && MISSING(oc, ol) && (oe) >= GRACE && SEESDONE(oc) ->
		out = Y_NEVERRAN
	:: else ->
		if
		:: (oe) >= WAITTICKS -> out = Y_TIMEDOUT
		:: else -> out = O_WAIT
		fi
	fi
}

/* Ghosts(oc, ol, oe, out) */
inline ghosts() {
	late = MISSING(oc, ol) && (oe) >= GRACE && (out == O_WAIT || out == Y_TIMEDOUT);
	lateOthers = lateOthers || (late && OTHERSDONE(oc));
	lateChecks = lateChecks || (late && CHECKSDONE(oc))
}

/* NewCommit(c, p, jobs, release) */
inline newCommit(nc, np, njobs, nr) {
	parent[nc] = np; isRel[nc] = nr; jobsOf[nc] = njobs;
	WF(nc, WA) = W_CREATING; WF(nc, WB) = W_CREATING;
	if
	:: OTHERWF -> WF(nc, WC) = W_CREATING
	:: else
	fi;
	ncommits = nc
}

/* lx := OnMain, as a mask */
inline onMain() {
	lx = 0;
	for (ix : 0 .. MAXC - 1) {
		if
		:: ix < mainLen -> lx = lx | BIT(mainSeq[ix])
		:: else
		fi
	}
}

/* anc := Anc(c), as a mask */
inline ancestors(ac) {
	anc = 0; cx = ac;
	for (ix : 0 .. MAXC) {
		if
		:: cx != 0 -> anc = anc | BIT(cx); cx = parent[cx]
		:: else
		fi
	}
}

inline check() {
#ifdef CHK_TypeOK
	TypeOK = fails <= MAXFAILS && lost <= MAXLOST;
	cx = 0;
	for (ix : 1 .. MAXRUNS) { TypeOK = TypeOK && vr[ix].st <= CANCELLED; cx = cx + (vr[ix].st == PENDING) }
	TypeOK = TypeOK && cx <= 1;
	assert(TypeOK);
#endif
#ifdef CHK_OneTagJob
	cx = 0;
	for (ix : 1 .. MAXRUNS) { cx = cx + TAGJOB(vr[ix].st) }
	OneTagJob = cx <= 1;
	assert(OneTagJob);
#endif
#ifdef CHK_TagOnMain
	onMain();
	TagOnMain = 1;
	for (ix : 1 .. MAXRUNS) { TagOnMain = TagOnMain && (!rel[ix].on || HAS(lx, rel[ix].c)) }
	assert(TagOnMain);
#endif
#ifdef CHK_TagChecked
	TagChecked = 1;
	for (jx : 1 .. MAXRUNS) {
		if
		:: rel[jx].on ->
			cx = parent[rel[jx].c];
			TagChecked = TagChecked && cx == vr[jx].co && ALLPASS(cx, jobsOf[cx])
		:: else
		fi
	}
	assert(TagChecked);
#endif
#ifdef CHK_DeployChecked
	DeployChecked = 1;
	for (jx : 1 .. MAXRUNS) {
		if
		:: rel[jx].on && rel[jx].dep == D_DEPLOYED ->
			cx = rel[jx].c;
			DeployChecked = DeployChecked && rel[jx].jobs == J_PASS && ALLPASS(cx, jobsOf[cx])
		:: else
		fi
	}
	assert(DeployChecked);
#endif
#ifdef CHK_FreshList
	FreshList = 1;
	for (jx : 1 .. MAXRUNS) { FreshList = FreshList && (!TAGJOB(vr[jx].st) || vr[jx].list == jobsOf[vr[jx].co]) }
	assert(FreshList);
#endif
#ifdef CHK_Includes
	Includes = 1;
	for (jx : 1 .. MAXRUNS) {
		if
		:: rel[jx].on -> lx = rel[jx].c; ancestors(lx); Includes = Includes && (vr[jx].seen & ~anc) == 0
		:: else
		fi
	}
	assert(Includes);
#endif
#ifdef CHK_WaitBounded
	WaitBounded = 1;
	for (jx : 1 .. MAXRUNS) {
		WaitBounded = WaitBounded && vr[jx].el <= WAITTICKS && rel[jx].el <= WAITTICKS &&
			(vr[jx].st != FAILED || vr[jx].why != Y_NONE) && (rel[jx].dep != D_FAILED || rel[jx].why != Y_NONE)
	}
	assert(WaitBounded);
#endif
#ifdef CHK_FastFail
	FastFail = !lateOthers;
	assert(FastFail);
#endif
#ifdef CHK_FastFailOnChecks
	FastFailOnChecks = !lateChecks;
	assert(FastFailOnChecks);
#endif
	ix = 0; jx = 0; cx = 0; lx = 0; ex = 0; out = 0; mv = 0; late = 0; anc = 0; oc = 0; ol = 0; oe = 0;
	nj = 0;
	TypeOK = 0; OneTagJob = 0; TagOnMain = 0; TagChecked = 0; DeployChecked = 0; FreshList = 0;
	Includes = 0; WaitBounded = 0; FastFail = 0; FastFailOnChecks = 0
}

/* ------------------------------------------------------------------------------------------- */

/* GitHub: CreateWf(c, w) and FinishWf(c, w), for every commit and workflow. */
#define GH(cc, w) \
	:: d_step { MAXC >= (cc) && WF(cc, w) == W_CREATING -> WF(cc, w) = W_QUEUED} \
	:: d_step { MAXC >= (cc) && WF(cc, w) == W_CREATING && lost < MAXLOST -> WF(cc, w) = W_LOST; lost++} \
	:: d_step { MAXC >= (cc) && WF(cc, w) == W_QUEUED -> WF(cc, w) = W_PASS} \
	:: d_step { MAXC >= (cc) && (w) != WC && WF(cc, w) == W_QUEUED && fails < MAXFAILS -> \
		WF(cc, w) = W_FAIL; fails++ }
#define GHC(cc) GH(cc, WA) GH(cc, WB) GH(cc, WC)

proctype GitHub() {
	do
	:: atomic {
	if
	GHC(1) GHC(2) GHC(3) GHC(4) GHC(5) GHC(6)
	fi;
	d_step { check() } }
	od
}

/* Job(i), for run ME. */
proctype Job() {
	do
	:: atomic {
	if
	/* StartPending */
	:: d_step { R.st == PENDING &&
	            !INGROUP(vr[1].st) && !(MAXRUNS > 1 && INGROUP(vr[2].st)) && !(MAXRUNS > 2 && INGROUP(vr[3].st)) ->
		R.st = CHECK }
	/* Check */
	:: d_step { R.st == CHECK -> R.st = (isRel[TIP] -> DONE : APPROVAL) }
	/* ApprovalTimeout */
	:: d_step { R.st == APPROVAL -> R.st = FAILED; R.why = Y_APPROVAL }
	/* Poll */
	:: d_step { R.st == WAIT && CANPOLL(R.co, R.el) ->
		oc = R.co; ol = R.list; oe = R.el;
		outcome();
		ghosts();
		if
		:: out == O_PASS -> R.st = PUSH
		:: out == O_WAIT -> R.el++
		:: else -> R.st = FAILED; R.why = out
		fi }
	/* Push */
	:: d_step { R.st == PUSH ->
		cx = ncommits + 1;
		mv = (TIP != R.co);
		if
		:: mv && ATOMICPUSH -> R.st = FAILED; R.why = Y_MOVED
		:: else ->
			ex = R.co; nj = jobsOf[ex];
			newCommit(cx, ex, nj, 1);
			if
			:: !mv -> mainSeq[mainLen] = cx; mainLen++; R.st = DONE
			:: else -> R.st = FAILED; R.why = Y_MOVED
			fi;
			L.on = 1; L.c = cx; L.jobs = J_QUEUED; L.dep = D_WAIT; L.el = 0; L.why = Y_NONE
		fi }
	/* Build */
	:: d_step { L.on && L.jobs == J_QUEUED -> L.jobs = J_PASS }
	:: d_step { L.on && L.jobs == J_QUEUED && fails < MAXFAILS -> L.jobs = J_FAIL; fails++ }
	/* DeployStart */
	:: d_step { L.on && L.dep == D_WAIT && L.jobs != J_QUEUED ->
		L.dep = (DEPLOYEXPLICIT && L.jobs == J_PASS -> D_CHECKS : D_SKIPPED) }
	/* DeployPoll */
	:: d_step { L.on && L.dep == D_CHECKS && CANPOLL(L.c, L.el) ->
		oc = L.c; ol = jobsOf[oc]; oe = L.el;
		outcome();
		ghosts();
		if
		:: out == O_PASS -> L.dep = D_DEPLOYED
		:: out == O_WAIT -> L.el++
		:: else -> L.dep = D_FAILED; L.why = out
		fi }
	fi;
	d_step { check() } }
	od
}

/* Merge, Create, Approve and Next's step of an ended system. */
#define INPROGRESS (INGROUP(vr[1].st) || (MAXRUNS > 1 && INGROUP(vr[2].st)) || (MAXRUNS > 2 && INGROUP(vr[3].st)))
#define ANYPENDING (vr[1].st == PENDING || (MAXRUNS > 1 && vr[2].st == PENDING) || (MAXRUNS > 2 && vr[3].st == PENDING))
#define RUNENDED(i) (MAXRUNS < (i) || (!LIVE(vr[i].st) && (!rel[i].on || RELENDED(i))))
#define COMMITENDED(cc) (MAXC < (cc) || (!CIOPEN(cc) && !CREATING(cc)))
#define ENDED (nruns == MAXRUNS && RUNENDED(1) && RUNENDED(2) && RUNENDED(3) && \
               COMMITENDED(1) && COMMITENDED(2) && COMMITENDED(3) && COMMITENDED(4) && COMMITENDED(5) && COMMITENDED(6))

/* Merge, with jobs the configuration given. */
inline merge(mj) {
	d_step { merges < MAXMERGES && ncommits < MAXC && (mj == jobsOf[TIP] || renames < MAXRENAMES) ->
		if
		:: mj != jobsOf[TIP] -> renames++
		:: else
		fi;
		cx = ncommits + 1; ex = TIP;
		newCommit(cx, ex, mj, 0);
		mainSeq[mainLen] = cx; mainLen++;
		merges++ }
}

/* Approve(i) */
inline approve(i) {
	d_step { MAXRUNS >= (i) && vr[i].st == APPROVAL ->
		cx = TIP;
		vr[i].st = (isRel[cx] -> DONE : WAIT);
		vr[i].co = cx;
		vr[i].list = (LISTFROMCOMMIT -> jobsOf[cx] : jobsOf[vr[i].at]);
		onMain(); vr[i].seen = lx }
}

proctype Env() {
end:
	do
	:: atomic {
	if
	/* Merge: {"t", "old"}, {"t", "new"}, {"t", "old", "new"} */
	:: merge(3)
	:: merge(5)
	:: merge(7)
	/* Create */
	:: d_step { nruns < MAXRUNS && !(!INPROGRESS && ANYPENDING) ->
		cx = nruns + 1;
		for (ix : 1 .. MAXRUNS) {
			if
			:: vr[ix].st == PENDING -> vr[ix].st = CANCELLED
			:: else
			fi
		}
		vr[cx].st = (INPROGRESS -> PENDING : CHECK);
		vr[cx].at = TIP;
		nruns++ }
	:: approve(1)
	:: approve(2)
	:: approve(3)
#ifdef LIVENESS
	/* The stutter (StoreLockingModel.pml says why). */
	:: lateOthers || !lateOthers -> skip
#else
	:: atomic { ENDED -> skip }
#endif
	fi;
	d_step { check() } }
	od
}

#ifdef LTL_TagJobEnds
#define TAGENDS(i) (MAXRUNS < (i) || (TAGJOB(vr[i].st) -> <> (vr[i].st == DONE || vr[i].st == FAILED)))
ltl TagJobEnds { [] (TAGENDS(1) && TAGENDS(2) && TAGENDS(3)) }
#endif
#ifdef LTL_DeployEnds
#define DEPLOYENDS(i) (MAXRUNS < (i) || (rel[i].on -> <> (rel[i].dep == D_DEPLOYED || rel[i].jobs == J_FAIL || rel[i].dep == D_FAILED)))
ltl DeployEnds { [] (DEPLOYENDS(1) && DEPLOYENDS(2) && DEPLOYENDS(3)) }
#endif

/* Init: SPIN's first state, then one step to the module's initial state, and the processes:
 * init is pid 0, Env 1, GitHub 2, run i's Job pid 2 + i. */
init {
	atomic {
		assert(MAXC <= 6 && MAXRUNS <= 3);
		d_step {
			mainSeq[0] = 1; mainLen = 1; ncommits = 1;
			isRel[1] = 1;
			for (ix : 1 .. MAXC) { jobsOf[ix] = BIT(NT) | BIT(NOLD) }
			WF(1, WA) = W_PASS; WF(1, WB) = W_PASS;
			if
			:: OTHERWF -> WF(1, WC) = W_PASS
			:: else
			fi;
			for (ix : 1 .. MAXRUNS) { vr[ix].at = 1; vr[ix].co = 1; rel[ix].c = 1 }
			check()
		};
		run Env();
		run GitHub();
		for (ix : 1 .. MAXRUNS) { run Job() }
	}
}
