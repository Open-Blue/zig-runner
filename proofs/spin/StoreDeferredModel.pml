/*
 * proofs/tla/StoreDeferred.tla in Promela, for SPIN (proofs/README.md, "The store's locking, in
 * TLA+", the deferred sync). The TLA+ module is the documented model, no longer machine-checked,
 * and this is the same model, action for action, in the way StoreLockingModel.pml is
 * StoreLocking.tla's (its header says how a module becomes Promela with the same states): a change
 * to one is a change to the other.
 *
 * A configuration (StoreDeferred*.pml, written from the .cfg of the same name by cfg.py) defines
 * the constants and the invariants it checks, then includes this file:
 *   NP NR NS MC MAXRCRASH MAXWERR      |Procs|, |Readers|, Steps, MachineCrashes,
 *                                      MaxRunnerCrashes, MaxWriteErrors
 *   SYNCBEFORE CHECKBOOT OWNERONLY POISON SETTLEEND
 *                                      SyncBeforeMark, CheckBoot, OwnerOnly, PoisonOnFail,
 *                                      SettleAtEnd: 0 or 1
 *   CHK_<Invariant>                    one for each invariant the .cfg lists
 *
 * The module's values, encoded:
 *   Procs      0 .. NP-1; runner q is SPIN's process q+1, Env NP+1. Readers 0 .. NR-1.
 *   Ents       <<q, i>> is the index q*NS + i-1; a set of entries (held, evicted, promised) a bit
 *              mask. cur[q] is the index plus 1, 0 for <<>>.
 *   strings    pc, meta and tree are the numbers below ("whole" 0, "broken" 1).
 *
 * The module's Spec has no fairness and no temporal property, so the processes only group the
 * actions: runner q's are Proc(q) (RunnerCrash among them, as the module has it), Env's the rest
 * (WbLoss, CollectOrphan, the readers', MachineCrash, and Next's step of an ended system). As in
 * the other ports, a process's loop is one atomic: an if whose options are the actions, then
 * check() once; the choices MachineCrash makes are in cb and cm, 0 in every stored state, and the
 * temporaries are hidden. SPIN's states are the module's and one more, its first.
 */

#define NE (NP * NS)
#define BIT(x) (1 << (x))
#define HAS(s, x) (((s) >> (x)) & 1)

/* pc */
#define STEP 0
#define SETTLE_D 1
#define SETTLE_M 2
#define SETTLE_C 3
#define DIRSYNC 4
#define DONE 5
/* meta */
#define M_NONE 0
#define M_PENDING 1
#define M_DURABLE 2

byte pc[NP];
byte cur[NP];
bit vis[NE];
bit linked[NE];
byte meta[NE];
byte pboot[NE];
bit mcommit[NE];
bit ddata[NE];
bit broken[NE];
byte boot;
byte werrors;
bit poisoned[NE];
byte held[NR];
bit alive[NP];
byte rcrashes;
bit badHold;
byte evicted;
byte promised;

/* MachineCrash's choices (lost, kept) and the entry it is at; 0 in every stored state. */
byte cb, cm, cd;

#ifdef NOHIDDEN
#define HIDDEN
#else
#define HIDDEN hidden
#endif
HIDDEN byte ix, jx, dx, cn;
HIDDEN byte TypeOK, NoWrongValid, NoLostPublish, MarkedHasData;

#define ME (_pid - 1)
#define E (cur[ME] - 1)
/* Settling */
#define SETTLING (SYNCBEFORE -> SETTLE_D : SETTLE_M)
#define HELDBY(e) (HAS(held[0], e) || (NR > 1 && HAS(held[NR - 1], e)))
#define OWNED(e) ((alive[0] && cur[0] == (e) + 1) || (NP > 1 && alive[NP - 1] && cur[NP - 1] == (e) + 1))
#define OTHERLOOKUP(e) (vis[e] && !poisoned[e] && (meta[e] == M_DURABLE || \
                        (meta[e] == M_PENDING && !OWNERONLY && (!CHECKBOOT || pboot[e] == boot))))
#define USABLE(e) (vis[e] && !poisoned[e] && (meta[e] == M_DURABLE || \
                   (meta[e] == M_PENDING && (!CHECKBOOT || pboot[e] == boot))))
#define TERMINATED (pc[0] == DONE && (NP < 2 || pc[NP - 1] == DONE))

inline check() {
#ifdef CHK_TypeOK
	TypeOK = 1;
	for (ix : 0 .. NP - 1) { TypeOK = TypeOK && pc[ix] <= DONE }
	for (ix : 0 .. NE - 1) { TypeOK = TypeOK && meta[ix] <= M_DURABLE }
	assert(TypeOK);
#endif
#ifdef CHK_NoWrongValid
	NoWrongValid = !badHold;
	for (ix : 0 .. NE - 1) {
		NoWrongValid = NoWrongValid && (!OTHERLOOKUP(ix) || !broken[ix]) &&
			(!(USABLE(ix) && meta[ix] == M_DURABLE) || !broken[ix])
	}
	assert(NoWrongValid);
#endif
#ifdef CHK_NoLostPublish
	NoLostPublish = 1;
	for (ix : 0 .. NE - 1) {
		NoLostPublish = NoLostPublish && (!HAS(promised, ix) || HAS(evicted, ix) || poisoned[ix] || USABLE(ix))
	}
	assert(NoLostPublish);
#endif
#ifdef CHK_MarkedHasData
	MarkedHasData = 1;
	for (ix : 0 .. NE - 1) { MarkedHasData = MarkedHasData && (!(mcommit[ix] && meta[ix] == M_DURABLE) || ddata[ix]) }
	assert(MarkedHasData);
#endif
	cb = 0; cm = 0; cd = 0;
	ix = 0; jx = 0; dx = 0; cn = 0;
	TypeOK = 0; NoWrongValid = 0; NoLostPublish = 0; MarkedHasData = 0
}

/* ------------------------------------------------------------------------------------------- */

/* Runner ME: Proc(ME). */
proctype Runner() {
	do
	:: atomic {
	if
	/* Step: cn := Done(ME) */
	:: d_step { pc[ME] == STEP && alive[ME] ->
		cn = 0;
		for (ix : 0 .. NS - 1) { cn = cn + (meta[ME * NS + ix] != M_NONE) }
		if
		:: cn < NS && cur[ME] != 0 -> pc[ME] = SETTLING
		:: cn < NS && cur[ME] == 0 ->
			/* publishTimed: the entry renamed in, pending, naming this boot */
			dx = ME * NS + cn;
			vis[dx] = 1; meta[dx] = M_PENDING; pboot[dx] = boot; cur[ME] = dx + 1
		:: else -> pc[ME] = (cur[ME] != 0 && SETTLEEND -> SETTLING : DIRSYNC)
		fi }
	/* SettleD: the data synced */
	:: d_step { pc[ME] == SETTLE_D && alive[ME] && !broken[E] ->
		assert(cur[ME] != 0);
		ddata[E] = 1;
		if
		:: SYNCBEFORE -> pc[ME] = SETTLE_M
		:: else -> pc[ME] = STEP; cur[ME] = 0
		fi }
	/* SettleD: the sync fails */
	:: d_step { pc[ME] == SETTLE_D && alive[ME] && (broken[E] || werrors < MAXWERR) ->
		assert(cur[ME] != 0);
		dx = E;
		if
		:: !broken[dx] -> werrors++
		:: else
		fi;
		poisoned[dx] = POISON || poisoned[dx];
		vis[dx] = HELDBY(dx);
		if
		:: !HELDBY(dx) -> evicted = evicted | BIT(dx)
		:: else
		fi;
		cur[ME] = 0; pc[ME] = STEP }
	/* SettleM */
	:: d_step { pc[ME] == SETTLE_M && alive[ME] -> meta[E] = M_DURABLE; pc[ME] = SETTLE_C }
	/* SettleC */
	:: d_step { pc[ME] == SETTLE_C && alive[ME] ->
		mcommit[E] = 1;
		if
		:: SYNCBEFORE -> pc[ME] = STEP; cur[ME] = 0
		:: else -> pc[ME] = SETTLE_D
		fi }
	/* DirSync */
	:: d_step { pc[ME] == DIRSYNC && alive[ME] ->
		for (ix : 0 .. NE - 1) {
			if
			:: vis[ix] ->
				linked[ix] = 1;
				if
				:: ix / NS == ME -> promised = promised | BIT(ix)
				:: else
				fi
			:: else
			fi
		}
		pc[ME] = DONE }
	/* RunnerCrash */
	:: d_step { rcrashes < MAXRCRASH && alive[ME] && pc[ME] != DONE ->
		alive[ME] = 0; rcrashes++; pc[ME] = DONE }
	fi;
	d_step { check() } }
	od
}

/* WbLoss(e) and CollectOrphan(e) */
#define ENT(e) \
	:: d_step { NE > (e) && vis[e] && meta[e] == M_PENDING && !ddata[e] && !broken[e] -> broken[e] = 1 } \
	:: d_step { NE > (e) && vis[e] && !OWNED(e) && ((meta[e] == M_PENDING && OWNERONLY) || poisoned[e]) && \
	            !HELDBY(e) -> vis[e] = 0; evicted = evicted | BIT(e) }
/* ReaderOpen(r, e) and ReaderRelease(r, e) */
#define READ(r, e) \
	:: d_step { NR > (r) && NE > (e) && OTHERLOOKUP(e) -> \
		held[r] = held[r] | BIT(e); badHold = badHold || broken[e] } \
	:: d_step { NR > (r) && NE > (e) && HAS(held[r], e) -> held[r] = held[r] & ~BIT(e) }

proctype Env() {
end:
	do
	:: atomic {
	if
	ENT(0) ENT(1) ENT(2) ENT(3)
	READ(0, 0) READ(0, 1) READ(0, 2) READ(0, 3)
	READ(1, 0) READ(1, 1) READ(1, 2) READ(1, 3)
	/* MachineCrash: cb := lost, cm := kept, one entry at a time. */
	:: boot < MC ->
		do
		:: cd == NE -> break
		:: cd < NE && vis[cd] && !linked[cd] -> cb = cb | BIT(cd); cd++
		:: cd < NE -> cd++
		od;
		cd = 0;
		do
		:: cd == NE -> break
		:: cd < NE && meta[cd] == M_DURABLE && !mcommit[cd] -> cm = cm | BIT(cd); cd++
		:: cd < NE -> cd++
		od;
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			boot++;
			for (ix : 0 .. NE - 1) {
				vis[ix] = vis[ix] && !HAS(cb, ix);
				if
				:: meta[ix] == M_DURABLE && !mcommit[ix] && !HAS(cm, ix) -> meta[ix] = M_PENDING
				:: else
				fi;
				broken[ix] = (ddata[ix] -> broken[ix] : 1);
				mcommit[ix] = mcommit[ix] || meta[ix] == M_DURABLE
			}
			for (ix : 0 .. NP - 1) { pc[ix] = DONE; cur[ix] = 0; alive[ix] = 0 }
			for (ix : 0 .. NR - 1) { held[ix] = 0 }
			ix = 0 /* a d_step may not end in a loop, whose exit is a jump out of it */
		}
#ifdef LIVENESS
	/* The stutter (StoreLockingModel.pml says why). */
	:: badHold || !badHold -> skip
#else
	:: TERMINATED && boot == MC -> skip
#endif
	fi;
	d_step { check() } }
	od
}

init {
	atomic {
		assert(NP <= 2 && NR <= 2 && NE <= 4 && MC <= 1);
		d_step {
			for (ix : 0 .. NP - 1) { alive[ix] = 1 }
			check()
		};
		for (ix : 0 .. NP - 1) { run Runner() }
		run Env()
	}
}
