/*
 * proofs/tla/StoreLocking.tla in Promela, for SPIN (proofs/README.md, "The store's locking, in
 * SPIN"). The TLA+ module is the documented model and this is the same model, action for action:
 * a change to one is a change to the other. Each TLA+ action is one atomic step of SPIN's here,
 * under the action's name; what it stands for in the code is said in the module, not again here.
 *
 * A configuration (StoreLocking*.pml, written from the .cfg of the same name by cfg.py) defines
 * the constants and the invariants it checks, then includes this file:
 *   NP NS MAXCRASH MC MAXCORR MAXWERR      |Procs|, Steps, MaxCrashes, MachineCrashes,
 *                                          MaxCorrupts, MaxWriteErrors
 *   NSK NBK                                |StepKeys|, |BuildKeys|
 *   OLDENTRY BUILDHOLDS SYNCBEFORE HEEDSYNC SYNCLAYERS CHECKBOOT EVRECHECK LOOKUPFIRST
 *                                          the module's Boolean constants, 0 or 1, in its order
 *   CHK_<Invariant>                        one for each invariant the .cfg lists
 *
 * The module's values, encoded:
 *   Procs      0 .. NP-1; runner q is SPIN's process q+1. Keys are 0 .. NK-1, the step keys first,
 *              and OldKey is NK. CHOOSE k \in Keys : TRUE (Idle's and NoEntry's key) is key 0.
 *   Ids        a directory <<q, i, e>> is an index: q*NS + i-1 when e = 0, NP*NS + q*MC + e-1
 *              when e > 0, and OldId is the last, ND-1. NoDir is NODIR. A set of Ids is a bit
 *              mask. A descriptor Fd(q) = <<q, step, life>> is the directory's index, so sh[x] is
 *              a mask of indices too.
 *   ex[x], gc  sets of Procs: bit masks.
 *   kfd        <<k, g>> is (kfk, kfg) with g >= 1; NoFd is (0, 0).
 *   strings    pc, a directory's name, mode and evRet are the numbers #defined below.
 *   st, dirs   arrays of records with the module's fields, no others.
 *   CHOOSE     over Pub(k) (one member at most, OnePub) and over ktodo: the least index.
 *
 * Atomicity. An action is a `d_step` (one transition, run as straight C), or, where it chooses,
 * an `atomic` that chooses first and then does the rest in one `d_step`. A choice the module
 * makes with \/ or \E is an option of its own where it is small (LkFlock, Run, PbBack, PbSync,
 * StepEnd's key, Rt), and otherwise is made into the state variables cd, cm, cb and ck0 .. ck3 before
 * the d_step (GcNext and BcNext's directory, MachineCrash's lost renames, Corrupt's entry, Init's
 * keys). Those are 0 in every state SPIN stores: the d_step that ends a step sets them to 0
 * (check()). Every other temporary is `hidden`, outside the state, and is set and read within
 * one d_step. (SPIN does not restore a hidden variable when its search backs up inside an
 * `atomic`, so a choice must not be kept in one.) SPIN's states are then the module's states and
 * one more, SPIN's first, before init has run.
 */

#define NK (NSK + NBK)
#define OLDKEY NK
#define ND (NP * NS + NP * MC + 1)
#define OLDID (ND - 1)
#define NODIR 15
#define DIVMC (MC > 0 -> MC : 1)

/* An id's runner (NP for OldId), step and epoch; ID is the inverse. */
#define PROCOF(x) ((x) < NP * NS -> (x) / NS : ((x) < NP * NS + NP * MC -> ((x) - NP * NS) / DIVMC : NP))
#define STEPOF(x) ((x) < NP * NS -> (x) % NS + 1 : 1)
#define LIFEOF(x) ((x) < NP * NS -> 0 : ((x) < NP * NS + NP * MC -> ((x) - NP * NS) % DIVMC + 1 : 0))
#define ID(q, i, e) ((e) == 0 -> (q) * NS + (i) - 1 : NP * NS + (q) * MC + (e) - 1)
/* The ids whose runner is q: Others(q, s) is s & ~PMASK(q). */
#define PMASK(q) ((((1 << NS) - 1) << ((q) * NS)) | (((1 << MC) - 1) << (NP * NS + (q) * MC)))
#define BIT(x) (1 << (x))
#define HAS(s, x) (((s) >> (x)) & 1)

/* pc */
#define START 0
#define LK_CREATE 1
#define LK_FLOCK 2
#define LK_SAME 3
#define OP_FILE 4
#define OP_FLOCK 5
#define OP_SAME 6
#define OP_READ 7
#define RUN 8
#define PB_MKDIR 9
#define PB_WRITE 10
#define PB_LOCK 11
#define PB_MOVE 12
#define PB_BACK 13
#define PB_META 14
#define PB_SYNC 15
#define PB_RENAME 16
#define PB_FAIL 17
#define STEP_END 18
#define END 19
#define END_SYNC 20
#define GC_LOCK 21
#define GC_NEXT 22
#define GC_UNLOCK 23
#define DK_NEXT 24
#define DK_DEL 25
#define BOOT 26
#define BC_NEXT 27
#define EV_OPEN 28
#define EV_FLOCK 29
#define EV_SAME 30
#define EV_RENAME 31
#define EV_DONE 32
#define RT 33
#define DONE 34
#define CRASHED 35

/* a directory's name, and rtOrig ("none" is N_NONE) */
#define N_NONE 0
#define N_TMP 1
#define N_PUB 2
#define N_DEAD 3
/* Parts */
#define META 1
#define REC 2
#define LOCK 4
#define FS 8
#define PARTS 15
/* mode */
#define M_STEP 0
#define M_BUILD 1
#define M_LOOKUP 2
#define M_RETRY 3
/* evRet */
#define R_OPEN 0
#define R_GC 1
#define R_BC 2

typedef Locals {
	unsigned pc : 6;
	unsigned step : 2;
	unsigned key : 2;
	unsigned mode : 2;
	unsigned after : 6;
	unsigned kfk : 2;
	byte kfg;
	bit klk;
	bit owns;
	bit keyed;
	unsigned opd : 4; /* od */
	bit moved;
	byte held;
	unsigned evk : 2;
	unsigned evd : 4;
	unsigned evRet : 2;
	unsigned rtd : 4;
	unsigned rtOrig : 2;
	unsigned rtRet : 6;
	byte todo;
	unsigned ktodo : 2;
	bit lost;
	bit werr;
	unsigned life : 2;
	byte pubd
};

typedef Dir {
	unsigned name : 2;
	unsigned key : 2;
	unsigned parts : 4;
	bit fsOk;
	bit recOk;
	bit synced;
	bit linked;
	bit old
};

Locals st[NP];
Dir dirs[ND];
byte sh[ND];
byte ex[ND];
byte kino[NK];
byte kgen[NK];
byte gc;
bit booted;
byte crashes, mcrashes, corrupts, werrors;
bit badRead, lostUpper;
byte promised;

/* A choice made before a step's d_step; 0 in every stored state. */
byte cd, cm, cb;
byte ck0, ck1, ck2, ck3;

/* Temporaries within one d_step: hidden, outside the state, but for SPIN's multi-core search,
 * which has no hidden variables (spin -DNOHIDDEN); check() sets them to 0 at the end of every
 * step, so the states are the same either way. */
#ifdef NOHIDDEN
#define HIDDEN
#else
#define HIDDEN hidden
#endif
HIDDEN byte ix, jx, dx, ky, hm, cn, nv, gv, gone, back;
/* Each checked invariant's value in the state just reached, so that SPIN's report of a failed
 * assertion names the invariant. */
HIDDEN byte TypeOK, NoBadRead, HeldIntact, KeyMutex, NoWrongValid, NoLostUpper, OnePub, NoBuildLost,
	NoLostPublish, OldGoes;

#define ME (_pid - 1)
#define S st[ME]
#define MEID ID(ME, S.step, S.life)

/* x \in Pub(k) */
#define ISPUB(x, k) (dirs[x].name == N_PUB && dirs[x].key == (k))
/* KFree(<<k, g>>) */
#define HOLDS(q, k, g) (NP > (q) && st[q].klk && st[q].kfk == (k) && st[q].kfg == (g))
#define KFREE(k, g) (!HOLDS(0, k, g) && !HOLDS(1, k, g) && !HOLDS(2, k, g) && !HOLDS(3, k, g))
#define VALIDATES(x) (dirs[x].name == N_PUB && (dirs[x].parts & (META | REC | FS)) == (META | REC | FS) && \
                      dirs[x].recOk && !dirs[x].old)
#define LOOKSWHOLE(x) ((dirs[x].parts & (META | REC | FS)) == (META | REC | FS) && !dirs[x].old)
#define ASCOUNTED(x) ((dirs[x].parts & (META | FS)) == (META | FS) && dirs[x].fsOk && !dirs[x].old)
#define INTACT(x) (dirs[x].name == N_PUB && dirs[x].parts == PARTS && dirs[x].fsOk)
#define ENDED(q) (NP <= (q) || st[q].pc == DONE || st[q].pc == CRASHED)
#define TERMINATED (ENDED(0) && ENDED(1) && ENDED(2) && ENDED(3))
#define RANK(q, x) ((STEPOF(x) * (MC + 1) + LIFEOF(x)) * 2 + (PROCOF(x) != (q) -> 1 : 0))
#define CORRUPTIBLE(x) (ND > (x) && dirs[x].name == N_PUB && dirs[x].recOk)
/* Begin(i, ...) ends the job: i past the job's steps. */
#define PASTSTEPS(i, e) ((i) > ((e) == 0 -> NS : 1))

/* dx := the least id in Pub(k), or NODIR. */
inline lowestPub(k) {
	dx = NODIR;
	for (ix : 0 .. ND - 1) {
		if
		:: dx == NODIR && ISPUB(ix, k) -> dx = ix
		:: else
		fi
	}
}

/* cm := First(ME, cm): the ids in cm of the least Rank. */
inline first() {
	jx = 255;
	for (ix : 0 .. ND - 1) {
		if
		:: HAS(cm, ix) && RANK(ME, ix) < jx -> jx = RANK(ME, ix)
		:: else
		fi
	}
	for (ix : 0 .. ND - 1) {
		if
		:: HAS(cm, ix) && RANK(ME, ix) != jx -> cm = cm & ~BIT(ix)
		:: else
		fi
	}
}

/* cd := any member of the nonempty mask cm (\E d \in cm), in an atomic; never blocks. */
inline pick() {
	cd = 0;
	do
	:: HAS(cm, cd) -> break
	:: HAS(cm, cd) && (cm >> (cd + 1)) != 0 -> cd++
	:: !HAS(cm, cd) -> cd++
	od
}

/* st[q] := Idle */
inline idle(q) {
	st[q].pc = START; st[q].step = 1; st[q].key = 0; st[q].mode = M_STEP; st[q].after = OP_FILE;
	st[q].kfk = 0; st[q].kfg = 0; st[q].klk = 0; st[q].owns = 0; st[q].keyed = 0; st[q].opd = NODIR;
	st[q].moved = 0; st[q].held = 0; st[q].evk = 0; st[q].evd = NODIR; st[q].evRet = R_OPEN;
	st[q].rtd = NODIR; st[q].rtOrig = N_NONE; st[q].rtRet = START; st[q].todo = 0; st[q].ktodo = 0;
	st[q].lost = 0; st[q].werr = 0; st[q].life = 0; st[q].pubd = 0
}

/* st[q] := the member of Begin(nv, hm, cn, gv) with key k (the caller sets those four first, as
 * an inline's argument may not be a record's field). */
inline begin(q, k) {
	idle(q);
	st[q].step = nv; st[q].held = hm; st[q].life = cn; st[q].pubd = gv;
	if
	:: PASTSTEPS(nv, cn) -> st[q].pc = END
	:: else ->
		st[q].key = k;
		if
		:: (k) < NSK -> st[q].mode = M_STEP; st[q].pc = LK_CREATE
		:: else -> st[q].mode = M_BUILD; st[q].pc = OP_FILE
		fi;
		st[q].after = OP_FILE
	fi
}

/* S := Missed(S) */
inline missed() {
	if
	:: S.mode == M_STEP -> S.pc = RUN; S.keyed = 1
	:: S.mode == M_BUILD -> S.pc = RUN
	:: S.mode == M_LOOKUP -> S.pc = PB_MKDIR
	:: S.mode == M_RETRY -> S.pc = STEP_END; S.lost = 1
	fi
}

/* S := Invalid(S) */
inline invalid() {
	if
	:: S.mode == M_STEP -> S.pc = RUN; S.keyed = 0; S.klk = 0; S.kfk = 0; S.kfg = 0; S.owns = 0
	:: else -> S.pc = STEP_END
	fi
}

/* S := RemoveTree(S, x, ret); S := Evict(S, k, ret) */
inline removeTree(x, ret) { S.pc = RT; S.rtd = x; S.rtOrig = dirs[x].name; S.rtRet = ret }
inline evict(k, ret) { S.pc = EV_OPEN; S.evk = k; S.evRet = ret }

/* S := EvReturn(S, ok) */
inline evReturn(ok) {
	S.evd = NODIR;
	if
	:: S.evRet == R_GC -> S.pc = GC_NEXT
	:: S.evRet == R_BC -> S.pc = BC_NEXT
	:: S.evRet == R_OPEN && ok -> missed()
	:: S.evRet == R_OPEN && !ok -> invalid()
	fi
}

/* The invariants the configuration checks, in the state the step reached; then the choices are
 * set back to 0. Every step ends with it, inside its d_step. */
inline check() {
#ifdef CHK_TypeOK
	/* Names, parts, keys and the sets' members are in range by their encoding; the rest: */
	TypeOK = ((gc & (gc - 1)) == 0);
	for (ix : 0 .. ND - 1) {
		TypeOK = TypeOK && (ex[ix] & (ex[ix] - 1)) == 0 && (sh[ix] & ~((1 << (ND - 1)) - 1)) == 0
	}
	for (ix : 0 .. NK - 1) { TypeOK = TypeOK && kino[ix] <= kgen[ix] && kgen[ix] < 255 }
	assert(TypeOK);
#endif
#ifdef CHK_NoBadRead
	NoBadRead = !badRead;
	assert(NoBadRead);
#endif
#ifdef CHK_HeldIntact
	HeldIntact = 1;
	for (jx : 0 .. NP - 1) {
		for (ix : 0 .. ND - 1) { HeldIntact = HeldIntact && (!HAS(st[jx].held, ix) || INTACT(ix)) }
	}
	assert(HeldIntact);
#endif
#ifdef CHK_KeyMutex
	KeyMutex = 1;
	for (ix : 0 .. NSK - 1) {
		cn = 0;
		for (jx : 0 .. NP - 1) {
			if
			:: st[jx].owns && st[jx].key == ix -> cn++
			:: else
			fi
		}
		KeyMutex = KeyMutex && cn <= 1
	}
	assert(KeyMutex);
#endif
#ifdef CHK_NoWrongValid
	NoWrongValid = 1;
	for (ix : 0 .. ND - 1) {
		NoWrongValid = NoWrongValid && (!VALIDATES(ix) || (dirs[ix].fsOk && dirs[ix].parts == PARTS))
	}
	assert(NoWrongValid);
#endif
#ifdef CHK_NoLostUpper
	NoLostUpper = !lostUpper;
	assert(NoLostUpper);
#endif
#ifdef CHK_OnePub
	OnePub = 1;
	for (jx : 0 .. NK - 1) {
		cn = 0;
		for (ix : 0 .. ND - 1) {
			if
			:: ISPUB(ix, jx) -> cn++
			:: else
			fi
		}
		OnePub = OnePub && cn <= 1
	}
	assert(OnePub);
#endif
#ifdef CHK_NoBuildLost
	NoBuildLost = 1;
	for (jx : 0 .. NP - 1) { NoBuildLost = NoBuildLost && !st[jx].lost }
	assert(NoBuildLost);
#endif
#ifdef CHK_NoLostPublish
	NoLostPublish = 1;
	for (ix : 0 .. ND - 1) { NoLostPublish = NoLostPublish && (!HAS(promised, ix) || dirs[ix].name != N_TMP) }
	assert(NoLostPublish);
#endif
#ifdef CHK_OldGoes
	OldGoes = !(TERMINATED && crashes == 0) || dirs[OLDID].name == N_NONE;
	assert(OldGoes);
#endif
	cd = 0; cm = 0; cb = 0; ck0 = 0; ck1 = 0; ck2 = 0; ck3 = 0;
	ix = 0; jx = 0; dx = 0; ky = 0; hm = 0; cn = 0; nv = 0; gv = 0; gone = 0; back = 0;
	TypeOK = 0; NoBadRead = 0; HeldIntact = 0; KeyMutex = 0; NoWrongValid = 0; NoLostUpper = 0;
	OnePub = 0; NoBuildLost = 0; NoLostPublish = 0; OldGoes = 0
}

/* ------------------------------------------------------------------------------------------- */

/* Runner ME: Proc(ME) \/ Crash(ME), an option an action (or a branch of one). */
proctype Runner() {
	do
	/* The job's steps. */

	/* LkCreate */
	:: d_step { S.pc == LK_CREATE ->
		ky = S.key;
		if
		:: kino[ky] == 0 -> kgen[ky]++; kino[ky] = kgen[ky]; S.kfk = ky; S.kfg = kgen[ky]
		:: else -> S.kfk = ky; S.kfg = kino[ky]
		fi;
		S.pc = LK_FLOCK; check() }
	/* LkFlock */
	:: d_step { S.pc == LK_FLOCK && KFREE(S.kfk, S.kfg) -> S.klk = 1; S.pc = LK_SAME; check() }
	:: d_step { S.pc == LK_FLOCK && !KFREE(S.kfk, S.kfg) -> S.kfk = 0; S.kfg = 0; S.pc = LK_CREATE; check() }
	:: d_step { S.pc == LK_FLOCK && !KFREE(S.kfk, S.kfg) && S.mode == M_STEP ->
		S.kfk = 0; S.kfg = 0; S.pc = STEP_END; check() }
	/* LkSame */
	:: d_step { S.pc == LK_SAME ->
		ky = S.key;
		if
		:: kino[ky] != 0 && S.kfk == ky && S.kfg == kino[ky] -> S.owns = (S.mode == M_STEP); S.pc = S.after
		:: else -> S.klk = 0; S.kfk = 0; S.kfg = 0; S.pc = LK_CREATE
		fi;
		check() }
	/* OpFile */
	:: d_step { S.pc == OP_FILE ->
		ky = S.key; lowestPub(ky);
		if
		:: dx != NODIR && (dirs[dx].parts & LOCK) -> S.opd = dx; S.pc = OP_FLOCK
		:: else -> missed()
		fi;
		check() }
	/* OpFlock */
	:: d_step { S.pc == OP_FLOCK && ex[S.opd] == 0 ->
		sh[S.opd] = sh[S.opd] | BIT(MEID); S.pc = OP_SAME; check() }
	/* OpSame */
	:: d_step { S.pc == OP_SAME ->
		dx = S.opd;
		if
		:: ISPUB(dx, S.key) && (dirs[dx].parts & LOCK) -> S.pc = OP_READ
		:: else -> sh[dx] = sh[dx] & ~BIT(MEID); S.opd = NODIR; missed()
		fi;
		check() }
	/* OpRead */
	:: d_step { S.pc == OP_READ ->
		dx = S.opd;
		if
		:: VALIDATES(dx) ->
			badRead = badRead || !INTACT(dx); S.held = S.held | BIT(dx); S.opd = NODIR; S.pc = STEP_END
		:: else -> sh[dx] = sh[dx] & ~BIT(MEID); S.opd = NODIR; ky = S.key; evict(ky, R_OPEN)
		fi;
		check() }
	/* Run: ok = FALSE, then ok = TRUE by its cases. */
	:: d_step { S.pc == RUN -> S.pc = STEP_END; check() }
	:: d_step { S.pc == RUN && S.mode == M_BUILD && BUILDHOLDS && LOOKUPFIRST ->
		S.pc = LK_CREATE; S.after = OP_FILE; S.mode = M_LOOKUP; check() }
	:: d_step { S.pc == RUN && S.mode == M_BUILD && BUILDHOLDS && !LOOKUPFIRST ->
		S.pc = LK_CREATE; S.after = PB_MKDIR; check() }
	:: d_step { S.pc == RUN && ((S.mode == M_BUILD && !BUILDHOLDS) || (S.mode != M_BUILD && S.keyed)) ->
		S.pc = PB_MKDIR; check() }
	/* PbMkdir */
	:: d_step { S.pc == PB_MKDIR ->
		dx = MEID;
		dirs[dx].name = N_TMP; dirs[dx].key = S.key; dirs[dx].parts = 0; dirs[dx].fsOk = 1;
		dirs[dx].recOk = 1; dirs[dx].synced = 0; dirs[dx].linked = 0; dirs[dx].old = 0;
		S.moved = 0; S.pc = PB_WRITE; check() }
	/* PbWrite */
	:: d_step { S.pc == PB_WRITE ->
		dx = MEID;
		if
		:: dirs[dx].name == N_NONE -> S.pc = PB_FAIL
		:: else -> dirs[dx].parts = dirs[dx].parts | REC; S.pc = PB_LOCK
		fi;
		check() }
	/* PbLock: enabled when Gone, or when no one holds the lock exclusively. */
	:: d_step { S.pc == PB_LOCK && (dirs[MEID].name == N_NONE || ex[MEID] == 0) ->
		dx = MEID;
		if
		:: dirs[dx].name == N_NONE -> S.pc = PB_FAIL
		:: else -> dirs[dx].parts = dirs[dx].parts | LOCK; sh[dx] = sh[dx] | BIT(dx); S.pc = PB_MOVE
		fi;
		check() }
	/* PbMove */
	:: d_step { S.pc == PB_MOVE ->
		dx = MEID;
		if
		:: dirs[dx].name == N_NONE -> S.pc = PB_FAIL
		:: else -> dirs[dx].parts = dirs[dx].parts | FS; dirs[dx].fsOk = 1; S.moved = 1; S.pc = PB_BACK
		fi;
		check() }
	/* PbBack */
	:: d_step { S.pc == PB_BACK -> S.pc = PB_META; check() }
	:: d_step { S.pc == PB_BACK && werrors < MAXWERR ->
		werrors++; S.werr = 1; S.pc = (HEEDSYNC -> PB_FAIL : PB_META); check() }
	/* PbMeta */
	:: d_step { S.pc == PB_META ->
		dx = MEID;
		if
		:: dirs[dx].name == N_NONE -> S.pc = PB_FAIL
		:: else -> dirs[dx].parts = dirs[dx].parts | META; S.pc = PB_SYNC
		fi;
		check() }
	/* PbSync */
	:: d_step { S.pc == PB_SYNC ->
		dx = MEID;
		if
		:: SYNCBEFORE && dirs[dx].name != N_NONE -> dirs[dx].synced = 1
		:: else
		fi;
		S.pc = PB_RENAME; check() }
	:: d_step { S.pc == PB_SYNC && werrors < MAXWERR ->
		werrors++; S.werr = 1; S.pc = (HEEDSYNC -> PB_FAIL : PB_RENAME); check() }
	/* PbRename */
	:: d_step { S.pc == PB_RENAME ->
		ky = S.key; lowestPub(ky);
		if
		:: dirs[MEID].name == N_TMP && dx == NODIR ->
			dx = MEID;
			dirs[dx].name = N_PUB; S.held = S.held | BIT(dx); S.moved = 0; S.pc = STEP_END;
			if
			:: S.mode == M_STEP -> S.pubd = S.pubd | BIT(dx)
			:: else
			fi
		:: else -> S.pc = PB_FAIL
		fi;
		check() }
	/* PbFail */
	:: d_step { S.pc == PB_FAIL ->
		dx = MEID;
		nv = (S.mode == M_BUILD -> OP_FILE : STEP_END);
		back = !S.moved || (dirs[dx].parts & FS);
		gone = (dirs[dx].name == N_NONE);
		sh[dx] = sh[dx] & ~BIT(dx);
		lostUpper = lostUpper || (S.moved && !((dirs[dx].parts & FS) && dirs[dx].fsOk));
		if
		:: S.moved && (dirs[dx].parts & FS) -> dirs[dx].parts = dirs[dx].parts & ~FS
		:: else
		fi;
		S.lost = (S.mode == M_LOOKUP && !S.werr);
		S.moved = 0;
		if
		:: S.mode == M_BUILD -> S.mode = M_RETRY
		:: else
		fi;
		if
		:: back && !gone -> removeTree(dx, nv)
		:: else -> S.pc = nv
		fi;
		check() }
	/* StepEnd: Begin's member with key 0 (or the job's end), then with key 1. */
	:: d_step { S.pc == STEP_END ->
		nv = S.step + 1; hm = S.held; cn = S.life; gv = S.pubd; begin(ME, 0); check() }
	:: d_step { S.pc == STEP_END && NK > 1 && !PASTSTEPS(S.step + 1, S.life) ->
		nv = S.step + 1; hm = S.held; cn = S.life; gv = S.pubd; begin(ME, 1); check() }
	/* End */
	:: d_step { S.pc == END ->
		for (ix : 0 .. ND - 1) {
			if
			:: HAS(S.held, ix) -> sh[ix] = sh[ix] & ~PMASK(ME)
			:: else
			fi
		}
		S.held = 0; S.pc = END_SYNC; check() }
	/* EndSync */
	:: d_step { S.pc == END_SYNC ->
		if
		:: S.pubd != 0 && SYNCLAYERS ->
			for (ix : 0 .. ND - 1) {
				if
				:: dirs[ix].name == N_PUB -> dirs[ix].linked = 1
				:: else
				fi
			}
		:: else
		fi;
		for (ix : 0 .. ND - 1) {
			if
			:: HAS(S.pubd, ix) && dirs[ix].name == N_PUB -> promised = promised | BIT(ix)
			:: else
			fi
		}
		S.pubd = 0; S.pc = GC_LOCK; check() }

	/* Store.collect. */

	/* GcLock */
	:: d_step { S.pc == GC_LOCK ->
		if
		:: gc == 0 ->
			gc = BIT(ME); S.todo = 0;
			for (ix : 0 .. ND - 1) {
				if
				:: dirs[ix].name != N_NONE -> S.todo = S.todo | BIT(ix)
				:: else
				fi
			}
			S.pc = GC_NEXT
		:: else -> S.pc = DONE
		fi;
		check() }
	/* GcNext, the listing done */
	:: d_step { S.pc == GC_NEXT && S.todo == 0 ->
		S.ktodo = 0;
		for (ix : 0 .. NK - 1) {
			if
			:: kino[ix] != 0 -> S.ktodo = S.ktodo | BIT(ix)
			:: else
			fi
		}
		S.pc = DK_NEXT; check() }
	/* GcNext, an entry: cd \in First(ME, todo), and cb whether an entry that looks whole is
	 * evicted (past the cap). */
	:: atomic { S.pc == GC_NEXT && S.todo != 0 ->
		d_step { cm = S.todo; first() };
		pick();
		if
		:: cb = 0
		:: dirs[cd].name == N_PUB && LOOKSWHOLE(cd) -> cb = 1
		fi;
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			dx = cd;
			ky = dirs[dx].key;
			S.todo = S.todo & ~BIT(dx);
			if
			:: dirs[dx].name == N_NONE -> skip
			:: dirs[dx].name == N_DEAD -> removeTree(dx, GC_NEXT)
			:: dirs[dx].name == N_TMP ->
				if
				:: kino[ky] == 0 ->
					kgen[ky]++; kino[ky] = kgen[ky];
					S.kfk = ky; S.kfg = kgen[ky]; S.klk = 1; removeTree(dx, GC_UNLOCK)
				:: else ->
					gv = kino[ky];
					if
					:: KFREE(ky, gv) -> S.kfk = ky; S.kfg = gv; S.klk = 1; removeTree(dx, GC_UNLOCK)
					:: else
					fi
				fi
			:: dirs[dx].name == N_PUB ->
				if
				:: LOOKSWHOLE(dx) && !cb -> skip
				:: else -> evict(ky, R_GC)
				fi
			fi;
			check() } }
	/* GcUnlock */
	:: d_step { S.pc == GC_UNLOCK -> S.kfk = 0; S.kfg = 0; S.klk = 0; S.pc = GC_NEXT; check() }
	/* DkNext */
	:: d_step { S.pc == DK_NEXT ->
		if
		:: S.ktodo == 0 -> gc = 0; S.pc = DONE
		:: else ->
			ky = (HAS(S.ktodo, 0) -> 0 : 1);
			S.ktodo = S.ktodo & ~BIT(ky);
			if
			:: kino[ky] != 0 && KFREE(ky, kino[ky]) -> S.kfk = ky; S.kfg = kino[ky]; S.klk = 1; S.pc = DK_DEL
			:: else
			fi
		fi;
		check() }
	/* DkDel */
	:: d_step { S.pc == DK_DEL ->
		kino[S.kfk] = 0; S.kfk = 0; S.kfg = 0; S.klk = 0; S.pc = DK_NEXT; check() }

	/* Store.checkOncePerBoot. */

	/* Boot: goes on (Begin's member with key 0, then key 1), or waits for gc.lock. */
	:: d_step { S.pc == BOOT && (booted || !CHECKBOOT) ->
		nv = 1; hm = 0; cn = S.life; gv = 0; begin(ME, 0); check() }
	:: d_step { S.pc == BOOT && (booted || !CHECKBOOT) && NK > 1 ->
		nv = 1; hm = 0; cn = S.life; gv = 0; begin(ME, 1); check() }
	:: d_step { S.pc == BOOT && !(booted || !CHECKBOOT) && gc == 0 ->
		gc = BIT(ME); S.todo = 0;
		for (ix : 0 .. ND - 1) {
			if
			:: dirs[ix].name == N_PUB -> S.todo = S.todo | BIT(ix)
			:: else
			fi
		}
		S.pc = BC_NEXT; check() }
	/* BcNext, the check done (key 0, then key 1) */
	:: d_step { S.pc == BC_NEXT && S.todo == 0 ->
		booted = 1; gc = 0; nv = 1; hm = 0; cn = S.life; gv = 0; begin(ME, 0); check() }
	:: d_step { S.pc == BC_NEXT && S.todo == 0 && NK > 1 ->
		booted = 1; gc = 0; nv = 1; hm = 0; cn = S.life; gv = 0; begin(ME, 1); check() }
	/* BcNext, an entry: cd \in First(ME, todo) */
	:: atomic { S.pc == BC_NEXT && S.todo != 0 ->
		d_step { cm = S.todo; first() };
		pick();
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			dx = cd;
			S.todo = S.todo & ~BIT(dx);
			if
			:: dirs[dx].name == N_PUB && !ASCOUNTED(dx) -> ky = dirs[dx].key; evict(ky, R_BC)
			:: else
			fi;
			check() } }

	/* Store.evict. */

	/* EvOpen */
	:: d_step { S.pc == EV_OPEN ->
		ky = S.evk; lowestPub(ky);
		if
		:: dx == NODIR -> evReturn(0)
		:: else ->
			if
			:: dirs[dx].parts & LOCK -> S.evd = dx; S.pc = EV_FLOCK
			:: else -> S.evd = NODIR; S.pc = EV_RENAME
			fi
		fi;
		check() }
	/* EvFlock */
	:: d_step { S.pc == EV_FLOCK ->
		dx = S.evd;
		if
		:: sh[dx] == 0 && ex[dx] == 0 -> ex[dx] = BIT(ME); S.pc = (EVRECHECK -> EV_SAME : EV_RENAME)
		:: else -> evReturn(0)
		fi;
		check() }
	/* EvSame */
	:: d_step { S.pc == EV_SAME ->
		dx = S.evd;
		if
		:: ISPUB(dx, S.evk) && (dirs[dx].parts & LOCK) -> S.pc = EV_RENAME
		:: else -> ex[dx] = 0; evReturn(0)
		fi;
		check() }
	/* EvRename */
	:: d_step { S.pc == EV_RENAME ->
		ky = S.evk; lowestPub(ky);
		if
		:: dx != NODIR -> dirs[dx].name = N_DEAD; removeTree(dx, EV_DONE)
		:: else ->
			if
			:: S.evd != NODIR -> ex[S.evd] = 0
			:: else
			fi;
			evReturn(0)
		fi;
		check() }
	/* EvDone */
	:: d_step { S.pc == EV_DONE ->
		if
		:: S.evd != NODIR -> ex[S.evd] = 0
		:: else
		fi;
		evReturn(1); check() }
	/* Rt: \E x \in parts, an option a part ("fs" is emptied, then removed), and the end. */
	:: d_step { S.pc == RT && (dirs[S.rtd].parts & META) ->
		dirs[S.rtd].parts = dirs[S.rtd].parts & ~META; check() }
	:: d_step { S.pc == RT && (dirs[S.rtd].parts & REC) ->
		dirs[S.rtd].parts = dirs[S.rtd].parts & ~REC; check() }
	:: d_step { S.pc == RT && (dirs[S.rtd].parts & LOCK) ->
		dirs[S.rtd].parts = dirs[S.rtd].parts & ~LOCK; check() }
	:: d_step { S.pc == RT && (dirs[S.rtd].parts & FS) && dirs[S.rtd].fsOk ->
		dirs[S.rtd].fsOk = 0; check() }
	:: d_step { S.pc == RT && (dirs[S.rtd].parts & FS) && !dirs[S.rtd].fsOk ->
		dirs[S.rtd].parts = dirs[S.rtd].parts & ~FS; check() }
	:: d_step { S.pc == RT && dirs[S.rtd].parts == 0 ->
		dx = S.rtd;
		if
		:: dirs[dx].name == S.rtOrig ->
			dirs[dx].name = N_NONE; dirs[dx].key = 0; dirs[dx].parts = 0; dirs[dx].fsOk = 0;
			dirs[dx].recOk = 0; dirs[dx].synced = 0; dirs[dx].linked = 0; dirs[dx].old = 0
		:: else
		fi;
		S.rtd = NODIR; S.rtOrig = N_NONE; S.pc = S.rtRet; check() }

	/* What happens to the processes. */

	/* Crash(ME) */
	:: d_step { crashes < MAXCRASH && S.pc != DONE && S.pc != CRASHED ->
		crashes++;
		idle(ME); S.pc = CRASHED;
		for (ix : 0 .. ND - 1) { sh[ix] = sh[ix] & ~PMASK(ME); ex[ix] = ex[ix] & ~BIT(ME) }
		gc = gc & ~BIT(ME);
		check() }
	od
}

/* MachineCrash, Corrupt, and Next's step of a terminated system, which changes nothing. Env is
 * always at an end label and the runners never are, so a state with no step is an invalid end
 * state to SPIN exactly when it is a deadlock to TLC. */
proctype Env() {
end:
	do
	/* MachineCrash: cb := lost \in SUBSET cm, a directory at a time. */
	:: atomic { mcrashes < MC ->
		d_step {
			for (ix : 0 .. ND - 1) {
				if
				:: dirs[ix].name == N_PUB && !dirs[ix].linked -> cm = cm | BIT(ix)
				:: else
				fi
			}
		};
		do
		:: cm == 0 -> break
		:: cm != 0 && HAS(cm, cd) -> cb = cb | BIT(cd); cm = cm & ~BIT(cd); cd++
		:: cm != 0 && HAS(cm, cd) -> cm = cm & ~BIT(cd); cd++
		:: cm != 0 && !HAS(cm, cd) -> cd++
		od;
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			mcrashes++;
			for (jx : 0 .. NP - 1) { idle(jx); st[jx].pc = BOOT; st[jx].life = mcrashes }
			for (ix : 0 .. ND - 1) {
				sh[ix] = 0; ex[ix] = 0;
				if
				:: HAS(cb, ix) -> dirs[ix].name = N_TMP
				:: else
				fi;
				if
				:: dirs[ix].name != N_NONE && !dirs[ix].synced -> dirs[ix].fsOk = 0
				:: else
				fi
			}
			gc = 0;
			booted = 0;
			check() } }
	/* Corrupt */
	:: atomic { corrupts < MAXCORR &&
		(CORRUPTIBLE(0) || CORRUPTIBLE(1) || CORRUPTIBLE(2) || CORRUPTIBLE(3) ||
		 CORRUPTIBLE(4) || CORRUPTIBLE(5) || CORRUPTIBLE(6) || CORRUPTIBLE(7)) ->
		d_step {
			for (ix : 0 .. ND - 1) {
				if
				:: CORRUPTIBLE(ix) -> cm = cm | BIT(ix)
				:: else
				fi
			}
		};
		pick();
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step { dirs[cd].recOk = 0; corrupts++; check() } }
	:: atomic { TERMINATED -> skip }
	od
}

/* Init: SPIN's first state, then one step to each of the module's initial states (each runner's
 * first key chosen into ck0 .. ck3), and the processes are made: init is pid 0, runner q pid q+1, Env
 * pid NP+1. */
init {
	atomic {
		assert(NP <= 4 && ND <= 8 && NK <= 2 && NS <= 2 && MC <= 1);
		/* Unrolled: a hidden loop counter would not survive the search backing up into it. */
		select(ck0 : 0 .. NK - 1);
		if :: NP > 1 -> select(ck1 : 0 .. NK - 1) :: else fi;
		if :: NP > 2 -> select(ck2 : 0 .. NK - 1) :: else fi;
		if :: NP > 3 -> select(ck3 : 0 .. NK - 1) :: else fi;
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			for (ix : 0 .. ND - 1) {
				dirs[ix].name = N_NONE; dirs[ix].key = 0; dirs[ix].parts = 0; dirs[ix].fsOk = 0;
				dirs[ix].recOk = 0; dirs[ix].synced = 0; dirs[ix].linked = 0; dirs[ix].old = 0;
				sh[ix] = 0; ex[ix] = 0
			}
			if
			:: OLDENTRY ->
				dirs[OLDID].name = N_PUB; dirs[OLDID].key = OLDKEY; dirs[OLDID].parts = PARTS;
				dirs[OLDID].fsOk = 1; dirs[OLDID].recOk = 1; dirs[OLDID].synced = 1;
				dirs[OLDID].linked = 1; dirs[OLDID].old = 1
			:: else
			fi;
			booted = 1;
			nv = 1; hm = 0; cn = 0; gv = 0;
			begin(0, ck0);
			if :: NP > 1 -> begin(1, ck1) :: else fi;
			if :: NP > 2 -> begin(2, ck2) :: else fi;
			if :: NP > 3 -> begin(3, ck3) :: else fi;
			check()
		};
		for (ix : 0 .. NP - 1) { run Runner() }
		run Env()
	}
}
