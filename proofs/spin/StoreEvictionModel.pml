/*
 * proofs/tla/StoreEviction.tla in Promela, for SPIN (proofs/README.md, "Eviction beside the
 * layers"). The TLA+ module is the documented model, no longer machine-checked, and this is the
 * same model, action for action, in the way StoreLockingModel.pml is StoreLocking.tla's (its header
 * says how a module becomes Promela with the same states): a change to one is a change to the
 * other.
 *
 * A configuration (StoreEviction*.pml, written from the .cfg of the same name by cfg.py) defines
 * the constants, the invariants and the temporal properties it checks, then includes this file:
 *   NP ROUNDS MAXCRASH MC MAXPLANT MAXSTUCK  |Procs|, Rounds, MaxCrashes, MachineCrashes,
 *                                            MaxPlants, MaxStuck
 *   NK VOLS OUTER INNER                      |Keys|, the volumes' mask, Outer's and Inner's key
 *                                            (NK for NoKey)
 *   OPENRECHECK DOWNRECHECK EVLOCKS EVRECHECK INNERLOCK RENAMEFIRST SYNCRENAME SYNCFS CLEARPLANT
 *   STUCKGOES                                the module's Boolean constants, 0 or 1, in its order
 *   CHK_<Invariant>, LTL_<Property>          one for each the .cfg lists
 * and spin.sh defines LIVENESS when it checks the properties (spin -DLIVENESS).
 *
 * The module's values, encoded:
 *   Procs      0 .. NP-1; runner q is SPIN's process q+1, Env NP+1.
 *   Keys       0 .. NK-1 in TLC's order of the model values (cfg.py: by name, t1 before v1,
 *              v1 before v2), so CHOOSE over keys is the least, as TLC's.
 *   fd, fd2    <<k, g>> is (fdk, fdg) with g >= 1; NoFd is (0, 0).
 *   locks      lk[q*NK + k] is the generation of key k's lock file process q holds a flock on (0
 *              for none), lkx[q*NK + k] whether it is exclusive. A process holds at most one
 *              flock on a key's files at a time (each Add follows a Drop or a fresh descriptor;
 *              add() asserts it), so this is the set exactly.
 *   dead       by tree id: dp[i] whether a record with id i is there, and its key, synced, src
 *              and stuck. Ids are unique, as a tree is renamed to a dead name once; add asserts
 *              it. A record not there has every field 0.
 *   half, tmp, gc  bit masks over ids, keys and processes.
 *   CHOOSE     over records (GcDead's tree, MachineCrash's tree for a key): TLC's least, which
 *              orders a record by its fields in the order the module first names them (key,
 *              stuck, synced, src, id), FALSE before TRUE (rank()).
 *
 * The rest is StoreLockingModel.pml's: each action one step, choices made into cd, cm, cb and
 * ck0 .. ck2 before its d_step, temporaries hidden, check() at the end of every step (once a
 * process, after its actions' `if`), Crash Env's.
 */

#define NID 16
#define BIT(x) (1 << (x))
#define HAS(s, x) (((s) >> (x)) & 1)
#define ISVOL(k) HAS(VOLS, k)

/* pc */
#define OPEN 0
#define FLOCK_SH 1
#define SAME 2
#define LOOK 3
#define FLOCK_EX 4
#define SAME_EX 5
#define MAKE 6
#define DOWN 7
#define FLOCK_SH2 8
#define ASSUME 9
#define USE 10
#define GC_LOCK 11
#define GC_DEAD 12
#define GC_END 13
#define GC_NEXT 14
#define EV_OPEN 15
#define EV_FLOCK 16
#define EV_SAME 17
#define EV_INNER 18
#define EV_RENAME 19
#define EV_SYNC 20
#define EV_UNLINK 21
#define DONE 22
#define CRASHED 23

typedef Locals {
	unsigned pc : 5;
	unsigned round : 2;
	unsigned key : 2;
	unsigned fdk : 2;
	byte fdg;
	unsigned fd2k : 2;
	byte fd2g;
	byte held;
	unsigned todo : 3;
	unsigned evk : 2
};

Locals st[NP];
byte lockIno[NK];
byte lockGen[NK];
byte lk[NP * NK];
bit lkx[NP * NK];
byte dirOf[NK];
byte nextId;
int half;
byte tmp;
bit dp[NID];
byte dkey[NID];
bit dsynced[NID];
bit dsrc[NID];
bit dstuck[NID];
byte gc;
bit planted;
byte crashes, mcrashes, plants, stucks;
bit pinned, stopped;

/* A choice made before a step's d_step; 0 in every stored state. */
byte cd, cm, cb;
byte ck0, ck1, ck2;

#ifdef NOHIDDEN
#define HIDDEN
#else
#define HIDDEN hidden
#endif
HIDDEN byte ix, jx, dx, ky, gv, cn;
HIDDEN int bestRank;
HIDDEN byte TypeOK, HeldWhole, NamedWhole, OneMaker, NotPinned, PassGoesOn, LocksExclude;

#define ME (_pid - 1)
#define S st[ME]
#define LK(q, k) lk[(q) * NK + (k)]
#define LKX(q, k) lkx[(q) * NK + (k)]
/* q holds a flock on <<k, g>> */
#define HOLDS(q, k, g) (NP > (q) && (g) != 0 && LK(q, k) == (g))
#define HOLDSEX(q, k, g) (HOLDS(q, k, g) && LKX(q, k))
/* Holders(<<k, g>>) = {}, and none of them exclusive */
#define FREE(k, g) (!HOLDS(0, k, g) && !HOLDS(1, k, g) && !HOLDS(2, k, g))
#define NOEX(k, g) (!HOLDSEX(0, k, g) && !HOLDSEX(1, k, g) && !HOLDSEX(2, k, g))
#define ENDED(q) (NP <= (q) || st[q].pc == DONE || st[q].pc == CRASHED)
#define TERMINATED (ENDED(0) && ENDED(1) && ENDED(2))
/* Begin(i) ends the job: i past the rounds. */
#define PAST(i) ((i) > ROUNDS)
/* A dead record's place in TLC's order of records: key, stuck, synced, src, id. */
#define LIVE(i) (dp[i] && !dstuck[i])
#define ANYLIVE (LIVE(1) || LIVE(2) || LIVE(3) || LIVE(4) || LIVE(5) || LIVE(6) || LIVE(7) || LIVE(8) || \
                 LIVE(9) || LIVE(10) || LIVE(11) || LIVE(12) || LIVE(13) || LIVE(14) || LIVE(15))
#define RANK(i) ((((dkey[i] * 2 + dstuck[i]) * 2 + dsynced[i]) * 2 + dsrc[i]) * NID + (i))

/* Add(<<k, g>>, q, m) */
inline add(q, k, g, m) {
	assert(LK(q, k) == 0);
	LK(q, k) = g; LKX(q, k) = m
}
/* Drop(<<k, g>>, q): q's flock on that inode let go */
inline drop(q, k, g) {
	if
	:: LK(q, k) == (g) -> LK(q, k) = 0; LKX(q, k) = 0
	:: else
	fi
}
/* locks \ Mine(q) */
inline dropMine(q) {
	for (ix : 0 .. NK - 1) { LK(q, ix) = 0; LKX(q, ix) = 0 }
}

/* st[q] := Idle */
inline idle(q) {
	st[q].pc = OPEN; st[q].round = 1; st[q].key = 0; st[q].fdk = 0; st[q].fdg = 0; st[q].fd2k = 0;
	st[q].fd2g = 0; st[q].held = 0; st[q].todo = 0; st[q].evk = 0
}

/* st[q] := the member of Begin(i) with key k */
inline begin(q, i, k) {
	idle(q);
	if
	:: PAST(i) -> st[q].pc = DONE
	:: else -> st[q].round = i; st[q].key = k
	fi
}

/* Fresh(k) */
inline fresh(k) { lockGen[k]++; lockIno[k] = lockGen[k] }

/* EvFail(p) */
inline evFail() { S.fdk = 0; S.fdg = 0; S.fd2k = 0; S.fd2g = 0; S.pc = GC_NEXT }

/* The record with id i put in dead. */
inline addDead(i, k) {
	assert(i > 0 && i < NID && !dp[i]);
	dp[i] = 1; dkey[i] = k; dsynced[i] = 0; dsrc[i] = 0; dstuck[i] = 0
}
inline delDead(i) { dp[i] = 0; dkey[i] = 0; dsynced[i] = 0; dsrc[i] = 0; dstuck[i] = 0 }

/* dx := CHOOSE d \in {d \in dead : ~d.stuck} : TRUE, the least; NID for none. */
inline leastLive() {
	dx = NID; bestRank = 2147483647;
	for (ix : 1 .. NID - 1) {
		if
		:: dp[ix] && !dstuck[ix] && RANK(ix) < bestRank -> dx = ix; bestRank = RANK(ix)
		:: else
		fi
	}
}

inline check() {
#ifdef CHK_TypeOK
	TypeOK = ((gc & (gc - 1)) == 0);
	for (ix : 0 .. NK - 1) { TypeOK = TypeOK && lockIno[ix] <= lockGen[ix] && lockGen[ix] < 255 }
	assert(TypeOK);
#endif
#ifdef CHK_HeldWhole
	HeldWhole = 1;
	for (jx : 0 .. NP - 1) {
		if
		:: st[jx].held != 0 ->
			cn = 0;
			for (ix : 0 .. NK - 1) { cn = cn || dirOf[ix] == st[jx].held }
			HeldWhole = HeldWhole && cn && !HAS(half, st[jx].held)
		:: else
		fi
	}
	assert(HeldWhole);
#endif
#ifdef CHK_NamedWhole
	NamedWhole = 1;
	for (ix : 0 .. NK - 1) { NamedWhole = NamedWhole && !HAS(half, dirOf[ix]) }
	assert(NamedWhole);
#endif
#ifdef CHK_OneMaker
	OneMaker = 1;
	for (jx : 0 .. NP - 1) {
		for (ix : 0 .. NP - 1) {
			OneMaker = OneMaker && !(ix != jx && st[jx].pc == MAKE && st[ix].pc == MAKE &&
			                         st[jx].key == st[ix].key)
		}
	}
	assert(OneMaker);
#endif
#ifdef CHK_NotPinned
	NotPinned = !pinned;
	assert(NotPinned);
#endif
#ifdef CHK_PassGoesOn
	PassGoesOn = !stopped;
	assert(PassGoesOn);
#endif
#ifdef CHK_LocksExclude
	/* Two flocks on one inode are both shared: per process at most one on a key's files, so two
	 * processes on the same generation. */
	LocksExclude = 1;
	for (ky : 0 .. NK - 1) {
		for (jx : 0 .. NP - 1) {
			for (ix : 0 .. NP - 1) {
				LocksExclude = LocksExclude &&
					!(ix != jx && LK(jx, ky) != 0 && LK(jx, ky) == LK(ix, ky) && (LKX(jx, ky) || LKX(ix, ky)))
			}
		}
	}
	assert(LocksExclude);
#endif
	/* Not the module's: the ids fit the arrays. */
	assert(nextId < NID);
	cd = 0; cm = 0; cb = 0; ck0 = 0; ck1 = 0; ck2 = 0;
	ix = 0; jx = 0; dx = 0; ky = 0; gv = 0; cn = 0; bestRank = 0;
	TypeOK = 0; HeldWhole = 0; NamedWhole = 0; OneMaker = 0; NotPinned = 0; PassGoesOn = 0;
	LocksExclude = 0
}

/* ------------------------------------------------------------------------------------------- */

proctype Runner() {
	do
	:: atomic {
	if
	/* A job. */

	/* Open */
	:: d_step { S.pc == OPEN ->
		ky = S.key;
		if
		:: lockIno[ky] == 0 -> fresh(ky)
		:: else
		fi;
		S.fdk = ky; S.fdg = lockIno[ky]; S.pc = FLOCK_SH;
		if
		:: ky == INNER -> planted = 0
		:: else
		fi }
	/* FlockSh */
	:: d_step { S.pc == FLOCK_SH && NOEX(S.fdk, S.fdg) ->
		add(ME, S.fdk, S.fdg, 0); S.pc = SAME }
	/* Same */
	:: d_step { S.pc == SAME ->
		if
		:: OPENRECHECK && lockIno[S.key] != S.fdg ->
			drop(ME, S.fdk, S.fdg); S.fdk = 0; S.fdg = 0; S.pc = OPEN
		:: else -> S.pc = LOOK
		fi }
	/* Look */
	:: d_step { S.pc == LOOK ->
		ky = S.key;
		if
		:: dirOf[ky] != 0 -> S.held = dirOf[ky]; S.pc = USE
		:: dirOf[ky] == 0 && ISVOL(ky) ->
			nextId++; dirOf[ky] = nextId; S.held = nextId; S.pc = USE
		:: else -> drop(ME, S.fdk, S.fdg); S.pc = FLOCK_EX
		fi }
	/* FlockEx */
	:: d_step { S.pc == FLOCK_EX && FREE(S.fdk, S.fdg) ->
		add(ME, S.fdk, S.fdg, 1); S.pc = SAME_EX }
	/* SameEx */
	:: d_step { S.pc == SAME_EX ->
		ky = S.key;
		if
		:: OPENRECHECK && lockIno[ky] != S.fdg ->
			drop(ME, S.fdk, S.fdg); S.fdk = 0; S.fdg = 0; S.pc = OPEN
		:: else ->
			if
			:: dirOf[ky] != 0 -> S.pc = DOWN
			:: else -> tmp = tmp | BIT(ky); S.pc = MAKE
			fi
		fi }
	/* Make */
	:: d_step { S.pc == MAKE ->
		ky = S.key; nextId++; dirOf[ky] = nextId; tmp = tmp & ~BIT(ky); S.pc = DOWN }
	/* Down */
	:: d_step { S.pc == DOWN -> drop(ME, S.fdk, S.fdg); S.pc = FLOCK_SH2 }
	/* FlockSh2 */
	:: d_step { S.pc == FLOCK_SH2 && NOEX(S.fdk, S.fdg) ->
		add(ME, S.fdk, S.fdg, 0); S.pc = (DOWNRECHECK -> SAME : ASSUME) }
	/* Assume */
	:: d_step { S.pc == ASSUME ->
		ky = S.key;
		S.held = (dirOf[ky] != 0 -> dirOf[ky] : nextId); S.pc = USE }
	/* Plant */
	:: d_step { S.pc == USE && S.key == OUTER && plants < MAXPLANT && FREE(INNER, lockIno[INNER]) ->
		plants++; planted = 1; lockIno[INNER] = 0 }
	/* Use */
	:: d_step { S.pc == USE ->
		drop(ME, S.fdk, S.fdg); S.fdk = 0; S.fdg = 0; S.held = 0; S.pc = GC_LOCK }

	/* evict.run. Next1's choice of the next job's key: key 0 (or the end), then key 1. */

	/* GcLock */
	:: d_step { S.pc == GC_LOCK && gc == 0 ->
		gc = BIT(ME); S.todo = (1 << NK) - 1; S.pc = GC_DEAD }
	:: d_step { S.pc == GC_LOCK && gc != 0 -> gv = S.round + 1; begin(ME, gv, 0) }
	:: d_step { S.pc == GC_LOCK && gc != 0 && NK > 1 && !PAST(S.round + 1) ->
		gv = S.round + 1; begin(ME, gv, 1) }
	/* GcDead: no live tree */
	:: d_step { S.pc == GC_DEAD && !ANYLIVE ->
		cn = 0;
		for (ix : 1 .. NID - 1) { cn = cn || dp[ix] }
		if
		:: cn && !STUCKGOES -> stopped = 1; S.pc = GC_END
		:: else -> S.pc = GC_NEXT
		fi }
	/* GcDead: a live tree. The sync first, when one is owed; else the least live tree, three ways. */
	:: atomic { S.pc == GC_DEAD && ANYLIVE ->
		d_step {
			cn = 0;
			for (ix : 1 .. NID - 1) { cn = cn || (dp[ix] && (!dsynced[ix] || (SYNCFS && !dsrc[ix]))) }
			cb = (SYNCRENAME && cn -> 3 : 0)
		};
		if
		:: cb == 3
		:: cb == 0 -> cb = 0
		:: cb == 0 && stucks < MAXSTUCK -> cb = 1
		:: cb == 0 -> cb = 2
		fi;
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			if
			:: cb == 3 ->
				for (ix : 1 .. NID - 1) {
					if
					:: dp[ix] -> dsynced[ix] = 1; dsrc[ix] = SYNCFS || !ISVOL(dkey[ix]) || dsrc[ix]
					:: else
					fi
				}
			:: else ->
				leastLive();
				if
				:: cb == 0 && HAS(half, dx) -> delDead(dx)
				:: cb == 0 && !HAS(half, dx) -> half = half | BIT(dx)
				:: cb == 1 -> stucks++; dstuck[dx] = 1
				:: cb == 2 -> S.pc = GC_NEXT
				fi
			fi } }
	/* GcEnd */
	:: d_step { S.pc == GC_END -> gc = 0; gv = S.round + 1; begin(ME, gv, 0) }
	:: d_step { S.pc == GC_END && NK > 1 && !PAST(S.round + 1) ->
		gc = 0; gv = S.round + 1; begin(ME, gv, 1) }
	/* GcNext, the keys done */
	:: d_step { S.pc == GC_NEXT && S.todo == 0 -> gc = 0; gv = S.round + 1; begin(ME, gv, 0) }
	:: d_step { S.pc == GC_NEXT && S.todo == 0 && NK > 1 && !PAST(S.round + 1) ->
		gc = 0; gv = S.round + 1; begin(ME, gv, 1) }
	/* GcNext, the least key left: passed over, or evicted when there is something there. */
	:: d_step { S.pc == GC_NEXT && S.todo != 0 ->
		ky = (HAS(S.todo, 0) -> 0 : (HAS(S.todo, 1) -> 1 : 2));
		S.todo = S.todo & ~BIT(ky) }
	:: d_step { S.pc == GC_NEXT && S.todo != 0 &&
	            !((lockIno[(HAS(S.todo, 0) -> 0 : (HAS(S.todo, 1) -> 1 : 2))] == 0 &&
	               dirOf[(HAS(S.todo, 0) -> 0 : (HAS(S.todo, 1) -> 1 : 2))] == 0) ||
	              ((HAS(S.todo, 0) -> 0 : (HAS(S.todo, 1) -> 1 : 2)) == INNER && dirOf[OUTER] != 0)) ->
		ky = (HAS(S.todo, 0) -> 0 : (HAS(S.todo, 1) -> 1 : 2));
		S.todo = S.todo & ~BIT(ky); S.evk = ky; S.pc = EV_OPEN }
	/* EvOpen */
	:: d_step { S.pc == EV_OPEN ->
		ky = S.evk;
		if
		:: lockIno[ky] == 0 -> S.pc = GC_NEXT
		:: else -> S.fdk = ky; S.fdg = lockIno[ky]; S.pc = (EVLOCKS -> EV_FLOCK : EV_INNER)
		fi }
	/* EvFlock */
	:: d_step { S.pc == EV_FLOCK ->
		if
		:: FREE(S.fdk, S.fdg) -> add(ME, S.fdk, S.fdg, 1); S.pc = EV_SAME
		:: else -> evFail()
		fi }
	/* EvSame */
	:: d_step { S.pc == EV_SAME ->
		if
		:: EVRECHECK && lockIno[S.evk] != S.fdg -> drop(ME, S.fdk, S.fdg); evFail()
		:: else -> S.pc = EV_INNER
		fi }
	/* EvInner */
	:: d_step { S.pc == EV_INNER ->
		ky = S.evk;
		tmp = tmp & ~BIT(ky);
		if
		:: ky == OUTER && planted && !CLEARPLANT -> pinned = 1; dropMine(ME); evFail()
		:: ky == OUTER && !(planted && !CLEARPLANT) && INNERLOCK ->
			planted = 0;
			if
			:: lockIno[INNER] == 0 ->
				fresh(INNER); add(ME, INNER, lockIno[INNER], 1);
				S.fd2k = INNER; S.fd2g = lockIno[INNER]; S.pc = EV_RENAME
			:: lockIno[INNER] != 0 && FREE(INNER, lockIno[INNER]) ->
				add(ME, INNER, lockIno[INNER], 1);
				S.fd2k = INNER; S.fd2g = lockIno[INNER]; S.pc = EV_RENAME
			:: else -> dropMine(ME); evFail()
			fi
		:: else -> S.pc = EV_RENAME
		fi }
	/* EvRename */
	:: d_step { S.pc == EV_RENAME ->
		ky = S.evk; dx = dirOf[ky];
		if
		:: dx == 0 -> S.pc = EV_UNLINK
		:: dx != 0 && !RENAMEFIRST && !HAS(half, dx) -> half = half | BIT(dx)
		:: else ->
			gv = (ky == OUTER -> dirOf[INNER] : 0);
			dirOf[ky] = 0;
			if
			:: ky == OUTER -> dirOf[INNER] = 0; lockIno[INNER] = 0
			:: else
			fi;
			addDead(dx, ky);
			if
			:: gv != 0 -> addDead(gv, ky)
			:: else
			fi;
			S.pc = EV_SYNC
		fi }
	/* EvSync */
	:: d_step { S.pc == EV_SYNC ->
		if
		:: SYNCRENAME ->
			for (ix : 1 .. NID - 1) {
				if
				:: dp[ix] -> dsynced[ix] = 1; dsrc[ix] = 1
				:: else
				fi
			}
		:: else
		fi;
		S.pc = EV_UNLINK }
	/* EvUnlink */
	:: d_step { S.pc == EV_UNLINK ->
		ky = S.evk;
		if
		:: lockIno[ky] == S.fdg -> lockIno[ky] = 0
		:: else
		fi;
		dropMine(ME); S.fdk = 0; S.fdg = 0; S.fd2k = 0; S.fd2g = 0; S.pc = GC_NEXT }
	fi;
	d_step { check() } }
	od
}

/* Crash(q), Env's (StoreLockingModel.pml says why). */
inline crash(q) {
	d_step { NP > (q) && crashes < MAXCRASH && st[q].pc != DONE && st[q].pc != CRASHED ->
		crashes++;
		idle(q); st[q].pc = CRASHED;
		dropMine(q);
		gc = gc & ~BIT(q) }
}

/* Crash, MachineCrash and Next's step of a terminated system; as StoreLockingModel.pml's Env. */
proctype Env() {
end:
	do
	:: atomic {
	if
	:: crash(0)
	:: crash(1)
	:: crash(2)
	/* MachineCrash: cb := back \in SUBSET cm, a dead tree at a time, then each runner's key. */
	:: atomic { mcrashes < MC ->
		d_step {
			cm = 0;
			for (ix : 1 .. NID - 1) {
				if
				:: dp[ix] && !dsrc[ix] && dirOf[dkey[ix]] == 0 -> cm = cm | BIT(ix)
				:: else
				fi
			}
			cd = 1
		};
		do
		:: cm == 0 -> break
		:: cm != 0 && HAS(cm, cd) -> cb = cb | BIT(cd); cm = cm & ~BIT(cd); cd++
		:: cm != 0 && HAS(cm, cd) -> cm = cm & ~BIT(cd); cd++
		:: cm != 0 && !HAS(cm, cd) -> cd++
		od;
		select(ck0 : 0 .. NK - 1);
		if :: NP > 1 -> select(ck1 : 0 .. NK - 1) :: else fi;
		if :: NP > 2 -> select(ck2 : 0 .. NK - 1) :: else fi;
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			mcrashes++;
			/* dirOf[k]: the least of back with key k, if any */
			for (ky : 0 .. NK - 1) {
				dx = NID; bestRank = 2147483647;
				for (ix : 1 .. NID - 1) {
					if
					:: HAS(cb, ix) && dkey[ix] == ky && RANK(ix) < bestRank -> dx = ix; bestRank = RANK(ix)
					:: else
					fi
				}
				if
				:: dx != NID -> dirOf[ky] = dx
				:: else
				fi
			}
			for (ix : 1 .. NID - 1) {
				if
				:: HAS(cb, ix) -> delDead(ix)
				:: else
				fi
			}
			for (ix : 0 .. NP * NK - 1) { lk[ix] = 0; lkx[ix] = 0 }
			gc = 0;
			begin(0, ROUNDS, ck0);
			if :: NP > 1 -> begin(1, ROUNDS, ck1) :: else fi;
			if :: NP > 2 -> begin(2, ROUNDS, ck2) :: else fi } }
#ifdef LIVENESS
	/* The stutter (StoreLockingModel.pml says why). */
	:: planted || !planted -> skip
#else
	:: atomic { TERMINATED -> skip }
#endif
	fi;
	d_step { check() } }
	od
}

#ifdef LTL_AllEnd
ltl AllEnd { <> TERMINATED }
#endif

init {
	atomic {
		assert(NP <= 3 && NK <= 3 && ROUNDS <= 3 && MC <= 1);
		select(ck0 : 0 .. NK - 1);
		if :: NP > 1 -> select(ck1 : 0 .. NK - 1) :: else fi;
		if :: NP > 2 -> select(ck2 : 0 .. NK - 1) :: else fi;
		skip; /* an if, a do or pick() may not end in a d_step */
		d_step {
			begin(0, 1, ck0);
			if :: NP > 1 -> begin(1, 1, ck1) :: else fi;
			if :: NP > 2 -> begin(2, 1, ck2) :: else fi;
			check()
		};
		for (ix : 0 .. NP - 1) { run Runner() }
		run Env()
	}
}
