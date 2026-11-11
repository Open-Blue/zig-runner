/* must fail: AllEnd. Store.evict without its deferred close: the exclusive lock stays on the
 * evicted entry's lock file, and an open that opened that file before the rename waits on its
 * LOCK_SH for ever. The canary of the liveness checks' fairness: a fairness that forced the
 * crashes (SPIN's per process, with Crash a runner's) would crash the waiter, and the job would end.
 * StoreLocking-liveness.cfg's bounds.
 * Written from proofs/tla/StoreLocking-evict-keeps-lock.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-ltl: AllEnd */
#define NP 2
#define NSK 1
#define NBK 1
#define NS 1
#define MAXCRASH 1
#define MC 0
#define MAXCORR 1
#define MAXWERR 0
#define OLDENTRY 0
#define BUILDHOLDS 1
#define SYNCBEFORE 1
#define HEEDSYNC 1
#define SYNCLAYERS 1
#define CHECKBOOT 1
#define EVRECHECK 1
#define LOOKUPFIRST 1
#define EVUNLOCK 0
#define LTL_AllEnd
#include "StoreLockingModel.pml"
