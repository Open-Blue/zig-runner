/* A mutant SPIN must fail: NoWrongValid. layers.zig's publish as it was before the fix, without the
 * key's lock: another runner's collect, finding the lock free, removes the build's .tmp- entry while
 * it is renamed into place, so an entry validates whose tree is half deleted.
 * Written from proofs/tla/StoreLocking-unlocked-build.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NSK 0
#define NBK 1
#define NS 1
#define MAXCRASH 0
#define MC 0
#define MAXCORR 0
#define MAXWERR 0
#define OLDENTRY 0
#define BUILDHOLDS 0
#define SYNCBEFORE 1
#define HEEDSYNC 1
#define SYNCLAYERS 1
#define CHECKBOOT 1
#define EVRECHECK 1
#define LOOKUPFIRST 1
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreLockingModel.pml"
