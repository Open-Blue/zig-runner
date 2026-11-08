/* A mutant TLC must fail: HeldIntact. Store.evict as it was before the fix, without sameFile after
 * its LOCK_EX: collect opens an entry's lock file to evict it, a reader finding the entry broken
 * evicts it first, a builder publishes the key again and holds it, and collect's flock on the old,
 * unlinked lock file succeeds and its rename by name takes the new entry from under the builder.
 * Written from proofs/tla/StoreLocking-unchecked-evict.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NSK 0
#define NBK 1
#define NS 2
#define MAXCRASH 0
#define MC 0
#define MAXCORR 1
#define MAXWERR 0
#define OLDENTRY 0
#define BUILDHOLDS 1
#define SYNCBEFORE 1
#define HEEDSYNC 1
#define SYNCLAYERS 1
#define CHECKBOOT 1
#define EVRECHECK 0
#define LOOKUPFIRST 1
#define CHK_TypeOK
#define CHK_HeldIntact
#include "StoreLockingModel.pml"
