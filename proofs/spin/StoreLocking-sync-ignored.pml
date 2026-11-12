/* A mutant SPIN must fail: NoWrongValid. publishTimed going on after a sync failed, as one that never
 * looked at fsync's result would: the rename publishes an entry the disk does not have, which a
 * crash then leaves validating (the store's crash test shows the same on dm-flakey).
 * Written from proofs/tla/StoreLocking-sync-ignored.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 1
#define NSK 1
#define NBK 0
#define NS 1
#define MAXCRASH 0
#define MC 1
#define MAXCORR 0
#define MAXWERR 1
#define OLDENTRY 0
#define BUILDHOLDS 1
#define SYNCBEFORE 1
#define HEEDSYNC 0
#define SYNCLAYERS 1
#define CHECKBOOT 1
#define EVRECHECK 1
#define LOOKUPFIRST 1
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreLockingModel.pml"
