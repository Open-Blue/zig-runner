/* A mutant TLC must fail: NoLostPublish. A job's end without `syncLayers`: a crash loses the rename
 * of a layer whose job had finished.
 * Written from proofs/tla/StoreLocking-no-dir-sync.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 1
#define NSK 1
#define NBK 0
#define NS 1
#define MAXCRASH 0
#define MC 1
#define MAXCORR 0
#define MAXWERR 0
#define OLDENTRY 0
#define BUILDHOLDS 1
#define SYNCBEFORE 1
#define HEEDSYNC 1
#define SYNCLAYERS 0
#define CHECKBOOT 1
#define EVRECHECK 1
#define LOOKUPFIRST 1
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoLostPublish
#include "StoreLockingModel.pml"
