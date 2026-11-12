/* A mutant SPIN must fail: NoBadRead. StoreLocking-boot-check.cfg without `checkOncePerBoot`: a job
 * after the crash takes an entry whose tree the disk lost.
 * Written from proofs/tla/StoreLocking-no-boot-check.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NSK 1
#define NBK 0
#define NS 1
#define MAXCRASH 0
#define MC 1
#define MAXCORR 0
#define MAXWERR 0
#define OLDENTRY 0
#define BUILDHOLDS 1
#define SYNCBEFORE 0
#define HEEDSYNC 1
#define SYNCLAYERS 1
#define CHECKBOOT 0
#define EVRECHECK 1
#define LOOKUPFIRST 1
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoBadRead
#include "StoreLockingModel.pml"
