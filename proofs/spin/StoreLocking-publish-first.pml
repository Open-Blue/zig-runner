/* A mutant SPIN must fail: NoBuildLost. layers.zig's publish as #299 had it, under the key's lock but
 * publishing first and looking the key up only once the rename was refused: a collect evicts the
 * layer another builder stored, no job holding it, between the refused rename and the lookup, and
 * the build fails with a layer it built and none stored (found by store_stress.zig).
 * Written from proofs/tla/StoreLocking-publish-first.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NSK 0
#define NBK 1
#define NS 1
#define MAXCRASH 0
#define MC 0
#define MAXCORR 0
#define MAXWERR 0
#define OLDENTRY 0
#define BUILDHOLDS 1
#define SYNCBEFORE 1
#define HEEDSYNC 1
#define SYNCLAYERS 1
#define CHECKBOOT 1
#define EVRECHECK 1
#define LOOKUPFIRST 0
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoBuildLost
#include "StoreLockingModel.pml"
