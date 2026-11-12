/* Liveness under weak fairness of each runner, and the safety invariants again, without symmetry
 * (a symmetry reduction is unsound for liveness): two runners, a step key and a build key,
 * one step a job, a process crash and a hand's change. The machine's crash ends every process, so
 * it adds nothing here.
 * Written from proofs/tla/StoreLocking-liveness.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-ltl: WaitEnds AllEnd
 * spin-states: 167363 */
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
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoBadRead
#define CHK_HeldIntact
#define CHK_KeyMutex
#define CHK_NoWrongValid
#define CHK_NoLostUpper
#define CHK_OnePub
#define CHK_NoBuildLost
#define CHK_NoLostPublish
#define CHK_OldGoes
#define LTL_WaitEnds
#define LTL_AllEnd
#include "StoreLockingModel.pml"
