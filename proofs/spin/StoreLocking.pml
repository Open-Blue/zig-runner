/* Safety of the protocol as the code has it (proofs/README.md, "The store's locking, in TLA+"):
 * three runners, a step key and a build key, one step a job, a process crash. Two-step jobs, the
 * machine's crash and a hand's change are StoreLocking-crash.cfg's; liveness is
 * StoreLocking-liveness.cfg's.
 * Written from proofs/tla/StoreLocking.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 16495443 */
#define NP 3
#define NSK 1
#define NBK 1
#define NS 1
#define MAXCRASH 1
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
#define LOOKUPFIRST 1
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
#include "StoreLockingModel.pml"
