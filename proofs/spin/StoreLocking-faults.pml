/* Safety with a process's faults at once: two steps a job, a process crash, a hand's change, a sync
 * the disk fails and an entry an older store_format left.
 * Written from proofs/tla/StoreLocking-faults.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 10758379 */
#define NP 2
#define NSK 1
#define NBK 1
#define NS 2
#define MAXCRASH 1
#define MC 0
#define MAXCORR 1
#define MAXWERR 1
#define OLDENTRY 1
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
#include "StoreLockingModel.pml"
