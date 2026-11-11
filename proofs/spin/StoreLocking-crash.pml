/* Safety across a machine's crash: two runners and a step key, a process crash and a hand's change,
 * then the crash and the first jobs of the next boot (`checkOncePerBoot`). Two steps a job, write
 * errors and an older format's entry are StoreLocking-faults.cfg's; a build key adds nothing a crash
 * can see, as a build's publish is a step's.
 * Written from proofs/tla/StoreLocking-crash.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 14674009 */
#define NP 2
#define NSK 1
#define NBK 0
#define NS 1
#define MAXCRASH 1
#define MC 1
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
#include "StoreLockingModel.pml"
