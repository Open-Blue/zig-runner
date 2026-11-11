/* What the check after a boot is for. Without the publish's sync, a crash leaves entries that
 * validate over a tree the disk lost: no job may take one, as the first job of the boot evicts it
 * and the others wait for it. The mutant below is this with the check taken away.
 * Written from proofs/tla/StoreLocking-boot-check.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 382280 */
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
#define CHECKBOOT 1
#define EVRECHECK 1
#define LOOKUPFIRST 1
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoBadRead
#define CHK_HeldIntact
#define CHK_KeyMutex
#include "StoreLockingModel.pml"
