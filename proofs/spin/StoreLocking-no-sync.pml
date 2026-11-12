/* A mutant SPIN must fail: NoWrongValid. Store.publish without its syncfs (Store.zig:462): a machine
 * crash after the rename leaves an entry that validates but whose tree was never written to disk.
 * Written from proofs/tla/StoreLocking-no-sync.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
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
#define SYNCBEFORE 0
#define HEEDSYNC 1
#define SYNCLAYERS 1
#define CHECKBOOT 1
#define EVRECHECK 1
#define LOOKUPFIRST 1
#define EVUNLOCK 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreLockingModel.pml"
