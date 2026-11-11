/* A mutant TLC must fail: HeldWhole. volumes.open without sameFile: a job holds the lock file an
 * eviction has just removed, while the entry goes.
 * Written from proofs/tla/StoreEviction-no-recheck.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define ROUNDS 2
#define MAXCRASH 0
#define MC 0
#define MAXPLANT 0
#define MAXSTUCK 0
#define NK 1
#define VOLS 1
#define OUTER 1
#define INNER 1
#define OPENRECHECK 0
#define DOWNRECHECK 1
#define EVLOCKS 1
#define EVRECHECK 1
#define INNERLOCK 1
#define RENAMEFIRST 1
#define SYNCRENAME 1
#define SYNCFS 1
#define CLEARPLANT 1
#define STUCKGOES 1
#define CHK_TypeOK
#define CHK_HeldWhole
#include "StoreEvictionModel.pml"
