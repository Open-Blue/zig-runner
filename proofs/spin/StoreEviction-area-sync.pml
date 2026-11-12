/* A mutant SPIN must fail: NamedWhole. removeDead syncing only the area's directory: a volume's rename has
 * another source directory, so a crash can keep the name and the deletes. Found in review, in 25 states.
 * Written from proofs/tla/StoreEviction-area-sync.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define ROUNDS 1
#define MAXCRASH 1
#define MC 1
#define MAXPLANT 0
#define MAXSTUCK 0
#define NK 2
#define VOLS 2
#define OUTER 2
#define INNER 2
#define OPENRECHECK 1
#define DOWNRECHECK 1
#define EVLOCKS 1
#define EVRECHECK 1
#define INNERLOCK 1
#define RENAMEFIRST 1
#define SYNCRENAME 1
#define SYNCFS 0
#define CLEARPLANT 1
#define STUCKGOES 1
#define CHK_TypeOK
#define CHK_NamedWhole
#include "StoreEvictionModel.pml"
