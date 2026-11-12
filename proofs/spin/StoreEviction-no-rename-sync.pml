/* A mutant SPIN must fail: NamedWhole. An eviction that deletes before its rename is on disk, on a
 * filesystem that keeps the deletes and loses the rename: the name comes back on a tree half gone.
 * Written from proofs/tla/StoreEviction-no-rename-sync.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 1
#define ROUNDS 2
#define MAXCRASH 0
#define MC 1
#define MAXPLANT 0
#define MAXSTUCK 0
#define NK 1
#define VOLS 1
#define OUTER 1
#define INNER 1
#define OPENRECHECK 1
#define DOWNRECHECK 1
#define EVLOCKS 1
#define EVRECHECK 1
#define INNERLOCK 1
#define RENAMEFIRST 1
#define SYNCRENAME 0
#define SYNCFS 1
#define CLEARPLANT 1
#define STUCKGOES 1
#define CHK_TypeOK
#define CHK_NamedWhole
#include "StoreEvictionModel.pml"
