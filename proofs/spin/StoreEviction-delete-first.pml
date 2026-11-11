/* A mutant TLC must fail: NamedWhole. An eviction that deletes before it renames: a crash between
 * leaves the name on a tree half gone.
 * Written from proofs/tla/StoreEviction-delete-first.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 1
#define ROUNDS 2
#define MAXCRASH 1
#define MC 0
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
#define RENAMEFIRST 0
#define SYNCRENAME 1
#define SYNCFS 1
#define CLEARPLANT 1
#define STUCKGOES 1
#define CHK_TypeOK
#define CHK_NamedWhole
#include "StoreEvictionModel.pml"
