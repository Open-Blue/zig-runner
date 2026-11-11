/* A mutant TLC must fail: PassGoesOn. A pass that ends at a dead tree it cannot remove: a job that can
 * make one stops eviction in every area.
 * Written from proofs/tla/StoreEviction-stuck-stops.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 3
#define ROUNDS 1
#define MAXCRASH 1
#define MC 0
#define MAXPLANT 0
#define MAXSTUCK 1
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
#define SYNCFS 1
#define CLEARPLANT 1
#define STUCKGOES 0
#define CHK_TypeOK
#define CHK_PassGoesOn
#include "StoreEvictionModel.pml"
