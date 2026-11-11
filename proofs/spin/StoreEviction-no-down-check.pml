/* A mutant TLC must fail: HeldWhole. ensure taking what it made to be there once it holds the lock
 * shared: flock gave the exclusive one up first, and an eviction came between.
 * Written from proofs/tla/StoreEviction-no-down-check.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define ROUNDS 1
#define MAXCRASH 0
#define MC 0
#define MAXPLANT 0
#define MAXSTUCK 0
#define NK 1
#define VOLS 0
#define OUTER 1
#define INNER 1
#define OPENRECHECK 1
#define DOWNRECHECK 0
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
