/* A mutant TLC must fail: HeldWhole. An eviction that takes a volume's lock and not the lock of the
 * volume inside it: the job holding the inner one loses it.
 * Written from proofs/tla/StoreEviction-no-inner-lock.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define ROUNDS 1
#define MAXCRASH 0
#define MC 0
#define MAXPLANT 0
#define MAXSTUCK 0
#define NK 2
#define VOLS 3
#define OUTER 0
#define INNER 1
#define OPENRECHECK 1
#define DOWNRECHECK 1
#define EVLOCKS 1
#define EVRECHECK 1
#define INNERLOCK 0
#define RENAMEFIRST 1
#define SYNCRENAME 1
#define SYNCFS 1
#define CLEARPLANT 1
#define STUCKGOES 1
#define CHK_TypeOK
#define CHK_HeldWhole
#include "StoreEvictionModel.pml"
