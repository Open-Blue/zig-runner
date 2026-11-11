/* Every job ends, without symmetry (unsound for liveness): two runners, a volume and a tree.
 * Written from proofs/tla/StoreEviction-liveness.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-ltl: AllEnd
 * spin-states: 11744 */
#define NP 2
#define ROUNDS 1
#define MAXCRASH 1
#define MC 0
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
#define SYNCFS 1
#define CLEARPLANT 1
#define STUCKGOES 1
#define CHK_TypeOK
#define LTL_AllEnd
#include "StoreEvictionModel.pml"
