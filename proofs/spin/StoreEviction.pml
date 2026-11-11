/* Safety as the code has it: three runners, a volume and a tree, one job each and a collect, a process
 * crash. A machine's crash is StoreEviction-crash.cfg's, the entry inside another -nested's.
 * Written from proofs/tla/StoreEviction.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 3109887 */
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
#define STUCKGOES 1
#define CHK_TypeOK
#define CHK_HeldWhole
#define CHK_NamedWhole
#define CHK_OneMaker
#define CHK_LocksExclude
#define CHK_NotPinned
#define CHK_PassGoesOn
#include "StoreEvictionModel.pml"
