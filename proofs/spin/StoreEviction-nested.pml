/* Safety with a volume inside another's directory: three runners, a process crash.
 * Written from proofs/tla/StoreEviction-nested.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 955705 */
#define NP 3
#define ROUNDS 1
#define MAXCRASH 1
#define MC 0
#define MAXPLANT 1
#define MAXSTUCK 0
#define NK 2
#define VOLS 3
#define OUTER 0
#define INNER 1
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
