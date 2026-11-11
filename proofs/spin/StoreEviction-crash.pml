/* Safety across a machine's crash: two runners, a volume and a tree, a job each, a process crash,
 * the crash, and a job each after it.
 * Written from proofs/tla/StoreEviction-crash.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 7379840 */
#define NP 2
#define ROUNDS 1
#define MAXCRASH 1
#define MC 1
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
