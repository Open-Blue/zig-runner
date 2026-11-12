/* A mutant SPIN must fail: NoWrongValid. A lookup that ignores the boot a pending mark names (and that
 * any job may take a pending layer): after a crash it takes a layer whose data never reached the disk.
 * Written from proofs/tla/StoreDeferred-trust-pending.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NR 1
#define NS 1
#define MC 1
#define MAXRCRASH 0
#define MAXWERR 0
#define SYNCBEFORE 1
#define CHECKBOOT 0
#define OWNERONLY 0
#define POISON 1
#define SETTLEEND 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreDeferredModel.pml"
