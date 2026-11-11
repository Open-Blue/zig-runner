/* A mutant TLC must fail: NoWrongValid. A failed settle refuses its layer, but any job of the boot may
 * take a pending one: a reader takes it before its writer's settle finds the loss (or after its runner was killed).
 * Written from proofs/tla/StoreDeferred-shared-pending.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NR 1
#define NS 1
#define MC 1
#define MAXRCRASH 1
#define MAXWERR 0
#define SYNCBEFORE 1
#define CHECKBOOT 1
#define OWNERONLY 0
#define POISON 1
#define SETTLEEND 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreDeferredModel.pml"
