/* A mutant SPIN must fail: NoWrongValid. A pending layer any job of the boot may take and a failed settle
 * that does not refuse it (the first version): a reader holds a layer whose write-back was lost.
 * Written from proofs/tla/StoreDeferred-no-poison.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NR 1
#define NS 1
#define MC 1
#define MAXRCRASH 0
#define MAXWERR 1
#define SYNCBEFORE 1
#define CHECKBOOT 1
#define OWNERONLY 0
#define POISON 0
#define SETTLEEND 1
#define BATCHEND 0
#define BATCHFIRST 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreDeferredModel.pml"
