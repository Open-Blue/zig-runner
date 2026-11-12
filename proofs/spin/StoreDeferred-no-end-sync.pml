/* A mutant TLC must fail: NoLostPublish. A job's end that leaves its last layer pending: a layer a
 * finished job published is refused after a crash.
 * Written from proofs/tla/StoreDeferred-no-end-sync.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NR 1
#define NS 1
#define MC 1
#define MAXRCRASH 0
#define MAXWERR 0
#define SYNCBEFORE 1
#define CHECKBOOT 1
#define OWNERONLY 1
#define POISON 1
#define SETTLEEND 0
#define CHK_TypeOK
#define CHK_NoLostPublish
#include "StoreDeferredModel.pml"
