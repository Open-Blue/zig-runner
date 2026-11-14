/* A mutant SPIN must fail: NoWrongValid. A job's end that joins a shared settle and marks its layer
 * durable before the batch's syncfs has run: a crash between them leaves a layer marked durable whose
 * tree never reached the disk.
 * Written from proofs/tla/StoreDeferred-batch-mark-first.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
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
#define SETTLEEND 1
#define BATCHEND 1
#define BATCHFIRST 0
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreDeferredModel.pml"
