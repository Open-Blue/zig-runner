/* A mutant TLC must fail: NoWrongValid. The durable mark written before the data's fsyncs: a crash
 * between them leaves a layer marked durable whose tree never reached the disk.
 * Written from proofs/tla/StoreDeferred-mark-first.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define NP 2
#define NR 1
#define NS 1
#define MC 1
#define MAXRCRASH 0
#define MAXWERR 0
#define SYNCBEFORE 0
#define CHECKBOOT 1
#define OWNERONLY 1
#define POISON 1
#define SETTLEEND 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#include "StoreDeferredModel.pml"
