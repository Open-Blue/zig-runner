/* The deferred sync (a publish renamed in pending, made durable at the next publish or the job's end):
 * two runners and a reader that holds layers, two layers a job, a machine crash, a killed runner, a
 * failed sync and a write-back that loses a pending layer's data within the boot. No other job takes
 * a pending layer, none takes a poisoned one, no lookup after any crash takes a layer whose tree is
 * not whole, and a job whose end finished loses none of its layers.
 * Written from proofs/tla/StoreDeferred.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 36662 */
#define NP 2
#define NR 1
#define NS 2
#define MC 1
#define MAXRCRASH 1
#define MAXWERR 1
#define SYNCBEFORE 1
#define CHECKBOOT 1
#define OWNERONLY 1
#define POISON 1
#define SETTLEEND 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#define CHK_NoLostPublish
#define CHK_MarkedHasData
#include "StoreDeferredModel.pml"
