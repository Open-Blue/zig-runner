/* The deferred sync with each job's end syncing on its own (RUNNER_NATIVE_SETTLE_WINDOW_MS=0, as
 * before the shared settle), in StoreDeferred.cfg's bounds: the same guarantees.
 * Written from proofs/tla/StoreDeferred-unbatched.cfg by proofs/spin/cfg.py: change the .cfg, not this.
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
#define BATCHEND 0
#define BATCHFIRST 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#define CHK_NoLostPublish
#define CHK_MarkedHasData
#include "StoreDeferredModel.pml"
