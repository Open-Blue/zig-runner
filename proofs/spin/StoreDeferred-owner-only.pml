/* The deferred sync with the ownership rule alone: a failed settle does not poison its layer, and no job but its writer takes a pending one, so it holds (the poison is for the layers a job already holds, which the model does not tell apart). Same bounds as StoreDeferred.cfg.
 * Written from proofs/tla/StoreDeferred-owner-only.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 34602 */
#define NP 2
#define NR 1
#define NS 2
#define MC 1
#define MAXRCRASH 1
#define MAXWERR 1
#define SYNCBEFORE 1
#define CHECKBOOT 1
#define OWNERONLY 1
#define POISON 0
#define SETTLEEND 1
#define CHK_TypeOK
#define CHK_NoWrongValid
#define CHK_NoLostPublish
#define CHK_MarkedHasData
#include "StoreDeferredModel.pml"
