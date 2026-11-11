/* A mutant TLC must fail: FastFail. wait-for-checks.sh as it was before #408: a check that never
 * started holds the wait to its end, after every run on the commit has finished.
 * Written from proofs/tla/ReleasePipeline-no-fast-fail.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define MAXMERGES 1
#define MAXRUNS 3
#define MAXRENAMES 1
#define MAXLOST 1
#define MAXFAILS 1
#define WAITTICKS 2
#define GRACE 1
#define COUNTALL 0
#define LISTFROMCOMMIT 1
#define FASTFAILS 0
#define OTHERWF 1
#define DEPLOYEXPLICIT 1
#define ATOMICPUSH 1
#define APPROVALHOLDS 1
#define CHK_FastFail
#define CHK_TypeOK
#define CHK_OneTagJob
#define CHK_TagOnMain
#define CHK_TagChecked
#define CHK_DeployChecked
#define CHK_FreshList
#define CHK_Includes
#define CHK_WaitBounded
#include "ReleasePipelineModel.pml"
