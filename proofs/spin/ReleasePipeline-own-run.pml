/* A mutant TLC must fail: FastFail. wait-for-checks.sh as #408 had it before 85dc4e8, counting every
 * workflow run on the commit, the waiting job's own among them: the fast fail never fired in the
 * deploy job (release.yml's run is on the tag commit), nor in a tag job on the commit its version
 * run was made at, so a check that never started held the wait to its end. Found by this model.
 * Written from proofs/tla/ReleasePipeline-own-run.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define MAXMERGES 1
#define MAXRUNS 3
#define MAXRENAMES 1
#define MAXLOST 1
#define MAXFAILS 1
#define WAITTICKS 2
#define GRACE 1
#define COUNTALL 1
#define LISTFROMCOMMIT 1
#define FASTFAILS 1
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
