/* A mutant TLC must fail: FreshList. The names inline in version.yml, before #408: the run's own
 * file, from main when the run was made, while the tag job waits on main as it is after approval;
 * a rename merged between the two is waited for under its old name.
 * Written from proofs/tla/ReleasePipeline-inline-list.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
#define MAXMERGES 1
#define MAXRUNS 3
#define MAXRENAMES 1
#define MAXLOST 1
#define MAXFAILS 1
#define WAITTICKS 2
#define GRACE 1
#define COUNTALL 0
#define LISTFROMCOMMIT 0
#define FASTFAILS 1
#define OTHERWF 1
#define DEPLOYEXPLICIT 1
#define ATOMICPUSH 1
#define APPROVALHOLDS 1
#define CHK_FreshList
#define CHK_TypeOK
#define CHK_OneTagJob
#define CHK_TagOnMain
#define CHK_TagChecked
#define CHK_DeployChecked
#define CHK_Includes
#define CHK_WaitBounded
#define CHK_FastFail
#include "ReleasePipelineModel.pml"
