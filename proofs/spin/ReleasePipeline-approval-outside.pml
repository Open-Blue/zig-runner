/* The weaker reading of GitHub's concurrency docs: a run whose tag job waits for approval is not in
 * progress in the group, so a newer run starts beside it. Two tag jobs may then run at once
 * (OneTagJob fails, left out here), and everything else still holds: the atomic push, not the
 * group, keeps a tag on main and checked.
 * Written from proofs/tla/ReleasePipeline-approval-outside.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 1445111 */
#define MAXMERGES 1
#define MAXRUNS 2
#define MAXRENAMES 1
#define MAXLOST 1
#define MAXFAILS 1
#define WAITTICKS 2
#define GRACE 1
#define COUNTALL 0
#define LISTFROMCOMMIT 1
#define FASTFAILS 1
#define OTHERWF 1
#define DEPLOYEXPLICIT 1
#define ATOMICPUSH 1
#define APPROVALHOLDS 0
#define CHK_TypeOK
#define CHK_TagOnMain
#define CHK_TagChecked
#define CHK_DeployChecked
#define CHK_FreshList
#define CHK_Includes
#define CHK_WaitBounded
#define CHK_FastFail
#include "ReleasePipelineModel.pml"
