/* Liveness under the fairness of GitHub's and the jobs' steps (not of merges, new runs or the
 * maintainer's approval), and the safety invariants again: a merge, two version runs, a push run
 * reporting no check, a lost run, a failure. TagJobEnds here, DeployEnds in -liveness-deploy.cfg,
 * the same model: TLC checks each in half the time of both (a tableau of two branches, not four),
 * and the two run in different parts.
 * Written from proofs/tla/ReleasePipeline-liveness.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-ltl: TagJobEnds
 * spin-states: 373472 */
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
#define APPROVALHOLDS 1
#define CHK_TypeOK
#define CHK_OneTagJob
#define CHK_TagOnMain
#define CHK_TagChecked
#define CHK_DeployChecked
#define CHK_FreshList
#define CHK_Includes
#define CHK_WaitBounded
#define CHK_FastFail
#define LTL_TagJobEnds
#include "ReleasePipelineModel.pml"
