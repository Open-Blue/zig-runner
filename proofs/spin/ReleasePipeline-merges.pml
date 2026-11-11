/* Safety with two merges (a rename before the tag job reads main and one while it waits, or the
 * other way round) and two version runs; no lost run, no failure and no third push run, which are
 * ReleasePipeline.cfg's (without a lost run no check is missing, so FastFail holds trivially here).
 * Written from proofs/tla/ReleasePipeline-merges.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 1474774 */
#define MAXMERGES 2
#define MAXRUNS 2
#define MAXRENAMES 1
#define MAXLOST 0
#define MAXFAILS 0
#define WAITTICKS 2
#define GRACE 1
#define COUNTALL 0
#define LISTFROMCOMMIT 1
#define FASTFAILS 1
#define OTHERWF 0
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
#include "ReleasePipelineModel.pml"
