/* ReleasePipeline-liveness.cfg with its other property, DeployEnds (see there), and the safety
 * invariants again.
 * Written from proofs/tla/ReleasePipeline-liveness-deploy.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-ltl: DeployEnds
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
#define LTL_DeployEnds
#include "ReleasePipelineModel.pml"
