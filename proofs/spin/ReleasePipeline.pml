/* Safety of the pipeline as #408 has it (proofs/README.md, "The release pipeline, in TLA+"): a
 * merge, which may rename or add a check, three version runs (one in progress, one pending, a third
 * replacing it), ci's and proofs' push runs and one reporting no check, a run GitHub never
 * creates, a push run or a release's job that fails, a wait of two polls with a grace of one. Two
 * merges are -merges.cfg's, liveness -liveness.cfg's.
 * Written from proofs/tla/ReleasePipeline.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-states: 2002483 */
#define MAXMERGES 1
#define MAXRUNS 3
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
#include "ReleasePipelineModel.pml"
