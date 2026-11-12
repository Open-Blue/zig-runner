/* A mutant SPIN must fail: TagOnMain. The push without --atomic: when main moved since the
 * checkout, main's update is refused and the tag still goes, on a commit off main. Two merges, as
 * -merges.cfg: one before the run has anything to release, one while its tag job waits.
 * Written from proofs/tla/ReleasePipeline-non-atomic.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
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
#define ATOMICPUSH 0
#define APPROVALHOLDS 1
#define CHK_TagOnMain
#define CHK_TypeOK
#define CHK_OneTagJob
#define CHK_TagChecked
#define CHK_DeployChecked
#define CHK_FreshList
#define CHK_Includes
#define CHK_WaitBounded
#define CHK_FastFail
#include "ReleasePipelineModel.pml"
