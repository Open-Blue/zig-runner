/* A mutant TLC must fail: DeployEnds. The deploy job's `if:` as v0.14.0 had it, the implicit
 * success(): Binaries (check) is skipped on a tag, so the deploy is skipped, and the release run
 * ends green without deploying.
 * Written from proofs/tla/ReleasePipeline-v0.14.0.cfg by proofs/spin/cfg.py: change the .cfg, not this.
 * spin-ltl: DeployEnds */
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
#define DEPLOYEXPLICIT 0
#define ATOMICPUSH 1
#define APPROVALHOLDS 1
#define LTL_DeployEnds
#include "ReleasePipelineModel.pml"
