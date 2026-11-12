/* A finding SPIN must fail: FastFailOnChecks. The fast fail waits for every run on the commit but
 * the waiting workflows', so one that reports no check (codeql, scorecard, a scheduled analysis
 * run made at the commit) holds it after ci's and proofs' runs have finished, up to the deadline
 * when it runs longer. By design (85dc4e8): FastFail, its own property, holds.
 * Written from proofs/tla/ReleasePipeline-other-wf.cfg by proofs/spin/cfg.py: change the .cfg, not this. */
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
#define CHK_FastFailOnChecks
#include "ReleasePipelineModel.pml"
