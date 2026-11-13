//! What `tools/giteajobcorpus.zig` compares with Gitea's workflow model, under one module root (a
//! file may belong to one module only, and `gitea/job_oracle.zig` imports the runner's own files
//! by path).
pub const oracle = @import("gitea/job_oracle.zig");
