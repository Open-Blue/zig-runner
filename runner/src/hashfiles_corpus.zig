//! What `tools/hashfilescorpus.zig` compares with GitHub's hashFiles(), under one module root (a
//! file may belong to one module only, and `native/hash_files.zig` imports `glob.zig` by path).
pub const glob = @import("glob.zig");
pub const native = @import("native/hash_files.zig");
pub const expr = @import("expr.zig");
