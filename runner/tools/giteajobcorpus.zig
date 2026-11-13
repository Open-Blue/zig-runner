//! The Zig half of `.github/scripts/gitea-job-diff.sh`: builds the `job.Job` of each task in a
//! directory (Gitea and Forgejo's answers of FetchTask) and compares it with what Gitea's workflow
//! model, run by `runner/tools/gitea-jobdiff`, reads from the same task.
//!
//!     giteajobcorpus <corpus dir> <answers.jsonl>
//!
//! Prints every difference, then counts. Fails when there is one.
const std = @import("std");
const runner = @import("runner");

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.debug.print("usage: giteajobcorpus <corpus dir> <answers.jsonl>\n", .{});
        return 2;
    }
    var out_buf: [8192]u8 = undefined;
    var out_w: std.Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;

    const cwd = std.Io.Dir.cwd();
    const answers = try cwd.readFileAlloc(io, args[2], arena, .limited(1 << 28));
    var dir = try cwd.openDir(io, args[1], .{});
    defer dir.close(io);

    var diffs: std.ArrayList([]const u8) = .empty;
    var tasks: usize = 0;
    var lines = std.mem.splitScalar(u8, answers, '\n');
    while (lines.next()) |l| {
        if (l.len == 0) continue;
        const entry = (try std.json.parseFromSliceLeaky(std.json.Value, arena, l, .{})).object;
        const file = entry.get("file").?.string;
        const text = try dir.readFileAlloc(io, file, arena, .limited(1 << 26));
        try runner.oracle.compare(arena, file, text, entry.get("model").?, &diffs);
        tasks += 1;
    }
    for (diffs.items) |d| try out.print("DIFFERS  {s}\n", .{d});
    try out.print("\n{d} tasks compared, {d} differences\n", .{ tasks, diffs.items.len });
    out.flush() catch |e| std.log.warn("stdout: {s}", .{@errorName(e)});
    return if (diffs.items.len == 0) 0 else 1;
}
