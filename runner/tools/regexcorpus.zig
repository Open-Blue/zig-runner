//! The Zig half of `.github/scripts/regex-diff.sh`: compiles each case's pattern with
//! src/regex.zig and compares what it makes of each input with what .NET made of it, as GitHub's
//! runner compiles problem matchers (tools/regexdiff/reference).
//!
//!     regexcorpus <cases.json> <reference.jsonl> [-v]
//!
//! Prints each disagreement (with -v, all of them; else the first few of each kind), then counts.
//! A pattern .NET refuses must be refused; one it takes must be taken (a refusal there is a gap,
//! counted apart from wrong answers); and each input must match or not as in .NET, every group with
//! the same value. Inputs where .NET timed out, or regex.zig ran out of its step budget, are left
//! out of the comparison.
const std = @import("std");
const regex = @import("regex");
const corpus = @import("corpus");

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        std.debug.print("usage: regexcorpus <cases.json> <reference.jsonl> [-v]\n", .{});
        return 2;
    }
    const verbose = args.len > 3 and std.mem.eql(u8, args[3], "-v");
    var out_buf: [8192]u8 = undefined;
    var out_w: std.Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    const cwd = std.Io.Dir.cwd();
    const cases = (try std.json.parseFromSliceLeaky(std.json.Value, arena, try cwd.readFileAlloc(io, args[1], arena, .limited(1 << 28)), .{})).array.items;
    const reference = try corpus.loadReference(arena, io, args[2]);

    const Count = struct { n: usize = 0, shown: usize = 0 };
    var agree_patterns: usize = 0;
    var agree_inputs: usize = 0;
    var both_refuse: usize = 0;
    var skipped: usize = 0;
    var accepts_refused: Count = .{};
    var refuses_ok: Count = .{};
    var unsupported: Count = .{};
    var wrong: Count = .{};
    const show_limit: usize = if (verbose) std.math.maxInt(usize) else 25;

    for (cases) |c| {
        const id = c.object.get("id").?.integer;
        const pattern = c.object.get("pattern").?.string;
        const want = reference.get(id) orelse continue;
        if (want.get("unreportable") != null) continue;
        const compiled = regex.Regex.compile(arena, pattern);
        if (want.get("error")) |e| {
            if (compiled) |_| {
                accepts_refused.n += 1;
                if (accepts_refused.shown < show_limit) {
                    accepts_refused.shown += 1;
                    try out.print("ACCEPTS what .NET refuses  /{s}/: {s}\n", .{ pattern, e.string });
                }
            } else |_| both_refuse += 1;
            continue;
        }
        const re = compiled catch |err| {
            const kind = if (err == error.Unsupported) &unsupported else &refuses_ok;
            kind.n += 1;
            if (kind.shown < show_limit) {
                kind.shown += 1;
                try out.print("{s}  /{s}/\n", .{ if (err == error.Unsupported) "UNSUPPORTED" else "REFUSES what .NET takes", pattern });
            }
            continue;
        };
        var all_agree = true;
        for (c.object.get("inputs").?.array.items, want.get("results").?.array.items) |in_v, res_v| {
            const input = in_v.string;
            const res = res_v.object;
            if (res.get("timeout") != null) {
                skipped += 1;
                continue;
            }
            const got = re.find(arena, input, 0) catch |err| switch (err) {
                error.TooComplex => {
                    skipped += 1;
                    continue;
                },
                else => return err,
            };
            const matched = res.get("matched").?.bool;
            var why: ?[]const u8 = null;
            if (matched != (got != null)) {
                why = if (matched) "no match, .NET matches" else "a match, .NET has none";
            } else if (got) |caps| {
                var it = res.get("groups").?.object.iterator();
                while (it.next()) |g| {
                    const n = try std.fmt.parseInt(usize, g.key_ptr.*, 10);
                    const theirs: ?[]const u8 = if (g.value_ptr.* == .string) g.value_ptr.string else null;
                    const ours = caps.text(n, input);
                    const same = if (theirs == null) ours == null else (ours != null and std.mem.eql(u8, ours.?, theirs.?));
                    if (!same) {
                        why = try std.fmt.allocPrint(arena, "group {d}: .NET {s}{s}{s}, here {s}{s}{s}", .{
                            n,                              if (theirs != null) "\"" else "", theirs orelse "null",           if (theirs != null) "\"" else "",
                            if (ours != null) "\"" else "", ours orelse "null",               if (ours != null) "\"" else "",
                        });
                        break;
                    }
                }
            }
            if (why) |w| {
                all_agree = false;
                wrong.n += 1;
                if (wrong.shown < show_limit) {
                    wrong.shown += 1;
                    try out.print("WRONG  /{s}/ on \"{s}\": {s}\n", .{ pattern, input, w });
                }
            } else agree_inputs += 1;
        }
        if (all_agree) agree_patterns += 1;
    }
    try out.print(
        "\n{d} patterns answer every input as .NET does ({d} inputs); {d} wrong answers; " ++
            "{d} patterns unsupported; {d} refused that .NET takes; {d} accepted that .NET refuses; " ++
            "{d} refused by both; {d} inputs skipped (time)\n",
        .{ agree_patterns, agree_inputs, wrong.n, unsupported.n, refuses_ok.n, accepts_refused.n, both_refuse, skipped },
    );
    return if (wrong.n + refuses_ok.n + accepts_refused.n + unsupported.n == 0) 0 else 1;
}
