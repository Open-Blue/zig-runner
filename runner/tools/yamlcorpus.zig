//! Compares src/yaml.zig with go.yaml.in/yaml/v3 file by file: reads the trees
//! runner/tools/yamldiff wrote (one JSON line per file) and parses each file with yaml.zig.
//! `.github/scripts/yaml-diff.sh` fetches the files and builds and runs both.
//!
//!     yamlcorpus <expected.jsonl> <dir of the files>
//!
//! Prints every file where the trees differ (with the path to the first difference), every file
//! yaml.zig reads that Go refuses, every file yaml.zig refuses that Go reads (its subset, or a
//! bug), then counts. Fails when trees differ or yaml.zig reads what Go refuses: refusing is
//! allowed, misreading is not.
const std = @import("std");
const yaml = @import("yaml");

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.debug.print("usage: yamlcorpus <expected.jsonl> <dir>\n", .{});
        return 2;
    }
    var out_buf: [8192]u8 = undefined;
    var out_w: std.Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    const cwd = std.Io.Dir.cwd();
    const expected = try cwd.readFileAlloc(io, args[1], arena, .limited(1 << 30));
    var dir = try cwd.openDir(io, args[2], .{});
    defer dir.close(io);

    var same: usize = 0;
    var differ: usize = 0;
    var refused: usize = 0;
    var go_refused: usize = 0;
    var lines = std.mem.splitScalar(u8, expected, '\n');
    while (lines.next()) |l| {
        if (l.len == 0) continue;
        const want = (try std.json.parseFromSliceLeaky(std.json.Value, arena, l, .{})).object;
        const file = want.get("file").?.string;
        const src = try dir.readFileAlloc(io, file, arena, .limited(1 << 26));
        var diag: yaml.Diag = .{};
        if (want.get("error")) |e| {
            go_refused += 1;
            // Reading what Go refuses is a difference too: it is not YAML, or not in the subset.
            if (yaml.parse(arena, src, &diag)) |_| {
                differ += 1;
                try out.print("ACCEPTS  {s}: Go refuses it ({s}), yaml.zig reads it\n", .{ file, e.string });
            } else |_| {}
            continue;
        }
        const got = yaml.parse(arena, src, &diag) catch |e| {
            refused += 1;
            try out.print("refused  {s}: {s} at line {d}: {s}\n", .{ file, @errorName(e), diag.line, diag.message });
            continue;
        };
        if (try difference(arena, got, want.get("tree") orelse .null, "")) |where| {
            differ += 1;
            try out.print("DIFFERS  {s}: {s}\n", .{ file, where });
        } else same += 1;
    }
    try out.print("\n{d} files read the same, {d} differ, {d} refused by yaml.zig, {d} refused by Go\n", .{
        same, differ, refused, go_refused,
    });
    return if (differ == 0) 0 else 1;
}

/// Where `got` first differs from `want` (yamldiff's form), or null when they are the same.
fn difference(arena: std.mem.Allocator, got: yaml.Node, want: std.json.Value, path: []const u8) !?[]const u8 {
    const at = if (path.len == 0) "the top" else path;
    switch (want) {
        .null => if (got != .null)
            return try std.fmt.allocPrint(arena, "{s}: Go has null, yaml.zig {s}", .{ at, try show(arena, got) }),
        .string => |s| {
            if (got != .string)
                return try std.fmt.allocPrint(arena, "{s}: Go has \"{s}\", yaml.zig {s}", .{ at, s, try show(arena, got) });
            if (!std.mem.eql(u8, got.string, s))
                return try std.fmt.allocPrint(arena, "{s}: Go has \"{s}\", yaml.zig \"{s}\"", .{ at, s, got.string });
        },
        .object => |o| if (o.get("seq")) |seq| {
            if (got != .seq)
                return try std.fmt.allocPrint(arena, "{s}: Go has a sequence, yaml.zig {s}", .{ at, try show(arena, got) });
            if (got.seq.len != seq.array.items.len)
                return try std.fmt.allocPrint(arena, "{s}: Go has {d} items, yaml.zig {d}", .{ at, seq.array.items.len, got.seq.len });
            for (got.seq, seq.array.items, 0..) |g, w, i|
                if (try difference(arena, g, w, try std.fmt.allocPrint(arena, "{s}[{d}]", .{ path, i }))) |d| return d;
        } else {
            const pairs = try lastWins(arena, o.get("map").?.array.items);
            if (got != .map)
                return try std.fmt.allocPrint(arena, "{s}: Go has a mapping, yaml.zig {s}", .{ at, try show(arena, got) });
            if (got.map.len != pairs.len)
                return try std.fmt.allocPrint(arena, "{s}: Go has {d} keys, yaml.zig {d}", .{ at, pairs.len, got.map.len });
            for (got.map, pairs) |g, p| {
                const key = p.array.items[0].string;
                if (!std.mem.eql(u8, g.key, key))
                    return try std.fmt.allocPrint(arena, "{s}: Go has key \"{s}\", yaml.zig \"{s}\"", .{ at, key, g.key });
                if (try difference(arena, g.value, p.array.items[1], try std.fmt.allocPrint(arena, "{s}.{s}", .{ path, key }))) |d| return d;
            }
        },
        else => unreachable,
    }
    return null;
}

/// Go's pairs as yaml.zig keeps them: a key given twice (which GitHub refuses) has its last value,
/// where it first appeared. Go's yaml.Node keeps both.
fn lastWins(arena: std.mem.Allocator, pairs: []std.json.Value) ![]std.json.Value {
    var out: std.ArrayList(std.json.Value) = .empty;
    next: for (pairs) |p| {
        for (out.items) |*q| if (std.mem.eql(u8, q.array.items[0].string, p.array.items[0].string)) {
            q.* = p;
            continue :next;
        };
        try out.append(arena, p);
    }
    return out.items;
}

fn show(arena: std.mem.Allocator, n: yaml.Node) ![]const u8 {
    return switch (n) {
        .null => "null",
        .string => |s| std.fmt.allocPrint(arena, "\"{s}\"", .{s}),
        .boolean, .number => "a typed scalar",
        .seq => "a sequence",
        .map => "a mapping",
    };
}
