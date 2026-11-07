//! The Zig half of `.github/scripts/hpack-diff.sh`: decodes the header blocks
//! runner/tools/hpackdiff wrote with src/hpack.zig, one Decoder per connection, block after block,
//! and compares each header list with the one Go encoded (or, for a broken block, with what Go's
//! decoder made of it).
//!
//!     hpackcorpus <cases.jsonl>
//!
//! Prints every block that decodes differently, and every one hpack.zig takes that Go refuses or
//! refuses that Go encoded, then counts. Refusing a broken block Go reads is printed and allowed:
//! hpack.zig takes only the integers and table sizes the engine can send. The decoder's memory
//! comes from a DebugAllocator, which poisons what is freed and fails the run on a leak.
const std = @import("std");
const hpack = @import("hpack");
const corpus = @import("corpus");

const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 2) {
        std.debug.print("usage: hpackcorpus <cases.jsonl>\n", .{});
        return 2;
    }
    var out_buf: [8192]u8 = undefined;
    var out_w: Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    var debug: std.heap.DebugAllocator(.{}) = .init;
    const cases = try Io.Dir.cwd().readFileAlloc(io, args[1], arena, .limited(1 << 30));
    var same: usize = 0;
    var differ: usize = 0;
    var refused: usize = 0;
    var both_refuse: usize = 0;
    var lines = std.mem.splitScalar(u8, cases, '\n');
    while (lines.next()) |l| {
        if (l.len == 0) continue;
        var case_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer case_arena.deinit();
        const a = case_arena.allocator();
        const c = (try std.json.parseFromSliceLeaky(std.json.Value, a, l, .{})).object;
        const id = c.get("id").?.integer;
        var d: hpack.Decoder = .{ .gpa = debug.allocator() };
        defer d.deinit();
        for (c.get("blocks").?.array.items, 0..) |b, n| {
            const block = try corpus.unhex(a, b.object.get("block").?.string);
            var got: Got = .{ .gpa = a };
            const err = d.decode(block, &got, Got.on);
            if (got.oom) return error.OutOfMemory;
            const want = if (b.object.get("headers").? == .array) b.object.get("headers").?.array.items else {
                if (err) |_| {
                    differ += 1;
                    try out.print("DIFFERS  case {d} block {d} ({x}): Go refuses it ({s}), hpack.zig reads", .{ id, n, block, b.object.get("error").?.string });
                    try list(out, got.fields.items);
                } else |_| both_refuse += 1;
                break;
            };
            const fields = try a.alloc([2][]const u8, want.len);
            for (want, fields) |w, *f| f.* = .{
                try corpus.unhex(a, w.array.items[0].string),
                try corpus.unhex(a, w.array.items[1].string),
            };
            err catch |e| {
                if (b.object.get("broken") != null) {
                    refused += 1;
                    try out.print("refused  case {d} block {d} ({x}): {s}; Go reads", .{ id, n, block, @errorName(e) });
                } else {
                    differ += 1;
                    try out.print("DIFFERS  case {d} block {d} ({x}): hpack.zig refuses it ({s}); Go encoded", .{ id, n, block, @errorName(e) });
                }
                try list(out, fields);
                break;
            };
            if (equal(fields, got.fields.items)) {
                same += 1;
                continue;
            }
            differ += 1;
            try out.print("DIFFERS  case {d} block {d} ({x})\n    Go:", .{ id, n, block });
            try list(out, fields);
            try out.print("    hpack.zig:", .{});
            try list(out, got.fields.items);
            break;
        }
    }
    const leaked = debug.deinit() == .leak;
    if (leaked) try out.print("hpack.zig leaked memory (above)\n", .{});
    try out.print("\n{d} blocks decode the same, {d} differ, {d} broken blocks refused by hpack.zig only, {d} by both\n", .{
        same, differ, refused, both_refuse,
    });
    return if (differ == 0 and !leaked) 0 else 1;
}

const Got = struct {
    gpa: std.mem.Allocator,
    fields: std.ArrayList([2][]const u8) = .empty,
    oom: bool = false,

    fn on(g: *Got, name: []const u8, value: []const u8) void {
        g.add(name, value) catch {
            g.oom = true;
        };
    }

    fn add(g: *Got, name: []const u8, value: []const u8) !void {
        try g.fields.append(g.gpa, .{ try g.gpa.dupe(u8, name), try g.gpa.dupe(u8, value) });
    }
};

fn equal(a: []const [2][]const u8, b: []const [2][]const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x[0], y[0]) or !std.mem.eql(u8, x[1], y[1])) return false;
    }
    return true;
}

fn list(out: *Io.Writer, fields: []const [2][]const u8) !void {
    for (fields) |f| try out.print(" \"{f}\": \"{f}\";", .{ std.zig.fmtString(cut(f[0])), std.zig.fmtString(cut(f[1])) });
    try out.writeByte('\n');
}

/// The first 80 bytes, for printing.
fn cut(s: []const u8) []const u8 {
    return s[0..@min(s.len, 80)];
}
