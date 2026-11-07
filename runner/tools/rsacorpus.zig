//! The Zig half of `.github/scripts/rsa-diff.sh`: signs the messages runner/tools/rsadiff wrote
//! with src/github/rsa_sign.zig, from the same keys, and compares the signatures with Go's
//! crypto/rsa SignPKCS1v15, byte for byte.
//!
//!     rsacorpus <cases.jsonl>
//!
//! Prints every case where the signatures differ or rsa_sign.zig fails, with the key (the keys are
//! new each run), then counts.
const std = @import("std");
const rsa_sign = @import("rsa_sign");
const corpus = @import("corpus");

const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 2) {
        std.debug.print("usage: rsacorpus <cases.jsonl>\n", .{});
        return 2;
    }
    var out_buf: [8192]u8 = undefined;
    var out_w: Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    const cases = try Io.Dir.cwd().readFileAlloc(io, args[1], arena, .limited(1 << 30));
    var same: usize = 0;
    var differ: usize = 0;
    var lines = std.mem.splitScalar(u8, cases, '\n');
    while (lines.next()) |l| {
        if (l.len == 0) continue;
        var case_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer case_arena.deinit();
        const a = case_arena.allocator();
        const c = (try std.json.parseFromSliceLeaky(std.json.Value, a, l, .{})).object;
        const n = try corpus.unhex(a, c.get("n").?.string);
        const d = try corpus.unhex(a, c.get("d").?.string);
        const msg = try corpus.unhex(a, c.get("msg").?.string);
        const want = try corpus.unhex(a, c.get("sig").?.string);
        var buf: [512]u8 = undefined;
        if (rsa_sign.signSha256(&buf, n, d, msg)) |sig| {
            if (std.mem.eql(u8, sig, want)) {
                same += 1;
                continue;
            }
            differ += 1;
            try out.print("DIFFERS  case {d}\n    Go:           {x}\n    rsa_sign.zig: {x}\n", .{ c.get("id").?.integer, want, sig });
        } else |e| {
            differ += 1;
            try out.print("DIFFERS  case {d}: rsa_sign.zig fails ({s}), Go signs {x}\n", .{ c.get("id").?.integer, @errorName(e), want });
        }
        try out.print("    n {x}\n    d {x}\n    message {x}\n", .{ n, d, msg });
    }
    try out.print("\n{d} signatures the same, {d} differ\n", .{ same, differ });
    return if (differ == 0) 0 else 1;
}
