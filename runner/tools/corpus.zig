//! What the corpus tools (`tools/*corpus.zig`) share: each is built by its own `.github/scripts`
//! diff script with this as the module `corpus`.
const std = @import("std");

pub fn unhex(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const buf = try a.alloc(u8, s.len / 2);
    return std.fmt.hexToBytes(buf, s);
}

/// The reference implementation's answers, by case id, from its JSON-lines output. Lines that do
/// not start a case's answer are skipped: the reference may print lines of its own (@actions/glob
/// prints `::debug::` lines on stdout).
pub fn loadReference(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !std.AutoHashMapUnmanaged(i64, std.json.ObjectMap) {
    var reference: std.AutoHashMapUnmanaged(i64, std.json.ObjectMap) = .empty;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 28));
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        if (!std.mem.startsWith(u8, l, "{\"id\"")) continue;
        const o = (try std.json.parseFromSliceLeaky(std.json.Value, arena, l, .{})).object;
        try reference.put(arena, o.get("id").?.integer, o);
    }
    return reference;
}
