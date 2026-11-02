//! Layers by key (docs/native-backend.md, P2 and P7): the narrowest interface the Dockerfile
//! builder needs from P2's layer store, "the layer stored under key K, or store this directory
//! under K". This stand-in keeps each layer as a directory `<dir>/<key>` and publishes one by
//! renaming a directory made beside it, so a reader never sees half a layer and two builders of
//! one key keep the first. P2's store (flock per key, LRU eviction, deterministic digests)
//! replaces it behind the same three calls.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Store = struct {
    dir: []const u8,

    /// The layer stored under `key`, or null.
    pub fn get(s: Store, arena: Allocator, io: std.Io, key: []const u8) !?[]const u8 {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ s.dir, key });
        std.Io.Dir.accessAbsolute(io, path, .{}) catch return null;
        return path;
    }

    /// A new, empty directory beside the layers, to build the layer for `key` in.
    pub fn begin(s: Store, arena: Allocator, io: std.Io, key: []const u8) ![]const u8 {
        var raw: [8]u8 = undefined;
        io.random(&raw);
        const path = try std.fmt.allocPrint(arena, "{s}/.new-{s}-{s}", .{
            s.dir,
            key[0..16],
            &std.fmt.bytesToHex(raw, .lower),
        });
        try std.Io.Dir.cwd().createDirPath(io, path);
        return path;
    }

    /// Stores the directory `begin` gave under `key`, and returns the layer's path. When another
    /// builder stored the key first, its layer is kept and this one removed.
    pub fn publish(s: Store, arena: Allocator, io: std.Io, built: []const u8, key: []const u8) ![]const u8 {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ s.dir, key });
        const cwd = std.Io.Dir.cwd();
        cwd.rename(built, cwd, path, io) catch |e| switch (e) {
            error.DirNotEmpty => cwd.deleteTree(io, built) catch {},
            else => return e,
        };
        return path;
    }
};

test "a layer is published once, whole, under its key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store: Store = .{ .dir = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try std.testing.expect(try store.get(arena, io, key) == null);
    const first = try store.begin(arena, io, key);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{first}), .data = "one" });
    const second = try store.begin(arena, io, key);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{second}), .data = "two" });
    const p = try store.publish(arena, io, first, key);
    try std.testing.expectEqualStrings(p, (try store.get(arena, io, key)).?);
    _ = try store.publish(arena, io, second, key);
    const got = try std.Io.Dir.cwd().readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}/f", .{p}), arena, .limited(16));
    try std.testing.expectEqualStrings("one", got);
}
