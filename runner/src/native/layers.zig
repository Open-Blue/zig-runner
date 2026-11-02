//! Layers by key (docs/native-backend.md, P2 and P7): the narrowest interface the Dockerfile
//! builder needs, "the layer stored under key K, or store this directory under K", over P2's
//! layer store (`Store.zig`). A layer is published there by one rename that never replaces (two
//! builders of one key keep the first), held shared while the job uses it, and evicted least
//! recently used under the store's cap like a step's. Its record is empty: a build layer is never
//! replayed as a step.
//!
//! The keys are the builder's own 64-hex sha256 (`dockerfile.plan`), hashed with the store's
//! format and the job's trust scope (`Backend.scope`) into a P2 key: a job the runner does not
//! vouch for, or a vouched fork's pull request, builds its own layers and never leaves one a
//! trusted job takes, as `Backend.below` keeps a step's layers apart. A build layer's files have
//! the image's ids (`docker_action.unshift`), not a job's range, so one layer serves every slot.

const std = @import("std");
const P2Store = @import("Store.zig");

const Allocator = std.mem.Allocator;

pub const Store = struct {
    /// Where a layer is built before it is published: the job's directory.
    dir: []const u8,
    /// P2's layer store.
    store: P2Store,
    /// The locks of the layers in use, held until the job ends (`Backend.held`).
    held: *std.ArrayList(std.Io.File),
    /// The job's trust scope (`set_up.packageCacheScope`: `repo` or `untrusted`), in every key.
    scope: []const u8,

    fn key(s: Store, hex: []const u8) !P2Store.Key {
        var k: P2Store.Key = undefined;
        if (hex.len != 2 * k.len) return error.BadLayerKey;
        _ = std.fmt.hexToBytes(&k, hex) catch return error.BadLayerKey;
        var h: P2Store.KeyHasher = .plain("a Dockerfile build's layer");
        h.field(P2Store.store_format);
        h.field(s.scope);
        h.field(&k);
        return h.final();
    }

    /// The layer stored under `key`, held for the job, or null.
    pub fn get(s: Store, arena: Allocator, io: std.Io, hex: []const u8) !?[]const u8 {
        const hit = (try s.store.open(arena, io, try s.key(hex))) orelse return null;
        try s.held.append(arena, hit.layer.lock);
        return hit.layer.fs;
    }

    /// A new, empty directory in the job's, to build the layer for `key` in.
    pub fn begin(s: Store, arena: Allocator, io: std.Io, hex: []const u8) ![]const u8 {
        var raw: [8]u8 = undefined;
        io.random(&raw);
        const path = try std.fmt.allocPrint(arena, "{s}/B-{s}-{s}", .{
            s.dir,
            hex[0..16],
            &std.fmt.bytesToHex(raw, .lower),
        });
        try std.Io.Dir.cwd().createDirPath(io, path);
        return path;
    }

    /// Stores the directory `begin` gave under `key`, held for the job, and returns the layer's
    /// path. When another builder stored the key first, its layer is used and this one removed.
    pub fn publish(s: Store, arena: Allocator, io: std.Io, built: []const u8, hex: []const u8) ![]const u8 {
        const k = try s.key(hex);
        // Kind `fetch`: a tree with an empty record, never replayed as a step's (P2 has no
        // `build` kind yet).
        const layer = s.store.publish(arena, io, k, .fetch, built, .{ .log = "", .fc = "" }) catch |e| {
            const first = (try s.store.open(arena, io, k)) orelse return e;
            P2Store.removeTree(arena, io, built);
            try s.held.append(arena, first.layer.lock);
            return first.layer.fs;
        };
        try s.held.append(arena, layer.lock);
        return layer.fs;
    }
};

test "a layer is published once, whole, under its key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try P2Store.prepare(arena, io, root, .{ .check_parents = false });
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    const store: Store = .{ .dir = root, .store = .{ .root = root }, .held = &held, .scope = "repo" };
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
    // Another trust scope's jobs never take it (finding 4 of the trial integration, #275).
    const untrusted: Store = .{ .dir = root, .store = .{ .root = root }, .held = &held, .scope = "untrusted" };
    try std.testing.expect(try untrusted.get(arena, io, key) == null);
}
