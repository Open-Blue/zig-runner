//! The native step store's key against the Lean model's (proofs/Runner/Native.lean, P8).
//!
//! `testdata/step_keys.tsv` is written by the model (`keyoracle`, proofs/KeyOracle.lean) and checked
//! to be its output by .github/scripts/key-vectors.sh. Each line is two inputs, whether the model's
//! keys for them are equal, and for each the bytes the store must hash: `key` lines for a step's or
//! a base's key (`Store.KeyHasher.init(tag)`, `core`, then `Backend.keyFor`'s tail), `below` lines
//! for the digest below a base (`Backend.below`). Two checks:
//!
//! - the preimage: a key's bytes as P2's `Store.KeyHasher` writes them, and the digest below a
//!   base's, must be the model's;
//! - the relation: a key function must give equal keys exactly where the model does. This half
//!   holds of any sound spelling (`Native.native_key_iff`), so it applies to the store's key
//!   whatever bytes it hashes.
//!
//! Both go through P2's own code: keys through `Store.KeyHasher` (`init`, `core`, its `bytes`
//! writer) and `Store.stableEnv`, with `keyFor`'s tail, which needs a `Backend`, written out here
//! as `keyFor` writes it; the digest below a base through `Backend.belowKey`, which `below` calls.
//!
//! `layer` lines are small trees (modes, an xattr, a symlink, an opaque directory, a whiteout) and
//! the model's `walkPreimage` of each: the last test makes each tree and checks
//! `Store.treeDigestTo`, the walk `Store.layerDigest` hashes, writes the same bytes.

const std = @import("std");
const Store = @import("Store.zig");
const Backend = @import("Backend.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;

const vectors = @embedFile("testdata/step_keys.tsv");

pub const Binding = struct { name: []const u8, value: []const u8 };
pub const File = struct { path: []const u8, contents: []const u8, mode: u64 };
pub const Bind = @import("sandbox.zig").Spec.Bind;

/// What a key is given (`Backend.keyFor`): the tag (0 a base, 1 a step's exec or a checkout's
/// fetch), the parent's key (for a base, the digest below it), the script, the whole env in the
/// container's order, who runs it, where, and the files kept.
pub const KeyInput = struct {
    tag: u64,
    parent: [32]u8,
    script: []const u8,
    env: []const Binding,
    uid: u64,
    gid: u64,
    workdir: []const u8,
    files: []const File,
};

/// What the digest below a base is of (`Backend.below`).
pub const BelowInput = struct {
    format: []const u8,
    scope: []const u8,
    repository: []const u8,
    fingerprint: []const u8,
    userns: []const u8,
    binds: []const Bind,
    /// P4's Zig cache seeds' layers; which binds are cache volumes is `Bind.volume`.
    seeds: []const []const u8 = &.{},
};

pub const KeyFn = fn (Allocator, KeyInput) anyerror![32]u8;
pub const BelowFn = fn (Allocator, BelowInput) anyerror![32]u8;

/// A key's preimage, through P2's `Store.KeyHasher`: the tag, `core` (parent, script, the env
/// through `Store.stableEnv`), then `Backend.keyFor`'s tail: uid, gid, the working directory, the
/// count of kept files and each one's path, contents and mode.
pub fn keyPreimage(gpa: Allocator, in: KeyInput) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    var h: Store.KeyHasher = .init(@fromBackingInt(@intCast(in.tag)));
    h.bytes = &w.writer;
    // `init` wrote the tag before `bytes` was set.
    var tag: [8]u8 = undefined;
    std.mem.writeInt(u64, &tag, in.tag, .little);
    try w.writer.writeAll(&tag);
    h.core(in.parent, in.script, in.env);
    h.int(in.uid);
    h.int(in.gid);
    h.field(in.workdir);
    h.int(in.files.len);
    for (in.files) |f| {
        h.field(f.path);
        h.field(f.contents);
        h.int(f.mode);
    }
    const key = h.final();
    const bytes = try w.toOwnedSlice();
    // The digest P2 computes is the digest of these bytes.
    var check: [32]u8 = undefined;
    Sha256.hash(bytes, &check, .{});
    std.debug.assert(std.mem.eql(u8, &check, &key));
    return bytes;
}

/// The digest below a base's preimage, through `Backend.belowKey`.
pub fn belowPreimage(gpa: Allocator, in: BelowInput) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    const key = Backend.belowKey(.{
        .format = in.format,
        .scope = in.scope,
        .repository = in.repository,
        .fingerprint = in.fingerprint,
        .userns = in.userns,
        .binds = in.binds,
        .seeds = in.seeds,
    }, &w.writer);
    const bytes = try w.toOwnedSlice();
    var check: [32]u8 = undefined;
    Sha256.hash(bytes, &check, .{});
    std.debug.assert(std.mem.eql(u8, &check, &key));
    return bytes;
}

fn sha(gpa: Allocator, bytes: []u8) [32]u8 {
    defer gpa.free(bytes);
    var key: [32]u8 = undefined;
    Sha256.hash(bytes, &key, .{});
    return key;
}

/// The key P2 gives, through `Store.KeyHasher`.
pub fn storeKey(gpa: Allocator, in: KeyInput) ![32]u8 {
    return sha(gpa, try keyPreimage(gpa, in));
}

/// The digest below a base P2 gives, through `Backend.belowKey`.
pub fn storeBelow(gpa: Allocator, in: BelowInput) ![32]u8 {
    return sha(gpa, try belowPreimage(gpa, in));
}

// --- the vectors ---

const Side = union(enum) {
    key: struct { in: KeyInput, preimage: []const u8 },
    below: struct { in: BelowInput, preimage: []const u8 },
};

const Vector = struct { name: []const u8, equal: bool, a: Side, b: Side };

const Fields = std.mem.SplitIterator(u8, .scalar);

fn unhex(arena: Allocator, text: []const u8) ![]u8 {
    const out = try arena.alloc(u8, text.len / 2);
    return std.fmt.hexToBytes(out, text);
}

fn num(text: []const u8) !u64 {
    return std.fmt.parseInt(u64, text, 10);
}

/// A `-` or a `,`-joined list of `=`-joined parts.
fn items(arena: Allocator, text: []const u8, parts: usize) ![]const []const []const u8 {
    return itemsOf(arena, text, parts, parts);
}

/// `items` whose items have between `min` and `max` parts.
fn itemsOf(arena: Allocator, text: []const u8, min: usize, max: usize) ![]const []const []const u8 {
    var out: std.ArrayList([]const []const u8) = .empty;
    if (std.mem.eql(u8, text, "-")) return out.items;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |item| {
        var ps: std.ArrayList([]const u8) = .empty;
        var p = std.mem.splitScalar(u8, item, '=');
        while (p.next()) |part| try ps.append(arena, part);
        try std.testing.expect(ps.items.len >= min and ps.items.len <= max);
        try out.append(arena, ps.items);
    }
    return out.items;
}

fn keySide(arena: Allocator, it: *Fields) !Side {
    const tag = try num(it.next().?);
    const parent = try unhex(arena, it.next().?);
    try std.testing.expectEqual(32, parent.len);
    const script = try unhex(arena, it.next().?);
    var env: std.ArrayList(Binding) = .empty;
    for (try items(arena, it.next().?, 2)) |p|
        try env.append(arena, .{ .name = try unhex(arena, p[0]), .value = try unhex(arena, p[1]) });
    const uid = try num(it.next().?);
    const gid = try num(it.next().?);
    const workdir = try unhex(arena, it.next().?);
    var files: std.ArrayList(File) = .empty;
    for (try items(arena, it.next().?, 3)) |p| try files.append(arena, .{
        .path = try unhex(arena, p[0]),
        .contents = try unhex(arena, p[1]),
        .mode = try num(p[2]),
    });
    return .{ .key = .{
        .in = .{
            .tag = tag,
            .parent = parent[0..32].*,
            .script = script,
            .env = env.items,
            .uid = uid,
            .gid = gid,
            .workdir = workdir,
            .files = files.items,
        },
        .preimage = try unhex(arena, it.next().?),
    } };
}

fn belowSide(arena: Allocator, it: *Fields) !Side {
    const format = try unhex(arena, it.next().?);
    const scope = try unhex(arena, it.next().?);
    const repository = try unhex(arena, it.next().?);
    const fingerprint = try unhex(arena, it.next().?);
    const userns = try unhex(arena, it.next().?);
    var binds: std.ArrayList(Bind) = .empty;
    // With P4's volumes, a fifth part: whether the bind is a cache volume.
    for (try itemsOf(arena, it.next().?, 4, 5)) |p| try binds.append(arena, .{
        .host = try unhex(arena, p[0]),
        .at = try unhex(arena, p[1]),
        .read_only = std.mem.eql(u8, p[2], "1"),
        .optional = std.mem.eql(u8, p[3], "1"),
        .volume = p.len == 5 and std.mem.eql(u8, p[4], "1"),
    });
    // P4's seeds, only when the job has them.
    var seeds: std.ArrayList([]const u8) = .empty;
    var last = it.next().?;
    if (std.mem.startsWith(u8, last, "seeds=")) {
        for (try items(arena, last["seeds=".len..], 1)) |p| try seeds.append(arena, try unhex(arena, p[0]));
        last = it.next().?;
    }
    return .{ .below = .{
        .in = .{ .format = format, .scope = scope, .repository = repository, .fingerprint = fingerprint, .userns = userns, .binds = binds.items, .seeds = seeds.items },
        .preimage = try unhex(arena, last),
    } };
}

fn parse(arena: Allocator) ![]Vector {
    var out: std.ArrayList(Vector) = .empty;
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var it = std.mem.splitScalar(u8, line, '\t');
        const kind = it.next().?;
        if (std.mem.eql(u8, kind, "layer")) continue;
        const name = it.next().?;
        const rel = it.next().?;
        const key = std.mem.eql(u8, kind, "key");
        try out.append(arena, .{
            .name = name,
            .equal = std.mem.eql(u8, rel, "equal"),
            .a = if (key) try keySide(arena, &it) else try belowSide(arena, &it),
            .b = if (key) try keySide(arena, &it) else try belowSide(arena, &it),
        });
        try std.testing.expect(it.next() == null);
    }
    return out.items;
}

/// Key functions give equal keys exactly for the pairs the model's keys are equal for.
pub fn checkRelation(comptime keyFn: KeyFn, comptime belowFn: BelowFn) !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const gpa = std.testing.allocator;
    for (try parse(arena)) |v| {
        const ka: [32]u8, const kb: [32]u8 = switch (v.a) {
            .key => |a| .{ try keyFn(gpa, a.in), try keyFn(gpa, v.b.key.in) },
            .below => |a| .{ try belowFn(gpa, a.in), try belowFn(gpa, v.b.below.in) },
        };
        std.testing.expectEqual(v.equal, std.mem.eql(u8, &ka, &kb)) catch |err| {
            std.debug.print("key vector {s}: the model says {s}\n", .{
                v.name,
                if (v.equal) "equal" else "differ",
            });
            return err;
        };
    }
}

test "the native key's preimage is the model's" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const vs = try parse(arena);
    try std.testing.expect(vs.len >= 20);
    for (vs) |v| for ([_]Side{ v.a, v.b }) |s| {
        const want: []const u8, const got: []const u8 = switch (s) {
            .key => |k| .{ k.preimage, try keyPreimage(arena, k.in) },
            .below => |b| .{ b.preimage, try belowPreimage(arena, b.in) },
        };
        std.testing.expectEqualSlices(u8, want, got) catch |err| {
            std.debug.print("key vector {s}: the preimage is not the model's\n", .{v.name});
            return err;
        };
    };
}

test "native keys are equal exactly where the model's are" {
    try checkRelation(storeKey, storeBelow);
}

const linux = std.os.linux;

/// Ids outside the job's range: every owner digests as the overflow id, 65534, whoever runs this.
const outside: Store.Ids = .{ .base = std.math.maxInt(u32) - 15, .count = 1 };

/// Makes a vector's tree under `root`; false when it needs what this process may not do (a
/// device, without CAP_MKNOD).
fn makeTree(arena: Allocator, io: std.Io, root: []const u8, entries: []const u8) !bool {
    var made: std.ArrayList(struct { path: [:0]const u8, kind: u8, perm: u32 }) = .empty;
    var rows = std.mem.splitScalar(u8, entries, ';');
    while (rows.next()) |row| {
        var f = std.mem.splitScalar(u8, row, '|');
        const rel = try unhex(arena, f.next().?);
        const kind = f.next().?[0];
        const perm = try std.fmt.parseInt(u32, f.next().?, 10);
        const xattrs = try items(arena, f.next().?, 2);
        const payload = f.next().?;
        const path = try std.fmt.allocPrintSentinel(arena, "{s}{s}", .{ root, rel }, 0);
        switch (kind) {
            'f' => try std.Io.Dir.cwd().writeFile(io, .{
                .sub_path = path,
                .data = try unhex(arena, payload),
            }),
            'd' => if (linux.errno(linux.mkdir(path, 0o700)) != .SUCCESS) return error.Mkdir,
            'l' => {
                const target = try arena.dupeSentinel(u8, try unhex(arena, payload), 0);
                if (linux.errno(linux.symlink(target, path)) != .SUCCESS) return error.Symlink;
            },
            'c' => {
                const colon = std.mem.indexOfScalar(u8, payload, ':').?;
                const major = try std.fmt.parseInt(u32, payload[0..colon], 10);
                const minor = try std.fmt.parseInt(u32, payload[colon + 1 ..], 10);
                const dev = (@as(u32, major) << 8) | minor;
                if (linux.errno(linux.mknod(path, linux.S.IFCHR | perm, dev)) != .SUCCESS)
                    return false;
            },
            else => return error.Kind,
        }
        for (xattrs) |x| {
            const xname = try arena.dupeSentinel(u8, try unhex(arena, x[0]), 0);
            const value = try unhex(arena, x[1]);
            const rc = linux.lsetxattr(path, xname, value.ptr, value.len, 0);
            if (linux.errno(rc) != .SUCCESS) return error.SetXattr;
        }
        try made.append(arena, .{ .path = path, .kind = kind, .perm = perm });
    }
    // The modes last, children first, so a directory's mode cannot stop its children being made.
    var i = made.items.len;
    while (i > 0) {
        i -= 1;
        const m = made.items[i];
        if (m.kind == 'l') continue;
        if (linux.errno(linux.chmod(m.path, m.perm)) != .SUCCESS) return error.Chmod;
    }
    return true;
}

test "native layer digests: P2's walk writes the model's bytes" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var checked: usize = 0;
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    while (lines.next()) |line| {
        var it = std.mem.splitScalar(u8, line, '\t');
        if (!std.mem.eql(u8, it.next() orelse continue, "layer")) continue;
        const name = it.next().?;
        const needs_root = std.mem.eql(u8, it.next().?, "root");
        const entries = it.next().?;
        const want = try unhex(arena, it.next().?);
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
        if (!try makeTree(arena, io, root, entries)) {
            // Only a tree that needs a device may be left out, where devices cannot be made; CI's
            // root pass of the native tests makes it.
            try std.testing.expect(needs_root);
            continue;
        }
        var w: std.Io.Writer.Allocating = .init(arena);
        _ = try Store.treeDigestTo(arena, io, root, .content, outside, &w.writer);
        std.testing.expectEqualSlices(u8, want, w.written()) catch |err| {
            std.debug.print("layer vector {s}: P2's walk is not the model's\n", .{name});
            return err;
        };
        checked += 1;
    }
    try std.testing.expect(checked >= 3);
}
