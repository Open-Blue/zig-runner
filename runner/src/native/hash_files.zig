//! `hashFiles()` on the native backend: glob.zig's search and GitHub's hash over the job's files as
//! the next step would see them, read from the layers themselves.
//!
//! The job's view is overlay's merge of its layers (the steps' uppers, the Zig cache seeds, the
//! rootfs), which is only a mount inside a step's sandbox. The runner does not mount it: that needs
//! privilege a rootless runner has not got, and a mount of the runner's own for each call would be
//! slower than the walk. `Merged` is the merge done by lookup instead, as `Store.flatten` does it
//! for a whole tree: the topmost layer with an entry decides what it is, a whiteout deletes it, a
//! non-directory hides what is below it, and a directory marked opaque stops the directories
//! below it from adding their entries. Mounts (the cache volumes, an action's runtime) are in no
//! layer, so they are not seen, as Dagger's `rootfs` does not see them either.
//!
//! The layers are the job's to write, so every look at one goes through `sandbox.openIn` with no
//! symlink followed: a link in a layer is read, never taken. The links of the merged view (the
//! job's `docs -> ../docs`, which GitHub's `fs.statSync` follows when it hashes a link that
//! `hashFiles()` found) are resolved here, on the merged paths, with `/` the job's root, so an
//! absolute link names the job's file and not the host's, and `..` is taken on the path already
//! resolved. Nothing the job plants reaches a file outside the layers.

const std = @import("std");
const linux = std.os.linux;
const expr = @import("../expr.zig");
const glob = @import("../glob.zig");
const sandbox = @import("sandbox.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Error = glob.Fs.Error;

/// The layers of the job's overlay, as it would mount them for the next step.
pub const Stack = struct {
    /// Their directories, topmost first: the job's layers newest first, the Zig cache seeds', then
    /// the rootfs (`Backend.execIn`'s `lowers`, in the same order).
    layers: []const []const u8,
    /// Overlay's opaque-directory attribute: `trusted.overlay.opaque`, or `user.overlay.opaque`
    /// under `userxattr` (`Backend.opaqueXattr`).
    opaque_xattr: [:0]const u8,
};

/// `hashFiles(args)` over `stack`: the SHA-256 of the SHA-256 digests of the files the patterns
/// find under `ws`, in GitHub's order; "" when none. As GitHub's script does, a name that is a
/// directory once links are followed is skipped, and a link is hashed as the file it leads to.
pub fn hashFiles(
    arena: Allocator,
    io: std.Io,
    stack: Stack,
    ws: []const u8,
    home: []const u8,
    args: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    var m: Merged = .{ .arena = arena, .io = io, .roots = &.{}, .opaque_xattr = stack.opaque_xattr };
    m.openLayers(stack.layers) catch |e| return failed(&m, e);
    defer m.close();
    return hashAll(&m, arena, ws, home, args) catch |e| failed(&m, e);
}

fn failed(m: *const Merged, e: Error) Allocator.Error!expr.HashFiles.Result {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.FsFailed => .{ .failed = m.why },
    };
}

fn hashAll(
    m: *Merged,
    arena: Allocator,
    ws: []const u8,
    home: []const u8,
    args: []const []const u8,
) Error!expr.HashFiles.Result {
    const files = switch (try glob.find(arena, m.fs(), args, ws, home, &m.why)) {
        .failed => |msg| return .{ .failed = msg },
        .files => |f| f,
    };
    var all = Sha256.init(.{});
    var hashed: usize = 0;
    for (files) |name| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ ws, name });
        const at = (try m.resolve(path, true)) orelse
            return .{ .failed = try std.fmt.allocPrint(arena, "{s}: No such file or directory", .{name}) };
        switch (at.node.kind) {
            .dir => continue,
            .file => {},
            else => return .{ .failed = try std.fmt.allocPrint(arena, "{s}: Not a regular file", .{name}) },
        }
        const sum = try m.digest(at.path, at.node.layer);
        all.update(&sum);
        hashed += 1;
    }
    if (hashed == 0) return .{ .ok = "" };
    return .{ .ok = try arena.dupe(u8, &std.fmt.bytesToHex(all.finalResult(), .lower)) };
}

/// What a path of the merged view is.
const Node = struct {
    kind: enum { missing, whiteout, dir, file, symlink, other },
    /// The topmost layer that has it.
    layer: u32 = 0,
    /// Where a link leads.
    target: []const u8 = "",
};

/// Links followed in one path before it counts as a loop (Linux's `MAXSYMLINKS`).
const max_links = 40;

/// The merged view of a stack of layers. Paths are absolute, `/` the job's root, with no symlink,
/// `.` or `..` in a path that names a real entry (`resolve` makes them so); the root is "".
const Merged = struct {
    arena: Allocator,
    io: std.Io,
    /// The layers' directories, opened, topmost first.
    roots: []linux.fd_t,
    opaque_xattr: [:0]const u8,
    /// What each real path is, and in which layers it is a directory that adds its entries (the
    /// topmost first; null when it is not a directory).
    nodes: std.StringHashMapUnmanaged(Node) = .empty,
    dirs: std.StringHashMapUnmanaged(?[]const u32) = .empty,
    /// What went wrong, for `Error.FsFailed`.
    why: []const u8 = "",

    fn openLayers(m: *Merged, layers: []const []const u8) Error!void {
        const roots = try m.arena.alloc(linux.fd_t, layers.len);
        for (layers, 0..) |path, i| {
            const fd = linux.open(try m.arena.dupeSentinel(u8, path, 0), .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
            }, 0);
            if (linux.errno(fd) != .SUCCESS) {
                for (roots[0..i]) |r| _ = linux.close(r);
                return m.fail("cannot read the job's layer {s}: {t}", .{ path, linux.errno(fd) });
            }
            roots[i] = std.math.cast(linux.fd_t, fd).?;
        }
        m.roots = roots;
    }

    fn close(m: *Merged) void {
        for (m.roots) |r| _ = linux.close(r);
    }

    fn fail(m: *Merged, comptime fmt: []const u8, args: anytype) Error {
        m.why = try std.fmt.allocPrint(m.arena, fmt, args);
        return error.FsFailed;
    }

    fn fs(m: *Merged) glob.Fs {
        return .{ .ptr = m, .vtable = &.{ .stat = statAll, .list = listAll, .realpath = realpathAll } };
    }

    // --- one layer ---

    /// `path` as a layer has it, with nothing followed: what it is, and where a link leads. A
    /// whiteout is overlay's character device 0:0.
    fn lstat(m: *Merged, layer: u32, path: []const u8) Error!Node {
        const rel = try m.arena.dupeSentinel(u8, relative(path), 0);
        const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
            .PATH = true,
            .NOFOLLOW = true,
        }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| {
                if (e == .NOENT or e == .NOTDIR) return .{ .kind = .missing };
                return m.fail("cannot look at {s} in the job's layers: {t}", .{ path, e });
            },
        };
        defer _ = linux.close(fd);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS)
            return m.fail("cannot look at {s} in the job's layers", .{path});
        const kind = st.mode & linux.S.IFMT;
        if (kind == linux.S.IFDIR) return .{ .kind = .dir };
        if (kind == linux.S.IFREG) return .{ .kind = .file };
        if (kind == linux.S.IFCHR and st.rdev_major == 0 and st.rdev_minor == 0)
            return .{ .kind = .whiteout };
        if (kind != linux.S.IFLNK) return .{ .kind = .other };
        var buf: [4096]u8 = undefined;
        const n = linux.readlinkat(fd, "", &buf, buf.len);
        if (linux.errno(n) != .SUCCESS or n == buf.len)
            return m.fail("cannot read the link {s} in the job's layers", .{path});
        return .{ .kind = .symlink, .target = try m.arena.dupe(u8, buf[0..n]) };
    }

    /// Whether the directory is opaque in the layer: what lies below it is hidden.
    fn isOpaque(m: *Merged, layer: u32, path: []const u8) Error!bool {
        const rel = try m.arena.dupeSentinel(u8, relative(path), 0);
        const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
        }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| return m.fail("cannot read {s} in the job's layers: {t}", .{ path, e }),
        };
        defer _ = linux.close(fd);
        var value: [1]u8 = undefined;
        const got = linux.fgetxattr(fd, m.opaque_xattr, &value, value.len);
        return switch (linux.errno(got)) {
            .SUCCESS => got == 1 and value[0] == 'y',
            // A file system without the attribute cannot have marked anything.
            .NODATA, .OPNOTSUPP => false,
            else => |e| m.fail("cannot read {s}'s attributes in the job's layers: {t}", .{ path, e }),
        };
    }

    // --- the merge ---

    /// The layers that add to the directory `dir`, topmost first: those where it is a directory,
    /// down to the first where it is hidden (a whiteout, or a file or link there) or opaque.
    /// Null when it is not a directory.
    fn contribs(m: *Merged, dir: []const u8) Error!?[]const u32 {
        if (m.dirs.get(dir)) |c| return c;
        var found: std.ArrayList(u32) = .empty;
        if (dir.len == 0) {
            var i: u32 = 0;
            while (i < m.roots.len) : (i += 1) try found.append(m.arena, i);
        } else if (try m.contribs(parentOf(dir))) |above| {
            for (above) |layer| {
                switch ((try m.lstat(layer, dir)).kind) {
                    .missing => continue,
                    .dir => {
                        try found.append(m.arena, layer);
                        if (try m.isOpaque(layer, dir)) break;
                    },
                    else => break,
                }
            }
        }
        const result: ?[]const u32 = if (found.items.len == 0) null else found.items;
        try m.dirs.put(m.arena, try m.arena.dupe(u8, dir), result);
        return result;
    }

    /// What the real path is: the topmost layer's entry for it, unless that is a whiteout.
    fn entry(m: *Merged, path: []const u8) Error!Node {
        if (path.len == 0) return .{ .kind = .dir };
        if (m.nodes.get(path)) |n| return n;
        var node: Node = .{ .kind = .missing };
        if (try m.contribs(parentOf(path))) |above| for (above) |layer| {
            const l = try m.lstat(layer, path);
            if (l.kind == .missing) continue;
            if (l.kind != .whiteout) {
                node = l;
                node.layer = layer;
            }
            break;
        };
        try m.nodes.put(m.arena, try m.arena.dupe(u8, path), node);
        return node;
    }

    const Resolved = struct { path: []const u8, node: Node };

    /// `path` with every link taken (the last one only when `follow_last`), as the job's own
    /// root sees it: null when something on the way is missing, is not a directory, or is a
    /// loop. The path it returns is real.
    fn resolve(m: *Merged, path: []const u8, follow_last: bool) Error!?Resolved {
        const arena = m.arena;
        var cur: []const u8 = "";
        var rest = path;
        var links: u32 = 0;
        while (true) {
            rest = std.mem.trimStart(u8, rest, "/");
            if (rest.len == 0) break;
            const slash = std.mem.indexOfScalar(u8, rest, '/');
            const name = rest[0 .. slash orelse rest.len];
            rest = if (slash) |s| rest[s + 1 ..] else "";
            if (std.mem.eql(u8, name, ".")) continue;
            if (std.mem.eql(u8, name, "..")) {
                cur = parentOf(cur);
                continue;
            }
            const next = try std.fmt.allocPrint(arena, "{s}/{s}", .{ cur, name });
            const node = try m.entry(next);
            switch (node.kind) {
                .missing, .whiteout => return null,
                .dir => cur = next,
                .file, .other => {
                    if (rest.len > 0) return null;
                    cur = next;
                },
                .symlink => {
                    if (rest.len == 0 and !follow_last) {
                        cur = next;
                        break;
                    }
                    links += 1;
                    if (links > max_links) return null;
                    if (node.target.len > 0 and node.target[0] == '/') cur = "";
                    rest = try std.fmt.allocPrint(arena, "{s}/{s}", .{ node.target, rest });
                },
            }
        }
        return .{ .path = if (cur.len == 0) "/" else cur, .node = try m.entry(cur) };
    }

    /// The SHA-256 of a regular file, read from the layer that has it: no link on the way is
    /// taken, and what opens is looked at again, so a file that has become something else (a
    /// pipe, which would block) is refused.
    fn digest(m: *Merged, path: []const u8, layer: u32) Error![32]u8 {
        const rel = try m.arena.dupeSentinel(u8, relative(path), 0);
        const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
            .ACCMODE = .RDONLY,
            .NONBLOCK = true,
            .NOCTTY = true,
        }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| return m.fail("{s}: cannot be read: {t}", .{ path, e }),
        };
        defer _ = linux.close(fd);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS or
            st.mode & linux.S.IFMT != linux.S.IFREG)
            return m.fail("{s}: Not a regular file", .{path});
        var h = Sha256.init(.{});
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = linux.read(fd, &buf, buf.len);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |e| return m.fail("{s}: cannot be read: {t}", .{ path, e }),
            }
            if (n == 0) break;
            h.update(buf[0..n]);
        }
        return h.finalResult();
    }

    // --- glob.Fs ---

    fn erased(ptr: *anyopaque) *Merged {
        return @ptrCast(@alignCast(ptr));
    }

    fn statAll(ptr: *anyopaque, arena: Allocator, paths: []const []const u8, follow: bool) Error![]const glob.Kind {
        const m = erased(ptr);
        const out = try arena.alloc(glob.Kind, paths.len);
        for (paths, out) |p, *k| {
            const at = (try m.resolve(p, follow)) orelse {
                k.* = .missing;
                continue;
            };
            k.* = switch (at.node.kind) {
                .dir => .directory,
                .file => .file,
                .symlink => .symlink,
                .missing, .whiteout => .missing,
                .other => .other,
            };
        }
        return out;
    }

    /// The names in each directory: the union of its layers' entries, less those a whiteout hides.
    fn listAll(ptr: *anyopaque, arena: Allocator, dirs: []const []const u8) Error![]const []const []const u8 {
        const m = erased(ptr);
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (dirs, out) |d, *list| list.* = try m.listDir(arena, d);
        return out;
    }

    fn listDir(m: *Merged, arena: Allocator, dir: []const u8) Error![]const []const u8 {
        const at = (try m.resolve(dir, true)) orelse return &.{};
        if (at.node.kind != .dir) return &.{};
        const layers = (try m.contribs(if (std.mem.eql(u8, at.path, "/")) "" else at.path)) orelse return &.{};
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        var out: std.ArrayList([]const u8) = .empty;
        for (layers) |layer| {
            const rel = try arena.dupeSentinel(u8, relative(at.path), 0);
            const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
            }, 0, sandbox.resolve_no_symlinks)) {
                .fd => |f| f,
                .err => |e| return m.fail("cannot read {s} in the job's layers: {t}", .{ at.path, e }),
            };
            defer _ = linux.close(fd);
            const d: std.Io.Dir = .{ .handle = fd };
            var it = d.iterateAssumeFirstIteration();
            while (it.next(m.io) catch |e|
                return m.fail("cannot list {s} in the job's layers: {t}", .{ at.path, e })) |e|
            {
                if (seen.contains(e.name)) continue;
                const name = try arena.dupe(u8, e.name);
                try seen.put(arena, name, {});
                if (e.kind == .character_device or e.kind == .unknown) {
                    const l = try m.lstat(layer, try std.fmt.allocPrint(arena, "{s}/{s}", .{ if (at.path.len == 1) "" else at.path, name }));
                    if (l.kind == .whiteout) continue;
                }
                try out.append(arena, name);
            }
        }
        return out.items;
    }

    /// Each path with every link taken. A path that is not there cannot be listed or followed:
    /// the walk asks only about directories it has just seen.
    fn realpathAll(ptr: *anyopaque, arena: Allocator, paths: []const []const u8) Error![]const []const u8 {
        const m = erased(ptr);
        const out = try arena.alloc([]const u8, paths.len);
        for (paths, out) |p, *r| {
            const at = (try m.resolve(p, true)) orelse return m.fail("{s}: No such file or directory", .{p});
            r.* = at.path;
        }
        return out;
    }
};

/// The path without its leading `/`, for a layer's `openat2`: "." for the root.
fn relative(path: []const u8) []const u8 {
    const t = std.mem.trimStart(u8, path, "/");
    return if (t.len == 0) "." else t;
}

/// The directory a real path is in; the root's is "".
fn parentOf(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..slash];
}

// --- tests ---

const Fixture = struct {
    arena: Allocator,
    tmp: std.testing.TmpDir,
    root: []const u8,

    fn init(arena: Allocator) !Fixture {
        var f: Fixture = .{ .arena = arena, .tmp = std.testing.tmpDir(.{}), .root = "" };
        f.root = try f.tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
        return f;
    }

    fn cleanup(f: *Fixture) void {
        f.tmp.cleanup();
    }

    fn put(f: Fixture, path: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(path)) |d| try f.tmp.dir.createDirPath(std.testing.io, d);
        try f.tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = data });
    }

    fn link(f: Fixture, path: []const u8, target: []const u8) !void {
        if (std.fs.path.dirname(path)) |d| try f.tmp.dir.createDirPath(std.testing.io, d);
        try f.tmp.dir.symLink(std.testing.io, target, path, .{});
    }

    fn abs(f: Fixture, path: []const u8) ![:0]const u8 {
        return std.fmt.allocPrintSentinel(f.arena, "{s}/{s}", .{ f.root, path }, 0);
    }

    /// `hashFiles(args)` with `/ws` as the workspace over the layers, topmost first.
    fn hash(f: Fixture, layers: []const []const u8, args: []const []const u8) !expr.HashFiles.Result {
        const paths = try f.arena.alloc([]const u8, layers.len);
        for (layers, paths) |l, *p| p.* = try std.fmt.allocPrint(f.arena, "{s}/{s}", .{ f.root, l });
        const stack: Stack = .{ .layers = paths, .opaque_xattr = "user.overlay.opaque" };
        return hashFiles(f.arena, std.testing.io, stack, "/ws", "/home/runner", args);
    }
};

/// GitHub's hash of files with these contents, in this order.
fn hashOf(contents: []const []const u8) [64]u8 {
    var all = Sha256.init(.{});
    for (contents) |c| {
        var d: [32]u8 = undefined;
        Sha256.hash(c, &d, .{});
        all.update(&d);
    }
    return std.fmt.bytesToHex(all.finalResult(), .lower);
}

fn expectHash(want: []const u8, got: expr.HashFiles.Result) !void {
    switch (got) {
        .ok => |h| try std.testing.expectEqualStrings(want, h),
        .failed => |why| {
            std.debug.print("hashFiles failed: {s}\n", .{why});
            return error.TestUnexpectedResult;
        },
    }
}

fn expectFailed(part: []const u8, got: expr.HashFiles.Result) !void {
    switch (got) {
        .ok => |h| {
            std.debug.print("hashFiles gave {s}, wanted a failure with {s}\n", .{ h, part });
            return error.TestUnexpectedResult;
        },
        .failed => |why| if (std.mem.indexOf(u8, why, part) == null) {
            std.debug.print("hashFiles failed with {s}, wanted {s}\n", .{ why, part });
            return error.TestUnexpectedResult;
        },
    }
}

test "native hashFiles: layers merge as overlay's do, the topmost entry wins, a whiteout deletes, an opaque directory hides" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // The rootfs, then two layers of steps.
    try f.put("l0/ws/a.txt", "a0");
    try f.put("l0/ws/gone.txt", "gone");
    try f.put("l0/ws/keep.txt", "keep");
    try f.put("l0/ws/dir/old.txt", "old");
    try f.put("l0/ws/dir/sub/deep.txt", "deep");
    try f.put("l1/ws/a.txt", "a1");
    try f.put("l1/ws/dir/new.txt", "new");
    try f.put("l2/ws/later.txt", "later");
    // l1's `dir` is opaque (a step removed it and made it again): l0's entries are hidden. l2
    // deletes `gone.txt`. Where this machine cannot make either, the case is left out.
    const opaque_dir = linux.errno(linux.setxattr(try f.abs("l1/ws/dir"), "user.overlay.opaque", "y", 1, 0)) == .SUCCESS;
    const whiteout = linux.errno(linux.mknod(try f.abs("l2/ws/gone.txt"), linux.S.IFCHR | 0o000, 0)) == .SUCCESS;
    const layers = [_][]const u8{ "l2", "l1", "l0" };

    // In GitHub's order: a.txt, dir/..., gone.txt, keep.txt, later.txt.
    var want: std.ArrayList([]const u8) = .empty;
    try want.append(f.arena, "a1");
    try want.append(f.arena, "new");
    if (!opaque_dir) try want.appendSlice(f.arena, &.{ "old", "deep" });
    if (!whiteout) try want.append(f.arena, "gone");
    try want.appendSlice(f.arena, &.{ "keep", "later" });
    try expectHash(&hashOf(want.items), try f.hash(&layers, &.{"**"}));
    // One layer sees only itself: the others are not what it is merged with.
    try expectHash(&hashOf(&.{ "a0", "old", "deep", "gone", "keep" }), try f.hash(&.{"l0"}, &.{"**"}));
    // Nothing found is "".
    try expectHash("", try f.hash(&layers, &.{"**/nothing.txt"}));
    // A pattern with `..` is refused, as GitHub refuses it.
    try expectFailed("Relative pathing", try f.hash(&layers, &.{"dir/../a.txt"}));
}

test "native hashFiles: a link is hashed as what it leads to inside the job's tree" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/etc/secret", "S");
    try f.put("l0/ws/real.txt", "R");
    try f.put("l0/ws/sub/inner.txt", "I");
    try f.link("l0/ws/link.txt", "real.txt");
    try f.link("l0/ws/abs.txt", "/etc/secret");
    try f.link("l0/ws/up.txt", "sub/../real.txt");
    try f.link("l0/ws/dl", "sub");
    try f.link("l0/ws/sub/back", "../real.txt");
    try f.link("l0/ws/sub/to-ws", "..");
    // The links are in a layer under the one that has the files: the merged view takes them.
    try f.put("l1/ws/top.txt", "T");
    const layers = [_][]const u8{ "l1", "l0" };

    // Links are not followed: each is a name found, hashed as its target (a directory skipped, as
    // GitHub skips what `statSync` calls one): abs.txt, dl, link.txt, real.txt, sub/back,
    // sub/inner.txt, sub/to-ws, top.txt, up.txt.
    try expectHash(&hashOf(&.{ "S", "R", "R", "R", "I", "T", "R" }), try f.hash(&layers, &.{"**"}));
    // Followed: `dl` is walked (its files are named by the path through it), `sub/to-ws` is the
    // workspace again and is not.
    try expectHash(
        &hashOf(&.{ "S", "R", "I", "R", "R", "R", "I", "T", "R" }),
        try f.hash(&layers, &.{ "--follow-symbolic-links", "**" }),
    );
}

test "native hashFiles: nothing a link names outside the layers is read" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // A file of the host's, at a path the job's tree does not have.
    try f.put("host/secret.txt", "HOST");
    try f.put("l0/ws/ok.txt", "ok");
    const abs_target = try f.abs("host/secret.txt");
    // Through `..`, as many as it takes to reach the host's root if the job's were it.
    const dots = "../../../../../../../../../../../../../../../../../../../../../../../../../../../../";
    const rel_target = try std.fmt.allocPrint(f.arena, "{s}{s}", .{ dots, std.mem.trimStart(u8, abs_target, "/") });
    try f.link("l0/ws/abs-link", abs_target);
    try f.link("l0/ws/rel-link", rel_target);
    try f.link("l0/ws/dir-link", try f.abs("host"));
    const layers = [_][]const u8{"l0"};
    // Not followed, the links are names, and their targets are not there: hashFiles fails on
    // them, as it fails on a broken link on GitHub, and the host's file is not hashed.
    try expectFailed("abs-link", try f.hash(&layers, &.{"abs-link"}));
    try expectFailed("rel-link", try f.hash(&layers, &.{"rel-link"}));
    // Followed, they lead to nothing, so there is nothing to find or to walk.
    try expectHash(&hashOf(&.{"ok"}), try f.hash(&layers, &.{ "--follow-symbolic-links", "**" }));
    try expectHash("", try f.hash(&layers, &.{ "--follow-symbolic-links", "dir-link/**" }));
    // A loop of links is no file either.
    try f.link("l0/ws/loop-a", "loop-b");
    try f.link("l0/ws/loop-b", "loop-a");
    try expectFailed("loop-a", try f.hash(&layers, &.{"loop-a"}));
}

test "native hashFiles: a directory in a layer hides a link below it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/etc/x", "from-etc");
    try f.link("l0/ws/d", "/etc");
    try f.put("l1/ws/d/x", "upper");
    try expectHash(&hashOf(&.{"upper"}), try f.hash(&.{ "l1", "l0" }, &.{"d/**"}));
    // Below the link only, `d` is the link: not followed, hashed as what it leads to (a directory,
    // so skipped); followed, /etc's files.
    try expectHash("", try f.hash(&.{"l0"}, &.{"d"}));
    try expectHash(&hashOf(&.{"from-etc"}), try f.hash(&.{"l0"}, &.{ "--follow-symbolic-links", "d/**" }));
}

test "native hashFiles: a pipe is refused, not waited for" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/ok.txt", "ok");
    if (linux.errno(linux.mknod(try f.abs("l0/ws/pipe"), linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
        return error.SkipZigTest;
    try expectFailed("pipe", try f.hash(&.{"l0"}, &.{"pipe"}));
}
