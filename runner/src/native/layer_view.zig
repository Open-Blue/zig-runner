//! A read-only view of overlay layers as their merge shows them, by lookup: what a `COPY` reads
//! when its source is a stage's layers, an image's rootfs or a build context spread over a job's
//! layers, and what it consults of the filesystem it copies into (a destination directory that is
//! there already keeps its mode and owner; one that is a link leads somewhere).
//!
//! The merge is overlay's, done without mounting (a mount needs privilege a rootless runner has
//! not got, and a view of a few files is cheaper than a mount): the topmost layer with an entry
//! decides what it is, a whiteout (a character device 0:0) deletes it, a non-directory hides
//! what is below it, and a directory marked opaque stops the directories below it from adding
//! their entries (`Store.flatten`'s rules, hash_files.zig's). Nothing is followed on the host: a
//! symlink in a layer is read, never taken, and paths are resolved here, with `/` the root of the
//! view, so an absolute link names the view's file and never the host's.

const std = @import("std");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;

/// Links followed in one path before it counts as a loop (Linux's `MAXSYMLINKS`).
const max_links = 40;

pub const Kind = enum { file, symlink, dir, other };

/// A path of the view. A directory is the layers' directories that add entries under it (topmost
/// first); anything else is one entry in one layer.
pub const Entry = struct {
    kind: Kind,
    /// The directory's, topmost first; a non-directory's parent directory alone.
    dirs: []const linux.fd_t,
    name: [:0]const u8,
    uid: u32,
    gid: u32,
    /// The permission bits, with the set-id and sticky bits.
    mode: u32,
    size: u64,
    /// Where it is in the view: relative to the root, with no link in it ("" for the root).
    rel: []const u8 = "",

    /// The directory the entry lives in, to open it by `name` (`std.Io.Dir.copyFile` and others).
    pub fn parent(e: Entry) std.Io.Dir {
        std.debug.assert(e.kind != .dir);
        return .{ .handle = e.dirs[0] };
    }
};

/// What a view leaves out, as `.dockerignore` leaves files out of a build context: asked about
/// each path of the view (`rel`, and whether it is a directory) as it is looked up, and a path
/// it excludes is not there.
pub const Filter = struct {
    ptr: *anyopaque,
    excludedFn: *const fn (ptr: *anyopaque, path: []const u8, is_dir: bool) bool,
};

pub const View = struct {
    arena: Allocator,
    io: std.Io,
    /// Every descriptor the view opened, closed with it.
    fds: std.ArrayList(linux.fd_t) = .empty,
    /// The view's root: the layers' directories at the view's base.
    top: Entry,
    /// Overlay's opaque-directory attribute: `trusted.overlay.opaque`, or `user.overlay.opaque`
    /// under `userxattr` (`Backend.opaqueXattr`).
    opaque_xattr: [:0]const u8,
    /// Set by whoever reads the view after it is open (the Dockerfile itself is read through
    /// the view whole, before `.dockerignore` is known).
    filter: ?Filter = null,

    /// The view of `layers` (topmost first) at `base` in each (a path with no `.` or `..`; "" for
    /// the layer itself). A layer that has no `base`, or has it as anything but a directory, adds
    /// nothing. Null when none has: there is no such directory.
    pub fn open(
        arena: Allocator,
        io: std.Io,
        layers: []const []const u8,
        base: []const u8,
        opaque_xattr: [:0]const u8,
    ) !?*View {
        const v = try arena.create(View);
        v.* = .{ .arena = arena, .io = io, .top = undefined, .opaque_xattr = opaque_xattr };
        errdefer v.close();
        var roots: std.ArrayList(linux.fd_t) = .empty;
        for (layers) |l| {
            var fd = openAt(linux.AT.FDCWD, try arena.dupeSentinel(u8, l, 0)) orelse return error.LayerNotReadable;
            try v.fds.append(arena, fd);
            var parts = std.mem.tokenizeScalar(u8, base, '/');
            while (parts.next()) |part| {
                fd = openAt(fd, try arena.dupeSentinel(u8, part, 0)) orelse break;
                try v.fds.append(arena, fd);
            } else try roots.append(arena, fd);
        }
        if (roots.items.len == 0) return null;
        v.top = .{ .kind = .dir, .dirs = roots.items, .name = "", .uid = 0, .gid = 0, .mode = 0o755, .size = 0 };
        return v;
    }

    pub fn close(v: *View) void {
        for (v.fds.items) |fd| _ = linux.close(fd);
        v.fds.clearRetainingCapacity();
    }

    /// `name` in the directory `dir`, as the merge shows it; null when it is not there.
    pub fn child(v: *View, dir: Entry, name: []const u8) !?Entry {
        std.debug.assert(dir.kind == .dir);
        const z = try v.arena.dupeSentinel(u8, name, 0);
        var found: ?Entry = null;
        var dirs: std.ArrayList(linux.fd_t) = .empty;
        for (dir.dirs) |d| {
            const st = statAt(d, z) orelse continue;
            const kind = kindOf(st);
            // A whiteout deletes what is below it; so does anything that is not a directory.
            if (kind == .other and isWhiteout(st)) break;
            if (kind != .dir) {
                if (found != null) break;
                var e = entryOf(st, kind, try v.arena.dupe(linux.fd_t, &.{d}), z);
                e.rel = try joinRel(v.arena, dir.rel, name);
                if (v.filter) |f| if (f.excludedFn(f.ptr, e.rel, false)) return null;
                return e;
            }
            const fd = openAt(d, z) orelse return error.LayerNotReadable;
            try v.fds.append(v.arena, fd);
            try dirs.append(v.arena, fd);
            if (found == null) found = entryOf(st, .dir, &.{}, z);
            if (try v.isOpaque(fd)) break;
        }
        var e = found orelse return null;
        e.dirs = dirs.items;
        e.rel = try joinRel(v.arena, dir.rel, name);
        if (v.filter) |f| if (f.excludedFn(f.ptr, e.rel, true)) return null;
        return e;
    }

    /// The names in the directory `dir`, sorted, without what a whiteout or a non-directory hides.
    pub fn names(v: *View, dir: Entry) ![]const []const u8 {
        std.debug.assert(dir.kind == .dir);
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        var out: std.ArrayList([]const u8) = .empty;
        for (dir.dirs) |d| {
            const d_dir: std.Io.Dir = .{ .handle = d };
            // From the start: the descriptor is the view's, read before.
            var it = d_dir.iterate();
            while (try it.next(v.io)) |e| {
                const name = try v.arena.dupe(u8, e.name);
                if ((try seen.getOrPut(v.arena, name)).found_existing) continue;
                // Whether the merge shows it: a whiteout on top deletes the entry.
                if ((try v.child(dir, name)) != null) try out.append(v.arena, name);
            }
        }
        std.mem.sortUnstable([]const u8, out.items, {}, lessThan);
        return out.items;
    }

    /// `path` (relative to the view's root, or absolute: `/` is the root either way) as the
    /// merge shows it. Links in the way are followed, inside the view, and the last one too when
    /// `follow_last`. Null when there is nothing there, or what is on the way is not a directory.
    pub fn resolve(v: *View, path: []const u8, follow_last: bool) !?Entry {
        var stack: std.ArrayList(Entry) = .empty;
        try stack.append(v.arena, v.top);
        var pending: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitBackwardsScalar(u8, path, '/');
        while (it.next()) |p| try pending.append(v.arena, p);
        var links: u32 = 0;
        while (pending.pop()) |part| {
            if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
            if (std.mem.eql(u8, part, "..")) {
                if (stack.items.len > 1) _ = stack.pop();
                continue;
            }
            const cur = stack.items[stack.items.len - 1];
            const e = (try v.child(cur, part)) orelse return null;
            const last = pendingEmpty(pending.items);
            if (e.kind == .symlink and (!last or follow_last)) {
                links += 1;
                if (links > max_links) return error.TooManyLinks;
                const target = try v.readLink(e);
                if (target.len > 0 and target[0] == '/') stack.shrinkRetainingCapacity(1);
                var parts = std.mem.splitBackwardsScalar(u8, target, '/');
                while (parts.next()) |p| try pending.append(v.arena, p);
                continue;
            }
            if (!last and e.kind != .dir) return null;
            try stack.append(v.arena, e);
        }
        return stack.items[stack.items.len - 1];
    }

    /// Where the link `e` leads, as written.
    pub fn readLink(v: *View, e: Entry) ![]const u8 {
        std.debug.assert(e.kind == .symlink);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const rc = linux.readlinkat(e.dirs[0], e.name, &buf, buf.len);
        if (linux.errno(rc) != .SUCCESS) return error.LayerNotReadable;
        return v.arena.dupe(u8, buf[0..rc]);
    }

    fn isOpaque(v: *View, fd: linux.fd_t) !bool {
        var value: [4]u8 = undefined;
        const path = try std.fmt.allocPrintSentinel(v.arena, "/proc/self/fd/{d}/.", .{fd}, 0);
        const got = linux.lgetxattr(path, v.opaque_xattr, &value, value.len);
        return linux.errno(got) == .SUCCESS and got == 1 and value[0] == 'y';
    }
};

fn joinRel(arena: Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    if (dir.len == 0) return arena.dupe(u8, name);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
}

/// Whether no part of the path is left to take (empty parts, from `//`, count for nothing).
fn pendingEmpty(pending: []const []const u8) bool {
    for (pending) |p| if (p.len > 0) return false;
    return true;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

const stat_mask: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .SIZE = true };

fn statAt(fd: linux.fd_t, name: [:0]const u8) ?linux.Statx {
    var st: linux.Statx = undefined;
    const rc = linux.statx(fd, name, linux.AT.SYMLINK_NOFOLLOW, stat_mask, &st);
    return if (linux.errno(rc) == .SUCCESS) st else null;
}

fn kindOf(st: linux.Statx) Kind {
    return switch (st.mode & linux.S.IFMT) {
        linux.S.IFREG => .file,
        linux.S.IFLNK => .symlink,
        linux.S.IFDIR => .dir,
        else => .other,
    };
}

/// Overlay's whiteout: the character device 0:0.
fn isWhiteout(st: linux.Statx) bool {
    return st.mode & linux.S.IFMT == linux.S.IFCHR and st.rdev_major == 0 and st.rdev_minor == 0;
}

fn entryOf(st: linux.Statx, kind: Kind, dirs: []const linux.fd_t, name: [:0]const u8) Entry {
    return .{
        .kind = kind,
        .dirs = dirs,
        .name = name,
        .uid = st.uid,
        .gid = st.gid,
        .mode = st.mode & 0o7777,
        .size = st.size,
    };
}

fn openAt(parent: linux.fd_t, name: [*:0]const u8) ?linux.fd_t {
    const rc = linux.openat(parent, name, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    return if (linux.errno(rc) == .SUCCESS) std.math.cast(linux.fd_t, rc) else null;
}

// --- tests ---

fn put(tmp: *std.testing.TmpDir, path: []const u8, data: []const u8) !void {
    const io = std.testing.io;
    if (std.fs.path.dirname(path)) |d| try tmp.dir.createDirPath(io, d);
    try tmp.dir.writeFile(io, .{ .sub_path = path, .data = data });
}

test "a view merges by lookup: the top layer decides, a whiteout deletes, links stay inside" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Below: /etc/a, /etc/b, /usr/bin/tool, /bin -> usr/bin, /abs -> /etc.
    try put(&tmp, "low/etc/a", "low a");
    try put(&tmp, "low/etc/b", "low b");
    try put(&tmp, "low/usr/bin/tool", "tool");
    try tmp.dir.symLink(io, "usr/bin", "low/bin", .{});
    try tmp.dir.symLink(io, "/etc", "low/abs", .{});
    // Above: /etc/a replaced, /etc/b deleted by a whiteout, /etc/c added.
    try put(&tmp, "high/etc/a", "high a");
    try put(&tmp, "high/etc/c", "high c");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const wh = try std.fmt.allocPrintSentinel(arena, "{s}/high/etc/b", .{root}, 0);
    const mk = linux.mknod(wh, linux.S.IFCHR, 0);
    if (linux.errno(mk) != .SUCCESS) return error.SkipZigTest;
    const layers = [_][]const u8{
        try std.fmt.allocPrint(arena, "{s}/high", .{root}),
        try std.fmt.allocPrint(arena, "{s}/low", .{root}),
    };
    const v = (try View.open(arena, io, &layers, "", "user.overlay.opaque")).?;
    defer v.close();

    const etc = (try v.resolve("etc", true)).?;
    const names = try v.names(etc);
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("a", names[0]);
    try std.testing.expectEqualStrings("c", names[1]);
    try std.testing.expect((try v.resolve("/etc/b", true)) == null);
    const a_file = (try v.resolve("etc/a", true)).?;
    try std.testing.expectEqual(@as(u64, 6), a_file.size);
    // A link on the way, and one at the end (followed or not); an absolute one is the view's.
    try std.testing.expect((try v.resolve("bin/tool", true)).?.kind == .file);
    try std.testing.expect((try v.resolve("bin", false)).?.kind == .symlink);
    try std.testing.expect((try v.resolve("bin", true)).?.kind == .dir);
    try std.testing.expect((try v.resolve("abs/c", true)).?.kind == .file);
    try std.testing.expect((try v.resolve("../../etc/a", true)).?.kind == .file);
    try std.testing.expect((try v.resolve("etc/a/x", true)) == null);
}

test "a view at a base in the layers: only what is under it, whichever layers have it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(&tmp, "l0/ws/ctx/Dockerfile", "FROM a");
    try put(&tmp, "l1/ws/ctx/run.sh", "x");
    try put(&tmp, "l1/other", "x");
    try put(&tmp, "l2/nothing", "x");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var layers: [3][]const u8 = undefined;
    for (&layers, 0..) |*l, i| l.* = try std.fmt.allocPrint(arena, "{s}/l{d}", .{ root, i });
    const v = (try View.open(arena, io, &layers, "ws/ctx", "user.overlay.opaque")).?;
    defer v.close();
    const names = try v.names(v.top);
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("Dockerfile", names[0]);
    try std.testing.expect((try v.resolve("other", true)) == null);
    try std.testing.expect((try View.open(arena, io, &layers, "nowhere", "user.overlay.opaque")) == null);
}
