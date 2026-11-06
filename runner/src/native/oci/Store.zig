//! Where pulled images and provisioned rootfs live, under the native store
//! (`RUNNER_NATIVE_STORE`): content-addressed blobs, each image flattened once, and keyed
//! directories made once and published by rename.
//!
//! "The directory under key K, made by `make` if it is not there yet" (`ensure`), with a lock per
//! key so runners sharing the store never make one twice. Keys are P2's (`Store.KeyHasher`, in
//! `Backend.provision`). A provisioned rootfs lives under `rootfs/`, apart from P2's `layers/`
//! (stacked layers with records, which P2's `collect` evicts): it is a whole tree with the image's
//! ids, flattened because only the lowest lower is idmapped. A job holds what it uses shared on
//! the lock beside it (`hold`, `ensure`) until it ends, and `evict.zig` takes what no job holds.
//!
//!   <store>/oci/blobs/sha256/<hex>     a blob, written only once its digest checked
//!   <store>/oci/refs/<hex>.<platform>  a pinned index's manifest for this platform (`image.zig`)
//!   <store>/oci/images/<hex>/          an image by its manifest's digest: `rootfs/`, `config.json`
//!                                      (`<hex>.rootless/` for a rootless runner's, all its own)
//!   <store>/rootfs/<key>/              a rootfs a native step made (provisioning): `rootfs/`
//!   <dir>.lock, <dir>.size              beside each: held by the jobs using it, its mtime its last
//!                                      use; its bytes when last measured (`evict.zig`)
//!   <store>/oci/blobs.lock             held shared by an unpack, as the blobs have no job to hold

const Store = @This();

const std = @import("std");
const linux = std.os.linux;
const layer = @import("layer.zig");
const LayerStore = @import("../Store.zig");

const Allocator = std.mem.Allocator;

/// The native store's root.
root: []const u8,

pub fn blobPath(s: Store, arena: Allocator, digest: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/oci/blobs/sha256/{s}", .{ s.root, digest["sha256:".len..] });
}

/// A blob being written, in the blobs' directory so it is renamed into place.
pub fn blobTemp(s: Store, arena: Allocator, io: std.Io, digest: []const u8) ![]const u8 {
    var raw: [8]u8 = undefined;
    io.random(&raw);
    return std.fmt.allocPrint(arena, "{s}/oci/blobs/sha256/.tmp-{s}-{s}", .{
        s.root, digest["sha256:".len..], &std.fmt.bytesToHex(raw, .lower),
    });
}

pub fn blobsLock(s: Store, arena: Allocator) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/oci/blobs.lock", .{s.root});
}

pub fn refPath(s: Store, arena: Allocator, digest: []const u8, platform: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/oci/refs/{s}.{s}", .{ s.root, digest["sha256:".len..], platform });
}

/// The store's directories, only the runner's: a pulled rootfs holds the image's set-uid files
/// with the image's owners, root's on a root runner.
pub fn prepare(s: Store, arena: Allocator, io: std.Io) !void {
    for ([_][]const u8{ "oci", "oci/blobs/sha256", "oci/refs", "oci/images", "rootfs" }) |d| {
        const p = try std.fmt.allocPrint(arena, "{s}/{s}", .{ s.root, d });
        try std.Io.Dir.cwd().createDirPath(io, p);
        _ = linux.chmod(try arena.dupeSentinel(u8, p, 0), 0o700);
    }
}

/// How a missing directory is made: `makeFn` fills the empty directory it is given.
pub const Maker = struct {
    ptr: *anyopaque,
    makeFn: *const fn (ptr: *anyopaque, dir: []const u8) anyerror!void,
};

const lock_sh: i32 = 1;
const lock_ex: i32 = 2;

fn flock(f: std.Io.File, how: i32) !void {
    if (linux.errno(linux.flock(f.handle, how)) != .SUCCESS) return error.Locked;
}

/// `dir`'s lock file (`<dir>.lock`), taken as `how` says: only on the file the path names, as an
/// eviction removes it once the directory is gone (`evict.zig`, `Store.lockKey`).
pub fn lockDir(arena: Allocator, io: std.Io, dir: []const u8, how: i32) !std.Io.File {
    const path = try std.fmt.allocPrint(arena, "{s}.lock", .{dir});
    while (true) {
        const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false });
        errdefer f.close(io);
        try flock(f, how);
        if (LayerStore.sameFile(arena, f, path)) return f;
        f.close(io);
    }
}

/// The directory `dir`, held shared for a job, its last use now, until the lock this returns is
/// closed: no eviction takes it meanwhile, on this runner or another. Null when it is not there.
/// Waits out a runner making it and an eviction under way.
pub fn holdDir(arena: Allocator, io: std.Io, dir: []const u8) !?std.Io.File {
    const f = try lockDir(arena, io, dir, lock_sh);
    if (std.Io.Dir.cwd().access(io, dir, .{})) |_| {
        _ = linux.utimensat(f.handle, null, null, 0);
        return f;
    } else |_| {
        f.close(io);
        return null;
    }
}

/// `<store>/<kind>/<key>`, held (`holdDir`), or null when it is not there.
pub fn hold(s: Store, arena: Allocator, io: std.Io, kind: []const u8, key: []const u8) !?std.Io.File {
    return holdDir(arena, io, try std.fmt.allocPrint(arena, "{s}/{s}/{s}", .{ s.root, kind, key }));
}

/// `<store>/<kind>/<key>`, made by `make` when it is not there: in a directory of its own, under
/// the key's lock (so a runner sharing the store waits instead of making it too), then renamed into
/// place. Whether it was made now, and its lock, held for the job as `hold` holds it.
pub fn ensure(
    s: Store,
    arena: Allocator,
    io: std.Io,
    kind: []const u8,
    key: []const u8,
    make: Maker,
) !struct { dir: []const u8, made: bool, lock: std.Io.File } {
    const dir = try std.fmt.allocPrint(arena, "{s}/{s}/{s}", .{ s.root, kind, key });
    const cwd = std.Io.Dir.cwd();
    var made = false;
    while (true) {
        if (try holdDir(arena, io, dir)) |lock| return .{ .dir = dir, .made = made, .lock = lock };
        const lock = try lockDir(arena, io, dir, lock_ex);
        defer lock.close(io);
        if (cwd.access(io, dir, .{})) |_| {} else |_| {
            // A runner that died while making it left this; the lock says no one is making it now.
            const tmp = try std.fmt.allocPrint(arena, "{s}/{s}/.tmp-{s}", .{ s.root, kind, key });
            removeTree(arena, io, tmp);
            try cwd.createDirPath(io, tmp);
            errdefer removeTree(arena, io, tmp);
            try make.makeFn(make.ptr, tmp);
            try syncFilesystem(arena, tmp);
            try cwd.rename(tmp, cwd, dir, io);
            made = true;
        }
        // Then held as any job holds it. Exclusive to shared in one call would give the lock up
        // first all the same, with an eviction free to come between, so it is taken again, and
        // what is there looked at: a tree evicted at once is made again.
    }
}

/// `path`'s filesystem written to disk: for a tree about to be renamed to the name that says it
/// is whole. Nothing checks such a tree when it is found, so a crash must not leave that name on
/// files whose contents were lost, and a step's overlay does not sync them at its unmount
/// (`sandbox.mountVolatile`). The whole filesystem, as these trees are rare and large (a layer's
/// are often small: `Store.writeBack`).
pub fn syncFilesystem(arena: Allocator, path: []const u8) !void {
    const rc = linux.open(try arena.dupeSentinel(u8, path, 0), .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Sync;
    const fd = std.math.cast(linux.fd_t, rc) orelse return error.Sync;
    defer _ = linux.close(fd);
    if (linux.errno(linux.syncfs(fd)) != .SUCCESS) return error.Sync;
}

/// Removes a tree, giving directories their permissions back first when that is what stops it
/// (overlay's work directory, a rootless runner's read-only directories).
pub fn removeTree(arena: Allocator, io: std.Io, path: []const u8) void {
    const parent = std.fs.path.dirname(path) orelse return;
    const name = arena.dupeSentinel(u8, std.fs.path.basename(path), 0) catch return;
    const rc = linux.open(arena.dupeSentinel(u8, parent, 0) catch return, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    defer _ = linux.close(@intCast(rc));
    layer.removeAt(io, @intCast(rc), name) catch
        std.log.warn("native: cannot remove {s}: {s} ({s})", .{
            path, layer.last_fs_error.op, @tagName(layer.last_fs_error.errno),
        });
}

// --- a step's upper flattened onto its lower ---

/// How `flatten` reads an overlay upper: what marks a directory opaque (`trusted.overlay.opaque`
/// on a root runner, `user.overlay.opaque` under `userxattr`), and the shift from the host's ids
/// back to the image's (a root runner's upper belongs to the job's range).
pub const Upper = struct {
    dir: []const u8,
    id_shift: u32 = 0,
};

/// `dest` as `lower` with the step's upper over it, as overlay showed it to the step, flattened:
/// `lower`'s files hard-linked (never written: the rootfs a step leaves is a new tree of links,
/// and a replaced file is a new inode), then the upper's entries moved in, whiteouts removing
/// what they hide, opaque directories emptied first, owners shifted back to the image's ids and
/// overlay's own xattrs dropped. The upper is consumed.
pub fn flatten(arena: Allocator, io: std.Io, lower: []const u8, upper: Upper, dest: []const u8) !void {
    const l = try openDir(arena, lower);
    defer _ = linux.close(l);
    try std.Io.Dir.cwd().createDirPath(io, dest);
    const d = try openDir(arena, dest);
    defer _ = linux.close(d);
    try copyMeta(l, d, 0);
    try cloneTree(io, l, d, 0);
    const u = try openDir(arena, upper.dir);
    defer _ = linux.close(u);
    try mergeTree(io, u, d, upper.id_shift, 0);
    try copyMeta(u, d, upper.id_shift);
}

fn openDir(arena: Allocator, path: []const u8) !linux.fd_t {
    const rc = linux.open(try arena.dupeSentinel(u8, path, 0), .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OpenFailed;
    return @intCast(rc);
}

fn openSub(dir: linux.fd_t, name: [*:0]const u8) !linux.fd_t {
    const rc = linux.openat(dir, name, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OpenFailed;
    return @intCast(rc);
}

const max_depth = 256;

/// Every entry of `src` into `dst`: directories made anew with their metadata, everything else
/// hard-linked (a symlink as itself).
fn cloneTree(io: std.Io, src: linux.fd_t, dst: linux.fd_t, depth: u32) !void {
    if (depth > max_depth) return error.TreeTooDeep;
    var it = (std.Io.Dir{ .handle = src }).iterate();
    var name: [256:0]u8 = undefined;
    while (try it.next(io)) |e| {
        const z = nameZ(&name, e.name) orelse return error.NameTooLong;
        if (e.kind == .directory) {
            if (linux.errno(linux.mkdirat(dst, z, 0o700)) != .SUCCESS) return error.CloneFailed;
            const s = try openSub(src, z);
            defer _ = linux.close(s);
            const t = try openSub(dst, z);
            defer _ = linux.close(t);
            try cloneTree(io, s, t, depth + 1);
            try copyMeta(s, t, 0);
        } else if (linux.errno(linux.linkat(src, z, dst, z, 0)) != .SUCCESS) return error.CloneFailed;
    }
}

/// The upper's entries moved over `dst` (see `flatten`).
fn mergeTree(io: std.Io, src: linux.fd_t, dst: linux.fd_t, shift: u32, depth: u32) !void {
    if (depth > max_depth) return error.TreeTooDeep;
    // Names first: entries are moved out of `src` while it is read.
    var names: std.ArrayList([]const u8) = .empty;
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var it = (std.Io.Dir{ .handle = src }).iterate();
    while (try it.next(io)) |e| try names.append(arena, try arena.dupe(u8, e.name));
    var buf: [256:0]u8 = undefined;
    for (names.items) |n| {
        const z = nameZ(&buf, n) orelse return error.NameTooLong;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(src, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true }, &st)) != .SUCCESS)
            return error.MergeFailed;
        const kind = st.mode & linux.S.IFMT;
        // A whiteout: a character device 0/0.
        if (kind == linux.S.IFCHR and st.rdev_major == 0 and st.rdev_minor == 0) {
            try layer.removeAt(io, dst, z);
            continue;
        }
        try plainEntry(src, z);
        if (kind == linux.S.IFDIR) {
            var dst_st: linux.Statx = undefined;
            const there = linux.errno(linux.statx(dst, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &dst_st)) == .SUCCESS;
            const s = try openSub(src, z);
            defer _ = linux.close(s);
            if (there and dst_st.mode & linux.S.IFMT == linux.S.IFDIR and !opaqueDir(s)) {
                const t = try openSub(dst, z);
                defer _ = linux.close(t);
                try mergeTree(io, s, t, shift, depth + 1);
                try copyMeta(s, t, shift);
                continue;
            }
            // New, opaque, or over something that is not a directory: the upper's, whole.
            if (there) try layer.removeAt(io, dst, z);
            try shiftTree(io, s, shift, depth + 1);
        } else if (shift > 0) {
            try shiftOwner(src, z, shift);
        }
        if (linux.errno(linux.renameat(src, z, dst, z)) != .SUCCESS) return error.MergeFailed;
    }
}

/// Refuses an entry whose content is still in a lower layer: a metacopy file (only its metadata
/// copied up) or a redirect, which overlay makes when mounted with `metacopy=on` or
/// `redirect_dir=on` (off in the kernel's defaults). Flattened, either would lose the content.
fn plainEntry(dir: linux.fd_t, name: [*:0]const u8) !void {
    var path: [64 + 256]u8 = undefined;
    const p = std.fmt.bufPrintSentinel(&path, "/proc/self/fd/{d}/{s}", .{ dir, std.mem.span(name) }, 0) catch
        return error.NameTooLong;
    const names = [_][*:0]const u8{
        "trusted.overlay.metacopy", "user.overlay.metacopy",
        "trusted.overlay.redirect", "user.overlay.redirect",
    };
    var v: [1]u8 = undefined;
    for (names) |n| {
        const rc = linux.lgetxattr(p, n, &v, 0);
        if (linux.errno(rc) == .SUCCESS) return error.OverlayMetadataInUpper;
    }
}

/// Whether overlay marked the directory opaque (what the lower layers had in it is hidden).
fn opaqueDir(fd: linux.fd_t) bool {
    var v: [4]u8 = undefined;
    for ([_][*:0]const u8{ "trusted.overlay.opaque", "user.overlay.opaque" }) |name| {
        const rc = linux.fgetxattr(fd, name, &v, v.len);
        if (linux.errno(rc) == .SUCCESS and rc >= 1 and v[0] == 'y') return true;
    }
    return false;
}

/// A directory moved whole from an upper: its entries' owners shifted, overlay's xattrs dropped
/// and its whiteouts (an opaque directory over one that had files) removed.
fn shiftTree(io: std.Io, dir: linux.fd_t, shift: u32, depth: u32) !void {
    if (depth > max_depth) return error.TreeTooDeep;
    dropOverlayXattrs(dir);
    var names: std.ArrayList([]const u8) = .empty;
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var it = (std.Io.Dir{ .handle = dir }).iterate();
    while (try it.next(io)) |e| try names.append(arena, try arena.dupe(u8, e.name));
    var buf: [256:0]u8 = undefined;
    for (names.items) |n| {
        const z = nameZ(&buf, n) orelse return error.NameTooLong;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(dir, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st)) != .SUCCESS)
            return error.MergeFailed;
        const kind = st.mode & linux.S.IFMT;
        if (kind == linux.S.IFCHR and st.rdev_major == 0 and st.rdev_minor == 0) {
            _ = linux.unlinkat(dir, z, 0);
            continue;
        }
        if (kind == linux.S.IFDIR) {
            const s = try openSub(dir, z);
            defer _ = linux.close(s);
            try shiftTree(io, s, shift, depth + 1);
        }
        if (shift > 0) try shiftOwner(dir, z, shift);
    }
    if (shift > 0) try shiftFd(dir, shift);
}

fn shiftOwner(dir: linux.fd_t, name: [*:0]const u8, shift: u32) !void {
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(dir, name, linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .GID = true, .MODE = true }, &st)) != .SUCCESS)
        return error.MergeFailed;
    if (linux.errno(linux.fchownat(dir, name, unshift(st.uid, shift), unshift(st.gid, shift), linux.AT.SYMLINK_NOFOLLOW)) != .SUCCESS)
        return error.MergeFailed;
    // Changing the owner cleared set-uid and set-gid bits; not on a symlink, which has no mode.
    if (st.mode & linux.S.IFMT != linux.S.IFLNK) _ = linux.fchmodat(dir, name, st.mode & 0o7777);
}

fn shiftFd(fd: linux.fd_t, shift: u32) !void {
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .UID = true, .GID = true, .MODE = true }, &st)) != .SUCCESS)
        return error.MergeFailed;
    if (linux.errno(linux.fchown(fd, unshift(st.uid, shift), unshift(st.gid, shift))) != .SUCCESS)
        return error.MergeFailed;
    _ = linux.fchmod(fd, st.mode & 0o7777);
}

/// An id of the job's range as the image's; one outside it (none should be) as the overflow id.
fn unshift(id: u32, shift: u32) u32 {
    return if (id >= shift and id - shift < 65536) id - shift else 65534;
}

/// `dst`'s mode, owner and times from `src`'s (owners shifted back by `shift`).
fn copyMeta(src: linux.fd_t, dst: linux.fd_t, shift: u32) !void {
    var st: linux.Statx = undefined;
    const mask: linux.STATX = .{ .MODE = true, .UID = true, .GID = true, .MTIME = true, .ATIME = true };
    if (linux.errno(linux.statx(src, "", linux.AT.EMPTY_PATH, mask, &st)) != .SUCCESS) return error.MergeFailed;
    if (linux.geteuid() == 0) {
        const uid = if (shift > 0) unshift(st.uid, shift) else st.uid;
        const gid = if (shift > 0) unshift(st.gid, shift) else st.gid;
        if (linux.errno(linux.fchown(dst, uid, gid)) != .SUCCESS) return error.MergeFailed;
    }
    _ = linux.fchmod(dst, st.mode & 0o7777);
    const times = [2]linux.timespec{
        .{ .sec = @intCast(st.atime.sec), .nsec = @intCast(st.atime.nsec) },
        .{ .sec = @intCast(st.mtime.sec), .nsec = @intCast(st.mtime.nsec) },
    };
    _ = linux.utimensat(dst, null, &times, 0);
}

fn dropOverlayXattrs(fd: linux.fd_t) void {
    var list: [4096]u8 = undefined;
    const rc = linux.flistxattr(fd, &list, list.len);
    if (linux.errno(rc) != .SUCCESS) return;
    var it = std.mem.splitScalar(u8, list[0..rc], 0);
    var name: [256:0]u8 = undefined;
    while (it.next()) |n| {
        if (!std.mem.startsWith(u8, n, "trusted.overlay.") and !std.mem.startsWith(u8, n, "user.overlay."))
            continue;
        const z = nameZ(&name, n) orelse continue;
        _ = linux.fremovexattr(fd, z);
    }
}

fn nameZ(buf: *[256:0]u8, name: []const u8) ?[:0]const u8 {
    if (name.len > 255) return null;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    return buf[0..name.len :0];
}

// --- tests ---

const testing = std.testing;

test "native store: a key's directory is made once and published whole" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const s: Store = .{ .root = try tmp.dir.realPathFileAlloc(testing.io, ".", arena) };
    try s.prepare(arena, testing.io);
    const Ctx = struct {
        calls: u32 = 0,
        fail: bool = false,
        fn make(ptr: *anyopaque, dir: []const u8) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(ptr));
            c.calls += 1;
            var d = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
            defer d.close(testing.io);
            try d.writeFile(testing.io, .{ .sub_path = "x", .data = "made" });
            if (c.fail) return error.TestFailure;
        }
    };
    var ctx: Ctx = .{ .fail = true };
    const maker: Maker = .{ .ptr = &ctx, .makeFn = Ctx.make };
    // A failed make leaves nothing behind, and the next one makes it.
    try testing.expectError(error.TestFailure, s.ensure(arena, testing.io, "rootfs", "k1", maker));
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "rootfs/.tmp-k1", .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "rootfs/k1", .{}));
    ctx.fail = false;
    const first = try s.ensure(arena, testing.io, "rootfs", "k1", maker);
    try testing.expect(first.made);
    const again = try s.ensure(arena, testing.io, "rootfs", "k1", maker);
    try testing.expect(!again.made);
    try testing.expectEqual(@as(u32, 2), ctx.calls);
    try testing.expectEqualStrings(first.dir, again.dir);
    // Both are held, shared, by the jobs that asked: another runner's exclusive lock waits.
    const probe = try std.Io.Dir.cwd().openFile(testing.io, try std.fmt.allocPrint(arena, "{s}.lock", .{first.dir}), .{});
    defer probe.close(testing.io);
    const lock_nb: i32 = 4;
    try testing.expect(linux.errno(linux.flock(probe.handle, lock_ex | lock_nb)) != .SUCCESS);
    first.lock.close(testing.io);
    again.lock.close(testing.io);
    try testing.expect(linux.errno(linux.flock(probe.handle, lock_ex | lock_nb)) == .SUCCESS);
    _ = linux.flock(probe.handle, 8);
    // Held again, its lock's mtime moves; a key with no directory holds nothing.
    const held = (try s.hold(arena, testing.io, "rootfs", "k1")).?;
    held.close(testing.io);
    try testing.expect(try s.hold(arena, testing.io, "rootfs", "none") == null);
}

test "native store: an upper flattened onto its lower, whiteouts and opaque directories as overlay showed them" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = tmp.dir;
    const io = testing.io;
    for ([_][]const u8{ "lower/etc", "lower/opq", "lower/keep", "upper/etc", "upper/opq", "upper/new/sub" }) |p| try d.createDirPath(io, p);
    try d.writeFile(io, .{ .sub_path = "lower/etc/a", .data = "lower a" });
    try d.writeFile(io, .{ .sub_path = "lower/etc/gone", .data = "lower" });
    try d.writeFile(io, .{ .sub_path = "lower/opq/old", .data = "old" });
    try d.writeFile(io, .{ .sub_path = "lower/keep/k", .data = "k" });
    try d.symLink(io, "etc/a", "lower/link", .{});
    try d.writeFile(io, .{ .sub_path = "upper/etc/a", .data = "upper a" });
    try d.writeFile(io, .{ .sub_path = "upper/opq/new", .data = "new" });
    try d.writeFile(io, .{ .sub_path = "upper/new/sub/f", .data = "f" });
    const base = try d.realPathFileAlloc(io, ".", arena);
    // A whiteout needs mknod of 0/0, which an unprivileged user may make since Linux 5.8; an
    // opaque mark needs `user.` xattrs on the test's filesystem. Without them, those parts are
    // left out.
    const wh = try std.fmt.allocPrintSentinel(arena, "{s}/upper/etc/gone", .{base}, 0);
    const have_wh = linux.errno(linux.mknodat(linux.AT.FDCWD, wh, linux.S.IFCHR | 0o600, 0)) == .SUCCESS;
    const opq = try std.fmt.allocPrintSentinel(arena, "{s}/upper/opq", .{base}, 0);
    const have_opq = linux.errno(linux.setxattr(opq, "user.overlay.opaque", "y", 1, 0)) == .SUCCESS;

    const lower = try std.fmt.allocPrint(arena, "{s}/lower", .{base});
    try flatten(arena, io, lower, .{ .dir = try std.fmt.allocPrint(arena, "{s}/upper", .{base}) }, try std.fmt.allocPrint(arena, "{s}/out", .{base}));

    const read = struct {
        fn f(dir: std.Io.Dir, ar: Allocator, p: []const u8) ![]const u8 {
            return dir.readFileAlloc(testing.io, p, ar, .limited(1024));
        }
    }.f;
    try testing.expectEqualStrings("upper a", try read(d, arena, "out/etc/a"));
    try testing.expectEqualStrings("upper a", try read(d, arena, "out/link"));
    try testing.expectEqualStrings("k", try read(d, arena, "out/keep/k"));
    try testing.expectEqualStrings("new", try read(d, arena, "out/opq/new"));
    try testing.expectEqualStrings("f", try read(d, arena, "out/new/sub/f"));
    // The lower is untouched: its file was linked, and replaced by a new inode, not written.
    try testing.expectEqualStrings("lower a", try read(d, arena, "lower/etc/a"));
    try testing.expectEqualStrings("lower", try read(d, arena, "lower/etc/gone"));
    if (have_wh) try testing.expectError(error.FileNotFound, d.access(io, "out/etc/gone", .{}));
    if (have_opq) try testing.expectError(error.FileNotFound, d.access(io, "out/opq/old", .{}));
    const st = try d.statFile(io, "out/keep/k", .{});
    try testing.expectEqual(@as(u64, 2), st.nlink);
}
