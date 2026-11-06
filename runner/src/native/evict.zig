//! Eviction of what sits beside the layers (docs/native-backend.md, "Eviction"): the cache
//! volumes under `volumes/`, which `Store.collect` runs after each job, under its `gc.lock`, so
//! one runner at a time does this and another finding it busy goes on.
//!
//! Each entry is a directory with a lock file beside it (`<dir>.lock`), which a job holds shared
//! until it ends. The file's mtime is the entry's last use, and `<dir>.size` its bytes when last
//! measured. An entry goes only under its lock taken exclusively and non-blocking, and only by
//! one rename to `.dead-<n>` beside the others, synced before anything of it is deleted: so a job
//! finds it whole or not at all, and a crash at any point leaves it where it was or under a dead
//! name. The lock file goes after the rename, so whoever takes a lock checks it is the file the
//! path names (`Store.sameFile`), as `Store.lockKey` does for `keys/`.
//!
//! Nothing here blocks a job. A job waits on an entry's lock only for the moment of the rename,
//! and on nothing else: the walks and the deletes hold no entry's lock. All of it runs at a job's
//! end, within a budget of time (`Limits.budget_ms`): what a deadline cut short stays under its
//! dead name, the next job's collect goes on with it, and nothing more is evicted until it is
//! gone. So what eviction has freed is known before it frees more.
//!
//! What an honest job loses is a rebuild, and not on a loop: an entry used in the last day
//! (`Limits.idle_s`) stays though the store is over its cap, so a store whose working set is over
//! the cap goes over it rather than throw away what the next job needs. What stops that growing
//! is the disk: with less than `Limits.min_free_pct` of it free, entries go until that much is
//! free, whatever the caps say, sparing only those used in the last hour (`Limits.recent_s`).

const std = @import("std");
const linux = std.os.linux;
const Store = @import("Store.zig");

const Allocator = std.mem.Allocator;

pub const default_volumes_max_bytes: u64 = 16 * 1024 * 1024 * 1024;
pub const default_min_free_pct: u8 = 10;

/// What `run` keeps to (`Store.limits`). A cap of 0 is no cap, as it is for the disk's floor:
/// such a store keeps what it has.
pub const Limits = struct {
    /// Past this many bytes of cache volumes, the least recently used go
    /// (`RUNNER_NATIVE_VOLUMES_MAX_MB`).
    volumes_max_bytes: u64 = default_volumes_max_bytes,
    /// With less than this percentage of the store's filesystem free, entries go whatever the
    /// caps say (`RUNNER_NATIVE_MIN_FREE_PCT`).
    min_free_pct: u8 = default_min_free_pct,
    /// Tests: an entry used this recently stays under a cap.
    idle_s: i64 = 24 * 60 * 60,
    /// Tests: an entry used this recently stays even when the disk is short.
    recent_s: i64 = 60 * 60,
    /// How long one job's end may spend deleting. Each entry costs a measure on top (`measureOne`).
    budget_ms: i64 = 1500,
    /// How often a volume in use is walked again: its size only steers eviction, and a walk is
    /// what the eviction must not cost more than. Tests: 0.
    remeasure_s: i64 = 60 * 60,
};

/// How long a walk of an entry may take: the first, of one never measured, and any later one. A
/// walk cut short records what it saw: too small, and only ever too small.
const measure_new_ms = 10_000;
const measure_again_ms = 1000;
/// What a walk may keep in memory of the directories' paths.
const measure_max_stack = 16 * 1024 * 1024;
/// The most entries of an area looked at, so a store's size bounds the pass's memory.
const max_entries = 16 * 1024;
/// How deep `volumes/` goes above a volume: `<owner>/<repository>/<scope>/<name>/<image>/runner`.
const max_key_depth = 7;
/// The name a step user's volume adds below its key (`dagger.runner_user`): the only volume that
/// can be inside another's directory (`volumes.plan`).
const nested = "runner";

const lock_ex: i32 = 2;
const lock_nb: i32 = 4;

fn flock(f: std.Io.File, how: i32) bool {
    return linux.errno(linux.flock(f.handle, how)) == .SUCCESS;
}

const Entry = struct {
    /// The directory's path. A `.lock` and a `.size` are beside it.
    dir: []const u8,
    /// Its last use, in seconds: the lock file's mtime.
    used_s: i64,
    /// When it was last measured, 0 when it never was: the size file's mtime.
    measured_s: i64 = 0,
    /// Its bytes when last measured.
    bytes: u64 = 0,
    /// A dead runner's private copy (`volumes.open`), which only takes room.
    private: bool = false,
};

/// One pass, under `gc.lock`.
pub fn run(s: Store, io: std.Io) void {
    var pass: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer pass.deinit();
    const arena = pass.allocator();
    const lim = s.limits;
    var budget: Budget = .init(io, lim.budget_ms);
    // What a deadline left first: nothing more goes until what already went is gone.
    if (!removeDead(arena, io, s.root, "volumes", &budget)) return;
    const entries = listVolumes(arena, io, s.root) catch return;
    measureOne(arena, io, entries, lim.remeasure_s);
    var evicted = capped(arena, io, s.root, entries, lim.volumes_max_bytes, lim);
    if (shortBy(arena, s.root, lim.min_free_pct)) |short| {
        var left = short;
        std.mem.sort(Entry, entries, {}, olderFirst);
        for (entries) |e| {
            if (left == 0) break;
            if (e.private or lim.recent_s > now(io) - e.used_s) continue;
            if (!evictEntry(arena, io, s.root, e)) continue;
            evicted = true;
            left -|= e.bytes;
        }
    }
    if (evicted) _ = removeDead(arena, io, s.root, "volumes", &budget);
}

fn now(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toSeconds();
}

/// A deadline in the awake clock, cheap enough to ask at every entry.
const Budget = struct {
    io: std.Io,
    deadline_ms: i64,

    fn init(io: std.Io, ms: i64) Budget {
        return .{ .io = io, .deadline_ms = std.Io.Clock.awake.now(io).toMilliseconds() + ms };
    }

    fn spent(b: Budget) bool {
        return std.Io.Clock.awake.now(b.io).toMilliseconds() >= b.deadline_ms;
    }
};

fn olderFirst(_: void, a: Entry, b: Entry) bool {
    return a.used_s < b.used_s;
}

/// Volumes evicted, the longest unused first, until the area is under `max`; whether any was. A
/// dead runner's private copy goes first, cap or no cap.
fn capped(arena: Allocator, io: std.Io, root: []const u8, entries: []Entry, max: u64, lim: Limits) bool {
    var total: u64 = 0;
    for (entries) |e| total += e.bytes;
    var evicted = false;
    for (entries) |e| if (e.private and evictEntry(arena, io, root, e)) {
        total -|= e.bytes;
        evicted = true;
    };
    if (max == 0 or total <= max) return evicted;
    std.mem.sort(Entry, entries, {}, olderFirst);
    const t = now(io);
    for (entries) |e| {
        if (total <= max) break;
        if (e.private or t - e.used_s < lim.idle_s) continue;
        if (!evictEntry(arena, io, root, e)) continue;
        total -|= e.bytes;
        evicted = true;
    }
    if (total > max) std.log.info("native: the volumes hold {d} MiB, over their cap of {d} MiB: " ++
        "what is left is in use or was used today", .{ total >> 20, max >> 20 });
    return evicted;
}

/// How many bytes the store's filesystem is short of `pct` percent free; null when it is not, or
/// when no one can tell.
fn shortBy(arena: Allocator, root: []const u8, pct: u8) ?u64 {
    if (pct == 0) return null;
    const z = arena.dupeSentinel(u8, root, 0) catch return null;
    var st: Statfs = undefined;
    if (linux.errno(linux.syscall2(.statfs, @intFromPtr(z.ptr), @intFromPtr(&st))) != .SUCCESS)
        return null;
    const want = st.blocks / 100 * pct;
    if (st.bavail >= want) return null;
    return (want - st.bavail) *| (std.math.cast(u64, st.frsize) orelse return null);
}

/// `struct statfs`, on the 64-bit machines the runner has.
const Statfs = extern struct {
    type: i64,
    bsize: i64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32,
    namelen: i64,
    frsize: i64,
    flags: i64,
    spare: [4]i64,
};

/// The volumes, stray lock files removed on the way.
fn listVolumes(arena: Allocator, io: std.Io, root: []const u8) ![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    try walkKeys(arena, io, try std.fmt.allocPrint(arena, "{s}/volumes", .{root}), &out, 0);
    return out.items;
}

/// The volumes under `dir`, a directory of a key's upper parts. A directory with a lock beside it
/// is a volume, a job's own content, and is not looked into, but for the one volume that can be
/// inside another. One without is a part of a key.
fn walkKeys(arena: Allocator, io: std.Io, dir: []const u8, out: *std.ArrayList(Entry), depth: u32) !void {
    if (depth > max_key_depth) return;
    var d = std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true, .follow_symlinks = false }) catch return;
    defer d.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (std.mem.startsWith(u8, e.name, ".dead-")) continue;
        try names.append(arena, try arena.dupe(u8, e.name));
    }
    for (names.items) |n| {
        const full = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, n });
        if (std.mem.endsWith(u8, n, ".lock")) {
            const v = full[0 .. full.len - ".lock".len];
            if (!isDir(arena, v)) dropStray(arena, io, v);
            continue;
        }
        if (std.mem.endsWith(u8, n, ".size")) {
            // A crash between the two removals of `forget`.
            if (!isDir(arena, full[0 .. full.len - ".size".len])) std.Io.Dir.cwd().deleteFile(io, full) catch {};
            continue;
        }
        if (!isDir(arena, full)) continue;
        const lock = try std.fmt.allocPrint(arena, "{s}.lock", .{full});
        if (!isFile(arena, lock)) {
            try walkKeys(arena, io, full, out, depth + 1);
            continue;
        }
        if (out.items.len >= max_entries) return;
        try out.append(arena, try entryOf(arena, io, full, std.mem.indexOf(u8, n, ".private-") != null));
        const inner = try std.fmt.allocPrint(arena, "{s}/{s}", .{ full, nested });
        if (isDir(arena, inner) and isFile(arena, try std.fmt.allocPrint(arena, "{s}.lock", .{inner})))
            try out.append(arena, try entryOf(arena, io, inner, false));
    }
}

fn entryOf(arena: Allocator, io: std.Io, dir: []const u8, private: bool) !Entry {
    var e: Entry = .{
        .dir = dir,
        .used_s = mtime(arena, try std.fmt.allocPrint(arena, "{s}.lock", .{dir})) orelse 0,
        .private = private,
    };
    const size = try std.fmt.allocPrint(arena, "{s}.size", .{dir});
    e.measured_s = mtime(arena, size) orelse 0;
    if (e.measured_s == 0) return e;
    const text = std.Io.Dir.cwd().readFileAlloc(io, size, arena, .limited(32)) catch return e;
    e.bytes = std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10) catch 0;
    return e;
}

fn lstat(arena: Allocator, p: []const u8, st: *linux.Statx) bool {
    const z = arena.dupeSentinel(u8, p, 0) catch return false;
    const mask: linux.STATX = .{ .TYPE = true, .MTIME = true };
    return linux.errno(linux.statx(linux.AT.FDCWD, z, linux.AT.SYMLINK_NOFOLLOW, mask, st)) == .SUCCESS;
}

fn isDir(arena: Allocator, p: []const u8) bool {
    var st: linux.Statx = undefined;
    return lstat(arena, p, &st) and st.mode & linux.S.IFMT == linux.S.IFDIR;
}

fn isFile(arena: Allocator, p: []const u8) bool {
    var st: linux.Statx = undefined;
    return lstat(arena, p, &st) and st.mode & linux.S.IFMT == linux.S.IFREG;
}

fn mtime(arena: Allocator, p: []const u8) ?i64 {
    var st: linux.Statx = undefined;
    return if (lstat(arena, p, &st)) st.mtime.sec else null;
}

/// A lock file whose directory is gone, removed so `volumes/` does not keep every key it ever
/// had: under the lock, as a job that opened it just before checks (`volumes.open`).
fn dropStray(arena: Allocator, io: std.Io, dir: []const u8) void {
    const lock = lockOf(arena, io, dir) orelse return;
    defer lock.close(io);
    if (!flock(lock, lock_ex | lock_nb)) return;
    const path = std.fmt.allocPrint(arena, "{s}.lock", .{dir}) catch return;
    if (!Store.sameFile(arena, lock, path) or isDir(arena, dir)) return;
    forget(arena, io, dir);
}

/// The lock file and the size beside `dir` removed, its lock held.
fn forget(arena: Allocator, io: std.Io, dir: []const u8) void {
    for ([_][]const u8{ "lock", "size" }) |what| {
        const p = std.fmt.allocPrint(arena, "{s}.{s}", .{ dir, what }) catch return;
        std.Io.Dir.cwd().deleteFile(io, p) catch {};
    }
}

fn lockOf(arena: Allocator, io: std.Io, dir: []const u8) ?std.Io.File {
    const path = std.fmt.allocPrint(arena, "{s}.lock", .{dir}) catch return null;
    return std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch null;
}

/// Evicts one entry no job holds: under its lock, with the lock of the volume inside it if it can
/// have one, renamed away and the rename synced. False when a job holds it, or it went already.
/// The tree itself is `removeDead`'s, after the locks are let go: a job starting now has to wait
/// for the rename, not for the delete.
fn evictEntry(arena: Allocator, io: std.Io, root: []const u8, e: Entry) bool {
    const cwd = std.Io.Dir.cwd();
    const lock = lockOf(arena, io, e.dir) orelse return false;
    defer lock.close(io);
    const lock_path = std.fmt.allocPrint(arena, "{s}.lock", .{e.dir}) catch return false;
    if (!flock(lock, lock_ex | lock_nb) or !Store.sameFile(arena, lock, lock_path)) return false;
    // The one that may be inside it, whose lock would go with the rename. Taken even when no such
    // volume is there, so that one starting now waits, then finds the path gone and starts over.
    const inner_path = std.fmt.allocPrint(arena, "{s}/{s}.lock", .{ e.dir, nested }) catch return false;
    const inner = Store.lockBeside(arena, io, inner_path) catch inner: {
        // A step may have left the volume's root read-only; no job is using it now.
        _ = linux.chmod(arena.dupeSentinel(u8, e.dir, 0) catch return false, 0o700);
        break :inner Store.lockBeside(arena, io, inner_path) catch return false;
    };
    defer inner.close(io);
    if (!flock(inner, lock_ex | lock_nb) or !Store.sameFile(arena, inner, inner_path)) return false;
    const dead = deadName(arena, io, root) catch return false;
    cwd.rename(e.dir, cwd, dead, io) catch return false;
    syncDirOf(arena, e.dir);
    syncDirOf(arena, dead);
    forget(arena, io, e.dir);
    return true;
}

fn deadName(arena: Allocator, io: std.Io, root: []const u8) ![]const u8 {
    var raw: [8]u8 = undefined;
    io.random(&raw);
    return std.fmt.allocPrint(arena, "{s}/volumes/.dead-{s}", .{ root, &std.fmt.bytesToHex(raw, .lower) });
}

/// The directory `path` is in, synced: a rename that a crash could undo must be on disk before
/// the tree it moved loses a file, or the old name would come back on a tree half gone.
fn syncDirOf(arena: Allocator, path: []const u8) void {
    const parent = std.fs.path.dirname(path) orelse return;
    const z = arena.dupeSentinel(u8, parent, 0) catch return;
    const rc = linux.open(z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd = std.math.cast(linux.fd_t, rc) orelse return;
    defer _ = linux.close(fd);
    if (linux.errno(linux.fsync(fd)) != .SUCCESS)
        std.log.warn("native: cannot sync {s}", .{parent});
}

/// Every `.dead-` entry of the area removed, as far as the budget goes; whether all are gone.
fn removeDead(arena: Allocator, io: std.Io, root: []const u8, name: []const u8, budget: *Budget) bool {
    const dir_path = std.fmt.allocPrint(arena, "{s}/{s}", .{ root, name }) catch return false;
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return true;
    defer dir.close(io);
    var dead: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (!std.mem.startsWith(u8, e.name, ".dead-")) continue;
        dead.append(arena, arena.dupe(u8, e.name) catch return false) catch return false;
    }
    // The runner that renamed these may have died before it synced the rename (`evictEntry`).
    if (dead.items.len > 0) syncDirOf(arena, std.fmt.allocPrint(arena, "{s}/{s}", .{ dir_path, dead.items[0] }) catch return false);
    for (dead.items) |n| {
        const p = std.fmt.allocPrint(arena, "{s}/{s}", .{ dir_path, n }) catch return false;
        if (!removeSome(p, io, budget.*)) return false;
    }
    return true;
}

/// As much of the tree `path` removed as `budget` allows, a directory's entries before it, through
/// no symlink and to any depth, holding in memory one path. Whether it is gone: otherwise what is
/// left stays under its dead name, and a later call goes on where this stopped.
fn removeSome(path: []const u8, io: std.Io, budget: Budget) bool {
    var keep: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer keep.deinit();
    var step: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer step.deinit();
    const a = step.allocator();
    const k = keep.allocator();
    const z = k.dupeSentinel(u8, path, 0) catch return false;
    _ = linux.chmod(z, 0o700);
    const root = Store.openRoot(k, path) catch return false;
    defer _ = linux.close(root);
    var rel: std.ArrayList(u8) = .empty;
    var name: [256:0]u8 = undefined;
    while (true) {
        _ = step.reset(.retain_capacity);
        const fd = if (rel.items.len == 0) root else Store.openRel(a, root, rel.items) catch return false;
        const down = emptyOut(io, fd, &name, budget) catch |e| {
            if (fd != root) _ = linux.close(fd);
            if (e != error.Spent) std.log.warn("native: cannot remove {s}/{s}: {t}", .{ path, rel.items, e });
            return false;
        };
        if (fd != root) _ = linux.close(fd);
        if (down) |n| {
            if (rel.items.len > 0) rel.append(k, '/') catch return false;
            rel.appendSlice(k, n) catch return false;
            continue;
        }
        // Empty now: gone from its parent, and on with what the parent has left.
        if (rel.items.len == 0) break;
        const cut = std.mem.lastIndexOfScalar(u8, rel.items, '/');
        const parent = if (cut) |c| Store.openRel(a, root, rel.items[0..c]) catch return false else root;
        defer if (parent != root) {
            _ = linux.close(parent);
        };
        const base = a.dupeSentinel(u8, rel.items[if (cut) |c| c + 1 else 0..], 0) catch return false;
        if (linux.errno(linux.unlinkat(parent, base, linux.AT.REMOVEDIR)) != .SUCCESS) {
            std.log.warn("native: cannot remove {s}/{s}", .{ path, rel.items });
            return false;
        }
        rel.shrinkRetainingCapacity(cut orelse 0);
    }
    const up = Store.openRoot(a, std.fs.path.dirname(path) orelse return false) catch return false;
    defer _ = linux.close(up);
    const base = a.dupeSentinel(u8, std.fs.path.basename(path), 0) catch return false;
    return linux.errno(linux.unlinkat(up, base, linux.AT.REMOVEDIR)) == .SUCCESS;
}

/// The directory `fd`'s files unlinked and its empty directories removed, until the first
/// directory with something in it, whose name is returned to go into (`name` holds it); null when
/// nothing is left. `error.Spent` when the budget ran out.
fn emptyOut(io: std.Io, fd: linux.fd_t, name: *[256:0]u8, budget: Budget) !?[]const u8 {
    if (budget.spent()) return error.Spent;
    var it = (std.Io.Dir{ .handle = fd }).iterate();
    var seen: u32 = 0;
    var failed = false;
    while (try it.next(io)) |e| {
        seen +%= 1;
        if (seen % 64 == 0 and budget.spent()) return error.Spent;
        if (e.name.len > 255) return error.NameTooLong;
        @memcpy(name[0..e.name.len], e.name);
        name[e.name.len] = 0;
        const z = name[0..e.name.len :0];
        switch (linux.errno(linux.unlinkat(fd, z, 0))) {
            .SUCCESS, .NOENT => continue,
            .ISDIR, .PERM => {},
            else => {
                failed = true;
                continue;
            },
        }
        switch (linux.errno(linux.unlinkat(fd, z, linux.AT.REMOVEDIR))) {
            .SUCCESS, .NOENT => continue,
            .NOTEMPTY, .ACCES, .PERM => {
                // Read-only as a step left it, or a rootless runner's.
                _ = linux.fchmodat(fd, z, 0o700);
                return name[0..e.name.len];
            },
            else => failed = true,
        }
    }
    if (failed) return error.NotRemoved;
    return null;
}

/// One entry measured, the one that has waited longest: never measured first, then one used
/// since it was measured over `remeasure_s` ago.
fn measureOne(arena: Allocator, io: std.Io, entries: []Entry, remeasure: i64) void {
    var pick: ?*Entry = null;
    const t = now(io);
    for (entries) |*e| {
        if (e.private) continue;
        const stale = e.measured_s == 0 or (e.used_s >= e.measured_s and t - e.measured_s >= remeasure);
        if (!stale) continue;
        if (pick == null or e.measured_s < pick.?.measured_s) pick = e;
    }
    const e = pick orelse return;
    const seen = usage(io, e.dir, .init(io, if (e.measured_s == 0) measure_new_ms else measure_again_ms));
    // Cut short, it is too small: what it saw before, if more, is the better guess.
    e.bytes = if (seen.whole) seen.bytes else @max(seen.bytes, e.bytes);
    e.measured_s = t;
    const p = std.fmt.allocPrint(arena, "{s}.size", .{e.dir}) catch return;
    const text = std.fmt.allocPrint(arena, "{d}\n", .{e.bytes}) catch return;
    // Not synced: lost, it is measured again. Never trusted further than that.
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = text }) catch {};
}

/// The bytes on disk of the tree `dir`, a file with several links shared among them, through no
/// symlink and to any depth, in a tree jobs may be writing: what vanishes is passed over. Not whole
/// when `budget` or `measure_max_stack` cut it short.
fn usage(io: std.Io, dir: []const u8, budget: Budget) struct { bytes: u64, whole: bool } {
    var pass: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer pass.deinit();
    const a = pass.allocator();
    const root = Store.openRoot(a, dir) catch return .{ .bytes = 0, .whole = false };
    defer _ = linux.close(root);
    var stack: std.ArrayList([]const u8) = .empty;
    stack.append(a, "") catch return .{ .bytes = 0, .whole = false };
    var held: usize = 0;
    var total: u64 = 0;
    var seen: u32 = 0;
    var name: [256:0]u8 = undefined;
    while (stack.pop()) |rel| {
        const fd = if (rel.len == 0) root else Store.openRel(a, root, rel) catch continue;
        defer if (fd != root) {
            _ = linux.close(fd);
        };
        var it = (std.Io.Dir{ .handle = fd }).iterate();
        while (it.next(io) catch null) |e| {
            seen +%= 1;
            if (seen % 64 == 0 and budget.spent()) return .{ .bytes = total, .whole = false };
            if (e.name.len > 255) continue;
            @memcpy(name[0..e.name.len], e.name);
            name[e.name.len] = 0;
            const z = name[0..e.name.len :0];
            var st: linux.Statx = undefined;
            const mask: linux.STATX = .{ .TYPE = true, .BLOCKS = true, .NLINK = true };
            if (linux.errno(linux.statx(fd, z, linux.AT.SYMLINK_NOFOLLOW, mask, &st)) != .SUCCESS) continue;
            const is_dir = st.mode & linux.S.IFMT == linux.S.IFDIR;
            total += st.blocks * 512 / (if (is_dir) 1 else @max(st.nlink, 1));
            if (!is_dir) continue;
            const sub = (if (rel.len == 0)
                a.dupe(u8, e.name)
            else
                std.fmt.allocPrint(a, "{s}/{s}", .{ rel, e.name })) catch return .{ .bytes = total, .whole = false };
            held += sub.len + @sizeOf([]const u8);
            if (held > measure_max_stack) return .{ .bytes = total, .whole = false };
            stack.append(a, sub) catch return .{ .bytes = total, .whole = false };
        }
    }
    return .{ .bytes = total, .whole = true };
}

// --- tests ---

const testing = std.testing;
const volumes = @import("volumes.zig");

const Fixture = struct {
    a: std.heap.ArenaAllocator,
    tmp: testing.TmpDir,
    s: Store,

    fn init() !*Fixture {
        const f = try testing.allocator.create(Fixture);
        f.a = .init(testing.allocator);
        f.tmp = testing.tmpDir(.{});
        const root = try f.tmp.dir.realPathFileAlloc(testing.io, ".", f.a.allocator());
        f.s = .{ .root = root };
        return f;
    }

    fn deinit(f: *Fixture) void {
        f.tmp.cleanup();
        f.a.deinit();
        testing.allocator.destroy(f);
    }

    fn arena(f: *Fixture) Allocator {
        return f.a.allocator();
    }

    /// A volume with `bytes` in a file, measured, last used `days` ago, let go.
    fn volume(f: *Fixture, name: []const u8, bytes: usize, days: i64) ![]const u8 {
        const v = try f.hold(name);
        defer v.release(testing.io);
        try f.fill(v.dir, bytes);
        try f.age(v.dir, days);
        return v.dir;
    }

    fn hold(f: *Fixture, name: []const u8) !volumes.Volume {
        const key = [_][]const u8{ "o", "r", "repo", name };
        return volumes.open(f.arena(), testing.io, f.s.root, &key, .shared, null);
    }

    fn fill(f: *Fixture, dir: []const u8, bytes: usize) !void {
        const arena_ = f.arena();
        const data = try arena_.alloc(u8, bytes);
        @memset(data, 'v');
        const cwd = std.Io.Dir.cwd();
        try cwd.writeFile(testing.io, .{ .sub_path = try std.fmt.allocPrint(arena_, "{s}/f", .{dir}), .data = data });
        try cwd.writeFile(testing.io, .{
            .sub_path = try std.fmt.allocPrint(arena_, "{s}.size", .{dir}),
            .data = try std.fmt.allocPrint(arena_, "{d}\n", .{bytes}),
        });
    }

    fn age(f: *Fixture, dir: []const u8, days: i64) !void {
        const p = try std.fmt.allocPrintSentinel(f.arena(), "{s}.lock", .{dir}, 0);
        const sec = now(testing.io) - days * 24 * 60 * 60;
        const t = [2]linux.timespec{ .{ .sec = sec, .nsec = 0 }, .{ .sec = sec, .nsec = 0 } };
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.utimensat(linux.AT.FDCWD, p, &t, 0)));
    }

    fn there(f: *Fixture, dir: []const u8) bool {
        return isDir(f.arena(), dir);
    }

    fn deadLeft(f: *Fixture) !usize {
        var d = try f.tmp.dir.openDir(testing.io, "volumes", .{ .iterate = true });
        defer d.close(testing.io);
        var n: usize = 0;
        var it = d.iterate();
        while (try it.next(testing.io)) |e| n += @intFromBool(std.mem.startsWith(u8, e.name, ".dead-"));
        return n;
    }
};

test "native eviction: the volumes unused longest go, down to the cap, and leave nothing" {
    const f = try Fixture.init();
    defer f.deinit();
    const oldest = try f.volume("oldest", 6000, 30);
    const old = try f.volume("old", 6000, 20);
    const newer = try f.volume("newer", 6000, 10);
    f.s.limits = .{ .volumes_max_bytes = 13_000, .min_free_pct = 0 };
    run(f.s, testing.io);
    try testing.expect(!f.there(oldest));
    try testing.expect(f.there(old) and f.there(newer));
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
    // Its lock and size went with it: a key no job uses again leaves no trace.
    try testing.expect(mtime(f.arena(), try std.fmt.allocPrint(f.arena(), "{s}.lock", .{oldest})) == null);
    try testing.expect(mtime(f.arena(), try std.fmt.allocPrint(f.arena(), "{s}.size", .{oldest})) == null);
}

test "native eviction: a volume a job holds stays, and one used today stays over the cap" {
    const f = try Fixture.init();
    defer f.deinit();
    const held = try f.hold("held");
    defer held.release(testing.io);
    try f.fill(held.dir, 6000);
    try f.age(held.dir, 30);
    const today = try f.volume("today", 6000, 0);
    const stale = try f.volume("stale", 6000, 20);
    f.s.limits = .{ .volumes_max_bytes = 1000, .min_free_pct = 0 };
    run(f.s, testing.io);
    try testing.expect(f.there(held.dir));
    try testing.expect(f.there(today));
    try testing.expect(!f.there(stale));
    // A job's own file is where it left it.
    _ = try std.Io.Dir.cwd().statFile(testing.io, try std.fmt.allocPrint(f.arena(), "{s}/f", .{held.dir}), .{});
}

test "native eviction: a volume evicted is a new, empty one to the next job" {
    const f = try Fixture.init();
    defer f.deinit();
    const dir = try f.volume("npm", 6000, 30);
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0 };
    run(f.s, testing.io);
    try testing.expect(!f.there(dir));
    const again = try f.hold("npm");
    defer again.release(testing.io);
    try testing.expectEqualStrings(dir, again.dir);
    try testing.expect(f.there(dir));
    var d = try std.Io.Dir.cwd().openDir(testing.io, dir, .{ .iterate = true });
    defer d.close(testing.io);
    var it = d.iterate();
    try testing.expect(try it.next(testing.io) == null);
}

test "native eviction: the disk's floor spares only what was used in the last hour" {
    const f = try Fixture.init();
    defer f.deinit();
    const today = try f.volume("today", 6000, 0);
    const yesterday = try f.volume("yesterday", 6000, 1);
    // No cap, and a floor no disk meets: only the disk asks for room.
    f.s.limits = .{ .volumes_max_bytes = 0, .min_free_pct = 100 };
    run(f.s, testing.io);
    try testing.expect(f.there(today));
    try testing.expect(!f.there(yesterday));
}

test "native eviction: a dead runner's private copy goes, a running job's stays" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const key = [_][]const u8{ "o", "r", "repo", "npm" };
    const first = try volumes.open(arena, io, f.s.root, &key, .locked, null);
    defer first.release(io);
    const live = try volumes.open(arena, io, f.s.root, &key, .private, null);
    defer live.release(io);
    try testing.expect(live.private);
    // Its runner gone: the copy and its lock are there, and no one holds the lock.
    const died = try volumes.open(arena, io, f.s.root, &key, .private, null);
    died.lock.close(io);
    f.s.limits = .{ .volumes_max_bytes = 0, .min_free_pct = 0 };
    run(f.s, io);
    try testing.expect(f.there(live.dir) and f.there(first.dir));
    try testing.expect(!f.there(died.dir));
}

test "native eviction: a lock file with no volume goes, and the walk never enters a volume" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const v = try f.volume("npm", 10, 0);
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = "volumes/o/r/repo/gone.lock", .data = "" });
    // A job's files that look like entries: not the store's.
    const inner = try std.fmt.allocPrint(arena, "{s}/x", .{v});
    try std.Io.Dir.cwd().createDirPath(testing.io, inner);
    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/x.lock", .{v}), .data = "" });
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0 };
    run(f.s, testing.io);
    try testing.expectError(error.FileNotFound, f.tmp.dir.access(testing.io, "volumes/o/r/repo/gone.lock", .{}));
    try testing.expect(f.there(inner));
}

test "native eviction: a volume inside another goes with it only when neither is in use" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const outer = try f.volume("npm", 6000, 30);
    const key = [_][]const u8{ "o", "r", "repo", "npm", "runner" };
    const v = try volumes.open(arena, io, f.s.root, &key, .shared, null);
    try f.fill(v.dir, 10);
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0 };
    run(f.s, io);
    try testing.expect(f.there(outer) and f.there(v.dir));
    v.release(io);
    try f.age(v.dir, 30);
    run(f.s, io);
    try testing.expect(!f.there(v.dir));
}

test "native eviction: a deadline leaves a dead tree for the next pass, and no more goes meanwhile" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const dir = try f.volume("big", 10, 30);
    for (0..300) |i| {
        const d = try std.fmt.allocPrint(arena, "{s}/d{d}", .{ dir, i });
        try std.Io.Dir.cwd().createDirPath(io, d);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{d}), .data = "x" });
    }
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0, .budget_ms = -1 };
    run(f.s, io);
    try testing.expect(!f.there(dir));
    try testing.expectEqual(@as(usize, 1), try f.deadLeft());
    const next = try f.volume("next", 6000, 20);
    run(f.s, io);
    try testing.expect(f.there(next));
    f.s.limits.budget_ms = 60_000;
    run(f.s, io);
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
}

test "native eviction: removal gets past a tree a step left unreadable, and through a symlink never" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const outside = try std.fmt.allocPrint(arena, "{s}/outside", .{f.s.root});
    try std.Io.Dir.cwd().createDirPath(io, outside);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/kept", .{outside}), .data = "k" });
    const dir = try std.fmt.allocPrint(arena, "{s}/tree", .{f.s.root});
    const deep = try std.fmt.allocPrint(arena, "{s}/a/b", .{dir});
    try std.Io.Dir.cwd().createDirPath(io, deep);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{deep}), .data = "x" });
    try std.Io.Dir.cwd().symLink(io, outside, try std.fmt.allocPrint(arena, "{s}/link", .{deep}), .{});
    for ([_][]const u8{ deep, try std.fmt.allocPrint(arena, "{s}/a", .{dir}) }) |d|
        _ = linux.chmod(try arena.dupeSentinel(u8, d, 0), 0);
    try testing.expect(removeSome(dir, io, .init(io, 60_000)));
    try testing.expect(!f.there(dir));
    _ = try std.Io.Dir.cwd().statFile(io, try std.fmt.allocPrint(arena, "{s}/kept", .{outside}), .{});
}

test "native eviction: a volume is measured when new, its size kept beside it" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const v = try f.hold("npm");
    defer v.release(io);
    const data = try arena.alloc(u8, 64 * 1024);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{v.dir}), .data = data });
    f.s.limits = .{ .volumes_max_bytes = 0, .min_free_pct = 0 };
    run(f.s, io);
    const text = try std.Io.Dir.cwd().readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}.size", .{v.dir}), arena, .limited(32));
    try testing.expect(try std.fmt.parseInt(u64, std.mem.trim(u8, text, "\n"), 10) >= 60 * 1024);
}

/// Workers racing a store's collects (each worker's after each of its jobs), each doing `one`.
const Race = struct {
    s: Store,
    deadline_ms: i64,
    faults: std.atomic.Value(u32) = .init(0),
    fresh: std.atomic.Value(u32) = .init(0),
    rounds: std.atomic.Value(u32) = .init(0),

    fn fault(r: *Race, comptime fmt: []const u8, args: anytype) void {
        std.debug.print("native eviction race: " ++ fmt ++ "\n", args);
        _ = r.faults.fetchAdd(1, .monotonic);
    }

    fn go(r: *Race, comptime one: fn (*Race, Allocator, usize, usize) anyerror!void) !void {
        var threads: [6]std.Thread = undefined;
        for (&threads, 0..) |*t, i| t.* = try .spawn(.{}, run1, .{ r, one, i });
        for (threads) |t| t.join();
        try testing.expectEqual(@as(u32, 0), r.faults.load(.monotonic));
        // It raced something: jobs found what others left, and found it evicted.
        try testing.expect(r.fresh.load(.monotonic) > 0);
        try testing.expect(r.fresh.load(.monotonic) < r.rounds.load(.monotonic));
    }

    fn run1(r: *Race, comptime one: fn (*Race, Allocator, usize, usize) anyerror!void, i: usize) void {
        const io = testing.io;
        var n: usize = 0;
        while (std.Io.Clock.awake.now(io).toMilliseconds() < r.deadline_ms) : (n += 1) {
            var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer a.deinit();
            _ = r.rounds.fetchAdd(1, .monotonic);
            one(r, a.allocator(), i, n) catch |e| r.fault("worker {d} round {d}: {t}", .{ i, n, e });
            r.s.collect(a.allocator(), io);
        }
    }
};

fn raceVolume(r: *Race, arena: Allocator, i: usize, n: usize) !void {
    const io = testing.io;
    const cwd = std.Io.Dir.cwd();
    const names = [_][]const u8{ "a", "b", "c" };
    const name = names[(i + n) % names.len];
    const v = try volumes.open(arena, io, r.s.root, &.{ "o", "r", "repo", name }, .shared, null);
    defer v.release(io);
    // What a pass will measure, left by the first job to find the volume empty.
    const base = try std.fmt.allocPrint(arena, "{s}/base", .{v.dir});
    if (cwd.access(io, base, .{})) |_| {} else |_| {
        _ = r.fresh.fetchAdd(1, .monotonic);
        cwd.writeFile(io, .{ .sub_path = base, .data = &(@as([8192]u8, @splat('b'))) }) catch |e|
            return r.fault("the volume {s} went while its job writes it: {t}", .{ name, e });
    }
    const own = try std.fmt.allocPrint(arena, "{s}/w{d}-{d}", .{ v.dir, i, n });
    try cwd.writeFile(io, .{ .sub_path = own, .data = "mine" });
    try io.sleep(.fromMilliseconds(std.math.cast(i64, n % 4).?), .awake);
    const back = cwd.readFileAlloc(io, own, arena, .limited(16)) catch |e|
        return r.fault("the volume {s} lost a job's file while it held it: {t}", .{ name, e });
    if (!std.mem.eql(u8, back, "mine")) r.fault("a job's file changed in the volume {s}", .{name});
    try cwd.deleteFile(io, own);
}

test "native eviction: jobs racing collects never lose a volume they hold" {
    const f = try Fixture.init();
    defer f.deinit();
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0, .idle_s = 0, .recent_s = 0, .remeasure_s = 0 };
    try Store.prepare(f.arena(), testing.io, f.s.root, .{ .check_parents = false });
    var r: Race = .{ .s = f.s, .deadline_ms = std.Io.Clock.awake.now(testing.io).toMilliseconds() + 1500 };
    try r.go(raceVolume);
    f.s.limits.budget_ms = 60_000;
    run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
}
