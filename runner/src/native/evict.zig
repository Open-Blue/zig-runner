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
//! end, within a budget of time (`Limits.budget_ms`), which starts after the sync of what is dead,
//! as that takes what the disk takes: what a deadline cut short stays under its
//! dead name, the next job's collect goes on with it, and nothing more is evicted until it is
//! gone. So what eviction has freed is known before it frees more.
//!
//! A job writes what is inside a volume, so nothing in there is believed or followed. The walk never
//! looks into a volume, sizes and the locks it goes by are in directories no job can reach, and
//! what is opened there is opened through no symlink and without waiting on a FIFO. The one thing
//! an eviction must look for inside a volume is the lock of a volume inside it (`innerLock`).
//!
//! What an honest job loses is a rebuild, and not on a loop: an entry used in the last day
//! (`Limits.idle_s`) stays though the store is over its cap, so a store whose working set is over
//! the cap goes over it rather than throw away what the next job needs. What stops that growing
//! is the disk: with less than `Limits.min_free_pct` of it free, layers (`Store.collect`) and then
//! entries go until that much is free, whatever the caps say, sparing only those used in the last
//! hour (`Limits.recent_s`).

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
/// What a pass removes of a dead tree however late it is.
const least_removed = 64;
/// What a walk may keep in memory of the directories' paths.
const measure_max_stack = 16 * 1024 * 1024;
/// The most entries of an area looked at, so a store's size bounds the pass's memory.
const max_entries = 16 * 1024;
/// How deep a key goes, from `<owner>`, 0: `<owner>/<repository>/<scope>/<name>/<image>/runner`.
const max_key_depth = 5;
/// The name a step user's volume adds below its key (`dagger.runner_user`): the only volume that
/// can be inside another's directory (`volumes.plan`).
pub const nested = "runner";

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
    // What a deadline left first: nothing more goes until what already went is gone. Synced first,
    // and once: a runner that died may not have synced it, and a slow disk must not take what the
    // pass has for deleting, or the worse the disk the less would ever go.
    var synced = syncDead(arena, io, s.root);
    if (!synced) return;
    var budget: Budget = .init(io, lim.budget_ms);
    if (!removeDead(arena, io, s.root, "volumes", &budget)) return;
    const entries = listVolumes(arena, io, s.root) catch return;
    measureOne(arena, io, entries, lim.remeasure_s);
    var evicted = capped(arena, io, s.root, entries, lim.volumes_max_bytes, lim, &budget, &synced);
    if (!synced) return;
    if (shortOf(arena, s)) |short| {
        var left = short;
        evicted = floor(arena, io, s.root, entries, &left, lim, &budget, &synced) or evicted;
    }
    if (evicted and synced) _ = removeDead(arena, io, s.root, "volumes", &budget);
}

/// What the disk is short of: `shortBy` by the store's limit.
pub fn shortOf(arena: Allocator, s: Store) ?u64 {
    return shortBy(arena, s.root, s.limits.min_free_pct);
}

/// Entries evicted, the longest unused first, until `left` bytes are gone, sparing what was used
/// in the last `recent_s`; whether any was. A size not known is measured first: an upgrade on a
/// nearly full disk finds nothing measured, and counting those as 0 would take them all. What a
/// walk cut short is the last to go in this pass, as how much it freed is not known. The deadline
/// counts from the first walk: each costs up to `measure_again_ms`.
fn floor(arena: Allocator, io: std.Io, root: []const u8, entries: []Entry, left: *u64, lim: Limits, budget: *const Budget, synced: *bool) bool {
    std.mem.sort(Entry, entries, {}, olderFirst);
    var evicted = false;
    for (entries) |*e| {
        if (left.* == 0 or !synced.* or (evicted and budget.late())) break;
        if (e.private or lim.recent_s > now(io) - e.used_s) continue;
        // No time left to walk it: the next may be known.
        if (e.measured_s == 0 and budget.late()) continue;
        const whole = e.measured_s != 0 or measure(arena, io, e, measure_again_ms);
        if (!evictEntry(arena, io, root, e.*, synced)) continue;
        evicted = true;
        left.* -|= e.bytes;
        if (!whole) break;
    }
    return evicted;
}

fn now(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toSeconds();
}

/// A deadline in the awake clock, cheap enough to ask at every entry.
pub const Budget = struct {
    io: std.Io,
    deadline_ms: i64,
    /// What removal takes whatever the clock says, so that a pass always frees something.
    least: u32,

    /// A deadline `ms` from now. Past it from the start (`ms` negative) it leaves removal nothing.
    pub fn init(io: std.Io, ms: i64) Budget {
        return .{
            .io = io,
            .deadline_ms = std.Io.Clock.awake.now(io).toMilliseconds() + ms,
            .least = if (ms < 0) 0 else least_removed,
        };
    }

    pub fn late(b: Budget) bool {
        return std.Io.Clock.awake.now(b.io).toMilliseconds() >= b.deadline_ms;
    }

    /// Whether removal should stop.
    fn spent(b: Budget) bool {
        return b.least == 0 and b.late();
    }

    fn took(b: *Budget) void {
        b.least -|= 1;
    }
};

fn olderFirst(_: void, a: Entry, b: Entry) bool {
    return a.used_s < b.used_s;
}

/// Volumes evicted, the longest unused first, until the area is under `max`; whether any was. One
/// not measured yet is left, as what taking it would free is not known. A dead runner's private
/// copy goes first, cap or no cap. Each eviction syncs a directory, so the budget counts here too.
fn capped(arena: Allocator, io: std.Io, root: []const u8, entries: []Entry, max: u64, lim: Limits, budget: *const Budget, synced: *bool) bool {
    var total: u64 = 0;
    for (entries) |e| total +|= e.bytes;
    var evicted = false;
    for (entries) |e| if (synced.* and e.private and evictEntry(arena, io, root, e, synced)) {
        total -|= e.bytes;
        evicted = true;
    };
    if (max == 0 or total <= max) return evicted;
    std.mem.sort(Entry, entries, {}, olderFirst);
    const t = now(io);
    for (entries) |e| {
        if (total <= max or !synced.* or (evicted and budget.late())) break;
        if (e.private or e.measured_s == 0 or t - e.used_s < lim.idle_s) continue;
        if (!evictEntry(arena, io, root, e, synced)) continue;
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
/// is a volume, a job's own content, which is never looked into: a volume inside it goes with it
/// (`innerLock`). One without is a part of a key, which no job can reach, so it must look like one:
/// the runner's own, and where a key has parts. Below the name, only an image's and the step user's.
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
        if (depth == max_key_depth and !std.mem.startsWith(u8, n, nested)) continue;
        const full = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, n });
        // By what it is: a repository may be named `x.lock`.
        if (!isDir(arena, full)) {
            if (std.mem.endsWith(u8, n, ".lock")) {
                const v = full[0 .. full.len - ".lock".len];
                if (!isDir(arena, v)) dropStray(arena, io, v);
            } else if (std.mem.endsWith(u8, n, ".size")) {
                // A crash between the two removals of `forget`.
                if (!isDir(arena, full[0 .. full.len - ".size".len])) std.Io.Dir.cwd().deleteFile(io, full) catch {};
            }
            continue;
        }
        if (!isFile(arena, try std.fmt.allocPrint(arena, "{s}.lock", .{full}))) {
            if (runners(arena, full)) try walkKeys(arena, io, full, out, depth + 1);
            continue;
        }
        if (out.items.len >= max_entries) return;
        try out.append(arena, try entryOf(arena, io, full, std.mem.indexOf(u8, n, ".private-") != null));
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
    const f = Store.openPlain(arena, size) orelse return e;
    defer f.close(io);
    var buf: [32]u8 = undefined;
    const got = linux.read(f.handle, &buf, buf.len);
    if (linux.errno(got) != .SUCCESS) return e;
    e.bytes = std.fmt.parseInt(u64, std.mem.trim(u8, buf[0..got], " \n"), 10) catch 0;
    return e;
}

/// Whether `p` is the runner's own: a volume's root is the volumes' range on a root runner.
fn runners(arena: Allocator, p: []const u8) bool {
    var st: linux.Statx = undefined;
    return lstat(arena, p, &st) and st.uid == linux.geteuid();
}

fn lstat(arena: Allocator, p: []const u8, st: *linux.Statx) bool {
    const z = arena.dupeSentinel(u8, p, 0) catch return false;
    const mask: linux.STATX = .{ .TYPE = true, .MTIME = true, .UID = true };
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
    _ = io;
    const path = std.fmt.allocPrint(arena, "{s}.lock", .{dir}) catch return null;
    return Store.openPlain(arena, path);
}

/// What an eviction finds of the volume that may be inside the one it takes.
const Inner = union(enum) {
    /// A job holds it: the outer one stays.
    held,
    /// No job can: its lock's name is taken by a directory, or the volume's own by something else,
    /// and `volumes.open` could make no lock there either.
    none,
    locked: linux.fd_t,
};

/// The lock of the volume that may be inside the volume `dir` is open on, taken exclusively. It
/// goes with the rename, so a job holding it must keep the volume, and one starting now must wait,
/// find the path gone and start over: it is taken even when no such volume is there, made if
/// need be. All this in a directory a job could write, and could have left anything in: through
/// the descriptor, opening no symlink and not waiting on a FIFO, and what is not a regular file
/// is removed, as `volumes.open` would remove it. No job has been using the volume since its own
/// lock was taken, so what is there stays there.
fn innerLock(dir: linux.fd_t) Inner {
    const name: [:0]const u8 = nested ++ ".lock";
    var flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    for (0..3) |_| {
        const refused = test_no_inodes and flags.CREAT;
        const rc = if (refused) 0 else linux.openat(dir, name, flags, 0o644);
        switch (if (refused) linux.E.NOSPC else linux.errno(rc)) {
            .SUCCESS => {},
            // A symlink.
            .LOOP => {
                _ = linux.unlinkat(dir, name, 0);
                continue;
            },
            // A step may have left the volume's root read-only.
            .ACCES => {
                _ = linux.fchmod(dir, 0o700);
                continue;
            },
            // No room to make it, so it is not there, or `O_CREAT` would have opened it: looked
            // for without. One that cannot be made either, a job cannot have made.
            .NOSPC, .DQUOT => {
                flags.CREAT = false;
                continue;
            },
            .NOENT => if (flags.CREAT) return .held else return .none,
            .ISDIR, .NOTDIR => return .none,
            // Whatever else, a job may hold it for all this can tell: out of descriptors, say.
            else => return .held,
        }
        const fd = std.math.cast(linux.fd_t, rc) orelse return .held;
        var st: linux.Statx = undefined;
        const mask: linux.STATX = .{ .TYPE = true, .INO = true };
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, mask, &st)) != .SUCCESS or
            st.mode & linux.S.IFMT != linux.S.IFREG)
        {
            _ = linux.close(fd);
            _ = linux.unlinkat(dir, name, 0);
            continue;
        }
        if (linux.errno(linux.flock(fd, lock_ex | lock_nb)) != .SUCCESS) {
            _ = linux.close(fd);
            return .held;
        }
        var named: linux.Statx = undefined;
        if (linux.errno(linux.statx(dir, name, linux.AT.SYMLINK_NOFOLLOW, mask, &named)) == .SUCCESS and
            named.ino == st.ino) return .{ .locked = fd };
        _ = linux.close(fd);
    }
    return .held;
}

/// The directory that holds `dir`, a path under `root`, opened a part at a time through no
/// symlink, or null, also when any part is a volume: what is in one is a job's. All it does to the
/// entry goes through this, so nothing it saw can be swapped under it for another path.
fn openHolder(arena: Allocator, root: []const u8, dir: []const u8) ?linux.fd_t {
    if (dir.len <= root.len or !std.mem.startsWith(u8, dir, root)) return null;
    var fd = Store.openRoot(arena, root) catch return null;
    var parts = std.mem.splitScalar(u8, std.fs.path.dirname(dir[root.len + 1 ..]) orelse "", '/');
    while (parts.next()) |part| {
        const up = fd;
        defer _ = linux.close(up);
        var lock: std.ArrayList(u8) = .empty;
        lock.print(arena, "{s}.lock\x00", .{part}) catch return null;
        const z = lock.items[0 .. lock.items.len - 1 :0];
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(up, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st)) == .SUCCESS) return null;
        fd = Store.openDirAt(up, (arena.dupeSentinel(u8, part, 0) catch return null).ptr) catch return null;
    }
    return fd;
}

/// Evicts one entry no job holds: under its lock, with the lock of the volume inside it if it can
/// have one, renamed away and the rename synced, each through a descriptor. False when a job holds
/// it, or it went already. The tree itself is `removeDead`'s, after the locks are let go: a job
/// starting now has to wait for the rename, not for the delete. `synced` goes false when the
/// rename may not be on disk, so nothing of it is deleted until a sync says it is.
fn evictEntry(arena: Allocator, io: std.Io, root: []const u8, e: Entry, synced: *bool) bool {
    const from = openHolder(arena, root, e.dir) orelse return false;
    defer _ = linux.close(from);
    const area = Store.openRoot(arena, std.fmt.allocPrint(arena, "{s}/volumes", .{root}) catch return false) catch return false;
    defer _ = linux.close(area);
    const base = arena.dupeSentinel(u8, std.fs.path.basename(e.dir), 0) catch return false;
    const lock_name = std.fmt.allocPrintSentinel(arena, "{s}.lock", .{base}, 0) catch return false;
    const size_name = std.fmt.allocPrintSentinel(arena, "{s}.size", .{base}, 0) catch return false;
    const lock = Store.openPlainAt(from, lock_name) orelse return false;
    defer lock.close(io);
    if (!flock(lock, lock_ex | lock_nb)) return false;
    // On the file the name is now, and it not used since the walk.
    var held: linux.Statx = undefined;
    var named: linux.Statx = undefined;
    const mask: linux.STATX = .{ .INO = true, .MTIME = true };
    if (linux.errno(linux.statx(lock.handle, "", linux.AT.EMPTY_PATH, mask, &held)) != .SUCCESS or
        linux.errno(linux.statx(from, lock_name, linux.AT.SYMLINK_NOFOLLOW, mask, &named)) != .SUCCESS or
        held.ino != named.ino or named.mtime.sec != e.used_s) return false;
    const fd = Store.openDirAt(from, base) catch return false;
    defer _ = linux.close(fd);
    const inner = innerLock(fd);
    defer switch (inner) {
        .locked => |l| _ = linux.close(l),
        else => {},
    };
    if (inner == .held) return false;
    var raw: [8]u8 = undefined;
    io.random(&raw);
    var dead: [32:0]u8 = undefined;
    const dead_name = std.fmt.bufPrintSentinel(&dead, ".dead-{s}", .{&std.fmt.bytesToHex(raw, .lower)}, 0) catch return false;
    if (linux.errno(linux.renameat(from, base, area, dead_name)) != .SUCCESS) return false;
    for ([_]linux.fd_t{ from, area }) |d| if (test_sync_fails or linux.errno(linux.fsync(d)) != .SUCCESS) {
        std.log.warn("native: cannot sync a directory of {s}; what went from there stays until it can be", .{root});
        synced.* = false;
    };
    _ = linux.unlinkat(from, lock_name, 0);
    _ = linux.unlinkat(from, size_name, 0);
    return true;
}

/// How long `syncDead` takes on top of the sync. Tests.
var test_sync_ms: i64 = 0;
/// Every sync here fails, as on a disk that fails writes. Tests.
var test_sync_fails = false;
/// `innerLock` can make no file, as on a filesystem with no inodes left. Tests.
var test_no_inodes = false;

/// The filesystem synced if anything is under a dead name, so that a rename it was given by is on
/// disk before anything of it is deleted: the runner that renamed it may have died before it
/// synced (`evictEntry`), and which directory it came from is not known here. Once, a pass; it
/// takes what the disk takes, which no budget can bound. Whether it is safe to delete.
fn syncDead(arena: Allocator, io: std.Io, root: []const u8) bool {
    const dir_path = std.fmt.allocPrint(arena, "{s}/volumes", .{root}) catch return false;
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return true;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (!std.mem.startsWith(u8, e.name, ".dead-")) continue;
        if (test_sync_ms > 0) io.sleep(.fromMilliseconds(test_sync_ms), .awake) catch {};
        if (!test_sync_fails and linux.errno(linux.syncfs(dir.handle)) == .SUCCESS) return true;
        std.log.warn("native: cannot sync {s}; what is dead there stays until it can be", .{dir_path});
        return false;
    }
    return true;
}

/// Every `.dead-` entry of the area removed, as far as the budget goes. False only when the budget
/// stopped it, which tells the pass to free no more yet: one that cannot be removed is logged and
/// stops nothing, or it would stop every eviction for good.
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
    for (dead.items) |n| {
        const p = std.fmt.allocPrint(arena, "{s}/{s}", .{ dir_path, n }) catch return false;
        switch (removeSome(arena, p, io, budget)) {
            .gone => {},
            .spent => return false,
            .stuck => std.log.warn("native: cannot remove {s}; it stays, and eviction goes on", .{p}),
        }
    }
    return true;
}

const Removal = enum { gone, spent, stuck };

/// How many directories `removeSome` keeps open on its way down.
const max_chain = 32;

/// As much of the tree `path` removed as `budget` allows, a directory's entries before it, to any
/// depth, through no symlink. It goes down by name and back by the descriptors it came through, up
/// to `max_chain` of them, never by `..`: so nothing it does can reach above the tree, whatever is
/// moved meanwhile, though nothing should touch a dead tree. Deeper than that, the directory it
/// is about to enter moves up to the tree's top under a name of its own, and the walk goes on from
/// there: what the budget leaves stays under the dead name for a later call, which starts at the
/// top, so a chain deeper than a pass can walk loses some of itself every pass. The name is random,
/// as a job can read its inodes and plant any name it can work out. A name that is no directory
/// just goes.
fn removeSome(arena: Allocator, path: []const u8, io: std.Io, budget: *Budget) Removal {
    const up_path = std.fs.path.dirname(path) orelse return .stuck;
    const up = Store.openRoot(arena, up_path) catch return .stuck;
    defer _ = linux.close(up);
    const base = arena.dupeSentinel(u8, std.fs.path.basename(path), 0) catch return .stuck;
    switch (linux.errno(linux.unlinkat(up, base, 0))) {
        .SUCCESS, .NOENT => return .gone,
        .ISDIR, .PERM => {},
        else => return .stuck,
    }
    chmodDir(up, base);
    var chain: [max_chain]linux.fd_t = undefined;
    chain[0] = Store.openDirAt(up, base) catch return .stuck;
    var held: usize = 1;
    defer for (chain[0..held]) |fd| {
        _ = linux.close(fd);
    };
    var name: [256:0]u8 = undefined;
    while (true) {
        const cur = chain[held - 1];
        const down = emptyOut(io, cur, &name, budget) catch |e| {
            if (e == error.Spent) return .spent;
            std.log.warn("native: cannot remove all of {s}: {t}", .{ path, e });
            return .stuck;
        };
        if (down) |n| {
            const child = Store.openDirAt(cur, n) catch return .stuck;
            if (held == max_chain) {
                if (!cutUp(io, cur, n, chain[0])) {
                    _ = linux.close(child);
                    return .stuck;
                }
                for (chain[1..held]) |fd| _ = linux.close(fd);
                held = 1;
            }
            chain[held] = child;
            held += 1;
            continue;
        }
        if (held == 1) break;
        // Empty now: the listing of the directory above finds it so, and removes it.
        held -= 1;
        _ = linux.close(chain[held]);
    }
    return if (linux.errno(linux.unlinkat(up, base, linux.AT.REMOVEDIR)) == .SUCCESS) .gone else .stuck;
}

/// The directory `name` in `from` moved to the tree's top, `top`, under a random name.
fn cutUp(io: std.Io, from: linux.fd_t, name: [*:0]const u8, top: linux.fd_t) bool {
    for (0..4) |_| {
        var raw: [8]u8 = undefined;
        io.random(&raw);
        var cut: [32:0]u8 = undefined;
        const to = std.fmt.bufPrintSentinel(&cut, ".cut-{s}", .{&std.fmt.bytesToHex(raw, .lower)}, 0) catch return false;
        switch (linux.errno(linux.renameat2(from, name, top, to, .{ .NOREPLACE = true }))) {
            .SUCCESS => return true,
            .EXIST => {},
            else => return false,
        }
    }
    return false;
}

/// The directory `name` in `dir` given its owner's permissions back, so it can be emptied: a step
/// may have left it so, or a rootless runner's. Never through a symlink: through a descriptor on
/// the name itself, which a symlink refuses.
fn chmodDir(dir: linux.fd_t, name: [*:0]const u8) void {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true };
    const rc = linux.openat(dir, name, flags, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd = std.math.cast(linux.fd_t, rc) orelse return;
    defer _ = linux.close(fd);
    var buf: [32:0]u8 = undefined;
    const p = std.fmt.bufPrintSentinel(&buf, "/proc/self/fd/{d}", .{fd}, 0) catch return;
    _ = linux.chmod(p, 0o700);
}

/// The directory `fd`'s files unlinked and its empty directories removed, until the first
/// directory with something in it, whose name is returned to go into (`name` holds it); null when
/// nothing is left. `error.Spent` when the budget ran out.
fn emptyOut(io: std.Io, fd: linux.fd_t, name: *[256:0]u8, budget: *Budget) !?[:0]const u8 {
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
            .SUCCESS, .NOENT => {
                budget.took();
                continue;
            },
            .ISDIR, .PERM => {},
            else => {
                failed = true;
                continue;
            },
        }
        switch (linux.errno(linux.unlinkat(fd, z, linux.AT.REMOVEDIR))) {
            .SUCCESS, .NOENT => {
                budget.took();
                continue;
            },
            .NOTEMPTY, .ACCES, .PERM => {
                chmodDir(fd, z);
                return z;
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
    _ = measure(arena, io, e, if (e.measured_s == 0) measure_new_ms else measure_again_ms);
}

/// `e` walked for up to `ms` and the size kept beside it; whether the walk was whole.
fn measure(arena: Allocator, io: std.Io, e: *Entry, ms: i64) bool {
    const seen = usage(io, e.dir, .init(io, ms));
    // Cut short, it is too small: what it saw before, if more, is the better guess.
    e.bytes = if (seen.whole) seen.bytes else @max(seen.bytes, e.bytes);
    e.measured_s = now(io);
    const p = std.fmt.allocPrintSentinel(arena, "{s}.size", .{e.dir}, 0) catch return seen.whole;
    var buf: [32]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}\n", .{e.bytes}) catch return seen.whole;
    // Not synced: lost, it is measured again. Never trusted further than that.
    const flags: linux.O = .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    const rc = linux.open(p, flags, 0o644);
    if (linux.errno(rc) != .SUCCESS) return seen.whole;
    const fd = std.math.cast(linux.fd_t, rc) orelse return seen.whole;
    defer _ = linux.close(fd);
    _ = linux.write(fd, text.ptr, text.len);
    return seen.whole;
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
            if (seen % 64 == 0 and budget.late()) return .{ .bytes = total, .whole = false };
            if (e.name.len > 255) continue;
            @memcpy(name[0..e.name.len], e.name);
            name[e.name.len] = 0;
            const z = name[0..e.name.len :0];
            var st: linux.Statx = undefined;
            const mask: linux.STATX = .{ .TYPE = true, .BLOCKS = true, .NLINK = true };
            if (linux.errno(linux.statx(fd, z, linux.AT.SYMLINK_NOFOLLOW, mask, &st)) != .SUCCESS) continue;
            const is_dir = st.mode & linux.S.IFMT == linux.S.IFDIR;
            total +|= st.blocks * 512 / (if (is_dir) 1 else @max(st.nlink, 1));
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
    var budget: Budget = .init(io, 60_000);
    try testing.expectEqual(Removal.gone, removeSome(f.arena(), dir, io, &budget));
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

    fn fault(r: *Race, comptime fmt: []const u8, args: anytype) void {
        std.debug.print("native eviction race: " ++ fmt ++ "\n", args);
        _ = r.faults.fetchAdd(1, .monotonic);
    }

    fn go(r: *Race, comptime one: fn (*Race, Allocator, usize, usize) anyerror!void) !void {
        var threads: [6]std.Thread = undefined;
        for (&threads, 0..) |*t, i| t.* = try .spawn(.{}, run1, .{ r, one, i });
        for (threads) |t| t.join();
        try testing.expectEqual(@as(u32, 0), r.faults.load(.monotonic));
        try testing.expect(r.fresh.load(.monotonic) > 0);
    }

    fn run1(r: *Race, comptime one: fn (*Race, Allocator, usize, usize) anyerror!void, i: usize) void {
        const io = testing.io;
        var n: usize = 0;
        while (std.Io.Clock.awake.now(io).toMilliseconds() < r.deadline_ms) : (n += 1) {
            var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer a.deinit();
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

// --- what a job can do to the directories it can write ---

const Hostile = struct {
    fn p(f: *Fixture, comptime fmt: []const u8, args: anytype) []const u8 {
        return std.fmt.allocPrint(f.arena(), fmt, args) catch @panic("out of memory");
    }

    fn write(path: []const u8, data: []const u8) !void {
        try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = data });
    }

    fn read(f: *Fixture, path: []const u8) ![]const u8 {
        return std.Io.Dir.cwd().readFileAlloc(testing.io, path, f.arena(), .limited(1 << 20));
    }

    fn mkfifo(f: *Fixture, path: []const u8) !void {
        const z = try f.arena().dupeSentinel(u8, path, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mknodat(linux.AT.FDCWD, z, linux.S.IFIFO | 0o644, 0)));
    }

    fn mode(f: *Fixture, path: []const u8) !u32 {
        const z = try f.arena().dupeSentinel(u8, path, 0);
        var st: linux.Statx = undefined;
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.statx(linux.AT.FDCWD, z, 0, .{ .MODE = true }, &st)));
        return st.mode & 0o7777;
    }

    fn agedLink(f: *Fixture, target: []const u8, path: []const u8) !void {
        try std.Io.Dir.cwd().symLink(testing.io, target, path, .{});
        const z = try f.arena().dupeSentinel(u8, path, 0);
        const t = [2]linux.timespec{ .{ .sec = 1, .nsec = 0 }, .{ .sec = 1, .nsec = 0 } };
        _ = linux.utimensat(linux.AT.FDCWD, z, &t, linux.AT.SYMLINK_NOFOLLOW);
    }

    const Pass = struct {
        s: Store,
        done: std.atomic.Value(bool) = .init(false),
        fn go(h: *Pass) void {
            run(h.s, testing.io);
            h.done.store(true, .release);
        }
    };

    /// `run` to its end, failing if it is still blocked after a few seconds, when the FIFO is
    /// opened for it so that the test can end.
    fn endsDespite(s: Store, fifo: []const u8) !void {
        var h: Pass = .{ .s = s };
        const t = try std.Thread.spawn(.{}, Pass.go, .{&h});
        const start = std.Io.Clock.awake.now(testing.io).toMilliseconds();
        while (!h.done.load(.acquire) and std.Io.Clock.awake.now(testing.io).toMilliseconds() - start < 3000)
            try testing.io.sleep(.fromMilliseconds(20), .awake);
        const stuck = !h.done.load(.acquire);
        var buf: [4096]u8 = undefined;
        const z = try std.fmt.bufPrintSentinel(&buf, "{s}", .{fifo}, 0);
        while (!h.done.load(.acquire)) {
            const rc = linux.open(z, .{ .ACCMODE = .WRONLY, .NONBLOCK = true }, 0);
            if (linux.errno(rc) != .SUCCESS) continue;
            _ = linux.close(std.math.cast(linux.fd_t, rc).?);
            break;
        }
        t.join();
        try testing.expect(!stuck);
    }
};

test "native eviction: a FIFO a job left at runner.lock in its volume does not hang the pass" {
    const f = try Fixture.init();
    defer f.deinit();
    const dir = try f.volume("victim", 6000, 30);
    const fifo = Hostile.p(f, "{s}/runner.lock", .{dir});
    try Hostile.mkfifo(f, fifo);
    f.s.limits = .{ .volumes_max_bytes = 1000, .min_free_pct = 0 };
    try Hostile.endsDespite(f.s, fifo);
    // Nor does it keep the volume.
    try testing.expect(!f.there(dir));
}

test "native eviction: a FIFO a job left at runner.size in its volume does not hang the pass" {
    const f = try Fixture.init();
    defer f.deinit();
    const v = try f.hold("victim");
    defer v.release(testing.io);
    try std.Io.Dir.cwd().createDirPath(testing.io, Hostile.p(f, "{s}/runner", .{v.dir}));
    try Hostile.write(Hostile.p(f, "{s}/runner.lock", .{v.dir}), "");
    const fifo = Hostile.p(f, "{s}/runner.size", .{v.dir});
    try Hostile.mkfifo(f, fifo);
    f.s.limits = .{ .volumes_max_bytes = 0, .min_free_pct = 0 };
    try Hostile.endsDespite(f.s, fifo);
}

test "native eviction: a job's symlink at runner.size does not get a file outside the store written" {
    const f = try Fixture.init();
    defer f.deinit();
    const victim = Hostile.p(f, "{s}/host-file", .{f.s.root});
    try Hostile.write(victim, "precious");
    const v = try f.hold("job-writable");
    defer v.release(testing.io);
    // mkdir runner; touch runner.lock; ln -s /host/file runner.size; touch -h -d @1 runner.size
    try std.Io.Dir.cwd().createDirPath(testing.io, Hostile.p(f, "{s}/runner", .{v.dir}));
    try Hostile.write(Hostile.p(f, "{s}/runner.lock", .{v.dir}), "");
    try Hostile.write(Hostile.p(f, "{s}/runner/x", .{v.dir}), "x");
    try Hostile.agedLink(f, victim, Hostile.p(f, "{s}/runner.size", .{v.dir}));
    f.s.limits = .{ .volumes_max_bytes = 0, .min_free_pct = 0, .remeasure_s = 0 };
    for (0..3) |_| run(f.s, testing.io);
    try testing.expectEqualStrings("precious", try Hostile.read(f, victim));
}

test "native eviction: what a job plants in its volume is no entry of the store" {
    const f = try Fixture.init();
    defer f.deinit();
    const v = try f.hold("job-writable");
    defer v.release(testing.io);
    try std.Io.Dir.cwd().createDirPath(testing.io, Hostile.p(f, "{s}/runner", .{v.dir}));
    try Hostile.write(Hostile.p(f, "{s}/runner.lock", .{v.dir}), "");
    for (try listVolumes(f.arena(), testing.io, f.s.root)) |e|
        try testing.expect(!std.mem.endsWith(u8, e.dir, "/runner"));
}

test "native eviction: a job's symlink at runner.lock neither pins its volume nor makes a file outside" {
    const f = try Fixture.init();
    defer f.deinit();
    const outside = Hostile.p(f, "{s}/outside", .{f.s.root});
    try std.Io.Dir.cwd().createDirPath(testing.io, outside);
    const dir = try f.volume("pinned", 6000, 30);
    try std.Io.Dir.cwd().symLink(testing.io, Hostile.p(f, "{s}/new-file", .{outside}), Hostile.p(f, "{s}/runner.lock", .{dir}), .{});
    f.s.limits = .{ .volumes_max_bytes = 1000, .min_free_pct = 0 };
    run(f.s, testing.io);
    try testing.expect(!f.there(dir));
    try testing.expect(!isFile(f.arena(), Hostile.p(f, "{s}/new-file", .{outside})));
}

test "native eviction: sizes a job wrote count for nothing, however large" {
    const f = try Fixture.init();
    defer f.deinit();
    const neighbour = try f.volume("neighbour", 1000, 30);
    const v = try f.hold("job-writable");
    defer v.release(testing.io);
    try std.Io.Dir.cwd().createDirPath(testing.io, Hostile.p(f, "{s}/runner", .{v.dir}));
    try Hostile.write(Hostile.p(f, "{s}/runner.lock", .{v.dir}), "");
    try Hostile.write(Hostile.p(f, "{s}/runner.size", .{v.dir}), "18446744073709551615\n");
    f.s.limits = .{ .volumes_max_bytes = 1 << 34, .min_free_pct = 0 };
    run(f.s, testing.io);
    try testing.expect(f.there(neighbour));
}

test "native eviction: sizes that do not fit a u64 when added up do not panic" {
    const f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{ "a", "b" }) |n| {
        const d = try f.volume(n, 10, 0);
        try Hostile.write(Hostile.p(f, "{s}.size", .{d}), "18446744073709551615\n");
    }
    f.s.limits = .{ .volumes_max_bytes = 1 << 34, .min_free_pct = 0 };
    run(f.s, testing.io);
}

test "native eviction: a dead name that is no directory goes, and one that will not go stops nothing" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const outside = Hostile.p(f, "{s}/outside", .{f.s.root});
    try std.Io.Dir.cwd().createDirPath(io, outside);
    _ = linux.chmod(try f.arena().dupeSentinel(u8, outside, 0), 0o755);
    const old = try f.volume("old", 6000, 30);
    try std.Io.Dir.cwd().symLink(io, outside, Hostile.p(f, "{s}/volumes/.dead-link", .{f.s.root}), .{});
    try Hostile.write(Hostile.p(f, "{s}/volumes/.dead-file", .{f.s.root}), "x");
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0, .budget_ms = 60_000 };
    run(f.s, io);
    try testing.expectEqual(@as(u32, 0o755), try Hostile.mode(f, outside));
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
    try testing.expect(!f.there(old));
}

fn deepChain(f: *Fixture, depth: usize) !void {
    const io = testing.io;
    try std.Io.Dir.cwd().createDirPath(io, Hostile.p(f, "{s}/volumes", .{f.s.root}));
    const vz = try f.arena().dupeSentinel(u8, Hostile.p(f, "{s}/volumes", .{f.s.root}), 0);
    const vfd = try Store.openDirAt(linux.AT.FDCWD, vz);
    defer _ = linux.close(vfd);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdirat(vfd, ".dead-chain", 0o755)));
    var fd = try Store.openDirAt(vfd, ".dead-chain");
    defer _ = linux.close(fd);
    for (0..depth) |_| {
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdirat(fd, "a", 0o755)));
        const n = try Store.openDirAt(fd, "a");
        _ = linux.close(fd);
        fd = n;
    }
}

test "native eviction: a chain of directories deeper than a pass gets through goes, a pass at a time" {
    const f = try Fixture.init();
    defer f.deinit();
    try deepChain(f, 30_000);
    const old = try f.volume("old", 6000, 30);
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0, .budget_ms = 60 };
    var passes: usize = 0;
    while (try f.deadLeft() > 0 and passes < 400) : (passes += 1) run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
    run(f.s, testing.io);
    try testing.expect(!f.there(old));
}

test "native eviction: under the floor, a volume never measured is measured before more go" {
    const f = try Fixture.init();
    defer f.deinit();
    var dirs: [8][]const u8 = undefined;
    for (&dirs, 0..) |*d, i| {
        d.* = try f.volume(Hostile.p(f, "v{d}", .{i}), 4096, 30 + std.math.cast(i64, i).?);
        try std.Io.Dir.cwd().deleteFile(testing.io, Hostile.p(f, "{s}.size", .{d.*}));
        // Each far larger than anything the disk could be short by.
        const big = try std.Io.Dir.cwd().createFile(testing.io, Hostile.p(f, "{s}/big", .{d.*}), .{});
        defer big.close(testing.io);
        try big.writeStreamingAll(testing.io, &(@as([65536]u8, @splat('x'))));
    }
    const short: u64 = 60 * 1024;
    var left = short;
    var synced = true;
    var budget: Budget = .init(testing.io, 5000);
    _ = floor(f.arena(), testing.io, f.s.root, try listVolumes(f.arena(), testing.io, f.s.root), &left, f.s.limits, &budget, &synced);
    var there: usize = 0;
    for (dirs) |d| there += @intFromBool(f.there(d));
    try testing.expectEqual(@as(usize, 7), there);
}

test "native eviction: a pass stops evicting when its budget is spent" {
    const f = try Fixture.init();
    defer f.deinit();
    for (0..50) |i| _ = try f.volume(Hostile.p(f, "v{d}", .{i}), 16, 30);
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0, .budget_ms = -1 };
    run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 1), try f.deadLeft());
}

test "native eviction: a volume used since the walk saw it stays" {
    const f = try Fixture.init();
    defer f.deinit();
    const dir = try f.volume("v", 6000, 30);
    const entries = try listVolumes(f.arena(), testing.io, f.s.root);
    try f.age(dir, 0);
    try testing.expect(!evictOne(f, entries[0]));
    try testing.expect(f.there(dir));
}

test "native eviction: a repository named like a lock or a size is counted" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const key = [_][]const u8{ "o", "r.lock", "repo", "npm" };
    const v = try volumes.open(arena, testing.io, f.s.root, &key, .shared, null);
    v.release(testing.io);
    const size = [_][]const u8{ "o", "r.size", "repo", "npm" };
    const w = try volumes.open(arena, testing.io, f.s.root, &size, .shared, null);
    w.release(testing.io);
    try testing.expectEqual(@as(usize, 2), (try listVolumes(arena, testing.io, f.s.root)).len);
}

test "native eviction: a job planting something where a volume's lock goes does not stop a job" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const outer = try f.volume("npm", 10, 0);
    const key = [_][]const u8{ "o", "r", "repo", "npm", "runner" };
    try Hostile.mkfifo(f, Hostile.p(f, "{s}/runner.lock", .{outer}));
    const v = try volumes.open(f.arena(), io, f.s.root, &key, .shared, null);
    v.release(io);
    try testing.expect(isFile(f.arena(), Hostile.p(f, "{s}/runner.lock", .{outer})));
}

test "native eviction: a volume's path that a job turned into a symlink is not followed" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const outside = Hostile.p(f, "{s}/outside", .{f.s.root});
    try std.Io.Dir.cwd().createDirPath(io, outside);
    const outer = try f.volume("npm", 10, 0);
    try std.Io.Dir.cwd().symLink(io, outside, Hostile.p(f, "{s}/runner", .{outer}), .{});
    const key = [_][]const u8{ "o", "r", "repo", "npm", "runner" };
    const v = try volumes.open(f.arena(), io, f.s.root, &key, .shared, null);
    defer v.release(io);
    try testing.expect(f.there(v.dir));
}

fn evictOne(f: *Fixture, e: Entry) bool {
    var synced = true;
    return evictEntry(f.arena(), testing.io, f.s.root, e, &synced);
}

test "native eviction: a key's part named like a lock is no sibling's lock" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const key = [_][]const u8{ "o", "r", "repo", "toolcache", "foo" };
    const v = try volumes.open(arena, testing.io, f.s.root, &key, .shared, null);
    defer v.release(testing.io);
    // A job's image is its to name: `…:t` and `…:t.lock`.
    const twin = [_][]const u8{ "o", "r", "repo", "toolcache", "foo.lock" };
    const w = try volumes.open(arena, testing.io, f.s.root, &twin, .shared, null);
    w.release(testing.io);
    try testing.expect(isFile(arena, Hostile.p(f, "{s}.lock", .{v.dir})));
    const again = try volumes.open(arena, testing.io, f.s.root, &key, .shared, null);
    again.release(testing.io);
    for ([_][]const u8{ "x.size", ".dead-1", "y.private-0123456789abcdef" }) |bad| {
        const n = try volumes.component(arena, bad);
        try testing.expect(!std.mem.endsWith(u8, n, ".size") and n[0] != '.');
        try testing.expect(std.mem.indexOf(u8, n, ".private-") == null);
    }
}

test "native eviction: a volume's path holding a file is an error unless a job can have left it" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const key = [_][]const u8{ "o", "r", "repo", "npm" };
    const dir = Hostile.p(f, "{s}/volumes/o/r/repo/npm", .{f.s.root});
    try std.Io.Dir.cwd().createDirPath(testing.io, Hostile.p(f, "{s}/volumes/o/r/repo", .{f.s.root}));
    try Hostile.write(dir, "someone's file");
    try testing.expectError(error.VolumeNotMade, volumes.open(arena, testing.io, f.s.root, &key, .shared, null));
    try testing.expectEqualStrings("someone's file", try Hostile.read(f, dir));
}

test "native eviction: a directory with no lock beside it is walked only as a key's part" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const cwd = std.Io.Dir.cwd();
    const key = [_][]const u8{ "o", "r", "repo", "toolcache", "foo" };
    const v = try volumes.open(arena, testing.io, f.s.root, &key, .shared, null);
    defer v.release(testing.io);
    // Its lock file lost, whatever lost it, and what its job left in it.
    try cwd.createDirPath(testing.io, Hostile.p(f, "{s}/sub/npm", .{v.dir}));
    try Hostile.write(Hostile.p(f, "{s}/sub/npm.lock", .{v.dir}), "");
    try cwd.deleteFile(testing.io, Hostile.p(f, "{s}.lock", .{v.dir}));
    for (try listVolumes(arena, testing.io, f.s.root)) |e|
        try testing.expect(!std.mem.endsWith(u8, e.dir, "/npm"));
}

test "native eviction: a symlink swapped into a key's part does not reach another repository" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const cwd = std.Io.Dir.cwd();
    const other = try f.volume("npm", 10, 30);
    const job = Hostile.p(f, "{s}/volumes/o/mine/repo/name", .{f.s.root});
    try cwd.createDirPath(testing.io, job);
    try cwd.symLink(testing.io, std.fs.path.dirname(other).?, Hostile.p(f, "{s}/sub", .{job}), .{});
    // What the walk would have seen before the swap.
    const e: Entry = .{
        .dir = Hostile.p(f, "{s}/sub/npm", .{job}),
        .used_s = mtime(arena, Hostile.p(f, "{s}.lock", .{other})).?,
        .measured_s = 1,
    };
    try testing.expect(!evictOne(f, e));
    try testing.expect(f.there(other));
}

test "native eviction: names a job planted under a dead tree do not stop the removal" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const cwd = std.Io.Dir.cwd();
    const depth: usize = 20_000;
    const dead = Hostile.p(f, "{s}/volumes/.dead-9", .{f.s.root});
    const build = Hostile.p(f, "{s}/build", .{f.s.root});
    try cwd.createDirPath(testing.io, dead);
    try cwd.createDirPath(testing.io, build);
    var fd = try Store.openRoot(arena, build);
    const df = try Store.openRoot(arena, dead);
    defer _ = linux.close(df);
    for (0..depth) |_| {
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdirat(fd, "a", 0o755)));
        const n = try Store.openDirAt(fd, "a");
        _ = linux.close(fd);
        fd = n;
        // A job reads its own inodes.
        var st: linux.Statx = undefined;
        _ = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &st);
        var name: [40:0]u8 = undefined;
        const z = try std.fmt.bufPrintSentinel(&name, ".cut-{d}", .{st.ino}, 0);
        const made = linux.openat(df, z, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
        _ = linux.close(std.math.cast(linux.fd_t, made).?);
    }
    _ = linux.close(fd);
    try cwd.rename(Hostile.p(f, "{s}/a", .{build}), cwd, Hostile.p(f, "{s}/a", .{dead}), testing.io);
    const old = try f.volume("old", 6000, 30);
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0, .budget_ms = 15 };
    var passes: usize = 0;
    while (passes < 300 and (try f.deadLeft() > 0 or f.there(old))) : (passes += 1) run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
    try testing.expect(!f.there(old));
}

test "native eviction: a slow sync does not eat what a pass may delete" {
    const f = try Fixture.init();
    defer f.deinit();
    const dead = Hostile.p(f, "{s}/volumes/.dead-9", .{f.s.root});
    try std.Io.Dir.cwd().createDirPath(testing.io, dead);
    for (0..2000) |i| try Hostile.write(Hostile.p(f, "{s}/f{d}", .{ dead, i }), "x");
    f.s.limits = .{ .volumes_max_bytes = 0, .min_free_pct = 0, .budget_ms = 300 };
    test_sync_ms = 400;
    defer test_sync_ms = 0;
    for (0..2) |_| run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
}

test "native eviction: an entry no sync can see is left, with descriptors short" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const outer = try f.hold("name");
    outer.release(testing.io);
    const key = [_][]const u8{ "o", "r", "repo", "name", "runner" };
    const inner = try volumes.open(arena, testing.io, f.s.root, &key, .shared, null);
    defer inner.release(testing.io);
    try f.age(outer.dir, 30);
    var e: ?Entry = null;
    for (try listVolumes(arena, testing.io, f.s.root)) |x| {
        if (std.mem.endsWith(u8, x.dir, "/name")) e = x;
    }
    const probe = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    const free: u64 = probe;
    _ = linux.close(std.math.cast(linux.fd_t, probe).?);
    var old: linux.rlimit = undefined;
    _ = linux.getrlimit(.NOFILE, &old);
    defer _ = linux.setrlimit(.NOFILE, &old);
    // However many descriptors it can have, it must not take the inner volume a job holds.
    for (1..10) |room| {
        const tight: linux.rlimit = .{ .cur = free + room, .max = old.max };
        _ = linux.setrlimit(.NOFILE, &tight);
        const went = evictOne(f, e.?);
        _ = linux.setrlimit(.NOFILE, &old);
        try testing.expect(!went);
        try testing.expect(f.there(inner.dir));
    }
}

test "native eviction: a directory moved out of a dead tree takes no removal out with it" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const cwd = std.Io.Dir.cwd();
    const outside = Hostile.p(f, "{s}/outside", .{f.s.root});
    try cwd.createDirPath(io, outside);
    try Hostile.write(Hostile.p(f, "{s}/keep", .{outside}), "not in the tree");
    const root = Hostile.p(f, "{s}/volumes/.dead-5", .{f.s.root});
    const c = Hostile.p(f, "{s}/a/b/c", .{root});
    try cwd.createDirPath(io, c);
    for (0..20000) |i| try Hostile.write(Hostile.p(f, "{s}/f{d}", .{ c, i }), "");
    const Mover = struct {
        from: []const u8,
        to: []const u8,
        fn go(m: @This()) void {
            testing.io.sleep(.fromMilliseconds(2), .awake) catch {};
            std.Io.Dir.cwd().rename(m.from, std.Io.Dir.cwd(), m.to, testing.io) catch {};
        }
    };
    const t = try std.Thread.spawn(.{}, Mover.go, .{Mover{ .from = Hostile.p(f, "{s}/a/b", .{root}), .to = Hostile.p(f, "{s}/b", .{outside}) }});
    var budget: Budget = .init(io, 60_000);
    _ = removeSome(f.arena(), root, io, &budget);
    t.join();
    try testing.expectEqualStrings("not in the tree", try Hostile.read(f, Hostile.p(f, "{s}/keep", .{outside})));
}

test "native eviction: giving a directory its permissions back follows no symlink" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const outside = Hostile.p(f, "{s}/outside", .{f.s.root});
    try std.Io.Dir.cwd().createDirPath(testing.io, outside);
    _ = linux.chmod(try arena.dupeSentinel(u8, outside, 0), 0o755);
    try std.Io.Dir.cwd().symLink(testing.io, outside, Hostile.p(f, "{s}/link", .{f.s.root}), .{});
    const dir = try Store.openRoot(arena, f.s.root);
    defer _ = linux.close(dir);
    chmodDir(dir, "link");
    try testing.expectEqual(@as(u32, 0o755), try Hostile.mode(f, outside));
    try std.Io.Dir.cwd().createDirPath(testing.io, Hostile.p(f, "{s}/real", .{f.s.root}));
    _ = linux.chmod(try arena.dupeSentinel(u8, Hostile.p(f, "{s}/real", .{f.s.root}), 0), 0);
    chmodDir(dir, "real");
    try testing.expectEqual(@as(u32, 0o700), try Hostile.mode(f, Hostile.p(f, "{s}/real", .{f.s.root})));
}

test "native eviction: past its deadline the floor measures nothing more" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    var dirs: [3][]const u8 = undefined;
    for (&dirs, 0..) |*d, i| {
        d.* = try f.volume(Hostile.p(f, "v{d}", .{i}), 10, 30);
        try std.Io.Dir.cwd().deleteFile(testing.io, Hostile.p(f, "{s}.size", .{d.*}));
    }
    var left: u64 = 1 << 40;
    var synced = true;
    var budget: Budget = .init(testing.io, -1);
    try testing.expect(!floor(arena, testing.io, f.s.root, try listVolumes(arena, testing.io, f.s.root), &left, f.s.limits, &budget, &synced));
    for (dirs) |d| try testing.expect(!isFile(arena, Hostile.p(f, "{s}.size", .{d})));
}

test "native eviction: a sync that fails stops the pass: nothing more goes until what went is gone" {
    const f = try Fixture.init();
    defer f.deinit();
    const dirs = [_][]const u8{
        try f.volume("v0", 6000, 30),
        try f.volume("v1", 6000, 20),
        try f.volume("v2", 6000, 10),
    };
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0 };
    test_sync_fails = true;
    defer test_sync_fails = false;
    // The rename's own sync fails: it stops at the one, and deletes nothing of it.
    run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 1), try f.deadLeft());
    try testing.expect(!f.there(dirs[0]) and f.there(dirs[1]) and f.there(dirs[2]));
    // And a pass that cannot sync what is dead does nothing, however often it runs.
    for (0..4) |_| run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 1), try f.deadLeft());
    try testing.expect(f.there(dirs[1]) and f.there(dirs[2]));
    test_sync_fails = false;
    run(f.s, testing.io);
    try testing.expectEqual(@as(usize, 0), try f.deadLeft());
}

test "native eviction: with no inodes left, a volume with no inner lock can still go" {
    const f = try Fixture.init();
    defer f.deinit();
    const dir = try f.volume("v", 6000, 30);
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0 };
    test_no_inodes = true;
    defer test_no_inodes = false;
    run(f.s, testing.io);
    try testing.expect(!f.there(dir));
}

test "native eviction: with no inodes left, a held inner volume still keeps the outer" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const outer = try f.volume("name", 6000, 30);
    const key = [_][]const u8{ "o", "r", "repo", "name", "runner" };
    const inner = try volumes.open(arena, testing.io, f.s.root, &key, .shared, null);
    defer inner.release(testing.io);
    f.s.limits = .{ .volumes_max_bytes = 1, .min_free_pct = 0 };
    test_no_inodes = true;
    defer test_no_inodes = false;
    run(f.s, testing.io);
    try testing.expect(f.there(outer) and f.there(inner.dir));
}

test "native eviction: a late floor passes over a volume never measured for one it knows" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const unknown = try f.volume("unknown", 10, 40);
    try std.Io.Dir.cwd().deleteFile(testing.io, Hostile.p(f, "{s}.size", .{unknown}));
    const known = try f.volume("known", 10, 30);
    var left: u64 = 1 << 40;
    var synced = true;
    var budget: Budget = .init(testing.io, -1);
    try testing.expect(floor(arena, testing.io, f.s.root, try listVolumes(arena, testing.io, f.s.root), &left, f.s.limits, &budget, &synced));
    try testing.expect(f.there(unknown) and !f.there(known));
    try testing.expect(!isFile(arena, Hostile.p(f, "{s}.size", .{unknown})));
}

test "native eviction: repositories whose names were rewritten do not share a volume" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    for ([_][2][]const u8{ .{ "x.lock", "x.lock_" }, .{ ".github", "_.github" }, .{ "a.private-b", "a-private-b" } }) |p| {
        const v = try volumes.open(arena, testing.io, f.s.root, &.{ "o", p[0], "repo", "zig-local" }, .shared, null);
        defer v.release(testing.io);
        const w = try volumes.open(arena, testing.io, f.s.root, &.{ "o", p[1], "repo", "zig-local" }, .shared, null);
        defer w.release(testing.io);
        try testing.expect(!std.mem.eql(u8, v.dir, w.dir));
    }
}

test "native eviction: no two repository names are one directory, and none reads as the store's" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // A repository's name is letters, digits, `.`, `-` and `_`: every way of putting together what
    // a rewrite looks for, and what a rewrite could have made.
    const tokens = [_][]const u8{ ".", "-", "_", "a", ".lock", ".size", ".private-", "private-", ".dead-", "lock", "size" };
    var seen: std.StringHashMapUnmanaged([]const u8) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    try names.append(arena, "");
    var from: usize = 0;
    for (0..4) |_| {
        const to = names.items.len;
        for (from..to) |i| for (tokens) |t| try names.append(arena, try std.mem.concat(arena, u8, &.{ names.items[i], t }));
        from = to;
    }
    for (names.items) |n| {
        const c = try volumes.component(arena, n);
        try testing.expect(c.len > 0 and c[0] != '.' and std.mem.indexOfScalar(u8, c, '/') == null);
        try testing.expect(!std.mem.endsWith(u8, c, ".lock") and !std.mem.endsWith(u8, c, ".size"));
        try testing.expect(std.mem.indexOf(u8, c, ".private-") == null);
        const got = try seen.getOrPut(arena, c);
        if (got.found_existing and !std.mem.eql(u8, got.value_ptr.*, n)) {
            std.debug.print("{s} and {s} are both {s}\n", .{ got.value_ptr.*, n, c });
            return error.TestUnexpectedResult;
        }
        got.value_ptr.* = n;
    }
}
