//! Eviction of what sits beside the layers (docs/native-backend.md, "Eviction"): the cache
//! volumes under `volumes/`, and the images, provisioned rootfs and Zig cache seeds under `oci/`,
//! `rootfs/` and `seeds/`, which `Store.collect` runs after each job, under its `gc.lock`, so
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
//! end, within a budget of time (`Limits.budget_ms`), but for the syncs of what is dead, which take
//! what the disk takes: what a deadline cut short stays under its
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
pub const default_images_max_bytes: u64 = 8 * 1024 * 1024 * 1024;
pub const default_min_free_pct: u8 = 10;

/// What `run` keeps to (`Store.limits`). A cap of 0 is no cap, as it is for the disk's floor:
/// such a store keeps what it has.
pub const Limits = struct {
    /// Past this many bytes of cache volumes, the least recently used go
    /// (`RUNNER_NATIVE_VOLUMES_MAX_MB`).
    volumes_max_bytes: u64 = default_volumes_max_bytes,
    /// Past this many bytes of blobs, images, provisioned rootfs and Zig cache seeds together,
    /// the blobs go, then those least recently used (`RUNNER_NATIVE_IMAGES_MAX_MB`).
    images_max_bytes: u64 = default_images_max_bytes,
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

/// The directories of trees: made once under a key and published by a rename.
const tree_areas = [_][]const u8{ "rootfs", "oci/images", "seeds" };
const all_areas = tree_areas ++ [_][]const u8{"volumes"};

/// How much sooner a rootfs goes than the image it was made from, which every job using it pulls
/// just before: a rootfs shares its files with its image, whose eviction would move their ctimes
/// (so `Store.rootfsFingerprint`, and every layer's key on it, at the next restart) and cost the
/// next job a pull it would not otherwise need.
const image_grace_s = 60 * 60;

const Entry = struct {
    /// The directory's path. A `.lock` and a `.size` are beside it.
    dir: []const u8,
    /// `all_areas`' name it is under, where its dead name goes.
    area: []const u8,
    /// A volume can hold a volume (`nested`), and is a job's: the tree areas hold neither.
    volume: bool,
    /// Its last use, in seconds: the lock file's mtime.
    used_s: i64,
    /// What the order of eviction goes by: its last use, and `image_grace_s` for an image.
    rank_s: i64,
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
    const budget: Budget = .init(io, lim.budget_ms);
    // What a deadline left first: nothing more goes until what already went is gone. Not synced
    // by this pass: a runner that died may not have synced it either.
    for (all_areas) |a| if (!removeDead(arena, io, s.root, a, .sync, budget)) return;
    const vols = listVolumes(arena, io, s.root) catch return;
    const trees = listTrees(arena, io, s.root, budget) catch return;
    measureOne(arena, io, vols, lim.remeasure_s);
    measureOne(arena, io, trees, lim.remeasure_s);
    var blobs = listBlobs(arena, io, s.root) catch return;
    var evicted = capped(arena, io, s.root, vols, lim.volumes_max_bytes, 0, lim, budget, "volumes");
    // A blob only saves a download, of an image already unpacked or not wanted since.
    var tree_bytes: u64 = 0;
    for (trees) |e| tree_bytes +|= e.bytes;
    const over_by = (tree_bytes +| blobs.bytes) -| lim.images_max_bytes;
    // An image unpacking has the blobs: it may be what took the area over, so wait for its end.
    if (lim.images_max_bytes > 0 and over_by > 0 and blobs.evict(arena, io, s.root, over_by))
        evicted = capped(arena, io, s.root, trees, lim.images_max_bytes, blobs.bytes, lim, budget, "images") or evicted;
    if (shortOf(arena, s)) |short| {
        var left = short;
        const before = blobs.bytes;
        _ = blobs.evict(arena, io, s.root, left);
        left -|= before - blobs.bytes;
        const all = std.mem.concat(arena, Entry, &.{ vols, trees }) catch return;
        evicted = floor(arena, io, s.root, all, &left, lim, budget) or evicted;
    }
    if (evicted) {
        dropRefs(arena, io, s.root);
        for (all_areas) |a| if (!removeDead(arena, io, s.root, a, .synced, budget)) return;
    }
}

/// What the disk is short of: `shortBy` by the store's limit.
pub fn shortOf(arena: Allocator, s: Store) ?u64 {
    return shortBy(arena, s.root, s.limits.min_free_pct);
}

/// Entries evicted, the longest unused first, until `left` bytes are gone, sparing what was used
/// in the last `recent_s`; whether any was. A size not known is measured first: an upgrade on a
/// nearly full disk finds nothing measured, and counting those as 0 would take them all. What a
/// walk cut short is the last to go in this pass, as how much it freed is not known.
fn floor(arena: Allocator, io: std.Io, root: []const u8, entries: []Entry, left: *u64, lim: Limits, budget: Budget) bool {
    std.mem.sort(Entry, entries, {}, olderFirst);
    var evicted = false;
    for (entries) |*e| {
        if (left.* == 0 or (evicted and budget.spent())) break;
        if (e.private or lim.recent_s > now(io) - e.used_s) continue;
        const whole = e.measured_s != 0 or measure(arena, io, e, measure_again_ms);
        if (!evictEntry(arena, io, root, e.*)) continue;
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
    return a.rank_s < b.rank_s;
}

/// `entries` evicted, the longest unused first, until they and `other` bytes are under `max`;
/// whether any was. One not measured yet is left, as what taking it would free is not known. A dead
/// runner's private copy goes first, cap or no cap. Each eviction syncs a directory, so the budget
/// counts here too.
fn capped(arena: Allocator, io: std.Io, root: []const u8, entries: []Entry, max: u64, other: u64, lim: Limits, budget: Budget, what: []const u8) bool {
    var total: u64 = other;
    for (entries) |e| total +|= e.bytes;
    var evicted = false;
    for (entries) |e| if (e.private and evictEntry(arena, io, root, e)) {
        total -|= e.bytes;
        evicted = true;
    };
    if (max == 0 or total <= max) return evicted;
    std.mem.sort(Entry, entries, {}, olderFirst);
    const t = now(io);
    for (entries) |e| {
        if (total <= max or (evicted and budget.spent())) break;
        if (e.private or e.measured_s == 0 or t - e.used_s < lim.idle_s) continue;
        if (!evictEntry(arena, io, root, e)) continue;
        total -|= e.bytes;
        evicted = true;
    }
    if (total > max) std.log.info("native: the {s} hold {d} MiB, over their cap of {d} MiB: " ++
        "what is left is in use or was used today", .{ what, total >> 20, max >> 20 });
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

/// The entries of the tree areas, what dead runners left of a tree they were making, and stray
/// lock files and sizes removed on the way: `.tmp-<key>` (`ensure`), `<name>.new-<n>`
/// (`volumes.adoptSeed`), each under the entry's lock, which its maker holds while it lives.
fn listTrees(arena: Allocator, io: std.Io, root: []const u8, budget: Budget) ![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    for (tree_areas) |a| {
        const dir_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, a });
        var d = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch continue;
        defer d.close(io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (try it.next(io)) |e| try names.append(arena, try arena.dupe(u8, e.name));
        for (names.items) |n| {
            const full = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir_path, n });
            if (std.mem.startsWith(u8, n, ".dead-")) continue;
            if (std.mem.startsWith(u8, n, ".tmp-")) {
                const key = n[".tmp-".len..];
                dropUnfinished(arena, io, full, try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir_path, key }), budget);
            } else if (std.mem.indexOf(u8, n, ".new-")) |at| {
                dropUnfinished(arena, io, full, try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir_path, n[0..at] }), budget);
            } else if (std.mem.endsWith(u8, n, ".lock")) {
                const entry = full[0 .. full.len - ".lock".len];
                if (!isDir(arena, entry)) dropStray(arena, io, entry);
            } else if (std.mem.endsWith(u8, n, ".size")) {
                if (!isDir(arena, full[0 .. full.len - ".size".len])) std.Io.Dir.cwd().deleteFile(io, full) catch {};
            } else if (isDir(arena, full) and isFile(arena, try std.fmt.allocPrint(arena, "{s}.lock", .{full}))) {
                if (out.items.len >= max_entries) return out.items;
                var e = try entryOf(arena, io, full, a, false, false);
                if (std.mem.eql(u8, a, "oci/images")) e.rank_s += image_grace_s;
                try out.append(arena, e);
            }
        }
    }
    return out.items;
}

/// `tree`, a dead maker's, removed if the lock of the entry it was for is free: as far as the
/// budget goes, and the next pass finds the rest.
fn dropUnfinished(arena: Allocator, io: std.Io, tree: []const u8, entry: []const u8, budget: Budget) void {
    const lock_path = std.fmt.allocPrint(arena, "{s}.lock", .{entry}) catch return;
    const lock = Store.lockBeside(arena, io, lock_path) catch return;
    defer lock.close(io);
    if (!flock(lock, lock_ex | lock_nb) or !Store.sameFile(arena, lock, lock_path)) return;
    _ = removeSome(arena, tree, io, budget);
}

/// The blobs, with what they take, and their lock's file: they have no job holding them, so an
/// eviction takes `oci/blobs.lock` exclusively, non-blocking, which an unpack holds shared.
const Blobs = struct {
    const Blob = struct { path: []const u8, used_s: i64, bytes: u64 };
    list: []Blob = &.{},
    bytes: u64 = 0,

    /// Blobs evicted, the oldest first, until `over` bytes of them are gone, what a dead runner
    /// left half fetched among them. False when an unpack holds them.
    fn evict(b: *Blobs, arena: Allocator, io: std.Io, root: []const u8, over: u64) bool {
        if (b.list.len == 0) return true;
        const path = std.fmt.allocPrint(arena, "{s}/oci/blobs.lock", .{root}) catch return false;
        const lock = Store.lockBeside(arena, io, path) catch return false;
        defer lock.close(io);
        if (!flock(lock, lock_ex | lock_nb)) return false;
        std.mem.sort(Blob, b.list, {}, struct {
            fn lt(_: void, x: Blob, y: Blob) bool {
                return x.used_s < y.used_s;
            }
        }.lt);
        var freed: u64 = 0;
        for (b.list) |blob| {
            if (freed >= over) break;
            std.Io.Dir.cwd().deleteFile(io, blob.path) catch continue;
            freed += blob.bytes;
        }
        b.bytes -|= freed;
        return true;
    }
};

fn listBlobs(arena: Allocator, io: std.Io, root: []const u8) !Blobs {
    const dir_path = try std.fmt.allocPrint(arena, "{s}/oci/blobs/sha256", .{root});
    var d = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return .{};
    defer d.close(io);
    var out: std.ArrayList(Blobs.Blob) = .empty;
    var total: u64 = 0;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (out.items.len >= max_entries) break;
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir_path, e.name });
        var st: linux.Statx = undefined;
        const z = try arena.dupeSentinel(u8, path, 0);
        const mask: linux.STATX = .{ .TYPE = true, .MTIME = true, .BLOCKS = true };
        if (linux.errno(linux.statx(linux.AT.FDCWD, z, linux.AT.SYMLINK_NOFOLLOW, mask, &st)) != .SUCCESS) continue;
        // A temporary file goes as a blob does, oldest first: only a live unpack holds one, and
        // none does while the lock is taken.
        const bytes = st.blocks * 512;
        total += bytes;
        try out.append(arena, .{ .path = path, .used_s = st.mtime.sec, .bytes = bytes });
    }
    return .{ .list = out.items, .bytes = total };
}

/// What a pinned index's record names when its image is gone: only a shortcut past the registry,
/// which a job would find leads nowhere, and `oci/refs/` would keep for ever.
fn dropRefs(arena: Allocator, io: std.Io, root: []const u8) void {
    const refs = std.fmt.allocPrint(arena, "{s}/oci/refs", .{root}) catch return;
    var d = std.Io.Dir.cwd().openDir(io, refs, .{ .iterate = true }) catch return;
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch null) |e| {
        const p = std.fmt.allocPrint(arena, "{s}/{s}", .{ refs, e.name }) catch return;
        const text = std.Io.Dir.cwd().readFileAlloc(io, p, arena, .limited(128)) catch continue;
        const manifest = std.mem.trim(u8, text, " \n");
        if (!std.mem.startsWith(u8, manifest, "sha256:")) continue;
        const hex = manifest["sha256:".len..];
        const base = std.fmt.allocPrint(arena, "{s}/oci/images/{s}", .{ root, hex }) catch return;
        const rootless = std.fmt.allocPrint(arena, "{s}.rootless", .{base}) catch return;
        if (!isDir(arena, base) and !isDir(arena, rootless)) std.Io.Dir.cwd().deleteFile(io, p) catch {};
    }
}

/// The volumes, stray lock files removed on the way.
fn listVolumes(arena: Allocator, io: std.Io, root: []const u8) ![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    try walkKeys(arena, io, try std.fmt.allocPrint(arena, "{s}/volumes", .{root}), &out, 0);
    return out.items;
}

/// The volumes under `dir`, a directory of a key's upper parts. A directory with a lock beside it
/// is a volume, a job's own content, which is never looked into: a volume inside it goes with it
/// (`innerLock`). One without is a part of a key, which no job can reach.
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
            try walkKeys(arena, io, full, out, depth + 1);
            continue;
        }
        if (out.items.len >= max_entries) return;
        try out.append(arena, try entryOf(arena, io, full, "volumes", true, std.mem.indexOf(u8, n, ".private-") != null));
    }
}

fn entryOf(arena: Allocator, io: std.Io, dir: []const u8, area: []const u8, volume: bool, private: bool) !Entry {
    const used_s = mtime(arena, try std.fmt.allocPrint(arena, "{s}.lock", .{dir})) orelse 0;
    var e: Entry = .{
        .dir = dir,
        .area = area,
        .volume = volume,
        .used_s = used_s,
        .rank_s = used_s,
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
    _ = io;
    const path = std.fmt.allocPrint(arena, "{s}.lock", .{dir}) catch return null;
    return Store.openPlain(arena, path);
}

/// What an eviction finds of the volume that may be inside the one it takes.
const Inner = union(enum) {
    /// A job holds it: the outer one stays.
    held,
    /// No job can: nothing regular can be made at its lock's name.
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
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    for (0..3) |_| {
        const rc = linux.openat(dir, name, flags, 0o644);
        switch (linux.errno(rc)) {
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
            else => return .none,
        }
        const fd = std.math.cast(linux.fd_t, rc) orelse return .none;
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
    // Used since the walk saw it, or become a part of a key's volume since (`walkKeys`).
    if (mtime(arena, lock_path) != e.used_s) return false;
    const up = std.fs.path.dirname(e.dir) orelse return false;
    if (isFile(arena, std.fmt.allocPrint(arena, "{s}.lock", .{up}) catch return false)) return false;
    const fd = Store.openRoot(arena, e.dir) catch return false;
    defer _ = linux.close(fd);
    const inner: Inner = if (e.volume) innerLock(fd) else .none;
    defer switch (inner) {
        .locked => |l| _ = linux.close(l),
        else => {},
    };
    if (inner == .held) return false;
    const dead = deadName(arena, io, root, e.area) catch return false;
    cwd.rename(e.dir, cwd, dead, io) catch return false;
    syncDirOf(arena, e.dir);
    syncDirOf(arena, dead);
    forget(arena, io, e.dir);
    return true;
}

fn deadName(arena: Allocator, io: std.Io, root: []const u8, area: []const u8) ![]const u8 {
    var raw: [8]u8 = undefined;
    io.random(&raw);
    return std.fmt.allocPrint(arena, "{s}/{s}/.dead-{s}", .{ root, area, &std.fmt.bytesToHex(raw, .lower) });
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

/// Whether what is under a dead name is known to be there for good: the runner that renamed it
/// may have died before it synced the rename (`evictEntry`), and which directory it came from is
/// not known here, so `.sync` syncs the filesystem. Once, a pass.
const Renames = enum { sync, synced };

/// Every `.dead-` entry of the area removed, as far as the budget goes. False only when the budget
/// stopped it, which tells the pass to free no more yet: one that cannot be removed is logged and
/// stops nothing, or it would stop every eviction for good.
fn removeDead(arena: Allocator, io: std.Io, root: []const u8, name: []const u8, renames: Renames, budget: Budget) bool {
    const dir_path = std.fmt.allocPrint(arena, "{s}/{s}", .{ root, name }) catch return false;
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return true;
    defer dir.close(io);
    var dead: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (!std.mem.startsWith(u8, e.name, ".dead-")) continue;
        dead.append(arena, arena.dupe(u8, e.name) catch return false) catch return false;
    }
    if (dead.items.len == 0) return true;
    if (renames == .sync and linux.errno(linux.syncfs(dir.handle)) != .SUCCESS) {
        std.log.warn("native: cannot sync {s}; what is dead there stays until it can be", .{dir_path});
        return true;
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

/// How deep `removeSome` goes before it moves the directory it is in up to the tree's top.
const max_chain = 512;

/// As much of the tree `path` removed as `budget` allows, a directory's entries before it, with two
/// descriptors open and no path kept, to any depth, through no symlink. Nothing else uses a dead
/// tree. What the budget leaves stays under the dead name for a later call, which starts at the
/// top: so what is deep is moved up on the way down, in pieces of `max_chain`, or a chain deeper
/// than a pass can walk would never lose a directory. A name that is no directory just goes.
fn removeSome(arena: Allocator, path: []const u8, io: std.Io, budget: Budget) Removal {
    const up_path = std.fs.path.dirname(path) orelse return .stuck;
    const up = Store.openRoot(arena, up_path) catch return .stuck;
    defer _ = linux.close(up);
    const base = arena.dupeSentinel(u8, std.fs.path.basename(path), 0) catch return .stuck;
    switch (linux.errno(linux.unlinkat(up, base, 0))) {
        .SUCCESS, .NOENT => return .gone,
        .ISDIR, .PERM => {},
        else => return .stuck,
    }
    _ = linux.fchmodat(up, base, 0o700);
    const root = Store.openDirAt(up, base) catch return .stuck;
    defer _ = linux.close(root);
    var top: linux.Statx = undefined;
    if (linux.errno(linux.statx(root, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &top)) != .SUCCESS) return .stuck;
    var cur = root;
    defer if (cur != root) {
        _ = linux.close(cur);
    };
    var depth: u32 = 0;
    var name: [256:0]u8 = undefined;
    while (true) {
        const down = emptyOut(io, cur, &name, budget) catch |e| {
            if (e == error.Spent) return .spent;
            std.log.warn("native: cannot remove all of {s}: {t}", .{ path, e });
            return .stuck;
        };
        if (down) |n| {
            const child = Store.openDirAt(cur, n) catch return .stuck;
            var st: linux.Statx = undefined;
            depth += 1;
            if (depth >= max_chain and linux.errno(linux.statx(child, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &st)) == .SUCCESS) {
                var cut: [32:0]u8 = undefined;
                // Refused when a name so is there already: it is only deeper for now.
                if (std.fmt.bufPrintSentinel(&cut, ".cut-{d}", .{st.ino}, 0)) |to| {
                    if (linux.errno(linux.renameat2(cur, n, root, to, .{ .NOREPLACE = true })) == .SUCCESS) depth = 1;
                } else |_| {}
            }
            if (cur != root) _ = linux.close(cur);
            cur = child;
            continue;
        }
        if (cur == root) break;
        // Up, by `..`: back to the directory above, whose listing now finds this one empty.
        const parent = Store.openDirAt(cur, "..") catch return .stuck;
        _ = linux.close(cur);
        var st: linux.Statx = undefined;
        const at_top = linux.errno(linux.statx(parent, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &st)) == .SUCCESS and st.ino == top.ino;
        if (at_top) {
            _ = linux.close(parent);
            cur = root;
            depth = 0;
        } else {
            cur = parent;
            depth -|= 1;
        }
    }
    return if (linux.errno(linux.unlinkat(up, base, linux.AT.REMOVEDIR)) == .SUCCESS) .gone else .stuck;
}

/// The directory `fd`'s files unlinked and its empty directories removed, until the first
/// directory with something in it, whose name is returned to go into (`name` holds it); null when
/// nothing is left. `error.Spent` when the budget ran out.
fn emptyOut(io: std.Io, fd: linux.fd_t, name: *[256:0]u8, budget: Budget) !?[:0]const u8 {
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
            if (seen % 64 == 0 and budget.spent()) return .{ .bytes = total, .whole = false };
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
    try testing.expectEqual(Removal.gone, removeSome(f.arena(), dir, io, .init(io, 60_000)));
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
    _ = floor(f.arena(), testing.io, f.s.root, try listVolumes(f.arena(), testing.io, f.s.root), &left, f.s.limits, .init(testing.io, 5000));
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
    try testing.expect(!evictEntry(f.arena(), testing.io, f.s.root, entries[0]));
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

const OciStore = @import("oci/Store.zig");

const TreeMaker = struct {
    fn make(_: *anyopaque, dir: []const u8) anyerror!void {
        var buf: [4096]u8 = undefined;
        const p = try std.fmt.bufPrint(&buf, "{s}/f", .{dir});
        try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = p, .data = &(@as([8192]u8, @splat('t'))) });
    }
};

fn testTree(f: *Fixture, kind: []const u8, key: []const u8, bytes: u64, days: i64) ![]const u8 {
    const oci: OciStore = .{ .root = f.s.root };
    try oci.prepare(f.arena(), testing.io);
    try f.tmp.dir.createDirPath(testing.io, kind);
    var unused: u8 = 0;
    const r = try oci.ensure(f.arena(), testing.io, kind, key, .{ .ptr = &unused, .makeFn = TreeMaker.make });
    r.lock.close(testing.io);
    try std.Io.Dir.cwd().writeFile(testing.io, .{
        .sub_path = try std.fmt.allocPrint(f.arena(), "{s}.size", .{r.dir}),
        .data = try std.fmt.allocPrint(f.arena(), "{d}\n", .{bytes}),
    });
    try f.age(r.dir, days);
    return r.dir;
}

test "native eviction: trees go past their cap, a held one stays, and a rootfs goes before its image" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const old_rootfs = try testTree(f, "rootfs", "r1", 6000, 30);
    // Pulled moments after the rootfs was last used, as every job using it does.
    const its_image = try testTree(f, "oci/images", "i1", 6000, 30);
    const in_use = try testTree(f, "rootfs", "r2", 6000, 40);
    const seed = try testTree(f, "seeds", "x86_64-0.16.0-root", 6000, 20);
    const held = (try OciStore.holdDir(f.arena(), io, in_use)).?;
    defer held.close(io);
    // `holdDir` touched its lock: a pass goes by that, so make it old again, as if used long ago.
    try f.age(in_use, 40);
    f.s.limits = .{ .images_max_bytes = 19_000, .volumes_max_bytes = 0, .min_free_pct = 0 };
    run(f.s, io);
    try testing.expect(f.there(in_use));
    try testing.expect(!f.there(old_rootfs));
    try testing.expect(f.there(its_image) and f.there(seed));
    f.s.limits.images_max_bytes = 13_000;
    run(f.s, io);
    try testing.expect(!f.there(its_image));
    try testing.expect(f.there(seed));
    // And the seed goes to the cap too, and to the next job's build.
    f.s.limits.images_max_bytes = 7000;
    run(f.s, io);
    try testing.expect(!f.there(seed));
    // A key used today stays, whatever the cap: the base image is not thrown away on a loop.
    const base = try testTree(f, "oci/images", "i2", 6000, 0);
    f.s.limits.images_max_bytes = 1;
    for (0..3) |_| run(f.s, io);
    try testing.expect(f.there(base));
}

test "native eviction: what a dead maker left goes, what a live one is making stays" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const cwd = std.Io.Dir.cwd();
    const oci: OciStore = .{ .root = f.s.root };
    try oci.prepare(arena, io);
    try cwd.createDirPath(io, try std.fmt.allocPrint(arena, "{s}/seeds", .{f.s.root}));
    for ([_][]const u8{ "rootfs/.tmp-dead", "rootfs/.tmp-live", "seeds/z.new-00" }) |d|
        try f.tmp.dir.createDirPath(io, d);
    const live = try OciStore.lockDir(arena, io, try std.fmt.allocPrint(arena, "{s}/rootfs/live", .{f.s.root}), 2);
    defer live.close(io);
    f.s.limits = .{ .images_max_bytes = 0, .volumes_max_bytes = 0, .min_free_pct = 0 };
    run(f.s, io);
    try testing.expectError(error.FileNotFound, f.tmp.dir.access(io, "rootfs/.tmp-dead", .{}));
    try testing.expectError(error.FileNotFound, f.tmp.dir.access(io, "seeds/z.new-00", .{}));
    try f.tmp.dir.access(io, "rootfs/.tmp-live", .{});
    // And the locks those dead makers' sweeps took or made go next time.
    run(f.s, io);
    try testing.expectError(error.FileNotFound, f.tmp.dir.access(io, "rootfs/dead.lock", .{}));
    try f.tmp.dir.access(io, "rootfs/live.lock", .{});
}

test "native eviction: the blobs go first, the oldest first, and not while an image unpacks" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const oci: OciStore = .{ .root = f.s.root };
    try oci.prepare(arena, io);
    const image = try testTree(f, "oci/images", "i1", 1000, 30);
    const names = [_][]const u8{ "old", "new" };
    for (names, [_]i64{ 1000, 2000 }) |n, sec| {
        const p = try std.fmt.allocPrintSentinel(arena, "{s}/oci/blobs/sha256/{s}", .{ f.s.root, n }, 0);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = &(@as([40960]u8, @splat('b'))) });
        const t = [2]linux.timespec{ .{ .sec = sec, .nsec = 0 }, .{ .sec = sec, .nsec = 0 } };
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.utimensat(linux.AT.FDCWD, p, &t, 0)));
    }
    f.s.limits = .{ .images_max_bytes = 50_000, .volumes_max_bytes = 0, .min_free_pct = 0 };
    const unpacking = try std.Io.Dir.cwd().createFile(io, try oci.blobsLock(arena), .{ .truncate = false });
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.flock(unpacking.handle, 1)));
    run(f.s, io);
    try f.tmp.dir.access(io, "oci/blobs/sha256/old", .{});
    unpacking.close(io);
    run(f.s, io);
    try testing.expectError(error.FileNotFound, f.tmp.dir.access(io, "oci/blobs/sha256/old", .{}));
    try f.tmp.dir.access(io, "oci/blobs/sha256/new", .{});
    try testing.expect(f.there(image));
}

test "native eviction: a pin's record goes with its image, and one whose image is here stays" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const hex_gone: [64]u8 = @splat('a');
    const hex_kept: [64]u8 = @splat('b');
    const oci: OciStore = .{ .root = f.s.root };
    try oci.prepare(arena, io);
    const gone = try testTree(f, "oci/images", &hex_gone, 1000, 30);
    _ = try testTree(f, "oci/images", &hex_kept, 1000, 0);
    for ([_][]const u8{ &hex_gone, &hex_kept }) |h|
        try f.tmp.dir.writeFile(io, .{
            .sub_path = try std.fmt.allocPrint(arena, "oci/refs/{s}.amd64", .{h}),
            .data = try std.fmt.allocPrint(arena, "sha256:{s}", .{h}),
        });
    f.s.limits = .{ .images_max_bytes = 1500, .volumes_max_bytes = 0, .min_free_pct = 0 };
    run(f.s, io);
    try testing.expect(!f.there(gone));
    try testing.expectError(error.FileNotFound, f.tmp.dir.access(io, "oci/refs/" ++ hex_gone ++ ".amd64", .{}));
    try f.tmp.dir.access(io, "oci/refs/" ++ hex_kept ++ ".amd64", .{});
}

fn raceTree(r: *Race, arena: Allocator, i: usize, n: usize) !void {
    const io = testing.io;
    const oci: OciStore = .{ .root = r.s.root };
    const keys = [_][]const u8{ "a", "b", "c" };
    const key = keys[(i + n) % keys.len];
    const got = try oci.ensure(arena, io, "rootfs", key, .{ .ptr = r, .makeFn = TreeMaker.make });
    defer got.lock.close(io);
    if (got.made) _ = r.fresh.fetchAdd(1, .monotonic);
    const file = try std.fmt.allocPrint(arena, "{s}/f", .{got.dir});
    for (0..2) |_| {
        const text = std.Io.Dir.cwd().readFileAlloc(io, file, arena, .limited(16 << 10)) catch |e|
            return r.fault("the tree {s} went while a job held it: {t}", .{ key, e });
        if (text.len != 8192) r.fault("the tree {s} is {d} bytes", .{ key, text.len });
        try io.sleep(.fromMilliseconds(std.math.cast(i64, n % 3).?), .awake);
    }
}

test "native eviction: a rootfs's fingerprint does not move while a sibling sharing its files goes" {
    const f = try Fixture.init();
    defer f.deinit();
    const arena = f.arena();
    const io = testing.io;
    const cwd = std.Io.Dir.cwd();
    const store = f.s.root;
    const r1 = try std.fmt.allocPrint(arena, "{s}/rootfs/k/rootfs", .{store});
    const dead = try std.fmt.allocPrint(arena, "{s}/rootfs/.dead-1", .{store});
    try cwd.createDirPath(io, r1);
    try cwd.createDirPath(io, dead);
    for (0..2000) |i| {
        const src = try std.fmt.allocPrintSentinel(arena, "{s}/f{d}", .{ r1, i }, 0);
        const lnk = try std.fmt.allocPrintSentinel(arena, "{s}/f{d}", .{ dead, i }, 0);
        try cwd.writeFile(io, .{ .sub_path = src, .data = "x" });
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.link(src, lnk)));
    }
    const first = try Store.rootfsFingerprint(arena, io, r1, store);
    // A pass cut short, as often as it takes.
    while (removeSome(arena, dead, io, .init(io, 1)) != .gone)
        try testing.expectEqualSlices(u8, &first, &try Store.rootfsFingerprint(arena, io, r1, store));
    try testing.expectEqualSlices(u8, &first, &try Store.rootfsFingerprint(arena, io, r1, store));
}

test "native eviction: jobs racing collects never lose a tree they hold, and make one at a time" {
    const f = try Fixture.init();
    defer f.deinit();
    const oci: OciStore = .{ .root = f.s.root };
    try oci.prepare(f.arena(), testing.io);
    f.s.limits = .{ .images_max_bytes = 1, .volumes_max_bytes = 0, .min_free_pct = 0, .idle_s = 0, .recent_s = 0, .remeasure_s = 0 };
    try Store.prepare(f.arena(), testing.io, f.s.root, .{ .check_parents = false });
    var r: Race = .{ .s = f.s, .deadline_ms = std.Io.Clock.awake.now(testing.io).toMilliseconds() + 1500 };
    try r.go(raceTree);
}

test "native eviction: a job that waited on a lock an eviction removed does not hold what is there now" {
    const f = try Fixture.init();
    defer f.deinit();
    const io = testing.io;
    const arena = f.arena();
    const oci: OciStore = .{ .root = f.s.root };
    try oci.prepare(arena, io);
    const dir = try testTree(f, "rootfs", "k", 10, 0);
    const lock_path = try std.fmt.allocPrint(arena, "{s}.lock", .{dir});
    // An eviction under way: the lock held exclusively, the job waiting on it.
    const eviction = try OciStore.lockDir(arena, io, dir, lock_ex);
    const Job = struct {
        got: ?std.Io.File = null,
        fn run1(j: *@This(), path: []const u8) void {
            var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer a.deinit();
            j.got = OciStore.holdDir(a.allocator(), testing.io, path) catch null;
        }
    };
    var job: Job = .{};
    const t: std.Thread = try .spawn(.{}, Job.run1, .{ &job, dir });
    try io.sleep(.fromMilliseconds(100), .awake);
    // It renames the tree, removes the lock file and lets go, and another runner makes the key
    // again meanwhile, with a lock file of its own.
    try std.Io.Dir.cwd().deleteFile(io, lock_path);
    const again = try OciStore.lockDir(arena, io, dir, 1);
    defer again.close(io);
    eviction.close(io);
    t.join();
    defer job.got.?.close(io);
    try testing.expect(Store.sameFile(arena, job.got.?, lock_path));
}
