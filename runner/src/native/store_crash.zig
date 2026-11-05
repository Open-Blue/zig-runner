//! The layer store across a crash and across a disk that fails writes (`Store.zig`, and the
//! rename-published trees of `oci/Store.zig` and `volumes.zig`): the half of a test that
//! `.github/scripts/store-crash.sh` drives on a throwaway machine, where root can put a
//! device-mapper target under an ext4 (dm-log-writes records every block write, so the disk can
//! be put back as it was at each flush; dm-flakey makes writes fail). This file runs the store's
//! operations and checks the store; the script owns the devices. Without
//! ZIG_TEST_STORE_CRASH it skips, so `zig build test` is what it was.
//!
//! ZIG_TEST_STORE_CRASH is `MODE ROOT SCRATCH ARG`: ROOT is on the disk under test, SCRATCH is on
//! another (what is expected is built there, never on the disk that crashes).
//!
//!   write   runs step ARG (1-6) of a sequence, as a job would, and marks the log at the points
//!           the checks need (ZIG_TEST_STORE_CRASH_MARK NAME):
//!             1  a job publishes three small layers (`syncTree`) and syncs the layers' directory;
//!             2  the next publishes a large one (over `sync_tree_max` entries: `syncfs`) and a small
//!                one;
//!             3  the first job after a reboot (the boot mark removed): `checkOncePerBoot`, then
//!                one more small layer;
//!             4  `collect` over a cap that evicts most, then one more layer;
//!             5  `oci.Store.ensure` makes a directory;
//!             6  `volumes.adoptSeed` makes a seed.
//!   verify  what a job finds on a disk put back to a point in the log: the first job after the
//!           crash is a job after a reboot (`checkOncePerBoot`), and then no layer `open` accepts
//!           differs from what was published (its tree's digest, its record), no directory
//!           `ensure` or `adoptSeed` published differs, and no layer a job had finished and
//!           synced (ARG: the last mark the log passed) is missing, unless a collect may have
//!           evicted it.
//!   corrupt a layer changed on purpose (ARG: `truncate` or `flip`), for the script to show that
//!           `verify` fails on it.
//!   fail    a publish on a disk that fails writes (ZIG_TEST_STORE_CRASH_FLIP on|off switches
//!           them; ARG: `sync-tree`, `small`, `large`, `cursor` or `no-cursor`): it must fail,
//!           and publish nothing.
//!   absent  that no layer is published under ROOT (after the disk was mounted again).
//!
//! Each prints what it checked, and fails with what was wrong.

const std = @import("std");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const OciStore = @import("oci/Store.zig");
const volumes = @import("volumes.zig");
const print = std.fmt.allocPrint;

const spec_env = "ZIG_TEST_STORE_CRASH";
const mark_env = "ZIG_TEST_STORE_CRASH_MARK";
const flip_env = "ZIG_TEST_STORE_CRASH_FLIP";

/// The layers the sequence publishes, in order (step 1: a, b, c; 2: big, d; 3: e; 4: f).
const names = [_][]const u8{ "a", "b", "c", "big", "d", "e", "f" };
/// Over `Store.sync_tree_max` entries, whatever it is: directories of 30 files.
const big = "big";
const ensure_key = "k1";
const seed_cache = "root/.cache/zig";
const record_fc = "::zig-file-command::ran\nj1\n";

fn keyOf(name: []const u8) Store.Key {
    var kh: Store.KeyHasher = .plain(name);
    return kh.final();
}

fn logOf(arena: Allocator, name: []const u8) ![]const u8 {
    return print(arena, "the log of {s}\n", .{name});
}

/// A tree of files whose bytes are the name's alone, `dir` made if need be: the same on every
/// call, so what a layer should hold is built again to be compared with what it holds.
fn makeTree(arena: Allocator, io: std.Io, dir: []const u8, name: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var prng: std.Random.DefaultPrng = .init(std.hash.Wyhash.hash(0, name));
    const rand = prng.random();
    try cwd.createDirPath(io, dir);
    if (std.mem.eql(u8, name, big)) {
        for (0..Store.sync_tree_max / 30 + 2) |d| for (0..30) |i| {
            try cwd.createDirPath(io, try print(arena, "{s}/d{d}", .{ dir, d }));
            const data = try arena.alloc(u8, if (i == 0) 70_000 else 4096);
            rand.bytes(data);
            try cwd.writeFile(io, .{ .sub_path = try print(arena, "{s}/d{d}/f{d}", .{ dir, d, i }), .data = data });
        };
        return;
    }
    try cwd.createDirPath(io, try print(arena, "{s}/d/e", .{dir}));
    for (0..5) |i| {
        const data = try arena.alloc(u8, 1 + rand.uintLessThan(usize, 9000));
        rand.bytes(data);
        const sub = if (i < 2) "" else if (i < 4) "d/" else "d/e/";
        try cwd.writeFile(io, .{ .sub_path = try print(arena, "{s}/{s}f{d}", .{ dir, sub, i }), .data = data });
    }
    try cwd.writeFile(io, .{ .sub_path = try print(arena, "{s}/empty", .{dir}), .data = "" });
    try cwd.symLink(io, "d/f2", try print(arena, "{s}/link", .{dir}), .{});
    // Too long for the inode (ext4 keeps a target of up to 59 bytes there): it takes a block of
    // its own, which `syncTree` never fsyncs (it skips symlinks) and the directory's commit must carry.
    const long_target = try print(arena, "d/e/{s}-{s}-the-target-of-a-symlink-too-long-for-its-inode-and-so-kept-in-a-block-of-its-own-on-disk", .{ name, name });
    try cwd.symLink(io, long_target, try print(arena, "{s}/longlink", .{dir}), .{});
}

fn digestOf(arena: Allocator, io: std.Io, dir: []const u8) !Store.Key {
    return Store.treeDigest(arena, io, dir, .content, .host);
}

/// What `name`'s layer holds, as a digest, built in the scratch directory.
fn expectedDigest(arena: Allocator, io: std.Io, scratch: []const u8, name: []const u8) !Store.Key {
    const dir = try print(arena, "{s}/expected/{s}", .{ scratch, name });
    if (!exists(io, dir)) try makeTree(arena, io, dir, name);
    return digestOf(arena, io, dir);
}

/// What a seed holds at its directory, built in the scratch directory.
fn expectedSeed(arena: Allocator, io: std.Io, scratch: []const u8) !Store.Key {
    const dir = try print(arena, "{s}/expected/seed", .{scratch});
    const zig = try print(arena, "{s}/{s}", .{ dir, seed_cache });
    if (!exists(io, dir)) {
        try makeTree(arena, io, zig, "seed");
        try std.Io.Dir.cwd().createDirPath(io, try print(arena, "{s}/p", .{zig}));
        // `adoptSeed` makes these with the mode 0755 whatever the umask.
        for ([_][]const u8{ "root", "root/.cache", "root/.cache/zig/p" }) |d|
            _ = linux.chmod(try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ dir, d }, 0), 0o755);
    }
    return digestOf(arena, io, dir);
}

const Spec = struct {
    mode: []const u8,
    root: []const u8,
    scratch: []const u8,
    arg: []const u8,

    fn store(sp: Spec, arena: Allocator) ![]const u8 {
        return print(arena, "{s}/store", .{sp.root});
    }
};

/// Runs the script ZIG_TEST_STORE_CRASH_MARK / _FLIP names, when it is set.
fn hook(io: std.Io, env: *const std.process.Environ.Map, name: []const u8, arg: []const u8) !void {
    const cmd = env.get(name) orelse return;
    var child = try std.process.spawn(io, .{
        .argv = &.{ cmd, arg },
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        std.debug.print("{s} {s}: {any}\n", .{ cmd, arg, term });
        return error.HookFailed;
    }
}

test "native store crash: the half of the crash and write-error tests that runs the store" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const text = env.get(spec_env) orelse {
        std.debug.print("native store crash: skipped ({s} is not set; store-crash.sh sets it)\n", .{spec_env});
        return error.SkipZigTest;
    };
    var f = std.mem.splitScalar(u8, text, ' ');
    const sp: Spec = .{
        .mode = f.next() orelse return error.BadSpec,
        .root = f.next() orelse return error.BadSpec,
        .scratch = f.next() orelse return error.BadSpec,
        .arg = f.next() orelse "",
    };
    if (std.mem.eql(u8, sp.mode, "write")) return write(arena, io, &env, sp);
    if (std.mem.eql(u8, sp.mode, "verify")) return verify(arena, io, sp);
    if (std.mem.eql(u8, sp.mode, "corrupt")) return corrupt(arena, io, sp);
    if (std.mem.eql(u8, sp.mode, "fail")) return fail(arena, io, &env, sp);
    if (std.mem.eql(u8, sp.mode, "absent")) return absent(arena, io, sp);
    return error.BadSpec;
}

/// A step's layer, built under ROOT and published as a job's step would be.
fn publishLayer(s: Store, arena: Allocator, io: std.Io, sp: Spec, name: []const u8) !void {
    const upper = try print(arena, "{s}/uppers/{s}", .{ sp.root, name });
    try makeTree(arena, io, upper, name);
    const key = keyOf(name);
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, key, &never);
    defer kl.close(io);
    const l = try s.publish(arena, io, key, .step, upper, .{ .log = try logOf(arena, name), .fc = record_fc });
    l.lock.close(io);
}

/// A job's beginning and end: its descriptor on the store's filesystem (`syncCursor`), and the
/// layers' directory synced at the end (`syncLayers`).
fn job(arena: Allocator, io: std.Io, sp: Spec) !Store {
    const root = try sp.store(arena);
    try Store.prepare(arena, io, root, .{ .check_parents = false });
    return .{ .root = root, .sync_fd = Store.syncCursor(arena, root) };
}

fn write(arena: Allocator, io: std.Io, env: *const std.process.Environ.Map, sp: Spec) !void {
    const step = try std.fmt.parseInt(u8, sp.arg, 10);
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, try print(arena, "{s}/uppers", .{sp.root}));
    var s = try job(arena, io, sp);
    defer if (s.sync_fd) |fd| {
        _ = linux.close(fd);
    };
    switch (step) {
        1 => {
            s.checkOncePerBoot(arena, io);
            for (names[0..3]) |n| try publishLayer(s, arena, io, sp, n);
            s.syncLayers(arena);
        },
        2 => {
            for ([_][]const u8{ big, "d" }) |n| try publishLayer(s, arena, io, sp, n);
            s.syncLayers(arena);
        },
        3 => {
            // A reboot: the next job to start is the first of its boot.
            cwd.deleteFile(io, try print(arena, "{s}/boot", .{s.root})) catch {};
            s.checkOncePerBoot(arena, io);
            try publishLayer(s, arena, io, sp, "e");
            s.syncLayers(arena);
        },
        4 => {
            // Uses every layer in turn, the large one last, and keeps room for it and little else.
            for ([_][]const u8{ "a", "b", "c", "d", "e", big }) |n| {
                const hit = (try s.open(arena, io, keyOf(n))) orelse return error.LayerMissing;
                hit.layer.lock.close(io);
            }
            _ = try expectedDigest(arena, io, sp.scratch, big);
            const kept = try Store.treeBytes(arena, io, try print(arena, "{s}/expected/{s}", .{ sp.scratch, big }));
            s.max_bytes = kept + 40_000;
            try hook(io, env, mark_env, "before-collect");
            s.collect(arena, io);
            try publishLayer(s, arena, io, sp, "f");
            s.syncLayers(arena);
        },
        5 => {
            const oci: OciStore = .{ .root = try print(arena, "{s}/oci", .{sp.root}) };
            try oci.prepare(arena, io);
            var unused: u8 = 0;
            const r = try oci.ensure(arena, io, "rootfs", ensure_key, .{ .ptr = &unused, .makeFn = makeRootfs });
            if (!r.made) return error.NotMade;
        },
        6 => {
            const base = try print(arena, "{s}/oci", .{sp.root});
            const built = try print(arena, "{s}/seed-built", .{base});
            try makeTree(arena, io, built, "seed");
            try cwd.createDirPath(io, try print(arena, "{s}/seeds", .{base}));
            try volumes.adoptSeed(arena, io, built, .{
                .seed = .{ .version = "0.17.0", .sha256 = "" },
                .dir = try print(arena, "{s}/seeds/z1", .{base}),
                .cache = seed_cache,
            }, try print(arena, "{s}/no-rootfs", .{base}), null);
        },
        else => return error.BadSpec,
    }
    try hook(io, env, mark_env, try print(arena, "after-{d}", .{step}));
    std.debug.print("native store crash: step {d} done\n", .{step});
}

/// What `ensure` makes: the tree of the name "rootfs".
fn makeRootfs(_: *anyopaque, dir: []const u8) anyerror!void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    try makeTree(a.allocator(), std.testing.io, dir, "rootfs");
}

/// Layers' names a job that had finished and synced would have to find, as of the last mark the
/// log passed. Not after the mark before a collect, which may have evicted any.
fn required(mark: []const u8) []const []const u8 {
    const M = struct { mark: []const u8, names: []const []const u8 };
    const table = [_]M{
        .{ .mark = "after-1", .names = names[0..3] },
        .{ .mark = "after-2", .names = names[0..5] },
        .{ .mark = "after-3", .names = names[0..6] },
        .{ .mark = "after-4", .names = names[6..7] },
        .{ .mark = "after-5", .names = names[6..7] },
        .{ .mark = "after-6", .names = names[6..7] },
        .{ .mark = "synced", .names = names[6..7] },
    };
    for (table) |m| if (std.mem.eql(u8, m.mark, mark)) return m.names;
    return &.{};
}

const Faults = struct {
    arena: Allocator,
    list: std.ArrayList([]const u8) = .empty,

    fn add(f: *Faults, comptime fmt: []const u8, args: anytype) !void {
        try f.list.append(f.arena, try print(f.arena, fmt, args));
    }

    fn done(f: *Faults, what: []const u8) !void {
        for (f.list.items) |l| std.debug.print("native store crash: VIOLATION {s}\n", .{l});
        if (f.list.items.len > 0) {
            std.debug.print("native store crash: {s}: {d} violations\n", .{ what, f.list.items.len });
            return error.TestUnexpectedResult;
        }
    }
};

/// Why a tree differs, when its long symlink (a target ext4 keeps in a block) is the reason.
fn longLinkLost(arena: Allocator, name: []const u8, fs: []const u8) ![]const u8 {
    if (std.mem.eql(u8, name, big)) return "";
    var buf: [linux.PATH_MAX]u8 = undefined;
    const p = try std.fmt.allocPrintSentinel(arena, "{s}/longlink", .{fs}, 0);
    const rc = linux.readlink(p, &buf, buf.len);
    if (linux.errno(rc) != .SUCCESS) return try print(arena, " (its long symlink: {t})", .{linux.errno(rc)});
    if (rc == 0 or buf[0] == 0) return " (its long symlink's target is empty)";
    if (std.mem.indexOfScalar(u8, buf[0..rc], 0) != null) return " (its long symlink's target has zeros)";
    return "";
}

fn exists(io: std.Io, p: []const u8) bool {
    return if (std.Io.Dir.cwd().access(io, p, .{})) |_| true else |_| false;
}

fn verify(arena: Allocator, io: std.Io, sp: Spec) !void {
    var faults: Faults = .{ .arena = arena };
    // The first job after the crash is the first of a boot.
    const s: Store = .{ .root = try sp.store(arena) };
    std.Io.Dir.cwd().deleteFile(io, try print(arena, "{s}/boot", .{s.root})) catch {};
    s.checkOncePerBoot(arena, io);

    var hits: usize = 0;
    for (names) |n| {
        const key = keyOf(n);
        const want = required(sp.arg);
        const hit = (s.open(arena, io, key) catch |e| {
            try faults.add("layer {s}: open failed: {s}", .{ n, @errorName(e) });
            continue;
        }) orelse {
            for (want) |w| if (std.mem.eql(u8, w, n))
                try faults.add("layer {s} missing: its job had finished and synced (last mark {s})", .{ n, sp.arg });
            continue;
        };
        defer hit.layer.lock.close(io);
        hits += 1;
        const got = digestOf(arena, io, hit.layer.fs) catch |e| {
            try faults.add("layer {s}: its tree cannot be read: {s}", .{ n, @errorName(e) });
            continue;
        };
        const exp = try expectedDigest(arena, io, sp.scratch, n);
        if (!std.mem.eql(u8, &got, &exp)) {
            try faults.add("layer {s}: a hit whose tree is not what was published{s}", .{ n, try longLinkLost(arena, n, hit.layer.fs) });
        }
        if (!std.mem.eql(u8, hit.rec.log, try logOf(arena, n)) or !std.mem.eql(u8, hit.rec.fc, record_fc))
            try faults.add("layer {s}: a hit whose record is not what was published", .{n});
    }
    // Nothing else is a layer.
    if (std.Io.Dir.cwd().openDir(io, try print(arena, "{s}/layers", .{s.root}), .{ .iterate = true })) |d_const| {
        var d = d_const;
        defer d.close(io);
        var it = d.iterate();
        while (try it.next(io)) |e| {
            if (e.name[0] == '.') continue;
            const known = for (names) |n| {
                if (std.mem.eql(u8, &Store.hex(keyOf(n)), e.name)) break true;
            } else false;
            if (!known) try faults.add("layer {s} is not one that was published", .{e.name});
        }
    } else |_| {}

    // What `ensure` and `adoptSeed` published whole.
    var dirs: usize = 0;
    const ensured = try print(arena, "{s}/oci/rootfs/{s}", .{ sp.root, ensure_key });
    if (exists(io, ensured)) {
        dirs += 1;
        const got = digestOf(arena, io, ensured) catch |e| blk: {
            try faults.add("ensure's directory cannot be read: {s}", .{@errorName(e)});
            break :blk std.mem.zeroes(Store.Key);
        };
        if (!std.mem.eql(u8, &got, &try expectedDigest(arena, io, sp.scratch, "rootfs")))
            try faults.add("ensure published a directory that is not what its maker made", .{});
    }
    const seeded = try print(arena, "{s}/oci/seeds/z1", .{sp.root});
    if (exists(io, seeded)) {
        dirs += 1;
        const got = digestOf(arena, io, seeded) catch |e| blk: {
            try faults.add("the seed cannot be read: {s}", .{@errorName(e)});
            break :blk std.mem.zeroes(Store.Key);
        };
        if (!std.mem.eql(u8, &got, &try expectedSeed(arena, io, sp.scratch)))
            try faults.add("adoptSeed published a seed that is not what was built", .{});
    }
    std.debug.print("native store crash: after {s}: {d} layers hit, {d} directories published, whole\n", .{ sp.arg, hits, dirs });
    try faults.done("verify");
}

/// A layer's first file changed in place: shorter by a byte, or one byte different.
fn corrupt(arena: Allocator, io: std.Io, sp: Spec) !void {
    const cwd = std.Io.Dir.cwd();
    const path = try print(arena, "{s}/store/layers/{s}/fs/f0", .{ sp.root, &Store.hex(keyOf("f")) });
    const data = try cwd.readFileAlloc(io, path, arena, .limited(1 << 20));
    if (std.mem.eql(u8, sp.arg, "truncate")) {
        try cwd.writeFile(io, .{ .sub_path = path, .data = data[0 .. data.len - 1] });
    } else {
        data[0] ^= 1;
        try cwd.writeFile(io, .{ .sub_path = path, .data = data });
    }
    std.debug.print("native store crash: changed {s} ({s})\n", .{ path, sp.arg });
}

fn absent(arena: Allocator, io: std.Io, sp: Spec) !void {
    const s: Store = .{ .root = try sp.store(arena) };
    for (names) |n| {
        if (try s.open(arena, io, keyOf(n))) |hit| {
            hit.layer.lock.close(io);
            std.debug.print("native store crash: layer {s} is published\n", .{n});
            return error.TestUnexpectedResult;
        }
    }
    // A journal that aborted may have lost the directories too.
    var d = std.Io.Dir.cwd().openDir(io, try print(arena, "{s}/layers", .{s.root}), .{ .iterate = true }) catch |e| {
        std.debug.print("native store crash: no layer is published (layers/: {s})\n", .{@errorName(e)});
        return;
    };
    defer d.close(io);
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (e.name[0] != '.') {
            std.debug.print("native store crash: {s} is in layers/\n", .{e.name});
            return error.TestUnexpectedResult;
        }
    }
    std.debug.print("native store crash: no layer is published\n", .{});
}

/// A disk that fails writes, and the publish on it.
fn fail(arena: Allocator, io: std.Io, env: *const std.process.Environ.Map, sp: Spec) !void {
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, try print(arena, "{s}/uppers", .{sp.root}));
    var s = try job(arena, io, sp);
    defer if (s.sync_fd) |fd| {
        _ = linux.close(fd);
    };
    const eq = std.mem.eql;
    if (eq(u8, sp.arg, "sync-tree")) {
        // Gone where a publish syncs its files another way (a branch that moved it): then the
        // `small` case, a publish, is the fsync path's test.
        if (!@hasDecl(Store, "syncTree")) {
            std.debug.print("native store crash: Store.syncTree is not there; the small publish covers the fsync path\n", .{});
            return;
        }
        // The fsync path itself: a small tree whose writes fail.
        const dir = try print(arena, "{s}/uppers/t", .{sp.root});
        try makeTree(arena, io, dir, "a");
        try hook(io, env, flip_env, "on");
        const r = Store.syncTree(arena, io, dir);
        try hook(io, env, flip_env, "off");
        try std.testing.expectError(error.Sync, r);
        std.debug.print("native store crash: syncTree on a disk that fails writes: error.Sync\n", .{});
        return;
    }
    const name: []const u8 = if (eq(u8, sp.arg, "small")) "a" else big;
    var other: ?std.Io.File = null;
    var other_fd: ?linux.fd_t = null;
    defer if (other_fd) |fd| {
        _ = linux.close(fd);
    };
    if (eq(u8, sp.arg, "cursor") or eq(u8, sp.arg, "no-cursor")) {
        // Another job's data fails to reach the disk while this job runs, and the job that
        // writes it learns so first (its `syncfs`): the error is gone for any descriptor
        // opened after, and is still told to this job's, opened before.
        other_fd = Store.syncCursor(arena, s.root);
        try cwd.createDirPath(io, try print(arena, "{s}/other", .{sp.root}));
        const data = try arena.alloc(u8, 1 << 20);
        @memset(data, 0x5a);
        const path = try print(arena, "{s}/other/blob", .{sp.root});
        try cwd.writeFile(io, .{ .sub_path = path, .data = data });
        other = try cwd.openFile(io, path, .{});
        defer other.?.close(io);
        try hook(io, env, flip_env, "on");
        // Writeback only, waited for: no journal commit, which would end the filesystem.
        const rc = linux.syscall4(.sync_file_range, @abs(other.?.handle), 0, 0, 7);
        try hook(io, env, flip_env, "off");
        if (linux.errno(rc) != .SUCCESS) std.debug.print("native store crash: the writeback told {t}\n", .{linux.errno(rc)});
        if (linux.errno(linux.syncfs(other_fd.?)) == .SUCCESS) {
            std.debug.print("native store crash: the failed writes were not told by syncfs: the disk did not fail them\n", .{});
            return error.TestUnexpectedResult;
        }
        if (eq(u8, sp.arg, "no-cursor")) {
            _ = linux.close(s.sync_fd.?);
            s.sync_fd = null;
        }
    } else try hook(io, env, flip_env, "on");

    const upper = try print(arena, "{s}/uppers/{s}", .{ sp.root, name });
    try makeTree(arena, io, upper, name);
    const key = keyOf(name);
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, key, &never);
    defer kl.close(io);
    const r = s.publish(arena, io, key, .step, upper, .{ .log = try logOf(arena, name), .fc = record_fc });
    if (!eq(u8, sp.arg, "cursor") and !eq(u8, sp.arg, "no-cursor")) try hook(io, env, flip_env, "off");

    if (eq(u8, sp.arg, "no-cursor")) {
        // Control: the same publish with a descriptor opened at the publish does not see an error
        // that was told before, so it publishes: the job's descriptor is what finds it.
        const l = try r;
        l.lock.close(io);
        std.debug.print("native store crash: without the job's descriptor the publish does not see the earlier error, as expected\n", .{});
        return;
    }
    if (r) |l| {
        l.lock.close(io);
        std.debug.print("native store crash: the publish succeeded on a disk that failed its writes\n", .{});
        return error.TestUnexpectedResult;
    } else |e| {
        if (e != error.Sync) {
            std.debug.print("native store crash: the publish failed with {s}, not error.Sync\n", .{@errorName(e)});
            return error.TestUnexpectedResult;
        }
    }
    std.debug.print("native store crash: {s}: the publish failed with error.Sync\n", .{sp.arg});
    if (try s.open(arena, io, key)) |hit| {
        hit.layer.lock.close(io);
        std.debug.print("native store crash: and the layer is a hit\n", .{});
        return error.TestUnexpectedResult;
    }
}
