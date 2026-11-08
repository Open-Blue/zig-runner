//! Host-path volumes of a native job container (docs/native-backend.md, "Job container
//! options"): `volumes: - /srv/data:/data[:ro]`, a directory of the host bound into the job.
//!
//! Off by default. The operator allows directories with `RUNNER_NATIVE_HOST_PATHS` (colon- or
//! comma-separated absolute paths); a job may bind one of them or a directory below one, and
//! nothing else. Each is canonicalised once, when the runner starts (`parse`, all its symlinks
//! resolved, its device and inode kept), and refused when it is `/`, under `/proc`, `/sys`, `/dev`
//! or `/run`, is, holds or lies inside one of the runner's own paths (its store, where every job's
//! layers and volumes are, its rootfs, its log spool, its executable, its GitHub App key's
//! directory, its env file), or is on a mount without `nosuid` and `nodev`: a job could otherwise
//! leave a setuid file there that a host user runs as the volumes' ids. Each job checks that list
//! again (`recheck`): an entry whose path now resolves elsewhere, or is another directory (device
//! and inode), is closed for the job, never followed to where it points now.
//!
//! A job's source is first checked as written, lexically, against the list, and only then resolved
//! (`resolve`), every symlink in it followed; it must still be under an allowed directory, so a
//! link inside one that points out of it is refused. Every refusal of a source says the same
//! thing, so a job cannot learn from it what exists on the host or where a link points. The step's
//! helper then opens the path from `/` with no symlink followed at all (`sandbox.bindHostIn`), so
//! a link swapped in after the check fails the step instead of escaping, and checks the mount it
//! landed on is `nosuid` and `nodev` again. A job the runner does not vouch for never gets a host
//! path, whatever the setting says, and neither does any job of a rootless runner.

const std = @import("std");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;

/// The operator's setting, named in every refusal.
pub const setting = "RUNNER_NATIVE_HOST_PATHS";
/// The operator's opt-in to host paths mounted with the host's ids where the kernel cannot
/// idmap the filesystem (`sandbox.bindHostIn`).
pub const unmapped_setting = "RUNNER_NATIVE_HOST_PATHS_UNMAPPED";

/// What no allowed directory may be below, as the kernel's and the system's own (`/run` holds
/// the Docker and systemd sockets).
const system_trees = [_][]const u8{ "/proc", "/sys", "/dev", "/run" };

/// Why an entry of the setting was refused.
pub const Refusal = struct { entry: []const u8 = "", why: []const u8 = "" };

pub const Error = error{ Refused, OutOfMemory };

/// An allowed directory, as checked when the runner started.
pub const Entry = struct {
    /// As the operator wrote it, cleaned (`.`, `..` and doubled slashes taken out lexically).
    written: []const u8,
    /// Canonical: every symlink resolved.
    real: []const u8,
    /// Which directory it was: a different one at `real` since (moved, replaced, remounted) is
    /// not the one the operator allowed.
    dev_major: u32 = 0,
    dev_minor: u32 = 0,
    ino: u64 = 0,
};

/// Whether `path` is `tree` or below it.
pub fn under(path: []const u8, tree: []const u8) bool {
    if (std.mem.eql(u8, tree, "/")) return true;
    return std.mem.startsWith(u8, path, tree) and
        (path.len == tree.len or path[tree.len] == '/');
}

pub const ParseOptions = struct {
    /// Tests of the rest on a filesystem mounted without them: whether an entry's mount must be
    /// `nosuid` and `nodev`. Always on outside tests.
    mount_flags: bool = true,
};

/// `raw` (the setting's value) as canonical directories, each a real directory with no symlink
/// in its path, on a `nosuid,nodev` mount. `runner_paths` are the runner's own files and
/// directories (canonicalised here too when they exist): an entry that is one, is above one or is
/// below one is refused. On `error.Refused`, `refusal` says which entry and why.
pub fn parse(
    arena: Allocator,
    io: std.Io,
    raw: []const u8,
    runner_paths: []const []const u8,
    refusal: *Refusal,
    opts: ParseOptions,
) Error![]const Entry {
    var out: std.ArrayList(Entry) = .empty;
    var mine: std.ArrayList([]const u8) = .empty;
    for (runner_paths) |d| {
        if (d.len == 0) continue;
        try mine.append(arena, canonical(arena, io, d) orelse d);
    }
    var it = std.mem.tokenizeAny(u8, raw, ":,");
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t");
        if (entry.len == 0) continue;
        refusal.entry = entry;
        if (entry[0] != '/') return refuse(refusal, "is not an absolute path");
        const real = canonical(arena, io, entry) orelse
            return refuse(refusal, "cannot be resolved (it must exist when the runner starts)");
        const id = dirId(arena, real) orelse return refuse(refusal, "is not a directory");
        if (std.mem.eql(u8, real, "/")) return refuse(refusal, "is the root directory");
        for (system_trees) |t| if (under(real, t)) return refuse(refusal, try std.fmt.allocPrint(
            arena,
            "resolves to {s}, under {s}, which is the kernel's or the system's",
            .{ real, t },
        ));
        for (mine.items) |d| if (under(real, d) or under(d, real)) return refuse(refusal, try std.fmt.allocPrint(
            arena,
            "resolves to {s}, which holds or is inside the runner's own {s}",
            .{ real, d },
        ));
        if (opts.mount_flags and !safeMount(arena, real)) return refuse(refusal, try std.fmt.allocPrint(
            arena,
            "resolves to {s}, on a mount without nosuid and nodev: a job could leave a setuid " ++
                "file or a device node there for the host (mount it with -o nosuid,nodev, or " ++
                "bind it so: mount --bind {s} {s} && mount -o remount,bind,nosuid,nodev {s})",
            .{ real, real, real, real },
        ));
        try out.append(arena, .{
            .written = try std.fs.path.resolveAllocPosix(arena, &.{entry}),
            .real = real,
            .dev_major = id.dev_major,
            .dev_minor = id.dev_minor,
            .ino = id.ino,
        });
    }
    return out.items;
}

fn refuse(refusal: *Refusal, why: []const u8) Error {
    refusal.why = why;
    return error.Refused;
}

/// The entries of `entries` that are still the directories the runner checked when it started:
/// the same canonical path, the same device and inode, still on a `nosuid,nodev` mount. One that
/// is not is left out (closed for this job), and `closed` says which, for the job's log; never
/// re-resolved to where its path points now.
pub fn recheck(
    arena: Allocator,
    io: std.Io,
    entries: []const Entry,
    opts: ParseOptions,
    closed: *std.ArrayList([]const u8),
) ![]const Entry {
    var out: std.ArrayList(Entry) = .empty;
    for (entries) |e| {
        const still = still: {
            const real = canonical(arena, io, e.written) orelse break :still false;
            if (!std.mem.eql(u8, real, e.real)) break :still false;
            const id = dirId(arena, real) orelse break :still false;
            if (id.dev_major != e.dev_major or id.dev_minor != e.dev_minor or id.ino != e.ino)
                break :still false;
            break :still !opts.mount_flags or safeMount(arena, real);
        };
        if (still) try out.append(arena, e) else try closed.append(arena, e.written);
    }
    return out.items;
}

/// `path` with every symlink resolved, or null when it cannot be (it is not there).
fn canonical(arena: Allocator, io: std.Io, path: []const u8) ?[]const u8 {
    const real = std.Io.Dir.cwd().realPathFileAlloc(io, path, arena) catch return null;
    return real;
}

const DirId = struct { dev_major: u32, dev_minor: u32, ino: u64 };

/// Which directory `path` is (not following a last symlink: `path` is canonical), or null when
/// it is not one.
fn dirId(arena: Allocator, path: []const u8) ?DirId {
    const z = arena.dupeSentinel(u8, path, 0) catch return null;
    var st: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .INO = true }, &st);
    if (linux.errno(rc) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFDIR) return null;
    return .{ .dev_major = st.dev_major, .dev_minor = st.dev_minor, .ino = st.ino };
}

/// `struct statfs`'s `f_flags`, at the same place on x86_64 and aarch64, and the two it must
/// have.
const statfs_flags_at = 80;
const st_nosuid = 0x2;
const st_nodev = 0x4;

/// Whether the mount `path` is on is `nosuid` and `nodev`.
fn safeMount(arena: Allocator, path: []const u8) bool {
    const z = arena.dupeSentinel(u8, path, 0) catch return false;
    var st: [120]u8 align(8) = undefined;
    if (linux.errno(linux.syscall2(.statfs, @intFromPtr(z.ptr), @intFromPtr(&st))) != .SUCCESS) return false;
    return safeFlags(std.mem.readInt(u64, st[statfs_flags_at..][0..8], .little));
}

/// Whether the mount `fd` is on is `nosuid` and `nodev` (the step's helper, on what it opened).
pub fn safeMountFd(fd: linux.fd_t) bool {
    var st: [120]u8 align(8) = undefined;
    const rc = linux.syscall2(.fstatfs, std.math.cast(usize, fd) orelse return false, @intFromPtr(&st));
    if (linux.errno(rc) != .SUCCESS) return false;
    return safeFlags(std.mem.readInt(u64, st[statfs_flags_at..][0..8], .little));
}

fn safeFlags(flags: u64) bool {
    return flags & st_nosuid != 0 and flags & st_nodev != 0;
}

/// A job's host source, allowed: the allowed directory it is under and its own canonical path.
pub const Allowed = struct { root: []const u8, path: []const u8 };

/// `source` (a job container's volume's host side) checked as written against `allowed`, then
/// resolved, every symlink followed, and the allowed directory it is in. Null, with `why`, when
/// it is in none, cannot be resolved or is not a directory: one reason for all of those, which
/// names no path but the source and the list, so a refusal tells a job nothing about the host.
pub fn resolve(
    arena: Allocator,
    io: std.Io,
    allowed: []const Entry,
    source: []const u8,
    why: *[]const u8,
    opts: ParseOptions,
) !?Allowed {
    if (allowed.len == 0) {
        why.* = "host paths are off: " ++ setting ++ " allows none";
        return null;
    }
    var list: std.ArrayList([]const u8) = .empty;
    for (allowed) |e| try list.append(arena, e.written);
    const not_allowed = try std.fmt.allocPrint(arena, "it is not a directory under one " ++
        setting ++ " allows ({s}), or it is not there", .{try std.mem.join(arena, ", ", list.items)});
    // As written first: a source outside the list is refused before anything of it is looked
    // at on the host.
    if (source.len == 0 or source[0] != '/') {
        why.* = not_allowed;
        return null;
    }
    const clean = try std.fs.path.resolveAllocPosix(arena, &.{source});
    const lexical = for (allowed) |e| {
        if (under(clean, e.written) or under(clean, e.real)) break true;
    } else false;
    if (!lexical) {
        why.* = not_allowed;
        return null;
    }
    const real = canonical(arena, io, clean) orelse {
        why.* = not_allowed;
        return null;
    };
    if (dirId(arena, real) == null) {
        why.* = not_allowed;
        return null;
    }
    for (allowed) |e| if (under(real, e.real)) {
        if (opts.mount_flags and !safeMount(arena, real)) {
            why.* = "it is on a mount without nosuid and nodev, below a directory " ++ setting ++
                " allows (the operator's to mount so)";
            return null;
        }
        return .{ .root = e.real, .path = real };
    };
    why.* = not_allowed;
    return null;
}

const no_flags: ParseOptions = .{ .mount_flags = false };

test "host paths: the setting canonicalised, and what it may never name refused" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for ([_][]const u8{ "data", "cache", "store/jobs", "linked-target", "bin", "keys" }) |d| try tmp.dir.createDirPath(io, d);
    try tmp.dir.symLink(io, "linked-target", "link", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "file", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "bin/zig-runner", .data = "" });
    const store = try std.fmt.allocPrint(arena, "{s}/store", .{root});
    // The runner's own files, as `Backend.hostPathsOf` gives them: its executable, and its
    // App key's directory.
    const exe = try std.fmt.allocPrint(arena, "{s}/bin/zig-runner", .{root});
    const keys = try std.fmt.allocPrint(arena, "{s}/keys", .{root});
    const mine = [_][]const u8{ store, exe, keys };
    var r: Refusal = .{};

    // Both separators, blanks between, and a symlink resolved to where it points.
    const raw = try std.fmt.allocPrint(arena, "{s}/data:{s}/cache, {s}/link,", .{ root, root, root });
    const got = try parse(arena, io, raw, &mine, &r, no_flags);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/data", .{root}), got[0].real);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/linked-target", .{root}), got[2].real);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/link", .{root}), got[2].written);
    try std.testing.expect(got[0].ino != 0);
    try std.testing.expectEqual(@as(usize, 0), (try parse(arena, io, "", &mine, &r, no_flags)).len);

    const Case = struct { entry: []const u8, why: []const u8 };
    const cases = [_]Case{
        .{ .entry = "relative/dir", .why = "absolute" },
        .{ .entry = "/", .why = "root" },
        .{ .entry = "/proc", .why = "under /proc" },
        .{ .entry = "/sys/fs", .why = "under /sys" },
        .{ .entry = "/dev", .why = "under /dev" },
        .{ .entry = "/run", .why = "under /run" },
        .{ .entry = try std.fmt.allocPrint(arena, "{s}/missing", .{root}), .why = "resolved" },
        .{ .entry = try std.fmt.allocPrint(arena, "{s}/file", .{root}), .why = "not a directory" },
        // The runner's store, a directory inside it, and one that holds it.
        .{ .entry = store, .why = "runner's own" },
        .{ .entry = try std.fmt.allocPrint(arena, "{s}/jobs", .{store}), .why = "runner's own" },
        .{ .entry = root, .why = "runner's own" },
        // The directory of its executable, and of its key.
        .{ .entry = try std.fmt.allocPrint(arena, "{s}/bin", .{root}), .why = "runner's own" },
        .{ .entry = keys, .why = "runner's own" },
    };
    for (cases) |c| {
        r = .{};
        const list = try std.fmt.allocPrint(arena, "{s}/data,{s}", .{ root, c.entry });
        try std.testing.expectError(error.Refused, parse(arena, io, list, &mine, &r, no_flags));
        try std.testing.expectEqualStrings(c.entry, r.entry);
        if (std.mem.indexOf(u8, r.why, c.why) == null) {
            std.debug.print("{s} refused as: {s}\n", .{ c.entry, r.why });
            return error.TestUnexpectedResult;
        }
    }
}

test "host paths: an entry on a mount without nosuid and nodev is refused, naming the fix" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var r: Refusal = .{};
    // The test's own directory's mount decides which way this goes; both are checked somewhere
    // (CI's work directory is ext4 with neither, and the root tests mount a tmpfs with both).
    if (safeMount(arena, root)) {
        try std.testing.expectEqual(@as(usize, 1), (try parse(arena, io, root, &.{}, &r, .{})).len);
        return;
    }
    try std.testing.expectError(error.Refused, parse(arena, io, root, &.{}, &r, .{}));
    try std.testing.expect(std.mem.indexOf(u8, r.why, "nosuid and nodev") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.why, "-o nosuid,nodev") != null);
    // /proc is mounted with both, on every Linux: the check itself.
    try std.testing.expect(safeMount(arena, "/proc"));
    try std.testing.expect(safeFlags(st_nosuid | st_nodev));
    try std.testing.expect(!safeFlags(st_nosuid) and !safeFlags(st_nodev));
}

test "host paths: an entry moved or replaced since the start is closed for the job, not followed" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for ([_][]const u8{ "one", "two", "elsewhere" }) |d| try tmp.dir.createDirPath(io, d);
    try tmp.dir.symLink(io, "one", "link", .{});
    var r: Refusal = .{};
    const raw = try std.fmt.allocPrint(arena, "{s}/link:{s}/two", .{ root, root });
    const entries = try parse(arena, io, raw, &.{}, &r, no_flags);
    var closed: std.ArrayList([]const u8) = .empty;
    try std.testing.expectEqual(@as(usize, 2), (try recheck(arena, io, entries, no_flags, &closed)).len);
    try std.testing.expectEqual(@as(usize, 0), closed.items.len);

    // The link now points elsewhere, and `two` is another directory of the same name.
    try tmp.dir.deleteFile(io, "link");
    try tmp.dir.symLink(io, "elsewhere", "link", .{});
    // Made while the old one is there, so its inode is another.
    try tmp.dir.createDirPath(io, "two-new");
    try tmp.dir.deleteDir(io, "two");
    try tmp.dir.rename("two-new", tmp.dir, "two", io);
    const now = try recheck(arena, io, entries, no_flags, &closed);
    try std.testing.expectEqual(@as(usize, 0), now.len);
    try std.testing.expectEqual(@as(usize, 2), closed.items.len);
    // And a job's source in either is refused.
    var why: []const u8 = "";
    try std.testing.expect(try resolve(arena, io, now, try std.fmt.allocPrint(arena, "{s}/elsewhere", .{root}), &why, no_flags) == null);
}

test "host paths: a job's source is allowed only inside the list, through no symlink out of it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for ([_][]const u8{ "allowed/sub", "outside", "allowed-not" }) |d| try tmp.dir.createDirPath(io, d);
    // A link inside the allowed directory that points out of it, and one that stays inside.
    try tmp.dir.symLink(io, "../outside", "allowed/escape", .{});
    try tmp.dir.symLink(io, "sub", "allowed/inside", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "allowed/file", .data = "" });
    const allowed_dir = try std.fmt.allocPrint(arena, "{s}/allowed", .{root});
    var r: Refusal = .{};
    const allowed = try parse(arena, io, allowed_dir, &.{}, &r, no_flags);
    var why: []const u8 = "";

    const whole = (try resolve(arena, io, allowed, allowed_dir, &why, no_flags)).?;
    try std.testing.expectEqualStrings(allowed_dir, whole.root);
    try std.testing.expectEqualStrings(allowed_dir, whole.path);
    const sub = (try resolve(arena, io, allowed, try std.fmt.allocPrint(arena, "{s}/sub/", .{allowed_dir}), &why, no_flags)).?;
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/sub", .{allowed_dir}), sub.path);
    const inside = (try resolve(arena, io, allowed, try std.fmt.allocPrint(arena, "{s}/inside", .{allowed_dir}), &why, no_flags)).?;
    try std.testing.expectEqualStrings(sub.path, inside.path);

    // Every refusal says the same, naming neither where a link points nor whether a path is
    // there: a link out, a path outside, one that only starts the same, `..` out, a missing
    // one, a file, and paths on the host the job has no business probing.
    const refused = [_][]const u8{
        "allowed/escape", "outside",      "allowed-not", "allowed/../outside",
        "allowed/gone",   "allowed/file",
    };
    var first: ?[]const u8 = null;
    for (refused) |rel| {
        why = "";
        const p = try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, rel });
        try std.testing.expect(try resolve(arena, io, allowed, p, &why, no_flags) == null);
        try std.testing.expect(std.mem.indexOf(u8, why, setting) != null);
        try std.testing.expect(std.mem.indexOf(u8, why, "outside") == null);
        if (first) |f| try std.testing.expectEqualStrings(f, why) else first = why;
    }
    for ([_][]const u8{ "/etc", "/etc/shadow", "/nonexistent", "relative" }) |p| {
        try std.testing.expect(try resolve(arena, io, allowed, p, &why, no_flags) == null);
        try std.testing.expectEqualStrings(first.?, why);
    }
    try std.testing.expect(try resolve(arena, io, &.{}, allowed_dir, &why, no_flags) == null);
    try std.testing.expect(std.mem.indexOf(u8, why, "off") != null);
}
