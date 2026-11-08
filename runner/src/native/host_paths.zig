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
//! leave a setuid file there that a host user runs as the volumes' ids (and it must not be shown
//! at another path on such a mount, `exposedElsewhere`). Each job checks that list
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
                "file or a device node there for the host (mount its filesystem with " ++
                "-o nosuid,nodev, in /etc/fstab so it lasts)",
            .{real},
        ));
        if (opts.mount_flags) if (exposedElsewhere(arena, io, real)) |elsewhere| {
            if (elsewhere) |at| return refuse(refusal, try std.fmt.allocPrint(
                arena,
                "resolves to {s}, which is also reachable at {s}, on a mount without nosuid and " ++
                    "nodev: a setuid file a job left would run there (mount the whole filesystem " ++
                    "with -o nosuid,nodev, not only this directory)",
                .{ real, at },
            ));
        } else |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unknown => return refuse(refusal, try std.fmt.allocPrint(
                arena,
                "resolves to {s}, whose mounts cannot be read from /proc/self/mountinfo",
                .{real},
            )),
        };
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
            if (!opts.mount_flags) break :still true;
            if (!safeMount(arena, real)) break :still false;
            const elsewhere = exposedElsewhere(arena, io, real) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Unknown => break :still false,
            };
            break :still elsewhere == null;
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

/// The most of `/proc/self/mountinfo` read: a machine's mount table is far smaller.
const mountinfo_max = 4 << 20;

/// Where else, in the runner's mount namespace, `path`'s directory is reachable on a mount without
/// `nosuid` or `nodev`, or null when nowhere. The mount at `path` passing (`safeMount`) is not
/// enough: the same filesystem may show the directory at another path too (`/srv` bound at
/// `/mnt/srv`), where a setuid file a job left runs. Other namespaces' mounts are not seen.
/// `error.Unknown` when the table cannot be read or has no mount for `path`.
fn exposedElsewhere(arena: Allocator, io: std.Io, path: []const u8) error{ Unknown, OutOfMemory }!?[]const u8 {
    const own = try readTable(arena, io, "/proc/self/mountinfo");
    // And the host's own view, pid 1's: a service manager may give the runner a mount namespace of
    // its own (deploy/zig-runner.service's ProtectSystem and PrivateTmp), which is not what host
    // users see.
    const host = try readTable(arena, io, "/proc/1/mountinfo");
    return exposedIn(arena, own, host, path);
}

/// A mount table, read to its end, not by its size: procfs gives it as 0. Cut short, it could
/// leave out the very mount that shows the directory, so a table past the limit is not read at all.
fn readTable(arena: Allocator, io: std.Io, path: []const u8) error{ Unknown, OutOfMemory }![]const u8 {
    const f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return error.Unknown;
    defer f.close(io);
    var table: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = f.readStreaming(io, &.{&buf}) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return error.Unknown,
        };
        if (n == 0) break;
        if (table.items.len + n > mountinfo_max) return error.Unknown;
        try table.appendSlice(arena, buf[0..n]);
    }
    return table.items;
}

/// `exposedElsewhere` on the runner's mount table `own` and the host's `host`, as
/// `/proc/<pid>/mountinfo` writes them.
fn exposedIn(arena: Allocator, own: []const u8, host: []const u8, path: []const u8) error{ Unknown, OutOfMemory }!?[]const u8 {
    // The mount `path` is on names the filesystem (its device), and its root joined to the rest of
    // `path` is the directory within that filesystem.
    const mounts = try parseTable(arena, own);
    const mine = visible(mounts, path) orelse return error.Unknown;
    const dev = mounts[mine].dev;
    const within = try join(arena, mounts[mine].root, below(path, mounts[mine].point));
    if (try shownIn(arena, mounts, dev, within)) |at| return at;
    return shownIn(arena, try parseTable(arena, host), dev, within);
}

/// Where a mount of `mounts` without `nosuid` and `nodev` shows the directory `within` of the
/// filesystem `dev`, or null: every mount of that filesystem whose root holds it shows it at a
/// path of its own, unless a mount on top hides that path (a directory bound onto itself hides
/// the filesystem's own mount there).
fn shownIn(arena: Allocator, mounts: []const Mount, dev: []const u8, within: []const u8) !?[]const u8 {
    for (mounts, 0..) |m, i| {
        if (m.safe or !std.mem.eql(u8, m.dev, dev) or !under(within, m.root)) continue;
        const at = try join(arena, m.point, below(within, m.root));
        if (visible(mounts, at) == i) return at;
    }
    return null;
}

fn parseTable(arena: Allocator, table: []const u8) ![]const Mount {
    var mounts: std.ArrayList(Mount) = .empty;
    var lines = std.mem.tokenizeScalar(u8, table, '\n');
    while (lines.next()) |line| if (try Mount.parse(arena, line)) |m| try mounts.append(arena, m);
    return mounts.items;
}

/// Which of `mounts` `path` (canonical) is on, as the kernel's path walk finds it: from the root
/// mount, at each of `path`'s prefixes, shortest first, down to a mount there whose parent is the
/// mount reached so far (one mounted on top of another has that one as its parent). So a mount
/// that a later one hides, mounted below where the later one sits, is never reached. Null when the
/// table has no root.
fn visible(mounts: []const Mount, path: []const u8) ?usize {
    var on: usize = for (mounts, 0..) |m, i| {
        if (std.mem.eql(u8, m.point, "/") and !hasId(mounts, m.parent)) break i;
    } else return null;
    var end: usize = 0;
    var steps: usize = 0;
    while (true) {
        const prefix = if (end == 0) "/" else path[0..end];
        down: while (steps <= mounts.len) : (steps += 1) {
            for (mounts, 0..) |m, i| {
                if (i == on or !std.mem.eql(u8, m.parent, mounts[on].id)) continue;
                if (!std.mem.eql(u8, m.point, prefix)) continue;
                on = i;
                continue :down;
            }
            break;
        } else return null;
        if (end == path.len or path.len <= 1) return on;
        end += 1;
        while (end < path.len and path[end] != '/') end += 1;
    }
}

fn hasId(mounts: []const Mount, id: []const u8) bool {
    for (mounts) |m| if (std.mem.eql(u8, m.id, id)) return true;
    return false;
}

/// What of `path` is below `tree` (`under(path, tree)`): empty, or starting with `/`.
fn below(path: []const u8, tree: []const u8) []const u8 {
    if (!std.mem.eql(u8, tree, "/")) return path[tree.len..];
    return if (std.mem.eql(u8, path, "/")) "" else path;
}

/// `base` and `rest` (empty, or starting with `/`) as one path.
fn join(arena: Allocator, base: []const u8, rest: []const u8) ![]const u8 {
    if (rest.len == 0) return base;
    if (std.mem.eql(u8, base, "/")) return rest;
    return std.mem.concat(arena, u8, &.{ base, rest });
}

/// One line of `/proc/self/mountinfo`: `id parent major:minor root point options [tags] - ...`.
const Mount = struct {
    id: []const u8,
    parent: []const u8,
    dev: []const u8,
    root: []const u8,
    point: []const u8,
    /// Its own options name both `nosuid` and `nodev`.
    safe: bool,

    fn parse(arena: Allocator, line: []const u8) !?Mount {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const id = f.next() orelse return null;
        const parent = f.next() orelse return null;
        const dev = f.next() orelse return null;
        const root = f.next() orelse return null;
        const point = f.next() orelse return null;
        const options = f.next() orelse return null;
        var nosuid = false;
        var nodev = false;
        var opts = std.mem.tokenizeScalar(u8, options, ',');
        while (opts.next()) |o| {
            if (std.mem.eql(u8, o, "nosuid")) nosuid = true;
            if (std.mem.eql(u8, o, "nodev")) nodev = true;
        }
        return .{
            .id = id,
            .parent = parent,
            .dev = dev,
            .root = try unescape(arena, root),
            .point = try unescape(arena, point),
            .safe = nosuid and nodev,
        };
    }

    /// The kernel writes a space, tab, newline or backslash in a path as `\ooo`.
    fn unescape(arena: Allocator, s: []const u8) ![]const u8 {
        if (std.mem.indexOfScalar(u8, s, '\\') == null) return s;
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < s.len) : (i += 1) {
            if (s[i] == '\\' and s.len - i > 3) {
                if (std.fmt.parseInt(u8, s[i + 1 ..][0..3], 8)) |c| {
                    try out.append(arena, c);
                    i += 3;
                    continue;
                } else |_| {}
            }
            try out.append(arena, s[i]);
        }
        return out.items;
    }
};

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

test "host paths: a directory also shown on a mount without nosuid and nodev is found there" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const root = "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n";
    const srv = "30 22 8:3 / /srv rw,nosuid,nodev,relatime - ext4 /dev/sda3 rw\n";
    // Its own filesystem nosuid,nodev, and shown nowhere else.
    try std.testing.expectEqual(@as(?[]const u8, null), try exposedIn(arena, root ++ srv, "", "/srv/data"));
    // Bound onto itself on the root filesystem: the bind hides the root's mount at that path.
    const self_bind = "40 22 8:2 /srv/data /srv/data rw,nosuid,nodev - ext4 /dev/sda2 rw\n";
    try std.testing.expectEqual(@as(?[]const u8, null), try exposedIn(arena, root ++ self_bind, "", "/srv/data"));
    // The filesystem shown again, without them, at another path: the directory is there too.
    const again = "41 22 8:3 / /mnt/srv rw,relatime - ext4 /dev/sda3 rw\n";
    try std.testing.expectEqualStrings("/mnt/srv/data", (try exposedIn(arena, root ++ srv ++ again, "", "/srv/data")).?);
    // A bind of a directory above it, and one of a sibling, which does not show it.
    const above = "42 22 8:3 /data /opt/d rw - ext4 /dev/sda3 rw\n";
    try std.testing.expectEqualStrings("/opt/d/x", (try exposedIn(arena, root ++ srv ++ above, "", "/srv/data/x")).?);
    const sibling = "43 22 8:3 /other /opt/o rw - ext4 /dev/sda3 rw\n";
    try std.testing.expectEqual(@as(?[]const u8, null), try exposedIn(arena, root ++ srv ++ sibling, "", "/srv/data"));
    // Hidden by a mount on top of the second view: not reachable there.
    const hidden = again ++ "44 41 0:50 / /mnt/srv rw,nosuid,nodev - tmpfs tmpfs rw\n";
    try std.testing.expectEqual(@as(?[]const u8, null), try exposedIn(arena, root ++ srv ++ hidden, "", "/srv/data"));
    // The kernel's escapes in a mount point.
    const spaced = "45 22 8:3 / /mnt/a\\040b rw - ext4 /dev/sda3 rw\n";
    try std.testing.expectEqualStrings("/mnt/a b/data", (try exposedIn(arena, root ++ srv ++ spaced, "", "/srv/data")).?);
    // No mount for the path at all.
    try std.testing.expectError(error.Unknown, exposedIn(arena, srv, "", "/elsewhere"));
    // A mount hidden under a later one is not where the path goes: a tmpfs at /mnt/srv/data,
    // then the filesystem bound at /mnt/srv over it, without nosuid. The walk goes through the
    // bind, and finds the directory there, not the tmpfs below.
    const under_bind = "50 22 0:60 / /mnt/srv/data rw,nosuid,nodev - tmpfs tmpfs rw\n" ++
        "51 22 8:3 / /mnt/srv rw - ext4 /dev/sda3 rw\n";
    try std.testing.expectEqualStrings("/mnt/srv/data", (try exposedIn(arena, root ++ srv ++ under_bind, "", "/srv/data")).?);
    // The host's own view counts too: shown there and not in the runner's namespace.
    const host = root ++ srv ++ "60 22 8:3 / /export rw - ext4 /dev/sda3 rw\n";
    try std.testing.expectEqualStrings("/export/data", (try exposedIn(arena, root ++ srv, host, "/srv/data")).?);
}

test "host paths, as root: an entry also bound elsewhere without nosuid is refused, at start and for each job" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "fs");
    try tmp.dir.createDirPath(io, "view");
    const fs = try std.fmt.allocPrintSentinel(arena, "{s}/fs", .{root}, 0);
    const view = try std.fmt.allocPrintSentinel(arena, "{s}/view", .{root}, 0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount("tmpfs", fs, "tmpfs", linux.MS.NOSUID | linux.MS.NODEV, 0)));
    defer _ = linux.umount2(fs, linux.MNT.DETACH);
    try tmp.dir.createDirPath(io, "fs/data");
    const data = try std.fmt.allocPrint(arena, "{s}/data", .{fs});
    var r: Refusal = .{};
    // Shown only where it is mounted nosuid,nodev: allowed.
    const entries = try parse(arena, io, data, &.{}, &r, .{});
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    // The same filesystem bound at a second path without them: refused, naming that path, and a
    // runner that started before the bind closes it for the next job.
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount(fs, view, null, linux.MS.BIND, 0)));
    defer _ = linux.umount2(view, linux.MNT.DETACH);
    // A bind keeps its source's flags: taken off again, as an operator's remount would.
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mount(null, view, null, linux.MS.REMOUNT | linux.MS.BIND, 0)));
    try std.testing.expectError(error.Refused, parse(arena, io, data, &.{}, &r, .{}));
    try std.testing.expect(std.mem.indexOf(u8, r.why, try std.fmt.allocPrint(arena, "{s}/data", .{view})) != null);
    var closed: std.ArrayList([]const u8) = .empty;
    try std.testing.expectEqual(@as(usize, 0), (try recheck(arena, io, entries, .{}, &closed)).len);
    try std.testing.expectEqual(@as(usize, 1), closed.items.len);
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
