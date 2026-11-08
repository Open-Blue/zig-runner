//! Host-path volumes of a native job container (docs/native-backend.md, "Job container
//! options"): `volumes: - /srv/data:/data[:ro]`, a directory of the host bound into the job.
//!
//! Off by default. The operator allows directories with `RUNNER_NATIVE_HOST_PATHS` (colon- or
//! comma-separated absolute paths); a job may bind one of them or a directory below one, and
//! nothing else. Each is canonicalised once (`parse`, all its symlinks resolved), and refused when
//! it is `/`, under `/proc`, `/sys`, `/dev` or `/run`, or is, holds or lies inside one of the
//! runner's own directories (its store, where every job's layers and volumes are, its rootfs, its
//! log spool): a job that could bind those could read or change other jobs. A job's source is
//! resolved again when it starts (`resolve`), every symlink in it followed, and must still be
//! under an allowed directory, so a link inside one that points out of it is refused; the step's
//! helper then opens the path below the allowed directory with no symlink followed at all
//! (`sandbox.bindHostIn`), so a link swapped in after the check fails the step instead of escaping.
//! A job the runner does not vouch for never gets a host path, whatever the setting says.

const std = @import("std");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;

/// The operator's setting, named in every refusal.
pub const setting = "RUNNER_NATIVE_HOST_PATHS";

/// What no allowed directory may be below, as the kernel's and the system's own (`/run` holds
/// the Docker and systemd sockets).
const system_trees = [_][]const u8{ "/proc", "/sys", "/dev", "/run" };

/// Why an entry of the setting was refused.
pub const Refusal = struct { entry: []const u8 = "", why: []const u8 = "" };

pub const Error = error{ Refused, OutOfMemory };

/// Whether `path` is `tree` or below it.
pub fn under(path: []const u8, tree: []const u8) bool {
    if (std.mem.eql(u8, tree, "/")) return true;
    return std.mem.startsWith(u8, path, tree) and
        (path.len == tree.len or path[tree.len] == '/');
}

/// `raw` (the setting's value) as canonical directories, each a real directory with no symlink
/// in its path. `runner_dirs` are the runner's own (canonicalised here too when they exist): an
/// entry that is one, is above one or is below one is refused. On `error.Refused`, `refusal`
/// says which entry and why.
pub fn parse(
    arena: Allocator,
    io: std.Io,
    raw: []const u8,
    runner_dirs: []const []const u8,
    refusal: *Refusal,
) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var mine: std.ArrayList([]const u8) = .empty;
    for (runner_dirs) |d| {
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
        if (!isDir(arena, real)) return refuse(refusal, "is not a directory");
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
        try out.append(arena, real);
    }
    return out.items;
}

fn refuse(refusal: *Refusal, why: []const u8) Error {
    refusal.why = why;
    return error.Refused;
}

/// `path` with every symlink resolved, or null when it cannot be (it is not there).
fn canonical(arena: Allocator, io: std.Io, path: []const u8) ?[]const u8 {
    const real = std.Io.Dir.cwd().realPathFileAlloc(io, path, arena) catch return null;
    return real;
}

fn isDir(arena: Allocator, path: []const u8) bool {
    const z = arena.dupeSentinel(u8, path, 0) catch return false;
    var st: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, z, 0, .{ .TYPE = true }, &st);
    return linux.errno(rc) == .SUCCESS and st.mode & linux.S.IFMT == linux.S.IFDIR;
}

/// A job's host source, allowed: the allowed directory it is under and its own canonical path.
pub const Allowed = struct { root: []const u8, path: []const u8 };

/// `source` (a job container's volume's host side) resolved now, every symlink followed, and
/// the allowed directory (`parse`'s) it is in. Null, with `why`, when it is in none, cannot be
/// resolved or is not a directory.
pub fn resolve(
    arena: Allocator,
    io: std.Io,
    allowed: []const []const u8,
    source: []const u8,
    why: *[]const u8,
) !?Allowed {
    if (allowed.len == 0) {
        why.* = "host paths are off: " ++ setting ++ " allows none";
        return null;
    }
    const real = canonical(arena, io, source) orelse {
        why.* = "it cannot be resolved on the host (it is not there)";
        return null;
    };
    if (!isDir(arena, real)) {
        why.* = "it is not a directory on the host";
        return null;
    }
    for (allowed) |root| if (under(real, root)) return .{ .root = root, .path = real };
    why.* = try std.fmt.allocPrint(arena, "it resolves to {s}, which is under none of the " ++
        "directories " ++ setting ++ " allows ({s})", .{ real, try std.mem.join(arena, ", ", allowed) });
    return null;
}

test "host paths: the setting canonicalised, and what it may never name refused" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    for ([_][]const u8{ "data", "cache", "store/jobs", "linked-target" }) |d| try tmp.dir.createDirPath(io, d);
    try tmp.dir.symLink(io, "linked-target", "link", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "file", .data = "" });
    const store = try std.fmt.allocPrint(arena, "{s}/store", .{root});
    var r: Refusal = .{};

    // Both separators, blanks between, and a symlink resolved to where it points.
    const raw = try std.fmt.allocPrint(arena, "{s}/data:{s}/cache, {s}/link,", .{ root, root, root });
    const got = try parse(arena, io, raw, &.{store}, &r);
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/data", .{root}), got[0]);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/linked-target", .{root}), got[2]);
    try std.testing.expectEqual(@as(usize, 0), (try parse(arena, io, "", &.{store}, &r)).len);

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
    };
    for (cases) |c| {
        r = .{};
        const list = try std.fmt.allocPrint(arena, "{s}/data,{s}", .{ root, c.entry });
        try std.testing.expectError(error.Refused, parse(arena, io, list, &.{store}, &r));
        try std.testing.expectEqualStrings(c.entry, r.entry);
        if (std.mem.indexOf(u8, r.why, c.why) == null) {
            std.debug.print("{s} refused as: {s}\n", .{ c.entry, r.why });
            return error.TestUnexpectedResult;
        }
    }
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
    const allowed_dir = try std.fmt.allocPrint(arena, "{s}/allowed", .{root});
    const allowed = [_][]const u8{allowed_dir};
    var why: []const u8 = "";

    const whole = (try resolve(arena, io, &allowed, allowed_dir, &why)).?;
    try std.testing.expectEqualStrings(allowed_dir, whole.root);
    try std.testing.expectEqualStrings(allowed_dir, whole.path);
    const sub = (try resolve(arena, io, &allowed, try std.fmt.allocPrint(arena, "{s}/sub/", .{allowed_dir}), &why)).?;
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/sub", .{allowed_dir}), sub.path);
    const inside = (try resolve(arena, io, &allowed, try std.fmt.allocPrint(arena, "{s}/inside", .{allowed_dir}), &why)).?;
    try std.testing.expectEqualStrings(sub.path, inside.path);

    for ([_][]const u8{ "allowed/escape", "outside", "allowed-not", "allowed/../outside" }) |rel| {
        why = "";
        const p = try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, rel });
        try std.testing.expect(try resolve(arena, io, &allowed, p, &why) == null);
        try std.testing.expect(std.mem.indexOf(u8, why, setting) != null);
    }
    try std.testing.expect(try resolve(arena, io, &allowed, try std.fmt.allocPrint(arena, "{s}/gone", .{allowed_dir}), &why) == null);
    try std.testing.expect(try resolve(arena, io, &.{}, allowed_dir, &why) == null);
    try std.testing.expect(std.mem.indexOf(u8, why, "off") != null);
}
