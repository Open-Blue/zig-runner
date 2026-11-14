//! The Dockerfile builder against BuildKit: the same Dockerfiles built both ways, the filesystems
//! and the image configs compared (docs/native-backend.md, "The Dockerfile builder"; run by
//! `.github/scripts/dockerfile-diff.sh`, weekly in compare.yml).
//!
//! `ZIG_RUNNER_DOCKERFILE_ORACLE` names a directory the script made (this test is skipped
//! without it):
//!
//!   bases.txt                one `<reference> <n>` per base image the cases use
//!   bases/<n>.tar            the base's filesystem (`docker build --output type=tar`)
//!   bases/<n>.json           its configuration (`docker image inspect --format '{{json .}}'`)
//!   cases/<name>/ctx/        a Dockerfile and its build context
//!   cases/<name>/expected.tar, expected.json    what BuildKit built from it
//!   cases/<name>/differences.txt                (optional) `<path or config field>\t<why>` of
//!                                               what the native build does differently on purpose
//!                                               (a path ending in `=` allows that path alone, not what is under it)
//!
//! Each base is put in the native image store as a pulled one would be; each case is built by
//! `docker_action.buildImage` as a Docker action's would be, its layers merged (`Store.flatten`)
//! and walked beside the extracted `expected.tar`: every path with its kind, mode, owner, size,
//! and content hash or link target, then the config's env, entrypoint, cmd, working directory
//! and user. A difference not in `differences.txt` fails the test and is printed; so is a
//! documented one that did not happen (the list does not go stale). As root, so owners can be
//! compared, in the container `.github/scripts/dockerfile-diff.sh` runs.

const std = @import("std");
const linux = std.os.linux;
const Backend = @import("Backend.zig");
const docker_action = @import("docker_action.zig");
const images = @import("images.zig");
const Store = @import("Store.zig");

const Allocator = std.mem.Allocator;
const Sha256 = @import("../sha256.zig").Sha256;

/// One path of a tree, as it is compared.
const Entry = struct { path: []const u8, line: []const u8 };

fn lessThan(_: void, a: Entry, b: Entry) bool {
    return std.mem.order(u8, a.path, b.path) == .lt;
}

/// Every path under `root` (not `root` itself) with what the oracle compares, sorted. A whiteout
/// (overlay's character device 0:0) is left out: it is a deletion, which a flattened tree keeps
/// to hide the rootfs below it, and the expected tree has nothing of the sort.
fn walk(arena: Allocator, io: std.Io, root: []const u8) ![]const Entry {
    var out: std.ArrayList(Entry) = .empty;
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(arena, "");
    while (stack.pop()) |rel| {
        const dir_path = if (rel.len == 0) root else try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, rel });
        var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true, .follow_symlinks = false });
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            const path = if (rel.len == 0) try arena.dupe(u8, e.name) else try std.fmt.allocPrint(arena, "{s}/{s}", .{ rel, e.name });
            const full = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ root, path }, 0);
            var st: linux.Statx = undefined;
            const rc = linux.statx(linux.AT.FDCWD, full, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .SIZE = true }, &st);
            if (linux.errno(rc) != .SUCCESS) return error.Stat;
            const mode = st.mode & 0o7777;
            const kind = st.mode & linux.S.IFMT;
            const detail: []const u8 = switch (kind) {
                linux.S.IFDIR => blk: {
                    try stack.append(arena, path);
                    break :blk "";
                },
                linux.S.IFREG => blk: {
                    const data = try std.Io.Dir.cwd().readFileAlloc(io, full, arena, .limited(1 << 30));
                    var sum: [32]u8 = undefined;
                    Sha256.hash(data, &sum, .{});
                    break :blk try std.fmt.allocPrint(arena, "{d} {s}", .{ st.size, &std.fmt.bytesToHex(sum, .lower) });
                },
                linux.S.IFLNK => blk: {
                    var buf: [std.fs.max_path_bytes]u8 = undefined;
                    const n = try dir.readLink(io, e.name, &buf);
                    break :blk try arena.dupe(u8, buf[0..n]);
                },
                linux.S.IFCHR => if (st.rdev_major == 0 and st.rdev_minor == 0) continue else try std.fmt.allocPrint(arena, "{d}:{d}", .{ st.rdev_major, st.rdev_minor }),
                else => "",
            };
            try out.append(arena, .{
                .path = path,
                .line = try std.fmt.allocPrint(arena, "{s} {o:0>4} {d}:{d} {s}", .{
                    kindName(kind),
                    mode,
                    st.uid,
                    st.gid,
                    detail,
                }),
            });
        }
    }
    std.mem.sortUnstable(Entry, out.items, {}, lessThan);
    return out.items;
}

fn kindName(kind: u32) []const u8 {
    return switch (kind) {
        linux.S.IFDIR => "dir",
        linux.S.IFREG => "file",
        linux.S.IFLNK => "link",
        linux.S.IFCHR => "chr",
        linux.S.IFBLK => "blk",
        linux.S.IFIFO => "fifo",
        linux.S.IFSOCK => "sock",
        else => "other",
    };
}

fn run(arena: Allocator, io: std.Io, argv: []const []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = argv });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s}{s}\n", .{ argv[0], res.stdout, res.stderr });
        return error.CommandFailed;
    }
}

fn read(arena: Allocator, io: std.Io, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64 << 20));
}

fn joinList(arena: Allocator, items: []const []const u8) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    for (items, 0..) |x, i| {
        if (i > 0) try w.writer.writeAll(" | ");
        try w.writer.writeAll(x);
    }
    return w.written();
}

/// The config fields the oracle compares, one line each.
fn configLines(arena: Allocator, c: images.Image) ![]const Entry {
    var out: std.ArrayList(Entry) = .empty;
    try out.append(arena, .{ .path = "config:env", .line = try joinList(arena, c.env) });
    try out.append(arena, .{ .path = "config:entrypoint", .line = try joinList(arena, c.entrypoint) });
    try out.append(arena, .{ .path = "config:cmd", .line = try joinList(arena, c.cmd) });
    try out.append(arena, .{ .path = "config:workdir", .line = if (c.workdir.len == 0) "/" else c.workdir });
    try out.append(arena, .{ .path = "config:user", .line = if (images.runsAsRoot(c.user)) "root" else c.user });
    return out.items;
}

/// What the case's `differences.txt` allows: a path (or a directory, which allows what is under
/// it; a path ending in `=` allows that path alone) and why, and whether the difference was seen.
const Allowed = struct { path: []const u8, why: []const u8, seen: bool = false };

fn allowedFor(arena: Allocator, io: std.Io, case_dir: []const u8) ![]Allowed {
    var out: std.ArrayList(Allowed) = .empty;
    const text = std.Io.Dir.cwd().readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}/differences.txt", .{case_dir}), arena, .limited(1 << 20)) catch |e| switch (e) {
        error.FileNotFound => return out.items,
        else => return e,
    };
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        if (l.len == 0 or l[0] == '#') continue;
        const tab = std.mem.indexOfScalar(u8, l, '\t') orelse return error.BadDifferences;
        try out.append(arena, .{ .path = l[0..tab], .why = l[tab + 1 ..] });
    }
    return out.items;
}

fn allows(list: []Allowed, path: []const u8) ?*Allowed {
    for (list) |*a| {
        if (a.path.len > 0 and a.path[a.path.len - 1] == '=') {
            if (std.mem.eql(u8, a.path[0 .. a.path.len - 1], path)) return a;
            continue;
        }
        if (std.mem.eql(u8, a.path, path)) return a;
        if (std.mem.startsWith(u8, path, a.path) and path.len > a.path.len and path[a.path.len] == '/') return a;
    }
    return null;
}

/// The differences between `native` and `expected` (sorted by path), the allowed ones marked
/// seen; the rest printed, and their number.
fn compare(case: []const u8, native: []const Entry, expected: []const Entry, allowed: []Allowed) !usize {
    var bad: usize = 0;
    var i: usize = 0;
    var j: usize = 0;
    while (i < native.len or j < expected.len) {
        const order: std.math.Order = if (i == native.len) .gt else if (j == expected.len) .lt else std.mem.order(u8, native[i].path, expected[j].path);
        const path = if (order == .gt) expected[j].path else native[i].path;
        const same = order == .eq and std.mem.eql(u8, native[i].line, expected[j].line);
        defer {
            if (order != .gt) i += 1;
            if (order != .lt) j += 1;
        }
        if (same) continue;
        const have: []const u8 = if (order == .gt) "(missing)" else native[i].line;
        const want: []const u8 = if (order == .lt) "(not in BuildKit's)" else expected[j].line;
        if (allows(allowed, path)) |a| {
            a.seen = true;
            continue;
        }
        bad += 1;
        std.debug.print("{s}: {s}\n    native:   {s}\n    BuildKit: {s}\n", .{ case, path, have, want });
    }
    return bad;
}

test "allows: a path with a trailing = allows that path alone, any other one what is under it" {
    var list = [_]Allowed{ .{ .path = "a=", .why = "" }, .{ .path = "b", .why = "" } };
    try std.testing.expect(allows(&list, "a") != null);
    try std.testing.expect(allows(&list, "a/f") == null);
    try std.testing.expect(allows(&list, "b") != null);
    try std.testing.expect(allows(&list, "b/f") != null);
    try std.testing.expect(allows(&list, "bc") == null);
}

test "oracle: the Dockerfile builder builds what BuildKit builds" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const dir = env.get("ZIG_RUNNER_DOCKERFILE_ORACLE") orelse return error.SkipZigTest;
    const only = env.get("ZIG_RUNNER_DOCKERFILE_ORACLE_ONLY") orelse "";
    if (std.os.linux.geteuid() != 0) {
        std.debug.print("the Dockerfile oracle compares owners, and needs root\n", .{});
        return error.SkipZigTest;
    }
    const cwd = std.Io.Dir.cwd();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    const work = try tmp.dir.realPathFileAlloc(io, ".", arena);

    // The bases, in the image store as a pulled image is.
    const images_dir = try std.fmt.allocPrint(arena, "{s}/images", .{work});
    var bases = std.mem.splitScalar(u8, try read(arena, io, try std.fmt.allocPrint(arena, "{s}/bases.txt", .{dir})), '\n');
    while (bases.next()) |l| {
        if (l.len == 0) continue;
        const sp = std.mem.indexOfScalar(u8, l, ' ').?;
        const entry = try std.fmt.allocPrint(arena, "{s}/{s}", .{ images_dir, try images.key(arena, l[0..sp]) });
        try cwd.createDirPath(io, try std.fmt.allocPrint(arena, "{s}/rootfs", .{entry}));
        try run(arena, io, &.{ "tar", "-C", try std.fmt.allocPrint(arena, "{s}/rootfs", .{entry}), "--numeric-owner", "-xpf", try std.fmt.allocPrint(arena, "{s}/bases/{s}.tar", .{ dir, l[sp + 1 ..] }) });
        try cwd.writeFile(io, .{
            .sub_path = try std.fmt.allocPrint(arena, "{s}/config.json", .{entry}),
            .data = try read(arena, io, try std.fmt.allocPrint(arena, "{s}/bases/{s}.json", .{ dir, l[sp + 1 ..] })),
        });
    }
    cfg.images = images_dir;
    // The images' own /usr: the tests' binds of the host's would hide it from every RUN.
    cfg.binds = &.{};
    var b = try Backend.init(arena, io, std.testing.allocator, cfg);
    defer b.deinit();

    var cases = try cwd.openDir(io, try std.fmt.allocPrint(arena, "{s}/cases", .{dir}), .{ .iterate = true });
    defer cases.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = cases.iterate();
    while (try it.next(io)) |e| if (e.kind == .directory and std.mem.indexOf(u8, e.name, only) != null)
        try names.append(arena, try arena.dupe(u8, e.name));
    std.mem.sortUnstable([]const u8, names.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    try std.testing.expect(names.items.len > 0);

    var failures: usize = 0;
    for (names.items) |name| {
        const case_dir = try std.fmt.allocPrint(arena, "{s}/cases/{s}", .{ dir, name });
        std.debug.print("oracle: {s}\n", .{name});
        // The native build, as a Docker action's.
        const built = switch (try docker_action.buildImage(&b, .{
            .dir = try std.fmt.allocPrint(arena, "{s}/ctx", .{case_dir}),
            .context = ".",
            .dockerfile = "Dockerfile",
        })) {
            .image => |i| i,
            .failed => |why| {
                std.debug.print("{s}: the native build failed: {s}\n", .{ name, why });
                failures += 1;
                continue;
            },
        };
        const bottom_first = try arena.alloc([]const u8, built.lowers.len);
        for (built.lowers, 0..) |l, k| bottom_first[built.lowers.len - 1 - k] = l;
        const merged = try std.fmt.allocPrint(arena, "{s}/native-{s}", .{ work, name });
        try Store.flatten(arena, io, bottom_first, merged, b.opaqueXattr());
        // What BuildKit built.
        const expected_dir = try std.fmt.allocPrint(arena, "{s}/expected-{s}", .{ work, name });
        try cwd.createDirPath(io, expected_dir);
        try run(arena, io, &.{ "tar", "-C", expected_dir, "--numeric-owner", "-xpf", try std.fmt.allocPrint(arena, "{s}/expected.tar", .{case_dir}) });

        const allowed = try allowedFor(arena, io, case_dir);
        const native = try std.mem.concat(arena, Entry, &.{ try walk(arena, io, merged), try configLines(arena, built.config) });
        const want_config = try images.parseConfig(arena, try read(arena, io, try std.fmt.allocPrint(arena, "{s}/expected.json", .{case_dir})));
        const expected = try std.mem.concat(arena, Entry, &.{ try walk(arena, io, expected_dir), try configLines(arena, want_config) });
        std.mem.sortUnstable(Entry, @constCast(native), {}, lessThan);
        std.mem.sortUnstable(Entry, @constCast(expected), {}, lessThan);
        failures += try compare(name, native, expected, allowed);
        for (allowed) |al| if (!al.seen) {
            std.debug.print("{s}: differences.txt allows {s} ({s}), which does not differ\n", .{ name, al.path, al.why });
            failures += 1;
        };
        std.Io.Dir.cwd().deleteTree(io, merged) catch {};
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}
