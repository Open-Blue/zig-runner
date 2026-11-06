//! The tool cache's trees, checked in "Set up job" (docs/native-backend.md, "Tool cache"): the
//! native counterpart of `dagger/tool_trees.sh`, which the Dagger backend runs in a container.
//! A script that pins a tree's digest (install-zig.sh pins Zig's) skips its own check of the tree
//! when the runner gives it the same one (`ZIG_RUNNER_TOOL_TREES`), and a replayed step that
//! names a directory in the tool cache is trusted only when a tree here holds it
//! (`Exec.toolDirNotHeld`, #229).
//!
//! For each directory `TOOL/VERSION/NAME` of the tool cache (the layout actions/tool-cache gives
//! what setup actions unpack, and install-zig.sh's `zig/VERSION/zig-ARCH-linux-VERSION`) the
//! digest is the one install-zig.sh pins, run inside the tree:
//!
//!   find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum
//!
//! Re-reading a tree (19,500 files and 309 MB for Zig 0.17.0) costs about 1 s on the laptop and
//! 10-19 s on razorbill, so a check keeps a list of one line per file (path, size, inode, mtime,
//! ctime, sha256) and re-reads only the files whose line changed. As in the script, that is sound
//! because the lists are the runner's alone (`lists_dir` is in no volume a step mounts), and any
//! write to a file sets its ctime to now, which a step cannot set back (that takes the clock, and
//! steps have no CAP_SYS_TIME). A file written twice within one tick of the kernel's coarse clock
//! keeps its ctime, so a file whose ctime is within `Limits.racy_s` of the check's start is listed
//! as "racy", which no stat matches, and is read again next time (git's "racy clean" entries).
//!
//! Unlike the script, this runs in the runner's process, on a directory a job can write, so it is
//! confined and bounded. Every look at the volume is relative to a directory descriptor, through
//! `sandbox.openIn` with no symlink and no mount crossed, so a link a job planted is never taken;
//! only regular files are opened, with O_NONBLOCK, so a pipe cannot hold the check. Files, bytes
//! read, depth and time are limited (`Limits`), the job's cancel is seen at every file and every
//! block read, and a tree the check stopped in is left out, as one it could not read is: a step
//! then checks it itself, and a replayed step that names it runs again.

const std = @import("std");
const linux = std.os.linux;
const dagger = @import("../dagger.zig");
const sandbox = @import("sandbox.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// What one check may spend. Zig 0.17.0 is 19,500 files and 309 MB; the defaults leave room for a
/// few such tools and stop a tree that is not one.
pub const Limits = struct {
    /// Files in one tree.
    tree_files: u32 = 65_536,
    /// Files, directories and trees visited by the whole check.
    visited: u32 = 400_000,
    /// Bytes read (hashed) by the whole check: what is not in a list yet or changed since.
    read_bytes: u64 = 4 << 30,
    /// Directories deep, below the tool cache.
    depth: u32 = 48,
    /// The whole check. Razorbill's cold check of Zig is 10-19 s.
    time_ms: i64 = 60_000,
    /// See the file's comment.
    racy_s: i64 = 2,
};

/// The environment value steps get (`DIGEST TREE` lines, `Exec.tool_trees`) and the line "Set up
/// job" says.
pub const Verdict = struct { env: []const u8, note: []const u8 };

const resolve_no_xdev = 0x01;
const resolve_no_symlinks = 0x04;
/// Both the walk and the reads: no link taken, no other filesystem entered.
const confined = resolve_no_xdev | resolve_no_symlinks;
/// A list is a line per file; one larger than this is not read, and the tree is read whole.
const max_list_bytes = 64 << 20;
const max_trees = 512;
/// Tools, or versions of one, in the tool cache: the names kept to walk below them.
const max_names = 1024;

/// Checks the trees under `cache` (the tool cache volume's directory on the host), keeping their
/// lists in `lists`, and says what steps are given. The trees' paths are `mount`'s (where steps
/// see the volume). `gpa` holds one tree's files at a time.
pub fn check(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    cache: []const u8,
    lists: []const u8,
    mount: []const u8,
    limits: Limits,
    cancel: ?*const dagger.Cancel,
) Allocator.Error!Verdict {
    var c: Check = .{
        .io = io,
        .gpa = gpa,
        .limits = limits,
        .cancel = cancel,
        .deadline_ms = nowMs(io) + limits.time_ms,
        .racy_from = @as(i128, std.Io.Clock.real.now(io).toNanoseconds()) -
            @as(i128, limits.racy_s) * std.time.ns_per_s,
    };
    var env: std.ArrayList(u8) = .empty;
    var note: std.ArrayList(u8) = .empty;
    const root = openRoot(arena, cache) orelse return .{
        .env = "",
        .note = "Tool cache: not checked (the volume cannot be opened)",
    };
    defer _ = linux.close(root);
    const found = c.trees(arena, root) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        // Some of the trees may be there: their lists stay.
        else => found: {
            c.complete = false;
            break :found &.{};
        },
    };
    for (found) |rel| {
        const digest = c.tree(root, lists, rel) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            // This one only; the others are still checked.
            error.Unreadable => continue,
            error.Stopped => break,
        };
        try env.print(arena, "{s}{x} {s}/{s}", .{
            if (env.items.len > 0) "\n" else "",
            &digest.sum,
            mount,
            rel,
        });
        try note.print(arena, "{s}{s} ({d} files, {d} read)", .{
            if (note.items.len > 0) ", " else "",
            rel,
            digest.files,
            digest.read,
        });
    }
    if (c.complete) forgetGone(arena, io, lists, found);
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, if (note.items.len == 0)
        "Tool cache: no trees to check"
    else
        try std.fmt.allocPrint(arena, "Tool cache: checked {s}", .{note.items}));
    if (c.why) |why| try text.print(arena, "; stopped: {s}", .{why});
    return .{ .env = env.items, .note = text.items };
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.awake.now(io).toMilliseconds();
}

/// A check in progress: what it has spent, and why it stopped when it did.
const Check = struct {
    io: std.Io,
    gpa: Allocator,
    limits: Limits,
    cancel: ?*const dagger.Cancel,
    deadline_ms: i64,
    /// Files with a ctime from here on are "racy" (ns since the epoch).
    racy_from: i128,
    visited: u32 = 0,
    read: u64 = 0,
    why: ?[]const u8 = null,
    /// Every tree was found (the walk to them was not cut short), so a list without one is stale.
    complete: bool = true,

    const Error = error{ OutOfMemory, Unreadable, Stopped };

    /// One more entry looked at: the job's cancel and the clock seen, the clock every 64th.
    fn visit(c: *Check) error{Stopped}!void {
        c.visited += 1;
        if (c.visited > c.limits.visited) return c.stop("too many files and directories");
        if (c.visited % 64 == 0) try c.poll();
    }

    fn poll(c: *Check) error{Stopped}!void {
        if (c.cancel) |x| if (x.requested.load(.acquire)) return c.stop("the job was cancelled");
        if (nowMs(c.io) > c.deadline_ms) return c.stop("out of time");
    }

    fn stop(c: *Check, why: []const u8) error{Stopped} {
        c.why = c.why orelse why;
        c.complete = false;
        return error.Stopped;
    }

    /// The directories `TOOL/VERSION/NAME` of the tool cache that are real directories, none
    /// named with a dot (install-zig.sh unpacks into one before moving a tree into place), in
    /// the byte order of the whole path (`sort` in the C locale).
    fn trees(c: *Check, arena: Allocator, root: linux.fd_t) Error![]const []const u8 {
        var found: std.ArrayList([]const u8) = .empty;
        try c.level(arena, root, "", 0, &found);
        std.mem.sort([]const u8, found.items, {}, pathLess);
        return found.items;
    }

    fn level(
        c: *Check,
        arena: Allocator,
        dir: linux.fd_t,
        prefix: []const u8,
        depth: u32,
        found: *std.ArrayList([]const u8),
    ) Error!void {
        var names: std.ArrayList([]const u8) = .empty;
        var it = (std.Io.Dir{ .handle = dir }).iterate();
        while (it.next(c.io) catch return error.Unreadable) |e| {
            try c.visit();
            if (e.kind != .directory or !treeName(e.name)) continue;
            if (names.items.len >= max_names) return c.stop("too many tools or versions");
            try names.append(arena, try arena.dupe(u8, e.name));
        }
        for (names.items) |name| {
            const rel = if (prefix.len == 0)
                name
            else
                try std.fmt.allocPrint(arena, "{s}/{s}", .{ prefix, name });
            if (depth == 2) {
                if (found.items.len >= max_trees) {
                    c.complete = false;
                    c.why = c.why orelse "too many trees";
                    return;
                }
                try found.append(arena, rel);
                continue;
            }
            const sub = openDir(dir, try arena.dupeSentinel(u8, name, 0)) orelse continue;
            defer _ = linux.close(sub);
            try c.level(arena, sub, rel, depth + 1, found);
        }
    }

    const Digest = struct { sum: [Sha256.digest_length]u8, files: usize, read: usize };

    /// One tree's digest, from its list where a file's line is unchanged, and the list rewritten.
    fn tree(
        c: *Check,
        root: linux.fd_t,
        lists: []const u8,
        rel: []const u8,
    ) Error!Digest {
        var ta: std.heap.ArenaAllocator = .init(c.gpa);
        defer ta.deinit();
        const t = ta.allocator();
        try c.visit();
        const top = openDir(root, try t.dupeSentinel(u8, rel, 0)) orelse
            return error.Unreadable;
        defer _ = linux.close(top);

        var files: std.ArrayList(File) = .empty;
        var odd = false;
        try c.walk(t, top, "", 0, &files, &odd);
        // A name sha256sum would escape, or one a list's line cannot hold: not reported, a step
        // checks that tree itself.
        if (odd) return error.Unreadable;
        std.mem.sort(File, files.items, {}, File.less);

        const list_path = try std.fmt.allocPrint(t, "{s}/{s}.stat", .{ lists, rel });
        const old = c.readList(t, list_path, files.items);
        var sums = Sha256.init(.{});
        var reread: usize = 0;
        var out: std.ArrayList(u8) = .empty;
        for (files.items, 0..) |*f, i| {
            try c.poll();
            const kept = if (old) |o| o[i].keep(f.stat) else null;
            if (kept) |h| f.hash = h else {
                try c.hashFile(t, top, f);
                reread += 1;
            }
            const racy = f.stat.ctime >= c.racy_from;
            const st = f.stat;
            try out.print(t, "{s}\t{d}\t{d}\t{d}\t", .{ f.path, st.size, st.ino, st.mtime });
            if (racy) try out.appendSlice(t, "racy") else try out.print(t, "{d}", .{f.stat.ctime});
            try out.print(t, "\t{x}\n", .{&f.hash});
            // `sha256sum`'s line, which install-zig.sh pins the digest of.
            var line: std.ArrayList(u8) = .empty;
            try line.print(t, "{x}  {s}\n", .{ &f.hash, f.path });
            sums.update(line.items);
        }
        var digest: Digest = .{ .sum = undefined, .files = files.items.len, .read = reread };
        sums.final(&digest.sum);
        keepList(t, c.io, list_path, out.items);
        return digest;
    }

    /// `dir`'s files, and its directories' below it (`prefix` the path from the tree's top, `./`
    /// first): regular files only, as `find -type f`. A symbolic link, a pipe or a device is
    /// neither opened nor followed.
    fn walk(
        c: *Check,
        t: Allocator,
        dir: linux.fd_t,
        prefix: []const u8,
        depth: u32,
        files: *std.ArrayList(File),
        odd: *bool,
    ) Error!void {
        if (depth > c.limits.depth) return c.stop("a tree is too deep");
        const here = if (prefix.len == 0) "." else prefix;
        var subdirs: std.ArrayList([]const u8) = .empty;
        var it = (std.Io.Dir{ .handle = dir }).iterate();
        while (it.next(c.io) catch return error.Unreadable) |e| {
            try c.visit();
            for (e.name) |ch| if (ch < 0x20 or ch == 0x7f or ch == '\\') {
                odd.* = true;
            };
            const name = try t.dupeSentinel(u8, e.name, 0);
            var st: linux.Statx = undefined;
            if (linux.errno(linux.statx(dir, name, linux.AT.SYMLINK_NOFOLLOW, .{
                .TYPE = true,
                .SIZE = true,
                .INO = true,
                .MTIME = true,
                .CTIME = true,
            }, &st)) != .SUCCESS) return error.Unreadable;
            const kind: std.Io.File.Kind = switch (st.mode & linux.S.IFMT) {
                linux.S.IFREG => .file,
                linux.S.IFDIR => .directory,
                else => .unknown,
            };
            switch (kind) {
                .file => {
                    if (files.items.len >= c.limits.tree_files)
                        return c.stop("a tree has too many files");
                    try files.append(t, .{
                        .path = try std.fmt.allocPrint(t, "{s}/{s}", .{ here, name }),
                        .stat = Stat.of(st),
                        .hash = undefined,
                    });
                },
                .directory => try subdirs.append(t, name),
                else => {},
            }
        }
        for (subdirs.items) |name| {
            const sub = openDir(dir, name.ptr[0..name.len :0]) orelse return error.Unreadable;
            defer _ = linux.close(sub);
            const path = try std.fmt.allocPrint(t, "{s}/{s}", .{ here, name });
            try c.walk(t, sub, path, depth + 1, files, odd);
        }
    }

    /// `f`'s sha256, and its stat as the descriptor says it, taken before the first byte is read:
    /// a write after it has a later ctime than the line records.
    fn hashFile(c: *Check, t: Allocator, top: linux.fd_t, f: *File) Error!void {
        const rel = try t.dupeSentinel(u8, f.path[2..], 0);
        const fd = switch (sandbox.openIn(top, rel, .{
            .ACCMODE = .RDONLY,
            .NONBLOCK = true,
            .NOCTTY = true,
        }, 0, confined)) {
            .fd => |x| x,
            .err => return error.Unreadable,
        };
        defer _ = linux.close(fd);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
            .TYPE = true,
            .SIZE = true,
            .INO = true,
            .MTIME = true,
            .CTIME = true,
        }, &st)) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFREG) return error.Unreadable;
        f.stat = Stat.of(st);
        var h = Sha256.init(.{});
        var block: [64 * 1024]u8 = undefined;
        while (true) {
            const n = linux.read(fd, &block, block.len);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.Unreadable,
            }
            if (n == 0) break;
            c.read += n;
            if (c.read > c.limits.read_bytes) return c.stop("too many bytes to read");
            h.update(block[0..n]);
            try c.poll();
        }
        h.final(&f.hash);
    }

    /// The list at `path`, when it holds exactly `files`' paths in order and each line parses;
    /// otherwise null and every file is read.
    fn readList(c: *Check, t: Allocator, path: []const u8, files: []const File) ?[]Line {
        const text = std.Io.Dir.cwd().readFileAlloc(c.io, path, t, .limited(max_list_bytes)) catch
            return null;
        const lines = t.alloc(Line, files.len) catch return null;
        var rows = std.mem.splitScalar(u8, text, '\n');
        for (files, lines) |f, *l| {
            l.* = Line.parse(rows.next() orelse return null, f.path) orelse return null;
        }
        // Only the empty piece after the last newline is left.
        if (!std.mem.eql(u8, rows.rest(), "")) return null;
        return lines;
    }
};

/// A file of a tree: its path from the tree's top (`./a/b`), its stat and its sha256.
const File = struct {
    path: []const u8,
    stat: Stat,
    hash: [Sha256.digest_length]u8,

    fn less(_: void, a: File, b: File) bool {
        return pathLess({}, a.path, b.path);
    }
};

const Stat = struct {
    size: u64,
    ino: u64,
    mtime: i128,
    ctime: i128,

    fn of(st: linux.Statx) Stat {
        return .{
            .size = st.size,
            .ino = st.ino,
            .mtime = ns(st.mtime),
            .ctime = ns(st.ctime),
        };
    }

    fn ns(t: linux.statx_timestamp) i128 {
        return @as(i128, t.sec) * std.time.ns_per_s + t.nsec;
    }
};

/// A list's line, as read: the stat it recorded (a ctime that is null was "racy") and the hash.
const Line = struct {
    stat: Stat,
    racy: bool,
    hash: [Sha256.digest_length]u8,

    fn parse(row: []const u8, path: []const u8) ?Line {
        var f = std.mem.splitScalar(u8, row, '\t');
        if (!std.mem.eql(u8, f.next() orelse return null, path)) return null;
        const size = std.fmt.parseInt(u64, f.next() orelse return null, 10) catch return null;
        const ino = std.fmt.parseInt(u64, f.next() orelse return null, 10) catch return null;
        const mtime = std.fmt.parseInt(i128, f.next() orelse return null, 10) catch return null;
        const ctime_text = f.next() orelse return null;
        const hash_text = f.next() orelse return null;
        if (f.next() != null) return null;
        const racy = std.mem.eql(u8, ctime_text, "racy");
        const ctime = if (racy) 0 else std.fmt.parseInt(i128, ctime_text, 10) catch return null;
        var hash: [Sha256.digest_length]u8 = undefined;
        if (hash_text.len != 2 * hash.len) return null;
        _ = std.fmt.hexToBytes(&hash, hash_text) catch return null;
        return .{
            .stat = .{ .size = size, .ino = ino, .mtime = mtime, .ctime = ctime },
            .racy = racy,
            .hash = hash,
        };
    }

    /// The hash, when the file is as the line says it was and the line was not made inside the
    /// clock's tick of a write.
    fn keep(l: Line, now: Stat) ?[Sha256.digest_length]u8 {
        if (l.racy) return null;
        const s = l.stat;
        if (s.size != now.size or s.ino != now.ino or s.mtime != now.mtime or s.ctime != now.ctime)
            return null;
        return l.hash;
    }
};

fn pathLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// A name that can be a tree's (or its parents'): what a tool cache's directories are called,
/// and the characters `Exec.toolDirNotHeld`'s caller and `set_up.path_chars` let into a path.
fn treeName(name: []const u8) bool {
    if (name.len == 0 or name[0] == '.') return false;
    for (name) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and std.mem.indexOfScalar(u8, "._+-", ch) == null)
            return false;
    }
    return true;
}

fn openRoot(arena: Allocator, path: []const u8) ?linux.fd_t {
    const fd = linux.open(arena.dupeSentinel(u8, path, 0) catch return null, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    return std.math.cast(linux.fd_t, fd);
}

fn openDir(parent: linux.fd_t, name: [:0]const u8) ?linux.fd_t {
    return switch (sandbox.openIn(parent, name, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOCTTY = true,
    }, 0, confined)) {
        .fd => |fd| fd,
        .err => null,
    };
}

/// Writes a tree's list to a file of its own and moves it into place, as a job set up at the same
/// time reads the old one or the new, never a part. A list that cannot be kept costs the next
/// check a read of the tree.
fn keepList(t: Allocator, io: std.Io, path: []const u8, text: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| cwd.createDirPath(io, dir) catch return;
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const part = std.fmt.allocPrint(t, "{s}.{x}", .{ path, &raw }) catch return;
    cwd.writeFile(io, .{ .sub_path = part, .data = text }) catch {
        cwd.deleteFile(io, part) catch {};
        return;
    };
    cwd.rename(part, cwd, path, io) catch cwd.deleteFile(io, part) catch {};
}

/// Removes the lists of trees that are gone.
fn forgetGone(arena: Allocator, io: std.Io, lists: []const u8, found: []const []const u8) void {
    var tools = std.Io.Dir.cwd().openDir(io, lists, .{ .iterate = true }) catch return;
    defer tools.close(io);
    var t_it = tools.iterate();
    while (t_it.next(io) catch null) |tool| {
        if (tool.kind != .directory) continue;
        var versions = tools.openDir(io, tool.name, .{ .iterate = true }) catch continue;
        defer versions.close(io);
        var v_it = versions.iterate();
        while (v_it.next(io) catch null) |version| {
            if (version.kind != .directory) continue;
            var names = versions.openDir(io, version.name, .{ .iterate = true }) catch continue;
            defer names.close(io);
            var n_it = names.iterate();
            while (n_it.next(io) catch null) |list| {
                if (list.kind != .file) continue;
                const stem = if (std.mem.endsWith(u8, list.name, ".stat"))
                    list.name[0 .. list.name.len - ".stat".len]
                else
                    continue;
                const rel = std.fmt.allocPrint(arena, "{s}/{s}/{s}", .{
                    tool.name,
                    version.name,
                    stem,
                }) catch return;
                const present = for (found) |f| {
                    if (std.mem.eql(u8, f, rel)) break true;
                } else false;
                if (!present) names.deleteFile(io, list.name) catch {};
            }
        }
    }
}

// --- tests ---

const tree_rel = "zig/0.17.0/zig-x86_64-linux-0.17.0";

/// A tool cache with the tree of `tree_rel` in it: what a few of Zig's files look like, a name
/// that sorts differently by component than by path, and what a job could leave beside them (a
/// link out of the tree, a pipe, an empty directory, a dot-named directory a tree is unpacked in).
const Fixture = struct { cache: []const u8, lists: []const u8 };

fn fixture(arena: Allocator, tmp: *std.testing.TmpDir) !Fixture {
    const io = std.testing.io;
    const d = tmp.dir;
    for ([_][]const u8{
        tree_rel ++ "/lib/std",
        tree_rel ++ "/a-b",
        tree_rel ++ "/a",
        tree_rel ++ "/empty",
        "zig/0.17.0/.unpacking/x",
        "node/22.0.0/x64/bin",
        "shallow/1",
    }) |p| try d.createDirPath(io, try std.fmt.allocPrint(arena, "cache/{s}", .{p}));
    for ([_][2][]const u8{
        .{ tree_rel ++ "/zig", "zig binary\n" },
        .{ tree_rel ++ "/lib/std/std.zig", "pub fn main() void {}\n" },
        .{ tree_rel ++ "/a-b/x", "dash\n" },
        .{ tree_rel ++ "/a/x", "plain\n" },
        .{ tree_rel ++ "/with space", "space\n" },
        .{ "zig/0.17.0/.unpacking/x/f", "half unpacked\n" },
        .{ "node/22.0.0/x64/bin/node", "node\n" },
        .{ "shallow/1/f", "too shallow\n" },
    }) |f| try d.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "cache/{s}", .{f[0]}),
        .data = f[1],
    });
    // A link to the host's files, a link to its directory, and a pipe nothing writes to.
    try d.symLink(io, "/etc/passwd", "cache/" ++ tree_rel ++ "/passwd", .{});
    try d.symLink(io, "/etc", "cache/" ++ tree_rel ++ "/etc", .{});
    try d.createDirPath(io, "lists");
    const root = try d.realPathFileAlloc(io, ".", arena);
    const cache = try std.fmt.allocPrint(arena, "{s}/cache", .{root});
    const fifo = try std.process.run(arena, io, .{
        .argv = &.{ "mkfifo", try std.fmt.allocPrint(arena, "{s}/{s}/pipe", .{ cache, tree_rel }) },
    });
    try std.testing.expect(fifo.term == .exited and fifo.term.exited == 0);
    return .{ .cache = cache, .lists = try std.fmt.allocPrint(arena, "{s}/lists", .{root}) };
}

/// The digest install-zig.sh pins, by the commands it runs.
fn shellDigest(arena: Allocator, tree: []const u8) ![]const u8 {
    const out = try std.process.run(arena, std.testing.io, .{
        .argv = &.{
            "sh", "-c",
            "cd \"$0\" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | " ++
                "sha256sum | cut -c1-64",
            tree,
        },
    });
    try std.testing.expect(out.term == .exited and out.term.exited == 0);
    return std.mem.trim(u8, out.stdout, "\n");
}

fn expectIn(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ needle, haystack });
        return error.TestUnexpectedResult;
    }
}

fn checkWith(arena: Allocator, f: anytype, limits: Limits, cancel: ?*const dagger.Cancel) !Verdict {
    const gpa = std.testing.allocator;
    return check(arena, gpa, std.testing.io, f.cache, f.lists, "/t", limits, cancel);
}

test "tool trees: the digest is the one install-zig.sh pins, for the cache's trees only" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const v = try checkWith(arena, f, .{}, null);
    const want = try std.fmt.allocPrint(arena, "{s} /t/node/22.0.0/x64\n{s} /t/{s}", .{
        try shellDigest(arena, try std.fmt.allocPrint(arena, "{s}/node/22.0.0/x64", .{f.cache})),
        try shellDigest(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.cache, tree_rel })),
        tree_rel,
    });
    try std.testing.expectEqualStrings(want, v.env);
    try std.testing.expectEqualStrings("Tool cache: checked node/22.0.0/x64 (1 files, 1 read), " ++
        tree_rel ++ " (5 files, 5 read)", v.note);
}

test "tool trees: a list spares the reading, and a change it cannot hide is read" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    const tree = try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.cache, tree_rel });
    const first = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const second = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expectEqualStrings(first.env, second.env);
    try expectIn(second.note, tree_rel ++ " (5 files, 0 read)");
    // One byte changed, the size and the mtime put back: the ctime is what a job cannot.
    const forge = "cd \"$0\" && touch -r zig ref && printf 'zig binarY\\n' > zig && " ++
        "touch -r ref zig && rm ref";
    const forged = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", forge, tree } });
    try std.testing.expect(forged.term == .exited and forged.term.exited == 0);
    const third = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try std.testing.expect(!std.mem.eql(u8, first.env, third.env));
    try expectIn(third.note, tree_rel ++ " (5 files, 1 read)");
    try expectIn(third.env, try shellDigest(arena, tree));
}

test "tool trees: a file written within the clock's tick of the check is read next time" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    // Everything was just written: all of it is racy, and none of it is trusted.
    _ = try checkWith(arena, f, .{ .racy_s = 3600 }, null);
    const again = try checkWith(arena, f, .{ .racy_s = 3600 }, null);
    try expectIn(again.note, tree_rel ++ " (5 files, 5 read)");
}

test "tool trees: a list that does not fit is not believed; a gone tree loses its list" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const list = try std.fmt.allocPrint(arena, "{s}/{s}.stat", .{ f.lists, tree_rel });
    // A file added to the tree, and a list cut off in the middle of a line.
    try tmp.dir.writeFile(io, .{ .sub_path = "cache/" ++ tree_rel ++ "/new", .data = "new\n" });
    const cut = try std.Io.Dir.cwd().readFileAlloc(io, list, arena, .limited(1 << 20));
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = list, .data = cut[0 .. cut.len - 20] });
    const v = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    try expectIn(v.note, tree_rel ++ " (6 files, 6 read)");
    try tmp.dir.deleteTree(io, "cache/node");
    _ = try checkWith(arena, f, .{ .racy_s = 0 }, null);
    const gone = tmp.dir.access(io, "lists/node/22.0.0/x64.stat", .{});
    try std.testing.expectError(error.FileNotFound, gone);
    try tmp.dir.access(io, "lists/" ++ tree_rel ++ ".stat", .{});
}

test "tool trees: a check is bounded in files, bytes and depth, and ends with the job" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    // The Zig tree has five files, and the node tree, which sorts first, one.
    const files = try checkWith(arena, f, .{ .tree_files = 3 }, null);
    try expectIn(files.note, "stopped: a tree has too many files");
    try expectIn(files.env, "node/22.0.0/x64");
    try std.testing.expect(std.mem.indexOf(u8, files.env, tree_rel) == null);
    const bytes = try checkWith(arena, f, .{ .read_bytes = 5 }, null);
    try expectIn(bytes.note, "stopped: too many bytes");
    const deep = try checkWith(arena, f, .{ .depth = 0 }, null);
    try expectIn(deep.note, "stopped: a tree is too deep");
    var cancel: dagger.Cancel = .{};
    cancel.request(0);
    const v = try checkWith(arena, f, .{}, &cancel);
    try std.testing.expectEqualStrings("", v.env);
    try expectIn(v.note, "stopped: the job was cancelled");
}

test "tool trees: a name a list cannot hold leaves its tree out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try fixture(arena, &tmp);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "cache/" ++ tree_rel ++ "/back\\slash",
        .data = "x",
    });
    const v = try checkWith(arena, f, .{}, null);
    try std.testing.expect(std.mem.indexOf(u8, v.env, tree_rel) == null);
    try expectIn(v.env, "node/22.0.0/x64");
}
