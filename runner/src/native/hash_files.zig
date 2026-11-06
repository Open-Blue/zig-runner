//! `hashFiles()` on the native backend: glob.zig's search and GitHub's hash over the job's files as
//! the next step would see them, read from the layers themselves.
//!
//! The job's view is overlay's merge of its layers (the steps' uppers, the Zig cache seeds, the
//! rootfs), which is only a mount inside a step's sandbox. The runner does not mount it: that needs
//! privilege a rootless runner has not got, and a mount of the runner's own for each call would be
//! slower than the walk. `Merged` is the merge done by lookup instead, as `Store.flatten` does it
//! for a whole tree: the topmost layer with an entry decides what it is, a whiteout deletes it, a
//! non-directory hides what is below it, and a directory marked opaque stops the directories
//! below it from adding their entries. Overlay's redirects and metacopy, which the runner never
//! asks for but a host's kernel may default to, are refused (the call fails) rather than read
//! wrongly. Mounts (the cache volumes, an action's runtime) are in no layer, so they are not seen,
//! as Dagger's `rootfs` does not see them either.
//!
//! The layers are the job's to write, so every look at one goes through `sandbox.openIn` with no
//! symlink followed: a link in a layer is read, never taken. The links of the merged view (the
//! job's `docs -> ../docs`, which GitHub's `fs.statSync` follows when it hashes a link that
//! `hashFiles()` found) are resolved here, on the merged paths, with `/` the job's root, so an
//! absolute link names the job's file and not the host's, and `..` is taken on the path already
//! resolved. Nothing the job plants reaches a file outside the layers.
//!
//! The job also controls how much there is to do, so a call is bounded (`Limits`): the files and
//! directories its walk visits, the path components it takes, the memory it holds (its own arena,
//! freed when it returns), and it stops when the job is cancelled, also in the middle of a file.
//! A file is read in full, however large and however sparse: the hash is GitHub's, which has no
//! shortcut for holes, so only a cancel ends a read of a file that takes hours.

const std = @import("std");
const linux = std.os.linux;
const expr = @import("../expr.zig");
const glob = @import("../glob.zig");
const sandbox = @import("sandbox.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Error = glob.Fs.Error;

/// What one call may use. A job's own files decide how much work they are.
pub const Limits = struct {
    /// Files and directories the walk visits (`glob.max_nodes`).
    nodes: usize = glob.max_nodes,
    /// Path components taken, one for each name of each path looked up and each entry listed: a
    /// real tree of a million files at depth ten is about twenty million.
    steps: u64 = 200_000_000,
    /// Bytes of the call's arena. A walk of `nodes` entries takes about 1 KB each.
    memory: usize = 2 << 30,
    /// Set when the job is cancelled (`dagger.Cancel.requested`): the call ends at once.
    cancel: ?*const std.atomic.Value(bool) = null,
};

/// The layers of the job's overlay, as it would mount them for the next step.
pub const Stack = struct {
    /// Their directories, topmost first: the job's layers newest first, the Zig cache seeds', then
    /// the rootfs (`Backend.execIn`'s `lowers`, in the same order).
    layers: []const []const u8,
    /// Overlay's opaque-directory attribute: `trusted.overlay.opaque`, or `user.overlay.opaque`
    /// under `userxattr` (`Backend.opaqueXattr`).
    opaque_xattr: [:0]const u8,
    limits: Limits = .{},
};

/// `hashFiles(args)` over `stack`: the SHA-256 of the SHA-256 digests of the files the patterns
/// find under `ws`, in GitHub's order; "" when none. As GitHub's script does, a name that is a
/// directory once links are followed is skipped, and a link is hashed as the file it leads to.
/// The call works in an arena of its own, freed on return: only the result is copied to `out`.
pub fn hashFiles(
    gpa: Allocator,
    out: Allocator,
    io: std.Io,
    stack: Stack,
    ws: []const u8,
    home: []const u8,
    args: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    return switch (try run(&scratch, io, stack, ws, home, args)) {
        .ok => |h| .{ .ok = try out.dupe(u8, h) },
        .failed => |why| .{ .failed = try out.dupe(u8, why) },
    };
}

/// `hashFiles` in `scratch`, which the caller frees.
fn run(
    scratch: *std.heap.ArenaAllocator,
    io: std.Io,
    stack: Stack,
    ws: []const u8,
    home: []const u8,
    args: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    var m: Merged = .{
        .arena = scratch.allocator(),
        .scratch = scratch,
        .io = io,
        .roots = &.{},
        .opaque_xattr = stack.opaque_xattr,
        .limits = stack.limits,
    };
    m.openLayers(stack.layers) catch |e| return failed(&m, e);
    defer m.close();
    return hashAll(&m, ws, home, args) catch |e| failed(&m, e);
}

fn failed(m: *const Merged, e: Error) Allocator.Error!expr.HashFiles.Result {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.FsFailed => .{ .failed = m.why },
    };
}

fn hashAll(m: *Merged, ws: []const u8, home: []const u8, args: []const []const u8) Error!expr.HashFiles.Result {
    const arena = m.arena;
    const files = switch (try glob.find(arena, m.fs(), args, ws, home, m.limits.nodes, &m.why)) {
        .failed => |msg| return .{ .failed = msg },
        .files => |f| f,
    };
    var all = Sha256.init(.{});
    var hashed: usize = 0;
    var path: std.ArrayList(u8) = .empty;
    for (files) |name| {
        path.clearRetainingCapacity();
        try path.print(arena, "{s}/{s}", .{ ws, name });
        const at = (try m.resolve(path.items, true)) orelse
            return .{ .failed = try std.fmt.allocPrint(arena, "{s}: No such file or directory", .{name}) };
        switch (at.node.kind) {
            .dir => continue,
            .file => {},
            else => return .{ .failed = try std.fmt.allocPrint(arena, "{s}: Not a regular file", .{name}) },
        }
        const sum = try m.digest(at.path, at.node.layer);
        all.update(&sum);
        hashed += 1;
    }
    if (hashed == 0) return .{ .ok = "" };
    return .{ .ok = try arena.dupe(u8, &std.fmt.bytesToHex(all.finalResult(), .lower)) };
}

/// What a path of the merged view is.
const Node = struct {
    kind: enum { missing, whiteout, dir, file, symlink, other },
    /// The topmost layer that has it.
    layer: u32 = 0,
    /// Where a link leads.
    target: []const u8 = "",
    /// A directory marked opaque in its layer.
    opaque_dir: bool = false,
};

/// Links followed in one path before it counts as a loop (Linux's `MAXSYMLINKS`).
const max_links = 40;

/// What the kernel takes as a path (`PATH_MAX`, with its terminating zero).
const path_max = 4096;

/// What a path resolves to: the real path and what it is.
const Resolved = struct { path: []const u8, node: Node };

/// The merged view of a stack of layers. Paths are absolute, `/` the job's root, with no symlink,
/// `.` or `..` in a path that names a real entry (`resolve` makes them so); the root is "".
const Merged = struct {
    arena: Allocator,
    /// `arena`'s owner, for its size.
    scratch: *std.heap.ArenaAllocator,
    io: std.Io,
    limits: Limits,
    /// The layers' directories, opened, topmost first.
    roots: []linux.fd_t,
    opaque_xattr: [:0]const u8,
    /// The attributes overlay's other features leave (same prefix as `opaque_xattr`).
    redirect_xattr: [:0]const u8 = "",
    metacopy_xattr: [:0]const u8 = "",
    /// What each real path is, and in which layers it is a directory that adds its entries (the
    /// topmost first; null when it is not a directory).
    nodes: std.StringHashMapUnmanaged(Node) = .empty,
    dirs: std.StringHashMapUnmanaged(?[]const u32) = .empty,
    /// Where each link that was followed leads (what its target resolves to), by the link's path.
    leads: std.StringHashMapUnmanaged(Resolved) = .empty,
    /// The path a top-level `resolve` builds, kept between calls.
    path: std.ArrayList(u8) = .empty,
    steps: u64 = 0,
    /// What went wrong, for `Error.FsFailed`.
    why: []const u8 = "",

    fn openLayers(m: *Merged, layers: []const []const u8) Error!void {
        const prefix = m.opaque_xattr[0 .. m.opaque_xattr.len - "opaque".len];
        m.redirect_xattr = try std.fmt.allocPrintSentinel(m.arena, "{s}redirect", .{prefix}, 0);
        m.metacopy_xattr = try std.fmt.allocPrintSentinel(m.arena, "{s}metacopy", .{prefix}, 0);
        const roots = try m.arena.alloc(linux.fd_t, layers.len);
        for (layers, 0..) |path, i| {
            const fd = linux.open(try m.arena.dupeSentinel(u8, path, 0), .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
            }, 0);
            if (linux.errno(fd) != .SUCCESS) {
                for (roots[0..i]) |r| _ = linux.close(r);
                return m.fail("cannot read the job's layer {s}: {t}", .{ path, linux.errno(fd) });
            }
            roots[i] = std.math.cast(linux.fd_t, fd).?;
        }
        m.roots = roots;
    }

    fn close(m: *Merged) void {
        for (m.roots) |r| _ = linux.close(r);
    }

    fn fail(m: *Merged, comptime fmt: []const u8, args: anytype) Error {
        m.why = try std.fmt.allocPrint(m.arena, fmt, args);
        return error.FsFailed;
    }

    /// One unit of work: counted, and the job's cancel and the call's memory looked at, so a call
    /// the job made too big or that the job gave up on ends here.
    fn tick(m: *Merged) Error!void {
        m.steps += 1;
        if (m.steps > m.limits.steps) return m.fail("hashFiles() took more than {d} steps through the " ++
            "job's files: its tree is too deep or too tangled to search", .{m.limits.steps});
        if (m.limits.cancel) |c| if (c.load(.monotonic)) return m.fail("hashFiles() stopped: the job was cancelled", .{});
        if (m.steps % 1024 == 0 and m.scratch.queryCapacity() > m.limits.memory)
            return m.fail("hashFiles() needed more than {d} MiB of memory: the job's tree is too " ++
                "large or too tangled to search", .{m.limits.memory >> 20});
    }

    fn fs(m: *Merged) glob.Fs {
        return .{ .ptr = m, .vtable = &.{ .stat = statAll, .list = listAll, .realpath = realpathAll } };
    }

    // --- one layer ---

    /// `path` for a layer's `openat2`, in `buf`: relative, "." for the root.
    fn relativeZ(m: *Merged, buf: *[path_max]u8, path: []const u8) Error![:0]const u8 {
        return std.mem.printSentinel(buf, "{s}", .{relative(path)}, 0) catch
            return m.fail("a path in the job's files is longer than {d} bytes", .{path_max - 1});
    }

    /// `path` as a layer has it, with nothing followed: what it is, and where a link leads. A
    /// whiteout is overlay's character device 0:0.
    fn lstat(m: *Merged, layer: u32, path: []const u8) Error!Node {
        var buf: [path_max]u8 = undefined;
        const rel = try m.relativeZ(&buf, path);
        const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
            .PATH = true,
            .NOFOLLOW = true,
        }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| {
                if (e == .NOENT or e == .NOTDIR) return .{ .kind = .missing };
                return m.fail("cannot look at {s} in the job's layers: {t}", .{ path, e });
            },
        };
        defer _ = linux.close(fd);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS)
            return m.fail("cannot look at {s} in the job's layers", .{path});
        const kind = st.mode & linux.S.IFMT;
        if (kind == linux.S.IFDIR) return .{ .kind = .dir, .opaque_dir = try m.attributes(fd, path, true) };
        if (kind == linux.S.IFREG) {
            _ = try m.attributes(fd, path, false);
            return .{ .kind = .file };
        }
        if (kind == linux.S.IFCHR and st.rdev_major == 0 and st.rdev_minor == 0)
            return .{ .kind = .whiteout };
        if (kind != linux.S.IFLNK) return .{ .kind = .other };
        var link: [path_max]u8 = undefined;
        const n = linux.readlinkat(fd, "", &link, link.len);
        if (linux.errno(n) != .SUCCESS or n == link.len)
            return m.fail("cannot read the link {s} in the job's layers", .{path});
        return .{ .kind = .symlink, .target = try m.arena.dupe(u8, link[0..n]) };
    }

    /// What overlay's attributes say of an entry of a layer (`fd` is an `O_PATH` one): whether the
    /// directory is opaque. The call fails when it has a redirect or metacopy, which this merge
    /// does not do: what overlay shows is then not what the entry holds, and the hash would be
    /// wrong without a word (`Store.flatten` refuses them as well).
    fn attributes(m: *Merged, fd: linux.fd_t, path: []const u8, is_dir: bool) Error!bool {
        // Through the descriptor's link in /proc, which these (following) calls take to the file.
        var proc: [32]u8 = undefined;
        const p = std.mem.printSentinel(&proc, "/proc/self/fd/{d}", .{fd}, 0) catch
            return m.fail("cannot look at {s}'s attributes in the job's layers", .{path});
        var list: [4096]u8 = undefined;
        const n = linux.listxattr(p, &list, list.len);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            // A file system without attributes cannot have marked anything.
            .NODATA, .OPNOTSUPP => return false,
            else => |e| return m.fail("cannot read {s}'s attributes in the job's layers: {t}", .{ path, e }),
        }
        var opaque_dir = false;
        var names = std.mem.splitScalar(u8, list[0..n], 0);
        while (names.next()) |name| {
            if (std.mem.eql(u8, name, m.redirect_xattr) or std.mem.eql(u8, name, m.metacopy_xattr))
                return m.fail("{s} is renamed or copied up by overlay's redirect or metacopy in the " ++
                    "job's layers, which hashFiles() cannot read", .{path});
            if (is_dir and std.mem.eql(u8, name, m.opaque_xattr)) opaque_dir = true;
        }
        if (!opaque_dir) return false;
        var value: [1]u8 = undefined;
        const got = linux.getxattr(p, m.opaque_xattr, &value, value.len);
        return linux.errno(got) == .SUCCESS and got == 1 and value[0] == 'y';
    }

    // --- the merge ---

    /// The layers that add to the directory `dir`, topmost first: those where it is a directory,
    /// down to the first where it is hidden (a whiteout, or a file or link there) or opaque.
    /// Null when it is not a directory.
    fn contribs(m: *Merged, dir: []const u8) Error!?[]const u32 {
        if (m.dirs.get(dir)) |c| return c;
        var found: std.ArrayList(u32) = .empty;
        if (dir.len == 0) {
            var i: u32 = 0;
            while (i < m.roots.len) : (i += 1) try found.append(m.arena, i);
        } else if (try m.contribs(parentOf(dir))) |above| {
            for (above) |layer| {
                const node = try m.lstat(layer, dir);
                switch (node.kind) {
                    .missing => continue,
                    .dir => {
                        try found.append(m.arena, layer);
                        if (node.opaque_dir) break;
                    },
                    else => break,
                }
            }
        }
        const result: ?[]const u32 = if (found.items.len == 0) null else found.items;
        try m.dirs.put(m.arena, try m.arena.dupe(u8, dir), result);
        return result;
    }

    /// What the real path is: the topmost layer's entry for it, unless that is a whiteout.
    fn entry(m: *Merged, path: []const u8) Error!Node {
        if (path.len == 0) return .{ .kind = .dir };
        if (m.nodes.get(path)) |n| return n;
        var node: Node = .{ .kind = .missing };
        if (try m.contribs(parentOf(path))) |above| for (above) |layer| {
            const l = try m.lstat(layer, path);
            if (l.kind == .missing) continue;
            if (l.kind != .whiteout) {
                node = l;
                node.layer = layer;
            }
            break;
        };
        try m.nodes.put(m.arena, try m.arena.dupe(u8, path), node);
        return node;
    }

    /// `path` with every link taken (the last one only when `follow_last`), as the job's own
    /// root sees it: null when something on the way is missing, is not a directory, or is a
    /// loop. The path it returns is real, and good until the next call.
    fn resolve(m: *Merged, path: []const u8, follow_last: bool) Error!?Resolved {
        m.path.clearRetainingCapacity();
        return m.walkPath(&m.path, path, follow_last, 0);
    }

    /// `path` taken from the real directory `buf` holds ("" the root), which it leaves holding
    /// where the path leads. Names are added to `buf` and cut off it again, and looked up where
    /// they are, so a long path costs no copy of itself for each of its names.
    fn walkPath(m: *Merged, buf: *std.ArrayList(u8), path: []const u8, follow_last: bool, links: u32) Error!?Resolved {
        const arena = m.arena;
        var rest = path;
        while (true) {
            rest = std.mem.trimStart(u8, rest, "/");
            if (rest.len == 0) break;
            const slash = std.mem.indexOfScalar(u8, rest, '/');
            const name = rest[0 .. slash orelse rest.len];
            rest = if (slash) |s| rest[s + 1 ..] else "";
            try m.tick();
            if (std.mem.eql(u8, name, ".")) continue;
            if (std.mem.eql(u8, name, "..")) {
                buf.shrinkRetainingCapacity(parentOf(buf.items).len);
                continue;
            }
            const parent_len = buf.items.len;
            try buf.append(arena, '/');
            try buf.appendSlice(arena, name);
            const node = try m.entry(buf.items);
            switch (node.kind) {
                .missing, .whiteout => return null,
                .dir => {},
                .file, .other => if (rest.len > 0) return null,
                .symlink => {
                    if (rest.len == 0 and !follow_last) break;
                    const to = (try m.follow(buf.items, parent_len, node.target, links + 1)) orelse return null;
                    buf.clearRetainingCapacity();
                    if (!std.mem.eql(u8, to.path, "/")) try buf.appendSlice(arena, to.path);
                },
            }
        }
        return .{ .path = if (buf.items.len == 0) "/" else buf.items, .node = try m.entry(buf.items) };
    }

    /// Where the link at `link` (in the directory its first `parent_len` bytes are) leads, once
    /// all its links are taken. Kept: a thousand links to one chain take it once.
    fn follow(m: *Merged, link: []const u8, parent_len: usize, target: []const u8, links: u32) Error!?Resolved {
        if (links > max_links) return null;
        if (m.leads.get(link)) |r| return r;
        var local: std.ArrayList(u8) = .empty;
        if (target.len == 0 or target[0] != '/') try local.appendSlice(m.arena, link[0..parent_len]);
        const to = (try m.walkPath(&local, target, true, links)) orelse return null;
        try m.leads.put(m.arena, try m.arena.dupe(u8, link), to);
        return to;
    }

    /// The SHA-256 of a regular file, read from the layer that has it: no link on the way is
    /// taken. What is found is looked at (`O_PATH`, no read) before it is opened, and opened
    /// through the descriptor that was looked at, so a file that has become a pipe, which would
    /// block, is refused and not opened. Read in blocks, between which the job's cancel is seen.
    fn digest(m: *Merged, path: []const u8, layer: u32) Error![32]u8 {
        var buf: [path_max]u8 = undefined;
        const rel = try m.relativeZ(&buf, path);
        const looked = switch (sandbox.openIn(m.roots[layer], rel, .{ .PATH = true }, 0, sandbox.resolve_no_symlinks)) {
            .fd => |f| f,
            .err => |e| return m.fail("{s}: cannot be read: {t}", .{ path, e }),
        };
        defer _ = linux.close(looked);
        if (!try m.isRegular(looked, path)) return m.fail("{s}: Not a regular file", .{path});
        var proc: [32]u8 = undefined;
        const p = std.mem.printSentinel(&proc, "/proc/self/fd/{d}", .{looked}, 0) catch
            return m.fail("{s}: cannot be read", .{path});
        const opened = linux.open(p, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .NOCTTY = true, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS)
            return m.fail("{s}: cannot be read: {t}", .{ path, linux.errno(opened) });
        const fd = std.math.cast(linux.fd_t, opened).?;
        defer _ = linux.close(fd);
        if (!try m.isRegular(fd, path)) return m.fail("{s}: Not a regular file", .{path});
        var h = Sha256.init(.{});
        var block: [64 * 1024]u8 = undefined;
        while (true) {
            try m.tick();
            const n = linux.read(fd, &block, block.len);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |e| return m.fail("{s}: cannot be read: {t}", .{ path, e }),
            }
            if (n == 0) break;
            h.update(block[0..n]);
        }
        return h.finalResult();
    }

    fn isRegular(m: *Merged, fd: linux.fd_t, path: []const u8) Error!bool {
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS)
            return m.fail("{s}: cannot be read", .{path});
        return st.mode & linux.S.IFMT == linux.S.IFREG;
    }

    // --- glob.Fs ---

    fn erased(ptr: *anyopaque) *Merged {
        return @ptrCast(@alignCast(ptr));
    }

    fn statAll(ptr: *anyopaque, arena: Allocator, paths: []const []const u8, follow_links: bool) Error![]const glob.Kind {
        const m = erased(ptr);
        const out = try arena.alloc(glob.Kind, paths.len);
        for (paths, out) |p, *k| {
            const at = (try m.resolve(p, follow_links)) orelse {
                k.* = .missing;
                continue;
            };
            k.* = switch (at.node.kind) {
                .dir => .directory,
                .file => .file,
                .symlink => .symlink,
                .missing, .whiteout => .missing,
                .other => .other,
            };
        }
        return out;
    }

    /// The names in each directory: the union of its layers' entries, less those a whiteout hides.
    fn listAll(ptr: *anyopaque, arena: Allocator, dirs: []const []const u8) Error![]const []const []const u8 {
        const m = erased(ptr);
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (dirs, out) |d, *list| list.* = try m.listDir(arena, d);
        return out;
    }

    fn listDir(m: *Merged, arena: Allocator, dir: []const u8) Error![]const []const u8 {
        const at = (try m.resolve(dir, true)) orelse return &.{};
        if (at.node.kind != .dir) return &.{};
        // The directory's path is in `m.path`, which a look at a whiteout's name would not touch,
        // but copy it: it is the key of the layers' lookups below.
        const real = try arena.dupe(u8, if (std.mem.eql(u8, at.path, "/")) "" else at.path);
        const layers = (try m.contribs(real)) orelse return &.{};
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        var out: std.ArrayList([]const u8) = .empty;
        for (layers) |layer| {
            var buf: [path_max]u8 = undefined;
            const rel = try m.relativeZ(&buf, real);
            const fd = switch (sandbox.openIn(m.roots[layer], rel, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
            }, 0, sandbox.resolve_no_symlinks)) {
                .fd => |f| f,
                .err => |e| return m.fail("cannot read {s} in the job's layers: {t}", .{ real, e }),
            };
            defer _ = linux.close(fd);
            const d: std.Io.Dir = .{ .handle = fd };
            var it = d.iterateAssumeFirstIteration();
            while (it.next(m.io) catch |e|
                return m.fail("cannot list {s} in the job's layers: {t}", .{ real, e })) |e|
            {
                try m.tick();
                if (seen.contains(e.name)) continue;
                const name = try arena.dupe(u8, e.name);
                try seen.put(arena, name, {});
                if (e.kind == .character_device or e.kind == .unknown) {
                    var joined: [path_max]u8 = undefined;
                    const child = std.fmt.bufPrint(&joined, "{s}/{s}", .{ real, name }) catch
                        return m.fail("a path in the job's files is longer than {d} bytes", .{path_max - 1});
                    if ((try m.lstat(layer, child)).kind == .whiteout) continue;
                }
                try out.append(arena, name);
            }
        }
        return out.items;
    }

    /// Each path with every link taken. A path that is not there cannot be listed or followed:
    /// the walk asks only about directories it has just seen.
    fn realpathAll(ptr: *anyopaque, arena: Allocator, paths: []const []const u8) Error![]const []const u8 {
        const m = erased(ptr);
        const out = try arena.alloc([]const u8, paths.len);
        for (paths, out) |p, *r| {
            const at = (try m.resolve(p, true)) orelse return m.fail("{s}: No such file or directory", .{p});
            r.* = try arena.dupe(u8, at.path);
        }
        return out;
    }
};

/// The path without its leading `/`, for a layer's `openat2`: "." for the root.
fn relative(path: []const u8) []const u8 {
    const t = std.mem.trimStart(u8, path, "/");
    return if (t.len == 0) "." else t;
}

/// The directory a real path is in; the root's is "".
fn parentOf(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..slash];
}

// --- tests ---

const Fixture = struct {
    arena: Allocator,
    tmp: std.testing.TmpDir,
    root: []const u8,

    fn init(arena: Allocator) !Fixture {
        var f: Fixture = .{ .arena = arena, .tmp = std.testing.tmpDir(.{}), .root = "" };
        f.root = try f.tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
        return f;
    }

    fn cleanup(f: *Fixture) void {
        f.tmp.cleanup();
    }

    fn put(f: Fixture, path: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(path)) |d| try f.tmp.dir.createDirPath(std.testing.io, d);
        try f.tmp.dir.writeFile(std.testing.io, .{ .sub_path = path, .data = data });
    }

    fn link(f: Fixture, path: []const u8, target: []const u8) !void {
        if (std.fs.path.dirname(path)) |d| try f.tmp.dir.createDirPath(std.testing.io, d);
        try f.tmp.dir.symLink(std.testing.io, target, path, .{});
    }

    fn abs(f: Fixture, path: []const u8) ![:0]const u8 {
        return std.fmt.allocPrintSentinel(f.arena, "{s}/{s}", .{ f.root, path }, 0);
    }

    /// `hashFiles(args)` with `/ws` as the workspace over the layers, topmost first.
    fn hash(f: Fixture, layers: []const []const u8, args: []const []const u8) !expr.HashFiles.Result {
        const paths = try f.arena.alloc([]const u8, layers.len);
        for (layers, paths) |l, *p| p.* = try std.fmt.allocPrint(f.arena, "{s}/{s}", .{ f.root, l });
        const stack_: Stack = .{ .layers = paths, .opaque_xattr = "user.overlay.opaque" };
        return f.hashWith(stack_, args);
    }

    fn hashWith(f: Fixture, st: Stack, args: []const []const u8) !expr.HashFiles.Result {
        return hashFiles(std.testing.allocator, f.arena, std.testing.io, st, "/ws", "/home/runner", args);
    }

    fn stackOf(f: Fixture, layers: []const []const u8, limits: Limits) !Stack {
        const paths = try f.arena.alloc([]const u8, layers.len);
        for (layers, paths) |l, *p| p.* = try std.fmt.allocPrint(f.arena, "{s}/{s}", .{ f.root, l });
        return .{ .layers = paths, .opaque_xattr = "user.overlay.opaque", .limits = limits };
    }
};

/// GitHub's hash of files with these contents, in this order.
fn hashOf(contents: []const []const u8) [64]u8 {
    var all = Sha256.init(.{});
    for (contents) |c| {
        var d: [32]u8 = undefined;
        Sha256.hash(c, &d, .{});
        all.update(&d);
    }
    return std.fmt.bytesToHex(all.finalResult(), .lower);
}

fn expectHash(want: []const u8, got: expr.HashFiles.Result) !void {
    switch (got) {
        .ok => |h| try std.testing.expectEqualStrings(want, h),
        .failed => |why| {
            std.debug.print("hashFiles failed: {s}\n", .{why});
            return error.TestUnexpectedResult;
        },
    }
}

fn expectFailed(part: []const u8, got: expr.HashFiles.Result) !void {
    switch (got) {
        .ok => |h| {
            std.debug.print("hashFiles gave {s}, wanted a failure with {s}\n", .{ h, part });
            return error.TestUnexpectedResult;
        },
        .failed => |why| if (std.mem.indexOf(u8, why, part) == null) {
            std.debug.print("hashFiles failed with {s}, wanted {s}\n", .{ why, part });
            return error.TestUnexpectedResult;
        },
    }
}

test "native hashFiles: layers merge as overlay's do, the topmost entry wins, a whiteout deletes, an opaque directory hides" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // The rootfs, then two layers of steps.
    try f.put("l0/ws/a.txt", "a0");
    try f.put("l0/ws/gone.txt", "gone");
    try f.put("l0/ws/keep.txt", "keep");
    try f.put("l0/ws/dir/old.txt", "old");
    try f.put("l0/ws/dir/sub/deep.txt", "deep");
    try f.put("l1/ws/a.txt", "a1");
    try f.put("l1/ws/dir/new.txt", "new");
    try f.put("l2/ws/later.txt", "later");
    // l1's `dir` is opaque (a step removed it and made it again): l0's entries are hidden. l2
    // deletes `gone.txt`. Where this machine cannot make either, the case is left out.
    const opaque_dir = linux.errno(linux.setxattr(try f.abs("l1/ws/dir"), "user.overlay.opaque", "y", 1, 0)) == .SUCCESS;
    const whiteout = linux.errno(linux.mknod(try f.abs("l2/ws/gone.txt"), linux.S.IFCHR | 0o000, 0)) == .SUCCESS;
    const layers = [_][]const u8{ "l2", "l1", "l0" };

    // In GitHub's order: a.txt, dir/..., gone.txt, keep.txt, later.txt.
    var want: std.ArrayList([]const u8) = .empty;
    try want.append(f.arena, "a1");
    try want.append(f.arena, "new");
    if (!opaque_dir) try want.appendSlice(f.arena, &.{ "old", "deep" });
    if (!whiteout) try want.append(f.arena, "gone");
    try want.appendSlice(f.arena, &.{ "keep", "later" });
    try expectHash(&hashOf(want.items), try f.hash(&layers, &.{"**"}));
    // One layer sees only itself: the others are not what it is merged with.
    try expectHash(&hashOf(&.{ "a0", "old", "deep", "gone", "keep" }), try f.hash(&.{"l0"}, &.{"**"}));
    // Nothing found is "".
    try expectHash("", try f.hash(&layers, &.{"**/nothing.txt"}));
    // A pattern with `..` is refused, as GitHub refuses it.
    try expectFailed("Relative pathing", try f.hash(&layers, &.{"dir/../a.txt"}));
}

test "native hashFiles: a link is hashed as what it leads to inside the job's tree" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/etc/secret", "S");
    try f.put("l0/ws/real.txt", "R");
    try f.put("l0/ws/sub/inner.txt", "I");
    try f.link("l0/ws/link.txt", "real.txt");
    try f.link("l0/ws/abs.txt", "/etc/secret");
    try f.link("l0/ws/up.txt", "sub/../real.txt");
    try f.link("l0/ws/dl", "sub");
    try f.link("l0/ws/sub/back", "../real.txt");
    try f.link("l0/ws/sub/to-ws", "..");
    // The links are in a layer under the one that has the files: the merged view takes them.
    try f.put("l1/ws/top.txt", "T");
    const layers = [_][]const u8{ "l1", "l0" };

    // Links are not followed: each is a name found, hashed as its target (a directory skipped, as
    // GitHub skips what `statSync` calls one): abs.txt, dl, link.txt, real.txt, sub/back,
    // sub/inner.txt, sub/to-ws, top.txt, up.txt.
    try expectHash(&hashOf(&.{ "S", "R", "R", "R", "I", "T", "R" }), try f.hash(&layers, &.{"**"}));
    // Followed: `dl` is walked (its files are named by the path through it), `sub/to-ws` is the
    // workspace again and is not.
    try expectHash(
        &hashOf(&.{ "S", "R", "I", "R", "R", "R", "I", "T", "R" }),
        try f.hash(&layers, &.{ "--follow-symbolic-links", "**" }),
    );
}

test "native hashFiles: nothing a link names outside the layers is read" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // A file of the host's, at a path the job's tree does not have.
    try f.put("host/secret.txt", "HOST");
    try f.put("l0/ws/ok.txt", "ok");
    const abs_target = try f.abs("host/secret.txt");
    // Through `..`, as many as it takes to reach the host's root if the job's were it.
    const dots = "../../../../../../../../../../../../../../../../../../../../../../../../../../../../";
    const rel_target = try std.fmt.allocPrint(f.arena, "{s}{s}", .{ dots, std.mem.trimStart(u8, abs_target, "/") });
    try f.link("l0/ws/abs-link", abs_target);
    try f.link("l0/ws/rel-link", rel_target);
    try f.link("l0/ws/dir-link", try f.abs("host"));
    const layers = [_][]const u8{"l0"};
    // Not followed, the links are names, and their targets are not there: hashFiles fails on
    // them, as it fails on a broken link on GitHub, and the host's file is not hashed.
    try expectFailed("abs-link", try f.hash(&layers, &.{"abs-link"}));
    try expectFailed("rel-link", try f.hash(&layers, &.{"rel-link"}));
    // Followed, they lead to nothing, so there is nothing to find or to walk.
    try expectHash(&hashOf(&.{"ok"}), try f.hash(&layers, &.{ "--follow-symbolic-links", "**" }));
    try expectHash("", try f.hash(&layers, &.{ "--follow-symbolic-links", "dir-link/**" }));
    // A loop of links is no file either.
    try f.link("l0/ws/loop-a", "loop-b");
    try f.link("l0/ws/loop-b", "loop-a");
    try expectFailed("loop-a", try f.hash(&layers, &.{"loop-a"}));
}

test "native hashFiles: a directory in a layer hides a link below it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/etc/x", "from-etc");
    try f.link("l0/ws/d", "/etc");
    try f.put("l1/ws/d/x", "upper");
    try expectHash(&hashOf(&.{"upper"}), try f.hash(&.{ "l1", "l0" }, &.{"d/**"}));
    // Below the link only, `d` is the link: not followed, hashed as what it leads to (a directory,
    // so skipped); followed, /etc's files.
    try expectHash("", try f.hash(&.{"l0"}, &.{"d"}));
    try expectHash(&hashOf(&.{"from-etc"}), try f.hash(&.{"l0"}, &.{ "--follow-symbolic-links", "d/**" }));
}

test "native hashFiles: a pipe is refused, not waited for" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/ok.txt", "ok");
    if (linux.errno(linux.mknod(try f.abs("l0/ws/pipe"), linux.S.IFIFO | 0o600, 0)) != .SUCCESS)
        return error.SkipZigTest;
    try expectFailed("pipe", try f.hash(&.{"l0"}, &.{"pipe"}));
}

fn many(arena: Allocator, s: []const u8, n: usize) ![]const []const u8 {
    const out = try arena.alloc([]const u8, n);
    @memset(out, s);
    return out;
}

/// What a call over these small trees may hold: well under what copying paths took.
const MEMORY_BOUND = 64 << 20;

test "native hashFiles: links that name one directory by many paths end in an error, not in memory" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // d0 .. d9, each with two links to the next: 2^9 paths lead to d9, and none is a cycle.
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        for ([_][]const u8{ "a", "b" }) |name| try f.link(
            try std.fmt.allocPrint(f.arena, "l0/ws/d{d}/{s}", .{ i, name }),
            try std.fmt.allocPrint(f.arena, "../d{d}", .{i + 1}),
        );
    }
    try f.put("l0/ws/d9/x", "x");
    const follow = [_][]const u8{ "--follow-symbolic-links", "d0/**" };
    try expectFailed("more than 300 files and directories", try f.hashWith(try f.stackOf(&.{"l0"}, .{ .nodes = 300 }), &follow));
    // With room for them it is the same tree: 512 files, each named by its own path.
    const all = try f.hashWith(try f.stackOf(&.{"l0"}, .{ .nodes = 5000 }), &follow);
    try expectHash(&hashOf(try many(f.arena, "x", 512)), all);
    // Not following, the links are names and there is almost nothing to visit.
    try expectHash("", try f.hashWith(try f.stackOf(&.{"l0"}, .{ .nodes = 300 }), &.{"d0/**"}));
}

test "native hashFiles: a deep path is not copied for each of its names" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    // 300 directories deep (a path of 600 bytes), 1500 files at the bottom.
    var dir: std.ArrayList(u8) = .empty;
    try dir.appendSlice(f.arena, "l0/ws");
    for (0..300) |_| try dir.appendSlice(f.arena, "/n");
    try f.tmp.dir.createDirPath(std.testing.io, dir.items);
    for (0..1500) |n| try f.put(try std.fmt.allocPrint(f.arena, "{s}/f{d}", .{ dir.items, n }), "x");
    var scratch: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer scratch.deinit();
    const got = try run(&scratch, std.testing.io, try f.stackOf(&.{"l0"}, .{}), "/ws", "/home/runner", &.{"**"});
    try expectHash(&hashOf(try many(f.arena, "x", 1500)), got);
    // A copy of the path for each name of it, for each file, twice, was over 300 MB.
    const used = scratch.queryCapacity();
    errdefer std.debug.print("the call held {d} bytes\n", .{used});
    try std.testing.expect(used < MEMORY_BOUND);
}

test "native hashFiles: many links to one long chain follow it once" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/end.txt", "end");
    // 39 links in a chain, each target 3 KB of `./` before the next name.
    const pad = try f.arena.alloc(u8, 3000);
    for (0..1500) |k| @memcpy(pad[2 * k ..][0..2], "./");
    var i: usize = 39;
    while (i > 0) : (i -= 1) {
        const target = if (i == 39) "end.txt" else try std.fmt.allocPrint(f.arena, "{s}c{d}", .{ pad, i + 1 });
        try f.link(try std.fmt.allocPrint(f.arena, "l0/ws/c{d}", .{i}), target);
    }
    for (0..3000) |n| try f.link(try std.fmt.allocPrint(f.arena, "l0/ws/l{d}", .{n}), try std.fmt.allocPrint(f.arena, "{s}c1", .{pad}));
    var scratch: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer scratch.deinit();
    const got = try run(&scratch, std.testing.io, try f.stackOf(&.{"l0"}, .{}), "/ws", "/home/runner", &.{"l*"});
    try expectHash(&hashOf(try many(f.arena, "end", 3000)), got);
    const used = scratch.queryCapacity();
    errdefer std.debug.print("the call held {d} bytes\n", .{used});
    try std.testing.expect(used < MEMORY_BOUND);
}

test "native hashFiles: the job's cancel ends a call in the middle of a file" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/ok.txt", "ok");
    // A file of 16 GiB that takes no disk: reading it takes seconds, and a bigger one hours.
    try f.tmp.dir.createDirPath(std.testing.io, "l0/ws");
    const big = try f.tmp.dir.createFile(std.testing.io, "l0/ws/big", .{});
    defer big.close(std.testing.io);
    big.setLength(std.testing.io, 16 << 30) catch return error.SkipZigTest;
    var cancel: std.atomic.Value(bool) = .init(false);
    const Canceller = struct {
        fn run(c: *std.atomic.Value(bool), io: std.Io) void {
            io.sleep(.fromMilliseconds(300), .awake) catch return;
            c.store(true, .release);
        }
    };
    const thread = try std.Thread.spawn(.{}, Canceller.run, .{ &cancel, std.testing.io });
    defer thread.join();
    const t0 = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    const got = try f.hashWith(try f.stackOf(&.{"l0"}, .{ .cancel = &cancel }), &.{"big"});
    const took = std.Io.Clock.awake.now(std.testing.io).toMilliseconds() - t0;
    try expectFailed("cancelled", got);
    errdefer std.debug.print("it took {d} ms\n", .{took});
    try std.testing.expect(took < 3000);
}

test "native hashFiles: a redirect or metacopy in a layer fails the call, for a directory and for a file" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var f = try Fixture.init(a.allocator());
    defer f.cleanup();
    try f.put("l0/ws/plain/a.txt", "a");
    try f.put("l1/ws/renamed/b.txt", "b");
    try f.put("l1/ws/copied.txt", "c");
    // Overlay shows a renamed directory's lower entries by its redirect, and a file that only had
    // its metadata changed by its metacopy: without either followed the hash would be wrong.
    if (linux.errno(linux.setxattr(try f.abs("l1/ws/renamed"), "user.overlay.redirect", "/ws/plain", 9, 0)) != .SUCCESS)
        return error.SkipZigTest;
    try expectFailed("redirect or metacopy", try f.hash(&.{ "l1", "l0" }, &.{"**"}));
    _ = linux.removexattr(try f.abs("l1/ws/renamed"), "user.overlay.redirect");
    try expectHash(&hashOf(&.{ "c", "a", "b" }), try f.hash(&.{ "l1", "l0" }, &.{"**"}));
    if (linux.errno(linux.setxattr(try f.abs("l1/ws/copied.txt"), "user.overlay.metacopy", "", 0, 0)) != .SUCCESS)
        return error.SkipZigTest;
    try expectFailed("copied.txt is renamed or copied up", try f.hash(&.{ "l1", "l0" }, &.{"**"}));
}
