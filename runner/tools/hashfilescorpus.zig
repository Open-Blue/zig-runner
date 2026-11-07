//! The Zig half of `.github/scripts/hashfiles-diff.sh`: runs src/glob.zig, the runner's hashFiles()
//! search, on a tree on the local disk and compares the files it hashes, in order, and the hash
//! with what GitHub's script (tools/hashfilesdiff/reference.mjs) reported for the same tree. It
//! also runs the native backend's `hashFiles()` (src/native/hash_files.zig, which reads the job's
//! layers) over the same tree as one layer, and compares its hash and its failures: it reports no
//! file list, but its hash is of the files' digests in order.
//!
//!     hashfilescorpus <cases.json> <workspace> <layer> <reference.jsonl>
//!
//! `workspace` is the path the reference saw the tree at (its working directory); `layer` is the
//! directory here that holds it at that path (`<layer><workspace>`), as a native job's layer
//! holds the job's workspace. Hashing is as GitHub's script does it: a name that is a directory once links
//! are followed is skipped, a broken link is an error, and the result is the SHA-256 of the files'
//! SHA-256 digests, "" for none.
const std = @import("std");
const runner = @import("runner");

const glob = runner.glob;
const native = runner.native;

const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 5) {
        std.debug.print("usage: hashfilescorpus <cases.json> <workspace> <layer> <reference.jsonl>\n", .{});
        return 2;
    }
    var out_buf: [8192]u8 = undefined;
    var out_w: Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    const cwd = Io.Dir.cwd();
    const ws = args[2];
    const layer = args[3];
    var disk: Disk = .{ .io = io, .ws = ws, .tree = try std.mem.concat(arena, u8, &.{ layer, ws }) };
    const cases = (try std.json.parseFromSliceLeaky(std.json.Value, arena, try cwd.readFileAlloc(io, args[1], arena, .limited(1 << 28)), .{})).array.items;
    var reference: std.AutoHashMapUnmanaged(i64, std.json.ObjectMap) = .empty;
    var lines = std.mem.splitScalar(u8, try cwd.readFileAlloc(io, args[4], arena, .limited(1 << 28)), '\n');
    while (lines.next()) |l| {
        // @actions/glob prints `::debug::` lines of its own on stdout.
        if (!std.mem.startsWith(u8, l, "{\"id\"")) continue;
        const o = (try std.json.parseFromSliceLeaky(std.json.Value, arena, l, .{})).object;
        try reference.put(arena, o.get("id").?.integer, o);
    }

    var same: usize = 0;
    var differ: usize = 0;
    var both_fail: usize = 0;
    var native_same: usize = 0;
    var native_differ: usize = 0;
    var native_both_fail: usize = 0;
    for (cases) |c| {
        const items = c.object.get("patterns").?.array.items;
        const pattern_args = try arena.alloc([]const u8, items.len);
        for (items, pattern_args) |i, *p| p.* = i.string;
        const shown = try std.mem.join(arena, " | ", pattern_args);
        const want = reference.get(c.object.get("id").?.integer).?;
        const got = try run(arena, &disk, pattern_args, ws);

        // The native backend's, on the same tree as one layer: the hash, or that it fails.
        const native_got = try native.hashFiles(
            init.gpa,
            arena,
            io,
            .{ .layers = &.{layer}, .opaque_xattr = "user.overlay.opaque", .step = null },
            ws,
            "/root",
            pattern_args,
        );
        switch (nativeVerdict(want, native_got)) {
            .same => native_same += 1,
            .both_fail => native_both_fail += 1,
            .differs => {
                native_differ += 1;
                try out.print("NATIVE DIFFERS  [{s}]\n    GitHub: ", .{shown});
                if (want.get("error")) |e| {
                    try out.print("fails: {s}", .{e.string});
                } else {
                    try out.print("{s}", .{want.get("hash").?.string});
                }
                switch (native_got) {
                    .ok => |h| try out.print("\n    native: {s}\n", .{h}),
                    .failed => |why| try out.print("\n    native fails: {s}\n", .{why}),
                }
            },
        }

        if (want.get("error")) |e| {
            if (got == .failed) {
                both_fail += 1;
                continue;
            }
            differ += 1;
            try out.print("DIFFERS  [{s}]\n    GitHub fails: {s}\n    runner: {s}\n", .{ shown, e.string, got.ok.hash });
            continue;
        }
        if (got == .failed) {
            differ += 1;
            try out.print("DIFFERS  [{s}]\n    GitHub: {s}\n    runner fails: {s}\n", .{ shown, want.get("hash").?.string, got.failed });
            continue;
        }
        const files = want.get("files").?.array.items;
        var equal = std.mem.eql(u8, got.ok.hash, want.get("hash").?.string) and files.len == got.ok.files.len;
        if (equal) for (files, got.ok.files) |w, g| if (!std.mem.eql(u8, w.string, g)) {
            equal = false;
        };
        if (equal) {
            same += 1;
            continue;
        }
        differ += 1;
        try out.print("DIFFERS  [{s}]\n    GitHub:", .{shown});
        for (files) |f| try out.print(" {s}", .{f.string});
        try out.print("\n    runner:", .{});
        for (got.ok.files) |f| try out.print(" {s}", .{f});
        try out.writeByte('\n');
    }
    try out.print("\n{d} cases hash the same files in the same order, {d} differ, {d} fail on both\n", .{ same, differ, both_fail });
    try out.print("native: {d} cases hash the same, {d} differ, {d} fail on both\n", .{ native_same, native_differ, native_both_fail });
    return if (differ == 0 and native_differ == 0) 0 else 1;
}

const Result = union(enum) {
    ok: struct { files: []const []const u8, hash: []const u8 },
    failed: []const u8,
};

/// The native backend's answer against GitHub's: the same hash, or a failure on both. Whether a
/// failure says the same is not compared (the words are each implementation's own).
fn nativeVerdict(want: std.json.ObjectMap, got: runner.expr.HashFiles.Result) enum { same, both_fail, differs } {
    if (want.get("error") != null) return if (got == .failed) .both_fail else .differs;
    return switch (got) {
        .ok => |h| if (std.mem.eql(u8, h, want.get("hash").?.string)) .same else .differs,
        .failed => .differs,
    };
}

/// hashFiles(), as the runner computes it, on the local tree.
fn run(arena: std.mem.Allocator, disk: *Disk, args: []const []const u8, ws: []const u8) !Result {
    const parsed = switch (try glob.parse(arena, args, ws, "/root")) {
        .invalid => |why| return .{ .failed = why },
        .ok => |p| p,
    };
    var why: []const u8 = "";
    const found = switch (try glob.walk(arena, disk.fs(), parsed.patterns, parsed.follow, ws, &why)) {
        .failed => |f| return .{ .failed = f },
        .files => |f| f,
    };
    var result = std.crypto.hash.sha2.Sha256.init(.{});
    var files: std.ArrayList([]const u8) = .empty;
    for (found) |path| {
        if (!std.mem.startsWith(u8, path, ws) or path.len <= ws.len or path[ws.len] != '/') continue;
        const kinds = disk.stat(arena, &.{path}, true) catch return .{ .failed = "stat failed" };
        switch (kinds[0]) {
            .directory => continue,
            .missing => return .{ .failed = try std.fmt.allocPrint(arena, "ENOENT: stat '{s}'", .{path}) },
            else => {},
        }
        const bytes = try Io.Dir.cwd().readFileAlloc(disk.io, try disk.onDisk(arena, path), arena, .limited(1 << 30));
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        result.update(&digest);
        try files.append(arena, path[ws.len + 1 ..]);
    }
    if (files.items.len == 0) return .{ .ok = .{ .files = &.{}, .hash = "" } };
    const hex = std.fmt.bytesToHex(result.finalResult(), .lower);
    return .{ .ok = .{ .files = files.items, .hash = try arena.dupe(u8, &hex) } };
}

/// glob.Fs on the local disk: `ws` in the paths the walk asks about is `tree` here.
const Disk = struct {
    io: Io,
    ws: []const u8,
    tree: []const u8,

    fn fs(d: *Disk) glob.Fs {
        return .{ .ptr = d, .vtable = &.{ .stat = statFn, .list = listFn, .realpath = realpathFn } };
    }

    fn onDisk(d: *Disk, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
        if (std.mem.startsWith(u8, path, d.ws)) return std.mem.concat(arena, u8, &.{ d.tree, path[d.ws.len..] });
        return path;
    }

    fn stat(d: *Disk, arena: std.mem.Allocator, paths: []const []const u8, follow: bool) glob.Fs.Error![]const glob.Kind {
        const out = try arena.alloc(glob.Kind, paths.len);
        for (paths, out) |p, *k| {
            const st = Io.Dir.cwd().statFile(d.io, try d.onDisk(arena, p), .{ .follow_symlinks = follow }) catch {
                k.* = .missing;
                continue;
            };
            k.* = switch (st.kind) {
                .file => .file,
                .directory => .directory,
                .sym_link => .symlink,
                else => .other,
            };
        }
        return out;
    }

    fn statFn(ptr: *anyopaque, arena: std.mem.Allocator, paths: []const []const u8, follow: bool) glob.Fs.Error![]const glob.Kind {
        const d: *Disk = @ptrCast(@alignCast(ptr));
        return d.stat(arena, paths, follow);
    }

    fn listFn(ptr: *anyopaque, arena: std.mem.Allocator, dirs: []const []const u8) glob.Fs.Error![]const []const []const u8 {
        const d: *Disk = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (dirs, out) |dir_path, *names| {
            var dir = Io.Dir.cwd().openDir(d.io, try d.onDisk(arena, dir_path), .{ .iterate = true }) catch {
                names.* = &.{};
                continue;
            };
            defer dir.close(d.io);
            var list: std.ArrayList([]const u8) = .empty;
            var it = dir.iterate();
            while (it.next(d.io) catch null) |e| try list.append(arena, try arena.dupe(u8, e.name));
            names.* = list.items;
        }
        return out;
    }

    fn realpathFn(ptr: *anyopaque, arena: std.mem.Allocator, paths: []const []const u8) glob.Fs.Error![]const []const u8 {
        const d: *Disk = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc([]const u8, paths.len);
        for (paths, out) |p, *r| r.* = Io.Dir.realPathFileAbsoluteAlloc(d.io, try d.onDisk(arena, p), arena) catch p;
        return out;
    }
};
