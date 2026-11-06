//! `hashFiles()` in a job: glob.zig's search over the job's container through Dagger's API
//! (`Fs`), and the found files hashed by `sha256sum` there.

const std = @import("std");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const expr = @import("../expr.zig");
const glob = @import("../glob.zig");
const Query = @import("query.zig").Query;
const Raw = @import("query.zig").Raw;
const Exec = @import("Exec.zig");
const run = @import("../dagger.zig").run;
const gql = @import("../dagger.zig").gql;
const jsonFind = @import("../dagger.zig").jsonFind;
const jsonFindString = @import("../dagger.zig").jsonFindString;
const jsonStrings = @import("../dagger.zig").jsonStrings;
const runner_home = @import("../dagger.zig").runner_home;
const FakeSession = @import("testing.zig").FakeSession;
const fake_child = @import("testing.zig").fake_child;
const base_answer = @import("testing.zig").base_answer;
const exec = @import("testing.zig").exec;
const testStep = @import("testing.zig").testStep;
const testJob = @import("testing.zig").testJob;
const braceBalanced = @import("testing.zig").braceBalanced;

const Allocator = std.mem.Allocator;

/// The list of files `hashFiles()` hashes, written next to the exec that hashes them.
const hash_list_path = "/tmp/zig-runner-hashfiles";

/// `hashFiles(patterns)`, as GitHub computes it: the SHA-256 of the SHA-256 digests of the
/// files its patterns find under the workspace, "" when none. The search is glob.zig
/// (@actions/glob, as GitHub's runner uses it), asking Dagger what is in the job's container
/// (`Fs`); the files are hashed by `sha256sum` there, in the order the search found them,
/// which is GitHub's, so the result is the hash GitHub computes for the same files.
pub fn hashFiles(
    ptr: *anyopaque,
    arena: Allocator,
    args: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    const x: *Exec = @ptrCast(@alignCast(ptr));
    const ws = x.ev.workspace;
    // A native job has no Dagger session: its files are in the layers (`native/hash_files.zig`).
    if (x.native) |b| return b.hashFiles(arena, ws, args);
    var dfs: Fs = .{ .x = x };
    const files = switch (try glob.find(arena, dfs.fs(), args, ws, runner_home, &dfs.why)) {
        .failed => |msg| return .{ .failed = msg },
        .files => |f| f,
    };
    if (files.len == 0) return .{ .ok = "" };
    return x.hashListed(arena, ws, files);
}

/// glob.Fs on the job's container, through Dagger's API: `exists` for what a path is (it is
/// false for a missing path, where `stat` would fail the query) and `entries` for what is in
/// a directory, many paths to a query. Canonical paths, which `--follow-symbolic-links` needs
/// to break cycles as GitHub does, are not in Dagger's API: `realpath` in the job's container
/// gives them (only for the directories reached while following links).
const Fs = struct {
    x: *Exec,
    why: []const u8 = "",

    /// Paths to a query, so that a big tree does not make one enormous document.
    const batch = 1000;

    fn fs(d: *Fs) glob.Fs {
        return .{ .ptr = d, .vtable = &.{ .stat = stat, .list = list, .realpath = realpath } };
    }

    fn run(d: *Fs, arena: Allocator, query: []const u8) glob.Fs.Error!std.json.Value {
        var msg: []const u8 = "";
        return gql(arena, d.x.transport, query, &msg) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                d.why = msg;
                return error.FsFailed;
            },
        };
    }

    fn stat(ptr: *anyopaque, arena: Allocator, paths: []const []const u8, follow: bool) glob.Fs.Error![]const glob.Kind {
        const d: *Fs = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc(glob.Kind, paths.len);
        var start: usize = 0;
        while (start < paths.len) : (start += batch) {
            const end = @min(start + batch, paths.len);
            var q: Query = .init(arena);
            q.call("loadContainerFromID", .{ .id = d.x.container_id }) catch return error.OutOfMemory;
            q.open("rootfs") catch return error.OutOfMemory;
            for (paths[start..end], start..) |p, i| {
                const types = [_]struct { []const u8, ?[]const u8 }{
                    .{ "e", null }, .{ "d", "DIRECTORY_TYPE" }, .{ "f", "REGULAR_TYPE" }, .{ "l", "SYMLINK_TYPE" },
                };
                for (types) |t| {
                    const alias = try std.fmt.allocPrint(arena, "{s}{d}", .{ t[0], i });
                    // A link is only itself when links are not followed.
                    const no_follow = !follow or std.mem.eql(u8, t[0], "l");
                    if (t[1]) |ty| {
                        q.leafArgs(alias, "exists", .{ .path = p, .expectedType = Raw{ .text = ty }, .doNotFollowSymlinks = no_follow }) catch return error.OutOfMemory;
                    } else q.leafArgs(alias, "exists", .{ .path = p, .doNotFollowSymlinks = no_follow }) catch return error.OutOfMemory;
                }
            }
            const data = try d.run(arena, q.finish() catch return error.OutOfMemory);
            for (start..end) |i| {
                const yes = struct {
                    fn f(arena_: Allocator, v: std.json.Value, kind: []const u8, at: usize) bool {
                        const key = std.fmt.allocPrint(arena_, "{s}{d}", .{ kind, at }) catch return false;
                        const got = jsonFind(v, key) orelse return false;
                        return got == .bool and got.bool;
                    }
                }.f;
                out[i] = if (!yes(arena, data, "e", i)) .missing //
                    else if (!follow and yes(arena, data, "l", i)) .symlink //
                    else if (yes(arena, data, "d", i)) .directory //
                    else if (yes(arena, data, "f", i)) .file //
                    else .other;
            }
        }
        return out;
    }

    /// `realpath` over the paths in the job's container (the exec's container is not kept: the
    /// job's is unchanged), a batch at a time. No options: busybox's realpath (Alpine) takes
    /// none, `-z` and `--` included, and every path here is absolute, so none reads as one;
    /// one per line, and a path with a newline in it fails the count instead of misleading.
    fn realpath(ptr: *anyopaque, arena: Allocator, paths: []const []const u8) glob.Fs.Error![]const []const u8 {
        const d: *Fs = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc([]const u8, paths.len);
        var start: usize = 0;
        while (start < paths.len) : (start += batch) {
            const end = @min(start + batch, paths.len);
            var argv: std.ArrayList([]const u8) = .empty;
            try argv.append(arena, "realpath");
            try argv.appendSlice(arena, paths[start..end]);
            var q: Query = .init(arena);
            q.call("loadContainerFromID", .{ .id = d.x.container_id }) catch return error.OutOfMemory;
            q.call("withExec", .{ .args = argv.items, .expect = Raw{ .text = "ANY" } }) catch return error.OutOfMemory;
            for ([_][]const u8{ "exitCode", "stdout", "stderr" }) |f| q.leaf(f) catch return error.OutOfMemory;
            const data = try d.run(arena, q.finish() catch return error.OutOfMemory);
            const code = if (jsonFind(data, "exitCode")) |c| (if (c == .integer) c.integer else 1) else 1;
            const stdout = jsonFindString(data, "stdout") orelse "";
            var names = std.mem.splitScalar(u8, std.mem.trimEnd(u8, stdout, "\n"), '\n');
            var i = start;
            while (names.next()) |n| : (i += 1) {
                if (i >= end) break;
                out[i] = n;
            }
            if (code != 0 or i != end) {
                d.why = std.mem.trim(u8, jsonFindString(data, "stderr") orelse "realpath failed", " \n");
                return error.FsFailed;
            }
        }
        return out;
    }

    fn list(ptr: *anyopaque, arena: Allocator, dirs: []const []const u8) glob.Fs.Error![]const []const []const u8 {
        const d: *Fs = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc([]const []const u8, dirs.len);
        var start: usize = 0;
        while (start < dirs.len) : (start += batch) {
            const end = @min(start + batch, dirs.len);
            var q: Query = .init(arena);
            q.call("loadContainerFromID", .{ .id = d.x.container_id }) catch return error.OutOfMemory;
            q.open("rootfs") catch return error.OutOfMemory;
            for (dirs[start..end], start..) |dir, j| {
                const alias = try std.fmt.allocPrint(arena, "c{d}", .{j});
                q.leafArgs(alias, "entries", .{ .path = dir }) catch return error.OutOfMemory;
            }
            const data = try d.run(arena, q.finish() catch return error.OutOfMemory);
            for (start..end) |j| {
                const key = try std.fmt.allocPrint(arena, "c{d}", .{j});
                // Entries name directories with a trailing `/`; the walk wants bare names.
                const names = jsonStrings(arena, jsonFind(data, key)) catch return error.OutOfMemory;
                const bare = try arena.alloc([]const u8, names.len);
                for (names, bare) |n, *b| b.* = std.mem.trimEnd(u8, n, "/");
                out[j] = bare;
            }
        }
        return out;
    }
};

/// `sha256sum` over the files, in order, in the job's container (the names are listed in a
/// file, so any number fits), then the SHA-256 of those digests, as GitHub computes it.
pub fn hashListed(
    x: *Exec,
    arena: Allocator,
    ws: []const u8,
    files: []const []const u8,
) Allocator.Error!expr.HashFiles.Result {
    const list = try std.mem.join(arena, "\n", files);
    var q: Query = .init(arena);
    q.call("loadContainerFromID", .{ .id = x.container_id }) catch return error.OutOfMemory;
    q.call("withNewFile", .{ .path = hash_list_path, .contents = list }) catch
        return error.OutOfMemory;
    // A name that is a directory once symbolic links are followed (`docs -> ../docs`) is
    // skipped, as GitHub's script skips what `fs.statSync` calls a directory: sha256sum would
    // fail on it, and hashFiles() with it. Dagger's glob cannot tell a link from a file.
    const hash_cmd = std.fmt.allocPrint(
        arena,
        "cd {s} && while IFS= read -r f || [ -n \"$f\" ]; do [ -d \"$f\" ] || printf '%s\\0' \"$f\"; " ++
            "done < " ++ hash_list_path ++ " | xargs -0 -r sha256sum --",
        .{ws},
    ) catch return error.OutOfMemory;
    q.call(
        "withExec",
        .{ .args = &[_][]const u8{ "sh", "-c", hash_cmd }, .expect = Raw{ .text = "ANY" } },
    ) catch return error.OutOfMemory;
    for ([_][]const u8{ "exitCode", "stdout", "stderr" }) |f| q.leaf(f) catch
        return error.OutOfMemory;
    var msg: []const u8 = "";
    const hdata = gql(
        arena,
        x.transport,
        q.finish() catch return error.OutOfMemory,
        &msg,
    ) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .failed = msg },
    };
    const code = if (jsonFind(
        hdata,
        "exitCode",
    )) |c| (if (c == .integer) c.integer else 1) else 1;
    if (code != 0) {
        const stderr = jsonFindString(hdata, "stderr") orelse "sha256sum failed";
        return .{ .failed = std.mem.trim(u8, stderr, " \n") };
    }
    return foldDigests(arena, jsonFindString(hdata, "stdout") orelse "", files.len);
}

/// The SHA-256 of the digests sha256sum printed, one line per file; a count that does not match
/// the files hashed is a failure, not a partial answer.
fn foldDigests(
    arena: Allocator,
    stdout: []const u8,
    expected: usize,
) Allocator.Error!expr.HashFiles.Result {
    var result = std.crypto.hash.sha2.Sha256.init(.{});
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, stdout, "\n"), '\n');
    var n: usize = 0;
    while (lines.next()) |line_in| {
        // sha256sum marks names it had to escape with a leading backslash.
        const line = if (std.mem.startsWith(u8, line_in, "\\")) line_in[1..] else line_in;
        if (line.len < 64) return .{ .failed = "unexpected sha256sum output" };
        var digest: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&digest, line[0..64]) catch
            return .{ .failed = "unexpected sha256sum output" };
        result.update(&digest);
        n += 1;
    }
    // Fewer is directories skipped (a failed read is a failed exit, seen before this).
    if (n > expected) return .{ .failed = "unexpected sha256sum output" };
    if (n == 0) return .{ .ok = "" };
    const hex = std.fmt.bytesToHex(result.finalResult(), .lower);
    return .{ .ok = try arena.dupe(u8, &hex) };
}

/// Dagger's answer to Fs.stat: one letter per path, `d`irectory, `f`ile, `l`ink, `m`issing.
fn existsAnswer(arena: Allocator, kinds: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"data\":{\"loadContainerFromID\":{\"rootfs\":{");
    for (kinds, 0..) |k, i| {
        if (i > 0) try out.append(arena, ',');
        try out.print(arena, "\"e{d}\":{},\"d{d}\":{},\"f{d}\":{},\"l{d}\":{}", .{
            i, k != 'm', i, k == 'd', i, k == 'f', i, k == 'l',
        });
    }
    try out.appendSlice(arena, "}}}}");
    return out.items;
}

test "hashFiles finds files as GitHub's script does, through Dagger, and hashes them in its order" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var st = testStep("");
    st.action.script.script = .{ .expr = "format('echo key-{0}', hashFiles('**/package-lock.json', '!node_modules/**'))" };
    var none = testStep("");
    none.action.script.script = .{ .expr = "format('echo none-{0}.', hashFiles('/elsewhere/x', '!a'))" };
    const steps = [_]job_mod.Step{ st, none };
    const d1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const d2 = "2222222222222222222222222222222222222222222222222222222222222222";
    const list = "{\"data\":{\"loadContainerFromID\":{\"rootfs\":{";
    const answers = [_][]const u8{
        base_answer,
        // The workspace, then what is in it (listed in any order; walked in byte order).
        try existsAnswer(arena, "d"),
        list ++ "\"c0\":[\"package-lock.json\",\"node_modules/\",\"a/\"]}}}}",
        try existsAnswer(arena, "ddf"), // a, node_modules, package-lock.json
        list ++ "\"c0\":[\"package-lock.json\"],\"c1\":[\"x/\"]}}}}",
        try existsAnswer(arena, "fd"), // a/package-lock.json, node_modules/x
        list ++ "\"c0\":[\"package-lock.json\"]}}}}",
        try existsAnswer(arena, "f"), // node_modules/x/package-lock.json: excluded, not hashed
        "{\"data\":{\"loadContainerFromID\":{\"withNewFile\":{\"withExec\":{\"exitCode\":0,\"stdout\":\"" ++ d1 ++ "  a/package-lock.json\\n" ++ d2 ++ "  package-lock.json\\n\",\"stderr\":\"\"}}}}}",
        try exec(arena, "C1", 0, ""),
        try exec(arena, "C2", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 11), seen.len);
    for (seen) |d| try std.testing.expect(braceBalanced(d));
    const ws = "/home/runner/work/r/r";
    try std.testing.expect(std.mem.indexOf(u8, seen[1], "loadContainerFromID(id:\"C0\") { rootfs { e0: exists(path:\"" ++ ws ++ "\",doNotFollowSymlinks:true) d0: exists(path:\"" ++ ws ++ "\",expectedType:DIRECTORY_TYPE,doNotFollowSymlinks:true)") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[2], "c0: entries(path:\"" ++ ws ++ "\")") != null);
    // Byte order: a, node_modules, package-lock.json.
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "e0: exists(path:\"" ++ ws ++ "/a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "e2: exists(path:\"" ++ ws ++ "/package-lock.json\"") != null);
    // In GitHub's order, depth-first; node_modules' file excluded. Directories are skipped there.
    try std.testing.expect(std.mem.indexOf(u8, seen[8], "loadContainerFromID(id:\"C0\") { withNewFile(path:\"/tmp/zig-runner-hashfiles\",contents:\"a/package-lock.json\\npackage-lock.json\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[8], "[ -d \\\"$f\\\" ] ||") != null);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&(@as([32]u8, @splat(0x11))));
    h.update(&(@as([32]u8, @splat(0x22))));
    const want = try std.fmt.allocPrint(arena, "echo key-{s}", .{&std.fmt.bytesToHex(h.finalResult(), .lower)});
    try std.testing.expect(std.mem.indexOf(u8, seen[9], want) != null);
    // Nothing inside the workspace to search: "" without asking Dagger.
    try std.testing.expect(std.mem.indexOf(u8, seen[10], "echo none-.") != null);
}

test "hashFiles --follow-symbolic-links follows links, breaks a cycle by realpath in the container" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var st = testStep("");
    st.action.script.script = .{ .expr = "format('echo key-{0}', hashFiles('--follow-symbolic-links', '**/*.txt'))" };
    const steps = [_]job_mod.Step{st};
    const ws = "/home/runner/work/r/r";
    const d1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const d2 = "2222222222222222222222222222222222222222222222222222222222222222";
    const list = "{\"data\":{\"loadContainerFromID\":{\"rootfs\":{";
    const real = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"exitCode\":0,\"stderr\":\"\",\"stdout\":\"";
    const answers = [_][]const u8{
        base_answer,
        try existsAnswer(arena, "d"),
        real ++ ws ++ "\\n\"}}}}",
        list ++ "\"c0\":[\"x.txt\",\"a/\"]}}}}",
        try existsAnswer(arena, "df"), // a, x.txt
        real ++ ws ++ "/a\\n\"}}}}",
        list ++ "\"c0\":[\"y.txt\",\"loop\"]}}}}",
        try existsAnswer(arena, "df"), // a/loop (a link to the workspace, followed), a/y.txt
        real ++ ws ++ "\\n\"}}}}", // a/loop is the workspace again: a cycle, not walked
        "{\"data\":{\"loadContainerFromID\":{\"withNewFile\":{\"withExec\":{\"exitCode\":0,\"stdout\":\"" ++ d1 ++ "  a/y.txt\\n" ++ d2 ++ "  x.txt\\n\",\"stderr\":\"\"}}}}}",
        try exec(arena, "C1", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 11), seen.len);
    // Following links: `exists` follows them, and realpath runs in the job's container.
    try std.testing.expect(std.mem.indexOf(u8, seen[1], "e0: exists(path:\"" ++ ws ++ "\",doNotFollowSymlinks:false)") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[2], "withExec(args:[\"realpath\",\"" ++ ws ++ "\"],expect:ANY)") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[8], "realpath\",\"" ++ ws ++ "/a/loop\"") != null);
    // The cycle is not listed; the files are hashed in GitHub's order.
    try std.testing.expect(std.mem.indexOf(u8, seen[9], "contents:\"a/y.txt\\nx.txt\"") != null);
}
