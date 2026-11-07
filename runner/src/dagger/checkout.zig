//! The built-in checkout: the query that fetches a repository with Dagger's git, the
//! submodules left empty, and the log and refs it leaves as actions/checkout does.

const std = @import("std");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const Query = @import("query.zig").Query;
const Transport = @import("../dagger.zig").Transport;
const Fetched = @import("../dagger.zig").Fetched;
const Outcome = @import("../dagger.zig").Outcome;
const run = @import("../dagger.zig").run;
const gql = @import("../dagger.zig").gql;
const jsonFind = @import("../dagger.zig").jsonFind;
const jsonFindString = @import("../dagger.zig").jsonFindString;
const shellQuote = @import("../dagger.zig").shellQuote;
const jobWorkspace = @import("../dagger.zig").jobWorkspace;
const FakeSession = @import("testing.zig").FakeSession;
const fake_child = @import("testing.zig").fake_child;
const base_answer = @import("testing.zig").base_answer;
const exec = @import("testing.zig").exec;
const testStep = @import("testing.zig").testStep;
const testJob = @import("testing.zig").testJob;
const braceBalanced = @import("testing.zig").braceBalanced;

const Allocator = std.mem.Allocator;

// --- checkout resolution ---

/// Whether `s` is a full 40-digit hexadecimal commit id.
pub fn isSha(s: []const u8) bool {
    if (s.len != 40) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

/// The time checked-out files get: 2000-01-01 00:00 UTC (see `query`).
pub const mtime: i64 = 946684800;

/// The query that resolves a checkout to a Directory id, or null with a reason. `auth`: a Dagger
/// secret holding the job's GITHUB_TOKEN, sent as GitHub expects a token over HTTPS (user
/// `x-access-token`), so private repositories can be checked out, as actions/checkout does.
pub fn query(
    arena: Allocator,
    job: job_mod.Job,
    co: job_mod.Checkout,
    auth: ?[]const u8,
) !union(enum) { doc: []const u8, err: []const u8 } {
    const repo = co.repository orelse job.github.repository;
    if (repo.len == 0)
        return .{ .err = "no repository to check out (the job has no github.repository)" };
    const own = co.repository == null or std.mem.eql(u8, repo, job.github.repository);
    const url = try std.fmt.allocPrint(
        arena,
        "{s}/{s}.git",
        .{ std.mem.trimEnd(u8, job.github.server_url, "/"), repo },
    );

    var q: Query = .init(arena);
    // The token, sent as GitHub expects one over HTTPS (user `x-access-token`).
    const auth_user: ?[]const u8 = if (auth != null) "x-access-token" else null;
    try q.call(
        "git",
        .{ .url = url, .httpAuthUsername = auth_user, .httpAuthToken = auth, .keepGitDir = true },
    );
    if (co.ref orelse (if (own and job.github.sha.len > 0) job.github.sha else null)) |ref| {
        if (isSha(ref))
            try q.call("commit", .{ .id = ref })
        else
            try q.call("ref", .{ .name = ref });
    } else {
        try q.open("head");
    }
    // `depth` is always sent: Dagger's default is 1, and 0 is what fetches the full history.
    // Dagger's git gives every file the time 1970-01-01 00:00:01. Tools reject that (Python wheels
    // are zips, which cannot hold times before 1980: "ZIP does not support timestamps before
    // 1980"); a fixed later time keeps the tree the same from run to run, so cached steps still
    // match. Without `submodules`, the root's entries say whether there are any to empty (see
    // `fetch`).
    const include_tags: ?bool = if (co.fetch_tags) true else null;
    try q.call("tree", .{ .depth = co.fetch_depth, .includeTags = include_tags });
    try q.call("withTimestamps", .{ .timestamp = mtime });
    try q.leaf("id");
    if (!co.submodules) try q.leaf("entries");
    return .{ .doc = try q.finish() };
}

/// The tree with each submodule's directory emptied, as actions/checkout leaves them without
/// `submodules` (Dagger's git always checks them out). The paths come from `.gitmodules`.
fn withoutSubmodules(
    arena: Allocator,
    t: Transport,
    dir: []const u8,
    msg: *[]const u8,
) !?[]const u8 {
    var read: Query = .init(arena);
    try read.call("loadDirectoryFromID", .{ .id = dir });
    try read.call("file", .{ .path = ".gitmodules" });
    try read.leaf("contents");
    const data = gql(arena, t, try read.finish(), msg) catch return null;
    const paths = try gitmodulePaths(arena, jsonFindString(data, "contents") orelse "");
    if (paths.len == 0) return dir;
    var q: Query = .init(arena);
    try q.call("loadDirectoryFromID", .{ .id = dir });
    for (paths) |p| {
        try q.call("withoutDirectory", .{ .path = p });
        try q.call("withNewDirectory", .{ .path = p });
    }
    // The new directories get the checkout's fixed time, as every other file has.
    try q.call("withTimestamps", .{ .timestamp = mtime });
    try q.leaf("id");
    const out = gql(arena, t, try q.finish(), msg) catch return null;
    return jsonFindString(out, "id") orelse {
        msg.* = "Dagger returned no tree";
        return null;
    };
}

/// The `path = ...` of each submodule in a `.gitmodules` file.
fn gitmodulePaths(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, line[0..eq], " \t"), "path")) continue;
        const p = std.mem.trim(u8, std.mem.trim(u8, line[eq + 1 ..], " \t"), "\"/");
        if (p.len == 0 or std.mem.indexOf(u8, p, "..") != null) continue;
        try out.append(arena, p);
    }
    return out.items;
}

/// The checkout step's log up to the commit: actions/checkout's folds ("Fetching the repository",
/// "Checking out the ref"), filled with what the built-in checkout did instead of git commands it
/// did not run. The script closes the last fold after setting up the refs.
pub fn log(arena: Allocator, f: Fetched) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    try out.append(arena, try std.fmt.allocPrint(arena, "Syncing repository: {s}", .{f.repo}));
    try out.append(arena, "##[group]Fetching the repository");
    try out.append(
        arena,
        try std.fmt.allocPrint(arena, "Fetched {s} with {s} (the runner's " ++
            "built-in checkout replaces actions/checkout)", .{ f.url, f.fetched_with }),
    );
    const kind: []const u8 = if (isSha(f.want)) "Commit" else "Ref";
    try out.append(arena, try std.fmt.allocPrint(arena, "{s}: {s}", .{ kind, f.want }));
    if (f.depth == 0) {
        try out.append(arena, "Depth: full history");
    } else {
        try out.append(arena, try std.fmt.allocPrint(arena, "Depth: {d}", .{f.depth}));
    }
    try out.append(
        arena,
        try std.fmt.allocPrint(arena, "Tags: {s}", .{if (f.tags) "fetched" else "not fetched"}),
    );
    try out.append(arena, "##[endgroup]");
    try out.append(arena, "##[group]Checking out the ref");
    try out.append(arena, try std.fmt.allocPrint(arena, "Into {s}", .{f.mount}));
    const ref = f.git_ref orelse {
        try out.append(
            arena,
            try std.fmt.allocPrint(arena, "HEAD is detached at {s}", .{f.ref_label}),
        );
        return out.items;
    };
    if (std.mem.startsWith(u8, ref, "refs/heads/")) {
        const b = ref["refs/heads/".len..];
        try out.append(
            arena,
            try std.fmt.allocPrint(arena, "Switched to a new branch '{s}'", .{b}),
        );
        try out.append(
            arena,
            try std.fmt.allocPrint(arena, "branch '{s}' set up to track 'origin/{s}'.", .{ b, b }),
        );
    } else if (std.mem.startsWith(u8, ref, "refs/pull/")) {
        const pull = ref["refs/pull/".len..];
        try out.append(arena, try std.fmt.allocPrint(arena, "HEAD is detached at " ++
            "refs/remotes/pull/{s}", .{pull}));
    } else if (std.mem.startsWith(u8, ref, "refs/")) {
        try out.append(arena, try std.fmt.allocPrint(arena, "HEAD is detached at {s}", .{ref}));
    } else {
        try out.append(
            arena,
            try std.fmt.allocPrint(arena, "HEAD is detached at origin/{s}", .{ref}),
        );
    }
    return out.items;
}

/// Shell lines that give a fetched tree the refs actions/checkout leaves: Dagger's tree has a
/// detached HEAD and no refs at all. Without a ref at HEAD, a later `git fetch` in the job cannot
/// tell the server what it already has and downloads the whole tree again; that is also why the
/// dagger CLI warned "failed to fetch branch" on pull requests (its go-git reads the PR head right
/// after such a fetch, and does not see the new pack file the large fetch produced). refs/heads/B
/// -> refs/remotes/origin/B and a local branch B tracking it, checked out refs/pull/N/merge   ->
/// refs/remotes/pull/N/merge (detached), likewise refs/pull/N/head refs/tags/T         ->
/// refs/tags/T (detached) other refs/...      -> the same ref (detached) a bare name         ->
/// refs/remotes/origin/<name> (detached) Failures are ignored (an image without git, say): the
/// checkout itself is already done.
pub fn refCommands(arena: Allocator, mount: []const u8, ref: []const u8) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("if command -v git >/dev/null 2>&1; then ( cd ");
    try shellQuote(w, mount);
    try w.writeAll(" && g() { git -c safe.directory='*' \"$@\"; }");
    if (std.mem.startsWith(u8, ref, "refs/heads/")) {
        const branch = ref["refs/heads/".len..];
        const items = [_][2][]const u8{
            .{ "update-ref", try std.fmt.allocPrint(arena, "refs/remotes/origin/{s}", .{branch}) },
            .{ "update-ref", ref },
        };
        for (items) |it| {
            try w.print(" && g {s} ", .{it[0]});
            try shellQuote(w, it[1]);
            try w.writeAll(" HEAD");
        }
        try w.writeAll(" && g symbolic-ref HEAD ");
        try shellQuote(w, ref);
        try w.writeAll(" && g config ");
        try shellQuote(w, try std.fmt.allocPrint(arena, "branch.{s}.remote", .{branch}));
        try w.writeAll(" origin && g config ");
        try shellQuote(w, try std.fmt.allocPrint(arena, "branch.{s}.merge", .{branch}));
        try w.writeByte(' ');
        try shellQuote(w, ref);
    } else {
        const target = if (std.mem.startsWith(u8, ref, "refs/pull/"))
            try std.fmt.allocPrint(arena, "refs/remotes/pull/{s}", .{ref["refs/pull/".len..]})
        else if (std.mem.startsWith(u8, ref, "refs/"))
            ref
        else
            try std.fmt.allocPrint(arena, "refs/remotes/origin/{s}", .{ref});
        try w.writeAll(" && g update-ref ");
        try shellQuote(w, target);
        try w.writeAll(" HEAD");
    }
    try w.writeAll(" ) >/dev/null 2>&1 || true; fi\n");
    return aw.written();
}

/// Whether git's message reads like a refused or missing credential, which the checkout then
/// explains.
pub fn looksLikeAuthFailure(text: []const u8) bool {
    const needles = [_][]const u8{
        "not found",
        "authentication",
        "Authentication",
        "denied",
        "403",
        "401",
        "could not read Username",
    };
    for (needles) |n| if (std.mem.indexOf(u8, text, n) != null) return true;
    return false;
}

pub fn fetch(
    arena: Allocator,
    t: Transport,
    job: job_mod.Job,
    co: job_mod.Checkout,
    auth: ?[]const u8,
) !Fetched {
    var f = try describe(arena, job, co);
    const repo = f.repo;
    const label = f.ref_label;

    const doc = switch (try query(arena, job, co, auth)) {
        .err => |msg| {
            f.result = .{ .failed = msg };
            return f;
        },
        .doc => |d| d,
    };
    var msg: []const u8 = "";
    if (gql(arena, t, doc, &msg)) |data| {
        if (jsonFindString(data, "id")) |id| {
            f.result = try checkedOutTree(arena, t, co, repo, data, id, &msg);
            return f;
        }
        msg = "Dagger returned no tree";
    } else |_| {}
    f.result = .{ .failed = try std.fmt.allocPrint(arena, "could not fetch {s}@{s}: {s}{s}", .{
        repo, label, msg,
        if (looksLikeAuthFailure(msg)) " (the job's GITHUB_TOKEN reads only " ++
            "the job's own repository; another private one cannot be checked out)" else "",
    }) };
    return f;
}

/// What a checkout fetches and where it goes, before anything is fetched: the `Fetched` with its
/// result still to be set. Shared with the native backend's checkout (`Backend.fetchCheckout`).
pub fn describe(arena: Allocator, job: job_mod.Job, co: job_mod.Checkout) !Fetched {
    const repo = co.repository orelse job.github.repository;
    const ws = try jobWorkspace(arena, job);
    const mount = if (co.path) |pth|
        try std.fmt.allocPrint(arena, "{s}/{s}", .{ ws, std.mem.trim(u8, pth, "/") })
    else
        ws;
    const want = co.ref orelse (if (co.repository == null) job.github.sha else "HEAD");
    const label = if (isSha(want)) want[0..7] else want;
    const git_ref = gitRef(co, job);
    return .{
        .result = .{ .failed = "" },
        .repo = repo,
        .ref_label = label,
        .mount = mount,
        .git_ref = git_ref,
        .url = try std.fmt.allocPrint(
            arena,
            "{s}/{s}",
            .{ std.mem.trimEnd(u8, job.github.server_url, "/"), repo },
        ),
        .want = want,
        .depth = co.fetch_depth,
        .tags = co.fetch_tags,
    };
}

/// The ref the checkout is named by (`git_ref`): the one asked for unless it is a commit, else for
/// the workflow's own repository the ref that triggered the run, as actions/checkout does.
fn gitRef(co: job_mod.Checkout, job: job_mod.Job) ?[]const u8 {
    if (co.ref) |r| return if (isSha(r)) null else r;
    if (co.repository == null and job.github.ref.len > 0) return job.github.ref;
    return null;
}

/// Whether the tree's root lists a `.gitmodules` (the query asks for `entries` only without
/// `submodules`).
fn hasGitmodules(data: std.json.Value) bool {
    const es = jsonFind(data, "entries") orelse return false;
    if (es != .array) return false;
    for (es.array.items) |e| {
        if (e == .string and std.mem.eql(u8, e.string, ".gitmodules")) return true;
    }
    return false;
}

/// The tree as checked out: `id`, or with its submodule directories emptied when the checkout did
/// not ask for them.
fn checkedOutTree(
    arena: Allocator,
    t: Transport,
    co: job_mod.Checkout,
    repo: []const u8,
    data: std.json.Value,
    id: []const u8,
    msg: *[]const u8,
) !@FieldType(Fetched, "result") {
    if (co.submodules or !hasGitmodules(data)) return .{ .dir = id };
    const dir = try withoutSubmodules(arena, t, id, msg) orelse return .{
        .failed = try std.fmt.allocPrint(arena, "could not leave {s}'s submodules out: {s}", .{
            repo,
            msg.*,
        }),
    };
    return .{ .dir = dir };
}

test "the checkout log names the ref as the checkout leaves it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const base: Fetched = .{ .result = .{ .dir = "D" }, .repo = "o/r", .ref_label = "abc1234", .mount = "/github/workspace", .url = "https://github.com/o/r", .want = "refs/pull/7/merge", .depth = 0 };
    const cases = [_]struct { ref: ?[]const u8, want: []const u8 }{
        .{ .ref = "refs/heads/main", .want = "branch 'main' set up to track 'origin/main'." },
        .{ .ref = "refs/pull/7/merge", .want = "HEAD is detached at refs/remotes/pull/7/merge" },
        .{ .ref = "v1", .want = "HEAD is detached at origin/v1" },
        .{ .ref = "refs/tags/v1", .want = "HEAD is detached at refs/tags/v1" },
        .{ .ref = null, .want = "HEAD is detached at abc1234" },
    };
    for (cases) |c| {
        var f = base;
        f.git_ref = c.ref;
        const lines = try log(arena, f);
        try std.testing.expectEqualStrings(c.want, lines[lines.len - 1]);
        try std.testing.expectEqualStrings("Depth: full history", lines[4]);
        try std.testing.expectEqualStrings("Ref: refs/pull/7/merge", lines[3]);
    }
}

test "the submodules to leave empty come from .gitmodules" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const paths = try gitmodulePaths(a.allocator(),
        \\[submodule "themes/PaperMod"]
        \\    path = themes/PaperMod
        \\    url = https://github.com/adityatelange/hugo-PaperMod.git
        \\
        \\[submodule "public"]
        \\    path=public/
        \\    url = https://github.com/lementknight/lementknight.github.io.git
        \\[submodule "escape"]
        \\    path = ../outside
    );
    try std.testing.expectEqual(@as(usize, 2), paths.len);
    try std.testing.expectEqualStrings("themes/PaperMod", paths[0]);
    try std.testing.expectEqualStrings("public", paths[1]);
}

test "query picks commit, ref or head and honours fetch-depth" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const job = testJob(&.{});
    const own = (try query(a.allocator(), job, .{}, null)).doc;
    try std.testing.expectEqualStrings("{ git(url:\"https://github.com/o/r.git\",keepGitDir:true) { commit(id:\"0123456789012345678901234567890123456789\") { tree(depth:1) { withTimestamps(timestamp:946684800) { id entries } } } } }", own);
    const by_ref = (try query(a.allocator(), job, .{ .ref = "refs/pull/7/merge", .fetch_depth = 0 }, null)).doc;
    try std.testing.expectEqualStrings("{ git(url:\"https://github.com/o/r.git\",keepGitDir:true) { ref(name:\"refs/pull/7/merge\") { tree(depth:0) { withTimestamps(timestamp:946684800) { id entries } } } } }", by_ref);
    const tags = (try query(a.allocator(), job, .{ .fetch_tags = true }, "SEC")).doc;
    try std.testing.expect(std.mem.indexOf(u8, tags, "tree(depth:1,includeTags:true) { withTimestamps(timestamp:946684800) { id entries }") != null);
    // With the job's GITHUB_TOKEN (a secret), as GitHub expects a token over HTTPS.
    try std.testing.expect(std.mem.indexOf(u8, tags, "git(url:\"https://github.com/o/r.git\",httpAuthUsername:\"x-access-token\",httpAuthToken:\"SEC\",keepGitDir:true)") != null);
    const other = (try query(a.allocator(), job, .{ .repository = "x/y", .fetch_depth = 3 }, null)).doc;
    try std.testing.expect(std.mem.indexOf(u8, other, "x/y.git") != null and std.mem.indexOf(u8, other, "{ head { tree(depth:3)") != null);
    var empty = job;
    empty.github.repository = "";
    try std.testing.expect((try query(a.allocator(), empty, .{}, null)) == .err);
}

test "run mounts a fetched checkout, and a failed fetch fails only that step" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var co = testStep("x");
    co.name = "Run actions/checkout@v4";
    co.action = .{ .checkout = &.{} };
    var after = testStep("echo after");
    after.condition = "always()";
    const steps = [_]job_mod.Step{ co, after };

    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"git\":{\"commit\":{\"tree\":{\"id\":\"TREE1\"}}}}}",
        try exec(arena, "C1", 0, "Syncing repository: o/r\\n"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var job_log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    _ = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &job_log);
    for (fake.seen.items) |d| try std.testing.expect(braceBalanced(d));
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "withDirectory(path:\"/home/runner/work/r/r\",source:\"TREE1\")") != null);
    // actions/checkout's folds, with what the built-in checkout did, and the commit last (from git).
    const co_script = fake.seen.items[2];
    for ([_][]const u8{
        "Syncing repository: o/r",
        "##[group]Fetching the repository",
        "Fetched https://github.com/o/r with Dagger",
        "Commit: 0123456789012345678901234567890123456789",
        "Depth: 1",
        "Tags: not fetched",
        "##[group]Checking out the ref",
        "Into /home/runner/work/r/r",
        "Switched to a new branch ",
        "/home/runner/work/r/r",
        " log -1 --format=%H",
    }) |want| if (std.mem.indexOf(u8, co_script, want) == null) {
        std.debug.print("missing: {s}\n", .{want});
        return error.TestUnexpectedResult;
    };

    // Fetch failure (GraphQL error): that step fails with the reason; the always() step still runs.
    const answers2 = [_][]const u8{
        base_answer,
        "{\"errors\":[{\"message\":\"remote: Repository not found.\"}]}",
        try exec(arena, "C1", 0, "after\\n"),
    };
    var fake2: FakeSession = .{ .answers = &answers2, .arena = arena };
    var buf2: [2048]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var log2: sink.LogSink = .{ .stdout = .{ .writer = &w2 } };
    const res2 = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake2.transport() }, testJob(&steps), &log2);
    try std.testing.expectEqual(Outcome.failure, res2.steps[0].outcome);
    try std.testing.expectEqual(Outcome.success, res2.steps[1].outcome);
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "could not fetch o/r@0123456: remote: Repository not found. (the job's GITHUB_TOKEN reads only the job's own repository; another private one cannot be checked out)") != null);
}

test "a checkout gets the refs actions/checkout leaves" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const branch = try refCommands(ar, "/github/workspace", "refs/heads/main");
    try std.testing.expect(std.mem.indexOf(u8, branch, "g update-ref 'refs/remotes/origin/main' HEAD && g update-ref 'refs/heads/main' HEAD && g symbolic-ref HEAD 'refs/heads/main' && g config 'branch.main.remote' origin && g config 'branch.main.merge' 'refs/heads/main'") != null);
    try std.testing.expect(std.mem.indexOf(u8, try refCommands(ar, "/w", "refs/pull/36/merge"), "g update-ref 'refs/remotes/pull/36/merge' HEAD )") != null);
    try std.testing.expect(std.mem.indexOf(u8, try refCommands(ar, "/w", "refs/tags/v1"), "g update-ref 'refs/tags/v1' HEAD )") != null);
    try std.testing.expect(std.mem.indexOf(u8, try refCommands(ar, "/w", "release"), "g update-ref 'refs/remotes/origin/release' HEAD )") != null);
    // Never fails the step, and only runs where git exists.
    try std.testing.expect(std.mem.startsWith(u8, branch, "if command -v git >/dev/null 2>&1; then ( cd '/github/workspace' && "));
    try std.testing.expect(std.mem.endsWith(u8, branch, ") >/dev/null 2>&1 || true; fi\n"));
}
