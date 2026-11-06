//! Output keys: the container a step after an always-run step starts from, keyed on what the
//! step produced (stored by digest in a cache volume) rather than on the step itself.

const std = @import("std");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const Query = @import("query.zig").Query;
const Evaluator = @import("Evaluator.zig");
const fc_dir = @import("scripts.zig").fc_dir;
const Exec = @import("Exec.zig");
const Options = @import("../dagger.zig").Options;
const run = @import("../dagger.zig").run;
const gql = @import("../dagger.zig").gql;
const jsonFind = @import("../dagger.zig").jsonFind;
const jsonFindString = @import("../dagger.zig").jsonFindString;
const shellQuote = @import("../dagger.zig").shellQuote;
const packageCacheScope = @import("set_up.zig").packageCacheScope;
const FakeSession = @import("testing.zig").FakeSession;
const fake_child = @import("testing.zig").fake_child;
const base_answer = @import("testing.zig").base_answer;
const exec = @import("testing.zig").exec;
const testStep = @import("testing.zig").testStep;
const testJob = @import("testing.zig").testJob;
const braceBalanced = @import("testing.zig").braceBalanced;

const Allocator = std.mem.Allocator;

/// The key of the output-key store (see `Exec.output_keys`); null when output keys are off.
pub fn outputKeysKey(
    arena: Allocator,
    ev: *Evaluator,
    job: job_mod.Job,
    opts: Options,
    step_cache: bool,
) !?[]const u8 {
    if (!(step_cache and opts.output_keys and job.github.repository.len > 0)) return null;
    const scope = try packageCacheScope(arena, ev, job.github.repository, opts.trusted);
    return try std.fmt.allocPrint(arena, "zig-runner/{s}/{s}/step-outputs", .{
        job.github.repository,
        scope,
    });
}

/// Where a step's changes are stored, and where the next step's container mounts the store and
/// busybox while copying them in.
const outputs_store = "/zig-runner-outputs";
/// Paths whose changes are left out of a step's output: neither keyed nor carried to the next
/// step. They change on every run without being anything a later step uses, so keying on them
/// would make every digest new: each step's file commands (the runner has read them, and
/// @actions/core writes a random delimiter into them). Tools' own such state (Go's telemetry,
/// Node's compile cache) is in cache volumes instead (see `package_cache_dirs`).
const outputs_ignored = [_][]const u8{fc_dir};

/// Busybox takes its first argument as the applet only when its own name starts with "busybox".
const outputs_busybox = "/busybox.zig-runner";

/// What `outputKeyed` needs of the container before a step, as a root field of the step's own
/// query (`zig_older`): `before` with what the runner added for the step (`pre`), its id and
/// user, and its filesystem without `outputs_ignored`. Only ids and the user are read, so the
/// field runs nothing; it saves a round trip per always-run step.
pub fn writeOlder(q: *Query, before: []const u8, pre: Query.Fragment) !void {
    try q.callAs("zig_older", "loadContainerFromID", .{ .id = before });
    try q.splice(pre);
    try q.leafAs("zig_base", "id");
    try q.leafAs("zig_user", "user");
    try q.callAs("zig_fs", "rootfs", .{});
    for (outputs_ignored) |p| try q.call("withoutDirectory", .{ .path = p });
    try q.leaf("id");
}

/// For a step that always runs: the container the next step starts from, keyed on what the step
/// produced rather than on the step. That is `before` (the container before the step) with what
/// the runner added for the step (`pre`, `pre_braces` nodes: the variables earlier steps set,
/// the action's code and the JavaScript runtime, whose recipes do not change from run to run),
/// and one exec that applies the step's changes (copied from the store at their content digest,
/// removed paths deleted). When the step produces the same files as in an earlier run, the
/// digest, the exec, and so every later step's key are the same, and the later steps can be
/// replayed.
///
/// The content stays in the engine: the runner only handles the digest and removed paths. Null
/// (keep the step's own container) when anything fails, so the job runs as without output keys.
///
/// `older` is the answer to `writeOlder`'s field, which came with the step's exec.
pub fn outputKeyed(
    x: *Exec,
    num: u32,
    older_answer: ?std.json.Value,
    after: []const u8,
) !?[]const u8 {
    const arena = x.arena;
    var msg: []const u8 = "";
    var t = std.Io.Clock.awake.now(x.io).toMilliseconds();

    const older = older_answer orelse return null;
    const base = jsonFindString(older, "zig_base") orelse return null;
    // The image's user ("" for its default, root): the copy runs as root, which can write
    // anywhere and keep owners, and the next steps run as this user again.
    const user = jsonFindString(older, "zig_user") orelse "";
    const older_id = (if (jsonFind(older, "zig_fs")) |f| jsonFindString(
        f,
        "id",
    ) else null) orelse return null;
    var changes_q: Query = .init(arena);
    try changes_q.call("loadContainerFromID", .{ .id = after });
    try changes_q.call("rootfs", .{});
    for (outputs_ignored) |p| try changes_q.call("withoutDirectory", .{ .path = p });
    try changes_q.call("changes", .{ .from = older_id });
    try changes_q.leaf("removedPaths");
    try changes_q.call("layer", .{});
    try changes_q.leaf("id");
    try changes_q.leaf("digest");
    const changes = gql(arena, x.transport, try changes_q.finish(), &msg) catch {
        x.outputsFallback(num, "{s}", .{msg});
        return null;
    };
    x.outputsPhase(num, "the diff and its digest", &t);
    const layer = jsonFind(changes, "layer") orelse return null;
    const layer_id = jsonFindString(layer, "id") orelse return null;
    const digest_full = jsonFindString(layer, "digest") orelse return null;
    const digest = if (std.mem.indexOfScalar(
        u8,
        digest_full,
        ':',
    )) |c| digest_full[c + 1 ..] else digest_full;
    var removed: std.ArrayList([]const u8) = .empty;
    if (jsonFind(changes, "removedPaths")) |r| if (r == .array) for (r.array.items) |p| {
        if (p == .string) try removed.append(arena, p.string);
    };
    return x.storeAndApply(num, base, user, layer_id, digest, .{ .changes = removed.items });
}

/// With step debug: how long one phase of the output-key work took, timed from `t`, which is
/// then reset.
pub fn outputsPhase(x: *Exec, num: u32, name: []const u8, t: *i64) void {
    const now = std.Io.Clock.awake.now(x.io).toMilliseconds();
    if (x.sh.step_debug)
        x.sh.appendFmt(num, "##[debug]Output keys: {s} took {d} ms", .{ name, now - t.* });
    t.* = now;
}

/// Why output keys did not apply to step `num`: shown with step debug, and kept for the
/// runner's own log line (see `Result.output_keys`).
pub fn outputsFallback(x: *Exec, num: u32, comptime fmt: []const u8, args: anytype) void {
    const why = std.fmt.allocPrint(x.arena, fmt, args) catch return;
    x.outputs_reason = why;
    if (x.sh.step_debug) x.sh.appendFmt(num, "##[debug]Output keys: {s}", .{why});
}

/// Counts one always-run step (`started_ms`: when its output-key work began): `id`, the
/// container keyed on its output, or null when it fell back. Returns `id`.
pub fn countOutputKeyed(x: *Exec, num: u32, started_ms: i64, id: ?[]const u8) ?[]const u8 {
    const took = std.Io.Clock.awake.now(x.io).toMilliseconds() - started_ms;
    x.outputs_ms += took;
    if (x.sh.step_debug) x.sh.appendFmt(num, "##[debug]Output keys took {d} ms", .{took});
    if (id != null) {
        x.outputs_applied += 1;
    } else {
        x.outputs_fell_back += 1;
        x.outputs_last_reason = x.outputs_reason orelse
            "an answer from Dagger lacked a field the runner needs";
    }
    x.outputs_reason = null;
    return id;
}

/// For a Docker action, which runs in its own image: the job's container with the workspace the
/// action left (`ws_out`) copied in by its digest. Null when that could not be done.
pub fn outputKeyedWorkspace(x: *Exec, num: u32, ws_out: []const u8) !?[]const u8 {
    var msg: []const u8 = "";
    var q: Query = .init(x.arena);
    try q.call("loadContainerFromID", .{ .id = x.container_id });
    try q.leaf("user");
    try q.close(1);
    try q.call("loadDirectoryFromID", .{ .id = ws_out });
    try q.leaf("digest");
    const data = gql(x.arena, x.transport, try q.finish(), &msg) catch {
        x.outputsFallback(num, "{s}", .{msg});
        return null;
    };
    const digest_full = jsonFindString(data, "digest") orelse return null;
    const digest = if (std.mem.indexOfScalar(
        u8,
        digest_full,
        ':',
    )) |c| digest_full[c + 1 ..] else digest_full;
    return x.storeAndApply(num, x.container_id, jsonFindString(data, "user") orelse
        "", ws_out, digest, .{ .replace_dir = x.ev.workspace });
}

/// Where `storeAndApply` puts a stored output in the next step's container: over the whole
/// filesystem, deleting the paths the step removed (a step's changes), or as the whole contents
/// of one directory (the workspace a Docker action leaves).
const OutputTarget = union(enum) {
    changes: []const []const u8,
    replace_dir: []const u8,
};

/// Stores an output (`layer_id`, a Directory, whose content digest is `digest`) and returns the
/// container the next step starts from: `base` with the output copied in by digest, as `user`.
pub fn storeAndApply(
    x: *Exec,
    num: u32,
    base: []const u8,
    user: []const u8,
    layer_id: []const u8,
    digest: []const u8,
    target: OutputTarget,
) !?[]const u8 {
    var t = std.Io.Clock.awake.now(x.io).toMilliseconds();
    if (digest.len == 0 or std.mem.indexOfNone(u8, digest, "0123456789abcdef") != null)
        return null;
    const busybox = (try x.busyboxFileFor(num, true)) orelse return null;
    const volume = (try x.outputsVolume(num)) orelse return null;
    if (!try x.storeOutput(num, busybox, volume, layer_id, digest)) return null;
    x.outputsPhase(num, "storing it", &t);
    const script = try x.applyScript(digest, target);
    const id = (try x.applyOutput(num, base, user, busybox, volume, script)) orelse return null;
    x.outputsPhase(num, "copying it into the next container", &t);
    x.debugApplied(num, digest, target);
    return id;
}

/// The cache volume outputs are stored in, asked for once per job. Null, with the fallback
/// noted, when the engine would not give one.
pub fn outputsVolume(x: *Exec, num: u32) !?[]const u8 {
    if (x.outputs_volume) |v| return v;
    const arena = x.arena;
    var msg: []const u8 = "";
    var q: Query = .init(arena);
    try q.call("cacheVolume", .{ .key = x.output_keys.? });
    try q.leaf("id");
    const data = gql(arena, x.transport, try q.finish(), &msg) catch {
        x.outputsFallback(num, "no store: {s}", .{msg});
        return null;
    };
    const id = jsonFindString(data, "id") orelse return null;
    x.outputs_volume = id;
    return id;
}

/// Stores the output under its digest unless it is there. Another job may store the same digest
/// at the same time: `mv -T` onto an existing directory fails and leaves it as it was. Each
/// store copies to its own temporary name (the run's nonce is shared by its matrix jobs).
///
/// The directory's time is when a step last produced it (this runs whenever one does, and is
/// never replayed). Outputs not produced for `outputs_days` days go, and copies left half made
/// for a day. Removing one is always safe: a replayed step does not read the store, and when
/// the copy into a next step has to run and finds nothing, that falls back to the step's own
/// container. False, with the fallback noted, when the store exec failed.
///
/// A directory goes by being renamed out of the way first (`<name>.dead.<tmp>`), then deleted:
/// another job may have just produced the same digest and be copying from it (`applyScript`),
/// and `rm -rf` in place would empty it under that copy, which could still end with status 0
/// and leave a partial output to be cached (#102). The rename takes the whole directory at
/// once, so a copy either read all of it first or finds it gone (`applyScript` checks).
pub fn storeOutput(
    x: *Exec,
    num: u32,
    busybox: []const u8,
    volume: []const u8,
    layer_id: []const u8,
    digest: []const u8,
) !bool {
    const arena = x.arena;
    var tmp_raw: [8]u8 = undefined;
    x.io.random(&tmp_raw);
    const tmp_name = std.fmt.bytesToHex(tmp_raw, .lower);
    const store_script = try std.fmt.allocPrint(arena,
        \\for p in $(/bin/busybox find /store -mindepth 1 -maxdepth 1 ! -name '*.dead.*' \( -name '*.tmp.*' -mtime +0 -o -mtime +{d} \)); do /bin/busybox mv -T "$p" "$p.dead.{s}" 2>/dev/null; done
        \\/bin/busybox find /store -mindepth 1 -maxdepth 1 -name '*.dead.*' -exec /bin/busybox rm -rf {{}} +
        \\d=/store/{s}; test -d "$d" && {{ /bin/busybox touch "$d"; exit 0; }}
        \\t="$d.tmp.{s}"; /bin/busybox rm -rf "$t"; /bin/busybox cp -a /in/. "$t" || exit 1
        \\/bin/busybox mv -T "$t" "$d" 2>/dev/null || /bin/busybox rm -rf "$t"; test -d "$d" && /bin/busybox touch "$d"
    , .{ x.outputs_days, &tmp_name, digest, &tmp_name });
    var msg: []const u8 = "";
    var q: Query = .init(arena);
    try q.open("container");
    try q.call(
        "withFile",
        .{ .path = "/bin/busybox", .source = busybox, .permissions = @as(u32, 0o755) },
    );
    try q.call("withMountedCache", .{ .path = "/store", .cache = volume });
    try q.call("withMountedDirectory", .{ .path = "/in", .source = layer_id });
    try q.call(
        "withExec",
        .{ .args = &[_][]const u8{ "/bin/busybox", "sh", "-c", store_script } },
    );
    try q.leaf("exitCode");
    _ = gql(arena, x.transport, try q.finish(), &msg) catch {
        x.outputsFallback(num, "could not store the step's output: {s}", .{msg});
        return false;
    };
    return true;
}

/// The shell that puts a stored output into the next step's container: over the whole
/// filesystem with the removed paths deleted (a step's changes), or as the whole contents of
/// one directory (a Docker action's workspace). The digest and removed paths are the exec's
/// arguments, so they are what its key depends on.
///
/// The stored directory must still be there after the copy: another job's prune renames it
/// away before deleting it (`storeOutput`), so if it is gone the copy may have read only part
/// of it, and the script fails, which falls back to the step's own container (#102).
pub fn applyScript(x: *Exec, digest: []const u8, target: OutputTarget) ![]const u8 {
    const arena = x.arena;
    var apply: std.Io.Writer.Allocating = .init(arena);
    const aw = &apply.writer;
    try aw.writeAll("set -e\ncd /\n");
    switch (target) {
        .changes => |removed| {
            if (removed.len > 0) {
                try aw.writeAll(outputs_busybox ++ " rm -rf --");
                for (removed) |p| {
                    try aw.writeAll(" ");
                    try shellQuote(
                        aw,
                        try std.fmt.allocPrint(arena, "/{s}", .{std.mem.trimStart(u8, p, "/")}),
                    );
                }
                try aw.writeAll("\n");
            }
            try aw.print(
                outputs_busybox ++ " cp -a " ++ outputs_store ++ "/{s}/. /\n",
                .{digest},
            );
            try aw.print("test -d " ++ outputs_store ++ "/{s}\n", .{digest});
        },
        .replace_dir => |dir| {
            try aw.writeAll(outputs_busybox ++ " rm -rf ");
            try shellQuote(aw, dir);
            try aw.writeAll("\n" ++ outputs_busybox ++ " cp -a " ++ outputs_store);
            try aw.print("/{s} ", .{digest});
            try shellQuote(aw, dir);
            try aw.writeAll("\n");
            try aw.print("test -d " ++ outputs_store ++ "/{s}\n", .{digest});
            // As the copy back without output keys does (see `runContainer`).
            if (x.dir_owner) |o| {
                try aw.print(outputs_busybox ++ " chown -R {s}:{s} ", .{ o, o });
                try shellQuote(aw, dir);
                try aw.writeAll("\n");
            }
        },
    }
    return apply.written();
}

/// The next step's container: `base` with the store and busybox mounted, the apply script run
/// as root now (exitCode, so a failure falls back here rather than failing the next step), then
/// the step user restored and the mounts removed. Null, with the fallback noted, when that
/// failed.
pub fn applyOutput(
    x: *Exec,
    num: u32,
    base: []const u8,
    user: []const u8,
    busybox: []const u8,
    volume: []const u8,
    script: []const u8,
) !?[]const u8 {
    const arena = x.arena;
    var q: Query = .init(arena);
    try q.call("loadContainerFromID", .{ .id = base });
    try q.call("withMountedCache", .{ .path = outputs_store, .cache = volume });
    try q.call("withMountedFile", .{ .path = outputs_busybox, .source = busybox });
    try q.call("withUser", .{ .name = "root" });
    try q.call("withExec", .{ .args = &[_][]const u8{ outputs_busybox, "sh", "-c", script } });
    try q.leaf("exitCode");
    if (user.len > 0)
        try q.call("withUser", .{ .name = user })
    else
        try q.call("withoutUser", .{});
    try q.call("withoutMount", .{ .path = outputs_store });
    try q.call("withoutMount", .{ .path = outputs_busybox });
    try q.leaf("id");
    var msg: []const u8 = "";
    const next = gql(arena, x.transport, try q.finish(), &msg) catch {
        x.outputsFallback(
            num,
            "could not copy the step's output into the next container: {s}",
            .{msg},
        );
        return null;
    };
    return jsonFindString(next, "id");
}

/// Under step debug: what the next steps start from.
pub fn debugApplied(x: *Exec, num: u32, digest: []const u8, target: OutputTarget) void {
    if (!x.sh.step_debug) return;
    const short = digest[0..@min(12, digest.len)];
    switch (target) {
        .changes => |removed| x.sh.appendFmt(
            num,
            "##[debug]Output keys: the next steps start from this step's output, " ++
                "sha256:{s} ({d} removed paths)",
            .{ short, removed.len },
        ),
        .replace_dir => |dir| x.sh.appendFmt(
            num,
            "##[debug]Output keys: the next steps start from this step's {s}, sha256:{s}",
            .{ dir, short },
        ),
    }
}

/// An exec's answer with, beside it, what output keys read of the container before the step
/// (`Exec.writeOlder`).
fn execOlder(arena: Allocator, id: []const u8, base: []const u8, user: []const u8, fs: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":{{\"id\":\"{s}\"," ++
            "\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\"}}}}," ++
            "\"zig_older\":{{\"zig_base\":\"{s}\",\"zig_user\":\"{s}\",\"zig_fs\":{{\"id\":\"{s}\"}}}}}}}}",
        .{ id, base, user, fs },
    );
}

test "output keys: after a Docker action, the next steps start from the workspace it left, by digest" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var pulled = testStep("");
    pulled.action = .{ .docker = .{ .image = "alpine:3.22", .inputs = &.{} } };
    const steps = [_]job_mod.Step{pulled};
    var job = testJob(&steps);
    job.secrets = &.{"ghs_jobtoken"};
    job.job_token = "ghs_jobtoken";
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"}]}}
    , .{});
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"bb\":{\"from\":{\"file\":{\"id\":\"BB\"}}},\"empty\":{\"id\":\"EMPTY\"}}}",
        "{\"data\":{\"container\":{\"from\":{\"id\":\"ALP\",\"entrypoint\":[],\"defaultArgs\":[\"/bin/sh\"]}}}}",
        "{\"data\":{\"loadContainerFromID\":{\"directory\":{\"id\":\"WS0\"}}}}",
        "{\"data\":{\"zsec0\":{\"id\":\"SEC\"}}}",
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"ws\":{\"id\":\"WS1\"},\"home\":{\"id\":\"H1\"}}}}}",
        "{\"data\":{\"loadContainerFromID\":{\"user\":\"\"},\"loadDirectoryFromID\":{\"digest\":\"sha256:abcd12\"}}}",
        "{\"data\":{\"cacheVolume\":{\"id\":\"VOL\"}}}",
        "{\"data\":{\"container\":{\"withExec\":{\"exitCode\":0}}}}",
        "{\"data\":{\"loadContainerFromID\":{\"withUser\":{\"withExec\":{\"exitCode\":0,\"withoutUser\":{\"withoutMount\":{\"withoutMount\":{\"id\":\"N1\"}}}}}}}}",
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .output_keys = true, .trusted = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    const seen = fake.seen.items;
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 10), seen.len);
    for (seen) |d| try std.testing.expect(braceBalanced(d));
    // The workspace the action left, by its digest, and the job container's user.
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "loadContainerFromID(id:\"C0\") { user } loadDirectoryFromID(id:\"WS1\") { digest }") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[8], "withMountedDirectory(path:\"/in\",source:\"WS1\")") != null);
    // The job's container before the action, its workspace replaced by the stored copy; the
    // action's own run is not part of it.
    const apply = seen[9];
    try std.testing.expect(std.mem.startsWith(u8, apply, "{ loadContainerFromID(id:\"C0\") {"));
    try std.testing.expect(std.mem.indexOf(u8, apply, "rm -rf '/home/runner/work/r/r'\\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, apply, "cp -a /zig-runner-outputs/abcd12 '/home/runner/work/r/r'\\ntest -d /zig-runner-outputs/abcd12\\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, apply, "WS1") == null);
}

test "output keys: the step after one that always runs starts from that step's output, by digest" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const ctx_json =
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"run_id","v":"123"},{"k":"run_attempt","v":"1"}]}}
    ;
    var with_secret = testStep("setup");
    with_secret.env = &.{.{ .name = "TOKEN", .value = .{ .lit = "s3cr3t-value" } }};
    const steps = [_]job_mod.Step{ with_secret, testStep("build") };
    var job = testJob(&steps);
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena, ctx_json, .{});
    job.secrets = &.{"s3cr3t-value"};
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"zsec0\":{\"id\":\"SEC\"}}}",
        // The exec, and beside it the container before the step.
        try execOlder(arena, "C1", "B0", "circleci", "R0"),
        "{\"data\":{\"loadContainerFromID\":{\"rootfs\":{\"changes\":{\"removedPaths\":[\"tmp/it's gone\"],\"layer\":{\"id\":\"L\",\"digest\":\"sha256:0123abcd\"}}}}}}",
        // busybox and the store, in one query
        "{\"data\":{\"bb\":{\"from\":{\"file\":{\"id\":\"BB\"}}},\"empty\":{\"id\":\"E\"},\"cout\":{\"id\":\"VOL\"}}}",
        "{\"data\":{\"container\":{\"withExec\":{\"exitCode\":0}}}}",
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"exitCode\":0,\"withoutMount\":{\"withoutMount\":{\"id\":\"N1\"}}}}}}",
        try exec(arena, "C2", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .output_keys = true, .trusted = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    for (fake.seen.items) |d| try std.testing.expect(braceBalanced(d));
    try std.testing.expectEqual(@as(usize, 8), fake.seen.items.len);
    // The store, scoped like the package caches, asked for with busybox.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[4], "cout: cacheVolume(key:\"zig-runner/o/r/repo/step-outputs\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[4], "bb: container") != null);
    // What the step changed: the container after it against the one before it, which came with
    // the exec as a field of its own.
    try std.testing.expect(std.mem.startsWith(u8, fake.seen.items[2], "{ loadContainerFromID(id:\"C0\") {"));
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "zig_older: loadContainerFromID(id:\"C0\") { zig_base: id zig_user: user zig_fs: rootfs { withoutDirectory(path:\"/github/file_commands\") {") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[3], "loadContainerFromID(id:\"C1\") { rootfs { withoutDirectory(path:\"/github/file_commands\") { changes(from:\"R0\")") != null);
    // Stored under its digest, the layer mounted.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[5], "withMountedDirectory(path:\"/in\",source:\"L\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[5], "d=/store/0123abcd;") != null);
    // A digest a step produced again is marked used; ones not produced for 7 days, and stale
    // temporary copies, go.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[5], "test -d \\\"$d\\\" && { /bin/busybox touch \\\"$d\\\"; exit 0; }") != null);
    // They go renamed out of the way first, so a copy another job is making from one never reads
    // it half deleted (#102): nothing but a renamed directory is deleted.
    const store = fake.seen.items[5];
    try std.testing.expect(std.mem.indexOf(u8, store, "! -name '*.dead.*' \\\\( -name '*.tmp.*' " ++
        "-mtime +0 -o -mtime +7 \\\\)); do /bin/busybox mv -T \\\"$p\\\" \\\"$p.dead.") != null);
    try std.testing.expect(std.mem.indexOf(u8, store, "-name '*.dead.*' -exec /bin/busybox rm -rf {} +") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, store, "-exec /bin/busybox rm -rf"));
    // Matrix jobs share the run's nonce (123.1): the temporary name is the store's own. Its random
    // hex can start with 123, but it has no dot.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[5], ".tmp.123.1") == null);
    // The next container: the one before the step (with what the runner added for it), the removed
    // path deleted and the content copied in, by digest; the step itself is not part of it.
    const apply = fake.seen.items[6];
    try std.testing.expect(std.mem.startsWith(u8, apply, "{ loadContainerFromID(id:\"B0\") {"));
    try std.testing.expect(std.mem.indexOf(u8, apply, "rm -rf -- '/tmp/it'\\\\''s gone'") != null);
    try std.testing.expect(std.mem.indexOf(u8, apply, "cp -a /zig-runner-outputs/0123abcd/. /\\n" ++
        "test -d /zig-runner-outputs/0123abcd\\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, apply, "C1") == null);
    // As root, which can write anywhere and keep owners; then as the image's user again.
    const as_root = std.mem.indexOf(u8, apply, "withUser(name:\"root\") { withExec(").?;
    try std.testing.expect(std.mem.indexOf(u8, apply, "exitCode withUser(name:\"circleci\") { withoutMount(").? > as_root);
    // The next step starts there.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[7], "loadContainerFromID(id:\"N1\")") != null);
    try std.testing.expectEqual(@as(u32, 1), res.output_keys.applied);
    try std.testing.expectEqual(@as(u32, 0), res.output_keys.fell_back);
}

test "output keys: when they cannot apply, the next step starts from the step's own container, and the job says why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var with_secret = testStep("setup");
    with_secret.env = &.{.{ .name = "TOKEN", .value = .{ .lit = "s3cr3t-value" } }};
    const steps = [_]job_mod.Step{ with_secret, testStep("build") };
    var job = testJob(&steps);
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"}]}}
    , .{});
    job.secrets = &.{"s3cr3t-value"};
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"zsec0\":{\"id\":\"SEC\"}}}",
        try execOlder(arena, "C1", "B0", "", "R0"),
        "{\"errors\":[{\"message\":\"no space left on device\"}]}",
        try exec(arena, "C2", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .output_keys = true, .trusted = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 5), fake.seen.items.len);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[4], "loadContainerFromID(id:\"C1\")") != null);
    try std.testing.expectEqual(@as(u32, 0), res.output_keys.applied);
    try std.testing.expectEqual(@as(u32, 1), res.output_keys.fell_back);
    try std.testing.expect(std.mem.indexOf(u8, res.output_keys.last_reason, "no space left on device") != null);
}
