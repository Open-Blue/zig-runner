//! The Gitea and Forgejo side of the pool: register once (or find the saved registration), then
//! every runner of the pool asks the instance for a task of its own, as `act_runner`'s `capacity`
//! does: one registration, `RUNNER_COUNT` pollers. A task it is handed is run and reported
//! (`run.zig`) before the runner asks again, so a runner has one task at a time.
//!
//! The pool is GitHub's (`loop.poolWith`): the trust notice, the memory gate, the log spool and the
//! pre-warm are the same, and only what each runner does is this file's.
const std = @import("std");
const Config = @import("../config.zig").Config;
const loop = @import("../loop.zig");
const sink = @import("../sink.zig");
const redact = @import("../redact.zig");
const build_version = @import("../version.zig");
const client_mod = @import("client.zig");
const state_mod = @import("state.zig");
const run = @import("run.zig");

const Allocator = std.mem.Allocator;
const Client = client_mod.Client;
const Failure = client_mod.Failure;

/// How often a runner asks, and how far the wait grows while there is nothing: `act_runner`'s
/// `fetch_interval` (2 s) and `fetch_interval_max` (60 s).
pub const Pace = struct {
    interval_ms: u32 = 2_000,
    max_ms: u32 = 60_000,

    /// The wait after `streak` fetches in a row that found nothing or failed: the interval for the
    /// first, then doubling up to `max_ms`. `jitter` (any value) adds up to a fifth on top, so
    /// runners that started together, or all met an outage together, do not ask together; the
    /// result never passes `max_ms`.
    pub fn waitMs(p: Pace, streak: u32, jitter: u32) u32 {
        const shift: u5 = std.math.cast(u5, @min(streak -| 1, 16)) orelse 16;
        const grown: u64 = @min(@as(u64, p.interval_ms) << shift, p.max_ms);
        const extra: u64 = grown / 5 * jitter / std.math.maxInt(u32);
        return std.math.cast(u32, @min(grown + extra, p.max_ms)) orelse p.max_ms;
    }
};

/// What the runners of the pool share: the credentials, the pace and the instance's latest tasks
/// version, which a runner that sees a newer one tells the others of (they would otherwise each
/// ask what the last answer already said).
const Shared = struct {
    client: Client,
    pace: Pace,
    tasks_version: std.atomic.Value(i64) = .init(0),

    fn seen(sh: *Shared, version: i64) void {
        var cur = sh.tasks_version.load(.acquire);
        while (version > cur) cur = sh.tasks_version.cmpxchgWeak(cur, version, .acq_rel, .acquire) orelse return;
    }

    /// One runner of the pool (`loop.poolWith` calls this in its task): asks for a task until it
    /// gets one, runs it, and asks again, until a stop is requested. Between asks it waits the
    /// pace's interval, longer while there is nothing (or the instance is failing), so a quiet
    /// instance is not asked every 2 s by every runner for ever. A stop is noticed between calls
    /// (a call in flight ends within `Client.deadline`, 10 s at the most); one in flight is not
    /// cut, because the instance may already have given it a task, which the answer would lose.
    /// A task running when the stop comes gets `RUNNER_STOP_GRACE_SECS` and is then cancelled
    /// (`jobs.StopDeadline`).
    pub fn run(sh: *Shared, c: loop.Runner, index: usize) loop.Exit {
        var arena_state: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena_state.deinit();
        var slot: Slot = .{ .shared = sh, .c = c, .index = index };
        defer if (c.gate) |g| g.leave(false);
        var streak: u32 = 0;
        while (!loop.stopRequested()) {
            // The memory gate: ask for a task only once the machine has the memory for one more.
            if (c.gate) |g| if (loop.checkGate(c, g)) |hold| {
                if (!(loop.admit(c, g, hold) catch false)) return .done;
            };
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();
            var failure: Failure = .{};
            const sent = sh.tasks_version.load(.acquire);
            if (sh.client.fetchTask(arena, c.io, sent, &failure)) |f| {
                // A fetch that took a task does not say the instance has no other: it answers a
                // version equal to the sender's with no assignment at all, so a version learned
                // from a task would leave the next task of the same burst (a matrix's second
                // job) unassigned until something else bumped it. Only an empty answer advances
                // the version, as it did, and a task is followed by a fetch with the old one.
                if (f.task == null) sh.seen(f.tasks_version);
                if (f.additional > 0) slot.tell(arena, "runner {d}: the instance also sent {d} " ++
                    "additional task(s), which are not used (one task is asked for)", .{ index, f.additional });
                if (f.task) |t| {
                    slot.runTask(arena, t);
                    streak = 0;
                    continue;
                }
                // A newer version means tasks may have been made: ask again soon.
                streak = if (f.tasks_version > sent) 0 else streak +| 1;
            } else |e| switch (e) {
                error.Unauthenticated => {
                    slot.tell(arena, "runner {d}: the instance does not know this runner any more " ++
                        "(HTTP {d} {s}: {s}); remove its saved registration and register again " ++
                        "with RUNNER_GITEA_REGISTRATION_TOKEN", .{
                        index,
                        @backingInt(failure.status),
                        failure.code,
                        failure.message,
                    });
                    return .github;
                },
                else => {
                    streak +|= 1;
                    slot.tell(arena, "runner {d}: FetchTask failed ({s}{s}{s}); trying again in {d} ms", .{
                        index,
                        @errorName(e),
                        if (failure.message.len > 0) ": " else "",
                        failure.message,
                        sh.pace.waitMs(streak, 0),
                    });
                },
            }
            var rnd: [4]u8 = undefined;
            c.io.random(&rnd);
            sleepOrStop(c.io, sh.pace.waitMs(streak, std.mem.readInt(u32, &rnd, .little)));
        }
        return .done;
    }
};

const Slot = struct {
    shared: *Shared,
    c: loop.Runner,
    index: usize,

    /// Runs the task the instance handed this runner, and reports it (`run.task`). Its end frees
    /// the memory gate's reservation, as a GitHub job's does.
    fn runTask(s: *Slot, arena: Allocator, t: client_mod.Task) void {
        const c = s.c;
        const what = t.describe(arena) catch |e| std.fmt.allocPrint(arena, "task {d} ({s})", .{ t.id, @errorName(e) }) catch "a task";
        s.tell(arena, "runner {d}: fetched {s}", .{ s.index, what });
        // The instance has handed it a job: it stops polling for the gate, which reserves the
        // job's memory from here (`Gate.leave`, `Admitted.begin`).
        if (c.gate) |g| g.leave(true);
        run.task(c, s.shared.client, t);
        // What the job's end said on the slot's own writer (native phases, `job-end:`) is not left
        // for the buffer to fill: `serve` flushes it after each cycle too.
        c.err.flush() catch |e| std.log.warn("gitea: stderr: {s}", .{@errorName(e)});
        if (c.gate) |g| {
            g.leave(false);
            _ = g.ended();
        }
    }

    /// A line in the log; one that cannot be written is no reason to stop fetching.
    fn tell(s: *Slot, arena: Allocator, comptime fmt: []const u8, args: anytype) void {
        const text = std.fmt.allocPrint(arena, fmt, args) catch return;
        s.c.log.say(text) catch |e| std.log.warn("gitea: log: {s}", .{@errorName(e)});
    }
};

/// The pool: `n` runners fetching until a stop signal. The exit code is the most severe of theirs.
pub fn pool(c: loop.Runner, n: u32) !loop.Exit {
    const cfg = c.cfg;
    try c.log.say(try std.fmt.allocPrint(
        c.arena,
        "{s}: {s}, {d} runner(s) asking for tasks every {d} s, up to {d} s when there are none",
        .{ @tagName(cfg.platform), cfg.gitea_url, n, cfg.gitea_fetch_interval_secs, cfg.gitea_fetch_interval_max_secs },
    ));
    const creds = switch (try connect(c)) {
        .ok => |st| st,
        .exit => |code| return code,
    };
    // Redacted in everything the runner writes from here on.
    var all: std.ArrayList([]const u8) = .empty;
    try all.appendSlice(c.arena, c.secrets);
    try all.append(c.arena, creds.token);
    c.log.setSecrets(try redact.expand(c.arena, all.items));
    // The jobs' logs redact them too, with the job's own (`run.task`).
    var pooled = c;
    pooled.secrets = all.items;

    var shared: Shared = .{
        .client = .{ .url = cfg.gitea_url, .flavor = flavorOf(cfg), .uuid = creds.uuid, .token = creds.token },
        .pace = .{
            .interval_ms = cfg.gitea_fetch_interval_secs *| 1000,
            .max_ms = cfg.gitea_fetch_interval_max_secs *| 1000,
        },
    };
    return loop.poolWith(pooled, n, &shared);
}

/// The runner's credentials: the saved registration, declared again (labels and version may have
/// changed since), or a new registration with the instance's token, saved. When it cannot be done
/// the operator has been told why (`c.err`), and the exit code to stop with is the answer.
const Connected = union(enum) { ok: state_mod.State, exit: loop.Exit };

fn connect(c: loop.Runner) !Connected {
    const cfg = c.cfg;
    const dir = try cfg.stateDir(c.arena, c.environ);
    const file = try state_mod.fileName(c.arena, cfg.name_prefix);
    const labels = try splitLabels(c.arena, cfg.labels);
    var client: Client = .{ .url = cfg.gitea_url, .flavor = flavorOf(cfg) };
    var failure: Failure = .{};

    const saved = state_mod.load(c.arena, c.io, dir, file) catch |e| {
        try c.err.print(
            "config error: {s}/{s} is not a saved registration ({s}); remove it to register again\n",
            .{ dir, file, @errorName(e) },
        );
        return .{ .exit = .config };
    };
    if (saved) |st| if (std.mem.eql(u8, st.url, cfg.gitea_url)) {
        client.uuid = st.uuid;
        client.token = st.token;
        if (client.declare(c.arena, c.io, .{ .version = build_version.string, .labels = labels }, &failure)) |_| {
            try c.log.say(try std.fmt.allocPrint(
                c.arena,
                "Gitea: runner '{s}' (id {d}) registered earlier ({s}), labels declared: {s}",
                .{ st.name, st.id, file, cfg.labels },
            ));
            return .{ .ok = st };
        } else |e| switch (e) {
            error.Unauthenticated => try c.log.say(try std.fmt.allocPrint(
                c.arena,
                "Gitea: the instance no longer knows runner '{s}' ({s}): registering again",
                .{ st.name, failure.message },
            )),
            else => return explain(c, "declare", e, failure),
        }
        client.uuid = "";
        client.token = "";
    };
    if (cfg.gitea_registration_token.len == 0) {
        try c.err.print(
            "config error: no saved registration in {s}/{s}, and RUNNER_GITEA_REGISTRATION_TOKEN " ++
                "is not set (Gitea: Site administration, Actions, Runners, Create new runner)\n",
            .{ dir, file },
        );
        return .{ .exit = .config };
    }
    const r = client.register(c.arena, c.io, .{
        .name = c.name,
        .token = cfg.gitea_registration_token,
        .version = build_version.string,
        .labels = labels,
    }, &failure) catch |e| return explain(c, "register", e, failure);
    const st: state_mod.State = .{
        .url = cfg.gitea_url,
        .id = r.id,
        .uuid = r.uuid,
        .token = r.token,
        .name = r.name,
    };
    state_mod.save(c.arena, c.io, dir, file, st) catch |e| {
        // Not fatal: the runner works, and registers again at its next start.
        try c.log.say(try std.fmt.allocPrint(
            c.arena,
            "WARNING: could not save the registration in {s}/{s} ({s}); a restart registers again",
            .{ dir, file, @errorName(e) },
        ));
    };
    try c.log.say(try std.fmt.allocPrint(
        c.arena,
        "Gitea: registered runner '{s}' (id {d}) with labels: {s}",
        .{ st.name, st.id, cfg.labels },
    ));
    return .{ .ok = st };
}

/// Tells the operator why a call at start-up failed, and stops the process: neither a refused
/// registration token nor an unreachable instance is helped by trying again here. The instance
/// refusing is the exit code GitHub's refusals have.
fn explain(c: loop.Runner, what: []const u8, e: anyerror, failure: Failure) !Connected {
    switch (e) {
        error.Unauthenticated, error.Rejected => try c.err.print(
            "gitea error: {s}: HTTP {d} {s}: {s}\n",
            .{ what, @backingInt(failure.status), failure.code, failure.message },
        ),
        else => try c.err.print("gitea error: {s} at {s}: {s}\n", .{ what, c.cfg.gitea_url, @errorName(e) }),
    }
    try c.err.flush();
    return .{ .exit = .github };
}

fn flavorOf(cfg: *const Config) client_mod.Flavor {
    return if (cfg.platform == .forgejo) .forgejo else .gitea;
}

fn splitLabels(arena: Allocator, labels: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, labels, ',');
    while (it.next()) |l| {
        const t = std.mem.trim(u8, l, " ");
        if (t.len > 0) try out.append(arena, t);
    }
    return out.items;
}

fn sleepOrStop(io: std.Io, ms: u32) void {
    var left: u32 = ms;
    while (left > 0 and !loop.stopRequested()) {
        const step = @min(left, 200);
        io.sleep(.fromMilliseconds(step), .awake) catch return;
        left -= step;
    }
}

test "the wait doubles while there is nothing, stays under the cap, and is spread by jitter" {
    const p: Pace = .{ .interval_ms = 2_000, .max_ms = 60_000 };
    try std.testing.expectEqual(@as(u32, 2_000), p.waitMs(0, 0));
    try std.testing.expectEqual(@as(u32, 2_000), p.waitMs(1, 0));
    try std.testing.expectEqual(@as(u32, 4_000), p.waitMs(2, 0));
    try std.testing.expectEqual(@as(u32, 16_000), p.waitMs(4, 0));
    try std.testing.expectEqual(@as(u32, 60_000), p.waitMs(6, 0));
    try std.testing.expectEqual(@as(u32, 60_000), p.waitMs(4_000_000_000, std.math.maxInt(u32)));
    // At most a fifth more, and the cap holds.
    try std.testing.expectEqual(@as(u32, 2_400), p.waitMs(1, std.math.maxInt(u32)));
    try std.testing.expectEqual(@as(u32, 1_200), (Pace{ .interval_ms = 1_000, .max_ms = 5_000 }).waitMs(1, std.math.maxInt(u32)));
}

/// A pool against the fake instance, in the test's thread until it stops.
const Rig = struct {
    server: testserver.Server = undefined,
    env: std.process.Environ.Map,
    cfg: Config = undefined,
    out: std.Io.Writer.Allocating,
    err_out: std.Io.Writer.Allocating,
    log: sink.LogSink = undefined,
    arena: std.heap.ArenaAllocator,
    dir: std.testing.TmpDir,
    url_buf: [64]u8 = undefined,

    fn init(r: *Rig, platform: []const u8) !void {
        r.env = .init(std.testing.allocator);
        r.out = .init(std.testing.allocator);
        r.err_out = .init(std.testing.allocator);
        r.arena = .init(std.testing.allocator);
        r.dir = std.testing.tmpDir(.{});
        try r.server.start();
        r.server.echo_acks = true;
        try r.server.replyAlways("UpdateTask", "200 OK", "{\"state\":{}}");
        const state = try r.dir.dir.realPathFileAlloc(std.testing.io, ".", r.arena.allocator());
        try r.env.put("RUNNER_PLATFORM", platform);
        try r.env.put("RUNNER_GITEA_URL", r.server.url(&r.url_buf));
        try r.env.put("RUNNER_GITEA_REGISTRATION_TOKEN", "registration-secret");
        try r.env.put("RUNNER_GITEA_FETCH_INTERVAL", "1");
        try r.env.put("RUNNER_STATE_DIR", state);
        // The pool's memory gate and pre-warm are GitHub's tests' business, not the machine's.
        try r.env.put("RUNNER_ADMISSION", "false");
        try r.env.put("RUNNER_PREWARM", "false");
        r.cfg = try Config.load(&r.env, &.{"runner"});
        r.log = .{ .stdout = .{ .writer = &r.out.writer } };
    }

    fn deinit(r: *Rig) void {
        r.server.stop();
        r.dir.cleanup();
        r.arena.deinit();
        r.out.deinit();
        r.err_out.deinit();
        r.env.deinit();
    }

    fn runner(r: *Rig) loop.Runner {
        var c = loop.testRunner(r.arena.allocator(), &r.log, &r.err_out.writer, &r.cfg);
        c.environ = &r.env;
        c.name = "zig-ab";
        c.secrets = &.{"registration-secret"};
        return c;
    }

    /// `pool` on a thread, stopped once the server has seen `fetches` FetchTask calls.
    fn runUntil(r: *Rig, fetches: usize) !loop.Exit {
        const T = struct {
            fn go(c: loop.Runner, out: *loop.Exit) void {
                out.* = pool(c, 1) catch .config;
            }
        };
        var code: loop.Exit = .done;
        const t = try std.Thread.spawn(.{}, T.go, .{ r.runner(), &code });
        var waited: u32 = 0;
        while (r.server.count("FetchTask") < fetches and waited < 500) : (waited += 1)
            try std.testing.io.sleep(.fromMilliseconds(20), .awake);
        try std.testing.io.sleep(.fromMilliseconds(100), .awake);
        _ = loop.stop_signals.fetchAdd(1, .acq_rel);
        defer loop.stop_signals.store(0, .release);
        t.join();
        return code;
    }
};

const testserver = @import("testserver.zig");

test "a pool registers once, keeps the registration, fetches, runs the task and reports it" {
    var r: Rig = undefined;
    try r.init("gitea");
    defer r.deinit();
    const s = &r.server;
    const reg =
        \\{"runner":{"id":"7","uuid":"uuid-7","token":"runner-token-7","name":"zig-ab","labels":["self-hosted"]}}
    ;
    try s.reply("Register", "200 OK", reg);
    try s.reply("FetchTask", "200 OK", "{\"tasksVersion\":\"1\"}");
    try s.reply("FetchTask", "500 Internal Server Error", "{\"code\":\"internal\",\"message\":\"db is busy\"}");
    try s.reply("FetchTask", "200 OK", @embedFile("testdata/fetch-task.json"));
    try s.reply("FetchTask", "200 OK", "{\"tasksVersion\":\"1\"}");
    try std.testing.expectEqual(loop.Exit.done, try r.runUntil(4));

    // The task is described by names, run (here it fails: no engine) and reported before the
    // runner asks again.
    try std.testing.expect(s.count("FetchTask") >= 4);
    const log = r.out.written();
    try std.testing.expect(std.mem.indexOf(u8, log, "registered runner 'zig-ab' (id 7)") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "FetchTask failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "fetched task 1: workflow \"probe\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "NOT RUN") == null);
    const last = s.nth("UpdateTask", s.count("UpdateTask") - 1).body;
    try std.testing.expect(std.mem.indexOf(u8, last, "\"result\":\"RESULT_FAILURE\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, last, "\"stoppedAt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s.nth("UpdateLog", s.count("UpdateLog") - 1).body, "\"noMore\":true") != null);
    // No credential, the runner's or the instance's, and no secret value, reaches the log.
    for ([_][]const u8{ "registration-secret", "runner-token-7", "uuid-7" }) |secret| {
        try std.testing.expect(std.mem.indexOf(u8, log, secret) == null);
        try std.testing.expect(std.mem.indexOf(u8, r.err_out.written(), secret) == null);
    }
    // The version the instance gave goes back on the next ask; the runner's headers on each.
    try std.testing.expectEqualStrings("{}", s.nth("FetchTask", 0).body);
    try std.testing.expectEqualStrings("{\"tasksVersion\":\"1\"}", s.nth("FetchTask", 1).body);
    try std.testing.expectEqualStrings("runner-token-7", s.nth("FetchTask", 2).token);
    try std.testing.expectEqualStrings("uuid-7", s.nth("FetchTask", 2).uuid);

    // A restart finds the registration: it declares, and does not register again.
    r.out.clearRetainingCapacity();
    try s.reply("Declare", "200 OK", reg);
    try s.reply("FetchTask", "200 OK", "{\"tasksVersion\":\"1\"}");
    try std.testing.expectEqual(loop.Exit.done, try r.runUntil(4));
    try std.testing.expectEqual(@as(usize, 1), s.count("Register"));
    try std.testing.expectEqual(@as(usize, 1), s.count("Declare"));
    try std.testing.expectEqualStrings("runner-token-7", s.nth("Declare", 0).token);
    try std.testing.expect(std.mem.indexOf(u8, r.out.written(), "registered earlier") != null);
}

test "a runner the instance has forgotten stops the pool with the instance's reason" {
    var r: Rig = undefined;
    try r.init("forgejo");
    defer r.deinit();
    const s = &r.server;
    try s.reply("Register", "200 OK", "{\"runner\":{\"id\":\"7\",\"uuid\":\"uuid-x\",\"token\":\"runner-token-x\",\"name\":\"zig-ab\"}}");
    try s.reply("FetchTask", "401 Unauthorized", "{\"code\":\"unauthenticated\",\"message\":\"unregistered runner\"}");
    try std.testing.expectEqual(loop.Exit.github, try r.runUntil(1));
    try std.testing.expect(std.mem.indexOf(u8, r.out.written(), "does not know this runner any more") != null);
    // Forgejo is sent no capabilities.
    try std.testing.expect(std.mem.indexOf(u8, s.nth("Register", 0).body, "capabilities") == null);
}

test "a refused registration token stops the pool and says so, with no token" {
    var r: Rig = undefined;
    try r.init("gitea");
    defer r.deinit();
    try r.server.reply("Register", "400 Bad Request", "{\"code\":\"invalid_argument\",\"message\":\"runner registration token not found\"}");
    try std.testing.expectEqual(loop.Exit.github, try pool(r.runner(), 1));
    try std.testing.expect(std.mem.indexOf(u8, r.err_out.written(), "runner registration token not found") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.err_out.written(), "registration-secret") == null);
    try std.testing.expectEqual(@as(usize, 0), r.server.count("FetchTask"));
}

test "with no saved registration and no token the pool asks for one" {
    var r: Rig = undefined;
    try r.init("gitea");
    defer r.deinit();
    r.cfg.gitea_registration_token = "";
    try std.testing.expectEqual(loop.Exit.config, try pool(r.runner(), 1));
    try std.testing.expect(std.mem.indexOf(u8, r.err_out.written(), "RUNNER_GITEA_REGISTRATION_TOKEN") != null);
    try std.testing.expectEqual(@as(usize, 0), r.server.count("Register"));
}

test "a stop before the first ask fetches nothing" {
    var r: Rig = undefined;
    try r.init("gitea");
    defer r.deinit();
    try r.server.reply("Register", "200 OK", "{\"runner\":{\"id\":\"7\",\"uuid\":\"uuid-x\",\"token\":\"runner-token-x\",\"name\":\"zig-ab\"}}");
    _ = loop.stop_signals.fetchAdd(1, .acq_rel);
    defer loop.stop_signals.store(0, .release);
    try std.testing.expectEqual(loop.Exit.done, try pool(r.runner(), 2));
    try std.testing.expectEqual(@as(usize, 0), r.server.count("FetchTask"));
}
