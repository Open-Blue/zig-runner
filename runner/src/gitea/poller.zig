//! The Gitea and Forgejo side of the pool: register once (or find the saved registration), then
//! every runner of the pool asks the instance for a task of its own, as `act_runner`'s `capacity`
//! does: one registration, `RUNNER_COUNT` pollers.
//!
//! This is as far as a task goes for now (#520, G2). A fetched task is read and described in the
//! log and not run: turning it into a job is G3, reporting it G4. See `hold`.
const std = @import("std");
const Config = @import("../config.zig").Config;
const loop = @import("../loop.zig");
const sink = @import("../sink.zig");
const redact = @import("../redact.zig");
const logfmt = @import("../logfmt.zig");
const build_version = @import("../version.zig");
const client_mod = @import("client.zig");
const state_mod = @import("state.zig");

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
    c: loop.Runner,
    client: Client,
    pace: Pace,
    tasks_version: std.atomic.Value(i64) = .init(0),

    fn seen(sh: *Shared, version: i64) void {
        var cur = sh.tasks_version.load(.acquire);
        while (version > cur) cur = sh.tasks_version.cmpxchgWeak(cur, version, .acq_rel, .acquire) orelse return;
    }
};

const Slot = struct {
    shared: *Shared,
    index: usize,
    exit: loop.Exit = .done,

    fn main(s: *Slot) void {
        s.exit = s.run();
    }

    /// One runner: asks for a task until it gets one or a stop is requested. Between asks it waits
    /// the pace's interval, longer while there is nothing (or the instance is failing), so a quiet
    /// instance is not asked every 2 s by every runner for ever. A stop is noticed between calls
    /// (a call in flight ends within `Client.deadline`, 10 s at the most); one in flight is not
    /// cut, because the instance may already have given it a task, which the answer would lose.
    fn run(s: *Slot) loop.Exit {
        const sh = s.shared;
        const c = sh.c;
        var arena_state: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena_state.deinit();
        var streak: u32 = 0;
        while (!loop.stopRequested()) {
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();
            var failure: Failure = .{};
            const sent = sh.tasks_version.load(.acquire);
            if (sh.client.fetchTask(arena, c.io, sent, &failure)) |f| {
                sh.seen(f.tasks_version);
                if (f.additional > 0) s.tell(arena, "runner {d}: the instance also sent {d} " ++
                    "additional task(s), which are not used (one task is asked for)", .{ s.index, f.additional });
                if (f.task) |t| return s.hold(arena, t);
                // A newer version means tasks may have been made: ask again soon.
                streak = if (f.tasks_version > sent) 0 else streak +| 1;
            } else |e| switch (e) {
                error.Unauthenticated => {
                    s.tell(arena, "error: kind=gitea_runner_unknown runner={d} http={d} code={f} message={f} " ++
                        "action=\"remove its saved registration and register again with " ++
                        "RUNNER_GITEA_REGISTRATION_TOKEN\"", .{
                        s.index,
                        @backingInt(failure.status),
                        logfmt.q(failure.code),
                        logfmt.q(failure.message),
                    });
                    return .github;
                },
                else => {
                    streak +|= 1;
                    s.tell(arena, "warn: kind=gitea_fetch_failed runner={d} err={s} message={f} retry_ms={d}", .{
                        s.index,
                        @errorName(e),
                        logfmt.q(failure.message),
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

    /// What becomes of a task this build fetches but cannot run. The instance has already given
    /// it to this runner, and nothing here can report it (G4), so it is left to the instance's
    /// zombie timeout, which fails it. The runner takes no second one: each further fetch would
    /// strand another job of someone's, and a queue of them would all fail one after another. It
    /// waits for the stop without asking again.
    fn hold(s: *Slot, arena: Allocator, t: client_mod.Task) loop.Exit {
        const c = s.shared.c;
        const what = t.describe(arena) catch |e| std.fmt.allocPrint(arena, "task {d} ({s})", .{ t.id, @errorName(e) }) catch "a task";
        s.tell(arena, "runner {d}: fetched {s}", .{ s.index, what });
        s.tell(arena, "warn: kind=gitea_task_not_run runner={d} task={d} reason=fetch_only " ++
            "action=no_more_tasks_until_restart", .{ s.index, t.id });
        while (!loop.stopRequested()) sleepOrStop(c.io, 1000);
        return .done;
    }

    /// A line in the log; one that cannot be written is no reason to stop fetching.
    fn tell(s: *Slot, arena: Allocator, comptime fmt: []const u8, args: anytype) void {
        const text = std.fmt.allocPrint(arena, fmt, args) catch return;
        s.shared.c.log.say(text) catch |e| std.log.warn("gitea: log: {s}", .{@errorName(e)});
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
    try c.log.say(
        "warn: kind=gitea_tasks_not_run reason=fetch_only issue=520 " ++
            "effect=\"a task it takes is logged, left unreported, and failed by the instance " ++
            "after its zombie timeout\"",
    );
    const creds = switch (try connect(c)) {
        .ok => |st| st,
        .exit => |code| return code,
    };
    // Redacted in everything the runner writes from here on.
    var all: std.ArrayList([]const u8) = .empty;
    try all.appendSlice(c.arena, c.secrets);
    try all.append(c.arena, creds.token);
    c.log.setSecrets(try redact.expand(c.arena, all.items));

    var shared: Shared = .{
        .c = c,
        .client = .{ .url = cfg.gitea_url, .flavor = flavorOf(cfg), .uuid = creds.uuid, .token = creds.token },
        .pace = .{
            .interval_ms = cfg.gitea_fetch_interval_secs *| 1000,
            .max_ms = cfg.gitea_fetch_interval_max_secs *| 1000,
        },
    };
    const slots = try c.arena.alloc(Slot, n);
    var group: std.Io.Group = .init;
    for (slots, 0..) |*s, i| {
        s.* = .{ .shared = &shared, .index = i };
        group.concurrent(c.io, Slot.main, .{s}) catch |e| {
            try logfmt.line(c.err, .err, "runners_not_started", "n={d} err={t}", .{ n, e });
            group.cancel(c.io);
            return .config;
        };
    }
    group.await(c.io) catch |e| std.log.warn("gitea: {s}", .{@errorName(e)});
    var worst: loop.Exit = .done;
    for (slots) |s| if (@backingInt(s.exit) > @backingInt(worst)) {
        worst = s.exit;
    };
    return worst;
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
        try logfmt.line(c.err, .err, "config", "what=saved_registration_unreadable path={f}/{f} err={t}", .{
            logfmt.q(dir), logfmt.q(file), e,
        });
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
        try logfmt.line(c.err, .err, "config", "what=no_registration path={f}/{f} missing=RUNNER_GITEA_REGISTRATION_TOKEN", .{
            logfmt.q(dir), logfmt.q(file),
        });
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
        var buf: [512]u8 = undefined;
        try c.log.say(logfmt.bufLine(&buf, .warn, "gitea_registration_not_saved", "path={f}/{f} err={t}", .{
            logfmt.q(dir), logfmt.q(file), e,
        }));
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
        error.Unauthenticated, error.Rejected => try logfmt.line(c.err, .err, "gitea_call_failed", "what={f} http={d} code={f} message={f}", .{
            logfmt.q(what), @backingInt(failure.status), logfmt.q(failure.code), logfmt.q(failure.message),
        }),
        else => try logfmt.line(c.err, .err, "gitea_call_failed", "what={f} url={f} err={t}", .{
            logfmt.q(what), logfmt.q(c.cfg.gitea_url), e,
        }),
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
        const state = try r.dir.dir.realPathFileAlloc(std.testing.io, ".", r.arena.allocator());
        try r.env.put("RUNNER_PLATFORM", platform);
        try r.env.put("RUNNER_GITEA_URL", r.server.url(&r.url_buf));
        try r.env.put("RUNNER_GITEA_REGISTRATION_TOKEN", "registration-secret");
        try r.env.put("RUNNER_GITEA_FETCH_INTERVAL", "1");
        try r.env.put("RUNNER_STATE_DIR", state);
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

test "a pool registers once, keeps the registration, fetches, and holds the task it cannot run" {
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
    try s.reply("FetchTask", "200 OK", @embedFile("testdata/fetch-task.json"));
    try std.testing.expectEqual(loop.Exit.done, try r.runUntil(3));

    // The task is described by names, and held: no fourth fetch.
    try std.testing.expectEqual(@as(usize, 3), s.count("FetchTask"));
    const log = r.out.written();
    try std.testing.expect(std.mem.indexOf(u8, log, "registered runner 'zig-ab' (id 7)") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "kind=gitea_fetch_failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "fetched task 1: workflow \"probe\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "kind=gitea_task_not_run") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, r.out.written(), "kind=gitea_runner_unknown") != null);
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
