//! A Gitea or Forgejo task, run and reported (#520, G4): the task becomes a job (`job.zig`), the job
//! runs through the same steps as a GitHub job (`loop/job.zig`: the memory gate, the trust
//! decision, the backend, the step cache), and what happens is reported as it does (`report.zig`).
//!
//! What GitHub's `handleJob` does for itself and this does not: acquire (the instance handed the
//! task over already), the hold's renewal and the cancel watch on the session (`UpdateTask` is the
//! heartbeat and the cancel), the live feed and the results service (the instance takes rows),
//! completejob (the final `UpdateTask`) and the run-state database (a platform's job ids are not
//! GitHub's check-run ids, so these jobs write none: `Runner.store` stays null for them).
//!
//! What GitHub does for the job and the runner does here: the job's `timeout-minutes` (GitHub
//! enforces it by cancelling through the session; here `JobTimeout` cancels through the same
//! ladder), and nothing for `continue-on-error` of the job, which is the instance's to apply to the
//! run: the task's result is what the job did.
const std = @import("std");
const dagger = @import("../dagger.zig");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const redact = @import("../redact.zig");
const Evaluator = @import("../dagger/Evaluator.zig");
const loop = @import("../loop.zig");
const jobs = @import("../loop/job.zig");
const client_mod = @import("client.zig");
const convert = @import("job.zig");
const report = @import("report.zig");
const reach = @import("reach.zig");

const Allocator = std.mem.Allocator;
const Reporter = report.Reporter;

/// GitHub's default `timeout-minutes` of a job, which the instances do not apply to a runner.
pub const default_timeout_minutes = 360;

/// How many minutes the job may run, from its `timeout-minutes` as written (the whole number of
/// them, as GitHub's cast leaves them); `default_timeout_minutes` when it sets none or sets
/// something that is not a positive number. A year at the most, so the sum with the clock cannot
/// overflow.
pub fn timeoutMinutes(written: ?[]const u8) i64 {
    const t = written orelse return default_timeout_minutes;
    const n = std.fmt.parseFloat(f64, std.mem.trim(u8, t, " ")) catch return default_timeout_minutes;
    if (!(n >= 1)) return default_timeout_minutes;
    return @intFromFloat(@trunc(@min(n, 366 * 24 * 60)));
}

/// Cancels the job when it has run for its `timeout-minutes`, as GitHub does through the session:
/// the running step is stopped, `if: always()` steps and post steps get the usual grace, and the
/// job is reported cancelled (GitHub shows a job that timed out cancelled).
pub const JobTimeout = struct {
    io: std.Io,
    log: *sink.LogSink,
    cancel: *dagger.Cancel,
    task_id: i64,
    minutes: i64,
    /// The grace for what still runs after the cancel.
    grace_ms: i64 = jobs.CancelWatch.cancelLimitMs(jobs.CancelWatch.default_grace_ms),
    /// A test counts in less than minutes.
    unit_ms: i64 = std.time.ms_per_min,
    stop: std.atomic.Value(bool) = .init(false),

    pub fn run(w: *JobTimeout) void {
        const started = std.Io.Clock.awake.now(w.io).toMilliseconds();
        const limit_ms = w.minutes *| w.unit_ms;
        while (!w.stop.load(.acquire)) {
            if (std.Io.Clock.awake.now(w.io).toMilliseconds() - started >= limit_ms) break;
            w.io.sleep(.fromMilliseconds(@min(100, @max(1, limit_ms))), .awake) catch return;
        } else return;
        w.cancel.requestBecause(std.Io.Clock.real.now(w.io).toMilliseconds() + w.grace_ms, .job_timeout);
        var buf: [256]u8 = undefined;
        const text = std.fmt.bufPrint(
            &buf,
            "gitea: task {d}: the job ran past its timeout of {d} minute(s); cancelling it " ++
                "({d} s for what still runs)",
            .{ w.task_id, w.minutes, @divTrunc(w.grace_ms, 1000) },
        ) catch return;
        w.log.say(text) catch |e| std.log.warn("gitea: log: {s}", .{@errorName(e)});
    }
};

/// The job's `timeout-minutes` evaluated: an expression (a matrix value, say) is read in the job's
/// own contexts.
fn jobTimeout(arena: Allocator, job: *const job_mod.Job, written: ?job_mod.Template) i64 {
    const t = written orelse return default_timeout_minutes;
    const text: ?[]const u8 = switch (t) {
        .lit => |l| l,
        .expr => text: {
            var ev = Evaluator.init(arena, job) catch break :text null;
            const sc = ev.scope(&.{}) catch break :text null;
            break :text ev.render(t, sc) catch null;
        },
    };
    return timeoutMinutes(text);
}

/// Runs the task the instance handed over and reports it, to its end. Everything it allocates is
/// freed here. A task that cannot be run is reported failed, with why in its log; one that cannot
/// be reported at all is left to the instance's zombie timeout, and said on the runner's console.
pub fn task(c: loop.Runner, client: client_mod.Client, t: client_mod.Task) void {
    var arena_state: std.heap.ArenaAllocator = .init(c.gpa);
    defer arena_state.deinit();
    var cc = c;
    cc.arena = arena_state.allocator();
    runTask(cc, client, t) catch |e| loop.sayUnallocated(
        c,
        "gitea: task {d}: not reported to the end ({s}); the instance fails it after its zombie timeout",
        .{ t.id, @errorName(e) },
    );
}

const noSteps: dagger.Result = .{
    .steps = &.{},
    .engine_error = null,
    .succeeded = false,
    .set_up_failed = true,
};

fn runTask(c: loop.Runner, client: client_mod.Client, t: client_mod.Task) !void {
    // The conversion fails the task, not the runner: a workflow it cannot read is reported to
    // the instance as the job's failure, with the reason in its log.
    var why: []const u8 = "";
    const converted = convert.fromTask(c.arena, t, &why) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.BadWorkflow => return failUnread(c, client, t, why),
    };
    const job = converted.job;

    // Each secret in every form it can take in output.
    var collect: sink.LogSink = .{ .collect = .{ .arena = c.arena, .io = c.io, .inner = c.log } };
    const secrets = try redact.expand(c.arena, try std.mem.concat(c.arena, []const u8, &.{ c.secrets, job.secrets }));
    collect.setSecrets(secrets);

    const names = try c.arena.alloc([]const u8, job.steps.len);
    for (job.steps, names) |s, *n| n.* = s.name;
    var cancel: dagger.Cancel = .{};
    var reporter = try Reporter.init(c.gpa, c.io, client, t.id, c.log, secrets, &cancel, names);
    defer reporter.deinit();
    var pumping: ?std.Io.Future(void) = c.io.concurrent(Reporter.pump, .{&reporter}) catch null;
    defer if (pumping) |*f| {
        reporter.stop.store(true, .release);
        f.cancel(c.io);
    };

    // An error in what follows still ends the task: reported failed, with the error in its log.
    runJob(c, converted, &collect, &reporter, &cancel, &pumping) catch |e| {
        var buf: [160]u8 = undefined;
        reporter.say(std.fmt.bufPrint(&buf, "The runner could not run the task: {s}", .{@errorName(e)}) catch
            "The runner could not run the task");
        if (pumping) |*f| {
            reporter.stop.store(true, .release);
            f.cancel(c.io);
            pumping = null;
        }
        if (!reporter.finished) try reporter.finish(c.arena, .failure, noSteps, &.{});
        return e;
    };
}

/// The job, from its place at the memory gate to its end, reported: the part of `runTask` that
/// has a reporter to tell. `pumping` is ended here before the end's reports are made.
fn runJob(
    c: loop.Runner,
    converted: convert.Converted,
    collect: *sink.LogSink,
    reporter: *Reporter,
    cancel: *dagger.Cancel,
    pumping: *?std.Io.Future(void),
) !void {
    var job = converted.job;
    const t_id = reporter.task_id;
    // A native job reaches the instance its task names (its ROOT_URL, which may not be the address
    // the runner was given), and fetches through the bridge when that is the host's loopback.
    if (c.cfg.backend == .native) {
        const subnet = try @import("../native/net.zig").Subnet.parse(c.cfg.native_subnet);
        if (reach.allow(c.arena, c.io, subnet, job.github.server_url)) |why| loop.sayUnallocated(c, "gitea: task {d}: {s}", .{ t_id, why });
        job = try reach.viewed(c.arena, c.io, subnet, job);
    }
    // Known by name now: it reserves what jobs of its name took at the memory gate, and what it
    // takes is learned when it ends.
    // The process's resources as the job starts, for its `job-end:` line.
    const stats_before = jobs.proc_stats.read();
    const admitted = jobs.Admitted.begin(c, job);
    defer admitted.end();

    collect.collect.listener = reporter.listener();
    defer collect.collect.listener = null;
    const log = collect;
    const spool = try jobs.openSpool(c, job, collect);
    defer if (spool) |sp| sp.close(c.io);

    // The instance's cancel arrives through the pump (`Reporter.reportStateLocked`); the job's
    // own limit and the runner's stop are watched here, and go down the same ladder.
    var timeout: JobTimeout = .{
        .io = c.io,
        .log = c.log,
        .cancel = cancel,
        .task_id = t_id,
        .minutes = jobTimeout(c.arena, &job, converted.timeout_minutes),
    };
    var timing: ?std.Io.Future(void) = c.io.concurrent(JobTimeout.run, .{&timeout}) catch null;
    defer if (timing) |*f| {
        timeout.stop.store(true, .release);
        f.cancel(c.io);
    };
    var deadline: jobs.StopDeadline = .{ .c = c, .cancel = cancel, .log_job = job.check_run_id };
    var stopping: ?std.Io.Future(void) = c.io.concurrent(jobs.StopDeadline.run, .{&deadline}) catch null;
    defer if (stopping) |*f| {
        deadline.stop.store(true, .release);
        f.cancel(c.io);
    };

    try jobs.sayJob(log, c.arena, job, "task {d}: {s}, runner {s}", .{ t_id, jobs.jobName(job), c.name });
    if (c.gate) |gate| try jobs.awaitRoom(c, gate, log, job, cancel);

    // The steps, as a GitHub job's are run: refused or unsupported ones failed in "Set up job".
    const result = if (try jobs.unrunnable(c, job, log)) |failed|
        failed
    else
        try jobs.execute(c, job, log, cancel, reporter.observer());
    // A native job's teardown comes after its result is reported, as for GitHub, and on every
    // path out of here, before the gate lets go of the job.
    defer if (result.teardown) |td| {
        _ = td.run();
    };
    if (result.engine_error) |msg| if (!result.cancelled) {
        try log.append(job.check_run_id, 0, .stderr, "the job could not run before its steps:");
        try log.append(job.check_run_id, 0, .stderr, msg);
    };
    if (result.engine_waited) if (c.warmer) |w| w.request();

    // "Complete job": the job's outputs as the runner logs them, then reported with the result.
    const complete_started = std.Io.Clock.real.now(c.io).toMilliseconds();
    const after_last = std.math.cast(u32, job.steps.len + 1) orelse return error.TooManySteps;
    const complete_step: u32 = if (result.next_log_step > 0) result.next_log_step else after_last;
    reporter.beginComplete(complete_step, complete_started);
    for (result.output_lines) |l| try log.append(job.check_run_id, complete_step, .stdout, l);
    try log.append(job.check_run_id, complete_step, .stdout, "Cleaning up orphan processes");
    try log.flush();
    try reporter.setOutputs(result.outputs);
    try jobs.reportCacheAndKeys(c, job, log, result);

    // The pump ends first: the end's reports are the only ones from here.
    if (pumping.*) |*f| {
        reporter.stop.store(true, .release);
        f.cancel(c.io);
        pumping.* = null;
    }
    const outcome = report.jobResult(result);
    try reporter.finish(c.arena, outcome, result, result.summaries);
    loop.sayUnallocated(c, "gitea: task {d} '{s}' {s}", .{ t_id, jobs.jobName(job), @tagName(outcome) });
    // The result is with the instance: the teardown can go, and the job's end is told.
    if (result.teardown) |td| if (td.run()) |p| try c.err.print("job {d} '{s}': native phases (ms): {s}\n", .{
        job.check_run_id,
        jobs.jobName(job),
        p,
    });
    jobs.sayJobEnd(c, job, stats_before);
}

/// A workflow the runner cannot read: the task fails with the reason, which is all the log holds.
fn failUnread(c: loop.Runner, client: client_mod.Client, t: client_mod.Task, why: []const u8) !void {
    var cancel: dagger.Cancel = .{};
    const secrets = try redact.expand(c.arena, c.secrets);
    var r = try Reporter.init(c.gpa, c.io, client, t.id, c.log, secrets, &cancel, &.{});
    defer r.deinit();
    r.say(why);
    try r.finish(c.arena, .failure, noSteps, &.{});
    loop.sayUnallocated(c, "gitea: task {d} is not a job this runner can run ({s}); reported failed", .{ t.id, why });
}

test "a job's timeout is its whole minutes, and 360 when it says none or nonsense" {
    try std.testing.expectEqual(@as(i64, 360), timeoutMinutes(null));
    try std.testing.expectEqual(@as(i64, 5), timeoutMinutes("5"));
    try std.testing.expectEqual(@as(i64, 1), timeoutMinutes(" 1.9 "));
    try std.testing.expectEqual(@as(i64, 360), timeoutMinutes("0"));
    try std.testing.expectEqual(@as(i64, 360), timeoutMinutes("-3"));
    try std.testing.expectEqual(@as(i64, 360), timeoutMinutes("soon"));
    try std.testing.expectEqual(@as(i64, 360), timeoutMinutes("nan"));
    try std.testing.expectEqual(@as(i64, 366 * 24 * 60), timeoutMinutes("1e12"));
}

test "a job past its timeout is cancelled as a timeout, with a grace; one that ended first is not" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out.writer } };
    var cancel: dagger.Cancel = .{};
    var w: JobTimeout = .{ .io = std.testing.io, .log = &log, .cancel = &cancel, .task_id = 3, .minutes = 30, .unit_ms = 1 };
    w.run();
    try std.testing.expect(cancel.requested.load(.acquire));
    try std.testing.expectEqual(dagger.Cancel.Why.job_timeout, cancel.why.load(.acquire));
    try std.testing.expect(cancel.hard_deadline_ms.load(.acquire) > std.Io.Clock.real.now(std.testing.io).toMilliseconds());
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "ran past its timeout of 30 minute(s)") != null);

    var other: dagger.Cancel = .{};
    var done: JobTimeout = .{ .io = std.testing.io, .log = &log, .cancel = &other, .task_id = 4, .minutes = 60, .unit_ms = 60_000 };
    done.stop.store(true, .release);
    done.run();
    try std.testing.expect(!other.requested.load(.acquire));
}

test "a cancel from the instance reaches a running job through the pump's heartbeat" {
    const testserver = @import("testserver.zig");
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    server.echo_acks = true;
    try server.reply("UpdateTask", "200 OK", "{\"state\":{}}");
    try server.reply("UpdateTask", "200 OK", "{\"state\":{\"result\":\"RESULT_CANCELLED\"}}");
    try server.replyAlways("UpdateTask", "200 OK", "{\"state\":{\"result\":\"RESULT_CANCELLED\"}}");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out.writer } };
    var cancel: dagger.Cancel = .{};
    var buf: [64]u8 = undefined;
    const client: client_mod.Client = .{ .url = server.url(&buf), .deadline = .fromSeconds(5) };
    var r = try Reporter.init(std.testing.allocator, std.testing.io, client, 9, &log, &.{}, &cancel, &.{});
    defer r.deinit();
    r.interval_ms = 50;
    var pumping = try std.testing.io.concurrent(Reporter.pump, .{&r});
    var waited: u32 = 0;
    while (!cancel.requested.load(.acquire) and waited < 200) : (waited += 1)
        try std.testing.io.sleep(.fromMilliseconds(25), .awake);
    r.stop.store(true, .release);
    pumping.cancel(std.testing.io);
    try std.testing.expect(cancel.requested.load(.acquire));
    // No result was sent while the job ran: the heartbeat carries none.
    try std.testing.expect(std.mem.indexOf(u8, server.nth("UpdateTask", 0).body, "\"result\"") == null);
}
