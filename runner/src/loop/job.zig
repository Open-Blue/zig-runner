//! One job, from acquire to completejob: the job's log and spool, its run through Dagger, the
//! run state in the database, and what watches it meanwhile (the hold renewer, the cancel watch
//! and the stop deadline).

const std = @import("std");
const Config = @import("../config.zig").Config;
const auth = @import("../github/auth.zig");
const broker = @import("../github/broker.zig");
const runservice = @import("../github/runservice.zig");
const job_mod = @import("../job.zig");
const trust = @import("../trust.zig");
const dagger = @import("../dagger.zig");
const zig_release = @import("../zig_release.zig");
const db = @import("../db.zig");
const sink = @import("../sink.zig");
const redact = @import("../redact.zig");
const timefmt = @import("../timefmt.zig");
const Live = @import("../live.zig").Live;
const admission = @import("../admission.zig");
const upload = @import("upload.zig");
const Runner = @import("../loop.zig").Runner;
const Cycle = @import("../loop.zig").Cycle;
const Registering = @import("../loop.zig").Registering;
const stopRequested = @import("../loop.zig").stopRequested;
const stop_signals = &@import("../loop.zig").stop_signals;
const say = @import("../loop.zig").say;
const sayUnallocated = @import("../loop.zig").sayUnallocated;
const token_refresh_secs = @import("../loop.zig").token_refresh_secs;
const poll_timeout = @import("../loop.zig").poll_timeout;
const mintToken = @import("../loop.zig").mintToken;
const jsonString = @import("../loop.zig").jsonString;
const fail = @import("../loop.zig").fail;
const failBody = @import("../loop.zig").failBody;
const testRunner = @import("../loop.zig").testRunner;

const Allocator = std.mem.Allocator;

/// Writes run state at the transitions SPEC §5.2 names: job start, step start, step end, job end.
/// Database errors are counted and reported at the end; they never fail the job.
const Reporter = struct {
    store: *db.Store,
    arena: Allocator,
    io: std.Io,
    job_id: u64,
    run_id: u64,
    /// A write that fails is not reported where it is made (`catch {}` below): the store counts
    /// it, since with its writer a row fails after the call that queued it has returned, and
    /// `finishReporter` reports how many failed since this count, taken when the job started.
    failed_before: u64 = 0,

    fn observer(r: *Reporter) dagger.Observer {
        return .{ .ptr = r, .startedFn = stepStartedFn, .finishedFn = stepFinishedFn };
    }

    fn iso(r: *Reporter, ms: i64) ?[]const u8 {
        if (ms <= 0) return null;
        return timefmt.isoTime(r.arena, ms) catch null;
    }

    /// Writes that failed since the job started (any runner's: they share the database).
    fn failures(r: *Reporter) u64 {
        return r.store.failed.load(.monotonic) -| r.failed_before;
    }

    fn stepStartedFn(ptr: *anyopaque, number: u32, name: []const u8, started_ms: i64) void {
        const r: *Reporter = @ptrCast(@alignCast(ptr));
        r.store.upsertStep(.{
            .job_id = r.job_id,
            .number = number,
            .name = name,
            .status = "in_progress",
            .started_at = r.iso(started_ms),
        }) catch {};
    }

    fn stepFinishedFn(ptr: *anyopaque, number: u32, res: dagger.StepResult) void {
        const r: *Reporter = @ptrCast(@alignCast(ptr));
        r.store.upsertStep(.{
            .job_id = r.job_id,
            .number = number,
            .name = res.name,
            .status = "completed",
            .conclusion = stepConclusion(res),
            .started_at = r.iso(res.started_ms),
            .completed_at = r.iso(res.completed_ms),
        }) catch {};
    }

    fn jobStarted(r: *Reporter, job: job_mod.Job, runner_name: []const u8, now_ms: i64) void {
        const g = job.github;
        r.store.upsertRun(.{
            .id = r.run_id,
            .repo = g.repository,
            .workflow = if (g.workflow.len > 0) g.workflow else "(unknown)",
            .event = nonEmpty(g.event_name),
            .branch = nonEmpty(g.ref_name),
            .sha = nonEmpty(g.sha),
            .status = "in_progress",
        }) catch {};
        r.store.upsertJob(.{
            .id = r.job_id,
            .run_id = r.run_id,
            .name = jobName(job),
            .runner_name = runner_name,
            .status = "in_progress",
            .started_at = r.iso(now_ms),
        }) catch {};
        // Step 0 is "Set up job" (db/migrations/001_init.sql): registration, acquiring and parsing.
        r.store.upsertStep(.{
            .job_id = r.job_id,
            .number = 0,
            .name = "Set up job",
            .status = "completed",
            .conclusion = "success",
            .started_at = r.iso(now_ms),
            .completed_at = r.iso(now_ms),
        }) catch {};
    }

    /// "Set up job" failed after all: the job failed before its steps (refused, unsupported, or an
    /// action that could not be resolved). `jobStarted` recorded it as a success, as it is for
    /// every job that reaches its steps; GitHub shows it failed, and so must the database.
    fn setUpFailed(r: *Reporter, started_ms: i64, now_ms: i64) void {
        r.store.upsertStep(.{
            .job_id = r.job_id,
            .number = 0,
            .name = "Set up job",
            .status = "completed",
            .conclusion = "failure",
            .started_at = r.iso(started_ms),
            .completed_at = r.iso(now_ms),
        }) catch {};
    }

    fn jobFinished(
        r: *Reporter,
        job: job_mod.Job,
        runner_name: []const u8,
        conclusion: []const u8,
        started_ms: i64,
        now_ms: i64,
    ) void {
        r.store.upsertJob(.{
            .id = r.job_id,
            .run_id = r.run_id,
            .name = jobName(job),
            .runner_name = runner_name,
            .status = "completed",
            .conclusion = conclusion,
            .started_at = r.iso(started_ms),
            .completed_at = r.iso(now_ms),
        }) catch {};
        // One runner handles one job, so the run's state follows this job (SPEC §5.2).
        const g = job.github;
        r.store.upsertRun(.{
            .id = r.run_id,
            .repo = g.repository,
            .workflow = if (g.workflow.len > 0) g.workflow else "(unknown)",
            .event = nonEmpty(g.event_name),
            .branch = nonEmpty(g.ref_name),
            .sha = nonEmpty(g.sha),
            .status = "completed",
            .conclusion = conclusion,
            .completed_at = r.iso(now_ms),
        }) catch {};
    }
};

fn nonEmpty(s: []const u8) ?[]const u8 {
    return if (s.len == 0) null else s;
}

fn jobName(job: job_mod.Job) []const u8 {
    if (job.display_name.len > 0) return job.display_name;
    if (job.github.job.len > 0) return job.github.job;
    return "job";
}

/// Same vocabulary as the DB's `steps.conclusion`: success | failure | cancelled | skipped.
fn stepConclusion(res: dagger.StepResult) []const u8 {
    return switch (res.outcome) {
        .success => "success",
        .failure => if (res.continued) "success" else "failure",
        .cancelled => "cancelled",
        .skipped, .not_run => "skipped",
    };
}

/// The runner's session, kept listening while a job runs (see `CancelWatch`).
const Listening = struct {
    creds: auth.Credentials,
    token: []const u8,
    token_at: i64,
    /// The broker's message URL, with the runner `Busy`.
    url: []const u8,
};

/// Whether `repo`'s jobs have spent too long on output keys lately (see `SlowOutputs`).
fn slowOutputs(c: Runner, repo: []const u8) bool {
    const so = c.slow_outputs orelse return false;
    return so.spent(repo) != null;
}

/// Waits before each further acquire, in milliseconds: 15.5 s in all.
const acquire_retry_ms = [_]i64{ 500, 1000, 2000, 4000, 8000 };

/// Acquires the job, trying again while the request fails or GitHub answers 5xx. A job whose
/// acquire failed stays assigned to this runner until GitHub gives it to another, about 70 s later:
/// three jobs whose acquires failed at once with HostUnreachable started 72 s after the rest.
fn acquire(
    c: Runner,
    jr: runservice.JobRequest,
    token: []const u8,
    retry_ms: []const i64,
) !broker.Response {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        const last = attempt == retry_ms.len or stopRequested();
        if (runservice.acquire(c.arena, c.io, jr, token)) |r| {
            if (last or r.status.class() != .server_error) return r;
            try say(c, "'{s}': acquirejob answered HTTP {d}; trying again", .{
                c.name,
                @backingInt(r.status),
            });
        } else |e| {
            if (last or e == error.OutOfMemory) return e;
            try say(c, "'{s}': acquirejob failed ({s}); trying again", .{ c.name, @errorName(e) });
        }
        c.io.sleep(.fromMilliseconds(retry_ms[attempt]), .awake) catch {};
    }
}

pub fn handleJob(c: Runner, session: Listening, body: []const u8) !Cycle {
    const runner_token = session.token;
    const jr = runservice.parseJobRequest(c.arena, body) catch |e| return fail(c, "job request", e);
    const acq = acquire(c, jr, runner_token, &acquire_retry_ms) catch |e|
        return fail(c, "acquirejob", e);
    if (acq.status.class() != .success) return failBody(c, "acquirejob", acq);

    // The definition holds secrets; it is parsed but never printed.
    const job = job_mod.parse(c.arena, acq.body) catch |e| return fail(c, "parse job", e);
    // Known by name now: it reserves what jobs of its name took (`admission.Learned`), and what it
    // takes is learned when it ends.
    const job_name = if (job.display_name.len > 0) job.display_name else job.github.job;
    const g = job.github;
    if (c.gate) |gate| gate.assigned(admission.jobKey(g.repository, g.workflow_ref, job_name));
    defer if (c.gate) |gate| if (gate.ended()) |learned| sayUnallocated(
        c,
        "job '{s}' raised the engine's memory by {f} at most ({s}); reserving {f} for it while " ++
            "it starts",
        .{
            job_name,
            admission.gb(learned.seen_mb),
            if (learned.alone) "alone" else "beside other jobs",
            admission.gb(learned.estimate_mb),
        },
    );

    // GitHub cancels a job (in its UI, or at the job's timeout-minutes) through the runner's
    // session.
    var cancel: dagger.Cancel = .{};
    // Keep the hold on the job while it runs, as GitHub's runner does (see `Renewer`).
    var renewer = Renewer.init(c, job, jr, &cancel);
    var renewing: ?std.Io.Future(void) = c.io.concurrent(Renewer.run, .{&renewer}) catch null;
    // Cancelled rather than waited for: it sleeps in 50 ms steps, and the job's end (and the
    // runner's next session) waited out the rest of one, 25 ms a job on average.
    defer if (renewing) |*f| {
        renewer.stop.store(true, .release);
        f.cancel(c.io);
    };
    var watcher = CancelWatch.init(c, session, job, &cancel);
    var watching: ?std.Io.Future(void) = c.io.concurrent(CancelWatch.run, .{&watcher}) catch null;
    defer if (watching) |*f| {
        watcher.stop.store(true, .release);
        f.cancel(c.io);
    };
    // The runner stopping cancels the job too, once it has had its time to finish.
    var deadline: StopDeadline = .{ .c = c, .cancel = &cancel, .log_job = job.check_run_id };
    var stopping: ?std.Io.Future(void) = c.io.concurrent(StopDeadline.run, .{&deadline}) catch
        null;
    defer if (stopping) |*f| {
        deadline.stop.store(true, .release);
        f.cancel(c.io);
    };
    // Everything the job logs is also kept (redacted, timestamped) so it can be uploaded to GitHub.
    var collect: sink.LogSink = .{ .collect = .{ .arena = c.arena, .io = c.io, .inner = c.log } };
    // Each secret in every form it can take in output (redact.forms): a multi-line one line by line.
    collect.setSecrets(try redact.expand(c.arena, try std.mem.concat(c.arena, []const u8, &.{ c.secrets, job.secrets })));
    const log = &collect;
    const spool = try openSpool(c, job, &collect);
    defer if (spool) |sp| sp.close(c.io);
    // The job, live in GitHub's UI: its steps as they run and their lines as they are logged.
    var live = try Live.init(c.gpa, c.arena, c.io, &job, c.log);
    collect.collect.listener = live.listener();
    live.start(std.Io.Clock.real.now(c.io).toMilliseconds());
    var live_done = false;
    defer if (!live_done) {
        collect.collect.listener = null;
        live.finish(&.{});
    };
    // Each step's log goes up as the step finishes; lines and step events go on to the live view.
    var step_logs = try upload.StepLogs.init(c.gpa, c.io, &job, live.ids, live.listener(), live.observer());
    collect.collect.listener = step_logs.listener();
    defer {
        collect.collect.listener = null;
        step_logs.deinit();
    }
    // For the runner's own console and database only: the job's log starts as GitHub's does.
    try sayJob(c.log, c.arena, job, "job acquired: {d} steps", .{job.steps.len});

    const job_started_ms = std.Io.Clock.real.now(c.io).toMilliseconds();
    var reporter = try startReporter(c, job, job_started_ms);
    const result = try runJobSteps(c, job, log, &cancel, &live, &step_logs, if (reporter) |*r| r else null);
    // The engine was starting when this job opened its session, so its cache may have been
    // wiped: warmed again for the next job.
    if (result.engine_waited) if (c.warmer) |w| w.request();
    // The steps are done: register the next runner, and open its session, while this job is
    // wrapped up.
    if (c.next) |slot| if (slot.* == null and !stopRequested()) {
        slot.* = Registering.start(c) catch null;
    };

    const completion = try logCompleteJob(c, job, log, &live, result, job_started_ms);
    if (reporter) |*r| {
        try finishReporter(c, r, job, result, job_started_ms);
    }
    try reportCacheAndKeys(c, job, log, result);
    const shown = try upload.shownSteps(c.arena, live.ids, job, result, job_started_ms, completion);
    const kept = log.collect.kept();
    {
        // The live view ends with the steps as completejob reports them, while the logs go up:
        // its last requests (the lines left, the final step list) and the uploads are
        // independent, as GitHub's runner sends its timeline and its logs from queues of their
        // own, and both are done before completejob. One after the other, the job's end waited
        // for both.
        const finals = try liveFinals(c.arena, shown);
        live_done = true;
        collect.collect.listener = null;
        var finishing: ?std.Io.Future(void) = c.io.concurrent(Live.finish, .{ &live, finals }) catch
            null;
        defer if (finishing) |*f| f.await(c.io);
        if (finishing == null) live.finish(finals);
        try upload.logs(c, job, shown, &kept, result.summaries, log.currentSecrets(), &step_logs, .{});
    }

    const conclusion = jobConclusion(result);
    if (try completeJobWithRetry(c, jr, job, conclusion, shown, result, log.currentSecrets())) |failed| return failed;
    try sayJob(log, c.arena, job, "job {s}", .{@tagName(conclusion)});
    return .{ .job = result.succeeded };
}

/// A line in the job's log, under its "Set up job" step, as `std.fmt` writes it.
fn sayJob(
    log: *sink.LogSink,
    arena: Allocator,
    job: job_mod.Job,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    try log.append(job.check_run_id, 0, .stdout, try std.fmt.allocPrint(arena, fmt, args));
}

/// The run-state rows at the job's end, and a note when any of its writes failed.
fn finishReporter(
    c: Runner,
    r: *Reporter,
    job: job_mod.Job,
    result: dagger.Result,
    job_started_ms: i64,
) !void {
    const ended_ms = std.Io.Clock.real.now(c.io).toMilliseconds();
    recordFinished(r, job, c.name, result, job_started_ms, ended_ms);
    const failed = r.failures();
    if (failed > 0) try c.err.print(
        "run state: {d} database write(s) failed while this job ran (last: {s})\n",
        .{ failed, r.store.lastError(c.arena) },
    );
}

/// The job's end in the run-state database: its conclusion, and "Set up job" failed when the job
/// failed before its steps.
fn recordFinished(
    r: *Reporter,
    job: job_mod.Job,
    runner_name: []const u8,
    result: dagger.Result,
    started_ms: i64,
    ended_ms: i64,
) void {
    if (result.set_up_failed) r.setUpFailed(started_ms, ended_ms);
    r.jobFinished(job, runner_name, reporterConclusion(result), started_ms, ended_ms);
}

test "integration: a job failed before its steps is recorded with Set up job failed" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var sc = try @import("../dbtest.zig").Scratch.create(arena);
    defer sc.destroy();
    var store = try db.Store.open(std.testing.allocator, std.testing.io, sc.cfg, sc.schema);
    defer store.close();

    const job: job_mod.Job = .{
        .plan_id = "p",
        .job_id = "j",
        .job_token = "t",
        .check_run_id = 7,
        .secrets = &.{},
        .steps = &.{},
        .github = .{ .repository = "o/r", .run_id = "42", .workflow = "ci", .event_name = "pull_request" },
    };
    var r: Reporter = .{ .store = &store, .arena = arena, .io = std.testing.io, .job_id = 7, .run_id = 42 };
    const started: i64 = 1_760_000_000_000;
    r.jobStarted(job, "zig-1", started);
    // Recorded as a success when the job starts, as for every job that reaches its steps.
    try std.testing.expectEqualStrings("success", try sc.scalar("select conclusion from steps where job_id = 7 and number = 0"));

    recordFinished(&r, job, "zig-1", try failedInSetUp(arena, 0), started, started + 500);
    try std.testing.expectEqual(@as(u64, 0), r.failures());
    try std.testing.expectEqualStrings("failure", try sc.scalar("select conclusion from steps where job_id = 7 and number = 0"));
    try std.testing.expectEqualStrings("completed/failure", try sc.scalar("select status || '/' || conclusion from jobs where id = 7"));
}

/// What completejob is told: cancelled first, then whether every step that had to succeed did.
fn jobConclusion(result: dagger.Result) runservice.Conclusion {
    if (result.cancelled) return .canceled;
    if (result.succeeded) return .succeeded;
    return .failed;
}

/// The job's log on disk while it runs, rather than in memory until it ends: it is then bounded by
/// the spool and survives the process (see `sink.Spool`). Best effort — a file the runner cannot
/// make is said once and the lines stay in memory, because logging must not fail a job. Null when
/// the runner has no spool directory (`SpoolDir`) or the file could not be made. It lives on the
/// cycle's arena so the collector can be pointed at it here, where it cannot be forgotten: the
/// first extraction of handleJob dropped that one line, and only an unused-parameter error caught
/// it.
const JobSpool = struct {
    spool: sink.Spool,
    dir: std.Io.Dir,
    /// The file's name in `dir`.
    name: []const u8,

    fn close(sp: *JobSpool, io: std.Io) void {
        sp.spool.file.close(io);
        sp.dir.deleteFile(io, sp.name) catch {};
    }
};

fn openSpool(c: Runner, job: job_mod.Job, collect: *sink.LogSink) !?*JobSpool {
    const sd = c.spool_dir orelse return null;
    const name = std.fmt.allocPrint(c.arena, "zig-runner-job-{d}.log", .{job.check_run_id}) catch
        return null;
    // Created, never opened: whatever is already at the name, a symlink planted there included, is
    // refused rather than followed or written through (#106). Readable by the runner's user alone,
    // like the directory it is in.
    const file = sd.dir.createFile(c.io, name, .{
        .read = true,
        .exclusive = true,
        .permissions = .fromMode(0o600),
    }) catch |e| {
        try c.err.print(
            "job {d}: no log spool in {s} ({s}); the job's log is kept in memory\n",
            .{ job.check_run_id, sd.path, @errorName(e) },
        );
        return null;
    };
    const js = try c.arena.create(JobSpool);
    js.* = .{ .spool = .{ .file = file, .io = c.io }, .dir = sd.dir, .name = name };
    collect.collect.spool = &js.spool;
    return js;
}

/// The runner's own directory for its jobs' logs, `<log_spool_dir>/zig-runner-<uid>`, made once
/// when the pool starts. A shared /tmp is anyone's to write in: a log file made there by name could
/// be a link someone else planted, or be read by them (#106). The systemd unit's `PrivateTmp`
/// gives the runner a /tmp of its own; this makes running it by hand as safe. A directory already
/// there is used only if it is a directory (not a link to one), owned by the runner's user and
/// closed to everyone else. It is held open, so the files go in the directory that was checked
/// whatever later happens to its path.
pub const SpoolDir = struct {
    dir: std.Io.Dir,
    path: []const u8,

    pub fn open(arena: Allocator, io: std.Io, base: []const u8) !SpoolDir {
        const uid = std.os.linux.geteuid();
        const path = try std.fmt.allocPrint(arena, "{s}/zig-runner-{d}", .{ base, uid });
        std.Io.Dir.cwd().createDir(io, path, .fromMode(0o700)) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
        // A link is not followed: opening one fails here rather than opening its target.
        const dir = try std.Io.Dir.cwd().openDir(io, path, .{ .follow_symlinks = false });
        errdefer dir.close(io);
        try checkPrivate(dir, uid);
        return .{ .dir = dir, .path = path };
    }

    pub fn close(sd: SpoolDir, io: std.Io) void {
        sd.dir.close(io);
    }

    /// Asked of the open directory, not its path, so what is checked is what the files go in.
    fn checkPrivate(
        dir: std.Io.Dir,
        uid: std.os.linux.uid_t,
    ) error{ SpoolDirUnchecked, SpoolDirNotOurs, SpoolDirNotPrivate }!void {
        const linux = std.os.linux;
        var st: linux.Statx = undefined;
        const rc = linux.statx(
            dir.handle,
            "",
            linux.AT.EMPTY_PATH,
            .{ .TYPE = true, .MODE = true, .UID = true },
            &st,
        );
        if (linux.errno(rc) != .SUCCESS) return error.SpoolDirUnchecked;
        if (!st.mask.TYPE or !st.mask.MODE or !st.mask.UID) return error.SpoolDirUnchecked;
        if (st.uid != uid) return error.SpoolDirNotOurs;
        if (st.mode & linux.S.IFMT != linux.S.IFDIR) return error.SpoolDirNotOurs;
        if (st.mode & 0o777 != 0o700) return error.SpoolDirNotPrivate;
    }
};

/// The job's conclusion as the run-state database records it.
fn reporterConclusion(result: dagger.Result) []const u8 {
    if (result.cancelled) return "cancelled";
    return if (result.succeeded) "success" else "failure";
}

/// Run state in the database, when there is one and the job can be identified. The reporter is
/// returned by value and the caller keeps it, because the spool pointer into `collect` is set here.
fn startReporter(c: Runner, job: job_mod.Job, job_started_ms: i64) !?Reporter {
    const st = c.store orelse return null;
    const run_id = std.fmt.parseInt(u64, job.github.run_id, 10) catch 0;
    if (run_id == 0 or job.check_run_id == 0) {
        try c.err.writeAll("run state not recorded: the job has no run id or job id\n");
        return null;
    }
    var reporter: Reporter = .{
        .store = st,
        .arena = c.arena,
        .io = c.io,
        .job_id = job.check_run_id,
        .run_id = run_id,
        .failed_before = st.failed.load(.monotonic),
    };
    reporter.jobStarted(job, c.name, job_started_ms);
    return reporter;
}

/// The steps, through Dagger — or failed up front: a job this runner does not trust
/// (`trust.zig`), or one whose `container:` or `services:` it does not support, rather than run
/// in ways that would fail confusingly without them.
fn runJobSteps(
    c: Runner,
    job: job_mod.Job,
    log: *sink.LogSink,
    cancel: *dagger.Cancel,
    live: *Live,
    /// Told of the steps first; passes them on to `live`.
    step_logs: *upload.StepLogs,
    reporter: ?*Reporter,
) !dagger.Result {
    const cfg = c.cfg;
    const refused = try trust.refusal(c.arena, cfg.trusted_refs, cfg.trusted_events, job.github);
    if (refused) |why| try c.err.print("job refused: {s}\n", .{why});
    const unsupported: ?[]const u8 = refused orelse job.container_error orelse job.services_error;
    if (unsupported) |why| {
        try log.append(job.check_run_id, 0, .stderr, why);
        return failedInSetUp(c.arena, job.steps.len);
    }
    const zig_seeds: zig_release.Resolved = if (cfg.zig_seed_registry) |r|
        try r.forJob(c.arena)
    else
        .{ .seeds = cfg.zig_seeds, .unverified = cfg.zig_seeds_unverified };
    var native = try dagger.Backend.configFor(
        c.arena,
        c.io,
        c.environ,
        cfg,
        trust.vouches(cfg.trusted_refs, cfg.trusted_events, job.github),
    );
    // A native job is measured in its own cgroup (`admission.Gate.native`).
    if (native) |*n| n.gate = c.gate;
    var result = try dagger.run(c.arena, c.io, c.environ, .{
        .dagger_cmd = c.cfg.dagger_cmd,
        .image = c.cfg.image,
        .js_runtime = c.cfg.js_runtime,
        .engine = c.cfg.engineEndpoint(),
        .gpa = c.gpa,
        .nesting = c.cfg.dagger_nesting,
        .package_caches = c.cfg.package_caches,
        // The same rule as the gate above, without its `*`: a runner that lets every job through
        // vouches for none, so none of its jobs share the trusted jobs' caches (#105).
        .trusted = trust.vouches(cfg.trusted_refs, cfg.trusted_events, job.github),
        .uv_env_in_cache = c.cfg.uv_env_in_cache,
        .zig_local_cache = c.cfg.zig_local_cache,
        .zig_local_cache_max_mb = c.cfg.zig_local_cache_max_mb,
        .zig_seeds = zig_seeds.seeds,
        .zig_seeds_unverified = zig_seeds.unverified,
        .zig_seed_registry = cfg.zig_seed_registry,
        .step_cache = c.cfg.step_cache,
        .step_user = c.cfg.step_user,
        // Skipped for a repository whose jobs spend too long on them (see `SlowOutputs`).
        .output_keys = c.cfg.output_keys and !slowOutputs(c, job.github.repository),
        .output_keys_days = c.cfg.output_keys_days,
        .cancel = cancel,
        .observer = observer: {
            live.next = if (reporter) |r| r.observer() else null;
            break :observer step_logs.observer();
        },
        .sink_job_id = job.check_run_id,
        .runner_name = c.name,
        .native = native,
    }, job, log);
    // A cancel can also end the job through a query it cut short (past the grace period).
    if (cancel.requested.load(.acquire)) {
        result.cancelled = true;
        result.succeeded = false;
    }
    if (result.engine_error) |msg| if (!result.cancelled) {
        try log.append(job.check_run_id, 0, .stderr, "dagger failed before running the steps:");
        try log.append(job.check_run_id, 0, .stderr, msg);
    };
    return result;
}

/// A job failed before any of its steps: "Set up job" failed, as GitHub's runner shows it, and the
/// steps keep their numbers without running (so "Complete job" does not take the first one's).
fn failedInSetUp(arena: std.mem.Allocator, steps: usize) !dagger.Result {
    const step_results = try arena.alloc(dagger.StepResult, steps);
    @memset(step_results, .{});
    return .{
        .steps = step_results,
        .engine_error = null,
        .succeeded = false,
        .set_up_failed = true,
    };
}

test "a job failed before its steps fails in Set up job" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const r = try failedInSetUp(a.allocator(), 2);
    try std.testing.expect(r.set_up_failed and !r.succeeded);
    try std.testing.expectEqual(@as(usize, 2), r.steps.len);
}

/// "Complete job", as GitHub's runner ends a job (the job's containers went with its session).
/// Returns where that step sits, for `upload.shownSteps`.
fn logCompleteJob(
    c: Runner,
    job: job_mod.Job,
    log: *sink.LogSink,
    live: *Live,
    result: dagger.Result,
    job_started_ms: i64,
) !upload.CompleteStep {
    const complete_started = std.Io.Clock.real.now(c.io).toMilliseconds();
    const after_last: u32 = @intCast(job.steps.len + 1);
    const complete_step: u32 = if (result.next_log_step > 0) result.next_log_step else after_last;
    if (result.set_up_failed) {
        // GitHub keeps a step's first conclusion and number: say "Set up job" failed before
        // "Complete job" starts (which would end it as a success), and number the steps that did
        // not run.
        live.end(0, "Set up job", .failure, job_started_ms, complete_started);
        live.skipNumbers(@intCast(job.steps.len));
    }
    live.begin(complete_step, "Complete job", complete_started);
    for (result.output_lines) |l| try log.append(job.check_run_id, complete_step, .stdout, l);
    try log.append(job.check_run_id, complete_step, .stdout, "Cleaning up orphan processes");
    try log.flush();
    return .{
        .log_step = complete_step,
        .started_ms = complete_started,
        .completed_ms = std.Io.Clock.real.now(c.io).toMilliseconds(),
    };
}

/// On the runner's own console: how many steps the engine served from cache, as the step logs say
/// (`dagger.reused_note`) — what step caching saved this job, next to what output keys cost it. A
/// job with a step replayed is not learned from by the memory gate (`admission.Gate.replayed`).
fn reportCacheAndKeys(
    c: Runner,
    job: job_mod.Job,
    log: *sink.LogSink,
    result: dagger.Result,
) !void {
    if (c.cfg.step_cache and job.steps.len > 0) {
        var replayed: usize = 0;
        // Read a line at a time, not held: the log can be the 64 MiB it keeps.
        const kept = log.collect.kept();
        var it = kept.iterate(c.io, try upload.keptBuffer(c));
        while (it.next() catch null) |l| {
            if (l.step >= 1 and l.step <= job.steps.len and
                ((it.textIs(dagger.reused_note) catch false) or
                    (it.textIs(dagger.native_reused_note) catch false))) replayed += 1;
        }
        if (replayed > 0) if (c.gate) |gate| gate.replayed();
        try c.err.print(
            "job {d}: {d} of {d} steps replayed from the cache\n",
            .{ job.check_run_id, replayed, job.steps.len },
        );
    }
    const ok = result.output_keys;
    if (ok.applied + ok.fell_back == 0) return;
    try c.err.print(
        "job {d}: output keys: {d} of {d} always-run steps applied",
        .{ job.check_run_id, ok.applied, ok.applied + ok.fell_back },
    );
    const ms: u64 = @intCast(@max(ok.ms, 0));
    try c.err.print(" in {d}.{d} s", .{ ms / 1000, ms % 1000 / 100 });
    if (ok.fell_back > 0)
        try c.err.print("; {d} fell back (last: {s})", .{ ok.fell_back, ok.last_reason });
    try c.err.writeAll("\n");
    // Over the limit: the rest of this repository's jobs do without them (see `SlowOutputs`).
    const cap = c.cfg.output_keys_max_ms;
    if (cap > 0 and ok.ms > cap and job.github.repository.len > 0) if (c.slow_outputs) |so| {
        if (so.record(job.github.repository, ok.ms))
            try c.err.print(
                "job {d}: output keys: {d}.{d} s is over the {d}.{d} s limit, so {s}'s later " ++
                    "jobs skip them (RUNNER_OUTPUT_KEYS_MAX_MS)\n",
                .{
                    job.check_run_id,
                    ms / 1000,
                    ms % 1000 / 100,
                    cap / 1000,
                    cap % 1000 / 100,
                    job.github.repository,
                },
            );
    };
}

/// The steps as completejob reports them, for the live view's last update.
fn liveFinals(arena: std.mem.Allocator, shown: []const upload.Shown) ![]const Live.Final {
    const finals = try arena.alloc(Live.Final, shown.len);
    for (shown, finals) |sh, *f| f.* = .{
        .id = sh.id,
        .number = sh.number,
        .name = sh.name,
        .conclusion = upload.liveConclusion(sh.conclusion),
        .started_ms = sh.started_ms,
        .completed_ms = sh.completed_ms,
    };
    return finals;
}

/// completejob with the step results and annotations, and once more without them if GitHub refuses:
/// a held job blocks the run for minutes, so it is always finished. Returns the failed Cycle when
/// even that did not succeed.
fn completeJobWithRetry(
    c: Runner,
    jr: runservice.JobRequest,
    job: job_mod.Job,
    conclusion: runservice.Conclusion,
    shown: []const upload.Shown,
    result: dagger.Result,
    /// The job's secrets and masks, which annotations are redacted with.
    secrets: []const []const u8,
) !?Cycle {
    const step_json = try upload.stepResultsJson(c.arena, shown);
    const annotations_json = try upload.annotationsJson(c.arena, shown, result.annotations, secrets);
    var done = completeJob(
        c,
        jr,
        job,
        conclusion,
        step_json,
        result.outputs,
        annotations_json,
        result.environment_url,
    ) catch |e|
        return try fail(c, "completejob", e);
    if (done.status.class() != .success) {
        try c.err.print(
            "completejob with step results and annotations failed (HTTP {d}: {s}); retrying " ++
                "without them\n",
            .{ @backingInt(done.status), done.body[0..@min(done.body.len, 200)] },
        );
        done = completeJob(
            c,
            jr,
            job,
            conclusion,
            "[]",
            result.outputs,
            "[]",
            result.environment_url,
        ) catch |e|
            return try fail(c, "completejob", e);
        if (done.status.class() != .success) return try failBody(c, "completejob", done);
    }
    return null;
}

/// completejob, tried again (after 2, 5 and 10 s) when the request fails or GitHub answers 5xx:
/// a job not completed stays held, and once its hold runs out GitHub fails it ("lost
/// communication") whatever its steps did. The hold is still being renewed meanwhile.
fn completeJob(
    c: Runner,
    jr: runservice.JobRequest,
    job: job_mod.Job,
    conclusion: runservice.Conclusion,
    step_json: []const u8,
    outputs: []const job_mod.EnvVar,
    annotations_json: []const u8,
    environment_url: ?[]const u8,
) !broker.Response {
    const delays = [_]i64{ 2, 5, 10 };
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        const r = runservice.complete(
            c.arena,
            c.io,
            jr,
            job.job_token,
            job.plan_id,
            job.job_id,
            conclusion,
            step_json,
            outputs,
            annotations_json,
            environment_url,
        );
        const retry = if (r) |resp| resp.status.class() == .server_error else |_| true;
        if (!retry or attempt == delays.len) return r;
        if (r) |resp| {
            try c.err.print(
                "completejob: HTTP {d}; trying again in {d}s\n",
                .{ @backingInt(resp.status), delays[attempt] },
            );
        } else |e| try c.err.print(
            "completejob: {s}; trying again in {d}s\n",
            .{ @errorName(e), delays[attempt] },
        );
        c.io.sleep(.fromSeconds(delays[attempt]), .awake) catch {};
    }
}

/// Renews the runner's hold on its job every 60 s while the job runs, as GitHub's runner does
/// (`renewjob`). Without it GitHub fails the job 10 minutes after it was acquired ("The self-hosted
/// runner lost communication with the server"), even while its steps still run (SPEC §3). Like
/// completejob it takes the job's own token; the runner's gets 401. Runs next to the job, so it
/// has memory of its own and reports through the runner's shared (locked) sink, not the job's log.
const Renewer = struct {
    fn init(
        c: Runner,
        job: job_mod.Job,
        jr: runservice.JobRequest,
        cancel: *dagger.Cancel,
    ) Renewer {
        return .{
            .c = c,
            .token = job.job_token,
            .jr = jr,
            .plan_id = job.plan_id,
            .job_id = job.job_id,
            .log_job = job.check_run_id,
            .cancel = cancel,
        };
    }

    c: Runner,
    token: []const u8,
    jr: runservice.JobRequest,
    plan_id: []const u8,
    job_id: []const u8,
    log_job: u64,
    /// Set when GitHub no longer has the job (404): it ended it, so nothing of it runs on.
    cancel: *dagger.Cancel,
    stop: std.atomic.Value(bool) = .init(false),

    pub const interval_secs = 60;

    fn run(r: *Renewer) void {
        var reported = false;
        while (true) {
            // In short steps: the job's end waits for this to see `stop`.
            var waited: u32 = 0;
            while (waited < interval_secs * 20 and !r.stop.load(.acquire)) : (waited += 1) {
                r.c.io.sleep(.fromMilliseconds(50), .awake) catch return;
            }
            if (r.stop.load(.acquire)) return;
            var call: std.heap.ArenaAllocator = .init(r.c.gpa);
            defer call.deinit();
            const arena = call.allocator();
            const resp = runservice.renew(
                arena,
                r.c.io,
                r.jr,
                r.token,
                r.plan_id,
                r.job_id,
            ) catch |e| {
                // Cut short at the job's end (see handleJob): nothing failed.
                if (e == error.Canceled or r.stop.load(.acquire)) return;
                r.say(arena, "renewjob failed: {s}", .{@errorName(e)});
                continue;
            };
            if (resp.status == .not_found) {
                // Seen when a cancelled job's grace period ran out: GitHub closed the job itself.
                r.say(arena, "GitHub no longer has the job (renewjob: HTTP 404); stopping it", .{});
                r.cancel.request(std.Io.Clock.real.now(r.c.io).toMilliseconds());
                return;
            }
            if (resp.status.class() != .success) {
                r.say(
                    arena,
                    "renewjob failed: HTTP {d}: {s}",
                    .{ @backingInt(resp.status), resp.body[0..@min(resp.body.len, 200)] },
                );
            } else if (!reported) {
                reported = true;
                r.say(
                    arena,
                    "job hold renewed (locked until {s})",
                    .{(jsonString(arena, resp.body, "lockedUntil") catch null) orelse "?"},
                );
            }
        }
    }

    fn say(r: *Renewer, arena: Allocator, comptime fmt: []const u8, args: anytype) void {
        const text = std.fmt.allocPrint(arena, "job {d}: " ++ fmt, .{r.log_job} ++ args) catch
            return;
        r.c.log.say(text) catch {};
    }
};

/// Listens on the runner's session while its job runs, as GitHub's runner does, for a
/// `JobCancellation` message: `{"jobId": ..., "timeout": "0.00:05:00.0000"}`, sent when the run is
/// cancelled and when the job reaches its `timeout-minutes` (GitHub enforces that limit itself; the
/// job definition does not carry it). The timeout is the grace period for what still runs after the
/// cancel (`if: always()` steps, post scripts); past it, the job's queries are ended too.
const CancelWatch = struct {
    fn init(c: Runner, session: Listening, job: job_mod.Job, cancel: *dagger.Cancel) CancelWatch {
        return .{
            .c = c,
            .session = session,
            .job_id = job.job_id,
            .log_job = job.check_run_id,
            .cancel = cancel,
        };
    }

    c: Runner,
    session: Listening,
    job_id: []const u8,
    log_job: u64,
    cancel: *dagger.Cancel,
    stop: std.atomic.Value(bool) = .init(false),

    fn run(w: *CancelWatch) void {
        var state: std.heap.ArenaAllocator = .init(w.c.gpa);
        defer state.deinit();
        var token = w.session.token;
        var token_at = w.session.token_at;
        while (!w.stop.load(.acquire)) {
            var call: std.heap.ArenaAllocator = .init(w.c.gpa);
            defer call.deinit();
            var cc = w.c;
            cc.arena = call.allocator();
            const now = std.Io.Clock.real.now(cc.io).toSeconds();
            if (now - token_at > token_refresh_secs) {
                var status: std.http.Status = .ok;
                if (mintToken(cc, w.session.creds, &status)) |t| {
                    token = state.allocator().dupe(u8, t) catch token;
                    token_at = now;
                } else |_| {}
            }
            // Stopped at the job's end by cancelling this poll, which the HTTP client can report as
            // an error other than Canceled. Without the `stop` check the watch then slept 5 s that
            // nothing interrupted, and the job's end waited it out: 5.1 s between every two jobs.
            // A long poll, so a request's usual deadline would end every one (`poll_timeout`).
            const m = broker.request(cc.arena, cc.io, .GET, w.session.url, null, .{
                .token = token,
                .deadline = poll_timeout,
            }) catch |e| {
                if (e == error.Canceled or w.stop.load(.acquire)) return;
                cc.io.sleep(.fromSeconds(5), .awake) catch return;
                continue;
            };
            if (w.stop.load(.acquire)) return;
            if (m.status.class() != .success or m.body.len == 0) {
                if (m.status != .accepted and m.status.class() != .success)
                    cc.io.sleep(.fromSeconds(5), .awake) catch return;
                continue;
            }
            // A message this cannot read for want of memory is lost either way: the poll took it.
            const mtype = (jsonString(cc.arena, m.body, "messageType") catch continue) orelse "";
            if (!std.mem.eql(u8, mtype, "JobCancellation")) continue;
            const inner = (jsonString(cc.arena, m.body, "body") catch continue) orelse continue;
            const id = (jsonString(cc.arena, inner, "jobId") catch continue) orelse continue;
            if (!std.mem.eql(u8, id, w.job_id)) continue;
            const grace_ms = timeSpanMs((jsonString(cc.arena, inner, "timeout") catch null) orelse "") orelse
                default_grace_ms;
            w.cancel.request(std.Io.Clock.real.now(cc.io).toMilliseconds() + grace_ms);
            const text = std.fmt.allocPrint(
                cc.arena,
                "job {d}: cancelled by GitHub; stopping the running step ({d} s for what still " ++
                    "runs)",
                .{ w.log_job, @divTrunc(grace_ms, 1000) },
            ) catch return;
            w.c.log.say(text) catch {};
            return;
        }
    }

    /// GitHub's default `cancel-timeout-minutes`.
    const default_grace_ms = 5 * 60 * 1000;
};

/// Cancels the job once the runner has been asked to stop (SIGTERM from systemd, Docker or a
/// deploy) and the job has had `Config.stop_grace_secs` to finish on its own. Before, a stop
/// waited for a running job however long it took: a stuck one held `systemctl stop` until the
/// unit's `TimeoutStopSec`, and the engine ran its step all that time (#127). The cancel is
/// GitHub's: the running step is stopped, `if: always()` steps and post scripts get
/// `stop_cancel_ms`, and the job is reported cancelled.
const StopDeadline = struct {
    c: Runner,
    cancel: *dagger.Cancel,
    log_job: u64,
    stop: std.atomic.Value(bool) = .init(false),

    fn run(s: *StopDeadline) void {
        // In short steps, as `waitForStop` does: the job's end waits for this to see `stop`.
        while (!stopRequested()) {
            if (s.stop.load(.acquire)) return;
            s.c.io.sleep(.fromMilliseconds(200), .awake) catch return;
        }
        const grace_ms = @as(i64, s.c.cfg.stop_grace_secs) * std.time.ms_per_s;
        const stopping_at = std.Io.Clock.awake.now(s.c.io).toMilliseconds();
        while (std.Io.Clock.awake.now(s.c.io).toMilliseconds() - stopping_at < grace_ms) {
            if (s.stop.load(.acquire)) return;
            s.c.io.sleep(.fromMilliseconds(200), .awake) catch return;
        }
        if (s.stop.load(.acquire)) return;
        s.cancel.request(std.Io.Clock.real.now(s.c.io).toMilliseconds() + stop_cancel_ms);
        sayUnallocated(
            s.c,
            "job {d}: the runner is stopping and the job did not finish within {d} s; " ++
                "cancelling it ({d} s for what still runs)",
            .{ s.log_job, s.c.cfg.stop_grace_secs, @divTrunc(stop_cancel_ms, 1000) },
        );
    }
};

/// What a job cancelled by the runner's stop still gets for `if: always()` steps and post scripts,
/// before whatever runs is stopped too: GitHub gives a cancelled job 5 minutes
/// (`CancelWatch.default_grace_ms`), but a stop is bounded by the unit's `TimeoutStopSec`.
const stop_cancel_ms = 60 * std.time.ms_per_s;

/// A .NET TimeSpan as GitHub writes one (`[d.]hh:mm:ss[.fffffff]`) in milliseconds; null when it
/// is not one.
pub fn timeSpanMs(text: []const u8) ?i64 {
    var rest = text;
    var days: i64 = 0;
    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    if (std.mem.lastIndexOfScalar(u8, rest[0..colon], '.')) |dot| {
        days = std.fmt.parseInt(i64, rest[0..dot], 10) catch return null;
        rest = rest[dot + 1 ..];
    }
    var parts = std.mem.splitScalar(u8, rest, ':');
    const h = std.fmt.parseInt(i64, parts.next() orelse return null, 10) catch return null;
    const m = std.fmt.parseInt(i64, parts.next() orelse return null, 10) catch return null;
    const sec = std.fmt.parseFloat(f64, parts.next() orelse return null) catch return null;
    if (parts.next() != null) return null;
    // Out of range is not a time span, and would overflow (or, for `inf`, panic in the conversion).
    if (days < 0 or days > 1_000_000 or h < 0 or h >= 24 or m < 0 or m >= 60) return null;
    if (!(sec >= 0 and sec < 60)) return null;
    return ((days * 24 + h) * 60 + m) * 60_000 + @as(i64, @intFromFloat(sec * 1000));
}

/// A runner whose jobs spool into `sd`, for the spool tests.
fn spoolTestRunner(
    arena: Allocator,
    cfg: *Config,
    log: *sink.LogSink,
    err: *std.Io.Writer,
    sd: ?*const SpoolDir,
) Runner {
    var c = testRunner(arena, log, err, cfg);
    c.spool_dir = sd;
    return c;
}

const spool_test_job: job_mod.Job = .{
    .plan_id = "p",
    .job_id = "j",
    .job_token = "t",
    .check_run_id = 7,
    .secrets = &.{},
    .steps = &.{},
};

/// The permission bits of `sub_path` in `dir`, the link itself if it is one.
fn modeOf(dir: std.Io.Dir, sub_path: []const u8) !std.posix.mode_t {
    const st = try dir.statFile(std.testing.io, sub_path, .{ .follow_symlinks = false });
    return st.permissions.toMode() & 0o777;
}

test "the job's log is spooled, and the spool file goes when the job ends" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &tmp.sub_path });

    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var inner: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };

    // The runner's directory is its own: made under the configured one, closed to everyone else.
    const sd = try SpoolDir.open(arena, io, base);
    defer sd.close(io);
    const own = try std.fmt.allocPrint(arena, "zig-runner-{d}", .{std.os.linux.geteuid()});
    try std.testing.expect(std.mem.endsWith(u8, sd.path, own));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), try modeOf(tmp.dir, own));
    const c = spoolTestRunner(arena, &cfg, &inner, &err, &sd);

    // Opening the spool points the collector at it; handleJob has nothing to remember.
    var collect: sink.LogSink = .{ .collect = .{ .arena = arena, .io = io, .inner = &inner } };
    const spool = try openSpool(c, spool_test_job, &collect);
    try std.testing.expect(spool != null);
    try std.testing.expect(collect.collect.spool == &spool.?.spool);
    try std.testing.expectEqualStrings("zig-runner-job-7.log", spool.?.name);
    // Readable by the runner's user alone.
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(sd.dir, spool.?.name));

    // A logged line is on disk, not in memory, and comes back from the file.
    try collect.append(7, 1, .stdout, "spooled");
    try std.testing.expectEqual(@as(usize, 0), collect.collect.lines.items.len);
    const back = collect.collect.collected(arena);
    try std.testing.expectEqual(@as(usize, 1), back.len);
    try std.testing.expectEqualStrings("spooled", back[0].text);

    // Closing deletes the file: a finished job leaves nothing in the spool directory.
    spool.?.close(io);
    try std.testing.expectError(
        error.FileNotFound,
        sd.dir.statFile(io, "zig-runner-job-7.log", .{ .follow_symlinks = false }),
    );

    // No spool directory: no spool, nothing said.
    const none = spoolTestRunner(arena, &cfg, &inner, &err, null);
    try std.testing.expect((try openSpool(none, spool_test_job, &collect)) == null);
    try std.testing.expectEqual(@as(usize, 0), err.buffered().len);

    // The same directory again, as the next start finds it: still the runner's, so used.
    const again = try SpoolDir.open(arena, io, base);
    again.close(io);
}

test "a link planted at the spool's name is not written through (#106)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &tmp.sub_path });

    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var inner: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    const sd = try SpoolDir.open(arena, io, base);
    defer sd.close(io);
    const c = spoolTestRunner(arena, &cfg, &inner, &err, &sd);

    // A file the link points at, and a link where the job's spool will be made.
    try tmp.dir.writeFile(io, .{ .sub_path = "victim", .data = "keep" });
    try sd.dir.symLink(io, "../victim", "zig-runner-job-7.log", .{});

    // Refused, said once, and the job carries on with its log in memory.
    var collect: sink.LogSink = .{ .collect = .{ .arena = arena, .io = io, .inner = &inner } };
    try std.testing.expect((try openSpool(c, spool_test_job, &collect)) == null);
    try std.testing.expect(collect.collect.spool == null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "no log spool in") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "PathAlreadyExists") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "kept in memory") != null);
    try collect.append(7, 1, .stdout, "in memory");
    try std.testing.expectEqual(@as(usize, 1), collect.collect.lines.items.len);

    // What the link points at is as it was: not truncated, not written to.
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("keep", try tmp.dir.readFile(io, "victim", &buf));
}

test "a spool directory that is a link, or open to others, is refused (#106)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const own = try std.fmt.allocPrint(arena, "zig-runner-{d}", .{std.os.linux.geteuid()});

    // A link to a directory that would pass every other check: not followed.
    try tmp.dir.createDir(io, "elsewhere", .fromMode(0o700));
    try tmp.dir.symLink(io, "elsewhere", own, .{});
    try std.testing.expectError(error.NotDir, SpoolDir.open(arena, io, base));
    try tmp.dir.deleteFile(io, own);

    // A directory others can read or write in: not private, so not used.
    try tmp.dir.createDir(io, own, .fromMode(0o700));
    try tmp.dir.setFilePermissions(io, own, .fromMode(0o755), .{});
    try std.testing.expectError(error.SpoolDirNotPrivate, SpoolDir.open(arena, io, base));
}

test "timeSpanMs reads GitHub's cancel timeout" {
    try std.testing.expectEqual(@as(?i64, 300_000), timeSpanMs("0.00:05:00.0000"));
    try std.testing.expectEqual(@as(?i64, 90_500), timeSpanMs("00:01:30.5"));
    try std.testing.expectEqual(@as(?i64, 86_400_000 + 60_000), timeSpanMs("1.00:01:00"));
    try std.testing.expectEqual(@as(?i64, null), timeSpanMs("soon"));
    try std.testing.expectEqual(@as(?i64, null), timeSpanMs("00:00:inf"));
    try std.testing.expectEqual(@as(?i64, null), timeSpanMs("9223372036854775807.00:00:00"));
}

test "a job's cancel watch stops at once when the job ends, mid-poll" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    // Connections complete in the listener's backlog and are never answered, so the watch is in
    // the middle of its poll when the job ends, as it always is.
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const url = try std.fmt.allocPrint(
        arena,
        "http://127.0.0.1:{d}/message",
        .{listener.socket.address.getPort()},
    );

    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    const c: Runner = .{
        .arena = arena,
        .gpa = std.testing.allocator,
        .io = io,
        .environ = undefined,
        .cfg = &cfg,
        .log = &log,
        .err = &err,
        .secrets = &.{},
        .name = "t",
    };
    const job: job_mod.Job = .{
        .plan_id = "p",
        .job_id = "j",
        .job_token = "t",
        .check_run_id = 7,
        .secrets = &.{},
        .steps = &.{},
    };
    var cancel: dagger.Cancel = .{};
    // No token refresh is due, so the credentials are never read.
    var watcher = CancelWatch.init(c, .{
        .creds = undefined,
        .token = "token",
        .token_at = std.Io.Clock.real.now(io).toSeconds(),
        .url = url,
    }, job, &cancel);
    var watching = try io.concurrent(CancelWatch.run, .{&watcher});
    try io.sleep(.fromMilliseconds(200), .awake);

    // As handleJob ends it: stop, then cancel the poll.
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    watcher.stop.store(true, .release);
    watching.cancel(io);
    const took = std.Io.Clock.awake.now(io).toMilliseconds() - started;
    try std.testing.expect(took < 1000);
    try std.testing.expect(!cancel.requested.load(.acquire));
}

test "a stop cancels a running job once its grace has passed, and not a job that ended first" {
    const io = std.testing.io;
    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var cfg: Config = .{ .gh_token = "", .scope = undefined, .stop_grace_secs = 0 };
    const c: Runner = .{
        .arena = undefined,
        .gpa = std.testing.allocator,
        .io = io,
        .environ = undefined,
        .cfg = &cfg,
        .log = &log,
        .err = undefined,
        .secrets = &.{},
        .name = "t",
    };
    stop_signals.store(1, .release);
    defer stop_signals.store(0, .release);

    // Past its grace: cancelled, with a minute for what still runs.
    var cancel: dagger.Cancel = .{};
    var deadline: StopDeadline = .{ .c = c, .cancel = &cancel, .log_job = 7 };
    const before = std.Io.Clock.real.now(io).toMilliseconds();
    var running = try io.concurrent(StopDeadline.run, .{&deadline});
    running.await(io);
    try std.testing.expect(cancel.requested.load(.acquire));
    const hard = cancel.hard_deadline_ms.load(.acquire);
    try std.testing.expect(hard >= before + stop_cancel_ms);
    try std.testing.expect(hard <= std.Io.Clock.real.now(io).toMilliseconds() + stop_cancel_ms);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "job 7: the runner is stopping") !=
        null);

    // A job that ends within its grace is left alone, and its end is not kept waiting.
    cfg.stop_grace_secs = 60;
    var left: dagger.Cancel = .{};
    var ending: StopDeadline = .{ .c = c, .cancel = &left, .log_job = 8 };
    var waiting = try io.concurrent(StopDeadline.run, .{&ending});
    try io.sleep(.fromMilliseconds(300), .awake);
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    // As handleJob ends it.
    ending.stop.store(true, .release);
    waiting.cancel(io);
    try std.testing.expect(std.Io.Clock.awake.now(io).toMilliseconds() - started < 1000);
    try std.testing.expect(!left.requested.load(.acquire));
}

test "acquirejob is tried again after a 5xx or a failed connection, not after a 4xx" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var server: @import("../github/testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    var url_buf: [64]u8 = undefined;

    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    const retry_ms = [_]i64{ 1, 1 };

    // 503 on every attempt: tried three times, and the last answer is returned.
    {
        var out_buf: [4096]u8 = undefined;
        var out: std.Io.Writer = .fixed(&out_buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
        const c = testRunner(arena, &log, &err, &cfg);
        const jr: runservice.JobRequest = .{
            .runner_request_id = "r",
            .run_service_url = try arena.dupe(
                u8,
                server.url(&url_buf, "127.0.0.1", "/unavailable"),
            ),
        };
        const r = try acquire(c, jr, "token", &retry_ms);
        try std.testing.expectEqual(std.http.Status.service_unavailable, r.status);
        try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, out.buffered(), "HTTP 503"));
    }
    // 404 is an answer, not a failure: returned at once.
    {
        var out_buf: [4096]u8 = undefined;
        var out: std.Io.Writer = .fixed(&out_buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
        const c = testRunner(arena, &log, &err, &cfg);
        const jr: runservice.JobRequest = .{
            .runner_request_id = "r",
            .run_service_url = try arena.dupe(u8, server.url(&url_buf, "127.0.0.1", "/nowhere")),
        };
        const r = try acquire(c, jr, "token", &retry_ms);
        try std.testing.expectEqual(std.http.Status.not_found, r.status);
        const retries = std.mem.count(u8, out.buffered(), "trying again");
        try std.testing.expectEqual(@as(usize, 0), retries);
    }
    // Nothing listening: tried three times, then the error.
    {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        var closed = try addr.listen(io, .{ .reuse_address = true });
        const port = closed.socket.address.getPort();
        closed.deinit(io);

        var out_buf: [4096]u8 = undefined;
        var out: std.Io.Writer = .fixed(&out_buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
        const c = testRunner(arena, &log, &err, &cfg);
        const jr: runservice.JobRequest = .{
            .runner_request_id = "r",
            .run_service_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{port}),
        };
        if (acquire(c, jr, "token", &retry_ms)) |_| return error.TestUnexpectedResult else |_| {}
        const retries = std.mem.count(u8, out.buffered(), "trying again");
        try std.testing.expectEqual(@as(usize, 2), retries);
    }
}
