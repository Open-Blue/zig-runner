//! What GitHub shows for a job once it ends: the steps in its runner's order and numbering, their
//! logs (each step's uploaded as it finishes, the rest at the job's end), the step results and the
//! annotations completejob sends.

const std = @import("std");
const Config = @import("../config.zig").Config;
const job_mod = @import("../job.zig");
const dagger = @import("../dagger.zig");
const results = @import("../github/results.zig");
const http = @import("../github/http.zig");
const sink = @import("../sink.zig");
const redact = @import("../redact.zig");
const timefmt = @import("../timefmt.zig");
const Live = @import("../live.zig").Live;
const Runner = @import("../loop.zig").Runner;
const testRunner = @import("../loop.zig").testRunner;

const Allocator = std.mem.Allocator;

/// Where "Complete job" sits in the log and when it ran, for `shownSteps`.
pub const CompleteStep = struct { log_step: u32, started_ms: i64, completed_ms: i64 };

/// A step as GitHub shows it for the job.
pub const Shown = struct {
    /// GitHub's step id, or one made here for the steps the runner adds.
    id: []const u8,
    number: u32,
    name: []const u8,
    /// Which lines are its log (`sink.CollectedLine.step`): 0 is "Set up job", 1..n the job's
    /// steps, then `pre`/`post` scripts and "Complete job" (see `dagger.ExtraStep`).
    log_step: u32,
    /// succeeded / failed / skipped, as completejob takes them.
    conclusion: []const u8,
    started_ms: i64 = 0,
    completed_ms: i64 = 0,
};

/// The steps GitHub shows for a job, in its runner's order and numbering: "Set up job", the
/// actions' `pre` scripts, the job's steps, their `post` scripts, "Complete job". GitHub lists only
/// the job's own steps; its runner adds the others with ids of their own, and so does this one.
/// `ids`: GitHub's id of each log step (see `Live.ids`), the same the live view used.
pub fn shownSteps(
    arena: Allocator,
    ids: []const []const u8,
    job: job_mod.Job,
    result: dagger.Result,
    job_started_ms: i64,
    complete: CompleteStep,
) ![]Shown {
    var out: std.ArrayList(Shown) = .empty;
    var first_started: i64 = complete.started_ms;
    for (result.steps) |r| if (r.started_ms > 0 and r.started_ms < first_started) {
        first_started = r.started_ms;
    };
    for (result.extra) |e| if (e.started_ms > 0 and e.started_ms < first_started) {
        first_started = e.started_ms;
    };
    const set_up: []const u8 = if (result.set_up_failed) "failed" else "succeeded";
    try out.append(arena, bookend(ids[0], "Set up job", 0, set_up, job_started_ms, first_started));
    for (result.extra) |e| if (e.kind == .initialize) try out.append(arena, extraShown(ids, e));
    for (result.extra) |e| if (e.kind == .pre) try out.append(arena, extraShown(ids, e));
    for (job.steps, result.steps, 1..) |step, r, n| try out.append(arena, .{
        .id = step.id,
        .number = 0,
        .name = if (r.name.len > 0) r.name else step.name,
        .log_step = @intCast(n),
        // Same vocabulary as the job conclusion (verified live): succeeded/failed/canceled/skipped.
        .conclusion = switch (r.outcome) {
            .success => "succeeded",
            .failure => if (r.continued) "succeeded" else "failed",
            .cancelled => "canceled",
            .skipped, .not_run => "skipped",
        },
        .started_ms = r.started_ms,
        .completed_ms = r.completed_ms,
    });
    const main_end = out.items.len;
    var posts: u32 = 0;
    var pres: u32 = 0;
    for (result.extra) |e| switch (e.kind) {
        .post => {
            try out.append(arena, extraShown(ids, e));
            posts += 1;
        },
        .pre => pres += 1,
        else => {},
    };
    const stop_at = out.items.len;
    for (result.extra) |e| if (e.kind == .stop) try out.append(arena, extraShown(ids, e));
    const has_stop = out.items.len > stop_at;
    try out.append(arena, completeShown(ids, complete));

    // GitHub's numbers (seen on every hosted job compared): in order up to the last main step. With
    // post steps or "Stop containers", one number is set aside after it for each step that could
    // have a post (the job's steps and the pre steps) and one more; the post steps take the last of
    // those, then "Stop containers" and "Complete job" follow.
    for (out.items[0..main_end], 1..) |*s, n| s.number = @intCast(n);
    var next: u32 = @intCast(main_end + 1);
    if (posts > 0 or has_stop) {
        const reserved: u32 = @as(u32, @intCast(job.steps.len)) + pres + 1;
        next = @as(u32, @intCast(main_end)) + 1 + reserved - posts;
    }
    for (out.items[main_end..]) |*s| {
        s.number = next;
        next += 1;
    }
    return out.items;
}

fn completeShown(ids: []const []const u8, c: CompleteStep) Shown {
    const id = ids[c.log_step];
    return bookend(id, "Complete job", c.log_step, "succeeded", c.started_ms, c.completed_ms);
}

/// "Set up job" and "Complete job": GitHub shows them without a step number.
fn bookend(
    id: []const u8,
    name: []const u8,
    log_step: u32,
    conclusion: []const u8,
    started_ms: i64,
    completed_ms: i64,
) Shown {
    return .{
        .id = id,
        .number = 0,
        .name = name,
        .log_step = log_step,
        .conclusion = conclusion,
        .started_ms = started_ms,
        .completed_ms = completed_ms,
    };
}

/// The live view's conclusion for a step's completejob one.
pub fn liveConclusion(c: []const u8) Live.Conclusion {
    if (std.mem.eql(u8, c, "succeeded")) return .success;
    if (std.mem.eql(u8, c, "failed")) return .failure;
    if (std.mem.eql(u8, c, "canceled")) return .cancelled;
    return .skipped;
}

fn extraShown(ids: []const []const u8, e: dagger.ExtraStep) Shown {
    return .{
        .id = ids[e.log_step],
        .number = 0,
        .name = e.name,
        .log_step = e.log_step,
        .conclusion = if (e.outcome == .success) "succeeded" else "failed",
        .started_ms = e.started_ms,
        .completed_ms = e.completed_ms,
    };
}

/// Uploads each shown step's log that did not already go up as the step finished (`StepLogs`), the
/// step summaries and the whole job's log, so GitHub's UI can show them, and waits for the steps'
/// own uploads too: when this returns, every log is up or has failed. Failures are reported but
/// never stop the job from completing, and however many uploads hang, this returns within
/// `Uploader.limit` (a request's deadline bounds each one already; this bounds them all).
pub fn logs(
    c: Runner,
    job: job_mod.Job,
    shown: []const Shown,
    kept: *const sink.Kept,
    summaries: []const []const u8,
    secrets: []const []const u8,
    /// The steps' logs uploaded as each step finished, when they were.
    early: ?*StepLogs,
    up: Uploader,
) !void {
    // Every blob's size from one read of the log; each blob is read again as it goes up.
    var log_steps: usize = 0;
    for (shown) |s| log_steps = @max(log_steps, s.log_step + 1);
    const sizes = try c.arena.alloc(results.KeptBlob.Size, log_steps);
    const job_size: results.KeptBlob.Size =
        results.KeptBlob.count(kept, c.io, try keptBuffer(c), sizes) catch |e| blk: {
            try c.err.print("job {d}: the job's log could not be read back ({s}); it is not " ++
                "uploaded\n", .{ job.check_run_id, @errorName(e) });
            @memset(sizes, .{});
            break :blk .{};
        };

    var uploads: std.ArrayList(Upload) = .empty;
    // Steps whose log went up as they finished: only reported, or uploaded again once that upload
    // is done if it failed or lacks what the step logged after it finished (`whole`). Started any
    // sooner, the step's whole log could go up first and be overwritten by the shorter one (#167).
    const Covered = struct {
        early: *StepLogs.Early,
        name: []const u8,
        blob: results.Blob,
        whole: bool,
    };
    var covered: std.ArrayList(Covered) = .empty;
    for (shown) |s| {
        const size = sizes[s.log_step];
        if (size.lines == 0) continue;
        const blob = try keptBlob(c, kept, s.log_step, size);
        if (early) |e| if (e.done(s.log_step, s.id)) |d| {
            const whole = d.blob.line_count == size.lines and d.text_bytes == size.text_bytes;
            try covered.append(
                c.arena,
                .{ .early = d, .name = s.name, .blob = blob, .whole = whole },
            );
            continue;
        };
        try uploads.append(
            c.arena,
            .{ .what = .{ .log = .{ .step = s.id } }, .name = s.name, .blob = blob },
        );
    }
    // Step summaries, masked as the logs are.
    for (shown) |s| {
        if (s.log_step == 0 or s.log_step > summaries.len) continue;
        const md = summaries[s.log_step - 1];
        if (md.len == 0) continue;
        var masked: std.Io.Writer.Allocating = .init(c.arena);
        try redact.write(&masked.writer, md, secrets);
        try uploads.append(c.arena, .{
            .what = .{ .summary = s.id },
            .name = s.name,
            .markdown = masked.written(),
        });
    }
    if (job_size.lines > 0) try uploads.append(
        c.arena,
        .{ .what = .{ .log = .job }, .blob = try keptBlob(c, kept, null, job_size) },
    );

    // Each upload is three requests one after another (a signed URL, the blob, its metadata), and
    // they were made one upload after another too: 30 round trips, 1.5 s, before the job could end.
    // Now they run at once, each with its own memory; what one failed to start runs here instead.
    // Room for the steps' logs uploaded again below: a task holds a pointer into `uploads`.
    try uploads.ensureUnusedCapacity(c.arena, covered.items.len);
    // Nothing between here and `group.await` can fail: every upload in `uploads` is running.
    var group: std.Io.Group = .init;
    for (uploads.items) |*u| {
        group.concurrent(c.io, Upload.run, .{ u, c.gpa, c.io, job, up }) catch
            Upload.run(u, c.gpa, c.io, job, up);
    }
    // The steps' own uploads, long done but for the last ones; one that failed (or never started)
    // goes up again now, with the rest. One still running after `early_wait` is given up on and
    // goes up again too: a step's upload once hung for 17 minutes on a dead connection, and the
    // job waited for it, "in progress" on GitHub (#100).
    if (early) |e| if (!e.waitAtMost(up.early_wait)) try c.err.print(
        "job {d}: a step's log upload was still running {d} s into the job's end; uploading it " ++
            "again\n",
        .{ job.check_run_id, @divTrunc(up.early_wait.nanoseconds, std.time.ns_per_s) },
    );
    for (covered.items) |cv| {
        if (cv.whole and cv.early.result.ok) continue;
        uploads.appendAssumeCapacity(.{
            .what = .{ .log = .{ .step = cv.early.id } },
            .name = cv.name,
            .blob = cv.blob,
            .again = if (cv.whole) cv.early.result.detail else null,
        });
        const u = &uploads.items[uploads.items.len - 1];
        group.concurrent(c.io, Upload.run, .{ u, c.gpa, c.io, job, up }) catch
            Upload.run(u, c.gpa, c.io, job, up);
    }
    // Whatever is still running at the limit is cancelled, and reported as failed (Canceled).
    _ = awaitAtMost(c.io, &group, up.limit);
    defer for (uploads.items) |*u| u.arena.deinit();
    for (covered.items) |cv| if (cv.whole and cv.early.result.ok) try c.err.print(
        "job {d}: log upload '{s}': ok, {s} (as the step finished)\n",
        .{ job.check_run_id, cv.name, cv.early.result.detail },
    );
    for (uploads.items) |*u| {
        const r = u.result;
        const outcome = if (r.ok) "ok, " else "FAILED: ";
        switch (u.what) {
            .log => |w| switch (w) {
                .step => if (u.again) |why| try c.err.print(
                    "job {d}: log upload '{s}': {s}{s} (again; as the step finished: {s})\n",
                    .{ job.check_run_id, u.name, outcome, r.detail, why },
                ) else try c.err.print(
                    "job {d}: log upload '{s}': {s}{s}\n",
                    .{ job.check_run_id, u.name, outcome, r.detail },
                ),
                .job => try c.err.print(
                    "job {d}: log upload job: {s}{s}\n",
                    .{ job.check_run_id, outcome, r.detail },
                ),
            },
            .summary => try c.err.print(
                "job {d}: summary upload '{s}': {s}{s}\n",
                .{ job.check_run_id, u.name, outcome, r.detail },
            ),
        }
    }
}

/// One upload of `logs`, made in a task of its own. The blob and the markdown are only read;
/// what the requests allocate, the result's detail included, lives in `arena` until it is reported.
const Upload = struct {
    what: union(enum) { log: results.Which, summary: []const u8 },
    name: []const u8 = "",
    blob: results.Blob = undefined,
    markdown: []const u8 = "",
    arena: std.heap.ArenaAllocator = undefined,
    result: results.Result = .{ .ok = false, .detail = "not run" },
    /// A step's log uploaded again because its upload as the step finished failed: why that did.
    again: ?[]const u8 = null,

    fn run(u: *Upload, gpa: Allocator, io: std.Io, job: job_mod.Job, up: Uploader) void {
        u.arena = .init(gpa);
        const arena = u.arena.allocator();
        u.result = switch (u.what) {
            .log => |w| up.log(arena, io, job, w, u.blob),
            .summary => |id| up.summary(arena, io, job, id, u.markdown),
        };
    }
};

/// The results service's uploads, and how long the job's end waits for them; replaced in tests.
const Uploader = struct {
    log: *const @TypeOf(results.upload) = results.upload,
    summary: *const @TypeOf(results.uploadSummary) = results.uploadSummary,
    /// How long the job's end waits for the steps' own uploads (`StepLogs`) before it uploads those
    /// logs again itself. Twice a request's deadline: one of at most 1 MiB that is still running
    /// then has met a dead connection (the 37 of 39 jobs of a stress test that wrapped up normally
    /// did so 0.2-0.6 s after their last step).
    early_wait: std.Io.Duration = default_early_wait,
    /// How long all the uploads at the job's end may take before what is left is cancelled and
    /// completejob goes ahead without it: `early_wait`, then the biggest blob's deadline
    /// (`results.blob_deadline_max`) and a minute for the requests around it. A job not completed
    /// stays "in progress" on GitHub, and its runner takes no new job.
    limit: std.Io.Duration = .{
        .nanoseconds = default_early_wait.nanoseconds + results.blob_deadline_max.nanoseconds +
            60 * std.time.ns_per_s,
    },

    const default_early_wait: std.Io.Duration = .{
        .nanoseconds = 2 * http.request_deadline.nanoseconds,
    };
};

/// Waits for `group`, cancelling what is still running in it once `limit` passes. False when it
/// did.
fn awaitAtMost(io: std.Io, group: *std.Io.Group, limit: std.Io.Duration) bool {
    // Cancelling a task in `Group.await` cancels the group's tasks too.
    const done = http.within(io, limit, awaitGroup, .{ group, io }) catch null;
    if (done == null) group.cancel(io);
    return done != null;
}

fn awaitGroup(group: *std.Io.Group, io: std.Io) void {
    group.await(io) catch {};
}

/// One step's log (`log_step` set) or the job's, read from `kept` as it goes up. Each upload reads
/// with a buffer of its own: they run at once.
fn keptBlob(
    c: Runner,
    kept: *const sink.Kept,
    log_step: ?u32,
    size: results.KeptBlob.Size,
) !results.Blob {
    const b = try c.arena.create(results.KeptBlob);
    b.* = .{
        .kept = kept,
        .io = c.io,
        .step = log_step,
        .buf = try keptBuffer(c),
        .len = size.bytes,
    };
    return b.blob(size.lines);
}

/// Room for reading the kept log: a spool record's header has to fit (a few dozen bytes); more
/// only means fewer reads.
pub fn keptBuffer(c: Runner) ![]u8 {
    return c.arena.alloc(u8, 64 * 1024);
}

/// Each step's log, uploaded in the background as soon as the step finishes, as actions/runner
/// does (its `JobServerQueue` sends a step's log while the next step runs), rather than every log
/// at the job's end: the end is left with "Set up job", "Complete job", the job's whole log and
/// whatever the steps' own uploads could not cover, and fewer uploads at once there (each a new
/// connection and three round trips) finish sooner. All of them are done before completejob, as
/// GitHub's runner has them.
///
/// Lines come from the job's log sink (its listener, so as redacted as everything else uploaded)
/// and are passed on to the live view; steps' ends from the Dagger observer, passed on too. A
/// step's lines are kept here, already formatted, only until its upload: one that logs more than
/// `max_bytes` gives up its early upload and is uploaded at the end from the spool, so the job's
/// memory never holds more than that per step on top of what it did before.
///
/// At the end, `logs` skips a step only when what was uploaded is exactly what the job logged
/// for it (the same id, line count and bytes) and the upload succeeded; a line that arrived after
/// the step's end, or a failed upload, means it is uploaded at the end as before.
pub const StepLogs = struct {
    gpa: Allocator,
    io: std.Io,
    job: *const job_mod.Job,
    /// GitHub's id for each log step (`Live.ids`).
    ids: []const []const u8,
    /// Where lines and step events go on to (the live view).
    inner: sink.CollectSink.Listener,
    next: dagger.Observer,
    up: Uploader = .{},

    mu: std.Io.Mutex = .init,
    /// Per log step (guarded by `mu`).
    steps: []Step,
    /// Uploads started (guarded by `mu`), each in `group`.
    sent: std.ArrayList(*Early) = .empty,
    group: std.Io.Group = .init,
    awaited: bool = false,

    /// A step's lines kept for its upload, at most this many bytes formatted.
    const max_bytes = 1 << 20;

    const Step = struct {
        text: std.ArrayList(u8) = .empty,
        lines: usize = 0,
        text_bytes: usize = 0,
        state: enum { collecting, too_big, sent } = .collecting,
    };

    /// One step's upload, made in a task of its own; its memory is its own (`gpa`).
    const Early = struct {
        log_step: u32,
        id: []const u8,
        blob: results.Blob,
        text_bytes: usize,
        arena: std.heap.ArenaAllocator,
        result: results.Result = .{ .ok = false, .detail = "not started" },

        /// The text is freed once it is up: a job of many steps does not keep their logs in
        /// memory until it ends (the spool has them).
        fn run(e: *Early, gpa: Allocator, io: std.Io, job: *const job_mod.Job, up: Uploader) void {
            e.result = up.log(e.arena.allocator(), io, job.*, .{ .step = e.id }, e.blob);
            gpa.free(e.blob.text);
            e.blob.text = &.{};
        }
    };

    pub fn init(
        gpa: Allocator,
        io: std.Io,
        job: *const job_mod.Job,
        ids: []const []const u8,
        inner: sink.CollectSink.Listener,
        next: dagger.Observer,
    ) !StepLogs {
        const steps = try gpa.alloc(Step, ids.len);
        @memset(steps, .{});
        return .{
            .gpa = gpa,
            .io = io,
            .job = job,
            .ids = ids,
            .inner = inner,
            .next = next,
            .steps = steps,
        };
    }

    /// Waits for the uploads still running and frees everything. The `StepLogs` must no longer be
    /// the sink's listener or the job's observer.
    pub fn deinit(s: *StepLogs) void {
        s.wait();
        for (s.sent.items) |e| {
            s.gpa.free(e.blob.text);
            e.arena.deinit();
            s.gpa.destroy(e);
        }
        s.sent.deinit(s.gpa);
        for (s.steps) |*st| st.text.deinit(s.gpa);
        s.gpa.free(s.steps);
    }

    /// Waits for every upload started. No step may finish after this.
    fn wait(s: *StepLogs) void {
        if (s.stopSending()) s.group.await(s.io) catch {};
    }

    /// Waits for every upload started, cancelling those still running once `limit` passes (their
    /// result is then a failure, so `logs` uploads them again). False when any was. No step
    /// may finish after this.
    fn waitAtMost(s: *StepLogs, limit: std.Io.Duration) bool {
        if (!s.stopSending()) return true;
        return awaitAtMost(s.io, &s.group, limit);
    }

    /// Ends `send`; false when that already happened.
    fn stopSending(s: *StepLogs) bool {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        if (s.awaited) return false;
        s.awaited = true;
        return true;
    }

    pub fn listener(s: *StepLogs) sink.CollectSink.Listener {
        return .{ .ptr = s, .onLine = onLine };
    }

    pub fn observer(s: *StepLogs) dagger.Observer {
        return .{
            .ptr = s,
            .startedFn = stepStarted,
            .finishedFn = stepFinished,
            .extraStartedFn = if (s.next.extraStartedFn != null) extraStarted else null,
            .extraFinishedFn = extraFinished,
            .postsFn = if (s.next.postsFn != null) posts else null,
        };
    }

    fn onLine(ptr: *anyopaque, step: u32, seq: u64, text: []const u8) void {
        const s: *StepLogs = @ptrCast(@alignCast(ptr));
        s.inner.onLine(s.inner.ptr, step, seq, text);
        // "Set up job" is uploaded at the end: the runner logs to it before and after the steps.
        if (step == 0 or step >= s.steps.len) return;
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        const st = &s.steps[step];
        if (st.state != .collecting) return;
        // As `results.formatBlob` writes a line.
        var ts_buf: [64]u8 = undefined;
        const ts = timefmt.isoTime7Buf(&ts_buf, std.Io.Clock.real.now(s.io).toMilliseconds());
        if (ts.len == 0) return s.giveUp(st);
        if (st.text.items.len + ts.len + text.len + 2 > max_bytes) return s.giveUp(st);
        st.text.ensureUnusedCapacity(s.gpa, ts.len + text.len + 2) catch return s.giveUp(st);
        st.text.appendSliceAssumeCapacity(ts);
        st.text.appendAssumeCapacity(' ');
        st.text.appendSliceAssumeCapacity(text);
        st.text.appendAssumeCapacity('\n');
        st.lines += 1;
        st.text_bytes += text.len;
    }

    /// A step whose lines are not all here: uploaded at the end instead.
    fn giveUp(s: *StepLogs, st: *Step) void {
        st.state = .too_big;
        st.text.clearAndFree(s.gpa);
    }

    /// Starts the upload of a step that finished, unless it logged nothing or gave up.
    fn send(s: *StepLogs, log_step: u32) void {
        if (log_step == 0 or log_step >= s.steps.len) return;
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        if (s.awaited) return;
        const st = &s.steps[log_step];
        if (st.state != .collecting or st.lines == 0) return;
        st.state = .sent;
        s.sent.ensureUnusedCapacity(s.gpa, 1) catch return;
        const e = s.gpa.create(Early) catch return;
        const text = st.text.toOwnedSlice(s.gpa) catch {
            s.gpa.destroy(e);
            return;
        };
        e.* = .{
            .log_step = log_step,
            .id = s.ids[log_step],
            .blob = .{ .text = text, .line_count = st.lines },
            .text_bytes = st.text_bytes,
            .arena = .init(s.gpa),
        };
        s.sent.appendAssumeCapacity(e);
        // Not run here when no task can be had: the step would wait for it. It is uploaded at the
        // end instead (its result says it was not started).
        s.group.concurrent(s.io, Early.run, .{ e, s.gpa, s.io, s.job, s.up }) catch {};
    }

    /// The upload made as `log_step` (`id`) finished; null when there is none. It may lack what the
    /// step logged after it finished. Its result is final only after `wait`.
    fn done(s: *StepLogs, log_step: u32, id: []const u8) ?*Early {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        for (s.sent.items) |e| {
            if (e.log_step != log_step) continue;
            if (!std.mem.eql(u8, e.id, id)) return null;
            return e;
        }
        return null;
    }

    fn stepStarted(ptr: *anyopaque, number: u32, name: []const u8, started_ms: i64) void {
        const s: *StepLogs = @ptrCast(@alignCast(ptr));
        s.next.startedFn(s.next.ptr, number, name, started_ms);
    }

    fn stepFinished(ptr: *anyopaque, number: u32, res: dagger.StepResult) void {
        const s: *StepLogs = @ptrCast(@alignCast(ptr));
        s.next.finishedFn(s.next.ptr, number, res);
        s.send(number);
    }

    fn extraStarted(
        ptr: *anyopaque,
        kind: dagger.ExtraKind,
        log_step: u32,
        name: []const u8,
        started_ms: i64,
    ) void {
        const s: *StepLogs = @ptrCast(@alignCast(ptr));
        s.next.extraStartedFn.?(s.next.ptr, kind, log_step, name, started_ms);
    }

    fn extraFinished(ptr: *anyopaque, e: dagger.ExtraStep) void {
        const s: *StepLogs = @ptrCast(@alignCast(ptr));
        if (s.next.extraFinishedFn) |f| f(s.next.ptr, e);
        s.send(e.log_step);
    }

    fn posts(ptr: *anyopaque, count: u32, stop: bool) void {
        const s: *StepLogs = @ptrCast(@alignCast(ptr));
        s.next.postsFn.?(s.next.ptr, count, stop);
    }
};

/// `stepResults` for completejob. Field names follow `actions/runner`'s StepResult; verified live
/// by checking the steps GitHub reports for the job.
/// `annotations` for completejob, as actions/runner sends them (its `Annotation` contract): level
/// FAILURE / WARNING / NOTICE, the message, and where it points (a repository path and lines and
/// columns) when the workflow command said, with the number of the step it came from. An annotation
/// without a file is shown by GitHub on the job's line in the workflow file.
/// `text` cut to at most `max` bytes, at a UTF-8 character boundary.
fn cutUtf8(text: []const u8, max: usize) []const u8 {
    if (text.len <= max) return text;
    var end = max;
    while (end > 0 and text[end] & 0xc0 == 0x80) end -= 1;
    return text[0..end];
}

/// GitHub's runner cuts an annotation's message at this many characters (`_maxIssueMessageLength`).
const max_annotation_message = 4096;

/// The annotations for completejob, masked as the log is (GitHub's runner masks them too; the run
/// page shows them to anyone who can read the repository) and cut as GitHub cuts them.
pub fn annotationsJson(
    arena: Allocator,
    shown: []const Shown,
    annotations: []const dagger.Annotation,
    secrets: []const []const u8,
) ![]const u8 {
    const Item = struct {
        level: []const u8,
        message: []const u8,
        title: ?[]const u8 = null,
        path: ?[]const u8 = null,
        startLine: ?u32 = null,
        endLine: ?u32 = null,
        startColumn: ?u32 = null,
        endColumn: ?u32 = null,
        stepNumber: ?u32 = null,
        isInfrastructureIssue: bool = false,
    };
    const items = try arena.alloc(Item, annotations.len);
    for (items, annotations) |*it, a| {
        const an = a.an;
        const line = propertyNumber(an.line);
        const col = propertyNumber(an.col);
        it.* = .{
            .level = if (std.mem.eql(
                u8,
                an.level,
                "error",
            )) "FAILURE" else if (std.mem.eql(u8, an.level, "warning")) "WARNING" else "NOTICE",
            .message = cutUtf8(try redact.alloc(arena, an.message, secrets), max_annotation_message),
            .title = if (an.title) |t| (if (t.len > 0) try redact.alloc(arena, t, secrets) else null) else null,
            .path = if (an.file) |f| (if (f.len > 0) try redact.alloc(arena, f, secrets) else null) else null,
            .startLine = line,
            .endLine = propertyNumber(an.end_line) orelse line,
            .startColumn = col,
            .endColumn = propertyNumber(an.end_column) orelse col,
            .stepNumber = for (shown) |s| (if (s.log_step == a.step) break s.number) else null,
        };
    }
    var aw: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(items, .{ .emit_null_optional_fields = false }, &aw.writer);
    return aw.written();
}

fn propertyNumber(text: ?[]const u8) ?u32 {
    return std.fmt.parseInt(u32, std.mem.trim(u8, text orelse return null, " "), 10) catch null;
}

test "annotations: GitHub's levels, the place they point to, and the step they came from" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const shown = [_]Shown{
        .{ .id = "s", .number = 1, .name = "Set up job", .log_step = 0, .conclusion = "succeeded" },
        .{ .id = "b", .number = 2, .name = "Build", .log_step = 1, .conclusion = "failed" },
    };
    const json = try annotationsJson(a.allocator(), &shown, &.{
        .{ .step = 1, .an = .{ .level = "error", .message = "bad", .file = "src/a.zig", .line = "3", .col = "5", .title = "T" } },
        .{ .step = 1, .an = .{ .level = "notice", .message = "fyi", .line = "x" } },
    }, &.{});
    try std.testing.expectEqualStrings(
        \\[{"level":"FAILURE","message":"bad","title":"T","path":"src/a.zig","startLine":3,"endLine":3,"startColumn":5,"endColumn":5,"stepNumber":2,"isInfrastructureIssue":false},{"level":"NOTICE","message":"fyi","stepNumber":2,"isInfrastructureIssue":false}]
    , json);
}

test "annotations are masked as the log is, and cut where GitHub cuts them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const shown = [_]Shown{.{ .id = "b", .number = 1, .name = "Build", .log_step = 1, .conclusion = "failed" }};
    // `::warning title=key s3cr3t::using s3cr3t`: the log line is masked, and now the annotation too.
    const secrets = try redact.expand(ar, &.{"s3cr3t"});
    const long = try ar.alloc(u8, 5000);
    @memset(long, 'x');
    long[4095] = 0xc3; // the first byte of a two-byte character across the cut
    long[4096] = 0xa9;
    const json = try annotationsJson(ar, &shown, &.{
        .{ .step = 1, .an = .{ .level = "warning", .message = "using s3cr3t", .title = "key s3cr3t" } },
        .{ .step = 1, .an = .{ .level = "error", .message = long } },
    }, secrets);
    try std.testing.expect(std.mem.indexOf(u8, json, "s3cr3t") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"using ***\",\"title\":\"key ***\"") != null);
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, ar, json, .{});
    try std.testing.expectEqual(@as(usize, 4095), parsed.array.items[1].object.get("message").?.string.len);
}

/// The `stepResults` array completejob sends: each shown step's result (see `Shown`).
pub fn stepResultsJson(arena: Allocator, shown: []const Shown) ![]const u8 {
    const Item = struct {
        external_id: []const u8,
        number: u32,
        name: []const u8,
        status: []const u8,
        conclusion: []const u8,
        started_at: ?[]const u8,
        completed_at: ?[]const u8,
    };
    const items = try arena.alloc(Item, shown.len);
    for (items, shown) |*it, s| it.* = .{
        .external_id = s.id,
        .number = s.number,
        .name = s.name,
        .status = "completed",
        .conclusion = s.conclusion,
        .started_at = if (s.started_ms > 0) try timefmt.isoTime(arena, s.started_ms) else null,
        .completed_at = if (s.completed_ms > 0) try timefmt.isoTime(
            arena,
            s.completed_ms,
        ) else null,
    };
    var aw: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(items, .{ .emit_null_optional_fields = false }, &aw.writer);
    return aw.written();
}

/// The results service for `StepLogs` tests: records each log upload (which log, how many lines,
/// its text), and fails the first upload of the step "post".
const FakeResults = struct {
    const Call = struct { id: [16]u8 = undefined, id_len: usize = 0, lines: usize = 0, text: [128]u8 = undefined, text_len: usize = 0 };
    var mu: std.Io.Mutex = .init;
    var calls: [32]Call = undefined;
    var n: usize = 0;

    fn upload(arena: Allocator, io: std.Io, _: job_mod.Job, which: results.Which, blob: results.Blob) results.Result {
        mu.lockUncancelable(io);
        defer mu.unlock(io);
        const id = switch (which) {
            .step => |s| s,
            .job => "job",
        };
        const first_post = std.mem.eql(u8, id, "post") and count("post") == 0;
        var call: Call = .{ .lines = blob.line_count };
        call.id_len = @min(id.len, call.id.len);
        @memcpy(call.id[0..call.id_len], id[0..call.id_len]);
        const text = blob.textAlloc(arena) catch "";
        call.text_len = @min(text.len, call.text.len);
        @memcpy(call.text[0..call.text_len], text[0..call.text_len]);
        calls[n] = call;
        n += 1;
        if (first_post) return .{ .ok = false, .detail = "HTTP 500" };
        return .{ .ok = true, .detail = std.fmt.allocPrint(arena, "{d} lines", .{blob.line_count}) catch "" };
    }

    fn summary(_: Allocator, _: std.Io, _: job_mod.Job, _: []const u8, _: []const u8) results.Result {
        return .{ .ok = true, .detail = "" };
    }

    fn count(id: []const u8) usize {
        var k: usize = 0;
        for (calls[0..n]) |cl| if (std.mem.eql(u8, cl.id[0..cl.id_len], id)) {
            k += 1;
        };
        return k;
    }

    /// The lines of each upload of `id`, in the order they were made.
    fn lines(id: []const u8, out: []usize) []usize {
        var k: usize = 0;
        for (calls[0..n]) |cl| if (std.mem.eql(u8, cl.id[0..cl.id_len], id)) {
            out[k] = cl.lines;
            k += 1;
        };
        return out[0..k];
    }

    const uploader: Uploader = .{ .log = upload, .summary = summary };
};

/// Counts what `StepLogs` passes on to the live view.
const FakeLive = struct {
    lines: std.atomic.Value(u32) = .init(0),
    finished: std.atomic.Value(u32) = .init(0),

    fn onLine(ptr: *anyopaque, _: u32, _: u64, _: []const u8) void {
        const l: *FakeLive = @ptrCast(@alignCast(ptr));
        _ = l.lines.fetchAdd(1, .monotonic);
    }
    fn started(_: *anyopaque, _: u32, _: []const u8, _: i64) void {}
    fn finishedFn(ptr: *anyopaque, _: u32, _: dagger.StepResult) void {
        const l: *FakeLive = @ptrCast(@alignCast(ptr));
        _ = l.finished.fetchAdd(1, .monotonic);
    }
    fn extraFinished(ptr: *anyopaque, _: dagger.ExtraStep) void {
        const l: *FakeLive = @ptrCast(@alignCast(ptr));
        _ = l.finished.fetchAdd(1, .monotonic);
    }
};

test "each step's log goes up as the step finishes, and the job's end uploads only the rest" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [4096]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    const c = testRunner(arena, &log, &err, &cfg);
    FakeResults.n = 0;

    const job: job_mod.Job = .{ .plan_id = "p", .job_id = "j", .job_token = "t", .check_run_id = 9, .secrets = &.{}, .steps = &.{} };
    const ids = [_][]const u8{ "setup", "a", "b", "c", "post", "complete" };
    var fake: FakeLive = .{};
    var step_logs = try StepLogs.init(
        std.testing.allocator,
        io,
        &job,
        &ids,
        .{ .ptr = &fake, .onLine = FakeLive.onLine },
        .{ .ptr = &fake, .startedFn = FakeLive.started, .finishedFn = FakeLive.finishedFn, .extraFinishedFn = FakeLive.extraFinished },
    );
    defer step_logs.deinit();
    step_logs.up = FakeResults.uploader;
    const l = step_logs.listener();
    const o = step_logs.observer();

    // What the job logs, as the sink tells its listener and keeps it (`collected`).
    var kept: std.ArrayList(sink.CollectedLine) = .empty;
    const big = try arena.alloc(u8, StepLogs.max_bytes);
    @memset(big, 'x');
    const Line = struct { step: u32, text: []const u8 };
    const log_line = struct {
        fn f(lst: sink.CollectSink.Listener, k: *std.ArrayList(sink.CollectedLine), al: Allocator, ln: Line) !void {
            lst.onLine(lst.ptr, ln.step, k.items.len + 1, ln.text);
            try k.append(al, .{ .step = ln.step, .seq = k.items.len + 1, .ts_ms = 0, .text = ln.text });
        }
    }.f;
    try log_line(l, &kept, arena, .{ .step = 0, .text = "job acquired" });
    try log_line(l, &kept, arena, .{ .step = 1, .text = "one" });
    try log_line(l, &kept, arena, .{ .step = 1, .text = "two" });
    o.finishedFn(o.ptr, 1, .{ .outcome = .success });
    try log_line(l, &kept, arena, .{ .step = 2, .text = "b" });
    o.finishedFn(o.ptr, 2, .{ .outcome = .success });
    // After step 2's end: its upload no longer holds its whole log.
    try log_line(l, &kept, arena, .{ .step = 2, .text = "late" });
    // Too much to keep in memory: uploaded at the end, from what the sink kept.
    try log_line(l, &kept, arena, .{ .step = 3, .text = big });
    o.finishedFn(o.ptr, 3, .{ .outcome = .success });
    try log_line(l, &kept, arena, .{ .step = 4, .text = "p" });
    o.extraFinishedFn.?(o.ptr, .{ .kind = .post, .name = "Post a", .log_step = 4, .outcome = .success, .started_ms = 0, .completed_ms = 0 });
    try log_line(l, &kept, arena, .{ .step = 5, .text = "Cleaning up orphan processes" });

    // Passed on to the live view, every line and every step.
    try std.testing.expectEqual(@as(u32, 8), fake.lines.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 4), fake.finished.load(.monotonic));
    // Started as each step finished, before the job's end: a, b and the post step.
    try std.testing.expectEqual(@as(usize, 3), step_logs.sent.items.len);

    const shown = [_]Shown{
        .{ .id = "setup", .number = 0, .name = "Set up job", .log_step = 0, .conclusion = "succeeded" },
        .{ .id = "a", .number = 1, .name = "a", .log_step = 1, .conclusion = "succeeded" },
        .{ .id = "b", .number = 2, .name = "b", .log_step = 2, .conclusion = "succeeded" },
        .{ .id = "c", .number = 3, .name = "c", .log_step = 3, .conclusion = "succeeded" },
        .{ .id = "post", .number = 4, .name = "Post a", .log_step = 4, .conclusion = "succeeded" },
        .{ .id = "complete", .number = 5, .name = "Complete job", .log_step = 5, .conclusion = "succeeded" },
    };
    const up = FakeResults.uploader;
    try logs(c, job, &shown, &.{ .memory = kept.items }, &.{}, &.{}, &step_logs, up);

    // Every upload is done once logs returns, so before completejob.
    var got: [4]usize = undefined;
    // a: once, as it finished, with both lines; as the blob formats them.
    try std.testing.expectEqualSlices(usize, &.{2}, FakeResults.lines("a", &got));
    for (FakeResults.calls[0..FakeResults.n]) |cl| if (std.mem.eql(u8, cl.id[0..cl.id_len], "a")) {
        const text = cl.text[0..cl.text_len];
        try std.testing.expectEqual(@as(usize, 2 * (28 + 1) + "one\ntwo\n".len), text.len);
        try std.testing.expect(std.mem.endsWith(u8, text[0..33], "Z one\n"));
        try std.testing.expect(std.mem.endsWith(u8, text, "Z two\n"));
    };
    // b: as it finished with one line, then at the end with the line that came after.
    try std.testing.expectEqualSlices(usize, &.{ 1, 2 }, FakeResults.lines("b", &got));
    // c: only at the end.
    try std.testing.expectEqualSlices(usize, &.{1}, FakeResults.lines("c", &got));
    // The post step: its upload failed, so it went up again at the end.
    try std.testing.expectEqualSlices(usize, &.{ 1, 1 }, FakeResults.lines("post", &got));
    // The rest only at the end, as before.
    try std.testing.expectEqualSlices(usize, &.{1}, FakeResults.lines("setup", &got));
    try std.testing.expectEqualSlices(usize, &.{1}, FakeResults.lines("complete", &got));
    try std.testing.expectEqualSlices(usize, &.{8}, FakeResults.lines("job", &got));
    try std.testing.expectEqual(@as(usize, 9), FakeResults.n);

    const said = err.buffered();
    try std.testing.expect(std.mem.indexOf(u8, said, "log upload 'a': ok, 2 lines (as the step finished)") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "log upload 'Post a': ok, 1 lines (again; as the step finished: HTTP 500)") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "FAILED") == null);
}

test "a step that finishes after the job's uploads began is uploaded at the end, not early" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const io = std.testing.io;
    FakeResults.n = 0;
    const job: job_mod.Job = .{ .plan_id = "p", .job_id = "j", .job_token = "t", .check_run_id = 9, .secrets = &.{}, .steps = &.{} };
    const ids = [_][]const u8{ "setup", "a" };
    var fake: FakeLive = .{};
    var step_logs = try StepLogs.init(
        std.testing.allocator,
        io,
        &job,
        &ids,
        .{ .ptr = &fake, .onLine = FakeLive.onLine },
        .{ .ptr = &fake, .startedFn = FakeLive.started, .finishedFn = FakeLive.finishedFn },
    );
    defer step_logs.deinit();
    step_logs.up = FakeResults.uploader;
    const l = step_logs.listener();
    l.onLine(l.ptr, 1, 1, "x");
    step_logs.wait();
    const o = step_logs.observer();
    o.finishedFn(o.ptr, 1, .{});
    try std.testing.expectEqual(@as(usize, 0), step_logs.sent.items.len);
    // Line forwarded, and the extra-step events this live view does not take are not offered.
    try std.testing.expectEqual(@as(u32, 1), fake.lines.load(.monotonic));
    try std.testing.expect(o.extraStartedFn == null and o.postsFn == null);
    try std.testing.expect(step_logs.done(1, "a") == null);
}

/// The results service over a dead connection: the first upload of step "a" and every upload of
/// the job's whole log never end until they are cancelled; the rest go up at once.
const HungResults = struct {
    var a_calls: std.atomic.Value(u32) = .init(0);

    fn upload(
        _: Allocator,
        io: std.Io,
        _: job_mod.Job,
        which: results.Which,
        _: results.Blob,
    ) results.Result {
        const hang = switch (which) {
            .step => |id| std.mem.eql(u8, id, "a") and a_calls.fetchAdd(1, .acq_rel) == 0,
            .job => true,
        };
        if (hang) io.sleep(.fromSeconds(600), .awake) catch
            return .{ .ok = false, .detail = "Canceled" };
        return .{ .ok = true, .detail = "up" };
    }

    fn summary(
        _: Allocator,
        _: std.Io,
        _: job_mod.Job,
        _: []const u8,
        _: []const u8,
    ) results.Result {
        return .{ .ok = true, .detail = "" };
    }
};

test "hung uploads hold up the job's end no longer than its limit, and a hung step's goes up again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [4096]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    const c = testRunner(arena, &log, &err, &cfg);
    HungResults.a_calls = .init(0);

    const job: job_mod.Job = .{ .plan_id = "p", .job_id = "j", .job_token = "t", .check_run_id = 9, .secrets = &.{}, .steps = &.{} };
    const ids = [_][]const u8{ "setup", "a" };
    var fake: FakeLive = .{};
    var step_logs = try StepLogs.init(
        std.testing.allocator,
        io,
        &job,
        &ids,
        .{ .ptr = &fake, .onLine = FakeLive.onLine },
        .{ .ptr = &fake, .startedFn = FakeLive.started, .finishedFn = FakeLive.finishedFn },
    );
    defer step_logs.deinit();
    const up: Uploader = .{
        .log = HungResults.upload,
        .summary = HungResults.summary,
        .early_wait = .fromMilliseconds(200),
        .limit = .fromMilliseconds(600),
    };
    step_logs.up = up;
    const kept = [_]sink.CollectedLine{
        .{ .step = 0, .seq = 1, .ts_ms = 0, .text = "job acquired" },
        .{ .step = 1, .seq = 2, .ts_ms = 0, .text = "one" },
    };
    const l = step_logs.listener();
    for (kept) |k| l.onLine(l.ptr, k.step, k.seq, k.text);
    // Step a's upload starts as it finishes, and hangs.
    const o = step_logs.observer();
    o.finishedFn(o.ptr, 1, .{ .outcome = .success });
    try std.testing.expectEqual(@as(usize, 1), step_logs.sent.items.len);

    const shown = [_]Shown{
        .{ .id = "setup", .number = 0, .name = "Set up job", .log_step = 0, .conclusion = "succeeded" },
        .{ .id = "a", .number = 1, .name = "a", .log_step = 1, .conclusion = "succeeded" },
    };
    const started = std.Io.Clock.awake.now(io);
    try logs(c, job, &shown, &.{ .memory = &kept }, &.{}, &.{}, &step_logs, up);
    const took = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    // Back by the limit (and not the 600 s the hung uploads would take), so completejob, next,
    // goes ahead.
    try std.testing.expect(took >= 600 and took < 3_000);

    const said = err.buffered();
    try std.testing.expect(std.mem.indexOf(u8, said, "uploading it again") != null);
    // Step a: given up as the step finished, and up at the end.
    try std.testing.expectEqual(@as(u32, 2), HungResults.a_calls.load(.acquire));
    try std.testing.expect(std.mem.indexOf(u8, said, "log upload 'a': ok, up (again; as the step finished: Canceled)") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "log upload 'Set up job': ok, up") != null);
    // The job's whole log: cancelled at the limit, and reported.
    try std.testing.expect(std.mem.indexOf(u8, said, "log upload job: FAILED: Canceled") != null);
}

test "the steps GitHub shows: Set up job, pre, the job's steps, post, Complete job, numbered in order" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const mk = struct {
        fn step(id: []const u8) job_mod.Step {
            return .{ .id = id, .name = id, .condition = "success()", .action = .{ .unsupported = "x" } };
        }
    };
    const steps = [_]job_mod.Step{ mk.step("a"), mk.step("b"), mk.step("c"), mk.step("d") };
    const job: job_mod.Job = .{ .plan_id = "p", .job_id = "j", .job_token = "t", .check_run_id = 1, .secrets = &.{}, .steps = &steps };
    var rs = [_]dagger.StepResult{
        .{ .outcome = .success, .started_ms = 1000, .completed_ms = 2000 },
        .{ .outcome = .failure, .exit_code = 5, .continued = true },
        .{ .outcome = .failure, .exit_code = 2 },
        .{ .outcome = .skipped },
    };
    const extra = [_]dagger.ExtraStep{
        .{ .kind = .pre, .name = "Pre a", .log_step = 5, .outcome = .success, .started_ms = 900, .completed_ms = 950 },
        .{ .kind = .post, .name = "Post a", .log_step = 6, .outcome = .failure, .started_ms = 3000, .completed_ms = 3100 },
    };
    const result: dagger.Result = .{ .steps = &rs, .engine_error = null, .succeeded = false, .extra = &extra, .next_log_step = 7 };
    const ids = [_][]const u8{ "setup", "a", "b", "c", "d", "pre-a", "post-a", "complete" };
    const shown = try shownSteps(arena, &ids, job, result, 500, .{ .log_step = 7, .started_ms = 3200, .completed_ms = 3300 });
    const names = [_][]const u8{ "Set up job", "Pre a", "a", "b", "c", "d", "Post a", "Complete job" };
    const log_steps = [_]u32{ 0, 5, 1, 2, 3, 4, 6, 7 };
    // After the main steps GitHub sets aside 4 job steps + 1 pre + 1 numbers; the post takes the last.
    const numbers = [_]u32{ 1, 2, 3, 4, 5, 6, 12, 13 };
    try std.testing.expectEqual(names.len, shown.len);
    for (shown, names, log_steps, numbers) |sh, name, ls, n| {
        try std.testing.expectEqualStrings(name, sh.name);
        try std.testing.expectEqual(ls, sh.log_step);
        try std.testing.expectEqual(n, sh.number);
    }
    // Each step has the id of its log step, the one the live view used: GitHub's for the job's steps.
    try std.testing.expectEqualStrings("setup", shown[0].id);
    try std.testing.expectEqualStrings("pre-a", shown[1].id);
    try std.testing.expectEqualStrings("a", shown[2].id);
    try std.testing.expectEqualStrings("complete", shown[7].id);
    // "Set up job" runs from the job's start until the first step (here the pre).
    try std.testing.expectEqual(@as(i64, 500), shown[0].started_ms);
    try std.testing.expectEqual(@as(i64, 900), shown[0].completed_ms);
    const json = try stepResultsJson(arena, shown);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"external_id\":\"a\",\"number\":3,\"name\":\"a\",\"status\":\"completed\",\"conclusion\":\"succeeded\",\"started_at\":\"1970-01-01T00:00:01.000Z\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"b\",\"status\":\"completed\",\"conclusion\":\"succeeded\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"c\",\"status\":\"completed\",\"conclusion\":\"failed\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"d\",\"status\":\"completed\",\"conclusion\":\"skipped\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"number\":12,\"name\":\"Post a\",\"status\":\"completed\",\"conclusion\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"number\":13,\"name\":\"Complete job\"") != null);
}

test "step numbers as GitHub gives them (cases from hosted jobs)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const mk = struct {
        fn step(id: []const u8) job_mod.Step {
            return .{ .id = id, .name = id, .condition = "success()", .action = .{ .unsupported = "x" } };
        }
    };
    const ids = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" };
    const Case = struct { steps: usize, extra: []const dagger.ExtraStep, complete_log: u32, want: []const u32 };
    const cases = [_]Case{
        // checkout, a run step, github-script; checkout's post: 1 2 3 4 · 8 9.
        .{ .steps = 3, .extra = &.{.{ .kind = .post, .name = "Post Run actions/checkout@v6", .log_step = 4, .outcome = .success, .started_ms = 0, .completed_ms = 0 }}, .complete_log = 5, .want = &.{ 1, 2, 3, 4, 8, 9 } },
        // services, four steps, no post: 1 2(Initialize) 3-6 · 12(Stop) 13.
        .{ .steps = 4, .extra = &.{
            .{ .kind = .initialize, .name = "Initialize containers", .log_step = 5, .outcome = .success, .started_ms = 0, .completed_ms = 0 },
            .{ .kind = .stop, .name = "Stop containers", .log_step = 6, .outcome = .success, .started_ms = 0, .completed_ms = 0 },
        }, .complete_log = 7, .want = &.{ 1, 2, 3, 4, 5, 6, 12, 13 } },
        // no post, no services: no gap.
        .{ .steps = 2, .extra = &.{}, .complete_log = 3, .want = &.{ 1, 2, 3, 4 } },
    };
    for (cases) |cs| {
        const steps = try arena.alloc(job_mod.Step, cs.steps);
        for (steps, 0..) |*st, i| st.* = mk.step(ids[i + 1]);
        const rs = try arena.alloc(dagger.StepResult, cs.steps);
        @memset(rs, .{ .outcome = .success });
        const job: job_mod.Job = .{ .plan_id = "p", .job_id = "j", .job_token = "t", .check_run_id = 1, .secrets = &.{}, .steps = steps };
        const result: dagger.Result = .{ .steps = rs, .engine_error = null, .succeeded = true, .extra = cs.extra, .next_log_step = cs.complete_log };
        const shown = try shownSteps(arena, &ids, job, result, 0, .{ .log_step = cs.complete_log, .started_ms = 0, .completed_ms = 0 });
        try std.testing.expectEqual(cs.want.len, shown.len);
        for (shown, cs.want) |sh, n| try std.testing.expectEqual(n, sh.number);
    }
}
