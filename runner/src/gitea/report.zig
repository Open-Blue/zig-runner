//! What a Gitea or Forgejo job tells its instance while it runs and when it ends (#520, G4): its
//! steps and their results, its log, its outputs and its result, through `UpdateTask` and
//! `UpdateLog`, as `act_runner`'s reporter does, and the cancel the instance answers with.
//!
//! The instance has one log stream per task, numbered by row, and slices it into steps by the
//! `logIndex` and `logLength` each step reports: so rows are appended in the order they come,
//! each to the step that is running, and a step's range is where its rows landed. Gitea shows
//! the steps it is sent in `reportedSteps` (setup, main, pre, post and cleanup, in display order);
//! both instances take `steps` by the workflow file's index, and Forgejo shows only those, with
//! "Set up job" as the rows before the first and "Complete job" as the rows after the last.
//!
//! Rows go up once a second by the pump, then the state (so no row is acknowledged without a
//! state report after it); what the instance did not acknowledge (`ackIndex`) is sent again. The
//! state report doubles as the heartbeat and the place a cancel comes back, so it is made every
//! tick. A report that fails is tried again at the next tick and said once; the end is retried for
//! a while, because a task that is never reported is failed by the instance's zombie timeout.
const std = @import("std");
const dagger = @import("../dagger.zig");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const redact = @import("../redact.zig");
const client_mod = @import("client.zig");
const task_mod = @import("task.zig");

const Allocator = std.mem.Allocator;
const Client = client_mod.Client;
const Failure = client_mod.Failure;
const Result = client_mod.Result;
const Stage = client_mod.Stage;

/// A job's step as it is reported, in display order.
const Step = struct {
    stage: Stage,
    /// The workflow step's 0-based index for main steps, and for the pre and post steps of an
    /// action the main step they belong to (or a number of their own when that is not known).
    number: i64,
    /// Which log step the runner's backends number it by (`dagger.ExtraStep.log_step`).
    log_step: u32,
    name: []const u8,
    started_ms: i64 = 0,
    stopped_ms: i64 = 0,
    result: Result = .unspecified,
    log_index: i64 = 0,
    log_length: i64 = 0,
};

/// A row waiting to be acknowledged; its content is the reporter's (`gpa`).
const Row = client_mod.Row;

/// A step of the log that has no number yet: "Complete job" until `beginComplete`.
const unnumbered = std.math.maxInt(u32);

/// An output on its way to the instance.
const Output = struct { name: []const u8, value: []const u8, sent: bool = false };

/// The most rows or bytes of rows one `UpdateLog` carries: a log of millions of lines goes up in
/// pieces, each acknowledged before the next.
const batch_rows = 1000;
const batch_bytes = 1 << 20;
/// What waits unacknowledged, at most: an instance that takes nothing for long does not grow the
/// runner's memory without bound. Rows past it are dropped, and counted (`dropped`).
const max_pending_bytes = 64 << 20;

/// Output limits of the instance, as `act_runner` applies them.
const max_output_key = 255;
const max_output_value = 1 << 20;

pub const Reporter = struct {
    gpa: Allocator,
    io: std.Io,
    client: Client,
    task_id: i64,
    /// The runner's console: what could not be reported is said there.
    log: *sink.LogSink,
    /// The job's secrets, in every form they take in output: names of steps and outputs that
    /// carry one are not reported.
    secrets: []const []const u8,
    /// Told when the instance cancels the task.
    cancel: *dagger.Cancel,
    /// How often the pump reports. A test shortens it.
    interval_ms: u32 = 1000,
    /// How long after the instance's cancel the job's queries are stopped too, as the grace GitHub
    /// gives a cancelled job (`loop/job.zig`, `CancelWatch.cancelLimitMs`).
    cancel_limit_ms: i64 = 285 * std.time.ms_per_s,

    /// Everything below is guarded by `mu`.
    mu: std.Io.Mutex = .init,
    names: std.heap.ArenaAllocator,
    started_ms: i64 = 0,
    steps: std.ArrayList(Step) = .empty,
    /// The step rows are being appended to.
    current: usize = 0,
    rows: std.ArrayList(Row) = .empty,
    pending_bytes: usize = 0,
    dropped: usize = 0,
    /// The index of `rows[0]` in the task's log: how many rows the instance has acknowledged.
    offset: i64 = 0,
    outputs: std.ArrayList(Output) = .empty,
    /// The instance's own result, once it has ended the task.
    server_result: Result = .unspecified,
    /// The job's result is with the instance.
    finished: bool = false,

    /// One report at a time: the pump's and the end's.
    send_mu: std.Io.Mutex = .init,
    stop: std.atomic.Value(bool) = .init(false),
    /// What was said about a method that fails, so an outage is one line at each end.
    failing: struct { log: bool = false, state: bool = false } = .{},
    /// What the instance last said when it refused a report, for that line (guarded by `send_mu`).
    refusal: [160]u8 = undefined,
    refusal_len: usize = 0,

    /// A reporter for the task, with its steps from the workflow (`step_names` are their names as
    /// the workflow gives them; the backends say the evaluated ones as each starts). The job's
    /// "Set up job" has started: its first rows are the runner's own.
    pub fn init(
        gpa: Allocator,
        io: std.Io,
        client: Client,
        task_id: i64,
        log: *sink.LogSink,
        secrets: []const []const u8,
        cancel: *dagger.Cancel,
        step_names: []const []const u8,
    ) Allocator.Error!Reporter {
        var r: Reporter = .{
            .gpa = gpa,
            .io = io,
            .client = client,
            .task_id = task_id,
            .log = log,
            .secrets = secrets,
            .cancel = cancel,
            .names = .init(gpa),
        };
        errdefer r.deinit();
        r.started_ms = now(io);
        try r.steps.append(gpa, .{ .stage = .setup, .number = 0, .log_step = 0, .name = "Set up job", .started_ms = r.started_ms });
        for (step_names, 1..) |name, n| try r.steps.append(gpa, .{
            .stage = .main,
            .number = std.math.cast(i64, n - 1) orelse 0,
            .log_step = std.math.cast(u32, n) orelse unnumbered,
            .name = try r.mask(name),
        });
        try r.steps.append(gpa, .{ .stage = .cleanup, .number = 0, .log_step = unnumbered, .name = "Complete job" });
        return r;
    }

    pub fn deinit(r: *Reporter) void {
        for (r.rows.items) |row| r.gpa.free(row.content);
        r.rows.deinit(r.gpa);
        r.steps.deinit(r.gpa);
        r.outputs.deinit(r.gpa);
        r.names.deinit();
    }

    /// The reporter a callback of the backends or the log's sink was given.
    fn of(ptr: *anyopaque) *Reporter {
        return @ptrCast(@alignCast(ptr));
    }

    fn now(io: std.Io) i64 {
        return std.Io.Clock.real.now(io).toMilliseconds();
    }

    // --- what the job tells ---------------------------------------------------------------------

    pub fn listener(r: *Reporter) sink.CollectSink.Listener {
        return .{ .ptr = r, .onLine = onLine };
    }

    pub fn observer(r: *Reporter) dagger.Observer {
        return .{
            .ptr = r,
            .startedFn = stepStarted,
            .finishedFn = stepFinished,
            .extraStartedFn = extraStarted,
            .extraFinishedFn = extraFinished,
        };
    }

    /// A line the job logged, redacted already by the sink. It goes under the step it was logged
    /// for when that step is the running one or a later one (a step's header is logged just
    /// before the backend says the step began, and must not land in the step before it); a line
    /// for a step already passed, or one this does not know, goes under the running step, as the
    /// instance wants rows in order and a backend's late note must not fall outside its range.
    fn onLine(ptr: *anyopaque, step: u32, _: u64, text: []const u8) void {
        const r = Reporter.of(ptr);
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        if (r.indexOfLogStep(step)) |i| if (i > r.current) r.enter(i, now(r.io));
        r.appendLocked(text);
    }

    /// Rows for `text`, one for each of its lines. The time is when it arrives.
    fn appendLocked(r: *Reporter, text: []const u8) void {
        const at = now(r.io);
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (r.pending_bytes + line.len > max_pending_bytes) {
                r.dropped += 1;
                continue;
            }
            const content = r.gpa.dupe(u8, line) catch {
                r.dropped += 1;
                continue;
            };
            r.rows.append(r.gpa, .{ .time_ms = at, .content = content }) catch {
                r.gpa.free(content);
                r.dropped += 1;
                continue;
            };
            r.pending_bytes += line.len;
            const step = &r.steps.items[r.current];
            if (step.log_length == 0) step.log_index = r.offset + (std.math.cast(i64, r.rows.items.len) orelse 0) - 1;
            step.log_length += 1;
        }
    }

    /// A line of the runner's own in the log, under the step running (`Complete job`'s output
    /// lines, a refused output).
    pub fn say(r: *Reporter, text: []const u8) void {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.appendLocked(text);
    }

    fn stepStarted(ptr: *anyopaque, number: u32, name: []const u8, started_ms: i64) void {
        const r = Reporter.of(ptr);
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const i = r.indexOfLogStep(number) orelse return;
        r.enter(i, started_ms);
        if (name.len > 0) r.steps.items[i].name = r.maskLocked(name);
    }

    fn stepFinished(ptr: *anyopaque, number: u32, res: dagger.StepResult) void {
        const r = Reporter.of(ptr);
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const i = r.indexOfLogStep(number) orelse return;
        const step = &r.steps.items[i];
        if (res.name.len > 0) step.name = r.maskLocked(res.name);
        if (step.started_ms == 0) step.started_ms = res.started_ms;
        step.stopped_ms = res.completed_ms;
        step.result = stepResult(res, false);
    }

    fn extraStarted(
        ptr: *anyopaque,
        kind: dagger.ExtraKind,
        log_step: u32,
        name: []const u8,
        started_ms: i64,
    ) void {
        const r = Reporter.of(ptr);
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const i = r.insertExtra(kind, log_step, name) orelse return;
        r.enter(i, started_ms);
    }

    fn extraFinished(ptr: *anyopaque, e: dagger.ExtraStep) void {
        const r = Reporter.of(ptr);
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const i = r.indexOfLogStep(e.log_step) orelse r.insertExtra(e.kind, e.log_step, e.name) orelse return;
        const step = &r.steps.items[i];
        if (step.started_ms == 0) step.started_ms = e.started_ms;
        step.stopped_ms = e.completed_ms;
        step.result = if (e.outcome == .success) .success else .failure;
    }

    /// The step the backend numbered `log_step` (guarded by `mu`).
    fn indexOfLogStep(r: *Reporter, log_step: u32) ?usize {
        for (r.steps.items, 0..) |s, i| if (s.log_step == log_step) return i;
        return null;
    }

    /// Makes step `i` the one rows go to, and ends "Set up job" if it was running: the first
    /// step's start is the end of the setup, as in `act_runner`.
    fn enter(r: *Reporter, i: usize, at_ms: i64) void {
        const prev = &r.steps.items[r.current];
        if (i != r.current and prev.stage == .setup and prev.stopped_ms == 0) {
            if (prev.result == .unspecified) prev.result = .success;
            prev.stopped_ms = at_ms;
        }
        r.current = i;
        const step = &r.steps.items[i];
        if (step.started_ms == 0) step.started_ms = at_ms;
    }

    /// A step the runner adds to the job's own, put where the instance lists it: initialising
    /// containers and `pre` steps before the first main step, `post` steps and stopping
    /// containers before "Complete job". Null when it cannot be added.
    fn insertExtra(r: *Reporter, kind: dagger.ExtraKind, log_step: u32, name: []const u8) ?usize {
        if (r.indexOfLogStep(log_step)) |i| return i;
        const stage: Stage = switch (kind) {
            .initialize => .init_containers,
            .pre => .pre,
            .post => .post,
            .stop => .stop_containers,
        };
        const at: usize = switch (kind) {
            .initialize, .pre => first: {
                for (r.steps.items, 0..) |s, i| if (s.stage == .main) break :first i;
                break :first r.steps.items.len - 1;
            },
            .post, .stop => r.steps.items.len - 1,
        };
        const own = r.ownerOf(stage, name) orelse log_step;
        r.steps.insert(r.gpa, at, .{
            .stage = stage,
            .number = own,
            .log_step = log_step,
            .name = r.maskLocked(name),
        }) catch return null;
        if (r.current >= at) r.current += 1;
        return at;
    }

    /// The workflow step a "Pre x" or "Post x" step belongs to: the main step named `x`, when one
    /// is and no other step of the stage has taken its number. Otherwise the step's own log
    /// number is its number (the instance only needs them apart).
    fn ownerOf(r: *Reporter, stage: Stage, name: []const u8) ?i64 {
        const prefix = switch (stage) {
            .pre => "Pre ",
            .post => "Post ",
            else => return null,
        };
        if (!std.mem.startsWith(u8, name, prefix)) return null;
        for (r.steps.items) |s| {
            if (s.stage != .main or !std.mem.eql(u8, s.name, name[prefix.len..])) continue;
            for (r.steps.items) |t| if (t.stage == stage and t.number == s.number) return null;
            return s.number;
        }
        return null;
    }

    /// "Complete job" begins, as the job's log step `log_step`: the rows after this are its.
    pub fn beginComplete(r: *Reporter, log_step: u32, at_ms: i64) void {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const i = r.steps.items.len - 1;
        r.steps.items[i].log_step = log_step;
        r.enter(i, at_ms);
    }

    /// The job's outputs, as `act_runner` sends them: a key or value over the instance's limits, or
    /// a value that carries a secret, is left out and said in the log, as GitHub leaves out what may
    /// hold a secret rather than mask it.
    pub fn setOutputs(r: *Reporter, outputs: []const job_mod.EnvVar) Allocator.Error!void {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const arena = r.names.allocator();
        for (outputs) |o| {
            const refused: ?[]const u8 = if (o.name.len > max_output_key)
                "its name is too long"
            else if (o.value.len > max_output_value)
                "its value is too long"
            else if (r.hasSecret(o.value))
                "it may contain a secret"
            else
                null;
            if (refused) |why| {
                var buf: [512]u8 = undefined;
                const line = std.fmt.bufPrint(&buf, "ignore output {s} because {s}", .{
                    o.name[0..@min(o.name.len, 80)],
                    why,
                }) catch continue;
                r.appendLocked(line);
                continue;
            }
            try r.outputs.append(r.gpa, .{ .name = try arena.dupe(u8, o.name), .value = try arena.dupe(u8, o.value) });
        }
    }

    fn hasSecret(r: *Reporter, text: []const u8) bool {
        var out: std.Io.Writer.Allocating = .init(r.gpa);
        defer out.deinit();
        redact.write(&out.writer, text, r.secrets) catch return true;
        return !std.mem.eql(u8, out.written(), text);
    }

    fn mask(r: *Reporter, text: []const u8) Allocator.Error![]const u8 {
        var out: std.Io.Writer.Allocating = .init(r.names.allocator());
        redact.write(&out.writer, text, r.secrets) catch return error.OutOfMemory;
        return out.written();
    }

    /// `mask` for a name that is set where the step cannot fail: unmasked it would be a secret
    /// shown, so a name that cannot be masked is not shown.
    fn maskLocked(r: *Reporter, text: []const u8) []const u8 {
        return r.mask(text) catch "(name not shown)";
    }

    // --- what it says -----------------------------------------------------------------------------

    /// Reports every `interval_ms` until `stop`: the log, then the state. Runs next to the job.
    pub fn pump(r: *Reporter) void {
        var arena_state: std.heap.ArenaAllocator = .init(r.gpa);
        defer arena_state.deinit();
        var waited: u32 = 0;
        while (!r.stop.load(.acquire)) {
            r.io.sleep(.fromMilliseconds(@min(50, r.interval_ms)), .awake) catch return;
            waited += 50;
            if (waited < r.interval_ms) continue;
            waited = 0;
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();
            if (r.flushLog(arena, false)) |_| {
                r.failing.log = false;
            } else |e| r.noteFailure("UpdateLog", &r.failing.log, e);
            if (r.reportState(arena, .unspecified)) |_| {
                r.failing.state = false;
            } else |e| r.noteFailure("UpdateTask", &r.failing.state, e);
        }
    }

    fn noteFailure(r: *Reporter, method: []const u8, said: *bool, e: anyerror) void {
        if (said.*) return;
        said.* = true;
        var buf: [256]u8 = undefined;
        const text = std.fmt.bufPrint(
            &buf,
            "gitea: task {d}: {s} failed ({s}{s}{s}); trying again at the next report",
            .{
                r.task_id,
                method,
                @errorName(e),
                if (r.refusal_len > 0) ": " else "",
                r.refusal[0..r.refusal_len],
            },
        ) catch return;
        r.log.say(text) catch |le| std.log.warn("gitea: log: {s}", .{@errorName(le)});
    }

    /// Sends the rows not acknowledged, up to `noMore` and the end of them when `all`: the instance's
    /// `ackIndex` says how many it took, and the rest is sent again by the next call. Errors when it
    /// took less than a final call sent.
    fn flushLog(r: *Reporter, arena: Allocator, final: bool) !void {
        r.send_mu.lockUncancelable(r.io);
        defer r.send_mu.unlock(r.io);
        while (true) {
            var failure: Failure = .{};
            // The rows are copied out, since the job logs while the instance is asked; their
            // content stays where it is, until it is acknowledged here.
            r.mu.lockUncancelable(r.io);
            const first = r.offset;
            var n: usize = 0;
            var bytes: usize = 0;
            while (n < r.rows.items.len and n < batch_rows and bytes < batch_bytes) : (n += 1)
                bytes += r.rows.items[n].content.len;
            const batch = try arena.dupe(Row, r.rows.items[0..n]);
            const last = n == r.rows.items.len;
            r.mu.unlock(r.io);
            if (n == 0 and !final) return;
            const no_more = final and last;
            const ack = r.client.updateLog(arena, r.io, r.task_id, first, batch, no_more, &failure) catch |e| {
                r.keepRefusal(failure);
                return e;
            };
            if (ack < first) return error.LogsLost;
            const taken: usize = std.math.cast(usize, @min(ack - first, std.math.cast(i64, n) orelse 0)) orelse 0;
            r.mu.lockUncancelable(r.io);
            for (r.rows.items[0..taken]) |row| {
                r.pending_bytes -|= row.content.len;
                r.gpa.free(row.content);
            }
            r.rows.replaceRangeAssumeCapacity(0, taken, &.{});
            r.offset = first + (std.math.cast(i64, taken) orelse 0);
            r.mu.unlock(r.io);
            // What was left out (taken < n) goes again at the next call, not in a loop: an
            // instance that takes nothing would be asked as fast as it answers.
            if (taken < n) {
                if (final) return error.LogsNotAccepted;
                return;
            }
            if (!last) continue;
            return;
        }
    }

    fn keepRefusal(r: *Reporter, failure: Failure) void {
        const n = @min(failure.message.len, r.refusal.len);
        @memcpy(r.refusal[0..n], failure.message[0..n]);
        r.refusal_len = n;
    }

    /// `UpdateTask` with the state as it is, and `result` as the job's (unspecified while it runs).
    /// An answer that carries a result of the instance's own is its cancel.
    fn reportState(r: *Reporter, arena: Allocator, result: Result) !void {
        r.send_mu.lockUncancelable(r.io);
        defer r.send_mu.unlock(r.io);
        return r.reportStateLocked(arena, result, 0);
    }

    fn reportStateLocked(r: *Reporter, arena: Allocator, result: Result, stopped_ms: i64) !void {
        const report = try r.snapshot(arena, result, stopped_ms);
        var failure: Failure = .{};
        const answer = r.client.updateTask(arena, r.io, report, &failure) catch |e| {
            r.keepRefusal(failure);
            return e;
        };
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        for (r.outputs.items) |*o| for (answer.sent_outputs) |k| if (std.mem.eql(u8, k, o.name)) {
            o.sent = true;
        };
        if (result == .unspecified and answer.result != .unspecified and r.server_result == .unspecified) {
            r.server_result = answer.result;
            const limit_ms = r.cancel_limit_ms;
            r.cancel.request(now(r.io) + limit_ms);
            var buf: [256]u8 = undefined;
            const text = std.fmt.bufPrint(
                &buf,
                "gitea: task {d}: the instance ended the task ({s}); stopping the running step " ++
                    "({d} s for what still runs)",
                .{ r.task_id, @tagName(answer.result), @divTrunc(limit_ms, 1000) },
            ) catch return;
            r.log.say(text) catch |e| std.log.warn("gitea: log: {s}", .{@errorName(e)});
        }
        if (result != .unspecified) for (r.outputs.items) |o| if (!o.sent) return error.OutputsNotAccepted;
    }

    /// The state as `UpdateTask` takes it, in `arena`. The pending outputs are in it.
    fn snapshot(r: *Reporter, arena: Allocator, result: Result, stopped_ms: i64) !client_mod.TaskReport {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const reported = try arena.alloc(client_mod.StepState, r.steps.items.len);
        var workflow: std.ArrayList(client_mod.StepState) = .empty;
        for (r.steps.items, reported, 0..) |s, *out, i| {
            out.* = .{
                .id = std.math.cast(i64, i) orelse 0,
                .result = s.result,
                .started_ms = s.started_ms,
                .stopped_ms = s.stopped_ms,
                .log_index = s.log_index,
                .log_length = s.log_length,
                .name = s.name,
                .stage = s.stage,
                .number = s.number,
            };
            if (s.stage == .main) try workflow.append(arena, .{
                .id = s.number,
                .result = s.result,
                .started_ms = s.started_ms,
                .stopped_ms = s.stopped_ms,
                .log_index = s.log_index,
                .log_length = s.log_length,
            });
        }
        var outputs: std.ArrayList(task_mod.Pair) = .empty;
        for (r.outputs.items) |o| if (!o.sent) try outputs.append(arena, .{ .name = o.name, .value = o.value });
        return .{
            .state = .{
                .id = r.task_id,
                .result = result,
                .started_ms = r.started_ms,
                .stopped_ms = stopped_ms,
                .steps = workflow.items,
                .reported_steps = reported,
            },
            .outputs = outputs.items,
        };
    }

    // --- the end ----------------------------------------------------------------------------------

    /// What the instance is told when the job ends: every step's result (the job's, for one
    /// that was running; skipped, or cancelled when the job was, for one that never started),
    /// the rest of the log, the summaries (Forgejo), and the job's result, each retried for a
    /// while (`flushFinal` in `act_runner`: ten tries, the wait doubling).
    pub fn finish(
        r: *Reporter,
        arena: Allocator,
        result: Result,
        run: dagger.Result,
        summaries: []const []const u8,
    ) !void {
        r.stop.store(true, .release);
        const ended_ms = now(r.io);
        r.finishSteps(result, run, ended_ms);
        if (r.dropped > 0) {
            var buf: [128]u8 = undefined;
            r.say(std.fmt.bufPrint(&buf, "{d} log line(s) were not kept: the instance did not take them", .{r.dropped}) catch "log lines were not kept");
        }
        var failure: ?anyerror = null;
        var attempt: u5 = 0;
        while (attempt < 10) : (attempt += 1) {
            if (attempt > 0) {
                const wait_ms: u64 = (@as(u64, 100) << attempt) / 2;
                const wait = std.math.cast(i64, @min(wait_ms, 10_000)) orelse 10_000;
                r.io.sleep(.fromMilliseconds(wait), .awake) catch break;
            }
            failure = null;
            r.flushLog(arena, true) catch |e| {
                failure = e;
                continue;
            };
            if (r.client.flavor == .forgejo) r.sendSummaries(arena, summaries);
            r.send_mu.lockUncancelable(r.io);
            defer r.send_mu.unlock(r.io);
            r.reportStateLocked(arena, result, ended_ms) catch |e| {
                failure = e;
                continue;
            };
            r.finished = true;
            return;
        }
        return failure orelse error.NotReported;
    }

    /// Forgejo's step summaries, by the workflow step they belong to. A failure is said and not
    /// retried: the job's result matters more than its summary.
    fn sendSummaries(r: *Reporter, arena: Allocator, summaries: []const []const u8) void {
        var list: std.ArrayList(client_mod.Summary) = .empty;
        r.mu.lockUncancelable(r.io);
        for (r.steps.items) |s| {
            if (s.stage != .main or s.log_step == 0 or s.log_step > summaries.len) continue;
            const text = summaries[s.log_step - 1];
            if (text.len > 0) list.append(arena, .{ .step = s.number, .content = text }) catch |e|
                std.log.warn("gitea: summary: {s}", .{@errorName(e)});
        }
        r.mu.unlock(r.io);
        if (list.items.len == 0) return;
        var failure: Failure = .{};
        r.client.updateStepSummary(arena, r.io, r.task_id, list.items, &failure) catch |e| {
            var buf: [200]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "gitea: task {d}: step summaries not reported ({s})", .{
                r.task_id,
                @errorName(e),
            }) catch return;
            r.log.say(text) catch |le| std.log.warn("gitea: log: {s}", .{@errorName(le)});
        };
    }

    /// Gives every step its last state: from the job's `run` where the backends have it, and the
    /// job's result for what was running when it ended. Nothing is changed that the backends said
    /// is over, except that their result wins over what was heard as it ran.
    fn finishSteps(r: *Reporter, job_result: Result, run: dagger.Result, ended_ms: i64) void {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        const cancelled = job_result == .cancelled;
        for (r.steps.items) |*s| {
            if (s.stage == .main and s.log_step >= 1 and s.log_step <= run.steps.len) {
                const res = run.steps[s.log_step - 1];
                if (res.name.len > 0) s.name = r.maskLocked(res.name);
                if (res.started_ms > 0) s.started_ms = res.started_ms;
                if (res.completed_ms > 0) s.stopped_ms = res.completed_ms;
                s.result = stepResult(res, cancelled);
                if (res.outcome == .not_run or res.outcome == .skipped) s.started_ms = 0;
            }
            for (run.extra) |e| if (e.log_step == s.log_step and s.stage != .main and s.stage != .setup) {
                if (e.started_ms > 0) s.started_ms = e.started_ms;
                if (e.completed_ms > 0) s.stopped_ms = e.completed_ms;
                s.result = if (e.outcome == .success) .success else .failure;
            };
            switch (s.stage) {
                .setup => {
                    s.result = if (run.set_up_failed) .failure else .success;
                    if (s.stopped_ms == 0) s.stopped_ms = firstStart(r.steps.items, ended_ms);
                },
                .cleanup => {
                    if (s.started_ms == 0) s.started_ms = ended_ms;
                    s.result = .success;
                    s.stopped_ms = ended_ms;
                },
                else => if (s.result == .unspecified) {
                    s.result = if (s.started_ms == 0)
                        (if (cancelled) Result.cancelled else Result.skipped)
                    else
                        job_result;
                    if (s.started_ms != 0 and s.stopped_ms == 0) s.stopped_ms = ended_ms;
                },
            }
        }
    }

    /// When the job's first step after "Set up job" began, the time "Set up job" ended.
    fn firstStart(steps: []const Step, fallback_ms: i64) i64 {
        var first = fallback_ms;
        for (steps) |s| if (s.stage != .setup and s.stage != .cleanup and s.started_ms > 0 and s.started_ms < first) {
            first = s.started_ms;
        };
        return first;
    }
};

/// A step's result as the instance has it: a failure the step's `continue-on-error` allowed is a
/// success (GitHub's conclusion, not its outcome), and a step that never ran is skipped, or
/// cancelled when the job was cancelled.
fn stepResult(res: dagger.StepResult, job_cancelled: bool) Result {
    return switch (res.outcome) {
        .success => .success,
        .failure => if (res.continued) .success else .failure,
        .cancelled => .cancelled,
        .skipped => .skipped,
        .not_run => if (job_cancelled) .cancelled else .skipped,
    };
}

/// The job's result as the instance has it, from how the backends ended it: cancelled first (the
/// instance's own cancel, the job's timeout, a stop of the runner), then whether every step that
/// had to succeed did.
pub fn jobResult(run: dagger.Result) Result {
    if (run.cancelled) return .cancelled;
    return if (run.succeeded) .success else .failure;
}

// --- tests ------------------------------------------------------------------------------------------

const testserver = @import("testserver.zig");

/// A reporter against the fake instance, for the tests below.
const Rig = struct {
    server: testserver.Server = undefined,
    out: std.Io.Writer.Allocating,
    log: sink.LogSink = undefined,
    cancel: dagger.Cancel = .{},
    arena: std.heap.ArenaAllocator,
    buf: [64]u8 = undefined,

    fn init(rig: *Rig, flavor: client_mod.Flavor, names: []const []const u8, secrets: []const []const u8) !Reporter {
        rig.out = .init(std.testing.allocator);
        rig.arena = .init(std.testing.allocator);
        rig.cancel = .{};
        try rig.server.start();
        rig.server.echo_acks = true;
        try rig.server.replyAlways("UpdateTask", "200 OK", "{\"state\":{}}");
        rig.log = .{ .stdout = .{ .writer = &rig.out.writer } };
        const client: Client = .{
            .flavor = flavor,
            .url = rig.server.url(&rig.buf),
            .uuid = "u",
            .token = "t",
            .deadline = .fromSeconds(5),
        };
        return .init(std.testing.allocator, std.testing.io, client, 7, &rig.log, secrets, &rig.cancel, names);
    }

    fn deinit(rig: *Rig, r: *Reporter) void {
        r.deinit();
        rig.server.stop();
        rig.arena.deinit();
        rig.out.deinit();
    }

    fn lastTask(rig: *Rig) []const u8 {
        return rig.server.nth("UpdateTask", rig.server.count("UpdateTask") - 1).body;
    }
};

fn has(text: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, text, needle) != null;
}

test "a job's steps, rows and result are reported to Gitea with their ranges" {
    var rig: Rig = undefined;
    var r = try rig.init(.gitea, &.{ "first", "second" }, &.{"s3cr3t"});
    defer rig.deinit(&r);
    const o = r.observer();
    const l = r.listener();
    l.onLine(l.ptr, 0, 1, "setting up");
    o.startedFn(o.ptr, 1, "first", 1_000);
    l.onLine(l.ptr, 1, 1, "one\ntwo");
    o.finishedFn(o.ptr, 1, .{ .name = "first", .outcome = .success, .started_ms = 1_000, .completed_ms = 2_000 });
    o.startedFn(o.ptr, 2, "second", 2_000);
    l.onLine(l.ptr, 2, 1, "boom");
    o.finishedFn(o.ptr, 2, .{ .name = "second", .outcome = .failure, .started_ms = 2_000, .completed_ms = 3_000 });
    r.beginComplete(3, 3_000);
    r.say("Cleaning up");
    try r.setOutputs(&.{ .{ .name = "v", .value = "1" }, .{ .name = "leak", .value = "x s3cr3t y" } });
    const steps = [_]dagger.StepResult{
        .{ .name = "first", .outcome = .success, .started_ms = 1_000, .completed_ms = 2_000 },
        .{ .name = "second", .outcome = .failure, .started_ms = 2_000, .completed_ms = 3_000 },
    };
    try rig.server.reply("UpdateTask", "200 OK", "{\"state\":{},\"sentOutputs\":[\"v\"]}");
    try r.finish(rig.arena.allocator(), .failure, .{ .steps = @constCast(&steps), .engine_error = null, .succeeded = false }, &.{});

    const body = rig.lastTask();
    try std.testing.expect(has(body, "\"result\":\"RESULT_FAILURE\",\"startedAt\""));
    try std.testing.expect(has(body, "\"outputs\":{\"v\":\"1\"}"));
    try std.testing.expect(!has(body, "leak"));
    // Gitea's reported steps: setup, the two main steps, cleanup, with their rows.
    try std.testing.expect(has(body, "\"name\":\"Set up job\",\"stage\":\"STEP_STAGE_SETUP\""));
    try std.testing.expect(has(body, "\"logIndex\":\"1\",\"logLength\":\"2\",\"name\":\"first\",\"stage\":\"STEP_STAGE_MAIN\""));
    try std.testing.expect(has(body, "\"result\":\"RESULT_FAILURE\",\"startedAt\":\"1970-01-01T00:00:02.000Z\",\"stoppedAt\":\"1970-01-01T00:00:03.000Z\",\"logIndex\":\"3\",\"logLength\":\"1\",\"name\":\"second\""));
    try std.testing.expect(has(body, "\"stage\":\"STEP_STAGE_CLEANUP\""));
    // By the workflow's index too, for the instances that derive the steps from the file.
    try std.testing.expect(has(body, "\"steps\":[{\"id\":\"0\",\"result\":\"RESULT_SUCCESS\""));
    // The rows, in order, split by line, the leaked output said and not sent.
    const logs = try rig.server.bodies("UpdateLog");
    defer {
        for (logs) |b| std.testing.allocator.free(b);
        std.testing.allocator.free(logs);
    }
    const final = logs[logs.len - 1];
    try std.testing.expect(has(final, "\"noMore\":true"));
    const all = try std.mem.join(std.testing.allocator, "", logs);
    defer std.testing.allocator.free(all);
    try std.testing.expect(has(all, "\"content\":\"setting up\""));
    try std.testing.expect(has(all, "\"content\":\"one\"") and has(all, "\"content\":\"two\""));
    try std.testing.expect(has(all, "ignore output leak because it may contain a secret"));
    try std.testing.expect(!has(all, "s3cr3t"));
}

test "Forgejo is sent the steps by workflow index only, and the summaries" {
    var rig: Rig = undefined;
    var r = try rig.init(.forgejo, &.{"only"}, &.{});
    defer rig.deinit(&r);
    try rig.server.reply("UpdateStepSummary", "200 OK", "{}");
    const steps = [_]dagger.StepResult{.{ .name = "only", .outcome = .success, .started_ms = 1_000, .completed_ms = 2_000 }};
    const summaries = [_][]const u8{"# done"};
    try r.finish(rig.arena.allocator(), .success, .{ .steps = @constCast(&steps), .engine_error = null, .succeeded = true }, &summaries);
    const body = rig.lastTask();
    try std.testing.expect(!has(body, "reportedSteps"));
    try std.testing.expect(!has(body, "STEP_STAGE"));
    try std.testing.expect(has(body, "\"result\":\"RESULT_SUCCESS\""));
    try std.testing.expectEqualStrings(
        "{\"taskId\":\"7\",\"summaries\":[{\"stepNumber\":\"0\",\"content\":\"# done\"}]}",
        rig.server.nth("UpdateStepSummary", 0).body,
    );
}

test "rows the instance did not acknowledge are sent again from its ackIndex" {
    var rig: Rig = undefined;
    var r = try rig.init(.gitea, &.{}, &.{});
    defer rig.deinit(&r);
    r.say("a\nb\nc");
    // It takes one of three.
    try rig.server.reply("UpdateLog", "200 OK", "{\"ackIndex\":\"1\"}");
    try r.flushLog(rig.arena.allocator(), false);
    try std.testing.expectEqual(@as(i64, 1), r.offset);
    try std.testing.expectEqual(@as(usize, 2), r.rows.items.len);
    // The next call starts at 1 with the two left, and the instance takes them.
    try r.flushLog(rig.arena.allocator(), false);
    try std.testing.expectEqual(@as(i64, 3), r.offset);
    try std.testing.expectEqual(@as(usize, 0), r.rows.items.len);
    const logs = try rig.server.bodies("UpdateLog");
    defer {
        for (logs) |b| std.testing.allocator.free(b);
        std.testing.allocator.free(logs);
    }
    try std.testing.expect(!has(logs[0], "\"index\""));
    try std.testing.expect(has(logs[1], "\"index\":\"1\""));
    try std.testing.expect(!has(logs[1], "\"content\":\"a\""));
    // An ack before what was already acknowledged is a log the instance lost.
    r.say("d");
    try rig.server.reply("UpdateLog", "200 OK", "{\"ackIndex\":\"0\"}");
    try std.testing.expectError(error.LogsLost, r.flushLog(rig.arena.allocator(), false));
}

test "the instance ending the task cancels the job, once, through the ladder" {
    var rig: Rig = undefined;
    var r = try rig.init(.gitea, &.{}, &.{});
    defer rig.deinit(&r);
    try rig.server.reply("UpdateTask", "200 OK", "{\"state\":{\"id\":\"7\",\"result\":\"RESULT_CANCELLED\"}}");
    try std.testing.expect(!rig.cancel.requested.load(.acquire));
    try r.reportState(rig.arena.allocator(), .unspecified);
    try std.testing.expect(rig.cancel.requested.load(.acquire));
    try std.testing.expectEqual(dagger.Cancel.Why.github, rig.cancel.why.load(.acquire));
    try std.testing.expect(rig.cancel.hard_deadline_ms.load(.acquire) > 0);
    try std.testing.expect(has(rig.out.written(), "the instance ended the task (cancelled)"));
    try std.testing.expectEqual(Result.cancelled, r.server_result);
}

test "an output the instance has not accepted keeps the end from finishing, until it has" {
    var rig: Rig = undefined;
    var r = try rig.init(.gitea, &.{}, &.{});
    defer rig.deinit(&r);
    try r.setOutputs(&.{.{ .name = "k", .value = "v" }});
    try rig.server.reply("UpdateTask", "200 OK", "{\"state\":{}}");
    try rig.server.reply("UpdateTask", "200 OK", "{\"state\":{},\"sentOutputs\":[\"k\"]}");
    try std.testing.expectError(error.OutputsNotAccepted, r.reportState(rig.arena.allocator(), .success));
    try r.reportState(rig.arena.allocator(), .success);
    // Sent while it was not accepted, and not again once it was.
    try std.testing.expect(has(rig.server.nth("UpdateTask", 1).body, "\"outputs\":{\"k\":\"v\"}"));
    try r.reportState(rig.arena.allocator(), .success);
    try std.testing.expect(!has(rig.lastTask(), "outputs"));
}

test "steps are given results the way the instances want them" {
    const cancelled = true;
    try std.testing.expectEqual(Result.success, stepResult(.{ .outcome = .success }, false));
    try std.testing.expectEqual(Result.failure, stepResult(.{ .outcome = .failure }, false));
    // A failure `continue-on-error` allowed is GitHub's conclusion: a success.
    try std.testing.expectEqual(Result.success, stepResult(.{ .outcome = .failure, .continued = true }, false));
    try std.testing.expectEqual(Result.cancelled, stepResult(.{ .outcome = .cancelled }, false));
    try std.testing.expectEqual(Result.skipped, stepResult(.{ .outcome = .skipped }, cancelled));
    try std.testing.expectEqual(Result.skipped, stepResult(.{ .outcome = .not_run }, false));
    try std.testing.expectEqual(Result.cancelled, stepResult(.{ .outcome = .not_run }, cancelled));
    const none: []dagger.StepResult = &.{};
    try std.testing.expectEqual(Result.success, jobResult(.{ .steps = none, .engine_error = null, .succeeded = true }));
    try std.testing.expectEqual(Result.failure, jobResult(.{ .steps = none, .engine_error = null, .succeeded = false }));
    // Cancelled wins, whatever the steps did before it.
    try std.testing.expectEqual(Result.cancelled, jobResult(.{ .steps = none, .engine_error = null, .succeeded = true, .cancelled = true }));
}

test "pre and post steps are listed where the instance wants them, and a step never run is skipped" {
    var rig: Rig = undefined;
    var r = try rig.init(.gitea, &.{ "act", "skipped" }, &.{});
    defer rig.deinit(&r);
    const o = r.observer();
    o.extraStartedFn.?(o.ptr, .pre, 3, "Pre act", 500);
    o.startedFn(o.ptr, 1, "act", 1_000);
    o.extraStartedFn.?(o.ptr, .post, 4, "Post act", 2_000);
    const extra = [_]dagger.ExtraStep{
        .{ .kind = .pre, .name = "Pre act", .log_step = 3, .outcome = .success, .started_ms = 500, .completed_ms = 600 },
        .{ .kind = .post, .name = "Post act", .log_step = 4, .outcome = .success, .started_ms = 2_000, .completed_ms = 2_100 },
    };
    const steps = [_]dagger.StepResult{
        .{ .name = "act", .outcome = .success, .started_ms = 1_000, .completed_ms = 1_500 },
        .{ .outcome = .skipped },
    };
    r.beginComplete(5, 2_200);
    try r.finish(rig.arena.allocator(), .success, .{ .steps = @constCast(&steps), .engine_error = null, .succeeded = true, .extra = &extra }, &.{});
    const body = rig.lastTask();
    const pre = std.mem.indexOf(u8, body, "\"name\":\"Pre act\"").?;
    const main = std.mem.indexOf(u8, body, "\"name\":\"act\"").?;
    const post = std.mem.indexOf(u8, body, "\"name\":\"Post act\"").?;
    const done = std.mem.indexOf(u8, body, "STEP_STAGE_CLEANUP").?;
    try std.testing.expect(pre < main and main < post and post < done);
    // The post step belongs to step 0, and the step that never ran is skipped, not left open.
    try std.testing.expect(has(body, "\"stage\":\"STEP_STAGE_POST\""));
    try std.testing.expect(has(body, "\"id\":\"1\",\"result\":\"RESULT_SKIPPED\""));
}

test "a step's header, logged just before the backend says it began, is the step's own row" {
    var rig: Rig = undefined;
    var r = try rig.init(.gitea, &.{ "one", "two" }, &.{});
    defer rig.deinit(&r);
    const o = r.observer();
    const l = r.listener();
    o.startedFn(o.ptr, 1, "one", 1_000);
    l.onLine(l.ptr, 1, 1, "out of one");
    // Step 2's header comes first, and a late line of the setup after it.
    l.onLine(l.ptr, 2, 1, "##[group]Run two");
    o.startedFn(o.ptr, 2, "two", 1_100);
    l.onLine(l.ptr, 0, 9, "late setup note");
    try std.testing.expectEqual(@as(i64, 1), r.steps.items[1].log_length);
    try std.testing.expectEqual(@as(i64, 2), r.steps.items[2].log_length);
    try std.testing.expectEqual(@as(i64, 1), r.steps.items[2].log_index);
    try std.testing.expectEqual(@as(i64, 0), r.steps.items[0].log_length);
}
