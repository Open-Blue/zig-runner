//! Runs a job's steps through Dagger (DESIGN §4, SPEC §6).
//!
//! One long-lived Dagger session hosts the whole job: the runner starts `dagger run`, which runs a
//! tiny child that prints the session's port and token and then waits. The runner then speaks
//! GraphQL to that session over HTTP (as the Dagger SDKs do), one query per step, threading the
//! container through by id. Container ids only live as long as the session, which is why this is
//! not one `dagger query` per step.
//!
//! Compared to a single query for the whole job this lets the runner decide what to run next from
//! earlier results (conditions, expressions, step outputs), and `withExec(expect: ANY)` returns the
//! real exit code and separate stdout/stderr, even for steps served from Dagger's cache.
//!
//! Live output comes from `dagger run`'s progress log on stderr, read by a reader task. Each step's
//! script brackets its output with marker lines so lines can be attributed to the step:
//!
//!     <marker>begin N <mark>      <marker>end N <mark>
//!
//! `<mark>` is the job's secret (`mark_env`), so a step cannot forge another step's markers by
//! printing text; see `scan`.
//!
//! Dagger's log frontend may repeat a span's header when it switches spans, so lines are attributed
//! to the step named in the most recent span header (a single line that contains the step's `begin`
//! marker text), not simply the last `begin`. A step served
//! from cache prints no log lines at all; its stdout/stderr from the query result are replayed.
const std = @import("std");
const job_mod = @import("job.zig");
const sink = @import("sink.zig");
const redact = @import("redact.zig");
const broker = @import("github/broker.zig");
const build_version = @import("version.zig");
const expr = @import("expr.zig");
const context = @import("context.zig");
const commands = @import("commands.zig");
const config = @import("config.zig");
const zig_release = @import("zig_release.zig");
const engine = @import("engine.zig");
const Query = @import("dagger/query.zig").Query;
const basePlan = @import("dagger/set_up.zig").basePlan;
const baseContainerId = @import("dagger/set_up.zig").baseContainerId;
const Base = @import("dagger/set_up.zig").Base;
pub const Backend = @import("native/Backend.zig");
const docker_action = @import("native/docker_action.zig");
const execFor = @import("dagger/set_up.zig").execFor;
const setUpJob = @import("dagger/set_up.zig").setUpJob;
const package_cache_dirs = @import("dagger/set_up.zig").package_cache_dirs;
const warmBase = @import("dagger/set_up.zig").warm;
pub const Warmed = @import("dagger/set_up.zig").Warmed;
const JobLog = @import("dagger/JobLog.zig");
pub const Marker = @import("dagger/JobLog.zig").Marker;
pub const Scan = @import("dagger/JobLog.zig").Scan;
pub const scan = @import("dagger/JobLog.zig").scan;
const readLogs = @import("dagger/JobLog.zig").readLogs;
const SpanDemux = @import("dagger/JobLog.zig").SpanDemux;
const awaitLiveOrReplay = @import("dagger/JobLog.zig").awaitLiveOrReplay;
pub const reused_note = @import("dagger/JobLog.zig").reused_note;
pub const native_reused_note = @import("dagger/JobLog.zig").native_reused_note;
const noteReusedSteps = @import("dagger/JobLog.zig").noteReusedSteps;
const Evaluator = @import("dagger/Evaluator.zig");
const StepCtx = @import("dagger/Evaluator.zig").StepCtx;
const checkout = @import("dagger/checkout.zig");
pub const stepScript = @import("dagger/scripts.zig").stepScript;
const stream_prologue = @import("dagger/scripts.zig").stream_prologue;
const writeMarkerEcho = @import("dagger/scripts.zig").writeMarkerEcho;
const shellLine = @import("dagger/scripts.zig").shellLine;
const secretAlias = @import("dagger/scripts.zig").secretAlias;
const FakeSession = @import("dagger/testing.zig").FakeSession;
const fake_child = @import("dagger/testing.zig").fake_child;
const base_answer = @import("dagger/testing.zig").base_answer;
const exec = @import("dagger/testing.zig").exec;
const execFc = @import("dagger/testing.zig").execFc;
const testStep = @import("dagger/testing.zig").testStep;
const testJob = @import("dagger/testing.zig").testJob;
const fileAnswer = @import("dagger/testing.zig").fileAnswer;
const treeAnswer = @import("dagger/testing.zig").treeAnswer;
const usesStep = @import("dagger/testing.zig").usesStep;
const braceBalanced = @import("dagger/testing.zig").braceBalanced;
const expectSecretOnlyInSetSecret = @import("dagger/testing.zig").expectSecretOnlyInSetSecret;

const Allocator = std.mem.Allocator;

/// The image a job runs in without `container:`, and the shared base every job's chain starts
/// from (set_up.zig provisions it). Pinned by its multi-arch index digest, which a moved tag cannot
/// change: one pin serves amd64 and arm64/v8, as for `busybox_image`. Renovate moves the pin
/// (renovate.json), and CI checks on every pull request that it is still an index for both
/// (.github/scripts/ubuntu-pin.sh), which prints the digest too.
pub const default_image = "ubuntu:24.04" ++
    "@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852";
/// The default image's name, which a workflow's `container:` or the config's image may give:
/// `resolveImage` makes it the pinned image, so it is provisioned and keyed as the default is.
pub const default_image_name = default_image[0..std.mem.indexOfScalar(u8, default_image, '@').?];

/// `default_image` for its bare name, any other image as given (a custom tag or digest is the
/// user's choice, used as is and not provisioned).
pub fn resolveImage(image: []const u8) []const u8 {
    return if (std.mem.eql(u8, image, default_image_name)) default_image else image;
}

/// An image without its digest: what binaries built in it depend on (its release), not which
/// rebuild of it the pin names.
pub fn imageName(image: []const u8) []const u8 {
    const at = std.mem.indexOfScalar(u8, image, '@') orelse return image;
    return image[0..at];
}
/// Where a Docker action sees the job's workspace, as on GitHub.
pub const docker_workspace = "/github/workspace";
/// GitHub's runner works under /home/runner/work; a `container:` job sees it as /__w.
pub const work_root = "/home/runner/work";
const container_work_root = "/__w";

/// The job's workspace, where GitHub's runner puts it: `<work>/<repo>/<repo>` (checked next to
/// `ubuntu-latest`). Scripts and tools that record absolute paths then see the same ones.
pub fn jobWorkspace(arena: Allocator, job: job_mod.Job) ![]const u8 {
    const repo = job.github.repository;
    const name = if (std.mem.lastIndexOfScalar(
        u8,
        repo,
        '/',
    )) |i| repo[i + 1 ..] else if (repo.len > 0) repo else "workspace";
    return std.fmt.allocPrint(arena, "{s}/{s}/{s}", .{ jobWorkRoot(job), name, name });
}

/// RUNNER_TEMP: `<work>/_temp`, as on GitHub.
pub fn jobTemp(arena: Allocator, job: job_mod.Job) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/_temp", .{jobWorkRoot(job)});
}

fn jobWorkRoot(job: job_mod.Job) []const u8 {
    return if (job.container != null) container_work_root else work_root;
}
pub const marker = "::zig-step::";

/// The user steps run as in the default image with `Options.step_user = .runner`, as on GitHub's
/// hosted runners: uid 1001, home /home/runner, passwordless sudo, and /github (the workspace, file
/// commands, the event) its own. Tests that expect file permissions to hold (writing a 0400 file
/// fails) behave as on GitHub; root ignores them.
pub const runner_user = "runner";
pub const runner_home = "/home/runner";

pub fn shellQuote(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('\'');
    for (s) |c| {
        if (c == '\'') try w.writeAll("'\\''") else try w.writeByte(c);
    }
    try w.writeByte('\'');
}

/// Evaluates an `if:` condition. Null when v0 cannot evaluate it. `job_failed` is true once a step
/// failed without continue-on-error.
pub fn evalCondition(cond: []const u8, job_failed: bool) ?bool {
    const c = std.mem.trim(u8, cond, " ");
    if (std.mem.eql(u8, c, "success()")) return !job_failed;
    if (std.mem.eql(u8, c, "always()")) return true;
    if (std.mem.eql(u8, c, "failure()")) return job_failed;
    if (std.mem.eql(u8, c, "cancelled()")) return false;
    return null;
}

/// A checkout step after its repository was fetched, or failed to be.
pub const Fetched = struct {
    /// Dagger Directory id of the fetched tree, or why it could not be fetched.
    result: union(enum) { dir: []const u8, failed: []const u8 },
    repo: []const u8,
    /// What was checked out, for the log (a short sha or the requested ref).
    ref_label: []const u8,
    /// Absolute directory inside the container.
    mount: []const u8,
    /// The ref the checkout stands for (`refs/heads/main`, `refs/pull/7/merge`, a bare name from
    /// `with: ref:`), or null for a sha or a repository's default branch. See
    /// `checkout.refCommands`.
    git_ref: ?[]const u8 = null,
    /// What was asked for, for the step's log: the URL, the ref or commit, the depth and tags.
    url: []const u8 = "",
    want: []const u8 = "",
    depth: u32 = 1,
    tags: bool = false,
    /// What fetched it, for the step's log: Dagger's git, or git in the image on the native
    /// backend (`Backend.fetchCheckout`).
    fetched_with: []const u8 = "Dagger's git support",
};

/// A step with its expressions evaluated, ready to become a script.
pub const Resolved = union(enum) {
    run: struct {
        script: []const u8,
        /// `bash`, `sh`, or null for the default.
        shell: ?[]const u8,
        working_directory: ?[]const u8,
        env: []const job_mod.EnvVar,
        /// Names of env variables whose values are Dagger secrets. The `i`th arrives in the
        /// container as `ZIG_SECRET_<i>` and the script gives it its real name (any name works, see
        /// `secretAlias`).
        secret_env: []const []const u8 = &.{},
        /// Set for steps that must run every time (they use secrets or read run-specific values): a
        /// line with a per-run value, so the step never matches an earlier run's cache entry.
        always_run: ?[]const u8 = null,
        /// Write the event payload from the volatile ZIG_RUNNER_EVENT variable to
        /// GITHUB_EVENT_PATH.
        write_event: bool = false,
        /// Give this step `volatile_sentinel` in place of the run-specific values (see
        /// `Options.enforce_volatile`). Set for a step that is *not* always-run, where a real value
        /// would be one it could read without the runner knowing and be replayed with.
        withhold_volatile: bool = false,
        /// The script holds a secret, so its file (`scripts.scriptPath`) is a mounted Dagger
        /// secret instead of being written by the command, which the engine keeps (#101).
        script_mounted: bool = false,
        /// The working directory holds a secret, so it is a Dagger secret attached under this
        /// alias (`secretAlias`) and `working_directory` is null: in the command, its `cd`
        /// would be in the engine's cache metadata (#102).
        working_directory_alias: ?[]const u8 = null,
    },
    checkout: Fetched,
};

/// The static busybox that Docker actions, service containers and output keys run their scripts
/// with (`Exec.busyboxFileFor`). Pinned by the multi-arch index digest, which a moved tag cannot
/// change (#107): one pin serves amd64 and arm64/v8, the engine picking its platform from the
/// index. Renovate moves the pin (renovate.json), and CI checks on every pull request that it is
/// still a pullable index with the applets the runner uses (.github/scripts/busybox-pin.sh). By
/// hand, `docker buildx imagetools inspect busybox:1.37.0-musl` prints the index digest.
pub const busybox_image = "busybox:1.37.0-musl" ++
    "@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478";
/// Where a Docker action's container gets its static busybox, and HOME (shared by the job's Docker
/// actions, as GitHub mounts one /github/home into each).
pub const busybox_path = "/github/_runtime/busybox";
pub const docker_home = "/github/home";

/// Inputs as INPUT_<NAME> (upper case, spaces as underscores, as `@actions/core` reads them).
pub fn inputEnv(arena: Allocator, inputs: []const expr.Value.Entry) ![]const job_mod.EnvVar {
    const out = try arena.alloc(job_mod.EnvVar, inputs.len);
    for (inputs, out) |in, *dst| {
        const name = try std.ascii.allocUpperString(
            arena,
            try std.mem.replaceOwned(u8, arena, in.key, " ", "_"),
        );
        dst.* = .{
            .name = try std.fmt.allocPrint(arena, "INPUT_{s}", .{name}),
            .value = in.value.string,
        };
    }
    return out;
}

/// The inputs an action gets, for the log as GitHub shows them: every one with a value (given or
/// defaulted), in the action's order, then any it does not declare.
pub fn shownInputs(arena: Allocator, inputs: []const expr.Value.Entry) ![]const job_mod.EnvVar {
    var out: std.ArrayList(job_mod.EnvVar) = .empty;
    for (inputs) |in| if (in.value == .string and in.value.string.len > 0) {
        try out.append(arena, .{ .name = in.key, .value = in.value.string });
    };
    return out.items;
}

/// The strings of a JSON array (an image's entrypoint or command); empty for anything else.
pub fn jsonStrings(arena: Allocator, v: ?std.json.Value) ![]const []const u8 {
    const arr = v orelse return &.{};
    if (arr != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (arr.array.items) |item| if (item == .string) try out.append(arena, item.string);
    return out.items;
}

pub const Outcome = enum { not_run, success, failure, skipped, cancelled };

pub const StepResult = struct {
    /// The step's display name with expressions evaluated; empty when it was never evaluated.
    name: []const u8 = "",
    /// Whether `continue-on-error` applied (evaluated), so a failure does not fail the job.
    continued: bool = false,
    outcome: Outcome = .not_run,
    exit_code: i32 = 0,
    started_ms: i64 = 0,
    completed_ms: i64 = 0,
};

pub const Result = struct {
    steps: []StepResult,
    /// Set when the engine itself failed (pull error, session lost): what Dagger said.
    engine_error: ?[]const u8,
    /// False if any step failed without continue-on-error, or the engine failed before running
    /// them.
    succeeded: bool,
    /// GitHub cancelled the job while it ran (a cancel in the UI, or the job's `timeout-minutes`).
    cancelled: bool = false,
    /// The engine refused the job's session at first (`openSessionWaiting`): it was starting, so
    /// its cache may have been wiped, and the runner pre-warms it again (`loop.Warmer`).
    engine_waited: bool = false,
    /// Actions' `pre` and `post` scripts that ran, as GitHub shows them: steps of their own.
    extra: []const ExtraStep = &.{},
    /// The first log step number not used (see `ExtraStep.log_step`); 0 means `steps.len + 1`.
    next_log_step: u32 = 0,
    /// The job's outputs, evaluated after its steps (see `job_mod.Job.outputs`), and what to log
    /// about them in "Complete job".
    outputs: []const job_mod.EnvVar = &.{},
    output_lines: []const []const u8 = &.{},
    /// `environment.url`, evaluated after the steps, for completejob; null when there is none or
    /// it was not set (see `environmentUrl`).
    environment_url: ?[]const u8 = null,
    annotations: []const Annotation = &.{},
    /// $GITHUB_STEP_SUMMARY per log step (index = log step - 1; empty when none was written).
    summaries: []const []const u8 = &.{},
    /// With output keys: how many always-run steps keyed the steps after them on their output, how
    /// many fell back, and why the last one did. For the runner's own log, so an operator sees how
    /// often they apply without turning on step debug.
    output_keys: struct {
        applied: u32 = 0,
        fell_back: u32 = 0,
        last_reason: []const u8 = "",
        ms: i64 = 0,
    } = .{},
    /// "Set up job" failed (an action could not be resolved), so no step ran.
    set_up_failed: bool = false,
};

/// An annotation and the log step it came from (mapped to GitHub's step number at completion).
pub const Annotation = struct { step: u32, an: commands.Annotation };

/// The largest answer to an exec's query read with its recorded output in it (`Exec.Recorded`): a
/// step served from the cache with more output than this is not replayed. The answer is held about
/// three times over while it is read and parsed, so this keeps a step's cost in the low tens of MB.
pub const max_recorded_bytes = 4 * 1024 * 1024;

/// A `pre` or `post` script that ran: a step of its own in GitHub's list ("Pre Run x@v1",
/// "Post Run x@v1"). Its lines are logged under `log_step`, a number after the job's own steps
/// (0 is "Set up job", 1..n the job's steps).
pub const ExtraKind = enum { pre, post, initialize, stop };

pub const ExtraStep = struct {
    /// `initialize` and `stop` are "Initialize containers" and "Stop containers", which GitHub
    /// lists with the pre and post steps but numbers apart from them (see `upload.shownSteps`).
    kind: ExtraKind,
    name: []const u8,
    log_step: u32,
    outcome: Outcome,
    started_ms: i64,
    completed_ms: i64,
};

/// Log step numbers a job can use: its steps, at most one `pre` and one `post` each, and
/// "Initialize containers" and "Stop containers" for its services.
pub fn logSteps(n: usize) usize {
    return n * 3 + 3;
}

/// Sends one GraphQL document to the Dagger session and returns the response body.
pub const Transport = struct {
    ptr: *anyopaque,
    /// The answer to `doc`, or `error.ResponseTooLarge` once it is past `limit` bytes.
    sendFn: *const fn (
        ptr: *anyopaque,
        arena: Allocator,
        doc: []const u8,
        limit: usize,
    ) anyerror![]const u8,
    /// Ends the document being sent, from another task, so `send` fails; false when none was in
    /// flight. Null when the transport cannot (the `dagger run` CLI): steps then run to their end.
    abortFn: ?*const fn (ptr: *anyopaque) bool = null,

    fn send(t: Transport, arena: Allocator, doc: []const u8, limit: usize) ![]const u8 {
        return t.sendFn(t.ptr, arena, doc, limit);
    }

    fn abort(t: Transport) bool {
        return if (t.abortFn) |f| f(t.ptr) else false;
    }
};

/// Set by the runner when the job is cancelled (GitHub's `JobCancellation` message, GitHub no
/// longer having the job, or the runner stopping), read by the job.
pub const Cancel = struct {
    requested: std.atomic.Value(bool) = .init(false),
    /// When whatever still runs is stopped too (the grace period GitHub gives after a cancel), in
    /// ms since the epoch; 0 for none.
    hard_deadline_ms: std.atomic.Value(i64) = .init(0),

    /// Cancels the job, with whatever still runs after it stopped at `hard_deadline_ms`. Called
    /// from the runner's tasks, possibly more than once (GitHub cancels, then the runner stops):
    /// the earliest deadline holds, so a later, longer grace period never extends a shorter one.
    pub fn request(c: *Cancel, hard_deadline_ms: i64) void {
        var cur = c.hard_deadline_ms.load(.acquire);
        while (cur == 0 or hard_deadline_ms < cur) {
            cur = c.hard_deadline_ms.cmpxchgWeak(cur, hard_deadline_ms, .acq_rel, .acquire) orelse
                break;
        }
        c.requested.store(true, .release);
    }
};

/// Stops a step that runs past its `timeout-minutes`, or that is running when the job is cancelled
/// and whose condition no longer holds (`survivesCancel`), by aborting the step's query (the
/// engine then cancels the exec). A task of its own checks every 200 ms; `begin` and `end` bracket
/// each step, so an interrupt meant for one step never reaches the next.
const Watch = struct {
    io: std.Io,
    transport: Transport,
    cancel: ?*Cancel,
    mu: std.Io.Mutex = .init,
    in_step: bool = false,
    deadline_ms: i64 = 0,
    /// The running step keeps running through a cancel, until the grace period ends
    /// (`survivesCancel`).
    survives_cancel: bool = false,
    /// A cancel arrived while this step ran and its query is still to be aborted.
    cancel_pending: bool = false,
    cancel_seen: bool = false,
    interrupt: Interrupt = .none,
    done: std.atomic.Value(bool) = .init(false),

    const Interrupt = enum { none, timed_out, cancelled };

    fn begin(w: *Watch, deadline_ms: i64, survives_cancel: bool) void {
        w.mu.lockUncancelable(w.io);
        defer w.mu.unlock(w.io);
        w.in_step = true;
        w.deadline_ms = deadline_ms;
        w.survives_cancel = survives_cancel;
        w.interrupt = .none;
        w.cancel_pending = false;
    }

    /// How the step was interrupted, if it was.
    fn end(w: *Watch) Interrupt {
        w.mu.lockUncancelable(w.io);
        defer w.mu.unlock(w.io);
        w.in_step = false;
        w.deadline_ms = 0;
        w.survives_cancel = false;
        w.cancel_pending = false;
        defer w.interrupt = .none;
        return w.interrupt;
    }

    fn run(w: *Watch) void {
        while (!w.done.load(.acquire)) {
            w.io.sleep(.fromMilliseconds(200), .awake) catch return;
            w.tick(std.Io.Clock.real.now(w.io).toMilliseconds());
        }
    }

    fn tick(w: *Watch, now: i64) void {
        w.mu.lockUncancelable(w.io);
        defer w.mu.unlock(w.io);
        if (w.cancel) |c| {
            if (!w.cancel_seen and c.requested.load(.acquire)) {
                w.cancel_seen = true;
                w.cancel_pending = w.in_step and !w.survives_cancel;
            }
            const hard = c.hard_deadline_ms.load(.acquire);
            // Past the grace period nothing runs on: whatever is in flight is ended.
            if (w.cancel_seen and hard > 0 and now > hard) w.cancel_pending = true;
        }
        if (w.cancel_pending and w.transport.abort()) {
            w.interrupt = .cancelled;
            w.cancel_pending = false;
            return;
        }
        if (w.in_step and w.deadline_ms > 0 and now > w.deadline_ms and w.transport.abort()) {
            w.interrupt = .timed_out;
            w.deadline_ms = 0;
        }
    }
};

/// Told when each step starts and finishes, so run state can be recorded at those transitions.
pub const Observer = struct {
    ptr: *anyopaque,
    startedFn: *const fn (ptr: *anyopaque, number: u32, name: []const u8, started_ms: i64) void,
    finishedFn: *const fn (ptr: *anyopaque, number: u32, result: StepResult) void,
    /// The steps the runner adds ("Pre ...", "Post ...", "Initialize containers", "Stop
    /// containers"), by log step (see `ExtraStep`); optional.
    extraStartedFn: ?*const fn (
        ptr: *anyopaque,
        kind: ExtraKind,
        log_step: u32,
        name: []const u8,
        started_ms: i64,
    ) void = null,
    extraFinishedFn: ?*const fn (ptr: *anyopaque, e: ExtraStep) void = null,
    /// Before the post steps: how many will run, and whether "Stop containers" follows (GitHub
    /// numbers them apart from the steps before, see `upload.shownSteps`).
    postsFn: ?*const fn (ptr: *anyopaque, posts: u32, stop: bool) void = null,

    fn started(o: Observer, number: u32, name: []const u8, started_ms: i64) void {
        o.startedFn(o.ptr, number, name, started_ms);
    }
    fn finished(o: Observer, number: u32, result: StepResult) void {
        o.finishedFn(o.ptr, number, result);
    }
};

pub const Options = struct {
    observer: ?Observer = null,
    /// The `dagger` command.
    dagger_cmd: []const u8 = "dagger",
    image: []const u8 = default_image,
    /// Installed into the image before the job (one cached exec). Used for the default image only,
    /// which has no git; a custom image is expected to bring what it needs.
    provision: bool = true,
    /// Key under which output lines are written to the sink.
    sink_job_id: u64 = 0,
    /// The name the runner registered under (`runner.name`, RUNNER_NAME).
    runner_name: []const u8 = "zig-runner",
    /// What runs JavaScript actions.
    js_runtime: config.JsRuntime = .bun,
    /// Steps may use the job's Dagger engine (`dagger call` inside a step):
    /// `experimentalPrivilegedNesting`. Only in a job the runner vouches for (`trusted`, and not
    /// a fork's pull request): a step's own client could open any cache volume by its key (#228).
    nesting: bool = false,
    /// Mount `package_cache_dirs` from persistent cache volumes, scoped to the repository. The
    /// runner turns this on (`RUNNER_PACKAGE_CACHES`, on by default).
    package_caches: bool = false,
    /// `Config.tool_trees`: "Set up job" checks the tool cache's trees and hands steps their
    /// digests (`set_up.verifyToolTrees`). Off here, on in the runner.
    tool_trees: bool = false,
    /// The runner vouches for the job (`trust.vouches`): its package caches and output-key store
    /// are the repository's shared `repo` volumes. Otherwise they are `untrusted` ones (see
    /// `packageCacheScope`).
    trusted: bool = false,
    /// Give a step that did not name a run-specific value `volatile_sentinel` instead of the real
    /// one, and `withheld_event` instead of the event payload. On by default: without it, such a step is replayed with an
    /// earlier run's value, which proofs/Runner/Enforce.agda shows is the one hypothesis behind
    /// step caching that the runner can discharge rather than assume.
    /// `RUNNER_ENFORCE_VOLATILE=false` restores GitHub's behaviour for a workflow that needs it.
    enforce_volatile: bool = true,
    /// Reuse unchanged steps' results across runs (see `volatile_env`). The runner turns this on
    /// (`RUNNER_STEP_CACHE`, on by default).
    step_cache: bool = false,
    /// Who steps run as in the default image (provisioned; see `runner_user`).
    step_user: config.StepUser = .root,
    /// Experimental, with `step_cache`: a step that always runs (it uses secrets) no longer makes
    /// every later step run too. What it changed is stored by content digest in a cache volume (see
    /// `Exec.outputKeyed`), and the next step starts from the container before it plus a copy of
    /// that content, so its key depends on what the step produced, not on the step having run. The
    /// runner turns this on with `RUNNER_OUTPUT_KEYS`.
    output_keys: bool = false,
    /// `Config.uv_env_in_cache`: uv's project environment goes inside its cache volume, in jobs
    /// whose steps are not cached (see `uvEnvFor`).
    uv_env_in_cache: bool = true,
    /// `Config.zig_local_cache`: Zig's local cache goes in a cache volume of its own.
    zig_local_cache: bool = false,
    /// `Config.zig_local_cache_max_mb`: past it, Zig's local cache starts over in a new generation
    /// (`set_up.rollZigLocal`). 0, the default here, keeps it in the volume's root, unbounded.
    zig_local_cache_max_mb: u32 = 0,
    /// `Config.zig_seeds`: the verified Zig releases Zig jobs' global cache is seeded from (see
    /// `set_up.zigSeedFor`); empty for none.
    zig_seeds: []const config.ZigSeed = &.{},
    /// `Config.zig_seeds_unverified`: releases left unseeded because they did not verify.
    zig_seeds_unverified: []const []const u8 = &.{},
    /// `Config.zig_seed_registry`: told the Zig versions a `repo` job's tool cache holds.
    zig_seed_registry: ?*zig_release.Registry = null,
    /// Stored outputs not produced again for this many days are removed
    /// (`RUNNER_OUTPUT_KEYS_DAYS`).
    output_keys_days: u32 = 7,
    /// Set by the runner when GitHub cancels the job.
    cancel: ?*Cancel = null,
    /// `RUNNER_BACKEND=native`: run the job on the native backend when it can
    /// (`Backend.unsupported`), else on Dagger with "Set up job" saying why.
    native: ?Backend.Config = null,
    /// Why a job that could have been native runs on Dagger, for "Set up job" (set by `run`).
    backend_note: ?[]const u8 = null,
    /// Talk to the Dagger engine directly (`engine.zig`) instead of through a `dagger run` child.
    engine: ?engine.Endpoint = null,
    /// Backs the direct session's long-lived buffers and tasks; must be thread-safe.
    gpa: Allocator = std.heap.smp_allocator,
    /// Tests only: replaces `dagger run ...` (it must print "<port> <token>" first) and the HTTP
    /// transport.
    test_session_argv: ?[]const []const u8 = null,
    test_transport: ?Transport = null,
    /// Tests: this job's `ran_env` value instead of a random one.
    test_ran_marker: ?[]const u8 = null,
    /// Tests: this job's `mark_env` value instead of a random one.
    test_step_mark: ?[]const u8 = null,
};

// --- the HTTP transport to the session ---

const HttpTransport = struct {
    io: std.Io,
    url: []const u8,
    auth: []const u8,

    fn send(ptr: *anyopaque, arena: Allocator, doc: []const u8, limit: usize) anyerror![]const u8 {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        var body: std.Io.Writer.Allocating = .init(arena);
        try body.writer.writeAll("{\"query\":");
        try std.json.Stringify.value(doc, .{}, &body.writer);
        try body.writer.writeByte('}');
        const r = try broker.request(arena, self.io, .POST, self.url, body.written(), .{
            .extra_headers = &.{.{ .name = "Authorization", .value = self.auth }},
            // A query runs as long as what it runs (a step's exec); the job's cancel ends it.
            .deadline = null,
            .max_body = limit,
        });
        // GraphQL errors can arrive with a non-2xx status; the body says what was wrong.
        if (r.status.class() != .success and r.body.len == 0) return error.DaggerSessionHttpError;
        return r.body;
    }
};

pub fn jsonFind(v: std.json.Value, key: []const u8) ?std.json.Value {
    if (v != .object) return null;
    var it = v.object.iterator();
    while (it.next()) |e| {
        if (std.mem.eql(u8, e.key_ptr.*, key)) return e.value_ptr.*;
        if (jsonFind(e.value_ptr.*, key)) |f| return f;
    }
    return null;
}

pub fn jsonFindString(v: std.json.Value, key: []const u8) ?[]const u8 {
    const f = jsonFind(v, key) orelse return null;
    return if (f == .string) f.string else null;
}

/// Runs a document and returns the parsed `data`, or the first GraphQL error message.
pub fn gql(arena: Allocator, t: Transport, doc: []const u8, err_msg: *[]const u8) !std.json.Value {
    return gqlAtMost(arena, t, doc, engine.no_limit, err_msg);
}

/// As `gql`, failing with `error.ResponseTooLarge` (and no `err_msg`) when the answer is past
/// `limit` bytes, before more than that is held.
pub fn gqlAtMost(
    arena: Allocator,
    t: Transport,
    doc: []const u8,
    limit: usize,
    err_msg: *[]const u8,
) !std.json.Value {
    const body = t.send(arena, doc, limit) catch |e| {
        if (e == error.ResponseTooLarge) return e;
        // Said in full: the runner gave up on the engine, and how to change that (#100).
        if (e == error.EngineSilent) {
            err_msg.* = "the Dagger engine went silent while this step ran (no health check, " ++
                "no answer and no log line for RUNNER_ENGINE_SILENCE_TIMEOUT), so the runner " ++
                "aborted its session; raise RUNNER_ENGINE_SILENCE_TIMEOUT, or set it to 0 to " ++
                "turn this off";
            return error.DaggerQueryFailed;
        }
        err_msg.* = try std.fmt.allocPrint(
            arena,
            "could not reach the Dagger session: {s}",
            .{@errorName(e)},
        );
        return error.DaggerQueryFailed;
    };
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch {
        err_msg.* = "Dagger returned a response that is not JSON";
        return error.DaggerQueryFailed;
    };
    if (root == .object) {
        if (root.object.get("errors")) |errs| if (errs == .array and errs.array.items.len > 0) {
            err_msg.* = jsonFindString(errs.array.items[0], "message") orelse
                "Dagger returned an error";
            return error.DaggerQueryFailed;
        };
        if (root.object.get("data")) |d| return d;
    }
    err_msg.* = "Dagger returned no data";
    return error.DaggerQueryFailed;
}

// --- secrets in the environment ---

/// Whether a value contains a secret. Such env values reach the step through a Dagger secret
/// (`withSecretVariable`), so they are not written into the command (which Dagger would keep in its
/// cache metadata and print in its progress log). Very short secret values are ignored: they would
/// match unrelated text.
pub fn containsSecret(job: job_mod.Job, value: []const u8) bool {
    for (job.secrets) |sec|
        if (sec.len >= min_secret_len and std.mem.indexOf(u8, value, sec) != null) return true;
    return false;
}

/// The shortest secret or mask that a value is checked for: a shorter one would match unrelated
/// text.
pub const min_secret_len = 3;

/// Whether a value contains a secret (`containsSecret`) or a value the job's steps masked so far
/// (`::add-mask::`, through `sh`; none before the first step). A step can pass a masked value on
/// through GITHUB_ENV, and it is then as secret as the job's own (#101).
pub fn holdsSecret(job: job_mod.Job, sh: ?*JobLog, value: []const u8) bool {
    if (containsSecret(job, value)) return true;
    const log = sh orelse return false;
    return log.holdsSecret(value, min_secret_len);
}

pub const SecretRef = struct { name: []const u8, id: []const u8 };

/// The Dagger secrets this job's session holds, by plaintext. A value is registered once per job,
/// however many steps use it (the job token reaches every action, a step's secret env every run of
/// it), and values first needed together are registered in one query.
pub const Secrets = struct {
    /// Secrets registered so far, for their names (`zig-secret-<n>`).
    counter: u32 = 0,
    ids: std.StringHashMapUnmanaged([]const u8) = .empty,
    /// The native backend's: values get their names without a session, and the native backend
    /// hands each step the value its name stands for (`Backend.execScript`).
    local: bool = false,

    /// The values in `plaintexts` not registered yet, each once.
    pub fn missing(s: *const Secrets, arena: Allocator, plaintexts: []const []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        for (plaintexts) |p| {
            if (s.ids.contains(p)) continue;
            for (out.items) |o| {
                if (std.mem.eql(u8, o, p)) break;
            } else try out.append(arena, p);
        }
        return out.items;
    }

    /// One `setSecret` per value in `pending` (from `missing`), aliased `zsec<i>`, as root fields of
    /// `q`, which must have nothing open.
    pub fn write(s: *const Secrets, arena: Allocator, q: *Query, pending: []const []const u8) !void {
        for (pending, 0..) |p, i| {
            const name = try std.fmt.allocPrint(arena, "zig-secret-{d}", .{s.counter + i + 1});
            const alias = try std.fmt.allocPrint(arena, "zsec{d}", .{i});
            try q.callAs(alias, "setSecret", .{ .name = name, .plaintext = p });
            try q.leaf("id");
            try q.close(1);
        }
    }

    /// The ids of `pending` from the answer to `write`'s fields. False when one is missing; none
    /// is kept then.
    pub fn read(s: *Secrets, arena: Allocator, data: std.json.Value, pending: []const []const u8) !bool {
        const ids = try arena.alloc([]const u8, pending.len);
        for (ids, 0..) |*id, i| {
            const f = jsonFind(data, try std.fmt.allocPrint(arena, "zsec{d}", .{i})) orelse
                return false;
            id.* = jsonFindString(f, "id") orelse return false;
        }
        for (pending, ids) |p, id| try s.ids.put(arena, p, id);
        s.counter += @intCast(pending.len);
        return true;
    }

    /// Registers the values not registered yet, in one query (none when there are none).
    pub fn register(
        s: *Secrets,
        arena: Allocator,
        t: Transport,
        plaintexts: []const []const u8,
        err_msg: *[]const u8,
    ) !void {
        const pending = try s.missing(arena, plaintexts);
        if (pending.len == 0) return;
        if (s.local) {
            for (pending) |p| {
                s.counter += 1;
                try s.ids.put(arena, p, try std.fmt.allocPrint(arena, "zig-secret-{d}", .{
                    s.counter,
                }));
            }
            return;
        }
        var q: Query = .init(arena);
        try s.write(arena, &q, pending);
        const data = try gql(arena, t, try q.finish(), err_msg);
        if (!try s.read(arena, data, pending)) {
            err_msg.* = "Dagger returned no secret id";
            return error.DaggerQueryFailed;
        }
    }
};

/// `plaintext` as a Dagger secret in this session: its id, registered if it is not yet.
pub fn newSecret(
    arena: Allocator,
    t: Transport,
    secrets: *Secrets,
    plaintext: []const u8,
    err_msg: *[]const u8,
) ![]const u8 {
    try secrets.register(arena, t, &.{plaintext}, err_msg);
    return secrets.ids.get(plaintext).?;
}

/// Splits env into plain variables and secret-bearing ones (`holdsSecret`, registered as Dagger
/// secrets, those not registered yet in one query).
pub fn splitEnv(
    arena: Allocator,
    t: Transport,
    job: job_mod.Job,
    sh: ?*JobLog,
    secrets: *Secrets,
    env: []const job_mod.EnvVar,
    plain: *std.ArrayList(job_mod.EnvVar),
    secret: *std.ArrayList(SecretRef),
    err_msg: *[]const u8,
) !void {
    var values: std.ArrayList([]const u8) = .empty;
    for (env) |e| if (holdsSecret(job, sh, e.value)) try values.append(arena, e.value);
    try secrets.register(arena, t, values.items, err_msg);
    for (env) |e| {
        if (holdsSecret(job, sh, e.value)) {
            try secret.append(arena, .{ .name = e.name, .id = secrets.ids.get(e.value).? });
        } else {
            try plain.append(arena, e);
        }
    }
}

// --- running a job ---

/// Prints the session's port and token for the runner, then waits for stdin to close.
const session_script = "printf '%s %s\\n' \"$DAGGER_SESSION_PORT\" \"$DAGGER_SESSION_TOKEN\"; " ++
    "cat >/dev/null";

fn base64Encode(arena: Allocator, s: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const buf = try arena.alloc(u8, enc.calcSize(s.len));
    return enc.encode(buf, s);
}

pub fn run(
    arena: Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    opts_in: Options,
    job: job_mod.Job,
    log: *sink.LogSink,
) !Result {
    var opts = opts_in;
    if (opts.native) |cfg| {
        // What the job uses, then what this machine can do (found once per process).
        const why = Backend.unsupported(io, job, opts, cfg) orelse
            try docker_action.unsupported(arena, opts.gpa, io, job, cfg) orelse
            Backend.usable(arena, io, opts.gpa, cfg);
        if (why) |w| {
            opts.backend_note = try std.fmt.allocPrint(arena, "This job runs on Dagger: {s}.", .{
                w,
            });
        } else if (try runNative(arena, io, opts, cfg, job, log, &opts.backend_note)) |r| {
            return r;
        } else if (cfg.gate) |g| {
            // Native set the job up (its cgroup told the gate) and then sent it here (P7's
            // preload): the gate measures it on the engine again, learning nothing from it.
            g.backToEngine();
        }
    }
    var env = try environ.clone(arena);
    try env.put("NO_COLOR", "1");
    try env.put("DAGGER_NO_NAG", "1");
    try env.put("GIT_TERMINAL_PROMPT", "0");

    const results = try arena.alloc(StepResult, job.steps.len);
    @memset(results, .{});
    var sh = try jobLogFor(arena, io, opts, job, log);

    if (opts.engine) |ep|
        if (opts.test_transport == null) return runDirect(arena, io, opts, job, &sh, results, ep);

    const argv: []const []const u8 = opts.test_session_argv orelse
        &.{ opts.dagger_cmd, "run", "--progress=logs", "sh", "-c", session_script };
    var child = try std.process.spawn(
        io,
        .{ .argv = argv, .environ_map = &env, .stdin = .pipe, .stdout = .pipe, .stderr = .pipe },
    );
    // The reader must run while we wait on queries. It owns stderr: `wait` closes the pipes the
    // child still holds, and closing this one under the reader let it read whatever file next got
    // the descriptor (ThreadSanitizer, `zig build test -Dsanitize-thread`).
    const stderr = child.stderr.?;
    child.stderr = null;
    var reader = io.concurrent(readLogs, .{ io, &sh, stderr }) catch |e| {
        stderr.close(io);
        child.kill(io);
        return e;
    };
    // Order matters: closing stdin ends the session child and `dagger run`, which gives the reader
    // EOF. Only then has every live line arrived, so only then can reused steps be told apart.
    defer {
        if (child.stdin) |f| f.close(io);
        child.stdin = null;
        reader.await(io);
        stderr.close(io);
        _ = child.wait(io) catch {};
        noteReusedSteps(&sh, reused_note);
        sh.flush();
    }

    var http = switch (try sessionTransport(arena, io, &child, &sh, results)) {
        .failed => |result| return result,
        .transport => |t| t,
    };
    const transport: Transport = opts.test_transport orelse
        .{ .ptr = &http, .sendFn = HttpTransport.send };
    return runSteps(arena, io, opts, job, &sh, results, transport, null);
}

/// The job on the native backend (`native/Backend.zig`): no Dagger session, the same steps code.
/// The step cache is the native layer store's (`native/Store.zig`). What the native backend has
/// no counterpart for yet is off for the job: output keys, and the tool cache's checked trees (a
/// replayed step that points into the tool cache's volume runs again, `Exec.tool_cache`). They
/// are caches, so a job's results do not depend on them. The cache volumes, Zig's local cache
/// and seeds are the backend's own (`native/volumes.zig`): off here for the shared code, which
/// would ask a Dagger session for them, and handed to the backend as they were. Null when the
/// job runs on Dagger after all, with `dagger_note` saying why.
fn runNative(
    arena: Allocator,
    io: std.Io,
    opts_in: Options,
    cfg: Backend.Config,
    job: job_mod.Job,
    log: *sink.LogSink,
    dagger_note: *?[]const u8,
) !?Result {
    var opts = opts_in;
    opts.output_keys = false;
    opts.package_caches = false;
    opts.zig_local_cache = false;
    opts.zig_seeds = &.{};
    opts.zig_seeds_unverified = &.{};
    opts.zig_seed_registry = null;
    opts.tool_trees = false;
    const results = try arena.alloc(StepResult, job.steps.len);
    @memset(results, .{});
    var sh = try jobLogFor(arena, io, opts, job, log);
    defer sh.flush();
    // After the last step, as for a Dagger session: each replayed step's log ends with the note.
    defer noteReusedSteps(&sh, native_reused_note);
    var b = Backend.init(arena, io, opts.gpa, cfg) catch |e| {
        // A job the runner does not vouch for whose cgroup could not be made with its limits
        // after all (P4, P5's `job_limits`): not native, and not failed either.
        if (e == error.NoJobLimits) {
            dagger_note.* = "This job runs on Dagger: native steps run a job this runner does " ++
                "not vouch for only within a cgroup of its own with memory and process limits, " ++
                "which could not be made for it.";
            return null;
        }
        return try fail(
            &sh,
            results,
            try std.fmt.allocPrint(arena, "could not make the job's native store: {s}", .{
                @errorName(e),
            }),
        );
    };
    defer b.deinit();
    b.caches = .of(opts_in);
    // The runtime its JavaScript actions get, for the preload in the base (`native/actions.zig`).
    b.js_runtime = opts.js_runtime;
    // Which ids the job's steps have, as "Set up job" says (`Backend.idsNote`).
    opts.backend_note = try b.idsNote(arena);
    return runSteps(arena, io, opts, job, &sh, results, b.transport(), &b) catch |e| switch (e) {
        // What its `uses:` actions are is known once they are fetched, in the job's image as the
        // base pulled and provisioned it: one native cannot run yet sends the job to Dagger,
        // before anything is logged (`native/actions.zig`).
        error.NativeToDagger => {
            dagger_note.* = try std.fmt.allocPrint(arena, "This job runs on Dagger: {s}.", .{
                b.to_dagger,
            });
            return null;
        },
        else => return e,
    };
}

/// What every task of a job shares: the log, and one slot per log step — the job's steps, then
/// their `pre` and `post` scripts (see `ExtraStep`) — for live lines, endings, commands, replays
/// and counts, plus a buffer per service for its output.
fn jobLogFor(
    arena: Allocator,
    io: std.Io,
    opts: Options,
    job: job_mod.Job,
    log: *sink.LogSink,
) !JobLog {
    const n = logSteps(job.steps.len);
    const live = try arena.alloc(std.atomic.Value(u32), n);
    const ended = try arena.alloc(std.atomic.Value(bool), n);
    for (live, ended) |*l, *e| {
        l.* = .init(0);
        e.* = .init(false);
    }
    const replayed_steps = try arena.alloc(bool, n);
    @memset(replayed_steps, false);
    const step_commands = try arena.alloc(JobLog.StepCommands, n);
    @memset(step_commands, .{});
    const line_counts = try arena.alloc(u32, n);
    @memset(line_counts, 0);
    const service_logs = try arena.alloc(std.ArrayList([]const u8), job.services.len);
    @memset(service_logs, .empty);
    const service_dropped = try arena.alloc(u32, job.services.len);
    @memset(service_dropped, 0);
    const mark = opts.test_step_mark orelse mark: {
        var raw: [12]u8 = undefined;
        io.random(&raw);
        break :mark try arena.dupe(u8, &std.fmt.bytesToHex(raw, .lower));
    };
    return .{
        .io = io,
        .arena = arena,
        .log = log,
        .sink_job_id = opts.sink_job_id,
        .live_lines = live,
        .ended = ended,
        .mark = mark,
        .commands = step_commands,
        .replayed_steps = replayed_steps,
        .line_counts = line_counts,
        .service_logs = service_logs,
        .service_dropped = service_dropped,
        .step_debug = stepDebug(arena, job),
        .workspace = try jobWorkspace(arena, job),
    };
}

/// The session's HTTP endpoint, or the failed Result the job ends with when the session never
/// reported one.
const SessionStart = union(enum) { transport: HttpTransport, failed: Result };

/// From the first line of `dagger run`'s child: "<port> <token>".
fn sessionTransport(
    arena: Allocator,
    io: std.Io,
    child: *std.process.Child,
    sh: *JobLog,
    results: []StepResult,
) !SessionStart {
    var first: [512]u8 = undefined;
    var out_reader = child.stdout.?.readerStreaming(io, &first);
    const line = (out_reader.interface.takeDelimiter('\n') catch null) orelse {
        const why = "could not start a Dagger session (is the Docker daemon running?)";
        return .{ .failed = try fail(sh, results, why) };
    };
    var parts = std.mem.tokenizeScalar(u8, line, ' ');
    const port = parts.next() orelse
        return .{ .failed = try fail(sh, results, "Dagger session did not report a port") };
    const token = parts.next() orelse
        return .{ .failed = try fail(sh, results, "Dagger session did not report a token") };
    const basic = try std.fmt.allocPrint(arena, "{s}:", .{token});
    return .{ .transport = .{
        .io = io,
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{s}/query", .{port}),
        .auth = try std.fmt.allocPrint(arena, "Basic {s}", .{try base64Encode(arena, basic)}),
    } };
}

/// A job's session held by this process (`engine.zig`), with no `dagger run` child: queries go over
/// the session, and live output comes from its log stream, routed to steps by span (`SpanDemux`).
fn runDirect(
    arena: Allocator,
    io: std.Io,
    opts: Options,
    job: job_mod.Job,
    sh: *JobLog,
    results: []StepResult,
    ep: engine.Endpoint,
) !Result {
    var demux: SpanDemux = .{ .sh = sh, .gpa = opts.gpa };
    defer demux.deinit();
    var sess: engine.Session = undefined;
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    const waited = openSessionWaiting(
        arena,
        io,
        opts,
        &sess,
        ep,
        .{ .ptr = &demux, .onRecord = SpanDemux.onRecord },
        sh,
        opts.cancel,
        started,
    ) catch |e| return fail(sh, results, try engineOpenError(arena, e, ep));
    if (waited) sh.append(0, try engineAcceptedNote(arena, io, started));
    // Closing the session ends its log stream; only then has every live line arrived.
    defer {
        sess.close();
        demux.flushPartial();
        noteReusedSteps(sh, reused_note);
        sh.flush();
    }
    var st: SessionTransport = .{ .s = &sess };
    var res = try runSteps(
        arena,
        io,
        opts,
        job,
        sh,
        results,
        .{ .ptr = &st, .sendFn = SessionTransport.send, .abortFn = SessionTransport.abort },
        null,
    );
    res.engine_waited = waited;
    return res;
}

/// Told by `warm` once the engine accepted the session, before any query: false gives up (a
/// stop came while it waited), so nothing that waits for the engine holds what this hands out.
pub const Ready = struct {
    ptr: *anyopaque,
    readyFn: *const fn (ptr: *anyopaque) bool,
};

/// The pre-warm (`set_up.warm`) over a session of its own, with no job: waits for an engine
/// that is starting as a job does, then `ready`, then sends the documents, aborted when
/// `opts.cancel` is requested. Direct engines only. On failure the message is in `err_msg`.
pub fn warm(
    arena: Allocator,
    io: std.Io,
    opts: Options,
    ready: Ready,
    err_msg: *[]const u8,
) anyerror!Warmed {
    if (opts.test_transport) |t| {
        if (!ready.readyFn(ready.ptr)) return error.Cancelled;
        return warmBase(arena, t, opts, err_msg);
    }
    const ep = opts.engine orelse return error.NeedsDirectEngine;
    var sess: engine.Session = undefined;
    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    _ = try openSessionWaiting(arena, io, opts, &sess, ep, null, null, opts.cancel, started);
    defer sess.close();
    if (!ready.readyFn(ready.ptr)) return error.Cancelled;
    var st: SessionTransport = .{ .s = &sess };
    const transport: Transport = .{
        .ptr = &st,
        .sendFn = SessionTransport.send,
        .abortFn = SessionTransport.abort,
    };
    // A stop aborts the query, and the engine cancels the exec, as for a step.
    var watch: Watch = .{ .io = io, .transport = transport, .cancel = opts.cancel };
    watch.begin(0, false);
    var watching = io.concurrent(Watch.run, .{&watch}) catch null;
    defer if (watching) |*f| {
        watch.done.store(true, .release);
        f.cancel(io);
    };
    return warmBase(arena, transport, opts, err_msg);
}

/// `openSession`, waiting for an engine that is starting (just restarted, or updated) and refuses
/// connections, or has no socket yet, for up to a minute or so, as GitHub's runner waits for
/// Docker, rather than fail. Gives up after `engine_wait_ms` counted from `started`, or when
/// `cancel` is requested. Returns whether it waited; the first wait is noted in `sh` when there is
/// one.
fn openSessionWaiting(
    arena: Allocator,
    io: std.Io,
    opts: Options,
    sess: *engine.Session,
    ep: engine.Endpoint,
    h: ?engine.LogHandler,
    sh: ?*JobLog,
    cancel: ?*Cancel,
    started: i64,
) !bool {
    var waiting = false;
    while (true) {
        if (openSession(sess, opts, io, ep, h)) |_| {
            return waiting;
        } else |e| {
            const starting = switch (e) {
                error.ConnectionRefused, error.FileNotFound => true,
                error.ConnectionResetByPeer, error.EngineUnreachable => true,
                else => false,
            };
            const cancelled = if (cancel) |c| c.requested.load(.acquire) else false;
            if (!starting or cancelled or
                std.Io.Clock.awake.now(io).toMilliseconds() - started > engine_wait_ms)
                return e;
            if (!waiting) if (sh) |s| s.append(
                0,
                try std.fmt.allocPrint(arena, "Waiting for the Dagger engine to accept " ++
                    "connections ({s}): it may be starting", .{@errorName(e)}),
            );
            waiting = true;
            io.sleep(.fromSeconds(2), .awake) catch return e;
        }
    }
}

/// How long the engine took to accept the session, once it did after a wait.
fn engineAcceptedNote(arena: Allocator, io: std.Io, started: i64) ![]const u8 {
    const secs = @divTrunc(std.Io.Clock.awake.now(io).toMilliseconds() - started, 1000);
    return std.fmt.allocPrint(arena, "The Dagger engine accepted the session after {d} s.", .{
        secs,
    });
}

/// Opens a session, starting the engine container first if it exists but is stopped, and having the
/// `dagger` CLI create it (`dagger core version`) if it does not exist, as `dagger run` would.
/// How long a job waits for an engine that refuses connections (see `openSessionWaiting`).
const engine_wait_ms = 3 * 60 * 1000;

fn openSession(
    sess: *engine.Session,
    opts: Options,
    io: std.Io,
    ep: engine.Endpoint,
    h: ?engine.LogHandler,
) !void {
    sess.open(opts.gpa, io, ep, h) catch |e| switch (e) {
        error.EngineContainerNotRunning => {
            try engine.startContainer(opts.gpa, io, ep);
            return sess.open(opts.gpa, io, ep, h);
        },
        error.EngineContainerNotFound => {
            var child = std.process.spawn(
                io,
                .{
                    .argv = &.{ opts.dagger_cmd, "core", "version" },
                    .stdin = .ignore,
                    .stdout = .ignore,
                    .stderr = .ignore,
                },
            ) catch return e;
            _ = child.wait(io) catch return e;
            return sess.open(opts.gpa, io, ep, h);
        },
        else => return e,
    };
}

fn engineOpenError(arena: Allocator, e: anyerror, ep: engine.Endpoint) ![]const u8 {
    if (ep.host.len > 0) return std.fmt.allocPrint(
        arena,
        "could not start a Dagger session on the engine at {s}: {s}",
        .{ ep.host, @errorName(e) },
    );
    return switch (e) {
        error.EngineContainerNotFound => std.fmt.allocPrint(
            arena,
            "the Dagger engine container '{s}' does not exist and `dagger core version` did " ++
                "not create it (set RUNNER_ENGINE=cli to use the dagger CLI instead)",
            .{ep.container},
        ),
        error.FileNotFound, error.ConnectionRefused => std.fmt.allocPrint(
            arena,
            "could not reach the Docker API at {s} (is Docker running? DOCKER_HOST sets " ++
                "another socket)",
            .{ep.docker_socket},
        ),
        else => std.fmt.allocPrint(
            arena,
            "could not start a Dagger session on '{s}': {s}",
            .{ ep.container, @errorName(e) },
        ),
    };
}

/// actions/checkout's inputs and defaults, in its order, for the step's log header (the token is
/// the job's GITHUB_TOKEN, a secret; `repository` is the job's).
const checkout_defaults = [_][2][]const u8{
    .{
        "repository",
        "",
    },
    .{ "token", "***" },
    .{ "ssh-strict", "true" },
    .{
        "ssh-user",
        "git",
    },
    .{ "persist-credentials", "true" },
    .{ "clean", "true" },
    .{
        "sparse-checkout-cone-mode",
        "true",
    },
    .{ "fetch-depth", "1" },
    .{ "fetch-tags", "false" },
    .{
        "show-progress",
        "true",
    },
    .{ "lfs", "false" },
    .{ "submodules", "false" },
    .{ "set-safe-directory", "true" },
};

/// Opens a `run:` step's log as GitHub's runner does: the command folded away with its shell and
/// the env it gets (workflow, job and step `env:`, and GITHUB_ENV; secret values are masked by the
/// log).
fn logRunHeader(
    arena: Allocator,
    sh: *JobLog,
    num: u32,
    script: []const u8,
    shell: ?[]const u8,
    env: []const job_mod.EnvVar,
) !void {
    sh.append(num, try std.fmt.allocPrint(arena, "##[group]Run {s}", .{firstLine(script)}));
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, script, "\n"), '\n');
    while (lines.next()) |l| sh.append(num, l);
    sh.append(num, try shellLine(arena, shell));
    if (env.len > 0) {
        sh.append(num, "env:");
        for (env) |e| sh.append(
            num,
            try std.fmt.allocPrint(arena, "  {s}: {s}", .{ e.name, firstLine(e.value) }),
        );
    }
    sh.append(num, "##[endgroup]");
}

/// What GitHub's runner logs when a script exits non-zero (ScriptHandler.cs ~354). Nothing for a
/// step a workflow or file command failed: that failure is the step's `CommandResult`, merged in
/// after the process (StepsRunner.cs ~348), and its own error line already says why.
pub fn logExitCode(sh: *JobLog, num: u32, out: Exec.Out) void {
    if (out.code == 0 or out.command_failed) return;
    sh.errorLine(
        num,
        std.fmt.allocPrint(sh.arena, "Process completed with exit code {d}.", .{out.code}) catch
            return,
    );
}

/// The `env` context a step sees: the job's (workflow, job, GITHUB_ENV), then the step's own.
pub fn envContext(
    arena: Allocator,
    job_env: []const job_mod.EnvVar,
    step_env: []const job_mod.EnvVar,
) ![]const job_mod.EnvVar {
    var out: std.ArrayList(job_mod.EnvVar) = .empty;
    try out.appendSlice(arena, job_env);
    for (step_env) |e| try Evaluator.putEnv(arena, &out, e.name, e.value);
    return out.items;
}

/// Sends GraphQL over a direct session.
const SessionTransport = struct {
    s: *engine.Session,

    fn send(ptr: *anyopaque, arena: Allocator, doc: []const u8, limit: usize) anyerror![]const u8 {
        const t: *SessionTransport = @ptrCast(@alignCast(ptr));
        return t.s.query(arena, doc, limit);
    }

    fn abort(ptr: *anyopaque) bool {
        const t: *SessionTransport = @ptrCast(@alignCast(ptr));
        return t.s.abort();
    }
};

/// Run-specific values do not take part in exec cache keys under step caching, so unchanged steps
/// are reused: they travel in a volatile variable rather than an ordinary one.
pub fn envVarNode(is_volatile: bool) []const u8 {
    return if (is_volatile) "withVolatileVariable" else "withEnvVariable";
}

/// A `run:` step's script, shell and working directory, evaluated, with its header logged as GitHub
/// logs it. Null when evaluation failed: the step has been failed and recorded, and the loop moves
/// on.
fn prepareScript(
    x: *Exec,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
    coe: bool,
    sc1: expr.Scope,
    step_env: []const job_mod.EnvVar,
    plain_step_env: []const job_mod.EnvVar,
    sc: @FieldType(job_mod.Action, "script"),
) !?Resolved {
    const arena = x.arena;
    const ev = x.ev;
    const script = ev.render(sc.script, sc1) catch {
        const msg = try std.fmt.allocPrint(arena, "could not evaluate the script: {s}", .{ev.diag});
        try failStep(ev, x.sh, x.observer, step, res, num, msg, coe);
        return null;
    };
    // `defaults.run` fills in a shell the step leaves out or empty, and a working directory it
    // leaves out (actions/runner src/Runner.Worker/Handlers/ScriptHandler.cs 155-180).
    // An expression in either that cannot be evaluated fails the step, as the script's does:
    // GitHub's runner evaluates them with the step's inputs (`EvaluateStepInputs`).
    const own_shell: ?[]const u8 = if (sc.shell) |t| ev.render(t, sc1) catch {
        const msg = try std.fmt.allocPrint(arena, "could not evaluate shell: {s}", .{ev.diag});
        try failStep(ev, x.sh, x.observer, step, res, num, msg, coe);
        return null;
    } else null;
    const shell = if (own_shell != null and own_shell.?.len > 0) own_shell else x.default_shell;
    if (shell) |sh_name| if (!job_mod.validShell(sh_name)) {
        try failStep(
            ev,
            x.sh,
            x.observer,
            step,
            res,
            num,
            try job_mod.unsupportedShell(arena, sh_name),
            coe,
        );
        return null;
    };
    const wd: ?[]const u8 = if (sc.working_directory) |t| ev.render(t, sc1) catch {
        const msg = try std.fmt.allocPrint(
            arena,
            "could not evaluate working-directory: {s}",
            .{ev.diag},
        );
        try failStep(ev, x.sh, x.observer, step, res, num, msg, coe);
        return null;
    } else x.default_working_directory;
    try logRunHeader(
        arena,
        x.sh,
        num,
        script,
        shell,
        try envContext(arena, ev.job_env.items, step_env),
    );
    return .{ .run = .{
        .script = script,
        .shell = shell,
        .working_directory = wd,
        .env = plain_step_env,
    } };
}

/// The built-in checkout: its inputs evaluated and logged as GitHub logs an action's, then the
/// repository fetched. Null when the inputs could not be evaluated, were unsupported, or the fetch
/// failed: the step has been failed and recorded, and the loop moves on.
fn prepareCheckout(
    x: *Exec,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
    coe: bool,
    sc1: expr.Scope,
    step_env: []const job_mod.EnvVar,
    inputs: []const job_mod.Input,
) !?Fetched {
    const arena = x.arena;
    const ev = x.ev;
    const sh = x.sh;
    const rendered = ev.renderEnv(inputs, sc1) catch {
        const msg = try std.fmt.allocPrint(
            arena,
            "could not evaluate the checkout inputs: {s}",
            .{ev.diag},
        );
        try failStep(ev, sh, x.observer, step, res, num, msg, coe);
        return null;
    };
    try logCheckoutHeader(x, num, step, rendered, step_env);
    const co = switch (try job_mod.checkoutFromInputs(arena, rendered)) {
        .ok => |c| c,
        .unsupported => |why| {
            try failStep(ev, sh, x.observer, step, res, num, why, coe);
            return null;
        },
    };
    const f = if (x.native) |b|
        try b.fetchCheckout(x, co)
    else
        try checkout.fetch(arena, x.transport, x.job.*, co, x.gitAuth());
    if (f.result == .failed) {
        try failStep(ev, sh, x.observer, step, res, num, f.result.failed, coe);
        return null;
    }
    return f;
}

/// As GitHub opens an action's log: the action, the inputs the workflow gave it, then
/// actions/checkout's defaults (the same in v4 to v6), then the env.
fn logCheckoutHeader(
    x: *Exec,
    num: u32,
    step: job_mod.Step,
    rendered: []const job_mod.EnvVar,
    step_env: []const job_mod.EnvVar,
) !void {
    const arena = x.arena;
    const sh = x.sh;
    const uses = if (step.uses.len > 0) step.uses else "actions/checkout";
    sh.append(num, try std.fmt.allocPrint(arena, "##[group]Run {s}", .{uses}));
    sh.append(num, "with:");
    for (rendered) |in| sh.append(
        num,
        try std.fmt.allocPrint(arena, "  {s}: {s}", .{ in.name, firstLine(in.value) }),
    );
    for (checkout_defaults) |d| {
        const given = for (rendered) |in| (if (std.mem.eql(
            u8,
            in.name,
            d[0],
        )) break true) else false;
        if (given) continue;
        const value = if (std.mem.eql(u8, d[0], "repository")) x.job.github.repository else d[1];
        sh.append(num, try std.fmt.allocPrint(arena, "  {s}: {s}", .{ d[0], value }));
    }
    const co_env = try envContext(arena, x.ev.job_env.items, step_env);
    if (co_env.len > 0) {
        sh.append(num, "env:");
        for (co_env) |e| sh.append(
            num,
            try std.fmt.allocPrint(arena, "  {s}: {s}", .{ e.name, firstLine(e.value) }),
        );
    }
    sh.append(num, "##[endgroup]");
}

/// One step of the job: its condition, env and timeout evaluated, then run as a script, a checkout,
/// an action or an image, and recorded. Null means the loop moves to the next step — the step ran,
/// was skipped, or was failed and recorded; a Result means the engine failed and the job is over.
fn runStep(
    x: *Exec,
    watch: *Watch,
    cancel: ?*Cancel,
    results: []StepResult,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
) !?Result {
    const ev = x.ev;
    const arena = x.arena;
    res.name = step.name;
    if (cancel) |c| if (c.requested.load(.acquire)) {
        ev.cancelled = true;
    };
    // 1. Step env, with the job env visible. GitHub's runner evaluates it before the condition,
    // so `if:` sees it, and an error fails the step whatever its condition says
    // (`StepsRunner.cs` ~114-139).
    ev.diag = "";
    const sc0 = try ev.scope(&.{});
    const step_env = ev.renderEnv(step.env, sc0) catch {
        const msg = try std.fmt.allocPrint(arena, "could not evaluate env: {s}", .{ev.diag});
        // Not continued: GitHub completes the step as failed here (`StepsRunner.cs` ~131-138)
        // and never reaches `ApplyContinueOnError`, which only `RunStepAsync` calls (~353).
        try failStep(ev, x.sh, x.observer, step, res, num, msg, false);
        return null;
    };
    const sc1 = try ev.scope(step_env);

    // 2. The name and condition, with the step env visible; then continue-on-error and the
    // step's own inputs.
    if (!try stepCondition(x, step, res, num, sc1)) return null;
    const coe = std.mem.eql(u8, ev.render(step.continue_on_error, sc1) catch "false", "true");
    res.continued = coe;
    const written: ?[]const u8 = if (step.timeout_minutes) |t| ev.render(t, sc1) catch null else null;
    const timeout_ms = timeoutMs(written);
    // GitHub's message on a timeout names the whole minutes it waited.
    const limit: ?[]const u8 = if (timeout_ms > 0)
        try std.fmt.allocPrint(arena, "{d}", .{@divTrunc(timeout_ms, 60_000)})
    else
        written;

    // Env that carries a secret goes in as a Dagger secret, the rest in the script.
    var plain: std.ArrayList(job_mod.EnvVar) = .empty;
    var secret: std.ArrayList(SecretRef) = .empty;
    x.splitStepEnv(step_env, &plain, &secret) catch {
        const msg = try std.fmt.allocPrint(arena, "Dagger could not register a secret: {s}", .{
            x.err_msg,
        });
        try failStep(ev, x.sh, x.observer, step, res, num, msg, coe);
        return null;
    };

    const how: StepRun = .{
        .coe = coe,
        .timeout = limit,
        .timeout_ms = timeout_ms,
        .scope = sc1,
        .survives_cancel = try survivesCancel(ev, step.condition, step_env),
    };
    var resolved: Resolved = undefined;
    var mount_buf: [1]Mount = undefined;
    var mounts: []const Mount = &.{};
    switch (step.action) {
        .unsupported => |why| {
            try failStep(ev, x.sh, x.observer, step, res, num, why, coe);
            return null;
        },
        .script => |sc| {
            const env = plain.items;
            resolved = try prepareScript(x, step, res, num, coe, sc1, step_env, env, sc) orelse
                return null;
        },
        .checkout => |inputs| {
            const f = try prepareCheckout(x, step, res, num, coe, sc1, step_env, inputs) orelse
                return null;
            resolved = .{ .checkout = f };
            const dir = f.result.dir;
            mount_buf[0] = .{ .dir = .{ .path = f.mount, .id = dir, .owner = x.dir_owner } };
            mounts = &mount_buf;
        },
        .uses, .docker => {
            return runActionStep(x, watch, results, step, res, num, how, plain.items, secret.items);
        },
    }
    return runResolvedStep(x, watch, results, step, res, num, how, resolved, mounts, secret.items);
}

/// What a step runs under once its env is evaluated: continue-on-error, its timeout as written and
/// in milliseconds (0 for none), and the scope its expressions see.
const StepRun = struct {
    coe: bool,
    timeout: ?[]const u8,
    timeout_ms: i64,
    scope: expr.Scope,
    /// The step's condition still holds once the job is cancelled (`survivesCancel`).
    survives_cancel: bool,
};

/// Whether a step keeps running when the job is cancelled while it runs. GitHub's runner then
/// evaluates the step's condition again, with the job cancelled, and stops the step only when it
/// no longer holds or cannot be evaluated (`StepsRunner.cs` ~141-183): an `if: always()` or
/// `if: cancelled()` step runs on. Nothing the condition reads changes while the step runs but the
/// job's status, so it is evaluated here, before the step, with the job taken as cancelled.
fn survivesCancel(ev: *Evaluator, condition: []const u8, step_env: []const job_mod.EnvVar) !bool {
    const was = ev.cancelled;
    defer ev.cancelled = was;
    ev.cancelled = true;
    const diag = ev.diag;
    defer ev.diag = diag;
    return expr.evalCondition(ev.arena, condition, try ev.scope(step_env)) catch false;
}

/// `timeout-minutes` in milliseconds, whole minutes: GitHub's runner casts the number to an
/// `Int32` (`ConvertToStepTimeout` in PipelineTemplateConverter.cs), so `1.5` is one minute and
/// `0.5` no timeout at all. 0 when absent, unparsable or not positive. At most a year: a larger
/// number (`1e300`, `inf`) would not fit, and converting it panics.
fn timeoutMs(timeout: ?[]const u8) i64 {
    const t = timeout orelse return 0;
    const minutes = std.fmt.parseFloat(f64, std.mem.trim(u8, t, " ")) catch return 0;
    if (!(minutes >= 1)) return 0;
    return @intFromFloat(@trunc(@min(minutes, 366 * 24 * 60)) * 60_000);
}

test "timeoutMs reads timeout-minutes, and a number too large to hold is a year" {
    try std.testing.expectEqual(@as(i64, 0), timeoutMs(null));
    // Whole minutes, as GitHub's cast to an integer leaves them.
    try std.testing.expectEqual(@as(i64, 60_000), timeoutMs(" 1.5 "));
    try std.testing.expectEqual(@as(i64, 0), timeoutMs("0.5"));
    try std.testing.expectEqual(@as(i64, 120_000), timeoutMs("2.99"));
    try std.testing.expectEqual(@as(i64, 0), timeoutMs("-1"));
    try std.testing.expectEqual(@as(i64, 0), timeoutMs("nan"));
    const year: i64 = 366 * 24 * 60 * 60_000;
    try std.testing.expectEqual(year, timeoutMs("1e300"));
    try std.testing.expectEqual(year, timeoutMs("inf"));
}

/// The step's name and condition, evaluated in `sc` (the job env and the step's). False when the
/// step was skipped or its condition could not be evaluated: it has been recorded and the loop
/// moves on.
fn stepCondition(x: *Exec, step: job_mod.Step, res: *StepResult, num: u32, sc: expr.Scope) !bool {
    const ev = x.ev;
    const arena = x.arena;
    // Evaluated with `secrets` in scope, and shown on GitHub, in the live view and in the database.
    if (step.name_expr) |ne| res.name = try x.sh.redacted(arena, expr.evalString(arena, ne, sc) catch step.name);
    const should_run = expr.evalCondition(arena, step.condition, sc) catch {
        const msg = try std.fmt.allocPrint(
            arena,
            "could not evaluate the condition '{s}': {s}",
            .{ step.condition, ev.diag },
        );
        try failStep(ev, x.sh, x.observer, step, res, num, msg, false);
        return false;
    };
    if (!should_run) {
        res.outcome = .skipped;
        try ev.record(step, .skipped, false, &.{});
        if (x.observer) |o| o.finished(num, res.*);
        return false;
    }
    return true;
}

/// A `uses:` action or a `docker://` image step: timed, watched for its timeout, and recorded.
fn runActionStep(
    x: *Exec,
    watch: *Watch,
    results: []StepResult,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
    how: StepRun,
    plain: []const job_mod.EnvVar,
    secret: []const SecretRef,
) !?Result {
    res.started_ms = std.Io.Clock.real.now(x.io).toMilliseconds();
    if (x.observer) |o| o.started(num, res.name, res.started_ms);
    const deadline_ms = if (how.timeout_ms > 0) res.started_ms + how.timeout_ms else 0;
    watch.begin(deadline_ms, how.survives_cancel);
    const ran = switch (step.action) {
        .uses => |u| x.runAction(num, u, how.scope, plain, secret, false),
        .docker => |d| x.runImageStep(num, d, how.scope, plain, secret),
        else => unreachable,
    };
    const intr = watch.end();
    const out = ran catch |e| switch (e) {
        error.EngineFailed => if (intr != .none) {
            try stepInterrupted(
                x.ev,
                x.sh,
                x.observer,
                step,
                res,
                num,
                how.coe,
                intr,
                how.timeout orelse "",
            );
            return null;
        } else return try engineFailed(x, x.observer, res, num, how.coe, results),
        else => return e,
    };
    try recordOutcome(
        x,
        step,
        res,
        num,
        how.coe,
        if (out.failed) .failure else .success,
        out.exit_code,
        out.outputs,
    );
    return null;
}

/// A script or a checkout, resolved, run through `execScript`: timed, watched for its timeout, and
/// recorded. A checkout also queues its post step, as actions/checkout has one.
fn runResolvedStep(
    x: *Exec,
    watch: *Watch,
    results: []StepResult,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
    how: StepRun,
    resolved: Resolved,
    mounts: []const Mount,
    secret: []const SecretRef,
) !?Result {
    res.started_ms = std.Io.Clock.real.now(x.io).toMilliseconds();
    if (x.observer) |o| o.started(num, res.name, res.started_ms);
    const deadline_ms = if (how.timeout_ms > 0) res.started_ms + how.timeout_ms else 0;
    watch.begin(deadline_ms, how.survives_cancel);
    const name = if (step.context_name.len > 0) step.context_name else step.id;
    const ran = x.execScript(num, num, resolved, name, secret, mounts);
    const intr = watch.end();
    const out = ran catch |e| switch (e) {
        error.EngineFailed => if (intr != .none) {
            try stepInterrupted(
                x.ev,
                x.sh,
                x.observer,
                step,
                res,
                num,
                how.coe,
                intr,
                how.timeout orelse "",
            );
            return null;
        } else return try engineFailed(x, x.observer, res, num, how.coe, results),
        else => return e,
    };
    if (resolved == .run and out.code != 0) {
        logExitCode(x.sh, num, out);
        x.noteNestingWithheld(num, resolved.run.script);
    }
    // As actions/checkout, a post step once the checkout ran (see `Post.checkout`).
    if (resolved == .checkout) try appendCheckoutPost(x, num, res.name);
    try recordOutcome(
        x,
        step,
        res,
        num,
        how.coe,
        if (out.code == 0) .success else .failure,
        out.code,
        out.outputs,
    );
    return null;
}

/// What every step ends with: its times and outcome on the result, the evaluator told, the job
/// marked failed unless the step continues on error, and the observer told it finished.
/// A composite action's step whose condition was false, as `steps.<id>` sees it.
/// `s` with its expressions evaluated, itself when there is none or they fail, null for null.
/// A JavaScript action's script as a `run:` step: no shell, no working directory.
pub fn scriptRun(script: []const u8, env: []const job_mod.EnvVar) Resolved {
    return .{ .run = .{ .script = script, .shell = null, .working_directory = null, .env = env } };
}

pub fn skippedStep(id: []const u8) StepCtx {
    return .{ .id = id, .outcome = "skipped", .conclusion = "skipped", .outputs = &.{} };
}

fn recordOutcome(
    x: *Exec,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
    coe: bool,
    outcome: Outcome,
    exit_code: i32,
    outputs: []const job_mod.EnvVar,
) !void {
    res.completed_ms = std.Io.Clock.real.now(x.io).toMilliseconds();
    res.outcome = outcome;
    res.exit_code = exit_code;
    try x.ev.record(step, res.outcome, coe, outputs);
    if (res.outcome == .failure and !coe) x.ev.job_failed = true;
    if (x.observer) |o| o.finished(num, res.*);
}

fn appendCheckoutPost(x: *Exec, num: u32, name: []const u8) !void {
    try x.posts.append(x.arena, .{
        .num = num,
        .name = try std.fmt.allocPrint(x.arena, "Post {s}", .{name}),
        .act = undefined,
        .u = undefined,
        .script = "",
        .condition = "always()",
        .inputs = &.{},
        .step_env = &.{},
        .step_secret = &.{},
        .state = &.{},
        .checkout = true,
    });
}

fn runSteps(
    arena: Allocator,
    io: std.Io,
    opts: Options,
    job: job_mod.Job,
    sh: *JobLog,
    results: []StepResult,
    transport: Transport,
    /// The job runs on the native backend (`runNative`): the base is made there, and each exec
    /// goes there (`Exec.execScript`).
    native: ?*Backend,
) !Result {
    var ev = try Evaluator.init(arena, &job);
    ev.runner_name = opts.runner_name;
    ev.runner_debug = sh.step_debug;
    var err_msg: []const u8 = "";
    // Services hold state a cached step would not have changed (a migration replayed from cache
    // leaves a fresh database empty), so a job with services runs every step.
    const no_services = job.services.len == 0;
    const step_cache = opts.step_cache and !optsOutOfStepCache(ev.job_env.items) and no_services;
    var secrets: Secrets = .{ .local = native != null };
    const plan = basePlan(
        arena,
        io,
        transport,
        &ev,
        job,
        opts,
        step_cache,
        sh.mark,
        &secrets,
        &err_msg,
    ) catch |e| switch (e) {
        error.BaseContainerFailed => return fail(sh, results, err_msg),
        else => return e,
    };
    const base: Base = if (native) |b| base: {
        b.base(&ev, plan, &err_msg) catch |e| switch (e) {
            error.BaseContainerFailed => return fail(sh, results, err_msg),
            else => return e,
        };
        break :base .{ .id = "native", .runtime_path = b.runtime_path };
    } else baseContainerId(arena, transport, &ev, job, plan, &secrets, &err_msg) catch |e|
        switch (e) {
            error.BaseContainerFailed => return fail(sh, results, err_msg),
            else => return e,
        };
    var x = try execFor(arena, io, transport, sh, &ev, &job, opts, plan, base.id, secrets, step_cache);
    x.container_path = base.runtime_path;
    x.native = native;
    x.tool_trees = base.tool_trees;
    // A native job's tool cache is its `toolcache` volume, in no layer, so a replayed step that
    // points at a tree there runs again (#229): no tree is checked natively (`tool_trees`).
    if (native) |b| x.tool_cache = b.cache_plan.tool_cache;
    ev.hash_files = .{ .ptr = &x, .hashFn = Exec.hashFiles };

    var watch: Watch = .{ .io = io, .transport = transport, .cancel = opts.cancel };
    var watching: ?std.Io.Future(void) = null;
    if (transport.abortFn != null) watching = io.concurrent(Watch.run, .{&watch}) catch null;
    defer if (watching) |*f| {
        watch.done.store(true, .release);
        f.cancel(io);
    };

    if (try setUpJob(&x, opts, results)) |failed| return failed;
    if (plan.zig_seed_note) |note| x.setUpLine(note);
    if (plan.zig_local_note) |note| x.setUpLine(note);
    if (base.tool_trees_note) |note| x.setUpLine(note);
    if (opts.backend_note) |note| x.setUpLine(note);
    if (native) |b| for (b.notes.items) |note| x.setUpLine(note);

    if (job.container != null or !no_services) {
        if (!try x.startServices()) return servicesFailed(&x, arena, sh, results);
    }
    if (try runPres(&x, arena, sh, results, job)) |failed| return failed;
    for (job.steps, results, 1..) |step, *res, n| {
        const num: u32 = @intCast(n);
        if (try runStep(&x, &watch, opts.cancel, results, step, res, num)) |finished|
            return finished;
    }
    return finishJob(&x, opts, results);
}

/// The job, failed at "Initialize containers": every step not run, the service steps shown.
fn servicesFailed(x: *Exec, arena: Allocator, sh: *JobLog, results: []StepResult) !Result {
    var failed = try finish(arena, sh, results, "");
    failed.succeeded = false;
    failed.engine_error = null;
    failed.extra = x.extra.items;
    failed.next_log_step = x.next_log_step;
    return failed;
}

/// JavaScript actions' `pre` scripts, before any step, as on GitHub. The job's result when the
/// engine failed on one; null to go on.
fn runPres(
    x: *Exec,
    arena: Allocator,
    sh: *JobLog,
    results: []StepResult,
    job: job_mod.Job,
) !?Result {
    for (job.steps, 1..) |step, n| if (step.action == .uses) {
        x.runPre(@intCast(n), step) catch |e| switch (e) {
            error.EngineFailed => return try finish(arena, sh, results, x.err_msg),
            else => return e,
        };
    };
    return null;
}

/// After the last step: the `post` scripts, last first, then the services, then the job's result
/// and outputs.
fn finishJob(x: *Exec, opts: Options, results: []StepResult) !Result {
    const arena = x.arena;
    const job = x.job;
    const stopping = job.services.len > 0 or job.container != null;
    if (x.posts.items.len > 0 or stopping)
        if (opts.observer) |o| if (o.postsFn) |f| f(o.ptr, @intCast(x.posts.items.len), stopping);
    x.runPosts() catch |e| switch (e) {
        error.EngineFailed => return finish(arena, x.sh, results, x.err_msg),
        else => return e,
    };
    try x.stopServices();
    var result = try finish(arena, x.sh, results, "");
    if (x.hook_failed) result.succeeded = false;
    if (opts.cancel) |c| if (c.requested.load(.acquire)) {
        x.ev.cancelled = true;
    };
    if (x.ev.cancelled) {
        result.cancelled = true;
        result.succeeded = false;
    }
    result.extra = x.extra.items;
    result.output_keys = .{
        .applied = x.outputs_applied,
        .fell_back = x.outputs_fell_back,
        .last_reason = x.outputs_last_reason,
        .ms = x.outputs_ms,
    };
    result.next_log_step = x.next_log_step;
    result.summaries = x.summaries;
    try jobOutputs(arena, x.ev, x.sh, job.*, &result);
    try environmentUrl(arena, x.ev, x.sh, job.*, &result);
    return result;
}

/// Evaluates `environment.url` after the job outputs, as GitHub's runner does when it finishes a
/// job (`FinalizeJob` in JobExtension.cs): one that would carry a secret is not set, with GitHub's
/// warning, and one that cannot be evaluated fails the job.
fn environmentUrl(
    arena: Allocator,
    ev: *Evaluator,
    sh: *JobLog,
    job: job_mod.Job,
    result: *Result,
) !void {
    const url = job.environment.url orelse return;
    var lines: std.ArrayList([]const u8) = .empty;
    try lines.appendSlice(arena, result.output_lines);
    try lines.append(arena, "Evaluate and set environment url");
    defer result.output_lines = lines.items;
    ev.diag = "";
    const value = ev.render(url, try ev.scope(&.{})) catch {
        try lines.append(arena, "##[error]Failed to evaluate environment url");
        if (ev.diag.len > 0)
            try lines.append(arena, try std.fmt.allocPrint(arena, "##[error]{s}", .{ev.diag}));
        result.succeeded = false;
        return;
    };
    if (containsSecret(job, value) or sh.holdsSecret(value, 1)) {
        try lines.append(arena, try std.fmt.allocPrint(arena, "##[warning]Skip setting " ++
            "environment url as environment '{s}' may contain secret.", .{job.environment.name}));
        return;
    }
    try lines.append(
        arena,
        try std.fmt.allocPrint(arena, "Evaluated environment url: {s}", .{value}),
    );
    result.environment_url = value;
}

/// Evaluates the job's outputs as GitHub's runner does when it finishes a job: against the final
/// contexts (the steps' outputs and outcomes), each output a string. One that would carry a secret
/// is dropped with GitHub's warning (later jobs could read it); one that cannot be evaluated is
/// dropped with the reason.
fn jobOutputs(arena: Allocator, ev: *Evaluator, sh: *JobLog, job: job_mod.Job, result: *Result) !void {
    if (job.outputs.len == 0) return;
    var outs: std.ArrayList(job_mod.EnvVar) = .empty;
    var lines: std.ArrayList([]const u8) = .empty;
    try lines.append(arena, "Evaluate and set job outputs");
    for (job.outputs) |o| {
        ev.diag = "";
        const sc = try ev.scope(&.{});
        const value = ev.render(o.value, sc) catch {
            try lines.append(
                arena,
                try std.fmt.allocPrint(arena, "##[warning]Could not evaluate output " ++
                    "'{s}': {s}", .{ o.name, ev.diag }),
            );
            continue;
        };
        // Against every secret and mask, in every form (`::add-mask::` values too: an OIDC-minted
        // token is one), as GitHub's runner checks job outputs.
        if (containsSecret(job, value) or sh.holdsSecret(value, 1)) {
            try lines.append(
                arena,
                try std.fmt.allocPrint(arena, "##[warning]Skip output '{s}' since it may " ++
                    "contain secret.", .{o.name}),
            );
            continue;
        }
        try outs.append(arena, .{ .name = o.name, .value = value });
        try lines.append(arena, try std.fmt.allocPrint(arena, "Set output '{s}'", .{o.name}));
    }
    result.outputs = outs.items;
    result.output_lines = lines.items;
}

/// A directory mounted into the container for one exec.
pub const Mount = union(enum) {
    /// `owner`: who owns the copy (`Exec.dir_owner`), so steps that do not run as root can write
    /// it.
    dir: struct { path: []const u8, id: []const u8, owner: ?[]const u8 = null },
    file: struct { path: []const u8, id: []const u8, permissions: u32 },
    new_file: struct { path: []const u8, contents: []const u8, permissions: u32 },
};

pub const Exec = @import("dagger/Exec.zig");

/// Where a job's event payload is written.
pub const event_dir = "/github/workflow";
pub const event_path = event_dir ++ "/event.json";
/// The volatile variable that carries the event payload when step caching is on.
pub const event_env = "ZIG_RUNNER_EVENT";
/// A value new for every job, in a volatile variable (not part of exec cache keys). Each step
/// writes it with its file commands, so the runner knows for certain whether a step ran in this job
/// or its result was replayed from Dagger's cache, instead of guessing from whether its log lines
/// arrived in time.
pub const ran_env = "ZIG_RUNNER_RAN";
/// The job's secret that its step markers carry (`writeMarkerEcho`): a value new for every job,
/// which a step's own program does not see (`env -u`, as `ran_env`), so a step cannot print another
/// step's `begin` or `end` and have its lines counted as that step's (issue #71). Not `ran_env`'s
/// value: that one is written to the step's file commands, where later steps can read it.
///
/// It is volatile under step caching (not part of exec cache keys); the scripts name the variable,
/// not its value. A replayed exec's recorded output carries an earlier job's value, which
/// `replayRecorded` learns from the recorded `begin` marker, the first line the script prints.
///
/// It keeps out text, not a determined step: one running as the same user can read the value
/// from its parent shell's /proc/<pid>/environ, and steps have sudo anyway.
pub const mark_env = "ZIG_RUNNER_MARK";

/// Default variables that identify the run rather than its inputs. With step caching they are
/// volatile: they reach every step but do not take part in exec cache keys.
/// RUNNER_NAME belongs here too: a pool registers every job under a new name, so as an input it
/// would make every job's keys new and no step would ever be reused.
/// So do the commit and the refs: as inputs they made every step of a new commit miss, even steps
/// before the checkout. A step whose script names one of these still runs every time
/// (`readsRunSpecific`), and a step that reads the commit some other way still sees a new workspace
/// (`.git` included) after a checkout, so its key changes with the commit anyway.
pub const volatile_env = [_][]const u8{
    "GITHUB_RUN_ID",           "GITHUB_RUN_NUMBER",   "GITHUB_RUN_ATTEMPT",  "GITHUB_ACTOR",
    "GITHUB_TRIGGERING_ACTOR", "RUNNER_NAME",         "GITHUB_SHA",          "GITHUB_REF",
    "GITHUB_REF_NAME",         "GITHUB_REF_TYPE",     "GITHUB_BASE_REF",     "GITHUB_HEAD_REF",
    "GITHUB_ACTOR_ID",         "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_REF_PROTECTED",
};

/// What a step that did not name a run-specific value is given instead of one.
///
/// `readsRunSpecific` below is a syntactic test — it looks for the name in the script text — and it
/// cannot be made sound: a script reaches the value through a file it sources, a program that reads
/// the environment, or a name built from pieces. Such a step is then replayed with an earlier run's
/// value, which is wrong rather than merely stale (docs/STUDY.md experiment 2, and the B1 check in
/// properties/). So a step that did not name one does not get one. The value is a constant, so the
/// step's cache key is unaffected; it is in the script's own `env` prefix, so it is part of that
/// key and cannot vary; and it is visible, so a step that prints it says so in its log.
///
/// This is a deliberate divergence from GitHub's runner, which always sets the real values. See
/// docs/SPEC.md "Where this runner differs from GitHub's" and proofs/Runner/Enforce.agda, which is
/// why it is sound: an unmarked step's input becomes a function of its cache key.
pub const volatile_sentinel = "zig-runner-withheld";

/// What a replayable step finds at GITHUB_EVENT_PATH instead of the event payload: the payload
/// differs on every run and is not part of the cache key, so a step that read it without naming it
/// would be replayed with an earlier run's (issue #68: a `workflow_dispatch` input read by a script
/// in a file). It is `volatile_sentinel` as a JSON string, so a parser reads it and anything that
/// looks inside fails (`jq .inputs.version`: cannot index string) instead of quietly getting
/// another run's answer. A step that names GITHUB_EVENT_PATH or the file runs every time, and gets
/// the real one.
pub const withheld_event = "\"" ++ volatile_sentinel ++ "\"";

/// Whether a script names a variable whose value differs between runs while the cache key does not
/// (the volatile ones, and the event payload: its variable or its file). Scripts the step runs from
/// files are not looked into; such a step is given `volatile_sentinel` and `withheld_event` instead.
pub fn readsRunSpecific(script: []const u8) bool {
    for (volatile_env) |v| if (std.mem.indexOf(u8, script, v) != null) return true;
    return std.mem.indexOf(u8, script, "GITHUB_EVENT_PATH") != null or
        std.mem.indexOf(u8, script, event_path) != null;
}

pub fn isVolatile(name: []const u8) bool {
    for (volatile_env) |v| if (std.mem.eql(u8, v, name)) return true;
    return false;
}

/// `ZIG_RUNNER_STEP_CACHE: false` in the workflow's or job's env turns step caching off for the
/// job.
fn optsOutOfStepCache(job_env: []const job_mod.EnvVar) bool {
    for (job_env) |e| if (std.mem.eql(u8, e.name, "ZIG_RUNNER_STEP_CACHE"))
        return std.ascii.eqlIgnoreCase(e.value, "false") or std.mem.eql(u8, e.value, "0");
    return false;
}

/// The `id` under alias `key` of a query result, or null.
pub fn idOf(data: std.json.Value, key: []const u8) ?[]const u8 {
    const v = jsonFind(data, key) orelse return null;
    return jsonFindString(v, "id");
}

/// What Bun prints when it refuses a program before running any of it, so the program can be run
/// again with Node. actions/setup-python v7's bundle mixes an ES `import` with CommonJS `exports`,
/// which Node accepts.
pub const bun_load_errors = [_][]const u8{"error: Cannot use import statement with CommonJS-only " ++
    "features"};

/// `ACTIONS_STEP_DEBUG` set to true, as a secret or a repository variable, shows `::debug::` lines.
fn stepDebug(arena: Allocator, job: job_mod.Job) bool {
    for (job.secret_vars) |sv| {
        if (!std.mem.eql(u8, sv.name, "ACTIONS_STEP_DEBUG")) continue;
        return std.ascii.eqlIgnoreCase(sv.value, "true");
    }
    if (job.context_data == .object) if (job.context_data.object.get("vars")) |vars| {
        const v = context.fromContextData(arena, vars) catch return false;
        if (v == .object) for (v.object) |e| if (std.mem.eql(u8, e.key, "ACTIONS_STEP_DEBUG")) {
            return e.value == .string and std.ascii.eqlIgnoreCase(e.value.string, "true");
        };
    };
    return false;
}

pub fn hasKey(v: expr.Value, key: []const u8) bool {
    if (v != .object) return false;
    for (v.object) |e| if (std.ascii.eqlIgnoreCase(e.key, key)) return true;
    return false;
}

/// `base` (an object, or null) with `extra` entries added or replaced.
pub fn withEntries(arena: Allocator, base: expr.Value, extra: []const expr.Value.Entry) !expr.Value {
    var list: std.ArrayList(expr.Value.Entry) = .empty;
    if (base == .object) for (base.object) |e| {
        var replaced = false;
        for (extra) |x| if (std.ascii.eqlIgnoreCase(x.key, e.key)) {
            replaced = true;
        };
        if (!replaced) try list.append(arena, e);
    };
    try list.appendSlice(arena, extra);
    return .{ .object = list.items };
}

pub fn firstLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \n\r\t");
    return t[0 .. std.mem.indexOfScalar(u8, t, '\n') orelse t.len];
}

/// Dagger itself failed during a step: the step and the job fail with what Dagger said.
/// A step its timeout or the job's cancellation stopped, logged as GitHub's runner logs it. A timed
/// out step failed (continue-on-error applies); a cancelled one is `cancelled`, and so is the job.
fn stepInterrupted(
    ev: *Evaluator,
    sh: *JobLog,
    observer: ?Observer,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
    coe: bool,
    intr: Watch.Interrupt,
    timeout: []const u8,
) !void {
    res.completed_ms = std.Io.Clock.real.now(sh.io).toMilliseconds();
    res.exit_code = 1;
    switch (intr) {
        .timed_out => {
            sh.errorLine(
                num,
                try std.fmt.allocPrint(ev.arena, "The action '{s}' has timed out after {s} " ++
                    "minutes.", .{ res.name, std.mem.trim(u8, timeout, " ") }),
            );
            res.outcome = .failure;
            if (!coe) ev.job_failed = true;
        },
        .cancelled, .none => {
            sh.errorLine(num, "The operation was canceled.");
            res.outcome = .cancelled;
            ev.cancelled = true;
        },
    }
    try ev.record(step, res.outcome, coe, &.{});
    if (observer) |o| o.finished(num, res.*);
}

fn engineFailed(
    x: *Exec,
    observer: ?Observer,
    res: *StepResult,
    num: u32,
    coe: bool,
    results: []StepResult,
) !Result {
    res.* = .{
        .name = res.name,
        .continued = coe,
        .outcome = .failure,
        .exit_code = 1,
        .started_ms = res.started_ms,
        .completed_ms = std.Io.Clock.real.now(x.io).toMilliseconds(),
    };
    x.sh.append(num, try std.fmt.allocPrint(x.arena, "Dagger error: {s}", .{x.err_msg}));
    if (observer) |o| o.finished(num, res.*);
    return finish(x.arena, x.sh, results, x.err_msg);
}

/// Logs why a step could not run and marks it failed (the job too, unless continue-on-error).
fn failStep(
    ev: *Evaluator,
    sh: *JobLog,
    observer: ?Observer,
    step: job_mod.Step,
    res: *StepResult,
    num: u32,
    msg: []const u8,
    coe: bool,
) !void {
    sh.append(num, msg);
    const name = res.name;
    res.* = .{ .name = name, .continued = coe, .outcome = .failure, .exit_code = 1 };
    try ev.record(step, .failure, coe, &.{});
    if (!coe) ev.job_failed = true;
    if (observer) |o| o.finished(num, res.*);
}

fn fail(sh: *JobLog, results: []StepResult, msg: []const u8) !Result {
    sh.flush();
    return .{ .steps = results, .engine_error = msg, .succeeded = false };
}

pub fn finish(arena: Allocator, sh: *JobLog, results: []StepResult, engine_msg: []const u8) !Result {
    sh.flush();
    var any_failed = false;
    var any_not_run = false;
    for (results) |res| {
        if (res.outcome == .failure and !res.continued) any_failed = true;
        if (res.outcome == .not_run) any_not_run = true;
    }
    var engine_error: ?[]const u8 = null;
    if ((any_not_run and !any_failed) or engine_msg.len > 0) {
        sh.mu.lockUncancelable(sh.io);
        defer sh.mu.unlock(sh.io);
        const tail = try std.mem.join(arena, "\n", sh.tail[0..sh.tail_len]);
        engine_error = if (engine_msg.len > 0)
            try std.fmt.allocPrint(
                arena,
                "{s}{s}{s}",
                .{ engine_msg, if (tail.len > 0) "\n" else "", tail },
            )
        else
            tail;
    }
    return .{
        .steps = results,
        .engine_error = engine_error,
        .succeeded = !any_failed and engine_error == null,
        .annotations = sh.annotations.items,
    };
}

// --- tests ---

const FakeAbort = struct {
    in_flight: bool = false,
    aborted: u32 = 0,

    fn send(_: *anyopaque, _: Allocator, _: []const u8, _: usize) anyerror![]const u8 {
        return "";
    }
    fn abort(ptr: *anyopaque) bool {
        const f: *FakeAbort = @ptrCast(@alignCast(ptr));
        if (!f.in_flight) return false;
        f.aborted += 1;
        f.in_flight = false;
        return true;
    }
    fn transport(f: *FakeAbort) Transport {
        return .{ .ptr = f, .sendFn = send, .abortFn = abort };
    }
};

test "a step past its timeout is stopped, and only that step" {
    var f: FakeAbort = .{};
    var w: Watch = .{ .io = std.testing.io, .transport = f.transport(), .cancel = null };
    w.begin(1_000, false);
    f.in_flight = true;
    w.tick(999);
    try std.testing.expectEqual(@as(u32, 0), f.aborted);
    w.tick(1_001);
    try std.testing.expectEqual(@as(u32, 1), f.aborted);
    try std.testing.expectEqual(Watch.Interrupt.timed_out, w.end());
    // The next step has no timeout: nothing reaches it.
    w.begin(0, false);
    f.in_flight = true;
    w.tick(5_000);
    try std.testing.expectEqual(@as(u32, 1), f.aborted);
    try std.testing.expectEqual(Watch.Interrupt.none, w.end());
}

test "a deadline passed between a step's queries stops its next query" {
    var f: FakeAbort = .{};
    var w: Watch = .{ .io = std.testing.io, .transport = f.transport(), .cancel = null };
    w.begin(1_000, false);
    w.tick(2_000); // no query in flight
    f.in_flight = true;
    w.tick(2_200);
    try std.testing.expectEqual(Watch.Interrupt.timed_out, w.end());
}

test "a cancel stops the running step, not the always() steps after it, until the grace period ends" {
    var f: FakeAbort = .{};
    var c: Cancel = .{};
    var w: Watch = .{ .io = std.testing.io, .transport = f.transport(), .cancel = &c };
    w.begin(0, false);
    f.in_flight = true;
    c.hard_deadline_ms.store(10_000, .release);
    c.requested.store(true, .release);
    w.tick(1_000);
    try std.testing.expectEqual(Watch.Interrupt.cancelled, w.end());
    // An `if: always()` step after it runs.
    w.begin(0, false);
    f.in_flight = true;
    w.tick(2_000);
    try std.testing.expectEqual(@as(u32, 1), f.aborted);
    try std.testing.expectEqual(Watch.Interrupt.none, w.end());
    // Past the grace period, whatever runs is stopped.
    w.begin(0, false);
    f.in_flight = true;
    w.tick(10_001);
    try std.testing.expectEqual(@as(u32, 2), f.aborted);
    try std.testing.expectEqual(Watch.Interrupt.cancelled, w.end());
}

test "an if: always() step runs on through a cancel, until the grace period ends" {
    var f: FakeAbort = .{};
    var c: Cancel = .{};
    var w: Watch = .{ .io = std.testing.io, .transport = f.transport(), .cancel = &c };
    w.begin(0, true);
    f.in_flight = true;
    c.hard_deadline_ms.store(10_000, .release);
    c.requested.store(true, .release);
    w.tick(1_000);
    try std.testing.expectEqual(@as(u32, 0), f.aborted);
    w.tick(10_001);
    try std.testing.expectEqual(@as(u32, 1), f.aborted);
    try std.testing.expectEqual(Watch.Interrupt.cancelled, w.end());
}

test "survivesCancel: the step's condition, evaluated with the job cancelled" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var job = testJob(&.{});
    var ev = try Evaluator.init(arena, &job);
    const go: []const job_mod.EnvVar = &.{.{ .name = "GO", .value = "yes" }};
    for ([_]struct { []const u8, bool }{
        .{ "always()", true },
        .{ "cancelled()", true },
        .{ "success()", false },
        .{ "failure()", false },
        .{ "!cancelled()", false },
        .{ "always() && env.GO == 'yes'", true },
        .{ "fromJSON('{')", false },
    }) |case| try std.testing.expectEqual(case[1], try survivesCancel(&ev, case[0], go));
    // The job itself is not cancelled by asking.
    try std.testing.expect(!ev.cancelled);
}

test "a second cancel can shorten the grace period, never lengthen it" {
    var c: Cancel = .{};
    c.request(10_000);
    try std.testing.expect(c.requested.load(.acquire));
    try std.testing.expectEqual(@as(i64, 10_000), c.hard_deadline_ms.load(.acquire));
    c.request(50_000); // GitHub's 5 minutes, after the runner's stop cancelled the job
    try std.testing.expectEqual(@as(i64, 10_000), c.hard_deadline_ms.load(.acquire));
    c.request(2_000); // GitHub no longer has the job: nothing runs on
    try std.testing.expectEqual(@as(i64, 2_000), c.hard_deadline_ms.load(.acquire));
}

test "a cancel between steps does not stop the next step" {
    var f: FakeAbort = .{};
    var c: Cancel = .{};
    var w: Watch = .{ .io = std.testing.io, .transport = f.transport(), .cancel = &c };
    c.requested.store(true, .release);
    w.tick(1_000);
    w.begin(0, false);
    f.in_flight = true;
    w.tick(1_200);
    try std.testing.expectEqual(@as(u32, 0), f.aborted);
    try std.testing.expectEqual(Watch.Interrupt.none, w.end());
}

test "evalCondition" {
    try std.testing.expectEqual(@as(?bool, true), evalCondition("success()", false));
    try std.testing.expectEqual(@as(?bool, false), evalCondition("success()", true));
    try std.testing.expectEqual(@as(?bool, true), evalCondition("failure()", true));
    try std.testing.expectEqual(@as(?bool, true), evalCondition(" always() ", true));
    try std.testing.expectEqual(@as(?bool, null), evalCondition("github.ref == 'x'", false));
}

/// An exec's answer that says whether it ran in the job marked `ran` (`Exec.ranThisRun`).
fn execRan(arena: Allocator, id: []const u8, code: i32, out: []const u8, ran: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":{{\"id\":\"{s}\"," ++
            "\"exitCode\":{d},\"stdout\":\"{s}\",\"stderr\":\"\",\"fc_ran\":{{\"contents\":\"{s}\"}}}}}}}}}}",
        .{ id, code, out, ran },
    );
}

test "step caching: a step run again after a replayed failure keeps the exports of the step before" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("setup"), testStep("./test.sh") };
    // The step before exports MODE (GITHUB_ENV); the step's first answer is an earlier job's
    // failure, so it runs again, and that second try must start from MODE too, as must what
    // follows (the audit of #80 found the second try without it).
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\"," ++
            "\"fc_ran\":{\"contents\":\"j1\"},\"fc_env\":{\"contents\":\"MODE=ci\\n\"}}}}}",
        try execRan(arena, "C2", 1, "failed", "earlier-job"),
        try execRan(arena, "C3", 0, "passed", "j1"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .test_ran_marker = "j1", .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 4), seen.len);
    const mode = "withEnvVariable(name:\"MODE\",value:\"ci\")";
    try std.testing.expect(std.mem.indexOf(u8, seen[2], mode) != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "its earlier run failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], mode) != null);
}

test "step caching: GITHUB_ENV cannot set the run marker or the runner's other variables" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("setup"), testStep("./test.sh") };
    // Set in the container, `ZIG_RUNNER_RAN` would be what every later step writes as its ran
    // marker: a step replayed from an earlier job would pass for one that ran in this one, and a
    // failure kept from an earlier run would be shown as this run's. The markers' secret, the
    // event and the secret aliases are the runner's too.
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\"," ++
            "\"fc_ran\":{\"contents\":\"j1\"},\"fc_env\":{\"contents\":\"MODE=ci\\nZIG_RUNNER_RAN=forged\\n" ++
            "ZIG_RUNNER_MARK=m\\nZIG_RUNNER_EVENT={}\\nZIG_SECRET_0=s\\n\"}}}}}",
        try execRan(arena, "C2", 0, "passed", "j1"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .test_ran_marker = "j1", .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    // Refused with an error annotation each; the step that wrote them goes on.
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 3), seen.len);
    try std.testing.expect(std.mem.indexOf(u8, seen[2], "withEnvVariable(name:\"MODE\",value:\"ci\")") != null);
    for ([_][]const u8{ "ZIG_RUNNER_RAN", "ZIG_RUNNER_MARK", "ZIG_RUNNER_EVENT", "ZIG_SECRET_0" }) |name| {
        const set = try std.fmt.allocPrint(arena, "withEnvVariable(name:\"{s}\"", .{name});
        try std.testing.expect(std.mem.indexOf(u8, seen[2], set) == null);
        const refused = try std.fmt.allocPrint(arena, "##[error]Can't store {s} using '$GITHUB_ENV' command: it is the runner's own.", .{name});
        try std.testing.expect(std.mem.indexOf(u8, w.buffered(), refused) != null);
    }
    // The next step still writes the job's own marker, from the base container's variable.
    try std.testing.expect(std.mem.indexOf(u8, seen[0], "withVolatileVariable(name:\"ZIG_RUNNER_RAN\",value:\"j1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[2], "::zig-file-command::ran' \\\"${ZIG_RUNNER_RAN-}\\\"") != null);
}

test "step caching: a failure the cache kept from an earlier run is not replayed, the step runs again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("npm test")};
    // #69: the first answer is an earlier job's failure (its ran marker is not this job's); the
    // step runs again, stamped, and this time passes. Then: a failure in this very job stands.
    for ([_]bool{ true, false }) |replayed| {
        const answers = [_][]const u8{
            base_answer,
            try execRan(arena, "C1", 137, "killed", if (replayed) "earlier-job" else "j1"),
            try execRan(arena, "C2", 0, "passed", "j1"),
        };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .test_ran_marker = "j1", .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
        const seen = fake.seen.items;
        const got = w.buffered();
        if (replayed) {
            try std.testing.expect(res.succeeded);
            try std.testing.expectEqual(@as(usize, 3), seen.len);
            try std.testing.expect(std.mem.indexOf(u8, seen[1], "runs this step every time") == null);
            try std.testing.expect(std.mem.indexOf(u8, seen[2], "zig-runner runs this step every time: its earlier run failed, and a failure is not replayed (run ") != null);
            // The earlier job's output is never shown; this run's is.
            try std.testing.expect(std.mem.indexOf(u8, got, "killed") == null);
            try std.testing.expect(std.mem.indexOf(u8, got, "passed") != null);
        } else {
            try std.testing.expect(!res.succeeded);
            try std.testing.expectEqual(@as(usize, 2), seen.len);
        }
    }
}

test "step caching: a failure whose ran marker is missing is not replayed, the step runs again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("npm test")};
    // The answer has no `fc_ran` (its file commands were cut short, or never written), and
    // nothing of the step arrived live: an earlier job's failure, so it runs again (#102).
    const answers = [_][]const u8{
        base_answer,
        try exec(arena, "C1", 1, "killed"),
        try execRan(arena, "C2", 0, "passed", "j1"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .step_cache = true,
        .test_ran_marker = "j1",
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 3), seen.len);
    try std.testing.expect(std.mem.indexOf(u8, seen[2], "its earlier run failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "killed") == null);
}

test "run threads the container through steps, applies conditions, and replays cached output" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);

    var s3 = testStep("c");
    s3.condition = "always()";
    var s4 = testStep("d");
    s4.condition = "success()";
    const steps = [_]job_mod.Step{ testStep("a"), testStep("b"), s3, s4 };
    const answers = [_][]const u8{
        base_answer,
        try exec(arena, "C1", 0, "from-a\\n"),
        try exec(arena, "C2", 3, "from-b\\n"),
        try exec(arena, "C3", 0, "from-c\\n"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);

    try std.testing.expectEqual(Outcome.success, res.steps[0].outcome);
    try std.testing.expectEqual(Outcome.failure, res.steps[1].outcome);
    try std.testing.expectEqual(@as(i32, 3), res.steps[1].exit_code);
    try std.testing.expectEqual(Outcome.success, res.steps[2].outcome); // always()
    try std.testing.expectEqual(Outcome.skipped, res.steps[3].outcome); // success() after a failure
    try std.testing.expect(!res.succeeded);
    // Every document is well-formed GraphQL (balanced braces outside of strings).
    for (fake.seen.items) |d| try std.testing.expect(braceBalanced(d));
    // Each step started from the previous step's container.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "id:\"C0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "id:\"C1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[3], "id:\"C2\"") != null);
    try std.testing.expectEqual(@as(usize, 4), fake.seen.items.len); // the skipped step sends nothing
    // No live lines were streamed, so the recorded stdout was replayed.
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "[job 0 step 1 stdout] from-a\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "[job 0 step 2 stdout] from-b\n") != null);
}

test "run streams live lines from the session's log and does not replay them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("a")};
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "live-line\\n") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };

    // The fake child also prints Dagger-style log output: noise, a span header, then the step's lines.
    const child =
        \\printf '0 tok\n'
        \\{ echo "connecting"; printf '\342\226\274 withExec sh -c '\''echo '\\\\'\''::zig-step::begin 1'\\\\'\''\\\\nexit $rc\\\\n'\'' (expect: ANY)\n'
        \\  echo "::zig-step::begin 1 m-job"; echo "live-line"; echo "::zig-step::end 1 m-job"; } >&2
        \\cat >/dev/null
    ;
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_step_mark = "m-job", .test_session_argv = &.{ "sh", "-c", child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, w.buffered(), "live-line\n"));
    // The markers carry the job's secret, so they are markers, not output.
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), marker) == null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "withExec") == null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "connecting") == null);
}

test "a step's last live lines, arriving after its exec answered, are its own and apply first" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("flood"), testStep("use") };
    // Step 1's end comes on the log stream well after its exec answered, as it does after a flood
    // (#140): a matcher and a mask in those late lines, which step 2 uses.
    const matcher_json = "{\"problemMatcher\":[{\"owner\":\"late\",\"pattern\":[{\"regexp\":" ++
        "\"^A:(.+):(\\\\d+): (.+)$\",\"file\":1,\"line\":2,\"message\":3}]}]}";
    var matcher_answer: std.Io.Writer.Allocating = .init(arena);
    try matcher_answer.writer.writeAll("{\"data\":{\"loadContainerFromID\":{\"file\":{\"contents\":");
    try std.json.Stringify.value(matcher_json, .{}, &matcher_answer.writer);
    try matcher_answer.writer.writeAll("}}}}");
    const answers = [_][]const u8{
        base_answer,
        try exec(arena, "C1", 0, ""),
        matcher_answer.written(),
        try exec(arena, "C2", 0, "A:f1:1: matcher hit\\nmask latesecret end\\n"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    const child =
        \\{ echo "::zig-step::begin 1 m-job"; echo "early"; } >&2
        \\printf '0 tok\n'
        \\sleep 0.3
        \\{ echo "late"; echo "::add-matcher::/m.json"; echo "::add-mask::latesecret"
        \\  echo "::zig-step::end 1 m-job"; } >&2
        \\cat >/dev/null
    ;
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_step_mark = "m-job", .test_session_argv = &.{ "sh", "-c", child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const got = w.buffered();
    // The late line is step 1's, logged before anything of step 2's.
    const late = std.mem.indexOf(u8, got, "[job 0 step 1 stdout] late\n") orelse
        return error.TestUnexpectedResult;
    const step2 = std.mem.indexOf(u8, got, "[job 0 step 2 ") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(late < step2);
    // The matcher was read after step 1, and step 2's line matched it; the mask held for step 2.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "file(path:\"/m.json\")") != null);
    try std.testing.expectEqual(@as(usize, 1), res.annotations.len);
    try std.testing.expectEqual(@as(u32, 2), res.annotations[0].step);
    try std.testing.expectEqualStrings("matcher hit", res.annotations[0].an.message);
    try std.testing.expect(std.mem.indexOf(u8, got, "latesecret") == null);
    try std.testing.expect(std.mem.indexOf(u8, got, "mask *** end") != null);
}

test "run reports an engine error when the session cannot start" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("a")};
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", "echo 'cannot connect to docker' >&2; exit 1" } }, testJob(&steps), &log);
    try std.testing.expect(!res.succeeded);
    try std.testing.expect(res.engine_error != null);
    try std.testing.expectEqual(Outcome.not_run, res.steps[0].outcome);
}

test "run evaluates expressions in conditions, names, env, scripts and the steps context" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);

    const json =
        \\{"plan":{"planId":"p"},"jobId":"j","resources":{"endpoints":[{"authorization":{"parameters":{"AccessToken":"t"}}}]},
        \\ "variables":{"TOKEN":{"value":"s3cr3t-value","isSecret":true}},
        \\ "environmentVariables":[{"type":2,"map":[{"Key":{"lit":"JOB_ENV"},"Value":{"type":3,"expr":"format('{0}-job', github.ref_name)"}},{"Key":{"lit":"JOB_SECRET"},"Value":{"type":3,"expr":"secrets.TOKEN"}}]}],
        \\ "contextData":{"matrix":null,"github":{"t":2,"d":[{"k":"ref","v":"refs/heads/main"},{"k":"ref_name","v":"main"},{"k":"sha","v":"abc123"},{"k":"repository","v":"o/r"}]}},
        \\ "steps":[
        \\  {"type":"action","reference":{"type":"script"},"id":"s1","contextName":"first","name":"first","condition":"success()",
        \\   "displayNameToken":{"type":3,"expr":"format('Build {0}', github.ref_name)"},
        \\   "environment":{"type":2,"map":[{"Key":{"lit":"STEP_ENV"},"Value":{"type":3,"expr":"github.sha"}}]},
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"type":3,"expr":"format('echo {0} $STEP_ENV {1}', github.sha, env.JOB_ENV)"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s2","contextName":"__run","name":"__run","condition":"success() && (github.ref == 'refs/heads/main')",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo on-main"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s3","contextName":"__run_2","name":"__run_2","condition":"success() && (github.ref == 'refs/heads/other')",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo never"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s4","contextName":"__run_3","name":"__run_3","condition":"success()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"type":3,"expr":"format('echo outcome={0} skipped={1}', steps.first.outcome, steps.__run_2.outcome)"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s5","contextName":"__run_4","name":"__run_4","condition":"success()",
        \\   "environment":{"type":2,"map":[{"Key":{"lit":"DB_PASSWORD"},"Value":{"type":3,"expr":"secrets.TOKEN"}},{"Key":{"lit":"WITH_SECRET"},"Value":{"type":3,"expr":"format('user:{0}@host', secrets.TOKEN)"}}]},
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo uses-secret-env"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s6","contextName":"__run_5","name":"__run_5","condition":"always()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo cleanup"}}]}}
        \\ ]}
    ;
    const job = try job_mod.parse(arena, json);
    const answers = [_][]const u8{
        "{\"data\":{\"zsec0\":{\"id\":\"SEC_JOB\"}}}", // JOB_SECRET (job-level env), before the base container
        base_answer,
        try exec(arena, "C1", 0, "ok\\n"),
        try exec(arena, "C2", 0, "ok\\n"),
        try exec(arena, "C3", 0, "ok\\n"),
        // WITH_SECRET; DB_PASSWORD has JOB_SECRET's value, which is registered already.
        "{\"data\":{\"zsec0\":{\"id\":\"SEC_B\"}}}",
        try exec(arena, "C4", 0, "ok\\n"),
        try exec(arena, "C5", 0, "ok\\n"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);

    // Names and outcomes.
    try std.testing.expectEqualStrings("Build main", res.steps[0].name);
    try std.testing.expectEqual(Outcome.success, res.steps[0].outcome);
    try std.testing.expectEqual(Outcome.success, res.steps[1].outcome);
    try std.testing.expectEqual(Outcome.skipped, res.steps[2].outcome); // condition false
    try std.testing.expectEqual(Outcome.success, res.steps[3].outcome);
    try std.testing.expectEqual(Outcome.success, res.steps[4].outcome);
    try std.testing.expectEqual(Outcome.success, res.steps[5].outcome);
    try std.testing.expect(res.succeeded);
    for (fake.seen.items) |d| try std.testing.expect(braceBalanced(d));
    // seen: 0 setSecret(job), 1 base, 2 s1, 3 s2, 4 s4, 5 setSecret, 6 s5, 7 s6
    try std.testing.expectEqual(@as(usize, 8), fake.seen.items.len);
    // Evaluated scripts reached Dagger: sha, step env, job env (from an expression), steps.* outcomes.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "echo abc123 $STEP_ENV main-job") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "STEP_ENV=abc123") != null);
    // `__run_2` is a generated id, which GitHub leaves out of the steps context: it reads as empty.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[4], "echo outcome=success skipped='") != null);
    // Job-level env is part of the base container: the plain value inline, the secret as a Dagger secret.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withEnvVariable(name:\"JOB_ENV\",value:\"main-job\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "withSecretVariable(name:\"JOB_SECRET\",secret:\"SEC_JOB\")") != null);
    // Secret-bearing step env is passed as Dagger secrets under aliases, given its name by the script,
    // removed again after the step, and appears nowhere in a command.
    const s5 = fake.seen.items[6];
    try std.testing.expect(std.mem.indexOf(u8, s5, "withSecretVariable(name:\"ZIG_SECRET_0\",secret:\"SEC_JOB\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, s5, "withSecretVariable(name:\"ZIG_SECRET_1\",secret:\"SEC_B\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, s5, "env -u ZIG_SECRET_0 -u ZIG_SECRET_1 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, s5, "'DB_PASSWORD='\\\"$ZIG_SECRET_0\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s5, "withoutSecretVariable(name:\"ZIG_SECRET_0\") { withoutSecretVariable(name:\"ZIG_SECRET_1\") { id } }") != null);
    // The next step does not get them.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[7], "ZIG_SECRET") == null);
    for (fake.seen.items, 0..) |d, i| {
        const is_set_secret = std.mem.indexOf(u8, d, "setSecret") != null;
        try std.testing.expectEqual(is_set_secret, std.mem.indexOf(u8, d, "s3cr3t-value") != null);
        _ = i;
    }
}

test "defaults.run gives run: steps their shell and working directory unless they set their own" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    // The workflow's defaults.run, then the job's, which replaces it whole: the workflow's
    // working-directory is gone, and the job's comes from an expression.
    const json =
        \\{"plan":{"planId":"p"},"jobId":"j","resources":{"endpoints":[{"authorization":{"parameters":{"AccessToken":"t"}}}]},
        \\ "defaults":[{"type":2,"map":[{"Key":{"lit":"run"},"Value":{"type":2,"map":[{"Key":{"lit":"working-directory"},"Value":{"lit":"wf"}}]}}]},
        \\  {"type":2,"map":[{"Key":{"lit":"run"},"Value":{"type":2,"map":[{"Key":{"lit":"shell"},"Value":{"lit":"bash"}},{"Key":{"lit":"working-directory"},"Value":{"type":3,"expr":"format('app-{0}', github.ref_name)"}}]}}]}],
        \\ "contextData":{"github":{"t":2,"d":[{"k":"ref_name","v":"main"}]}},
        \\ "steps":[
        \\  {"type":"action","reference":{"type":"script"},"id":"s1","contextName":"__run","name":"__run","condition":"success()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"false | true"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s2","contextName":"__run_2","name":"__run_2","condition":"success()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo own"}},{"Key":{"lit":"shell"},"Value":{"lit":"sh"}},{"Key":{"lit":"workingDirectory"},"Value":{"lit":"own"}}]}}
        \\ ]}
    ;
    const job = try job_mod.parse(arena, json);
    const answers = [_][]const u8{
        base_answer,
        try exec(arena, "C1", 0, ""),
        try exec(arena, "C2", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 3), fake.seen.items.len);
    // The step without its own: the defaults' `bash` (pipefail, so `false | true` fails as on
    // GitHub) in the job's directory, and the log header says so.
    const s1 = fake.seen.items[1];
    try std.testing.expect(std.mem.indexOf(u8, s1, "cd 'app-main' && ") != null);
    try std.testing.expect(std.mem.indexOf(u8, s1, "'bash' '--noprofile' '--norc' '-e' '-o' 'pipefail' '/tmp/zig-runner-step-1.sh'") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}") != null);
    // The step's own settings win.
    const s2 = fake.seen.items[2];
    try std.testing.expect(std.mem.indexOf(u8, s2, "cd 'own' && ") != null);
    try std.testing.expect(std.mem.indexOf(u8, s2, "'sh' '-e' '/tmp/zig-runner-step-2.sh'") != null);
    try std.testing.expect(std.mem.indexOf(u8, s2, "app-main") == null);
}

test "defaults.run that cannot be evaluated fails Set up job, and no step runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("echo never")};
    var job = testJob(&steps);
    job.defaults_run = .{ .shell = .{ .expr = "no_such_function()" } };
    const answers = [_][]const u8{base_answer};
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(!res.succeeded);
    try std.testing.expect(res.set_up_failed);
    try std.testing.expectEqual(@as(usize, 1), fake.seen.items.len);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "defaults.run.shell: ") != null);
}

test "a step's shell or working-directory that cannot be evaluated fails the step" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var bad_shell = testStep("echo never");
    bad_shell.action.script.shell = .{ .expr = "no_such_function()" };
    var bad_wd = testStep("echo never");
    bad_wd.action.script.working_directory = .{ .expr = "fromJSON('not json')" };
    bad_wd.condition = "always()";
    var after = testStep("echo after");
    after.condition = "always()";
    const steps = [_]job_mod.Step{ bad_shell, bad_wd, after };
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(!res.succeeded);
    try std.testing.expectEqual(Outcome.failure, res.steps[0].outcome);
    try std.testing.expectEqual(Outcome.failure, res.steps[1].outcome);
    try std.testing.expectEqual(Outcome.success, res.steps[2].outcome);
    // Neither ran: the only exec is the last step's.
    try std.testing.expectEqual(@as(usize, 2), fake.seen.items.len);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "echo after") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "could not evaluate shell: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "could not evaluate working-directory: ") != null);
}

test "the steps context holds only steps with an id of their own, as on GitHub" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    // A step without `id:` fails but continues on error; GitHub leaves its generated `__run` out
    // of `steps`, so `contains(steps.*.outcome, 'failure')` is false. A step without any name is
    // left out too.
    var unnamed_fails = testStep("exit 1");
    unnamed_fails.context_name = "__run";
    unnamed_fails.continue_on_error = .{ .lit = "true" };
    const nameless = testStep("true");
    var named = testStep("true");
    named.context_name = "build";
    var check = testStep("");
    check.action.script.script = .{ .expr = "format('echo any-failure={0} generated={1} " ++
        "named={2}', contains(steps.*.outcome, 'failure'), steps.__run.outcome, " ++
        "join(steps.*.outcome, ','))" };
    const steps = [_]job_mod.Step{ unnamed_fails, nameless, named, check };
    const answers = [_][]const u8{
        base_answer,
        try exec(arena, "C1", 1, ""),
        try exec(arena, "C2", 0, ""),
        try exec(arena, "C3", 0, ""),
        try exec(arena, "C4", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 5), fake.seen.items.len);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[4], "echo any-failure=false generated= named=success'") != null);
}

test "file commands: outputs feed steps.<id>.outputs, GITHUB_ENV and GITHUB_PATH reach later steps" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const json =
        \\{"plan":{"planId":"p"},"jobId":"j","resources":{"endpoints":[{"authorization":{"parameters":{"AccessToken":"t"}}}]},
        \\ "contextData":{"github":{"t":2,"d":[{"k":"sha","v":"abc"},{"k":"repository","v":"o/r"},{"k":"ref_name","v":"main"}]}},
        \\ "steps":[
        \\  {"type":"action","reference":{"type":"script"},"id":"s1","contextName":"build","name":"build","condition":"success()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo producing"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s2","contextName":"use","name":"use","condition":"success()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"type":3,"expr":"format('echo version={0} multi={1} env=$FROM_ENV sha={2}', steps.build.outputs.version, steps.build.outputs.notes, env.GITHUB_SHA)"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s3","contextName":"bad","name":"bad","condition":"success()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo writes garbage"}}]}},
        \\  {"type":"action","reference":{"type":"script"},"id":"s4","contextName":"after","name":"after","condition":"always()",
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo done"}}]}}
        \\ ]}
    ;
    const job = try job_mod.parse(arena, json);
    const answers = [_][]const u8{
        base_answer,
        try execFc(arena, "C1", "producing\\n", "version=1.2.3\\nnotes<<EOF\\nline a\\nline b\\nEOF\\n", "FROM_ENV=hello\\nGITHUB_SHA=evil\\nCI=false\\nGITHUB_TOKEN=pat\\n" ++
            "NODE_OPTIONS=--require=/x.js\\n", "/opt/tool/bin\\n"),
        try execFc(arena, "C2", "x\\n", "", "", ""),
        try execFc(arena, "C3", "y\\n", "this is not valid\\n", "BEFORE=1\\nnope\\nAFTER=2\\n", ""),
        try execFc(arena, "C4", "z\\n", "", "", ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);

    for (fake.seen.items) |d| try std.testing.expect(braceBalanced(d));
    // Default environment is set once on the base container.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "withEnvVariable(name:\"GITHUB_SHA\",value:\"abc\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "name:\"CI\",value:\"true\"") != null);
    // Step 1's query reads the file commands.
    // One read for all of a step's file commands, combined by its script.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "fc_all: file(path:\"/github/file_commands/all_1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "fc_output: file(") == null);
    // Outputs (including a multi-line one) were evaluated into step 2's script.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "echo version=1.2.3 multi=line a\\nline b env=$FROM_ENV sha=evil") != null);
    // GITHUB_ENV and GITHUB_PATH apply to the next step's container, GITHUB_* and CI included.
    // A default GitHub sets again over the env context keeps its value in the container, but
    // the env context has what the step wrote (above); NODE_OPTIONS alone is refused, as an
    // error annotation that does not fail the step.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "withEnvVariable(name:\"FROM_ENV\",value:\"hello\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "withEnvVariable(name:\"PATH\",value:\"/opt/tool/bin:$PATH\",expand:true)") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "name:\"GITHUB_SHA\",value:\"evil\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "withEnvVariable(name:\"CI\",value:\"false\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "withEnvVariable(name:\"GITHUB_TOKEN\",value:\"pat\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "NODE_OPTIONS") == null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "##[error]Can't store NODE_OPTIONS output parameter using '$GITHUB_ENV' command.") != null);
    try std.testing.expectEqual(Outcome.success, res.steps[0].outcome);
    // ...and only once: step 3 no longer re-applies them.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[3], "withEnvVariable") == null);
    // A malformed file command fails the step that wrote it, with GitHub's two errors; always()
    // still runs. What came before the bad line applies, as on GitHub; nothing after it.
    try std.testing.expectEqual(Outcome.failure, res.steps[2].outcome);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "##[error]Unable to process file command 'output' successfully.") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "##[error]invalid format 'this is not valid' on line 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "##[error]Unable to process file command 'env' successfully.") != null);
    // Its process exited 0, so no exit code is logged, as on GitHub (#214).
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "Process completed with exit code") == null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[4], "withEnvVariable(name:\"BEFORE\",value:\"1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[4], "AFTER") == null);
    try std.testing.expectEqual(Outcome.success, res.steps[3].outcome);
}

test "GITHUB_PATH: newest directory first, each once, also before a step env or GITHUB_ENV PATH" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var custom = testStep("custom");
    custom.env = &.{.{ .name = "PATH", .value = .{ .lit = "/custom" } }};
    var last = testStep("last");
    last.env = &.{.{ .name = "PATH", .value = .{ .lit = "/x" } }};
    const steps = [_]job_mod.Step{ testStep("first"), custom, last };
    const answers = [_][]const u8{
        base_answer,
        try execFc(arena, "C1", "", "", "", "/a\\n/b\\n/a\\n/c\\n"),
        try execFc(arena, "C2", "", "", "PATH=/env\\n", "/b\\n"),
        try exec(arena, "C3", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    // GitHub keeps [/b, /a, /c] and prepends it reversed.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "withEnvVariable(name:\"PATH\",value:\"/c:/a:/b:$PATH\",expand:true)") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "PATH=/c:/a:/b:/custom") != null);
    // /b again moves to the front, here and before the next step's own PATH; a PATH set
    // through GITHUB_ENV keeps every directory in front of it.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[3], "withEnvVariable(name:\"PATH\",value:\"/b:/c:/a:/env\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[3], "$PATH") == null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[3], "PATH=/b:/c:/a:/x") != null);
}

test "GITHUB_PATH in a container job: the directories, then the container's own PATH, over any PATH" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var custom = testStep("custom");
    custom.env = &.{.{ .name = "PATH", .value = .{ .lit = "/custom" } }};
    const steps = [_]job_mod.Step{ testStep("first"), custom, testStep("last") };
    var job = testJob(&steps);
    job.container = .{ .name = "", .image = .{ .lit = "node:20" } };
    const own = "/usr/local/bin:/usr/bin";
    const answers = [_][]const u8{
        "{\"data\":{\"container\":{\"from\":{\"zig_runtime_path\":\"" ++ own ++ "\"," ++
            "\"withWorkdir\":{\"id\":\"C0\"}}}}}",
        // starting the job container: its image's digest, and whether it is musl
        "{\"data\":{\"container\":{\"from\":{\"imageRef\":\"node:20\"}}}}",
        "{\"data\":{\"container\":{\"from\":{\"directory\":{\"entries\":[]}}}}}",
        try execFc(arena, "C1", "", "", "", "/a\\n/b\\n"),
        try execFc(arena, "C2", "", "", "PATH=/from-github-env\\n", ""),
        try exec(arena, "C3", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expect(std.mem.indexOf(u8, seen[0], "zig_runtime_path: envVariable(name:\"PATH\")") != null);
    // GitHub's `docker exec -e PATH="<directories>:<container PATH>"` comes after the step's env.
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "withEnvVariable(name:\"PATH\",value:\"/b:/a:" ++ own ++ "\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "PATH=/b:/a:" ++ own) != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "/custom") == null);
    // ...and after a PATH written to GITHUB_ENV.
    try std.testing.expect(std.mem.indexOf(u8, seen[5], "withEnvVariable(name:\"PATH\",value:\"/b:/a:" ++ own ++ "\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[5], "/from-github-env") == null);
}

test "an output set twice keeps its last value, case-insensitively; GITHUB_OUTPUT beats set-output" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var first = testStep("x");
    first.context_name = "p";
    var after = testStep("");
    after.action.script.script = .{ .expr = "format('echo v={0} legacy={1} both={2}', " ++
        "steps.p.outputs.v, steps.p.outputs.LEGACY, steps.p.outputs.both)" };
    const steps = [_]job_mod.Step{ first, after };
    const legacy = "::set-output name=Legacy::old\\n::set-output name=legacy::new\\n" ++
        "::set-output name=both::from-command\\n";
    const answers = [_][]const u8{
        base_answer,
        try execFc(arena, "C1", legacy, "v=1\\nV=2\\nboth=from-file\\n", "", ""),
        try exec(arena, "C2", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "echo v=2 legacy=new both=from-file") != null);
}

const Recorder = struct {
    events: std.ArrayList([]const u8) = .empty,
    arena: Allocator,

    fn started(ptr: *anyopaque, number: u32, name: []const u8, started_ms: i64) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        const msg = std.fmt.allocPrint(
            self.arena,
            "start {d} {s} {s}",
            .{ number, name, if (started_ms > 0) "t" else "-" },
        ) catch return;
        self.events.append(self.arena, msg) catch {};
    }

    fn finished(ptr: *anyopaque, number: u32, r: StepResult) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        const msg = std.fmt.allocPrint(
            self.arena,
            "finish {d} {s} {s}",
            .{ number, r.name, @tagName(r.outcome) },
        ) catch return;
        self.events.append(self.arena, msg) catch {};
    }
};

test "the observer sees each step start and finish, including skipped and failed-to-evaluate steps" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var s2 = testStep("never");
    s2.condition = "failure()";
    var s3 = testStep("x");
    s3.action = .{ .unsupported = "not supported here" };
    const steps = [_]job_mod.Step{ testStep("ok"), s2, s3, testStep("bad") };
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "a\\n"), try exec(arena, "C2", 1, "b\\n") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var rec: Recorder = .{ .arena = arena };
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    // step 3 is unsupported (fails without running); step 4 is skipped by success() afterwards.
    _ = try run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
        .observer = .{ .ptr = &rec, .startedFn = Recorder.started, .finishedFn = Recorder.finished },
    }, testJob(&steps), &log);

    const want = [_][]const u8{
        "start 1 n t", // the step has begun, with a start time
        "finish 1 n success",
        "finish 2 n skipped", // failure() was false: reported once, never "started"
        "finish 3 n failure", // unsupported: reported once, never "started"
        "finish 4 n skipped", // success() after a failure
    };
    try std.testing.expectEqual(want.len, rec.events.items.len);
    for (want, rec.events.items) |expected, got| try std.testing.expectEqualStrings(expected, got);
}

// --- composite actions ---

test "a replay logs what the live run logged: one stream, in order, blank lines and masks too" {
    // The step's output as its script wrote it, stdout and stderr in one stream
    // (`stream_prologue`): a stderr line before the mask, a blank line, the secret after it, a
    // stopped command, a line without a trailing newline before the end marker, and marker text
    // of the step's own.
    const body = [_][]const u8{
        "out: starting",
        "err: password hunter2 leaked early",
        "",
        "::add-mask::hunter2",
        "err: hunter2 again",
        "",
        "::stop-commands::tok",
        "::group::not a group",
        "::tok::",
        marker ++ "end 1 another-jobs-secret",
        marker ++ "begin 2",
    };
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    const logOf = struct {
        fn f(arena: Allocator, mark: []const u8, comptime replay: bool, lines: []const []const u8, tail: []const u8) ![]const u8 {
            var aw: std.Io.Writer.Allocating = .init(arena);
            var log: sink.LogSink = .{ .stdout = .{ .writer = &aw.writer } };
            var live = [_]std.atomic.Value(u32){ .init(0), .init(0) };
            var ended = [_]std.atomic.Value(bool){ .init(false), .init(false) };
            var replayed = [_]bool{ false, false };
            var cmds = [_]JobLog.StepCommands{ .{}, .{} };
            var line_counts = [_]u32{ 0, 0, 0 };
            var sh: JobLog = .{ .io = std.testing.io, .arena = arena, .log = &log, .sink_job_id = 0, .live_lines = &live, .ended = &ended, .replayed_steps = &replayed, .commands = &cmds, .line_counts = &line_counts, .mark = "this-job" };
            const begin = try std.fmt.allocPrint(arena, marker ++ "begin 1 {s}", .{mark});
            const end = try std.fmt.allocPrint(arena, "{s}" ++ marker ++ "end 1 {s}", .{ tail, mark });
            if (replay) {
                // The exec's recorded stdout, from an earlier job (another secret).
                var rec: std.ArrayList(u8) = .empty;
                try rec.appendSlice(arena, begin);
                try rec.append(arena, '\n');
                for (lines) |l| {
                    try rec.appendSlice(arena, l);
                    try rec.append(arena, '\n');
                }
                try rec.appendSlice(arena, end);
                try rec.append(arena, '\n');
                try std.testing.expect(awaitLiveOrReplay(std.testing.io, &sh, 1, rec.items, "", false));
            } else {
                var sd: SpanDemux = .{ .sh = &sh, .gpa = std.testing.allocator };
                defer sd.deinit();
                var span: SpanDemux.Span = .{};
                sd.line(&span, begin);
                for (lines) |l| sd.line(&span, l);
                sd.line(&span, end);
                try std.testing.expect(ended[0].load(.acquire));
            }
            try log.flush();
            return aw.written();
        }
    }.f;
    const live_log = try logOf(ar, "this-job", false, &body, "no newline");
    const replay_log = try logOf(ar, "earlier-job", true, &body, "no newline");
    try std.testing.expectEqualStrings(live_log, replay_log);
    // And what that log is: masked from the mask on, blank lines kept, commands stopped.
    try std.testing.expectEqualStrings(
        "[job 0 step 1 stdout] out: starting\n" ++
            "[job 0 step 1 stdout] err: password hunter2 leaked early\n" ++
            "[job 0 step 1 stdout] \n" ++
            "[job 0 step 1 stdout] err: *** again\n" ++
            "[job 0 step 1 stdout] \n" ++
            "[job 0 step 1 stdout] ::stop-commands::tok\n" ++
            "[job 0 step 1 stdout] ::group::not a group\n" ++
            "[job 0 step 1 stdout] ::tok::\n" ++
            "[job 0 step 1 stdout] " ++ marker ++ "end 1 another-jobs-secret\n" ++
            "[job 0 step 1 stdout] " ++ marker ++ "begin 2\n" ++
            "[job 0 step 1 stdout] no newline\n",
        live_log,
    );
}

test "steps see the name the runner registered under" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var st = testStep("");
    st.action.script.script = .{ .expr = "format('echo {0}', runner.name)" };
    const steps = [_]job_mod.Step{st};
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    _ = try run(arena, std.testing.io, &env, .{ .runner_name = "zig-1a2b3c4d", .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "withEnvVariable(name:\"RUNNER_NAME\",value:\"zig-1a2b3c4d\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "echo zig-1a2b3c4d") != null);
}

test "the workspace is where GitHub's runner puts it, /__w in a container job" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var job = testJob(&.{});
    job.github.repository = "Lementknight/zig-actions-runner";
    try std.testing.expectEqualStrings("/home/runner/work/zig-actions-runner/zig-actions-runner", try jobWorkspace(arena, job));
    try std.testing.expectEqualStrings("/home/runner/work/_temp", try jobTemp(arena, job));
    job.container = .{ .name = "", .image = .{ .lit = "golang:1.26" } };
    try std.testing.expectEqualStrings("/__w/zig-actions-runner/zig-actions-runner", try jobWorkspace(arena, job));
    try std.testing.expectEqualStrings("/__w/_temp", try jobTemp(arena, job));
}

test "logs read like GitHub's: Set up job, then each step's header with its shell, env or inputs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var run_step = testStep("echo one\necho two");
    run_step.env = &.{
        .{ .name = "GREETING", .value = .{ .lit = "hi" } },
        .{ .name = "TOKEN", .value = .{ .lit = "s3cr3t-value" } },
    };
    var co = testStep("x");
    co.action = .{ .checkout = &.{.{ .name = "fetch-depth", .value = .{ .lit = "0" } }} };
    co.uses = "actions/checkout@v4";
    const action_yml = "runs:\n  using: composite\n  steps:\n    - shell: sh\n      run: echo from-the-action\n";
    const steps = [_]job_mod.Step{ co, usesStep("act", "o", "act", "v1", &.{}), run_step };
    var job = testJob(&steps);
    job.secrets = &.{"s3cr3t-value"};
    job.display_name = "build (linux)";
    job.runner_group = "Default";
    job.token_permissions = "{\"Contents\":\"read\",\"PullRequests\":\"write\"}";
    job.env = &.{.{ .name = "FROM_JOB", .value = .{ .lit = "j" } }};
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"git\":{\"ref\":{\"tree\":{\"id\":\"D1\",\"entries\":[\"action.yml\"]},\"sha\":\"0123456789abcdef0123456789abcdef01234567\"}}}}",
        try fileAnswer(arena, action_yml),
        "{\"data\":{\"git\":{\"commit\":{\"tree\":{\"id\":\"TREE1\"}}}}}",
        try exec(arena, "C1", 0, ""),
        try exec(arena, "C2", 0, ""),
        "{\"data\":{\"zsec0\":{\"id\":\"SEC\"}}}",
        try exec(arena, "C3", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w, .secrets = &.{"s3cr3t-value"} } };
    const res = try run(arena, std.testing.io, &env, .{ .runner_name = "zig-1a2b3c4d", .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "tree(depth:1) { id entries(path:\".\") } sha: commit") != null);
    const out = w.buffered();
    const want_in_order = [_][]const u8{
        // GitHub's protocol version, then this build's own, which is the line a job's log is read
        // for when a machine is behaving unexpectedly.
        "[job 0 step 0 stdout] Current runner version: '" ++ broker.version ++ "' (zig-runner " ++ build_version.string ++ ")",
        "[job 0 step 0 stdout] Runner name: 'zig-1a2b3c4d'",
        "[job 0 step 0 stdout] Runner group name: 'Default'",
        "[job 0 step 0 stdout] ##[group]Runner Image",
        "[job 0 step 0 stdout] Image: " ++ default_image,
        "[job 0 step 0 stdout] ##[group]GITHUB_TOKEN Permissions",
        "[job 0 step 0 stdout] Contents: read",
        "[job 0 step 0 stdout] PullRequests: write",
        "[job 0 step 0 stdout] Secret source: Actions",
        "[job 0 step 0 stdout] Prepare workflow directory",
        "[job 0 step 0 stdout] Prepare all required actions",
        "[job 0 step 0 stdout] Getting action download info",
        "[job 0 step 0 stdout] Download action repository 'o/act@v1' (SHA:0123456789abcdef0123456789abcdef01234567)",
        "[job 0 step 0 stdout] Complete job name: build (linux)",
        "[job 0 step 1 stdout] ##[group]Run actions/checkout@v4",
        "[job 0 step 1 stdout] with:",
        "[job 0 step 1 stdout]   fetch-depth: 0",
        "[job 0 step 1 stdout] ##[endgroup]",
        "[job 0 step 2 stdout] ##[group]Run echo from-the-action",
        "[job 0 step 2 stdout] shell: /usr/bin/sh -e {0}",
        "[job 0 step 3 stdout] ##[group]Run echo one",
        "[job 0 step 3 stdout] echo one",
        "[job 0 step 3 stdout] echo two",
        "[job 0 step 3 stdout] shell: /usr/bin/bash -e {0}",
        "[job 0 step 3 stdout] env:",
        "[job 0 step 3 stdout]   FROM_JOB: j",
        "[job 0 step 3 stdout]   GREETING: hi",
        "[job 0 step 3 stdout]   TOKEN: ***",
        "[job 0 step 3 stdout] ##[endgroup]",
    };
    var at: usize = 0;
    for (want_in_order) |want| {
        const i = std.mem.indexOfPos(u8, out, at, want) orelse {
            std.debug.print("missing (in order): {s}\nlog:\n{s}\n", .{ want, out });
            return error.TestUnexpectedResult;
        };
        at = i + want.len;
    }
    // The default shell is GitHub's `bash -e` (no pipefail); an explicit `sh` stays `sh -e`.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[7], "printf '%s' 'echo one\\necho two' > /tmp/zig-runner-step-3.sh") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[7], "\\\"$zig_shell\\\" '-e' '/tmp/zig-runner-step-3.sh'") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[5], "'sh' '-e' '/tmp/zig-runner-step-") != null);
}

test "masks a step sets, and the job's secrets, keep a job output and a step's name from leaving unmasked" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    // The step's name names a secret; the step masks an OIDC-style token and outputs it (#96).
    var st = testStep("mint");
    st.context_name = "m";
    st.name_expr = "format('Deploy with {0}', 'hunter2-secret')";
    const steps = [_]job_mod.Step{st};
    var job = testJob(&steps);
    job.secrets = &.{"hunter2-secret"};
    job.outputs = &.{
        .{ .name = "token", .value = .{ .expr = "steps.m.outputs.token" } },
        .{ .name = "fine", .value = .{ .lit = "ok" } },
    };
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"::add-mask::minted-token-123\\n\",\"stderr\":\"\",\"fc_output\":{\"contents\":\"token=minted-token-123\\n\"}}}}}",
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    // As loop.zig sets the job's secrets before its steps run.
    log.setSecrets(try redact.expand(arena, job.secrets));
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqualStrings("Deploy with ***", res.steps[0].name);
    try std.testing.expectEqual(@as(usize, 1), res.outputs.len);
    try std.testing.expectEqualStrings("fine", res.outputs[0].name);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "minted-token-123") == null);
}

test "job outputs are evaluated after the steps; one carrying a secret is skipped" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var st = testStep("echo version=1.2.3 >> $GITHUB_OUTPUT");
    st.context_name = "v";
    const steps = [_]job_mod.Step{st};
    var job = testJob(&steps);
    job.secrets = &.{"s3cr3t-value"};
    job.outputs = &.{
        .{ .name = "version", .value = .{ .expr = "steps.v.outputs.version" } },
        .{ .name = "literal", .value = .{ .lit = "fixed" } },
        .{ .name = "combined", .value = .{ .expr = "format('v={0}', steps.v.outputs.version)" } },
        .{ .name = "leak", .value = .{ .lit = "token s3cr3t-value" } },
    };
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"fc_output\":{\"contents\":\"version=1.2.3\\n\"}}}}}",
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 3), res.outputs.len);
    try std.testing.expectEqualStrings("version", res.outputs[0].name);
    try std.testing.expectEqualStrings("1.2.3", res.outputs[0].value);
    try std.testing.expectEqualStrings("fixed", res.outputs[1].value);
    try std.testing.expectEqualStrings("v=1.2.3", res.outputs[2].value);
    const want = [_][]const u8{ "Evaluate and set job outputs", "Set output 'version'", "Set output 'literal'", "Set output 'combined'", "##[warning]Skip output 'leak' since it may contain secret." };
    try std.testing.expectEqual(want.len, res.output_lines.len);
    for (want, res.output_lines) |wnt, got| try std.testing.expectEqualStrings(wnt, got);
}

test "environment.url is evaluated after the steps and reported, unless it carries a secret" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var st = testStep("echo page=https://pr-7.example.test >> $GITHUB_OUTPUT");
    st.context_name = "deploy";
    const steps = [_]job_mod.Step{st};
    const Case = struct { url: job_mod.Template, want: ?[]const u8, line: []const u8, ok: bool };
    const cases = [_]Case{
        .{ .url = .{ .expr = "steps.deploy.outputs.page" }, .want = "https://pr-7.example.test", .line = "Evaluated environment url: https://pr-7.example.test", .ok = true },
        .{ .url = .{ .lit = "https://x.test/?t=s3cr3t-value" }, .want = null, .line = "##[warning]Skip setting environment url as environment 'preview' may contain secret.", .ok = true },
        // GitHub fails the job when the url cannot be evaluated.
        .{ .url = .{ .expr = "fromJSON('not json')" }, .want = null, .line = "##[error]Failed to evaluate environment url", .ok = false },
    };
    for (cases) |c| {
        var job = testJob(&steps);
        job.secrets = &.{"s3cr3t-value"};
        job.environment = .{ .name = "preview", .url = c.url };
        const answers = [_][]const u8{
            base_answer,
            "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"fc_output\":{\"contents\":\"page=https://pr-7.example.test\\n\"}}}}}",
        };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
        try std.testing.expectEqual(c.ok, res.succeeded);
        if (c.want) |u| try std.testing.expectEqualStrings(u, res.environment_url.?) else try std.testing.expect(res.environment_url == null);
        try std.testing.expectEqualStrings("Evaluate and set environment url", res.output_lines[0]);
        try std.testing.expectEqualStrings(c.line, res.output_lines[1]);
    }
}

test "steps get the engine (privileged nesting) unless it is turned off" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("dagger call ci")};
    for ([_]bool{ true, false }) |nesting| {
        const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "") };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        _ = try run(arena, std.testing.io, &env, .{ .nesting = nesting, .trusted = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
        // The setup query (and its provisioning exec) never gets it; the step does when enabled.
        try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "experimentalPrivilegedNesting") == null);
        try std.testing.expectEqual(nesting, std.mem.indexOf(u8, fake.seen.items[1], ",expect:ANY,experimentalPrivilegedNesting:true)") != null);
        try std.testing.expect(braceBalanced(fake.seen.items[1]));
    }
}

test "steps get the engine only in jobs the runner vouches for, and a step that needs it is told why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("dagger call ci")};
    // A fork's pull request, which a runner vouching for pull requests still does not share
    // its trusted caches with (`packageCacheScope`).
    const fork_ctx =
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"event","v":{"t":2,"d":[
    ++
        \\{"k":"pull_request","v":{"t":2,"d":[{"k":"head","v":{"t":2,"d":[{"k":"repo","v":
    ++
        \\{"t":2,"d":[{"k":"full_name","v":"someone/r"}]}}]}}]}}]}}]}}
    ;
    const Case = struct { trusted: bool, fork: bool, nesting: bool };
    for ([_]Case{
        .{ .trusted = true, .fork = false, .nesting = true },
        .{ .trusted = false, .fork = false, .nesting = false },
        .{ .trusted = true, .fork = true, .nesting = false },
    }) |c| {
        var job = testJob(&steps);
        if (c.fork) job.context_data = try std.json.parseFromSliceLeaky(
            std.json.Value,
            arena,
            fork_ctx,
            .{},
        );
        // The step fails, as `dagger` does when it finds no engine.
        const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 1, "") };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        _ = try run(arena, std.testing.io, &env, .{
            .nesting = true,
            .trusted = c.trusted,
            .test_session_argv = &.{ "sh", "-c", fake_child },
            .test_transport = fake.transport(),
        }, job, &log);
        const step = fake.seen.items[1];
        try std.testing.expectEqual(c.nesting, std.mem.indexOf(
            u8,
            step,
            "experimentalPrivilegedNesting",
        ) != null);
        const out = w.buffered();
        try std.testing.expectEqual(!c.nesting, std.mem.indexOf(u8, out, "Dagger in steps: off") !=
            null);
        try std.testing.expectEqual(!c.nesting, std.mem.indexOf(
            u8,
            out,
            Exec.nesting_withheld_note,
        ) != null);
    }
}

test "workflow commands in a step's output: masks, groups, annotations, debug, set-output, stop-commands" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var after = testStep("");
    after.action.script.script = .{ .expr = "format('echo got={0}', steps.cmds.outputs.legacy)" };
    var first = testStep("x");
    first.context_name = "cmds";
    const steps = [_]job_mod.Step{ first, after };
    const out1 =
        "before s3cr3t-token\\n::add-mask::s3cr3t-token\\nafter s3cr3t-token\\n" ++
        "::group::Install%25\\ninside\\n::endgroup::\\n" ++
        "::error file=a.js,line=1::bad%0Asecond line\\n::warning::careful\\n::debug::hidden\\n" ++
        "::set-output name=legacy::42\\n" ++
        "::stop-commands::tok\\n::group::not a group\\n::add-mask::not-masked\\n::tok::\\n::notice::back\\n";
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, out1), try exec(arena, "C2", 0, "s3cr3t-token in step 2\\n") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const want =
        \\[job 0 step 1 stdout] before s3cr3t-token
        \\[job 0 step 1 stdout] after ***
        \\[job 0 step 1 stdout] ##[group]Install%
        \\[job 0 step 1 stdout] inside
        \\[job 0 step 1 stdout] ##[endgroup]
        \\[job 0 step 1 stdout] ##[error]bad
        \\[job 0 step 1 stdout] second line
        \\[job 0 step 1 stdout] ##[warning]careful
        \\[job 0 step 1 stdout] ::stop-commands::tok
        \\[job 0 step 1 stdout] ::group::not a group
        \\[job 0 step 1 stdout] ::tok::
        \\[job 0 step 1 stdout] ##[notice]back
    ;
    const got = w.buffered();
    var it = std.mem.splitScalar(u8, want, '\n');
    var pos: usize = 0;
    while (it.next()) |line| {
        const i = std.mem.indexOfPos(u8, got, pos, line) orelse {
            std.debug.print("missing, in order: {s}\n--- log:\n{s}\n", .{ line, got });
            return error.TestUnexpectedResult;
        };
        pos = i + line.len;
    }
    // Lines that must not be logged: the mask command, debug (ACTIONS_STEP_DEBUG is off). The
    // lines that stop and resume commands are, as GitHub logs them.
    for ([_][]const u8{ "add-mask::s3cr3t", "hidden", "::set-output" }) |no| try std.testing.expect(std.mem.indexOf(u8, got, no) == null);
    // While stopped, commands are plain text; afterwards they work again.
    try std.testing.expect(std.mem.indexOf(u8, got, "] ::group::not a group") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "] ::add-mask::not-masked") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "##[notice]back") != null);
    // The mask holds for later steps, and set-output reached steps.<id>.outputs.
    try std.testing.expect(std.mem.indexOf(u8, got, "[job 0 step 2 stdout] *** in step 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[2], "echo got=42") != null);
    // Annotations for completejob: the error points to its file; the others, to their line in the
    // step's log.
    try std.testing.expectEqual(@as(usize, 3), res.annotations.len);
    const err = res.annotations[0];
    try std.testing.expectEqual(@as(u32, 1), err.step);
    try std.testing.expectEqualStrings("a.js", err.an.file.?);
    try std.testing.expectEqualStrings("1", err.an.line.?);
    try std.testing.expectEqualStrings("bad\nsecond line", err.an.message);
    var n: u32 = 0;
    var lines = std.mem.splitScalar(u8, got, '\n');
    while (lines.next()) |l| {
        if (!std.mem.startsWith(u8, l, "[job 0 step 1 stdout] ")) continue;
        n += 1;
        if (std.mem.endsWith(u8, l, "##[warning]careful")) break;
    }
    try std.testing.expectEqualStrings("warning", res.annotations[1].an.level);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{d}", .{n}), res.annotations[1].an.line.?);
    try std.testing.expectEqualStrings("notice", res.annotations[2].an.level);
}

test "stop-commands: a long token is masked, a refused one fails the step and stops nothing" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("x")};
    const out1 = "::stop-commands::a1b2c3d4e5f6\\n::warning::stopped\\n::a1b2c3d4e5f6::\\n" ++
        "::stop-commands::pause-logging\\n::add-mask::hidden-after\\nsee hidden-after\\n";
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, out1) };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    const want =
        \\[job 0 step 1 stdout] ::stop-commands::***
        \\[job 0 step 1 stdout] ::warning::stopped
        \\[job 0 step 1 stdout] ::***::
        \\[job 0 step 1 stdout] ##[error]You cannot use a endToken that is an empty string, the string 'pause-logging', or another workflow command.
        \\[job 0 step 1 stdout] see ***
    ;
    const got = w.buffered();
    var it = std.mem.splitScalar(u8, want, '\n');
    var pos: usize = 0;
    while (it.next()) |line| {
        const i = std.mem.indexOfPos(u8, got, pos, line) orelse {
            std.debug.print("missing, in order: {s}\n--- log:\n{s}\n", .{ line, got });
            return error.TestUnexpectedResult;
        };
        pos = i + line.len;
    }
    try std.testing.expect(std.mem.indexOf(u8, got, "a1b2c3d4e5f6") == null);
    // The refused token failed the step, though its process succeeded.
    try std.testing.expect(!res.succeeded);
    try std.testing.expectEqual(Outcome.failure, res.steps[0].outcome);
}

test "set-env and add-path fail the step, unless ACTIONS_ALLOW_UNSECURE_COMMANDS is true" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var after = testStep("");
    after.action.script.script = .{ .expr = "format('echo x={0}', env.X)" };
    after.condition = "always()";
    const steps = [_]job_mod.Step{ testStep("x"), after };
    const out1 = "::set-env name=X::1\\n::add-path::/opt/x\\n" ++
        "::set-env name=NODE_OPTIONS::--require=/x.js\\n";
    for ([_]?[]const u8{ null, "false", "True" }) |allow| {
        var job = testJob(&steps);
        if (allow) |v| job.env = &.{.{ .name = "ACTIONS_ALLOW_UNSECURE_COMMANDS", .value = .{ .lit = v } }};
        const allowed = allow != null and std.mem.eql(u8, allow.?, "True");
        const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, out1), try exec(arena, "C2", 0, "") };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
        const got = w.buffered();
        const step2 = fake.seen.items[2];
        if (allowed) {
            // As GitHub: the variable and the directory reach the next step; NODE_OPTIONS is
            // refused with an error that does not fail the step.
            try std.testing.expect(res.succeeded);
            try std.testing.expectEqual(Outcome.success, res.steps[0].outcome);
            try std.testing.expect(std.mem.indexOf(u8, step2, "withEnvVariable(name:\"X\",value:\"1\")") != null);
            try std.testing.expect(std.mem.indexOf(u8, step2, "withEnvVariable(name:\"PATH\",value:\"/opt/x:$PATH\",expand:true)") != null);
            try std.testing.expect(std.mem.indexOf(u8, step2, "echo x=1") != null);
            try std.testing.expect(std.mem.indexOf(u8, step2, "NODE_OPTIONS") == null);
            try std.testing.expect(std.mem.indexOf(u8, got, "##[error]Can't update NODE_OPTIONS environment variable using ::set-env:: command.") != null);
            try std.testing.expect(std.mem.indexOf(u8, got, "is disabled") == null);
        } else {
            // Each command is an error that fails the step, though its process succeeded.
            try std.testing.expect(!res.succeeded);
            try std.testing.expectEqual(Outcome.failure, res.steps[0].outcome);
            try std.testing.expect(std.mem.indexOf(u8, got, "##[error]Unable to process command '::set-env name=X::1' successfully.") != null);
            try std.testing.expect(std.mem.indexOf(u8, got, "##[error]The `set-env` command is disabled.") != null);
            try std.testing.expect(std.mem.indexOf(u8, got, "##[error]Unable to process command '::add-path::/opt/x' successfully.") != null);
            try std.testing.expect(std.mem.indexOf(u8, got, "##[error]The `add-path` command is disabled.") != null);
            // No exit code is logged: GitHub logs only the process's own, and it exited 0
            // (#214).
            try std.testing.expect(std.mem.indexOf(u8, got, "Process completed with exit code") == null);
            try std.testing.expect(std.mem.indexOf(u8, step2, "name:\"X\"") == null);
            try std.testing.expect(std.mem.indexOf(u8, step2, "/opt/x") == null);
        }
    }
}

test "ACTIONS_STEP_DEBUG shows ::debug:: lines" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("x")};
    var job = testJob(&steps);
    job.secret_vars = &.{.{ .name = "ACTIONS_STEP_DEBUG", .value = "true" }};
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "::debug::shown%0Anow\\n") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    _ = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "##[debug]shown\nnow") != null);
}

test "what a step writes to GITHUB_STEP_SUMMARY is kept for upload" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("x"), testStep("y") };
    const with_summary = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"fc_step_summary\":{\"contents\":\"# Results\\n| a | b |\\n\"}}}}}";
    const answers = [_][]const u8{ base_answer, with_summary, try exec(arena, "C2", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expectEqualStrings("# Results\n| a | b |\n", res.summaries[0]);
    try std.testing.expectEqualStrings("", res.summaries[1]);
    // The query reads the file back.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "fc_all: file(path:") != null);
}

test "a malformed GITHUB_STATE fails the step that wrote it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("x")};
    const bad_state = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"fc_state\":{\"contents\":\"pid=7\\nnot state\\n\"}}}}}";
    const answers = [_][]const u8{ base_answer, bad_state };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(!res.succeeded);
    try std.testing.expectEqual(Outcome.failure, res.steps[0].outcome);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "##[error]Unable to process file command 'state' successfully.") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "##[error]invalid format 'not state' on line 2") != null);
}

test "the 1 MiB summary limit is per file: a composite's steps add up past it, one file over is dropped" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const composite =
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - shell: bash
        \\      run: one
        \\    - shell: bash
        \\      run: two
    ;
    const steps = [_]job_mod.Step{ usesStep("sum", "o", "sum", "v1", &.{}), testStep("big") };
    const summary = struct {
        fn answer(ar: Allocator, id: []const u8, size: usize) ![]const u8 {
            const text = try ar.alloc(u8, size);
            @memset(text, 'a');
            return std.fmt.allocPrint(ar, "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":" ++
                "{{\"id\":\"{s}\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\"," ++
                "\"fc_step_summary\":{{\"contents\":\"{s}\"}}}}}}}}}}", .{ id, text });
        }
    }.answer;
    const answers = [_][]const u8{
        base_answer,
        try treeAnswer(arena, "D1", &.{"action.yml"}),
        try fileAnswer(arena, composite),
        try summary(arena, "C1", 700 * 1024),
        try summary(arena, "C2", 700 * 1024),
        try summary(arena, "C3", 1024 * 1024 + 1),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expectEqual(@as(usize, 1400 * 1024), res.summaries[0].len);
    try std.testing.expectEqual(@as(usize, 0), res.summaries[1].len);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "[job 0 step 2 stdout] ##[error]$GITHUB_STEP_SUMMARY upload aborted, supports content up to a size of 1024k, got 1024k.") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "step 1 stdout] ##[error]$GITHUB_STEP_SUMMARY") == null);
}

test "step caching: run-specific values are volatile, steps with secrets always run, workflows can opt out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const ctx_json =
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"sha","v":"abc"},{"k":"run_id","v":"123"},{"k":"run_attempt","v":"2"},
        \\  {"k":"event","v":{"t":2,"d":[{"k":"ref","v":"refs/heads/x"}]}}]}}
    ;
    var with_secret = testStep("deploy");
    with_secret.env = &.{.{ .name = "TOKEN", .value = .{ .lit = "s3cr3t-value" } }};
    const steps = [_]job_mod.Step{ testStep("build"), with_secret };
    for ([_]bool{ false, true }) |opt_out| {
        var job = testJob(&steps);
        job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena, ctx_json, .{});
        job.secrets = &.{"s3cr3t-value"};
        if (opt_out) job.env = &.{.{ .name = "ZIG_RUNNER_STEP_CACHE", .value = .{ .lit = "false" } }};
        const answers = [_][]const u8{
            base_answer,
            try exec(arena, "C1", 0, "built\\n"), // no live lines in this fake session: replayed, so "reused"
            "{\"data\":{\"zsec0\":{\"id\":\"SEC\"}}}",
            try exec(arena, "C2", 0, ""),
        };
        var fake: FakeSession = .{ .answers = &answers, .arena = arena };
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .runner_name = "zig-pi-1a2b3c4d", .test_ran_marker = "j1", .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
        try std.testing.expect(res.succeeded);
        const base = fake.seen.items[0];
        const build = fake.seen.items[1];
        const deploy = fake.seen.items[3];
        for (fake.seen.items) |d| try std.testing.expect(braceBalanced(d));
        // The commit is volatile with step caching (a new commit is not by itself a new key); without
        // it, it is an ordinary variable.
        try std.testing.expect(std.mem.indexOf(u8, base, if (opt_out) "withEnvVariable(name:\"GITHUB_SHA\",value:\"abc\")" else "withVolatileVariable(name:\"GITHUB_SHA\",value:\"abc\")") != null);
        if (!opt_out) {
            try std.testing.expect(std.mem.indexOf(u8, base, "withVolatileVariable(name:\"GITHUB_RUN_ID\",value:\"123\")") != null);
            // A pool names every job's runner anew: as an input it would make every key new.
            try std.testing.expect(std.mem.indexOf(u8, base, "withVolatileVariable(name:\"RUNNER_NAME\",value:\"zig-pi-1a2b3c4d\")") != null);
            try std.testing.expect(std.mem.indexOf(u8, base, "withVolatileVariable(name:\"ZIG_RUNNER_EVENT\",value:") != null);
            try std.testing.expect(std.mem.indexOf(u8, base, "withNewFile") == null);
            // A step that always runs writes the event file from the volatile variable; a replayable
            // one writes the withheld payload (#68). Both hide the variable.
            try std.testing.expect(std.mem.indexOf(u8, deploy, "printf '%s' \\\"$ZIG_RUNNER_EVENT\\\" > /github/workflow/event.json") != null);
            try std.testing.expect(std.mem.indexOf(u8, build, "printf '%s' '\\\"zig-runner-withheld\\\"' > /github/workflow/event.json") != null);
            try std.testing.expect(std.mem.indexOf(u8, build, "$ZIG_RUNNER_EVENT") == null);
            try std.testing.expect(std.mem.indexOf(u8, build, "-u ZIG_RUNNER_EVENT ") != null);
            // Only the step with a secret is forced to run, with a value new for every job (a run's
            // matrix jobs share its id).
            try std.testing.expect(std.mem.indexOf(u8, build, "runs this step every time") == null);
            try std.testing.expect(std.mem.indexOf(u8, deploy, ": 'zig-runner runs this step every time: it uses secrets (run 123.2, job j1)'") != null);
        } else {
            try std.testing.expect(std.mem.indexOf(u8, base, "withEnvVariable(name:\"GITHUB_RUN_ID\",value:\"123\")") != null);
            try std.testing.expect(std.mem.indexOf(u8, base, "withNewFile(path:\"/github/workflow/event.json\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, base, "withVolatileVariable") == null);
            try std.testing.expect(std.mem.indexOf(u8, deploy, "runs this step every time") == null);
        }
        const got = w.buffered();
        try std.testing.expect(std.mem.indexOf(u8, got, "[job 0 step 1 stdout] built") != null);
        if (opt_out) {
            // Without step caching nothing is replayed from an earlier job: the output is the step's
            // own, though no line of it streamed.
            try std.testing.expect(std.mem.indexOf(u8, got, "Reused from Dagger's cache") == null);
        } else {
            // The note follows the replayed output, at the end of the job.
            const note = std.mem.indexOf(u8, got, "[job 0 step 1 stdout] Reused from Dagger's cache") orelse return error.TestUnexpectedResult;
            try std.testing.expect(std.mem.indexOf(u8, got, "[job 0 step 1 stdout] built").? < note);
        }
    }
}

test "with id-token: write, every step can request OIDC tokens, and so always runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("one"), testStep("two") };
    for ([_]bool{ true, false }) |granted| {
        var job = testJob(&steps);
        job.secrets = &.{"ghs_jobtoken"};
        job.job_token = "ghs_jobtoken";
        if (granted) job.runtime.id_token_url = "https://token.test/idtoken?api-version=2.0";
        const answers = [_][]const u8{
            base_answer,
            "{\"data\":{\"zsec0\":{\"id\":\"SEC_ID\"}}}", // registered once for the job
            try exec(arena, "C1", 0, ""),
            try exec(arena, "C2", 0, ""),
        };
        var fake: FakeSession = .{ .answers = if (granted) &answers else &.{ answers[0], answers[2], answers[3] }, .arena = arena };
        var buf: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
        const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
        try std.testing.expect(res.succeeded);
        const seen = fake.seen.items;
        for (seen) |d| try std.testing.expect(braceBalanced(d));
        if (!granted) {
            try std.testing.expectEqual(@as(usize, 3), seen.len);
            for (seen) |d| try std.testing.expect(std.mem.indexOf(u8, d, "ACTIONS_ID_TOKEN") == null);
            continue;
        }
        try std.testing.expectEqual(@as(usize, 4), seen.len);
        try std.testing.expect(std.mem.indexOf(u8, seen[1], "setSecret") != null);
        for ([_][]const u8{ seen[2], seen[3] }) |d| {
            try std.testing.expect(std.mem.indexOf(u8, d, "'ACTIONS_ID_TOKEN_REQUEST_URL=https://token.test/idtoken?api-version=2.0'") != null);
            try std.testing.expect(std.mem.indexOf(u8, d, "withSecretVariable(name:\"ZIG_SECRET_0\",secret:\"SEC_ID\")") != null);
            try std.testing.expect(std.mem.indexOf(u8, d, "'ACTIONS_ID_TOKEN_REQUEST_TOKEN='\\\"$ZIG_SECRET_0\\\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, d, "runs this step every time: it can request OIDC tokens (id-token: write)") != null);
            try std.testing.expect(std.mem.indexOf(u8, d, "ghs_") == null);
        }
    }
}

test "with step caching, each step's marker says whether it ran in this job or was replayed" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("fast"), testStep("cached") };
    const job = testJob(&steps);
    const answer = struct {
        fn f(ar: Allocator, id: []const u8, out: []const u8, ran_value: []const u8) ![]const u8 {
            return std.fmt.allocPrint(ar, "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":{{\"id\":\"{s}\",\"exitCode\":0,\"stdout\":\"{s}\",\"stderr\":\"\",\"fc_all\":{{\"contents\":\"::zig-file-command::ran\\n{s}\\n\"}}}}}}}}}}", .{ id, out, ran_value });
        }
    }.f;
    const answers = [_][]const u8{
        base_answer,
        // Ran in this job, though none of its lines streamed (they came late).
        try answer(arena, "C1", "fast\\n", "m-this-job"),
        // Replayed: an earlier job's marker.
        try answer(arena, "C2", "cached\\n", "m-earlier-job"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .step_cache = true, .test_ran_marker = "m-this-job", .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    // The marker is volatile: not part of any step's cache key.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "withVolatileVariable(name:\"ZIG_RUNNER_RAN\",value:\"m-this-job\")") != null);
    // Each step writes it with its file commands, and its own program does not see it.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "::zig-file-command::ran' \\\"${ZIG_RUNNER_RAN-}\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "-u ZIG_RUNNER_RAN ") != null);
    // The markers' secret is volatile too, and hidden from the step's program.
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[0], "withVolatileVariable(name:\"ZIG_RUNNER_MARK\",value:\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, fake.seen.items[1], "-u ZIG_RUNNER_MARK ") != null);
    const got = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, got, "[job 0 step 1 stdout] fast") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "[job 0 step 1 stdout] Reused") == null);
    try std.testing.expect(std.mem.indexOf(u8, got, "[job 0 step 2 stdout] cached") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "[job 0 step 2 stdout] Reused from Dagger's cache") != null);
}

test "a script that names the commit or a ref runs every time; one that does not can be replayed" {
    try std.testing.expect(readsRunSpecific("go build -ldflags \"-X main.commit=$GITHUB_SHA\" ./..."));
    try std.testing.expect(readsRunSpecific("if [ \"$GITHUB_REF\" = refs/heads/main ]; then ./deploy.sh; fi"));
    try std.testing.expect(readsRunSpecific("echo ${GITHUB_HEAD_REF}"));
    try std.testing.expect(!readsRunSpecific("go test ./..."));
    try std.testing.expect(isVolatile("GITHUB_SHA") and isVolatile("GITHUB_REF_NAME") and !isVolatile("GITHUB_REPOSITORY"));
}

// --- round trips per step ---

/// A stand-in for the Dagger session that answers any document with data of the shape it selects
/// (ids unique, exit codes 0, outputs empty, files from `files`), and records every document. The
/// request counts below do not depend on the order queries are sent in, only on how many there are.
const AutoSession = struct {
    arena: Allocator,
    seen: std.ArrayList([]const u8) = .empty,
    /// `file(path:)` contents by path; others are "".
    files: []const [2][]const u8 = &.{},
    /// An exec whose document contains [0] prints [1].
    stdout: []const [2][]const u8 = &.{},
    ids: u32 = 0,

    fn send(ptr: *anyopaque, arena: Allocator, doc: []const u8, _: usize) anyerror![]const u8 {
        const self: *AutoSession = @ptrCast(@alignCast(ptr));
        try self.seen.append(self.arena, try self.arena.dupe(u8, doc));
        var p: Answer = .{ .s = doc, .self = self, .arena = arena };
        try p.out.appendSlice(arena, "{\"data\":");
        p.ws();
        try p.selection(null);
        try p.out.append(arena, '}');
        return p.out.items;
    }

    fn transport(self: *AutoSession) Transport {
        return .{ .ptr = self, .sendFn = send };
    }

    /// Documents that contain `needle`.
    fn count(self: *AutoSession, needle: []const u8) usize {
        var n: usize = 0;
        for (self.seen.items) |d| {
            if (std.mem.indexOf(u8, d, needle) != null) n += 1;
        }
        return n;
    }

    const Answer = struct {
        s: []const u8,
        i: usize = 0,
        self: *AutoSession,
        arena: Allocator,
        out: std.ArrayList(u8) = .empty,

        fn ws(p: *Answer) void {
            while (p.i < p.s.len and p.s[p.i] == ' ') p.i += 1;
        }

        fn name(p: *Answer) []const u8 {
            const start = p.i;
            while (p.i < p.s.len and (std.ascii.isAlphanumeric(p.s[p.i]) or p.s[p.i] == '_'))
                p.i += 1;
            return p.s[start..p.i];
        }

        /// Skips `(...)`, strings and lists included; returns what was inside.
        fn args(p: *Answer) []const u8 {
            const start = p.i + 1;
            var depth: usize = 0;
            var in_str = false;
            while (p.i < p.s.len) : (p.i += 1) {
                const c = p.s[p.i];
                if (in_str) {
                    if (c == '\\') p.i += 1 else if (c == '"') in_str = false;
                    continue;
                }
                switch (c) {
                    '"' => in_str = true,
                    '(', '[' => depth += 1,
                    ')', ']' => {
                        depth -= 1;
                        if (depth == 0) {
                            p.i += 1;
                            return p.s[start .. p.i - 1];
                        }
                    },
                    else => {},
                }
            }
            return p.s[start..];
        }

        fn pathArg(a: []const u8) ?[]const u8 {
            const k = std.mem.indexOf(u8, a, "path:\"") orelse return null;
            const rest = a[k + 6 ..];
            const end = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
            return rest[0..end];
        }

        fn selection(p: *Answer, file: ?[]const u8) anyerror!void {
            p.i += 1; // {
            try p.out.append(p.arena, '{');
            var first = true;
            while (true) {
                p.ws();
                if (p.s[p.i] == '}') {
                    p.i += 1;
                    break;
                }
                const key = p.name();
                var field = key;
                p.ws();
                if (p.s[p.i] == ':') {
                    p.i += 1;
                    p.ws();
                    field = p.name();
                    p.ws();
                }
                var a: []const u8 = "";
                if (p.s[p.i] == '(') {
                    a = p.args();
                    p.ws();
                }
                if (!first) try p.out.append(p.arena, ',');
                first = false;
                try p.out.print(p.arena, "\"{s}\":", .{key});
                if (p.s[p.i] == '{') {
                    try p.selection(if (std.mem.eql(u8, field, "file")) pathArg(a) else file);
                } else try p.leaf(field, file);
            }
            try p.out.append(p.arena, '}');
        }

        fn leaf(p: *Answer, field: []const u8, file: ?[]const u8) !void {
            const w = p.arena;
            const eql = std.mem.eql;
            if (eql(u8, field, "id")) {
                p.self.ids += 1;
                return p.out.print(w, "\"ID{d}\"", .{p.self.ids});
            }
            if (eql(u8, field, "exitCode")) {
                try p.out.appendSlice(w, "0");
                // An exec's output comes with it, asked for or not, as in the scripted answers:
                // it stands in for the live stream these tests have none of, which would
                // otherwise send every step's document again for its output (`Exec.Recorded`).
                const rest = p.s[p.i..];
                const selected = rest[0 .. std.mem.indexOfScalar(u8, rest, '}') orelse rest.len];
                if (std.mem.indexOf(u8, selected, "stdout") != null) return;
                try p.out.appendSlice(w, ",\"stdout\":");
                try p.leaf("stdout", file);
                return p.out.appendSlice(w, ",\"stderr\":\"\"");
            }
            if (eql(u8, field, "entries")) return p.out.appendSlice(w, "[\"action.yml\"]");
            if (eql(u8, field, "digest")) return p.out.appendSlice(w, "\"sha256:0123abcd\"");
            if (eql(u8, field, "removedPaths") or eql(u8, field, "entrypoint"))
                return p.out.appendSlice(w, "[]");
            if (eql(u8, field, "defaultArgs")) return p.out.appendSlice(w, "[\"/bin/sh\"]");
            var text: []const u8 = "";
            if (eql(u8, field, "contents")) {
                if (file) |f| for (p.self.files) |kv| {
                    if (eql(u8, kv[0], f)) text = kv[1];
                };
            } else if (eql(u8, field, "stdout")) {
                for (p.self.stdout) |r| if (std.mem.indexOf(u8, p.s, r[0]) != null) {
                    text = r[1];
                };
            }
            var aw: std.Io.Writer.Allocating = .init(w);
            try std.json.Stringify.value(text, .{}, &aw.writer);
            try p.out.appendSlice(w, aw.written());
        }
    };
};

/// Runs `job` against `auto` and returns how many documents it sent.
fn roundTrips(arena: Allocator, auto: *AutoSession, opts_in: Options, job: job_mod.Job) !usize {
    var env: std.process.Environ.Map = .init(arena);
    const buf = try arena.alloc(u8, 1 << 16);
    var w: std.Io.Writer = .fixed(buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var opts = opts_in;
    opts.test_session_argv = &.{ "sh", "-c", fake_child };
    opts.test_transport = auto.transport();
    const res = try run(arena, std.testing.io, &env, opts, job, &log);
    if (!res.succeeded) {
        std.debug.print("job failed: {s}\n", .{w.buffered()});
        return error.JobFailed;
    }
    for (auto.seen.items) |d| try std.testing.expect(braceBalanced(d));
    return auto.seen.items.len;
}

test "round trips: documents sent per step kind, before and after" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const ctx = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"run_id","v":"9"},{"k":"run_attempt","v":"1"}]}}
    , .{});
    const js_yml =
        \\inputs:
        \\  github-token:
        \\    default: ${{ github.token }}
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\  post: dist/post.js
    ;
    const composite_yml =
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - shell: bash
        \\      run: echo one
        \\    - shell: bash
        \\      run: echo two
    ;
    const secret = "s3cr3t-value";
    var with_secret = testStep("deploy");
    with_secret.env = &.{.{ .name = "TOKEN", .value = .{ .lit = secret } }};
    const checkout_step: job_mod.Step = .{ .id = "co", .name = "co", .condition = "success()", .action = .{ .checkout = &.{} } };
    const matcher_json = "{\"problemMatcher\":[]}";
    var docker = testStep("");
    docker.action = .{ .docker = .{ .image = "alpine:3.22", .inputs = &.{} } };
    // Every job here has the job token and GITHUB_TOKEN among its secrets, as on GitHub. `was` is
    // what the runner sent before secrets were registered once per job and in batches, actions
    // loaded once per job, the job setup's queries merged, matcher files read together, and output
    // keys' reads folded into the step's own query; `docs` is what it sends now, `secret_docs` how
    // many of those register secrets.
    const Case = struct {
        name: []const u8,
        steps: []const job_mod.Step,
        opts: Options = .{},
        job_env_secret: bool = false,
        files: []const [2][]const u8 = &.{},
        stdout: []const [2][]const u8 = &.{},
        was: usize,
        docs: usize,
        secret_docs: usize,
    };
    const runs3 = [_]job_mod.Step{ testStep("a"), testStep("b"), testStep("c") };
    const js2 = [_]job_mod.Step{ usesStep("j1", "o", "js", "v1", &.{}), usesStep("j2", "o", "js", "v1", &.{}) };
    const js_files = [_][2][]const u8{.{ "action.yml", js_yml }};
    const keyed = Options{ .step_cache = true, .output_keys = true };
    const cases = [_]Case{
        // Set up job (the base container), then one query per step: nothing to save.
        .{ .name = "3 run steps", .steps = &runs3, .was = 4, .docs = 4, .secret_docs = 0 },
        .{ .name = "3 run steps, step cache", .steps = &runs3, .opts = .{ .step_cache = true }, .was = 4, .docs = 4, .secret_docs = 0 },
        .{ .name = "3 run steps, package caches", .steps = &runs3, .opts = .{ .package_caches = true }, .was = 5, .docs = 5, .secret_docs = 0 },
        // The step's secret is registered once, not once per step.
        .{ .name = "3 run steps with the same secret env", .steps = &.{ with_secret, with_secret, with_secret }, .was = 7, .docs = 5, .secret_docs = 1 },
        // The job env's secret is registered in the cache volumes' query.
        .{ .name = "run step, job env secret, package caches", .steps = &.{testStep("a")}, .opts = .{ .package_caches = true }, .job_env_secret = true, .was = 4, .docs = 3, .secret_docs = 1 },
        .{ .name = "checkout + run step", .steps = &.{ checkout_step, testStep("a") }, .was = 5, .docs = 5, .secret_docs = 1 },
        .{ .name = "checkout + run step, package caches", .steps = &.{ checkout_step, testStep("a") }, .opts = .{ .package_caches = true }, .was = 6, .docs = 5, .secret_docs = 1 },
        // The action fetched once; its two tokens registered once, together.
        .{ .name = "JS action in 2 steps, main + post each", .steps = &js2, .files = &js_files, .was = 18, .docs = 9, .secret_docs = 1 },
        .{ .name = "JS action in 2 steps, package caches", .steps = &js2, .files = &js_files, .opts = .{ .package_caches = true }, .was = 19, .docs = 9, .secret_docs = 1 },
        .{ .name = "composite action with 2 run steps", .steps = &.{usesStep("c1", "o", "comp", "v1", &.{})}, .files = &.{.{ "action.yml", composite_yml }}, .was = 5, .docs = 5, .secret_docs = 0 },
        .{ .name = "docker:// step twice", .steps = &.{ docker, docker }, .was = 11, .docs = 10, .secret_docs = 1 },
        // Both matcher files in one query.
        .{ .name = "run step adding 2 matchers + run step", .steps = &.{ testStep("matchers"), testStep("b") }, .stdout = &.{.{ "matchers", "::add-matcher::/m1.json\n::add-matcher::/m2.json\n" }}, .files = &.{ .{ "/m1.json", matcher_json }, .{ "/m2.json", matcher_json } }, .was = 5, .docs = 4, .secret_docs = 0 },
        // The container before the step read with its exec; the store asked for with busybox, or
        // in the cache volumes' query.
        .{ .name = "output keys: always-run step + run step", .steps = &.{ with_secret, testStep("b") }, .opts = keyed, .was = 10, .docs = 8, .secret_docs = 1 },
        .{ .name = "output keys: 2 always-run steps + run step", .steps = &.{ with_secret, with_secret, testStep("b") }, .opts = keyed, .was = 16, .docs = 12, .secret_docs = 1 },
        .{ .name = "output keys: always-run + run step, package caches", .steps = &.{ with_secret, testStep("b") }, .opts = .{ .step_cache = true, .output_keys = true, .package_caches = true }, .was = 11, .docs = 9, .secret_docs = 1 },
    };
    for (cases) |c| {
        var job = testJob(c.steps);
        job.context_data = ctx;
        job.secrets = &.{ secret, "ghs_jobtoken", "ghs_token" };
        job.job_token = "ghs_jobtoken";
        job.secret_vars = &.{.{ .name = "GITHUB_TOKEN", .value = "ghs_token" }};
        if (c.job_env_secret) job.env = &.{.{ .name = "JOB_SECRET", .value = .{ .lit = secret } }};
        var auto: AutoSession = .{ .arena = arena, .files = c.files, .stdout = c.stdout };
        const n = try roundTrips(arena, &auto, c.opts, job);
        if (n != c.docs or auto.count("setSecret") != c.secret_docs) {
            std.debug.print("{s}: {d} documents ({d} with setSecret), want {d} ({d}); was {d}\n", .{
                c.name, n, auto.count("setSecret"), c.docs, c.secret_docs, c.was,
            });
            return error.TestUnexpectedResult;
        }
        try std.testing.expect(c.docs <= c.was);
    }
}

test "round trips: a matcher file that cannot be read is read alone, and the others still load" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("matchers"), testStep("b") };
    const answers = [_][]const u8{
        base_answer,
        try exec(arena, "C1", 0, "::add-matcher::/m1.json\\n::add-matcher::/missing.json\\n"),
        "{\"errors\":[{\"message\":\"/missing.json: no such file or directory\"}]}",
        "{\"data\":{\"loadContainerFromID\":{\"file\":{\"contents\":\"{\\\"problemMatcher\\\":[]}\"}}}}",
        "{\"errors\":[{\"message\":\"/missing.json: no such file or directory\"}]}",
        try exec(arena, "C2", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 6), seen.len);
    try std.testing.expect(std.mem.indexOf(u8, seen[2], "loadContainerFromID(id:\"C1\") { m0: file(path:\"/m1.json\") { contents } m1: file(path:\"/missing.json\") { contents } }") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "file(path:\"/m1.json\") { contents }") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "file(path:\"/missing.json\") { contents }") != null);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "Could not read the problem matcher '/missing.json'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Could not read the problem matcher '/m1.json'") == null);
}

test "an exec's recorded output is asked for only to replay it, and never past max_recorded_bytes" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("biglog"), testStep("biglog"), testStep("b") };
    // Answers without the output, which the exec's document no longer asks for.
    const lean = "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":" ++
        "{{\"id\":\"C{d}\",\"exitCode\":0}}}}}}}}";
    // Steps 1 and 2 printed more than is read back: the transport stops at the limit.
    const big = try arena.alloc(u8, max_recorded_bytes);
    @memset(big, 'x');
    const answers = [_][]const u8{
        base_answer,
        try std.fmt.allocPrint(arena, lean, .{1}),
        try exec(arena, "C1", 0, big),
        try exec(arena, "C2", 0, big),
        try std.fmt.allocPrint(arena, lean, .{2}),
        try exec(arena, "C2", 0, big),
        try exec(arena, "C3", 0, "replayed line"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
        .step_cache = true,
    }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 7), seen.len);
    // The exec asks for no output: asking made the engine log all of it again (verbose).
    try std.testing.expect(std.mem.indexOf(u8, seen[1], "stdout") == null);
    // None of its lines arrived live (there is no stream here) and nothing says it ran, so it was
    // served from the cache and its output is asked for: the same document, which the engine
    // answers from its cache, with the fields put in.
    const fields = "stdout stderr ";
    try std.testing.expectEqual(seen[1].len + fields.len, seen[2].len);
    const at = std.mem.indexOf(u8, seen[2], "exitCode " ++ fields).? + "exitCode ".len;
    try std.testing.expectEqualStrings(seen[1][0..at], seen[2][0..at]);
    try std.testing.expectEqualStrings(seen[1][at..], seen[2][at + fields.len ..]);
    // Past the limit it is not read on, and the log says why the step shows nothing.
    const note = "could not be read back (it is over the 4 MiB that is replayed)";
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, w.buffered(), note));
    // After a replay the next exec asks for its output in its own query. Past the limit it goes
    // again without, and the output is asked for on its own as before, and not read either.
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "loadContainerFromID(id:\"C1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "exitCode " ++ fields) != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "stdout") == null);
    try std.testing.expectEqualStrings(seen[3], seen[5]);
    // The next step's replay is one query: its small output comes with its result.
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "loadContainerFromID(id:\"C2\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "exitCode " ++ fields) != null);
    const replayed = "step 3 stdout] replayed line";
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), replayed) != null);
}

test "after a replay, each replayed step is one query, its output shown once" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("a"), testStep("b"), testStep("c"), testStep("d") };
    const lean = "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":" ++
        "{{\"id\":\"C{d}\",\"exitCode\":0}}}}}}}}";
    const answers = [_][]const u8{
        base_answer,
        try std.fmt.allocPrint(arena, lean, .{1}),
        try exec(arena, "C1", 0, "line 1"),
        try exec(arena, "C2", 0, "line 2"),
        try exec(arena, "C3", 0, "line 3"),
        try exec(arena, "C4", 0, "line 4"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
        .step_cache = true,
    }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    // The first replay asks twice; every one after it once.
    try std.testing.expectEqual(@as(usize, 6), fake.seen.items.len);
    for (fake.seen.items[3..]) |d| try std.testing.expect(std.mem.indexOf(u8, d, "stdout") != null);
    for (1..5) |i| {
        const line = try std.fmt.allocPrint(arena, "step {d} stdout] line {d}", .{ i, i });
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, w.buffered(), line));
    }
}

test "a step that ran and printed nothing does not ask for its output" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{ testStep("true"), testStep("true") };
    // Without step caching every step runs in this job: one with no line live printed none.
    const answers = [_][]const u8{
        base_answer,
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0}}}}",
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C2\",\"exitCode\":0}}}}",
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 3), fake.seen.items.len);
    for (fake.seen.items) |d| try std.testing.expect(std.mem.indexOf(u8, d, "stdout") == null);
}

test "a step whose env fails to evaluate fails the job, continue-on-error or not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    // 20 characters, 8^5 times: past GitHub's 1 MiB expression memory.
    const f8 = "format('{0}{0}{0}{0}{0}{0}{0}{0}', ";
    var huge = testStep("huge");
    huge.env = &.{.{
        .name = "HUGE",
        .value = .{ .expr = f8 ++ f8 ++ f8 ++ f8 ++ f8 ++ "'xxxxxxxxxxxxxxxxxxxx')))))" },
    }};
    huge.continue_on_error = .{ .lit = "true" };
    const steps = [_]job_mod.Step{ huge, testStep("b") };
    const answers = [_][]const u8{ base_answer, try exec(arena, "C2", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, testJob(&steps), &log);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "could not evaluate env: the " ++
        "expression needs more than the 1048576 bytes") != null);
    // As on GitHub, continue-on-error is not applied to a step that never ran: it failed, the
    // job failed, and the next step (success()) was skipped.
    try std.testing.expect(!res.succeeded);
    try std.testing.expectEqual(@as(usize, 1), fake.seen.items.len);
    try std.testing.expectEqual(Outcome.failure, res.steps[0].outcome);
    try std.testing.expect(!res.steps[0].continued);
    try std.testing.expectEqual(Outcome.skipped, res.steps[1].outcome);
}

test "a step's if: and name see its own env, and an env error fails it whatever its if: says" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var gated = testStep("gated");
    gated.env = &.{.{ .name = "GO", .value = .{ .lit = "yes" } }};
    gated.condition = "env.GO == 'yes'";
    gated.name_expr = "format('go {0}', env.GO)";
    var bad = testStep("bad");
    bad.env = &.{.{ .name = "BAD", .value = .{ .expr = "fromJSON('{')" } }};
    bad.condition = "false";
    const steps = [_]job_mod.Step{ gated, bad };
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, testJob(&steps), &log);
    try std.testing.expectEqual(Outcome.success, res.steps[0].outcome);
    try std.testing.expectEqualStrings("go yes", res.steps[0].name);
    try std.testing.expectEqual(@as(usize, 2), fake.seen.items.len);
    // GitHub evaluates the env first and fails the step on an error, before its `if:`.
    try std.testing.expectEqual(Outcome.failure, res.steps[1].outcome);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "could not evaluate env: ") != null);
    try std.testing.expect(!res.succeeded);
}

test "a step's env cannot change the variables GitHub sets again, though its env context has them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    var step = testStep("");
    step.action.script.script = .{ .expr = "format('echo ctx={0}', env.RUNNER_TEMP)" };
    step.env = &.{
        .{ .name = "RUNNER_TEMP", .value = .{ .lit = "/elsewhere" } },
        .{ .name = "GITHUB_ACTIONS", .value = .{ .lit = "false" } },
        .{ .name = "CI", .value = .{ .lit = "false" } },
        .{ .name = "OWN", .value = .{ .lit = "kept" } },
    };
    const steps = [_]job_mod.Step{step};
    const answers = [_][]const u8{ base_answer, try exec(arena, "C1", 0, "") };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{
        .test_session_argv = &.{ "sh", "-c", fake_child },
        .test_transport = fake.transport(),
    }, testJob(&steps), &log);
    try std.testing.expect(res.succeeded);
    const s1 = fake.seen.items[1];
    // GitHub's handlers set the github and runner contexts' variables (and GITHUB_ACTIONS) over
    // the step's env (ScriptHandler.cs), so the process keeps the runner's values; CI, which
    // GitHub sets only when nothing else has, and any other name are the step's.
    try std.testing.expect(std.mem.indexOf(u8, s1, "'RUNNER_TEMP=/elsewhere'") == null);
    try std.testing.expect(std.mem.indexOf(u8, s1, "'GITHUB_ACTIONS=false'") == null);
    try std.testing.expect(std.mem.indexOf(u8, s1, "'CI=false'") != null);
    try std.testing.expect(std.mem.indexOf(u8, s1, "'OWN=kept'") != null);
    // The env context, and the log header, have what the step wrote.
    try std.testing.expect(std.mem.indexOf(u8, s1, "echo ctx=/elsewhere") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "  RUNNER_TEMP: /elsewhere") != null);
}

test "round trips: the job setup's query is sent again without the secrets when it fails with them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const steps = [_]job_mod.Step{testStep("npm ci")};
    var job = testJob(&steps);
    job.secrets = &.{"s3cr3t-value"};
    job.env = &.{.{ .name = "JOB_SECRET", .value = .{ .lit = "s3cr3t-value" } }};
    var volumes: std.Io.Writer.Allocating = .init(arena);
    try volumes.writer.writeAll("{\"data\":{");
    for (package_cache_dirs, 0..) |_, i| try volumes.writer.print("{s}\"c{d}\":{{\"id\":\"V{d}\"}}", .{ if (i > 0) "," else "", i, i });
    try volumes.writer.writeAll("}}");
    const answers = [_][]const u8{
        "{\"errors\":[{\"message\":\"secret store unavailable\"}]}",
        volumes.written(),
        "{\"data\":{\"zsec0\":{\"id\":\"SEC_JOB\"}}}",
        base_answer,
        try exec(arena, "C1", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .package_caches = true, .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    const seen = fake.seen.items;
    try std.testing.expectEqual(@as(usize, 5), seen.len);
    try std.testing.expect(std.mem.indexOf(u8, seen[0], "zsec0: setSecret(") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[0], "c0: cacheVolume(") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[1], "setSecret") == null);
    try std.testing.expect(std.mem.indexOf(u8, seen[1], "c0: cacheVolume(") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[2], "zsec0: setSecret(") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "withSecretVariable(name:\"JOB_SECRET\",secret:\"SEC_JOB\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "withMountedCache(path:") != null);
}

/// The document that runs the step whose script is `script`.
fn execOf(auto: *const AutoSession, script: []const u8) ![]const u8 {
    for (auto.seen.items) |d| {
        if (std.mem.indexOf(u8, d, "withExec") != null and std.mem.indexOf(u8, d, script) != null)
            return d;
    }
    return error.TestUnexpectedResult;
}

test "a secret in a container job's env reaches steps as a Dagger secret, and they always run" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "npm_s3cr3t-value";
    const steps = [_]job_mod.Step{testStep("npm publish")};
    var job = testJob(&steps);
    job.secrets = &.{secret};
    job.container = .{ .name = "", .image = .{ .lit = "node:20" }, .env = &.{
        .{ .name = "NPM_TOKEN", .value = .{ .lit = secret } },
        .{ .name = "NODE_ENV", .value = .{ .lit = "production" } },
    } };
    var auto: AutoSession = .{ .arena = arena };
    _ = try roundTrips(arena, &auto, .{ .step_cache = true, .test_ran_marker = "j1" }, job);
    try expectSecretOnlyInSetSecret(auto.seen.items, secret);
    try std.testing.expectEqual(@as(usize, 1), auto.count("withSecretVariable(name:\"NPM_TOKEN\""));
    try std.testing.expectEqual(@as(usize, 1), auto.count("withEnvVariable(name:\"NODE_ENV\""));
    // The step names no secret, but its environment has one: it runs in every job.
    const publish = try execOf(&auto, "npm publish");
    try std.testing.expect(std.mem.indexOf(u8, publish, "runs this step every time: it uses " ++
        "secrets (run ") != null);
}

test "a container job's env gives way to the job's env of the same name" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "npm_s3cr3t-value";
    const steps = [_]job_mod.Step{testStep("npm publish")};
    var job = testJob(&steps);
    job.secrets = &.{secret};
    job.env = &.{.{ .name = "NPM_TOKEN", .value = .{ .lit = "from-the-job" } }};
    job.container = .{ .name = "", .image = .{ .lit = "node:20" }, .env = &.{
        .{ .name = "NPM_TOKEN", .value = .{ .lit = secret } },
    } };
    var auto: AutoSession = .{ .arena = arena };
    _ = try roundTrips(arena, &auto, .{}, job);
    // Only the job's value is set: a secret variable beside it would leave the winner to the
    // engine.
    try std.testing.expectEqual(@as(usize, 0), auto.count(secret));
    try std.testing.expectEqual(@as(usize, 1), auto.count("withEnvVariable(name:\"NPM_TOKEN\"," ++
        "value:\"from-the-job\")"));
}

test "a secret passed on through GITHUB_ENV reaches later steps as a Dagger secret, and they always run" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "deploy_s3cr3t-value";
    const steps = [_]job_mod.Step{
        testStep("./fetch-token >> \"$GITHUB_ENV\""),
        testStep("./deploy.sh"),
    };
    var job = testJob(&steps);
    job.secrets = &.{secret};
    const files = [_][2][]const u8{.{
        "/github/file_commands/all_1",
        "::zig-file-command::env\nTOKEN=" ++ secret ++ "\nREGION=eu\n",
    }};
    for ([_]Options{
        .{ .step_cache = true, .test_ran_marker = "j1" },
        .{ .step_cache = true, .output_keys = true, .test_ran_marker = "j1" },
    }) |opts| {
        var auto: AutoSession = .{ .arena = arena, .files = &files };
        _ = try roundTrips(arena, &auto, opts, job);
        try expectSecretOnlyInSetSecret(auto.seen.items, secret);
        const deploy = try execOf(&auto, "./deploy.sh");
        try std.testing.expect(std.mem.indexOf(u8, deploy, "withoutEnvVariable(name:\"TOKEN\") " ++
            "{ withSecretVariable(name:\"TOKEN\",secret:\"ID") != null);
        try std.testing.expect(std.mem.indexOf(u8, deploy, "withEnvVariable(name:\"REGION\"," ++
            "value:\"eu\")") != null);
        // The script names no secret, but its environment has one: it runs in every job.
        try std.testing.expect(std.mem.indexOf(u8, deploy, "runs this step every time: it uses " ++
            "secrets (run ") != null);
        const fetch = try execOf(&auto, "./fetch-token");
        try std.testing.expect(std.mem.indexOf(u8, fetch, "runs this step every time") == null);
    }
}

test "a value masked before it is passed on through GITHUB_ENV is a secret to the steps after" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // Not one of the job's secrets: a token a step minted (an OIDC exchange) and masked.
    const minted = "minted-token-4242";
    const steps = [_]job_mod.Step{ testStep("./mint-token"), testStep("./deploy.sh") };
    const files = [_][2][]const u8{.{
        "/github/file_commands/all_1",
        "::zig-file-command::env\nTOKEN=" ++ minted ++ "\n",
    }};
    var auto: AutoSession = .{
        .arena = arena,
        .files = &files,
        .stdout = &.{.{ "./mint-token", "::add-mask::" ++ minted ++ "\n" }},
    };
    _ = try roundTrips(arena, &auto, .{ .step_cache = true, .test_ran_marker = "j1" }, testJob(&steps));
    try expectSecretOnlyInSetSecret(auto.seen.items, minted);
    const deploy = try execOf(&auto, "./deploy.sh");
    try std.testing.expect(std.mem.indexOf(u8, deploy, "withSecretVariable(name:\"TOKEN\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, deploy, "runs this step every time: it uses " ++
        "secrets (run ") != null);
}

test "a value in GITHUB_ENV masked by a later step makes the steps after that one always run" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const late = "masked-later-4242";
    const steps = [_]job_mod.Step{
        testStep("./export-value"),
        testStep("./mask-it"),
        testStep("./deploy.sh"),
    };
    const files = [_][2][]const u8{.{
        "/github/file_commands/all_1",
        "::zig-file-command::env\nVALUE=" ++ late ++ "\n",
    }};
    var auto: AutoSession = .{
        .arena = arena,
        .files = &files,
        .stdout = &.{.{ "./mask-it", "::add-mask::" ++ late ++ "\n" }},
    };
    _ = try roundTrips(arena, &auto, .{ .step_cache = true, .test_ran_marker = "j1" }, testJob(&steps));
    // The step that masks it got it as a plain variable (nothing said it was secret yet), and
    // nothing can take that back; the steps after it run every time, and get it from the
    // container, not in their own documents.
    const mask_it = try execOf(&auto, "./mask-it");
    try std.testing.expect(std.mem.indexOf(u8, mask_it, "runs this step every time") == null);
    const deploy = try execOf(&auto, "./deploy.sh");
    try std.testing.expect(std.mem.indexOf(u8, deploy, late) == null);
    try std.testing.expect(std.mem.indexOf(u8, deploy, "runs this step every time: it uses " ++
        "secrets (run ") != null);
}

test "a secret variable set again through GITHUB_ENV as a plain value loses its secret first" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "job_s3cr3t-value";
    const steps = [_]job_mod.Step{ testStep("./reset-token"), testStep("./use-token") };
    var job = testJob(&steps);
    job.secrets = &.{secret};
    job.env = &.{.{ .name = "TOKEN", .value = .{ .lit = secret } }};
    const files = [_][2][]const u8{.{
        "/github/file_commands/all_1",
        "::zig-file-command::env\nTOKEN=anonymous\n",
    }};
    var auto: AutoSession = .{ .arena = arena, .files = &files };
    _ = try roundTrips(arena, &auto, .{}, job);
    try expectSecretOnlyInSetSecret(auto.seen.items, secret);
    const use = try execOf(&auto, "./use-token");
    try std.testing.expect(std.mem.indexOf(u8, use, "withoutSecretVariable(name:\"TOKEN\") " ++
        "{ withEnvVariable(name:\"TOKEN\",value:\"anonymous\")") != null);
}

test "a script with a secret written in reaches its file as a mounted Dagger secret" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "inline_s3cr3t-value";
    // As `${{ secrets.T }}` renders: the value in the script's text.
    const steps = [_]job_mod.Step{
        testStep("curl -H 'Authorization: Bearer " ++ secret ++ "' https://deploy.example"),
        testStep("./after.sh"),
    };
    var job = testJob(&steps);
    job.secrets = &.{secret};
    for ([_]config.StepUser{ .root, .runner }) |user| {
        var auto: AutoSession = .{ .arena = arena };
        _ = try roundTrips(arena, &auto, .{
            .step_cache = true,
            .step_user = user,
            .test_ran_marker = "j1",
        }, job);
        try expectSecretOnlyInSetSecret(auto.seen.items, secret);
        // The script is nowhere but in its own `setSecret`.
        try expectSecretOnlyInSetSecret(auto.seen.items, "curl -H 'Authorization: Bearer ");
        const deploy = try execOf(&auto, "begin 1");
        // Where the command would have written it, readable by the step's user, and gone again
        // with the step's secrets; the shell runs that file as before.
        try std.testing.expect(std.mem.indexOf(u8, deploy, "withMountedSecret(path:\"/tmp/" ++
            "zig-runner-step-1.sh\",source:\"ID") != null);
        const owner = std.mem.indexOf(u8, deploy, ",owner:\"runner\",mode:292)") != null;
        try std.testing.expectEqual(user == .runner, owner);
        try std.testing.expect(std.mem.indexOf(u8, deploy, "mode:292)") != null);
        try std.testing.expect(std.mem.indexOf(u8, deploy, "\\\"$zig_shell\\\" '-e' " ++
            "'/tmp/zig-runner-step-1.sh'") != null);
        try std.testing.expect(std.mem.indexOf(u8, deploy, "> /tmp/zig-runner-step-1.sh") == null);
        try std.testing.expect(std.mem.indexOf(u8, deploy, "rm -f /tmp/zig-runner-step-1.sh") ==
            null);
        try std.testing.expect(std.mem.indexOf(u8, deploy, "withoutMount(path:\"/tmp/" ++
            "zig-runner-step-1.sh\") { id }") != null);
        try std.testing.expect(std.mem.indexOf(u8, deploy, "runs this step every time: it uses " ++
            "secrets (run ") != null);
        // A script without one is written by the command, as before.
        const after = try execOf(&auto, "./after.sh");
        try std.testing.expect(std.mem.indexOf(u8, after, "withMountedSecret") == null);
        try std.testing.expect(std.mem.indexOf(u8, after, "> /tmp/zig-runner-step-2.sh") != null);
    }
}

test "a working directory with a secret in it reaches the step as a Dagger secret, and it always runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "wd_s3cr3t-value";
    // The step's own working directory, and `defaults.run`'s for a step without one.
    var own = testStep("./deploy.sh");
    own.action.script.working_directory = .{ .lit = "deploy/" ++ secret };
    const steps = [_]job_mod.Step{ own, testStep("./by-default.sh") };
    var job = testJob(&steps);
    job.secrets = &.{secret};
    job.defaults_run = .{ .working_directory = .{ .lit = "default/" ++ secret } };
    var auto: AutoSession = .{ .arena = arena };
    _ = try roundTrips(arena, &auto, .{ .step_cache = true, .test_ran_marker = "j1" }, job);
    try expectSecretOnlyInSetSecret(auto.seen.items, secret);
    for ([_][]const u8{ "./deploy.sh", "./by-default.sh" }) |script| {
        const d = try execOf(&auto, script);
        // The script changes to it through an alias the step's own env does not get.
        try std.testing.expect(std.mem.indexOf(u8, d, "withSecretVariable(name:" ++
            "\"ZIG_SECRET_0\",secret:\"ID") != null);
        try std.testing.expect(std.mem.indexOf(u8, d, "cd \\\"$ZIG_SECRET_0\\\" && env " ++
            "-u ZIG_SECRET_0 ") != null);
        try std.testing.expect(std.mem.indexOf(u8, d, "withoutSecretVariable(name:" ++
            "\"ZIG_SECRET_0\")") != null);
        // The directory is the step's input as much as its script: it runs in every job.
        try std.testing.expect(std.mem.indexOf(u8, d, "runs this step every time: it uses " ++
            "secrets (run ") != null);
    }
}

test "a secret in a service's env reaches the service as a Dagger secret" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "db_s3cr3t-value";
    const steps = [_]job_mod.Step{testStep("./migrate.sh")};
    var job = testJob(&steps);
    job.secrets = &.{secret};
    job.services = &.{.{
        .name = "postgres",
        .image = .{ .lit = "postgres:17" },
        .env = &.{
            .{ .name = "POSTGRES_PASSWORD", .value = .{ .lit = secret } },
            .{ .name = "POSTGRES_DB", .value = .{ .lit = "app" } },
        },
        .ports = &.{.{ .lit = "5432:5432" }},
    }};
    var auto: AutoSession = .{ .arena = arena };
    _ = try roundTrips(arena, &auto, .{}, job);
    try expectSecretOnlyInSetSecret(auto.seen.items, secret);
    // In the query that starts the service.
    try std.testing.expectEqual(@as(usize, 1), auto.count("withSecretVariable(name:" ++
        "\"POSTGRES_PASSWORD\",secret:\"ID"));
    for (auto.seen.items) |d| if (std.mem.indexOf(u8, d, "POSTGRES_PASSWORD") != null)
        try std.testing.expect(std.mem.indexOf(u8, d, "asService(") != null);
    try std.testing.expectEqual(@as(usize, 1), auto.count("withEnvVariable(name:\"POSTGRES_DB\"," ++
        "value:\"app\")"));
}

test "a Docker action's argument holding a secret reaches its command as a Dagger secret" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const secret = "args_s3cr3t-value";
    var step = testStep("");
    // Split as GitHub splits it: the quoted word, space and secret included, is one argument.
    step.action = .{ .docker = .{ .image = "alpine:3.22", .inputs = &.{.{
        .name = "args",
        .value = .{ .lit = "--token \"Bearer " ++ secret ++ "\" deploy" },
    }} } };
    var job = testJob(&.{step});
    job.secrets = &.{secret};
    var auto: AutoSession = .{ .arena = arena };
    _ = try roundTrips(arena, &auto, .{ .step_cache = true, .test_ran_marker = "j1" }, job);
    try expectSecretOnlyInSetSecret(auto.seen.items, secret);
    const run_doc = try execOf(&auto, "/github/_runtime/busybox");
    // The argument is expanded from an alias as the one word it was, between the others; the
    // alias is attached, after the env's own secrets, and hidden from the command.
    const before = "'--token' \\\"$";
    const at = (std.mem.indexOf(u8, run_doc, before) orelse return error.TestUnexpectedResult) +
        before.len;
    const len = std.mem.indexOfScalar(u8, run_doc[at..], '\\') orelse
        return error.TestUnexpectedResult;
    const alias = run_doc[at..][0..len];
    try std.testing.expect(std.mem.startsWith(u8, alias, "ZIG_SECRET_"));
    try std.testing.expect(std.mem.startsWith(u8, run_doc[at + len ..], "\\\" 'deploy'"));
    const attached = try std.fmt.allocPrint(arena, "withSecretVariable(name:\"{s}\",", .{alias});
    try std.testing.expect(std.mem.indexOf(u8, run_doc, attached) != null);
    const hidden = try std.fmt.allocPrint(arena, "env -u {s} ", .{alias});
    try std.testing.expect(std.mem.indexOf(u8, run_doc, hidden) != null);
}

test "busybox is pinned by digest" {
    // A truncated or upper-case paste fails here, before CI's busybox-pin.sh pulls it.
    const at = std.mem.indexOfScalar(u8, busybox_image, '@') orelse
        return error.TestUnexpectedResult;
    const name = busybox_image[0..at];
    try std.testing.expect(std.mem.startsWith(u8, name, "busybox:"));
    try std.testing.expect(std.mem.endsWith(u8, name, "-musl"));
    try expectDigest(busybox_image[at..]);
}

test "the default image is pinned by digest, and its bare name resolves to the pin" {
    // A truncated or upper-case paste fails here, before CI's ubuntu-pin.sh asks Docker Hub.
    try std.testing.expectEqualStrings("ubuntu:24.04", default_image_name);
    try expectDigest(default_image[default_image_name.len..]);
    try std.testing.expectEqualStrings(default_image, resolveImage("ubuntu:24.04"));
    try std.testing.expectEqualStrings(default_image, resolveImage(default_image));
    // Another tag, or another digest of the same tag, is the user's image, as given.
    for ([_][]const u8{ "ubuntu:22.04", "ubuntu:latest", "ubuntu", "ubuntu:24.04@sha256:0000000000000000000000000000000000000000000000000000000000000000" }) |other|
        try std.testing.expectEqualStrings(other, resolveImage(other));
    try std.testing.expectEqualStrings("ubuntu:24.04", imageName(default_image));
    try std.testing.expectEqualStrings("custom/image:1", imageName("custom/image:1"));
}

fn expectDigest(digest: []const u8) !void {
    try std.testing.expect(std.mem.startsWith(u8, digest, "@sha256:"));
    const hex = digest["@sha256:".len..];
    try std.testing.expectEqual(@as(usize, 64), hex.len);
    for (hex) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return error.TestUnexpectedResult,
    };
}
