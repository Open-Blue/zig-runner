//! The runner's main flow (DESIGN §6): register a JIT runner, open a broker session, wait for one
//! job, acquire it, execute it through Dagger, report the result, and start over with a new
//! registration (`serve`), or exit after one job with `--once`.
const std = @import("std");
const Config = @import("config.zig").Config;
const jitconfig = @import("github/jitconfig.zig");
const auth = @import("github/auth.zig");
const broker = @import("github/broker.zig");
const engine = @import("engine.zig");
const dagger = @import("dagger.zig");
const db = @import("db.zig");
const sink = @import("sink.zig");
const redact = @import("redact.zig");
const admission = @import("admission.zig");
const handleJob = @import("loop/job.zig").handleJob;
const SpoolDir = @import("loop/job.zig").SpoolDir;
const trust = @import("trust.zig");

const Allocator = std.mem.Allocator;

/// SPEC §2 exit codes.
pub const Exit = enum(u8) { done = 0, config = 1, github = 2, db = 3 };

/// SIGTERM / SIGINT received so far (`main` installs the handlers). The first asks the runners to
/// stop: waiting ones stop at once, running jobs get `Config.stop_grace_secs` to finish and are
/// then cancelled (`StopDeadline`). The second exits immediately.
pub var stop_signals: std.atomic.Value(u32) = .init(0);

pub fn stopRequested() bool {
    return stop_signals.load(.acquire) > 0;
}

pub const Runner = struct {
    /// Lives for one cycle (`serve` frees it after each job).
    arena: Allocator,
    /// Backs each cycle's arena.
    gpa: Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    cfg: *const Config,
    log: *sink.LogSink,
    err: *std.Io.Writer,
    /// Config secrets; the job's own secrets are appended once it is acquired.
    secrets: []const []const u8,
    /// The runner's registration name; `serve` gives each cycle a new one.
    name: []const u8,
    /// Where run state is written (SPEC §5.2); null when the runner has no database.
    store: ?*db.Store = null,
    /// Shared by the pool: repositories whose output-key work ran over the limit.
    slow_outputs: ?*SlowOutputs = null,
    /// Where `serve` keeps the previous cycle's ending, running in the background (`endCycle`);
    /// null ends a cycle in place, as tests and one-off commands do.
    ending: ?*?std.Io.Future(void) = null,
    /// Where `serve` keeps the next cycle's registration, started while this cycle's job finishes
    /// (`Registering`); null registers each cycle in its turn, as tests and `--once` do.
    next: ?*?*Registering = null,
    /// This runner's place at the memory gate (`admission.zig`); null takes jobs whatever the
    /// machine's memory, as tests and `RUNNER_ADMISSION=false` do.
    gate: ?*admission.Gate = null,
    /// Where each job's log is spooled (`SpoolDir`), shared by the pool; null keeps job logs in
    /// memory, as tests and an empty `Config.log_spool_dir` do.
    spool_dir: ?*const SpoolDir = null,
    /// The pool's pre-warm, asked for again after a job that waited for the engine; null for none.
    warmer: ?*Warmer = null,
};

/// Output keys cost two walks of the job's filesystem whatever the step changed, so they are cheap
/// on a small checkout and not on a large one (25 s against 1 s, STUDY.md §3.6). When a job spends
/// more than `Config.output_keys_max_ms` on them, this remembers the repository and later jobs skip
/// them, until the runner restarts. Shared by every runner in the pool.
pub const SlowOutputs = struct {
    mu: std.Io.Mutex = .init,
    io: std.Io,
    gpa: Allocator,
    /// Repository to the milliseconds that put it here.
    repos: std.StringHashMapUnmanaged(i64) = .empty,

    /// The milliseconds a job spent, when this repository is already known to be slow.
    pub fn spent(so: *SlowOutputs, repo: []const u8) ?i64 {
        so.mu.lockUncancelable(so.io);
        defer so.mu.unlock(so.io);
        return so.repos.get(repo);
    }

    /// Remembers a repository whose job went over. True the first time, so the caller logs it once.
    pub fn record(so: *SlowOutputs, repo: []const u8, ms: i64) bool {
        so.mu.lockUncancelable(so.io);
        defer so.mu.unlock(so.io);
        if (so.repos.contains(repo)) return false;
        const key = so.gpa.dupe(u8, repo) catch return false;
        so.repos.put(so.gpa, key, ms) catch {
            so.gpa.free(key);
            return false;
        };
        return true;
    }
};

pub fn say(c: Runner, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(c.arena, fmt, args);
    try c.log.say(text);
}

/// Poll responses are 202 when idle. A fresh token is minted before the old one can expire.
pub const token_refresh_secs = 10 * 60;

/// What one cycle did.
pub const Cycle = union(enum) {
    /// A job ran and GitHub was told; whether it succeeded.
    job: bool,
    /// No job ran (or it could not be completed): the exit code, and whether trying again could
    /// help.
    failed: struct { exit: Exit, retry: bool = true },
    /// A stop was requested while the runner waited for a job.
    stopped,
    /// The machine was short of memory before a poll (`admission.zig`): the cycle ended, and with
    /// it the registration, so GitHub does not hand a job to a runner that is not asking for one.
    held,
};

/// Runs `n` runners in this process as concurrent tasks (`std.Io.Group`), each serving jobs one
/// after another (`serve`) with its own registrations, memory per job and Dagger session per job.
/// They share the configuration, the log sinks and the database connection (all safe to share).
/// Returns once every runner has stopped: the most severe exit code among them.
pub fn pool(c: Runner, n: u32) !Exit {
    // What this runner trusts, once: a runner that trusts no ref fails every job, and one that
    // trusts every ref runs pull requests, so neither may go unnoticed (#105).
    const refs = c.cfg.trusted_refs;
    try c.log.say(try trust.mode(c.arena, refs, c.cfg.trusted_events));
    if (trust.everything(refs) and trust.prodLabel(c.cfg.labels)) try c.log.say(
        "WARNING: this runner carries the prod label and trusts every ref " ++
            "(RUNNER_TRUSTED_REFS=*): a pull request that names prod in runs-on runs here",
    );
    // Nesting is control of the host, so whether it is on is said beside the trust it rides on.
    try c.log.say(if (c.cfg.dagger_nesting)
        "Dagger in steps: on, in jobs this runner vouches for (RUNNER_DAGGER_NESTING=true)"
    else
        "Dagger in steps: off (RUNNER_DAGGER_NESTING=true turns it on)");
    // When a silent engine fails a step, so it is no surprise (#100).
    if (c.cfg.engineEndpoint() != null) {
        const t = c.cfg.engine_silence_timeout_secs;
        if (t == 0) {
            try c.log.say("engine silence timeout: off (RUNNER_ENGINE_SILENCE_TIMEOUT=0)");
        } else try say(c, "engine silence timeout: {d} s (RUNNER_ENGINE_SILENCE_TIMEOUT): a " ++
            "step's query with nothing heard from the engine for that long is aborted", .{t});
    }
    // Made once here and shared: each job's spool file is created in it (`SpoolDir`). One that is
    // not safe to use is said once and the jobs keep their logs in memory, as with no directory.
    const base = c.cfg.log_spool_dir;
    var spool_dir: ?SpoolDir = null;
    if (base.len > 0) spool_dir = SpoolDir.open(c.arena, c.io, base) catch |e| d: {
        try c.err.print(
            "no log spool in {s} ({s}); job logs are kept in memory\n",
            .{ base, @errorName(e) },
        );
        break :d null;
    };
    defer if (spool_dir) |sd| sd.close(c.io);
    const slots = try c.arena.alloc(Slot, n);
    // One per process, so what one runner learns about a repository the others use too.
    const slow = try c.arena.create(SlowOutputs);
    slow.* = .{ .io = c.io, .gpa = c.gpa };
    // One per process too, so each runner counts the others' jobs before it takes one.
    const memory: ?*admission.Admission = if (c.cfg.admission) m: {
        const m = try c.arena.create(admission.Admission);
        // The last slot is the pre-warm's (`Warmer`).
        const entries = try c.arena.alloc(admission.Admission.Slot, n + 1);
        m.* = .init(c.io, c.cfg.admission_limits, entries);
        const cgroup = c.cfg.engine_cgroup;
        m.engine.source = if (std.mem.eql(u8, cgroup, "none"))
            .off
        else if (cgroup.len > 0)
            .{ .cgroup = cgroup }
        else
            .{ .host = c.cfg.engine_host };
        break :m m;
    } else null;
    // Measures the jobs running, for what jobs of their names reserve next; ends with the pool.
    var sampling: ?std.Io.Future(void) = if (memory) |m|
        c.io.concurrent(admission.Admission.sample, .{m}) catch null
    else
        null;
    defer if (sampling) |*f| f.cancel(c.io);
    // In the background, so no runner waits for it to listen for jobs.
    const warmer = if (n > 0) try Warmer.init(c, memory, n) else null;
    if (warmer) |w| w.start();
    defer if (warmer) |w| w.stop();
    var group: std.Io.Group = .init;
    for (slots, 0..) |*s, i| {
        s.* = .{ .c = c };
        s.c.warmer = warmer;
        s.c.slow_outputs = slow;
        if (spool_dir) |*sd| s.c.spool_dir = sd;
        if (memory) |m| {
            s.gate = .{ .pool = m, .slot = i };
            s.c.gate = &s.gate;
        }
        group.concurrent(c.io, Slot.main, .{s}) catch |e| {
            try c.err.print("could not start {d} runners: {s}\n", .{ n, @errorName(e) });
            group.cancel(c.io);
            return .config;
        };
    }
    if (n > 1) try say(c, "started {d} runners", .{n});
    group.await(c.io) catch {};
    var worst: Exit = .done;
    for (slots) |s| if (@backingInt(s.exit) > @backingInt(worst)) {
        worst = s.exit;
    };
    return worst;
}

/// One runner of a pool. Its error messages go through its own buffer, flushed a cycle at a time,
/// so runners' messages do not interleave mid-line.
const Slot = struct {
    c: Runner,
    exit: Exit = .done,
    gate: admission.Gate = undefined,
    err_buf: [4096]u8 = undefined,

    fn main(s: *Slot) void {
        var err_w: std.Io.File.Writer = .initStreaming(.stderr(), s.c.io, &s.err_buf);
        var c = s.c;
        c.err = &err_w.interface;
        s.exit = serve(c) catch |e| blk: {
            c.err.print("runner stopped: {s}\n", .{@errorName(e)}) catch {};
            break :blk .github;
        };
        err_w.interface.flush() catch {};
    }
};

/// Runs jobs one after another: each cycle registers a fresh JIT runner (GitHub gives a JIT runner
/// a single job), waits for a job, runs it, and frees everything the cycle allocated before the
/// next. A cycle that fails before running a job is retried with a growing delay (`backoffSecs`),
/// unless GitHub rejected the registration itself (bad token or scope), which retrying cannot fix.
/// With `--once`, returns after the first cycle: 0 if its job succeeded.
pub fn serve(c: Runner) !Exit {
    var ending: ?std.Io.Future(void) = null;
    defer if (ending) |*f| f.await(c.io);
    var next: ?*Registering = null;
    // A registration made for a cycle that will not run is removed, as an idle one must be.
    defer if (next) |r| r.discard(c);
    var failures: u32 = 0;
    defer if (c.gate) |g| g.leave(false);
    // The name the next cycle registers under, chosen before the memory gate so that a held runner
    // logs its own name: `c.name` is the pool's, shared by every runner of it.
    var held_name_buf: [256]u8 = undefined;
    var held_name: ?[]const u8 = null;
    while (true) {
        // The memory gate (#126): register only once the machine has the memory for one more job.
        if (c.gate) |g| if (checkGate(c, g)) |hold| {
            // A registration made while the last job finished would sit idle: a runner GitHub can
            // hand a job to, that is not asking for one.
            if (next) |r| {
                next = null;
                r.discard(c);
            }
            held_name = try runnerNameBuf(&held_name_buf, c);
            var hc = c;
            hc.name = held_name.?;
            if (!try admit(hc, g, hold)) return .done;
        };
        var cycle_arena: std.heap.ArenaAllocator = .init(c.gpa);
        defer cycle_arena.deinit();
        var cc = c;
        cc.arena = cycle_arena.allocator();
        cc.ending = &ending;
        if (!c.cfg.once) cc.next = &next;
        cc.name = if (next) |r|
            try cc.arena.dupe(u8, r.name)
        else if (held_name) |n|
            try cc.arena.dupe(u8, n)
        else
            try runnerName(cc.arena, c);
        held_name = null;

        const r = try cycle(cc);
        c.err.flush() catch {};
        // Polling is over, and so is the job if there was one: the next cycle is let through, or
        // not, afresh, and a job that ended reserves nothing any more.
        if (c.gate) |g| {
            g.leave(false);
            _ = g.ended();
        }
        if (r == .held and !stopRequested()) continue;
        if (c.cfg.once) return switch (r) {
            .job => |ok| if (ok) .done else .github,
            .failed => |f| f.exit,
            .stopped, .held => .done,
        };
        if (r == .stopped or r == .held or stopRequested()) return .done;
        switch (r) {
            .job => failures = 0,
            .stopped, .held => unreachable,
            .failed => |f| {
                if (!f.retry) return f.exit;
                failures += 1;
                const wait = backoffSecs(failures);
                try c.err.print(
                    "trying again in {d}s ({d} failed attempt(s) in a row)\n",
                    .{ wait, failures },
                );
                try c.err.flush();
                // In steps, so a stop is not kept waiting.
                var waited: u32 = 0;
                // A cancel (`serve`'s pool, when another runner could not start) ends the slot:
                // swallowed, it was lost, and the slot retried until a stop while the pool waited.
                while (waited < wait * 5 and !stopRequested()) : (waited += 1) {
                    try c.io.sleep(.fromMilliseconds(200), .awake);
                }
                if (stopRequested()) return .done;
            },
        }
    }
}

/// Waits, held at the memory gate for `hold`, until the machine has the memory for one more job:
/// true then, false if a stop is requested first. The hold and its end are each logged once, not
/// at every look.
fn admit(c: Runner, g: *admission.Gate, hold: admission.Hold) !bool {
    holdingBack(c, g, hold);
    while (true) {
        // In steps, so a stop is not kept waiting.
        var left = g.pool.recheck.toMilliseconds();
        while (left > 0) : (left -= @min(left, 200)) {
            if (stopRequested()) return false;
            try c.io.sleep(.fromMilliseconds(@min(left, 200)), .awake); // a cancel ends the slot (`serve`)
        }
        if (stopRequested()) return false;
        if (checkGate(c, g) == null) break;
    }
    sayUnallocated(c, "'{s}': memory is back; taking jobs again", .{c.name});
    g.announced = false;
    return true;
}

/// `Gate.check`, and what it learned about the engine's cgroup when that changed: found at start,
/// or not and why, which tells an operator whether the engine's cap is being watched.
fn checkGate(c: Runner, g: *admission.Gate) ?admission.Hold {
    const hold = g.check();
    var buf: [512]u8 = undefined;
    if (g.pool.engineNews(&buf)) |news| sayUnallocated(c, "{s}", .{news});
    return hold;
}

/// Logs a hold, unless this one already was (`listen` finds it, `admit` waits it out).
fn holdingBack(c: Runner, g: *admission.Gate, hold: admission.Hold) void {
    if (g.announced) return;
    sayUnallocated(c, "'{s}' holding back from new jobs: {f}", .{ c.name, hold });
    g.announced = true;
}

/// As `say`, on the stack: `serve`'s runner has the process's arena, which a line for every hold
/// would grow for as long as the runner runs.
pub fn sayUnallocated(c: Runner, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return;
    c.log.say(text) catch {};
}

/// A new registration name: the prefix and a random suffix.
fn runnerName(arena: Allocator, c: Runner) ![]const u8 {
    var buf: [256]u8 = undefined;
    return arena.dupe(u8, try runnerNameBuf(&buf, c));
}

fn runnerNameBuf(buf: []u8, c: Runner) ![]const u8 {
    var suffix: [4]u8 = undefined;
    c.io.random(&suffix);
    return std.fmt.bufPrint(buf, "{s}-{x}", .{ c.cfg.name_prefix, suffix });
}

/// Builds what every job builds before its first step, with no job (`set_up.warm`): the base
/// container, and the Zig cache seeds (`Config.zig_seeds`). On the laptop the first job after an
/// engine wipe spent 169 s in "Set up job" on them, the next 1 s. So it warms the engine when the
/// pool starts (a new runner, or an engine restarted while it was down), when the engine starts
/// again (a wipe happens only then), and after a job that had to wait for the engine. A failed
/// warm is said and nothing else: the first job builds what it needs, as before.
///
/// An engine start is the memory gate's to see where it sees the engine's cgroup (it is found
/// again after it was not, `Admission.engineReturns`); otherwise, as under deploy/compose.yaml,
/// it is the engine's socket appearing or being replaced (`engine.SocketIdentity`). The warm is a
/// job to the gate, in the pool's extra slot, taken only once the engine accepted the session, so
/// a warm waiting for an engine that is down holds no memory.
pub const Warmer = struct {
    c: Runner,
    /// Backs each warm, reset before the next.
    arena: std.heap.ArenaAllocator,
    memory: ?*admission.Admission,
    gate: admission.Gate = undefined,
    /// Warms asked for since the last began; the pool's start is the first.
    requests: std.atomic.Value(u32) = .init(1),
    /// What `engineStarted` saw last.
    socket: ?engine.SocketIdentity = null,
    returns: ?u32 = null,
    /// Requested when the pool stops: a wait ends, and a query is aborted.
    cancel: dagger.Cancel = .{},
    /// The current warm went through the gate, and when.
    admitted: bool = false,
    admitted_ms: i64 = 0,
    /// The last warm's error, so a failure that repeats is said once.
    failed: ?anyerror = null,
    future: ?std.Io.Future(void) = null,
    calls: Calls = .{},

    const Calls = struct {
        warm: *const @TypeOf(dagger.warm) = dagger.warm,
        socket: *const @TypeOf(engine.SocketIdentity.of) = engine.SocketIdentity.of,
    };

    /// What the warm is learned under at the gate.
    pub const job_name = "zig-runner pre-warm";
    /// How often the engine is looked at for a start: a stat, or the gate's count.
    const look_ms = 5 * std.time.ms_per_s;
    /// A warm shorter than this found everything in the engine's cache and is not learned from,
    /// as a job that replayed steps is not (`Gate.replayed`): on razorbill a warm after the other
    /// instance's took 0.4 s and was learned at 0 GB, against 1.3 GB cold, so the warm after the
    /// next wipe would have reserved nothing. A cold warm pulls an image and builds a container,
    /// far longer than this. Judged by time, not by a near-zero peak: a real run beside a job that
    /// frees memory can measure 0 too (`Learned.min_mb`), and a warm misjudged as cached only
    /// reserves the worst case again.
    const cached_ms = 3 * std.time.ms_per_s;

    /// A warmer for the pool, its gate on `memory`'s slot `slot`, or null, said why, when it would
    /// have nothing to do.
    pub fn init(c: Runner, memory: ?*admission.Admission, slot: usize) !?*Warmer {
        if (!c.cfg.prewarm) return null;
        if (c.cfg.engineEndpoint() == null) {
            try c.log.say("pre-warm skipped: RUNNER_ENGINE=cli opens no session of its own");
            return null;
        }
        if (trust.none(c.cfg.trusted_refs)) {
            try c.log.say("pre-warm skipped: this runner trusts no ref, so runs no job");
            return null;
        }
        const w = try c.arena.create(Warmer);
        w.* = .{ .c = c, .arena = .init(c.gpa), .memory = memory };
        if (memory) |m| w.gate = .{ .pool = m, .slot = slot, .warm = true };
        // What is there now is what the first warm warms.
        w.socket = w.calls.socket(c.io, c.cfg.engine_host);
        if (memory) |m| w.returns = m.engineReturns();
        return w;
    }

    pub fn start(w: *Warmer) void {
        w.future = w.c.io.concurrent(run, .{w}) catch |e| {
            sayUnallocated(w.c, "pre-warm not started: {s}", .{@errorName(e)});
            return;
        };
    }

    /// Ends a warm under way, waiting for it, and frees what it used.
    pub fn stop(w: *Warmer) void {
        w.cancel.request(std.Io.Clock.real.now(w.c.io).toMilliseconds());
        if (w.future) |*f| f.cancel(w.c.io);
        w.arena.deinit();
    }

    /// Asks for one more warm, after the one under way if there is one.
    pub fn request(w: *Warmer) void {
        _ = w.requests.fetchAdd(1, .acq_rel);
    }

    fn run(w: *Warmer) void {
        var since_look: i64 = 0;
        while (!stopRequested() and !w.cancel.requested.load(.acquire)) {
            if (since_look >= look_ms) {
                since_look = 0;
                if (w.engineStarted()) w.request();
            }
            if (w.requests.swap(0, .acq_rel) > 0) w.once();
            w.c.io.sleep(.fromMilliseconds(200), .awake) catch return;
            since_look += 200;
        }
    }

    /// Whether the engine started since this was last asked.
    fn engineStarted(w: *Warmer) bool {
        if (w.memory) |m| if (m.engineReturns()) |n| {
            defer w.returns = n;
            // First seen now: what the socket said until then covered it.
            return if (w.returns) |before| n != before else false;
        };
        const now = w.calls.socket(w.c.io, w.c.cfg.engine_host);
        defer w.socket = now;
        return engine.SocketIdentity.changed(w.socket, now);
    }

    /// One warm, said in one line.
    fn once(w: *Warmer) void {
        const turn = w.engineTurn() orelse return;
        defer if (turn) |dir| dir.close(w.c.io);
        _ = w.arena.reset(.retain_capacity);
        const arena = w.arena.allocator();
        const cfg = w.c.cfg;
        w.admitted = false;
        var msg: []const u8 = "";
        const result = w.calls.warm(arena, w.c.io, .{
            .dagger_cmd = cfg.dagger_cmd,
            .image = cfg.image,
            .engine = cfg.engineEndpoint(),
            .gpa = w.c.gpa,
            .package_caches = cfg.package_caches,
            .zig_local_cache = cfg.zig_local_cache,
            .zig_local_cache_max_mb = cfg.zig_local_cache_max_mb,
            .zig_seeds = cfg.zig_seeds,
            .step_user = cfg.step_user,
            .cancel = &w.cancel,
        }, .{ .ptr = w, .readyFn = ready }, &msg);
        const ms = std.Io.Clock.awake.now(w.c.io).toMilliseconds() - w.admitted_ms;
        if (w.admitted and w.memory != null and ms < cached_ms) w.gate.replayed();
        if (w.admitted) if (w.memory != null) if (w.gate.ended()) |learned| sayUnallocated(
            w.c,
            "the pre-warm raised the engine's memory by {f} at most ({s}); reserving {f} for it",
            .{
                admission.gb(learned.seen_mb),
                if (learned.alone) "alone" else "beside jobs",
                admission.gb(learned.estimate_mb),
            },
        );
        const warmed = result catch |e| {
            if (e == error.Cancelled or w.cancel.requested.load(.acquire)) return;
            if (w.failed) |f| if (f == e) return;
            w.failed = e;
            sayUnallocated(w.c, "pre-warm failed ({s}): {s}; the first job builds it", .{
                @errorName(e),
                if (msg.len > 0) msg else "no message",
            });
            return;
        };
        w.failed = null;
        // The packages' fingerprint names the provisioned seed, whose packages are the archive's
        // on the day it was built (set_up.zig, `provision_packages`).
        sayUnallocated(w.c, "pre-warm: base container{s} built in {d}.{d} s ({s}{s}{s})", .{
            if (warmed.seeded) " and Zig seed" else "",
            @divTrunc(ms, 1000),
            @divTrunc(@mod(ms, 1000), 100),
            warmed.image,
            if (warmed.packages != null) ", packages " else "",
            warmed.packages orelse "",
        });
    }

    /// This warm's turn on the engine: the directory of the engine's socket, locked, which closing
    /// unlocks; null inside when there is nothing to lock; null outside when a stop came first.
    /// Pools that share an engine (razorbill's two systemd units) started together and both built
    /// the base container and the seed in parallel, 205 s each: the engine does not merge two
    /// identical builds. One at a time, the second finds it all cached (`cached_ms`). The lock is
    /// on the socket's directory because it is the one place every runner of an engine can open:
    /// under systemd's ProtectSystem=strict and PrivateTmp it is read-only and /tmp is private, and
    /// under compose the engine-socket volume is all the runner shares with the engine. Opening it
    /// only needs read access, and flock works through a read-only mount and across containers (it
    /// locks the inode). A holder that dies releases it with its descriptors. A TCP engine, or a
    /// directory that cannot be opened or locked, warms unlocked, as before.
    fn engineTurn(w: *Warmer) ??std.Io.Dir {
        const io = w.c.io;
        const host = w.c.cfg.engine_host;
        if (!std.mem.startsWith(u8, host, "unix://")) return @as(?std.Io.Dir, null);
        const path = std.fs.path.dirname(host["unix://".len..]) orelse
            return @as(?std.Io.Dir, null);
        // Iterable: opened for reading, not as a bare path, which flock refuses.
        const dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch
            return @as(?std.Io.Dir, null);
        const file: std.Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
        var said = false;
        while (true) {
            const taken = file.tryLock(io, .exclusive) catch {
                dir.close(io);
                return @as(?std.Io.Dir, null);
            };
            if (taken) return dir;
            if (!said) sayUnallocated(
                w.c,
                "pre-warm waiting for another runner's warm on this engine ({s})",
                .{path},
            );
            said = true;
            // In steps, so a stop is not kept waiting.
            if (stopRequested() or w.cancel.requested.load(.acquire)) break;
            io.sleep(.fromMilliseconds(200), .awake) catch break;
        }
        dir.close(io);
        return null;
    }

    /// The engine accepted the session: through the gate, as a job of its own, unless a stop
    /// comes first.
    fn ready(ptr: *anyopaque) bool {
        const w: *Warmer = @ptrCast(@alignCast(ptr));
        if (w.memory != null) {
            var said = false;
            while (w.gate.check()) |hold| {
                if (!said) sayUnallocated(w.c, "pre-warm holding back: {f}", .{hold});
                said = true;
                var left = w.gate.pool.recheck.toMilliseconds();
                while (left > 0) : (left -= @min(left, 200)) {
                    if (stopRequested() or w.cancel.requested.load(.acquire)) return false;
                    w.c.io.sleep(.fromMilliseconds(@min(left, 200)), .awake) catch return false;
                }
            }
            w.gate.leave(true);
            w.gate.assigned(admission.jobKey("", "", job_name));
            w.admitted = true;
        }
        w.admitted_ms = std.Io.Clock.awake.now(w.c.io).toMilliseconds();
        return !stopRequested() and !w.cancel.requested.load(.acquire);
    }
};

/// The next cycle's JIT registration, made in the background while this cycle's job finishes
/// (completing it with GitHub, uploading its logs), so the next cycle can listen at once instead
/// of first waiting for GitHub to register it (about 0.7 s) and then for a token and a broker
/// session (about 0.2 s more). It is started only once a job's steps are done, so it is never left
/// waiting through a long job, and it outlives the cycle whose arena `serve` frees, so it has
/// memory of its own.
///
/// The session is the new runner's own, so it never meets the session of the runner finishing its
/// job (each JIT registration is a runner of its own, with its own agent id). A session that could
/// not be opened here is opened by the cycle, which reports why if it fails again. Whoever ends up
/// with the session deletes it exactly once: the cycle (through its `Ending`) once it took it over,
/// or `discard` when no cycle does (the runner stopping).
pub const Registering = struct {
    arena: std.heap.ArenaAllocator,
    c: Runner,
    name: []const u8,
    future: std.Io.Future(void) = undefined,
    /// GitHub's calls, replaced in tests.
    calls: Calls = .{},
    result: union(enum) {
        pending,
        ok: jitconfig.Jit,
        failed: struct { err: anyerror, status: std.http.Status, message: []const u8 },
    } = .pending,
    /// The registered runner's broker session, when it could be opened.
    session: ?Session = null,

    const Calls = struct {
        generate: *const @TypeOf(jitconfig.generate) = jitconfig.generate,
        remove: *const fn (Runner, u64, []const u8) void = removeRegistration,
        open: *const fn (Runner, jitconfig.Jit) ?Session = openSession,
        delete: *const fn (Runner, []const u8, []const u8, []const u8) void = deleteSession,
    };

    /// What the next cycle takes over: copied into its arena.
    const Taken = struct { result: @FieldType(Registering, "result"), session: ?Session };

    pub fn start(c: Runner) !*Registering {
        return startWith(c, .{});
    }

    fn startWith(c: Runner, calls: Calls) !*Registering {
        const r = try c.gpa.create(Registering);
        errdefer c.gpa.destroy(r);
        r.* = .{ .arena = .init(c.gpa), .c = c, .name = undefined, .calls = calls };
        errdefer r.arena.deinit();
        const a = r.arena.allocator();
        r.name = try runnerName(a, c);
        r.c.arena = a;
        r.c.name = r.name;
        r.c.ending = null;
        r.c.next = null;
        r.future = try c.io.concurrent(run, .{r});
        return r;
    }

    fn run(r: *Registering) void {
        var status: std.http.Status = .ok;
        var message: []const u8 = "";
        r.result = if (r.calls.generate(r.c.arena, r.c.io, r.c.cfg, r.name, &status, &message)) |jit|
            .{ .ok = jit }
        else |e|
            .{ .failed = .{ .err = e, .status = status, .message = message } };
        // A runner that is stopping takes nothing over: no session to open, only to delete.
        if (r.result == .ok and !stopRequested()) r.session = r.calls.open(r.c, r.result.ok);
    }

    /// The registration and its session, copied into `arena` (the cycle's); this is freed. When
    /// they cannot be copied, they are removed rather than left behind.
    fn take(r: *Registering, arena: Allocator) !Taken {
        r.future.await(r.c.io);
        defer r.free();
        errdefer r.end();
        return .{
            .result = switch (r.result) {
                .pending => unreachable,
                .ok => |jit| .{ .ok = try copyJit(arena, jit) },
                .failed => |f| .{ .failed = .{
                    .err = f.err,
                    .status = f.status,
                    .message = try arena.dupe(u8, f.message),
                } },
            },
            .session = if (r.session) |s| try s.copy(arena) else null,
        };
    }

    /// Never used: waited for, and its session and registration removed.
    fn discard(r: *Registering, c: Runner) void {
        r.future.await(c.io);
        r.end();
        r.free();
    }

    /// Deletes the session, then the registration, as a cycle's `Ending` does.
    fn end(r: *Registering) void {
        if (r.session) |s| r.calls.delete(r.c, s.base, s.sid, s.token);
        if (r.result == .ok) r.calls.remove(r.c, r.result.ok.runner_id, r.result.ok.runner_name);
    }

    fn free(r: *Registering) void {
        const gpa = r.c.gpa;
        r.arena.deinit();
        gpa.destroy(r);
    }
};

/// A runner's broker session, open, with the token it was opened with.
const Session = struct {
    /// The broker's URL, with a trailing slash.
    base: []const u8,
    sid: []const u8,
    token: []const u8,
    /// When `token` was minted, in seconds (see `token_refresh_secs`).
    token_at: i64,

    fn copy(s: Session, arena: Allocator) !Session {
        return .{
            .base = try arena.dupe(u8, s.base),
            .sid = try arena.dupe(u8, s.sid),
            .token = try arena.dupe(u8, s.token),
            .token_at = s.token_at,
        };
    }
};

/// Opens a session for a registered runner, as `cycle` does, for `Registering`; null when any step
/// fails (the cycle then tries again and reports what went wrong).
fn openSession(c: Runner, jit: jitconfig.Jit) ?Session {
    const creds = auth.parseCredentials(c.arena, jit.files) catch return null;
    const settings = broker.parseSettings(c.arena, jit.files) catch return null;
    var status: std.http.Status = .ok;
    const token = mintToken(c, creds, &status) catch return null;
    const token_at = std.Io.Clock.real.now(c.io).toSeconds();
    const base = withSlash(c.arena, settings.broker_url) catch return null;
    const url = std.fmt.allocPrint(c.arena, "{s}session", .{base}) catch return null;
    const body = broker.sessionBody(c.arena, settings, "zig-runner") catch return null;
    const created = broker.call(c.arena, c.io, .POST, url, token, body) catch return null;
    if (created.status.class() != .success) return null;
    const sid = jsonString(c.arena, created.body, "sessionId") orelse return null;
    return .{ .base = base, .sid = sid, .token = token, .token_at = token_at };
}

fn copyJit(arena: Allocator, jit: jitconfig.Jit) !jitconfig.Jit {
    const files = try arena.alloc(jitconfig.File, jit.files.len);
    for (jit.files, files) |f, *o| o.* = .{ .name = try arena.dupe(u8, f.name), .content = try arena.dupe(u8, f.content) };
    return .{ .runner_id = jit.runner_id, .runner_name = try arena.dupe(u8, jit.runner_name), .files = files };
}

/// Seconds to wait after `failures` failed cycles in a row: 5, 10, 20, ... up to 5 minutes.
pub fn backoffSecs(failures: u32) u32 {
    if (failures == 0) return 0;
    const shift: u5 = @intCast(@min(failures - 1, 6));
    return @min(@as(u32, 5) << shift, 300);
}

const Polled = union(enum) { poll: anyerror!broker.Response, stop: void, timeout: void };

/// How long a poll may go unanswered. The broker answers within about 50 s, with a message or
/// without one; a connection that died under the poll is never answered at all. A laptop that slept
/// for 40 minutes woke with every runner waiting on such a connection, listening as far as it knew
/// and offline as far as GitHub knew, until the runner was restarted.
pub const poll_timeout: std.Io.Duration = .fromSeconds(90);

/// One long poll for a message (it can take about 50 s), given up as soon as a stop is requested or
/// `timeout` passes: the poll runs next to a watcher and a timer, and whichever ends first cancels
/// the others (a blocked read is interrupted, and its connection is not reused). The cycle's
/// cleanup then deletes the session and the registration.
fn poll(c: Runner, url: []const u8, token: []const u8, timeout: std.Io.Duration) !Polled {
    var buf: [3]Polled = undefined;
    var sel: std.Io.Select(Polled) = .init(c.io, &buf);
    // A task that could not start must not leave the ones that did running on `buf`.
    errdefer while (sel.cancel()) |_| {};
    try sel.concurrent(.poll, pollOnce, .{ c.arena, c.io, url, token });
    try sel.concurrent(.stop, waitForStop, .{c});
    try sel.concurrent(.timeout, waitFor, .{ c.io, timeout });
    const first = sel.await() catch Polled{ .stop = {} };
    while (sel.cancel()) |_| {}
    return first;
}

fn waitFor(io: std.Io, timeout: std.Io.Duration) void {
    io.sleep(timeout, .awake) catch {};
}

fn pollOnce(
    arena: Allocator,
    io: std.Io,
    url: []const u8,
    token: []const u8,
) anyerror!broker.Response {
    // No deadline of its own: `poll`'s timer is it.
    return broker.request(arena, io, .GET, url, null, .{ .token = token, .deadline = null });
}

var stop_announced: std.atomic.Value(bool) = .init(false);

fn waitForStop(c: Runner) void {
    while (!stopRequested()) c.io.sleep(.fromMilliseconds(200), .awake) catch return;
    if (stop_announced.swap(true, .acq_rel)) return;
    // On the stack. (The cycle's arena would do even with the poll using it at the same time: std's
    // ArenaAllocator is thread-safe over a thread-safe gpa.)
    sayUnallocated(
        c,
        "stopping: waiting runners stop now, running jobs get {d} s to finish before they are " ++
            "cancelled (a second signal exits at once)",
        .{c.cfg.stop_grace_secs},
    );
}

/// Deletes the cycle's runner registration, trying again (after 1 s, then 2 s) when GitHub refuses
/// for now (422 right after a job, 5xx) or the request fails; a registration still left is reported
/// instead of being dropped silently. 404: already gone.
fn removeRegistration(c: Runner, id: u64, name: []const u8) void {
    var last: []const u8 = "";
    for (0..3) |attempt| {
        if (attempt > 0)
            c.io.sleep(.fromMilliseconds(@as(i64, @intCast(attempt)) * 1000), .awake) catch {};
        if (jitconfig.deleteRunner(c.arena, c.io, c.cfg, id)) |status| {
            const code = @backingInt(status);
            if (status.class() == .success or code == 404) return;
            last = std.fmt.allocPrint(c.arena, "HTTP {d}", .{code}) catch "HTTP error";
            if (code != 422 and status.class() != .server_error) break;
        } else |e| last = @errorName(e);
    }
    // Through the log, not `c.err`: this can run in the background while the runner's next cycle
    // writes to its own buffer.
    say(
        c,
        "could not remove runner registration '{s}' (id {d}): {s}; " ++
            "delete it in the repository's runner settings",
        .{ name, id, last },
    ) catch {};
}

/// What a cycle leaves behind: its registration and, once it had one, its broker session.
const Ending = struct {
    id: u64,
    name: []const u8,
    session: ?struct { base: []const u8, sid: []const u8 } = null,
    token: []const u8 = "",

    fn now(e: Ending, c: Runner) void {
        if (e.session) |s| deleteSession(c, s.base, s.sid, e.token);
        removeRegistration(c, e.id, e.name);
    }
};

/// Ends a cycle: deletes its session, then its registration (GitHub removes an ephemeral runner
/// once its job completes; an idle one must be removed). In a pool this runs in the background, so
/// the next cycle registers at once instead of after both answer (0.65 s between jobs). The previous
/// cycle's ending, long finished by then, is awaited first, and `serve` awaits the last.
fn endCycle(c: Runner, e: Ending) void {
    const slot = c.ending orelse return e.now(c);
    if (slot.*) |*f| f.await(c.io);
    slot.* = null;
    slot.* = EndingTask.start(c, e) catch return e.now(c);
}

/// An `Ending` run in a task of its own. It outlives the cycle, whose arena `serve` frees, so it
/// keeps copies of what it needs in memory of its own, freed when it is done.
const EndingTask = struct {
    arena: std.heap.ArenaAllocator,
    c: Runner,
    e: Ending,

    fn start(c: Runner, e: Ending) !std.Io.Future(void) {
        const t = try c.gpa.create(EndingTask);
        errdefer c.gpa.destroy(t);
        t.arena = .init(c.gpa);
        errdefer t.arena.deinit();
        const a = t.arena.allocator();
        t.e = .{
            .id = e.id,
            .name = try a.dupe(u8, e.name),
            .token = try a.dupe(u8, e.token),
            .session = if (e.session) |s|
                .{ .base = try a.dupe(u8, s.base), .sid = try a.dupe(u8, s.sid) }
            else
                null,
        };
        t.c = c;
        t.c.arena = a;
        t.c.name = t.e.name;
        t.c.ending = null;
        return c.io.concurrent(run, .{t});
    }

    fn run(t: *EndingTask) void {
        const gpa = t.c.gpa;
        t.e.now(t.c);
        t.arena.deinit();
        gpa.destroy(t);
    }
};

/// One registration and at most one job.
pub fn cycle(c: Runner) !Cycle {
    var status: std.http.Status = .ok;
    var message: []const u8 = "";
    // Made while the previous job finished, when there was one (`Registering`).
    const early: ?*Registering = if (c.next) |slot| slot.* else null;
    if (c.next) |slot| slot.* = null;
    // Its session too, when it could open one.
    var opened: ?Session = null;
    const jit = if (early) |r| taken: {
        const t = try r.take(c.arena);
        opened = t.session;
        break :taken switch (t.result) {
            .pending => unreachable,
            .ok => |j| j,
            .failed => |f| return registrationFailed(c, f.err, f.status, f.message),
        };
    } else jitconfig.generate(c.arena, c.io, c.cfg, c.name, &status, &message) catch |e|
        return registrationFailed(c, e, status, message);
    // Read when the cycle ends: the session once there is one, and the latest token. A session
    // taken over is the cycle's from here on, whatever happens next.
    var token: []const u8 = if (opened) |o| o.token else "";
    var session: @FieldType(Ending, "session") =
        if (opened) |o| .{ .base = o.base, .sid = o.sid } else null;
    defer endCycle(c, .{
        .id = jit.runner_id,
        .name = jit.runner_name,
        .session = session,
        .token = token,
    });
    try say(c, "registered runner '{s}' (id {d})", .{ jit.runner_name, jit.runner_id });

    const creds = auth.parseCredentials(c.arena, jit.files) catch |e|
        return fail(c, "credentials", e);
    var token_at: i64 = undefined;
    var base: []const u8 = undefined;
    var sid: []const u8 = undefined;
    if (opened) |o| {
        token_at = o.token_at;
        base = o.base;
        sid = o.sid;
    } else {
        const settings = broker.parseSettings(c.arena, jit.files) catch |e|
            return fail(c, "runner settings", e);
        token = mintToken(c, creds, &status) catch |e|
            return failHttp(c, "oauth token", e, status);
        token_at = std.Io.Clock.real.now(c.io).toSeconds();

        base = try withSlash(c.arena, settings.broker_url);
        const session_url = try std.fmt.allocPrint(c.arena, "{s}session", .{base});
        const session_body = try broker.sessionBody(c.arena, settings, "zig-runner");
        const created = broker.call(c.arena, c.io, .POST, session_url, token, session_body) catch |e|
            return fail(c, "create session", e);
        if (created.status.class() != .success) return failBody(c, "create session", created);
        sid = jsonString(c.arena, created.body, "sessionId") orelse
            return fail(c, "create session", error.BadResponse);
        session = .{ .base = base, .sid = sid };
    }
    try say(c, "'{s}' listening for jobs (labels: {s})", .{ c.name, c.cfg.labels });
    return listen(c, creds, base, sid, &token, &token_at);
}

/// Polls the session until a job comes, and runs it. Before each poll the runner checks that the
/// machine still has the memory for a job (`admission.zig`); when it does not, the cycle ends
/// rather than sit registered and silent, and `serve` waits for memory before registering again.
/// `token` is kept fresh for the cycle's end, which deletes the session with it.
fn listen(
    c: Runner,
    creds: auth.Credentials,
    base: []const u8,
    sid: []const u8,
    token: *[]const u8,
    token_at: *i64,
) !Cycle {
    var status: std.http.Status = .ok;
    while (true) {
        if (stopRequested()) return .stopped;
        if (c.gate) |g| if (checkGate(c, g)) |hold| {
            holdingBack(c, g, hold);
            return .held;
        };
        const now = std.Io.Clock.real.now(c.io).toSeconds();
        if (now - token_at.* > token_refresh_secs) {
            token.* = mintToken(c, creds, &status) catch |e|
                return failHttp(c, "oauth token refresh", e, status);
            token_at.* = now;
        }
        const url = try broker.messageUrl(c.arena, base, sid, "Online");
        const m = switch (try poll(c, url, token.*, poll_timeout)) {
            .stop => return .stopped,
            .timeout => {
                // Not a failure: the next poll goes out on a new connection. If the session did
                // not survive what killed this one, that poll fails and the cycle starts afresh.
                try say(c, "'{s}': no answer to a poll in {d} s; polling again", .{
                    c.name,
                    @divTrunc(poll_timeout.nanoseconds, std.time.ns_per_s),
                });
                continue;
            },
            .poll => |r| r catch |e| return fail(c, "poll", e),
        };
        if (m.status == .accepted or (m.status.class() == .success and m.body.len == 0)) continue;
        if (m.status.class() != .success) return failBody(c, "poll", m);

        const mtype = jsonString(c.arena, m.body, "messageType") orelse "";
        if (!std.mem.eql(u8, mtype, "RunnerJobRequest")) {
            try say(c, "ignoring message of type '{s}'", .{mtype});
            continue;
        }
        const inner = jsonString(c.arena, m.body, "body") orelse
            return fail(c, "job request", error.BadResponse);
        // Its memory is reserved in the other runners' checks while it ramps up.
        if (c.gate) |g| g.leave(true);
        return handleJob(c, .{
            .creds = creds,
            .token = token.*,
            .token_at = token_at.*,
            .url = try broker.messageUrl(c.arena, base, sid, "Busy"),
        }, inner);
    }
}

/// Why the runner could not be registered, with what the token must allow when GitHub refused it.
/// Rejected credentials or scope will be rejected again; anything else may be transient.
fn registrationFailed(
    c: Runner,
    e: anyerror,
    status: std.http.Status,
    message: []const u8,
) !Cycle {
    // The slot was cancelled (`serve`'s pool): not a failure to retry.
    if (e == error.Canceled) return error.Canceled;
    try c.err.writeAll("github error: ");
    try redact.write(c.err, @errorName(e), c.secrets);
    try c.err.print(" (HTTP {d})", .{@backingInt(status)});
    if (message.len > 0) {
        try c.err.writeAll(": ");
        try redact.write(c.err, message, c.secrets);
    }
    if (@backingInt(status) == 403 or @backingInt(status) == 404)
        try c.err.writeAll("\n  GH_TOKEN, or the GitHub App, must be able to manage " ++
            "self-hosted runners of GH_SCOPE: \"Administration: read and write\" on the " ++
            "repository (\"Self-hosted runners: read and write\" for an organization), " ++
            "or a classic token with repo (admin:org)");
    try c.err.writeByte('\n');
    const fatal = switch (@backingInt(status)) {
        401, 403, 404, 422 => true,
        else => false,
    };
    return .{ .failed = .{ .exit = .github, .retry = !fatal } };
}

/// `url` with one trailing slash, so paths can be appended to it.
fn withSlash(arena: Allocator, url: []const u8) ![]const u8 {
    if (std.mem.endsWith(u8, url, "/")) return url;
    return std.fmt.allocPrint(arena, "{s}/", .{url});
}

/// Ends the broker session; best effort, on the way out.
fn deleteSession(c: Runner, base: []const u8, sid: []const u8, token: []const u8) void {
    const url = std.fmt.allocPrint(c.arena, "{s}session?sessionId={s}", .{ base, sid }) catch "";
    _ = broker.call(c.arena, c.io, .DELETE, url, token, null) catch {};
}

pub fn mintToken(c: Runner, creds: auth.Credentials, status: *std.http.Status) !([]const u8) {
    var jti: [8]u8 = undefined;
    c.io.random(&jti);
    const now = std.Io.Clock.real.now(c.io).toSeconds();
    const jwt = try auth.buildJwt(
        c.arena,
        creds,
        now,
        try std.fmt.allocPrint(c.arena, "{x}", .{jti}),
    );
    return auth.fetchAccessToken(c.arena, c.io, creds, jwt, status);
}

pub fn jsonString(arena: Allocator, body: []const u8, key: []const u8) ?[]const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return null;
    if (v != .object) return null;
    const s = v.object.get(key) orelse return null;
    return if (s == .string) s.string else null;
}

const github_failure: Cycle = .{ .failed = .{ .exit = .github } };

pub fn fail(c: Runner, what: []const u8, e: anyerror) !Cycle {
    try c.err.print("error during {s}: ", .{what});
    try redact.write(c.err, @errorName(e), c.secrets);
    try c.err.writeByte('\n');
    return github_failure;
}

fn failHttp(c: Runner, what: []const u8, e: anyerror, status: std.http.Status) !Cycle {
    try c.err.print(
        "error during {s}: {s} (HTTP {d})\n",
        .{ what, @errorName(e), @backingInt(status) },
    );
    return github_failure;
}

pub fn failBody(c: Runner, what: []const u8, r: broker.Response) !Cycle {
    // Error bodies are short JSON documents without credentials.
    try c.err.print(
        "error during {s}: HTTP {d}: {s}\n",
        .{ what, @backingInt(r.status), r.body[0..@min(r.body.len, 400)] },
    );
    return github_failure;
}

test "backoffSecs doubles from 5s up to 5 minutes" {
    try std.testing.expectEqual(@as(u32, 5), backoffSecs(1));
    try std.testing.expectEqual(@as(u32, 10), backoffSecs(2));
    try std.testing.expectEqual(@as(u32, 160), backoffSecs(6));
    try std.testing.expectEqual(@as(u32, 300), backoffSecs(7));
    try std.testing.expectEqual(@as(u32, 300), backoffSecs(1000));
}

/// A runner for tests that make requests but run no job: its log lines go to `log`.
pub fn testRunner(arena: Allocator, log: *sink.LogSink, err: *std.Io.Writer, cfg: *Config) Runner {
    return .{
        .arena = arena,
        .gpa = std.testing.allocator,
        .io = std.testing.io,
        .environ = undefined,
        .cfg = cfg,
        .log = log,
        .err = err,
        .secrets = &.{},
        .name = "t",
    };
}

const FakeGitHub = struct {
    var removed: ?u64 = null;

    fn generate(arena: Allocator, _: std.Io, _: *const Config, name: []const u8, _: *std.http.Status, _: *[]const u8) jitconfig.Error!jitconfig.Jit {
        const files = try arena.alloc(jitconfig.File, 1);
        files[0] = .{ .name = ".runner", .content = try arena.dupe(u8, "{\"agentId\": 7}") };
        return .{ .runner_id = 7, .runner_name = try arena.dupe(u8, name), .files = files };
    }

    fn refuse(_: Allocator, _: std.Io, _: *const Config, _: []const u8, status: *std.http.Status, message: *[]const u8) jitconfig.Error!jitconfig.Jit {
        status.* = .forbidden;
        message.* = "no";
        return error.GithubRejected;
    }

    fn remove(_: Runner, id: u64, _: []const u8) void {
        removed = id;
        removes += 1;
    }

    // Sessions: opened in the background (`open`), or not (`noSession`); each deletion counted.
    var opens: u32 = 0;
    var removes: u32 = 0;
    var deletes: u32 = 0;
    var deleted_sid: [16]u8 = undefined;
    var deleted_len: usize = 0;

    fn reset() void {
        removed = null;
        opens = 0;
        removes = 0;
        deletes = 0;
        deleted_len = 0;
    }

    fn open(c: Runner, jit: jitconfig.Jit) ?Session {
        opens += 1;
        const sid = std.fmt.allocPrint(c.arena, "s-{d}", .{jit.runner_id}) catch return null;
        return .{ .base = "https://broker.test/", .sid = sid, .token = "tok", .token_at = 42 };
    }

    fn noSession(_: Runner, _: jitconfig.Jit) ?Session {
        opens += 1;
        return null;
    }

    fn delete(_: Runner, _: []const u8, sid: []const u8, _: []const u8) void {
        deletes += 1;
        deleted_len = @min(sid.len, deleted_sid.len);
        @memcpy(deleted_sid[0..deleted_len], sid[0..deleted_len]);
    }

    const calls: Registering.Calls = .{ .generate = generate, .remove = remove, .open = open, .delete = delete };
};

test "the next registration, made while a job finishes, is taken over, or removed when unused" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var cfg: Config = .{ .gh_token = "", .scope = undefined, .name_prefix = "r" };
    const c = testRunner(a.allocator(), &log, &w, &cfg);

    // Taken over: copied into the cycle's arena, and the background task's memory freed (the
    // testing allocator would report it otherwise). Its session too, which is the cycle's to
    // delete from then on: nothing is deleted or removed here.
    FakeGitHub.reset();
    const r = try Registering.startWith(c, FakeGitHub.calls);
    const name = try a.allocator().dupe(u8, r.name);
    const taken = try r.take(a.allocator());
    const got = taken.result.ok;
    try std.testing.expectEqual(@as(u64, 7), got.runner_id);
    try std.testing.expectEqualStrings(name, got.runner_name);
    try std.testing.expect(std.mem.startsWith(u8, got.runner_name, "r-"));
    try std.testing.expectEqualStrings("{\"agentId\": 7}", got.files[0].content);
    const s = taken.session.?;
    try std.testing.expectEqualStrings("s-7", s.sid);
    try std.testing.expectEqualStrings("https://broker.test/", s.base);
    try std.testing.expectEqualStrings("tok", s.token);
    try std.testing.expectEqual(@as(i64, 42), s.token_at);
    try std.testing.expectEqual(@as(u32, 0), FakeGitHub.deletes);
    try std.testing.expectEqual(@as(u32, 0), FakeGitHub.removes);

    // Never used (the runner stopped): its session deleted, then its registration removed, once
    // each, as an idle registration must be.
    FakeGitHub.reset();
    const unused = try Registering.startWith(c, FakeGitHub.calls);
    unused.discard(c);
    try std.testing.expectEqual(@as(u32, 1), FakeGitHub.deletes);
    try std.testing.expectEqualStrings("s-7", FakeGitHub.deleted_sid[0..FakeGitHub.deleted_len]);
    try std.testing.expectEqual(@as(u32, 1), FakeGitHub.removes);
    try std.testing.expectEqual(@as(?u64, 7), FakeGitHub.removed);

    // Refused: the cycle gets GitHub's answer, as if it had registered itself; no session is
    // opened for a runner that does not exist.
    FakeGitHub.reset();
    var refusing = FakeGitHub.calls;
    refusing.generate = FakeGitHub.refuse;
    const refused = try Registering.startWith(c, refusing);
    const f = (try refused.take(a.allocator())).result.failed;
    try std.testing.expectEqual(error.GithubRejected, f.err);
    try std.testing.expectEqual(std.http.Status.forbidden, f.status);
    try std.testing.expectEqualStrings("no", f.message);
    try std.testing.expectEqual(@as(u32, 0), FakeGitHub.opens);
    try std.testing.expectEqual(@as(u32, 0), FakeGitHub.deletes + FakeGitHub.removes);
}

test "a session the next registration could not open is left to the cycle, and never deleted" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var cfg: Config = .{ .gh_token = "", .scope = undefined, .name_prefix = "r" };
    const c = testRunner(a.allocator(), &log, &w, &cfg);
    var calls = FakeGitHub.calls;
    calls.open = FakeGitHub.noSession;

    // Taken over without one: the cycle opens it itself, as it did before.
    FakeGitHub.reset();
    const r = try Registering.startWith(c, calls);
    const taken = try r.take(a.allocator());
    try std.testing.expect(taken.result == .ok);
    try std.testing.expect(taken.session == null);
    try std.testing.expectEqual(@as(u32, 1), FakeGitHub.opens);

    // Unused: only the registration is removed; there is no session to delete.
    FakeGitHub.reset();
    const unused = try Registering.startWith(c, calls);
    unused.discard(c);
    try std.testing.expectEqual(@as(u32, 0), FakeGitHub.deletes);
    try std.testing.expectEqual(@as(u32, 1), FakeGitHub.removes);
}

test "a registration made as the runner stops opens no session, and is removed once" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var cfg: Config = .{ .gh_token = "", .scope = undefined, .name_prefix = "r" };
    const c = testRunner(a.allocator(), &log, &w, &cfg);

    FakeGitHub.reset();
    stop_signals.store(1, .release);
    defer stop_signals.store(0, .release);
    const r = try Registering.startWith(c, FakeGitHub.calls);
    // As `serve` ends on a stop: what no cycle took is discarded.
    r.discard(c);
    try std.testing.expectEqual(@as(u32, 0), FakeGitHub.opens);
    try std.testing.expectEqual(@as(u32, 0), FakeGitHub.deletes);
    try std.testing.expectEqual(@as(u32, 1), FakeGitHub.removes);
}

test "a runner short of memory stops asking for jobs, and asks again once memory is back" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    // The broker: every poll is handed a job, whose acquirejob then answers 404.
    var server: @import("github/testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    var url_buf: [64]u8 = undefined;
    const base = try arena.dupe(u8, server.url(&url_buf, "127.0.0.1", "/broker/"));

    // The machine: plenty of memory, but under pressure (PSI) until the test says otherwise.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    const thrashing = "some avg10=50.00 avg60=20.00 avg300=5.00 total=900\n";
    const calm = "some avg10=0.00 avg60=0.00 avg300=0.00 total=900\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 8388608 kB\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "pressure", .data = thrashing });
    var slots: [1]admission.Admission.Slot = undefined;
    var memory: admission.Admission = .init(io, .{}, &slots);
    memory.paths = .{
        .meminfo = try std.fs.path.join(arena, &.{ dir, "meminfo" }),
        .pressure = try std.fs.path.join(arena, &.{ dir, "pressure" }),
    };
    memory.recheck = .fromMilliseconds(10);
    var gate: admission.Gate = .{ .pool = &memory };

    var out_buf: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    var c = testRunner(arena, &log, &err, &cfg);
    c.gate = &gate;
    // A token minted now is not refreshed, so the credentials are never read.
    const creds: auth.Credentials = undefined;
    var token: []const u8 = "tok";
    var token_at = std.Io.Clock.real.now(io).toSeconds();

    // Under pressure the cycle ends before its first poll: nothing asked, nothing counted.
    try std.testing.expectEqual(Cycle.held, try listen(c, creds, base, "s", &token, &token_at));
    try std.testing.expectEqual(@as(u32, 0), server.polls.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), memory.polling);

    // `serve` then waits, looking again every 10 ms, and still asks for nothing.
    const Waiter = struct {
        done: std.atomic.Value(bool) = .init(false),
        fn run(w: *@This(), cc: Runner, g: *admission.Gate, h: admission.Hold) anyerror!bool {
            defer w.done.store(true, .release);
            return admit(cc, g, h);
        }
    };
    var waiter: Waiter = .{};
    var waiting = try io.concurrent(Waiter.run, .{ &waiter, c, &gate, gate.check().? });
    io.sleep(.fromMilliseconds(150), .awake) catch {};
    try std.testing.expect(!waiter.done.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), server.polls.load(.acquire));

    // The pressure goes: the runner is let through and takes the job it is handed.
    try tmp.dir.writeFile(io, .{ .sub_path = "pressure", .data = calm });
    try std.testing.expect(try waiting.await(io));
    try std.testing.expectEqual(@as(u32, 1), memory.polling);
    const r = try listen(c, creds, base, "s", &token, &token_at);
    try std.testing.expect(r == .failed);
    try std.testing.expectEqual(@as(u32, 1), server.polls.load(.acquire));
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "acquirejob") != null);
    // No longer polling, and its job reserved while it ramps up.
    try std.testing.expectEqual(@as(u32, 0), memory.polling);
    try std.testing.expect(slots[0].started_ms > std.math.minInt(i64));

    // The hold and its end were each said once, though the gate was looked at many times.
    const said = out.buffered();
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "holding back"));
    try std.testing.expect(std.mem.indexOf(u8, said, "memory pressure 50.00%") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "taking jobs again"));

    // A runner held when a stop comes stops at once.
    try tmp.dir.writeFile(io, .{ .sub_path = "pressure", .data = thrashing });
    stop_signals.store(1, .release);
    defer stop_signals.store(0, .release);
    const hold = gate.check().?;
    try std.testing.expect(!try admit(c, &gate, hold));
}

test "a runner holds while the engine is near its own cap, though the machine has memory" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var server: @import("github/testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    var url_buf: [64]u8 = undefined;
    const base = try arena.dupe(u8, server.url(&url_buf, "127.0.0.1", "/broker/"));

    // The machine: 8 GB available, calm. The engine (#142): 3.6 of its 4 GB in use.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 8388608 kB\n" });
    try tmp.dir.createDirPath(io, "cg/docker-e.scope");
    var scope = try tmp.dir.openDir(io, "cg/docker-e.scope", .{});
    defer scope.close(io);
    try scope.writeFile(io, .{ .sub_path = "memory.max", .data = "4294967296\n" });
    try scope.writeFile(io, .{ .sub_path = "memory.current", .data = "3774873600\n" });
    try scope.writeFile(io, .{ .sub_path = "memory.stat", .data = "inactive_file 0\n" });
    var slots: [1]admission.Admission.Slot = undefined;
    var memory: admission.Admission = .init(io, .{}, &slots);
    memory.paths = .{
        .meminfo = try std.fs.path.join(arena, &.{ dir, "meminfo" }),
        .pressure = "/nonexistent",
        .cgroup_root = try std.fs.path.join(arena, &.{ dir, "cg" }),
    };
    const cgroup = try std.fs.path.join(arena, &.{ dir, "cg", "docker-e.scope" });
    memory.engine.source = .{ .cgroup = cgroup };
    memory.recheck = .fromMilliseconds(10);
    var gate: admission.Gate = .{ .pool = &memory };

    var out_buf: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    var c = testRunner(arena, &log, &err, &cfg);
    c.gate = &gate;
    const creds: auth.Credentials = undefined;
    var token: []const u8 = "tok";
    var token_at = std.Io.Clock.real.now(io).toSeconds();

    try std.testing.expectEqual(Cycle.held, try listen(c, creds, base, "s", &token, &token_at));
    try std.testing.expectEqual(@as(u32, 0), server.polls.load(.acquire));
    const hold = gate.check().?;
    try std.testing.expect(hold == .engine);
    // A job's compiles end: the engine is back to 1 GB, and the runner takes jobs again.
    try scope.writeFile(io, .{ .sub_path = "memory.current", .data = "1073741824\n" });
    try std.testing.expect(try admit(c, &gate, hold));
    const said = out.buffered();
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "the engine's cgroup is"));
    try std.testing.expect(std.mem.indexOf(u8, said, "capped at 4.0 GB") != null);
    try std.testing.expect(std.mem.indexOf(u8, said, "engine 3.5 GB of 4.0 GB in use") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "taking jobs again"));
    try std.testing.expectEqual(@as(u32, 1), memory.polling);
}

test "a poll that is never answered is given up after its timeout" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const io = std.testing.io;
    // Connections complete in the listener's backlog and are never accepted, so a request is sent
    // and nothing ever comes back: a connection that died under the poll.
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const url = try std.fmt.allocPrint(
        a.allocator(),
        "http://127.0.0.1:{d}/message",
        .{listener.socket.address.getPort()},
    );

    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var err_buf: [1024]u8 = undefined;
    var err: std.Io.Writer = .fixed(&err_buf);
    var cfg: Config = .{ .gh_token = "", .scope = undefined };
    const c = testRunner(a.allocator(), &log, &err, &cfg);

    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    const r = try poll(c, url, "token", .fromMilliseconds(300));
    const took = std.Io.Clock.awake.now(io).toMilliseconds() - started;
    try std.testing.expect(r == .timeout);
    try std.testing.expect(took >= 300 and took < 5000);
}

test "a repository whose output keys run over the limit is remembered once" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var so: SlowOutputs = .{ .io = std.testing.io, .gpa = std.testing.allocator };
    defer {
        var it = so.repos.keyIterator();
        while (it.next()) |k| std.testing.allocator.free(k.*);
        so.repos.deinit(std.testing.allocator);
    }
    try std.testing.expect(so.spent("o/r") == null);
    try std.testing.expect(so.record("o/r", 25_600)); // the first job over the limit says so
    try std.testing.expect(!so.record("o/r", 30_000)); // later ones stay quiet
    try std.testing.expectEqual(@as(?i64, 25_600), so.spent("o/r"));
    // Another repository is unaffected: the cost follows the checkout's size, not the runner's.
    try std.testing.expect(so.spent("o/small") == null);
}

test "the pool logs what it trusts once at startup, and warns when prod trusts every ref" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    var cfg: Config = .{
        .gh_token = "",
        .scope = undefined,
        .admission = false,
        .trusted_refs = "refs/heads/main,refs/tags/v*",
    };
    const c = testRunner(a.allocator(), &log, &w, &cfg);
    try std.testing.expectEqual(Exit.done, try pool(c, 0));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(
        u8,
        w.buffered(),
        "trusting refs refs/heads/main,refs/tags/v* and events push,workflow_dispatch",
    ));
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "WARNING") == null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "Dagger in steps: off") != null);

    w.end = 0;
    cfg.dagger_nesting = true;
    _ = try pool(c, 0);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "Dagger in steps: on") != null);
    cfg.dagger_nesting = false;

    w.end = 0;
    cfg.trusted_refs = "";
    _ = try pool(c, 0);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "trusting no ref") != null);

    w.end = 0;
    cfg.trusted_refs = "*";
    cfg.labels = "self-hosted,linux,zig,prod";
    _ = try pool(c, 0);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "trusting every ref") != null);
    const warning = "WARNING: this runner carries the prod label and trusts every ref";
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), warning) != null);
}

/// `dagger.warm` for the Warmer's tests: what it was asked, and the gate as the warm found it.
const FakeWarm = struct {
    var calls: std.atomic.Value(u32) = .init(0);
    var opts: dagger.Options = .{};
    var memory: ?*admission.Admission = null;
    var during: ?admission.Admission.Slot = null;
    /// How long the warm takes, and what it raises the engine's working set by, if measured.
    var took_ms: i64 = 0;
    var rose_mb: ?u64 = null;

    fn warm(_: Allocator, _: std.Io, o: dagger.Options, ready: dagger.Ready, _: *[]const u8) anyerror!dagger.Warmed {
        _ = calls.fetchAdd(1, .acq_rel);
        opts = o;
        if (!ready.readyFn(ready.ptr)) return error.Cancelled;
        const w: *Warmer = @ptrCast(@alignCast(ready.ptr));
        w.admitted_ms -= took_ms;
        if (memory) |m| {
            const s = &m.slots[m.slots.len - 1];
            during = s.*;
            if (rose_mb) |mb| {
                s.base_mb = 600;
                s.peak_mb = 600 + mb;
            }
        }
        return .{ .image = "docker.io/library/ubuntu:24.04@sha256:abc", .seeded = o.zig_seeds.len > 0, .packages = "0123456789ab" };
    }
    fn socket(_: std.Io, _: []const u8) ?engine.SocketIdentity {
        return sockets[@min(looks, sockets.len - 1)];
    }
    var sockets: []const ?engine.SocketIdentity = &.{null};
    var looks: usize = 0;
    const calls_: Warmer.Calls = .{ .warm = warm, .socket = socket };
};

fn testWarmer(c: Runner, memory: ?*admission.Admission) !*Warmer {
    const w = (try Warmer.init(c, memory, 1)).?;
    w.calls = FakeWarm.calls_;
    FakeWarm.calls.store(0, .release);
    FakeWarm.memory = memory;
    FakeWarm.during = null;
    FakeWarm.took_ms = 0;
    FakeWarm.rose_mb = null;
    return w;
}

test "the pre-warm builds the job's base container and Zig seed through the memory gate, as a job of its own" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 8388608 kB\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "pressure", .data = "some avg10=50.00 avg60=20.00 avg300=5.00 total=900\n" });
    // One runner and the pre-warm, as `pool` makes them.
    var slots: [2]admission.Admission.Slot = undefined;
    var memory: admission.Admission = .init(io, .{}, &slots);
    memory.paths = .{
        .meminfo = try std.fs.path.join(arena, &.{ dir, "meminfo" }),
        .pressure = try std.fs.path.join(arena, &.{ dir, "pressure" }),
    };
    memory.recheck = .fromMilliseconds(10);

    var out_buf: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var cfg: Config = .{
        .gh_token = "",
        .scope = undefined,
        .trusted_refs = "refs/heads/main",
        .zig_seeds = &.{.{ .version = "0.17.0", .sha256 = "00" }},
    };
    const c = testRunner(arena, &log, &out, &cfg);
    const w = try testWarmer(c, &memory);
    defer w.arena.deinit();

    // A stop while the gate holds the warm: it gives up there, having taken nothing.
    w.cancel.request(1);
    w.once();
    try std.testing.expectEqual(@as(u32, 1), FakeWarm.calls.load(.acquire));
    try std.testing.expect(FakeWarm.during == null);
    try std.testing.expectEqual(@as(u32, 0), memory.polling);
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), slots[1].started_ms);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out.buffered(), "pre-warm holding back"));
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "pre-warm:") == null);

    // Memory back: the warm takes the pool's extra slot while it runs, under its own name, and
    // asks for what a job of this runner builds, the seed included.
    w.cancel = .{};
    try tmp.dir.writeFile(io, .{ .sub_path = "pressure", .data = "some avg10=0.00 avg60=0.00 avg300=0.00 total=900\n" });
    w.once();
    const during = FakeWarm.during.?;
    try std.testing.expect(during.started_ms != std.math.minInt(i64));
    try std.testing.expectEqual(admission.jobKey("", "", Warmer.job_name), during.key.?);
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), slots[0].started_ms);
    try std.testing.expectEqualStrings("0.17.0", FakeWarm.opts.zig_seeds[0].version);
    try std.testing.expect(FakeWarm.opts.cancel == &w.cancel);
    // Over: it reserves nothing, and said what it built from which image.
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), slots[1].started_ms);
    try std.testing.expectEqual(@as(u32, 0), memory.polling);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "pre-warm: base container and Zig seed built in 0.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "(docker.io/library/ubuntu:24.04@sha256:abc, packages 0123456789ab)") != null);
}

test "a pre-warm that found everything cached is not learned from: the cold warm's estimate stays" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var out_buf: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var cfg: Config = .{ .gh_token = "", .scope = undefined, .trusted_refs = "refs/heads/main" };
    const c = testRunner(arena, &log, &out, &cfg);
    var slots: [2]admission.Admission.Slot = undefined;
    var memory: admission.Admission = .init(std.testing.io, .{}, &slots);
    memory.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    const w = try testWarmer(c, &memory);
    defer w.arena.deinit();

    // razorbill's cold warm: 40 s, 1.3 GB.
    FakeWarm.took_ms = 40 * std.time.ms_per_s;
    FakeWarm.rose_mb = 1340;
    w.once();
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "reserving 1.3 GB for it") != null);
    // Then warms that found it all cached, 0.4 s and nothing raised, more of them than a name
    // keeps runs of: each still reserves the cold estimate, and none is learned.
    FakeWarm.took_ms = 400;
    FakeWarm.rose_mb = 0;
    for (0..admission.Learned.kept + 1) |_| {
        out.end = 0;
        w.once();
        try std.testing.expectEqual(@as(?u32, 1340), FakeWarm.during.?.est_mb);
        try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "reserving") == null);
    }
    // A restart whose first warm is cached, the other instance having warmed the engine: nothing
    // learned, so the warm after the next wipe reserves the worst case.
    memory.learned = .{};
    w.once();
    w.once();
    try std.testing.expectEqual(@as(?u32, null), FakeWarm.during.?.est_mb);
}

test "an engine start asks for a pre-warm: the gate's count where it sees the engine, else its socket appearing or replaced" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var cfg: Config = .{ .gh_token = "", .scope = undefined, .trusted_refs = "refs/heads/main" };
    const c = testRunner(arena, &log, &out, &cfg);

    // No cgroup to see (compose): the socket. Absent at start, then there, then replaced.
    const one: engine.SocketIdentity = .{ .inode = 1, .ctime = .{ .nanoseconds = 5 } };
    const two: engine.SocketIdentity = .{ .inode = 2, .ctime = .{ .nanoseconds = 9 } };
    FakeWarm.sockets = &.{ null, null, one, one, two, null };
    FakeWarm.looks = 0;
    const w = try testWarmer(c, null);
    defer w.arena.deinit();
    w.socket = null;
    var started: [5]bool = undefined;
    for (&started) |*s| {
        FakeWarm.looks += 1;
        s.* = w.engineStarted();
    }
    try std.testing.expectEqualSlices(bool, &.{ false, true, false, true, false }, &started);

    // The gate sees the engine: its count, whatever the socket does.
    var slots: [2]admission.Admission.Slot = undefined;
    var memory: admission.Admission = .init(std.testing.io, .{}, &slots);
    w.memory = &memory;
    try std.testing.expect(!w.engineStarted());
    memory.engine.seen = true;
    try std.testing.expect(!w.engineStarted());
    try std.testing.expect(!w.engineStarted());
    memory.engine.returns += 1;
    try std.testing.expect(w.engineStarted());
    try std.testing.expect(!w.engineStarted());

    // Asked for by the pool's start, and again by a job that waited for the engine.
    try std.testing.expectEqual(@as(u32, 1), w.requests.load(.acquire));
    w.request();
    try std.testing.expectEqual(@as(u32, 2), w.requests.load(.acquire));
}

test "two pools on one engine pre-warm one after the other, and a stop ends the wait" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    var out_buf: [2048]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var cfg: Config = .{
        .gh_token = "",
        .scope = undefined,
        .trusted_refs = "refs/heads/main",
        .engine_host = try std.fmt.allocPrint(arena, "unix://{s}/engine.sock", .{dir}),
    };
    const c = testRunner(arena, &log, &out, &cfg);
    // Each its own open of the directory, as two processes have.
    const first = try testWarmer(c, null);
    defer first.arena.deinit();
    const second = try testWarmer(c, null);
    defer second.arena.deinit();

    // The first is warming: the second waits for it, building nothing meanwhile, and warms once
    // it is done.
    const turn = first.engineTurn().?.?;
    const t = try std.Thread.spawn(.{}, Warmer.once, .{second});
    try io.sleep(.fromMilliseconds(600), .awake);
    try std.testing.expectEqual(@as(u32, 0), FakeWarm.calls.load(.acquire));
    turn.close(io);
    t.join();
    try std.testing.expectEqual(@as(u32, 1), FakeWarm.calls.load(.acquire));
    const waiting = "pre-warm waiting for another runner's warm on this engine";
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out.buffered(), waiting));
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "pre-warm: base container") != null);

    // A stop while it waits: it gives up there, having built nothing.
    out.end = 0;
    const again = first.engineTurn().?.?;
    defer again.close(io);
    second.cancel.request(1);
    second.once();
    try std.testing.expectEqual(@as(u32, 1), FakeWarm.calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out.buffered(), waiting));
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "pre-warm:") == null);

    // A TCP engine has no directory to share: warmed unlocked, as before.
    cfg.engine_host = "tcp://127.0.0.1:1234";
    try std.testing.expect(first.engineTurn().? == null);
}

test "no pre-warm when it is off, with RUNNER_ENGINE=cli, or when the runner trusts no ref" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var out_buf: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out } };
    var cfg: Config = .{ .gh_token = "", .scope = undefined, .trusted_refs = "refs/heads/main", .prewarm = false };
    const c = testRunner(arena, &log, &out, &cfg);
    // Off: nothing made, so nothing is sent, and a job that waited asks no one.
    try std.testing.expect(try Warmer.init(c, null, 1) == null);
    try std.testing.expectEqual(@as(usize, 0), out.buffered().len);
    cfg.prewarm = true;
    cfg.engine = .cli;
    try std.testing.expect(try Warmer.init(c, null, 1) == null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "pre-warm skipped: RUNNER_ENGINE=cli") != null);
    cfg.engine = .direct;
    cfg.trusted_refs = "";
    try std.testing.expect(try Warmer.init(c, null, 1) == null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "trusts no ref") != null);
}
