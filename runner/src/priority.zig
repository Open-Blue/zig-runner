//! Job priority, a zig-runner extension GitHub Actions does not have (#544).
//!
//! GitHub's broker hands a runner jobs in its own order and the runner cannot change it. Inside a
//! pool, though, jobs already handed out wait for room at the memory gate (`admission.zig`) and then
//! share the machine, and both can follow a priority. This file holds what is decided without the
//! machine: where a priority comes from (`Policy`, `fromEnv`), how a waiting job's priority grows
//! with its wait so that a low one is never starved (`effective`, `starvationBoundMs`), what the
//! cgroup controllers get for it (`cpuWeight`, `ioWeight`, `protectsMemory`), and which running job
//! to pause under memory pressure and when to let it go (`govern`).
//!
//! A priority is a level, 0 to 9. `normal` (4) is what a job without any gets, so a pool that
//! configures nothing behaves as before: equal levels keep the order they came in.

const std = @import("std");

pub const Level = u8;

pub const max_level: Level = 9;
pub const low: Level = 1;
pub const normal: Level = 4;
pub const high: Level = 7;

/// `high`, `low`, `normal`, or a digit 0 to 9; null for anything else.
pub fn parseLevel(text: []const u8) ?Level {
    const t = std.mem.trim(u8, text, " \t\r");
    if (std.ascii.eqlIgnoreCase(t, "low")) return low;
    if (std.ascii.eqlIgnoreCase(t, "normal")) return normal;
    if (std.ascii.eqlIgnoreCase(t, "high")) return high;
    if (t.len == 1 and t[0] >= '0' and t[0] <= '9') return t[0] - '0';
    return null;
}

/// How the pool treats priorities (`RUNNER_PRIORITY_*`). Off by default except the order, which
/// with every job at `default` is the arrival order it always was.
pub const Config = struct {
    /// The level of a job no rule, and no marker it may use, gives one.
    default: Level = normal,
    /// The highest level a job's own `ZIG_RUNNER_PRIORITY` may ask for (`fromEnv`): a workflow
    /// is the repository's author's, so what it may take from the pool is the operator's to cap.
    /// A rule in the policy file is the operator's own word and is not capped.
    env_max: Level = high,
    /// Milliseconds a job waits at the gate for each level it rises by (`effective`). 0 turns
    /// aging off, and then only the level and the arrival order count: a low job can starve.
    age_step_ms: u32 = 60 * std.time.ms_per_s,
    /// Pause low-priority native jobs while a higher one is held back by memory (`govern`).
    freeze: bool = false,
    /// PSI `some avg10`, in hundredths of a percent, from which a lower job is paused. The
    /// gate's own `max_pressure` is the line for taking no new job; this is the second line.
    freeze_pressure: u32 = 2000,
    /// The longest one pause lasts, in ms: a paused job keeps its place and its memory, but its
    /// step timeouts and its connections' idle timeouts run on, so a pause is bounded, and the
    /// job is then not paused again for as long (`govern`).
    freeze_max_ms: u32 = 90 * std.time.ms_per_s,
};

/// The level a job's rank rises to after waiting `waited_ms`, from `base`: one level per
/// `step_ms`, no further than `max_level`. A job at `max_level` ranks by its arrival, so one that
/// has waited longer is first (`admission.Admission.before`).
pub fn effective(base: Level, waited_ms: i64, step_ms: u32) Level {
    const b = @min(base, max_level);
    if (step_ms == 0 or waited_ms <= 0) return b;
    const risen = @divFloor(@as(u64, @intCast(waited_ms)), step_ms);
    return @intCast(@min(@as(u64, max_level), b + risen));
}

/// How long a job of level `base` waits at the most for its rank to reach `max_level`, from which
/// only jobs that came before it rank ahead: the time no job of any level can be kept behind
/// later arrivals, whatever their level. Null with aging off (no bound).
pub fn starvationBoundMs(base: Level, step_ms: u32) ?u64 {
    if (step_ms == 0) return null;
    return @as(u64, max_level -| @min(base, max_level)) * step_ms;
}

/// `cpu.weight` for a level: the kernel's default of 100 at `normal`, a factor of about 1.45 for
/// each level (so `high` gets three times what `normal` gets, `low` a quarter). A job's weight is
/// its share against the other jobs under the same parent only while they compete: alone it gets
/// whatever it can use.
pub fn cpuWeight(level: Level) u32 {
    const table = [_]u32{ 25, 35, 50, 70, 100, 140, 200, 300, 450, 700 };
    return table[@min(level, max_level)];
}

/// `io.weight` for a level: the same scale (the default is 100; 1 to 10000). Only the BFQ or
/// the io.cost controller honour it, and only where the job's I/O is not already throttled.
pub fn ioWeight(level: Level) u32 {
    return cpuWeight(level);
}

/// Whether a level's working set is protected from reclaim with `memory.low`: when the machine
/// must reclaim, it takes from the cgroups under their `memory.low` last, so a high job keeps its
/// pages and a lower job is what goes to swap. `memory.min` is not used: a hard guarantee
/// the kernel will OOM-kill other jobs to keep.
pub fn protectsMemory(level: Level) bool {
    return level >= high;
}

/// What a job's own environment may ask for (`ZIG_RUNNER_PRIORITY`), as a level: the value
/// capped at `env_max`, and at `default` when the job is not from a trusted ref or event, so that a
/// pull request cannot jump the line by naming itself urgent. Null when the value is no level.
pub fn fromEnv(value: []const u8, cfg: Config, trusted: bool) ?Level {
    const asked = parseLevel(value) orelse return null;
    const cap = if (trusted) cfg.env_max else @min(cfg.env_max, cfg.default);
    return @min(asked, cap);
}

/// What a rule matches on: the facts GitHub wrote into the job, not the workflow's own claims.
pub const Facts = struct {
    repository: []const u8 = "",
    workflow_ref: []const u8 = "",
    event: []const u8 = "",
    ref: []const u8 = "",
    job: []const u8 = "",
};

/// One line of the policy file: a level, and the glob each named field must match (all of them).
pub const Rule = struct {
    level: Level,
    repo: []const u8 = "*",
    workflow: []const u8 = "*",
    event: []const u8 = "*",
    ref: []const u8 = "*",
    job: []const u8 = "*",

    fn matches(r: Rule, f: Facts) bool {
        return glob(r.repo, f.repository) and glob(r.workflow, f.workflow_ref) and
            glob(r.event, f.event) and glob(r.ref, f.ref) and glob(r.job, f.job);
    }
};

/// The policy file (`RUNNER_PRIORITY_POLICY`): one rule a line, the first that matches wins, `#`
/// starts a comment:
///
///     high   repo=Open-Blue/zig-runner event=push ref=refs/heads/main
///     high   repo=Open-Blue/* job=release*
///     low    event=schedule
///     low    repo=*/docs workflow=*/.github/workflows/lint.yml@*
///
/// A field is a glob where `*` matches any run of characters (slashes too). Fields omitted match
/// anything. The level is a name or a digit.
pub const Policy = struct {
    rules: []const Rule = &.{},

    pub const Error = error{ BadLevel, BadField, OutOfMemory };

    /// `text` is held by the result: it must outlive it.
    pub fn parse(arena: std.mem.Allocator, text: []const u8) Error!Policy {
        var rules: std.ArrayList(Rule) = .empty;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, raw, '#')) |i| raw[0..i] else raw, " \t\r");
            if (line.len == 0) continue;
            var words = std.mem.tokenizeAny(u8, line, " \t");
            var rule: Rule = .{ .level = parseLevel(words.next().?) orelse return error.BadLevel };
            while (words.next()) |w| {
                const eq = std.mem.indexOfScalar(u8, w, '=') orelse return error.BadField;
                const key = w[0..eq];
                const val = w[eq + 1 ..];
                if (std.mem.eql(u8, key, "repo")) rule.repo = val //
                else if (std.mem.eql(u8, key, "workflow")) rule.workflow = val //
                else if (std.mem.eql(u8, key, "event")) rule.event = val //
                else if (std.mem.eql(u8, key, "ref")) rule.ref = val //
                else if (std.mem.eql(u8, key, "job")) rule.job = val //
                else return error.BadField;
            }
            try rules.append(arena, rule);
        }
        return .{ .rules = rules.items };
    }

    /// The first rule that matches the job, or null.
    pub fn resolve(p: Policy, f: Facts) ?Level {
        for (p.rules) |r| if (r.matches(f)) return r.level;
        return null;
    }
};

/// `*` matches any run of characters, including none; everything else matches itself.
pub fn glob(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < text.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (p < pattern.len and pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// One job as the freeze governor sees it: running natively, in a cgroup it can pause.
pub const Candidate = struct {
    level: Level,
    paused: bool,
    /// For how long it has been paused, ms (0 when not).
    paused_ms: i64 = 0,
    /// It may not be paused again before this (awake clock, ms): after a pause reached its limit.
    pause_ok_ms: i64 = std.math.minInt(i64),
    /// What it holds, MB: of those equally low, the largest is paused first, for it frees most.
    mb: u64 = 0,
};

pub const Action = union(enum) {
    none,
    /// Pause `candidates[i]`.
    pause: usize,
    /// Let `candidates[i]` go on; `expired` when it was cut short by `freeze_max_ms`.
    resume_job: struct { i: usize, expired: bool },
};

/// What to do this second, one job at a time: nothing, pause one, or let one go on.
///
/// `top` is the highest level of a job that is not paused: running, or waiting at the gate for room
/// (the one a pause is for). A job is paused only for a higher one: the lowest level below `top`,
/// when `pressure` (PSI, hundredths of a percent) is at `Config.freeze_pressure` or more. Equal
/// levels never pause each other, and the job at `top` is never paused, so there is always one
/// running. A job is let go on when it has been paused `freeze_max_ms`, when no job above it is
/// left to wait for, or when the pressure is below half the line (the same hysteresis as the
/// gate's resume thresholds), the highest first.
pub fn govern(cfg: Config, cands: []const Candidate, top: Level, pressure: u32, now_ms: i64) Action {
    // Expiry first, whatever else: a pause is bounded.
    for (cands, 0..) |c, i| {
        if (c.paused and c.paused_ms >= cfg.freeze_max_ms) return .{ .resume_job = .{ .i = i, .expired = true } };
    }
    const calm = pressure < cfg.freeze_pressure / 2;
    var best_resume: ?usize = null;
    for (cands, 0..) |c, i| {
        if (!c.paused) continue;
        if (!(calm or c.level >= top)) continue;
        if (best_resume == null or c.level > cands[best_resume.?].level) best_resume = i;
    }
    if (best_resume) |i| return .{ .resume_job = .{ .i = i, .expired = false } };
    if (pressure < cfg.freeze_pressure) return .none;
    var pick: ?usize = null;
    for (cands, 0..) |c, i| {
        if (c.paused or c.level >= top or now_ms < c.pause_ok_ms) continue;
        if (pick == null) {
            pick = i;
            continue;
        }
        const p = cands[pick.?];
        if (c.level < p.level or (c.level == p.level and c.mb > p.mb)) pick = i;
    }
    return if (pick) |i| .{ .pause = i } else .none;
}

test "levels: names and digits" {
    try std.testing.expectEqual(@as(?Level, 7), parseLevel("high"));
    try std.testing.expectEqual(@as(?Level, 1), parseLevel(" LOW "));
    try std.testing.expectEqual(@as(?Level, 9), parseLevel("9"));
    try std.testing.expectEqual(@as(?Level, null), parseLevel("10"));
    try std.testing.expectEqual(@as(?Level, null), parseLevel("urgent"));
}

test "aging: one level per step, capped, and a bound on the wait" {
    const step = 60_000;
    try std.testing.expectEqual(@as(Level, 1), effective(1, 59_999, step));
    try std.testing.expectEqual(@as(Level, 2), effective(1, 60_000, step));
    try std.testing.expectEqual(@as(Level, 9), effective(1, 10 * step, step));
    try std.testing.expectEqual(@as(Level, 9), effective(9, 1 << 40, step));
    try std.testing.expectEqual(@as(Level, 1), effective(1, 1 << 40, 0));
    try std.testing.expectEqual(@as(Level, 1), effective(1, -5, step));
    try std.testing.expectEqual(@as(?u64, 8 * step), starvationBoundMs(1, step));
    try std.testing.expectEqual(@as(?u64, 0), starvationBoundMs(9, step));
    try std.testing.expectEqual(@as(?u64, null), starvationBoundMs(1, 0));
    // At the bound the level is the top one: from there only earlier arrivals rank ahead.
    try std.testing.expectEqual(max_level, effective(1, @intCast(starvationBoundMs(1, step).?), step));
}

test "the weights rise with the level and are the kernel's defaults at normal" {
    try std.testing.expectEqual(@as(u32, 100), cpuWeight(normal));
    var last: u32 = 0;
    for (0..10) |l| {
        const w = cpuWeight(@intCast(l));
        try std.testing.expect(w > last and w >= 1 and w <= 10000);
        last = w;
    }
    try std.testing.expect(!protectsMemory(normal) and protectsMemory(high));
}

test "a job's own marker is capped, and a job that is not trusted cannot rise above the default" {
    const cfg: Config = .{ .env_max = high };
    try std.testing.expectEqual(@as(?Level, high), fromEnv("high", cfg, true));
    try std.testing.expectEqual(@as(?Level, high), fromEnv("9", cfg, true));
    try std.testing.expectEqual(@as(?Level, low), fromEnv("low", cfg, true));
    try std.testing.expectEqual(@as(?Level, normal), fromEnv("high", cfg, false));
    try std.testing.expectEqual(@as(?Level, low), fromEnv("low", cfg, false));
    try std.testing.expectEqual(@as(?Level, null), fromEnv("fast", cfg, true));
}

test "globs" {
    try std.testing.expect(glob("*", ""));
    try std.testing.expect(glob("Open-Blue/*", "Open-Blue/zig-runner"));
    try std.testing.expect(!glob("Open-Blue/*", "Other/zig-runner"));
    try std.testing.expect(glob("*/.github/workflows/lint.yml@*", "o/r/.github/workflows/lint.yml@refs/heads/main"));
    try std.testing.expect(glob("a*b*c", "aXbYbZc"));
    try std.testing.expect(!glob("a*b*c", "aXbYbZ"));
    try std.testing.expect(glob("push", "push") and !glob("push", "pushed"));
}

test "the policy file: first matching rule wins, comments, bad lines are refused" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const p = try Policy.parse(arena_state.allocator(),
        \\# the repository's main line first
        \\high repo=Open-Blue/zig-runner event=push ref=refs/heads/main
        \\low  event=schedule   # nightly work
        \\2    repo=Open-Blue/* job=docs*
        \\
    );
    try std.testing.expectEqual(@as(usize, 3), p.rules.len);
    const main: Facts = .{ .repository = "Open-Blue/zig-runner", .event = "push", .ref = "refs/heads/main" };
    try std.testing.expectEqual(@as(?Level, high), p.resolve(main));
    try std.testing.expectEqual(@as(?Level, null), p.resolve(.{ .repository = "Open-Blue/zig-runner", .event = "push", .ref = "refs/heads/x" }));
    try std.testing.expectEqual(@as(?Level, low), p.resolve(.{ .event = "schedule", .repository = "Open-Blue/zig-runner" }));
    try std.testing.expectEqual(@as(?Level, 2), p.resolve(.{ .repository = "Open-Blue/x", .event = "push", .job = "docs build" }));
    try std.testing.expectError(error.BadLevel, Policy.parse(arena_state.allocator(), "urgent repo=a\n"));
    try std.testing.expectError(error.BadField, Policy.parse(arena_state.allocator(), "high team=a\n"));
    try std.testing.expectError(error.BadField, Policy.parse(arena_state.allocator(), "high repo\n"));
}

test "govern: pause the lowest job below the top under pressure, never the top or an equal" {
    const cfg: Config = .{ .freeze = true, .freeze_pressure = 2000, .freeze_max_ms = 90_000 };
    var c = [_]Candidate{
        .{ .level = high, .paused = false, .mb = 500 },
        .{ .level = low, .paused = false, .mb = 300 },
        .{ .level = low, .paused = false, .mb = 900 },
        .{ .level = normal, .paused = false, .mb = 2000 },
    };
    // Below the line: nothing.
    try std.testing.expectEqual(Action.none, govern(cfg, &c, high, 1999, 0));
    // At it: the lowest, and of two lows the larger.
    try std.testing.expectEqual(Action{ .pause = 2 }, govern(cfg, &c, high, 2000, 0));
    // Alone at the top, or all equal: nothing to pause.
    try std.testing.expectEqual(Action.none, govern(cfg, c[0..1], high, 9000, 0));
    var eq = [_]Candidate{ .{ .level = normal, .paused = false }, .{ .level = normal, .paused = false } };
    try std.testing.expectEqual(Action.none, govern(cfg, &eq, normal, 9000, 0));
}

test "govern: resume when calm or when nothing above is left, and always within the bound" {
    const cfg: Config = .{ .freeze = true, .freeze_pressure = 2000, .freeze_max_ms = 90_000 };
    var c = [_]Candidate{
        .{ .level = normal, .paused = true, .paused_ms = 5000 },
        .{ .level = low, .paused = true, .paused_ms = 5000 },
    };
    // Still pressed, and a higher job above: both stay paused.
    try std.testing.expectEqual(Action.none, govern(cfg, &c, high, 1500, 0));
    // Hysteresis: only below half the line is calm. The higher of the two goes first.
    try std.testing.expectEqual(Action{ .resume_job = .{ .i = 0, .expired = false } }, govern(cfg, &c, high, 999, 0));
    // The job above is gone (top fell to its level): that one goes on, whatever the pressure.
    try std.testing.expectEqual(Action{ .resume_job = .{ .i = 0, .expired = false } }, govern(cfg, &c, normal, 9000, 0));
    // A pause is bounded, however pressed the machine.
    c[1].paused_ms = 90_000;
    try std.testing.expectEqual(Action{ .resume_job = .{ .i = 1, .expired = true } }, govern(cfg, &c, high, 9000, 0));
    // After that it is not paused again at once.
    var d = [_]Candidate{ .{ .level = high, .paused = false }, .{ .level = low, .paused = false, .pause_ok_ms = 100_000 } };
    try std.testing.expectEqual(Action.none, govern(cfg, &d, high, 9000, 50_000));
    try std.testing.expectEqual(Action{ .pause = 1 }, govern(cfg, &d, high, 9000, 100_000));
}
