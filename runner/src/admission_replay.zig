//! Test-only replay of job traces through the real memory gate (`admission.zig`), for comparing
//! variants of it (experiment, not for merge). It drives the real `Admission` and `Gate` with a
//! virtual clock (a copy of the test `Io` whose `now` is ours) and a memory model: each running job's
//! working set ramps linearly to its peak, the machine's `MemAvailable` is a fixed baseline less
//! the working sets, written to the fixture file the gate reads. Page cache, reclaim and swap are
//! not modelled. One tick is one second; a held runner looks again after `recheck` or when its
//! own pool's `changes()` moves, as in `loop.zig`.
//!
//! The same file compiles on every variant: what only some of them have (`Limits.margin_percent`
//! of #464, `Admission.budget` of #469) is found with `@hasField`.
const std = @import("std");
const admission = @import("admission.zig");

const Admission = admission.Admission;
const Gate = admission.Gate;
const Limits = admission.Limits;

const has_margin = @hasField(Limits, "margin_percent");
const has_budget = @hasField(Admission, "budget");

fn variantName() []const u8 {
    if (has_margin and has_budget) return "main+464+469";
    if (has_margin) return "main+464";
    if (has_budget) return "main+469";
    return "main";
}

// The virtual clock. Awake time starts well above zero; wall time at a fixed date.
var clock_ms: i64 = 0;
const awake_base_ms: i64 = 10_000_000;
const wall_base_ms: i64 = 1_800_000_000_000;
var vtable_copy: std.Io.VTable = undefined;

fn virtualNow(_: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
    const ms: i64 = switch (clock) {
        .real => wall_base_ms + clock_ms,
        else => awake_base_ms + clock_ms,
    };
    return .{ .nanoseconds = @as(i96, ms) * std.time.ns_per_ms };
}

fn virtualIo() std.Io {
    vtable_copy = std.testing.io.vtable.*;
    vtable_copy.now = virtualNow;
    return .{ .userdata = std.testing.io.userdata, .vtable = &vtable_copy };
}

/// razorbill: 8 GB, MemAvailable 5368 MB at idle (runner-bench p9-v031-pi samples), job cgroup
/// memory.max 3.1 GB.
const Machine = struct {
    total_mb: u64 = 7900,
    idle_available_mb: u64 = 5368,
    job_cap_mb: u64 = 3174,
};

pub const Job = struct {
    name: []const u8,
    pool: u8,
    arrive_s: u32,
    dur_s: u32,
    peak_mb: u32,
    ramp_s: u32 = 45,
    /// Not measured: runs to teach the gate sizes (steady state), never killed.
    warm: bool = false,
    /// Times it is run again, `rerun_delay_s` after being killed.
    reruns: u8 = 0,
};

const rerun_delay_s = 20;

pub const Options = struct {
    machine: Machine = .{},
    /// Runners per pool (prod, ci, bench).
    runners: [3]u32 = .{ 3, 6, 6 },
    /// The kernel kills a job when its working set meets its cgroup's `memory.max` or the sum of
    /// the working sets meets the machine's available memory (the largest dies).
    kill: bool = false,
    shared: bool = false,
    margin: ?u32 = null,
    horizon_s: u32 = 6 * 3600,
    /// Print each start (measured jobs).
    trace: bool = false,
};

const pool_names = [3][]const u8{ "prod", "ci", "bench" };

const State = enum { idle, listening, waiting, running };

const Runner = struct {
    gate: Gate,
    state: State = .idle,
    next_check_ms: i64 = 0,
    seen_epoch: u32 = 0,
    job: usize = 0,
    cgroup: []const u8 = "",
};

const Pool = struct {
    adm: Admission,
    slots: []Admission.Slot,
    runners: []Runner,
    queue: std.ArrayList(usize) = .empty,
};

const Live = struct {
    job: Job,
    arrived_ms: i64 = 0,
    started_ms: i64 = -1,
    ended_ms: i64 = -1,
    forced: bool = false,
    killed: bool = false,
    ws_mb: u64 = 0,
    reruns_left: u8 = 0,
};

pub const Result = struct {
    jobs: u32 = 0,
    unfinished: u32 = 0,
    median_delay_s: f64 = 0,
    p95_delay_s: f64 = 0,
    worst_delay_s: f64 = 0,
    /// Rising edges of "sum of working sets > what the machine has", and seconds spent there.
    oom_events: u32 = 0,
    oom_seconds: u32 = 0,
    /// Same, but for the sum of the running jobs' real peaks (what was committed, whenever it hits).
    commit_events: u32 = 0,
    /// Seconds with less than the gate's floor (1536 MB) of available memory left.
    below_floor_s: u32 = 0,
    forced_starts: u32 = 0,
    kills: u32 = 0,
    wall_s: u32 = 0,
    max_ws_mb: u64 = 0,
};

fn lessF(_: void, a: f64, b: f64) bool {
    return a < b;
}

fn pct(sorted: []const f64, p: f64) f64 {
    if (sorted.len == 0) return 0;
    const i: usize = @intFromFloat(@floor(p * @as(f64, @floatFromInt(sorted.len - 1)) + 0.5));
    return sorted[i];
}

pub fn run(jobs_in: []const Job, opt: Options) !Result {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = virtualIo();
    clock_ms = 0;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    const meminfo = try std.fmt.allocPrint(arena, "{s}/meminfo", .{base});
    try tmp.dir.createDirPath(std.testing.io, "proc");

    var limits: Limits = .{};
    if (has_margin) if (opt.margin) |m| {
        limits.margin_percent = m;
    };

    var pools: [3]*Pool = undefined;
    for (&pools, 0..) |*p, pi| {
        const n = opt.runners[pi];
        const pool = try arena.create(Pool);
        pool.slots = try arena.alloc(Admission.Slot, n + 1);
        pool.runners = try arena.alloc(Runner, n);
        pool.adm = Admission.init(io, limits, pool.slots);
        pool.adm.native = true;
        pool.adm.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
        pool.queue = .empty;
        if (has_budget and opt.shared) {
            const pid: i32 = @intCast(1000 + pi);
            const start: u64 = 5000 + pi;
            var dir: [32]u8 = undefined;
            var text: [160]u8 = undefined;
            try tmp.dir.createDirPath(std.testing.io, try std.fmt.bufPrint(&dir, "proc/{d}", .{pid}));
            try tmp.dir.writeFile(std.testing.io, .{
                .sub_path = try std.fmt.bufPrint(&dir, "proc/{d}/stat", .{pid}),
                .data = try std.fmt.bufPrint(
                    &text,
                    "{d} (zig run) ner) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {d} 0 0\n",
                    .{ pid, start },
                ),
            });
            pool.adm.budget = .{
                .path = try std.fmt.allocPrint(arena, "{s}/budget", .{base}),
                .pool = pool_names[pi],
                .pid = pid,
                .start = start,
                .proc = try std.fmt.allocPrint(arena, "{s}/proc", .{base}),
            };
        }
        for (pool.runners, 0..) |*r, i| {
            const cg = try std.fmt.allocPrint(arena, "{s}/cg-{d}-{d}", .{ base, pi, i });
            try tmp.dir.createDirPath(std.testing.io, try std.fmt.allocPrint(arena, "cg-{d}-{d}", .{ pi, i }));
            r.* = .{ .gate = .{ .pool = &pool.adm, .slot = i }, .cgroup = cg };
        }
        p.* = pool;
    }

    var live: std.ArrayList(Live) = .empty;
    for (jobs_in) |j| try live.append(arena, .{ .job = j, .reruns_left = j.reruns });
    // The measured jobs come after the warm-up has ended and its reservations have expired.
    var warm_end_s: u32 = 0;
    for (jobs_in) |j| if (j.warm) {
        warm_end_s = @max(warm_end_s, j.arrive_s + j.dur_s);
    };
    const shift_s: u32 = if (warm_end_s > 0) warm_end_s + 200 else 0;
    for (live.items) |*l| {
        l.arrived_ms = @as(i64, l.job.arrive_s + (if (l.job.warm) 0 else shift_s)) * 1000;
    }

    var res: Result = .{};
    var last_avail: i64 = -1;
    var over_ws = false;
    var over_commit = false;
    var t: u32 = 0;
    var open: usize = live.items.len;
    var first_arrival_ms: i64 = std.math.maxInt(i64);
    var last_end_ms: i64 = 0;
    for (live.items) |l| if (!l.job.warm) {
        first_arrival_ms = @min(first_arrival_ms, l.arrived_ms);
    };

    while (open > 0 and t < opt.horizon_s) : (t += 1) {
        clock_ms = @as(i64, t) * 1000;
        const now_ms = clock_ms;
        const kill_on = opt.kill;

        // 1. Memory: working sets, kills, the machine's reading.
        var sum_ws: u64 = 0;
        var sum_peak: u64 = 0;
        var biggest: ?usize = null;
        for (pools) |pool| for (pool.runners) |*r| {
            if (r.state != .running) continue;
            const l = &live.items[r.job];
            const el: u64 = @intCast(@max(now_ms - l.started_ms, 0) / 1000);
            const ramp: u64 = @max(@min(l.job.ramp_s, l.job.dur_s / 2), 1);
            l.ws_mb = if (el >= ramp) l.job.peak_mb else @as(u64, l.job.peak_mb) * el / ramp;
            sum_ws += l.ws_mb;
            sum_peak += l.job.peak_mb;
            if (biggest == null or l.ws_mb > live.items[biggest.?].ws_mb) biggest = r.job;
        };
        const measuring = t >= shift_s;
        if (measuring) {
            const avail = opt.machine.idle_available_mb;
            const ow = sum_ws > avail;
            if (ow and !over_ws) res.oom_events += 1;
            if (ow) res.oom_seconds += 1;
            over_ws = ow;
            const oc = sum_peak > avail;
            if (oc and !over_commit) res.commit_events += 1;
            over_commit = oc;
            if (avail < sum_ws + 1536) res.below_floor_s += 1;
            res.max_ws_mb = @max(res.max_ws_mb, sum_ws);
        }
        // Kills (not of warm-up runs).
        var to_kill: [64]usize = undefined;
        var nk: usize = 0;
        if (kill_on) {
            for (pools) |pool| for (pool.runners) |*r| {
                if (r.state != .running) continue;
                const l = &live.items[r.job];
                if (l.job.warm) continue;
                if (l.ws_mb >= opt.machine.job_cap_mb and l.job.peak_mb >= opt.machine.job_cap_mb) {
                    if (nk < to_kill.len) {
                        to_kill[nk] = r.job;
                        nk += 1;
                    }
                }
            };
            if (sum_ws > opt.machine.idle_available_mb) if (biggest) |b| {
                if (!live.items[b].job.warm and nk < to_kill.len) {
                    var dup = false;
                    for (to_kill[0..nk]) |k| dup = dup or k == b;
                    if (!dup) {
                        to_kill[nk] = b;
                        nk += 1;
                    }
                }
            };
            sum_ws = 0;
            for (pools) |pool| for (pool.runners) |*r| if (r.state == .running) {
                var dead = false;
                for (to_kill[0..nk]) |k| dead = dead or k == r.job;
                if (!dead) sum_ws += live.items[r.job].ws_mb;
            };
        }
        const avail_now: i64 = @as(i64, @intCast(opt.machine.idle_available_mb)) - @as(i64, @intCast(sum_ws));
        const shown: i64 = @max(avail_now, 0);
        if (shown != last_avail) {
            last_avail = shown;
            var buf: [160]u8 = undefined;
            try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "meminfo", .data = try std.fmt.bufPrint(
                &buf,
                "MemTotal: {d} kB\nMemAvailable: {d} kB\n",
                .{ opt.machine.total_mb * 1024, @as(u64, @intCast(shown)) * 1024 },
            ) });
        }
        // The gate's own sampling of peaks (once a second, from the cgroup).
        for (pools) |pool| for (pool.runners) |*r| if (r.state == .running) {
            const s = &pool.slots[r.gate.slot];
            s.peak_mb = @max(s.peak_mb, live.items[r.job].ws_mb);
        };

        // 2. Jobs that end: by time, or killed.
        for (pools) |pool| for (pool.runners, 0..) |*r, ri| {
            if (r.state != .running) continue;
            const l = &live.items[r.job];
            var killed = false;
            for (to_kill[0..nk]) |k| killed = killed or k == r.job;
            const done = now_ms - l.started_ms >= @as(i64, l.job.dur_s) * 1000;
            if (!killed and !done) continue;
            if (killed) {
                l.killed = true;
                res.kills += 1;
                var buf: [64]u8 = undefined;
                const evs = try std.fmt.allocPrint(arena, "cg-{d}-{d}/memory.events", .{ poolIndex(pools, pool), ri });
                try tmp.dir.writeFile(std.testing.io, .{ .sub_path = evs, .data = "high 0\noom 1\noom_kill 1\n" });
                _ = &buf;
            }
            r.gate.nativeDone();
            _ = r.gate.ended();
            l.ended_ms = now_ms;
            last_end_ms = @max(last_end_ms, now_ms);
            r.state = .idle;
            r.next_check_ms = now_ms;
            open -= 1;
            if (killed and l.reruns_left > 0) {
                try live.append(arena, .{
                    .job = l.job,
                    .arrived_ms = now_ms + rerun_delay_s * 1000,
                    .reruns_left = l.reruns_left - 1,
                });
                open += 1;
            }
        };

        // 3. Arrivals join their pool's queue.
        for (live.items, 0..) |*l, i| {
            if (l.started_ms == -1 and l.arrived_ms == now_ms and l.ended_ms == -1) {
                try pools[l.job.pool].queue.append(arena, i);
            }
        }

        // 4. Runners.
        for (pools) |pool| for (pool.runners, 0..) |*r, ri| {
            const due = now_ms >= r.next_check_ms or pool.adm.changes() != r.seen_epoch;
            switch (r.state) {
                .idle => {
                    if (!due) continue;
                    const hold = r.gate.check();
                    r.seen_epoch = pool.adm.changes();
                    r.next_check_ms = now_ms + 5000;
                    if (hold == null) r.state = .listening;
                },
                .listening, .waiting => {},
                .running => continue,
            }
            if (r.state == .listening and pool.queue.items.len > 0) {
                const ji = pool.queue.orderedRemove(0);
                r.job = ji;
                const j = live.items[ji].job;
                r.gate.leave(true);
                r.gate.assigned(admission.jobKey("o/r", "o/r/.github/workflows/w.yml", j.name));
                r.state = .waiting;
                r.next_check_ms = now_ms;
            }
            if (r.state == .waiting and (now_ms >= r.next_check_ms or pool.adm.changes() != r.seen_epoch)) {
                const l = &live.items[r.job];
                const st = r.gate.start();
                r.seen_epoch = pool.adm.changes();
                r.next_check_ms = now_ms + 5000;
                switch (st) {
                    .wait => {},
                    .started, .forced => {
                        if (st == .forced and !l.job.warm) {
                            l.forced = true;
                            res.forced_starts += 1;
                        }
                        const cg = try std.fmt.allocPrint(arena, "cg-{d}-{d}", .{ poolIndex(pools, pool), ri });
                        try tmp.dir.writeFile(std.testing.io, .{
                            .sub_path = try std.fmt.allocPrint(arena, "{s}/memory.current", .{cg}),
                            .data = "0\n",
                        });
                        try tmp.dir.writeFile(std.testing.io, .{
                            .sub_path = try std.fmt.allocPrint(arena, "{s}/memory.max", .{cg}),
                            .data = try std.fmt.allocPrint(arena, "{d}\n", .{opt.machine.job_cap_mb << 20}),
                        });
                        try tmp.dir.writeFile(std.testing.io, .{
                            .sub_path = try std.fmt.allocPrint(arena, "{s}/memory.events", .{cg}),
                            .data = "high 0\noom 0\noom_kill 0\n",
                        });
                        _ = r.gate.native(r.cgroup);
                        r.gate.noHigh(opt.machine.job_cap_mb);
                        l.started_ms = now_ms;
                        r.state = .running;
                        if (opt.trace and !l.job.warm) std.debug.print("START\tt={d}\tpool={s}\t{s}\tdelay={d}\tforced={}\tavail={d}\n", .{ @divTrunc(now_ms, 1000) - shift_s, pool_names[poolIndex(pools, pool)], l.job.name, @divTrunc(now_ms - l.arrived_ms, 1000), st == .forced, last_avail });
                    },
                }
            }
        };
    }

    // Statistics over the measured jobs.
    var delays: std.ArrayList(f64) = .empty;
    for (live.items) |l| {
        if (l.job.warm) continue;
        res.jobs += 1;
        if (l.started_ms < 0) {
            res.unfinished += 1;
            continue;
        }
        try delays.append(arena, @as(f64, @floatFromInt(l.started_ms - l.arrived_ms)) / 1000.0);
        if (l.ended_ms < 0) res.unfinished += 1;
    }
    std.mem.sort(f64, delays.items, {}, lessF);
    res.median_delay_s = pct(delays.items, 0.5);
    res.p95_delay_s = pct(delays.items, 0.95);
    res.worst_delay_s = if (delays.items.len > 0) delays.items[delays.items.len - 1] else 0;
    res.wall_s = @intCast(@max(@divTrunc(last_end_ms - @min(first_arrival_ms, last_end_ms), 1000), 0));
    return res;
}

fn poolIndex(pools: [3]*Pool, p: *Pool) usize {
    for (pools, 0..) |q, i| if (q == p) return i;
    unreachable;
}

fn report(scenario: []const u8, label: []const u8, r: Result) void {
    std.debug.print(
        "RESULT\t{s}\t{s}\t{s}\tjobs={d}\tunfinished={d}\tmedian={d:.1}\tp95={d:.1}\tworst={d:.1}" ++
            "\toom_ev={d}\toom_s={d}\tcommit_ev={d}\tbelow_floor_s={d}\tforced={d}\tkills={d}" ++
            "\twall={d}\tmax_ws={d}\n",
        .{
            variantName(),    scenario,        label,           r.jobs,       r.unfinished,
            r.median_delay_s, r.p95_delay_s,   r.worst_delay_s, r.oom_events, r.oom_seconds,
            r.commit_events,  r.below_floor_s, r.forced_starts, r.kills,      r.wall_s,
            r.max_ws_mb,
        },
    );
}

// ---- Scenarios ------------------------------------------------------------------------------

const bench_pool = 2;
const ci_pool = 1;
const prod_pool = 0;

/// The e2e jobs of the bench workflow (names and durations from the p9 journals).
const e2e = [_]struct { name: []const u8, dur: u32 }{
    .{ .name = "cache", .dur = 8 },     .{ .name = "secret", .dur = 2 },  .{ .name = "docker", .dur = 2 },
    .{ .name = "js", .dur = 3 },        .{ .name = "service", .dur = 2 }, .{ .name = "files", .dur = 2 },
    .{ .name = "toolcache", .dur = 3 }, .{ .name = "hog", .dur = 10 },
};

fn parseTrace(arena: std.mem.Allocator, text: []const u8) ![]Job {
    var out: std.ArrayList(Job) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, '\t');
        const off = try std.fmt.parseInt(u32, f.next().?, 10);
        const name = f.next().?;
        const dur = try std.fmt.parseInt(u32, f.next().?, 10);
        const peak = try std.fmt.parseInt(u32, f.next().?, 10);
        try out.append(arena, .{ .name = name, .pool = bench_pool, .arrive_s = off, .dur_s = dur, .peak_mb = peak });
    }
    return out.items;
}

/// A warm-up that runs each of `names` twice, one after the other, alone: what a pool that has
/// been up for a while has learned.
fn warmUp(arena: std.mem.Allocator, out: *std.ArrayList(Job), specs: []const Job) !void {
    var t: u32 = 0;
    for (0..2) |_| for (specs) |s| {
        var j = s;
        j.warm = true;
        j.arrive_s = t;
        j.reruns = 0;
        try out.append(arena, j);
        t += s.dur_s + 130;
    };
}

fn tail(arena: std.mem.Allocator, out: *std.ArrayList(Job), specs: []const Job) !void {
    for (specs) |s| try out.append(arena, s);
}

const Scenario = struct {
    name: []const u8,
    jobs: []const Job,
    kill: bool,
};

fn buildScenarios(arena: std.mem.Allocator) ![]Scenario {
    var list: std.ArrayList(Scenario) = .empty;
    const trace_text = @embedFile("admission_replay_trace.tsv");

    // T: the real bench trace (p9-v031-pi), steady state: the names are learned first.
    {
        const trace = try parseTrace(arena, trace_text);
        var jobs: std.ArrayList(Job) = .empty;
        var seen: std.ArrayList(Job) = .empty;
        for (trace) |j| {
            var known = false;
            for (seen.items) |s| known = known or (std.mem.eql(u8, s.name, j.name) and s.peak_mb == j.peak_mb);
            if (!known) try seen.append(arena, j);
        }
        try warmUp(arena, &jobs, seen.items);
        try tail(arena, &jobs, trace);
        try list.append(arena, .{ .name = "T-trace", .jobs = jobs.items, .kill = false });

        // T+: the same bench trace with the other pools busy: ci builds and prod jobs on
        // a steady cadence over the same hour (synthetic, see the report).
        var plus: std.ArrayList(Job) = .empty;
        const ci_specs = [_]Job{
            .{ .name = "ci-test", .pool = ci_pool, .arrive_s = 0, .dur_s = 150, .peak_mb = 2000 },
            .{ .name = "ci-lint", .pool = ci_pool, .arrive_s = 0, .dur_s = 40, .peak_mb = 300 },
            .{ .name = "prod-build", .pool = prod_pool, .arrive_s = 0, .dur_s = 180, .peak_mb = 1800 },
            .{ .name = "prod-deploy", .pool = prod_pool, .arrive_s = 0, .dur_s = 30, .peak_mb = 150 },
        };
        var all_warm: std.ArrayList(Job) = .empty;
        try all_warm.appendSlice(arena, seen.items);
        try all_warm.appendSlice(arena, &ci_specs);
        try warmUp(arena, &plus, all_warm.items);
        try tail(arena, &plus, trace);
        var at: u32 = 20;
        var n: u32 = 0;
        while (at < 3500) : (n += 1) {
            var a = ci_specs[0];
            a.arrive_s = at;
            try plus.append(arena, a);
            var b = ci_specs[1];
            b.arrive_s = at + 5;
            try plus.append(arena, b);
            if (n % 2 == 0) {
                var c = ci_specs[2];
                c.arrive_s = at + 30;
                try plus.append(arena, c);
                var d = ci_specs[3];
                d.arrive_s = at + 31;
                try plus.append(arena, d);
            }
            at += 240;
        }
        try list.append(arena, .{ .name = "T+-trace+busy-pools", .jobs = plus.items, .kill = false });
    }

    // A: all three pools get a burst at the same moment.
    {
        var jobs: std.ArrayList(Job) = .empty;
        var specs: std.ArrayList(Job) = .empty;
        try specs.append(arena, .{ .name = "build", .pool = bench_pool, .arrive_s = 0, .dur_s = 250, .peak_mb = 2400 });
        for (e2e) |e| try specs.append(arena, .{ .name = e.name, .pool = bench_pool, .arrive_s = 0, .dur_s = e.dur, .peak_mb = 64 });
        try specs.append(arena, .{ .name = "ci-build", .pool = ci_pool, .arrive_s = 0, .dur_s = 200, .peak_mb = 2400 });
        try specs.append(arena, .{ .name = "prod-job", .pool = prod_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 1500 });
        try warmUp(arena, &jobs, specs.items);
        // 2 cold builds and 7 e2e on bench, 1 build on ci, 1 job on prod, all at t=0.
        const burst = [_]Job{
            .{ .name = "build", .pool = bench_pool, .arrive_s = 0, .dur_s = 250, .peak_mb = 2400 },
            .{ .name = "build", .pool = bench_pool, .arrive_s = 0, .dur_s = 250, .peak_mb = 2400 },
            .{ .name = "cache", .pool = bench_pool, .arrive_s = 0, .dur_s = 8, .peak_mb = 64 },
            .{ .name = "secret", .pool = bench_pool, .arrive_s = 0, .dur_s = 2, .peak_mb = 64 },
            .{ .name = "docker", .pool = bench_pool, .arrive_s = 0, .dur_s = 2, .peak_mb = 64 },
            .{ .name = "js", .pool = bench_pool, .arrive_s = 0, .dur_s = 3, .peak_mb = 64 },
            .{ .name = "service", .pool = bench_pool, .arrive_s = 0, .dur_s = 2, .peak_mb = 64 },
            .{ .name = "files", .pool = bench_pool, .arrive_s = 0, .dur_s = 2, .peak_mb = 64 },
            .{ .name = "toolcache", .pool = bench_pool, .arrive_s = 0, .dur_s = 3, .peak_mb = 64 },
            .{ .name = "ci-build", .pool = ci_pool, .arrive_s = 0, .dur_s = 200, .peak_mb = 2400 },
            .{ .name = "prod-job", .pool = prod_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 1500 },
        };
        try tail(arena, &jobs, &burst);
        try list.append(arena, .{ .name = "A-burst-all-pools", .jobs = jobs.items, .kill = false });
    }

    // B: jobs whose real peak is 40% above what they were learned at (1200 -> 1680, 600 -> 840), on
    // three pools together, with small jobs about.
    {
        var jobs: std.ArrayList(Job) = .empty;
        const learned = [_]Job{
            .{ .name = "big", .pool = bench_pool, .arrive_s = 0, .dur_s = 150, .peak_mb = 1200 },
            .{ .name = "big-ci", .pool = ci_pool, .arrive_s = 0, .dur_s = 150, .peak_mb = 1200 },
            .{ .name = "mid-prod", .pool = prod_pool, .arrive_s = 0, .dur_s = 150, .peak_mb = 600 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 0, .dur_s = 10, .peak_mb = 100 },
        };
        try warmUp(arena, &jobs, &learned);
        const steps = [_]Job{
            .{ .name = "big", .pool = bench_pool, .arrive_s = 0, .dur_s = 150, .peak_mb = 1680 },
            .{ .name = "big", .pool = bench_pool, .arrive_s = 2, .dur_s = 150, .peak_mb = 1680 },
            .{ .name = "big-ci", .pool = ci_pool, .arrive_s = 4, .dur_s = 150, .peak_mb = 1680 },
            .{ .name = "mid-prod", .pool = prod_pool, .arrive_s = 6, .dur_s = 150, .peak_mb = 840 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 8, .dur_s = 10, .peak_mb = 100 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 30, .dur_s = 10, .peak_mb = 100 },
        };
        try tail(arena, &jobs, &steps);
        try list.append(arena, .{ .name = "B-peak-40pct-over", .jobs = jobs.items, .kill = true });
    }

    // C: a job killed for memory and rerun. Learned at 1200, the real peak is 2900 this time, on
    // three runners at once; the kernel kills the largest when the machine runs out.
    {
        var jobs: std.ArrayList(Job) = .empty;
        const learned = [_]Job{
            .{ .name = "heavy", .pool = bench_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 1200 },
            .{ .name = "heavy-ci", .pool = ci_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 1200 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 0, .dur_s = 10, .peak_mb = 100 },
        };
        try warmUp(arena, &jobs, &learned);
        const steps = [_]Job{
            .{ .name = "heavy", .pool = bench_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 2900, .reruns = 2 },
            .{ .name = "heavy", .pool = bench_pool, .arrive_s = 1, .dur_s = 120, .peak_mb = 2900, .reruns = 2 },
            .{ .name = "heavy-ci", .pool = ci_pool, .arrive_s = 2, .dur_s = 120, .peak_mb = 2900, .reruns = 2 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 8, .dur_s = 10, .peak_mb = 100 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 60, .dur_s = 10, .peak_mb = 100 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 120, .dur_s = 10, .peak_mb = 100 },
        };
        try tail(arena, &jobs, &steps);
        try list.append(arena, .{ .name = "C-kill-and-rerun", .jobs = jobs.items, .kill = true });
    }

    // C2: the same on one pool (bench) alone: the kill and its rerun are in one gate's sight, so
    // the raise after a kill and the cooldown can act. Real 2900 against 1200 learned, two runners
    // of the same name beside a third of another, and small jobs about.
    {
        var jobs: std.ArrayList(Job) = .empty;
        const learned = [_]Job{
            .{ .name = "heavy", .pool = bench_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 1200 },
            .{ .name = "heavy2", .pool = bench_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 1200 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 0, .dur_s = 10, .peak_mb = 100 },
        };
        try warmUp(arena, &jobs, &learned);
        const steps = [_]Job{
            .{ .name = "heavy", .pool = bench_pool, .arrive_s = 0, .dur_s = 120, .peak_mb = 2900, .reruns = 3 },
            .{ .name = "heavy", .pool = bench_pool, .arrive_s = 1, .dur_s = 120, .peak_mb = 2900, .reruns = 3 },
            .{ .name = "heavy2", .pool = bench_pool, .arrive_s = 2, .dur_s = 120, .peak_mb = 2900, .reruns = 3 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 8, .dur_s = 10, .peak_mb = 100 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 60, .dur_s = 10, .peak_mb = 100 },
            .{ .name = "small", .pool = bench_pool, .arrive_s = 120, .dur_s = 10, .peak_mb = 100 },
        };
        try tail(arena, &jobs, &steps);
        try list.append(arena, .{ .name = "C2-kill-one-pool", .jobs = jobs.items, .kill = true });
    }

    // D: a long-tail mix, three pools, an hour: 14 names with log-normal sizes (median 300 MB,
    // a few over 2 GB), each run varying by +-25% around its name's size.
    {
        var prng = std.Random.DefaultPrng.init(0x5eed);
        const rnd = prng.random();
        var jobs: std.ArrayList(Job) = .empty;
        var specs: std.ArrayList(Job) = .empty;
        for (0..14) |i| {
            const size = std.math.clamp(300.0 * @exp(1.1 * rnd.floatNorm(f64)), 64.0, 3000.0);
            const dur = std.math.clamp(60.0 * @exp(0.9 * rnd.floatNorm(f64)), 5.0, 400.0);
            try specs.append(arena, .{
                .name = try std.fmt.allocPrint(arena, "job-{d}", .{i}),
                .pool = @intCast(i % 3),
                .arrive_s = 0,
                .dur_s = @intFromFloat(dur),
                .peak_mb = @intFromFloat(size),
            });
        }
        try warmUp(arena, &jobs, specs.items);
        var t: f64 = 0;
        while (t < 3600) {
            t += -@log(1.0 - rnd.float(f64)) * 40.0;
            var j = specs.items[rnd.uintLessThan(usize, specs.items.len)];
            const var_pct = 0.75 + 0.5 * rnd.float(f64);
            j.peak_mb = @intFromFloat(@as(f64, @floatFromInt(j.peak_mb)) * var_pct);
            j.arrive_s = @intFromFloat(t);
            try jobs.append(arena, j);
        }
        try list.append(arena, .{ .name = "D-long-tail", .jobs = jobs.items, .kill = true });
    }
    return list.items;
}

test "replay: variants over the scenarios" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const scenarios = try buildScenarios(arena_state.allocator());
    for (scenarios) |sc| {
        const r = try run(sc.jobs, .{ .kill = sc.kill, .shared = false });
        report(sc.name, "default", r);
        if (has_budget) {
            const rs = try run(sc.jobs, .{ .kill = sc.kill, .shared = true });
            report(sc.name, "shared=on", rs);
        }
    }
}

test "replay: trace A" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const scenarios = try buildScenarios(arena_state.allocator());
    for (scenarios) |sc| {
        if (!std.mem.startsWith(u8, sc.name, "A-") and !std.mem.startsWith(u8, sc.name, "T+") and !std.mem.startsWith(u8, sc.name, "B-") and !std.mem.startsWith(u8, sc.name, "C-")) continue;
        std.debug.print("SCEN {s}\n", .{sc.name});
        std.debug.print("TRACE {s} shared=false\n", .{variantName()});
        _ = try run(sc.jobs, .{ .kill = sc.kill, .trace = true });
        if (has_budget) {
            std.debug.print("TRACE {s} shared=true\n", .{variantName()});
            _ = try run(sc.jobs, .{ .kill = sc.kill, .shared = true, .trace = true });
        }
    }
}

test "replay: margin sweep" {
    if (!has_margin) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const scenarios = try buildScenarios(arena_state.allocator());
    for (scenarios) |sc| for ([_]u32{ 0, 5, 10, 15 }) |m| {
        const r = try run(sc.jobs, .{ .kill = sc.kill, .margin = m, .shared = has_budget });
        var lab: [32]u8 = undefined;
        report(sc.name, std.fmt.bufPrint(&lab, "margin={d}", .{m}) catch "margin", r);
    };
}
