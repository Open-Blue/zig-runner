//! Admission control (#126): a runner takes a new job only while the machine has the memory for
//! it. Four `zig build test` jobs taken at once on razorbill (a Raspberry Pi 5 with 8 GB, and 2 GB
//! of swap on an SD card) pushed the Dagger engine to its 4 GB cap and into swap, and the Pi
//! thrashed for hours. This is a soft gate: it decides whether to ask for the next job, and never
//! touches a job that is running.
//!
//! Three signals, each read from a file whose absence (another OS, a kernel without PSI) means
//! "no signal" rather than "hold":
//! - `MemAvailable` (/proc/meminfo), less a reservation for every job that may not show in it yet:
//!   one for each runner of the pool that is polling (it can be handed a job at any moment), one
//!   for each job started in the last `ramp_ms`, and one for the runner asking. Without the
//!   reservations, four idle runners all pass the check and are all handed a job in the same
//!   second, which is what happened.
//! - memory pressure (PSI, /proc/pressure/memory, `some avg10`): the share of the last 10 s in
//!   which some task waited on memory, reclaiming or reading back from swap. It sees what
//!   `MemAvailable` cannot: the engine's own cgroup swapping at its cap while the host still has
//!   memory to spare.
//! - swap growth (`SwapTotal - SwapFree`, as a rate): a machine writing to swap fast, for kernels
//!   without PSI. Swap in use is not a signal: pages stay there long after the burst that put them
//!   there, so it would hold a runner for days after one incident.
//!
//! `/proc/meminfo` and `/proc/pressure` are not namespaced: in a container they describe the whole
//! machine, which is what the gate needs, since the engine runs in a container next to the runner.
//!
//! The machine is not the only limit: the engine's container has its own memory cap (`Engine`).
//! Where the gate can find the engine's cgroup, it holds on that too, by the same reservations.
//!
//! A reservation is not the same for every job (#144). On razorbill a `zig build test` job raises
//! the engine's working set by about 1.6 GB within 45 s of starting, a uv job by 0.3 GB, and a flat
//! reservation held the next runner back for either as if it were the heavier. A runner cannot know
//! which job it will be handed, so a runner polling, or asking, reserves the worst case; once its
//! job is known (`Gate.assigned`), the job reserves what jobs of its name were seen to take
//! (`Learned`), measured from the engine's working set while they ran (`Admission.sample`).
const std = @import("std");
const builtin = @import("builtin");

/// The thresholds (`RUNNER_MIN_MEM_AVAILABLE_MB` and the rest, see deploy/runner.env.example). 0
/// turns a check off.
pub const Limits = struct {
    /// `MemAvailable` that must be left once every job that may start has its `per_job_mb`.
    min_available_mb: u32 = 1536,
    /// Memory to reserve for a job that does not show in `MemAvailable` yet, and the least
    /// reserved for one whose name is not known yet (`Admission.unknown`). A job whose name has
    /// been seen reserves what it took instead (`Learned`).
    per_job_mb: u32 = 1024,
    /// PSI `some avg10`, in percent, at or above which no runner takes a job.
    max_pressure: u32 = 10,
    /// Swap growth, in MB a minute, at or above which no runner takes a job: the machine's, and
    /// the engine cgroup's.
    max_swap_growth_mb: u32 = 64,
    /// Room that must be left under the engine's memory cap once every job that may start has its
    /// `per_job_mb` (`Engine`).
    min_engine_headroom_mb: u32 = 256,
};

/// Where the signals are read; tests point these at fixtures.
pub const Paths = struct {
    meminfo: []const u8 = "/proc/meminfo",
    pressure: []const u8 = "/proc/pressure/memory",
    /// Where the cgroup v2 hierarchy is mounted: the paths in `/proc/<pid>/cgroup` are under it.
    cgroup_root: []const u8 = "/sys/fs/cgroup",
};

/// How long a job's memory takes to show in `MemAvailable`: `zig build test` reached the engine's
/// cap about 90 s after four started at once on razorbill.
pub const ramp_ms = 120 * std.time.ms_per_s;

/// Once held, a runner resumes only with this much more memory than it needed to be let through,
/// and with pressure and swap growth under half their limits, so that a machine sitting at a
/// threshold does not hold and resume runners on alternate checks.
pub const resume_margin_mb = 256;

/// The pool's shared view of memory: one per process, used by every runner's `Gate`.
pub const Admission = struct {
    mu: std.Io.Mutex = .init,
    io: std.Io,
    limits: Limits,
    paths: Paths = .{},
    /// How often a held runner looks again.
    recheck: std.Io.Duration = .fromSeconds(5),
    /// Runners let through to poll for a job: each may be handed one at any moment.
    polling: u32 = 0,
    /// Each runner's job, one entry per runner (`Gate.slot`): a runner runs one job at a time.
    slots: []Slot,
    /// What jobs took, by name. In memory only: a restart forgets it, and jobs reserve the worst
    /// case again until each has run once.
    learned: Learned = .{},
    swap: SwapGrowth = .{},
    engine: Engine = .{},

    /// One runner's job. Cleared when the job ends, so a job that is over reserves nothing,
    /// however soon it ended.
    pub const Slot = struct {
        /// When the job started (awake clock, ms).
        started_ms: i64 = std.math.minInt(i64),
        /// What the job reserves while it ramps up, in MB; null while its name is not known, for
        /// the worst case (`unknown`), whatever that has become since.
        est_mb: ?u32 = null,
        /// The job's identity (`jobKey`), once known.
        key: ?u64 = null,
        /// The engine's working set when the job's name became known, and the most it has been
        /// since, in MB: null without an engine signal, and nothing is learned from the job.
        base_mb: ?u64 = null,
        peak_mb: u64 = 0,
        /// A step was replayed from the step cache: not learned from (`Learned`).
        replayed: bool = false,
        /// Another runner's job ran at some point during this one: its peak is the engine's for
        /// both, an upper bound on its own (`Learned`).
        overlapped: bool = false,
        /// The job runs on the native backend (`Gate.native`): measured in its own cgroup, whose
        /// path is in `cgroup_buf` while it is there, from nothing, so never beside another job;
        /// and it takes nothing of the engine's cap.
        native: bool = false,
        cgroup_buf: [256]u8 = @splat(0),
        cgroup_len: usize = 0,

        fn cgroup(s: *const Slot) ?[]const u8 {
            return if (s.cgroup_len > 0) s.cgroup_buf[0..s.cgroup_len] else null;
        }
    };

    /// `slots` must have one entry for each runner in the pool, plus one for the pool's pre-warm
    /// (`loop.Warmer`), which is a job to the gate, and each `Gate.slot` a different index into it.
    pub fn init(io: std.Io, limits: Limits, slots: []Slot) Admission {
        @memset(slots, .{});
        return .{ .io = io, .limits = limits, .slots = slots };
    }

    /// What a job whose name is not known yet reserves: the configured `per_job_mb`, or the most
    /// any known job took if that is more, so that a job heavier than configured raises it. 0
    /// (`per_job_mb` off) reserves nothing, learned or not.
    fn unknown(a: *const Admission) u32 {
        if (a.limits.per_job_mb == 0) return 0;
        return @max(a.limits.per_job_mb, a.learned.largest());
    }

    /// What may start without showing in the machine's or the engine's memory yet: a worst case
    /// for each of `polling` runners that may be handed a job, and each job started less than
    /// `ramp_ms` ago with its own estimate.
    fn reserved(a: *const Admission, now_ms: i64, polling: u32) Reservation {
        const unknown_mb = a.unknown();
        var r: Reservation = .{ .jobs = polling };
        r.mb = @as(u64, r.jobs) * unknown_mb;
        for (a.slots) |s| if (s.started_ms > now_ms - ramp_ms) {
            r.jobs += 1;
            r.mb += s.est_mb orelse unknown_mb;
            if (s.native) r.native_mb += s.est_mb orelse unknown_mb;
        };
        return r;
    }

    /// Raises the peak of every job running, once a second, from the engine's working set, until
    /// cancelled with the pool. It reads nothing while no job is being measured.
    pub fn sample(a: *Admission) void {
        while (true) {
            a.io.sleep(.fromSeconds(1), .awake) catch return;
            a.samplePeaks();
        }
    }

    /// A Dagger job's peak is the engine's, not its own: the engine is one cgroup for every job,
    /// so a job that overlaps another is charged for both (`Slot.overlapped`). A native job's is
    /// its own cgroup's (`Gate.native`). The engine is read once, and only for a job measured
    /// there.
    fn samplePeaks(a: *Admission) void {
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        var engine: ?EngineMemory = null;
        var engine_read = false;
        for (a.slots) |*s| {
            if (s.base_mb == null) continue;
            if (s.native) {
                if (s.cgroup()) |dir| if (workingSetMb(a.io, dir)) |mb| {
                    s.peak_mb = @max(s.peak_mb, mb);
                };
                continue;
            }
            if (!engine_read) {
                engine_read = true;
                if (a.engine.dir) |dir| engine = readEngine(a.io, dir);
            }
            if (engine) |e| s.peak_mb = @max(s.peak_mb, e.used_mb);
        }
    }

    /// How often the engine started again since the runner did (`Engine.returns`), or null while
    /// its cgroup has never been found and the gate cannot tell (the runner in a container of its
    /// own, as in deploy/compose.yaml).
    pub fn engineReturns(a: *Admission) ?u32 {
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        return if (a.engine.seen) a.engine.returns else null;
    }

    /// What the gate has learned about the engine's cgroup since this was last asked (found, or
    /// not found and why), written into `buf`; null if nothing new. Each change is told once, to
    /// whichever runner asks first.
    pub fn engineNews(a: *Admission, buf: []u8) ?[]const u8 {
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const e = &a.engine;
        if (e.told) return null;
        e.told = true;
        return switch (e.outcome) {
            .found => |cap_mb| std.fmt.bufPrint(
                buf,
                "the engine's cgroup is {s}, capped at {f}: the memory gate holds on it too",
                .{ e.dir.?, gb(cap_mb) },
            ),
            .missing => |err| std.fmt.bufPrint(
                buf,
                "the engine's cgroup was not found ({s}): the memory gate sees the machine's " ++
                    "memory only, and looks again every {d} s",
                .{ @errorName(err), Engine.retry_ms / std.time.ms_per_s },
            ),
        } catch null;
    }
};

/// One runner's place at the gate. The runner is counted in `Admission.polling` from the check that
/// lets it through until it leaves: when it takes a job, or its cycle ends.
pub const Gate = struct {
    pool: *Admission,
    /// This runner's entry in `pool.slots`.
    slot: usize = 0,
    /// Counted in `pool.polling`.
    claimed: bool = false,
    /// Held at the last check: the resume thresholds apply.
    holding: bool = false,
    /// The hold was logged, so its end is logged too, once each.
    announced: bool = false,
    /// The pool's pre-warm (`loop.Warmer`), not a runner: it is never counted as polling, and it
    /// reserves against the jobs that run, not the runners polling. A pool is sized so that its
    /// idle pollers' worst cases fill the gate (16 on the laptop: 17 GB of 18), so against them
    /// it waited for ever, and precisely while the machine was idle. A job a poller is handed
    /// while the warm runs still counts the warm (`leave`).
    warm: bool = false,

    /// Null when the runner may poll for a job (and it is then counted as polling); otherwise why
    /// not. For the pre-warm (`warm`): whether it may start now.
    pub fn check(g: *Gate) ?Hold {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const now_ms = std.Io.Clock.awake.now(a.io).toMilliseconds();
        if (a.engine.dir == null) a.engine.find(a.io, a.paths, now_ms);
        const sample = read(a.io, a.paths, a.engine.dir);
        // Its files are gone: the engine's container was recreated, under a new cgroup. The jobs
        // running are not measured further: the new engine's working set is not theirs.
        if (a.engine.dir != null and sample.engine == null) {
            a.engine.lost();
            for (a.slots) |*s| if (!s.native) {
                s.base_mb = null;
            };
        }
        const swap_rate = if (sample.swap_used_mb) |u| a.swap.update(u, now_ms) else null;
        const engine_swap_rate = if (sample.engine_swap_mb) |u|
            a.engine.swap.update(u, now_ms)
        else
            null;
        // A runner asks beside every runner polling; the warm asks for itself alone.
        const asking = if (g.warm) 1 else a.polling + @intFromBool(!g.claimed);
        const hold = decide(a.limits, .{
            .available_mb = sample.available_mb,
            .pressure = sample.pressure,
            .swap_growth_mb = swap_rate,
            .engine = sample.engine,
            .engine_swap_growth_mb = engine_swap_rate,
        }, a.reserved(now_ms, asking), g.holding);
        g.holding = hold != null;
        if (g.warm) return hold;
        if (hold == null and !g.claimed) a.polling += 1;
        if (hold != null and g.claimed) a.polling -= 1;
        g.claimed = hold == null;
        return hold;
    }

    /// The runner stops polling; `took_job` when because it was handed a job, whose memory is then
    /// reserved for `ramp_ms`, or until the job ends (`ended`) if that is sooner: the worst case
    /// until its name is known (`assigned`).
    pub fn leave(g: *Gate, took_job: bool) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        if (g.claimed) a.polling -= 1;
        g.claimed = false;
        if (!took_job) return;
        // Two jobs overlap exactly when one starts while the other runs, so marking both here
        // catches every overlap, however briefly the jobs shared the engine.
        var overlapped = false;
        for (a.slots, 0..) |*s, i| if (i != g.slot and s.started_ms != std.math.minInt(i64)) {
            s.overlapped = true;
            overlapped = true;
        };
        a.slots[g.slot] = .{
            .started_ms = std.Io.Clock.awake.now(a.io).toMilliseconds(),
            .overlapped = overlapped,
        };
    }

    /// The runner's job is known as `key` (`jobKey`): it reserves what jobs of that name took, or
    /// the worst case for a name not seen yet, and is measured from here (`Admission.sample`).
    pub fn assigned(g: *Gate, key: u64) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = &a.slots[g.slot];
        std.debug.assert(s.started_ms != std.math.minInt(i64));
        s.key = key;
        if (a.limits.per_job_mb > 0) s.est_mb = a.learned.estimate(key);
        // Without the engine's cgroup (another OS, `RUNNER_ENGINE_CGROUP=none`) nothing is
        // measured, nothing learned, and every job reserves `per_job_mb`.
        const dir = a.engine.dir orelse return;
        const e = readEngine(a.io, dir) orelse return;
        s.base_mb = e.used_mb;
        s.peak_mb = e.used_mb;
    }

    /// The runner's job runs on the native backend, in the cgroup `dir` (`native/cgroup.zig`), or
    /// in none (null). It is measured in its cgroup, from nothing (the cgroup is new), instead of
    /// from the engine's working set, where it takes nothing; so it is never measured beside
    /// another job, and it does not count against the engine's cap. Without a cgroup it is not
    /// measured, as a job without an engine signal is not. A job the gate was not told of
    /// (`leave`) is left alone.
    pub fn native(g: *Gate, dir: ?[]const u8) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = &a.slots[g.slot];
        if (s.started_ms == std.math.minInt(i64)) return;
        s.native = true;
        s.cgroup_len = 0;
        s.base_mb = null;
        const d = dir orelse return;
        if (d.len > s.cgroup_buf.len) return;
        @memcpy(s.cgroup_buf[0..d.len], d);
        s.cgroup_len = d.len;
        s.base_mb = 0;
        s.peak_mb = workingSetMb(a.io, d) orelse 0;
    }

    /// The runner's native job's cgroup is about to be removed: read a last time, then no more.
    /// The job went to the Dagger engine after `native` (a native set-up that found it cannot
    /// run there): it takes the engine's cap again, and with no engine baseline nothing is learned
    /// from it, rather than its native cgroup's few MB.
    pub fn backToEngine(g: *Gate) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = &a.slots[g.slot];
        s.native = false;
        s.cgroup_len = 0;
        s.base_mb = null;
    }

    pub fn nativeDone(g: *Gate) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = &a.slots[g.slot];
        if (s.cgroup()) |dir| if (workingSetMb(a.io, dir)) |mb| {
            s.peak_mb = @max(s.peak_mb, mb);
        };
        s.cgroup_len = 0;
    }

    /// The runner's job replayed a step from the step cache: what it took is not learned.
    pub fn replayed(g: *Gate) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        a.slots[g.slot].replayed = true;
    }

    /// The runner's job is over: its memory is no longer reserved. Without this a job reserved its
    /// memory for the whole `ramp_ms` however short it was, so a burst of short jobs went through
    /// at most (available - floor) / per-job every two minutes: 1.5 jobs a minute on razorbill.
    /// What the job was seen to take is learned for its name, and returned when that changed what
    /// its name reserves, for the log. Null for a job not measured, or already ended.
    pub fn ended(g: *Gate) ?Learned.Change {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = a.slots[g.slot];
        a.slots[g.slot] = .{};
        if (s.replayed) return null;
        const key = s.key orelse return null;
        const base = s.base_mb orelse return null;
        // At most 1 TB, so that it fits the table's u32 and sums of them cannot overflow.
        const seen_mb: u32 = @intCast(@min(@max(s.peak_mb -| base, Learned.min_mb), 1 << 20));
        const before = a.learned.estimate(key);
        const alone = !s.overlapped or s.native;
        const after = a.learned.record(key, seen_mb, alone);
        if (before == after) return null;
        return .{ .seen_mb = seen_mb, .estimate_mb = after, .alone = alone };
    }
};

/// What jobs took, by name (`jobKey`): the engine's working set at its highest while each ran, less
/// what it was when the job's name became known. Fixed in size: the name least recently used makes
/// room for a new one. A job that replayed any step from the step cache is not learned from: it
/// ran little of its work and took far less than its next real run will, and re-runs of one commit
/// after a restart would otherwise teach an estimate that under-reserves the run that matters.
///
/// A run that shared the engine with another job (`Slot.overlapped`) measured both: an upper
/// bound on its own peak, not the peak. On razorbill the first `zig build test` runs overlapped
/// another and were learned at 2.9 and 3.1 GB, against 1.6 GB alone; kept as peaks, they doubled
/// zig's estimate and the worst case with it, and held runners for memory no job needed. So runs
/// alone and runs beside others are kept apart: a name reserves the most of its recent runs alone,
/// and only while it has none, the least of its recent runs beside others, still an upper bound.
pub const Learned = struct {
    entries: [capacity]Entry = undefined,
    len: usize = 0,
    /// Counts uses, so that the entry least recently used has the smallest `used`.
    tick: u64 = 0,

    pub const capacity = 64;
    /// A job reserves the most it took in its last `kept` runs alone: a job that varies with what
    /// it is given (a cache missed, a larger change) is reserved for its heavier runs.
    pub const kept = 5;
    /// The least a job is seen to take: one that ran while another job freed memory can measure 0.
    pub const min_mb = 64;

    const Entry = struct {
        key: u64,
        alone: Runs = .{},
        beside: Runs = .{},
        used: u64 = 0,

        fn estimate(e: *const Entry) u32 {
            if (e.alone.n > 0) return std.mem.max(u32, e.alone.slice());
            return std.mem.min(u32, e.beside.slice());
        }
    };

    /// The last `kept` runs' MB, oldest overwritten first.
    const Runs = struct {
        mb: [kept]u32 = undefined,
        /// Runs in `mb`, up to `kept`, and where the next one goes.
        n: u8 = 0,
        next: u8 = 0,

        fn slice(r: *const Runs) []const u32 {
            return r.mb[0..r.n];
        }
    };

    /// A job's end that changed what its name reserves: what it took, whether it ran alone, and
    /// what is now reserved.
    pub const Change = struct { seen_mb: u32, estimate_mb: u32, alone: bool };

    /// What a job of this name reserves, or null for a name not seen.
    fn estimate(l: *Learned, key: u64) ?u32 {
        const e = l.find(key) orelse return null;
        l.tick += 1;
        e.used = l.tick;
        return e.estimate();
    }

    /// A run of `key` that took `seen_mb`, `alone` or beside other jobs; returns what its name now
    /// reserves.
    fn record(l: *Learned, key: u64, seen_mb: u32, alone: bool) u32 {
        const e = l.find(key) orelse e: {
            if (l.len < capacity) {
                l.len += 1;
            } else {
                var lru: usize = 0;
                for (l.entries, 0..) |x, i| if (x.used < l.entries[lru].used) {
                    lru = i;
                };
                // The last slot is the one reused: swapped in, so `entries[0..len]` stays whole.
                std.mem.swap(Entry, &l.entries[lru], &l.entries[capacity - 1]);
            }
            l.entries[l.len - 1] = .{ .key = key };
            break :e &l.entries[l.len - 1];
        };
        const runs = if (alone) &e.alone else &e.beside;
        runs.mb[runs.next] = seen_mb;
        runs.next = (runs.next + 1) % kept;
        runs.n = @min(runs.n + 1, kept);
        l.tick += 1;
        e.used = l.tick;
        return e.estimate();
    }

    /// The most any known name reserves; 0 with none known.
    fn largest(l: *const Learned) u32 {
        var most: u32 = 0;
        for (l.entries[0..l.len]) |*e| most = @max(most, e.estimate());
        return most;
    }

    fn find(l: *Learned, key: u64) ?*Entry {
        for (l.entries[0..l.len]) |*e| if (e.key == key) return e;
        return null;
    }
};

/// A job's identity across runs: its repository, its workflow file without the ref (a branch's
/// runs and main's are one job), and its name as GitHub shows it, a matrix leg's included.
pub fn jobKey(repository: []const u8, workflow_ref: []const u8, name: []const u8) u64 {
    const at = std.mem.lastIndexOfScalar(u8, workflow_ref, '@') orelse workflow_ref.len;
    var h: std.hash.Wyhash = .init(0);
    // Each ended by a 0 byte, so that no two different triples hash the same bytes.
    for ([_][]const u8{ repository, workflow_ref[0..at], name }) |part| {
        h.update(part);
        h.update(&.{0});
    }
    return h.final();
}

/// What may start without showing in memory yet: how many jobs, and what they reserve together;
/// `native_mb` of it for native jobs, which do not run in the engine (`Gate.native`).
pub const Reservation = struct { jobs: u32, mb: u64 = 0, native_mb: u64 = 0 };

/// Why a runner may not take a job, for the log.
pub const Hold = union(enum) {
    memory: struct { available_mb: u64, reserved: Reservation, floor_mb: u32 },
    /// Hundredths of a percent.
    pressure: struct { now: u32, limit: u32 },
    /// MB a minute.
    swap: struct { now: u64, limit: u32 },
    engine: struct { used_mb: u64, cap_mb: u64, reserved: Reservation, floor_mb: u32 },
    /// MB a minute.
    engine_swap: struct { now: u64, limit: u32 },

    pub fn format(h: Hold, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (h) {
            .memory => |m| try w.print(
                "{d} MB of memory available; {d} job(s) needing {f} would leave under {d} MB",
                .{ m.available_mb, m.reserved.jobs, gb(m.reserved.mb), m.floor_mb },
            ),
            .engine => |e| try w.print(
                "engine {f} of {f} in use; {d} job(s) needing {f} would leave under {d} MB of " ++
                    "its cap",
                .{ gb(e.used_mb), gb(e.cap_mb), e.reserved.jobs, gb(e.reserved.mb), e.floor_mb },
            ),
            .engine_swap => |s| try w.print(
                "engine swapping {d} MB/min (its cgroup's memory.swap.current), limit {d} MB/min",
                .{ s.now, s.limit },
            ),
            .pressure => |p| try w.print(
                "memory pressure {d}.{d:0>2}% (PSI some avg10), limit {d}%",
                .{ p.now / 100, p.now % 100, p.limit },
            ),
            .swap => |s| try w.print("swap growing {d} MB/min, limit {d} MB/min", .{
                s.now,
                s.limit,
            }),
        }
    }
};

/// MB as GB with one decimal, for the log: "3.6 GB".
pub fn gb(mb: u64) Gb {
    return .{ .tenths = mb * 10 / 1024 };
}

const Gb = struct {
    tenths: u64,

    pub fn format(g: Gb, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{d}.{d} GB", .{ g.tenths / 10, g.tenths % 10 });
    }
};

/// What the decision reads; null is "no signal".
pub const Signals = struct {
    available_mb: ?u64 = null,
    /// PSI `some avg10`, in hundredths of a percent.
    pressure: ?u32 = null,
    swap_growth_mb: ?u64 = null,
    engine: ?EngineMemory = null,
    engine_swap_growth_mb: ?u64 = null,
};

/// Whether one more job may be taken when the jobs `reserved` (this one included) may start
/// without showing in `available_mb` yet: null if so. `holding` applies the resume thresholds
/// instead (`resume_margin_mb`, half the pressure and swap limits).
pub fn decide(limits: Limits, s: Signals, reserved: Reservation, holding: bool) ?Hold {
    if (s.available_mb) |avail| {
        const margin: u64 = if (holding) resume_margin_mb else 0;
        const needed = limits.min_available_mb + reserved.mb;
        if (needed > 0 and avail < needed + margin) return .{ .memory = .{
            .available_mb = avail,
            .reserved = reserved,
            .floor_mb = limits.min_available_mb,
        } };
    }
    // The same reservations against the engine's cap, but native jobs': every other job taken
    // runs in the engine.
    if (s.engine) |e| {
        const margin: u64 = if (holding) resume_margin_mb else 0;
        const needed = limits.min_engine_headroom_mb + (reserved.mb -| reserved.native_mb);
        if (needed > 0 and e.cap_mb -| e.used_mb < needed + margin) return .{ .engine = .{
            .used_mb = e.used_mb,
            .cap_mb = e.cap_mb,
            .reserved = reserved,
            .floor_mb = limits.min_engine_headroom_mb,
        } };
    }
    if (s.pressure) |p| if (limits.max_pressure > 0) {
        const limit = limits.max_pressure * 100;
        if (p >= if (holding) limit / 2 else limit)
            return .{ .pressure = .{ .now = p, .limit = limits.max_pressure } };
    };
    if (s.swap_growth_mb) |g| if (limits.max_swap_growth_mb > 0) {
        const limit = limits.max_swap_growth_mb;
        if (g >= if (holding) limit / 2 else limit)
            return .{ .swap = .{ .now = g, .limit = limit } };
    };
    if (s.engine_swap_growth_mb) |g| if (limits.max_swap_growth_mb > 0) {
        const limit = limits.max_swap_growth_mb;
        if (g >= if (holding) limit / 2 else limit)
            return .{ .engine_swap = .{ .now = g, .limit = limit } };
    };
    return null;
}

/// Swap growth as a rate over at least `window_ms`. Runners check at irregular times (before each
/// poll, about every 50 s, and every `Admission.recheck` while held), so the rate is measured
/// against a baseline at least that old, and kept between measurements.
pub const SwapGrowth = struct {
    base: ?struct { used_mb: u64, at_ms: i64 } = null,
    rate: ?u64 = null,

    pub const window_ms = 10 * std.time.ms_per_s;

    /// MB a minute, or null before there are two samples far enough apart. Swap that shrank is 0.
    pub fn update(s: *SwapGrowth, used_mb: u64, now_ms: i64) ?u64 {
        const base = s.base orelse {
            s.base = .{ .used_mb = used_mb, .at_ms = now_ms };
            return null;
        };
        const elapsed = now_ms - base.at_ms;
        if (elapsed < window_ms) return s.rate;
        s.rate = (used_mb -| base.used_mb) * std.time.ms_per_min / @as(u64, @intCast(elapsed));
        s.base = .{ .used_mb = used_mb, .at_ms = now_ms };
        return s.rate;
    }
};

/// The signals as the files give them now.
pub const Sample = struct {
    available_mb: ?u64 = null,
    swap_used_mb: ?u64 = null,
    /// PSI `some avg10`, in hundredths of a percent.
    pressure: ?u32 = null,
    engine: ?EngineMemory = null,
    engine_swap_mb: ?u64 = null,
};

/// Reads the machine's files, and those of the engine's cgroup `engine_dir`; one that cannot be
/// read, or reads as something else, gives no signal.
pub fn read(io: std.Io, paths: Paths, engine_dir: ?[]const u8) Sample {
    var s: Sample = .{};
    // /proc/meminfo is about 1.5 KB; the fields read are near the top.
    var mem_buf: [4096]u8 = undefined;
    if (std.Io.Dir.cwd().readFile(io, paths.meminfo, &mem_buf)) |text| {
        const m = parseMeminfo(text);
        s.available_mb = m.available_mb;
        s.swap_used_mb = m.swap_used_mb;
    } else |_| {}
    var psi_buf: [256]u8 = undefined;
    // PSI compiled in but off (`psi=0`) fails the read with EOPNOTSUPP: no signal either.
    if (std.Io.Dir.cwd().readFile(io, paths.pressure, &psi_buf)) |text| {
        s.pressure = parsePressure(text);
    } else |_| {}
    if (engine_dir) |dir| if (readEngine(io, dir)) |e| {
        s.engine = e;
        // Without swap accounting (`swapaccount=0`) the file is not there: no signal.
        if (readBytes(io, dir, "memory.swap.current")) |b| s.engine_swap_mb = b >> 20;
    };
    return s;
}

/// The engine's cap, and its working set: `memory.current` less what the kernel reclaims first
/// and cheaply as the cgroup nears its cap, `inactive_file` and `slab_reclaimable`. The engine's
/// cache is file-backed and large (image layers, the step and package caches), and the reclaimable
/// slab is the dentries and inodes of the files it hashes and reads: the Zig tool cache's 19,505
/// files every job (BENCHMARKS.md), 180-270 MB on razorbill at idle, where the gate charged 1.3 GB
/// for an engine whose own heap was about 650 MB. Counting either would hold runners, and raise a
/// job's learned size (#144), for memory the engine gives up the moment a job needs it (#126).
/// Active file pages stay counted: they are being read, dropping them turns into reads from the SD
/// card, and without them two unknown 1536 MB jobs would poll at idle on razorbill, the shape of
/// #144. `MemAvailable` leaves both out the same way, so the host's signal and the engine's agree
/// about the same bytes. Dirty and writeback pages sit inside `inactive_file` and are left out
/// although the card must take them first: the gate under-charges most during provisioning's
/// apt-get (622 MB written, and the dentries of every file unpacked), a known under-charge left for
/// its own change. `docker stats` and the kubelet subtract `inactive_file` only, so on the Pi they
/// read the reclaimable slab higher than the log. A key missing from memory.stat subtracts nothing,
/// so the gate can only charge more than meant. Null unless the cap is a number and usage is
/// readable (a cap removed is no longer a limit).
fn readEngine(io: std.Io, dir: []const u8) ?EngineMemory {
    const cap = readBytes(io, dir, "memory.max") orelse return null;
    return .{ .cap_mb = cap >> 20, .used_mb = workingSetMb(io, dir) orelse return null };
}

/// A cgroup's working set in MB, as `readEngine` counts the engine's: `memory.current` less
/// `inactive_file` and `slab_reclaimable`. A native job's own cgroup is read so too
/// (`Gate.native`), so what the gate learns of a job means the same on either backend.
pub fn workingSetMb(io: std.Io, dir: []const u8) ?u64 {
    const current = readBytes(io, dir, "memory.current") orelse return null;
    // memory.stat is about 1.3 KB (cgroup v2 on Linux 7.0), both keys in its first half. A longer
    // file is cut at the buffer, and a key past the cut is a missing one.
    var stat_buf: [8192]u8 = undefined;
    const reclaimable = if (readIn(io, dir, "memory.stat", &stat_buf)) |text|
        (parseStat(text, "inactive_file") orelse 0) +|
            (parseStat(text, "slab_reclaimable") orelse 0)
    else |_|
        0;
    return (current -| reclaimable) >> 20;
}

pub const readCgroupBytes = readBytes;

/// A cgroup file that holds one number of bytes; null for "max", or one that cannot be read.
fn readBytes(io: std.Io, dir: []const u8, name: []const u8) ?u64 {
    var buf: [32]u8 = undefined;
    const text = readIn(io, dir, name, &buf) catch return null;
    return std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10) catch null;
}

fn readIn(io: std.Io, dir: []const u8, name: []const u8, buf: []u8) ![]u8 {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name });
    return std.Io.Dir.cwd().readFile(io, path, buf);
}

/// One key of a cgroup's memory.stat ("inactive_file 65536"), in bytes.
pub fn parseStat(text: []const u8, key: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len <= key.len or line[key.len] != ' ') continue;
        if (!std.mem.startsWith(u8, line, key)) continue;
        return std.fmt.parseInt(u64, line[key.len + 1 ..], 10) catch null;
    }
    return null;
}

/// The engine's memory, in MB.
pub const EngineMemory = struct { cap_mb: u64, used_mb: u64 };

/// The engine's own memory cap (#142). On razorbill the engine's container is capped at 4 GB of
/// the Pi's 8: four jobs' coinciding compiles pushed it to its cap and 1 GB into swap in 30 s,
/// while `MemAvailable` still showed 2 GB, and had shown 4.8 GB as each job was let through. The
/// machine's signals cannot see a cgroup's cap, so the gate reads the engine's cgroup too.
///
/// Found without Docker (the runner need not be in the docker group): the engine's unix socket is
/// connected to, and `SO_PEERCRED` names the process listening on it, in the runner's own PID
/// namespace. Its `/proc/<pid>/cgroup` names its cgroup, and the cap that binds is the nearest one
/// at or above it. `/proc/net/unix` cannot do this: the engine's socket is in its container's
/// network namespace, so the host's list does not show it. Where the engine's process is not
/// visible (the runner in a container of its own, as in deploy/compose.yaml), the PID comes back
/// 0, and the gate goes on with the machine's signals alone.
pub const Engine = struct {
    source: Source = .off,
    /// The cgroup whose cap binds, in `dir_buf`: null until found, and again once its files cannot
    /// be read (the engine's container was recreated, under a new cgroup).
    dir: ?[]const u8 = null,
    dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined,
    /// When `find` last failed (awake clock, ms): it is tried again `retry_ms` later. At boot the
    /// runner can start before Docker has started the engine.
    failed_ms: ?i64 = null,
    swap: SwapGrowth = .{},
    /// What `find` last concluded, told once (`Admission.engineNews`).
    outcome: union(enum) { found: u64, missing: anyerror } = .{ .missing = error.NotLookedFor },
    told: bool = true,
    /// Found at least once: the runner can see the engine's process.
    seen: bool = false,
    /// How often it was found after it was looked for and not found, or lost: each is an engine
    /// that started (`loop.Warmer` pre-warms it again). Its first finding at startup is not one.
    returns: u32 = 0,

    pub const retry_ms = 60 * std.time.ms_per_s;

    /// Where the engine's cgroup is found (`RUNNER_ENGINE_CGROUP`, `RUNNER_ENGINE_HOST`).
    pub const Source = union(enum) {
        /// No engine signal, and nothing logged about it.
        off,
        /// A cgroup directory, given.
        cgroup: []const u8,
        /// The engine's address: a `unix://` one is followed to its listener's cgroup.
        host: []const u8,
    };

    fn find(e: *Engine, io: std.Io, paths: Paths, now_ms: i64) void {
        if (e.source == .off) return;
        if (e.failed_ms) |t| if (now_ms - t < retry_ms) return;
        if (locate(io, paths, e.source, &e.dir_buf)) |dir| {
            if (e.outcome == .missing and e.outcome.missing != error.NotLookedFor) e.returns += 1;
            e.seen = true;
            e.dir = dir;
            e.failed_ms = null;
            e.swap = .{};
            e.outcome = .{ .found = (readBytes(io, dir, "memory.max") orelse 0) >> 20 };
            e.told = false;
        } else |err| {
            e.failed_ms = now_ms;
            // Logged once, not at every minute's look.
            if (e.outcome == .missing and e.outcome.missing == err) return;
            e.outcome = .{ .missing = err };
            e.told = false;
        }
    }

    fn lost(e: *Engine) void {
        e.dir = null;
        e.failed_ms = null;
        e.outcome = .{ .missing = error.EngineCgroupGone };
        e.told = false;
    }
};

/// The engine's cgroup directory, written into `buf`: the nearest at or above the one `source`
/// names with a memory cap.
fn locate(io: std.Io, paths: Paths, source: Engine.Source, buf: []u8) ![]const u8 {
    var start_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const start = switch (source) {
        .off => unreachable,
        .cgroup => |dir| dir,
        .host => |host| s: {
            if (!std.mem.startsWith(u8, host, "unix://")) return error.EngineHostNotUnixSocket;
            const pid = try listenerPid(io, host["unix://".len..]);
            var proc_buf: [32]u8 = undefined;
            const proc = try std.fmt.bufPrint(&proc_buf, "/proc/{d}/cgroup", .{pid});
            var text_buf: [4096]u8 = undefined;
            const text = try std.Io.Dir.cwd().readFile(io, proc, &text_buf);
            const rel = parseProcCgroup(text) orelse return error.NoCgroupV2;
            break :s try std.fmt.bufPrint(&start_buf, "{s}{s}", .{ paths.cgroup_root, rel });
        },
    };
    return cappedAncestor(io, paths.cgroup_root, start, buf);
}

/// The process listening on the unix socket at `path`, as this process's PID namespace numbers
/// it. Connecting is enough: the listener's credentials are recorded when it calls listen().
fn listenerPid(io: std.Io, path: []const u8) !i32 {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const linux = std.os.linux;
    const addr = try std.Io.net.UnixAddress.init(path);
    const stream = try addr.connect(io);
    defer stream.close(io);
    var cred: extern struct { pid: i32, uid: u32, gid: u32 } = undefined;
    var len: linux.socklen_t = @sizeOf(@TypeOf(cred));
    const rc = linux.getsockopt(
        stream.socket.handle,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&cred),
        &len,
    );
    if (linux.errno(rc) != .SUCCESS) return error.NoPeerCredentials;
    // 0: the listener is in a PID namespace this process cannot see into.
    if (cred.pid <= 0) return error.EngineProcessNotVisible;
    return cred.pid;
}

/// The cgroup v2 path in /proc/<pid>/cgroup ("0::/system.slice/docker-<id>.scope").
pub fn parseProcCgroup(text: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "0::/")) return line["0::".len..];
    }
    return null;
}

/// `start`, or the nearest cgroup above it, whose memory.max is a number, copied into `buf`. The
/// engine's own process can sit in a child of its container's cgroup, where the cap is not
/// (Docker-in-Docker style entrypoints move it into one to nest cgroups).
fn cappedAncestor(io: std.Io, root: []const u8, start: []const u8, buf: []u8) ![]const u8 {
    var dir = std.mem.trimEnd(u8, start, "/");
    var first = true;
    while (dir.len > root.len and std.mem.startsWith(u8, dir, root)) : (first = false) {
        var max_buf: [32]u8 = undefined;
        const text = readIn(io, dir, "memory.max", &max_buf) catch |err| switch (err) {
            // A cgroup given that is not there is worth saying so; past it, the root's lack.
            error.FileNotFound => if (first) return error.CgroupNotFound else break,
            else => return err,
        };
        if (std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10)) |_| {
            if (dir.len > buf.len) return error.NameTooLong;
            @memcpy(buf[0..dir.len], dir);
            return buf[0..dir.len];
        } else |_| {}
        dir = std.fs.path.dirname(dir) orelse break;
    }
    return error.NoMemoryCap;
}

/// `MemAvailable`, and swap in use, in MB.
pub fn parseMeminfo(text: []const u8) struct { available_mb: ?u64, swap_used_mb: ?u64 } {
    var available: ?u64 = null;
    var swap_total: ?u64 = null;
    var swap_free: ?u64 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = line[0..colon];
        // "MemAvailable:    5632000 kB"
        var fields = std.mem.tokenizeScalar(u8, line[colon + 1 ..], ' ');
        const kb = std.fmt.parseInt(u64, fields.next() orelse continue, 10) catch continue;
        if (std.mem.eql(u8, key, "MemAvailable")) available = kb / 1024 //
        else if (std.mem.eql(u8, key, "SwapTotal")) swap_total = kb / 1024 //
        else if (std.mem.eql(u8, key, "SwapFree")) swap_free = kb / 1024;
    }
    const swap_used = if (swap_total != null and swap_free != null)
        swap_total.? -| swap_free.?
    else
        null;
    return .{ .available_mb = available, .swap_used_mb = swap_used };
}

/// `some avg10` from /proc/pressure/memory, in hundredths of a percent ("12.34" is 1234).
pub fn parsePressure(text: []const u8) ?u32 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "some ")) continue;
        var fields = std.mem.tokenizeScalar(u8, line["some ".len..], ' ');
        while (fields.next()) |field| {
            if (!std.mem.startsWith(u8, field, "avg10=")) continue;
            return hundredths(field["avg10=".len..]);
        }
    }
    return null;
}

/// "12.34" as 1234; the kernel prints two decimals.
fn hundredths(s: []const u8) ?u32 {
    const dot = std.mem.indexOfScalar(u8, s, '.') orelse s.len;
    const whole = std.fmt.parseInt(u32, s[0..dot], 10) catch return null;
    var frac: u32 = 0;
    if (dot < s.len) {
        const digits = s[dot + 1 ..];
        if (digits.len == 0 or digits.len > 2) return null;
        frac = std.fmt.parseInt(u32, digits, 10) catch return null;
        if (digits.len == 1) frac *= 10;
    }
    return whole * 100 + frac;
}

test "MemAvailable and swap in use from /proc/meminfo" {
    // Trimmed from razorbill at idle.
    const text = "MemTotal:        8245632 kB\n" ++
        "MemFree:          921344 kB\n" ++
        "MemAvailable:    5632000 kB\n" ++
        "Buffers:           12288 kB\n" ++
        "SwapCached:         4096 kB\n" ++
        "SwapTotal:       2097148 kB\n" ++
        "SwapFree:        1048572 kB\n" ++
        "Hugepagesize:       2048 kB\n";
    const m = parseMeminfo(text);
    try std.testing.expectEqual(@as(?u64, 5500), m.available_mb);
    try std.testing.expectEqual(@as(?u64, 1024), m.swap_used_mb);

    // A kernel without swap, and text that is not meminfo.
    const no_swap = parseMeminfo("MemAvailable: 1024 kB\n");
    try std.testing.expectEqual(@as(?u64, 1), no_swap.available_mb);
    try std.testing.expectEqual(@as(?u64, null), no_swap.swap_used_mb);
    const junk = parseMeminfo("MemAvailable: lots\nnonsense\n");
    try std.testing.expectEqual(@as(?u64, null), junk.available_mb);
}

test "PSI some avg10 from /proc/pressure/memory" {
    const text = "some avg10=12.34 avg60=3.10 avg300=0.80 total=123456789\n" ++
        "full avg10=9.00 avg60=2.00 avg300=0.50 total=98765432\n";
    try std.testing.expectEqual(@as(?u32, 1234), parsePressure(text));
    try std.testing.expectEqual(@as(?u32, 0), parsePressure(
        "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    ));
    try std.testing.expectEqual(@as(?u32, 10000), parsePressure("some avg10=100.00 total=1\n"));
    try std.testing.expectEqual(@as(?u32, 50), parsePressure("some avg10=0.5\n"));
    // Only `full` (not a format the kernel writes), or nothing readable: no signal.
    try std.testing.expectEqual(@as(?u32, null), parsePressure("full avg10=9.00\n"));
    try std.testing.expectEqual(@as(?u32, null), parsePressure("some avg10=x\n"));
    try std.testing.expectEqual(@as(?u32, null), parsePressure(""));
}

test "missing files give no signal" {
    const s = read(
        std.testing.io,
        .{ .meminfo = "/nonexistent/m", .pressure = "/nonexistent/p" },
        "/nonexistent/engine",
    );
    try std.testing.expectEqual(Sample{}, s);
    try std.testing.expect(decide(.{}, .{}, flat(4), false) == null);
}

test "the defaults on razorbill: three jobs at once from idle, not four" {
    // Idle: about 5.5 GB available with the engine at 600 MB, no pressure.
    const idle: Signals = .{ .available_mb = 5500, .pressure = 0, .swap_growth_mb = 0 };
    try std.testing.expect(decide(.{}, idle, flat(3), false) == null);
    try std.testing.expect(decide(.{}, idle, flat(4), false).? == .memory);
    // Three heavy jobs in: about 1.1 GB each, the engine near its 4 GB cap.
    const busy: Signals = .{ .available_mb = 2200, .pressure = 0, .swap_growth_mb = 0 };
    try std.testing.expect(decide(.{}, busy, flat(1), false).? == .memory);
    // Three light jobs (200 MB each) past their ramp: a fourth is let through.
    const light: Signals = .{ .available_mb = 4900, .pressure = 0, .swap_growth_mb = 0 };
    try std.testing.expect(decide(.{}, light, flat(1), false) == null);
    // The incident: engine swapping at its cgroup cap while the host still has memory.
    const thrash: Signals = .{ .available_mb = 2100, .pressure = 4500, .swap_growth_mb = 400 };
    const none: Reservation = .{ .jobs = 1 };
    try std.testing.expect(decide(.{ .per_job_mb = 0 }, thrash, none, false).? == .pressure);
    const thrash_no_psi: Signals = .{ .available_mb = 2100, .swap_growth_mb = 400 };
    try std.testing.expect(decide(.{ .per_job_mb = 0 }, thrash_no_psi, none, false).? == .swap);
}

/// `jobs` jobs at the default `per_job_mb`, as every job reserved before #144.
fn flat(jobs: u32) Reservation {
    return .{ .jobs = jobs, .mb = @as(u64, jobs) * (Limits{}).per_job_mb };
}

test "a held runner resumes only past the margins, so it does not flap at a threshold" {
    const limits: Limits = .{ .min_available_mb = 1000, .per_job_mb = 500 };
    const at500: Reservation = .{ .jobs = 1, .mb = 500 };
    // Needs 1500 MB to start, 1756 to resume.
    try std.testing.expect(decide(limits, .{ .available_mb = 1600 }, at500, false) == null);
    try std.testing.expect(decide(limits, .{ .available_mb = 1499 }, at500, false) != null);
    try std.testing.expect(decide(limits, .{ .available_mb = 1600 }, at500, true) != null);
    try std.testing.expect(decide(limits, .{ .available_mb = 1756 }, at500, true) == null);
    // Pressure: holds at 10%, resumes under 5%.
    try std.testing.expect(decide(limits, .{ .pressure = 999 }, at500, false) == null);
    try std.testing.expect(decide(limits, .{ .pressure = 1000 }, at500, false).? == .pressure);
    try std.testing.expect(decide(limits, .{ .pressure = 700 }, at500, true) != null);
    try std.testing.expect(decide(limits, .{ .pressure = 499 }, at500, true) == null);
    // Swap growth: holds at 64 MB/min, resumes under 32.
    try std.testing.expect(decide(limits, .{ .swap_growth_mb = 64 }, at500, false).? == .swap);
    try std.testing.expect(decide(limits, .{ .swap_growth_mb = 40 }, at500, true) != null);
    try std.testing.expect(decide(limits, .{ .swap_growth_mb = 31 }, at500, true) == null);
    // Every check off.
    const off: Limits = .{
        .min_available_mb = 0,
        .per_job_mb = 0,
        .max_pressure = 0,
        .max_swap_growth_mb = 0,
    };
    const worst: Signals = .{ .available_mb = 0, .pressure = 10000, .swap_growth_mb = 9999 };
    try std.testing.expect(decide(off, worst, .{ .jobs = 4 }, true) == null);
}

test "swap growth is a rate over at least ten seconds" {
    var g: SwapGrowth = .{};
    try std.testing.expectEqual(@as(?u64, null), g.update(100, 0));
    // Too soon to measure: still nothing.
    try std.testing.expectEqual(@as(?u64, null), g.update(500, 5_000));
    // 200 MB in 20 s: 600 MB a minute.
    try std.testing.expectEqual(@as(?u64, 600), g.update(300, 20_000));
    // Kept until the next measurement; shrinking swap is no growth.
    try std.testing.expectEqual(@as(?u64, 600), g.update(900, 25_000));
    try std.testing.expectEqual(@as(?u64, 0), g.update(250, 30_000));
}

test "the pool reserves memory for runners polling and jobs just started" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 5632000 kB\n" });
    var path_buf: [256]u8 = undefined;
    const meminfo = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/meminfo", .{tmp.sub_path});

    var slots: [4]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
    var gates: [4]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    // 5500 MB: three runners may poll (1536 + 3 * 1024 = 4608), a fourth may not (5632).
    for (gates[0..3]) |*g| try std.testing.expect(g.check() == null);
    try std.testing.expectEqual(@as(u32, 3), pool.polling);
    try std.testing.expect(gates[3].check().? == .memory);
    // Looking again while counted does not count a runner twice.
    try std.testing.expect(gates[0].check() == null);
    try std.testing.expectEqual(@as(u32, 3), pool.polling);
    // A job taken stays reserved while it ramps up: the fourth is still held.
    gates[0].leave(true);
    try std.testing.expectEqual(@as(u32, 2), pool.polling);
    try std.testing.expect(gates[3].check() != null);
    // A cycle that ends without a job frees its place.
    gates[1].leave(false);
    gates[2].leave(false);
    try std.testing.expectEqual(@as(u32, 0), pool.polling);
    try std.testing.expect(gates[3].check() == null);
}

test "a job that is over reserves nothing, however soon it ended" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 5632000 kB\n" });
    var path_buf: [256]u8 = undefined;
    const meminfo = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/meminfo", .{tmp.sub_path});

    var slots: [4]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
    var gates: [4]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    // Three runners take a job each; while those ramp up, a fourth is held.
    for (gates[0..3]) |*g| {
        try std.testing.expect(g.check() == null);
        g.leave(true);
    }
    try std.testing.expect(gates[3].check() != null);
    // The jobs end at once (short jobs): their reservations go with them, well within ramp_ms.
    for (gates[0..3]) |*g| _ = g.ended();
    try std.testing.expect(gates[3].check() == null);
    // A runner's next job takes its own entry again, not another runner's.
    gates[3].leave(true);
    _ = gates[3].ended();
    try std.testing.expectEqual(std.math.minInt(i64), slots[3].started_ms);
}

/// What a test's memory.stat says, in bytes. `slab_reclaimable` null leaves its line out, as a
/// kernel without the key would.
const Stat = struct { inactive_file: u64 = 0, slab_reclaimable: ?u64 = 0 };

/// A cgroup directory under `tmp` with memory.max, memory.current, memory.stat and, if given,
/// memory.swap.current, in bytes.
fn writeCgroup(
    tmp: std.Io.Dir,
    sub: []const u8,
    max: []const u8,
    current: u64,
    stat: Stat,
    swap: ?u64,
) !void {
    const io = std.testing.io;
    try tmp.createDirPath(io, sub);
    var dir = try tmp.openDir(io, sub, .{});
    defer dir.close(io);
    var buf: [512]u8 = undefined;
    try dir.writeFile(io, .{
        .sub_path = "memory.max",
        .data = try std.fmt.bufPrint(&buf, "{s}\n", .{max}),
    });
    try dir.writeFile(io, .{
        .sub_path = "memory.current",
        .data = try std.fmt.bufPrint(&buf, "{d}\n", .{current}),
    });
    // Trimmed from a `docker run --memory 512m` container's memory.stat (Linux 7.0), the keys in
    // the kernel's order; slab is the sum of its two halves.
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("anon 53248\nfile 1216512\nkernel 352256\nshmem 0\nfile_mapped 847872\n" ++
        "inactive_anon 0\nactive_anon 53248\ninactive_file {d}\nactive_file 1150976\n" ++
        "unevictable 0\n", .{stat.inactive_file});
    if (stat.slab_reclaimable) |s| try w.print("slab_reclaimable {d}\n", .{s});
    const slab = (stat.slab_reclaimable orelse 0) + 81920;
    try w.print("slab_unreclaimable 81920\nslab {d}\n", .{slab});
    try dir.writeFile(io, .{ .sub_path = "memory.stat", .data = w.buffered() });
    if (swap) |s| try dir.writeFile(io, .{
        .sub_path = "memory.swap.current",
        .data = try std.fmt.bufPrint(&buf, "{d}\n", .{s}),
    });
}

const mib = 1 << 20;

test "the engine's cgroup: its cap, its use less inactive file cache and reclaimable slab, swap" {
    const stat = "anon 1\ninactive_file 65536\n";
    try std.testing.expectEqual(@as(?u64, 65536), parseStat(stat, "inactive_file"));
    // A key that only starts with the one asked for is another key.
    try std.testing.expectEqual(@as(?u64, null), parseStat("inactive_filex 3\n", "inactive_file"));
    try std.testing.expectEqual(@as(?u64, null), parseStat("", "inactive_file"));
    // The three slab keys sit together, in this order, and each is read as itself.
    const slabs = "slab_reclaimable 258312\nslab_unreclaimable 81920\nslab 340232\n";
    try std.testing.expectEqual(@as(?u64, 258312), parseStat(slabs, "slab_reclaimable"));
    try std.testing.expectEqual(@as(?u64, 81920), parseStat(slabs, "slab_unreclaimable"));
    try std.testing.expectEqual(@as(?u64, 340232), parseStat(slabs, "slab"));
    try std.testing.expectEqual(@as(?u64, null), parseStat("slab 7\n", "slab_reclaimable"));
    try std.testing.expectEqual(@as(?u64, null), parseStat("slab_reclaimable 1\n", "slab"));
    // A garbled value is no value: it subtracts nothing.
    const garbled = "slab_reclaimable x\n";
    try std.testing.expectEqual(@as(?u64, null), parseStat(garbled, "slab_reclaimable"));
    try std.testing.expectEqualStrings(
        "/system.slice/docker-ab12.scope",
        parseProcCgroup("0::/system.slice/docker-ab12.scope\n").?,
    );
    // A cgroup v1 machine names no unified hierarchy.
    try std.testing.expectEqual(@as(?[]const u8, null), parseProcCgroup("12:memory:/docker/a\n"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const none: Paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    // razorbill's engine mid-soak: 3.9 GB charged, 300 MB of it inactive cache, and swapping.
    try writeCgroup(tmp.dir, "engine", "4294967296", 3900 * mib, .{
        .inactive_file = 300 * mib,
    }, 512 * mib);
    var path_buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    const s = read(io, none, dir);
    try std.testing.expectEqual(EngineMemory{ .cap_mb = 4096, .used_mb = 3600 }, s.engine.?);
    try std.testing.expectEqual(@as(?u64, 512), s.engine_swap_mb);

    // The same, and 200 MB of dentries and inodes: those are not charged either.
    try writeCgroup(tmp.dir, "reclaim", "4294967296", 3900 * mib, .{
        .inactive_file = 300 * mib,
        .slab_reclaimable = 200 * mib,
    }, null);
    const reclaim = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/reclaim", .{tmp.sub_path});
    try std.testing.expectEqual(@as(u64, 3400), read(io, none, reclaim).engine.?.used_mb);

    // A kernel whose memory.stat has no slab_reclaimable line charges as before.
    try writeCgroup(tmp.dir, "older", "4294967296", 3900 * mib, .{
        .inactive_file = 300 * mib,
        .slab_reclaimable = null,
    }, null);
    const older = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/older", .{tmp.sub_path});
    try std.testing.expectEqual(@as(u64, 3600), read(io, none, older).engine.?.used_mb);

    // A memory.stat longer than the 8 KB read is cut there: a key past the cut is missing, and
    // the engine is charged all of memory.current rather than anything less.
    try writeCgroup(tmp.dir, "oversize", "4294967296", 3900 * mib, .{}, null);
    var big: [8192 + 64]u8 = undefined;
    for (0..8192 / 4) |i| @memcpy(big[i * 4 ..][0..4], "x 0\n");
    const tail = try std.fmt.bufPrint(big[8192..], "inactive_file {d}\nslab_reclaimable {d}\n", .{
        300 * mib,
        200 * mib,
    });
    var oversize_dir = try tmp.dir.openDir(io, "oversize", .{});
    defer oversize_dir.close(io);
    try oversize_dir.writeFile(io, .{
        .sub_path = "memory.stat",
        .data = big[0 .. 8192 + tail.len],
    });
    const oversize = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/oversize", .{
        tmp.sub_path,
    });
    try std.testing.expectEqual(@as(u64, 3900), read(io, none, oversize).engine.?.used_mb);

    // No cap ("max"): no engine signal.
    try writeCgroup(tmp.dir, "uncapped", "max", 3900 * mib, .{}, null);
    const uncapped = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/uncapped", .{
        tmp.sub_path,
    });
    try std.testing.expectEqual(@as(?EngineMemory, null), read(io, none, uncapped).engine);
}

test "the engine's cap holds a runner the machine's memory would let through" {
    // The incident (#142): the machine shows 4.8 GB available and lets a job through; the
    // engine, 3.5 of its 4 GB in use, does not.
    const incident: Signals = .{
        .available_mb = 4800,
        .pressure = 0,
        .swap_growth_mb = 0,
        .engine = .{ .cap_mb = 4096, .used_mb = 3600 },
    };
    try std.testing.expect(decide(.{}, .{ .available_mb = 4800 }, flat(1), false) == null);
    const hold = decide(.{}, incident, flat(1), false).?;
    try std.testing.expect(hold == .engine);
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "engine 3.5 GB of 4.0 GB in use; 1 job(s) needing 1.0 GB would leave under 256 MB " ++
            "of its cap",
        try std.fmt.bufPrint(&buf, "{f}", .{hold}),
    );
    // The engine at idle (600 MB): three jobs fit under its cap, as under the machine's; four not.
    const idle: Signals = .{ .engine = .{ .cap_mb = 4096, .used_mb = 600 } };
    try std.testing.expect(decide(.{}, idle, flat(3), false) == null);
    try std.testing.expect(decide(.{}, idle, flat(4), false).? == .engine);
    // Held, it resumes only with `resume_margin_mb` more: 1280 MB needed, 1536 to resume.
    const tight: Signals = .{ .engine = .{ .cap_mb = 4096, .used_mb = 4096 - 1400 } };
    try std.testing.expect(decide(.{}, tight, flat(1), false) == null);
    try std.testing.expect(decide(.{}, tight, flat(1), true).? == .engine);
    const freed: Signals = .{ .engine = .{ .cap_mb = 4096, .used_mb = 4096 - 1536 } };
    try std.testing.expect(decide(.{}, freed, flat(1), true) == null);
    // Over its cap (memory.current can pass memory.max for a moment): held, not an overflow.
    const over: Signals = .{ .engine = .{ .cap_mb = 4096, .used_mb = 4200 } };
    try std.testing.expect(decide(.{}, over, flat(1), false).? == .engine);
    // The engine swapping: held at 64 MB/min, resumed under 32, as for the machine's swap.
    const swapping: Signals = .{ .engine_swap_growth_mb = 64 };
    try std.testing.expect(decide(.{}, swapping, flat(1), false).? == .engine_swap);
    try std.testing.expect(decide(.{}, .{ .engine_swap_growth_mb = 40 }, flat(1), true) != null);
    try std.testing.expect(decide(.{}, .{ .engine_swap_growth_mb = 31 }, flat(1), true) == null);
}

test "the engine's cgroup is the nearest capped one at or above its process's" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var root_buf: [128]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}/cg", .{tmp.sub_path});
    // The scope Docker made, capped, and a child its entrypoint moved the engine into, not.
    try writeCgroup(tmp.dir, "cg/system.slice/docker-e.scope", "4294967296", 0, .{}, null);
    try writeCgroup(tmp.dir, "cg/system.slice/docker-e.scope/init", "max", 0, .{}, null);
    try writeCgroup(tmp.dir, "cg/system.slice", "max", 0, .{}, null);
    var start_buf: [256]u8 = undefined;
    var buf: [256]u8 = undefined;
    const start = try std.fmt.bufPrint(&start_buf, "{s}/system.slice/docker-e.scope/init", .{root});
    const found = try cappedAncestor(io, root, start, &buf);
    try std.testing.expect(std.mem.endsWith(u8, found, "cg/system.slice/docker-e.scope"));
    // Nothing capped up to the root, or a cgroup that is not there.
    const slice = try std.fmt.bufPrint(&start_buf, "{s}/system.slice", .{root});
    try std.testing.expectError(error.NoMemoryCap, cappedAncestor(io, root, slice, &buf));
    const gone = try std.fmt.bufPrint(&start_buf, "{s}/system.slice/docker-x.scope", .{root});
    try std.testing.expectError(error.CgroupNotFound, cappedAncestor(io, root, gone, &buf));
}

test "the engine's cgroup is found through its socket's listener, or not, saying why once" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    // This test process stands in for the engine: its own cgroup, under a fixture root.
    var self_buf: [4096]u8 = undefined;
    const self = std.Io.Dir.cwd().readFile(io, "/proc/self/cgroup", &self_buf) catch
        return error.SkipZigTest;
    const own = parseProcCgroup(self) orelse return error.SkipZigTest;
    if (own.len < 2) return error.SkipZigTest;
    var sub_buf: [512]u8 = undefined;
    const sub = try std.fmt.bufPrint(&sub_buf, "cg{s}", .{own});
    try writeCgroup(tmp.dir, sub, "536870912", 0, .{}, null);
    var root_buf: [128]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}/cg", .{tmp.sub_path});
    // Relative: an absolute path into a worktree can pass a socket address's 108 bytes.
    var sock_buf: [128]u8 = undefined;
    const sock = try std.fmt.bufPrint(&sock_buf, ".zig-cache/tmp/{s}/e.sock", .{tmp.sub_path});
    const addr = try std.Io.net.UnixAddress.init(sock);
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    var host_buf: [160]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "unix://{s}", .{sock});

    var slots: [1]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    const paths: Paths = .{
        .meminfo = "/nonexistent",
        .pressure = "/nonexistent",
        .cgroup_root = root,
    };
    pool.paths = paths;
    pool.engine.source = .{ .host = host };
    var gate: Gate = .{ .pool = &pool };
    _ = gate.check();
    try std.testing.expect(std.mem.endsWith(u8, pool.engine.dir.?, own));
    var buf: [512]u8 = undefined;
    const news = pool.engineNews(&buf).?;
    try std.testing.expect(std.mem.indexOf(u8, news, "capped at 0.5 GB") != null);
    try std.testing.expectEqual(@as(?[]const u8, null), pool.engineNews(&buf));

    // No engine there: said once with why, and not looked for again for a minute.
    var none: Admission = .init(io, .{}, &slots);
    none.paths = paths;
    none.engine.source = .{ .host = "unix:///nonexistent/engine.sock" };
    var g2: Gate = .{ .pool = &none };
    try std.testing.expect(g2.check() == null);
    try std.testing.expectEqual(@as(?[]const u8, null), none.engine.dir);
    try std.testing.expect(std.mem.indexOf(u8, none.engineNews(&buf).?, "FileNotFound") != null);
    _ = g2.check();
    try std.testing.expectEqual(@as(?[]const u8, null), none.engineNews(&buf));
    // An engine reached over TCP, or through Docker, has no socket to follow.
    var tcp: Admission = .init(io, .{}, &slots);
    tcp.paths = paths;
    tcp.engine.source = .{ .host = "tcp://127.0.0.1:1234" };
    var g3: Gate = .{ .pool = &tcp };
    _ = g3.check();
    const why = tcp.engineNews(&buf).?;
    try std.testing.expect(std.mem.indexOf(u8, why, "EngineHostNotUnixSocket") != null);
    // Off: nothing looked for, nothing said.
    var off: Admission = .init(io, .{}, &slots);
    off.paths = paths;
    var g4: Gate = .{ .pool = &off };
    _ = g4.check();
    try std.testing.expectEqual(@as(?[]const u8, null), off.engineNews(&buf));
}

test "an engine container recreated is looked for again, and counted as an engine that started" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try writeCgroup(tmp.dir, "cg/docker-a.scope", "4294967296", 1024 * mib, .{}, null);
    var root_buf: [128]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}/cg", .{tmp.sub_path});
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "{s}/docker-a.scope", .{root});
    var slots: [1]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent", .cgroup_root = root };
    pool.engine.source = .{ .cgroup = dir };
    var gate: Gate = .{ .pool = &pool };
    // Never found: the gate cannot tell when the engine starts.
    try std.testing.expectEqual(@as(?u32, null), pool.engineReturns());
    try std.testing.expect(gate.check() == null);
    try std.testing.expect(pool.engine.dir != null);
    // Found at startup: not an engine that started since.
    try std.testing.expectEqual(@as(?u32, 0), pool.engineReturns());
    var buf: [512]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, pool.engineNews(&buf).?, "capped at 4.0") != null);
    // Gone: forgotten and said, and looked for again at the next check, not a minute later.
    try tmp.dir.deleteTree(io, "cg/docker-a.scope");
    try std.testing.expect(gate.check() == null);
    try std.testing.expectEqual(@as(?[]const u8, null), pool.engine.dir);
    const gone = pool.engineNews(&buf).?;
    try std.testing.expect(std.mem.indexOf(u8, gone, "not found (EngineCgroupGone)") != null);
    try std.testing.expect(gate.check() == null);
    const news = pool.engineNews(&buf).?;
    try std.testing.expect(std.mem.indexOf(u8, news, "not found (CgroupNotFound)") != null);
    // Back, under the same name (`docker restart` keeps the container's ID).
    try writeCgroup(tmp.dir, "cg/docker-a.scope", "4294967296", 1024 * mib, .{}, null);
    pool.engine.failed_ms = null;
    try std.testing.expect(gate.check() == null);
    try std.testing.expect(pool.engine.dir != null);
    try std.testing.expectEqual(@as(?u32, 1), pool.engineReturns());
}

test "reservations add up what each job reserves, not a flat amount for each" {
    // razorbill idle (5.5 GB available): four jobs at the flat 1 GB do not fit, but three at the
    // worst case (polling, asking) and one light job ramping (300 MB) do.
    const idle: Signals = .{ .available_mb = 5500 };
    try std.testing.expect(decide(.{}, idle, flat(4), false).? == .memory);
    try std.testing.expect(decide(.{}, idle, .{ .jobs = 4, .mb = 3 * 1024 + 300 }, false) == null);
    const engine: Signals = .{ .engine = .{ .cap_mb = 4096, .used_mb = 3072 } };
    const hold = decide(.{}, engine, .{ .jobs = 2, .mb = 1024 + 2200 }, false).?;
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "engine 3.0 GB of 4.0 GB in use; 2 job(s) needing 3.1 GB would leave under 256 MB " ++
            "of its cap",
        try std.fmt.bufPrint(&buf, "{f}", .{hold}),
    );
}

/// The engine's cgroup fixture, "engine" under `tmp`: `used` MB in use of a 4 GB cap.
fn setEngine(tmp: std.Io.Dir, used: u64) !void {
    try writeCgroup(tmp, "engine", "4294967296", used * mib, .{}, null);
}

test "a job known to be light lets the next runner through where the worst case would hold" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    try setEngine(tmp.dir, 600);
    var slots: [2]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = dir;
    var gates: [2]Gate = .{ .{ .pool = &pool, .slot = 0 }, .{ .pool = &pool, .slot = 1 } };
    const uv = jobKey("o/r", "o/r/.github/workflows/ci.yml@refs/heads/main", "uv");

    // A uv job's first run: the worst case while it runs, and 300 MB learned when it ends.
    try std.testing.expect(gates[0].check() == null);
    gates[0].leave(true);
    gates[0].assigned(uv);
    try std.testing.expectEqual(@as(?u32, null), slots[0].est_mb);
    try setEngine(tmp.dir, 900);
    pool.samplePeaks();
    try setEngine(tmp.dir, 700);
    pool.samplePeaks();
    const learned = gates[0].ended().?;
    const change: Learned.Change = .{ .seen_mb = 300, .estimate_mb = 300, .alone = true };
    try std.testing.expectEqual(change, learned);

    // The engine at 1.8 GB, 2.3 GB under its cap. A job just handed out, its name not known
    // yet, and the runner asking: 2 x 1024 + 256 MB do not fit.
    try setEngine(tmp.dir, 1800);
    try std.testing.expect(gates[0].check() == null);
    gates[0].leave(true);
    try std.testing.expect(gates[1].check().? == .engine);
    // It is the uv job again: 300 + 1024 + 256 MB do, with the resume margin.
    gates[0].assigned(uv);
    try std.testing.expectEqual(@as(?u32, 300), slots[0].est_mb);
    try std.testing.expect(gates[1].check() == null);
    // It took less this time (the 64 MB floor): still 300 MB reserved, so nothing to say.
    try std.testing.expectEqual(@as(?Learned.Change, null), gates[0].ended());
}

test "a job's dentries and inodes are not learned as its size" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    try setEngine(tmp.dir, 600);
    var slots: [1]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = dir;
    var gate: Gate = .{ .pool = &pool, .slot = 0 };
    const zig = jobKey("o/r", "o/r/.github/workflows/ci.yml@refs/heads/main", "test (zig)");

    // Hashing the tool cache grows the reclaimable slab by 200 MB while memory.current grows by
    // 1.5 GB: the job is learned at 1.3 GB, what the engine's heap took, as if the slab had not
    // moved.
    gate.leave(true);
    gate.assigned(zig);
    try writeCgroup(tmp.dir, "engine", "4294967296", 2100 * mib, .{
        .slab_reclaimable = 200 * mib,
    }, null);
    pool.samplePeaks();
    const change: Learned.Change = .{ .seen_mb = 1300, .estimate_mb = 1300, .alone = true };
    try std.testing.expectEqual(change, gate.ended().?);
}

test "a job heavier than configured raises what an unknown job reserves" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    try setEngine(tmp.dir, 600);
    var slots: [2]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = dir;
    var gates: [2]Gate = .{ .{ .pool = &pool, .slot = 0 }, .{ .pool = &pool, .slot = 1 } };
    const workflow = "o/r/.github/workflows/ci.yml@refs/pull/7/merge";
    try std.testing.expectEqual(@as(u32, 1024), pool.unknown());

    // `zig build test`: 1.6 GB over the engine's use at its start.
    gates[0].leave(true);
    gates[0].assigned(jobKey("o/r", workflow, "test (zig)"));
    try setEngine(tmp.dir, 2200);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u32, 1600), gates[0].ended().?.estimate_mb);
    try std.testing.expectEqual(@as(u32, 1600), pool.unknown());

    // A name not seen yet, and a runner asking: both at the new worst case.
    gates[1].leave(true);
    gates[1].assigned(jobKey("o/r", workflow, "lint"));
    try std.testing.expectEqual(@as(?u32, null), slots[1].est_mb);
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    try std.testing.expectEqual(Reservation{ .jobs = 2, .mb = 3200 }, pool.reserved(now_ms, pool.polling + 1));
    // `per_job_mb` off reserves nothing, whatever was learned.
    pool.limits.per_job_mb = 0;
    try std.testing.expectEqual(@as(u64, 0), pool.reserved(now_ms, pool.polling + 1).mb);
}

test "a name reserves the most it took in its last five runs; a full table forgets the oldest" {
    var l: Learned = .{};
    try std.testing.expectEqual(@as(?u32, null), l.estimate(1));
    try std.testing.expectEqual(@as(u32, 1000), l.record(1, 1000, true));
    for (0..4) |_| try std.testing.expectEqual(@as(u32, 1000), l.record(1, 300, true));
    // A sixth run: the heavy one is no longer among the last five.
    try std.testing.expectEqual(@as(u32, 300), l.record(1, 300, true));
    try std.testing.expectEqual(@as(u32, 300), l.largest());

    // Full: a new name takes the place of the one least recently used, name 3, since names 1
    // and 2 were just looked up.
    for (2..Learned.capacity + 1) |k| _ = l.record(k, 100, true);
    try std.testing.expectEqual(@as(usize, Learned.capacity), l.len);
    _ = l.estimate(1);
    _ = l.estimate(2);
    _ = l.record(Learned.capacity + 1, 2000, true);
    try std.testing.expectEqual(@as(usize, Learned.capacity), l.len);
    try std.testing.expectEqual(@as(?u32, null), l.estimate(3));
    try std.testing.expectEqual(@as(?u32, 300), l.estimate(1));
    try std.testing.expectEqual(@as(?u32, 100), l.estimate(2));
    try std.testing.expectEqual(@as(?u32, 2000), l.estimate(Learned.capacity + 1));
    try std.testing.expectEqual(@as(u32, 2000), l.largest());
}

test "sampling raises the peaks of jobs running only; a job seen to take nothing takes 64 MB" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    try setEngine(tmp.dir, 1000);
    var slots: [3]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = dir;
    var running: Gate = .{ .pool = &pool, .slot = 0 };
    // Handed a job whose name is not known yet: not measured.
    var handed: Gate = .{ .pool = &pool, .slot = 1 };
    running.leave(true);
    running.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "build"));
    handed.leave(true);
    try setEngine(tmp.dir, 1500);
    pool.samplePeaks();
    try setEngine(tmp.dir, 1200);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u64, 1500), slots[0].peak_mb);
    try std.testing.expectEqual(@as(?u64, null), slots[1].base_mb);
    try std.testing.expectEqual(@as(u64, 0), slots[1].peak_mb);
    try std.testing.expectEqual(Admission.Slot{}, slots[2]);
    try std.testing.expectEqual(@as(?Learned.Change, null), handed.ended());
    try std.testing.expectEqual(@as(u32, 500), running.ended().?.seen_mb);

    // The engine's use fell while the job ran (another job ended): the floor is learned.
    running.leave(true);
    running.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "fmt"));
    try setEngine(tmp.dir, 400);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u32, Learned.min_mb), running.ended().?.estimate_mb);
}

test "a native job is measured in its own cgroup, alone, and not against the engine's cap" {
    // Two jobs at once, as on razorbill (#144): a Dagger job and a native one. The engine sees
    // only the Dagger job's growth; the native job's cgroup only its own.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const engine = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    var job_buf: [256]u8 = undefined;
    const job = try std.fmt.bufPrint(&job_buf, ".zig-cache/tmp/{s}/job", .{tmp.sub_path});
    try setEngine(tmp.dir, 1000);
    try writeCgroup(tmp.dir, "job", "max", 0, .{}, null);
    var slots: [2]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = engine;
    var on_dagger: Gate = .{ .pool = &pool, .slot = 0 };
    var on_native: Gate = .{ .pool = &pool, .slot = 1 };
    on_dagger.leave(true);
    on_dagger.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "dagger"));
    on_native.leave(true);
    on_native.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "native"));
    on_native.native(job);
    try std.testing.expect(slots[0].overlapped and slots[1].overlapped);
    try setEngine(tmp.dir, 1700);
    try writeCgroup(tmp.dir, "job", "max", 900 * mib, .{}, null);
    pool.samplePeaks();
    try writeCgroup(tmp.dir, "job", "max", 300 * mib, .{}, null);
    pool.samplePeaks();
    // The engine's reservation leaves the native job out: with the engine at 1700 of 4096 MB,
    // two unknown jobs (2048 MB) and its headroom (256 MB) fit, the native one's 1024 MB beside.
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    const r = pool.reserved(now_ms, 0);
    try std.testing.expectEqual(@as(u64, 2048), r.mb);
    try std.testing.expectEqual(@as(u64, 1024), r.native_mb);
    try std.testing.expect(decide(.{}, .{ .engine = .{ .cap_mb = 4096, .used_mb = 2700 } }, r, false) == null);
    try std.testing.expect(decide(.{}, .{ .engine = .{ .cap_mb = 4096, .used_mb = 2900 } }, r, false) != null);
    // Its cgroup goes before the job ends: read a last time, then left alone.
    try writeCgroup(tmp.dir, "job", "max", 950 * mib, .{}, null);
    on_native.nativeDone();
    try writeCgroup(tmp.dir, "job", "max", 4000 * mib, .{}, null);
    pool.samplePeaks();
    const native_learned = on_native.ended().?;
    try std.testing.expectEqual(@as(u32, 950), native_learned.seen_mb);
    try std.testing.expect(native_learned.alone);
    // The Dagger job overlapped it, and is still taken as beside another: its own reading is the
    // engine's, which is all its own here, but the gate does not know that yet.
    const dagger_learned = on_dagger.ended().?;
    try std.testing.expectEqual(@as(u32, 700), dagger_learned.seen_mb);
    try std.testing.expect(!dagger_learned.alone);

    // A native job without a cgroup is not measured: nothing is learned from it.
    on_native.leave(true);
    on_native.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "uncounted"));
    on_native.native(null);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(?Learned.Change, null), on_native.ended());
}

test "without the engine's cgroup nothing is learned, and every job reserves per_job_mb" {
    var slots: [2]Admission.Slot = undefined;
    var pool: Admission = .init(std.testing.io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    var gate: Gate = .{ .pool = &pool };
    try std.testing.expect(gate.check() == null);
    gate.leave(true);
    gate.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "build"));
    pool.samplePeaks();
    const now_ms = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    try std.testing.expectEqual(Reservation{ .jobs = 2, .mb = 2048 }, pool.reserved(now_ms, pool.polling + 1));
    try std.testing.expectEqual(@as(?Learned.Change, null), gate.ended());
    try std.testing.expectEqual(@as(usize, 0), pool.learned.len);
}

test "a pre-warm is let through on an idle machine whose pollers fill the gate, and a job after it counts it" {
    // The laptop's pool: 16 runners, 18 GB available, 1 GB per job, 1.5 GB floor.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 18404352 kB\n" });
    var path_buf: [256]u8 = undefined;
    const meminfo = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/meminfo", .{tmp.sub_path});
    var slots: [17]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
    var gates: [16]Gate = undefined;
    for (&gates, 0..) |*g, i| {
        g.* = .{ .pool = &pool, .slot = i };
        try std.testing.expect(g.check() == null);
    }
    try std.testing.expectEqual(@as(u32, 16), pool.polling);
    // One more runner would not fit beside the 16 pollers' worst cases.
    var extra: Gate = .{ .pool = &pool, .slot = 16 };
    try std.testing.expect(extra.check() != null);
    // The warm, in the same slot, asks against what runs: nothing. Not counted as polling.
    var warm: Gate = .{ .pool = &pool, .slot = 16, .warm = true };
    try std.testing.expect(warm.check() == null);
    try std.testing.expectEqual(@as(u32, 16), pool.polling);
    warm.leave(true);
    warm.assigned(jobKey("", "", "zig-runner pre-warm"));
    // A poller handed a job while the warm runs: both reserved, and both marked overlapped.
    gates[0].leave(true);
    try std.testing.expect(slots[16].overlapped and slots[0].overlapped);
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    try std.testing.expectEqual(Reservation{ .jobs = 17, .mb = 17 * 1024 }, pool.reserved(now_ms, pool.polling));
    // So a poller that asks again is held, the warm counted: 14 polling, itself, 2 running.
    gates[1].leave(false);
    try std.testing.expect(gates[1].check() != null);
    _ = warm.ended();
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), slots[16].started_ms);
}

test "a job that replayed steps from the cache is not learned from, and still frees its slot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    try setEngine(tmp.dir, 600);
    var slots: [1]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = dir;
    var gate: Gate = .{ .pool = &pool };
    const zig = jobKey("o/r", "o/r/.github/workflows/ci.yml@refs/heads/main", "test (zig)");
    // A re-run of one commit: its steps replayed, 100 MB where a real run takes 1.6 GB.
    gate.leave(true);
    gate.assigned(zig);
    try setEngine(tmp.dir, 700);
    pool.samplePeaks();
    gate.replayed();
    try std.testing.expectEqual(@as(?Learned.Change, null), gate.ended());
    try std.testing.expectEqual(Admission.Slot{}, slots[0]);
    try std.testing.expectEqual(@as(?u32, null), pool.learned.estimate(zig));
    // The next run is real: learned, and not flagged by the replay before it.
    gate.leave(true);
    gate.assigned(zig);
    try setEngine(tmp.dir, 2300);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u32, 1600), gate.ended().?.estimate_mb);
}

test "runs beside other jobs are upper bounds: the most alone, else the least beside others" {
    var l: Learned = .{};
    // razorbill's burst: zig's first runs overlapped another zig job.
    try std.testing.expectEqual(@as(u32, 2970), l.record(1, 2970, false));
    // Only runs beside others: the least of them, which still bounds the job's own peak.
    try std.testing.expectEqual(@as(u32, 2970), l.record(1, 3170, false));
    try std.testing.expectEqual(@as(u32, 2600), l.record(1, 2600, false));
    // A run alone replaces them, lower or not.
    try std.testing.expectEqual(@as(u32, 1600), l.record(1, 1600, true));
    try std.testing.expectEqual(@as(u32, 1600), l.largest());
    // Later runs beside others do not raise it.
    try std.testing.expectEqual(@as(u32, 1600), l.record(1, 3100, false));
    try std.testing.expectEqual(@as(u32, 1700), l.record(1, 1700, true));
}

test "jobs that share the engine at any moment are each marked as overlapped" {
    var slots: [3]Admission.Slot = undefined;
    var pool: Admission = .init(std.testing.io, .{}, &slots);
    var gates: [3]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    // Alone, until another starts beside it: both marked, and the mark stays after it ends.
    gates[0].leave(true);
    try std.testing.expect(!slots[0].overlapped);
    gates[1].leave(true);
    try std.testing.expect(slots[0].overlapped and slots[1].overlapped);
    _ = gates[1].ended();
    try std.testing.expect(slots[0].overlapped);
    _ = gates[0].ended();
    // The next job on an idle engine runs alone; a runner ending a cycle with no job is no job.
    gates[1].leave(false);
    gates[2].leave(true);
    try std.testing.expect(!slots[2].overlapped);
}

test "a job is the same job on any ref, and another under another name or workflow" {
    const main = jobKey("o/r", "o/r/.github/workflows/ci.yml@refs/heads/main", "test (zig)");
    const pr = jobKey("o/r", "o/r/.github/workflows/ci.yml@refs/pull/7/merge", "test (zig)");
    try std.testing.expectEqual(main, pr);
    const leg = jobKey("o/r", "o/r/.github/workflows/ci.yml@refs/heads/main", "test (uv)");
    try std.testing.expect(main != leg);
    const other = jobKey("o/r", "o/r/.github/workflows/cd.yml@refs/heads/main", "test (zig)");
    try std.testing.expect(main != other);
    // Where one part ends matters: "ab" and "c" are not "a" and "bc".
    try std.testing.expect(jobKey("ab", "c", "") != jobKey("a", "bc", ""));
}
