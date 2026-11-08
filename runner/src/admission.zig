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
//!
//! On a native pool the order is the other way round (#361). A native job is bounded by its own
//! cgroup and its parent's `memory.max`, and nothing of it runs until the runner has set it up, so
//! the room for it can be looked for after GitHub has handed it out and named it. A runner polling
//! reserves `native_per_job_mb`, not the heaviest job there was: with one `zig build test` learned
//! at 2.6 GB, six pollers reserved 15.8 GB on razorbill and held every small job behind a heavy
//! one that was not there. The job, once named, waits for room for its own estimate (`Gate.start`)
//! with the job's hold renewed, one job at a time under the lock so that a burst of heavy ones is
//! let through only as far as there is room. Nothing of this on the engine, where a job starts
//! the moment it is handed out and the poll is the only gate.
//!
//! A native job (`Gate.native`, docs/native-backend.md P4) is measured in a cgroup of its own, and
//! learned in a table of its own (`Admission.learned_native`): the engine's reading of a job is the
//! job plus whatever the engine grew by for it, so the two are not the same quantity, and a job
//! that runs natively one day and on Dagger the next would otherwise mix them. Native jobs have
//! their own default too (`Limits.native_per_job_mb`): razorbill's six native runners held e2e
//! jobs of a few MB for 87-150 s each behind 1.5 GB reserved per job not learned yet, sized for
//! `zig build test` on the engine. What lets a native default be low is the cgroup: a native job
//! that outgrows its estimate meets its `memory.high` (`nativeHighMb`) and is slowed and reclaimed
//! there, rather than taking memory its neighbours were admitted against; while the host has
//! memory to spare the limit moves out of its way (`Admission.growHigh`).
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
    /// `per_job_mb` for native jobs (`RUNNER_NATIVE_MEM_PER_JOB_MB`): what one whose name has not
    /// run natively yet reserves while it sets up (more where jobs cannot swap, below), and what a
    /// runner of a native pool reserves while it polls: the job it is handed is checked again once
    /// it is named, against its own estimate (`Gate.start`). A native job is measured in its own cgroup
    /// with nothing of the engine's in it. Where jobs can swap it is slowed at its `memory.high`
    /// (`nativeHighMb`) if it outgrows what it reserved; where they cannot, the default, one not
    /// learned yet reserves the most any native job took (`Gate.noHigh`). Either way this need not
    /// cover the very first heavy job the way `per_job_mb` does in the engine's one cgroup, whose
    /// `memory.max` holds it. 256 MB covers what the gate counts of a
    /// shell, checkout, uv or npm job (a few MB to about 300; page cache is not counted), and six
    /// runners' worth is razorbill's 1.5 GB floor. 0 reserves nothing for native jobs and sets no
    /// `memory.high`.
    native_per_job_mb: u32 = 256,
};

/// The `memory.high` of a native job that reserves `est_mb` (learned, or `native_per_job_mb`):
/// twice the estimate, since a job varies with what it is given (a cache missed, a larger change),
/// plus `high_headroom_mb`, since `memory.high` counts the job's page cache and reclaimable slab,
/// which the estimate does not (`workingSetMb`): a checkout's or a build's file cache is reclaimed
/// there, cheaply, instead of growing until the host's memory runs short. Past it the kernel
/// reclaims the job's memory and then slows its allocations; it kills nothing, which stays
/// `memory.max`'s (`RUNNER_NATIVE_MEMORY_MAX_MB`) to do. A job not learned yet gets 1 GB. This is
/// where a job starts: `Admission.growHigh` raises it while the host has memory to spare. It takes
/// swap to work at all: with none it stops a job dead, and it is not set (`Gate.noHigh`).
pub fn nativeHighMb(est_mb: u32) u32 {
    return est_mb *| 2 +| high_headroom_mb;
}

pub const high_headroom_mb = 512;

/// How much a native job's `memory.high` grows at a time (`Admission.growHigh`), and how close to
/// it its working set comes first.
pub const high_step_mb = 256;
pub const high_grow_margin_mb = 256;

/// Where the signals are read; tests point these at fixtures.
pub const Paths = struct {
    meminfo: []const u8 = "/proc/meminfo",
    pressure: []const u8 = "/proc/pressure/memory",
    /// Where the cgroup v2 hierarchy is mounted: the paths in `/proc/<pid>/cgroup` are under it.
    cgroup_root: []const u8 = "/sys/fs/cgroup",
    /// The runner's own cgroup (`runnerMemory`).
    self_cgroup: []const u8 = "/proc/self/cgroup",
    /// What names the machine in the file the gate keeps (`Identity`).
    machine_id: []const u8 = "/etc/machine-id",
    hostname: []const u8 = "/proc/sys/kernel/hostname",
};

/// How long a job's memory takes to show in `MemAvailable`: `zig build test` reached the engine's
/// cap about 90 s after four started at once on razorbill.
pub const ramp_ms = 120 * std.time.ms_per_s;

/// Once held, a runner resumes only with this much more memory than it needed to be let through,
/// and with pressure and swap growth under half their limits, so that a machine sitting at a
/// threshold does not hold and resume runners on alternate checks.
pub const resume_margin_mb = 256;

/// A job whose name ran no longer than this in each of its last `Learned.kept` runs is expected to
/// finish soon: it may start beside a job waiting for room, if it fits without it (#415).
pub const short_run_ms = 60 * std.time.ms_per_s;

/// A job that went ahead of the one waiting for room and has run this long was not as short as it
/// was learned: no more go ahead on the strength of a learned run time while it runs.
pub const overdue_ms = 2 * short_run_ms;

/// The pool's shared view of memory: one per process, used by every runner's `Gate`.
pub const Admission = struct {
    mu: std.Io.Mutex = .init,
    io: std.Io,
    limits: Limits,
    paths: Paths = .{},
    /// How often a held runner looks again, at the latest: it looks at once when `changes` moves.
    recheck: std.Io.Duration = .fromSeconds(5),
    /// Counts what may have lowered a reservation (`Gate.leave`, `assigned`, `native`,
    /// `backToEngine`, `ended`), so that a held runner looks again when it happens instead of
    /// at the next `recheck`. A burst of short jobs went through one runner at a time, each
    /// waiting out the 5 s before it saw the reservation of the one before it drop (razorbill,
    /// 2026-11-05: seven jobs of 1 to 7 s each waited 4 to 12 s in the queue).
    epoch: std.atomic.Value(u32) = .init(0),
    /// Runners let through to poll for a job: each may be handed one at any moment.
    polling: u32 = 0,
    /// The pool runs steps natively (`RUNNER_BACKEND=native`): a runner polling reserves
    /// `native_per_job_mb`, and a job, once named, waits for room for what it took natively.
    native: bool = false,
    /// Counts the jobs that came to wait (`Slot.wait_seq`): the oldest is let through when
    /// nothing else runs, however little room there is.
    waits: u64 = 0,
    /// Each runner's job, one entry per runner (`Gate.slot`): a runner runs one job at a time.
    slots: []Slot,
    /// What jobs took, by name: on the engine, and natively. Kept in a file between runs when
    /// `restore` was called (#407); without it a restart forgets them, and jobs reserve the worst
    /// case again until each has run once.
    learned: Learned = .{},
    learned_native: Learned = .{},
    swap: SwapGrowth = .{},
    engine: Engine = .{},
    /// Where `learned` and `learned_native` are kept between runs, after `restore`.
    persist: ?Persist = null,

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
        /// How many other jobs on the engine ran at some point during this one while it was on
        /// the engine too: its peak is the engine's for all of them, an upper bound on its own
        /// (`Learned`). A native job is none of them (`Admission.shareEngine`).
        overlaps: u16 = 0,
        /// The job runs on the native backend (`Gate.native`): measured in its own cgroup, whose
        /// path is in `cgroup_buf` while it is there, from nothing, so never beside another job;
        /// and it takes nothing of the engine's cap.
        native: bool = false,
        cgroup_buf: [256]u8 = @splat(0),
        cgroup_len: usize = 0,
        /// The native job's `memory.high` in MB (`nativeHighMb`, then `Admission.growHigh`), null
        /// for none; and whether its cgroup went over it (memory.events `high`), read as the
        /// cgroup goes.
        high_mb: ?u32 = null,
        over_high: bool = false,
        /// The job is handed out and named but does not run yet: on a native pool it waits for
        /// room (`Gate.start`), holding the job GitHub gave it. The one that waits longest counts
        /// in the reservations of runners polling and of the jobs waiting behind it, at its
        /// estimate (`withHead`); the others do not, which would hold them for ever and small
        /// jobs behind them (#415); the order they came in is `wait_seq`.
        waiting: bool = false,
        wait_seq: u64 = 0,
        /// The job started although it did not fit beside the first in line, because it is
        /// expected to finish soon (`Admission.aheadOpen`, #415).
        ahead: bool = false,

        fn cgroup(s: *const Slot) ?[]const u8 {
            return if (s.cgroup_len > 0) s.cgroup_buf[0..s.cgroup_len] else null;
        }

        fn running(s: *const Slot) bool {
            return s.started_ms != std.math.minInt(i64);
        }

        pub fn overlapped(s: *const Slot) bool {
            return s.overlaps > 0;
        }
    };

    /// `slots` must have one entry for each runner in the pool, plus one for the pool's pre-warm
    /// (`loop.Warmer`), which is a job to the gate, and each `Gate.slot` a different index into it.
    pub fn init(io: std.Io, limits: Limits, slots: []Slot) Admission {
        @memset(slots, .{});
        return .{ .io = io, .limits = limits, .slots = slots };
    }

    /// The count of events that may have lowered a reservation: a held runner looks again when
    /// it differs from what it read before its last look.
    pub fn changes(a: *const Admission) u32 {
        return a.epoch.load(.acquire);
    }

    fn changed(a: *Admission) void {
        _ = a.epoch.fetchAdd(1, .release);
    }

    /// What the gate reads now: the machine's and the engine's memory, pressure and swap growth.
    /// With the lock held.
    fn signals(a: *Admission, now_ms: i64) Signals {
        if (a.engine.dir == null) a.engine.find(a.io, a.paths, now_ms);
        const reading = read(a.io, a.paths, a.engine.dir);
        // Its files are gone: the engine's container was recreated, under a new cgroup. The jobs
        // running are not measured further: the new engine's working set is not theirs.
        if (a.engine.dir != null and reading.engine == null) {
            a.engine.lost();
            for (a.slots) |*s| if (!s.native) {
                s.base_mb = null;
            };
        }
        const swap_rate = if (reading.swap_used_mb) |u| a.swap.update(u, now_ms) else null;
        const engine_swap_rate = if (reading.engine_swap_mb) |u|
            a.engine.swap.update(u, now_ms)
        else
            null;
        return .{
            .available_mb = reading.available_mb,
            .pressure = reading.pressure,
            .swap_growth_mb = swap_rate,
            .engine = reading.engine,
            .engine_swap_growth_mb = engine_swap_rate,
        };
    }

    /// The waiting job `s` runs from `now_ms`: its estimate is reserved for the ramp from here,
    /// not from when it was handed out.
    fn admit(s: *Slot, now_ms: i64) void {
        s.waiting = false;
        s.started_ms = now_ms;
    }

    /// Whether the job in `slot` is the one waiting longest and no other job runs: the one that
    /// may start whatever the room (`Gate.start`). A job handed out and not named yet counts as
    /// running, for it may be a job that fits, or end at once.
    fn firstAlone(a: *const Admission, slot: usize) bool {
        const mine = a.slots[slot].wait_seq;
        for (a.slots, 0..) |s, i| {
            if (i == slot) continue;
            if (s.waiting) {
                if (s.wait_seq < mine) return false;
            } else if (s.running()) return false;
        }
        return true;
    }

    /// What a runner polling, or a job handed out and not named yet, reserves. On the engine,
    /// the worst case: it cannot be told apart from the job it may be handed, which is then
    /// started at once. On a native pool, `native_per_job_mb`: a job there is checked again once
    /// it is named, and waits for room for its own estimate (`Gate.start`), so reserving the
    /// heaviest job for every runner that polls only held small jobs behind a heavy one that was
    /// not there (#361).
    fn unknown(a: *const Admission) u32 {
        return if (a.native) a.limits.native_per_job_mb else a.worstCase(false);
    }

    /// A job's worst case on the engine, or natively: the configured `per_job_mb` (or
    /// `native_per_job_mb`), or the most any job took there if that is more, so that a job heavier
    /// than configured raises it. 0 (the setting off) reserves nothing, learned or not.
    fn worstCase(a: *const Admission, native: bool) u32 {
        const floor = if (native) a.limits.native_per_job_mb else a.limits.per_job_mb;
        if (floor == 0) return 0;
        return @max(floor, if (native) a.learned_native.largest() else a.learned.largest());
    }

    /// What a job of this name reserves once it runs natively: what it took natively, or
    /// `native_per_job_mb` for a name not seen there. Not the worst case, as on the engine: a
    /// native job that outgrows its estimate is slowed at its own `memory.high` (`nativeHighMb`)
    /// rather than taking its neighbours' memory. Where it has none, `Gate.noHigh` raises this. 0
    /// with the setting off.
    fn nativeEstimate(a: *Admission, key: ?u64) u32 {
        if (a.limits.native_per_job_mb == 0) return 0;
        const k = key orelse return a.limits.native_per_job_mb;
        return a.learned_native.estimate(k) orelse a.limits.native_per_job_mb;
    }

    /// What may start without showing in the machine's or the engine's memory yet: what a runner
    /// polling reserves (`unknown`) for each of `polling` that may be handed a job, and each job
    /// started less than `ramp_ms` ago with its own estimate. A job without one reserves what
    /// a runner polling does while its name is not known, and its own backend's worst case once
    /// it is. A job waiting for room (`Slot.waiting`) reserves its estimate for as long as it
    /// waits, unless `waiters` is false: the jobs waiting do not count each other. On a native
    /// pool the runners polling reserve natively (`native_mb`): the job one is handed runs in its
    /// own cgroup and never in the engine, and one sent back to the engine reserves there from
    /// `Gate.backToEngine` on (#414).
    fn reserved(a: *const Admission, now_ms: i64, polling: u32, waiters: bool) Reservation {
        var r: Reservation = .{ .jobs = polling };
        r.mb = @as(u64, r.jobs) * a.unknown();
        if (a.native) r.native_mb = r.mb;
        for (a.slots) |s| {
            if (s.waiting) {
                if (!waiters) continue;
            } else if (s.started_ms <= now_ms - ramp_ms) continue;
            const mb = a.slotMb(s);
            r.jobs += 1;
            r.mb += mb;
            if (s.native or s.waiting) r.native_mb += mb;
        }
        return r;
    }

    /// The job waiting longest for room: the next to start
    /// (`firstAlone`), whose room no other job may take (`withHead`). Null with none waiting.
    fn head(a: *const Admission) ?*const Slot {
        var first: ?*const Slot = null;
        for (a.slots) |*s| {
            if (!s.waiting) continue;
            if (first == null or s.wait_seq < first.?.wait_seq) first = s;
        }
        return first;
    }

    /// `r` and, if a job waits for room that is not the one in `slot`, what that job needs to
    /// start: a runner or a job is let through only while the job at the head of the line still has
    /// room to start with it (#415). The jobs behind the head are not counted, so a small job
    /// passes beside a heavy one waiting wherever there is room for both, and the head is never
    /// delayed by a job that began after it did.
    fn withHead(a: *const Admission, r: Reservation, slot: ?usize) Reservation {
        const h = a.head() orelse return r;
        if (slot) |i| if (h == &a.slots[i]) return r;
        const mb: u64 = h.est_mb orelse a.unknown();
        return .{ .jobs = r.jobs + 1, .mb = r.mb + mb, .native_mb = r.native_mb + mb };
    }

    /// What a job in `s` reserves: its estimate, or what a runner polling reserves while its name
    /// is not known, and its backend's worst case once it is.
    fn slotMb(a: *const Admission, s: Slot) u64 {
        return s.est_mb orelse if (s.key == null) a.unknown() else a.worstCase(s.native);
    }

    /// How long jobs of this name ran, at the longest of their last `Learned.kept` runs, in either
    /// backend's table; null for a name that has not run (`Learned.longest`).
    fn runMs(a: *const Admission, key: ?u64) ?u32 {
        const k = key orelse return null;
        const native = a.learned_native.longest(k);
        const engine = a.learned.longest(k);
        if (native != null and engine != null) return @max(native.?, engine.?);
        return native orelse engine;
    }

    fn waitingCount(a: *const Admission) usize {
        var n: usize = 0;
        for (a.slots) |s| n += @intFromBool(s.waiting);
        return n;
    }

    /// Whether a runner polling, or a job named, that does not fit beside the first in line may
    /// start anyway (#415): the room is the first in line's, but what goes ahead is not expected
    /// to hold it for long. The caller checked that it fits if the first in line were not waiting
    /// and, for a named job, that its learned run time is at most `short_run_ms` (`runMs`; a name
    /// not learned is long). Open while:
    /// - the first in line does not fit even with every job that went ahead of it gone, so it
    ///   waits for jobs not expected to end soon. Once it would fit without them it waits for the
    ///   ones ahead, and no more go before it: a steady stream of short jobs cannot keep it
    ///   waiting, only the ones in flight can, each for as long as it was learned to run;
    /// - some job that did not go ahead runs. With only jobs that went ahead running, the first in
    ///   line is the one started whatever the room (`firstAlone`, #386) when they end;
    /// - no job that went ahead has run for more than `overdue_ms`: it was learned short and is
    ///   not, so no more go ahead on the word of a learned run time while it runs; when it ends
    ///   its run is learned (`Learned.recordRun`) and its name is long.
    fn aheadOpen(a: *const Admission, signal: Signals, now_ms: i64) bool {
        const h = a.head() orelse return false;
        var r = a.reserved(now_ms, a.polling, false);
        var freed_mb: u64 = 0;
        var others_run = false;
        for (a.slots) |s| {
            if (s.waiting or !s.running()) continue;
            if (!s.ahead) {
                others_run = true;
                continue;
            }
            if (now_ms -| s.started_ms > overdue_ms) return false;
            const mb = a.slotMb(s);
            // In the reservation while it ramps up, in `available_mb` after.
            if (s.started_ms > now_ms - ramp_ms) {
                r.jobs -= 1;
                r.mb -= mb;
                if (s.native) r.native_mb -= mb;
            } else freed_mb += mb;
        }
        if (!others_run) return false;
        var without = signal;
        if (without.available_mb) |m| without.available_mb = m + freed_mb;
        const mb: u64 = h.est_mb orelse a.unknown();
        r.jobs += 1;
        r.mb += mb;
        r.native_mb += mb;
        return decide(a.limits, without, r, false) != null;
    }

    /// Whether a runner held for `hold` should poll anyway (#406): the hold is about room (the
    /// machine's, or an engine cap that is smaller than the reservation), nothing runs or waits, and no other runner polls, so no job will end and free any: the machine is as
    /// free as it gets, and a pool that never polls would never say why. Not for pressure or
    /// swap, which pass by themselves. `claimed` is whether the runner asking is counted in
    /// `polling`.
    fn idleFor(a: *const Admission, hold: Hold, claimed: bool) bool {
        switch (hold) {
            .memory => {},
            // The engine in use by others frees up by itself; a cap too small for the reservation
            // does not.
            .engine => |e| if (e.cap_mb >= e.floor_mb + (e.reserved.mb -| e.reserved.native_mb)) return false,
            else => return false,
        }
        if (a.polling != @intFromBool(claimed)) return false;
        for (a.slots) |s| if (s.waiting or s.running()) return false;
        return true;
    }

    /// The job in `slot` begins (`join`) or stops sharing the engine with every other job on it
    /// now; returns how many those are. It begins as it starts, or as it comes back from native
    /// (`Gate.backToEngine`), and stops as it goes native (`Gate.native`): a job on the engine is
    /// not taken as beside a native job, which was on the engine only for its few seconds of
    /// set-up, before anything ran.
    fn shareEngine(a: *Admission, slot: usize, join: bool) u16 {
        var n: u16 = 0;
        for (a.slots, 0..) |*s, i| if (i != slot and s.running() and !s.native) {
            if (join) s.overlaps +|= 1 else s.overlaps -|= 1;
            n +|= 1;
        };
        return n;
    }

    /// The engine's working set now, as the job's baseline and peak there; where the engine is
    /// not seen, none, and nothing is learned of the job on the engine.
    fn engineBaseline(a: *Admission, s: *Slot) void {
        const dir = a.engine.dir orelse return;
        const e = readEngine(a.io, dir) orelse return;
        s.base_mb = e.used_mb;
        s.peak_mb = e.used_mb;
    }

    /// Raises the peak of every job running, once a second, from the engine's working set, until
    /// cancelled with the pool. It reads nothing while no job is being measured.
    pub fn sample(a: *Admission) void {
        while (true) {
            a.io.sleep(.fromSeconds(1), .awake) catch return;
            a.samplePeaks();
            a.persistNow(false);
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
                    a.growHigh(s, dir, mb);
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

    /// A native job near its `memory.high` gets more of it while the host has the memory: the limit
    /// is there for the job's neighbours, and with none to protect it only harms. A build three
    /// times its limit, on a machine with 4 GB free, was reclaimed into compressed swap and
    /// took over an hour where the engine took 2 minutes (razorbill, 2026-11-05). What is left
    /// above the step is the floor every job was let in against, and what jobs still ramping up
    /// reserved; runners only polling reserve nothing here, as the gate holds them back itself
    /// once this shows in `MemAvailable`. Measured by working set, so a job full of page cache,
    /// which is cheap to reclaim, stays at its limit.
    fn growHigh(a: *Admission, s: *Slot, dir: []const u8, working_mb: u64) void {
        const high = s.high_mb orelse return;
        if (working_mb +| high_grow_margin_mb < high) return;
        const available = read(a.io, a.paths, null).available_mb orelse return;
        const now_ms = std.Io.Clock.awake.now(a.io).toMilliseconds();
        const others = a.reserved(now_ms, 0, true).mb;
        if (available < @as(u64, a.limits.min_available_mb) + others + high_step_mb) return;
        const next = high +| high_step_mb;
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        var text_buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/memory.high", .{dir}) catch return;
        const text = std.fmt.bufPrint(&text_buf, "{d}", .{@as(u64, next) << 20}) catch return;
        std.Io.Dir.cwd().writeFile(a.io, .{ .sub_path = path, .data = text }) catch |e| {
            std.log.warn("native: cannot raise {s}: {s}", .{ path, @errorName(e) });
            return;
        };
        s.high_mb = next;
    }

    /// Keeps the learned estimates at `path` (in the runner's state directory, `Config.nativeStore`)
    /// from here on, and reads what an earlier run left there (#407). A file written on another
    /// machine, by another backend or in another format, or one that does not parse, is not used
    /// (said in the result) and is replaced at the next write. Call once at start, before any runner
    /// polls; `path` must outlive the pool.
    pub fn restore(a: *Admission, path: []const u8) Restore {
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const id: Identity = .read(a.io, a.paths, a.native);
        a.persist = .{ .path = path, .identity = id };
        var buf: [file_max_bytes]u8 = undefined;
        const text = std.Io.Dir.cwd().readFile(a.io, path, &buf) catch |e| return switch (e) {
            error.FileNotFound => .absent,
            else => .{ .ignored = "it cannot be read" },
        };
        if (text.len == buf.len) return .{ .ignored = "it is larger than the gate ever writes" };
        var tables: Tables = .{};
        var why: []const u8 = "";
        parseTables(text, id, &tables, &why) catch |e| return .{ .ignored = switch (e) {
            error.Format => "it is not a memory gate file, or is damaged",
            error.WrongVersion => "it is in another format version",
            error.Foreign => why,
        } };
        a.learned = tables.engine;
        a.learned_native = tables.native;
        return .{ .loaded = @truncate(tables.engine.len + tables.native.len) };
    }

    /// Writes the estimates if some changed since the last write, and not within
    /// `Persist.min_interval_ms` of it unless `force`. Nothing without `restore`. A failed write is
    /// warned of once and tried again at the next interval; what the runner knows is still in
    /// memory.
    fn persistNow(a: *Admission, force: bool) void {
        var tables: Tables = undefined;
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        var id: Identity = undefined;
        const path = p: {
            a.mu.lockUncancelable(a.io);
            defer a.mu.unlock(a.io);
            const persist = &(a.persist orelse return);
            if (!persist.dirty) return;
            const now_ms = std.Io.Clock.awake.now(a.io).toMilliseconds();
            // Saturating: `written_ms` starts at the least i64, so the first write after a start
            // goes ahead (v0.28.0 subtracted plainly, which overflowed and aborted the runner at
            // its first job's end on razorbill).
            if (!force and now_ms -| persist.written_ms < Persist.min_interval_ms) return;
            if (persist.path.len > path_buf.len) return;
            persist.dirty = false;
            persist.written_ms = now_ms;
            tables = .{ .engine = a.learned, .native = a.learned_native };
            id = persist.identity;
            @memcpy(path_buf[0..persist.path.len], persist.path);
            break :p path_buf[0..persist.path.len];
        };
        var buf: [file_max_bytes]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const written: anyerror!void = if (render(&w, id, &tables)) |_|
            writeFileAtomic(a.io, path, w.buffered())
        else |e|
            e;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const persist = &(a.persist orelse return);
        if (written) |_| {
            persist.warned = false;
        } else |e| {
            persist.dirty = true;
            if (!persist.warned) std.log.warn(
                "memory gate: cannot write the learned estimates to {s}: {s}; they are lost " ++
                    "if the runner restarts",
                .{ path, @errorName(e) },
            );
            persist.warned = true;
        }
    }

    /// Writes any estimate not yet written; at the pool's end.
    pub fn flush(a: *Admission) void {
        a.persistNow(true);
    }

    /// Whether one job could ever start on this machine (#406): its reservation plus the floor
    /// against the machine's memory, or the cgroup limit the runner is under if that is less, and on
    /// the engine against the engine's cap with its headroom. A pool that fails this holds every
    /// runner for ever. Null when it fits, or when nothing can be read to say.
    pub fn misfit(a: *Admission) ?Misfit {
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const l = a.limits;
        const per = if (a.native) l.native_per_job_mb else l.per_job_mb;
        const per_name = if (a.native) "RUNNER_NATIVE_MEM_PER_JOB_MB" else "RUNNER_MEM_PER_JOB_MB";
        if (runnerMemory(a.io, a.paths)) |m| {
            if (@as(u64, per) + l.min_available_mb > m.mb and per + l.min_available_mb > 0) return .{
                .setting = per_name,
                .setting_mb = per,
                .floor_setting = "RUNNER_MIN_MEM_AVAILABLE_MB",
                .floor_mb = l.min_available_mb,
                .against = if (m.cgroup) "the memory limit the runner runs under is" else "the machine's memory is",
                .limit_mb = m.mb,
            };
        }
        // A native job never runs in the engine.
        if (a.native) return null;
        a.engine.find(a.io, a.paths, std.Io.Clock.awake.now(a.io).toMilliseconds());
        const dir = a.engine.dir orelse return null;
        const cap_mb = (readBytes(a.io, dir, "memory.max") orelse return null) >> 20;
        if (@as(u64, per) + l.min_engine_headroom_mb > cap_mb and per + l.min_engine_headroom_mb > 0) return .{
            .setting = per_name,
            .setting_mb = per,
            .floor_setting = "RUNNER_MIN_ENGINE_HEADROOM_MB",
            .floor_mb = l.min_engine_headroom_mb,
            .against = "the engine's memory cap is",
            .limit_mb = cap_mb,
        };
        return null;
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
    /// Set by `check` when it let the runner through although the machine had not the room, because
    /// nothing else runs (`Admission.idleFor`): the hold it overrode. The caller says so.
    forced: ?Hold = null,
    /// The forced poll was logged, once for as long as it lasts.
    forced_told: bool = false,
    /// The hold was logged, so its end is logged too, once each.
    announced: bool = false,
    /// The pool's pre-warm (`loop.Warmer`), not a runner: it is never counted as polling, and it
    /// reserves against the jobs that run, not the runners polling. A pool is sized so that its
    /// idle pollers' worst cases fill the gate (16 on the laptop: 17 GB of 18), so against them
    /// it waited for ever, and precisely while the machine was idle. A job a poller is handed
    /// while the warm runs still counts the warm (`leave`).
    warm: bool = false,

    /// Null when the runner may poll for a job (and it is then counted as polling); otherwise why
    /// not. For the pre-warm (`warm`): whether it may start now. A runner polling reserves for the
    /// runners beside it and the jobs running, and for the one job that waits longest for room
    /// (`Admission.withHead`), not for the others waiting behind it (#415). When nothing runs and
    /// no other runner polls, the one asking polls even without room (`Admission.idleFor`,
    /// `forced`), so a machine that cannot fit a job says so and still works (#406).
    pub fn check(g: *Gate) ?Hold {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const now_ms = std.Io.Clock.awake.now(a.io).toMilliseconds();
        const signal = a.signals(now_ms);
        // A runner asks beside every runner polling; the warm asks for itself alone.
        const asking = if (g.warm) 1 else a.polling + @intFromBool(!g.claimed);
        var r = a.withHead(a.reserved(now_ms, asking, false), null);
        // The pre-warm is a job on the engine, not a native one, however it is counted.
        if (g.warm and a.native) r.native_mb -|= a.unknown();
        var hold = decide(a.limits, signal, r, g.holding);
        // A job waits for room and the runner would take it: it may still poll if it fits without
        // that job, since what it is handed is told at `start`, where a job that is not expected
        // to be short waits behind the first in line. The cost is the runner it holds, and no more
        // than half the pool's are let to (`Admission.aheadOpen`, #415).
        if (hold != null and !g.warm and a.head() != null) {
            const no_head = a.reserved(now_ms, asking, false);
            if (decide(a.limits, signal, no_head, g.holding) == null and
                a.waitingCount() < a.slots.len / 2 and a.aheadOpen(signal, now_ms))
            {
                hold = null;
            }
        }
        g.forced = null;
        if (hold) |h| if (!g.warm and a.idleFor(h, g.claimed)) {
            g.forced = h;
            hold = null;
        };
        g.holding = hold != null;
        if (g.warm) return hold;
        if (hold == null and !g.claimed) a.polling += 1;
        if (hold != null and g.claimed) a.polling -= 1;
        g.claimed = hold == null;
        return hold;
    }

    /// How a job named on a native pool fares at the gate (`Gate.start`).
    pub const Start = union(enum) {
        /// It may run: it reserves its estimate from now, for `ramp_ms` or until it ends.
        started,
        /// No room, and the job waits.
        wait: Hold,
        /// No room either, but nothing else runs, so none will come of waiting: the machine is
        /// as free as it gets. It runs, under its cgroup's `memory.max`, and the reason it would
        /// have waited is told.
        forced: Hold,
    };

    /// Whether the runner's job, handed out and named (`assigned`), runs now. A runner cannot
    /// know its job before GitHub hands it one, so a native pool's pollers reserve little
    /// (`Admission.unknown`) and the room is looked for here, for this job's estimate: what
    /// jobs of its name took, or the worst case for a name not seen. Decided under the lock, so
    /// that jobs named in the same moment pass one at a time, each counting the ones before it:
    /// a burst of heavy jobs gets as far as there is room for, and the rest wait, holding the
    /// jobs GitHub gave them (`Renewer`). Waiting jobs do not reserve against each other, which
    /// would hold them all for ever; a job that is not first in line leaves room for the one that
    /// is (`withHead`). When none else runs, the one that came first is let through
    /// however little room there is: the machine cannot get freer, and a job over `memory.max`
    /// is the kernel's to end. Always `started` for a job that does not wait: on the engine, or
    /// the pre-warm.
    pub fn start(g: *Gate) Start {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = &a.slots[g.slot];
        if (!s.waiting) return .started;
        const now_ms = std.Io.Clock.awake.now(a.io).toMilliseconds();
        const signal = a.signals(now_ms);
        const est: u64 = s.est_mb orelse a.unknown();
        var r = a.withHead(a.reserved(now_ms, a.polling, false), g.slot);
        r.jobs += 1;
        r.mb += est;
        r.native_mb += est;
        const hold = decide(a.limits, signal, r, g.holding);
        g.holding = hold != null;
        const h = hold orelse {
            Admission.admit(s, now_ms);
            return .started;
        };
        // No room beside the first in line, but room without it, and a name expected to be gone
        // soon: it goes ahead (#415). A name not learned is long, and waits its turn.
        if (a.head() != &a.slots[g.slot]) {
            const short = if (a.runMs(s.key)) |ms| ms <= short_run_ms else false;
            var no_head = a.reserved(now_ms, a.polling, false);
            no_head.jobs += 1;
            no_head.mb += est;
            no_head.native_mb += est;
            if (short and decide(a.limits, signal, no_head, false) == null and
                a.aheadOpen(signal, now_ms))
            {
                Admission.admit(s, now_ms);
                s.ahead = true;
                g.holding = false;
                return .started;
            }
        }
        if (!a.firstAlone(g.slot)) return .{ .wait = h };
        Admission.admit(s, now_ms);
        g.holding = false;
        return .{ .forced = h };
    }

    /// The job runs whatever the room: GitHub cancelled it while it waited, and what is left to
    /// run is the steps that survive a cancel.
    pub fn startNow(g: *Gate) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = &a.slots[g.slot];
        if (s.waiting) Admission.admit(s, std.Io.Clock.awake.now(a.io).toMilliseconds());
    }

    /// The runner stops polling; `took_job` when because it was handed a job, whose memory is then
    /// reserved for `ramp_ms`, or until the job ends (`ended`) if that is sooner: the worst case
    /// until its name is known (`assigned`).
    pub fn leave(g: *Gate, took_job: bool) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        defer a.changed();
        if (g.claimed) a.polling -= 1;
        g.claimed = false;
        if (!took_job) return;
        // Two jobs overlap exactly when one starts while the other runs, so marking both here
        // catches every overlap, however briefly the jobs shared the engine.
        const now_ms = std.Io.Clock.awake.now(a.io).toMilliseconds();
        a.slots[g.slot] = .{ .started_ms = now_ms, .overlaps = a.shareEngine(g.slot, true) };
    }

    /// The runner's job is known as `key` (`jobKey`): it reserves what jobs of that name took, or
    /// the worst case for a name not seen yet, and is measured from here (`Admission.sample`). On
    /// a native pool it reserves what it took natively, or else on the engine (it went there
    /// last time, and likely will again), or else the native worst case, until it is known to run
    /// natively (`native`) or on the engine (`backToEngine`). It waits for room to start
    /// (`start`) from here; on the engine it does not wait.
    pub fn assigned(g: *Gate, key: u64) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        defer a.changed();
        const s = &a.slots[g.slot];
        std.debug.assert(s.running());
        s.key = key;
        // The pre-warm never waits here: `ready` let it through already. It reserves as on the
        // engine until the native store's warm makes its cgroup (`native`), and stays on the
        // engine for the engine's warm.
        if (a.native and !g.warm) {
            // Unlearned, the worst case, as `noHigh` has it where jobs cannot swap: until it is
            // native, and its estimate is what it is.
            s.est_mb = if (a.limits.native_per_job_mb == 0)
                0
            else
                a.learned_native.estimate(key) orelse a.learned.estimate(key) orelse
                    a.worstCase(true);
            // It waits for room (`start`) before anything of it runs.
            s.waiting = true;
            a.waits += 1;
            s.wait_seq = a.waits;
        } else if (a.limits.per_job_mb > 0) s.est_mb = a.learned.estimate(key);
        // Measured on the engine until it goes native, so a job a native pool sends to Dagger is
        // learned there. Without the engine's cgroup (another OS, `RUNNER_ENGINE_CGROUP=none`)
        // nothing is measured on the engine, nothing learned, and every job there reserves
        // `per_job_mb`.
        a.engineBaseline(s);
    }

    /// The runner's job runs on the native backend, in the cgroup `dir` (`native/cgroup.zig`), or
    /// in none (null). It is measured in its cgroup, from nothing (the cgroup is new), instead of
    /// from the engine's working set, where it takes nothing; so it is never measured beside
    /// another job, and it does not count against the engine's cap. Without a cgroup it is not
    /// measured, as a job without an engine signal is not. It reserves what it took natively
    /// before, or `native_per_job_mb`. A job the gate was not told of (`leave`) is left alone.
    ///
    /// Returns the `memory.high` to give its cgroup, in MB (`nativeHighMb`), or null for none:
    /// without a cgroup, with `native_per_job_mb` off, or for a job the gate was not told of.
    pub fn native(g: *Gate, dir: ?[]const u8) ?u32 {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        defer a.changed();
        const s = &a.slots[g.slot];
        if (!s.running()) return null;
        s.waiting = false;
        if (!s.native) {
            _ = a.shareEngine(g.slot, false);
            s.overlaps = 0;
        }
        s.native = true;
        s.cgroup_len = 0;
        s.base_mb = null;
        s.high_mb = null;
        const est = a.nativeEstimate(s.key);
        s.est_mb = est;
        const d = dir orelse return null;
        if (d.len > s.cgroup_buf.len) return null;
        @memcpy(s.cgroup_buf[0..d.len], d);
        s.cgroup_len = d.len;
        s.base_mb = 0;
        s.peak_mb = workingSetMb(a.io, d) orelse 0;
        if (est > 0) s.high_mb = nativeHighMb(est);
        return s.high_mb;
    }

    /// The job's memory cannot be reclaimed (`cgroup.canSwap`), so it gets no `memory.high`, which
    /// would stop it instead of slowing it, and none is raised (`growHigh`): it is learned at what
    /// it took, and `memory.max` (`limit_mb`) ends it if it takes too much. With nothing to hold it
    /// to its estimate, a job not learned yet may be as heavy as any before it, so it reserves
    /// that while it ramps up, no more than it may take: `native_per_job_mb` would let in a burst
    /// of new heavy names at 256 MB each. It holds the jobs after it for `ramp_ms` at the most,
    /// and no job before it. The same worst case is what a job not learned yet asks for to start
    /// (`assigned`, `start`), so a burst of new names is let through one at a time.
    pub fn noHigh(g: *Gate, limit_mb: ?u64) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        defer a.changed();
        const s = &a.slots[g.slot];
        s.high_mb = null;
        const learned = if (s.key) |k| a.learned_native.estimate(k) else null;
        if (learned != null) return;
        const worst = a.worstCase(true);
        s.est_mb = if (limit_mb) |l| @min(worst, l) else worst;
    }

    /// The job runs on the Dagger engine after all: a native pool's job that the native backend
    /// cannot run, or one whose native set-up (`native`) found it cannot run there. It takes the
    /// engine's cap again, reserves what it took on the engine (or the engine's worst case), and is
    /// measured there from now, so it is learned under the engine, beside the jobs it now shares
    /// the engine with, rather than from its native cgroup's few MB.
    pub fn backToEngine(g: *Gate) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        defer a.changed();
        const s = &a.slots[g.slot];
        if (!s.running()) return;
        s.waiting = false;
        if (s.native) s.overlaps = a.shareEngine(g.slot, true);
        s.native = false;
        s.cgroup_len = 0;
        s.high_mb = null;
        s.over_high = false;
        s.est_mb = null;
        if (a.limits.per_job_mb > 0) if (s.key) |k| {
            s.est_mb = a.learned.estimate(k);
        };
        s.base_mb = null;
        a.engineBaseline(s);
    }

    /// The runner's native job's cgroup is about to be removed: read a last time, then no more.
    pub fn nativeDone(g: *Gate) void {
        const a = g.pool;
        a.mu.lockUncancelable(a.io);
        defer a.mu.unlock(a.io);
        const s = &a.slots[g.slot];
        if (s.cgroup()) |dir| {
            if (workingSetMb(a.io, dir)) |mb| s.peak_mb = @max(s.peak_mb, mb);
            var buf: [512]u8 = undefined;
            if (readIn(a.io, dir, "memory.events", &buf)) |text| {
                s.over_high = (parseStat(text, "high") orelse 0) > 0;
            } else |_| {}
        }
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
        defer a.changed();
        const s = a.slots[g.slot];
        a.slots[g.slot] = .{};
        const now_ms = std.Io.Clock.awake.now(a.io).toMilliseconds();
        if (s.replayed) return null;
        const key = s.key orelse return null;
        const base = s.base_mb orelse return null;
        // At most 1 TB, so that it fits the table's u32 and sums of them cannot overflow.
        var seen_mb: u32 = @intCast(@min(@max(s.peak_mb -| base, Learned.min_mb), 1 << 20));
        // A native job that outgrew its estimate and met its `memory.high` was held down there
        // (its allocations slowed, its pages reclaimed or swapped out), so what it was seen to take
        // is what the limit let it, not what it needed: learned as no less than the limit, its next
        // run's limit is twice as high, until a run fits under it.
        if (s.native and s.over_high and seen_mb > (s.est_mb orelse 0)) if (s.high_mb) |h| {
            seen_mb = @max(seen_mb, h);
        };
        // Separate tables: an engine reading is not a native one (the module's doc comment).
        const table = if (s.native) &a.learned_native else &a.learned;
        const before = table.estimate(key);
        // A native job ran in a cgroup of its own: alone, whatever else ran.
        const alone = s.native or !s.overlapped();
        const after = table.record(key, seen_mb, alone);
        // How long it ran, for the jobs that may go ahead of one waiting for room (`aheadOpen`): not
        // a job that never started (cancelled while it waited), and not one that replayed steps,
        // which ran less than its next real run will (above).
        if (!s.waiting) table.recordRun(key, now_ms -| s.started_ms);
        if (a.persist) |*p| p.dirty = true;
        if (before == after) return null;
        return .{ .seen_mb = seen_mb, .estimate_mb = after, .alone = alone, .native = s.native };
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
    /// The longest run kept: 12 days, so that it fits the table's u32 and the file.
    pub const max_run_ms = 1 << 30;

    const Entry = struct {
        key: u64,
        alone: Runs = .{},
        beside: Runs = .{},
        /// How long the last `kept` runs took, in ms, whatever they were beside (`recordRun`).
        ran: Runs = .{},
        used: u64 = 0,

        fn estimate(e: *const Entry) u32 {
            if (e.alone.n > 0) return std.mem.max(u32, e.alone.slice());
            return std.mem.min(u32, e.beside.slice());
        }
    };

    /// The last `kept` runs' MB (or ms), oldest overwritten first.
    const Runs = struct {
        v: [kept]u32 = undefined,
        /// Runs in `mb`, up to `kept`, and where the next one goes.
        n: u8 = 0,
        next: u8 = 0,

        fn slice(r: *const Runs) []const u32 {
            return r.v[0..r.n];
        }

        fn push(r: *Runs, value: u32) void {
            r.v[r.next] = value;
            r.next = (r.next + 1) % kept;
            r.n = @min(r.n + 1, kept);
        }
    };

    /// A job's end that changed what its name reserves: what it took, whether it ran alone, and
    /// what is now reserved; natively (in its own cgroup) or on the engine.
    pub const Change = struct { seen_mb: u32, estimate_mb: u32, alone: bool, native: bool = false };

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
        runs.push(seen_mb);
        l.tick += 1;
        e.used = l.tick;
        return e.estimate();
    }

    /// A run of `key` took `ms` from start to end; for a name `record` has seen (the job ended
    /// with its memory learned). A run is at least 1 ms and at most `max_run_ms`.
    fn recordRun(l: *Learned, key: u64, ms: i64) void {
        const e = l.find(key) orelse return;
        e.ran.push(std.math.lossyCast(u32, std.math.clamp(ms, 1, max_run_ms)));
    }

    /// How long the longest of the last `kept` runs of `key` took, in ms: not the mean, so that a
    /// job that is sometimes long is not taken for a short one. Null for a name with no run
    /// learned. Does not count as a use of the name.
    fn longest(l: *const Learned, key: u64) ?u32 {
        for (l.entries[0..l.len]) |*e| if (e.key == key) {
            return if (e.ran.n == 0) null else std.mem.max(u32, e.ran.slice());
        };
        return null;
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

// ---- What jobs took, kept between runs (#407) ----

/// Where the learned estimates are kept between runs.
pub const Persist = struct {
    /// The file; its temp file is `path` + ".tmp".
    path: []const u8,
    identity: Identity,
    /// Something was learned since the last write.
    dirty: bool = false,
    written_ms: i64 = std.math.minInt(i64),
    /// A failed write was warned of already, until one succeeds.
    warned: bool = false,

    /// At most this often a change is written; a later one waits for the next look, and the pool's
    /// end writes what is left (`Admission.flush`).
    pub const min_interval_ms = 10 * std.time.ms_per_s;
};

/// What the estimates were measured on: a machine's memory accounting and a backend's reading of a
/// job differ, so a file written elsewhere or by another backend is wrong here (#407).
pub const Identity = struct {
    machine_buf: [64]u8 = undefined,
    machine_len: usize = 0,
    /// `MemTotal`, in MB; 0 when unknown.
    memory_mb: u64 = 0,
    native: bool = false,

    fn machine(i: *const Identity) []const u8 {
        return i.machine_buf[0..i.machine_len];
    }

    /// The machine id (`/etc/machine-id`), else the host name, else "unknown"; its memory; and the
    /// pool's backend.
    pub fn read(io: std.Io, paths: Paths, native: bool) Identity {
        var i: Identity = .{ .native = native };
        for ([_][]const u8{ paths.machine_id, paths.hostname }) |file| {
            var buf: [64]u8 = undefined;
            const text = std.Io.Dir.cwd().readFile(io, file, &buf) catch continue;
            const id = std.mem.trim(u8, text, " \n\t\r");
            if (id.len == 0 or std.mem.indexOfAny(u8, id, " \n\t\r") != null) continue;
            @memcpy(i.machine_buf[0..id.len], id);
            i.machine_len = id.len;
            break;
        }
        if (i.machine_len == 0) {
            @memcpy(i.machine_buf[0..7], "unknown");
            i.machine_len = 7;
        }
        var mem_buf: [4096]u8 = undefined;
        if (std.Io.Dir.cwd().readFile(io, paths.meminfo, &mem_buf)) |text| {
            i.memory_mb = parseMeminfo(text).total_mb orelse 0;
        } else |_| {}
        return i;
    }

    /// Why a file written for `file` is no good for `i`, or null if it is.
    fn mismatch(i: *const Identity, file: Identity) ?[]const u8 {
        if (!std.mem.eql(u8, i.machine(), file.machine())) return "it was written on another machine";
        if (i.native != file.native) return "it was written by another backend";
        // MemTotal moves a little between boots (the kernel's own reservations); a different amount
        // of memory is another machine as far as the accounting goes (a resized VM).
        const diff = if (i.memory_mb > file.memory_mb) i.memory_mb - file.memory_mb else file.memory_mb - i.memory_mb;
        if (diff > @max(i.memory_mb, file.memory_mb) / 16) return "the machine's memory is not what it was";
        return null;
    }
};

/// What `Admission.restore` found.
pub const Restore = union(enum) {
    /// No file: a first start.
    absent,
    /// The estimates read, in both tables.
    loaded: u32,
    /// A file that is not used, and why; to be warned of.
    ignored: []const u8,
};

const file_header = "zig-runner memory gate v2";
const file_header_prefix = "zig-runner memory gate ";

/// Both tables, as the file holds them.
const Tables = struct { engine: Learned = .{}, native: Learned = .{} };

/// The tables as text: the header, the identity, then one line for each name, in the order the
/// tables hold them.
fn render(w: *std.Io.Writer, id: Identity, t: *const Tables) std.Io.Writer.Error!void {
    try w.print("{s}\nmachine {s}\nmemory_mb {d}\nbackend {s}\n", .{
        file_header,
        id.machine(),
        id.memory_mb,
        if (id.native) "native" else "dagger",
    });
    inline for (.{ "engine", "native" }) |name| {
        const table = &@field(t, name);
        for (table.entries[0..table.len]) |*e| {
            try w.print("e {s} {x:0>16} {d}", .{ name, e.key, e.used });
            inline for (.{ .{ 'A', "alone" }, .{ 'B', "beside" }, .{ 'R', "ran" } }) |run| {
                const runs = &@field(e, run[1]);
                try w.print(" {c} {d} {d}", .{ run[0], runs.n, runs.next });
                for (runs.slice()) |mb| try w.print(" {d}", .{mb});
            }
            try w.writeByte('\n');
        }
    }
}

const FileError = error{ Format, WrongVersion, Foreign };

/// The tables in `text` if it is a file for `id`: all of them or an error, for half a file would
/// teach estimates that are not any run's.
fn parseTables(text: []const u8, id: Identity, out: *Tables, why: *[]const u8) FileError!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    const first = lines.next() orelse return error.Format;
    if (!std.mem.eql(u8, first, file_header)) {
        return if (std.mem.startsWith(u8, first, file_header_prefix)) error.WrongVersion else error.Format;
    }
    var file: Identity = .{};
    for (0..3) |_| {
        var words = std.mem.tokenizeScalar(u8, lines.next() orelse return error.Format, ' ');
        const key = words.next() orelse return error.Format;
        const value = words.next() orelse return error.Format;
        if (words.next() != null) return error.Format;
        if (std.mem.eql(u8, key, "machine")) {
            if (value.len > file.machine_buf.len) return error.Format;
            @memcpy(file.machine_buf[0..value.len], value);
            file.machine_len = value.len;
        } else if (std.mem.eql(u8, key, "memory_mb")) {
            file.memory_mb = std.fmt.parseInt(u64, value, 10) catch return error.Format;
        } else if (std.mem.eql(u8, key, "backend")) {
            if (std.mem.eql(u8, value, "native")) {
                file.native = true;
            } else if (!std.mem.eql(u8, value, "dagger")) return error.Format;
        } else return error.Format;
    }
    if (id.mismatch(file)) |reason| {
        why.* = reason;
        return error.Foreign;
    }
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, words.next() orelse return error.Format, "e")) return error.Format;
        const which = words.next() orelse return error.Format;
        const table = if (std.mem.eql(u8, which, "engine"))
            &out.engine
        else if (std.mem.eql(u8, which, "native"))
            &out.native
        else
            return error.Format;
        if (table.len == Learned.capacity) return error.Format;
        var e: Learned.Entry = .{ .key = 0 };
        e.key = std.fmt.parseInt(u64, words.next() orelse return error.Format, 16) catch return error.Format;
        e.used = std.fmt.parseInt(u64, words.next() orelse return error.Format, 10) catch return error.Format;
        inline for (.{
            .{ "A", "alone", 1 << 20 },
            .{ "B", "beside", 1 << 20 },
            .{ "R", "ran", Learned.max_run_ms },
        }) |run| {
            const runs = &@field(e, run[1]);
            if (!std.mem.eql(u8, words.next() orelse return error.Format, run[0])) return error.Format;
            const n = std.fmt.parseInt(u8, words.next() orelse return error.Format, 10) catch return error.Format;
            const next = std.fmt.parseInt(u8, words.next() orelse return error.Format, 10) catch return error.Format;
            if (n > Learned.kept or next >= Learned.kept) return error.Format;
            // Filled from 0 until `kept` runs are there, then overwritten oldest first.
            if (n < Learned.kept and next != n) return error.Format;
            runs.n = n;
            runs.next = next;
            for (runs.v[0..n]) |*mb| {
                mb.* = std.fmt.parseInt(u32, words.next() orelse return error.Format, 10) catch return error.Format;
                if (mb.* > run[2]) return error.Format;
            }
        }
        if (words.next() != null) return error.Format;
        if (table.find(e.key) != null) return error.Format;
        table.entries[table.len] = e;
        table.len += 1;
        table.tick = @max(table.tick, e.used);
    }
}

/// Writes `data` to `path` so that a reader finds the old file or the whole new one: to a temp file
/// beside it, synced, renamed over it, and the directory synced for the rename.
pub fn writeFileAtomic(io: std.Io, path: []const u8, data: []const u8) !void {
    const linux = std.os.linux;
    const cwd = std.Io.Dir.cwd();
    var tmp_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});
    const dir_path = std.fs.path.dirname(path) orelse ".";
    try cwd.createDirPath(io, dir_path);
    {
        const f = try cwd.createFile(io, tmp, .{});
        defer f.close(io);
        errdefer removeTemp(io, tmp);
        try f.writeStreamingAll(io, data);
        if (linux.errno(linux.fsync(f.handle)) != .SUCCESS) return error.Sync;
    }
    cwd.rename(tmp, cwd, path, io) catch |e| {
        removeTemp(io, tmp);
        return e;
    };
    var dir = try cwd.openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    if (linux.errno(linux.fsync(dir.handle)) != .SUCCESS) return error.Sync;
}

fn removeTemp(io: std.Io, tmp: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, tmp) catch |e| std.log.warn(
        "memory gate: cannot remove {s}: {s}",
        .{ tmp, @errorName(e) },
    );
}

/// A file of 128 names is about 28 KB.
const file_max_bytes = 48 * 1024;

// ---- A reservation that can never fit (#406) ----

/// A setting whose one job could never start on this machine.
pub const Misfit = struct {
    /// One job's reservation and the setting it comes from.
    setting: []const u8,
    setting_mb: u32,
    /// What must be left beyond it, and the setting it comes from.
    floor_setting: []const u8,
    floor_mb: u32,
    /// What they were compared with ("the machine has", "the engine's cap is"), and its size.
    against: []const u8,
    limit_mb: u64,

    pub fn format(m: Misfit, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print(
            "{s}={d} plus {s}={d} need {d} MB for one job, but {s} {d} MB: no job could ever " ++
                "start, and the memory gate would hold every runner for ever. Lower them, or " ++
                "turn the gate off with RUNNER_ADMISSION=false",
            .{
                m.setting,                           m.setting_mb, m.floor_setting, m.floor_mb,
                @as(u64, m.setting_mb) + m.floor_mb, m.against,    m.limit_mb,
            },
        );
    }
};

/// The memory this process can have at most, in MB: the machine's, or the least `memory.max` of the
/// cgroups the runner is in and above (a systemd `MemoryMax=`, a container's limit) if that is less.
/// Null when `MemTotal` cannot be read.
fn runnerMemory(io: std.Io, paths: Paths) ?struct { mb: u64, cgroup: bool } {
    var buf: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, paths.meminfo, &buf) catch return null;
    var least: u64 = parseMeminfo(text).total_mb orelse return null;
    var cgroup = false;
    var rel_buf: [4096]u8 = undefined;
    const own = std.Io.Dir.cwd().readFile(io, paths.self_cgroup, &rel_buf) catch return .{ .mb = least, .cgroup = false };
    const rel = parseProcCgroup(own) orelse return .{ .mb = least, .cgroup = false };
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var at: []const u8 = std.fmt.bufPrint(&dir_buf, "{s}{s}", .{ paths.cgroup_root, rel }) catch
        return .{ .mb = least, .cgroup = false };
    while (at.len > paths.cgroup_root.len) {
        if (readBytes(io, at, "memory.max")) |cap| if (cap >> 20 < least) {
            least = cap >> 20;
            cgroup = true;
        };
        at = std.fs.path.dirname(at) orelse break;
    }
    return .{ .mb = least, .cgroup = cgroup };
}

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
    // The same reservations against the engine's cap, less the native ones (`native_mb`): a native
    // job runs in its own cgroup and takes nothing of it, and neither does a runner polling on a
    // native pool, whatever job it is handed (#414). Every other job taken runs in the engine.
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
/// files every job (docs/BENCHMARKS.md), 180-270 MB on razorbill at idle, where the gate charged 1.3 GB
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
pub fn parseMeminfo(text: []const u8) struct { available_mb: ?u64, swap_used_mb: ?u64, total_mb: ?u64 } {
    var available: ?u64 = null;
    var total: ?u64 = null;
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
        else if (std.mem.eql(u8, key, "MemTotal")) total = kb / 1024 //
        else if (std.mem.eql(u8, key, "SwapTotal")) swap_total = kb / 1024 //
        else if (std.mem.eql(u8, key, "SwapFree")) swap_free = kb / 1024;
    }
    const swap_used = if (swap_total != null and swap_free != null)
        swap_total.? -| swap_free.?
    else
        null;
    return .{ .available_mb = available, .swap_used_mb = swap_used, .total_mb = total };
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

test "what may lower a reservation moves the count a held runner waits on" {
    var slots: [2]Admission.Slot = undefined;
    var pool: Admission = .init(std.testing.io, .{}, &slots);
    var g: Gate = .{ .pool = &pool };
    var seen = pool.changes();
    g.leave(true);
    try std.testing.expect(pool.changes() != seen);
    seen = pool.changes();
    g.assigned(jobKey("o/r", "o/r/.github/workflows/w.yml", "j"));
    try std.testing.expect(pool.changes() != seen);
    seen = pool.changes();
    _ = g.native(null);
    try std.testing.expect(pool.changes() != seen);
    seen = pool.changes();
    g.backToEngine();
    try std.testing.expect(pool.changes() != seen);
    seen = pool.changes();
    _ = g.ended();
    try std.testing.expect(pool.changes() != seen);
    // A look moves nothing: held runners do not wake each other.
    seen = pool.changes();
    _ = g.check();
    try std.testing.expectEqual(seen, pool.changes());
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
    try std.testing.expectEqual(Reservation{ .jobs = 2, .mb = 3200 }, pool.reserved(now_ms, pool.polling + 1, true));
    // `per_job_mb` off reserves nothing, whatever was learned.
    pool.limits.per_job_mb = 0;
    try std.testing.expectEqual(@as(u64, 0), pool.reserved(now_ms, pool.polling + 1, true).mb);
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
    // Both started on the engine as far as the gate knew; the native one was there only for its
    // set-up, so once it is known to be native neither is beside the other.
    try std.testing.expect(slots[0].overlapped() and slots[1].overlapped());
    try std.testing.expectEqual(@as(?u32, 1024), on_native.native(job));
    try std.testing.expect(!slots[0].overlapped());
    try setEngine(tmp.dir, 1700);
    try writeCgroup(tmp.dir, "job", "max", 900 * mib, .{}, null);
    pool.samplePeaks();
    try writeCgroup(tmp.dir, "job", "max", 300 * mib, .{}, null);
    pool.samplePeaks();
    // The engine's reservation leaves the native job out: with the engine at 1700 of 4096 MB,
    // the unknown Dagger job (1024 MB) and its headroom (256 MB) fit, the native one's 256 MB
    // (`native_per_job_mb`) beside.
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    const r = pool.reserved(now_ms, 0, true);
    try std.testing.expectEqual(@as(u64, 1024 + 256), r.mb);
    try std.testing.expectEqual(@as(u64, 256), r.native_mb);
    try std.testing.expect(decide(.{}, .{ .engine = .{ .cap_mb = 4096, .used_mb = 2800 } }, r, false) == null);
    try std.testing.expect(decide(.{}, .{ .engine = .{ .cap_mb = 4096, .used_mb = 2900 } }, r, false) != null);
    // Its cgroup goes before the job ends: read a last time, then left alone.
    try writeCgroup(tmp.dir, "job", "max", 950 * mib, .{}, null);
    on_native.nativeDone();
    try writeCgroup(tmp.dir, "job", "max", 4000 * mib, .{}, null);
    pool.samplePeaks();
    const native_learned = on_native.ended().?;
    try std.testing.expectEqual(@as(u32, 950), native_learned.seen_mb);
    try std.testing.expect(native_learned.alone and native_learned.native);
    // The Dagger job ran beside it, but not beside it on the engine: alone, its reading all its
    // own.
    const dagger_learned = on_dagger.ended().?;
    try std.testing.expectEqual(@as(u32, 700), dagger_learned.seen_mb);
    try std.testing.expect(dagger_learned.alone and !dagger_learned.native);

    // A native job without a cgroup is not measured: nothing is learned from it, and it has no
    // cgroup to give a memory.high.
    on_native.leave(true);
    on_native.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "uncounted"));
    try std.testing.expectEqual(@as(?u32, null), on_native.native(null));
    pool.samplePeaks();
    try std.testing.expectEqual(@as(?Learned.Change, null), on_native.ended());
}

test "a native job not learned yet reserves native_per_job_mb, and a native pool's poller the native worst case" {
    // razorbill's bench pool: six native runners, 5533 MB available. Before, three runners
    // asking reserved 1.5 GB each and were held ("3 job(s) needing 4.5 GB would leave under
    // 1536 MB"); natively, each reserves 256 MB.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 5665792 kB\n" });
    var path_buf: [256]u8 = undefined;
    const meminfo = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/meminfo", .{tmp.sub_path});
    var slots: [6]Admission.Slot = undefined;
    const limits: Limits = .{ .per_job_mb = 1536 };
    var dagger_pool: Admission = .init(io, limits, &slots);
    dagger_pool.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
    var gates: [6]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &dagger_pool, .slot = i };
    for (gates[0..2]) |*g| try std.testing.expect(g.check() == null);
    try std.testing.expect(gates[2].check().? == .memory);

    var pool: Admission = .init(io, limits, &slots);
    pool.paths = dagger_pool.paths;
    pool.native = true;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    try std.testing.expectEqual(@as(u32, 256), pool.unknown());
    // Every runner polls: 1536 + 6 x 256 = 3072 MB.
    for (&gates) |*g| try std.testing.expect(g.check() == null);
    // A job handed out and named reserves 256 MB while it sets up, and once it runs natively.
    gates[0].leave(true);
    gates[0].assigned(jobKey("o/r", "o/r/.github/workflows/e2e.yml", "e2e (1)"));
    try std.testing.expectEqual(@as(?u32, 256), slots[0].est_mb);
    try std.testing.expectEqual(@as(?u32, null), gates[0].native(null));
    try std.testing.expectEqual(@as(?u32, 256), slots[0].est_mb);
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    try std.testing.expectEqual(
        Reservation{ .jobs = 6, .mb = 6 * 256, .native_mb = 6 * 256 },
        pool.reserved(now_ms, pool.polling, true),
    );
    _ = gates[0].ended();

    // The setting off: native jobs reserve nothing, and get no memory.high.
    pool.limits.native_per_job_mb = 0;
    try std.testing.expectEqual(@as(u32, 0), pool.unknown());
    gates[0].leave(true);
    gates[0].assigned(jobKey("o/r", "o/r/.github/workflows/e2e.yml", "e2e (1)"));
    try std.testing.expectEqual(@as(?u32, 0), slots[0].est_mb);
    try std.testing.expectEqual(@as(?u32, null), gates[0].native(null));
    try std.testing.expectEqual(@as(u64, 0), pool.reserved(now_ms, 0, true).mb);
}

/// A native pool of `slots.len` runners and `available_mb` of memory (floor 1536 MB), with one
/// heavy name (2600 MB, razorbill's `zig build test`) and one light (200 MB) learned.
fn burstPool(tmp: std.Io.Dir, sub_path: []const u8, slots: []Admission.Slot, available_mb: u64) !Admission {
    var text: [64]u8 = undefined;
    try tmp.writeFile(std.testing.io, .{
        .sub_path = "meminfo",
        .data = try std.fmt.bufPrint(&text, "MemAvailable: {d} kB\n", .{available_mb * 1024}),
    });
    const Paths_ = struct {
        var buf: [256]u8 = undefined;
    };
    const meminfo = try std.fmt.bufPrint(&Paths_.buf, ".zig-cache/tmp/{s}/meminfo", .{sub_path});
    var pool: Admission = .init(std.testing.io, .{}, slots);
    pool.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
    pool.native = true;
    _ = pool.learned_native.record(burst_heavy, 2600, true);
    _ = pool.learned_native.record(burst_light, 200, true);
    return pool;
}

const burst_heavy = jobKey("o/r", "o/r/.github/workflows/ci.yml", "test (zig)");
const burst_light = jobKey("o/r", "o/r/.github/workflows/ci.yml", "lint");
const StartTag = std.meta.Tag(Gate.Start);

test "a native pool's runners reserve native_per_job_mb while they poll, however heavy a job was learned (#361)" {
    var slots: [6]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 5400);
    const now_ms = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    // razorbill: six pollers beside a learned 2.6 GB job reserved 15.8 GB, now 1.5 GB.
    try std.testing.expectEqual(
        Reservation{ .jobs = 6, .mb = 6 * 256, .native_mb = 6 * 256 },
        pool.reserved(now_ms, 6, true),
    );
    var gates: [6]Gate = undefined;
    for (&gates, 0..) |*g, i| {
        g.* = .{ .pool = &pool, .slot = i };
        try std.testing.expect(g.check() == null);
    }
    // The engine's pool keeps its worst case: a job there starts the moment it is handed out.
    var dagger_pool: Admission = .init(std.testing.io, .{}, &slots);
    _ = dagger_pool.learned.record(burst_heavy, 1600, true);
    try std.testing.expectEqual(@as(u32, 1600), dagger_pool.unknown());
}

test "heavy jobs handed out together start as far as there is room, and the rest wait (#361)" {
    var slots: [7]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Room for two heavy jobs above the floor: 7400 - 1536 = 5864 of 2 x 2600 = 5200.
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 7400);
    var gates: [7]Gate = undefined;
    for (&gates, 0..) |*g, i| {
        g.* = .{ .pool = &pool, .slot = i };
        try std.testing.expect(g.check() == null);
    }
    // Six heavy jobs in the same moment, each named: they used to start, all six, because the
    // gate looked only when the runner polled.
    for (gates[0..6]) |*g| {
        g.leave(true);
        g.assigned(burst_heavy);
    }
    var started: usize = 0;
    for (gates[0..6]) |*g| {
        if (g.start() == .started) started += 1;
        const now_ms = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
        // Whatever has started, the floor holds: nothing runs that would take the machine under it.
        try std.testing.expect(1536 + pool.reserved(now_ms, 0, false).mb <= 7400);
    }
    try std.testing.expectEqual(@as(usize, 2), started);
    try std.testing.expect(!slots[0].waiting and !slots[1].waiting and slots[2].waiting);
    // A light job named meanwhile waits for the first of the heavy ones, whose room it would take:
    // 1536 + 5200 + 2600 + 200 do not fit (#415 has it start beside them where they do).
    gates[6].leave(true);
    gates[6].assigned(burst_light);
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[6].start()));
    // The waiting jobs do not reserve against each other (the first in line is counted by those
    // that ask, `withHead`).
    const now_ms = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    try std.testing.expectEqual(@as(u64, 2 * 2600 + 200 + 4 * 2600), pool.reserved(now_ms, 0, true).mb);
    // One heavy job ends, and the next in line starts; the others still wait.
    const epoch = pool.changes();
    _ = gates[0].ended();
    try std.testing.expect(pool.changes() != epoch);
    try std.testing.expectEqual(@as(StartTag, .started), std.meta.activeTag(gates[2].start()));
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[3].start()));
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[4].start()));
    // Cancelled while it waits, a job runs what survives a cancel, and is then reserved.
    gates[3].startNow();
    try std.testing.expect(!slots[3].waiting);
}

test "every runner holding a job that has no room starts them one at a time, oldest first (#361)" {
    var slots: [3]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Under the floor: nothing fits, and nothing is running to free anything.
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 1000);
    var gates: [3]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    // Handed out in the order 1, 2, 0.
    for ([_]usize{ 1, 2, 0 }) |i| {
        gates[i].leave(true);
        gates[i].assigned(burst_heavy);
    }
    // None runs: the oldest starts, with what it would have waited for told.
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[2].start()));
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[0].start()));
    try std.testing.expectEqual(@as(StartTag, .forced), std.meta.activeTag(gates[1].start()));
    try std.testing.expect(gates[1].start() == .started);
    // It runs, so the others wait for it, and are not all let through at once.
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[2].start()));
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[0].start()));
    _ = gates[1].ended();
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[0].start()));
    try std.testing.expectEqual(@as(StartTag, .forced), std.meta.activeTag(gates[2].start()));
    _ = gates[2].ended();
    try std.testing.expectEqual(@as(StartTag, .forced), std.meta.activeTag(gates[0].start()));
}

test "on the engine a job is never held after it is named, and a native pool's job unlearned asks for the worst case (#361)" {
    var slots: [2]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 1000);
    var gates: [2]Gate = .{ .{ .pool = &pool, .slot = 0 }, .{ .pool = &pool, .slot = 1 } };
    // A name not seen yet cannot be told from the heaviest, as `noHigh` has it where jobs
    // cannot swap.
    gates[0].leave(true);
    gates[0].assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "new"));
    try std.testing.expectEqual(@as(?u32, 2600), slots[0].est_mb);
    // The Dagger pool: no waiting, whatever the memory.
    pool.native = false;
    gates[1].leave(true);
    gates[1].assigned(burst_heavy);
    try std.testing.expect(!slots[1].waiting);
    try std.testing.expect(gates[1].start() == .started);
}

test "a native job is learned from its own cgroup under its name, apart from the same name on the engine" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const engine = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    var job_buf: [256]u8 = undefined;
    const job = try std.fmt.bufPrint(&job_buf, ".zig-cache/tmp/{s}/job", .{tmp.sub_path});
    try setEngine(tmp.dir, 1000);
    var slots: [1]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    pool.engine.dir = engine;
    pool.native = true;
    var gate: Gate = .{ .pool = &pool };
    const zig = jobKey("o/r", "o/r/.github/workflows/ci.yml@refs/heads/main", "test (zig)");

    // On the engine first (a native pool's job the native backend could not run): 1.6 GB of the
    // engine's growth, learned under the engine.
    gate.leave(true);
    gate.assigned(zig);
    gate.backToEngine();
    try std.testing.expectEqual(@as(?u32, null), slots[0].est_mb);
    try setEngine(tmp.dir, 2600);
    pool.samplePeaks();
    const on_engine = gate.ended().?;
    try std.testing.expectEqual(@as(u32, 1600), on_engine.estimate_mb);
    try std.testing.expect(!on_engine.native);
    try std.testing.expectEqual(@as(usize, 0), pool.learned_native.len);

    // Then natively: named, it reserves its engine estimate (where it went last time) until it
    // is known to run natively, and then what natively it has never taken: the native default.
    gate.leave(true);
    gate.assigned(zig);
    try std.testing.expectEqual(@as(?u32, 1600), slots[0].est_mb);
    try writeCgroup(tmp.dir, "job", "max", 0, .{}, null);
    try std.testing.expectEqual(@as(?u32, 1024), gate.native(job));
    try std.testing.expectEqual(@as(?u32, 256), slots[0].est_mb);
    // Its cgroup's working set, not the engine's (which moved for other reasons), is learned:
    // 700 MB of memory.current, 100 MB of it inactive file cache.
    try setEngine(tmp.dir, 3900);
    try writeCgroup(tmp.dir, "job", "max", 700 * mib, .{ .inactive_file = 100 * mib }, null);
    pool.samplePeaks();
    gate.nativeDone();
    const natively = gate.ended().?;
    const change: Learned.Change = .{ .seen_mb = 600, .estimate_mb = 600, .alone = true, .native = true };
    try std.testing.expectEqual(change, natively);
    try std.testing.expectEqual(@as(?u32, 1600), pool.learned.estimate(zig));
    try std.testing.expectEqual(@as(?u32, 600), pool.learned_native.estimate(zig));

    // Its next run reserves the 600 MB it took natively, its memory.high from that.
    gate.leave(true);
    gate.assigned(zig);
    try std.testing.expectEqual(@as(?u32, 600), slots[0].est_mb);
    try std.testing.expectEqual(@as(?u32, 2 * 600 + high_headroom_mb), gate.native(job));
    _ = gate.ended();
    // A native pool's poller reserves the native default however heavy a job was (#361), the
    // job itself what it took; the engine's own worst case is the engine's.
    try std.testing.expectEqual(@as(u32, 256), pool.unknown());
    try std.testing.expectEqual(@as(u32, 600), pool.worstCase(true));
    try std.testing.expectEqual(@as(u32, 1600), pool.worstCase(false));
}

test "a native job at its memory.high gets more while the host has memory to spare" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var job_buf: [256]u8 = undefined;
    const job = try std.fmt.bufPrint(&job_buf, ".zig-cache/tmp/{s}/job", .{tmp.sub_path});
    var mem_buf: [256]u8 = undefined;
    const meminfo = try std.fmt.bufPrint(&mem_buf, ".zig-cache/tmp/{s}/meminfo", .{tmp.sub_path});
    var slots: [2]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
    var gate: Gate = .{ .pool = &pool };
    const available = struct {
        fn set(dir: std.Io.Dir, mb: u64) !void {
            var buf: [64]u8 = undefined;
            try dir.writeFile(std.testing.io, .{
                .sub_path = "meminfo",
                .data = try std.fmt.bufPrint(&buf, "MemAvailable: {d} kB\n", .{mb * 1024}),
            });
        }
    }.set;
    const high = struct {
        fn get(dir: std.Io.Dir) !u64 {
            var buf: [32]u8 = undefined;
            const text = try dir.readFile(std.testing.io, "job/memory.high", &buf);
            return try std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10) >> 20;
        }
    }.get;

    gate.leave(true);
    gate.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "test (zig)"));
    try writeCgroup(tmp.dir, "job", "max", 0, .{}, null);
    try std.testing.expectEqual(@as(?u32, 1024), gate.native(job));
    try tmp.dir.writeFile(io, .{ .sub_path = "job/memory.high", .data = "1073741824\n" });
    // Past its ramp: what it took shows in MemAvailable now, and nothing else may start.
    pool.slots[0].started_ms = std.math.minInt(i64) + 1;
    pool.polling = 5;

    // Well under its limit: left alone.
    try available(tmp.dir, 6000);
    try writeCgroup(tmp.dir, "job", "max", 500 * mib, .{}, null);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u64, 1024), try high(tmp.dir));

    // At it, on an idle machine: a build a 1 GB limit would hold down for an hour (razorbill,
    // 2026-11-05). Idle runners reserve nothing here.
    try writeCgroup(tmp.dir, "job", "max", 900 * mib, .{}, null);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u64, 1024 + high_step_mb), try high(tmp.dir));
    try std.testing.expectEqual(@as(?u32, 1024 + high_step_mb), pool.slots[0].high_mb);

    // At it on page cache alone, which is cheap to reclaim: left alone.
    try writeCgroup(tmp.dir, "job", "max", 1200 * mib, .{ .inactive_file = 900 * mib }, null);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u64, 1024 + high_step_mb), try high(tmp.dir));

    // The host at its floor: the limit holds, as it must for the job's neighbours.
    try writeCgroup(tmp.dir, "job", "max", 1200 * mib, .{}, null);
    try available(tmp.dir, 1536 + high_step_mb - 1);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u64, 1024 + high_step_mb), try high(tmp.dir));

    // Above the floor but for another job still ramping up, which reserves its share.
    pool.slots[1].started_ms = std.math.maxInt(i64) / 2;
    pool.slots[1].est_mb = 512;
    try available(tmp.dir, 1536 + high_step_mb + 100);
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u64, 1024 + high_step_mb), try high(tmp.dir));
    pool.slots[1] = .{};

    // A host it cannot read: the limit holds.
    pool.paths.meminfo = "/nonexistent";
    pool.samplePeaks();
    try std.testing.expectEqual(@as(u64, 1024 + high_step_mb), try high(tmp.dir));
}

test "a native job not learned yet, with no memory.high, reserves the most any native job took" {
    const io = std.testing.io;
    var slots: [2]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    var gate: Gate = .{ .pool = &pool };
    const new = jobKey("o/r", "o/r/.github/workflows/ci.yml", "new");
    const light = jobKey("o/r", "o/r/.github/workflows/ci.yml", "light");
    const start = struct {
        fn native(g: *Gate, key: u64) void {
            g.leave(true);
            g.assigned(key);
            _ = g.native(null);
        }
    };
    // Nothing heavy seen: the default.
    start.native(&gate, new);
    gate.noHigh(3000);
    try std.testing.expectEqual(@as(?u32, 256), pool.slots[0].est_mb);
    pool.slots[0] = .{};
    // After a 3 GB job: what a burst of new names reserves, each.
    _ = pool.learned_native.record(jobKey("o/r", "x", "heavy"), 3000, true);
    _ = pool.learned_native.record(light, 100, true);
    start.native(&gate, new);
    gate.noHigh(3400);
    try std.testing.expectEqual(@as(?u32, 3000), pool.slots[0].est_mb);
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    try std.testing.expectEqual(@as(u64, 3000), pool.reserved(now_ms, 0, true).mb);
    // On a machine where a job may take less, it reserves no more than that.
    gate.noHigh(2000);
    try std.testing.expectEqual(@as(?u32, 2000), pool.slots[0].est_mb);
    // Once ramped up it reserves nothing: what it took shows in `MemAvailable`, and nothing after
    // it waits on this for good.
    try std.testing.expectEqual(@as(u64, 0), pool.reserved(now_ms + ramp_ms + 1, 0, true).mb);
    pool.slots[0] = .{};
    // A name that has run keeps what it took.
    start.native(&gate, light);
    const est = pool.slots[0].est_mb;
    gate.noHigh(3400);
    try std.testing.expectEqual(est, pool.slots[0].est_mb);
    pool.slots[0] = .{};
}

test "a native job that cannot swap gets no memory.high, and the gate raises none" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var meminfo_buf: [256]u8 = undefined;
    const meminfo = try std.fmt.bufPrint(
        &meminfo_buf,
        ".zig-cache/tmp/{s}/meminfo",
        .{tmp.sub_path},
    );
    var job_buf: [256]u8 = undefined;
    const job = try std.fmt.bufPrint(&job_buf, ".zig-cache/tmp/{s}/job", .{tmp.sub_path});
    try tmp.dir.writeFile(io, .{ .sub_path = "meminfo", .data = "MemAvailable: 6144000 kB\n" });
    var slots: [1]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = meminfo, .pressure = "/nonexistent" };
    var gate: Gate = .{ .pool = &pool };
    gate.leave(true);
    gate.assigned(jobKey("o/r", "o/r/.github/workflows/ci.yml", "test (zig)"));
    try writeCgroup(tmp.dir, "job", "max", 0, .{}, null);
    try tmp.dir.writeFile(io, .{ .sub_path = "job/memory.high", .data = "max\n" });
    try std.testing.expectEqual(@as(?u32, 1024), gate.native(job));
    gate.noHigh(null);
    pool.slots[0].started_ms = std.math.minInt(i64) + 1;
    // At what would have been its limit, on an idle machine: a write here would stop the job.
    try writeCgroup(tmp.dir, "job", "max", 900 * mib, .{}, null);
    pool.samplePeaks();
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("max\n", try tmp.dir.readFile(io, "job/memory.high", &buf));
    try std.testing.expectEqual(@as(?u32, null), pool.slots[0].high_mb);
    _ = gate.ended();
}

test "a native job held down at its memory.high is learned at no less than it, so its next limit is higher" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var job_buf: [256]u8 = undefined;
    const job = try std.fmt.bufPrint(&job_buf, ".zig-cache/tmp/{s}/job", .{tmp.sub_path});
    var slots: [1]Admission.Slot = undefined;
    var pool: Admission = .init(io, .{}, &slots);
    pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    var gate: Gate = .{ .pool = &pool };
    const zig = jobKey("o/r", "o/r/.github/workflows/ci.yml", "test (zig)");

    // A first run of `zig build test`, natively: its limit is 1 GB, and it is held near it, part of
    // it swapped out, so its working set reads 900 MB.
    gate.leave(true);
    gate.assigned(zig);
    try writeCgroup(tmp.dir, "job", "max", 0, .{}, null);
    try std.testing.expectEqual(@as(?u32, 1024), gate.native(job));
    try writeCgroup(tmp.dir, "job", "max", 900 * mib, .{}, null);
    try tmp.dir.writeFile(io, .{
        .sub_path = "job/memory.events",
        .data = "low 0\nhigh 4180\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
    });
    gate.nativeDone();
    const throttled = gate.ended().?;
    try std.testing.expectEqual(@as(u32, 1024), throttled.estimate_mb);
    gate.leave(true);
    gate.assigned(zig);
    try std.testing.expectEqual(@as(?u32, 2 * 1024 + high_headroom_mb), gate.native(job));
    _ = gate.ended();

    // Over memory.high on page cache alone (a checkout's files), its working set within its
    // estimate: learned as it read.
    const checkout = jobKey("o/r", "o/r/.github/workflows/ci.yml", "checkout");
    gate.leave(true);
    gate.assigned(checkout);
    try writeCgroup(tmp.dir, "job", "max", 0, .{}, null);
    _ = gate.native(job);
    try writeCgroup(tmp.dir, "job", "max", 1100 * mib, .{ .inactive_file = 1000 * mib }, null);
    gate.nativeDone();
    try std.testing.expectEqual(@as(u32, 100), gate.ended().?.estimate_mb);
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
    try std.testing.expectEqual(Reservation{ .jobs = 2, .mb = 2048 }, pool.reserved(now_ms, pool.polling + 1, true));
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
    try std.testing.expect(slots[16].overlapped() and slots[0].overlapped());
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    try std.testing.expectEqual(Reservation{ .jobs = 17, .mb = 17 * 1024 }, pool.reserved(now_ms, pool.polling, true));
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
    try std.testing.expect(!slots[0].overlapped());
    gates[1].leave(true);
    try std.testing.expect(slots[0].overlapped() and slots[1].overlapped());
    _ = gates[1].ended();
    try std.testing.expect(slots[0].overlapped());
    _ = gates[0].ended();
    // The next job on an idle engine runs alone; a runner ending a cycle with no job is no job.
    gates[1].leave(false);
    gates[2].leave(true);
    try std.testing.expect(!slots[2].overlapped());
    _ = gates[2].ended();

    // A native job is on no engine: a job starting beside it is alone there, and so is one it
    // started beside, once it is known to be native.
    gates[0].leave(true);
    gates[1].leave(true);
    _ = gates[1].native(null);
    try std.testing.expect(!slots[0].overlapped());
    gates[2].leave(true);
    try std.testing.expect(slots[0].overlapped() and slots[2].overlapped());
    _ = gates[2].ended();
    _ = gates[0].ended();
    // Until it goes to the engine after all (`backToEngine`): from then it shares it.
    gates[0].leave(true);
    try std.testing.expect(!slots[0].overlapped());
    gates[1].backToEngine();
    try std.testing.expect(slots[0].overlapped() and slots[1].overlapped());
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

test "a native pool's runners are not counted against the engine's cap, a Dagger pool's are (#414)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var path_buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    // razorbill's bench pool: the engine busy at 2.4 GB of its 4 GB (another pool's Dagger jobs),
    // 1696 MB under the cap, and six runners polling at 256 MB each.
    try setEngine(tmp.dir, 2400);
    const limits: Limits = .{ .per_job_mb = 256, .native_per_job_mb = 256, .min_available_mb = 0 };

    var native_slots: [7]Admission.Slot = undefined;
    var native_pool: Admission = .init(io, limits, &native_slots);
    native_pool.paths = .{ .meminfo = "/nonexistent", .pressure = "/nonexistent" };
    native_pool.engine.dir = dir;
    native_pool.native = true;
    var native_gates: [6]Gate = undefined;
    // 6 x 256 + 256 MB of headroom is 1792: over the 1696 free, if the pollers were the engine's.
    for (&native_gates, 0..) |*g, i| {
        g.* = .{ .pool = &native_pool, .slot = i };
        try std.testing.expect(g.check() == null);
    }
    const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
    try std.testing.expectEqual(
        Reservation{ .jobs = 6, .mb = 6 * 256, .native_mb = 6 * 256 },
        native_pool.reserved(now_ms, 6, true),
    );
    // A job that goes back to the engine reserves there from then on.
    native_gates[0].leave(true);
    native_gates[0].assigned(burst_heavy);
    try std.testing.expect(native_gates[0].start() == .started);
    try std.testing.expectEqual(@as(?u32, null), native_gates[0].native(null));
    native_gates[0].backToEngine();
    const back = native_pool.reserved(now_ms, 0, true);
    try std.testing.expectEqual(Reservation{ .jobs = 1, .mb = 256, .native_mb = 0 }, back);

    // The same numbers on a Dagger pool: its runners poll for jobs that run in the engine.
    var slots: [7]Admission.Slot = undefined;
    var pool: Admission = .init(io, limits, &slots);
    pool.paths = native_pool.paths;
    pool.engine.dir = dir;
    var gates: [6]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    for (gates[0..5]) |*g| try std.testing.expect(g.check() == null);
    try std.testing.expect(gates[5].check().? == .engine);
}

/// A native pool of `slots.len` runners, as `burstPool`, with `n` heavy jobs named at once and
/// waiting for room, in the order of their slots.
fn waitingHeavy(gates: []Gate, n: usize) void {
    for (gates[0..n]) |*g| {
        g.leave(true);
        g.assigned(burst_heavy);
    }
}

test "a poller passes beside waiting heavy jobs when the first of them still has room, not when it would take it (#415)" {
    var slots: [8]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Three heavy jobs (2600 MB each) named and waiting; nothing runs. The floor is 1536 MB.
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 6500);
    var gates: [8]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    waitingHeavy(&gates, 3);
    for (gates[0..3]) |*g| try std.testing.expect(slots[g.slot].waiting);
    // Before, the poller reserved all three: 1536 + 3 x 2600 + 256 = 9592 MB, over 6500, and held.
    // Now it reserves the first: 1536 + 2600 + 256 = 4392 MB, and polls; the two behind it do not
    // hold it.
    try std.testing.expect(gates[6].check() == null);
    // A light job named meanwhile starts beside them, with room for it and the first.
    gates[7].leave(true);
    gates[7].assigned(burst_light);
    try std.testing.expectEqual(@as(StartTag, .started), std.meta.activeTag(gates[7].start()));
    // The poller is still counted; the first of the line starts at its next look, with the room
    // that was kept for it: 1536 + 200 + 256 (the poller) + 2600 = 4592 MB of 6500.
    try std.testing.expectEqual(@as(StartTag, .started), std.meta.activeTag(gates[0].start()));
    try std.testing.expect(!slots[0].waiting and slots[1].waiting and slots[2].waiting);
}

test "a poller or a job that would take the room of the first in line is held, and the first starts as soon as it fits (#415)" {
    var slots: [8]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // 4200 MB: the first heavy job fits alone (1536 + 2600 = 4136), not beside a poller (4392) or
    // a light job (4336).
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 4200);
    var gates: [8]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    waitingHeavy(&gates, 3);
    try std.testing.expect(gates[6].check().? == .memory);
    try std.testing.expect(!gates[6].claimed);
    gates[7].leave(true);
    gates[7].assigned(burst_light);
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[7].start()));
    try std.testing.expect(slots[7].waiting);
    // The second in line does not start either, whatever it asks.
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[1].start()));
    // The first fits and starts, with the others waiting and a light job behind it.
    try std.testing.expectEqual(@as(StartTag, .started), std.meta.activeTag(gates[0].start()));
    // The next in line is now the first, and it waits for the room of the one that runs.
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[1].start()));
    // A job that began waiting after the first one never delayed it: the light job is still
    // waiting for the heavy one to end, then for the second's room.
    try std.testing.expectEqual(@as(StartTag, .wait), std.meta.activeTag(gates[7].start()));
    // The machine has a little more by now (a held job needs the resume margin more to go).
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "meminfo", .data = "MemAvailable: 4608000 kB\n" });
    _ = gates[0].ended();
    try std.testing.expectEqual(@as(StartTag, .started), std.meta.activeTag(gates[1].start()));
}

test "nothing fits and nothing runs: the first in line is forced and a poller is let through (#415, #406)" {
    var slots: [4]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Under the floor: not even the first fits.
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 1000);
    var gates: [4]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    waitingHeavy(&gates, 2);
    // A job waits, so a poller is held: the job is the one forced.
    try std.testing.expect(gates[2].check().? == .memory);
    try std.testing.expect(gates[2].forced == null);
    try std.testing.expectEqual(@as(StartTag, .forced), std.meta.activeTag(gates[0].start()));
}

test "with nothing running or named, one poller is let through however little room there is (#406)" {
    var slots: [4]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // 1000 MB available, 1536 MB floor: a poller can never pass on room.
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 1000);
    var gates: [4]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    try std.testing.expect(gates[0].check() == null);
    try std.testing.expect(gates[0].forced.? == .memory);
    try std.testing.expect(gates[0].claimed);
    // Only one: the others hold, as the rest of the pool would otherwise take jobs at once.
    try std.testing.expect(gates[1].check().? == .memory);
    try std.testing.expect(gates[1].forced == null);
    // Looking again changes nothing for the one that polls.
    try std.testing.expect(gates[0].check() == null);
    try std.testing.expectEqual(@as(u32, 1), pool.polling);
    // It takes a job: now something runs, and the others wait for it.
    gates[0].leave(true);
    try std.testing.expect(gates[1].check().? == .memory);
    gates[0].assigned(burst_light);
    try std.testing.expect(gates[1].check().? == .memory);
    _ = gates[0].ended();
    // It ended: nothing runs again, and the next one is let through.
    try std.testing.expect(gates[1].check() == null);
    try std.testing.expect(gates[1].forced != null);
}

test "pressure and swap holds are not overridden when nothing runs (#406)" {
    var slots: [2]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 8000);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "pressure",
        .data = "some avg10=50.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    });
    var path_buf: [256]u8 = undefined;
    pool.paths.pressure = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/pressure", .{tmp.sub_path});
    var gate: Gate = .{ .pool = &pool, .slot = 0 };
    try std.testing.expect(gate.check().? == .pressure);
    try std.testing.expect(gate.forced == null);
}

// ---- Jobs expected to finish soon go ahead of one waiting for room (#415) ----

const burst_novel = jobKey("o/r", "o/r/.github/workflows/ci.yml", "docs");
const burst_long = jobKey("o/r", "o/r/.github/workflows/ci.yml", "e2e long");

fn setAvailable(dir: std.Io.Dir, mb: u64) !void {
    var buf: [64]u8 = undefined;
    try dir.writeFile(std.testing.io, .{
        .sub_path = "meminfo",
        .data = try std.fmt.bufPrint(&buf, "MemAvailable: {d} kB\n", .{mb * 1024}),
    });
}

/// The runner of `g` is handed a job named `key`, and asks to start it.
fn named(g: *Gate, key: u64) StartTag {
    g.leave(true);
    g.assigned(key);
    return std.meta.activeTag(g.start());
}

/// What razorbill's pool has learned of these names: memory (`burstPool`), and how long each ran.
fn learnRuns(pool: *Admission) void {
    pool.learned_native.recordRun(burst_heavy, 270 * std.time.ms_per_s);
    pool.learned_native.recordRun(burst_light, 5 * std.time.ms_per_s);
    // Short memory-wise, and not short in time or not timed at all.
    _ = pool.learned_native.record(burst_long, 200, true);
    pool.learned_native.recordRun(burst_long, 180 * std.time.ms_per_s);
    _ = pool.learned_native.record(burst_novel, 200, true);
}

test "short jobs start beside a heavy one waiting for room; it starts when the heavy one running ends (#415)" {
    var slots: [12]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // 6500 MB of 1536 floor: a heavy job (2600) running, ramping, and a second one waiting
    // (1536 + 2600 + 2600 = 6736) cannot start; a short one beside the first can (4336).
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 6500);
    learnRuns(&pool);
    var gates: [12]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    try std.testing.expectEqual(StartTag.started, named(&gates[0], burst_heavy));
    try std.testing.expectEqual(StartTag.wait, named(&gates[1], burst_heavy));
    // The seven-job e2e burst: each starts at once, ahead of the heavy job waiting.
    for (gates[2..9]) |*g| try std.testing.expectEqual(StartTag.started, named(g, burst_light));
    for (slots[2..9]) |s| try std.testing.expect(s.ahead and !s.waiting);
    try std.testing.expect(slots[1].waiting);
    // Two runners poll for more: they are not held for the waiting job's room either.
    try std.testing.expect(gates[9].check() == null);
    try std.testing.expect(gates[10].check() == null);
    // The heavy job running ends: the waiting one starts at its next look, with the short jobs
    // still running (they were learned to take seconds, and do not hold what it needs).
    _ = gates[0].ended();
    try setAvailable(tmp.dir, 7600);
    try std.testing.expectEqual(StartTag.started, std.meta.activeTag(gates[1].start()));
    try std.testing.expect(!slots[1].waiting and slots[2].ahead);
}

test "a job not learned or learned long waits behind the first in line, and so does a short one with no room (#415)" {
    var slots: [12]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 6500);
    learnRuns(&pool);
    var gates: [12]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    _ = named(&gates[0], burst_heavy);
    _ = named(&gates[1], burst_heavy);
    // Memory for each is there; the name never ran (so unknown, long), or ran for 180 s.
    try std.testing.expectEqual(StartTag.wait, named(&gates[2], burst_novel));
    try std.testing.expectEqual(StartTag.wait, named(&gates[3], burst_long));
    try std.testing.expect(slots[2].waiting and !slots[2].ahead and slots[3].waiting);
    // A short one starts beside them, and the first in line is still the first.
    try std.testing.expectEqual(StartTag.started, named(&gates[4], burst_light));
    // A short job that takes what is left of the room waits: 4336 + 200 + 200 x 10 > 6500.
    try setAvailable(tmp.dir, 4500);
    try std.testing.expectEqual(StartTag.wait, named(&gates[5], burst_light));
    try std.testing.expectEqual(@as(?*const Admission.Slot, &slots[1]), pool.head());
}

test "no short job goes ahead once the first in line would fit without the ones ahead: a stream cannot starve it (#415)" {
    var slots: [12]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 5200);
    learnRuns(&pool);
    var gates: [12]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    // A job of a name not timed runs (not ahead of anything), then the heavy one and the one
    // waiting for it; four short jobs go ahead.
    try std.testing.expectEqual(StartTag.started, named(&gates[6], burst_novel));
    try std.testing.expectEqual(StartTag.started, named(&gates[0], burst_heavy));
    try std.testing.expectEqual(StartTag.wait, named(&gates[1], burst_heavy));
    for (gates[2..6]) |*g| try std.testing.expectEqual(StartTag.started, named(g, burst_light));
    // The heavy job ends. The first in line needs 1536 + 200 + 4 x 200 + 2600 = 5136 MB and has
    // 4700, so it waits for the short jobs; without them it would fit (4336, and 256 more to
    // resume), so no more go before it: a stream of short jobs arrives and waits, each time one
    // of them ends.
    _ = gates[0].ended();
    try setAvailable(tmp.dir, 4700);
    try std.testing.expectEqual(StartTag.wait, std.meta.activeTag(gates[1].start()));
    for (0..4) |i| {
        try std.testing.expectEqual(StartTag.wait, named(&gates[7 + i], burst_light));
        try std.testing.expect(!slots[7 + i].ahead);
        if (i < 3) try std.testing.expectEqual(StartTag.wait, std.meta.activeTag(gates[1].start()));
        _ = gates[2 + i].ended();
    }
    // The last one ended: the first in line starts, ahead of the stream waiting behind it.
    try std.testing.expectEqual(StartTag.started, std.meta.activeTag(gates[1].start()));
    for (slots[7..11]) |s| try std.testing.expect(s.waiting);
}

test "with only jobs that went ahead running, the first in line is forced when they end, not kept waiting (#415, #386)" {
    var slots: [6]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 6500);
    learnRuns(&pool);
    var gates: [6]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    _ = named(&gates[0], burst_heavy);
    _ = named(&gates[1], burst_heavy);
    try std.testing.expectEqual(StartTag.started, named(&gates[2], burst_light));
    _ = gates[0].ended();
    // The first in line does not fit (4136 needed), a short job would. Only the short job runs.
    try setAvailable(tmp.dir, 3000);
    try std.testing.expectEqual(StartTag.wait, named(&gates[3], burst_light));
    try std.testing.expectEqual(StartTag.wait, std.meta.activeTag(gates[1].start()));
    _ = gates[2].ended();
    try std.testing.expectEqual(StartTag.forced, std.meta.activeTag(gates[1].start()));
    try std.testing.expect(!slots[1].waiting);
}

test "a job learned short that runs long delays the first in line by that run, once, and is learned long (#415)" {
    var slots: [12]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 6500);
    learnRuns(&pool);
    var gates: [12]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    // A job that is not short runs besides, so the first in line waits for more than the short one.
    try std.testing.expectEqual(StartTag.started, named(&gates[4], burst_novel));
    _ = named(&gates[0], burst_heavy);
    _ = named(&gates[1], burst_heavy);
    try std.testing.expectEqual(StartTag.started, named(&gates[2], burst_light));
    try std.testing.expectEqual(@as(?u32, 5 * std.time.ms_per_s), pool.runMs(burst_light));
    // It runs for ten minutes (it was 5 s each time before). The heavy job ends, and the machine
    // has what the first in line needs and not what the long job holds.
    const ten_minutes: i64 = 10 * 60 * std.time.ms_per_s;
    slots[2].started_ms -= ten_minutes;
    _ = gates[0].ended();
    try setAvailable(tmp.dir, 4100);
    try std.testing.expectEqual(StartTag.wait, std.meta.activeTag(gates[1].start()));
    // No more go ahead on the word of its learned time while it overruns.
    try std.testing.expectEqual(StartTag.wait, named(&gates[3], burst_light));
    try std.testing.expect(!slots[3].ahead);
    // It ends: the first in line starts, delayed by that run and no more, and the run is learned.
    slots[2].base_mb = 0;
    slots[2].peak_mb = 100;
    _ = gates[2].ended();
    try setAvailable(tmp.dir, 4700);
    try std.testing.expectEqual(StartTag.started, std.meta.activeTag(gates[1].start()));
    try std.testing.expect(pool.runMs(burst_light).? >= ten_minutes - 1000);
    try std.testing.expect(pool.runMs(burst_light).? > short_run_ms);
}

test "a poller is held while the pool's runners are half taken by waiting jobs (#415)" {
    var slots: [8]Admission.Slot = undefined;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pool = try burstPool(tmp.dir, &tmp.sub_path, &slots, 6500);
    learnRuns(&pool);
    var gates: [8]Gate = undefined;
    for (&gates, 0..) |*g, i| g.* = .{ .pool = &pool, .slot = i };
    _ = named(&gates[0], burst_heavy);
    // Four jobs wait (the first heavy, three not short): half the runners.
    _ = named(&gates[1], burst_heavy);
    for (gates[2..4]) |*g| _ = named(g, burst_novel);
    try std.testing.expect(gates[7].check() == null);
    gates[7].leave(false);
    _ = named(&gates[4], burst_novel);
    try std.testing.expect(gates[7].check().? == .memory);
}

/// Where the fixtures of a pool that keeps its estimates (#407) are: meminfo, machine-id and
/// hostname files and the gate's own file, all in `tmp`.
const KeptFixture = struct {
    meminfo: [256]u8 = undefined,
    machine_id: [256]u8 = undefined,
    hostname: [256]u8 = undefined,
    file: [256]u8 = undefined,
    sub_path: []const u8,

    fn path(f: *KeptFixture, buf: []u8, name: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/{s}", .{ f.sub_path, name }) catch "";
    }

    /// A pool on the machine `machine` with `mem_mb` of memory.
    fn pool(
        f: *KeptFixture,
        tmp: std.Io.Dir,
        slots: []Admission.Slot,
        machine: []const u8,
        mem_mb: u64,
        native: bool,
    ) !Admission {
        const io = std.testing.io;
        var text: [128]u8 = undefined;
        try tmp.writeFile(io, .{
            .sub_path = "meminfo",
            .data = try std.fmt.bufPrint(&text, "MemTotal: {d} kB\nMemAvailable: {d} kB\n", .{ mem_mb * 1024, mem_mb * 512 }),
        });
        try tmp.writeFile(io, .{ .sub_path = "machine-id", .data = machine });
        var p: Admission = .init(io, .{}, slots);
        p.paths = .{
            .meminfo = f.path(&f.meminfo, "meminfo"),
            .pressure = "/nonexistent",
            .machine_id = f.path(&f.machine_id, "machine-id"),
            .hostname = "/nonexistent",
        };
        p.native = native;
        return p;
    }

    fn stateFile(f: *KeptFixture) []const u8 {
        return f.path(&f.file, "memory-gate");
    }
};

fn expectSameLearned(want: *const Learned, got: *const Learned) !void {
    try std.testing.expectEqual(want.len, got.len);
    try std.testing.expectEqual(want.tick, got.tick);
    for (want.entries[0..want.len], got.entries[0..got.len]) |w, g| {
        try std.testing.expectEqual(w.key, g.key);
        try std.testing.expectEqual(w.used, g.used);
        for ([_][2]*const Learned.Runs{ .{ &w.alone, &g.alone }, .{ &w.beside, &g.beside }, .{ &w.ran, &g.ran } }) |r| {
            try std.testing.expectEqual(r[0].n, r[1].n);
            try std.testing.expectEqual(r[0].next, r[1].next);
            try std.testing.expectEqualSlices(u32, r[0].slice(), r[1].slice());
        }
        try std.testing.expectEqual(w.estimate(), g.estimate());
    }
}

test "a restart keeps what jobs took, natively and on the engine, in the order they were used (#407)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fix: KeptFixture = .{ .sub_path = &tmp.sub_path };
    var slots: [2]Admission.Slot = undefined;
    var first = try fix.pool(tmp.dir, &slots, "abc123\n", 8000, true);
    try std.testing.expectEqual(Restore.absent, first.restore(fix.stateFile()));
    // Seven runs of one name (the last five count), a name seen beside others, and a native one.
    for ([_]u32{ 900, 1200, 600, 2600, 700, 800, 650 }) |mb| _ = first.learned_native.record(burst_heavy, mb, true);
    _ = first.learned.record(burst_light, 300, false);
    _ = first.learned.record(burst_heavy, 1600, true);
    // How long they ran: the longest of the last five counts, 270 s.
    for ([_]i64{ 90_000, 270_000, 4_000 }) |ms| first.learned_native.recordRun(burst_heavy, ms);
    first.learned.recordRun(burst_light, 2_500);
    // Used since: the light name is the one least recently used now.
    _ = first.learned.estimate(burst_heavy);
    first.persist.?.dirty = true;
    first.flush();
    try std.testing.expect(!first.persist.?.dirty);

    var second_slots: [2]Admission.Slot = undefined;
    var second = try fix.pool(tmp.dir, &second_slots, "abc123\n", 8000, true);
    try std.testing.expectEqual(Restore{ .loaded = 3 }, second.restore(fix.stateFile()));
    try expectSameLearned(&first.learned, &second.learned);
    try expectSameLearned(&first.learned_native, &second.learned_native);
    // The estimate that reserves: the most of the last five runs, 2600.
    try std.testing.expectEqual(@as(?u32, 2600), second.learned_native.estimate(burst_heavy));
    try std.testing.expectEqual(@as(u32, 2600), second.nativeEstimate(burst_heavy));
    try std.testing.expectEqual(@as(?u32, 270_000), second.runMs(burst_heavy));
    try std.testing.expectEqual(@as(?u32, 2_500), second.runMs(burst_light));
    // Least recently used goes first when the table is full, as before the restart.
    for (0..Learned.capacity - 1) |i| _ = second.learned.record(i, 100, true);
    try std.testing.expectEqual(@as(?u32, null), second.learned.estimate(burst_light));
    try std.testing.expect(second.learned.estimate(burst_heavy) != null);

    // A job's end marks the estimates changed, and the next write has them.
    var third_slots: [2]Admission.Slot = undefined;
    var third = try fix.pool(tmp.dir, &third_slots, "abc123\n", 8000, true);
    _ = third.restore(fix.stateFile());
    var gate: Gate = .{ .pool = &third, .slot = 0 };
    gate.leave(true);
    gate.assigned(burst_light);
    third.slots[0].base_mb = 0;
    third.slots[0].peak_mb = 500;
    third.slots[0].waiting = false;
    third.slots[0].started_ms -= 3_000;
    try std.testing.expect(!third.persist.?.dirty);
    _ = gate.ended();
    try std.testing.expect(third.persist.?.dirty);
    // The first write after a start goes ahead: `written_ms` is still its start value (v0.28.0
    // overflowed here and the runner panicked at its first job's end).
    third.persistNow(false);
    try std.testing.expect(!third.persist.?.dirty);
    third.persist.?.dirty = true;
    // Written at most every `min_interval_ms`; the pool's end writes the rest.
    third.persist.?.written_ms = std.Io.Clock.awake.now(std.testing.io).toMilliseconds();
    third.persistNow(false);
    try std.testing.expect(third.persist.?.dirty);
    third.flush();
    try std.testing.expect(!third.persist.?.dirty);
    var fourth_slots: [2]Admission.Slot = undefined;
    var fourth = try fix.pool(tmp.dir, &fourth_slots, "abc123\n", 8000, true);
    try std.testing.expectEqual(Restore{ .loaded = 3 }, fourth.restore(fix.stateFile()));
    try std.testing.expectEqual(@as(?u32, 500), fourth.learned.estimate(burst_light));
    // The job's run was learned too: at least the 3 s it was moved back by.
    try std.testing.expect(fourth.learned.longest(burst_light).? >= 3_000);
    try std.testing.expect(fourth.learned.longest(burst_light).? < 30_000);
}

test "a file from another machine, memory, backend or format, or a damaged one, is not used (#407)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var fix: KeptFixture = .{ .sub_path = &tmp.sub_path };
    var slots: [2]Admission.Slot = undefined;
    var writer = try fix.pool(tmp.dir, &slots, "abc123\n", 8000, true);
    _ = writer.restore(fix.stateFile());
    _ = writer.learned_native.record(burst_heavy, 2600, true);
    writer.persist.?.dirty = true;
    writer.flush();
    var good: [file_max_bytes]u8 = undefined;
    const text = try std.Io.Dir.cwd().readFile(io, fix.stateFile(), &good);
    try std.testing.expect(std.mem.startsWith(u8, text, "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native "));

    const Case = struct { machine: []const u8, mem_mb: u64, native: bool, why: []const u8 };
    const cases = [_]Case{
        .{ .machine = "other", .mem_mb = 8000, .native = true, .why = "it was written on another machine" },
        .{ .machine = "abc123", .mem_mb = 16000, .native = true, .why = "the machine's memory is not what it was" },
        .{ .machine = "abc123", .mem_mb = 8000, .native = false, .why = "it was written by another backend" },
    };
    for (cases) |case| {
        var s: [2]Admission.Slot = undefined;
        var reader = try fix.pool(tmp.dir, &s, case.machine, case.mem_mb, case.native);
        const got = reader.restore(fix.stateFile());
        try std.testing.expectEqualStrings(case.why, got.ignored);
        try std.testing.expectEqual(@as(usize, 0), reader.learned_native.len + reader.learned.len);
    }
    // A little less memory after a boot is the same machine.
    var s: [2]Admission.Slot = undefined;
    var again = try fix.pool(tmp.dir, &s, "abc123\n", 7900, true);
    try std.testing.expectEqual(Restore{ .loaded = 1 }, again.restore(fix.stateFile()));

    const bad = [_]struct { []const u8, []const u8 }{
        // The last format, without the run times: not used, and warned of.
        .{ "zig-runner memory gate v1\nmachine abc123\nmemory_mb 8000\nbackend native\ne native 0000000000000001 1 A 1 1 5 B 0 0\n", "it is in another format version" },
        .{ "", "it is not a memory gate file, or is damaged" },
        // A run time over what is kept, and an entry without the run times.
        .{ "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native 0000000000000001 1 A 0 0 B 0 0 R 1 1 1073741825\n", "it is not a memory gate file, or is damaged" },
        .{ "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native 0000000000000001 1 A 0 0 B 0 0\n", "it is not a memory gate file, or is damaged" },
        .{ "not a gate file at all\n", "it is not a memory gate file, or is damaged" },
        .{ "zig-runner memory gate v2\nmachine abc123\n", "it is not a memory gate file, or is damaged" },
        .{ text[0 .. text.len - 9], "it is not a memory gate file, or is damaged" },
        .{ "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native zz 1 A 0 0 B 0 0 R 0 0\n", "it is not a memory gate file, or is damaged" },
        .{ "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native 0000000000000001 1 A 6 0 B 0 0 R 0 0\n", "it is not a memory gate file, or is damaged" },
        .{ "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native 0000000000000001 1 A 1 0 1 B 0 0 R 0 0\n", "it is not a memory gate file, or is damaged" },
        .{ "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native 0000000000000001 1 A 1 1 5 B 0 0 R 0 0\ne native 0000000000000001 2 A 1 1 5 B 0 0 R 0 0\n", "it is not a memory gate file, or is damaged" },
        .{ "zig-runner memory gate v2\nmachine abc123\nmemory_mb 8000\nbackend native\ne native 0000000000000001 1 A 1 1 99999999999 B 0 0 R 0 0\n", "it is not a memory gate file, or is damaged" },
    };
    for (bad) |case| {
        try tmp.dir.writeFile(io, .{ .sub_path = "memory-gate", .data = case[0] });
        var s2: [2]Admission.Slot = undefined;
        var reader = try fix.pool(tmp.dir, &s2, "abc123\n", 8000, true);
        const got = reader.restore(fix.stateFile());
        try std.testing.expectEqualStrings(case[1], got.ignored);
        // Nothing of a damaged file is kept, and the next write replaces it.
        try std.testing.expectEqual(@as(usize, 0), reader.learned_native.len);
        reader.persist.?.dirty = true;
        reader.flush();
        var s3: [2]Admission.Slot = undefined;
        var next = try fix.pool(tmp.dir, &s3, "abc123\n", 8000, true);
        try std.testing.expectEqual(Restore{ .loaded = 0 }, next.restore(fix.stateFile()));
    }
}

test "an atomic write leaves the old file or the whole new one, never half, and no temp file (#407)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var buf: [256]u8 = undefined;
    const dir = try std.fmt.bufPrint(&buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/state/memory-gate", .{dir});
    // The directory is made, the file is whole.
    try writeFileAtomic(io, path, "old");
    var read_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("old", try std.Io.Dir.cwd().readFile(io, path, &read_buf));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "state/memory-gate.tmp", .{}));
    try writeFileAtomic(io, path, "new and longer");
    try std.testing.expectEqualStrings("new and longer", try std.Io.Dir.cwd().readFile(io, path, &read_buf));
    try writeFileAtomic(io, path, "short");
    try std.testing.expectEqualStrings("short", try std.Io.Dir.cwd().readFile(io, path, &read_buf));

    // The rename fails (the target is a directory that is not empty): the old thing is as it was,
    // and the temp file is gone.
    try tmp.dir.createDirPath(io, "state/blocked/inside");
    var blocked_buf: [256]u8 = undefined;
    const blocked = try std.fmt.bufPrint(&blocked_buf, "{s}/state/blocked", .{dir});
    try std.testing.expect(std.meta.isError(writeFileAtomic(io, blocked, "whole")));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "state/blocked.tmp", .{}));
    try std.testing.expect((try tmp.dir.statFile(io, "state/blocked/inside", .{})).kind == .directory);

    // The temp file cannot be made (a directory is in its place): the old file stands.
    try tmp.dir.createDirPath(io, "state/memory-gate.tmp");
    try std.testing.expect(std.meta.isError(writeFileAtomic(io, path, "lost")));
    try std.testing.expectEqualStrings("short", try std.Io.Dir.cwd().readFile(io, path, &read_buf));
}

test "a failed write is warned of once and tried again, and the estimates stay in memory (#407)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fix: KeptFixture = .{ .sub_path = &tmp.sub_path };
    var slots: [2]Admission.Slot = undefined;
    var pool = try fix.pool(tmp.dir, &slots, "abc123\n", 8000, true);
    _ = pool.restore(fix.stateFile());
    // Something is in the way of the temp file.
    try tmp.dir.createDirPath(std.testing.io, "memory-gate.tmp");
    _ = pool.learned_native.record(burst_heavy, 2600, true);
    pool.persist.?.dirty = true;
    pool.flush();
    try std.testing.expect(pool.persist.?.dirty);
    try std.testing.expect(pool.persist.?.warned);
    try std.testing.expectEqual(@as(?u32, 2600), pool.learned_native.estimate(burst_heavy));
    try tmp.dir.deleteDir(std.testing.io, "memory-gate.tmp");
    pool.flush();
    try std.testing.expect(!pool.persist.?.dirty);
    try std.testing.expect(!pool.persist.?.warned);
}

/// A pool with `MemTotal` of `total_mb`, for what one job needs against it (#406).
fn fitPool(tmp: std.Io.Dir, sub_path: []const u8, slots: []Admission.Slot, total_mb: u64, limits: Limits) !Admission {
    const Fix = struct {
        var buf: [256]u8 = undefined;
    };
    var text: [64]u8 = undefined;
    try tmp.writeFile(std.testing.io, .{
        .sub_path = "meminfo",
        .data = try std.fmt.bufPrint(&text, "MemTotal: {d} kB\nMemAvailable: {d} kB\n", .{ total_mb * 1024, total_mb * 1024 }),
    });
    var pool: Admission = .init(std.testing.io, limits, slots);
    pool.paths = .{
        .meminfo = try std.fmt.bufPrint(&Fix.buf, ".zig-cache/tmp/{s}/meminfo", .{sub_path}),
        .pressure = "/nonexistent",
        .self_cgroup = "/nonexistent",
    };
    return pool;
}

test "a reservation that can never fit is named at start, with the setting and the numbers (#406)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var slots: [2]Admission.Slot = undefined;
    // The laptop benchmark: RUNNER_NATIVE_MEM_PER_JOB_MB=24000 on a machine with 18.6 GB.
    var pool = try fitPool(tmp.dir, &tmp.sub_path, &slots, 19000, .{ .native_per_job_mb = 24000 });
    pool.native = true;
    const bad = pool.misfit().?;
    var buf: [512]u8 = undefined;
    try std.testing.expectEqualStrings(
        "RUNNER_NATIVE_MEM_PER_JOB_MB=24000 plus RUNNER_MIN_MEM_AVAILABLE_MB=1536 need 25536 MB " ++
            "for one job, but the machine's memory is 19000 MB: no job could ever start, and the " ++
            "memory gate would hold every runner for ever. Lower them, or turn the gate off with " ++
            "RUNNER_ADMISSION=false",
        try std.fmt.bufPrint(&buf, "{f}", .{bad}),
    );
    // The floor alone can be the setting that does not fit.
    var floor = try fitPool(tmp.dir, &tmp.sub_path, &slots, 4000, .{ .min_available_mb = 4000, .native_per_job_mb = 256 });
    floor.native = true;
    try std.testing.expectEqualStrings("RUNNER_MIN_MEM_AVAILABLE_MB", floor.misfit().?.floor_setting);
    // The Dagger pool's setting.
    var dagger = try fitPool(tmp.dir, &tmp.sub_path, &slots, 2000, .{});
    try std.testing.expectEqualStrings("RUNNER_MEM_PER_JOB_MB", dagger.misfit().?.setting);
    // The defaults fit anywhere that runs jobs at all, and the gate off (0) never is a misfit.
    var fits = try fitPool(tmp.dir, &tmp.sub_path, &slots, 8000, .{});
    try std.testing.expectEqual(@as(?Misfit, null), fits.misfit());
    fits.native = true;
    try std.testing.expectEqual(@as(?Misfit, null), fits.misfit());
    var off = try fitPool(tmp.dir, &tmp.sub_path, &slots, 100, .{ .min_available_mb = 0, .per_job_mb = 0, .native_per_job_mb = 0 });
    try std.testing.expectEqual(@as(?Misfit, null), off.misfit());
}

test "the cgroup limit the runner runs under, and the engine's cap, are compared too (#406)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var slots: [2]Admission.Slot = undefined;
    var pool = try fitPool(tmp.dir, &tmp.sub_path, &slots, 8000, .{ .per_job_mb = 1600, .native_per_job_mb = 1600 });
    var root_buf: [256]u8 = undefined;
    var own_buf: [256]u8 = undefined;
    var self_buf: [256]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}/cg", .{tmp.sub_path});
    // A service with MemoryMax=2G: 1600 + 1536 MB do not fit in 2048.
    try tmp.dir.createDirPath(io, "cg/system.slice/runner.service");
    try tmp.dir.writeFile(io, .{ .sub_path = "cg/system.slice/memory.max", .data = "2147483648\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "cg/system.slice/runner.service/memory.max", .data = "max\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "self-cgroup", .data = "0::/system.slice/runner.service\n" });
    pool.paths.cgroup_root = root;
    pool.paths.self_cgroup = try std.fmt.bufPrint(&self_buf, ".zig-cache/tmp/{s}/self-cgroup", .{tmp.sub_path});
    pool.native = true;
    const bad = pool.misfit().?;
    try std.testing.expectEqualStrings("the memory limit the runner runs under is", bad.against);
    try std.testing.expectEqual(@as(u64, 2048), bad.limit_mb);
    // No cap above it: the machine's 8000 MB it is.
    try tmp.dir.writeFile(io, .{ .sub_path = "cg/system.slice/memory.max", .data = "max\n" });
    try std.testing.expectEqual(@as(?Misfit, null), pool.misfit());

    // On the engine, one job and the headroom must fit under the engine's cap, 4096 MB.
    pool.native = false;
    pool.limits.per_job_mb = 4000;
    pool.engine.dir = try std.fmt.bufPrint(&own_buf, ".zig-cache/tmp/{s}/engine", .{tmp.sub_path});
    try setEngine(tmp.dir, 0);
    const engine_bad = pool.misfit().?;
    try std.testing.expectEqualStrings("the engine's memory cap is", engine_bad.against);
    try std.testing.expectEqual(@as(u64, 4096), engine_bad.limit_mb);
    try std.testing.expectEqualStrings("RUNNER_MIN_ENGINE_HEADROOM_MB", engine_bad.floor_setting);
    // A native job never runs in the engine: its cap is not the native pool's concern.
    pool.native = true;
    pool.limits.native_per_job_mb = 256;
    try std.testing.expectEqual(@as(?Misfit, null), pool.misfit());
}
