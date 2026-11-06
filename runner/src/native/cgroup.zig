//! A cgroup v2 per native job (docs/native-backend.md, P4): `memory.max` and `pids.max` hold a
//! runaway job inside its own limits, so a memory hog is OOM-killed in its own cgroup and a fork
//! bomb stops at its own process limit, without touching its neighbours; `memory.current` and
//! `memory.stat` give the memory gate (`admission.zig`) the job's own working set, where the
//! Dagger engine's one cgroup charges every job running for all of them; and `memory.high`, from
//! what the gate reserves for the job (`Job.setHigh`), slows a job that outgrows that before it
//! takes its neighbours' memory, below `memory.max`, which kills. That needs swap: with none,
//! there is nothing to reclaim its memory into, and it stops dead (`canSwap`).
//!
//! Each step's helper joins the job's cgroup before it does anything else (`sandbox.zig`), so
//! every process of the step is born in it; the runner never is. Between steps the cgroup is
//! empty and kept: its peak and events are the job's, across its steps.
//!
//! All jobs together are bounded on their parent (`Limits`, `Job.make`): a job's own limit cannot
//! stop two jobs at once from taking the machine. Page cache counts towards these limits and is
//! reclaimed at them, and swap is off below the parent, so a job past its memory is killed in its
//! own tree instead of taking the machine into swap (#367). The parent is always the runner's own
//! cgroup, never one an operator configured (`resolve`), and its limits are not changed under
//! running jobs (`limitAll`).
//!
//! Where the jobs' cgroups go (`parent`, `RUNNER_NATIVE_CGROUP`):
//! - On a root runner, by default, a tree of the runner's own at `/sys/fs/cgroup/zig-runner`, as
//!   Docker's cgroupfs driver makes `/sys/fs/cgroup/docker`. It is the host's, like the slots'
//!   locks: every runner on a host makes its jobs' cgroups there, each named by its job's
//!   directory (random, so never two alike), and only the runner that holds a job's lock removes
//!   its cgroup (`Backend.sweep`). A root runner at the root of a cgroup namespace (a container's)
//!   cannot make it, as that root holds processes, and takes `self` instead (`resolve`).
//! - `self`: the runner's own cgroup, delegated to it (systemd's `Delegate=yes`, or
//!   `systemd-run --user --scope -p Delegate=yes` for a rootless runner). The runner moves its
//!   own processes into a leaf (`runner`) and makes the jobs' cgroups under `jobs`, as systemd's
//!   delegation rules ask: a cgroup that gives its children controllers holds no process itself.
//!   In a container with a cgroup namespace of its own, the container's root is its cgroup, and
//!   `self` works there too.
//! - A path under /sys/fs/cgroup: that cgroup, made if missing, with the jobs under a `jobs` child
//!   of it. The path is the operator's, and any limit on it (a slice's `MemoryMax=`) is theirs: the
//!   runner writes none there, and theirs holds over everything under it.
//! - `none`: no cgroup, on the operator's word: the job runs unbounded, and "Set up job" says so
//!   plainly. Nothing else runs a job without limits: a rootless runner without `self`, or a
//!   parent that cannot be made, sends it to Dagger, or fails it where there is no engine
//!   (`Backend.jobCgroup`).

const std = @import("std");
const linux = std.os.linux;
const admission = @import("../admission.zig");

const Allocator = std.mem.Allocator;

/// Where the cgroup v2 hierarchy is mounted.
pub const mount_point = "/sys/fs/cgroup";
/// The jobs' tree on a root runner when `RUNNER_NATIVE_CGROUP` names none.
pub const default_parent = mount_point ++ "/zig-runner";
/// `pids.max` by default: well above what a build's processes and threads reach (`zig build
/// test` on 16 cores runs about 100, a browser test suite a few hundred), and far below what lets
/// a fork bomb take a machine. Every thread counts.
pub const default_pids_max: u32 = 8192;
/// How many jobs' `pids.max` all jobs together may hold (`Limits.pids_total`): a pool's jobs reach
/// a few hundred each, and this keeps four fork bombs at once short of a machine's `threads-max`
/// (about 60 000 on 8 GB).
pub const pids_total_jobs = 4;
/// The most `pids.max` takes (`PID_MAX_LIMIT` on 64 bits): more would be refused, and the job with
/// it.
const pids_limit: u32 = 4 << 20;
/// What the machine keeps from native jobs, at the least and at the most (`totalOf`).
const reserve_min: u64 = 2 << 30;
const reserve_max: u64 = 12 << 30;
/// The machine's memory when /proc/meminfo cannot be read: a bound that is too small fails a large
/// job and says so; none takes the machine down.
const assumed_memory: u64 = 4 << 30;

/// What the runner configures.
pub const Config = struct {
    /// `RUNNER_NATIVE_CGROUP`: "" (the default above), "self", "none", or a cgroup's path.
    parent: []const u8 = "",
    /// `RUNNER_NATIVE_MEMORY_MAX_MB`: each job's `memory.max`; null for two thirds of all jobs'
    /// together, 0 for no limit.
    memory_max_mb: ?u32 = null,
    /// `RUNNER_NATIVE_MEMORY_TOTAL_MB`: all jobs' under the parent together; null for what
    /// `totalOf` leaves, 0 for no limit.
    memory_total_mb: ?u32 = null,
    /// `RUNNER_NATIVE_SWAP`: whether jobs may swap (`memory.swap.max` on the parent).
    swap: bool = false,
    /// `RUNNER_NATIVE_PIDS_MAX`: each job's `pids.max`, and `pids_total_jobs` times it for all
    /// jobs together; 0 for no limit.
    pids_max: u32 = default_pids_max,
};

/// The limits of a job and of all jobs under its parent, as written: null is `max`.
pub const Limits = struct {
    memory_max: ?u64,
    pids_max: ?u32,
    memory_total: ?u64 = null,
    pids_total: ?u32 = null,
    swap: bool = false,

    /// From the configuration and, for the defaults, the memory jobs under `parent_dir` can have
    /// (`memoryUnder`): null when there is no parent to look above.
    pub fn of(io: std.Io, cfg: Config, parent_dir: ?[]const u8) Limits {
        return compute(cfg, memoryUnder(io, mount_point, parent_dir));
    }

    /// An operator's number always wins, and 0 is theirs to give: an explicit per-job limit above
    /// the default total raises the total with it, and "no limit" on a job leaves all jobs without
    /// one too, unless `memory_total_mb` says otherwise. The default depends on the machine alone,
    /// so every runner sharing a parent and these settings writes the same numbers on it.
    pub fn compute(cfg: Config, memory: ?u64) Limits {
        const fair = totalOf(memory orelse assumed_memory);
        const set_total: ?u64 = if (cfg.memory_total_mb) |mb|
            (if (mb == 0) null else @as(u64, mb) << 20)
        else
            fair;
        const job: ?u64 = if (cfg.memory_max_mb) |mb|
            (if (mb == 0) null else @as(u64, mb) << 20)
        else
            (set_total orelse fair) / 3 * 2;
        const total: ?u64 = if (cfg.memory_total_mb != null)
            set_total
        else if (job) |j| @max(fair, j) else null;
        return .{
            .memory_max = job,
            .pids_max = if (cfg.pids_max == 0) null else @min(cfg.pids_max, pids_limit),
            .memory_total = total,
            .pids_total = if (cfg.pids_max == 0)
                null
            else
                @min(cfg.pids_max *| pids_total_jobs, pids_limit),
            .swap = cfg.swap,
        };
    }
};

/// What all native jobs may hold of `memory` by default: a third is kept for the rest of the
/// machine (the runner, the engine, a desktop), at least 2 GiB and at most 12 GiB so that a small
/// machine stays usable and a large one is not wasted, and jobs get at least half whatever the
/// reserve says. 20 GiB of a 30 GiB laptop, 5.3 GiB of an 8 GiB Pi, and each job two thirds of
/// that (`Limits.compute`): 3.6 GiB on the Pi, 3.15 GiB under razorbill's `MemoryMax=90%`, above
/// the 2.4 GB of anonymous memory its build reaches, while a job that runs away still leaves its
/// neighbours a third. Whatever else the machine runs is not known here: an engine beside the
/// jobs is not subtracted, as razorbill's 4 GB cap would leave a job less than that build.
fn totalOf(memory: u64) u64 {
    const reserve = std.math.clamp(memory / 3, reserve_min, reserve_max);
    return @max(memory -| reserve, memory / 2);
}

/// The memory jobs under `parent_dir` can have: the machine's, or the tightest `memory.max` above
/// the parent, where something put the runner in a container or a slice with a limit of its own
/// (in a cgroup namespace, `mount` itself is that container's). The parent's own is left out: it
/// is the runner's, written from this. A path's `MemoryMax=` is above it, so it counts here.
fn memoryUnder(io: std.Io, mount: []const u8, parent_dir: ?[]const u8) ?u64 {
    var least = memTotal(io);
    var at = parent_dir orelse return least;
    while (std.fs.path.dirname(at)) |up| : (at = up) {
        if (up.len < mount.len) break;
        const cap = admission.readCgroupBytes(io, up, "memory.max") orelse continue;
        least = if (least) |l| @min(l, cap) else cap;
    }
    return least;
}

/// `MemTotal` in /proc/meminfo, in bytes.
fn memTotal(io: std.Io) ?u64 {
    return meminfo(io, "MemTotal:");
}

/// A field of /proc/meminfo, in bytes.
fn meminfo(io: std.Io, key: []const u8) ?u64 {
    var buf: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, "/proc/meminfo", &buf) catch return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        var words = std.mem.tokenizeScalar(u8, line[key.len..], ' ');
        const kb = std.fmt.parseInt(u64, words.next() orelse return null, 10) catch return null;
        return kb * 1024;
    }
    return null;
}

/// Whether the jobs' anonymous memory can be reclaimed at all: they may swap and the machine has
/// somewhere to. Without it `memory.high` does not slow a job past it, it stops it: the kernel has
/// nothing to reclaim, so each allocation waits and fails to free anything, and nothing kills the
/// job. A hog at a 50 MiB `memory.high` under a 300 MiB `memory.max`, swap 0, reached 50 MiB in
/// 7 s and not 55 in the next 100, with no OOM event. `memory.max` is what ends such a job, so
/// it is left to (`Backend.jobCgroup`, `Gate.noHigh`).
pub fn canSwap(all: All, io: std.Io) bool {
    return all.swap and (meminfo(io, "SwapTotal:") orelse 0) > 0;
}

/// Where this runner's jobs' cgroups go, or why they have none.
pub const Parent = union(enum) { dir: []const u8, none: []const u8 };

/// `resolve`d once per process for each setting when it is found (a `self` moves the runner's
/// processes once), and kept in buffers of its own, since the arena it came from is a job's. A
/// parent not found is looked for again at the next job: a cgroup made late, or a controller
/// given since, is then taken.
pub fn parent(arena: Allocator, io: std.Io, want: []const u8) Parent {
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    if (cache.found and std.mem.eql(u8, cache.want(), want)) return cache.get();
    const found = resolve(arena, io, want);
    if (found == .none) return found;
    cache.put(want, found);
    return cache.get();
}

var mu: std.Io.Mutex = .init;
var cache: Cache = .{};

const Cache = struct {
    found: bool = false,
    is_dir: bool = false,
    want_buf: [512]u8 = undefined,
    want_len: usize = 0,
    text_buf: [1024]u8 = undefined,
    len: usize = 0,

    fn want(c: *const Cache) []const u8 {
        return c.want_buf[0..c.want_len];
    }

    fn get(c: *const Cache) Parent {
        const text = c.text_buf[0..c.len];
        return if (c.is_dir) .{ .dir = text } else .{ .none = text };
    }

    fn put(c: *Cache, w: []const u8, p: Parent) void {
        c.found = true;
        c.want_len = @min(w.len, c.want_buf.len);
        @memcpy(c.want_buf[0..c.want_len], w[0..c.want_len]);
        const text = switch (p) {
            .dir, .none => |t| t,
        };
        // A directory cut short would be another one: none, then.
        c.is_dir = p == .dir and text.len <= c.text_buf.len;
        const keep: []const u8 = if (p == .dir and !c.is_dir) "its path is too long" else text;
        c.len = @min(keep.len, c.text_buf.len);
        @memcpy(c.text_buf[0..c.len], keep[0..c.len]);
    }
};

/// The text "Set up job" gives a rootless runner without a cgroup to delegate.
pub const not_delegated = "the runner is not root and RUNNER_NATIVE_CGROUP does not name a " ++
    "cgroup delegated to it (`self` under `systemd-run --user --scope -p Delegate=yes`, or a " ++
    "unit with `Delegate=yes`)";

fn resolve(arena: Allocator, io: std.Io, want: []const u8) Parent {
    if (std.mem.eql(u8, want, "none")) return .{ .none = "RUNNER_NATIVE_CGROUP=none" };
    if (!isCgroup2(arena, mount_point)) return .{ .none = "there is no cgroup v2 hierarchy " ++
        "at " ++ mount_point };
    var self = std.mem.eql(u8, want, "self");
    if (want.len == 0) {
        if (linux.geteuid() != 0) return .{ .none = not_delegated };
        // A root that holds processes is a cgroup namespace's: the host's may hold them and still
        // give its children controllers. It takes the setting a container needs (`self`), which
        // moves nothing but what is in the namespace, so that it works without being told.
        ensure(arena, default_parent) catch |e| {
            if (e != error.HasProcesses or !atNamespaceRoot(io))
                return cannotHold(arena, default_parent, e);
            _ = linux.rmdir(default_parent);
            self = true;
        };
        if (!self) return .{ .dir = default_parent };
    }
    const dir: []const u8 = if (self)
        selfParent(arena, io) catch |e| return .{ .none = std.fmt.allocPrint(
            arena,
            "the runner's own cgroup cannot hold its jobs' ({s}): is it delegated to the runner?",
            .{@errorName(e)},
        ) catch "the runner's own cgroup cannot hold its jobs'" }
    else dir: {
        if (!within(want)) return .{ .none = "RUNNER_NATIVE_CGROUP is not a cgroup's path " ++
            "under " ++ mount_point };
        // The operator's: its limits stay theirs, and the runner's go on a child of its own.
        ensure(arena, want) catch |e| return cannotHold(arena, want, e);
        break :dir std.fmt.allocPrint(arena, "{s}/jobs", .{want}) catch
            return .{ .none = "the jobs' cgroup parent cannot be made" };
    };
    ensure(arena, dir) catch |e| return cannotHold(arena, dir, e);
    return .{ .dir = dir };
}

fn cannotHold(arena: Allocator, dir: []const u8, e: anyerror) Parent {
    return .{ .none = std.fmt.allocPrint(
        arena,
        "{s} cannot hold the jobs' cgroups ({s}: {s})",
        .{ dir, @errorName(e), explain(e) },
    ) catch "the jobs' cgroup parent cannot be made" };
}

/// Whether this process is at the root of its cgroup namespace: `/proc/self/cgroup` says `/`.
fn atNamespaceRoot(io: std.Io) bool {
    var buf: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, "/proc/self/cgroup", &buf) catch return false;
    return isRootCgroup(text);
}

fn isRootCgroup(proc_self_cgroup: []const u8) bool {
    var lines = std.mem.splitScalar(u8, proc_self_cgroup, '\n');
    while (lines.next()) |line| if (std.mem.eql(u8, line, "0::/")) return true;
    return false;
}

/// Whether `path` is a cgroup's below the mount point, through no `.` or `..`.
pub fn within(path: []const u8) bool {
    if (!std.mem.startsWith(u8, path, mount_point ++ "/")) return false;
    var parts = std.mem.splitScalar(u8, path[mount_point.len + 1 ..], '/');
    while (parts.next()) |p| {
        if (p.len == 0 or std.mem.eql(u8, p, ".") or std.mem.eql(u8, p, "..")) return false;
    }
    return true;
}

fn explain(e: anyerror) []const u8 {
    return switch (e) {
        error.ControllersUnavailable => "its parent does not give it the memory and pids " ++
            "controllers",
        error.HasProcesses => "processes run in it, and a cgroup that gives its children " ++
            "controllers may hold none (RUNNER_NATIVE_CGROUP=self moves the runner's into a leaf)",
        error.AccessDenied => "the runner may not write it (Docker mounts cgroups read-only " ++
            "without `privileged: true` or `security_opt: [writable-cgroups=true]`)",
        else => "see the error",
    };
}

/// Whether a cgroup v2 hierarchy is mounted at `path` (`CGROUP2_SUPER_MAGIC`).
fn isCgroup2(arena: Allocator, path: []const u8) bool {
    var st: [120]u8 align(8) = undefined;
    const p = arena.dupeSentinel(u8, path, 0) catch return false;
    if (linux.errno(linux.syscall2(.statfs, @intFromPtr(p.ptr), @intFromPtr(&st))) != .SUCCESS)
        return false;
    // `struct statfs`'s `f_type`, first, a long on x86_64 and aarch64.
    return std.mem.readInt(u64, st[0..8], .little) == 0x63677270;
}

/// The runner's own cgroup made the jobs' parent: its processes moved into `<own>/runner`, the
/// memory and pids controllers given to its children, and `<own>/jobs` returned.
fn selfParent(arena: Allocator, io: std.Io) ![]const u8 {
    var buf: [4096]u8 = undefined;
    const text = try std.Io.Dir.cwd().readFile(io, "/proc/self/cgroup", &buf);
    var lines = std.mem.splitScalar(u8, text, '\n');
    const rel = while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "0::")) break line[3..];
    } else return error.NoCgroupV2;
    const own = if (std.mem.eql(u8, rel, "/"))
        mount_point
    else
        try std.fmt.allocPrint(arena, "{s}{s}", .{ mount_point, rel });
    const leaf = try std.fmt.allocPrint(arena, "{s}/runner", .{own});
    try mkdir(arena, leaf);
    // Processes may be forked while they are moved: a few rounds, until none is left.
    for (0..10) |_| {
        var procs_buf: [64 * 1024]u8 = undefined;
        const procs = try readIn(io, own, "cgroup.procs", &procs_buf);
        var pids = std.mem.tokenizeScalar(u8, procs, '\n');
        var moved = false;
        while (pids.next()) |pid| {
            moved = true;
            switch (write(arena, leaf, "cgroup.procs", pid)) {
                // Gone since it was listed, or a kernel thread that stays where it is.
                .SUCCESS, .SRCH, .INVAL => {},
                .ACCES, .PERM => return error.AccessDenied,
                else => return error.MoveFailed,
            }
        }
        if (!moved) break;
    }
    try enable(arena, own);
    const jobs = try std.fmt.allocPrint(arena, "{s}/jobs", .{own});
    try mkdir(arena, jobs);
    return jobs;
}

/// `dir` made if missing, with the memory and pids controllers for its children; when its parent
/// does not give it them, asked of the parent once (the hierarchy's root has no processes to
/// forbid it).
fn ensure(arena: Allocator, dir: []const u8) !void {
    try mkdir(arena, dir);
    if (!try hasControllers(arena, dir, "cgroup.controllers")) {
        try enable(arena, std.fs.path.dirname(dir) orelse return error.ControllersUnavailable);
        if (!try hasControllers(arena, dir, "cgroup.controllers"))
            return error.ControllersUnavailable;
    }
    try enable(arena, dir);
}

/// The memory and pids controllers given to `dir`'s children.
fn enable(arena: Allocator, dir: []const u8) !void {
    if (try hasControllers(arena, dir, "cgroup.subtree_control")) return;
    switch (write(arena, dir, "cgroup.subtree_control", "+memory +pids")) {
        .SUCCESS => {},
        .BUSY => return error.HasProcesses,
        .NOENT => return error.ControllersUnavailable,
        .ACCES, .PERM => return error.AccessDenied,
        else => return error.EnableFailed,
    }
}

fn hasControllers(arena: Allocator, dir: []const u8, file: []const u8) !bool {
    var buf: [512]u8 = undefined;
    const text = readRaw(arena, dir, file, &buf) orelse return error.NotACgroup;
    var memory = false;
    var pids = false;
    var words = std.mem.tokenizeAny(u8, text, " \n");
    while (words.next()) |w| {
        memory = memory or std.mem.eql(u8, w, "memory");
        pids = pids or std.mem.eql(u8, w, "pids");
    }
    return memory and pids;
}

fn mkdir(arena: Allocator, dir: []const u8) !void {
    const p = try arena.dupeSentinel(u8, dir, 0);
    switch (linux.errno(linux.mkdir(p, 0o755))) {
        .SUCCESS, .EXIST => {},
        .ACCES, .PERM, .ROFS => return error.AccessDenied,
        .NOENT => return error.NotACgroup,
        else => return error.MakeFailed,
    }
}

/// All jobs' limits on their parent as they stand, which `Job.make` reports and "Set up job" says.
pub const All = struct {
    memory: ?u64 = null,
    pids: ?u32 = null,
    /// Jobs may swap: `memory.swap.max` is not 0.
    swap: bool = false,
    /// The kernel accounts for swap (`swapaccount=0`, or one without it, has no file): without it
    /// jobs swap whatever `swap` asks, and memory is still bounded.
    accounted: bool = true,
    /// They are not what this runner is set to: other limits were found with jobs running under
    /// them, and left.
    kept: bool = false,
};

/// All jobs' limits, on their parent: hierarchical, so they hold whatever a job's own say, and
/// over every runner on the parent. Checked for each job, so a restart with another setting takes
/// effect at its first job. Never changed under running jobs: a lower `memory.max` over what they
/// hold kills them there and then (40 MiB over a job holding 100 was killed, the write
/// succeeding), and `max` from a runner set to no limit would take the bound from another's jobs
/// while its "Set up job" still gave one. Then what stands is left and reported (`All.kept`).
fn limitAll(arena: Allocator, io: std.Io, dir: []const u8, limits: Limits) !All {
    const now = readAll(io, dir);
    const wanted: All = .{
        .memory = limits.memory_total,
        .pids = limits.pids_total,
        .swap = limits.swap,
        .accounted = now.accounted,
    };
    // The kernel rounds `memory.max` down to a page, 64 KiB at the most.
    const memory_same = if (now.memory != null and wanted.memory != null)
        now.memory.? <= wanted.memory.? and wanted.memory.? - now.memory.? < 1 << 16
    else
        now.memory == null and wanted.memory == null;
    if (memory_same and now.pids == wanted.pids and (!now.accounted or now.swap == wanted.swap))
        return now;
    if (populated(io, dir)) {
        var left = now;
        left.kept = true;
        return left;
    }
    const memory = if (limits.memory_total) |m|
        try std.fmt.allocPrint(arena, "{d}", .{m})
    else
        "max";
    if (write(arena, dir, "memory.max", memory) != .SUCCESS) return error.TotalMemoryLimitFailed;
    const pids = if (limits.pids_total) |p| try std.fmt.allocPrint(arena, "{d}", .{p}) else "max";
    if (write(arena, dir, "pids.max", pids) != .SUCCESS) return error.TotalPidsLimitFailed;
    if (now.accounted and
        write(arena, dir, "memory.swap.max", if (limits.swap) "max" else "0") != .SUCCESS)
        return error.SwapLimitFailed;
    return wanted;
}

fn readAll(io: std.Io, dir: []const u8) All {
    var buf: [32]u8 = undefined;
    const swap = readIn(io, dir, "memory.swap.max", &buf) catch null;
    return .{
        .memory = admission.readCgroupBytes(io, dir, "memory.max"),
        .pids = if (admission.readCgroupBytes(io, dir, "pids.max")) |p|
            @intCast(@min(p, pids_limit))
        else
            null,
        .swap = if (swap) |t| !std.mem.eql(u8, std.mem.trim(u8, t, " \n"), "0") else true,
        .accounted = swap != null,
    };
}

/// Whether any process is in `dir`'s tree (`cgroup.events`).
fn populated(io: std.Io, dir: []const u8) bool {
    var buf: [64]u8 = undefined;
    const text = readIn(io, dir, "cgroup.events", &buf) catch return false;
    return (admission.parseStat(text, "populated") orelse 0) > 0;
}

/// One job's cgroup.
pub const Job = struct {
    dir: []const u8,
    /// All jobs' limits as they stand (`limitAll`).
    all: All = .{},

    /// `<parent>/<name>`, with the job's limits, and all jobs' on the parent. One left by a runner
    /// that died is taken over.
    pub fn make(
        arena: Allocator,
        io: std.Io,
        parent_dir: []const u8,
        name: []const u8,
        limits: Limits,
    ) !Job {
        const all = try limitAll(arena, io, parent_dir, limits);
        const dir = try std.fmt.allocPrint(arena, "{s}/{s}", .{ parent_dir, name });
        try mkdir(arena, dir);
        const j: Job = .{ .dir = dir, .all = all };
        errdefer j.remove(arena, null);
        const memory = if (limits.memory_max) |m|
            try std.fmt.allocPrint(arena, "{d}", .{m})
        else
            "max";
        if (write(arena, dir, "memory.max", memory) != .SUCCESS) return error.MemoryLimitFailed;
        const pids = if (limits.pids_max) |p| try std.fmt.allocPrint(arena, "{d}", .{p}) else "max";
        if (write(arena, dir, "pids.max", pids) != .SUCCESS) return error.PidsLimitFailed;
        return j;
    }

    /// `memory.high`, where it can slow a job (`canSwap`), from the memory gate's estimate for the
    /// job (`admission.nativeHighMb`):
    /// past it the kernel reclaims the job's memory, its page cache first, and then slows its
    /// allocations, so a job that outgrows what it reserved is held back in its own cgroup instead
    /// of taking memory its neighbours were let in against. Nothing is killed there; that is
    /// `memory.max`'s, the hard cap, above it. Returns what the kernel holds afterwards.
    pub fn setHigh(j: Job, arena: Allocator, io: std.Io, bytes: u64) !u64 {
        const text = try std.fmt.allocPrint(arena, "{d}", .{bytes});
        if (write(arena, j.dir, "memory.high", text) != .SUCCESS) return error.MemoryHighFailed;
        return admission.readCgroupBytes(io, j.dir, "memory.high") orelse error.MemoryHighFailed;
    }

    /// What the job has used so far.
    pub fn usage(j: Job, io: std.Io) Usage {
        var events_buf: [512]u8 = undefined;
        const memory_events = readIn(io, j.dir, "memory.events", &events_buf) catch "";
        const oom_kills = admission.parseStat(memory_events, "oom_kill") orelse 0;
        const ooms = admission.parseStat(memory_events, "oom") orelse 0;
        const pids_events = readIn(io, j.dir, "pids.events", &events_buf) catch "";
        var parent_buf: [512]u8 = undefined;
        const parent_dir = std.fs.path.dirname(j.dir) orelse "";
        const parent_events = readIn(io, parent_dir, "memory.events", &parent_buf) catch "";
        return .{
            .working_set_mb = admission.workingSetMb(io, j.dir),
            .peak_mb = if (admission.readCgroupBytes(io, j.dir, "memory.peak")) |b|
                b >> 20
            else
                null,
            .oom_kills = oom_kills,
            .ooms = ooms,
            .parent_ooms = admission.parseStat(parent_events, "oom") orelse 0,
            .pids_max_hits = admission.parseStat(pids_events, "max") orelse 0,
        };
    }

    /// Every process left in it killed (`cgroup.kill`, Linux 5.14; one by one before it), and the
    /// cgroup removed once they are gone. `io` null: not waited for (a failed `make`, where none
    /// ran).
    pub fn remove(j: Job, arena: Allocator, io: ?std.Io) void {
        if (write(arena, j.dir, "cgroup.kill", "1") != .SUCCESS) if (io) |i| {
            var buf: [64 * 1024]u8 = undefined;
            const procs = readIn(i, j.dir, "cgroup.procs", &buf) catch "";
            var pids = std.mem.tokenizeScalar(u8, procs, '\n');
            while (pids.next()) |p| {
                const pid = std.fmt.parseInt(linux.pid_t, p, 10) catch continue;
                _ = linux.kill(pid, .KILL);
            }
        };
        const p = arena.dupeSentinel(u8, j.dir, 0) catch return;
        // The killed processes leave the cgroup as they exit, which takes a moment.
        for (0..200) |_| {
            switch (linux.errno(linux.rmdir(p))) {
                .SUCCESS, .NOENT => return,
                .BUSY => {},
                else => break,
            }
            const i = io orelse break;
            i.sleep(.fromMilliseconds(10), .awake) catch break;
        }
        std.log.warn("native: cannot remove the job's cgroup {s}", .{j.dir});
    }
};

/// A job's use of its cgroup.
pub const Usage = struct {
    /// What the memory gate counts (`admission.workingSetMb`), now.
    working_set_mb: ?u64,
    /// `memory.peak` (Linux 5.19): the most the cgroup held, page cache included.
    peak_mb: ?u64,
    /// Processes the kernel's OOM killer ended in it (`memory.events`).
    oom_kills: u64,
    /// Times the job's own `memory.max` ran out (`memory.events`), and the parent's or anything's
    /// under it: an OOM kill with neither came from above all jobs (`Killer`).
    ooms: u64,
    parent_ooms: u64,
    /// Forks refused at `pids.max` (`pids.events`).
    pids_max_hits: u64,
};

/// Which limit an OOM kill in a job came from: `memory.events` counts `oom_kill` where the process
/// was, and `oom` where the limit ran out and above. A kill for the machine's memory, or a limit
/// above the jobs' parent, counts no `oom` here.
pub const Killer = enum {
    job,
    all,
    above,

    pub fn of(before: Usage, now: Usage) Killer {
        if (now.ooms > before.ooms) return .job;
        return if (now.parent_ooms > before.parent_ooms) .all else .above;
    }
};

/// Writes `text` into the cgroup file `dir/file`; the errno.
fn write(arena: Allocator, dir: []const u8, file: []const u8, text: []const u8) linux.E {
    const path = std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ dir, file }, 0) catch
        return .NOMEM;
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return linux.errno(fd);
    defer _ = linux.close(@intCast(fd));
    return linux.errno(linux.write(@intCast(fd), text.ptr, text.len));
}

fn readRaw(arena: Allocator, dir: []const u8, file: []const u8, buf: []u8) ?[]u8 {
    const path = std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ dir, file }, 0) catch
        return null;
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    const n = linux.read(@intCast(fd), buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return buf[0..n];
}

fn readIn(io: std.Io, dir: []const u8, name: []const u8, buf: []u8) ![]u8 {
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name });
    return std.Io.Dir.cwd().readFile(io, path, buf);
}

const gib: u64 = 1 << 30;

test "native cgroup: all jobs' limit and each job's leave the machine room, on 8 and 30 GiB" {
    // A Pi: a third kept, and razorbill's build (2.4 GB of anonymous memory) well inside a job's.
    const pi = Limits.compute(.{}, 8 * gib);
    try std.testing.expectEqual(@as(?u64, 8 * gib - 8 * gib / 3), pi.memory_total);
    try std.testing.expectEqual(@as(?u64, pi.memory_total.? / 3 * 2), pi.memory_max);
    try std.testing.expect(pi.memory_max.? >= 3 * gib);
    // What a kernel reports of an 8 GB board.
    try std.testing.expect(Limits.compute(.{}, 77 * gib / 10).memory_max.? >= 3 * gib);
    // And under deploy/zig-runner.service's `MemoryMax=90%`, with `self`.
    try std.testing.expect(Limits.compute(.{}, 693 * gib / 100).memory_max.? >= 3 * gib);
    // A 30 GiB laptop: 10 GiB kept whatever the jobs do, where one job could take 22.5 GiB, and
    // several all of it (#367). Swap is off, so that is all they get.
    const laptop = Limits.compute(.{}, 30 * gib);
    try std.testing.expectEqual(@as(?u64, 20 * gib), laptop.memory_total);
    try std.testing.expectEqual(@as(?u64, 20 * gib / 3 * 2), laptop.memory_max);
    try std.testing.expect(!laptop.swap);
    // Small and large: half at the least, 12 GiB kept at the most, and never more than the total.
    try std.testing.expectEqual(@as(?u64, 1 * gib), Limits.compute(.{}, 2 * gib).memory_total);
    try std.testing.expectEqual(@as(?u64, 2 * gib), Limits.compute(.{}, 4 * gib).memory_total);
    try std.testing.expectEqual(@as(?u64, 116 * gib), Limits.compute(.{}, 128 * gib).memory_total);
    for ([_]u64{ gib / 2, gib, 2 * gib, 8 * gib, 30 * gib, 128 * gib, 1024 * gib }) |m| {
        const l = Limits.compute(.{}, m);
        try std.testing.expect(l.memory_max.? <= l.memory_total.?);
        try std.testing.expect(l.memory_total.? < m);
    }
    // Memory that cannot be read is still a bound.
    try std.testing.expectEqual(@as(?u64, 2 * gib), Limits.compute(.{}, null).memory_total);
    // Processes too: four jobs' worth by default.
    try std.testing.expectEqual(@as(?u32, default_pids_max), pi.pids_max);
    try std.testing.expectEqual(@as(?u32, 4 * default_pids_max), pi.pids_total);
}

test "native cgroup: what the operator sets wins, and 0 is no limit" {
    // A job's limit under the default total leaves the total.
    const set = Limits.compute(.{ .memory_max_mb = 512, .pids_max = 64 }, 30 * gib);
    try std.testing.expectEqual(@as(?u64, 512 << 20), set.memory_max);
    try std.testing.expectEqual(@as(?u64, 20 * gib), set.memory_total);
    try std.testing.expectEqual(@as(?u32, 64), set.pids_max);
    try std.testing.expectEqual(@as(?u32, 256), set.pids_total);
    // One above it is honoured, the total raised with it.
    const big = Limits.compute(.{ .memory_max_mb = 28 * 1024 }, 30 * gib);
    try std.testing.expectEqual(@as(?u64, 28 * gib), big.memory_max);
    try std.testing.expectEqual(@as(?u64, 28 * gib), big.memory_total);
    // A total sets the default job's, and is kept to even under a job's limit above it.
    const total = Limits.compute(.{ .memory_total_mb = 3 * 1024 }, 30 * gib);
    try std.testing.expectEqual(@as(?u64, 3 * gib), total.memory_total);
    try std.testing.expectEqual(@as(?u64, 2 * gib), total.memory_max);
    const both = Limits.compute(.{ .memory_max_mb = 4096, .memory_total_mb = 2048 }, 30 * gib);
    try std.testing.expectEqual(@as(?u64, 4 * gib), both.memory_max);
    try std.testing.expectEqual(@as(?u64, 2 * gib), both.memory_total);
    // 0: no limit, and none on all jobs either, unless a total is set.
    const off = Limits.compute(.{ .memory_max_mb = 0, .pids_max = 0 }, 30 * gib);
    try std.testing.expect(off.memory_max == null and off.pids_max == null);
    try std.testing.expect(off.memory_total == null and off.pids_total == null);
    const no_total = Limits.compute(.{ .memory_total_mb = 0 }, 30 * gib);
    try std.testing.expect(no_total.memory_total == null);
    try std.testing.expectEqual(@as(?u64, 20 * gib / 3 * 2), no_total.memory_max);
    const job_off = Limits.compute(.{ .memory_max_mb = 0, .memory_total_mb = 1024 }, 30 * gib);
    try std.testing.expect(job_off.memory_max == null);
    try std.testing.expectEqual(@as(?u64, 1 * gib), job_off.memory_total);
    try std.testing.expect(Limits.compute(.{ .swap = true }, 8 * gib).swap);
}

test "native cgroup: the tightest limit above the parent counts, the parent's own does not" {
    const io = std.testing.io;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "unit/slice/jobs");
    const mount = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const jobs = try std.fmt.allocPrint(arena, "{s}/unit/slice/jobs", .{mount});
    const machine = memTotal(io);
    // No limit anywhere: the machine's memory.
    try std.testing.expectEqual(machine, memoryUnder(io, mount, jobs));
    try std.testing.expectEqual(machine, memoryUnder(io, mount, null));
    // The parent's own, written from this number, must not shrink it job after job.
    try tmp.dir.writeFile(io, .{ .sub_path = "unit/slice/jobs/memory.max", .data = "4096\n" });
    try std.testing.expectEqual(machine, memoryUnder(io, mount, jobs));
    // A `max` is no limit; the mount itself is one in a cgroup namespace.
    try tmp.dir.writeFile(io, .{ .sub_path = "unit/slice/memory.max", .data = "max\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "unit/memory.max", .data = "8388608\n" });
    try std.testing.expectEqual(@as(?u64, 8 << 20), memoryUnder(io, mount, jobs));
    try tmp.dir.writeFile(io, .{ .sub_path = "memory.max", .data = "4194304\n" });
    try std.testing.expectEqual(@as(?u64, 4 << 20), memoryUnder(io, mount, jobs));
}

/// A parent's files as the kernel keeps them, for `limitAll`: empty is `max`, as the kernel's would
/// read, and a write replaces what was there.
fn writeParent(t: *std.testing.TmpDir, swap: ?[]const u8, jobs_running: bool) !void {
    const io = std.testing.io;
    for ([_][]const u8{ "memory.max", "pids.max" }) |f|
        try t.dir.writeFile(io, .{ .sub_path = f, .data = "max\n\n\n\n\n\n\n\n\n\n\n\n" });
    if (swap) |text| try t.dir.writeFile(io, .{ .sub_path = "memory.swap.max", .data = text });
    try t.dir.writeFile(io, .{
        .sub_path = "cgroup.events",
        .data = if (jobs_running) "populated 1\nfrozen 0\n" else "populated 0\nfrozen 0\n",
    });
}

test "native cgroup: every job's start holds all jobs to their limits on the parent" {
    const io = std.testing.io;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // Without swap accounting there is no file: the memory is bounded all the same.
    try writeParent(&tmp, null, false);
    const limits = Limits.compute(.{ .memory_total_mb = 1024 }, 30 * gib);
    const no_account = try limitAll(arena, io, dir, limits);
    try std.testing.expect(!no_account.accounted and !no_account.kept);
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "1073741824",
        std.mem.trim(u8, try tmp.dir.readFile(io, "memory.max", &buf), "\n"),
    );
    try std.testing.expectEqualStrings(
        "32768",
        std.mem.trim(u8, try tmp.dir.readFile(io, "pids.max", &buf), "\n"),
    );
    // With it, swap is off unless the operator allows it.
    try writeParent(&tmp, "max\n", false);
    const no_swap = try limitAll(arena, io, dir, limits);
    try std.testing.expect(no_swap.accounted and !no_swap.swap);
    const off_swap = try tmp.dir.readFile(io, "memory.swap.max", &buf);
    try std.testing.expectEqualStrings("0", off_swap[0..1]);
    var allowed = limits;
    allowed.swap = true;
    try writeParent(&tmp, "0\n\n\n\n", false);
    try std.testing.expect((try limitAll(arena, io, dir, allowed)).swap);
    const on_swap = try tmp.dir.readFile(io, "memory.swap.max", &buf);
    try std.testing.expectEqualStrings("max", on_swap[0..3]);
    // The operator's no limit takes an old limit away, with no job there.
    try writeParent(&tmp, "0\n", false);
    try tmp.dir.writeFile(io, .{ .sub_path = "memory.max", .data = "4096\n" });
    const off = try limitAll(arena, io, dir, Limits.compute(.{
        .memory_total_mb = 0,
        .pids_max = 0,
    }, 30 * gib));
    try std.testing.expect(off.memory == null and off.pids == null and !off.kept);
    try std.testing.expectEqualStrings("max", (try tmp.dir.readFile(io, "memory.max", &buf))[0..3]);
    // A parent that takes no limit is not one to run jobs under.
    try tmp.dir.deleteFile(io, "memory.max");
    try std.testing.expectError(error.TotalMemoryLimitFailed, limitAll(arena, io, dir, limits));
}

test "native cgroup: all jobs' limits are not changed under running jobs" {
    const io = std.testing.io;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var buf: [32]u8 = undefined;
    // Another pool's jobs run under 2 GiB, and no swap.
    const theirs = "2147483648\n";
    try writeParent(&tmp, "0\n", true);
    try tmp.dir.writeFile(io, .{ .sub_path = "memory.max", .data = theirs });
    try tmp.dir.writeFile(io, .{ .sub_path = "pids.max", .data = "32768\n" });
    // Lower would kill them, and no limit would take theirs away: neither is written, and the
    // job is told what stands.
    for ([_]Config{ .{ .memory_total_mb = 1024 }, .{ .memory_max_mb = 0 } }) |other| {
        const all = try limitAll(arena, io, dir, Limits.compute(other, 30 * gib));
        try std.testing.expect(all.kept);
        try std.testing.expectEqual(@as(?u64, 2 * gib), all.memory);
        try std.testing.expectEqualStrings(theirs, try tmp.dir.readFile(io, "memory.max", &buf));
    }
    // The same limits, rounded down to a page by the kernel, are no difference.
    try tmp.dir.writeFile(io, .{ .sub_path = "memory.max", .data = "2147434496\n" });
    const rounded = Limits.compute(.{ .memory_total_mb = 2048 }, 30 * gib);
    const same = try limitAll(arena, io, dir, rounded);
    try std.testing.expect(!same.kept);
}

test "native cgroup: a kill is put down to the limit that ran out, or to what is above them" {
    const before: Usage = .{
        .working_set_mb = null,
        .peak_mb = null,
        .oom_kills = 1,
        .ooms = 1,
        .parent_ooms = 3,
        .pids_max_hits = 0,
    };
    var now = before;
    now.oom_kills = 2;
    try std.testing.expectEqual(Killer.above, Killer.of(before, now));
    now.parent_ooms = 4;
    try std.testing.expectEqual(Killer.all, Killer.of(before, now));
    now.ooms = 2;
    try std.testing.expectEqual(Killer.job, Killer.of(before, now));
}

test "native cgroup: only a root runner at the root of a cgroup namespace looks for itself" {
    try std.testing.expect(isRootCgroup("0::/\n"));
    try std.testing.expect(!isRootCgroup("0::/system.slice/zr.service\n"));
    try std.testing.expect(!isRootCgroup(""));
}

test "native cgroup: no swap, or nowhere to swap to, is no use for memory.high" {
    const io = std.testing.io;
    try std.testing.expect(!canSwap(.{ .swap = false }, io));
    const has_swap = (meminfo(io, "SwapTotal:") orelse 0) > 0;
    try std.testing.expectEqual(has_swap, canSwap(.{ .swap = true }, io));
}

test "native cgroup: the kernel's most processes is as much as is asked for" {
    const huge = Limits.compute(.{ .pids_max = 2 << 20 }, 8 * gib);
    try std.testing.expectEqual(@as(?u32, 2 << 20), huge.pids_max);
    try std.testing.expectEqual(@as(?u32, 4 << 20), huge.pids_total);
    const over = Limits.compute(.{ .pids_max = 8 << 20 }, 8 * gib);
    try std.testing.expectEqual(@as(?u32, 4 << 20), over.pids_max);
    try std.testing.expectEqual(@as(?u32, 4 << 20), over.pids_total);
}

test "native cgroup: a parent must be a cgroup's path, through no dot directory" {
    try std.testing.expect(within("/sys/fs/cgroup/zig-runner"));
    try std.testing.expect(within("/sys/fs/cgroup/system.slice/zr.service/jobs"));
    try std.testing.expect(!within("/sys/fs/cgroup"));
    try std.testing.expect(!within("/sys/fs/cgroup/"));
    try std.testing.expect(!within("/sys/fs/cgroup/../../etc"));
    try std.testing.expect(!within("/sys/fs/cgroup/a//b"));
    try std.testing.expect(!within("/tmp/x"));
}

test "native cgroup: none is none, and the answer is kept per setting" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const p = parent(a.allocator(), std.testing.io, "none");
    try std.testing.expectEqualStrings("RUNNER_NATIVE_CGROUP=none", p.none);
    const bad = parent(a.allocator(), std.testing.io, "/etc");
    try std.testing.expect(bad == .none);
}
