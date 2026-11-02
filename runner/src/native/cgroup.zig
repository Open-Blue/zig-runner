//! A cgroup v2 per native job (docs/native-backend.md, P4): `memory.max` and `pids.max` hold a
//! runaway job inside its own limits, so a memory hog is OOM-killed in its own cgroup and a fork
//! bomb stops at its own process limit, without touching its neighbours; `memory.current` and
//! `memory.stat` give the memory gate (`admission.zig`) the job's own working set, where the
//! Dagger engine's one cgroup charges every job running for all of them; and `memory.high`, from
//! what the gate reserves for the job (`Job.setHigh`), slows a job that outgrows that before it
//! takes its neighbours' memory, below `memory.max`, which kills.
//!
//! Each step's helper joins the job's cgroup before it does anything else (`sandbox.zig`), so
//! every process of the step is born in it; the runner never is. Between steps the cgroup is
//! empty and kept: its peak and events are the job's, across its steps.
//!
//! Where the jobs' cgroups go (`parent`, `RUNNER_NATIVE_CGROUP`):
//! - On a root runner, by default, a tree of the runner's own at `/sys/fs/cgroup/zig-runner`, as
//!   Docker's cgroupfs driver makes `/sys/fs/cgroup/docker`. It is the host's, like the slots'
//!   locks: every runner on a host makes its jobs' cgroups there, each named by its job's
//!   directory (random, so never two alike), and only the runner that holds a job's lock removes
//!   its cgroup (`Backend.sweep`).
//! - `self`: the runner's own cgroup, delegated to it (systemd's `Delegate=yes`, or
//!   `systemd-run --user --scope -p Delegate=yes` for a rootless runner). The runner moves its
//!   own processes into a leaf (`runner`) and makes the jobs' cgroups under `jobs`, as systemd's
//!   delegation rules ask: a cgroup that gives its children controllers holds no process itself.
//!   In a container with a cgroup namespace of its own, the container's root is its cgroup, and
//!   `self` works there too.
//! - A path under /sys/fs/cgroup: that cgroup, made if missing.
//! - `none`, or a rootless runner without `self`: no cgroup. Native jobs then run as in P1, with
//!   no limit of their own, and "Set up job" says why.

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

/// What the runner configures.
pub const Config = struct {
    /// `RUNNER_NATIVE_CGROUP`: "" (the default above), "self", "none", or a cgroup's path.
    parent: []const u8 = "",
    /// `RUNNER_NATIVE_MEMORY_MAX_MB`: each job's `memory.max`; null for three quarters of the
    /// machine's memory (`MemTotal`), 0 for no limit.
    memory_max_mb: ?u32 = null,
    /// `RUNNER_NATIVE_PIDS_MAX`: each job's `pids.max`; 0 for no limit.
    pids_max: u32 = default_pids_max,
};

/// A job's limits, as written: null is `max`.
pub const Limits = struct {
    memory_max: ?u64,
    pids_max: ?u32,

    /// From the configuration and, for the default memory limit, the machine's memory.
    pub fn of(io: std.Io, cfg: Config) Limits {
        const memory: ?u64 = if (cfg.memory_max_mb) |mb|
            (if (mb == 0) null else @as(u64, mb) << 20)
        else if (memTotal(io)) |total| total / 4 * 3 else null;
        return .{ .memory_max = memory, .pids_max = if (cfg.pids_max == 0) null else cfg.pids_max };
    }
};

/// `MemTotal` in /proc/meminfo, in bytes.
fn memTotal(io: std.Io) ?u64 {
    var buf: [4096]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, "/proc/meminfo", &buf) catch return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "MemTotal:")) continue;
        var words = std.mem.tokenizeScalar(u8, line["MemTotal:".len..], ' ');
        const kb = std.fmt.parseInt(u64, words.next() orelse return null, 10) catch return null;
        return kb * 1024;
    }
    return null;
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
    const dir: []const u8 = if (want.len == 0) dir: {
        if (linux.geteuid() != 0) return .{ .none = not_delegated };
        break :dir default_parent;
    } else if (std.mem.eql(u8, want, "self"))
        selfParent(arena, io) catch |e| return .{ .none = std.fmt.allocPrint(
            arena,
            "the runner's own cgroup cannot hold its jobs' ({s}): is it delegated to the runner?",
            .{@errorName(e)},
        ) catch "the runner's own cgroup cannot hold its jobs'" }
    else dir: {
        if (!within(want)) return .{ .none = "RUNNER_NATIVE_CGROUP is not a cgroup's path " ++
            "under " ++ mount_point };
        break :dir want;
    };
    ensure(arena, dir) catch |e| return .{ .none = std.fmt.allocPrint(
        arena,
        "{s} cannot hold the jobs' cgroups ({s}: {s})",
        .{ dir, @errorName(e), explain(e) },
    ) catch "the jobs' cgroup parent cannot be made" };
    return .{ .dir = dir };
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
        error.AccessDenied => "the runner may not write it",
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

/// One job's cgroup.
pub const Job = struct {
    dir: []const u8,

    /// `<parent>/<name>`, with the job's limits. One left by a runner that died is taken over.
    pub fn make(arena: Allocator, parent_dir: []const u8, name: []const u8, limits: Limits) !Job {
        const dir = try std.fmt.allocPrint(arena, "{s}/{s}", .{ parent_dir, name });
        try mkdir(arena, dir);
        const j: Job = .{ .dir = dir };
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

    /// `memory.high`, from the memory gate's estimate for the job (`admission.nativeHighMb`):
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
        const pids_events = readIn(io, j.dir, "pids.events", &events_buf) catch "";
        return .{
            .working_set_mb = admission.workingSetMb(io, j.dir),
            .peak_mb = if (admission.readCgroupBytes(io, j.dir, "memory.peak")) |b|
                b >> 20
            else
                null,
            .oom_kills = oom_kills,
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
    /// Forks refused at `pids.max` (`pids.events`).
    pids_max_hits: u64,
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

test "native cgroup: limits from the configuration and the machine's memory" {
    const io = std.testing.io;
    const derived = Limits.of(io, .{});
    try std.testing.expectEqual(@as(?u32, default_pids_max), derived.pids_max);
    if (memTotal(io)) |total| try std.testing.expectEqual(@as(?u64, total / 4 * 3), derived.memory_max);
    const set = Limits.of(io, .{ .memory_max_mb = 512, .pids_max = 64 });
    try std.testing.expectEqual(@as(?u64, 512 << 20), set.memory_max);
    try std.testing.expectEqual(@as(?u32, 64), set.pids_max);
    const off = Limits.of(io, .{ .memory_max_mb = 0, .pids_max = 0 });
    try std.testing.expect(off.memory_max == null and off.pids_max == null);
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
