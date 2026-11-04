//! The layer store under load (`Store.zig`, docs/native-backend.md, P2): several processes share
//! one store, as a pool's runners do, each running jobs whose steps hit overlapping keys and
//! Dockerfile builds whose layers overlap (`layers.zig`), under a cap so small that eviction runs
//! after nearly every job. The workers are this test binary again, each running only the worker
//! test (`worker_test`) through the test runner's own protocol (`--listen=-`).
//!
//! What must hold, checked while they run and once they stopped:
//!
//!   - a replayed step's log is the live log of the run that stored it, line for line, and its
//!     file commands that run's (each live run prints a nonce of its own, sets it in $GITHUB_ENV
//!     and writes it into its layer; a final step that always runs reads both back);
//!   - no job sees a layer evicted or half published: the files a job's layers hold are there,
//!     whole, until it ends (the final step's reads, each build's tree read before and after it
//!     is held a while);
//!   - every published entry is whole whenever it is looked at: its meta, its record's lengths
//!     and sha256s, its tree's bytes (`Store.checkEntry`);
//!   - no key runs in two jobs at once (each step marks itself running in a shared directory);
//!     on a root runner the jobs are in different slots, with one key for all (canonical ids);
//!   - no fd or lock outlives a job in a worker, and a store that works logs no warning;
//!   - once all stopped and a last collect ran: no `.tmp-` or `.dead-` entry, no key lock, no
//!     job's directory, and the store within its cap.
//!
//! ZIG_TEST_STORE_STRESS_SECONDS (30), ZIG_TEST_STORE_STRESS_PROCS (6) and
//! ZIG_TEST_STORE_STRESS_SEED (random, printed) set the run; the nightly analysis workflow runs it
//! for longer; 0 seconds skips it, for a machine already loaded (a laptop's pre-push hook).
//! A seed fixes each worker's jobs, builds and pauses; the processes' interleaving
//! and the steps' own nonces and sleeps are the machine's.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;
const Backend = @import("Backend.zig");
const Store = @import("Store.zig");
const layers = @import("layers.zig");
const dagger = @import("../dagger.zig");
const sink = @import("../sink.zig");
const job_mod = @import("../job.zig");
const testStep = @import("../dagger/testing.zig").testStep;
const testJob = @import("../dagger/testing.zig").testJob;
const print = std.fmt.allocPrint;

/// Set in a worker's environment: `root|index|seed|deadline_ms|cap`.
const worker_env = "ZIG_TEST_STORE_STRESS_WORKER";
const worker_test = "native store under load: one worker (run only by the test above, " ++
    "in a process of its own)";

/// Steps are keyed by their chain: "a", then "ab", then "abc", each a step of its own over the
/// one before it, from this alphabet, so jobs share prefixes and keys (39 chains).
const alphabet = "abc";
const max_depth = 3;
/// Dockerfile build layers, by index.
const builds = 6;
/// A step's layer takes 8-12 KiB, a build's about 60 KiB: the keys' layers together are about
/// three times the cap, so most jobs leave the store over it.
const cap: u64 = 256 * 1024;

test "native store under load: processes share one store under a small cap" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Also whether this machine can run native jobs at all (skipped, or failed under
    // ZIG_RUNNER_REQUIRE_NATIVE=1, when not).
    const cfg = try Backend.testConfig(arena, &tmp);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var env = try std.testing.environ.createMap(arena);
    const seconds = try envInt(&env, "ZIG_TEST_STORE_STRESS_SECONDS", 30);
    if (seconds == 0) {
        std.debug.print("native store under load: skipped (ZIG_TEST_STORE_STRESS_SECONDS=0)\n", .{});
        return error.SkipZigTest;
    }
    const procs = try envInt(&env, "ZIG_TEST_STORE_STRESS_PROCS", 6);
    const seed = try envInt(&env, "ZIG_TEST_STORE_STRESS_SEED", seed: {
        var raw: [4]u8 = undefined;
        io.random(&raw);
        break :seed std.mem.readInt(u32, &raw, .little);
    });
    std.debug.print("native store under load: ZIG_TEST_STORE_STRESS_SEED={d}, {d} processes, " ++
        "{d} s, cap {d} KiB, as {s}\n", .{
        seed,                                           procs, seconds, cap / 1024,
        if (linux.geteuid() == 0) "root" else "a user",
    });

    // Shared with every step at /shared, writable by any job's root (on a root runner, each
    // slot's is another host id).
    for ([_][]const u8{ "shared", "shared/running", "shared/live", "rootfs/shared" }) |d| {
        try tmp.dir.createDirPath(io, d);
        _ = linux.chmod(try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ root, d }, 0), 0o777);
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "shared/overlaps", .data = "" });
    const overlaps_z = try std.fmt.allocPrintSentinel(arena, "{s}/shared/overlaps", .{root}, 0);
    _ = linux.chmod(overlaps_z, 0o666);

    // The workers: this binary, asked through the test runner's protocol to run the worker test
    // and then exit (std.zig.Client: a header of tag and body length, then the body).
    const index = for (builtin.test_functions, 0..) |t, i| {
        if (std.mem.endsWith(u8, t.name, worker_test)) break i;
    } else return error.NoWorkerTest;
    const run_test = 5;
    const exit = 0;
    var msgs: [20]u8 = undefined;
    const index32 = std.math.cast(u32, index) orelse return error.TooManyTests;
    for ([_]u32{ run_test, 4, index32, exit, 0 }, 0..) |v, i|
        std.mem.writeInt(u32, msgs[4 * i ..][0..4], v, .little);
    try tmp.dir.writeFile(io, .{ .sub_path = "worker.in", .data = &msgs });
    const self = try std.Io.Dir.cwd().realPathFileAlloc(io, "/proc/self/exe", arena);
    const deadline = std.Io.Clock.real.now(io).toMilliseconds() + @as(i64, seconds) * 1000;
    const children = try arena.alloc(std.process.Child, procs);
    for (children, 0..) |*child, i| {
        var wenv = try env.clone(arena);
        const wseed = @as(u64, seed) +% @as(u64, i) *% 0x9e3779b97f4a7c15;
        try wenv.put(worker_env, try print(arena, "{s}|{d}|{d}|{d}|{d}", .{ root, i, wseed, deadline, cap }));
        const in = try tmp.dir.openFile(io, "worker.in", .{});
        defer in.close(io);
        const err = try tmp.dir.createFile(io, try print(arena, "w{d}.err", .{i}), .{});
        defer err.close(io);
        child.* = try std.process.spawn(io, .{
            .argv = &.{ self, "--listen=-" },
            .environ_map = &wenv,
            .stdin = .{ .file = in },
            .stdout = .ignore,
            .stderr = .{ .file = err },
        });
    }

    // Every published entry checked whole, again and again, while the workers run.
    const s: Store = .{ .root = cfg.store, .max_bytes = cap };
    var faults: Faults = .{ .arena = arena };
    var peak: u64 = 0;
    while (std.Io.Clock.real.now(io).toMilliseconds() < deadline) {
        var pass: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer pass.deinit();
        peak = @max(peak, (try checkEntries(pass.allocator(), io, s, &faults)).bytes);
        try io.sleep(.fromMilliseconds(20), .awake);
    }
    for (children, 0..) |*child, i| {
        const term = try child.wait(io);
        if (term != .exited or term.exited != 0) try faults.add("worker {d} ended {any}", .{ i, term });
    }

    // What the workers saw and said. The first stderr that says more than its result (a job's
    // log, a crash) is shown.
    var obs: std.ArrayList(u8) = .empty;
    var totals: Stats = .{};
    var told: ?[]const u8 = null;
    for (0..procs) |i| {
        const before = faults.list.items.len;
        const err_text = try tmp.dir.readFileAlloc(io, try print(arena, "w{d}.err", .{i}), arena, .limited(16 << 20));
        // A store that works logs nothing: a layer not published or not removed, a record that
        // cannot be replayed, a lock that cannot be taken are all warnings.
        var lines = std.mem.splitScalar(u8, err_text, '\n');
        while (lines.next()) |l| {
            if (std.mem.indexOf(u8, l, "(err)") != null or std.mem.indexOf(u8, l, "(warn)") != null)
                try faults.add("worker {d} logged: {s}", .{ i, l });
        }
        const limit: std.Io.Limit = .limited(64 << 20);
        if (tmp.dir.readFileAlloc(io, try print(arena, "w{d}.result", .{i}), arena, limit)) |result| {
            var rl = std.mem.splitScalar(u8, result, '\n');
            totals.add(try Stats.parse(rl.first()));
            while (rl.next()) |l| if (l.len > 0) try faults.add("worker {d}: {s}", .{ i, l });
            try obs.appendSlice(arena, try tmp.dir.readFileAlloc(io, try print(arena, "w{d}.obs", .{i}), arena, limit));
        } else |_| try faults.add("worker {d} left no result", .{i});
        if (told == null and faults.list.items.len > before) told = err_text[0..@min(err_text.len, 64 << 10)];
    }
    const again = try checkReplays(arena, io, root, obs.items, &faults);
    const overlaps = try tmp.dir.readFileAlloc(io, "shared/overlaps", arena, .limited(1 << 20));
    if (overlaps.len > 0) try faults.add("keys ran in two jobs at once (chain, nonce):\n{s}", .{overlaps});

    // A last collect, as the last job's would: nothing half made or half removed is left, no key
    // lock and no job's directory, every entry whole and the store within its cap.
    s.collect(arena, io);
    const left = try checkEntries(arena, io, s, &faults);
    if (left.dot > 0) try faults.add("{d} .tmp-/.dead- entries left after a collect", .{left.dot});
    if (left.bytes > cap) try faults.add("{d} bytes stored after a collect, over the cap", .{left.bytes});
    for ([_][]const u8{ "keys", "jobs" }) |d| {
        var dir = try std.Io.Dir.cwd().openDir(io, try print(arena, "{s}/{s}", .{ cfg.store, d }), .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| try faults.add("left in {s}/: {s}", .{ d, e.name });
    }

    std.debug.print("native store under load: {d} jobs ({d} steps run, {d} replayed, {d} keys " ++
        "run again after eviction), {d} builds ({d} found stored), {d} entry checks, at most " ++
        "{d} KiB stored\n", .{
        totals.jobs,   totals.live,       totals.replayed, again,
        totals.builds, totals.build_hits, faults.checked,  peak / 1024,
    });
    if (faults.list.items.len > 0) {
        if (told) |text| std.debug.print("the first worker that found something, on stderr:\n{s}\n", .{text});
        const shown = @min(faults.list.items.len, 40);
        for (faults.list.items[0..shown]) |f| std.debug.print("  {s}\n", .{f});
        if (faults.list.items.len > shown) std.debug.print("  and {d} more\n", .{faults.list.items.len - shown});
        std.debug.print("native store under load: failed; ZIG_TEST_STORE_STRESS_SEED={d} runs " ++
            "the same workers again\n", .{seed});
        return error.TestUnexpectedResult;
    }
    // It did what it is for: jobs replayed one another's steps, and evicted ones ran again.
    try std.testing.expect(totals.jobs > 0 and totals.replayed > 0 and again > 0);
}

fn envInt(env: *const std.process.Environ.Map, name: []const u8, default: u32) !u32 {
    const v = env.get(name) orelse return default;
    return std.fmt.parseInt(u32, v, 10);
}

/// What the test found wrong, a line each (a few carry a log), and how many entries it checked.
const Faults = struct {
    arena: Allocator,
    list: std.ArrayList([]const u8) = .empty,
    checked: usize = 0,

    fn add(f: *Faults, comptime fmt: []const u8, args: anytype) !void {
        try f.list.append(f.arena, try print(f.arena, fmt, args));
    }
};

/// What a worker did, its result's first line.
const Stats = struct {
    jobs: u64 = 0,
    live: u64 = 0,
    replayed: u64 = 0,
    builds: u64 = 0,
    build_hits: u64 = 0,

    const names = .{ "jobs", "live", "replayed", "builds", "build_hits" };

    pub fn format(s: Stats, w: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (names) |name| try w.print("{d} ", .{@field(s, name)});
    }

    fn parse(line: []const u8) !Stats {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        var s: Stats = .{};
        inline for (names) |name|
            @field(s, name) = try std.fmt.parseInt(u64, f.next() orelse return error.BadResult, 10);
        return s;
    }

    fn add(s: *Stats, o: Stats) void {
        inline for (names) |name| @field(s, name) += @field(o, name);
    }
};

/// Every entry under `layers/` checked (`Store.checkEntry`), a fault for each that is not whole;
/// the bytes of those that are, and how many `.tmp-`/`.dead-` entries there were.
fn checkEntries(arena: Allocator, io: std.Io, s: Store, faults: *Faults) !struct { bytes: u64, dot: usize } {
    var dir = try std.Io.Dir.cwd().openDir(io, try print(arena, "{s}/layers", .{s.root}), .{ .iterate = true });
    defer dir.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |e| try names.append(arena, try arena.dupe(u8, e.name));
    var bytes: u64 = 0;
    var dot: usize = 0;
    for (names.items) |name| {
        if (name[0] == '.') {
            dot += 1;
            continue;
        }
        faults.checked += 1;
        bytes += (s.checkEntry(arena, io, name) catch |e| {
            try faults.add("entry {s}: {t}", .{ name, e });
            continue;
        }) orelse 0;
    }
    return .{ .bytes = bytes, .dot = dot };
}

/// The workers' observations (`w<n>.obs`: `live|replay <chain> <nonce> <lines>`, the step's log
/// lines joined by 0x1f) held against one another: each nonce was run live once, by a step of
/// its chain (`shared/live/<nonce>`), and every replay of it printed what that live run printed.
/// How many chains ran live more than once: run again after their layer was evicted.
fn checkReplays(arena: Allocator, io: std.Io, root: []const u8, obs: []const u8, faults: *Faults) !usize {
    const Seen = struct { chain: []const u8, lines: []const u8 };
    var live: std.StringHashMapUnmanaged(Seen) = .empty;
    var live_runs: std.StringHashMapUnmanaged(usize) = .empty;
    var lines = std.mem.splitScalar(u8, obs, '\n');
    // Live runs first, then the replays against them.
    for ([_][]const u8{ "live", "replay" }) |pass| {
        lines.reset();
        while (lines.next()) |l| {
            if (l.len == 0) continue;
            var f = std.mem.splitScalar(u8, l, ' ');
            if (!std.mem.eql(u8, f.first(), pass)) continue;
            const chain = f.next() orelse return error.BadObservation;
            const nonce = f.next() orelse return error.BadObservation;
            const text = f.rest();
            if (pass[0] == 'r') {
                const first = live.get(nonce) orelse {
                    try faults.add("{s} replayed nonce {s}, which no job ran live", .{ chain, nonce });
                    continue;
                };
                if (!std.mem.eql(u8, first.chain, chain) or !std.mem.eql(u8, first.lines, text))
                    try faults.add("a replay of {s} printed\n    {s}\n  but its live run, of {s}, " ++
                        "printed\n    {s}", .{ chain, text, first.chain, first.lines });
                continue;
            }
            const marked = try print(arena, "{s}/shared/live/{s}", .{ root, nonce });
            const ran = std.Io.Dir.cwd().readFileAlloc(io, marked, arena, .limited(64)) catch "";
            if (!std.mem.eql(u8, std.mem.trimEnd(u8, ran, "\n"), chain))
                try faults.add("{s} printed nonce {s}, which a step of {s} ran", .{ chain, nonce, ran });
            const got = try live.getOrPut(arena, nonce);
            if (got.found_existing) try faults.add("nonce {s} of {s} was run live twice", .{ nonce, chain });
            got.value_ptr.* = .{ .chain = chain, .lines = text };
            const n = try live_runs.getOrPut(arena, chain);
            n.value_ptr.* = if (n.found_existing) n.value_ptr.* + 1 else 1;
        }
    }
    var again: usize = 0;
    var it = live_runs.valueIterator();
    while (it.next()) |n| again += @intFromBool(n.* > 1);
    return again;
}

// --- a worker ---

const Worker = struct {
    index: usize,
    cfg: Backend.Config,
    store: Store,
    rand: std.Random,
    /// The worker's own, for what it keeps until it ends.
    arena: Allocator,
    stats: Stats = .{},
    /// What went wrong, a line each, for its result.
    faults: std.ArrayList(u8) = .empty,
    /// `w<n>.obs`'s lines (`checkReplays`).
    obs: std.ArrayList(u8) = .empty,
    /// How many more faults may carry their job's whole log.
    logs_left: u8 = 2,

    /// A fault: its first line in the result, all of it (a log, maybe) on stderr.
    fn fault(w: *Worker, comptime fmt: []const u8, args: anytype) void {
        const text = print(w.arena, fmt ++ "\n", args) catch @panic("out of memory recording a fault");
        std.debug.print("worker {d}: {s}", .{ w.index, text });
        const first = std.mem.indexOfScalar(u8, text, '\n').? + 1;
        w.faults.appendSlice(w.arena, text[0..first]) catch @panic("out of memory recording a fault");
    }

    /// A job's log for a fault, the first few times: the rest would bury the first.
    fn log(w: *Worker, text: []const u8) []const u8 {
        if (w.logs_left == 0) return "(log omitted: see the first faults)";
        w.logs_left -= 1;
        return text;
    }
};

test "native store under load: one worker (run only by the test above, in a process of its own)" {
    var env = try std.testing.environ.createMap(std.testing.allocator);
    defer env.deinit();
    const spec = env.get(worker_env) orelse return error.SkipZigTest;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var f = std.mem.splitScalar(u8, spec, '|');
    const root = f.first();
    const index = try std.fmt.parseInt(usize, f.next().?, 10);
    var prng: std.Random.DefaultPrng = .init(try std.fmt.parseInt(u64, f.next().?, 10));
    const deadline = try std.fmt.parseInt(i64, f.next().?, 10);
    // The test's backend, keyed as its other workers' are, and its /shared.
    const exe = try std.Io.Dir.cwd().realPathFileAlloc(io, env.get("ZIG_RUNNER_TEST_EXE").?, arena);
    var cfg = try Backend.testConfigAt(arena, root, exe);
    cfg.store_max_bytes = try std.fmt.parseInt(u64, f.next().?, 10);
    const shared = try print(arena, "{s}/shared", .{root});
    cfg.binds = try std.mem.concat(arena, @TypeOf(cfg.binds[0]), &.{
        cfg.binds,
        &.{.{ .host = shared, .at = "/shared", .read_only = false }},
    });
    var w: Worker = .{
        .index = index,
        .cfg = cfg,
        .store = .{ .root = cfg.store, .max_bytes = cfg.store_max_bytes },
        .rand = prng.random(),
        .arena = arena,
    };
    const build_dir = try print(arena, "{s}/build-{d}", .{ root, index });
    try std.Io.Dir.cwd().createDirPath(io, build_dir);

    // A job, then a build, then either at random, each with a pause after. What stays open is
    // counted from after the first of each, which open what the process keeps.
    var fds_kept: usize = 0;
    var n: usize = 0;
    while (std.Io.Clock.real.now(io).toMilliseconds() < deadline) : (n += 1) {
        var job_arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer job_arena.deinit();
        const build = if (n < 2) n == 1 else w.rand.uintLessThan(u32, 4) == 0;
        const what = if (build) "build" else "job";
        if (build)
            try runBuild(&w, job_arena.allocator(), io, build_dir, n)
        else
            try runJob(&w, job_arena.allocator(), io, n);
        const fds = try countFds(io);
        if (n == 1) fds_kept = fds;
        if (n > 1 and fds > fds_kept) w.fault("{d} fds open after {s} {d}, {d} before", .{ fds, what, n, fds_kept });
        const locks = try countLocks(job_arena.allocator(), io);
        if (locks > 0) w.fault("{d} flocks held after {s} {d}", .{ locks, what, n });
        try io.sleep(.fromMilliseconds(w.rand.uintLessThan(u32, 30)), .awake);
    }

    var out: std.Io.Writer.Allocating = .init(arena);
    try out.writer.print("{f}\n{s}", .{ w.stats, w.faults.items });
    const cwd = std.Io.Dir.cwd();
    try cwd.writeFile(io, .{ .sub_path = try print(arena, "{s}/w{d}.obs", .{ root, index }), .data = w.obs.items });
    try cwd.writeFile(io, .{ .sub_path = try print(arena, "{s}/w{d}.result", .{ root, index }), .data = out.written() });
}

/// A step of chain `c`: marks itself running (a second run of the key at once finds the mark),
/// writes a nonce of its own into its layer with padding of a random size, prints it on stdout
/// and stderr, sets it in $GITHUB_ENV, records that it ran it, sleeps a little, and unmarks.
fn stepScript(arena: Allocator, c: []const u8) ![]const u8 {
    return print(arena,
        \\c={s}; r=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
        \\n=$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')
        \\mkdir /shared/running/$c 2>/dev/null || echo "$c $n" >> /shared/overlaps
        \\mkdir -p /w; {{ echo $n; head -c $((r % 3000)) /dev/zero; }} > /w/$c
        \\echo "@$c $n out"; echo "@$c $n err" >&2; echo "S_$c=$n" >> "$GITHUB_ENV"
        \\echo $c > /shared/live/$n; sleep 0.$((r % 4)); rmdir /shared/running/$c
    , .{c});
}

/// The last step, which always runs (it reads $GITHUB_SHA): what each step's layer and file
/// commands left, as this job sees them.
fn finalScript(arena: Allocator, chain: []const u8) ![]const u8 {
    var cs: std.ArrayList(u8) = .empty;
    for (1..chain.len + 1) |i| try cs.print(arena, " {s}", .{chain[0..i]});
    return print(arena,
        \\: $GITHUB_SHA; for c in{s}; do
        \\  eval "e=\$S_$c"; echo "@final $c file=$(head -n1 /w/$c) env=$e"
        \\done
    , .{cs.items});
}

/// A job of up to three steps on a random chain, and the final step: its steps' nonces and
/// whether each was replayed, observed for `checkReplays`, and what the final step read held
/// against them.
fn runJob(w: *Worker, arena: Allocator, io: std.Io, n: usize) !void {
    var chain: [max_depth]u8 = undefined;
    const depth = 1 + w.rand.uintLessThan(usize, max_depth);
    for (chain[0..depth]) |*ch| ch.* = alphabet[w.rand.uintLessThan(usize, alphabet.len)];
    const c = chain[0..depth];
    const steps = try arena.alloc(job_mod.Step, depth + 1);
    for (steps[0..depth], 1..) |*st, i| st.* = testStep(try stepScript(arena, c[0..i]));
    steps[depth] = testStep(try finalScript(arena, c));

    var env: std.process.Environ.Map = .init(arena);
    var out: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &out.writer } };
    const res = try dagger.run(arena, io, &env, .{
        .native = w.cfg,
        .step_cache = true,
        .test_ran_marker = try print(arena, "w{d}-{d}", .{ w.index, n }),
        .gpa = std.testing.allocator,
    }, testJob(steps), &log);
    const text = out.written();
    w.stats.jobs += 1;
    if (!res.succeeded)
        return w.fault("job {d} ({s}) failed: {s}\n{s}", .{ n, c, res.engine_error orelse "-", w.log(text) });

    var nonces: [max_depth][]const u8 = undefined;
    for (0..depth) |i| {
        const step = c[0 .. i + 1];
        // The step's lines ("[job 0 step 2 stdout] ..."), without the note a replay ends with.
        const prefix = try print(arena, "step {d} ", .{i + 1});
        const tag = try print(arena, "@{s} ", .{step});
        var mine: std.ArrayList(u8) = .empty;
        var replayed = false;
        var nonce: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |l| {
            if (!std.mem.startsWith(u8, l, "[job ") or std.mem.indexOf(u8, l, prefix) == null) continue;
            if (std.mem.indexOf(u8, l, dagger.native_reused_note) != null) {
                replayed = true;
                continue;
            }
            if (mine.items.len > 0) try mine.append(arena, 0x1f);
            try mine.appendSlice(arena, l);
            const at = std.mem.indexOf(u8, l, tag) orelse continue;
            var f = std.mem.splitScalar(u8, l[at + tag.len ..], ' ');
            const this = f.first();
            if (nonce) |seen| if (!std.mem.eql(u8, seen, this))
                w.fault("step {s} printed nonces {s} and {s}", .{ step, seen, this });
            nonce = this;
        }
        nonces[i] = nonce orelse return w.fault("step {s} printed no nonce:\n{s}", .{ step, w.log(text) });
        if (replayed) w.stats.replayed += 1 else w.stats.live += 1;
        const kind = if (replayed) "replay" else "live";
        try w.obs.print(w.arena, "{s} {s} {s} {s}\n", .{ kind, step, nonces[i], mine.items });
    }
    // What the job's layers and file commands held is what its steps printed.
    for (nonces[0..depth], 1..) |nonce, i| {
        const want = try print(arena, "@final {s} file={s} env={s}", .{ c[0..i], nonce, nonce });
        if (std.mem.indexOf(u8, text, want) == null)
            w.fault("job {d} ({s}): no \"{s}\" in\n{s}", .{ n, c, want, w.log(text) });
    }
}

/// A Dockerfile build's layers (`layers.Store`, as `dockerfile.zig` uses it): some of the six,
/// each found stored or built and published, read whole, held a while, read again, let go, and
/// the store collected, as a job's end does.
fn runBuild(w: *Worker, arena: Allocator, io: std.Io, dir: []const u8, n: usize) !void {
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |l| l.close(io);
    const ls: layers.Store = .{ .dir = dir, .store = w.store, .held = &held, .scope = "repo" };
    var got: [builds]?[]const u8 = @splat(null);
    for (0..1 + w.rand.uintLessThan(usize, 3)) |_| {
        const b = w.rand.uintLessThan(usize, builds);
        if (got[b] != null) continue;
        var key: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(try print(arena, "stress build {d}", .{b}), &key, .{});
        const hex = std.fmt.bytesToHex(key, .lower);
        w.stats.builds += 1;
        got[b] = if (try ls.get(arena, io, &hex)) |p| hit: {
            w.stats.build_hits += 1;
            break :hit p;
        } else built: {
            const at = try ls.begin(arena, io, &hex);
            try fillBuild(arena, io, at, b);
            break :built ls.publish(arena, io, at, &hex) catch |e| {
                w.fault("build {d}: layer {d} not published: {t}", .{ n, b, e });
                continue;
            };
        };
        checkBuild(w, arena, io, got[b].?, b, n, "found");
    }
    try io.sleep(.fromMilliseconds(w.rand.uintLessThan(u32, 60)), .awake);
    for (got, 0..) |p, b| if (p) |path| checkBuild(w, arena, io, path, b, n, "held");
    for (held.items) |l| l.close(io);
    held.clearRetainingCapacity();
    w.store.collect(arena, io);
}

const build_files = 12;

/// Build `b`'s file `m`: its name, padded to a size of its own.
fn buildFile(arena: Allocator, b: usize, m: usize) ![]const u8 {
    const text = try print(arena, "build {d} file {d}\n", .{ b, m });
    const pad = try arena.alloc(u8, b * 300 + m * 100);
    @memset(pad, 'p');
    return std.mem.concat(arena, u8, &.{ text, pad });
}

fn fillBuild(arena: Allocator, io: std.Io, at: []const u8, b: usize) !void {
    const cwd = std.Io.Dir.cwd();
    for (0..build_files) |m| {
        try cwd.createDirPath(io, try print(arena, "{s}/d{d}", .{ at, m % 3 }));
        try cwd.writeFile(io, .{
            .sub_path = try print(arena, "{s}/d{d}/f{d}", .{ at, m % 3, m }),
            .data = try buildFile(arena, b, m),
        });
    }
}

fn checkBuild(w: *Worker, arena: Allocator, io: std.Io, at: []const u8, b: usize, n: usize, when: []const u8) void {
    for (0..build_files) |m| {
        const p = print(arena, "{s}/d{d}/f{d}", .{ at, m % 3, m }) catch return;
        const want = buildFile(arena, b, m) catch return;
        const got = std.Io.Dir.cwd().readFileAlloc(io, p, arena, .limited(1 << 16)) catch |e|
            return w.fault("build {d}: layer {d} {s}: {s}: {t}", .{ n, b, when, p, e });
        if (!std.mem.eql(u8, got, want)) return w.fault("build {d}: layer {d} {s}: {s} changed", .{ n, b, when, p });
    }
}

fn countFds(io: std.Io) !usize {
    var dir = try std.Io.Dir.cwd().openDir(io, "/proc/self/fd", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    var n: usize = 0;
    while (try it.next(io)) |_| n += 1;
    return n;
}

/// The flocks this process holds (/proc/locks: `1: FLOCK ADVISORY WRITE <pid> ...`).
fn countLocks(arena: Allocator, io: std.Io) !usize {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, "/proc/locks", arena, .limited(1 << 20));
    const pid = try print(arena, "{d}", .{linux.getpid()});
    var n: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        var f = std.mem.tokenizeScalar(u8, l, ' ');
        _ = f.next();
        if (!std.mem.eql(u8, f.next() orelse "", "FLOCK")) continue;
        _ = f.next();
        _ = f.next();
        n += @intFromBool(std.mem.eql(u8, f.next() orelse "", pid));
    }
    return n;
}
