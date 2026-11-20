//! Runs the unit tests in several processes of one test binary, as many as the machine has cores:
//! the suite is mostly waiting (peers that never answer, timeouts) and one core's work at a time.
//!
//!     test_shards <test binary> [its arguments]
//!     test_shards --names <test binary>
//!
//! The binary keeps Zig's own test runner. Each shard is a copy of it started with `--listen=-`
//! and told which test to run over that runner's protocol (`std.zig.Client`), as the build system
//! does, one test at a time. Here the next test goes to whichever shard is free. A shard's stderr
//! is a file, read between its test's start and its result, so one test's output is never mixed
//! with another's.
//!
//! A failed test is shown as the stock runner shows it, `12/642 name...FAIL` and everything the
//! test wrote to stderr (the failed `expect`, the error return trace). Passing and skipped tests
//! say nothing; the last line counts them. A test that ends its shard (a panic, a signal) fails
//! with the shard's last words, and a new shard takes its place.
//!
//! Tests that cannot run beside each other run one after another (`serial`). One shard, or one
//! test (a `--test-filter`), runs the binary itself, as without this program.
//! `--names` only prints the binary's test names, one a line, as `.github/scripts/test-files.sh`
//! compares them with the source's. ZIG_TEST_SHARDS=N sets the number of shards; the default is the cores this process may use.
//! ZIG_TEST_PART=K/N runs only part K of N, so N machines share a suite (CI's native tests as root,
//! which run one at a time on each): the longest tests (`heavy`) are shared out by their measured
//! time, the others every N-th, starting at the K-th.
//! `zig build test -Dshard-tests=false` runs the tests without it.
//! ZIG_TEST_TIMES=1 prints every test's wall time (`time: 1.234 s name`, longest first) and each
//! shard's busy time and test count before the totals line; off by default (only the five slowest
//! tests past 2 s are named). `ZIG_TEST_FULL=1` is read by the tests, not here: it runs their
//! exhaustive sweeps (see CONTRIBUTING.md).
//!
//! A leak check, like the allocator's for memory, for the temporary directories `std.testing.tmpDir`
//! makes (`.zig-cache/tmp`, under the working directory): what is there after the run, and was not
//! before it, is a test's leftover. It is reported with its depth and its paths, the tests that were
//! running when it was made are named (one of them left it, the only one when the tests do not run
//! beside each other), the run fails, and it is removed, a chain too deep to name included, by names
//! relative to a directory descriptor from the bottom (`du` and file watchers crash on those). What
//! an earlier run left (killed in the middle, so nothing could clean up) and is older than
//! ZIG_TEST_SWEEP_AGE_S seconds (default 1800: another run may be using a newer one) is removed
//! at the start. `leaves_state` lists the tests that leave a directory on purpose, with why.
const std = @import("std");
const Io = std.Io;

const Request = std.zig.Client.Message.Header;
const Reply = std.zig.Server.Message.Header;
const Results = std.zig.Server.Message.TestResults;

/// The tests that cannot run beside each other: those that listen on fixed ports on the host, or
/// publish a service on one (services.zig: 5432, 16379, 47321, 47999), and those that look for what
/// a job can reach from the host's own listeners (Backend.zig: 17123, 17124, 17126; all named
/// "root runner"). As root, all the native backend's: a root job takes the first free slot of ids
/// and addresses on the host (`net.slots_dir`), and the tests that name its ids expect the first.
/// Rootless, they have a store and a directory of their own and run side by side.
fn serial(name: []const u8, root: bool) bool {
    return std.mem.indexOf(u8, name, "native.services.") != null or
        std.mem.indexOf(u8, name, "root runner") != null or
        root and std.mem.indexOf(u8, name, "native") != null;
}

/// The tests that take seconds, which start first: the run ends with its last test, so one that
/// starts late makes the others wait for it. The first is work (6 s alone, an allocation failure at
/// a time over a whole job), the next two wait for a peer, then workers on a store, and the rest
/// are the root tests that took 10-18 s each in CI (the `slow:` lines a run prints). They are also
/// shared out among a run's parts on their own (ZIG_TEST_PART), so no part gets most of them, as
/// every N-th test did: one root part ran 162 s of tests where its other took about 100. A test
/// missing here only starts later than it could, and is shared out with the others.
fn slow(name: []const u8) bool {
    const parts = [_][]const u8{
        "allocation failures",          "never answers",
        "slow to answer",               "store under load",
        "a job's own network",          "stay under the limit on their parent",
        "forks all through the ladder", "a container job's ports",
    };
    for (parts) |part| {
        if (std.mem.indexOf(u8, name, part) != null) return true;
    }
    return false;
}

/// The tests that take the longest in the root run (measured by ZIG_TEST_TIMES=1 on CI's hosted
/// runners, 2026-11-20, x86_64 and arm64, three runs each, averaged; the weight is tenths of a second; the ones of
/// 1 s and more, which together are 257 s of the 312 s the root tests take). As root every native
/// test runs alone, so a part takes the sum of its tests' times, and sharing out every N-th test
/// left one part with most of the long ones. These are shared out first, each to the part with the
/// least weight so far (longest first), and the rest alternate as before: a deterministic split,
/// the same in every process, needing no file at run time. Refresh: run the root part with
/// ZIG_TEST_TIMES=1 (`time:` lines, longest first), and put the tests of 1 s and more here; a
/// test missing or out of date only makes the parts less equal, never drops or repeats a test.
const heavy = [_]struct { u32, []const u8 }{
    .{ 202, "native docker api: while job A is running, job B cannot reach A's socket, finds no other socket, and has an API of its own" },
    .{ 187, "root runner: a job's own network, out of reach of the host's services and other jobs" },
    .{ 185, "root runner: a native job resolves through a nameserver only another interface reaches, and reaches nothing else there" },
    .{ 164, "native nft: a job's packets carry its own source address, and nothing else of its use of the bridge changes" },
    .{ 143, "native nft: a job reaches an instance Docker publishes, and a job cannot use the rule for anything else" },
    .{ 110, "native store under load: with the deferred sync, jobs miss one another's pending layers" },
    .{ 107, "native store under load: processes share one store under a small cap" },
    .{ 106, "a native step that forks all through the ladder leaves nothing at its end" },
    .{ 86, "root runner: all native jobs together stay under the limit on their parent" },
    .{ 83, "root runner: native gate accuracy, each job's own cgroup against the engine-wide reading" },
    .{ 80, "a native step that takes no SIGINT hears SIGTERM 7500 ms on, and its end counts as cancelled" },
    .{ 74, "root runner: a container job's --cpus 0.5 sets the job's cpu.max and throttles a busy loop, with no engine" },
    .{ 71, "a container job's ports: published on the host, never another job's nor a bridge's, gone with the job; a taken port fails it; a bare one is the kernel's pick" },
    .{ 63, "root runner: a native job's runaway is OOM-killed in its own cgroup, a fork bomb stops at pids.max" },
    .{ 63, "native services: the host and other jobs cannot reach a job's services (root runner)" },
    .{ 62, "root runner: a job the runner does not vouch for does not run where no total can hold" },
    .{ 45, "root runner: with no swap a job past what the gate reserves is not held there" },
    .{ 43, "root runner: a job's source address pin is on the host while it runs, and gone after (#603)" },
    .{ 37, "each post script of a native job hears its own SIGINT at the job's limit" },
    .{ 35, "native cgroup: under pressure the lower job's steps are frozen and use no CPU, the higher job's go on, and the pause ends" },
    .{ 34, "a native step that ignores every signal is dead at the ladder's end, whatever it started" },
    .{ 28, "native hashFiles: calls that each hold memory and need more run in turn, none waits on another for good" },
    .{ 26, "native tool trees: a job's first step ends the epoch of the tool cache for those that have not checked yet" },
    .{ 25, "native eviction under a real job: a seed and a volume stay until it ends, and a seed built again is a new key" },
    .{ 25, "a published port's quiet connections make way for a newcomer, and idle ones are closed" },
    .{ 24, "a container job's named volumes: kept between jobs, filled from the image once, apart by scope and repository, :ro read-only" },
    .{ 24, "native step cache: with the deferred sync, a job that lost a key to another's pending layer keeps caching its later steps" },
    .{ 24, "root runner: a native step's fork bomb that ignores signals goes at the ladder's end" },
    .{ 22, "native services: postgres and redis from real images (ZIG_RUNNER_SERVICE_IMAGES, root)" },
    .{ 21, "a published port with no idle timeout keeps a quiet connection" },
    .{ 20, "native cgroup: a job's directory left frozen is thawed when it is made again" },
    .{ 20, "native cgroup: an explicit --cpu-shares weight is written after the priority's, and so wins" },
    .{ 18, "the tests' runaway and fork bomb end by themselves, with no limit on them" },
    .{ 16, "root runner: each native step's log says its memory peak, the next step's its own" },
    .{ 16, "native trust: a fork's pull request on a runner that vouches for pull requests reaches nothing a trusted job reads or replays" },
    .{ 16, "native docker api: a step that made a request beyond ping, version and info is not stored, even one it never read the answer of; the next runs uncached" },
    .{ 15, "native eviction: jobs racing collects never lose a volume they hold" },
    .{ 15, "native cargo target cache: two repo jobs share cargo's target directory, a roll does not move a running job's, an untrusted job and a job without the option do not" },
    .{ 15, "root runner: a job the runner does not vouch for reaches nothing a trusted job reads or replays" },
    .{ 15, "native hashFiles: many links to one long chain follow it once" },
    .{ 15, "native eviction: jobs racing collects never lose a tree they hold, and make one at a time" },
    .{ 14, "native step cache: a checkout with submodules never replays one without, or with fewer" },
    .{ 14, "native tool trees: an installing step replays while its tree is held, not once changed" },
    .{ 13, "the native checkout's submodules: `true` the first level, `recursive` all, `false` none" },
    .{ 13, "native eviction under a real job: its rootfs and image are its overlay's lowers, and stay" },
    .{ 13, "native nft: rules made by several makers at once are all made, none lost to the others" },
    .{ 12, "native step cache: two jobs with one key at once run it once; the other replays it" },
    .{ 12, "native hashFiles: a directory of thousands of entries costs its entries, not the matching of each" },
    .{ 12, "a task's cancel that lands in a sink's write of a native step's output is not lost" },
    .{ 11, "root runner: an idmapped upper leaves the layers the shift does, and each reads the other's store" },
    .{ 11, "native oci zstd: a stream that is wrong is refused with a reason, never read out of bounds" },
    .{ 11, "download: a 429 or 5xx is tried again (Retry-After honoured), a persistent one gives up, a 404 is not retried" },
    .{ 11, "native docker api: a job container volume or --tmpfs around the socket's path gives the job no API, and the job still runs" },
    .{ 10, "native oci pull: with a record, a 401, a 403 and a 404 are errors; a 503, 429 and no answer fall back; an evicted image does not; a bad record is not trusted" },
    .{ 10, "native hashFiles: steps read the files the steps before them left, replayed or run, and a changed file is not served a stale replay" },
    .{ 10, "native oci pull: a registry that answers 429 gives the last known digest; a first pull waits out Retry-After" },
    .{ 10, "a published UDP port takes only so many new clients a second" },
};

fn heavyWeight(name: []const u8) ?u32 {
    for (heavy) |h| if (std.mem.endsWith(u8, name, h[1])) return h[0];
    return null;
}

/// Tests that are single-threaded and exhaustive (every bit of a seed flipped, every allocation
/// failed in turn): ThreadSanitizer, which reports races between threads, has nothing to find in
/// them, and slows them about tenfold. Under it (ZIG_TEST_SANITIZE_THREAD=1, zig-test.sh) they
/// are skipped, saying so; the Tests jobs run them without it. Measured in a database part under
/// ThreadSanitizer: 69 s, 51 s and 35 s, the rest of the part's tests 20 s.
const untouched_by_tsan = [_][]const u8{
    "zstd decoders: every bit of the small seeds flipped",
    "allocation failures: the job message",
    "native oci zstd: a stream that is wrong is refused with a reason, never read out of bounds",
};

fn skippedUnderTsan(name: []const u8) bool {
    for (untouched_by_tsan) |t| if (std.mem.endsWith(u8, name, t)) return true;
    return false;
}

/// Tests that leave their temporary directory behind on purpose, because a later test reads it,
/// each with why. None does.
const leaves_state = [_][]const u8{};

/// Past this the shards only compete with each other: what is left to wait for is the slowest test.
const max_shards = 32;

const Run = struct {
    io: Io,
    gpa: std.mem.Allocator,
    argv: []const []const u8,
    names: []const []const u8,
    /// The indexes of the tests that run on any shard, and of those that run one at a time.
    free: []const u32,
    alone: []const u32,
    next_free: std.atomic.Value(usize) = .init(0),
    next_alone: std.atomic.Value(usize) = .init(0),
    /// Held by the shard that is running the serial tests.
    alone_lock: Io.Mutex = .init,
    /// Held while a test's result is told, so that two are not mixed.
    say_lock: Io.Mutex = .init,
    passed: std.atomic.Value(usize) = .init(0),
    skipped: std.atomic.Value(usize) = .init(0),
    failed: std.atomic.Value(usize) = .init(0),
    /// How long each test took, by index: each is run once, by one shard, and read after the
    /// shards are joined.
    took_ns: []u64,
    /// Which shard ran each test, by index, for ZIG_TEST_TIMES.
    shard_of: []u8,
    /// When each began and ended, by index, on the real clock (a directory's creation time is on it).
    began_ns: []i128,
    ended_ns: []i128,
};

/// What the shards run with: this process's environment, and where the build copied the runner
/// binary the native tests start, unless told otherwise. The build cannot give that path as an
/// environment variable of this step: a step's variables are fixed when the build is configured
/// (and cached with it), the whole environment included, so a ZIG_TEST_FULL or a PG* variable set
/// later never reached the tests (found 2026-11-16: ZIG_TEST_FULL=1 ran as the 0 it had at the
/// first configure). Without its own map the step passes the live environment on.
var child_env: ?*const std.process.Environ.Map = null;
const native_step_exe = ".zig-cache/native-step/runner";

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    {
        const env = try arena.create(std.process.Environ.Map);
        env.* = try init.environ_map.clone(arena);
        if (env.get("ZIG_RUNNER_TEST_EXE") == null) try env.put("ZIG_RUNNER_TEST_EXE", native_step_exe);
        child_env = env;
    }
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: test_shards [--names] <test binary> [its arguments]\n", .{});
        return 2;
    }
    if (std.mem.eql(u8, args[1], "--names")) {
        if (args.len != 3) {
            std.debug.print("usage: test_shards --names <test binary>\n", .{});
            return 2;
        }
        var shard = try Shard.start(arena, io, &.{ args[2], "--listen=-" });
        defer shard.stop(io);
        var out_buf: [4096]u8 = undefined;
        var out: Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
        for (try shard.testNames(arena)) |name| try out.interface.print("{s}\n", .{name});
        try out.interface.flush();
        return 0;
    }
    const wanted = try shardCount(init.environ_map);
    const part = try partOf(init.environ_map);
    const age_s = ageOf(init.environ_map);
    sweepStale(arena, io, tmp_path, age_s);
    const kept = tmpNames(arena, io, tmp_path);
    const listening = try std.mem.concat(arena, []const u8, &.{
        args[1..2], &.{"--listen=-"}, args[2..],
    });

    // The first shard tells what the tests are.
    var first = try Shard.start(arena, io, listening);
    const names = try first.testNames(arena);
    const shards = @max(1, @min(wanted, names.len));
    // A part is chosen here, test by test: the binary itself would run them all. One shard is no
    // exception: the leak check is made here, and the binary ends with the last test.
    const root = std.os.linux.geteuid() == 0;
    const tsan = if (init.environ_map.get("ZIG_TEST_SANITIZE_THREAD")) |v| std.mem.eql(u8, v, "1") else false;
    var free: std.ArrayList(u32) = .empty;
    var alone: std.ArrayList(u32) = .empty;
    var tsan_skipped: usize = 0;
    const in_part = try inPart(arena, names, part);
    for ([_]bool{ true, false }) |slow_first| {
        for (names, 0..) |name, i| {
            if (!in_part[i]) continue;
            if (tsan and skippedUnderTsan(name)) {
                if (slow_first) {
                    tsan_skipped += 1;
                    std.debug.print("{d}/{d} {s}...SKIP (single-threaded: nothing for ThreadSanitizer to find; the Tests jobs run it)\n", .{ i + 1, names.len, name });
                }
                continue;
            }
            if (slow(name) == slow_first)
                try (if (serial(name, root)) &alone else &free).append(arena, @intCast(i));
        }
    }
    var run: Run = .{
        .io = io,
        .gpa = std.heap.smp_allocator,
        .argv = listening,
        .names = names,
        .free = free.items,
        .alone = alone.items,
        .took_ns = try arena.alloc(u64, names.len),
        .shard_of = try arena.alloc(u8, names.len),
        .began_ns = try arena.alloc(i128, names.len),
        .ended_ns = try arena.alloc(i128, names.len),
    };
    @memset(run.began_ns, 0);
    @memset(run.ended_ns, 0);
    _ = run.skipped.fetchAdd(tsan_skipped, .monotonic);
    @memset(run.took_ns, 0);
    @memset(run.shard_of, 0);
    const started = Io.Clock.awake.now(io);
    const threads = try arena.alloc(std.Thread, shards);
    for (threads, 0..) |*t, i|
        t.* = try std.Thread.spawn(.{}, work, .{ &run, @as(u8, @intCast(i)), if (i == 0) first else null });
    for (threads) |t| t.join();
    leakCheck(arena, &run, tmp_path, kept);

    const failed = run.failed.load(.monotonic);
    const took = started.durationTo(Io.Clock.awake.now(io));
    const seconds = @as(f64, @floatFromInt(took.toNanoseconds())) / std.time.ns_per_s;
    if (timesWanted(init.environ_map)) printTimes(arena, &run, shards) else printSlowest(arena, &run);
    std.debug.print("{d} passed; {d} skipped; {d} failed ({d} shards, {d:.1} s).\n", .{
        run.passed.load(.monotonic), run.skipped.load(.monotonic), failed, shards, seconds,
    });
    return if (failed == 0) 0 else 1;
}

/// Which of `names` are in `part` (all of them without one): the heavy ones to the part with the
/// least weight so far, longest first (the table's order); every N-th of the other slow ones, and
/// every N-th of the rest, each counted on its own, so the slow ones are spread over the parts.
/// Each test is in exactly one of the N parts.
fn inPart(arena: std.mem.Allocator, names: []const []const u8, part: ?Part) ![]bool {
    const in_part = try arena.alloc(bool, names.len);
    const heavy_load = try arena.alloc(u64, if (part) |p| p.of else 0);
    @memset(heavy_load, 0);
    if (part) |p| {
        @memset(in_part, false);
        for (heavy) |h| for (names, 0..) |name, i| {
            if (!std.mem.endsWith(u8, name, h[1])) continue;
            var least: usize = 0;
            for (heavy_load, 0..) |load, k| {
                if (load < heavy_load[least]) least = k;
            }
            heavy_load[least] += h[0];
            in_part[i] = least == p.index;
        };
    }
    var slow_seen: usize = 0;
    var other_seen: usize = 0;
    for (names, in_part) |name, *in| {
        const p = part orelse {
            in.* = true;
            continue;
        };
        if (heavyWeight(name) != null) continue;
        const seen = if (slow(name)) &slow_seen else &other_seen;
        in.* = seen.* % p.of == p.index;
        seen.* += 1;
    }
    return in_part;
}

test "every test is in exactly one part, the heavy ones shared by weight" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var names: std.ArrayList([]const u8) = .empty;
    for (heavy) |h| try names.append(arena, try std.fmt.allocPrint(arena, "native.X.test.{s}", .{h[1]}));
    for (0..50) |i| {
        try names.append(arena, try std.fmt.allocPrint(arena, "native.Y.test.small {d}", .{i}));
        if (i % 7 == 0) try names.append(arena, try std.fmt.allocPrint(arena, "native.Y.test.a container job's ports {d}", .{i}));
    }
    for ([_]usize{ 1, 2, 3 }) |of| {
        const counts = try arena.alloc(u8, names.items.len);
        @memset(counts, 0);
        for (0..of) |k| {
            const in = try inPart(arena, names.items, .{ .index = k, .of = of });
            for (in, counts) |x, *c| c.* += @intFromBool(x);
        }
        for (counts) |c| try std.testing.expectEqual(@as(u8, 1), c);
    }
    // Two parts: the heavy tests' weights differ by less than the lightest of them.
    var weight = [2]u32{ 0, 0 };
    for (0..2) |k| {
        const in = try inPart(arena, names.items, .{ .index = k, .of = 2 });
        for (names.items, in) |name, x| {
            if (x) weight[k] += heavyWeight(name) orelse 0;
        }
    }
    try std.testing.expect(@max(weight[0], weight[1]) - @min(weight[0], weight[1]) < 20);
}

test "every test is in exactly one part when the heavy table is stale or names repeat" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var names: std.ArrayList([]const u8) = .empty;
    // Only every third heavy test still exists: the table's other entries match nothing.
    for (heavy, 0..) |h, i| {
        if (i % 3 != 0) continue;
        const name = try std.fmt.allocPrint(arena, "native.X.test.{s}", .{h[1]});
        try names.append(arena, name);
        // The same name twice (two modules with a test of one name), and a longer name that ends
        // with a heavy entry's text, so it matches that entry too.
        if (i % 2 == 0) try names.append(arena, name);
        try names.append(arena, try std.fmt.allocPrint(arena, "native.Z.test.also {s}", .{h[1]}));
    }
    for (0..20) |i| {
        const small = try std.fmt.allocPrint(arena, "native.Y.test.small {d}", .{i});
        try names.append(arena, small);
        if (i % 4 == 0) try names.append(arena, small);
    }
    for ([_]usize{ 1, 2, 3 }) |of| {
        const counts = try arena.alloc(u8, names.items.len);
        @memset(counts, 0);
        for (0..of) |k| {
            const in = try inPart(arena, names.items, .{ .index = k, .of = of });
            for (in, counts) |x, *c| c.* += @intFromBool(x);
        }
        for (counts) |c| try std.testing.expectEqual(@as(u8, 1), c);
    }
}

/// The tests that took longest, up to `slowest_shown` of those past `slowest_min_ns`: what holds
/// a run, or a part of one (ZIG_TEST_PART), back.
fn printSlowest(arena: std.mem.Allocator, run: *const Run) void {
    const order = arena.alloc(u32, run.took_ns.len) catch return;
    for (order, 0..) |*o, i| o.* = @intCast(i);
    std.mem.sort(u32, order, run.took_ns, struct {
        fn longer(took: []const u64, a: u32, b: u32) bool {
            return took[a] > took[b];
        }
    }.longer);
    for (order[0..@min(slowest_shown, order.len)]) |i| {
        const ns = run.took_ns[i];
        if (ns < slowest_min_ns) break;
        const seconds = @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
        std.debug.print("slow: {d:.1} s {s}\n", .{ seconds, run.names[i] });
    }
}

/// ZIG_TEST_TIMES=1: every test's time and each shard's busy time, instead of the five slowest.
fn timesWanted(environ_map: *const std.process.Environ.Map) bool {
    const v = environ_map.get("ZIG_TEST_TIMES") orelse return false;
    return std.mem.eql(u8, v, "1");
}

fn printTimes(arena: std.mem.Allocator, run: *const Run, shards: usize) void {
    const order = arena.alloc(u32, run.took_ns.len) catch return;
    for (order, 0..) |*o, i| o.* = @intCast(i);
    std.mem.sort(u32, order, run.took_ns, struct {
        fn longer(took: []const u64, a: u32, b: u32) bool {
            return took[a] > took[b];
        }
    }.longer);
    const busy = arena.alloc(u64, shards) catch return;
    const count = arena.alloc(usize, shards) catch return;
    @memset(busy, 0);
    @memset(count, 0);
    var total: u64 = 0;
    for (order) |i| {
        const ns = run.took_ns[i];
        if (ns == 0 and run.began_ns[i] == 0) continue; // not run here (a part, ThreadSanitizer)
        busy[run.shard_of[i]] += ns;
        count[run.shard_of[i]] += 1;
        total += ns;
        std.debug.print("time: {d:.3} s {s}\n", .{ @as(f64, @floatFromInt(ns)) / std.time.ns_per_s, run.names[i] });
    }
    for (busy, count, 0..) |b, c, s| {
        std.debug.print("shard {d}: {d:.1} s busy, {d} tests\n", .{ s + 1, @as(f64, @floatFromInt(b)) / std.time.ns_per_s, c });
    }
    std.debug.print("tests total: {d:.1} s summed\n", .{@as(f64, @floatFromInt(total)) / std.time.ns_per_s});
}

const slowest_shown = 5;
const slowest_min_ns = 2 * std.time.ns_per_s;

const Part = struct {
    /// 0-based: part K of N is index K-1.
    index: usize,
    of: usize,
};

/// ZIG_TEST_PART=K/N (1 <= K <= N), or null to run every test.
fn partOf(environ_map: *const std.process.Environ.Map) !?Part {
    const text = environ_map.get("ZIG_TEST_PART") orelse return null;
    if (text.len == 0) return null;
    bad: {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse break :bad;
        const k = std.fmt.parseUnsigned(usize, text[0..slash], 10) catch break :bad;
        const n = std.fmt.parseUnsigned(usize, text[slash + 1 ..], 10) catch break :bad;
        if (k == 0 or k > n) break :bad;
        return .{ .index = k - 1, .of = n };
    }
    std.debug.print("ZIG_TEST_PART={s}: K/N, with 1 <= K <= N\n", .{text});
    return error.InvalidPart;
}

/// ZIG_TEST_SHARDS, or the cores this process may use.
fn shardCount(environ_map: *const std.process.Environ.Map) !usize {
    if (environ_map.get("ZIG_TEST_SHARDS")) |text| {
        const n = std.fmt.parseUnsigned(usize, text, 10) catch 0;
        if (n == 0) {
            std.debug.print("ZIG_TEST_SHARDS={s}: a number of shards, 1 or more\n", .{text});
            return error.InvalidShards;
        }
        return n;
    }
    return @min(std.Thread.getCpuCount() catch 1, max_shards);
}

/// One shard's thread: tests until none are left. The first to find the serial tests free takes
/// them all, one after another, and then joins the others.
fn work(run: *Run, id: u8, started: ?Shard) void {
    var shard: ?Shard = started;
    defer if (shard) |*s| s.finish(run);
    while (true) {
        const index: u32 = i: {
            if (run.next_alone.load(.monotonic) < run.alone.len and run.alone_lock.tryLock()) {
                defer run.alone_lock.unlock(run.io);
                while (true) {
                    const n = run.next_alone.fetchAdd(1, .monotonic);
                    if (n >= run.alone.len) break;
                    runOne(run, &shard, id, run.alone[n]);
                }
            }
            const n = run.next_free.fetchAdd(1, .monotonic);
            if (n >= run.free.len) return;
            break :i run.free[n];
        };
        runOne(run, &shard, id, index);
    }
}

fn runOne(run: *Run, shard: *?Shard, id: u8, index: u32) void {
    run.shard_of[index] = id;
    if (shard.* == null) shard.* = Shard.start(run.gpa, run.io, run.argv) catch |e| {
        _ = run.failed.fetchAdd(1, .monotonic);
        say(run, index, "the test binary did not start: {t}\n", .{e});
        return;
    };
    const s = &shard.*.?;
    const t0 = Io.Clock.awake.now(run.io);
    run.began_ns[index] = Io.Clock.real.now(run.io).toNanoseconds();
    defer {
        run.took_ns[index] = @intCast(t0.durationTo(Io.Clock.awake.now(run.io)).toNanoseconds());
        run.ended_ns[index] = Io.Clock.real.now(run.io).toNanoseconds();
    }
    const results = s.run(index) catch {
        // The shard is gone, from a panic or a signal; what it said last is in its file.
        _ = run.failed.fetchAdd(1, .monotonic);
        const last = s.output(run.gpa, run.io) catch "";
        defer run.gpa.free(last);
        say(run, index, "the test ended its process ({s})\n{s}", .{ s.wait(run.io), last });
        shard.* = null;
        return;
    };
    const text = s.output(run.gpa, run.io) catch "";
    defer run.gpa.free(text);
    const flags = results.flags;
    // As the build system counts them: an error logged or memory leaked fails a test that passed.
    // So does a ThreadSanitizer report, which the sanitizer only prints (the process would end
    // with a status that `finish` checks, but a report belongs to the test that ran).
    const raced = std.mem.indexOf(u8, text, race_report) != null;
    if (flags.status == .fail or flags.log_err_count != 0 or flags.leak_count != 0 or raced) {
        _ = run.failed.fetchAdd(1, .monotonic);
        s.raced = s.raced or raced;
        say(run, index, "{s}{s}{s}{s}", .{
            text,
            if (flags.log_err_count != 0) "error(s) were logged\n" else "",
            if (flags.leak_count != 0) "memory leaked\n" else "",
            if (raced) "a data race was reported\n" else "",
        });
    } else if (flags.status == .skip) {
        _ = run.skipped.fetchAdd(1, .monotonic);
        // A test that says why it skipped (a native one that cannot make a sandbox) keeps saying
        // it, on one line; a silent skip is silent.
        const why = std.mem.trim(u8, text, " \r\n");
        if (why.len > 0) {
            const line = run.gpa.dupe(u8, why) catch return;
            defer run.gpa.free(line);
            std.mem.replaceScalar(u8, line, '\n', ' ');
            run.say_lock.lockUncancelable(run.io);
            defer run.say_lock.unlock(run.io);
            std.debug.print("{d}/{d} {s}...SKIP ({s})\n", .{
                index + 1, run.names.len, run.names[index], line,
            });
        }
    } else _ = run.passed.fetchAdd(1, .monotonic);
}

/// What ThreadSanitizer prints for a race, on the shard's stderr.
const race_report = "WARNING: ThreadSanitizer";

/// A failed test: its place in the run and its name, as the stock runner says them, then `what`.
fn say(run: *Run, index: u32, comptime what: []const u8, args: anytype) void {
    run.say_lock.lockUncancelable(run.io);
    defer run.say_lock.unlock(run.io);
    const name = run.names[index];
    std.debug.print("{d}/{d} {s}...FAIL\n", .{ index + 1, run.names.len, name });
    std.debug.print(what, args);
}

/// A copy of the test binary serving the test runner's protocol on pipes, its stderr in a file.
const Shard = struct {
    child: std.process.Child,
    err: Io.File,
    err_at: u64 = 0,
    /// A test of this shard failed on a race report, which the process's own status repeats.
    raced: bool = false,
    reader: *Io.File.Reader,
    writer: *Io.File.Writer,

    fn start(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) !Shard {
        // Unlinked at once: the child and this keep it open.
        var random: [8]u8 = undefined;
        io.random(&random);
        const path = try std.fmt.allocPrint(gpa, "/tmp/zig-test-shard-{x}", .{random});
        defer gpa.free(path);
        const err = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .exclusive = true });
        errdefer err.close(io);
        Io.Dir.cwd().deleteFile(io, path) catch {};
        var child = try std.process.spawn(io, .{
            .argv = argv,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .{ .file = err },
            .environ_map = child_env,
        });
        errdefer child.kill(io);
        const reader = try gpa.create(Io.File.Reader);
        reader.* = .initStreaming(child.stdout.?, io, try gpa.alloc(u8, 4096));
        const writer = try gpa.create(Io.File.Writer);
        writer.* = .initStreaming(child.stdin.?, io, try gpa.alloc(u8, 64));
        var shard: Shard = .{ .child = child, .err = err, .reader = reader, .writer = writer };
        // Its first word is its Zig's version.
        const hello = try shard.header();
        if (hello.tag != .zig_version) return error.UnexpectedMessage;
        try reader.interface.discardAll(hello.bytes_len);
        return shard;
    }

    fn header(s: *Shard) !Reply {
        return s.reader.interface.takeStruct(Reply, .little);
    }

    /// The names of the binary's tests, in the order its indexes count them.
    fn testNames(s: *Shard, arena: std.mem.Allocator) ![]const []const u8 {
        const out = &s.writer.interface;
        try out.writeStruct(Request{ .tag = .query_test_metadata, .bytes_len = 0 }, .little);
        try out.flush();
        const hdr = try s.header();
        if (hdr.tag != .test_metadata) return error.UnexpectedMessage;
        const body = try arena.alloc(u8, hdr.bytes_len);
        try s.reader.interface.readSliceAll(body);
        const meta_len = @sizeOf(std.zig.Server.Message.TestMetadata);
        const meta = std.mem.bytesToValue(std.zig.Server.Message.TestMetadata, body[0..meta_len]);
        const strings = body[meta_len + 8 * meta.tests_len ..][0..meta.string_bytes_len];
        const names = try arena.alloc([]const u8, meta.tests_len);
        for (names, 0..) |*name, i| {
            const at = std.mem.readInt(u32, body[meta_len + 4 * i ..][0..4], .little);
            name.* = std.mem.sliceTo(strings[at..], 0);
        }
        return names;
    }

    /// Runs one test and waits for its result.
    fn run(s: *Shard, index: u32) !Results {
        const out = &s.writer.interface;
        try out.writeStruct(Request{ .tag = .run_test, .bytes_len = 4 }, .little);
        try out.writeInt(u32, index, .little);
        try out.flush();
        while (true) {
            const hdr = try s.header();
            switch (hdr.tag) {
                .test_started => try s.reader.interface.discardAll(hdr.bytes_len),
                .test_results => {
                    const results = try s.reader.interface.takeStruct(Results, .little);
                    if (results.index != index) return error.UnexpectedMessage;
                    return results;
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    /// What the shard wrote to stderr since the last call. Owned by the caller.
    fn output(s: *Shard, gpa: std.mem.Allocator, io: Io) ![]u8 {
        const size = (try s.err.stat(io)).size;
        const text = try gpa.alloc(u8, size - s.err_at);
        errdefer gpa.free(text);
        if (try s.err.readPositionalAll(io, text, s.err_at) != text.len) return error.EndOfStream;
        s.err_at += text.len;
        return text;
    }

    /// How a shard that ended ended.
    fn wait(s: *Shard, io: Io) []const u8 {
        const term = s.child.wait(io) catch return "unknown";
        s.err.close(io);
        return switch (term) {
            .exited => "exited",
            .signal => "killed by a signal",
            else => "stopped",
        };
    }

    /// Ends a shard that the run is done with, and fails the run if the process did not end well:
    /// ThreadSanitizer reports found after the last test (a thread still running, an exit-time
    /// check) leave it with a status, and its text is on stderr, unread until now.
    fn finish(s: *Shard, job: *Run) void {
        const term = s.end(job.io);
        const ok = if (term) |t| switch (t) {
            .exited => |code| code == 0,
            else => false,
        } else false;
        if (!ok and !s.raced) {
            _ = job.failed.fetchAdd(1, .monotonic);
            const rest = s.output(job.gpa, job.io) catch "";
            defer if (rest.len > 0) job.gpa.free(rest);
            job.say_lock.lockUncancelable(job.io);
            defer job.say_lock.unlock(job.io);
            std.debug.print("a test binary ended with a failing status after its last test\n{s}", .{rest});
        }
        s.err.close(job.io);
    }

    /// Asks the shard to exit and waits for it.
    fn end(s: *Shard, io: Io) ?std.process.Child.Term {
        s.writer.interface.writeStruct(Request{ .tag = .exit, .bytes_len = 0 }, .little) catch {};
        s.writer.interface.flush() catch {};
        s.child.stdin.?.close(io);
        s.child.stdin = null;
        return s.child.wait(io) catch null;
    }

    fn stop(s: *Shard, io: Io) void {
        _ = s.end(io);
        s.err.close(io);
    }
};

// The leak check.

const linux = std.os.linux;
const tmp_path = ".zig-cache/tmp";
const coarse_ns = 50 * std.time.ns_per_ms;

/// ZIG_TEST_SWEEP_AGE_S, default half an hour.
fn ageOf(environ_map: *const std.process.Environ.Map) i64 {
    const text = environ_map.get("ZIG_TEST_SWEEP_AGE_S") orelse return 1800;
    return std.fmt.parseInt(i64, text, 10) catch 1800;
}

/// The names in `tmp` (`tmp_path`, or a directory of a test's own); none when it is not there.
fn tmpNames(arena: std.mem.Allocator, io: Io, tmp: []const u8) []const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    var dir = Io.Dir.cwd().openDir(io, tmp, .{ .iterate = true }) catch return &.{};
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        const name = arena.dupe(u8, e.name) catch return names.items;
        names.append(arena, name) catch return names.items;
    }
    return names.items;
}

fn inList(list: []const []const u8, name: []const u8) bool {
    for (list) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

/// What a directory held: how deep it went, and the first paths of it (to a depth of 6).
const Found = struct {
    depth: usize = 0,
    paths: std.ArrayList([]const u8) = .empty,
};

/// Removes the directory `name` of `parent`, and what is in it, however deep: from the bottom, by
/// names relative to a descriptor, going up through `..` (the full path of the deepest is too long
/// to name). Best effort: what cannot be removed stays, and is said.
fn wipe(arena: std.mem.Allocator, io: Io, parent: linux.fd_t, name: [:0]const u8, found: *Found) void {
    var names: std.ArrayList([:0]const u8) = .empty;
    var cur = openDirAt(parent, name) orelse return;
    defer _ = linux.close(cur);
    while (true) {
        const first: ?[:0]const u8 = first: {
            const again = openDirAt(cur, ".") orelse return;
            defer _ = linux.close(again);
            var d: Io.Dir = .{ .handle = again };
            var it = d.iterate();
            const e = (it.next(io) catch return) orelse break :first null;
            break :first arena.dupeSentinel(u8, e.name, 0) catch return;
        };
        if (first) |entry| {
            found.depth = @max(found.depth, names.items.len + 1);
            if (names.items.len < 6 and found.paths.items.len < 10) {
                var path: std.ArrayList(u8) = .empty;
                for (names.items) |n| path.print(arena, "{s}/", .{n}) catch return;
                path.appendSlice(arena, entry) catch return;
                found.paths.append(arena, path.items) catch return;
            }
            switch (linux.errno(linux.unlinkat(cur, entry, 0))) {
                .SUCCESS => continue,
                .ISDIR, .PERM => {},
                else => return,
            }
            const down = openDirAt(cur, entry) orelse return;
            _ = linux.close(cur);
            cur = down;
            names.append(arena, entry) catch return;
        } else {
            const dir_name = names.pop() orelse break;
            const up = openDirAt(cur, "..") orelse return;
            _ = linux.close(cur);
            cur = up;
            if (linux.errno(linux.unlinkat(cur, dir_name, linux.AT.REMOVEDIR)) != .SUCCESS) return;
        }
    }
    _ = linux.close(cur);
    cur = -1;
    _ = linux.unlinkat(parent, name, linux.AT.REMOVEDIR);
}

fn openDirAt(parent: linux.fd_t, name: [*:0]const u8) ?linux.fd_t {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true };
    const rc = linux.openat(parent, name, flags, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

/// Directories an earlier run left, older than `age_s`, removed: a run killed in the middle (a
/// timeout, the OOM killer) could not remove its own. Not one a process holds open (or may: see
/// `heldOpen`): a long test of another run is no leftover.
fn sweepStale(arena: std.mem.Allocator, io: Io, tmp_dir: []const u8, age_s: i64) void {
    var tmp = Io.Dir.cwd().openDir(io, tmp_dir, .{ .iterate = true }) catch return;
    defer tmp.close(io);
    const now_s = Io.Clock.real.now(io).toSeconds();
    for (tmpNames(arena, io, tmp_dir)) |name| {
        const st = tmp.statFile(io, name, .{ .follow_symlinks = false }) catch continue;
        if (now_s - st.mtime.toSeconds() < age_s) continue;
        if (heldOpen(arena, io, tmp_dir, name) != .no) continue;
        var found: Found = .{};
        const z = arena.dupeSentinel(u8, name, 0) catch continue;
        wipe(arena, io, tmp.handle, z, &found);
        std.debug.print("test_shards: removed {s}/{s}, left by an earlier run (depth {d})\n", .{ tmp_dir, name, found.depth });
    }
}

/// What the run left in `.zig-cache/tmp` beyond what was there at its start (`kept`): reported, its
/// owner among the tests that ran then named, and removed. The run fails.
fn leakCheck(arena: std.mem.Allocator, run: *Run, tmp_dir: []const u8, kept: []const []const u8) void {
    const io = run.io;
    var tmp = Io.Dir.cwd().openDir(io, tmp_dir, .{ .iterate = true }) catch return;
    defer tmp.close(io);
    for (tmpNames(arena, io, tmp_dir)) |name| {
        if (inList(kept, name)) continue;
        // Another run's, in this directory at the same time, has a process holding it open. One
        // that may have (`heldOpen`: a test of another user, which /proc hides) is not this run's
        // to report either: whatever is new here was made after this run began, so nothing tells
        // whose it is. The check is then blind to that directory, which is said, not failed.
        switch (heldOpen(arena, io, tmp_dir, name)) {
            .yes => continue,
            .maybe => {
                std.debug.print("test_shards: {s}/{s} is new, and a test of another user may hold it: not checked\n", .{ tmp_dir, name });
                continue;
            },
            .no => {},
        }
        const z = arena.dupeSentinel(u8, name, 0) catch continue;
        // When it was made: the tests running then, one of which left it.
        var born_ns: i128 = 0;
        var sx: linux.Statx = undefined;
        if (linux.errno(linux.statx(tmp.handle, z, linux.AT.SYMLINK_NOFOLLOW, .{ .BTIME = true }, &sx)) == .SUCCESS)
            born_ns = @as(i128, sx.btime.sec) * std.time.ns_per_s + sx.btime.nsec;
        var owners: std.ArrayList(u32) = .empty;
        // Set when memory ran out while listing them: the report then says its list is incomplete.
        var owners_short = false;
        for (0..run.names.len) |i| {
            if (run.began_ns[i] == 0) continue;
            // A creation time is the kernel's coarse clock, a few milliseconds behind this one.
            if (run.began_ns[i] - coarse_ns <= born_ns and born_ns <= run.ended_ns[i]) owners.append(arena, @intCast(i)) catch {
                owners_short = true;
            };
        }
        var found: Found = .{};
        wipe(arena, io, tmp.handle, z, &found);
        // A test that leaves its directory on purpose, and nothing else running then.
        var allowed = owners.items.len > 0 and !owners_short;
        for (owners.items) |i| {
            var listed = false;
            for (leaves_state) |t| listed = listed or std.mem.endsWith(u8, run.names[i], t);
            allowed = allowed and listed;
        }
        if (allowed) continue;
        _ = run.failed.fetchAdd(1, .monotonic);
        std.debug.print("LEAK {s}/{s}: left in the tests' temporary directory (depth {d}); removed. ", .{ tmp_dir, name, found.depth });
        if (owners.items.len == 0) {
            std.debug.print("No test was running when it was made.\n", .{});
        } else {
            std.debug.print("Made while {s}: ", .{if (owners.items.len == 1) "this ran" else "these ran, one left it"});
            for (owners.items) |i| std.debug.print("\n  {s}", .{run.names[i]});
            if (owners_short) std.debug.print("\n  (more, not listed: out of memory)", .{});
            std.debug.print("\n", .{});
        }
        for (found.paths.items) |p| std.debug.print("  {s}/{s}\n", .{ name, p });
    }
}

const Held = enum { no, yes, maybe };

/// Whether a process has `<tmp_dir>/<name>` open (or a directory in it): a test running, in
/// another run that shares this directory. `maybe` when a process whose fds /proc hides from this
/// one (another user's: a root container's tests) looks like a test run (`looksLikeTests`) and none
/// that can be read holds it.
fn heldOpen(arena: std.mem.Allocator, io: Io, tmp_dir: []const u8, name: []const u8) Held {
    const needle = std.fmt.allocPrint(arena, "{s}/{s}", .{ tmp_dir, name }) catch return .yes;
    var proc = Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true }) catch return .no;
    defer proc.close(io);
    var hidden = false;
    var pids = proc.iterate();
    while (pids.next(io) catch null) |p| {
        _ = std.fmt.parseInt(u32, p.name, 10) catch continue;
        const fd_path = std.fmt.allocPrint(arena, "/proc/{s}/fd", .{p.name}) catch return .yes;
        var fds = Io.Dir.cwd().openDir(io, fd_path, .{ .iterate = true }) catch |e| {
            if (e == error.AccessDenied or e == error.PermissionDenied) {
                const cmd_path = std.fmt.allocPrint(arena, "/proc/{s}/cmdline", .{p.name}) catch return .yes;
                var buf: [4096]u8 = undefined;
                const cmd = Io.Dir.cwd().readFile(io, cmd_path, &buf) catch continue;
                if (looksLikeTests(cmd)) hidden = true;
            }
            continue;
        };
        defer fds.close(io);
        var it = fds.iterate();
        while (it.next(io) catch null) |e| {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const n = fds.readLink(io, e.name, &buf) catch continue;
            if (std.mem.indexOf(u8, buf[0..n], needle) != null) return .yes;
        }
    }
    return if (hidden) .maybe else .no;
}

/// Whether a command line (NUL-separated arguments) is a test run: the shard runner, or a test
/// binary of the build cache.
fn looksLikeTests(cmdline: []const u8) bool {
    return std.mem.indexOf(u8, cmdline, "test_shards") != null or
        std.mem.indexOf(u8, cmdline, ".zig-cache") != null or
        std.mem.indexOf(u8, cmdline, "--listen=-") != null;
}

// Tests. Each works in a directory of its own under `.zig-cache/tmp` (`std.testing.tmpDir`), named
// to the functions above as the tests' temporary directory.

fn testRun(arena: std.mem.Allocator) !Run {
    return .{
        .io = std.testing.io,
        .gpa = std.testing.allocator,
        .argv = &.{},
        .names = &.{},
        .free = &.{},
        .alone = &.{},
        .took_ns = try arena.alloc(u64, 0),
        .shard_of = try arena.alloc(u8, 0),
        .began_ns = try arena.alloc(i128, 0),
        .ended_ns = try arena.alloc(i128, 0),
    };
}

/// `depth` nested directories "a" in `parent`'s directory `name`, made by names relative to a
/// descriptor (the path is too long to name).
fn makeChain(parent: linux.fd_t, name: [:0]const u8, depth: usize) !void {
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mkdirat(parent, name, 0o755)));
    var cur = openDirAt(parent, name) orelse return error.TestUnexpectedResult;
    for (0..depth) |_| {
        // A filesystem that will not make a chain so deep (overlayfs) skips the test.
        if (linux.errno(linux.mkdirat(cur, "a", 0o755)) != .SUCCESS) return error.SkipZigTest;
        const down = openDirAt(cur, "a") orelse return error.TestUnexpectedResult;
        _ = linux.close(cur);
        cur = down;
    }
    _ = linux.close(cur);
}

test "wipe removes a chain of directories too deep to name" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try makeChain(tmp.dir.handle, "deep", 5000);
    var found: Found = .{};
    wipe(a.allocator(), std.testing.io, tmp.dir.handle, "deep", &found);
    try std.testing.expectEqual(@as(usize, 5000), found.depth);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "deep", .{}));
}

test "leakCheck flags a directory the tests left, names it, removes it, and fails the run" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const where = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try tmp.dir.createDir(std.testing.io, "kept", .default_dir);
    const kept = tmpNames(arena, std.testing.io, where);
    try tmp.dir.createDir(std.testing.io, "leaked", .default_dir);
    try makeChain(tmp.dir.handle, "leaked-deep", 300);
    var run = try testRun(arena);
    leakCheck(arena, &run, where, kept);
    // The two new ones are leaks (with no test running when they were made); `kept` is not.
    try std.testing.expectEqual(@as(usize, 2), run.failed.load(.monotonic));
    try tmp.dir.access(std.testing.io, "kept", .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "leaked", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "leaked-deep", .{}));
    // Nothing new, nothing reported.
    leakCheck(arena, &run, where, tmpNames(arena, std.testing.io, where));
    try std.testing.expectEqual(@as(usize, 2), run.failed.load(.monotonic));
}

test "heldOpen sees a directory a process has open, and sweepStale and leakCheck leave it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const where = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    const kept = tmpNames(arena, io, where);
    try tmp.dir.createDir(io, "busy", .default_dir);
    try tmp.dir.createDir(io, "idle", .default_dir);
    // This process holds `busy`; the answer for `idle` is no (or maybe, where a process hidden
    // from this one looks like a test run: never yes).
    var busy = try tmp.dir.openDir(io, "busy", .{});
    try std.testing.expectEqual(Held.yes, heldOpen(arena, io, where, "busy"));
    try std.testing.expect(heldOpen(arena, io, where, "idle") != .yes);
    // Both are "old" at age 0, but the one held is left alone.
    sweepStale(arena, io, where, 0);
    try tmp.dir.access(io, "busy", .{});
    var run = try testRun(arena);
    leakCheck(arena, &run, where, kept);
    try tmp.dir.access(io, "busy", .{});
    try std.testing.expectEqual(@as(usize, 0), run.failed.load(.monotonic));
    busy.close(io);
    // Closed, it is a leftover as any other.
    sweepStale(arena, io, where, 0);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "busy", .{}));
}

test "a command line that is a test run, and one that is not" {
    try std.testing.expect(looksLikeTests("/w/.zig-cache/o/abc/test\x00--listen=-\x00"));
    try std.testing.expect(looksLikeTests("test_shards\x00/w/t"));
    try std.testing.expect(!looksLikeTests("/usr/bin/firefox\x00--new-tab\x00"));
}
