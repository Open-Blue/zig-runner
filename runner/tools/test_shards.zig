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
//! ZIG_TEST_PART=K/N runs only part K of N: every N-th test, starting at the K-th, so N machines
//! share a suite (CI's native tests as root, which run one at a time on each).
//! `zig build test -Dshard-tests=false` runs the tests without it.
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
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
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
    const listening = try std.mem.concat(arena, []const u8, &.{
        args[1..2], &.{"--listen=-"}, args[2..],
    });

    // The first shard tells what the tests are.
    var first = try Shard.start(arena, io, listening);
    const names = try first.testNames(arena);
    const shards = @min(wanted, names.len);
    // A part is chosen here, test by test: the binary itself would run them all.
    if (shards <= 1 and part == null) {
        first.stop(io);
        const err = std.process.replace(io, .{ .argv = args[1..] });
        std.debug.print("{s}: {t}\n", .{ args[1], err });
        return 1;
    }

    const root = std.os.linux.geteuid() == 0;
    const tsan = if (init.environ_map.get("ZIG_TEST_SANITIZE_THREAD")) |v| std.mem.eql(u8, v, "1") else false;
    var free: std.ArrayList(u32) = .empty;
    var alone: std.ArrayList(u32) = .empty;
    var tsan_skipped: usize = 0;
    // A part's tests: every N-th of the slow ones, and every N-th of the others, each counted on
    // its own, so the slow ones are spread over the parts.
    const in_part = try arena.alloc(bool, names.len);
    var slow_seen: usize = 0;
    var other_seen: usize = 0;
    for (names, in_part) |name, *in| {
        const p = part orelse {
            in.* = true;
            continue;
        };
        const seen = if (slow(name)) &slow_seen else &other_seen;
        in.* = seen.* % p.of == p.index;
        seen.* += 1;
    }
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
    };
    _ = run.skipped.fetchAdd(tsan_skipped, .monotonic);
    @memset(run.took_ns, 0);
    const started = Io.Clock.awake.now(io);
    const threads = try arena.alloc(std.Thread, shards);
    for (threads, 0..) |*t, i|
        t.* = try std.Thread.spawn(.{}, work, .{ &run, if (i == 0) first else null });
    for (threads) |t| t.join();

    const failed = run.failed.load(.monotonic);
    const took = started.durationTo(Io.Clock.awake.now(io));
    const seconds = @as(f64, @floatFromInt(took.toNanoseconds())) / std.time.ns_per_s;
    printSlowest(arena, &run);
    std.debug.print("{d} passed; {d} skipped; {d} failed ({d} shards, {d:.1} s).\n", .{
        run.passed.load(.monotonic), run.skipped.load(.monotonic), failed, shards, seconds,
    });
    return if (failed == 0) 0 else 1;
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
fn work(run: *Run, started: ?Shard) void {
    var shard: ?Shard = started;
    defer if (shard) |*s| s.stop(run.io);
    while (true) {
        const index: u32 = i: {
            if (run.next_alone.load(.monotonic) < run.alone.len and run.alone_lock.tryLock()) {
                defer run.alone_lock.unlock(run.io);
                while (true) {
                    const n = run.next_alone.fetchAdd(1, .monotonic);
                    if (n >= run.alone.len) break;
                    runOne(run, &shard, run.alone[n]);
                }
            }
            const n = run.next_free.fetchAdd(1, .monotonic);
            if (n >= run.free.len) return;
            break :i run.free[n];
        };
        runOne(run, &shard, index);
    }
}

fn runOne(run: *Run, shard: *?Shard, index: u32) void {
    if (shard.* == null) shard.* = Shard.start(run.gpa, run.io, run.argv) catch |e| {
        _ = run.failed.fetchAdd(1, .monotonic);
        say(run, index, "the test binary did not start: {t}\n", .{e});
        return;
    };
    const s = &shard.*.?;
    const t0 = Io.Clock.awake.now(run.io);
    defer run.took_ns[index] = @intCast(t0.durationTo(Io.Clock.awake.now(run.io)).toNanoseconds());
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
    if (flags.status == .fail or flags.log_err_count != 0 or flags.leak_count != 0) {
        _ = run.failed.fetchAdd(1, .monotonic);
        say(run, index, "{s}{s}{s}", .{
            text,
            if (flags.log_err_count != 0) "error(s) were logged\n" else "",
            if (flags.leak_count != 0) "memory leaked\n" else "",
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

    fn stop(s: *Shard, io: Io) void {
        s.writer.interface.writeStruct(Request{ .tag = .exit, .bytes_len = 0 }, .little) catch {};
        s.writer.interface.flush() catch {};
        s.child.stdin.?.close(io);
        s.child.stdin = null;
        _ = s.child.wait(io) catch {};
        s.err.close(io);
    }
};
