//! A job's upkeep of the store (the layers' directory synced, `Store.collect`), run after the job's
//! end has returned and the runner is polling again, rather than before. Nothing in it is on the
//! way to the next job: the result is reported already, the job's layers are let go, and what
//! `collect` frees is room that only the cap and the disk's floor ask for. On a slow disk the two
//! cost a job's end 10 to 25 ms, and 200 to 700 ms when the disk was busy.
//!
//! One thread at a time, started when a job hands its upkeep over and gone when none is left. Jobs
//! that end while it works are queued, and their syncs are done each, but one `collect` serves all
//! of them: it keeps the store under its cap for the layers they all published, so a burst of jobs
//! costs one pass, not one each. A full queue, or a thread that cannot be started, is the job's to
//! run inline (`submit` says so), as is a store that may be past its cap (`Store.lagFits`): the cap
//! is held to within `Store.lagMargin`, and a collect that lags further than that is waited for.
//!
//! A new job is not held up by it. The one lock `collect` takes that a job's set-up could wait for
//! is `gc.lock`, and only the first job after a boot waits for that (`Store.checkOncePerBoot`), for
//! a pass: a few ms, and at most the pass's own budget (`Eviction.Limits.budget_ms`). What a pass
//! evicts is what no job holds, as before: a layer a new job holds is never taken, and the
//! evictions keep to the order of use that the jobs' ends left (`Store.touchChain`, which still runs
//! before the job's end returns).
//!
//! A runner that is stopped waits for the thread, within a limit (`drain`). What it leaves, a pass
//! cut short or the process killed, is what a crash during an inline `collect` always left: an
//! eviction is one rename, and the tree under its dead name is swept by the next pass.

const std = @import("std");

const Store = @import("Store.zig");
const phases = @import("phases.zig");

/// The most jobs' upkeep waiting. A burst this long is the caller's to run inline.
const max_queued = 8;

const gpa = std.heap.page_allocator;

/// What a job hands over: its own copy of the store's handle, owning every byte of it, so the job's
/// arena goes with its end (`Store.detach`).
const Task = struct {
    arena: std.heap.ArenaAllocator,
    store: Store,
    /// Whether the job published a layer: its renames are in the layers' directory, not yet synced.
    sync: bool,
    /// The job's id, for the log line of the pass that serves it.
    job_id: u64,

    fn destroy(t: *Task) void {
        t.arena.deinit();
        gpa.destroy(t);
    }
};

var mu: std.Io.Mutex = .init;
var queue: [max_queued]*Task = undefined;
var queued: usize = 0;
/// Whether a thread is running, decided under `mu`: set by whoever starts one, cleared by the
/// thread when it finds the queue empty.
var running = false;

/// Tests: how many passes ran, and how many ran at once at the most.
pub var passes: std.atomic.Value(u32) = .init(0);
var active: std.atomic.Value(u32) = .init(0);
pub var most_active: std.atomic.Value(u32) = .init(0);
/// Tests of a whole job: whether its end waits for the thread, so that what the store holds is as
/// when the end collected itself. The stress test turns it off to run the thread as it runs.
pub var test_wait = true;
/// Tests: while set, the thread takes no work, so a test can queue several jobs' upkeep.
pub var test_hold: std.atomic.Value(bool) = .init(false);

/// Hands `s`'s upkeep over: `sync` if the job published a layer; `job_id` is named in the log. False when it is not taken (no
/// room, the job's sync failed, the queue is full, no thread could be started), and then it is the
/// caller's to run before it returns. Everything the thread uses is copied here, from the caller's
/// arena, which may be freed as soon as this returns.
pub fn submit(io: std.Io, s: Store, sync: bool, job_id: u64) bool {
    const t = gpa.create(Task) catch return false;
    t.* = .{ .arena = .init(gpa), .store = undefined, .sync = sync, .job_id = job_id };
    t.store = s.detach(t.arena.allocator()) orelse {
        t.destroy();
        return false;
    };
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    if (queued == max_queued) {
        t.destroy();
        return false;
    }
    queue[queued] = t;
    queued += 1;
    if (!running and !spawn(io)) {
        queued -= 1;
        t.destroy();
        return false;
    }
    return true;
}

/// Starts the thread, under `mu`; false when none could be.
fn spawn(io: std.Io) bool {
    running = true;
    // The default stack, as the reaper's: `collect` keeps path buffers on it.
    const thread = std.Thread.spawn(.{}, run, .{io}) catch {
        running = false;
        return false;
    };
    thread.detach();
    return true;
}

/// Whether upkeep is waiting or running.
pub fn pending(io: std.Io) bool {
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    return running or queued > 0;
}

/// Waits for the queue to be empty and the thread gone, for at most `limit_ms` (null: as long as it
/// takes); whether it is. A stopping runner calls it so that the pass it started is not cut off,
/// and a second signal does not wait for it (`main.onStopSignal`).
pub fn drain(io: std.Io, limit_ms: ?u64) bool {
    const start = phases.now();
    while (pending(io)) {
        if (limit_ms) |l| if (phases.now() -| start > l * std.time.ns_per_ms) return false;
        io.sleep(.fromMilliseconds(2), .awake) catch return false;
    }
    return true;
}

fn run(io: std.Io) void {
    while (true) {
        while (test_hold.load(.acquire)) io.sleep(.fromMilliseconds(1), .awake) catch return;
        var batch: [max_queued]*Task = undefined;
        mu.lockUncancelable(io);
        if (queued == 0) {
            running = false;
            mu.unlock(io);
            return;
        }
        const n = queued;
        @memcpy(batch[0..n], queue[0..n]);
        queued = 0;
        mu.unlock(io);
        pass(io, batch[0..n]);
        for (batch[0..n]) |t| t.destroy();
    }
}

/// Each task's layers synced, then one `collect` for the store each names (the last task's handle:
/// they differ only in their logs).
fn pass(io: std.Io, tasks: []const *Task) void {
    const now_active = active.fetchAdd(1, .acq_rel) + 1;
    defer _ = active.fetchSub(1, .acq_rel);
    _ = most_active.fetchMax(now_active, .monotonic);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var ph: phases.Phases = .{};
    const start = phases.now();
    var t = start;
    for (tasks) |task| {
        if (task.sync) task.store.syncLayers(arena);
        task.store.dropUnsynced(arena, io);
    }
    t = ph.since(arena, .collect_syncdir, t);
    for (tasks, 0..) |task, i| {
        if (task.store.root.len == 0) continue;
        var later = false;
        for (tasks[i + 1 ..]) |other| later = later or std.mem.eql(u8, other.store.root, task.store.root);
        if (!later) task.store.collectTimed(arena, io, &ph);
    }
    _ = ph.since(arena, .collect, t);
    _ = passes.fetchAdd(1, .monotonic);
    const text = ph.text(arena, null, .all) catch return;
    // The jobs it served, so that an analysis can give each its share (`native-phases.sh`).
    var ids: std.Io.Writer.Allocating = .init(arena);
    for (tasks, 0..) |task, i| ids.writer.print("{s}{d}", .{ if (i > 0) "," else "", task.job_id }) catch return;
    std.log.info("native: store upkeep of job(s) {s}, after they returned (ms): {s}", .{ ids.written(), text });
}

const testing = std.testing;

fn testStore(arena: std.mem.Allocator, io: std.Io, tmp: std.testing.TmpDir) !Store {
    var s: Store = .{ .root = "", .defer_collect = true, .sync_log = Store.newSyncLog(arena) };
    const k, const l = try Store.testLayer(arena, io, tmp, &s, "seed");
    _ = k;
    l.lock.close(io);
    return s;
}

test "collector: a job's upkeep runs on the thread, after submit returned, from a copy that outlives the job's arena" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var job: std.heap.ArenaAllocator = .init(testing.allocator);
    var s = try testStore(job.allocator(), io, tmp);
    s.max_bytes = 0;
    const root = try testing.allocator.dupe(u8, s.root);
    defer testing.allocator.free(root);
    test_hold.store(true, .release);
    defer test_hold.store(false, .release);
    try testing.expect(submit(io, s, true, 0));
    // The job's end returns and frees its arena: the thread has only its own copy.
    job.deinit();
    try testing.expect(pending(io));
    var check: std.heap.ArenaAllocator = .init(testing.allocator);
    defer check.deinit();
    // Nothing has run: the layer is still there, evicted by no one.
    try testing.expectEqual(@as(usize, 1), (try Store.layerNames(check.allocator(), io, .{ .root = root })).len);
    test_hold.store(false, .release);
    try testing.expect(drain(io, 10_000));
    try testing.expectEqual(@as(usize, 0), (try Store.layerNames(check.allocator(), io, .{ .root = root })).len);
}

test "collector: jobs ending together are served by one pass at a time, and each one's log is acted on" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const s = try testStore(arena, io, tmp);
    test_hold.store(true, .release);
    defer test_hold.store(false, .release);
    const passes_before = passes.load(.monotonic);
    most_active.store(0, .monotonic);
    for (0..5) |_| try testing.expect(submit(io, s, true, 0));
    test_hold.store(false, .release);
    try testing.expect(drain(io, 10_000));
    // The five were queued before the thread took any: one pass served them.
    try testing.expectEqual(passes_before + 1, passes.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), most_active.load(.monotonic));
    // A queue longer than `max_queued` is the caller's own.
    test_hold.store(true, .release);
    var taken: usize = 0;
    for (0..max_queued + 3) |_| taken += @intFromBool(submit(io, s, false, 0));
    try testing.expectEqual(@as(usize, max_queued), taken);
    test_hold.store(false, .release);
    try testing.expect(drain(io, 10_000));
}

test "collector: the copy keeps the job's log and root as they were, and is none for a job whose sync failed" {
    const io = testing.io;
    _ = io;
    var job: std.heap.ArenaAllocator = .init(testing.allocator);
    const log = Store.newSyncLog(job.allocator()).?;
    try log.since.append(job.allocator(), try job.allocator().dupe(u8, "aa"));
    var own: std.heap.ArenaAllocator = .init(testing.allocator);
    defer own.deinit();
    const root = try job.allocator().dupe(u8, "/some/store");
    const copy = (Store{ .root = root, .sync_log = log, .sync_fd = 7 }).detach(own.allocator()).?;
    // The job's end changes and frees everything it had.
    log.since.clearRetainingCapacity();
    @memset(@constCast(root), 'x');
    job.deinit();
    try testing.expectEqualStrings("/some/store", copy.root);
    try testing.expectEqual(@as(usize, 1), copy.sync_log.?.since.items.len);
    try testing.expectEqualStrings("aa", copy.sync_log.?.since.items[0]);
    try testing.expect(copy.sync_fd == null);
    var failed: Store.SyncLog = .{ .failed = true };
    try testing.expect((Store{ .root = "r", .sync_log = &failed }).detach(own.allocator()) == null);
}

test "collector: a job whose sync failed is not taken, and a layer a job holds is never evicted" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var s: Store = .{ .root = "", .defer_collect = true, .sync_log = Store.newSyncLog(arena), .max_bytes = 0 };
    const k, const held = try Store.testLayer(arena, io, tmp, &s, "held");
    _ = k;
    const k2, const free = try Store.testLayer(arena, io, tmp, &s, "free");
    free.lock.close(io);
    s.sync_log.?.failed = true;
    try testing.expect(!submit(io, s, true, 0));
    s.sync_log.?.failed = false;
    try testing.expect(submit(io, s, true, 0));
    try testing.expect(drain(io, 10_000));
    // Over its cap (0) and collected off the job's path: the held layer stays, the free one goes.
    try testing.expect(try s.open(arena, io, k2) == null);
    try testing.expect(std.fs.path.dirname(held.fs) != null);
    var check: std.heap.ArenaAllocator = .init(testing.allocator);
    defer check.deinit();
    try testing.expectEqual(@as(usize, 1), (try Store.layerNames(check.allocator(), io, s)).len);
    held.lock.close(io);
}

test "collector: a runner that stops waits for the thread within its limit and no longer" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const s = try testStore(a.allocator(), io, tmp);
    test_hold.store(true, .release);
    defer test_hold.store(false, .release);
    try testing.expect(submit(io, s, true, 0));
    const t = phases.now();
    // Stuck: given up on after the limit, the work left for the next start (the dead names and the
    // layers are swept by its first collect).
    try testing.expect(!drain(io, 30));
    try testing.expect(phases.now() - t >= 30 * std.time.ns_per_ms);
    test_hold.store(false, .release);
    try testing.expect(drain(io, 10_000));
    try testing.expect(!pending(io));
}
