//! Deletes what `Store.collect` evicted, off the job's path. A layer is evicted by one rename to
//! `layers/.dead-<n>`, after which no lookup can find it (the path of its key names nothing), and
//! only then is its tree deleted, which is what a job's end spent its time on: a tree of many
//! files takes a disk as long as it took to write. The runner then reports and polls for the next
//! job while this thread deletes.
//!
//! One thread at a time, started when there is something to delete and gone when there is not,
//! and a queue of `max_queued` trees: a full queue is the caller's to delete, so a store that
//! evicts faster than a disk deletes slows the job's end as it did, and never grows without bound.
//!
//! Nothing here is the only record of a tree: whatever the process loses (a crash, its end with
//! the queue full) is still under its dead name, and the next `Store.collect` finds it there and
//! queues it again, which is the sweep at start-up. The layers' directory is synced before the
//! first tree of a run is deleted, so a crash cannot bring back a layer whose files are half gone
//! (the rename not yet on the disk). The disk's floor (`evict.shortOf`) does not count trees
//! still being deleted as freed: it asks `pending`.

const std = @import("std");
const linux = std.os.linux;

const Store = @import("Store.zig");

/// The most trees waiting. The trees a pass evicts are few (it stops at the cap or the floor).
const max_queued = 16;
/// The most trees remembered as ones that would not go (`stuck`).
const max_stuck = 8;

var mu: std.Io.Mutex = .init;
var queue: [max_queued][]u8 = undefined;
var queued: usize = 0;
/// The tree being deleted now, so that a second `collect` finding its dead name does not queue it
/// again.
var working: ?[]u8 = null;
/// Whether a thread is running, which is decided under `mu`: set by whoever starts one, cleared by
/// the thread when it finds the queue empty.
var running = false;
/// Trees the thread could not delete (a log of why is in `Store.removeTree`'s warning): not queued
/// again by this process, or the disk's floor would wait for them for ever. The next process
/// tries them again.
var stuck: [max_stuck][]u8 = undefined;
var stuck_count: usize = 0;

const gpa = std.heap.page_allocator;

/// Tests: while set, the thread deletes nothing, so a test can fill the queue.
pub var test_hold: std.atomic.Value(bool) = .init(false);

/// Queues the tree at `path` for deletion; false when it is not queued (the queue is full, or no
/// thread could be started), and then it is the caller's to delete. A tree already queued, being
/// deleted or given up on counts as queued.
pub fn enqueue(io: std.Io, path: []const u8) bool {
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    if (known(path)) return true;
    if (queued == max_queued) return false;
    const copy = gpa.dupe(u8, path) catch return false;
    queue[queued] = copy;
    queued += 1;
    if (!running) {
        running = true;
        // The default stack: a delete of a deep tree and its permissions' repair (`Store.removeTree`)
        // keep path buffers on it, and 256 KiB overflowed in a debug build.
        const thread = std.Thread.spawn(.{}, run, .{io}) catch {
            running = false;
            queued -= 1;
            gpa.free(copy);
            return false;
        };
        thread.detach();
    }
    return true;
}

fn known(path: []const u8) bool {
    for (queue[0..queued]) |q| if (std.mem.eql(u8, q, path)) return true;
    if (working) |w| if (std.mem.eql(u8, w, path)) return true;
    for (stuck[0..stuck_count]) |s| if (std.mem.eql(u8, s, path)) return true;
    return false;
}

/// Whether trees are waiting or being deleted: the disk has not yet got their room back.
pub fn pending(io: std.Io) bool {
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    return running or queued > 0;
}

/// Waits for the queue to be empty and the thread gone. For tests, and for a runner that stops
/// and would leave the trees for the next one.
pub fn drain(io: std.Io) void {
    while (pending(io)) io.sleep(.fromMilliseconds(5), .awake) catch return;
}

fn run(io: std.Io) void {
    var synced_dir: ?[]u8 = null;
    defer if (synced_dir) |d| gpa.free(d);
    while (true) {
        const path = next(io) orelse return;
        defer finish(io, path);
        while (test_hold.load(.acquire)) io.sleep(.fromMilliseconds(1), .awake) catch return;
        // A rename is durable only once its directory is: sync it before the first tree under it
        // goes, not once a tree.
        const dir = std.fs.path.dirname(path) orelse ".";
        if (synced_dir == null or !std.mem.eql(u8, synced_dir.?, dir)) {
            syncDir(dir);
            if (synced_dir) |d| gpa.free(d);
            synced_dir = gpa.dupe(u8, dir) catch null;
        }
        var pass: std.heap.ArenaAllocator = .init(gpa);
        defer pass.deinit();
        Store.removeTree(pass.allocator(), io, path);
    }
}

/// The next tree, now `working`; null, with `running` cleared, when there is none.
fn next(io: std.Io) ?[]u8 {
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    if (queued == 0) {
        running = false;
        return null;
    }
    const path = queue[0];
    std.mem.copyForwards([]u8, queue[0 .. queued - 1], queue[1..queued]);
    queued -= 1;
    working = path;
    return path;
}

/// `path` done: freed, or given up on if it is still there.
fn finish(io: std.Io, path: []u8) void {
    var st: linux.Statx = undefined;
    const z = gpa.dupeSentinel(u8, path, 0) catch null;
    const still = if (z) |p| linux.errno(linux.statx(linux.AT.FDCWD, p, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st)) == .SUCCESS else false;
    if (z) |p| gpa.free(p);
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    working = null;
    if (still and stuck_count < max_stuck) {
        stuck[stuck_count] = path;
        stuck_count += 1;
    } else gpa.free(path);
}

fn syncDir(dir: []const u8) void {
    const z = gpa.dupeSentinel(u8, dir, 0) catch return;
    defer gpa.free(z);
    const rc = linux.open(z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: linux.fd_t = std.math.cast(linux.fd_t, rc) orelse return;
    defer _ = linux.close(fd);
    _ = linux.fsync(fd);
}

/// Tests: forget what was given up on.
pub fn forgetStuck(io: std.Io) void {
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    for (stuck[0..stuck_count]) |s| gpa.free(s);
    stuck_count = 0;
}
