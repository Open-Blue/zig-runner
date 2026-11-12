//! The runner process's own resources, for the logs: what a leak or a slow growth shows as before
//! the process ends (a leak was seen only at exit, with no allocation site: #518). Read from
//! /proc/self with fixed buffers, so it allocates nothing and works with the heap in any state, and
//! counted by a wrapper around the process's allocator (`Heap`). Printed in the `health:` line and
//! once per job in a `job-end:` line (`loop/job.zig`).
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const Stats = struct {
    /// VmRSS and RssAnon of /proc/self/status.
    rss_kb: ?u64 = null,
    anon_kb: ?u64 = null,
    threads: ?u32 = null,
    /// Open descriptors (/proc/self/fd).
    fds: ?u32 = null,
    /// Mounts in the runner's mount namespace (/proc/self/mountinfo lines): a job's that are left
    /// add to it.
    mounts: ?u32 = null,
    /// Children of the runner that exited and were not waited for.
    zombies: ?u32 = null,
    /// What `heap` counts as allocated and not freed.
    heap_bytes: u64 = 0,
    heap_blocks: u64 = 0,

    /// ` rss=63M anon=60M thr=24 fds=71 mounts=29 zombies=0 heap=41M/41200`, each `?` when it
    /// could not be read.
    pub fn format(s: Stats, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("rss={f} anon={f} thr={f} fds={f} mounts={f} zombies={f} heap={f}/{d}", .{
            Kb{ .v = s.rss_kb },    Kb{ .v = s.anon_kb },    Count{ .v = s.threads },        Count{ .v = s.fds },
            Count{ .v = s.mounts }, Count{ .v = s.zombies }, Kb{ .v = s.heap_bytes / 1024 }, s.heap_blocks,
        });
    }
};

/// What changed between two readings, signed, for the `job-end:` line: `dheap=+12K dfds=+0 …`.
pub const Delta = struct {
    before: Stats,
    after: Stats,

    pub fn format(d: Delta, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("dheap={f} dblocks={f} dfds={f} dthr={f} dmounts={f}", .{
            Signed{ .v = diff(d.before.heap_bytes / 1024, d.after.heap_bytes / 1024), .unit = "K" },
            Signed{ .v = diff(d.before.heap_blocks, d.after.heap_blocks), .unit = "" },
            Signed{ .v = diffOpt(d.before.fds, d.after.fds), .unit = "" },
            Signed{ .v = diffOpt(d.before.threads, d.after.threads), .unit = "" },
            Signed{ .v = diffOpt(d.before.mounts, d.after.mounts), .unit = "" },
        });
    }
};

fn diff(a: u64, b: u64) ?i64 {
    const x = std.math.cast(i64, a) orelse return null;
    const y = std.math.cast(i64, b) orelse return null;
    return y - x;
}

fn diffOpt(a: ?u32, b: ?u32) ?i64 {
    return @as(i64, b orelse return null) - @as(i64, a orelse return null);
}

const Kb = struct {
    v: ?u64,
    pub fn format(k: Kb, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const v = k.v orelse return w.writeAll("?");
        if (v >= 10 * 1024) return w.print("{d}M", .{v / 1024});
        try w.print("{d}K", .{v});
    }
};

const Count = struct {
    v: ?u32,
    pub fn format(c: Count, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{d}", .{c.v orelse return w.writeAll("?")});
    }
};

const Signed = struct {
    v: ?i64,
    unit: []const u8,
    pub fn format(s: Signed, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const v = s.v orelse return w.writeAll("?");
        try w.print("{s}{d}{s}", .{ if (v >= 0) "+" else "", v, s.unit });
    }
};

/// The process's own resources now: a handful of small reads of /proc/self.
pub fn read() Stats {
    var s: Stats = .{ .heap_bytes = heap.bytes.load(.monotonic), .heap_blocks = heap.blocks.load(.monotonic) };
    if (builtin.os.tag != .linux) return s;
    var buf: [4096]u8 = undefined;
    if (readFile("/proc/self/status", &buf)) |text| {
        s.rss_kb = field(text, "VmRSS:");
        s.anon_kb = field(text, "RssAnon:");
        if (field(text, "Threads:")) |t| s.threads = std.math.cast(u32, t);
    }
    s.fds = countFds();
    s.mounts = countLines("/proc/self/mountinfo");
    s.zombies = zombieChildren();
    return s;
}

fn readFile(path: [*:0]const u8, buf: []u8) ?[]const u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    defer _ = linux.close(fd);
    const n = linux.read(fd, buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return buf[0..n];
}

/// The number after `key` on its line of /proc/self/status (`VmRSS:     64232 kB`).
fn field(text: []const u8, key: []const u8) ?u64 {
    const at = std.mem.indexOf(u8, text, key) orelse return null;
    var rest = std.mem.trimStart(u8, text[at + key.len ..], " \t");
    const end = std.mem.indexOfAny(u8, rest, " \t\n") orelse rest.len;
    rest = rest[0..end];
    return std.fmt.parseUnsigned(u64, rest, 10) catch null;
}

/// The names in a directory, without `.` and `..`, read with `getdents64` into a buffer of its
/// own: a name holds until the next `next`.
const Entries = struct {
    fd: linux.fd_t,
    buf: [4096]u8 align(@alignOf(linux.dirent64)) = undefined,
    got: usize = 0,
    off: usize = 0,
    failed: bool = false,

    fn open(path: [*:0]const u8) ?Entries {
        const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        return .{ .fd = std.math.cast(linux.fd_t, rc) orelse return null };
    }

    fn close(e: *Entries) void {
        _ = linux.close(e.fd);
    }

    fn next(e: *Entries) ?[]const u8 {
        while (true) {
            if (e.off >= e.got) {
                const got = linux.getdents64(e.fd, &e.buf, e.buf.len);
                if (linux.errno(got) != .SUCCESS) {
                    e.failed = true;
                    return null;
                }
                if (got == 0) return null;
                e.got = got;
                e.off = 0;
            }
            const d: *align(1) const linux.dirent64 = @ptrCast(&e.buf[e.off]);
            e.off += d.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&d.name)), 0);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) return name;
        }
    }
};

/// Open descriptors, without the one this counts with.
fn countFds() ?u32 {
    var e = Entries.open("/proc/self/fd") orelse return null;
    defer e.close();
    var n: u32 = 0;
    while (e.next()) |_| n += 1;
    if (e.failed) return null;
    return n -| 1;
}

fn countLines(path: [*:0]const u8) ?u32 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    defer _ = linux.close(fd);
    var buf: [8192]u8 = undefined;
    var n: usize = 0;
    while (true) {
        const got = linux.read(fd, &buf, buf.len);
        if (linux.errno(got) != .SUCCESS) return null;
        if (got == 0) return std.math.cast(u32, n);
        n += std.mem.count(u8, buf[0..got], "\n");
    }
}

/// Children of any of the runner's threads that are zombies (state `Z` in /proc/<pid>/stat), from
/// each thread's /proc/self/task/<tid>/children.
fn zombieChildren() ?u32 {
    var tasks = Entries.open("/proc/self/task") orelse return null;
    defer tasks.close();
    var zombies: u32 = 0;
    while (tasks.next()) |tid| {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrintSentinel(&path_buf, "/proc/self/task/{s}/children", .{tid}, 0) catch continue;
        var kids: [1024]u8 = undefined;
        const text = readFile(path, &kids) orelse continue;
        var it = std.mem.tokenizeAny(u8, text, " \n");
        while (it.next()) |pid| {
            var stat_path: [48]u8 = undefined;
            const sp = std.fmt.bufPrintSentinel(&stat_path, "/proc/{s}/stat", .{pid}, 0) catch continue;
            var stat: [512]u8 = undefined;
            const st = readFile(sp, &stat) orelse continue;
            // `pid (comm) S ...`: the state follows the last `)`, as comm may hold one.
            const close = std.mem.lastIndexOfScalar(u8, st, ')') orelse continue;
            if (close + 2 < st.len and st[close + 2] == 'Z') zombies += 1;
        }
    }
    return if (tasks.failed) null else zombies;
}

/// Counts what the process's allocator has handed out and not taken back. `main` wraps its `gpa`
/// in it; two relaxed atomic adds per allocation.
pub const Heap = struct {
    child: std.mem.Allocator = undefined,
    bytes: std.atomic.Value(u64) = .init(0),
    blocks: std.atomic.Value(u64) = .init(0),

    pub fn allocator(h: *Heap, child: std.mem.Allocator) std.mem.Allocator {
        h.child = child;
        return .{ .ptr = h, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const h = of(ctx);
        const p = h.child.rawAlloc(len, alignment, ret) orelse return null;
        _ = h.bytes.fetchAdd(len, .monotonic);
        _ = h.blocks.fetchAdd(1, .monotonic);
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const h = of(ctx);
        if (!h.child.rawResize(memory, alignment, new_len, ret)) return false;
        h.moved(memory.len, new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const h = of(ctx);
        const p = h.child.rawRemap(memory, alignment, new_len, ret) orelse return null;
        h.moved(memory.len, new_len);
        return p;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const h = of(ctx);
        h.child.rawFree(memory, alignment, ret);
        _ = h.bytes.fetchSub(memory.len, .monotonic);
        _ = h.blocks.fetchSub(1, .monotonic);
    }

    fn of(ctx: *anyopaque) *Heap {
        return @ptrCast(@alignCast(ctx));
    }

    fn moved(h: *Heap, old: usize, new: usize) void {
        if (new >= old) _ = h.bytes.fetchAdd(new - old, .monotonic) else _ = h.bytes.fetchSub(old - new, .monotonic);
    }
};

/// The process's: `main` wraps its allocator in it; read by `read`.
pub var heap: Heap = .{};

test "the heap wrapper counts what is in use, through resizes and frees" {
    var h: Heap = .{};
    const a = h.allocator(std.testing.allocator);
    const x = try a.alloc(u8, 100);
    var y = try a.alloc(u8, 50);
    try std.testing.expectEqual(@as(u64, 150), h.bytes.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), h.blocks.load(.monotonic));
    y = try a.realloc(y, 80);
    try std.testing.expectEqual(@as(u64, 180), h.bytes.load(.monotonic));
    a.free(x);
    a.free(y);
    try std.testing.expectEqual(@as(u64, 0), h.bytes.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), h.blocks.load(.monotonic));
}

test "the process's stats read, a child left unwaited counts as a zombie, and a delta prints signed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const before = read();
    try std.testing.expect(before.rss_kb.? > 0);
    try std.testing.expect(before.threads.? >= 1);
    try std.testing.expect(before.fds.? >= 3);
    try std.testing.expect(before.mounts.? >= 1);
    const pid = linux.fork();
    if (pid == 0) linux.exit_group(0);
    // Its exit, not yet waited for.
    var tries: u32 = 0;
    while (tries < 200) : (tries += 1) {
        if (read().zombies.? >= 1) break;
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 5 * std.time.ns_per_ms }, null);
    }
    try std.testing.expect(read().zombies.? >= 1);
    var status: i32 = 0;
    _ = linux.waitpid(std.math.cast(linux.pid_t, pid).?, &status, 0);
    try std.testing.expectEqual(before.zombies.?, read().zombies.?);

    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("{f}", .{Delta{ .before = .{ .fds = 10, .heap_bytes = 4096 }, .after = .{ .fds = 8, .heap_bytes = 8192 } }});
    try std.testing.expectEqualStrings("dheap=+4K dblocks=+0 dfds=-2 dthr=? dmounts=?", w.buffered());
}
