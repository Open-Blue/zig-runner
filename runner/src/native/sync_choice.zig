//! Which way a layer's data is made durable, chosen for the job that is waiting for it: its own
//! files' write-back and fsyncs from threads (`Store.writeBack`, `Store.syncEntries`), or one
//! `syncfs` of the filesystem. Each is cheapest in another state of the disk. `syncfs` waits for
//! every dirty page of the filesystem, so on a quiet disk it is one cheap call (155-169 ms for a
//! cold layer on a Pi's SD card), and beside another job's writes it was 5-8 s. Per file waits for
//! this layer's data alone, the fsyncs sharing a commit, but costs a call for each file.
//!
//! The choice is the most files a layer may have for the per-file way (`limit`): past it, `syncfs`.
//! It rests on what the disk is doing now, as the kernel says: PSI's `some avg10` of
//! /proc/pressure/io and the dirty and written-back bytes of /proc/meminfo. Neither is namespaced,
//! so in a container they are the host's, the disk the store is on in the usual case. A wrong
//! reading changes the speed and nothing else: each way is sufficient by itself.
//!
//! The thresholds are starting points from the Pi's measurements (a quiet disk under 5 percent,
//! 5-8 s `syncfs` beside a writer at 20 percent and over), to be fitted there. Without either
//! file, the limit is what it was before this choice: `Store.sync_tree_max`.

const std = @import("std");
const admission = @import("../admission.zig");

/// What the disk is doing now; a field the kernel did not give is null.
pub const Load = struct {
    /// PSI `some avg10` of the disk, in hundredths of a percent.
    io_some: ?u32 = null,
    /// Dirty plus written-back data of the whole machine, in KiB. This layer's own data is in it.
    dirty_kib: ?u64 = null,
};

/// The disk is quiet below this share of its last 10 s with a task waiting on it (5 percent).
const quiet_pressure = 500;
/// ... and this much dirty data (4 MiB): little for a `syncfs` to wait for besides the layer's own.
const quiet_dirty_kib = 4 * 1024;
/// Busy from this pressure (20 percent), where `syncfs` took 5-8 s.
const busy_pressure = 2000;
/// Busy by dirty data alone, where PSI is missing: more than any one layer is likely to leave.
const busy_dirty_kib = 256 * 1024;

/// The most entries a layer may have for its own files to be synced one by one.
pub const quiet_limit = 64;
pub const mid_limit = 512;
/// 4096 files from 16 threads at 1.2-2.3 ms each is 0.3-0.6 s, against a `syncfs` of seconds.
pub const busy_limit = 4096;

pub fn limitFor(load: Load) u64 {
    if (load.io_some == null and load.dirty_kib == null) return mid_limit;
    if (load.io_some) |p| if (p >= busy_pressure) return busy_limit;
    if (load.io_some == null) if (load.dirty_kib) |d| if (d >= busy_dirty_kib) return busy_limit;
    const calm = (load.io_some orelse 0) < quiet_pressure and (load.dirty_kib orelse 0) < quiet_dirty_kib;
    return if (calm) quiet_limit else mid_limit;
}

/// The load now.
pub fn read(io: std.Io) Load {
    var load: Load = .{};
    var buf: [2048]u8 = undefined;
    const cwd = std.Io.Dir.cwd();
    if (cwd.readFile(io, "/proc/pressure/io", &buf)) |text| {
        load.io_some = admission.parsePressure(text);
    } else |_| {}
    if (cwd.readFile(io, "/proc/meminfo", &buf)) |text| {
        load.dirty_kib = dirtyKib(text);
    } else |_| {}
    return load;
}

/// `Dirty:` plus `Writeback:`, in KiB; null when either line is missing.
pub fn dirtyKib(meminfo: []const u8) ?u64 {
    var sum: u64 = 0;
    var found: u8 = 0;
    var lines = std.mem.splitScalar(u8, meminfo, '\n');
    while (lines.next()) |line| {
        inline for (.{ "Dirty:", "Writeback:" }) |name| if (std.mem.startsWith(u8, line, name)) {
            var f = std.mem.tokenizeScalar(u8, line[name.len..], ' ');
            sum +|= std.fmt.parseInt(u64, f.next() orelse return null, 10) catch return null;
            found += 1;
        };
    }
    return if (found == 2) sum else null;
}

/// The limit for a sync beginning now.
pub fn limit(io: std.Io) u64 {
    return limitFor(read(io));
}

test "sync choice: a quiet disk takes syncfs from a few dozen files, a busy one from a few thousand" {
    const t = std.testing;
    try t.expectEqual(@as(u64, mid_limit), limitFor(.{}));
    try t.expectEqual(@as(u64, quiet_limit), limitFor(.{ .io_some = 120, .dirty_kib = 900 }));
    try t.expectEqual(@as(u64, quiet_limit), limitFor(.{ .io_some = 0 }));
    try t.expectEqual(@as(u64, quiet_limit), limitFor(.{ .dirty_kib = 100 }));
    try t.expectEqual(@as(u64, mid_limit), limitFor(.{ .io_some = 800, .dirty_kib = 900 }));
    try t.expectEqual(@as(u64, mid_limit), limitFor(.{ .io_some = 120, .dirty_kib = 40_000 }));
    try t.expectEqual(@as(u64, busy_limit), limitFor(.{ .io_some = 2000, .dirty_kib = 900 }));
    // Dirty data alone is a layer's own, too: busy only where PSI cannot say.
    try t.expectEqual(@as(u64, mid_limit), limitFor(.{ .io_some = 300, .dirty_kib = 900_000 }));
    try t.expectEqual(@as(u64, busy_limit), limitFor(.{ .dirty_kib = 900_000 }));
}

test "sync choice: meminfo's dirty and written-back lines, and a kernel that has neither" {
    const t = std.testing;
    try t.expectEqual(@as(?u64, 1536), dirtyKib("MemTotal: 1 kB\nDirty:              1024 kB\nWriteback:            512 kB\n"));
    try t.expectEqual(@as(?u64, null), dirtyKib("MemTotal: 1 kB\nDirty: 4 kB\n"));
    try t.expectEqual(@as(?u64, null), dirtyKib(""));
}
