//! The measurement harness for job priority (#549, `tools/priority-bench.sh`): runs the pool's real
//! priority code against cgroups the script made, so that what is measured is what the runner does.
//!
//!     priobench weights <job cgroup> <level> [protect MB]    cpu.weight, io.weight, memory.low
//!     priobench govern <pressure file> <freeze|nofreeze> <dir:level:mb>...
//!
//! `govern` keeps the gate's priority tick (`Admission.tick`: the freeze governor and the jobs'
//! parent `memory.low`) going every 250 ms for the jobs named, each a native job running in its
//! cgroup `dir` with its level and estimate, until it is killed. Its pressure is the file named
//! (a cgroup's `memory.pressure`, to measure one cgroup without the rest of the machine).
const std = @import("std");
const admission = @import("admission.zig");
const priority = @import("priority.zig");
const cgroup = @import("native/cgroup.zig");

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len >= 4 and std.mem.eql(u8, args[1], "weights")) {
        const level = priority.parseLevel(args[3]) orelse return 2;
        const mb: u64 = if (args.len > 4) try std.fmt.parseInt(u64, args[4], 10) else 0;
        const j: cgroup.Job = .{ .dir = args[2] };
        const done = j.limitPriority(gpa, level, mb << 20);
        std.debug.print("cpu={} io={} memory={}\n", .{ done.cpu, done.io, done.memory });
        return 0;
    }
    if (args.len >= 5 and std.mem.eql(u8, args[1], "govern")) {
        const freeze = std.mem.eql(u8, args[3], "freeze");
        const slots = try gpa.alloc(admission.Admission.Slot, args.len - 4);
        var a: admission.Admission = .init(io, .{ .priority = .{ .freeze = freeze, .freeze_pressure = 1000, .freeze_max_ms = 600_000 } }, slots);
        a.native = true;
        a.paths.pressure = args[2];
        const now_ms = std.Io.Clock.awake.now(io).toMilliseconds();
        for (args[4..], slots) |spec, *s| {
            var it = std.mem.splitScalar(u8, spec, ':');
            const dir = it.next().?;
            s.* = .{
                .started_ms = now_ms,
                .native = true,
                .level = priority.parseLevel(it.next() orelse return 2) orelse return 2,
                .est_mb = try std.fmt.parseInt(u32, it.next() orelse return 2, 10),
            };
            @memcpy(s.cgroup_buf[0..dir.len], dir);
            s.cgroup_len = dir.len;
        }
        while (true) {
            a.tick();
            io.sleep(.fromMilliseconds(250), .awake) catch return 0;
        }
    }
    return 2;
}
