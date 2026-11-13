//! Secret masking's throughput (src/redact.zig, `Set.write`) over a log, line by line, as a step's
//! output goes through it: `<secrets>` random 40-byte secrets, each in the forms the runner masks
//! (`redact.expand`: base64 at every offset, URL-encoded...), then every line of the file.
//!
//!     zig build-exe -OReleaseSafe -target x86_64-linux-musl --dep redact -Mroot=tools/redactbench.zig -Mredact=src/redact.zig
//!     redactbench <log file> <secrets>
const std = @import("std");
const redact = @import("redact");
pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    const log = try std.Io.Dir.cwd().readFileAlloc(io, args[1], gpa, .limited(1 << 30));
    const n = try std.fmt.parseInt(usize, args[2], 10);
    var prng: std.Random.DefaultPrng = .init(42);
    var set: redact.Set = .{};
    var plain: std.ArrayList([]const u8) = .empty;
    for (0..n) |_| {
        const secret = try gpa.alloc(u8, 40);
        for (secret) |*c| c.* = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[prng.random().uintLessThan(usize, 62)];
        try plain.append(gpa, secret);
    }
    const all = try redact.expand(gpa, plain.items);
    for (all) |sec| try set.add(gpa, sec);
    var sink: std.Io.Writer.Discarding = .init(&.{});
    var rates: [9]f64 = undefined;
    for (0..10) |r| {
        const start = std.Io.Clock.awake.now(io);
        var lines = std.mem.splitScalar(u8, log, '\n');
        while (lines.next()) |line| try set.write(&sink.writer, line);
        const ns: f64 = @floatFromInt(start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds);
        if (r > 0) rates[r - 1] = @as(f64, @floatFromInt(log.len)) / ns * 1000.0;
    }
    std.mem.sort(f64, &rates, {}, std.sort.asc(f64));
    std.debug.print("redact {d} secrets ({d} masks): {d:.0} MB/s, {d} bytes written\n", .{ n, all.len, rates[4], sink.fullCount() });
    return 0;
}
