//! Throughput of the runner's own SHA-256, decompressors, layer unpacking and secret masking on
//! real files, for comparing them with C and Rust candidates (docs/BENCHMARKS.md). Built like the
//! runner, C sources included (`.github/scripts/impl-bench.sh`). Prints MB/s and the median.
//!
//!     implbench sha-dispatch|sha-baseline|zstd|libzstd|gzip <file> [rounds]
//!     implbench apply <layer blob> <empty dir> [0|1: pipelined]
//!     implbench redact <log file> <secrets> [rounds]
const std = @import("std");
const Sha256 = @import("sha256.zig").Sha256;
const zstd = @import("native/oci/zstd.zig");
const redact = @import("redact.zig");
const libzstd = @import("native/oci/libzstd.zig");
const layer = @import("native/oci/layer.zig");
const linux = std.os.linux;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 3) return 2;
    if (std.mem.eql(u8, args[1], "apply")) {
        // implbench apply <layer blob> <dir> [pipeline 0|1]: one layer unpacked into an empty dir
        const blob = try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(1 << 30));
        const path = try gpa.dupeSentinel(u8, args[3], 0);
        const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        const fd: linux.fd_t = std.math.cast(linux.fd_t, fd_rc) orelse return 1;
        var in: std.Io.Reader = .fixed(blob);
        var totals: layer.Totals = .{};
        const pipeline = args.len > 4 and args[4][0] == '1';
        const start = std.Io.Clock.awake.now(io);
        try layer.apply(gpa, io, fd, &in, "", .{ .owners = false, .pipeline = pipeline }, &totals);
        const ns: f64 = @floatFromInt(start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds);
        std.debug.print("apply {s}: {d:.3} s, {d} entries, {d} bytes\n", .{ args[2], ns / 1e9, totals.entries, totals.bytes });
        return 0;
    }
    if (std.mem.eql(u8, args[1], "redact")) {
        // implbench redact <log file> <number of secrets> [rounds]: every line through `Set.write`
        const log = try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(1 << 30));
        const n = try std.fmt.parseInt(usize, args[3], 10);
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
        const rounds: u32 = if (args.len > 4) try std.fmt.parseInt(u32, args[4], 10) else 5;
        var rates: [64]f64 = undefined;
        for (0..rounds + 1) |r| {
            const start = std.Io.Clock.awake.now(io);
            var lines = std.mem.splitScalar(u8, log, '\n');
            while (lines.next()) |line| try set.write(&sink.writer, line);
            const ns: f64 = @floatFromInt(start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds);
            if (r > 0) rates[r - 1] = @as(f64, @floatFromInt(log.len)) / ns * 1000.0;
        }
        std.mem.sort(f64, rates[0..rounds], {}, std.sort.asc(f64));
        std.debug.print("redact {d} secrets ({d} masks) over {d} bytes: median {d:.0} MB/s\n", .{ n, all.len, log.len, rates[rounds / 2] });
        return 0;
    }
    const data = try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(1 << 30));
    const rounds = if (args.len > 3) try std.fmt.parseInt(u32, args[3], 10) else 7;
    var rates: [64]f64 = undefined;
    var out_len: usize = 0;
    var digest: [32]u8 = undefined;
    for (0..rounds + 1) |r| {
        const start = std.Io.Clock.awake.now(io);
        const cpu0 = std.Io.Clock.cpu_process.now(io);
        var bytes: usize = 0;
        if (std.mem.eql(u8, args[1], "sha-dispatch")) {
            var h = Sha256.init(.{});
            h.update(data);
            h.final(&digest);
            bytes = data.len;
        } else if (std.mem.eql(u8, args[1], "sha-baseline")) {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(data);
            h.final(&digest);
            bytes = data.len;
        } else if (std.mem.eql(u8, args[1], "zstd")) {
            var in: std.Io.Reader = .fixed(data);
            const d = try zstd.Decompress.create(gpa, &in);
            defer d.destroy();
            bytes = try d.reader.discardRemaining();
        } else if (std.mem.eql(u8, args[1], "libzstd")) {
            var in: std.Io.Reader = .fixed(data);
            const d = try libzstd.Decompress.create(gpa, &in);
            defer d.destroy();
            bytes = try d.reader.discardRemaining();
        } else if (std.mem.eql(u8, args[1], "gzip")) {
            var in: std.Io.Reader = .fixed(data);
            const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
            defer gpa.free(window);
            var d: std.compress.flate.Decompress = .init(&in, .gzip, window);
            bytes = try d.reader.discardRemaining();
        } else return 2;
        const ns: f64 = @floatFromInt(start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds);
        _ = cpu0;
        if (r == 0) {
            out_len = bytes;
            continue;
        }
        rates[r - 1] = @as(f64, @floatFromInt(bytes)) / ns * 1000.0;
    }
    std.mem.sort(f64, rates[0..rounds], {}, std.sort.asc(f64));
    std.debug.print("{s} {s}: median {d:.0} MB/s (min {d:.0}, max {d:.0}) output {d} bytes digest {x}\n", .{
        args[1], args[2], rates[rounds / 2], rates[0], rates[rounds - 1], out_len, digest[0..4],
    });
    return 0;
}
