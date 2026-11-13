//! Benchmark of std.http.Client: bench_std <url> <mode: warm|cold|conc> <n> [workers]
//! Prints one line: mode n p50_us p99_us mean_us wall_ms cpu_ms maxrss_kb
const std = @import("std");
const linux = std.os.linux;

const Ctx = struct { client: *std.http.Client, url: []const u8, keep: bool, lat: []u64, fails: *std.atomic.Value(u32) };

fn now() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn worker(c: Ctx) void {
    var buf: [8192]u8 = undefined;
    for (c.lat) |*l| {
        var w: std.Io.Writer = .fixed(&buf);
        const t0 = now();
        const r = c.client.fetch(.{ .location = .{ .url = c.url }, .response_writer = &w, .keep_alive = c.keep }) catch {
            _ = c.fails.fetchAdd(1, .monotonic);
            l.* = 0;
            continue;
        };
        if (r.status != .ok) _ = c.fails.fetchAdd(1, .monotonic);
        l.* = now() - t0;
    }
}

var inner: *const std.Io.VTable = undefined;
var wrapped: std.Io.VTable = undefined;

fn connectNoDelay(ud: ?*anyopaque, a: *const std.Io.net.IpAddress, o: std.Io.net.IpAddress.ConnectOptions) std.Io.net.IpAddress.ConnectError!std.Io.net.Socket {
    const s = try inner.netConnectIp(ud, a, o);
    const one: c_int = 1;
    _ = linux.setsockopt(s.handle, 6, 1, std.mem.asBytes(&one), @sizeOf(c_int));
    return s;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var io = init.io;
    if (init.environ_map.get("NODELAY") != null) {
        inner = io.vtable;
        wrapped = io.vtable.*;
        wrapped.netConnectIp = connectNoDelay;
        io = .{ .userdata = io.userdata, .vtable = &wrapped };
    }
    var args = try init.minimal.args.iterateAllocator(gpa);
    _ = args.next();
    const url = args.next().?;
    const mode = args.next().?;
    const n = try std.fmt.parseInt(usize, args.next().?, 10);
    const workers: usize = if (args.next()) |w| try std.fmt.parseInt(usize, w, 10) else 1;

    var client: std.http.Client = .{ .allocator = gpa, .io = io, .write_buffer_size = 16 * 1024 };
    defer client.deinit();
    client.now = std.Io.Clock.real.now(io);
    try client.ca_bundle.addCertsFromFilePathAbsolute(gpa, io, client.now.?, (init.environ_map.get("CA_FILE") orelse "/home/lement/projects/zig-runner-http-client/bench/http-client/certs/cert.pem"));

    const lat = try gpa.alloc(u64, n);
    var fails: std.atomic.Value(u32) = .init(0);
    const keep = !std.mem.eql(u8, mode, "cold");
    const w = if (std.mem.eql(u8, mode, "conc")) workers else 1;
    // Warm the connection(s) up outside the timing for warm/conc.
    const t0 = now();
    if (w == 1) {
        worker(.{ .client = &client, .url = url, .keep = keep, .lat = lat, .fails = &fails });
    } else {
        var g: std.Io.Group = .init;
        const per = n / w;
        for (0..w) |i| {
            const slice = lat[i * per ..][0..per];
            try g.concurrent(io, worker, .{Ctx{ .client = &client, .url = url, .keep = true, .lat = slice, .fails = &fails }});
        }
        try g.await(io);
    }
    const wall = now() - t0;
    const done = if (w == 1) n else n / w * w;
    const l = lat[0..done];
    std.mem.sort(u64, l, {}, std.sort.asc(u64));
    var sum: u64 = 0;
    for (l) |x| sum += x;
    var ru: linux.rusage = undefined;
    _ = linux.getrusage(0, &ru);
    const cpu_us = @as(u64, @intCast(ru.utime.sec + ru.stime.sec)) * 1_000_000 + @as(u64, @intCast(ru.utime.usec + ru.stime.usec));
    std.debug.print("std {s} n={d} p50={d} p99={d} mean={d} wall_ms={d} cpu_ms={d} rss_kb={d} fails={d}\n", .{
        mode, done, l[done / 2] / 1000, l[done * 99 / 100] / 1000, sum / done / 1000, wall / 1_000_000, cpu_us / 1000, ru.maxrss, fails.load(.monotonic),
    });
}
