//! Letting a native job reach the instance it was handed by (#520, G4). A native job has a network
//! of its own that reaches nothing of the host's (`native/nft.zig`), so a checkout of
//! `github.server_url` fails when the instance is the host's own, or on the LAN or tailnet the host
//! is on, for every address but the ones the runner opens. It opens, port-scoped, the addresses of
//! the instance the runner serves (`RUNNER_GITEA_URL`) and of the one its tasks name, which may be
//! another name for the same host (`github.server_url`, the instance's `ROOT_URL`), and nothing
//! else of the host's.
//!
//! An instance on the host's loopback cannot be reached as the task names it, since a job's
//! 127.0.0.1 is its own, and the kernel cannot redirect to it (a reply from 127.0.0.1 may not leave
//! by the bridge). The runner listens on the bridge's address at the same port and forwards to the
//! loopback (`forward`); the job fetches from there, and `github.server_url` as the checkout reads
//! it is made so. What the workflow sees of it (the `github` context, in expressions) is not
//! changed, nor is `GITHUB_SERVER_URL`.
const std = @import("std");
const net = @import("../native/net.zig");
const job_mod = @import("../job.zig");

const Allocator = std.mem.Allocator;

/// The host and port of an `http://` or `https://` URL (443 and 80 by default), or null.
pub const Target = struct { host: []const u8, port: u16, https: bool };

pub fn target(url: []const u8) ?Target {
    const https = std.mem.startsWith(u8, url, "https://");
    const rest = if (https) url["https://".len..] else if (std.mem.startsWith(u8, url, "http://")) url["http://".len..] else return null;
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    var authority = rest[0..end];
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| authority = authority[at + 1 ..];
    if (authority.len == 0 or authority[0] == '[') return null;
    var host = authority;
    var port: u16 = if (https) 443 else 80;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return null;
    }
    if (host.len == 0) return null;
    return .{ .host = host, .port = port, .https = https };
}

/// The IPv4 addresses `host` names: itself when it is one, `localhost` as the loopback, else its
/// DNS answers (at most `out.len`).
fn addresses(io: std.Io, host: []const u8, out: *[net.max_reach][4]u8) [][4]u8 {
    if (net.parseIp4(host)) |a| {
        out[0] = a;
        return out[0..1];
    }
    if (std.ascii.eqlIgnoreCase(host, "localhost")) {
        out[0] = .{ 127, 0, 0, 1 };
        return out[0..1];
    }
    const name = std.Io.net.HostName.init(host) catch return out[0..0];
    var buf: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&buf);
    name.lookup(io, &queue, .{ .port = 0, .family = .ip4 }) catch return out[0..0];
    var n: usize = 0;
    while (queue.getOneUncancelable(io)) |item| {
        switch (item) {
            .address => |a| if (a == .ip4 and n < out.len) {
                out[n] = a.ip4.bytes;
                n += 1;
            },
            .canonical_name => {},
        }
    } else |_| {}
    return out[0..n];
}

/// Opens `url`'s address and port to the jobs of this runner (on the loopback, at the bridge's
/// address of `subnet`, forwarded), and says why when it could not (null when it did, or `url` is
/// no URL).
pub fn allow(arena: Allocator, io: std.Io, subnet: net.Subnet, url: []const u8) ?[]const u8 {
    const t = target(url) orelse return null;
    var found: [net.max_reach][4]u8 = undefined;
    const addrs = addresses(io, t.host, &found);
    if (addrs.len == 0) return std.fmt.allocPrint(arena, "jobs cannot reach {s}: the name does not resolve here", .{t.host}) catch null;
    for (addrs) |a| {
        if (!net.allow(.{ .addr = a, .port = t.port }))
            return std.fmt.allocPrint(arena, "jobs cannot reach {s}: too many instances", .{t.host}) catch null;
        if (a[0] == 127) startForward(io, subnet.gateway(), t.port);
    }
    return null;
}

var forwarded: [net.max_reach]u16 = undefined;
var forwarded_len: usize = 0;
var forwarded_mu: std.atomic.Mutex = .unlocked;

/// Starts the forwarder of `port` once, on a thread of its own that ends with the process.
fn startForward(io: std.Io, gateway: [4]u8, port: u16) void {
    while (!forwarded_mu.tryLock()) std.atomic.spinLoopHint();
    defer forwarded_mu.unlock();
    for (forwarded[0..forwarded_len]) |p| if (p == port) return;
    if (forwarded_len == forwarded.len) return;
    const th = std.Thread.spawn(.{}, forward, .{ io, gateway, port }) catch |e| {
        std.log.warn("gitea: no forwarder for port {d}: {s}", .{ port, @errorName(e) });
        return;
    };
    th.detach();
    forwarded[forwarded_len] = port;
    forwarded_len += 1;
}

/// Listens on `gateway:port` (the bridge's address, which exists once a job has made it: tried
/// again each second until it is there) and forwards each connection to 127.0.0.1:`port`, until
/// the process ends. Only the bridge's own address is bound, so nothing else sees the port.
pub fn forward(io: std.Io, gateway: [4]u8, port: u16) void {
    const addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = gateway, .port = port } };
    var conns: std.Io.Group = .init;
    defer conns.cancel(io);
    while (true) {
        var server = addr.listen(io, .{ .reuse_address = true }) catch {
            io.sleep(.fromSeconds(1), .awake) catch return;
            continue;
        };
        defer server.deinit(io);
        while (true) {
            const client = server.accept(io) catch |e| switch (e) {
                error.Canceled => return,
                else => break,
            };
            conns.concurrent(io, connection, .{ io, client, port }) catch client.close(io);
        }
    }
}

/// One forwarded connection: both directions until each side has closed.
fn connection(io: std.Io, client: std.Io.net.Stream, port: u16) void {
    defer client.close(io);
    const to: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const instance = to.connect(io, .{ .mode = .stream }) catch return;
    defer instance.close(io);
    var back: std.Io.Group = .init;
    back.concurrent(io, pump, .{ io, instance, client }) catch return;
    pump(io, client, instance);
    back.await(io) catch |e| std.log.debug("gitea: forward: {s}", .{@errorName(e)});
}

/// Copies `from` to `to` to the end, then tells `to` there is no more.
fn pump(io: std.Io, from: std.Io.net.Stream, to: std.Io.net.Stream) void {
    var rb: [8192]u8 = undefined;
    var wb: [8192]u8 = undefined;
    var r = from.reader(io, &rb);
    var w = to.writer(io, &wb);
    // What has arrived goes on at once: a request is not held until its sender closes.
    while (true) {
        const chunk = r.interface.peekGreedy(1) catch break;
        w.interface.writeAll(chunk) catch break;
        w.interface.flush() catch break;
        r.interface.toss(chunk.len);
    }
    to.shutdown(io, .send) catch |e| std.log.debug("gitea: forward: {s}", .{@errorName(e)});
}

/// The job, as a native job is to see the instance: when its `github.server_url` is on the loopback
/// the checkout fetches through the bridge's address (`subnet`'s gateway) at the same port.
pub fn viewed(arena: Allocator, io: std.Io, subnet: net.Subnet, job: job_mod.Job) Allocator.Error!job_mod.Job {
    const t = target(job.github.server_url) orelse return job;
    var found: [net.max_reach][4]u8 = undefined;
    const addrs = addresses(io, t.host, &found);
    if (addrs.len == 0 or addrs[0][0] != 127) return job;
    var out = job;
    const g = subnet.gateway();
    out.github.server_url = try std.fmt.allocPrint(arena, "{s}://{d}.{d}.{d}.{d}:{d}", .{
        if (t.https) "https" else "http", g[0], g[1], g[2], g[3], t.port,
    });
    return out;
}

test "a URL's host and port, with the scheme's default" {
    const a = target("http://127.0.0.1:3300/").?;
    try std.testing.expectEqualStrings("127.0.0.1", a.host);
    try std.testing.expectEqual(@as(u16, 3300), a.port);
    const b = target("https://git.example.com").?;
    try std.testing.expectEqualStrings("git.example.com", b.host);
    try std.testing.expectEqual(@as(u16, 443), b.port);
    try std.testing.expectEqual(@as(u16, 80), target("http://gitea.tail1234.ts.net/x?y").?.port);
    try std.testing.expectEqualStrings("h", target("http://user:pw@h:1/").?.host);
    try std.testing.expect(target("ssh://h") == null);
    try std.testing.expect(target("http://:80") == null);
    try std.testing.expect(target("http://h:99999") == null);
}

test "an instance on the loopback is fetched from through the bridge's address, others as they are" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var job: job_mod.Job = undefined;
    job.github = .{};
    job.github.server_url = "http://127.0.0.1:3300/";
    const seen = try viewed(arena, std.testing.io, .default, job);
    try std.testing.expectEqualStrings("http://10.211.0.1:3300", seen.github.server_url);
    job.github.server_url = "http://localhost:3400";
    try std.testing.expectEqualStrings("http://10.211.0.1:3400", (try viewed(arena, std.testing.io, .default, job)).github.server_url);
    job.github.server_url = "https://10.0.0.43:3500/";
    try std.testing.expectEqualStrings("https://10.0.0.43:3500/", (try viewed(arena, std.testing.io, .default, job)).github.server_url);
}

test "a connection to the bridge's address is forwarded to the instance on the loopback" {
    const io = std.testing.io;
    // The instance: echoes one line.
    const loop_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var instance = try loop_addr.listen(io, .{ .reuse_address = true });
    defer instance.deinit(io);
    const port = instance.socket.address.getPort();
    const Echo = struct {
        fn run(s: *std.Io.net.Server, i: std.Io) void {
            const c = s.accept(i) catch return;
            defer c.close(i);
            var rb: [64]u8 = undefined;
            var wb: [64]u8 = undefined;
            var r = c.reader(i, &rb);
            var w = c.writer(i, &wb);
            const line = r.interface.takeDelimiterInclusive('\n') catch return;
            w.interface.writeAll(line) catch return;
            w.interface.flush() catch return;
        }
    };
    const echo = try std.Thread.spawn(.{}, Echo.run, .{ &instance, io });
    defer echo.join();
    // The "bridge's address" of the test is another loopback address, at the same port.
    const gateway: [4]u8 = .{ 127, 0, 0, 2 };
    const fwd = try std.Thread.spawn(.{}, forward, .{ io, gateway, port });
    fwd.detach();
    var tries: u32 = 0;
    const to: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = gateway, .port = port } };
    const client = while (tries < 50) : (tries += 1) {
        break to.connect(io, .{ .mode = .stream }) catch {
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
    } else return error.NoForwarder;
    defer client.close(io);
    var rb: [64]u8 = undefined;
    var wb: [64]u8 = undefined;
    var r = client.reader(io, &rb);
    var w = client.writer(io, &wb);
    try w.interface.writeAll("ping\n");
    try w.interface.flush();
    try std.testing.expectEqualStrings("ping\n", try r.interface.takeDelimiterInclusive('\n'));
}
