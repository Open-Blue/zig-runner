//! Times what std's HTTP client does not show: the DNS lookup, the TCP connect and, from the
//! rest, the TLS handshake of a new connection. The client opens connections inside
//! `Client.request`, through its `Io`, and exposes no hook, so the `Io` it is given is wrapped:
//! `wrap` returns an `Io` that shares the original's userdata and vtable except for two calls,
//! `netLookup` and `netConnectIp`, which note when they started and ended and then do exactly what
//! the original does. Nothing else about a request changes.
//!
//! A lookup is noted by host name and a connect by the socket it made, so `request_log.Probe`
//! finds its own: the connect by the connection's socket (exact), the lookup by host name and the
//! window of the request (two requests to one host that open connections at once may each take
//! the other's lookup, which takes about as long).

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const net = Io.net;

/// Nanoseconds on the monotonic clock.
pub fn now() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const sec = std.math.cast(u64, ts.sec) orelse 0;
    const nsec = std.math.cast(u64, ts.nsec) orelse 0;
    return sec * std.time.ns_per_s + nsec;
}

/// The original's vtable, set by the first `wrap`; `vtable` is a copy of it with the two hooks.
var inner: ?*const Io.VTable = null;
var vtable: Io.VTable = undefined;
var setup_lock: std.atomic.Mutex = .unlocked;

/// `io` with its lookups and connects timed, or `io` itself when it cannot be (a second kind of
/// `Io` in the process: there is one).
pub fn wrap(io: Io) Io {
    if (hooked(io)) return io;
    while (!setup_lock.tryLock()) std.atomic.spinLoopHint();
    defer setup_lock.unlock();
    if (inner == null) {
        vtable = io.vtable.*;
        vtable.netLookup = lookup;
        vtable.netConnectIp = connect;
        inner = io.vtable;
    }
    if (inner.? != io.vtable) return io;
    return .{ .userdata = io.userdata, .vtable = &vtable };
}

/// Whether `io` comes from `wrap`.
pub fn hooked(io: Io) bool {
    return io.vtable == &vtable;
}

const slots = 64;
const host_max = 253;

const Lookup = struct {
    host: [host_max]u8 = undefined,
    host_len: u8 = 0,
    start: u64 = 0,
    end: u64 = 0,
};

const Connect = struct {
    fd: i32 = -1,
    start: u64 = 0,
    end: u64 = 0,
};

var lock: std.atomic.Mutex = .unlocked;
var lookups: [slots]Lookup = @splat(.{});
var connects: [slots]Connect = @splat(.{});
var lookups_next: usize = 0;
var connects_next: usize = 0;

fn acquire() void {
    while (!lock.tryLock()) std.atomic.spinLoopHint();
}

fn lookup(
    userdata: ?*anyopaque,
    host: net.HostName,
    queue: *Io.Queue(net.HostName.LookupResult),
    options: net.HostName.LookupOptions,
) net.HostName.LookupError!void {
    const start = now();
    defer note: {
        const end = now();
        if (host.bytes.len > host_max) break :note;
        acquire();
        defer lock.unlock();
        const slot = &lookups[lookups_next % slots];
        lookups_next +%= 1;
        @memcpy(slot.host[0..host.bytes.len], host.bytes);
        slot.host_len = std.math.cast(u8, host.bytes.len) orelse break :note;
        slot.start = start;
        slot.end = end;
    }
    return inner.?.netLookup(userdata, host, queue, options);
}

fn connect(
    userdata: ?*anyopaque,
    address: *const net.IpAddress,
    options: net.IpAddress.ConnectOptions,
) net.IpAddress.ConnectError!net.Socket {
    const start = now();
    const socket = try inner.?.netConnectIp(userdata, address, options);
    const end = now();
    noDelay(socket.handle);
    acquire();
    defer lock.unlock();
    // The same descriptor again replaces its old entry: the old connection is closed.
    var at: usize = connects_next % slots;
    for (connects, 0..) |c, i| if (c.fd == socket.handle) {
        at = i;
        break;
    };
    connects[at] = .{ .fd = socket.handle, .start = start, .end = end };
    if (at == connects_next % slots) connects_next +%= 1;
    return socket;
}

var nodelay_failed: std.atomic.Value(bool) = .init(false);

/// TCP_NODELAY on a new connection. Std never sets it, and a TLS connection whose peer then goes
/// quiet after our Finished waits for Nagle's algorithm and the peer's delayed ACK, about 40 ms
/// (45 ms against 2.2 ms for a cold request, measured locally). Interim: the HTTP client is
/// moving to one that sets it itself. A failure is logged once and is never fatal.
fn noDelay(fd: std.posix.socket_t) void {
    const on: c_int = 1;
    std.posix.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&on)) catch |e| {
        if (!nodelay_failed.swap(true, .monotonic))
            std.log.warn("http: TCP_NODELAY could not be set on a connection: {t}", .{e});
    };
}

/// What a new connection took.
pub const Opened = struct {
    /// The lookup, null when none was seen in the request's window.
    dns_ns: ?u64,
    /// The TCP connect of the winning address.
    connect_ns: u64,
    /// From the connect's end to `until`: the TLS handshake, or the little that follows a plain
    /// connect.
    after_connect_ns: u64,
};

/// The connect that made `fd` (taken: a connection is opened once), when it ended after
/// `window_start`, and the lookup of `host` inside the window. Null for a connection that was
/// already open.
pub fn takeOpened(fd: i32, host: []const u8, window_start: u64, until: u64) ?Opened {
    acquire();
    defer lock.unlock();
    var found: ?Connect = null;
    for (&connects) |*c| if (c.fd == fd) {
        if (c.end >= window_start) found = c.*;
        c.fd = -1;
    };
    const c = found orelse return null;
    var dns: ?u64 = null;
    var best_end: u64 = 0;
    for (lookups) |l| {
        if (l.host_len == 0 or l.start < window_start or l.end > c.end) continue;
        if (!std.ascii.eqlIgnoreCase(l.host[0..l.host_len], host)) continue;
        if (l.end >= best_end) {
            best_end = l.end;
            dns = l.end - l.start;
        }
    }
    return .{
        .dns_ns = dns,
        .connect_ns = c.end - c.start,
        .after_connect_ns = until -| c.end,
    };
}

test "a wrapped Io times the lookup and the connect of a new connection, and no more" {
    const io = wrap(std.testing.io);
    try std.testing.expect(hooked(io));
    try std.testing.expect(wrap(io).vtable == io.vtable);
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const t0 = now();
    const host: net.HostName = try .init("localhost");
    const stream = try host.connect(io, listener.socket.address.getPort(), .{ .mode = .stream });
    defer stream.close(io);
    const opened = takeOpened(stream.socket.handle, "LOCALHOST", t0, now()).?;
    try std.testing.expect(opened.dns_ns != null);
    // Taken once: a second look finds a connection that is no longer new.
    try std.testing.expect(takeOpened(stream.socket.handle, "localhost", t0, now()) == null);
}

test "a wrapped connect sets TCP_NODELAY on its socket" {
    const io = wrap(std.testing.io);
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var got: c_int = 0;
    var len: linux.socklen_t = @sizeOf(c_int);
    try std.testing.expectEqual(@as(usize, 0), linux.getsockopt(stream.socket.handle, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&got), &len));
    try std.testing.expectEqual(@as(c_int, 1), got);
}
