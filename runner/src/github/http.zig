//! What the runner's network calls share around the library (`net_client.zig`): the limit of one
//! request (`request_deadline`), `within` (a function run next to a timer, cancelled when the time
//! passes or the caller is cancelled) and the keepalive of the sockets Zig itself opens (the
//! database's, the Dagger engine's).
const std = @import("std");
const builtin = @import("builtin");

/// How long one request to GitHub may take, from connecting to the last byte of its answer, before
/// it is given up (`within`). GitHub's API and results service answer in well under a second, the
/// slowest calls (generate-jitconfig, completejob) in a few, so 30 s is generous even for a
/// Raspberry Pi's TLS handshake; a request with no answer by then is on a connection that died. A
/// log upload once read a reused connection GitHub had dropped silently for 17 minutes, and its job
/// sat "in progress" all that time (razorbill, 2026-10-28; #100). Long polls and blob uploads take
/// longer and set their own (`broker.RequestOptions.deadline`).
pub const request_deadline: std.Io.Duration = .fromSeconds(30);

/// `function(args)`, given up once `limit` passes: it runs next to a timer and whichever ends first
/// cancels the other, which interrupts a blocked read or write (a request's connection is then not
/// reused: see `broker.exchange`). Null when the time ran out. Without a task to run it in, it runs
/// here, with no limit, as it did before there were limits.
pub fn within(
    io: std.Io,
    limit: std.Io.Duration,
    function: anytype,
    args: std.meta.ArgsTuple(@TypeOf(function)),
) std.Io.Cancelable!?@typeInfo(@TypeOf(function)).@"fn".return_type.? {
    return withinClosing(io, limit, function, args, {}, discardLate);
}

fn discardLate(_: void, _: anytype) void {}

/// `within` for a function whose result owns something (a connection): `closeLate(ctx, result)`
/// releases a result that arrives after the time ran out, or after the caller was cancelled, which
/// nobody would otherwise take. A connect that finished just as the limit passed is such a result.
pub fn withinClosing(
    io: std.Io,
    limit: std.Io.Duration,
    function: anytype,
    args: std.meta.ArgsTuple(@TypeOf(function)),
    ctx: anytype,
    comptime closeLate: anytype,
) std.Io.Cancelable!?@typeInfo(@TypeOf(function)).@"fn".return_type.? {
    const Ended = union(enum) {
        done: @typeInfo(@TypeOf(function)).@"fn".return_type.?,
        timeout: void,
    };
    var buf: [2]Ended = undefined;
    var sel: std.Io.Select(Ended) = .init(io, &buf);
    sel.concurrent(.done, function, args) catch return @call(.auto, function, args);
    // Without a timer it is only waited for.
    sel.concurrent(.timeout, sleep, .{ io, limit }) catch {};
    const first = sel.await() catch |e| {
        drain(&sel, ctx, closeLate);
        return e;
    };
    drain(&sel, ctx, closeLate);
    return switch (first) {
        .done => |r| r,
        .timeout => null,
    };
}

/// Ends what `withinClosing` still runs, handing a result that came in late to `closeLate`.
fn drain(sel: anytype, ctx: anytype, comptime closeLate: anytype) void {
    while (sel.cancel()) |ended| switch (ended) {
        .done => |r| closeLate(ctx, r),
        .timeout => {},
    };
}

fn sleep(io: std.Io, d: std.Io.Duration) void {
    io.sleep(d, .awake) catch {};
}

/// Seconds idle before a connection is probed, between probes, and probes unanswered before it is
/// given up: a peer that went away (the machine slept, the network dropped) is noticed within about
/// 90 s even by a request that is only waiting to read, which nothing else would ever interrupt.
pub const keepalive_idle_secs = 60;
pub const keepalive_interval_secs = 10;
pub const keepalive_probes = 3;

/// How long data sent may go unacknowledged before the kernel gives the connection up
/// (`TCP_USER_TIMEOUT`), the same 90 s. Keepalive probes only an idle connection: a request written
/// to a peer that had silently gone away is retransmitted instead, for as long as Linux's
/// `tcp_retries2` allows, about 15 minutes, and a log upload read its answer for 17 (razorbill,
/// 2026-10-28). A slow peer still acknowledges what it gets, so only a dead one is cut off.
pub const unacked_limit_ms = (keepalive_idle_secs + keepalive_probes * keepalive_interval_secs) *
    1000;

/// Turns on TCP keepalive for a connection's socket, and the limit on unacknowledged data. Best
/// effort: a socket that refuses keeps working as before.
pub fn keepAlive(fd: std.posix.socket_t) void {
    if (builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const on: c_int = 1;
    const idle: c_int = keepalive_idle_secs;
    const interval: c_int = keepalive_interval_secs;
    const probes: c_int = keepalive_probes;
    const unacked: c_uint = unacked_limit_ms;
    const P = std.posix;
    P.setsockopt(fd, linux.SOL.SOCKET, linux.SO.KEEPALIVE, std.mem.asBytes(&on)) catch return;
    P.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.KEEPIDLE, std.mem.asBytes(&idle)) catch {};
    P.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.KEEPINTVL, std.mem.asBytes(&interval)) catch {};
    P.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.KEEPCNT, std.mem.asBytes(&probes)) catch {};
    P.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, std.mem.asBytes(&unacked)) catch {};
}

test "keepAlive turns TCP keepalive on, with its timings and the limit on unacked data" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const fd = stream.socket.handle;

    keepAlive(fd);
    const linux = std.os.linux;
    const Opt = struct { level: i32, name: u32, want: c_int };
    for ([_]Opt{
        .{ .level = linux.SOL.SOCKET, .name = linux.SO.KEEPALIVE, .want = 1 },
        .{ .level = linux.IPPROTO.TCP, .name = linux.TCP.KEEPIDLE, .want = keepalive_idle_secs },
        .{
            .level = linux.IPPROTO.TCP,
            .name = linux.TCP.KEEPINTVL,
            .want = keepalive_interval_secs,
        },
        .{ .level = linux.IPPROTO.TCP, .name = linux.TCP.KEEPCNT, .want = keepalive_probes },
        .{ .level = linux.IPPROTO.TCP, .name = linux.TCP.USER_TIMEOUT, .want = unacked_limit_ms },
    }) |o| {
        var got: c_int = 0;
        var len: linux.socklen_t = @sizeOf(c_int);
        const rc = linux.getsockopt(fd, o.level, o.name, std.mem.asBytes(&got), &len);
        try std.testing.expectEqual(@as(usize, 0), rc);
        try std.testing.expectEqual(o.want, got);
    }
}
