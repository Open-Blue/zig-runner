//! The process's HTTP client. One client loads the CA bundle once and keeps connections alive; a
//! client per request (what the runner did before) loaded the bundle every time, into memory that a
//! waiting runner only frees after its next job, so idle runners grew by hundreds of KB per poll.
const std = @import("std");
const builtin = @import("builtin");

/// Set by `main` for the runner (its allocator must be thread-safe: runners share it). Unset in
/// tests and one-off commands, where each request gets its own client. `renew` replaces it.
pub var shared: std.atomic.Value(?*std.http.Client) = .init(null);

/// The write buffer of every client that sends a bearer token: std's default of 1 KiB is smaller
/// than the ~1.6 KiB token, and requests stall.
pub const write_buffer_size = 16 * 1024;

/// The shared client, or `local` (owned by the caller) when there is none.
pub fn client(local: *std.http.Client) *std.http.Client {
    return shared.load(.acquire) orelse local;
}

/// The least time between two `renew`s, the time of the last one (0: none yet), and the age at which
/// `keepFresh` replaces a client that has met no failure. Real time: a laptop's sleep counts.
const renew_every_s = 15 * 60;
const renew_age_s = 24 * 60 * 60;
var renewed_at_s: std.atomic.Value(i64) = .init(0);

/// Replaces the shared client with a new one, unless that already happened since `stale` was taken.
/// A client checks certificates against the time of its first HTTPS request (`Client.now`, which
/// std never moves and cannot safely move while it is in use), so after a process has run for a
/// while, a certificate issued since it started is "not yet valid" and every new connection to that
/// host fails. A new client takes the time again and rescans the system's root certificates. The
/// old one is never freed: a job's live feed holds one of its connections for as long as the job
/// runs. So one every `renew_every_s` at most: `staleClock` cannot tell a stale clock from a TLS
/// failure with another cause, and an outage that lasts would otherwise leave a client behind on
/// every try.
pub fn renew(stale: *std.http.Client) void {
    const now = std.Io.Clock.real.now(stale.io).toSeconds();
    const last = renewed_at_s.load(.acquire);
    if (last != 0 and now - last < renew_every_s) return;
    if (renewed_at_s.cmpxchgStrong(last, now, .acq_rel, .acquire) != null) return;
    const gpa = stale.allocator;
    const fresh = gpa.create(std.http.Client) catch return;
    fresh.* = .{ .allocator = gpa, .io = stale.io, .write_buffer_size = stale.write_buffer_size };
    if (shared.cmpxchgStrong(stale, fresh, .acq_rel, .acquire) != null) return gpa.destroy(fresh);
    // Its idle connections close now, and the ones in use as they finish.
    stale.connection_pool.resize(stale.io, 0) catch return;
}

/// Replaces the shared client once it is `renew_age_s` old, for what no failure shows: its clock
/// also accepts a certificate that expired since it took the time. Called before a request; the
/// first call starts the count.
pub fn keepFresh(io: std.Io) void {
    const c = shared.load(.acquire) orelse return;
    const now = std.Io.Clock.real.now(io).toSeconds();
    const last = renewed_at_s.load(.acquire);
    if (last == 0) {
        _ = renewed_at_s.cmpxchgStrong(0, now, .acq_rel, .acquire);
    } else if (now - last >= renew_age_s) renew(c);
}

/// How many times a request may meet a kept-alive connection the server has closed (nothing was
/// processed) before it gives up: one more than the idle connections the pool keeps, so it always
/// gets past all of them to a new one. It was 8, and 16 runners registering at once leave 16 idle
/// connections to api.github.com, all closed by GitHub a minute later: the next request found 8
/// dead ones in a row and failed (the stale-registration sweep's listing, every time).
pub fn staleRetries(c: ?*std.http.Client) u32 {
    const default_pool: std.http.Client.ConnectionPool = .{};
    const kept: usize = if (c) |cl| cl.connection_pool.free_size else default_pool.free_size;
    return @intCast(kept + 1);
}

/// Whether `err` may be a certificate judged by a client's stale clock (see `renew`). std reports
/// every failed TLS handshake as `TlsInitializationFailed` and drops the reason, so that is all
/// there is to go on: razorbill's runners spent an hour retrying a certificate issued after they
/// started (2026-11-06), and a restart was what cured them.
pub fn staleClock(err: anyerror) bool {
    return err == error.TlsInitializationFailed;
}

/// How long one request to GitHub may take, from connecting to the last byte of its answer, before
/// it is given up (`within`). GitHub's API and results service answer in well under a second, the
/// slowest calls (generate-jitconfig, completejob) in a few, so 30 s is generous even for a
/// Raspberry Pi's TLS handshake; a request with no answer by then is on a connection that died. A
/// log upload once read a reused connection GitHub had dropped silently for 17 minutes, and its job
/// sat "in progress" all that time (razorbill, 2026-10-28; #100). Long polls and blob uploads take
/// longer and set their own (`broker.RequestOptions.deadline`).
pub const request_deadline: std.Io.Duration = .fromSeconds(30);

pub const FetchError = std.http.Client.FetchError || error{Timeout};

/// `client.fetch` within `request_deadline`, tried again while a kept-alive connection turns out to
/// be closed (no byte came back, so nothing was processed or written; see `broker.request`). Not
/// tried again when the time runs out, as `broker.request` is: its callers (generate-jitconfig, the
/// OAuth token) are tried again by the runner's cycle, and a registration sent twice makes two.
pub fn fetch(
    c: *std.http.Client,
    options: std.http.Client.FetchOptions,
) FetchError!std.http.Client.FetchResult {
    keepFresh(c.io);
    var attempt: u32 = 0;
    var cl = c;
    var renewed = false;
    while (true) : (attempt += 1) {
        const r = try within(cl.io, request_deadline, fetchOnce, .{ cl, options });
        return (r orelse return error.Timeout) catch |err| switch (err) {
            error.HttpConnectionClosing => if (attempt < staleRetries(cl)) continue else err,
            else => if (!renewed and staleClock(err) and shared.load(.acquire) == cl) {
                renew(cl);
                cl = shared.load(.acquire).?;
                renewed = true;
                continue;
            } else err,
        };
    }
}

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

fn fetchOnce(
    c: *std.http.Client,
    options: std.http.Client.FetchOptions,
) std.http.Client.FetchError!std.http.Client.FetchResult {
    return c.fetch(options);
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

test "renew replaces the shared client once, however many saw it go stale" {
    const gpa = std.testing.allocator;
    var first: std.http.Client = .{ .allocator = gpa, .io = std.testing.io };
    defer first.deinit();
    shared.store(&first, .release);
    defer shared.store(null, .release);
    renewed_at_s.store(0, .release);

    renew(&first);
    const second = shared.load(.acquire).?;
    defer gpa.destroy(second);
    defer second.deinit();
    try std.testing.expect(second != &first);
    try std.testing.expect(second.now == null); // takes the time again on its first request
    // A second runner that saw the same stale client finds it already replaced.
    renew(&first);
    try std.testing.expectEqual(second, shared.load(.acquire).?);
}

test "renew leaves one client behind at most in its interval, however long TLS keeps failing" {
    const gpa = std.testing.allocator;
    var first: std.http.Client = .{ .allocator = gpa, .io = std.testing.io };
    defer first.deinit();
    shared.store(&first, .release);
    defer shared.store(null, .release);
    renewed_at_s.store(0, .release);

    renew(&first);
    const second = shared.load(.acquire).?;
    defer gpa.destroy(second);
    defer second.deinit();
    // The new client fails too: it stays, and no third is made.
    renew(second);
    try std.testing.expectEqual(second, shared.load(.acquire).?);
}

test "a client is replaced at its age with no failure, and its idle connections go with it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var first: std.http.Client = .{ .allocator = gpa, .io = io };
    defer first.deinit();
    shared.store(&first, .release);
    defer shared.store(null, .release);
    renewed_at_s.store(0, .release);

    // The first call starts the count, and a young client stays.
    keepFresh(io);
    try std.testing.expect(renewed_at_s.load(.acquire) != 0);
    keepFresh(io);
    try std.testing.expectEqual(&first, shared.load(.acquire).?);

    renewed_at_s.store(std.Io.Clock.real.now(io).toSeconds() - renew_age_s, .release);
    keepFresh(io);
    const second = shared.load(.acquire).?;
    defer gpa.destroy(second);
    defer second.deinit();
    try std.testing.expect(second != &first);
    try std.testing.expectEqual(@as(usize, 0), first.connection_pool.free_size);
}

test "what std makes of a handshake's failure counts as a stale clock" {
    try std.testing.expect(staleClock(error.TlsInitializationFailed));
    try std.testing.expect(!staleClock(error.ConnectionRefused));
    try std.testing.expect(!staleClock(error.HttpConnectionClosing));
}

test "a request can get past every idle connection the pool keeps" {
    var c: std.http.Client = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer c.deinit();
    const kept: u32 = @intCast(c.connection_pool.free_size);
    try std.testing.expectEqual(kept + 1, staleRetries(&c));
    // 16 runners, each leaving a connection behind: more than the 8 tries there used to be.
    try std.testing.expect(staleRetries(&c) > 16);
    try std.testing.expectEqual(@as(u32, 33), staleRetries(null));
}
