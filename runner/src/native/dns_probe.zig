//! How long a native job's nameserver takes to answer, seen from the job's network (#522). A job's
//! resolver is one nameserver (`net.Resolver`), often a forwarder with a slow upstream behind it
//! (Tailscale's MagicDNS in front of a Pi-hole), and a lookup that waits there shows in the job
//! only as a slow `git fetch` or "Could not resolve host". Once the job's network exists, the
//! runner asks each nameserver the job gets for one fixed name from a thread that has joined the
//! job's network namespace, so the query takes the job's path (veth, NAT, forward rules), off the
//! job's own path, and logs when it was slow, answered with an error or did not answer:
//!
//!     warn: kind=dns_lookup_slow name=github.com ms=3120 rcode=0 server=100.100.100.100 source=probe
//!     warn: kind=dns_lookup_failed name=github.com ms=5000 rcode=? server=100.100.100.100 source=probe err=Timeout
//!
//! Nothing changes for the job: its resolv.conf and its queries are as before. The same two kinds
//! are logged for the runner's own requests, with `source=request`, when their `dns_ms` is over the
//! threshold (`github/request_log.zig`): there `ms` is the whole lookup in the host's namespace,
//! here it is one query to one nameserver.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const logfmt = @import("../logfmt.zig");
const phases = @import("phases.zig");
const forward = @import("forward.zig");

/// The name asked for.
pub const probe_name = "github.com";
/// A lookup over this is logged as slow; one with no answer in `give_up_ms` as failed.
pub const slow_ms = 2000;
pub const give_up_ms = 5000;

pub const Outcome = union(enum) {
    /// A reply to our query: its RCODE (0 is NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED).
    answered: struct { ms: u32, rcode: u4 },
    failed: struct { ms: u32, err: []const u8 },
};

/// The kind `o` is logged under; null for a quick, successful lookup. A reply with an error code
/// counts as a failure; NXDOMAIN too, as the name asked for exists.
pub fn kindOf(o: Outcome) ?[]const u8 {
    return switch (o) {
        .answered => |a| if (a.rcode != 0) "dns_lookup_failed" else if (a.ms > slow_ms) "dns_lookup_slow" else null,
        .failed => "dns_lookup_failed",
    };
}

/// A query for `name`'s A record with id `id`, in `buf`; its length.
pub fn query(buf: []u8, id: u16, name: []const u8) usize {
    std.mem.writeInt(u16, buf[0..2], id, .big);
    @memcpy(buf[2..12], &[_]u8{ 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }); // RD, one question
    var n: usize = 12;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |l| {
        buf[n] = @truncate(l.len); // a label is at most 63 bytes
        @memcpy(buf[n + 1 ..][0..l.len], l);
        n += 1 + l.len;
    }
    @memcpy(buf[n..][0..5], &[_]u8{ 0, 0, 1, 0, 1 }); // root, A, IN
    return n + 5;
}

/// The RCODE of `reply` when it answers `sent` (a query of `query`): same id, the response bit
/// set, one question and that question's bytes. Anything else (another id, a short or cut reply)
/// is null: not ours.
pub fn replyTo(sent: []const u8, reply: []const u8) ?u4 {
    if (reply.len < sent.len or !std.mem.eql(u8, reply[0..2], sent[0..2])) return null;
    if (reply[2] & 0x80 == 0 or std.mem.readInt(u16, reply[4..6], .big) != 1) return null;
    if (!std.mem.eql(u8, reply[12..sent.len], sent[12..])) return null;
    return @truncate(reply[3]);
}

fn since(t0: u64) u32 {
    return std.math.lossyCast(u32, (phases.now() - t0) / std.time.ns_per_ms);
}

/// Asks `server` (UDP port 53) for `name` once and says how long it took.
pub fn ask(server: [4]u8, name: []const u8) Outcome {
    return askAt(server, 53, name, give_up_ms);
}

/// `ask` on `port`, giving up after `budget_ms`: the time to the first reply that is ours (a
/// datagram that is not is read past), whatever its RCODE; or `failed` with why.
pub fn askAt(server: [4]u8, port: u16, name: []const u8, budget_ms: u32) Outcome {
    const t0 = phases.now();
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return .{ .failed = .{ .ms = 0, .err = "Socket" } };
    const fd = std.math.cast(linux.fd_t, rc) orelse return .{ .failed = .{ .ms = 0, .err = "Socket" } };
    defer _ = linux.close(fd);
    // A backstop: poll says when a datagram is there, and a recv that blocks anyway ends too.
    var tv: linux.timeval = .{ .sec = budget_ms / 1000 + 1, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    var sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.bytesToValue(u32, &server) };
    if (linux.errno(linux.connect(fd, forward.asSockaddr(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return .{ .failed = .{ .ms = since(t0), .err = "Connect" } };
    var q: [300]u8 = undefined;
    var id_bytes: [2]u8 = undefined;
    _ = linux.getrandom(&id_bytes, id_bytes.len, 0);
    const len = query(&q, std.mem.readInt(u16, &id_bytes, .big), name);
    if (linux.errno(linux.sendto(fd, &q, len, 0, null, 0)) != .SUCCESS)
        return .{ .failed = .{ .ms = since(t0), .err = "Send" } };
    while (true) {
        const spent = since(t0);
        if (spent >= budget_ms) return .{ .failed = .{ .ms = spent, .err = "Timeout" } };
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const p = linux.poll(&fds, 1, std.math.lossyCast(i32, budget_ms - spent));
        switch (linux.errno(p)) {
            .SUCCESS => {},
            .INTR => continue, // with what is left of the budget
            else => return .{ .failed = .{ .ms = since(t0), .err = "Poll" } },
        }
        if (p == 0) continue; // the budget check above ends it
        var r: [512]u8 = undefined;
        const got = linux.recvfrom(fd, &r, r.len, 0, null, null);
        switch (linux.errno(got)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            else => return .{ .failed = .{ .ms = since(t0), .err = "Recv" } },
        }
        if (replyTo(q[0..len], r[0..got])) |rcode| return .{ .answered = .{ .ms = since(t0), .rcode = rcode } };
    }
}

/// Logs what `o` was for `server`, if it was slow or failed.
pub fn report(o: Outcome, name: []const u8, server: [4]u8) void {
    if (kindOf(o) == null) return;
    const a = server;
    switch (o) {
        .answered => |r| logfmt.warn("dns_lookup_slow", "name={f} ms={d} rcode={d} server={d}.{d}.{d}.{d} source=probe", .{
            logfmt.q(name), r.ms, r.rcode, a[0], a[1], a[2], a[3],
        }),
        .failed => |f| logfmt.warn("dns_lookup_failed", "name={f} ms={d} rcode=? server={d}.{d}.{d}.{d} source=probe err={s}", .{
            logfmt.q(name), f.ms, a[0], a[1], a[2], a[3], f.err,
        }),
    }
}

/// Asks each of `servers` for `probe_name` on a thread of its own that has joined the namespace
/// file `netns`, so the job does not wait for a slow answer; the thread ends with the last answer
/// or `give_up_ms`. A namespace that cannot be joined (the job is already over) logs nothing.
pub fn start(netns: []const u8, servers: []const [4]u8) void {
    if (servers.len == 0 or builtin.is_test) return; // tests name nameservers that are not real
    const gpa = std.heap.page_allocator;
    const path = gpa.dupeSentinel(u8, netns, 0) catch return;
    var copy: [max_servers][4]u8 = undefined;
    const n = @min(servers.len, copy.len);
    @memcpy(copy[0..n], servers[0..n]);
    const t = std.Thread.spawn(.{}, run, .{ path, copy, n }) catch {
        gpa.free(path);
        return;
    };
    t.detach();
}

const max_servers = 8;

fn run(path: [:0]u8, servers: [max_servers][4]u8, n: usize) void {
    defer std.heap.page_allocator.free(path);
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const fd = std.math.cast(linux.fd_t, rc) orelse return;
    defer _ = linux.close(fd);
    if (linux.errno(linux.setns(fd, linux.CLONE.NEWNET)) != .SUCCESS) return;
    for (servers[0..n]) |s| report(ask(s, probe_name), probe_name, s);
}

test "a lookup is logged when it was slow, answered with an error or did not answer" {
    try std.testing.expectEqual(@as(?[]const u8, null), kindOf(.{ .answered = .{ .ms = 20, .rcode = 0 } }));
    try std.testing.expectEqual(@as(?[]const u8, null), kindOf(.{ .answered = .{ .ms = slow_ms, .rcode = 0 } }));
    try std.testing.expectEqualStrings("dns_lookup_slow", kindOf(.{ .answered = .{ .ms = slow_ms + 1, .rcode = 0 } }).?);
    try std.testing.expectEqualStrings("dns_lookup_failed", kindOf(.{ .answered = .{ .ms = 5, .rcode = 2 } }).?);
    try std.testing.expectEqualStrings("dns_lookup_failed", kindOf(.{ .failed = .{ .ms = 5000, .err = "Timeout" } }).?);
}

test "the query is a standard A query for the name" {
    var b: [300]u8 = undefined;
    const n = query(&b, 0xabcd, "github.com");
    try std.testing.expectEqualSlices(u8, &.{ 0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6 }, b[0..13]);
    try std.testing.expectEqualSlices(u8, "\x06github\x03com\x00\x00\x01\x00\x01", b[12..n]);
}

test "a reply is ours only with our id, the response bit and our question" {
    var q: [300]u8 = undefined;
    const n = query(&q, 0x1234, probe_name);
    var r: [300]u8 = undefined;
    @memcpy(r[0..n], q[0..n]);
    try std.testing.expectEqual(@as(?u4, null), replyTo(q[0..n], r[0..n])); // a query, not a response
    r[2] |= 0x80;
    try std.testing.expectEqual(@as(?u4, 0), replyTo(q[0..n], r[0..n]));
    r[3] = 0x82; // SERVFAIL, recursion available
    try std.testing.expectEqual(@as(?u4, 2), replyTo(q[0..n], r[0..n]));
    try std.testing.expectEqual(@as(?u4, null), replyTo(q[0..n], r[0 .. n - 1])); // cut short
    r[1] ^= 1;
    try std.testing.expectEqual(@as(?u4, null), replyTo(q[0..n], r[0..n])); // another id
    r[1] ^= 1;
    r[13] = 'x';
    try std.testing.expectEqual(@as(?u4, null), replyTo(q[0..n], r[0..n])); // another question
}

/// A UDP responder on the loopback for the tests: it answers the one query it gets as `mode` says.
const Responder = struct {
    fd: linux.fd_t,
    port: u16,
    mode: Mode,
    thread: std.Thread = undefined,

    const Mode = enum { echo, servfail, wrong_id_first, truncated_only, silent };

    fn start(mode: Mode) !*Responder {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        const fd = std.math.cast(linux.fd_t, rc) orelse return error.Socket;
        var sa: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.bytesToValue(u32, &[4]u8{ 127, 0, 0, 1 }) };
        if (linux.errno(linux.bind(fd, forward.asSockaddr(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.Bind;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        if (linux.errno(linux.getsockname(fd, forward.asSockaddr(&sa), &len)) != .SUCCESS) return error.Bind;
        const r = try std.testing.allocator.create(Responder);
        r.* = .{ .fd = fd, .port = std.mem.bigToNative(u16, sa.port), .mode = mode };
        r.thread = try std.Thread.spawn(.{}, serve, .{r});
        return r;
    }

    fn stop(r: *Responder) void {
        r.thread.join();
        _ = linux.close(r.fd);
        std.testing.allocator.destroy(r);
    }

    fn serve(r: *Responder) void {
        var fds = [_]linux.pollfd{.{ .fd = r.fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&fds, 1, 3000) != 1) return;
        var buf: [512]u8 = undefined;
        var from: linux.sockaddr.in = undefined;
        var flen: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        const n = linux.recvfrom(r.fd, &buf, buf.len, 0, forward.asSockaddr(&from), &flen);
        if (linux.errno(n) != .SUCCESS) return;
        const sa = forward.asSockaddr(&from);
        buf[2] |= 0x80;
        switch (r.mode) {
            .silent => {},
            .echo => _ = linux.sendto(r.fd, &buf, n, 0, sa, flen),
            .servfail => {
                buf[3] = 2;
                _ = linux.sendto(r.fd, &buf, n, 0, sa, flen);
            },
            .wrong_id_first => {
                var other = buf;
                other[0] ^= 0xff;
                _ = linux.sendto(r.fd, &other, n, 0, sa, flen);
                _ = linux.sendto(r.fd, &buf, n, 0, sa, flen);
            },
            .truncated_only => _ = linux.sendto(r.fd, &buf, 20, 0, sa, flen),
        }
    }
};

test "ask against a real responder: the first reply that is ours, and its rcode" {
    const lo: [4]u8 = .{ 127, 0, 0, 1 };
    for ([_]struct { Responder.Mode, u4 }{ .{ .echo, 0 }, .{ .servfail, 2 }, .{ .wrong_id_first, 0 } }) |c| {
        const r = try Responder.start(c[0]);
        defer r.stop();
        const o = askAt(lo, r.port, probe_name, 2000);
        try std.testing.expectEqual(c[1], o.answered.rcode);
        try std.testing.expect(o.answered.ms < 1000);
    }
}

test "ask: a cut reply and a silent server end in Timeout inside the budget" {
    const lo: [4]u8 = .{ 127, 0, 0, 1 };
    for ([_]Responder.Mode{ .truncated_only, .silent }) |m| {
        const r = try Responder.start(m);
        defer r.stop();
        const t0 = phases.now();
        const o = askAt(lo, r.port, probe_name, 300);
        try std.testing.expectEqualStrings("Timeout", o.failed.err);
        const took = (phases.now() - t0) / std.time.ns_per_ms;
        try std.testing.expect(took >= 300 and took < 1500);
    }
}
