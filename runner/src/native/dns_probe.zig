//! How long a native job's nameserver takes to answer, seen from the runner (#522). A job's
//! resolver is one nameserver (`net.Resolver`), often a forwarder with a slow upstream behind it
//! (Tailscale's MagicDNS in front of a Pi-hole), and a lookup that waits there shows in the job
//! only as a slow `git fetch` or "Could not resolve host". The runner asks that same nameserver
//! for one fixed name at the start of each job, off the job's path, and logs when it was slow or
//! did not answer:
//!
//!     warn: kind=dns_lookup_slow name=github.com ms=3120 server=100.100.100.100
//!     warn: kind=dns_lookup_failed name=github.com ms=5000 server=100.100.100.100 err=Timeout
//!
//! Nothing changes for the job: its resolv.conf and its queries are as before. The same two kinds
//! are logged for the runner's own requests when their `dns_ms` is over the threshold
//! (`github/request_log.zig`).
const std = @import("std");
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
    answered: u32,
    failed: struct { ms: u32, err: []const u8 },
};

/// Whether `o` is worth a line, and the kind it gets; null for a lookup that was quick.
pub fn kindOf(o: Outcome) ?[]const u8 {
    return switch (o) {
        .answered => |ms| if (ms > slow_ms) "dns_lookup_slow" else null,
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

fn since(t0: u64) u32 {
    return std.math.lossyCast(u32, (phases.now() - t0) / std.time.ns_per_ms);
}

/// Asks `server` (UDP port 53) for `name` once and says how long it took: the answer's arrival,
/// whatever it holds (NXDOMAIN is an answer), or `failed` after `give_up_ms`.
pub fn ask(server: [4]u8, name: []const u8) Outcome {
    const t0 = phases.now();
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return .{ .failed = .{ .ms = 0, .err = "Socket" } };
    const fd = std.math.cast(linux.fd_t, rc) orelse return .{ .failed = .{ .ms = 0, .err = "Socket" } };
    defer _ = linux.close(fd);
    var sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, 53), .addr = std.mem.bytesToValue(u32, &server) };
    if (linux.errno(linux.connect(fd, forward.asSockaddr(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return .{ .failed = .{ .ms = 0, .err = "Connect" } };
    var q: [300]u8 = undefined;
    const id: u16 = @truncate(t0);
    const len = query(&q, id, name);
    if (linux.errno(linux.sendto(fd, &q, len, 0, null, 0)) != .SUCCESS)
        return .{ .failed = .{ .ms = 0, .err = "Send" } };
    while (true) {
        const spent = since(t0);
        if (spent >= give_up_ms) return .{ .failed = .{ .ms = spent, .err = "Timeout" } };
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&fds, 1, std.math.lossyCast(i32, give_up_ms - spent)) == 0) continue;
        var r: [512]u8 = undefined;
        const got = linux.recvfrom(fd, &r, r.len, 0, null, null);
        if (linux.errno(got) != .SUCCESS) return .{ .failed = .{ .ms = spent, .err = "Recv" } };
        if (got >= 12 and std.mem.readInt(u16, r[0..2], .big) == id)
            return .{ .answered = since(t0) };
    }
}

/// Logs what `o` was for `server`, if it was slow or failed.
pub fn report(o: Outcome, name: []const u8, server: [4]u8) void {
    if (kindOf(o) == null) return;
    switch (o) {
        .answered => |ms| logfmt.warn("dns_lookup_slow", "name={f} ms={d} server={d}.{d}.{d}.{d}", .{
            logfmt.q(name), ms, server[0], server[1], server[2], server[3],
        }),
        .failed => |f| logfmt.warn("dns_lookup_failed", "name={f} ms={d} server={d}.{d}.{d}.{d} err={s}", .{
            logfmt.q(name), f.ms, server[0], server[1], server[2], server[3], f.err,
        }),
    }
}

/// Asks each of `servers` for `probe_name` on a thread of its own, so the job does not wait for a
/// slow answer; the thread ends with the last answer or `give_up_ms`.
pub fn start(servers: []const [4]u8) void {
    if (servers.len == 0 or @import("builtin").is_test) return; // tests name nameservers that are not real
    var copy: [8][4]u8 = undefined;
    const n = @min(servers.len, copy.len);
    @memcpy(copy[0..n], servers[0..n]);
    const t = std.Thread.spawn(.{}, run, .{ copy, n }) catch return;
    t.detach();
}

fn run(servers: [8][4]u8, n: usize) void {
    for (servers[0..n]) |s| report(ask(s, probe_name), probe_name, s);
}

test "a lookup is logged when it was slow or did not answer, not when it was quick" {
    try std.testing.expectEqual(@as(?[]const u8, null), kindOf(.{ .answered = 20 }));
    try std.testing.expectEqual(@as(?[]const u8, null), kindOf(.{ .answered = slow_ms }));
    try std.testing.expectEqualStrings("dns_lookup_slow", kindOf(.{ .answered = slow_ms + 1 }).?);
    try std.testing.expectEqualStrings("dns_lookup_failed", kindOf(.{ .failed = .{ .ms = 5000, .err = "Timeout" } }).?);
}

test "the query is a standard A query for the name" {
    var b: [300]u8 = undefined;
    const n = query(&b, 0xabcd, "github.com");
    try std.testing.expectEqualSlices(u8, &.{ 0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6 }, b[0..13]);
    try std.testing.expectEqualSlices(u8, "\x06github\x03com\x00\x00\x01\x00\x01", b[12..n]);
}

test "ask times a nameserver on the loopback that answers at once, and one that never does" {
    // Port 53 on loopback is not ours to bind in a test; a closed port answers ICMP unreachable,
    // which `recv` reports, so the outcome is a failure the probe names rather than a hang.
    const o = ask(.{ 127, 0, 0, 1 }, probe_name);
    switch (o) {
        .failed => |f| try std.testing.expect(f.ms < give_up_ms),
        .answered => {},
    }
}
