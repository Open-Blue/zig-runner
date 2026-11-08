//! A job container's `ports:` on the native backend (docs/native-backend.md, "Job container
//! options"): each published from the host into the job's network, as `docker create -p` does.
//!
//! By a relay of the runner's own (`forward.zig` with `Spec.publish`), not by nftables. It listens
//! on the host's address and port in the runner's network namespace, then joins the job's, where
//! it connects each client to the job's port on the job's loopback, and drops to the job's
//! `nobody` under the steps' seccomp filter before it reads a byte. The runner's table
//! (`nft.zig`) stays as it is: no process of the host's reaches a job through the bridge, for a
//! published port too, so the drop holds for every port that is not published and the job's own
//! address is never exposed. A DNAT in that table would have needed an accept beside the drop, a
//! rule per job to remove on every end (and at the next start after a crash), and
//! `route_localnet` to reach the job from the host's 127.0.0.1. The relay needs none of that: its
//! sockets are a process's, which ends with its lifeline (its stdin, the runner's pipe), so a job's
//! end or the runner's crash takes the published ports with it and there is nothing stale to remove
//! at the next start.
//!
//! What a job may publish is the operator's: the host addresses `RUNNER_NATIVE_PORT_ADDRESSES`
//! allows (127.0.0.1 alone by default: published on the host's loopback, which only the host's own
//! processes reach; an entry with no address takes the first one), no host port below 1024 (the
//! host's privileged ports), and none for a job the runner does not vouch for (a fork's pull
//! request included): its port would be a way in to code no one reviewed, on the host's address.
//! A port another process holds fails the job naming it, as Docker's bind does.

const std = @import("std");
const container_options = @import("container_options.zig");
const forward = @import("forward.zig");

const Allocator = std.mem.Allocator;

/// The operator's setting, named in the refusals.
pub const setting = "RUNNER_NATIVE_PORT_ADDRESSES";
pub const default_addresses = [_][4]u8{.{ 127, 0, 0, 1 }};

/// `text` (colon- or comma-separated IPv4 addresses, `0.0.0.0` for every address of the host) as
/// the addresses a published port may take; empty is the default, 127.0.0.1.
pub fn parseAddresses(arena: Allocator, text: []const u8) error{ InvalidAddress, OutOfMemory }![]const [4]u8 {
    var out: std.ArrayList([4]u8) = .empty;
    var it = std.mem.tokenizeAny(u8, text, ",: \t");
    while (it.next()) |w| try out.append(arena, container_options.parseIp4(w) orelse return error.InvalidAddress);
    if (out.items.len == 0) return &default_addresses;
    return out.items;
}

/// Whether `parseAddresses` takes `text`, without allocating (`Config.load`).
pub fn validAddresses(text: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, text, ",: \t");
    while (it.next()) |w| if (container_options.parseIp4(w) == null) return false;
    return true;
}

/// `ports` as the relay's maps (`forward.Spec.Map`), each on its address (the entry's or the
/// first allowed). On `error.Refused`, `why` names the entry and the setting or the rule.
pub fn plan(
    arena: Allocator,
    ports: []const container_options.Port,
    allowed: []const [4]u8,
    trusted: bool,
    why: *[]const u8,
) error{ Refused, OutOfMemory }![]const forward.Spec.Map {
    if (ports.len == 0) return &.{};
    if (!trusted) {
        why.* = "a job the runner does not vouch for (a fork's pull request included) publishes " ++
            "no port: a job container's `ports:` are refused for it";
        return error.Refused;
    }
    if (ports.len > forward.max_published) {
        why.* = try std.fmt.allocPrint(arena, "a job container publishes at most {d} ports", .{forward.max_published});
        return error.Refused;
    }
    std.debug.assert(allowed.len > 0);
    var out: std.ArrayList(forward.Spec.Map) = .empty;
    for (ports) |p| {
        const address = p.address orelse allowed[0];
        const ok = for (allowed) |a| {
            if (std.mem.eql(u8, &a, &address)) break true;
        } else false;
        if (!ok) {
            why.* = try std.fmt.allocPrint(arena, "the job container's port {f} publishes on " ++
                "{f}, which " ++ setting ++ " does not allow (it allows {f})", .{
                Shown{ .p = p, .address = address },
                Ip{ .a = address },
                IpList{ .list = allowed },
            });
            return error.Refused;
        }
        if (p.host != 0 and p.host < 1024) {
            why.* = try std.fmt.allocPrint(arena, "the job container's port {f} publishes host " ++
                "port {d}, below 1024: the host's privileged ports are not given to a job", .{
                Shown{ .p = p, .address = address },
                p.host,
            });
            return error.Refused;
        }
        try out.append(arena, .{ .host = p.host, .container = p.container, .address = address, .udp = p.udp });
    }
    return out.items;
}

/// What "Set up job" says of the published ports, as `docker port` prints them:
/// `80/tcp -> 127.0.0.1:32768`, one per port, with the host port each got.
pub fn report(arena: Allocator, maps: []const forward.Spec.Map, bound: []const u16) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (maps, 0..) |m, i| try out.append(arena, try std.fmt.allocPrint(arena, "{d}/{s} -> {f}:{d}", .{
        m.container,
        if (m.udp) "udp" else "tcp",
        Ip{ .a = m.address },
        if (i < bound.len) bound[i] else m.host,
    }));
    return out.items;
}

const Ip = struct {
    a: [4]u8,
    pub fn format(ip: Ip, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{d}.{d}.{d}.{d}", .{ ip.a[0], ip.a[1], ip.a[2], ip.a[3] });
    }
};

const IpList = struct {
    list: []const [4]u8,
    pub fn format(l: IpList, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (l.list, 0..) |a, i| {
            if (i > 0) try w.writeAll(", ");
            try (Ip{ .a = a }).format(w);
        }
    }
};

/// An entry as it reads with its address: `127.0.0.1:8080:80/tcp`, `0.0.0.0::53/udp`.
const Shown = struct {
    p: container_options.Port,
    address: [4]u8,
    pub fn format(s: Shown, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try (Ip{ .a = s.address }).format(w);
        try w.writeByte(':');
        if (s.p.host != 0) try w.print("{d}", .{s.p.host});
        try w.print(":{d}/{s}", .{ s.p.container, if (s.p.udp) "udp" else "tcp" });
    }
};

test "publish: what the operator allows, by address, port and trust" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";
    const loopback = &default_addresses;
    try std.testing.expectEqualSlices([4]u8, loopback, try parseAddresses(arena, ""));
    const both = try parseAddresses(arena, "0.0.0.0, 192.168.1.5");
    try std.testing.expectEqual(@as(usize, 2), both.len);
    try std.testing.expectError(error.InvalidAddress, parseAddresses(arena, "0.0.0.0,localhost"));

    // An entry with no address takes the first allowed: 127.0.0.1 unless the operator says.
    const ports = [_]container_options.Port{
        .{ .host = 8080, .container = 80 },
        .{ .container = 53, .udp = true },
        .{ .address = .{ 127, 0, 0, 1 }, .host = 9000, .container = 9000 },
    };
    const maps = try plan(arena, &ports, loopback, true, &why);
    try std.testing.expectEqual(@as(usize, 3), maps.len);
    for (maps) |m| try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &m.address);
    try std.testing.expect(maps[1].udp and maps[1].host == 0);
    const wide = try plan(arena, ports[0..1], both, true, &why);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &wide[0].address);
    const lines = try report(arena, maps, &.{ 8080, 41234, 9000 });
    try std.testing.expectEqualStrings("80/tcp -> 127.0.0.1:8080", lines[0]);
    try std.testing.expectEqualStrings("53/udp -> 127.0.0.1:41234", lines[1]);

    // An address the operator did not allow, a privileged host port, an untrusted job.
    const Case = struct { port: container_options.Port, trusted: bool, says: []const []const u8 };
    for ([_]Case{
        .{ .port = .{ .address = .{ 0, 0, 0, 0 }, .host = 8080, .container = 80 }, .trusted = true, .says = &.{ "0.0.0.0:8080:80/tcp", setting, "allows 127.0.0.1" } },
        .{ .port = .{ .address = .{ 10, 0, 0, 1 }, .container = 80 }, .trusted = true, .says = &.{ "10.0.0.1::80/tcp", setting } },
        .{ .port = .{ .host = 80, .container = 80 }, .trusted = true, .says = &.{ "127.0.0.1:80:80/tcp", "port 80, below 1024" } },
        .{ .port = .{ .host = 1023, .container = 80, .udp = true }, .trusted = true, .says = &.{"port 1023, below 1024"} },
        .{ .port = .{ .host = 8080, .container = 80 }, .trusted = false, .says = &.{"does not vouch for"} },
    }) |c| {
        why = "";
        try std.testing.expectError(error.Refused, plan(arena, &.{c.port}, loopback, c.trusted, &why));
        for (c.says) |s| if (std.mem.indexOf(u8, why, s) == null) {
            std.debug.print("missing {s} in: {s}\n", .{ s, why });
            return error.TestUnexpectedResult;
        };
    }
    // Port 1024 and up, and a port the kernel picks, are the job's to take.
    _ = try plan(arena, &.{.{ .host = 1024, .container = 80 }}, loopback, true, &why);
    try std.testing.expectEqual(@as(usize, 0), (try plan(arena, &.{}, loopback, false, &why)).len);
}
