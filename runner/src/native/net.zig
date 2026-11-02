//! A job's own network on a root runner (docs/native-backend.md, P1): a network namespace for all
//! of the job's steps, joined to a bridge of the runner's (`bridge`) by a veth pair, with an
//! address of its own and a default route through the bridge. So each job has its own `lo` and
//! port space, and no step reaches the host's 127.0.0.1. Dagger gives each exec the same through
//! BuildKit's CNI network.
//!
//! Links, addresses and routes are made over rtnetlink here, with no `ip`; the NAT that takes the
//! jobs' traffic out, and the rules that keep them from the host and each other, over nftables
//! netlink (`natRules`, `nft.zig`), with no `iptables`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const nft = @import("nft.zig");

const Allocator = std.mem.Allocator;

/// The runner's bridge. It is the host's, shared by every runner on the host, as the slots are
/// (`slots_dir`).
pub const bridge = "zr0";
/// Slots beyond this have no address (`Subnet.jobAddress`) and no range of ids.
pub const max_slots = 250;

/// Where the slots' locks live: a fixed path on the host, not under a runner's store, since a
/// slot names host-wide things (the veth `zrh<n>`, the address, the range of ids) that two runners
/// with different stores would otherwise both take. A directory only root may enter, so no other
/// user can hold a slot's lock. tmpfs: the locks go with a reboot, as the veths do.
pub const slots_dir = "/run/zig-runner/slots";

/// The jobs' network (`RUNNER_NATIVE_SUBNET`): the bridge is its first address, and slot n's job
/// its 259th + n (`jobAddress`). A prefix of 8 to 23 bits, so there is room for every slot.
pub const Subnet = struct {
    base: [4]u8,
    prefix: u8,

    /// Not podman's 10.88.0.0/16, Docker's 172.17.0.0/16 or its pools' 172.18-31 and
    /// 192.168.x, nor libvirt's 192.168.122.0/24.
    pub const default: Subnet = .{ .base = .{ 10, 211, 0, 0 }, .prefix = 16 };
    pub const default_text = "10.211.0.0/16";

    /// `a.b.c.d/p`, with no host bits set and 8 <= p <= 23.
    pub fn parse(text: []const u8) error{InvalidNativeSubnet}!Subnet {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidNativeSubnet;
        const prefix = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch
            return error.InvalidNativeSubnet;
        if (prefix < 8 or prefix > 23) return error.InvalidNativeSubnet;
        var base: [4]u8 = undefined;
        var octets = std.mem.splitScalar(u8, text[0..slash], '.');
        for (&base) |*b| b.* = std.fmt.parseInt(u8, octets.next() orelse
            return error.InvalidNativeSubnet, 10) catch return error.InvalidNativeSubnet;
        if (octets.next() != null) return error.InvalidNativeSubnet;
        const s: Subnet = .{ .base = base, .prefix = prefix };
        if (s.int() & ~s.mask() != 0) return error.InvalidNativeSubnet;
        return s;
    }

    pub fn gateway(s: Subnet) [4]u8 {
        return bytes(s.int() + 1);
    }

    /// Slot `n`'s address.
    pub fn jobAddress(s: Subnet, slot: u32) [4]u8 {
        std.debug.assert(slot < max_slots);
        return bytes(s.int() + 256 + 2 + slot);
    }

    pub fn format(s: Subnet, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const b = s.base;
        try w.print("{d}.{d}.{d}.{d}/{d}", .{ b[0], b[1], b[2], b[3], s.prefix });
    }

    /// Whether the network `dest`/`mask` (host order) shares an address with this one.
    pub fn overlaps(s: Subnet, dest: u32, mask_: u32) bool {
        const m = s.mask() & mask_;
        return s.int() & m == dest & m;
    }

    fn int(s: Subnet) u32 {
        return std.mem.readInt(u32, &s.base, .big);
    }

    fn mask(s: Subnet) u32 {
        return ~@as(u32, 0) << @intCast(32 - @as(u32, s.prefix));
    }

    fn bytes(v: u32) [4]u8 {
        var out: [4]u8 = undefined;
        std.mem.writeInt(u32, &out, v, .big);
        return out;
    }
};

/// The host's end of slot `n`'s veth pair; the job's end is named `eth0` inside its namespace.
pub fn hostLink(buf: *[16]u8, slot: u32) []const u8 {
    return std.fmt.bufPrint(buf, "zrh{d}", .{slot}) catch unreachable;
}

/// The helper's subcommand that makes a job's network (`main.zig` dispatches it):
/// `zig-runner native-net <namespace file> <slot> <subnet>`.
pub const command = "native-net";

/// The helper's entry: the bridge (if it is not there), a new network namespace kept by
/// bind-mounting it over `path`, with what a step needs in it (`lo`, ports below 1024 and ping
/// without capabilities on the host's, since the namespace's owner is the host's root, not the
/// job's; no IPv6 on its `eth0`, whose link-local address would reach the host past the IPv4
/// rules), then the slot's veth pair, isolated on the bridge, its address and the default route.
/// The runner holds the slot's lock and removed a dead job's veth of it (`Backend.jobNetwork`).
/// A helper, as a thread of the runner must not change its namespace. Exits 0, or 1 with why on
/// stderr.
pub fn upMain(
    arena: Allocator,
    path: []const u8,
    slot_text: []const u8,
    subnet_text: []const u8,
) u8 {
    const slot = std.fmt.parseInt(u32, slot_text, 10) catch return fail("a slot number", .INVAL);
    if (slot >= max_slots) return fail("a slot number", .INVAL);
    const subnet = Subnet.parse(subnet_text) catch return fail("a subnet", .INVAL);
    var host = Socket.open() catch return fail("open rtnetlink", .ACCES);
    host.ensureBridge(subnet) catch return fail("make the bridge " ++ bridge, .INVAL);
    if (!writeSysctl(arena, "/proc/sys/net/ipv6/conf/" ++ bridge ++ "/disable_ipv6", "1"))
        return fail("turn IPv6 off on the bridge", .ACCES);
    const unshared = linux.unshare(linux.CLONE.NEWNET);
    if (linux.errno(unshared) != .SUCCESS) return fail("unshare(net)", linux.errno(unshared));
    var job = Socket.open() catch return fail("open rtnetlink in the job's namespace", .ACCES);
    const sysctls = [_][2][]const u8{
        .{ "/proc/sys/net/ipv4/ip_unprivileged_port_start", "0" },
        .{ "/proc/sys/net/ipv4/ping_group_range", "0 2147483647" },
        // For the links made from here on: `eth0` gets no IPv6, `lo` keeps its ::1.
        .{ "/proc/sys/net/ipv6/conf/default/disable_ipv6", "1" },
    };
    for (sysctls) |kv| if (!writeSysctl(arena, kv[0], kv[1])) return fail("set a sysctl", .ACCES);
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CREAT = true, .CLOEXEC = true };
    const file = linux.open(z(arena, path), flags, 0o444);
    if (linux.errno(file) != .SUCCESS) return fail("make the namespace's file", linux.errno(file));
    _ = linux.close(@intCast(file));
    const kept = linux.mount("/proc/self/ns/net", z(arena, path), null, linux.MS.BIND, 0);
    if (linux.errno(kept) != .SUCCESS) return fail("keep the namespace", linux.errno(kept));
    const ns = linux.open("/proc/self/ns/net", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(ns) != .SUCCESS) return fail("open the namespace", linux.errno(ns));
    host.addVeth(slot, @intCast(ns)) catch return fail("make the veth pair", .INVAL);
    job.configureJob(subnet, slot) catch return fail("configure the job's network", .INVAL);
    return 0;
}

/// Writes a sysctl; true when it took, or when the kernel has no such file under an IPv6 that is
/// off altogether (`ipv6.disable=1`), where there is nothing to turn off.
fn writeSysctl(arena: Allocator, path: []const u8, value: []const u8) bool {
    const fd = linux.open(z(arena, path), .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) == .NOENT and std.mem.indexOf(u8, path, "/ipv6/") != null) return true;
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.write(@intCast(fd), value.ptr, value.len);
    return linux.errno(n) == .SUCCESS;
}

fn fail(what: []const u8, e: linux.E) u8 {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "native net: {s} failed ({s})\n", .{
        what,
        @tagName(e),
    }) catch
        "native net: failed\n";
    _ = linux.write(2, msg.ptr, msg.len);
    return 1;
}

fn z(arena: Allocator, s: []const u8) [*:0]const u8 {
    const out: [:0]const u8 = arena.dupeSentinel(u8, s, 0) catch "";
    return out.ptr;
}

/// An rtnetlink socket in the network namespace the calling thread was in when it was opened,
/// with a datagram socket of that namespace for looking links up by name (`index`). A socket stays
/// in the namespace it was made in, whichever the thread moves to: `upMain` holds one for the
/// host's and one for the job's.
pub const Socket = struct {
    fd: linux.fd_t,
    ioctl_fd: linux.fd_t,
    seq: u32 = 1,

    pub fn open() !Socket {
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.NetlinkSocket;
        const dgram = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(dgram) != .SUCCESS) {
            _ = linux.close(@intCast(rc));
            return error.NetlinkSocket;
        }
        return .{ .fd = @intCast(rc), .ioctl_fd = @intCast(dgram) };
    }

    pub fn close(s: *Socket) void {
        _ = linux.close(s.fd);
        _ = linux.close(s.ioctl_fd);
    }

    /// Sends one request and reads its acknowledgement: the kernel's errno, `.SUCCESS` for none.
    fn request(s: *Socket, msg: *Message) linux.E {
        s.seq += 1;
        msg.finish(s.seq);
        const sent = linux.sendto(s.fd, msg.buf[0..msg.len].ptr, msg.len, 0, null, 0);
        if (linux.errno(sent) != .SUCCESS) return linux.errno(sent);
        var buf: [4096]u8 align(4) = undefined;
        while (true) {
            const n = linux.recvfrom(s.fd, &buf, buf.len, 0, null, null);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS) return linux.errno(n);
            var off: usize = 0;
            while (off + @sizeOf(linux.nlmsghdr) <= n) {
                const h: *const linux.nlmsghdr = @ptrCast(@alignCast(&buf[off]));
                if (h.seq == s.seq and h.type == .ERROR) {
                    const at = off + @sizeOf(linux.nlmsghdr);
                    const code: *const i32 = @ptrCast(@alignCast(&buf[at]));
                    if (code.* == 0) return .SUCCESS;
                    return @fromBackingInt(@intCast(@as(u16, @intCast(-code.*))));
                }
                off += std.mem.alignForward(usize, h.len, 4);
                if (h.len == 0) break;
            }
        }
    }

    /// A link's index in the socket's namespace, or null when there is none of that name.
    pub fn index(s: *Socket, name: []const u8) ?i32 {
        var req: extern struct { name: [16]u8, index: i32, pad: [20]u8 } = .{
            .name = @splat(0),
            .index = 0,
            .pad = @splat(0),
        };
        @memcpy(req.name[0..name.len], name);
        const siocgifindex = 0x8933;
        if (linux.errno(linux.ioctl(s.ioctl_fd, siocgifindex, @intFromPtr(&req))) != .SUCCESS)
            return null;
        return req.index;
    }

    /// Makes the bridge, gives it the gateway's address and brings it up; none of it is an error
    /// when it is there already.
    pub fn ensureBridge(s: *Socket, subnet: Subnet) !void {
        var m: Message = .init(.RTM_NEWLINK, linux.NLM_F_CREATE | linux.NLM_F_EXCL);
        m.ifinfo(0, 0);
        m.attrString(ifla_ifname, bridge);
        const info = m.begin(ifla_linkinfo);
        m.attrString(ifla_info_kind, "bridge");
        m.end(info);
        try expect(s.request(&m), true);
        const i = s.index(bridge) orelse return error.NoBridge;
        try s.addAddress(i, subnet.gateway(), subnet.prefix);
        try s.up(i);
    }

    /// Makes the veth pair of slot `n`, its job's end in the namespace `netns` (a file
    /// descriptor) and named `eth0` there, its host's end on the bridge, isolated
    /// (`IFLA_BRPORT_ISOLATED`: the bridge forwards nothing between two isolated ports, so one
    /// job cannot reach another's address), and up.
    pub fn addVeth(s: *Socket, slot: u32, netns: linux.fd_t) !void {
        var buf: [16]u8 = undefined;
        const host = hostLink(&buf, slot);
        var m: Message = .init(.RTM_NEWLINK, linux.NLM_F_CREATE | linux.NLM_F_EXCL);
        m.ifinfo(0, 0);
        m.attrString(ifla_ifname, host);
        const info = m.begin(ifla_linkinfo);
        m.attrString(ifla_info_kind, "veth");
        const data = m.begin(ifla_info_data);
        const peer = m.begin(veth_info_peer);
        m.ifinfo(0, 0);
        m.attrString(ifla_ifname, "eth0");
        m.attrU32(ifla_net_ns_fd, @intCast(netns));
        m.end(peer);
        m.end(data);
        m.end(info);
        try expect(s.request(&m), false);
        const i = s.index(host) orelse return error.NoVeth;
        const b = s.index(bridge) orelse return error.NoBridge;
        var master: Message = .init(.RTM_NEWLINK, 0);
        master.ifinfo(i, 0);
        master.attrU32(ifla_master, @intCast(b));
        try expect(s.request(&master), false);
        var iso: Message = .init(.RTM_SETLINK, 0);
        iso.put(IfInfoMsg, .{ .family = af_bridge, .index = i });
        const protinfo = iso.begin(ifla_protinfo | nla_f_nested);
        iso.attrBytes(ifla_brport_isolated, &.{1});
        iso.end(protinfo);
        try expect(s.request(&iso), false);
        try s.up(i);
    }

    /// Removes slot `n`'s veth pair (both ends go with the host's); none there is no error.
    pub fn deleteVeth(s: *Socket, slot: u32) void {
        var buf: [16]u8 = undefined;
        const i = s.index(hostLink(&buf, slot)) orelse return;
        var m: Message = .init(.RTM_DELLINK, 0);
        m.ifinfo(i, 0);
        _ = s.request(&m);
    }

    /// Inside a job's namespace: `lo` and `eth0` up, `eth0` with slot `n`'s address, and the
    /// default route through the bridge.
    pub fn configureJob(s: *Socket, subnet: Subnet, slot: u32) !void {
        try s.up(s.index("lo") orelse return error.NoLoopback);
        const eth = s.index("eth0") orelse return error.NoVeth;
        try s.addAddress(eth, subnet.jobAddress(slot), subnet.prefix);
        try s.up(eth);
        var m: Message = .init(.RTM_NEWROUTE, linux.NLM_F_CREATE | linux.NLM_F_EXCL);
        m.put(RtMsg, .{});
        const gw = subnet.gateway();
        m.attrBytes(rta_gateway, &gw);
        try expect(s.request(&m), false);
    }

    fn addAddress(s: *Socket, i: i32, addr: [4]u8, prefix: u8) !void {
        var m: Message = .init(.RTM_NEWADDR, linux.NLM_F_CREATE | linux.NLM_F_EXCL);
        m.put(IfAddrMsg, .{ .index = @intCast(i), .prefixlen = prefix });
        m.attrBytes(ifa_local, &addr);
        m.attrBytes(ifa_address, &addr);
        try expect(s.request(&m), true);
    }

    fn up(s: *Socket, i: i32) !void {
        var m: Message = .init(.RTM_NEWLINK, 0);
        m.ifinfo(i, iff_up);
        try expect(s.request(&m), false);
    }
};

fn expect(e: linux.E, exist_ok: bool) !void {
    if (e == .SUCCESS or (exist_ok and e == .EXIST)) return;
    std.log.debug("rtnetlink: {s}", .{@tagName(e)});
    return error.Netlink;
}

const ifla_ifname = 3;
const ifla_master = 10;
const ifla_protinfo = 12;
const ifla_brport_isolated = 33;
const nla_f_nested = 0x8000;
const af_bridge = 7;
const ifla_linkinfo = 18;
const ifla_net_ns_fd = 28;
const ifla_info_kind = 1;
const ifla_info_data = 2;
const veth_info_peer = 1;
const ifa_address = 1;
const ifa_local = 2;
const rta_gateway = 5;
const iff_up = 1;

const IfInfoMsg = extern struct {
    family: u8 = 0,
    pad: u8 = 0,
    type: u16 = 0,
    index: i32 = 0,
    flags: u32 = 0,
    change: u32 = 0,
};

const IfAddrMsg = extern struct {
    family: u8 = linux.AF.INET,
    prefixlen: u8,
    flags: u8 = 0,
    scope: u8 = 0,
    index: u32,
};

/// A default route in the main table, as `ip route add default via ...` sends it.
const RtMsg = extern struct {
    family: u8 = linux.AF.INET,
    dst_len: u8 = 0,
    src_len: u8 = 0,
    tos: u8 = 0,
    table: u8 = 254,
    protocol: u8 = 3,
    scope: u8 = 0,
    type: u8 = 1,
    flags: u32 = 0,
};

/// One netlink request being built: a header, a fixed part, then attributes, nested ones with
/// `begin` and `end`.
const Message = struct {
    buf: [1024]u8 align(4) = undefined,
    len: usize = @sizeOf(linux.nlmsghdr),
    type: linux.NetlinkMessageType,
    flags: u16,

    fn init(t: linux.NetlinkMessageType, flags: u16) Message {
        return .{ .type = t, .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK | flags };
    }

    fn put(m: *Message, comptime T: type, v: T) void {
        const bytes = std.mem.asBytes(&v);
        @memcpy(m.buf[m.len..][0..bytes.len], bytes);
        m.len = std.mem.alignForward(usize, m.len + bytes.len, 4);
    }

    fn ifinfo(m: *Message, i: i32, flags: u32) void {
        m.put(IfInfoMsg, .{ .index = i, .flags = flags, .change = if (flags != 0) flags else 0 });
    }

    fn attrBytes(m: *Message, t: u16, data: []const u8) void {
        const hdr: linux.rtattr = .{
            .len = @intCast(@sizeOf(linux.rtattr) + data.len),
            .type = .{ .link = @fromBackingInt(@intCast(t)) },
        };
        @memcpy(m.buf[m.len..][0..@sizeOf(linux.rtattr)], std.mem.asBytes(&hdr));
        @memcpy(m.buf[m.len + @sizeOf(linux.rtattr) ..][0..data.len], data);
        m.len = std.mem.alignForward(usize, m.len + hdr.len, 4);
    }

    fn attrString(m: *Message, t: u16, s: []const u8) void {
        var term: [32]u8 = @splat(0);
        @memcpy(term[0..s.len], s);
        m.attrBytes(t, term[0 .. s.len + 1]);
    }

    fn attrU32(m: *Message, t: u16, v: u32) void {
        m.attrBytes(t, std.mem.asBytes(&v));
    }

    fn begin(m: *Message, t: u16) usize {
        const at = m.len;
        m.attrBytes(t, &.{});
        return at;
    }

    fn end(m: *Message, at: usize) void {
        const len: u16 = @intCast(m.len - at);
        @memcpy(m.buf[at..][0..2], std.mem.asBytes(&len));
    }

    fn finish(m: *Message, seq: u32) void {
        const h: linux.nlmsghdr = .{
            .len = @intCast(m.len),
            .type = m.type,
            .flags = m.flags,
            .seq = seq,
            .pid = 0,
        };
        @memcpy(m.buf[0..@sizeOf(linux.nlmsghdr)], std.mem.asBytes(&h));
    }
};

/// What the runner needs from the host for its jobs' traffic to leave, and nothing more:
///
/// - IPv4 forwarding on. It is host-wide and stays on (other runners' jobs need it too); the
///   runner says so in its log when it turns it on, and warns when the host's FORWARD policy would
///   then route for anyone (ACCEPT, or no filter at all).
/// - The jobs' rules, over nftables netlink (`nft.zig`): their addresses masqueraded on the way
///   out; from `zr0` nothing into the host but replies, and nothing forwarded but out through the
///   host's uplinks (the interfaces of its default routes), so never to another job, to Docker's
///   containers or to the host's other networks; to `zr0` replies only. The host's iptables-nft
///   `FORWARD` and `DOCKER-USER` chains (Docker's and ufw's, whose policies drop) accept the
///   bridge's traffic and leave the deciding to the runner's table.
/// - To `zr0` from the host's own processes (`OUTPUT`), replies only, as routed traffic to it:
///   nothing reaches a job that the job did not ask for, its services' ports included (P6).
///
/// On failure, what went wrong.
pub fn natRules(
    arena: Allocator,
    io: std.Io,
    subnet: Subnet,
    ups: []const []const u8,
) !?[]const u8 {
    if (ups.len == 0) return "the host has no default route for the jobs' traffic to leave by";
    const cwd = std.Io.Dir.cwd();
    const fwd_path = "/proc/sys/net/ipv4/ip_forward";
    const fwd = readProc(arena, io, fwd_path) orelse "0";
    if (!std.mem.startsWith(u8, fwd, "1")) {
        cwd.writeFile(io, .{ .sub_path = fwd_path, .data = "1" }) catch |e|
            return try std.fmt.allocPrint(arena, "cannot turn on IPv4 forwarding: {s}", .{
                @errorName(e),
            });
        std.log.warn("native: turned on IPv4 forwarding (net.ipv4.ip_forward=1, host-wide) for " ++
            "the jobs' NAT; it stays on (docs/native-backend.md)", .{});
    }
    if (nft.forwardPolicy() != .drop)
        std.log.warn("native: the host's FORWARD policy is ACCEPT (or it has no filter), so " ++
            "with IPv4 forwarding on it routes for its neighbours; set it to DROP (the jobs' " ++
            "traffic has rules of its own)", .{});
    // Rules made with iptables-legacy are not nftables': a legacy FORWARD policy of DROP would
    // drop the jobs' traffic past the runner's accepts.
    const legacy = readProc(arena, io, "/proc/net/ip_tables_names") orelse "";
    if (std.mem.indexOf(u8, legacy, "filter") != null)
        std.log.warn("native: this host has iptables-legacy tables (/proc/net/ip_tables_names), " ++
            "which the jobs' nftables rules do not reach; a legacy FORWARD policy of DROP " ++
            "would cut the jobs' traffic", .{});
    return nft.apply(subnet, ups);
}

/// The host's uplinks: the interfaces of its IPv4 default routes (`/proc/net/route`), the bridge
/// left out.
pub fn uplinks(arena: Allocator, io: std.Io) ![]const []const u8 {
    const text = routeTable(arena, io) orelse return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    var it = routes(text);
    while (it.next()) |r| {
        if (r.dest != 0 or r.mask != 0 or std.mem.eql(u8, r.iface, bridge)) continue;
        for (out.items) |o| {
            if (std.mem.eql(u8, o, r.iface)) break;
        } else try out.append(arena, try arena.dupe(u8, r.iface));
    }
    return out.items;
}

/// Why the jobs' subnet cannot be used here: a route of the host's (an interface's network,
/// Docker's or podman's bridge, a VPN) other than the bridge's covers some of it. Null when none
/// does. Default routes are left out: everything overlaps them.
pub fn subnetClash(arena: Allocator, io: std.Io, subnet: Subnet) !?[]const u8 {
    return clashIn(arena, routeTable(arena, io) orelse return null, subnet);
}

fn routeTable(arena: Allocator, io: std.Io) ?[]const u8 {
    return readProc(arena, io, "/proc/net/route");
}

/// A /proc file's contents, read to its end (up to 1 MiB): /proc reports its files' sizes as 0,
/// so a read sized by `stat` (`readFileAlloc`) gets nothing.
pub fn readProc(arena: Allocator, io: std.Io, path: []const u8) ?[]const u8 {
    const f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer f.close(io);
    var out: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (out.items.len < 1 << 20) {
        const n = f.readStreaming(io, &.{&buf}) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return null,
        };
        if (n == 0) break;
        out.appendSlice(arena, buf[0..n]) catch return null;
    }
    return out.items;
}

fn clashIn(arena: Allocator, text: []const u8, subnet: Subnet) !?[]const u8 {
    var it = routes(text);
    while (it.next()) |r| {
        if (r.mask == 0 or std.mem.eql(u8, r.iface, bridge)) continue;
        if (subnet.overlaps(r.dest, r.mask)) return try std.fmt.allocPrint(arena, "the jobs' " ++
            "subnet {f} (RUNNER_NATIVE_SUBNET) overlaps a route on {s}", .{ subnet, r.iface });
    }
    return null;
}

/// The lines of `/proc/net/route`: an interface, then its destination and mask as the kernel
/// prints a network-order address, in hex of the host's byte order.
fn routes(text: []const u8) RouteIterator {
    var lines = std.mem.splitScalar(u8, text, '\n');
    _ = lines.next();
    return .{ .lines = lines };
}

const Route = struct { iface: []const u8, dest: u32, mask: u32 };

const RouteIterator = struct {
    lines: std.mem.SplitIterator(u8, .scalar),

    fn next(it: *RouteIterator) ?Route {
        while (it.lines.next()) |line| {
            var f = std.mem.tokenizeAny(u8, line, " \t");
            var cols: [8][]const u8 = undefined;
            var n: usize = 0;
            while (f.next()) |c| : (n += 1) {
                if (n == cols.len) break;
                cols[n] = c;
            }
            if (n < cols.len) continue;
            const dest = std.fmt.parseInt(u32, cols[1], 16) catch continue;
            const mask = std.fmt.parseInt(u32, cols[7], 16) catch continue;
            return .{ .iface = cols[0], .dest = fromRouteHex(dest), .mask = fromRouteHex(mask) };
        }
        return null;
    }
};

/// An address as `/proc/net/route` prints it (a network-order word read in the host's order) in
/// host order.
fn fromRouteHex(v: u32) u32 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, builtin.cpu.arch.endian());
    return std.mem.readInt(u32, &b, .big);
}

/// The resolver a job's steps get: its own namespace cannot reach a resolver on the host's
/// loopback (systemd-resolved's 127.0.0.53), so the upstream servers systemd-resolved lists, or
/// the host's /etc/resolv.conf when it names no loopback server. Null when neither will do.
pub fn resolvConf(arena: Allocator, io: std.Io) ?[]const u8 {
    for ([_][]const u8{ "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf" }) |p| {
        const text = std.Io.Dir.cwd().readFileAlloc(io, p, arena, .limited(64 * 1024)) catch
            continue;
        if (namesOnlyReachable(text)) return p;
    }
    return null;
}

/// Whether a resolv.conf names at least one nameserver, and none on the loopback.
pub fn namesOnlyReachable(text: []const u8) bool {
    var any = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        var words = std.mem.tokenizeAny(u8, raw, " \t");
        const key = words.next() orelse continue;
        if (!std.mem.eql(u8, key, "nameserver")) continue;
        const addr = words.next() orelse continue;
        if (std.mem.startsWith(u8, addr, "127.") or std.mem.eql(u8, addr, "::1")) return false;
        any = true;
    }
    return any;
}

test "a resolv.conf for a job's namespace names no loopback server" {
    try std.testing.expect(!namesOnlyReachable("nameserver 127.0.0.53\noptions edns0\n"));
    try std.testing.expect(namesOnlyReachable("# upstream\nnameserver 1.1.1.1\n" ++
        "nameserver 8.8.8.8\n"));
    try std.testing.expect(!namesOnlyReachable("search example.com\n"));
    try std.testing.expect(!namesOnlyReachable("nameserver 10.0.0.2\nnameserver ::1\n"));
}

test "slots' addresses and links" {
    const sub = Subnet.default;
    try std.testing.expectEqual([4]u8{ 10, 211, 0, 1 }, sub.gateway());
    try std.testing.expectEqual([4]u8{ 10, 211, 1, 2 }, sub.jobAddress(0));
    try std.testing.expectEqual([4]u8{ 10, 211, 1, 251 }, sub.jobAddress(249));
    const small = try Subnet.parse("192.168.64.0/23");
    try std.testing.expectEqual([4]u8{ 192, 168, 65, 251 }, small.jobAddress(max_slots - 1));
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("zrh7", hostLink(&buf, 7));
}

test "the jobs' subnet: what parses, and a clash with the host's routes" {
    try std.testing.expectEqual(Subnet.default, try Subnet.parse(Subnet.default_text));
    var text: [32]u8 = undefined;
    const printed = try std.fmt.bufPrint(&text, "{f}", .{Subnet.default});
    try std.testing.expectEqualStrings(Subnet.default_text, printed);
    const bad = [_][]const u8{
        "10.211.0.0",      "10.211.0.1/16", "10.211.0.0/24", "10.211.0.0/7", "10.211.0/16",
        "10.211.0.0.0/16", "10.256.0.0/16", "10.211.0.0/x",  "",
    };
    for (bad) |b| try std.testing.expectError(error.InvalidNativeSubnet, Subnet.parse(b));
    // podman's 10.88.0.0/16 and Docker's 172.17.0.0/16 on a little-endian host, a default route,
    // and the bridge's own route.
    const table =
        \\Iface Destination Gateway  Flags RefCnt Use Metric Mask  MTU Window IRTT
        \\wlp0s20f3 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0
        \\podman0 0000580A 00000000 0001 0 0 0 0000FFFF 0 0 0
        \\docker0 000011AC 00000000 0001 0 0 0 0000FFFF 0 0 0
        \\zr0 0000D30A 00000000 0001 0 0 0 0000FFFF 0 0 0
        \\
    ;
    if (builtin.cpu.arch.endian() != .little) return;
    const a = std.testing.allocator;
    try std.testing.expect(try clashIn(a, table, Subnet.default) == null);
    const podman = (try clashIn(a, table, try Subnet.parse("10.88.0.0/16"))).?;
    defer a.free(podman);
    try std.testing.expect(std.mem.indexOf(u8, podman, "podman0") != null);
    // A wider subnet covering Docker's.
    const wide = (try clashIn(a, table, try Subnet.parse("172.16.0.0/12"))).?;
    defer a.free(wide);
    try std.testing.expect(std.mem.indexOf(u8, wide, "docker0") != null);
    var it = routes(table);
    try std.testing.expectEqualStrings("wlp0s20f3", it.next().?.iface);
    // The real table, read whole although /proc says it is empty: at least its header.
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const real = readProc(arena.allocator(), std.testing.io, "/proc/net/route").?;
    try std.testing.expect(std.mem.startsWith(u8, real, "Iface"));
}
