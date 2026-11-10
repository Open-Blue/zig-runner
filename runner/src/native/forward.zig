//! A native job's published service ports (docs/native-backend.md, P6): `ports: ['15432:5432']`
//! makes `localhost:15432` in the job's steps reach the service's 5432, as a job on GitHub's
//! runner reaches a container's published port. The steps and the services share the job's
//! network namespace, so a port published as itself (`5432:5432`, `6379`) needs nothing: the
//! service listens on the job's loopback already. Only a port published under another number
//! needs this, a small TCP relay of the runner's own in the job's namespace, where the Dagger
//! path runs busybox's `tcpsvd` and `nc` in every step.
//!
//! It is a helper (`zig-runner native-forward`), as the job's network is made by one: a thread of
//! the runner must not change its namespace. Its spec is one line of JSON on stdin, which then
//! stays open as its lifeline; it prints `ready` once it listens. On a root runner it joins the
//! job's namespace as the host's root, binds, and then becomes the job's `nobody` (a host id of
//! the job's range, no capabilities, no_new_privs, the steps' seccomp filter) before it reads a
//! byte of the job's traffic. It runs in the host's mount namespace, so the filter keeps a bug in
//! it to the calls Docker allows a container.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox.zig");

const Allocator = std.mem.Allocator;

/// The helper's subcommand (`main.zig` dispatches it).
pub const command = "native-forward";

pub const Spec = struct {
    /// The job's network namespace file; null rootless, where the job has none.
    netns: ?[]const u8 = null,
    /// Root runner: the host id the relay runs as once it listens.
    id: ?u32 = null,
    /// The job's cgroup (P4), joined first: the relay is held to the job's limits and killed
    /// with it.
    cgroup: ?[]const u8 = null,
    ports: []const Map,
    /// A job container's `ports:` (`publish.zig`): each listener is made in the runner's own
    /// network namespace on `Map.address` before the helper joins the job's, where it connects to
    /// the job's port on its loopback. Otherwise (a service's published port) the listeners are on
    /// the job's loopback.
    publish: bool = false,
    /// Published: the host ports a kernel pick must not land on (the runner's own endpoints).
    reserved: []const u16 = &.{},
    /// Published beyond the host's loopback: the runner's jobs' subnet, whose peers are refused,
    /// as are those on the host's bridges (`Guard`).
    guard: ?GuardSpec = null,

    /// The relay's timeouts; tests shorten them.
    limits: Limits = .{},

    pub const Map = struct {
        /// 0 when published: the kernel picks one, which the ready line says.
        host: u16,
        container: u16,
        /// Where a published port listens on the host.
        address: [4]u8 = .{ 127, 0, 0, 1 },
        /// A published UDP port: datagrams relayed per client (`Assoc`).
        udp: bool = false,
    };

    pub const GuardSpec = struct { subnet: [4]u8, prefix: u8 };

    pub const Limits = struct {
        /// A connection to the job's port that has not completed in this long is given up: the
        /// connect is non-blocking, so one the job's full backlog holds never stalls the others.
        connect_ms: u64 = 10_000,
        /// A connection with no byte either way for this long is closed; 0 never closes one for
        /// that (`RUNNER_NATIVE_PORT_IDLE_TIMEOUT`). Even then the slots bound the relay: when all
        /// `max_conns` are in use a newcomer takes the place of the one quiet longest once it has
        /// been quiet `evict_idle_ms`, so idle connections cannot hold resources without limit.
        idle_ms: u64 = 300_000,
        /// How long a connection must have been quiet before a newcomer may take its place.
        evict_idle_ms: u64 = 10_000,
    };
};

/// Connections relayed at once. A newcomer past it takes the place of the one quiet longest, once
/// that one has been quiet `Limits.evict_idle_ms`; until then it is closed. So connections held open and
/// silent cannot lock out the rest.
const max_conns = 64;
/// The most ports one helper publishes (`publish.zig` refuses more).
pub const max_published = 64;
const buf_len = 16 * 1024;
/// New UDP clients taken per second; datagrams from more new ones in that second are dropped, so
/// a flood of sources cannot churn the relay's sockets.
const max_new_assocs_per_s = 32;

/// The helper's entry. Exits 0 when its lifeline closes, 1 with why on stderr when it cannot
/// listen.
pub fn main(arena: Allocator) u8 {
    var rest: std.ArrayList(u8) = .empty;
    const spec = sandbox.readJsonLine(Spec, arena, &rest) catch
        sandbox.fatal("read the relay's spec", @as(u32, 22));
    if (spec.cgroup) |dir| sandbox.joinCgroup(arena, dir);
    // Published from the host: listening in the runner's network namespace, then into the job's,
    // where every connection to the job's port is made. A socket stays in the namespace it was
    // made in, so the listeners are the host's and the connections the job's.
    if (!spec.publish) joinNetns(arena, spec.netns);
    // The host's routes, opened while the helper is in the host's network: a file of /proc/net
    // stays its namespace's, so `Guard` reads the host's bridges from it later.
    var guard: ?Guard = if (spec.publish) if (spec.guard) |g| .{
        .route = openRoute(),
        .subnet = g.subnet,
        .prefix = g.prefix,
    } else null else null;
    var listeners: std.ArrayList(Listener) = .empty;
    var ready: std.ArrayList(u8) = .empty;
    ready.appendSlice(arena, "ready") catch sandbox.oom();
    for (spec.ports) |m| {
        if (spec.publish) {
            const got = publishOne(m, spec.reserved, HostSockets{});
            const pair = switch (got) {
                .ok => |p| p,
                .taken => |v6| {
                    const what = if (v6)
                        std.fmt.allocPrint(arena, "publish [::1]:{d}/{s}", .{ m.host, if (m.udp) "udp" else "tcp" }) catch "publish a port"
                    else
                        std.fmt.allocPrint(arena, "publish {d}.{d}.{d}.{d}:{d}/{s}", .{
                            m.address[0],                m.address[1], m.address[2], m.address[3], m.host,
                            if (m.udp) "udp" else "tcp",
                        }) catch "publish a port";
                    sandbox.fatal(what, @as(u32, 98));
                },
            };
            const guarded = guard != null and m.address[0] != 127;
            listeners.append(arena, .{ .fd = pair.v4, .to = m.container, .udp = m.udp, .guarded = guarded }) catch sandbox.oom();
            if (pair.v6) |fd| listeners.append(arena, .{ .fd = fd, .to = m.container, .udp = m.udp, .v6 = true }) catch sandbox.oom();
            ready.print(arena, " {d}", .{boundPort(pair.v4)}) catch sandbox.oom();
            continue;
        }
        const v4 = listen(m.host, false) orelse {
            const what = sandbox.about(arena, "listen on 127.0.0.1 port", portText(arena, m.host));
            sandbox.fatal(what, @as(u32, 98));
        };
        listeners.append(arena, .{ .fd = v4, .to = m.container }) catch sandbox.oom();
        // ::1 too, as the Dagger path forwards it, where the namespace has IPv6.
        const v6 = listen(m.host, true) orelse continue;
        listeners.append(arena, .{ .fd = v6, .to = m.container, .v6 = true }) catch sandbox.oom();
    }
    if (spec.publish) joinNetns(arena, spec.netns);
    ready.append(arena, '\n') catch sandbox.oom();
    if (spec.id) |id| {
        sandbox.check("setgroups", linux.setgroups(0, sandbox.no_groups));
        sandbox.check("setresgid", linux.setresgid(id, id, id));
        sandbox.check("setresuid", linux.setresuid(id, id, id));
    }
    sandbox.check("no_new_privs", linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    // Docker's allow list, as each step has it: after no_new_privs, which an unprivileged
    // filter needs, and before any of the job's traffic.
    sandbox.installSeccomp();
    _ = linux.write(1, ready.items.ptr, ready.items.len);
    relay(arena, listeners.items, if (guard) |*g| g else null, spec.limits);
    return 0;
}

/// Into the job's network namespace, when it has one (a rootless job has none).
fn joinNetns(arena: Allocator, netns: ?[]const u8) void {
    const p = netns orelse return;
    const rc = linux.open(sandbox.z(arena, p), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    sandbox.check("open the job's network namespace", rc);
    const fd = std.math.cast(linux.fd_t, rc) orelse sandbox.fatal("open the job's network namespace", @as(u32, 9));
    sandbox.check("enter the job's network namespace", linux.setns(fd, linux.CLONE.NEWNET));
    _ = linux.close(fd);
}

fn portText(arena: Allocator, port: u16) []const u8 {
    return std.fmt.allocPrint(arena, "{d}", .{port}) catch "?";
}

const Listener = struct {
    fd: linux.fd_t,
    to: u16,
    udp: bool = false,
    /// Its peers are IPv6 (it is on `::1`).
    v6: bool = false,
    /// Published beyond the host's loopback: each peer is checked (`Guard`).
    guarded: bool = false,
};

/// A published port's sockets: IPv4 on its address, and on `::1` too when that is 127.0.0.1 and
/// the host has IPv6, so a client that resolves `localhost` to `::1` reaches it as on Docker.
const Pair = struct { v4: linux.fd_t, v6: ?linux.fd_t = null };

/// `m` listened on, or which of its sockets was taken (true: `::1`'s). A port the kernel picks is
/// picked again when it lands on one of `reserved` (the runner's own) or its `::1` is taken.
/// `sockets` makes them (`HostSockets`; a test fakes the binds).
fn publishOne(m: Spec.Map, reserved: []const u16, sockets: anytype) union(enum) { ok: Pair, taken: bool } {
    for (0..16) |_| {
        const v4 = sockets.listen4(m.address, m.host, m.udp) orelse return .{ .taken = false };
        const port = sockets.boundTo(v4);
        if (m.host == 0 and std.mem.indexOfScalar(u16, reserved, port) != null) {
            sockets.close(v4);
            continue;
        }
        if (m.address[0] != 127) return .{ .ok = .{ .v4 = v4 } };
        switch (sockets.listen6(port, m.udp)) {
            .fd => |fd| return .{ .ok = .{ .v4 = v4, .v6 = fd } },
            .off => return .{ .ok = .{ .v4 = v4 } },
            .taken => {
                sockets.close(v4);
                if (m.host != 0) return .{ .taken = true };
            },
        }
    }
    return .{ .taken = false };
}

/// The host's sockets, as `publishOne` makes them.
const HostSockets = struct {
    fn listen4(_: HostSockets, address: [4]u8, port: u16, udp: bool) ?linux.fd_t {
        return listenOn(address, port, udp);
    }
    fn boundTo(_: HostSockets, fd: linux.fd_t) u16 {
        return boundPort(fd);
    }
    fn listen6(_: HostSockets, port: u16, udp: bool) Loopback6 {
        return listenLoopback6(port, udp);
    }
    fn close(_: HostSockets, fd: linux.fd_t) void {
        _ = linux.close(fd);
    }
};

const Loopback6 = union(enum) { fd: linux.fd_t, off, taken };

/// A socket on `[::1]:port`, listening for TCP or bound for UDP; `off` where the host has no
/// IPv6 (no AF_INET6, or no `::1`), `taken` when another process holds it.
fn listenLoopback6(port: u16, udp: bool) Loopback6 {
    const sock: u32 = if (udp) linux.SOCK.DGRAM else linux.SOCK.STREAM;
    const rc = linux.socket(linux.AF.INET6, sock | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return .off;
    const fd = std.math.cast(linux.fd_t, rc) orelse return .off;
    const one: i32 = 1;
    const ipv6_v6only = 26;
    _ = linux.setsockopt(fd, linux.IPPROTO.IPV6, ipv6_v6only, std.mem.asBytes(&one), 4);
    if (!udp) _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&one), 4);
    var sa = loopback6(port);
    const bound = linux.errno(linux.bind(fd, asSockaddr6(&sa), @sizeOf(linux.sockaddr.in6)));
    if (bound == .SUCCESS and (udp or linux.errno(linux.listen(fd, 128)) == .SUCCESS)) return .{ .fd = fd };
    _ = linux.close(fd);
    return if (bound == .ADDRINUSE) .taken else .off;
}

/// A socket of the host's on `address:port` (0: one the kernel picks), listening for TCP or
/// bound for UDP, or null when it cannot be (the port is taken, the address is not the host's).
fn listenOn(address: [4]u8, port: u16, udp: bool) ?linux.fd_t {
    const sock: u32 = if (udp) linux.SOCK.DGRAM else linux.SOCK.STREAM;
    const kind = sock | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const rc = linux.socket(linux.AF.INET, kind, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    const one: i32 = 1;
    if (!udp) _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&one), 4);
    var sa = inet4(address, port);
    const bound = linux.errno(linux.bind(fd, asSockaddr(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS;
    if (!bound or (!udp and linux.errno(linux.listen(fd, 128)) != .SUCCESS)) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

/// An IPv4 address as the socket calls take it: the one cast this file's sockets need.
pub fn asSockaddr(sa: *linux.sockaddr.in) *linux.sockaddr {
    return @ptrCast(sa);
}

fn asSockaddr6(sa: *linux.sockaddr.in6) *linux.sockaddr {
    return @ptrCast(sa);
}

fn inet4(address: [4]u8, port: u16) linux.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, std.mem.readInt(u32, &address, .big)),
    };
}

/// The port `fd` is bound to: the kernel's pick for port 0.
fn boundPort(fd: linux.fd_t) u16 {
    var sa: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, asSockaddr(&sa), &len)) != .SUCCESS) return 0;
    return std.mem.bigToNative(u16, sa.port);
}

/// A listening socket on the loopback (`::1` for `v6`, which may be missing: null then).
fn listen(port: u16, v6: bool) ?linux.fd_t {
    const family: u32 = if (v6) linux.AF.INET6 else linux.AF.INET;
    const kind = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const rc = linux.socket(family, kind, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: linux.fd_t = @intCast(rc);
    const one: i32 = 1;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&one), 4);
    const ok = if (v6) ok: {
        const ipv6_v6only = 26;
        _ = linux.setsockopt(fd, linux.IPPROTO.IPV6, ipv6_v6only, std.mem.asBytes(&one), 4);
        var sa = loopback6(port);
        const rc6 = linux.bind(fd, asSockaddr6(&sa), @sizeOf(linux.sockaddr.in6));
        break :ok linux.errno(rc6) == .SUCCESS;
    } else ok: {
        var sa = loopback4(port);
        const rc4 = linux.bind(fd, asSockaddr(&sa), @sizeOf(linux.sockaddr.in));
        break :ok linux.errno(rc4) == .SUCCESS;
    };
    if (!ok or linux.errno(linux.listen(fd, 128)) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

fn loopback4(port: u16) linux.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
}

fn loopback6(port: u16) linux.sockaddr.in6 {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .scope_id = 0,
    };
}

/// The host's IPv4 routes, `/proc/self/net/route` of the namespace the helper is in now; -1
/// when it cannot be read, which refuses every peer beyond loopback (`Guard.allows`).
fn openRoute() linux.fd_t {
    const rc = linux.open("/proc/self/net/route", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    return std.math.cast(linux.fd_t, rc) orelse -1;
}

/// Who may reach a port published beyond the host's loopback: not the runner's own jobs (their
/// subnet; the runner's table drops them at the bridge already) and not a container or VM of the
/// host's (on Docker's bridge, the Dagger engine's, a Dagger-fallback job's, a veth routed to as
/// Calico's are, a tap as Firecracker's): those are local, and not the host's to let in through a
/// trusted job's port. The host's links are read from its routes on each such peer, so one made
/// since the job started is refused too.
pub const Guard = struct {
    route: linux.fd_t,
    subnet: [4]u8,
    prefix: u8,
    /// Whether an interface leads to the host's own containers or VMs (tests give their own).
    local: *const fn ([]const u8) bool = isLocal,
    buf: [32 * 1024]u8 = undefined,
    /// UDP peers' verdicts (`allowsCached`).
    verdicts: [max_verdicts]Verdict = @splat(.{}),

    const Verdict = struct { peer: [4]u8 = @splat(0), port: u16 = 0, ok: bool = false, until: u64 = 0 };

    pub fn allows(g: *Guard, peer: [4]u8) bool {
        if (peer[0] == 127) return true;
        if (inSubnet(peer, g.subnet, g.prefix)) return false;
        if (g.route < 0) return false;
        const n = linux.pread(g.route, &g.buf, g.buf.len, 0);
        if (linux.errno(n) != .SUCCESS or n == g.buf.len) return false;
        return !onLocal(g.buf[0..n], peer, g.local);
    }

    /// `allows`, its verdict on `peer:port` kept `verdict_ms`: a UDP client's datagrams are not
    /// each a read of the routes, and a route changed still counts within the second. The verdict
    /// that expires first makes way when all are in use.
    pub fn allowsCached(g: *Guard, peer: [4]u8, port: u16, now: u64) bool {
        var slot = &g.verdicts[0];
        for (&g.verdicts) |*v| {
            if (v.until > now and v.port == port and std.mem.eql(u8, &v.peer, &peer)) return v.ok;
            if (v.until < slot.until) slot = v;
        }
        const ok = g.allows(peer);
        slot.* = .{ .peer = peer, .port = port, .ok = ok, .until = now + verdict_ms };
        return ok;
    }
};

/// The UDP peers whose verdict the guard keeps (`Guard.allowsCached`), and for how long.
const max_verdicts = max_assocs;
const verdict_ms = 1000;

fn inSubnet(a: [4]u8, base: [4]u8, prefix: u8) bool {
    if (prefix == 0) return true;
    const shift: u5 = @truncate(32 - @as(u32, @min(prefix, 32)));
    const mask: u32 = if (prefix >= 32) 0xffff_ffff else ~@as(u32, 0) << shift;
    return std.mem.readInt(u32, &a, .big) & mask == std.mem.readInt(u32, &base, .big) & mask;
}

/// Whether `peer` is reached directly (no gateway) through a link of `route`'s
/// (`/proc/net/route`'s text) that `local` says is the host's own containers' or VMs'. Lines that
/// cannot be read count as no link's.
pub fn onLocal(route: []const u8, peer: [4]u8, local: *const fn ([]const u8) bool) bool {
    var lines = std.mem.splitScalar(u8, route, '\n');
    _ = lines.next();
    const want = std.mem.readInt(u32, &peer, .little);
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const iface = f.next() orelse continue;
        const dest = std.fmt.parseInt(u32, f.next() orelse continue, 16) catch continue;
        const gw = std.fmt.parseInt(u32, f.next() orelse continue, 16) catch continue;
        const flags = std.fmt.parseInt(u32, f.next() orelse continue, 16) catch continue;
        for (0..3) |_| _ = f.next();
        const mask = std.fmt.parseInt(u32, f.next() orelse continue, 16) catch continue;
        // Up, no gateway (directly connected), and not the default route.
        if (flags & 1 == 0 or gw != 0 or mask == 0) continue;
        if (want & mask != dest & mask) continue;
        if (local(iface)) return true;
    }
    return false;
}

/// The host's interfaces: sysfs is the host's network's, as the helper stays in the host's mount
/// namespace.
fn isLocal(name: []const u8) bool {
    return isLocalAt("/sys/class/net", name);
}

/// Whether the interface `name` of `sys` (a `/sys/class/net`) leads to the host's own containers
/// or VMs rather than its LAN: a bridge; a tun or tap (a VM's, Firecracker's, and a VPN's too);
/// or a link into another namespace, as a veth is (Calico routes each pod's /32 out of one): its
/// `iflink` is not its own `ifindex`, and it has no `lower_*` device (a VLAN or macvlan of the
/// LAN's NIC has one). A name or file that cannot be read counts as local.
pub fn isLocalAt(sys: []const u8, name: []const u8) bool {
    // Not a name the kernel gives an interface, nor one that leaves `sys`.
    if (name.len == 0 or name.len > 15 or std.mem.indexOfScalar(u8, name, '/') != null) return true;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return true;
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (sysExists(&buf, sys, name, "bridge") orelse return true) return true;
    if (sysExists(&buf, sys, name, "tun_flags") orelse return true) return true;
    const index = sysNumber(&buf, sys, name, "ifindex") orelse return true;
    const link = sysNumber(&buf, sys, name, "iflink") orelse return true;
    if (index == link) return false;
    return !(hasLower(&buf, sys, name) orelse false);
}

/// Whether `sys/name/file` exists; null when that cannot be told.
fn sysExists(buf: []u8, sys: []const u8, name: []const u8, file: []const u8) ?bool {
    const path = std.fmt.bufPrintSentinel(buf, "{s}/{s}/{s}", .{ sys, name, file }, 0) catch return null;
    return switch (linux.errno(linux.faccessat(linux.AT.FDCWD, path, linux.F_OK, 0))) {
        .SUCCESS => true,
        .NOENT => false,
        else => null,
    };
}

/// `sys/name/file`'s number (`ifindex`, `iflink`), or null.
fn sysNumber(buf: []u8, sys: []const u8, name: []const u8, file: []const u8) ?u32 {
    const path = std.fmt.bufPrintSentinel(buf, "{s}/{s}/{s}", .{ sys, name, file }, 0) catch return null;
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    defer _ = linux.close(fd);
    var text: [32]u8 = undefined;
    const n = linux.read(fd, &text, text.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return std.fmt.parseInt(u32, std.mem.trim(u8, text[0..n], " \t\n"), 10) catch null;
}

/// Whether `sys/name` has a `lower_*` entry (a device of the host's it is stacked on); null when
/// its directory cannot be read.
fn hasLower(buf: []u8, sys: []const u8, name: []const u8) ?bool {
    const path = std.fmt.bufPrintSentinel(buf, "{s}/{s}", .{ sys, name }, 0) catch return null;
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    defer _ = linux.close(fd);
    var ents: [4096]u8 = undefined;
    while (true) {
        const n = linux.getdents64(fd, &ents, ents.len);
        if (linux.errno(n) != .SUCCESS) return null;
        if (n == 0) return false;
        // Each a `dirent64`: its length at `reclen`, its name from `name` to a NUL.
        const reclen = @offsetOf(linux.dirent64, "reclen");
        const name_at = @offsetOf(linux.dirent64, "name");
        var at: usize = 0;
        while (at + name_at < n) {
            const len = std.mem.readInt(u16, ents[at + reclen ..][0..2], .native);
            if (len <= name_at or at + len > n) return null;
            if (std.mem.startsWith(u8, std.mem.sliceTo(ents[at + name_at .. at + len], 0), "lower_")) return true;
            at += len;
        }
    }
}

/// The monotonic clock, in milliseconds.
fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const sec = std.math.cast(u64, ts.sec) orelse 0;
    const nsec = std.math.cast(u64, ts.nsec) orelse 0;
    return sec * 1000 + nsec / 1_000_000;
}

/// One direction of a connection: bytes read from one end, not yet written to the other.
const Pipe = struct {
    buf: [buf_len]u8 = undefined,
    start: usize = 0,
    end: usize = 0,
    /// The reading end said it is done; once drained, the writing end is shut for writing.
    eof: bool = false,
    shut: bool = false,

    fn pending(p: *const Pipe) bool {
        return p.end > p.start;
    }

    fn room(p: *Pipe) []u8 {
        if (p.start == p.end) {
            p.start = 0;
            p.end = 0;
        }
        return p.buf[p.end..];
    }
};

/// A relayed connection: `fds[0]` the step's, `fds[1]` the service's; `pipes[i]` carries what
/// `fds[i]` sends.
const Conn = struct {
    used: bool = false,
    fds: [2]linux.fd_t = .{ -1, -1 },
    pipes: [2]Pipe = .{ .{}, .{} },
    /// Its connect to the job's port is under way (non-blocking).
    connecting: bool = false,
    /// That connect is to `::1` (IPv4's was refused).
    v6: bool = false,
    to: u16 = 0,
    /// When a byte last went either way (or it was accepted), `nowMs`.
    last: u64 = 0,

    fn close(c: *Conn) void {
        for (c.fds) |fd| if (fd >= 0) {
            _ = linux.close(fd);
        };
        c.* = .{};
    }

    /// When it is given up: its connect's timeout, or its idle one (never, with none set).
    fn deadline(c: *const Conn, l: Spec.Limits) u64 {
        if (!c.connecting and l.idle_ms == 0) return std.math.maxInt(u64);
        return c.last + if (c.connecting) l.connect_ms else l.idle_ms;
    }
};

/// Until the lifeline closes: accepts, connects each to the service's port, and copies both
/// ways, each direction shut once its sender is done.
fn relay(arena: Allocator, listeners: []const Listener, guard: ?*Guard, limits: Spec.Limits) void {
    const conns = arena.alloc(Conn, max_conns) catch sandbox.oom();
    for (conns) |*c| c.* = .{};
    var udp: Udp = .{ .assocs = arena.alloc(Assoc, max_assocs) catch sandbox.oom(), .guard = guard };
    for (udp.assocs) |*s| s.* = .{};
    const nfds = 1 + listeners.len + 2 * max_conns + max_assocs;
    const fds = arena.alloc(linux.pollfd, nfds) catch sandbox.oom();
    while (true) {
        fds[0] = .{ .fd = 0, .events = linux.POLL.IN, .revents = 0 };
        for (listeners, fds[1..][0..listeners.len]) |l, *p|
            p.* = .{ .fd = l.fd, .events = linux.POLL.IN, .revents = 0 };
        const assoc_fds = fds[nfds - max_assocs ..];
        for (udp.assocs, assoc_fds) |s, *p|
            p.* = .{ .fd = if (s.used) s.fd else -1, .events = linux.POLL.IN, .revents = 0 };
        const conn_fds = fds[1 + listeners.len .. nfds - max_assocs];
        var next: ?u64 = null;
        for (conns, 0..) |*c, i| {
            if (c.used) next = @min(next orelse c.deadline(limits), c.deadline(limits));
            for (0..2) |side| {
                var ev: i16 = 0;
                var fd: linux.fd_t = if (c.used) c.fds[side] else -1;
                if (c.used and c.connecting) {
                    // Only the connect is waited on: the client's bytes wait in its socket.
                    if (side == 1) ev = linux.POLL.OUT else fd = -1;
                } else if (c.used) {
                    if (!c.pipes[side].eof and c.pipes[side].room().len > 0) ev |= linux.POLL.IN;
                    if (c.pipes[1 - side].pending()) ev |= linux.POLL.OUT;
                }
                conn_fds[2 * i + side] = .{ .fd = fd, .events = ev, .revents = 0 };
            }
        }
        const now = nowMs();
        const wait: i32 = if (next) |d| std.math.cast(i32, d -| now) orelse std.math.maxInt(i32) else -1;
        const rc = linux.poll(fds.ptr, nfds, wait);
        if (linux.errno(rc) == .INTR) continue;
        sandbox.check("wait for the relay's connections", rc);
        if (fds[0].revents != 0) return;
        const t = nowMs();
        for (listeners, fds[1..][0..listeners.len], 0..) |l, p, i| if (p.revents != 0) {
            if (l.udp) udp.fromClients(listeners, i, t) else accept(conns, l, guard, t, limits);
        };
        for (conns, 0..) |*c, i| if (c.used) {
            if (!step(c, conn_fds[2 * i ..][0..2], t, limits)) c.close();
        };
        for (udp.assocs, assoc_fds) |*s, p| if (s.used and p.revents != 0) udp.toClient(listeners, s);
    }
}

/// UDP clients relayed at once; past it, the one quiet longest is dropped for the newcomer.
const max_assocs = 64;

/// One UDP client of a published port: its address on the host, and the socket of the job's
/// that carries its datagrams to the job's port and the answers back.
const Assoc = struct {
    used: bool = false,
    listener: usize = 0,
    client: linux.sockaddr.in = undefined,
    /// A `::1` listener's client.
    client6: linux.sockaddr.in6 = undefined,
    is_v6: bool = false,
    fd: linux.fd_t = -1,
    /// When it was last heard from or answered, in the relay's own count.
    seen: u64 = 0,
};

const Udp = struct {
    assocs: []Assoc,
    guard: ?*Guard = null,
    clock: u64 = 0,
    /// The second (`nowMs` / 1000) new clients are being counted in, and how many came in it.
    second: u64 = 0,
    new_in_second: u32 = 0,
    buf: [64 * 1024]u8 = undefined,

    /// Every datagram waiting on listener `i`, each sent on by its client's socket in the job's
    /// network (made on its first datagram, connected to the job's port on the loopback).
    fn fromClients(u: *Udp, listeners: []const Listener, i: usize, now: u64) void {
        const l = listeners[i];
        // A `::1` listener's clients have IPv6 addresses.
        if (l.v6) return u.fromClients6(listeners, i, now);
        while (true) {
            var from: linux.sockaddr.in = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const n = linux.recvfrom(l.fd, &u.buf, u.buf.len, 0, asSockaddr(&from), &len);
            if (linux.errno(n) != .SUCCESS) return;
            if (l.guarded) if (u.guard) |g| if (!g.allowsCached(peerOf(from), from.port, now)) continue;
            u.clock += 1;
            const s = u.assocOf(i, .{ .v4 = from }, l.to, now) orelse continue;
            s.seen = u.clock;
            _ = linux.sendto(s.fd, &u.buf, n, 0, null, 0);
        }
    }

    fn fromClients6(u: *Udp, listeners: []const Listener, i: usize, now: u64) void {
        const l = listeners[i];
        while (true) {
            var from: linux.sockaddr.in6 = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
            const n = linux.recvfrom(l.fd, &u.buf, u.buf.len, 0, asSockaddr6(&from), &len);
            if (linux.errno(n) != .SUCCESS) return;
            u.clock += 1;
            const s = u.assocOf(i, .{ .v6 = from }, l.to, now) orelse continue;
            s.seen = u.clock;
            _ = linux.sendto(s.fd, &u.buf, n, 0, null, 0);
        }
    }

    const Client = union(enum) { v4: linux.sockaddr.in, v6: linux.sockaddr.in6 };

    /// The client's association, made when it has none (the quietest dropped when all are in
    /// use), or null when this second's new clients are spent.
    fn assocOf(u: *Udp, listener: usize, client: Client, to: u16, now: u64) ?*Assoc {
        var free: ?*Assoc = null;
        var oldest: *Assoc = &u.assocs[0];
        for (u.assocs) |*s| {
            if (!s.used) {
                if (free == null) free = s;
                continue;
            }
            if (s.listener == listener and sameClient(s, client)) return s;
            if (s.seen < oldest.seen) oldest = s;
        }
        if (now / 1000 != u.second) {
            u.second = now / 1000;
            u.new_in_second = 0;
        }
        if (u.new_in_second >= max_new_assocs_per_s) return null;
        u.new_in_second += 1;
        const s = free orelse s: {
            _ = linux.close(oldest.fd);
            oldest.* = .{};
            break :s oldest;
        };
        const fd = dialUdp(to) orelse return null;
        s.* = .{ .used = true, .listener = listener, .fd = fd, .seen = u.clock };
        switch (client) {
            .v4 => |c| s.client = c,
            .v6 => |c| s.client6 = c,
        }
        s.is_v6 = client == .v6;
        return s;
    }

    fn sameClient(s: *const Assoc, client: Client) bool {
        return switch (client) {
            .v4 => |c| !s.is_v6 and s.client.port == c.port and s.client.addr == c.addr,
            .v6 => |c| s.is_v6 and s.client6.port == c.port and std.mem.eql(u8, &s.client6.addr, &c.addr),
        };
    }

    /// The job's answers on `s`, sent to its client from the published port.
    fn toClient(u: *Udp, listeners: []const Listener, s: *Assoc) void {
        while (true) {
            const n = linux.recvfrom(s.fd, &u.buf, u.buf.len, 0, null, null);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                // The job's port answered with an ICMP error: nothing listens there yet.
                .CONNREFUSED => continue,
                else => return,
            }
            u.clock += 1;
            s.seen = u.clock;
            const out = listeners[s.listener].fd;
            if (s.is_v6)
                _ = linux.sendto(out, &u.buf, n, 0, asSockaddr6(&s.client6), @sizeOf(linux.sockaddr.in6))
            else
                _ = linux.sendto(out, &u.buf, n, 0, asSockaddr(&s.client), @sizeOf(linux.sockaddr.in));
        }
    }
};

fn peerOf(sa: linux.sockaddr.in) [4]u8 {
    var a: [4]u8 = undefined;
    std.mem.writeInt(u32, &a, std.mem.bigToNative(u32, sa.addr), .big);
    return a;
}

/// A UDP socket of the job's network connected to its `port` on 127.0.0.1, non-blocking.
fn dialUdp(port: u16) ?linux.fd_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    var sa = loopback4(port);
    if (linux.errno(linux.connect(fd, asSockaddr(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

fn accept(conns: []Conn, l: Listener, guard: ?*Guard, now: u64, limits: Spec.Limits) void {
    var peer: linux.sockaddr.in6 = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    const rc = linux.accept4(l.fd, asSockaddr6(&peer), &len, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
    if (linux.errno(rc) != .SUCCESS) return;
    const client = std.math.cast(linux.fd_t, rc) orelse return;
    // An IPv4 peer's address is at bytes 4 to 8 of the storage (`sockaddr_in`'s `sin_addr`).
    if (l.guarded) if (guard) |g| if (!g.allows(std.mem.asBytes(&peer)[4..8].*)) {
        _ = linux.close(client);
        return;
    };
    var oldest: ?*Conn = null;
    const slot = for (conns) |*c| {
        if (!c.used) break c;
        if (!c.connecting and (oldest == null or c.last < oldest.?.last)) oldest = c;
    } else s: {
        // All in use: the one quiet longest makes way, once it has been quiet a while.
        const o = oldest orelse break :s null;
        if (now -| o.last < limits.evict_idle_ms) break :s null;
        o.close();
        break :s o;
    };
    const s = slot orelse {
        _ = linux.close(client);
        return;
    };
    const up = dial(l.to, false) orelse dial(l.to, true) orelse {
        _ = linux.close(client);
        return;
    };
    s.* = .{ .used = true, .fds = .{ client, up.fd }, .connecting = !up.done, .v6 = up.v6, .to = l.to, .last = now };
}

/// A non-blocking connection to the service's `port` on the loopback (`::1` for `v6`): made
/// (`done`), under way, or null when it was refused at once.
fn dial(port: u16, v6: bool) ?struct { fd: linux.fd_t, done: bool, v6: bool } {
    const family: u32 = if (v6) linux.AF.INET6 else linux.AF.INET;
    const rc = linux.socket(family, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    const done = if (v6) done: {
        var sa = loopback6(port);
        break :done linux.connect(fd, asSockaddr6(&sa), @sizeOf(linux.sockaddr.in6));
    } else done: {
        var sa = loopback4(port);
        break :done linux.connect(fd, asSockaddr(&sa), @sizeOf(linux.sockaddr.in));
    };
    switch (linux.errno(done)) {
        .SUCCESS => return .{ .fd = fd, .done = true, .v6 = v6 },
        .INPROGRESS => return .{ .fd = fd, .done = false, .v6 = v6 },
        else => {
            _ = linux.close(fd);
            return null;
        },
    }
}

/// One round for a connection: its connect finished, or what can be read, read; what can be
/// written, written; a drained direction whose sender is done, shut. False when it is over (both
/// directions shut, an error, its connect refused or too slow, or idle too long).
fn step(c: *Conn, polled: []const linux.pollfd, now: u64, limits: Spec.Limits) bool {
    if (c.connecting) {
        if (polled[1].revents == 0) return now < c.deadline(limits);
        var err: i32 = 0;
        var len: linux.socklen_t = @sizeOf(i32);
        const so_error = 4;
        const rc = linux.getsockopt(c.fds[1], linux.SOL.SOCKET, so_error, std.mem.asBytes(&err), &len);
        if (linux.errno(rc) == .SUCCESS and err == 0) {
            c.connecting = false;
            c.last = now;
            return true;
        }
        // Refused on IPv4: the job's port may be on `::1` alone.
        _ = linux.close(c.fds[1]);
        c.fds[1] = -1;
        if (c.v6) return false;
        const up = dial(c.to, true) orelse return false;
        c.fds[1] = up.fd;
        c.connecting = !up.done;
        c.v6 = true;
        c.last = now;
        return true;
    }
    var moved = false;
    for (0..2) |side| {
        const re = polled[side].revents;
        if (re & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0 and !c.pipes[side].eof) {
            const room = c.pipes[side].room();
            if (room.len > 0) {
                const n = linux.read(c.fds[side], room.ptr, room.len);
                switch (linux.errno(n)) {
                    .SUCCESS => if (n == 0) {
                        c.pipes[side].eof = true;
                    } else {
                        c.pipes[side].end += n;
                        moved = true;
                    },
                    .AGAIN, .INTR => {},
                    else => return false,
                }
            }
        }
        if (re & linux.POLL.OUT != 0) {
            const p = &c.pipes[1 - side];
            if (p.pending()) {
                const n = linux.write(c.fds[side], p.buf[p.start..p.end].ptr, p.end - p.start);
                switch (linux.errno(n)) {
                    .SUCCESS => {
                        p.start += n;
                        moved = true;
                    },
                    .AGAIN, .INTR => {},
                    else => return false,
                }
            }
        }
    }
    if (moved) c.last = now;
    for (0..2) |side| {
        const p = &c.pipes[side];
        if (p.eof and !p.pending() and !p.shut) {
            _ = linux.shutdown(c.fds[1 - side], linux.SHUT.WR);
            p.shut = true;
        }
    }
    if (now >= c.deadline(limits)) return false;
    return !(c.pipes[0].shut and c.pipes[1].shut);
}

// --- the runner's side ---

/// A running relay: its process and its lifeline.
pub const Running = struct {
    child: std.process.Child,
    lifeline: std.Io.File,
    /// Published: the host port each `Spec.ports` entry got, in order (the kernel's pick for 0).
    ports: []const u16 = &.{},

    /// Closes its lifeline and waits for it.
    pub fn stop(r: *Running, io: std.Io) void {
        r.lifeline.close(io);
        _ = r.child.wait(io) catch {};
    }
};

/// Starts the relay (`self_exe native-forward`) and waits until it listens. On failure, why.
pub fn start(
    arena: Allocator,
    io: std.Io,
    self_exe: []const u8,
    spec: Spec,
    why: *[]const u8,
) !Running {
    var empty: std.process.Environ.Map = .init(arena);
    var child = try std.process.spawn(io, .{
        .argv = &.{ self_exe, command },
        .environ_map = &empty,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    var json: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(spec, .{}, &json.writer);
    try json.writer.writeByte('\n');
    child.stdin.?.writeStreamingAll(io, json.written()) catch {};
    const lifeline = child.stdin.?;
    child.stdin = null;
    // "ready", then each published port: one line, written at once.
    var buf: [8 * max_published]u8 = undefined;
    var n: usize = 0;
    while (n < buf.len) {
        const got = child.stdout.?.readStreaming(io, &.{buf[n..]}) catch 0;
        if (got == 0) break;
        n += got;
        if (std.mem.indexOfScalar(u8, buf[0..n], '\n') != null) break;
    }
    if (n > 0 and std.mem.startsWith(u8, buf[0..n], "ready")) {
        var bound: std.ArrayList(u16) = .empty;
        var words = std.mem.tokenizeAny(u8, buf["ready".len..n], " \n");
        while (words.next()) |w| try bound.append(arena, std.fmt.parseInt(u16, w, 10) catch 0);
        return .{ .child = child, .lifeline = lifeline, .ports = bound.items };
    }
    lifeline.close(io);
    var err: std.ArrayList(u8) = .empty;
    var ebuf: [1024]u8 = undefined;
    while (err.items.len < 4096) {
        const got = child.stderr.?.readStreaming(io, &.{&ebuf}) catch break;
        if (got == 0) break;
        try err.appendSlice(arena, ebuf[0..got]);
    }
    _ = child.wait(io) catch {};
    why.* = std.mem.trim(u8, err.items, " \n");
    if (why.len == 0) why.* = "the port relay ended before it listened";
    return error.ForwardFailed;
}

test "a published port reaches the service's own port, both ways, until the relay is stopped" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const exe_rel = env.get("ZIG_RUNNER_TEST_EXE") orelse return error.SkipZigTest;
    const exe = std.Io.Dir.cwd().realPathFileAlloc(io, exe_rel, arena) catch
        return error.SkipZigTest;
    // A "service": an echo server of the test's on a port of the host's loopback (the relay runs
    // in the host's network here, as for a rootless job).
    const server = listen(0, false) orelse return error.SkipZigTest;
    defer _ = linux.close(server);
    var sa: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = linux.getsockname(server, asSockaddr(&sa), &len);
    const to = std.mem.bigToNative(u16, sa.port);
    // A free port to publish it on.
    const probe = listen(0, false) orelse return error.SkipZigTest;
    _ = linux.getsockname(probe, asSockaddr(&sa), &len);
    const from = std.mem.bigToNative(u16, sa.port);
    _ = linux.close(probe);
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{ .ports = &.{.{ .host = from, .container = to }} }, &why);
    defer r.stop(io);
    const client = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    defer _ = linux.close(@intCast(client));
    var dest = loopback4(from);
    const connected = linux.connect(@intCast(client), asSockaddr(&dest), @sizeOf(linux.sockaddr.in));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(connected));
    // The server's side: accept, read what came, answer, and close.
    var fds = [_]linux.pollfd{.{ .fd = server, .events = linux.POLL.IN, .revents = 0 }};
    _ = linux.write(@intCast(client), "ping", 4);
    _ = linux.shutdown(@intCast(client), linux.SHUT.WR);
    _ = linux.poll(&fds, 1, 5000);
    const conn_rc = linux.accept4(server, null, null, linux.SOCK.CLOEXEC);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(conn_rc));
    const conn: linux.fd_t = @intCast(conn_rc);
    var got: [16]u8 = undefined;
    var have: usize = 0;
    while (true) {
        const n = linux.read(conn, got[have..].ptr, got.len - have);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        have += n;
    }
    try std.testing.expectEqualStrings("ping", got[0..have]);
    _ = linux.write(conn, "pong", 4);
    _ = linux.close(conn);
    have = 0;
    while (true) {
        const n = linux.read(@intCast(client), got[have..].ptr, got.len - have);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        have += n;
    }
    try std.testing.expectEqualStrings("pong", got[0..have]);
}

test "a relay that cannot listen says why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const exe_rel = env.get("ZIG_RUNNER_TEST_EXE") orelse return error.SkipZigTest;
    const exe = std.Io.Dir.cwd().realPathFileAlloc(io, exe_rel, arena) catch
        return error.SkipZigTest;
    const taken = listen(0, false) orelse return error.SkipZigTest;
    defer _ = linux.close(taken);
    var sa: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = linux.getsockname(taken, asSockaddr(&sa), &len);
    const port = std.mem.bigToNative(u16, sa.port);
    var why: []const u8 = "";
    try std.testing.expectError(error.ForwardFailed, start(arena, io, exe, .{
        .ports = &.{.{ .host = port, .container = 1 }},
    }, &why));
    try std.testing.expect(std.mem.indexOf(u8, why, "listen on 127.0.0.1 port") != null);
    // Published: the port another process holds is named, with its address and protocol.
    why = "";
    try std.testing.expectError(error.ForwardFailed, start(arena, io, exe, .{
        .ports = &.{.{ .host = port, .container = 1 }},
        .publish = true,
    }, &why));
    const named = try std.fmt.allocPrint(arena, "publish 127.0.0.1:{d}/tcp", .{port});
    if (std.mem.indexOf(u8, why, named) == null) {
        std.debug.print("{s} is not in: {s}\n", .{ named, why });
        return error.TestUnexpectedResult;
    }
}

fn testExe(arena: Allocator) ![]const u8 {
    var env = try std.testing.environ.createMap(arena);
    const exe_rel = env.get("ZIG_RUNNER_TEST_EXE") orelse return error.SkipZigTest;
    return std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, exe_rel, arena) catch error.SkipZigTest;
}

/// `fd`'s data, read until it ends or `want` bytes came, waiting at most 5 s for each read.
fn readAll(fd: linux.fd_t, buf: []u8) []const u8 {
    var have: usize = 0;
    while (have < buf.len) {
        var p = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&p, 1, 5000) != 1) break;
        const n = linux.read(fd, buf[have..].ptr, buf.len - have);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        have += n;
    }
    return buf[0..have];
}

test "a published port: listened on in the host's network on a port the kernel picks, said in the ready line, gone with the relay" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const exe = try testExe(arena);
    // The job's port: a server of the test's (the relay has no job network to join here, so it
    // connects in the host's, as for a rootless job).
    const server = listen(0, false) orelse return error.SkipZigTest;
    defer _ = linux.close(server);
    const to = boundPort(server);
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{
        .ports = &.{.{ .host = 0, .container = to }},
        .publish = true,
    }, &why);
    var stopped = false;
    defer if (!stopped) r.stop(io);
    try std.testing.expectEqual(@as(usize, 1), r.ports.len);
    const published = r.ports[0];
    try std.testing.expect(published != 0 and published != to);
    const client_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    const client: linux.fd_t = std.math.cast(linux.fd_t, client_rc) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(client);
    var dest = loopback4(published);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.connect(client, asSockaddr(&dest), @sizeOf(linux.sockaddr.in))));
    _ = linux.write(client, "ping", 4);
    _ = linux.shutdown(client, linux.SHUT.WR);
    var p = [_]linux.pollfd{.{ .fd = server, .events = linux.POLL.IN, .revents = 0 }};
    _ = linux.poll(&p, 1, 5000);
    const conn_rc = linux.accept4(server, null, null, linux.SOCK.CLOEXEC);
    const conn: linux.fd_t = std.math.cast(linux.fd_t, conn_rc) orelse return error.TestUnexpectedResult;
    var got: [16]u8 = undefined;
    try std.testing.expectEqualStrings("ping", readAll(conn, &got));
    _ = linux.write(conn, "pong", 4);
    _ = linux.close(conn);
    try std.testing.expectEqualStrings("pong", readAll(client, &got));
    // Stopped, the port is no one's: nothing is left to remove.
    r.stop(io);
    stopped = true;
    const again_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    const again: linux.fd_t = std.math.cast(linux.fd_t, again_rc) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(again);
    try std.testing.expectEqual(linux.E.CONNREFUSED, linux.errno(linux.connect(again, asSockaddr(&dest), @sizeOf(linux.sockaddr.in))));
}

test "a published UDP port relays each client's datagrams and the answers back" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const exe = try testExe(arena);
    const server = listenOn(.{ 127, 0, 0, 1 }, 0, true) orelse return error.SkipZigTest;
    defer _ = linux.close(server);
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{
        .ports = &.{.{ .host = 0, .container = boundPort(server), .udp = true }},
        .publish = true,
    }, &why);
    defer r.stop(io);
    const published = r.ports[0];
    try std.testing.expect(published != 0);
    // Two clients, each answered on its own.
    var clients: [2]linux.fd_t = undefined;
    for (&clients, 0..) |*c, i| {
        c.* = listenOn(.{ 127, 0, 0, 1 }, 0, true) orelse return error.TestUnexpectedResult;
        var dest = loopback4(published);
        const msg = if (i == 0) "one" else "two";
        _ = linux.sendto(c.*, msg.ptr, msg.len, 0, asSockaddr(&dest), @sizeOf(linux.sockaddr.in));
    }
    defer for (clients) |c| {
        _ = linux.close(c);
    };
    var buf: [64]u8 = undefined;
    for (0..2) |_| {
        var p = [_]linux.pollfd{.{ .fd = server, .events = linux.POLL.IN, .revents = 0 }};
        try std.testing.expectEqual(@as(usize, 1), linux.poll(&p, 1, 5000));
        var from: linux.sockaddr.in = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        const n = linux.recvfrom(server, &buf, buf.len, 0, asSockaddr(&from), &len);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(n));
        const answer = try std.fmt.allocPrint(arena, "re:{s}", .{buf[0..n]});
        _ = linux.sendto(server, answer.ptr, answer.len, 0, asSockaddr(&from), len);
    }
    for (clients, 0..) |c, i| {
        var p = [_]linux.pollfd{.{ .fd = c, .events = linux.POLL.IN, .revents = 0 }};
        try std.testing.expectEqual(@as(usize, 1), linux.poll(&p, 1, 5000));
        const n = linux.recvfrom(c, &buf, buf.len, 0, null, null);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(n));
        try std.testing.expectEqualStrings(if (i == 0) "re:one" else "re:two", buf[0..n]);
    }
}

/// The local links of `testRoutes`: Docker's bridge, the runner's, a Calico pod's veth and a
/// Firecracker VM's tap. Counted, for the guard's kept verdicts.
fn testLocal(name: []const u8) bool {
    test_local_calls += 1;
    for ([_][]const u8{ "docker0", "zr0", "cali1a2b", "tap0" }) |l| if (std.mem.eql(u8, name, l)) return true;
    return false;
}
var test_local_calls: usize = 0;

/// As /proc/net/route has them: a default route via the LAN's NIC, the LAN, Docker's bridge, a
/// route that is down, a Calico pod's /32 (172.16.0.5) and a VM's tap (172.31.0.0/30), in the
/// kernel's byte order.
const test_routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" ++
    "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" ++
    "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" ++
    "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" ++
    "down0\t00001EAC\t00000000\t0000\t0\t0\t0\t0000FFFF\t0\t0\t0\n" ++
    "cali1a2b\t050010AC\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n" ++
    "tap0\t00001FAC\t00000000\t0001\t0\t0\t0\tFCFFFFFF\t0\t0\t0\n";

/// `test_routes` opened as the guard opens the host's.
fn testRoutes(tmp: *std.testing.TmpDir, arena: Allocator) !linux.fd_t {
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "route", .data = test_routes });
    const path = try tmp.dir.realPathFileAlloc(io, "route", arena);
    const rc = linux.open(try arena.dupeSentinel(u8, path, 0), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    return std.math.cast(linux.fd_t, rc) orelse error.TestUnexpectedResult;
}

test "the guard: a peer of the runner's jobs or of the host's own containers and VMs is refused; loopback and the LAN are not" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const fd = try testRoutes(&tmp, a.allocator());
    defer _ = linux.close(fd);
    var g: Guard = .{ .route = fd, .subnet = .{ 10, 211, 0, 0 }, .prefix = 16, .local = testLocal };
    try std.testing.expect(g.allows(.{ 127, 0, 0, 1 }));
    try std.testing.expect(g.allows(.{ 192, 168, 1, 50 }));
    try std.testing.expect(g.allows(.{ 8, 8, 8, 8 }));
    // A route that is down is no link's.
    try std.testing.expect(g.allows(.{ 172, 30, 0, 2 }));
    try std.testing.expect(!g.allows(.{ 10, 211, 1, 2 }));
    try std.testing.expect(!g.allows(.{ 172, 17, 0, 2 }));
    // Routed, not bridged: a pod's /32 out of its veth, a VM out of its tap. The pod's neighbour
    // has no route of its own, so it is reached by the default one, through the LAN.
    try std.testing.expect(!g.allows(.{ 172, 16, 0, 5 }));
    try std.testing.expect(g.allows(.{ 172, 16, 0, 6 }));
    try std.testing.expect(!g.allows(.{ 172, 31, 0, 2 }));
    try std.testing.expect(g.allows(.{ 172, 31, 0, 4 }));
    // Routes that cannot be read refuse every peer beyond loopback.
    g.route = -1;
    try std.testing.expect(!g.allows(.{ 192, 168, 1, 50 }));
    try std.testing.expect(g.allows(.{ 127, 0, 0, 1 }));
}

test "the guard keeps a UDP peer's verdict for a second, for so many peers" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const fd = try testRoutes(&tmp, a.allocator());
    defer _ = linux.close(fd);
    var g: Guard = .{ .route = fd, .subnet = .{ 10, 211, 0, 0 }, .prefix = 16, .local = testLocal };
    const pod: [4]u8 = .{ 172, 16, 0, 5 };
    const lan: [4]u8 = .{ 192, 168, 1, 50 };
    const t0: u64 = 50_000;
    test_local_calls = 0;
    try std.testing.expect(!g.allowsCached(pod, 4000, t0));
    const once = test_local_calls;
    try std.testing.expect(once > 0);
    // The same peer within the second: kept, the routes not read again.
    try std.testing.expect(!g.allowsCached(pod, 4000, t0 + 1));
    try std.testing.expect(!g.allowsCached(pod, 4000, t0 + verdict_ms - 1));
    try std.testing.expectEqual(once, test_local_calls);
    // Another port of the same address is another client, and an allowed verdict is kept too.
    try std.testing.expect(!g.allowsCached(pod, 4001, t0));
    try std.testing.expect(g.allowsCached(lan, 4000, t0));
    const three = test_local_calls;
    try std.testing.expect(g.allowsCached(lan, 4000, t0 + 2));
    try std.testing.expectEqual(three, test_local_calls);
    // A second on, the routes are read again: a link made or gone since counts.
    try std.testing.expect(!g.allowsCached(pod, 4000, t0 + verdict_ms));
    try std.testing.expect(test_local_calls > three);
    // Past `max_verdicts` peers, the one that expires first makes way; the verdicts stay right.
    for (0..max_verdicts + 8) |i| {
        const port = std.math.cast(u16, 10_000 + i).?;
        try std.testing.expect(g.allowsCached(lan, port, t0 + 10 + i));
        try std.testing.expect(!g.allowsCached(pod, port, t0 + 10 + i));
    }
    const full = test_local_calls;
    try std.testing.expect(g.allowsCached(lan, 10_000, t0 + 200));
    try std.testing.expect(test_local_calls > full);
    // Loopback is never refused, and the runner's jobs always are, kept or not.
    try std.testing.expect(g.allowsCached(.{ 127, 0, 0, 1 }, 1, t0));
    try std.testing.expect(!g.allowsCached(.{ 10, 211, 0, 9 }, 1, t0));
}

test "the guard's links: a bridge, a tun or tap, and a veth into another namespace are local; a NIC and a VLAN of it are not" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    // A /sys/class/net as the host's has them: `ifindex`, `iflink`, and the files that tell.
    const Link = struct { name: []const u8, index: []const u8, link: []const u8, extra: []const u8 = "" };
    for ([_]Link{
        .{ .name = "eth0", .index = "2", .link = "2" },
        .{ .name = "docker0", .index = "3", .link = "3", .extra = "bridge/bridge_id" },
        .{ .name = "tap0", .index = "11", .link = "11", .extra = "tun_flags" },
        .{ .name = "tun0", .index = "12", .link = "12", .extra = "tun_flags" },
        // A veth's `iflink` is its peer's index, in the pod's namespace.
        .{ .name = "cali1a2b", .index = "9", .link = "4" },
        // A VLAN's is its NIC's, which it is stacked on (`lower_eth0`).
        .{ .name = "eth0.10", .index = "10", .link = "2", .extra = "lower_eth0" },
        .{ .name = "vlan10", .index = "13", .link = "2", .extra = "lower_eth0" },
        // No `iflink`: cannot be told, so local.
        .{ .name = "odd0", .index = "14", .link = "" },
    }) |l| {
        try tmp.dir.createDirPath(io, l.name);
        const index = try std.fmt.allocPrint(a.allocator(), "{s}/ifindex", .{l.name});
        try tmp.dir.writeFile(io, .{ .sub_path = index, .data = try std.fmt.allocPrint(a.allocator(), "{s}\n", .{l.index}) });
        if (l.link.len > 0) {
            const link = try std.fmt.allocPrint(a.allocator(), "{s}/iflink", .{l.name});
            try tmp.dir.writeFile(io, .{ .sub_path = link, .data = try std.fmt.allocPrint(a.allocator(), "{s}\n", .{l.link}) });
        }
        if (l.extra.len > 0) {
            const extra = try std.fmt.allocPrint(a.allocator(), "{s}/{s}", .{ l.name, l.extra });
            if (std.fs.path.dirname(extra)) |d| try tmp.dir.createDirPath(io, d);
            try tmp.dir.writeFile(io, .{ .sub_path = extra, .data = "" });
        }
    }
    const sys = try tmp.dir.realPathFileAlloc(io, ".", a.allocator());
    try std.testing.expect(!isLocalAt(sys, "eth0"));
    try std.testing.expect(!isLocalAt(sys, "vlan10"));
    try std.testing.expect(!isLocalAt(sys, "eth0.10"));
    try std.testing.expect(isLocalAt(sys, "docker0"));
    try std.testing.expect(isLocalAt(sys, "tap0"));
    try std.testing.expect(isLocalAt(sys, "tun0"));
    try std.testing.expect(isLocalAt(sys, "cali1a2b"));
    try std.testing.expect(isLocalAt(sys, "odd0"));
    // A name that is no interface, or no name sysfs could have, is local too.
    try std.testing.expect(isLocalAt(sys, "gone0"));
    try std.testing.expect(isLocalAt(sys, ".."));
    try std.testing.expect(isLocalAt(sys, "../eth0"));
    try std.testing.expect(isLocalAt(sys, ""));
    // The host's own loopback is its own link.
    try std.testing.expect(!isLocal("lo"));
}

/// Sockets `publishOne` makes, faked: the kernel's picks are `picks`, in turn; fds are their
/// indexes. Counts what it closed.
const TestSockets = struct {
    picks: []const u16,
    next: usize = 0,
    closed: usize = 0,
    v6: Loopback6 = .off,

    fn listen4(s: *TestSockets, _: [4]u8, port: u16, _: bool) ?linux.fd_t {
        if (port != 0) return 100;
        if (s.next == s.picks.len) return null;
        s.next += 1;
        return std.math.cast(linux.fd_t, s.next - 1);
    }
    fn boundTo(s: *TestSockets, fd: linux.fd_t) u16 {
        return if (fd == 100) 50080 else s.picks[std.math.cast(usize, fd).?];
    }
    fn listen6(s: *TestSockets, _: u16, _: bool) Loopback6 {
        return s.v6;
    }
    fn close(s: *TestSockets, _: linux.fd_t) void {
        s.closed += 1;
    }
};

test "a published port the kernel picks is picked again when it lands on one of the runner's own" {
    const reserved = [_]u16{ 5432, 2375 };
    const picked: Spec.Map = .{ .host = 0, .container = 80, .address = .{ 0, 0, 0, 0 } };
    var s: TestSockets = .{ .picks = &.{ 5432, 2375, 41234 } };
    const got = publishOne(picked, &reserved, &s);
    try std.testing.expectEqual(@as(linux.fd_t, 2), got.ok.v4);
    try std.testing.expectEqual(@as(usize, 2), s.closed);
    // Every pick reserved: given up, as a port taken.
    const all_reserved: [20]u16 = @splat(5432);
    s = .{ .picks = &all_reserved };
    try std.testing.expect(publishOne(picked, &reserved, &s) == .taken);
    // A port the job names is the operator's to allow (`publish.plan`), never picked again.
    s = .{ .picks = &.{} };
    const named = publishOne(.{ .host = 50080, .container = 80, .address = .{ 0, 0, 0, 0 } }, &.{50080}, &s);
    try std.testing.expectEqual(@as(linux.fd_t, 100), named.ok.v4);
    // On 127.0.0.1, a pick whose ::1 is taken is picked again too.
    s = .{ .picks = &.{ 2375, 41234 }, .v6 = .taken };
    try std.testing.expect(publishOne(.{ .host = 0, .container = 80 }, &reserved, &s) == .taken);
    try std.testing.expectEqual(@as(usize, 2), s.closed);
}

/// A TCP client of `127.0.0.1:port` (or `[::1]:port`), connected, or null.
fn testConnect(port: u16, v6: bool) ?linux.fd_t {
    const family: u32 = if (v6) linux.AF.INET6 else linux.AF.INET;
    const fd = std.math.cast(linux.fd_t, linux.socket(family, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)) orelse return null;
    const rc = if (v6) rc: {
        var sa = loopback6(port);
        break :rc linux.connect(fd, asSockaddr6(&sa), @sizeOf(linux.sockaddr.in6));
    } else rc: {
        var sa = loopback4(port);
        break :rc linux.connect(fd, asSockaddr(&sa), @sizeOf(linux.sockaddr.in));
    };
    if (linux.errno(rc) != .SUCCESS) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

/// One round on `server`: accept within `ms`, read what came, answer "pong", close. Whether it did.
fn testServeOnce(server: linux.fd_t, ms: i32) bool {
    var p = [_]linux.pollfd{.{ .fd = server, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&p, 1, ms) != 1) return false;
    const conn = std.math.cast(linux.fd_t, linux.accept4(server, null, null, linux.SOCK.CLOEXEC)) orelse return false;
    defer _ = linux.close(conn);
    var got: [16]u8 = undefined;
    _ = readAll(conn, got[0..4]);
    _ = linux.write(conn, "pong", 4);
    return true;
}

/// Whether `fd` is still open after `ms`: no end of file came on it.
fn testStillOpen(fd: linux.fd_t, ms: i32) bool {
    var p = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&p, 1, ms) == 0) return true;
    var b: [1]u8 = undefined;
    const n = linux.read(fd, &b, 1);
    return linux.errno(n) == .SUCCESS and n > 0;
}

test "a published port's connect to the job is not waited on: a job port whose backlog is full stalls no other" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const exe = try testExe(arena);
    // The stuck port: a backlog of none, never accepted, filled by two clients of the test's, so
    // the next SYN is dropped and a blocking connect would wait for minutes.
    const stuck = std.math.cast(linux.fd_t, linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)).?;
    defer _ = linux.close(stuck);
    var sa = loopback4(0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(stuck, asSockaddr(&sa), @sizeOf(linux.sockaddr.in))));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(stuck, 0)));
    var fillers: [2]linux.fd_t = undefined;
    for (&fillers) |*f| {
        f.* = std.math.cast(linux.fd_t, linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0)).?;
        var to = loopback4(boundPort(stuck));
        _ = linux.connect(f.*, asSockaddr(&to), @sizeOf(linux.sockaddr.in));
    }
    defer for (fillers) |f| {
        _ = linux.close(f);
    };
    const server = listen(0, false) orelse return error.SkipZigTest;
    defer _ = linux.close(server);
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{
        .ports = &.{ .{ .host = 0, .container = boundPort(stuck) }, .{ .host = 0, .container = boundPort(server) } },
        .publish = true,
    }, &why);
    defer r.stop(io);
    // A client of the stuck port, whose connect the relay starts and cannot finish.
    const waiting = testConnect(r.ports[0], false) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(waiting);
    _ = linux.write(waiting, "ping", 4);
    io.sleep(.fromMilliseconds(200), .awake) catch {};
    // The other port is served meanwhile.
    const client = testConnect(r.ports[1], false) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(client);
    _ = linux.write(client, "ping", 4);
    try std.testing.expect(testServeOnce(server, 3000));
    var got: [16]u8 = undefined;
    try std.testing.expectEqualStrings("pong", readAll(client, &got));
}

test "a published port's quiet connections make way for a newcomer, and idle ones are closed" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const exe = try testExe(arena);
    // The job's port: its connections complete in its backlog, never read.
    const server = std.math.cast(linux.fd_t, linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)).?;
    defer _ = linux.close(server);
    var sa = loopback4(0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(server, asSockaddr(&sa), @sizeOf(linux.sockaddr.in))));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(server, 512)));
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{
        .ports = &.{.{ .host = 0, .container = boundPort(server) }},
        .publish = true,
        .limits = .{ .evict_idle_ms = 200, .idle_ms = 1500 },
    }, &why);
    defer r.stop(io);
    // Every place taken by a connection that says nothing.
    var held: [max_conns]linux.fd_t = undefined;
    for (&held) |*h| h.* = testConnect(r.ports[0], false) orelse return error.TestUnexpectedResult;
    defer for (held) |h| {
        _ = linux.close(h);
    };
    io.sleep(.fromMilliseconds(400), .awake) catch {};
    // A newcomer is relayed, in the place of the one quiet longest, which is closed.
    const newcomer = testConnect(r.ports[0], false) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(newcomer);
    try std.testing.expect(testStillOpen(newcomer, 300));
    var closed: usize = 0;
    for (held) |h| closed += @intFromBool(!testStillOpen(h, 0));
    try std.testing.expectEqual(@as(usize, 1), closed);
    // Past the idle timeout, every connection that said nothing is closed.
    io.sleep(.fromMilliseconds(1800), .awake) catch {};
    try std.testing.expect(!testStillOpen(newcomer, 500));
}

test "a published port with no idle timeout keeps a quiet connection" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const exe = try testExe(arena);
    const server = std.math.cast(linux.fd_t, linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)).?;
    defer _ = linux.close(server);
    var sa = loopback4(0);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.bind(server, asSockaddr(&sa), @sizeOf(linux.sockaddr.in))));
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.listen(server, 512)));
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{
        .ports = &.{.{ .host = 0, .container = boundPort(server) }},
        .publish = true,
        .limits = .{ .idle_ms = 0 },
    }, &why);
    defer r.stop(io);
    const quiet = testConnect(r.ports[0], false) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(quiet);
    io.sleep(.fromMilliseconds(1800), .awake) catch {};
    try std.testing.expect(testStillOpen(quiet, 300));
}

test "a published UDP port takes only so many new clients a second" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const exe = try testExe(arena);
    const server = listenOn(.{ 127, 0, 0, 1 }, 0, true) orelse return error.SkipZigTest;
    defer _ = linux.close(server);
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{
        .ports = &.{.{ .host = 0, .container = boundPort(server), .udp = true }},
        .publish = true,
    }, &why);
    defer r.stop(io);
    // A hundred sources at once: past the cap their datagrams are dropped, not given sockets.
    var clients: [100]linux.fd_t = undefined;
    for (&clients) |*c| {
        c.* = listenOn(.{ 127, 0, 0, 1 }, 0, true) orelse return error.TestUnexpectedResult;
        var dest = loopback4(r.ports[0]);
        _ = linux.sendto(c.*, "x", 1, 0, asSockaddr(&dest), @sizeOf(linux.sockaddr.in));
    }
    defer for (clients) |c| {
        _ = linux.close(c);
    };
    var got: usize = 0;
    var buf: [16]u8 = undefined;
    while (true) {
        var p = [_]linux.pollfd{.{ .fd = server, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&p, 1, 1000) != 1) break;
        if (linux.errno(linux.recvfrom(server, &buf, buf.len, 0, null, null)) == .SUCCESS) got += 1;
    }
    // At most two seconds' worth, should the hundred straddle one.
    try std.testing.expect(got > 0 and got <= 2 * max_new_assocs_per_s);
}

test "a port published on 127.0.0.1 is on ::1 too, where the host has IPv6" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const exe = try testExe(arena);
    const probe = listen(0, true) orelse return error.SkipZigTest;
    _ = linux.close(probe);
    const server = listen(0, false) orelse return error.SkipZigTest;
    defer _ = linux.close(server);
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{
        .ports = &.{.{ .host = 0, .container = boundPort(server) }},
        .publish = true,
    }, &why);
    defer r.stop(io);
    const client = testConnect(r.ports[0], true) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(client);
    _ = linux.write(client, "ping", 4);
    try std.testing.expect(testServeOnce(server, 3000));
    var got: [16]u8 = undefined;
    try std.testing.expectEqualStrings("pong", readAll(client, &got));
}
