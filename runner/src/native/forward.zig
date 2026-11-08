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

    pub const Map = struct {
        /// 0 when published: the kernel picks one, which the ready line says.
        host: u16,
        container: u16,
        /// Where a published port listens on the host.
        address: [4]u8 = .{ 127, 0, 0, 1 },
        /// A published UDP port: datagrams relayed per client (`Assoc`).
        udp: bool = false,
    };
};

/// Connections relayed at once; more wait in the listen queue.
const max_conns = 64;
/// The most ports one helper publishes (`publish.zig` refuses more).
pub const max_published = 64;
const buf_len = 16 * 1024;

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
    var listeners: std.ArrayList(Listener) = .empty;
    var ready: std.ArrayList(u8) = .empty;
    ready.appendSlice(arena, "ready") catch sandbox.oom();
    for (spec.ports) |m| {
        if (spec.publish) {
            const fd = listenOn(m.address, m.host, m.udp) orelse {
                const what = std.fmt.allocPrint(arena, "publish {d}.{d}.{d}.{d}:{d}/{s}", .{
                    m.address[0],                m.address[1], m.address[2], m.address[3], m.host,
                    if (m.udp) "udp" else "tcp",
                }) catch "publish a port";
                sandbox.fatal(what, @as(u32, 98));
            };
            listeners.append(arena, .{ .fd = fd, .to = m.container, .udp = m.udp }) catch sandbox.oom();
            ready.print(arena, " {d}", .{boundPort(fd)}) catch sandbox.oom();
            continue;
        }
        const v4 = listen(m.host, false) orelse {
            const what = sandbox.about(arena, "listen on 127.0.0.1 port", portText(arena, m.host));
            sandbox.fatal(what, @as(u32, 98));
        };
        listeners.append(arena, .{ .fd = v4, .to = m.container }) catch sandbox.oom();
        // ::1 too, as the Dagger path forwards it, where the namespace has IPv6.
        const v6 = listen(m.host, true) orelse continue;
        listeners.append(arena, .{ .fd = v6, .to = m.container }) catch sandbox.oom();
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
    relay(arena, listeners.items);
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

const Listener = struct { fd: linux.fd_t, to: u16, udp: bool = false };

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
        const rc6 = linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6));
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

    fn close(c: *Conn) void {
        for (c.fds) |fd| _ = linux.close(fd);
        c.* = .{};
    }
};

/// Until the lifeline closes: accepts, connects each to the service's port, and copies both
/// ways, each direction shut once its sender is done.
fn relay(arena: Allocator, listeners: []const Listener) void {
    const conns = arena.alloc(Conn, max_conns) catch sandbox.oom();
    for (conns) |*c| c.* = .{};
    var udp: Udp = .{ .assocs = arena.alloc(Assoc, max_assocs) catch sandbox.oom() };
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
        for (conns, 0..) |*c, i| for (0..2) |side| {
            var ev: i16 = 0;
            if (c.used) {
                if (!c.pipes[side].eof and c.pipes[side].room().len > 0) ev |= linux.POLL.IN;
                if (c.pipes[1 - side].pending()) ev |= linux.POLL.OUT;
            }
            const fd = if (c.used) c.fds[side] else -1;
            conn_fds[2 * i + side] = .{ .fd = fd, .events = ev, .revents = 0 };
        };
        const rc = linux.poll(fds.ptr, nfds, -1);
        if (linux.errno(rc) == .INTR) continue;
        sandbox.check("wait for the relay's connections", rc);
        if (fds[0].revents != 0) return;
        for (listeners, fds[1..][0..listeners.len], 0..) |l, p, i| if (p.revents != 0) {
            if (l.udp) udp.fromClients(listeners, i) else accept(conns, l);
        };
        for (conns, 0..) |*c, i| if (c.used) {
            if (!step(c, conn_fds[2 * i ..][0..2])) c.close();
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
    fd: linux.fd_t = -1,
    /// When it was last heard from or answered, in the relay's own count.
    seen: u64 = 0,
};

const Udp = struct {
    assocs: []Assoc,
    clock: u64 = 0,
    buf: [64 * 1024]u8 = undefined,

    /// Every datagram waiting on listener `i`, each sent on by its client's socket in the job's
    /// network (made on its first datagram, connected to the job's port on the loopback).
    fn fromClients(u: *Udp, listeners: []const Listener, i: usize) void {
        const l = listeners[i];
        while (true) {
            var from: linux.sockaddr.in = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const n = linux.recvfrom(l.fd, &u.buf, u.buf.len, 0, asSockaddr(&from), &len);
            if (linux.errno(n) != .SUCCESS) return;
            u.clock += 1;
            const s = u.assocOf(i, from, l.to) orelse continue;
            s.seen = u.clock;
            _ = linux.sendto(s.fd, &u.buf, n, 0, null, 0);
        }
    }

    /// The client's association, made when it has none (the quietest dropped when all are in use).
    fn assocOf(u: *Udp, listener: usize, client: linux.sockaddr.in, to: u16) ?*Assoc {
        var free: ?*Assoc = null;
        var oldest: *Assoc = &u.assocs[0];
        for (u.assocs) |*s| {
            if (!s.used) {
                if (free == null) free = s;
                continue;
            }
            if (s.listener == listener and s.client.port == client.port and s.client.addr == client.addr) return s;
            if (s.seen < oldest.seen) oldest = s;
        }
        const s = free orelse s: {
            _ = linux.close(oldest.fd);
            oldest.* = .{};
            break :s oldest;
        };
        const fd = dialUdp(to) orelse return null;
        s.* = .{ .used = true, .listener = listener, .client = client, .fd = fd, .seen = u.clock };
        return s;
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
            _ = linux.sendto(listeners[s.listener].fd, &u.buf, n, 0, asSockaddr(&s.client), @sizeOf(linux.sockaddr.in));
        }
    }
};

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

fn accept(conns: []Conn, l: Listener) void {
    const rc = linux.accept4(l.fd, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
    if (linux.errno(rc) != .SUCCESS) return;
    const client: linux.fd_t = @intCast(rc);
    const slot = for (conns) |*c| {
        if (!c.used) break c;
    } else {
        _ = linux.close(client);
        return;
    };
    const upstream = dial(l.to) orelse {
        _ = linux.close(client);
        return;
    };
    slot.* = .{ .used = true, .fds = .{ client, upstream } };
}

/// A connection to the service's `port` on the loopback (127.0.0.1, else ::1), made non-blocking
/// once connected; a connection on the loopback is made or refused at once.
fn dial(port: u16) ?linux.fd_t {
    for ([_]bool{ false, true }) |v6| {
        const family: u32 = if (v6) linux.AF.INET6 else linux.AF.INET;
        const rc = linux.socket(family, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) continue;
        const fd: linux.fd_t = @intCast(rc);
        const done = if (v6) done: {
            var sa = loopback6(port);
            break :done linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6));
        } else done: {
            var sa = loopback4(port);
            break :done linux.connect(fd, asSockaddr(&sa), @sizeOf(linux.sockaddr.in));
        };
        if (linux.errno(done) != .SUCCESS) {
            _ = linux.close(fd);
            continue;
        }
        const nonblock: usize = 0o4000;
        const fl = linux.fcntl(fd, linux.F.GETFL, 0);
        _ = linux.fcntl(fd, linux.F.SETFL, fl | nonblock);
        return fd;
    }
    return null;
}

/// One round for a connection: what can be read, read; what can be written, written; a drained
/// direction whose sender is done, shut. False when it is over (both directions shut, or an
/// error).
fn step(c: *Conn, polled: []const linux.pollfd) bool {
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
                    .SUCCESS => p.start += n,
                    .AGAIN, .INTR => {},
                    else => return false,
                }
            }
        }
    }
    for (0..2) |side| {
        const p = &c.pipes[side];
        if (p.eof and !p.pending() and !p.shut) {
            _ = linux.shutdown(c.fds[1 - side], linux.SHUT.WR);
            p.shut = true;
        }
    }
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
