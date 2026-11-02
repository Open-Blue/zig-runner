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

    pub const Map = struct { host: u16, container: u16 };
};

/// Connections relayed at once; more wait in the listen queue.
const max_conns = 64;
const buf_len = 16 * 1024;

/// The helper's entry. Exits 0 when its lifeline closes, 1 with why on stderr when it cannot
/// listen.
pub fn main(arena: Allocator) u8 {
    const spec = sandbox.readJsonLine(Spec, arena) catch
        sandbox.fatal("read the relay's spec", @as(u32, 22));
    if (spec.cgroup) |dir| sandbox.joinCgroup(arena, dir);
    if (spec.netns) |p| {
        const fd = linux.open(sandbox.z(arena, p), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        sandbox.check("open the job's network namespace", fd);
        const joined = linux.setns(@intCast(fd), linux.CLONE.NEWNET);
        sandbox.check("enter the job's network namespace", joined);
        _ = linux.close(@intCast(fd));
    }
    var listeners: std.ArrayList(Listener) = .empty;
    for (spec.ports) |m| {
        const v4 = listen(m.host, false) orelse {
            const what = sandbox.about(arena, "listen on 127.0.0.1 port", portText(arena, m.host));
            sandbox.fatal(what, @as(u32, 98));
        };
        listeners.append(arena, .{ .fd = v4, .to = m.container }) catch sandbox.oom();
        // ::1 too, as the Dagger path forwards it, where the namespace has IPv6.
        const v6 = listen(m.host, true) orelse continue;
        listeners.append(arena, .{ .fd = v6, .to = m.container }) catch sandbox.oom();
    }
    if (spec.id) |id| {
        sandbox.check("setgroups", linux.setgroups(0, sandbox.no_groups));
        sandbox.check("setresgid", linux.setresgid(id, id, id));
        sandbox.check("setresuid", linux.setresuid(id, id, id));
    }
    sandbox.check("no_new_privs", linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    // Docker's allow list, as each step has it: after no_new_privs, which an unprivileged
    // filter needs, and before any of the job's traffic.
    sandbox.installSeccomp();
    _ = linux.write(1, "ready\n", 6);
    relay(arena, listeners.items);
    return 0;
}

fn portText(arena: Allocator, port: u16) []const u8 {
    return std.fmt.allocPrint(arena, "{d}", .{port}) catch "?";
}

const Listener = struct { fd: linux.fd_t, to: u16 };

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
        const rc4 = linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
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
    const nfds = 1 + listeners.len + 2 * max_conns;
    const fds = arena.alloc(linux.pollfd, nfds) catch sandbox.oom();
    while (true) {
        fds[0] = .{ .fd = 0, .events = linux.POLL.IN, .revents = 0 };
        for (listeners, fds[1..][0..listeners.len]) |l, *p|
            p.* = .{ .fd = l.fd, .events = linux.POLL.IN, .revents = 0 };
        const conn_fds = fds[1 + listeners.len ..];
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
        for (listeners, fds[1..][0..listeners.len]) |l, p| if (p.revents != 0) accept(conns, l);
        for (conns, 0..) |*c, i| if (c.used) {
            if (!step(c, conn_fds[2 * i ..][0..2])) c.close();
        };
    }
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
            break :done linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
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
    var buf: [16]u8 = undefined;
    const n = child.stdout.?.readStreaming(io, &.{&buf}) catch 0;
    if (n > 0 and std.mem.startsWith(u8, buf[0..n], "ready"))
        return .{ .child = child, .lifeline = lifeline };
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
    _ = linux.getsockname(server, @ptrCast(&sa), &len);
    const to = std.mem.bigToNative(u16, sa.port);
    // A free port to publish it on.
    const probe = listen(0, false) orelse return error.SkipZigTest;
    _ = linux.getsockname(probe, @ptrCast(&sa), &len);
    const from = std.mem.bigToNative(u16, sa.port);
    _ = linux.close(probe);
    var why: []const u8 = "";
    var r = try start(arena, io, exe, .{ .ports = &.{.{ .host = from, .container = to }} }, &why);
    defer r.stop(io);
    const client = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    defer _ = linux.close(@intCast(client));
    var dest = loopback4(from);
    const connected = linux.connect(@intCast(client), @ptrCast(&dest), @sizeOf(linux.sockaddr.in));
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
    _ = linux.getsockname(taken, @ptrCast(&sa), &len);
    const port = std.mem.bigToNative(u16, sa.port);
    var why: []const u8 = "";
    try std.testing.expectError(error.ForwardFailed, start(arena, io, exe, .{
        .ports = &.{.{ .host = port, .container = 1 }},
    }, &why));
    try std.testing.expect(std.mem.indexOf(u8, why, "listen on 127.0.0.1 port") != null);
}
