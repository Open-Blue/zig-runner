//! A Docker-compatible API for one native job (issue #448): a unix socket in the job's directory,
//! bound into every step at `/var/run/docker.sock`, and a thread of the runner that answers on it.
//!
//! Stage 1a is the skeleton, so that a step's `docker` CLI finds a server, says what it is and
//! learns plainly what is not there yet:
//!
//!   GET|HEAD /_ping      `OK`, with `API-Version`, `Builder-Version: 1` and `OSType: linux`
//!   GET /version, /info  JSON a real `docker version` and `docker info` print
//!   POST /build          501 "not supported by zig-runner yet (stage 1b)"
//!   /grpc, /session, /build?version=2
//!                        501 with the BuildKit hint (the classic builder is the first stage)
//!   anything else        501 `{"message":"not supported by zig-runner yet: <METHOD> <path>"}`
//!
//! An optional `/v1.NN` prefix is stripped (1.24 to 1.52 are served; others get Docker's own 400).
//!
//! The server never hangs and never trusts the client: a connection is one thread (at most
//! `Limits.max_connections` at a time, the next is told 503), every wait is a `poll` with a
//! deadline (a request's head must arrive within `header_ms` of its first byte, a kept connection
//! may idle `idle_ms`, a write may take `write_ms`), a request head is at most `header_bytes`, a
//! malformed one gets 400 and a closed connection, and the body of a request is never held: it is
//! read and dropped (up to `drain_bytes` or `drain_ms`) after the answer, which closes the
//! connection. `stop` wakes every thread through one eventfd and joins them all.
//!
//! The socket is made `0666`: a step's user is another one of the host's (a user namespace's), and
//! what protects it is that only the job's own steps have it in their root, and the job's
//! directory (`Store.secure`) is not the host's to walk.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;

/// The newest API version served, answered as `API-Version`.
pub const api_version = "1.52";
/// The oldest one a request's `/vX.Y` prefix may name, as Docker 29's daemon accepts.
pub const min_api_version = "1.24";
const newest_minor = 52;
const oldest_minor = 24;

/// Where the socket is bound inside every step.
pub const socket_at = "/var/run/docker.sock";
/// What the job's steps get in their environment (a workflow's own `env:` wins).
pub const env_host = "unix://" ++ socket_at;

pub const buildkit_hint = "BuildKit is not supported by zig-runner yet; DOCKER_BUILDKIT=0 is set " ++
    "for you, and docker buildx / docker/build-push-action need a later stage";
pub const build_stage_1b = "not supported by zig-runner yet (stage 1b)";

pub const Limits = struct {
    /// The most bytes of a request's line and headers.
    header_bytes: usize = 16 * 1024,
    /// The longest target (path and query) of a request line.
    target_bytes: usize = 4096,
    /// From a request's first byte to the end of its head.
    header_ms: u32 = 10_000,
    /// A connection kept open between requests.
    idle_ms: u32 = 15_000,
    /// One write of an answer, every wait in it together.
    write_ms: u32 = 10_000,
    /// What of a request's body is read and dropped after the answer, and how long that may take.
    drain_bytes: usize = 8 * 1024 * 1024,
    drain_ms: u32 = 2_000,
    /// Requests answered on one connection.
    max_requests: u32 = 1000,
    max_connections: usize = 8,
};

pub const Config = struct {
    /// The job, named in `/info` (`Name`) and in the log line.
    job: []const u8,
    /// The runner's version, as `--version` prints it.
    version: []const u8,
    limits: Limits = .{},
};

/// What a job did with its API, said once when the job ends (`Server.stop`).
pub const Stats = struct {
    connections: u32 = 0,
    requests: u32 = 0,
    /// Answered 501: the endpoint is not there yet.
    unsupported: u32 = 0,
    /// Answered 4xx: malformed, too large, too slow, a version out of range.
    refused: u32 = 0,
    /// The ones of those that were a timeout.
    timeouts: u32 = 0,
    /// Turned away for want of a free connection.
    busy: u32 = 0,
};

pub const Server = struct {
    gpa: Allocator,
    cfg: Config,
    path: []const u8,
    listen_fd: linux.fd_t,
    /// Readable for good once `stop` is called.
    wake_fd: linux.fd_t,
    thread: std.Thread = undefined,
    slots: []Slot,
    counters: struct {
        connections: std.atomic.Value(u32) = .init(0),
        requests: std.atomic.Value(u32) = .init(0),
        unsupported: std.atomic.Value(u32) = .init(0),
        refused: std.atomic.Value(u32) = .init(0),
        timeouts: std.atomic.Value(u32) = .init(0),
        busy: std.atomic.Value(u32) = .init(0),
    } = .{},

    const Slot = struct {
        thread: ?std.Thread = null,
        done: std.atomic.Value(bool) = .init(false),
        server: *Server = undefined,
        fd: linux.fd_t = -1,
    };

    /// Listens on a socket made at `path` (made `0666`) and answers on a thread of its own. The
    /// socket's file is removed by `stop`.
    pub fn start(gpa: Allocator, path: []const u8, cfg: Config) !*Server {
        const lfd = try listenAt(path);
        errdefer {
            _ = linux.close(lfd);
            unlinkPath(path);
        }
        const wfd = try fdOf(linux.eventfd(0, linux.EFD.CLOEXEC));
        errdefer _ = linux.close(wfd);
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        const slots = try gpa.alloc(Slot, cfg.limits.max_connections);
        errdefer gpa.free(slots);
        const owned = try gpa.dupe(u8, path);
        errdefer gpa.free(owned);
        var own_cfg = cfg;
        own_cfg.job = try gpa.dupe(u8, cfg.job);
        errdefer gpa.free(own_cfg.job);
        own_cfg.version = try gpa.dupe(u8, cfg.version);
        errdefer gpa.free(own_cfg.version);
        for (slots) |*sl| sl.* = .{};
        s.* = .{
            .gpa = gpa,
            .cfg = own_cfg,
            .path = owned,
            .listen_fd = lfd,
            .wake_fd = wfd,
            .slots = slots,
        };
        s.thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, acceptLoop, .{s});
        return s;
    }

    /// Wakes and joins every thread, removes the socket and frees the server. What the job did.
    pub fn stop(s: *Server) Stats {
        const one: u64 = 1;
        _ = linux.write(s.wake_fd, std.mem.asBytes(&one).ptr, @sizeOf(u64));
        s.thread.join();
        const st = s.stats();
        _ = linux.close(s.listen_fd);
        _ = linux.close(s.wake_fd);
        unlinkPath(s.path);
        const gpa = s.gpa;
        gpa.free(s.path);
        gpa.free(s.cfg.job);
        gpa.free(s.cfg.version);
        gpa.free(s.slots);
        gpa.destroy(s);
        return st;
    }

    pub fn stats(s: *const Server) Stats {
        const c = &s.counters;
        return .{
            .connections = c.connections.load(.acquire),
            .requests = c.requests.load(.acquire),
            .unsupported = c.unsupported.load(.acquire),
            .refused = c.refused.load(.acquire),
            .timeouts = c.timeouts.load(.acquire),
            .busy = c.busy.load(.acquire),
        };
    }

    fn bump(s: *Server, comptime field: []const u8) void {
        _ = @field(s.counters, field).fetchAdd(1, .acq_rel);
    }

    fn acceptLoop(s: *Server) void {
        defer for (s.slots) |*sl| if (sl.thread) |t| {
            t.join();
            sl.thread = null;
        };
        while (true) {
            var fds = [_]linux.pollfd{
                .{ .fd = s.listen_fd, .events = linux.POLL.IN, .revents = 0 },
                .{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 },
            };
            const rc = linux.poll(&fds, fds.len, -1);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return,
            }
            if (fds[1].revents != 0) return;
            if (fds[0].revents & linux.POLL.IN == 0) {
                if (fds[0].revents != 0) return;
                continue;
            }
            // A refusal (a connection that went, no descriptors left) is tried again when the next
            // one arrives.
            const fd = fdOf(linux.accept4(s.listen_fd, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK)) catch continue;
            s.bump("connections");
            const slot = s.freeSlot() orelse {
                s.bump("busy");
                s.bump("refused");
                // One short write into a fresh socket's buffer: it cannot block.
                if (sendAll(s, fd, busy_answer, 100)) {} else |_| {} // the peer going is no matter
                _ = linux.close(fd);
                continue;
            };
            slot.* = .{ .server = s, .fd = fd };
            slot.thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, connection, .{slot}) catch {
                _ = linux.close(fd);
                continue;
            };
        }
    }

    /// A slot with no thread, after the finished ones were joined.
    fn freeSlot(s: *Server) ?*Slot {
        var free: ?*Slot = null;
        for (s.slots) |*sl| {
            if (sl.thread) |t| if (sl.done.load(.acquire)) {
                t.join();
                sl.thread = null;
            };
            if (sl.thread == null and free == null) free = sl;
        }
        if (free) |f| f.done.store(false, .release);
        return free;
    }
};

const busy_answer = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n" ++
    "Content-Length: 46\r\nConnection: close\r\n\r\n" ++
    "{\"message\":\"too many connections to the API\"}\n";

// --- the socket ---

/// The descriptor a syscall returned, or its failure.
fn fdOf(rc: usize) error{Syscall}!linux.fd_t {
    if (linux.errno(rc) != .SUCCESS) return error.Syscall;
    return std.math.cast(linux.fd_t, rc) orelse error.Syscall;
}

/// A socket address as `bind` takes it (`sockaddr`) and as it is made (`sockaddr.un`).
const Addr = extern union { base: linux.sockaddr, un: linux.sockaddr.un };

/// A listening unix socket at `path`, `0666`. A path past `sun_path` is bound through the
/// directory's descriptor (`/proc/self/fd/N/name`).
fn listenAt(path: []const u8) !linux.fd_t {
    const fd = try fdOf(linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0));
    errdefer _ = linux.close(fd);
    var guard: DirFd = .{};
    defer guard.close();
    const addr = try unixAddr(path, &guard);
    const as_base: Addr = .{ .un = addr };
    switch (linux.errno(linux.bind(fd, &as_base.base, @sizeOf(linux.sockaddr.un)))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        else => return error.Bind,
    }
    errdefer unlinkPath(path);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = zpath(&buf, "{s}", .{path}) catch return error.NameTooLong;
    if (linux.errno(linux.chmod(z, 0o666)) != .SUCCESS) return error.Chmod;
    if (linux.errno(linux.listen(fd, 16)) != .SUCCESS) return error.Listen;
    return fd;
}

/// An O_PATH descriptor of a socket's directory, held while a long path is used through it.
const DirFd = struct {
    fd: linux.fd_t = -1,

    fn close(g: *DirFd) void {
        if (g.fd >= 0) _ = linux.close(g.fd);
        g.fd = -1;
    }
};

fn unixAddr(path: []const u8, guard: *DirFd) !linux.sockaddr.un {
    var addr: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len < addr.path.len) {
        @memcpy(addr.path[0..path.len], path);
        return addr;
    }
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.NameTooLong;
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = zpath(&dir_buf, "{s}", .{if (slash == 0) "/" else path[0..slash]}) catch
        return error.NameTooLong;
    guard.fd = fdOf(linux.open(dir, .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0)) catch
        return error.NameTooLong;
    const via = std.fmt.bufPrint(&addr.path, "/proc/self/fd/{d}/{s}", .{ guard.fd, path[slash + 1 ..] }) catch
        return error.NameTooLong;
    addr.path[via.len] = 0;
    return addr;
}

/// `text` in `buf`, null-terminated.
fn zpath(buf: []u8, comptime fmt: []const u8, args: anytype) ![:0]u8 {
    const s = try std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt, args);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

fn unlinkPath(path: []const u8) void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = zpath(&buf, "{s}", .{path}) catch return;
    _ = linux.unlink(z);
}

/// A connection to the socket at `path`, blocking: for the runner's tests, and a client's probe.
pub fn connect(path: []const u8) !linux.fd_t {
    const fd = try fdOf(linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0));
    errdefer _ = linux.close(fd);
    var guard: DirFd = .{};
    defer guard.close();
    const addr = try unixAddr(path, &guard);
    if (linux.errno(linux.connect(fd, &addr, @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.Connect;
    return fd;
}

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return std.math.lossyCast(u64, ts.sec) * 1000 + std.math.lossyCast(u64, ts.nsec) / 1_000_000;
}

const Wait = enum { ready, timeout, stopped, gone };

/// Waits for `fd` to be readable (or writable) until `deadline` (milliseconds of `nowMs`), or for
/// the server's stop.
fn waitFor(s: *const Server, fd: linux.fd_t, events: i16, deadline: u64) Wait {
    while (true) {
        const now = nowMs();
        if (now >= deadline) return .timeout;
        var fds = [_]linux.pollfd{
            .{ .fd = fd, .events = events, .revents = 0 },
            .{ .fd = s.wake_fd, .events = linux.POLL.IN, .revents = 0 },
        };
        const left = std.math.lossyCast(i32, deadline - now);
        const rc = linux.poll(&fds, fds.len, left);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return .gone,
        }
        if (fds[1].revents != 0) return .stopped;
        if (fds[0].revents & (events | linux.POLL.HUP | linux.POLL.ERR) != 0) return .ready;
    }
}

/// All of `bytes`, in `write_ms`.
fn sendAll(s: *Server, fd: linux.fd_t, bytes: []const u8, write_ms: u32) error{ Timeout, Gone }!void {
    const deadline = nowMs() + write_ms;
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.sendto(fd, bytes[off..].ptr, bytes.len - off, linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => {},
            .AGAIN => switch (waitFor(s, fd, linux.POLL.OUT, deadline)) {
                .ready => {},
                .timeout => return error.Timeout,
                .stopped, .gone => return error.Gone,
            },
            else => return error.Gone,
        }
    }
}

// --- one connection ---

fn connection(slot: *Server.Slot) void {
    const s = slot.server;
    defer {
        _ = linux.close(slot.fd);
        slot.done.store(true, .release);
    }
    var arena: std.heap.ArenaAllocator = .init(s.gpa);
    defer arena.deinit();
    serve(s, slot.fd, &arena);
}

fn serve(s: *Server, fd: linux.fd_t, arena: *std.heap.ArenaAllocator) void {
    const lim = s.cfg.limits;
    const head_buf = s.gpa.alloc(u8, lim.header_bytes) catch return;
    defer s.gpa.free(head_buf);
    var have: usize = 0;
    var served: u32 = 0;
    while (served < lim.max_requests) {
        _ = arena.reset(.retain_capacity);
        // The head: to its blank line, in `header_ms` from its first byte (`idle_ms` for that).
        var deadline = nowMs() + lim.idle_ms;
        var started = have > 0;
        if (started) deadline = nowMs() + lim.header_ms;
        const end = while (true) {
            if (std.mem.indexOf(u8, head_buf[0..have], "\r\n\r\n")) |i| break i + 4;
            if (have == head_buf.len) {
                _ = reply(s, fd, arena.allocator(), 431, error_json(arena.allocator(), "request header too large"), false, false);
                return;
            }
            switch (waitFor(s, fd, linux.POLL.IN, deadline)) {
                .ready => {},
                .timeout => {
                    if (started) {
                        s.bump("timeouts");
                        _ = reply(s, fd, arena.allocator(), 408, error_json(arena.allocator(), "request timeout"), false, false);
                    }
                    return;
                },
                .stopped, .gone => return,
            }
            const rc = linux.recvfrom(fd, head_buf[have..].ptr, head_buf.len - have, linux.MSG.DONTWAIT, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => return,
            }
            if (rc == 0) return;
            have += rc;
            if (!started) {
                started = true;
                deadline = nowMs() + lim.header_ms;
            }
        };
        const a = arena.allocator();
        const req = parseHead(head_buf[0..end], lim) catch |e| {
            s.bump("refused");
            _ = s.counters.requests.fetchAdd(1, .acq_rel);
            const status: u16 = if (e == error.TargetTooLong) 414 else 400;
            _ = reply(s, fd, a, status, error_json(a, switch (e) {
                error.TargetTooLong => "request target too long",
                else => "malformed HTTP request",
            }), false, false);
            return;
        };
        s.bump("requests");
        served += 1;
        const has_body = req.chunked or (req.content_length orelse 0) > 0;
        const answer = route(a, s.cfg, req.method, req.target) catch Answer.oom;
        switch (answer.status) {
            501 => s.bump("unsupported"),
            400...499 => s.bump("refused"),
            else => {},
        }
        // A request with a body is answered and the connection closed: the body is not kept.
        const keep = req.keep_alive and !has_body and served < lim.max_requests;
        if (!reply(s, fd, a, answer.status, answer, req.head_only, keep)) return;
        if (!keep) {
            if (has_body) drain(s, fd, lim);
            return;
        }
        // What came after the head (a pipelined request) stays for the next round.
        std.mem.copyForwards(u8, head_buf[0 .. have - end], head_buf[end..have]);
        have -= end;
    }
}

/// Reads and drops what the client is still sending, so that closing does not reset the
/// connection with our answer unread (the CLI sends a build's context while reading the answer).
fn drain(s: *Server, fd: linux.fd_t, lim: Limits) void {
    _ = linux.shutdown(fd, linux.SHUT.WR);
    const deadline = nowMs() + lim.drain_ms;
    var left = lim.drain_bytes;
    var junk: [4096]u8 = undefined;
    while (left > 0) {
        if (waitFor(s, fd, linux.POLL.IN, deadline) != .ready) return;
        const rc = linux.recvfrom(fd, &junk, junk.len, linux.MSG.DONTWAIT, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            else => return,
        }
        if (rc == 0) return;
        left -|= rc;
    }
}

// --- requests ---

const Request = struct {
    method: []const u8,
    target: []const u8,
    content_length: ?u64 = null,
    chunked: bool = false,
    keep_alive: bool = true,
    head_only: bool = false,
};

const ParseError = error{ Malformed, TargetTooLong };

/// The request line and headers of `head` (to and with its blank line). The slices are in `head`.
fn parseHead(head: []const u8, lim: Limits) ParseError!Request {
    var lines = std.mem.splitSequence(u8, head[0 .. head.len - 4], "\r\n");
    const line = lines.next().?;
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next().?;
    const target = parts.next() orelse return error.Malformed;
    const version = parts.next() orelse return error.Malformed;
    if (parts.next() != null) return error.Malformed;
    if (method.len == 0 or method.len > 16) return error.Malformed;
    for (method) |ch| if (!std.ascii.isUpper(ch)) return error.Malformed;
    if (target.len == 0 or target[0] != '/') return error.Malformed;
    if (target.len > lim.target_bytes) return error.TargetTooLong;
    for (target) |ch| if (ch <= ' ' or ch == 127) return error.Malformed;
    const http11 = std.mem.eql(u8, version, "HTTP/1.1");
    if (!http11 and !std.mem.eql(u8, version, "HTTP/1.0")) return error.Malformed;
    var req: Request = .{
        .method = method,
        .target = target,
        .keep_alive = http11,
        .head_only = std.mem.eql(u8, method, "HEAD"),
    };
    var host = false;
    while (lines.next()) |h| {
        // No folded lines, no bare line feeds or control characters: a smuggler's tools.
        for (h) |ch| if ((ch < ' ' and ch != '\t') or ch == 127) return error.Malformed;
        const colon = std.mem.indexOfScalar(u8, h, ':') orelse return error.Malformed;
        const name = h[0..colon];
        if (name.len == 0) return error.Malformed;
        for (name) |ch| if (!isTokenChar(ch)) return error.Malformed;
        const value = std.mem.trim(u8, h[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const n = std.fmt.parseInt(u64, value, 10) catch return error.Malformed;
            if (req.content_length) |old| if (old != n) return error.Malformed;
            req.content_length = n;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.Malformed;
            req.chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.findIgnoreCase(value, "close") != null) req.keep_alive = false;
            if (!http11 and std.ascii.findIgnoreCase(value, "keep-alive") != null) req.keep_alive = true;
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            host = true;
        }
    }
    if (req.chunked and req.content_length != null) return error.Malformed;
    // Docker's client sends one; HTTP/1.1 requires it.
    if (http11 and !host) return error.Malformed;
    return req;
}

fn isTokenChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", ch) != null;
}

// --- answers ---

const Answer = struct {
    status: u16,
    body: []const u8,
    content_type: []const u8 = "application/json",
    /// Only on /_ping: Docker's headers (the others carry them too, as the daemon's do).
    const oom: Answer = .{ .status = 500, .body = "{\"message\":\"out of memory\"}\n" };
};

fn error_json(a: Allocator, message: []const u8) Answer {
    return .{ .status = 0, .body = jsonMessage(a, message) catch "{\"message\":\"error\"}\n" };
}

/// `{"message":<message>}` and a newline, as Docker's daemon writes its errors.
fn jsonMessage(a: Allocator, message: []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    try out.writer.writeAll("{\"message\":");
    try std.json.Stringify.value(message, .{}, &out.writer);
    try out.writer.writeAll("}\n");
    return out.written();
}

fn failure(a: Allocator, status: u16, message: []const u8) !Answer {
    return .{ .status = status, .body = try jsonMessage(a, message) };
}

fn reasonOf(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        400 => "Bad Request",
        408 => "Request Timeout",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        else => "Error",
    };
}

/// The prefix `/vMAJOR.MINOR` of `path`, if it has one: its version, and the path after it.
const Versioned = struct { major: u32, minor: u32, rest: []const u8 };

fn versionPrefix(path: []const u8) ?Versioned {
    if (path.len < 4 or path[0] != '/' or path[1] != 'v') return null;
    const end = std.mem.indexOfScalarPos(u8, path, 1, '/') orelse path.len;
    const ver = path[2..end];
    const dot = std.mem.indexOfScalar(u8, ver, '.') orelse return null;
    const major = std.fmt.parseInt(u32, ver[0..dot], 10) catch return null;
    const minor = std.fmt.parseInt(u32, ver[dot + 1 ..], 10) catch return null;
    return .{ .major = major, .minor = minor, .rest = path[end..] };
}

/// What `method target` is answered, for the server's config. A status of 0 in an `Answer` the
/// caller makes itself (`error_json`) stands for the one it gives.
fn route(a: Allocator, cfg: Config, method: []const u8, target: []const u8) !Answer {
    const q = std.mem.indexOfScalar(u8, target, '?');
    var path = target[0 .. q orelse target.len];
    const query = if (q) |i| target[i + 1 ..] else "";
    if (versionPrefix(path)) |v| {
        if (v.major != 1 or v.minor > newest_minor) return failure(a, 400, try std.fmt.allocPrint(
            a,
            "client version {d}.{d} is too new. Maximum supported API version is " ++ api_version,
            .{ v.major, v.minor },
        ));
        if (v.minor < oldest_minor) return failure(a, 400, try std.fmt.allocPrint(
            a,
            "client version {d}.{d} is too old. Minimum supported API version is " ++
                min_api_version ++ ", please upgrade your client to a newer version",
            .{ v.major, v.minor },
        ));
        path = if (v.rest.len == 0) "/" else v.rest;
    }
    const is_get = std.mem.eql(u8, method, "GET");
    if ((is_get or std.mem.eql(u8, method, "HEAD")) and std.mem.eql(u8, path, "/_ping"))
        return .{ .status = 200, .body = "OK", .content_type = "text/plain; charset=utf-8" };
    if (is_get and std.mem.eql(u8, path, "/version")) return .{ .status = 200, .body = try versionJson(a, cfg) };
    if (is_get and std.mem.eql(u8, path, "/info")) return .{ .status = 200, .body = try infoJson(a, cfg) };
    // `docker buildx build` looks for its builder's container (`buildx_buildkit_<name>`) first.
    if (std.mem.eql(u8, path, "/grpc") or std.mem.eql(u8, path, "/session") or
        std.mem.startsWith(u8, path, "/containers/buildx_buildkit"))
        return failure(a, 501, buildkit_hint);
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/build")) {
        var params = std.mem.splitScalar(u8, query, '&');
        while (params.next()) |p| if (std.mem.eql(u8, p, "version=2"))
            return failure(a, 501, buildkit_hint);
        return failure(a, 501, build_stage_1b);
    }
    const shown = if (path.len > 200) path[0..200] else path;
    return failure(a, 501, try std.fmt.allocPrint(
        a,
        "not supported by zig-runner yet: {s} {s}",
        .{ if (method.len > 16) method[0..16] else method, shown },
    ));
}

/// `{}` where a struct's field must be an object and an empty tuple would be `[]`.
const empty_object = struct {}{};

fn archName() []const u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @tagName(builtin.cpu.arch),
    };
}

fn kernelOf() struct { release: [64:0]u8, host: [64:0]u8 } {
    var u: linux.utsname = undefined;
    if (linux.errno(linux.uname(&u)) != .SUCCESS) return .{ .release = @splat(0), .host = @splat(0) };
    return .{ .release = u.release, .host = u.nodename };
}

fn cstr(buf: *const [64:0]u8) []const u8 {
    return std.mem.sliceTo(buf, 0);
}

fn versionJson(a: Allocator, cfg: Config) ![]const u8 {
    const k = kernelOf();
    const kernel = cstr(&k.release);
    const version = std.mem.trimStart(u8, cfg.version, "v");
    const details = .{
        .ApiVersion = api_version,
        .Arch = archName(),
        .BuildTime = "",
        .Experimental = "false",
        .GitCommit = "",
        .GoVersion = "",
        .KernelVersion = kernel,
        .MinAPIVersion = min_api_version,
        .Os = "linux",
    };
    var out: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{
        .Platform = .{ .Name = "zig-runner" },
        .Components = .{.{ .Name = "Engine", .Version = version, .Details = details }},
        .Version = version,
        .ApiVersion = api_version,
        .MinAPIVersion = min_api_version,
        .GitCommit = "",
        .GoVersion = "",
        .Os = "linux",
        .Arch = archName(),
        .KernelVersion = kernel,
        .BuildTime = "",
    }, .{}, &out.writer);
    try out.writer.writeByte('\n');
    return out.written();
}

fn infoJson(a: Allocator, cfg: Config) ![]const u8 {
    const k = kernelOf();
    var si: linux.Sysinfo = undefined;
    const mem: u64 = if (linux.errno(linux.sysinfo(&si)) == .SUCCESS) @as(u64, si.totalram) * si.mem_unit else 0;
    const cpus: usize = std.Thread.getCpuCount() catch 1;
    const version = std.mem.trimStart(u8, cfg.version, "v");
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    const secs: std.time.epoch.EpochSeconds = .{ .secs = std.math.lossyCast(u64, ts.sec) };
    const day = secs.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const clock = secs.getDaySeconds();
    const now_text = try std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        day.year,                month.month.numeric(),      month.day_index + 1,
        clock.getHoursIntoDay(), clock.getMinutesIntoHour(), clock.getSecondsIntoMinute(),
    });
    var out: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{
        .ID = cfg.job,
        .Containers = 0,
        .ContainersRunning = 0,
        .ContainersPaused = 0,
        .ContainersStopped = 0,
        .Images = 0,
        .Driver = "overlay2",
        .DriverStatus = [_][2][]const u8{},
        .Plugins = .{
            .Volume = [_][]const u8{"local"},
            .Network = [_][]const u8{ "bridge", "host", "null" },
            .Authorization = null,
            .Log = [_][]const u8{"local"},
        },
        .MemoryLimit = true,
        .SwapLimit = false,
        .CpuCfsPeriod = true,
        .CpuCfsQuota = true,
        .CPUShares = true,
        .CPUSet = true,
        .PidsLimit = true,
        .IPv4Forwarding = true,
        .Debug = false,
        .NFd = 0,
        .OomKillDisable = true,
        .NGoroutines = 0,
        .SystemTime = now_text,
        .LoggingDriver = "local",
        .CgroupDriver = "cgroupfs",
        .CgroupVersion = "2",
        .NEventsListener = 0,
        .KernelVersion = cstr(&k.release),
        .OperatingSystem = "zig-runner",
        .OSVersion = "",
        .OSType = "linux",
        .Architecture = if (builtin.cpu.arch == .x86_64) "x86_64" else if (builtin.cpu.arch == .aarch64) "aarch64" else archName(),
        .IndexServerAddress = "https://index.docker.io/v1/",
        .RegistryConfig = .{
            .InsecureRegistryCIDRs = [_][]const u8{"127.0.0.0/8"},
            .IndexConfigs = empty_object,
            .Mirrors = null,
        },
        .NCPU = cpus,
        .MemTotal = mem,
        .GenericResources = null,
        .DockerRootDir = "/var/lib/docker",
        .HttpProxy = "",
        .HttpsProxy = "",
        .NoProxy = "",
        .Name = cstr(&k.host),
        .Labels = [_][]const u8{},
        .ExperimentalBuild = false,
        .ServerVersion = version,
        .Runtimes = .{ .@"io.containerd.runc.v2" = .{ .path = "runc" }, .runc = .{ .path = "runc" } },
        .DefaultRuntime = "runc",
        .Swarm = .{
            .NodeID = "",
            .NodeAddr = "",
            .LocalNodeState = "inactive",
            .ControlAvailable = false,
            .Error = "",
            .RemoteManagers = null,
        },
        .LiveRestoreEnabled = false,
        .Isolation = "",
        .InitBinary = "docker-init",
        .SecurityOptions = [_][]const u8{ "name=seccomp,profile=builtin", "name=cgroupns" },
        .Warnings = [_][]const u8{
            "zig-runner serves a Docker-compatible API for this job; only /_ping, /version and /info are implemented so far (a build comes with stage 1b)",
        },
    }, .{}, &out.writer);
    try out.writer.writeByte('\n');
    return out.written();
}

/// Writes `answer` (a status of 0 for an `error_json`, the one it was made for: 400). Returns
/// false when the connection is gone.
fn reply(s: *Server, fd: linux.fd_t, a: Allocator, status: u16, answer: Answer, head_only: bool, keep: bool) bool {
    const code = if (answer.status == 0) status else answer.status;
    var out: std.Io.Writer.Allocating = .init(a);
    out.writer.print(
        "HTTP/1.1 {d} {s}\r\nApi-Version: " ++ api_version ++ "\r\nBuilder-Version: 1\r\n" ++
            "Docker-Experimental: false\r\nOstype: linux\r\nServer: zig-runner/{s} (linux)\r\n" ++
            "Content-Type: {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\n\r\n",
        .{
            code,
            reasonOf(code),
            std.mem.trimStart(u8, s.cfg.version, "v"),
            answer.content_type,
            answer.body.len,
            if (keep) "keep-alive" else "close",
        },
    ) catch return false;
    if (!head_only) out.writer.writeAll(answer.body) catch return false;
    sendAll(s, fd, out.written(), s.cfg.limits.write_ms) catch |e| {
        if (e == error.Timeout) s.bump("timeouts");
        return false;
    };
    return true;
}

// --- tests ---

const testing = std.testing;

fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    const out = comptime blk: {
        @setEvalBranchQuota(200_000);
        var o: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(o[i * s.len ..][0..s.len], s);
        break :blk o;
    };
    return &out;
}

const test_cfg: Config = .{ .job = "0123456789abcdef", .version = "v9.9.9-test" };

/// A server on a socket in a fresh temporary directory.
const Fixture = struct {
    tmp: std.testing.TmpDir,
    path: []const u8,
    server: *Server,

    fn start(cfg: Config) !Fixture {
        var f: Fixture = .{ .tmp = std.testing.tmpDir(.{}), .path = "", .server = undefined };
        errdefer f.tmp.cleanup();
        const dir = try f.tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
        defer testing.allocator.free(dir);
        f.path = try std.fmt.allocPrint(testing.allocator, "{s}/docker.sock", .{dir});
        errdefer testing.allocator.free(f.path);
        f.server = try Server.start(testing.allocator, f.path, cfg);
        return f;
    }

    fn finish(f: *Fixture) Stats {
        const st = f.server.stop();
        testing.allocator.free(f.path);
        f.tmp.cleanup();
        return st;
    }
};

/// Sends `request` and reads until the server closes or `ms` pass with nothing more.
/// Returns what came, and whether the server closed the connection.
const Heard = struct { text: []u8, closed: bool };

fn ask(path: []const u8, request: []const u8, ms: u32) !Heard {
    const fd = try connect(path);
    defer _ = linux.close(fd);
    return askOn(fd, request, ms);
}

fn askOn(fd: linux.fd_t, request: []const u8, ms: u32) !Heard {
    if (request.len > 0) _ = linux.sendto(fd, request.ptr, request.len, linux.MSG.NOSIGNAL, null, 0);
    var got: std.ArrayList(u8) = .empty;
    errdefer got.deinit(testing.allocator);
    var closed = false;
    const end = nowMs() + ms;
    while (nowMs() < end) {
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const left = std.math.lossyCast(i32, end - nowMs());
        if (linux.poll(&fds, 1, left) == 0) break;
        var buf: [8192]u8 = undefined;
        const rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(rc) != .SUCCESS or rc == 0) {
            closed = true;
            break;
        }
        try got.appendSlice(testing.allocator, buf[0..rc]);
        // An answer with its whole body is enough when the server keeps the connection.
        if (completeAnswer(got.items) and std.mem.indexOf(u8, got.items, "Connection: close") == null) break;
    }
    return .{ .text = try got.toOwnedSlice(testing.allocator), .closed = closed };
}

fn completeAnswer(text: []const u8) bool {
    const head_end = std.mem.indexOf(u8, text, "\r\n\r\n") orelse return false;
    const key = "Content-Length: ";
    const at = std.mem.indexOf(u8, text[0..head_end], key) orelse return false;
    const stop = std.mem.indexOfScalarPos(u8, text, at, '\r') orelse return false;
    const n = std.fmt.parseInt(usize, text[at + key.len .. stop], 10) catch return false;
    if (std.mem.startsWith(u8, text, "HEAD")) return true;
    return text.len == head_end + 4 + n;
}

fn bodyOf(text: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, text, "\r\n\r\n") orelse return "";
    return text[i + 4 ..];
}

fn statusOf(text: []const u8) u16 {
    if (text.len < 12) return 0;
    return std.fmt.parseInt(u16, text[9..12], 10) catch 0;
}

fn get(path: []const u8, target: []const u8) ![]u8 {
    const req = try std.fmt.allocPrint(testing.allocator, "GET {s} HTTP/1.1\r\nHost: docker\r\n\r\n", .{target});
    defer testing.allocator.free(req);
    const r = try ask(path, req, 3000);
    return r.text;
}

fn expectContains(hay: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, hay, needle) == null) {
        std.debug.print("ERROR: {s} is not in:\n{s}\n", .{ needle, hay });
        return error.TestExpectedContains;
    }
}

test "docker api: /_ping answers OK with Docker's headers, with and without a version prefix" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    for ([_][]const u8{ "/_ping", "/v1.24/_ping", "/v1.41/_ping", "/v1.52/_ping" }) |target| {
        const text = try get(f.path, target);
        defer testing.allocator.free(text);
        try testing.expectEqual(@as(u16, 200), statusOf(text));
        try testing.expectEqualStrings("OK", bodyOf(text));
        try expectContains(text, "Api-Version: 1.52\r\n");
        try expectContains(text, "Builder-Version: 1\r\n");
        try expectContains(text, "Ostype: linux\r\n");
        try expectContains(text, "Content-Length: 2\r\n");
    }
}

test "docker api: HEAD /_ping has the headers and no body" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const r = try ask(f.path, "HEAD /_ping HTTP/1.1\r\nHost: docker\r\n\r\n", 300);
    defer testing.allocator.free(r.text);
    try testing.expectEqual(@as(u16, 200), statusOf(r.text));
    try expectContains(r.text, "Content-Length: 2\r\n");
    try testing.expectEqualStrings("", bodyOf(r.text));
}

test "docker api: /version and /info are the JSON the docker CLI reads" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const v = try get(f.path, "/v1.45/version");
    defer testing.allocator.free(v);
    try testing.expectEqual(@as(u16, 200), statusOf(v));
    try expectContains(v, "Content-Type: application/json\r\n");
    var pv = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(v), .{});
    defer pv.deinit();
    const vo = pv.value.object;
    try testing.expectEqualStrings("zig-runner", vo.get("Platform").?.object.get("Name").?.string);
    try testing.expectEqualStrings("9.9.9-test", vo.get("Version").?.string);
    try testing.expectEqualStrings("1.52", vo.get("ApiVersion").?.string);
    try testing.expectEqualStrings("1.24", vo.get("MinAPIVersion").?.string);
    try testing.expectEqualStrings("linux", vo.get("Os").?.string);
    try testing.expect(vo.get("Arch").?.string.len > 0);
    const comp = vo.get("Components").?.array.items[0].object;
    try testing.expectEqualStrings("Engine", comp.get("Name").?.string);
    try testing.expectEqualStrings("1.52", comp.get("Details").?.object.get("ApiVersion").?.string);

    const i = try get(f.path, "/info");
    defer testing.allocator.free(i);
    try testing.expectEqual(@as(u16, 200), statusOf(i));
    var pi = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(i), .{});
    defer pi.deinit();
    const io = pi.value.object;
    try testing.expectEqualStrings("0123456789abcdef", io.get("ID").?.string);
    try testing.expectEqualStrings("linux", io.get("OSType").?.string);
    try testing.expectEqualStrings("9.9.9-test", io.get("ServerVersion").?.string);
    try testing.expectEqualStrings("zig-runner", io.get("OperatingSystem").?.string);
    try testing.expect(io.get("NCPU").?.integer >= 1);
    try testing.expect(io.get("MemTotal").?.integer > 0);
    try testing.expect(io.get("Plugins").?.object.get("Volume") != null);
    try testing.expect(io.get("Swarm").?.object.get("LocalNodeState") != null);
    for ([_][]const u8{ "Driver", "DockerRootDir", "Name", "Architecture", "KernelVersion", "Runtimes", "DefaultRuntime" }) |k|
        try testing.expect(io.get(k) != null);
}

fn expectMessage(f: *Fixture, method: []const u8, target: []const u8, status: u16, message: []const u8) !void {
    const req = try std.fmt.allocPrint(testing.allocator, "{s} {s} HTTP/1.1\r\nHost: docker\r\n\r\n", .{ method, target });
    defer testing.allocator.free(req);
    const r = try ask(f.path, req, 3000);
    defer testing.allocator.free(r.text);
    try testing.expectEqual(status, statusOf(r.text));
    var p = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(r.text), .{});
    defer p.deinit();
    try testing.expectEqualStrings(message, p.value.object.get("message").?.string);
}

test "docker api: every other endpoint is 501 naming the method and the path" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const prefix = "not supported by zig-runner yet: ";
    try expectMessage(&f, "GET", "/containers/json", 501, prefix ++ "GET /containers/json");
    try expectMessage(&f, "POST", "/v1.43/containers/create?name=x", 501, prefix ++ "POST /containers/create");
    try expectMessage(&f, "DELETE", "/images/alpine", 501, prefix ++ "DELETE /images/alpine");
    try expectMessage(&f, "GET", "/v1.52/images/json", 501, prefix ++ "GET /images/json");
    try expectMessage(&f, "POST", "/_ping", 501, prefix ++ "POST /_ping");
    try expectMessage(&f, "GET", "/", 501, prefix ++ "GET /");
    try expectMessage(&f, "GET", "/v1.30", 501, prefix ++ "GET /");
    // A path with quotes and slashes stays valid JSON.
    try expectMessage(&f, "GET", "/a\"b\\c", 501, prefix ++ "GET /a\"b\\c");
}

test "docker api: BuildKit's endpoints get the hint, the classic /build says stage 1b" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    try expectMessage(&f, "POST", "/grpc", 501, buildkit_hint);
    try expectMessage(&f, "POST", "/v1.47/session", 501, buildkit_hint);
    try expectMessage(&f, "POST", "/build?version=2&t=x", 501, buildkit_hint);
    try expectMessage(&f, "GET", "/v1.52/containers/buildx_buildkit_default/json", 501, buildkit_hint);
    try expectMessage(&f, "POST", "/v1.41/build?t=x&dockerfile=Dockerfile", 501, build_stage_1b);
    try expectMessage(&f, "POST", "/build", 501, build_stage_1b);
    try testing.expect(std.mem.indexOf(u8, buildkit_hint, "DOCKER_BUILDKIT=0 is set for you") != null);
}

test "docker api: a version out of 1.24 to 1.52 is Docker's 400" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    try expectMessage(&f, "GET", "/v1.53/_ping", 400, "client version 1.53 is too new. Maximum supported API version is 1.52");
    try expectMessage(&f, "GET", "/v1.23/_ping", 400, "client version 1.23 is too old. Minimum supported API version is 1.24, please upgrade your client to a newer version");
    try expectMessage(&f, "GET", "/v2.0/_ping", 400, "client version 2.0 is too new. Maximum supported API version is 1.52");
    // Not a version prefix: just an unknown path.
    try expectMessage(&f, "GET", "/vault/x", 501, "not supported by zig-runner yet: GET /vault/x");
}

test "docker api: requests are kept alive and pipelined requests are all answered" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const one = try askOn(fd, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 3000);
    defer testing.allocator.free(one.text);
    try testing.expectEqual(@as(u16, 200), statusOf(one.text));
    try testing.expect(!one.closed);
    try expectContains(one.text, "Connection: keep-alive");
    const both = "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\nGET /nope HTTP/1.1\r\nHost: d\r\n\r\n";
    // The two answers may come in one read or in two: until both are in, or three seconds.
    var heard: std.ArrayList(u8) = .empty;
    defer heard.deinit(testing.allocator);
    const until = nowMs() + 3000;
    var first_round = true;
    while (std.mem.count(u8, heard.items, "HTTP/1.1 ") < 2 and nowMs() < until) {
        const part = try askOn(fd, if (first_round) both else "", 100);
        defer testing.allocator.free(part.text);
        first_round = false;
        try heard.appendSlice(testing.allocator, part.text);
    }
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, heard.items, "HTTP/1.1 "));
    try expectContains(heard.items, "GET /nope");
    const st = f.server.stats();
    try testing.expectEqual(@as(u32, 3), st.requests);
    try testing.expectEqual(@as(u32, 1), st.unsupported);
    try testing.expectEqual(@as(u32, 1), st.connections);
}

test "docker api: Connection: close and HTTP/1.0 close after the answer" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const a = try ask(f.path, "GET /_ping HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n", 3000);
    defer testing.allocator.free(a.text);
    try testing.expectEqual(@as(u16, 200), statusOf(a.text));
    try expectContains(a.text, "Connection: close");
    const b = try ask(f.path, "GET /_ping HTTP/1.0\r\n\r\n", 3000);
    defer testing.allocator.free(b.text);
    try testing.expectEqual(@as(u16, 200), statusOf(b.text));
    try expectContains(b.text, "Connection: close");
}

test "docker api: malformed requests are 400 and closed, never a crash" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const bad = [_][]const u8{
        "this is not http\r\n\r\n",
        "GET\r\n\r\n",
        "GET /_ping\r\n\r\n",
        "GET /_ping HTTP/1.1 extra\r\nHost: d\r\n\r\n",
        "get /_ping HTTP/1.1\r\nHost: d\r\n\r\n",
        "GET _ping HTTP/1.1\r\nHost: d\r\n\r\n",
        "GET /_ping HTTP/2.0\r\nHost: d\r\n\r\n",
        "GET /_ping HTTP/1.1\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\nno colon here\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\n folded: x\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\nBad Name: x\r\n\r\n",
        "GET /_ping HTTP/1.1\r\nHost: d\r\nX: a\x00b\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: abc\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /build HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: gzip\r\n\r\n",
        "GET /_ping HTTP/1.1\nHost: d\n\n\r\n\r\n",
    };
    for (bad) |req| {
        const r = try ask(f.path, req, 3000);
        defer testing.allocator.free(r.text);
        errdefer std.debug.print("ERROR request {any}\n", .{req});
        try testing.expectEqual(@as(u16, 400), statusOf(r.text));
        try expectContains(bodyOf(r.text), "malformed HTTP request");
        try testing.expect(r.closed or std.mem.indexOf(u8, r.text, "Connection: close") != null);
    }
    // Binary noise, and a connection that sends nothing and goes: the server is still there.
    const noise = try ask(f.path, "\xff\xfe\x00\x01\r\n\r\n", 3000);
    defer testing.allocator.free(noise.text);
    try testing.expectEqual(@as(u16, 400), statusOf(noise.text));
    const fd = try connect(f.path);
    _ = linux.close(fd);
    const ok = try get(f.path, "/_ping");
    defer testing.allocator.free(ok);
    try testing.expectEqual(@as(u16, 200), statusOf(ok));
}

test "docker api: an oversized head is 431 and an oversized target 414" {
    var cfg = test_cfg;
    cfg.limits.header_bytes = 1024;
    cfg.limits.target_bytes = 100;
    var f = try Fixture.start(cfg);
    defer _ = f.finish();
    const big = try std.fmt.allocPrint(testing.allocator, "GET /_ping HTTP/1.1\r\nHost: d\r\nX-Fill: {s}\r\n\r\n", .{repeat("a", 2000)});
    defer testing.allocator.free(big);
    const a = try ask(f.path, big, 3000);
    defer testing.allocator.free(a.text);
    try testing.expectEqual(@as(u16, 431), statusOf(a.text));
    // No end to the head at all: the same, without waiting for one.
    const endless = try ask(f.path, "GET /_ping HTTP/1.1\r\n" ++ comptime repeat("X: b\r\n", 400), 3000);
    defer testing.allocator.free(endless.text);
    try testing.expectEqual(@as(u16, 431), statusOf(endless.text));
    const long = try std.fmt.allocPrint(testing.allocator, "GET /{s} HTTP/1.1\r\nHost: d\r\n\r\n", .{repeat("p", 200)});
    defer testing.allocator.free(long);
    const b = try ask(f.path, long, 3000);
    defer testing.allocator.free(b.text);
    try testing.expectEqual(@as(u16, 414), statusOf(b.text));
}

test "docker api: a head that stalls is 408 and a silent connection is closed, within the limits" {
    var cfg = test_cfg;
    cfg.limits.header_ms = 200;
    cfg.limits.idle_ms = 300;
    var f = try Fixture.start(cfg);
    defer _ = f.finish();
    var t0 = nowMs();
    const slow = try ask(f.path, "GET /_ping HTTP/1.1\r\nHost: d\r\n", 3000);
    defer testing.allocator.free(slow.text);
    try testing.expectEqual(@as(u16, 408), statusOf(slow.text));
    try testing.expect(slow.closed);
    try testing.expect(nowMs() - t0 < 1500);
    t0 = nowMs();
    const idle = try ask(f.path, "", 3000);
    defer testing.allocator.free(idle.text);
    try testing.expect(idle.closed);
    try testing.expectEqualStrings("", idle.text);
    try testing.expect(nowMs() - t0 < 1500);
    // A kept connection that goes quiet after an answer is closed too.
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const one = try askOn(fd, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    defer testing.allocator.free(one.text);
    try testing.expectEqual(@as(u16, 200), statusOf(one.text));
    t0 = nowMs();
    const after = try askOn(fd, "", 3000);
    defer testing.allocator.free(after.text);
    try testing.expect(after.closed);
    try testing.expect(nowMs() - t0 < 1500);
    try testing.expect(f.server.stats().timeouts >= 1);
}

test "docker api: a request with a body is answered at once, then its body is dropped and the connection closed" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const head = "POST /v1.41/build?t=x HTTP/1.1\r\nHost: d\r\nContent-Length: 1000000\r\n\r\n";
    _ = linux.sendto(fd, head.ptr, head.len, linux.MSG.NOSIGNAL, null, 0);
    // The answer comes before the body is sent.
    var got = try askOn(fd, "", 3000);
    try testing.expectEqual(@as(u16, 501), statusOf(got.text));
    try expectContains(got.text, build_stage_1b);
    try expectContains(got.text, "Connection: close");
    testing.allocator.free(got.text);
    // And the client may still send all of it: it is read, not reset.
    const chunk = repeat("x", 65536);
    var sent: usize = 0;
    while (sent < 1_000_000) {
        const n = @min(chunk.len, 1_000_000 - sent);
        const rc = linux.sendto(fd, chunk.ptr, n, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(rc) != .SUCCESS) break;
        sent += rc;
    }
    try testing.expectEqual(@as(usize, 1_000_000), sent);
    got = try askOn(fd, "", 3000);
    defer testing.allocator.free(got.text);
    try testing.expect(got.closed);
}

test "docker api: a client that sends a body forever is let go after the drain limit" {
    var cfg = test_cfg;
    cfg.limits.drain_bytes = 100_000;
    cfg.limits.drain_ms = 300;
    var f = try Fixture.start(cfg);
    defer _ = f.finish();
    const fd = try connect(f.path);
    defer _ = linux.close(fd);
    const head = "POST /containers/create HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n";
    const r = try askOn(fd, head, 3000);
    defer testing.allocator.free(r.text);
    try testing.expectEqual(@as(u16, 501), statusOf(r.text));
    const t0 = nowMs();
    const more = try askOn(fd, "", 3000);
    defer testing.allocator.free(more.text);
    try testing.expect(more.closed);
    try testing.expect(nowMs() - t0 < 1500);
}

test "docker api: with every connection busy the next is 503, and stop does not wait for them" {
    var cfg = test_cfg;
    cfg.limits.max_connections = 2;
    var f = try Fixture.start(cfg);
    const a = try connect(f.path);
    defer _ = linux.close(a);
    const b = try connect(f.path);
    defer _ = linux.close(b);
    // Each holds a connection open and silent (the default idle limit is long).
    const one = try askOn(a, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    testing.allocator.free(one.text);
    const two = try askOn(b, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 1000);
    testing.allocator.free(two.text);
    const third = try ask(f.path, "GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n", 3000);
    defer testing.allocator.free(third.text);
    try testing.expectEqual(@as(u16, 503), statusOf(third.text));
    const t0 = nowMs();
    const st = f.finish();
    try testing.expect(nowMs() - t0 < 1000);
    try testing.expectEqual(@as(u32, 1), st.busy);
    try testing.expectEqual(@as(u32, 3), st.connections);
    // The socket's file is gone with the server.
    try testing.expectError(error.Connect, connect(f.path));
}

test "docker api: a socket path past sun_path is bound through its directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(root);
    var dir: std.ArrayList(u8) = .empty;
    defer dir.deinit(testing.allocator);
    try dir.appendSlice(testing.allocator, root);
    while (dir.items.len < 130) {
        try dir.appendSlice(testing.allocator, "/long-directory-name");
        try tmp.dir.createDirPath(testing.io, dir.items[root.len + 1 ..]);
    }
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/docker.sock", .{dir.items});
    defer testing.allocator.free(path);
    const server = try Server.start(testing.allocator, path, test_cfg);
    defer _ = server.stop();
    const text = try get(path, "/_ping");
    defer testing.allocator.free(text);
    try testing.expectEqual(@as(u16, 200), statusOf(text));
    const st = try tmp.dir.statFile(testing.io, path[root.len + 1 ..], .{});
    try testing.expect(st.kind == .unix_domain_socket);
}

test "docker api: the socket is 0666 and a second server on the same path is refused" {
    var f = try Fixture.start(test_cfg);
    defer _ = f.finish();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try zpath(&buf, "{s}", .{f.path});
    var stx: linux.Statx = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.statx(linux.AT.FDCWD, z, 0, .{ .MODE = true }, &stx)));
    try testing.expectEqual(@as(u16, 0o666), stx.mode & 0o7777);
    try testing.expectError(error.AddressInUse, Server.start(testing.allocator, f.path, test_cfg));
}

test "docker api: the log line's counts" {
    var f = try Fixture.start(test_cfg);
    const a = try get(f.path, "/_ping");
    testing.allocator.free(a);
    const b = try get(f.path, "/images/json");
    testing.allocator.free(b);
    const c = try ask(f.path, "junk\r\n\r\n", 3000);
    testing.allocator.free(c.text);
    const st = f.finish();
    try testing.expectEqual(Stats{ .connections = 3, .requests = 3, .unsupported = 1, .refused = 1 }, st);
}

// For recording a real `docker` CLI's traffic (`testdata/docker_api/`): with
// `ZIG_TEST_DOCKER_API_SERVE=<socket path>` the server runs there until `<socket path>.stop` is
// made (`touch`), and a CLI with `DOCKER_HOST=unix://<path>` talks to it. Skipped otherwise.
test "docker api: serve for a real CLI (ZIG_TEST_DOCKER_API_SERVE=<socket>, ends when <socket>.stop exists)" {
    var env = try std.testing.environ.createMap(testing.allocator);
    defer env.deinit();
    const path = env.get("ZIG_TEST_DOCKER_API_SERVE") orelse return error.SkipZigTest;
    const server = try Server.start(testing.allocator, path, .{ .job = "0123456789abcdef", .version = "v0.0.0-recorded" });
    defer _ = server.stop();
    const stop = try std.fmt.allocPrint(testing.allocator, "{s}.stop", .{path});
    defer testing.allocator.free(stop);
    const dir = std.fs.path.dirname(path) orelse ".";
    const ino = try fdOf(linux.inotify_init1(linux.IN.CLOEXEC));
    defer _ = linux.close(ino);
    var dir_z: [std.fs.max_path_bytes]u8 = undefined;
    const dz = try zpath(&dir_z, "{s}", .{dir});
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.inotify_add_watch(ino, dz, linux.IN.CREATE | linux.IN.MOVED_TO)));
    var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
    while (true) {
        std.Io.Dir.cwd().access(testing.io, stop, .{}) catch {
            const rc = linux.read(ino, &buf, buf.len);
            if (linux.errno(rc) == .INTR) continue;
            continue;
        };
        break;
    }
}

// --- a real docker CLI's traffic, recorded (testdata/docker_api/, cli-transcript.txt) ---

const Capture = struct { name: []const u8, request: []const u8, response: []const u8 };

/// What the docker CLI 29.9.3 sent the server of this stage, and what it answered, as a proxy
/// between the two wrote it down (`docker version`, `docker info`, `docker build .` of the legacy
/// builder with and without `-t`, `--build-arg` and `--target`, a BuildKit build's `/grpc` and its
/// builder's inspect, `docker ps`, `docker images`).
const captures = [_]Capture{
    .{ .name = "version", .request = @embedFile("testdata/docker_api/01-version.req"), .response = @embedFile("testdata/docker_api/01-version.resp") },
    .{ .name = "info", .request = @embedFile("testdata/docker_api/02-info.req"), .response = @embedFile("testdata/docker_api/02-info.resp") },
    .{ .name = "build", .request = @embedFile("testdata/docker_api/03-build.req"), .response = @embedFile("testdata/docker_api/03-build.resp") },
    .{ .name = "build with args", .request = @embedFile("testdata/docker_api/04-build-args.req"), .response = @embedFile("testdata/docker_api/04-build-args.resp") },
    .{ .name = "grpc", .request = @embedFile("testdata/docker_api/05-grpc.req"), .response = @embedFile("testdata/docker_api/05-grpc.resp") },
    .{ .name = "buildx builder", .request = @embedFile("testdata/docker_api/06-buildx-builder.req"), .response = @embedFile("testdata/docker_api/06-buildx-builder.resp") },
    .{ .name = "ps", .request = @embedFile("testdata/docker_api/07-ps.req"), .response = @embedFile("testdata/docker_api/07-ps.resp") },
    .{ .name = "images", .request = @embedFile("testdata/docker_api/08-images.req"), .response = @embedFile("testdata/docker_api/08-images.resp") },
};

/// The methods of the requests in `stream`, up to the first one that has a body.
fn methodsOf(a: Allocator, stream: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var rest = stream;
    while (std.mem.indexOf(u8, rest, "\r\n\r\n")) |end| {
        const head = rest[0..end];
        try out.append(a, head[0 .. std.mem.indexOfScalar(u8, head, ' ') orelse head.len]);
        if (std.ascii.findIgnoreCase(head, "transfer-encoding:") != null or
            std.ascii.findIgnoreCase(head, "content-length: ") != null and
                std.ascii.findIgnoreCase(head, "content-length: 0") == null) break;
        rest = rest[end + 4 ..];
    }
    return out.items;
}

const Response = struct { head: []const u8, body: []const u8 };

/// The responses in `stream`, `methods` being the requests' (a HEAD's has no body). A last one cut
/// short is left out.
fn responsesOf(a: Allocator, stream: []const u8, methods: []const []const u8) ![]const Response {
    var out: std.ArrayList(Response) = .empty;
    var rest = stream;
    for (methods) |m| {
        const end = std.mem.indexOf(u8, rest, "\r\n\r\n") orelse break;
        const head = rest[0..end];
        var n: usize = 0;
        if (std.ascii.findIgnoreCase(head, "content-length: ")) |i| {
            const from = i + "content-length: ".len;
            const to = std.mem.indexOfScalarPos(u8, head, from, '\r') orelse head.len;
            n = try std.fmt.parseInt(usize, head[from..to], 10);
        }
        if (std.mem.eql(u8, m, "HEAD")) n = 0;
        if (rest.len < end + 4 + n) break;
        try out.append(a, .{ .head = head, .body = rest[end + 4 ..][0..n] });
        rest = rest[end + 4 + n ..];
    }
    return out.items;
}

/// The lines of `head` but the ones that name this machine or this body's length, sorted.
fn stableHead(a: Allocator, head: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |l| {
        if (std.ascii.startsWithIgnoreCase(l, "server:") or std.ascii.startsWithIgnoreCase(l, "content-length:")) continue;
        try out.append(a, l);
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.less);
    return out.items;
}

/// Whether `got` is what `want` is, as JSON: the same keys and kinds of value all the way down,
/// what a machine's values differ in left alone (a `message` must be the same text).
fn sameShape(want: std.json.Value, got: std.json.Value, key: []const u8) bool {
    if (std.meta.activeTag(want) != std.meta.activeTag(got)) return false;
    switch (want) {
        .object => |wo| {
            if (wo.count() != got.object.count()) return false;
            var it = wo.iterator();
            while (it.next()) |e| {
                const g = got.object.get(e.key_ptr.*) orelse return false;
                if (!sameShape(e.value_ptr.*, g, e.key_ptr.*)) return false;
            }
            return true;
        },
        .array => |wa| {
            if (wa.items.len == 0 or got.array.items.len == 0) return wa.items.len == got.array.items.len;
            return sameShape(wa.items[0], got.array.items[0], key);
        },
        .string => |s| return !std.mem.eql(u8, key, "message") or std.mem.eql(u8, s, got.string),
        .bool => |b| return b == got.bool,
        else => return true,
    }
}

test "docker api: a real docker CLI's traffic, replayed, is answered as it was (version, info, build, BuildKit, ps, images)" {
    var f = try Fixture.start(.{ .job = "0123456789abcdef", .version = "v0.0.0-recorded" });
    defer _ = f.finish();
    for (captures) |c| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        errdefer std.debug.print("ERROR capture {s}\n", .{c.name});
        const methods = try methodsOf(a, c.request);
        const want = try responsesOf(a, c.response, methods);
        try testing.expectEqual(methods.len, want.len);
        // Everything the CLI sent, at once, as the CLI sent it; then what comes back.
        const fd = try connect(f.path);
        defer _ = linux.close(fd);
        var got_bytes: std.ArrayList(u8) = .empty;
        var sent = false;
        const end = nowMs() + 3000;
        var got: []const Response = &.{};
        while (nowMs() < end and got.len < want.len) {
            const heard = try askOn(fd, if (sent) "" else c.request, 100);
            defer testing.allocator.free(heard.text);
            sent = true;
            try got_bytes.appendSlice(a, heard.text);
            got = try responsesOf(a, got_bytes.items, methods);
            if (heard.closed) break;
        }
        try testing.expectEqual(want.len, got.len);
        for (want, got) |w, g| {
            try testing.expectEqualDeep(try stableHead(a, w.head), try stableHead(a, g.head));
            if (std.mem.indexOf(u8, w.head, "application/json") != null) {
                const pw = try std.json.parseFromSliceLeaky(std.json.Value, a, w.body, .{});
                const pg = try std.json.parseFromSliceLeaky(std.json.Value, a, g.body, .{});
                try testing.expect(sameShape(pw, pg, ""));
            } else try testing.expectEqualStrings(w.body, g.body);
        }
    }
}
