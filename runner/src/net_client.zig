//! The runner's HTTP client: the network library's (`rust/zr-net/src/client.rs`, docs/rust-net.md)
//! behind `fetch`. A request is handed to the library, which runs it on its runtime, and this file
//! waits for it through std.Io on a descriptor the library makes readable when it has finished, so
//! a deadline or a cancel ends the wait where it blocks and drops the request (and its connection).
//! Each request logs one `request:` line (`github/request_line.zig`) with the library's own,
//! exact, DNS, connect, TLS and first-byte times. Whole bodies: streaming is for R4.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = @import("github/http.zig");
const request_line = @import("github/request_line.zig");
const build_version = @import("version.zig");

const Handle = opaque {};
const Call = opaque {};

const ClientConfig = extern struct {
    user_agent: [*]const u8,
    user_agent_len: usize,
    roots: [*]const u8,
    roots_len: usize,
    connect_timeout_ms: u32,
    tls_timeout_ms: u32,
    idle_timeout_ms: u32,
    max_idle_per_host: u32,
    flags: u32,
};

const RequestSpec = extern struct {
    method: [*]const u8,
    method_len: usize,
    url: [*]const u8,
    url_len: usize,
    headers: [*]const u8,
    headers_len: usize,
    body: [*]const u8,
    body_len: usize,
    max_redirects: u32,
    max_response: usize,
    first_byte_ms: u32,
    read_idle_ms: u32,
};

const Info = extern struct {
    @"error": i32,
    status: u16,
    http_minor: u8,
    reused: u8,
    redirects: u32,
    dns_ns: u64,
    connect_ns: u64,
    tls_ns: u64,
    ttfb_ns: u64,
    total_ns: u64,
    bytes_in: u64,
    headers_len: usize,
    body_len: usize,
    message_len: usize,
};

extern fn zr_net_client_new(cfg: *const ClientConfig, out: *?*Handle, msg: [*]u8, msg_cap: usize) i32;
extern fn zr_net_client_free(c: ?*Handle) void;
extern fn zr_net_call_start(c: *Handle, spec: *const RequestSpec, out: *?*Call, fd: *i32, msg: [*]u8, msg_cap: usize) i32;
extern fn zr_net_call_result(call: *Call, info: *Info) i32;
extern fn zr_net_call_copy(call: *Call, what: u32, out: [*]u8, cap: usize) usize;
extern fn zr_net_call_free(call: ?*Call) void;

/// `Code` of the library (client.rs), as the errors callers can tell apart.
pub const Error = error{
    BadUrl,
    DnsFailed,
    ConnectionRefused,
    ConnectionTimedOut,
    ConnectionFailed,
    TlsUnknownIssuer,
    TlsCertificateExpired,
    TlsNameMismatch,
    TlsCertificate,
    TlsFailed,
    /// No first byte or a body that stopped within the call's limits, or the whole request's deadline.
    Timeout,
    TooManyRedirects,
    BodyTooLarge,
    ProtocolError,
    ProxyFailed,
    NetworkIo,
    NetworkConfig,
} || Allocator.Error || Io.Cancelable;

fn errorOf(code: i32) Error {
    return switch (code) {
        1 => error.BadUrl,
        2 => error.DnsFailed,
        3 => error.ConnectionRefused,
        4 => error.ConnectionTimedOut,
        5 => error.ConnectionFailed,
        6 => error.TlsUnknownIssuer,
        7 => error.TlsCertificateExpired,
        8 => error.TlsNameMismatch,
        9 => error.TlsCertificate,
        10 => error.TlsFailed,
        11 => error.Timeout,
        12 => error.Canceled,
        13 => error.TooManyRedirects,
        14 => error.BodyTooLarge,
        15 => error.ProtocolError,
        16 => error.ProxyFailed,
        18 => error.NetworkConfig,
        else => error.NetworkIo,
    };
}

pub const Timings = struct {
    dns_ns: ?u64 = null,
    connect_ns: ?u64 = null,
    tls_ns: ?u64 = null,
    ttfb_ns: ?u64 = null,
    total_ns: u64 = 0,
    bytes_in: u64 = 0,
    redirects: u32 = 0,
    reused: bool = false,
};

pub const Response = struct {
    status: std.http.Status,
    /// `name: value` lines, names lower-case, `\n` between.
    headers: []const u8,
    body: []u8,
    timings: Timings,

    /// The first header called `name` (lower case), or null.
    pub fn header(r: Response, name: []const u8) ?[]const u8 {
        var lines = std.mem.splitScalar(u8, r.headers, '\n');
        while (lines.next()) |l| {
            const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
            if (std.mem.eql(u8, l[0..colon], name)) return std.mem.trim(u8, l[colon + 1 ..], " ");
        }
        return null;
    }
};

pub const Options = struct {
    method: std.http.Method = .GET,
    url: []const u8,
    headers: []const std.http.Header = &.{},
    /// The body; null for none.
    payload: ?[]const u8 = null,
    max_redirects: u32 = 3,
    max_response: usize = 16 << 20,
    /// Limits of the library's: no first byte, a body that stops. The whole request's `deadline` is
    /// this file's.
    first_byte: ?Io.Duration = null,
    read_idle: ?Io.Duration = null,
    deadline: Io.Duration = http.request_deadline,
    /// Which attempt this is, for the line's `retry`.
    retry: u32 = 0,
    /// Roots (PEM) that replace the system's, for the client this call creates. Tests.
    roots_pem: []const u8 = "",
};

var shared: std.atomic.Value(?*Handle) = .init(null);
var user_agent_buf: [96]u8 = undefined;

/// The process's client, made on first use: the pool, the proxy settings read from the environment,
/// the roots, the user agent.
fn client(roots_pem: []const u8) Error!*Handle {
    if (roots_pem.len == 0) if (shared.load(.acquire)) |c| return c;
    const ua = std.fmt.bufPrint(&user_agent_buf, "zig-runner/{s}", .{build_version.string}) catch "zig-runner";
    const cfg: ClientConfig = .{
        .user_agent = ua.ptr,
        .user_agent_len = ua.len,
        .roots = roots_pem.ptr,
        .roots_len = roots_pem.len,
        .connect_timeout_ms = 0,
        .tls_timeout_ms = 0,
        .idle_timeout_ms = 0,
        .max_idle_per_host = 0,
        .flags = 1,
    };
    var handle: ?*Handle = null;
    var msg: [128]u8 = undefined;
    if (zr_net_client_new(&cfg, &handle, &msg, msg.len) != 0) return error.NetworkConfig;
    // A client with roots of its own is for one call (tests): it is not the process's.
    if (roots_pem.len > 0) return handle.?;
    if (shared.cmpxchgStrong(null, handle, .acq_rel, .acquire)) |won| {
        zr_net_client_free(handle);
        return won.?;
    }
    return handle.?;
}

/// Frees the process's client, once nothing uses it (the runner's exit).
pub fn deinit() void {
    if (shared.swap(null, .acq_rel)) |c| zr_net_client_free(c);
}

/// One request within `opts.deadline`, with its `request:` line. The error is the library's
/// (`Error`); a certificate problem is told apart, and the message goes to the log.
pub fn fetch(arena: Allocator, io: Io, opts: Options) Error!Response {
    var line: Probe = .{ .io = io, .opts = opts };
    line.start(io);
    const r = http.within(io, opts.deadline, call, .{ arena, io, opts, &line }) catch |e| {
        line.finish(.{ .err = "Canceled" });
        return e;
    };
    return (r orelse {
        line.finish(.{ .err = "Timeout" });
        return error.Timeout;
    }) catch |e| {
        line.finish(.{ .err = @errorName(e) });
        return e;
    };
}

/// What `request:` needs of the request, kept apart from the call so that a deadline that ends the
/// call still logs.
const Probe = struct {
    io: Io,
    opts: Options,
    started: Io.Timestamp = undefined,
    timings: Timings = .{},
    status: ?u16 = null,
    headers: []const u8 = "",
    logged: bool = false,

    fn start(p: *Probe, io: Io) void {
        p.started = Io.Clock.awake.now(io);
    }

    fn finish(p: *Probe, outcome: request_line.Status) void {
        if (p.logged) return;
        p.logged = true;
        const uri = std.Uri.parse(p.opts.url) catch std.Uri{ .scheme = "" };
        var host_buf: [255]u8 = undefined;
        const host = if (uri.host) |h| (h.toRaw(&host_buf) catch "?") else "?";
        var path_buf: [256]u8 = undefined;
        var raw_path_buf: [512]u8 = undefined;
        const path = request_line.redactPath(&path_buf, if (uri.path.toRaw(&raw_path_buf)) |s| s else |_| "");
        const total: u64 = std.math.lossyCast(u64, p.started.durationTo(Io.Clock.awake.now(p.io)).toNanoseconds());
        var l: request_line.Line = .{
            .host = host,
            .method = @tagName(p.opts.method),
            .path = path,
            .status = if (p.status) |s| .{ .code = s } else outcome,
            .dns_ns = p.timings.dns_ns,
            .connect_ns = p.timings.connect_ns,
            .tls_ns = p.timings.tls_ns,
            .ttfb_ns = p.timings.ttfb_ns,
            .total_ns = if (p.timings.total_ns != 0) p.timings.total_ns else total,
            .bytes_in = if (p.status != null) p.timings.bytes_in else null,
            .retry = p.opts.retry,
            .reused = if (p.status != null) p.timings.reused else null,
        };
        var rl = Response{ .status = .ok, .headers = p.headers, .body = &.{}, .timings = p.timings };
        l.rl_remaining = parseU64(rl.header("x-ratelimit-remaining"));
        l.rl_limit = parseU64(rl.header("x-ratelimit-limit"));
        l.rl_reset = parseU64(rl.header("x-ratelimit-reset"));
        l.rl_resource = rl.header("x-ratelimit-resource") orelse "";
        request_line.emit(p.io, l, rl.header("retry-after") orelse "");
    }
};

fn parseU64(s: ?[]const u8) ?u64 {
    return std.fmt.parseInt(u64, s orelse return null, 10) catch null;
}

fn call(arena: Allocator, io: Io, opts: Options, probe: *Probe) Error!Response {
    const c = try client(opts.roots_pem);
    defer if (opts.roots_pem.len > 0) zr_net_client_free(c);

    var header_lines: std.Io.Writer.Allocating = .init(arena);
    for (opts.headers) |h| header_lines.writer.print("{s}: {s}\n", .{ h.name, h.value }) catch return error.OutOfMemory;
    const payload = opts.payload orelse "";
    const method = @tagName(opts.method);
    const spec: RequestSpec = .{
        .method = method.ptr,
        .method_len = method.len,
        .url = opts.url.ptr,
        .url_len = opts.url.len,
        .headers = header_lines.written().ptr,
        .headers_len = header_lines.written().len,
        .body = payload.ptr,
        .body_len = payload.len,
        .max_redirects = opts.max_redirects,
        .max_response = opts.max_response,
        .first_byte_ms = if (opts.first_byte) |d| std.math.lossyCast(u32, @max(1, d.toMilliseconds())) else 0,
        .read_idle_ms = if (opts.read_idle) |d| std.math.lossyCast(u32, @max(1, d.toMilliseconds())) else 0,
    };
    var handle: ?*Call = null;
    var fd: i32 = -1;
    var msg: [256]u8 = undefined;
    const rc = zr_net_call_start(c, &spec, &handle, &fd, &msg, msg.len);
    if (rc != 0) {
        std.log.warn("net: {s}", .{std.mem.sliceTo(&msg, 0)});
        return errorOf(rc);
    }
    const done: Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    // The call's request is dropped, and the descriptor closed, whichever way this ends: the
    // library never writes to a descriptor a caller closed (its own end is a separate one).
    defer {
        zr_net_call_free(handle);
        done.close(io);
    }
    var one: [1]u8 = undefined;
    var bufs = [_][]u8{&one};
    _ = done.readStreaming(io, &bufs) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkIo,
    };

    var info: Info = undefined;
    if (zr_net_call_result(handle.?, &info) != 0) return error.NetworkIo;
    probe.timings = .{
        .dns_ns = opt(info.dns_ns),
        .connect_ns = opt(info.connect_ns),
        .tls_ns = opt(info.tls_ns),
        .ttfb_ns = opt(info.ttfb_ns),
        .total_ns = if (info.total_ns == std.math.maxInt(u64)) 0 else info.total_ns,
        .bytes_in = info.bytes_in,
        .redirects = info.redirects,
        .reused = info.reused != 0,
    };
    if (info.@"error" != 0) {
        const m = try arena.alloc(u8, info.message_len);
        _ = zr_net_call_copy(handle.?, 2, m.ptr, m.len);
        std.log.warn("net: {s} {s}: {s}", .{ method, opts.url, m });
        return errorOf(info.@"error");
    }
    const headers = try arena.alloc(u8, info.headers_len);
    _ = zr_net_call_copy(handle.?, 0, headers.ptr, headers.len);
    const body = try arena.alloc(u8, info.body_len);
    _ = zr_net_call_copy(handle.?, 1, body.ptr, body.len);
    probe.status = info.status;
    probe.headers = headers;
    const status = std.enums.fromInt(std.http.Status, info.status) orelse return error.ProtocolError;
    probe.finish(.{ .code = info.status });
    return .{ .status = status, .headers = headers, .body = body, .timings = probe.timings };
}

fn opt(v: u64) ?u64 {
    return if (v == std.math.maxInt(u64)) null else v;
}
