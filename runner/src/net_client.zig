//! The runner's HTTP client: the network library's (`rust/zr-net/src/client.rs`, docs/rust-net.md)
//! behind `fetch`. A request is handed to the library, which runs it on its runtime, and this file
//! waits for it through std.Io on a descriptor the library makes readable when it has finished, so
//! a deadline or a cancel ends the wait where it blocks and drops the request (and its connection).
//! Each request logs one `request:` line (`github/request_log.zig`) with the library's own,
//! exact, DNS, connect, TLS and first-byte times.
//!
//! `fetch` reads the whole answer. `open` gives the head and then the body as it arrives (`Stream`),
//! through a queue of a fixed size in the library, so a download of any size costs the same memory;
//! its line is written when the body ends or the stream is closed. A request body that does not fit
//! in memory is written as it is sent (`Options.upload`, the same queue the other way).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const http = @import("github/http.zig");
const request_log = @import("github/request_log.zig");
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
    flags: u32,
    total_ms: u32,
};

const flag_stream_response = 1;
const flag_stream_request = 2;
const flag_fresh = 4;

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
extern fn zr_net_body_read(call: *Call, out: [*]u8, cap: usize, n: *usize, msg: [*]u8, msg_cap: usize) i32;
extern fn zr_net_body_write(call: *Call, data: [*]const u8, len: usize, taken: *usize) i32;
extern fn zr_net_body_peak(call: *Call) usize;

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
    /// A handshake the peer broke for good: no shared version or cipher, malformed records (not tried again).
    TlsProtocol,
    /// No first byte or a body that stopped within the call's limits, or the whole request's deadline.
    Timeout,
    TooManyRedirects,
    BodyTooLarge,
    ProtocolError,
    ProxyFailed,
    NetworkIo,
    NetworkConfig,
    /// A kept connection turned out to be closed after a request body had begun to be taken: the
    /// body is written again (`Options.fresh`).
    StaleConnection,
    /// The writer of a request body failed (`Body.writeFn`) or wrote less than its length.
    UploadFailed,
    /// The writer of a request body wrote more than the `len` it declared; what it wrote past
    /// that was not sent.
    BodyLongerThanDeclared,
    /// The server did not accept a WebSocket upgrade (`Ws.open`): it answered with another status.
    WebSocketRefused,
    /// A WebSocket that ended (the peer closed it, or the connection was lost) before what was asked of it.
    WebSocketClosed,
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
        19 => error.StaleConnection,
        20 => error.WebSocketRefused,
        21 => error.TlsProtocol,
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

/// A body of `len` bytes that `writeFn` writes, once per attempt. An implementation embeds it as a
/// field and recovers itself in `writeFn` with `@fieldParentPtr`; the request holds a pointer to
/// it, so it must not be copied.
pub const Body = struct {
    len: usize,
    writeFn: *const fn (body: *const Body, w: *std.Io.Writer) anyerror!void,
};

pub const Options = struct {
    method: std.http.Method = .GET,
    url: []const u8,
    headers: []const std.http.Header = &.{},
    /// The body; null for none.
    payload: ?[]const u8 = null,
    /// A body written as it is sent, in place of `payload`.
    upload: ?*const Body = null,
    /// A connection made for this request, not a kept one (an upload sent again after
    /// `error.StaleConnection`).
    fresh: bool = false,
    /// Limit of the whole request, its body included (the library's); null for none. `fetch` has
    /// `deadline` besides.
    total: ?Io.Duration = null,
    max_redirects: u32 = 3,
    max_response: usize = 16 << 20,
    /// Limits of the library's: no first byte, a body that stops. The whole request's `deadline` is
    /// this file's.
    first_byte: ?Io.Duration = null,
    read_idle: ?Io.Duration = null,
    /// Null for none (a long poll, a request that lasts as long as something else does).
    deadline: ?Io.Duration = http.request_deadline,
    /// Whether the call writes its `request:` line (off for the Dagger engine's queries, which go to
    /// this machine).
    log: bool = true,
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
/// What a null `deadline` waits: ten years, a limit no request reaches, which keeps one code path for
/// both (the timer is a task that is cancelled with the request).
const no_deadline: Io.Duration = .fromSeconds(10 * 365 * 24 * 3600);

pub fn fetch(arena: Allocator, io: Io, opts: Options) Error!Response {
    var line: Probe = .{ .io = io, .opts = opts };
    line.start(io);
    const limit = opts.deadline orelse no_deadline;
    const r = http.within(io, limit, call, .{ arena, io, opts, &line }) catch |e| {
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

    fn finish(p: *Probe, outcome: request_log.Status) void {
        if (p.logged) return;
        p.logged = true;
        if (!p.opts.log) return;
        const uri = std.Uri.parse(p.opts.url) catch std.Uri{ .scheme = "" };
        var host_buf: [255 + 6]u8 = undefined;
        const name = if (uri.host) |h| (h.toRaw(host_buf[0..255]) catch "?") else "?";
        if (name.ptr != &host_buf) @memcpy(host_buf[0..name.len], name);
        // With its port when the URL names one, as the line has always shown it.
        const host_len = name.len + if (uri.port) |port|
            (std.fmt.bufPrint(host_buf[name.len..], ":{d}", .{port}) catch @as([]u8, host_buf[0..0])).len
        else
            0;
        const host = host_buf[0..host_len];
        var path_buf: [256]u8 = undefined;
        var raw_path_buf: [512]u8 = undefined;
        const path = request_log.redactPath(&path_buf, if (uri.path.toRaw(&raw_path_buf)) |s| s else |_| "");
        const total: u64 = std.math.lossyCast(u64, p.started.durationTo(Io.Clock.awake.now(p.io)).toNanoseconds());
        var l: request_log.Line = .{
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
        request_log.emit(p.io, l, rl.header("retry-after") orelse "");
    }
};

fn parseU64(s: ?[]const u8) ?u64 {
    return std.fmt.parseInt(u64, s orelse return null, 10) catch null;
}

/// A call the library is running, and the descriptor that says when there is something to read.
const Live = struct {
    io: Io,
    call: *Call,
    done: Io.File,
    /// The client made for this call alone (`Options.roots_pem`), freed with it.
    own: ?*Handle,

    /// Starts `opts`; `stream` for a response read with `Stream.read`.
    fn begin(arena: Allocator, io: Io, opts: Options, stream: bool) Error!Live {
        const c = try client(opts.roots_pem);
        errdefer if (opts.roots_pem.len > 0) zr_net_client_free(c);

        var header_lines: std.Io.Writer.Allocating = .init(arena);
        for (opts.headers) |h| header_lines.writer.print("{s}: {s}\n", .{ h.name, h.value }) catch return error.OutOfMemory;
        const payload = opts.payload orelse "";
        const method = @tagName(opts.method);
        var flags: u32 = 0;
        if (stream) flags |= flag_stream_response;
        if (opts.upload != null) flags |= flag_stream_request;
        if (opts.fresh) flags |= flag_fresh;
        const spec: RequestSpec = .{
            .method = method.ptr,
            .method_len = method.len,
            .url = opts.url.ptr,
            .url_len = opts.url.len,
            .headers = header_lines.written().ptr,
            .headers_len = header_lines.written().len,
            .body = payload.ptr,
            .body_len = if (opts.upload) |u| u.len else payload.len,
            .max_redirects = opts.max_redirects,
            .max_response = opts.max_response,
            .first_byte_ms = ms(opts.first_byte),
            .read_idle_ms = ms(opts.read_idle),
            .flags = flags,
            .total_ms = ms(opts.total),
        };
        var handle: ?*Call = null;
        var fd: i32 = -1;
        var msg: [256]u8 = undefined;
        const rc = zr_net_call_start(c, &spec, &handle, &fd, &msg, msg.len);
        if (rc != 0) {
            std.log.warn("net: {s}", .{std.mem.sliceTo(&msg, 0)});
            return errorOf(rc);
        }
        return .{ .io = io, .call = handle.?, .done = .{ .handle = fd, .flags = .{ .nonblocking = false } }, .own = if (opts.roots_pem.len > 0) c else null };
    }

    /// The call's request is dropped, and the descriptor closed, whichever way this ends: the
    /// library never writes to a descriptor a caller closed (its own end is a separate one).
    fn end(l: *Live) void {
        zr_net_call_free(l.call);
        l.done.close(l.io);
        if (l.own) |c| zr_net_client_free(c);
    }

    /// Waits until the library has something to say: a wake on the descriptor, spurious ones
    /// included. Where a deadline or a cancel ends the wait.
    fn wait(l: Live) Error!void {
        var sink: [64]u8 = undefined;
        var bufs = [_][]u8{&sink};
        _ = l.done.readStreaming(l.io, &bufs) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return error.NetworkIo,
        };
    }

    /// The call's figures, once it has finished (its head, in a streaming call).
    fn info(l: Live) Error!Info {
        while (true) {
            var i: Info = undefined;
            if (zr_net_call_result(l.call, &i) == 0) return i;
            try l.wait();
        }
    }

    /// Writes `body` through the library's queue as it is sent. Null when the call ended before the
    /// body did (the server answered, or the call failed): its result says how.
    fn upload(l: Live, body: *const Body) Error!void {
        var buf: [16 * 1024]u8 = undefined;
        var u: Uploader = .{ .live = l, .len = body.len, .interface = .{ .vtable = &.{ .drain = Uploader.drain }, .buffer = &buf, .end = 0 } };
        body.writeFn(body, &u.interface) catch |e| {
            if (u.err) |c| return c;
            if (u.overrun) return error.BodyLongerThanDeclared;
            if (u.over) return;
            std.log.warn("net: the request body could not be written: {t}", .{e});
            return error.UploadFailed;
        };
        u.interface.flush() catch {
            if (u.err) |c| return c;
            if (u.overrun) return error.BodyLongerThanDeclared;
            if (u.over) return;
            return error.UploadFailed;
        };
        if (u.overrun) return error.BodyLongerThanDeclared;
        if (!u.over and u.sent != body.len) return error.UploadFailed;
    }

    fn headOf(l: Live, arena: Allocator, probe: *Probe, method: []const u8, url: []const u8) Error!Info {
        _ = .{ method, url };
        const info_ = try l.info();
        probe.timings = timingsOf(info_);
        if (info_.@"error" != 0) {
            const m = try arena.alloc(u8, info_.message_len);
            _ = zr_net_call_copy(l.call, 2, m.ptr, m.len);
            std.log.warn("net: {s} {s}: {s}", .{ method, url, m });
            return errorOf(info_.@"error");
        }
        return info_;
    }
};

const Uploader = struct {
    live: Live,
    interface: Io.Writer,
    /// The body's declared length.
    len: usize,
    sent: usize = 0,
    /// The library refused more: the call is over, or the body is complete.
    over: bool = false,
    /// More was written once all `len` bytes had been taken: the writer is wrong, not the call.
    overrun: bool = false,
    err: ?Error = null,

    fn writeAll(u: *Uploader, bytes: []const u8) Io.Writer.Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            var taken: usize = 0;
            switch (zr_net_body_write(u.live.call, bytes.ptr + off, bytes.len - off, &taken)) {
                0 => {
                    off += taken;
                    u.sent += taken;
                },
                1 => u.live.wait() catch |e| {
                    u.err = e;
                    return error.WriteFailed;
                },
                else => {
                    u.over = true;
                    u.overrun = u.sent >= u.len;
                    return error.WriteFailed;
                },
            }
        }
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const u: *Uploader = @fieldParentPtr("interface", w);
        try u.writeAll(w.buffered());
        w.end = 0;
        if (data.len == 0) return 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            try u.writeAll(bytes);
            n += bytes.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            try u.writeAll(pattern);
            n += pattern.len;
        }
        return n;
    }
};

fn ms(d: ?Io.Duration) u32 {
    return if (d) |v| std.math.lossyCast(u32, @max(1, v.toMilliseconds())) else 0;
}

fn timingsOf(info: Info) Timings {
    return .{
        .dns_ns = opt(info.dns_ns),
        .connect_ns = opt(info.connect_ns),
        .tls_ns = opt(info.tls_ns),
        .ttfb_ns = opt(info.ttfb_ns),
        .total_ns = if (info.total_ns == std.math.maxInt(u64)) 0 else info.total_ns,
        .bytes_in = info.bytes_in,
        .redirects = info.redirects,
        .reused = info.reused != 0,
    };
}

fn call(arena: Allocator, io: Io, opts: Options, probe: *Probe) Error!Response {
    var live = try Live.begin(arena, io, opts, false);
    defer live.end();
    if (opts.upload) |body| try live.upload(body);
    const info = try live.headOf(arena, probe, @tagName(opts.method), opts.url);
    const headers = try arena.alloc(u8, info.headers_len);
    _ = zr_net_call_copy(live.call, 0, headers.ptr, headers.len);
    const body = try arena.alloc(u8, info.body_len);
    _ = zr_net_call_copy(live.call, 1, body.ptr, body.len);
    probe.status = info.status;
    probe.headers = headers;
    const status = std.enums.fromInt(std.http.Status, info.status) orelse return error.ProtocolError;
    probe.finish(.{ .code = info.status });
    return .{ .status = status, .headers = headers, .body = body, .timings = probe.timings };
}

fn opt(v: u64) ?u64 {
    return if (v == std.math.maxInt(u64)) null else v;
}

/// A response whose head has come and whose body is read as it arrives. One per `open`, closed
/// with `close` whatever happens (it frees the call, which drops a connection still carrying a body).
pub const Stream = struct {
    status: std.http.Status,
    /// `name: value` lines, names lower-case, `\n` between.
    headers: []const u8,
    /// The head's figures; `timings()` has the final ones.
    head_timings: Timings,
    live: Live,
    probe: Probe,
    /// Bytes `read` has given out.
    bytes: u64 = 0,
    ended: bool = false,
    closed: bool = false,

    /// The first header called `name` (lower case), or null.
    pub fn header(s: *const Stream, name: []const u8) ?[]const u8 {
        const r = Response{ .status = s.status, .headers = s.headers, .body = &.{}, .timings = s.head_timings };
        return r.header(name);
    }

    /// Up to `out.len` bytes of the body, waiting for them (the wait ends at a cancel); 0 at its end.
    /// An error is the library's: a body that stopped (`read_idle`), a call over its `total`, a
    /// connection that failed, more than `max_response`.
    pub fn read(s: *Stream, out: []u8) Error!usize {
        std.debug.assert(out.len > 0);
        if (s.ended) return 0;
        while (true) {
            var n: usize = 0;
            var msg: [200]u8 = undefined;
            switch (zr_net_body_read(s.live.call, out.ptr, out.len, &n, &msg, msg.len)) {
                0 => {
                    s.bytes += n;
                    return n;
                },
                1 => s.live.wait() catch |e| {
                    s.log(.{ .err = "Canceled" });
                    return e;
                },
                2 => {
                    s.ended = true;
                    s.log(.{ .code = @backingInt(s.status) });
                    return 0;
                },
                else => |rc| {
                    std.log.warn("net: {s}: {s}", .{ s.probe.opts.url, std.mem.sliceTo(&msg, 0) });
                    const e = errorOf(rc - 100);
                    s.log(.{ .err = @errorName(e) });
                    return e;
                },
            }
        }
    }

    /// Reads the rest of the body, up to `limit` bytes, so that the connection can serve the next
    /// request; true when it ended within the limit.
    pub fn discard(s: *Stream, limit: usize) bool {
        var buf: [4096]u8 = undefined;
        var seen: usize = 0;
        while (seen <= limit) {
            const n = s.read(&buf) catch return false;
            if (n == 0) return true;
            seen += n;
        }
        return false;
    }

    /// The most the library's queue held at once: the memory a body of any size costs.
    pub fn queuePeak(s: *const Stream) usize {
        return zr_net_body_peak(s.live.call);
    }

    /// The call's figures now (final once `read` returned 0).
    pub fn timings(s: *Stream) Timings {
        var i: Info = undefined;
        if (zr_net_call_result(s.live.call, &i) == 0) s.probe.timings = timingsOf(i);
        return s.probe.timings;
    }

    fn log(s: *Stream, outcome: request_log.Status) void {
        _ = s.timings();
        s.probe.status = @backingInt(s.status);
        s.probe.finish(outcome);
    }

    /// Ends the call (dropping its connection unless the body was read to its end) and writes the
    /// request's line, if `read` has not. Safe to call twice.
    pub fn close(s: *Stream) void {
        if (s.closed) return;
        s.closed = true;
        if (!s.ended) s.log(.{ .err = "Closed" });
        s.live.end();
    }
};

/// A request answered with its head and a body to read: within `opts.deadline` for the head, the
/// body as long as `opts.read_idle` and `opts.total` allow. `opts.max_response` bounds the body (the
/// default of `fetch`, 16 MiB, is no bound here: pass the size a body may have).
pub fn open(arena: Allocator, io: Io, opts: Options) Error!Stream {
    var line: Probe = .{ .io = io, .opts = opts };
    line.start(io);
    const limit = opts.deadline orelse no_deadline;
    const r = http.withinClosing(io, limit, openCall, .{ arena, io, opts, &line }, {}, closeLate) catch |e| {
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

fn closeLate(_: void, r: Error!Stream) void {
    if (r) |ok| {
        var s = ok;
        s.close();
    } else |_| {}
}

fn openCall(arena: Allocator, io: Io, opts: Options, probe: *Probe) Error!Stream {
    var live = try Live.begin(arena, io, opts, true);
    errdefer live.end();
    if (opts.upload) |body| try live.upload(body);
    const info = try live.headOf(arena, probe, @tagName(opts.method), opts.url);
    const headers = try arena.alloc(u8, info.headers_len);
    _ = zr_net_call_copy(live.call, 0, headers.ptr, headers.len);
    probe.status = info.status;
    probe.headers = headers;
    const status = std.enums.fromInt(std.http.Status, info.status) orelse return error.ProtocolError;
    return .{ .status = status, .headers = headers, .head_timings = probe.timings, .live = live, .probe = probe.* };
}

// --- WebSocket (R6) ---

const WsHandle = opaque {};

const WsSpec = extern struct {
    url: [*]const u8,
    url_len: usize,
    headers: [*]const u8,
    headers_len: usize,
    max_frame: u32,
    open_ms: u32,
    close_wait_ms: u32,
    queue_limit: u32,
    recv_limit: u32,
    close_flush_ms: u32,
};

const WsInfo = extern struct {
    @"error": i32,
    state: u32,
    status: u16,
    close_code: u16,
    dns_ns: u64,
    connect_ns: u64,
    tls_ns: u64,
    ttfb_ns: u64,
    total_ns: u64,
    bytes_in: u64,
    bytes_out: u64,
    queued: usize,
    waiting: usize,
    dropped: u64,
    unsent: u64,
    message_len: usize,
};

const ws_connecting = 0;
const ws_closed = 3;
const ws_text = 0;
const ws_binary = 1;
const ws_ping = 2;

extern fn zr_net_ws_connect(c: *Handle, spec: *const WsSpec, out: *?*WsHandle, fd: *i32, msg: [*]u8, msg_cap: usize) i32;
extern fn zr_net_ws_info(ws: *WsHandle, info: *WsInfo) void;
extern fn zr_net_ws_message(ws: *WsHandle, out: [*]u8, cap: usize) usize;
extern fn zr_net_ws_send(ws: *WsHandle, kind: u32, data: [*]const u8, len: usize) i32;
extern fn zr_net_ws_recv(ws: *WsHandle, out: [*]u8, cap: usize, n: *usize, kind: *u32) i32;
extern fn zr_net_ws_close(ws: *WsHandle) void;
extern fn zr_net_ws_free(ws: ?*WsHandle) void;

/// A WebSocket the library runs (`rust/zr-net/src/ws.rs`): the upgrade is made on the same
/// connection code as a request (proxy, roots, timeouts, `request:` line), and ping, pong and the
/// close handshake are the library's. Waits go through std.Io on a descriptor the library wakes, so
/// a cancel ends a wait where it blocks. Must not move after `open`.
pub const Ws = struct {
    io: Io,
    handle: *WsHandle,
    done: Io.File,
    own: ?*Handle,
    /// How long `close` waits in all (see `close`).
    close_limit: Io.Duration,
    closed: bool = false,

    pub const Config = struct {
        /// `wss://` or `ws://`.
        url: []const u8,
        headers: []const std.http.Header = &.{},
        /// A message goes in frames of at most this many bytes (the first text or binary, the rest
        /// continuations); 0: one frame.
        max_frame: u32 = 0,
        /// The upgrade's limit, from connecting to the server's answer; null for none.
        deadline: ?Io.Duration = http.request_deadline,
        /// Bytes of messages waiting to be sent before `sendText` waits (0: the library's 64 KiB),
        /// and of received ones waiting to be read (0: 1 MiB).
        queue_limit: u32 = 0,
        recv_limit: u32 = 0,
        /// How long `close` waits for the peer's close frame (null: 2 s).
        close_wait: ?Io.Duration = null,
        /// How long what is queued may take to be written once `close` is called (null: 3 s); then the
        /// connection is dropped. The library keeps this limit itself, so it holds with no concurrent task.
        close_flush: ?Io.Duration = null,
        /// Whether the upgrade writes its `request:` line.
        log: bool = true,
        /// Roots (PEM) that replace the system's, for the client this connection creates. Tests.
        roots_pem: []const u8 = "",
    };

    /// What `recv` gives: a message and whether it is text.
    pub const Message = struct { len: usize, text: bool };

    /// Connects within `opts.deadline`, with the upgrade's `request:` line. An error is the library's
    /// (`Error`): `WebSocketRefused` for a server that answered with another status.
    pub fn open(arena: Allocator, io: Io, opts: Config) Error!Ws {
        var line: Probe = .{ .io = io, .opts = .{ .url = opts.url, .log = opts.log } };
        line.start(io);
        const limit = opts.deadline orelse no_deadline;
        const r = http.withinClosing(io, limit, upgrade, .{ arena, io, opts, &line }, {}, dropLate) catch |e| {
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

    fn dropLate(_: void, r: Error!Ws) void {
        if (r) |ok| {
            var w = ok;
            w.abort();
        } else |_| {}
    }

    fn upgrade(arena: Allocator, io: Io, opts: Config, probe: *Probe) Error!Ws {
        const c = try client(opts.roots_pem);
        // A client made for this connection (`roots_pem`) is freed once: here until the `Ws` owns it
        // (`own`), then by `abort`, whichever way the upgrade ends.
        const own = opts.roots_pem.len > 0;
        var handed_over = false;
        errdefer if (own and !handed_over) zr_net_client_free(c);
        var header_lines: std.Io.Writer.Allocating = .init(arena);
        for (opts.headers) |h| header_lines.writer.print("{s}: {s}\n", .{ h.name, h.value }) catch return error.OutOfMemory;
        const spec: WsSpec = .{
            .url = opts.url.ptr,
            .url_len = opts.url.len,
            .headers = header_lines.written().ptr,
            .headers_len = header_lines.written().len,
            .max_frame = opts.max_frame,
            .open_ms = ms(opts.deadline),
            .close_wait_ms = ms(opts.close_wait),
            .queue_limit = opts.queue_limit,
            .recv_limit = opts.recv_limit,
            .close_flush_ms = ms(opts.close_flush),
        };
        var handle: ?*WsHandle = null;
        var fd: i32 = -1;
        var msg: [256]u8 = undefined;
        const rc = zr_net_ws_connect(c, &spec, &handle, &fd, &msg, msg.len);
        if (rc != 0) {
            std.log.warn("net: {s}", .{std.mem.sliceTo(&msg, 0)});
            return errorOf(rc);
        }
        var w: Ws = .{
            .io = io,
            .handle = handle.?,
            .done = .{ .handle = fd, .flags = .{ .nonblocking = false } },
            .own = if (own) c else null,
            .close_limit = closeLimit(opts.close_wait, opts.close_flush),
        };
        handed_over = true;
        errdefer w.abort();
        var info: WsInfo = undefined;
        while (true) {
            zr_net_ws_info(w.handle, &info);
            if (info.state != ws_connecting) break;
            try w.wait();
        }
        probe.timings = .{
            .dns_ns = opt(info.dns_ns),
            .connect_ns = opt(info.connect_ns),
            .tls_ns = opt(info.tls_ns),
            .ttfb_ns = opt(info.ttfb_ns),
            .total_ns = if (info.total_ns == std.math.maxInt(u64)) 0 else info.total_ns,
        };
        if (info.@"error" != 0) {
            std.log.warn("net: GET {s}: {s}", .{ opts.url, w.message(&msg) });
            return errorOf(info.@"error");
        }
        probe.status = info.status;
        probe.finish(.{ .code = info.status });
        return w;
    }

    fn message(w: *const Ws, buf: []u8) []const u8 {
        const n = zr_net_ws_message(w.handle, buf.ptr, buf.len);
        return buf[0..n];
    }

    /// Waits until the library has something to say: a wake on the descriptor, spurious ones included.
    fn wait(w: *const Ws) Error!void {
        var sink: [64]u8 = undefined;
        var bufs = [_][]u8{&sink};
        const n = w.done.readStreaming(w.io, &bufs) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return error.NetworkIo,
        };
        _ = n;
    }

    /// Why the connection is over: the library's error, or a close.
    fn ended(w: *Ws) Error {
        var info: WsInfo = undefined;
        zr_net_ws_info(w.handle, &info);
        var msg: [256]u8 = undefined;
        if (info.@"error" == 0) {
            // The peer closed it: its code and reason, for the log.
            std.log.info("net: websocket: {s}", .{w.message(&msg)});
            return error.WebSocketClosed;
        }
        std.log.warn("net: websocket: {s}", .{w.message(&msg)});
        return errorOf(info.@"error");
    }

    fn send(w: *Ws, kind: u32, data: []const u8) Error!void {
        while (true) switch (zr_net_ws_send(w.handle, kind, data.ptr, data.len)) {
            0 => return,
            1 => try w.wait(),
            else => return w.ended(),
        };
    }

    /// One text message, queued; waits while the queue is full (the peer reads slower than this
    /// sends). The library writes it, in frames of `max_frame`, in the order queued.
    pub fn sendText(w: *Ws, payload: []const u8) Error!void {
        return w.send(ws_text, payload);
    }

    pub fn sendBinary(w: *Ws, payload: []const u8) Error!void {
        return w.send(ws_binary, payload);
    }

    /// A ping, so a socket that has nothing to say for a while is not closed as idle on the way. The
    /// peer's are answered by the library.
    pub fn ping(w: *Ws) Error!void {
        return w.send(ws_ping, "");
    }

    /// The oldest message the peer sent, into `buf`, waiting for one; null when the peer closed the
    /// connection and nothing is left. `error.BodyTooLarge` when it does not fit `buf`.
    pub fn recv(w: *Ws, buf: []u8) Error!?Message {
        while (true) {
            var n: usize = 0;
            var kind: u32 = 0;
            switch (zr_net_ws_recv(w.handle, buf.ptr, buf.len, &n, &kind)) {
                0 => return .{ .len = n, .text = kind == ws_text },
                1 => try w.wait(),
                2 => return null,
                3 => return error.BodyTooLarge,
                else => |rc| return errorOf(rc - 100),
            }
        }
    }

    /// Bytes still queued to be sent, and the library's counts.
    pub fn counts(w: *Ws) struct { queued: usize, waiting: usize, dropped: u64, bytes_out: u64, close_code: u16, unsent: u64 } {
        var i: WsInfo = undefined;
        zr_net_ws_info(w.handle, &i);
        return .{ .queued = i.queued, .waiting = i.waiting, .dropped = i.dropped, .bytes_out = i.bytes_out, .close_code = i.close_code, .unsent = i.unsent };
    }

    /// The close handshake: what is queued is sent, then a close frame (1000), then the peer's is
    /// waited for (the library's limit, `close_wait`, 2 s by default), and the connection freed. The
    /// whole wait is within `close_limit` (`close_wait` and 3 s more, for the queue to drain): a peer
    /// that stopped reading, or went away without a word, does not hold the caller for TCP's own
    /// limit (90 s of unacknowledged data), the connection is dropped then. A cancel ends it too.
    pub fn close(w: *Ws) void {
        if (w.closed) return;
        zr_net_ws_close(w.handle);
        if (http.within(w.io, w.close_limit, untilClosed, .{w})) |ended_in_time| {
            if (ended_in_time == null) std.log.info("net: websocket: no close from the peer within {d} ms, dropped", .{w.close_limit.toMilliseconds()});
        } else |e| std.log.debug("net: websocket close: {t}", .{e});
        w.abort();
    }

    fn untilClosed(w: *Ws) void {
        while (true) {
            var i: WsInfo = undefined;
            zr_net_ws_info(w.handle, &i);
            if (i.state == ws_closed) return;
            w.wait() catch return;
        }
    }

    fn closeLimit(close_wait: ?Io.Duration, close_flush: ?Io.Duration) Io.Duration {
        const wait_ms: i64 = if (close_wait) |d| d.toMilliseconds() else 2000;
        const flush_ms: i64 = if (close_flush) |d| d.toMilliseconds() else 3000;
        // The library's own limits end it by then; this one is a second belt.
        return .fromMilliseconds(wait_ms + flush_ms + 1000);
    }

    /// Drops the connection at once, with no close frame, and frees it.
    pub fn abort(w: *Ws) void {
        if (w.closed) return;
        w.closed = true;
        zr_net_ws_free(w.handle);
        w.done.close(w.io);
        if (w.own) |c| zr_net_client_free(c);
    }
};

// --- tests the std oracle (deleted in R6, in git history as `net_oracle.zig`) used to cover, now against the test server alone ---

const testserver = @import("github/testserver.zig");

test "the request line has every figure it measured, for a plain request" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    var captured: Io.Writer.Allocating = .init(arena);
    request_log.capture = &captured;
    request_log.enabled.store(true, .monotonic);
    defer {
        request_log.enabled.store(false, .monotonic);
        request_log.capture = null;
    }
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/unavailable/x?x=y", .{server.port});
    _ = try fetch(arena, std.testing.io, .{ .url = url, .headers = &.{.{ .name = "Authorization", .value = "Bearer secret-token" }} });
    const line = captured.written();
    errdefer std.debug.print("line: {s}\n", .{line});
    var want: [96]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, line, try std.fmt.bufPrint(&want, "request: host=127.0.0.1:{d} method=GET path=/unavailable/x status=503 dns_ms=", .{server.port})));
    // Nothing of the query or the token; a plain http request has no TLS to time; a new connection.
    try std.testing.expect(std.mem.indexOf(u8, line, "secret") == null and std.mem.indexOf(u8, line, "x=y") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, " tls_ms=? ") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, " retry=0 reused=0 ") != null);
    for ([_][]const u8{ " dns_ms=?", " connect_ms=?", " ttfb_ms=?", " total_ms=?" }) |unknown|
        try std.testing.expect(std.mem.indexOf(u8, line, unknown) == null);
    try std.testing.expect(std.mem.endsWith(u8, line, " rl_remaining=? rl_limit=? rl_reset=? rl_resource=?\n"));
}

test "requests are logged by the same switch as the others' (RUNNER_LOG_REQUESTS)" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    var captured: Io.Writer.Allocating = .init(arena);
    request_log.capture = &captured;
    defer request_log.capture = null;
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/unavailable/x", .{server.port});
    // `main` stores `config.log_requests` there; tests start with it off.
    request_log.enabled.store(false, .monotonic);
    _ = try fetch(arena, std.testing.io, .{ .url = url });
    try std.testing.expectEqual(@as(usize, 0), captured.written().len);
    request_log.enabled.store(true, .monotonic);
    defer request_log.enabled.store(false, .monotonic);
    _ = try fetch(arena, std.testing.io, .{ .url = url });
    try std.testing.expect(std.mem.startsWith(u8, captured.written(), "request: host=127.0.0.1:"));
}

test "fetch: a request nobody answers is given up at its deadline, and cancelling one ends it at once" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/silent", .{server.port});

    const started = Io.Clock.awake.now(io);
    try std.testing.expectError(error.Timeout, fetch(arena, io, .{ .url = url, .deadline = .fromMilliseconds(300) }));
    try std.testing.expect(started.durationTo(Io.Clock.awake.now(io)).toMilliseconds() < 5_000);

    // The same, cancelled by the caller rather than by the deadline.
    const Runner = struct {
        fn run(a: std.mem.Allocator, i: Io, u: []const u8) Error!void {
            _ = try fetch(a, i, .{ .url = u, .deadline = .fromSeconds(60) });
        }
    };
    var f = try io.concurrent(Runner.run, .{ arena, io, url });
    try io.sleep(.fromMilliseconds(100), .awake);
    const cancelled_at = Io.Clock.awake.now(io);
    try std.testing.expectError(error.Canceled, f.cancel(io));
    try std.testing.expect(cancelled_at.durationTo(Io.Clock.awake.now(io)).toMilliseconds() < 5_000);
}

test "fetch with no deadline waits as long as it is let, and a cancel ends it at once" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "127.0.0.1", "/silent");
    const Poll = struct {
        fn run(a: std.mem.Allocator, i: Io, u: []const u8) anyerror!void {
            _ = try fetch(a, i, .{ .url = u, .deadline = null, .headers = &.{.{ .name = "Authorization", .value = "Bearer t" }} });
        }
    };
    var f = try io.concurrent(Poll.run, .{ arena, io, url });
    try io.sleep(.fromMilliseconds(700), .awake);
    const at = Io.Clock.awake.now(io);
    try std.testing.expectError(error.Canceled, f.cancel(io));
    try std.testing.expect(at.durationTo(Io.Clock.awake.now(io)).toMilliseconds() < 5_000);
}

test "a body written past its declared length is an error the caller sees, not a silent cut" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/sink", .{server.port});
    const Long = struct {
        /// How many bytes `write` writes, set per case (it runs on this thread).
        var total: usize = 0;
        fn write(_: *const Body, w: *Io.Writer) anyerror!void {
            var left = total;
            const chunk: [4096]u8 = @splat('x');
            while (left > 0) {
                const n = @min(left, chunk.len);
                try w.writeAll(chunk[0..n]);
                left -= n;
            }
        }
    };
    // Declared 100, 110 written (in the buffer, over at the flush); declared 0; declared 3 MiB
    // and 10 bytes more (the writer meets the refusal at the end of a long body).
    for ([_][2]usize{ .{ 100, 110 }, .{ 0, 10 }, .{ 3 << 20, (3 << 20) + 10 } }) |c| {
        Long.total = c[1];
        const body: Body = .{ .len = c[0], .writeFn = Long.write };
        try std.testing.expectError(error.BodyLongerThanDeclared, fetch(arena, io, .{ .method = .PUT, .url = url, .upload = &body, .deadline = .fromSeconds(10) }));
    }
    // Exactly its length is fine.
    Long.total = 100;
    const ok: Body = .{ .len = 100, .writeFn = Long.write };
    try std.testing.expectEqual(std.http.Status.ok, (try fetch(arena, io, .{ .method = .PUT, .url = url, .upload = &ok, .deadline = .fromSeconds(10) })).status);
}

test "a response limit of 0 allows no body, whole or streamed, and maxInt none" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/blob/1000", .{server.port});
    try std.testing.expectError(error.BodyTooLarge, fetch(arena, io, .{ .url = url, .max_response = 0 }));
    // Streamed: the head says how long the body is, or the first read finds it too long.
    if (open(arena, io, .{ .url = url, .max_response = 0 })) |opened| {
        var s = opened;
        defer s.close();
        var buf: [4096]u8 = undefined;
        try std.testing.expectError(error.BodyTooLarge, s.read(&buf));
    } else |e| try std.testing.expectEqual(error.BodyTooLarge, e);
    var s = try open(arena, io, .{ .url = url, .max_response = std.math.maxInt(usize) });
    defer s.close();
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = try s.read(&buf);
        if (n == 0) break;
        total += n;
    }
    try std.testing.expectEqual(@as(usize, 1000), total);
}

test "a streamed download's request line has the whole body's bytes and the final figures" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    var captured: Io.Writer.Allocating = .init(arena);
    request_log.capture = &captured;
    request_log.enabled.store(true, .monotonic);
    defer {
        request_log.enabled.store(false, .monotonic);
        request_log.capture = null;
    }
    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/blob/300000?sig=secret", .{server.port});
    var dl = try open(arena, std.testing.io, .{ .url = url, .headers = &.{.{ .name = "Authorization", .value = "Bearer secret-token" }}, .max_response = 1 << 30 });
    defer dl.close();
    var chunk: [4096]u8 = undefined;
    while ((try dl.read(&chunk)) > 0) {}
    const line = captured.written();
    errdefer std.debug.print("line: {s}\n", .{line});
    // One line, written when the body ended, with its size; nothing of the query or the token.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "request: "));
    try std.testing.expect(std.mem.startsWith(u8, line, "request: host=127.0.0.1:"));
    try std.testing.expect(std.mem.indexOf(u8, line, " method=GET path=/blob/300000 status=200 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, " bytes_in=300000 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "secret") == null);
}

test "a stream closed before its end gives up its connection and still logs its line" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    var captured: Io.Writer.Allocating = .init(arena);
    request_log.capture = &captured;
    request_log.enabled.store(true, .monotonic);
    defer {
        request_log.enabled.store(false, .monotonic);
        request_log.capture = null;
    }
    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/blob/{d}", .{ server.port, 8 << 20 });
    var s = try open(arena, std.testing.io, .{ .url = url, .max_response = 1 << 30 });
    var buf: [1000]u8 = undefined;
    try std.testing.expect((try s.read(&buf)) > 0);
    s.close();
    s.close();
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, captured.written(), "request: "));
    try std.testing.expect(std.mem.indexOf(u8, captured.written(), "status=200") != null);
    // The server's thread is still serving: a next request is answered.
    const again = try fetch(arena, std.testing.io, .{ .url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/echo", .{server.port}) });
    try std.testing.expectEqual(std.http.Status.ok, again.status);
}

test "allocation failures: a request through the network library (the arena path)" {
    const af = @import("alloc_failures.zig");
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const S = struct {
        /// The response, or out of memory; a failure of the request itself is the same as without one.
        fn run(a: std.mem.Allocator, port: u16, path: []const u8, want_status: u16, want_body: []const u8) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            var url_buf: [128]u8 = undefined;
            const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ port, path });
            const r = fetch(arena.allocator(), std.testing.io, .{
                .url = url,
                .headers = &.{ .{ .name = "Authorization", .value = "Bearer t0k" }, .{ .name = "Accept", .value = "*/*" } },
            }) catch |e| {
                if (want_status == 0 and e == error.TooManyRedirects) return;
                return e;
            };
            try std.testing.expectEqual(want_status, @as(u16, @backingInt(r.status)));
            try std.testing.expectEqualStrings(want_body, r.body);
            // The headers the request log reads, from the same memory.
            _ = r.header("content-type");
        }
    };
    try af.checkOne(S.run, .{ server.port, "/echo", 200, "GET Bearer t0k" });
    try af.checkOne(S.run, .{ server.port, "/same", 200, "GET Bearer t0k" });
    try af.checkOne(S.run, .{ server.port, "/nothing-here", 404, "{\"message\":\"Not Found\"}" });
    try af.checkOne(S.run, .{ server.port, "/limited/x", 429, "" });
    // A redirect loop ends in the library's error, not in a swallowed one.
    try af.checkOne(S.run, .{ server.port, "/loop", 0, "" });
}
