//! Broker session and message long-poll (v2 flow). Endpoints and bodies come from `actions/runner`
//! source and are verified live via `runner --inspect`; see SPEC §3.
const std = @import("std");
const jitconfig = @import("jitconfig.zig");
const auth = @import("auth.zig");
const http = @import("http.zig");
const request_log = @import("request_log.zig");
const net_hooks = @import("net_hooks.zig");

const Allocator = std.mem.Allocator;

pub const version = "2.338.0";

pub const Settings = struct {
    agent_id: u64,
    agent_name: []const u8,
    broker_url: []const u8,
    use_v2: bool,
};

pub fn parseSettings(arena: Allocator, files: []const jitconfig.File) !Settings {
    const json = auth.findFile(files, ".runner") orelse return error.MissingFile;
    const R = struct {
        AgentId: []const u8,
        AgentName: []const u8,
        ServerUrlV2: []const u8,
        UseV2Flow: []const u8,
    };
    const r = try std.json.parseFromSliceLeaky(R, arena, json, .{ .ignore_unknown_fields = true });
    return .{
        .agent_id = try std.fmt.parseInt(u64, r.AgentId, 10),
        .agent_name = r.AgentName,
        .broker_url = r.ServerUrlV2,
        .use_v2 = std.ascii.eqlIgnoreCase(r.UseV2Flow, "true"),
    };
}

pub const Response = struct {
    status: std.http.Status,
    body: []const u8,
};

pub fn call(
    arena: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    token: []const u8,
    payload: ?[]const u8,
) !Response {
    return request(arena, io, method, url, payload, .{ .token = token });
}

pub const RequestOptions = struct {
    /// Sent as `Authorization: Bearer`. Leave null for signed URLs (blob storage rejects extra
    /// auth).
    token: ?[]const u8 = null,
    content_type: []const u8 = "application/json",
    extra_headers: []const std.http.Header = &.{},
    /// How long one attempt may take (`http.within`); null for none, for a caller that bounds the
    /// request itself or a request that lasts as long as something else does (a Dagger query runs
    /// as long as its step).
    deadline: ?std.Io.Duration = http.request_deadline,
    /// The most of the body read, decompressed; past it the request fails with
    /// `error.ResponseTooLarge` (a Dagger query whose answer is a step's whole output).
    max_body: usize = std.math.maxInt(usize),
    /// The request's body written out as it is sent, in place of `payload`: one too big to hold
    /// (a job's log, `results.upload`).
    body: ?Body = null,
    /// Whether the request gets a `request:` line (`request_log`). Off for the Dagger engine's
    /// queries, which go to the engine on this machine.
    log: bool = true,
};

/// A body of `len` bytes that `writeFn` writes, as many times as the request is sent (the network
/// library's: `net_client.Body`).
pub const Body = @import("../net_client.zig").Body;

pub fn request(
    arena: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
    opts: RequestOptions,
) !Response {
    // A kept-alive connection the server had closed while it sat idle (seen on completejob after a
    // 16-minute step): no byte came back (HttpConnectionClosing), or the request could not even be
    // written (WriteFailed, seen on log uploads to blob storage), so it was never processed, and
    // the connection is dropped (see `exchange`). The pool can hold many such connections to the
    // same host (one per runner that registered at once, a minute later), so try again until a
    // live or new connection answers (`http.staleRetries`).
    // A certificate judged by the shared client's stale clock: once, with a new client (`renew`).
    // A connection that died under the request without a word (no answer by the deadline, a read
    // or write that failed): once more, on a new connection of a client of its own, so not on
    // another connection the pool kept from the same time. A log upload read such a connection
    // for 17 minutes and then failed with ReadFailed (#100).
    http.keepFresh(io);
    var attempt: u32 = 0;
    var renewed = false;
    var fresh = false;
    while (true) : (attempt += 1) {
        const used = http.shared.load(.acquire);
        return requestWithin(arena, io, method, url, payload, opts, fresh, attempt) catch |err| {
            if (err == error.Canceled) return err;
            if (!renewed and http.staleClock(err) and used != null) {
                http.renew(used.?);
                renewed = true;
                continue;
            }
            if (fresh) return err;
            const closed = err == error.HttpConnectionClosing or err == error.WriteFailed;
            if (closed and attempt < http.staleRetries(used)) continue;
            if (!closed and !deadConnection(err)) return err;
            fresh = true;
            continue;
        };
    }
}

/// Errors of a connection that stopped answering, or went away, while it carried the request.
fn deadConnection(err: anyerror) bool {
    return switch (err) {
        error.Timeout,
        error.ReadFailed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.BrokenPipe,
        => true,
        else => false,
    };
}

/// One attempt, given up at `opts.deadline` (`error.Timeout`).
fn requestWithin(
    arena: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
    opts: RequestOptions,
    fresh: bool,
    attempt: u32,
) anyerror!Response {
    // The request's `request:` line: written by `exchange` when it ends, here when it did not
    // (it ran out of time, or was cancelled).
    var probe: request_log.Probe = .init(io, opts.log, method, std.Uri.parse(url) catch .{ .scheme = "" }, attempt);
    const args = .{ arena, io, method, url, payload, opts, fresh, &probe };
    const limit = opts.deadline orelse {
        const r = @call(.auto, requestOnce, args);
        if (r) |_| {} else |_| probe.finishOuter(false);
        return r;
    };
    const r = http.within(io, limit, requestOnce, args) catch |e| {
        probe.finishOuter(false);
        return e;
    };
    if (r == null) probe.finishOuter(true);
    return r orelse error.Timeout;
}

/// `fresh`: on a client of its own, whose pool is empty, rather than the shared one.
fn requestOnce(
    arena: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
    opts: RequestOptions,
    fresh: bool,
    probe: *request_log.Probe,
) anyerror!Response {
    // What the request needs only while it runs (headers, the decompression window) is freed with
    // it; only the response body goes to `arena`, which a waiting runner keeps until its next job.
    const shared = http.shared.load(.acquire);
    var scratch_state: std.heap.ArenaAllocator = .init(if (shared) |c| c.allocator else arena);
    defer scratch_state.deinit();
    const scratch = scratch_state.allocator();
    var bearer: ?[]const u8 = if (opts.token) |t| try std.fmt.allocPrint(
        scratch,
        "Bearer {s}",
        .{t},
    ) else null;
    const headers = try acceptJsonHeaders(scratch, opts.extra_headers);
    // A fresh client's CA bundle is freed with it, not kept in `arena` (one is rarely needed).
    var local: std.http.Client = .{
        .allocator = if (fresh and shared != null) shared.?.allocator else arena,
        .io = net_hooks.wrap(io),
        .write_buffer_size = http.write_buffer_size,
    };
    defer local.deinit();
    const client = if (fresh) &local else http.client(&local);

    // Redirects are followed here, not by the client: it would send the token to wherever a
    // redirect points (it drops only `privileged_headers` across domains, which it never sends at
    // all). The token goes on only to the same scheme, host and port. GitHub redirects every
    // request for a renamed or transferred repository, which is how a runner could not remove its
    // registration while the client had no room for a redirect at all.
    var target = try std.Uri.parse(url);
    var current = method;
    var hops: u32 = 0;
    while (true) : (hops += 1) {
        if (hops > 0) probe.hop(target);
        const next = switch (try exchange(probe, .{
            .arena = arena,
            .scratch = scratch,
            .client = client,
            .method = current,
            .uri = target,
            .payload = payload,
            .bearer = bearer,
            .headers = headers,
            .content_type = opts.content_type,
            .max_body = opts.max_body,
            .body = opts.body,
        })) {
            .done => |r| return r,
            .redirect => |r| r,
        };
        if (hops == max_redirects) return error.TooManyHttpRedirects;
        if (!sameOrigin(target, next.uri)) bearer = null;
        if (next.see_other) current = .GET;
        target = next.uri;
    }
}

/// GitHub's redirects come one at a time; a chain longer than this is a loop.
const max_redirects = 3;

const Exchange = struct {
    arena: Allocator,
    scratch: Allocator,
    client: *std.http.Client,
    method: std.http.Method,
    uri: std.Uri,
    payload: ?[]const u8,
    bearer: ?[]const u8,
    headers: []const std.http.Header,
    content_type: []const u8,
    max_body: usize,
    body: ?Body,
};

const Redirect = struct { uri: std.Uri, see_other: bool };

const Exchanged = union(enum) { done: Response, redirect: Redirect };

/// One request and its answer, or where a redirect points when the request has no body to resend.
/// A request with a body gets the redirect as it came: its body is already sent.
fn exchange(probe: *request_log.Probe, x: Exchange) !Exchanged {
    const r = exchangeProbed(probe, x) catch |e| {
        if (e != error.Canceled) probe.finish(e);
        return e;
    };
    probe.finish(null);
    return r;
}

fn exchangeProbed(probe: *request_log.Probe, x: Exchange) !Exchanged {
    if (trace) std.debug.print("trace: connecting {s}\n", .{@tagName(x.method)});
    var req = try x.client.request(x.method, x.uri, .{
        .headers = .{
            .authorization = if (x.bearer) |b| .{ .override = b } else .default,
            .content_type = if (x.payload != null or x.body != null)
                .{ .override = x.content_type }
            else
                .default,
        },
        .extra_headers = x.headers,
        .redirect_behavior = .unhandled,
    });
    defer req.deinit();
    probe.connected(x.client.io, req.connection);
    if (req.connection) |conn| http.keepAlive(conn.stream_reader.stream.socket.handle);
    // A connection a request failed on is not given back to the pool: one that failed while writing
    // (the server had closed it) would otherwise fail every later request to that host, which is
    // how every log upload of a runner failed from one moment on. One given up at its deadline
    // (cancelled, `http.within`) fails here too, and the next request would wait on it in turn.
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };

    if (trace) std.debug.print("trace: connected\n", .{});
    send(&req, x.payload, x.body) catch |e| return canceledOr(&req, e);
    probe.sent();
    if (trace) std.debug.print("trace: request sent\n", .{});

    var response = req.receiveHead(&.{}) catch |e| return canceledOr(&req, e);
    probe.head(response.head);
    if (trace) std.debug.print("trace: head status={d} content_length={?d} chunked={}\n", .{
        @backingInt(response.head.status),
        response.head.content_length,
        response.head.transfer_encoding == .chunked,
    });

    if (x.payload == null and x.body == null and response.head.status.class() == .redirect) {
        if (response.head.location) |location| {
            // The location is copied out first: reading past the head (the body) overwrites it.
            const buf = try x.scratch.alloc(u8, redirect_buffer_len);
            if (location.len > buf.len) return error.HttpRedirectLocationOversize;
            @memcpy(buf[0..location.len], location);
            const see_other = response.head.status == .see_other;
            _ = response.reader(&.{}).discardRemaining() catch {
                req.connection.?.closing = true;
            };
            var aux: []u8 = buf;
            const next = x.uri.resolveInPlace(location.len, &aux) catch
                return error.HttpRedirectLocationInvalid;
            return .{ .redirect = .{ .uri = next, .see_other = see_other } };
        }
    }

    // 204/304 carry no body. Without Content-Length, Request.deinit would wait on the socket for
    // one, so mark the connection closing (deinit then skips draining it).
    if (response.head.status == .no_content or response.head.status == .not_modified) {
        req.connection.?.closing = true;
        probe.bytes_in = 0;
        return .{ .done = .{ .status = response.head.status, .body = "" } };
    }

    const body = readBody(x.scratch, &response, x.max_body) catch |e|
        return canceledOr(&req, e);
    probe.bytes_in = body.len;
    if (trace) std.debug.print("trace: body {d} bytes\n", .{body.len});
    return .{ .done = .{ .status = response.head.status, .body = try x.arena.dupe(u8, body) } };
}

/// `error.Canceled` when that is what failed the connection's read or write under `err`: the client
/// reports it as ReadFailed or WriteFailed, and `request` would take that for a dead connection and
/// try again, on and on past a cancel that is signalled only once (the poll that `loop.poll` gave
/// up on, a job's end cancelling its uploads).
fn canceledOr(req: *std.http.Client.Request, err: anyerror) anyerror {
    const conn = req.connection orelse return err;
    if (conn.stream_reader.err) |e| if (e == error.Canceled) return e;
    if (conn.stream_writer.err) |e| if (e == error.Canceled) return e;
    return err;
}

/// Whether a redirect stays where the token may go: the same scheme, host and port.
fn sameOrigin(a: std.Uri, b: std.Uri) bool {
    if (!std.ascii.eqlIgnoreCase(a.scheme, b.scheme)) return false;
    var a_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    var b_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const a_host = std.Io.net.HostName.fromUri(a, &a_buf) catch return false;
    const b_host = std.Io.net.HostName.fromUri(b, &b_buf) catch return false;
    if (!std.ascii.eqlIgnoreCase(a_host.bytes, b_host.bytes)) return false;
    return (a.port orelse defaultPort(a.scheme)) == (b.port orelse defaultPort(b.scheme));
}

fn defaultPort(scheme: []const u8) ?u16 {
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
    return null;
}

/// Longer than any location GitHub redirects to (`/repositories/<id>/...` URLs, signed blob
/// URLs); and the room the resolved location may need.
const redirect_buffer_len = 8 * 1024;

/// `Accept: application/json` ahead of the caller's headers.
fn acceptJsonHeaders(scratch: Allocator, extra: []const std.http.Header) ![]std.http.Header {
    const headers = try scratch.alloc(std.http.Header, extra.len + 1);
    headers[0] = .{ .name = "Accept", .value = "application/json" };
    @memcpy(headers[1..], extra);
    return headers;
}

/// The request line and headers, then `payload` or `body` as the body when there is one.
fn send(req: *std.http.Client.Request, payload: ?[]const u8, body_in: ?Body) !void {
    if (body_in) |b| {
        req.transfer_encoding = .{ .content_length = b.len };
        var body = try req.sendBodyUnflushed(&.{});
        // The writer stops short of `len` rather than past it (std's body writer would underflow);
        // short of it, `end` would trip its assertion and take the process down.
        try b.writeFn(b.ptr, &body.writer);
        try body.writer.flush();
        if (body.state.content_length != 0) return error.BodyShorterThanItsLength;
        try body.end();
        return req.connection.?.flush();
    }
    const p = payload orelse return req.sendBodiless();
    req.transfer_encoding = .{ .content_length = p.len };
    var body = try req.sendBodyUnflushed(&.{});
    try body.writer.writeAll(p);
    try body.end();
    try req.connection.?.flush();
}

/// The whole body, decompressed, on `scratch`; `error.ResponseTooLarge` past `limit` bytes.
fn readBody(scratch: Allocator, response: *std.http.Client.Response, limit: usize) ![]const u8 {
    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const decompress_buffer = try scratch.alloc(u8, std.compress.flate.max_window_len);
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);
    return reader.allocRemaining(scratch, .limited(limit)) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
        error.StreamTooLong => return error.ResponseTooLarge,
        else => |e| return e,
    };
}

/// The machine's architecture as GitHub names it (`runner.arch`, RUNNER_ARCH): the runner, the
/// engine and the steps' containers all run on it.
pub const arch = switch (@import("builtin").cpu.arch) {
    .x86_64 => "X64",
    .aarch64 => "ARM64",
    .arm => "ARM",
    .x86 => "X86",
    else => @compileError("unsupported architecture"),
};

/// Prints request stages to stderr (never headers or bodies). Set while probing.
pub var trace = false;

pub fn messageUrl(
    arena: Allocator,
    base: []const u8,
    session_id: []const u8,
    status: []const u8,
) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "{s}message?sessionId={s}&status={s}&runnerVersion={s}" ++
            "&os=Linux&architecture=" ++ arch ++ "&disableUpdate=true",
        .{ base, session_id, status, version },
    );
}

pub fn sessionBody(arena: Allocator, s: Settings, owner: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"ownerName\":\"{s}\",\"agent\":{{\"id\":{d},\"name\":\"{s}\",\"version\":\"{s}\"," ++
            "\"osDescription\":\"Linux\",\"ephemeral\":true,\"disableUpdate\":true}}," ++
            "\"useFipsEncryption\":false}}",
        .{ owner, s.agent_id, s.agent_name, version },
    );
}

test "the token goes on only to the same scheme, host and port" {
    const api = try std.Uri.parse("https://api.github.com/repos/o/r");
    try std.testing.expect(sameOrigin(api, try std.Uri.parse("https://API.github.com/repositories/1")));
    try std.testing.expect(sameOrigin(api, try std.Uri.parse("https://api.github.com:443/x")));
    try std.testing.expect(!sameOrigin(api, try std.Uri.parse("https://objects.githubusercontent.com/x")));
    try std.testing.expect(!sameOrigin(api, try std.Uri.parse("https://evil.api.github.com/x")));
    try std.testing.expect(!sameOrigin(api, try std.Uri.parse("http://api.github.com/x")));
    try std.testing.expect(!sameOrigin(api, try std.Uri.parse("https://api.github.com:8443/x")));
}

test "over real connections: the token stays on its host, and only bodiless requests follow" {
    const TestServer = @import("testserver.zig").Server;
    var server: TestServer = undefined;
    try server.start();
    defer server.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const io = std.testing.io;
    const t: RequestOptions = .{ .token = "t0k" };
    var buf: [64]u8 = undefined;

    // Sent without a redirect, kept on one to the same host (absolute or relative).
    for ([_][]const u8{ "/echo", "/same", "/relative" }) |path| {
        const r = try request(a, io, .GET, server.url(&buf, "127.0.0.1", path), null, t);
        try std.testing.expectEqual(std.http.Status.ok, r.status);
        try std.testing.expectEqualStrings("GET Bearer t0k", r.body);
    }
    // Dropped on a redirect to another host: the same server, by another name.
    const other = try request(a, io, .GET, server.url(&buf, "127.0.0.1", "/other"), null, t);
    try std.testing.expectEqualStrings("GET -", other.body);
    // A 303 continues as a GET.
    const seen = try request(a, io, .DELETE, server.url(&buf, "127.0.0.1", "/see-other"), null, t);
    try std.testing.expectEqualStrings("GET Bearer t0k", seen.body);
    // A request with a body gets the redirect as it came.
    const posted = try request(a, io, .POST, server.url(&buf, "127.0.0.1", "/same"), "{}", t);
    try std.testing.expectEqual(std.http.Status.found, posted.status);
    // So does one whose body is written as it is sent; one that writes less than it said it would
    // fails, rather than tripping the body writer's assertion and taking the process down.
    const Written = struct {
        text: []const u8,
        fn write(ptr: *const anyopaque, w: *std.Io.Writer) anyerror!void {
            const self: *const @This() = @ptrCast(@alignCast(ptr));
            try w.writeAll(self.text);
        }
    };
    const whole: Written = .{ .text = "{}" };
    var streamed = t;
    streamed.body = .{ .len = 2, .ptr = &whole, .writeFn = Written.write };
    const sent = try request(a, io, .POST, server.url(&buf, "127.0.0.1", "/same"), null, streamed);
    try std.testing.expectEqual(std.http.Status.found, sent.status);
    const short: Written = .{ .text = "{" };
    streamed.body = .{ .len = 2, .ptr = &short, .writeFn = Written.write };
    try std.testing.expectError(
        error.BodyShorterThanItsLength,
        request(a, io, .POST, server.url(&buf, "127.0.0.1", "/same"), null, streamed),
    );
    // A loop ends.
    try std.testing.expectError(
        error.TooManyHttpRedirects,
        request(a, io, .GET, server.url(&buf, "127.0.0.1", "/loop"), null, t),
    );
}

test "a request never answered is given up at its deadline, and tried once on a new connection" {
    const TestServer = @import("testserver.zig").Server;
    var server: TestServer = undefined;
    try server.start();
    defer server.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const io = std.testing.io;
    var buf: [64]u8 = undefined;
    const quick: RequestOptions = .{ .deadline = .fromMilliseconds(200) };

    // A blob upload, as `results.putBlob` makes it, to a server that never answers.
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        request(a, io, .PUT, server.url(&buf, "127.0.0.1", "/silent"), "log text", quick),
    );
    const took = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    // Two attempts of 200 ms each, not the minutes a dead connection used to be read for.
    try std.testing.expect(took >= 400 and took < 10_000);
    try std.testing.expectEqual(@as(u32, 2), server.accepts.load(.acquire));

    // Never answered the first time, answered the second: the retry succeeds.
    const once = server.url(&buf, "127.0.0.1", "/silent-once/x");
    const r = try request(a, io, .POST, once, "{}", quick);
    try std.testing.expectEqual(std.http.Status.ok, r.status);
    try std.testing.expectEqualStrings("ok", r.body);
    try std.testing.expectEqual(@as(u32, 4), server.accepts.load(.acquire));
}

test "a kept-alive connection that went silent is dropped, and the request tried on a new one" {
    const TestServer = @import("testserver.zig").Server;
    var server: TestServer = undefined;
    try server.start();
    defer server.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const io = std.testing.io;
    var buf: [64]u8 = undefined;
    // Connections are pooled only by the shared client.
    var client: std.http.Client = .{ .allocator = std.testing.allocator, .io = io };
    defer client.deinit();
    http.shared.store(&client, .release);
    defer http.shared.store(null, .release);
    const quick: RequestOptions = .{ .deadline = .fromMilliseconds(200) };

    for ([_][]const u8{ "/keep", "/keep-close" }, 0..) |path, i| {
        const kept = try request(a, io, .GET, server.url(&buf, "127.0.0.1", path), null, quick);
        try std.testing.expectEqualStrings("kept", kept.body);
        try std.testing.expectEqual(@as(usize, 1), client.connection_pool.free_len);
        // /keep: the next request on the pooled connection is never answered; /keep-close: it
        // finds the connection closed. Either way it is answered on a new connection.
        const r = try request(a, io, .GET, server.url(&buf, "127.0.0.1", "/echo"), null, quick);
        try std.testing.expectEqualStrings("GET -", r.body);
        try std.testing.expectEqual(@as(u32, @intCast(2 * (i + 1))), server.accepts.load(.acquire));
        // The connection given up is not back in the pool for the next request to wait on.
        try std.testing.expectEqual(@as(usize, 0), client.connection_pool.free_len);
    }
}

test "parseSettings" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const files = [_]jitconfig.File{.{ .name = ".runner", .content = "{\"AgentId\":\"2\",\"AgentName\":\"n\",\"ServerUrlV2\":\"https://b/\",\"UseV2Flow\":\"true\",\"Extra\":1}" }};
    const s = try parseSettings(a.allocator(), &files);
    try std.testing.expectEqual(@as(u64, 2), s.agent_id);
    try std.testing.expect(s.use_v2);
}

test "request lines: timed, without the query or a token, and a 429's rate limit headers and retry-after" {
    const TestServer = @import("testserver.zig").Server;
    var server: TestServer = undefined;
    try server.start();
    defer server.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var lines: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer lines.deinit();
    request_log.capture = &lines;
    request_log.enabled.store(true, .monotonic);
    defer {
        request_log.capture = null;
        request_log.enabled.store(false, .monotonic);
    }
    var buf: [128]u8 = undefined;
    const t: RequestOptions = .{ .token = "t0k-secret" };

    // A new connection to "localhost", so that its lookup, connect and (no) TLS are timed.
    _ = try request(a, std.testing.io, .GET, server.url(&buf, "localhost", "/broker/message?sig=SECRET&sessionId=x"), null, t);
    const limited = try request(a, std.testing.io, .GET, server.url(&buf, "127.0.0.1", "/limited/ghs" ++ "_16C7e42F292c6912E7710c838347Ae178B4a"), null, t);
    try std.testing.expectEqual(std.http.Status.too_many_requests, limited.status);

    const text = lines.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "SECRET") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "t0k") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ghs_") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "sig") == null);
    var it = std.mem.splitScalar(u8, text, '\n');
    const first = it.next().?;
    var want: [160]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, first, try std.fmt.bufPrint(&want, "request: host=localhost:{d} method=GET path=/broker/message status=200 dns_ms=", .{server.port})));
    try std.testing.expect(std.mem.indexOf(u8, first, " tls_ms=0.0 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, first, " bytes_in=") != null);
    try std.testing.expect(std.mem.indexOf(u8, first, " retry=0 reused=0 rl_remaining=? rl_limit=? rl_reset=? rl_resource=?") != null);
    // Every time of a new connection was measured.
    try std.testing.expect(std.mem.indexOf(u8, first, "ms=?") == null);
    const second = it.next().?;
    try std.testing.expect(std.mem.indexOf(u8, second, " path=/limited/* status=429 ") != null);
    try std.testing.expect(std.mem.endsWith(u8, second, " retry=0 reused=0 rl_remaining=0 rl_limit=5000 rl_reset=1700000000 rl_resource=core"));
}
