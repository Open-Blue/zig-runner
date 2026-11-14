//! The old `broker.request`, on std's HTTP client: kept as the oracle of the network library's
//! version (`net_oracle.zig`, docs/rust-net.md "Validation") until R6 deletes the std client. Tests
//! only: nothing in the runner imports it. It is `github/broker.zig` as it was before R5, with its
//! types and helpers, and no behaviour changed.
const std = @import("std");
const http = @import("github/http.zig");
const request_log = @import("github/request_log.zig");
const net_hooks = @import("github/net_hooks.zig");
const Body = @import("net_client.zig").Body;

const Allocator = std.mem.Allocator;
const trace = false;

pub const Response = @import("github/broker.zig").Response;
pub const RequestOptions = @import("github/broker.zig").RequestOptions;

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
