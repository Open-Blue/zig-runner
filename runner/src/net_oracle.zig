//! The std client as the oracle of the network library's (docs/rust-net.md, "Validation"): the same
//! requests against `github/testserver.zig` through both, and the same status and body, and the
//! headers that mean something, from each. Kept until the std client's last use goes (R6); every
//! later PR extends the script with its call sites' shapes (R4: streamed downloads and uploads, and
//! the registry's pull flow). Where the two must differ, the case says
//! so and what each does: a difference nobody wrote down fails.
const std = @import("std");
const Io = std.Io;
const broker = @import("github/broker.zig");
const http = @import("github/http.zig");
const net_client = @import("net_client.zig");
const request_log = @import("github/request_log.zig");
const testserver = @import("github/testserver.zig");

const Case = struct {
    name: []const u8,
    method: std.http.Method = .GET,
    /// What follows `http://<host>:<port>` (host: 127.0.0.1).
    path: []const u8,
    authorization: ?[]const u8 = null,
    payload: ?[]const u8 = null,
    /// What both return, except where `std_body` says std differs.
    status: u16,
    body: []const u8,
    /// A difference of std's, written down: its status and body, and why the library's are right.
    std_status: ?u16 = null,
    std_body: ?[]const u8 = null,
    why: []const u8 = "",
    /// Both fail: std with `std_error`, the library with `error_name`.
    fails: bool = false,
};

const cases = [_]Case{
    .{ .name = "a plain GET", .path = "/echo", .status = 200, .body = "GET -" },
    .{ .name = "a GET with a token", .path = "/echo", .authorization = "Bearer t0k", .status = 200, .body = "GET Bearer t0k" },
    .{ .name = "a POST with a body", .method = .POST, .path = "/echo", .payload = "{\"a\":1}", .authorization = "Bearer t0k", .status = 200, .body = "POST Bearer t0k" },
    .{ .name = "a 404 with GitHub's body", .path = "/nothing-here", .status = 404, .body = "{\"message\":\"Not Found\"}" },
    .{ .name = "a 503 with no body", .path = "/unavailable/x", .status = 503, .body = "" },
    .{ .name = "a redirect to the same host keeps the token", .path = "/same", .authorization = "Bearer t0k", .status = 200, .body = "GET Bearer t0k" },
    .{ .name = "a relative redirect", .path = "/relative", .authorization = "Bearer t0k", .status = 200, .body = "GET Bearer t0k" },
    .{
        .name = "a 303 for a POST is a GET",
        .method = .POST,
        .path = "/see-other",
        .payload = "x",
        .status = 200,
        .body = "GET -",
        .std_status = 303,
        .std_body = "",
        .why = "std does not follow a redirect of a request with a body and hands the 303 back; the library follows it as a GET, as curl and browsers do",
    },
    .{
        .name = "a redirect to another host name takes the token away",
        .path = "/other",
        .authorization = "Bearer t0k",
        .status = 200,
        .body = "GET -",
        .std_body = "GET Bearer t0k",
        .why = "std 0.17 keeps `headers.authorization` across a redirect to another host (registry.zig works around it by hand); the library drops it",
    },
    .{ .name = "an App token is accepted only as itself", .path = "/app-token/ghs_abc", .authorization = "Bearer ghs_abc", .status = 200, .body = "ok" },
    .{ .name = "a wrong App token is refused", .path = "/app-token/ghs_abc", .authorization = "Bearer ghs_other", .status = 401, .body = "" },
    .{ .name = "a loop of redirects fails", .path = "/loop", .status = 0, .body = "", .fails = true },
};

fn viaStd(arena: std.mem.Allocator, io: Io, port: u16, c: Case) !struct { status: u16, body: []const u8 } {
    var local: std.http.Client = .{ .allocator = arena, .io = io };
    defer local.deinit();
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ port, c.path });
    var resp: Io.Writer.Allocating = .init(arena);
    const r = try http.fetch(&local, .{
        .location = .{ .url = url },
        .method = c.method,
        .payload = c.payload,
        .headers = if (c.authorization) |a| .{ .authorization = .{ .override = a } } else .{},
        .response_writer = &resp.writer,
    });
    return .{ .status = @backingInt(r.status), .body = resp.written() };
}

fn viaLibrary(arena: std.mem.Allocator, io: Io, port: u16, c: Case) !struct { status: u16, body: []const u8 } {
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ port, c.path });
    const r = try net_client.fetch(arena, io, .{
        .url = url,
        .method = c.method,
        .payload = c.payload,
        .headers = if (c.authorization) |a| &.{.{ .name = "Authorization", .value = a }} else &.{},
    });
    return .{ .status = @backingInt(r.status), .body = r.body };
}

test "oracle: the library answers what std's client does, the differences written down" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    for (cases) |c| {
        errdefer std.debug.print("case: {s}\n", .{c.name});
        if (c.fails) {
            try std.testing.expectError(error.TooManyHttpRedirects, viaStd(arena, io, server.port, c));
            try std.testing.expectError(error.TooManyRedirects, viaLibrary(arena, io, server.port, c));
            continue;
        }
        const lib = try viaLibrary(arena, io, server.port, c);
        const old = try viaStd(arena, io, server.port, c);
        try std.testing.expectEqual(c.status, lib.status);
        // A POST's echo is "<method> <auth>": the server does not echo bodies.
        try std.testing.expectEqualStrings(c.body, lib.body);
        try std.testing.expectEqual(c.std_status orelse c.status, old.status);
        try std.testing.expectEqualStrings(c.std_body orelse c.body, old.body);
    }
}

test "oracle: the library's request line has every figure it measured, for a plain request" {
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
    _ = try net_client.fetch(arena, std.testing.io, .{ .url = url, .headers = &.{.{ .name = "Authorization", .value = "Bearer secret-token" }} });
    const line = captured.written();
    errdefer std.debug.print("line: {s}\n", .{line});
    try std.testing.expect(std.mem.startsWith(u8, line, "request: host=127.0.0.1 method=GET path=/unavailable/x status=503 dns_ms="));
    // Nothing of the query or the token; a plain http request has no TLS to time; a new connection.
    try std.testing.expect(std.mem.indexOf(u8, line, "secret") == null and std.mem.indexOf(u8, line, "x=y") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, " tls_ms=? ") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, " retry=0 reused=0 ") != null);
    for ([_][]const u8{ " dns_ms=?", " connect_ms=?", " ttfb_ms=?", " total_ms=?" }) |unknown|
        try std.testing.expect(std.mem.indexOf(u8, line, unknown) == null);
    try std.testing.expect(std.mem.endsWith(u8, line, " rl_remaining=? rl_limit=? rl_reset=? rl_resource=?\n"));
}

test "oracle: the library's requests are logged by the same switch as the others' (RUNNER_LOG_REQUESTS)" {
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
    _ = try net_client.fetch(arena, std.testing.io, .{ .url = url });
    try std.testing.expectEqual(@as(usize, 0), captured.written().len);
    request_log.enabled.store(true, .monotonic);
    defer request_log.enabled.store(false, .monotonic);
    _ = try net_client.fetch(arena, std.testing.io, .{ .url = url });
    try std.testing.expect(std.mem.startsWith(u8, captured.written(), "request: host=127.0.0.1 "));
}

test "oracle: a request nobody answers is given up at its deadline, and cancelling one ends it at once" {
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
    try std.testing.expectError(error.Timeout, net_client.fetch(arena, io, .{ .url = url, .deadline = .fromMilliseconds(300) }));
    try std.testing.expect(started.durationTo(Io.Clock.awake.now(io)).toMilliseconds() < 5_000);

    // The same, cancelled by the caller rather than by the deadline.
    const Runner = struct {
        fn run(a: std.mem.Allocator, i: Io, u: []const u8) net_client.Error!void {
            _ = try net_client.fetch(a, i, .{ .url = u, .deadline = .fromSeconds(60) });
        }
    };
    var f = try io.concurrent(Runner.run, .{ arena, io, url });
    try io.sleep(.fromMilliseconds(100), .awake);
    const cancelled_at = Io.Clock.awake.now(io);
    try std.testing.expectError(error.Canceled, f.cancel(io));
    try std.testing.expect(cancelled_at.durationTo(Io.Clock.awake.now(io)).toMilliseconds() < 5_000);
}

// --- R4: downloads, uploads, the registry ---

/// FNV-1a of a download's bytes, taken as they arrive: what is compared, so that neither side needs
/// the whole body in memory to be checked (the std side holds it, being the oracle).
const Hash = testserver.Sink;

fn expectedBlob(n: u64) Hash {
    var h: Hash = .{};
    var chunk: [4096]u8 = undefined;
    var at: u64 = 0;
    while (at < n) {
        const len: usize = @intCast(@min(n - at, chunk.len));
        for (chunk[0..len], 0..) |*c, i| c.* = testserver.blobByte(at + i);
        h.add(chunk[0..len]);
        at += len;
    }
    return h;
}

const Download = struct { status: u16, hash: Hash, peak: usize = 0 };

fn downloadViaStd(arena: std.mem.Allocator, io: Io, url: []const u8, token: ?[]const u8) !Download {
    var local: std.http.Client = .{ .allocator = arena, .io = io };
    defer local.deinit();
    var resp: Io.Writer.Allocating = .init(arena);
    const r = try http.fetch(&local, .{
        .location = .{ .url = url },
        .headers = if (token) |a| .{ .authorization = .{ .override = a } } else .{},
        .response_writer = &resp.writer,
    });
    var h: Hash = .{};
    h.add(resp.written());
    return .{ .status = @backingInt(r.status), .hash = h };
}

fn downloadViaLibrary(arena: std.mem.Allocator, io: Io, url: []const u8, token: ?[]const u8, read_size: usize) !Download {
    var s = try net_client.open(arena, io, .{
        .url = url,
        .headers = if (token) |a| &.{.{ .name = "Authorization", .value = a }} else &.{},
        .max_response = 1 << 30,
    });
    defer s.close();
    var h: Hash = .{};
    const buf = try arena.alloc(u8, read_size);
    while (true) {
        const n = try s.read(buf);
        if (n == 0) break;
        h.add(buf[0..n]);
    }
    return .{ .status = @backingInt(s.status), .hash = h, .peak = s.queuePeak() };
}

test "oracle: a download is the same bytes through std's client and the library's stream, in bounded memory" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    const sizes = [_]u64{ 0, 1, 4095, 70_000, 24 << 20 };
    for (sizes) |n| {
        errdefer std.debug.print("size: {d}\n", .{n});
        var url_buf: [96]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/blob/{d}", .{ server.port, n });
        const want = expectedBlob(n);
        const old = try downloadViaStd(arena, io, url, null);
        // Reads of 1 byte-ish sizes, a page, and a big one: the same bytes whatever the reader asks.
        for ([_]usize{ 1000, 64 * 1024, 1 << 20 }) |rs| {
            const lib = try downloadViaLibrary(arena, io, url, null, rs);
            try std.testing.expectEqual(@as(u16, 200), lib.status);
            try std.testing.expectEqual(want.bytes, lib.hash.bytes);
            try std.testing.expectEqual(want.hash, lib.hash.hash);
            // The memory a download costs does not depend on its size: the queue's bound (1 MiB and
            // one read of hyper's), where std's client was handed a writer that held all of it.
            try std.testing.expect(lib.peak < (1 << 20) + 512 * 1024);
        }
        try std.testing.expectEqual(@as(u16, 200), old.status);
        try std.testing.expectEqual(want.hash, old.hash.hash);
        try std.testing.expectEqual(want.bytes, old.hash.bytes);
    }
}

test "oracle: a download redirected to another host: the library takes the token away, std keeps it" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/to-cdn/5000", .{server.port});
    const want = expectedBlob(5000);
    // With the token: the CDN (a signed URL) refuses a token it was not made for. The library does not
    // send it; std 0.17 does (the difference "a redirect to another host name takes the token away"
    // found in R3, now on a download), which registry.zig worked around by following redirects by hand.
    const lib = try downloadViaLibrary(arena, io, url, "Bearer t0k", 65536);
    try std.testing.expectEqual(@as(u16, 200), lib.status);
    try std.testing.expectEqual(want.hash, lib.hash.hash);
    const old = try downloadViaStd(arena, io, url, "Bearer t0k");
    try std.testing.expectEqual(@as(u16, 403), old.status);
    // Without one, both are the same.
    const lib2 = try downloadViaLibrary(arena, io, url, null, 65536);
    const old2 = try downloadViaStd(arena, io, url, null);
    try std.testing.expectEqual(old2.status, lib2.status);
    try std.testing.expectEqual(old2.hash.hash, lib2.hash.hash);
}

const Pattern = struct {
    len: usize,

    fn write(ptr: *const anyopaque, w: *Io.Writer) anyerror!void {
        const p: *const Pattern = @ptrCast(@alignCast(ptr));
        var chunk: [7000]u8 = undefined;
        var at: usize = 0;
        while (at < p.len) {
            const len = @min(p.len - at, chunk.len);
            for (chunk[0..len], 0..) |*c, i| c.* = testserver.blobByte(at + i);
            try w.writeAll(chunk[0..len]);
            at += len;
        }
    }
};

test "oracle: an upload written as it is sent arrives as the same bytes through std's client and the library's" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/sink", .{server.port});
    for ([_]usize{ 0, 1, 1000, 70_000, 5 << 20 }) |n| {
        errdefer std.debug.print("size: {d}\n", .{n});
        var expect_buf: [64]u8 = undefined;
        const want = expectedBlob(n);
        const expect = try std.fmt.bufPrint(&expect_buf, "{d} {x:0>16}", .{ want.bytes, want.hash });
        const pattern: Pattern = .{ .len = n };
        const body: net_client.Body = .{ .len = n, .ptr = &pattern, .writeFn = Pattern.write };
        const lib = try net_client.fetch(arena, io, .{ .method = .PUT, .url = url, .upload = body, .headers = &.{.{ .name = "x-ms-blob-type", .value = "BlockBlob" }} });
        try std.testing.expectEqual(std.http.Status.ok, lib.status);
        try std.testing.expectEqualStrings(expect, lib.body);
        const old = try broker.request(arena, io, .PUT, url, null, .{ .body = body, .content_type = "text/plain" });
        try std.testing.expectEqual(std.http.Status.ok, old.status);
        try std.testing.expectEqualStrings(expect, old.body);
    }
    // A body held in memory, as the other calls send it, the same.
    const held = try arena.alloc(u8, 3 << 20);
    for (held, 0..) |*c, i| c.* = testserver.blobByte(i);
    const lib = try net_client.fetch(arena, io, .{ .method = .POST, .url = url, .payload = held });
    var want: Hash = .{};
    want.add(held);
    var expect_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings(try std.fmt.bufPrint(&expect_buf, "{d} {x:0>16}", .{ want.bytes, want.hash }), lib.body);
}

test "oracle: an upload whose writer stops short or fails is an error, not a hung request" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: testserver.Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/sink", .{server.port});
    const Short = struct {
        fn write(_: *const anyopaque, w: *Io.Writer) anyerror!void {
            try w.writeAll("only this");
        }
        fn fail(_: *const anyopaque, w: *Io.Writer) anyerror!void {
            try w.writeAll("this much");
            return error.LogChangedWhileUploaded;
        }
    };
    var unused: u8 = 0;
    const short: net_client.Body = .{ .len = 100, .ptr = &unused, .writeFn = Short.write };
    try std.testing.expectError(error.UploadFailed, net_client.fetch(arena, io, .{ .method = .PUT, .url = url, .upload = short, .deadline = .fromSeconds(5) }));
    const failing: net_client.Body = .{ .len = 100, .ptr = &unused, .writeFn = Short.fail };
    try std.testing.expectError(error.UploadFailed, net_client.fetch(arena, io, .{ .method = .PUT, .url = url, .upload = failing, .deadline = .fromSeconds(5) }));
}

test "oracle: a streamed download's request line has the whole body's bytes and the final figures" {
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
    _ = try downloadViaLibrary(arena, std.testing.io, url, "Bearer secret-token", 4096);
    const line = captured.written();
    errdefer std.debug.print("line: {s}\n", .{line});
    // One line, written when the body ended, with its size; nothing of the query or the token.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "request: "));
    try std.testing.expect(std.mem.startsWith(u8, line, "request: host=127.0.0.1 method=GET path=/blob/300000 status=200 "));
    try std.testing.expect(std.mem.indexOf(u8, line, " bytes_in=300000 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "secret") == null);
}

test "oracle: a stream closed before its end gives up its connection and still logs its line" {
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
    var s = try net_client.open(arena, std.testing.io, .{ .url = url, .max_response = 1 << 30 });
    var buf: [1000]u8 = undefined;
    try std.testing.expect((try s.read(&buf)) > 0);
    s.close();
    s.close();
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, captured.written(), "request: "));
    try std.testing.expect(std.mem.indexOf(u8, captured.written(), "status=200") != null);
    // The server's thread is still serving: a next request is answered.
    const again = try net_client.fetch(arena, std.testing.io, .{ .url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/echo", .{server.port}) });
    try std.testing.expectEqual(std.http.Status.ok, again.status);
}
