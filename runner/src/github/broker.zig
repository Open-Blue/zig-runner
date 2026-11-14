//! Broker session and message long-poll (v2 flow). Endpoints and bodies come from `actions/runner`
//! source and are verified live via `runner --inspect`; see SPEC §3.
const std = @import("std");
const jitconfig = @import("jitconfig.zig");
const auth = @import("auth.zig");
const http = @import("http.zig");
const ratelimit = @import("ratelimit.zig");
const request_log = @import("request_log.zig");
const net_client = @import("../net_client.zig");

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
    /// How long GitHub asked to wait before asking again, in milliseconds (`ratelimit.parse`: a
    /// 429, a 503, or a secondary rate limit's 403); 0 for no request.
    wait_ms: i64 = 0,
};

/// What may be done when a request may have reached the server and no answer came (the deadline
/// passed, a read failed, a connection died under it), chosen by each call's author, never from the
/// method alone.
pub const Resend = enum {
    /// Once more on a connection made for the request. For a call that does the same when it
    /// arrives twice: a GET, a DELETE, and the POSTs the server answers the same for the same job
    /// (see `runservice.zig`, `gitea/client.zig`).
    once_more,
    /// Not again: the first may have been done, and a second would do it twice (a session or a
    /// runner created, a task taken). The caller decides what an unknown outcome means. A
    /// connection that was closed before anything was sent is replaced by the network library
    /// whatever this says: nothing was processed, so that is always safe.
    never,
};

pub fn call(
    arena: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    token: []const u8,
    payload: ?[]const u8,
    resend: Resend,
) !Response {
    return request(arena, io, method, url, payload, .{ .token = token, .resend = resend });
}

pub const RequestOptions = struct {
    /// What to do about an unknown outcome (`Resend`). No default: every call site says.
    resend: Resend,
    /// Sent as `Authorization: Bearer`. Leave null for signed URLs (blob storage rejects extra
    /// auth).
    token: ?[]const u8 = null,
    content_type: []const u8 = "application/json",
    extra_headers: []const std.http.Header = &.{},
    /// How long one attempt may take (`net_client.Options.deadline`); null for none, for a caller
    /// that bounds the request itself or a request that lasts as long as something else does (a
    /// Dagger query runs as long as its step, a long poll as long as its poll).
    deadline: ?std.Io.Duration = http.request_deadline,
    /// The most of the body read; past it the request fails with `error.ResponseTooLarge` (a
    /// Dagger query whose answer is a step's whole output).
    max_body: usize = std.math.maxInt(usize),
    /// The request's body written out as it is sent, in place of `payload`: one too big to hold
    /// (a job's log, `results.upload`).
    body: ?*const Body = null,
    /// Whether the request gets a `request:` line (`request_log`). Off for the Dagger engine's
    /// queries, which go to the engine on this machine.
    log: bool = true,
};

/// A body of `len` bytes that `writeFn` writes, as many times as the request is sent (the network
/// library's: `net_client.Body`).
pub const Body = net_client.Body;

/// One request through the network library (`net_client.fetch`), which keeps the connections, loads
/// the CA bundle once, follows up to three redirects (dropping the token at another origin) and
/// replaces a kept connection that turns out closed before anything was sent. What it cannot see is
/// a connection that died under the request without a word (no answer by the deadline, a read that
/// failed, a streamed body it could not take back): for a call that says `Resend.once_more`, once more,
/// on a connection made for the request, so not another of the pool's from the same time; for
/// `Resend.never`, the error. A log upload read such a connection
/// for 17 minutes and then failed (#100).
pub fn request(
    arena: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
    opts: RequestOptions,
) !Response {
    var headers: std.ArrayList(std.http.Header) = .empty;
    try headers.append(arena, .{ .name = "Accept", .value = "application/json" });
    if (opts.token) |t| try headers.append(arena, .{
        .name = "Authorization",
        .value = try std.fmt.allocPrint(arena, "Bearer {s}", .{t}),
    });
    if (payload != null or opts.body != null)
        try headers.append(arena, .{ .name = "Content-Type", .value = opts.content_type });
    try headers.appendSlice(arena, opts.extra_headers);
    var attempt: u32 = 0;
    var fresh = false;
    while (true) : (attempt += 1) {
        const r = net_client.fetch(arena, io, .{
            .method = method,
            .url = url,
            .headers = headers.items,
            .payload = payload,
            .upload = opts.body,
            .fresh = fresh,
            .deadline = opts.deadline,
            .max_response = opts.max_body,
            .log = opts.log,
            .retry = attempt,
        }) catch |err| {
            if (!fresh and opts.resend == .once_more and deadConnection(err)) {
                fresh = true;
                continue;
            }
            return if (err == error.BodyTooLarge) error.ResponseTooLarge else err;
        };
        // What GitHub asked to wait (a 429's `Retry-After`, a rate limit's reset).
        const wait_ms = ratelimit.parse(
            r.status,
            r.header("retry-after"),
            r.header("x-ratelimit-remaining"),
            r.header("x-ratelimit-reset"),
            std.Io.Clock.real.now(io).toMilliseconds(),
        );
        return .{ .status = r.status, .body = r.body, .wait_ms = wait_ms };
    }
}

/// Errors of a connection that stopped answering, or went away, while it carried the request.
fn deadConnection(err: net_client.Error) bool {
    return switch (err) {
        error.Timeout, error.NetworkIo, error.StaleConnection => true,
        else => false,
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

test "over real connections: the token stays on its host, and redirects are followed by the library's rules" {
    const TestServer = @import("testserver.zig").Server;
    var server: TestServer = undefined;
    try server.start();
    defer server.stop();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const io = std.testing.io;
    const t: RequestOptions = .{ .token = "t0k", .resend = .never };
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
    // A request with a body is redirected too (before R5 the 302 was handed back): a 302 makes it
    // a GET, and the token stays on the same host.
    const posted = try request(a, io, .POST, server.url(&buf, "127.0.0.1", "/same"), "{}", t);
    try std.testing.expectEqual(std.http.Status.ok, posted.status);
    try std.testing.expectEqualStrings("GET Bearer t0k", posted.body);
    // The same for one whose body is written as it is sent; one that writes less than it said it
    // would fails, rather than sending a body of the wrong length.
    const Written = struct {
        body: Body,
        text: []const u8,
        fn init(len: usize, text: []const u8) @This() {
            return .{ .body = .{ .len = len, .writeFn = write }, .text = text };
        }
        fn write(body: *const Body, w: *std.Io.Writer) anyerror!void {
            const self: *const @This() = @fieldParentPtr("body", body);
            try w.writeAll(self.text);
        }
    };
    const whole: Written = .init(2, "{}");
    var streamed = t;
    streamed.body = &whole.body;
    const sent = try request(a, io, .POST, server.url(&buf, "127.0.0.1", "/same"), null, streamed);
    try std.testing.expectEqual(std.http.Status.ok, sent.status);
    const short: Written = .init(2, "{");
    streamed.body = &short.body;
    try std.testing.expectError(
        error.UploadFailed,
        request(a, io, .POST, server.url(&buf, "127.0.0.1", "/same"), null, streamed),
    );
    // A loop ends.
    try std.testing.expectError(
        error.TooManyRedirects,
        request(a, io, .GET, server.url(&buf, "127.0.0.1", "/loop"), null, t),
    );
    // A body past `max_body` is its own error, not the library's.
    var small = t;
    small.max_body = 4;
    try std.testing.expectError(
        error.ResponseTooLarge,
        request(a, io, .GET, server.url(&buf, "127.0.0.1", "/echo"), null, small),
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
    const quick: RequestOptions = .{ .deadline = .fromMilliseconds(200), .resend = .once_more };
    var once_only = quick;
    once_only.resend = .never;

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

    // The same request from a call that says `.never` is not sent again: the first may have been
    // done, and a session or a runner would be made twice. One attempt, the deadline's error.
    const before_never = server.accepts.load(.acquire);
    try std.testing.expectError(
        error.Timeout,
        request(a, io, .POST, server.url(&buf, "127.0.0.1", "/silent"), "{}", once_only),
    );
    try std.testing.expectEqual(before_never + 1, server.accepts.load(.acquire));

    // Never answered the first time, answered the second: a call that may be sent again succeeds
    // (two connections), one that may not fails and leaves the second request unsent (one).
    const once = server.url(&buf, "127.0.0.1", "/silent-once/x");
    const before_again = server.accepts.load(.acquire);
    const r = try request(a, io, .POST, once, "{}", quick);
    try std.testing.expectEqual(std.http.Status.ok, r.status);
    try std.testing.expectEqualStrings("ok", r.body);
    try std.testing.expectEqual(before_again + 2, server.accepts.load(.acquire));
    server.silent_once = 0;
    const before_not = server.accepts.load(.acquire);
    try std.testing.expectError(error.Timeout, request(a, io, .POST, once, "{}", once_only));
    try std.testing.expectEqual(before_not + 1, server.accepts.load(.acquire));
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
    const quick: RequestOptions = .{ .deadline = .fromMilliseconds(500), .resend = .once_more };

    for ([_][]const u8{ "/keep", "/keep-close" }, 0..) |path, i| {
        const kept = try request(a, io, .GET, server.url(&buf, "127.0.0.1", path), null, quick);
        try std.testing.expectEqualStrings("kept", kept.body);
        // /keep: the next request on the pooled connection is never answered; /keep-close: it
        // finds the connection closed. Either way it is answered on a new connection.
        const r = try request(a, io, .GET, server.url(&buf, "127.0.0.1", "/echo"), null, quick);
        try std.testing.expectEqualStrings("GET -", r.body);
        try std.testing.expectEqual(@as(u32, @intCast(2 * (i + 1))), server.accepts.load(.acquire));
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
    const t: RequestOptions = .{ .token = "t0k-secret", .resend = .never };

    // A new connection to "localhost", so that its lookup, connect and (no) TLS are timed.
    _ = try request(a, std.testing.io, .GET, server.url(&buf, "localhost", "/broker/message?sig=SECRET&sessionId=x"), null, t);
    const limited = try request(a, std.testing.io, .GET, server.url(&buf, "127.0.0.1", "/limited/ghs" ++ "_16C7e42F292c6912E7710c838347Ae178B4a"), null, t);
    try std.testing.expectEqual(std.http.Status.too_many_requests, limited.status);
    // The server's Retry-After: 7 reaches the caller, who retries by it.
    try std.testing.expectEqual(@as(i64, 7000), limited.wait_ms);

    const text = lines.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "SECRET") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "t0k") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ghs_") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "sig") == null);
    var it = std.mem.splitScalar(u8, text, '\n');
    const first = it.next().?;
    var want: [160]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, first, try std.fmt.bufPrint(&want, "request: host=localhost:{d} method=GET path=/broker/message status=200 dns_ms=", .{server.port})));
    // Plain http: no TLS to time.
    try std.testing.expect(std.mem.indexOf(u8, first, " tls_ms=? ") != null);
    try std.testing.expect(std.mem.indexOf(u8, first, " bytes_in=") != null);
    try std.testing.expect(std.mem.indexOf(u8, first, " retry=0 reused=0 rl_remaining=? rl_limit=? rl_reset=? rl_resource=?") != null);
    // Every time of a new connection that has them was measured.
    for ([_][]const u8{ " dns_ms=?", " connect_ms=?", " ttfb_ms=?", " total_ms=?" }) |unknown|
        try std.testing.expect(std.mem.indexOf(u8, first, unknown) == null);
    const second = it.next().?;
    try std.testing.expect(std.mem.indexOf(u8, second, " path=/limited/* status=429 ") != null);
    try std.testing.expect(std.mem.endsWith(u8, second, " retry=0 reused=0 rl_remaining=0 rl_limit=5000 rl_reset=1700000000 rl_resource=core"));
}
