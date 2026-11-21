//! GitHub's live log feed: a WebSocket to the `FeedStreamUrl` of the job's `SystemVssConnection`
//! endpoint (`wss://results-receiver.actions.githubusercontent.com/_ws/ingest.sock`), authorized with
//! the job token. The runner only sends: text messages, split into 1 KiB frames as actions/runner
//! does. `Socket` runs on the network library (`net_client.Ws`, `rust/zr-net/src/ws.rs`: the upgrade
//! on the same connection code as every request, with its `request:` line; masking, framing, ping,
//! pong and the close handshake are the library's). The hand-written client it replaced (std's HTTP
//! client, its own framing) was held to the same frames by an oracle test until R6's removal pull
//! request; `the feed's frames on the wire` keeps what that test established.
const std = @import("std");
const http = @import("http.zig");
const net_client = @import("../net_client.zig");
const ws_server = @import("ws_server.zig");

const Allocator = std.mem.Allocator;

/// The longest payload of one frame: actions/runner splits a message into 1 KiB frames.
const max_frame_payload = 1024;

/// The feed, on the network library. `open`, `sendText`, `ping` and `close` are what `live.zig` calls.
pub const Socket = struct {
    ws: net_client.Ws,

    /// Connects (`wss://` is TLS with an upgrade), within `http.request_deadline`.
    pub fn open(s: *Socket, gpa: Allocator, io: std.Io, url: []const u8, token: []const u8) !void {
        s.* = try openWithin(gpa, io, url, token, http.request_deadline);
    }

    /// `open`, given up at `limit` (`error.Timeout`). A feed endpoint that accepted and never answered
    /// the handshake or the upgrade held the job's start, or, opened again from `Live.run`, its end,
    /// for good (#100).
    fn openWithin(gpa: Allocator, io: std.Io, url: []const u8, token: []const u8, limit: std.Io.Duration) !Socket {
        if (!std.mem.startsWith(u8, url, "wss://") and !std.mem.startsWith(u8, url, "ws://"))
            return error.NotAWebSocketUrl;
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const bearer = try std.fmt.allocPrint(arena.allocator(), "Bearer {s}", .{token});
        const ws = try net_client.Ws.open(arena.allocator(), io, .{
            .url = url,
            .headers = &.{.{ .name = "Authorization", .value = bearer }},
            .max_frame = max_frame_payload,
            .deadline = limit,
            // The peer's close is waited for briefly: the job's end does not hang on a feed that went.
            .close_wait = .fromSeconds(1),
        });
        return .{ .ws = ws };
    }

    /// One text message, queued for the library to send in frames of at most 1 KiB (the first a text
    /// frame, the rest continuations). Waits while the library's queue is full; an error when the
    /// connection has ended, which `live.zig` answers by opening the feed again.
    pub fn sendText(s: *Socket, payload: []const u8) !void {
        try s.ws.sendText(payload);
    }

    /// A ping, so a feed that has nothing to say for a while is not closed as idle on the way.
    pub fn ping(s: *Socket) !void {
        try s.ws.ping();
    }

    /// Messages that were queued, or being written, when the connection ended: never sent (for the log).
    pub fn unsent(s: *Socket) u64 {
        return s.ws.counts().unsent;
    }

    pub fn close(s: *Socket, gpa: Allocator) void {
        _ = gpa;
        s.ws.close();
    }
};

// --- tests of `Socket` ---

const Frame = ws_server.Frame;

/// What a feed does in the oracle test: short and long messages, an empty one, one of exactly a frame,
/// one of a frame and a byte, a ping, and the close.
fn script(sock: anytype, gpa: Allocator) !void {
    var long: [2500]u8 = undefined;
    for (&long, 0..) |*c, i| c.* = 'a' + @as(u8, @truncate(i % 26));
    try sock.sendText("{\"hello\":1}");
    try sock.sendText(&long);
    try sock.sendText("");
    try sock.sendText(long[0..1024]);
    try sock.sendText(long[0..1025]);
    try sock.ping();
    try sock.sendText("last");
    sock.close(gpa);
}

test "the feed's frames on the wire: every byte, 1 KiB frames, masked, a ping, a close with status 1000, and the handshake" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .record);
    defer server.stop();
    var buf: [64]u8 = undefined;
    var sock: Socket = undefined;
    try sock.open(gpa, io, server.url(&buf), "tok-123");
    try script(&sock, gpa);
    server.waitEnded();
    var seen: std.ArrayList(Frame) = .empty;
    defer seen.deinit(gpa);
    try server.recorded(&seen, gpa);
    // What the std client sent for the same script (the oracle test, until it was removed), every
    // byte: the short message, the long one (a pattern, so a shifted or repeated byte shows) in
    // three frames across the 1 KiB boundaries, the empty one, the one of exactly a frame, the one of
    // a frame and a byte (two), the ping, the last message, and the close (1000).
    var long: [2500]u8 = undefined;
    for (&long, 0..) |*c, i| c.* = 'a' + @as(u8, @truncate(i % 26));
    const want = [_]struct { opcode: u8, fin: bool, payload: []const u8 }{
        .{ .opcode = 1, .fin = true, .payload = "{\"hello\":1}" },
        .{ .opcode = 1, .fin = false, .payload = long[0..1024] },
        .{ .opcode = 0, .fin = false, .payload = long[1024..2048] },
        .{ .opcode = 0, .fin = true, .payload = long[2048..2500] },
        .{ .opcode = 1, .fin = true, .payload = "" },
        .{ .opcode = 1, .fin = true, .payload = long[0..1024] },
        .{ .opcode = 1, .fin = false, .payload = long[0..1024] },
        .{ .opcode = 0, .fin = true, .payload = long[1024..1025] },
        .{ .opcode = 9, .fin = true, .payload = "" },
        .{ .opcode = 1, .fin = true, .payload = "last" },
        .{ .opcode = 8, .fin = true, .payload = &.{ 0x03, 0xE8 } },
    };
    try std.testing.expectEqual(want.len, seen.items.len);
    for (want, seen.items, 0..) |w, f, i| {
        errdefer std.debug.print("frame {d}\n", .{i});
        try std.testing.expectEqual(w.opcode, f.opcode);
        try std.testing.expectEqual(w.fin, f.fin);
        try std.testing.expect(f.masked);
        try std.testing.expectEqualSlices(u8, w.payload, f.payload);
    }
    // The upgrade: a GET of the path with the token as a bearer, the version, `Upgrade` and
    // `Connection`, and a key of 16 random bytes in base64.
    const head = server.head.items;
    try std.testing.expect(std.mem.startsWith(u8, head, "GET /_ws/ingest.sock HTTP/1.1\r\n"));
    var key: ?[]const u8 = null;
    var squeezed: std.ArrayList(u8) = .empty;
    defer squeezed.deinit(gpa);
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], "sec-websocket-key")) key = std.mem.trim(u8, line[colon + 1 ..], " ");
        for (line) |c| if (c != ' ') try squeezed.append(gpa, std.ascii.toLower(c));
        try squeezed.append(gpa, '\n');
    }
    for ([_][]const u8{ "authorization:bearertok-123\n", "sec-websocket-version:13\n", "upgrade:websocket\n", "connection:upgrade\n" }) |h| {
        errdefer std.debug.print("missing {s} in:\n{s}\n", .{ h, head });
        try std.testing.expect(std.mem.indexOf(u8, squeezed.items, h) != null);
    }
    const k = key orelse return error.NoKey;
    try std.testing.expectEqual(@as(usize, 24), k.len);
    var raw: [16]u8 = undefined;
    try std.base64.standard.Decoder.decode(&raw, k);
}

test "an upgrade answered with the wrong Sec-WebSocket-Accept is refused" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .wrong_accept);
    defer server.stop();
    var buf: [64]u8 = undefined;
    var sock: Socket = undefined;
    try std.testing.expectError(error.ProtocolError, sock.open(gpa, io, server.url(&buf), "tok"));
}

test "a feed that accepts and never answers the upgrade is given up at its deadline" {
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(std.testing.allocator, io, .never_answer);
    defer server.stop();
    var buf: [64]u8 = undefined;
    const url = server.url(&buf);

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        Socket.openWithin(std.testing.allocator, io, url, "token", .fromMilliseconds(200)),
    );
    const took = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    try std.testing.expect(took >= 150 and took < 10_000);
}

test "a feed to a server that went away fails its next sends, which live.zig answers by reopening it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .vanish);
    defer server.stop();
    var buf: [64]u8 = undefined;
    var sock: Socket = undefined;
    // The server drops the connection right after the upgrade: the loss may be seen before `open`
    // returns, which is the same answer sooner.
    sock.open(gpa, io, server.url(&buf), "tok") catch |e| return std.testing.expectEqual(error.NetworkIo, e);
    defer sock.close(gpa);
    // The connection is lost with no close frame: sends fail within a moment, not after TCP's own
    // limits (the library reads the connection all the time, so it knows).
    var failed: ?anyerror = null;
    for (0..2000) |_| {
        sock.sendText("{}") catch |e| {
            failed = e;
            break;
        };
        io.sleep(.fromMilliseconds(5), .awake) catch {};
    }
    try std.testing.expect(failed != null);
    try std.testing.expect(failed.? == error.NetworkIo or failed.? == error.WebSocketClosed);
}

test "a URL that is not a WebSocket one is refused" {
    try std.testing.expectError(
        error.NotAWebSocketUrl,
        Socket.openWithin(std.testing.allocator, std.testing.io, "https://example.test/", "t", .fromSeconds(1)),
    );
}

test "a server's ping is answered with a pong while the feed only sends, and the close is a handshake" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .record);
    server.ping_on_open = "are-you-there";
    defer server.stop();
    var buf: [64]u8 = undefined;
    var sock: Socket = undefined;
    try sock.open(gpa, io, server.url(&buf), "tok");
    // The feed sends nothing; the library answers the ping by itself.
    server.waitFrames(1);
    {
        var seen: std.ArrayList(Frame) = .empty;
        defer seen.deinit(gpa);
        try server.recorded(&seen, gpa);
        try std.testing.expectEqual(@as(usize, 1), seen.items.len);
        try std.testing.expectEqual(@as(u8, 0xA), seen.items[0].opcode);
        try std.testing.expectEqualStrings("are-you-there", seen.items[0].payload);
        try std.testing.expect(seen.items[0].masked);
    }
    // `close` returns once the server's close arrived (the server answers it at once); the client's
    // close (status 1000) is the last frame recorded.
    const started = std.Io.Clock.awake.now(io);
    sock.close(gpa);
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds() < 1500);
    server.waitEnded();
    var seen: std.ArrayList(Frame) = .empty;
    defer seen.deinit(gpa);
    try server.recorded(&seen, gpa);
    try std.testing.expectEqual(@as(usize, 2), seen.items.len);
    try std.testing.expectEqual(@as(u8, 0x8), seen.items[1].opcode);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0xE8 }, seen.items[1].payload);
}

test "a peer that reads slowly holds the queue at its bound, wakes the sender when it drains, and loses nothing" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .stall);
    defer server.stop();
    var buf: [64]u8 = undefined;
    const limit = 16 * 1024;
    var ws = try net_client.Ws.open(gpa, io, .{ .url = server.url(&buf), .queue_limit = limit });
    defer ws.close();

    // A sender task: numbered messages of 4 KiB, one after another.
    const Sender = struct {
        ws: *net_client.Ws,
        sent: std.atomic.Value(u32) = .init(0),
        total: u32,
        fn run(self: *@This()) void {
            var msg: [4096]u8 = @splat('x');
            for (0..self.total) |i| {
                _ = std.fmt.bufPrint(msg[0..8], "{d:0>8}", .{i}) catch @panic("8 digits");
                self.ws.sendText(&msg) catch return;
                _ = self.sent.fetchAdd(1, .acq_rel);
            }
        }
    };
    // More than the kernel's buffers and the queue hold, so the stall is real.
    var sender: Sender = .{ .ws = &ws, .total = 4000 };
    var task = try io.concurrent(Sender.run, .{&sender});
    // The sender stops short, blocked in `sendText`, and the queue's bound holds (a message may be
    // in flight beyond it).
    var last: u32 = 0;
    var stable: u32 = 0;
    while (stable < 40) {
        try io.sleep(.fromMilliseconds(10), .awake);
        const now = sender.sent.load(.acquire);
        stable = if (now == last) stable + 1 else 0;
        last = now;
        try std.testing.expect(ws.counts().queued <= limit + 4096);
    }
    try std.testing.expect(last < sender.total);
    try std.testing.expect(ws.counts().queued >= limit - 4096);
    // The reader starts: the sender is woken as the queue drains, and finishes.
    server.release();
    task.await(io);
    try std.testing.expectEqual(sender.total, sender.sent.load(.acquire));
    ws.close();
    server.waitEnded();
    var seen: std.ArrayList(Frame) = .empty;
    defer seen.deinit(gpa);
    try server.recorded(&seen, gpa);
    // Every message, whole and in order, then the close.
    try std.testing.expectEqual(@as(usize, sender.total + 1), seen.items.len);
    for (seen.items[0..sender.total], 0..) |f, i| {
        var want: [8]u8 = undefined;
        _ = std.fmt.bufPrint(&want, "{d:0>8}", .{i}) catch @panic("8 digits");
        try std.testing.expectEqualStrings(&want, f.payload[0..8]);
    }
}

test "a cancel ends a sender blocked in a full queue and a reader blocked for a message" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .stall);
    defer server.stop();
    var buf: [64]u8 = undefined;

    // Mid-send: the peer reads nothing and the sender is cancelled while it waits for room.
    var ws = try net_client.Ws.open(gpa, io, .{ .url = server.url(&buf), .queue_limit = 4096 });
    const Sender = struct {
        ws: *net_client.Ws,
        outcome: ?anyerror = null,
        fn run(self: *@This()) void {
            const msg: [2048]u8 = @splat('s');
            while (true) self.ws.sendText(&msg) catch |e| {
                self.outcome = e;
                return;
            };
        }
    };
    var sender: Sender = .{ .ws = &ws };
    var task = try io.concurrent(Sender.run, .{&sender});
    // Until the kernel's buffers and the queue are full, so that it waits.
    var left: u32 = 1000;
    var last: usize = 0;
    var steady: u32 = 0;
    while (left > 0 and steady < 30) : (left -= 1) {
        try io.sleep(.fromMilliseconds(10), .awake);
        const q = ws.counts().queued;
        steady = if (q == last and q > 0) steady + 1 else 0;
        last = q;
    }
    try std.testing.expect(steady >= 30);
    task.cancel(io);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), sender.outcome);
    ws.abort();
    // The stalled server now reads what was written and then the end of the connection.
    server.release();
    server.waitEnded();
    try std.testing.expect(server.ended.load(.acquire));

    // Mid-receive: a reader waits for a message that never comes, and is cancelled.
    server.mode = .record;
    var ws2 = try net_client.Ws.open(gpa, io, .{ .url = server.url(&buf) });
    defer ws2.abort();
    const Reader = struct {
        ws: *net_client.Ws,
        outcome: ?anyerror = null,
        fn run(self: *@This()) void {
            var b: [64]u8 = undefined;
            if (self.ws.recv(&b)) |_| {} else |e| self.outcome = e;
        }
    };
    var reader: Reader = .{ .ws = &ws2 };
    var rtask = try io.concurrent(Reader.run, .{&reader});
    try io.sleep(.fromMilliseconds(100), .awake);
    rtask.cancel(io);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), reader.outcome);
}

// --- a measurement, not a check: the memory a feed connection costs ---

/// The resident set of this process, in KiB.
fn rssKib() usize {
    var buf: [128]u8 = undefined;
    const f = std.Io.Dir.cwd().openFile(std.testing.io, "/proc/self/statm", .{}) catch return 0;
    defer f.close(std.testing.io);
    var bufs = [_][]u8{&buf};
    const n = f.readStreaming(std.testing.io, &bufs) catch return 0;
    var it = std.mem.tokenizeScalar(u8, buf[0..n], ' ');
    _ = it.next();
    const pages = std.fmt.parseInt(usize, it.next() orelse return 0, 10) catch return 0;
    return pages * (std.heap.pageSize() / 1024);
}

// `ZR_FEED_RSS=<wss://...> ZR_FEED_RSS_IMPL=<a label for the line> ZR_FEED_RSS_N=<connections>`: opens N feed
// connections to the server named (the docs/rust-net.md measurement: std took about 0.6 MiB per TLS
// connection, hyper about 0.07 MiB), sends 200 messages of 1 KiB on each, and prints the resident
// set after the first connection, after N, and after the traffic. Skipped without the variable.
test "measure: resident memory per feed connection" {
    const url = std.c.getenv("ZR_FEED_RSS") orelse return error.SkipZigTest;
    const gpa = std.heap.page_allocator;
    const io = std.testing.io;
    const impl = std.mem.span(std.c.getenv("ZR_FEED_RSS_IMPL") orelse "lib");
    const n = std.fmt.parseInt(usize, std.mem.span(std.c.getenv("ZR_FEED_RSS_N") orelse "50"), 10) catch 50;
    const lib_socks = try gpa.alloc(Socket, n);
    const base = rssKib();
    var first: usize = 0;
    for (0..n) |i| {
        try lib_socks[i].open(gpa, io, std.mem.span(url), "token");
        if (i == 0) first = rssKib();
    }
    const opened = rssKib();
    var msg: [1024]u8 = @splat('m');
    for (0..200) |_| for (0..n) |i| {
        try lib_socks[i].sendText(&msg);
    };
    const sent = rssKib();
    for (0..n) |i| lib_socks[i].close(gpa);
    var out_buf: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &out_buf,
        "rss {s}: base {d} KiB; first connection +{d} KiB; {d} connections +{d} KiB ({d} KiB each after the first); after 200 x 1 KiB each +{d} KiB; closed {d} KiB\n",
        .{ impl, base, first - base, n, opened - base, if (n > 1) (opened - first) / (n - 1) else 0, sent - opened, rssKib() },
    );
    std.debug.print("{s}", .{line});
    // The tests' runner shows a passing test's output to no one: it is appended to the file named.
    if (std.c.getenv("ZR_FEED_RSS_FILE")) |path| {
        const f = try std.Io.Dir.cwd().createFile(io, std.mem.span(path), .{ .truncate = false });
        defer f.close(io);
        try f.writePositionalAll(io, line, try f.length(io));
    }
}

test "an upgrade that fails frees the client made for its roots once, whichever way it ends" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // A refused upgrade with roots of its own (the connection's client is its own): the client was
    // freed twice, by `abort` and by the open's own cleanup.
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .refuse);
    defer server.stop();
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.WebSocketRefused, net_client.Ws.open(gpa, io, .{ .url = server.url(&buf), .roots_pem = "not used by ws://" }));
    // A deadline that passes with the upgrade unanswered, and one that succeeds and is closed.
    var silent: ws_server.Server = undefined;
    try silent.start(gpa, io, .never_answer);
    defer silent.stop();
    try std.testing.expectError(error.Timeout, net_client.Ws.open(gpa, io, .{ .url = silent.url(&buf), .roots_pem = "x", .deadline = .fromMilliseconds(200) }));
    var ok: ws_server.Server = undefined;
    try ok.start(gpa, io, .record);
    defer ok.stop();
    var ws = try net_client.Ws.open(gpa, io, .{ .url = ok.url(&buf), .roots_pem = "x" });
    ws.close();
}

test "close does not wait for a peer that stopped reading, beyond its limit" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .stall);
    defer server.stop();
    var buf: [64]u8 = undefined;
    var ws = try net_client.Ws.open(gpa, io, .{ .url = server.url(&buf), .queue_limit = 4096, .close_wait = .fromMilliseconds(300) });
    const Sender = struct {
        ws: *net_client.Ws,
        fn run(self: *@This()) void {
            const msg: [2048]u8 = @splat('s');
            while (true) self.ws.sendText(&msg) catch return;
        }
    };
    var sender: Sender = .{ .ws = &ws };
    var task = try io.concurrent(Sender.run, .{&sender});
    var last: usize = 0;
    var steady: u32 = 0;
    while (steady < 30) {
        try io.sleep(.fromMilliseconds(10), .awake);
        const q = ws.counts().queued;
        steady = if (q == last and q > 0) steady + 1 else 0;
        last = q;
    }
    task.cancel(io);
    // The queue is full and the writer blocked: the close frame cannot be written. `close` gives up
    // at its limit (the wait of 300 ms and 3 s), not at TCP's.
    const started = std.Io.Clock.awake.now(io);
    ws.close();
    const took = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    try std.testing.expect(took >= 2000 and took < 8000);
    server.release();
}
