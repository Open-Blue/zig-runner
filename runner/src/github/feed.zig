//! GitHub's live log feed: a WebSocket to the `FeedStreamUrl` of the job's `SystemVssConnection`
//! endpoint (`wss://results-receiver.actions.githubusercontent.com/_ws/ingest.sock`), authorized with
//! the job token. The runner only sends: text messages, split into 1 KiB frames as actions/runner
//! does. `Socket` runs on the network library (`net_client.Ws`, `rust/zr-net/src/ws.rs`: the upgrade
//! on the same connection code as every request, with its `request:` line; masking, framing, ping,
//! pong and the close handshake are the library's). `StdSocket` below is the hand-written client on
//! std's HTTP client that the feed was, kept for its oracle test only (docs/rust-net.md, R6): the
//! same messages must produce the same frames through both.
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

    pub fn close(s: *Socket, gpa: Allocator) void {
        _ = gpa;
        s.ws.close();
    }
};

/// The frame opcodes the runner sends (RFC 6455 §5.2).
const Opcode = struct {
    const continuation = 0x0;
    const text = 0x1;
    const close = 0x8;
    const ping = 0x9;
};

/// The feed as it was, on std's HTTP client: a hand-written client (RFC 6455) whose upgrade, framing
/// and masking are this file's. Only the oracle test uses it; it goes with the std client.
pub const StdSocket = struct {
    io: std.Io,
    /// Holds the upgraded connection; deinit closes it.
    req: std.http.Client.Request,
    local: ?*std.http.Client,

    /// Connects (`wss://` is HTTPS with an `Upgrade`), within `http.request_deadline`. The Socket
    /// must not move afterwards.
    pub fn open(s: *StdSocket, gpa: Allocator, io: std.Io, url: []const u8, token: []const u8) !void {
        // The feed is the last user of the std client (R6 moves it): the other calls no longer
        // renew it, so a client that is a day old, or whose clock judged a certificate wrong, is
        // replaced here (`http.renew`).
        http.keepFresh(io);
        s.* = openWithin(gpa, io, url, token, http.request_deadline) catch |e| {
            if (http.staleClock(e)) if (http.shared.load(.acquire)) |c| http.renew(c);
            return e;
        };
    }

    /// `connect`, given up at `limit` (`error.Timeout`), as `http.within` does. A feed endpoint that
    /// accepted and never answered the handshake or the upgrade held the job's start, or, opened
    /// again from `Live.run`, its end, for good (#100).
    fn openWithin(
        gpa: Allocator,
        io: std.Io,
        url: []const u8,
        token: []const u8,
        limit: std.Io.Duration,
    ) !StdSocket {
        const r = try http.withinClosing(io, limit, connect, .{ gpa, io, url, token }, gpa, closeLate) orelse
            return error.Timeout;
        return r;
    }

    /// A feed opened just as the time ran out is closed.
    fn closeLate(gpa: Allocator, opened: anyerror!StdSocket) void {
        var s = opened catch return;
        s.close(gpa);
    }

    fn connect(gpa: Allocator, io: std.Io, url: []const u8, token: []const u8) anyerror!StdSocket {
        const https = if (std.mem.startsWith(u8, url, "wss://"))
            try std.fmt.allocPrint(gpa, "https://{s}", .{url["wss://".len..]})
        else if (std.mem.startsWith(u8, url, "ws://"))
            try std.fmt.allocPrint(gpa, "http://{s}", .{url["ws://".len..]})
        else
            return error.NotAWebSocketUrl;
        defer gpa.free(https);

        var key_raw: [16]u8 = undefined;
        io.random(&key_raw);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &key_raw);
        const bearer = try std.fmt.allocPrint(gpa, "Bearer {s}", .{token});
        defer gpa.free(bearer);

        var local: ?*std.http.Client = null;
        const client = http.shared.load(.acquire) orelse blk: {
            const c = try gpa.create(std.http.Client);
            c.* = .{ .allocator = gpa, .io = io, .write_buffer_size = http.write_buffer_size };
            local = c;
            break :blk c;
        };
        errdefer if (local) |c| {
            c.deinit();
            gpa.destroy(c);
        };

        var req = try client.request(.GET, try std.Uri.parse(https), .{
            .headers = .{
                .connection = .{ .override = "Upgrade" },
                .authorization = .{ .override = bearer },
                .accept_encoding = .omit,
            },
            .extra_headers = &.{
                .{ .name = "Upgrade", .value = "websocket" },
                .{ .name = "Sec-WebSocket-Version", .value = "13" },
                .{ .name = "Sec-WebSocket-Key", .value = &key },
            },
            .keep_alive = false,
            .redirect_behavior = .unhandled,
        });
        errdefer req.deinit();
        // Open for the whole job and mostly idle: keepalive notices a peer that went away.
        if (req.connection) |conn| http.keepAlive(conn.stream_reader.stream.socket.handle);
        try req.sendBodiless();
        const resp = try req.receiveHead(&.{});
        if (resp.head.status != .switching_protocols) return error.WebSocketRefused;
        return .{ .io = io, .req = req, .local = local };
    }

    /// One text message: frames of at most 1 KiB, the first a text frame, the rest continuations.
    pub fn sendText(s: *StdSocket, payload: []const u8) !void {
        const w = s.req.connection.?.writer();
        var i: usize = 0;
        var first = true;
        while (true) {
            const end = @min(payload.len, i + max_frame_payload);
            const opcode: u4 = if (first) Opcode.text else Opcode.continuation;
            try writeFrame(s.io, w, opcode, end == payload.len, payload[i..end]);
            first = false;
            i = end;
            if (i == payload.len) break;
        }
        try s.req.connection.?.flush();
    }

    /// A ping, so a feed that has nothing to say for a while is not closed as idle on the way.
    pub fn ping(s: *StdSocket) !void {
        try writeFrame(s.io, s.req.connection.?.writer(), Opcode.ping, true, &.{});
        try s.req.connection.?.flush();
    }

    pub fn close(s: *StdSocket, gpa: Allocator) void {
        const w = s.req.connection.?.writer();
        // A close frame with status 1000 (normal closure).
        writeFrame(s.io, w, Opcode.close, true, &.{ 0x03, 0xE8 }) catch {};
        s.req.connection.?.flush() catch {};
        s.req.connection.?.closing = true;
        s.req.deinit();
        if (s.local) |c| {
            c.deinit();
            gpa.destroy(c);
        }
    }
};

/// One frame from a client: FIN, the opcode, the mask bit and length, a random mask, and the masked
/// payload.
fn writeFrame(io: std.Io, w: *std.Io.Writer, opcode: u4, fin: bool, payload: []const u8) !void {
    var mask: [4]u8 = undefined;
    io.random(&mask);
    try writeFrameMasked(w, opcode, fin, payload, mask);
}

fn writeFrameMasked(
    w: *std.Io.Writer,
    opcode: u4,
    fin: bool,
    payload: []const u8,
    mask: [4]u8,
) !void {
    try w.writeByte(@as(u8, if (fin) 0x80 else 0) | opcode);
    if (payload.len < 126) {
        try w.writeByte(0x80 | @as(u8, @intCast(payload.len)));
    } else if (payload.len <= 0xFFFF) {
        try w.writeByte(0x80 | 126);
        try w.writeInt(u16, @intCast(payload.len), .big);
    } else {
        try w.writeByte(0x80 | 127);
        try w.writeInt(u64, payload.len, .big);
    }
    try w.writeAll(&mask);
    for (payload, 0..) |b, i| try w.writeByte(b ^ mask[i % 4]);
}

test "client frames are masked, with the length in 7, 16 or 64 bits" {
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeFrameMasked(&w, 0x1, true, "Hi", .{ 1, 2, 3, 4 });
    try std.testing.expectEqualSlices(u8, &.{ 0x81, 0x82, 1, 2, 3, 4, 'H' ^ 1, 'i' ^ 2 }, w.buffered());

    w = .fixed(&buf);
    const long: [300]u8 = @splat(0);
    try writeFrameMasked(&w, 0x0, false, &long, .{ 0, 0, 0, 0 });
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x80 | 126, 0x01, 0x2C }, w.buffered()[0..4]);
}

// --- tests of `Socket` (the library's) and the oracle: the same messages through both ---

const Frame = ws_server.Frame;

/// What a feed does in the oracle test: short and long messages, an empty one, one of exactly a frame,
/// one of a frame and a byte, a ping, and the close.
fn script(sock: anytype, gpa: Allocator) !void {
    var long: [2500]u8 = undefined;
    for (&long, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
    try sock.sendText("{\"hello\":1}");
    try sock.sendText(&long);
    try sock.sendText("");
    try sock.sendText(long[0..1024]);
    try sock.sendText(long[0..1025]);
    try sock.ping();
    try sock.sendText("last");
    sock.close(gpa);
}

fn expectFrames(want: []const Frame, got: []const Frame) !void {
    try std.testing.expectEqual(want.len, got.len);
    for (want, got, 0..) |a, b, i| {
        errdefer std.debug.print("frame {d}: opcode {d}/{d}, fin {}/{}, len {d}/{d}\n", .{ i, a.opcode, b.opcode, a.fin, b.fin, a.payload.len, b.payload.len });
        try std.testing.expectEqual(a.opcode, b.opcode);
        try std.testing.expectEqual(a.fin, b.fin);
        try std.testing.expect(b.masked);
        try std.testing.expectEqualSlices(u8, a.payload, b.payload);
    }
}

/// The lines of an upgrade request that both clients must send alike: the request line and the
/// headers that say what is asked (not the key, the host's spelling or the user agent).
fn upgradeHeaders(head: []const u8, out: *std.ArrayList(u8), gpa: Allocator) !void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |l| {
        if (l.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, l, ':') orelse {
            try out.print(gpa, "{s}\n", .{l});
            continue;
        };
        var name_buf: [64]u8 = undefined;
        const name = std.ascii.lowerString(&name_buf, l[0..@min(colon, name_buf.len)]);
        const value = std.mem.trim(u8, l[colon + 1 ..], " ");
        for ([_][]const u8{ "authorization", "sec-websocket-version" }) |k| {
            if (std.mem.eql(u8, name, k)) try out.print(gpa, "{s}:{s}\n", .{ name, value });
        }
        // `Upgrade` and `Connection` are `websocket` and `Upgrade` in both, in whichever case.
        for ([_][]const u8{ "upgrade", "connection" }) |k| {
            if (std.mem.eql(u8, name, k)) {
                var v: [32]u8 = undefined;
                try out.print(gpa, "{s}:{s}\n", .{ name, std.ascii.lowerString(&v, value[0..@min(value.len, v.len)]) });
            }
        }
    }
}

/// The lines of `text`, sorted: the two clients send their headers in their own order.
fn sortLines(gpa: Allocator, text: *std.ArrayList(u8)) !void {
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(gpa);
    var it = std.mem.splitScalar(u8, text.items, '\n');
    while (it.next()) |l| if (l.len > 0) try lines.append(gpa, l);
    std.mem.sort([]const u8, lines.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    var sorted: std.ArrayList(u8) = .empty;
    errdefer sorted.deinit(gpa);
    for (lines.items) |l| try sorted.print(gpa, "{s}\n", .{l});
    text.deinit(gpa);
    text.* = sorted;
}

test "the feed on the library sends the same upgrade and frames as the std client, to a test server" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const Seen = struct { frames: std.ArrayList(Frame) = .empty, head: std.ArrayList(u8) = .empty };
    var results: [2]Seen = .{ .{}, .{} };
    defer for (&results) |*r| {
        for (r.frames.items) |f| gpa.free(f.payload);
        r.frames.deinit(gpa);
        r.head.deinit(gpa);
    };
    inline for (.{ StdSocket, Socket }, 0..) |T, k| {
        var server: ws_server.Server = undefined;
        try server.start(gpa, io, .record);
        defer server.stop();
        var buf: [64]u8 = undefined;
        var sock: T = undefined;
        try sock.open(gpa, io, server.url(&buf), "tok-123");
        try script(&sock, gpa);
        server.waitEnded();
        var seen: std.ArrayList(Frame) = .empty;
        defer seen.deinit(gpa);
        try server.recorded(&seen, gpa);
        // The server frees its payloads on stop: keep copies.
        for (seen.items) |f| try results[k].frames.append(gpa, .{ .opcode = f.opcode, .fin = f.fin, .masked = f.masked, .payload = try gpa.dupe(u8, f.payload) });
        try upgradeHeaders(server.head.items, &results[k].head, gpa);
        try sortLines(gpa, &results[k].head);
    }
    // The short message, the long one in three frames, the empty one, the one of exactly a frame, the one of
    // a frame and a byte (two), the ping, the last message, and the close (1000).
    try std.testing.expectEqual(@as(usize, 1 + 3 + 1 + 1 + 2 + 1 + 1 + 1), results[0].frames.items.len);
    try expectFrames(results[0].frames.items, results[1].frames.items);
    try std.testing.expectEqualStrings(results[0].head.items, results[1].head.items);
    try std.testing.expect(std.mem.indexOf(u8, results[1].head.items, "authorization:Bearer tok-123") != null);
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
    // The std client's answer to the same server was the same.
    try std.testing.expectError(
        error.Timeout,
        StdSocket.openWithin(std.testing.allocator, io, url, "token", .fromMilliseconds(200)),
    );
}

test "a feed to a server that went away fails its next sends, which live.zig answers by reopening it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var server: ws_server.Server = undefined;
    try server.start(gpa, io, .vanish);
    defer server.stop();
    var buf: [64]u8 = undefined;
    var sock: Socket = undefined;
    try sock.open(gpa, io, server.url(&buf), "tok");
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
                _ = std.fmt.bufPrint(msg[0..8], "{d:0>8}", .{i}) catch unreachable;
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
        _ = std.fmt.bufPrint(&want, "{d:0>8}", .{i}) catch unreachable;
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

// `ZR_FEED_RSS=<wss://...> ZR_FEED_RSS_IMPL=std|lib ZR_FEED_RSS_N=<connections>`: opens N feed
// connections to the server named (the docs/rust-net.md measurement: std took about 0.6 MiB per TLS
// connection, hyper about 0.07 MiB), sends 200 messages of 1 KiB on each, and prints the resident
// set after the first connection, after N, and after the traffic. Skipped without the variable.
test "measure: resident memory per feed connection" {
    const url = std.c.getenv("ZR_FEED_RSS") orelse return error.SkipZigTest;
    const gpa = std.heap.page_allocator;
    const io = std.testing.io;
    const impl = std.mem.span(std.c.getenv("ZR_FEED_RSS_IMPL") orelse "lib");
    const n = std.fmt.parseInt(usize, std.mem.span(std.c.getenv("ZR_FEED_RSS_N") orelse "50"), 10) catch 50;
    const use_std = std.mem.eql(u8, impl, "std");
    const std_socks = try gpa.alloc(StdSocket, n);
    const lib_socks = try gpa.alloc(Socket, n);
    const base = rssKib();
    var first: usize = 0;
    for (0..n) |i| {
        if (use_std) try std_socks[i].open(gpa, io, std.mem.span(url), "token") else try lib_socks[i].open(gpa, io, std.mem.span(url), "token");
        if (i == 0) first = rssKib();
    }
    const opened = rssKib();
    var msg: [1024]u8 = @splat('m');
    for (0..200) |_| for (0..n) |i| {
        if (use_std) try std_socks[i].sendText(&msg) else try lib_socks[i].sendText(&msg);
    };
    const sent = rssKib();
    for (0..n) |i| if (use_std) std_socks[i].close(gpa) else lib_socks[i].close(gpa);
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
