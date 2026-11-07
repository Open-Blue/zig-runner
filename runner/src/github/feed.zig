//! A minimal WebSocket client (RFC 6455) for GitHub's live log feed: the `FeedStreamUrl` of the
//! job's `SystemVssConnection` endpoint (`wss://results-receiver.actions.githubusercontent.com/
//! _ws/ingest.sock`), authorized with the job token. The runner only sends: text messages, masked
//! as a client must, split into 1 KiB frames as actions/runner does.
const std = @import("std");
const http = @import("http.zig");

const Allocator = std.mem.Allocator;

/// The frame opcodes the runner sends (RFC 6455 §5.2).
const Opcode = struct {
    const continuation = 0x0;
    const text = 0x1;
    const close = 0x8;
    const ping = 0x9;
};

/// The longest payload of one frame: actions/runner splits a message into 1 KiB frames.
const max_frame_payload = 1024;

pub const Socket = struct {
    io: std.Io,
    /// Holds the upgraded connection; deinit closes it.
    req: std.http.Client.Request,
    local: ?*std.http.Client,

    /// Connects (`wss://` is HTTPS with an `Upgrade`), within `http.request_deadline`. The Socket
    /// must not move afterwards.
    pub fn open(s: *Socket, gpa: Allocator, io: std.Io, url: []const u8, token: []const u8) !void {
        s.* = try openWithin(gpa, io, url, token, http.request_deadline);
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
    ) !Socket {
        const r = try http.withinClosing(io, limit, connect, .{ gpa, io, url, token }, gpa, closeLate) orelse
            return error.Timeout;
        return r;
    }

    /// A feed opened just as the time ran out is closed.
    fn closeLate(gpa: Allocator, opened: anyerror!Socket) void {
        var s = opened catch return;
        s.close(gpa);
    }

    fn connect(gpa: Allocator, io: std.Io, url: []const u8, token: []const u8) anyerror!Socket {
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
    pub fn sendText(s: *Socket, payload: []const u8) !void {
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
    pub fn ping(s: *Socket) !void {
        try writeFrame(s.io, s.req.connection.?.writer(), Opcode.ping, true, &.{});
        try s.req.connection.?.flush();
    }

    pub fn close(s: *Socket, gpa: Allocator) void {
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

test "a feed that accepts and never answers the upgrade is given up at its deadline" {
    const io = std.testing.io;
    // Connections complete in the listener's backlog and are never answered.
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &buf,
        "ws://127.0.0.1:{d}/_ws/ingest.sock",
        .{listener.socket.address.getPort()},
    );

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        Socket.openWithin(std.testing.allocator, io, url, "token", .fromMilliseconds(200)),
    );
    const took = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    try std.testing.expect(took >= 200 and took < 10_000);
}
