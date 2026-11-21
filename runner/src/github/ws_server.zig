//! A WebSocket server for tests, on 127.0.0.1 and an ephemeral port: it answers the upgrade, then
//! records every frame a client sends, exactly as it arrives (opcode, FIN, whether it was masked,
//! the unmasked payload), so that the feed's two clients can be held to the same frames
//! (`feed.zig`'s oracle test) and the library's behaviours can be seen from the wire: ping, pong,
//! the close handshake, a peer that stops reading, one that goes away.
//!
//! One connection at a time, served on a thread of its own until `stop`. `mode` says how a
//! connection goes; the head of the last upgrade request is kept in `head`.
const std = @import("std");
const Io = std.Io;

pub const Frame = struct {
    opcode: u8,
    fin: bool,
    masked: bool,
    payload: []u8,
};

pub const Mode = enum {
    /// Answers the upgrade, records frames, answers a ping with a pong and a close with a close.
    record,
    /// Accepts and never answers the upgrade (the connection waits in the backlog and is held).
    never_answer,
    /// Answers the upgrade and goes: the connection is closed with no close frame.
    vanish,
    /// Answers the upgrade with a 403.
    refuse,
    /// Answers the upgrade and reads nothing until `release`, then records as `record`.
    stall,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    port: u16,
    thread: std.Thread,
    mode: Mode,
    /// Sent right after the upgrade: a ping with this payload (null: none).
    ping_on_open: ?[]const u8 = null,
    mu: Io.Mutex = .init,
    frames: std.ArrayList(Frame) = .empty,
    head: std.ArrayList(u8) = .empty,
    /// Connections accepted so far.
    accepts: std.atomic.Value(u32) = .init(0),
    /// A client's close frame was answered, or the client went away: the connection is over.
    ended: std.atomic.Value(bool) = .init(false),
    released: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),
    held: ?Io.net.Stream = null,
    /// The last error that ended a session (a client that went away is one).
    err: ?anyerror = null,

    pub fn start(s: *Server, gpa: std.mem.Allocator, io: Io, mode: Mode) !void {
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .listener = try addr.listen(io, .{ .reuse_address = true }),
            .port = 0,
            .thread = undefined,
            .mode = mode,
        };
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, serve, .{s});
    }

    /// A last connection tells the thread to stop (closing the listener does not wake a blocked
    /// accept everywhere), then it is joined.
    pub fn stop(s: *Server) void {
        s.stopping.store(true, .release);
        s.released.store(true, .release);
        if (Io.net.IpAddress.parse("127.0.0.1", s.port)) |addr| {
            if (addr.connect(s.io, .{ .mode = .stream })) |c| c.close(s.io) else |_| {}
        } else |_| {}
        s.thread.join();
        if (s.held) |c| c.close(s.io);
        s.listener.deinit(s.io);
        for (s.frames.items) |f| s.gpa.free(f.payload);
        s.frames.deinit(s.gpa);
        s.head.deinit(s.gpa);
    }

    pub fn url(s: *const Server, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "ws://127.0.0.1:{d}/_ws/ingest.sock", .{s.port}) catch @panic("the url buffer is too small");
    }

    pub fn release(s: *Server) void {
        s.released.store(true, .release);
    }

    /// The frames recorded so far (a copy of the list; the payloads are the server's).
    pub fn recorded(s: *Server, out: *std.ArrayList(Frame), gpa: std.mem.Allocator) !void {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        try out.appendSlice(gpa, s.frames.items);
    }

    pub fn count(s: *Server) usize {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        return s.frames.items.len;
    }

    /// Waits (a bounded number of short sleeps) until `n` frames are recorded or the connection is over.
    pub fn waitFrames(s: *Server, n: usize) void {
        var left: u32 = 2000;
        while (left > 0 and s.count() < n and !s.ended.load(.acquire)) : (left -= 1)
            s.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    pub fn waitEnded(s: *Server) void {
        var left: u32 = 2000;
        while (left > 0 and !s.ended.load(.acquire)) : (left -= 1)
            s.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    fn serve(s: *Server) void {
        while (true) {
            const conn = s.listener.accept(s.io) catch return;
            if (s.stopping.load(.acquire)) {
                conn.close(s.io);
                return;
            }
            _ = s.accepts.fetchAdd(1, .acq_rel);
            s.ended.store(false, .release);
            switch (s.mode) {
                .never_answer => {
                    if (s.held) |old| old.close(s.io);
                    s.held = conn;
                },
                else => {
                    s.session(conn) catch |e| {
                        s.err = e;
                    };
                    conn.close(s.io);
                    s.ended.store(true, .release);
                },
            }
        }
    }

    fn session(s: *Server, conn: Io.net.Stream) !void {
        var rb: [4096]u8 = undefined;
        var r = conn.reader(s.io, &rb);
        var wb: [1024]u8 = undefined;
        var w = conn.writer(s.io, &wb);
        const in = &r.interface;
        const out = &w.interface;

        var key: []const u8 = "";
        var key_buf: [64]u8 = undefined;
        s.mu.lockUncancelable(s.io);
        s.head.clearRetainingCapacity();
        s.mu.unlock(s.io);
        while (true) {
            const line = try in.takeDelimiterInclusive('\n');
            s.mu.lockUncancelable(s.io);
            s.head.appendSlice(s.gpa, line) catch |e| {
                s.err = e;
            };
            s.mu.unlock(s.io);
            const header = std.mem.trimEnd(u8, line, "\r\n");
            if (header.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, header, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(header[0..colon], "sec-websocket-key")) {
                const v = std.mem.trim(u8, header[colon + 1 ..], " ");
                @memcpy(key_buf[0..v.len], v);
                key = key_buf[0..v.len];
            }
        }
        if (s.mode == .refuse) {
            try out.writeAll("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            try out.flush();
            return;
        }
        var sha: [20]u8 = undefined;
        var h: std.crypto.hash.Sha1 = .init(.{});
        h.update(key);
        h.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        h.final(&sha);
        var accept: [28]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&accept, &sha);
        try out.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{accept});
        try out.flush();
        if (s.mode == .vanish) return;
        if (s.ping_on_open) |p| {
            try out.writeAll(&.{ 0x89, @as(u8, @truncate(p.len)) });
            try out.writeAll(p);
            try out.flush();
        }
        // A client that does not read, such as this one when stalled, lets its queue fill.
        if (s.mode == .stall) while (!s.released.load(.acquire)) s.io.sleep(.fromMilliseconds(5), .awake) catch return;

        while (true) {
            const b0 = try in.takeByte();
            const b1 = try in.takeByte();
            var len: u64 = b1 & 0x7f;
            if (len == 126) len = try in.takeInt(u16, .big) else if (len == 127) len = try in.takeInt(u64, .big);
            var mask: [4]u8 = @splat(0);
            const masked = b1 & 0x80 != 0;
            if (masked) try in.readSliceAll(&mask);
            const payload = try s.gpa.alloc(u8, std.math.cast(usize, len) orelse return error.FrameTooLong);
            // Owned by the list once it is in it.
            var owned = false;
            errdefer if (!owned) s.gpa.free(payload);
            try in.readSliceAll(payload);
            if (masked) for (payload, 0..) |*c, i| {
                c.* ^= mask[i % 4];
            };
            const frame: Frame = .{ .opcode = b0 & 0x0f, .fin = b0 & 0x80 != 0, .masked = masked, .payload = payload };
            s.mu.lockUncancelable(s.io);
            s.frames.append(s.gpa, frame) catch {
                s.mu.unlock(s.io);
                s.gpa.free(payload);
                return;
            };
            owned = true;
            s.mu.unlock(s.io);
            switch (frame.opcode) {
                // A close is answered with a close (the same status), and that is the end.
                0x8 => {
                    try out.writeAll(&.{ 0x88, @as(u8, @truncate(payload.len)) });
                    try out.writeAll(payload);
                    try out.flush();
                    return;
                },
                // A ping is answered with a pong of the same payload.
                0x9 => {
                    try out.writeAll(&.{ 0x8a, @as(u8, @truncate(payload.len)) });
                    try out.writeAll(payload);
                    try out.flush();
                },
                else => {},
            }
        }
    }
};
