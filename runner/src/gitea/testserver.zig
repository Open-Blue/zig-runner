//! A fake Gitea for tests: an HTTP/1.1 server on 127.0.0.1 and an ephemeral port that answers
//! `POST /api/actions/runner.v1.RunnerService/<Method>` with what the test queued for that method
//! (`reply`), and remembers each call (`calls`), headers and body included. A method with nothing
//! queued answers as an instance without it does: 404 with a Connect error. As `github/testserver`,
//! it is real connections, so the client's headers and deadlines are tested as they go out.
const std = @import("std");
const Io = std.Io;

const gpa = std.testing.allocator;

/// What the server was asked: the method named in the path, the runner headers and the JSON body.
pub const Call = struct {
    method: []const u8,
    uuid: []const u8,
    token: []const u8,
    content_type: []const u8,
    connect_version: []const u8,
    body: []const u8,
};

const Reply = struct {
    method: []const u8,
    status: []const u8,
    body: []const u8,
    /// Never answered: the connection is held open, as one to a peer that went away is.
    silent: bool,
    used: bool = false,
};

pub const Server = struct {
    listener: Io.net.Server,
    port: u16,
    thread: std.Thread,
    mu: Io.Mutex = .init,
    replies: std.ArrayList(Reply) = .empty,
    calls: std.ArrayList(Call) = .empty,
    held: [4]Io.net.Stream = undefined,
    held_len: usize = 0,

    pub fn start(s: *Server) !void {
        const io = std.testing.io;
        s.* = .{ .listener = undefined, .port = 0, .thread = undefined };
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        s.listener = try addr.listen(io, .{ .reuse_address = true });
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, serve, .{s});
    }

    pub fn stop(s: *Server) void {
        const io = std.testing.io;
        if (connect(s.port)) |conn| {
            var wb: [64]u8 = undefined;
            var w = conn.writer(io, &wb);
            w.interface.writeAll("GET /quit HTTP/1.1\r\nHost: x\r\n\r\n") catch |e| std.log.warn("testserver: {s}", .{@errorName(e)});
            w.interface.flush() catch |e| std.log.warn("testserver: {s}", .{@errorName(e)});
            conn.close(io);
        } else |_| {}
        s.thread.join();
        for (s.held[0..s.held_len]) |conn| conn.close(io);
        s.listener.deinit(io);
        for (s.replies.items) |r| {
            gpa.free(r.method);
            gpa.free(r.status);
            gpa.free(r.body);
        }
        s.replies.deinit(gpa);
        for (s.calls.items) |c| {
            gpa.free(c.method);
            gpa.free(c.uuid);
            gpa.free(c.token);
            gpa.free(c.content_type);
            gpa.free(c.connect_version);
            gpa.free(c.body);
        }
        s.calls.deinit(gpa);
    }

    /// The instance's address, for `RUNNER_GITEA_URL`.
    pub fn url(s: *const Server, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}", .{s.port}) catch @panic("buffer too small");
    }

    /// Queues one answer for `method`; the first unused one is sent for each call to it.
    pub fn reply(s: *Server, method: []const u8, status: []const u8, body: []const u8) !void {
        try s.queue(.{
            .method = try gpa.dupe(u8, method),
            .status = try gpa.dupe(u8, status),
            .body = try gpa.dupe(u8, body),
            .silent = false,
        });
    }

    /// Queues a call to `method` that is never answered.
    pub fn replySilence(s: *Server, method: []const u8) !void {
        try s.queue(.{
            .method = try gpa.dupe(u8, method),
            .status = try gpa.dupe(u8, ""),
            .body = try gpa.dupe(u8, ""),
            .silent = true,
        });
    }

    fn queue(s: *Server, r: Reply) !void {
        const io = std.testing.io;
        s.mu.lockUncancelable(io);
        defer s.mu.unlock(io);
        try s.replies.append(gpa, r);
    }

    /// The calls so far of `method`.
    pub fn count(s: *Server, method: []const u8) usize {
        const io = std.testing.io;
        s.mu.lockUncancelable(io);
        defer s.mu.unlock(io);
        var n: usize = 0;
        for (s.calls.items) |c| {
            if (std.mem.eql(u8, c.method, method)) n += 1;
        }
        return n;
    }

    /// The `n`th call (from 0) of `method`; the test reads it after the call returned.
    pub fn nth(s: *Server, method: []const u8, n: usize) Call {
        const io = std.testing.io;
        s.mu.lockUncancelable(io);
        defer s.mu.unlock(io);
        var seen: usize = 0;
        for (s.calls.items) |c| if (std.mem.eql(u8, c.method, method)) {
            if (seen == n) return c;
            seen += 1;
        };
        @panic("no such call");
    }

    fn serve(s: *Server) void {
        while (true) {
            const conn = s.listener.accept(std.testing.io) catch return;
            switch (answer(s, conn)) {
                .close => conn.close(std.testing.io),
                .hold => if (s.held_len < s.held.len) {
                    s.held[s.held_len] = conn;
                    s.held_len += 1;
                } else conn.close(std.testing.io),
                .quit => {
                    conn.close(std.testing.io);
                    return;
                },
            }
        }
    }
};

const Outcome = enum { close, hold, quit };

fn connect(port: u16) !Io.net.Stream {
    const addr = try Io.net.IpAddress.parse("127.0.0.1", port);
    return addr.connect(std.testing.io, .{ .mode = .stream });
}

const prefix = "/api/actions/runner.v1.RunnerService/";

fn answer(s: *Server, conn: Io.net.Stream) Outcome {
    const io = std.testing.io;
    var rb: [4096]u8 = undefined;
    var r = conn.reader(io, &rb);
    const first = r.interface.takeDelimiterInclusive('\n') catch return .close;
    var parts = std.mem.tokenizeAny(u8, first, " \r\n");
    _ = parts.next() orelse return .close;
    const path = parts.next() orelse return .close;
    if (std.mem.eql(u8, path, "/quit")) return .quit;

    var uuid: []const u8 = "";
    var token: []const u8 = "";
    var content_type: []const u8 = "";
    var version: []const u8 = "";
    var body_len: usize = 0;
    var strings: std.ArrayList([]const u8) = .empty;
    defer {
        for (strings.items) |h| gpa.free(h);
        strings.deinit(gpa);
    }
    while (true) {
        const line = r.interface.takeDelimiterInclusive('\n') catch return .close;
        const header = std.mem.trimEnd(u8, line, "\r\n");
        if (header.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, header, ':') orelse continue;
        const name = header[0..colon];
        const value = gpa.dupe(u8, std.mem.trim(u8, header[colon + 1 ..], " ")) catch return .close;
        strings.append(gpa, value) catch return .close;
        if (std.ascii.eqlIgnoreCase(name, "x-runner-uuid")) uuid = value;
        if (std.ascii.eqlIgnoreCase(name, "x-runner-token")) token = value;
        if (std.ascii.eqlIgnoreCase(name, "content-type")) content_type = value;
        if (std.ascii.eqlIgnoreCase(name, "connect-protocol-version")) version = value;
        if (std.ascii.eqlIgnoreCase(name, "content-length"))
            body_len = std.fmt.parseInt(usize, value, 10) catch 0;
    }
    const body = gpa.alloc(u8, body_len) catch return .close;
    defer gpa.free(body);
    r.interface.readSliceAll(body) catch return .close;

    var method: []const u8 = "";
    if (std.mem.startsWith(u8, path, prefix)) method = path[prefix.len..];

    s.mu.lockUncancelable(io);
    s.calls.append(gpa, .{
        .method = gpa.dupe(u8, method) catch @panic("oom"),
        .uuid = gpa.dupe(u8, uuid) catch @panic("oom"),
        .token = gpa.dupe(u8, token) catch @panic("oom"),
        .content_type = gpa.dupe(u8, content_type) catch @panic("oom"),
        .connect_version = gpa.dupe(u8, version) catch @panic("oom"),
        .body = gpa.dupe(u8, body) catch @panic("oom"),
    }) catch @panic("oom");
    var status: []const u8 = "404 Not Found";
    var out_body: []const u8 = "{\"code\":\"unimplemented\",\"message\":\"no such method\"}";
    var silent = false;
    for (s.replies.items) |*rep| {
        if (rep.used or !std.mem.eql(u8, rep.method, method)) continue;
        rep.used = true;
        status = rep.status;
        out_body = rep.body;
        silent = rep.silent;
        break;
    }
    // Copied out: the queue may grow (and move) once the lock is let go.
    const status_copy = gpa.dupe(u8, status) catch @panic("oom");
    const body_copy = gpa.dupe(u8, out_body) catch @panic("oom");
    s.mu.unlock(io);
    defer gpa.free(status_copy);
    defer gpa.free(body_copy);
    if (silent) return .hold;

    var wb: [1024]u8 = undefined;
    var w = conn.writer(io, &wb);
    const out = &w.interface;
    out.print("HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status_copy,
        body_copy.len,
        body_copy,
    }) catch return .close;
    out.flush() catch return .close;
    return .close;
}
