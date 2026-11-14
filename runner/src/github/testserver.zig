//! A small HTTP/1.1 server for tests, on 127.0.0.1 and an ephemeral port, answering each request by
//! its path. The client's handling of redirects and tokens is then tested over real connections:
//! a unit test that only described the request once passed while every request had lost its token
//! (`broker.request`). "localhost" reaches the same server under another host name, which is what a
//! redirect to another host needs.
//!
//!   /echo        200, body "<method> <Authorization header, or ->"
//!   /same        302 to http://127.0.0.1:<port>/echo
//!   /other       302 to http://localhost:<port>/echo
//!   /relative    302 to /echo
//!   /see-other   303 to /echo
//!   /loop        302 to /loop
//!   /unavailable/...  503
//!   /limited/...  429 with `Retry-After: 7` and GitHub's `X-RateLimit-*` headers (remaining 0 of
//!                5000, resetting at 1700000000, resource `core`)
//!   /broker/message?...  200, a `RunnerJobRequest` whose run service is /nowhere (so acquirejob
//!                answers 404); each one counted in `Server.polls`
//!   /silent      never answered: the connection stays open, as one to a peer that went away
//!                without a word does (written to, never read from)
//!   /silent-once/...  never answered the first time (of all such paths), 200 "ok" after that
//!   /keep        200 "kept", and the connection kept alive; the next request on it is never
//!                answered, as on a kept-alive connection GitHub dropped silently while idle
//!   /keep-close  200 "kept", the connection kept alive as far as the client knows, then closed
//!   /repos/o/r/installation, /orgs/acme/installation  200, installation 42 or 43, for a
//!                request with a JWT (`Bearer eyJ...`); 401 without one
//!   /app/installations/<id>/access_tokens  201, installation token `ghs_<n>` (n counts them, in
//!                `Server.app_tokens`) expiring at 2030-01-01T00:00:00Z, for a JWT
//!   /app-token/<token>  200 "ok" with `Authorization: Bearer <token>`, else 401
//!   /results/twirp/results.services.receiver.Receiver/<Method>  200, a `logs_url` naming
//!                /results-blob for the Get...SignedBlobURL methods, "{}" for the rest; /results-blob
//!                (PUT) 201. Each kind counted in `Server.results`. The first `results_fail`
//!                requests whose path contains `results_fail_on` answer `results_fail_status`
//!                instead (a results service having a bad moment).
//!   /blob/<n>    200, n bytes of `blobByte` (any size: a download for streaming tests)
//!   /to-cdn/<n>  302 to http://localhost:<port>/cdn-blob/<n>, another host name
//!   /cdn-blob/<n>  the same bytes, but 403 for a request that carries an Authorization header (a
//!                signed URL refuses the token it was not made for)
//!   /sink        200, "<bytes received> <fnv1a-64 of them, hex>" for any body (an upload)
//!   anything else 404, with GitHub's `{"message":"Not Found"}`
//!
//! Every connection accepted is counted in `Server.accepts`.
const std = @import("std");
const Io = std.Io;

pub const Server = struct {
    listener: Io.net.Server,
    port: u16,
    thread: std.Thread,
    /// Requests to /broker/message so far.
    polls: std.atomic.Value(u32),
    /// Connections accepted so far.
    accepts: std.atomic.Value(u32),
    /// Requests to the results service so far: signed URLs asked for, blobs put, metadata made.
    results: struct { urls: u32 = 0, puts: u32 = 0, metas: u32 = 0, put_bytes: usize = 0 },
    /// How many requests to a path containing `results_fail_on` answer `results_fail_status`.
    results_fail: u32,
    results_fail_on: []const u8,
    results_fail_status: []const u8,
    /// Installation tokens minted so far (/app/installations/...).
    app_tokens: std.atomic.Value(u32),
    /// Requests to /silent-once/... so far.
    silent_once: u32,
    /// Connections left unanswered (/silent, /keep), closed by `stop`; used by the thread only.
    held: [8]Io.net.Stream,
    held_len: usize,

    /// Listens and serves on a thread of its own until `stop`.
    pub fn start(s: *Server) !void {
        const io = std.testing.io;
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        s.listener = try addr.listen(io, .{ .reuse_address = true });
        s.port = s.listener.socket.address.getPort();
        s.polls = .init(0);
        s.accepts = .init(0);
        s.app_tokens = .init(0);
        s.silent_once = 0;
        s.results = .{};
        s.results_fail = 0;
        s.results_fail_on = "";
        s.results_fail_status = "503 Service Unavailable";
        s.held_len = 0;
        s.thread = try std.Thread.spawn(.{}, serve, .{s});
    }

    /// A last request tells the thread to stop (closing the listener does not wake a blocked
    /// accept everywhere), then it is joined.
    pub fn stop(s: *Server) void {
        const io = std.testing.io;
        if (connect(s.port)) |conn| {
            var wb: [64]u8 = undefined;
            var w = conn.writer(io, &wb);
            w.interface.writeAll("GET /quit HTTP/1.1\r\nHost: x\r\n\r\n") catch {};
            w.interface.flush() catch {};
            conn.close(io);
        } else |_| {}
        s.thread.join();
        for (s.held[0..s.held_len]) |conn| conn.close(io);
        s.listener.deinit(io);
    }

    /// `http://<host>:<port><path>` on `buf`.
    pub fn url(s: *const Server, buf: []u8, host: []const u8, path: []const u8) []const u8 {
        const port = s.port;
        return std.fmt.bufPrint(buf, "http://{s}:{d}{s}", .{ host, port, path }) catch unreachable;
    }

    fn serve(s: *Server) void {
        while (true) {
            const conn = s.listener.accept(std.testing.io) catch return;
            _ = s.accepts.fetchAdd(1, .acq_rel);
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

/// The byte at `i` of a /blob/<n>.
pub fn blobByte(i: u64) u8 {
    return @truncate((i *% 2654435761) >> 7);
}

/// What /sink received: how much, and its FNV-1a (64).
pub const Sink = struct {
    bytes: u64 = 0,
    hash: u64 = 0xcbf29ce484222325,

    pub fn add(s: *Sink, data: []const u8) void {
        for (data) |c| s.hash = (s.hash ^ c) *% 0x100000001b3;
        s.bytes += data.len;
    }
};

/// What becomes of a connection once its request is answered (or not).
const Outcome = enum { close, hold, quit };

fn connect(port: u16) !Io.net.Stream {
    const addr = try Io.net.IpAddress.parse("127.0.0.1", port);
    return addr.connect(std.testing.io, .{ .mode = .stream });
}

/// One request on `conn`, answered or not, and what becomes of the connection.
fn answer(s: *Server, conn: Io.net.Stream) Outcome {
    const io = std.testing.io;
    const port = s.port;
    var rb: [4096]u8 = undefined;
    var r = conn.reader(io, &rb);
    const first = r.interface.takeDelimiterInclusive('\n') catch return .close;
    var parts = std.mem.tokenizeAny(u8, first, " \r\n");
    var method_buf: [16]u8 = undefined;
    const method = copy(&method_buf, parts.next() orelse return .close);
    var path_buf: [256]u8 = undefined;
    const path = copy(&path_buf, parts.next() orelse return .close);

    var auth_buf: [1024]u8 = undefined;
    var auth: []const u8 = "-";
    var body_len: usize = 0;
    while (true) {
        const line = r.interface.takeDelimiterInclusive('\n') catch return .close;
        const header = std.mem.trimEnd(u8, line, "\r\n");
        if (header.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, header, ':') orelse continue;
        const name = header[0..colon];
        const value = std.mem.trim(u8, header[colon + 1 ..], " ");
        if (std.ascii.eqlIgnoreCase(name, "authorization")) auth = copy(&auth_buf, value);
        if (std.ascii.eqlIgnoreCase(name, "content-length"))
            body_len = std.fmt.parseInt(usize, value, 10) catch 0;
    }
    var sunk: Sink = .{};
    if (std.mem.eql(u8, path, "/sink")) {
        var left = body_len;
        var chunk: [16 * 1024]u8 = undefined;
        while (left > 0) {
            const n = r.interface.readSliceShort(chunk[0..@min(left, chunk.len)]) catch return .close;
            if (n == 0) return .close;
            sunk.add(chunk[0..n]);
            left -= n;
        }
    } else r.interface.discardAll(body_len) catch {};
    if (std.mem.eql(u8, path, "/quit")) return .quit;
    if (std.mem.eql(u8, path, "/silent")) return .hold;
    if (std.mem.startsWith(u8, path, "/silent-once/")) {
        s.silent_once += 1;
        if (s.silent_once == 1) return .hold;
    }

    var wb: [1024]u8 = undefined;
    var w = conn.writer(io, &wb);
    const out = &w.interface;
    var loc_buf: [128]u8 = undefined;
    if (std.mem.startsWith(u8, path, "/blob/") or std.mem.startsWith(u8, path, "/cdn-blob/") or
        std.mem.startsWith(u8, path, "/to-cdn/"))
    {
        const tail = path[std.mem.lastIndexOfScalar(u8, path, '/').? + 1 ..];
        const n = std.fmt.parseInt(u64, tail[0 .. std.mem.indexOfScalar(u8, tail, '?') orelse tail.len], 10) catch 0;
        if (std.mem.startsWith(u8, path, "/to-cdn/")) {
            var b: [64]u8 = undefined;
            const loc = std.fmt.bufPrint(&b, "http://localhost:{d}/cdn-blob/{d}", .{ port, n }) catch return .close;
            respond(out, "302 Found", loc, "");
        } else if (std.mem.startsWith(u8, path, "/cdn-blob/") and !std.mem.eql(u8, auth, "-")) {
            respond(out, "403 Forbidden", null, "token refused");
        } else {
            out.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{n}) catch return .close;
            var chunk: [8192]u8 = undefined;
            var at: u64 = 0;
            while (at < n) {
                const len: usize = @intCast(@min(n - at, chunk.len));
                for (chunk[0..len], 0..) |*c, i| c.* = blobByte(at + i);
                out.writeAll(chunk[0..len]) catch return .close;
                at += len;
            }
        }
    } else if (std.mem.eql(u8, path, "/sink")) {
        var b: [64]u8 = undefined;
        respond(out, "200 OK", null, std.fmt.bufPrint(&b, "{d} {x:0>16}", .{ sunk.bytes, sunk.hash }) catch return .close);
    } else if (std.mem.eql(u8, path, "/echo")) {
        var body_buf: [1100]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{s} {s}", .{ method, auth }) catch return .close;
        respond(out, "200 OK", null, body);
    } else if (std.mem.eql(u8, path, "/same")) {
        respond(out, "302 Found", fmtLoc(&loc_buf, "127.0.0.1", port), "");
    } else if (std.mem.eql(u8, path, "/other")) {
        respond(out, "302 Found", fmtLoc(&loc_buf, "localhost", port), "");
    } else if (std.mem.eql(u8, path, "/relative")) {
        respond(out, "302 Found", "/echo", "");
    } else if (std.mem.eql(u8, path, "/see-other")) {
        respond(out, "303 See Other", "/echo", "");
    } else if (std.mem.eql(u8, path, "/loop")) {
        respond(out, "302 Found", "/loop", "");
    } else if (std.mem.startsWith(u8, path, "/unavailable/")) {
        respond(out, "503 Service Unavailable", null, "");
    } else if (std.mem.startsWith(u8, path, "/limited/")) {
        out.writeAll("HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n" ++
            "Retry-After: 7\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Limit: 5000\r\n" ++
            "X-RateLimit-Reset: 1700000000\r\nX-RateLimit-Resource: core\r\n\r\n") catch return .close;
    } else if (std.mem.startsWith(u8, path, "/broker/message?")) {
        _ = s.polls.fetchAdd(1, .acq_rel);
        var body_buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(
            &body_buf,
            "{{\"messageType\":\"RunnerJobRequest\",\"body\":\"{{\\\"runner_request_id\\\":" ++
                "\\\"r\\\",\\\"run_service_url\\\":\\\"http://127.0.0.1:{d}/nowhere\\\"}}\"}}",
            .{port},
        ) catch return .close;
        respond(out, "200 OK", null, body);
    } else if (std.mem.startsWith(u8, path, "/results")) {
        const failing = s.results_fail > 0 and std.mem.indexOf(u8, path, s.results_fail_on) != null;
        if (failing) s.results_fail -= 1;
        if (failing) {
            respond(out, s.results_fail_status, null, "{\"message\":\"try later\"}");
        } else if (std.mem.eql(u8, path, "/results-blob")) {
            s.results.puts += 1;
            s.results.put_bytes = body_len;
            respond(out, "201 Created", null, "");
        } else if (std.mem.indexOf(u8, path, "SignedBlobURL") != null) {
            s.results.urls += 1;
            var body_buf: [128]u8 = undefined;
            const body = std.fmt.bufPrint(
                &body_buf,
                "{{\"logs_url\":\"http://127.0.0.1:{d}/results-blob\"}}",
                .{port},
            ) catch return .close;
            respond(out, "200 OK", null, body);
        } else {
            s.results.metas += 1;
            respond(out, "200 OK", null, "{}");
        }
    } else if (std.mem.startsWith(u8, path, "/silent-once/")) {
        respond(out, "200 OK", null, "ok");
    } else if (std.mem.eql(u8, path, "/keep") or std.mem.eql(u8, path, "/keep-close")) {
        out.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nkept") catch {};
        out.flush() catch {};
        return if (std.mem.eql(u8, path, "/keep")) .hold else .close;
    } else if (std.mem.eql(u8, path, "/repos/o/r/installation") or
        std.mem.eql(u8, path, "/orgs/acme/installation"))
    {
        if (!std.mem.startsWith(u8, auth, "Bearer eyJ")) {
            respond(out, "401 Unauthorized", null, "");
        } else {
            const repo = std.mem.startsWith(u8, path, "/repos/");
            respond(out, "200 OK", null, if (repo) "{\"id\":42}" else "{\"id\":43}");
        }
    } else if (std.mem.startsWith(u8, path, "/app/installations/") and
        std.mem.endsWith(u8, path, "/access_tokens"))
    {
        if (!std.mem.startsWith(u8, auth, "Bearer eyJ")) {
            respond(out, "401 Unauthorized", null, "");
        } else {
            const n = s.app_tokens.fetchAdd(1, .acq_rel) + 1;
            var body_buf: [128]u8 = undefined;
            const body = std.fmt.bufPrint(
                &body_buf,
                "{{\"token\":\"ghs_{d}\",\"expires_at\":\"2030-01-01T00:00:00Z\"}}",
                .{n},
            ) catch return .close;
            respond(out, "201 Created", null, body);
        }
    } else if (std.mem.startsWith(u8, path, "/app-token/")) {
        const want = path["/app-token/".len..];
        const ok = std.mem.startsWith(u8, auth, "Bearer ") and std.mem.eql(u8, auth[7..], want);
        if (ok) respond(out, "200 OK", null, "ok") else respond(out, "401 Unauthorized", null, "");
    } else {
        respond(out, "404 Not Found", null, "{\"message\":\"Not Found\"}");
    }
    out.flush() catch {};
    return .close;
}

fn respond(out: *Io.Writer, status: []const u8, location: ?[]const u8, body: []const u8) void {
    out.print("HTTP/1.1 {s}\r\nContent-Length: {d}\r\nConnection: close\r\n", .{
        status,
        body.len,
    }) catch return;
    if (location) |l| out.print("Location: {s}\r\n", .{l}) catch return;
    out.print("\r\n{s}", .{body}) catch return;
}

fn fmtLoc(buf: []u8, host: []const u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "http://{s}:{d}/echo", .{ host, port }) catch unreachable;
}

fn copy(buf: []u8, s: []const u8) []const u8 {
    const n = @min(buf.len, s.len);
    @memcpy(buf[0..n], s[0..n]);
    return buf[0..n];
}
