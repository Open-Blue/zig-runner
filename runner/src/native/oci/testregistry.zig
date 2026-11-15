//! A registry for the pull's tests, on 127.0.0.1 and an ephemeral port: the distribution API's
//! manifests and blobs for one repository, behind token auth as Docker Hub's (a 401 naming a
//! realm, a token for the right Basic credentials), and one blob redirected to another host
//! ("localhost"), which must not see the token. Requests are answered from `routes`.
//!
//!   /token?...                     {"token":"tok"}, given `Basic user:pass` when `private`
//!   /v2/<repo>/manifests/<ref>     the route's, given `Bearer tok` (401 with the challenge without)
//!   /v2/<repo>/blobs/<digest>      the same; a route with `redirect` answers 307 to /cdn/...
//!   /cdn/<digest>                  the blob, on any host; 400 when it comes with an Authorization
//!
//! Every request is counted in `Server.requests`, every connection in `Server.connections`.
//!
//! Each connection is closed once its request is answered. Normally the answer says so
//! (`Connection: close`); with `Server.stale` it does not, so the client keeps the connection for
//! its next request and finds it closed, as a connection Docker Hub closed after a minute idle
//! is found; with `Server.mute`, no request is ever answered.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const layer = @import("layer.zig");

const Allocator = std.mem.Allocator;
const Sha256 = @import("../../sha256.zig").Sha256;

pub const Route = struct {
    path: []const u8,
    body: []const u8,
    content_type: []const u8 = "application/octet-stream",
    /// Served from /cdn/<this> on "localhost" instead.
    redirect: bool = false,
    /// Only this many bytes of the body are sent, whole length declared, and the connection closed.
    cut_at: ?usize = null,
};

pub const Server = struct {
    listener: Io.net.Server = undefined,
    port: u16 = 0,
    thread: std.Thread = undefined,
    routes: []const Route = &.{},
    /// Token auth on the API, with these Basic credentials for the token.
    private: bool = false,
    /// Answers as if the connection were kept, then closes it.
    stale: bool = false,
    /// Closes every connection once its request is read, without answering it.
    mute: bool = false,
    /// How many token requests are answered with a reset, as a socket closed with the request
    /// unread answers one.
    resets: std.atomic.Value(u32) = .init(0),
    /// How many manifest requests are answered `429 Too Many Requests`, `Retry-After: 1`.
    limited: std.atomic.Value(u32) = .init(0),
    /// When not 0, every manifest request is answered with this status (401, 403, 503, ...).
    refuse: std.atomic.Value(u32) = .init(0),
    requests: std.atomic.Value(u32) = .init(0),
    connections: std.atomic.Value(u32) = .init(0),

    pub fn start(s: *Server) !void {
        const io = std.testing.io;
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        s.listener = try addr.listen(io, .{ .reuse_address = true });
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, serve, .{s});
    }

    pub fn stop(s: *Server) void {
        const io = std.testing.io;
        if (Io.net.IpAddress.parse("127.0.0.1", s.port)) |addr| {
            if (addr.connect(io, .{ .mode = .stream })) |conn| {
                var wb: [64]u8 = undefined;
                var w = conn.writer(io, &wb);
                w.interface.writeAll("GET /quit HTTP/1.1\r\nHost: x\r\n\r\n") catch {};
                w.interface.flush() catch {};
                conn.close(io);
            } else |_| {}
        } else |_| {}
        s.thread.join();
        s.listener.deinit(io);
    }

    /// `127.0.0.1:<port>/<repo>:<tag>`.
    pub fn image(s: *const Server, a: Allocator, repo_tag: []const u8) ![]const u8 {
        return std.fmt.allocPrint(a, "127.0.0.1:{d}/{s}", .{ s.port, repo_tag });
    }

    fn serve(s: *Server) void {
        while (true) {
            const conn = s.listener.accept(std.testing.io) catch return;
            _ = s.connections.fetchAdd(1, .acq_rel);
            const quit = answer(s, conn);
            conn.close(std.testing.io);
            if (quit) return;
        }
    }
};

/// One request (the client may keep the connection: each is answered and then it is closed, with
/// `Connection: close`). True for /quit.
fn answer(s: *Server, conn: Io.net.Stream) bool {
    const io = std.testing.io;
    var rb: [8192]u8 = undefined;
    var r = conn.reader(io, &rb);
    const first = r.interface.takeDelimiterInclusive('\n') catch return false;
    var parts = std.mem.tokenizeAny(u8, first, " \r\n");
    _ = parts.next();
    var path_buf: [1024]u8 = undefined;
    const raw_path = parts.next() orelse return false;
    if (raw_path.len > path_buf.len) return false;
    @memcpy(path_buf[0..raw_path.len], raw_path);
    const path = path_buf[0..raw_path.len];
    var auth_buf: [2048]u8 = undefined;
    var auth: []const u8 = "";
    var host_buf: [128]u8 = undefined;
    var host: []const u8 = "";
    while (true) {
        const line = r.interface.takeDelimiterInclusive('\n') catch return false;
        const header = std.mem.trimEnd(u8, line, "\r\n");
        if (header.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, header, ':') orelse continue;
        const value = std.mem.trim(u8, header[colon + 1 ..], " ");
        if (std.ascii.eqlIgnoreCase(header[0..colon], "authorization") and value.len <= auth_buf.len) {
            @memcpy(auth_buf[0..value.len], value);
            auth = auth_buf[0..value.len];
        }
        if (std.ascii.eqlIgnoreCase(header[0..colon], "host") and value.len <= host_buf.len) {
            @memcpy(host_buf[0..value.len], value);
            host = host_buf[0..value.len];
        }
    }
    if (std.mem.eql(u8, path, "/quit")) return true;
    _ = s.requests.fetchAdd(1, .acq_rel);
    if (s.mute) return false;
    if (std.mem.startsWith(u8, path, "/token?") and s.resets.load(.acquire) > 0) {
        _ = s.resets.fetchSub(1, .acq_rel);
        // No lingering: the close sends a reset, not an end of stream.
        const linger: std.os.linux.linger = .{ .onoff = 1, .linger = 0 };
        std.posix.setsockopt(conn.socket.handle, std.os.linux.SOL.SOCKET, std.os.linux.SO.LINGER, std.mem.asBytes(&linger)) catch return false;
        return false;
    }
    var wb: [64 * 1024]u8 = undefined;
    var w = conn.writer(io, &wb);
    const out = &w.interface;
    var hb: [256]u8 = undefined;

    if (std.mem.startsWith(u8, path, "/token?")) {
        if (s.private and !std.mem.eql(u8, auth, "Basic dXNlcjpwYXNz"))
            return respond(s, out, "401 Unauthorized", "", "text/plain", "bad credentials");
        return respond(s, out, "200 OK", "", "application/json", "{\"token\":\"tok\"}");
    }
    if (std.mem.startsWith(u8, path, "/cdn/")) {
        if (auth.len > 0) return respond(s, out, "400 Bad Request", "", "text/plain", "credentials sent to the CDN");
        for (s.routes) |rt| if (rt.redirect and std.mem.endsWith(u8, rt.path, path["/cdn/".len..]))
            return respond(s, out, "200 OK", "", rt.content_type, rt.body);
        return respond(s, out, "404 Not Found", "", "text/plain", "");
    }
    if (std.mem.startsWith(u8, path, "/v2/")) {
        if (s.private and !std.mem.eql(u8, auth, "Bearer tok")) {
            const ch = std.fmt.bufPrint(&hb, "WWW-Authenticate: Bearer realm=\"http://127.0.0.1:{d}/token\",service=\"test\"\r\n", .{s.port}) catch return false;
            return respond(s, out, "401 Unauthorized", ch, "application/json", "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}");
        }
        if (std.mem.indexOf(u8, path, "/manifests/") != null and s.limited.load(.acquire) > 0) {
            _ = s.limited.fetchSub(1, .acq_rel);
            return respond(s, out, "429 Too Many Requests", "Retry-After: 1\r\n", "application/json", "{\"errors\":[{\"code\":\"TOOMANYREQUESTS\"}]}");
        }
        if (std.mem.indexOf(u8, path, "/manifests/") != null and s.refuse.load(.acquire) != 0) {
            var sb: [32]u8 = undefined;
            const line = std.fmt.bufPrint(&sb, "{d} Refused", .{s.refuse.load(.acquire)}) catch return false;
            return respond(s, out, line, "", "application/json", "{\"errors\":[]}");
        }
        for (s.routes) |rt| if (std.mem.eql(u8, rt.path, path)) {
            if (rt.redirect) {
                const digest = path[std.mem.lastIndexOfScalar(u8, path, '/').? + 1 ..];
                const loc = std.fmt.bufPrint(&hb, "Location: http://localhost:{d}/cdn/{s}\r\n", .{ s.port, digest }) catch return false;
                return respond(s, out, "307 Temporary Redirect", loc, "text/plain", "");
            }
            if (rt.cut_at) |n| {
                out.print("HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ rt.content_type, rt.body.len }) catch return false;
                out.writeAll(rt.body[0..n]) catch return false;
                out.flush() catch return false;
                return false;
            }
            return respond(s, out, "200 OK", "", rt.content_type, rt.body);
        };
        return respond(s, out, "404 Not Found", "", "application/json", "{\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\"}]}");
    }
    return respond(s, out, "404 Not Found", "", "text/plain", "");
}

fn respond(s: *const Server, out: *Io.Writer, status: []const u8, extra: []const u8, ct: []const u8, body: []const u8) bool {
    const close: []const u8 = if (s.stale) "" else "Connection: close\r\n";
    out.print("HTTP/1.1 {s}\r\n{s}Content-Type: {s}\r\nContent-Length: {d}\r\n{s}\r\n", .{
        status, extra, ct, body.len, close,
    }) catch return false;
    out.writeAll(body) catch return false;
    out.flush() catch {};
    return false;
}

/// `sha256:<hex>` of `bytes`.
pub fn digestOf(a: Allocator, bytes: []const u8) ![]const u8 {
    var sum: [32]u8 = undefined;
    Sha256.hash(bytes, &sum, .{});
    return std.fmt.allocPrint(a, "sha256:{s}", .{&std.fmt.bytesToHex(sum, .lower)});
}

/// The digest of a layer once decompressed (its diff id).
pub fn diffIdOf(a: Allocator, blob: []const u8) ![]const u8 {
    var in: Io.Reader = .fixed(blob);
    var out: Io.Writer.Allocating = .init(a);
    if (std.mem.startsWith(u8, blob, "\x1f\x8b")) {
        const window = try a.alloc(u8, std.compress.flate.max_window_len);
        var d: std.compress.flate.Decompress = .init(&in, .gzip, window);
        _ = try d.reader.streamRemaining(&out.writer);
    } else if (std.mem.startsWith(u8, blob, "\x28\xb5\x2f\xfd")) {
        const window = try a.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
        var d: std.compress.zstd.Decompress = .init(&in, window, .{});
        _ = try d.reader.streamRemaining(&out.writer);
    } else return digestOf(a, blob);
    return digestOf(a, out.written());
}

/// An image of `layers` (blobs as stored) with `env`, as routes for repository `repo` under tag
/// `tag`: an index (with an attestation, for every platform the pull may ask for) pointing at
/// one manifest. `redirect_first` sends the first layer's blob through the CDN redirect.
pub const TestImage = struct {
    routes: []const Route,
    /// The index's digest (what the tag resolves to) and the manifest's (the image's key).
    index: []const u8,
    manifest: []const u8,
};

pub fn testImage(a: Allocator, repo: []const u8, tag: []const u8, layers: []const []const u8, env: []const u8, redirect_first: bool) !TestImage {
    var routes: std.ArrayList(Route) = .empty;
    var diff_ids: std.ArrayList(u8) = .empty;
    var descs: std.ArrayList(u8) = .empty;
    for (layers, 0..) |l, i| {
        const d = try digestOf(a, l);
        if (i > 0) {
            try diff_ids.append(a, ',');
            try descs.append(a, ',');
        }
        try diff_ids.print(a, "\"{s}\"", .{try diffIdOf(a, l)});
        try descs.print(a, "{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{s}\",\"size\":{d}}}", .{ d, l.len });
        try routes.append(a, .{ .path = try std.fmt.allocPrint(a, "/v2/{s}/blobs/{s}", .{ repo, d }), .body = l, .redirect = redirect_first and i == 0 });
    }
    const config = try std.fmt.allocPrint(a, "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"config\":{{\"Env\":[{s}],\"User\":\"\"}},\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[{s}]}}}}", .{ env, diff_ids.items });
    const config_digest = try digestOf(a, config);
    try routes.append(a, .{ .path = try std.fmt.allocPrint(a, "/v2/{s}/blobs/{s}", .{ repo, config_digest }), .body = config });
    const manifest = try std.fmt.allocPrint(a, "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{s}]}}", .{ config_digest, config.len, descs.items });
    const manifest_digest = try digestOf(a, manifest);
    const mt = "application/vnd.oci.image.manifest.v1+json";
    try routes.append(a, .{ .path = try std.fmt.allocPrint(a, "/v2/{s}/manifests/{s}", .{ repo, manifest_digest }), .body = manifest, .content_type = mt });
    var entries: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "\"amd64\"", "\"arm64\",\"variant\":\"v8\"" }) |arch| {
        try entries.print(a, "{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"platform\":{{\"architecture\":{s},\"os\":\"linux\"}}}},", .{ mt, manifest_digest, manifest.len, arch });
    }
    try entries.print(a, "{{\"mediaType\":\"{s}\",\"digest\":\"sha256:{s}\",\"size\":1,\"platform\":{{\"architecture\":\"unknown\",\"os\":\"unknown\"}}}}", .{ mt, layer.repeat('0', 64) });
    const index = try std.fmt.allocPrint(a, "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{s}]}}", .{entries.items});
    const index_digest = try digestOf(a, index);
    const it = "application/vnd.oci.image.index.v1+json";
    try routes.append(a, .{ .path = try std.fmt.allocPrint(a, "/v2/{s}/manifests/{s}", .{ repo, tag }), .body = index, .content_type = it });
    try routes.append(a, .{ .path = try std.fmt.allocPrint(a, "/v2/{s}/manifests/{s}", .{ repo, index_digest }), .body = index, .content_type = it });
    return .{ .routes = routes.items, .index = index_digest, .manifest = manifest_digest };
}

// --- the pull's tests ---

const image = @import("image.zig");
const registry_api = @import("registry.zig");
const Store = @import("Store.zig");
const testing = std.testing;

test "native oci pull: token auth with credentials, an index, gzip and zstd layers, a CDN redirect without the token, and the store's copy after" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;

    var t: layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "etc/", .kind = .directory, .mode = 0o755 });
    try t.add(.{ .path = "etc/marker", .body = "from the image\n" });
    try t.add(.{ .path = "etc/gone", .body = "x" });
    try t.add(.{ .path = "zstd.txt", .body = "replaced by the zstd layer" });
    const base = try t.finish();
    var t2: layer.TestTar = .{ .a = arena };
    try t2.add(.{ .path = "etc/.wh.gone" });
    const wh = try t2.finish();
    const img = try testImage(arena, "test/img", "1", &.{ base, &layer.test_gzip, &layer.test_zstd, wh }, "\"PATH=/usr/bin:/bin\",\"FROM_IMAGE=yes\"", true);

    var server: Server = .{ .routes = img.routes, .private = true };
    try server.start();
    defer server.stop();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };

    // Without credentials: refused, saying why.
    var why: []const u8 = "";
    try testing.expectError(error.Unauthorized, image.pull(arena, testing.allocator, io, store, .{ .image = try server.image(arena, "test/img:1"), .owners = false }, &why));
    try testing.expect(std.mem.indexOf(u8, why, "credentials") != null);

    why = "";
    const got = image.pull(arena, testing.allocator, io, store, .{
        .image = try server.image(arena, "test/img:1"),
        .creds = .{ .username = "user", .password = "pass" },
        .owners = false,
    }, &why) catch |e| {
        std.debug.print("pull: {s}\n", .{why});
        return e;
    };
    try testing.expectEqualStrings(img.index, got.digest);
    try testing.expectEqualStrings(img.manifest, got.manifest);
    try testing.expect(got.pulled != null);
    try testing.expectEqual(@as(usize, 4), got.pulled.?.layers);
    // Held for whoever pulled it: an eviction's exclusive lock cannot be had until it lets go.
    const held_path = try std.fmt.allocPrint(arena, "{s}.lock", .{std.fs.path.dirname(got.rootfs).?});
    const probe = try std.Io.Dir.cwd().openFile(io, held_path, .{});
    defer probe.close(io);
    try testing.expect(linux.errno(linux.flock(probe.handle, 2 | 4)) != .SUCCESS);
    got.lock.close(io);
    try testing.expect(linux.errno(linux.flock(probe.handle, 2 | 4)) == .SUCCESS);
    _ = linux.flock(probe.handle, 8);
    try testing.expectEqualStrings("FROM_IMAGE=yes", got.env[1]);
    var root = try std.Io.Dir.cwd().openDir(io, got.rootfs, .{});
    defer root.close(io);
    try testing.expectEqualStrings("from the image\n", try root.readFileAlloc(io, "etc/marker", arena, .limited(100)));
    try testing.expectEqualStrings("gzip\n", try root.readFileAlloc(io, "gzip.txt", arena, .limited(100)));
    try testing.expectEqualStrings("zstd\n", try root.readFileAlloc(io, "zstd.txt", arena, .limited(100)));
    try testing.expectError(error.FileNotFound, root.access(io, "etc/gone", .{}));

    // By tag again: the manifest is asked for (a tag moves), the blobs and rootfs are not.
    const before = server.requests.load(.acquire);
    const again = try image.pull(arena, testing.allocator, io, store, .{
        .image = try server.image(arena, "test/img:1"),
        .creds = .{ .username = "user", .password = "pass" },
        .owners = false,
    }, &why);
    try testing.expect(again.pulled == null);
    try testing.expectEqualStrings(got.rootfs, again.rootfs);
    try testing.expect(server.requests.load(.acquire) - before <= 4);
    // Pinned by the index's digest, once seen: no request at all.
    const pinned = try std.fmt.allocPrint(arena, "{s}@{s}", .{ try server.image(arena, "test/img:1"), img.index });
    _ = try image.pull(arena, testing.allocator, io, store, .{ .image = pinned, .creds = .{ .username = "user", .password = "pass" }, .owners = false }, &why);
    const seen = server.requests.load(.acquire);
    const cached = try image.pull(arena, testing.allocator, io, store, .{ .image = pinned, .owners = false }, &why);
    try testing.expectEqual(seen, server.requests.load(.acquire));
    try testing.expectEqualStrings(got.rootfs, cached.rootfs);
}

/// An image with one layer at `repo:tag`, on a server whose routes are `routes` (a second image
/// served under the same tag later: a tag that moved).
fn tinyImage(arena: Allocator, repo: []const u8, tag: []const u8, marker: []const u8) !TestImage {
    var t: layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "marker", .body = marker });
    return testImage(arena, repo, tag, &.{try t.finish()}, "\"A=1\"", false);
}

fn pullTag(arena: Allocator, store: Store, ref: []const u8, ttl: u32, why: *[]const u8) !image.Image {
    const img = try image.pull(arena, testing.allocator, testing.io, store, .{ .image = ref, .owners = false, .tag_ttl_s = ttl }, why);
    img.lock.close(testing.io);
    return img;
}

test "native oci pull: a tag resolved within the TTL costs no request, one past it asks and sees a moved tag" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(testing.io, ".", arena) };
    const one = try tinyImage(arena, "test/img", "t", "one");
    const two = try tinyImage(arena, "test/img", "t", "two");
    var server: Server = .{ .routes = one.routes };
    try server.start();
    defer server.stop();
    const ref = try server.image(arena, "test/img:t");
    var why: []const u8 = "";

    const first = try pullTag(arena, store, ref, 300, &why);
    try testing.expect(first.pulled != null);
    // Five more jobs within the TTL: the registry is not asked.
    const seen = server.requests.load(.acquire);
    for (0..5) |_| {
        const again = try pullTag(arena, store, ref, 300, &why);
        try testing.expectEqualStrings(one.index, again.digest);
        try testing.expectEqualStrings(first.rootfs, again.rootfs);
    }
    try testing.expectEqual(seen, server.requests.load(.acquire));
    // The tag moves; within the TTL it is not seen, past it (here: TTL 0) it is.
    server.routes = two.routes;
    try testing.expectEqualStrings(one.index, (try pullTag(arena, store, ref, 300, &why)).digest);
    const moved = try pullTag(arena, store, ref, 0, &why);
    try testing.expectEqualStrings(two.index, moved.digest);
    try testing.expect(moved.pulled != null);
    // And the new resolution is what is reused after.
    const after = server.requests.load(.acquire);
    try testing.expectEqualStrings(two.index, (try pullTag(arena, store, ref, 300, &why)).digest);
    try testing.expectEqual(after, server.requests.load(.acquire));
}

test "native oci pull: a registry that answers 429 gives the last known digest; a first pull waits out Retry-After" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(testing.io, ".", arena) };
    const one = try tinyImage(arena, "test/img", "t", "one");
    var server: Server = .{ .routes = one.routes };
    try server.start();
    defer server.stop();
    const ref = try server.image(arena, "test/img:t");
    var why: []const u8 = "";

    // Nothing known yet: the 429 is waited out (Retry-After: 1) and the pull goes through.
    server.limited.store(1, .release);
    const started = std.Io.Clock.awake.now(testing.io).toMilliseconds();
    const first = try pullTag(arena, store, ref, 0, &why);
    try testing.expect(std.Io.Clock.awake.now(testing.io).toMilliseconds() - started >= 900);
    try testing.expect(first.reused == null);

    // Known now: a 429 is not waited for, the last known digest serves, saying so.
    server.limited.store(100, .release);
    const t0 = std.Io.Clock.awake.now(testing.io).toMilliseconds();
    const stale = try pullTag(arena, store, ref, 0, &why);
    try testing.expect(std.Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 900);
    try testing.expectEqualStrings(one.index, stale.digest);
    try testing.expectEqualStrings(first.rootfs, stale.rootfs);
    try testing.expect(stale.reused != null);
    try testing.expect(std.mem.indexOf(u8, stale.reused.?, one.index) != null);

    // A tag the registry no longer has is an error, not the old digest.
    server.limited.store(0, .release);
    server.routes = &.{};
    try testing.expectError(error.NotFound, pullTag(arena, store, ref, 0, &why));
}

/// The one tag record in the store's refs, rewritten to `text` (null: its path only).
fn tagRecord(arena: Allocator, store: Store, text: ?[]const u8) ![]const u8 {
    var d = try std.Io.Dir.cwd().openDir(testing.io, try std.fmt.allocPrint(arena, "{s}/oci/refs", .{store.root}), .{ .iterate = true });
    defer d.close(testing.io);
    var it = d.iterate();
    while (try it.next(testing.io)) |e| if (std.mem.startsWith(u8, e.name, "tag-")) {
        const path = try std.fmt.allocPrint(arena, "{s}/oci/refs/{s}", .{ store.root, e.name });
        if (text) |t| try d.writeFile(testing.io, .{ .sub_path = e.name, .data = t });
        return path;
    };
    return error.NoTagRecord;
}

test "native oci pull: a tag's record belongs to the credentials that resolved it" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(testing.io, ".", arena) };
    const one = try tinyImage(arena, "test/img", "t", "one");
    var server: Server = .{ .routes = one.routes, .private = true };
    try server.start();
    defer server.stop();
    const ref = try server.image(arena, "test/img:t");
    const good: registry_api.Credentials = .{ .username = "user", .password = "pass" };
    var why: []const u8 = "";
    const mine = try image.pull(arena, testing.allocator, testing.io, store, .{ .image = ref, .creds = good, .owners = false, .tag_ttl_s = 300 }, &why);
    mine.lock.close(testing.io);
    // Within the TTL, the same login is served without a request...
    const seen = server.requests.load(.acquire);
    (try image.pull(arena, testing.allocator, testing.io, store, .{ .image = ref, .creds = good, .owners = false, .tag_ttl_s = 300 }, &why)).lock.close(testing.io);
    try testing.expectEqual(seen, server.requests.load(.acquire));
    // ... no login, or another, asks the registry and is refused, on a TTL's reuse and as a fallback.
    for ([_]?registry_api.Credentials{ null, .{ .username = "user", .password = "other" }, .{ .username = "other", .password = "pass" } }) |cr| {
        try testing.expectError(error.Unauthorized, image.pull(arena, testing.allocator, testing.io, store, .{ .image = ref, .creds = cr, .owners = false, .tag_ttl_s = 300 }, &why));
        try testing.expect(server.requests.load(.acquire) > seen);
    }
}

test "native oci pull: tag records are named by a keyed hash: each store's own, 0600, and made again when lost" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = testing.io;
    var tmp1 = testing.tmpDir(.{});
    defer tmp1.cleanup();
    var tmp2 = testing.tmpDir(.{});
    defer tmp2.cleanup();
    const s1: Store = .{ .root = try tmp1.dir.realPathFileAlloc(io, ".", arena) };
    const s2: Store = .{ .root = try tmp2.dir.realPathFileAlloc(io, ".", arena) };
    try s1.prepare(arena, io);
    try s2.prepare(arena, io);
    const ref = try registry_api.parseRef(arena, "example.com/test/img:t");
    const cr: registry_api.Credentials = .{ .username = "user", .password = "pass" };
    const p1 = (try image.tagPath(arena, io, s1, ref, cr, .{ .architecture = "amd64" })).?;
    const p2 = (try image.tagPath(arena, io, s2, ref, cr, .{ .architecture = "amd64" })).?;
    try testing.expect(!std.mem.eql(u8, std.fs.path.basename(p1), std.fs.path.basename(p2)));
    // Stable in one store, and the password is not in the name, nor is the secret's file open.
    try testing.expectEqualStrings(p1, (try image.tagPath(arena, io, s1, ref, cr, .{ .architecture = "amd64" })).?);
    const other = (try image.tagPath(arena, io, s1, ref, .{ .username = "user", .password = "pass2" }, .{ .architecture = "amd64" })).?;
    try testing.expect(!std.mem.eql(u8, p1, other));
    var st: linux.Statx = undefined;
    const key = try arena.dupeSentinel(u8, try std.fmt.allocPrint(arena, "{s}/oci/refs.key", .{s1.root}), 0);
    try testing.expect(linux.errno(linux.statx(linux.AT.FDCWD, key, 0, .{ .MODE = true, .SIZE = true }, &st)) == .SUCCESS);
    try testing.expectEqual(@as(u32, 0o600), st.mode & 0o7777);
    try testing.expectEqual(@as(u64, 32), st.size);

    // A lost or damaged secret: a new one, so the old records are not found and the registry is asked.
    const one = try tinyImage(arena, "test/img", "t", "one");
    var server: Server = .{ .routes = one.routes };
    try server.start();
    defer server.stop();
    const sref = try server.image(arena, "test/img:t");
    var why: []const u8 = "";
    _ = try pullTag(arena, s1, sref, 300, &why);
    const seen = server.requests.load(.acquire);
    _ = try pullTag(arena, s1, sref, 300, &why);
    try testing.expectEqual(seen, server.requests.load(.acquire));
    for ([_]?[]const u8{ null, "short" }) |damage| {
        if (damage) |d| try tmp1.dir.writeFile(io, .{ .sub_path = "oci/refs.key", .data = d }) else try tmp1.dir.deleteFile(io, "oci/refs.key");
        const before = server.requests.load(.acquire);
        _ = try pullTag(arena, s1, sref, 300, &why);
        try testing.expect(server.requests.load(.acquire) > before);
        const again = server.requests.load(.acquire);
        _ = try pullTag(arena, s1, sref, 300, &why);
        try testing.expectEqual(again, server.requests.load(.acquire));
    }
}

test "native oci pull: with a record, a 401, a 403 and a 404 are errors; a 503, 429 and no answer fall back; an evicted image does not; a bad record is not trusted" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(testing.io, ".", arena) };
    const one = try tinyImage(arena, "test/img", "t", "one");
    const two = try tinyImage(arena, "test/img", "t", "two");
    var server: Server = .{ .routes = one.routes };
    try server.start();
    defer server.stop();
    const ref = try server.image(arena, "test/img:t");
    var why: []const u8 = "";
    const first = try pullTag(arena, store, ref, 300, &why);

    for ([_]u32{ 401, 403 }) |status| {
        server.refuse.store(status, .release);
        try testing.expectError(error.HttpStatus, pullTag(arena, store, ref, 0, &why));
    }
    server.refuse.store(503, .release);
    const down = try pullTag(arena, store, ref, 0, &why);
    try testing.expectEqualStrings(one.index, down.digest);
    try testing.expect(down.reused != null);
    server.refuse.store(0, .release);

    // No answer at all.
    server.mute = true;
    const mute = try pullTag(arena, store, ref, 0, &why);
    try testing.expectEqualStrings(first.rootfs, mute.rootfs);
    try testing.expect(mute.reused != null);
    server.mute = false;

    // Records that are not to be trusted: the registry is asked, and the moved tag seen.
    server.routes = two.routes;
    const path = try tagRecord(arena, store, null);
    const bad = [_][]const u8{
        "garbage",
        "",
        try std.fmt.allocPrint(arena, "{s} {s} 9999999999999\n", .{ one.manifest, one.index }),
        try std.fmt.allocPrint(arena, "{s} {s} -5\n", .{ one.manifest, one.index }),
        try std.fmt.allocPrint(arena, "{s} sha256:zz 1\n", .{one.manifest}),
    };
    for (bad) |text| {
        _ = try tagRecord(arena, store, text);
        const got = try pullTag(arena, store, ref, 300, &why);
        try testing.expectEqualStrings(two.index, got.digest);
        // Back to the first image's record for the next.
        server.routes = one.routes;
        _ = try pullTag(arena, store, ref, 0, &why);
        server.routes = two.routes;
    }
    _ = path;

    // The record's image evicted: a 429 is waited out, not given a digest the store lacks.
    server.routes = one.routes;
    _ = try pullTag(arena, store, ref, 0, &why);
    const key = one.manifest["sha256:".len..];
    const dir = try std.fmt.allocPrint(arena, "{s}/oci/images/{s}.rootless", .{ store.root, key });
    Store.removeTree(testing.io, dir);
    server.limited.store(1, .release);
    const t0 = std.Io.Clock.awake.now(testing.io).toMilliseconds();
    const again = try pullTag(arena, store, ref, 0, &why);
    try testing.expect(std.Io.Clock.awake.now(testing.io).toMilliseconds() - t0 >= 900);
    try testing.expect(again.reused == null and again.pulled != null);
}

test "native oci pull: a blob that does not match its digest is refused and not kept" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var t: layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "f", .body = "good" });
    const img = try testImage(arena, "test/bad", "1", &.{try t.finish()}, "", false);
    // The layer's route serves other bytes of the same length.
    const routes = try arena.dupe(Route, img.routes);
    var t2: layer.TestTar = .{ .a = arena };
    try t2.add(.{ .path = "f", .body = "evil" });
    routes[0].body = try t2.finish();
    var server: Server = .{ .routes = routes };
    try server.start();
    defer server.stop();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    var why: []const u8 = "";
    try testing.expectError(error.DigestMismatch, image.pull(arena, testing.allocator, io, store, .{ .image = try server.image(arena, "test/bad:1"), .owners = false }, &why));
    try testing.expect(std.mem.indexOf(u8, why, "hashing to") != null);
    var blobs = try tmp.dir.openDir(io, "oci/blobs/sha256", .{ .iterate = true });
    defer blobs.close(io);
    var it = blobs.iterate();
    try testing.expect(try it.next(io) == null);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, try std.fmt.allocPrint(arena, "oci/images/{s}.rootless", .{img.manifest["sha256:".len..]}), .{}));
}

test "native oci blob: a declared size of 0 allows no body, and a download cut off halfway writes nothing more to the file" {
    const registry = @import("registry.zig");
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const big = try arena.alloc(u8, 200_000);
    @memset(big, 'b');
    const small = "not empty";
    const big_digest = try digestOf(arena, big);
    const small_digest = try digestOf(arena, small);
    const routes = [_]Route{
        .{ .path = try std.fmt.allocPrint(arena, "/v2/test/b/blobs/{s}", .{big_digest}), .body = big, .cut_at = 100_000 },
        .{ .path = try std.fmt.allocPrint(arena, "/v2/test/b/blobs/{s}", .{small_digest}), .body = small },
    };
    var server: Server = .{ .routes = &routes };
    try server.start();
    defer server.stop();
    var c: registry.Client = .{ .arena = arena, .io = io, .ref = try registry.parseRef(arena, try server.image(arena, "test/b:1")), .creds = null };

    // A blob that says it is 0 bytes and has a body: refused, and nothing written.
    const zero = try tmp.dir.createFile(io, "zero", .{});
    defer zero.close(io);
    if (c.blob(small_digest, 0, zero)) |_| return error.TestExpectedError else |e| {
        try testing.expect(e == error.BodyTooLarge or e == error.ResponseTooLarge);
    }
    try testing.expectEqual(@as(u64, 0), (try zero.stat(io)).size);

    // A download that ends halfway, in the 1 MiB the file body keeps waiting: none of it is written
    // after the error (the file holds only what was written before, here nothing).
    const cut = try tmp.dir.createFile(io, "cut", .{});
    defer cut.close(io);
    if (c.blob(big_digest, big.len, cut)) |_| return error.TestExpectedError else |_| {}
    try testing.expectEqual(@as(u64, 0), (try cut.stat(io)).size);
}

test "native oci pull: a kept-alive connection the registry closed is replaced; a registry that never answers fails, after a bounded number of tries" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var t: layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "f", .body = "kept" });
    const img = try testImage(arena, "test/stale", "1", &.{ try t.finish(), &layer.test_gzip }, "", true);
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    const creds: @import("registry.zig").Credentials = .{ .username = "user", .password = "pass" };

    // Every answer looks kept alive and its connection is then closed: each request after the
    // first (the token's, on the registry's host here, the manifests', the blobs', the CDN's)
    // finds its kept connection closed, as Docker Hub's are after a minute idle, and goes on
    // another.
    var server: Server = .{ .routes = img.routes, .private = true, .stale = true };
    try server.start();
    defer server.stop();
    var why: []const u8 = "";
    const got = image.pull(arena, testing.allocator, io, store, .{
        .image = try server.image(arena, "test/stale:1"),
        .creds = creds,
        .owners = false,
    }, &why) catch |e| {
        std.debug.print("pull: {s}; the server read {d} requests on {d} connections\n", .{
            why, server.requests.load(.acquire), server.connections.load(.acquire),
        });
        return e;
    };
    try testing.expectEqualStrings(img.manifest, got.manifest);
    try testing.expect(server.requests.load(.acquire) >= 6);

    // A registry that closes every connection unanswered is no stale connection: the pull fails
    // with the error, after the one repeat the library makes of a GET that met a closed connection.
    var mute: Server = .{ .routes = img.routes, .mute = true };
    try mute.start();
    defer mute.stop();
    why = "";
    try testing.expectError(error.NetworkIo, image.pull(arena, testing.allocator, io, store, .{
        .image = try mute.image(arena, "test/stale:2"),
        .owners = false,
    }, &why));
    try testing.expect(std.mem.indexOf(u8, why, "could not fetch its manifest: NetworkIo") != null);
    try testing.expectEqual(@as(u32, 2), mute.requests.load(.acquire));
}

test "native oci pull: a token request reset is sent again, a bounded number of times" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var t: layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "f", .body = "kept" });
    const img = try testImage(arena, "test/reset", "1", &.{try t.finish()}, "", false);
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    const creds: @import("registry.zig").Credentials = .{ .username = "user", .password = "pass" };

    var server: Server = .{ .routes = img.routes, .private = true, .resets = .init(1) };
    try server.start();
    defer server.stop();
    var why: []const u8 = "";
    const got = image.pull(arena, testing.allocator, io, store, .{
        .image = try server.image(arena, "test/reset:1"),
        .creds = creds,
        .owners = false,
    }, &why) catch |e| {
        std.debug.print("pull: {s}\n", .{why});
        return e;
    };
    try testing.expectEqualStrings(img.manifest, got.manifest);
    try testing.expectEqual(@as(u32, 0), server.resets.load(.acquire));

    // Reset every time: the error stands, after the one repeat the library makes.
    var always: Server = .{ .routes = img.routes, .private = true, .resets = .init(7) };
    try always.start();
    defer always.stop();
    why = "";
    try testing.expectError(error.Unauthorized, image.pull(arena, testing.allocator, io, store, .{
        .image = try always.image(arena, "test/reset:2"),
        .creds = creds,
        .owners = false,
    }, &why));
    try testing.expect(std.mem.indexOf(u8, why, "the token service: NetworkIo") != null);
    try testing.expectEqual(@as(u32, 5), always.resets.load(.acquire));
}

test "native oci pull of the default image from Docker Hub (ZIG_RUNNER_TEST_PULL=1; measures a cold pull)" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const env = try testing.environ.createMap(arena);
    if (!std.mem.eql(u8, env.get("ZIG_RUNNER_TEST_PULL") orelse "", "1")) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    const dagger = @import("../../dagger.zig");
    var why: []const u8 = "";
    const t0 = std.Io.Clock.awake.now(io).toMilliseconds();
    const got = image.pull(arena, testing.allocator, io, store, .{
        .image = env.get("ZIG_RUNNER_TEST_PULL_IMAGE") orelse dagger.default_image,
        .owners = std.os.linux.geteuid() == 0,
    }, &why) catch |e| {
        std.debug.print("pull: {s}\n", .{why});
        return e;
    };
    const ms = std.Io.Clock.awake.now(io).toMilliseconds() - t0;
    std.debug.print("\ncold pull: {d} ms whole, {d} ms in the pull's own clock, {d} layers, {d} bytes, " ++
        "{d} devices skipped; {s} -> {s}\n", .{ ms, got.pulled.?.ms, got.pulled.?.layers, got.pulled.?.bytes, got.pulled.?.devices, got.digest, got.manifest });
    var root = try std.Io.Dir.cwd().openDir(io, got.rootfs, .{});
    defer root.close(io);
    const osr = try root.readFileAlloc(io, "usr/lib/os-release", arena, .limited(4096));
    try testing.expect(std.mem.indexOf(u8, osr, "Ubuntu") != null);
    const t1 = std.Io.Clock.awake.now(io).toMilliseconds();
    const warm = try image.pull(arena, testing.allocator, io, store, .{ .image = dagger.default_image, .owners = std.os.linux.geteuid() == 0 }, &why);
    std.debug.print("warm (pinned, in the store): {d} ms\n", .{std.Io.Clock.awake.now(io).toMilliseconds() - t1});
    try testing.expect(warm.pulled == null);
    // A pull by tag, so it asks the registry, after the client's kept connections have sat idle
    // past Docker Hub's minute: they are closed, and the pull goes on new ones (razorbill failed
    // here with HttpConnectionClosing). The same client, as the runner's is the process's.
    try io.sleep(.fromSeconds(70), .awake);
    const idle = image.pull(arena, testing.allocator, io, store, .{
        .image = "alpine:3.22",
        .owners = std.os.linux.geteuid() == 0,
    }, &why) catch |e| {
        std.debug.print("pull after a minute idle: {s}\n", .{why});
        return e;
    };
    std.debug.print("after 70 s idle: {s}\n", .{idle.digest});
}

test "bench: a cold image pull (ZIG_RUNNER_BENCH_PULL=<image>; ZIG_RUNNER_BENCH_POLICY=new|fixed; ZIG_RUNNER_BENCH_BUSY=<other jobs running>)" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const env = try testing.environ.createMap(arena);
    const image_name = env.get("ZIG_RUNNER_BENCH_PULL") orelse return error.SkipZigTest;
    const admission = @import("../../admission.zig");
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    // The pool's gate, with `busy` of its other runners shown as running a job: the policy's input.
    var slots: [64]admission.Admission.Slot = undefined;
    for (&slots) |*s| s.* = .{};
    var pool: admission.Admission = .init(io, .{}, &slots);
    const busy = std.fmt.parseInt(usize, env.get("ZIG_RUNNER_BENCH_BUSY") orelse "0", 10) catch 0;
    for (slots[1..][0..busy]) |*s| s.started_ms = 1;
    var gate: admission.Gate = .{ .pool = &pool, .slot = 0 };
    const new_policy = std.mem.eql(u8, env.get("ZIG_RUNNER_BENCH_POLICY") orelse "new", "new");
    var why: []const u8 = "";
    {
        // What the policy chooses for these layers now, as `Prefetch.start` asks it.
        var w: []const u8 = "";
        std.debug.print("bench pull: the policy would fetch {d} of 11 layers at a time ({s})\n", .{ gate.fetchConcurrency(11, @import("../../zr_net.zig").cores(), 8, &w), w });
    }
    var ru0: std.os.linux.rusage = undefined;
    _ = std.os.linux.getrusage(0, &ru0);
    const t0 = std.Io.Clock.awake.now(io).toMilliseconds();
    const got = image.pull(arena, testing.allocator, io, store, .{
        .image = image_name,
        .owners = false,
        .gate = if (new_policy) &gate else null,
    }, &why) catch |e| {
        std.debug.print("pull: {s}\n", .{why});
        return e;
    };
    const ms = std.Io.Clock.awake.now(io).toMilliseconds() - t0;
    var ru: std.os.linux.rusage = undefined;
    _ = std.os.linux.getrusage(0, &ru);
    const cpu_ms = (ru.utime.sec - ru0.utime.sec) * 1000 + @divTrunc(ru.utime.usec - ru0.utime.usec, 1000) +
        (ru.stime.sec - ru0.stime.sec) * 1000 + @divTrunc(ru.stime.usec - ru0.stime.usec, 1000);
    std.debug.print("\nbench pull: {s} policy {s} busy {d}: {d} ms, cpu {d} ms, peak RSS {d} kB, {d} layers, {d} bytes\n", .{
        image_name, if (new_policy) "new" else "fixed", busy, ms, cpu_ms, ru.maxrss, got.pulled.?.layers, got.pulled.?.bytes,
    });
}

test "allocation failures: a pull through token auth, an index, gzip and zstd layers and a redirect" {
    const af = @import("../../alloc_failures.zig");
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;

    var t: layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "etc/", .kind = .directory, .mode = 0o755 });
    try t.add(.{ .path = "etc/marker", .body = "from the image\n" });
    const base = try t.finish();
    const img = try testImage(arena, "test/img", "1", &.{base}, "\"A=b\"", true);
    var server: Server = .{ .routes = img.routes, .private = true };
    try server.start();
    defer server.stop();
    const reference = try server.image(arena, "test/img:1");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);

    // The registry client's, the manifests' and the store's memory fail one allocation at a time,
    // in `arena` (`checkOne`: every run must end in `error.OutOfMemory`). The memory the layers'
    // fetching tasks use (`gpa`) is failed in a second pass, `FailOnce`: those tasks run beside the
    // pull's own thread, so which allocation is number N varies between runs, and a failure may
    // land where it is survived on purpose (a message that cannot be copied is left empty). That
    // pass can only require that a run ends in `error.OutOfMemory` or in a pull, with nothing
    // leaked, and no other error.
    const S = struct {
        var run_count: usize = 0;
        fn pull(a_: Allocator, root_: []const u8, reference_: []const u8, creds: ?@import("registry.zig").Credentials) !void {
            return pullWith(a_, testing.allocator, root_, reference_, creds);
        }
        fn pullWith(a_: Allocator, gpa_: Allocator, root_: []const u8, reference_: []const u8, creds: ?@import("registry.zig").Credentials) !void {
            var scratch: af.Scratch = .init(a_);
            defer scratch.deinit();
            const arena_ = scratch.allocator();
            run_count += 1;
            // Each run its own store: a layer already in it would not be fetched.
            const store: Store = .{ .root = try std.fmt.allocPrint(arena_, "{s}/store{d}", .{ root_, run_count }) };
            var why: []const u8 = "";
            const got = try image.pull(arena_, gpa_, testing.io, store, .{
                .image = reference_,
                .creds = creds,
                .owners = false,
            }, &why);
            got.lock.close(testing.io);
            try testing.expectEqual(@as(usize, 1), got.env.len);
        }
    };
    const creds: ?@import("registry.zig").Credentials = .{ .username = "user", .password = "pass" };
    try af.checkOne(S.pull, .{ root, reference, creds });

    // A pinned reference seen before: its ref file is read (`image.pull`'s first lookup), and the
    // image comes from the store without a request. Unseen is not a failure to read it: out of
    // memory there must come back as itself, not as "not seen" and a pull over the network.
    const known_root = try std.fmt.allocPrint(arena, "{s}/known", .{root});
    const pinned = try server.image(arena, try std.fmt.allocPrint(arena, "test/img@{s}", .{img.index}));
    {
        var why: []const u8 = "";
        const first = try image.pull(arena, testing.allocator, io, .{ .root = known_root }, .{
            .image = pinned,
            .creds = creds,
            .owners = false,
        }, &why);
        first.lock.close(io);
    }
    const K = struct {
        fn again(a_: Allocator, root_: []const u8, reference_: []const u8, creds_: ?@import("registry.zig").Credentials) !void {
            var scratch: af.Scratch = .init(a_);
            defer scratch.deinit();
            var why: []const u8 = "";
            const got = try image.pull(scratch.allocator(), testing.allocator, testing.io, .{ .root = root_ }, .{
                .image = reference_,
                .creds = creds_,
                .owners = false,
            }, &why);
            got.lock.close(testing.io);
            try testing.expectEqual(@as(usize, 1), got.env.len);
            // From the store: no layer was fetched again.
            try testing.expect(got.pulled == null);
        }
    };
    try af.checkOne(K.again, .{ known_root, pinned, creds });

    var clean: af.FailOnce = .{ .child = std.heap.smp_allocator };
    try S.pullWith(testing.allocator, clean.allocator(), root, reference, creds);
    try clean.checkFreed();
    const n = clean.count.load(.monotonic);
    try testing.expect(n > 0);
    const step: usize = if (std.valgrind.runningOnValgrind() != 0) 13 else 1;
    var i: usize = 0;
    while (i < n) : (i += step) {
        var once: af.FailOnce = .{ .child = std.heap.smp_allocator, .fail_at = i };
        S.pullWith(testing.allocator, once.allocator(), root, reference, creds) catch |e| if (e != error.OutOfMemory) {
            std.debug.print("allocation failures: layer tasks' allocation {d} of {d} failing, the pull ended in {s}\n", .{ i, n, @errorName(e) });
            return e;
        };
        once.checkFreed() catch |e| {
            std.debug.print("allocation failures: layer tasks' allocation {d} of {d} failing leaked\n", .{ i, n });
            return e;
        };
    }
}

test "allocation failures: a registry's refusal keeps its status, and running out of memory is not hidden by it" {
    const af = @import("../../alloc_failures.zig");
    var server: Server = .{};
    try server.start();
    defer server.stop();
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", a.allocator());
    const reference = try server.image(a.allocator(), "test/img:missing");

    const S = struct {
        /// A manifest the registry answers 404 with a body: out of memory while keeping the body
        /// for the message must be `error.OutOfMemory`, not the 404 with the body left out.
        fn missing(a_: Allocator, root_: []const u8, reference_: []const u8) !void {
            var scratch: af.Scratch = .init(a_);
            defer scratch.deinit();
            var why: []const u8 = "";
            const got = image.pull(scratch.allocator(), testing.allocator, testing.io, .{ .root = root_ }, .{
                .image = reference_,
                .owners = false,
            }, &why);
            if (got) |g| {
                g.lock.close(testing.io);
                return error.TestUnexpectedResult;
            } else |e| {
                if (e == error.OutOfMemory) return e;
                try testing.expectEqual(error.NotFound, e);
                try testing.expect(std.mem.indexOf(u8, why, "HTTP 404") != null);
                try testing.expect(std.mem.indexOf(u8, why, "MANIFEST_UNKNOWN") != null);
            }
        }
    };
    // A store in use has its secret (`image.tagPath` makes it once): the run that makes it
    // allocates otherwise than the ones that read it.
    const primed: Store = .{ .root = root };
    try primed.prepare(a.allocator(), testing.io);
    _ = try image.tagPath(a.allocator(), testing.io, primed, try registry_api.parseRef(a.allocator(), reference), null, .{ .architecture = "amd64" });
    try af.checkOne(S.missing, .{ root, reference });
}
