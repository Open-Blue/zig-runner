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
const Io = std.Io;
const layer = @import("layer.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Route = struct {
    path: []const u8,
    body: []const u8,
    content_type: []const u8 = "application/octet-stream",
    /// Served from /cdn/<this> on "localhost" instead.
    redirect: bool = false,
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
        for (s.routes) |rt| if (std.mem.eql(u8, rt.path, path)) {
            if (rt.redirect) {
                const digest = path[std.mem.lastIndexOfScalar(u8, path, '/').? + 1 ..];
                const loc = std.fmt.bufPrint(&hb, "Location: http://localhost:{d}/cdn/{s}\r\n", .{ s.port, digest }) catch return false;
                return respond(s, out, "307 Temporary Redirect", loc, "text/plain", "");
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
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = io };
    defer client.deinit();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };

    // Without credentials: refused, saying why.
    var why: []const u8 = "";
    try testing.expectError(error.Unauthorized, image.pull(arena, testing.allocator, io, &client, store, .{ .image = try server.image(arena, "test/img:1"), .owners = false }, &why));
    try testing.expect(std.mem.indexOf(u8, why, "credentials") != null);

    why = "";
    const got = image.pull(arena, testing.allocator, io, &client, store, .{
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
    try testing.expectEqualStrings("FROM_IMAGE=yes", got.env[1]);
    var root = try std.Io.Dir.cwd().openDir(io, got.rootfs, .{});
    defer root.close(io);
    try testing.expectEqualStrings("from the image\n", try root.readFileAlloc(io, "etc/marker", arena, .limited(100)));
    try testing.expectEqualStrings("gzip\n", try root.readFileAlloc(io, "gzip.txt", arena, .limited(100)));
    try testing.expectEqualStrings("zstd\n", try root.readFileAlloc(io, "zstd.txt", arena, .limited(100)));
    try testing.expectError(error.FileNotFound, root.access(io, "etc/gone", .{}));

    // By tag again: the manifest is asked for (a tag moves), the blobs and rootfs are not.
    const before = server.requests.load(.acquire);
    const again = try image.pull(arena, testing.allocator, io, &client, store, .{
        .image = try server.image(arena, "test/img:1"),
        .creds = .{ .username = "user", .password = "pass" },
        .owners = false,
    }, &why);
    try testing.expect(again.pulled == null);
    try testing.expectEqualStrings(got.rootfs, again.rootfs);
    try testing.expect(server.requests.load(.acquire) - before <= 4);
    // Pinned by the index's digest, once seen: no request at all.
    const pinned = try std.fmt.allocPrint(arena, "{s}@{s}", .{ try server.image(arena, "test/img:1"), img.index });
    _ = try image.pull(arena, testing.allocator, io, &client, store, .{ .image = pinned, .creds = .{ .username = "user", .password = "pass" }, .owners = false }, &why);
    const seen = server.requests.load(.acquire);
    const cached = try image.pull(arena, testing.allocator, io, &client, store, .{ .image = pinned, .owners = false }, &why);
    try testing.expectEqual(seen, server.requests.load(.acquire));
    try testing.expectEqualStrings(got.rootfs, cached.rootfs);
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
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = io };
    defer client.deinit();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    var why: []const u8 = "";
    try testing.expectError(error.DigestMismatch, image.pull(arena, testing.allocator, io, &client, store, .{ .image = try server.image(arena, "test/bad:1"), .owners = false }, &why));
    try testing.expect(std.mem.indexOf(u8, why, "hashing to") != null);
    var blobs = try tmp.dir.openDir(io, "oci/blobs/sha256", .{ .iterate = true });
    defer blobs.close(io);
    var it = blobs.iterate();
    try testing.expect(try it.next(io) == null);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, try std.fmt.allocPrint(arena, "oci/images/{s}.rootless", .{img.manifest["sha256:".len..]}), .{}));
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
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = io };
    defer client.deinit();
    var why: []const u8 = "";
    const got = image.pull(arena, testing.allocator, io, &client, store, .{
        .image = try server.image(arena, "test/stale:1"),
        .creds = creds,
        .owners = false,
    }, &why) catch |e| {
        std.debug.print("pull: {s}\n", .{why});
        return e;
    };
    try testing.expectEqualStrings(img.manifest, got.manifest);
    try testing.expect(server.requests.load(.acquire) >= 6);

    // A registry that closes every connection unanswered is no stale connection: the pull fails
    // with the error, once every kept connection the pool could hold has been tried.
    var mute: Server = .{ .routes = img.routes, .mute = true };
    try mute.start();
    defer mute.stop();
    why = "";
    try testing.expectError(error.HttpConnectionClosing, image.pull(arena, testing.allocator, io, &client, store, .{
        .image = try mute.image(arena, "test/stale:2"),
        .owners = false,
    }, &why));
    try testing.expect(std.mem.indexOf(u8, why, "could not fetch its manifest: HttpConnectionClosing") != null);
    const tries = mute.requests.load(.acquire);
    try testing.expectEqual(@import("../../github/http.zig").staleRetries(&client) + 1, tries);
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
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = io, .write_buffer_size = 16 * 1024 };
    defer client.deinit();
    const store: Store = .{ .root = try tmp.dir.realPathFileAlloc(io, ".", arena) };
    const dagger = @import("../../dagger.zig");
    var why: []const u8 = "";
    const t0 = std.Io.Clock.awake.now(io).toMilliseconds();
    const got = image.pull(arena, testing.allocator, io, &client, store, .{
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
    const warm = try image.pull(arena, testing.allocator, io, &client, store, .{ .image = dagger.default_image, .owners = std.os.linux.geteuid() == 0 }, &why);
    std.debug.print("warm (pinned, in the store): {d} ms\n", .{std.Io.Clock.awake.now(io).toMilliseconds() - t1});
    try testing.expect(warm.pulled == null);
    // A pull by tag, so it asks the registry, after the client's kept connections have sat idle
    // past Docker Hub's minute: they are closed, and the pull goes on new ones (razorbill failed
    // here with HttpConnectionClosing). The same client, as the runner's is the process's.
    try io.sleep(.fromSeconds(70), .awake);
    const idle = image.pull(arena, testing.allocator, io, &client, store, .{
        .image = "alpine:3.22",
        .owners = std.os.linux.geteuid() == 0,
    }, &why) catch |e| {
        std.debug.print("pull after a minute idle: {s}\n", .{why});
        return e;
    };
    std.debug.print("after 70 s idle: {s}\n", .{idle.digest});
}
