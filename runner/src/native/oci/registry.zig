//! The registry side of an image pull: image references, the distribution API's manifests and
//! blobs over HTTPS, and its token auth, with a private registry's credentials when the job gives
//! them (the same `container: credentials:` the Dagger path hands `withRegistryAuth`).
//!
//! Auth is the registry's challenge, answered once per pull: a request without credentials, a
//! `401` naming a `Bearer` realm (a token service, Docker Hub's `auth.docker.io`) or `Basic`, then
//! the token (asked for with the credentials, as Basic, when there are any) or the credentials
//! themselves on every request after. Authorization is a privileged header: std's client drops it
//! on a redirect to another domain (a blob's CDN), as Docker does.
//!
//! Plain HTTP only to a registry on the loopback (`localhost`, `127.0.0.1`, `[::1]`), as Docker
//! allows by default; a token realm elsewhere must be HTTPS, since the credentials go to it.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// An image reference, normalized as Docker does: `ubuntu:24.04` is
/// `docker.io/library/ubuntu:24.04`, pulled from `registry-1.docker.io`.
pub const Ref = struct {
    /// Where credentials are looked up (`docker.registryHost`'s answer): `docker.io` for Docker Hub.
    registry: []const u8,
    /// The host the API is reached at.
    host: []const u8,
    repository: []const u8,
    tag: []const u8 = "latest",
    /// `sha256:<hex>` when pinned; the tag is then only what it was called.
    digest: ?[]const u8 = null,

    /// The digest, or else the tag: what the manifest is asked for by.
    pub fn reference(r: Ref) []const u8 {
        return r.digest orelse r.tag;
    }

    pub fn loopback(r: Ref) bool {
        const host = hostOnly(r.host);
        return std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "127.0.0.1") or
            std.mem.eql(u8, host, "[::1]");
    }

    fn scheme(r: Ref) []const u8 {
        return if (r.loopback()) "http" else "https";
    }

    pub fn format(r: Ref, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{s}/{s}", .{ r.registry, r.repository });
        if (r.digest) |d| try w.print("@{s}", .{d}) else try w.print(":{s}", .{r.tag});
    }
};

fn hostOnly(host_port: []const u8) []const u8 {
    if (std.mem.startsWith(u8, host_port, "[")) {
        const end = std.mem.indexOfScalar(u8, host_port, ']') orelse return host_port;
        return host_port[0 .. end + 1];
    }
    return host_port[0 .. std.mem.indexOfScalar(u8, host_port, ':') orelse host_port.len];
}

/// Parses an image reference, refusing anything that is not one (its parts go into URLs).
pub fn parseRef(arena: Allocator, image: []const u8) !Ref {
    var rest = image;
    var digest: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
        digest = rest[at + 1 ..];
        rest = rest[0..at];
        if (!validDigest(digest.?)) return error.InvalidImageReference;
    }
    var tag: []const u8 = "latest";
    const last_slash = std.mem.lastIndexOfScalar(u8, rest, '/') orelse 0;
    if (std.mem.lastIndexOfScalar(u8, rest, ':')) |colon| if (colon > last_slash) {
        tag = rest[colon + 1 ..];
        rest = rest[0..colon];
        if (!validTag(tag)) return error.InvalidImageReference;
    };
    var registry: []const u8 = "docker.io";
    var repository = rest;
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
        const first = rest[0..slash];
        if (std.mem.indexOfAny(u8, first, ".:") != null or std.mem.eql(u8, first, "localhost")) {
            registry = first;
            repository = rest[slash + 1 ..];
        }
    }
    if (std.mem.eql(u8, registry, "index.docker.io")) registry = "docker.io";
    const hub = std.mem.eql(u8, registry, "docker.io");
    if (hub and std.mem.indexOfScalar(u8, repository, '/') == null)
        repository = try std.fmt.allocPrint(arena, "library/{s}", .{repository});
    if (!validRepository(repository) or !validHost(registry)) return error.InvalidImageReference;
    return .{
        .registry = registry,
        .host = if (hub) "registry-1.docker.io" else registry,
        .repository = repository,
        .tag = tag,
        .digest = digest,
    };
}

pub fn validDigest(d: []const u8) bool {
    const hex = std.mem.cutPrefix(u8, d, "sha256:") orelse return false;
    if (hex.len != 64) return false;
    for (hex) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return false;
    return true;
}

fn validTag(t: []const u8) bool {
    if (t.len == 0 or t.len > 128 or t[0] == '.' or t[0] == '-') return false;
    for (t) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '.' and c != '-') return false;
    return true;
}

fn validRepository(r: []const u8) bool {
    if (r.len == 0 or r.len > 255) return false;
    var it = std.mem.splitScalar(u8, r, '/');
    while (it.next()) |part| {
        if (part.len == 0) return false;
        if (!std.ascii.isAlphanumeric(part[0]) or !std.ascii.isAlphanumeric(part[part.len - 1]))
            return false;
        for (part) |c| {
            const ok = std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '.' or c == '_' or c == '-';
            if (!ok) return false;
        }
    }
    return true;
}

fn validHost(h: []const u8) bool {
    if (h.len == 0) return false;
    for (h) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, ".-:[]", c) == null)
        return false;
    return true;
}

/// A registry user and password (or token), from the job's `container: credentials:`.
pub const Credentials = struct { username: []const u8, password: []const u8 };

/// Every manifest type a pull takes, the platform-independent lists first.
pub const manifest_accept = "application/vnd.oci.image.index.v1+json, " ++
    "application/vnd.docker.distribution.manifest.list.v2+json, " ++
    "application/vnd.oci.image.manifest.v1+json, " ++
    "application/vnd.docker.distribution.manifest.v2+json";

/// containerd's limit for a manifest.
pub const max_manifest = 4 << 20;

/// One pull's conversation with a registry: the auth it was asked for, kept for the next request.
pub const Client = struct {
    arena: Allocator,
    http: *std.http.Client,
    ref: Ref,
    creds: ?Credentials,
    /// `Bearer <token>` or `Basic <base64>`, once the registry asked for it.
    authorization: ?[]const u8 = null,
    /// Why the last request failed, for the job's log.
    why: []const u8 = "",
    /// The last response's.
    content_type: []const u8 = "",

    pub const Manifest = struct {
        bytes: []const u8,
        media_type: []const u8,
        /// Of `bytes`, as computed here (never the registry's say-so).
        digest: []const u8,
    };

    /// The manifest the reference names, or `reference` (a digest from an index) instead. Asked
    /// for by digest, its bytes must hash to it.
    pub fn manifest(c: *Client, reference: []const u8) !Manifest {
        const url = try std.fmt.allocPrint(c.arena, "{s}://{s}/v2/{s}/manifests/{s}", .{
            c.ref.scheme(), c.ref.host, c.ref.repository, reference,
        });
        var body: Body = .{ .memory = .{ .arena = c.arena, .limit = max_manifest } };
        const ct = try c.get(url, manifest_accept, &body);
        var sum: [32]u8 = undefined;
        Sha256.hash(body.memory.bytes.items, &sum, .{});
        const digest = try std.fmt.allocPrint(c.arena, "sha256:{s}", .{&std.fmt.bytesToHex(sum, .lower)});
        if (std.mem.startsWith(u8, reference, "sha256:") and !std.mem.eql(u8, digest, reference)) {
            c.why = try std.fmt.allocPrint(c.arena, "the manifest {s} hashes to {s}", .{ reference, digest });
            return error.DigestMismatch;
        }
        return .{ .bytes = body.memory.bytes.items, .media_type = ct, .digest = digest };
    }

    /// A blob into `file`, checked against its digest and size as it arrives.
    pub fn blob(c: *Client, digest: []const u8, size: u64, file: std.Io.File) !void {
        const url = try std.fmt.allocPrint(c.arena, "{s}://{s}/v2/{s}/blobs/{s}", .{
            c.ref.scheme(), c.ref.host, c.ref.repository, digest,
        });
        var body: Body = .{ .file = .{ .file = file, .limit = size } };
        _ = try c.get(url, "*/*", &body);
        var sum: [32]u8 = undefined;
        body.file.hash.final(&sum);
        const got = std.fmt.bytesToHex(sum, .lower);
        if (body.file.written != size or !std.mem.eql(u8, &got, digest["sha256:".len..])) {
            c.why = try std.fmt.allocPrint(c.arena, "the blob {s} came as {d} bytes hashing to " ++
                "sha256:{s}, not {d}", .{ digest, body.file.written, &got, size });
            return error.DigestMismatch;
        }
    }

    /// A blob that fits in memory (an image's config), checked against its digest.
    pub fn smallBlob(c: *Client, digest: []const u8, limit: usize) ![]const u8 {
        const url = try std.fmt.allocPrint(c.arena, "{s}://{s}/v2/{s}/blobs/{s}", .{
            c.ref.scheme(), c.ref.host, c.ref.repository, digest,
        });
        var body: Body = .{ .memory = .{ .arena = c.arena, .limit = limit } };
        _ = try c.get(url, "*/*", &body);
        var sum: [32]u8 = undefined;
        Sha256.hash(body.memory.bytes.items, &sum, .{});
        if (!std.mem.eql(u8, &std.fmt.bytesToHex(sum, .lower), digest["sha256:".len..])) {
            c.why = try std.fmt.allocPrint(c.arena, "the blob {s} does not hash to its digest", .{digest});
            return error.DigestMismatch;
        }
        return body.memory.bytes.items;
    }

    /// GET `url` into `body`, answering one auth challenge. The response's content type.
    fn get(c: *Client, url: []const u8, accept: []const u8, body: *Body) ![]const u8 {
        var challenged = false;
        while (true) {
            var challenge: ?[]const u8 = null;
            const ct = try c.once(url, accept, body, &challenge);
            const ch = challenge orelse return ct;
            if (challenged) {
                c.why = try std.fmt.allocPrint(c.arena, "{f}: unauthorized{s}", .{
                    c.ref, if (c.creds == null) " (a private image needs `credentials:`)" else "",
                });
                return error.Unauthorized;
            }
            challenged = true;
            try c.answer(ch);
        }
    }

    /// One request, following redirects itself. A 401 sets `challenge` (its `WWW-Authenticate`)
    /// and returns. The authorization goes to the registry's own host only: never to where a
    /// redirect leads (a blob's CDN, with a signed URL of its own).
    fn once(c: *Client, url: []const u8, accept: []const u8, body: *Body, challenge: *?[]const u8) ![]const u8 {
        var uri = try std.Uri.parse(url);
        var redirects: u32 = 0;
        while (true) : (redirects += 1) {
            if (redirects > max_redirects) {
                c.why = try std.fmt.allocPrint(c.arena, "{s}: too many redirects", .{url});
                return error.TooManyRedirects;
            }
            uri = try c.onceAt(uri, accept, body, challenge) orelse return c.content_type;
        }
    }

    const max_redirects = 5;

    /// One request to `uri`: null when it was answered (its content type in `content_type`), or
    /// where it redirects to (in the arena).
    fn onceAt(c: *Client, uri: std.Uri, accept: []const u8, body: *Body, challenge: *?[]const u8) !?std.Uri {
        // std 0.17's client never sends `privileged_headers`, and keeps `headers.authorization`
        // across a redirect to another host: redirects are followed here, and the header is
        // given only to the registry.
        const own = c.authorization != null and sameOrigin(uri, c.ref);
        var req = try c.http.request(.GET, uri, .{
            .headers = .{
                .accept_encoding = .omit,
                .user_agent = .{ .override = "zig-runner" },
                .authorization = if (own) .{ .override = c.authorization.? } else .omit,
            },
            .extra_headers = &.{.{ .name = "accept", .value = accept }},
            .redirect_behavior = .unhandled,
        });
        defer req.deinit();
        errdefer if (req.connection) |conn| {
            conn.closing = true;
        };
        try req.sendBodiless();
        var res = try req.receiveHead(&.{});
        const status = res.head.status;
        c.content_type = "";
        var it = res.head.iterateHeaders();
        var location: ?[]const u8 = null;
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate") and status == .unauthorized)
                challenge.* = try c.arena.dupe(u8, h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "content-type"))
                c.content_type = try c.arena.dupe(u8, std.mem.trim(u8, h.value[0 .. std.mem.indexOfScalar(u8, h.value, ';') orelse h.value.len], " "));
            if (std.ascii.eqlIgnoreCase(h.name, "location")) location = try c.arena.dupe(u8, h.value);
        }
        var transfer: [64]u8 = undefined;
        const r = res.reader(&transfer);
        if (status.class() == .redirect) if (location) |loc| {
            _ = r.discardRemaining() catch {
                req.connection.?.closing = true;
            };
            // Relative to the request's URL.
            var buf = try c.arena.alloc(u8, loc.len + 2048);
            @memcpy(buf[0..loc.len], loc);
            var aux: []u8 = buf;
            const next = uri.resolveInPlace(loc.len, &aux) catch return error.HttpRedirectLocationInvalid;
            if (!std.mem.eql(u8, next.scheme, "https") and !std.mem.eql(u8, next.scheme, "http"))
                return error.HttpRedirectLocationInvalid;
            return next;
        };
        if (status == .unauthorized and challenge.* != null) {
            _ = r.discardRemaining() catch {};
            return null;
        }
        if (status != .ok) {
            var err_body: Body = .{ .memory = .{ .arena = c.arena, .limit = 4096 } };
            err_body.take(r) catch {};
            c.why = try std.fmt.allocPrint(c.arena, "{f}: HTTP {d} {s}", .{
                c.ref, @backingInt(status), std.mem.trim(u8, err_body.memory.bytes.items, " \n"),
            });
            return if (status == .not_found) error.NotFound else error.HttpStatus;
        }
        body.take(r) catch |e| switch (e) {
            error.ReadFailed => return res.bodyErr() orelse e,
            else => return e,
        };
        return null;
    }

    /// Sets `authorization` from a 401's challenge.
    fn answer(c: *Client, challenge: []const u8) !void {
        const ch = try parseChallenge(c.arena, challenge);
        switch (ch.scheme) {
            .basic => {
                const cr = c.creds orelse {
                    c.why = try std.fmt.allocPrint(c.arena, "{f}: the registry asks for a " ++
                        "password (a private image needs `credentials:`)", .{c.ref});
                    return error.Unauthorized;
                };
                c.authorization = try basic(c.arena, cr);
            },
            .bearer => c.authorization = try std.fmt.allocPrint(c.arena, "Bearer {s}", .{
                try c.token(ch),
            }),
        }
    }

    /// A token from the realm the challenge names, for pulling this repository.
    fn token(c: *Client, ch: Challenge) ![]const u8 {
        const realm = std.Uri.parse(ch.realm) catch {
            c.why = try std.fmt.allocPrint(c.arena, "{f}: the registry's token realm is not a URL", .{c.ref});
            return error.Unauthorized;
        };
        if (!std.mem.eql(u8, realm.scheme, "https") and !c.ref.loopback()) {
            c.why = try std.fmt.allocPrint(c.arena, "{f}: the registry's token realm is not HTTPS", .{c.ref});
            return error.Unauthorized;
        }
        var url: std.Io.Writer.Allocating = .init(c.arena);
        try url.writer.writeAll(ch.realm);
        try url.writer.writeByte(if (std.mem.indexOfScalar(u8, ch.realm, '?') == null) '?' else '&');
        if (ch.service) |s| {
            try url.writer.writeAll("service=");
            try std.Uri.Component.percentEncode(&url.writer, s, isQueryChar);
            try url.writer.writeByte('&');
        }
        const scope = try std.fmt.allocPrint(c.arena, "repository:{s}:pull", .{c.ref.repository});
        try url.writer.writeAll("scope=");
        try std.Uri.Component.percentEncode(&url.writer, scope, isQueryChar);
        const auth: ?[]const u8 = if (c.creds) |cr| try basic(c.arena, cr) else null;
        var body: std.Io.Writer.Allocating = .init(c.arena);
        // No redirect is followed: the credentials would go with it (see `onceAt`).
        const res = c.http.fetch(.{
            .location = .{ .url = url.written() },
            .headers = .{
                .user_agent = .{ .override = "zig-runner" },
                .authorization = if (auth) |a| .{ .override = a } else .omit,
            },
            .redirect_behavior = .unhandled,
            .response_writer = &body.writer,
        }) catch |e| {
            c.why = try std.fmt.allocPrint(c.arena, "{f}: the token service: {s}", .{ c.ref, @errorName(e) });
            return error.Unauthorized;
        };
        if (res.status != .ok) {
            c.why = try std.fmt.allocPrint(c.arena, "{f}: the token service answered HTTP {d}{s}", .{
                c.ref,
                @backingInt(res.status),
                if (c.creds == null) " (a private image needs `credentials:`)" else " (are the credentials right?)",
            });
            return error.Unauthorized;
        }
        const T = struct { token: ?[]const u8 = null, access_token: ?[]const u8 = null };
        const t = std.json.parseFromSliceLeaky(T, c.arena, body.written(), .{
            .ignore_unknown_fields = true,
        }) catch return error.Unauthorized;
        return t.token orelse t.access_token orelse error.Unauthorized;
    }
};

/// Whether `uri` is the registry's own scheme, host and port.
fn sameOrigin(uri: std.Uri, ref: Ref) bool {
    if (!std.mem.eql(u8, uri.scheme, ref.scheme())) return false;
    var buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = std.Io.net.HostName.fromUri(uri, &buf) catch return false;
    const want_host = hostOnly(ref.host);
    const bare = std.mem.trim(u8, want_host, "[]");
    if (!std.ascii.eqlIgnoreCase(host.bytes, bare) and !std.ascii.eqlIgnoreCase(host.bytes, want_host)) return false;
    const want_port: ?u16 = if (std.mem.lastIndexOfScalar(u8, ref.host, ':')) |i|
        (if (i > (std.mem.lastIndexOfScalar(u8, ref.host, ']') orelse 0)) std.fmt.parseInt(u16, ref.host[i + 1 ..], 10) catch null else null)
    else
        null;
    return uri.port == want_port;
}

fn isQueryChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '.' or ch == '_' or ch == '~';
}

fn basic(arena: Allocator, cr: Credentials) ![]const u8 {
    const plain = try std.fmt.allocPrint(arena, "{s}:{s}", .{ cr.username, cr.password });
    const enc = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(plain.len));
    return std.fmt.allocPrint(arena, "Basic {s}", .{enc.encode(out, plain)});
}

/// Where a response's body goes: memory up to a limit, or a file, hashed, up to the blob's size.
const Body = union(enum) {
    memory: struct { arena: Allocator, limit: usize, bytes: std.ArrayList(u8) = .empty },
    file: struct { file: std.Io.File, limit: u64, written: u64 = 0, hash: Sha256 = .init(.{}) },

    fn take(b: *Body, r: *std.Io.Reader) !void {
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try r.readSliceShort(&buf);
            if (n == 0) return;
            switch (b.*) {
                .memory => |*m| {
                    if (m.bytes.items.len + n > m.limit) return error.ResponseTooLarge;
                    try m.bytes.appendSlice(m.arena, buf[0..n]);
                },
                .file => |*f| {
                    if (f.written + n > f.limit) return error.ResponseTooLarge;
                    f.hash.update(buf[0..n]);
                    try writeAll(f.file, buf[0..n]);
                    f.written += n;
                },
            }
        }
    }
};

fn writeAll(file: std.Io.File, bytes: []const u8) !void {
    var rest = bytes;
    while (rest.len > 0) {
        const rc = std.os.linux.write(file.handle, rest.ptr, rest.len);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => rest = rest[rc..],
            .INTR => {},
            else => return error.WriteFailed,
        }
    }
}

pub const Challenge = struct {
    scheme: enum { bearer, basic },
    realm: []const u8 = "",
    service: ?[]const u8 = null,
};

/// `Bearer realm="...",service="...",scope="..."` or `Basic realm="..."`.
pub fn parseChallenge(arena: Allocator, text: []const u8) !Challenge {
    const t = std.mem.trim(u8, text, " ");
    const sp = std.mem.indexOfScalar(u8, t, ' ') orelse t.len;
    const scheme = t[0..sp];
    var ch: Challenge = if (std.ascii.eqlIgnoreCase(scheme, "bearer"))
        .{ .scheme = .bearer }
    else if (std.ascii.eqlIgnoreCase(scheme, "basic"))
        .{ .scheme = .basic }
    else
        return error.UnsupportedAuth;
    var rest = t[sp..];
    while (true) {
        rest = std.mem.trimStart(u8, rest, " ,");
        if (rest.len == 0) break;
        const eq = std.mem.indexOfScalar(u8, rest, '=') orelse break;
        const key = std.mem.trim(u8, rest[0..eq], " ");
        rest = rest[eq + 1 ..];
        var value: []const u8 = undefined;
        if (rest.len > 0 and rest[0] == '"') {
            var out: std.ArrayList(u8) = .empty;
            var i: usize = 1;
            while (i < rest.len and rest[i] != '"') : (i += 1) {
                if (rest[i] == '\\' and i + 1 < rest.len) i += 1;
                try out.append(arena, rest[i]);
            }
            value = out.items;
            rest = if (i < rest.len) rest[i + 1 ..] else "";
        } else {
            const end = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
            value = std.mem.trim(u8, rest[0..end], " ");
            rest = rest[end..];
        }
        if (std.ascii.eqlIgnoreCase(key, "realm")) ch.realm = value;
        if (std.ascii.eqlIgnoreCase(key, "service")) ch.service = value;
    }
    if (ch.scheme == .bearer and ch.realm.len == 0) return error.UnsupportedAuth;
    return ch;
}

// --- tests ---

const testing = std.testing;

test "native oci references are normalized as Docker's, and anything else is refused" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const hex = "fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852";
    const cases = [_]struct { in: []const u8, registry: []const u8, host: []const u8, repo: []const u8, ref: []const u8 }{
        .{ .in = "ubuntu:24.04", .registry = "docker.io", .host = "registry-1.docker.io", .repo = "library/ubuntu", .ref = "24.04" },
        .{ .in = "ubuntu", .registry = "docker.io", .host = "registry-1.docker.io", .repo = "library/ubuntu", .ref = "latest" },
        .{ .in = "ubuntu:24.04@sha256:" ++ hex, .registry = "docker.io", .host = "registry-1.docker.io", .repo = "library/ubuntu", .ref = "sha256:" ++ hex },
        .{ .in = "bitnami/postgresql:17", .registry = "docker.io", .host = "registry-1.docker.io", .repo = "bitnami/postgresql", .ref = "17" },
        .{ .in = "ghcr.io/acme/app/img:1.2", .registry = "ghcr.io", .host = "ghcr.io", .repo = "acme/app/img", .ref = "1.2" },
        .{ .in = "localhost:5000/db", .registry = "localhost:5000", .host = "localhost:5000", .repo = "db", .ref = "latest" },
        .{ .in = "docker.io/library/node:20", .registry = "docker.io", .host = "registry-1.docker.io", .repo = "library/node", .ref = "20" },
    };
    for (cases) |c| {
        const r = try parseRef(arena, c.in);
        try testing.expectEqualStrings(c.registry, r.registry);
        try testing.expectEqualStrings(c.host, r.host);
        try testing.expectEqualStrings(c.repo, r.repository);
        try testing.expectEqualStrings(c.ref, r.reference());
    }
    for ([_][]const u8{ "Ubuntu", "ubuntu:", "ubuntu@sha256:abc", "a/../b", "ghcr.io/a b", "x:t/../../y", "ghcr.io/acme/img:1?x", "" }) |bad|
        try testing.expectError(error.InvalidImageReference, parseRef(arena, bad));
    try testing.expect((try parseRef(arena, "127.0.0.1:5000/x")).loopback());
    try testing.expect(!(try parseRef(arena, "ghcr.io/x")).loopback());
}

test "native oci registry challenges: Bearer with its realm and service, Basic" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ch = try parseChallenge(a.allocator(), "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/ubuntu:pull\"");
    try testing.expect(ch.scheme == .bearer);
    try testing.expectEqualStrings("https://auth.docker.io/token", ch.realm);
    try testing.expectEqualStrings("registry.docker.io", ch.service.?);
    try testing.expect((try parseChallenge(a.allocator(), "Basic realm=\"x\"")).scheme == .basic);
    try testing.expectError(error.UnsupportedAuth, parseChallenge(a.allocator(), "Negotiate"));
    try testing.expectError(error.UnsupportedAuth, parseChallenge(a.allocator(), "Bearer service=\"x\""));
}
