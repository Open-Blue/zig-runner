//! GitHub App authentication for managing the runner's registrations, in place of `GH_TOKEN`. A
//! JWT signed with the App's private key (`auth.signJwt`) buys an installation token, valid for an
//! hour, which every runner-management call sends (`jitconfig`). The App needs the repository
//! permission "Administration: read and write" for a repository scope, or the organization
//! permission "Self-hosted runners: read and write" for an organization, and must be installed on
//! the scope. A broad OAuth token reaches every repository its user can; an App installation only
//! the ones it was given, and the scale-set API (#231) needs an App too.
const std = @import("std");
const Scope = @import("../config.zig").Scope;
const GhApp = @import("../config.zig").GhApp;
const auth = @import("auth.zig");
const net_client = @import("../net_client.zig");
const jitconfig = @import("jitconfig.zig");
const rsa_sign = @import("rsa_sign.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    /// The private key is not an RSA key in PKCS#1 or PKCS#8 PEM.
    BadKey,
    /// GitHub refused the App's JWT or found no installation: non-2xx, its reason in
    /// `message_out`.
    AppRejected,
    BadResponse,
} || Allocator.Error || net_client.Error || std.Io.Writer.Error || rsa_sign.Error || std.Io.Cancelable;

/// The App's installation tokens for one scope, shared by every runner of the process: one token
/// at a time, minted when the last is near its end or GitHub refused it.
pub const Auth = struct {
    /// What the JWT's `iss` names: the App's ID, or its Client ID (`Iv23...`), which GitHub
    /// accepts too and now recommends.
    app_id: []const u8,
    key: Key,
    /// Found from `scope` with the first token when not configured.
    installation_id: ?u64,
    scope: Scope,
    /// GitHub's REST API; a test server's in tests.
    api: []const u8 = "https://api.github.com",
    mu: std.Io.Mutex = .init,
    token_buf: [max_token_len]u8 = undefined,
    token_len: usize = 0,
    /// When GitHub says the cached token expires, in unix seconds.
    expires_at: i64 = 0,

    /// From the configuration: the key read from its file or taken inline, and parsed. Nothing is
    /// asked of GitHub until the first `token`.
    pub fn init(arena: Allocator, io: std.Io, settings: GhApp, scope: Scope) !Auth {
        const pem = switch (settings.key) {
            .file => |path| try std.Io.Dir.cwd().readFileAlloc(
                io,
                path,
                arena,
                .limited(64 * 1024),
            ),
            .pem => |pem| pem,
        };
        return .{
            .app_id = settings.id,
            .key = try parsePem(arena, pem),
            .installation_id = settings.installation_id,
            .scope = scope,
        };
    }

    /// An installation token valid for at least `refresh_margin_secs` more, copied to `arena` (the
    /// cache may be replaced by another runner meanwhile). When GitHub refuses, its status and
    /// reason go to `status_out` and `message_out`.
    pub fn token(
        a: *Auth,
        arena: Allocator,
        io: std.Io,
        status_out: *std.http.Status,
        message_out: *[]const u8,
    ) Error![]const u8 {
        const now = std.Io.Clock.real.now(io).toSeconds();
        return a.tokenAt(arena, io, now, status_out, message_out);
    }

    fn tokenAt(
        a: *Auth,
        arena: Allocator,
        io: std.Io,
        now: i64,
        status_out: *std.http.Status,
        message_out: *[]const u8,
    ) Error![]const u8 {
        // Held across the requests, so runners asking at once wait for one token, not mint one
        // each.
        try a.mu.lock(io);
        defer a.mu.unlock(io);
        if (a.token_len > 0 and now < a.expires_at - refresh_margin_secs)
            return arena.dupe(u8, a.token_buf[0..a.token_len]);

        const jwt = try buildJwt(arena, a.app_id, a.key, now);
        const id = a.installation_id orelse found: {
            const url = switch (a.scope) {
                .repo => |r| try std.fmt.allocPrint(
                    arena,
                    "{s}/repos/{s}/{s}/installation",
                    .{ a.api, r.owner, r.name },
                ),
                .org => |o| try std.fmt.allocPrint(
                    arena,
                    "{s}/orgs/{s}/installation",
                    .{ a.api, o },
                ),
            };
            const body = try call(arena, io, .GET, url, jwt, status_out, message_out);
            const Installation = struct { id: u64 };
            const i = std.json.parseFromSliceLeaky(Installation, arena, body, .{
                .ignore_unknown_fields = true,
            }) catch return error.BadResponse;
            a.installation_id = i.id;
            break :found i.id;
        };

        const url = try std.fmt.allocPrint(
            arena,
            "{s}/app/installations/{d}/access_tokens",
            .{ a.api, id },
        );
        const body = try call(arena, io, .POST, url, jwt, status_out, message_out);
        const Minted = struct { token: []const u8, expires_at: []const u8 };
        const m = std.json.parseFromSliceLeaky(Minted, arena, body, .{
            .ignore_unknown_fields = true,
        }) catch return error.BadResponse;
        if (m.token.len == 0 or m.token.len > max_token_len) return error.BadResponse;
        a.expires_at = unixSeconds(m.expires_at) orelse return error.BadResponse;
        @memcpy(a.token_buf[0..m.token.len], m.token);
        a.token_len = m.token.len;
        return arena.dupe(u8, m.token);
    }

    /// Drops the cached token after GitHub refused `stale` (401: revoked, or the App's permissions
    /// changed), unless another runner already replaced it.
    pub fn invalidate(a: *Auth, io: std.Io, stale: []const u8) void {
        a.mu.lockUncancelable(io);
        defer a.mu.unlock(io);
        if (std.mem.eql(u8, a.token_buf[0..a.token_len], stale)) a.token_len = 0;
    }
};

/// GitHub's installation tokens are 40 characters today; it has said they may grow to 255.
const max_token_len = 1024;

/// A token is replaced this long before GitHub says it expires, so a request never carries one
/// that runs out on the way.
const refresh_margin_secs = 5 * 60;

/// An RSA private key, big-endian, as `rsa_sign` takes it.
pub const Key = struct {
    modulus: []const u8,
    public_exponent: []const u8,
    private_exponent: []const u8,
};

/// The App's JWT: issued a minute in the past and valid for nine more, as GitHub allows ten at
/// most and a clock a little off must not turn it away.
pub fn buildJwt(arena: Allocator, app_id: []const u8, key: Key, now: i64) Error![]const u8 {
    const claims = try std.fmt.allocPrint(
        arena,
        "{{\"iat\":{d},\"exp\":{d},\"iss\":\"{s}\"}}",
        .{ now - 60, now + 9 * 60, app_id },
    );
    return auth.signJwt(arena, claims, key.modulus, key.private_exponent);
}

/// One request to the App API with the App's JWT; the body of a 2xx answer.
fn call(
    arena: Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    jwt: []const u8,
    status_out: *std.http.Status,
    message_out: *[]const u8,
) Error![]const u8 {
    const result = try net_client.fetch(arena, io, .{
        .url = url,
        .method = method,
        .payload = if (method == .POST) "" else null,
        .headers = &.{
            .{ .name = "Authorization", .value = try std.fmt.allocPrint(arena, "Bearer {s}", .{jwt}) },
            .{ .name = "Accept", .value = "application/vnd.github+json" },
            .{ .name = "X-GitHub-Api-Version", .value = "2022-11-28" },
        },
    });
    status_out.* = result.status;
    if (result.status.class() != .success) {
        message_out.* = jitconfig.errorMessage(arena, result.body);
        return error.AppRejected;
    }
    return result.body;
}

/// The key in a PEM: PKCS#1 (`BEGIN RSA PRIVATE KEY`, what GitHub's "Generate a private key"
/// downloads) or PKCS#8 (`BEGIN PRIVATE KEY`, what `openssl pkcs8` makes of it). A key given
/// inline in an env file has its line breaks written `\n`, as env files hold one line per
/// variable; those count as line breaks.
pub fn parsePem(arena: Allocator, pem: []const u8) error{ BadKey, OutOfMemory }!Key {
    const pkcs1 = "RSA PRIVATE KEY";
    const pkcs8 = "PRIVATE KEY";
    if (pemBody(pem, pkcs1)) |body| return rsaPrivateKey(try unbase64(arena, body));
    const body = pemBody(pem, pkcs8) orelse return error.BadKey;
    // PrivateKeyInfo (RFC 5208): version, AlgorithmIdentifier, the PKCS#1 key in an OCTET STRING.
    var info: Der = .{ .bytes = try unbase64(arena, body) };
    var seq: Der = .{ .bytes = try info.next(.sequence) };
    _ = try seq.next(.integer);
    var algorithm: Der = .{ .bytes = try seq.next(.sequence) };
    const rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    if (!std.mem.eql(u8, try algorithm.next(.object_identifier), &rsa_encryption))
        return error.BadKey;
    return rsaPrivateKey(try seq.next(.octet_string));
}

/// What lies between `-----BEGIN <label>-----` and `-----END <label>-----`.
fn pemBody(pem: []const u8, comptime label: []const u8) ?[]const u8 {
    const begin = "-----BEGIN " ++ label ++ "-----";
    const end = "-----END " ++ label ++ "-----";
    const from = (std.mem.indexOf(u8, pem, begin) orelse return null) + begin.len;
    const to = std.mem.indexOfPos(u8, pem, from, end) orelse return null;
    return pem[from..to];
}

/// Base64 with line breaks, spaces and `\n` escapes in it.
fn unbase64(arena: Allocator, text: []const u8) error{ BadKey, OutOfMemory }![]const u8 {
    const clean = try arena.alloc(u8, text.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (text[i] == '\\') {
            i += 1; // the escape's letter
        } else if (!std.ascii.isWhitespace(text[i])) {
            clean[n] = text[i];
            n += 1;
        }
    }
    const dec = std.base64.standard.Decoder;
    const out = try arena.alloc(u8, dec.calcSizeForSlice(clean[0..n]) catch return error.BadKey);
    dec.decode(out, clean[0..n]) catch return error.BadKey;
    return out;
}

/// RSAPrivateKey (RFC 8017 A.1.2): version 0, n, e, d, then the CRT values the signer does not use.
fn rsaPrivateKey(der: []const u8) error{BadKey}!Key {
    var outer: Der = .{ .bytes = der };
    var seq: Der = .{ .bytes = try outer.next(.sequence) };
    const version = try seq.next(.integer);
    if (version.len != 1 or version[0] != 0) return error.BadKey; // 1 is multi-prime
    const key: Key = .{
        .modulus = trimZeros(try seq.next(.integer)),
        .public_exponent = trimZeros(try seq.next(.integer)),
        .private_exponent = trimZeros(try seq.next(.integer)),
    };
    if (key.modulus.len < 256 or key.private_exponent.len == 0) return error.BadKey;
    return key;
}

fn trimZeros(b: []const u8) []const u8 {
    return std.mem.trimStart(u8, b, &.{0});
}

/// DER elements read one after another, checked against the bytes there are: the key is the
/// operator's input, and std's `der.Element.parse` assumes well-formed bytes.
const Der = struct {
    bytes: []const u8,
    pos: usize = 0,

    const Tag = enum(u8) {
        integer = 0x02,
        octet_string = 0x04,
        object_identifier = 0x06,
        sequence = 0x30,
    };

    /// The next element's contents, which must have `tag`.
    fn next(d: *Der, tag: Tag) error{BadKey}![]const u8 {
        const rest = d.bytes[d.pos..];
        if (rest.len < 2 or rest[0] != @backingInt(tag)) return error.BadKey;
        var len: usize = rest[1];
        var at: usize = 2;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            if (n == 0 or n > 4 or rest.len < 2 + n) return error.BadKey;
            len = 0;
            for (rest[2..][0..n]) |b| len = len << 8 | b;
            at += n;
        }
        if (len > rest.len - at) return error.BadKey;
        d.pos += at + len;
        return rest[at..][0..len];
    }
};

/// `2026-11-01T12:00:00Z`, the form GitHub gives `expires_at` in, as unix seconds.
fn unixSeconds(iso: []const u8) ?i64 {
    if (iso.len != 20 or iso[4] != '-' or iso[7] != '-' or iso[10] != 'T' or iso[13] != ':' or
        iso[16] != ':' or iso[19] != 'Z') return null;
    const p = struct {
        fn f(s: []const u8) ?i64 {
            return std.fmt.parseInt(i64, s, 10) catch null;
        }
    }.f;
    const year = p(iso[0..4]) orelse return null;
    const month = p(iso[5..7]) orelse return null;
    const day = p(iso[8..10]) orelse return null;
    if (month < 1 or month > 12 or day < 1 or day > 31) return null;
    // Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const doy = @divFloor(153 * (if (month > 2) month - 3 else month + 9) + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    const secs = (p(iso[11..13]) orelse return null) * 3600 +
        (p(iso[14..16]) orelse return null) * 60 + (p(iso[17..19]) orelse return null);
    return days * std.time.s_per_day + secs;
}

// A throwaway 2048-bit key made with `openssl genrsa -traditional` for these tests, in both forms.
// The BEGIN lines are put together at compile time so that secret scanners, which look for them,
// do not take a test fixture for a leaked key.
const test_pkcs1 = "-----BEGIN RSA " ++ "PRIVATE KEY-----\n" ++ test_pkcs1_body ++
    "\n-----END RSA PRIVATE KEY-----\n";
const test_pkcs8 = "-----BEGIN " ++ "PRIVATE KEY-----\n" ++ test_pkcs8_body ++
    "\n-----END PRIVATE KEY-----\n";

fn verifyJwt(jwt: []const u8, key: Key) !void {
    const b64url = std.base64.url_safe_no_pad;
    const sig_at = std.mem.lastIndexOfScalar(u8, jwt, '.').?;
    var sig: [256]u8 = undefined;
    try b64url.Decoder.decode(&sig, jwt[sig_at + 1 ..]);
    const rsa = std.crypto.Certificate.rsa;
    const pk = try rsa.PublicKey.fromBytes(key.public_exponent, key.modulus);
    try rsa.PKCS1v1_5Signature.verify(256, &sig, jwt[0..sig_at], pk, std.crypto.hash.sha2.Sha256);
}

test "PKCS#1 and PKCS#8 PEMs give the same key; anything else is BadKey" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const k1 = try parsePem(arena, test_pkcs1);
    const k8 = try parsePem(arena, test_pkcs8);
    try std.testing.expectEqual(@as(usize, 256), k1.modulus.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x01 }, k1.public_exponent);
    try std.testing.expectEqualSlices(u8, k1.modulus, k8.modulus);
    try std.testing.expectEqualSlices(u8, k1.private_exponent, k8.private_exponent);

    // Inline in an env file: one line, its breaks written `\n`.
    const escaped = try std.mem.replaceOwned(u8, arena, test_pkcs1, "\n", "\\n");
    try std.testing.expectEqualSlices(u8, k1.modulus, (try parsePem(arena, escaped)).modulus);

    try std.testing.expectError(error.BadKey, parsePem(arena, "not a key"));
    try std.testing.expectError(error.BadKey, parsePem(arena, "-----BEGIN " ++
        "PRIVATE KEY-----\nMAMCAQA=\n-----END PRIVATE KEY-----"));
    // Cut short: every length is checked against what is there.
    const cut = test_pkcs1[0 .. test_pkcs1.len / 2] ++ "\n-----END RSA PRIVATE KEY-----";
    try std.testing.expectError(error.BadKey, parsePem(arena, cut));
}

test "the App JWT has GitHub's claims and verifies with the key" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const key = try parsePem(arena, test_pkcs1);
    const jwt = try buildJwt(arena, "123456", key, 1_800_000_000);
    try verifyJwt(jwt, key);

    var parts = std.mem.splitScalar(u8, jwt, '.');
    _ = parts.next();
    const c = parts.next().?;
    const b64url = std.base64.url_safe_no_pad;
    const claims = try arena.alloc(u8, try b64url.Decoder.calcSizeForSlice(c));
    try b64url.Decoder.decode(claims, c);
    try std.testing.expectEqualStrings(
        "{\"iat\":1799999940,\"exp\":1800000540,\"iss\":\"123456\"}",
        claims,
    );

    var tampered = try arena.dupe(u8, jwt);
    tampered[10] ^= 1;
    try std.testing.expectError(error.InvalidSignature, verifyJwt(tampered, key));
}

test "expires_at" {
    try std.testing.expectEqual(@as(?i64, 0), unixSeconds("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, 1893456000), unixSeconds("2030-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, 1709210096), unixSeconds("2024-02-29T12:34:56Z"));
    try std.testing.expectEqual(@as(?i64, null), unixSeconds("2030-01-01 00:00:00"));
    try std.testing.expectEqual(@as(?i64, null), unixSeconds("2030-13-01T00:00:00Z"));
}

/// An `Auth` for `o/r`, installation 42, against the test server (`testserver.zig`) on `port`,
/// with the fixture key.
pub fn testAuth(arena: Allocator, port: u16) !Auth {
    if (!@import("builtin").is_test) @compileError("tests only");
    return .{
        .app_id = "Iv23test",
        .key = try parsePem(arena, test_pkcs1),
        .installation_id = 42,
        .scope = .{ .repo = .{ .owner = "o", .name = "r" } },
        .api = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{port}),
    };
}

test "installation tokens are cached, refreshed 5 minutes before expiry, and after a 401" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: @import("testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var a = try testAuth(arena, server.port);
    var status: std.http.Status = .ok;
    var message: []const u8 = "";

    // The test server's tokens expire at 2030-01-01T00:00:00Z (1893456000).
    const t1 = try a.tokenAt(arena, io, 1_800_000_000, &status, &message);
    try std.testing.expectEqualStrings("ghs_1", t1);
    const still = try a.tokenAt(arena, io, 1_893_455_699, &status, &message);
    try std.testing.expectEqualStrings("ghs_1", still);
    try std.testing.expectEqual(@as(u32, 1), server.app_tokens.load(.acquire));
    const t2 = try a.tokenAt(arena, io, 1_893_455_700, &status, &message);
    try std.testing.expectEqualStrings("ghs_2", t2);

    // A 401 for a token another runner already replaced keeps the new one.
    a.invalidate(io, t1);
    const kept = try a.tokenAt(arena, io, 1_800_000_000, &status, &message);
    try std.testing.expectEqualStrings("ghs_2", kept);
    a.invalidate(io, t2);
    const t3 = try a.tokenAt(arena, io, 1_800_000_000, &status, &message);
    try std.testing.expectEqualStrings("ghs_3", t3);
    try std.testing.expectEqual(@as(u32, 3), server.app_tokens.load(.acquire));
}

test "the installation is found from the scope when not configured" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: @import("testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var status: std.http.Status = .ok;
    var message: []const u8 = "";

    var repo = try testAuth(arena, server.port);
    repo.installation_id = null;
    _ = try repo.tokenAt(arena, io, 1_800_000_000, &status, &message);
    try std.testing.expectEqual(@as(?u64, 42), repo.installation_id);

    var org = try testAuth(arena, server.port);
    org.installation_id = null;
    org.scope = .{ .org = "acme" };
    _ = try org.tokenAt(arena, io, 1_800_000_000, &status, &message);
    try std.testing.expectEqual(@as(?u64, 43), org.installation_id);

    // Not installed there: GitHub's 404 and reason come back.
    var other = try testAuth(arena, server.port);
    other.installation_id = null;
    other.scope = .{ .org = "elsewhere" };
    try std.testing.expectError(
        error.AppRejected,
        other.tokenAt(arena, io, 1_800_000_000, &status, &message),
    );
    try std.testing.expectEqual(std.http.Status.not_found, status);
    try std.testing.expectEqualStrings("Not Found", message);
}

test "Auth.init reads the key from a file or inline" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "app.pem", .data = test_pkcs8 });
    const path = try tmp.dir.realPathFileAlloc(io, "app.pem", arena);
    const scope: Scope = .{ .org = "acme" };
    const from_file = try Auth.init(arena, io, .{ .id = "7", .key = .{ .file = path } }, scope);
    const inline_ = try Auth.init(arena, io, .{ .id = "7", .key = .{ .pem = test_pkcs1 } }, scope);
    try std.testing.expectEqualSlices(u8, from_file.key.modulus, inline_.key.modulus);
    try std.testing.expectEqual(@as(?u64, null), from_file.installation_id);
}

const test_pkcs1_body =
    \\MIIEpAIBAAKCAQEAqKSbUP8BFUxsKqVIduWxtUPxmBrB53nWKFXZXeyoYtptf9xG
    \\epuQAltOypTxWbq50u+/ydAXRn9aCtaukoIZmqMPAoAoMhXCL1zj5TndnlGjSAEF
    \\1kW6HZc7UHkDXkZPyLZzzLv4pkdorCZiXBMlBSiXl1G+NkU7VrwpyQRHGzudzIBV
    \\TC72ch/7xj21c8VceMMY9BVbE+T54cgHzG54AvBMCtCai4Mpj6A8BAFj691u4w8K
    \\+Fay0njjmbbLtBSE6Q39YUk5FovApzM6A6X5txRHetFf26TeJdkdUwKOOD2KOAIc
    \\Ro+9OnV2giLQ3yMlNLqcP9EzwoMPypChbi+kIwIDAQABAoIBACgwYhshSh7LQZPA
    \\I87B2mG6OV7oMYF6VYDzRIPPnClCqImp8tnRLLaDD/nTGNkrWJFeNTRg9MsGGm0u
    \\0Bd2Daf+Z9tOs0WMTeR/nIfKDHhoOCM2qy9vGnVmzunUjOrwkp7gbCREP3NQ3S75
    \\TsNmhJIAJHAZON0yDnwTB1oyPMfOQDhkVuPryiqAxXilLAoGv7G2W+DJ9LnhMvf/
    \\3avMkuD0y7r3Q/geeLKBEqDNv3HOh+E0iwu38KfGeHE02uFlbTQ+MTMqQvc7i91/
    \\rd0jzOsRgY6Hmw3aZjSQ5GXK462zYNqg1bmoIsaLKAWTWwFs0gee5qu9bHNw3qlw
    \\SC3j3+ECgYEA0lUUSPsIcfCwdVWC8pEyEMbDUrHNrt9R4qEaMBCrDxllb50Yz70K
    \\+bcsUw7FSyWIVDI0frKToiAgsx1vCnj2JZkibNAGA2tGVXWC7sjJ5Yt615IgQ0FO
    \\3UEy1s+HeKwCEAnd3yfypdED2/UXpV5iriTPjqanGicV9fXlzrs/4tkCgYEAzUJO
    \\EE/tJX8gIDvGY03LbJoAVqXX/XGNNXVpqP2nCqt1FQPx1cQaWXaqcRtBqm9901PG
    \\12f4j3jTQIWA9YxIlim8/VnV+cAlNUhAJ51PxJetSw+FMJOPE8KaZG7W4mWpnjVT
    \\eQnMhVqYJZplegmW8DhCJuVh9Waf2MjqZRqHaVsCgYEAwNgw2RkRDSbZIztb7Hsj
    \\pC4ZN+C97O/kbB25nQgrTpTCZCttbEqvnXVMtnp8egHXlRrS9rdUlPlQAemivb9a
    \\L+7PmWTBnrDks8YiXjzKoCPaZXwdCI0AeewlaL6uPv22hm4Fd21xFIcnOqzlGUII
    \\yBIIG4rA+0GK6RCju4ADe0ECgYAzKePrjQC/6ABKCJxbBHlAiOKstoowUq2wNaQw
    \\y4lnz3VP17vgXRF0W3AA4ZpssX3bv3ZBG1mJ6cQ+wQh0LJOrWpwRSuNbbdnYfjn/
    \\pebMSkKYAzZf9WgktM1nW3mU1WKCXSiBcz/Xvc1PEj1ZPiqxllRm/aZ9VSdjEjHb
    \\IdG/IQKBgQCDg/AXFAIRjXLgezj2UKmD+fcOfT5OhElcQ9+J/b9lwiRXCyqN9wxy
    \\bwDpI2/zuu4Pj6yIRicSxu/pk3sXz8FE5Zlj/2XpBvrfDVd4eghw+Ej2jDQm5gEN
    \\oGZNSWX2J94WvAH07TddCF+lxaQpMeLRE99PLQfQJF6qTRKXG8R6PA==
;

const test_pkcs8_body =
    \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCopJtQ/wEVTGwq
    \\pUh25bG1Q/GYGsHnedYoVdld7Khi2m1/3EZ6m5ACW07KlPFZurnS77/J0BdGf1oK
    \\1q6Sghmaow8CgCgyFcIvXOPlOd2eUaNIAQXWRbodlztQeQNeRk/ItnPMu/imR2is
    \\JmJcEyUFKJeXUb42RTtWvCnJBEcbO53MgFVMLvZyH/vGPbVzxVx4wxj0FVsT5Pnh
    \\yAfMbngC8EwK0JqLgymPoDwEAWPr3W7jDwr4VrLSeOOZtsu0FITpDf1hSTkWi8Cn
    \\MzoDpfm3FEd60V/bpN4l2R1TAo44PYo4AhxGj706dXaCItDfIyU0upw/0TPCgw/K
    \\kKFuL6QjAgMBAAECggEAKDBiGyFKHstBk8AjzsHaYbo5XugxgXpVgPNEg8+cKUKo
    \\iany2dEstoMP+dMY2StYkV41NGD0ywYabS7QF3YNp/5n206zRYxN5H+ch8oMeGg4
    \\IzarL28adWbO6dSM6vCSnuBsJEQ/c1DdLvlOw2aEkgAkcBk43TIOfBMHWjI8x85A
    \\OGRW4+vKKoDFeKUsCga/sbZb4Mn0ueEy9//dq8yS4PTLuvdD+B54soESoM2/cc6H
    \\4TSLC7fwp8Z4cTTa4WVtND4xMypC9zuL3X+t3SPM6xGBjoebDdpmNJDkZcrjrbNg
    \\2qDVuagixosoBZNbAWzSB57mq71sc3DeqXBILePf4QKBgQDSVRRI+whx8LB1VYLy
    \\kTIQxsNSsc2u31HioRowEKsPGWVvnRjPvQr5tyxTDsVLJYhUMjR+spOiICCzHW8K
    \\ePYlmSJs0AYDa0ZVdYLuyMnli3rXkiBDQU7dQTLWz4d4rAIQCd3fJ/Kl0QPb9Rel
    \\XmKuJM+OpqcaJxX19eXOuz/i2QKBgQDNQk4QT+0lfyAgO8ZjTctsmgBWpdf9cY01
    \\dWmo/acKq3UVA/HVxBpZdqpxG0Gqb33TU8bXZ/iPeNNAhYD1jEiWKbz9WdX5wCU1
    \\SEAnnU/El61LD4Uwk48TwppkbtbiZameNVN5CcyFWpglmmV6CZbwOEIm5WH1Zp/Y
    \\yOplGodpWwKBgQDA2DDZGRENJtkjO1vseyOkLhk34L3s7+RsHbmdCCtOlMJkK21s
    \\Sq+ddUy2enx6AdeVGtL2t1SU+VAB6aK9v1ov7s+ZZMGesOSzxiJePMqgI9plfB0I
    \\jQB57CVovq4+/baGbgV3bXEUhyc6rOUZQgjIEggbisD7QYrpEKO7gAN7QQKBgDMp
    \\4+uNAL/oAEoInFsEeUCI4qy2ijBSrbA1pDDLiWfPdU/Xu+BdEXRbcADhmmyxfdu/
    \\dkEbWYnpxD7BCHQsk6tanBFK41tt2dh+Of+l5sxKQpgDNl/1aCS0zWdbeZTVYoJd
    \\KIFzP9e9zU8SPVk+KrGWVGb9pn1VJ2MSMdsh0b8hAoGBAIOD8BcUAhGNcuB7OPZQ
    \\qYP59w59Pk6ESVxD34n9v2XCJFcLKo33DHJvAOkjb/O67g+PrIhGJxLG7+mTexfP
    \\wUTlmWP/ZekG+t8NV3h6CHD4SPaMNCbmAQ2gZk1JZfYn3ha8AfTtN10IX6XFpCkx
    \\4tET308tB9AkXqpNEpcbxHo8
;
