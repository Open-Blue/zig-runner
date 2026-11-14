//! THE OLD CLIENT, as an oracle (docs/rust-net.md, "The old TLS client as an oracle"): `runner/src/pg.zig`
//! as it was before the database's TLS moved to rustls (main at 3516c49), on tls.zig, with its tests
//! removed and three edits: the import of `github/http.zig` is a path, `Config` has `sslrootcert`
//! (the roots the new client takes from the same field), and `startTls` loads it. Compiled only by
//! `zig build test-tls-oracle -Dtls-oracle`, which fetches tls.zig; nothing else imports it.
//!
//! A small PostgreSQL client: wire protocol v3 over TCP, optional TLS, SCRAM-SHA-256 / MD5 /
//! cleartext authentication, the simple query protocol and `COPY ... FROM STDIN`.
//!
//! Pure Zig on std, so the runner stays one static binary (SPEC §7) with no libpq. It is built for
//! one job: writing run state and log batches to Postgres/TimescaleDB (Tiger Data). It is not a
//! general driver: no extended protocol, no prepared statements, no binary formats.
//!
//! Values are inserted with `quote()`d literals (standard_conforming_strings is on by default, so a
//! backslash is an ordinary character and only `'` needs doubling) or sent through COPY's text
//! format.
const std = @import("std");

const Allocator = std.mem.Allocator;
/// Not std's TLS client: it fails when the server asks for a client certificate (a TLS 1.3
/// CertificateRequest), which Tiger Data and any Postgres configured with a CA file do. This one
/// answers with an empty Certificate message, as RFC 8446 §4.4.2 says a client without one does.
const tls = @import("tls");
const http = @import("../../src/github/http.zig");
const Io = std.Io;

/// PostgreSQL's port, when the URL or PGPORT names none.
pub const default_port = 5432;

pub const SslMode = enum {
    /// Plain TCP. For local development containers.
    disable,
    /// TLS, verifying the certificate chain against the system CAs and the host name (Tiger Data).
    require,
    /// TLS without verifying anything. Encrypts, but gives no protection against impostors.
    no_verify,
};

pub const Config = struct {
    host: []const u8,
    port: u16 = default_port,
    user: []const u8,
    password: []const u8 = "",
    database: []const u8,
    sslmode: SslMode = .require,
    /// Added for the oracle (the old client trusted the system's roots only): a PEM file of roots
    /// that replaces them, so that it can verify the fixture's private CA as the new client does.
    sslrootcert: []const u8 = "",
    application_name: []const u8 = "zig-actions-runner",
    /// How long connecting may take, through TLS and authentication, before it is given up
    /// (`error.Timeout`). A host that accepts and never answers, or a network that dropped the
    /// connection silently, held a connect for good, and the run-state writer held its lock
    /// through it, so the job's end waited behind it (#100).
    connect_timeout: Io.Duration = .fromSeconds(10),
    /// How long one statement may wait for its answer (`Client.query_timeout`).
    query_timeout: Io.Duration = .fromSeconds(30),
};

pub const ParseError = error{ InvalidUrl, InvalidSslMode, OutOfMemory };

/// `postgres://user:password@host:port/database?sslmode=require|disable|no-verify`. User and
/// password may be percent-encoded. A missing sslmode means `require`.
pub fn parseUrl(arena: Allocator, url: []const u8) ParseError!Config {
    var rest = url;
    inline for (.{ "postgresql://", "postgres://" }) |scheme| {
        if (std.mem.startsWith(u8, rest, scheme)) {
            rest = rest[scheme.len..];
            break;
        }
    } else return error.InvalidUrl;

    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        query = rest[q + 1 ..];
        rest = rest[0..q];
    }
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.InvalidUrl;
    const authority = rest[0..slash];
    const database = rest[slash + 1 ..];
    if (database.len == 0) return error.InvalidUrl;

    var user: []const u8 = "";
    var password: []const u8 = "";
    var hostport = authority;
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
        hostport = authority[at + 1 ..];
        const cred = authority[0..at];
        if (std.mem.indexOfScalar(u8, cred, ':')) |colon| {
            user = try percentDecode(arena, cred[0..colon]);
            password = try percentDecode(arena, cred[colon + 1 ..]);
        } else user = try percentDecode(arena, cred);
    }
    if (user.len == 0) return error.InvalidUrl;

    var host = hostport;
    var port: u16 = default_port;
    if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |colon| {
        host = hostport[0..colon];
        port = std.fmt.parseInt(u16, hostport[colon + 1 ..], 10) catch return error.InvalidUrl;
    }
    if (host.len == 0) return error.InvalidUrl;

    var cfg: Config = .{
        .host = host,
        .port = port,
        .user = user,
        .password = password,
        .database = try percentDecode(arena, database),
    };
    var params = std.mem.splitScalar(u8, query, '&');
    while (params.next()) |p| {
        const eq = std.mem.indexOfScalar(u8, p, '=') orelse continue;
        if (std.mem.eql(u8, p[0..eq], "sslmode")) cfg.sslmode = try parseSslMode(p[eq + 1 ..]);
    }
    return cfg;
}

pub fn parseSslMode(s: []const u8) ParseError!SslMode {
    if (std.mem.eql(u8, s, "disable")) return .disable;
    if (std.mem.eql(u8, s, "require") or std.mem.eql(u8, s, "verify-full") or
        std.mem.eql(u8, s, "verify-ca")) return .require;
    if (std.mem.eql(u8, s, "no-verify")) return .no_verify;
    return error.InvalidSslMode;
}

/// The standard libpq variables: PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE, PGSSLMODE.
/// Returns null unless at least host, user and database are set.
pub fn fromEnv(env: *const std.process.Environ.Map) ParseError!?Config {
    const host = env.get("PGHOST") orelse return null;
    const user = env.get("PGUSER") orelse return null;
    const database = env.get("PGDATABASE") orelse return null;
    return .{
        .host = host,
        .port = if (env.get("PGPORT")) |p| std.fmt.parseInt(u16, p, 10) catch
            return error.InvalidUrl else default_port,
        .user = user,
        .password = env.get("PGPASSWORD") orelse "",
        .database = database,
        .sslmode = if (env.get("PGSSLMODE")) |m| try parseSslMode(m) else .require,
    };
}

fn percentDecode(arena: Allocator, s: []const u8) ParseError![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '%') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%') {
            if (i + 3 > s.len) return error.InvalidUrl;
            const v = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return error.InvalidUrl;
            try out.append(arena, v);
            i += 2;
        } else try out.append(arena, s[i]);
    }
    return out.items;
}

/// A SQL string literal: single-quoted with `'` doubled. NUL bytes (which Postgres text cannot
/// hold) and invalid UTF-8 are replaced with U+FFFD. Safe only with standard_conforming_strings =
/// on.
pub fn quote(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    try w.writeByte('\'');
    try writeSanitized(w, s, .quote);
    try w.writeByte('\'');
}

const Escape = enum { quote, copy };

/// Writes `s` as valid UTF-8 (bad bytes and NUL become U+FFFD) with the escapes of the given
/// context.
fn writeSanitized(w: *Io.Writer, s: []const u8, mode: Escape) Io.Writer.Error!void {
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c < 0x80) {
            i += 1;
            switch (mode) {
                .quote => switch (c) {
                    '\'' => try w.writeAll("''"),
                    0 => try w.writeAll("\u{FFFD}"),
                    else => try w.writeByte(c),
                },
                .copy => switch (c) {
                    0 => try w.writeAll("\u{FFFD}"),
                    '\\' => try w.writeAll("\\\\"),
                    '\n' => try w.writeAll("\\n"),
                    '\r' => try w.writeAll("\\r"),
                    '\t' => try w.writeAll("\\t"),
                    else => try w.writeByte(c),
                },
            }
            continue;
        }
        const n = std.unicode.utf8ByteSequenceLength(c) catch {
            try w.writeAll("\u{FFFD}");
            i += 1;
            continue;
        };
        if (i + n <= s.len and std.unicode.utf8ValidateSlice(s[i .. i + n])) {
            try w.writeAll(s[i .. i + n]);
            i += n;
        } else {
            try w.writeAll("\u{FFFD}");
            i += 1;
        }
    }
}

/// A field of a COPY text-format row (escapes tab, newline, carriage return and backslash).
pub fn copyField(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    try writeSanitized(w, s, .copy);
}

// --- messages ---

/// What went wrong on the server side (ErrorResponse fields S, C, M).
pub const ServerError = struct {
    severity: []const u8 = "",
    code: []const u8 = "",
    message: []const u8 = "",
};

pub fn parseErrorFields(body: []const u8) ServerError {
    var e: ServerError = .{};
    var i: usize = 0;
    while (i < body.len and body[i] != 0) {
        const tag = body[i];
        const end = std.mem.indexOfScalarPos(u8, body, i + 1, 0) orelse body.len;
        const val = body[i + 1 .. end];
        switch (tag) {
            'S' => e.severity = val,
            'C' => e.code = val,
            'M' => e.message = val,
            else => {},
        }
        i = end + 1;
    }
    return e;
}

/// A DataRow body: int16 column count, then each column as int32 length (-1 = NULL) and bytes.
pub fn parseDataRow(
    arena: Allocator,
    body: []const u8,
) (error{BadMessage} || Allocator.Error)![]const ?[]const u8 {
    if (body.len < 2) return error.BadMessage;
    const n = std.mem.readInt(u16, body[0..2], .big);
    const cols = try arena.alloc(?[]const u8, n);
    var i: usize = 2;
    for (cols) |*c| {
        if (i + 4 > body.len) return error.BadMessage;
        const len = std.mem.readInt(i32, body[i..][0..4], .big);
        i += 4;
        if (len < 0) {
            c.* = null;
            continue;
        }
        const l: usize = @intCast(len);
        if (i + l > body.len) return error.BadMessage;
        c.* = body[i .. i + l];
        i += l;
    }
    return cols;
}

// --- SCRAM-SHA-256 (RFC 5802 / 7677) ---

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Scram = struct {
    client_nonce: []const u8,
    /// `n=<user>,r=<nonce>`
    client_first_bare: []const u8,

    /// `username` is the SCRAM user name. PostgreSQL ignores it (it uses the startup user), so the
    /// client passes it empty.
    pub fn init(
        arena: Allocator,
        username: []const u8,
        client_nonce: []const u8,
    ) Allocator.Error!Scram {
        return .{
            .client_nonce = client_nonce,
            .client_first_bare = try std.fmt.allocPrint(
                arena,
                "n={s},r={s}",
                .{ username, client_nonce },
            ),
        };
    }

    /// The initial response: GS2 header (no channel binding) plus the bare message.
    pub fn clientFirst(s: Scram, arena: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(arena, "n,,{s}", .{s.client_first_bare});
    }

    pub const Final = struct {
        message: []const u8,
        /// What the server must answer with: `v=<signature>`.
        expected_server_final: []const u8,
    };

    pub const ScramError = error{
        BadServerFirst,
        BadNonce,
        BadSalt,
        BadIterations,
    } || Allocator.Error || error{ WeakParameters, OutputTooLong };

    pub fn clientFinal(
        s: Scram,
        arena: Allocator,
        password: []const u8,
        server_first: []const u8,
    ) ScramError!Final {
        var nonce: ?[]const u8 = null;
        var salt_b64: ?[]const u8 = null;
        var iterations: ?u32 = null;
        var parts = std.mem.splitScalar(u8, server_first, ',');
        while (parts.next()) |p| {
            if (p.len < 2 or p[1] != '=') continue;
            switch (p[0]) {
                'r' => nonce = p[2..],
                's' => salt_b64 = p[2..],
                'i' => iterations = std.fmt.parseInt(u32, p[2..], 10) catch
                    return error.BadIterations,
                else => {},
            }
        }
        const combined = nonce orelse return error.BadServerFirst;
        if (!std.mem.startsWith(u8, combined, s.client_nonce)) return error.BadNonce;
        const salt_text = salt_b64 orelse return error.BadServerFirst;
        const iters = iterations orelse return error.BadServerFirst;

        const dec = std.base64.standard.Decoder;
        const salt = try arena.alloc(u8, dec.calcSizeForSlice(salt_text) catch
            return error.BadSalt);
        dec.decode(salt, salt_text) catch return error.BadSalt;

        var salted: [32]u8 = undefined;
        try std.crypto.pwhash.pbkdf2(&salted, password, salt, iters, Hmac);

        var client_key: [32]u8 = undefined;
        Hmac.create(&client_key, "Client Key", &salted);
        var stored_key: [32]u8 = undefined;
        Sha256.hash(&client_key, &stored_key, .{});

        const without_proof = try std.fmt.allocPrint(arena, "c=biws,r={s}", .{combined});
        const auth_message = try std.fmt.allocPrint(
            arena,
            "{s},{s},{s}",
            .{ s.client_first_bare, server_first, without_proof },
        );

        var client_sig: [32]u8 = undefined;
        Hmac.create(&client_sig, auth_message, &stored_key);
        var proof: [32]u8 = undefined;
        for (&proof, client_key, client_sig) |*p, a, b| p.* = a ^ b;

        var server_key: [32]u8 = undefined;
        Hmac.create(&server_key, "Server Key", &salted);
        var server_sig: [32]u8 = undefined;
        Hmac.create(&server_sig, auth_message, &server_key);

        const enc = std.base64.standard.Encoder;
        const proof_b64 = try arena.alloc(u8, enc.calcSize(proof.len));
        _ = enc.encode(proof_b64, &proof);
        const sig_b64 = try arena.alloc(u8, enc.calcSize(server_sig.len));
        _ = enc.encode(sig_b64, &server_sig);
        return .{
            .message = try std.fmt.allocPrint(arena, "{s},p={s}", .{ without_proof, proof_b64 }),
            .expected_server_final = try std.fmt.allocPrint(arena, "v={s}", .{sig_b64}),
        };
    }
};

// --- the client ---

pub const Error = error{
    /// The server answered with an ErrorResponse; see `Client.last_error`.
    ServerError,
    UnexpectedMessage,
    BadMessage,
    AuthenticationFailed,
    UnsupportedAuthentication,
    TlsRefused,
    TlsFailed,
    ConnectionClosed,
    /// No answer within `Config.query_timeout`. The connection is then in the middle of a
    /// statement and cannot be used again: the caller closes it.
    Timeout,
    Canceled,
    OutOfMemory,
};

pub const Client = struct {
    gpa: Allocator,
    io: Io,
    stream: Io.net.Stream,
    stream_reader: Io.net.Stream.Reader,
    stream_writer: Io.net.Stream.Writer,
    tls: ?tls.Connection = null,
    tls_reader: tls.Connection.Reader = undefined,
    tls_writer: tls.Connection.Writer = undefined,
    r: *Io.Reader,
    w: *Io.Writer,
    buffers: []u8,
    ca_bundle: std.crypto.Certificate.Bundle = .empty,
    /// "ERROR 42P01: relation ... does not exist": the last ErrorResponse from the server.
    last_error: []const u8 = "",
    error_buf: [512]u8 = undefined,
    /// How long `query`, `exec` and `copyIn` wait for the server (`Config.query_timeout`).
    /// Keepalive and `TCP_USER_TIMEOUT` notice a host that went away, not one that is there and
    /// never answers.
    query_timeout: Io.Duration,

    const plain_buf_len = 16 * 1024;

    /// Connects within `cfg.connect_timeout` (`error.Timeout`): it runs next to a timer, and
    /// whichever ends first cancels the other, which interrupts a blocked connect, read or write.
    /// std's own connect timeout is not implemented yet, and `SO_RCVTIMEO` would make a read end
    /// in `EAGAIN`, which std treats as a bug.
    pub fn connect(gpa: Allocator, io: Io, cfg: Config) anyerror!*Client {
        const r = try http.withinClosing(
            io,
            cfg.connect_timeout,
            connectUnbounded,
            .{ gpa, io, cfg },
            {},
            closeLate,
        ) orelse return error.Timeout;
        return r;
    }

    /// A connection made just as the time ran out is closed.
    fn closeLate(_: void, made: anyerror!*Client) void {
        if (made) |c| c.close() else |_| {}
    }

    fn connectUnbounded(gpa: Allocator, io: Io, cfg: Config) anyerror!*Client {
        const host: Io.net.HostName = try .init(cfg.host);
        const stream = try host.connect(io, cfg.port, .{ .mode = .stream });
        errdefer stream.close(io);
        // A database host that went away is then noticed (in about 90 s) by a query that is only
        // waiting for its answer, which would otherwise wait for good.
        http.keepAlive(stream.socket.handle);

        const sock_len = tls.input_buffer_len + tls.output_buffer_len;
        const buffers = try gpa.alloc(u8, sock_len + 2 * plain_buf_len);
        errdefer gpa.free(buffers);

        const c = try gpa.create(Client);
        errdefer gpa.destroy(c);
        // Socket-level buffers (ciphertext when TLS is on, sized for a whole record), then the TLS
        // plaintext buffers.
        const sock_r = buffers[0..tls.input_buffer_len];
        const sock_w = buffers[tls.input_buffer_len..sock_len];
        c.* = .{
            .gpa = gpa,
            .io = io,
            .stream = stream,
            .stream_reader = stream.reader(io, sock_r),
            .stream_writer = stream.writer(io, sock_w),
            .r = undefined,
            .w = undefined,
            .buffers = buffers,
            .query_timeout = cfg.query_timeout,
        };
        c.r = &c.stream_reader.interface;
        c.w = &c.stream_writer.interface;

        errdefer c.ca_bundle.deinit(gpa);
        if (cfg.sslmode != .disable) try c.startTls(cfg, buffers[sock_len..]);
        try c.startup(cfg);
        return c;
    }

    pub fn close(c: *Client) void {
        c.sendMessage('X', "") catch {};
        c.flush() catch {};
        if (c.tls) |*t| t.close() catch {};
        c.stream.close(c.io);
        c.ca_bundle.deinit(c.gpa);
        const gpa = c.gpa;
        gpa.free(c.buffers);
        gpa.destroy(c);
    }

    /// The SSLRequest code, in place of a protocol version: 1234 in the high 16 bits, 5679 below.
    const ssl_request_code = 80877103;
    /// Protocol 3.0, as the StartupMessage gives it: the major version in the high 16 bits.
    const protocol_version = 3 << 16;
    /// The most of a COPY's data one CopyData message carries.
    const copy_chunk_len = 64 * 1024;

    fn startTls(c: *Client, cfg: Config, plain: []u8) Error!void {
        // SSLRequest: int32 length 8, int32 code.
        c.w.writeInt(u32, 8, .big) catch return error.ConnectionClosed;
        c.w.writeInt(u32, ssl_request_code, .big) catch return error.ConnectionClosed;
        c.w.flush() catch return error.ConnectionClosed;
        const answer = c.r.takeByte() catch return error.ConnectionClosed;
        if (answer != 'S') return error.TlsRefused;

        const rng: std.Random.IoSource = .{ .io = c.io };
        const now = Io.Clock.real.now(c.io);
        const verify = cfg.sslmode == .require;
        if (!verify) {} else if (cfg.sslrootcert.len > 0)
            c.ca_bundle.addCertsFromFilePathAbsolute(c.gpa, c.io, now, cfg.sslrootcert) catch return error.TlsFailed
        else
            c.ca_bundle.rescan(c.gpa, c.io, now) catch return error.TlsFailed;
        c.tls = tls.client(c.r, c.w, .{
            .rng = rng.interface(),
            .now = now,
            .host = cfg.host,
            .root_ca = c.ca_bundle,
            .insecure_skip_verify = !verify,
        }) catch return error.TlsFailed;
        c.tls_reader = c.tls.?.reader(plain[0..plain_buf_len]);
        c.tls_writer = c.tls.?.writer(plain[plain_buf_len..]);
        c.r = &c.tls_reader.interface;
        c.w = &c.tls_writer.interface;
    }

    /// With TLS on, each record is written through to the socket as it is sealed.
    fn flush(c: *Client) Io.Writer.Error!void {
        try c.w.flush();
    }

    /// `tag` null is the untagged startup message.
    fn sendMessage(c: *Client, tag: ?u8, body: []const u8) Io.Writer.Error!void {
        if (tag) |t| try c.w.writeByte(t);
        try c.w.writeInt(u32, @intCast(body.len + 4), .big);
        try c.w.writeAll(body);
    }

    const Message = struct { tag: u8, body: []u8 };

    fn readMessage(c: *Client, arena: Allocator) Error!Message {
        const tag = c.r.takeByte() catch return error.ConnectionClosed;
        const len = c.r.takeInt(u32, .big) catch return error.ConnectionClosed;
        if (len < 4) return error.BadMessage;
        const body = try arena.alloc(u8, len - 4);
        c.r.readSliceAll(body) catch return error.ConnectionClosed;
        return .{ .tag = tag, .body = body };
    }

    fn remember(c: *Client, body: []const u8) void {
        const e = parseErrorFields(body);
        c.last_error = std.fmt.bufPrint(
            &c.error_buf,
            "{s} {s}: {s}",
            .{ e.severity, e.code, e.message },
        ) catch c.error_buf[0..0];
    }

    fn startup(c: *Client, cfg: Config) !void {
        var arena_state: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        try c.sendMessage(null, try startupMessage(arena, cfg));
        try c.flush();

        var auth: AuthState = .{};
        while (true) {
            const m = try c.readMessage(arena);
            switch (m.tag) {
                'R' => try c.authenticate(arena, cfg, m.body, &auth),
                'E' => {
                    c.remember(m.body);
                    return error.ServerError;
                },
                'Z' => return, // ReadyForQuery: connected
                else => {}, // ParameterStatus (S), BackendKeyData (K), NoticeResponse (N)
            }
        }
    }

    /// The StartupMessage: protocol 3.0 and the parameters the server needs, NUL-terminated pairs
    /// ending in an empty name.
    fn startupMessage(arena: std.mem.Allocator, cfg: Config) ![]const u8 {
        var body: std.Io.Writer.Allocating = .init(arena);
        try body.writer.writeInt(u32, protocol_version, .big);
        for ([_][2][]const u8{
            .{ "user", cfg.user },
            .{ "database", cfg.database },
            .{ "application_name", cfg.application_name },
            .{ "client_encoding", "UTF8" },
        }) |kv| {
            try body.writer.writeAll(kv[0]);
            try body.writer.writeByte(0);
            try body.writer.writeAll(kv[1]);
            try body.writer.writeByte(0);
        }
        try body.writer.writeByte(0);
        return body.written();
    }

    /// What SCRAM carries across the server's messages: the exchange, and the signature the server
    /// must end with.
    const AuthState = struct { scram: ?Scram = null, expected_final: ?[]const u8 = null };

    /// One Authentication message, by kind: Ok, cleartext, MD5, or the three SASL steps of
    /// SCRAM-SHA-256. Anything else the server could ask for is unsupported.
    fn authenticate(
        c: *Client,
        arena: std.mem.Allocator,
        cfg: Config,
        body: []const u8,
        auth: *AuthState,
    ) !void {
        if (body.len < 4) return error.BadMessage;
        const kind = std.mem.readInt(u32, body[0..4], .big);
        switch (kind) {
            0 => {}, // AuthenticationOk
            3 => { // cleartext
                try c.sendMessage('p', try std.fmt.allocPrint(arena, "{s}\x00", .{cfg.password}));
                try c.flush();
            },
            5 => { // MD5
                if (body.len < 8) return error.BadMessage;
                try c.sendMessage('p', try md5Password(arena, cfg, body[4..8]));
                try c.flush();
            },
            10 => { // SASL: pick SCRAM-SHA-256
                if (std.mem.indexOf(u8, body[4..], "SCRAM-SHA-256") == null)
                    return error.UnsupportedAuthentication;
                auth.scram = try c.saslFirst(arena);
            },
            11 => { // SASLContinue: server-first-message
                const s = auth.scram orelse return error.UnexpectedMessage;
                const fin = s.clientFinal(arena, cfg.password, body[4..]) catch
                    return error.AuthenticationFailed;
                try c.sendMessage('p', fin.message);
                try c.flush();
                auth.expected_final = fin.expected_server_final;
            },
            12 => { // SASLFinal: verify the server's signature
                const want = auth.expected_final orelse return error.UnexpectedMessage;
                if (!std.mem.eql(u8, body[4..], want)) return error.AuthenticationFailed;
            },
            else => return error.UnsupportedAuthentication,
        }
    }

    /// The MD5 password message: "md5" + md5(md5(password + user) + salt), NUL-terminated.
    fn md5Password(arena: std.mem.Allocator, cfg: Config, salt: []const u8) ![]const u8 {
        const hex = std.fmt.bytesToHex;
        var h1: [16]u8 = undefined;
        var md5 = std.crypto.hash.Md5.init(.{});
        md5.update(cfg.password);
        md5.update(cfg.user);
        md5.final(&h1);
        const h1_hex = hex(h1, .lower);
        var h2: [16]u8 = undefined;
        var md5b = std.crypto.hash.Md5.init(.{});
        md5b.update(&h1_hex);
        md5b.update(salt);
        md5b.final(&h2);
        const h2_hex = hex(h2, .lower);
        return std.fmt.allocPrint(arena, "md5{s}\x00", .{h2_hex});
    }

    /// Starts SCRAM-SHA-256: a fresh nonce, the client-first-message sent as SASLInitialResponse.
    fn saslFirst(c: *Client, arena: std.mem.Allocator) !Scram {
        var nonce_raw: [18]u8 = undefined;
        c.io.random(&nonce_raw);
        const enc = std.base64.standard.Encoder;
        const nonce = try arena.alloc(u8, enc.calcSize(nonce_raw.len));
        _ = enc.encode(nonce, &nonce_raw);
        const s = try Scram.init(arena, "", nonce);
        const first = try s.clientFirst(arena);
        var msg: std.Io.Writer.Allocating = .init(arena);
        try msg.writer.writeAll("SCRAM-SHA-256\x00");
        try msg.writer.writeInt(u32, @intCast(first.len), .big);
        try msg.writer.writeAll(first);
        try c.sendMessage('p', msg.written());
        try c.flush();
        return s;
    }

    /// Runs one or more statements, discarding any rows.
    pub fn exec(c: *Client, sql: []const u8) Error!void {
        var arena_state: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena_state.deinit();
        _ = try c.query(arena_state.allocator(), sql);
    }

    pub const Rows = []const []const ?[]const u8;

    /// Runs a statement and returns all rows of its last result as text. Rows live in `arena`.
    pub fn query(c: *Client, arena: Allocator, sql: []const u8) Error!Rows {
        return c.bounded(Rows, queryUnbounded, .{ c, arena, sql });
    }

    /// `function(args)` within `query_timeout`: `error.Timeout` when it ran out (see `Error`).
    fn bounded(c: *Client, comptime T: type, function: anytype, args: anytype) Error!T {
        const r = try http.within(c.io, c.query_timeout, function, args);
        return r orelse error.Timeout;
    }

    fn queryUnbounded(c: *Client, arena: Allocator, sql: []const u8) Error!Rows {
        try c.sendQuery(arena, sql);
        return c.readResults(arena);
    }

    /// A Query message: `sql`, NUL-terminated, sent at once.
    fn sendQuery(c: *Client, arena: Allocator, sql: []const u8) Error!void {
        var q: std.Io.Writer.Allocating = .init(arena);
        q.writer.writeAll(sql) catch return error.OutOfMemory;
        q.writer.writeByte(0) catch return error.OutOfMemory;
        c.sendMessage('Q', q.written()) catch return error.ConnectionClosed;
        c.flush() catch return error.ConnectionClosed;
    }

    fn readResults(c: *Client, arena: Allocator) Error!Rows {
        var rows: std.ArrayList([]const ?[]const u8) = .empty;
        var failed = false;
        while (true) {
            const m = try c.readMessage(arena);
            switch (m.tag) {
                'D' => rows.append(
                    arena,
                    parseDataRow(arena, m.body) catch return error.BadMessage,
                ) catch return error.OutOfMemory,
                'T' => rows.clearRetainingCapacity(), // a new result set starts
                'E' => {
                    c.remember(m.body);
                    // Keep reading until ReadyForQuery, so the connection stays usable.
                    failed = true;
                },
                'Z' => {
                    if (failed) return error.ServerError;
                    return rows.items;
                },
                else => {}, // CommandComplete (C), EmptyQueryResponse (I), NoticeResponse (N), ...
            }
        }
    }

    /// `sql` must be `COPY ... FROM STDIN` in text format. Returns the number of rows the server
    /// stored.
    pub fn copyIn(c: *Client, sql: []const u8, data: []const u8) Error!u64 {
        return c.bounded(u64, copyInUnbounded, .{ c, sql, data });
    }

    fn copyInUnbounded(c: *Client, sql: []const u8, data: []const u8) Error!u64 {
        var arena_state: std.heap.ArenaAllocator = .init(c.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        try c.sendQuery(arena, sql);

        // Wait for CopyInResponse ('G'); an error here means the statement was rejected.
        while (true) {
            const m = try c.readMessage(arena);
            switch (m.tag) {
                'G' => break,
                'E' => {
                    c.remember(m.body);
                    try c.drainToReady(arena);
                    return error.ServerError;
                },
                else => {},
            }
        }
        var off: usize = 0;
        while (off < data.len) {
            const n = @min(data.len - off, copy_chunk_len);
            c.sendMessage('d', data[off .. off + n]) catch return error.ConnectionClosed;
            off += n;
        }
        c.sendMessage('c', "") catch return error.ConnectionClosed;
        c.flush() catch return error.ConnectionClosed;

        var copied: u64 = 0;
        var failed = false;
        while (true) {
            const m = try c.readMessage(arena);
            switch (m.tag) {
                'C' => { // CommandComplete: "COPY <n>"
                    const tag = std.mem.sliceTo(m.body, 0);
                    if (std.mem.startsWith(u8, tag, "COPY "))
                        copied = std.fmt.parseInt(u64, tag[5..], 10) catch 0;
                },
                'E' => {
                    c.remember(m.body);
                    failed = true;
                },
                'Z' => {
                    if (failed) return error.ServerError;
                    return copied;
                },
                else => {},
            }
        }
    }

    fn drainToReady(c: *Client, arena: Allocator) Error!void {
        while (true) {
            const m = try c.readMessage(arena);
            if (m.tag == 'Z') return;
        }
    }
};

// --- tests ---
