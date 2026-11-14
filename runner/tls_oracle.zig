//! The old TLS client as an oracle for the new one (docs/rust-net.md, "The old TLS client as an
//! oracle"): the database client before the move to rustls (`tools/tls_oracle/pg_old.zig`, on
//! tls.zig) and the one the runner has (`src/pg.zig`, on the network library) connect to the same
//! servers, case by case, and the test compares what each does: the handshake's outcome, the
//! results of the same statements, and the class of the errors.
//!
//! The servers are the Postgres of the Database tests job (the TLS oracle job starts the same one), which `pg-tls-fixture.sh` makes serve
//! TLS (private CA, client certificates), and, for the certificates Postgres does not have, a TLS
//! endpoint of the test's own: it answers the SSLRequest with `S` and hands the socket to
//! `openssl s_server -inetd`, so the client's TLS meets a real TLS server with the certificate the
//! case names. What follows the handshake is not Postgres, so those cases compare how far each
//! client got: a handshake the client refuses (`tls_failed`) or one it finished (`after_tls`).
//!
//! Where the two clients are meant to differ, the case says so (`why`), and both outcomes are
//! written down: a test that finds either client doing something else fails, so neither can drift
//! unnoticed, and a difference with no `why` fails too. Run by `zig build test-tls-oracle
//! -Dtls-oracle` (which fetches tls.zig; no other build does) where the Database fixture is: it
//! skips itself without `ZIG_TEST_PG_TLS_DIR`, and fails there when `ZIG_TEST_REQUIRE_DB` is set.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const new = @import("src/pg.zig");
const old = @import("tools/tls_oracle/pg_old.zig");
const dbtest = @import("src/dbtest.zig");

/// How far a client got, which is all two clients' errors have in common.
const Outcome = enum {
    /// Connected, and a statement ran.
    connected,
    /// The TLS handshake did not complete (`error.TlsFailed`).
    tls_failed,
    /// The connection ended (`error.ConnectionClosed`): the server hung up, or its alert is how
    /// the client learns of a refusal.
    closed,
    /// Past the handshake, then refused by the server (its error).
    after_tls,
};

const Server = union(enum) {
    /// The fixture's Postgres.
    postgres,
    /// `openssl s_server` with this certificate and key (files of the fixture's directory), and
    /// extra arguments for it.
    tls: struct { cert: []const u8, key: []const u8, args: []const []const u8 = &.{} },
    /// Answers the SSLRequest, then says something that is not TLS and hangs up.
    garbage,
    /// Answers the SSLRequest, then hangs up.
    hangup,
};

const Case = struct {
    name: []const u8,
    server: Server = .postgres,
    host: []const u8 = "127.0.0.1",
    user: []const u8 = "postgres",
    verify: bool = true,
    /// Roots (a file of the fixture's directory; "" the system's), client certificate and key (new only).
    root: []const u8 = "ca.pem",
    cert: []const u8 = "",
    key: []const u8 = "",
    /// What each client does. Several: either is acceptable (the server's alert reaches the client
    /// as a failed handshake or as the connection ending).
    old: []const Outcome = &.{.connected},
    new: []const Outcome = &.{.connected},
    /// An intended difference, and why. Required when the two lists above differ.
    why: []const u8 = "",
};

const cases = [_]Case{
    .{ .name = "Postgres, a private CA's certificate, verified" },
    .{ .name = "Postgres, no-verify", .verify = false, .root = "" },
    .{ .name = "Postgres, a CA nobody trusts", .root = "other-ca.pem", .old = &.{.tls_failed}, .new = &.{.tls_failed} },
    .{ .name = "Postgres, the system's roots only", .root = "", .old = &.{.tls_failed}, .new = &.{.tls_failed} },
    .{
        .name = "Postgres, a client certificate (the user comes in only by it)",
        .user = "pgecdsa",
        .cert = "client-ecdsa.pem",
        .key = "client-ecdsa-key.pem",
        .old = &.{.after_tls},
        .new = &.{.connected},
        .why = "the old client had no client certificates: it answered a CertificateRequest with an empty Certificate, and the server refused the user",
    },
    .{
        .name = "Postgres, a certificate-only user and no certificate",
        .user = "pgrsa",
        .old = &.{.after_tls},
        .new = &.{ .after_tls, .closed },
    },
    .{ .name = "a server certificate for the name, in a subjectAltName, TLS 1.3", .server = .{ .tls = .{ .cert = "server.pem", .key = "server-key.pem" } }, .old = &.{.after_tls}, .new = &.{.after_tls} },
    .{ .name = "the same, TLS 1.2 only", .server = .{ .tls = .{ .cert = "server.pem", .key = "server-key.pem", .args = &.{"-tls1_2"} } }, .old = &.{.after_tls}, .new = &.{.after_tls} },
    .{
        .name = "a CA certificate as the server's own",
        .server = .{ .tls = .{ .cert = "ca-leaf.pem", .key = "ca-leaf-key.pem" } },
        .old = &.{.after_tls},
        .new = &.{.tls_failed},
        .why = "rustls refuses a certificate that may sign others (basicConstraints CA:TRUE) as the server's own; the old client accepted it",
    },
    .{
        .name = "the name only in the subject (no subjectAltName)",
        .server = .{ .tls = .{ .cert = "subject-only.pem", .key = "subject-only-key.pem" } },
        .host = "localhost",
        .old = &.{.after_tls},
        .new = &.{.tls_failed},
        .why = "RFC 6125 and rustls check subjectAltName only; the old client fell back to the subject's common name",
    },
    .{ .name = "a server that answers the SSLRequest and then speaks plain text", .server = .garbage, .root = "", .old = &.{.tls_failed}, .new = &.{.tls_failed} },
    .{
        .name = "a server that answers the SSLRequest and hangs up",
        .server = .hangup,
        .root = "",
        .old = &.{.tls_failed},
        .new = &.{.closed},
        .why = "both fail; the library says the connection ended (the peer closed during the handshake), tls.zig that the handshake failed",
    },
};

fn dirFile(arena: Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    return if (name.len == 0) "" else std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
}

/// A TLS endpoint of the test's own: answers the SSLRequest, then is a proxy to an `openssl
/// s_server` on a Unix socket (which has no Postgres in front of it), one connection per client
/// the case runs.
const Endpoint = struct {
    listener: Io.net.Server,
    port: u16,
    sock: []const u8 = "",
    child: ?std.process.Child = null,

    fn start(io: Io, arena: Allocator, dir: []const u8, server: Server) !Endpoint {
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        const l = try addr.listen(io, .{ .reuse_address = true });
        var e: Endpoint = .{ .listener = l, .port = l.socket.address.getPort() };
        if (server == .tls) {
            const t = server.tls;
            e.sock = try std.fmt.allocPrint(arena, "/tmp/tls-oracle-{d}.sock", .{e.port});
            var argv: std.ArrayList([]const u8) = .empty;
            try argv.appendSlice(arena, &.{ "openssl", "s_server", "-unix", e.sock, "-unlink", "-quiet", "-ign_eof" });
            try argv.appendSlice(arena, &.{ "-cert", try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, t.cert }) });
            try argv.appendSlice(arena, &.{ "-key", try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, t.key }) });
            try argv.appendSlice(arena, t.args);
            e.child = try std.process.spawn(io, .{ .argv = argv.items, .stdin = .pipe, .stdout = .ignore, .stderr = .inherit });
        }
        return e;
    }

    fn stop(e: *Endpoint, io: Io) void {
        if (e.child) |*c| c.kill(io);
        if (e.sock.len > 0) Io.Dir.cwd().deleteFile(io, e.sock) catch {};
        e.listener.deinit(io);
    }

    /// Serves `connections` connections of `server`, one after another.
    fn serve(e: *Endpoint, io: Io, server: Server, connections: usize) void {
        for (0..connections) |_| e.serveOne(io, server) catch return;
    }

    fn serveOne(e: *Endpoint, io: Io, server: Server) !void {
        const stream = try e.listener.accept(io);
        defer stream.close(io);
        var rbuf: [16 * 1024]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        // The SSLRequest: length 8, code 80877103.
        try r.interface.discardAll(8);
        var wbuf: [64]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        try w.interface.writeByte('S');
        try w.interface.flush();
        switch (server) {
            .postgres => unreachable,
            .hangup => {},
            .garbage => {
                try w.interface.writeAll("this is not a TLS server\r\n");
                try w.interface.flush();
            },
            .tls => {
                // s_server is starting: its socket appears a moment after the process.
                const ua = try Io.net.UnixAddress.init(e.sock);
                const up = for (0..200) |_| {
                    if (ua.connect(io)) |u| break u else |_| try io.sleep(.fromMilliseconds(25), .awake);
                } else return error.ConnectionRefused;
                defer up.close(io);
                const back = try std.Thread.spawn(.{}, pump, .{ io, stream, up });
                // What the client has buffered goes first (nothing yet: it waits for the answer).
                pump(io, up, stream);
                back.join();
            },
        }
    }
};

/// Everything `from` says goes to `to`, until `from` ends; then `to` is told.
fn pump(io: Io, from: Io.net.Stream, to: Io.net.Stream) void {
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var r = from.reader(io, &rbuf);
    var w = to.writer(io, &wbuf);
    while (true) {
        const data = r.interface.peekGreedy(1) catch break;
        w.interface.writeAll(data) catch break;
        r.interface.toss(data.len);
        w.interface.flush() catch break;
    }
    to.shutdown(io, .send) catch {};
}

fn attempt(comptime P: type, io: Io, cfg: P.Config) Outcome {
    const c = P.Client.connect(std.testing.allocator, io, cfg) catch |e| return switch (e) {
        error.TlsFailed => .tls_failed,
        error.ConnectionClosed => .closed,
        else => .after_tls,
    };
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const rows = c.query(arena_state.allocator(), "select 1") catch return .closed;
    return if (rows.len == 1) .connected else .after_tls;
}

fn configOf(comptime P: type, c: Case, base: new.Config, port: u16, dir: []const u8, arena: Allocator) !P.Config {
    var cfg: P.Config = .{
        .host = c.host,
        .port = port,
        .user = c.user,
        .password = if (std.mem.eql(u8, c.user, "postgres")) base.password else "",
        .database = base.database,
        .sslmode = if (c.verify) .require else .no_verify,
        .sslrootcert = try dirFile(arena, dir, c.root),
        .connect_timeout = .fromSeconds(15),
        .query_timeout = .fromSeconds(15),
    };
    if (@hasField(P.Config, "sslcert")) {
        cfg.sslcert = try dirFile(arena, dir, c.cert);
        cfg.sslkey = try dirFile(arena, dir, c.key);
    }
    return cfg;
}

fn allowed(list: []const Outcome, got: Outcome) bool {
    return std.mem.indexOfScalar(Outcome, list, got) != null;
}

test "tls oracle: the old and the new client reach the same servers, and differ where the cases say" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const dir = env.get("ZIG_TEST_PG_TLS_DIR") orelse return dbtest.unavailable(&env);
    const base = (try new.fromEnv(&env)) orelse return dbtest.unavailable(&env);

    var wrong: usize = 0;
    std.debug.print("\n{s:<64} {s:<12} {s:<12}\n", .{ "case", "old", "new" });
    for (cases) |c| {
        var port = base.port;
        var endpoint: Endpoint = undefined;
        var serving: ?Io.Future(void) = null;
        if (c.server != .postgres) {
            endpoint = try Endpoint.start(io, arena, dir, c.server);
            port = endpoint.port;
            serving = try io.concurrent(Endpoint.serve, .{ &endpoint, io, c.server, @as(usize, 2) });
        }
        const got_old = attempt(old, io, try configOf(old, c, base, port, dir, arena));
        const got_new = attempt(new, io, try configOf(new, c, base, port, dir, arena));
        if (serving) |*s| {
            s.cancel(io);
            endpoint.stop(io);
        }
        const as_expected = allowed(c.old, got_old) and allowed(c.new, got_new);
        // A difference is only intended where the case says why.
        const differs = for (c.old) |o| {
            if (allowed(c.new, o)) break false;
        } else true;
        const explained = !differs or c.why.len > 0;
        std.debug.print("{s:<64} {s:<12} {s:<12}{s}\n", .{ c.name, @tagName(got_old), @tagName(got_new), if (!as_expected) "  UNEXPECTED" else if (differs) "  (intended difference)" else "" });
        if (differs and c.why.len > 0) std.debug.print("    why: {s}\n", .{c.why});
        if (!as_expected or !explained) wrong += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), wrong);
}

/// The statements both clients run over TLS to the fixture's Postgres: their results, and the
/// class and text of the server's errors, as one text.
fn transcript(comptime P: type, io: Io, cfg: P.Config, out: *std.Io.Writer.Allocating) !void {
    const gpa = std.testing.allocator;
    const c = try P.Client.connect(gpa, io, cfg);
    defer c.close();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const w = &out.writer;

    const who = try c.query(arena, "select current_user, ssl::text from pg_stat_ssl where pid = pg_backend_pid()");
    try w.print("who: {s} ssl={s}\n", .{ who[0][0].?, who[0][1].? });
    // Many small rows, hashed, with some NULLs and non-ASCII text.
    const many = try c.query(arena, "select i::text, md5(i::text), case when i % 7 = 0 then null else repeat('é', i % 50) end from generate_series(1, 20000) i");
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (many) |row| for (row) |field| {
        hash.update(field orelse "\x00NULL");
        hash.update("\x1f");
    };
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    try w.print("rows: {d} sha256={x}\n", .{ many.len, &digest });
    // A result of 8 MiB in one field: many records each way.
    const big = try c.query(arena, "select repeat('x', 8 * 1024 * 1024)");
    try w.print("big: {d}\n", .{big[0][0].?.len});
    // The server's errors: same class and text, and the connection goes on.
    for ([_][]const u8{ "select 1/0", "select * from zig_oracle_no_such_table", "selec 1" }) |sql| {
        c.exec(sql) catch |e| try w.print("error {s}: {s}\n", .{ @errorName(e), c.last_error });
    }
    try w.print("after errors: {s}\n", .{(try c.query(arena, "select 2"))[0][0].?});
    // COPY in, 4 MiB through the records.
    try c.exec("create temp table zig_oracle_copy (line text)");
    var data: std.Io.Writer.Allocating = .init(arena);
    const filler: [1000]u8 = @splat('y');
    for (0..4096) |i| try data.writer.print("{d}-{s}\n", .{ i, &filler });
    try w.print("copy: {d} rows\n", .{try c.copyIn("copy zig_oracle_copy (line) from stdin", data.written())});
    try w.print("sum: {s}\n", .{(try c.query(arena, "select sum(length(line))::text from zig_oracle_copy"))[0][0].?});
}

test "tls oracle: the same statements give the same results and errors through both clients" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const dir = env.get("ZIG_TEST_PG_TLS_DIR") orelse return dbtest.unavailable(&env);
    const base = (try new.fromEnv(&env)) orelse return dbtest.unavailable(&env);

    // Verified against the private CA, and not verified: both ways the old client could connect.
    for ([_]Case{ cases[0], cases[1] }) |c| {
        var from_old: std.Io.Writer.Allocating = .init(arena);
        var from_new: std.Io.Writer.Allocating = .init(arena);
        try transcript(old, io, try configOf(old, c, base, base.port, dir, arena), &from_old);
        try transcript(new, io, try configOf(new, c, base, base.port, dir, arena), &from_new);
        try std.testing.expectEqualStrings(from_old.written(), from_new.written());
        // The text is the evidence in the log, once.
        std.debug.print("\n{s}:\n{s}", .{ c.name, from_new.written() });
    }
}
