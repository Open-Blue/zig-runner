//! What `loop.zig` and `loop/job.zig` both do on a cycle: say a line, fail the cycle with a report,
//! mint an access token and read a string out of a broker message.
const std = @import("std");
const auth = @import("../github/auth.zig");
const broker = @import("../github/broker.zig");
const redact = @import("../redact.zig");
const logfmt = @import("../logfmt.zig");
const Runner = @import("../loop.zig").Runner;
const Cycle = @import("../loop.zig").Cycle;

const Allocator = std.mem.Allocator;

/// Logs one line to the job's log, formatted in the cycle's arena.
pub fn say(c: Runner, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(c.arena, fmt, args);
    try c.log.say(text);
}

/// A warning or an error to the log, in `logfmt`'s format. On the stack, so it can be said when
/// the arena cannot grow; a line longer than the buffer is cut.
pub fn sayLine(c: Runner, comptime level: logfmt.Level, comptime kind: []const u8, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    c.log.say(logfmt.bufLine(&buf, level, kind, fmt, args)) catch |e| std.log.debug("log: {t}", .{e});
}

/// `text` with the job's secrets masked, in `buf` (cut if it does not fit), for a value of a line.
pub fn masked(c: Runner, buf: []u8, text: []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    redact.write(&w, text, c.secrets) catch {};
    return w.buffered();
}

/// A fresh access token for the runner's credentials (a JWT exchanged at the OAuth endpoint).
pub fn mintToken(c: Runner, creds: auth.Credentials, status: *std.http.Status) !([]const u8) {
    var jti: [8]u8 = undefined;
    c.io.random(&jti);
    const now = std.Io.Clock.real.now(c.io).toSeconds();
    const jwt = try auth.buildJwt(
        c.arena,
        creds,
        now,
        try std.fmt.allocPrint(c.arena, "{x}", .{jti}),
    );
    return auth.fetchAccessToken(c.arena, c.io, creds, jwt, status);
}

/// The string at `key` in the JSON object `body`, or null when it is not one. Running out of memory
/// is an error, not a missing key: read as one, a job request was ignored as a message of type ''.
pub fn jsonString(arena: Allocator, body: []const u8, key: []const u8) Allocator.Error!?[]const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (v != .object) return null;
    const s = v.object.get(key) orelse return null;
    return if (s == .string) s.string else null;
}

const github_failure: Cycle = .{ .failed = .{ .exit = .github } };

/// Reports a failed exchange to stderr (the error's name, redacted) and returns the cycle's ending.
pub fn fail(c: Runner, what: []const u8, e: anyerror) !Cycle {
    var buf: [128]u8 = undefined;
    try logfmt.line(c.err, .err, "exchange_failed", "what={f} err={f}", .{
        logfmt.q(what),
        logfmt.q(masked(c, &buf, @errorName(e))),
    });
    return github_failure;
}

/// `fail` for a failed token request, which also has the HTTP status.
pub fn failHttp(c: Runner, what: []const u8, e: anyerror, status: std.http.Status) !Cycle {
    try logfmt.line(c.err, .err, "exchange_failed", "what={f} err={t} http={d}", .{
        logfmt.q(what), e, @backingInt(status),
    });
    return github_failure;
}

/// `fail` for a response GitHub answered with a non-success status.
pub fn failBody(c: Runner, what: []const u8, r: broker.Response) !Cycle {
    // Error bodies are short JSON documents without credentials.
    try logfmt.line(c.err, .err, "exchange_failed", "what={f} http={d} body={f}", .{
        logfmt.q(what), @backingInt(r.status), logfmt.q(r.body[0..@min(r.body.len, 400)]),
    });
    return github_failure;
}
