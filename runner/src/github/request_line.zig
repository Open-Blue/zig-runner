//! One `request:` line per HTTP request the runner makes (docs/rust-net.md, R3), for finding where
//! time and rate limit go:
//!
//!   request: host=api.github.com method=GET path=/repos/o/r status=200 dns_ms=1.2 connect_ms=8.0
//!   tls_ms=20.5 ttfb_ms=61.0 total_ms=95.3 bytes_in=512 retry=0 reused=0 rl_remaining=4999
//!   rl_limit=5000 rl_reset=1700000000 rl_resource=core
//!
//! (on one line). The format, the path redaction and the rate-limit fields are those of the draft
//! pull request #530 (`github/request_log.zig`), which measures std's client by wrapping its Io
//! and so can only approximate the phases; the network library's figures are exact. When that
//! lands this file is the only one that stays: its `Line` is what both write, and the golden test
//! below pins the bytes. `key=value`, times in milliseconds to a tenth, `?` for a figure that could
//! not be read. Never a token, a query string or a body: the path is cut at its `?` and each
//! segment that could be a secret is replaced (`redactPath`). `RUNNER_LOG_REQUESTS=0` turns the
//! lines off.
const std = @import("std");
const builtin = @import("builtin");

/// Off in tests, which would print a line for every request; the tests that look at the lines
/// turn it on.
pub var enabled: std.atomic.Value(bool) = .init(!builtin.is_test);

/// Where a line goes in place of stderr, for tests.
pub var capture: ?*std.Io.Writer.Allocating = null;
var capture_lock: std.atomic.Mutex = .unlocked;

pub const Status = union(enum) {
    code: u16,
    /// The error that ended the request, by name.
    err: []const u8,
};

/// What one request measured. Times are nanoseconds; null is `?`.
pub const Line = struct {
    host: []const u8,
    method: []const u8,
    path: []const u8,
    status: Status,
    dns_ns: ?u64 = null,
    connect_ns: ?u64 = null,
    tls_ns: ?u64 = null,
    ttfb_ns: ?u64 = null,
    total_ns: u64,
    bytes_in: ?u64 = null,
    retry: u32 = 0,
    reused: ?bool = null,
    rl_remaining: ?u64 = null,
    rl_limit: ?u64 = null,
    rl_reset: ?u64 = null,
    rl_resource: []const u8 = "",

    pub fn write(l: Line, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("request: host={s} method={s} path={s} status=", .{ l.host, l.method, l.path });
        switch (l.status) {
            .code => |c| try w.print("{d}", .{c}),
            .err => |e| try w.writeAll(e),
        }
        for ([_]struct { []const u8, ?u64 }{
            .{ "dns_ms", l.dns_ns },
            .{ "connect_ms", l.connect_ns },
            .{ "tls_ms", l.tls_ns },
            .{ "ttfb_ms", l.ttfb_ns },
            .{ "total_ms", l.total_ns },
        }) |f| {
            try w.print(" {s}=", .{f[0]});
            try ms(w, f[1]);
        }
        try number(w, "bytes_in", l.bytes_in);
        try w.print(" retry={d} reused=", .{l.retry});
        try w.writeAll(if (l.reused) |r| (if (r) "1" else "0") else "?");
        try number(w, "rl_remaining", l.rl_remaining);
        try number(w, "rl_limit", l.rl_limit);
        try number(w, "rl_reset", l.rl_reset);
        try w.print(" rl_resource={s}\n", .{if (l.rl_resource.len > 0) l.rl_resource else "?"});
    }
};

fn ms(w: *std.Io.Writer, ns: ?u64) std.Io.Writer.Error!void {
    const n = ns orelse return w.writeByte('?');
    const tenths = n / 100_000;
    try w.print("{d}.{d}", .{ tenths / 10, tenths % 10 });
}

fn number(w: *std.Io.Writer, key: []const u8, v: ?u64) std.Io.Writer.Error!void {
    try w.print(" {s}=", .{key});
    if (v) |n| try w.print("{d}", .{n}) else try w.writeByte('?');
}

/// `path` cut at a `?` or `#`, and each segment that could be a secret replaced by `*`. What
/// stays is what names an endpoint: a segment of letters, digits, `.`, `_`, `-` and `~`, at most
/// 40 bytes, that does not look like a credential. A segment is replaced when it:
///   - holds anything else (an encoded or odd byte);
///   - is longer than 40 bytes (a signed blob's file name, a JWT);
///   - starts as a known token does (`gh[pousr]_`, `github_pat_`, `eyJ`, `glpat-`);
///   - or is 20 bytes or more of letters and digits (`_` and `-` too) holding both, with no `.`,
///     unless it is a UUID: an opaque id (a git commit's hash, a session's key).
/// Numbers, names, UUIDs, `generate-jitconfig` and Twirp's `Receiver.Method` all stay. The
/// result is written to `out`, which is `path` cut short when it does not fit.
pub fn redactPath(out: []u8, path: []const u8) []const u8 {
    const cut = std.mem.indexOfAny(u8, path, "?#") orelse path.len;
    var n: usize = 0;
    var segments = std.mem.splitScalar(u8, path[0..cut], '/');
    var first = true;
    while (segments.next()) |seg| {
        const text = if (secretShaped(seg)) "*" else seg;
        const need = text.len + @intFromBool(!first);
        if (n + need > out.len) break;
        if (!first) {
            out[n] = '/';
            n += 1;
        }
        @memcpy(out[n..][0..text.len], text);
        n += text.len;
        first = false;
    }
    return out[0..n];
}

fn secretShaped(seg: []const u8) bool {
    if (seg.len == 0) return false;
    if (seg.len > 40) return true;
    var letters = false;
    var digits = false;
    var dotted = false;
    for (seg) |c| switch (c) {
        'a'...'z', 'A'...'Z' => letters = true,
        '0'...'9' => digits = true,
        '.' => dotted = true,
        '_', '-', '~' => {},
        else => return true,
    };
    for ([_][]const u8{ "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "eyJ", "glpat-" }) |p|
        if (std.mem.startsWith(u8, seg, p)) return true;
    if (seg.len >= 20 and letters and digits and !dotted) return !isUuid(seg);
    return false;
}

fn isUuid(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| switch (i) {
        8, 13, 18, 23 => if (c != '-') return false,
        else => if (!std.ascii.isHex(c)) return false,
    };
    return true;
}

/// Writes `l` as one line on stderr, in a single write so that lines of requests made at once do
/// not mix; and the warning a 403 or 429 gets, with the `retry-after` when it came.
pub fn emit(io: std.Io, l: Line, retry_after: []const u8) void {
    if (!enabled.load(.monotonic)) return;
    var buf: [1536]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    l.write(&w) catch return;
    if (capture) |c| {
        while (!capture_lock.tryLock()) std.atomic.spinLoopHint();
        defer capture_lock.unlock();
        c.writer.writeAll(w.buffered()) catch return;
    } else std.Io.File.stderr().writeStreamingAll(io, w.buffered()) catch return;
    if (l.status == .code and (l.status.code == 403 or l.status.code == 429)) {
        if (retry_after.len > 0)
            std.log.warn("request: {s} {s}{s} answered {d}; retry-after={s}", .{ l.method, l.host, l.path, l.status.code, retry_after })
        else
            std.log.warn("request: {s} {s}{s} answered {d}", .{ l.method, l.host, l.path, l.status.code });
    }
}

// The golden text: #530's own test of its line, so that the two writers cannot drift.
test "a line is the same text whatever made it: exact fields, tenths of a millisecond" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (Line{
        .host = "api.github.com",
        .method = "GET",
        .path = "/repos/o/r",
        .status = .{ .code = 200 },
        .dns_ns = 1_240_000,
        .connect_ns = 8_000_000,
        .tls_ns = 20_560_000,
        .ttfb_ns = 61_000_000,
        .total_ns = 95_349_999,
        .bytes_in = 512,
        .retry = 1,
        .reused = false,
        .rl_remaining = 4999,
        .rl_limit = 5000,
        .rl_reset = 1700000000,
        .rl_resource = "core",
    }).write(&w);
    try std.testing.expectEqualStrings(
        "request: host=api.github.com method=GET path=/repos/o/r status=200 dns_ms=1.2 " ++
            "connect_ms=8.0 tls_ms=20.5 ttfb_ms=61.0 total_ms=95.3 bytes_in=512 retry=1 reused=0 " ++
            "rl_remaining=4999 rl_limit=5000 rl_reset=1700000000 rl_resource=core\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try (Line{
        .host = "h",
        .method = "POST",
        .path = "/",
        .status = .{ .err = "Timeout" },
        .total_ns = 30_000_000_000,
    }).write(&w);
    try std.testing.expectEqualStrings(
        "request: host=h method=POST path=/ status=Timeout dns_ms=? connect_ms=? tls_ms=? " ++
            "ttfb_ms=? total_ms=30000.0 bytes_in=? retry=0 reused=? rl_remaining=? rl_limit=? " ++
            "rl_reset=? rl_resource=?\n",
        w.buffered(),
    );
}

test "a path loses its query and the segments that could be secrets" {
    var buf: [256]u8 = undefined;
    const cases = [_][2][]const u8{
        .{ "/repos/o/r/actions/runners/generate-jitconfig", "/repos/o/r/actions/runners/generate-jitconfig" },
        .{ "/message?sessionId=abc&status=Online", "/message" },
        .{ "/app/installations/42/access_tokens", "/app/installations/42/access_tokens" },
        .{ "/twirp/results.services.receiver.Receiver/CreateStepLogsMetadata", "/twirp/results.services.receiver.Receiver/CreateStepLogsMetadata" },
        .{ "/s/0f8fad5b-d9cb-469f-a165-70867728950e/x", "/s/0f8fad5b-d9cb-469f-a165-70867728950e/x" },
        .{ "/app-token/ghs" ++ "_16C7e42F292c6912E7710c838347Ae178B4a", "/app-token/*" },
        .{ "/x/github" ++ "_pat_11ABCDEFG0abcdef", "/x/*" },
        .{ "/x/eyJ" ++ "hbGciOiJSUzI1NiJ9.e30.sig", "/x/*" },
        .{ "/commits/9fceb02d0ae598e95dc970b74767f19372d61af8", "/commits/*" },
        .{ "/a/b%2Fc/d", "/a/*/d" },
        .{ "/o/actions-results/step-logs-0f8fad5b-d9cb-469f-a165-70867728950e.txt", "/o/actions-results/*" },
        .{ "/a#frag", "/a" },
        .{ "", "" },
    };
    for (cases) |c| try std.testing.expectEqualStrings(c[1], redactPath(&buf, c[0]));
}
