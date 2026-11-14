//! How long GitHub asks a client to wait before it asks again, from a 429, 503 or secondary-rate-
//! limit 403's headers: `Retry-After` (seconds, or an HTTP date), else `X-RateLimit-Reset` (epoch
//! seconds) when `X-RateLimit-Remaining` is 0. Retries wait at least this long (`wait`), unless a
//! deadline of the caller's comes first.
const std = @import("std");

/// The longest wait a retry honours without a deadline of its own: a job's cancel or its end must
/// win over a server that asks for an hour.
pub const max_wait_ms: i64 = 60 * std.time.ms_per_s;

/// What the headers of a response ask for, in milliseconds; 0 for no request. `now_ms` is the
/// wall clock. A 403 only asks when it names a rate limit (Retry-After, or remaining 0): any other
/// is the request's own fault.
pub fn parse(
    status: std.http.Status,
    retry_after: ?[]const u8,
    remaining: ?[]const u8,
    reset: ?[]const u8,
    now_ms: i64,
) i64 {
    const limited = status == .too_many_requests or status == .forbidden or
        status.class() == .server_error;
    if (!limited) return 0;
    if (retry_after) |v| if (retryAfter(v, now_ms)) |ms| return ms;
    const rem = remaining orelse return 0;
    if (!std.mem.eql(u8, std.mem.trim(u8, rem, " "), "0")) return 0;
    const at = std.fmt.parseInt(i64, std.mem.trim(u8, reset orelse return 0, " "), 10) catch return 0;
    return clamp(at *| std.time.ms_per_s -| now_ms);
}

/// A `Retry-After` value: whole seconds, or an HTTP date (IMF-fixdate, the form GitHub uses).
fn retryAfter(value: []const u8, now_ms: i64) ?i64 {
    const v = std.mem.trim(u8, value, " ");
    if (std.fmt.parseInt(u32, v, 10)) |s| return clamp(@as(i64, s) * std.time.ms_per_s) else |_| {}
    const at = httpDate(v) orelse return null;
    return clamp(at *| std.time.ms_per_s -| now_ms);
}

fn clamp(ms: i64) i64 {
    return @max(ms, 0);
}

/// "Sun, 06 Nov 1994 08:49:37 GMT" as epoch seconds.
fn httpDate(v: []const u8) ?i64 {
    var it = std.mem.tokenizeScalar(u8, v, ' ');
    const dow = it.next() orelse return null;
    if (dow.len != 4 or dow[3] != ',') return null;
    const day = std.fmt.parseInt(u5, it.next() orelse return null, 10) catch return null;
    const mon_name = it.next() orelse return null;
    const months = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const mon_idx = std.mem.indexOf(u8, months, mon_name) orelse return null;
    if (mon_name.len != 3 or mon_idx % 3 != 0) return null;
    const month = std.math.cast(u4, mon_idx / 3 + 1) orelse return null;
    const year = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    const clock = it.next() orelse return null;
    if (!std.mem.eql(u8, it.next() orelse return null, "GMT")) return null;
    var parts = std.mem.splitScalar(u8, clock, ':');
    const h = std.fmt.parseInt(u8, parts.next() orelse return null, 10) catch return null;
    const m = std.fmt.parseInt(u8, parts.next() orelse return null, 10) catch return null;
    const s = std.fmt.parseInt(u8, parts.next() orelse return null, 10) catch return null;
    if (day == 0 or h > 23 or m > 59 or s > 60 or year < 1970) return null;
    const epoch_day = daysFromCivil(year, month, day);
    return epoch_day * 86400 + @as(i64, h) * 3600 + @as(i64, m) * 60 + s;
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's algorithm).
fn daysFromCivil(year: u16, month: u4, day: u5) i64 {
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (month > 2) @as(i64, month) - 3 else @as(i64, month) + 9;
    const doy = @divFloor(153 * mp + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// How long a retry waits: its own backoff, or the server's request if longer, with up to 10%
/// more on the server's (so runners told the same instant do not return together), never past
/// `max_wait_ms`.
pub fn wait(io: std.Io, backoff_ms: i64, asked_ms: i64) i64 {
    if (asked_ms <= backoff_ms) return backoff_ms;
    var r: [2]u8 = undefined;
    io.random(&r);
    // Bounded first, so the jitter's product cannot overflow whatever the server asked.
    const asked = @min(asked_ms, max_wait_ms);
    const jitter = @divFloor(@divFloor(asked, 10) * std.mem.readInt(u16, &r, .little), 65536);
    return @max(backoff_ms, @min(asked + jitter, max_wait_ms));
}

test "Retry-After in seconds, an HTTP date, and x-ratelimit-reset with remaining 0" {
    const t = std.testing;
    try t.expectEqual(@as(i64, 7000), parse(.too_many_requests, "7", null, null, 0));
    try t.expectEqual(@as(i64, 120_000), parse(.service_unavailable, " 120 ", null, null, 5));
    // 1994-11-06 08:49:37 GMT is 784111777; ten seconds before it:
    try t.expectEqual(@as(i64, 10_000), parse(.too_many_requests, "Sun, 06 Nov 1994 08:49:37 GMT", null, null, 784_111_767_000));
    // A date in the past asks for nothing.
    try t.expectEqual(@as(i64, 0), parse(.too_many_requests, "Sun, 06 Nov 1994 08:49:37 GMT", null, null, 784_111_999_000));
    try t.expectEqual(@as(i64, 3500), parse(.forbidden, null, "0", "1000", 996_500));
    try t.expectEqual(@as(i64, 0), parse(.forbidden, null, "12", "1000", 0));
    // A plain 403, and a 200, ask for nothing.
    try t.expectEqual(@as(i64, 0), parse(.forbidden, null, null, null, 0));
    try t.expectEqual(@as(i64, 0), parse(.ok, "9", "0", "99999999999", 0));
    try t.expectEqual(@as(i64, 0), parse(.too_many_requests, "soon", null, null, 0));
}

test "a wait is the server's request over the backoff, bounded" {
    const io = std.testing.io;
    try std.testing.expectEqual(@as(i64, 2000), wait(io, 2000, 500));
    const w = wait(io, 1000, 30_000);
    try std.testing.expect(w >= 30_000 and w <= 33_000);
    try std.testing.expectEqual(max_wait_ms, wait(io, 1000, 3_600_000));
}
