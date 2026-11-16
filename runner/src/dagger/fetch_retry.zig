//! Retrying a `uses:` action's fetch (native `actions.fetch`, Dagger `actions.fetchAction`) when
//! the network blinks: a DNS lookup that fails for a second, a connection refused or reset, a TLS
//! handshake that times out, a 5xx or a 429. One failed git attempt used to fail "Set up job".
//!
//! What actions/runner does (`src/Runner.Worker/ActionManager.cs`, `DownloadRepositoryArchive`):
//! up to 3 attempts at the archive, any error but a 404 or an access denial retried, between
//! them a uniformly random wait of 10 to 30 s (`BackoffTimerHelper.GetRandomBackoff`; a 429's
//! `Retry-After`, 10 s to 10 min, instead), each logged as `##[warning]`; the same 3 attempts, 10
//! to 30 s apart, for resolving the action's download info; a Docker pull or build 3 times, 1 to
//! 10 s apart. A cancel of the job ends the waiting and is never retried.
//!
//! Here: up to `max_attempts` (5) in all, waiting `base_ms` (4 s) doubled for each retry, 4, 8,
//! 16 and 32 s at most, each wait a random 50 to 100% of that (so runners that failed together
//! do not return together): 30 to 60 s of waiting in all, the whole of actions/runner's 3 x 10
//! to 30 s, but with the first retry early enough to ride out a blip of a few seconds and more
//! attempts for one that lasts. Only what is transient is retried (`transientText`); a missing
//! repository or ref and a refused credential are the answer at once. A cancel (the job's, its
//! timeout's) ends the wait (`pause`).

const std = @import("std");

pub const max_attempts: u32 = 5;
pub const default_base_ms: i64 = 4000;
/// No wait is longer than this, whatever the attempt.
const cap_ms: i64 = 32_000;

/// What marks a failure worth another try: what git and curl print, what the Dagger engine's Go
/// network code prints, and the 5xx and 429 a server answers with. Compared without case.
const transient_needles = [_][]const u8{
    // DNS
    "could not resolve host",
    "temporary failure in name resolution",
    "name or service not known",
    "no such host",
    "server misbehaving",
    "unknown host",
    // Connection
    "connection refused",
    "connection reset",
    "connection timed out",
    "connection timeout",
    "operation timed out",
    "i/o timeout",
    "failed to connect",
    "could not connect to server",
    "network is unreachable",
    "no route to host",
    "empty reply from server",
    "broken pipe",
    "early eof",
    "rpc failed",
    "unexpected disconnect while reading sideband",
    "remote end hung up unexpectedly",
    "the remote end hung up",
    "http/2 stream",
    // TLS
    "tls handshake timeout",
    "tls connection was non-properly terminated",
    "ssl_connect",
    "ssl_read",
    "ssl_write",
    "gnutls_handshake",
    "gnutls recv error",
    // HTTP
    "returned error: 5",
    "returned error: 429",
    "bad gateway",
    "service unavailable",
    "gateway time-out",
    "gateway timeout",
    "too many requests",
};

/// What a retry cannot change, whatever else the text says: the repository or the ref is not
/// there, or a credential is refused.
const permanent_needles = [_][]const u8{
    "repository not found",
    "couldn't find remote ref",
    "not our ref",
    "does not contain ref",
    "authentication failed",
    "could not read username",
    "returned error: 401",
    "returned error: 403",
    "returned error: 404",
    "permission denied",
};

/// The names the runner's own HTTP client gives a download's transport failures (the tarball path
/// has no git to print them): the lookup, the connection and the stream. A 15-minute `Timeout`
/// is none of them: it already took the time a retry would.
const transient_errors = [_][]const u8{
    "UnknownHostName",
    "NameServerFailure",
    "NoAddressReturned",
    "ConnectionRefused",
    "ConnectionResetByPeer",
    "ConnectionTimedOut",
    "ConnectionAborted",
    "NetworkUnreachable",
    "HostUnreachable",
    "HttpConnectionClosing",
    "ResetBeforeHead",
    "EndOfStream",
    "BrokenPipe",
    "ReadFailed",
};

fn mentions(text: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.ascii.findIgnoreCase(text, n) != null) return true;
    return false;
}

/// Whether the output of a failed git (or the engine's message for one) is a network failure
/// that may not come again.
pub fn transientText(text: []const u8) bool {
    return mentions(text, &transient_needles) and !mentions(text, &permanent_needles);
}

/// Whether a failed tarball download's message (`tarball.fetchInto`'s `.failed`: "could not
/// download <url>: <why or the error's name>") is a transport failure. An HTTP status is not
/// judged here: the download already tried a 5xx and a 429 again (`tarball.max_retries`).
pub fn transientDownload(text: []const u8) bool {
    for (transient_errors) |n| if (std.mem.indexOf(u8, text, n) != null) return true;
    return false;
}

/// The wait before attempt `attempt + 1` (`attempt` counts from 1): `base_ms` doubled for each
/// attempt before it, at most `cap_ms`, then a random half to all of it.
pub fn delayMs(io: std.Io, base_ms: i64, attempt: u32) i64 {
    const doublings: u6 = @min(attempt -| 1, 16);
    const full = @min(std.math.shl(i64, base_ms, doublings), @max(cap_ms, base_ms));
    var r: [2]u8 = undefined;
    io.random(&r);
    const jitter = @divFloor(@divFloor(full, 2) * std.mem.readInt(u16, &r, .little), 65536);
    return @divFloor(full, 2) + jitter;
}

/// Waits `ms`, ending early when `cancel` is set or the task is cancelled; true when it ended
/// early. Looked at every 100 ms, as the runner's other waits are.
pub fn pause(io: std.Io, cancel: ?*const std.atomic.Value(bool), ms: i64) bool {
    var left = ms;
    while (left > 0) {
        if (cancel) |c| if (c.load(.acquire)) return true;
        const slice = @min(left, 100);
        io.sleep(.fromMilliseconds(slice), .awake) catch {
            // Delivered once: re-armed, so whatever runs next sees the cancel too.
            io.recancel();
            return true;
        };
        left -= slice;
    }
    return if (cancel) |c| c.load(.acquire) else false;
}

/// The job-log line for a retry: GitHub's runner warns the same way (`Failed to download action
/// '<url>'. Error: ...`, `Back off N seconds before retry.`). The error is the last line the
/// failure said, which is the one that names the cause (`fatal: unable to access ...`).
pub fn warning(
    arena: std.mem.Allocator,
    kind: []const u8,
    what: []const u8,
    attempt: u32,
    failure: []const u8,
    wait_ms: i64,
) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "##[warning]Failed to fetch {s} '{s}' (attempt {d} of {d}): {s}. Retrying in {d} seconds.",
        .{ kind, what, attempt, max_attempts, lastLine(failure), @divFloor(wait_ms + 500, 1000) },
    );
}

fn lastLine(text: []const u8) []const u8 {
    const t = std.mem.trim(u8, text, " \r\n\t");
    const line = if (std.mem.lastIndexOfScalar(u8, t, '\n')) |i| std.mem.trim(u8, t[i + 1 ..], " \r\t") else t;
    return if (line.len > 300) line[0..300] else line;
}

/// One fetch's attempts. `again` is asked after each failure.
pub const Attempts = struct {
    io: std.Io,
    cancel: ?*const std.atomic.Value(bool) = null,
    base_ms: i64 = default_base_ms,
    n: u32 = 1,
    /// What is fetched, for the warning: an `action`, or the `repository` of a checkout.
    kind: []const u8 = "action",
    /// The warning to log for the retry just decided on.
    said: []const u8 = "",
    wait_ms: i64 = 0,

    /// Whether to try again after attempt `n` failed with `failure`: only when `transient`, with
    /// attempts left and no cancel; `said` is then the warning, and the wait has been made.
    pub fn again(a: *Attempts, arena: std.mem.Allocator, what: []const u8, failure: []const u8, transient: bool) !bool {
        if (!try a.plan(arena, what, failure, transient)) return false;
        return a.wait();
    }

    /// The decision alone: whether to retry, and `said`, with the wait's length in `wait_ms`.
    pub fn plan(a: *Attempts, arena: std.mem.Allocator, what: []const u8, failure: []const u8, transient: bool) !bool {
        if (!transient or a.n >= max_attempts) return false;
        if (if (a.cancel) |c| c.load(.acquire) else false) return false;
        a.wait_ms = delayMs(a.io, a.base_ms, a.n);
        a.said = try warning(arena, a.kind, what, a.n, failure, a.wait_ms);
        return true;
    }

    /// The wait `plan` decided on; false when a cancel ended it, else the next attempt is `n`.
    pub fn wait(a: *Attempts) bool {
        if (pause(a.io, a.cancel, a.wait_ms)) return false;
        a.n += 1;
        return true;
    }
};

/// A checkout's attempts (`Backend.fetchCheckout`, `checkout.fetch`): `again` logs each warning in
/// the step's log at once, with the failure text redacted first (the job's token and masks never
/// reach it), and keeps it in `lines`.
pub const Retrying = struct {
    at: Attempts,
    sh: ?*@import("JobLog.zig") = null,
    num: u32 = 0,
    lines: std.ArrayList([]const u8) = .empty,

    pub fn again(r: *Retrying, arena: std.mem.Allocator, what: []const u8, failure: []const u8, transient: bool) !bool {
        const safe = if (r.sh) |sh| sh.redacted(arena, failure) catch failure else failure;
        if (!try r.at.plan(arena, what, safe, transient)) return false;
        if (r.sh) |sh| sh.append(r.num, r.at.said);
        try r.lines.append(arena, r.at.said);
        return r.at.wait();
    }
};

test "transient: what git, curl, Go and the HTTP client say of the network" {
    const t = std.testing;
    for ([_][]const u8{
        "fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host: github.com",
        "fatal: unable to access 'https://github.com/o/r.git/': Failed to connect to github.com port 443 after 129 ms: Connection refused",
        "fatal: unable to access 'https://github.com/o/r.git/': Recv failure: Connection reset by peer",
        "fatal: unable to access 'https://github.com/o/r.git/': Connection timed out after 300001 milliseconds",
        "fatal: unable to access 'https://github.com/o/r.git/': GnuTLS recv error (-110): The TLS connection was non-properly terminated.",
        "fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 503",
        "fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 429",
        "error: RPC failed; curl 56 OpenSSL SSL_read: Connection reset by peer, errno 104\nfatal: early EOF",
        "dial tcp: lookup github.com on 10.0.0.1:53: no such host",
        "dial tcp 140.82.112.3:443: i/o timeout",
        "net/http: TLS handshake timeout",
        "fatal: unable to access 'https://github.com/o/r.git/': Temporary failure in name resolution",
    }) |text| try t.expect(transientText(text));
    // The answer, whoever says it: not there, refused, no such ref.
    for ([_][]const u8{
        "remote: Repository not found.\nfatal: repository 'https://github.com/o/r.git/' not found",
        "fatal: couldn't find remote ref v9",
        "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
        "remote: Invalid username or password.\nfatal: Authentication failed for 'https://github.com/o/r.git/'",
        "fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 404",
        "fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 403",
        "git error: repository does not contain ref \"v10\"",
        "sh: 1: git: not found",
        "",
    }) |text| try t.expect(!transientText(text));
    // A permanent word wins over a transient one in the same output.
    try t.expect(!transientText("Could not resolve host: x\nfatal: Authentication failed"));
}

test "transientDownload: the client's transport errors, not a status or its own 15 minutes" {
    const t = std.testing;
    try t.expect(transientDownload("could not download https://github.com/o/r/archive/v1.tar.gz: UnknownHostName"));
    try t.expect(transientDownload("could not download https://x/y: ConnectionRefused"));
    try t.expect(transientDownload("could not download https://x/y: ResetBeforeHead"));
    try t.expect(!transientDownload("could not download https://x/y: HTTP 404 (not found, or a private repository the job's token cannot read)"));
    try t.expect(!transientDownload("could not download https://x/y: HTTP 500"));
    try t.expect(!transientDownload("could not download https://x/y: it took longer than 15 minutes"));
    try t.expect(!transientDownload("could not download https://x/y: TooManyRedirects"));
}

test "delayMs: half to all of base, doubled per attempt, capped, and never zero for a real base" {
    const io = std.testing.io;
    for (0..200) |_| {
        for ([_]u32{ 1, 2, 3, 4 }) |n| {
            const full: i64 = @min(std.math.shl(i64, default_base_ms, n - 1), cap_ms);
            const d = delayMs(io, default_base_ms, n);
            try std.testing.expect(d >= @divFloor(full, 2) and d <= full);
        }
        try std.testing.expect(delayMs(io, default_base_ms, 40) <= cap_ms);
    }
    // The longest all four waits can be: under actions/runner's 2 x 30 s and 1 minute of waiting.
    try std.testing.expect(4000 + 8000 + 16_000 + 32_000 == 60_000);
}

test "Attempts: transient failures are retried up to max_attempts, permanent ones and a cancel are not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const dns = "fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host: github.com";

    // Fails twice with the DNS text, then succeeds: two retries, each said.
    var at: Attempts = .{ .io = io, .base_ms = 1 };
    var tries: u32 = 0;
    var said: usize = 0;
    while (true) {
        tries += 1;
        if (tries > 2) break;
        if (!try at.again(arena, "o/r@v1", dns, transientText(dns))) break;
        said += 1;
        try std.testing.expect(std.mem.indexOf(u8, at.said, "##[warning]Failed to fetch action 'o/r@v1' (attempt ") != null);
        try std.testing.expect(std.mem.indexOf(u8, at.said, "Could not resolve host: github.com") != null);
    }
    try std.testing.expectEqual(@as(u32, 3), tries);
    try std.testing.expectEqual(@as(usize, 2), said);

    // Never succeeding: max_attempts - 1 retries, then the failure stands.
    var never: Attempts = .{ .io = io, .base_ms = 1 };
    var retries: u32 = 0;
    while (try never.again(arena, "o/r@v1", dns, true)) retries += 1;
    try std.testing.expectEqual(max_attempts - 1, retries);

    // Not transient: at once, nothing said.
    var perm: Attempts = .{ .io = io, .base_ms = 1 };
    const gone = "remote: Repository not found.";
    try std.testing.expect(!try perm.again(arena, "o/r@v1", gone, transientText(gone)));
    try std.testing.expectEqual(@as(u32, 1), perm.n);
    try std.testing.expectEqualStrings("", perm.said);
}

test "pause: a cancel ends a long wait at once, and one already set means no retry" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var flag: std.atomic.Value(bool) = .init(false);

    // Cancelled while it waits (an hour's wait, 200 ms to the cancel).
    const T = struct {
        fn cancelLater(f: *std.atomic.Value(bool), where: std.Io) void {
            where.sleep(.fromMilliseconds(200), .awake) catch return;
            f.store(true, .release);
        }
    };
    const th = try std.Thread.spawn(.{}, T.cancelLater, .{ &flag, io });
    const t0 = std.Io.Clock.awake.now(io).toMilliseconds();
    var at: Attempts = .{ .io = io, .cancel = &flag, .base_ms = 2 * 3600 * 1000 };
    try std.testing.expect(!try at.again(arena, "o/r@v1", "Could not resolve host: github.com", true));
    th.join();
    try std.testing.expect(std.Io.Clock.awake.now(io).toMilliseconds() - t0 < 5000);
    try std.testing.expectEqual(@as(u32, 1), at.n);

    // Already cancelled: it does not even say it will retry.
    var late: Attempts = .{ .io = io, .cancel = &flag, .base_ms = 1 };
    try std.testing.expect(!try late.again(arena, "o/r@v1", "Could not resolve host: x", true));
    try std.testing.expectEqualStrings("", late.said);
}
