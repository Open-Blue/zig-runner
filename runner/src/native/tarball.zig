//! A repository as the archive GitHub serves, for a job whose image has no git: the built-in
//! checkout and the fetch of a `uses:` action run `git` in the job's image (`Backend.fetchCheckout`,
//! `actions.fetch`), and a slim or Alpine image has none. The Dagger engine fetched with its own
//! git, so such a job used to go to Dagger, and fails with no engine. Here the runner downloads the
//! tarball itself, as actions/checkout does when git is missing (`downloadRepository`), and the
//! step extracts it with the image's `tar` from a read-only bind of the download, so the files get
//! the job's ids and the layer exactly as any step's do.
//!
//! What a tarball is not: there is no `.git`, no history, no tags and no submodules (the same as
//! actions/checkout without git, which is why the step says so and a checkout that asks for
//! submodules fails here instead of giving a tree without them).
//!
//! The archive is read by `tar` in the sandbox, as the job's root and no more: nothing the archive
//! names can reach outside the job's layer. The runner reads only its first 1 KiB of it, for the
//! commit GitHub records in the pax header, which is bounded and never trusted for more than a
//! 40-digit hex string.

const std = @import("std");
const http = @import("../github/http.zig");
const ratelimit = @import("../github/ratelimit.zig");
const checkout = @import("../dagger/checkout.zig");
const sandbox = @import("sandbox.zig");
const Backend = @import("Backend.zig");

const Allocator = std.mem.Allocator;

/// Where the downloaded archive is in the step: its directory, bound read-only.
pub const bind_at = "/tmp/zig-runner-source";
const archive_name = "source.tar.gz";

/// The most a repository's archive may be. GitHub's own limit on a tarball is not documented; this
/// is above the repositories this is meant for and below a full disk.
pub const max_bytes: u64 = 4 * 1024 * 1024 * 1024;

/// A download takes at most this long (a slow link, a large monorepo, a Pi).
const deadline: std.Io.Duration = .fromSeconds(15 * 60);

const max_redirects = 5;

pub const Source = struct {
    url: []const u8,
    /// Sent to the first host only, never to where a redirect leads.
    token: ?[]const u8 = null,
    /// The first wait before a retry, doubled for each after it (a test's is a millisecond).
    backoff_ms: i64 = 1000,
};

/// How many times a download is made again after a 429, a 5xx or a rate-limited 403. With the
/// backoff (1, 2, 4 s) and what GitHub asks (at most `ratelimit.max_wait_ms` each) this stays well
/// inside the download's own `deadline`, which bounds the whole of it.
const max_retries = 3;

/// GitHub's API for a server: `api.github.com` for github.com, `<server>/api/v3` for a GitHub
/// Enterprise Server, `api.<host>` for GitHub's data-residency hosts (`*.ghe.com`).
pub fn apiBase(arena: Allocator, server_url: []const u8) ![]const u8 {
    const server = std.mem.trimEnd(u8, server_url, "/");
    const uri = std.Uri.parse(server) catch return std.fmt.allocPrint(arena, "{s}/api/v3", .{server});
    var buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = (std.Io.net.HostName.fromUri(uri, &buf) catch return std.fmt.allocPrint(arena, "{s}/api/v3", .{server})).bytes;
    if (std.ascii.eqlIgnoreCase(host, "github.com")) return "https://api.github.com";
    if (std.ascii.endsWithIgnoreCase(host, ".ghe.com"))
        return std.fmt.allocPrint(arena, "{s}://api.{s}", .{ uri.scheme, host });
    return std.fmt.allocPrint(arena, "{s}/api/v3", .{server});
}

/// Why `ref` cannot be put in a URL's path, or null. A segment that is empty, `.` or `..` would
/// move the request to another path of the same host (the job's token goes with it); git's ref
/// names cannot have one (`git check-ref-format`), so no branch, tag or commit is refused.
pub fn refProblem(ref: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, ref, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, ".."))
            return "the ref has an empty, `.` or `..` path segment, which no git ref has";
    }
    return null;
}

/// A refs' path in a URL: each segment percent-encoded, the slashes of `refs/pull/7/merge` kept.
fn refPath(arena: Allocator, ref: []const u8) ![]const u8 {
    if (refProblem(ref) != null) return error.InvalidRef;
    var w: std.Io.Writer.Allocating = .init(arena);
    var it = std.mem.splitScalar(u8, ref, '/');
    var first = true;
    while (it.next()) |seg| {
        if (!first) try w.writer.writeByte('/');
        first = false;
        try std.Uri.Component.percentEncode(&w.writer, seg, isSegmentChar);
    }
    return w.written();
}

fn isSegmentChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '-', '.', '_', '~', '@', '+' => true,
        else => false,
    };
}

/// The built-in checkout's source: the REST API's tarball, which takes the job's token and so reads
/// a private repository. `want` is the commit, the ref, or `HEAD` for the default branch.
pub fn checkoutSource(arena: Allocator, server_url: []const u8, repo: []const u8, want: []const u8, token: ?[]const u8) !Source {
    const base = try apiBase(arena, server_url);
    const tail: []const u8 = if (std.mem.eql(u8, want, "HEAD")) "" else try std.fmt.allocPrint(arena, "/{s}", .{try refPath(arena, want)});
    return .{ .url = try std.fmt.allocPrint(arena, "{s}/repos/{s}/tarball{s}", .{ base, repo, tail }), .token = token };
}

/// An action's source: the web archive of a public repository, as git over HTTPS reads it with no
/// token (the Dagger path sends none either, for an action in another repository). `ref` is a
/// commit, a tag or a branch. The job's own repository takes `checkoutSource`, with its token.
pub fn actionSource(arena: Allocator, server_url: []const u8, repo: []const u8, ref: []const u8) !Source {
    const server = std.mem.trimEnd(u8, server_url, "/");
    return .{ .url = try std.fmt.allocPrint(arena, "{s}/{s}/archive/{s}.tar.gz", .{ server, repo, try refPath(arena, ref) }) };
}

/// An action's source on a Gitea or Forgejo instance, which takes the task's token on its web
/// archive too (a private repository's): `Bearer`, sent to that host only.
pub fn instanceSource(arena: Allocator, server_url: []const u8, repo: []const u8, ref: []const u8, token: []const u8) !Source {
    var s = try actionSource(arena, server_url, repo, ref);
    s.token = token;
    return s;
}

/// The step that extracts the archive into `mount`: `tar` as it is in busybox and GNU alike (the
/// top directory GitHub adds stripped, owners not applied), the modes git's checkout gives and the
/// files given the checkout's fixed time (`checkout.mtime`).
pub fn extractScript(arena: Allocator, mount: []const u8) ![]const u8 {
    return extractScriptFrom(arena, mount, bind_at);
}

fn extractScriptFrom(arena: Allocator, mount: []const u8, from: []const u8) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    try w.writer.writeAll("set -e\nmkdir -p ");
    try shellQuote(&w.writer, mount);
    try w.writer.writeAll(" && cd ");
    try shellQuote(&w.writer, mount);
    try w.writer.print("\ntar -xzf {s}/{s} --strip-components=1 -o\n", .{ from, archive_name });
    // Modes as git's checkout makes them, whatever the archive stores (GitHub's are `git archive`'s,
    // group-writable) and whoever extracts it: directories 755, executables 755, other files 644.
    // A directory the archive stores with no owner access (mode 000) is made enterable first, one
    // `chmod` at a time: `find` runs it before it reads the directory, where the batched `+` forms
    // below run after the walk, which a non-root job user cannot make through one.
    try w.writer.writeAll("find . -type d ! -perm -700 -exec chmod u+rwx {} \\;\n" ++
        "find . -type d -exec chmod 755 {} +\n" ++
        "find . -type f -perm -100 -exec chmod 755 {} +\n" ++
        "find . -type f ! -perm -100 -exec chmod 644 {} +\n");
    try w.writer.print("find . -exec touch -h -d @{d} {{}} +\n", .{checkout.mtime});
    return w.written();
}

fn shellQuote(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('\'');
    for (s) |c| {
        if (c == '\'') try w.writeAll("'\\''") else try w.writeByte(c);
    }
    try w.writeByte('\'');
}

/// What came of `fetchInto`: the commit the archive holds, or why it could not be had.
pub const Fetched = union(enum) { sha: []const u8, failed: []const u8 };

/// Downloads `src`, then extracts it into `mount` in a new layer of the job (which the caller keys
/// or keeps), as the user `uid`:`gid`. The commit is `expect` when the caller knows it, else the one GitHub's pax header
/// records. Never fails the job by itself: a download or an extraction that fails is `.failed`
/// with why, for the step to say.
pub fn fetchInto(b: *Backend, mount: []const u8, src: Source, expect: ?[]const u8, uid: u32, gid: u32) !Fetched {
    const arena = b.arena;
    b.preflights += 1;
    const dir = try std.fmt.allocPrint(arena, "{s}/source-{d}", .{ b.dir, b.preflights });
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(b.io, dir);
    defer cwd.deleteTree(b.io, dir) catch |e| std.log.warn("native: the downloaded archive in {s} is left behind: {s}", .{ dir, @errorName(e) });
    const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, archive_name });

    if (try downloadFailure(arena, b.gpa, b.io, src, path)) |msg| return .{ .failed = msg };
    const archived = try commitOf(arena, b.io, path);
    if (try commitMismatch(arena, expect, archived)) |msg| return .{ .failed = msg };
    const sha: []const u8 = archived orelse expect orelse "";

    const script = try extractScript(arena, mount);
    const saved = b.binds;
    b.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ saved, &.{.{
        .host = dir,
        .at = bind_at,
        .read_only = true,
        .nosuid = true,
        .make = true,
    }} });
    defer b.binds = saved;
    var out: Backend.Captured = .{ .arena = arena };
    const ended = try b.execOn(&.{ "sh", "-c", script }, &.{"PATH=" ++ Backend.image_path}, &.{}, uid, gid, out.output(), null);
    if (ended.failure.len > 0 or ended.code != 0) return .{ .failed = try std.fmt.allocPrint(
        arena,
        "could not unpack {s} in the job's image (it needs `tar` and `gzip`): {s}",
        .{ src.url, if (ended.failure.len > 0) ended.failure else out.tail() },
    ) };
    return .{ .sha = sha };
}

/// Why `src` could not be downloaded into `path`, for the step to say, or null when it was. Only
/// the download's own failures are one: memory that ran out is an error, not a verdict on it.
fn downloadFailure(arena: Allocator, gpa: Allocator, io: std.Io, src: Source, path: []const u8) !?[]const u8 {
    var why: []const u8 = "";
    download(arena, gpa, io, src, path, &why) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return try std.fmt.allocPrint(
            arena,
            "could not download {s}: {s}",
            .{ src.url, if (why.len > 0) why else @errorName(e) },
        ),
    };
    return null;
}

/// Why the archive is not the commit that was asked for, or null: `expect` (a 40-digit hex commit
/// the job named, or null for a branch or a tag) against the commit the archive records. An
/// archive that records none cannot be compared and is taken as the request.
fn commitMismatch(arena: Allocator, expect: ?[]const u8, archived: ?[]const u8) !?[]const u8 {
    const want = expect orelse return null;
    const got = archived orelse return null;
    if (!checkout.isSha(want) or std.ascii.eqlIgnoreCase(want, got)) return null;
    return try std.fmt.allocPrint(arena, "the archive holds commit {s}, not the {s} that was asked for", .{ got, want });
}

/// GET `src` into the file `path`, following up to `max_redirects` redirects itself: std's client
/// keeps an Authorization header across a redirect to another host, and the token is GitHub's API's
/// to see, not the signed URL's CDN.
pub fn download(arena: Allocator, gpa: Allocator, io: std.Io, src: Source, path: []const u8, why: *[]const u8) !void {
    var local: std.http.Client = .{ .allocator = gpa, .io = io, .write_buffer_size = http.write_buffer_size };
    defer local.deinit();
    const r = try http.within(io, deadline, downloadWith, .{ arena, http.client(&local), io, src, path, why });
    return r orelse {
        why.* = "it took longer than 15 minutes";
        return error.Timeout;
    };
}

fn downloadWith(arena: Allocator, client: *std.http.Client, io: std.Io, src: Source, path: []const u8, why: *[]const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var uri = try std.Uri.parse(src.url);
    const origin = uri;
    var redirects: u32 = 0;
    var stale: u32 = 0;
    var retries: u32 = 0;
    while (true) {
        const own = sameOrigin(uri, origin);
        const bearer: ?[]const u8 = if (own) (if (src.token) |t| try std.fmt.allocPrint(arena, "Bearer {s}", .{t}) else null) else null;
        var miss: Miss = .{};
        const next = onceAt(arena, client, uri, bearer, file, why, &miss, io) catch |e| switch (e) {
            error.HttpConnectionClosing, error.ResetBeforeHead => if (stale < http.staleRetries(client)) {
                stale += 1;
                continue;
            } else return e,
            // A server that is busy or limiting: again, after at least what it asked for (a
            // cancel of the job ends the sleep), a bounded number of times.
            error.HttpStatus => if (miss.retryable() and retries < max_retries) {
                const backoff = std.math.shl(@TypeOf(src.backoff_ms), src.backoff_ms, retries);
                retries += 1;
                try io.sleep(.fromMilliseconds(ratelimit.wait(io, backoff, miss.asked_ms)), .awake);
                continue;
            } else return e,
            else => return e,
        };
        uri = next orelse return;
        redirects += 1;
        if (redirects > max_redirects) {
            why.* = "too many redirects";
            return error.TooManyRedirects;
        }
    }
}

fn sameOrigin(a: std.Uri, b: std.Uri) bool {
    if (!std.mem.eql(u8, a.scheme, b.scheme)) return false;
    var ba: [std.Io.net.HostName.max_len]u8 = undefined;
    var bb: [std.Io.net.HostName.max_len]u8 = undefined;
    const ha = std.Io.net.HostName.fromUri(a, &ba) catch return false;
    const hb = std.Io.net.HostName.fromUri(b, &bb) catch return false;
    return std.ascii.eqlIgnoreCase(ha.bytes, hb.bytes) and a.port == b.port;
}

/// What a refused request says of trying again.
const Miss = struct {
    status: std.http.Status = .ok,
    /// What the response's `Retry-After` or rate-limit headers ask to wait, in milliseconds.
    asked_ms: i64 = 0,

    fn retryable(m: Miss) bool {
        return m.status == .too_many_requests or m.status.class() == .server_error or m.asked_ms > 0;
    }
};

/// One request: null when answered (the body is in `file`), else where it redirects to.
fn onceAt(arena: Allocator, client: *std.http.Client, uri: std.Uri, bearer: ?[]const u8, file: std.Io.File, why: *[]const u8, miss: *Miss, io: std.Io) !?std.Uri {
    var req = try client.request(.GET, uri, .{
        .headers = .{
            .accept_encoding = .omit,
            .user_agent = .{ .override = "zig-runner" },
            .authorization = if (bearer) |a| .{ .override = a } else .omit,
        },
        .redirect_behavior = .unhandled,
    });
    defer req.deinit();
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };
    try req.sendBodiless();
    var res = req.receiveHead(&.{}) catch |e| return switch (e) {
        error.ReadFailed => error.ResetBeforeHead,
        else => e,
    };
    const status = res.head.status;
    var location: ?[]const u8 = null;
    var retry_after: ?[]const u8 = null;
    var remaining: ?[]const u8 = null;
    var reset: ?[]const u8 = null;
    var it = res.head.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "location")) location = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "retry-after")) retry_after = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-ratelimit-remaining")) remaining = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-ratelimit-reset")) reset = try arena.dupe(u8, h.value);
    }
    var transfer: [64]u8 = undefined;
    const r = res.reader(&transfer);
    if (status.class() == .redirect) if (location) |loc| {
        _ = r.discardRemaining() catch {
            req.connection.?.closing = true;
        };
        var buf = try arena.alloc(u8, loc.len + 2048);
        @memcpy(buf[0..loc.len], loc);
        var aux: []u8 = buf;
        const next = uri.resolveInPlace(loc.len, &aux) catch return error.HttpRedirectLocationInvalid;
        if (!std.mem.eql(u8, next.scheme, "https") and !std.mem.eql(u8, next.scheme, "http"))
            return error.HttpRedirectLocationInvalid;
        return next;
    };
    if (status != .ok) {
        miss.* = .{
            .status = status,
            .asked_ms = ratelimit.parse(status, retry_after, remaining, reset, std.Io.Clock.real.now(io).toMilliseconds()),
        };
        why.* = try std.fmt.allocPrint(arena, "HTTP {d}{s}", .{
            @backingInt(status),
            if (status == .not_found) " (not found, or a private repository the job's token cannot read)" else "",
        });
        return if (status == .not_found) error.NotFound else error.HttpStatus;
    }
    var buf: [64 * 1024]u8 = undefined;
    var written: u64 = 0;
    while (true) {
        const n = r.readSliceShort(&buf) catch |e| switch (e) {
            error.ReadFailed => return res.bodyErr() orelse e,
        };
        if (n == 0) break;
        written += n;
        if (written > max_bytes) {
            why.* = "the archive is larger than 4 GiB";
            return error.ResponseTooLarge;
        }
        try writeAll(file, buf[0..n]);
    }
    return null;
}

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

/// The commit GitHub (and `git archive`) record in the archive's pax global header, `comment=<sha>`:
/// the tar's first entry, read from the first 1 KiB of the decompressed stream. Null when there is
/// none or it is not a 40-digit hex string. Nothing else in the archive is read here.
pub fn commitOf(arena: Allocator, io: std.Io, path: []const u8) !?[]const u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var rbuf: [4096]u8 = undefined;
    var fr = file.reader(io, &rbuf);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var d: std.compress.flate.Decompress = .init(&fr.interface, .gzip, &window);
    var head: [1024]u8 = undefined;
    const n = d.reader.readSliceShort(&head) catch return null;
    return paxCommit(arena, head[0..n]);
}

/// `comment=<sha>` in the first entry of a tar, when that entry is a pax global header ('g').
pub fn paxCommit(arena: Allocator, tar_head: []const u8) !?[]const u8 {
    if (tar_head.len < 512 or tar_head[156] != 'g') return null;
    const size_text = std.mem.trim(u8, std.mem.sliceTo(tar_head[124..136], 0), " ");
    const size = std.fmt.parseInt(usize, size_text, 8) catch return null;
    if (size > tar_head.len - 512) return null;
    const data = tar_head[512 .. 512 + size];
    // Records are `<length> <key>=<value>\n`.
    var rest = data;
    while (rest.len > 0) {
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
        const len = std.fmt.parseInt(usize, rest[0..sp], 10) catch return null;
        if (len <= sp + 1 or len > rest.len) return null;
        const record = std.mem.trimEnd(u8, rest[sp + 1 .. len], "\n");
        rest = rest[len..];
        if (std.mem.startsWith(u8, record, "comment=")) {
            const sha = record["comment=".len..];
            return if (checkout.isSha(sha)) try arena.dupe(u8, sha) else null;
        }
    }
    return null;
}

test "apiBase: github.com, data residency hosts, and a server's own /api/v3" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    try std.testing.expectEqualStrings("https://api.github.com", try apiBase(arena, "https://github.com"));
    try std.testing.expectEqualStrings("https://api.github.com", try apiBase(arena, "https://github.com/"));
    try std.testing.expectEqualStrings("https://api.acme.ghe.com", try apiBase(arena, "https://acme.ghe.com"));
    try std.testing.expectEqualStrings("https://git.example.com/api/v3", try apiBase(arena, "https://git.example.com"));
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/api/v3", try apiBase(arena, "http://127.0.0.1:8080/"));
}

test "sources: the API's tarball for a checkout, the web archive for an action, refs encoded" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const c1 = try checkoutSource(arena, "https://github.com", "o/r", "refs/pull/7/merge", "tok");
    try std.testing.expectEqualStrings("https://api.github.com/repos/o/r/tarball/refs/pull/7/merge", c1.url);
    try std.testing.expectEqualStrings("tok", c1.token.?);
    const c2 = try checkoutSource(arena, "https://github.com", "o/r", "HEAD", null);
    try std.testing.expectEqualStrings("https://api.github.com/repos/o/r/tarball", c2.url);
    const c3 = try checkoutSource(arena, "https://github.com", "o/r", "feat/a b?c#d", null);
    try std.testing.expectEqualStrings("https://api.github.com/repos/o/r/tarball/feat/a%20b%3Fc%23d", c3.url);
    const s = try actionSource(arena, "https://github.com/", "actions/cache", "v4");
    try std.testing.expectEqualStrings("https://github.com/actions/cache/archive/v4.tar.gz", s.url);
    try std.testing.expect(s.token == null);
}

test "extractScript quotes the mount and keeps the checkout's time" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const s = try extractScript(arena, "/home/runner/work/it's/repo");
    try std.testing.expect(std.mem.indexOf(u8, s, "mkdir -p '/home/runner/work/it'\\''s/repo'") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "tar -xzf /tmp/zig-runner-source/source.tar.gz --strip-components=1 -o") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "chmod 644") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "@946684800") != null);
}

test "paxCommit reads the commit from a pax global header and nothing else" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const sha = "0123456789abcdef0123456789abcdef01234567";
    var block: [1024]u8 = @splat(0);
    block[156] = 'g';
    const rec = "52 comment=" ++ sha ++ "\n";
    try std.testing.expectEqual(@as(usize, 52), rec.len);
    _ = try std.fmt.bufPrint(block[124..136], "{o:0>11}", .{rec.len});
    @memcpy(block[512..][0..rec.len], rec);
    try std.testing.expectEqualStrings(sha, (try paxCommit(arena, &block)).?);
    // Not a global header, a short record, a size past what was read, a non-hex comment.
    block[156] = '0';
    try std.testing.expect((try paxCommit(arena, &block)) == null);
    block[156] = 'g';
    try std.testing.expect((try paxCommit(arena, block[0..300])) == null);
    _ = try std.fmt.bufPrint(block[124..136], "{o:0>11}", .{@as(usize, 9999)});
    try std.testing.expect((try paxCommit(arena, &block)) == null);
    _ = try std.fmt.bufPrint(block[124..136], "{o:0>11}", .{rec.len});
    block[512 + 11] = 'z';
    try std.testing.expect((try paxCommit(arena, &block)) == null);
}

test "paxCommit survives every prefix and every flipped byte of a real header" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var block: [1024]u8 = @splat(0);
    block[156] = 'g';
    const rec = "52 comment=0123456789abcdef0123456789abcdef01234567\n";
    _ = try std.fmt.bufPrint(block[124..136], "{o:0>11}", .{rec.len});
    @memcpy(block[512..][0..rec.len], rec);
    for (0..block.len) |n| _ = try paxCommit(arena, block[0..n]);
    for (0..block.len) |i| {
        const save = block[i];
        defer block[i] = save;
        for ([_]u8{ 0, 0xff, ' ', '\n', '=', '9' }) |v| {
            block[i] = v;
            _ = try paxCommit(arena, &block);
        }
    }
}

// --- tests ---

const Io = std.Io;
const job_mod = @import("../job.zig");
const dagger = @import("../dagger.zig");
const sink = @import("../sink.zig");
const testStep = @import("../dagger/testing.zig").testStep;
const testJob = @import("../dagger/testing.zig").testJob;
const usesStep = @import("../dagger/testing.zig").usesStep;

/// GitHub's two hosts for a tarball, on 127.0.0.1: `api_path` answers 302 to `/cdn` on "localhost"
/// (a host that must never see the token, as codeload must not), `archive_path` answers the
/// archive itself, and `/cdn` answers it unless an Authorization came with the request. Every
/// request is counted, and the Authorization of each path is kept.
const TestServer = struct {
    listener: Io.net.Server = undefined,
    port: u16 = 0,
    thread: std.Thread = undefined,
    api_path: []const u8 = "",
    archive_path: []const u8 = "",
    /// A second archive, a second action's.
    archive_path2: []const u8 = "",
    body: []const u8 = "",
    requests: std.atomic.Value(u32) = .init(0),
    api_auth: [256]u8 = undefined,
    api_auth_len: std.atomic.Value(usize) = .init(0),
    cdn_saw_auth: std.atomic.Value(bool) = .init(false),
    /// `flaky_path` answers `flaky_status` (with `flaky_extra` headers) `flaky_fails` times, then
    /// the archive.
    flaky_path: []const u8 = "",
    flaky_status: []const u8 = "",
    flaky_extra: []const u8 = "",
    flaky_fails: u32 = 0,
    flaky_seen: std.atomic.Value(u32) = .init(0),
    /// The first `drop_first` requests for `archive_path` are closed with no answer at all, as a
    /// connection that a network resets.
    drop_first: u32 = 0,
    drop_seen: std.atomic.Value(u32) = .init(0),

    fn start(s: *TestServer) !void {
        const io = std.testing.io;
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        s.listener = try addr.listen(io, .{ .reuse_address = true });
        s.port = s.listener.socket.address.getPort();
        s.thread = try std.Thread.spawn(.{}, serve, .{s});
    }

    fn stop(s: *TestServer) void {
        const io = std.testing.io;
        if (Io.net.IpAddress.parse("127.0.0.1", s.port)) |addr| {
            if (addr.connect(io, .{ .mode = .stream })) |conn| {
                var wb: [64]u8 = undefined;
                var w = conn.writer(io, &wb);
                const sent = w.interface.writeAll("GET /quit HTTP/1.1\r\nHost: x\r\n\r\n");
                if (sent) w.interface.flush() catch |e| std.log.warn("test server: {s}", .{@errorName(e)}) else |e| std.log.warn("test server: {s}", .{@errorName(e)});
                conn.close(io);
            } else |_| {}
        } else |_| {}
        s.thread.join();
        s.listener.deinit(io);
    }

    fn serve(s: *TestServer) void {
        while (true) {
            const conn = s.listener.accept(std.testing.io) catch return;
            const quit = s.answer(conn);
            conn.close(std.testing.io);
            if (quit) return;
        }
    }

    fn answer(s: *TestServer, conn: Io.net.Stream) bool {
        const io = std.testing.io;
        var rb: [8192]u8 = undefined;
        var r = conn.reader(io, &rb);
        const first = r.interface.takeDelimiterInclusive('\n') catch return false;
        var parts = std.mem.tokenizeAny(u8, first, " \r\n");
        _ = parts.next();
        var path_buf: [1024]u8 = undefined;
        const raw = parts.next() orelse return false;
        if (raw.len > path_buf.len) return false;
        @memcpy(path_buf[0..raw.len], raw);
        const path = path_buf[0..raw.len];
        var auth: []const u8 = "";
        var auth_buf: [256]u8 = undefined;
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
        }
        if (std.mem.eql(u8, path, "/quit")) return true;
        _ = s.requests.fetchAdd(1, .acq_rel);
        var wb: [64 * 1024]u8 = undefined;
        var w = conn.writer(io, &wb);
        const out = &w.interface;
        if (std.mem.eql(u8, path, s.api_path)) {
            @memcpy(s.api_auth[0..auth.len], auth);
            s.api_auth_len.store(auth.len, .release);
            var hb: [128]u8 = undefined;
            const loc = std.fmt.bufPrint(&hb, "Location: http://localhost:{d}/cdn\r\n", .{s.port}) catch return false;
            return reply(out, "302 Found", loc, "");
        }
        if (std.mem.eql(u8, path, "/cdn")) {
            if (auth.len > 0) {
                s.cdn_saw_auth.store(true, .release);
                return reply(out, "400 Bad Request", "", "credentials sent to the CDN");
            }
            return reply(out, "200 OK", "", s.body);
        }
        if (s.flaky_path.len > 0 and std.mem.eql(u8, path, s.flaky_path)) {
            if (s.flaky_seen.fetchAdd(1, .acq_rel) < s.flaky_fails)
                return reply(out, s.flaky_status, s.flaky_extra, "busy");
            return reply(out, "200 OK", "", s.body);
        }
        if (std.mem.eql(u8, path, s.archive_path) and s.drop_seen.fetchAdd(1, .acq_rel) < s.drop_first) return false;
        if (std.mem.eql(u8, path, s.archive_path) or (s.archive_path2.len > 0 and std.mem.eql(u8, path, s.archive_path2))) {
            if (auth.len > 0) s.cdn_saw_auth.store(true, .release);
            return reply(out, "200 OK", "", s.body);
        }
        return reply(out, "404 Not Found", "", "");
    }

    fn reply(out: *Io.Writer, status: []const u8, extra: []const u8, body: []const u8) bool {
        out.print("HTTP/1.1 {s}\r\n{s}Content-Type: application/gzip\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, extra, body.len }) catch return false;
        out.writeAll(body) catch return false;
        out.flush() catch return false;
        return false;
    }
};

/// A repository at `<tmp>/src` with a file, an executable, a nested file and a link, committed;
/// its commit, and its `git archive` as GitHub's tarball has it (`o-r-<sha7>/` and the pax header).
fn testArchive(arena: Allocator, tmp: *std.testing.TmpDir) !TestArchive {
    return testArchiveOf(arena, tmp, "echo from-the-archive > file; printf '#!/bin/sh\\necho hi\\n' > run.sh; chmod 755 run.sh; " ++
        "mkdir -p sub/deeper; echo nested > sub/deeper/n.txt; ln -s file link");
}

const TestArchive = struct { sha: []const u8, tgz: []const u8, root: []const u8 };

/// `testArchive` of a repository `files` (shell, run in its work tree) makes.
fn testArchiveOf(arena: Allocator, tmp: *std.testing.TmpDir, files: []const u8) !TestArchive {
    const io = std.testing.io;
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const make = try std.fmt.allocPrint(arena, "set -e; cd '{s}'; git init -q -b main src; cd src; {s}; " ++
        "git add -A; git -c user.name=t -c user.email=t@t commit -q -m first; " ++
        "sha=$(git rev-parse HEAD); git archive --format=tar.gz --prefix=o-r-$(echo $sha | cut -c1-7)/ -o ../src.tgz HEAD; " ++
        "echo $sha", .{ root, files });
    const made = std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", make } }) catch return error.SkipZigTest;
    if (made.term != .exited or made.term.exited != 0) return error.SkipZigTest;
    const tgz = try tmp.dir.readFileAlloc(io, "src.tgz", arena, .limited(1 << 20));
    return .{ .sha = std.mem.trim(u8, made.stdout, "\n"), .tgz = tgz, .root = root };
}

test "commitOf reads the commit out of a real git archive" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ar = try testArchive(arena, &tmp);
    const got = try commitOf(arena, std.testing.io, try std.fmt.allocPrint(arena, "{s}/src.tgz", .{ar.root}));
    try std.testing.expectEqualStrings(ar.sha, got.?);
}

test "download: the token goes to the API and not to where it redirects; failures say why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ar = try testArchive(arena, &tmp);
    var srv: TestServer = .{ .api_path = "/api/v3/repos/o/r/tarball/abc", .archive_path = "/o/r/archive/v1.tar.gz", .body = ar.tgz };
    try srv.start();
    defer srv.stop();
    const io = std.testing.io;
    const dest = try std.fmt.allocPrint(arena, "{s}/got.tgz", .{ar.root});
    var why: []const u8 = "";

    try download(arena, std.testing.allocator, io, .{
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/api/v3/repos/o/r/tarball/abc", .{srv.port}),
        .token = "s3cret",
    }, dest, &why);
    const got = try tmp.dir.readFileAlloc(io, "got.tgz", arena, .limited(1 << 20));
    try std.testing.expectEqualSlices(u8, ar.tgz, got);
    try std.testing.expectEqualStrings("Bearer s3cret", srv.api_auth[0..srv.api_auth_len.load(.acquire)]);
    try std.testing.expect(!srv.cdn_saw_auth.load(.acquire));

    // An action's web archive: no token at all.
    try download(arena, std.testing.allocator, io, .{
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/o/r/archive/v1.tar.gz", .{srv.port}),
    }, dest, &why);
    try std.testing.expect(!srv.cdn_saw_auth.load(.acquire));

    // A 404 is said as one, with the likely reason.
    try std.testing.expectError(error.NotFound, download(arena, std.testing.allocator, io, .{
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/nope", .{srv.port}),
    }, dest, &why));
    try std.testing.expect(std.mem.indexOf(u8, why, "HTTP 404") != null);
}

test "download: a 429 or 5xx is tried again (Retry-After honoured), a persistent one gives up, a 404 is not retried" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ar = try testArchive(arena, &tmp);
    const io = std.testing.io;
    const dest = try std.fmt.allocPrint(arena, "{s}/got.tgz", .{ar.root});
    var why: []const u8 = "";

    // 429 with Retry-After: 1, then the archive: the wait is at least what was asked.
    var limited: TestServer = .{ .flaky_path = "/limited", .flaky_status = "429 Too Many Requests", .flaky_extra = "Retry-After: 1\r\n", .flaky_fails = 1, .body = ar.tgz };
    try limited.start();
    defer limited.stop();
    const t0 = std.Io.Clock.awake.now(io).toMilliseconds();
    try download(arena, std.testing.allocator, io, .{
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/limited", .{limited.port}),
        .backoff_ms = 1,
    }, dest, &why);
    try std.testing.expect(std.Io.Clock.awake.now(io).toMilliseconds() - t0 >= 1000);
    try std.testing.expectEqual(@as(u32, 2), limited.flaky_seen.load(.acquire));
    const got = try tmp.dir.readFileAlloc(io, "got.tgz", arena, .limited(1 << 20));
    try std.testing.expectEqualSlices(u8, ar.tgz, got);

    // 502, then the archive.
    var bad_gateway: TestServer = .{ .flaky_path = "/gw", .flaky_status = "502 Bad Gateway", .flaky_fails = 2, .body = ar.tgz };
    try bad_gateway.start();
    defer bad_gateway.stop();
    try download(arena, std.testing.allocator, io, .{
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/gw", .{bad_gateway.port}),
        .backoff_ms = 1,
    }, dest, &why);
    try std.testing.expectEqual(@as(u32, 3), bad_gateway.flaky_seen.load(.acquire));

    // A 500 that never ends: one try and `max_retries` more, then the status as the reason.
    var broken: TestServer = .{ .flaky_path = "/broken", .flaky_status = "500 Internal Server Error", .flaky_fails = 1000, .body = ar.tgz };
    try broken.start();
    defer broken.stop();
    try std.testing.expectError(error.HttpStatus, download(arena, std.testing.allocator, io, .{
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/broken", .{broken.port}),
        .backoff_ms = 1,
    }, dest, &why));
    try std.testing.expectEqual(@as(u32, 1 + max_retries), broken.flaky_seen.load(.acquire));
    try std.testing.expect(std.mem.indexOf(u8, why, "HTTP 500") != null);

    // A 404 is the answer at once.
    var missing: TestServer = .{ .body = ar.tgz };
    try missing.start();
    defer missing.stop();
    try std.testing.expectError(error.NotFound, download(arena, std.testing.allocator, io, .{
        .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/nope", .{missing.port}),
        .backoff_ms = 1,
    }, dest, &why));
    try std.testing.expectEqual(@as(u32, 1), missing.requests.load(.acquire));
}

test "an allocation that fails is OutOfMemory, not a failed download" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ar = try testArchive(arena, &tmp);
    var srv: TestServer = .{ .archive_path = "/o/r/archive/v1.tar.gz", .body = ar.tgz };
    try srv.start();
    defer srv.stop();
    const io = std.testing.io;
    const dest = try std.fmt.allocPrint(arena, "{s}/got.tgz", .{ar.root});
    const src: Source = .{ .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/o/r/archive/v1.tar.gz", .{srv.port}) };
    // Each allocation fails in turn, in the step's arena (a token makes it allocate) and then in
    // the client's: the outcome is never a message.
    const with_token: Source = .{ .url = src.url, .token = "tok" };
    inline for (.{ true, false }) |in_arena| {
        var index: usize = 0;
        while (true) : (index += 1) {
            var failing: std.testing.FailingAllocator = .init(std.testing.allocator, .{ .fail_index = index });
            var scratch = @import("../alloc_failures.zig").Scratch.init(if (in_arena) failing.allocator() else std.testing.allocator);
            defer scratch.deinit();
            const gpa = if (in_arena) std.testing.allocator else failing.allocator();
            if (downloadFailure(scratch.allocator(), gpa, io, with_token, dest)) |msg| {
                try std.testing.expect(msg == null);
                try std.testing.expect(index > 0);
                break;
            } else |e| try std.testing.expectEqual(error.OutOfMemory, e);
        }
    }
    // A failure that is the download's own stays one, with its message.
    const bad: Source = .{ .url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}/nope", .{srv.port}) };
    const msg = (try downloadFailure(arena, std.testing.allocator, io, bad, dest)).?;
    try std.testing.expect(std.mem.indexOf(u8, msg, "HTTP 404") != null);
}

test "a ref with an empty, . or .. segment is refused; refs git has are not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    for ([_][]const u8{ "..", ".", "a/../b", "../../user", "a/./b", "a//b", "/a", "a/", "refs/heads/../../x" }) |bad| {
        try std.testing.expect(refProblem(bad) != null);
        try std.testing.expectError(error.InvalidRef, checkoutSource(arena, "https://github.com", "o/r", bad, "tok"));
        try std.testing.expectError(error.InvalidRef, actionSource(arena, "https://github.com", "o/r", bad));
    }
    for ([_][]const u8{ "main", "v1.2.3", "refs/pull/7/merge", "feat/a..b", ".hidden/x", "0123456789abcdef0123456789abcdef01234567" }) |ok|
        try std.testing.expect(refProblem(ok) == null);
}

test "gitMissing: the shell's own not-found forms for git, and no other 127" {
    const ended: sandbox.Ended = .{ .code = 127, .failure = "" };
    var c: Backend.Captured = .{ .arena = std.testing.allocator };
    defer c.text.deinit(std.testing.allocator);
    for ([_][]const u8{
        "sh: 1: git: not found\n",
        "set -e\nsh: git: not found\n",
        "bash: line 3: git: command not found\n",
        "sh: /usr/bin/git: No such file or directory\r\n",
        "git: not found",
    }) |text| {
        c.text.clearRetainingCapacity();
        try c.text.appendSlice(std.testing.allocator, text);
        try std.testing.expect(Backend.gitMissing(ended, &c));
    }
    // 127 from another tool, with git named in what it printed; and git-named things that are not git.
    for ([_][]const u8{
        "sh: 1: sed: not found\nfetching git history\n",
        "sh: 1: git-lfs: not found\n",
        "sh: 1: legit: not found\n",
        "git failed: sh: 1: curl: not found\n",
        "fatal: unable to access 'https://x/git: not found'\n",
        "",
    }) |text| {
        c.text.clearRetainingCapacity();
        try c.text.appendSlice(std.testing.allocator, text);
        try std.testing.expect(!Backend.gitMissing(ended, &c));
    }
    // Only exit 127 without a sandbox failure counts.
    c.text.clearRetainingCapacity();
    try c.text.appendSlice(std.testing.allocator, "sh: 1: git: not found\n");
    try std.testing.expect(!Backend.gitMissing(.{ .code = 1, .failure = "" }, &c));
    try std.testing.expect(!Backend.gitMissing(.{ .code = 127, .failure = "oom" }, &c));
}

test "commitMismatch: a requested commit must be the archive's, naming both when not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const one = "0123456789abcdef0123456789abcdef01234567";
    const two = "fedcba9876543210fedcba9876543210fedcba98";
    try std.testing.expect((try commitMismatch(arena, one, one)) == null);
    try std.testing.expect((try commitMismatch(arena, "0123456789ABCDEF0123456789abcdef01234567", one)) == null);
    // Nothing requested, a ref that is not a commit, or an archive that says nothing: no comparison.
    try std.testing.expect((try commitMismatch(arena, null, one)) == null);
    try std.testing.expect((try commitMismatch(arena, "v1", one)) == null);
    try std.testing.expect((try commitMismatch(arena, one, null)) == null);
    const msg = (try commitMismatch(arena, one, two)).?;
    try std.testing.expect(std.mem.indexOf(u8, msg, one) != null and std.mem.indexOf(u8, msg, two) != null);
}

test "extraction makes a mode 000 directory usable by the job's user" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // An archive whose directories and files all have mode 000, made by GNU tar (skipped without it).
    const make = try std.fmt.allocPrint(arena, "set -e; cd '{s}'; mkdir -p top/locked/inner; echo a > top/locked/inner/f; echo b > top/g; " ++
        "mkdir dl; tar -czf dl/source.tar.gz --mode='u-rwx,g-rwx,o-rwx' top", .{root});
    const made = std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", make } }) catch return error.SkipZigTest;
    if (made.term != .exited or made.term.exited != 0) return error.SkipZigTest;
    const script = try extractScriptFrom(arena, try std.fmt.allocPrint(arena, "{s}/out", .{root}), try std.fmt.allocPrint(arena, "{s}/dl", .{root}));
    const ran = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", script } });
    errdefer std.debug.print("{s}{s}\n", .{ ran.stdout, ran.stderr });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, ran.term);
    const listed = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", try std.fmt.allocPrint(arena, "cd '{s}/out' && find . -printf '%P|%m\\n' | LC_ALL=C sort", .{root}) } });
    try std.testing.expectEqualStrings("g|644\nlocked/inner/f|644\nlocked/inner|755\nlocked|755\n|755\n", listed.stdout);
}

/// The listing a job prints of its workspace, for comparing a tree from git with one from a tarball:
/// every path but `.git` with its type, mode, size and mtime, and the files' hashes.
const tree_listing = "echo BEGIN-LIST''ING; find . -path ./.git -prune -o -printf '%P|%y|%m|%s|%T@\\n' | sort; " ++
    "find . -path ./.git -prune -o -type f -exec sha256sum {} + | sort -k2; readlink link; echo END-LIST''ING";

fn expectSucceeded(res: dagger.Result, text: []const u8, steps: usize) !void {
    for (res.steps[0..steps]) |st| if (st.outcome != .success) {
        std.debug.print("a step failed ({s}); engine {s}\n{s}\n", .{ @tagName(st.outcome), res.engine_error orelse "-", text });
        return error.TestUnexpectedResult;
    };
}

test "native checkout in an image with no git: the tarball's tree is the git checkout's (oracle), and the token stays with the API" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    const ar = try testArchive(arena, &tmp);
    // The oracle's repository, at a file:// URL the steps see at the same path.
    try tmp.dir.createDirPath(io, "o");
    const cloned = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", try std.fmt.allocPrint(arena, "cd '{s}' && git clone -q --bare src o/r.git", .{ar.root}) } });
    try std.testing.expectEqual(@as(u8, 0), cloned.term.exited);
    try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "rootfs/{s}", .{ar.root}));
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{ .host = ar.root, .at = ar.root }} });

    var co = testStep("");
    co.name = "checkout";
    co.action = .{ .checkout = &.{.{ .name = "ref", .value = .{ .lit = ar.sha } }} };
    const check = testStep(tree_listing);

    // With git: the old path, and the reference.
    var env: std.process.Environ.Map = .init(arena);
    var w1: Io.Writer.Allocating = .init(arena);
    var log1: sink.LogSink = .{ .stdout = .{ .writer = &w1.writer } };
    var job1 = testJob(&.{ co, check });
    job1.github.server_url = try std.fmt.allocPrint(arena, "file://{s}", .{ar.root});
    job1.env = &.{.{ .name = "GIT_CONFIG_PARAMETERS", .value = .{ .lit = "'safe.directory=*'" } }};
    const res1 = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job1, &log1);
    try expectSucceeded(res1, w1.written(), 2);

    // Without: a `git` that is not found, and the tarball from a server.
    try tmp.dir.writeFile(io, .{ .sub_path = "nogit.sh", .data = "#!/bin/sh\necho \"sh: 1: git: not found\" >&2\nexit 127\n", .flags = .{ .permissions = .fromMode(0o755) } });
    var cfg2 = cfg;
    cfg2.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/nogit.sh", .{ar.root}),
        .at = "/usr/bin/git",
    }} });
    var srv: TestServer = .{
        .api_path = try std.fmt.allocPrint(arena, "/api/v3/repos/o/r/tarball/{s}", .{ar.sha}),
        .body = ar.tgz,
    };
    try srv.start();
    defer srv.stop();
    var w2: Io.Writer.Allocating = .init(arena);
    var log2: sink.LogSink = .{ .stdout = .{ .writer = &w2.writer } };
    var job2 = testJob(&.{ co, check });
    job2.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{srv.port});
    job2.secret_vars = &.{.{ .name = "GITHUB_TOKEN", .value = "tok-123" }};
    const res2 = try dagger.run(arena, io, &env, .{ .native = cfg2, .step_user = .root, .gpa = std.testing.allocator }, job2, &log2);
    try expectSucceeded(res2, w2.written(), 2);

    try std.testing.expect(std.mem.indexOf(u8, w2.written(), "the repository's tarball (the job's image has no git)") != null);
    try std.testing.expectEqualStrings("Bearer tok-123", srv.api_auth[0..srv.api_auth_len.load(.acquire)]);
    try std.testing.expect(!srv.cdn_saw_auth.load(.acquire));
    try std.testing.expect(std.mem.indexOf(u8, w2.written(), "tok-123") == null);
    // The same tree: what the listing says between its markers, whichever fetched it.
    const want = between(w1.written(), "BEGIN-LISTING", "END-LISTING");
    const got = between(w2.written(), "BEGIN-LISTING", "END-LISTING");
    if (!std.mem.eql(u8, want, got) or want.len < 100) {
        std.debug.print("git's tree:\n{s}\nthe tarball's:\n{s}\n", .{ want, got });
        return error.TestUnexpectedResult;
    }
    if (std.mem.indexOf(u8, got, "946684800") == null or std.mem.indexOf(u8, got, "run.sh|f|755|") == null) {
        std.debug.print("the listing:\n{s}\n", .{got});
        return error.TestUnexpectedResult;
    }
}

fn between(text: []const u8, from: []const u8, to: []const u8) []const u8 {
    const start = (std.mem.indexOf(u8, text, from) orelse return "") + from.len;
    const end = std.mem.indexOfPos(u8, text, start, to) orelse return "";
    return std.mem.trim(u8, text[start..end], "\n ");
}

test "a remote action fetched in an image with no git: its archive extracted, the commit read from it (oracle: git's own)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    const ar = try testArchiveOf(arena, &tmp, "printf 'inputs:\\n  v: {}\\nruns:\\n  using: composite\\n  steps:\\n" ++
        "    - shell: bash\\n      run: echo composite-ran ${{ inputs.v }} from $GITHUB_ACTION_PATH; ls $GITHUB_ACTION_PATH\\n' > action.yml; echo marker > data.txt");
    try tmp.dir.writeFile(io, .{ .sub_path = "nogit.sh", .data = "#!/bin/sh\necho \"sh: 1: git: not found\" >&2\nexit 127\n", .flags = .{ .permissions = .fromMode(0o755) } });
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/nogit.sh", .{ar.root}),
        .at = "/usr/bin/git",
    }} });
    var srv: TestServer = .{ .archive_path = "/o/act/archive/v1.tar.gz", .body = ar.tgz };
    try srv.start();
    defer srv.stop();

    const v = [_]job_mod.Input{.{ .name = "v", .value = .{ .lit = "7" } }};
    const steps = [_]job_mod.Step{usesStep("act", "o", "act", "v1", &v)};
    var job = testJob(&steps);
    job.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{srv.port});
    var env: std.process.Environ.Map = .init(arena);
    var w: Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log);
    errdefer std.debug.print("{s}\n", .{w.written()});
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[0].outcome);
    const text = w.written();
    // The commit is the one `git archive` recorded; the action ran from its extracted tree.
    try std.testing.expect(std.mem.indexOf(u8, text, try std.fmt.allocPrint(arena, "Download action repository 'o/act@v1' (SHA:{s})", .{ar.sha})) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "composite-ran 7 from /github/_actions/o/act/v1") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "data.txt") != null);
    try std.testing.expect(!srv.cdn_saw_auth.load(.acquire));
}

test "an action on a host the workflow names is not downloaded by the runner in an image with no git; the instance's own server still is" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    const ar = try testArchiveOf(arena, &tmp, "printf 'runs:\\n  using: composite\\n  steps:\\n    - shell: bash\\n      run: echo instance-ran\\n' > action.yml");
    try tmp.dir.writeFile(io, .{ .sub_path = "nogit.sh", .data = "#!/bin/sh\necho \"sh: 1: git: not found\" >&2\nexit 127\n", .flags = .{ .permissions = .fromMode(0o755) } });
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/nogit.sh", .{ar.root}),
        .at = "/usr/bin/git",
    }} });
    // The host's loopback: the instance's server, and another service of the host's the workflow
    // points a URL at.
    var instance: TestServer = .{ .archive_path = "/o/act/archive/v1.tar.gz", .body = ar.tgz };
    try instance.start();
    defer instance.stop();
    var other: TestServer = .{ .archive_path = "/o/act/archive/v1.tar.gz", .body = ar.tgz };
    try other.start();
    defer other.stop();

    // First the foreign host alone: refused, the reason said, nothing reached.
    var steps = [_]job_mod.Step{ usesStep("foreign", "o", "act", "v1", &.{}), usesStep("own", "o", "act", "v1", &.{}) };
    steps[0].action.uses.source = .url;
    steps[0].action.uses.url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{other.port});
    var job = testJob(steps[0..1]);
    job.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{instance.port});
    var env: std.process.Environ.Map = .init(arena);
    var w: Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    var res = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log);
    errdefer std.debug.print("{s}\n", .{w.written()});
    try std.testing.expect(res.steps.len == 0 or res.steps[0].outcome != .success);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "the runner does not fetch other hosts from its own network") != null);
    try std.testing.expectEqual(@as(u32, 0), other.requests.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), instance.requests.load(.acquire));

    // The instance's own server, in the same image: fetched.
    w.clearRetainingCapacity();
    job = testJob(steps[1..2]);
    job.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{instance.port});
    res = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log);
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[0].outcome);
    try std.testing.expect(std.mem.indexOf(u8, w.written(), "instance-ran") != null);
    try std.testing.expect(instance.requests.load(.acquire) > 0);
    try std.testing.expectEqual(@as(u32, 0), other.requests.load(.acquire));
}

test "after the first fetch finds no git, the next action's fetch does not run git again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    const ar = try testArchiveOf(arena, &tmp, "printf 'runs:\\n  using: composite\\n  steps:\\n    - shell: bash\\n      run: echo ran\\n' > action.yml");
    // A git that counts its runs, in a file of the test's directory (bound in the step, where the
    // job's user is not the test's: the file is open to all).
    try tmp.dir.writeFile(io, .{ .sub_path = "git-runs", .data = "" });
    const opened = try std.process.run(arena, io, .{ .argv = &.{ "chmod", "a+rwx", ar.root, try std.fmt.allocPrint(arena, "{s}/git-runs", .{ar.root}) } });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, opened.term);
    try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "rootfs/{s}", .{ar.root}));
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{ .host = ar.root, .at = ar.root, .read_only = false }} });
    try tmp.dir.writeFile(io, .{ .sub_path = "nogit.sh", .data = try std.fmt.allocPrint(
        arena,
        "#!/bin/sh\necho x >> '{s}/git-runs'\necho \"sh: 1: git: not found\" >&2\nexit 127\n",
        .{ar.root},
    ), .flags = .{ .permissions = .fromMode(0o755) } });
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/nogit.sh", .{ar.root}),
        .at = "/usr/bin/git",
    }} });
    var srv: TestServer = .{ .archive_path = "/o/one/archive/v1.tar.gz", .archive_path2 = "/o/two/archive/v1.tar.gz", .body = ar.tgz };
    try srv.start();
    defer srv.stop();

    const steps = [_]job_mod.Step{ usesStep("one", "o", "one", "v1", &.{}), usesStep("two", "o", "two", "v1", &.{}) };
    var job = testJob(&steps);
    job.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{srv.port});
    var env: std.process.Environ.Map = .init(arena);
    var w: Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log);
    errdefer std.debug.print("{s}\n", .{w.written()});
    try expectSucceeded(res, w.written(), 2);
    const runs = try tmp.dir.readFileAlloc(io, "git-runs", arena, .limited(1 << 12));
    try std.testing.expectEqualStrings("x\n", runs);
}

test "an action pinned to a commit the archive is not: the step says both" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    const ar = try testArchiveOf(arena, &tmp, "printf 'runs:\\n  using: composite\\n  steps:\\n    - shell: bash\\n      run: echo ran\\n' > action.yml");
    try tmp.dir.writeFile(io, .{ .sub_path = "nogit.sh", .data = "#!/bin/sh\necho \"sh: 1: git: not found\" >&2\nexit 127\n", .flags = .{ .permissions = .fromMode(0o755) } });
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/nogit.sh", .{ar.root}),
        .at = "/usr/bin/git",
    }} });
    const asked = "fedcba9876543210fedcba9876543210fedcba98";
    var srv: TestServer = .{ .archive_path = "/o/act/archive/" ++ asked ++ ".tar.gz", .body = ar.tgz };
    try srv.start();
    defer srv.stop();
    const steps = [_]job_mod.Step{usesStep("act", "o", "act", asked, &.{})};
    var job = testJob(&steps);
    job.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{srv.port});
    var env: std.process.Environ.Map = .init(arena);
    var w: Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log);
    errdefer std.debug.print("{s}\n", .{w.written()});
    try std.testing.expect(res.steps[0].outcome != .success);
    const text = w.written();
    try std.testing.expect(std.mem.indexOf(u8, text, asked) != null);
    try std.testing.expect(std.mem.indexOf(u8, text, ar.sha) != null);
}

test "an action fetch over the tarball whose connection is dropped every time once is tried again, and the job runs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.fetch_backoff_ms = 1;
    const ar = try testArchiveOf(arena, &tmp, "printf 'runs:\\n  using: composite\\n  steps:\\n" ++
        "    - shell: bash\\n      run: echo composite-ran\\n' > action.yml");
    try tmp.dir.writeFile(io, .{ .sub_path = "nogit.sh", .data = "#!/bin/sh\necho \"sh: 1: git: not found\" >&2\nexit 127\n", .flags = .{ .permissions = .fromMode(0o755) } });
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/nogit.sh", .{ar.root}),
        .at = "/usr/bin/git",
    }} });
    var srv: TestServer = .{ .archive_path = "/o/act/archive/v1.tar.gz", .body = ar.tgz, .drop_first = http.staleRetries(null) + 1 };
    try srv.start();
    defer srv.stop();

    const steps = [_]job_mod.Step{usesStep("act", "o", "act", "v1", &.{})};
    var job = testJob(&steps);
    job.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{srv.port});
    var env: std.process.Environ.Map = .init(arena);
    var w: Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log);
    const text = w.written();
    errdefer std.debug.print("{s}\n", .{text});
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[0].outcome);
    // The first fetch met a connection closed on every try (the client's own stale-connection
    // retries, `staleRetries`, all spent); the second got the archive.
    try std.testing.expectEqual(http.staleRetries(null) + 2, srv.requests.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "##[warning]Failed to fetch action 'o/act@v1' (attempt 1 of 5): could not download "));
    try std.testing.expect(std.mem.indexOf(u8, text, "Download action repository 'o/act@v1' (SHA:") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "composite-ran") != null);
}

test "an action fetch over the tarball that gets a 404 is not tried again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.fetch_backoff_ms = 1;
    try tmp.dir.writeFile(io, .{ .sub_path = "nogit.sh", .data = "#!/bin/sh\necho \"sh: 1: git: not found\" >&2\nexit 127\n", .flags = .{ .permissions = .fromMode(0o755) } });
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/nogit.sh", .{try tmp.dir.realPathFileAlloc(io, ".", arena)}),
        .at = "/usr/bin/git",
    }} });
    var srv: TestServer = .{ .body = "" };
    try srv.start();
    defer srv.stop();
    const steps = [_]job_mod.Step{usesStep("act", "o", "act", "v1", &.{})};
    var job = testJob(&steps);
    job.github.server_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{srv.port});
    var env: std.process.Environ.Map = .init(arena);
    var w: Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{ .native = cfg, .step_user = .root, .gpa = std.testing.allocator }, job, &log);
    const text = w.written();
    errdefer std.debug.print("{s}\n", .{text});
    try std.testing.expect(!res.succeeded and res.set_up_failed);
    try std.testing.expectEqual(@as(u32, 1), srv.requests.load(.acquire));
    try std.testing.expect(std.mem.indexOf(u8, text, "Failed to fetch action") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "HTTP 404") != null);
}
