//! JIT runner registration: `generate-jitconfig` call and `encoded_jit_config` decoding (SPEC §3).
const std = @import("std");
const Config = @import("../config.zig").Config;
const Scope = @import("../config.zig").Scope;
const broker = @import("broker.zig");
const net_client = @import("../net_client.zig");
const app = @import("app.zig");

const Allocator = std.mem.Allocator;

/// The REST API version every call here asks for.
const api_version_header: std.http.Header = .{
    .name = "X-GitHub-Api-Version",
    .value = "2022-11-28",
};

pub const File = struct {
    name: []const u8,
    content: []const u8,
};

pub const Jit = struct {
    runner_id: u64,
    runner_name: []const u8,
    /// Decoded files (runner settings, RSA credentials, OAuth credential data). Sensitive.
    files: []const File,
};

pub const Error = error{
    /// Non-2xx from GitHub. Maps to exit code 2.
    GithubRejected,
    BadResponse,
} || Allocator.Error || net_client.Error || std.Io.Writer.Error || app.Error;

/// The token runner management sends: `GH_TOKEN`, or the GitHub App's installation token. When
/// GitHub will not give the App one, its status and reason go to `status_out` and `message_out`.
fn token(
    arena: Allocator,
    io: std.Io,
    cfg: *const Config,
    status_out: *std.http.Status,
    message_out: *[]const u8,
) app.Error![]const u8 {
    const a = cfg.app_auth orelse return cfg.gh_token;
    return a.token(arena, io, status_out, message_out);
}

/// A runner-management request with no body, with the configured credentials. With a GitHub App,
/// a 401 drops the cached installation token (revoked, or the App's permissions changed) and the
/// request goes once more with a new one: GitHub processed nothing it answered 401.
fn manage(
    arena: Allocator,
    io: std.Io,
    cfg: *const Config,
    method: std.http.Method,
    url: []const u8,
) !broker.Response {
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        var status: std.http.Status = .ok;
        var message: []const u8 = "";
        const t = try token(arena, io, cfg, &status, &message);
        const r = try broker.request(arena, io, method, url, null, .{
            .token = t,
            .extra_headers = &.{api_version_header},
        });
        if (r.status != .unauthorized or attempt > 0) return r;
        const a = cfg.app_auth orelse return r;
        a.invalidate(io, t);
    }
}

fn runnersUrl(arena: Allocator, cfg: *const Config) Allocator.Error![]const u8 {
    return switch (cfg.scope) {
        .repo => |r| std.fmt.allocPrint(
            arena,
            "https://api.github.com/repos/{s}/{s}/actions/runners",
            .{ r.owner, r.name },
        ),
        .org => |o| std.fmt.allocPrint(
            arena,
            "https://api.github.com/orgs/{s}/actions/runners",
            .{o},
        ),
    };
}

/// Removes a registered runner (cleanup for runners that never ran a job). Goes through
/// `broker.request`: GitHub answers 204 with no Content-Length, and `std.http.Client.fetch` then
/// waits on the idle connection until GitHub closes it, which kept the runner from exiting for
/// minutes after its job.
pub fn deleteRunner(
    arena: Allocator,
    io: std.Io,
    cfg: *const Config,
    runner_id: u64,
) !std.http.Status {
    const url = try std.fmt.allocPrint(
        arena,
        "{s}/{d}",
        .{ try runnersUrl(arena, cfg), runner_id },
    );
    const r = try manage(arena, io, cfg, .DELETE, url);
    return r.status;
}

/// Request a JIT config for `name`. All returned memory is allocated from `arena`.
/// `status_out` receives the HTTP status, and `message_out` GitHub's reason when it refuses
/// ("Resource not accessible by personal access token"), for diagnostics.
pub fn generate(
    arena: Allocator,
    io: std.Io,
    cfg: *const Config,
    name: []const u8,
    status_out: *std.http.Status,
    message_out: *[]const u8,
) Error!Jit {
    const url = try std.fmt.allocPrint(
        arena,
        "{s}/generate-jitconfig",
        .{try runnersUrl(arena, cfg)},
    );

    var labels: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, cfg.labels, ',');
    while (it.next()) |l| try labels.append(arena, std.mem.trim(u8, l, " "));

    var body: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(.{
        .name = name,
        .runner_group_id = cfg.runner_group_id,
        .labels = labels.items,
    }, .{}, &body.writer);

    var resp: []const u8 = "";
    // Sent again only after a 401 with a GitHub App, with a new token (see `manage`): a
    // registration GitHub refused was not made, so the second does not make two.
    var attempt: u32 = 0;
    const result = while (true) : (attempt += 1) {
        const t = try token(arena, io, cfg, status_out, message_out);
        const r = try net_client.fetch(arena, io, .{
            .url = url,
            .method = .POST,
            .payload = body.written(),
            .headers = &.{
                .{ .name = "Authorization", .value = try std.fmt.allocPrint(arena, "Bearer {s}", .{t}) },
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Accept", .value = "application/vnd.github+json" },
                api_version_header,
            },
            .retry = attempt,
        });
        resp = r.body;
        if (r.status != .unauthorized or attempt > 0) break r;
        const a = cfg.app_auth orelse break r;
        a.invalidate(io, t);
    };
    status_out.* = result.status;
    if (result.status.class() != .success) {
        message_out.* = errorMessage(arena, resp);
        return error.GithubRejected;
    }

    return parseResponse(arena, resp);
}

/// The `message` of a GitHub API error body; "" when there is none.
pub fn errorMessage(arena: Allocator, body: []const u8) []const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return "";
    if (v != .object) return "";
    const m = v.object.get("message") orelse return "";
    return if (m == .string) m.string else "";
}

test "a refusal says why" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    try std.testing.expectEqualStrings("Resource not accessible by personal access token", errorMessage(a.allocator(), "{\"message\":\"Resource not accessible by personal access token\",\"documentation_url\":\"x\",\"status\":\"403\"}"));
    try std.testing.expectEqualStrings("", errorMessage(a.allocator(), "<html>"));
}

/// Parse the `generate-jitconfig` response body.
pub fn parseResponse(arena: Allocator, body: []const u8) Error!Jit {
    const Resp = struct {
        runner: struct { id: u64, name: []const u8 },
        encoded_jit_config: []const u8,
    };
    const parsed = std.json.parseFromSliceLeaky(
        Resp,
        arena,
        body,
        .{ .ignore_unknown_fields = true },
    ) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadResponse,
    };
    return .{
        .runner_id = parsed.runner.id,
        .runner_name = parsed.runner.name,
        .files = decode(arena, parsed.encoded_jit_config) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadResponse,
        },
    };
}

/// `encoded_jit_config` is base64 JSON `{ "<filename>": "<base64 content>" }`.
pub fn decode(arena: Allocator, encoded: []const u8) ![]const File {
    const dec = std.base64.standard.Decoder;
    const json_bytes = try arena.alloc(u8, try dec.calcSizeForSlice(encoded));
    try dec.decode(json_bytes, encoded);

    const map = try std.json.parseFromSliceLeaky(
        std.json.ArrayHashMap([]const u8),
        arena,
        json_bytes,
        .{},
    );
    const files = try arena.alloc(File, map.map.count());
    for (map.map.keys(), map.map.values(), files) |k, v, *f| {
        const content = try arena.alloc(u8, try dec.calcSizeForSlice(v));
        try dec.decode(content, v);
        f.* = .{ .name = k, .content = content };
    }
    return files;
}

test "decode nested base64 files" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // {".runner":"aGVsbG8=",".credentials":"d29ybGQ="}
    const enc = "eyIucnVubmVyIjoiYUdWc2JHOD0iLCIuY3JlZGVudGlhbHMiOiJkMjl5YkdRPSJ9";
    const files = try decode(arena, enc);
    try std.testing.expectEqual(@as(usize, 2), files.len);
    try std.testing.expectEqualStrings(".runner", files[0].name);
    try std.testing.expectEqualStrings("hello", files[0].content);
    try std.testing.expectEqualStrings("world", files[1].content);
}

test "parse generate-jitconfig response" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const body =
        \\{"runner":{"id":23,"name":"zig-h-1","os":"unknown","status":"offline"},
        \\ "encoded_jit_config":"eyIucnVubmVyIjoiYUdWc2JHOD0ifQ=="}
    ;
    const jit = try parseResponse(arena_state.allocator(), body);
    try std.testing.expectEqual(@as(u64, 23), jit.runner_id);
    try std.testing.expectEqualStrings("hello", jit.files[0].content);
}

test "bad response" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.BadResponse, parseResponse(arena_state.allocator(), "{}"));
}

/// The repository's current name when GitHub knows it by another than GH_SCOPE's (it was renamed
/// or transferred), else null. GitHub redirects requests for the old name, but registering a runner
/// sends a body, which cannot follow a redirect; so the runner asks once, at start, and uses the
/// current name. Null too for an organization, or when GitHub could not say: the runner then goes
/// on with GH_SCOPE as given, and any real problem shows on registering.
pub fn movedRepo(arena: Allocator, io: std.Io, cfg: *const Config) ?Scope {
    const r = switch (cfg.scope) {
        .repo => |r| r,
        .org => return null,
    };
    const url = std.fmt.allocPrint(
        arena,
        "https://api.github.com/repos/{s}/{s}",
        .{ r.owner, r.name },
    ) catch return null;
    const resp = manage(arena, io, cfg, .GET, url) catch return null;
    if (resp.status.class() != .success) return null;
    return currentName(arena, cfg.scope, resp.body);
}

/// The repository's `full_name` from GitHub's answer, when it is not `scope` (names compare without
/// case, as GitHub's do).
fn currentName(arena: Allocator, scope: Scope, body: []const u8) ?Scope {
    const Repo = struct { full_name: []const u8 };
    const repo = std.json.parseFromSliceLeaky(Repo, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    const now = Scope.parse(repo.full_name) catch return null;
    const was = scope.repo;
    if (std.ascii.eqlIgnoreCase(was.owner, now.repo.owner) and
        std.ascii.eqlIgnoreCase(was.name, now.repo.name)) return null;
    return now;
}

/// This instance's registrations that look left behind by a stopped runner: offline, idle, and
/// named `<prefix>-<8 hex digits>` as this runner names its own, from every page of the list. Each
/// was registered for one just-in-time session, which cannot be resumed. A registration another
/// process with the same prefix has just made looks the same until its runner connects (seconds),
/// so these are only candidates: `removeStillStale` removes those still offline a while later.
pub fn staleRegistrations(arena: Allocator, io: std.Io, cfg: *const Config) ![]const u64 {
    const GitHub = struct {
        arena: Allocator,
        io: std.Io,
        cfg: *const Config,
        base: []const u8,

        fn page(g: @This(), n: u32) ![]const u8 {
            const url = try std.fmt.allocPrint(
                g.arena,
                "{s}?per_page={d}&page={d}",
                .{ g.base, per_page, n },
            );
            const resp = try manage(g.arena, g.io, g.cfg, .GET, url);
            if (resp.status.class() != .success) return error.GithubRejected;
            return resp.body;
        }
    };
    return collectStale(arena, cfg.name_prefix, GitHub{
        .arena = arena,
        .io = io,
        .cfg = cfg,
        .base = try runnersUrl(arena, cfg),
    });
}

/// The stale-looking registrations from `pages.page(1)`, `pages.page(2)`, ... up to the first page
/// with fewer than `per_page` runners (a full last page costs one more, empty, request).
fn collectStale(arena: Allocator, prefix: []const u8, pages: anytype) ![]const u64 {
    var ids: std.ArrayList(u64) = .empty;
    var n: u32 = 1;
    while (n <= max_pages) : (n += 1) {
        const found = try staleIds(arena, try pages.page(n), prefix);
        try ids.appendSlice(arena, found.ids);
        if (found.listed < per_page) break;
    }
    return ids.items;
}

/// How long a stale-looking registration must stay so before it is removed: far longer than a new
/// one takes to connect.
pub const stale_confirm_seconds = 60;

const per_page = 100;
/// 10,000 runners; a list longer than that is not this runner's to page through at every start.
const max_pages = 100;

/// Removes the registrations in `earlier` that still look left behind (see `staleRegistrations`).
/// Returns how many were removed; failures are left for the next start.
pub fn removeStillStale(
    arena: Allocator,
    io: std.Io,
    cfg: *const Config,
    earlier: []const u64,
) u32 {
    const now = staleRegistrations(arena, io, cfg) catch return 0;
    var removed: u32 = 0;
    for (stillStale(earlier, now)) |id| {
        const status = deleteRunner(arena, io, cfg, id) catch continue;
        if (status.class() == .success) removed += 1;
    }
    return removed;
}

/// The ids in both lists, in `earlier`'s order (ids are few: a quadratic scan is fine). Reuses
/// `earlier`'s memory, which the caller does not need again.
fn stillStale(earlier: []const u64, now: []const u64) []const u64 {
    const out = @constCast(earlier);
    var n: usize = 0;
    for (earlier) |id| if (std.mem.indexOfScalar(u64, now, id) != null) {
        out[n] = id;
        n += 1;
    };
    return out[0..n];
}

/// The stale-looking registrations in one page of `GET .../actions/runners`, and how many runners
/// the page listed (fewer than asked for: the last page).
fn staleIds(
    arena: Allocator,
    body: []const u8,
    prefix: []const u8,
) !struct { ids: []const u64, listed: usize } {
    const Runners = struct {
        runners: []const struct { id: u64, name: []const u8, status: []const u8, busy: bool },
    };
    const list = try std.json.parseFromSliceLeaky(Runners, arena, body, .{
        .ignore_unknown_fields = true,
    });
    var ids: std.ArrayList(u64) = .empty;
    for (list.runners) |r| {
        if (!std.mem.eql(u8, r.status, "offline") or r.busy) continue;
        if (!ownName(r.name, prefix)) continue;
        try ids.append(arena, r.id);
    }
    return .{ .ids = ids.items, .listed = list.runners.len };
}

/// Whether `name` is one this runner gives its registrations: `<prefix>-` and 8 hex digits (four
/// random bytes, as `main.runnerName` writes them).
fn ownName(name: []const u8, prefix: []const u8) bool {
    if (name.len != prefix.len + "-".len + 8) return false;
    if (!std.mem.startsWith(u8, name, prefix) or name[prefix.len] != '-') return false;
    for (name[prefix.len + 1 ..]) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

test "a moved repository's current name" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const old: Scope = .{ .repo = .{ .owner = "Lementknight", .name = "zig-runner" } };
    const moved = currentName(a.allocator(), old, "{\"id\":1,\"full_name\":\"Open-Blue/zig-runner\"}").?;
    try std.testing.expectEqualStrings("Open-Blue", moved.repo.owner);
    try std.testing.expectEqualStrings("zig-runner", moved.repo.name);
    // The same name, whatever its case, is not a move; nor is an answer without one.
    try std.testing.expectEqual(null, currentName(a.allocator(), old, "{\"full_name\":\"lementknight/Zig-Runner\"}"));
    try std.testing.expectEqual(null, currentName(a.allocator(), old, "{\"message\":\"Not Found\"}"));
    try std.testing.expectEqual(null, currentName(a.allocator(), old, "<html>"));
}

test "stale registrations: offline, idle, and named as this runner names its own" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const body =
        \\{"total_count":6,"runners":[
        \\ {"id":24,"name":"zig-ci-9216e058","status":"offline","busy":false,"labels":[]},
        \\ {"id":25,"name":"zig-ci-2f160103","status":"online","busy":false},
        \\ {"id":26,"name":"zig-ci-41ef27a0","status":"offline","busy":true},
        \\ {"id":27,"name":"zig-ci-handmade","status":"offline","busy":false},
        \\ {"id":28,"name":"zig-sandbox-0a1b2c3d","status":"offline","busy":false},
        \\ {"id":29,"name":"zig-ci-0a1b2c3d4","status":"offline","busy":false}
        \\]}
    ;
    const found = try staleIds(a.allocator(), body, "zig-ci");
    try std.testing.expectEqualSlices(u64, &.{24}, found.ids);
    try std.testing.expectEqual(@as(usize, 6), found.listed);
}

test "only what still looks stale a minute later is removed" {
    // 24 and 31 stayed offline; 30 connected meanwhile (another process's new registration); 32
    // appeared since and waits for the next start.
    var earlier = [_]u64{ 24, 30, 31 };
    try std.testing.expectEqualSlices(u64, &.{ 24, 31 }, stillStale(&earlier, &.{ 31, 24, 32 }));
    var none = [_]u64{30};
    try std.testing.expectEqualSlices(u64, &.{}, stillStale(&none, &.{}));
}

test "stale registrations come from every page" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Pages of `sizes[n - 1]` runners: the first is a stale registration of this instance's
    // (id 1000 + n), the rest online runners named by hand.
    const Fake = struct {
        arena: Allocator,
        sizes: []const usize,
        asked: *u32,

        fn page(f: @This(), n: u32) ![]const u8 {
            f.asked.* += 1;
            var out: std.Io.Writer.Allocating = .init(f.arena);
            const w = &out.writer;
            try w.writeAll("{\"runners\":[");
            const size = if (n <= f.sizes.len) f.sizes[n - 1] else 0;
            for (0..size) |i| {
                if (i > 0) try w.writeAll(",");
                if (i == 0) {
                    try w.print("{{\"id\":{d},\"name\":\"zig-ci-0000000{d}\",\"status\":\"offline\",\"busy\":false}}", .{ 1000 + n, n });
                } else {
                    try w.print("{{\"id\":{d},\"name\":\"other-{d}\",\"status\":\"online\",\"busy\":false}}", .{ n * 1000 + i, i });
                }
            }
            try w.writeAll("]}");
            return out.written();
        }
    };
    var asked: u32 = 0;
    // A full first page and a short second: both stale registrations, and no third request.
    const two = Fake{ .arena = arena, .sizes = &.{ 100, 3 }, .asked = &asked };
    const found = try collectStale(arena, "zig-ci", two);
    try std.testing.expectEqualSlices(u64, &.{ 1001, 1002 }, found);
    try std.testing.expectEqual(@as(u32, 2), asked);
    // Two full pages: a third, empty, request ends it.
    asked = 0;
    const full = Fake{ .arena = arena, .sizes = &.{ 100, 100 }, .asked = &asked };
    try std.testing.expectEqualSlices(u64, &.{ 1001, 1002 }, try collectStale(arena, "zig-ci", full));
    try std.testing.expectEqual(@as(u32, 3), asked);
}

test "with a GitHub App, a 401 gets a new installation token and one more try" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var server: @import("testserver.zig").Server = undefined;
    try server.start();
    defer server.stop();
    const io = std.testing.io;
    var a = try app.testAuth(arena, server.port);
    const cfg: Config = .{ .gh_token = "", .scope = a.scope, .app_auth = &a };
    var buf: [128]u8 = undefined;

    // The server takes only the second token it mints there.
    const r = try manage(arena, io, &cfg, .GET, server.url(&buf, "127.0.0.1", "/app-token/ghs_2"));
    try std.testing.expectEqual(std.http.Status.ok, r.status);
    try std.testing.expectEqual(@as(u32, 2), server.app_tokens.load(.acquire));
    // Never a third: a second 401 is GitHub's answer.
    const no = try manage(arena, io, &cfg, .GET, server.url(&buf, "127.0.0.1", "/app-token/x"));
    try std.testing.expectEqual(std.http.Status.unauthorized, no.status);
    try std.testing.expectEqual(@as(u32, 3), server.app_tokens.load(.acquire));
}
