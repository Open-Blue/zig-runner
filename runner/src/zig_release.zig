//! The Zig releases Zig jobs' global cache is seeded from (`set_up.zig`, "The Zig cache seed"),
//! each checked here, in the runner and outside any job, before it is used: the tarball is
//! downloaded from ziglang.org with its `.minisig`, the signature and its trusted comment are
//! verified against Zig's pinned public key (`minisign.zig`), and only then is the tarball's
//! sha256 handed to the seed build, whose exec checks the tarball it downloads against it. The seed
//! stays a function of the version and that digest, so the engine still caches it by its recipe.
//!
//! Which versions are seeded is configuration (`Config.zig_seed_versions`), never a job's choice,
//! and even a list a job could influence would only pick which official, signed release is seeded,
//! never what is in it. A few at most (`max_versions`): each costs a download at startup, a seed
//! build per engine and about 60 MB in every Zig job's global cache.
const std = @import("std");
const Sha256 = @import("sha256.zig").Sha256;
const builtin = @import("builtin");
const config = @import("config.zig");
const minisign = @import("minisign.zig");
const http = @import("github/http.zig");

/// Zig's minisign public key, as https://ziglang.org/download/ publishes it ("Files are signed with
/// minisign using this public key"), checked there on 2026-10-31.
pub const public_key = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";

pub const max_versions = 3;

/// The release tarball for this machine's architecture (the engine's: they share a host). A
/// development build is under `builds/`, a release under `download/<version>/`.
pub fn tarballUrl(arena: std.mem.Allocator, version: []const u8) ![]const u8 {
    const name = try tarballName(arena, version);
    return if (std.mem.indexOf(u8, version, "-dev.") != null)
        std.fmt.allocPrint(arena, "https://ziglang.org/builds/{s}", .{name})
    else
        std.fmt.allocPrint(arena, "https://ziglang.org/download/{s}/{s}", .{ version, name });
}

fn tarballName(arena: std.mem.Allocator, version: []const u8) ![]const u8 {
    const arch = @tagName(builtin.cpu.arch);
    return std.fmt.allocPrint(arena, "zig-{s}-linux-{s}.tar.xz", .{ arch, version });
}

/// The versions in a comma-separated list, each once, in order, up to `max_versions`. One with a
/// character a version does not have (it goes into a URL and a shell script) is left out.
pub fn versions(arena: std.mem.Allocator, list: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |item| {
        const v = std.mem.trim(u8, item, " ");
        if (!config.validZigVersion(v)) {
            std.log.warn("Zig seed: {s} is not a Zig version, left out", .{v});
            continue;
        }
        for (out.items) |seen| {
            if (std.mem.eql(u8, seen, v)) break;
        } else {
            if (out.items.len == max_versions) {
                std.log.warn("Zig seed: at most {d} versions, {s} left out", .{ max_versions, v });
                continue;
            }
            try out.append(arena, v);
        }
    }
    return out.items;
}

pub const CheckError = minisign.Error || error{WrongFile};

/// The seed for `version` when `minisig` is a valid signature of `tarball` by `pk` whose trusted
/// comment names this release's file (so another release's signed tarball cannot stand in).
pub fn check(
    arena: std.mem.Allocator,
    pk: minisign.PublicKey,
    version: []const u8,
    tarball: []const u8,
    minisig: []const u8,
) (CheckError || std.mem.Allocator.Error)!config.ZigSeed {
    const trusted = try minisign.verify(pk, tarball, minisig);
    const file = try std.mem.concat(arena, u8, &.{ "file:", try tarballName(arena, version) });
    var words = std.mem.tokenizeAny(u8, trusted, " \t");
    while (words.next()) |w| {
        if (std.mem.eql(u8, w, file)) break;
    } else return error.WrongFile;
    var digest: [32]u8 = undefined;
    Sha256.hash(tarball, &digest, .{});
    return .{
        .version = try arena.dupe(u8, version),
        .sha256 = try arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower)),
    };
}

pub const Resolved = struct {
    seeds: []const config.ZigSeed,
    /// The versions that could not be downloaded or did not verify, for "Set up job".
    unverified: []const []const u8,
};

/// The seeds for `list` (`versions`), each downloaded and checked (`check`). One that cannot be
/// downloaded or does not verify is said and left out, so its jobs run unseeded, their global cache
/// still their own.
pub fn resolve(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    client: *std.http.Client,
    list: []const u8,
) !Resolved {
    const pk = minisign.PublicKey.parse(public_key) catch unreachable;
    var out: std.ArrayList(config.ZigSeed) = .empty;
    var unverified: std.ArrayList([]const u8) = .empty;
    for (try versions(arena, list)) |v| {
        // The tarball (about 50 MB) is freed once its digest is taken.
        var tmp: std.heap.ArenaAllocator = .init(gpa);
        defer tmp.deinit();
        const url = try tarballUrl(tmp.allocator(), v);
        const tarball = download(tmp.allocator(), client, url) catch |e| {
            std.log.warn("Zig seed: {s} not seeded, {s}: {s}", .{ v, url, @errorName(e) });
            try unverified.append(arena, v);
            continue;
        };
        const sig_url = try std.mem.concat(tmp.allocator(), u8, &.{ url, ".minisig" });
        const sig = download(tmp.allocator(), client, sig_url) catch |e| {
            std.log.warn("Zig seed: {s} not seeded, {s}: {s}", .{ v, sig_url, @errorName(e) });
            try unverified.append(arena, v);
            continue;
        };
        const seed = check(arena, pk, v, tarball, sig) catch |e| {
            std.log.err(
                "Zig seed: {s} not seeded, its signature does not verify: {s}",
                .{ v, @errorName(e) },
            );
            try unverified.append(arena, v);
            continue;
        };
        std.log.info("Zig seed: {s} verified against Zig's signing key", .{v});
        try out.append(arena, seed);
    }
    return .{ .seeds = out.items, .unverified = unverified.items };
}

/// The seeds jobs get, shared by the process's runners: the configured releases (`resolve`, at
/// startup), and the Zig versions `repo` jobs' tool caches hold (`discover`, from the runner's own
/// tree check, `set_up.verifyToolTrees`), each verified before any job is seeded from it
/// (`forJob`). Every version tried counts against `max_versions`, verified or not, so a tool cache
/// full of made-up versions costs a few failed downloads, once each, and no more. Only `repo` jobs
/// add to it: an untrusted job cannot choose what trusted jobs are seeded from, even among
/// official releases.
pub const Registry = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    client: ?*std.http.Client,
    mu: std.Io.Mutex = .init,
    seeds: std.ArrayList(config.ZigSeed) = .empty,
    unverified: std.ArrayList([]const u8) = .empty,
    pending: std.ArrayList([]const u8) = .empty,
    /// Taken from `pending` by a job verifying them.
    inflight: std.ArrayList([]const u8) = .empty,

    /// Frees what the registry holds in its own allocator, at the pool's end: its lists and the
    /// versions `discover` queued. The seeds' own strings are `resolve`'s arena's.
    pub fn deinit(r: *Registry) void {
        for (r.pending.items) |v| r.gpa.free(v);
        for (r.inflight.items) |v| r.gpa.free(v);
        r.seeds.deinit(r.gpa);
        r.unverified.deinit(r.gpa);
        r.pending.deinit(r.gpa);
        r.inflight.deinit(r.gpa);
    }

    fn known(r: *Registry) usize {
        return r.seeds.items.len + r.unverified.items.len + r.pending.items.len +
            r.inflight.items.len;
    }

    fn has(r: *Registry, v: []const u8) bool {
        for (r.seeds.items) |s| if (std.mem.eql(u8, s.version, v)) return true;
        for (r.unverified.items) |u| if (std.mem.eql(u8, u, v)) return true;
        for (r.pending.items) |p| if (std.mem.eql(u8, p, v)) return true;
        for (r.inflight.items) |p| if (std.mem.eql(u8, p, v)) return true;
        return false;
    }

    /// Starts with what `resolve` found.
    pub fn add(r: *Registry, resolved: Resolved) !void {
        try r.seeds.appendSlice(r.gpa, resolved.seeds);
        try r.unverified.appendSlice(r.gpa, resolved.unverified);
    }

    /// Queues the Zig versions of the tool cache's trees (`DIGEST TREE` lines, TREE
    /// `<tool cache>/zig/<version>/...`) that it does not know, while there is room.
    pub fn discover(r: *Registry, tool_cache: []const u8, trees: []const u8) void {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        var lines = std.mem.tokenizeScalar(u8, trees, '\n');
        while (lines.next()) |line| {
            const tree = line[(std.mem.indexOfScalar(u8, line, ' ') orelse continue) + 1 ..];
            const prefix_len = tool_cache.len + "/zig/".len;
            if (tree.len <= prefix_len or !std.mem.startsWith(u8, tree, tool_cache) or
                !std.mem.eql(u8, tree[tool_cache.len..prefix_len], "/zig/")) continue;
            const rest = tree[prefix_len..];
            const v = rest[0 .. std.mem.indexOfScalar(u8, rest, '/') orelse rest.len];
            if (!config.validZigVersion(v) or r.has(v) or r.known() >= max_versions) continue;
            const copy = r.gpa.dupe(u8, v) catch return;
            r.pending.append(r.gpa, copy) catch return;
            std.log.info("Zig seed: {s} found in a tool cache, to be verified", .{v});
        }
    }

    /// The seeds for a job, copied into `arena`, after verifying what `discover` queued (a
    /// download each, once, outside the lock).
    pub fn forJob(r: *Registry, arena: std.mem.Allocator) !Resolved {
        var taken: []const []const u8 = &.{};
        if (r.client != null) {
            r.mu.lockUncancelable(r.io);
            defer r.mu.unlock(r.io);
            taken = try arena.dupe([]const u8, r.pending.items);
            try r.inflight.appendSlice(r.gpa, r.pending.items);
            r.pending.clearRetainingCapacity();
        }
        if (taken.len > 0) {
            const todo = try std.mem.join(arena, ",", taken);
            const got = try resolve(r.gpa, r.gpa, r.client.?, todo);
            r.mu.lockUncancelable(r.io);
            defer r.mu.unlock(r.io);
            for (taken) |v| for (r.inflight.items, 0..) |w, i| {
                if (std.mem.eql(u8, v, w)) {
                    _ = r.inflight.orderedRemove(i);
                    break;
                }
            };
            try r.add(got);
        }
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        return .{
            .seeds = try arena.dupe(config.ZigSeed, r.seeds.items),
            .unverified = try arena.dupe([]const u8, r.unverified.items),
        };
    }
};

const download_deadline: std.Io.Duration = .fromSeconds(300);
const max_download = 256 * 1024 * 1024;

fn download(arena: std.mem.Allocator, client: *std.http.Client, url: []const u8) ![]const u8 {
    var body: std.Io.Writer.Allocating = .init(arena);
    const r = try http.within(client.io, download_deadline, fetchInto, .{ client, url, &body });
    const status = try (r orelse return error.Timeout);
    if (status != .ok) return error.HttpStatus;
    if (body.written().len > max_download) return error.TooLarge;
    return body.written();
}

fn fetchInto(
    client: *std.http.Client,
    url: []const u8,
    body: *std.Io.Writer.Allocating,
) std.http.Client.FetchError!std.http.Status {
    const res = try client.fetch(.{ .location = .{ .url = url }, .response_writer = &body.writer });
    return res.status;
}

test "a registry frees what it holds: its lists and the versions it queued" {
    var r: Registry = .{ .io = std.testing.io, .gpa = std.testing.allocator, .client = null };
    defer r.deinit();
    const seeds = [_]config.ZigSeed{.{ .version = "0.17.0", .sha256 = "" }};
    try r.add(.{ .seeds = &seeds, .unverified = &.{"0.16.0"} });
    r.discover("/tc", "d /tc/zig/0.15.2/x\nd /tc/zig/0.14.1/y");
    try std.testing.expectEqual(@as(usize, 1), r.pending.items.len);
}

test "versions: each once, in order, at most three, nothing that is not a version" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const got = try versions(arena, "0.17.0, 0.16.0,0.17.0,0.15.2,0.14.1,0.18.0-dev.1+abc");
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try std.testing.expectEqualStrings("0.17.0", got[0]);
    try std.testing.expectEqualStrings("0.16.0", got[1]);
    try std.testing.expectEqualStrings("0.15.2", got[2]);
    try std.testing.expectEqual(@as(usize, 1), (try versions(arena, "0.17.0;rm -rf /,0.17.0")).len);
    try std.testing.expectEqual(@as(usize, 0), (try versions(arena, "")).len);
}

test "tarballUrl: a release under download/, a development build under builds/" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arch = @tagName(builtin.cpu.arch);
    try std.testing.expectEqualStrings("https://ziglang.org/download/0.17.0/zig-" ++ arch ++ "-linux-0.17.0.tar.xz", try tarballUrl(a.allocator(), "0.17.0"));
    try std.testing.expectEqualStrings("https://ziglang.org/builds/zig-" ++ arch ++ "-linux-0.18.0-dev.5+abc.tar.xz", try tarballUrl(a.allocator(), "0.18.0-dev.5+abc"));
}

test "check: a signed tarball gives its sha256; a tampered one, or another release's, gives nothing" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(3));
    const tarball = "a fixture standing in for a Zig tarball";
    const file = try tarballName(arena, "0.17.0");
    const f = try minisign.testing.fixture(arena, kp, tarball, try std.fmt.allocPrint(arena, "timestamp:1\tfile:{s}\thashed", .{file}));
    const pk = try minisign.PublicKey.parse(&f.pk);
    const seed = try check(arena, pk, "0.17.0", tarball, f.minisig);
    try std.testing.expectEqualStrings("0.17.0", seed.version);
    var digest: [32]u8 = undefined;
    Sha256.hash(tarball, &digest, .{});
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(digest, .lower), seed.sha256);
    try std.testing.expectError(error.BadSignature, check(arena, pk, "0.17.0", "a fixture standing in for a Zig tarbalL", f.minisig));
    // A genuine signature of another release's file, served as this one.
    try std.testing.expectError(error.WrongFile, check(arena, pk, "0.16.0", tarball, f.minisig));
    // Signed by another key (not Zig's).
    try std.testing.expectError(error.WrongKey, check(arena, try minisign.PublicKey.parse(public_key), "0.17.0", tarball, f.minisig));
}

test "Registry: tool cache versions are queued once each, within the cap, and only Zig's" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var r: Registry = .{ .io = std.testing.io, .gpa = arena, .client = null };
    try r.add(.{ .seeds = &.{.{ .version = "0.17.0", .sha256 = "00" }}, .unverified = &.{} });
    const tc = "/opt/hostedtoolcache";
    r.discover(tc, "d " ++ tc ++ "/zig/0.17.0/zig-x86_64-linux-0.17.0\n" ++
        "d " ++ tc ++ "/node/22.1.0/x64\n" ++
        "d " ++ tc ++ "/zig/0.16.0/zig-x86_64-linux-0.16.0\n" ++
        "d " ++ tc ++ "/zig/0.16.0/other\n" ++
        "d " ++ tc ++ "/zig/0.15.2/zig-x86_64-linux-0.15.2\n" ++
        "d " ++ tc ++ "/zig/0.14.1/zig-x86_64-linux-0.14.1\n" ++
        "d /elsewhere/zig/0.13.0/x");
    try std.testing.expectEqual(@as(usize, 1), r.pending.items.len);
    try std.testing.expectEqualStrings("0.16.0", r.pending.items[0]);
    try std.testing.expectEqualStrings("0.15.2", r.pending.items[1]);
    // Without a client nothing is verified, so nothing pending is seeded.
    const got = try r.forJob(arena);
    try std.testing.expectEqual(@as(usize, 1), got.seeds.len);
    try std.testing.expectEqualStrings("0.17.0", got.seeds[0].version);
}
