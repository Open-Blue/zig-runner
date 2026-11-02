//! The images native services start from (docs/native-backend.md, P6): what a service needs of an
//! image is its filesystem as a directory and its configuration (`Image`). P3's pull gives them
//! (`fromPulled`, through `Backend.pullImage`).
//!
//! Tests (and the real-images root test) can instead fill a directory (`Backend.Config.images`):
//! one entry per reference, named as the reference is written with each `/` as `+`
//! (`postgres:17`, `ghcr.io+o+db:1`), holding `rootfs/` (the image's filesystem, as
//! `docker export` gives it, owned as in the image) and `config.json` (its configuration, as
//! `docker image inspect --format '{{json .}}'` prints it, or an OCI image configuration). A
//! reference with no tag or digest is also looked for as `:latest`.

const std = @import("std");
const health = @import("health.zig");

const Allocator = std.mem.Allocator;

/// What a service runs from: the image's filesystem (a directory used read-only, as the lowest
/// layer of the service's overlay) and the parts of its configuration a container takes.
pub const Image = struct {
    /// Absolute.
    rootfs: []const u8,
    entrypoint: []const []const u8 = &.{},
    cmd: []const []const u8 = &.{},
    /// `NAME=value`.
    env: []const []const u8 = &.{},
    workdir: []const u8 = "",
    /// `user`, `uid`, `user:group` or `uid:gid`, as the image's `USER`; "" for root.
    user: []const u8 = "",
    healthcheck: ?health.ImageCheck = null,
    /// `sha256:...`, when the configuration says which digest it was pulled as.
    digest: ?[]const u8 = null,
};

/// The entry's name in the images directory: the reference with each `/` as `+`, which no
/// reference holds.
fn entryName(arena: Allocator, ref: []const u8) ![]const u8 {
    const out = try arena.dupe(u8, ref);
    std.mem.replaceScalar(u8, out, '/', '+');
    return out;
}

/// Whether a reference names a tag or a digest (`name:tag`, `name@sha256:...`); a `:` before the
/// last `/` is a registry's port.
fn hasTag(ref: []const u8) bool {
    if (std.mem.indexOfScalar(u8, ref, '@') != null) return true;
    const last = ref[(if (std.mem.lastIndexOfScalar(u8, ref, '/')) |s| s + 1 else 0)..];
    return std.mem.indexOfScalar(u8, last, ':') != null;
}

/// The entry `ref` is in `dir`, or null when there is none.
fn entry(arena: Allocator, io: std.Io, dir: []const u8, ref: []const u8) !?[]const u8 {
    if (dir.len == 0 or ref.len == 0 or std.mem.indexOf(u8, ref, "..") != null) return null;
    const tries = [_][]const u8{
        ref,
        if (hasTag(ref)) "" else try std.fmt.allocPrint(arena, "{s}:latest", .{ref}),
    };
    for (tries) |r| {
        if (r.len == 0) continue;
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, try entryName(arena, r) });
        const rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{path});
        std.Io.Dir.accessAbsolute(io, rootfs, .{}) catch continue;
        return path;
    }
    return null;
}

/// Whether `dir` has `ref` (`Backend.unsupported`, before anything runs).
pub fn has(arena: Allocator, io: std.Io, dir: []const u8, ref: []const u8) bool {
    return (entry(arena, io, dir, ref) catch null) != null;
}

/// `ref` from `dir`: its filesystem and configuration, or null when `dir` does not have it.
/// `error.BadImageConfig` when its configuration cannot be read.
pub fn find(arena: Allocator, io: std.Io, dir: []const u8, ref: []const u8) !?Image {
    const path = (try entry(arena, io, dir, ref)) orelse return null;
    const cwd = std.Io.Dir.cwd();
    const rootfs = try cwd.realPathFileAlloc(io, try std.fmt.allocPrint(arena, "{s}/rootfs", .{
        path,
    }), arena);
    const config_path = try std.fmt.allocPrint(arena, "{s}/config.json", .{path});
    const text = cwd.readFileAlloc(io, config_path, arena, .limited(4 << 20)) catch |e|
        switch (e) {
            // An image with nothing configured: it must then say what to run some other way.
            error.FileNotFound => return .{ .rootfs = rootfs },
            else => return error.BadImageConfig,
        };
    var image = parseConfig(arena, text) catch return error.BadImageConfig;
    image.rootfs = rootfs;
    return image;
}

/// An image P3's pull gave (`oci.Image`): its rootfs, and its configuration from the
/// `config.json` beside it in the store (`oci/images/<manifest>/`), with the digest the reference
/// resolved to.
pub fn fromPulled(arena: Allocator, io: std.Io, rootfs: []const u8, digest: []const u8) !Image {
    const dir = std.fs.path.dirname(rootfs) orelse return error.BadImageConfig;
    const text = std.Io.Dir.cwd().readFileAlloc(
        io,
        try std.fmt.allocPrint(arena, "{s}/config.json", .{dir}),
        arena,
        .limited(4 << 20),
    ) catch return error.BadImageConfig;
    var image = parseConfig(arena, text) catch return error.BadImageConfig;
    image.rootfs = rootfs;
    image.digest = digest;
    return image;
}

/// An image's configuration from `docker image inspect --format '{{json .}}'` (its `Config`) or
/// an OCI image configuration (its `config`). `rootfs` is left empty.
pub fn parseConfig(arena: Allocator, text: []const u8) !Image {
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    if (root != .object) return error.BadImageConfig;
    const c = root.object.get("config") orelse root.object.get("Config") orelse
        return .{ .rootfs = "" };
    var image: Image = .{ .rootfs = "" };
    if (c == .object) {
        image.entrypoint = try strings(arena, c.object.get("Entrypoint"));
        image.cmd = try strings(arena, c.object.get("Cmd"));
        image.env = try strings(arena, c.object.get("Env"));
        image.workdir = string(c.object.get("WorkingDir"));
        image.user = string(c.object.get("User"));
        if (c.object.get("Healthcheck")) |h| if (h == .object) {
            image.healthcheck = .{
                .test_cmd = try strings(arena, h.object.get("Test")),
                .interval_ns = int(h.object.get("Interval")),
                .timeout_ns = int(h.object.get("Timeout")),
                .start_period_ns = int(h.object.get("StartPeriod")),
                .retries = @intCast(@min(int(h.object.get("Retries")), std.math.maxInt(u32))),
            };
        };
    }
    if (root.object.get("RepoDigests")) |d| if (d == .array and d.array.items.len > 0) {
        const first = d.array.items[0];
        if (first == .string) if (std.mem.indexOfScalar(u8, first.string, '@')) |at| {
            image.digest = first.string[at + 1 ..];
        };
    };
    return image;
}

fn strings(arena: Allocator, v: ?std.json.Value) ![]const []const u8 {
    const arr = v orelse return &.{};
    if (arr != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (arr.array.items) |item| if (item == .string) try out.append(arena, item.string);
    return out.items;
}

fn string(v: ?std.json.Value) []const u8 {
    const s = v orelse return "";
    return if (s == .string) s.string else "";
}

fn int(v: ?std.json.Value) u64 {
    const n = v orelse return 0;
    return switch (n) {
        .integer => |i| if (i > 0) @intCast(i) else 0,
        else => 0,
    };
}

/// The ids `user` (an image's `USER`) names, from the image's /etc/passwd and /etc/group text:
/// `name` or `uid` takes the user's primary group, `user:group` both. Null when a name is not
/// there, as `docker run` then refuses to start.
pub fn userIds(user: []const u8, passwd: []const u8, group: []const u8) ?Ids {
    if (user.len == 0) return .{ .uid = 0, .gid = 0 };
    const colon = std.mem.indexOfScalar(u8, user, ':');
    const u = if (colon) |c| user[0..c] else user;
    var uid: u32 = 0;
    var gid: ?u32 = null;
    if (std.fmt.parseInt(u32, u, 10)) |n| {
        uid = n;
        gid = if (lookup(passwd, null, n)) |f| std.fmt.parseInt(u32, f[3], 10) catch null else null;
    } else |_| {
        const f = lookup(passwd, u, null) orelse return null;
        uid = std.fmt.parseInt(u32, f[2], 10) catch return null;
        gid = std.fmt.parseInt(u32, f[3], 10) catch return null;
    }
    if (colon) |c| {
        const g = user[c + 1 ..];
        if (std.fmt.parseInt(u32, g, 10)) |n| {
            gid = n;
        } else |_| {
            const f = lookup(group, g, null) orelse return null;
            gid = std.fmt.parseInt(u32, f[2], 10) catch return null;
        }
    }
    return .{ .uid = uid, .gid = gid orelse 0 };
}

pub const Ids = struct { uid: u32, gid: u32 };

/// The fields of the line of an /etc/passwd or /etc/group naming `name` or id `id` (its third
/// field).
fn lookup(text: []const u8, name: ?[]const u8, id: ?u32) ?[4][]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var it = std.mem.splitScalar(u8, line, ':');
        var f: [4][]const u8 = .{ "", "", "", "" };
        var n: usize = 0;
        while (it.next()) |v| : (n += 1) {
            if (n == f.len) break;
            f[n] = v;
        }
        if (n < 3) continue;
        if (name) |want| if (std.mem.eql(u8, f[0], want)) return f;
        if (id) |want| if ((std.fmt.parseInt(u32, f[2], 10) catch continue) == want) return f;
    }
    return null;
}

test "an image's configuration, from docker image inspect or an OCI configuration" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const inspect =
        \\{"Id":"sha256:1","RepoDigests":["redis@sha256:abc"],"Config":{"User":"redis",
        \\"Env":["PATH=/usr/local/bin:/usr/bin"],"Entrypoint":["docker-entrypoint.sh"],
        \\"Cmd":["redis-server"],"WorkingDir":"/data","Healthcheck":{"Test":["CMD-SHELL",
        \\"redis-cli ping"],"Interval":2000000000,"Retries":4}}}
    ;
    const img = try parseConfig(arena, inspect);
    try std.testing.expectEqualStrings("docker-entrypoint.sh", img.entrypoint[0]);
    try std.testing.expectEqualStrings("redis-server", img.cmd[0]);
    try std.testing.expectEqualStrings("/data", img.workdir);
    try std.testing.expectEqualStrings("redis", img.user);
    try std.testing.expectEqualStrings("sha256:abc", img.digest.?);
    try std.testing.expectEqual(@as(u64, 2_000_000_000), img.healthcheck.?.interval_ns);
    try std.testing.expectEqual(@as(u32, 4), img.healthcheck.?.retries);
    const oci = try parseConfig(arena, "{\"architecture\":\"amd64\",\"config\":" ++
        "{\"Cmd\":[\"sh\"],\"Entrypoint\":null}}");
    try std.testing.expectEqualStrings("sh", oci.cmd[0]);
    try std.testing.expectEqual(@as(usize, 0), oci.entrypoint.len);
    try std.testing.expectError(error.BadImageConfig, parseConfig(arena, "[1]"));
}

test "images are found by reference, with :latest for none, and nothing outside the directory" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "images/postgres:17/rootfs");
    try tmp.dir.createDirPath(io, "images/ghcr.io+o+db:latest/rootfs");
    try tmp.dir.createDirPath(io, "images/localhost:5000+x:1/rootfs");
    try tmp.dir.writeFile(io, .{
        .sub_path = "images/postgres:17/config.json",
        .data = "{\"Config\":{\"Cmd\":[\"postgres\"]}}",
    });
    const dir = try std.fmt.allocPrint(arena, "{s}/images", .{
        try tmp.dir.realPathFileAlloc(io, ".", arena),
    });
    const pg = (try find(arena, io, dir, "postgres:17")).?;
    try std.testing.expectEqualStrings("postgres", pg.cmd[0]);
    try std.testing.expect(std.mem.endsWith(u8, pg.rootfs, "/postgres:17/rootfs"));
    try std.testing.expect(has(arena, io, dir, "ghcr.io/o/db"));
    // A registry's port is not a tag.
    try std.testing.expect(!has(arena, io, dir, "localhost:5000/x"));
    try std.testing.expect(has(arena, io, dir, "localhost:5000/x:1"));
    try std.testing.expect(!has(arena, io, dir, "postgres:16"));
    try std.testing.expect(!has(arena, io, dir, "../images/postgres:17"));
    try std.testing.expect(!has(arena, io, "", "postgres:17"));
}

test "an image's USER as ids, from its own /etc/passwd and /etc/group" {
    const passwd = "root:x:0:0::/root:/bin/sh\npostgres:x:70:70::/var/lib/postgresql:/bin/sh\n";
    const group = "root:x:0:\npostgres:x:70:\nwww:x:33:\n";
    try std.testing.expectEqual(Ids{ .uid = 0, .gid = 0 }, userIds("", passwd, group).?);
    try std.testing.expectEqual(Ids{ .uid = 70, .gid = 70 }, userIds("postgres", passwd, group).?);
    try std.testing.expectEqual(Ids{ .uid = 70, .gid = 33 }, userIds("70:www", passwd, group).?);
    try std.testing.expectEqual(Ids{ .uid = 1234, .gid = 0 }, userIds("1234", passwd, group).?);
    try std.testing.expectEqual(Ids{ .uid = 5, .gid = 6 }, userIds("5:6", passwd, group).?);
    try std.testing.expect(userIds("nobody", passwd, group) == null);
    try std.testing.expect(userIds("postgres:nogroup", passwd, group) == null);
}
