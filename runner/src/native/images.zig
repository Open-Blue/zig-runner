//! The images native services and Docker actions start from (docs/native-backend.md, P6, P7):
//! what they need of an image is its filesystem as a directory and its configuration (`Image`).
//! P3's pull gives them (`fromPulled`, through `Backend.pullImage` and `Backend.pullAt`).
//!
//! Tests (and the real-images root test) can instead fill a directory (`Backend.Config.images`),
//! in one of two layouts, P6's for services (`find`) and P7's for Docker actions (`lookup`; its
//! `<key>` is the normalised reference, percent-encoded, `key`). Debt: one layout.
//!
//! P6's layout (`find`): one entry per reference, named as the reference is written with each `/`
//! as `+` (`postgres:17`, `ghcr.io+o+db:1`), holding `rootfs/` (the image's filesystem, as
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
        gid = if (entryOf(passwd, null, n)) |f| std.fmt.parseInt(u32, f[3], 10) catch null else null;
    } else |_| {
        const f = entryOf(passwd, u, null) orelse return null;
        uid = std.fmt.parseInt(u32, f[2], 10) catch return null;
        gid = std.fmt.parseInt(u32, f[3], 10) catch return null;
    }
    if (colon) |c| {
        const g = user[c + 1 ..];
        if (std.fmt.parseInt(u32, g, 10)) |n| {
            gid = n;
        } else |_| {
            const f = entryOf(group, g, null) orelse return null;
            gid = std.fmt.parseInt(u32, f[2], 10) catch return null;
        }
    }
    return .{ .uid = uid, .gid = gid orelse 0 };
}

pub const Ids = struct { uid: u32, gid: u32 };

/// The fields of the line of an /etc/passwd or /etc/group naming `name` or id `id` (its third
/// field).
fn entryOf(text: []const u8, name: ?[]const u8, id: ?u32) ?[4][]const u8 {
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

/// The reference as Docker resolves it: a registry host first (`docker.io` when the first part
/// names none: no dot, no port, not `localhost`), `library/` for Docker Hub's official images, and
/// `:latest` when there is neither a tag nor a digest. `alpine:3.22` is
/// `docker.io/library/alpine:3.22`.
pub fn normalize(arena: Allocator, ref: []const u8) ![]const u8 {
    const slash = std.mem.indexOfScalar(u8, ref, '/');
    const names_host = if (slash) |s| blk: {
        const first = ref[0..s];
        break :blk std.mem.indexOfAny(u8, first, ".:") != null or
            std.mem.eql(u8, first, "localhost");
    } else false;
    const host = if (names_host) ref[0..slash.?] else "docker.io";
    const path = if (names_host) ref[slash.? + 1 ..] else ref;
    const library = std.mem.eql(u8, host, "docker.io") and
        std.mem.indexOfScalar(u8, path, '/') == null;
    const last = path[(std.mem.lastIndexOfScalar(u8, path, '/') orelse 0)..];
    const tagged = std.mem.indexOfScalar(u8, path, '@') != null or
        std.mem.indexOfScalar(u8, last, ':') != null;
    return std.fmt.allocPrint(arena, "{s}/{s}{s}{s}", .{
        host,
        if (library) "library/" else "",
        path,
        if (tagged) "" else ":latest",
    });
}

/// The directory name of `ref`'s image in the store: its normalised form, with every byte outside
/// `[A-Za-z0-9._-]` as `%XX`, so two references never share one and none names a path.
pub fn key(arena: Allocator, ref: []const u8) ![]const u8 {
    const full = try normalize(arena, ref);
    var out: std.ArrayList(u8) = .empty;
    for (full) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')
            try out.append(arena, c)
        else
            try out.print(arena, "%{X:0>2}", .{c});
    }
    return out.items;
}

/// Whether an image's `USER` is root: unset, `root` or uid 0, with or without a group.
pub fn runsAsRoot(user: []const u8) bool {
    const name = user[0 .. std.mem.indexOfScalar(u8, user, ':') orelse user.len];
    return name.len == 0 or std.mem.eql(u8, name, "root") or std.mem.eql(u8, name, "0");
}

/// `ref`'s image in the store at `dir`, or why it is not there.
pub const Found = union(enum) { image: Image, missing: []const u8 };

pub fn lookup(arena: Allocator, io: std.Io, dir: []const u8, ref: []const u8) !Found {
    if (dir.len == 0) return .{ .missing = "there is no images directory" };
    const k = try key(arena, ref);
    const rootfs = try std.fmt.allocPrint(arena, "{s}/{s}/rootfs", .{ dir, k });
    std.Io.Dir.accessAbsolute(io, rootfs, .{}) catch return .{ .missing = try std.fmt.allocPrint(
        arena,
        "the image {s} is not in the tests' images directory (as {s})",
        .{ ref, k },
    ) };
    const config_path = try std.fmt.allocPrint(arena, "{s}/{s}/config.json", .{ dir, k });
    const text = std.Io.Dir.cwd().readFileAlloc(io, config_path, arena, .limited(4 << 20)) catch
        return .{ .missing = try std.fmt.allocPrint(
            arena,
            "the image {s} has no config.json in the native image store",
            .{ref},
        ) };
    var image = parseConfig(arena, text) catch return .{ .missing = try std.fmt.allocPrint(
        arena,
        "the image {s} has a config.json the runner cannot read",
        .{ref},
    ) };
    image.rootfs = rootfs;
    return .{ .image = image };
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

test "references normalise as Docker resolves them, and key one directory each" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const Case = struct { []const u8, []const u8 };
    for ([_]Case{
        .{ "alpine", "docker.io/library/alpine:latest" },
        .{ "alpine:3.22", "docker.io/library/alpine:3.22" },
        .{ "bitnami/postgresql:17", "docker.io/bitnami/postgresql:17" },
        .{ "docker.io/library/alpine:3", "docker.io/library/alpine:3" },
        .{ "ghcr.io/acme/tool", "ghcr.io/acme/tool:latest" },
        .{ "localhost:5000/x", "localhost:5000/x:latest" },
        .{ "localhost/x:1", "localhost/x:1" },
        .{ "alpine@sha256:abcd", "docker.io/library/alpine@sha256:abcd" },
    }) |c| try std.testing.expectEqualStrings(c[1], try normalize(arena, c[0]));
    try std.testing.expectEqualStrings(
        "docker.io%2Flibrary%2Falpine%3A3.22",
        try key(arena, "alpine:3.22"),
    );
    // Nothing in a key leaves its directory.
    try std.testing.expectEqualStrings(
        "..%2F..%2Fetc%3Alatest",
        try key(arena, "../../etc"),
    );
}

test "an OCI image config gives the entrypoint, command, env and user" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const img = try parseConfig(arena,
        \\{"architecture":"amd64","config":{"Env":["PATH=/usr/bin","X=1"],
        \\"Entrypoint":["/entry.sh"],"Cmd":null,"User":"","WorkingDir":"/app"},"rootfs":{}}
    );
    try std.testing.expectEqual(@as(usize, 1), img.entrypoint.len);
    try std.testing.expectEqualStrings("/entry.sh", img.entrypoint[0]);
    try std.testing.expectEqual(@as(usize, 0), img.cmd.len);
    try std.testing.expectEqualStrings("X=1", img.env[1]);
    try std.testing.expect(runsAsRoot(img.user));
    try std.testing.expect(runsAsRoot("0:0") and runsAsRoot("root"));
    try std.testing.expect(!runsAsRoot("1000") and !runsAsRoot("actionuser:actionuser"));
    const bare = try parseConfig(arena, "{}");
    try std.testing.expectEqual(@as(usize, 0), bare.env.len);
}
