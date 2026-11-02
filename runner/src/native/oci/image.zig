//! An image pulled natively into the store (docs/native-backend.md, P3): the reference resolved
//! at its registry (`registry.zig`), a multi-platform index narrowed to this machine's platform
//! (linux/amd64, or linux/arm64 on the Pi), the platform's manifest, its config and its layers
//! fetched as content-addressed blobs and checked against their digests, and the layers applied
//! in order to one directory (`layer.zig`). The flattened rootfs is kept under the manifest's
//! digest (`Store.ensure`), so an image is unpacked once per store, and a digest-pinned reference
//! seen before (the default image) needs no network at all.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const registry = @import("registry.zig");
const layer = @import("layer.zig");
const Store = @import("Store.zig");

const Allocator = std.mem.Allocator;

pub const Platform = struct {
    architecture: []const u8,
    variant: ?[]const u8 = null,

    /// `amd64` or `arm64/v8`: a name for the store's files.
    pub fn name(p: Platform) []const u8 {
        return if (p.variant) |v| (if (std.mem.eql(u8, v, "v8")) "arm64-v8" else p.architecture) else p.architecture;
    }
};

/// This machine's, as registries name it.
pub fn hostPlatform() ?Platform {
    return switch (builtin.cpu.arch) {
        .x86_64 => .{ .architecture = "amd64" },
        .aarch64 => .{ .architecture = "arm64", .variant = "v8" },
        else => null,
    };
}

pub const Request = struct {
    image: []const u8,
    creds: ?registry.Credentials = null,
    /// Give files the image's owners (a root runner; `layer.Options.owners`).
    owners: bool,
    platform: ?Platform = null,
};

/// A pulled image: its rootfs and what its config says steps start with.
pub const Image = struct {
    rootfs: []const u8,
    /// What the reference resolved to: the index's digest for a multi-platform image, as Dagger's
    /// `imageRef` reports it.
    digest: []const u8,
    /// The platform's manifest's digest: the image's key in the store.
    manifest: []const u8,
    /// `NAME=value`, the image's own env.
    env: []const []const u8,
    /// The image's `USER` (`name`, `uid`, `uid:gid`, ...), "" for root.
    user: []const u8,
    /// Set when this pull fetched and unpacked it; null when the store had it.
    pulled: ?Pulled = null,
};

pub const Pulled = struct { layers: usize, bytes: u64, ms: i64, devices: u64 };

/// Pulls `req.image` into `store`, or finds it there. On failure, `why` says what went wrong.
pub fn pull(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    http: *std.http.Client,
    store: Store,
    req: Request,
    why: *[]const u8,
) !Image {
    const ref = registry.parseRef(arena, req.image) catch {
        why.* = try std.fmt.allocPrint(arena, "{s} is not an image reference", .{req.image});
        return error.InvalidImageReference;
    };
    const platform = req.platform orelse hostPlatform() orelse {
        why.* = "this machine's architecture has no images";
        return error.UnsupportedPlatform;
    };
    try store.prepare(arena, io);
    const cwd = std.Io.Dir.cwd();

    // A pinned reference seen before: its platform's manifest is known, and its rootfs is here.
    if (ref.digest) |d| {
        const known = cwd.readFileAlloc(io, try store.refPath(arena, d, platform.name()), arena, .limited(128)) catch null;
        if (known) |m| if (registry.validDigest(m)) {
            if (try fromStore(arena, io, store, d, m, req.owners)) |img| return img;
        };
    }

    var c: registry.Client = .{ .arena = arena, .http = http, .ref = ref, .creds = req.creds };
    errdefer if (c.why.len > 0 and why.len == 0) {
        why.* = c.why;
    };
    const top = c.manifest(ref.reference()) catch |e| return fail(arena, why, &c, e, "its manifest");
    const top_doc = try parseManifest(arena, top, why);
    const man = if (top_doc.manifests) |list| m: {
        const pick = pickPlatform(list, platform) orelse {
            why.* = try std.fmt.allocPrint(arena, "{s} has no linux/{s} image", .{ req.image, platform.name() });
            return error.NoImageForPlatform;
        };
        break :m c.manifest(pick.digest) catch |e| return fail(arena, why, &c, e, "its platform's manifest");
    } else top;
    const doc = if (top_doc.manifests == null) top_doc else try parseManifest(arena, man, why);
    if (doc.manifests != null or doc.config == null or doc.layers == null) {
        why.* = try std.fmt.allocPrint(arena, "{s}: the manifest is not an image's", .{req.image});
        return error.BadManifest;
    }
    if (ref.digest) |d| writeRef(arena, io, try store.refPath(arena, d, platform.name()), man.digest);

    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    var unpack: Unpack = .{
        .arena = arena,
        .gpa = gpa,
        .io = io,
        .client = &c,
        .store = store,
        .doc = doc,
        .owners = req.owners,
        .image = req.image,
    };
    const made = store.ensure(arena, io, "oci/images", try imageKey(arena, man.digest, req.owners), .{
        .ptr = &unpack,
        .makeFn = Unpack.make,
    }) catch |e| {
        if (unpack.why.len > 0) why.* = unpack.why;
        return fail(arena, why, &c, e, "its layers");
    };
    var img = (try fromStore(arena, io, store, top.digest, man.digest, req.owners)) orelse {
        why.* = try std.fmt.allocPrint(arena, "{s}: the store lost the image just unpacked", .{req.image});
        return error.ImageMissing;
    };
    _ = made.dir;
    if (made.made) img.pulled = .{
        .layers = doc.layers.?.len,
        .bytes = unpack.bytes,
        .ms = std.Io.Clock.awake.now(io).toMilliseconds() - started,
        .devices = unpack.totals.devices,
    };
    return img;
}

fn fail(arena: Allocator, why: *[]const u8, c: *const registry.Client, e: anyerror, what: []const u8) anyerror {
    // Returns the error rather than an error union: out of memory, that is the error returned.
    if (why.len == 0) why.* = if (c.why.len > 0)
        c.why
    else
        std.fmt.allocPrint(arena, "{f}: could not fetch {s}: {s}", .{ c.ref, what, @errorName(e) }) catch |oom|
            return oom;
    return e;
}

/// An image's directory in the store: its manifest's digest, apart for a rootless runner, whose
/// files are all its own instead of the image's owners'.
fn imageKey(arena: Allocator, manifest: []const u8, owners: bool) ![]const u8 {
    const hex = manifest["sha256:".len..];
    return if (owners) hex else std.fmt.allocPrint(arena, "{s}.rootless", .{hex});
}

/// The image under `manifest` in the store, with its config, or null when it is not there.
fn fromStore(arena: Allocator, io: std.Io, store: Store, digest: []const u8, manifest: []const u8, owners: bool) !?Image {
    const dir = try std.fmt.allocPrint(arena, "{s}/oci/images/{s}", .{ store.root, try imageKey(arena, manifest, owners) });
    const cwd = std.Io.Dir.cwd();
    const raw = cwd.readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}/config.json", .{dir}), arena, .limited(max_config)) catch
        return null;
    const cfg = std.json.parseFromSliceLeaky(Config, arena, raw, .{ .ignore_unknown_fields = true }) catch
        return null;
    const inner = cfg.config orelse Config.Inner{};
    return .{
        .rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{dir}),
        .digest = digest,
        .manifest = manifest,
        .env = inner.Env orelse &.{},
        .user = inner.User orelse "",
    };
}

/// Records which manifest a pinned index gives this platform: written aside and renamed, so a
/// reader never sees half of it.
fn writeRef(arena: Allocator, io: std.Io, path: []const u8, manifest: []const u8) void {
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const tmp = std.fmt.allocPrint(arena, "{s}.tmp-{s}", .{ path, &std.fmt.bytesToHex(raw, .lower) }) catch return;
    const cwd = std.Io.Dir.cwd();
    cwd.writeFile(io, .{ .sub_path = tmp, .data = manifest }) catch return;
    cwd.rename(tmp, cwd, path, io) catch cwd.deleteFile(io, tmp) catch {};
}

const max_config = 8 << 20;

/// A manifest or an index, the fields a pull reads.
pub const Manifest = struct {
    schemaVersion: u32 = 0,
    mediaType: []const u8 = "",
    manifests: ?[]const Descriptor = null,
    config: ?Descriptor = null,
    layers: ?[]const Descriptor = null,
};

pub const Descriptor = struct {
    mediaType: []const u8 = "",
    digest: []const u8,
    size: u64 = 0,
    platform: ?struct {
        architecture: []const u8 = "",
        os: []const u8 = "",
        variant: ?[]const u8 = null,
    } = null,
};

pub const Config = struct {
    architecture: []const u8 = "",
    os: []const u8 = "",
    config: ?Inner = null,
    rootfs: ?struct { diff_ids: []const []const u8 = &.{} } = null,

    pub const Inner = struct {
        Env: ?[]const []const u8 = null,
        User: ?[]const u8 = null,
        WorkingDir: ?[]const u8 = null,
    };
};

pub fn parseManifest(arena: Allocator, m: registry.Client.Manifest, why: *[]const u8) !Manifest {
    const doc = std.json.parseFromSliceLeaky(Manifest, arena, m.bytes, .{ .ignore_unknown_fields = true }) catch {
        why.* = "the registry's manifest is not one";
        return error.BadManifest;
    };
    if (doc.schemaVersion != 2) {
        why.* = try std.fmt.allocPrint(arena, "manifest schema {d} is not supported (only 2: " ++
            "OCI and Docker's v2)", .{doc.schemaVersion});
        return error.BadManifest;
    }
    for ([_]?[]const Descriptor{ doc.manifests, doc.layers, if (doc.config) |cd| &.{cd} else null }) |list|
        if (list) |l| for (l) |d| if (!registry.validDigest(d.digest)) {
            why.* = try std.fmt.allocPrint(arena, "the manifest names a digest that is not sha256: {s}", .{d.digest});
            return error.BadManifest;
        };
    return doc;
}

/// The index's manifest for linux on `p`: an exact variant first, then one without a variant.
/// Attestations (platform `unknown/unknown`) never match.
pub fn pickPlatform(list: []const Descriptor, p: Platform) ?Descriptor {
    var loose: ?Descriptor = null;
    for (list) |d| {
        const dp = d.platform orelse continue;
        if (!std.mem.eql(u8, dp.os, "linux") or !std.mem.eql(u8, dp.architecture, p.architecture)) continue;
        const want = p.variant orelse return d;
        if (dp.variant) |v| {
            if (std.mem.eql(u8, v, want)) return d;
        } else if (loose == null) loose = d;
    }
    return loose;
}

/// The layer types a pull unpacks; the compression is found from each blob's first bytes.
fn layerType(media: []const u8) bool {
    const known = [_][]const u8{
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    };
    for (known) |k| if (std.mem.eql(u8, media, k)) return true;
    return false;
}

/// Fetches an image's config and layers and unpacks them into the directory `Store.ensure` gives.
const Unpack = struct {
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    client: *registry.Client,
    store: Store,
    doc: Manifest,
    owners: bool,
    image: []const u8,
    bytes: u64 = 0,
    totals: layer.Totals = .{},
    why: []const u8 = "",

    fn make(ptr: *anyopaque, dir: []const u8) anyerror!void {
        const u: *Unpack = @ptrCast(@alignCast(ptr));
        const arena = u.arena;
        const io = u.io;
        const c = u.client;
        const cfg_desc = u.doc.config.?;
        const raw = try c.smallBlob(cfg_desc.digest, max_config);
        const cfg = std.json.parseFromSliceLeaky(Config, arena, raw, .{ .ignore_unknown_fields = true }) catch {
            u.why = try std.fmt.allocPrint(arena, "{s}: its config is not an image config", .{u.image});
            return error.BadConfig;
        };
        const layers = u.doc.layers.?;
        const diff_ids = if (cfg.rootfs) |r| r.diff_ids else &.{};
        if (diff_ids.len != layers.len) {
            u.why = try std.fmt.allocPrint(arena, "{s}: {d} layers but {d} diff ids in its config", .{
                u.image, layers.len, diff_ids.len,
            });
            return error.BadConfig;
        }
        const cwd = std.Io.Dir.cwd();
        const rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{dir});
        try cwd.createDirPath(io, rootfs);
        _ = linux.chmod(try arena.dupeSentinel(u8, rootfs, 0), 0o755);
        const rc = linux.open(try arena.dupeSentinel(u8, rootfs, 0), .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) return error.OpenFailed;
        const root: linux.fd_t = @intCast(rc);
        defer _ = linux.close(root);
        for (layers, diff_ids, 1..) |l, diff_id, n| {
            if (!layerType(l.mediaType)) {
                u.why = try std.fmt.allocPrint(arena, "{s}: layer {d} is a {s}, not a tar layer", .{ u.image, n, l.mediaType });
                return error.UnsupportedLayer;
            }
            const path = try u.blob(l);
            const f = try cwd.openFile(io, path, .{});
            defer f.close(io);
            var buf: [64 * 1024]u8 = undefined;
            var fr = f.reader(io, &buf);
            layer.apply(u.gpa, io, root, &fr.interface, diff_id, .{ .owners = u.owners }, &u.totals) catch |e| {
                u.why = try std.fmt.allocPrint(arena, "{s}: layer {d} ({s}): {s}{s}", .{
                    u.image, n, l.digest, @errorName(e),
                    if (e == error.FsFailed) try std.fmt.allocPrint(arena, " ({s}: {s})", .{
                        layer.last_fs_error.op, @tagName(layer.last_fs_error.errno),
                    }) else "",
                });
                return e;
            };
        }
        try cwd.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/config.json", .{dir}), .data = raw });
    }

    /// The layer's blob in the store, fetched when it is not there yet.
    fn blob(u: *Unpack, l: Descriptor) ![]const u8 {
        const arena = u.arena;
        const io = u.io;
        const path = try u.store.blobPath(arena, l.digest);
        const cwd = std.Io.Dir.cwd();
        if (cwd.access(io, path, .{})) |_| return path else |_| {}
        const tmp = try u.store.blobTemp(arena, io, l.digest);
        const f = try cwd.createFile(io, tmp, .{ .exclusive = true });
        {
            defer f.close(io);
            errdefer cwd.deleteFile(io, tmp) catch {};
            try u.client.blob(l.digest, l.size, f);
        }
        u.bytes += l.size;
        try cwd.rename(tmp, cwd, path, io);
        return path;
    }
};

// --- tests ---

const testing = std.testing;

test "native oci platform pick: linux on this architecture, its variant first, never an attestation" {
    const list = [_]Descriptor{
        .{ .digest = "sha256:a", .platform = .{ .architecture = "unknown", .os = "unknown" } },
        .{ .digest = "sha256:b", .platform = .{ .architecture = "arm", .os = "linux", .variant = "v7" } },
        .{ .digest = "sha256:c", .platform = .{ .architecture = "arm64", .os = "linux" } },
        .{ .digest = "sha256:d", .platform = .{ .architecture = "arm64", .os = "linux", .variant = "v8" } },
        .{ .digest = "sha256:e", .platform = .{ .architecture = "amd64", .os = "windows" } },
        .{ .digest = "sha256:f", .platform = .{ .architecture = "amd64", .os = "linux" } },
    };
    try testing.expectEqualStrings("sha256:f", pickPlatform(&list, .{ .architecture = "amd64" }).?.digest);
    try testing.expectEqualStrings("sha256:d", pickPlatform(&list, .{ .architecture = "arm64", .variant = "v8" }).?.digest);
    try testing.expectEqualStrings("sha256:c", pickPlatform(list[0..3], .{ .architecture = "arm64", .variant = "v8" }).?.digest);
    try testing.expect(pickPlatform(list[0..2], .{ .architecture = "amd64" }) == null);
    try testing.expect(hostPlatform() != null);
}
