//! An image pulled natively into the store (docs/native-backend.md, P3): the reference resolved
//! at its registry (`registry.zig`), a multi-platform index narrowed to this machine's platform
//! (linux/amd64, or linux/arm64 on the Pi), the platform's manifest, its config and its layers
//! fetched as content-addressed blobs and checked against their digests, and the layers applied
//! in order to one directory (`layer.zig`). The flattened rootfs is kept under the manifest's
//! digest (`Store.ensure`), so an image is unpacked once per store, and a digest-pinned reference
//! seen before (the default image) needs no network at all.

const std = @import("std");
const builtin = @import("builtin");
const registry = @import("registry.zig");
const layer = @import("layer.zig");
const Store = @import("Store.zig");
const admission = @import("../../admission.zig");
const zr_net = @import("../../zr_net.zig");
const linux = std.os.linux;

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
    /// The runner's place at the memory gate, for sizing the layer downloads (`Prefetch.start`);
    /// without it, `Prefetch.default_fetchers`.
    gate: ?*admission.Gate = null,
    /// How long a tag's resolution (`tag_record`) is reused without asking the registry, in
    /// seconds; 0 asks every time (a failed ask still falls back to the last known digest).
    tag_ttl_s: u32 = 0,
};

/// What a tag resolved to by default (`Config.image_tag_ttl_secs`): minutes, so that a burst of
/// jobs asks the registry once and a moved tag is picked up before the next one.
pub const default_tag_ttl_s: u32 = 300;

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
    /// Held shared on the image in the store (`Store.hold`) until the caller closes it, which a
    /// job does at its end: a pull's rootfs is a lower of its mounts, and of what it provisions.
    lock: std.Io.File,
    /// Why the registry was not asked or did not answer, when this is its last known digest for
    /// the tag (`tag_record`) and not a fresh resolution; for the job's log.
    reused: ?[]const u8 = null,
};

pub const Pulled = struct { layers: usize, bytes: u64, ms: i64, devices: u64 };

/// Pulls `req.image` into `store`, or finds it there. On failure, `why` says what went wrong.
pub fn pull(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    store: Store,
    req: Request,
    why: *[]const u8,
) !Image {
    const ref = registry.parseRef(arena, req.image) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidImageReference => {
            why.* = try std.fmt.allocPrint(arena, "{s} is not an image reference", .{req.image});
            return error.InvalidImageReference;
        },
    };
    const platform = req.platform orelse hostPlatform() orelse {
        why.* = "this machine's architecture has no images";
        return error.UnsupportedPlatform;
    };
    try store.prepare(arena, io);
    const cwd = std.Io.Dir.cwd();

    // A pinned reference seen before: its platform's manifest is known, and its rootfs is here.
    if (ref.digest) |d| {
        const known = cwd.readFileAlloc(io, try store.refPath(arena, d, platform.name()), arena, .limited(128)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        if (known) |m| if (registry.validDigest(m)) {
            if (try fromKnown(arena, io, store, d, m, req.owners)) |img| return img;
        };
    }

    // A tag resolved lately, or whose last resolution the registry may fail to repeat.
    const tag_path: ?[]const u8 = if (ref.digest == null) try tagPath(arena, io, store, ref, req.creds, platform) else null;
    const known_tag: ?TagRecord = if (tag_path) |p| try readTag(arena, io, p) else null;
    if (known_tag) |k| {
        const age = std.Io.Clock.real.now(io).toSeconds() - k.at;
        if (age >= 0 and age < req.tag_ttl_s) {
            if (try fromKnown(arena, io, store, k.top, k.manifest, req.owners)) |img| return img;
        }
    }

    // The last known digest's image, if the store still has it: what a registry that cannot answer
    // is replaced by, and then its "slow down" is not waited out.
    var fallback: ?Image = if (known_tag) |k| try fromKnown(arena, io, store, k.top, k.manifest, req.owners) else null;
    errdefer if (fallback) |f| f.lock.close(io);
    var c: registry.Client = .{ .arena = arena, .io = io, .ref = ref, .creds = req.creds, .wait_on_limit = fallback == null };
    errdefer if (c.why.len > 0 and why.len == 0) {
        why.* = c.why;
    };
    const top = c.manifest(ref.reference()) catch |e| {
        if (fallback) |*img| if (c.unavailable()) {
            img.reused = try std.fmt.allocPrint(arena, "the registry did not answer ({s}); using the last " ++
                "known digest of {s}, {s}", .{ if (c.why.len > 0) c.why else @errorName(e), req.image, known_tag.?.top });
            std.log.warn("image {s}: {s}", .{ req.image, img.reused.? });
            return img.*;
        };
        return fail(arena, why, &c, e, "its manifest");
    };
    // Not needed: the pull goes on, and holds what it pulls itself.
    if (fallback) |f| f.lock.close(io);
    fallback = null;
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
    if (ref.digest) |d| try writeRef(arena, io, try store.refPath(arena, d, platform.name()), man.digest);
    if (tag_path) |p| try writeTag(arena, io, p, top.digest, man.digest);

    const started = std.Io.Clock.awake.now(io).toMilliseconds();
    var unpack: Unpack = .{
        .arena = arena,
        .gpa = gpa,
        .io = io,
        .client = &c,
        .store = store,
        .doc = doc,
        .owners = req.owners,
        .gate = req.gate,
        .image = req.image,
    };
    const made = store.ensure(arena, io, "oci/images", try imageKey(arena, man.digest, req.owners), .{
        .ptr = &unpack,
        .makeFn = Unpack.make,
    }) catch |e| {
        if (unpack.why.len > 0) why.* = unpack.why;
        return fail(arena, why, &c, e, "its layers");
    };
    errdefer made.lock.close(io);
    var img = (try fromStore(arena, io, store, top.digest, man.digest, req.owners, made.lock)) orelse {
        why.* = try std.fmt.allocPrint(arena, "{s}: the store lost the image just unpacked", .{req.image});
        return error.ImageMissing;
    };
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

/// The store's copy of the image under `manifest` (`digest` is what its reference resolved to),
/// held, or null when it is not there.
fn fromKnown(arena: Allocator, io: std.Io, store: Store, digest: []const u8, manifest: []const u8, owners: bool) !?Image {
    const lock = (try store.hold(arena, io, "oci/images", try imageKey(arena, manifest, owners))) orelse return null;
    errdefer lock.close(io);
    if (try fromStore(arena, io, store, digest, manifest, owners, lock)) |img| return img;
    lock.close(io);
    return null;
}

/// What a tag resolved to, and when (epoch seconds): `<manifest> <top> <at>`, the platform's
/// manifest and what the tag named (the index, for a multi-platform image).
const TagRecord = struct { manifest: []const u8, top: []const u8, at: i64 };

/// Where the tag's record is: named by an HMAC-SHA256 of the reference and of who asked
/// (`anonymous`, or the credentials' user and password), keyed by the store's own secret
/// (`storeSecret`), so that what one credential context was let pull is never served to another (a
/// private image, a revoked login), and a weak password cannot be guessed from the file names.
/// Null when the store has no secret and cannot be given one: its tags are then not remembered.
pub fn tagPath(arena: Allocator, io: std.Io, store: Store, ref: registry.Ref, creds: ?registry.Credentials, platform: Platform) !?[]const u8 {
    const secret = (try storeSecret(arena, io, store)) orelse return null;
    const name = if (creds) |cr|
        try std.fmt.allocPrint(arena, "{f}\x00{d}:{s}\x00{s}", .{ ref, cr.username.len, cr.username, cr.password })
    else
        try std.fmt.allocPrint(arena, "{f}\x00anonymous", .{ref});
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, name, &secret);
    return try std.fmt.allocPrint(arena, "{s}/oci/refs/tag-{s}.{s}", .{ store.root, &std.fmt.bytesToHex(mac, .lower), platform.name() });
}

/// The store's 32-byte secret (`oci/refs.key`, 0600 in the store's private directory, never
/// logged): made from random bytes the first time, written aside and renamed so a reader never sees
/// half of it, and read back, so that runners racing to make it use the one that won. A file that
/// is missing, short or unreadable is replaced; records made under the old one are then never
/// found, and the registry is asked. Null when it can be neither read nor written.
fn storeSecret(arena: Allocator, io: std.Io, store: Store) Allocator.Error!?[32]u8 {
    const path = try std.fmt.allocPrint(arena, "{s}/oci/refs.key", .{store.root});
    const cwd = std.Io.Dir.cwd();
    for (0..2) |_| {
        if (readSecret(arena, io, path)) |k| return k else |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSecret => {},
        }
        var fresh: [32]u8 = undefined;
        io.random(&fresh);
        var raw: [8]u8 = undefined;
        io.random(&raw);
        const tmp = try std.fmt.allocPrint(arena, "{s}.tmp-{s}", .{ path, &std.fmt.bytesToHex(raw, .lower) });
        {
            const f = cwd.createFile(io, tmp, .{ .permissions = .fromMode(0o600), .exclusive = true }) catch return null;
            defer f.close(io);
            f.writeStreamingAll(io, &fresh) catch return null;
            if (linux.errno(linux.fsync(f.handle)) != .SUCCESS) return null;
        }
        cwd.rename(tmp, cwd, path, io) catch {
            cwd.deleteFile(io, tmp) catch {};
            return null;
        };
    }
    return readSecret(arena, io, path) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NoSecret => null,
    };
}

fn readSecret(arena: Allocator, io: std.Io, path: []const u8) error{ OutOfMemory, NoSecret }![32]u8 {
    const raw = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NoSecret,
    };
    if (raw.len != 32) return error.NoSecret;
    return raw[0..32].*;
}

/// The record at `path`, or null when there is none or it is not one.
fn readTag(arena: Allocator, io: std.Io, path: []const u8) Allocator.Error!?TagRecord {
    const raw = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(256)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    var it = std.mem.tokenizeAny(u8, raw, " \n");
    const manifest = it.next() orelse return null;
    const top = it.next() orelse return null;
    const at = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    if (!registry.validDigest(manifest) or !registry.validDigest(top)) return null;
    return .{ .manifest = manifest, .top = top, .at = at };
}

fn writeTag(arena: Allocator, io: std.Io, path: []const u8, top: []const u8, manifest: []const u8) Allocator.Error!void {
    const text = try std.fmt.allocPrint(arena, "{s} {s} {d}\n", .{ manifest, top, std.Io.Clock.real.now(io).toSeconds() });
    try writeRef(arena, io, path, text);
}

/// An image's directory in the store: its manifest's digest, apart for a rootless runner, whose
/// files are all its own instead of the image's owners'.
fn imageKey(arena: Allocator, manifest: []const u8, owners: bool) ![]const u8 {
    const hex = manifest["sha256:".len..];
    return if (owners) hex else std.fmt.allocPrint(arena, "{s}.rootless", .{hex});
}

/// The image under `manifest` in the store, with its config, or null when it is not there. `lock`
/// holds it (`Store.hold`) and goes with the image.
fn fromStore(arena: Allocator, io: std.Io, store: Store, digest: []const u8, manifest: []const u8, owners: bool, lock: std.Io.File) !?Image {
    const dir = try std.fmt.allocPrint(arena, "{s}/oci/images/{s}", .{ store.root, try imageKey(arena, manifest, owners) });
    const cwd = std.Io.Dir.cwd();
    // Out of memory is not "not in the store": read as one, the pull reported that the store lost
    // the image it had just unpacked.
    const raw = cwd.readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}/config.json", .{dir}), arena, .limited(max_config)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    const cfg = parseConfig(arena, raw) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BadConfig => return null,
    };
    const inner = cfg.config orelse Config.Inner{};
    return .{
        .rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{dir}),
        .digest = digest,
        .manifest = manifest,
        .env = inner.Env orelse &.{},
        .user = inner.User orelse "",
        .lock = lock,
    };
}

/// Records which manifest a pinned index gives this platform: written aside and renamed, so a
/// reader never sees half of it.
fn writeRef(arena: Allocator, io: std.Io, path: []const u8, manifest: []const u8) Allocator.Error!void {
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const tmp = try std.fmt.allocPrint(arena, "{s}.tmp-{s}", .{ path, &std.fmt.bytesToHex(raw, .lower) });
    const cwd = std.Io.Dir.cwd();
    {
        const f = cwd.createFile(io, tmp, .{}) catch return;
        defer f.close(io);
        f.writeStreamingAll(io, manifest) catch return;
        // On disk before its name is: a crash must not leave an empty record under it.
        if (linux.errno(linux.fsync(f.handle)) != .SUCCESS) return;
    }
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

/// An image config, or `error.BadConfig`; out of memory is not a bad config.
fn parseConfig(arena: Allocator, raw: []const u8) error{ OutOfMemory, BadConfig }!Config {
    return std.json.parseFromSliceLeaky(Config, arena, raw, .{ .ignore_unknown_fields = true }) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadConfig,
    };
}

pub fn parseManifest(arena: Allocator, m: registry.Client.Manifest, why: *[]const u8) error{ OutOfMemory, BadManifest }!Manifest {
    const doc = std.json.parseFromSliceLeaky(Manifest, arena, m.bytes, .{ .ignore_unknown_fields = true }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            why.* = "the registry's manifest is not one";
            return error.BadManifest;
        },
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
    gate: ?*admission.Gate = null,
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
        const cfg = parseConfig(arena, raw) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BadConfig => {
                u.why = try std.fmt.allocPrint(arena, "{s}: its config is not an image config", .{u.image});
                return error.BadConfig;
            },
        };
        // The blobs have no job to hold them: an eviction stays out while any image unpacks.
        const blobs = try std.Io.Dir.cwd().createFile(io, try u.store.blobsLock(arena), .{ .truncate = false });
        defer blobs.close(io);
        if (linux.errno(linux.flock(blobs.handle, 1)) != .SUCCESS) return error.Locked;
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
        const ahead = try Prefetch.start(u, layers);
        defer ahead.stop(io);
        for (layers, diff_ids, 0..) |l, diff_id, i| {
            const n = i + 1;
            if (!layerType(l.mediaType)) {
                u.why = try std.fmt.allocPrint(arena, "{s}: layer {d} is a {s}, not a tar layer", .{ u.image, n, l.mediaType });
                return error.UnsupportedLayer;
            }
            const path = try ahead.wait(i);
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
};

/// The layers' blobs fetched while the earlier ones unpack, `fetchers` at a time, in order. A
/// blob goes into the store (renamed into place once it is whole and on disk) as it did when each
/// was fetched just before its turn; what changes is that the wait for the registry overlaps the
/// unpacking, which on a real network was most of a pull.
const Prefetch = struct {
    u: *Unpack,
    layers: []const Descriptor,
    slots: []Slot,
    next: std.atomic.Value(usize) = .init(0),
    group: std.Io.Group = .init,
    /// How many fetch tasks run. Without any, `wait` fetches in the caller.
    running: usize = 0,

    /// Downloads at once when there is no gate to ask (tests, `pullAt`): what it was before the pull
    /// chose them.
    const default_fetchers = 3;
    /// The most downloads at once. Measured on a 12-thread laptop against loopback servers (docs/rust-net.md,
    /// "Workers and concurrent pulls"): 8 streams as fast with 8 workers as with 12. Where a pull's
    /// layers unpack more slowly than they download, wider does nothing more.
    const max_fetchers = 8;

    const Slot = struct {
        done: std.Io.Event = .unset,
        path: []const u8,
        /// Bytes fetched (0 when the store had the blob).
        bytes: u64 = 0,
        err: ?anyerror = null,
        /// Why `err`, owned by `Unpack.gpa`.
        why: []const u8 = "",
    };

    fn start(u: *Unpack, layers: []const Descriptor) !*Prefetch {
        const p = try u.arena.create(Prefetch);
        const slots = try u.arena.alloc(Slot, layers.len);
        for (slots, layers) |*s, l| s.* = .{ .path = try u.store.blobPath(u.arena, l.digest) };
        p.* = .{ .u = u, .layers = layers, .slots = slots };
        var why: []const u8 = "no gate";
        const fetchers: u32 = if (u.gate) |g|
            g.fetchConcurrency(layers.len, zr_net.cores(), max_fetchers, &why)
        else
            default_fetchers;
        // Once per pull, for the jobs' logs (P9, the server runs): what was chosen and what limited it.
        std.log.info("native: {s}: {d} layers, fetching {d} at a time ({s}; {d} cores)", .{ u.image, layers.len, fetchers, why, zr_net.cores() });
        for (0..@min(fetchers, layers.len)) |_| {
            p.group.concurrent(u.io, run, .{p}) catch break;
            p.running += 1;
        }
        return p;
    }

    /// Lets the tasks go, whatever they are doing.
    fn stop(p: *Prefetch, io: std.Io) void {
        p.next.store(p.slots.len, .monotonic);
        p.group.cancel(io);
        for (p.slots) |s| if (s.why.len > 0) p.u.gpa.free(s.why);
    }

    /// Layer `i`'s blob in the store, once it is there.
    fn wait(p: *Prefetch, i: usize) ![]const u8 {
        const s = &p.slots[i];
        if (p.running == 0) {
            var client = p.u.client.*;
            p.fetch(&client, p.u.arena, i);
        } else s.done.waitUncancelable(p.u.io);
        p.u.bytes += s.bytes;
        if (s.err) |e| {
            if (s.why.len > 0) p.u.client.why = try p.u.arena.dupe(u8, s.why);
            return e;
        }
        return s.path;
    }

    /// A fetch task: layers taken in turn until there are none, with a client and a memory of its
    /// own (the registry's conversation, `registry.Client`, is not for two threads).
    fn run(p: *Prefetch) void {
        var arena_state: std.heap.ArenaAllocator = .init(p.u.gpa);
        defer arena_state.deinit();
        var client = p.u.client.*;
        client.why = "";
        while (true) {
            const i = p.next.fetchAdd(1, .monotonic);
            if (i >= p.slots.len) return;
            _ = arena_state.reset(.retain_capacity);
            client.arena = arena_state.allocator();
            p.fetch(&client, arena_state.allocator(), i);
        }
    }

    /// Layer `i`'s blob made sure of, the slot set and its event raised.
    fn fetch(p: *Prefetch, client: *registry.Client, arena: Allocator, i: usize) void {
        const s = &p.slots[i];
        defer s.done.set(p.u.io);
        if (!layerType(p.layers[i].mediaType)) return;
        s.bytes = p.blob(client, arena, p.layers[i], s.path) catch |e| {
            s.err = e;
            if (client.why.len > 0) s.why = p.u.gpa.dupe(u8, client.why) catch "";
            return;
        };
    }

    /// The layer's blob in the store, fetched when it is not there yet: the bytes fetched.
    fn blob(p: *Prefetch, c: *registry.Client, arena: Allocator, l: Descriptor, path: []const u8) !u64 {
        const io = p.u.io;
        const cwd = std.Io.Dir.cwd();
        if (cwd.access(io, path, .{})) |_| {
            // Its last use, which an eviction goes by, on the file's own mtime.
            _ = linux.utimensat(linux.AT.FDCWD, try arena.dupeSentinel(u8, path, 0), null, 0);
            return 0;
        } else |_| {}
        const tmp = try p.u.store.blobTemp(arena, io, l.digest);
        const f = try cwd.createFile(io, tmp, .{ .exclusive = true });
        {
            defer f.close(io);
            errdefer cwd.deleteFile(io, tmp) catch {};
            try c.blob(l.digest, l.size, f);
            // On disk before its name is: a blob is trusted by its path, and an unpacked one is
            // not fetched again.
            if (linux.errno(linux.fsync(f.handle)) != .SUCCESS) return error.Sync;
        }
        try cwd.rename(tmp, cwd, path, io);
        return l.size;
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

test "allocation failures: OCI manifests, indexes and image configs" {
    const af = @import("../../alloc_failures.zig");
    const S = struct {
        fn manifest(a: Allocator, bytes: []const u8, ok: bool) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            var why: []const u8 = "";
            const m: registry.Client.Manifest = .{ .bytes = bytes, .media_type = "", .digest = "" };
            const doc = parseManifest(arena.allocator(), m, &why) catch |e| switch (e) {
                error.BadManifest => return if (ok) e else {},
                else => return e,
            };
            try testing.expect(ok and (doc.manifests != null or doc.layers != null));
        }
        fn config(a: Allocator, raw: []const u8) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            const cfg = try parseConfig(arena.allocator(), raw);
            try testing.expectEqual(@as(usize, 2), cfg.config.?.Env.?.len);
        }
    };
    const d = comptime "sha256:" ++ layer.repeat('a', 64);
    const index = std.fmt.comptimePrint(
        \\{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
        \\ {{"digest":"{s}","size":1,"platform":{{"architecture":"amd64","os":"linux"}}}},
        \\ {{"digest":"{s}","platform":{{"architecture":"arm64","os":"linux","variant":"v8"}},"annotations":{{"x":"y"}}}}]}}
    , .{ d, d });
    const image = std.fmt.comptimePrint(
        \\{{"schemaVersion":2,"config":{{"mediaType":"c","digest":"{s}"}},
        \\ "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{s}","size":3}}]}}
    , .{ d, d });
    try af.checkOne(S.manifest, .{ index, true });
    try af.checkOne(S.manifest, .{ image, true });
    // Refused, each with a message: schema 1, a digest that is not sha256, not JSON.
    try af.checkOne(S.manifest, .{ "{\"schemaVersion\":1}", false });
    try af.checkOne(S.manifest, .{ "{\"schemaVersion\":2,\"layers\":[{\"digest\":\"md5:x\"}]}", false });
    try af.checkOne(S.manifest, .{ "not json", false });
    try af.checkOne(S.config, .{
        \\{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin","A=1"],"User":"u","WorkingDir":"/w"},
        \\ "rootfs":{"type":"layers","diff_ids":["sha256:1","sha256:2"]},"history":[{"created_by":"x"}]}
    });
}
