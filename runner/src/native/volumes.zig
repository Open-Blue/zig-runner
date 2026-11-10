//! Cache volumes for native jobs (docs/native-backend.md, P4): what Dagger's `cacheVolume`s are
//! to the Dagger backend, as host directories bound into every step. A volume is never part of a
//! step's layers, so it is never part of what P2 will key a step on (`Input.mounts` in the
//! model), and it outlives the job.
//!
//! The volumes are the Dagger backend's, by the same names, paths and rules (`set_up.zig`):
//! one per package manager the job uses (`set_up.cachesUsed`), the tool cache for every job,
//! Zig's package tarballs under its global cache, Zig's local cache in the `repo` scope only, and
//! uv's project environment inside uv's volume. Each lives under the store at
//! `volumes/<owner>/<repository>/<scope>/<name>[/<image>][/runner]`, so the `repo` and
//! `untrusted` scopes of `set_up.packageCacheScope` are separate directory trees: an untrusted
//! job can plant nothing a trusted one reads.
//!
//! Dagger's sharing modes are kept with an flock on `<volume>.lock` beside each volume, held for
//! the job: `shared` (Dagger's default, and every volume's here) takes it shared, so jobs use a
//! volume at once and only an eviction (`evict.zig`) has to wait, which it does not: it takes the
//! lock non-blocking and leaves a volume in use alone. `locked` takes it exclusive, so jobs take
//! turns; `private` takes it exclusive if it is free and otherwise gives the job a fresh volume of
//! its own, under a lock of its own (`<volume>.private-<n>.lock`), removed when the job ends, or
//! by the next collect when the job's runner died. The lock's mtime is the volume's last use.
//! A volume is a cache: one that was evicted is an empty directory to the next job, as a new one
//! is, and a job that held it to its end never sees that.
//!
//! Ownership. On a root runner each job's ids are its slot's range, so a volume filled by one
//! slot's job would be nobody's to the next slot's. Its files are owned on disk by a range of
//! their own instead (`Backend.volumeIdBase`, just past the slots' ranges, no host user's), and
//! each step sees them through an idmapped mount as its own ids (`sandbox.Spec.Bind.volume`):
//! root's files as the job's root's, 1001's as its runner user's. Never host ids: a setuid file a
//! job left in a volume is then nobody's on the host, and the mount is nosuid anyway.
//!
//! A job container's named volumes (`volumes: - name:/path`, `openNamed`) live here too, beside
//! the caches of their repository and scope (`namedKey`), and outlive the job as Docker's do. Their
//! files are owned and seen as the cache volumes' are. Unlike Docker's, they are evicted as the
//! cache volumes are (least recently used, past `RUNNER_NATIVE_VOLUMES_MAX_MB` or under the disk's
//! floor), so one a job has not used for a day can be gone: what a workflow keeps in one must be
//! something it can make again.
//!
//! The Zig cache seed (`Options.zig_seeds`, minisign-verified releases) is a layer, not a volume:
//! the global cache `zig build --help` leaves, built once per release, architecture and step user
//! in a sandbox from the release's tarball checked against its pinned sha256, as the Dagger
//! backend builds it (`set_up.zigSeedScript`), and kept under `seeds/`. It sits between the
//! rootfs and the job's layers, so what a job adds to its global cache goes in the job's own
//! layers, as Dagger mounts the seed as a directory whose writes go with the container. Nothing a
//! job wrote is in it, which is why one seed may go to every scope's jobs. A job holds each seed it
//! runs on until it ends (`Backend.holdSeed`), and `evict.zig` takes one no job holds.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const config = @import("../config.zig");
const dagger = @import("../dagger.zig");
const job_mod = @import("../job.zig");
const set_up = @import("../dagger/set_up.zig");
const sandbox = @import("sandbox.zig");
const OciStore = @import("oci/Store.zig");
const Store = @import("Store.zig");
const evict = @import("evict.zig");

const Allocator = std.mem.Allocator;

/// What the job's options say of caches: `dagger.Options`' own, kept by `runNative` before it
/// turns them off for the shared code (which would ask a Dagger session for volumes).
pub const Options = struct {
    package_caches: bool = false,
    trusted: bool = false,
    uv_env_in_cache: bool = false,
    zig_local_cache: bool = false,
    zig_local_cache_max_mb: u32 = 0,
    zig_seeds: []const config.ZigSeed = &.{},
    zig_seeds_unverified: []const []const u8 = &.{},
    /// "Set up job" checks the tool cache's trees (`tool_trees.zig`).
    tool_trees: bool = false,
    /// The job's cancel, which ends that check.
    cancel: ?*const dagger.Cancel = null,

    pub fn of(opts: dagger.Options) Options {
        return .{
            .package_caches = opts.package_caches,
            .trusted = opts.trusted,
            .uv_env_in_cache = opts.uv_env_in_cache,
            .zig_local_cache = opts.zig_local_cache,
            .zig_local_cache_max_mb = opts.zig_local_cache_max_mb,
            .zig_seeds = opts.zig_seeds,
            .zig_seeds_unverified = opts.zig_seeds_unverified,
            .tool_trees = opts.tool_trees,
            .cancel = opts.cancel,
        };
    }
};

const lock_sh: i32 = 1;
const lock_ex: i32 = 2;
const lock_nb: i32 = 4;

/// Dagger's cache sharing modes (`CacheSharingMode`).
pub const Sharing = enum { shared, locked, private };

/// A volume a job holds: its directory, and the lock that holds it.
pub const Volume = struct {
    dir: []const u8,
    /// `<store>/volumes`, which `dir` is below.
    root: []const u8,
    lock: std.Io.File,
    /// A `private` volume's copy of the job's own, removed when it is let go.
    private: bool = false,
    /// Made by this open (`openNamed`): it is held exclusively until `share`, so the job can
    /// seed it from its image before any other job sees it.
    new: bool = false,

    /// A new named volume, seeded, given to the jobs that wait for it: its lock taken shared.
    pub fn share(v: *Volume) void {
        std.debug.assert(v.new);
        _ = linux.flock(v.lock.handle, lock_sh);
        v.new = false;
    }

    /// A new named volume that could not be seeded, removed, so the next job makes it again
    /// and seeds it. Its lock is still held exclusively here: no job is in it.
    pub fn discard(v: Volume, io: std.Io) void {
        std.debug.assert(v.new);
        std.Io.Dir.cwd().deleteTree(io, v.dir) catch |e|
            std.log.warn("native: cannot remove {s}: {s}", .{ v.dir, @errorName(e) });
        v.lock.close(io);
    }

    /// Lets the volume go; a private copy is removed, and its lock with it.
    pub fn release(v: Volume, io: std.Io) void {
        defer v.lock.close(io);
        if (!v.private) return;
        const cwd = std.Io.Dir.cwd();
        cwd.deleteTree(io, v.dir) catch |e|
            std.log.warn("native: cannot remove {s}: {s}", .{ v.dir, @errorName(e) });
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const lock = std.fmt.bufPrint(&buf, "{s}.lock", .{v.dir}) catch return;
        cwd.deleteFile(io, lock) catch {};
    }
};

/// The volume at `<store>/volumes/<key...>`, made if missing, its root owned by `owner` (a host
/// id, for both uid and gid; null leaves it the runner's), and held as `sharing` says. Each part
/// of the key is a name of its own (`component`), so none can reach outside the store.
pub fn open(
    arena: Allocator,
    io: std.Io,
    store: []const u8,
    key: []const []const u8,
    sharing: Sharing,
    owner: ?u32,
) !Volume {
    const root = try std.fmt.allocPrint(arena, "{s}/volumes", .{store});
    try std.Io.Dir.cwd().createDirPath(io, root);
    // Only the runner's user may look in: a job's files are here, whoever owns them.
    _ = linux.chmod(try arena.dupeSentinel(u8, root, 0), 0o700);
    var path: std.ArrayList(u8) = .empty;
    try path.appendSlice(arena, root);
    for (key) |part| {
        try path.append(arena, '/');
        try path.appendSlice(arena, try component(arena, part));
    }
    const dir = path.items;
    const lock_path = try std.fmt.allocPrint(arena, "{s}.lock", .{dir});
    var private = false;
    // Until the lock is on the file the path names: an eviction removes the file once it has the
    // volume away, and can take the directory it is in (`evict.nested`).
    var lock = while (true) {
        try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(dir).?);
        const f = Store.lockBeside(arena, io, lock_path) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        errdefer f.close(io);
        switch (sharing) {
            .shared, .locked => {
                const op = if (sharing == .shared) lock_sh else lock_ex;
                if (linux.errno(linux.flock(f.handle, op)) != .SUCCESS) return error.Locked;
            },
            .private => private = linux.errno(linux.flock(f.handle, lock_ex | lock_nb)) != .SUCCESS,
        }
        if (private or Store.sameFile(arena, f, lock_path)) break f;
        f.close(io);
    };
    errdefer lock.close(io);
    const at = if (private) private: {
        var raw: [8]u8 = undefined;
        io.random(&raw);
        const copy = try std.fmt.allocPrint(arena, "{s}.private-{s}", .{
            dir,
            &std.fmt.bytesToHex(raw, .lower),
        });
        // A lock of its own, which tells a copy in use from one a dead runner left.
        const own = try Store.lockBeside(arena, io, try std.fmt.allocPrint(arena, "{s}.lock", .{copy}));
        lock.close(io);
        lock = own;
        if (linux.errno(linux.flock(lock.handle, lock_ex | lock_nb)) != .SUCCESS) return error.Locked;
        break :private copy;
    } else dir;
    // Its last use, which an eviction goes by.
    _ = linux.utimensat(lock.handle, null, null, 0);
    const at_z = try arena.dupeSentinel(u8, at, 0);
    switch (linux.errno(linux.mkdir(at_z, 0o755))) {
        .SUCCESS => {},
        .EXIST => {
            // The one name inside another volume, where a job may have left anything. Anywhere
            // else no job reaches, and what is there is the store's.
            var st: linux.Statx = undefined;
            const rc = linux.statx(linux.AT.FDCWD, at_z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st);
            if (linux.errno(rc) != .SUCCESS) return error.VolumeNotMade;
            if (st.mode & linux.S.IFMT != linux.S.IFDIR) {
                if (!std.mem.eql(u8, std.fs.path.basename(at), evict.nested)) return error.VolumeNotMade;
                if (linux.errno(linux.unlink(at_z)) != .SUCCESS) return error.VolumeNotMade;
                if (linux.errno(linux.mkdir(at_z, 0o755)) != .SUCCESS) return error.VolumeNotMade;
            }
        },
        else => return error.VolumeNotMade,
    }
    if (owner) |o| if (linux.errno(linux.lchown(at_z, o, o)) != .SUCCESS)
        return error.VolumeNotOwned;
    return .{ .dir = at, .root = root, .lock = lock, .private = private };
}

/// One part of a volume's key as a directory name: the characters a repository's or a tool's
/// name has (letters, digits, `.`, `-`, `_`) kept, any other turned into `-`, and a name that is
/// empty or starts with a dot marked with a leading `~`, so no part is `.`, `..` or a path. A job
/// chooses its image, and so a part of its key: none may read as what the store keeps beside a
/// volume or calls one that is going (`.lock`, `.size`, `.private-<n>`, `.dead-<n>`), or its sibling
/// would take it for that, so those are marked with `~` too. No name keeps a `~` of its own, so a
/// marked name is no other repository's, which would share its volume: Zig runs what it finds in
/// `zig-local` unchecked.
pub fn component(arena: Allocator, part: []const u8) ![]const u8 {
    var out = try arena.alloc(u8, part.len);
    for (part, 0..) |c, i| out[i] = if (std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or
        c == '_') c else '-';
    while (std.mem.indexOf(u8, out, ".private-")) |at| out[at] = '~';
    if (out.len == 0 or out[0] == '.') out = try std.mem.concat(arena, u8, &.{ "~", out });
    if (std.mem.endsWith(u8, out, ".lock") or std.mem.endsWith(u8, out, ".size"))
        out = try std.mem.concat(arena, u8, &.{ out, "~" });
    return out;
}

/// The part of a key under a scope that holds the job containers' named volumes: no cache volume
/// is called so (`set_up.package_cache_dirs`, `zig-local`, `zig-builtin`).
pub const named_part = "named";

/// The key of a job container's named volume `name` (`volumes: - name:/path`):
/// `<owner>/<repository>/<scope>/named/<name>`. Docker's volumes are the host's, one namespace for
/// every container; here a name is the repository's, in its trust scope, because a volume holds
/// what one job left for the next, which reads it as its own: a job of another repository, or an
/// untrusted job of this one (a fork's pull request, `set_up.packageCacheScope`), could otherwise
/// plant files in it that a trusted job runs or ships. A workflow that shares a volume across
/// repositories on Docker gets one per repository here.
pub fn namedKey(arena: Allocator, repository: []const u8, scope: []const u8, name: []const u8) ![]const []const u8 {
    if (repository.len == 0) return error.NoRepository;
    var parts = std.mem.splitScalar(u8, repository, '/');
    const repo_owner = parts.next().?;
    return arena.dupe([]const u8, &.{ repo_owner, parts.rest(), scope, named_part, name });
}

/// A job container's named volume (`namedKey`), made if missing, held for the job as a cache
/// volume is (its lock shared, so jobs use it at once as Docker's containers do, and an eviction
/// takes none in use). One this open made is `new`, its root owned by `owner` (a host id; null
/// leaves it the runner's) and its lock held exclusively until the job has seeded it from its
/// image (`Volume.share`), so a job that opens it meanwhile waits for it whole: Docker copies the
/// image's files into a volume once, before the first container that mounts it starts. An open
/// that finds it in use waits only for such a seeding, never for a job that holds it shared.
pub fn openNamed(
    arena: Allocator,
    io: std.Io,
    store: []const u8,
    key: []const []const u8,
    owner: ?u32,
) !Volume {
    return openNamedWaiting(arena, io, store, key, owner, .{});
}

/// How long a job's seeding of a new named volume may take (`Backend.seedVolume` stops it then).
pub const seed_limit_ms: u64 = 10 * 60 * 1000;

/// How an open waits for another job's seeding of the volume: never for good.
pub const Wait = struct {
    /// Past the longest seeding, by a margin: a holder past it is stuck, not slow.
    ms: u64 = seed_limit_ms + 60 * 1000,
    /// The job's cancel (`dagger.Cancel.requested`): the open gives up at once when it is set.
    cancel: ?*const std.atomic.Value(bool) = null,
};

/// `openNamed`, waiting for another job's seeding as `wait` says: `error.VolumeBusy` past its
/// time, `error.Canceled` once the job is cancelled.
pub fn openNamedWaiting(
    arena: Allocator,
    io: std.Io,
    store: []const u8,
    key: []const []const u8,
    owner: ?u32,
    wait: Wait,
) !Volume {
    const root = try std.fmt.allocPrint(arena, "{s}/volumes", .{store});
    try std.Io.Dir.cwd().createDirPath(io, root);
    _ = linux.chmod(try arena.dupeSentinel(u8, root, 0), 0o700);
    var path: std.ArrayList(u8) = .empty;
    try path.appendSlice(arena, root);
    for (key) |part| {
        try path.append(arena, '/');
        try path.appendSlice(arena, try component(arena, part));
    }
    const dir = path.items;
    const dir_z = try arena.dupeSentinel(u8, dir, 0);
    const lock_path = try std.fmt.allocPrint(arena, "{s}.lock", .{dir});
    // Each turn ends with the lock on the file the path names, or starts again: an eviction
    // removes the file once it has taken the volume away, and a seeding that failed removes the
    // volume (`Volume.discard`).
    var turns: u32 = 0;
    while (turns < 64) : (turns += 1) {
        try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(dir).?);
        const f = Store.lockBeside(arena, io, lock_path) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        errdefer f.close(io);
        // Free: this job may make it. Not free: it is in use, so it is there, or being seeded,
        // which a shared lock waits for.
        const alone = linux.errno(linux.flock(f.handle, lock_ex | lock_nb)) == .SUCCESS;
        if (!alone) try waitShared(io, f, wait);
        if (!Store.sameFile(arena, f, lock_path)) {
            f.close(io);
            continue;
        }
        _ = linux.utimensat(f.handle, null, null, 0);
        const made = switch (linux.errno(linux.mkdir(dir_z, 0o755))) {
            .SUCCESS => true,
            .EXIST => false,
            else => return error.VolumeNotMade,
        };
        if (made and !alone) {
            // Gone since it was in use (evicted, or its seeding failed): made again by an open
            // that holds it alone, so it is seeded.
            _ = linux.rmdir(dir_z);
            f.close(io);
            continue;
        }
        if (!made) {
            // Only the runner writes here, never a job: what is not a directory is the store's
            // fault.
            var st: linux.Statx = undefined;
            const rc = linux.statx(linux.AT.FDCWD, dir_z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st);
            if (linux.errno(rc) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFDIR)
                return error.VolumeNotMade;
            if (alone) _ = linux.flock(f.handle, lock_sh);
            return .{ .dir = dir, .root = root, .lock = f };
        }
        if (owner) |o| if (linux.errno(linux.lchown(dir_z, o, o)) != .SUCCESS) {
            _ = linux.rmdir(dir_z);
            return error.VolumeNotOwned;
        };
        return .{ .dir = dir, .root = root, .lock = f, .new = true };
    }
    return error.Locked;
}

/// The lock `f` taken shared, polled (`LOCK_NB`) while another job holds it exclusively (a seeding),
/// until `wait`'s time is up or the job is cancelled.
fn waitShared(io: std.Io, f: std.Io.File, wait: Wait) !void {
    const start = nowMs();
    while (true) {
        switch (linux.errno(linux.flock(f.handle, lock_sh | lock_nb))) {
            .SUCCESS => return,
            .AGAIN, .INTR => {},
            else => return error.Locked,
        }
        if (wait.cancel) |c| if (c.load(.acquire)) return error.Canceled;
        if (nowMs() -| start >= wait.ms) return error.VolumeBusy;
        io.sleep(.fromMilliseconds(50), .awake) catch return error.Canceled;
    }
}

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const sec = std.math.cast(u64, ts.sec) orelse 0;
    const nsec = std.math.cast(u64, ts.nsec) orelse 0;
    return sec * 1000 + nsec / 1_000_000;
}

/// What a job gets of the caches (`plan`).
pub const Plan = struct {
    /// The volumes, held until the job ends (`release`).
    held: std.ArrayList(Volume) = .empty,
    /// Each volume's mount, for every step.
    binds: std.ArrayList(sandbox.Spec.Bind) = .empty,
    /// Set right after the image's own env, before the job's (`set_up.writeFrom`): Zig's local
    /// cache directory.
    early_env: std.ArrayList(job_mod.EnvVar) = .empty,
    /// Set before GitHub's defaults (`set_up.writeRunEnv`): uv's project environment.
    env: std.ArrayList(job_mod.EnvVar) = .empty,
    /// uv's environment in its volume: the workspace's `.venv` links to it.
    uv_env: ?[]const u8 = null,
    /// Where the `toolcache` volume is bound (RUNNER_TOOL_CACHE), when the job has one: what a
    /// step installs there is in no layer, so a replay is checked against it (`Exec.tool_cache`).
    tool_cache: ?[]const u8 = null,
    /// The same volume's directory on the host, where `tool_trees.check` reads the trees.
    tool_cache_host: ?[]const u8 = null,
    /// Zig's local cache volume, when its generations are rolled (`zig_local_cache_max_mb`).
    zig_local_roll: ?[]const u8 = null,
    /// The volume of the `builtin.zig` files the local cache's manifests name, bound once the
    /// seeds are in (`Backend.seedBuiltin`) because its mount hides the seed's own `b/`.
    zig_builtin: ?sandbox.Spec.Bind = null,
    /// The Zig cache seeds the job runs with, built if missing (`Seed`).
    seeds: std.ArrayList(Seed) = .empty,
    /// What "Set up job" says of them.
    notes: std.ArrayList([]const u8) = .empty,

    pub fn release(p: *Plan, io: std.Io) void {
        for (p.held.items) |v| v.release(io);
        p.held.clearRetainingCapacity();
    }
};

/// A Zig cache seed's layer: built in `dir` when it is not there yet.
pub const Seed = struct {
    seed: config.ZigSeed,
    dir: []const u8,
    /// Where the global cache is, relative to the layer's root: the step user's.
    cache: []const u8,
};

/// The job's caches, as the Dagger backend gives them (`set_up.basePlan`): its volumes opened
/// and held, their mounts, the variables that point at them, and the seeds it runs with.
/// `volume_owner` is the volumes' first on-disk id on a root runner (null rootless).
pub fn plan(
    arena: Allocator,
    io: std.Io,
    store: []const u8,
    opts: Options,
    scope: []const u8,
    job: job_mod.Job,
    /// The job's image (`dagger.resolveImage`): the tool cache is one per image, as on Dagger.
    job_image: []const u8,
    as_runner: bool,
    step_cache: bool,
    volume_owner: ?u32,
) !Plan {
    var p: Plan = .{};
    errdefer p.release(io);
    const repo = job.github.repository;
    if (!opts.package_caches or repo.len == 0) return p;
    const owner: ?u32 = if (volume_owner) |base|
        base + @as(u32, if (as_runner) dagger_runner_uid else 0)
    else
        null;
    const used = set_up.cachesUsed(job);
    var repo_parts = std.mem.splitScalar(u8, repo, '/');
    const repo_owner = repo_parts.next().?;
    const repo_name = repo_parts.rest();
    for (set_up.package_cache_dirs, used, 0..) |d, u, i| {
        if (!u) continue;
        var key: std.ArrayList([]const u8) = .empty;
        try key.appendSlice(arena, &.{ repo_owner, repo_name, scope, d.name });
        // The tool cache holds binaries built for one image: one per image, by name.
        if (std.mem.eql(u8, d.name, "toolcache")) try key.append(arena, dagger.imageName(job_image));
        if (as_runner) try key.append(arena, dagger.runner_user);
        const v = try open(arena, io, store, key.items, .shared, owner);
        try p.held.append(arena, v);
        const path = if (as_runner) try set_up.runnerCachePath(arena, i) else d.path;
        if (std.mem.eql(u8, d.name, "toolcache")) {
            p.tool_cache = path;
            p.tool_cache_host = v.dir;
        }
        const zig = std.mem.eql(u8, d.name, set_up.zig_packages);
        // Zig's global cache is the job's own (its layers, over the seed); only its package
        // tarballs, which Zig hashes again when it unpacks them, are in the volume.
        try p.binds.append(arena, .{
            .host = v.dir,
            .volume_root = v.root,
            .at = if (zig) try std.mem.concat(arena, u8, &.{ path, "/p" }) else path,
            .read_only = false,
            .volume = true,
            .make = true,
        });
        if (std.mem.eql(u8, d.name, "uv") and opts.uv_env_in_cache and !step_cache)
            p.uv_env = try set_up.uvEnvPath(arena, path, job.github.ref);
    }
    if (p.uv_env) |e| try p.env.appendSlice(arena, &.{
        .{ .name = "UV_PROJECT_ENVIRONMENT", .value = e },
        .{ .name = "UV_VENV_CLEAR", .value = "1" },
    });

    if (opts.zig_local_cache) {
        try p.early_env.append(arena, .{
            .name = "ZIG_LOCAL_CACHE_DIR",
            .value = set_up.zigLocalCacheEnv(as_runner, opts.zig_local_cache_max_mb),
        });
        // Shared only between the jobs the runner vouches for (`set_up.zigLocalShared`): Zig
        // runs what it finds there without checking it.
        if (std.mem.eql(u8, scope, "repo")) {
            const key = [_][]const u8{ repo_owner, repo_name, scope, "zig-local" };
            const keyed = if (as_runner)
                try std.mem.concat(arena, []const u8, &.{ &key, &.{dagger.runner_user} })
            else
                &key;
            const v = try open(arena, io, store, keyed, .shared, owner);
            try p.held.append(arena, v);
            try p.binds.append(arena, .{
                .host = v.dir,
                .volume_root = v.root,
                .at = set_up.zigLocalCacheDir(as_runner),
                .read_only = false,
                .volume = true,
                .make = true,
            });
            if (opts.zig_local_cache_max_mb > 0) p.zig_local_roll = v.dir;
            // The `builtin.zig` files its manifests name, which Zig keeps in the global cache
            // that is otherwise the job's own (`set_up.zigBuiltinDir`).
            const builtin_key = [_][]const u8{ repo_owner, repo_name, scope, "zig-builtin" };
            const builtin_keyed = if (as_runner)
                try std.mem.concat(arena, []const u8, &.{ &builtin_key, &.{dagger.runner_user} })
            else
                &builtin_key;
            const b = try open(arena, io, store, builtin_keyed, .shared, owner);
            try p.held.append(arena, b);
            p.zig_builtin = .{
                .host = b.dir,
                .volume_root = b.root,
                .at = try set_up.zigBuiltinDir(arena, as_runner),
                .read_only = false,
                .volume = true,
                .make = true,
            };
        } else try p.notes.append(arena, "Zig local cache: this job's own (not kept between " ++
            "untrusted jobs)");
    }

    if (set_up.usesZig(job)) {
        const unverified = if (opts.zig_seeds_unverified.len == 0) "" else try std.fmt.allocPrint(
            arena,
            "; not seeded from Zig {s}: its tarball's signature was not verified",
            .{try std.mem.join(arena, ", ", opts.zig_seeds_unverified)},
        );
        if (opts.zig_seeds.len == 0) {
            if (unverified.len > 0) try p.notes.append(arena, try std.fmt.allocPrint(
                arena,
                "Zig global cache not seeded, this job's own{s}",
                .{unverified},
            ));
        }
        for (opts.zig_seeds) |seed| try p.seeds.append(arena, try seedFor(arena, store, seed, as_runner));
    }
    return p;
}

/// Where `seed` lives in the store, and where its cache is in the layer, for the step user: the
/// one place a job (`plan`) and the pre-warm (`Backend.warm`) both name it, so the seed the
/// pre-warm built is the one a job finds.
pub fn seedFor(arena: Allocator, store: []const u8, seed: config.ZigSeed, as_runner: bool) !Seed {
    const zig_dir = set_up.package_cache_dirs[zig_index].path;
    const cache = if (as_runner) try set_up.runnerCachePath(arena, zig_index) else zig_dir;
    return .{
        .seed = seed,
        .dir = try std.fmt.allocPrint(arena, "{s}/seeds/{s}-{s}-{s}", .{
            store,
            @tagName(builtin.cpu.arch),
            try component(arena, seed.version),
            if (as_runner) dagger.runner_user else "root",
        }),
        .cache = std.mem.trimStart(u8, cache, "/"),
    };
}

const zig_index = for (set_up.package_cache_dirs, 0..) |d, i| {
    if (std.mem.eql(u8, d.name, set_up.zig_packages)) break i;
} else unreachable;

/// `runner_user`'s uid in the provisioned image.
pub const dagger_runner_uid = 1001;

/// "Set up job"'s line on the seeds, as the Dagger backend says it (`set_up.zigSeedFor`).
pub fn seedNote(
    arena: Allocator,
    opts: Options,
    seeded: []const []const u8,
    failure: ?[]const u8,
) !?[]const u8 {
    if (opts.zig_seeds.len == 0) return null;
    const unverified = if (opts.zig_seeds_unverified.len == 0) "" else try std.fmt.allocPrint(
        arena,
        "; not seeded from Zig {s}: its tarball's signature was not verified",
        .{try std.mem.join(arena, ", ", opts.zig_seeds_unverified)},
    );
    if (seeded.len > 0) return try std.fmt.allocPrint(arena, "Zig global cache seeded from " ++
        "Zig {s}{s}", .{ try std.mem.join(arena, ", ", seeded), unverified });
    return try std.fmt.allocPrint(arena, "Zig cache seed not built, running unseeded: {s}{s}", .{
        failure orelse "no seed was built",
        unverified,
    });
}

/// Makes a built seed `seed.dir`: the cache the build left at `built` (in its sandbox's layer)
/// moved under `seed.cache` in a new layer, the directories above it as the rootfs has them, its
/// files owned by the step user on disk (`user`, the image's id: the layer is seen through the
/// job's ids, as the rootfs is) or left the runner's (null, rootless), no setuid or setgid bit
/// on any, an empty `p` for the package volume's mount, and published by rename, so a seed is
/// whole or absent. One built at once by another runner wins; this one is dropped.
pub fn adoptSeed(
    arena: Allocator,
    io: std.Io,
    built: []const u8,
    seed: Seed,
    rootfs: []const u8,
    user: ?u32,
) !void {
    const cwd = std.Io.Dir.cwd();
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const new = try std.fmt.allocPrint(arena, "{s}.new-{s}", .{
        seed.dir,
        &std.fmt.bytesToHex(raw, .lower),
    });
    try cwd.createDirPath(io, new);
    errdefer cwd.deleteTree(io, new) catch {};
    // The directories above the cache, as the rootfs has them (`/root` is 0700), or made the
    // step user's.
    var parts = std.mem.splitScalar(u8, seed.cache, '/');
    var rel: std.ArrayList(u8) = .empty;
    var last: []const u8 = "";
    while (parts.next()) |part| {
        if (rel.items.len > 0) try rel.append(arena, '/');
        try rel.appendSlice(arena, part);
        if (parts.peek() == null) {
            last = rel.items;
            break;
        }
        const at = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ new, rel.items }, 0);
        const in_rootfs = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{
            rootfs,
            rel.items,
        }, 0);
        var st: linux.Statx = undefined;
        const mask: linux.STATX = .{ .MODE = true, .UID = true, .GID = true, .TYPE = true };
        const rc = linux.statx(linux.AT.FDCWD, in_rootfs, linux.AT.SYMLINK_NOFOLLOW, mask, &st);
        const there = linux.errno(rc) == .SUCCESS and st.mode & linux.S.IFMT == linux.S.IFDIR;
        if (linux.errno(linux.mkdir(at, 0o755)) != .SUCCESS) return error.SeedNotMade;
        if (there) {
            _ = linux.chmod(at, st.mode & 0o7777);
            if (user != null) _ = linux.lchown(at, st.uid, st.gid);
        } else if (user) |u| _ = linux.lchown(at, u, u);
    }
    const into = try std.fmt.allocPrint(arena, "{s}/{s}", .{ new, last });
    try cwd.rename(built, cwd, into, io);
    try ownTree(arena, io, into, user, 0);
    const p = try std.fmt.allocPrintSentinel(arena, "{s}/p", .{into}, 0);
    _ = linux.mkdir(p, 0o755);
    if (user) |u| _ = linux.lchown(p, u, u);
    // Nothing below would notice a seed a crash emptied: a key says which build it is, not what it holds.
    try OciStore.syncFilesystem(arena, new);
    cwd.rename(new, cwd, seed.dir, io) catch |e| switch (e) {
        error.DirNotEmpty => {
            cwd.deleteTree(io, new) catch {};
            return;
        },
        else => return e,
    };
}

/// What keys know a seed by: its path, and which build lives there. A seed evicted is built again
/// under the same path, from the same release, and need not be the same tree, so a layer on the old
/// one must not be replayed on the new (`Backend.below`). Which directory, since when: no one
/// changes a seed's root once it is published.
pub fn seedId(arena: Allocator, dir: []const u8) ![]const u8 {
    var st: linux.Statx = undefined;
    const z = try arena.dupeSentinel(u8, dir, 0);
    const mask: linux.STATX = .{ .INO = true, .CTIME = true };
    if (linux.errno(linux.statx(linux.AT.FDCWD, z, linux.AT.SYMLINK_NOFOLLOW, mask, &st)) != .SUCCESS)
        return error.SeedGone;
    return std.fmt.allocPrint(arena, "{s}@{d}.{d}.{d}", .{ dir, st.ino, st.ctime.sec, st.ctime.nsec });
}

/// Every file under `path` owned by `user` (none followed through a symlink), and every
/// setuid and setgid bit cleared.
fn ownTree(arena: Allocator, io: std.Io, path: []const u8, user: ?u32, depth: u32) !void {
    if (depth > 64) return error.SeedTooDeep;
    const p = try arena.dupeSentinel(u8, path, 0);
    if (user) |u| _ = linux.lchown(p, u, u);
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        const sub = try std.fmt.allocPrint(arena, "{s}/{s}", .{ path, e.name });
        const s = try arena.dupeSentinel(u8, sub, 0);
        switch (e.kind) {
            .directory => try ownTree(arena, io, sub, user, depth + 1),
            .sym_link => if (user) |u| {
                _ = linux.lchown(s, u, u);
            },
            else => {
                if (user) |u| _ = linux.lchown(s, u, u);
                var st: linux.Statx = undefined;
                if (linux.errno(linux.statx(linux.AT.FDCWD, s, linux.AT.SYMLINK_NOFOLLOW, .{
                    .MODE = true,
                }, &st)) == .SUCCESS and st.mode & 0o6000 != 0)
                    _ = linux.chmod(s, st.mode & 0o1777);
            },
        }
    }
}

test "native volumes: a seed built again is another seed to a key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cwd = std.Io.Dir.cwd();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const dir = try std.fmt.allocPrint(arena, "{s}/seed", .{root});
    const aside = try std.fmt.allocPrint(arena, "{s}/aside", .{root});
    try cwd.createDirPath(io, dir);
    const first = try seedId(arena, dir);
    try std.testing.expectEqualStrings(first, try seedId(arena, dir));
    // The old one still there, so no inode can be used again.
    try cwd.rename(dir, cwd, aside, io);
    try cwd.createDirPath(io, dir);
    try std.testing.expect(!std.mem.eql(u8, first, try seedId(arena, dir)));
}

test "native volumes: a key's parts are names of their own" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    try std.testing.expectEqualStrings("Open-Blue", try component(arena, "Open-Blue"));
    try std.testing.expectEqualStrings("zig-runner.v2_x", try component(arena, "zig-runner.v2_x"));
    try std.testing.expectEqualStrings("a-b-c", try component(arena, "a/b c"));
    try std.testing.expectEqualStrings("~..", try component(arena, ".."));
    try std.testing.expectEqualStrings("~.", try component(arena, "."));
    try std.testing.expectEqualStrings("~", try component(arena, ""));
    try std.testing.expectEqualStrings("-", try component(arena, "~"));
    try std.testing.expectEqualStrings("foo.lock~", try component(arena, "foo.lock"));
    try std.testing.expectEqualStrings("~.github", try component(arena, ".github"));
    try std.testing.expectEqualStrings("a~private-b", try component(arena, "a.private-b"));
}

test "native volumes: shared ones are used at once, locked ones in turn, private ones copied" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const key = [_][]const u8{ "o", "r", "repo", "npm" };
    const one = try open(arena, io, store, &key, .shared, null);
    const two = try open(arena, io, store, &key, .shared, null);
    try std.testing.expectEqualStrings(one.dir, two.dir);
    try std.testing.expect(std.mem.endsWith(u8, one.dir, "/volumes/o/r/repo/npm"));
    // In use: a private one is the job's own copy, gone when it is let go.
    const mine = try open(arena, io, store, &key, .private, null);
    try std.testing.expect(mine.private);
    try std.testing.expect(!std.mem.eql(u8, mine.dir, one.dir));
    mine.release(io);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, mine.dir, .{}));
    one.release(io);
    two.release(io);
    // Free: a private one is the volume itself, and a locked one is then held for it alone.
    const alone = try open(arena, io, store, &key, .private, null);
    try std.testing.expect(!alone.private);
    try std.testing.expectEqualStrings(one.dir, alone.dir);
    const probe = try std.Io.Dir.cwd().openFile(io, try std.fmt.allocPrint(arena, "{s}.lock", .{
        alone.dir,
    }), .{});
    defer probe.close(io);
    try std.testing.expect(linux.errno(linux.flock(probe.handle, lock_ex | lock_nb)) != .SUCCESS);
    alone.release(io);
    try std.testing.expect(linux.errno(linux.flock(probe.handle, lock_ex | lock_nb)) == .SUCCESS);
}

test "native volumes: the job's caches, by scope and step user, as the Dagger backend names them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const testing = @import("../dagger/testing.zig");
    var job = testing.testJob(&.{testing.testStep("npm ci && zig build test && uv sync")});
    job.github.repository = "o/r";
    job.github.ref = "refs/heads/main";
    const opts: Options = .{
        .package_caches = true,
        .trusted = true,
        .uv_env_in_cache = true,
        .zig_local_cache = true,
        .zig_local_cache_max_mb = 512,
        .zig_seeds = &.{.{ .version = "0.17.0", .sha256 = "ab" }},
    };
    var trusted = try plan(arena, io, store, opts, "repo", job, dagger.default_image, true, false, null);
    defer trusted.release(io);
    var ats: std.ArrayList([]const u8) = .empty;
    for (trusted.binds.items) |b| {
        try ats.append(arena, b.at);
        try std.testing.expect(b.volume and b.make and !b.read_only);
        try std.testing.expect(b.volume_root.len > 0);
        try std.testing.expect(std.mem.indexOf(u8, b.host, "/volumes/o/r/repo/") != null);
        try std.testing.expect(std.mem.endsWith(u8, b.host, "/runner"));
    }
    const want = [_][]const u8{
        "/opt/hostedtoolcache",
        "/home/runner/.npm",
        "/tmp/node-compile-cache",
        "/home/runner/.cache/uv",
        "/home/runner/.cache/zig/p",
        "/home/runner/.cache/zig-local",
    };
    for (want) |w| for (ats.items) |at| {
        if (std.mem.eql(u8, at, w)) break;
    } else {
        std.debug.print("no volume at {s}\n", .{w});
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(want.len, ats.items.len);
    try std.testing.expectEqualStrings(
        "/home/runner/.cache/uv/zig-runner-envs/refs-heads-main",
        trusted.uv_env.?,
    );
    try std.testing.expectEqualStrings(
        "/home/runner/.cache/zig-local/current",
        trusted.early_env.items[0].value,
    );
    try std.testing.expect(trusted.zig_local_roll != null);
    try std.testing.expectEqualStrings("/home/runner/.cache/zig/b", trusted.zig_builtin.?.at);
    try std.testing.expect(std.mem.endsWith(u8, trusted.zig_builtin.?.host, "/runner"));
    try std.testing.expectEqual(@as(usize, 1), trusted.seeds.items.len);
    try std.testing.expectEqualStrings("home/runner/.cache/zig", trusted.seeds.items[0].cache);
    // The tool cache is bound where Dagger mounts it, for every step user.
    try std.testing.expectEqualStrings(set_up.tool_cache_dir, trusted.tool_cache.?);

    // Untrusted: its own tree, and no shared Zig local cache.
    var untrusted = try plan(arena, io, store, opts, "untrusted", job, dagger.default_image, false, false, null);
    defer untrusted.release(io);
    for (untrusted.binds.items) |b| {
        try std.testing.expect(std.mem.indexOf(u8, b.host, "/volumes/o/r/untrusted/") != null);
        try std.testing.expect(!std.mem.eql(u8, b.at, "/root/.cache/zig-local"));
    }
    try std.testing.expect(untrusted.zig_local_roll == null);
    try std.testing.expect(untrusted.zig_builtin == null);
    try std.testing.expectEqualStrings("Zig local cache: this job's own (not kept between " ++
        "untrusted jobs)", untrusted.notes.items[0]);

    // No caches, or no repository to key them by: nothing.
    var off = opts;
    off.package_caches = false;
    const none = try plan(arena, io, store, off, "repo", job, dagger.default_image, false, false, null);
    try std.testing.expectEqual(@as(usize, 0), none.binds.items.len);
    // With step caching (P2), uv's environment stays in the workspace (#70).
    var cached = try plan(arena, io, store, opts, "repo", job, dagger.default_image, false, true, null);
    defer cached.release(io);
    try std.testing.expect(cached.uv_env == null);
}

test "native volumes: whatever an untrusted job names, its volumes stay in its own scope's tree" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const testing = @import("../dagger/testing.zig");
    var job = testing.testJob(&.{testing.testStep("npm ci && zig build test && uv sync")});
    job.github.repository = "o/r";
    const opts: Options = .{ .package_caches = true, .trusted = false, .zig_local_cache = true };
    // The job chooses its image, and the tool cache is a volume per image: none of these names a
    // place outside the untrusted tree, let alone the repository's (`component`).
    const images = [_][]const u8{
        "../../repo/toolcache/x",   "repo/../../repo/npm", "/etc",                 ".",
        "..",                       "",                    "x.lock",               "x.private-1",
        "../untrusted/../repo/npm", "ubuntu:24.04/../..",  "a\x00b/../../../repo",
    };
    const untrusted_tree = try std.fmt.allocPrint(arena, "{s}/volumes/o/r/untrusted/", .{store});
    for (images) |image| {
        var p = try plan(arena, io, store, opts, "untrusted", job, image, false, false, null);
        defer p.release(io);
        try std.testing.expect(p.binds.items.len > 0);
        for (p.binds.items) |b| {
            try std.testing.expect(std.mem.startsWith(u8, b.host, untrusted_tree));
            var parts = std.mem.splitScalar(u8, b.host[untrusted_tree.len..], '/');
            while (parts.next()) |part| {
                try std.testing.expect(part.len > 0 and !std.mem.eql(u8, part, ".") and !std.mem.eql(u8, part, ".."));
            }
        }
    }
    // The repository's tree was never made by any of them, and nothing escaped to the store's
    // other directories.
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "volumes/o/r/repo", .{}));
    var top = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer top.close(io);
    var it = top.iterate();
    while (try it.next(io)) |e| try std.testing.expectEqualStrings("volumes", e.name);
    var vols = try tmp.dir.openDir(io, "volumes/o/r", .{ .iterate = true });
    defer vols.close(io);
    var inside = vols.iterate();
    while (try inside.next(io)) |e| try std.testing.expectEqualStrings("untrusted", e.name);
}

test "native volumes: the pre-warm names a seed where a job's plan does, for each step user" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const testing = @import("../dagger/testing.zig");
    var job = testing.testJob(&.{testing.testStep("zig build test")});
    job.github.repository = "o/r";
    const seed: config.ZigSeed = .{ .version = "0.17.0", .sha256 = "ab" };
    const opts: Options = .{ .package_caches = true, .trusted = true, .zig_seeds = &.{seed} };
    for ([_]bool{ false, true }) |as_runner| {
        var p = try plan(arena, io, store, opts, "repo", job, dagger.default_image, as_runner, false, null);
        defer p.release(io);
        const named = try seedFor(arena, store, seed, as_runner);
        try std.testing.expectEqual(@as(usize, 1), p.seeds.items.len);
        try std.testing.expectEqualStrings(p.seeds.items[0].dir, named.dir);
        try std.testing.expectEqualStrings(p.seeds.items[0].cache, named.cache);
    }
    // The two users' seeds are apart: root's cache is not the runner user's.
    const root = try seedFor(arena, store, seed, false);
    const runner = try seedFor(arena, store, seed, true);
    try std.testing.expect(!std.mem.eql(u8, root.dir, runner.dir));
}

test "native named volumes: kept between opens, new only the first time, apart by scope and repository" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const cwd = std.Io.Dir.cwd();

    const key = try namedKey(arena, "o/r", "repo", "data");
    var first = try openNamed(arena, io, store, key, null);
    try std.testing.expect(first.new);
    try std.testing.expect(std.mem.endsWith(u8, first.dir, "/volumes/o/r/repo/named/data"));
    try cwd.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{first.dir}), .data = "kept" });
    first.share();
    first.release(io);
    // The next job finds it as the last left it, and seeds nothing.
    const again = try openNamed(arena, io, store, key, null);
    defer again.release(io);
    try std.testing.expect(!again.new);
    try std.testing.expectEqualStrings(first.dir, again.dir);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("kept", try cwd.readFile(io, try std.fmt.allocPrint(arena, "{s}/f", .{again.dir}), &buf));

    // An untrusted job of the repository, and a job of another, each get a volume of their own.
    for ([_][2][]const u8{ .{ "o/r", "untrusted" }, .{ "o/other", "repo" }, .{ "x/r", "repo" } }) |other| {
        var v = try openNamed(arena, io, store, try namedKey(arena, other[0], other[1], "data"), null);
        defer v.release(io);
        try std.testing.expect(v.new);
        try std.testing.expect(!std.mem.eql(u8, v.dir, again.dir));
        try std.testing.expectError(error.FileNotFound, cwd.access(io, try std.fmt.allocPrint(arena, "{s}/f", .{v.dir}), .{}));
        v.share();
    }
    // A name is a directory of its own, whatever Docker lets it hold, and never a cache's.
    const odd = try namedKey(arena, "o/r", "repo", "x.lock");
    try std.testing.expectEqualStrings(named_part, odd[3]);
    var v = try openNamed(arena, io, store, odd, null);
    defer v.release(io);
    try std.testing.expect(std.mem.endsWith(u8, v.dir, "/named/x.lock~"));
    v.share();
    try std.testing.expectError(error.NoRepository, namedKey(arena, "", "repo", "data"));
}

test "native named volumes: jobs use one at once, waiting only while a new one is filled" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const cwd = std.Io.Dir.cwd();
    const key = try namedKey(arena, "o/r", "repo", "data");
    const lock_path = try std.fmt.allocPrint(arena, "{s}/volumes/o/r/repo/named/data.lock", .{store});

    // New: held alone while the job fills it, so no other job sees it half filled.
    var seeding = try openNamed(arena, io, store, key, null);
    try std.testing.expect(seeding.new);
    const probe = try cwd.openFile(io, lock_path, .{});
    defer probe.close(io);
    try std.testing.expect(linux.errno(linux.flock(probe.handle, lock_sh | lock_nb)) != .SUCCESS);

    // A second job opening it meanwhile waits for the filling, then shares it.
    const Opener = struct {
        arena: Allocator,
        store: []const u8,
        key: []const []const u8,
        out: ?Volume = null,
        done: std.atomic.Value(bool) = .init(false),
        fn go(o: *@This()) void {
            o.out = openNamed(o.arena, std.testing.io, o.store, o.key, null) catch null;
            o.done.store(true, .release);
        }
    };
    var thread_arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer thread_arena.deinit();
    var opener: Opener = .{ .arena = thread_arena.allocator(), .store = store, .key = key };
    const t = try std.Thread.spawn(.{}, Opener.go, .{&opener});
    for (0..20) |_| {
        try std.testing.expect(!opener.done.load(.acquire));
        io.sleep(.fromMilliseconds(10), .awake) catch {};
    }
    try cwd.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/seeded", .{seeding.dir}), .data = "" });
    seeding.share();
    t.join();
    const second = opener.out orelse return error.TestUnexpectedResult;
    defer second.release(io);
    try std.testing.expect(!second.new);
    try cwd.access(io, try std.fmt.allocPrint(arena, "{s}/seeded", .{second.dir}), .{});
    // Both hold it shared: a third opens it at once, and only an eviction is kept out.
    const third = try openNamed(arena, io, store, key, null);
    defer third.release(io);
    try std.testing.expect(!third.new);
    try std.testing.expect(linux.errno(linux.flock(probe.handle, lock_ex | lock_nb)) != .SUCCESS);
    seeding.release(io);

    // A new one whose filling failed is gone: the next job makes it again, and fills it.
    const fresh_key = try namedKey(arena, "o/r", "repo", "fresh");
    const failed = try openNamed(arena, io, store, fresh_key, null);
    try std.testing.expect(failed.new);
    failed.discard(io);
    var retry = try openNamed(arena, io, store, fresh_key, null);
    defer retry.release(io);
    try std.testing.expect(retry.new);
    retry.share();
}

test "native named volumes: an open waits for another job's filling only so long, and not past a cancel" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const key = try namedKey(arena, "o/r", "repo", "data");
    // A job filling it, that never ends (its image's `cp` hangs, its runner is stopped).
    var seeding = try openNamed(arena, io, store, key, null);
    try std.testing.expect(seeding.new);
    defer seeding.discard(io);
    const start = nowMs();
    try std.testing.expectError(error.VolumeBusy, openNamedWaiting(arena, io, store, key, null, .{ .ms = 300 }));
    const took = nowMs() - start;
    try std.testing.expect(took >= 300 and took < 5000);
    // Cancelled, the open gives up at once, however long it would wait.
    var cancelled: std.atomic.Value(bool) = .init(true);
    const before = nowMs();
    try std.testing.expectError(error.Canceled, openNamedWaiting(arena, io, store, key, null, .{ .ms = 60_000, .cancel = &cancelled }));
    try std.testing.expect(nowMs() - before < 5000);
}
