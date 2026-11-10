//! The native backend's layer store (docs/native-backend.md, P2): the layers steps left, kept
//! between jobs under the key of what made them, so a step whose inputs are unchanged since an
//! earlier job is replayed instead of run. It stands where BuildKit's cache stood for the Dagger
//! backend, and keeps the model's key (proofs/Runner/Model.lean, `keyOf`): a step's key is its
//! parent's key, its script and its stable environment, never the volatile variables or the
//! mounts' content.
//!
//! On disk, under the store's directory (`RUNNER_NATIVE_STORE`, mode 0700):
//!
//!     layers/<key>/fs       the layer's tree, an overlay upper become a lower
//!     layers/<key>/log      the step's output as it was printed, markers and all
//!     layers/<key>/fc       its combined file commands (`scripts.writeCombinedFileCommands`)
//!     layers/<key>/meta     its format, kind, bytes on disk and record's lengths and sha256s
//!     layers/<key>/lock     held shared by every job using the layer; its mtime is its last use
//!     layers/<key>/digest   its deterministic digest, once asked for (`layerDigest`)
//!     keys/<key>.lock       held while a step with that key runs (`lockKey`)
//!     jobs/<id>/            the jobs running now (`Backend`)
//!
//! A layer is built under `layers/.tmp-<key>-<n>` and published by one rename, so a reader finds
//! it whole or not at all. Only a step that exited 0, is not always-run (it uses no secret) and
//! whose parent is in the store is published (`Backend.execScript`), so a failure is never
//! replayed (#69) and no layer or log holds a step's secrets.

const Store = @This();

const std = @import("std");
const linux = std.os.linux;

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const dagger = @import("../dagger.zig");
const Eviction = @import("evict.zig");
const phases = @import("phases.zig");
const key_diff = @import("key_diff.zig");

/// The store's directory.
root: []const u8,
/// Past this many bytes of layers, the least recently used go (`collect`).
max_bytes: u64 = default_max_bytes,
/// What `collect` keeps the rest of the store to (`evict.zig`).
limits: Eviction.Limits = .{},
/// A descriptor on the store's filesystem, opened when the job began (`syncCursor`): `syncfs` on
/// it reports a write error since then even if another job's `syncfs` was told first, which one
/// opened at the publish would miss. Null: the publish's own.
sync_fd: ?linux.fd_t = null,

pub const default_max_bytes: u64 = 10 * 1024 * 1024 * 1024;

pub const Key = [Sha256.digest_length]u8;

pub fn hex(k: Key) [2 * Sha256.digest_length]u8 {
    return std.fmt.bytesToHex(k, .lower);
}

/// The store's format: what a layer and its record mean (the sandbox that made the tree, the
/// record's files and how they replay, the key's extras). Part of every base's parent
/// (`Backend.below`), so every key: bump it with any change to those, and a runner upgraded
/// finds none of the layers an older one left (`collect` removes them, as not whole).
pub const store_format = "zig-runner native store 5";

/// What a key is of (P8's tag, proofs/Runner/Native.lean): a job's base, a step's container (a
/// `run:` step's exec, or a checkout's fetch), or one keyed on what a step produced.
pub const Tag = enum(u64) { base = 0, step = 1, output_keyed = 2 };

/// A key, from its preimage as P8 fixes it (proofs/Runner/Native.lean, `stepPreimage`; test
/// vectors in P8's `native/testdata/step_keys.tsv`): the tag as a u64, then the parent's key, the
/// script's text, the count of stable bindings and each name and value (`core`), every field
/// prefixed with its length as a u64, little-endian, so two different lists of fields never hash
/// alike. What the runner adds to P8's model (who runs it, where, the files kept) follows the
/// core (`Backend.keyFor`).
pub const KeyHasher = struct {
    h: Sha256,
    /// Tests: the preimage's bytes too.
    bytes: ?*std.Io.Writer = null,

    pub fn init(tag: Tag) KeyHasher {
        var k: KeyHasher = .{ .h = .init(.{}) };
        k.int(@backingInt(tag));
        return k;
    }

    /// A digest that is no key (a tree's, what lies below a base): no tag.
    pub fn plain(what: []const u8) KeyHasher {
        var k: KeyHasher = .{ .h = .init(.{}) };
        k.field(what);
        return k;
    }

    /// P8's core after the tag: the parent's key, the script, and the stable env in the
    /// container's order (`stableEnv`), counted first.
    pub fn core(k: *KeyHasher, parent: Key, script: []const u8, env: anytype) void {
        k.field(&parent);
        k.field(script);
        var stable: u64 = 0;
        for (env) |e| stable += @intFromBool(stableEnv(e.name));
        k.int(stable);
        for (env) |e| if (stableEnv(e.name)) {
            k.field(e.name);
            k.field(e.value);
        };
    }

    pub fn field(k: *KeyHasher, b: []const u8) void {
        k.int(b.len);
        k.update(b);
    }

    pub fn int(k: *KeyHasher, v: u64) void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        k.update(&b);
    }

    fn update(k: *KeyHasher, b: []const u8) void {
        k.h.update(b);
        if (k.bytes) |out| out.writeAll(b) catch {};
    }

    pub fn final(k: *KeyHasher) Key {
        return k.h.finalResult();
    }
};

/// Whether a container variable is part of a key. Not the run-specific ones
/// (`dagger.volatile_env`), which steps are given withheld (`dagger.volatile_sentinel`) unless
/// they always run, nor the runner's own per-job values, volatile under Dagger too (the event, the
/// ran marker, the markers' secret), nor the secret aliases.
pub fn stableEnv(name: []const u8) bool {
    if (dagger.isVolatile(name)) return false;
    for ([_][]const u8{ dagger.event_env, dagger.ran_env, dagger.mark_env }) |n|
        if (std.mem.eql(u8, name, n)) return false;
    return !std.mem.startsWith(u8, name, "ZIG_SECRET_");
}

/// How `prepare` checks the store's place.
pub const Prepare = struct {
    /// Whether every directory above the store must be safe from other users (`unsafeParents`).
    /// Off only in tests, whose stores are under a checkout a non-root user owns.
    check_parents: bool = true,
};

/// The store's directories, made if missing, and the store made the runner's alone: owned by the
/// runner's user (root on a root runner, set through a descriptor opened through no symlink) and
/// mode 0700, with no directory above it another user can write (`unsafeParents`). On a root
/// runner its layers hold files with the canonical ids, so a job's set-uid-root file or file
/// capability is the host's root's on disk: whoever could reach the store, or replace a directory
/// on the way to it, would have the host's root. An error when the store is not so, after
/// logging why (`secure` returns the reason, for the probe to give it).
pub fn prepare(arena: Allocator, io: std.Io, root: []const u8, how: Prepare) !void {
    if (try secure(arena, io, root, how)) |why| {
        std.log.err("native: {s}", .{why});
        return error.StoreUnsafe;
    }
}

/// `prepare`'s work: null when the store is the runner's alone, else why it is not.
pub fn secure(arena: Allocator, io: std.Io, root: []const u8, how: Prepare) !?[]const u8 {
    const cwd = std.Io.Dir.cwd();
    if (!std.fs.path.isAbsolute(root))
        return try std.fmt.allocPrint(arena, "the native store {s} is not an absolute path", .{root});
    for ([_][]const u8{ "layers", "keys", "jobs", "steps" }) |d|
        try cwd.createDirPath(io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, d }));
    const owner = linux.geteuid();
    if (how.check_parents) if (try unsafeParents(arena, io, root, owner)) |why| return why;
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true };
    const rc = linux.open(try arena.dupeSentinel(u8, root, 0), flags, 0);
    if (linux.errno(rc) != .SUCCESS) return try std.fmt.allocPrint(arena, "the native store {s} " ++
        "cannot be opened as a directory through no symlink", .{root});
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    if (owner == 0) _ = linux.fchown(fd, 0, 0);
    _ = linux.fchmod(fd, 0o700);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .UID = true, .MODE = true }, &st)) != .SUCCESS)
        return error.Stat;
    if (st.uid != owner or st.mode & 0o7777 != 0o700) return try std.fmt.allocPrint(
        arena,
        "the native store {s} is owned by uid {d} with mode {o}, not the runner's (uid {d}) " ++
            "with mode 700, and could not be made so",
        .{ root, st.uid, st.mode & 0o7777, owner },
    );
    return null;
}

/// Why a directory above `root` would let another user than `owner` (and root) replace the
/// store, or a directory on the way to it: one owned by another user, or writable by others (or by
/// its group, but for group root) without the sticky bit (which `/tmp` has: there only an entry's owner may rename
/// it). Checked along the path as given and along the path it resolves to, so a symlink on the
/// way is safe only where it cannot be changed and points somewhere that cannot either. Null
/// when none.
pub fn unsafeParents(arena: Allocator, io: std.Io, root: []const u8, owner: u32) !?[]const u8 {
    const real = try std.Io.Dir.cwd().realPathFileAlloc(io, root, arena);
    for ([_][]const u8{ root, real }) |path| {
        var dir: []const u8 = path;
        while (std.fs.path.dirname(dir)) |up| : (dir = up) {
            const z = try arena.dupeSentinel(u8, up, 0);
            var st: linux.Statx = undefined;
            if (linux.errno(linux.statx(linux.AT.FDCWD, z, 0, .{ .UID = true, .GID = true, .MODE = true }, &st)) != .SUCCESS)
                return try std.fmt.allocPrint(arena, "{s}, above the native store, cannot be read", .{up});
            if (st.uid != 0 and st.uid != owner) return try std.fmt.allocPrint(
                arena,
                "{s}, above the native store {s}, is owned by uid {d}, who could replace the " ++
                    "store; its directories must be root's (or the rootless runner's own)",
                .{ up, root, st.uid },
            );
            // Group root's write is root's (a umask of 002 gives it to what root makes).
            const writable: u32 = if (st.gid == 0) 0o002 else 0o022;
            if (st.mode & writable != 0 and st.mode & linux.S.ISVTX == 0) return try std.fmt.allocPrint(
                arena,
                "{s}, above the native store {s}, is writable by its group or others (mode {o}) " ++
                    "without the sticky bit, so another user could replace the store",
                .{ up, root, st.mode & 0o7777 },
            );
        }
    }
    return null;
}

fn layerDir(s: Store, arena: Allocator, key: Key) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/layers/{s}", .{ s.root, &hex(key) });
}

const lock_sh: i32 = 1;
const lock_ex: i32 = 2;
const lock_nb: i32 = 4;

fn flock(f: std.Io.File, how: i32) bool {
    return linux.errno(linux.flock(f.handle, how)) == .SUCCESS;
}

/// Held while a step with this key runs, so two jobs sharing the store (a pool's runners, or two
/// jobs of one) never run one key at once: the second waits, then finds the first's layer.
/// Polled, so `stop` (a cancel or a timeout while it waits) ends the wait with `error.Stopped`;
/// the waiting task's own cancel ends it with `error.Canceled`.
/// A lock file `collect` removed while it was being taken is not trusted: the lock is taken only
/// on the file the path names.
pub fn lockKey(
    s: Store,
    arena: Allocator,
    io: std.Io,
    key: Key,
    stop: *const std.atomic.Value(bool),
) !std.Io.File {
    const path = try std.fmt.allocPrint(arena, "{s}/keys/{s}.lock", .{ s.root, &hex(key) });
    while (true) {
        const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false });
        if (flock(f, lock_ex | lock_nb)) {
            if (sameFile(arena, f, path)) return f;
            f.close(io);
            continue;
        }
        f.close(io);
        if (stop.load(.acquire)) return error.Stopped;
        try io.sleep(.fromMilliseconds(50), .awake);
    }
}

/// Whether some process holds the key's lock (`lockKey`): this one's own holder too, as a lock
/// taken through another open of the file conflicts with it.
fn keyLocked(s: Store, arena: Allocator, io: std.Io, key: Key) bool {
    const path = std.fmt.allocPrint(arena, "{s}/keys/{s}.lock", .{ s.root, &hex(key) }) catch
        return false;
    const f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    defer f.close(io);
    return !flock(f, lock_ex | lock_nb);
}

/// A layer a job uses, held shared until the job ends: eviction takes the lock exclusively, so
/// it never removes a layer under a running job.
pub const Layer = struct {
    /// The layer's tree, an overlay lower.
    fs: []const u8,
    lock: std.Io.File,
};

/// What made a layer, which says what its record must hold: a step's file commands end with its
/// ran marker; a base's and a checkout's fetch's are empty.
pub const Kind = enum { base, step, fetch };

/// A stored layer found: held, with its record.
pub const Hit = struct { layer: Layer, rec: Record };

/// The layer stored under `key`, held (`Layer`), checked whole (`readEntry`) and its last use now;
/// null when there is none. An entry that cannot be replayed (a part missing or cut short, a disk
/// that filled, a hand that changed it) is evicted, and then is a miss too; `error.Invalid` when
/// another job holds it, so it can be neither replayed nor replaced now.
pub fn open(s: Store, arena: Allocator, io: std.Io, key: Key) !?Hit {
    const dir = try s.layerDir(arena, key);
    const lock_path = try join(arena, dir, "lock");
    const f = std.Io.Dir.cwd().openFile(io, lock_path, .{}) catch return null;
    // Waits out an eviction under way, which then leaves the path naming nothing.
    if (!flock(f, lock_sh) or !sameFile(arena, f, lock_path)) {
        f.close(io);
        return null;
    }
    const rec = readEntry(arena, io, dir) catch {
        f.close(io);
        if (s.evict(arena, io, &hex(key))) return null;
        return error.Invalid;
    };
    // Only a whole entry counts as used, so a broken one ages out.
    _ = linux.utimensat(f.handle, null, null, 0);
    return .{ .layer = .{ .fs = try join(arena, dir, "fs"), .lock = f }, .rec = rec };
}

/// Marks a job's chain of stored layers (`locks`, oldest first, each held) as used, the base last
/// and newest, so `collect`'s least-recently-used order evicts a child before its parent.
///
/// A step's layer is a diff over its parents' (an overlay lower each), and a job reaches a layer
/// only through every ancestor's `open` or `publish`, each earlier than its child's: left alone,
/// the ancestors are always the older and go first. A child kept without its parent still
/// replays (the parent's key is hashed into its own), but only after the parent has run again, so
/// the job saves one step and pays for the rest. Each ancestor a nanosecond newer keeps the order
/// exact where the clock is coarse. Nothing here stops an eviction: only the order changes, so the
/// cap and the disk's floor free the same bytes.
pub fn touchChain(io: std.Io, locks: []const std.Io.File) void {
    const now_ns = std.Io.Clock.real.now(io).toNanoseconds();
    for (locks, 0..) |l, i| {
        const ns = now_ns + @as(i128, locks.len - 1 - i);
        const t: linux.timespec = .{
            .sec = std.math.cast(@FieldType(linux.timespec, "sec"), @divFloor(ns, std.time.ns_per_s)) orelse return,
            .nsec = std.math.cast(@FieldType(linux.timespec, "nsec"), @mod(ns, std.time.ns_per_s)) orelse return,
        };
        _ = linux.utimensat(l.handle, null, &[2]linux.timespec{ t, t }, 0);
    }
}

/// What replaying a stored step needs: its output as printed, and its file commands.
pub const Record = struct {
    log: []const u8,
    fc: []const u8,
    /// The key's components (`key_diff.zig`), written beside the record for `key-diff`. Advisory:
    /// not in `meta`, never read to replay, so an entry without them is whole.
    components: []const u8 = "",
};

/// A step that printed more than this is not published: its replay would hold it all in memory.
/// Dagger's limit on a recorded output (`dagger.max_recorded_bytes`).
pub const max_record_bytes = dagger.max_recorded_bytes;

const combinedPart = @import("../dagger/scripts.zig").combinedPart;

/// Why a record cannot be stored or replayed as a `kind`'s, or null when it can.
fn recordFault(kind: Kind, rec: Record) ?anyerror {
    if (rec.log.len > max_record_bytes or rec.fc.len > max_record_bytes)
        return error.RecordTooLarge;
    return switch (kind) {
        // Its file commands are whole, every part its length and the ran marker last
        // (`scripts.combinedPart`): otherwise they were cut short.
        .step => if (combinedPart(rec.fc, "ran") == null) error.ShortRecord else null,
        .base, .fetch => if (rec.fc.len > 0) error.ShortRecord else null,
    };
}

/// An entry's `meta`: the store's format, what made it, its bytes on disk, and its record's
/// files' lengths and sha256s, so a part cut short or changed is told from a whole one.
const Meta = struct {
    kind: Kind,
    bytes: u64,
    log_len: u64,
    fc_len: u64,
    log_sha: Key,
    fc_sha: Key,

    fn write(m: Meta, arena: Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "format {s}\nkind {t}\nbytes {d}\nlog {d} {s}\n" ++
            "fc {d} {s}\n", .{
            store_format, m.kind,         m.bytes, m.log_len, &hex(m.log_sha),
            m.fc_len,     &hex(m.fc_sha),
        });
    }

    fn parse(text: []const u8) !Meta {
        var m: Meta = undefined;
        var lines = std.mem.splitScalar(u8, text, '\n');
        const want = [_][]const u8{ "format", "kind", "bytes", "log", "fc" };
        for (want) |name| {
            const line = lines.next() orelse return error.BadMeta;
            var f = std.mem.splitScalar(u8, line, ' ');
            if (!std.mem.eql(u8, f.next() orelse "", name)) return error.BadMeta;
            const v = f.rest();
            switch (name[0]) {
                'f' => if (name.len == 2) {
                    try parseFile(v, &m.fc_len, &m.fc_sha);
                } else if (!std.mem.eql(u8, v, store_format)) return error.BadMeta,
                'k' => m.kind = std.meta.stringToEnum(Kind, v) orelse return error.BadMeta,
                'b' => m.bytes = try std.fmt.parseInt(u64, v, 10),
                'l' => try parseFile(v, &m.log_len, &m.log_sha),
                else => unreachable,
            }
        }
        return m;
    }

    fn parseFile(v: []const u8, len: *u64, sha: *Key) !void {
        var f = std.mem.splitScalar(u8, v, ' ');
        len.* = try std.fmt.parseInt(u64, f.next() orelse return error.BadMeta, 10);
        _ = try std.fmt.hexToBytes(sha, f.next() orelse return error.BadMeta);
    }
};

/// The entry in `dir` read and checked whole: its tree there, its `meta` this format's, its
/// record's files of the lengths and sha256s it says, and the record one its kind may have.
fn readEntry(arena: Allocator, io: std.Io, dir: []const u8) !Record {
    const m = try metaOf(arena, io, dir);
    if (!isDir(arena, try join(arena, dir, "fs"))) return error.NoTree;
    const cwd = std.Io.Dir.cwd();
    const limit: std.Io.Limit = .limited(max_record_bytes + 1);
    const rec: Record = .{
        .log = try cwd.readFileAlloc(io, try join(arena, dir, "log"), arena, limit),
        .fc = try cwd.readFileAlloc(io, try join(arena, dir, "fc"), arena, limit),
    };
    if (rec.log.len != m.log_len or rec.fc.len != m.fc_len) return error.ShortRecord;
    var sha: Key = undefined;
    Sha256.hash(rec.log, &sha, .{});
    if (!std.mem.eql(u8, &sha, &m.log_sha)) return error.ChangedRecord;
    Sha256.hash(rec.fc, &sha, .{});
    if (!std.mem.eql(u8, &sha, &m.fc_sha)) return error.ChangedRecord;
    if (recordFault(m.kind, rec)) |e| return e;
    return rec;
}

/// The published entry `name` (under `layers/`) checked as a replay checks it (`readEntry`),
/// held shared meanwhile as `open` holds it, and its tree the bytes its meta counted: its bytes,
/// or null when it was evicted before it could be held. An error says what is wrong with it. For
/// the stress test (`store_stress.zig`), which checks every entry while jobs publish, replay and
/// evict around it.
pub fn checkEntry(s: Store, arena: Allocator, io: std.Io, name: []const u8) !?u64 {
    const dir = try std.fmt.allocPrint(arena, "{s}/layers/{s}", .{ s.root, name });
    const lock_path = try join(arena, dir, "lock");
    const f = std.Io.Dir.cwd().openFile(io, lock_path, .{}) catch |e| {
        // Published whole, so with its lock: gone since the listing, or broken.
        if (e == error.FileNotFound and !isDir(arena, dir)) return null;
        return e;
    };
    defer f.close(io);
    if (!flock(f, lock_sh) or !sameFile(arena, f, lock_path)) return null;
    _ = try readEntry(arena, io, dir);
    const m = try metaOf(arena, io, dir);
    const bytes = try treeBytes(arena, io, try join(arena, dir, "fs"));
    if (bytes != m.bytes) {
        std.debug.print("native store: {s}'s tree takes {d} bytes, its meta says {d}\n", .{ name, bytes, m.bytes });
        return error.TreeBytes;
    }
    return m.bytes;
}

/// The first job after a boot checks every layer's tree against the bytes its meta counted, and
/// evicts one that differs: nothing else compares a tree (`open` reads only its record, and
/// walking the tree there would cost every replay), and a crash, the one thing that could leave
/// a whole-looking entry with files short or empty, only shows across a boot. Later jobs read
/// the boot's id and stop. A job waits for the check, so no job holds a layer it could evict, and
/// a false difference is only a miss.
pub fn checkOncePerBoot(s: Store, arena: Allocator, io: std.Io) void {
    const cwd = std.Io.Dir.cwd();
    const mark = join(arena, s.root, "boot") catch return;
    // `readFile`, which reads to the end, and not `readFileAlloc`: a /proc file's size is 0, so
    // that read nothing, every boot matched the empty mark, and no boot after the first was ever
    // checked.
    var boot_buf: [64]u8 = undefined;
    const boot = cwd.readFile(io, "/proc/sys/kernel/random/boot_id", &boot_buf) catch return;
    if (boot.len == 0) return;
    if (checkedIn(arena, io, mark, boot)) return;
    const gc = cwd.createFile(io, join(arena, s.root, "gc.lock") catch return, .{
        .truncate = false,
    }) catch return;
    defer gc.close(io);
    if (!flock(gc, lock_ex)) return;
    if (checkedIn(arena, io, mark, boot)) return;

    const layers = join(arena, s.root, "layers") catch return;
    var dir = cwd.openDir(io, layers, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        if (e.name[0] == '.') continue;
        var pass: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer pass.deinit();
        const a = pass.allocator();
        const full = join(a, layers, e.name) catch return;
        if (treeAsCounted(a, io, full)) continue;
        std.log.warn("native: layer {s}'s tree is not what was published; evicted", .{e.name});
        _ = s.evict(a, io, e.name);
    }

    const tmp = std.fmt.allocPrint(arena, "{s}.tmp", .{mark}) catch return;
    const f = cwd.createFile(io, tmp, .{}) catch return;
    defer f.close(io);
    f.writeStreamingAll(io, boot) catch return;
    if (linux.errno(linux.fsync(f.handle)) != .SUCCESS) return;
    cwd.rename(tmp, cwd, mark, io) catch |e|
        std.log.warn("native: cannot mark {s}, so the next job checks it again: {s}", .{ mark, @errorName(e) });
}

fn checkedIn(arena: Allocator, io: std.Io, mark: []const u8, boot: []const u8) bool {
    const text = std.Io.Dir.cwd().readFileAlloc(io, mark, arena, .limited(64)) catch return false;
    return std.mem.eql(u8, text, boot);
}

fn treeAsCounted(arena: Allocator, io: std.Io, dir: []const u8) bool {
    const m = metaOf(arena, io, dir) catch return false;
    const fs = join(arena, dir, "fs") catch return false;
    return m.bytes == (treeBytes(arena, io, fs) catch return false);
}

fn metaOf(arena: Allocator, io: std.Io, dir: []const u8) !Meta {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, try join(arena, dir, "meta"), arena, .limited(1024));
    return Meta.parse(text);
}

/// The cheap half of `readEntry`, for `collect`, which looks at every entry after every job: the
/// meta, the tree, and the record's files' lengths, without reading them.
fn entryLooksWhole(arena: Allocator, io: std.Io, dir: []const u8) ?Meta {
    const m = metaOf(arena, io, dir) catch return null;
    if (!isDir(arena, join(arena, dir, "fs") catch return null)) return null;
    for ([_]struct { []const u8, u64 }{ .{ "log", m.log_len }, .{ "fc", m.fc_len } }) |part| {
        const p = std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ dir, part[0] }, 0) catch
            return null;
        var st: linux.Statx = undefined;
        const mask: linux.STATX = .{ .TYPE = true, .SIZE = true };
        if (linux.errno(linux.statx(linux.AT.FDCWD, p, linux.AT.SYMLINK_NOFOLLOW, mask, &st)) !=
            .SUCCESS) return null;
        if (st.mode & linux.S.IFMT != linux.S.IFREG or st.size != part[1]) return null;
    }
    if (m.log_len > max_record_bytes or m.fc_len > max_record_bytes) return null;
    if (m.kind == .step and m.fc_len == 0) return null;
    return m;
}

fn isDir(arena: Allocator, p: []const u8) bool {
    const z = arena.dupeSentinel(u8, p, 0) catch return false;
    var st: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st);
    return linux.errno(rc) == .SUCCESS and st.mode & linux.S.IFMT == linux.S.IFDIR;
}

/// Moves a finished upper (`upper`, in the job's directory) into the store under `key`, with its
/// record (`Record`, which must be one its `kind` may have and within `max_record_bytes`), and
/// holds it for the job. Built under a temporary name, written to disk (`writeBack`,
/// `syncEntries`) before it is visible, held before it is visible (so an eviction cannot take it at once), and published by
/// one rename that never replaces. On failure the upper is back where it was, or, if it cannot be
/// put back, left in the temporary entry and logged, never deleted.
///
/// The caller holds the key's lock (`lockKey`) until this returns: `collect` takes a temporary
/// entry whose key's lock is free for one a dead runner left, and removes it
/// (proofs/tla/StoreLocking.tla). Refused (`error.KeyNotLocked`) when no one holds it, before
/// anything moves.
pub fn publish(
    s: Store,
    arena: Allocator,
    io: std.Io,
    key: Key,
    kind: Kind,
    upper: []const u8,
    rec: Record,
) !Layer {
    return s.publishTimed(arena, io, key, kind, upper, rec, null);
}

/// `publish`, its phases (the upper's size, its record written, the sync, the rename) sampled
/// into `ph` when given (`phases.zig`). The sync is one sample for the whole and one for each
/// part: the write-back wait, the entries' fsyncs, the meta, and the filesystem's `syncfs` when
/// the entry was past `sync_tree_max` or had a file that could not be opened.
pub fn publishTimed(
    s: Store,
    arena: Allocator,
    io: std.Io,
    key: Key,
    kind: Kind,
    upper: []const u8,
    rec: Record,
    ph: ?*phases.Phases,
) !Layer {
    if (recordFault(kind, rec)) |e| return e;
    if (!s.keyLocked(arena, io, key)) return error.KeyNotLocked;
    var t = phases.now();
    const cwd = std.Io.Dir.cwd();
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const tmp = try std.fmt.allocPrint(arena, "{s}/layers/.tmp-{s}-{s}", .{
        s.root,
        &hex(key),
        &std.fmt.bytesToHex(raw, .lower),
    });
    const fs_tmp = try join(arena, tmp, "fs");
    var moved = false;
    var lock: ?std.Io.File = null;
    try cwd.createDirPath(io, tmp);
    errdefer {
        if (lock) |l| l.close(io);
        const back = !moved or if (cwd.rename(fs_tmp, cwd, upper, io)) true else |e| no: {
            std.log.warn("native: cannot put {s} back from {s}: {s}", .{ upper, fs_tmp, @errorName(e) });
            break :no false;
        };
        if (back) removeTree(arena, io, tmp);
    }
    var m: Meta = .{
        .kind = kind,
        .bytes = undefined,
        .log_len = rec.log.len,
        .fc_len = rec.fc.len,
        .log_sha = undefined,
        .fc_sha = undefined,
    };
    Sha256.hash(rec.log, &m.log_sha, .{});
    Sha256.hash(rec.fc, &m.fc_sha, .{});
    try cwd.writeFile(io, .{ .sub_path = try join(arena, tmp, "log"), .data = rec.log });
    try cwd.writeFile(io, .{ .sub_path = try join(arena, tmp, "fc"), .data = rec.fc });
    if (rec.components.len > 0) cwd.writeFile(io, .{
        .sub_path = try join(arena, tmp, "components"),
        .data = rec.components,
    }) catch |e| std.log.warn("native: a layer's key components cannot be written: {s}", .{@errorName(e)});
    lock = try cwd.createFile(io, try join(arena, tmp, "lock"), .{});
    if (!flock(lock.?, lock_sh)) return error.Locked;
    try cwd.rename(upper, cwd, fs_tmp, io);
    moved = true;
    if (ph) |p| t = p.since(arena, .record, t);
    // On disk before it is visible: a crash after the rename must not leave a whole-looking
    // entry whose files are empty or short. A small entry's own files and directories
    // (`writeBack`, `syncEntries`), so it never waits for the rest of the disk's writes; a large
    // one's whole filesystem, as each file's `fsync` costs a flush of the disk's cache.
    //
    // The tree's data goes first and the fsyncs last, with the meta written between them, so
    // that one journal commit takes the entry whole: fsyncs before the meta would make one
    // commit, the meta's fsync a second, and each costs a flush.
    const entry = try openRoot(arena, tmp);
    defer _ = linux.close(entry);
    var whole_disk = false;
    var syncfs_ns: ?u64 = null;
    const todo = writeBack(arena, io, entry, sync_tree_max) catch |e| switch (e) {
        error.Unreadable, error.TooLarge => no: {
            whole_disk = true;
            break :no &.{};
        },
        else => return e,
    };
    const wb_ns = phases.now() -| t;
    t = phases.now();
    if (whole_disk) {
        try s.syncDisk(lock.?);
        syncfs_ns = phases.now() -| t;
    }
    t = phases.now();
    // Measured once written: a file the kernel is still writing back can show fewer blocks
    // than it takes (a block short, the stress test found, under other publishers' syncfs),
    // and the store would count less than it holds.
    m.bytes = try treeBytes(arena, io, fs_tmp);
    if (ph) |p| t = p.since(arena, .size, t);
    const meta = try cwd.createFile(io, try join(arena, tmp, "meta"), .{});
    defer meta.close(io);
    try meta.writeStreamingAll(io, try m.write(arena));
    // Its blocks allocated now, or its own fsync would need a commit of its own for them.
    _ = syncRange(meta.handle, sync_file_range_write);
    var meta_ns = phases.now() -| t;
    t = phases.now();
    var fsync_ns: u64 = 0;
    if (!whole_disk) {
        const unreadable = if (syncEntries(entry, todo)) |_| false else |e| switch (e) {
            error.Unreadable => true,
            else => return error.Sync,
        };
        fsync_ns = phases.now() -| t;
        if (unreadable) {
            t = phases.now();
            try s.syncDisk(lock.?);
            syncfs_ns = phases.now() -| t;
        }
    }
    t = phases.now();
    if (linux.errno(linux.fsync(meta.handle)) != .SUCCESS) return error.Sync;
    meta_ns += phases.now() -| t;
    if (ph) |p| {
        p.add(arena, .sync, wb_ns + meta_ns + fsync_ns + (syncfs_ns orelse 0));
        p.add(arena, .sync_wb, wb_ns);
        p.add(arena, .sync_fsync, fsync_ns);
        p.add(arena, .sync_meta, meta_ns);
        if (syncfs_ns) |ns| p.add(arena, .syncfs, ns);
        t = phases.now();
    }
    const dir = try s.layerDir(arena, key);
    // One rename that never replaces: a layer published meanwhile stays, and this one is not.
    const rc = linux.renameat2(
        linux.AT.FDCWD,
        try arena.dupeSentinel(u8, tmp, 0),
        linux.AT.FDCWD,
        try arena.dupeSentinel(u8, dir, 0),
        .{ .NOREPLACE = true },
    );
    if (linux.errno(rc) != .SUCCESS) return error.Publish;
    // The rename is not synced here: an entry whose rename a crash lost is only a miss, made
    // again. The job syncs the layers' directory once, at its end (`syncLayers`).
    if (ph) |p| _ = p.since(arena, .rename, t);
    return .{ .fs = try join(arena, dir, "fs"), .lock = lock.? };
}

/// The filesystem's writes on disk, for an entry too large for its own fsyncs: through the
/// descriptor the job opened at its start (`sync_fd`), or `lock`, a descriptor on the same disk.
fn syncDisk(s: Store, lock: std.Io.File) !void {
    if (linux.errno(linux.syncfs(s.sync_fd orelse lock.handle)) != .SUCCESS) return error.Sync;
}

/// The data of the tree `root` written to disk and waited for, and nothing else of its
/// filesystem: what a publish needs without waiting for every other write to the same disk
/// (another job's tool cache volume being filled, its workspace), which `syncfs` waited for.
/// Returns what `syncEntries` must then fsync: every file and directory. Only regular files and
/// directories hold anything to write: a symlink's, a device node's or a fifo's inode is
/// metadata, committed with its directory.
///
/// Writing the data back makes no journal commit, and allocates every block in one transaction,
/// so the fsyncs that follow have only that transaction to commit. It stops being cheap only
/// with the entries' own count: `error.TooLarge` past `max`, as soon as the walk sees it.
/// `error.Unreadable` when a file cannot be opened (a step's `chmod 000` on a rootless runner,
/// whose user is no one's superuser). The caller syncs the whole filesystem instead of either.
fn writeBack(arena: Allocator, io: std.Io, root: linux.fd_t, max: u64) ![]const Synced {
    var todo: std.ArrayList(Synced) = .empty;
    try todo.append(arena, .{ .dir = "", .name = "" });
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(arena, "");
    var started: [write_back_batch]linux.fd_t = undefined;
    var n_started: usize = 0;
    // On an early return: their writeback goes on, and nothing waits for it.
    defer for (started[0..n_started]) |f| {
        _ = linux.close(f);
    };
    var entries: u64 = 0;
    while (stack.pop()) |rel| {
        const fd = if (rel.len == 0) root else try openRel(arena, root, rel);
        defer if (fd != root) {
            _ = linux.close(fd);
        };
        for (try listDir(arena, io, fd)) |n| {
            entries += 1;
            if (entries > max) return error.TooLarge;
            switch (n.kind()) {
                linux.S.IFREG => {
                    try todo.append(arena, .{ .dir = rel, .name = n.name });
                    if (n.st.size == 0) continue;
                    if (n_started == started.len) {
                        const batch = started[0..n_started];
                        n_started = 0;
                        try waitWritten(batch);
                    }
                    const f = try openFileAt(fd, n.name);
                    _ = syncRange(f, sync_file_range_write);
                    started[n_started] = f;
                    n_started += 1;
                },
                linux.S.IFDIR => {
                    const sub = if (rel.len == 0)
                        try arena.dupe(u8, n.name)
                    else
                        try std.fmt.allocPrint(arena, "{s}/{s}", .{ rel, n.name });
                    try stack.append(arena, sub);
                    try todo.append(arena, .{ .dir = sub, .name = "" });
                },
                else => {},
            }
        }
    }
    const batch = started[0..n_started];
    n_started = 0;
    try waitWritten(batch);
    return todo.items;
}

/// Each descriptor's writeback finished, then closed. The wait's error must be taken here: it
/// is reported once for the file, so an `fsync` through a descriptor opened after it would not
/// see it. A kernel or filesystem without the call leaves it to the fsyncs.
fn waitWritten(fds: []const linux.fd_t) !void {
    var failed = false;
    for (fds) |f| {
        switch (linux.errno(syncRange(f, sync_file_range_wait))) {
            .SUCCESS, .NOSYS, .INVAL, .OPNOTSUPP => {},
            else => failed = true,
        }
        _ = linux.close(f);
    }
    if (failed) return error.Sync;
}

fn syncRange(f: linux.fd_t, how: u32) usize {
    return linux.syscall4(.sync_file_range, @abs(f), 0, 0, how);
}

/// `SYNC_FILE_RANGE_WRITE`: writeback started, not waited for.
const sync_file_range_write = 2;
/// `SYNC_FILE_RANGE_WAIT_BEFORE | WRITE | WAIT_AFTER`: all of it written, and waited for.
const sync_file_range_wait = 7;

/// How many files `writeBack` has writing at once, each with a descriptor open until it is done.
const write_back_batch = 256;

/// Every file and directory of `todo` (`writeBack`) fsynced, from `sync_threads` threads at once:
/// one at a time, each `fsync` could be a journal commit and a flush of the disk's cache of its
/// own (a small layer's 15 took 86 ms on a laptop's NVMe, where `syncfs` took 15 ms), while fsyncs
/// that wait together share commits. Every one is still made, each promising its own file
/// whatever the filesystem; on ext4 the first commits the transaction and the rest find nothing
/// to do. `error.Unreadable` as for `writeBack`.
fn syncEntries(root: linux.fd_t, todo: []const Synced) !void {
    var work: SyncWork = .{ .root = root, .todo = todo };
    var threads: [sync_threads]?std.Thread = @splat(null);
    for (threads[0..@min(sync_threads, todo.len)]) |*t|
        t.* = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, SyncWork.run, .{&work}) catch null;
    // This thread too, so the work is done when no thread could be started.
    work.run();
    for (threads) |t| if (t) |th| th.join();
    return work.result();
}

/// How many threads `syncEntries` fsyncs from.
const sync_threads = 16;

/// What `syncEntries` fsyncs: the directory `dir` under its root when `name` is empty, else the file
/// `name` in it.
const Synced = struct { dir: []const u8, name: [:0]const u8 };

/// `syncEntries`' fsyncs, taken in turn by its threads.
const SyncWork = struct {
    root: linux.fd_t,
    todo: []const Synced,
    next: std.atomic.Value(usize) = .init(0),
    unreadable: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),

    /// A failed `fsync` first: `error.Unreadable` sends the caller to `syncfs`, which may not
    /// report a write error an `fsync` has already taken, and the layer would be published.
    fn result(w: *const SyncWork) !void {
        if (w.failed.load(.acquire)) return error.Sync;
        if (w.unreadable.load(.acquire)) return error.Unreadable;
    }

    fn run(w: *SyncWork) void {
        var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena_state.deinit();
        while (true) {
            const i = w.next.fetchAdd(1, .monotonic);
            if (i >= w.todo.len) return;
            _ = arena_state.reset(.retain_capacity);
            w.one(arena_state.allocator(), w.todo[i]) catch |e| switch (e) {
                error.Unreadable => w.unreadable.store(true, .release),
                else => w.failed.store(true, .release),
            };
        }
    }

    fn one(w: *SyncWork, arena: Allocator, s: Synced) !void {
        const dir = if (s.dir.len == 0) w.root else openRel(arena, w.root, s.dir) catch
            return error.Unreadable;
        defer if (dir != w.root) {
            _ = linux.close(dir);
        };
        if (s.name.len == 0) {
            if (linux.errno(linux.fsync(dir)) != .SUCCESS) return error.Sync;
            return;
        }
        const f = try openFileAt(dir, s.name);
        defer _ = linux.close(f);
        if (linux.errno(linux.fsync(f)) != .SUCCESS) return error.Sync;
    }
};

/// The regular file `name` in `dir`, read-only, never through a symlink.
fn openFileAt(dir: linux.fd_t, name: [*:0]const u8) !linux.fd_t {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true };
    const rc = linux.openat(dir, name, flags, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Unreadable;
    return std.math.cast(linux.fd_t, rc) orelse error.Unreadable;
}

/// The most entries (files, directories, anything) of an upper whose own files a publish syncs
/// (`writeBack`, `syncEntries`); past it, it syncs the filesystem (`syncfs`), as fsyncs that share commits still
/// cost the disk's cache a flush each now and then.
///
/// A checkout of this repository is about 370 entries, and took `syncfs`, so it waited for
/// whatever else the disk was writing: twice as long beside a writer, on a laptop's NVMe. Around
/// 800 `syncfs` is twice as fast on a tree already written, and slower only on one just written
/// beside a writer.
pub const sync_tree_max = 512;

/// The layers' directory synced, so the renames that published this job's layers outlive a
/// crash: once a job, at its end, rather than once a publish. A failure is logged: it loses only
/// entries, which are then misses.
/// `sync_fd` for a job beginning now; null when the store cannot be opened.
pub fn syncCursor(arena: Allocator, root: []const u8) ?linux.fd_t {
    return openRoot(arena, root) catch null;
}

pub fn syncLayers(s: Store, arena: Allocator) void {
    const p = join(arena, s.root, "layers") catch return;
    const fd = openRoot(arena, p) catch return;
    defer _ = linux.close(fd);
    if (linux.errno(linux.fsync(fd)) != .SUCCESS)
        std.log.warn("native: cannot sync {s}; a crash now may lose the layers just published", .{p});
}

fn join(arena: Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
}

/// Keeps the store under `max_bytes`: the layers no job holds go, least recently used first.
/// Also removes what dead runners left (a layer half built, one half evicted) and the lock files
/// of keys no step is running, and keeps what is beside the layers within its own limits
/// (`evict.run`). One runner at a time collects; another finding it busy goes on.
pub fn collect(s: Store, arena: Allocator, io: std.Io) void {
    const cwd = std.Io.Dir.cwd();
    const gc = cwd.createFile(io, join(arena, s.root, "gc.lock") catch return, .{
        .truncate = false,
    }) catch return;
    defer gc.close(io);
    if (!flock(gc, lock_ex | lock_nb)) return;

    const layers = join(arena, s.root, "layers") catch return;
    var dir = cwd.openDir(io, layers, .{ .iterate = true }) catch return;
    defer dir.close(io);
    const Entry = struct { name: []const u8, bytes: u64, used_ns: i128 };
    var entries: std.ArrayList(Entry) = .empty;
    var total: u64 = 0;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        const full = join(arena, layers, e.name) catch return;
        if (std.mem.startsWith(u8, e.name, ".dead-")) {
            removeTree(arena, io, full);
            continue;
        }
        if (std.mem.startsWith(u8, e.name, ".tmp-")) {
            // Its publisher holds the key's lock while it builds; a free lock means it died.
            const key_hex = e.name[".tmp-".len..][0..@min(64, e.name.len - ".tmp-".len)];
            const lock_path = std.fmt.allocPrint(arena, "{s}/keys/{s}.lock", .{
                s.root,
                key_hex,
            }) catch return;
            const kl = cwd.createFile(io, lock_path, .{ .truncate = false }) catch continue;
            defer kl.close(io);
            if (flock(kl, lock_ex | lock_nb)) removeTree(arena, io, full);
            continue;
        }
        // An entry that cannot be replayed would only take room (`open` evicts it too).
        const meta = entryLooksWhole(arena, io, full) orelse {
            _ = s.evict(arena, io, e.name);
            continue;
        };
        const bytes = accounted(meta);
        var st: linux.Statx = undefined;
        const lock_z = arena.dupeSentinel(u8, join(arena, full, "lock") catch return, 0) catch
            return;
        const rc = linux.statx(linux.AT.FDCWD, lock_z, 0, .{ .MTIME = true }, &st);
        const used_ns: i128 = if (linux.errno(rc) == .SUCCESS)
            @as(i128, st.mtime.sec) * std.time.ns_per_s + st.mtime.nsec
        else
            0;
        total += bytes;
        entries.append(arena, .{
            .name = arena.dupe(u8, e.name) catch return,
            .bytes = bytes,
            .used_ns = used_ns,
        }) catch return;
    }
    // The disk's floor counts here first: a layer is the cheapest thing the store has to make
    // again. So under it a layer goes as the rest does (`evict.floor`), sparing recent use, and
    // only past the cap whatever its use.
    const keep = @min(s.max_bytes, total -| (Eviction.shortOf(arena, s) orelse 0));
    const budget: Eviction.Budget = .init(io, s.limits.budget_ms);
    if (total > keep) {
        std.mem.sort(Entry, entries.items, {}, struct {
            fn lt(_: void, a: Entry, b: Entry) bool {
                return a.used_ns < b.used_ns;
            }
        }.lt);
        const recent = std.Io.Clock.real.now(io).toNanoseconds() - @as(i128, s.limits.recent_s) * std.time.ns_per_s;
        var went = false;
        for (entries.items) |e| {
            if (total <= keep) break;
            // Under the cap only the disk asks, and a pass has its time for that: the next goes on.
            if (total <= s.max_bytes and (e.used_ns >= recent or (went and budget.late()))) continue;
            if (s.evict(arena, io, e.name)) {
                total -|= e.bytes;
                went = true;
            }
        }
    }
    s.dropKeyLocks(arena, io);
    key_diff.sweep(arena, io, s.root);
    Eviction.run(s, io);
}

/// What an entry counts for against the cap: its tree, and its record, as a step that printed much
/// and changed little is no cheaper to keep. And `entry_overhead`: its `meta`, its directories and
/// their inodes, or keys of steps that change nothing would grow for ever under a cap that sees 0.
fn accounted(m: Meta) u64 {
    return m.bytes + m.log_len + m.fc_len + entry_overhead;
}

const entry_overhead = 16 * 1024;

/// Removes one layer no job holds: renamed away under its lock taken exclusively (no job can
/// take it after that: the path names nothing), then deleted. False when a job holds it.
fn evict(s: Store, arena: Allocator, io: std.Io, name: []const u8) bool {
    const full = std.fmt.allocPrint(arena, "{s}/layers/{s}", .{ s.root, name }) catch return false;
    // An entry without its lock file (a broken one) no job can hold.
    const lock: ?std.Io.File = std.Io.Dir.cwd().openFile(io, join(arena, full, "lock") catch return false, .{}) catch |e|
        if (e == error.FileNotFound) null else return false;
    defer if (lock) |l| l.close(io);
    return s.evictOpened(arena, io, name, lock);
}

/// `evict` once the entry's lock file is open (`lock`, null when it has none). The lock counts only
/// on the file the path names now, as in `open` and `lockKey`: an entry evicted by another runner
/// since the file was opened leaves it unlinked and free, and the rename by name would then take
/// the entry published there since, which a job holds (proofs/tla/StoreLocking.tla).
fn evictOpened(s: Store, arena: Allocator, io: std.Io, name: []const u8, lock: ?std.Io.File) bool {
    const cwd = std.Io.Dir.cwd();
    const full = std.fmt.allocPrint(arena, "{s}/layers/{s}", .{ s.root, name }) catch return false;
    if (lock) |l| {
        if (!flock(l, lock_ex | lock_nb)) return false;
        if (!sameFile(arena, l, join(arena, full, "lock") catch return false)) return false;
    }
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const dead = std.fmt.allocPrint(arena, "{s}/layers/.dead-{s}", .{
        s.root,
        &std.fmt.bytesToHex(raw, .lower),
    }) catch return false;
    cwd.rename(full, cwd, dead, io) catch return false;
    removeTree(arena, io, dead);
    return true;
}

/// The lock files of keys no step is running now, removed so `keys/` does not grow with every
/// key ever run. A runner that opened one just before is not misled (`lockKey`).
fn dropKeyLocks(s: Store, arena: Allocator, io: std.Io) void {
    const cwd = std.Io.Dir.cwd();
    const keys = join(arena, s.root, "keys") catch return;
    var dir = cwd.openDir(io, keys, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        const full = join(arena, keys, e.name) catch return;
        const f = cwd.openFile(io, full, .{}) catch continue;
        defer f.close(io);
        if (!flock(f, lock_ex | lock_nb)) continue;
        cwd.deleteFile(io, full) catch {};
    }
}

/// The regular file `path`, read-only, or null: never through a symlink, and with no wait on a
/// FIFO, as a job may have left anything where one is looked for (`evict.zig`).
pub fn openPlain(arena: Allocator, path: []const u8) ?std.Io.File {
    const z = arena.dupeSentinel(u8, path, 0) catch return null;
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true };
    const rc = linux.open(z, flags, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    if (isRegular(fd)) return .{ .handle = fd, .flags = .{ .nonblocking = true } };
    _ = linux.close(fd);
    return null;
}

/// `openPlain`, of the name in `dir`.
pub fn openPlainAt(dir: linux.fd_t, name: [*:0]const u8) ?std.Io.File {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true };
    const rc = linux.openat(dir, name, flags, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd = std.math.cast(linux.fd_t, rc) orelse return null;
    if (isRegular(fd)) return .{ .handle = fd, .flags = .{ .nonblocking = true } };
    _ = linux.close(fd);
    return null;
}

fn isRegular(fd: linux.fd_t) bool {
    var st: linux.Statx = undefined;
    return linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) == .SUCCESS and
        st.mode & linux.S.IFMT == linux.S.IFREG;
}

/// The lock file `path`, made if it is not there, never through a symlink and with no wait on a
/// FIFO: a lock beside a volume may be in a directory a job could write (`evict.innerLock`). A
/// symlink or a FIFO there is no lock anyone holds, and is removed. A directory is an error,
/// `error.Locked`: it could hold anything, and is the outer volume's to lose. The lock counts only
/// once `sameFile` says so, as an eviction removes these.
pub fn lockBeside(arena: Allocator, io: std.Io, path: []const u8) !std.Io.File {
    const cwd = std.Io.Dir.cwd();
    const z = try arena.dupeSentinel(u8, path, 0);
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    for (0..8) |_| {
        const rc = linux.open(z, flags, 0o644);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                const fd = std.math.cast(linux.fd_t, rc) orelse return error.Locked;
                if (isRegular(fd)) return .{ .handle = fd, .flags = .{ .nonblocking = true } };
                _ = linux.close(fd);
            },
            .LOOP => {},
            .NOENT => return error.FileNotFound,
            else => return error.Locked,
        }
        cwd.deleteFile(io, path) catch {};
    }
    return error.Locked;
}

/// Whether `f` is the file `path` names now.
pub fn sameFile(arena: Allocator, f: std.Io.File, p: []const u8) bool {
    var held: linux.Statx = undefined;
    var named: linux.Statx = undefined;
    const z = arena.dupeSentinel(u8, p, 0) catch return false;
    const mask: linux.STATX = .{ .INO = true };
    if (linux.errno(linux.statx(f.handle, "", linux.AT.EMPTY_PATH, mask, &held)) != .SUCCESS)
        return false;
    if (linux.errno(linux.statx(linux.AT.FDCWD, z, 0, mask, &named)) != .SUCCESS) return false;
    return held.ino == named.ino and held.dev_major == named.dev_major and
        held.dev_minor == named.dev_minor;
}

/// Removes a tree, giving its directories their owner's permissions back first if a plain
/// delete fails (a step's `chmod 000`, overlay's work directory). What still fails is logged.
pub fn removeTree(arena: Allocator, io: std.Io, p: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    cwd.deleteTree(io, p) catch {
        chmodDirs(arena, io, p);
        cwd.deleteTree(io, p) catch |e|
            std.log.warn("native: cannot remove {s}: {s}", .{ p, @errorName(e) });
    };
}

/// Every directory under `p` given its owner's permissions, top down, with no limit on depth: a
/// directory is opened only once the ones above it are searchable again.
fn chmodDirs(arena: Allocator, io: std.Io, p: []const u8) void {
    const z = arena.dupeSentinel(u8, p, 0) catch return;
    _ = linux.chmod(z, 0o700);
    const root = openRoot(arena, p) catch return;
    defer _ = linux.close(root);
    var stack: std.ArrayList([]const u8) = .empty;
    stack.append(arena, "") catch return;
    while (stack.pop()) |rel| {
        const fd = if (rel.len == 0) root else openRel(arena, root, rel) catch continue;
        defer if (fd != root) {
            _ = linux.close(fd);
        };
        const nodes = listDir(arena, io, fd) catch continue;
        for (nodes) |n| {
            if (n.kind() != linux.S.IFDIR) continue;
            _ = linux.fchmodat(fd, n.name, 0o700);
            const sub = if (rel.len == 0)
                arena.dupe(u8, n.name) catch return
            else
                std.fmt.allocPrint(arena, "{s}/{s}", .{ rel, n.name }) catch return;
            stack.append(arena, sub) catch return;
        }
    }
}

/// The directory `rel` under `root`, through no symlink and never above `root`: in one `openat2`
/// (`RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`), or a component at a time, each `O_NOFOLLOW`, when
/// the kernel has no `openat2` (before 5.6) or the path is past its limit (a step can nest
/// directories deeper than PATH_MAX).
pub fn openRel(arena: Allocator, root: linux.fd_t, rel: []const u8) !linux.fd_t {
    if (rel.len < linux.PATH_MAX) {
        const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true };
        const how: OpenHow = .{
            .flags = @as(u32, @bitCast(flags)),
            .resolve = resolve_no_symlinks | resolve_beneath,
        };
        const rc = linux.syscall4(
            .openat2,
            @as(usize, @bitCast(@as(isize, root))),
            @intFromPtr((try arena.dupeSentinel(u8, rel, 0)).ptr),
            @intFromPtr(&how),
            @sizeOf(OpenHow),
        );
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .NOSYS, .NAMETOOLONG => {},
            else => return error.OpenDir,
        }
    }
    var fd = root;
    var parts = std.mem.splitScalar(u8, rel, '/');
    while (parts.next()) |part| {
        const next = openDirAt(fd, try arena.dupeSentinel(u8, part, 0)) catch |e| {
            if (fd != root) _ = linux.close(fd);
            return e;
        };
        if (fd != root) _ = linux.close(fd);
        fd = next;
    }
    return fd;
}

const max_depth = 256;

/// `struct open_how`, for `openat2(2)`.
const OpenHow = extern struct {
    flags: u64,
    mode: u64 = 0,
    resolve: u64,
};
const resolve_no_symlinks = 0x04;
const resolve_beneath = 0x08;

// --- walking trees: sizes, digests, the rootfs's fingerprint ---

/// One entry of a directory, as `walk` sees it: never through a symlink.
const Node = struct {
    name: [:0]const u8,
    st: linux.Statx,

    fn kind(n: Node) u32 {
        return n.st.mode & linux.S.IFMT;
    }
};

const stat_mask: linux.STATX = .{
    .TYPE = true,
    .MODE = true,
    .UID = true,
    .GID = true,
    .SIZE = true,
    .MTIME = true,
    .CTIME = true,
    .INO = true,
    .BLOCKS = true,
    .NLINK = true,
};

/// The entries of the directory `fd`, sorted by name (as bytes), stat'ed without following
/// symlinks.
fn listDir(arena: Allocator, io: std.Io, fd: linux.fd_t) ![]Node {
    const dir: std.Io.Dir = .{ .handle = fd };
    var out: std.ArrayList(Node) = .empty;
    var it = dir.iterateAssumeFirstIteration();
    while (try it.next(io)) |e| {
        const name = try arena.dupeSentinel(u8, e.name, 0);
        var st: linux.Statx = undefined;
        const rc = linux.statx(fd, name, linux.AT.SYMLINK_NOFOLLOW, stat_mask, &st);
        if (linux.errno(rc) != .SUCCESS) return error.Stat;
        try out.append(arena, .{ .name = name, .st = st });
    }
    std.mem.sort(Node, out.items, {}, struct {
        fn lt(_: void, a: Node, b: Node) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.lt);
    return out.items;
}

pub fn openDirAt(fd: linux.fd_t, name: [*:0]const u8) !linux.fd_t {
    const flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const rc = linux.openat(fd, name, flags, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OpenDir;
    return @intCast(rc);
}

pub fn openRoot(arena: Allocator, p: []const u8) !linux.fd_t {
    return openDirAt(linux.AT.FDCWD, try arena.dupeSentinel(u8, p, 0));
}

/// The bytes a tree takes on disk, each inode counted once, with no limit on depth. An error when
/// any directory of it cannot be read: a count that left part out would let the store pass its
/// cap, so such a layer is not published.
pub fn treeBytes(arena: Allocator, io: std.Io, p: []const u8) !u64 {
    const root = try openRoot(arena, p);
    defer _ = linux.close(root);
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(arena, "");
    var total: u64 = 0;
    while (stack.pop()) |rel| {
        const fd = if (rel.len == 0) root else try openRel(arena, root, rel);
        defer if (fd != root) {
            _ = linux.close(fd);
        };
        for (try listDir(arena, io, fd)) |n| {
            if (n.st.nlink > 1 and n.kind() != linux.S.IFDIR) {
                if ((try seen.getOrPut(arena, n.st.ino)).found_existing) continue;
            }
            total += n.st.blocks * 512;
            if (n.kind() != linux.S.IFDIR) continue;
            try stack.append(arena, if (rel.len == 0)
                try arena.dupe(u8, n.name)
            else
                try std.fmt.allocPrint(arena, "{s}/{s}", .{ rel, n.name }));
        }
    }
    return total;
}

/// How a job's namespace sees host ids: `base` onwards, `count` of them, as 0 onwards; any other
/// is the kernel's overflow id. A digest hashes ids so, never the host's.
pub const Ids = struct {
    base: u32 = 0,
    count: u32 = std.math.maxInt(u32),

    pub const host: Ids = .{};
    const overflow: u32 = 65534;

    fn inside(m: Ids, id: u32) u32 {
        if (id < m.base or id - m.base >= m.count) return overflow;
        return id - m.base;
    }
};

// --- canonical ids: a layer any slot can use ---

/// Gives every entry of the tree `p` (its root too) the ids the job's namespace saw it with
/// (`Ids.inside`): on a root runner, a layer a step left in its slot's host ids (`ids.base`
/// onwards) gets the canonical ids, 0 to 65535, which any slot's job sees as its own through an
/// idmapped mount (`sandbox.idmapLowers`); any other host id becomes the overflow id. So a layer
/// is the same whichever slot made it, and its digest with `ids` before is its digest with the
/// canonical ids after. Set-id bits, which `chown` clears, are put back; so are file capabilities
/// (also cleared), with their root's id shifted (one outside the range drops them); ACL entries'
/// ids are shifted. Through no symlink, with no limit on depth, each inode once. An error when
/// any entry cannot be read or changed: the layer must then not be published.
///
/// The invariant it relies on: nothing writes the tree while it runs. It is a step's upper after
/// the step ended (its PID namespace, and so every process of it, is gone) or the job's own
/// layers before a flatten, in the job's directory under the 0700 store. It is still careful, as
/// host root changing owners in a tree a job wrote must be: directories are opened beneath the
/// root through no symlink (`openRel`), and each entry is changed through an `O_PATH` descriptor
/// of its own, after checking it is the inode the walk saw, never by name.
pub fn unshift(arena: Allocator, io: std.Io, p: []const u8, ids: Ids) !void {
    const root = try openRoot(arena, p);
    defer _ = linux.close(root);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(root, "", linux.AT.EMPTY_PATH, stat_mask, &st)) != .SUCCESS)
        return error.Stat;
    try unshiftAt(arena, root, st, ids);
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(arena, "");
    while (stack.pop()) |rel| {
        const fd = if (rel.len == 0) root else try openRel(arena, root, rel);
        defer if (fd != root) {
            _ = linux.close(fd);
        };
        for (try listDir(arena, io, fd)) |n| {
            // A hard link's second name: its inode has its canonical ids already, which a second
            // shift would take for a host id outside the range.
            if (n.st.nlink > 1 and n.kind() != linux.S.IFDIR) {
                if ((try seen.getOrPut(arena, n.st.ino)).found_existing) continue;
            }
            try unshiftEntry(arena, fd, n.name, n.st, ids);
            if (n.kind() != linux.S.IFDIR) continue;
            try stack.append(arena, if (rel.len == 0)
                try arena.dupe(u8, n.name)
            else
                try std.fmt.allocPrint(arena, "{s}/{s}", .{ rel, n.name }));
        }
    }
}

const cap_xattr = "security.capability";
const acl_xattrs = [_][:0]const u8{ "system.posix_acl_access", "system.posix_acl_default" };

/// One entry, `name` in `dir`, shifted (`unshift`) through a descriptor of its own: opened
/// `O_PATH | O_NOFOLLOW` (a symlink is itself), and refused unless it is the inode `st` describes.
fn unshiftEntry(arena: Allocator, dir: linux.fd_t, name: [:0]const u8, st: linux.Statx, ids: Ids) !void {
    const flags: linux.O = .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true };
    const rc = linux.openat(dir, name, flags, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Open;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var now: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, stat_mask, &now)) != .SUCCESS)
        return error.Stat;
    if (now.ino != st.ino or now.dev_major != st.dev_major or now.dev_minor != st.dev_minor or
        now.mode & linux.S.IFMT != st.mode & linux.S.IFMT) return error.Changed;
    try unshiftAt(arena, fd, now, ids);
}

/// The entry `fd` is (an `O_PATH` descriptor, or the tree's root), shifted: owner, set-id bits,
/// ACLs and capabilities, each through the descriptor.
fn unshiftAt(arena: Allocator, fd: linux.fd_t, st: linux.Statx, ids: Ids) !void {
    const kind = st.mode & linux.S.IFMT;
    if (kind == linux.S.IFLNK) {
        if (linux.errno(linux.fchownat(fd, "", ids.inside(st.uid), ids.inside(st.gid), linux.AT.EMPTY_PATH)) != .SUCCESS)
            return error.Chown;
        return;
    }
    // The magic link reaches the descriptor's inode, not a name: followed, it is that entry.
    const p = try std.fmt.allocPrintSentinel(arena, "/proc/self/fd/{d}", .{fd}, 0);
    // Read before the chown, which drops a file's capabilities.
    const cap = if (kind == linux.S.IFREG) try ownXattr(arena, p, cap_xattr) else null;
    if (linux.errno(linux.fchownat(fd, "", ids.inside(st.uid), ids.inside(st.gid), linux.AT.EMPTY_PATH)) != .SUCCESS)
        return error.Chown;
    if (st.mode & (linux.S.ISUID | linux.S.ISGID) != 0) try chmodFd(fd, p, st.mode & 0o7777);
    for (acl_xattrs) |acl| {
        const v = try ownXattr(arena, p, acl) orelse continue;
        const shifted = try arena.dupe(u8, v);
        unshiftAcl(shifted, ids);
        if (linux.errno(linux.setxattr(p, acl, shifted.ptr, shifted.len, 0)) != .SUCCESS)
            return error.SetXattr;
    }
    if (cap) |v| if (try unshiftCap(arena, v, ids)) |shifted| {
        if (linux.errno(linux.setxattr(p, cap_xattr, shifted.ptr, shifted.len, 0)) != .SUCCESS)
            return error.SetXattr;
    };
}

/// `mode` set on the entry `fd` is, never a symlink: `fchmodat2` (Linux 6.6) on the descriptor,
/// else `chmod` through its magic link `p`.
fn chmodFd(fd: linux.fd_t, p: [:0]const u8, mode: u32) !void {
    switch (linux.errno(linux.fchmodat2(fd, "", mode, linux.AT.EMPTY_PATH | linux.AT.SYMLINK_NOFOLLOW))) {
        .SUCCESS => return,
        .NOSYS, .INVAL, .OPNOTSUPP, .BADF => {},
        else => return error.Chmod,
    }
    if (linux.errno(linux.chmod(p, mode)) != .SUCCESS) return error.Chmod;
}

/// An xattr's value, or null when the entry has none or its filesystem does not keep that kind.
/// `p` is a descriptor's magic link, followed to its inode.
fn ownXattr(arena: Allocator, p: [:0]const u8, name: [:0]const u8) !?[]const u8 {
    var buf: [64 * 1024]u8 = undefined;
    const got = linux.getxattr(p, name, &buf, buf.len);
    return switch (linux.errno(got)) {
        .SUCCESS => try arena.dupe(u8, buf[0..got]),
        .NODATA, .OPNOTSUPP => null,
        else => error.GetXattr,
    };
}

/// A POSIX ACL's xattr (a 4-byte header, then 8-byte entries of a u16 tag, a u16 permission and a
/// u32 id, little-endian) with its named users' and groups' ids shifted in place.
fn unshiftAcl(v: []u8, ids: Ids) void {
    const acl_user = 0x02;
    const acl_group = 0x08;
    var i: usize = 4;
    while (i + 8 <= v.len) : (i += 8) {
        const tag = std.mem.readInt(u16, v[i..][0..2], .little);
        if (tag != acl_user and tag != acl_group) continue;
        const id = std.mem.readInt(u32, v[i + 4 ..][0..4], .little);
        std.mem.writeInt(u32, v[i + 4 ..][0..4], ids.inside(id), .little);
    }
}

/// A file's capabilities (`vfs_ns_cap_data`) to set again after the chown: a v2 as it was; a v3,
/// whose root id is the host id of the namespace root they are for, as a v2 when that is the
/// job's root, or with its id shifted when it is another of the job's ids. Null, dropping them,
/// when that root is outside the job's range or the value is not one the kernel writes.
fn unshiftCap(arena: Allocator, v: []const u8, ids: Ids) !?[]const u8 {
    const revision_mask: u32 = 0xff000000;
    const revision_2: u32 = 0x02000000;
    const revision_3: u32 = 0x03000000;
    const v2_len = 20;
    if (v.len < 4) return null;
    const magic = std.mem.readInt(u32, v[0..4], .little);
    if (magic & revision_mask == revision_2 and v.len == v2_len) return v;
    if (magic & revision_mask != revision_3 or v.len != v2_len + 4) return null;
    const rootid = std.mem.readInt(u32, v[v2_len..][0..4], .little);
    if (rootid < ids.base or rootid - ids.base >= ids.count) return null;
    const inside = rootid - ids.base;
    if (inside != 0) {
        const out = try arena.dupe(u8, v);
        std.mem.writeInt(u32, out[v2_len..][0..4], inside, .little);
        return out;
    }
    const out = try arena.dupe(u8, v[0..v2_len]);
    std.mem.writeInt(u32, out[0..4], (magic & ~revision_mask) | revision_2, .little);
    return out;
}

/// What a digest covers of a regular file: its content (a layer's digest), or only its size and
/// mtime (the rootfs's fingerprint, where reading every byte of an image would cost seconds).
pub const Depth = enum { content, metadata };

/// A tree's digest: sha256 over a walk in byte order of names of each entry's path, type, mode,
/// owner as the job's namespace sees it (`ids`, so a layer made in one slot's range of ids
/// digests as one made in another's), the xattrs that say what it is (sorted; overlay's
/// bookkeeping, `origin`, `impure` and the like, left out), and its content: a file's bytes (or
/// its size and mtime, `Depth.metadata`), a symlink's target, a device's numbers (an overlay
/// whiteout among them). The same tree gives the same digest wherever and whenever it was made:
/// mtimes (but for `metadata`), inode numbers and link counts are not in it.
pub fn treeDigest(arena: Allocator, io: std.Io, p: []const u8, depth: Depth, ids: Ids) !Key {
    return treeDigestTo(arena, io, p, depth, ids, null);
}

/// `treeDigest`, with its preimage written to `bytes` when given: P8's layer vectors
/// (`key_vectors.zig`) check it against the model's (proofs/Runner/Native.lean, `walkPreimage`).
pub fn treeDigestTo(
    arena: Allocator,
    io: std.Io,
    p: []const u8,
    depth: Depth,
    ids: Ids,
    bytes: ?*std.Io.Writer,
) !Key {
    const fd = try openRoot(arena, p);
    defer _ = linux.close(fd);
    var h: KeyHasher = .{ .h = .init(.{}), .bytes = bytes };
    h.field("tree");
    try digestIn(arena, io, &h, fd, "", depth, ids, 0);
    return h.final();
}

fn digestIn(
    arena: Allocator,
    io: std.Io,
    h: *KeyHasher,
    fd: linux.fd_t,
    rel: []const u8,
    depth: Depth,
    ids: Ids,
    level: u32,
) !void {
    if (level > max_depth) return error.TooDeep;
    for (try listDir(arena, io, fd)) |n| {
        const sub_rel = try std.fmt.allocPrint(arena, "{s}/{s}", .{ rel, n.name });
        h.field(sub_rel);
        h.int(n.st.mode);
        h.int(ids.inside(n.st.uid));
        h.int(ids.inside(n.st.gid));
        try digestXattrs(arena, h, fd, n);
        // The rootfs's fingerprint: any write, chmod or touch since moves an entry's ctime,
        // which no tool can set back (a tar restoring mtimes does not restore it).
        if (depth == .metadata) {
            h.int(n.st.ino);
            // Seconds are signed (before 1970 is negative): hashed as their two's complement.
            h.int(@bitCast(n.st.ctime.sec));
            h.int(n.st.ctime.nsec);
        }
        switch (n.kind()) {
            linux.S.IFREG => switch (depth) {
                .metadata => {
                    h.int(n.st.size);
                    h.int(@bitCast(n.st.mtime.sec));
                    h.int(n.st.mtime.nsec);
                },
                .content => {
                    const flags: linux.O = .{
                        .ACCMODE = .RDONLY,
                        .NOFOLLOW = true,
                        .CLOEXEC = true,
                    };
                    const f = linux.openat(fd, n.name, flags, 0);
                    if (linux.errno(f) != .SUCCESS) return error.Open;
                    defer _ = linux.close(@intCast(f));
                    var fh: Sha256 = .init(.{});
                    var buf: [64 * 1024]u8 = undefined;
                    while (true) {
                        const got = linux.read(@intCast(f), &buf, buf.len);
                        if (linux.errno(got) != .SUCCESS) return error.Read;
                        if (got == 0) break;
                        fh.update(buf[0..got]);
                    }
                    h.field(&fh.finalResult());
                },
            },
            linux.S.IFLNK => {
                var buf: [linux.PATH_MAX]u8 = undefined;
                const got = linux.readlinkat(fd, n.name, &buf, buf.len);
                if (linux.errno(got) != .SUCCESS) return error.ReadLink;
                h.field(buf[0..got]);
            },
            linux.S.IFCHR, linux.S.IFBLK => {
                h.int(n.st.rdev_major);
                h.int(n.st.rdev_minor);
            },
            linux.S.IFDIR => {
                const sub = try openDirAt(fd, n.name);
                defer _ = linux.close(sub);
                try digestIn(arena, io, h, sub, sub_rel, depth, ids, level + 1);
                h.field("..");
            },
            else => {},
        }
    }
}

/// Whether an xattr says what an entry is (a digest covers it), rather than being overlay's
/// bookkeeping about where it came from.
fn digestedXattr(name: []const u8) bool {
    for ([_][]const u8{ "trusted.overlay.", "user.overlay." }) |prefix| {
        if (!std.mem.startsWith(u8, name, prefix)) continue;
        const rest = name[prefix.len..];
        return std.mem.eql(u8, rest, "opaque") or std.mem.eql(u8, rest, "redirect") or
            std.mem.eql(u8, rest, "metacopy") or std.mem.eql(u8, rest, "whiteout");
    }
    return true;
}

/// Counted first, so the last xattr and the content after it cannot be told apart otherwise (P8,
/// `Native.walk_injective`: a symlink's target is a field like an xattr's name).
fn digestXattrs(arena: Allocator, h: *KeyHasher, dir: linux.fd_t, n: Node) !void {
    const p = try procPath(arena, dir, n.name);
    const names = try xattrNames(arena, p);
    var count: u64 = 0;
    for (names) |name| count += @intFromBool(digestedXattr(name));
    h.int(count);
    for (names) |name| {
        if (!digestedXattr(name)) continue;
        h.field(name);
        h.field(try xattrValue(arena, p, name) orelse "");
    }
}

/// A path to `name` in the directory `dir` for the `l*xattr` calls, which take no directory.
fn procPath(arena: Allocator, dir: linux.fd_t, name: []const u8) ![:0]const u8 {
    return std.fmt.allocPrintSentinel(arena, "/proc/self/fd/{d}/{s}", .{ dir, name }, 0);
}

/// The xattrs' names of `p` (not through a final symlink), sorted.
fn xattrNames(arena: Allocator, p: [:0]const u8) ![]const []const u8 {
    var buf: [64 * 1024]u8 = undefined;
    const got = linux.llistxattr(p, &buf, buf.len);
    switch (linux.errno(got)) {
        .SUCCESS => {},
        .OPNOTSUPP, .NODATA => return &.{},
        else => return error.ListXattr,
    }
    var out: std.ArrayList([]const u8) = .empty;
    var names = std.mem.splitScalar(u8, buf[0..got], 0);
    while (names.next()) |name| if (name.len > 0) try out.append(arena, try arena.dupe(u8, name));
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    return out.items;
}

fn xattrValue(arena: Allocator, p: [:0]const u8, name: []const u8) !?[]const u8 {
    var buf: [64 * 1024]u8 = undefined;
    const got = linux.lgetxattr(p, try arena.dupeSentinel(u8, name, 0), &buf, buf.len);
    switch (linux.errno(got)) {
        .SUCCESS => return try arena.dupe(u8, buf[0..got]),
        .NODATA => return null,
        else => return error.GetXattr,
    }
}

/// A layer's digest (`treeDigest` of its tree), computed when first asked for and then kept
/// beside it. What `changes(from:).layer.digest` gives the Dagger backend's output keys.
pub fn layerDigest(s: Store, arena: Allocator, io: std.Io, key: Key, ids: Ids) !Key {
    const dir = try s.layerDir(arena, key);
    const cwd = std.Io.Dir.cwd();
    const kept = try join(arena, dir, "digest");
    if (cwd.readFileAlloc(io, kept, arena, .limited(128))) |text| {
        var d: Key = undefined;
        const digest = std.mem.trim(u8, text, " \n");
        // Whole: `hexToBytes` takes an empty file too, and fills in nothing.
        if (digest.len == d.len * 2) {
            if (std.fmt.hexToBytes(&d, digest)) |_| return d else |_| {}
        }
    } else |_| {}
    const d = try treeDigest(arena, io, try join(arena, dir, "fs"), .content, ids);
    // Written aside and renamed, so a reader never sees half of it.
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const tmp = try std.fmt.allocPrint(arena, "{s}.{s}", .{
        kept,
        &std.fmt.bytesToHex(raw, .lower),
    });
    {
        const f = try cwd.createFile(io, tmp, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, &hex(d));
        // On disk before its name is. Kept only to save a walk: without it, it is walked again.
        if (linux.errno(linux.fsync(f.handle)) != .SUCCESS) {
            cwd.deleteFile(io, tmp) catch {};
            return d;
        }
    }
    cwd.rename(tmp, cwd, kept, io) catch cwd.deleteFile(io, tmp) catch {};
    return d;
}

/// The rootfs's fingerprint, for the base's parent (`Backend.below`): a rootfs made again gives
/// the jobs new keys. It is `treeDigest` of the metadata (ctimes and inodes among it), which a walk
/// of a whole image costs, so it is kept per process and checked again for every job against
/// what changes when the rootfs is replaced or touched: the root's inode and ctime, and the
/// provisioning stamp's (`rootfs_stamp`, which the recipe touches after changing the rootfs in
/// place). A change the stamp does not show, under a running runner, is found at its restart.
///
/// A rootfs in the store (`store`, its root; "" for none) is not walked: no one writes it, what it
/// holds is in its key, and only making it again gives it a new root. Its files' ctimes say nothing:
/// they share inodes with its image and siblings (`oci.Store.flatten`), so each file an eviction
/// removes from any of those would move this digest, a little at each pass.
pub fn rootfsFingerprint(arena: Allocator, io: std.Io, rootfs: []const u8, store: []const u8) !Key {
    if (storeTree(rootfs, store)) {
        var h: KeyHasher = .plain("a rootfs in the store");
        h.field(rootfs);
        h.field(&try rootIdentity(arena, rootfs));
        return h.final();
    }
    const seen = try rootfsSeen(arena, rootfs);
    fp_mu.lockUncancelable(io);
    defer fp_mu.unlock(io);
    if (fp_len > 0 and std.mem.eql(u8, fp_path[0..fp_len], rootfs) and
        std.mem.eql(u8, &fp_seen, &seen)) return fp_key;
    var h: KeyHasher = .plain("rootfs");
    h.field(&try treeDigest(arena, io, rootfs, .metadata, .host));
    h.field(&seen);
    const k = h.final();
    if (rootfs.len <= fp_path.len) {
        @memcpy(fp_path[0..rootfs.len], rootfs);
        fp_len = rootfs.len;
        fp_key = k;
        fp_seen = seen;
    }
    return k;
}

/// The file, in the rootfs, that says it was provisioned again: touched after changing it in place
/// (docs/native-backend.md, "The rootfs").
pub const rootfs_stamp = ".zig-runner-provisioned";

/// Whether `rootfs` is a tree the store made: `<store>/rootfs/<key>/rootfs` or
/// `<store>/oci/images/<key>/rootfs`, and not whatever an operator keeps under it
/// (`RUNNER_NATIVE_ROOTFS`), which changes in place and says so with its stamp.
fn storeTree(rootfs: []const u8, store: []const u8) bool {
    if (store.len == 0 or rootfs.len <= store.len + 1 or rootfs[store.len] != '/' or
        !std.mem.startsWith(u8, rootfs, store)) return false;
    const rel = rootfs[store.len + 1 ..];
    const end = "/rootfs";
    if (!std.mem.endsWith(u8, rel, end)) return false;
    for ([_][]const u8{ "rootfs/", "oci/images/" }) |area| {
        if (!std.mem.startsWith(u8, rel, area) or rel.len <= area.len + end.len) continue;
        return std.mem.indexOfScalar(u8, rel[area.len .. rel.len - end.len], '/') == null;
    }
    return false;
}

/// A rootfs's root directory: which inode, since when.
fn rootIdentity(arena: Allocator, rootfs: []const u8) !Key {
    const p = try arena.dupeSentinel(u8, rootfs, 0);
    var st: linux.Statx = undefined;
    const mask: linux.STATX = .{ .INO = true, .CTIME = true };
    if (linux.errno(linux.statx(linux.AT.FDCWD, p, linux.AT.SYMLINK_NOFOLLOW, mask, &st)) != .SUCCESS)
        return error.RootfsUnreadable;
    var h: KeyHasher = .plain("rootfs root");
    h.int(st.ino);
    h.int(std.math.cast(u64, st.ctime.sec) orelse 0);
    h.int(st.ctime.nsec);
    return h.final();
}

/// What `rootfsFingerprint` checks for every job: the root's and the stamp's identity and ctime.
fn rootfsSeen(arena: Allocator, rootfs: []const u8) !Key {
    var h: KeyHasher = .plain("rootfs seen");
    for ([_][]const u8{ "", rootfs_stamp }) |name| {
        const p = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ rootfs, name }, 0);
        var st: linux.Statx = undefined;
        const mask: linux.STATX = .{ .INO = true, .CTIME = true };
        const rc = linux.statx(linux.AT.FDCWD, p, linux.AT.SYMLINK_NOFOLLOW, mask, &st);
        if (linux.errno(rc) != .SUCCESS) {
            if (name.len == 0) return error.RootfsUnreadable;
            h.field("none");
            continue;
        }
        h.int(st.dev_major);
        h.int(st.dev_minor);
        h.int(st.ino);
        h.int(@bitCast(st.ctime.sec));
        h.int(st.ctime.nsec);
    }
    return h.final();
}

var fp_mu: std.Io.Mutex = .init;
var fp_path: [std.Io.Dir.max_path_bytes]u8 = undefined;
var fp_len: usize = 0;
var fp_key: Key = undefined;
var fp_seen: Key = undefined;

// --- flattening ---

/// Merges overlay layers (`layers`, bottom first) into the new directory `out`, as overlay shows
/// them over what lies below: a later layer's entry replaces an earlier one's, its whiteout
/// deletes it (and is kept, to hide the rootfs below `out`), its opaque directory hides what
/// earlier ones had there (and stays opaque). Files are hard links, not copies, so a merge costs
/// directories and links, not bytes; directories are made with their owner, mode, xattrs and
/// times. `opaque_xattr` is overlay's (`trusted.overlay.opaque`, or `user.overlay.opaque` under
/// `userxattr`). Overlay's redirects and metacopy, which the runner never turns on, are refused.
pub fn flatten(
    arena: Allocator,
    io: std.Io,
    layers: []const []const u8,
    out: []const u8,
    opaque_xattr: [:0]const u8,
) !void {
    const out_z = try arena.dupeSentinel(u8, out, 0);
    if (linux.errno(linux.mkdir(out_z, 0o700)) != .SUCCESS) return error.MakeDir;
    const out_fd = try openRoot(arena, out);
    defer _ = linux.close(out_fd);
    var top: ?linux.fd_t = null;
    defer if (top) |t| {
        _ = linux.close(t);
    };
    for (layers) |l| {
        const src = try openRoot(arena, l);
        try merge(arena, io, src, out_fd, opaque_xattr, 0);
        if (top) |t| _ = linux.close(t);
        top = src;
    }
    // The root's own owner, mode and xattrs: the top layer's, as overlay shows them.
    if (top) |t| try copyDirMeta(arena, t, out_fd);
}

fn merge(
    arena: Allocator,
    io: std.Io,
    src: linux.fd_t,
    out: linux.fd_t,
    opaque_xattr: [:0]const u8,
    depth: u32,
) !void {
    if (depth > max_depth) return error.TooDeep;
    for (try listDir(arena, io, src)) |n| {
        var ost: linux.Statx = undefined;
        const rc = linux.statx(out, n.name, linux.AT.SYMLINK_NOFOLLOW, stat_mask, &ost);
        const exists = linux.errno(rc) == .SUCCESS;
        if (n.kind() != linux.S.IFDIR) {
            if (exists) try removeAt(arena, io, out, n.name, 0);
            // A whiteout too: kept, as it hides the rootfs's entry below.
            if (linux.errno(linux.linkat(src, n.name, out, n.name, 0)) != .SUCCESS)
                return error.Link;
            continue;
        }
        const p = try procPath(arena, src, n.name);
        for ([_][]const u8{ "redirect", "metacopy" }) |what| {
            const name = try std.fmt.allocPrint(arena, "{s}{s}", .{
                opaque_xattr[0 .. opaque_xattr.len - "opaque".len],
                what,
            });
            if (try xattrValue(arena, p, name) != null) return error.OverlayRedirectOrMetacopy;
        }
        const opaque_dir = if (try xattrValue(arena, p, opaque_xattr)) |v|
            std.mem.eql(u8, v, "y")
        else
            false;
        const merges = exists and (ost.mode & linux.S.IFMT) == linux.S.IFDIR and !opaque_dir;
        if (exists and !merges) try removeAt(arena, io, out, n.name, 0);
        if (!merges) {
            if (linux.errno(linux.mkdirat(out, n.name, 0o700)) != .SUCCESS) return error.MakeDir;
        } else _ = linux.fchmodat(out, n.name, 0o700);
        const s = try openDirAt(src, n.name);
        defer _ = linux.close(s);
        const o = try openDirAt(out, n.name);
        defer _ = linux.close(o);
        try merge(arena, io, s, o, opaque_xattr, depth + 1);
        try copyDirMeta(arena, s, o);
    }
}

/// A directory's owner, mode, xattrs and times from `src` onto `out`. Xattrs are set, never
/// removed, so an opaque `out` stays opaque: a later layer's plain directory over an opaque one
/// still hides the rootfs's.
fn copyDirMeta(arena: Allocator, src: linux.fd_t, out: linux.fd_t) !void {
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(src, "", linux.AT.EMPTY_PATH, stat_mask, &st)) != .SUCCESS)
        return error.Stat;
    // Through `.`, so the `l*xattr` calls see the directory, not the magic link to it.
    const sp = try std.fmt.allocPrintSentinel(arena, "/proc/self/fd/{d}/.", .{src}, 0);
    for (try xattrNames(arena, sp)) |name| {
        if (!digestedXattr(name)) continue;
        const v = try xattrValue(arena, sp, name) orelse continue;
        const name_z = try arena.dupeSentinel(u8, name, 0);
        // An LSM's label (`security.selinux`) may be refused; the rest says what the entry is.
        if (linux.errno(linux.fsetxattr(out, name_z, v.ptr, v.len, 0)) != .SUCCESS and
            !std.mem.startsWith(u8, name, "security.")) return error.SetXattr;
    }
    if (linux.errno(linux.fchown(out, st.uid, st.gid)) != .SUCCESS) return error.Chown;
    if (linux.errno(linux.fchmod(out, st.mode & 0o7777)) != .SUCCESS) return error.Chmod;
    const times = [2]linux.timespec{
        .{ .sec = @intCast(st.mtime.sec), .nsec = @intCast(st.mtime.nsec) },
        .{ .sec = @intCast(st.mtime.sec), .nsec = @intCast(st.mtime.nsec) },
    };
    _ = linux.utimensat(out, null, &times, 0);
}

/// Removes `name` from the directory `dir`, a directory with everything in it.
fn removeAt(arena: Allocator, io: std.Io, dir: linux.fd_t, name: [*:0]const u8, depth: u32) !void {
    switch (linux.errno(linux.unlinkat(dir, name, 0))) {
        .SUCCESS, .NOENT => return,
        .ISDIR => {},
        else => return error.Unlink,
    }
    if (depth > max_depth) return error.TooDeep;
    _ = linux.fchmodat(dir, name, 0o700);
    const sub = try openDirAt(dir, name);
    {
        defer _ = linux.close(sub);
        for (try listDir(arena, io, sub)) |n| try removeAt(arena, io, sub, n.name, depth + 1);
    }
    if (linux.errno(linux.unlinkat(dir, name, linux.AT.REMOVEDIR)) != .SUCCESS)
        return error.Unlink;
}

// --- tests ---

test "native store: a tree's digest: the same tree anywhere digests alike; content, mode and xattrs count" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = tmp.dir;
    // The same files, made in different orders at different times.
    for ([_][]const u8{ "x", "y" }) |top| {
        const order: []const []const u8 = if (top[0] == 'x')
            &.{ "a/b/one", "a/two", "three" }
        else
            &.{ "three", "a/two", "a/b/one" };
        for (order) |f| {
            const p = try std.fmt.allocPrint(arena, "{s}/{s}", .{ top, f });
            try d.createDirPath(io, std.fs.path.dirname(p).?);
            try d.writeFile(io, .{ .sub_path = p, .data = f });
        }
        try d.symLink(io, "three", try std.fmt.allocPrint(arena, "{s}/link", .{top}), .{});
    }
    const root = try d.realPathFileAlloc(io, ".", arena);
    const x = try std.fmt.allocPrint(arena, "{s}/x", .{root});
    const y = try std.fmt.allocPrint(arena, "{s}/y", .{root});
    const dx = try treeDigest(arena, io, x, .content, .host);
    try std.testing.expectEqualSlices(u8, &dx, &try treeDigest(arena, io, y, .content, .host));
    // The content counts.
    try d.writeFile(io, .{ .sub_path = "y/a/two", .data = "changed" });
    const changed = try treeDigest(arena, io, y, .content, .host);
    try std.testing.expect(!std.mem.eql(u8, &dx, &changed));
    try d.writeFile(io, .{ .sub_path = "y/a/two", .data = "a/two" });
    try std.testing.expectEqualSlices(u8, &dx, &try treeDigest(arena, io, y, .content, .host));
    // The mode counts.
    const two = try arena.dupeSentinel(u8, try std.fmt.allocPrint(arena, "{s}/a/two", .{y}), 0);
    var was: linux.Statx = undefined;
    _ = linux.statx(linux.AT.FDCWD, two, 0, .{ .MODE = true }, &was);
    _ = linux.chmod(two, 0o600);
    try std.testing.expect(!std.mem.eql(u8, &dx, &try treeDigest(arena, io, y, .content, .host)));
    _ = linux.chmod(two, was.mode & 0o7777);
    try std.testing.expectEqualSlices(u8, &dx, &try treeDigest(arena, io, y, .content, .host));
    // A user xattr counts, where the filesystem has them.
    if (linux.errno(linux.setxattr(two, "user.zr", "v", 1, 0)) == .SUCCESS)
        try std.testing.expect(!std.mem.eql(u8, &dx, &try treeDigest(arena, io, y, .content, .host)));
    // A metadata digest sees a touch the content digest does not.
    const mx = try treeDigest(arena, io, x, .metadata, .host);
    const one = try arena.dupeSentinel(u8, try std.fmt.allocPrint(arena, "{s}/a/b/one", .{x}), 0);
    const t = [2]linux.timespec{ .{ .sec = 1, .nsec = 0 }, .{ .sec = 1, .nsec = 0 } };
    _ = linux.utimensat(linux.AT.FDCWD, one, &t, 0);
    try std.testing.expect(!std.mem.eql(u8, &mx, &try treeDigest(arena, io, x, .metadata, .host)));
    try std.testing.expectEqualSlices(u8, &dx, &try treeDigest(arena, io, x, .content, .host));
}

test "native store: flattening layers: later entries win, whiteouts are kept, opaque directories hide" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = tmp.dir;
    const files = [_][2][]const u8{
        .{ "l0/keep", "0" },       .{ "l0/replaced", "0" }, .{ "l0/dir/old", "0" },
        .{ "l0/merged/a", "0" },   .{ "l1/replaced", "1" }, .{ "l1/dir/new", "1" },
        .{ "l1/merged/b", "1" },   .{ "l2/gone", "2" },     .{ "l2/became-dir/x", "2" },
        .{ "l0/became-dir", "0" },
    };
    for (files) |f| {
        try d.createDirPath(io, std.fs.path.dirname(f[0]).?);
        try d.writeFile(io, .{ .sub_path = f[0], .data = f[1] });
    }
    const root = try d.realPathFileAlloc(io, ".", arena);
    const opaque_name = "user.overlay.opaque";
    // l1's `dir` is opaque: l0's `dir/old` is hidden.
    const dir1 = try std.fmt.allocPrintSentinel(arena, "{s}/l1/dir", .{root}, 0);
    if (linux.errno(linux.setxattr(dir1, opaque_name, "y", 1, 0)) != .SUCCESS)
        return error.SkipZigTest; // no user xattrs here
    // l2 deletes `keep` with a whiteout; a whiteout needs CAP_MKNOD, so where it cannot be made
    // the case is left out.
    const wh = try std.fmt.allocPrintSentinel(arena, "{s}/l2/keep", .{root}, 0);
    const whiteout = linux.errno(linux.mknod(wh, linux.S.IFCHR | 0o000, 0)) == .SUCCESS;
    const layers = [_][]const u8{
        try std.fmt.allocPrint(arena, "{s}/l0", .{root}),
        try std.fmt.allocPrint(arena, "{s}/l1", .{root}),
        try std.fmt.allocPrint(arena, "{s}/l2", .{root}),
    };
    const out = try std.fmt.allocPrint(arena, "{s}/out", .{root});
    try flatten(arena, io, &layers, out, opaque_name);
    const read = struct {
        fn f(ar: Allocator, dd: std.Io.Dir, p: []const u8) ?[]const u8 {
            return dd.readFileAlloc(std.testing.io, p, ar, .limited(64)) catch null;
        }
    }.f;
    try std.testing.expectEqualStrings("1", read(arena, d, "out/replaced").?);
    try std.testing.expectEqualStrings("1", read(arena, d, "out/dir/new").?);
    try std.testing.expect(read(arena, d, "out/dir/old") == null);
    try std.testing.expectEqualStrings("0", read(arena, d, "out/merged/a").?);
    try std.testing.expectEqualStrings("1", read(arena, d, "out/merged/b").?);
    try std.testing.expectEqualStrings("2", read(arena, d, "out/gone").?);
    try std.testing.expectEqualStrings("2", read(arena, d, "out/became-dir/x").?);
    // The opaque directory stays opaque, for the rootfs below.
    const out_dir = try std.fmt.allocPrintSentinel(arena, "{s}/out/dir", .{root}, 0);
    var v: [4]u8 = undefined;
    const got = linux.getxattr(out_dir, opaque_name, &v, v.len);
    try std.testing.expectEqualStrings("y", v[0..got]);
    if (whiteout) {
        var st: linux.Statx = undefined;
        const p = try std.fmt.allocPrintSentinel(arena, "{s}/out/keep", .{root}, 0);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.statx(linux.AT.FDCWD, p, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &st)));
        try std.testing.expectEqual(@as(u32, linux.S.IFCHR), st.mode & linux.S.IFMT);
    } else try std.testing.expectEqualStrings("0", read(arena, d, "out/keep").?);
    // Files are links to the layers' own, not copies.
    var s0: linux.Statx = undefined;
    var s1: linux.Statx = undefined;
    const a0 = try std.fmt.allocPrintSentinel(arena, "{s}/l1/replaced", .{root}, 0);
    const a1 = try std.fmt.allocPrintSentinel(arena, "{s}/out/replaced", .{root}, 0);
    _ = linux.statx(linux.AT.FDCWD, a0, 0, .{ .INO = true }, &s0);
    _ = linux.statx(linux.AT.FDCWD, a1, 0, .{ .INO = true }, &s1);
    try std.testing.expectEqual(s0.ino, s1.ino);
}

test "native store: after a boot a layer whose tree changed is evicted, once" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    const kept, const l1 = try testLayer(arena, io, tmp, &s, "kept");
    l1.lock.close(io);
    const cut, const l2 = try testLayer(arena, io, tmp, &s, "cut");
    l2.lock.close(io);
    // This boot's check passes both, and marks the store with this boot's id: a mark that came
    // out empty (the id read as 0 bytes, as /proc files are by their size) would match an empty
    // read on every later boot, and no boot would be checked again.
    s.checkOncePerBoot(arena, io);
    var id_buf: [64]u8 = undefined;
    const id = try std.Io.Dir.cwd().readFile(io, "/proc/sys/kernel/random/boot_id", &id_buf);
    try std.testing.expectEqual(@as(usize, 37), id.len);
    const mark = try tmp.dir.readFileAlloc(io, "store/boot", arena, .limited(64));
    try std.testing.expectEqualStrings(id, mark);
    (try s.open(arena, io, kept)).?.layer.lock.close(io);
    (try s.open(arena, io, cut)).?.layer.lock.close(io);

    // What a crash leaves: a file emptied under a whole-looking entry. `open` cannot see it.
    const file = try std.fmt.allocPrint(arena, "store/layers/{s}/fs/f", .{&hex(cut)});
    try tmp.dir.writeFile(io, .{ .sub_path = file, .data = "" });
    (try s.open(arena, io, cut)).?.layer.lock.close(io);
    // In the same boot, nothing looks.
    s.checkOncePerBoot(arena, io);
    (try s.open(arena, io, cut)).?.layer.lock.close(io);

    // After another boot it is gone, and the whole one stays.
    try tmp.dir.writeFile(io, .{ .sub_path = "store/boot", .data = "another boot\n" });
    s.checkOncePerBoot(arena, io);
    try std.testing.expect(try s.open(arena, io, cut) == null);
    (try s.open(arena, io, kept)).?.layer.lock.close(io);
}

test "native store: a failed fsync is not lost to an unreadable file's fallback" {
    var w: SyncWork = .{ .root = -1, .todo = &.{} };
    try w.result();
    w.unreadable.store(true, .release);
    try std.testing.expectError(error.Unreadable, w.result());
    w.failed.store(true, .release);
    try std.testing.expectError(error.Sync, w.result());
}

/// The tree at `p` synced as a publish syncs it: what a test needs of `writeBack` and `syncEntries`.
fn testSync(arena: Allocator, io: std.Io, p: []const u8) !void {
    const root = try openRoot(arena, p);
    defer _ = linux.close(root);
    return syncEntries(root, try writeBack(arena, io, root, std.math.maxInt(u64)));
}

test "native store: a writeback's error is the publish's, which no later fsync would see" {
    // No such descriptor.
    const bad = [_]linux.fd_t{1 << 30};
    try std.testing.expectError(error.Sync, waitWritten(&bad));
    try waitWritten(&.{});
}

test "native store: a walk that passes the limit stops, and a large entry syncs the filesystem" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "t/d");
    // More files than `write_back_batch`, so a batch is waited for on the way.
    for (0..write_back_batch + 3) |i| try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "t/d/f{d}", .{i}),
        .data = "x",
    });
    const t = try std.fmt.allocPrint(arena, "{s}/t", .{root});
    const entries = write_back_batch + 4;
    for ([_]u64{ entries, entries - 1 }) |max| {
        const fd = try openRoot(arena, t);
        defer _ = linux.close(fd);
        if (writeBack(arena, io, fd, max)) |todo| {
            // Each file and directory, and the tree's own root.
            try std.testing.expectEqual(entries, max);
            try std.testing.expectEqual(entries + 1, todo.len);
        } else |e| {
            try std.testing.expectEqual(error.TooLarge, e);
            try std.testing.expectEqual(entries - 1, max);
        }
    }

    // A descriptor that fails shows which sync a publish made: a small entry's own fsyncs never
    // touch it, a large one's `syncfs` must, and then nothing is published and the upper is back.
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}), .sync_fd = -1 };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    var never: std.atomic.Value(bool) = .init(false);
    var small_key: KeyHasher = .plain("small");
    const small = small_key.final();
    const small_lock = try s.lockKey(arena, io, small, &never);
    defer small_lock.close(io);
    try tmp.dir.createDirPath(io, "small");
    try tmp.dir.writeFile(io, .{ .sub_path = "small/f", .data = "s" });
    const small_upper = try std.fmt.allocPrint(arena, "{s}/small", .{root});
    const l = try s.publish(arena, io, small, .fetch, small_upper, .{ .log = "", .fc = "" });
    l.lock.close(io);
    var large_key: KeyHasher = .plain("large");
    const large = large_key.final();
    const large_lock = try s.lockKey(arena, io, large, &never);
    defer large_lock.close(io);
    for (0..sync_tree_max) |i| try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "t/d/g{d}", .{i}),
        .data = "",
    });
    try std.testing.expectError(
        error.Sync,
        s.publish(arena, io, large, .fetch, t, .{ .log = "", .fc = "" }),
    );
    try tmp.dir.access(io, "t/d/g0", .{});
    try std.testing.expect(try s.open(arena, io, large) == null);
}

test "native store: a publish's phases show the sync's parts, and syncfs only when it was taken" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    var never: std.atomic.Value(bool) = .init(false);
    var ph: phases.Phases = .{};
    for ([_]struct { name: []const u8, files: usize }{
        .{ .name = "under", .files = 3 },
        .{ .name = "over", .files = sync_tree_max + 1 },
    }) |c| {
        const dir = try std.fmt.allocPrint(arena, "{s}/up-{s}", .{ root, c.name });
        try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "up-{s}", .{c.name}));
        for (0..c.files) |i| try tmp.dir.writeFile(io, .{
            .sub_path = try std.fmt.allocPrint(arena, "up-{s}/f{d}", .{ c.name, i }),
            .data = "x",
        });
        var kh: KeyHasher = .plain(c.name);
        const k = kh.final();
        const kl = try s.lockKey(arena, io, k, &never);
        defer kl.close(io);
        const before = ph.mark();
        const l = try s.publishTimed(arena, io, k, .fetch, dir, .{ .log = "", .fc = "" }, &ph);
        l.lock.close(io);
        const line = try ph.text(arena, before, .steps);
        for ([_][]const u8{ "sync=", "sync_wb=", "sync_fsync=", "sync_meta=" }) |name| {
            try std.testing.expect(std.mem.indexOf(u8, line, name) != null);
        }
        const took = std.mem.indexOf(u8, line, "syncfs=") != null;
        try std.testing.expectEqual(c.files > sync_tree_max, took);
    }
}

test "native store: a checkout's size of entries is synced on its own, not with the whole disk" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "t/d");
    for (0..370) |i| try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "t/d/f{d}", .{i}),
        .data = "x",
    });
    // A descriptor that fails: `syncfs` would refuse the publish, so it was not called.
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}), .sync_fd = -1 };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    var kh: KeyHasher = .plain("checkout");
    const k = kh.final();
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, k, &never);
    defer kl.close(io);
    const upper = try std.fmt.allocPrint(arena, "{s}/t", .{root});
    const l = try s.publish(arena, io, k, .fetch, upper, .{ .log = "", .fc = "" });
    l.lock.close(io);
}

test "native store: a publish syncs the entry's own tree, and a file it cannot open falls back to the filesystem's" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // Nested directories, files with data and empty, a symlink and a fifo (never opened: one
    // would block), all synced.
    try tmp.dir.createDirPath(io, "t/a/b/c");
    try tmp.dir.writeFile(io, .{ .sub_path = "t/a/b/c/f", .data = &@as([70000]u8, @splat('y')) });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/empty", .data = "" });
    try tmp.dir.symLink(io, "a/b/c/f", "t/link", .{});
    const fifo = try std.fmt.allocPrint(arena, "{s}/t/a/fifo", .{root});
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mknodat(
        linux.AT.FDCWD,
        try arena.dupeSentinel(u8, fifo, 0),
        linux.S.IFIFO | 0o600,
        0,
    )));
    try testSync(arena, io, try std.fmt.allocPrint(arena, "{s}/t", .{root}));
    // A file nobody may read: the runner's root may open it anyway; its user may not, and then
    // the publish syncs the whole filesystem instead, and still publishes.
    try tmp.dir.writeFile(io, .{ .sub_path = "t/a/secret", .data = "s" });
    const secret = try arena.dupeSentinel(u8, try std.fmt.allocPrint(arena, "{s}/t/a/secret", .{root}), 0);
    _ = linux.chmod(secret, 0);
    if (testSync(arena, io, try std.fmt.allocPrint(arena, "{s}/t", .{root}))) |_| {
        try std.testing.expectEqual(@as(u32, 0), linux.geteuid());
    } else |e| try std.testing.expectEqual(error.Unreadable, e);
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    var kh: KeyHasher = .plain("sync");
    const k = kh.final();
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, k, &never);
    defer kl.close(io);
    const l = try s.publish(arena, io, k, .fetch, try std.fmt.allocPrint(arena, "{s}/t", .{root}), .{
        .log = "",
        .fc = "",
    });
    l.lock.close(io);
    const hit = (try s.open(arena, io, k)).?;
    hit.layer.lock.close(io);
    // The meta was written before the tree's fsyncs, and still counts what the tree takes.
    try std.testing.expectEqual(
        (try metaOf(arena, io, try s.layerDir(arena, k))).bytes,
        try treeBytes(arena, io, hit.layer.fs),
    );
    _ = linux.chmod(try arena.dupeSentinel(u8, try std.fmt.allocPrint(arena, "{s}/a/secret", .{hit.layer.fs}), 0), 0o600);
}

test "native store: a published layer is found and held; eviction keeps under the cap, never a held one" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}), .max_bytes = 0 };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    var keys: [3]Key = undefined;
    var held: [3]?Layer = .{ null, null, null };
    defer for (held) |h| if (h) |l| l.lock.close(io);
    for (&keys, 0..) |*k, i| {
        var kh: KeyHasher = .plain("test");
        kh.int(i);
        k.* = kh.final();
        try std.testing.expect(try s.open(arena, io, k.*) == null);
        const upper = try std.fmt.allocPrint(arena, "{s}/up{d}", .{ root, i });
        try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "up{d}/d", .{i}));
        try tmp.dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "up{d}/d/f", .{i}), .data = &@as([5000]u8, @splat('x')) });
        var never: std.atomic.Value(bool) = .init(false);
        const kl = try s.lockKey(arena, io, k.*, &never);
        defer kl.close(io);
        const l = try s.publish(arena, io, k.*, .step, upper, .{ .log = "the log\n", .fc = "::zig-file-command::ran\nj1\n" });
        // The upper moved in.
        try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, try std.fmt.allocPrint(arena, "up{d}", .{i}), .{}));
        held[i] = l;
        const hit = (try s.open(arena, io, k.*)).?;
        hit.layer.lock.close(io);
        try std.testing.expectEqualStrings("the log\n", hit.rec.log);
        try std.testing.expectEqualStrings("::zig-file-command::ran\nj1\n", hit.rec.fc);
    }
    // Over the cap (0), but every layer is held: nothing goes.
    s.collect(arena, io);
    for (keys) |k| {
        const h = (try s.open(arena, io, k)).?;
        h.layer.lock.close(io);
    }
    // Let the first two go: they are evicted, the held one stays, and a new open misses.
    for (held[0..2]) |*h| {
        h.*.?.lock.close(io);
        h.* = null;
    }
    s.collect(arena, io);
    try std.testing.expect(try s.open(arena, io, keys[0]) == null);
    try std.testing.expect(try s.open(arena, io, keys[1]) == null);
    const kept = (try s.open(arena, io, keys[2])).?.layer;
    kept.lock.close(io);
    // Its digest, kept once computed, is the tree's.
    const d1 = try s.layerDigest(arena, io, keys[2], .host);
    const d2 = try s.layerDigest(arena, io, keys[2], .host);
    try std.testing.expectEqualSlices(u8, &d1, &d2);
    try std.testing.expectEqualSlices(u8, &d1, &try treeDigest(arena, io, kept.fs, .content, .host));
    // The key locks of steps no longer running were dropped.
    var kd = try tmp.dir.openDir(io, "store/keys", .{ .iterate = true });
    defer kd.close(io);
    var it = kd.iterate();
    try std.testing.expect(try it.next(io) == null);
}

test "native store: a key's lock: a second taker waits, and a stop ends its wait" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = root };
    try prepare(arena, io, root, .{ .check_parents = false });
    var kh: KeyHasher = .plain("test");
    const k = kh.final();
    var never: std.atomic.Value(bool) = .init(false);
    const first = try s.lockKey(arena, io, k, &never);
    var stop: std.atomic.Value(bool) = .init(true);
    try std.testing.expectError(error.Stopped, s.lockKey(arena, io, k, &stop));
    first.close(io);
    const second = try s.lockKey(arena, io, k, &never);
    second.close(io);
}

test "native store: a key's lock: the waiting task's cancel ends its wait" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = root };
    try prepare(arena, io, root, .{ .check_parents = false });
    var kh: KeyHasher = .plain("test");
    const k = kh.final();
    var never: std.atomic.Value(bool) = .init(false);
    const first = try s.lockKey(arena, io, k, &never);
    defer first.close(io);
    // Its own arena: the waiter allocates while this thread does not.
    var wa: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer wa.deinit();
    var waiter = try io.concurrent(lockKey, .{ s, wa.allocator(), io, k, &never });
    try std.testing.expectError(error.Canceled, waiter.cancel(io));
}

test "native store: a key's preimage is P8's: tag, parent, script, then the stable env counted" {
    // P8's vector `volatile-absent` (native/testdata/step_keys.tsv on its branch): GITHUB_RUN_ID
    // is volatile, so the env counts 2.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    // `init(.step)`, with the bytes seen from the tag on.
    var k: KeyHasher = .{ .h = .init(.{}), .bytes = &w };
    k.int(@backingInt(Tag.step));
    const Binding = struct { name: []const u8, value: []const u8 };
    k.core(@splat(0), ": step 1\nmake test", &[_]Binding{
        .{ .name = "PATH", .value = "/usr/bin:/bin" },
        .{ .name = "GITHUB_RUN_ID", .value = "123" },
        .{ .name = "HOME", .value = "/root" },
    });
    const want_hex = "01000000000000002000000000000000000000000000000000000000000000000000000000000000" ++
        "000000000000000012000000000000003a207374657020310a6d616b652074657374020000000000" ++
        "00000400000000000000504154480d000000000000002f7573722f62696e3a2f62696e0400000000" ++
        "000000484f4d4505000000000000002f726f6f74";
    var want: [want_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try std.testing.expectEqualSlices(u8, &want, w.buffered());
    var plain: [32]u8 = undefined;
    Sha256.hash(&want, &plain, .{});
    try std.testing.expectEqualSlices(u8, &plain, &k.final());
}

test "native store: a digest sees ids as the job's namespace does, never the host's" {
    try std.testing.expectEqual(@as(u32, 0), (Ids{ .base = 1000, .count = 1 }).inside(1000));
    try std.testing.expectEqual(@as(u32, 65534), (Ids{ .base = 1000, .count = 1 }).inside(0));
    try std.testing.expectEqual(@as(u32, 1001), (Ids{ .base = 1_900_000_000, .count = 65536 }).inside(1_900_001_001));
    try std.testing.expectEqual(@as(u32, 65534), (Ids{ .base = 1_900_000_000, .count = 65536 }).inside(1_900_065_536));
}

test "native store: made the runner's alone, refused under a directory another user can change" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const cwd = std.Io.Dir.cwd();
    // Under /tmp (root's, sticky), not the checkout, whose directories a non-root user owns.
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const t = try std.fmt.allocPrint(arena, "/tmp/zig-runner-store-test-{s}", .{&std.fmt.bytesToHex(raw, .lower)});
    try cwd.createDirPath(io, t);
    defer cwd.deleteTree(io, t) catch {};
    _ = linux.chmod(try arena.dupeSentinel(u8, t, 0), 0o755);
    const me = linux.geteuid();
    const store = try std.fmt.allocPrint(arena, "{s}/a/store", .{t});
    const a_dir = try std.fmt.allocPrintSentinel(arena, "{s}/a", .{t}, 0);
    try cwd.createDirPath(io, store);
    _ = linux.chmod(a_dir, 0o755);
    // A store the runner made, in directories that are root's or its own: made 0700, and its own.
    _ = linux.chmod(try arena.dupeSentinel(u8, store, 0), 0o755);
    if (me == 0) _ = linux.chown(try arena.dupeSentinel(u8, store, 0), 1234, 1234);
    if (try secure(arena, io, store, .{})) |why| {
        std.debug.print("{s}\n", .{why});
        return error.TestUnexpectedResult;
    }
    var st: linux.Statx = undefined;
    _ = linux.statx(linux.AT.FDCWD, try arena.dupeSentinel(u8, store, 0), 0, .{ .UID = true, .MODE = true }, &st);
    try std.testing.expectEqual(me, st.uid);
    try std.testing.expectEqual(@as(u32, 0o700), st.mode & 0o7777);
    // A directory above it anyone can write: refused; with the sticky bit, as /tmp has: not.
    _ = linux.chmod(a_dir, 0o777);
    const why = (try secure(arena, io, store, .{})).?;
    try std.testing.expect(std.mem.indexOf(u8, why, "without the sticky bit") != null);
    _ = linux.chmod(a_dir, 0o1777);
    try std.testing.expect(try unsafeParents(arena, io, store, me) == null);
    // Reached through a symlink: the directories it resolves to are checked too.
    _ = linux.chmod(a_dir, 0o777);
    const link = try std.fmt.allocPrint(arena, "{s}/link", .{t});
    try cwd.symLink(io, "a", link, .{});
    try std.testing.expect(try unsafeParents(arena, io, try std.fmt.allocPrint(arena, "{s}/store", .{link}), me) != null);
    _ = linux.chmod(a_dir, 0o755);
    // The store itself a symlink: refused.
    try std.testing.expect(try secure(arena, io, link, .{}) != null);
    // As root: a directory above it another user owns.
    if (me == 0) {
        _ = linux.chown(a_dir, 1234, 1234);
        const other = (try unsafeParents(arena, io, store, me)).?;
        try std.testing.expect(std.mem.indexOf(u8, other, "owned by uid 1234") != null);
    }
}

test "native store: a layer shifted to canonical ids: owners, set-id bits, links, capabilities, ACLs, its digest" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    const slot: Ids = .{ .base = 1_900_131_072, .count = 65536 };
    // Capabilities: a v3's root id is a host id; the job's root's become a v2, another of its ids
    // is shifted, one outside the range drops them.
    var v3: [24]u8 = @splat(0);
    std.mem.writeInt(u32, v3[0..4], 0x03000001, .little);
    std.mem.writeInt(u32, v3[4..8], 1 << 10, .little);
    std.mem.writeInt(u32, v3[20..24], slot.base, .little);
    const as_v2 = (try unshiftCap(arena, &v3, slot)).?;
    try std.testing.expectEqual(@as(usize, 20), as_v2.len);
    try std.testing.expectEqual(@as(u32, 0x02000001), std.mem.readInt(u32, as_v2[0..4], .little));
    try std.testing.expectEqualSlices(u8, v3[4..20], as_v2[4..20]);
    std.mem.writeInt(u32, v3[20..24], slot.base + 1001, .little);
    try std.testing.expectEqual(@as(u32, 1001), std.mem.readInt(u32, (try unshiftCap(arena, &v3, slot)).?[20..24], .little));
    std.mem.writeInt(u32, v3[20..24], 0, .little);
    try std.testing.expect(try unshiftCap(arena, &v3, slot) == null);
    try std.testing.expectEqualSlices(u8, as_v2, (try unshiftCap(arena, as_v2, slot)).?);
    // ACLs: named users' and groups' ids shifted, the rest (ACL_UNDEFINED_ID) as they were.
    var acl: [4 + 3 * 8]u8 = @splat(0);
    std.mem.writeInt(u32, acl[0..4], 2, .little);
    const entries = [_][2]u32{ .{ 0x01, 0xffffffff }, .{ 0x02, slot.base + 1001 }, .{ 0x08, 7 } };
    for (entries, 0..) |e, i| {
        std.mem.writeInt(u16, acl[4 + i * 8 ..][0..2], @intCast(e[0]), .little);
        std.mem.writeInt(u32, acl[8 + i * 8 ..][0..4], e[1], .little);
    }
    unshiftAcl(&acl, slot);
    try std.testing.expectEqual(@as(u32, 0xffffffff), std.mem.readInt(u32, acl[8..12], .little));
    try std.testing.expectEqual(@as(u32, 1001), std.mem.readInt(u32, acl[16..20], .little));
    try std.testing.expectEqual(@as(u32, 65534), std.mem.readInt(u32, acl[24..28], .little));

    // A tree as a step in that slot leaves it; changing owners needs the host's root.
    if (linux.geteuid() != 0) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const setup = try std.fmt.allocPrint(arena,
        \\set -e
        \\cd '{s}' && mkdir -p up/d
        \\echo x > up/d/mine && chown {d}:{d} up/d/mine
        \\cp /bin/true up/suid && chown {d}:{d} up/suid && chmod 4755 up/suid
        \\echo y > up/stranger && chown 12345:0 up/stranger
        \\ln up/d/mine up/twice
        \\ln -s d/mine up/link && chown -h {d}:{d} up/link
        \\chown {d}:{d} up up/d && chmod 2775 up/d
    , .{
        root,
        slot.base + 1001,
        slot.base + 1001,
        slot.base,
        slot.base,
        slot.base + 1001,
        slot.base + 1001,
        slot.base,
        slot.base,
    });
    const made = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", setup } });
    try std.testing.expect(made.term == .exited and made.term.exited == 0);
    const up = try std.fmt.allocPrint(arena, "{s}/up", .{root});
    const before = try treeDigest(arena, io, up, .content, slot);
    // A v3 for the slot's root, as a step's `setcap` leaves it (its digest aside: a capability's
    // root id is a host id, digested raw).
    const suid = try std.fmt.allocPrintSentinel(arena, "{s}/suid", .{up}, 0);
    std.mem.writeInt(u32, v3[20..24], slot.base, .little);
    const capped = linux.errno(linux.lsetxattr(suid, cap_xattr, &v3, v3.len, 0)) == .SUCCESS;
    try unshift(arena, io, up, slot);
    // As the job's namespace saw them, now on disk.
    const want = [_]struct { []const u8, u32, u32 }{
        .{ "", 0, 0o755 },         .{ "d", 0, 0o2775 },    .{ "d/mine", 1001, 0o644 },
        .{ "twice", 1001, 0o644 }, .{ "suid", 0, 0o4755 }, .{ "stranger", 65534, 0o644 },
        .{ "link", 1001, 0o777 },
    };
    for (want) |w| {
        const p = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ up, w[0] }, 0);
        var st: linux.Statx = undefined;
        try std.testing.expectEqual(@as(usize, 0), linux.statx(linux.AT.FDCWD, p, linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .MODE = true }, &st));
        std.testing.expectEqual(w[1], st.uid) catch |e| {
            std.debug.print("{s}: uid {d}\n", .{ w[0], st.uid });
            return e;
        };
        if (st.mode & linux.S.IFMT != linux.S.IFLNK) try std.testing.expectEqual(w[2], st.mode & 0o7777);
    }
    if (capped) {
        var got: [64]u8 = undefined;
        const n = linux.lgetxattr(suid, cap_xattr, &got, got.len);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(n));
        try std.testing.expectEqualSlices(u8, as_v2, got[0..n]);
        _ = linux.lremovexattr(suid, cap_xattr);
    }
    // Its digest: the same tree as the namespace sees it, whichever ids it has on disk.
    const after = try treeDigest(arena, io, up, .content, .{ .base = 0, .count = 65536 });
    try std.testing.expectEqualSlices(u8, &before, &after);
}

test "native store: the rootfs's fingerprint changes when the rootfs is changed in place" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "rootfs/usr/bin");
    try tmp.dir.writeFile(io, .{ .sub_path = "rootfs/usr/bin/tool", .data = "v1" });
    const rootfs = try tmp.dir.realPathFileAlloc(io, "rootfs", arena);
    const first = try rootfsFingerprint(arena, io, rootfs, "");
    try std.testing.expectEqualSlices(u8, &first, &try rootfsFingerprint(arena, io, rootfs, ""));
    // Provisioned again in place, as `tar -x` over it does: same size, mtime set back. The ctime
    // moved, but only a new walk sees it; the stamp, touched after, makes the next job walk.
    try tmp.dir.writeFile(io, .{ .sub_path = "rootfs/usr/bin/tool", .data = "v2" });
    const tool = try std.fmt.allocPrintSentinel(arena, "{s}/usr/bin/tool", .{rootfs}, 0);
    const t = [2]linux.timespec{ .{ .sec = 1, .nsec = 0 }, .{ .sec = 1, .nsec = 0 } };
    _ = linux.utimensat(linux.AT.FDCWD, tool, &t, 0);
    try tmp.dir.writeFile(io, .{ .sub_path = "rootfs/" ++ rootfs_stamp, .data = "" });
    const second = try rootfsFingerprint(arena, io, rootfs, "");
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    // A walk sees an in-place change by its ctime even with the stamp untouched, as at a
    // restart, when nothing is kept.
    _ = linux.utimensat(linux.AT.FDCWD, tool, &t, 0);
    fp_len = 0;
    const third = try rootfsFingerprint(arena, io, rootfs, "");
    try std.testing.expect(!std.mem.eql(u8, &second, &third));
}

test "native store: a record that cannot be replayed is refused, and a broken entry is evicted" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    try tmp.dir.createDirPath(io, "up");
    const upper = try std.fmt.allocPrint(arena, "{s}/up", .{root});
    var kh: KeyHasher = .plain("test");
    const k = kh.final();
    const ran = "::zig-file-command::ran\nj1\n";
    // Refused without the key's lock, which `collect` would take for a dead publisher's.
    try std.testing.expectError(error.KeyNotLocked, s.publish(arena, io, k, .base, upper, .{ .log = "", .fc = "" }));
    try tmp.dir.access(io, "up", .{});
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, k, &never);
    defer kl.close(io);
    // Refused, and the upper left where it was: a step's file commands without their ran marker
    // or empty, a base's with any, and file commands past the limit.
    const big = try arena.alloc(u8, max_record_bytes + 1);
    @memset(big, 'x');
    const refused = [_]struct { Kind, Record }{
        .{ .step, .{ .log = "", .fc = "::zig-file-command::env 4\nA=1\n\n" } },
        .{ .step, .{ .log = "", .fc = "" } },
        .{ .base, .{ .log = "", .fc = ran } },
        .{ .step, .{ .log = "", .fc = big } },
    };
    for (refused) |r| {
        try std.testing.expect(std.meta.isError(s.publish(arena, io, k, r[0], upper, r[1])));
        try tmp.dir.access(io, "up", .{});
    }
    // A base's empty record is whole.
    const base = try s.publish(arena, io, k, .base, upper, .{ .log = "", .fc = "" });
    base.lock.close(io);
    (try s.open(arena, io, k)).?.layer.lock.close(io);

    // A step's entry whose log was cut short afterwards: a miss, and evicted, so it can be
    // published again.
    var kh2: KeyHasher = .plain("test 2");
    const k2 = kh2.final();
    const kl2 = try s.lockKey(arena, io, k2, &never);
    defer kl2.close(io);
    try tmp.dir.createDirPath(io, "up2");
    const up2 = try std.fmt.allocPrint(arena, "{s}/up2", .{root});
    const l = try s.publish(arena, io, k2, .step, up2, .{ .log = "a whole log\n", .fc = ran });
    l.lock.close(io);
    const log_path = try std.fmt.allocPrint(arena, "store/layers/{s}/log", .{&hex(k2)});
    try tmp.dir.writeFile(io, .{ .sub_path = log_path, .data = "a who" });
    try std.testing.expect(try s.open(arena, io, k2) == null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, log_path, .{}));
    // `collect` removes one too, by its lengths, without reading it.
    try tmp.dir.createDirPath(io, "up3");
    const up3 = try std.fmt.allocPrint(arena, "{s}/up3", .{root});
    (try s.publish(arena, io, k2, .step, up3, .{ .log = "a whole log\n", .fc = ran })).lock.close(io);
    try tmp.dir.writeFile(io, .{ .sub_path = log_path, .data = "a who" });
    s.collect(arena, io);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, log_path, .{}));
}

test "native store: an eviction whose entry went meanwhile leaves the one published since" {
    // The counterexample of proofs/tla/StoreLocking.tla: `collect` opened an entry's lock file to
    // evict it; another runner, finding the entry broken, evicted it first, and a job published the
    // key again and held it; `collect`'s LOCK_EX on the old, unlinked lock file succeeded, and its
    // rename by name took the new entry from under the job.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    var kh: KeyHasher = .plain("test");
    const k = kh.final();
    // Each publish under the key's lock, as `publish` requires.
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, k, &never);
    defer kl.close(io);
    try tmp.dir.createDirPath(io, "up1");
    const up1 = try std.fmt.allocPrint(arena, "{s}/up1", .{root});
    (try s.publish(arena, io, k, .base, up1, .{ .log = "", .fc = "" })).lock.close(io);
    const lock_path = try std.fmt.allocPrint(arena, "{s}/layers/{s}/lock", .{ s.root, &hex(k) });
    // `collect`'s eviction has the first entry's lock file open.
    const stale = try std.Io.Dir.cwd().openFile(io, lock_path, .{});
    defer stale.close(io);
    // Another runner evicts it, and a job publishes the key again and holds it until it ends.
    try std.testing.expect(s.evict(arena, io, &hex(k)));
    try tmp.dir.createDirPath(io, "up2");
    const up2 = try std.fmt.allocPrint(arena, "{s}/up2", .{root});
    const held = try s.publish(arena, io, k, .base, up2, .{ .log = "", .fc = "" });
    defer held.lock.close(io);
    // The old lock file is unlinked and free: the eviction must not take the new entry.
    try std.testing.expect(!s.evictOpened(arena, io, &hex(k), stale));
    try std.Io.Dir.cwd().access(io, held.fs, .{});
    const hit = (try s.open(arena, io, k)).?;
    hit.layer.lock.close(io);
}

test "native store: a tree's walk has no depth limit, and fails closed on what it cannot read" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // 300 levels, past the old limit of 256, with a file at the bottom and the deepest
    // directories taken every permission from.
    var rel: std.ArrayList(u8) = .empty;
    try rel.appendSlice(arena, "deep");
    for (0..300) |_| try rel.appendSlice(arena, "/d");
    try tmp.dir.createDirPath(io, rel.items);
    try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{rel.items}),
        .data = &@as([8192]u8, @splat('x')),
    });
    const deep = try tmp.dir.realPathFileAlloc(io, "deep", arena);
    try std.testing.expect(try treeBytes(arena, io, deep) >= 8192);
    // Rootless, a directory it cannot open fails the count (root reads it anyway).
    const bottom = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{
        try tmp.dir.realPathFileAlloc(io, ".", arena),
        rel.items,
    }, 0);
    _ = linux.chmod(bottom, 0);
    if (linux.geteuid() != 0) try std.testing.expect(std.meta.isError(treeBytes(arena, io, deep)));
    // Removed whole all the same.
    removeTree(arena, io, deep);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "deep", .{}));
}

/// A store under `tmp`, and a step's layer published in it under `key` (held: the caller closes
/// it), with a 5000-byte file in its tree.
fn testLayer(arena: Allocator, io: std.Io, tmp: std.testing.TmpDir, s: *Store, name: []const u8) !struct { Key, Layer } {
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    if (s.root.len == 0) {
        s.root = try std.fmt.allocPrint(arena, "{s}/store", .{root});
        try prepare(arena, io, s.root, .{ .check_parents = false });
    }
    var kh: KeyHasher = .plain(name);
    const k = kh.final();
    try tmp.dir.createDirPath(io, name);
    try tmp.dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/f", .{name}), .data = &@as([5000]u8, @splat('x')) });
    const upper = try std.fmt.allocPrint(arena, "{s}/{s}", .{ root, name });
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, k, &never);
    defer kl.close(io);
    const l = try s.publish(arena, io, k, .step, upper, .{ .log = "a log\n", .fc = "::zig-file-command::ran\nj1\n" });
    return .{ k, l };
}

test "native store: collect keeps a whole layer no job holds while the store is at or under its cap" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    const k, const l = try testLayer(arena, io, tmp, &s, "up");
    const bytes = accounted(try metaOf(arena, io, std.fs.path.dirname(l.fs).?));
    l.lock.close(io);
    // Exactly at the cap: nothing goes.
    s.max_bytes = bytes;
    s.collect(arena, io);
    (try s.open(arena, io, k)).?.layer.lock.close(io);
    // A byte under it: the layer goes, since no job holds it.
    s.max_bytes = bytes - 1;
    s.collect(arena, io);
    try std.testing.expect(try s.open(arena, io, k) == null);
}

test "native store: over its cap, collect evicts the least recently used layers until it fits, no more" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    var keys: [3]Key = undefined;
    var bytes: u64 = 0;
    for (&keys, [_][]const u8{ "up0", "up1", "up2" }) |*k, name| {
        k.*, const l = try testLayer(arena, io, tmp, &s, name);
        bytes = accounted(try metaOf(arena, io, std.fs.path.dirname(l.fs).?));
        l.lock.close(io);
    }
    // Used in the order 1, 0, 2 (an open is a use): room for two, so 1 goes, and only 1.
    for ([_]usize{ 1, 0, 2 }) |i| {
        (try s.open(arena, io, keys[i])).?.layer.lock.close(io);
        io.sleep(.fromMilliseconds(20), .awake) catch {};
    }
    s.max_bytes = 2 * bytes;
    s.collect(arena, io);
    try std.testing.expect(try s.open(arena, io, keys[1]) == null);
    (try s.open(arena, io, keys[0])).?.layer.lock.close(io);
    (try s.open(arena, io, keys[2])).?.layer.lock.close(io);
}

test "native eviction: over its cap, a chain loses its newest layer first, and the floor still frees all" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    // A job's chain, base to leaf, each held until its end as `Backend.chain` does.
    var keys: [3]Key = undefined;
    var locks: [3]std.Io.File = undefined;
    var bytes: u64 = 0;
    for (&keys, &locks, [_][]const u8{ "base", "mid", "leaf" }) |*k, *lock, name| {
        k.*, const l = try testLayer(arena, io, tmp, &s, name);
        lock.* = l.lock;
        bytes = accounted(try metaOf(arena, io, std.fs.path.dirname(l.fs).?));
        io.sleep(.fromMilliseconds(20), .awake) catch {};
    }
    // As published, the ancestors are the least recently used, and would go first.
    touchChain(io, &locks);
    for (locks) |l| l.close(io);
    // Room for two: the leaf goes, not the base or the layer between. A leaf is a diff over its
    // parents, so a parent kept without the leaf still serves every job up to the leaf's step.
    s.max_bytes = 2 * bytes;
    s.collect(arena, io);
    try std.testing.expect(try s.open(arena, io, keys[2]) == null);
    (try s.open(arena, io, keys[0])).?.layer.lock.close(io);
    (try s.open(arena, io, keys[1])).?.layer.lock.close(io);
    // The order is no shield: past the cap it goes on, ancestors and all, to nothing.
    s.max_bytes = 0;
    s.collect(arena, io);
    for (keys[0..2]) |k| try std.testing.expect(try s.open(arena, io, k) == null);
}

test "native store: a layer counts its record and its own files, not only its tree" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    const k, const l = try testLayer(arena, io, tmp, &s, "up");
    const tree = try treeBytes(arena, io, l.fs);
    l.lock.close(io);
    s.max_bytes = tree + entry_overhead;
    s.collect(arena, io);
    try std.testing.expect(try s.open(arena, io, k) == null);
}

test "native store: under the disk's floor a layer goes though the store is under its cap, not one just used" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    const old, const l0 = try testLayer(arena, io, tmp, &s, "up0");
    const lock = try arena.dupeSentinel(u8, try join(arena, std.fs.path.dirname(l0.fs).?, "lock"), 0);
    l0.lock.close(io);
    const new, const l1 = try testLayer(arena, io, tmp, &s, "up1");
    l1.lock.close(io);
    const t = [2]linux.timespec{ .{ .sec = 1, .nsec = 0 }, .{ .sec = 1, .nsec = 0 } };
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.utimensat(linux.AT.FDCWD, lock, &t, 0)));
    // A floor no disk meets.
    s.limits.min_free_pct = 100;
    s.collect(arena, io);
    try std.testing.expect(try s.open(arena, io, old) == null);
    (try s.open(arena, io, new)).?.layer.lock.close(io);
}

test "native store: under the disk's floor a pass takes what its budget allows of the layers" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    const t = [2]linux.timespec{ .{ .sec = 1, .nsec = 0 }, .{ .sec = 1, .nsec = 0 } };
    for (0..20) |i| {
        _, const l = try testLayer(arena, io, tmp, &s, try std.fmt.allocPrint(arena, "up{d}", .{i}));
        const lock = try arena.dupeSentinel(u8, try join(arena, std.fs.path.dirname(l.fs).?, "lock"), 0);
        try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.utimensat(linux.AT.FDCWD, lock, &t, 0)));
        l.lock.close(io);
    }
    s.limits.min_free_pct = 100;
    s.limits.budget_ms = 0;
    s.collect(arena, io);
    var left: usize = 0;
    var d = try std.Io.Dir.cwd().openDir(io, try join(arena, s.root, "layers"), .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    while (try it.next(io)) |_| left += 1;
    try std.testing.expectEqual(@as(usize, 19), left);
}

test "native store: a key published already stays, and the second upper is put back where it was" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    const k, const l = try testLayer(arena, io, tmp, &s, "up");
    l.lock.close(io);
    try tmp.dir.createDirPath(io, "again");
    try tmp.dir.writeFile(io, .{ .sub_path = "again/g", .data = "second" });
    const again = try std.fmt.allocPrint(arena, "{s}/again", .{try tmp.dir.realPathFileAlloc(io, ".", arena)});
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, k, &never);
    defer kl.close(io);
    try std.testing.expectError(error.Publish, s.publish(arena, io, k, .step, again, .{ .log = "b\n", .fc = "::zig-file-command::ran\nj2\n" }));
    // The upper is back, whole, and nothing of the attempt is left in the store.
    try tmp.dir.access(io, "again/g", .{});
    var layers = try tmp.dir.openDir(io, "store/layers", .{ .iterate = true });
    defer layers.close(io);
    var it = layers.iterate();
    var n: usize = 0;
    while (try it.next(io)) |e| : (n += 1) try std.testing.expectEqualStrings(&hex(k), e.name);
    try std.testing.expectEqual(@as(usize, 1), n);
    // The first layer is the one replayed.
    const hit = (try s.open(arena, io, k)).?;
    hit.layer.lock.close(io);
    try std.testing.expectEqualStrings("a log\n", hit.rec.log);
    // An upper that cannot be read fails before it moves: its temporary entry is removed.
    var other: KeyHasher = .plain("other");
    const missing = try std.fmt.allocPrint(arena, "{s}/missing", .{s.root});
    const k_other = other.final();
    const ol = try s.lockKey(arena, io, k_other, &never);
    defer ol.close(io);
    try std.testing.expect(std.meta.isError(s.publish(arena, io, k_other, .step, missing, .{ .log = "", .fc = "::zig-file-command::ran\n" })));
    var after = try tmp.dir.openDir(io, "store/layers", .{ .iterate = true });
    defer after.close(io);
    var it2 = after.iterate();
    n = 0;
    while (try it2.next(io)) |_| n += 1;
    try std.testing.expectEqual(@as(usize, 1), n);
}

test "native store: a key's tag is part of its preimage, output-keyed's as 2" {
    var buf: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var k: KeyHasher = .{ .h = .init(.{}), .bytes = &w };
    k.int(@backingInt(Tag.output_keyed));
    try std.testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 0, 0, 0, 0 }, w.buffered());
    var base: KeyHasher = .init(.base);
    var step: KeyHasher = .init(.step);
    var keyed: KeyHasher = .init(.output_keyed);
    const kb = base.final();
    const ks = step.final();
    const kk = keyed.final();
    try std.testing.expect(!std.mem.eql(u8, &kb, &ks) and !std.mem.eql(u8, &ks, &kk) and !std.mem.eql(u8, &kb, &kk));
}

test "native store: a step's log past the limit, or a base's file commands, are not published" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    try tmp.dir.createDirPath(io, "up");
    const upper = try std.fmt.allocPrint(arena, "{s}/up", .{root});
    var kh: KeyHasher = .plain("test");
    const k = kh.final();
    const big = try arena.alloc(u8, max_record_bytes + 1);
    @memset(big, 'x');
    const ran = "::zig-file-command::ran\nj1\n";
    var never: std.atomic.Value(bool) = .init(false);
    const kl = try s.lockKey(arena, io, k, &never);
    try std.testing.expectError(error.RecordTooLarge, s.publish(arena, io, k, .step, upper, .{ .log = big, .fc = ran }));
    try std.testing.expectError(error.ShortRecord, s.publish(arena, io, k, .base, upper, .{ .log = "", .fc = "x" }));
    try std.testing.expectError(error.ShortRecord, s.publish(arena, io, k, .fetch, upper, .{ .log = "", .fc = "x" }));
    try tmp.dir.access(io, "up", .{});
    // At the limit, both are: and a base, whose record is empty, is kept by `collect` too.
    const fc = try arena.alloc(u8, max_record_bytes);
    @memset(fc, 'x');
    @memcpy(fc[0..ran.len], ran);
    (try s.publish(arena, io, k, .step, upper, .{ .log = big[0..max_record_bytes], .fc = fc })).lock.close(io);
    kl.close(io);
    (try s.open(arena, io, k)).?.layer.lock.close(io);
    try tmp.dir.createDirPath(io, "base");
    var kb: KeyHasher = .plain("base");
    const k_base = kb.final();
    const base_up = try std.fmt.allocPrint(arena, "{s}/base", .{root});
    const bl = try s.lockKey(arena, io, k_base, &never);
    (try s.publish(arena, io, k_base, .base, base_up, .{ .log = "", .fc = "" })).lock.close(io);
    bl.close(io);
    s.collect(arena, io);
    (try s.open(arena, io, k_base)).?.layer.lock.close(io);
    (try s.open(arena, io, k)).?.layer.lock.close(io);
}

test "native store: a layer whose file commands or tree changed is not replayed" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s: Store = .{ .root = "" };
    // The file commands changed in place, their length kept: a miss, and evicted.
    const k, const l = try testLayer(arena, io, tmp, &s, "up");
    l.lock.close(io);
    const fc = try std.fmt.allocPrint(arena, "store/layers/{s}/fc", .{&hex(k)});
    try tmp.dir.writeFile(io, .{ .sub_path = fc, .data = "::zig-file-command::ran\nj2\n" });
    try std.testing.expect(try s.open(arena, io, k) == null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, fc, .{}));
    // The log, likewise.
    const k3, const l3 = try testLayer(arena, io, tmp, &s, "up3");
    l3.lock.close(io);
    const log = try std.fmt.allocPrint(arena, "store/layers/{s}/log", .{&hex(k3)});
    try tmp.dir.writeFile(io, .{ .sub_path = log, .data = "A log\n" });
    try std.testing.expect(try s.open(arena, io, k3) == null);
    // Its tree gone: a miss for `open`.
    const k4, const l4 = try testLayer(arena, io, tmp, &s, "up4");
    l4.lock.close(io);
    removeTree(arena, io, l4.fs);
    try std.testing.expect(try s.open(arena, io, k4) == null);
    // And `collect`, which reads no record, removes it too.
    const k2, const l2 = try testLayer(arena, io, tmp, &s, "up2");
    l2.lock.close(io);
    removeTree(arena, io, l2.fs);
    s.collect(arena, io);
    const dir2 = try std.fmt.allocPrint(arena, "store/layers/{s}", .{&hex(k2)});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, dir2, .{}));
}

test "native store: collect removes a half-built layer whose publisher died, not one still building" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const s: Store = .{ .root = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    try prepare(arena, io, s.root, .{ .check_parents = false });
    var building: KeyHasher = .plain("building");
    var dead: KeyHasher = .plain("dead");
    const kb = building.final();
    const kd = dead.final();
    // A publisher holds its key's lock while it builds `.tmp-KEY-RANDOM`.
    var never: std.atomic.Value(bool) = .init(false);
    const held = try s.lockKey(arena, io, kb, &never);
    defer held.close(io);
    const tmp_b = try std.fmt.allocPrint(arena, "store/layers/.tmp-{s}-0123456789abcdef", .{&hex(kb)});
    const tmp_d = try std.fmt.allocPrint(arena, "store/layers/.tmp-{s}-0123456789abcdef", .{&hex(kd)});
    try tmp.dir.createDirPath(io, tmp_b);
    try tmp.dir.createDirPath(io, tmp_d);
    s.collect(arena, io);
    try tmp.dir.access(io, tmp_b, .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, tmp_d, .{}));
}

test "native store: sameFile tells the file a path names from another on the same disk" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.writeFile(io, .{ .sub_path = "one", .data = "1" });
    try tmp.dir.writeFile(io, .{ .sub_path = "two", .data = "2" });
    const f = try tmp.dir.openFile(io, "one", .{});
    defer f.close(io);
    const one = try std.fmt.allocPrint(arena, "{s}/one", .{root});
    try std.testing.expect(sameFile(arena, f, one));
    try std.testing.expect(!sameFile(arena, f, try std.fmt.allocPrint(arena, "{s}/two", .{root})));
    try std.testing.expect(!sameFile(arena, f, try std.fmt.allocPrint(arena, "{s}/none", .{root})));
    // Replaced under the same name, as an eviction leaves it: no longer the file held.
    try tmp.dir.deleteFile(io, "one");
    try tmp.dir.writeFile(io, .{ .sub_path = "one", .data = "1" });
    try std.testing.expect(!sameFile(arena, f, one));
}
