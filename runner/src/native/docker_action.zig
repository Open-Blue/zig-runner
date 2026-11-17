//! Docker actions on the native backend (docs/native-backend.md, P7): a `docker://` step runs in
//! its image's filesystem (`images.zig`) as a sandbox of its own (`sandbox.Spec.Container`), with
//! the job's workspace and its file-command, home and workflow directories bound in at the paths
//! GitHub binds them (`shares`), its command started as `docker run` starts it.
//!
//! Everything about what the action gets is the Dagger path's, shared (`dagger/docker.zig`): its
//! argv (`Exec.containerArgv`), its env (`Exec.containerEnv`), the step's log group, the file
//! commands applied (`Exec.collect`). What differs is how it runs. Dagger copies the workspace
//! into the container and back, and starts the command under a static busybox that writes the
//! step's markers and file commands (`containerScript`), since the image may have no shell. Here
//! the workspace is bound, as GitHub's `docker run -v` binds it, so what the action writes lands in
//! the job's next layer without a copy; and the runner itself does the script's part: the markers
//! around the output, the file-command files made before and combined after. No shell or busybox
//! enters the image.

const std = @import("std");
const job_mod = @import("../job.zig");
const dagger = @import("../dagger.zig");
const Backend = @import("Backend.zig");
const build_env = @import("build_env.zig");
const build_frames = @import("build_frames.zig");
const planner = @import("planner.zig");
const Env = build_env.Env;
const sandbox = @import("sandbox.zig");
const images = @import("images.zig");
const expr = @import("../expr.zig");
const Exec = @import("../dagger/Exec.zig");
const SpanDemux = @import("../dagger/JobLog.zig").SpanDemux;
const scripts = @import("../dagger/scripts.zig");
const dockerfile = @import("dockerfile.zig");
const Store = @import("Store.zig");
const layers = @import("layers.zig");
const layer_view = @import("layer_view.zig");
const net_client = @import("../net_client.zig");
const Sha256 = @import("../sha256.zig").Sha256;

const Allocator = std.mem.Allocator;

/// Where GitHub binds a Docker action's directories (`ContainerActionHandler.cs`): the workspace,
/// and the home, workflow and file-command directories, which every Docker action of the job
/// shares. In the job's overlay the last three are at the same paths: the file commands and the
/// event are where the job's `run:` steps have them, and /github/home is kept for the next
/// Docker action as GitHub keeps `_github_home`.
fn shares(arena: Allocator, workspace: []const u8) ![]const sandbox.Spec.Container.Share {
    return arena.dupe(sandbox.Spec.Container.Share, &.{
        .{ .from = workspace, .at = dagger.docker_workspace },
        .{ .from = dagger.docker_home, .at = dagger.docker_home },
        .{ .from = scripts.fc_dir, .at = scripts.fc_dir },
        .{ .from = dagger.event_dir, .at = dagger.event_dir },
    });
}

/// Who a Docker action's image runs as, resolved as Docker resolves its `USER`.
pub const ImageUser = struct { uid: u32, gid: u32, groups: []const u32 };

/// `path` in an image's layers, `lowers` top first: the first layer that has it, "" when none
/// does or one deletes it. The image's own links are followed, inside it.
fn textInLayers(arena: Allocator, lowers: []const []const u8, path: []const u8) []const u8 {
    for (lowers) |layer| switch (sandbox.readFollowingIn(arena, layer, path, 4 << 20) catch return "") {
        .text => |t| return t,
        .whiteout => return "",
        .missing => {},
    };
    return "";
}

/// The image's `USER` (`user`, not root: `images.runsAsRoot`) as ids the job reaches, from the
/// image's /etc/passwd and /etc/group (a name there, or a number; `images.userIds`), or why it
/// cannot be: a name the image does not have (`docker run` refuses it as well), or ids past the
/// job's range, which only root outside could give (`Backend.ids_per_slot`).
pub fn resolveUser(arena: Allocator, lowers: []const []const u8, user: []const u8) !union(enum) {
    ok: ImageUser,
    refused: []const u8,
} {
    const passwd = textInLayers(arena, lowers, "/etc/passwd");
    const group = textInLayers(arena, lowers, "/etc/group");
    const ids = images.userIds(user, passwd, group) orelse return .{ .refused = try std.fmt.allocPrint(
        arena,
        "the image's USER {s} is not in its /etc/passwd or /etc/group",
        .{user},
    ) };
    if (ids.uid >= Backend.ids_per_slot or ids.gid >= Backend.ids_per_slot) return .{
        .refused = try std.fmt.allocPrint(arena, "the image's USER {s} is uid {d} and gid {d}, " ++
            "and a job has the ids below {d} only", .{ user, ids.uid, ids.gid, Backend.ids_per_slot }),
    };
    return .{ .ok = .{
        .uid = ids.uid,
        .gid = ids.gid,
        .groups = try Backend.mappedGroups(arena, try images.supplementaryGroups(arena, passwd, group, user)),
    } };
}

/// Who an image run as `user` runs as, or why it cannot be run natively: root always can; another
/// user only on a root runner (the shares are idmapped, `sandbox.Spec.Container.owner`), and one
/// the image has. Resolved once, so what is checked is what is used.
pub fn userCheck(arena: Allocator, lowers: []const []const u8, ref: []const u8, user: []const u8) !union(enum) {
    root,
    ok: ImageUser,
    refused: []const u8,
} {
    if (images.runsAsRoot(user)) return .root;
    if (std.os.linux.geteuid() != 0) return .{ .refused = try std.fmt.allocPrint(arena, "the image " ++
        "{s} runs as USER {s}, and a rootless runner's Docker actions run as root only", .{ ref, user }) };
    return switch (try resolveUser(arena, lowers, user)) {
        .ok => |u| .{ .ok = u },
        .refused => |why| .{ .refused = try std.fmt.allocPrint(arena, "{s}: {s}", .{ ref, why }) },
    };
}

test "userCheck resolves the user once: root is root, and a name the image lacks is refused" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    try std.testing.expect((try userCheck(arena, &.{}, "img", "")) == .root);
    try std.testing.expect((try userCheck(arena, &.{}, "img", "root")) == .root);
    // Rootless: refused for the runner; as root: for the image having no such user. Never `.ok`.
    try std.testing.expect((try userCheck(arena, &.{}, "img", "nobody-here")) == .refused);
    try std.testing.expect((try userReason(arena, &.{}, "img", "nobody-here")) != null);
}

/// Why an image run as `user` cannot be run natively, or null (`userCheck`).
pub fn userReason(arena: Allocator, lowers: []const []const u8, ref: []const u8, user: []const u8) !?[]const u8 {
    return switch (try userCheck(arena, lowers, ref, user)) {
        .root, .ok => null,
        .refused => |why| why,
    };
}

/// Why a job's Docker actions cannot run natively yet, or null: each `docker://` step's image
/// must be pulled natively (P3, `find`) and its `USER` one the job's ids reach (`userReason`).
/// `Backend.unsupported` leaves these steps to this, since it needs the image's config.
pub fn unsupported(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    job: job_mod.Job,
    cfg: Backend.Config,
) !?[]const u8 {
    for (job.steps) |step| {
        const d = switch (step.action) {
            .docker => |d| d,
            else => continue,
        };
        // A step that never runs (`if: false`) pulls nothing: a failed pull would send the whole
        // job to Dagger for an image no step uses (#351). A step that may run is pulled, as a
        // pull that fails is Dagger's to try, and the job cannot start natively without it.
        if (try expr.neverTrue(arena, step.condition)) continue;
        switch (try find(arena, gpa, io, cfg.images, cfg.store, d.image, cfg.image_tag_ttl_s, null)) {
            .missing => |why| return why,
            // GitHub's documentation asks for root ("Docker actions must be run by the default
            // Docker user"); Dagger's path gives another USER the directories it writes, which
            // here are idmapped shares of the workspace.
            .image => |img| if (try userReason(arena, &.{img.rootfs}, d.image, img.user)) |why|
                return why,
        }
    }
    return null;
}

/// `ref`'s image: pulled natively into the store at `store` (P3, `Backend.pullAt`), or from the
/// tests' directory when `dir` is set (`images.lookup`). A pull that fails is `missing`, with why.
/// `held` is the job's list of locks (`Backend.held`), which keeps the image from eviction until
/// the job ends; null when no job will use it.
pub fn find(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    dir: []const u8,
    store: []const u8,
    ref: []const u8,
    tag_ttl_s: u32,
    held: ?*std.ArrayList(std.Io.File),
) !images.Found {
    if (dir.len > 0) return images.lookup(arena, io, dir, ref);
    var why: []const u8 = "";
    const owners = std.os.linux.geteuid() == 0;
    const img = Backend.pullAt(arena, gpa, io, store, owners, ref, null, tag_ttl_s, &why) catch |e|
        return .{ .missing = try std.fmt.allocPrint(arena, "the image {s} could not be pulled " ++
            "natively: {s}", .{ ref, if (why.len > 0) why else @errorName(e) }) };
    if (held) |h| h.append(arena, img.lock) catch |e| {
        img.lock.close(io);
        return e;
    } else img.lock.close(io);
    return .{ .image = images.fromPulled(arena, io, img.rootfs, img.digest, img.manifest) catch
        return .{ .missing = try std.fmt.allocPrint(arena, "the image {s} has a config the " ++
            "runner cannot read", .{ref}) } };
}

/// `Exec.runContainer` on the native backend: the action's command run as step `num` in its
/// image, its output streamed into the step's log, its file commands applied. Null when it
/// cannot run (the step failed and logged); `error.EngineFailed` with `x.err_msg` when the
/// sandbox failed or the step was stopped.
pub fn run(
    b: *Backend,
    x: *Exec,
    num: u32,
    dr: Exec.DockerRun,
    state: []const job_mod.EnvVar,
) !?Exec.Out {
    const arena = b.arena;
    var img_lowers: []const []const u8 = &.{};
    const ref, const img = switch (dr.image) {
        .pull => |r| .{ r, switch (try find(arena, b.gpa, b.io, b.images_dir, b.store_cfg.root, r, b.image_tag_ttl_s, &b.held)) {
            .image => |i| i,
            .missing => |why| {
                _ = try x.actionFailed(num, "could not pull {s} for {s}: {s}", .{ r, dr.label, why });
                return null;
            },
        } },
        .build => |bd| switch (try buildImage(b, bd)) {
            .image => |built| blk: {
                img_lowers = built.lowers;
                break :blk .{ bd.dockerfile, built.config };
            },
            .failed => |why| {
                _ = try x.actionFailed(num, "could not build {s} of {s}: {s}", .{
                    bd.dockerfile,
                    dr.label,
                    why,
                });
                return null;
            },
        },
    };
    if (img_lowers.len == 0) img_lowers = try arena.dupe([]const u8, &.{img.rootfs});
    // Another USER than root: the shares are theirs for the step (`sandbox.Spec.Container.owner`).
    var step_user: ImageUser = .{ .uid = 0, .gid = 0, .groups = &.{} };
    var owner: ?sandbox.Spec.Container.Owner = null;
    if (!images.runsAsRoot(img.user)) {
        switch (try userCheck(arena, img_lowers, ref, img.user)) {
            .refused => |w| {
                _ = try x.actionFailed(num, "{s}: {s}", .{ dr.label, w });
                return null;
            },
            .ok => |u| step_user = u,
            .root => {},
        }
        if (b.how.userns != .mapped) {
            _ = try x.actionFailed(num, "{s}: a rootless runner's Docker actions run as root " ++
                "only", .{dr.label});
            return null;
        }
        owner = .{
            .uid = step_user.uid,
            .gid = step_user.gid,
            .groups = step_user.groups,
            .job_uid = b.uid,
            .job_gid = b.gid,
        };
    }
    const info: Exec.ImageInfo = .{
        .id = ref,
        .entrypoint = img.entrypoint,
        .cmd = img.cmd,
        .user = img.user,
    };
    const argv = (try x.containerArgv(num, dr, info)) orelse return null;
    const fc = x.next_fc;
    x.next_fc += 1;
    const env = try processEnv(arena, x, dr, img, state, fc);

    // The file commands made empty, and the event payload, in the job's overlay under the
    // directories the container shares: what Dagger's `withDirectory` and `withNewFile` give it.
    var files: std.ArrayList(sandbox.Spec.File) = .empty;
    for (scripts.fc_kinds) |k| try files.append(arena, .{
        .path = try scripts.fcPath(arena, k, fc),
        .contents = "",
        .mode = 0o644,
        .keep = true,
        .own = true,
    });
    try files.append(arena, .{
        .path = dagger.event_path,
        .contents = try x.ev.eventJson(),
        .mode = 0o644,
        .keep = true,
        .own = true,
    });

    // The container's own layer goes when the step ends; what it shares is the job's.
    const upper = try std.fmt.allocPrint(arena, "CU{d}", .{fc});
    const upper_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, upper });
    const cwd = std.Io.Dir.cwd();
    for ([_][]const u8{ upper, "CW", "C" }) |d|
        try cwd.createDirPath(b.io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, d }));
    defer Backend.removeTree(arena, b.io, upper_path);
    if (b.how.userns == .mapped) {
        const p = try arena.dupeSentinel(u8, upper_path, 0);
        _ = std.os.linux.chown(p, b.idBase(), b.idBase());
        _ = std.os.linux.chmod(p, 0o755);
    }

    // The step's env after the job's: the last value of a variable decides (`runContainer`).
    x.sh.beginCommands(num, try dagger.envContext(arena, x.ev.job_env.items, dr.step_env));
    x.beginExec(num);
    var demux: SpanDemux = .{ .sh = x.sh, .gpa = b.gpa };
    defer demux.deinit();
    var live: Backend.Live = .{ .demux = &demux, .arena = arena, .record = null };
    const out = live.output();
    // The markers the script would echo (`scripts.writeMarkerEcho`), around the output.
    out.chunkFn(out.ptr, try markerLine(arena, "begin", num, x.sh.mark));
    // It starts in the workspace, as `docker run --workdir /github/workspace`.
    const workdir = b.workdir;
    b.workdir = dagger.docker_workspace;
    defer b.workdir = workdir;
    const ended = try b.execOn(argv, env, files.items, step_user.uid, step_user.gid, out, .{
        .lowers = img_lowers,
        .upper = upper,
        .work = "CW",
        .merged = "C",
        .shares = try shares(arena, x.ev.workspace),
        .owner = owner,
    });
    demux.flushPartial();
    out.chunkFn(out.ptr, try markerLine(arena, "end", num, x.sh.mark));
    x.sh.ended[num - 1].store(true, .release);
    x.sh.flush();
    if (ended.failure.len > 0) {
        x.err_msg = ended.failure;
        return error.EngineFailed;
    }
    if (ended.killed) {
        x.err_msg = "the step was stopped";
        return error.EngineFailed;
    }

    const layer = try b.layerPath(b.layers.items.len - 1);
    // Root's files in the directories it shares are the step user's, as Dagger copies them back
    // owned by it: a later step as the runner user can change what the action wrote, and write
    // its own file commands where the action's were made (the directory too, when the action
    // was the job's first step and made it).
    // The layer's ids are the slot's host ids, or the canonical ones when its upper was written
    // through an idmapped mount (`Backend.idmappedUpper`).
    const host_base: u32 = if (b.layers.items[b.layers.items.len - 1].canonical) 0 else b.idBase();
    if (b.how.userns == .mapped and b.uid != 0) for (try shares(arena, x.ev.workspace)) |sh|
        ownShared(b.io, layer, sh.from, host_base + b.uid, host_base + b.gid);
    var answer: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(.{
        .exitCode = ended.code,
        .fc_all = .{ .contents = try combined(arena, layer, fc) },
    }, .{}, &answer.writer);
    const data = try std.json.parseFromSliceLeaky(std.json.Value, arena, answer.written(), .{});
    return try x.collect(num, data, .{ .doc = "", .at = 0 });
}

/// Gives everything the step's layer holds under `shared` (a directory the container shares with
/// the job), `shared` itself included, to host ids `uid` and `gid`: what the action changed,
/// since the layer holds nothing else. No symlink is followed and no whiteout touched; the step's
/// processes are gone, so nothing changes under the walk.
fn ownShared(io: std.Io, layer: []const u8, shared: []const u8, uid: u32, gid: u32) void {
    const nofollow: std.Io.Dir.OpenOptions = .{ .follow_symlinks = false, .iterate = true };
    var dir = std.Io.Dir.cwd().openDir(io, layer, nofollow) catch return;
    var parts = std.mem.tokenizeScalar(u8, shared, '/');
    while (parts.next()) |part| {
        const sub = dir.openDir(io, part, nofollow) catch {
            dir.close(io);
            return;
        };
        dir.close(io);
        dir = sub;
    }
    defer dir.close(io);
    _ = std.os.linux.fchownat(dir.handle, "", uid, gid, std.os.linux.AT.EMPTY_PATH);
    ownTree(io, dir, uid, gid, 0);
}

fn ownTree(io: std.Io, dir: std.Io.Dir, uid: u32, gid: u32, depth: u32) void {
    if (depth > 256) return;
    var name: [std.fs.max_name_bytes + 1]u8 = undefined;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        // An overlay whiteout: the deletion of a file below, not a file.
        if (e.kind == .character_device) continue;
        if (e.name.len >= name.len) continue;
        @memcpy(name[0..e.name.len], e.name);
        name[e.name.len] = 0;
        const z: [*:0]const u8 = name[0..e.name.len :0];
        _ = std.os.linux.fchownat(dir.handle, z, uid, gid, std.os.linux.AT.SYMLINK_NOFOLLOW);
        if (e.kind != .directory) continue;
        var sub = dir.openDir(io, e.name, .{ .follow_symlinks = false, .iterate = true }) catch
            continue;
        defer sub.close(io);
        ownTree(io, sub, uid, gid, depth + 1);
    }
}

const Build = @FieldType(Exec.DockerRun.Image, "build");

/// The Dockerfile's build context: `bd.context` in the directory `bd.dir` (a fetched action's,
/// `Loaded.dir`, its directory in the layer its fetch made) or, for a local action (`bd.dir`
/// is no host path), in the job's own layers at the action's place (`bd.path`), where its files
/// are as the steps before left them. Looked into through no symlink, as a view the builder
/// reads its sources and the Dockerfile through. Null when it is no directory of the action.
fn openContext(b: *Backend, bd: Build) !?*layer_view.View {
    var parts = std.mem.tokenizeScalar(u8, bd.context, '/');
    while (parts.next()) |part| if (std.mem.eql(u8, part, "..")) return null;
    if (std.fs.path.isAbsolutePosix(bd.dir))
        return layer_view.View.open(b.arena, b.io, &.{bd.dir}, bd.context, b.opaqueXattr());
    var at = std.mem.tokenizeScalar(u8, bd.path, '/');
    while (at.next()) |part| if (std.mem.eql(u8, part, "..")) return null;
    const base = try std.fmt.allocPrint(b.arena, "{s}/{s}", .{ bd.path, bd.context });
    return layer_view.View.open(b.arena, b.io, try b.jobLayers(b.arena), base, b.opaqueXattr());
}

/// What a build's base image is, for its keys (`dockerfile.fromKey`): its reference only names it,
/// and a tag moves. A pulled image has its platform's manifest's digest, which is what it holds; any
/// other (`images.lookup`'s directory, in no way content-addressed) is known by its tree, as
/// `Backend.below` knows the job's.
fn baseId(arena: Allocator, io: std.Io, base: images.Image) ![]const u8 {
    if (base.manifest) |m| return m;
    return arena.dupe(u8, &Store.hex(try Store.rootfsFingerprint(arena, io, base.rootfs, "")));
}

/// What the planner asks of the world: the images a Dockerfile starts or copies from (pulled
/// into the native store, `find`), the content of the context's sources, and an `ADD`'s
/// downloads. Without `digests` (judging whether a build can run, before the job) none of it is
/// read: the keys are not used, and nothing is downloaded.
/// What a build's planning does over the network is stopped by this flag, at once: an `ADD` of a
/// URL and a pull of a base are tasks that the flag's watcher cancels (`cancellable`).
pub const Net = struct {
    cancel: ?*const std.atomic.Value(bool) = null,
    /// Refuse an `ADD` whose address is the host's own (loopback, link-local, unspecified): the
    /// fetch is made from the runner's network, not the job's.
    deny_local: bool = false,
    /// What the `ADD`s of one build may download in all.
    add_budget: u64 = 256 << 20,
};

/// Calls `function(args)`, or, with a `flag`, as a task that ends when the flag is set: its error is
/// `error.Cancelled` then, and what the task was doing (a fetch, a pull) is cancelled where it
/// waits.
fn cancellable(
    comptime T: type,
    io: std.Io,
    flag: ?*const std.atomic.Value(bool),
    function: anytype,
    args: std.meta.ArgsTuple(@TypeOf(function)),
) error{Cancelled}!T {
    const f = flag orelse return @call(.auto, function, args);
    if (f.load(.acquire)) return error.Cancelled;
    const Event = union(enum) { done: T, flagged: void };
    var buf: [2]Event = undefined;
    var sel: std.Io.Select(Event) = .init(io, &buf);
    sel.concurrent(.done, function, args) catch return @call(.auto, function, args);
    sel.concurrent(.flagged, watch, .{ io, f }) catch {
        // No task for the watcher: the work alone, uncancellable.
        const got = sel.await() catch {
            sel.cancelDiscard();
            return error.Cancelled;
        };
        sel.cancelDiscard();
        return switch (got) {
            .done => |v| v,
            .flagged => error.Cancelled,
        };
    };
    const got = sel.await() catch {
        sel.cancelDiscard();
        return error.Cancelled;
    };
    sel.cancelDiscard();
    return switch (got) {
        .done => |v| v,
        .flagged => error.Cancelled,
    };
}

fn watch(io: std.Io, flag: *const std.atomic.Value(bool)) void {
    while (!flag.load(.acquire)) io.sleep(.fromMilliseconds(100), .awake) catch return;
}

/// Whether `url`'s host is the machine's own by its name: `localhost`, a loopback, link-local or
/// unspecified address. By the written form (a name that resolves there, a redirect, is not seen).
pub fn hostIsLocal(url: []const u8) bool {
    const rest = if (std.mem.indexOf(u8, url, "://")) |i| url[i + 3 ..] else url;
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    var host = rest[0..end];
    if (std.mem.lastIndexOfScalar(u8, host, '@')) |at| host = host[at + 1 ..];
    if (host.len > 0 and host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return true;
        host = host[1..close];
    } else if (std.mem.lastIndexOfScalar(u8, host, ':')) |c| host = host[0..c];
    if (std.ascii.eqlIgnoreCase(host, "localhost") or std.ascii.endsWithIgnoreCase(host, ".localhost")) return true;
    if (std.Io.net.Ip6Address.parse(host, 0)) |a| {
        const b = a.bytes;
        var zero = true;
        for (b[0..15]) |x| if (x != 0) {
            zero = false;
        };
        if (zero and (b[15] == 0 or b[15] == 1)) return true; // :: and ::1
        if (b[0] == 0xfe and b[1] & 0xc0 == 0x80) return true; // fe80::/10
        // ::ffff:a.b.c.d
        if (std.mem.eql(u8, b[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }))
            return ipv4Local(b[12], b[13]);
        return false;
    } else |_| {}
    var o: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, host, '.');
    var n: usize = 0;
    while (it.next()) |part| : (n += 1) {
        if (n == 4) return false;
        o[n] = std.fmt.parseInt(u8, part, 10) catch return false;
    }
    if (n != 4) return false;
    return ipv4Local(o[0], o[1]);
}

fn ipv4Local(a: u8, b: u8) bool {
    return a == 127 or a == 0 or (a == 169 and b == 254);
}

const Planning = struct {
    net: Net = .{},
    added: u64 = 0,
    env: *Env,
    /// The context to read the sources' content from; null when `digests` is not wanted.
    context: ?*layer_view.View,
    digests: bool,
    bases_iface: dockerfile.Bases = .{ .resolveFn = resolve },
    context_iface: dockerfile.Context = .{ .digestFn = digest, .fetchFn = fetch },

    fn bases(p: *Planning) *dockerfile.Bases {
        return &p.bases_iface;
    }

    fn resolve(iface: *dockerfile.Bases, arena: Allocator, ref: []const u8, why: *[]const u8) anyerror!?dockerfile.BaseImage {
        const p: *Planning = @fieldParentPtr("bases_iface", iface);
        const env = p.env;
        // An image the job's Docker API built and tagged (`docker build -t x .`) is `FROM x`'s first.
        if (try env.host.localImage(arena, ref)) |local| {
            return .{ .config = local.config, .id = if (p.digests) local.id else "" };
        }
        // `find` grows the job's list of held locks from the arena it is given: the job's.
        const found = try cancellable(anyerror!images.Found, env.io, p.net.cancel, find, .{ env.arena, env.gpa, env.io, env.images_dir, env.store_cfg.root, ref, env.image_tag_ttl_s, env.held });
        switch (try found) {
            .image => |i| return .{ .config = i, .id = if (p.digests) try baseId(arena, env.io, i) else "" },
            .missing => |w| {
                why.* = w;
                return null;
            },
        }
    }

    fn ctx(p: *Planning) *dockerfile.Context {
        return &p.context_iface;
    }

    fn digest(i: *dockerfile.Context, arena: Allocator, sources: []const []const u8) anyerror![64]u8 {
        const p: *Planning = @fieldParentPtr("context_iface", i);
        if (!p.digests) return @splat('0');
        return dockerfile.contextDigest(arena, p.context.?, sources);
    }

    /// An `ADD`'s URL downloaded into the job's directory, whole, by the runner's own client.
    fn fetch(i: *dockerfile.Context, arena: Allocator, url: []const u8) anyerror!dockerfile.Fetched {
        const p: *Planning = @fieldParentPtr("context_iface", i);
        if (!p.digests) return .{ .file = "", .digest = @splat('0') };
        if (p.net.deny_local and hostIsLocal(url)) return error.LocalAddress;
        if (p.added >= p.net.add_budget) return error.TooMuchAdded;
        // A server that stalls ends the build at its limits (the job's own cancel is the step's end,
        // which waits for them): no first byte or no byte for 30 s, 10 minutes in all.
        const res = try try cancellable(net_client.Error!net_client.Response, p.env.io, p.net.cancel, net_client.fetch, .{ arena, p.env.io, net_client.Options{
            .url = url,
            .max_response = std.math.lossyCast(usize, @min(max_add_bytes, p.net.add_budget - p.added)),
            .first_byte = .fromSeconds(30),
            .read_idle = .fromSeconds(30),
            .deadline = .fromSeconds(600),
        } });
        if (res.status != .ok) return error.BadStatus;
        p.added += res.body.len;
        var sum: [32]u8 = undefined;
        Sha256.hash(res.body, &sum, .{});
        const hex = std.fmt.bytesToHex(sum, .lower);
        const file = try std.fmt.allocPrint(arena, "{s}/ADD-{s}", .{ p.env.dir, hex[0..32] });
        try std.Io.Dir.cwd().writeFile(p.env.io, .{ .sub_path = file, .data = res.body });
        return .{ .file = file, .digest = hex };
    }
};

/// The most an `ADD` of a URL downloads, held in memory whole (the build's own arena, for an API
/// build, freed when it ends).
const max_add_bytes = 128 << 20;

/// The Dockerfile of `bd` read from `context` and planned, with the base images from the native
/// store, the sources' content and the images' identity keyed (a build).
fn planBuild(env: *Env, bd: Build, context: *layer_view.View) !dockerfile.Plan {
    const arena = env.arena;
    const df = (try context.resolve(bd.dockerfile, true)) orelse return error.NoDockerfile;
    if (df.kind != .file) return error.NoDockerfile;
    const text = try df.parent().readFileAlloc(env.io, df.name, arena, .limited(max_dockerfile));
    try ignoreFiles(env, bd, context);
    return planText(env, text, context);
}

/// What the context leaves out of a build: its `.dockerignore` (a `<Dockerfile>.dockerignore`
/// beside the Dockerfile is the one then), and, for an action fetched by git, the repository's
/// own `.git`, which GitHub's copy of the action has not. Set on the view once the Dockerfile,
/// which is always the builder's to read, has been read through it.
fn ignoreFiles(env: *Env, bd: Build, context: *layer_view.View) !void {
    const always: []const []const u8 = if (std.fs.path.isAbsolutePosix(bd.dir)) &.{".git"} else &.{};
    return ignoreFilesOf(env, env.arena, bd.dockerfile, always, context);
}

/// `ignoreFiles` for the Dockerfile `dockerfile` and `always` left out whatever the ignore file says.
fn ignoreFilesOf(env: *Env, arena: Allocator, dockerfile_name: []const u8, always: []const []const u8, context: *layer_view.View) !void {
    var text: []const u8 = "";
    const specific = try std.fmt.allocPrint(arena, "{s}.dockerignore", .{dockerfile_name});
    for ([_][]const u8{ specific, ".dockerignore" }) |name| {
        const e = (try context.resolve(name, true)) orelse continue;
        if (e.kind != .file) continue;
        text = try e.parent().readFileAlloc(env.io, e.name, arena, .limited(max_dockerfile));
        break;
    }
    const ignore = try arena.create(dockerfile.Ignore);
    ignore.* = try dockerfile.Ignore.parse(arena, text, always);
    context.filter = ignore.filter();
}

/// The most a Dockerfile may be.
const max_dockerfile = 1 << 20;

/// `text` planned: with a `context`, a build's (what the sources hold and what the images are
/// keyed); without, only whether it can be built, with fixed keys and nothing downloaded.
fn planText(env: *Env, text: []const u8, context: ?*layer_view.View) !dockerfile.Plan {
    return planTextFor(env, env.arena, text, context, .action, .{}, .{});
}

/// What a plan is for: a Docker action, whose image the runner then runs (as its `USER`), or the
/// Docker API's `POST /build`, whose image is only kept.
const PlanFor = enum { action, api };

fn planTextFor(
    env: *Env,
    arena: Allocator,
    text: []const u8,
    context: ?*layer_view.View,
    purpose: PlanFor,
    opts: dockerfile.Options,
    net: Net,
) !dockerfile.Plan {
    const digests = context != null;
    const ins = switch (try dockerfile.parse(arena, text)) {
        .ok => |i| i,
        .refused => |r| {
            env.build_reason = try std.fmt.allocPrint(arena, "line {d}: {s}", .{ r.line, r.why });
            return error.Refused;
        },
    };
    var planning: Planning = .{ .env = env, .context = context, .digests = digests, .net = net };
    const p = switch (try dockerfile.planWith(arena, ins, planning.bases(), planning.ctx(), opts)) {
        .ok => |p| p,
        .refused => |r| {
            env.build_reason = try std.fmt.allocPrint(arena, "line {d}: {s}", .{ r.line, r.why });
            return error.Refused;
        },
    };
    // Whether the USER is one the image has is known once it is built (`run`).
    const user = p.stages[p.final].config.user;
    if (purpose == .action and !images.runsAsRoot(user) and !env.mapped) {
        env.build_reason = try std.fmt.allocPrint(arena, "the image runs as USER {s}, and a " ++
            "rootless runner's Docker actions run as root only", .{user});
        return error.Refused;
    }
    for (p.stages) |stage| for (stage.steps) |st| if (st.op == .run and !images.runsAsRoot(st.op.run.user)) {
        env.build_reason = try std.fmt.allocPrint(arena, "line {d}: a RUN as USER {s} is not " ++
            "native yet", .{ st.line, st.op.run.user });
        return error.Refused;
    };
    return p;
}

/// Why the Dockerfile action `label` cannot be built natively, or null (`actions.preload`).
pub fn buildReason(b: *Backend, bd: Build, label: []const u8) !?[]const u8 {
    const arena = b.arena;
    const ctx = (try openContext(b, bd)) orelse return try std.fmt.allocPrint(
        arena,
        "the build context {s} of {s} is not a directory of the action",
        .{ bd.context, label },
    );
    defer ctx.close();
    const df = (try ctx.resolve(bd.dockerfile, true)) orelse
        return try std.fmt.allocPrint(arena, "{s} has no {s}", .{ label, bd.dockerfile });
    if (df.kind != .file) return try std.fmt.allocPrint(arena, "{s} has no {s}", .{ label, bd.dockerfile });
    return buildReasonText(b, try df.parent().readFileAlloc(b.io, df.name, arena, .limited(max_dockerfile)), label);
}

/// `buildReason` for a Dockerfile whose text is all there is (a local action's, read from the
/// job's commit before the job: its context is not anywhere yet).
pub fn buildReasonText(b: *Backend, text: []const u8, label: []const u8) !?[]const u8 {
    var ad: Adapter = .{ .b = b };
    var env = ad.env();
    _ = planText(&env, text, null) catch |e| return switch (e) {
        error.Refused => try std.fmt.allocPrint(b.arena, "{s}'s Dockerfile cannot be built " ++
            "natively: {s}", .{ label, env.build_reason }),
        else => e,
    };
    return null;
}

pub const Built = union(enum) {
    image: struct { lowers: []const []const u8, config: images.Image },
    failed: []const u8,
};

/// A Dockerfile action's image, built natively on its base from the image store: each
/// instruction's layer taken from the native layer store by its key, or made and stored there
/// (`dockerfile.build`), a RUN in a sandbox on the layers before it (`Backend.execBuild`).
pub fn buildImage(b: *Backend, bd: Build) !Built {
    var ad: Adapter = .{ .b = b };
    var env = ad.env();
    const arena = env.arena;
    const ctx = (try openContext(b, bd)) orelse return .{ .failed = "the build context is " ++
        "not a directory of the action" };
    defer ctx.close();
    const p = planBuild(&env, bd, ctx) catch |e| return switch (e) {
        error.Refused => .{ .failed = env.build_reason },
        error.NoDockerfile => .{ .failed = "the action has no such Dockerfile" },
        else => e,
    };
    // P2's layer store: published there, held for the job, evicted under its cap.
    const store: layers.Store = .{
        .dir = env.dir,
        .store = env.store_cfg,
        .held = env.held,
        .scope = env.scope,
        .userns = env.userns,
    };
    var runner: BuildRunner = .{ .env = &env };
    return switch (try dockerfile.build(arena, env.io, p, store, runner.runner(), .{
        .context = ctx,
        .opaque_xattr = env.opaque_xattr,
    })) {
        .ok => |built| if (built.lowers.len == 0)
            .{ .failed = "the Dockerfile builds an image with no files" }
        else
            .{ .image = .{ .lowers = built.lowers, .config = built.config } },
        .failed => |f| switch (f.what) {
            .copy => .{ .failed = try std.fmt.allocPrint(arena, "the COPY on line {d}: {s}", .{ f.line, f.why }) },
            .workdir => .{ .failed = try std.fmt.allocPrint(arena, "the WORKDIR on line {d}: {s}", .{ f.line, f.why }) },
            .run => .{ .failed = if (runner.failure.len > 0)
                try std.fmt.allocPrint(arena, "the RUN on line {d}: {s}", .{ f.line, runner.failure })
            else
                try std.fmt.allocPrint(arena, "the RUN on line {d} exited with {d}: {s}", .{
                    f.line,
                    f.code,
                    runner.last.tail(),
                }) },
        },
    };
}

/// What a `Backend` gives a build (`build_env.zig`): its job's data, and a `RUN` through the job's
/// own sandbox launcher.
pub const Adapter = struct {
    b: *Backend,
    host: build_env.Host = .{ .runFn = runFn, .localImageFn = localImageFn, .planFn = planFn },

    pub fn env(ad: *Adapter) Env {
        const b = ad.b;
        return .{
            .io = b.io,
            .gpa = b.gpa,
            .arena = b.arena,
            .dir = b.dir,
            .store_cfg = b.store_cfg,
            .held = &b.held,
            .scope = b.scope,
            .userns = @tagName(b.how.userns),
            .mapped = b.how.userns == .mapped,
            .id_base = b.idBase(),
            .slot_ids = b.slotIds(),
            .images_dir = b.images_dir,
            .image_tag_ttl_s = b.image_tag_ttl_s,
            .opaque_xattr = b.opaqueXattr(),
            .host = &ad.host,
        };
    }

    fn runFn(h: *build_env.Host, call: build_env.RunCall) anyerror!sandbox.Ended {
        const ad: *Adapter = @fieldParentPtr("host", h);
        const b = ad.b;
        const workdir = b.workdir;
        b.workdir = call.workdir;
        defer b.workdir = workdir;
        if (call.running) |running| return b.execBuildApi(running, call.argv, call.env, call.out, call.container);
        return b.execBuild(call.argv, call.env, 0, 0, call.out, call.container);
    }

    /// The planner, confined (`Spec.confined`), in a root of nothing but its mount points.
    fn planFn(h: *build_env.Host, call: build_env.PlanCall) anyerror!sandbox.Ended {
        const ad: *Adapter = @fieldParentPtr("host", h);
        const b = ad.b;
        const arena = b.arena;
        const cwd = std.Io.Dir.cwd();
        const base = try std.fmt.allocPrint(arena, "{s}/{s}", .{ b.dir, call.dir });
        for ([_][]const u8{ "root/dev", "root/proc", "root/sys", "root/tmp", "root/ctx", "root/plan", "upper", "work", "merged", "plan" }) |d|
            try cwd.createDirPath(b.io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ base, d }));
        for ([_][]const u8{ "root/spool.tar", "root/parse" }) |f|
            try cwd.writeFile(b.io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ base, f }), .data = "" });
        const plan_dir = try std.fmt.allocPrint(arena, "{s}/plan", .{base});
        // The planner is the job's root: what it writes is the slot's ids on a root runner.
        if (b.how.userns == .mapped) for ([_][]const u8{ call.ctx, plan_dir, call.tar, try std.fmt.allocPrint(arena, "{s}/upper", .{base}) }) |p| {
            const z = try arena.dupeSentinel(u8, p, 0);
            _ = std.os.linux.chown(z, b.idBase(), b.idBase());
        };
        const rel = try std.fmt.allocPrint(arena, "{s}/", .{call.dir});
        const spec: sandbox.Spec = .{
            .root = b.dir,
            .lowers = &.{try std.fmt.allocPrint(arena, "{s}root", .{rel})},
            .upper = try std.fmt.allocPrint(arena, "{s}upper", .{rel}),
            .work = try std.fmt.allocPrint(arena, "{s}work", .{rel}),
            .merged = try std.fmt.allocPrint(arena, "{s}merged", .{rel}),
            .workdir = "/",
            .argv = &.{ "/parse", planner.command, planner.request_at, planner.tar_at, planner.context_at, planner.out_at },
            .exec = "/parse",
            .env = &.{"PATH=/"},
            .binds = &.{
                .{ .host = b.self_exe, .at = "/parse", .read_only = true, .nosuid = true },
                .{ .host = call.tar, .at = planner.tar_at, .read_only = true, .nosuid = true },
                .{ .host = call.ctx, .at = planner.context_at, .read_only = false, .nosuid = true },
                .{ .host = plan_dir, .at = "/plan", .read_only = false, .nosuid = true },
            },
            .userns = b.how.userns,
            .id_base = b.idBase(),
            .id_count = Backend.ids_per_slot,
            .cgroup = if (b.job_cgroup) |j| j.stepsDir() else null,
            .image_layers = 1,
            .confined = true,
        };
        const ended = try sandbox.run(arena, b.io, b.how.argv_prefix, spec, call.running, call.out);
        return ended;
    }

    fn localImageFn(h: *build_env.Host, arena: Allocator, ref: []const u8) anyerror!?build_env.LocalImage {
        const ad: *Adapter = @fieldParentPtr("host", h);
        const st = ad.b.docker_api_state orelse return null;
        const local = (try st.baseOf(arena, ref)) orelse return null;
        return .{ .config = local.config, .id = local.id };
    }
};

/// `dockerfile.Runner` over the sandbox: a RUN on the image's layers so far (each idmapped on a
/// root runner, as the image's are when it runs), writing into the build's new layer. On a root
/// runner what the RUN writes has the job's host ids; they are shifted back to the image's own
/// (`Store.unshift`), so the layer is the same whichever job's range built it.
const BuildRunner = struct {
    env: *Env,
    last: Backend.Captured = undefined,
    failure: []const u8 = "",
    /// Set for a build the job's Docker API runs, while a step of the job is running.
    api: ?*const Api = null,

    fn runner(r: *BuildRunner) dockerfile.Runner {
        return .{ .ptr = r, .runFn = runStep };
    }

    fn runStep(
        ptr: *anyopaque,
        lowers: []const []const u8,
        upper: []const u8,
        op: @FieldType(dockerfile.Step.Op, "run"),
    ) anyerror!i32 {
        const r: *BuildRunner = @ptrCast(@alignCast(ptr));
        const env = r.env;
        const arena = env.arena;
        for ([_][]const u8{ "BU", "BW", "BC" }) |d|
            try std.Io.Dir.cwd().createDirPath(env.io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ env.dir, d }));
        if (env.mapped) {
            const p = try arena.dupeSentinel(u8, upper, 0);
            _ = std.os.linux.chown(p, env.id_base, env.id_base);
        }
        r.last = .{ .arena = arena };
        const container: sandbox.Spec.Container = .{
            .lowers = lowers,
            .upper = upper,
            .work = "BW",
            .merged = "BC",
        };
        if (r.api) |api| if (api.cancelled()) {
            r.failure = "the build was cancelled";
            return 125;
        };
        const ended = try env.host.run(.{
            .argv = op.argv,
            .env = op.env,
            .workdir = op.workdir,
            .container = container,
            .running = if (r.api) |api| api.running else null,
            .out = if (r.api) |api| api.out else r.last.output(),
        });
        // The sandbox's own failure is the build's, with why.
        if (ended.failure.len > 0) {
            r.failure = ended.failure;
            return 125;
        }
        // Stopped, it may be half done whatever it exited with: never a layer for the store.
        if (ended.killed) return ended.code;
        // The layer gets the canonical ids, as P2 gives a step's before it is stored
        // (`Store.unshift`, #276), so it serves every slot. Half shifted, it must not be stored.
        if (env.mapped) Store.unshift(env.arena, env.io, upper, env.slot_ids) catch |e| {
            r.failure = try std.fmt.allocPrint(env.arena, "the RUN's layer could not be given the " ++
                "image's ids: {s}", .{@errorName(e)});
            return 125;
        };
        return ended.code;
    }
};

/// What the job's Docker API gives a build it runs while a step is running (`buildApi`): an
/// implementation embeds it as a field and recovers itself with `@fieldParentPtr`.
pub const Api = struct {
    /// The build's `RUN`s run under this (so that stopping them leaves the step alone) and write
    /// their output to `out`.
    running: *sandbox.Running,
    out: sandbox.Output,
    /// Whether the build was stopped: no `RUN` starts after.
    cancelledFn: *const fn (api: *const Api) bool,

    fn cancelled(a: *const Api) bool {
        return a.cancelledFn(a);
    }
};

/// Tells a build's progress: its plan once made (`planned`), then its stages and steps
/// (`progress`). Embedded and recovered like the interfaces above.
pub const Observer = struct {
    plannedFn: *const fn (o: *Observer, plan: dockerfile.Plan, ins: []const dockerfile.Instruction) void,
    progress: dockerfile.Progress,
};

pub const ApiRequest = struct {
    /// The context's directory, absolute, empty: the planner unpacks the tar into it.
    dir: []const u8,
    /// The spooled tar (absolute) and the build's number (the planner's directory, `px-<id>`).
    tar: []const u8,
    id: u32,
    dockerfile: []const u8,
    options: dockerfile.Options,
    api: *const Api,
    /// What the build allocates from: its own, freed when it ends (not the job's).
    arena: Allocator,
    observer: ?*Observer = null,
    /// Set when the build is to stop (before each of its steps).
    cancel: ?*const std.atomic.Value(bool) = null,
};

pub const ApiBuilt = union(enum) {
    image: struct {
        lowers: []const []const u8,
        config: images.Image,
        /// The key of the build's last step.
        final_key: []const u8,
    },
    /// Why not, as the build says it: the Dockerfile's refusal or the step that failed.
    failed: []const u8,
};

/// A `POST /build`'s image (`docker_api_job.zig`): `buildImage` for a context the client sent, with
/// `--build-arg`, `--target`, `--label` and `--no-cache` (`req.options`), the sources' `.git`
/// included as Docker's context has it, and the `RUN`s in the job's cgroup beside the step that
/// asked. Layers are the store's, keyed with the job's trust scope, as an action's are.
pub fn buildApi(b: *Backend, req: ApiRequest) !ApiBuilt {
    var ad: Adapter = .{ .b = b };
    var env = ad.env();
    return buildApiIn(&env, req);
}

/// `buildApi` for a build's `Env`: the job's own, or the builder process's.
pub fn buildApiIn(env: *Env, req: ApiRequest) !ApiBuilt {
    const arena = req.arena;
    var world: ApiWorld = .{ .env = env, .arena = arena, .net = .{ .cancel = req.cancel, .deny_local = true } };
    const planned = switch (try planThroughChild(env, req, &world)) {
        .failed => |why| return .{ .failed = why },
        .ok => |p| p,
    };
    // The planner is dead and gone: the context is the executor's to read now, through a view that
    // follows no link.
    const ctx = (try layer_view.View.open(arena, env.io, &.{req.dir}, "", env.opaque_xattr)) orelse
        return .{ .failed = "the build context is empty" };
    defer ctx.close();
    try ignoreFilesOf(env, arena, req.dockerfile, &.{}, ctx);
    world.ctx = ctx;
    // What an `ADD` fetches, by this side, before a key is made of it.
    for (planned.plan.stages) |stage| for (stage.steps) |step| if (step.op == .copy) for (step.op.copy.sources) |src| if (src == .url) {
        if (world.urls.get(src.url.url) != null) continue;
        const got = fetchUrl(env, arena, src.url.url, req.cancel, &world.added) catch |e| return .{ .failed = switch (e) {
            error.Cancelled => "the build was cancelled",
            error.LocalAddress => "an ADD of an address of the machine itself (loopback, link-local) is refused: the fetch is made from the runner's network, not the job's",
            else => try std.fmt.allocPrint(arena, "ADD of {s} failed: {s}", .{ src.url.url, @errorName(e) }),
        } };
        try world.urls.put(arena, src.url.url, got);
    };
    const salt = req.options.salt;
    const p = dockerfile.rekeyApi(arena, planned.plan, salt, &world.iface) catch |e| switch (e) {
        error.SourceMissing => return .{ .failed = "a source of a COPY is not in the build context" },
        else => return e,
    };
    if (req.observer) |o| o.plannedFn(o, p, planned.ins);
    const store: layers.Store = .{
        .dir = env.dir,
        .store = env.store_cfg,
        .held = env.held,
        .held_arena = env.arena,
        .scope = env.scope,
        .userns = env.userns,
    };
    var runner: BuildRunner = .{ .env = env, .api = req.api };
    return switch (dockerfile.build(arena, env.io, p, store, runner.runner(), .{
        .context = ctx,
        .opaque_xattr = env.opaque_xattr,
        .progress = if (req.observer) |o| &o.progress else null,
        .cancel = req.cancel,
    }) catch |e| switch (e) {
        error.Cancelled => return .{ .failed = "the build was cancelled" },
        else => return e,
    }) {
        .ok => |built| if (built.lowers.len == 0)
            .{ .failed = "the Dockerfile builds an image with no files" }
        else
            .{ .image = .{
                .lowers = built.lowers,
                .config = built.config,
                .final_key = try arena.dupe(u8, &p.stages[p.final].key),
            } },
        .failed => |f| switch (f.what) {
            .copy => .{ .failed = try std.fmt.allocPrint(arena, "COPY failed (Dockerfile line {d}): {s}", .{ f.line, f.why }) },
            .workdir => .{ .failed = try std.fmt.allocPrint(arena, "WORKDIR failed (Dockerfile line {d}): {s}", .{ f.line, f.why }) },
            .run => .{ .failed = if (runner.failure.len > 0)
                try std.fmt.allocPrint(arena, "The command on line {d} could not run: {s}", .{ f.line, runner.failure })
            else
                try std.fmt.allocPrint(arena, "The command on line {d} returned a non-zero code: {d}", .{ f.line, f.code }) },
        },
    };
}

/// The one `ADD` of `url`, fetched by the executor: into the job's directory, hashed, bounded by
/// what a build may add in all (`Net.add_budget`) and cancelled with the build.
fn fetchUrl(env: *Env, arena: Allocator, url: []const u8, cancel: ?*const std.atomic.Value(bool), added: *u64) !dockerfile.Fetched {
    const net: Net = .{ .cancel = cancel, .deny_local = true };
    if (net.deny_local and hostIsLocal(url)) return error.LocalAddress;
    if (added.* >= net.add_budget) return error.TooMuchAdded;
    const res = try try cancellable(net_client.Error!net_client.Response, env.io, cancel, net_client.fetch, .{ arena, env.io, net_client.Options{
        .url = url,
        .max_response = std.math.lossyCast(usize, @min(max_add_bytes, net.add_budget - added.*)),
        .first_byte = .fromSeconds(30),
        .read_idle = .fromSeconds(30),
        .deadline = .fromSeconds(600),
    } });
    if (res.status != .ok) return error.BadStatus;
    added.* += res.body.len;
    var sum: [32]u8 = undefined;
    Sha256.hash(res.body, &sum, .{});
    const hex = std.fmt.bytesToHex(sum, .lower);
    const file = try std.fmt.allocPrint(arena, "{s}/ADD-{s}", .{ env.dir, hex[0..32] });
    try std.Io.Dir.cwd().writeFile(env.io, .{ .sub_path = file, .data = res.body });
    return .{ .file = file, .digest = hex };
}

/// A base the executor has: the image, its id (made when a key needs it), and where it came from.
const BaseEntry = struct {
    ref: []const u8,
    image: ?images.Image = null,
    id: ?[]const u8 = null,
    local: bool = false,
    missing: []const u8 = "",
};

/// What the keys of an API build need of the world (`dockerfile.KeyWorld`): the executor's own
/// answers, from the bases it resolved, the context it reads and the fetches it made.
const ApiWorld = struct {
    env: *Env,
    arena: Allocator,
    net: Net,
    ctx: ?*layer_view.View = null,
    bases: std.ArrayList(BaseEntry) = .empty,
    urls: std.StringHashMapUnmanaged(dockerfile.Fetched) = .empty,
    added: u64 = 0,
    iface: dockerfile.KeyWorld = .{ .baseFn = base, .sourcesFn = sources, .urlFn = urlOf },

    fn base(w: *const dockerfile.KeyWorld, rootfs: []const u8) ?dockerfile.KeyWorld.Resolved {
        const self: *ApiWorld = @constCast(@fieldParentPtr("iface", w));
        const prefix = "/base/";
        if (!std.mem.startsWith(u8, rootfs, prefix)) return null;
        const n = std.fmt.parseInt(usize, rootfs[prefix.len..], 10) catch return null;
        if (n >= self.bases.items.len) return null;
        const e = &self.bases.items[n];
        const image = e.image orelse return null;
        if (e.id == null) e.id = baseId(self.arena, self.env.io, image) catch return null;
        return .{ .id = e.id.?, .rootfs = image.rootfs, .layers = image.layers };
    }

    fn sources(w: *const dockerfile.KeyWorld, arena: Allocator, paths: []const []const u8) anyerror![64]u8 {
        const self: *const ApiWorld = @fieldParentPtr("iface", w);
        return dockerfile.contextDigest(arena, self.ctx.?, paths);
    }

    fn urlOf(w: *const dockerfile.KeyWorld, url: []const u8) ?dockerfile.Fetched {
        const self: *const ApiWorld = @fieldParentPtr("iface", w);
        return self.urls.get(url);
    }
};

const Planned = struct { plan: dockerfile.Plan, ins: []const dockerfile.Instruction };

/// The plan of the request's Dockerfile, made by the confined planner (`planner.zig`) in as many
/// rounds as it needs bases resolved, and read here as hostile input (`build_frames.decode`).
fn planThroughChild(env: *Env, req: ApiRequest, world: *ApiWorld) !union(enum) { ok: Planned, failed: []const u8 } {
    const arena = req.arena;
    const cwd = std.Io.Dir.cwd();
    const dir = try std.fmt.allocPrint(arena, "px-{d}", .{req.id});
    const plan_dir = try std.fmt.allocPrint(arena, "{s}/{s}/plan", .{ env.dir, dir });
    var round: u32 = 0;
    while (round < 16) : (round += 1) {
        if (req.cancel) |c| if (c.load(.acquire)) return .{ .failed = "the build was cancelled" };
        // The request: the bases resolved so far, by number.
        const wire = try arena.alloc(build_frames.Request.Base, world.bases.items.len);
        for (world.bases.items, wire) |e, *w| {
            var cfg = e.image orelse images.Image{ .rootfs = "" };
            cfg.rootfs = "";
            cfg.layers = &.{};
            cfg.healthcheck = null;
            cfg.digest = null;
            cfg.manifest = null;
            w.* = .{ .ref = e.ref, .config = cfg, .local = e.local, .missing = e.missing };
        }
        const pairs = try arena.alloc(build_frames.Request.Pair, req.options.build_args.len);
        for (req.options.build_args, pairs) |a, *p| p.* = .{ .name = a.name, .value = a.value };
        const lpairs = try arena.alloc(build_frames.Request.Pair, req.options.labels.len);
        for (req.options.labels, lpairs) |a, *p| p.* = .{ .name = a.name, .value = a.value };
        var json: std.Io.Writer.Allocating = .init(arena);
        try std.json.Stringify.value(build_frames.Request{
            .dockerfile = req.dockerfile,
            .build_args = pairs,
            .labels = lpairs,
            .target = req.options.target,
            .bases = wire,
        }, .{}, &json.writer);
        // (The plan directory is made by `planFn`; the request is written once it is there.)
        try cwd.createDirPath(env.io, plan_dir);
        try cwd.writeFile(env.io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}/request.json", .{plan_dir}), .data = json.written() });
        cwd.deleteFile(env.io, try std.fmt.allocPrint(arena, "{s}/out.bin", .{plan_dir})) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
        var tail: Backend.Captured = .{ .arena = arena };
        const ended = try env.host.plan(.{
            .dir = dir,
            .tar = req.tar,
            .ctx = req.dir,
            .running = req.api.running,
            .out = tail.output(),
        });
        if (req.cancel) |c| if (c.load(.acquire)) return .{ .failed = "the build was cancelled" };
        if (ended.failure.len > 0) return .{ .failed = try std.fmt.allocPrint(arena, "the planner could not run: {s}", .{ended.failure}) };
        const bytes = cwd.readFileAlloc(env.io, try std.fmt.allocPrint(arena, "{s}/out.bin", .{plan_dir}), arena, .limited(build_frames.max_frame + 1)) catch
            return .{ .failed = try std.fmt.allocPrint(arena, "the planner ended with code {d} and no plan: {s}", .{ ended.code, try printable(arena, tail.tail()) }) };
        var why: []const u8 = "";
        const out = build_frames.decode(arena, bytes, &why) catch |e| switch (e) {
            error.Invalid, error.BadFrame, error.TooBig => return .{ .failed = if (why.len > 0) why else "the planner's frame is malformed" },
            else => return e,
        };
        switch (out.status) {
            .failed => return .{ .failed = out.why },
            .refused => return .{ .failed = try std.fmt.allocPrint(arena, "line {d}: {s}", .{ out.line, out.why }) },
            .need => {
                if (out.need.len == 0) return .{ .failed = "the planner asked for nothing" };
                for (out.need) |ref| {
                    if (world.bases.items.len >= build_frames.max_bases) return .{ .failed = "the Dockerfile names too many images" };
                    try world.bases.append(arena, try resolveBase(env, arena, ref, req.cancel));
                }
            },
            .plan => {
                const ins = try arena.alloc(dockerfile.Instruction, out.ins.len);
                for (out.ins, ins) |x, *i| i.* = .{ .kind = x.kind, .text = x.text, .line = x.line };
                return .{ .ok = .{ .plan = out.plan.?, .ins = ins } };
            },
        }
    }
    return .{ .failed = "the Dockerfile needs more rounds of bases than a build may" };
}

/// A base the planner asked for: the job's own image of that name, else the native store's (pulled
/// when it must be, and stopped with the build).
fn resolveBase(env: *Env, arena: Allocator, ref: []const u8, cancel: ?*const std.atomic.Value(bool)) !BaseEntry {
    if (try env.host.localImage(arena, ref)) |local|
        return .{ .ref = ref, .image = local.config, .id = local.id, .local = true };
    const found = cancellable(anyerror!images.Found, env.io, cancel, find, .{ env.arena, env.gpa, env.io, env.images_dir, env.store_cfg.root, ref, env.image_tag_ttl_s, env.held }) catch
        return .{ .ref = ref, .missing = "the build was cancelled" };
    return switch (found catch |e| return .{ .ref = ref, .missing = try std.fmt.allocPrint(arena, "the image {s} could not be had: {s}", .{ ref, @errorName(e) }) }) {
        .image => |i| .{ .ref = ref, .image = i },
        .missing => |w| .{ .ref = ref, .missing = w },
    };
}

/// A client's text as one short printable line.
fn printable(arena: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (text[0..@min(text.len, 300)]) |c| try out.append(arena, if (c < 0x20 or c == 0x7f) '?' else c);
    return out.items;
}

/// The action's environment, as the Dagger path's container gives its command
/// (`containerScript`): the image's `ENV`, GitHub's default variables with GITHUB_WORKSPACE at
/// /github/workspace (`writeActionEnv`), the job's, step's and action's env with the runtime's
/// (`Exec.containerEnv`), its secrets by value, then the file commands and GITHUB_ACTION, last so
/// nothing points them elsewhere (`writeEnvCommand`). The runner's markers and the event variable
/// are not in it, as the script's `env -u` leaves them out. Secret values reach the helper over
/// its stdin, never a command line, as P1's steps' do.
fn processEnv(
    arena: Allocator,
    x: *Exec,
    dr: Exec.DockerRun,
    img: images.Image,
    state: []const job_mod.EnvVar,
    fc: u32,
) ![]const []const u8 {
    var all: std.ArrayList(job_mod.EnvVar) = .empty;
    for (img.env) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        try put(arena, &all, kv[0..eq], kv[eq + 1 ..]);
    }
    for (try x.ev.defaultEnv()) |e| try put(
        arena,
        &all,
        e.name,
        if (std.mem.eql(u8, e.name, "GITHUB_WORKSPACE")) dagger.docker_workspace else e.value,
    );
    const ce = try x.containerEnv(dr, state);
    for (ce.plain) |e| try put(arena, &all, e.name, e.value);
    for (ce.secret) |s| try put(arena, &all, s.name, Backend.plaintext(x, s.id));
    const names = [_][]const u8{
        "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_STATE",
    };
    for (names, scripts.fc_kinds) |name, kind|
        try put(arena, &all, name, try scripts.fcPath(arena, kind, fc));
    const label = if (dr.repository.len > 0) dr.repository else dr.label;
    try put(arena, &all, "GITHUB_ACTION", label);
    const out = try arena.alloc([]const u8, all.items.len);
    for (all.items, out) |e, *o| o.* = try std.fmt.allocPrint(arena, "{s}={s}", .{ e.name, e.value });
    return out;
}

fn put(arena: Allocator, env: *std.ArrayList(job_mod.EnvVar), name: []const u8, value: []const u8) !void {
    for (env.items) |*e| if (std.mem.eql(u8, e.name, name)) {
        e.value = value;
        return;
    };
    try env.append(arena, .{ .name = name, .value = value });
}

/// `<marker><kind> <n> <mark>`, a line as `echo '<marker><kind> <n>' "$ZIG_RUNNER_MARK"` prints it.
fn markerLine(arena: Allocator, kind: []const u8, n: u32, mark: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, dagger.marker ++ "{s} {d} {s}\n", .{ kind, n, mark });
}

/// The step's file commands as one text, as `scripts.writeCombinedFileCommands` writes `all_<fc>`:
/// each after a `::zig-file-command::<kind> <bytes>` line and followed by a newline, read from the step's
/// layer (one the action removed is empty, as the script's `>>` makes it), then the `ran` marker,
/// empty with the step cache off. Each is read inside the layer, through no symlink.
fn combined(arena: Allocator, layer: []const u8, fc: u32) ![]const u8 {
    var parts: [scripts.fc_kinds.len][2][]const u8 = undefined;
    for (scripts.fc_kinds, &parts) |k, *p| p.* = .{ k, switch (try sandbox.readIn(arena, layer, try scripts.fcPath(arena, k, fc), Backend.max_read)) {
        .text => |t| t,
        .missing, .whiteout => "",
    } };
    return scripts.combine(arena, &parts, "");
}

// --- tests ---

const sink = @import("../sink.zig");
const runner_config = @import("../config.zig");
const testStep = @import("../dagger/testing.zig").testStep;
const testJob = @import("../dagger/testing.zig").testJob;

/// An image in the native store at `<tmp>/images`, as `images.zig` reads it: a rootfs of a few
/// directories (the tests bind the host's /usr over it, as over the job's) holding
/// `/image-marker`, and `config` as its config.json.
pub fn testImage(arena: Allocator, tmp: *std.testing.TmpDir, ref: []const u8, config: []const u8) ![]const u8 {
    const io = std.testing.io;
    const d = tmp.dir;
    const base = try std.fmt.allocPrint(arena, "images/{s}", .{try images.key(arena, ref)});
    for ([_][]const u8{ "etc/ssl", "usr", "tmp", "dev", "proc", "sys", "root" }) |p|
        try d.createDirPath(io, try std.fmt.allocPrint(arena, "{s}/rootfs/{s}", .{ base, p }));
    for ([_][2][]const u8{ .{ "usr/bin", "bin" }, .{ "usr/lib", "lib" }, .{ "usr/lib64", "lib64" } }) |l|
        try d.symLink(io, l[0], try std.fmt.allocPrint(arena, "{s}/rootfs/{s}", .{ base, l[1] }), .{});
    const files = [_][2][]const u8{
        .{ "rootfs/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n" },
        .{ "rootfs/etc/hosts", "" },
        .{ "rootfs/etc/resolv.conf", "" },
        .{ "rootfs/etc/ld.so.cache", "" },
        .{ "rootfs/image-marker", "in the image\n" },
        .{ "config.json", config },
    };
    for (files) |f| try d.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ base, f[0] }),
        .data = f[1],
    });
    return std.fmt.allocPrint(arena, "{s}/images", .{try d.realPathFileAlloc(io, ".", arena)});
}

fn dockerStep(image: []const u8, inputs: []const job_mod.Input) job_mod.Step {
    var s = testStep("");
    s.action = .{ .docker = .{ .image = image, .inputs = inputs } };
    return s;
}

test "a docker:// step runs natively in its image, with the workspace and file commands bound in" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.images = try testImage(arena, &tmp, "zr-test/tool:1",
        \\{"config":{"Env":["PATH=/usr/bin:/bin","IMG_VAR=from-image","GITHUB_ACTION=image"],
        \\"Entrypoint":["/bin/sh","-c"],
        \\"Cmd":["echo default command; test -f /github/home/kept && echo home kept; test -e /container-only || echo container layer gone; exit 4"]}}
    );

    var s1 = testStep("echo from-job > in.txt");
    s1.name = "job";
    var s2 = dockerStep("zr-test/tool:1", &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"pwd; cat in.txt; echo from-action > out.txt; " ++
            "rm in.txt; echo said=hi >> $GITHUB_OUTPUT; echo FROM_ACTION=yes >> $GITHUB_ENV; " ++
            "echo HOME=$HOME GW=$GITHUB_WORKSPACE IMG=$IMG_VAR ACTION=$GITHUB_ACTION " ++
            "WHO=$INPUT_WHO STEP=$STEP_VAR; cat /image-marker; " ++
            "test -s /github/workflow/event.json && echo event; touch /github/home/kept " ++
            "/container-only; echo MARK=${ZIG_RUNNER_MARK-unset}\"" } },
        .{ .name = "who", .value = .{ .lit = "world" } },
    });
    s2.context_name = "act";
    s2.env = &.{.{ .name = "STEP_VAR", .value = .{ .lit = "from the step" } }};
    var s3 = testStep("cat out.txt; test -e in.txt || echo in.txt gone; " ++
        "test -e /image-marker || echo image not in the job; echo FROM_ACTION=$FROM_ACTION OUT=$OUT");
    s3.env = &.{.{ .name = "OUT", .value = .{ .expr = "steps.act.outputs.said" } }};
    // The image's own entrypoint and command, which fails the step.
    var s4 = dockerStep("zr-test/tool:1", &.{});
    s4.continue_on_error = .{ .lit = "true" };
    // A command the image does not have.
    var s5 = dockerStep("zr-test/tool:1", &.{.{ .name = "entrypoint", .value = .{ .lit = "no-such-tool" } }});
    s5.condition = "always()";
    s5.continue_on_error = .{ .lit = "true" };
    const job = testJob(&.{ s1, s2, s3, s4, s5 });

    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    errdefer std.debug.print("{s}\n", .{text});

    try std.testing.expectEqual(dagger.Outcome.success, res.steps[1].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[2].outcome);
    try std.testing.expectEqual(dagger.Outcome.failure, res.steps[3].outcome);
    try std.testing.expectEqual(@as(i32, 4), res.steps[3].exit_code);
    try std.testing.expectEqual(dagger.Outcome.failure, res.steps[4].outcome);
    try std.testing.expectEqual(@as(i32, 127), res.steps[4].exit_code);
    const expect = [_][]const u8{
        "Engine: native",
        "image: zr-test/tool:1",
        "/github/workspace",
        "from-job",
        "HOME=/github/home GW=/github/workspace IMG=from-image ACTION=docker://zr-test/tool:1 " ++
            "WHO=world STEP=from the step",
        "in the image",
        "event",
        "MARK=unset",
        // What the action wrote in the workspace is the job's, deletions included.
        "from-action",
        "in.txt gone",
        "image not in the job",
        "FROM_ACTION=yes OUT=hi",
        "default command",
        // /github/home is the job's Docker actions'; the container's own layer went with it.
        "home kept",
        "container layer gone",
        "exec: \"no-such-tool\": executable file not found in $PATH",
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s}\n", .{e});
        return error.TestUnexpectedResult;
    };
}

test "a Docker action's own PID 1 hears a native cancel, as `docker stop` tells it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.images = try testImage(arena, &tmp, "zr-test/tool:1",
        \\{"config":{"Env":["PATH=/usr/bin:/bin"],"Entrypoint":["/bin/sh","-c"],"Cmd":["true"]}}
    );
    var s1 = dockerStep("zr-test/tool:1", &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"trap 'echo int > got-int; exit 0' INT; " ++
            "sleep 613.77 & wait\"" } },
    });
    s1.name = "action";
    var s2 = testStep("cat got-int");
    s2.condition = "always()";
    const r = try Backend.runCancelled(arena, cfg, testJob(&.{ s1, s2 }), .{ .when = "613.77" });
    errdefer std.debug.print("took {d} ms:\n{s}\n", .{ r.took_ms, r.text });
    try std.testing.expectEqual(dagger.Outcome.cancelled, r.res.steps[0].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, r.res.steps[1].outcome);
    try std.testing.expect(r.took_ms < 5_000);
}

test "unsupported: a docker:// step needs its image in the native store, run as root" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const dir = try testImage(arena, &tmp, "zr-test/root:1", "{\"config\":{\"User\":\"0:0\"}}");
    _ = try testImage(arena, &tmp, "zr-test/user:1", "{\"config\":{\"User\":\"actionuser\"}}");
    const Case = struct { image: []const u8, store: []const u8, why: ?[]const u8 };
    for ([_]Case{
        .{ .image = "zr-test/root:1", .store = dir, .why = null },
        // Without the tests' directory the image is pulled (P3); not done here (no network).
        .{ .image = "zr-test/other:1", .store = dir, .why = "zr-test/other:1 is not in the tests' images directory" },
        .{ .image = "zr-test/user:1", .store = dir, .why = "USER actionuser" },
    }) |c| {
        const job = testJob(&.{dockerStep(c.image, &.{})});
        const why = try unsupported(arena, std.testing.allocator, io, job, .{ .images = c.store });
        if (c.why) |want| {
            try std.testing.expect(std.mem.indexOf(u8, why.?, want) != null);
        } else try std.testing.expect(why == null);
    }
}

test "on a root runner, what a Docker action writes in the workspace is the runner user's" {
    if (std.os.linux.geteuid() != 0) {
        std.debug.print("native backend test skipped: it needs root\n", .{});
        return error.SkipZigTest;
    }
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.images = try testImage(arena, &tmp, "zr-test/tool:1",
        \\{"config":{"Env":["PATH=/usr/bin:/bin"]}}
    );
    // /github is the runner user's in the provisioned image (`set_up.provision_runner_script`),
    try tmp.dir.createDirPath(io, "rootfs/github");
    const github = try std.fmt.allocPrintSentinel(arena, "{s}/github", .{cfg.rootfs}, 0);
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.chown(github, 1001, 1001));
    // and /tmp is everyone's, for the runner user's step scripts.
    const tmp_dir = try std.fmt.allocPrintSentinel(arena, "{s}/tmp", .{cfg.rootfs}, 0);
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.chmod(tmp_dir, 0o1777));

    var s1 = testStep("echo kept > kept.txt");
    s1.name = "job";
    const s2 = dockerStep("zr-test/tool:1", &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"id -u; echo made > made.txt; mkdir sub; " ++
            "echo x > sub/f; ln -s /etc/passwd link; echo changed >> kept.txt\"" } },
    });
    const s3 = testStep("id -u; echo more >> made.txt && echo more >> sub/f && " ++
        "echo more >> kept.txt && stat -c 'owner %u' made.txt sub sub/f kept.txt . && " ++
        "stat -c 'link %u' /etc/passwd");
    const job = testJob(&.{ s1, s2, s3 });

    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{
        .native = cfg,
        .step_user = .runner,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    errdefer std.debug.print("{s}\n", .{text});
    for (res.steps) |st| try std.testing.expectEqual(dagger.Outcome.success, st.outcome);
    // The action ran as root, the step after it as the runner user, and every file the action
    // made or changed is the runner user's; the symlink's target was not followed.
    try std.testing.expect(std.mem.indexOf(u8, text, "step 2 stdout] 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "step 3 stdout] 1001") != null);
    try std.testing.expectEqual(@as(usize, 5), std.mem.count(u8, text, "owner 1001"));
    try std.testing.expect(std.mem.indexOf(u8, text, "link 0") != null);

    // The action as the job's first step makes the file commands' directory, as root: the
    // runner user's step after it still writes its own there (runner-bench's e2e `docker` job).
    const first = dockerStep("zr-test/tool:1", &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"echo FROM_DOCKER=yes >> $GITHUB_ENV\"" } },
    });
    const after = testStep("test \"$FROM_DOCKER\" = yes && echo v=1 >> \"$GITHUB_OUTPUT\" && " ++
        "echo wrote its output");
    var w2: std.Io.Writer.Allocating = .init(arena);
    var log2: sink.LogSink = .{ .stdout = .{ .writer = &w2.writer } };
    const res2 = try dagger.run(arena, io, &env, .{
        .native = cfg,
        .step_user = .runner,
        .gpa = std.testing.allocator,
    }, testJob(&.{ first, after }), &log2);
    errdefer std.debug.print("{s}\n", .{w2.written()});
    for (res2.steps) |st| try std.testing.expectEqual(dagger.Outcome.success, st.outcome);
    try std.testing.expect(std.mem.indexOf(u8, w2.written(), "wrote its output") != null);
}

test "unsupported: a docker:// step that never runs pulls nothing and decides nothing" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testImage(arena, &tmp, "zr-test/root:1", "{\"config\":{\"User\":\"0:0\"}}");
    _ = try testImage(arena, &tmp, "zr-test/user:1", "{\"config\":{\"User\":\"actionuser\"}}");
    const missing = "zr-test/missing:1 is not in";
    const Case = struct { condition: []const u8, image: []const u8, why: ?[]const u8 };
    for ([_]Case{
        // Never true: not looked at, whether the image is missing or a user's.
        .{ .condition = "false", .image = "zr-test/missing:1", .why = null },
        .{ .condition = "${{ 1 == 2 }}", .image = "zr-test/missing:1", .why = null },
        .{ .condition = "false", .image = "zr-test/user:1", .why = null },
        // It may run, whatever the job's state or contexts say: judged as before.
        .{ .condition = "success()", .image = "zr-test/missing:1", .why = missing },
        .{ .condition = "failure()", .image = "zr-test/missing:1", .why = missing },
        .{ .condition = "github.event_name == 'push'", .image = "zr-test/missing:1", .why = missing },
        .{ .condition = "hashFiles('x') == 'y'", .image = "zr-test/missing:1", .why = missing },
        .{ .condition = "true", .image = "zr-test/root:1", .why = null },
    }) |c| {
        var s = dockerStep(c.image, &.{});
        s.condition = c.condition;
        // A step after it, which runs: the one that decides.
        const job = testJob(&.{ s, dockerStep("zr-test/root:1", &.{}) });
        const why = try unsupported(arena, std.testing.allocator, std.testing.io, job, .{ .images = dir });
        errdefer std.debug.print("{s}: {?s}\n", .{ c.condition, why });
        if (c.why) |want| {
            try std.testing.expect(std.mem.indexOf(u8, why.?, want) != null);
        } else try std.testing.expect(why == null);
    }
}

test "a job whose docker:// step never runs stays native, though its image cannot be pulled" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.images = try testImage(arena, &tmp, "zr-test/tool:1",
        \\{"config":{"Env":["PATH=/usr/bin:/bin"],"Entrypoint":["/bin/sh","-c"],"Cmd":["echo ran in image"]}}
    );
    var dead = dockerStep("zr-test/missing:1", &.{});
    dead.condition = "false";
    // The step that runs follows, so a job the pre-check leaves to the native backend runs it.
    const job = testJob(&.{ dead, dockerStep("zr-test/tool:1", &.{}) });
    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, std.testing.io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    errdefer std.debug.print("{s}\n", .{text});
    try std.testing.expectEqual(dagger.Outcome.skipped, res.steps[0].outcome);
    try std.testing.expectEqual(dagger.Outcome.success, res.steps[1].outcome);
    try std.testing.expect(std.mem.indexOf(u8, text, "Engine: native") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "This job runs on Dagger") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ran in image") != null);
}

test "an image's USER, as Docker resolves it, as ids the job reaches" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    // The user is in the upper layer; the group file is the lower one's.
    try tmp.dir.createDirPath(io, "lower/etc");
    try tmp.dir.createDirPath(io, "upper/etc");
    try tmp.dir.writeFile(io, .{ .sub_path = "lower/etc/passwd", .data = "app:x:7:7::/h:/bin/sh\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "lower/etc/group", .data = "staff:x:50:app,actionuser\nuser:x:1501:\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "upper/etc/passwd", .data = "actionuser:x:1500:1500::/home/a:/bin/sh\n" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const stack = [_][]const u8{
        try std.fmt.allocPrint(arena, "{s}/upper", .{root}),
        try std.fmt.allocPrint(arena, "{s}/lower", .{root}),
    };
    // A name the top layer has; its file hides the lower one's, so `app` is not there.
    const named = (try resolveUser(arena, &stack, "actionuser")).ok;
    try std.testing.expectEqual(@as(u32, 1500), named.uid);
    try std.testing.expectEqual(@as(u32, 1500), named.gid);
    try std.testing.expectEqualSlices(u32, &.{50}, named.groups);
    try std.testing.expect((try resolveUser(arena, &stack, "app")) == .refused);
    // A number the image does not list is Docker's too: gid 0 unless one is given.
    const bare = (try resolveUser(arena, &stack, "4000")).ok;
    try std.testing.expectEqual(@as(u32, 4000), bare.uid);
    try std.testing.expectEqual(@as(u32, 0), bare.gid);
    const both = (try resolveUser(arena, &stack, "4000:1501")).ok;
    try std.testing.expectEqual(@as(u32, 1501), both.gid);
    // Past the job's ids: not native, whoever the user is.
    try std.testing.expect((try resolveUser(arena, &stack, "70000")) == .refused);
    try std.testing.expect((try resolveUser(arena, &stack, "1:70000")) == .refused);
}

test "on a root runner, a Docker action as the image's USER writes the workspace and file commands" {
    if (std.os.linux.geteuid() != 0) {
        std.debug.print("native backend test skipped: it needs root\n", .{});
        return error.SkipZigTest;
    }
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.images = try testImage(arena, &tmp, "zr-test/user:1",
        \\{"config":{"User":"actionuser","Env":["PATH=/usr/bin:/bin"]}}
    );
    // The image's own files: the user's home is theirs, and /etc/group names a group of theirs.
    const base = try std.fmt.allocPrint(arena, "images/{s}/rootfs", .{try images.key(arena, "zr-test/user:1")});
    try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/etc/passwd", .{base}),
        .data = "root:x:0:0:root:/root:/bin/sh\nactionuser:x:1500:1500::/home/actionuser:/bin/sh\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/etc/group", .{base}),
        .data = "root:x:0:\nactionuser:x:1500:\nstaff:x:50:actionuser\n",
    });
    try tmp.dir.createDirPath(io, try std.fmt.allocPrint(arena, "{s}/home/actionuser", .{base}));
    const image_home = try std.fmt.allocPrintSentinel(arena, "{s}/{s}/rootfs/home/actionuser", .{
        cfg.images,
        try images.key(arena, "zr-test/user:1"),
    }, 0);
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.chown(image_home, 1500, 1500));
    // /github is the runner user's in the provisioned image, /tmp is everyone's.
    try tmp.dir.createDirPath(io, "rootfs/github");
    const github = try std.fmt.allocPrintSentinel(arena, "{s}/github", .{cfg.rootfs}, 0);
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.chown(github, 1001, 1001));
    const tmp_dir = try std.fmt.allocPrintSentinel(arena, "{s}/tmp", .{cfg.rootfs}, 0);
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.chmod(tmp_dir, 0o1777));

    for ([_]struct { user: runner_config.StepUser, job: u32 }{
        .{ .user = .runner, .job = 1001 },
        .{ .user = .root, .job = 0 },
    }) |c| {
        var s1 = testStep("echo kept > kept.txt; mkdir keep-dir; echo in-dir > keep-dir/f");
        s1.name = "job";
        // As the image's user: it reads and changes what the job made, makes its own files and
        // directories, writes its file commands and /github/home, has its group, and writes
        // nothing of the image but its own home.
        const s2 = dockerStep("zr-test/user:1", &.{
            .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
            .{ .name = "args", .value = .{ .lit = "-c \"echo ids=$(id -u):$(id -g):$(id -G); " ++
                "cat kept.txt keep-dir/f; echo changed >> kept.txt; echo made > made.txt; " ++
                "mkdir sub; echo x > sub/f; echo said=hi >> $GITHUB_OUTPUT; " ++
                "echo FROM_ACTION=yes >> $GITHUB_ENV; echo HOME=$HOME; touch /github/home/h; " ++
                "echo mine >> /home/actionuser/f; rm keep-dir/f; " ++
                "test -w /etc/passwd || echo etc not writable; test -s /github/workflow/event.json " ++
                "&& echo event\"" } },
        });
        // The job's user after it: every file is theirs, the action's included.
        const s3 = testStep("id -u; echo more >> made.txt && echo more >> sub/f && " ++
            "echo more >> kept.txt && stat -c 'owner %u' made.txt sub sub/f kept.txt . && " ++
            "stat -c 'home %u' /github/home/h && test \"$FROM_ACTION\" = yes && echo env ok; " ++
            "ls keep-dir | wc -l");
        const job = testJob(&.{ s1, s2, s3 });

        var env: std.process.Environ.Map = .init(arena);
        var w: std.Io.Writer.Allocating = .init(arena);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
        const res = try dagger.run(arena, io, &env, .{
            .native = cfg,
            .step_user = c.user,
            .gpa = std.testing.allocator,
        }, job, &log);
        const text = w.written();
        errdefer std.debug.print("{s}\n", .{text});
        for (res.steps) |st| try std.testing.expectEqual(dagger.Outcome.success, st.outcome);
        try std.testing.expect(std.mem.indexOf(u8, text, "Engine: native") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "ids=1500:1500:1500 50") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "HOME=/github/home") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "etc not writable") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "event") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "env ok") != null);
        const owner = try std.fmt.allocPrint(arena, "owner {d}", .{c.job});
        try std.testing.expectEqual(@as(usize, 5), std.mem.count(u8, text, owner));
        const home_owner = try std.fmt.allocPrint(arena, "home {d}", .{c.job});
        try std.testing.expect(std.mem.indexOf(u8, text, home_owner) != null);

        // The action as the job's first step, as the image's user: its file commands are
        // applied, and the job's user's step after it writes its own beside them.
        const first = dockerStep("zr-test/user:1", &.{
            .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
            .{ .name = "args", .value = .{ .lit = "-c \"echo FROM_DOCKER=yes >> $GITHUB_ENV\"" } },
        });
        const after = testStep("test \"$FROM_DOCKER\" = yes && echo v=1 >> \"$GITHUB_OUTPUT\" && " ++
            "echo wrote its output");
        var w2: std.Io.Writer.Allocating = .init(arena);
        var log2: sink.LogSink = .{ .stdout = .{ .writer = &w2.writer } };
        const res2 = try dagger.run(arena, io, &env, .{
            .native = cfg,
            .step_user = c.user,
            .gpa = std.testing.allocator,
        }, testJob(&.{ first, after }), &log2);
        errdefer std.debug.print("{s}\n", .{w2.written()});
        for (res2.steps) |st| try std.testing.expectEqual(dagger.Outcome.success, st.outcome);
        try std.testing.expect(std.mem.indexOf(u8, w2.written(), "wrote its output") != null);
    }
}

test "an ADD of the machine's own address is refused by its written form" {
    for ([_][]const u8{
        "http://127.0.0.1/x",   "http://127.0.0.1:8080/x",   "http://localhost/x", "https://LOCALHOST:9/x",
        "http://a.localhost/x", "http://[::1]:80/x",         "http://[::]/x",      "http://169.254.169.254/latest",
        "http://0.0.0.0:1/",    "http://user:pw@127.1.2.3/", "http://[fe80::1]/x", "http://[::ffff:127.0.0.1]/x",
        "http://127.0.0.1",
    }) |u| try std.testing.expect(hostIsLocal(u));
    for ([_][]const u8{
        "https://example.com/x",  "http://10.0.0.5/x",               "http://192.168.1.1:80/", "http://8.8.8.8/",
        "http://[2001:db8::1]/x", "https://localhost.example.com/x", "http://172.17.0.1/x",
    }) |u| try std.testing.expect(!hostIsLocal(u));
}

fn sleepsLong(io: std.Io) error{Never}!u32 {
    io.sleep(.fromSeconds(60), .awake) catch return 7;
    return 1;
}

test "a task tied to a flag ends when it is set, however long the work would wait" {
    const io = std.testing.io;
    var flag: std.atomic.Value(bool) = .init(false);
    const Setter = struct {
        fn run(f: *std.atomic.Value(bool)) void {
            var ts: std.os.linux.timespec = .{ .sec = 0, .nsec = 300_000_000 };
            _ = std.os.linux.nanosleep(&ts, null);
            f.store(true, .release);
        }
    };
    const t0 = std.Io.Clock.awake.now(io);
    const th = try std.Thread.spawn(.{}, Setter.run, .{&flag});
    defer th.join();
    try std.testing.expectError(error.Cancelled, cancellable(error{Never}!u32, io, &flag, sleepsLong, .{io}));
    try std.testing.expect(t0.durationTo(std.Io.Clock.awake.now(io)).toSeconds() < 5);
    // Already set: not even started. Not tied: called as is.
    try std.testing.expectError(error.Cancelled, cancellable(error{Never}!u32, io, &flag, sleepsLong, .{io}));
    const quick = struct {
        fn f() error{Never}!u32 {
            return 3;
        }
    }.f;
    try std.testing.expectEqual(@as(u32, 3), try try cancellable(error{Never}!u32, io, null, quick, .{}));
}

test "a fetch from a server that never answers ends when the build's flag is set" {
    const linux = std.os.linux;
    const io = std.testing.io;
    // A listener that accepts and says nothing (the connection is the kernel's, never read).
    const lfd_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(lfd_rc) != .SUCCESS) return error.SkipZigTest;
    const lfd = std.math.cast(linux.fd_t, lfd_rc) orelse return error.SkipZigTest;
    defer _ = linux.close(lfd);
    var any: extern union { base: linux.sockaddr, in: linux.sockaddr.in } = .{ .in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) } };
    if (linux.errno(linux.bind(lfd, &any.base, @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (linux.errno(linux.listen(lfd, 4)) != .SUCCESS) return error.SkipZigTest;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(lfd, &any.base, &len)) != .SUCCESS) return error.SkipZigTest;
    const port = std.mem.bigToNative(u16, any.in.port);
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const url = try std.fmt.allocPrint(a.allocator(), "http://127.0.0.1:{d}/x", .{port});
    var flag: std.atomic.Value(bool) = .init(false);
    const Setter = struct {
        fn run(f: *std.atomic.Value(bool)) void {
            var ts: std.os.linux.timespec = .{ .sec = 0, .nsec = 400_000_000 };
            _ = std.os.linux.nanosleep(&ts, null);
            f.store(true, .release);
        }
    };
    const th = try std.Thread.spawn(.{}, Setter.run, .{&flag});
    defer th.join();
    const t0 = std.Io.Clock.awake.now(io);
    const got = cancellable(net_client.Error!net_client.Response, io, &flag, net_client.fetch, .{ a.allocator(), io, net_client.Options{
        .url = url,
        .first_byte = .fromSeconds(120),
        .read_idle = .fromSeconds(120),
        .deadline = .fromSeconds(600),
    } });
    try std.testing.expectError(error.Cancelled, got);
    try std.testing.expect(t0.durationTo(std.Io.Clock.awake.now(io)).toSeconds() < 10);
}
