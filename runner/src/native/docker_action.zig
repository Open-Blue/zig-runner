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
const sandbox = @import("sandbox.zig");
const images = @import("images.zig");
const Exec = @import("../dagger/Exec.zig");
const SpanDemux = @import("../dagger/JobLog.zig").SpanDemux;
const scripts = @import("../dagger/scripts.zig");

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

/// Why a job's Docker actions cannot run natively yet, or null: each `docker://` step's image
/// must be pulled natively (P3, `find`) and run as root. `Backend.unsupported` leaves these steps
/// to this, since it needs the image's config.
pub fn unsupported(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    job: job_mod.Job,
    cfg: Backend.Config,
) !?[]const u8 {
    for (job.steps) |step| switch (step.action) {
        .docker => |d| switch (try find(arena, gpa, io, cfg.images, cfg.store, d.image)) {
            .missing => |why| return why,
            // GitHub's documentation asks for root ("Docker actions must be run by the default
            // Docker user"); Dagger's path gives another USER the directories it writes, which
            // here would be an idmapped share of the workspace.
            .image => |img| if (!images.runsAsRoot(img.user)) return try std.fmt.allocPrint(
                arena,
                "the image {s} runs as USER {s}, and native Docker actions run as root only " ++
                    "yet",
                .{ d.image, img.user },
            ),
        },
        else => {},
    };
    return null;
}

/// `ref`'s image: pulled natively into the store at `store` (P3, `Backend.pullAt`), or from the
/// tests' directory when `dir` is set (`images.lookup`). A pull that fails is `missing`, with why.
pub fn find(
    arena: Allocator,
    gpa: Allocator,
    io: std.Io,
    dir: []const u8,
    store: []const u8,
    ref: []const u8,
) !images.Found {
    if (dir.len > 0) return images.lookup(arena, io, dir, ref);
    var why: []const u8 = "";
    const owners = std.os.linux.geteuid() == 0;
    const img = Backend.pullAt(arena, gpa, io, store, owners, ref, null, &why) catch |e|
        return .{ .missing = try std.fmt.allocPrint(arena, "the image {s} could not be pulled " ++
            "natively: {s}", .{ ref, if (why.len > 0) why else @errorName(e) }) };
    return .{ .image = images.fromPulled(arena, io, img.rootfs, img.digest) catch
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
    const ref = switch (dr.image) {
        .pull => |r| r,
        // Only `uses:` actions are built, and they are not native yet (`Backend.unsupported`).
        .build => |bd| {
            _ = try x.actionFailed(num, "could not build {s} of {s}: native steps do not " ++
                "build Dockerfiles yet", .{ bd.dockerfile, dr.label });
            return null;
        },
    };
    const img = switch (try find(arena, b.gpa, b.io, b.images_dir, b.store_cfg.root, ref)) {
        .image => |i| i,
        .missing => |why| {
            _ = try x.actionFailed(num, "could not pull {s} for {s}: {s}", .{ ref, dr.label, why });
            return null;
        },
    };
    if (!images.runsAsRoot(img.user)) {
        _ = try x.actionFailed(num, "{s}: the image runs as USER {s}; native Docker actions " ++
            "run as root only yet", .{ dr.label, img.user });
        return null;
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
    });
    try files.append(arena, .{
        .path = dagger.event_path,
        .contents = try x.ev.eventJson(),
        .mode = 0o644,
        .keep = true,
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
    const ended = try b.execOn(argv, env, files.items, 0, 0, out, .{
        .rootfs = img.rootfs,
        .upper = upper,
        .work = "CW",
        .merged = "C",
        .shares = try shares(arena, x.ev.workspace),
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
    if (b.how.userns == .mapped and b.uid != 0) for (try shares(arena, x.ev.workspace)) |sh|
        ownShared(b.io, layer, sh.from, b.idBase() + b.uid, b.idBase() + b.gid);
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
/// each after a `::zig-file-command::<kind>` line and followed by a newline, read from the step's
/// layer (one the action removed is empty, as the script's `>>` makes it), then the `ran` marker,
/// empty with the step cache off. Each is read inside the layer, through no symlink.
fn combined(arena: Allocator, layer: []const u8, fc: u32) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    for (scripts.fc_kinds) |k| {
        const text = switch (try sandbox.readIn(arena, layer, try scripts.fcPath(arena, k, fc), Backend.max_read)) {
            .text => |t| t,
            .missing, .whiteout => "",
        };
        try w.print(scripts.fc_marker ++ "{s}\n{s}\n", .{ k, text });
    }
    try w.writeAll(scripts.fc_marker ++ "ran\n\n");
    return aw.written();
}

// --- tests ---

const sink = @import("../sink.zig");
const testStep = @import("../dagger/testing.zig").testStep;
const testJob = @import("../dagger/testing.zig").testJob;

/// An image in the native store at `<tmp>/images`, as `images.zig` reads it: a rootfs of a few
/// directories (the tests bind the host's /usr over it, as over the job's) holding
/// `/image-marker`, and `config` as its config.json.
fn testImage(arena: Allocator, tmp: *std.testing.TmpDir, ref: []const u8, config: []const u8) ![]const u8 {
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
