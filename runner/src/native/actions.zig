//! `uses:` actions on the native backend (docs/native-backend.md, P7): each remote action fetched
//! by git in the job's image into the job's layers, at the path Dagger mounts it
//! (`/github/_actions/<owner>/<repo>/<ref>`), and its `action.yml` read from there.
//!
//! Which backend runs a job is decided before the job starts, for the whole job (never per step:
//! the steps after a switch would need the native layers exported into Dagger). What a `uses:`
//! action is, though, is in its `action.yml`. So `preload` fetches every remote action the job
//! uses, its composite actions' nested ones too, before "Set up job", with nothing logged, and
//! says why the job cannot be native when one of them is something native cannot run yet; the
//! job then goes to Dagger, which fetches them again. Otherwise "Set up job" takes the loaded
//! actions from the Backend (`Exec.loadAction`) and logs them as Dagger's would be.
//!
//! What runs natively: Docker actions, with a `docker://` image from the native image store or
//! built from their Dockerfile (`docker_action.zig`, `dockerfile.zig`), and composite actions,
//! whose steps are scripts, nested actions and checkouts like the job's. JavaScript actions need
//! a JavaScript runtime mounted in the job's image, which the Dagger path takes from its own
//! image; they send the job to Dagger, as local actions (`uses: ./path`) do: those are read from
//! the workspace once a step has checked it out, after the choice.

const std = @import("std");
const job_mod = @import("../job.zig");
const action = @import("../action.zig");
const dagger = @import("../dagger.zig");
const Backend = @import("Backend.zig");
const sandbox = @import("sandbox.zig");
const images = @import("images.zig");
const docker_action = @import("docker_action.zig");
const Exec = @import("../dagger/Exec.zig");
const js = @import("../dagger/js.zig");
const config = @import("../config.zig");

const Allocator = std.mem.Allocator;

/// `Exec.loadAction`'s key for an action, so the loaded ones fill its map.
pub fn key(arena: Allocator, u: job_mod.Uses) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}/{s}@{s}", .{ u.owner, u.name, u.path, u.ref });
}

/// Fetches and reads every remote action of `job` into `b.actions`, and says why the job cannot
/// run natively, or null. An action that cannot be fetched or read is not a reason: native
/// "Set up job" fails with it, as Dagger's would.
pub fn preload(b: *Backend, job: job_mod.Job, js_runtime: config.JsRuntime) !?[]const u8 {
    b.js_runtime = js_runtime;
    for (job.steps) |step| switch (step.action) {
        .uses => |u| if (try reasonFor(b, job, u, 0)) |why| return why,
        else => {},
    };
    return null;
}

/// GitHub nests composite actions at most this deep (`actions.max_composite_depth`).
const max_depth = 10;

fn reasonFor(b: *Backend, job: job_mod.Job, u: job_mod.Uses, depth: u32) anyerror!?[]const u8 {
    const arena = b.arena;
    if (depth > max_depth) return null;
    if (u.local) return localReason(b, job, u.path, depth);
    const k = try key(arena, u);
    const lr = b.actions.get(k) orelse lr: {
        const fetched = fetch(b, job, u) catch |e| switch (e) {
            error.NoGit => return "the job's image has no git to fetch its actions with " ++
                "natively (Dagger fetches them with its own)",
            else => return e,
        };
        try b.actions.put(arena, k, fetched);
        break :lr fetched;
    };
    const act = switch (lr) {
        .ok => |a| a,
        .failed, .unresolved => return null,
    };
    return judge(b, job, act.meta, act.ref_label, .{
        .dir = act.dir,
        .sub = act.sub,
    }, depth);
}

/// Where a fetched action's Dockerfile is, for `docker_action.buildReason`; null for a local
/// action, whose tree is only in the workspace.
const Tree = struct { dir: []const u8, sub: []const u8 };

/// Why an action with metadata `meta` cannot run natively, or null.
fn judge(
    b: *Backend,
    job: job_mod.Job,
    meta: action.Metadata,
    label: []const u8,
    tree: ?Tree,
    depth: u32,
) anyerror!?[]const u8 {
    const arena = b.arena;
    switch (meta.runs) {
        // The runtime from the image store, as Dagger takes it from its image (`js.zig`).
        .node => {
            // The musl build on a musl image (`container: alpine`), as `js.zig` mounts it.
            const rt = (if (b.isMusl()) js.runtimes_musl else js.runtimes).get(b.js_runtime);
            return switch (try docker_action.find(arena, b.gpa, b.io, b.images_dir, b.store_cfg.root, rt.image)) {
                .image => null,
                .missing => |why| try std.fmt.allocPrint(arena, "{s} is a JavaScript action, " ++
                    "and its runtime is not here: {s}", .{ label, why }),
            };
        },
        .docker => |dk| {
            if (std.mem.startsWith(u8, dk.image, "docker://"))
                return imageReason(b, dk.image["docker://".len..]);
            const t = tree orelse return try std.fmt.allocPrint(arena, "{s} is built from a " ++
                "Dockerfile in the workspace, which native steps build only from a fetched " ++
                "action yet", .{label});
            const from = if (t.sub.len > 0) t.sub else ".";
            const rel = try std.fs.path.resolvePosix(arena, &.{ from, dk.image });
            return docker_action.buildReason(b, .{
                .dir = t.dir,
                .context = std.fs.path.dirnamePosix(rel) orelse ".",
                .dockerfile = std.fs.path.basenamePosix(rel),
            }, label);
        },
        .composite => |steps| for (steps) |st| {
            const text = st.uses orelse continue;
            const parsed = action.parseUses(text) orelse continue;
            switch (parsed) {
                .docker => |image| if (try imageReason(b, image)) |why| return why,
                .local => |raw| {
                    const dir = job_mod.localActionPath(raw) orelse continue;
                    if (try localReason(b, job, dir, depth + 1)) |why| return why;
                },
                .repo => |r| {
                    const checkout = std.ascii.eqlIgnoreCase(r.owner, "actions") and
                        std.ascii.eqlIgnoreCase(r.name, "checkout") and r.path.len == 0;
                    if (checkout) continue;
                    const nested: job_mod.Uses = .{
                        .owner = r.owner,
                        .name = r.name,
                        .path = r.path,
                        .ref = r.ref,
                        .inputs = &.{},
                    };
                    if (try reasonFor(b, job, nested, depth + 1)) |why| return why;
                },
            }
        },
    }
    return null;
}

/// A local action (`uses: ./<path>`) judged from the job's own repository at the job's commit,
/// which is what a checkout of it puts in the workspace: its `action.yml` read by git in the
/// job's image, without the rest of the tree (a blobless fetch of that one commit). The step
/// itself reads the workspace, as on Dagger (`loadLocal`). One that is not in the repository at
/// that commit (made by a step, or another repository checked out there) sends the job to
/// Dagger, since nothing can be known of it before the job.
fn localReason(b: *Backend, job: job_mod.Job, path: []const u8, depth: u32) anyerror!?[]const u8 {
    const arena = b.arena;
    const label = try std.fmt.allocPrint(arena, "./{s}", .{path});
    const not_known = try std.fmt.allocPrint(arena, "the local action {s} is not in {s} at " ++
        "{s}, so what it is cannot be known before the job", .{ label, job.github.repository, job.github.sha });
    if (job.github.repository.len == 0 or job.github.sha.len == 0) return not_known;
    const text = (try readOwn(b, job, path)) orelse return not_known;
    const meta = switch (try action.parse(arena, text)) {
        .ok => |m| m,
        // The step reads it again and fails with why, as on Dagger.
        .invalid => return null,
    };
    return judge(b, job, meta, label, null, depth);
}

/// `<path>/action.yml` (or `.yaml`) of the job's repository at its commit, or null.
fn readOwn(b: *Backend, job: job_mod.Job, path: []const u8) !?[]const u8 {
    const arena = b.arena;
    const server = std.mem.trimEnd(u8, job.github.server_url, "/");
    b.preflights += 1;
    const out_path = try std.fmt.allocPrint(arena, "/tmp/zig-runner-preflight-{d}.yml", .{b.preflights});
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("set -e\nd=$(mktemp -d)\ntrap 'rm -rf \"$d\"' EXIT\ncd \"$d\"\ngit init -q\n" ++
        "git remote add origin ");
    try dagger.shellQuote(w, try std.fmt.allocPrint(arena, "{s}/{s}.git", .{ server, job.github.repository }));
    try w.writeAll("\ngit -c protocol.version=2 fetch -q --depth=1 --filter=blob:none --no-tags origin ");
    try dagger.shellQuote(w, job.github.sha);
    try w.writeAll("\nfor f in action.yml action.yaml; do\n  if git cat-file -e FETCH_HEAD:");
    try dagger.shellQuote(w, try std.fmt.allocPrint(arena, "{s}{s}", .{ path, if (path.len > 0) "/" else "" }));
    try w.writeAll("\"$f\" 2>/dev/null; then git cat-file -p FETCH_HEAD:");
    try dagger.shellQuote(w, try std.fmt.allocPrint(arena, "{s}{s}", .{ path, if (path.len > 0) "/" else "" }));
    try w.print("\"$f\" > {s}; exit 0; fi\ndone\nexit 3\n", .{out_path});
    var out: Backend.Captured = .{ .arena = arena };
    const ended = try b.execOn(&.{ "sh", "-c", aw.written() }, try gitEnv(b, job, true), &.{}, 0, 0, out.output(), null);
    const layer = try b.layerPath(b.layers.items.len - 1);
    // Its layer is a look, nothing the job keeps: dropped, so it leaves no unkeyed layer below
    // the base, and the job's steps keep their keys (P2).
    defer b.dropTop();
    if (ended.failure.len > 0 or ended.code != 0) return null;
    return switch (try sandbox.readIn(arena, layer, out_path, Backend.max_read)) {
        .text => |t| t,
        .missing, .whiteout => null,
    };
}

/// `Exec.loadLocal` on this backend: the local action's `action.yml` read from the workspace as
/// the job's last step left it, layer by layer through no symlink (`Backend.readFile`), with
/// Dagger's messages. Its files are in the job's layers already: nothing is mounted.
pub fn loadLocal(b: *Backend, x: *Exec, u: job_mod.Uses) !Exec.LoadResult {
    const arena = b.arena;
    const abs = if (u.path.len > 0)
        try std.fmt.allocPrint(arena, "{s}/{s}", .{ x.ev.workspace, u.path })
    else
        x.ev.workspace;
    const label = try std.fmt.allocPrint(arena, "./{s}", .{u.path});
    for ([_][]const u8{ "action.yml", "action.yaml" }) |name| {
        const text = b.readFile(try std.fmt.allocPrint(arena, "{s}/{s}", .{ abs, name })) orelse continue;
        const meta = switch (try action.parse(arena, text)) {
            .ok => |m| m,
            .invalid => |why| return .{ .failed = try std.fmt.allocPrint(
                arena,
                "{s} of {s} {s}",
                .{ name, label, why },
            ) },
        };
        try x.mounted_actions.put(arena, abs, {});
        return .{ .ok = .{ .meta = meta, .dir = "native", .mount = abs, .path = abs, .ref_label = label } };
    }
    return .{ .failed = try std.fmt.allocPrint(
        arena,
        "Can't find 'action.yml' or 'action.yaml' under '{s}'. Did you forget to run " ++
            "actions/checkout before running your local action?",
        .{abs},
    ) };
}

fn imageReason(b: *Backend, image: []const u8) !?[]const u8 {
    return switch (try docker_action.find(b.arena, b.gpa, b.io, b.images_dir, b.store_cfg.root, image)) {
        .missing => |why| why,
        .image => |img| if (images.runsAsRoot(img.user)) null else try std.fmt.allocPrint(
            b.arena,
            "the image {s} runs as USER {s}, and native Docker actions run as root only yet",
            .{ image, img.user },
        ),
    };
}

/// git's environment in the job's image before the base is made (the container's env is not set
/// yet): its PATH and HOME, no prompt, and its config through the environment, never a command
/// line: the job's token for the job's own repository (`own`), as Dagger's `git` has it, and
/// `safe.directory` (the fetch is the job's root's; a file:// source is the host's, and git's
/// ownership check would refuse to read it).
fn gitEnv(b: *Backend, job: job_mod.Job, own: bool) ![]const []const u8 {
    const arena = b.arena;
    const server = std.mem.trimEnd(u8, job.github.server_url, "/");
    var env: std.ArrayList([]const u8) = .empty;
    try env.appendSlice(arena, &.{
        "PATH=" ++ Backend.image_path,
        "HOME=/root",
        "GIT_TERMINAL_PROMPT=0",
    });
    var git_config: std.ArrayList([2][]const u8) = .empty;
    try git_config.append(arena, .{ "safe.directory", "*" });
    if (own and job.job_token.len > 0) {
        const basic = try std.fmt.allocPrint(arena, "x-access-token:{s}", .{job.job_token});
        const enc = std.base64.standard.Encoder;
        const b64 = try arena.alloc(u8, enc.calcSize(basic.len));
        try git_config.append(arena, .{
            try std.fmt.allocPrint(arena, "http.{s}/.extraheader", .{server}),
            try std.fmt.allocPrint(arena, "AUTHORIZATION: basic {s}", .{enc.encode(b64, basic)}),
        });
    }
    try env.append(arena, try std.fmt.allocPrint(arena, "GIT_CONFIG_COUNT={d}", .{git_config.items.len}));
    for (git_config.items, 0..) |c, i| {
        try env.append(arena, try std.fmt.allocPrint(arena, "GIT_CONFIG_KEY_{d}={s}", .{ i, c[0] }));
        try env.append(arena, try std.fmt.allocPrint(arena, "GIT_CONFIG_VALUE_{d}={s}", .{ i, c[1] }));
    }
    return env.items;
}

/// The action's repository fetched at its ref into a new layer of the job, as the built-in
/// checkout fetches (`Backend.fetchCheckout`): only the commit, with the job's token for the job's
/// own repository and anonymously for others, as the Dagger path fetches. `Loaded.dir` is the
/// repository's host directory in that layer, for a Dockerfile's build context.
fn fetch(b: *Backend, job: job_mod.Job, u: job_mod.Uses) !Exec.LoadResult {
    const arena = b.arena;
    const repository = try std.fmt.allocPrint(arena, "{s}/{s}", .{ u.owner, u.name });
    const sub = if (u.path.len > 0) try std.fmt.allocPrint(arena, "/{s}", .{u.path}) else "";
    const ref_label = try std.fmt.allocPrint(arena, "{s}{s}@{s}", .{ repository, sub, u.ref });
    const mount = try std.fmt.allocPrint(arena, "/github/_actions/{s}/{s}", .{ repository, u.ref });
    const server = std.mem.trimEnd(u8, job.github.server_url, "/");
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll("set -e\nmkdir -p ");
    try dagger.shellQuote(w, mount);
    try w.writeAll(" && cd ");
    try dagger.shellQuote(w, mount);
    try w.writeAll("\ngit init -q\ngit remote add origin ");
    try dagger.shellQuote(w, try std.fmt.allocPrint(arena, "{s}/{s}.git", .{ server, repository }));
    try w.writeAll("\ngit -c protocol.version=2 fetch -q --depth=1 --no-tags origin ");
    try dagger.shellQuote(w, u.ref);
    try w.writeAll("\ngit checkout -q --detach FETCH_HEAD\nrm -f .git/FETCH_HEAD\n" ++
        "git rev-parse HEAD\n");

    const env = try gitEnv(b, job, std.mem.eql(u8, repository, job.github.repository));
    var out: Backend.Captured = .{ .arena = arena };
    const ended = try b.execOn(&.{ "sh", "-c", aw.written() }, env, &.{}, 0, 0, out.output(), null);
    // `sh` found no git in the image (any image is native since P3, not only the provisioned
    // default one): Dagger fetches with git of its own.
    if (ended.failure.len == 0 and ended.code == 127) return error.NoGit;
    if (ended.failure.len > 0 or ended.code != 0) return .{ .unresolved = try std.fmt.allocPrint(
        arena,
        "Unable to resolve action `{s}`: {s}",
        .{ ref_label, if (ended.failure.len > 0) ended.failure else out.tail() },
    ) };
    const sha = out.tail();
    // The tree is the commit's, whoever fetched it and when: keyed so, the base and the steps
    // above it keep their keys from job to job (`Backend.keyFetched`).
    if (sha.len == 40) try b.keyFetched(try std.fmt.allocPrint(arena, "an action's tree: {s}/{s}.git " ++
        "at {s} in {s}", .{ server, repository, sha, mount }));

    const layer = try b.layerPath(b.layers.items.len - 1);
    const dir = try std.fmt.allocPrint(arena, "{s}{s}", .{ layer, mount });
    const path = try std.fs.path.resolvePosix(arena, &.{ mount, u.path });
    var name: []const u8 = "action.yml";
    const text = for ([_][]const u8{ "action.yml", "action.yaml" }) |n| {
        const p = try std.fmt.allocPrint(arena, "{s}/{s}", .{ path, n });
        switch (try sandbox.readIn(arena, layer, p, Backend.max_read)) {
            .text => |t| {
                name = n;
                break t;
            },
            .missing, .whiteout => {},
        }
    } else return .{ .failed = try std.fmt.allocPrint(
        arena,
        "{s} has no action.yml or action.yaml",
        .{ref_label},
    ) };
    const meta = switch (try action.parse(arena, text)) {
        .ok => |m| m,
        .invalid => |why| return .{ .failed = try std.fmt.allocPrint(
            arena,
            "{s} of {s} {s}",
            .{ name, ref_label, why },
        ) },
    };
    return .{ .ok = .{
        .meta = meta,
        .dir = dir,
        .mount = mount,
        .path = path,
        .sub = u.path,
        .ref_label = ref_label,
        .sha = if (sha.len == 40) sha else "",
        .repository = repository,
        .ref = u.ref,
    } };
}

// --- tests ---

const sink = @import("../sink.zig");
const testStep = @import("../dagger/testing.zig").testStep;
const testJob = @import("../dagger/testing.zig").testJob;
const usesStep = @import("../dagger/testing.zig").usesStep;

/// A repository `o/<name>` at `<tmp>/git/o/<name>.git`, bare, holding `files` in one commit
/// tagged `v1`: what the job fetches as `file:///srv/git/o/<name>.git` (`testActions`).
fn testRepo(arena: Allocator, tmp: *std.testing.TmpDir, name: []const u8, files: []const [2][]const u8) !void {
    const io = std.testing.io;
    const work = try std.fmt.allocPrint(arena, "work/{s}", .{name});
    try tmp.dir.createDirPath(io, work);
    for (files) |f| try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work, f[0] }),
        .data = f[1],
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    try tmp.dir.createDirPath(io, "git/o");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const script = try std.fmt.allocPrint(arena,
        \\set -e
        \\cd '{s}/{s}'
        \\git init -q -b main . && git add -A
        \\git -c user.name=t -c user.email=t@t commit -q -m one && git tag v1
        \\git clone -q --bare . '{s}/git/o/{s}.git'
    , .{ root, work, root, name });
    const res = try std.process.run(arena, io, .{ .argv = &.{ "sh", "-c", script } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}\n", .{res.stderr});
        return error.GitFailed;
    }
}

/// A native backend whose jobs fetch actions from `<tmp>/git`, bound in at /srv/git, with
/// `zr-test/base:1` in the image store.
fn testActions(arena: Allocator, tmp: *std.testing.TmpDir) !Backend.Config {
    var cfg = try Backend.testConfig(arena, tmp);
    cfg.images = try docker_action.testImage(arena, tmp, "zr-test/base:1",
        \\{"config":{"Env":["PATH=/usr/bin:/bin"]}}
    );
    const io = std.testing.io;
    try tmp.dir.createDirPath(io, "rootfs/srv/git");
    try tmp.dir.createDirPath(io, "git");
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    cfg.binds = try std.mem.concat(arena, sandbox.Spec.Bind, &.{ cfg.binds, &.{.{
        .host = try std.fmt.allocPrint(arena, "{s}/git", .{root}),
        .at = "/srv/git",
    }} });
    return cfg;
}

test "uses: actions natively: a Dockerfile action built in layers, an image action, a composite one" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testActions(arena, &tmp);
    try testRepo(arena, &tmp, "dock", &.{
        .{
            "action.yml",
            \\inputs:
            \\  who:
            \\    default: nobody
            \\runs:
            \\  using: docker
            \\  image: Dockerfile
            \\  args:
            \\    - ${{ inputs.who }}
        },
        .{
            "Dockerfile",
            \\FROM zr-test/base:1
            \\COPY entrypoint.sh /entrypoint.sh
            \\RUN chmod 755 /entrypoint.sh && echo built-by-run > /built
            \\ENTRYPOINT ["/entrypoint.sh"]
        },
        .{ "entrypoint.sh", "#!/bin/sh\necho \"hello $1 from $(cat /built) in $PWD\"\n" ++
            "echo greeting=hi >> \"$GITHUB_OUTPUT\"\n" },
    });
    try testRepo(arena, &tmp, "img", &.{.{
        "action.yml",
        \\inputs:
        \\  x: {}
        \\runs:
        \\  using: docker
        \\  image: docker://zr-test/base:1
        \\  entrypoint: sh
        \\  args: ["-c", "echo image action $INPUT_X"]
    }});
    try testRepo(arena, &tmp, "comp", &.{.{
        "action.yml",
        \\inputs:
        \\  v: {}
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - shell: bash
        \\      run: echo composite ${{ inputs.v }} at ${{ github.action_path }}
        \\    - uses: o/img@v1
        \\      with:
        \\        x: nested
    }});

    const who = [_]job_mod.Input{.{ .name = "who", .value = .{ .lit = "world" } }};
    const v = [_]job_mod.Input{.{ .name = "v", .value = .{ .lit = "7" } }};
    var s2 = testStep("echo OUT=$OUT");
    s2.env = &.{.{ .name = "OUT", .value = .{ .expr = "steps.dock.outputs.greeting" } }};
    const steps = [_]job_mod.Step{
        usesStep("dock", "o", "dock", "v1", &who),
        s2,
        usesStep("comp", "o", "comp", "v1", &v),
        // Built again: every layer from the store.
        usesStep("again", "o", "dock", "v1", &who),
    };
    var job = testJob(&steps);
    job.github.server_url = "file:///srv/git";

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
    for (res.steps) |st| try std.testing.expectEqual(dagger.Outcome.success, st.outcome);
    const expect = [_][]const u8{
        "Engine: native",
        "Download action repository 'o/dock@v1' (SHA:",
        "Download action repository 'o/comp@v1' (SHA:",
        "image: built from Dockerfile",
        "hello world from built-by-run in /github/workspace",
        "OUT=hi",
        "composite 7 at /github/_actions/o/comp/v1",
        "image action nested",
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s}\n", .{e});
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, text, "from built-by-run"));
    // The two layers the build made (the COPY and the RUN), stored once by their keys.
    const io = std.testing.io;
    var dir = try std.Io.Dir.cwd().openDir(io, try std.fmt.allocPrint(arena, "{s}/layers", .{cfg.store}), .{ .iterate = true });
    defer dir.close(io);
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (!std.mem.startsWith(u8, e.name, ".new-")) n += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), n);
}

test "a job with an action keeps its steps cached: the action's tree is keyed by its commit" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testActions(arena, &tmp);
    try testRepo(arena, &tmp, "comp", &.{.{
        "action.yml",
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - shell: bash
        \\      run: echo composite step
    }});
    const steps = [_]job_mod.Step{ usesStep("comp", "o", "comp", "v1", &.{}), testStep("echo after the action") };
    var job = testJob(&steps);
    job.github.server_url = "file:///srv/git";
    var texts: [2][]const u8 = undefined;
    for (&texts, [_][]const u8{ "ran-1", "ran-2" }) |*text, ran| {
        var env: std.process.Environ.Map = .init(arena);
        var w: std.Io.Writer.Allocating = .init(arena);
        var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
        const res = try dagger.run(arena, std.testing.io, &env, .{
            .native = cfg,
            .step_user = .root,
            .step_cache = true,
            .test_ran_marker = ran,
            .gpa = std.testing.allocator,
        }, job, &log);
        text.* = w.written();
        errdefer std.debug.print("{s}\n", .{text.*});
        try std.testing.expect(std.mem.indexOf(u8, text.*, "Engine: native") != null);
        for (res.steps) |st| try std.testing.expectEqual(dagger.Outcome.success, st.outcome);
    }
    // Fetched again by the second job, the same commit: the same key, so the base and the steps
    // above it are the first job's. Unkeyed, nothing above the fetch was ever replayed.
    errdefer std.debug.print("first:\n{s}\nsecond:\n{s}\n", .{ texts[0], texts[1] });
    try std.testing.expect(std.mem.indexOf(u8, texts[0], dagger.native_reused_note) == null);
    try std.testing.expect(std.mem.count(u8, texts[1], dagger.native_reused_note) >= 1);
    try std.testing.expect(std.mem.indexOf(u8, texts[1], "after the action") != null);
}

test "preload: a JavaScript action, a local one, or an image not in the store sends the job to Dagger" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testActions(arena, &tmp);
    try testRepo(arena, &tmp, "js", &.{.{ "action.yml", "runs:\n  using: node20\n  main: index.js\n" }});
    try testRepo(arena, &tmp, "far", &.{.{ "action.yml", "runs:\n  using: docker\n  image: docker://zr-test/other:1\n" }});
    try testRepo(arena, &tmp, "multi", &.{
        .{ "action.yml", "runs:\n  using: docker\n  image: Dockerfile\n" },
        .{ "Dockerfile", "FROM zr-test/base:1 AS build\nFROM zr-test/base:1\n" },
    });
    const Case = struct { step: job_mod.Step, why: ?[]const u8 };
    var local = testStep("");
    local.action = .{ .uses = .{ .owner = "", .name = "", .path = "act", .ref = "", .local = true } };
    for ([_]Case{
        .{ .step = usesStep("j", "o", "js", "v1", &.{}), .why = "o/js@v1 is a JavaScript action" },
        .{ .step = local, .why = "is not in o/r at" },
        .{ .step = usesStep("f", "o", "far", "v1", &.{}), .why = "zr-test/other:1 is not in the tests' images directory" },
        .{ .step = usesStep("m", "o", "multi", "v1", &.{}), .why = "line 1: multi-stage" },
        // One that cannot be fetched is not a reason: native "Set up job" fails with it.
        .{ .step = usesStep("n", "o", "nope", "v1", &.{}), .why = null },
    }) |c| {
        var job = testJob(&.{c.step});
        job.github.server_url = "file:///srv/git";
        var b = try Backend.init(arena, std.testing.io, std.testing.allocator, cfg);
        defer b.deinit();
        const why = try preload(&b, job, .bun);
        if (c.why) |want| {
            errdefer std.debug.print("got: {?s}\n", .{why});
            try std.testing.expect(std.mem.indexOf(u8, why orelse "", want) != null);
        } else try std.testing.expect(why == null);
    }
}

test "JavaScript actions natively: pre, main and post with their inputs, state, outputs and post-if" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try testActions(arena, &tmp);
    // The runtime's image, as `js.runtimes` names it, with a stand-in for Bun that runs the
    // "JavaScript" as a shell script: what is tested is everything around the runtime.
    const rt = js.runtimes.get(.bun);
    cfg.images = try docker_action.testImage(arena, &tmp, rt.image, "{}");
    const bin = try std.fmt.allocPrint(arena, "images/{s}/rootfs{s}", .{ try images.key(arena, rt.image), rt.binary });
    try tmp.dir.createDirPath(io, std.fs.path.dirnamePosix(bin).?);
    try tmp.dir.writeFile(io, .{
        .sub_path = bin,
        .data = "#!/bin/sh\nexec /bin/sh \"$@\"\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    try testRepo(arena, &tmp, "js", &.{
        .{
            "action.yml",
            \\inputs:
            \\  who:
            \\    default: nobody
            \\runs:
            \\  using: node24
            \\  pre: pre.js
            \\  main: main.js
            \\  post: post.js
            \\  post-if: success()
        },
        .{ "pre.js", "echo \"pre $INPUT_WHO\"; echo phase=pre >> \"$GITHUB_STATE\"\n" },
        .{ "main.js", "echo \"main $INPUT_WHO state=$STATE_phase repo=$GITHUB_ACTION_REPOSITORY " ++
            "node=$(command -v node) npx=$(command -v npx)\"\n" ++
            "echo out=42 >> \"$GITHUB_OUTPUT\"; echo phase=main >> \"$GITHUB_STATE\"\n" },
        .{ "post.js", "echo \"post state=$STATE_phase\"\n" },
    });
    try testRepo(arena, &tmp, "jsno", &.{
        .{ "action.yml", "runs:\n  using: node20\n  main: main.js\n  post: post.js\n  post-if: failure()\n" },
        .{ "main.js", "echo second main\n" },
        .{ "post.js", "echo never\n" },
    });
    const who = [_]job_mod.Input{.{ .name = "who", .value = .{ .lit = "world" } }};
    var s2 = testStep("echo OUT=$OUT");
    s2.env = &.{.{ .name = "OUT", .value = .{ .expr = "steps.js.outputs.out" } }};
    var job = testJob(&.{ usesStep("js", "o", "js", "v1", &who), s2, usesStep("no", "o", "jsno", "v1", &.{}) });
    job.github.server_url = "file:///srv/git";

    var env: std.process.Environ.Map = .init(arena);
    var w: std.Io.Writer.Allocating = .init(arena);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    const res = try dagger.run(arena, io, &env, .{
        .native = cfg,
        .step_user = .root,
        .gpa = std.testing.allocator,
    }, job, &log);
    const text = w.written();
    errdefer std.debug.print("{s}\n", .{text});
    try std.testing.expect(res.succeeded);
    const expect = [_][]const u8{
        "Engine: native",
        "pre world",
        "main world state=pre repo=o/js node=/github/_runtime/bin/node npx=/github/_runtime/bin/npx",
        "OUT=42",
        "second main",
        "post state=main",
    };
    for (expect) |e| if (std.mem.indexOf(u8, text, e) == null) {
        std.debug.print("missing {s}\n", .{e});
        return error.TestUnexpectedResult;
    };
    try std.testing.expect(std.mem.indexOf(u8, text, "never") == null);
}

/// The job's own repository `o/r` with `files`, served so a job can fetch its commit by sha with
/// no blobs (a checkout, `readOwn`); its commit.
fn ownRepo(arena: Allocator, tmp: *std.testing.TmpDir, files: []const [2][]const u8) ![]const u8 {
    try testRepo(arena, tmp, "r", files);
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
    const script = try std.fmt.allocPrint(arena,
        \\set -e
        \\cd '{s}/git/o/r.git'
        \\git config uploadpack.allowFilter true
        \\git config uploadpack.allowAnySHA1InWant true
        \\git rev-parse v1
    , .{root});
    const res = try std.process.run(arena, std.testing.io, .{ .argv = &.{ "sh", "-c", script } });
    if (res.term != .exited or res.term.exited != 0) return error.GitFailed;
    return std.mem.trim(u8, res.stdout, "\n");
}

test "local actions natively: judged from the job's commit before the job, read from the workspace in it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg = try testActions(arena, &tmp);
    try tmp.dir.createDirPath(std.testing.io, "work/r/.github/actions/hello");
    try tmp.dir.createDirPath(std.testing.io, "work/r/.github/actions/img");
    try tmp.dir.createDirPath(std.testing.io, "work/r/.github/actions/built");
    const sha = try ownRepo(arena, &tmp, &.{
        .{
            ".github/actions/hello/action.yml",
            \\inputs:
            \\  x: {}
            \\runs:
            \\  using: composite
            \\  steps:
            \\    - shell: bash
            \\      run: echo local composite ${{ inputs.x }}
            \\    - uses: ./.github/actions/img
        },
        .{
            ".github/actions/img/action.yml",
            \\runs:
            \\  using: docker
            \\  image: docker://zr-test/base:1
            \\  entrypoint: sh
            \\  args: ["-c", "echo local image action in $PWD"]
        },
        .{ ".github/actions/built/action.yml", "runs:\n  using: docker\n  image: Dockerfile\n" },
        .{ ".github/actions/built/Dockerfile", "FROM zr-test/base:1\n" },
    });
    const x = [_]job_mod.Input{.{ .name = "x", .value = .{ .lit = "yes" } }};
    var co = testStep("");
    co.action = .{ .checkout = &.{} };
    var hello = testStep("");
    hello.action = .{ .uses = .{ .owner = "", .name = "", .path = ".github/actions/hello", .ref = "", .inputs = &x, .local = true } };
    var job = testJob(&.{ co, hello });
    job.github.server_url = "file:///srv/git";
    job.github.sha = sha;

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
    try std.testing.expect(res.succeeded);
    for ([_][]const u8{ "Engine: native", "local composite yes", "local image action in /github/workspace" }) |e|
        if (std.mem.indexOf(u8, text, e) == null) {
            std.debug.print("missing {s}\n", .{e});
            return error.TestUnexpectedResult;
        };

    // Not at the job's commit, or built from a Dockerfile in the workspace: to Dagger.
    const Case = struct { path: []const u8, why: []const u8 };
    for ([_]Case{
        .{ .path = "made/by/a/step", .why = "is not in o/r at" },
        .{ .path = ".github/actions/built", .why = "Dockerfile in the workspace" },
    }) |c| {
        var st = testStep("");
        st.action = .{ .uses = .{ .owner = "", .name = "", .path = c.path, .ref = "", .local = true } };
        var j = testJob(&.{st});
        j.github.server_url = "file:///srv/git";
        j.github.sha = sha;
        var b = try Backend.init(arena, std.testing.io, std.testing.allocator, cfg);
        defer b.deinit();
        const why = try preload(&b, j, .bun);
        errdefer std.debug.print("got: {?s}\n", .{why});
        try std.testing.expect(std.mem.indexOf(u8, why orelse "", c.why) != null);
    }
}
