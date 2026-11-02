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

const Allocator = std.mem.Allocator;

/// `Exec.loadAction`'s key for an action, so the loaded ones fill its map.
pub fn key(arena: Allocator, u: job_mod.Uses) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}/{s}@{s}", .{ u.owner, u.name, u.path, u.ref });
}

/// Fetches and reads every remote action of `job` into `b.actions`, and says why the job cannot
/// run natively, or null. An action that cannot be fetched or read is not a reason: native
/// "Set up job" fails with it, as Dagger's would.
pub fn preload(b: *Backend, job: job_mod.Job) !?[]const u8 {
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
    if (u.local) return "local actions (`uses: ./...`) are read once the workspace is checked " ++
        "out, after the job's backend is chosen";
    if (depth > max_depth) return null;
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
    switch (act.meta.runs) {
        .node => return try std.fmt.allocPrint(arena, "{s} is a JavaScript action, and native " ++
            "steps have no JavaScript runtime yet", .{act.ref_label}),
        .docker => |dk| {
            if (std.mem.startsWith(u8, dk.image, "docker://"))
                return imageReason(b, dk.image["docker://".len..]);
            const from = if (act.sub.len > 0) act.sub else ".";
            const rel = try std.fs.path.resolvePosix(arena, &.{ from, dk.image });
            return docker_action.buildReason(b, .{
                .dir = act.dir,
                .context = std.fs.path.dirnamePosix(rel) orelse ".",
                .dockerfile = std.fs.path.basenamePosix(rel),
            }, act.ref_label);
        },
        .composite => |steps| for (steps) |st| {
            const text = st.uses orelse continue;
            const parsed = action.parseUses(text) orelse continue;
            switch (parsed) {
                .docker => |image| if (try imageReason(b, image)) |why| return why,
                .local => return "a composite action uses a local action, read from the " ++
                    "workspace after the job's backend is chosen",
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

    // Below the base's layer, and not with the container's env: git gets what it needs here.
    var env: std.ArrayList([]const u8) = .empty;
    try env.appendSlice(arena, &.{
        "PATH=" ++ Backend.image_path,
        "HOME=/root",
        "GIT_TERMINAL_PROMPT=0",
    });
    // The repository was made by another user (the fetch is the job's root, a file:// source is
    // the host's): git's ownership check would refuse to read it.
    var config: std.ArrayList([2][]const u8) = .empty;
    try config.append(arena, .{ "safe.directory", "*" });
    if (std.mem.eql(u8, repository, job.github.repository) and job.job_token.len > 0) {
        const basic = try std.fmt.allocPrint(arena, "x-access-token:{s}", .{job.job_token});
        const enc = std.base64.standard.Encoder;
        const b64 = try arena.alloc(u8, enc.calcSize(basic.len));
        try config.append(arena, .{
            try std.fmt.allocPrint(arena, "http.{s}/.extraheader", .{server}),
            try std.fmt.allocPrint(arena, "AUTHORIZATION: basic {s}", .{enc.encode(b64, basic)}),
        });
    }
    try env.append(arena, try std.fmt.allocPrint(arena, "GIT_CONFIG_COUNT={d}", .{config.items.len}));
    for (config.items, 0..) |c, i| {
        try env.append(arena, try std.fmt.allocPrint(arena, "GIT_CONFIG_KEY_{d}={s}", .{ i, c[0] }));
        try env.append(arena, try std.fmt.allocPrint(arena, "GIT_CONFIG_VALUE_{d}={s}", .{ i, c[1] }));
    }
    var out: Backend.Captured = .{ .arena = arena };
    const ended = try b.execOn(&.{ "sh", "-c", aw.written() }, env.items, &.{}, 0, 0, out.output(), null);
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
        .{ .step = local, .why = "local actions" },
        .{ .step = usesStep("f", "o", "far", "v1", &.{}), .why = "zr-test/other:1 is not in the tests' images directory" },
        .{ .step = usesStep("m", "o", "multi", "v1", &.{}), .why = "line 1: multi-stage" },
        // One that cannot be fetched is not a reason: native "Set up job" fails with it.
        .{ .step = usesStep("n", "o", "nope", "v1", &.{}), .why = null },
    }) |c| {
        var job = testJob(&.{c.step});
        job.github.server_url = "file:///srv/git";
        var b = try Backend.init(arena, std.testing.io, std.testing.allocator, cfg);
        defer b.deinit();
        const why = try preload(&b, job);
        if (c.why) |want| {
            errdefer std.debug.print("got: {?s}\n", .{why});
            try std.testing.expect(std.mem.indexOf(u8, why orelse "", want) != null);
        } else try std.testing.expect(why == null);
    }
}
