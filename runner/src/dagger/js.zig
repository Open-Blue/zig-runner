//! JavaScript actions (`runs.using: node*`): the runtime (Bun by default, or Node) taken from its
//! image with its shims, the action's script run with its inputs and the runtime services, and
//! Node again for code Bun refuses to load.

const std = @import("std");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const expr = @import("../expr.zig");
const action = @import("../action.zig");
const config = @import("../config.zig");
const Query = @import("query.zig").Query;
const Exec = @import("Exec.zig");
const Mount = @import("../dagger.zig").Mount;
const SecretRef = @import("../dagger.zig").SecretRef;
const run = @import("../dagger.zig").run;
const gql = @import("../dagger.zig").gql;
const idOf = @import("../dagger.zig").idOf;
const shellQuote = @import("../dagger.zig").shellQuote;
const inputEnv = @import("../dagger.zig").inputEnv;
const shownInputs = @import("../dagger.zig").shownInputs;
const splitEnv = @import("../dagger.zig").splitEnv;
const scriptRun = @import("../dagger.zig").scriptRun;
const ActionOut = @import("Exec.zig").ActionOut;
const Loaded = @import("Exec.zig").Loaded;
const Phase = @import("Exec.zig").Phase;
const ContainerEnv = @import("docker.zig").ContainerEnv;
const FakeSession = @import("testing.zig").FakeSession;
const fake_child = @import("testing.zig").fake_child;
const base_answer = @import("testing.zig").base_answer;
const exec = @import("testing.zig").exec;
const testStep = @import("testing.zig").testStep;
const testJob = @import("testing.zig").testJob;
const treeAnswer = @import("testing.zig").treeAnswer;
const fileAnswer = @import("testing.zig").fileAnswer;
const usesStep = @import("testing.zig").usesStep;
const braceBalanced = @import("testing.zig").braceBalanced;

const Allocator = std.mem.Allocator;
const Backend = @import("../native/Backend.zig");
const docker_action = @import("../native/docker_action.zig");

/// JavaScript actions run with this binary, named `node` so that Bun behaves as Node. The shim on
/// PATH answers `node --version`, which Bun named `node` does not handle, and runs the binary
/// otherwise, so actions that start `node` themselves get the same runtime.
const runtime_path = "/github/_runtime/node/node";
const bin_dir = "/github/_runtime/bin";
const shim_path = bin_dir ++ "/node";
const node_shim =
    \\#!/bin/sh
    \\case "$1" in -v|--version) exec /github/_runtime/node/node -p process.version ;; esac
    \\exec /github/_runtime/node/node "$@"
    \\
;

/// `npx` for actions that run a package's binary (FirebaseExtended/action-hosting-deploy runs
/// `npx firebase-tools@<version> ...`). With Bun it is `bun x`, whose progress goes to stderr, so a
/// tool's stdout (often JSON the action parses) stays clean. Bun has no `npm`.
const bun_path = "/github/_runtime/node/bun";
const npx_bun_shim =
    \\#!/bin/sh
    \\case "$1" in -y|--yes) shift ;; esac
    \\exec /github/_runtime/node/bun x "$@"
    \\
;
/// With Node, npm's own package (from the same image) provides `npx` and `npm`.
const npm_dir = "/github/_runtime/npm";
const npx_node_shim =
    \\#!/bin/sh
    \\exec /github/_runtime/node/node /github/_runtime/npm/bin/npx-cli.js "$@"
    \\
;
const npm_node_shim =
    \\#!/bin/sh
    \\exec /github/_runtime/node/node /github/_runtime/npm/bin/npm-cli.js "$@"
    \\
;

/// The ids of a JavaScript runtime's files in its image: the binary (`bin`), npm when the runtime
/// ships it (`npm`), and on musl the C++ runtime it needs (`libs`).
fn runtimeQuery(arena: Allocator, rt: RuntimeSource, musl: bool) ![]const u8 {
    var q: Query = .init(arena);
    try q.open("container");
    try q.call("from", .{ .address = rt.image });
    try q.callAs("bin", "file", .{ .path = rt.binary });
    try q.leaf("id");
    try q.close(1);
    if (rt.npm_dir) |npm| {
        try q.callAs("npm", "directory", .{ .path = npm });
        try q.leaf("id");
        try q.close(1);
    }
    if (musl) {
        try q.callAs("libs", "directory", .{ .path = "/usr/lib" });
        try q.call("filter", .{ .include = &[_][]const u8{ "libstdc++.so*", "libgcc_s.so*" } });
        try q.leaf("id");
        try q.close(2);
    }
    return q.finish();
}

/// The ids of a runtime's files (`runtimeQuery`'s answer): from Dagger, or on the native backend
/// the files' host paths in the native store, the image pulled by P3 (`docker_action.find`), as
/// `host:<path>` ids that the native backend binds (`Backend.applyMounts`), nosuid and nodev. On
/// musl (any image is native since P3: `container: alpine`), the musl runtime with its C++ runtime
/// (`libs`), as Dagger's query filters it from the image's /usr/lib. Null with `msg` when the
/// image cannot be had.
fn runtimeFiles(x: *Exec, rt: RuntimeSource, msg: *[]const u8) !?std.json.Value {
    const arena = x.arena;
    const b = x.native orelse
        return gql(arena, x.transport, try runtimeQuery(arena, rt, x.musl), msg) catch null;
    // P3's pull (or the tests' images directory), as Dagger pulls the runtime's image.
    const img = switch (try docker_action.find(arena, b.gpa, b.io, b.images_dir, b.store_cfg.root, rt.image)) {
        .image => |i| i,
        .missing => |why| {
            msg.* = why;
            return null;
        },
    };
    var obj: std.json.ObjectMap = .empty;
    const id = struct {
        fn f(ar: Allocator, rootfs: []const u8, path: []const u8) !std.json.Value {
            var o: std.json.ObjectMap = .empty;
            try o.put(ar, "id", .{ .string = try std.fmt.allocPrint(ar, "{s}{s}{s}", .{
                Backend.host_id,
                rootfs,
                path,
            }) });
            return .{ .object = o };
        }
    }.f;
    try obj.put(arena, "bin", try id(arena, img.rootfs, rt.binary));
    if (rt.npm_dir) |npm| try obj.put(arena, "npm", try id(arena, img.rootfs, npm));
    if (x.musl) {
        const libs = cxxRuntime(arena, b.io, b.dir, img.rootfs, rt.image) catch |e| {
            msg.* = try std.fmt.allocPrint(arena, "its C++ runtime could not be taken: {s}", .{
                @errorName(e),
            });
            return null;
        };
        try obj.put(arena, "libs", try id(arena, libs, ""));
    }
    return .{ .object = obj };
}

/// The C++ runtime a musl runtime needs (`libstdc++.so*`, `libgcc_s.so*`), copied from its
/// image's /usr/lib into a directory of the job's own, as Dagger's `filter` takes them: binding the
/// whole /usr/lib would put the image's other libraries on the runtime's library path. Its
/// symlinks are copied as symlinks (they name their neighbours), nothing is followed out of it.
fn cxxRuntime(
    arena: Allocator,
    io: std.Io,
    job_dir: []const u8,
    rootfs: []const u8,
    image: []const u8,
) ![]const u8 {
    const out = try std.fmt.allocPrint(arena, "{s}/JSLIB-{x}", .{ job_dir, std.hash.Wyhash.hash(0, image) });
    const cwd = std.Io.Dir.cwd();
    cwd.deleteTree(io, out) catch {};
    try cwd.createDirPath(io, out);
    var to = try cwd.openDir(io, out, .{});
    defer to.close(io);
    const lib = try std.fmt.allocPrint(arena, "{s}/usr/lib", .{rootfs});
    var from = try cwd.openDir(io, lib, .{ .iterate = true, .follow_symlinks = false });
    defer from.close(io);
    var it = from.iterate();
    var found = false;
    while (try it.next(io)) |e| {
        if (!std.mem.startsWith(u8, e.name, "libstdc++.so") and
            !std.mem.startsWith(u8, e.name, "libgcc_s.so")) continue;
        switch (e.kind) {
            .sym_link => {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const n = try from.readLink(io, e.name, &buf);
                try to.symLink(io, buf[0..n], e.name, .{});
            },
            .file => try from.copyFile(e.name, to, e.name, io, .{ .permissions = .fromMode(0o755) }),
            else => continue,
        }
        found = true;
    }
    if (!found) return error.NoCxxRuntime;
    return out;
}

/// Runs the musl Node with its own C++ runtime first on the library path.
const node_fallback_wrapper = "#!/bin/sh\nLD_LIBRARY_PATH=" ++ fallback_dir ++
    "/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH} exec " ++ fallback_dir ++ "/node-musl \"$@\"\n";

fn fileMount(path: []const u8, id: []const u8) Mount {
    return .{ .file = .{ .path = path, .id = id, .permissions = 0o755 } };
}

fn newFileMount(path: []const u8, contents: []const u8) Mount {
    return .{ .new_file = .{ .path = path, .contents = contents, .permissions = 0o755 } };
}

pub const RuntimeSource = struct {
    image: []const u8,
    binary: []const u8,
    npm_dir: ?[]const u8 = null,
};
/// Bun is pinned to the version the repository's images use (see api/Dockerfile).
pub const runtimes: std.EnumArray(config.JsRuntime, RuntimeSource) = .init(.{
    .bun = .{ .image = "oven/bun:1.4.3", .binary = "/usr/local/bin/bun" },
    .node = .{
        .image = "node:24-bookworm-slim",
        .binary = "/usr/local/bin/node",
        .npm_dir = "/usr/local/lib/node_modules/npm",
    },
});
/// For a musl job image (`container: alpine`): the runtimes' Alpine builds, which also need the
/// C++ runtime from their image (mounted at `lib_dir`).
pub const runtimes_musl: std.EnumArray(config.JsRuntime, RuntimeSource) = .init(.{
    .bun = .{ .image = "oven/bun:1.4.3-alpine", .binary = "/usr/local/bin/bun" },
    .node = .{
        .image = "node:24-alpine",
        .binary = "/usr/local/bin/node",
        .npm_dir = "/usr/local/lib/node_modules/npm",
    },
});
const lib_dir = "/github/_runtime/lib";
const musl_dir = "/github/_runtime/musl";

/// Node, for JavaScript actions Bun refuses to load when Bun is the runtime (see
/// `bun_load_errors`).
const fallback_dir = "/github/_runtime/fallback";
const fallback_path = fallback_dir ++ "/node";

/// On musl, `runtime_path` (and `bun_path`) start the binary with its C++ runtime found.
fn muslWrapper(arena: Allocator, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "#!/bin/sh\nLD_LIBRARY_PATH=" ++ lib_dir ++ "${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}} " ++
            "exec " ++ musl_dir ++ "/{s} \"$@\"\n",
        .{name},
    );
}

/// Runs a JavaScript action's `main` with the configured runtime (Bun by default, see SPEC §6).
pub fn runJs(
    x: *Exec,
    num: u32,
    act: Loaded,
    u: job_mod.Uses,
    nd: @FieldType(action.Runs, "node"),
    inputs: []const expr.Value.Entry,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
) !ActionOut {
    const out = (try x.runJsScript(
        num,
        .main,
        act,
        u,
        nd.main,
        inputs,
        step_env,
        step_secret,
        try x.preState(num),
    )) orelse
        return .{ .failed = true, .exit_code = 1 };
    // Its `post` runs after the job's steps, with the inputs and the state saved so far.
    if (nd.post) |post| try x.posts.append(x.arena, .{
        .num = num,
        .name = try x.extraName("Post", num, act),
        .act = act,
        .u = u,
        .script = post,
        .condition = nd.post_if orelse "always()",
        .inputs = inputs,
        .step_env = step_env,
        .step_secret = step_secret,
        .state = try std.mem.concat(
            x.arena,
            job_mod.EnvVar,
            &.{ try x.preState(num), out.state },
        ),
    });
    return .{ .failed = out.code != 0, .exit_code = out.code, .outputs = out.outputs };
}

/// Runs one of a JavaScript action's scripts (`pre`, `main` or `post`, relative to the action's
/// directory) with the configured runtime (Bun by default, see SPEC §6). `state` reaches it as
/// STATE_<name>. Null when the runtime could not be set up (the reason is logged).
pub fn runJsScript(
    x: *Exec,
    num: u32,
    phase: Phase,
    act: Loaded,
    _: job_mod.Uses,
    script_rel: []const u8,
    inputs: []const expr.Value.Entry,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
    state: []const job_mod.EnvVar,
) !?Exec.Out {
    const arena = x.arena;
    var mounts: std.ArrayList(Mount) = .empty;
    if (!x.js_mounted) {
        if (!try x.appendJsRuntimeMounts(num, &mounts)) return null;
    }
    // Mounted once: a later phase sees what an earlier one left in the action's directory.
    const action_dir: Mount = .{
        .dir = .{ .path = act.mount, .id = act.dir, .owner = x.dir_owner },
    };
    if (!x.mounted_actions.contains(act.mount)) try mounts.append(arena, action_dir);
    const env = try x.jsEnv(act, inputs, state, step_env, step_secret);

    // GitHub folds the action's inputs at the start of its main step; its pre and post steps
    // start with their output.
    const shown = try shownInputs(arena, inputs);
    if (phase == .main)
        try x.logGroup(num, phase, act.ref_label, shown, step_env, step_secret, &.{});

    const script = try command(arena, runtime_path, act, script_rel);
    const fc = x.next_fc;
    x.next_fc += 1;
    // What the first try starts from and uses up, should Node have to run it again.
    const before = x.container_id;
    const pending_env = try arena.dupe(job_mod.EnvVar, x.ev.pending_env.items);
    const pending_path = try arena.dupe([]const u8, x.ev.pending_path.items);
    const path_prepend = try arena.dupe([]const u8, x.ev.path_prepend.items);
    const name = if (act.repository.len > 0) act.repository else act.ref_label;
    const resolved = scriptRun(script, env.plain);
    const out = try x.execScript(num, fc, resolved, name, env.secret, mounts.items);
    x.js_mounted = true;
    try x.mounted_actions.put(arena, act.mount, {});
    if (!out.bun_refused or x.js_runtime != .bun) return out;

    // Bun refused the action's code before running any of it, so running it again with Node
    // repeats nothing. The second try starts where the first did, not from the refused exec:
    // with step caching that exec always runs (it has the job token), and starting from it
    // would keep every later step from being replayed.
    x.sh.append(num, "Bun could not load this action's code; running it with Node instead.");
    const node_mounts = (try x.nodeFallback(num)) orelse return out;
    x.container_id = before;
    x.ev.pending_env.clearRetainingCapacity();
    try x.ev.pending_env.appendSlice(arena, pending_env);
    x.ev.pending_path.clearRetainingCapacity();
    try x.ev.pending_path.appendSlice(arena, pending_path);
    x.ev.path_prepend.clearRetainingCapacity();
    try x.ev.path_prepend.appendSlice(arena, path_prepend);
    const again = scriptRun(try command(arena, fallback_path, act, script_rel), env.plain);
    const fc_again = x.next_fc;
    x.next_fc += 1;
    const all_mounts = try std.mem.concat(arena, Mount, &.{ mounts.items, node_mounts });
    return try x.execScript(num, fc_again, again, name, env.secret, all_mounts);
}

/// The command that runs one of the action's scripts: the runtime at `runtime`, with the
/// shims on PATH, through bash where there is one — dash drops variables whose names are not
/// identifiers (INPUT_GITHUB-TOKEN) when it starts a program; bash, and busybox's sh (Alpine
/// images, which have no bash), pass them on.
fn command(
    arena: Allocator,
    runtime: []const u8,
    act: Loaded,
    script_rel: []const u8,
) ![]const u8 {
    var script: std.Io.Writer.Allocating = .init(arena);
    try script.writer.print("PATH=\"" ++ bin_dir ++ ":$PATH\" exec {s} ", .{runtime});
    try shellQuote(
        &script.writer,
        try std.fmt.allocPrint(arena, "{s}/{s}", .{ act.path, script_rel }),
    );
    return script.written();
}

/// Inputs as INPUT_<NAME> (spaces become underscores, as in @actions/core), the action's
/// location, and the services actions/cache and artifact actions talk to — on top of the step's
/// env, split into plain variables and Dagger secrets.
pub fn jsEnv(
    x: *Exec,
    act: Loaded,
    inputs: []const expr.Value.Entry,
    state: []const job_mod.EnvVar,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
) !ContainerEnv {
    const arena = x.arena;
    var env: std.ArrayList(job_mod.EnvVar) = .empty;
    try env.appendSlice(arena, try inputEnv(arena, inputs));
    try env.append(arena, .{ .name = "GITHUB_ACTION_REPOSITORY", .value = act.repository });
    try env.append(arena, .{ .name = "GITHUB_ACTION_REF", .value = act.ref });
    try x.runtimeEnv(&env, state);
    var plain: std.ArrayList(job_mod.EnvVar) = .empty;
    var secret: std.ArrayList(SecretRef) = .empty;
    try plain.appendSlice(arena, step_env);
    try secret.appendSlice(arena, step_secret);
    splitEnv(
        arena,
        x.transport,
        x.job.*,
        x.sh,
        &x.secrets,
        env.items,
        &plain,
        &secret,
        &x.err_msg,
    ) catch return error.EngineFailed;
    return .{ .plain = plain.items, .secret = secret.items };
}

/// The JavaScript runtime's files, taken from its image once per job: the binary (and on musl
/// its C++ runtime and a wrapper), the `node` shim, and Bun's or Node's CLI with its npx/npm
/// shims. False when the image could not be had: the step has been failed with the reason.
pub fn appendJsRuntimeMounts(x: *Exec, num: u32, mounts: *std.ArrayList(Mount)) !bool {
    const arena = x.arena;
    const rt = (if (x.musl) runtimes_musl else runtimes).get(x.js_runtime);
    var msg: []const u8 = "";
    const data = (try runtimeFiles(x, rt, &msg)) orelse {
        _ = try x.actionFailed(num, "could not get the JavaScript runtime from {s}: {s}", .{
            rt.image,
            msg,
        });
        return false;
    };
    const bin = idOf(data, "bin") orelse {
        _ = try x.actionFailed(num, "could not get the JavaScript runtime from {s}", .{
            rt.image,
        });
        return false;
    };
    if (x.musl) {
        const libs_id = idOf(data, "libs") orelse {
            _ = try x.actionFailed(num, "could not get the C++ runtime from {s}", .{rt.image});
            return false;
        };
        try mounts.append(arena, .{ .dir = .{ .path = lib_dir, .id = libs_id } });
        try mounts.append(arena, fileMount(musl_dir ++ "/node", bin));
        try mounts.append(arena, newFileMount(runtime_path, try muslWrapper(arena, "node")));
    } else try mounts.append(arena, fileMount(runtime_path, bin));
    try mounts.append(arena, newFileMount(shim_path, node_shim));
    switch (x.js_runtime) {
        // The same binary named `bun` is Bun's own CLI, for `bun x`.
        .bun => {
            if (x.musl) {
                try mounts.append(arena, fileMount(musl_dir ++ "/bun", bin));
                const wrapper = try muslWrapper(arena, "bun");
                try mounts.append(arena, newFileMount(bun_path, wrapper));
            } else try mounts.append(arena, fileMount(bun_path, bin));
            try mounts.append(arena, newFileMount(bin_dir ++ "/npx", npx_bun_shim));
        },
        .node => {
            const npm = idOf(data, "npm") orelse {
                _ = try x.actionFailed(num, "could not get npm from {s}", .{rt.image});
                return false;
            };
            try mounts.append(arena, .{ .dir = .{ .path = npm_dir, .id = npm } });
            try mounts.append(arena, newFileMount(bin_dir ++ "/npx", npx_node_shim));
            try mounts.append(arena, newFileMount(bin_dir ++ "/npm", npm_node_shim));
        },
    }
    return true;
}

/// Node at `fallback_path`, for an action Bun cannot load, from the same images as
/// `RUNNER_JS_RUNTIME=node` (with its own C++ runtime on musl). The mounts, once per job; null,
/// with the step failed, when the image could not be had.
pub fn nodeFallback(x: *Exec, num: u32) !?[]const Mount {
    if (x.node_fallback_mounted) return &.{};
    const arena = x.arena;
    const rt = (if (x.musl) runtimes_musl else runtimes).get(.node);
    var msg: []const u8 = "";
    const data = (try runtimeFiles(x, rt, &msg)) orelse {
        _ = try x.actionFailed(num, "could not get Node from {s}: {s}", .{ rt.image, msg });
        return null;
    };
    const bin = idOf(data, "bin") orelse {
        _ = try x.actionFailed(num, "could not get Node from {s}", .{rt.image});
        return null;
    };
    var mounts: std.ArrayList(Mount) = .empty;
    if (x.musl) {
        const libs_id = idOf(data, "libs") orelse {
            _ = try x.actionFailed(num, "could not get the C++ runtime from {s}", .{rt.image});
            return null;
        };
        try mounts.append(
            arena,
            .{ .dir = .{ .path = fallback_dir ++ "/lib", .id = libs_id } },
        );
        try mounts.append(
            arena,
            fileMount(fallback_dir ++ "/node-musl", bin),
        );
        try mounts.append(arena, newFileMount(fallback_path, node_fallback_wrapper));
    } else try mounts.append(
        arena,
        fileMount(fallback_path, bin),
    );
    x.node_fallback_mounted = true;
    return mounts.items;
}

test "a JavaScript action Bun refuses to load runs again with Node" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const action_yml =
        \\runs:
        \\  using: node24
        \\  main: dist/setup/index.js
    ;
    const steps = [_]job_mod.Step{usesStep("sp", "actions", "setup-python", "v7", &.{})};
    const job = testJob(&steps);
    const refused = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":1,\"stdout\":\"\",\"stderr\":\"error: Cannot use import statement with CommonJS-only features\\n\"}}}}";
    const answers = [_][]const u8{
        base_answer,
        try treeAnswer(arena, "D1", &.{ "action.yml", "dist" }),
        try fileAnswer(arena, action_yml),
        "{\"data\":{\"container\":{\"from\":{\"bin\":{\"id\":\"BUN\"}}}}}",
        refused,
        "{\"data\":{\"container\":{\"from\":{\"bin\":{\"id\":\"NODE\"}}}}}",
        try exec(arena, "C2", 0, "set up\\n"),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    const seen = fake.seen.items;
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 7), seen.len);
    for (seen) |d| try std.testing.expect(braceBalanced(d));
    // Bun first; then Node, from the image RUNNER_JS_RUNTIME=node uses, for the same script.
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "exec /github/_runtime/node/node") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[5], "from(address:\"node:24-bookworm-slim\") { bin: file(path:\"/usr/local/bin/node\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "withFile(path:\"/github/_runtime/fallback/node\",source:\"NODE\"") != null);
    // From where the first try started, not from its result, with the action's code mounted again.
    try std.testing.expect(std.mem.startsWith(u8, seen[6], "{ loadContainerFromID(id:\"C0\")"));
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "withDirectory(path:\"/github/_actions/actions/setup-python/v7\",source:\"D1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "exec /github/_runtime/fallback/node ") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "dist/setup/index.js") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "Bun could not load this action's code; running it with Node instead.") != null);
}

test "a JavaScript action that fails for another reason does not run again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);
    const action_yml =
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
    ;
    const steps = [_]job_mod.Step{usesStep("x", "o", "act", "v1", &.{})};
    const job = testJob(&steps);
    const failed = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":1,\"stdout\":\"\",\"stderr\":\"TypeError: x is not a function\\n\"}}}}";
    const answers = [_][]const u8{
        base_answer,
        try treeAnswer(arena, "D1", &.{ "action.yml", "dist" }),
        try fileAnswer(arena, action_yml),
        "{\"data\":{\"container\":{\"from\":{\"bin\":{\"id\":\"BUN\"}}}}}",
        failed,
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(!res.succeeded);
    try std.testing.expectEqual(@as(usize, 5), fake.seen.items.len);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "running it with Node") == null);
}

test "a JavaScript action runs its main with the runtime, inputs as INPUT_*, the runtime services, and the event" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);

    const action_yml =
        \\inputs:
        \\  github-token:
        \\    default: ${{ github.token }}
        \\  script:
        \\    required: true
        \\  result encoding:
        \\    default: json
        \\outputs:
        \\  result:
        \\    description: set by the action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\  post: dist/post.js
    ;
    const inputs = [_]job_mod.Input{.{ .name = "script", .value = .{ .lit = "return 42" } }};
    var after = testStep("");
    after.action.script.script = .{ .expr = "format('echo {0}', steps.gs.outputs.result)" };
    const steps = [_]job_mod.Step{ usesStep("gs", "actions", "github-script", "v9", &inputs), usesStep("again", "actions", "github-script", "v9", &inputs), after };
    var job = testJob(&steps);
    job.secrets = &.{ "ghs_jobtoken", "ghs_secret" };
    job.job_token = "ghs_jobtoken";
    job.secret_vars = &.{.{ .name = "GITHUB_TOKEN", .value = "ghs_secret" }};
    job.runtime = .{ .pipelines_url = "https://pipelines.test/", .cache_url = "https://cache.test/", .results_url = "https://results.test/", .cache_v2 = true };
    const ctx_json =
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"event","v":{"t":2,"d":[{"k":"ref","v":"refs/heads/x"}]}}]}}
    ;
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena, ctx_json, .{});

    const main_with_state = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"id\":\"C1\",\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"fc_output\":{\"contents\":\"result=42\\n\"},\"fc_state\":{\"contents\":\"pid=7\\n\"}}}}}";
    const answers = [_][]const u8{
        base_answer,
        // Every action is fetched at the start of the job (the `pre` pass), as GitHub does, once
        // however many steps use it.
        try treeAnswer(arena, "D1", &.{ "action.yml", "dist" }),
        try fileAnswer(arena, action_yml),
        "{\"data\":{\"container\":{\"from\":{\"bin\":{\"id\":\"BUN\"}}}}}",
        // INPUT_GITHUB-TOKEN and ACTIONS_RUNTIME_TOKEN, in one query, once for the job.
        "{\"data\":{\"zsec0\":{\"id\":\"SEC_TOKEN\"},\"zsec1\":{\"id\":\"SEC_RUNTIME\"}}}",
        main_with_state,
        try exec(arena, "C2", 0, ""),
        try exec(arena, "C3", 0, ""),
        // posts, last step first
        try exec(arena, "C4", 0, ""),
        try exec(arena, "C5", 0, ""),
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);

    const seen = fake.seen.items;
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 10), seen.len);
    for (seen) |d| try std.testing.expect(braceBalanced(d));
    // The event payload is written for GITHUB_EVENT_PATH.
    try std.testing.expect(std.mem.indexOf(u8, seen[0], "withNewFile(path:\"/github/workflow/event.json\",contents:\"{\\n  \\\"ref\\\": \\\"refs/heads/x\\\"\\n}\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[0], "withEnvVariable(name:\"GITHUB_EVENT_PATH\",value:\"/github/workflow/event.json\")") != null);
    // Bun comes from its image, once per job.
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "from(address:\"oven/bun:1.4.3\") { bin: file(path:\"/usr/local/bin/bun\")") != null);
    const run1 = seen[5];
    try std.testing.expect(std.mem.indexOf(u8, run1, "withFile(path:\"/github/_runtime/node/node\",source:\"BUN\",permissions:493)") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withNewFile(path:\"/github/_runtime/bin/node\"") != null);
    // npx is `bun x`, through the same binary named bun.
    try std.testing.expect(std.mem.indexOf(u8, run1, "withFile(path:\"/github/_runtime/node/bun\",source:\"BUN\",permissions:493)") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withNewFile(path:\"/github/_runtime/bin/npx\",contents:\"#!/bin/sh\\ncase \\\"$1\\\" in -y|--yes) shift ;; esac\\nexec /github/_runtime/node/bun x \\\"$@\\\"\\n\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withDirectory(path:\"/github/_actions/actions/github-script/v9\",source:\"D1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "exec /github/_runtime/node/node '\\\\''/github/_actions/actions/github-script/v9/dist/index.js'\\\\''") != null);
    // Inputs: given, defaulted (github.token, a secret, under its hyphenated name), names upper-cased with spaces as underscores.
    try std.testing.expect(std.mem.indexOf(u8, run1, "'INPUT_SCRIPT=return 42'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'INPUT_RESULT_ENCODING=json'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'INPUT_GITHUB-TOKEN='\\\"$ZIG_SECRET_0\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'ACTIONS_RUNTIME_TOKEN='\\\"$ZIG_SECRET_1\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'ACTIONS_CACHE_URL=https://cache.test/'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'ACTIONS_CACHE_SERVICE_V2=True'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "GITHUB_STATE=") != null);
    // bash where there is one, not dash, starts the runtime (dash would drop INPUT_GITHUB-TOKEN).
    try std.testing.expect(std.mem.indexOf(u8, run1, "printf '%s' 'PATH=\\\"/github/_runtime/bin:$PATH\\\" exec") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "if command -v bash >/dev/null 2>&1; then zig_shell=bash; else zig_shell=sh; fi") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "$zig_shell\\\" '-e' '/tmp/zig-runner-step-") != null);
    // No token in any command; the runtime is fetched only once.
    for (seen) |d| if (std.mem.indexOf(u8, d, "setSecret") == null) try std.testing.expect(std.mem.indexOf(u8, d, "ghs_") == null);
    // Both tokens registered in one query, and reused by the second step and the posts.
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "zsec0: setSecret(name:\"zig-secret-1\",plaintext:\"ghs_secret\") { id } zsec1: setSecret(name:\"zig-secret-2\",plaintext:\"ghs_jobtoken\") { id }") != null);
    for (seen[6..]) |d| try std.testing.expect(std.mem.indexOf(u8, d, "secret:\"SEC_RUNTIME\"") != null or std.mem.indexOf(u8, d, "echo 42") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[6], "withFile(path:\"/github/_runtime/node/node\"") == null);
    // The action's output reaches the next step.
    try std.testing.expect(std.mem.indexOf(u8, seen[7], "echo 42") != null);
    const out = w.buffered();
    // Posts run after the steps, last step first, with the state the main script saved.
    try std.testing.expect(std.mem.indexOf(u8, seen[8], "/github/_actions/actions/github-script/v9/dist/post.js") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[8], "STATE_pid") == null); // the second step saved nothing
    try std.testing.expect(std.mem.indexOf(u8, seen[9], "dist/post.js") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[9], "'STATE_pid=7'") != null);
    // The action directory and runtime are not mounted again for the post.
    try std.testing.expect(std.mem.indexOf(u8, seen[9], "withDirectory") == null);
    // Each post is a step of its own (log steps 4 and 5, after the job's three), starting as GitHub's do.
    try std.testing.expect(std.mem.indexOf(u8, out, "[job 0 step 4 stdout] Post job cleanup.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[job 0 step 5 stdout] Post job cleanup.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "##[group]Post") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "##[group]Run actions/github-script@v9") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "  script: return 42") != null);
}

test "native: a musl runtime's C++ runtime is its image's libstdc++ and libgcc_s, nothing else" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "img/usr/lib");
    try tmp.dir.createDirPath(io, "job");
    try tmp.dir.writeFile(io, .{ .sub_path = "img/usr/lib/libstdc++.so.6.0.33", .data = "cxx" });
    try tmp.dir.symLink(io, "libstdc++.so.6.0.33", "img/usr/lib/libstdc++.so.6", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "img/usr/lib/libgcc_s.so.1", .data = "gcc" });
    try tmp.dir.writeFile(io, .{ .sub_path = "img/usr/lib/libssl.so.3", .data = "other" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const rootfs = try std.fmt.allocPrint(arena, "{s}/img", .{root});
    const job = try std.fmt.allocPrint(arena, "{s}/job", .{root});
    const out = try cxxRuntime(arena, io, job, rootfs, "node:24-alpine");
    var dir = try std.Io.Dir.cwd().openDir(io, out, .{ .iterate = true });
    defer dir.close(io);
    var names: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        names += 1;
        try std.testing.expect(!std.mem.startsWith(u8, e.name, "libssl"));
    }
    try std.testing.expectEqual(@as(usize, 3), names);
    var buf: [64]u8 = undefined;
    const n = try dir.readLink(io, "libstdc++.so.6", &buf);
    try std.testing.expectEqualStrings("libstdc++.so.6.0.33", buf[0..n]);
    // An image without one cannot run the musl runtime: refused, not bound empty.
    try tmp.dir.createDirPath(io, "bare/usr/lib");
    const bare = try std.fmt.allocPrint(arena, "{s}/bare", .{root});
    try std.testing.expectError(error.NoCxxRuntime, cxxRuntime(arena, io, job, bare, "x"));
}
