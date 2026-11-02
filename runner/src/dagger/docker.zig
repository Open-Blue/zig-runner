//! Docker actions (`runs.using: docker` and `docker://` steps): the image pulled or built, the
//! command run under busybox with the workspace copied in and back, and registry credentials
//! for private images.

const std = @import("std");
const job_mod = @import("../job.zig");
const sink = @import("../sink.zig");
const Query = @import("query.zig").Query;
const Raw = @import("query.zig").Raw;
const expr = @import("../expr.zig");
const action = @import("../action.zig");
const Evaluator = @import("Evaluator.zig");
const Exec = @import("Exec.zig");
const Transport = @import("../dagger.zig").Transport;
const SecretRef = @import("../dagger.zig").SecretRef;
const Secrets = @import("../dagger.zig").Secrets;
const run = @import("../dagger.zig").run;
const gql = @import("../dagger.zig").gql;
const jsonFind = @import("../dagger.zig").jsonFind;
const jsonFindString = @import("../dagger.zig").jsonFindString;
const idOf = @import("../dagger.zig").idOf;
const newSecret = @import("../dagger.zig").newSecret;
const holdsSecret = @import("../dagger.zig").holdsSecret;
const envVarNode = @import("../dagger.zig").envVarNode;
const splitEnv = @import("../dagger.zig").splitEnv;
const inputEnv = @import("../dagger.zig").inputEnv;
const shownInputs = @import("../dagger.zig").shownInputs;
const shellQuote = @import("../dagger.zig").shellQuote;
const isVolatile = @import("../dagger.zig").isVolatile;
const busybox_image = @import("../dagger.zig").busybox_image;
const busybox_path = @import("../dagger.zig").busybox_path;
const docker_home = @import("../dagger.zig").docker_home;
const docker_workspace = @import("../dagger.zig").docker_workspace;
const event_dir = @import("../dagger.zig").event_dir;
const event_env = @import("../dagger.zig").event_env;
const event_path = @import("../dagger.zig").event_path;
const mark_env = @import("../dagger.zig").mark_env;
const ran_env = @import("../dagger.zig").ran_env;
const ActionOut = @import("Exec.zig").ActionOut;
const DockerRun = @import("Exec.zig").DockerRun;
const ImageInfo = @import("Exec.zig").ImageInfo;
const Loaded = @import("Exec.zig").Loaded;
const Phase = @import("Exec.zig").Phase;
const Recorded = @import("Exec.zig").Recorded;
const stream_prologue = @import("scripts.zig").stream_prologue;
const writeMarkerEcho = @import("scripts.zig").writeMarkerEcho;
const fc_dir = @import("scripts.zig").fc_dir;
const fc_kinds = @import("scripts.zig").fc_kinds;
const fcPath = @import("scripts.zig").fcPath;
const writeEnvCommand = @import("scripts.zig").writeEnvCommand;
const writeCombinedFileCommands = @import("scripts.zig").writeCombinedFileCommands;
const writeEndMarker = @import("scripts.zig").writeEndMarker;
const secretAlias = @import("scripts.zig").secretAlias;
const FakeSession = @import("testing.zig").FakeSession;
const fake_child = @import("testing.zig").fake_child;
const base_answer = @import("testing.zig").base_answer;
const testStep = @import("testing.zig").testStep;
const testJob = @import("testing.zig").testJob;
const treeAnswer = @import("testing.zig").treeAnswer;
const fileAnswer = @import("testing.zig").fileAnswer;
const usesStep = @import("testing.zig").usesStep;
const braceBalanced = @import("testing.zig").braceBalanced;

const Allocator = std.mem.Allocator;

/// An argument of a Docker action's command: its text, or the alias of the Dagger secret that
/// holds it (`secretAlias`), which the script expands as one word whatever it holds, so the
/// arguments are the same either way.
pub const Arg = union(enum) { text: []const u8, alias: []const u8 };

/// The busybox `sh -c` script that runs a Docker action's command `argv` as step `n`: as
/// `stepScriptFc`, with the image's command in place of a shell script, and busybox's own `mkdir`,
/// `printf` and `env` (the image may have none).
pub fn containerScript(
    arena: Allocator,
    n: u32,
    fc: u32,
    argv: []const Arg,
    env: []const job_mod.EnvVar,
    secret_env: []const []const u8,
    always_run: ?[]const u8,
    write_event: bool,
    withhold_volatile: bool,
    action_name: []const u8,
) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.writeAll(stream_prologue);
    try writeMarkerEcho(w, "begin", n);
    try w.writeAll("B=" ++ busybox_path ++ "\n\"$B\" mkdir -p " ++ fc_dir ++ " " ++
        docker_home ++ " " ++ event_dir ++ " && : ");
    for (fc_kinds) |k| try w.print("> {s} ", .{try fcPath(arena, k, fc)});
    try w.writeByte('\n');
    if (always_run) |why| {
        try w.writeAll(": ");
        try shellQuote(w, why);
        try w.writeByte('\n');
    }
    if (write_event) try w.writeAll("if [ -n \"${" ++ event_env ++ "+x}\" ]; then " ++
        "\"$B\" printf '%s' \"$" ++ event_env ++ "\" > " ++ event_path ++ "; fi\n");
    // An argument's alias is the shell's, not the action's: the command does not inherit it.
    var env_cmd: std.Io.Writer.Allocating = .init(arena);
    try env_cmd.writer.writeAll("\"$B\" env ");
    for (argv) |a| if (a == .alias) try env_cmd.writer.print("-u {s} ", .{a.alias});
    try writeEnvCommand(
        w,
        arena,
        env_cmd.written(),
        env,
        secret_env,
        write_event,
        withhold_volatile,
        fc,
        action_name,
    );
    for (argv) |a| {
        switch (a) {
            .text => |t| try shellQuote(w, t),
            .alias => |name| try w.print("\"${s}\"", .{name}),
        }
        try w.writeByte(' ');
    }
    try w.writeAll("\nrc=$?\n");
    try writeEndMarker(w, n);
    try w.writeAll(": ");
    for (fc_kinds) |k| try w.print(">> {s} ", .{try fcPath(arena, k, fc)});
    try w.writeByte('\n');
    try writeCombinedFileCommands(w, arena, "\"$B\" ", fc);
    try w.writeAll("exit $rc\n");
    return aw.written();
}

/// Splits `with: args` of a `docker://` step into arguments as GitHub's runner does (it hands the
/// string to `docker run`): at whitespace, with double quotes grouping and `\"` a literal quote.
fn splitArgs(arena: Allocator, s: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var cur: std.ArrayList(u8) = .empty;
    var in_arg = false;
    var quoted = false;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '\\' and i + 1 < s.len and s[i + 1] == '"') {
            try cur.append(arena, '"');
            in_arg = true;
            i += 1;
        } else if (c == '"') {
            quoted = !quoted;
            in_arg = true;
        } else if (!quoted and std.ascii.isWhitespace(c)) {
            if (in_arg) try out.append(arena, try cur.toOwnedSlice(arena));
            in_arg = false;
        } else {
            try cur.append(arena, c);
            in_arg = true;
        }
    }
    if (in_arg) try out.append(arena, try cur.toOwnedSlice(arena));
    return out.items;
}

/// The registry an image is pulled from, for its credentials: the first part of the reference when
/// it names a host (a dot, a port or `localhost`), else Docker Hub.
pub fn registryHost(image: []const u8) []const u8 {
    const slash = std.mem.indexOfScalar(u8, image, '/') orelse return "docker.io";
    const first = image[0..slash];
    if (std.mem.indexOfAny(u8, first, ".:") != null or std.mem.eql(u8, first, "localhost"))
        return first;
    return "docker.io";
}

/// `withRegistryAuth`'s arguments for an image behind a private registry.
pub const RegistryAuth = struct { address: []const u8, username: []const u8, secret: []const u8 };

/// A registry username and password (the job container's or a service's), evaluated; null
/// without both.
pub fn registryCredentials(
    ev: *Evaluator,
    svc: job_mod.Service,
) !?struct { user: []const u8, pass: []const u8 } {
    const ut = svc.username orelse return null;
    const pt = svc.password orelse return null;
    const sc = try ev.scope(&.{});
    const user = ev.render(ut, sc) catch "";
    const pass = ev.render(pt, sc) catch "";
    if (user.len == 0 or pass.len == 0) return null;
    return .{ .user = user, .pass = pass };
}

/// The credentials for a service's or the job container's image, or null without them. Sets
/// `err_msg` (and returns null) when the password could not be registered as a secret.
pub fn registryAuth(
    arena: Allocator,
    ev: *Evaluator,
    transport: Transport,
    secrets: *Secrets,
    svc: job_mod.Service,
    image: []const u8,
    err_msg: *[]const u8,
) !?RegistryAuth {
    const cred = try registryCredentials(ev, svc) orelse return null;
    const secret = newSecret(arena, transport, secrets, cred.pass, err_msg) catch {
        err_msg.* = try std.fmt.allocPrint(
            arena,
            "could not register the credentials for {s}: {s}",
            .{ image, err_msg.* },
        );
        return null;
    };
    return .{ .address = registryHost(image), .username = cred.user, .secret = secret };
}

/// Runs a Docker action (`runs.using: docker`) and registers its `post-entrypoint`.
pub fn runDocker(
    x: *Exec,
    num: u32,
    act: Loaded,
    u: job_mod.Uses,
    dk: @FieldType(action.Runs, "docker"),
    inputs: []const expr.Value.Entry,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
) !ActionOut {
    const failed: ActionOut = .{ .failed = true, .exit_code = 1 };
    const dr = (try x.dockerRunFor(
        num,
        act,
        u,
        dk,
        inputs,
        step_env,
        step_secret,
        dk.entrypoint,
    )) orelse return failed;
    const out = (try x.runContainer(num, .main, dr, try x.preState(num))) orelse return failed;
    if (dk.post_entrypoint) |post| {
        var p = dr;
        p.entrypoint = post;
        try x.posts.append(x.arena, .{
            .num = num,
            .name = try x.extraName("Post", num, act),
            .act = act,
            .u = u,
            .script = post,
            .condition = dk.post_if orelse "always()",
            .inputs = inputs,
            .step_env = step_env,
            .step_secret = step_secret,
            .state = try std.mem.concat(
                x.arena,
                job_mod.EnvVar,
                &.{ try x.preState(num), out.state },
            ),
            .docker = p,
        });
    }
    return .{ .failed = out.code != 0, .exit_code = out.code, .outputs = out.outputs };
}

/// How a Docker action runs: its image (`docker://<image>`, or built from the Dockerfile in its
/// directory, with the Dockerfile's directory as the context, as GitHub builds it), and its
/// `args` and `env:` evaluated with its `inputs` in scope. Null when they cannot be evaluated
/// (logged).
/// A Docker action's environment: the step's `env:`, its inputs as INPUT_*, and the action's
/// own `env:` evaluated; null, with the step failed, when one of those cannot be evaluated.
pub fn dockerEnv(
    x: *Exec,
    num: u32,
    act: Loaded,
    action_env: []const action.KeyValue,
    sc: expr.Scope,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
    inputs: []const expr.Value.Entry,
) !?[]const job_mod.EnvVar {
    const arena = x.arena;
    var env: std.ArrayList(job_mod.EnvVar) = .empty;
    try env.appendSlice(arena, step_env);
    try env.appendSlice(arena, try inputEnv(arena, inputs));
    const given = env.items.len;
    for (action_env) |e| {
        const value = expr.interpolate(arena, e.value, sc) catch {
            _ = try x.actionFailed(num, "could not evaluate env '{s}' of {s}: {s}", .{
                e.name,
                act.ref_label,
                x.ev.diag,
            });
            return null;
        };
        // The action's env only fills names the job's env, the step's and its inputs leave
        // unset, as GitHub's `ContainerActionHandler.cs` (~160-169) does.
        const set = for (env.items[0..given]) |g| {
            if (std.mem.eql(u8, g.name, e.name)) break true;
        } else for (step_secret) |sr| {
            if (std.mem.eql(u8, sr.name, e.name)) break true;
        } else for (x.ev.job_env.items) |j| {
            if (std.mem.eql(u8, j.name, e.name)) break true;
        } else false;
        if (!set) try env.append(arena, .{ .name = e.name, .value = value });
    }
    return env.items;
}

pub fn dockerRunFor(
    x: *Exec,
    num: u32,
    act: Loaded,
    _: job_mod.Uses,
    dk: @FieldType(action.Runs, "docker"),
    inputs: []const expr.Value.Entry,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
    entrypoint: ?[]const u8,
) !?DockerRun {
    const arena = x.arena;
    const ev = x.ev;
    const saved_inputs = ev.inputs;
    defer ev.inputs = saved_inputs;
    ev.inputs = .{ .object = inputs };
    ev.diag = "";
    const sc = try ev.scope(step_env);

    var args: ?[]const []const u8 = null;
    if (dk.args) |list| {
        const out = try arena.alloc([]const u8, list.len);
        for (list, out) |a, *dst| dst.* = expr.interpolate(arena, a, sc) catch {
            _ = try x.actionFailed(num, "could not evaluate the args of {s}: {s}", .{
                act.ref_label,
                ev.diag,
            });
            return null;
        };
        args = out;
    }
    const env = try x.dockerEnv(num, act, dk.env, sc, step_env, step_secret, inputs) orelse return null;

    const image: DockerRun.Image = if (std.mem.startsWith(u8, dk.image, "docker://"))
        .{ .pull = dk.image["docker://".len..] }
    else img: {
        const from = if (act.sub.len > 0) act.sub else ".";
        const rel = try std.fs.path.resolveAllocPosix(arena, &.{ from, dk.image });
        break :img .{ .build = .{
            .dir = act.dir,
            .context = std.fs.path.dirnamePosix(rel) orelse ".",
            .dockerfile = std.fs.path.basenamePosix(rel),
        } };
    };
    return .{
        .image = image,
        .entrypoint = entrypoint,
        .args = args,
        .env = env,
        .secret = step_secret,
        .label = act.ref_label,
        .repository = act.repository,
        .ref = act.ref,
        .shown = try shownInputs(arena, inputs),
        .step_env = step_env,
        .step_secret = step_secret,
    };
}

/// `uses: docker://<image>`: the image runs as a Docker action, with `with: args` (split as a
/// command line) and `with: entrypoint`; every input also arrives as INPUT_<NAME>.
pub fn runImageStep(
    x: *Exec,
    num: u32,
    d: @FieldType(job_mod.Action, "docker"),
    sc: expr.Scope,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
) !ActionOut {
    const arena = x.arena;
    const ev = x.ev;
    const inputs = try arena.alloc(expr.Value.Entry, d.inputs.len);
    for (d.inputs, inputs) |in, *dst| {
        ev.diag = "";
        dst.* = .{ .key = in.name, .value = .{ .string = ev.render(in.value, sc) catch
            return x.actionFailed(
                num,
                "could not evaluate input '{s}': {s}",
                .{ in.name, ev.diag },
            ) } };
    }
    var args: ?[]const []const u8 = null;
    var entrypoint: ?[]const u8 = null;
    for (inputs) |in| {
        if (std.ascii.eqlIgnoreCase(in.key, "args"))
            args = try splitArgs(arena, in.value.string);
        if (std.ascii.eqlIgnoreCase(in.key, "entrypoint") and in.value.string.len > 0)
            entrypoint = in.value.string;
    }
    const label = try std.fmt.allocPrint(arena, "docker://{s}", .{d.image});
    const shown = try arena.alloc(job_mod.EnvVar, inputs.len);
    for (inputs, shown) |in, *dst| dst.* = .{ .name = in.key, .value = in.value.string };
    const dr: DockerRun = .{
        .image = .{ .pull = d.image },
        .entrypoint = entrypoint,
        .args = args,
        .env = try std.mem.concat(
            arena,
            job_mod.EnvVar,
            &.{ step_env, try inputEnv(arena, inputs) },
        ),
        .secret = step_secret,
        .label = label,
        .shown = shown,
        .step_env = step_env,
        .step_secret = step_secret,
    };
    const out = (try x.runContainer(num, .main, dr, &.{})) orelse
        return .{ .failed = true, .exit_code = 1 };
    return .{ .failed = out.code != 0, .exit_code = out.code, .outputs = out.outputs };
}

/// Runs a Docker action's container as (part of) step `num`, as GitHub does with `docker run`:
/// the job's workspace is copied in at /github/workspace (the working directory), with the
/// event file, the file commands and /github/home, and the workspace is copied back into the
/// job's container afterwards, deletions included. The command is started by a static busybox
/// (`busybox_image`), so images without a shell work too. Null when the image could not be
/// pulled or built (logged).
/// The step's log group, with the image the action runs in.
pub fn logContainerStart(x: *Exec, num: u32, phase: Phase, dr: DockerRun) !void {
    const arena = x.arena;
    const image_line = switch (dr.image) {
        .pull => |ref| try std.fmt.allocPrint(arena, "image: {s}", .{ref}),
        .build => |b| try std.fmt.allocPrint(arena, "image: built from {s}", .{
            try std.fs.path.resolveAllocPosix(arena, &.{ b.context, b.dockerfile }),
        }),
    };
    try x.logGroup(num, phase, dr.label, dr.shown, dr.step_env, dr.step_secret, &.{image_line});
}

/// The shell a Docker action's container runs. It always has the job token
/// (ACTIONS_RUNTIME_TOKEN), so with step caching it always runs and is never replayed, which
/// is why it keeps the real run-specific values (`false`).
pub fn containerScriptFor(
    x: *Exec,
    num: u32,
    fc: u32,
    argv: []const Arg,
    env: []const job_mod.EnvVar,
    names: []const []const u8,
    dr: DockerRun,
) ![]const u8 {
    const label = if (dr.repository.len > 0) dr.repository else dr.label;
    const always_run = try x.alwaysRunNote();
    return containerScript(
        x.arena,
        num,
        fc,
        argv,
        env,
        names,
        always_run,
        x.event_from_env,
        false,
        label,
    );
}

pub fn runContainer(
    x: *Exec,
    num: u32,
    phase: Phase,
    dr: DockerRun,
    state: []const job_mod.EnvVar,
) !?Exec.Out {
    const arena = x.arena;
    if (phase == .main) try x.logContainerStart(num, phase, dr);
    // The native backend runs it in its image's filesystem (`native/docker_action.zig`).
    if (x.native) |b| return @import("../native/docker_action.zig").run(b, x, num, dr, state);
    const busybox = (try x.busyboxFile(num)) orelse return null;
    const img = (try x.imageInfo(num, dr.image, dr.label)) orelse return null;
    const argv = (try x.containerArgv(num, dr, img)) orelse return null;
    const ws_in = try x.workspaceDirId();
    const env = try x.containerEnv(dr, state);
    const names = try arena.alloc([]const u8, env.secret.len);
    for (env.secret, names) |sr, *n| n.* = sr.name;
    // An argument that holds a secret or a mask (`args: ${{ secrets.X }}`) reaches the
    // container as a Dagger secret after the env's, by its alias: in the command, it would be
    // in the engine's cache metadata (#101).
    var secret: std.ArrayList(SecretRef) = .empty;
    try secret.appendSlice(arena, env.secret);
    const args = try arena.alloc(Arg, argv.len);
    for (argv, args) |text, *arg| {
        if (!holdsSecret(x.job.*, x.sh, text)) {
            arg.* = .{ .text = text };
            continue;
        }
        const id = newSecret(arena, x.transport, &x.secrets, text, &x.err_msg) catch
            return error.EngineFailed;
        const alias = try secretAlias(arena, secret.items.len);
        try secret.append(arena, .{ .name = alias, .id = id });
        arg.* = .{ .alias = alias };
    }
    const fc = x.next_fc;
    x.next_fc += 1;
    const script = try x.containerScriptFor(num, fc, args, env.plain, names, dr);

    var q: Query = .init(arena);
    try q.call("loadContainerFromID", .{ .id = img.id });
    try q.call("withWorkdir", .{ .path = docker_workspace });
    const mode: u32 = 0o755;
    try q.call("withFile", .{ .path = busybox_path, .permissions = mode, .source = busybox });
    try x.writeActionDirs(&q, img, ws_in);
    try x.writeActionEnv(&q);
    try writeActionSecrets(arena, &q, secret.items);
    // A Docker action reaches the job's services by name, as on GitHub's container network.
    try x.writeServiceBindings(&q);
    const nesting: ?bool = if (x.nesting) true else null;
    try q.call("withExec", .{
        .args = &[_][]const u8{ busybox_path, "sh", "-c", script },
        .expect = Raw{ .text = "ANY" },
        .experimentalPrivilegedNesting = nesting,
    });
    try q.leaf("exitCode");
    const output_at = Recorded.position(&q);
    try q.callAs("fc_all", "file", .{ .path = try fcPath(arena, "all", fc) });
    try q.leaf("contents");
    try q.close(1);
    try q.callAs("ws", "directory", .{ .path = docker_workspace });
    try q.leaf("id");
    try q.close(1);
    try q.callAs("home", "directory", .{ .path = docker_home });
    try q.leaf("id");
    try q.close(1);

    // The step's env after the job's: the last value of a variable decides.
    const env_context = try std.mem.concat(
        arena,
        job_mod.EnvVar,
        &.{ x.ev.job_env.items, dr.step_env },
    );
    x.sh.beginCommands(num, env_context);
    x.beginExec(num);
    var recorded: Recorded = .{ .doc = try q.finish(), .at = output_at };
    const data = try recorded.send(x, x.replayed_last);
    const out = try x.collect(num, data, recorded);
    try x.takeWorkspaceBack(num, data, out);
    return out;
}

/// As `docker run [--entrypoint E] image [args]`: the action's entrypoint and args over the
/// image's. Null, with the step failed, when neither gives anything to run.
pub fn containerArgv(x: *Exec, num: u32, dr: DockerRun, img: ImageInfo) !?[]const []const u8 {
    const arena = x.arena;
    var argv: std.ArrayList([]const u8) = .empty;
    if (dr.entrypoint) |ep| {
        try argv.append(arena, ep);
        if (dr.args) |a| try argv.appendSlice(arena, a);
    } else {
        try argv.appendSlice(arena, img.entrypoint);
        try argv.appendSlice(arena, dr.args orelse img.cmd);
    }
    if (argv.items.len == 0) {
        _ = try x.actionFailed(
            num,
            "{s}: the image has no entrypoint or command, and the action gives none",
            .{dr.label},
        );
        return null;
    }
    return argv.items;
}

/// The job's workspace as a directory id, to copy into the action's container.
pub fn workspaceDirId(x: *Exec) ![]const u8 {
    const arena = x.arena;
    var q: Query = .init(arena);
    try q.call("loadContainerFromID", .{ .id = x.container_id });
    try q.call("directory", .{ .path = x.ev.workspace });
    try q.leaf("id");
    const doc = try q.finish();
    const data = gql(arena, x.transport, doc, &x.err_msg) catch return error.EngineFailed;
    return jsonFindString(data, "id") orelse {
        x.err_msg = "Dagger returned no workspace directory";
        return error.EngineFailed;
    };
}

/// What a Docker action's container gets in its environment, split into plain variables and
/// Dagger secrets.
pub const ContainerEnv = struct { plain: []const job_mod.EnvVar, secret: []const SecretRef };

/// The job's env (workflow, job, GITHUB_ENV) without the defaults GitHub sets again over it
/// (`Evaluator.withoutReapplied`; `writeActionEnv` sets them), then the step's and the action's,
/// then the runtime's and the OIDC token when the job has one — as on GitHub.
pub fn containerEnv(x: *Exec, dr: DockerRun, state: []const job_mod.EnvVar) !ContainerEnv {
    const arena = x.arena;
    var env: std.ArrayList(job_mod.EnvVar) = .empty;
    try env.appendSlice(arena, try x.ev.withoutReapplied(x.ev.job_env.items));
    try env.appendSlice(arena, dr.env);
    try env.append(arena, .{ .name = "HOME", .value = docker_home });
    if (dr.repository.len > 0) {
        try env.append(arena, .{ .name = "GITHUB_ACTION_REPOSITORY", .value = dr.repository });
        try env.append(arena, .{ .name = "GITHUB_ACTION_REF", .value = dr.ref });
    }
    try x.runtimeEnv(&env, state);
    var plain: std.ArrayList(job_mod.EnvVar) = .empty;
    var secret: std.ArrayList(SecretRef) = .empty;
    try secret.appendSlice(arena, dr.secret);
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
    if (try x.idToken()) |t| {
        try plain.append(arena, t.url);
        try secret.append(arena, t.token);
    }
    return .{ .plain = plain.items, .secret = secret.items };
}

/// The workspace, /github/home, and where file commands and the event go, owned by the image's
/// user, which may not be root (GitHub's own example action runs as one).
pub fn writeActionDirs(x: *Exec, q: *Query, img: ImageInfo, ws_in: []const u8) !void {
    const dirs = [_][2][]const u8{
        .{ docker_workspace, ws_in },
        .{ docker_home, x.docker_home orelse x.empty_dir },
        .{ fc_dir, x.empty_dir },
        .{ event_dir, x.empty_dir },
    };
    const owner: ?[]const u8 = if (img.user.len > 0) img.user else null;
    for (dirs) |d|
        try q.call("withDirectory", .{ .path = d[0], .source = d[1], .owner = owner });
}

/// The default variables (volatile under step caching), the event payload, and the ran marker.
pub fn writeActionEnv(x: *Exec, q: *Query) !void {
    const ev = x.ev;
    for (try ev.defaultEnv()) |e| {
        const node = envVarNode(x.step_cache and isVolatile(e.name));
        // GitHub mounts the workspace at /github/workspace in a Docker action, and says so.
        const value = if (std.mem.eql(
            u8,
            e.name,
            "GITHUB_WORKSPACE",
        )) docker_workspace else e.value;
        try q.call(node, .{ .name = e.name, .value = value });
    }
    const event = try ev.eventJson();
    if (x.event_from_env) {
        try q.call("withVolatileVariable", .{ .name = event_env, .value = event });
    } else {
        try q.call("withNewFile", .{ .path = event_path, .contents = event });
    }
    if (x.step_cache)
        try q.call("withVolatileVariable", .{ .name = ran_env, .value = x.ran_marker });
    try q.call(envVarNode(x.step_cache), .{ .name = mark_env, .value = x.sh.mark });
}

/// Each secret as a Dagger secret variable under its alias.
pub fn writeActionSecrets(arena: Allocator, q: *Query, secret: []const SecretRef) !void {
    for (secret, 0..) |sr, i| {
        try q.call(
            "withSecretVariable",
            .{ .name = try secretAlias(arena, i), .secret = sr.id },
        );
    }
}

/// After the action ran: /github/home kept for its next step, and the workspace as the action
/// left it replacing the job's — through output keys when they apply, else copied back whole,
/// deletions included.
pub fn takeWorkspaceBack(x: *Exec, num: u32, data: std.json.Value, out: Exec.Out) !void {
    const arena = x.arena;
    if (jsonFind(data, "home")) |h| if (jsonFindString(h, "id")) |id| {
        x.docker_home = id;
    };
    const ws_out = idOf(data, "ws") orelse {
        x.err_msg = "Dagger returned no workspace directory";
        return error.EngineFailed;
    };
    // The action always runs (it has the job token); with output keys the next steps are keyed
    // on the workspace it left, not on its run (see `Options.output_keys`).
    if (x.output_keys != null and out.code == 0) {
        const started = std.Io.Clock.awake.now(x.io).toMilliseconds();
        if (x.countOutputKeyed(num, started, try x.outputKeyedWorkspace(num, ws_out))) |id| {
            x.container_id = id;
            return;
        }
    }
    var q: Query = .init(arena);
    try q.call("loadContainerFromID", .{ .id = x.container_id });
    try q.call("withoutDirectory", .{ .path = x.ev.workspace });
    try q.call(
        "withDirectory",
        .{ .path = x.ev.workspace, .source = ws_out, .owner = x.dir_owner },
    );
    try q.leaf("id");
    const bdata = gql(arena, x.transport, try q.finish(), &x.err_msg) catch
        return error.EngineFailed;
    x.container_id = jsonFindString(bdata, "id") orelse {
        x.err_msg = "Dagger returned no container";
        return error.EngineFailed;
    };
}

test "service credentials go to the image's registry" {
    try std.testing.expectEqualStrings("docker.io", registryHost("postgres:17"));
    try std.testing.expectEqualStrings("docker.io", registryHost("bitnami/postgresql:17"));
    try std.testing.expectEqualStrings("ghcr.io", registryHost("ghcr.io/acme/db:1"));
    try std.testing.expectEqualStrings("localhost:5000", registryHost("localhost:5000/db"));
}

test "Docker actions: built or pulled, the workspace copied in and back, args, env, entrypoints and post" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);

    const action_yml =
        \\inputs:
        \\  who:
        \\    default: nobody
        \\runs:
        \\  using: docker
        \\  image: ./docker/Dockerfile
        \\  args:
        \\    - hello ${{ inputs.who }}
        \\  env:
        \\    GREETING: hi ${{ inputs.who }}
        \\  post-entrypoint: /cleanup.sh
    ;
    const inputs = [_]job_mod.Input{.{ .name = "who", .value = .{ .lit = "world" } }};
    var built = usesStep("dock", "o", "dock", "v1", &inputs);
    built.action.uses.path = "sub";
    var pulled = testStep("");
    pulled.action = .{ .docker = .{ .image = "alpine:3.22", .inputs = &.{
        .{ .name = "entrypoint", .value = .{ .lit = "sh" } },
        .{ .name = "args", .value = .{ .lit = "-c \"echo $GREETING\" x" } },
    } } };
    pulled.env = &.{.{ .name = "GREETING", .value = .{ .lit = "from the step" } }};
    const steps = [_]job_mod.Step{ built, pulled };
    var job = testJob(&steps);
    job.secrets = &.{"ghs_jobtoken"};
    job.job_token = "ghs_jobtoken";

    const ws = "{\"data\":{\"loadContainerFromID\":{\"directory\":{\"id\":\"WS0\"}}}}";
    const back = "{\"data\":{\"loadContainerFromID\":{\"withoutDirectory\":{\"withDirectory\":{\"id\":\"CB\"}}}}}";
    const secret = "{\"data\":{\"zsec0\":{\"id\":\"SEC\"}}}";
    const ran = "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"exitCode\":0,\"stdout\":\"\",\"stderr\":\"\",\"fc_output\":{\"contents\":\"said=hi\\n\"},\"ws\":{\"id\":\"WS1\"},\"home\":{\"id\":\"H1\"}}}}}";
    const answers = [_][]const u8{
        base_answer,
        try treeAnswer(arena, "D1", &.{"action.yml"}),
        try fileAnswer(arena, action_yml),
        // step 1: busybox, the image built from its Dockerfile, the workspace, the token, the exec, the copy back
        "{\"data\":{\"bb\":{\"from\":{\"file\":{\"id\":\"BB\"}}},\"empty\":{\"id\":\"EMPTY\"}}}",
        "{\"data\":{\"loadDirectoryFromID\":{\"directory\":{\"dockerBuild\":{\"id\":\"IMG\",\"entrypoint\":[\"/entry.sh\"],\"defaultArgs\":[\"unused\"],\"user\":\"actionuser\"}}}}}",
        ws,
        secret,
        ran,
        back,
        // step 2: a pulled image; busybox is not fetched again, nor the token registered again
        "{\"data\":{\"container\":{\"from\":{\"id\":\"ALP\",\"entrypoint\":[],\"defaultArgs\":[\"/bin/sh\"]}}}}",
        ws,
        ran,
        back,
        // post of step 1: the same image (not built again), with its post-entrypoint
        ws,
        ran,
        back,
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);

    const seen = fake.seen.items;
    try std.testing.expect(res.succeeded);
    try std.testing.expectEqual(@as(usize, 16), seen.len);
    for (seen) |d| try std.testing.expect(braceBalanced(d));
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "from(address:\"" ++ busybox_image ++
        "\") { file(path:\"/bin/busybox\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[3], "empty: directory { id }") != null);
    // Built with the Dockerfile's directory as the context.
    try std.testing.expect(std.mem.indexOf(u8, seen[4], "loadDirectoryFromID(id:\"D1\") { directory(path:\"sub/docker\") { dockerBuild(dockerfile:\"Dockerfile\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[5], "loadContainerFromID(id:\"C0\") { directory(path:\"/home/runner/work/r/r\")") != null);
    const run1 = seen[7];
    try std.testing.expect(std.mem.indexOf(u8, run1, "loadContainerFromID(id:\"IMG\") { withWorkdir(path:\"/github/workspace\")") != null);
    // The image's user owns what it writes: the workspace, /github/home, file commands, the event.
    try std.testing.expect(std.mem.indexOf(u8, run1, "withDirectory(path:\"/github/workspace\",source:\"WS0\",owner:\"actionuser\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withDirectory(path:\"/github/home\",source:\"EMPTY\",owner:\"actionuser\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withDirectory(path:\"/github/file_commands\",source:\"EMPTY\",owner:\"actionuser\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withDirectory(path:\"/github/workflow\",source:\"EMPTY\",owner:\"actionuser\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withFile(path:\"/github/_runtime/busybox\",permissions:493,source:\"BB\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withExec(args:[\"/github/_runtime/busybox\",\"sh\",\"-c\",") != null);
    // The image's entrypoint with the action's args, evaluated with its inputs; its env and INPUT_*.
    try std.testing.expect(std.mem.indexOf(u8, run1, "'/entry.sh' 'hello world'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "unused") == null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'GREETING=hi world'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'INPUT_WHO=world'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'HOME=/github/home'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "'ACTIONS_RUNTIME_TOKEN='\\\"$ZIG_SECRET_0\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "withEnvVariable(name:\"GITHUB_WORKSPACE\",value:\"/github/workspace\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run1, "ws: directory(path:\"/github/workspace\") { id } home: directory(path:\"/github/home\") { id }") != null);
    // The workspace it left replaces the job's.
    try std.testing.expect(std.mem.indexOf(u8, seen[8], "withoutDirectory(path:\"/home/runner/work/r/r\") { withDirectory(path:\"/home/runner/work/r/r\",source:\"WS1\")") != null);
    // docker://: the entrypoint input, args split like a command line, the step's env; /github/home is shared.
    try std.testing.expect(std.mem.indexOf(u8, seen[9], "from(address:\"alpine:3.22\") { id entrypoint defaultArgs user }") != null);
    const run2 = seen[11];
    try std.testing.expect(std.mem.indexOf(u8, run2, "loadContainerFromID(id:\"ALP\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run2, "'sh' '-c' 'echo $GREETING' 'x'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run2, "/bin/sh") == null);
    try std.testing.expect(std.mem.indexOf(u8, run2, "'GREETING=from the step'") != null);
    try std.testing.expect(std.mem.indexOf(u8, run2, "withDirectory(path:\"/github/home\",source:\"H1\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, run2, "owner:") == null);
    try std.testing.expect(std.mem.indexOf(u8, run2, "loadContainerFromID(id:\"CB\")") == null);
    try std.testing.expect(std.mem.indexOf(u8, seen[10], "loadContainerFromID(id:\"CB\")") != null);
    // The post: same image, its post-entrypoint with the args.
    try std.testing.expect(std.mem.indexOf(u8, seen[14], "loadContainerFromID(id:\"IMG\")") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen[14], "'/cleanup.sh' 'hello world'") != null);
    for (seen) |d| if (std.mem.indexOf(u8, d, "setSecret") == null) try std.testing.expect(std.mem.indexOf(u8, d, "ghs_") == null);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "##[group]Run o/dock/sub@v1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "image: built from sub/docker/Dockerfile") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "[job 0 step 3 stdout] Post job cleanup.") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "##[group]Post") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "image: alpine:3.22") != null);
}

test "a Docker action's runs.env only fills names the job, the step and its inputs leave unset" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env: std.process.Environ.Map = .init(arena);

    const action_yml =
        \\inputs:
        \\  who:
        \\    default: nobody
        \\runs:
        \\  using: docker
        \\  image: Dockerfile
        \\  env:
        \\    GREETING: from the action
        \\    FROM_JOB: from the action
        \\    INPUT_WHO: from the action
        \\    ONLY_ACTION: from the action
    ;
    const inputs = [_]job_mod.Input{.{ .name = "who", .value = .{ .lit = "world" } }};
    var step = usesStep("dock", "o", "dock", "v1", &inputs);
    step.env = &.{.{ .name = "GREETING", .value = .{ .lit = "from the step" } }};
    const steps = [_]job_mod.Step{step};
    var job = testJob(&steps);
    job.env = &.{.{ .name = "FROM_JOB", .value = .{ .lit = "from the job" } }};
    job.secrets = &.{"ghs_jobtoken"};
    job.job_token = "ghs_jobtoken";

    const answers = [_][]const u8{
        base_answer,
        try treeAnswer(arena, "D1", &.{"action.yml"}),
        try fileAnswer(arena, action_yml),
        "{\"data\":{\"bb\":{\"from\":{\"file\":{\"id\":\"BB\"}}},\"empty\":{\"id\":\"EMPTY\"}}}",
        "{\"data\":{\"loadDirectoryFromID\":{\"directory\":{\"dockerBuild\":{\"id\":\"IMG\"," ++
            "\"entrypoint\":[\"/entry.sh\"],\"defaultArgs\":[],\"user\":\"\"}}}}}",
        "{\"data\":{\"loadContainerFromID\":{\"directory\":{\"id\":\"WS0\"}}}}",
        "{\"data\":{\"zsec0\":{\"id\":\"SEC\"}}}",
        "{\"data\":{\"loadContainerFromID\":{\"withExec\":{\"exitCode\":0,\"stdout\":\"\"," ++
            "\"stderr\":\"\",\"ws\":{\"id\":\"WS1\"},\"home\":{\"id\":\"H1\"}}}}}",
        "{\"data\":{\"loadContainerFromID\":{\"withoutDirectory\":{\"withDirectory\":" ++
            "{\"id\":\"CB\"}}}}}",
    };
    var fake: FakeSession = .{ .answers = &answers, .arena = arena };
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    const res = try run(arena, std.testing.io, &env, .{ .test_session_argv = &.{ "sh", "-c", fake_child }, .test_transport = fake.transport() }, job, &log);
    try std.testing.expect(res.succeeded);
    const exec = fake.seen.items[7];
    try std.testing.expect(std.mem.indexOf(u8, exec, "'GREETING=from the step'") != null);
    try std.testing.expect(std.mem.indexOf(u8, exec, "'FROM_JOB=from the job'") != null);
    try std.testing.expect(std.mem.indexOf(u8, exec, "'INPUT_WHO=world'") != null);
    try std.testing.expect(std.mem.indexOf(u8, exec, "'ONLY_ACTION=from the action'") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, exec, "from the action"));
}

test "splitArgs splits like a command line, with double quotes" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const got = try splitArgs(a.allocator(), "  -c \"echo hi there\"  a\\\"b 'x y' \"\"");
    const want = [_][]const u8{ "-c", "echo hi there", "a\"b", "'x", "y'", "" };
    try std.testing.expectEqual(want.len, got.len);
    for (want, got) |wnt, g| try std.testing.expectEqualStrings(wnt, g);
}
