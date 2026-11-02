//! What running steps needs, shared by the job's own steps and the steps of composite actions.

const std = @import("std");
const job_mod = @import("../job.zig");
const broker = @import("../github/broker.zig");
const build_version = @import("../version.zig");
const expr = @import("../expr.zig");
const commands = @import("../commands.zig");
const matcher = @import("../matcher.zig");
const action = @import("../action.zig");
const config = @import("../config.zig");
const engine = @import("../engine.zig");
const sink = @import("../sink.zig");
const Query = @import("query.zig").Query;
const Raw = @import("query.zig").Raw;
const JobLog = @import("JobLog.zig");
const awaitLive = @import("JobLog.zig").awaitLive;
const servedFromCache = @import("JobLog.zig").servedFromCache;
const replayNotLive = @import("JobLog.zig").replayNotLive;
const Evaluator = @import("Evaluator.zig");
const stepScriptFc = @import("scripts.zig").stepScriptFc;
const fcPath = @import("scripts.zig").fcPath;
const fc_marker = @import("scripts.zig").fc_marker;
const secretAlias = @import("scripts.zig").secretAlias;
const scriptPath = @import("scripts.zig").scriptPath;
const Port = @import("services.zig").Port;
const Transport = @import("../dagger.zig").Transport;
const SecretRef = @import("../dagger.zig").SecretRef;
const Secrets = @import("../dagger.zig").Secrets;
const Mount = @import("../dagger.zig").Mount;
const Resolved = @import("../dagger.zig").Resolved;
const ExtraKind = @import("../dagger.zig").ExtraKind;
const ExtraStep = @import("../dagger.zig").ExtraStep;
const Observer = @import("../dagger.zig").Observer;
const Options = @import("../dagger.zig").Options;
const gql = @import("../dagger.zig").gql;
const gqlAtMost = @import("../dagger.zig").gqlAtMost;
const jsonFind = @import("../dagger.zig").jsonFind;
const jsonFindString = @import("../dagger.zig").jsonFindString;
const jsonStrings = @import("../dagger.zig").jsonStrings;
const idOf = @import("../dagger.zig").idOf;
const newSecret = @import("../dagger.zig").newSecret;
const splitEnv = @import("../dagger.zig").splitEnv;
const holdsSecret = @import("../dagger.zig").holdsSecret;
const envContext = @import("../dagger.zig").envContext;
const firstLine = @import("../dagger.zig").firstLine;
const readsRunSpecific = @import("../dagger.zig").readsRunSpecific;
const bun_load_errors = @import("../dagger.zig").bun_load_errors;
const busybox_image = @import("../dagger.zig").busybox_image;
const default_image = @import("../dagger.zig").default_image;
const max_recorded_bytes = @import("../dagger.zig").max_recorded_bytes;
const Backend = @import("../native/Backend.zig");

const Exec = @This();

const Allocator = std.mem.Allocator;

arena: Allocator,
io: std.Io,
transport: Transport,
sh: *JobLog,
ev: *Evaluator,
job: *const job_mod.Job,
/// The container after the last exec; each exec starts from it.
container_id: []const u8,
/// What Dagger said when a query failed.
err_msg: []const u8 = "",
/// The secrets registered in the session (see `Secrets`).
secrets: Secrets,
/// File-command ids for the steps of composite actions, after the job's own step numbers.
next_fc: u32,
js_runtime: config.JsRuntime,
/// Whether the JavaScript runtime is in the container yet (it is added by the first JS action).
js_mounted: bool = false,
/// Whether Node, for actions Bun cannot load, is in the container yet (see `nodeFallback`).
node_fallback_mounted: bool = false,
/// Per log step (index = step - 1, see `ExtraStep`): execs so far.
execs: []u32,
/// The next log step number for a `pre` or `post` script, and the scripts that ran.
next_log_step: u32,
extra: std.ArrayList(ExtraStep) = .empty,
/// Per job step (index = step - 1): the action loaded for it, the state its `pre` saved.
loaded: []?LoadResult,
pre_state: [][]const job_mod.EnvVar,
/// The `steps` ids from the job step down to the composite step running now ("" outside
/// composite actions, `build/__2` two levels in): which nested action a `pre` state is for.
nested_path: []const u8 = "",
/// The state the `pre` of an action inside a composite action saved, by `nestedKey`.
nested_pre_state: std.StringHashMapUnmanaged([]const job_mod.EnvVar) = .empty,
/// A `container:` job's PATH as its image and `env:` set it. With $GITHUB_PATH directories,
/// GitHub's runner starts every step there with `PATH=<directories>:<this>`, whatever PATH the
/// job's, the step's or $GITHUB_ENV's env says (`ContainerStepHost`, `StepHost.cs` ~250-255).
container_path: ?[]const u8 = null,
/// What each log step wrote to $GITHUB_STEP_SUMMARY (index = log step - 1), uploaded with the
/// logs so GitHub shows it on the run's summary page.
summaries: [][]const u8,
/// Action directories already mounted (by path), so a later phase sees what an earlier one
/// left.
mounted_actions: std.StringHashMapUnmanaged(void) = .empty,
/// Remote actions loaded so far, by `owner/name/path@ref` (see `loadAction`).
actions: std.StringHashMapUnmanaged(LoadResult) = .empty,
/// JavaScript actions' `post` scripts, run after the job's steps in reverse order.
posts: std.ArrayList(Post) = .empty,
/// A `pre` or `post` script failed: the job fails, whatever its steps' results.
hook_failed: bool = false,
/// Steps may use the job's Dagger engine (see `Options.nesting`).
nesting: bool,
/// `Options.nesting` asked for it, but the runner does not vouch for the job, so its steps do not
/// get the engine (`set_up.execFor`, #228).
nesting_withheld: bool = false,
/// Unchanged steps may be reused across runs (see `Options.step_cache`).
step_cache: bool,
/// Where the tool cache is mounted, when it is a cache volume (`set_up.package_cache_dirs`), and
/// the trees "Set up job" found in it (`ZIG_RUNNER_TOOL_TREES`), when it checked them: a replayed
/// step that names a directory in it that no tree holds runs again (`toolDirNotHeld`, #229).
tool_cache: ?[]const u8 = null,
tool_trees: ?[]const u8 = null,
/// See `Options.enforce_volatile`.
enforce_volatile: bool,
/// With `Options.output_keys`: the key of the cache volume that stores steps' changes by digest
/// (scoped like the package caches), and the volume once created.
output_keys: ?[]const u8,
outputs_volume: ?[]const u8 = null,
/// See `Options.output_keys_days`.
outputs_days: u32,
/// Always-run steps whose output keyed the next steps, and those that fell back to their own
/// container (see `Result.output_keys`); why the last one fell back, and the reason, if any,
/// given during the current attempt.
outputs_applied: u32 = 0,
outputs_fell_back: u32 = 0,
outputs_last_reason: []const u8 = "",
outputs_reason: ?[]const u8 = null,
/// Milliseconds spent on output keys in this job (diff, digest, store, copy).
outputs_ms: i64 = 0,
/// The event payload is in ZIG_RUNNER_EVENT; each step writes it to GITHUB_EVENT_PATH.
event_from_env: bool,
/// Workflow-, job- or `container:`-level env carries a secret, so every step uses secrets.
job_secret_env: bool,
/// The variables the job's container holds as Dagger secrets (`withSecretVariable`), by name:
/// one set again as a plain variable (`writePendingEnv`) loses its secret first.
secret_vars: std.StringHashMapUnmanaged(void) = .empty,
/// Differs for every job (the run, its attempt, and `ran_marker`): makes steps that use secrets
/// run every time, in every job.
run_nonce: []const u8,
/// This job's value of `ran_env`.
ran_marker: []const u8,
/// Whether the last exec was served from the cache and replayed: the next one asks for its
/// recorded output in its own query (`Recorded.send`).
replayed_last: bool = false,
/// Who owns what the runner copies into the job's container (checkouts, actions, the workspace
/// a Docker action leaves): `runner_user` when steps run as it, else root (null).
dir_owner: ?[]const u8 = null,
/// The job token as a Dagger secret, for ACTIONS_ID_TOKEN_REQUEST_TOKEN (registered on first
/// use).
id_token_secret: ?[]const u8 = null,
/// The job's GITHUB_TOKEN as a Dagger secret, for git fetches (see `gitAuth`).
git_auth: ?union(enum) { none, id: []const u8 } = null,
/// Docker actions: the static busybox that starts their command, their images (pulled or built
/// once per job, by `DockerRun.Image` key), and /github/home, which they share, as on GitHub.
busybox_id: ?[]const u8 = null,
/// How deep composite actions are nested right now (see `max_composite_depth`).
depth: u32 = 0,
/// An empty Directory, for the directories a Docker action's container needs.
empty_dir: []const u8 = "",
images: std.StringHashMapUnmanaged(ImageInfo) = .empty,
docker_home: ?[]const u8 = null,
/// Told when the runner's own steps start and finish (see `Observer`).
observer: ?Observer = null,
/// The image the steps run in: `container:`'s, or the runner's.
job_image: []const u8 = default_image,
/// The job's image uses musl (Alpine): JavaScript actions get the runtime's musl build.
musl: bool = false,
/// The job's `services:`, running for the whole job (see `startServices`).
services: std.ArrayList(RunningService) = .empty,
/// Shell lines at the start of every step that forward `localhost:<port>` to the services, as
/// a job on GitHub's runner reaches them through ports published on its host.
forward_prelude: []const u8 = "",
/// `defaults.run`, evaluated once in "Set up job" (`setUpJob`); null where unset or empty. Only
/// the job's own `run:` steps use them, not a composite action's.
default_shell: ?[]const u8 = null,
default_working_directory: ?[]const u8 = null,
/// The job runs on the native backend: each exec goes there instead of to Dagger
/// (`Backend.execScript`), and so do reads of the container's files.
native: ?*Backend = null,

pub const RunningService = struct {
    name: []const u8,
    id: []const u8,
    ports: []const Port,
};

const Post = struct {
    num: u32,
    /// "Post Run x@v1": the step's name for the step's own action, the action for a nested one.
    name: []const u8,
    act: Loaded,
    u: job_mod.Uses,
    script: []const u8,
    condition: []const u8,
    inputs: []const expr.Value.Entry,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
    state: []const job_mod.EnvVar,
    /// A Docker action's `post-entrypoint` (`script` is then the entrypoint).
    docker: ?DockerRun = null,
    /// The built-in checkout's: actions/checkout has a post step (it removes the credentials it
    /// stored); this checkout stores none, so it only takes its place in the job's steps.
    checkout: bool = false,
};

/// A Docker action to run: its image and how it is started (see `runContainer`).
pub const DockerRun = struct {
    image: Image,
    /// Replaces the image's entrypoint, and then its command too, as `docker run --entrypoint`
    /// does.
    entrypoint: ?[]const u8 = null,
    /// Null: the image's command.
    args: ?[]const []const u8 = null,
    /// The step's env, INPUT_<NAME>, the action's `env:`.
    env: []const job_mod.EnvVar,
    secret: []const SecretRef,
    /// `owner/repo@ref` or `docker://<image>`, for the log and messages.
    label: []const u8,
    /// GITHUB_ACTION_REPOSITORY and GITHUB_ACTION_REF; empty for a `docker://` step.
    repository: []const u8 = "",
    ref: []const u8 = "",
    /// The `with:` inputs the workflow gave, for the log.
    shown: []const job_mod.EnvVar = &.{},
    /// The step's own env (also in `env` and `secret`), shown in the log.
    step_env: []const job_mod.EnvVar = &.{},
    step_secret: []const SecretRef = &.{},

    pub const Image = union(enum) {
        pull: []const u8,
        /// Built from `dockerfile` with `context` as the build context, both paths in the
        /// Directory `dir`.
        build: struct { dir: []const u8, context: []const u8, dockerfile: []const u8 },
    };
};

/// `user` is the image's USER ("" for root): the action runs as it, so it gets the directories
/// it writes.
pub const ImageInfo = struct {
    id: []const u8,
    entrypoint: []const []const u8,
    cmd: []const []const u8,
    user: []const u8,
};

pub const Phase = enum {
    pre,
    main,
    post,
    fn label(p: Phase) []const u8 {
        return switch (p) {
            .pre => "Pre",
            .main => "Run",
            .post => "Post",
        };
    }
};

pub const Out = struct {
    code: i32,
    /// `code` is 1 only because a workflow or file command failed the step (a refused
    /// `::set-env`, a malformed GITHUB_OUTPUT); the process itself exited 0. GitHub logs
    /// "Process completed with exit code" only for the process's own (`logExitCode`).
    command_failed: bool = false,
    outputs: []const job_mod.EnvVar,
    /// From GITHUB_STATE and `::save-state`; a JavaScript action's later phases get it as
    /// STATE_*.
    state: []const job_mod.EnvVar = &.{},
    /// Bun refused to load the program (see `bun_load_errors`): nothing of it ran.
    bun_refused: bool = false,
};

/// Runs one script in the job's container, logging as step `num`, and applies its file
/// commands. `error.EngineFailed` (with `err_msg`) when Dagger itself failed.
pub fn execScript(
    x: *Exec,
    num: u32,
    fc: u32,
    resolved_in: Resolved,
    action_name: []const u8,
    secret_env_in: []const SecretRef,
    mounts: []const Mount,
) !Out {
    // A checkout's tree is already in the native layers (`Backend.fetchCheckout`): no mounts.
    if (x.native) |b| return b.execScript(x, num, fc, resolved_in, action_name, secret_env_in, mounts);
    const arena = x.arena;
    // What the runner adds for the step, apart from its secrets: the variables earlier steps
    // set, which the container before this step lacks, and the mounts. `outputKeyed` reuses
    // it. Built once: writePendingEnv hands the exports on and forgets them, and a step run
    // again (below) needs them as much as the first try did.
    var env: Query = .initFragment(arena);
    try x.writePendingEnv(&env);
    var mount_nodes: Query = .initFragment(arena);
    try writeMounts(&mount_nodes, mounts);
    // Set when the cache answered with a failure: the step runs again, for real (below).
    var rerun: ?[]const u8 = null;
    while (true) {
        const step_run = try x.resolveRunStep(resolved_in, secret_env_in, rerun);
        const resolved = step_run.resolved;
        const secret_env = step_run.secret_env;
        const script = try std.mem.concat(
            arena,
            u8,
            &.{ x.forward_prelude, try stepScriptFc(arena, num, fc, resolved, action_name) },
        );
        const before = x.container_id;
        var pre: Query = .initFragment(arena);
        try pre.splice(env.fragment());
        try pre.splice(mount_nodes.fragment());

        var q: Query = .init(arena);
        try q.call("loadContainerFromID", .{ .id = x.container_id });
        try q.splice(env.fragment());
        try writeActionSecrets(arena, &q, secret_env);
        try q.splice(mount_nodes.fragment());
        // Readable by the step's user, whoever that is in a job container's image; owned by the
        // runner user when steps run as it.
        const script_mount: ?[]const u8 = if (step_run.script_secret) |id| mount: {
            const path = try scriptPath(arena, fc, resolved.run.shell);
            try q.call("withMountedSecret", .{
                .path = path,
                .source = id,
                .owner = x.dir_owner,
                .mode = @as(u32, 0o444),
            });
            break :mount path;
        } else null;
        const output_at = try x.writeScriptExec(&q, script, fc, secret_env, script_mount);
        // A step whose output may key the next steps: what `outputKeyed` needs of the container
        // before it comes in the same query, as a field of its own (nothing is run for it).
        const keyed = x.output_keys != null and resolved == .run and
            resolved.run.always_run != null;
        if (keyed) {
            try q.close(q.depth);
            try writeOlder(&q, before, pre.fragment());
        }

        const step_env = switch (resolved) {
            .run => |r| r.env,
            .checkout => &.{},
        };
        const env_context = try envContext(arena, x.ev.job_env.items, step_env);
        x.sh.beginCommands(num, env_context);
        x.beginExec(num);
        var recorded: Recorded = .{ .doc = try q.finish(), .at = output_at };
        // A re-run marked to run every time is not replayed: its output is not asked for.
        const answer = try recorded.send(x, x.replayed_last and rerun == null);
        // The exec's own answer; with `keyed`, the container before it is beside it.
        const data = if (keyed and answer == .object)
            answer.object.get("loadContainerFromID") orelse answer
        else
            answer;
        // A failure the cache kept from an earlier run is not this run's: the step may have
        // failed for a reason that has passed (a network blip, a runner out of memory), and
        // replaying it would fail every re-run the same way until an input changed (#69). So
        // it runs again, marked to run every time, which no earlier run's result can match.
        // Its replayed output is never shown and its file commands never applied.
        if (rerun == null and exitCode(data) != 0 and
            failedEarlier(x.io, x.sh, num, x.ranThisRun(data)))
        {
            rerun = "its earlier run failed, and a failure is not replayed";
            continue;
        }
        // Likewise an earlier run's answer that names a directory of the tool cache, a volume in
        // no key, that "Set up job" found no tree holding: the volume may have lost it since,
        // and replayed, the step would point PATH at nothing (#229).
        if (rerun == null and x.step_cache) if (try x.toolDirNotHeld(data)) |dir| {
            if (failedEarlier(x.io, x.sh, num, x.ranThisRun(data))) {
                rerun = try std.fmt.allocPrint(arena, "its record names {s} in the tool " ++
                    "cache, where \"Set up job\" found no tree holding it", .{dir});
                continue;
            }
        };
        if (jsonFindString(data, "id")) |id| x.container_id = id;
        const out = try x.collect(num, data, recorded);
        // Any `::add-matcher::` this step emitted: read the files from the container it just
        // produced, which is where the paths it printed are valid.
        x.loadPendingMatchers(num);
        if (keyed and out.code == 0) {
            const started = std.Io.Clock.awake.now(x.io).toMilliseconds();
            const older: ?std.json.Value = if (answer == .object)
                answer.object.get("zig_older")
            else
                null;
            if (x.countOutputKeyed(
                num,
                started,
                try x.outputKeyed(num, older, x.container_id),
            )) |id| x.container_id = id;
        }
        return out;
    }
}

/// A step as it will run: the script's secret aliases and OIDC token set, and under step
/// caching its always-run reason or its volatile withholding decided.
const ScriptRun = struct {
    resolved: Resolved,
    secret_env: []const SecretRef,
    /// The script as a Dagger secret, when it holds one (`Resolved.run.script_mounted`).
    script_secret: ?[]const u8 = null,
};

/// Secret variables are for scripts only; they reach them through aliases (`secretAlias`). With
/// `id-token: write`, every step can request OIDC tokens, as on GitHub (`curl
/// "$ACTIONS_ID_TOKEN_REQUEST_URL"` in a script, `core.getIDToken()` in an action).
pub fn resolveRunStep(
    x: *Exec,
    resolved_in: Resolved,
    secret_env_in: []const SecretRef,
    /// Why the step must run again, if the cache answered with a failure (`execScript`).
    rerun: ?[]const u8,
) !ScriptRun {
    const arena = x.arena;
    var resolved = resolved_in;
    if (resolved != .run) return .{ .resolved = resolved, .secret_env = &.{} };
    var secret_env: []const SecretRef = secret_env_in;
    // A PATH in the step's env gets the $GITHUB_PATH directories in front, as the container's
    // does (`Handler.AddPrependPathToEnvironment`, `Handler.cs` ~205-232).
    if (x.ev.path_prepend.items.len > 0) {
        const env = try arena.dupe(job_mod.EnvVar, resolved.run.env);
        for (env) |*e| if (std.mem.eql(u8, e.name, "PATH")) {
            e.value = try std.fmt.allocPrint(arena, "{s}:{s}", .{
                try Evaluator.prependPath(arena, x.ev.path_prepend.items),
                x.container_path orelse e.value,
            });
        };
        resolved.run.env = env;
    }
    // A script with a secret written in (`${{ secrets.X }}`) reaches its file as a Dagger
    // secret: in the command, the plaintext would be in the engine's cache metadata (#101).
    const script_secret: ?[]const u8 = if (holdsSecret(x.job.*, x.sh, resolved.run.script))
        newSecret(arena, x.transport, &x.secrets, resolved.run.script, &x.err_msg) catch
            return error.EngineFailed
    else
        null;
    resolved.run.script_mounted = script_secret != null;
    // Its working directory too, the step's own or `defaults.run`'s (#102); registered below,
    // once its alias, after every secret variable's, is known.
    const wd_secret = if (resolved.run.working_directory) |wd|
        holdsSecret(x.job.*, x.sh, wd)
    else
        false;
    const uses_secrets = secret_env.len > 0 or x.job_secret_env or x.envHoldsSecret() or
        script_secret != null or wd_secret;
    const oidc = try x.idToken();
    if (oidc) |t| {
        resolved.run.env = try std.mem.concat(
            arena,
            job_mod.EnvVar,
            &.{ resolved.run.env, &.{t.url} },
        );
        secret_env = try std.mem.concat(arena, SecretRef, &.{ secret_env, &.{t.token} });
    }
    const names = try arena.alloc([]const u8, secret_env.len);
    for (secret_env, names) |s, *n| n.* = s.name;
    resolved.run.secret_env = names;
    if (wd_secret) {
        const id = newSecret(
            arena,
            x.transport,
            &x.secrets,
            resolved.run.working_directory.?,
            &x.err_msg,
        ) catch return error.EngineFailed;
        const alias = try secretAlias(arena, secret_env.len);
        secret_env = try std.mem.concat(arena, SecretRef, &.{ secret_env, &.{.{
            .name = alias,
            .id = id,
        }} });
        resolved.run.working_directory = null;
        resolved.run.working_directory_alias = alias;
    }
    resolved.run.write_event = x.event_from_env;
    // A step that uses secrets (a deploy, a publish) must not be skipped because an earlier run
    // had the same inputs, and one that reads run-specific values must not replay an earlier
    // run's; every step after it then runs too. One that can get OIDC tokens may publish or
    // deploy without any secret (npm's trusted publishing, cloud logins), so it runs too.
    if (x.step_cache) {
        const reason: ?[]const u8 = if (uses_secrets)
            "it uses secrets"
        else if (oidc != null)
            "it can request OIDC tokens (id-token: write)"
        else if (readsRunSpecific(resolved.run.script))
            "it reads run- or commit-specific values"
        else
            rerun;
        if (reason) |r| resolved.run.always_run = try std.fmt.allocPrint(
            arena,
            "zig-runner runs this step every time: {s} (run {s})",
            .{ r, x.run_nonce },
        )
            // A step that is replayable must not be given a value that differs between runs,
            // because it can read one without the runner being able to tell
            // (`volatile_sentinel`).
        else resolved.run.withhold_volatile = x.enforce_volatile;
    }
    return .{ .resolved = resolved, .secret_env = secret_env, .script_secret = script_secret };
}

/// Whether the env the job's steps get (workflow, job, GITHUB_ENV) holds a secret or a mask: a
/// step can pass one on through GITHUB_ENV, or mask a value already there, and every step after
/// it then has it (#101).
fn envHoldsSecret(x: *Exec) bool {
    for (x.ev.job_env.items) |e| if (holdsSecret(x.job.*, x.sh, e.value)) return true;
    return false;
}

/// Variables and PATH entries the previous steps asked for through $GITHUB_ENV / $GITHUB_PATH,
/// written and then forgotten: the container after this step has them. A value that holds a
/// secret or a mask goes in as a Dagger secret, as the job's env does: as a plain variable it
/// would be in every later exec's key and the engine's metadata (#101).
fn writePendingEnv(x: *Exec, q: *Query) !void {
    const arena = x.arena;
    const ev = x.ev;
    var values: std.ArrayList([]const u8) = .empty;
    for (ev.pending_env.items) |e|
        if (holdsSecret(x.job.*, x.sh, e.value)) try values.append(arena, e.value);
    x.secrets.register(arena, x.transport, values.items, &x.err_msg) catch
        return error.EngineFailed;
    // GitHub puts the $GITHUB_PATH directories before whatever PATH a step gets, a PATH set
    // through $GITHUB_ENV included (`Handler.cs` ~205-232); then the container already has them.
    var path_set = false;
    // A variable is plain or secret, never both: with both, which one a step sees would be the
    // engine's choice.
    for (ev.pending_env.items) |e| {
        if (holdsSecret(x.job.*, x.sh, e.value)) {
            try q.call("withoutEnvVariable", .{ .name = e.name });
            try q.call(
                "withSecretVariable",
                .{ .name = e.name, .secret = x.secrets.ids.get(e.value).? },
            );
            try x.secret_vars.put(arena, e.name, {});
        } else {
            if (x.secret_vars.remove(e.name))
                try q.call("withoutSecretVariable", .{ .name = e.name });
            const path = std.mem.eql(u8, e.name, "PATH") and ev.path_prepend.items.len > 0;
            const value = if (path) try std.fmt.allocPrint(arena, "{s}:{s}", .{
                try Evaluator.prependPath(arena, ev.path_prepend.items),
                x.container_path orelse e.value,
            }) else e.value;
            path_set = path_set or path;
            try q.call("withEnvVariable", .{ .name = e.name, .value = value });
        }
    }
    // Only the directories added since: the container's PATH has the earlier ones. One added
    // again then appears twice, its first place being the one GitHub gives it.
    if (ev.pending_path.items.len > 0 and !path_set) if (x.container_path) |own| {
        // A job container: every directory, then the container's own PATH, over any other.
        const value = try std.fmt.allocPrint(arena, "{s}:{s}", .{
            try Evaluator.prependPath(arena, ev.path_prepend.items),
            own,
        });
        try q.call("withEnvVariable", .{ .name = "PATH", .value = value });
    } else {
        const value = try std.fmt.allocPrint(arena, "{s}:$PATH", .{
            try Evaluator.prependPath(arena, ev.pending_path.items),
        });
        try q.call("withEnvVariable", .{ .name = "PATH", .value = value, .expand = true });
    };
    ev.pending_env.clearRetainingCapacity();
    ev.pending_path.clearRetainingCapacity();
}

/// Each mount as its call.
fn writeMounts(q: *Query, mounts: []const Mount) !void {
    for (mounts) |m| switch (m) {
        .dir => |d| try q.call(
            "withDirectory",
            .{ .path = d.path, .source = d.id, .owner = d.owner },
        ),
        .file => |f| try q.call(
            "withFile",
            .{ .path = f.path, .source = f.id, .permissions = f.permissions },
        ),
        .new_file => |f| try q.call("withNewFile", .{
            .path = f.path,
            .contents = f.contents,
            .permissions = f.permissions,
        }),
    };
}

/// The exec itself and what is read back: exit code, the combined file commands, and the
/// container id — taken after the step's secrets are removed, so the next step starts without
/// them. Nesting gives the step's `dagger` CLI a session on this engine, sharing its cache.
/// Returns where its recorded output would be asked for (`Recorded`).
fn writeScriptExec(
    x: *Exec,
    q: *Query,
    script: []const u8,
    fc: u32,
    secret_env: []const SecretRef,
    /// Where the script is mounted as a secret, if it is: unmounted with the step's secrets.
    script_mount: ?[]const u8,
) !usize {
    const arena = x.arena;
    const nesting: ?bool = if (x.nesting) true else null;
    try q.call("withExec", .{
        .args = &[_][]const u8{ "sh", "-c", script },
        .expect = Raw{ .text = "ANY" },
        .experimentalPrivilegedNesting = nesting,
    });
    try q.leaf("exitCode");
    const output_at = Recorded.position(q);
    try q.callAs("fc_all", "file", .{ .path = try fcPath(arena, "all", fc) });
    try q.leaf("contents");
    try q.close(1);
    for (secret_env, 0..) |_, i|
        try q.call("withoutSecretVariable", .{ .name = try secretAlias(arena, i) });
    if (script_mount) |path| try q.call("withoutMount", .{ .path = path });
    try q.leaf("id");
    return output_at;
}

/// An exec's recorded output (`stdout`, `stderr`), asked for only when it is needed: when none
/// of the step's lines arrived live, because the engine served the exec from its cache. Asked
/// for with every exec, a 200 MB log came back in the answer, and the engine repeated it on the
/// log stream as well (a `stdout` field's value is logged, marked verbose): the runner grew by
/// 1.8 GB. The exec's document is sent again with the fields put in, which the engine answers
/// from its cache without running the exec again, and an answer past `max_recorded_bytes` is
/// not read. After a replayed exec they go in the exec's own query instead (`send`).
pub const Recorded = struct {
    /// The exec's document, and where in it the fields go (`position`).
    doc: []const u8,
    at: usize,
    /// Whether `doc` went with the fields in (`send`), so its answer holds the output.
    in_answer: bool = false,

    /// Where the fields would go: the current position, in the exec's selection.
    pub fn position(q: *Query) usize {
        // The document has begun (the exec was called), so this is an offset into what
        // `finish` returns.
        std.debug.assert(q.began);
        return q.out.written().len;
    }

    const Output = struct { stdout: []const u8, stderr: []const u8 };
    const fields = "stdout stderr ";

    /// Sends the exec's document, with the fields in when `ask`: an exec after a replayed one is
    /// most likely replayed too (a re-run job), and then a replay is one round trip instead of
    /// two. One that runs anyway gets its output back beside its result, which the engine also
    /// repeats on the log stream as verbose records (`JobLog`, dropped), and only shows it if it
    /// is replayed after all, as `read` would have. An answer past `max_recorded_bytes` is not
    /// read: the document goes again without the fields, and a replay asks for them as before.
    pub fn send(r: *Recorded, x: *Exec, ask: bool) !std.json.Value {
        if (ask) {
            const parts = [_][]const u8{ r.doc[0..r.at], fields, r.doc[r.at..] };
            const doc = try std.mem.concat(x.arena, u8, &parts);
            if (gqlAtMost(x.arena, x.transport, doc, max_recorded_bytes, &x.err_msg)) |data| {
                r.in_answer = true;
                return data;
            } else |e| if (e != error.ResponseTooLarge) return error.EngineFailed;
        }
        return gql(x.arena, x.transport, r.doc, &x.err_msg) catch error.EngineFailed;
    }

    /// The output, from the exec's answer `data` when it holds it, or why it could not be had.
    fn read(
        r: Recorded,
        x: *Exec,
        data: std.json.Value,
    ) union(enum) { ok: Output, failed: []const u8 } {
        if (r.in_answer) return .{ .ok = .{
            .stdout = jsonFindString(data, "stdout") orelse "",
            .stderr = jsonFindString(data, "stderr") orelse "",
        } };
        const arena = x.arena;
        const doc = std.mem.concat(arena, u8, &.{ r.doc[0..r.at], fields, r.doc[r.at..] }) catch
            return .{ .failed = "out of memory" };
        var err_msg: []const u8 = "";
        const answer = gqlAtMost(arena, x.transport, doc, max_recorded_bytes, &err_msg) catch |e|
            return .{ .failed = if (e == error.ResponseTooLarge)
                std.fmt.comptimePrint("it is over the {d} MiB that is replayed", .{
                    max_recorded_bytes / (1024 * 1024),
                })
            else if (err_msg.len > 0) err_msg else @errorName(e) };
        return .{ .ok = .{
            .stdout = jsonFindString(answer, "stdout") orelse "",
            .stderr = jsonFindString(answer, "stderr") orelse "",
        } };
    }
};

/// Reads the matcher files a step asked for, and registers what they define.
///
/// The paths come from the step's own output, so they are absolute in *its* container — the one
/// this has just finished building, which is why the read happens here rather than in the log
/// path. A file that cannot be read, or holds nothing this engine can compile, warns in the
/// step's log and is otherwise ignored: an action that ships an exotic pattern should lose its
/// annotations, not its job.
fn warnMatcher(x: *Exec, num: u32, comptime fmt: []const u8, args: anytype) void {
    const text = std.fmt.allocPrint(x.arena, "##[warning]" ++ fmt, args) catch return;
    x.sh.warnUnlocked(num, text);
}

pub fn loadPendingMatchers(x: *Exec, num: u32) void {
    const pending = x.sh.takePendingMatchers();
    if (pending.len == 0) return;
    // All the files in one query. One that cannot be read fails it all; each is then read on
    // its own, so the others still load and the warning names the one that failed.
    const all = x.readMatcherFiles(pending);
    for (pending, 0..) |path, i| {
        const text = (if (all) |texts| texts[i] else x.readMatcherFile(path)) orelse {
            x.warnMatcher(num, "Could not read the problem matcher '{s}'", .{path});
            continue;
        };
        const loaded = matcher.load(x.arena, text) catch {
            x.warnMatcher(num, "'{s}' is not a problem matcher file", .{path});
            continue;
        };
        for (loaded.refused) |r|
            x.warnMatcher(
                num,
                "Problem matcher '{s}' is ignored: its pattern needs {s} ({s})",
                .{ r.owner, r.why, r.pattern },
            );
        x.sh.addMatchers(loaded.matchers);
    }
}

/// The contents of each of `paths` in the job's container, in one query; null when that
/// failed, and for a single path (`readMatcherFile` reads it).
fn readMatcherFiles(x: *Exec, paths: []const []const u8) ?[]const []const u8 {
    if (paths.len < 2 or x.native != null) return null;
    const arena = x.arena;
    var q: Query = .init(arena);
    q.call("loadContainerFromID", .{ .id = x.container_id }) catch return null;
    for (paths, 0..) |path, i| {
        const alias = std.fmt.allocPrint(arena, "m{d}", .{i}) catch return null;
        q.callAs(alias, "file", .{ .path = path }) catch return null;
        q.leaf("contents") catch return null;
        q.close(1) catch return null;
    }
    const doc = q.finish() catch return null;
    var msg: []const u8 = "";
    const data = gql(arena, x.transport, doc, &msg) catch return null;
    const texts = arena.alloc([]const u8, paths.len) catch return null;
    for (texts, 0..) |*t, i| {
        const alias = std.fmt.allocPrint(arena, "m{d}", .{i}) catch return null;
        const f = jsonFind(data, alias) orelse return null;
        t.* = jsonFindString(f, "contents") orelse return null;
    }
    return texts;
}

/// The contents of `path` in the job's container; null when it could not be read.
fn readMatcherFile(x: *Exec, path: []const u8) ?[]const u8 {
    if (x.native) |b| return b.readFile(path);
    var q: Query = .init(x.arena);
    q.call("loadContainerFromID", .{ .id = x.container_id }) catch return null;
    q.call("file", .{ .path = path }) catch return null;
    q.leaf("contents") catch return null;
    const doc = q.finish() catch return null;
    var msg: []const u8 = "";
    const data = gql(x.arena, x.transport, doc, &msg) catch return null;
    return jsonFindString(data, "contents");
}

// output_keys.zig
pub const writeOlder = @import("output_keys.zig").writeOlder;
pub const outputKeyed = @import("output_keys.zig").outputKeyed;
pub const outputsPhase = @import("output_keys.zig").outputsPhase;
pub const outputsFallback = @import("output_keys.zig").outputsFallback;
pub const countOutputKeyed = @import("output_keys.zig").countOutputKeyed;
pub const outputKeyedWorkspace = @import("output_keys.zig").outputKeyedWorkspace;
pub const storeAndApply = @import("output_keys.zig").storeAndApply;
pub const outputsVolume = @import("output_keys.zig").outputsVolume;
pub const storeOutput = @import("output_keys.zig").storeOutput;
pub const applyScript = @import("output_keys.zig").applyScript;
pub const applyOutput = @import("output_keys.zig").applyOutput;
pub const debugApplied = @import("output_keys.zig").debugApplied;

/// Several execs can log as one step (a composite action's steps, a JavaScript action's pre,
/// main and post): after the first, count each one's live lines afresh, so a cached one is
/// replayed, and forget the lines replayed for the one before, so a line of this exec's that
/// one also printed is not taken for its late copy and dropped, workflow command and all (#102).
pub fn beginExec(x: *Exec, num: u32) void {
    if (x.execs[num - 1] > 0) {
        x.sh.live_lines[num - 1].store(0, .monotonic);
        x.sh.ended[num - 1].store(false, .release);
        x.sh.forgetReplayed();
    }
    x.sh.bun_refused.store(0, .release);
    x.execs[num - 1] += 1;
}

/// Whether the exec's lines arrived live (`awaitLive`). Not when its marker says it did not run
/// in this job: a cached exec prints nothing, so lines counted for its step are an earlier
/// exec's of the same step arriving late (a composite action's previous step), and waiting on
/// them would skip this one's replay, its log, masks, outputs and state with it (#102).
fn liveThisExec(io: std.Io, sh: *JobLog, num: u32, ran: ?bool) bool {
    if (ran == false) return false;
    return awaitLive(io, sh, num);
}

/// An exec's result (`exitCode fc_<kind> { contents }`): its output, replayed if it was cached
/// (`Recorded`), and its file commands applied.
pub fn collect(x: *Exec, num: u32, data: std.json.Value, recorded: Recorded) !Out {
    const arena = x.arena;
    const ev = x.ev;
    const exited = exitCode(data);
    var code = exited;
    // A cached step prints no log lines. Wait briefly for a live stream, then replay the
    // recorded output. Without step caching nothing is replayed from an earlier job:
    // run-specific values are part of every key.
    var output: Recorded.Output = .{ .stdout = "", .stderr = "" };
    const ran = x.ranThisRun(data);
    x.replayed_last = false;
    if (!liveThisExec(x.io, x.sh, num, ran)) {
        // An answer that has it already unasked (a test's) is not asked again; a step that ran
        // here and printed nothing has nothing to show.
        if (!recorded.in_answer and jsonFind(data, "stdout") != null) output = .{
            .stdout = jsonFindString(data, "stdout") orelse "",
            .stderr = jsonFindString(data, "stderr") orelse "",
        } else if (servedFromCache(x.sh, num, ran)) switch (recorded.read(x, data)) {
            .ok => |o| output = o,
            .failed => |why| x.sh.append(num, try std.fmt.allocPrint(
                arena,
                "##[warning]This step's output cannot be shown: its recorded output " ++
                    "could not be read back ({s}).",
                .{why},
            )),
        };
        x.replayed_last = replayNotLive(x.sh, num, output.stdout, output.stderr, ran);
    }
    const stdout = output.stdout;
    const stderr = output.stderr;

    // `::set-env` and `::add-path` before the file commands: GitHub's runner applies them as
    // they are printed, and the file commands after the step, so a file command's value wins.
    // A command that failed fails the step.
    const unsecure = x.sh.takeUnsecure(num);
    for (unsecure.env) |e| try Evaluator.putEnv(arena, &ev.job_env, e.name, e.value);
    try ev.pending_env.appendSlice(arena, try ev.withoutReapplied(unsecure.env));
    try ev.pending_path.appendSlice(arena, unsecure.paths);
    if (unsecure.failed and code == 0) code = 1;

    // File commands: outputs for `steps.<id>.outputs`, env and PATH for the steps that follow,
    // state for the action's later phases. A file with a bad line counts up to it, and then
    // fails the step, each file on its own (`ProcessFiles` in FileCommandManager.cs).
    var outputs: []const job_mod.EnvVar = &.{};
    var file_failed = false;
    if (fileCommand(data, "fc_output")) |text| {
        const parsed = try commands.parseKeyValues(arena, text);
        outputs = parsed.pairs;
        if (parsed.invalid) |why| file_failed = try x.fileCommandFailed(num, "output", why);
    }
    if (fileCommand(data, "fc_env")) |text| {
        const parsed = try commands.parseKeyValues(arena, text);
        var set: std.ArrayList(job_mod.EnvVar) = .empty;
        for (parsed.pairs) |e| {
            // An error annotation, and the step goes on (`SetEnvFileCommand`).
            if (commands.isBlockedEnvName(e.name)) {
                x.sh.errorLine(num, "Can't store NODE_OPTIONS output parameter using " ++
                    "'$GITHUB_ENV' command.");
                continue;
            }
            // Likewise the runner's own variables (not in GitHub's runner).
            if (commands.isRunnerEnvName(e.name)) {
                x.sh.errorLine(num, try std.fmt.allocPrint(arena, "Can't store {s} using " ++
                    "'$GITHUB_ENV' command: it is the runner's own.", .{e.name}));
                continue;
            }
            try Evaluator.putEnv(arena, &ev.job_env, e.name, e.value);
            try set.append(arena, e);
        }
        try ev.pending_env.appendSlice(arena, try ev.withoutReapplied(set.items));
        if (parsed.invalid) |why| file_failed = try x.fileCommandFailed(num, "env", why);
    }
    if (fileCommand(data, "fc_path")) |text| {
        for (try commands.parsePaths(arena, text)) |dir| try ev.addPath(dir);
    }
    if (fileCommand(data, "fc_step_summary")) |text| try x.appendSummary(num, text);
    // GitHub's runner sets each output in turn into a case-insensitive dictionary: the deprecated
    // `::set-output` lines as they are printed, then GITHUB_OUTPUT's pairs after the step
    // (`FileCommandManager.cs` ~346, `StepsContext.SetOutput`). So the last value of a name wins,
    // with its first spelling (`DictionaryContextData`'s indexer keeps the casing).
    const legacy = x.sh.takeOutputs(num);
    outputs = try lastWins(arena, try std.mem.concat(arena, job_mod.EnvVar, &.{ legacy, outputs }));
    var state: []const job_mod.EnvVar = x.sh.takeState(num);
    if (fileCommand(data, "fc_state")) |text| {
        const parsed = try commands.parseKeyValues(arena, text);
        state = try std.mem.concat(arena, job_mod.EnvVar, &.{ state, parsed.pairs });
        if (parsed.invalid) |why| file_failed = try x.fileCommandFailed(num, "state", why);
    }
    if (file_failed and code == 0) code = 1;
    // Bun's message is on stderr, which the step's script sends to its stdout
    // (`stream_prologue`): in a line that arrived live, or in the recorded output replayed.
    const refused = code != 0 and (x.sh.bun_refused.load(.acquire) == num or
        for (bun_load_errors) |e| {
            const in_out = std.mem.indexOf(u8, stdout, e) != null;
            if (in_out or std.mem.indexOf(u8, stderr, e) != null) break true;
        } else false);
    return .{
        .code = code,
        .command_failed = exited == 0 and code != 0,
        .outputs = outputs,
        .state = state,
        .bun_refused = refused,
    };
}

/// `pairs` with one entry per name, compared without case: the first spelling and position, the
/// last value.
fn lastWins(arena: Allocator, pairs: []const job_mod.EnvVar) ![]const job_mod.EnvVar {
    var out: std.ArrayList(job_mod.EnvVar) = try .initCapacity(arena, pairs.len);
    next: for (pairs) |p| {
        for (out.items) |*o| if (std.ascii.eqlIgnoreCase(o.name, p.name)) {
            o.value = p.value;
            continue :next;
        };
        out.appendAssumeCapacity(p);
    }
    return out.items;
}

/// Whether the step ran in this job (true), was replayed from an earlier run (false), or did
/// not say (null): under step caching the exec writes the run's marker to a file command.
fn ranThisRun(x: *Exec, data: std.json.Value) ?bool {
    if (!x.step_cache) return true;
    const m = fileCommand(data, "fc_ran") orelse return null;
    return std.mem.eql(u8, std.mem.trim(u8, m, " \n"), x.ran_marker);
}

/// After a `run:` step failed: when it names Dagger and its job was not given the engine, why
/// its `dagger` found none, rather than leaving the step's connection error to explain it.
pub fn noteNestingWithheld(x: *Exec, num: u32, script: []const u8) void {
    if (!x.nesting_withheld) return;
    if (std.ascii.findIgnoreCase(script, "dagger") == null) return;
    x.sh.errorLine(num, nesting_withheld_note);
}

pub const nesting_withheld_note = "This step names Dagger, but steps do not get the Dagger " ++
    "engine in jobs this runner does not vouch for (README, \"Environments\"): a step's own " ++
    "Dagger client could open the cache volumes of the jobs it does vouch for.";

/// The first directory of the tool cache that an answer's $GITHUB_PATH entries or $GITHUB_ENV
/// values name and no tree "Set up job" checked holds (`tool_trees`); null when the tool cache
/// is not a volume, whose content then goes with the container like any other (#229).
pub fn toolDirNotHeld(x: *Exec, data: std.json.Value) !?[]const u8 {
    const cache = x.tool_cache orelse return null;
    const arena = x.arena;
    var dirs: std.ArrayList([]const u8) = .empty;
    if (fileCommand(data, "fc_path")) |text|
        try dirs.appendSlice(arena, try commands.parsePaths(arena, text));
    // A value may be a list of directories (`PATH`-like) as well as one.
    if (fileCommand(data, "fc_env")) |text| {
        for ((try commands.parseKeyValues(arena, text)).pairs) |e| {
            var parts = std.mem.splitScalar(u8, e.value, ':');
            while (parts.next()) |p| try dirs.append(arena, p);
        }
    }
    for (dirs.items) |dir| {
        if (!std.mem.startsWith(u8, dir, cache) or dir.len == cache.len) continue;
        if (dir[cache.len] != '/') continue;
        if (!treeHolds(x.tool_trees orelse "", dir)) return dir;
    }
    return null;
}

/// Whether one of `trees` (`DIGEST TREE` lines, `set_up.verifyToolTrees`) holds `dir`: is it or
/// is under it, through no `..`.
fn treeHolds(trees: []const u8, dir: []const u8) bool {
    if (std.mem.indexOf(u8, dir, "/..") != null) return false;
    var lines = std.mem.tokenizeScalar(u8, trees, '\n');
    while (lines.next()) |line| {
        const tree = line[(std.mem.indexOfScalar(u8, line, ' ') orelse continue) + 1 ..];
        if (!std.mem.startsWith(u8, dir, tree)) continue;
        if (dir.len == tree.len or dir[tree.len] == '/') return true;
    }
    return false;
}

/// Whether an answer is one the cache kept from an earlier run (#69), given its marker
/// (`ranThisRun`). Without one (its file commands cut short by a full disk, or never written
/// because the step's own `trap 'kill 0' EXIT` killed the shell first), it is an earlier run's
/// unless the step showed it ran in this job, with a live line or its end marker: a cached
/// exec prints nothing, and a failing step that did run here must not run twice (#102).
fn failedEarlier(io: std.Io, sh: *JobLog, num: u32, ran: ?bool) bool {
    if (ran) |r| return !r;
    return !awaitLive(io, sh, num) and !sh.ended[num - 1].load(.acquire);
}

/// Text a step added to $GITHUB_STEP_SUMMARY; past the size limit the summary is dropped, in
/// GitHub's runner's words.
fn appendSummary(x: *Exec, num: u32, text: []const u8) !void {
    if (text.len == 0 or num > x.summaries.len) return;
    // The limit is per file, which is per exec: GitHub checks each step's file, a composite's
    // inner steps' and an action's phases' each on its own (`CreateStepSummaryCommand`).
    if (text.len > max_summary_bytes) {
        x.sh.errorLine(num, try std.fmt.allocPrint(
            x.arena,
            "$GITHUB_STEP_SUMMARY upload aborted, supports content up to a size of " ++
                "{d}k, got {d}k. For more information see: https://docs.github.com/actions/" ++
                "using-workflows/workflow-commands-for-github-actions" ++
                "#adding-a-markdown-summary",
            .{ max_summary_bytes / 1024, text.len / 1024 },
        ));
        return;
    }
    x.summaries[num - 1] = try std.mem.concat(x.arena, u8, &.{ x.summaries[num - 1], text });
}

/// A file command that could not be read to its end, reported as GitHub's runner reports one:
/// two errors, the file's context name and then why (`ProcessFiles` in FileCommandManager.cs).
/// True, for the caller to fail the step.
fn fileCommandFailed(x: *Exec, num: u32, name: []const u8, why: []const u8) !bool {
    x.sh.errorLine(num, try std.fmt.allocPrint(
        x.arena,
        "Unable to process file command '{s}' successfully.",
        .{name},
    ));
    x.sh.errorLine(num, why);
    return true;
}

pub const ActionOut = struct {
    failed: bool,
    exit_code: i32 = 0,
    outputs: []const job_mod.EnvVar = &.{},
};

/// Why a Docker action's exec always runs under step caching: it has the job token
/// (ACTIONS_RUNTIME_TOKEN). Null without step caching.
pub fn alwaysRunNote(x: *Exec) !?[]const u8 {
    if (!x.step_cache) return null;
    return try std.fmt.allocPrint(x.arena, "zig-runner runs this step every time: " ++
        "it uses secrets (run {s})", .{x.run_nonce});
}

/// `splitEnv` of a step's `env:` with this Exec's session, job and secret counter; the message
/// in `x.err_msg`. The defaults GitHub sets again over the env context are left out of what the
/// step's process gets (`Evaluator.withoutReapplied`): `env: {GITHUB_SHA: x}` leaves the commit in
/// `$GITHUB_SHA`, as every handler of GitHub's runner applies them after the step's env
/// (ScriptHandler.cs, NodeScriptActionHandler.cs, ContainerActionHandler.cs). The env context
/// keeps the step's value.
pub fn splitStepEnv(
    x: *Exec,
    env: []const job_mod.EnvVar,
    plain: *std.ArrayList(job_mod.EnvVar),
    secret: *std.ArrayList(SecretRef),
) !void {
    const counter = &x.secrets;
    return splitEnv(
        x.arena,
        x.transport,
        x.job.*,
        x.sh,
        counter,
        try x.ev.withoutReapplied(env),
        plain,
        secret,
        &x.err_msg,
    );
}

pub fn actionFailed(x: *Exec, num: u32, comptime fmt: []const u8, args: anytype) !ActionOut {
    x.sh.append(num, try std.fmt.allocPrint(x.arena, fmt, args));
    return .{ .failed = true, .exit_code = 1 };
}

// actions.zig
pub const runAction = @import("actions.zig").runAction;
pub const loadUses = @import("actions.zig").loadUses;
pub const enterAction = @import("actions.zig").enterAction;
pub const runCompositeStep = @import("actions.zig").runCompositeStep;
pub const nestedEnv = @import("actions.zig").nestedEnv;
pub const runNestedUses = @import("actions.zig").runNestedUses;
pub const runNestedScript = @import("actions.zig").runNestedScript;
pub const logNestedRunHeader = @import("actions.zig").logNestedRunHeader;
pub const runNested = @import("actions.zig").runNested;
pub const runNestedCheckout = @import("actions.zig").runNestedCheckout;
pub const loadFor = @import("actions.zig").loadFor;
pub const resolveInputs = @import("actions.zig").resolveInputs;
pub const runPre = @import("actions.zig").runPre;
pub const runPosts = @import("actions.zig").runPosts;
pub const nestedFailed = @import("actions.zig").nestedFailed;
pub const loadAction = @import("actions.zig").loadAction;
pub const fetchAction = @import("actions.zig").fetchAction;
pub const actionTreeQuery = @import("actions.zig").actionTreeQuery;
pub const loadLocal = @import("actions.zig").loadLocal;

/// `unresolved`: the action's repository or ref could not be fetched, which GitHub reports in
/// "Set up job", before any step runs.
pub const LoadResult = union(enum) { ok: Loaded, failed: []const u8, unresolved: []const u8 };

/// The name GitHub gives a `pre` or `post` step: the prefix and the step's name for the step's
/// own action ("Post Run actions/cache@v4"), or "<prefix> Run <action>" for an action nested in
/// a composite one (`depth` > 0 while a composite action's steps run).
/// The state the running action's `pre` saved: the job step's own, or a nested action's
/// (`nested_pre_state`).
pub fn preState(x: *Exec, num: u32) ![]const job_mod.EnvVar {
    if (x.nested_path.len == 0) return x.pre_state[num - 1];
    return x.nested_pre_state.get(try x.nestedKey(num)) orelse &.{};
}

/// `<step>/<nested_path>`: one action inside the composite action of job step `num`.
pub fn nestedKey(x: *Exec, num: u32) ![]const u8 {
    std.debug.assert(x.nested_path.len > 0);
    return std.fmt.allocPrint(x.arena, "{d}/{s}", .{ num, x.nested_path });
}

pub fn extraName(x: *Exec, prefix: []const u8, num: u32, act: Loaded) ![]const u8 {
    if (x.depth == 0)
        return std.fmt.allocPrint(x.arena, "{s} {s}", .{ prefix, x.job.steps[num - 1].name });
    return std.fmt.allocPrint(x.arena, "{s} Run {s}", .{ prefix, act.ref_label });
}

// js.zig
pub const runJs = @import("js.zig").runJs;
pub const runJsScript = @import("js.zig").runJsScript;
pub const jsEnv = @import("js.zig").jsEnv;
pub const appendJsRuntimeMounts = @import("js.zig").appendJsRuntimeMounts;
pub const nodeFallback = @import("js.zig").nodeFallback;

// hash_files.zig
pub const hashFiles = @import("hash_files.zig").hashFiles;
pub const hashListed = @import("hash_files.zig").hashListed;

/// A line of the job's "Set up job" log (step 0).
pub fn setUpLine(x: *Exec, line: []const u8) void {
    x.sh.append(0, line);
}

/// The start of "Set up job", in the form GitHub's runner uses for a self-hosted runner: the
/// runner, then (for this runner) the image and engine, the GITHUB_TOKEN's permissions, where
/// secrets come from, and the preparation steps.
pub fn logSetUp(x: *Exec, opts: Options) !void {
    const arena = x.arena;
    // GitHub's own line, with this runner's build after it: the protocol version is what GitHub
    // validates and says nothing about which binary is running, which is the question a job's
    // log is asked when a machine behaves unexpectedly.
    x.setUpLine(try std.fmt.allocPrint(
        arena,
        "Current runner version: '{s}' (zig-runner {s})",
        .{ broker.version, build_version.string },
    ));
    x.setUpLine(try std.fmt.allocPrint(arena, "Runner name: '{s}'", .{opts.runner_name}));
    if (x.job.runner_group.len > 0) x.setUpLine(try std.fmt.allocPrint(
        arena,
        "Runner group name: '{s}'",
        .{x.job.runner_group},
    ));
    var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    if (std.posix.gethostname(&host_buf)) |host| {
        x.setUpLine(try std.fmt.allocPrint(arena, "Machine name: '{s}'", .{host}));
    } else |_| {}
    x.setUpLine("##[group]Runner Image");
    x.setUpLine(try std.fmt.allocPrint(arena, "Image: {s}", .{x.job_image}));
    x.setUpLine(if (x.native != null)
        "Engine: native (namespaces, overlayfs and pivot_root in the runner)"
    else if (opts.engine) |ep|
        try std.fmt.allocPrint(
            arena,
            "Engine: Dagger {s}, direct session ({s})",
            .{ engine.client_version, if (ep.host.len > 0) ep.host else ep.container },
        )
    else
        "Engine: Dagger, through `dagger run`");
    if (x.nesting_withheld) x.setUpLine("Dagger in steps: off, as for every job this runner " ++
        "does not vouch for (README, \"Environments\")");
    x.setUpLine("##[endgroup]");
    if (x.job.token_permissions.len > 0) {
        const perms = std.json.parseFromSliceLeaky(
            std.json.Value,
            arena,
            x.job.token_permissions,
            .{},
        ) catch null;
        if (perms) |p| if (p == .object) {
            x.setUpLine("##[group]GITHUB_TOKEN Permissions");
            var it = p.object.iterator();
            while (it.next()) |e| if (e.value_ptr.* == .string) {
                x.setUpLine(try std.fmt.allocPrint(
                    arena,
                    "{s}: {s}",
                    .{ e.key_ptr.*, e.value_ptr.string },
                ));
            };
            x.setUpLine("##[endgroup]");
        };
    }
    x.setUpLine(if (std.mem.eql(
        u8,
        x.ev.githubString("actor"),
        "dependabot[bot]",
    )) "Secret source: Dependabot" else "Secret source: Actions");
    x.setUpLine("Prepare workflow directory");
    x.setUpLine("Prepare all required actions");
    x.setUpLine("Getting action download info");
}

/// The job's GITHUB_TOKEN as a Dagger secret, registered on first use: what checkouts (and
/// fetches of actions in the job's own repository) authenticate with. Null when the job has
/// none or it could not be registered (the fetch then goes without, as for a public
/// repository).
pub fn gitAuth(x: *Exec) ?[]const u8 {
    if (x.git_auth) |g| return switch (g) {
        .none => null,
        .id => |id| id,
    };
    x.git_auth = .none;
    for (x.job.secret_vars) |sv|
        if (std.mem.eql(u8, sv.name, "GITHUB_TOKEN") and sv.value.len > 0) {
            const id = newSecret(
                x.arena,
                x.transport,
                &x.secrets,
                sv.value,
                &x.err_msg,
            ) catch return null;
            x.git_auth = .{ .id = id };
            return id;
        };
    return null;
}

/// With `id-token: write` (GitHub then sends GenerateIdTokenUrl), the variables every step
/// requests OIDC tokens with: the URL, and the job token as a Dagger secret (registered once
/// per job).
pub fn idToken(x: *Exec) !?struct { url: job_mod.EnvVar, token: SecretRef } {
    if (x.job.runtime.id_token_url.len == 0) return null;
    const id = x.id_token_secret orelse id: {
        const id = newSecret(
            x.arena,
            x.transport,
            &x.secrets,
            x.job.job_token,
            &x.err_msg,
        ) catch return error.EngineFailed;
        x.id_token_secret = id;
        break :id id;
    };
    return .{
        .url = .{ .name = "ACTIONS_ID_TOKEN_REQUEST_URL", .value = x.job.runtime.id_token_url },
        .token = .{ .name = "ACTIONS_ID_TOKEN_REQUEST_TOKEN", .id = id },
    };
}

/// What GitHub's runner gives actions besides their inputs: the services actions/cache and
/// artifact actions talk to, and what earlier phases saved (`core.saveState`) as STATE_<name>.
pub fn runtimeEnv(
    x: *Exec,
    env: *std.ArrayList(job_mod.EnvVar),
    state: []const job_mod.EnvVar,
) !void {
    const rt = x.job.runtime;
    const vars = [_]job_mod.EnvVar{
        .{ .name = "ACTIONS_RUNTIME_URL", .value = rt.pipelines_url },
        .{ .name = "ACTIONS_RUNTIME_TOKEN", .value = x.job.job_token },
        .{ .name = "ACTIONS_CACHE_URL", .value = rt.cache_url },
        .{ .name = "ACTIONS_RESULTS_URL", .value = rt.results_url },
        .{ .name = "ACTIONS_CACHE_SERVICE_V2", .value = if (rt.cache_v2) "True" else "" },
    };
    for (vars) |v| if (v.value.len > 0) try env.append(x.arena, v);
    for (state) |st| {
        const name = try std.fmt.allocPrint(x.arena, "STATE_{s}", .{st.name});
        try env.append(x.arena, .{ .name = name, .value = st.value });
    }
}

/// As GitHub shows an action: `##[group]Run <action>`, its inputs, the env it gets (the job's
/// and the step's; secret-backed variables as ***), `##[endgroup]`.
pub fn logGroup(
    x: *Exec,
    num: u32,
    phase: Phase,
    label: []const u8,
    shown: []const job_mod.EnvVar,
    step_env: []const job_mod.EnvVar,
    step_secret: []const SecretRef,
    extra: []const []const u8,
) !void {
    const arena = x.arena;
    x.sh.append(
        num,
        try std.fmt.allocPrint(arena, "##[group]{s} {s}", .{ phase.label(), label }),
    );
    if (shown.len > 0) {
        x.sh.append(num, "with:");
        for (shown) |in| x.sh.append(
            num,
            try std.fmt.allocPrint(arena, "  {s}: {s}", .{ in.name, firstLine(in.value) }),
        );
    }
    var env = try envContext(arena, x.ev.job_env.items, step_env);
    for (step_secret) |sr|
        env = try envContext(arena, env, &.{.{ .name = sr.name, .value = "***" }});
    if (env.len > 0) {
        x.sh.append(num, "env:");
        for (env) |e| x.sh.append(
            num,
            try std.fmt.allocPrint(arena, "  {s}: {s}", .{ e.name, firstLine(e.value) }),
        );
    }
    for (extra) |l| x.sh.append(num, l);
    x.sh.append(num, "##[endgroup]");
}

// docker.zig
pub const ContainerEnv = @import("docker.zig").ContainerEnv;
pub const runDocker = @import("docker.zig").runDocker;
pub const dockerEnv = @import("docker.zig").dockerEnv;
pub const dockerRunFor = @import("docker.zig").dockerRunFor;
pub const runImageStep = @import("docker.zig").runImageStep;
pub const logContainerStart = @import("docker.zig").logContainerStart;
pub const containerScriptFor = @import("docker.zig").containerScriptFor;
pub const runContainer = @import("docker.zig").runContainer;
pub const containerArgv = @import("docker.zig").containerArgv;
pub const workspaceDirId = @import("docker.zig").workspaceDirId;
pub const containerEnv = @import("docker.zig").containerEnv;
pub const writeActionDirs = @import("docker.zig").writeActionDirs;
pub const writeActionEnv = @import("docker.zig").writeActionEnv;
pub const writeActionSecrets = @import("docker.zig").writeActionSecrets;
pub const takeWorkspaceBack = @import("docker.zig").takeWorkspaceBack;

/// Tells the observer that a step the runner adds (a pre or post script, "Initialize containers",
/// "Stop containers") started, logged under `log_step`.
pub fn startExtra(
    x: *Exec,
    kind: ExtraKind,
    log_step: u32,
    name: []const u8,
    started_ms: i64,
) void {
    if (x.observer) |o| if (o.extraStartedFn) |f| f(o.ptr, kind, log_step, name, started_ms);
}

pub fn addExtra(x: *Exec, e: ExtraStep) !void {
    try x.extra.append(x.arena, e);
    if (x.observer) |o| if (o.extraFinishedFn) |f| f(o.ptr, e);
}

// services.zig
pub const startServices = @import("services.zig").startServices;
pub const pullJobContainer = @import("services.zig").pullJobContainer;
pub const startService = @import("services.zig").startService;
pub const serviceSpec = @import("services.zig").serviceSpec;
pub const serviceHead = @import("services.zig").serviceHead;
pub const pullServiceConfig = @import("services.zig").pullServiceConfig;
pub const startServiceContainer = @import("services.zig").startServiceContainer;
pub const bindServicesToJob = @import("services.zig").bindServicesToJob;
pub const writeServiceBindings = @import("services.zig").writeServiceBindings;
pub const stopServices = @import("services.zig").stopServices;

/// The static busybox that starts Docker actions' commands (taken from its image once per job).
pub fn busyboxFile(x: *Exec, num: u32) !?[]const u8 {
    return x.busyboxFileFor(num, false);
}

/// `busyboxFile`; with `outputs`, the output-key store too when it is not known yet, in the
/// same query (see `outputsVolume`).
pub fn busyboxFileFor(x: *Exec, num: u32, outputs: bool) !?[]const u8 {
    if (x.busybox_id) |id| return id;
    var msg: []const u8 = "";
    var q: Query = .init(x.arena);
    try q.callAs("bb", "container", .{});
    try q.call("from", .{ .address = busybox_image });
    try q.call("file", .{ .path = "/bin/busybox" });
    try q.leaf("id");
    try q.close(3);
    try q.callAs("empty", "directory", .{});
    try q.leaf("id");
    const store = outputs and x.outputs_volume == null and x.output_keys != null;
    if (store) {
        try q.close(1);
        try q.callAs("cout", "cacheVolume", .{ .key = x.output_keys.? });
        try q.leaf("id");
    }
    const data = gql(x.arena, x.transport, try q.finish(), &msg) catch {
        _ = try x.actionFailed(
            num,
            "could not get busybox from {s}: {s}",
            .{ busybox_image, msg },
        );
        return null;
    };
    const id = idOf(data, "bb") orelse {
        _ = try x.actionFailed(num, "could not get busybox from {s}", .{busybox_image});
        return null;
    };
    x.empty_dir = idOf(data, "empty") orelse {
        _ = try x.actionFailed(num, "Dagger returned no directory", .{});
        return null;
    };
    if (store) x.outputs_volume = idOf(data, "cout");
    x.busybox_id = id;
    return id;
}

/// A Docker action's image, pulled or built once per job, with its entrypoint and command.
pub fn imageInfo(x: *Exec, num: u32, image: DockerRun.Image, label: []const u8) !?ImageInfo {
    const arena = x.arena;
    const key = switch (image) {
        .pull => |ref| try std.fmt.allocPrint(arena, "pull {s}", .{ref}),
        .build => |b| try std.fmt.allocPrint(
            arena,
            "build {s} {s} {s}",
            .{ b.dir, b.context, b.dockerfile },
        ),
    };
    if (x.images.get(key)) |info| return info;
    var q: Query = .init(arena);
    switch (image) {
        .pull => |ref| {
            try q.open("container");
            try q.call("from", .{ .address = ref });
        },
        .build => |b| {
            try q.call("loadDirectoryFromID", .{ .id = b.dir });
            try q.call("directory", .{ .path = b.context });
            try q.call("dockerBuild", .{ .dockerfile = b.dockerfile });
        },
    }
    for ([_][]const u8{ "id", "entrypoint", "defaultArgs", "user" }) |f| try q.leaf(f);
    var msg: []const u8 = "";
    const data = gql(arena, x.transport, try q.finish(), &msg) catch {
        switch (image) {
            .pull => |ref| _ = try x.actionFailed(
                num,
                "could not pull {s} for {s}: {s}",
                .{ ref, label, msg },
            ),
            .build => |b| _ = try x.actionFailed(
                num,
                "could not build {s} of {s}: {s}",
                .{ b.dockerfile, label, msg },
            ),
        }
        return null;
    };
    const info: ImageInfo = .{
        .id = jsonFindString(data, "id") orelse {
            _ = try x.actionFailed(num, "could not get the image of {s}", .{label});
            return null;
        },
        .entrypoint = try jsonStrings(arena, jsonFind(data, "entrypoint")),
        .cmd = try jsonStrings(arena, jsonFind(data, "defaultArgs")),
        .user = jsonFindString(data, "user") orelse "",
    };
    try x.images.put(arena, key, info);
    return info;
}

pub const Loaded = struct {
    meta: action.Metadata,
    /// Dagger Directory id of the action's repository (of the action's own directory, for a
    /// local action).
    dir: []const u8,
    /// Where the repository is mounted, and the action's own directory inside it.
    mount: []const u8,
    path: []const u8,
    /// The action's directory inside `dir` ("" for its root).
    sub: []const u8 = "",
    /// `owner/repo[/path]@ref` or `./path`, for messages.
    ref_label: []const u8,
    /// The commit the action's ref resolved to ("" when not known), for the "Set up job" log.
    sha: []const u8 = "",
    /// `github.action_repository` / `action_ref` (GITHUB_ACTION_REPOSITORY / _REF):
    /// `owner/repo` and the ref, or empty for a local action, as on GitHub.
    repository: []const u8 = "",
    ref: []const u8 = "",
};

/// The largest step summary GitHub accepts (its `soft_size_limit`).
const max_summary_bytes = 1024 * 1024;

/// The contents of a file command read by the step's query ("" when the field is absent).
/// The exec's exit code; 1 when the result lacks one.
fn exitCode(data: std.json.Value) i32 {
    const c = jsonFind(data, "exitCode") orelse return 1;
    return if (c == .integer) @intCast(c.integer) else 1;
}

fn fileCommand(data: std.json.Value, alias: []const u8) ?[]const u8 {
    if (jsonFind(data, "fc_all")) |all| {
        const text = combinedFileCommand(
            jsonFindString(all, "contents") orelse return null,
            alias["fc_".len..],
        ) orelse return null;
        return if (text.len == 0) null else text;
    }
    const f = jsonFind(data, alias) orelse return null;
    const text = jsonFindString(f, "contents") orelse return null;
    return if (text.len == 0) null else text;
}

/// One kind's contents in a combined file (see `writeCombinedFileCommands`).
fn combinedFileCommand(all: []const u8, kind: []const u8) ?[]const u8 {
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, all, start, fc_marker)) |i| {
        const line_end = std.mem.indexOfScalarPos(u8, all, i, '\n') orelse return null;
        const body = line_end + 1;
        // The next marker starts a line; the newline before it is the one added after the contents.
        const next = std.mem.indexOfPos(u8, all, body, "\n" ++ fc_marker) orelse all.len;
        if (std.mem.eql(u8, all[i + fc_marker.len .. line_end], kind)) {
            const at_end = next == all.len;
            const trailing_newline = at_end and all.len > body and all[all.len - 1] == '\n';
            const end = if (trailing_newline) all.len - 1 else next;
            return all[body..@max(body, end)];
        }
        start = if (next == all.len) all.len else next + 1;
    }
    return null;
}

test "a failed answer without a ran marker is an earlier run's unless the step showed it ran here" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var w: std.Io.Writer.Discarding = .init(&.{});
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w.writer } };
    var live = [_]std.atomic.Value(u32){.init(0)};
    var ended = [_]std.atomic.Value(bool){.init(false)};
    var sh: JobLog = .{
        .io = std.testing.io,
        .arena = a.allocator(),
        .log = &log,
        .sink_job_id = 0,
        .live_lines = &live,
        .ended = &ended,
        // The live line below never gets its end marker: not 5 s of waiting for it.
        .stall_ms = 50,
    };
    // The marker decides when there is one.
    try std.testing.expect(failedEarlier(std.testing.io, &sh, 1, false));
    try std.testing.expect(!failedEarlier(std.testing.io, &sh, 1, true));
    // Without one: nothing reached the live log, so the cache answered.
    try std.testing.expect(failedEarlier(std.testing.io, &sh, 1, null));
    // A live line, or the end marker alone: it ran in this job.
    live[0].store(1, .monotonic);
    try std.testing.expect(!failedEarlier(std.testing.io, &sh, 1, null));
    live[0].store(0, .monotonic);
    ended[0].store(true, .release);
    try std.testing.expect(!failedEarlier(std.testing.io, &sh, 1, null));
}

test "a cached exec is replayed though the exec before it, of the same step, is still arriving" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &w } };
    // A composite's inner step A ran; its last lines are still arriving when inner step B, which
    // the cache answered, is collected: the step's count is above zero, and B's end never comes.
    var live = [_]std.atomic.Value(u32){.init(2)};
    var ended = [_]std.atomic.Value(bool){.init(false)};
    var replayed = [_]bool{false};
    var cmds = [_]JobLog.StepCommands{.{}};
    var sh: JobLog = .{
        .io = std.testing.io,
        .arena = a.allocator(),
        .log = &log,
        .sink_job_id = 0,
        .live_lines = &live,
        .ended = &ended,
        .replayed_steps = &replayed,
        .commands = &cmds,
    };
    try std.testing.expect(!liveThisExec(std.testing.io, &sh, 1, false));
    _ = replayNotLive(&sh, 1, "::set-output name=v::from-b\nb's line\n", "", false);
    const outs = sh.takeOutputs(1);
    try std.testing.expectEqual(@as(usize, 1), outs.len);
    try std.testing.expectEqualStrings("from-b", outs[0].value);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "b's line") != null);
    // Nor did it wait for an end that never comes, and warn of output that had not arrived.
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "had not arrived") == null);
    // An exec that ran here, or did not say, still waits for its own lines.
    ended[0].store(true, .release);
    try std.testing.expect(liveThisExec(std.testing.io, &sh, 1, true));
    try std.testing.expect(liveThisExec(std.testing.io, &sh, 1, null));
}

test "file commands come back from one combined file" {
    const all = "::zig-file-command::output\nversion=1\nnotes<<EOF\na\nEOF\n\n::zig-file-command::env\n\n::zig-file-command::path\n/opt/x/bin\n\n::zig-file-command::step_summary\nno newline at end\n::zig-file-command::state\n\n";
    try std.testing.expectEqualStrings("version=1\nnotes<<EOF\na\nEOF\n", combinedFileCommand(all, "output").?);
    try std.testing.expectEqualStrings("", combinedFileCommand(all, "env").?);
    try std.testing.expectEqualStrings("/opt/x/bin\n", combinedFileCommand(all, "path").?);
    try std.testing.expectEqualStrings("no newline at end", combinedFileCommand(all, "step_summary").?);
    try std.testing.expectEqualStrings("", combinedFileCommand(all, "state").?);
    try std.testing.expect(combinedFileCommand(all, "missing") == null);
}
