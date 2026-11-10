//! Holds what expressions can see while a job runs and evaluates the templates of each step.

const Evaluator = @This();

const std = @import("std");
const Sha256 = @import("../sha256.zig").Sha256;
const job_mod = @import("../job.zig");
const expr = @import("../expr.zig");
const context = @import("../context.zig");
const broker = @import("../github/broker.zig");
const Exec = @import("Exec.zig");
const Outcome = @import("../dagger.zig").Outcome;
const jobWorkspace = @import("../dagger.zig").jobWorkspace;
const jobTemp = @import("../dagger.zig").jobTemp;
const hasKey = @import("../dagger.zig").hasKey;
const withEntries = @import("../dagger.zig").withEntries;
const event_path = @import("../dagger.zig").event_path;
const isVolatile = @import("../dagger.zig").isVolatile;
const testJob = @import("testing.zig").testJob;
const testStep = @import("testing.zig").testStep;

const Allocator = std.mem.Allocator;

arena: Allocator,
job: *const job_mod.Job,
/// github, inputs, matrix, needs, strategy, vars from the job's contextData.
github: expr.Value,
inputs: expr.Value,
matrix: expr.Value,
needs: expr.Value,
strategy: expr.Value,
vars: expr.Value,
/// `job` from contextData (`check_run_id`, `workflow_ref`, ...), which GitHub copies whole into
/// the `job` context before adding `status`, `services` and `container`.
job_context: expr.Value,
/// Workflow- and job-level env, evaluated once.
job_env: std.ArrayList(job_mod.EnvVar) = .empty,
steps: std.ArrayList(StepCtx) = .empty,
/// Changes a step made through $GITHUB_ENV / $GITHUB_PATH, applied to the container before the
/// next step.
pending_env: std.ArrayList(job_mod.EnvVar) = .empty,
/// Directories added since the container's PATH was last written, oldest first, each once.
pending_path: std.ArrayList([]const u8) = .empty,
/// Every directory added through $GITHUB_PATH in the job, oldest first, each once: GitHub's
/// `Global.PrependPath`. PATH starts with them newest first.
path_prepend: std.ArrayList([]const u8) = .empty,
job_failed: bool = false,
/// Set once GitHub cancelled the job: `cancelled()` is true and `success()` false from then on.
cancelled: bool = false,
/// `job.services`: `{<name>: {id, network, ports: {<container port>: <host port>}}}`.
services: ?expr.Value = null,
/// `job.container`: `{id, network}` in a `container:` job, `{network}` in a job with only
/// services, as GitHub sets it when it starts the job's containers.
container: ?expr.Value = null,
/// Inside a composite action: whether the job had failed when the outermost action started.
/// `job.status` reads it there, as on GitHub, where the job's status changes only between the
/// job's own steps; `job_failed` is the action's own, for its steps' `success()`.
status_failed: ?bool = null,
diag: []const u8 = "",
/// Reads the job's files for `hashFiles()`, once the job's container exists.
hash_files: ?expr.HashFiles = null,
/// `runner.name` and RUNNER_NAME: the name the runner registered under.
runner_name: []const u8 = "zig-runner",
/// Step debug is on (ACTIONS_STEP_DEBUG): steps get RUNNER_DEBUG=1, as on GitHub.
runner_debug: bool = false,
/// GITHUB_WORKSPACE and RUNNER_TEMP (see `jobWorkspace`).
workspace: []const u8 = "",
temp: []const u8 = "",

// --- expression evaluation ---

/// One entry of the `steps` context: a finished step's outcome, conclusion and outputs, by its id.
pub const StepCtx = struct {
    id: []const u8,
    outcome: []const u8,
    conclusion: []const u8,
    outputs: []const job_mod.EnvVar,
};

/// An evaluator for `job`, its contexts as the job sent them.
pub fn init(arena: Allocator, job: *const job_mod.Job) !Evaluator {
    var ev: Evaluator = .{
        .arena = arena,
        .job = job,
        .workspace = try jobWorkspace(arena, job.*),
        .temp = try jobTemp(arena, job.*),
        .github = try context.named(arena, job.context_data, "github"),
        .inputs = try context.named(arena, job.context_data, "inputs"),
        .matrix = try context.named(arena, job.context_data, "matrix"),
        .needs = try context.named(arena, job.context_data, "needs"),
        .strategy = try context.named(arena, job.context_data, "strategy"),
        .vars = try context.named(arena, job.context_data, "vars"),
        .job_context = try context.named(arena, job.context_data, "job"),
    };
    // GitHub's runner adds `github.token` (the job's GITHUB_TOKEN); it is not in contextData.
    // Actions default their `github-token` input to it.
    if (ev.github == .object and !hasKey(ev.github, "token")) {
        for (job.secret_vars) |sv| if (std.mem.eql(u8, sv.name, "GITHUB_TOKEN")) {
            ev.github = try withEntries(
                arena,
                ev.github,
                &.{.{ .key = "token", .value = .{ .string = sv.value } }},
            );
        };
    }
    // Nor is `github.job` (GITHUB_JOB, the job's key in the workflow): it comes from the
    // message's `jobName`.
    if (ev.github == .object and !hasKey(ev.github, "job") and job.github.job.len > 0) {
        ev.github = try withEntries(
            arena,
            ev.github,
            &.{.{ .key = "job", .value = .{ .string = job.github.job } }},
        );
    }
    // Nor is `github.workspace` (GITHUB_WORKSPACE), which actions use as an input default
    // (setup-uv's `working-directory`).
    if (ev.github == .object and !hasKey(ev.github, "workspace")) {
        ev.github = try withEntries(
            arena,
            ev.github,
            &.{.{ .key = "workspace", .value = .{ .string = ev.workspace } }},
        );
    }
    for (job.env) |in| {
        const sc = try ev.scope(&.{});
        const val = ev.render(in.value, sc) catch
            continue; // an env value that cannot be evaluated stays unset
        try putEnv(arena, &ev.job_env, in.name, val);
    }
    return ev;
}

/// Sets `name` in `list`, replacing a value already there.
pub fn putEnv(
    arena: Allocator,
    list: *std.ArrayList(job_mod.EnvVar),
    name: []const u8,
    value: []const u8,
) !void {
    for (list.items) |*e| if (std.mem.eql(u8, e.name, name)) {
        e.value = value;
        return;
    };
    try list.append(arena, .{ .name = name, .value = value });
}

/// A directory a step added through $GITHUB_PATH. As GitHub's `AddPathFileCommand`
/// (`FileCommandManager.cs` ~140-155), an earlier copy is removed and the directory goes last, so
/// it comes first in PATH.
pub fn addPath(ev: *Evaluator, dir: []const u8) !void {
    for ([_]*std.ArrayList([]const u8){ &ev.pending_path, &ev.path_prepend }) |list| {
        for (list.items, 0..) |d, i| if (std.mem.eql(u8, d, dir)) {
            _ = list.orderedRemove(i);
            break;
        };
        try list.append(ev.arena, dir);
    }
}

/// `dirs` newest first, joined with `:`, as GitHub's `Handler.AddPrependPathToEnvironment`
/// (`Handler.cs` ~205-232) puts them before PATH.
pub fn prependPath(arena: Allocator, dirs: []const []const u8) ![]const u8 {
    std.debug.assert(dirs.len > 0);
    var out: std.ArrayList(u8) = .empty;
    var i = dirs.len;
    while (i > 0) {
        i -= 1;
        try out.appendSlice(arena, dirs[i]);
        if (i > 0) try out.append(arena, ':');
    }
    return out.items;
}

/// The scope for evaluating one step: `step_env` is applied on top of the job's env.
pub fn scope(ev: *Evaluator, step_env: []const job_mod.EnvVar) !expr.Scope {
    const arena = ev.arena;
    var env_list: std.ArrayList(job_mod.EnvVar) = .empty;
    try env_list.appendSlice(arena, ev.job_env.items);
    for (step_env) |e| try putEnv(arena, &env_list, e.name, e.value);
    const env_entries = try arena.alloc(expr.Value.Entry, env_list.items.len);
    for (env_list.items, env_entries) |e, *o|
        o.* = .{ .key = e.name, .value = .{ .string = e.value } };

    // A step without an `id:` of its own has no name (the job's) or a generated one starting with
    // `__` (`__run`, a composite step's `__1`), and GitHub leaves it out of `steps`, so
    // `steps.*.outcome` lists only steps the workflow named (actions/runner
    // src/Runner.Worker/ExecutionContext.cs 652-660, 713-720).
    var step_entries: std.ArrayList(expr.Value.Entry) = .empty;
    for (ev.steps.items) |sc| {
        if (sc.id.len == 0 or std.mem.startsWith(u8, sc.id, "__")) continue;
        const outs = try arena.alloc(expr.Value.Entry, sc.outputs.len);
        for (sc.outputs, outs) |ov, *oo|
            oo.* = .{ .key = ov.name, .value = .{ .string = ov.value } };
        const fields = try arena.alloc(expr.Value.Entry, 3);
        fields[0] = .{ .key = "outputs", .value = .{ .object = outs } };
        fields[1] = .{ .key = "outcome", .value = .{ .string = sc.outcome } };
        fields[2] = .{ .key = "conclusion", .value = .{ .string = sc.conclusion } };
        try step_entries.append(arena, .{ .key = sc.id, .value = .{ .object = fields } });
    }

    // contextData's `job` first, then what the runner sets (actions/runner
    // src/Runner.Worker/ExecutionContext.cs 1023-1033, ContainerOperationProvider.cs).
    var job_fields: std.ArrayList(expr.Value.Entry) = .empty;
    if (ev.job_context == .object) for (ev.job_context.object) |e| {
        const ours = std.ascii.eqlIgnoreCase(e.key, "status") or
            std.ascii.eqlIgnoreCase(e.key, "services") or
            std.ascii.eqlIgnoreCase(e.key, "container");
        if (!ours) try job_fields.append(arena, e);
    };
    try job_fields.append(arena, .{ .key = "status", .value = .{ .string = ev.jobStatus() } });
    if (ev.services) |v| try job_fields.append(arena, .{ .key = "services", .value = v });
    if (ev.container) |v| try job_fields.append(arena, .{ .key = "container", .value = v });
    const runner_fields = try arena.alloc(expr.Value.Entry, if (ev.runner_debug) 8 else 7);
    runner_fields[0] = .{ .key = "os", .value = .{ .string = "Linux" } };
    runner_fields[1] = .{ .key = "arch", .value = .{ .string = broker.arch } };
    runner_fields[2] = .{ .key = "name", .value = .{ .string = ev.runner_name } };
    runner_fields[3] = .{ .key = "temp", .value = .{ .string = ev.temp } };
    runner_fields[4] = .{ .key = "tool_cache", .value = .{ .string = "/opt/hostedtoolcache" } };
    runner_fields[5] = .{ .key = "environment", .value = .{ .string = "self-hosted" } };
    // RUNNER_WORKSPACE's value: the directory above the workspace (JobExtension.cs 213-215).
    runner_fields[6] = .{ .key = "workspace", .value = .{ .string = ev.runnerWorkspace() } };
    if (ev.runner_debug) runner_fields[7] = .{ .key = "debug", .value = .{ .string = "1" } };

    const secret_entries = try arena.alloc(expr.Value.Entry, ev.job.secret_vars.len);
    for (ev.job.secret_vars, secret_entries) |sv, *o|
        o.* = .{ .key = sv.name, .value = .{ .string = sv.value } };

    const ctxs = try arena.alloc(expr.Value.Entry, 11);
    ctxs[0] = .{ .key = "github", .value = ev.github };
    ctxs[1] = .{ .key = "env", .value = .{ .object = env_entries } };
    ctxs[2] = .{ .key = "steps", .value = .{ .object = step_entries.items } };
    ctxs[3] = .{ .key = "job", .value = .{ .object = job_fields.items } };
    ctxs[4] = .{ .key = "runner", .value = .{ .object = runner_fields } };
    ctxs[5] = .{ .key = "inputs", .value = ev.inputs };
    ctxs[6] = .{ .key = "matrix", .value = ev.matrix };
    ctxs[7] = .{ .key = "needs", .value = ev.needs };
    ctxs[8] = .{ .key = "strategy", .value = ev.strategy };
    ctxs[9] = .{ .key = "vars", .value = ev.vars };
    ctxs[10] = .{ .key = "secrets", .value = .{ .object = secret_entries } };
    return .{
        .contexts = ctxs,
        .job_failed = ev.job_failed,
        .cancelled = ev.cancelled,
        .diag = &ev.diag,
        .hash_files = ev.hash_files,
    };
}

/// A template's text: a literal as it is, an expression evaluated in `sc`.
pub fn render(ev: *Evaluator, t: job_mod.Template, sc: expr.Scope) ![]const u8 {
    return switch (t) {
        .lit => |l| l,
        .expr => |e| expr.evalString(ev.arena, e, sc),
    };
}

/// The environment (or `with:` inputs) a step is given, each value rendered in `sc`.
pub fn renderEnv(
    ev: *Evaluator,
    inputs: []const job_mod.Input,
    sc: expr.Scope,
) ![]const job_mod.EnvVar {
    const out = try ev.arena.alloc(job_mod.EnvVar, inputs.len);
    for (inputs, out) |in, *o| o.* = .{ .name = in.name, .value = try ev.render(in.value, sc) };
    return out;
}

/// `job.status` as the expression language sees it.
fn jobStatus(ev: *const Evaluator) []const u8 {
    if (ev.cancelled) return "cancelled";
    return if (ev.status_failed orelse ev.job_failed) "failure" else "success";
}

/// `runner.workspace` and RUNNER_WORKSPACE.
fn runnerWorkspace(ev: *const Evaluator) []const u8 {
    return std.fs.path.dirnamePosix(ev.workspace) orelse "/";
}

/// `job.services` from the running services, and `job.container`: `container_id` is the job
/// container's, null in a job with only services.
pub fn setServices(
    ev: *Evaluator,
    running: []const Exec.RunningService,
    container_id: ?[]const u8,
) !void {
    const arena = ev.arena;
    const container = try arena.alloc(expr.Value.Entry, if (container_id != null) 2 else 1);
    container[0] = .{ .key = "network", .value = .{ .string = "dagger" } };
    if (container_id) |id| {
        container[1] = .{ .key = "id", .value = .{ .string = try stableId(arena, id) } };
    }
    ev.container = .{ .object = container };
    const entries = try arena.alloc(expr.Value.Entry, running.len);
    for (running, entries) |r, *e| {
        const ports = try arena.alloc(expr.Value.Entry, r.ports.len);
        for (r.ports, ports) |p, *pe| pe.* = .{
            .key = try std.fmt.allocPrint(arena, "{d}", .{p.container}),
            .value = .{ .string = try std.fmt.allocPrint(arena, "{d}", .{p.host}) },
        };
        const fields = try arena.alloc(expr.Value.Entry, 3);
        fields[0] = .{ .key = "id", .value = .{ .string = try stableId(arena, r.id) } };
        fields[1] = .{ .key = "network", .value = .{ .string = "dagger" } };
        fields[2] = .{ .key = "ports", .value = .{ .object = ports } };
        e.* = .{ .key = r.name, .value = .{ .object = fields } };
    }
    ev.services = .{ .object = entries };
}

/// A stable id for a running container, from its Dagger id (GitHub gives the Docker container's
/// id, which no step here can use, so only its shape matters).
fn stableId(arena: Allocator, dagger_id: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(dagger_id, &digest, .{});
    return std.fmt.allocPrint(arena, "{x}", .{&digest});
}

/// Adds a finished step to the `steps` context. A failure the step continued past concludes as a
/// success, as in GitHub.
pub fn record(
    ev: *Evaluator,
    step: job_mod.Step,
    outcome: Outcome,
    continued: bool,
    outputs: []const job_mod.EnvVar,
) !void {
    const raw: []const u8 = switch (outcome) {
        .success => "success",
        .failure => "failure",
        .cancelled => "cancelled",
        .skipped, .not_run => "skipped",
    };
    const conclusion: []const u8 = if (outcome == .failure and continued) "success" else raw;
    try ev.steps.append(ev.arena, .{
        .id = step.context_name,
        .outcome = raw,
        .conclusion = conclusion,
        .outputs = outputs,
    });
}

/// A `github` context value as GitHub's runner puts it in the environment: strings as they
/// are, numbers and booleans as text; null when the context has no such key.
fn githubText(ev: *const Evaluator, key: []const u8) !?[]const u8 {
    if (ev.github != .object) return null;
    for (ev.github.object) |e|
        if (std.ascii.eqlIgnoreCase(e.key, key)) return switch (e.value) {
            .string, .number, .boolean => try expr.toStr(ev.arena, e.value),
            else => null,
        };
    return null;
}

/// A string from the `github` context ("" when absent).
pub fn githubString(ev: *const Evaluator, key: []const u8) []const u8 {
    if (ev.github != .object) return "";
    for (ev.github.object) |e|
        if (std.ascii.eqlIgnoreCase(e.key, key)) return switch (e.value) {
            .string => |str| str,
            else => "",
        };
    return "";
}

/// `github.event` as JSON, for GITHUB_EVENT_PATH; `{}` when the job has none.
pub fn eventJson(ev: *Evaluator) ![]const u8 {
    const ctxs = [_]expr.Value.Entry{.{ .key = "github", .value = ev.github }};
    const text = expr.evalString(ev.arena, "toJSON(github.event)", .{ .contexts = &ctxs }) catch
        return "{}";
    return if (std.mem.eql(u8, text, "null") or text.len == 0) "{}" else text;
}

/// The variables every step sees, as on a GitHub-hosted runner.
pub fn defaultEnv(ev: *const Evaluator) ![]const job_mod.EnvVar {
    var out: std.ArrayList(job_mod.EnvVar) = .empty;
    const fixed = [_]job_mod.EnvVar{
        .{ .name = "CI", .value = "true" },
        .{ .name = "GITHUB_ACTIONS", .value = "true" },
        .{ .name = "GITHUB_WORKSPACE", .value = ev.workspace },
        .{ .name = "RUNNER_OS", .value = "Linux" },
        .{ .name = "RUNNER_ARCH", .value = broker.arch },
        .{ .name = "RUNNER_NAME", .value = ev.runner_name },
        .{ .name = "RUNNER_TEMP", .value = ev.temp },
        .{ .name = "RUNNER_TOOL_CACHE", .value = "/opt/hostedtoolcache" },
        .{ .name = "RUNNER_WORKSPACE", .value = ev.runnerWorkspace() },
        .{ .name = "RUNNER_ENVIRONMENT", .value = "self-hosted" },
        .{ .name = "GITHUB_EVENT_PATH", .value = event_path },
        // Set in every step, empty outside an action's own steps (which set them), as on
        // GitHub.
        .{ .name = "GITHUB_ACTION_REPOSITORY", .value = "" },
        .{ .name = "GITHUB_ACTION_REF", .value = "" },
    };
    try out.appendSlice(ev.arena, &fixed);
    if (ev.runner_debug) try out.append(ev.arena, .{ .name = "RUNNER_DEBUG", .value = "1" });
    const from_github = [_][2][]const u8{
        .{ "GITHUB_REPOSITORY", "repository" },
        .{ "GITHUB_REPOSITORY_OWNER", "repository_owner" },
        .{ "GITHUB_SHA", "sha" },
        .{ "GITHUB_REF", "ref" },
        .{ "GITHUB_REF_NAME", "ref_name" },
        .{ "GITHUB_REF_TYPE", "ref_type" },
        .{ "GITHUB_EVENT_NAME", "event_name" },
        .{ "GITHUB_ACTOR", "actor" },
        .{ "GITHUB_TRIGGERING_ACTOR", "triggering_actor" },
        .{ "GITHUB_RUN_ID", "run_id" },
        .{ "GITHUB_RUN_NUMBER", "run_number" },
        .{ "GITHUB_RUN_ATTEMPT", "run_attempt" },
        .{ "GITHUB_JOB", "job" },
        .{ "GITHUB_WORKFLOW", "workflow" },
        .{ "GITHUB_BASE_REF", "base_ref" },
        .{ "GITHUB_HEAD_REF", "head_ref" },
        .{ "GITHUB_SERVER_URL", "server_url" },
        .{ "GITHUB_API_URL", "api_url" },
        .{ "GITHUB_GRAPHQL_URL", "graphql_url" },
        .{ "GITHUB_ACTOR_ID", "actor_id" },
        .{ "GITHUB_REPOSITORY_ID", "repository_id" },
        .{ "GITHUB_REPOSITORY_OWNER_ID", "repository_owner_id" },
        .{ "GITHUB_WORKFLOW_REF", "workflow_ref" },
        .{ "GITHUB_WORKFLOW_SHA", "workflow_sha" },
        .{ "GITHUB_REF_PROTECTED", "ref_protected" },
        .{ "GITHUB_RETENTION_DAYS", "retention_days" },
    };
    // Every key the context has, even an empty one (GITHUB_BASE_REF and GITHUB_HEAD_REF on a
    // push): a script under `set -u` reads them on GitHub.
    for (from_github) |m| {
        if (try ev.githubText(m[1])) |v|
            try out.append(ev.arena, .{ .name = m[0], .value = v });
    }
    return out.items;
}

/// `env`, an `env` context (workflow, job, GITHUB_ENV), without the variables GitHub sets again
/// over it in every step's processes: its `GITHUB_*` from the `github` context's allowlist and
/// `RUNNER_*` from the `runner` context (`GetRuntimeEnvironmentVariables` in actions/runner's
/// GitHubContext.cs and RunnerContext.cs, applied after the env context in ScriptHandler.cs and
/// ContainerActionHandler.cs), and GITHUB_ACTIONS (ProcessInvoker.cs). Those are `defaultEnv`'s
/// names but `CI`, which GitHub sets only when nothing else has. The `env` context keeps them:
/// `${{ env.GITHUB_SHA }}` reads what a step wrote, as on GitHub.
pub fn withoutReapplied(
    ev: *const Evaluator,
    env: []const job_mod.EnvVar,
) ![]const job_mod.EnvVar {
    const defaults = try ev.defaultEnv();
    var out: std.ArrayList(job_mod.EnvVar) = .empty;
    for (env) |e| {
        const reapplied = !std.mem.eql(u8, e.name, "CI") and
            for (defaults) |d| (if (std.mem.eql(u8, d.name, e.name)) break true) else false;
        if (!reapplied) try out.append(ev.arena, e);
    }
    return out.items;
}

test "the variables GitHub's runner sets: empty ones too, numbers and booleans as text" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var job = testJob(&.{});
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"base_ref","v":""},{"k":"head_ref","v":""},
        \\ {"k":"repository_id","v":123},{"k":"ref_protected","v":false},{"k":"workflow_sha","v":"0123abc"}]}}
    , .{});
    var ev = try Evaluator.init(arena, &job);
    ev.runner_debug = true;
    const env = try ev.defaultEnv();
    const Want = struct { []const u8, []const u8 };
    for ([_]Want{
        .{ "GITHUB_BASE_REF", "" },
        .{ "GITHUB_HEAD_REF", "" },
        .{ "GITHUB_REPOSITORY_ID", "123" },
        .{ "GITHUB_REF_PROTECTED", "false" },
        .{ "GITHUB_WORKFLOW_SHA", "0123abc" },
        .{ "RUNNER_ENVIRONMENT", "self-hosted" },
        .{ "RUNNER_WORKSPACE", "/home/runner/work/r" },
        .{ "RUNNER_DEBUG", "1" },
        .{ "GITHUB_ACTION_REPOSITORY", "" },
    }) |want| {
        const got = for (env) |e| (if (std.mem.eql(u8, e.name, want[0])) break e.value) else return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(want[1], got);
    }
    // Keys the context does not have are not set.
    for (env) |e| try std.testing.expect(!std.mem.eql(u8, e.name, "GITHUB_ACTOR_ID"));
    // The workflow's commit and ref follow the commit and branch: not part of step cache keys.
    try std.testing.expect(isVolatile("GITHUB_WORKFLOW_SHA") and isVolatile("GITHUB_WORKFLOW_REF"));
}

test "the env context reaches processes but for the defaults GitHub sets again" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var job = testJob(&.{});
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"},{"k":"sha","v":"abc"}]}}
    , .{});
    const ev = try Evaluator.init(arena, &job);
    const env = [_]job_mod.EnvVar{
        .{ .name = "GITHUB_SHA", .value = "evil" },
        .{ .name = "RUNNER_TEMP", .value = "/elsewhere" },
        .{ .name = "GITHUB_ACTIONS", .value = "false" },
        .{ .name = "CI", .value = "false" },
        .{ .name = "GITHUB_TOKEN", .value = "pat" },
        .{ .name = "RUNNER_MINE", .value = "1" },
        // Not in this job's github context, so GitHub does not set it again either.
        .{ .name = "GITHUB_ACTOR_ID", .value = "7" },
    };
    const kept = try ev.withoutReapplied(&env);
    try std.testing.expectEqual(@as(usize, 4), kept.len);
    for (kept, [_][]const u8{ "CI", "GITHUB_TOKEN", "RUNNER_MINE", "GITHUB_ACTOR_ID" }) |e, n|
        try std.testing.expectEqualStrings(n, e.name);
}

test "github.workspace is the job's workspace, as actions' input defaults expect" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{testStep("true")};
    var job = testJob(&steps);
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"}]}}
    , .{});
    var ev = try Evaluator.init(arena, &job);
    try std.testing.expectEqualStrings("/home/runner/work/r/r", ev.githubString("workspace"));
    try std.testing.expectEqualStrings("/home/runner/work/r/r", try ev.render(.{ .expr = "github.workspace" }, try ev.scope(&.{})));
}

test "the job context is contextData's job, with status, services and container from the runner" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const steps = [_]job_mod.Step{testStep("true")};
    var job = testJob(&steps);
    job.context_data = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"github":{"t":2,"d":[{"k":"repository","v":"o/r"}]},
        \\ "job":{"t":2,"d":[{"k":"check_run_id","v":123},{"k":"workflow_ref","v":"o/r/.github/workflows/ci.yml@refs/heads/main"},{"k":"status","v":"stale"}]}}
    , .{});
    var ev = try Evaluator.init(arena, &job);
    const Case = struct { []const u8, []const u8 };
    for ([_]Case{
        .{ "job.check_run_id", "123" },
        .{ "job.workflow_ref", "o/r/.github/workflows/ci.yml@refs/heads/main" },
        .{ "job.status", "success" },
        .{ "job.container.network", "" },
        .{ "runner.workspace", "/home/runner/work/r" },
    }) |c| try std.testing.expectEqualStrings(c[1], try ev.render(.{ .expr = c[0] }, try ev.scope(&.{})));
    // A container job's containers have started: `job.container` has its network and an id.
    try ev.setServices(&.{}, "C0");
    try std.testing.expectEqualStrings("dagger", try ev.render(.{ .expr = "job.container.network" }, try ev.scope(&.{})));
    try std.testing.expectEqual(@as(usize, 64), (try ev.render(.{ .expr = "job.container.id" }, try ev.scope(&.{}))).len);
}
