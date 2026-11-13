//! A Gitea or Forgejo task as the `job.Job` the backends run (#520, G3): what `job.parse` makes of
//! GitHub's job message, made from the task's `workflowPayload` YAML and its context, secrets, vars
//! and needs.
//!
//! GitHub resolves a job before it sends it, and `job.parse` only reads the result: a step's
//! `uses:` already split into a repository, a name and a ref, its text already rewritten from
//! `echo ${{ github.sha }}` into `format('echo {0}', github.sha)`. Gitea sends the YAML as written
//! (one job, its matrix cut to the job's own values), so the same work is done here, by the same
//! rules: a text with no `${{` is a literal, a text that is one expression alone is that
//! expression, and anything else is one `format()` expression, as GitHub's `TemplateReader` makes
//! it. The backends see no difference between the two front ends.
//!
//! What the task does not say is left for later steps: the `Runtime` URLs and `results_endpoint`
//! stay empty (G5 sets them from the instance), and nothing here runs the job (G4).
//!
//! Where the task has no counterpart in `job.Job`:
//!   - `plan_id` and `job_id` are the task's id, as text. The instance has no plan, and the task id
//!     is the one name for this job on both sides, which logs and `UpdateTask` use.
//!   - `check_run_id` is the task id too (0 if it does not fit), the database's key for the job.
//!   - `job_token` is the context's `gitea_runtime_token` (the token the job presents to the
//!     instance's artifact and cache services), or empty. There is no `completejob` here to use it.
//!   - The job's own `runs-on`, `if`, `timeout-minutes` and `continue-on-error` have no field in
//!     `job.Job`, which GitHub enforces itself; they are in `Converted`, for the poller to use.
const std = @import("std");
const job_mod = @import("../job.zig");
const yaml = @import("../yaml.zig");
const expr = @import("../expr.zig");
const task_mod = @import("task.zig");

const Allocator = std.mem.Allocator;
const Node = yaml.Node;
const Value = std.json.Value;
const Template = job_mod.Template;
const Input = job_mod.Input;

pub const Error = error{BadWorkflow} || Allocator.Error;

/// The job and what the task says of it that `job.Job` has no place for.
pub const Converted = struct {
    job: job_mod.Job,
    /// `runs-on`: the labels the instance matched to this runner. The server has already chosen
    /// the runner by them; they are kept for the log.
    runs_on: []const []const u8 = &.{},
    /// The job's `if`, as written ("" when it sets none: Gitea adds `always()`). The instance has
    /// evaluated it before it handed the task over.
    condition: []const u8 = "",
    /// The job's `timeout-minutes`, which the runner has to enforce itself.
    timeout_minutes: ?Template = null,
    /// The job's `continue-on-error`, for the instance's bookkeeping of the run.
    continue_on_error: Template = .{ .lit = "false" },
};

/// The job `t` describes. On `error.BadWorkflow`, `why` is the reason, for the operator and the
/// task's log. What is wrong with one part of the job (a step the runner cannot run, a `container:`
/// it cannot read) does not stop the conversion: it is marked as `job.parse` marks the same, and
/// fails when the job reaches it.
pub fn fromTask(arena: Allocator, t: task_mod.Task, why: *[]const u8) Error!Converted {
    var b: Builder = .{ .arena = arena };
    return b.convert(t) catch |e| switch (e) {
        error.Bad => {
            why.* = b.why;
            return error.BadWorkflow;
        },
        error.OutOfMemory => return error.OutOfMemory,
    };
}

const BuildError = error{ Bad, OutOfMemory };

const Builder = struct {
    arena: Allocator,
    why: []const u8 = "",

    fn bad(b: *Builder, comptime fmt: []const u8, args: anytype) BuildError {
        b.why = try std.fmt.allocPrint(b.arena, fmt, args);
        return error.Bad;
    }

    fn convert(b: *Builder, t: task_mod.Task) BuildError!Converted {
        const arena = b.arena;
        var diag: yaml.Diag = .{};
        const doc = yaml.parseTyped(arena, t.workflow, &diag) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return b.bad("the workflow is not read ({s}, line {d}): {s}", .{
                @errorName(e), diag.line, diag.message,
            }),
        };
        const jobs = doc.get("jobs") orelse return b.bad("the workflow has no jobs", .{});
        if (jobs != .map or jobs.map.len != 1) return b.bad(
            "a task is one job, and this has {d}",
            .{if (jobs == .map) jobs.map.len else 0},
        );
        const key = jobs.map[0].key;
        const jn = jobs.map[0].value;
        if (jn != .map) return b.bad("job '{s}' is not a mapping", .{key});

        const steps_node = jn.get("steps") orelse return b.bad("job '{s}' has no steps", .{key});
        if (steps_node != .seq) return b.bad("job '{s}': steps is not a list", .{key});
        const steps = try arena.alloc(job_mod.Step, steps_node.seq.len);
        var unnamed: usize = 0;
        for (steps_node.seq, steps, 0..) |sn, *out, i|
            out.* = try b.step(t.id, i + 1, sn, &unnamed);

        const svcs = try b.servicesOf(jn.get("services"));
        const ctr = try b.containerOf(jn.get("container"));
        const dflt = try b.defaults(doc.get("defaults"), jn.get("defaults"));
        const token = contextString(t.context, "gitea_runtime_token");
        const id_text = try std.fmt.allocPrint(arena, "{d}", .{t.id});

        const j: job_mod.Job = .{
            .plan_id = id_text,
            .job_id = id_text,
            .job_token = token,
            .check_run_id = std.math.cast(u64, t.id) orelse 0,
            .display_name = if (jn.get("name")) |n| n.scalarText() orelse key else key,
            .container = ctr.value,
            .container_error = ctr.err,
            .services = svcs.value,
            .services_error = svcs.err,
            .outputs = try b.outputs(jn.get("outputs")),
            .environment = try b.environment(jn.get("environment")),
            .secrets = try secretValues(arena, t, token),
            .secret_vars = try secretVars(arena, t),
            .github = try githubOf(arena, t.context, key),
            .env = try b.jobEnv(doc.get("env"), jn.get("env")),
            .defaults_run = dflt.run,
            .defaults_error = dflt.err,
            .context_data = try b.contextData(t, jn),
            .steps = steps,
        };
        return .{
            .job = j,
            .runs_on = try labels(arena, jn.get("runs-on")),
            .condition = if (jn.get("if")) |c| c.scalarText() orelse "" else "",
            .timeout_minutes = if (jn.get("timeout-minutes")) |n| try b.optionalTemplate(n) else null,
            .continue_on_error = if (jn.get("continue-on-error")) |n|
                (try b.optionalTemplate(n)) orelse .{ .lit = "false" }
            else
                .{ .lit = "false" },
        };
    }

    // --- templates ---

    /// `text` as a literal or an expression (see the top of this file).
    fn template(b: *Builder, text: []const u8) BuildError!Template {
        return templateOf(b.arena, text) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unclosed => return b.bad("'${{{{' in '{s}' is never closed with '}}}}'", .{shorten(text)}),
            error.EmptyExpression => return b.bad("an empty expression '${{{{ }}}}' in '{s}'", .{shorten(text)}),
        };
    }

    /// A scalar as a template; null for a collection. A null is an empty string, as Go reads it.
    fn optionalTemplate(b: *Builder, n: Node) BuildError!?Template {
        if (n == .null) return .{ .lit = "" };
        const text = n.scalarText() orelse return null;
        return try b.template(text);
    }

    fn scalarTemplate(b: *Builder, n: Node, what: []const u8) BuildError!Template {
        return (try b.optionalTemplate(n)) orelse
            b.bad("{s} must be a string, a number, a boolean or an expression", .{what});
    }

    /// A mapping's entries as inputs, in order.
    fn mappingInputs(b: *Builder, n: Node, what: []const u8) BuildError![]const Input {
        if (n != .map) return b.bad("{s} must be a mapping", .{what});
        const out = try b.arena.alloc(Input, n.map.len);
        for (n.map, out) |e, *o| o.* = .{ .name = e.key, .value = try b.scalarTemplate(e.value, what) };
        return out;
    }

    fn sequenceTemplates(b: *Builder, n: Node, what: []const u8) BuildError![]const Template {
        if (n != .seq) return b.bad("{s} must be a list", .{what});
        const out = try b.arena.alloc(Template, n.seq.len);
        for (n.seq, out) |e, *o| o.* = try b.scalarTemplate(e, what);
        return out;
    }

    // --- the job's parts ---

    /// Workflow-level then job-level `env`; an unreadable block is an error here, where GitHub's
    /// message would have been refused by its own server.
    fn jobEnv(b: *Builder, workflow: ?Node, jn: ?Node) BuildError![]const Input {
        var out: std.ArrayList(Input) = .empty;
        for ([_]?Node{ workflow, jn }) |maybe| {
            const n = maybe orelse continue;
            if (n == .null) continue;
            try out.appendSlice(b.arena, try b.mappingInputs(n, "env"));
        }
        return out.items;
    }

    fn outputs(b: *Builder, maybe: ?Node) BuildError![]const Input {
        const n = maybe orelse return &.{};
        if (n != .map) return &.{}; // as job.parse: an unreadable mapping counts as none
        return b.mappingInputs(n, "outputs");
    }

    fn environment(b: *Builder, maybe: ?Node) BuildError!job_mod.Environment {
        const n = maybe orelse return .{};
        if (n.scalarText()) |name| return .{ .name = name };
        if (n != .map) return .{};
        return .{
            .name = if (n.get("name")) |v| v.scalarText() orelse "" else "",
            .url = if (n.get("url")) |u| try b.optionalTemplate(u) else null,
        };
    }

    const Defaults = struct { run: job_mod.RunDefaults = .{}, err: ?[]const u8 = null };

    /// `defaults.run`: the job's replaces the workflow's whole when it has one, as GitHub's runner
    /// reads the two (`job.jobDefaults`).
    fn defaults(b: *Builder, workflow: ?Node, jn: ?Node) BuildError!Defaults {
        const unreadable: Defaults = .{
            .err = "defaults: could not be read (written as an expression, or in a form the " ++
                "runner does not know)",
        };
        var out: Defaults = .{};
        for ([_]?Node{ workflow, jn }) |maybe| {
            const n = maybe orelse continue;
            if (n == .null) continue;
            if (n != .map) return unreadable;
            const run = n.get("run") orelse continue;
            if (run != .map) return unreadable;
            out.run = .{};
            for (run.map) |e| {
                const tpl = (b.optionalTemplate(e.value) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.Bad => return unreadable,
                }) orelse return unreadable;
                if (std.ascii.eqlIgnoreCase(e.key, "shell")) out.run.shell = tpl;
                if (std.ascii.eqlIgnoreCase(e.key, "working-directory")) out.run.working_directory = tpl;
            }
        }
        return out;
    }

    const Services = struct { value: []const job_mod.Service = &.{}, err: ?[]const u8 = null };
    const Container = struct { value: ?job_mod.Service = null, err: ?[]const u8 = null };

    fn servicesOf(b: *Builder, maybe: ?Node) Allocator.Error!Services {
        const n = maybe orelse return .{};
        if (n == .null) return .{};
        const unreadable: Services = .{
            .err = "services: could not be read (written as an expression, or in a form the " ++
                "runner does not know)",
        };
        if (n != .map) return unreadable;
        const out = try b.arena.alloc(job_mod.Service, n.map.len);
        for (n.map, out) |e, *o| o.* = b.service(e.key, e.value) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Bad => return unreadable,
        };
        return .{ .value = out };
    }

    fn containerOf(b: *Builder, maybe: ?Node) Allocator.Error!Container {
        const n = maybe orelse return .{};
        if (n == .null) return .{};
        const value = b.service("job", n) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Bad => return .{
                .err = "container: could not be read (written as an expression, or in a form the " ++
                    "runner does not know)",
            },
        };
        return .{ .value = value };
    }

    /// One service, or the job's container: a mapping, or just the image. A field `job.Service`
    /// has no place for (Gitea's `cmd`, say) is ignored, as `job.parse` ignores the same.
    fn service(b: *Builder, name: []const u8, n: Node) BuildError!job_mod.Service {
        if (n.scalarText() != null) return .{ .name = name, .image = try b.scalarTemplate(n, "image") };
        if (n != .map) return error.Bad;
        var svc: job_mod.Service = .{ .name = name, .image = .{ .lit = "" } };
        for (n.map) |e| {
            const k = e.key;
            if (std.mem.eql(u8, k, "image")) {
                svc.image = try b.scalarTemplate(e.value, "image");
            } else if (std.mem.eql(u8, k, "env")) {
                svc.env = try b.mappingInputs(e.value, "env");
            } else if (std.mem.eql(u8, k, "ports")) {
                svc.ports = try b.sequenceTemplates(e.value, "ports");
            } else if (std.mem.eql(u8, k, "volumes")) {
                svc.volumes = try b.sequenceTemplates(e.value, "volumes");
            } else if (std.mem.eql(u8, k, "options")) {
                svc.options = try b.scalarTemplate(e.value, "options");
            } else if (std.mem.eql(u8, k, "credentials")) {
                for (try b.mappingInputs(e.value, "credentials")) |c| {
                    if (std.mem.eql(u8, c.name, "username")) svc.username = c.value;
                    if (std.mem.eql(u8, c.name, "password")) svc.password = c.value;
                }
            }
        }
        return svc;
    }

    // --- steps ---

    fn step(b: *Builder, task_id: i64, number: usize, sn: Node, unnamed: *usize) BuildError!job_mod.Step {
        const arena = b.arena;
        if (sn != .map) return b.bad("step {d} is not a mapping", .{number});
        const id = try std.fmt.allocPrint(arena, "{d}-{d}", .{ task_id, number });
        const context_name = if (sn.get("id")) |n| (n.scalarText() orelse "") else "";

        // What GitHub's server names a step that has no `id:`: `__run`, `__run_2`, ...
        const named = if (context_name.len > 0) context_name else blk: {
            unnamed.* += 1;
            break :blk if (unnamed.* == 1) "__run" else try std.fmt.allocPrint(arena, "__run_{d}", .{unnamed.*});
        };

        var out: job_mod.Step = .{
            .id = id,
            .context_name = named,
            .name = "",
            .condition = "success()",
            .action = .{ .unsupported = "" },
        };
        // One broken part of a step fails that step, with the reason, as `job.parse` does.
        var script_text: []const u8 = "";
        var label: []const u8 = "";
        out.action = b.stepAction(sn, &script_text, &label) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Bad => .{ .unsupported = b.why },
        };
        const fields = b.stepFields(sn, &out) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Bad => blk: {
                out.action = .{ .unsupported = b.why };
                break :blk null;
            },
        };
        out.uses = label;
        var explicit: []const u8 = "";
        if (fields) |f| {
            out.name_expr = f.name_expr;
            explicit = f.name;
        }
        out.name = try job_mod.displayName(arena, explicit, script_text, label);
        return out;
    }

    const StepFields = struct { name: []const u8 = "", name_expr: ?[]const u8 = null };

    /// A step's `name`, `if`, `env`, `continue-on-error` and `timeout-minutes`, set in `out`.
    fn stepFields(b: *Builder, sn: Node, out: *job_mod.Step) BuildError!StepFields {
        var f: StepFields = .{};
        if (sn.get("name")) |n| if (n.scalarText()) |text| switch (try b.template(text)) {
            .lit => |l| f.name = l,
            .expr => |e| f.name_expr = e,
        };
        if (sn.get("if")) |n| if (n.scalarText()) |text| {
            out.condition = try b.conditionOf(text);
        };
        if (sn.get("env")) |n| if (n != .null) {
            out.env = try b.mappingInputs(n, "env");
        };
        if (sn.get("continue-on-error")) |n| out.continue_on_error = (try b.optionalTemplate(n)) orelse
            .{ .lit = "false" };
        if (sn.get("timeout-minutes")) |n| out.timeout_minutes = try b.optionalTemplate(n);
        return f;
    }

    /// A step's `if:` as the job message carries it: the expression, with `success() && ( )` around
    /// it when it calls no status function, as GitHub's server writes it. `${{ }}` around the whole
    /// of it is optional in a workflow.
    fn conditionOf(b: *Builder, text_in: []const u8) BuildError![]const u8 {
        var text = std.mem.trim(u8, text_in, " \t\r\n");
        if (std.mem.startsWith(u8, text, "${{")) if (expr.expressionEnd(text, 3)) |end| {
            if (end + 2 == text.len) text = std.mem.trim(u8, text[3..end], " \t\r\n");
        };
        if (text.len == 0) return "success()";
        if (try expr.hasStatusFunction(b.arena, text)) return text;
        return std.fmt.allocPrint(b.arena, "success() && ({s})", .{text});
    }

    fn stepAction(b: *Builder, sn: Node, script_text: *[]const u8, label: *[]const u8) BuildError!job_mod.Action {
        const run = sn.get("run");
        const uses = sn.get("uses");
        if (run != null and uses != null) return b.bad("a step has both run and uses", .{});
        if (run) |r| {
            const text = r.scalarText() orelse return b.bad("run must be a string", .{});
            const script = try b.template(text);
            // The name GitHub shows is made from the text as written, expressions and all; a job
            // message has only the rewritten one, where `job.parse` falls back to "Run step".
            script_text.* = text;
            const shell = if (sn.get("shell")) |n| try b.optionalTemplate(n) else null;
            const wd = if (sn.get("working-directory")) |n| try b.optionalTemplate(n) else null;
            // A literal shell is checked now, an expression when the step runs, as in job.parse.
            if (shell) |sh| if (sh == .lit and !job_mod.validShell(sh.lit))
                return .{ .unsupported = try job_mod.unsupportedShell(b.arena, sh.lit) };
            return .{ .script = .{ .script = script, .shell = shell, .working_directory = wd } };
        }
        const u = uses orelse return b.bad("a step has neither run nor uses", .{});
        const text = std.mem.trim(u8, u.scalarText() orelse return b.bad("uses must be a string", .{}), " ");
        label.* = text;
        return b.usesAction(text, sn.get("with"));
    }

    /// `uses:` as Gitea's model reads it (`Step.Type`, `ParseActionUses`).
    fn usesAction(b: *Builder, text: []const u8, with: ?Node) BuildError!job_mod.Action {
        const arena = b.arena;
        if (std.mem.indexOf(u8, text, "${{") != null) return .{ .unsupported = try std.fmt.allocPrint(
            arena,
            "uses: {s}: an action reference cannot be an expression",
            .{text},
        ) };
        const inputs = try b.withInputs(with);
        if (std.mem.startsWith(u8, text, "docker://")) {
            const image = text["docker://".len..];
            if (image.len == 0) return .{ .unsupported = "uses: docker:// names no image" };
            return .{ .docker = .{ .image = image, .inputs = inputs } };
        }
        if (std.mem.indexOf(u8, text, ".github/workflows/") != null and
            (std.mem.indexOf(u8, text, ".yml") != null or std.mem.indexOf(u8, text, ".yaml") != null))
            return .{ .unsupported = try std.fmt.allocPrint(
                arena,
                "uses: {s}: a reusable workflow is not an action a step can run",
                .{text},
            ) };
        if (std.mem.startsWith(u8, text, "./")) {
            const dir = job_mod.localActionPath(text) orelse return .{ .unsupported = try std.fmt.allocPrint(
                arena,
                "uses: {s}: a local action must be inside the workspace",
                .{text},
            ) };
            return .{ .uses = .{ .owner = "", .name = "", .path = dir, .ref = "", .inputs = inputs, .local = true } };
        }
        // Gitea's `$/path`, `self:owner/repo@ref` and `https://host/owner/repo@ref` name where the
        // action is fetched from, which `job.Uses` cannot say: that is G5.
        if (std.mem.startsWith(u8, text, "$/") or std.mem.startsWith(u8, text, "self:") or
            std.mem.indexOf(u8, text, "://") != null)
            return .{ .unsupported = try std.fmt.allocPrint(
                arena,
                "uses: {s}: actions named by a URL, self: or $/ are not supported yet (#520, G5)",
                .{text},
            ) };
        const invalid: job_mod.Action = .{ .unsupported = try std.fmt.allocPrint(
            arena,
            "uses: {s} is not a valid action reference",
            .{text},
        ) };
        const at = std.mem.indexOfScalar(u8, text, '@') orelse return invalid;
        const ref = text[at + 1 ..];
        var parts = std.mem.splitScalar(u8, text[0..at], '/');
        const owner = parts.next() orelse "";
        const repo = parts.next() orelse "";
        const dir = std.mem.trim(u8, parts.rest(), "/");
        if (owner.len == 0 or repo.len == 0 or ref.len == 0 or std.mem.indexOf(u8, dir, "..") != null)
            return invalid;
        if (dir.len == 0 and std.ascii.eqlIgnoreCase(text[0..at], "actions/checkout"))
            return .{ .checkout = inputs };
        return .{ .uses = .{ .owner = owner, .name = repo, .path = dir, .ref = ref, .inputs = inputs } };
    }

    /// A `uses:` step's `with:`; empty when it has none.
    fn withInputs(b: *Builder, with: ?Node) BuildError![]const Input {
        const n = with orelse return &.{};
        if (n == .null) return &.{};
        return b.mappingInputs(n, "with");
    }

    // --- contexts ---

    /// `contextData`: the contexts an expression reads, in GitHub's encoding (`context.zig`).
    fn contextData(b: *Builder, t: task_mod.Task, jn: Node) BuildError!Value {
        const arena = b.arena;
        var root = std.json.ObjectMap.empty;
        try root.put(arena, "github", try fromJson(arena, t.context));

        const strategy = jn.get("strategy");
        var matrix: Value = .null;
        if (strategy) |s| if (s.get("matrix")) |m| {
            matrix = try b.matrixContext(m);
        };
        try root.put(arena, "matrix", matrix);
        try root.put(arena, "strategy", try b.strategyContext(strategy));

        const needs = try arena.alloc(Entry, t.needs.len);
        for (t.needs, needs) |need, *out| {
            const outs = try arena.alloc(Entry, need.outputs.len);
            for (need.outputs, outs) |p, *e| e.* = .{ .key = p.name, .value = .{ .string = p.value } };
            out.* = .{ .key = need.job, .value = try dictOf(arena, &.{
                .{ .key = "outputs", .value = try dictOf(arena, outs) },
                .{ .key = "result", .value = .{ .string = resultName(need.result) } },
            }) };
        }
        try root.put(arena, "needs", try dictOf(arena, needs));

        const vars = try arena.alloc(Entry, t.vars.len);
        for (t.vars, vars) |p, *e| e.* = .{ .key = p.name, .value = .{ .string = p.value } };
        try root.put(arena, "vars", try dictOf(arena, vars));

        // The `inputs` context of a workflow_dispatch run is the event's inputs.
        if (t.context == .object) if (t.context.object.get("event")) |ev| if (ev == .object) {
            if (ev.object.get("inputs")) |inputs| if (inputs == .object)
                try root.put(arena, "inputs", try fromJson(arena, inputs));
        };
        try root.put(arena, "job", try dictOf(arena, &.{.{ .key = "status", .value = .{ .string = "success" } }}));
        return .{ .object = root };
    }

    /// `strategy.matrix` cut to this job: each key holds the one value the job has, which is the
    /// context's value (Gitea writes `n: [1]` where the `matrix` context has `n: 1`). A key with
    /// several values, or an `include` with entries, is a matrix the instance did not expand.
    fn matrixContext(b: *Builder, m: Node) BuildError!Value {
        if (m != .map) return b.bad("strategy.matrix is not a mapping", .{});
        const entries = try b.arena.alloc(Entry, m.map.len);
        var n: usize = 0;
        for (m.map) |e| {
            if (std.mem.eql(u8, e.key, "include") or std.mem.eql(u8, e.key, "exclude")) {
                if (e.value == .seq and e.value.seq.len == 0) continue;
                if (e.value == .null) continue;
                return b.bad("strategy.matrix.{s} is set: the instance sends each combination as its own task", .{e.key});
            }
            const value: Node = switch (e.value) {
                .seq => |items| switch (items.len) {
                    1 => items[0],
                    else => return b.bad("strategy.matrix.{s} has {d} values: the instance sends each combination as its own task", .{ e.key, items.len }),
                },
                else => e.value,
            };
            entries[n] = .{ .key = e.key, .value = try fromYaml(b.arena, value) };
            n += 1;
        }
        return dictOf(b.arena, entries[0..n]);
    }

    /// `strategy`: GitHub's keys. Gitea writes `job-total` (and, from some versions, `job-index`)
    /// beside `matrix` in the job's `strategy:`.
    fn strategyContext(b: *Builder, maybe: ?Node) BuildError!Value {
        const s = maybe orelse return .null;
        if (s != .map) return .null;
        var list: std.ArrayList(Entry) = .empty;
        const fail_fast: Value = if (s.get("fail-fast")) |f| (if (f.scalarText()) |text|
            .{ .bool = !std.ascii.eqlIgnoreCase(text, "false") }
        else
            .{ .bool = true }) else .{ .bool = true };
        try list.append(b.arena, .{ .key = "fail-fast", .value = fail_fast });
        for ([_][]const u8{ "job-index", "job-total", "max-parallel" }) |k| {
            if (s.get(k)) |n| try list.append(b.arena, .{ .key = k, .value = try fromYaml(b.arena, n) });
        }
        return dictOf(b.arena, list.items);
    }
};

// --- text into templates ---

const TemplateError = error{ Unclosed, EmptyExpression, OutOfMemory };

/// `text` as GitHub's `TemplateReader` reads a string: a literal when it holds no `${{`; the
/// expression itself when it is one `${{ }}` and nothing else; otherwise `format('<text>', e0, e1)`
/// with the text between the expressions, its quotes and braces doubled, as the format string.
pub fn templateOf(arena: Allocator, text: []const u8) TemplateError!Template {
    if (std.mem.indexOf(u8, text, "${{") == null) return .{ .lit = text };
    const Segment = struct { before: []const u8, body: []const u8 };
    var segments: std.ArrayList(Segment) = .empty;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, text, i, "${{")) |open| {
        const close = expr.expressionEnd(text, open + 3) orelse return error.Unclosed;
        const body = std.mem.trim(u8, text[open + 3 .. close], " \t\r\n");
        if (body.len == 0) return error.EmptyExpression;
        try segments.append(arena, .{ .before = text[i..open], .body = body });
        i = close + 2;
    }
    const after = text[i..];
    if (segments.items.len == 1 and segments.items[0].before.len == 0 and after.len == 0)
        return .{ .expr = segments.items[0].body };

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "format('");
    for (segments.items, 0..) |seg, n| {
        try escapeFormat(arena, &out, seg.before);
        try out.print(arena, "{{{d}}}", .{n});
    }
    try escapeFormat(arena, &out, after);
    try out.append(arena, '\'');
    for (segments.items) |seg| {
        try out.appendSlice(arena, ", ");
        try out.appendSlice(arena, seg.body);
    }
    try out.append(arena, ')');
    return .{ .expr = out.items };
}

fn escapeFormat(arena: Allocator, out: *std.ArrayList(u8), text: []const u8) Allocator.Error!void {
    for (text) |c| switch (c) {
        '\'' => try out.appendSlice(arena, "''"),
        '{' => try out.appendSlice(arena, "{{"),
        '}' => try out.appendSlice(arena, "}}"),
        else => try out.append(arena, c),
    };
}

/// The start of `text`, for a message.
fn shorten(text: []const u8) []const u8 {
    return text[0..@min(text.len, 60)];
}

// --- the task's own data ---

fn contextString(context: Value, key: []const u8) []const u8 {
    if (context != .object) return "";
    const v = context.object.get(key) orelse return "";
    return if (v == .string) v.string else "";
}

fn githubOf(arena: Allocator, context: Value, job_key: []const u8) Allocator.Error!job_mod.Github {
    var g: job_mod.Github = .{};
    g.repository = contextString(context, "repository");
    g.sha = contextString(context, "sha");
    g.ref = contextString(context, "ref");
    g.workflow = contextString(context, "workflow");
    g.event_name = contextString(context, "event_name");
    g.ref_name = contextString(context, "ref_name");
    g.workflow_ref = contextString(context, "workflow_ref");
    const server = contextString(context, "server_url");
    if (server.len > 0) g.server_url = server;
    g.job = contextString(context, "job");
    if (g.job.len == 0) g.job = job_key;
    if (context == .object) if (context.object.get("run_id")) |v| switch (v) {
        .string => |s| g.run_id = s,
        .integer => |n| g.run_id = try std.fmt.allocPrint(arena, "{d}", .{n}),
        else => {},
    };
    return g;
}

/// Every value that must stay out of the logs: the secrets, the runtime token, and the context's
/// own tokens (`token`, `gitea_runtime_token`, and any other key that names one).
fn secretValues(arena: Allocator, t: task_mod.Task, runtime_token: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (runtime_token.len > 0) try out.append(arena, runtime_token);
    for (t.secrets) |s| if (s.value.len > 0) try out.append(arena, s.value);
    if (t.context == .object) {
        var it = t.context.object.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* != .string or e.value_ptr.string.len == 0) continue;
            if (std.ascii.findIgnoreCase(e.key_ptr.*, "token") == null) continue;
            if (!contains(out.items, e.value_ptr.string)) try out.append(arena, e.value_ptr.string);
        }
    }
    return out.items;
}

fn contains(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

/// The `secrets` context. `GITHUB_TOKEN` is among them: Gitea sends it with the others.
fn secretVars(arena: Allocator, t: task_mod.Task) Allocator.Error![]const job_mod.EnvVar {
    const out = try arena.alloc(job_mod.EnvVar, t.secrets.len);
    for (t.secrets, out) |s, *o| o.* = .{ .name = s.name, .value = s.value };
    return out;
}

/// What a job's `needs` result is called in the `needs` context: `success`, `failure`...
fn resultName(result: []const u8) []const u8 {
    const prefix = "RESULT_";
    if (!std.mem.startsWith(u8, result, prefix)) return result;
    const rest = result[prefix.len..];
    const table = [_][2][]const u8{
        .{ "SUCCESS", "success" },
        .{ "FAILURE", "failure" },
        .{ "CANCELLED", "cancelled" },
        .{ "SKIPPED", "skipped" },
    };
    for (table) |row| if (std.mem.eql(u8, rest, row[0])) return row[1];
    return result;
}

fn labels(arena: Allocator, runs_on: ?Node) Allocator.Error![]const []const u8 {
    const n = runs_on orelse return &.{};
    if (n.scalarText()) |one| {
        const out = try arena.alloc([]const u8, 1);
        out[0] = one;
        return out;
    }
    if (n == .seq) {
        var out: std.ArrayList([]const u8) = .empty;
        for (n.seq) |l| if (l.scalarText()) |text| try out.append(arena, text);
        return out.items;
    }
    // `runs-on: {group: g, labels: [a, b]}`.
    if (n.get("labels")) |l| return labels(arena, l);
    return &.{};
}

// --- contexts as GitHub encodes them ---

const Entry = struct { key: []const u8, value: Value };

/// `{"t":2,"d":[{"k":..,"v":..}]}`.
fn dictOf(arena: Allocator, entries: []const Entry) Allocator.Error!Value {
    var d = std.json.Array.init(arena);
    for (entries) |e| {
        var item = std.json.ObjectMap.empty;
        try item.put(arena, "k", .{ .string = e.key });
        try item.put(arena, "v", e.value);
        try d.append(.{ .object = item });
    }
    var o = std.json.ObjectMap.empty;
    try o.put(arena, "t", .{ .integer = 2 });
    try o.put(arena, "d", .{ .array = d });
    return .{ .object = o };
}

/// A JSON value (the task's context) as a context: objects as dictionaries, arrays as `{"t":1,"a"}`.
fn fromJson(arena: Allocator, v: Value) Allocator.Error!Value {
    switch (v) {
        .object => |o| {
            const entries = try arena.alloc(Entry, o.count());
            for (o.keys(), o.values(), entries) |k, val, *e| e.* = .{ .key = k, .value = try fromJson(arena, val) };
            return dictOf(arena, entries);
        },
        .array => |a| {
            var items = std.json.Array.init(arena);
            for (a.items) |x| try items.append(try fromJson(arena, x));
            return arrayOf(arena, items);
        },
        else => return v,
    }
}

/// A YAML node, typed (`parseTyped`), as a context.
fn fromYaml(arena: Allocator, n: Node) Allocator.Error!Value {
    switch (n) {
        .null => return .null,
        .string => |s| return .{ .string = s },
        .boolean => |b| return .{ .bool = b },
        .number => |s| {
            if (std.fmt.parseInt(i64, s, 10)) |i| return .{ .integer = i } else |_| {}
            if (std.fmt.parseFloat(f64, s)) |f| return .{ .float = f } else |_| {}
            return .{ .string = s };
        },
        .seq => |items| {
            var out = std.json.Array.init(arena);
            for (items) |x| try out.append(try fromYaml(arena, x));
            return arrayOf(arena, out);
        },
        .map => |entries| {
            const list = try arena.alloc(Entry, entries.len);
            for (entries, list) |e, *o| o.* = .{ .key = e.key, .value = try fromYaml(arena, e.value) };
            return dictOf(arena, list);
        },
    }
}

fn arrayOf(arena: Allocator, items: std.json.Array) Allocator.Error!Value {
    var o = std.json.ObjectMap.empty;
    try o.put(arena, "t", .{ .integer = 1 });
    try o.put(arena, "a", .{ .array = items });
    return .{ .object = o };
}

// --- tests ---

const testing = std.testing;
const context_mod = @import("../context.zig");

fn fixtureTask(arena: Allocator, json: []const u8) !task_mod.Task {
    const Answer = struct { task: ?task_mod.Wire = null };
    const answer = try std.json.parseFromSliceLeaky(Answer, arena, json, .{ .ignore_unknown_fields = true });
    return task_mod.fromWire(arena, answer.task.?);
}

/// A task of one job, made from workflow text and a context as JSON.
fn textTask(arena: Allocator, workflow: []const u8, context_json: []const u8) !task_mod.Task {
    return .{
        .id = 7,
        .workflow = workflow,
        .context = try std.json.parseFromSliceLeaky(Value, arena, context_json, .{}),
        .secrets = &.{},
        .vars = &.{},
        .needs = &.{},
    };
}

fn convertText(arena: Allocator, body: []const u8) !Converted {
    const text = try std.fmt.allocPrint(arena, "name: t\njobs:\n  j:\n    runs-on: x\n{s}", .{body});
    var why: []const u8 = "";
    return fromTask(arena, try textTask(arena, text, "{}"), &why);
}

/// The context `name` of `c`'s job, as an expression value.
fn contextOf(arena: Allocator, c: Converted, name: []const u8) !expr.Value {
    return context_mod.named(arena, c.job.context_data, name);
}

test "Gitea's fixture becomes the job GitHub's message would" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const t = try fixtureTask(arena, @embedFile("testdata/fetch-task.json"));
    var why: []const u8 = "";
    const c = try fromTask(arena, t, &why);
    const j = c.job;

    try testing.expectEqualStrings("1", j.plan_id);
    try testing.expectEqualStrings("1", j.job_id);
    try testing.expectEqual(@as(u64, 1), j.check_run_id);
    try testing.expectEqualStrings("hello (1)", j.display_name);
    try testing.expectEqualStrings("ubuntu-latest", c.runs_on[0]);
    try testing.expectEqualStrings("always()", c.condition);
    try testing.expectEqual(@as(usize, 3), j.steps.len);

    try testing.expect(j.steps[0].action == .checkout);
    try testing.expectEqualStrings("Run actions/checkout@v4", j.steps[0].name);
    try testing.expectEqualStrings("actions/checkout@v4", j.steps[0].uses);
    try testing.expectEqualStrings("success()", j.steps[0].condition);
    try testing.expectEqualStrings("Say", j.steps[1].name);
    try testing.expectEqualStrings(
        "format('echo \"$GREETING {0} {1} {2}\"', matrix.n, github.repository, secrets.TOKEN_X)",
        j.steps[1].action.script.script.expr,
    );
    try testing.expectEqualStrings("out", j.steps[2].context_name);
    try testing.expectEqualStrings("echo \"v=1\" >> \"$GITHUB_OUTPUT\"", j.steps[2].action.script.script.lit);
    try testing.expectEqualStrings("Run echo \"v=1\" >> \"$GITHUB_OUTPUT\"", j.steps[2].name);

    try testing.expectEqual(@as(usize, 1), j.env.len);
    try testing.expectEqualStrings("GREETING", j.env[0].name);
    try testing.expectEqualStrings("hi", j.env[0].value.lit);
    try testing.expectEqualStrings("v", j.outputs[0].name);
    try testing.expectEqualStrings("steps.out.outputs.v", j.outputs[0].value.expr);

    try testing.expectEqualStrings("zradmin/probe", j.github.repository);
    try testing.expectEqualStrings("refs/heads/main", j.github.ref);
    try testing.expectEqualStrings("push", j.github.event_name);
    try testing.expectEqualStrings("hello", j.github.job);
    try testing.expectEqualStrings("1", j.github.run_id);
    try testing.expectEqualStrings("http://127.0.0.1:3300/", j.github.server_url);
    // Left for G5.
    try testing.expectEqualStrings("", j.runtime.pipelines_url);
    try testing.expectEqualStrings("", j.results_endpoint);
    try testing.expectEqualStrings("", j.container_error orelse "");

    // The contexts an expression reads.
    const matrix = try contextOf(arena, c, "matrix");
    try testing.expectEqual(@as(f64, 1), matrix.object[0].value.number);
    const strategy = try contextOf(arena, c, "strategy");
    var found_total = false;
    for (strategy.object) |e| if (std.mem.eql(u8, e.key, "job-total")) {
        found_total = true;
        try testing.expectEqual(@as(f64, 2), e.value.number);
    };
    try testing.expect(found_total);
    const gh = try contextOf(arena, c, "github");
    try testing.expect(gh.object.len > 10);
}

test "every token the task carries is kept out of logs" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var t = try textTask(arena, "jobs:\n  j:\n    steps:\n      - run: echo\n", "{\"token\":\"ctx-token-1\",\"gitea_runtime_token\":\"rt-token-2\",\"repository\":\"o/r\"}");
    t.secrets = &.{ .{ .name = "GITHUB_TOKEN", .value = "sec-3" }, .{ .name = "EMPTY", .value = "" } };
    var why: []const u8 = "";
    const j = (try fromTask(arena, t, &why)).job;
    try testing.expect(contains(j.secrets, "ctx-token-1"));
    try testing.expect(contains(j.secrets, "rt-token-2"));
    try testing.expect(contains(j.secrets, "sec-3"));
    try testing.expect(!contains(j.secrets, "o/r"));
    try testing.expect(!contains(j.secrets, ""));
    try testing.expectEqualStrings("rt-token-2", j.job_token);
    try testing.expectEqual(@as(usize, 2), j.secret_vars.len);
    try testing.expectEqualStrings("GITHUB_TOKEN", j.secret_vars[0].name);
    // The secrets are not in the context data an expression dump or a log might show.
    var buf: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(j.context_data, .{}, &buf.writer);
    try testing.expect(std.mem.indexOf(u8, buf.written(), "sec-3") == null);
}

test "Forgejo's fixture is read the same" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const t = try fixtureTask(arena, @embedFile("testdata/fetch-task-forgejo.json"));
    var why: []const u8 = "";
    const c = try fromTask(arena, t, &why);
    try testing.expectEqual(@as(usize, 3), c.job.steps.len);
    try testing.expectEqualStrings("", c.condition);
    try testing.expectEqualStrings("hello (1)", c.job.display_name);
    try testing.expectEqualStrings(
        "format('echo \"{0} {1}\"', matrix.n, github.repository)",
        c.job.steps[1].action.script.script.expr,
    );
    try testing.expectEqualStrings("http://127.0.0.1:3400/", c.job.github.server_url);
    try testing.expect(c.job.steps[2].action.script.script == .lit);
    // The summary file command is an ordinary script for the backends.
    try testing.expect(std.mem.indexOf(u8, c.job.steps[2].action.script.script.lit, "GITHUB_STEP_SUMMARY") != null);
}

test "text becomes a literal, one expression, or a format() as GitHub's reader makes it" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    try testing.expectEqualStrings("echo hi", (try templateOf(arena, "echo hi")).lit);
    try testing.expectEqualStrings("github.sha", (try templateOf(arena, "${{ github.sha }}")).expr);
    try testing.expectEqualStrings("github.sha", (try templateOf(arena, "${{github.sha}}")).expr);
    try testing.expectEqualStrings("format('v{0}', github.sha)", (try templateOf(arena, "v${{ github.sha }}")).expr);
    try testing.expectEqualStrings("format('{0} ', github.sha)", (try templateOf(arena, "${{ github.sha }} ")).expr);
    try testing.expectEqualStrings(
        "format('it''s {{x}} {0}-{1}', a, b)",
        (try templateOf(arena, "it's {x} ${{ a }}-${{ b }}")).expr,
    );
    // A `}}` inside a quoted string does not end the expression.
    try testing.expectEqualStrings("format('{0}!', format('{{0}}', 1))", (try templateOf(arena, "${{ format('{{0}}', 1) }}!")).expr);
    try testing.expectError(error.Unclosed, templateOf(arena, "echo ${{ github.sha"));
    try testing.expectError(error.EmptyExpression, templateOf(arena, "echo ${{ }}"));
}

test "a template evaluates to what interpolating its text gives" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const ctxs = [_]expr.Value.Entry{.{ .key = "github", .value = .{ .object = &.{
        .{ .key = "sha", .value = .{ .string = "abc" } },
        .{ .key = "n", .value = .{ .string = "it's {x}" } },
    } } }};
    const scope: expr.Scope = .{ .contexts = &ctxs };
    for ([_][]const u8{
        "plain",
        "${{ github.sha }}",
        "a ${{ github.sha }} b ${{ github.n }} c",
        "{braces} 'quotes' ${{ github.n }} {{0}} }",
        "${{ github.sha }}\n",
    }) |text| {
        const tpl = try templateOf(arena, text);
        const want = try expr.interpolate(arena, text, scope);
        const got = switch (tpl) {
            .lit => |l| l,
            .expr => |e| try expr.evalString(arena, e, scope),
        };
        try testing.expectEqualStrings(want, got);
    }
}

test "run steps: shell, working directory, step fields and the names GitHub gives" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const c = try convertText(arena,
        \\    steps:
        \\      - run: make
        \\        shell: bash
        \\        working-directory: sub
        \\        if: github.ref == 'x'
        \\        continue-on-error: true
        \\        timeout-minutes: 5
        \\        env:
        \\          A: 1
        \\          B: ${{ github.sha }}
        \\      - name: Build ${{ github.ref_name }}
        \\        run: |
        \\          echo one
        \\          echo two
        \\        if: ${{ failure() }}
        \\      - run: x
        \\        shell: pwsh
        \\      - run: y
        \\        shell: node {0}
        \\        continue-on-error: ${{ matrix.exp }}
        \\        timeout-minutes: ${{ inputs.limit }}
    );
    const s = c.job.steps;
    try testing.expectEqualStrings("__run", s[0].context_name);
    try testing.expectEqualStrings("__run_2", s[1].context_name);
    try testing.expectEqualStrings("7-1", s[0].id);
    try testing.expectEqualStrings("Run make", s[0].name);
    try testing.expectEqualStrings("bash", s[0].action.script.shell.?.lit);
    try testing.expectEqualStrings("sub", s[0].action.script.working_directory.?.lit);
    try testing.expectEqualStrings("success() && (github.ref == 'x')", s[0].condition);
    try testing.expectEqualStrings("true", s[0].continue_on_error.lit);
    try testing.expectEqualStrings("5", s[0].timeout_minutes.?.lit);
    try testing.expectEqualStrings("1", s[0].env[0].value.lit);
    try testing.expectEqualStrings("github.sha", s[0].env[1].value.expr);

    try testing.expectEqualStrings("format('Build {0}', github.ref_name)", s[1].name_expr.?);
    try testing.expectEqualStrings("Run echo one", s[1].name);
    try testing.expectEqualStrings("echo one\necho two\n", s[1].action.script.script.lit);
    try testing.expectEqualStrings("failure()", s[1].condition);

    try testing.expect(s[2].action == .unsupported);
    try testing.expect(std.mem.indexOf(u8, s[2].action.unsupported, "PowerShell") != null);
    try testing.expectEqualStrings("node {0}", s[3].action.script.shell.?.lit);
    try testing.expectEqualStrings("matrix.exp", s[3].continue_on_error.expr);
    try testing.expectEqualStrings("inputs.limit", s[3].timeout_minutes.?.expr);
}

test "uses steps: docker, local, remote with a directory, checkout, and what is not supported yet" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const c = try convertText(arena,
        \\    steps:
        \\      - uses: docker://alpine:3.22
        \\        with:
        \\          entrypoint: /bin/sh
        \\          args: -c "echo hi"
        \\      - uses: ./.gitea/actions/mine
        \\        with:
        \\          a: ${{ github.sha }}
        \\      - uses: ./
        \\      - uses: owner/repo/sub/dir@v1.2
        \\        with:
        \\          n: 3
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          fetch-depth: 0
        \\          submodules: true
        \\      - uses: https://github.com/actions/cache@v4
        \\      - uses: ./.github/workflows/x.yml
        \\      - uses: nonsense
        \\      - uses: ./../out
        \\      - uses: o/r@v1
        \\        run: echo
        \\      - name: nothing
        \\      - uses: o/r@v1
        \\        env: [a]
        \\      - uses: actions/checkout/sub@v4
    );
    const s = c.job.steps;
    try testing.expectEqualStrings("alpine:3.22", s[0].action.docker.image);
    try testing.expectEqualStrings("entrypoint", s[0].action.docker.inputs[0].name);
    try testing.expectEqualStrings("-c \"echo hi\"", s[0].action.docker.inputs[1].value.lit);
    try testing.expectEqualStrings("docker://alpine:3.22", s[0].uses);
    try testing.expectEqualStrings("Run docker://alpine:3.22", s[0].name);

    try testing.expect(s[1].action.uses.local);
    try testing.expectEqualStrings(".gitea/actions/mine", s[1].action.uses.path);
    try testing.expectEqualStrings("github.sha", s[1].action.uses.inputs[0].value.expr);
    try testing.expectEqualStrings("", s[2].action.uses.path);

    try testing.expectEqualStrings("owner", s[3].action.uses.owner);
    try testing.expectEqualStrings("repo", s[3].action.uses.name);
    try testing.expectEqualStrings("sub/dir", s[3].action.uses.path);
    try testing.expectEqualStrings("v1.2", s[3].action.uses.ref);
    try testing.expectEqualStrings("3", s[3].action.uses.inputs[0].value.lit);
    try testing.expectEqualStrings("owner/repo/sub/dir@v1.2", s[3].uses);

    try testing.expectEqual(@as(usize, 2), s[4].action.checkout.len);
    try testing.expectEqualStrings("true", s[4].action.checkout[1].value.lit);

    for ([_]usize{ 5, 6, 7, 8, 9, 10, 11 }) |i| try testing.expect(s[i].action == .unsupported);
    try testing.expect(std.mem.indexOf(u8, s[5].action.unsupported, "G5") != null);
    try testing.expect(std.mem.indexOf(u8, s[6].action.unsupported, "reusable workflow") != null);
    try testing.expect(std.mem.indexOf(u8, s[7].action.unsupported, "not a valid action") != null);
    try testing.expect(std.mem.indexOf(u8, s[8].action.unsupported, "inside the workspace") != null);
    try testing.expect(std.mem.indexOf(u8, s[9].action.unsupported, "both run and uses") != null);
    try testing.expect(std.mem.indexOf(u8, s[10].action.unsupported, "neither run nor uses") != null);
    try testing.expect(std.mem.indexOf(u8, s[11].action.unsupported, "mapping") != null);
    // `actions/checkout` with a directory is an action of that repository, not the checkout.
    try testing.expect(s[12].action == .uses);
    try testing.expectEqualStrings("sub", s[12].action.uses.path);
}

test "a step with an expression that never closes fails that step, not the job" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const c = try convertText(arena,
        \\    steps:
        \\      - run: echo ${{ github.sha
        \\      - run: ok
    );
    try testing.expect(c.job.steps[0].action == .unsupported);
    try testing.expect(std.mem.indexOf(u8, c.job.steps[0].action.unsupported, "never closed") != null);
    try testing.expect(c.job.steps[1].action == .script);
}

test "container, services, defaults, env, outputs, environment and the job's own settings" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";
    var t = try textTask(arena,
        \\name: t
        \\env:
        \\  W: w
        \\  SHARED: workflow
        \\defaults:
        \\  run:
        \\    shell: sh
        \\    working-directory: wd
        \\jobs:
        \\  build:
        \\    name: Build ${{ matrix.os }}
        \\    runs-on: [self-hosted, linux]
        \\    if: github.ref == 'refs/heads/main'
        \\    timeout-minutes: 15
        \\    continue-on-error: true
        \\    environment:
        \\      name: prod
        \\      url: https://x/${{ github.sha }}
        \\    env:
        \\      SHARED: job
        \\    defaults:
        \\      run:
        \\        shell: bash
        \\    container:
        \\      image: node:22
        \\      env:
        \\        A: b
        \\      options: --user 1
        \\      credentials:
        \\        username: u
        \\        password: ${{ secrets.P }}
        \\    services:
        \\      redis:
        \\        image: redis:7
        \\        ports:
        \\          - 6379:6379
        \\        volumes:
        \\          - /a:/b
        \\      pg: postgres:16
        \\    outputs:
        \\      v: ${{ steps.a.outputs.v }}
        \\    steps:
        \\      - run: x
    , "{}");
    const c = try fromTask(arena, t, &why);
    const j = c.job;
    // A job's display name is its text as written: GitHub evaluates it before it sends it, and so
    // does the instance, which has put the matrix's values in.
    try testing.expectEqualStrings("Build ${{ matrix.os }}", j.display_name);
    try testing.expectEqualStrings("self-hosted", c.runs_on[0]);
    try testing.expectEqualStrings("linux", c.runs_on[1]);
    try testing.expectEqualStrings("github.ref == 'refs/heads/main'", c.condition);
    try testing.expectEqualStrings("15", c.timeout_minutes.?.lit);
    try testing.expectEqualStrings("true", c.continue_on_error.lit);
    try testing.expectEqualStrings("prod", j.environment.name);
    try testing.expectEqualStrings("format('https://x/{0}', github.sha)", j.environment.url.?.expr);
    // Workflow env first, the job's after: the later one wins.
    try testing.expectEqual(@as(usize, 3), j.env.len);
    try testing.expectEqualStrings("SHARED", j.env[2].name);
    try testing.expectEqualStrings("job", j.env[2].value.lit);
    // The job's defaults.run replaces the workflow's whole.
    try testing.expectEqualStrings("bash", j.defaults_run.shell.?.lit);
    try testing.expect(j.defaults_run.working_directory == null);
    try testing.expect(j.defaults_error == null);
    const ctr = j.container.?;
    try testing.expectEqualStrings("job", ctr.name);
    try testing.expectEqualStrings("node:22", ctr.image.lit);
    try testing.expectEqualStrings("b", ctr.env[0].value.lit);
    try testing.expectEqualStrings("--user 1", ctr.options.?.lit);
    try testing.expectEqualStrings("u", ctr.username.?.lit);
    try testing.expectEqualStrings("secrets.P", ctr.password.?.expr);
    try testing.expectEqual(@as(usize, 2), j.services.len);
    try testing.expectEqualStrings("redis", j.services[0].name);
    try testing.expectEqualStrings("6379:6379", j.services[0].ports[0].lit);
    try testing.expectEqualStrings("/a:/b", j.services[0].volumes[0].lit);
    try testing.expectEqualStrings("postgres:16", j.services[1].image.lit);
    try testing.expectEqualStrings("steps.a.outputs.v", j.outputs[0].value.expr);

    // A container, services and defaults the runner cannot read are reported, and the job still converts.
    t.workflow =
        \\jobs:
        \\  j:
        \\    container: ${{ fromJSON(x) }}
        \\    services: ${{ fromJSON(y) }}
        \\    defaults: [a]
        \\    steps:
        \\      - run: x
    ;
    // A whole-expression container is a template of its image, as in a job message.
    const d = (try fromTask(arena, t, &why)).job;
    try testing.expectEqualStrings("fromJSON(x)", d.container.?.image.expr);
    try testing.expect(d.services_error != null);
    try testing.expect(d.defaults_error != null);
    t.workflow =
        \\jobs:
        \\  j:
        \\    container: [a]
        \\    steps:
        \\      - run: x
    ;
    const e = (try fromTask(arena, t, &why)).job;
    try testing.expect(e.container == null);
    try testing.expect(e.container_error != null);
}

test "the matrix, strategy, needs, vars and inputs contexts" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";
    var t = try textTask(arena,
        \\jobs:
        \\  j:
        \\    strategy:
        \\      matrix:
        \\        os:
        \\          - ubuntu
        \\        py:
        \\          - '3.10'
        \\        exp:
        \\          - false
        \\        n:
        \\          - 4
        \\        f:
        \\          - 2.5
        \\        obj:
        \\          - a: 1
        \\        include: []
        \\      fail-fast: false
        \\      job-index: 1
        \\      job-total: 3
        \\    steps:
        \\      - run: x
    , "{\"event\":{\"inputs\":{\"label\":\"e2e\"}},\"event_name\":\"workflow_dispatch\"}");
    t.vars = &.{.{ .name = "REGION", .value = "mars" }};
    t.needs = &.{.{ .job = "build", .result = "RESULT_SUCCESS", .outputs = &.{.{ .name = "v", .value = "9" }} }};
    const c = try fromTask(arena, t, &why);
    const m = try contextOf(arena, c, "matrix");
    try testing.expectEqualStrings("ubuntu", m.object[0].value.string);
    // A quoted number stays a string; a plain one is a number; a plain false is a boolean.
    try testing.expectEqualStrings("3.10", m.object[1].value.string);
    try testing.expectEqual(false, m.object[2].value.boolean);
    try testing.expectEqual(@as(f64, 4), m.object[3].value.number);
    try testing.expectEqual(@as(f64, 2.5), m.object[4].value.number);
    try testing.expectEqual(@as(f64, 1), m.object[5].value.object[0].value.number);
    try testing.expectEqual(@as(usize, 6), m.object.len);

    const s = try contextOf(arena, c, "strategy");
    try testing.expectEqual(false, s.object[0].value.boolean);
    try testing.expectEqualStrings("job-index", s.object[1].key);
    try testing.expectEqual(@as(f64, 3), s.object[2].value.number);

    const needs = try contextOf(arena, c, "needs");
    try testing.expectEqualStrings("build", needs.object[0].key);
    const build = needs.object[0].value;
    try testing.expectEqualStrings("9", build.object[0].value.object[0].value.string);
    try testing.expectEqualStrings("success", build.object[1].value.string);
    const vars = try contextOf(arena, c, "vars");
    try testing.expectEqualStrings("mars", vars.object[0].value.string);
    const inputs = try contextOf(arena, c, "inputs");
    try testing.expectEqualStrings("e2e", inputs.object[0].value.string);
    // And they evaluate the way a template reads them.
    const scope: expr.Scope = .{ .contexts = &.{
        .{ .key = "matrix", .value = m },
        .{ .key = "needs", .value = needs },
    } };
    try testing.expectEqualStrings("ubuntu-3.10-9", try expr.interpolate(arena, "${{ matrix.os }}-${{ matrix.py }}-${{ needs.build.outputs.v }}", scope));
    try testing.expect(!(try expr.evalCondition(arena, "matrix.exp", scope)));

    // A matrix the instance did not expand is refused, with the reason.
    t.workflow =
        \\jobs:
        \\  j:
        \\    strategy:
        \\      matrix:
        \\        os: [a, b]
        \\    steps:
        \\      - run: x
    ;
    try testing.expectError(error.BadWorkflow, fromTask(arena, t, &why));
    try testing.expect(std.mem.indexOf(u8, why, "os has 2 values") != null);
}

test "what is not a task is refused with a reason" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";
    const cases = [_]struct { yaml: []const u8, reason: []const u8 }{
        .{ .yaml = "jobs: [", .reason = "not read" },
        .{ .yaml = "name: x\n", .reason = "no jobs" },
        .{ .yaml = "jobs:\n  a:\n    steps: []\n  b:\n    steps: []\n", .reason = "has 2" },
        .{ .yaml = "jobs:\n  a:\n    runs-on: x\n", .reason = "no steps" },
        .{ .yaml = "jobs:\n  a:\n    steps: x\n", .reason = "not a list" },
        .{ .yaml = "jobs:\n  a:\n    steps:\n      - x\n", .reason = "step 1 is not a mapping" },
        .{ .yaml = "jobs:\n  a:\n    env: x\n    steps: []\n", .reason = "env must be a mapping" },
        .{ .yaml = "jobs:\n  a:\n    env:\n      A: ${{ x\n    steps: []\n", .reason = "never closed" },
        .{ .yaml = "jobs:\n  a:\n    env:\n      A: [1]\n    steps: []\n", .reason = "env must be" },
    };
    for (cases) |case| {
        try testing.expectError(error.BadWorkflow, fromTask(arena, try textTask(arena, case.yaml, "{}"), &why));
        try testing.expect(std.mem.indexOf(u8, why, case.reason) != null);
    }
}

test "a task with no context still converts" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";
    var t = try textTask(arena, "jobs:\n  only:\n    steps:\n      - run: x\n", "{}");
    t.context = .null;
    const c = try fromTask(arena, t, &why);
    try testing.expectEqualStrings("only", c.job.display_name);
    try testing.expectEqualStrings("only", c.job.github.job);
    try testing.expectEqualStrings("https://github.com", c.job.github.server_url);
    try testing.expectEqualStrings("", c.job.job_token);
    try testing.expect((try contextOf(arena, c, "matrix")) == .null);
}

test "allocation failures: a task is converted or fails with OutOfMemory, never leaks" {
    const t: task_mod.Task = .{
        .id = 3,
        .workflow = "jobs:\n  j:\n    env:\n      A: ${{ github.sha }}\n    strategy:\n      matrix:\n        n: [1]\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ${{ matrix.n }}\n",
        .context = .null,
        .secrets = &.{.{ .name = "S", .value = "v" }},
        .vars = &.{},
        .needs = &.{},
    };
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(alloc: Allocator, task: task_mod.Task) !void {
            var arena: std.heap.ArenaAllocator = .init(alloc);
            defer arena.deinit();
            var why: []const u8 = "";
            _ = try fromTask(arena.allocator(), task, &why);
        }
    }.run, .{t});
}

/// `job` with what only GitHub's message has (its GUIDs and `__run` names) taken out of each step,
/// and the display name of one whose `name:` is an expression, which GitHub's message gives as the
/// step's id and the YAML does not have.
fn comparable(arena: Allocator, steps: []const job_mod.Step) ![]job_mod.Step {
    const out = try arena.dupe(job_mod.Step, steps);
    for (out) |*s| {
        s.id = "";
        s.context_name = "";
        if (s.name_expr != null) s.name = "";
    }
    return out;
}

test "the same workflow from GitHub's message and from Gitea's task is the same job" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // The fixture job.zig's own tests parse: GitHub's shape of eight steps, a checkout with inputs,
    // a bare one, actions/cache, a submodules checkout, an escaping one, and a script expression.
    const github = try job_mod.parse(arena, job_mod.fixture);
    var why: []const u8 = "";
    const gitea = (try fromTask(arena, try textTask(arena,
        \\name: t
        \\jobs:
        \\  j:
        \\    outputs:
        \\      version: ${{ steps.v.outputs.version }}
        \\      literal: fixed
        \\    steps:
        \\      - run: echo hello && sleep 2 && echo done
        \\      - name: Build
        \\        if: always()
        \\        continue-on-error: true
        \\        timeout-minutes: 1
        \\        env:
        \\          A: 1
        \\        run: make
        \\        shell: bash
        \\        working-directory: sub
        \\      - name: Checkout
        \\        uses: actions/checkout@v4
        \\        with:
        \\          ref: main
        \\          path: sub/dir
        \\          fetch-depth: 0
        \\          persist-credentials: false
        \\      - uses: actions/checkout@v4
        \\      - uses: actions/cache@v4
        \\      - name: x
        \\        uses: actions/checkout@v4
        \\        with:
        \\          submodules: recursive
        \\      - name: y
        \\        uses: actions/checkout@v4
        \\        with:
        \\          path: ../escape
        \\      - name: Expr
        \\        run: ${{ github.sha }}
    , "{}"), &why)).job;
    // GitHub's steps are listed s1 s2 s3 s5 s6 s7 s8 s4 in the file; the order is the same here.
    try testing.expectEqualDeep(try comparable(arena, github.steps), try comparable(arena, gitea.steps));
    try testing.expectEqualDeep(github.outputs, gitea.outputs);
}

test "the same expressions from GitHub's message and from Gitea's task are the same templates" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // job.zig's "expressions are kept as templates" message.
    const github = try job_mod.parse(arena,
        \\{"plan":{"planId":"p"},"jobId":"j","resources":{"endpoints":[{"authorization":{"parameters":{"AccessToken":"t"}}}]},
        \\ "environmentVariables":[{"type":2,"map":[{"Key":{"lit":"W"},"Value":{"lit":"w"}}]},{"type":2,"map":[{"Key":{"lit":"J"},"Value":{"type":3,"expr":"format('{0}-job', github.ref_name)"}}]}],
        \\ "steps":[{"type":"action","reference":{"type":"script"},"id":"g","contextName":"first","name":"first",
        \\   "displayNameToken":{"type":3,"expr":"format('Build {0}', github.ref_name)"},
        \\   "condition":"success() && (github.ref == 'x')","continueOnError":{"type":3,"expr":"github.event_name == 'push'"},"timeoutInMinutes":{"type":3,"expr":"inputs.limit"},
        \\   "environment":{"type":2,"map":[{"Key":{"lit":"STEP_ENV"},"Value":{"type":3,"expr":"github.sha"}}]},
        \\   "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"type":3,"expr":"format('echo {0}', github.sha)"}}]}}]}
    );
    var why: []const u8 = "";
    const gitea = (try fromTask(arena, try textTask(arena,
        \\env:
        \\  W: w
        \\jobs:
        \\  j:
        \\    env:
        \\      J: ${{ github.ref_name }}-job
        \\    steps:
        \\      - id: first
        \\        name: Build ${{ github.ref_name }}
        \\        if: github.ref == 'x'
        \\        continue-on-error: ${{ github.event_name == 'push' }}
        \\        timeout-minutes: ${{ inputs.limit }}
        \\        env:
        \\          STEP_ENV: ${{ github.sha }}
        \\        run: echo ${{ github.sha }}
    , "{}"), &why)).job;
    // The one step's display name when its `name:` is an expression: GitHub's message names it by
    // its id, so it is the same for the part of it that is evaluated (`name_expr`).
    try testing.expectEqualDeep(try comparable(arena, github.steps), try comparable(arena, gitea.steps));
    try testing.expectEqualDeep(github.env, gitea.env);
}

test "the same services, container and defaults from GitHub's message and from Gitea's task" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const head =
        \\{"plan":{"planId":"p"},"jobId":"j","steps":[],"resources":{"endpoints":[{"authorization":{"parameters":{"AccessToken":"t"}}}]},
    ;
    // job.zig's "services:", "container:" and "defaults:" messages.
    const github = try job_mod.parse(arena, head ++
        \\"jobServiceContainers":{"type":2,"map":[
        \\  {"Key":{"type":0,"lit":"postgres"},"Value":{"type":2,"map":[
        \\    {"Key":{"type":0,"lit":"image"},"Value":{"type":0,"lit":"postgres:17"}},
        \\    {"Key":{"type":0,"lit":"env"},"Value":{"type":2,"map":[{"Key":{"type":0,"lit":"POSTGRES_PASSWORD"},"Value":{"type":3,"expr":"secrets.PG"}}]}},
        \\    {"Key":{"type":0,"lit":"ports"},"Value":{"type":1,"seq":[{"type":0,"lit":"5432:5432"}]}},
        \\    {"Key":{"type":0,"lit":"options"},"Value":{"type":0,"lit":"--health-cmd \"pg_isready\""}}]}},
        \\  {"Key":{"type":0,"lit":"redis"},"Value":{"type":0,"lit":"redis:7"}}]},
        \\ "jobContainer":{"type":2,"map":[{"Key":{"type":0,"lit":"image"},"Value":{"type":3,"expr":"matrix.image"}},
        \\  {"Key":{"type":0,"lit":"env"},"Value":{"type":2,"map":[{"Key":{"type":0,"lit":"NODE_ENV"},"Value":{"type":0,"lit":"test"}}]}}]},
        \\ "defaults":[{"type":2,"map":[{"Key":{"lit":"run"},"Value":{"type":2,"map":[{"Key":{"lit":"working-directory"},"Value":{"lit":"wf"}}]}}]},
        \\  {"type":2,"map":[{"Key":{"lit":"Run"},"Value":{"type":2,"map":[{"Key":{"lit":"Shell"},"Value":{"type":3,"expr":"vars.SHELL"}}]}}]}]}
    );
    var why: []const u8 = "";
    const gitea = (try fromTask(arena, try textTask(arena,
        \\defaults:
        \\  run:
        \\    working-directory: wf
        \\jobs:
        \\  j:
        \\    defaults:
        \\      run:
        \\        shell: ${{ vars.SHELL }}
        \\    container:
        \\      image: ${{ matrix.image }}
        \\      env:
        \\        NODE_ENV: test
        \\    services:
        \\      postgres:
        \\        image: postgres:17
        \\        env:
        \\          POSTGRES_PASSWORD: ${{ secrets.PG }}
        \\        ports:
        \\          - 5432:5432
        \\        options: --health-cmd "pg_isready"
        \\      redis: redis:7
        \\    steps: []
    , "{}"), &why)).job;
    try testing.expectEqualDeep(github.services, gitea.services);
    try testing.expectEqualDeep(github.container, gitea.container);
    try testing.expectEqualDeep(github.defaults_run, gitea.defaults_run);
    try testing.expectEqual(github.defaults_error, gitea.defaults_error);
    try testing.expectEqual(github.services_error, gitea.services_error);
    try testing.expectEqual(github.container_error, gitea.container_error);
}

test "a run step whose script has an expression is named from the text as written" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const c = try convertText(a.allocator(),
        \\    steps:
        \\      - run: |
        \\          echo ${{ github.sha }}
        \\          echo two
    );
    try testing.expectEqualStrings("Run echo ${{ github.sha }}", c.job.steps[0].name);
}
