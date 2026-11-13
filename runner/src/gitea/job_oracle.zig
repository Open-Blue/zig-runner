//! The Zig half of the oracle for `gitea/job.zig`: compares the `job.Job` it builds from a task
//! with what Gitea's own workflow model (gitea.dev/actionslib, `runner/tools/gitea-jobdiff`) reads
//! from the same task's payload. The unit tests run it over the committed corpus and the model's
//! committed answers; `.github/scripts/gitea-job-diff.sh` runs it over answers made fresh.
//!
//! The model gives each text as written, with its `${{ }}`; the job has templates. They are not
//! compared as text but by what they evaluate to: the model's text through `expr.interpolate`
//! (which reads a text as GitHub's `TemplateReader` does, and which `exprdiff` compares with
//! Gitea's evaluator), and the job's template through `expr.evalString`. So the rewrite into
//! `format()` is what is checked, and not that it is the same rewrite.
const std = @import("std");
const job_mod = @import("../job.zig");
const expr = @import("../expr.zig");
const context_mod = @import("../context.zig");
const task_mod = @import("task.zig");
const convert = @import("job.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Template = job_mod.Template;

/// Appends to `diffs` every way `task_json` (an answer of FetchTask) converts differently from what
/// `model` (`gitea-jobdiff`'s answer for it) says. `where` names the task in each.
pub fn compare(
    arena: Allocator,
    where: []const u8,
    task_json: []const u8,
    model: Value,
    diffs: *std.ArrayList([]const u8),
) !void {
    var c: Comparer = .{ .arena = arena, .where = where, .diffs = diffs };
    const Answer = struct { task: ?task_mod.Wire = null };
    const answer = try std.json.parseFromSliceLeaky(Answer, arena, task_json, .{ .ignore_unknown_fields = true });
    const task = try task_mod.fromWire(arena, answer.task.?);
    var why: []const u8 = "";
    const converted = convert.fromTask(arena, task, &why) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BadWorkflow => {
            if (model.object.get("error") == null) try c.say("", "the runner refuses it ({s}), the model reads it", .{why});
            return;
        },
    };
    if (model.object.get("error")) |e| return c.say("", "the model refuses it ({s}), the runner converts it", .{e.string});
    try c.job(converted, model);
}

const Comparer = struct {
    arena: Allocator,
    where: []const u8,
    diffs: *std.ArrayList([]const u8),
    scope: expr.Scope = .{},
    context_data: Value = .null,

    fn say(c: *Comparer, field: []const u8, comptime fmt: []const u8, args: anytype) !void {
        const text = try std.fmt.allocPrint(c.arena, fmt, args);
        try c.diffs.append(c.arena, try std.fmt.allocPrint(c.arena, "{s} {s}: {s}", .{ c.where, field, text }));
    }

    fn job(c: *Comparer, conv: convert.Converted, m: Value) !void {
        const j = conv.job;
        c.scope = try scopeOf(c.arena, j);
        c.context_data = j.context_data;
        const o = m.object;
        try c.eqText("name", str(o, "name"), j.display_name);
        try c.eqList("runs_on", o.get("runs_on"), conv.runs_on);
        try c.eqText("if", str(o, "if"), conv.condition);
        try c.optionalTemplate("timeout_minutes", str(o, "timeout_minutes"), conv.timeout_minutes, null);
        try c.optionalTemplate("continue_on_error", str(o, "continue_on_error"), conv.continue_on_error, "false");

        // The workflow's env then the job's: the later one wins.
        try c.inputMap("env", o.get("env"), j.env);
        try c.defaults(o.get("defaults_run").?, j.defaults_run, j.defaults_error);
        try c.container(o.get("container").?, o.get("container_unreadable").?, j.container, j.container_error);
        try c.services(o.get("services").?, j.services, j.services_error);
        try c.inputMap("outputs", o.get("outputs"), j.outputs);
        try c.matrix(o);
        try c.strategy(o.get("strategy").?);
        try c.steps(o.get("steps") orelse .{ .array = .init(c.arena) }, j.steps);
    }

    // --- one text, one template ---

    /// The model's text and the job's template read the same.
    fn sameTemplate(c: *Comparer, raw: []const u8, tpl: Template) !bool {
        const want = expr.interpolate(c.arena, raw, c.scope) catch null;
        const got: ?[]const u8 = switch (tpl) {
            .lit => |l| l,
            .expr => |e| expr.evalString(c.arena, e, c.scope) catch null,
        };
        if (want == null or got == null) return want == null and got == null;
        return std.mem.eql(u8, want.?, got.?);
    }

    fn template(c: *Comparer, field: []const u8, raw: []const u8, tpl: Template) !void {
        if (!try c.sameTemplate(raw, tpl)) try c.say(field, "the model has '{s}', the job {s}", .{ raw, showTemplate(tpl) });
    }

    /// A template the job may not have; "" in the model is none, or `default`.
    fn optionalTemplate(c: *Comparer, field: []const u8, raw: []const u8, tpl: ?Template, default: ?[]const u8) !void {
        if (raw.len == 0) {
            const t = tpl orelse return;
            if (default) |d| if (try c.sameTemplate(d, t)) return;
            return c.say(field, "the model has none, the job {s}", .{showTemplate(t)});
        }
        const t = tpl orelse return c.say(field, "the model has '{s}', the job none", .{raw});
        return c.template(field, raw, t);
    }

    fn eqText(c: *Comparer, field: []const u8, want: []const u8, got: []const u8) !void {
        if (!std.mem.eql(u8, want, got)) try c.say(field, "the model has '{s}', the job '{s}'", .{ want, got });
    }

    fn eqList(c: *Comparer, field: []const u8, want: ?Value, got: []const []const u8) !void {
        const items = if (want) |w| (if (w == .array) w.array.items else &[_]Value{}) else &[_]Value{};
        if (items.len != got.len) return c.say(field, "the model has {d} entries, the job {d}", .{ items.len, got.len });
        for (items, got) |w, g| try c.eqText(field, w.string, g);
    }

    /// The model's map of names to texts, and the job's list of inputs (later ones override).
    fn inputMap(c: *Comparer, field: []const u8, want: ?Value, got: []const job_mod.Input) !void {
        const w = if (want) |v| v.object else std.json.ObjectMap.empty;
        for (w.keys(), w.values()) |k, v| {
            const tpl = lastInput(got, k) orelse {
                try c.say(field, "the model has '{s}', the job does not", .{k});
                continue;
            };
            try c.template(try std.fmt.allocPrint(c.arena, "{s}.{s}", .{ field, k }), v.string, tpl);
        }
        for (got) |in| if (!w.contains(in.name)) try c.say(field, "the job has '{s}', the model does not", .{in.name});
    }

    fn defaults(c: *Comparer, want: Value, got: job_mod.RunDefaults, err: ?[]const u8) !void {
        if (err != null) return c.say("defaults", "the job cannot read them ({s})", .{err.?});
        try c.optionalTemplate("defaults.shell", str(want.object, "shell"), got.shell, null);
        try c.optionalTemplate("defaults.working-directory", str(want.object, "working-directory"), got.working_directory, null);
    }

    fn container(c: *Comparer, want: Value, broken: Value, got: ?job_mod.Service, err: ?[]const u8) !void {
        if (broken.bool != (err != null)) return c.say("container", "the model's unreadable is {}, the job's error is {}", .{ broken.bool, err != null });
        if (want == .null) {
            if (got != null) try c.say("container", "the job has one, the model does not", .{});
            return;
        }
        const g = got orelse return c.say("container", "the model has one, the job does not", .{});
        try c.service("container", want, g);
    }

    fn services(c: *Comparer, want: Value, got: []const job_mod.Service, err: ?[]const u8) !void {
        if (err != null) return c.say("services", "the job cannot read them ({s})", .{err.?});
        if (want.object.count() != got.len) return c.say("services", "the model has {d}, the job {d}", .{ want.object.count(), got.len });
        for (got) |g| {
            const w = want.object.get(g.name) orelse {
                try c.say("services", "the job has '{s}', the model does not", .{g.name});
                continue;
            };
            try c.service(try std.fmt.allocPrint(c.arena, "services.{s}", .{g.name}), w, g);
        }
    }

    fn service(c: *Comparer, field: []const u8, want: Value, got: job_mod.Service) !void {
        const o = want.object;
        try c.template(field, str(o, "image"), got.image);
        try c.inputMap(field, o.get("env"), got.env);
        try c.templates(field, o.get("ports"), got.ports);
        try c.templates(field, o.get("volumes"), got.volumes);
        try c.optionalTemplate(field, str(o, "options"), got.options, null);
        const creds = o.get("credentials").?.object;
        try c.optionalTemplate(field, if (creds.get("username")) |v| v.string else "", got.username, null);
        try c.optionalTemplate(field, if (creds.get("password")) |v| v.string else "", got.password, null);
    }

    fn templates(c: *Comparer, field: []const u8, want: ?Value, got: []const Template) !void {
        const items = if (want) |w| w.array.items else &[_]Value{};
        if (items.len != got.len) return c.say(field, "the model has {d} entries, the job {d}", .{ items.len, got.len });
        for (items, got) |w, g| try c.template(field, w.string, g);
    }

    // --- contexts ---

    fn matrix(c: *Comparer, o: std.json.ObjectMap) !void {
        const count = o.get("matrix_count").?.integer;
        if (count != 1) return c.say("matrix", "the model expands it to {d} combinations: the runner should refuse it", .{count});
        const want = o.get("matrix").?.object;
        const got = try context_mod.named(c.arena, c.context_data, "matrix");
        const entries: []const expr.Value.Entry = if (got == .object) got.object else &.{};
        for (want.keys(), want.values()) |k, v| {
            const g = entryOf(entries, k) orelse {
                try c.say("matrix", "the model has '{s}', the job does not", .{k});
                continue;
            };
            if (!sameValue(v, g)) try c.say("matrix", "'{s}' differs: the model has {f}, the job {s}", .{ k, std.json.fmt(v, .{}), showValue(g) });
        }
        for (entries) |e| if (!want.contains(e.key)) try c.say("matrix", "the job has '{s}', the model does not", .{e.key});
    }

    fn strategy(c: *Comparer, want: Value) !void {
        const got = try context_mod.named(c.arena, c.context_data, "strategy");
        const entries: []const expr.Value.Entry = if (got == .object) got.object else &.{};
        for (want.object.keys(), want.object.values()) |k, v| {
            const g = entryOf(entries, k) orelse {
                try c.say("strategy", "the model has '{s}', the job does not", .{k});
                continue;
            };
            // Gitea writes `fail-fast: "false"` as a string, and the model keeps it one; GitHub's
            // strategy context holds a boolean, which is what the job has.
            if (std.mem.eql(u8, k, "fail-fast") and v == .string and g == .boolean and
                std.ascii.eqlIgnoreCase(v.string, if (g.boolean) "true" else "false")) continue;
            if (!sameValue(v, g)) try c.say("strategy", "'{s}' differs: the model has {f}, the job {s}", .{ k, std.json.fmt(v, .{}), showValue(g) });
        }
    }

    // --- steps ---

    fn steps(c: *Comparer, want: Value, got: []const job_mod.Step) !void {
        const items = want.array.items;
        if (items.len != got.len) return c.say("steps", "the model has {d} steps, the job {d}", .{ items.len, got.len });
        for (items, got, 1..) |w, g, i| {
            const field = try std.fmt.allocPrint(c.arena, "step {d}", .{i});
            try c.step(field, w.object, g);
        }
    }

    fn step(c: *Comparer, field: []const u8, o: std.json.ObjectMap, s: job_mod.Step) !void {
        const kind = str(o, "kind");
        const uses = str(o, "uses");
        const with = o.get("with");
        // What the kinds are called by the model, and the actions the job has for them.
        if (s.action == .unsupported) {
            // Only what is outside this step's scope (G5: where an action is fetched from) and what
            // the model calls invalid may be unsupported.
            const known = std.mem.eql(u8, kind, "invalid") or
                (std.mem.eql(u8, kind, "remote-action") and
                    (std.mem.indexOf(u8, uses, "://") != null or std.mem.startsWith(u8, uses, "$/") or std.mem.startsWith(u8, uses, "self:") or std.mem.indexOf(u8, s.action.unsupported, "valid action reference") != null)) or
                std.mem.indexOf(u8, kind, "reusable-workflow") != null or
                std.mem.indexOf(u8, s.action.unsupported, "shell") != null;
            if (!known) try c.say(field, "unsupported ({s}) though the model reads a {s} step", .{ s.action.unsupported, kind });
            return;
        }
        const kind_ok = switch (s.action) {
            .script => std.mem.eql(u8, kind, "run"),
            .docker => std.mem.eql(u8, kind, "docker"),
            .checkout => std.mem.eql(u8, kind, "remote-action"),
            .uses => |u| std.mem.eql(u8, kind, if (u.local) "local-action" else "remote-action"),
            .unsupported => unreachable,
        };
        if (!kind_ok) try c.say(field, "the model says {s}, the job has a {s} step", .{ kind, @tagName(s.action) });

        // Names: as written, or an expression, or the default GitHub shows.
        const name = str(o, "name");
        if (name.len == 0) {
            if (s.name_expr != null) try c.say(field, "the job has a name expression, the model no name", .{});
        } else if (std.mem.indexOf(u8, name, "${{") != null) {
            const e = s.name_expr orelse return c.say(field, "the model's name has an expression, the job's does not", .{});
            try c.template(field, name, .{ .expr = e });
        } else try c.eqText(field, name, s.name);

        const id = str(o, "id");
        if (id.len > 0) try c.eqText(field, id, s.context_name) else if (!std.mem.startsWith(u8, s.context_name, "__run"))
            try c.say(field, "an unnamed step is '{s}'", .{s.context_name});

        // `if`: the job message carries `success() && (...)` where the text has no status function.
        const cond = stripWrapper(str(o, "if"));
        if (cond.len == 0) {
            try c.eqText(field, "success()", s.condition);
        } else if (!std.mem.eql(u8, cond, s.condition)) {
            const wrapped = try std.fmt.allocPrint(c.arena, "success() && ({s})", .{cond});
            if (!std.mem.eql(u8, wrapped, s.condition)) try c.say(field, "if: the model has '{s}', the job '{s}'", .{ cond, s.condition });
        }

        try c.optionalTemplate(field, str(o, "continue_on_error"), s.continue_on_error, "false");
        try c.optionalTemplate(field, str(o, "timeout_minutes"), s.timeout_minutes, null);
        try c.inputMap(field, o.get("env"), s.env);

        switch (s.action) {
            .script => |sc| {
                try c.template(field, str(o, "run"), sc.script);
                try c.optionalTemplate(field, str(o, "shell"), sc.shell, null);
                try c.optionalTemplate(field, str(o, "working_directory"), sc.working_directory, null);
            },
            .docker => |d| {
                try c.eqText(field, uses, try std.fmt.allocPrint(c.arena, "docker://{s}", .{d.image}));
                try c.inputMap(field, with, d.inputs);
            },
            .checkout => |inputs| {
                try c.eqText(field, uses, s.uses);
                try c.inputMap(field, with, inputs);
            },
            .uses => |u| {
                try c.eqText(field, uses, s.uses);
                try c.inputMap(field, with, u.inputs);
            },
            .unsupported => unreachable,
        }
    }
};

fn str(o: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = o.get(key) orelse return "";
    return if (v == .string) v.string else "";
}

fn lastInput(list: []const job_mod.Input, name: []const u8) ?Template {
    var i = list.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, list[i].name, name)) return list[i].value;
    }
    return null;
}

fn entryOf(entries: []const expr.Value.Entry, key: []const u8) ?expr.Value {
    for (entries) |e| if (std.mem.eql(u8, e.key, key)) return e.value;
    return null;
}

fn stripWrapper(text_in: []const u8) []const u8 {
    const text = std.mem.trim(u8, text_in, " \t\r\n");
    if (std.mem.startsWith(u8, text, "${{")) if (expr.expressionEnd(text, 3)) |end| {
        if (end + 2 == text.len) return std.mem.trim(u8, text[3..end], " \t\r\n");
    };
    return text;
}

fn showTemplate(t: Template) []const u8 {
    return switch (t) {
        .lit => |l| l,
        .expr => |e| e,
    };
}

fn showValue(v: expr.Value) []const u8 {
    return switch (v) {
        .string => |s| s,
        .boolean => |b| if (b) "true" else "false",
        .number => "a number",
        .null => "null",
        .array => "an array",
        .object => "an object",
    };
}

/// A JSON value from the model and a value of the job's context are the same.
fn sameValue(want: Value, got: expr.Value) bool {
    return switch (want) {
        .null => got == .null,
        .bool => |b| got == .boolean and got.boolean == b,
        .integer => |i| got == .number and got.number == @as(f64, @floatFromInt(i)),
        .float => |f| got == .number and got.number == f,
        .number_string => false,
        .string => |s| got == .string and std.mem.eql(u8, got.string, s),
        .array => |a| blk: {
            if (got != .array or got.array.len != a.items.len) break :blk false;
            for (a.items, got.array) |x, y| if (!sameValue(x, y)) break :blk false;
            break :blk true;
        },
        .object => |o| blk: {
            if (got != .object or got.object.len != o.count()) break :blk false;
            for (o.keys(), o.values()) |k, v| {
                const g = entryOf(got.object, k) orelse break :blk false;
                if (!sameValue(v, g)) break :blk false;
            }
            break :blk true;
        },
    };
}

/// What an expression in the job can read: its contexts, and empty ones for what only exists once
/// it runs.
fn scopeOf(arena: Allocator, j: job_mod.Job) !expr.Scope {
    const empty: expr.Value = .{ .object = &.{} };
    const secrets = try arena.alloc(expr.Value.Entry, j.secret_vars.len);
    for (j.secret_vars, secrets) |s, *e| e.* = .{ .key = s.name, .value = .{ .string = s.value } };
    const ctxs = try arena.alloc(expr.Value.Entry, 12);
    ctxs[0] = .{ .key = "github", .value = try context_mod.named(arena, j.context_data, "github") };
    ctxs[1] = .{ .key = "matrix", .value = try context_mod.named(arena, j.context_data, "matrix") };
    ctxs[2] = .{ .key = "strategy", .value = try context_mod.named(arena, j.context_data, "strategy") };
    ctxs[3] = .{ .key = "needs", .value = try context_mod.named(arena, j.context_data, "needs") };
    ctxs[4] = .{ .key = "vars", .value = try context_mod.named(arena, j.context_data, "vars") };
    ctxs[5] = .{ .key = "inputs", .value = try context_mod.named(arena, j.context_data, "inputs") };
    ctxs[6] = .{ .key = "job", .value = try context_mod.named(arena, j.context_data, "job") };
    ctxs[7] = .{ .key = "secrets", .value = .{ .object = secrets } };
    ctxs[8] = .{ .key = "env", .value = empty };
    ctxs[9] = .{ .key = "steps", .value = empty };
    ctxs[10] = .{ .key = "runner", .value = empty };
    ctxs[11] = .{ .key = "jobs", .value = empty };
    return .{ .contexts = ctxs };
}

// --- tests ---

const testing = std.testing;

/// The corpus: tasks Gitea and Forgejo handed out for runner-bench's workflows (and the two
/// fixtures' workflow), cut to the parts the conversion reads, with the model's answers.
const corpus_names = @embedFile("testdata/corpus/INDEX");
const model_answers = @embedFile("testdata/corpus-model.jsonl");

fn taskText(comptime name: []const u8) []const u8 {
    return @embedFile("testdata/corpus/" ++ name);
}

test "the job built from each task of the corpus is what Gitea's model reads from it" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var diffs: std.ArrayList([]const u8) = .empty;
    var models = std.mem.splitScalar(u8, model_answers, '\n');
    var count: usize = 0;
    inline for (comptime corpus_lines()) |name| {
        const line = models.next() orelse return error.CorpusAndModelAnswersDiffer;
        const entry = try std.json.parseFromSliceLeaky(Value, arena, line, .{});
        try testing.expectEqualStrings(name, entry.object.get("file").?.string);
        try compare(arena, name, taskText(name), entry.object.get("model").?, &diffs);
        count += 1;
    }
    for (diffs.items) |d| std.debug.print("{s}\n", .{d});
    try testing.expectEqual(@as(usize, 0), diffs.items.len);
    try testing.expect(count >= 60);
}

fn corpus_lines() []const []const u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var names: []const []const u8 = &.{};
        var it = std.mem.tokenizeScalar(u8, corpus_names, '\n');
        while (it.next()) |n| names = names ++ [_][]const u8{n};
        return names;
    }
}

test "the comparison sees a job that is not what the model says" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const task = taskText("gitea-e2e-js.json");
    var line = std.mem.tokenizeScalar(u8, model_answers, '\n');
    var good: ?Value = null;
    while (line.next()) |l| {
        const entry = try std.json.parseFromSliceLeaky(Value, arena, l, .{});
        if (std.mem.eql(u8, entry.object.get("file").?.string, "gitea-e2e-js.json")) good = entry.object.get("model").?;
    }
    const model = good.?;
    var diffs: std.ArrayList([]const u8) = .empty;
    try compare(arena, "js", task, model, &diffs);
    try testing.expectEqual(@as(usize, 0), diffs.items.len);

    // A different run text, a different step kind, a step too many, an env value, a matrix.
    var bent = model.object;
    var steps = model.object.get("steps").?.array;
    var first = steps.items[0].object;
    try first.put(arena, "kind", .{ .string = "docker" });
    var second = steps.items[1].object;
    try second.put(arena, "run", .{ .string = "echo different" });
    var env = std.json.ObjectMap.empty;
    try env.put(arena, "E2E_NONCE", .{ .string = "other" });
    try bent.put(arena, "env", .{ .object = env });
    var matrix = std.json.ObjectMap.empty;
    try matrix.put(arena, "n", .{ .integer = 3 });
    try bent.put(arena, "matrix", .{ .object = matrix });
    try bent.put(arena, "name", .{ .string = "renamed" });
    try steps.append(.{ .object = first });
    try bent.put(arena, "steps", .{ .array = steps });
    try compare(arena, "js", task, .{ .object = bent }, &diffs);
    try testing.expect(diffs.items.len >= 4);
    var text: std.ArrayList(u8) = .empty;
    for (diffs.items) |d| try text.appendSlice(arena, d);
    for ([_][]const u8{ "name", "env.E2E_NONCE", "matrix", "steps" }) |needle|
        try testing.expect(std.mem.indexOf(u8, text.items, needle) != null);

    // A task the model refuses and the runner converts, and the other way round.
    diffs.clearRetainingCapacity();
    var refusal = std.json.ObjectMap.empty;
    try refusal.put(arena, "error", .{ .string = "bad" });
    try compare(arena, "js", task, .{ .object = refusal }, &diffs);
    try testing.expectEqual(@as(usize, 1), diffs.items.len);
}
