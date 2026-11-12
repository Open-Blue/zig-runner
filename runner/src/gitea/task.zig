//! A task as `FetchTask` hands it over: one job of a workflow, already expanded by the instance
//! (`Task` in `runner/v1/messages.proto`), in Connect's JSON mapping of protobuf: camelCase names,
//! an int64 as a string, `bytes` as base64, absent when empty.
const std = @import("std");
const yaml = @import("../yaml.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{BadTask} || Allocator.Error;

/// A name and its value. The values of secrets and vars are what the job reads; nothing here writes
/// them to a log.
pub const Pair = struct { name: []const u8, value: []const u8 };

/// What a job this one `needs:` produced.
pub const Need = struct {
    job: []const u8,
    /// `RESULT_SUCCESS`, `RESULT_FAILURE`... as the instance names it; empty when it sent none.
    result: []const u8,
    outputs: []const Pair,
};

pub const Task = struct {
    id: i64,
    /// The YAML of the one job, decoded.
    workflow: []const u8,
    /// The `github` context (with Gitea's own fields), an object; `.null` when none came.
    context: std.json.Value,
    secrets: []const Pair,
    vars: []const Pair,
    needs: []const Need,

    /// What the runner says about a task it takes: the workflow's and job's names, how many steps,
    /// and the names of what came with it. Never a value: a secret's value, the context's token
    /// and the job's variables stay out of the log.
    pub fn describe(t: Task, arena: Allocator) error{ WriteFailed, OutOfMemory }![]const u8 {
        var out: std.Io.Writer.Allocating = .init(arena);
        const w = &out.writer;
        try w.print("task {d}: ", .{t.id});
        var diag: yaml.Diag = .{};
        if (yaml.parse(arena, t.workflow, &diag)) |doc| {
            const name = if (doc.get("name")) |n| n.text() orelse "" else "";
            try w.print("workflow \"{s}\"", .{name});
            if (doc.get("jobs")) |jobs| if (jobs == .map) {
                try w.print(", {d} job(s):", .{jobs.map.len});
                for (jobs.map) |j| {
                    const label = if (j.value.get("name")) |n| n.text() orelse j.key else j.key;
                    const steps = if (j.value.get("steps")) |s| if (s == .seq) s.seq.len else 0 else 0;
                    try w.print(" {s} (\"{s}\", {d} steps)", .{ j.key, label, steps });
                }
            };
        } else |_| try w.print("workflow unreadable ({s})", .{diag.message});
        try w.print("; context keys: ", .{});
        try listKeys(w, t.context);
        try w.print("; secrets: ", .{});
        try listNames(w, t.secrets);
        try w.print("; vars: ", .{});
        try listNames(w, t.vars);
        try w.print("; needs: {d}", .{t.needs.len});
        return out.written();
    }
};

fn listKeys(w: *std.Io.Writer, v: std.json.Value) !void {
    if (v != .object or v.object.count() == 0) return w.writeAll("none");
    for (v.object.keys(), 0..) |k, i| try w.print("{s}{s}", .{ if (i == 0) "" else ",", k });
}

fn listNames(w: *std.Io.Writer, list: []const Pair) !void {
    if (list.len == 0) return w.writeAll("none");
    for (list, 0..) |p, i| try w.print("{s}{s}", .{ if (i == 0) "" else ",", p.name });
}

/// protobuf JSON's int64: a string (`"12"`), though a number is read too.
pub const Int64 = struct {
    value: i64 = 0,

    pub fn jsonParse(a: Allocator, source: anytype, options: std.json.ParseOptions) !Int64 {
        const v = try std.json.innerParse(std.json.Value, a, source, options);
        return .{ .value = switch (v) {
            .integer => |i| i,
            .string, .number_string => |s| std.fmt.parseInt(i64, s, 10) catch return error.InvalidNumber,
            else => return error.UnexpectedToken,
        } };
    }
};

const WireNeed = struct {
    outputs: ?std.json.ArrayHashMap([]const u8) = null,
    result: ?[]const u8 = null,
};

/// `Task` as it comes over the wire, before it is made into one.
pub const Wire = struct {
    id: Int64 = .{},
    workflowPayload: ?[]const u8 = null,
    context: ?std.json.Value = null,
    secrets: ?std.json.ArrayHashMap([]const u8) = null,
    needs: ?std.json.ArrayHashMap(WireNeed) = null,
    vars: ?std.json.ArrayHashMap([]const u8) = null,
};

/// The task `w` holds. A task with no id, or whose workflow does not decode, is `BadTask`: the
/// instance never sends one, and a runner that ran it would be running nothing it could name.
pub fn fromWire(arena: Allocator, w: Wire) Error!Task {
    if (w.id.value <= 0) return error.BadTask;
    const payload = w.workflowPayload orelse return error.BadTask;
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(payload) catch return error.BadTask;
    const workflow = try arena.alloc(u8, size);
    decoder.decode(workflow, payload) catch return error.BadTask;
    return .{
        .id = w.id.value,
        .workflow = workflow,
        .context = w.context orelse .null,
        .secrets = try pairs(arena, w.secrets),
        .vars = try pairs(arena, w.vars),
        .needs = try needs(arena, w.needs),
    };
}

fn pairs(arena: Allocator, m: ?std.json.ArrayHashMap([]const u8)) Allocator.Error![]const Pair {
    const map = m orelse return &.{};
    const out = try arena.alloc(Pair, map.map.count());
    for (map.map.keys(), map.map.values(), out) |k, v, *p| p.* = .{ .name = k, .value = v };
    return out;
}

fn needs(arena: Allocator, m: ?std.json.ArrayHashMap(WireNeed)) Allocator.Error![]const Need {
    const map = m orelse return &.{};
    const out = try arena.alloc(Need, map.map.count());
    for (map.map.keys(), map.map.values(), out) |k, v, *n| n.* = .{
        .job = k,
        .result = v.result orelse "",
        .outputs = try pairs(arena, v.outputs),
    };
    return out;
}

const fixture = @embedFile("testdata/fetch-task.json");

test "a task the instance handed over is read" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Answer = struct { task: ?Wire = null, tasksVersion: Int64 = .{} };
    const answer = try std.json.parseFromSliceLeaky(Answer, arena, fixture, .{ .ignore_unknown_fields = true });
    try std.testing.expectEqual(@as(i64, 1), answer.tasksVersion.value);
    const t = try fromWire(arena, answer.task.?);
    try std.testing.expectEqual(@as(i64, 1), t.id);
    try std.testing.expect(std.mem.startsWith(u8, t.workflow, "name: probe\n"));
    try std.testing.expectEqualStrings("refs/heads/main", t.context.object.get("ref").?.string);
    try std.testing.expectEqual(@as(usize, 2), t.secrets.len);
    try std.testing.expectEqualStrings("GITEA_TOKEN", t.secrets[0].name);
    try std.testing.expectEqual(@as(usize, 0), t.vars.len);
    try std.testing.expectEqual(@as(usize, 0), t.needs.len);
}

test "a task from Forgejo is read the same" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Answer = struct { task: ?Wire = null };
    const answer = try std.json.parseFromSliceLeaky(Answer, arena, @embedFile("testdata/fetch-task-forgejo.json"), .{ .ignore_unknown_fields = true });
    const t = try fromWire(arena, answer.task.?);
    try std.testing.expect(t.id > 0);
    try std.testing.expect(t.secrets.len >= 1);
    const line = try t.describe(arena);
    try std.testing.expect(std.mem.indexOf(u8, line, "FORGEJO_TOKEN") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "job(s):") != null);
}

test "what the runner says of a task has names and counts, and no value" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Answer = struct { task: ?Wire = null };
    const answer = try std.json.parseFromSliceLeaky(Answer, arena, fixture, .{ .ignore_unknown_fields = true });
    var t = try fromWire(arena, answer.task.?);
    t.secrets = &.{.{ .name = "DEPLOY_KEY", .value = "hunter2-do-not-print" }};
    t.vars = &.{.{ .name = "REGION", .value = "mars-1" }};
    const line = try t.describe(arena);
    try std.testing.expect(std.mem.indexOf(u8, line, "task 1: workflow \"probe\", 1 job(s): hello (\"hello (1)\", 3 steps)") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "secrets: DEPLOY_KEY;") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "vars: REGION;") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "hunter2") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "mars-1") == null);
    // The context's values (its token among them) are not in it either.
    try std.testing.expect(std.mem.indexOf(u8, line, "refs/heads/main") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "gitea_runtime_token,") != null);
}

test "needs, vars and a numeric id are read; a task without a workflow is not one" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const json =
        \\{"id":12,"workflowPayload":"am9iczoge30K","vars":{"A":"1"},
        \\ "needs":{"build":{"result":"RESULT_SUCCESS","outputs":{"v":"2"}}}}
    ;
    const w = try std.json.parseFromSliceLeaky(Wire, arena, json, .{});
    const t = try fromWire(arena, w);
    try std.testing.expectEqual(@as(i64, 12), t.id);
    try std.testing.expectEqualStrings("A", t.vars[0].name);
    try std.testing.expectEqualStrings("build", t.needs[0].job);
    try std.testing.expectEqualStrings("RESULT_SUCCESS", t.needs[0].result);
    try std.testing.expectEqualStrings("2", t.needs[0].outputs[0].value);
    try std.testing.expect(t.context == .null);

    const bare = try std.json.parseFromSliceLeaky(Wire, arena, "{\"id\":\"3\"}", .{});
    try std.testing.expectError(error.BadTask, fromWire(arena, bare));
    const bad64 = try std.json.parseFromSliceLeaky(Wire, arena, "{\"id\":\"3\",\"workflowPayload\":\"!!\"}", .{});
    try std.testing.expectError(error.BadTask, fromWire(arena, bad64));
}
