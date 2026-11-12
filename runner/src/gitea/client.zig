//! A Gitea or Forgejo instance's runner protocol (`runner.v1.RunnerService`), over Connect's JSON
//! encoding: each RPC is a POST of the request as protobuf's JSON mapping to
//! `<instance>/api/actions/runner.v1.RunnerService/<Method>`, and a failure is a non-200 answer
//! with `{"code": ..., "message": ...}`. No protobuf codec is needed (#520 §1).
//!
//! Requests go through `github/broker.request`, which has the process's shared HTTP client, the
//! per-request deadline and the retry of a kept-alive connection the instance had closed. Every
//! call after `register` carries the runner's uuid and token as headers.
const std = @import("std");
const broker = @import("../github/broker.zig");
const task_mod = @import("task.zig");

const Allocator = std.mem.Allocator;

pub const Task = task_mod.Task;

pub const Error = error{
    /// The instance does not know this runner (or its registration token): HTTP 401, or Connect's
    /// `unauthenticated` or `permission_denied`. Trying again cannot help; registering might.
    Unauthenticated,
    /// Any other refusal; `Failure` says which.
    Rejected,
    /// An answer that is not what the method answers.
    BadResponse,
} || Allocator.Error;

/// What a refused call said, for the log: the HTTP status, Connect's code and its message (cut
/// short). Never the request, which holds tokens.
pub const Failure = struct {
    status: std.http.Status = .ok,
    code: []const u8 = "",
    message: []const u8 = "",
};

/// Which instance software answers. They share the transport, the headers and the three calls here;
/// Forgejo's `RegisterRequest` and `DeclareRequest` have no `capabilities`, and its `FetchTask` can
/// take a `taskCapacity` (not sent: one task per runner) and answer `additionalTasks`.
pub const Flavor = enum { gitea, forgejo };

pub const Client = struct {
    flavor: Flavor = .gitea,
    /// The instance's address, without a trailing slash.
    url: []const u8,
    /// The runner's credentials, empty until `register` (or the saved state) gives them.
    uuid: []const u8 = "",
    token: []const u8 = "",
    /// How long one call may take (`http.within`). `FetchTask` is a short poll, so this is the
    /// longest a stop waits for a call in flight.
    deadline: std.Io.Duration = .fromSeconds(10),

    /// POSTs `body` to `method` and returns the answer's body. A refusal fills `failure`.
    pub fn call(
        c: Client,
        arena: Allocator,
        io: std.Io,
        method: []const u8,
        body: []const u8,
        failure: *Failure,
    ) !([]const u8) {
        const url = try std.fmt.allocPrint(arena, "{s}/api/actions/runner.v1.RunnerService/{s}", .{ c.url, method });
        var headers: std.ArrayList(std.http.Header) = .empty;
        try headers.append(arena, .{ .name = "Connect-Protocol-Version", .value = "1" });
        if (c.uuid.len > 0) try headers.append(arena, .{ .name = "x-runner-uuid", .value = c.uuid });
        if (c.token.len > 0) try headers.append(arena, .{ .name = "x-runner-token", .value = c.token });
        const r = try broker.request(arena, io, .POST, url, body, .{
            .extra_headers = headers.items,
            .deadline = c.deadline,
            .max_body = 16 * 1024 * 1024,
        });
        if (r.status == .ok) return r.body;
        failure.* = refusal(arena, r);
        if (r.status == .unauthorized or std.mem.eql(u8, failure.code, "unauthenticated") or
            std.mem.eql(u8, failure.code, "permission_denied")) return error.Unauthenticated;
        return error.Rejected;
    }

    /// `{"runner": {...}}`, what `Register` and `Declare` answer.
    fn runnerOf(arena: Allocator, text: []const u8) Error!Runner {
        const parsed = std.json.parseFromSliceLeaky(
            struct { runner: ?WireRunner = null },
            arena,
            text,
            .{ .ignore_unknown_fields = true },
        ) catch return error.BadResponse;
        const w = parsed.runner orelse return error.BadResponse;
        return .{
            .id = w.id.value,
            .uuid = w.uuid,
            .token = w.token,
            .name = w.name,
            .labels = w.labels,
        };
    }

    /// Registers a runner with the instance's registration token. The answer's uuid and token are
    /// the runner's credentials from here on (this `Client` is not changed: the caller keeps
    /// them, in the state file, and sets them).
    pub fn register(
        c: Client,
        arena: Allocator,
        io: std.Io,
        req: RegisterRequest,
        failure: *Failure,
    ) !Runner {
        var q = req;
        if (c.flavor == .forgejo) q.capabilities = &.{};
        const body = try json(arena, q);
        const r = try runnerOf(arena, try c.call(arena, io, "Register", body, failure));
        if (r.uuid.len == 0 or r.token.len == 0) return error.BadResponse;
        return r;
    }

    /// Tells the instance the runner's version, labels and capabilities, as `act_runner` does at
    /// each start: the registration keeps what it was given then, and labels may have changed.
    pub fn declare(
        c: Client,
        arena: Allocator,
        io: std.Io,
        req: DeclareRequest,
        failure: *Failure,
    ) !Runner {
        var q = req;
        if (c.flavor == .forgejo) q.capabilities = &.{};
        const body = try json(arena, q);
        return runnerOf(arena, try c.call(arena, io, "Declare", body, failure));
    }

    /// Asks for a task. `tasks_version` is the last the runner saw (0 at first): the instance
    /// answers with the latest, and a task when there is one for this runner.
    pub fn fetchTask(
        c: Client,
        arena: Allocator,
        io: std.Io,
        tasks_version: i64,
        failure: *Failure,
    ) !Fetched {
        // An int64 is a string in protobuf's JSON, and a zero is left out.
        const body = if (tasks_version == 0)
            "{}"
        else
            try std.fmt.allocPrint(arena, "{{\"tasksVersion\":\"{d}\"}}", .{tasks_version});
        const text = try c.call(arena, io, "FetchTask", body, failure);
        const parsed = std.json.parseFromSliceLeaky(
            struct {
                task: ?task_mod.Wire = null,
                tasksVersion: task_mod.Int64 = .{},
                additionalTasks: []const task_mod.Wire = &.{},
            },
            arena,
            text,
            .{ .ignore_unknown_fields = true },
        ) catch return error.BadResponse;
        const t = if (parsed.task) |w| (task_mod.fromWire(arena, w) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BadTask => return error.BadResponse,
        }) else null;
        return .{
            .task = t,
            .tasks_version = parsed.tasksVersion.value,
            .additional = parsed.additionalTasks.len,
        };
    }
};

pub const RegisterRequest = struct {
    name: []const u8,
    token: []const u8,
    version: []const u8,
    labels: []const []const u8,
    ephemeral: bool = false,
    capabilities: []const []const u8 = &.{},
};

pub const DeclareRequest = struct {
    version: []const u8,
    labels: []const []const u8,
    capabilities: []const []const u8 = &.{},
};

/// `Runner` in `messages.proto`, the fields the runner uses.
pub const Runner = struct {
    id: i64,
    uuid: []const u8,
    token: []const u8,
    name: []const u8,
    labels: []const []const u8,
};

const WireRunner = struct {
    id: task_mod.Int64 = .{},
    uuid: []const u8 = "",
    token: []const u8 = "",
    name: []const u8 = "",
    labels: []const []const u8 = &.{},
};

/// What `fetchTask` got: a task or none, and the instance's latest tasks version.
pub const Fetched = struct {
    task: ?Task,
    tasks_version: i64,
    /// Forgejo's `additionalTasks`: how many came besides `task`. Read, not used: the runner asks
    /// for one task, so none should (`taskCapacity` is not sent).
    additional: usize = 0,
};

/// `value` as JSON with protobuf's habit of leaving out what is empty or false.
fn json(arena: Allocator, value: anytype) error{ WriteFailed, OutOfMemory }![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const T = @TypeOf(value);
    try out.writer.writeByte('{');
    var first = true;
    inline for (@typeInfo(T).@"struct".field_names, @typeInfo(T).@"struct".field_types) |name, FT| {
        const v = @field(value, name);
        const empty = switch (@typeInfo(FT)) {
            .bool => !v,
            .pointer => v.len == 0,
            else => false,
        };
        if (!empty) {
            if (!first) try out.writer.writeByte(',');
            first = false;
            try std.json.Stringify.value(@as([]const u8, name), .{}, &out.writer);
            try out.writer.writeByte(':');
            try std.json.Stringify.value(v, .{}, &out.writer);
        }
    }
    try out.writer.writeByte('}');
    return out.written();
}

/// Connect's error body, or what there is of the answer when it is none.
fn refusal(arena: Allocator, r: broker.Response) Failure {
    const Wire = struct { code: []const u8 = "", message: []const u8 = "" };
    const w = std.json.parseFromSliceLeaky(Wire, arena, r.body, .{ .ignore_unknown_fields = true }) catch
        return .{ .status = r.status, .message = r.body[0..@min(r.body.len, 200)] };
    return .{ .status = r.status, .code = w.code, .message = w.message[0..@min(w.message.len, 200)] };
}

const testserver = @import("testserver.zig");

fn testClient(s: *const testserver.Server, buf: []u8) Client {
    return .{ .url = s.url(buf), .deadline = .fromSeconds(5) };
}

const registered =
    \\{"runner":{"id":"7","uuid":"uuid-7","token":"runner-token-7","name":"zig-ab","status":"RUNNER_STATUS_OFFLINE","labels":["linux","zig"]}}
;

test "Register sends the instance's token as JSON and returns the runner's credentials" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.reply("Register", "200 OK", registered);
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    var failure: Failure = .{};
    const r = try testClient(&s, &buf).register(arena, std.testing.io, .{
        .name = "zig-ab",
        .token = "registration-secret",
        .version = "0.1.0",
        .labels = &.{ "linux", "zig" },
    }, &failure);
    try std.testing.expectEqual(@as(i64, 7), r.id);
    try std.testing.expectEqualStrings("uuid-7", r.uuid);
    try std.testing.expectEqualStrings("runner-token-7", r.token);
    try std.testing.expectEqual(@as(usize, 2), r.labels.len);

    const seen = s.nth("Register", 0);
    try std.testing.expectEqualStrings("application/json", seen.content_type);
    try std.testing.expectEqualStrings("1", seen.connect_version);
    // Nothing identifies the runner before it has registered.
    try std.testing.expectEqualStrings("", seen.uuid);
    try std.testing.expectEqualStrings("", seen.token);
    try std.testing.expectEqualStrings(
        "{\"name\":\"zig-ab\",\"token\":\"registration-secret\",\"version\":\"0.1.0\",\"labels\":[\"linux\",\"zig\"]}",
        seen.body,
    );
}

test "Declare and FetchTask carry the runner's uuid and token" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.reply("Declare", "200 OK", registered);
    try s.reply("FetchTask", "200 OK", "{\"tasksVersion\":\"4\"}");
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    var c = testClient(&s, &buf);
    c.uuid = "uuid-7";
    c.token = "runner-token-7";
    var failure: Failure = .{};
    const io = std.testing.io;
    _ = try c.declare(arena, io, .{ .version = "0.1.0", .labels = &.{"zig"}, .capabilities = &.{"cancelling"} }, &failure);
    const f = try c.fetchTask(arena, io, 3, &failure);
    try std.testing.expectEqual(@as(?Task, null), f.task);
    try std.testing.expectEqual(@as(i64, 4), f.tasks_version);

    for ([_][]const u8{ "Declare", "FetchTask" }) |m| {
        const seen = s.nth(m, 0);
        try std.testing.expectEqualStrings("uuid-7", seen.uuid);
        try std.testing.expectEqualStrings("runner-token-7", seen.token);
    }
    try std.testing.expectEqualStrings(
        "{\"version\":\"0.1.0\",\"labels\":[\"zig\"],\"capabilities\":[\"cancelling\"]}",
        s.nth("Declare", 0).body,
    );
    // The version is an int64, so a string; zero is left out.
    try std.testing.expectEqualStrings("{\"tasksVersion\":\"3\"}", s.nth("FetchTask", 0).body);
}

test "FetchTask with a task answers it typed, and sends no version the first time" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.reply("FetchTask", "200 OK", @embedFile("testdata/fetch-task.json"));
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    var failure: Failure = .{};
    const f = try testClient(&s, &buf).fetchTask(arena, std.testing.io, 0, &failure);
    try std.testing.expectEqual(@as(i64, 1), f.task.?.id);
    try std.testing.expectEqual(@as(i64, 1), f.tasks_version);
    try std.testing.expectEqualStrings("{}", s.nth("FetchTask", 0).body);
}

test "a 401 and Connect's unauthenticated are the instance not knowing the runner" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.reply("FetchTask", "401 Unauthorized", "{\"code\":\"unauthenticated\",\"message\":\"unregistered runner\"}");
    try s.reply("FetchTask", "401 Unauthorized", "not json");
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    const c = testClient(&s, &buf);
    var failure: Failure = .{};
    try std.testing.expectError(error.Unauthenticated, c.fetchTask(arena, std.testing.io, 0, &failure));
    try std.testing.expectEqual(std.http.Status.unauthorized, failure.status);
    try std.testing.expectEqualStrings("unauthenticated", failure.code);
    try std.testing.expectEqualStrings("unregistered runner", failure.message);
    // A refusal that is not Connect's still says what it was.
    try std.testing.expectError(error.Unauthenticated, c.fetchTask(arena, std.testing.io, 0, &failure));
    try std.testing.expectEqualStrings("not json", failure.message);
}

test "other refusals are Rejected, with Connect's code and message" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.reply("Register", "400 Bad Request", "{\"code\":\"invalid_argument\",\"message\":\"runner registration token is invalid\"}");
    // No FetchTask queued: an instance without Actions answers 404 for it.
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    const c = testClient(&s, &buf);
    var failure: Failure = .{};
    try std.testing.expectError(error.Rejected, c.register(arena, std.testing.io, .{
        .name = "n",
        .token = "t",
        .version = "v",
        .labels = &.{},
    }, &failure));
    try std.testing.expectEqualStrings("invalid_argument", failure.code);
    try std.testing.expectEqualStrings("runner registration token is invalid", failure.message);
    try std.testing.expectError(error.Rejected, c.fetchTask(arena, std.testing.io, 0, &failure));
    try std.testing.expectEqual(std.http.Status.not_found, failure.status);
    try std.testing.expectEqualStrings("unimplemented", failure.code);
}

test "an answer that is not the method's is a BadResponse, not a crash" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.reply("Register", "200 OK", "{\"runner\":{\"id\":\"7\"}}"); // no credentials
    try s.reply("Declare", "200 OK", "<html>proxy</html>");
    try s.reply("FetchTask", "200 OK", "{\"task\":{\"id\":\"5\",\"workflowPayload\":\"***\"}}");
    try s.reply("FetchTask", "200 OK", "{\"tasksVersion\":[1]}");
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    const c = testClient(&s, &buf);
    const io = std.testing.io;
    var failure: Failure = .{};
    try std.testing.expectError(error.BadResponse, c.register(arena, io, .{ .name = "n", .token = "t", .version = "v", .labels = &.{} }, &failure));
    try std.testing.expectError(error.BadResponse, c.declare(arena, io, .{ .version = "v", .labels = &.{} }, &failure));
    try std.testing.expectError(error.BadResponse, c.fetchTask(arena, io, 0, &failure));
    try std.testing.expectError(error.BadResponse, c.fetchTask(arena, io, 0, &failure));
}

test "a call that is never answered times out instead of hanging" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.replySilence("FetchTask");
    try s.replySilence("FetchTask");
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    var c = testClient(&s, &buf);
    c.deadline = .fromMilliseconds(200);
    var failure: Failure = .{};
    try std.testing.expectError(error.Timeout, c.fetchTask(arena, std.testing.io, 0, &failure));
}

test "Forgejo is sent no capabilities, and an answer with additional tasks is counted" {
    var s: testserver.Server = undefined;
    try s.start();
    defer s.stop();
    try s.reply("Register", "200 OK", registered);
    try s.reply("Declare", "200 OK", registered);
    try s.reply("FetchTask", "200 OK", @embedFile("testdata/fetch-task-forgejo.json"));
    try s.reply("FetchTask", "200 OK", "{\"task\":{\"id\":\"2\",\"workflowPayload\":\"am9iczoge30K\"},\"additionalTasks\":[{\"id\":\"3\",\"workflowPayload\":\"am9iczoge30K\"}],\"tasksVersion\":\"9\"}");
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: [64]u8 = undefined;
    var c = testClient(&s, &buf);
    c.flavor = .forgejo;
    const io = std.testing.io;
    var failure: Failure = .{};
    _ = try c.register(arena, io, .{ .name = "n", .token = "t", .version = "v", .labels = &.{"zig"}, .capabilities = &.{"cancelling"} }, &failure);
    _ = try c.declare(arena, io, .{ .version = "v", .labels = &.{"zig"}, .capabilities = &.{"cancelling"} }, &failure);
    try std.testing.expect(std.mem.indexOf(u8, s.nth("Register", 0).body, "capabilities") == null);
    try std.testing.expect(std.mem.indexOf(u8, s.nth("Declare", 0).body, "capabilities") == null);

    const f = try c.fetchTask(arena, io, 0, &failure);
    try std.testing.expect(f.task != null);
    try std.testing.expectEqual(@as(usize, 0), f.additional);
    // The payload is Forgejo's: 4-space indents and "on".
    try std.testing.expect(std.mem.indexOf(u8, f.task.?.workflow, "jobs:") != null);
    try std.testing.expect(f.task.?.context.object.get("job_name") != null);
    try std.testing.expect(f.task.?.context.object.get("workflow_sha") == null);
    const g = try c.fetchTask(arena, io, 0, &failure);
    try std.testing.expectEqual(@as(usize, 1), g.additional);
    try std.testing.expectEqual(@as(i64, 9), g.tasks_version);
    // taskCapacity is never sent.
    try std.testing.expect(std.mem.indexOf(u8, s.nth("FetchTask", 0).body, "taskCapacity") == null);
}
