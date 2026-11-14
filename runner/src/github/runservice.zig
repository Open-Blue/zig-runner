//! Run service calls for the v2 flow: acknowledge, acquirejob, renewjob, completejob.
//! The URL comes from the broker's `RunnerJobRequest` message. Request shapes are from the
//! `actions/runner` source; live findings are recorded in SPEC §3.
const std = @import("std");
const broker = @import("broker.zig");
const EnvVar = @import("../job.zig").EnvVar;

const Allocator = std.mem.Allocator;

pub const api_version = "2024-11-01";

/// The JSON document nested in the `body` string of a `RunnerJobRequest` message.
pub const JobRequest = struct {
    runner_request_id: []const u8,
    run_service_url: []const u8,
    billing_owner_id: []const u8 = "",
    should_acknowledge: bool = false,
};

pub fn parseJobRequest(arena: Allocator, body: []const u8) !JobRequest {
    return std.json.parseFromSliceLeaky(
        JobRequest,
        arena,
        body,
        .{ .ignore_unknown_fields = true },
    );
}

/// What each call does when it arrives twice, which decides its `broker.Resend`. actions/runner's
/// own `RunServer` retries `acquirejob`, `renewjob` and `completejob` on any failure but a 404 (and
/// 409/422 for acquire, 401 for complete), with the same body: they are keyed by the job message id
/// or by plan and job id, and a repeat is answered the same, or refused (409, 404), never done twice
/// (actions/runner `src/Runner.Common/RunServer.cs`, `src/Sdk/RSWebApi/RunServiceHttpClient.cs`,
/// read 2026-11-14; the server's side is not public, so this is the client's evidence). Nothing
/// there retries `acknowledge`, and nothing shows it deduplicated: never resent.
pub fn endpoint(arena: Allocator, req: JobRequest, op: []const u8) Allocator.Error![]const u8 {
    const base = std.mem.trimEnd(u8, req.run_service_url, "/");
    return std.fmt.allocPrint(arena, "{s}/{s}?api-version={s}", .{ base, op, api_version });
}

fn post(
    arena: Allocator,
    io: std.Io,
    req: JobRequest,
    token: []const u8,
    op: []const u8,
    body: []const u8,
    resend: broker.Resend,
) !broker.Response {
    return broker.call(arena, io, .POST, try endpoint(arena, req, op), token, body, resend);
}

pub fn acknowledge(
    arena: Allocator,
    io: std.Io,
    req: JobRequest,
    token: []const u8,
) !broker.Response {
    const body = try std.fmt.allocPrint(
        arena,
        "{{\"runnerRequestId\":\"{s}\"}}",
        .{req.runner_request_id},
    );
    return post(arena, io, req, token, "acknowledge", body, .never);
}

/// Returns the job definition (steps, contexts, variables, tokens). Treat the body as secret.
pub fn acquire(arena: Allocator, io: std.Io, req: JobRequest, token: []const u8) !broker.Response {
    const body = try std.fmt.allocPrint(
        arena,
        "{{\"jobMessageId\":\"{s}\",\"runnerOS\":\"Linux\",\"billingOwnerId\":\"{s}\"}}",
        .{ req.runner_request_id, req.billing_owner_id },
    );
    return post(arena, io, req, token, "acquirejob", body, .once_more);
}

/// Renews the runner's hold on the job, as actions/runner does every 60 s while a job runs (its
/// RenewJobRequest). Returns `{lockedUntil, ...}`.
pub fn renew(
    arena: Allocator,
    io: std.Io,
    req: JobRequest,
    token: []const u8,
    plan_id: []const u8,
    job_id: []const u8,
) !broker.Response {
    const body = try std.fmt.allocPrint(
        arena,
        "{{\"planId\":\"{s}\",\"jobId\":\"{s}\"}}",
        .{ plan_id, job_id },
    );
    return post(arena, io, req, token, "renewjob", body, .once_more);
}

/// As the run service spells them (the .NET TaskResult names): "cancelled" is rejected with 400.
pub const Conclusion = enum { succeeded, failed, canceled };

pub fn complete(
    arena: Allocator,
    io: std.Io,
    req: JobRequest,
    token: []const u8,
    plan_id: []const u8,
    job_id: []const u8,
    conclusion: Conclusion,
    /// JSON array of step results (see `upload.stepResultsJson`).
    step_results: []const u8,
    /// The job's outputs, read by later jobs as `needs.<job>.outputs.<name>`.
    outputs: []const EnvVar,
    /// JSON array of annotations (see `upload.annotationsJson`).
    annotations: []const u8,
    /// The evaluated `environment.url`, the deployment's link; left out when null, as GitHub's
    /// runner leaves it out (`CompleteJobRequest.EnvironmentUrl`, `EmitDefaultValue = false`).
    environment_url: ?[]const u8,
) !broker.Response {
    // Outputs as the runner sends them: name -> {value, isSecret} (actions/runner's VariableValue).
    var out_json: std.Io.Writer.Allocating = .init(arena);
    const w = &out_json.writer;
    try w.writeByte('{');
    for (outputs, 0..) |o, i| {
        if (i > 0) try w.writeByte(',');
        try std.json.Stringify.value(o.name, .{}, w);
        try w.writeAll(":{\"value\":");
        try std.json.Stringify.value(o.value, .{}, w);
        try w.writeAll(",\"isSecret\":false}");
    }
    try w.writeByte('}');
    const outputs_json = out_json.written();
    const body = try std.fmt.allocPrint(
        arena,
        "{{\"planId\":\"{s}\",\"jobId\":\"{s}\",\"conclusion\":\"{s}\",\"outputs\":{s}," ++
            "\"stepResults\":{s},\"annotations\":{s}{s},\"telemetry\":[]}}",
        .{
            plan_id,
            job_id,
            @tagName(conclusion),
            outputs_json,
            step_results,
            annotations,
            try environmentUrlField(arena, environment_url),
        },
    );
    return post(arena, io, req, token, "completejob", body, .once_more);
}

/// `,"environmentUrl":"<url>"` for completejob's body, or nothing without a url.
fn environmentUrlField(arena: Allocator, url: ?[]const u8) ![]const u8 {
    const u = url orelse return "";
    var out: std.Io.Writer.Allocating = .init(arena);
    try out.writer.writeAll(",\"environmentUrl\":");
    try std.json.Stringify.value(u, .{}, &out.writer);
    return out.written();
}

test "completejob's environmentUrl: JSON-quoted, and absent without a url" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const field = try environmentUrlField(a.allocator(), "https://x.test/?q=\"a\"");
    try std.testing.expectEqualStrings(",\"environmentUrl\":\"https://x.test/?q=\\\"a\\\"\"", field);
    try std.testing.expectEqualStrings("", try environmentUrlField(a.allocator(), null));
}

test "parse nested job request and build endpoint" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const r = try parseJobRequest(a.allocator(), "{\"runner_request_id\":\"abc\",\"run_service_url\":\"https://r.test/\",\"billing_owner_id\":\"U_1\",\"should_acknowledge\":true}");
    try std.testing.expect(r.should_acknowledge);
    try std.testing.expectEqualStrings("https://r.test/acquirejob?api-version=2024-11-01", try endpoint(a.allocator(), r, "acquirejob"));
}
