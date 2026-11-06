//! Fakes and fixtures shared by the tests of `dagger.zig` and the files split out of it: a
//! scripted Dagger session (`FakeSession`), the answers it gives, and the steps and jobs the tests
//! run.

const std = @import("std");
const job_mod = @import("../job.zig");
const Transport = @import("../dagger.zig").Transport;

const Allocator = std.mem.Allocator;

pub fn testStep(script: []const u8) job_mod.Step {
    return .{
        .id = "x",
        .name = "n",
        .condition = "success()",
        .action = .{ .script = .{
            .script = .{ .lit = script },
            .shell = null,
            .working_directory = null,
        } },
    };
}

pub fn testJob(steps: []const job_mod.Step) job_mod.Job {
    return .{
        .plan_id = "p",
        .job_id = "j",
        .job_token = "t",
        .check_run_id = 1,

        .secrets = &.{},
        .github = .{
            .repository = "o/r",
            .sha = "0123456789012345678901234567890123456789",
            .ref = "refs/heads/x",
        },
        .steps = steps,
    };
}

/// Every document in `seen` carries `secret` only as a `setSecret` value: not in an exec's args,
/// its key or anything else the engine keeps (#101).
pub fn expectSecretOnlyInSetSecret(seen: []const []const u8, secret: []const u8) !void {
    for (seen) |d| {
        var rest = d;
        while (std.mem.indexOf(u8, rest, secret)) |at| : (rest = rest[at + secret.len ..]) {
            const before = rest[0..at];
            const call = std.mem.lastIndexOf(u8, before, "setSecret(name:") orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(std.mem.indexOfScalar(u8, before[call..], ')') == null);
        }
    }
}

pub fn braceBalanced(doc: []const u8) bool {
    var depth: i32 = 0;
    var in_str = false;
    var i: usize = 0;
    while (i < doc.len) : (i += 1) {
        const c = doc[i];
        if (in_str) {
            if (c == '\\') i += 1 else if (c == '"') in_str = false;
        } else switch (c) {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth < 0) return false;
            },
            else => {},
        }
    }
    return depth == 0 and !in_str;
}

/// A scripted stand-in for the Dagger session: answers queries in order and records them.
pub const FakeSession = struct {
    answers: []const []const u8,
    next: usize = 0,
    seen: std.ArrayList([]const u8) = .empty,
    arena: Allocator,

    fn send(ptr: *anyopaque, _: Allocator, doc: []const u8, limit: usize) anyerror![]const u8 {
        const self: *FakeSession = @ptrCast(@alignCast(ptr));
        try self.seen.append(self.arena, try self.arena.dupe(u8, doc));
        defer self.next += 1;
        if (self.next >= self.answers.len) return error.NoMoreAnswers;
        if (self.answers[self.next].len > limit) return error.ResponseTooLarge;
        return self.answers[self.next];
    }

    pub fn transport(self: *FakeSession) Transport {
        return .{ .ptr = self, .sendFn = send };
    }
};

/// A session child that logs nothing: closing its stderr ends the log stream at once, so no step
/// waits out `live_grace_ms` for lines that cannot come (`JobLog.stream_ended`).
pub const fake_child = "printf '0 tok\\n'; exec 2>&-; cat >/dev/null";
pub const base_answer = "{\"data\":{\"container\":{\"from\":{\"withWorkdir\":{\"id\":\"C0\"}}}}}";

pub fn exec(arena: Allocator, id: []const u8, code: i32, out: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":{{\"id\":\"{s}\"," ++
            "\"exitCode\":{d},\"stdout\":\"{s}\",\"stderr\":\"\"}}}}}}}}",
        .{ id, code, out },
    );
}

pub fn execFc(
    arena: Allocator,
    id: []const u8,
    out: []const u8,
    fc_output: []const u8,
    fc_env: []const u8,
    fc_path: []const u8,
) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"data\":{{\"loadContainerFromID\":{{\"withExec\":{{\"id\":\"{s}\"," ++
            "\"exitCode\":0,\"stdout\":\"{s}\",\"stderr\":\"\"," ++
            "\"fc_output\":{{\"contents\":\"{s}\"}}," ++
            "\"fc_env\":{{\"contents\":\"{s}\"}}," ++
            "\"fc_path\":{{\"contents\":\"{s}\"}}}}}}}}}}",
        .{ id, out, fc_output, fc_env, fc_path },
    );
}

pub fn treeAnswer(arena: Allocator, dir: []const u8, entries: []const []const u8) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    try aw.writer.print(
        "{{\"data\":{{\"git\":{{\"ref\":{{\"tree\":{{\"id\":\"{s}\",\"entries\":",
        .{dir},
    );
    try std.json.Stringify.value(entries, .{}, &aw.writer);
    try aw.writer.writeAll("}}}}}");
    return aw.written();
}

pub fn fileAnswer(arena: Allocator, contents: []const u8) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    try aw.writer.writeAll("{\"data\":{\"loadDirectoryFromID\":{\"file\":{\"contents\":");
    try std.json.Stringify.value(contents, .{}, &aw.writer);
    try aw.writer.writeAll("}}}}");
    return aw.written();
}

pub fn usesStep(
    id: []const u8,
    owner: []const u8,
    name: []const u8,
    ref: []const u8,
    inputs: []const job_mod.Input,
) job_mod.Step {
    return .{
        .id = id,
        .context_name = id,
        .name = "uses",
        .condition = "success()",
        .action = .{ .uses = .{ .owner = owner, .name = name, .ref = ref, .inputs = inputs } },
    };
}
