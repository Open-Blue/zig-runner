//! What the processes of an API build say to one another (#448), as bounded, validated frames. The
//! planner (`native-parse`, unprivileged, confined) handles the client's bytes (the tar, the
//! Dockerfile) and writes a **plan**; the executor (`native-build`, privileged) reads it as hostile
//! input: a frame is a magic, a length and JSON, parsed into a fixed type (no unknown field, no
//! duplicate key), and every number, count, length, string and path checked here before anything of
//! it is acted on (`validate`). The plan carries no keys (`dockerfile.rekeyApi` makes them) and
//! no paths of the host: a base image is a placeholder `/base/<n>` the executor resolves itself.

const std = @import("std");
const dockerfile = @import("dockerfile.zig");
const images = @import("images.zig");

const Allocator = std.mem.Allocator;

pub const magic = "ZRP1";
/// A frame's whole size, header included, and a plan's parts.
pub const max_frame = 8 << 20;
pub const max_stages = 128;
pub const max_steps = 4096;
pub const max_total_steps = 16384;
pub const max_string = 64 * 1024;
pub const max_words = 512;
pub const max_env = 2048;
pub const max_sources = 4096;
pub const max_inline_total = 4 << 20;
pub const max_bases = 64;
pub const max_path = 4096;
pub const max_labels = 256;

/// What the executor asks of the planner, in `/plan/request.json` (the executor's own: trusted, but
/// parsed typed all the same).
pub const Request = struct {
    dockerfile: []const u8,
    build_args: []const Pair = &.{},
    labels: []const Pair = &.{},
    target: []const u8 = "",
    /// The bases the executor has resolved so far, in the order of `/base/<n>`.
    bases: []const Base = &.{},

    pub const Pair = struct { name: []const u8, value: []const u8 };
    pub const Base = struct {
        ref: []const u8,
        config: images.Image,
        /// An image the job's own Docker API built: `COPY --from` it is refused.
        local: bool = false,
        /// Why the executor could not have it (a pull that failed): the planner refuses the line
        /// that asks for it with this.
        missing: []const u8 = "",
    };
};

/// What the planner writes.
pub const Out = struct {
    status: Status,
    plan: ?dockerfile.Plan = null,
    /// The image references the plan needs and the request did not have (`status` = `need`).
    need: []const []const u8 = &.{},
    /// A Dockerfile or a context that cannot be built, and why (`refused`, `failed`).
    line: u32 = 0,
    why: []const u8 = "",
    /// The Dockerfile's instructions, for the build's progress lines (`Step 3/7 : RUN ...`).
    ins: []const Ins = &.{},

    pub const Status = enum { plan, need, refused, failed };
};

pub const Ins = struct { line: u32, kind: dockerfile.Kind, text: []const u8 };

pub const Error = error{ BadFrame, TooBig, Invalid } || Allocator.Error;

/// `Out` as a frame.
pub fn encode(arena: Allocator, out: Out) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    try w.writer.writeAll(magic);
    try w.writer.writeAll("\x00\x00\x00\x00");
    try std.json.Stringify.value(out, .{}, &w.writer);
    const all = w.written();
    if (all.len > max_frame) return error.TooBig;
    std.mem.writeInt(u32, all[magic.len..][0..4], std.math.lossyCast(u32, all.len - magic.len - 4), .little);
    return all;
}

/// The JSON of the frame `bytes`: its magic and its length checked against what there is.
pub fn payload(bytes: []const u8) Error![]const u8 {
    if (bytes.len > max_frame) return error.TooBig;
    if (bytes.len < magic.len + 4 or !std.mem.eql(u8, bytes[0..magic.len], magic)) return error.BadFrame;
    const n = std.mem.readInt(u32, bytes[magic.len..][0..4], .little);
    if (n != bytes.len - magic.len - 4) return error.BadFrame;
    return bytes[magic.len + 4 ..];
}

/// A frame read as `Out` and validated: the reason, in `why`, when it is not.
pub fn decode(arena: Allocator, bytes: []const u8, why: *[]const u8) Error!Out {
    const json = try payload(bytes);
    const out = std.json.parseFromSliceLeaky(Out, arena, json, .{
        .ignore_unknown_fields = false,
        .duplicate_field_behavior = .@"error",
        .allocate = .alloc_always,
        .max_value_len = max_string,
    }) catch |e| {
        why.* = switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => "the planner's frame is not what a plan is",
        };
        return error.Invalid;
    };
    if (validate(out)) |reason| {
        why.* = reason;
        return error.Invalid;
    }
    return out;
}

fn text(s: []const u8, max: usize) bool {
    return s.len <= max and std.unicode.utf8ValidateSlice(s) and std.mem.indexOfScalar(u8, s, 0) == null;
}

fn isBase(path: []const u8) ?usize {
    const prefix = "/base/";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const n = std.fmt.parseInt(usize, path[prefix.len..], 10) catch return null;
    // Written the way the executor writes it.
    var buf: [24]u8 = undefined;
    const want = std.fmt.bufPrint(&buf, "/base/{d}", .{n}) catch return null;
    if (!std.mem.eql(u8, want, path) or n >= max_bases) return null;
    return n;
}

fn relPath(path: []const u8) bool {
    if (!text(path, max_path) or path.len == 0 or path[0] == '/') return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |c| if (std.mem.eql(u8, c, "..")) return false;
    return true;
}

fn url(u: []const u8) bool {
    if (!text(u, max_path)) return false;
    if (!(std.mem.startsWith(u8, u, "http://") or std.mem.startsWith(u8, u, "https://"))) return false;
    for (u) |c| if (c <= ' ' or c == 127) return false;
    return true;
}

fn imageRef(ref: []const u8) bool {
    if (!text(ref, 512) or ref.len == 0) return false;
    for (ref) |c| if (c <= ' ' or c == 127) return false;
    return true;
}

fn strings(list: []const []const u8, max_count: usize, max_each: usize, max_all: usize) bool {
    if (list.len > max_count) return false;
    var all: usize = 0;
    for (list) |s| {
        if (!text(s, max_each)) return false;
        all += s.len;
    }
    return all <= max_all;
}

/// A stage that starts from a job's own image carries the planner's `/local` marker; no other layer.
fn localOnly(layers: []const []const u8) bool {
    return layers.len == 0 or (layers.len == 1 and std.mem.eql(u8, layers[0], "/local"));
}

fn config(c: images.Image) bool {
    if (c.rootfs.len != 0) return false;
    if (!strings(c.entrypoint, max_words, max_string, 256 * 1024)) return false;
    if (!strings(c.cmd, max_words, max_string, 256 * 1024)) return false;
    if (!strings(c.env, max_env, max_string, 1 << 20)) return false;
    for (c.env) |kv| if (std.mem.indexOfScalar(u8, kv, '=') == null) return false;
    if (!text(c.workdir, max_path) or !text(c.user, 256)) return false;
    if (c.labels.len > max_labels) return false;
    for (c.labels) |l| if (!text(l.name, 1024) or !text(l.value, max_string)) return false;
    // Nothing a plan has no use for.
    return c.healthcheck == null and c.digest == null and c.manifest == null and localOnly(c.layers);
}

/// Why `out` is not a plan this side acts on, or null. Everything is bounded and written as the
/// executor writes it: a placeholder base is `/base/<n>`, a source relative with no `..`, a URL
/// http(s), a reference without a space; counts and lengths are capped; a stage refers only to an
/// earlier stage; the final stage is one that is built.
pub fn validate(out: Out) ?[]const u8 {
    switch (out.status) {
        .plan => {},
        .need => {
            if (out.plan != null) return "a request for bases has a plan";
            if (out.need.len > max_bases) return "the planner wants too many bases";
            for (out.need) |r| if (!imageRef(r)) return "the planner names a reference that is no reference";
            return null;
        },
        .refused, .failed => {
            if (out.plan != null) return "a refusal has a plan";
            if (!text(out.why, 4096)) return "a refusal's reason is not text";
            return null;
        },
    }
    const p = out.plan orelse return "a plan with no plan";
    if (out.ins.len > max_total_steps * 2) return "the plan has too many instructions";
    var ins_bytes: usize = 0;
    for (out.ins) |x| {
        if (!text(x.text, max_string)) return "an instruction is not text";
        ins_bytes += x.text.len;
    }
    if (ins_bytes > (1 << 20) + max_total_steps) return "the instructions are too big";
    if (p.stages.len == 0 or p.stages.len > max_stages) return "a plan with no stages or too many";
    if (p.final >= p.stages.len or !p.stages[p.final].needed) return "the plan's final stage is not built";
    var total: usize = 0;
    var inline_total: usize = 0;
    for (p.stages, 0..) |st, i| {
        if (!text(st.name, 256)) return "a stage name is not text";
        if (!st.needed) {
            if (st.steps.len != 0) return "a stage that is not built has steps";
            continue;
        }
        switch (st.base) {
            .scratch => {},
            .stage => |d| if (d >= i or !p.stages[d].needed) return "a stage starts from a stage that is not before it",
            .image => |im| {
                if (!imageRef(im.ref)) return "a base's reference is not a reference";
                if (isBase(im.rootfs) == null) return "a base is not a placeholder";
                if (!localOnly(im.layers)) return "a base has layers of its own";
            },
        }
        if (!config(st.config)) return "a stage's config is not one";
        if (!strings(st.shell, 16, 1024, 8192)) return "a stage's shell is not one";
        if (st.steps.len > max_steps) return "a stage has too many steps";
        total += st.steps.len;
        if (total > max_total_steps) return "a plan has too many steps";
        for (st.steps) |step| {
            if (step.line > (1 << 20) or !text(step.evaluated, max_string)) return "a step is malformed";
            if (step.kind == .from) return "a step that is a FROM";
            switch (step.op) {
                .none => {},
                .run => |r| {
                    if (r.argv.len == 0 or !strings(r.argv, max_words, max_string, 256 * 1024)) return "a RUN's command is not one";
                    if (!strings(r.env, max_env, max_string, 1 << 20)) return "a RUN's env is not one";
                    for (r.env) |kv| if (std.mem.indexOfScalar(u8, kv, '=') == null) return "a RUN's env has an entry that is no assignment";
                    if (!text(r.workdir, max_path) or !text(r.user, 256)) return "a RUN's directory or user is not text";
                },
                .mkdir => |m| if (!text(m.path, max_path) or m.path.len == 0 or m.path[0] != '/' or !text(m.user, 256)) return "a WORKDIR is malformed",
                .copy => |c| {
                    if (!text(c.dest, max_path) or c.dest.len == 0 or c.dest[0] != '/') return "a COPY's destination is not absolute";
                    if (!text(c.chown, 256)) return "a COPY's owner is not text";
                    if (c.chmod) |m| if (m > 0o7777) return "a COPY's mode is not a mode";
                    if (c.sources.len == 0 or c.sources.len > max_sources) return "a COPY has no sources or too many";
                    switch (c.from) {
                        .context => {},
                        .stage => |d| if (d >= i or !p.stages[d].needed) return "a COPY --from a stage that is not before it",
                        .rootfs => |r| if (isBase(r) == null) return "a COPY --from an image that is not a placeholder",
                    }
                    for (c.sources) |src| switch (src) {
                        .path => |pth| if (c.from == .context) {
                            if (!relPath(pth) and !std.mem.eql(u8, pth, ".")) return "a COPY source outside the context";
                        } else if (!text(pth, max_path)) return "a COPY source is not text",
                        .inline_file => |f| {
                            if (!text(f.name, 256) or std.mem.indexOfScalar(u8, f.name, '/') != null) return "an inline file's name is malformed";
                            if (!std.unicode.utf8ValidateSlice(f.content)) return "an inline file is not text";
                            inline_total += f.content.len;
                            if (inline_total > max_inline_total) return "the plan's inline files are too big";
                        },
                        .url => |u| {
                            if (!url(u.url)) return "an ADD URL is not an http(s) URL";
                            if (u.file.len != 0) return "an ADD's file is the executor's to name";
                            if (!text(u.name, 256) or std.mem.indexOfScalar(u8, u.name, '/') != null) return "an ADD's name is malformed";
                        },
                    };
                },
            }
        }
    }
    return null;
}

// --- tests ---

const testing = std.testing;

fn okPlan(arena: Allocator) !Out {
    const steps = try arena.dupe(dockerfile.Step, &.{
        .{ .key = @splat('0'), .line = 2, .kind = .copy, .evaluated = "a /a", .op = .{ .copy = .{
            .from = .context,
            .sources = &.{.{ .path = "a.txt" }},
            .dest = "/a",
            .chown = "",
            .chmod = null,
        } } },
        .{ .key = @splat('0'), .line = 3, .kind = .run, .evaluated = "echo hi", .op = .{ .run = .{
            .argv = &.{ "/bin/sh", "-c", "echo hi" },
            .env = &.{"A=1"},
            .workdir = "/",
            .user = "",
        } } },
    });
    const stages = try arena.dupe(dockerfile.Stage, &.{.{
        .name = "",
        .base = .{ .image = .{ .ref = "alpine:3", .rootfs = "/base/0" } },
        .steps = steps,
        .config = .{ .rootfs = "", .env = &.{"PATH=/bin"} },
        .key = @splat('0'),
        .shell = &.{ "/bin/sh", "-c" },
        .needed = true,
    }});
    return .{ .status = .plan, .plan = .{ .stages = stages, .final = 0 } };
}

fn expectInvalid(arena: Allocator, out: Out, want: []const u8) !void {
    const reason = validate(out) orelse {
        std.debug.print("ERROR accepted, want: {s}\n", .{want});
        return error.TestUnexpectedResult;
    };
    _ = arena;
    try testing.expect(std.mem.indexOf(u8, reason, want) != null);
}

test "build frames: a plan makes the round trip and is valid" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const out = try okPlan(arena);
    try testing.expect(validate(out) == null);
    const bytes = try encode(arena, out);
    var why: []const u8 = "";
    const back = try decode(arena, bytes, &why);
    try testing.expectEqual(@as(usize, 1), back.plan.?.stages.len);
    try testing.expectEqualStrings("echo hi", back.plan.?.stages[0].steps[1].evaluated);
    // The statuses without a plan.
    const need = try encode(arena, .{ .status = .need, .need = &.{ "alpine:3", "busybox" } });
    try testing.expectEqual(@as(usize, 2), (try decode(arena, need, &why)).need.len);
    const refused = try encode(arena, .{ .status = .refused, .line = 3, .why = "RUN --mount is not native yet" });
    try testing.expectEqual(@as(u32, 3), (try decode(arena, refused, &why)).line);
}

test "build frames: a frame that is cut, grown, unmarked, unknown or duplicated is refused" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const good = try encode(arena, try okPlan(arena));
    var why: []const u8 = "";
    try testing.expectError(error.BadFrame, decode(arena, good[0 .. good.len - 3], &why));
    try testing.expectError(error.BadFrame, decode(arena, try std.mem.concat(arena, u8, &.{ good, "x" }), &why));
    try testing.expectError(error.BadFrame, decode(arena, "ZRP2\x00\x00\x00\x00", &why));
    try testing.expectError(error.BadFrame, decode(arena, "", &why));
    const huge = try arena.alloc(u8, max_frame + 1);
    try testing.expectError(error.TooBig, decode(arena, huge, &why));
    // An unknown field, a duplicate one, a wrong type, a depth of nesting that is not the type's.
    for ([_][]const u8{
        "{\"status\":\"failed\",\"why\":\"x\",\"extra\":1}",
        "{\"status\":\"failed\",\"why\":\"x\",\"why\":\"y\"}",
        "{\"status\":\"nope\"}",
        "{\"status\":\"failed\",\"line\":-1}",
        "{\"status\":\"need\",\"need\":[[[[[[]]]]]]}",
        "[]",
        "{\"status\":\"failed\",\"why\":\"x\"} trailing",
    }) |json| {
        const framed = try std.mem.concat(arena, u8, &.{ magic, &std.mem.toBytes(@as(u32, std.math.lossyCast(u32, json.len))), json });
        testing.expectError(error.Invalid, decode(arena, framed, &why)) catch |e| {
            std.debug.print("ERROR accepted: {s}\n", .{json});
            return e;
        };
    }
}

test "build frames: what a plan may not hold is refused with its reason" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const base = try okPlan(arena);
    // A base that is a host path, not a placeholder.
    {
        var o = base;
        const stages = try arena.dupe(dockerfile.Stage, base.plan.?.stages);
        stages[0].base = .{ .image = .{ .ref = "alpine", .rootfs = "/etc" } };
        o.plan = .{ .stages = stages, .final = 0 };
        try expectInvalid(arena, o, "placeholder");
        stages[0].base = .{ .image = .{ .ref = "alpine", .rootfs = "/base/07" } };
        try expectInvalid(arena, o, "placeholder");
        stages[0].base = .{ .image = .{ .ref = "al pine", .rootfs = "/base/0" } };
        try expectInvalid(arena, o, "reference");
    }
    // A source outside the context, an absolute one, a URL that is not http(s), a file the planner named.
    const Case = struct { src: dockerfile.Source, want: []const u8 };
    const cases = [_]Case{
        .{ .src = .{ .path = "../etc/passwd" }, .want = "outside the context" },
        .{ .src = .{ .path = "a/../../x" }, .want = "outside the context" },
        .{ .src = .{ .path = "/etc/passwd" }, .want = "outside the context" },
        .{ .src = .{ .path = "a\x00b" }, .want = "outside the context" },
        .{ .src = .{ .url = .{ .url = "file:///etc/passwd", .file = "", .name = "x" } }, .want = "http(s)" },
        .{ .src = .{ .url = .{ .url = "http://a b/", .file = "", .name = "x" } }, .want = "http(s)" },
        .{ .src = .{ .url = .{ .url = "http://a/x", .file = "/etc/shadow", .name = "x" } }, .want = "executor's to name" },
        .{ .src = .{ .inline_file = .{ .name = "../x", .content = "" } }, .want = "inline file" },
    };
    for (cases) |c| {
        var o = base;
        const stages = try arena.dupe(dockerfile.Stage, base.plan.?.stages);
        const steps = try arena.dupe(dockerfile.Step, stages[0].steps);
        var cp = steps[0].op.copy;
        cp.sources = try arena.dupe(dockerfile.Source, &.{c.src});
        steps[0].op = .{ .copy = cp };
        stages[0].steps = steps;
        o.plan = .{ .stages = stages, .final = 0 };
        try expectInvalid(arena, o, c.want);
    }
    // Counts, text and structure.
    {
        var o = base;
        const stages = try arena.dupe(dockerfile.Stage, base.plan.?.stages);
        const steps = try arena.dupe(dockerfile.Step, stages[0].steps);
        steps[1].op.run.argv = &.{};
        stages[0].steps = steps;
        o.plan = .{ .stages = stages, .final = 0 };
        try expectInvalid(arena, o, "command");
        steps[1].op.run.argv = &.{"\xff\xfe"};
        try expectInvalid(arena, o, "command");
        steps[1].op.run.argv = &.{"sh"};
        steps[1].op.run.env = &.{"NOEQUALS"};
        try expectInvalid(arena, o, "assignment");
        steps[1].op.run.env = &.{};
        steps[1].kind = .from;
        try expectInvalid(arena, o, "FROM");
        steps[1].kind = .run;
        o.plan = .{ .stages = stages, .final = 3 };
        try expectInvalid(arena, o, "final");
    }
    {
        // A stage that starts from a later one, and a COPY --from a stage not yet built.
        var o = base;
        const stages = try arena.dupe(dockerfile.Stage, base.plan.?.stages);
        stages[0].base = .{ .stage = 0 };
        o.plan = .{ .stages = stages, .final = 0 };
        try expectInvalid(arena, o, "before it");
    }
    {
        var o = base;
        const stages = try arena.alloc(dockerfile.Stage, max_stages + 1);
        @memset(stages, base.plan.?.stages[0]);
        o.plan = .{ .stages = stages, .final = 0 };
        try expectInvalid(arena, o, "too many");
    }
    // A bound on a base's own config: a layer list, a rootfs path, a health check.
    {
        var o = base;
        const stages = try arena.dupe(dockerfile.Stage, base.plan.?.stages);
        stages[0].config.rootfs = "/host/path";
        o.plan = .{ .stages = stages, .final = 0 };
        try expectInvalid(arena, o, "config");
    }
}
