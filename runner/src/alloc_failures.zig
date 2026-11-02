//! Allocation-failure tests for the parsers and decoders that allocate: each runs once per
//! allocation it makes, with that allocation failing (`std.testing.checkAllAllocationFailures`),
//! and must then return `error.OutOfMemory`, having freed everything it allocated. An answer
//! instead (the failure swallowed, a wrong result returned), another error, a leak or a crash
//! fails the test. The inputs are small on purpose: the suite reruns once per allocation.
//!
//! Most of these parsers allocate from an arena the caller frees. An `ArenaAllocator` over the
//! failing allocator would hide nearly every allocation (it asks its child for a few large
//! blocks, and asks again smaller when one fails), so each run gives them a `Scratch` instead:
//! every allocation goes to the failing allocator, and whatever is still held is freed at the
//! end. What is checked there is that a failure comes back as `error.OutOfMemory`, not as an
//! answer or as some other error. The HPACK decoder frees its own memory, so its leaks are
//! checked too. image.zig, job.zig and layer.zig test their private parsers the same way.
const std = @import("std");

const expr = @import("expr.zig");
const glob = @import("glob.zig");
const hpack = @import("hpack.zig");
const loop = @import("loop.zig");
const regex = @import("regex.zig");
const runservice = @import("github/runservice.zig");
const yaml = @import("yaml.zig");
const layer = @import("native/oci/layer.zig");
const registry = @import("native/oci/registry.zig");

const Allocator = std.mem.Allocator;
const check = std.testing.checkAllAllocationFailures;
const gpa = std.testing.allocator;

/// An arena for these tests: like `std.heap.ArenaAllocator`, everything is freed at `deinit`, but
/// each allocation is its own call to `child`, so the failing allocator can fail any one of them.
/// Its bookkeeping lives in `std.testing.allocator`, outside what is counted.
pub const Scratch = struct {
    child: Allocator,
    live: std.AutoHashMapUnmanaged(usize, Held) = .empty,

    const Held = struct { len: usize, alignment: std.mem.Alignment };

    pub fn init(child: Allocator) Scratch {
        return .{ .child = child };
    }

    pub fn deinit(s: *Scratch) void {
        var it = s.live.iterator();
        while (it.next()) |e| {
            const ptr: [*]u8 = @ptrFromInt(e.key_ptr.*);
            s.child.rawFree(ptr[0..e.value_ptr.len], e.value_ptr.alignment, @returnAddress());
        }
        s.live.deinit(std.testing.allocator);
    }

    pub fn allocator(s: *Scratch) Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const s: *Scratch = @ptrCast(@alignCast(ctx));
        s.live.ensureUnusedCapacity(std.testing.allocator, 1) catch return null;
        const p = s.child.rawAlloc(len, alignment, ra) orelse return null;
        s.live.putAssumeCapacity(@intFromPtr(p), .{ .len = len, .alignment = alignment });
        return p;
    }

    /// Never in place: whether the child could grow a block in place depends on where it put
    /// it, so a run's allocations, and which one fails, would vary from run to run
    /// (`error.NondeterministicMemoryUsage`). Refused, the caller allocates anew every time.
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const s: *Scratch = @ptrCast(@alignCast(ctx));
        _ = s.live.remove(@intFromPtr(memory.ptr));
        s.child.rawFree(memory, alignment, ra);
    }
};

/// Whether `e` is one of the errors `allowed` (the input's own, which a run without a failure
/// returns too) rather than a failure that came back as something else.
fn expected(e: anyerror, comptime allowed: []const anyerror) bool {
    inline for (allowed) |a| if (e == a) return true;
    return false;
}

/// `checkAllAllocationFailures`, then `checkEachAllocationFailure`, saying which input failed.
pub fn checkOne(comptime f: anytype, args: anytype) !void {
    const fmt = if (@TypeOf(args[0]) == []const u8) "\"{s}\"" else "{any}";
    check(gpa, f, args) catch |e| {
        std.debug.print("allocation failures: failed for input " ++ fmt ++ "\n", .{args[0]});
        return e;
    };
    checkEachAllocationFailure(f, args) catch |e| {
        std.debug.print("allocation failures: one failure swallowed for input " ++ fmt ++ "\n", .{args[0]});
        return e;
    };
}

/// Fails one allocation at a time, the ones after it succeeding. `checkAllAllocationFailures`
/// fails every allocation from the chosen one on, so a failure caught and turned into an answer
/// goes unnoticed whenever anything is allocated later: that later allocation fails too, and the
/// run still ends in `error.OutOfMemory`. Memory that runs out for a moment comes back, so here
/// such a run must still end in `error.OutOfMemory`, not in an answer.
fn checkEachAllocationFailure(comptime f: anytype, args: anytype) !void {
    var n: usize = 0;
    {
        var once: FailOnce = .{ .child = gpa };
        try @call(.auto, f, .{once.allocator()} ++ args);
        n = once.count;
    }
    for (0..n) |i| {
        var once: FailOnce = .{ .child = gpa, .fail_at = i };
        if (@call(.auto, f, .{once.allocator()} ++ args)) |_| {
            if (once.failed) return error.SwallowedOutOfMemoryError;
        } else |e| if (e != error.OutOfMemory) return e;
    }
}

/// `checkAllAllocationFailures` for code that falls back when an allocation fails, on purpose:
/// an arena reset with `.retain_capacity` tries one larger block and keeps what it has when that
/// fails. Every failure from one on must end in `error.OutOfMemory` or in an answer, never in
/// another error, and with everything allocated freed.
pub fn checkNoLeaks(comptime f: anytype, args: anytype) !void {
    var n: usize = 0;
    {
        var failing: std.testing.FailingAllocator = .init(gpa, .{});
        try @call(.auto, f, .{failing.allocator()} ++ args);
        n = failing.alloc_index;
    }
    for (0..n) |i| {
        var failing: std.testing.FailingAllocator = .init(gpa, .{ .fail_index = i });
        @call(.auto, f, .{failing.allocator()} ++ args) catch |e| if (e != error.OutOfMemory) return e;
        if (failing.allocated_bytes != failing.freed_bytes) {
            std.debug.print("allocation failures: {d} bytes leaked failing allocation {d} of {d}\n", .{
                failing.allocated_bytes - failing.freed_bytes, i, n,
            });
            return error.MemoryLeakDetected;
        }
    }
}

/// Fails allocation number `fail_at`, and only that one.
const FailOnce = struct {
    child: Allocator,
    fail_at: ?usize = null,
    count: usize = 0,
    failed: bool = false,

    fn allocator(o: *FailOnce) Allocator {
        return .{ .ptr = o, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const o: *FailOnce = @ptrCast(@alignCast(ctx));
        defer o.count += 1;
        if (o.fail_at == o.count) {
            o.failed = true;
            return null;
        }
        return o.child.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const o: *FailOnce = @ptrCast(@alignCast(ctx));
        return o.child.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const o: *FailOnce = @ptrCast(@alignCast(ctx));
        return o.child.rawRemap(memory, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const o: *FailOnce = @ptrCast(@alignCast(ctx));
        o.child.rawFree(memory, alignment, ra);
    }
};

test "allocation failures: YAML" {
    const S = struct {
        fn run(a: Allocator, source: []const u8) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            var diag: yaml.Diag = .{};
            _ = yaml.parse(arena.allocator(), source, &diag) catch |e| {
                if (expected(e, &.{ error.InvalidYaml, error.UnsupportedYaml })) return;
                return e;
            };
        }
    };
    for ([_][]const u8{
        "on: push\njobs:\n  a:\n    runs-on: [self-hosted, x]\n    steps:\n      - run: |\n          echo hi\n",
        "a: &x {b: [1, {c: d}]}\ne: *x\nf: >-\n  folded\n  text\n",
        "- 'it''s'\n- \"\\u00e9\\n\"\n- ~\n? k\n: v\n",
        "a: \"one\n  two\"\nb: [x,\n  y]\n---\n",
        "a: [}]\n",
        "a:\n  b: 1\n a: 2\n",
    }) |source| try checkOne(S.run, .{source});
}

const contexts_json =
    \\{"github":{"ref":"refs/heads/main","event":{"commits":[{"id":"1"},{"id":"2"}]}},
    \\ "matrix":{"os":"a"},"steps":{"s":{"outputs":{"o":"1"}}},"env":{"A":"1"}}
;

fn testScope(arena: Allocator, diag: *[]const u8) !expr.Scope {
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, contexts_json, .{});
    return .{ .contexts = (try expr.fromJsonValue(arena, parsed)).object, .diag = diag };
}

test "allocation failures: expressions" {
    const S = struct {
        fn evaluate(a: Allocator, text: []const u8) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            var diag: []const u8 = "";
            const scope = try testScope(arena.allocator(), &diag);
            _ = expr.evalString(arena.allocator(), text, scope) catch |e| {
                if (expected(e, &.{ error.ParseError, error.EvalError })) return;
                return e;
            };
        }
        fn condition(a: Allocator, text: []const u8, job_failed: bool, want: bool) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            var diag: []const u8 = "";
            var scope = try testScope(arena.allocator(), &diag);
            scope.job_failed = job_failed;
            try std.testing.expectEqual(want, try expr.evalCondition(arena.allocator(), text, scope));
        }
        fn interpolate(a: Allocator, text: []const u8) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            var diag: []const u8 = "";
            const scope = try testScope(arena.allocator(), &diag);
            _ = expr.interpolate(arena.allocator(), text, scope) catch |e| {
                if (expected(e, &.{ error.ParseError, error.EvalError })) return;
                return e;
            };
        }
    };
    for ([_][]const u8{
        "github.event.commits.*.id",
        "contains(fromJSON('[\"a\",\"b\"]'), matrix.os) && !cancelled()",
        "format('{0}-{1}', github.ref, toJSON(steps))",
        "join(github.event.commits.*.id, ', ') == '1, 2'",
        "fromJSON('{\"n\": [1, {\"m\": true}]}').n[1].m",
        "startsWith(github.ref, 'refs/') || case(true, 1, 2)",
        // Errors, whose messages are made in the same memory.
        "fromJSON('{')",
        "format('{1}', 1)",
        "nosuch.context",
        "1 +",
    }) |text| try checkOne(S.evaluate, .{text});
    // A condition without a status function is `success() && (...)`: a failure while looking for
    // one must not run a step after a failed one.
    try checkOne(S.condition, .{ "github.ref == 'refs/heads/main'", true, false });
    try checkOne(S.condition, .{ "always() && github.ref == 'refs/heads/main'", true, true });
    try checkOne(S.condition, .{ "${{ matrix.os == 'a' }}", false, true });
    // Only the failures from one on: interpolate evaluates each expression in an arena it resets
    // with `.retain_capacity`, which tries one larger block and keeps what it has when that fails,
    // a failure swallowed on purpose.
    for ([_][]const u8{
        "a ${{ github.ref }} b ${{ format('{0}', matrix.os) }} {c}",
        "${{ toJSON(github.event) }}",
        "x ${{ fromJSON('[') }} y",
        "${{ 'unclosed'",
    }) |text| check(gpa, S.interpolate, .{text}) catch |e| {
        std.debug.print("allocation failures: failed for input \"{s}\"\n", .{text});
        return e;
    };
}

test "allocation failures: regular expressions" {
    const S = struct {
        fn run(a: Allocator, pattern: []const u8, input: []const u8) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            const re = regex.Regex.compile(arena.allocator(), pattern) catch |e| {
                // Only the last pattern below is refused.
                if (expected(e, &.{error.BadPattern}) and input.len == 0) return;
                return e;
            };
            var from: usize = 0;
            while (from <= input.len) {
                const caps = (try re.find(arena.allocator(), input, from)) orelse return;
                const whole = caps.group(0).?;
                from = if (whole.end > whole.start) whole.end else whole.end + 1;
            }
        }
    };
    for ([_][2][]const u8{
        .{ "^(?<file>[^:]+):(\\d+):(\\d+): (error|warning): (.*)$", "a.zig:3:7: error: boom" },
        .{ "(a|ab)(c|bcd)(d*)", "abcd" },
        .{ "(?:(a)|b)\\1", "aa ba" },
        .{ "(?<=\\$)\\d+(?!\\.)", "$12.5 $30" },
        .{ "[^\\]a-c-]+?x{2,3}\\b", "zzxxx yx" },
        .{ "(?(1)a|b)(x)?", "bx" },
        .{ "(?<n>x)?(?(n)a|b)", "xa b" },
        .{ "(?(?=a)ab|cd)", "ab cd" },
        .{ "(?(a+)ab|cd)", "ab cd" },
        .{ "(?>a+)b|\\p{L}+", "aab é" },
        .{ "(?i)HELLO\\s+\\w+", "hello world" },
        .{ "(unclosed", "" },
    }) |c| try checkOne(S.run, .{ c[0], c[1] });
}

test "allocation failures: HPACK" {
    const S = struct {
        fn on(n: *usize, name: []const u8, value: []const u8) void {
            n.* += name.len + value.len;
        }
        fn run(a: Allocator, blocks: []const []const u8) !void {
            var d: hpack.Decoder = .{ .gpa = a };
            defer d.deinit();
            var seen: usize = 0;
            for (blocks) |b| try d.decode(b, &seen, on);
            var arena: Scratch = .init(a);
            defer arena.deinit();
            _ = try hpack.huffmanDecode(arena.allocator(), "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff");
        }
    };
    // RFC 7541 C.3 and C.4: literals added to the dynamic table, references to them, Huffman.
    try checkOne(S.run, .{@as([]const []const u8, &.{
        "\x82\x86\x84\x41\x0fwww.example.com",
        "\x82\x86\x84\xbe\x58\x08no-cache",
        "\x82\x87\x85\xbf\x40\x0acustom-key\x0ccustom-value",
        "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
        // A table size update that evicts, then more entries.
        "\x3f\xe1\x1f\x40\x01k\x01v",
        "\x20\x40\x01k\x01v",
    })});
}

/// A small tree for the glob walk: /w holding a/x.txt, a/b/y and b.txt.
const tree = struct {
    const kinds = [_]struct { []const u8, glob.Kind }{
        .{ "/w", .directory },     .{ "/w/a", .directory }, .{ "/w/a/x.txt", .file },
        .{ "/w/a/b", .directory }, .{ "/w/a/b/y", .file },  .{ "/w/b.txt", .file },
    };
    const lists = [_]struct { []const u8, []const []const u8 }{
        .{ "/w", &.{ "a", "b.txt" } },
        .{ "/w/a", &.{ "x.txt", "b" } },
        .{ "/w/a/b", &.{"y"} },
    };
    fn fs() glob.Fs {
        return .{ .ptr = undefined, .vtable = &.{ .stat = stat, .list = list, .realpath = null } };
    }
    fn stat(_: *anyopaque, arena: Allocator, paths: []const []const u8, _: bool) glob.Fs.Error![]const glob.Kind {
        const out = try arena.alloc(glob.Kind, paths.len);
        for (paths, out) |p, *k| {
            k.* = .missing;
            for (kinds) |e| if (std.mem.eql(u8, e[0], p)) {
                k.* = e[1];
            };
        }
        return out;
    }
    fn list(_: *anyopaque, arena: Allocator, dirs: []const []const u8) glob.Fs.Error![]const []const []const u8 {
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (dirs, out) |d, *l| {
            l.* = &.{};
            for (lists) |e| if (std.mem.eql(u8, e[0], d)) {
                l.* = e[1];
            };
        }
        return out;
    }
};

test "allocation failures: hashFiles patterns and the walk" {
    const S = struct {
        fn run(a: Allocator, args: []const []const u8, want: usize) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            const parsed = switch (try glob.parse(arena.allocator(), args, "/w", "/home/u")) {
                .ok => |ok| ok,
                .invalid => return,
            };
            var why: []const u8 = "";
            switch (try glob.walk(arena.allocator(), tree.fs(), parsed.patterns, false, "/w", &why)) {
                .files => |files| try std.testing.expectEqual(want, files.len),
                .failed => return error.TestUnexpectedResult,
            }
        }
    };
    try checkOne(S.run, .{ @as([]const []const u8, &.{"**/*.txt\n!a/x.txt"}), 1 });
    try checkOne(S.run, .{ @as([]const []const u8, &.{ "a/**", "[ab]?txt", "# c" }), 3 });
    try checkOne(S.run, .{ @as([]const []const u8, &.{ "--follow-symbolic-links", "/w/../w/./b.txt" }), 0 });
    try checkOne(S.run, .{ @as([]const []const u8, &.{"--bad"}), 0 });
}

test "allocation failures: the broker's messages" {
    const S = struct {
        fn run(a: Allocator, message: []const u8) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            const ar = arena.allocator();
            const mtype = (try loop.jsonString(ar, message, "messageType")) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqualStrings("RunnerJobRequest", mtype);
            const body = (try loop.jsonString(ar, message, "body")) orelse return error.TestUnexpectedResult;
            const req = try runservice.parseJobRequest(ar, body);
            try std.testing.expectEqualStrings("https://run.test/", req.run_service_url);
        }
    };
    try checkOne(S.run, .{
        \\{"messageId":1,"messageType":"RunnerJobRequest","body":"{\"runner_request_id\":\"r1\",\"run_service_url\":\"https://run.test/\",\"should_acknowledge\":true,\"extra\":[1]}"}
    });
}

test "allocation failures: OCI image references and registry challenges" {
    const S = struct {
        fn ref(a: Allocator, image: []const u8) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            _ = registry.parseRef(arena.allocator(), image) catch |e| {
                if (expected(e, &.{error.InvalidImageReference})) return;
                return e;
            };
        }
        fn challenge(a: Allocator, text: []const u8) !void {
            var arena: Scratch = .init(a);
            defer arena.deinit();
            _ = registry.parseChallenge(arena.allocator(), text) catch |e| {
                if (expected(e, &.{error.UnsupportedAuth})) return;
                return e;
            };
        }
    };
    for ([_][]const u8{ "ubuntu", "ghcr.io/o/r:1.2", "redis@sha256:" ++ layer.repeat('a', 64), "Bad/Ref" }) |image|
        try checkOne(S.ref, .{image});
    for ([_][]const u8{
        "Bearer realm=\"https://auth.test/token\",service=\"reg\\\"x\",scope=\"repository:o/r:pull\"",
        "Basic realm=x",
        "Negotiate",
    }) |text| try checkOne(S.challenge, .{text});
}

test "allocation failures: tar headers, GNU long names and PAX records" {
    var a: std.heap.ArenaAllocator = .init(gpa);
    defer a.deinit();
    const arena = a.allocator();
    var t: layer.TestTar = .{ .a = arena };
    try t.add(.{ .path = "./", .kind = .directory });
    try t.add(.{ .path = "x", .body = "pax", .pax = try std.mem.concat(arena, u8, &.{
        try layer.TestTar.paxRecord(arena, "path", "deep/" ++ layer.repeat('d', 120) ++ "/file"),
        try layer.TestTar.paxRecord(arena, "mtime", "1700000000.25"),
        try layer.TestTar.paxRecord(arena, "SCHILY.xattr.user.a", "1"),
        try layer.TestTar.paxRecord(arena, "SCHILY.xattr.security.capability", "2"),
    }) });
    try t.add(.{ .path = "l", .kind = .symlink, .link = "x" });
    const bytes = try t.finish();

    const S = struct {
        fn run(al: Allocator, tar: []const u8) !void {
            var scratch: Scratch = .init(al);
            defer scratch.deinit();
            var in: std.Io.Reader = .fixed(tar);
            var r: layer.TarReader = .{ .in = &in, .scratch = scratch.allocator() };
            var n: usize = 0;
            while (try r.next()) |e| : (n += 1) {
                if (e.kind == .file) try std.testing.expectEqual(@as(usize, 2), e.xattrs.len);
                _ = try layer.clean(scratch.allocator(), e.path);
            }
            try std.testing.expectEqual(@as(usize, 3), n);
        }
    };
    try checkOne(S.run, .{bytes});
}
