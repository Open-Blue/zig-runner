//! CPU-bound microbenchmarks of the runner's hot paths, for comparing two builds of the same code
//! (BENCHMARKS.md, "Position-independent executable"): expression evaluation (src/expr.zig),
//! workflow YAML parsing (src/yaml.zig), the HPACK decoder (src/hpack.zig), the hashFiles() glob's
//! walk over an in-memory tree (src/glob.zig), and SHA-256 of a 32 MiB buffer (std, which the step
//! store and hashFiles() use). `.github/scripts/hotbench.sh` builds it twice and runs both in turn.
//!
//!     hotbench <rounds> <workflow.yml>...
//!
//! Each benchmark runs `rounds` timed rounds of a fixed amount of work, after one untimed round,
//! and prints one line per round: `<benchmark>\t<nanoseconds>`. Every result is checked once
//! before timing starts, so a benchmark cannot be measuring an early error.
const std = @import("std");
const expr = @import("expr");
const yaml = @import("yaml");
const hpack = @import("hpack");
const glob = @import("glob");

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 3) {
        std.debug.print("usage: hotbench <rounds> <workflow.yml>...\n", .{});
        return 2;
    }
    const rounds = try std.fmt.parseInt(u32, args[1], 10);
    var workflows: std.ArrayList([]const u8) = .empty;
    for (args[2..]) |path|
        try workflows.append(gpa, try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 24)));

    var out_buf: [4096]u8 = undefined;
    var out_w: std.Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();

    const ctx: Ctx = .{
        .arena = &arena_state,
        .contexts = try contexts(gpa),
        .workflows = workflows.items,
        .tree = try Tree.init(gpa),
        .big = try bigBuffer(gpa),
    };
    inline for (benchmarks) |b| {
        try b.run(ctx, 1); // checks the results, warms caches
        for (0..rounds) |_| {
            const start = std.Io.Clock.awake.now(io);
            try b.run(ctx, b.iterations);
            const ns = start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds;
            try out.print("{s}\t{d}\n", .{ b.name, ns });
        }
    }
    return 0;
}

const Bench = struct { name: []const u8, iterations: u32, run: fn (Ctx, u32) anyerror!void };

/// Iterations per round: each round takes roughly 50-200 ms on the laptop.
const benchmarks = [_]Bench{
    .{ .name = "expr", .iterations = 4000, .run = Ctx.evaluate },
    .{ .name = "yaml", .iterations = 200, .run = Ctx.parseYaml },
    .{ .name = "hpack", .iterations = 16000, .run = Ctx.decodeHpack },
    .{ .name = "glob", .iterations = 6, .run = Ctx.walkGlob },
    .{ .name = "sha256", .iterations = 1, .run = Ctx.hashSha256 },
};

const Ctx = struct {
    arena: *std.heap.ArenaAllocator,
    contexts: []const expr.Value.Entry,
    workflows: []const []const u8,
    tree: Tree,
    big: []const u8,

    fn evaluate(c: Ctx, n: u32) !void {
        for (0..n) |_| {
            defer _ = c.arena.reset(.retain_capacity);
            const a = c.arena.allocator();
            var diag: []const u8 = "";
            const scope: expr.Scope = .{ .contexts = c.contexts, .diag = &diag };
            for (expressions) |e| {
                const v = expr.evaluate(a, e.text, scope) catch |err| {
                    std.debug.print("{s}: {s} ({s})\n", .{ e.text, @errorName(err), diag });
                    return err;
                };
                const got = try expr.toStr(a, v);
                if (!std.mem.eql(u8, got, e.want)) {
                    std.debug.print("{s}: {s}, not {s}\n", .{ e.text, got, e.want });
                    return error.WrongResult;
                }
            }
            const s = try expr.interpolate(a, "zig-${{ runner.os }}-${{ matrix.zig }}-${{ github.sha }}", scope);
            std.mem.doNotOptimizeAway(s.ptr);
        }
    }

    fn parseYaml(c: Ctx, n: u32) !void {
        for (0..n) |_| {
            for (c.workflows) |w| {
                defer _ = c.arena.reset(.retain_capacity);
                var diag: yaml.Diag = .{};
                const node = yaml.parse(c.arena.allocator(), w, &diag) catch |err| {
                    std.debug.print("yaml: {s} at line {d}: {s}\n", .{ @errorName(err), diag.line, diag.message });
                    return err;
                };
                std.mem.doNotOptimizeAway(&node);
            }
        }
    }

    fn decodeHpack(c: Ctx, n: u32) !void {
        _ = c;
        for (0..n) |_| {
            // A connection's decoder, through RFC 7541's request (C.4) and response (C.6) examples,
            // which share a dynamic table each and use Huffman coding throughout.
            inline for (.{ &rfc_requests, &rfc_responses }) |blocks| {
                var d: hpack.Decoder = .{ .gpa = std.heap.smp_allocator };
                defer d.deinit();
                var got: Got = .{};
                for (blocks) |b| try d.decode(b, &got, Got.on);
                if (got.fields != blockFields(blocks)) return error.WrongResult;
            }
        }
    }

    fn walkGlob(c: Ctx, n: u32) !void {
        for (0..n) |_| {
            defer _ = c.arena.reset(.retain_capacity);
            const a = c.arena.allocator();
            const args = [_][]const u8{"**/package-lock.json\n**/*.zig\n!**/node_modules/**\nbuild.zig.zon"};
            const parsed = switch (try glob.parse(a, &args, Tree.ws, "/root")) {
                .ok => |p| p,
                .invalid => |why| {
                    std.debug.print("glob: {s}\n", .{why});
                    return error.WrongResult;
                },
            };
            var why: []const u8 = "";
            var tree = c.tree;
            switch (try glob.walk(a, tree.fs(), parsed.patterns, parsed.follow, Tree.ws, &why)) {
                .files => |files| if (files.len != Tree.matching) {
                    std.debug.print("glob: {d} files, not {d}\n", .{ files.len, Tree.matching });
                    return error.WrongResult;
                },
                .failed => |f| {
                    std.debug.print("glob: {s}\n", .{f});
                    return error.WrongResult;
                },
            }
        }
    }

    fn hashSha256(c: Ctx, n: u32) !void {
        for (0..n) |_| {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(c.big, &digest, .{});
            std.mem.doNotOptimizeAway(&digest);
        }
    }
};

// --- expressions ---

const Case = struct { text: []const u8, want: []const u8 };

/// What workflows' `if:`s, `runs-on:`s and `with:`s commonly hold.
const expressions = [_]Case{
    .{ .text = "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')", .want = "false" },
    .{ .text = "contains(github.event.pull_request.labels.*.name, 'ci:full')", .want = "true" },
    .{ .text = "github.event.pull_request.base.sha || github.event.merge_group.base_sha", .want = "1111111111111111111111111111111111111111" },
    .{ .text = "format('{0}-{1}-{2}', runner.os, matrix.zig, matrix.target)", .want = "Linux-0.17.0-x86_64-linux-musl" },
    .{ .text = "fromJSON(env.MATRIX).include[1].os", .want = "ubuntu-26.04-arm" },
    .{ .text = "join(github.event.commits.*.message, ', ')", .want = "one, two, three" },
    .{ .text = "steps.scope.outputs.run == 'true' && !cancelled()", .want = "true" },
    .{ .text = "toJSON(matrix)", .want = "{\n  \"zig\": \"0.17.0\",\n  \"target\": \"x86_64-linux-musl\"\n}" },
    .{ .text = "github.event_name == 'pull_request' && github.event.pull_request.head.repo.fork == false", .want = "true" },
    .{ .text = "endsWith(github.repository, '/zig-runner') && (github.run_attempt > 1 || env.FORCE == 'yes')", .want = "true" },
};

fn contexts(gpa: std.mem.Allocator) ![]const expr.Value.Entry {
    const json =
        \\{"github": {"event_name": "pull_request", "ref": "refs/pull/281/merge", "repository": "Open-Blue/zig-runner",
        \\   "sha": "0123456789abcdef0123456789abcdef01234567", "run_attempt": 2,
        \\   "event": {"pull_request": {"number": 281, "base": {"sha": "1111111111111111111111111111111111111111"},
        \\     "head": {"repo": {"fork": false}},
        \\     "labels": [{"name": "packaging"}, {"name": "ci:full"}, {"name": "security"}]},
        \\     "commits": [{"message": "one"}, {"message": "two"}, {"message": "three"}]}},
        \\ "runner": {"os": "Linux", "arch": "X64", "temp": "/tmp/runner"},
        \\ "matrix": {"zig": "0.17.0", "target": "x86_64-linux-musl"},
        \\ "env": {"FORCE": "no", "MATRIX": "{\"include\": [{\"os\": \"ubuntu-26.04\"}, {\"os\": \"ubuntu-26.04-arm\"}]}"},
        \\ "steps": {"scope": {"outputs": {"run": "true"}, "outcome": "success", "conclusion": "success"}}}
    ;
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, gpa, json, .{});
    return (try expr.fromJsonValue(gpa, parsed)).object;
}

// --- HPACK ---

const Got = struct {
    fields: usize = 0,
    fn on(g: *Got, name: []const u8, value: []const u8) void {
        std.mem.doNotOptimizeAway(name.ptr);
        std.mem.doNotOptimizeAway(value.ptr);
        g.fields += 1;
    }
};

fn blockFields(blocks: anytype) usize {
    return if (blocks == &rfc_requests) 4 + 5 + 5 else 4 + 4 + 6;
}

const rfc_requests = [_][]const u8{
    &.{ 0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff },
    &.{ 0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf },
    &.{ 0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf },
};

const rfc_responses = [_][]const u8{
    &.{
        0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe,
        0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6,
        0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8,
        0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3,
    },
    &.{ 0x48, 0x83, 0x64, 0x0e, 0xff, 0xc1, 0xc0, 0xbf },
    &.{
        0x88, 0xc1, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95,
        0x04, 0x0b, 0x81, 0x66, 0xe0, 0x84, 0xa6, 0x2d, 0x1b, 0xff, 0xc0, 0x5a, 0x83, 0x9b, 0xd9, 0xab,
        0x77, 0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2, 0xe6, 0xc7, 0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b,
        0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36, 0x72, 0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f,
        0x95, 0x87, 0x31, 0x60, 0x65, 0xc0, 0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07,
    },
};

// --- the glob's tree ---

/// A workspace like a JavaScript and Zig monorepo's: `packages` packages, each with a lockfile, a
/// src/ of Zig files and a node_modules/ the patterns exclude.
const Tree = struct {
    dirs: std.StringHashMapUnmanaged([]const []const u8),

    const ws = "/ws";
    const packages = 40;
    const zig_files = 12;
    const modules = 30;
    /// Each package's lockfile and Zig files, and the root's build.zig.zon.
    const matching = packages * (1 + zig_files) + 1;

    fn init(gpa: std.mem.Allocator) !Tree {
        var t: Tree = .{ .dirs = .empty };
        var root: std.ArrayList([]const u8) = .empty;
        try root.appendSlice(gpa, &.{ "build.zig.zon", "README.md", "packages" });
        try t.dirs.put(gpa, ws, root.items);
        var pkgs: std.ArrayList([]const u8) = .empty;
        for (0..packages) |p| {
            const name = try std.fmt.allocPrint(gpa, "pkg{d}", .{p});
            try pkgs.append(gpa, name);
            const dir = try std.fmt.allocPrint(gpa, ws ++ "/packages/{s}", .{name});
            try t.dirs.put(gpa, dir, &.{ "package-lock.json", "package.json", "src", "node_modules" });
            var src: std.ArrayList([]const u8) = .empty;
            for (0..zig_files) |f| try src.append(gpa, try std.fmt.allocPrint(gpa, "file{d}.zig", .{f}));
            try src.append(gpa, "notes.txt");
            try t.dirs.put(gpa, try std.fmt.allocPrint(gpa, "{s}/src", .{dir}), src.items);
            var nm: std.ArrayList([]const u8) = .empty;
            for (0..modules) |m| {
                const mod = try std.fmt.allocPrint(gpa, "mod{d}", .{m});
                try nm.append(gpa, mod);
                try t.dirs.put(gpa, try std.fmt.allocPrint(gpa, "{s}/node_modules/{s}", .{ dir, mod }), &.{ "package.json", "index.js", "lib.zig" });
            }
            try t.dirs.put(gpa, try std.fmt.allocPrint(gpa, "{s}/node_modules", .{dir}), nm.items);
        }
        try t.dirs.put(gpa, ws ++ "/packages", pkgs.items);
        return t;
    }

    fn fs(t: *Tree) glob.Fs {
        return .{ .ptr = t, .vtable = &.{ .stat = stat, .list = list, .realpath = null } };
    }

    fn stat(ptr: *anyopaque, arena: std.mem.Allocator, paths: []const []const u8, follow: bool) glob.Fs.Error![]const glob.Kind {
        _ = follow;
        const t: *Tree = @ptrCast(@alignCast(ptr));
        const kinds = try arena.alloc(glob.Kind, paths.len);
        for (paths, kinds) |p, *k| k.* = if (t.dirs.contains(p)) .directory else .file;
        return kinds;
    }

    fn list(ptr: *anyopaque, arena: std.mem.Allocator, dirs: []const []const u8) glob.Fs.Error![]const []const []const u8 {
        const t: *Tree = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (dirs, out) |d, *o| o.* = t.dirs.get(d) orelse &.{};
        return out;
    }
};

fn bigBuffer(gpa: std.mem.Allocator) ![]const u8 {
    const buf = try gpa.alloc(u8, 32 << 20);
    var rng: std.Random.DefaultPrng = .init(0x5eed);
    rng.random().bytes(buf);
    return buf;
}
