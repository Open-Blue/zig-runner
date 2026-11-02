//! Fuzz tests for the parsers that read what jobs, workflows and servers hand the runner: workflow
//! commands, problem matchers and their regular expressions, YAML, expressions, hashFiles()
//! patterns, HPACK, an image's layers (tar, PAX, paths), references, registry challenges and
//! manifests, and minisign signatures. A crash in any of them takes the whole runner down, every
//! job on it included, so each test holds the parser to returning, with an answer or an error,
//! whatever the input, plus what must hold of the answer.
//!
//! `zig build test` runs each over its seed corpus below (and empty input), as ordinary tests;
//! `zig build test -Dllvm --fuzz` runs them continuously, mutating the seeds (Zig's fuzzer, with a
//! web UI showing coverage; LLVM, since Zig's own x86_64 backend instruments nothing for it).
//! The `fuzz` workflow runs each for a bounded number of runs every night
//! (`.github/scripts/zig-fuzz.sh`). A crash it finds belongs in the corpus once fixed.
const std = @import("std");
const linux = std.os.linux;

const commands = @import("commands.zig");
const expr = @import("expr.zig");
const glob = @import("glob.zig");
const hpack = @import("hpack.zig");
const matcher = @import("matcher.zig");
const minisign = @import("minisign.zig");
const regex = @import("regex.zig");
const yaml = @import("yaml.zig");
const image = @import("native/oci/image.zig");
const layer = @import("native/oci/layer.zig");
const registry = @import("native/oci/registry.zig");

const Smith = std.testing.Smith;

/// The next input string, at most `buf.len` bytes.
fn take(smith: *Smith, buf: []u8) []const u8 {
    return buf[0..smith.slice(buf)];
}

/// A corpus entry of strings, as `take` reads them: each a little-endian u32 length, then the bytes.
fn seed(comptime parts: []const []const u8) []const u8 {
    comptime {
        var out: []const u8 = "";
        for (parts) |p| {
            var len: [4]u8 = undefined;
            std.mem.writeInt(u32, &len, p.len, .little);
            out = out ++ len ++ p;
        }
        const final = out[0..out.len].*;
        return &final;
    }
}

/// `seed`, at run time: for corpus entries built by the test (archives, signatures).
fn seedAlloc(a: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (parts) |p| {
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(p.len), .little);
        try out.appendSlice(a, &len);
        try out.appendSlice(a, p);
    }
    return out.items;
}

fn seeds(comptime list: []const []const []const u8) []const []const u8 {
    comptime {
        var out: [list.len][]const u8 = undefined;
        for (list, &out) |parts, *o| o.* = seed(parts);
        const final = out;
        return &final;
    }
}

test "fuzz: workflow commands" {
    try std.testing.fuzz({}, workflowCommands, .{ .corpus = comptime seeds(&.{
        &.{"::set-output name=x::1"},
        &.{"::error file=a.zig,line=3,col=7,title=T%0A::boom%25"},
        &.{"::add-mask::secret"},
        &.{"::stop-commands::tok"},
        &.{"::add-matcher::.github/m.json"},
        &.{"  ::warning ::  "},
        &.{"::debug::%0D%0A%3A%3A"},
        &.{"NAME<<EOF\nline\nEOF\nB=2\n"},
        &.{"/usr/bin\n\n/opt/x\n"},
    }) });
}

fn workflowCommands(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var buf: [4096]u8 = undefined;
    const text = take(smith, &buf);
    _ = try commands.parseWorkflow(a.allocator(), text, null);
    _ = try commands.parseWorkflow(a.allocator(), text, "tok");
    // The same text as a step's GITHUB_ENV / GITHUB_OUTPUT and GITHUB_PATH files.
    _ = try commands.parseKeyValues(a.allocator(), text);
    _ = try commands.parsePaths(a.allocator(), text);
}

test "fuzz: problem matchers" {
    try std.testing.fuzz({}, problemMatchers, .{ .corpus = comptime seeds(&.{
        &.{
            \\{"problemMatcher":[{"owner":"zig","pattern":[{"regexp":"^(.+):(\\d+):(\\d+): (error|warning): (.*)$","file":1,"line":2,"column":3,"severity":4,"message":5}]}]}
            ,
            "src/main.zig:3:7: error: expected type",
        },
        &.{
            \\{"problemMatcher":[{"owner":"eslint","severity":"warning","pattern":[{"regexp":"^([^\\s].*)$","file":1},{"regexp":"^\\s+(\\d+):(\\d+)\\s+(error|warning)\\s+(.*)$","line":1,"column":2,"severity":3,"message":4,"loop":true}]}]}
            ,
            "a.js\n  1:2  error  bad\n  3:4  warning  meh\n\n",
        },
        &.{
            \\{"problemMatcher":[{"owner":"x","pattern":[{"regexp":"(?<n>a)\\k<n>(?=b)(?<!c)","message":1}]}]}
            ,
            "aab",
        },
    }) });
}

fn problemMatchers(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var jbuf: [4096]u8 = undefined;
    var lbuf: [4096]u8 = undefined;
    const json = take(smith, &jbuf);
    const lines = take(smith, &lbuf);
    const loaded = matcher.load(arena, json) catch |e| switch (e) {
        error.BadMatcher => return,
        else => return e,
    };
    var set: matcher.Set = .{};
    try set.add(arena, loaded.matchers);
    var it = std.mem.splitScalar(u8, lines, '\n');
    while (it.next()) |line| _ = set.feed(arena, line) catch |e| switch (e) {
        error.BadMatcher => {},
        else => return e,
    };
}

test "fuzz: regular expressions" {
    try std.testing.fuzz({}, regularExpressions, .{ .corpus = comptime seeds(&.{
        &.{ "^(.+):(\\d+):(\\d+): (error|warning): (.*)$", "src/a.zig:1:2: error: x" },
        &.{ "(a|ab)(c|bcd)(d*)", "abcd" },
        &.{ "(?:(a)|b)\\1", "aa ba" },
        &.{ "(?<=\\$)\\d+(?!\\.)", "$12.5 $30" },
        &.{ "[^\\]a-c-]+?x{2,3}\\b", "zzxxx yx" },
        &.{ "(a+)+$", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab" },
        &.{ "\\101\\x41\\u0041\\cA[\\b]", "AAA\x01\x08" },
        &.{ "(?(1)a|b)(x)?", "bx" },
    }) });
}

fn regularExpressions(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var pbuf: [256]u8 = undefined;
    var ibuf: [1024]u8 = undefined;
    const pattern = take(smith, &pbuf);
    const input = take(smith, &ibuf);
    const re = regex.Regex.compile(arena, pattern) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return,
    };
    var from: usize = 0;
    while (from <= input.len) {
        const caps = (re.find(arena, input, from) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => return,
        }) orelse return;
        // Every group that took part lies within the input, in order.
        var n: usize = 0;
        while (n <= re.group_count) : (n += 1) {
            const g = caps.group(n) orelse continue;
            try std.testing.expect(g.start <= g.end and g.end <= input.len);
        }
        const whole = caps.group(0).?;
        try std.testing.expect(whole.start >= from);
        from = if (whole.end > whole.start) whole.end else whole.end + 1;
    }
}

test "fuzz: YAML" {
    try std.testing.fuzz({}, yamlDocuments, .{
        .corpus = comptime seeds(&.{
            &.{"on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo hi\n"},
            &.{"a: &x {b: [1, 2, {c: d}]}\ne: *x\nf: >-\n  folded\n  text\n"},
            &.{"- 'single ''quoted'''\n- \"double \\u00e9 \\n\"\n- ~\n- Null\n? complex\n: value\n"},
            &.{"key: [a, [b, [c, [d]]]]\n# comment\n---\n"},
            // Each once read an empty entry for ever, until memory ran out.
            &.{"a: [}]\n"},
            &.{"a: {]}\n"},
            // Quoted scalars and flow collections over several lines, and explicit keys.
            &.{"a: \"one  \n  two \\\n  three\n\n  four\"\nb: 'it''s\n\n  x'\n? |\n  k\n: v\n"},
            &.{"a: [\n  x\n   y, # c\n  {? k : v, \"q\":\n   [1,\n2]},\n  z: w,\n]\nb: {a: [b, c], ? d}\n"},
        }),
    });
}

fn yamlDocuments(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var buf: [8192]u8 = undefined;
    const source = take(smith, &buf);
    var diag: yaml.Diag = .{};
    _ = yaml.parse(a.allocator(), source, &diag) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {},
    };
}

test "fuzz: expressions" {
    try std.testing.fuzz({}, expressions, .{ .corpus = comptime seeds(&.{
        &.{"github.event.pull_request.labels.*.name"},
        &.{"contains(fromJSON('[\"a\",\"b\"]'), matrix.os) && !cancelled()"},
        &.{"format('{0}-{1}', runner.os, hashFiles('**/x'))"},
        &.{"(1 < '2') == true || null >= 0 && 0x10 != 1e1"},
        &.{"toJSON(steps.*.outputs) == join(github.event.commits.*.id, ', ')"},
        &.{"startsWith(github.ref, 'refs/tags/') && endsWith(github.head_ref, 'x') || case(true, 1, 2)"},
    }) });
}

fn expressions(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var buf: [2048]u8 = undefined;
    const text = take(smith, &buf);
    const contexts_json =
        \\{"github":{"ref":"refs/heads/main","head_ref":"","event":{"pull_request":{"labels":[{"name":"a"},{"name":"b"}]},"commits":[{"id":"1"},{"id":"2"}]}},
        \\ "matrix":{"os":"a"},"runner":{"os":"Linux"},"steps":{"s":{"outputs":{"o":"1"},"outcome":"success"}},
        \\ "env":{"A":"1"},"inputs":{"n":3.5,"b":true,"z":null}}
    ;
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, contexts_json, .{});
    const scope: expr.Scope = .{ .contexts = (try expr.fromJsonValue(arena, parsed)).object };
    _ = expr.evaluate(arena, text, scope) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {},
    };
    _ = expr.interpolate(arena, text, scope) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {},
    };
}

test "fuzz: hashFiles patterns" {
    try std.testing.fuzz({}, hashFilesPatterns, .{ .corpus = comptime seeds(&.{
        &.{"**/*.txt\n!a/skip.txt"},
        &.{"--follow-symbolic-links\n~/x/**"},
        &.{"[ab]?/**/[!x]*\n# comment\n/w/../w/./b.txt"},
        &.{"a/**/b/**\n!**/b"},
    }) });
}

const fuzz_tree = struct {
    const Kind = glob.Kind;
    const kinds = [_]struct { []const u8, Kind }{
        .{ "/w", .directory },     .{ "/w/a", .directory },  .{ "/w/a/x.txt", .file },
        .{ "/w/a/b", .directory }, .{ "/w/a/b/y", .file },   .{ "/w/b.txt", .file },
        .{ "/w/.h", .file },       .{ "/w/link", .symlink },
    };
    const lists = [_]struct { []const u8, []const []const u8 }{
        .{ "/w", &.{ "a", "b.txt", ".h", "link" } },
        .{ "/w/a", &.{ "x.txt", "b" } },
        .{ "/w/a/b", &.{"y"} },
    };
    fn fs() glob.Fs {
        return .{ .ptr = undefined, .vtable = &.{ .stat = stat, .list = list, .realpath = null } };
    }
    fn stat(_: *anyopaque, arena: std.mem.Allocator, paths: []const []const u8, _: bool) glob.Fs.Error![]const Kind {
        const out = try arena.alloc(Kind, paths.len);
        for (paths, out) |p, *k| {
            k.* = .missing;
            for (kinds) |e| if (std.mem.eql(u8, e[0], p)) {
                k.* = e[1];
            };
        }
        return out;
    }
    fn list(_: *anyopaque, arena: std.mem.Allocator, dirs: []const []const u8) glob.Fs.Error![]const []const []const u8 {
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

fn hashFilesPatterns(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var buf: [1024]u8 = undefined;
    const text = take(smith, &buf);
    // Arguments one per line, as hashFiles('a', 'b') passes them; a first `--` one is an option.
    var args: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |arg| try args.append(arena, arg);
    const parsed = switch (try glob.parse(arena, args.items, "/w", "/home/u")) {
        .ok => |ok| ok,
        .invalid => return,
    };
    var why: []const u8 = "";
    switch (try glob.walk(arena, fuzz_tree.fs(), parsed.patterns, false, "/w", &why)) {
        // Only files of the tree, within the workspace, each once.
        .files => |files| for (files, 0..) |f, i| {
            try std.testing.expect(std.mem.startsWith(u8, f, "/w/"));
            for (files[0..i]) |g| try std.testing.expect(!std.mem.eql(u8, f, g));
            var known = false;
            for (fuzz_tree.kinds) |e| known = known or std.mem.eql(u8, e[0], f);
            try std.testing.expect(known);
        },
        .failed => {},
    }
}

test "fuzz: HPACK" {
    try std.testing.fuzz({}, hpackBlocks, .{
        .corpus = comptime seeds(&.{
            // :status 200, then a literal with incremental indexing and its dynamic-table reference.
            &.{ "\x88\x40\x0acustom-key\x0dcustom-header\xbe", "\x8c\x82" },
            // A Huffman-coded literal (www.example.com) and a table size update.
            &.{ "\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", "\x3f\xe1\x1f\x82" },
        }),
    });
}

fn hpackBlocks(_: void, smith: *Smith) !void {
    var d: hpack.Decoder = .{ .gpa = std.testing.allocator };
    defer d.deinit();
    var buf: [2048]u8 = undefined;
    const Sum = struct {
        fn on(n: *usize, name: []const u8, value: []const u8) void {
            n.* += name.len + value.len;
        }
    };
    var seen: usize = 0;
    // Blocks in turn, as one connection's: the dynamic table carries over.
    while (!smith.eos()) {
        d.decode(take(smith, &buf), &seen, Sum.on) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => return,
        };
        try std.testing.expect(d.size <= d.max_size);
    }
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    _ = hpack.huffmanDecode(a.allocator(), take(smith, &buf)) catch {};
}

// --- images: layers, references, challenges, manifests ---

/// Where "fuzz: OCI layer" applies its layers: `root`, which a layer may change, beside `outside`
/// and its file `host`, which no layer may reach. Absolute, so the corpus can name it.
const LayerBox = struct {
    base: linux.fd_t,
    path: []const u8,
};

test "fuzz: OCI layer" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "outside");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "outside/host", .data = "host" });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
    const rc = linux.open(try arena.dupeSentinel(u8, path, 0), .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    const box: LayerBox = .{ .base = @intCast(rc), .path = path };
    defer _ = linux.close(box.base);

    const host = try std.fmt.allocPrint(arena, "{s}/outside/host", .{path});
    const pax = try std.mem.concat(arena, u8, &.{
        try layer.TestTar.paxRecord(arena, "path", "a/very/long/name/" ++ layer.repeat('n', 120)),
        try layer.TestTar.paxRecord(arena, "size", "3"),
        try layer.TestTar.paxRecord(arena, "uid", "1000"),
        try layer.TestTar.paxRecord(arena, "mtime", "1700000000.25"),
        try layer.TestTar.paxRecord(arena, "SCHILY.xattr.user.k", "v"),
        try layer.TestTar.paxRecord(arena, "SCHILY.xattr.trusted.overlay.opaque", "y"),
    });
    const archives = [_][]const layer.TestTar.Spec{
        &.{
            .{ .path = "./", .kind = .directory, .mode = 0o755 },
            .{ .path = "usr/bin/", .kind = .directory, .mode = 0o555 },
            .{ .path = "usr/bin/tool", .body = "#!/bin/sh\n", .mode = 0o4755 },
            .{ .path = "bin", .kind = .symlink, .link = "usr/bin" },
            .{ .path = "bin/via", .body = "through the symlink" },
            .{ .path = "usr/bin/tool2", .kind = .hard_link, .link = "usr/bin/tool" },
            .{ .path = "fifo", .kind = .fifo },
            .{ .path = "dev/null", .kind = .char },
        },
        // Whiteouts: one name, an opaque directory, aufs's own.
        &.{
            .{ .path = "etc/a", .body = "a" },
            .{ .path = "etc/.wh.a" },
            .{ .path = "opq/x", .body = "x" },
            .{ .path = "opq/.wh..wh..opq" },
            .{ .path = ".wh..wh.plnk" },
            .{ .path = "etc/.wh.." },
        },
        &.{.{ .path = "short", .body = "pax", .pax = pax }},
        // The ways out: through an absolute symlink, through `..` in a symlink, a hard link to
        // the host's file, a whiteout of it, a `..` in a path or a hard link's target.
        &.{
            .{ .path = "esc", .kind = .symlink, .link = host },
            .{ .path = "esc", .body = "replaces the symlink" },
            .{ .path = "up", .kind = .symlink, .link = "../../../.." },
            .{ .path = "up/outside/host", .body = "written inside" },
            .{ .path = "hostlink", .kind = .symlink, .link = host },
            .{ .path = "hard", .kind = .hard_link, .link = "hostlink" },
            .{ .path = "up/outside/.wh.host" },
        },
        &.{.{ .path = "a/../../outside/host", .body = "refused" }},
        &.{.{ .path = "link", .kind = .hard_link, .link = "../outside/host" }},
    };
    var corpus: std.ArrayList([]const u8) = .empty;
    const raw: [8]u8 = @splat(0); // `structured` false: the bytes are the blob
    for (archives) |specs| {
        var t: layer.TestTar = .{ .a = arena };
        for (specs) |s| try t.add(s);
        try corpus.append(arena, try seedAlloc(arena, &.{ &raw, try t.finish() }));
    }
    for ([_][]const u8{ &layer.test_gzip, &layer.test_zstd }) |blob|
        try corpus.append(arena, try seedAlloc(arena, &.{ &raw, blob }));
    try std.testing.fuzz(&box, ociLayer, .{ .corpus = corpus.items });
}

fn ociLayer(box: *const LayerBox, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var buf: [64 * 1024]u8 = undefined;
    // Raw bytes (gzip, zstd or a tar), or an archive of headers made from the input with their
    // checksums right, which raw mutation rarely gets past.
    const blob = if (smith.value(bool)) try tarFrom(arena, smith) else take(smith, &buf);
    try readTar(arena, blob);

    // A fresh `root`, the layer applied to it, and nothing outside it changed.
    try layer.removeAt(std.testing.io, box.base, "root");
    try std.testing.expect(linux.errno(linux.mkdirat(box.base, "root", 0o755)) == .SUCCESS);
    const rc = linux.openat(box.base, "root", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    const root: linux.fd_t = @intCast(rc);
    defer _ = linux.close(root);
    var r: std.Io.Reader = .fixed(blob);
    var totals: layer.Totals = .{};
    const opts: layer.Options = .{ .owners = false, .max_bytes = 1 << 20, .max_entries = 1000 };
    layer.apply(std.testing.allocator, std.testing.io, root, &r, "", opts, &totals) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {},
    };
    try expectOnly(box.base, ".", &.{ "outside", "root" });
    try expectOnly(box.base, "outside", &.{"host"});
    var st: linux.Statx = undefined;
    try std.testing.expect(linux.errno(linux.statx(box.base, "outside/host", linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .NLINK = true, .SIZE = true }, &st)) == .SUCCESS);
    // Still a file of its own, as it was: nothing wrote to it, nothing linked to it from inside.
    try std.testing.expect(st.mode & linux.S.IFMT == linux.S.IFREG and st.nlink == 1 and st.size == 4);
}

/// The names in `dir` (under `base`), which must be exactly `want`.
fn expectOnly(base: linux.fd_t, dir: [:0]const u8, want: []const []const u8) !void {
    const rc = linux.openat(base, dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    var d: std.Io.Dir = .{ .handle = @intCast(rc) };
    defer d.close(std.testing.io);
    var seen: usize = 0;
    var it = d.iterate();
    while (try it.next(std.testing.io)) |e| {
        var known = false;
        for (want) |w| known = known or std.mem.eql(u8, w, e.name);
        if (!known) std.debug.print("a layer reached outside its rootfs: {s}/{s}\n", .{ dir, e.name });
        try std.testing.expect(known);
        seen += 1;
    }
    try std.testing.expectEqual(want.len, seen);
}

/// The archive's entries as the reader gives them: each path, once cleaned, relative and without
/// `.`, `..` or empty components; only a file has a size; every body readable to its end.
fn readTar(arena: std.mem.Allocator, blob: []const u8) !void {
    var r: std.Io.Reader = .fixed(blob);
    var tr: layer.TarReader = .{ .in = &r, .scratch = arena };
    var body: [4096]u8 = undefined;
    while (true) {
        const e = (tr.next() catch return) orelse return;
        if (e.kind != .file) try std.testing.expectEqual(@as(u64, 0), e.size);
        try expectClean(arena, e.path);
        if (e.kind == .hard_link) try expectClean(arena, e.link);
        while ((tr.read(&body) catch return) > 0) {}
    }
}

fn expectClean(arena: std.mem.Allocator, raw: []const u8) !void {
    const p = layer.clean(arena, raw) catch |e| switch (e) {
        error.PathEscapesRootfs => {
            // Refused only for a `..` component.
            var it = std.mem.tokenizeScalar(u8, raw, '/');
            while (it.next()) |c| if (std.mem.eql(u8, c, "..")) return;
            return error.TestUnexpectedResult;
        },
        error.BadTarHeader => return std.testing.expect(std.mem.indexOfScalar(u8, raw, 0) != null),
        else => return e,
    };
    if (p.len == 0) return;
    try std.testing.expect(p[0] != '/' and p[p.len - 1] != '/');
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |c| try std.testing.expect(c.len > 0 and !std.mem.eql(u8, c, ".") and
        !std.mem.eql(u8, c, "..") and std.mem.indexOfScalar(u8, c, 0) == null);
}

/// A tar archive of up to 12 entries from the input: each header's fields from it (names, octal
/// numbers or raw bytes, the type flag, ustar's magic and prefix), its checksum computed (or,
/// rarely, left wrong), then its body, padded to the block.
fn tarFrom(arena: std.mem.Allocator, smith: *Smith) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var n: usize = 0;
    while (n < 12 and !smith.eos()) : (n += 1) {
        var h: [512]u8 = @splat(0);
        _ = smith.slice(h[0..100]);
        const flags = "0123456 7xgLK\x00A";
        h[156] = flags[smith.index(flags.len)];
        var body_buf: [2048]u8 = undefined;
        const body = take(smith, &body_buf);
        _ = std.fmt.bufPrint(h[100..107], "{o:0>7}", .{smith.value(u32) & 0o7777777}) catch unreachable;
        _ = std.fmt.bufPrint(h[108..115], "{o:0>7}", .{smith.value(u16)}) catch unreachable;
        _ = std.fmt.bufPrint(h[116..123], "{o:0>7}", .{smith.value(u16)}) catch unreachable;
        if (smith.value(bool)) {
            smith.bytes(h[124..136]); // base-256, or not a number at all
        } else {
            _ = std.fmt.bufPrint(h[124..135], "{o:0>11}", .{body.len}) catch unreachable;
        }
        _ = std.fmt.bufPrint(h[136..147], "{o:0>11}", .{smith.value(u32)}) catch unreachable;
        _ = smith.slice(h[157..257]);
        if (smith.value(bool)) {
            @memcpy(h[257..263], "ustar\x00");
            @memcpy(h[263..265], "00");
            _ = smith.slice(h[345..500]);
        }
        @memset(h[148..156], ' ');
        var sum: u32 = 0;
        for (h) |c| sum += c;
        if (smith.boolWeighted(31, 1)) sum +%= smith.value(u8);
        _ = std.fmt.bufPrint(h[148..155], "{o:0>6}\x00", .{sum & 0o777777}) catch unreachable;
        try out.appendSlice(arena, &h);
        try out.appendSlice(arena, body);
        try out.appendNTimes(arena, 0, (512 - body.len % 512) % 512);
    }
    if (smith.value(bool)) try out.appendNTimes(arena, 0, 1024);
    return out.items;
}

test "fuzz: OCI references and challenges" {
    const hex = "fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852";
    try std.testing.fuzz({}, ociRefs, .{ .corpus = comptime seeds(&.{
        &.{ "ubuntu:24.04", "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/ubuntu:pull\"" },
        &.{ "ghcr.io/acme/app/img:1.2@sha256:" ++ hex, "Basic realm=\"x\"" },
        &.{ "localhost:5000/db", "bearer realm=\"http://127.0.0.1:1/t?a=b\" , service=x" },
        &.{ "[::1]:5000/a/b-c_d.e:v1", "Bearer realm=\"a\\\"b\",service=\"\\\\\"" },
        &.{ "index.docker.io/node", "Negotiate abc" },
    }) });
}

fn ociRefs(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var rbuf: [512]u8 = undefined;
    var cbuf: [1024]u8 = undefined;
    const text = take(smith, &rbuf);
    const challenge = take(smith, &cbuf);
    if (registry.parseRef(arena, text)) |ref| {
        if (ref.digest) |d| try std.testing.expect(registry.validDigest(d));
        // Its own name reads back as the same reference.
        const again = try registry.parseRef(arena, try std.fmt.allocPrint(arena, "{f}", .{ref}));
        try std.testing.expectEqualStrings(ref.registry, again.registry);
        try std.testing.expectEqualStrings(ref.host, again.host);
        try std.testing.expectEqualStrings(ref.repository, again.repository);
        try std.testing.expectEqualStrings(ref.reference(), again.reference());
        // Its parts go into the API's URLs, where none may reach into another part.
        const url = try std.fmt.allocPrint(arena, "https://{s}/v2/{s}/manifests/{s}", .{ ref.host, ref.repository, ref.reference() });
        if (std.Uri.parse(url)) |uri| {
            try std.testing.expect(uri.query == null and uri.fragment == null and uri.user == null);
            try std.testing.expect(std.mem.startsWith(u8, uri.path.percent_encoded, "/v2/"));
        } else |_| {}
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        else => {},
    }
    if (registry.parseChallenge(arena, challenge)) |ch| {
        if (ch.scheme == .bearer) try std.testing.expect(ch.realm.len > 0);
        _ = std.Uri.parse(ch.realm) catch {};
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        else => {},
    }
}

test "fuzz: OCI manifests" {
    const d = "sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852";
    try std.testing.fuzz({}, ociManifests, .{ .corpus = comptime seeds(&.{
        &.{"{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[" ++
            "{\"digest\":\"" ++ d ++ "\",\"size\":1,\"platform\":{\"architecture\":\"unknown\",\"os\":\"unknown\"}}," ++
            "{\"digest\":\"" ++ d ++ "\",\"platform\":{\"architecture\":\"arm64\",\"os\":\"linux\",\"variant\":\"v8\"}}," ++
            "{\"digest\":\"" ++ d ++ "\",\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"}}]}"},
        &.{"{\"schemaVersion\":2,\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"" ++ d ++
            "\",\"size\":2},\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"" ++ d ++ "\",\"size\":3}]}"},
        &.{"{\"architecture\":\"amd64\",\"os\":\"linux\",\"config\":{\"Env\":[\"PATH=/bin\"],\"User\":\"1000:1000\",\"WorkingDir\":\"/w\"},\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"" ++ d ++ "\"]}}"},
        &.{"{\"schemaVersion\":1,\"x\":[[[[{}]]]]}"},
    }) });
}

fn ociManifests(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var buf: [8192]u8 = undefined;
    const json = take(smith, &buf);
    var why: []const u8 = "";
    if (image.parseManifest(arena, .{ .bytes = json, .media_type = "", .digest = "" }, &why)) |doc| {
        // Every digest it names is one, so it can go into a URL and a store path.
        for ([_]?[]const image.Descriptor{ doc.manifests, doc.layers, if (doc.config) |c| &.{c} else null }) |list|
            if (list) |l| for (l) |desc| try std.testing.expect(registry.validDigest(desc.digest));
        if (doc.manifests) |list| for ([_]image.Platform{
            .{ .architecture = "amd64" },
            .{ .architecture = "arm64", .variant = "v8" },
            .{ .architecture = "arm", .variant = "v7" },
        }) |p| if (image.pickPlatform(list, p)) |pick| {
            const pp = pick.platform.?;
            try std.testing.expectEqualStrings("linux", pp.os);
            try std.testing.expectEqualStrings(p.architecture, pp.architecture);
        };
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        else => try std.testing.expect(why.len > 0),
    }
    // The same bytes as an image's config.
    _ = std.json.parseFromSliceLeaky(image.Config, arena, json, .{ .ignore_unknown_fields = true }) catch {};
}

// --- minisign ---

/// The signature the fuzzer starts from, and what alone may verify against its key.
const Signed = struct {
    pk: minisign.PublicKey,
    content: []const u8,
    trusted: []const u8,
};

test "fuzz: minisign" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(7));
    const content = "zig-x86_64-linux-0.17.0.tar.xz, as a fixture";
    const trusted = "timestamp:1 file:zig.tar.xz";
    const f = try minisign.testing.fixture(arena, kp, content, trusted);
    const signed: Signed = .{ .pk = try minisign.PublicKey.parse(&f.pk), .content = content, .trusted = trusted };
    const corpus = [_][]const u8{
        try seedAlloc(arena, &.{ f.minisig, content, &f.pk }),
        try seedAlloc(arena, &.{ try std.mem.replaceOwned(u8, arena, f.minisig, "\n", "\r\n"), content, "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U" }),
        try seedAlloc(arena, &.{ try std.mem.replaceOwned(u8, arena, f.minisig, "timestamp:1", "timestamp:2"), content, "" }),
    };
    try std.testing.fuzz(&signed, minisignatures, .{ .corpus = &corpus });
}

fn minisignatures(signed: *const Signed, smith: *Smith) !void {
    var sbuf: [1024]u8 = undefined;
    var cbuf: [256]u8 = undefined;
    var kbuf: [128]u8 = undefined;
    const sig = take(smith, &sbuf);
    const content = take(smith, &cbuf);
    const key = take(smith, &kbuf);
    // Only the signed content verifies, and only with its own trusted comment.
    if (minisign.verify(signed.pk, content, sig)) |trusted| {
        try std.testing.expectEqualStrings(signed.content, content);
        try std.testing.expectEqualStrings(signed.trusted, trusted);
    } else |_| {}
    if (minisign.PublicKey.parse(key)) |pk| {
        _ = minisign.verify(pk, content, sig) catch {};
    } else |_| {}
}
