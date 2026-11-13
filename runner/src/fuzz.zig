//! Fuzz tests for the parsers that read what jobs, workflows and servers hand the runner: workflow
//! commands, problem matchers and their regular expressions, YAML, expressions, hashFiles()
//! patterns, HPACK, an image's layers (tar, PAX, paths), references, registry challenges and
//! manifests, minisign signatures and zstd streams (the runner's decoder, held to std's); and
//! property tests of the text paths that guard secrets and a job's environment: masking (secret masking), file commands and their heredocs (file
//! commands), the broker's and run service's messages (job messages) and HTTP/2's framing
//! (HTTP2 frames). A crash in any of them takes the whole runner down, every job on it included,
//! so each test holds the parser to returning, with an answer or an error, whatever the input,
//! plus what must hold of the answer; the property tests also hold the answer to what GitHub's
//! runner gives for the same input, where its code says.
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
const zstd = @import("native/oci/zstd.zig");
const tls_stream = @import("tls_stream.zig");
const registry = @import("native/oci/registry.zig");
const redact = @import("redact.zig");
const sink = @import("sink.zig");
const dagger = @import("dagger.zig");
const JobLog = @import("dagger/JobLog.zig");
const scripts = @import("dagger/scripts.zig");
const engine = @import("engine.zig");
const job_mod = @import("job.zig");
const exchange = @import("loop/exchange.zig");
const loop_job = @import("loop/job.zig");
const runservice = @import("github/runservice.zig");

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
        std.mem.writeInt(u32, &len, std.math.cast(u32, p.len) orelse return error.SeedTooLong, .little);
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
    try std.testing.fuzz({}, regularExpressions, .{
        .corpus = comptime seeds(&.{
            &.{ "^(.+):(\\d+):(\\d+): (error|warning): (.*)$", "src/a.zig:1:2: error: x" },
            &.{ "(a|ab)(c|bcd)(d*)", "abcd" },
            &.{ "(?:(a)|b)\\1", "aa ba" },
            &.{ "(?<=\\$)\\d+(?!\\.)", "$12.5 $30" },
            &.{ "[^\\]a-c-]+?x{2,3}\\b", "zzxxx yx" },
            &.{ "(a+)+$", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab" },
            &.{ "\\101\\x41\\u0041\\cA[\\b]", "AAA\x01\x08" },
            &.{ "(?(1)a|b)(x)?", "bx" },
            // Each stepped back past the start of the input from inside a character: an empty match
            // moved `from` into the 4-byte U+101DFE (the fuzzer's, cut down), and `\1` matched the
            // lone 0xC3 to the first byte of À.
            &.{ "(?<=\\$.)'\x9f\x84\x9e\xdb|", "H\xf4\x81\xb7\xbe{" },
            &.{ "(?=.(.))\\1(?<=.)", "\xc3\x80\xc3" },
        }),
    });
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
    try std.testing.fuzz({}, hashFilesPatterns, .{
        .corpus = comptime seeds(&.{
            &.{"**/*.txt\n!a/skip.txt"},
            &.{"--follow-symbolic-links\n~/x/**"},
            &.{"[ab]?/**/[!x]*\n# comment\n/w/../w/./b.txt"},
            &.{"a/**/b/**\n!**/b"},
            // Asserted, until the fuzzer found it: `\.` is accepted, its implicit `/w/\./**` is not.
            &.{"\\."},
        }),
    });
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
    /// What `apply` runs its inflating thread on. Not `std.testing.io`, whose threads allocate
    /// their tasks from the testing allocator and free them after the awaiting thread has been
    /// woken: the input's run can end, and its leak check start, while a worker is still in that
    /// `free`, which the checker reports as a corrupted bucket (found by the nightly's fuzzing).
    io: std.Io,
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
    var threaded: std.Io.Threaded = .init(std.heap.smp_allocator, .{});
    defer threaded.deinit();
    const box: LayerBox = .{ .base = try fd(rc), .path = path, .io = threaded.io() };
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
    const root = try fd(rc);
    defer _ = linux.close(root);
    var r: std.Io.Reader = .fixed(blob);
    var totals: layer.Totals = .{};
    const opts: layer.Options = .{ .owners = false, .max_bytes = 1 << 20, .max_entries = 1000 };
    layer.apply(std.testing.allocator, box.io, root, &r, "", opts, &totals) catch |e| switch (e) {
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

/// The descriptor an `open` returned, checked as no cast would be.
fn fd(rc: usize) !linux.fd_t {
    return std.math.cast(linux.fd_t, rc) orelse error.TestUnexpectedResult;
}

/// `v` in octal, zero-padded to fill `field` (a tar header's number), its high digits dropped
/// when it does not fit.
fn octal(field: []u8, v: u64) void {
    var rest = v;
    var i = field.len;
    while (i > 0) {
        i -= 1;
        field[i] = '0' + @as(u8, @truncate(rest & 7));
        rest >>= 3;
    }
}

/// The names in `dir` (under `base`), which must be exactly `want`.
fn expectOnly(base: linux.fd_t, dir: [:0]const u8, want: []const []const u8) !void {
    const rc = linux.openat(base, dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    var d: std.Io.Dir = .{ .handle = try fd(rc) };
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
        octal(h[100..107], smith.value(u32));
        octal(h[108..115], smith.value(u16));
        octal(h[116..123], smith.value(u16));
        if (smith.value(bool)) {
            smith.bytes(h[124..136]); // base-256, or not a number at all
        } else {
            octal(h[124..135], body.len);
        }
        octal(h[136..147], smith.value(u32));
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
        octal(h[148..154], sum);
        h[154] = 0;
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

// --- zstd ---

/// "fuzz: zstd" holds the runner's decoder (`oci/zstd.zig`, which reads every zstd layer a
/// registry sends) to what std's `std.compress.zstd`, the slow oracle, makes of the same bytes,
/// and to its own limits. The input is a stream of frames. Both decoders read it, to the same
/// window limit and to the same output cap (a bomb is cut off, not waited for), and then:
///
///  - both fail, or both give the same bytes (or the same first `zstd_output` of them);
///  - the runner's decoder takes nothing std refuses, and refuses nothing std takes, except where
///    std is the one that is lenient or does not do it: a dictionary id of 0 and std's own
///    limits (it refuses the flag, not the id), and an offset beyond the frame's window or its
///    start, which std checks only against its buffer, not the frame;
///  - a failure has a reason (`Decompress.err`), and the heap stays within `zstd_heap` live bytes,
///    which window, blocks and tables fit in with room to spare: nothing the stream says
///    allocates more;
///  - no more than 128 KiB comes out of 4 bytes of input (a block's header and its one byte), so
///    the work is in proportion to the input; and an input takes under `zstd_seconds`.
const zstd_input = 80 * 1024;
const zstd_window = 1 << 20;
const zstd_output = 1 << 20;
const zstd_heap = 4 << 20;
const zstd_seconds = 10;

var zstd_oracle_window: [zstd_window + std.compress.zstd.block_size_max]u8 = undefined;
var zstd_ours_out: [zstd_output]u8 = undefined;
var zstd_oracle_out: [zstd_output]u8 = undefined;

/// The heap a run of "fuzz: zstd" gets: an allocator that fails past `limit` live bytes. One run at
/// a time (the fuzzer is one thread), so it is a global, which needs no cast from the allocator's
/// pointer.
var zstd_budget: struct { limit: usize = zstd_heap, live: usize = 0 } = .{};

const zstd_budget_vtable: std.mem.Allocator.VTable = .{
    .alloc = struct {
        fn f(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
            if (len > zstd_budget.limit - zstd_budget.live) return null;
            const p = std.testing.allocator.rawAlloc(len, alignment, ret) orelse return null;
            zstd_budget.live += len;
            return p;
        }
    }.f,
    .resize = struct {
        fn f(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
            if (new_len > memory.len and new_len - memory.len > zstd_budget.limit - zstd_budget.live) return false;
            if (!std.testing.allocator.rawResize(memory, alignment, new_len, ret)) return false;
            zstd_budget.live = zstd_budget.live - memory.len + new_len;
            return true;
        }
    }.f,
    .remap = struct {
        fn f(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
            if (new_len > memory.len and new_len - memory.len > zstd_budget.limit - zstd_budget.live) return null;
            const p = std.testing.allocator.rawRemap(memory, alignment, new_len, ret) orelse return null;
            zstd_budget.live = zstd_budget.live - memory.len + new_len;
            return p;
        }
    }.f,
    .free = struct {
        fn f(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
            std.testing.allocator.rawFree(memory, alignment, ret);
            zstd_budget.live -= memory.len;
        }
    }.f,
};

const zstd_files = [_][]const u8{
    "bin6k-l19",            "bin6k",                      "empty",                  "hand-dictid0",           "hand-raw",
    "hand-rle-window",      "hand-rle",                   "period-l19",             "period",                 "random3k",
    "skew4k-l19",           "skew4k",                     "skippable-only",         "skippable-then-frame",   "text12k-checksum",
    "text12k-fast",         "text12k-l1",                 "text12k-l19",            "text12k-l22",            "text12k-l3",
    "text12k-stdin-nosize", "text12k-wlog17",             "text300",                "text3k-l9",              "text3k-stdin",
    "text40",               "two-frames",                 "zeros20k-l19",           "zeros20k",               "blocks-l3",
    "blocks-l9",            "blocks-l19",                 "blocks-l1",              "blocks-bin",             "blocks-bin-l19",
    "blocks-w10",           "hand-huffman-direct-f0",     "hand-huffman-direct-f1", "hand-huffman-direct-f2", "hand-huffman-direct-f3",
    "hand-literals-rle",    "hand-sequences-rle-refused", "hand-sequences-rle",     "hand-window-slides",
};

/// The seed corpus (`fuzz_corpus/zstd`), 1.5.7's `zstd` and libzstd's frames of text, a binary,
/// random bytes (raw blocks), runs (RLE blocks, repeated offsets) and a skewed alphabet, at levels
/// from `--fast` to `--ultra -22` and in blocks of 1.3 KB (`targetCBlockSize`, so a short input
/// has many that reuse the last one's tree and tables), with and without a checksum, a content size
/// or a window descriptor, behind and between skippable frames and concatenated; and frames made
/// by hand for what zstd does not write at this size: a dictionary id of 0, a window that slides
/// (a match across 150 KB), Huffman trees of direct weights in all four literals headers, RLE
/// literals, RLE sequence tables, and a repeat offset out of reach. Together the seeds reach every
/// literals type and size format, every sequences table mode, and all four repeat offsets.
const zstd_seeds = zstd_seeds: {
    var out: [zstd_files.len][]const u8 = undefined;
    for (zstd_files, 0..) |name, i| out[i] = seed(&.{@embedFile("fuzz_corpus/zstd/" ++ name ++ ".zst")});
    const final = out;
    break :zstd_seeds &final;
};

test "fuzz: zstd" {
    try std.testing.fuzz({}, zstdFrames, .{ .corpus = zstd_seeds });
}

/// What a decoder made of the input: `done` (all of it), `capped` (the output buffer full, with
/// more perhaps to come) or `failed`.
const ZstdRun = enum { done, capped, failed };

fn zstdRead(r: *std.Io.Reader, out: []u8) struct { ZstdRun, usize } {
    const n = r.readSliceShort(out) catch return .{ .failed, 0 };
    return .{ if (n == out.len) .capped else .done, n };
}

/// Why std refuses a stream the runner's decoder takes, when std is the one that does not do it:
/// a dictionary id flag (with an id of 0, which is no dictionary) and the limits of its buffers.
fn zstdOracleDeclines(why: ?std.compress.zstd.Decompress.Error) bool {
    const e = why orelse return false;
    return switch (e) {
        error.DictionaryIdFlagUnsupported,
        error.WindowOversize,
        error.OutputBufferUndersize,
        error.SequenceBufferUndersize,
        error.InputBufferUndersize,
        => true,
        else => false,
    };
}

fn zstdOracleLenient(why: zstd.Error) bool {
    return switch (why) {
        error.BadOffset, error.IncompleteHuffmanTree, error.BadLiteralStream => true,
        else => false,
    };
}

fn zstdFrames(_: void, smith: *Smith) !void {
    var buf: [zstd_input]u8 = undefined;
    try zstdAgrees(take(smith, &buf));
}

// The fuzzer's byte mutations rarely make the exact change that tells two decoders apart (the
// marker bit of a stream's last byte moved, one bit of a header), so every bit of each small
// seed is flipped, one at a time, as a test.
test "zstd decoders: every bit of the small seeds flipped" {
    var buf: [400]u8 = undefined;
    // Under Valgrind (many times slower, two decoders a run) every 37th bit: it looks for memory
    // errors, which any input shows, not for disagreements.
    const stride: usize = if (std.valgrind.runningOnValgrind() != 0) 37 else 1;
    inline for (zstd_files) |name| {
        const frame = @embedFile("fuzz_corpus/zstd/" ++ name ++ ".zst");
        if (comptime frame.len <= buf.len) {
            var bit: usize = 0;
            while (bit < frame.len * 8) : (bit += stride) {
                @memcpy(buf[0..frame.len], frame);
                buf[bit / 8] ^= std.math.shl(u8, 1, bit % 8);
                zstdAgrees(buf[0..frame.len]) catch |e| {
                    std.debug.print("SEED {s} bit {d} {x}\n", .{ name, bit, buf[0..frame.len] });
                    return e;
                };
            }
        }
    }
}

/// `input` read by the runner's decoder and by std's, and held to the target's properties.
fn zstdAgrees(input: []const u8) !void {
    const io = std.testing.io;
    const started = std.Io.Timestamp.now(io, .awake);

    zstd_budget.live = 0;
    const heap: std.mem.Allocator = .{ .ptr = &zstd_budget, .vtable = &zstd_budget_vtable };
    var in: std.Io.Reader = .fixed(input);
    const d = try zstd.Decompress.create(heap, &in);
    defer d.destroy();
    d.window_limit = zstd_window;
    const mine, const mine_len = zstdRead(&d.reader, &zstd_ours_out);
    const ours = zstd_ours_out[0..mine_len];

    var oracle_in: std.Io.Reader = .fixed(input);
    var oracle: std.compress.zstd.Decompress = .init(&oracle_in, &zstd_oracle_window, .{ .window_len = zstd_window });
    const theirs, const theirs_len = zstdRead(&oracle.reader, &zstd_oracle_out);
    const want = zstd_oracle_out[0..theirs_len];

    // A failure has a reason, and none is for want of memory.
    if (mine == .failed) {
        try std.testing.expect(d.err != null);
        try std.testing.expect(d.err.? != error.OutOfMemory);
    }
    // Reading on after a failure fails again, or ends, and never reads out of bounds.
    var more: [64]u8 = undefined;
    if (d.reader.readSliceShort(&more)) |_| {} else |_| {}

    switch (mine) {
        .done => switch (theirs) {
            .done => try std.testing.expectEqualSlices(u8, want, ours),
            .capped => return zstdDisagree(input, "the runner's decoder ends, std's gives more", d.err, oracle.err),
            .failed => if (!zstdOracleDeclines(oracle.err)) return zstdDisagree(input, "std refuses what the runner's takes", d.err, oracle.err),
        },
        .capped => switch (theirs) {
            .capped => try std.testing.expectEqualSlices(u8, want, ours),
            .done => return zstdDisagree(input, "std's decoder ends, the runner's gives more", d.err, oracle.err),
            .failed => if (!zstdOracleDeclines(oracle.err)) return zstdDisagree(input, "std refuses what the runner's takes", d.err, oracle.err),
        },
        .failed => switch (theirs) {
            .failed => {},
            // What std does not look at, and libzstd refuses (each found by this target, and
            // checked against `zstd -d`): an offset beyond the frame's window or start (std checks
            // its buffer), a Huffman tree whose weights leave no power of two for the last symbol,
            // and a literal stream that holds more or fewer bits than its symbols take (std moves
            // on to the next of the four streams).
            .done, .capped => if (!zstdOracleLenient(d.err.?)) return zstdDisagree(input, "the runner's refuses what std takes", d.err, oracle.err),
        },
    }

    // Work in proportion to the input: a block is 4 bytes at the least and holds 128 KiB at the most.
    if (mine != .capped) try std.testing.expect(mine_len <= (input.len / 4 + 1) * std.compress.zstd.block_size_max);
    const took = started.durationTo(std.Io.Timestamp.now(io, .awake)).nanoseconds;
    try std.testing.expect(took < zstd_seconds * std.time.ns_per_s);
}

fn zstdDisagree(input: []const u8, what: []const u8, ours: ?zstd.Error, theirs: ?std.compress.zstd.Decompress.Error) error{ZstdDisagreement} {
    std.debug.print("zstd: {s} (runner's: {?s}, std's: {?s}), {d} input bytes\n", .{
        what,
        if (ours) |e| @errorName(e) else null,
        if (theirs) |e| @errorName(e) else null,
        input.len,
    });
    return error.ZstdDisagreement;
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

// --- secret masking ---

test "fuzz: secret masking" {
    try std.testing.fuzz({}, secretMasking, .{
        .corpus = comptime seeds(&.{
            // A job secret and an added mask, raw, encoded and split across records.
            &.{ "s3cret-value\x00\x01added-mask", "plain s3cret-value text\n\x04\x01after \x02\x01 and \x03\x01\x00 \x03\x01\x09 \x03\x01\x12\n", "\x05\x03\x07" },
            // Overlapping, touching and prefix masks, and a long line of them.
            &.{ "ab\x00bcdef\x00\x01aaa\x00\x01abc", "xabcdefy aaaaa abab abcdef\n\x04\x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bcdefab\n", "\x01" },
            // A multi-line mask, and the forms GitHub's encoders give.
            &.{ "line-one\nline-two\x00\x01pa\"ss'w<o>rd&+s3", "\x02\x00\n\x04\x01\x03\x01\x03 \x03\x01\x04 \x03\x01\x05 \x03\x01\x0a \x03\x01\x11\n", "\x40" },
            // A line cut while a secret is in it, with CRLF and multi-byte UTF-8 around it.
            &.{ "s3cret-välue", "0123456789abc s3cret-välue 98765\r\n0123456789abc s3cret-välue\r\r\n", "\x00\x05" },
        }) ++ &[_][]const u8{
            // Found by fuzzing: a long `::add-mask::` line, cut and its tail shown.
            @embedFile("fuzz_corpus/secret-masking-cut-command.bin"),
        },
    });
}

/// Masks (a job's secrets, and `::add-mask::` values a step prints) and a step's output, and the
/// log that output becomes, through the path a direct session's lines take (`JobLog.SpanDemux`:
/// records joined into lines, long lines cut, workflow commands, the sink's masking):
///
///   - the log, line by line, is what GitHub's runner logs for the same output: each line masked
///     as `SecretMasker.MaskSecrets` masks it (`redact.modelGitHub`), with every form of every
///     mask added before it (`redact.forms`), however the output was split into records and
///     however long its lines (a cut line's parts, joined, mask as the whole line);
///   - no mask shows as written, nor base64 of it at any offset in a longer encoded text;
///   - `redact.write` and `redact.Set` mask arbitrary text as `modelGitHub` does, and a line cut
///     where `redact.cut` says masks, part by part, as the whole.
///
/// Inputs: masks, `\x00` apart, each at most 12 bytes, `\x01` first for one the step adds; the
/// output, where `\x02 k` is mask k as written, `\x03 k e` mask k in encoding e (base64 at an
/// offset, JSON, URL, XML, command line, expression) and `\x04 k` a line adding mask k; then the
/// records' sizes, after a first byte that sets the line length where lines are cut.
fn secretMasking(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var mbuf: [80]u8 = undefined;
    var sbuf: [1024]u8 = undefined;
    var cbuf: [32]u8 = undefined;
    const mspec = take(smith, &mbuf);
    const sspec = take(smith, &sbuf);
    const cspec = take(smith, &cbuf);

    // The masks: job secrets, and those the step adds.
    var masks: [4][]const u8 = undefined;
    var added: [4]bool = undefined;
    var n: usize = 0;
    var parts = std.mem.splitScalar(u8, mspec, 0);
    while (parts.next()) |p| {
        if (n == masks.len) break;
        added[n] = p.len > 0 and p[0] == 1;
        const raw = if (added[n]) p[1..] else p;
        const m = try ar.dupe(u8, raw[0..@min(raw.len, 12)]);
        // Kept out of the log's own syntax: commands and markers.
        for (m) |*c| if (c.* == ':' or c.* == '#') {
            c.* = '.';
        };
        masks[n] = m;
        n += 1;
    }
    const mask_list = masks[0..n];

    // The oracle on its own, over the raw output bytes as text.
    {
        var all: std.ArrayList([]const u8) = .empty;
        var set: redact.Set = .{};
        for (mask_list) |m| for (try redact.forms(ar, m)) |f| {
            try all.append(ar, f);
            try set.add(ar, f);
        };
        const want = try redact.modelGitHub(ar, sspec, all.items);
        try std.testing.expectEqualStrings(want, try redact.alloc(ar, sspec, all.items));
        var got: std.Io.Writer.Allocating = .init(ar);
        try set.write(&got.writer, sspec);
        try std.testing.expectEqualStrings(want, got.written());
        if (redact.cut(sspec, all.items, &set, false)) |c| {
            const joined = try std.mem.concat(ar, u8, &.{
                try redact.modelGitHub(ar, sspec[0..c.at], all.items),
                try redact.modelGitHub(ar, sspec[c.at..], all.items),
            });
            try std.testing.expectEqualStrings(try oneSpans(ar, want), try oneSpans(ar, joined));
        }
    }

    const max_line: usize = 16 + @as(usize, if (cspec.len > 0) cspec[0] % 48 else 0);
    const sizes = if (cspec.len > 1) cspec[1..] else "\x06";

    // The step's output.
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < sspec.len) : (i += 1) {
        const c = sspec[i];
        switch (c) {
            2, 3, 4 => {
                if (n == 0 or i + 1 >= sspec.len) continue;
                const m = mask_list[sspec[i + 1] % n];
                i += 1;
                if (c == 2) {
                    try out.appendSlice(ar, m);
                } else if (c == 3) {
                    const e: u8 = if (i + 1 < sspec.len) sspec[i + 1] else 0;
                    i += 1;
                    try out.appendSlice(ar, try encoded(ar, m, e));
                } else if ((try redact.forms(ar, m)).len > 0) {
                    if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try out.append(ar, '\n');
                    try out.appendSlice(ar, "::add-mask::");
                    for (m) |b| switch (b) {
                        '%' => try out.appendSlice(ar, "%25"),
                        '\r' => try out.appendSlice(ar, "%0D"),
                        '\n' => try out.appendSlice(ar, "%0A"),
                        else => try out.append(ar, b),
                    };
                    try out.append(ar, '\n');
                }
            },
            ':', '#' => try out.append(ar, '.'),
            else => try out.append(ar, c),
        }
    }
    if (out.items.len == 0 or out.items[out.items.len - 1] != '\n') try out.append(ar, '\n');
    // A `\r` that ends a line is the line's end, not its text; and no line so long that it is
    // cut without a place free of secrets (four times `max_line`: see `SpanDemux.onRecord`).
    var text: std.ArrayList(u8) = .empty;
    var run: usize = 0;
    for (out.items) |b| {
        try text.append(ar, b);
        run = if (b == '\n') 0 else run + 1;
        if (run == 4 * max_line - 1) {
            try text.append(ar, '\n');
            run = 0;
        }
    }
    for (text.items[0 .. text.items.len - 1], text.items[1..]) |*b, next| {
        if (b.* == '\r' and next == '\n') b.* = '.';
    }

    // What GitHub's runner logs for it.
    var active: std.ArrayList([]const u8) = .empty;
    for (mask_list, added[0..n]) |m, add| if (!add) try active.appendSlice(ar, try redact.forms(ar, m));
    var shown: std.ArrayList([]const u8) = .empty;
    for (mask_list, added[0..n]) |m, add| if (!add) try shown.append(ar, m);
    var want: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, text.items[0 .. text.items.len - 1], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "::add-mask::")) {
            const value = try std.mem.replaceOwned(u8, ar, line["::add-mask::".len..], "%0A", "\n");
            const v2 = try std.mem.replaceOwned(u8, ar, value, "%0D", "\r");
            const v3 = try std.mem.replaceOwned(u8, ar, v2, "%25", "%");
            try active.appendSlice(ar, try redact.forms(ar, v3));
            try shown.append(ar, v3);
            continue;
        }
        const masked = try redact.modelGitHub(ar, line, active.items);
        try expectNoneShown(ar, masked, shown.items);
        try want.appendSlice(ar, masked);
    }

    // What this runner logs for it.
    var log_out: std.Io.Writer.Allocating = .init(ar);
    var log: sink.LogSink = .{ .stdout = .{ .writer = &log_out.writer } };
    var job_secrets: std.ArrayList([]const u8) = .empty;
    for (mask_list, added[0..n]) |m, add| if (!add) try job_secrets.append(ar, m);
    log.setSecrets(try redact.expand(ar, job_secrets.items));
    var live = [_]std.atomic.Value(u32){.init(0)};
    var ended = [_]std.atomic.Value(bool){.init(false)};
    var replayed = [_]bool{false};
    var cmds = [_]JobLog.StepCommands{.{}};
    var line_counts = [_]u32{ 0, 0 };
    var sh: JobLog = .{
        .io = std.testing.io,
        .arena = ar,
        .log = &log,
        .sink_job_id = 0,
        .live_lines = &live,
        .ended = &ended,
        .replayed_steps = &replayed,
        .commands = &cmds,
        .line_counts = &line_counts,
        .mark = "m",
    };
    var sd: JobLog.SpanDemux = .{ .sh = &sh, .gpa = std.testing.allocator, .max_line = max_line };
    defer sd.deinit();
    JobLog.SpanDemux.onRecord(&sd, .{ .span = "s", .stream = 1, .text = dagger.marker ++ "begin 1 m\n" });
    var at: usize = 0;
    var k: usize = 0;
    while (at < text.items.len) : (k += 1) {
        const len = @min(1 + sizes[k % sizes.len] % 64, text.items.len - at);
        JobLog.SpanDemux.onRecord(&sd, .{ .span = "s", .stream = 1, .text = text.items[at..][0..len] });
        at += len;
    }
    var got: std.ArrayList(u8) = .empty;
    var logged = std.mem.splitScalar(u8, log_out.written(), '\n');
    while (logged.next()) |l| {
        if (l.len == 0) continue;
        const prefix = "[job 0 step 1 stdout] ";
        try std.testing.expect(std.mem.startsWith(u8, l, prefix));
        try got.appendSlice(ar, l[prefix.len..]);
    }
    try expectSameLog(try oneSpans(ar, want.items), try oneSpans(ar, got.items));
}

/// `want` and `got` the same, or where they part shown escaped (binary logs are unreadable as
/// expectEqualStrings prints them).
fn expectSameLog(want: []const u8, got: []const u8) !void {
    const at = std.mem.indexOfDiff(u8, want, got) orelse return;
    const from = at -| 40;
    std.debug.print("logs differ at byte {d}:\n want {f}\n  got {f}\n", .{
        at,
        std.ascii.hexEscape(want[from..@min(want.len, at + 40)], .lower),
        std.ascii.hexEscape(got[from..@min(got.len, at + 40)], .lower),
    });
    return error.LogDiffers;
}

/// `text` with masks that touch made one, as they are within a line: a line cut between two
/// spans that touch masks each part to its own `***`.
fn oneSpans(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var t = text;
    while (std.mem.indexOf(u8, t, redact.mask ++ redact.mask) != null)
        t = try std.mem.replaceOwned(u8, arena, t, redact.mask ++ redact.mask, redact.mask);
    return t;
}

/// Mask `m` as encoding `e` writes it: base64 of it after 0 to 2 bytes and before 0 to 2 more,
/// JSON, URL encoding, XML, a command line's `\"`, an expression's `''`.
fn encoded(arena: std.mem.Allocator, m: []const u8, e: u8) ![]const u8 {
    switch (e % 6) {
        0 => {
            const before = "xy"[0 .. (e / 6) % 3];
            const after = "zw"[0 .. (e / 18) % 3];
            const plain = try std.mem.concat(arena, u8, &.{ before, m, after });
            const enc = std.base64.standard.Encoder;
            const out = try arena.alloc(u8, enc.calcSize(plain.len));
            return enc.encode(out, plain);
        },
        1 => {
            var w: std.Io.Writer.Allocating = .init(arena);
            try std.json.Stringify.encodeJsonStringChars(m, .{}, &w.writer);
            return w.written();
        },
        2 => {
            var out: std.ArrayList(u8) = .empty;
            for (m) |c| {
                if (std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "-._~", c) != null)
                    try out.append(arena, c)
                else
                    try out.print(arena, "%{X:0>2}", .{c});
            }
            return out.items;
        },
        3 => {
            var out: std.ArrayList(u8) = .empty;
            for (m) |c| try out.appendSlice(arena, switch (c) {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&apos;",
                else => &.{c},
            });
            return out.items;
        },
        4 => return std.mem.replaceOwned(u8, arena, m, "\"", "\\\""),
        else => return std.mem.replaceOwned(u8, arena, m, "'", "''"),
    }
}

/// No mask in `masks` shows in `line`, a line as logged: not as written (trimmed, as a secret is
/// masked), nor the part of its base64 that only its own bytes make, at any offset in a longer
/// encoded text. A mask with `*` in it is left out: `***` itself could hold it.
fn expectNoneShown(arena: std.mem.Allocator, line: []const u8, masks: []const []const u8) !void {
    for (masks) |raw| {
        const m = std.mem.trim(u8, raw, &std.ascii.whitespace);
        if (m.len == 0 or std.mem.indexOfScalar(u8, m, '*') != null) continue;
        if (std.mem.indexOf(u8, line, m) != null) {
            std.debug.print("mask {f} shown in {f}\n", .{ std.ascii.hexEscape(m, .lower), std.ascii.hexEscape(line, .lower) });
            return error.MaskShown;
        }
        if (m.len < 6) continue;
        for (0..3) |shift| {
            const bytes = m[shift..];
            const enc = std.base64.standard.Encoder;
            const full = try arena.alloc(u8, enc.calcSize(bytes.len));
            _ = enc.encode(full, bytes);
            const own = full[0 .. bytes.len * 8 / 6];
            if (own.len >= 8 and std.mem.indexOf(u8, line, own) != null) {
                std.debug.print("base64 of mask {f} shown in {f}\n", .{ std.ascii.hexEscape(m, .lower), std.ascii.hexEscape(line, .lower) });
                return error.MaskShown;
            }
        }
    }
}

// --- file commands ---

test "fuzz: file commands" {
    try std.testing.fuzz({}, fileCommands, .{ .corpus = comptime seeds(&.{
        &.{ "a=1\nmsg<<EOF\nline one\nk=v << not one\nEOF\nafter=ok\n", "EOF\x00v\x00x\nEOF\r\nINJECTED=1\x00", "/usr/bin\r/opt/x\n\n" },
        &.{ "a=1\r\nb<<D\r\nx\r\nD\r\n\r\n", "ghadelimiter_7f3a\x00naïve ✓\x00\x00EOF\x00", "\xEF\xBB\xBF/bin\n" },
        &.{ "\xEF\xBB\xBFa<<E\nx", "E\x00 E\nE \nxE\x00=x\x00", "::zig-file-command::env 3\nA=1\n" },
        &.{ "v<<EOF\n::zig-file-command::env 13\nBASH_ENV=/x\n\nEOF\n=x\nm<<\n", "D\x00a\nD\x00", "" },
    }) });
}

/// The file commands a step writes, read as GitHub's runner reads them:
///
///   - GITHUB_ENV, GITHUB_OUTPUT and GITHUB_STATE give the entries, and fail where,
///     `EnvFileKeyValuePairs` (FileCommandManager.cs) gives and fails on Linux (`ghKeyValues`, a
///     port of it), but for a `=value` line, which fails here (`commands.parseKeyValues`);
///   - entries written as `name<<DELIMITER`, with values holding anything (CRLF, the delimiter
///     inside a line, multi-byte UTF-8), come back as written, unless a value has a line that is
///     the delimiter exactly: only that ends a value early;
///   - GITHUB_PATH gives `File.ReadAllLines`'s lines, trimmed, without the empty ones;
///   - the step's file commands joined into one file (`scripts.combine`) come back each as written,
///     whatever they hold, and reading any text as one never fails but by returning nothing.
///
/// Inputs: a file's text; a delimiter, then values, `\x00` apart, written as entries; GITHUB_PATH's
/// text.
fn fileCommands(_: void, smith: *Smith) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var fbuf: [2048]u8 = undefined;
    var ebuf: [1024]u8 = undefined;
    var pbuf: [512]u8 = undefined;
    const file = take(smith, &fbuf);
    const spec = take(smith, &ebuf);
    const paths = take(smith, &pbuf);

    // As GitHub's runner reads the file.
    try expectKeyValuesLikeGitHub(ar, file);

    // Entries written with a delimiter.
    var it = std.mem.splitScalar(u8, spec, 0);
    const delim = it.first();
    if (delim.len > 0 and std.mem.indexOfScalar(u8, delim, '\n') == null) {
        var text: std.ArrayList(u8) = .empty;
        var values: std.ArrayList([]const u8) = .empty;
        var safe = true;
        while (it.next()) |v| {
            if (values.items.len == 8) break;
            try text.print(ar, "N{d}<<{s}\n{s}\n{s}\n", .{ values.items.len, delim, v, delim });
            try values.append(ar, v);
            var vl = std.mem.splitScalar(u8, v, '\n');
            while (vl.next()) |l| if (std.mem.eql(u8, l, delim)) {
                safe = false;
            };
        }
        const parsed = try commands.parseKeyValues(ar, text.items);
        if (safe) {
            try std.testing.expect(parsed.invalid == null);
            try std.testing.expectEqual(values.items.len, parsed.pairs.len);
            for (parsed.pairs, values.items, 0..) |p, v, k| {
                try std.testing.expectEqualStrings(try std.fmt.allocPrint(ar, "N{d}", .{k}), p.name);
                try std.testing.expectEqualStrings(v, p.value);
            }
        }
        // Each a variable: with a `\r` before the newlines, a CRLF file's.
        const crlf = try std.mem.replaceOwned(u8, ar, text.items, "\n", "\r\n");
        try expectKeyValuesLikeGitHub(ar, crlf);
    }

    // GITHUB_PATH.
    var want_paths: std.ArrayList([]const u8) = .empty;
    const ptext = if (std.mem.startsWith(u8, paths, "\xEF\xBB\xBF")) paths[3..] else paths;
    var pl = std.mem.tokenizeAny(u8, ptext, "\r\n");
    while (pl.next()) |l| {
        const t = std.mem.trim(u8, l, " \t");
        if (t.len > 0) try want_paths.append(ar, t);
    }
    const got_paths = try commands.parsePaths(ar, paths);
    try std.testing.expectEqual(want_paths.items.len, got_paths.len);
    for (want_paths.items, got_paths) |w, g| try std.testing.expectEqualStrings(w, g);

    // The combined file: each part as written, the markers inside them their text.
    const parts = [_][2][]const u8{
        .{ "output", file }, .{ "env", spec }, .{ "path", paths }, .{ "step_summary", file[0 .. file.len / 2] }, .{ "state", "" },
    };
    const all = try scripts.combine(ar, &parts, "j1");
    for (parts) |p| try std.testing.expectEqualStrings(p[1], scripts.combinedPart(all, p[0]).?);
    try std.testing.expectEqualStrings("j1", scripts.combinedPart(all, "ran").?);
    try std.testing.expect(scripts.combinedWhole(all));
    // Any text: a part is a slice of it, or nothing.
    for ([_][]const u8{ file, spec, paths }) |t| for (scripts.fc_kinds ++ [_][]const u8{"ran"}) |kind| {
        if (scripts.combinedPart(t, kind)) |part| {
            try std.testing.expect(@intFromPtr(part.ptr) >= @intFromPtr(t.ptr));
            try std.testing.expect(@intFromPtr(part.ptr) + part.len <= @intFromPtr(t.ptr) + t.len);
        }
        _ = scripts.combinedWhole(t);
    };
}

/// `commands.parseKeyValues` gives the entries `ghKeyValues` gives, and fails where it fails, but
/// for an empty name, which it refuses where GitHub sets it.
fn expectKeyValuesLikeGitHub(ar: std.mem.Allocator, file: []const u8) !void {
    const got = try commands.parseKeyValues(ar, file);
    const want = try ghKeyValues(ar, file);
    var same = want.pairs.len;
    for (want.pairs, 0..) |p, k| if (p.name.len == 0) {
        same = k;
        break;
    };
    if (same < want.pairs.len) {
        try std.testing.expectEqual(same, got.pairs.len);
        try std.testing.expect(got.invalid != null);
    } else {
        try std.testing.expectEqual(want.pairs.len, got.pairs.len);
        try std.testing.expectEqual(want.failed, got.invalid != null);
    }
    for (got.pairs, want.pairs[0..got.pairs.len]) |g, w| {
        try std.testing.expectEqualStrings(w.name, g.name);
        try std.testing.expectEqualStrings(w.value, g.value);
    }
}

/// What GitHub's runner reads from a GITHUB_ENV, GITHUB_OUTPUT or GITHUB_STATE file on Linux:
/// `EnvFileKeyValuePairs.GetEnumerator` in FileCommandManager.cs, line for line, with
/// `File.ReadAllText`'s byte order mark dropped. `failed` where it throws; `pairs` those yielded
/// before.
fn ghKeyValues(arena: std.mem.Allocator, file: []const u8) !struct { pairs: []const job_mod.EnvVar, failed: bool } {
    const text = if (std.mem.startsWith(u8, file, "\xEF\xBB\xBF")) file[3..] else file;
    const ReadLine = struct {
        /// `ReadLine(text, ref index, out newline)`, on Linux: the line, and whether a `\n` ended it.
        fn read(t: []const u8, index: *usize) ?struct { []const u8, bool } {
            if (index.* >= t.len) return null;
            const start = index.*;
            const lf = std.mem.indexOfScalarPos(u8, t, start, '\n') orelse {
                index.* = t.len;
                return .{ t[start..], false };
            };
            index.* = lf + 1;
            return .{ t[start..lf], true };
        }
    };
    var pairs: std.ArrayList(job_mod.EnvVar) = .empty;
    var index: usize = 0;
    while (ReadLine.read(text, &index)) |r| {
        const line = r[0];
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=');
        const hd = std.mem.indexOf(u8, line, "<<");
        if (eq != null and (hd == null or eq.? < hd.?)) {
            try pairs.append(arena, .{ .name = line[0..eq.?], .value = line[eq.? + 1 ..] });
        } else if (hd != null and (eq == null or hd.? < eq.?)) {
            const key = line[0..hd.?];
            const delimiter = line[hd.? + 2 ..];
            if (key.len == 0 or delimiter.len == 0) return .{ .pairs = pairs.items, .failed = true };
            const start = index;
            var end = index;
            var temp = ReadLine.read(text, &index);
            while (temp == null or !std.mem.eql(u8, temp.?[0], delimiter)) {
                const t = temp orelse return .{ .pairs = pairs.items, .failed = true };
                if (!t[1]) return .{ .pairs = pairs.items, .failed = true };
                end = index - 1;
                temp = ReadLine.read(text, &index);
            }
            try pairs.append(arena, .{ .name = key, .value = if (end > start) text[start..end] else "" });
        } else return .{ .pairs = pairs.items, .failed = true };
    }
    return .{ .pairs = pairs.items, .failed = false };
}

// --- broker and run service messages ---

/// The heap a fuzz target's parser gets, so a parse that takes more than it should fails the
/// target with OutOfMemory rather than going unseen.
var capped_heap: [4 << 20]u8 = undefined;

test "fuzz: job messages" {
    try std.testing.fuzz({}, jobMessages, .{ .corpus = comptime seeds(&.{
        &.{ "{\"messageType\":\"RunnerJobRequest\",\"body\":\"{\\\"runner_request_id\\\":\\\"1\\\",\\\"run_service_url\\\":\\\"https://run/\\\"}\"}", "extra", "[1,{\"a\":null}]" },
        &.{ "{\"runner_request_id\":\"r\",\"run_service_url\":\"u\",\"billing_owner_id\":\"b\",\"should_acknowledge\":true}", "should_acknowledge", "\"x\"" },
        &.{ job_base, "Steps", "{\"type\":\"action\"}" },
        &.{ "{\"messageType\":\"JobCancellation\",\"body\":\"{\\\"jobId\\\":\\\"j\\\",\\\"timeout\\\":\\\"0.00:05:00.0000\\\"}\"}", "timeout", "1e999" },
        &.{ "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{\"body\":{\"bytesValue\":\"aGk=\"},\"attributes\":[{\"key\":\"stdio.stream\",\"value\":{\"intValue\":\"-9\"}}],\"spanId\":\"s\"}]}]}]}", "", "" },
        &.{ "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]", "", "" },
    }) });
}

/// A job message with what `job.parse` needs and one step.
const job_base =
    \\{"plan":{"planId":"p"},"jobId":"j","jobName":"zig","resources":{"endpoints":[{"authorization":{"parameters":{"AccessToken":"t"}}}]},
    \\ "contextData":{"github":{"t":2,"d":[{"k":"repository","v":"o/r"}]}},
    \\ "steps":[{"type":"action","reference":{"type":"script"},"id":"s1","name":"Run","condition":"success()",
    \\  "inputs":{"type":2,"map":[{"Key":{"lit":"script"},"Value":{"lit":"echo hi"}}]}}]}
;

/// The messages the broker and the run service send, as the runner reads them: a poll's message
/// (`exchange.jsonString`), the job request in its body (`runservice.parseJobRequest`), the job
/// (`job.parse`), a cancellation's timeout (`timeSpanMs`), and the engine's log records
/// (`engine.eachLogRecord`). Each returns, an answer or an error, within a heap of a fixed size
/// (no panic, and memory in proportion to the message); and a field the runner does not know is
/// ignored, as GitHub's runner ignores one, wherever it is, whatever it holds.
///
/// Inputs: a message; a field's name and its value (JSON, or else a string), added to a job
/// request, to a job and to its step.
fn jobMessages(_: void, smith: *Smith) !void {
    var mbuf: [4096]u8 = undefined;
    var kbuf: [64]u8 = undefined;
    var vbuf: [512]u8 = undefined;
    const msg = take(smith, &mbuf);
    const key = take(smith, &kbuf);
    const value = take(smith, &vbuf);
    var fba: std.heap.FixedBufferAllocator = .init(&capped_heap);
    const ar = fba.allocator();

    if (try exchange.jsonString(ar, msg, "messageType")) |t| _ = t;
    if (try exchange.jsonString(ar, msg, "body")) |body| {
        _ = runservice.parseJobRequest(ar, body) catch |e| if (e == error.OutOfMemory) return e;
    }
    _ = runservice.parseJobRequest(ar, msg) catch |e| if (e == error.OutOfMemory) return e;
    _ = job_mod.parse(ar, msg) catch |e| if (e == error.OutOfMemory) return e;
    _ = loop_job.timeSpanMs(msg);
    const Count = struct {
        fn on(ptr: *anyopaque, rec: engine.LogRecord) void {
            _ = ptr;
            std.debug.assert(rec.stream <= 2);
        }
    };
    var dummy: u8 = 0;
    engine.eachLogRecord(ar, msg, .{ .ptr = &dummy, .onRecord = Count.on });
    try std.testing.expect(fba.end_index < capped_heap.len);

    // An unknown field, anywhere, changes nothing.
    fba.reset();
    const known = [_][]const u8{
        "runner_request_id", "run_service_url", "billing_owner_id", "should_acknowledge",
        "plan",              "jobId",           "jobName",          "resources",
        "contextData",       "steps",           "type",             "reference",
        "id",                "name",            "condition",        "inputs",
    };
    for (known) |k| if (std.ascii.eqlIgnoreCase(k, key)) return;
    // JSON is UTF-8: a message that is not is malformed, not one with an unknown field.
    if (!std.unicode.utf8ValidateSlice(key) or !std.unicode.utf8ValidateSlice(value)) return;
    var kw: std.Io.Writer.Allocating = .init(ar);
    try std.json.Stringify.encodeJsonString(key, .{}, &kw.writer);
    // Parsed, not `std.json.validate`d: that allows a repeated key, which parsing refuses.
    const parsed = if (std.json.parseFromSliceLeaky(std.json.Value, ar, value, .{})) |_| true else |e| switch (e) {
        error.OutOfMemory => return e,
        else => false,
    };
    const val = if (parsed) value else v: {
        var vw: std.Io.Writer.Allocating = .init(ar);
        try std.json.Stringify.encodeJsonString(value, .{}, &vw.writer);
        break :v vw.written();
    };
    const field = try std.fmt.allocPrint(ar, "{s}:{s},", .{ kw.written(), val });
    const req = try std.fmt.allocPrint(ar, "{{{s}\"runner_request_id\":\"r\",\"run_service_url\":\"u\",\"should_acknowledge\":true}}", .{field});
    const jr = try runservice.parseJobRequest(ar, req);
    try std.testing.expectEqualStrings("r", jr.runner_request_id);
    try std.testing.expect(jr.should_acknowledge);
    const top = try std.mem.concat(ar, u8, &.{ "{", field, job_base[1..] });
    const in_step = try std.mem.replaceOwned(u8, ar, job_base, "{\"type\":\"action\"", try std.mem.concat(ar, u8, &.{ "{", field, "\"type\":\"action\"" }));
    for ([_][]const u8{ top, in_step }) |doc| {
        const job = try job_mod.parse(ar, doc);
        try std.testing.expectEqualStrings("j", job.job_id);
        try std.testing.expectEqual(@as(usize, 1), job.steps.len);
    }
}

// --- TLS records (the network library's rustls, behind the C ABI) ---

test "fuzz: TLS records" {
    const flight13 = @embedFile("fuzz_corpus/tls/flight13.bin");
    const flight12 = @embedFile("fuzz_corpus/tls/flight12.bin");
    try std.testing.fuzz({}, tlsRecords, .{
        .corpus = comptime seeds(&.{
            // The server's first flight, in one piece and in two (verifying, then not).
            &.{ "\x01", flight13 },
            &.{ "\x00", flight13[0..90], flight13[90..] },
            &.{ "\x01", flight12 },
            &.{ "\x00", flight12[0..60], flight12[60..400], flight12[400..] },
            // An alert, and records of the wrong version and length.
            &.{ "\x01", "\x15\x03\x03\x00\x02\x02\x28" },
            &.{ "\x01", "\x16\x03\x01\x00\x04\x02\x00\x00\x00", "\x17\x03\x03\xff\xff" },
        }),
    });
}

/// What the server of one TLS connection sends, in chunks of any size and content: the library
/// returns an error or goes on, never panics (which would end the process: `panic = "abort"`), and
/// never holds more than it was given. Input: a string of flags (bit 0: check the server's
/// certificate), then the server's chunks.
fn tlsRecords(_: void, smith: *Smith) !void {
    var flags_buf: [8]u8 = undefined;
    const flags = take(smith, &flags_buf);
    const verify = flags.len > 0 and flags[0] & 1 != 0;
    const before = @import("zr_net.zig").heap().bytes;
    {
        const p = tls_stream.Probe.init(.{
            .host = "db.example",
            .verify = verify,
            .roots_pem = @embedFile("fuzz_corpus/tls/ca.pem"),
        }) orelse return error.TlsProbeNotCreated;
        defer p.deinit();
        _ = p.drain();
        var total: usize = 0;
        var chunk: [20000]u8 = undefined;
        while (!smith.eos()) {
            const bytes = take(smith, &chunk);
            total += bytes.len;
            if (!p.feed(bytes)) break;
        }
        // What the library holds for one connection is bounded by its buffers (rustls limits what it
        // keeps unread to 64 KiB of plaintext and about as much of ciphertext), however much it was fed.
        const during = @import("zr_net.zig").heap().bytes;
        try std.testing.expect(during <= before + 512 * 1024 + total / 8);
    }
    // And all of it is returned when the connection is.
    try std.testing.expect(@import("zr_net.zig").heap().bytes <= before + 64 * 1024);
}

// --- HTTP/2 framing ---

test "fuzz: HTTP2 frames" {
    try std.testing.fuzz({}, http2Frames, .{
        .corpus = comptime seeds(&.{
            // SETTINGS, PING, HEADERS for a health check, DATA, WINDOW_UPDATE, GOAWAY.
            &.{"\x04\x00\x00\x06\x00\x03\x00\x00\x00\x64\x06\x00\x00\x0812345678\x01\x04\x01\x1e\x04\x1c/grpc.health.v1.Health/Check\x00\x01\x01\x05\x00\x00\x00\x00\x00\x08\x00\x00\x04\x00\x00\x00\x10\x07\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"},
            // Padding and priority, and a header block in CONTINUATIONs.
            &.{"\x01\x28\x01\x0a\x02\x00\x00\x00\x03\x10\x82\x84\x00\x00\x09\x00\x01\x01\x86\x09\x04\x01\x01\x87"},
            // CONTINUATIONs that never end the block, repeated; a frame past 16 KiB.
            &.{"\x01\x00\x01\x40\x41\x49\x00\x01\xff\x41\x80\x00\x01\xff"},
        }),
    });
}

/// What "fuzz: HTTP2 frames" hands the connection, a few hundred bytes a read; a global, so the
/// reader needs no cast of its context.
const H2Input = struct {
    data: []const u8 = "",
    pos: usize = 0,

    fn read(_: *anyopaque, dst: []u8) anyerror!usize {
        const s = &h2_input;
        const n = @min(dst.len, 777, s.data.len - s.pos);
        @memcpy(dst[0..n], s.data[s.pos..][0..n]);
        s.pos += n;
        return n;
    }
};
var h2_input: H2Input = .{};

/// The engine's HTTP/2 connection (`engine.h2.serve`), with frames of any type, flags, stream,
/// length and payload, in any order: SETTINGS, PING, WINDOW_UPDATE, GOAWAY, DATA, HEADERS with
/// padding and priority, CONTINUATION sequences, repeated (a flood), and longer than a peer may
/// send. It returns or fails with an error, never panics, and never takes more memory than a heap
/// of a fixed size; it answers at most one call per HEADERS frame.
///
/// Input: frames, each a type (`| 0x40`: the frame repeated, as many times as its length byte
/// says; `| 0x80`: its length times 128), its flags, its stream (0 to 3) and its length (a byte),
/// then its payload, from what follows and zeros past it.
fn http2Frames(_: void, smith: *Smith) !void {
    var sbuf: [2048]u8 = undefined;
    const spec = take(smith, &sbuf);
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var input: std.ArrayList(u8) = .empty;
    try input.appendSlice(ar, engine.h2.preface);
    var headers: usize = 0;
    var i: usize = 0;
    while (i + 4 <= spec.len) {
        const t = spec[i];
        const kind = (t & 0x3f) % 11;
        const len: usize = if (t & 0x80 != 0) @as(usize, spec[i + 3]) * 128 else spec[i + 3];
        const times: usize = if (t & 0x40 != 0) @max(1, spec[i + 3]) else 1;
        var hdr: [9]u8 = undefined;
        std.mem.writeInt(u24, hdr[0..3], @truncate(len), .big);
        hdr[3] = kind;
        hdr[4] = spec[i + 1];
        std.mem.writeInt(u32, hdr[5..9], spec[i + 2] % 4, .big);
        i += 4;
        const have = @min(len, spec.len - i);
        const payload = spec[i..][0..have];
        i += have;
        for (0..times) |_| {
            // Past the most a header block may hold, four times over: more only slows a run.
            if (input.items.len > 4 * engine.h2.max_header_block) break;
            try input.appendSlice(ar, &hdr);
            try input.appendSlice(ar, payload);
            try input.appendNTimes(ar, 0, len - have);
            if (kind == 1) headers += 1;
        }
    }
    h2_input = .{ .data = input.items };
    var in: engine.In = .{ .src = .{ .ptr = &h2_input, .readFn = H2Input.read } };
    var fba: std.heap.FixedBufferAllocator = .init(capped_heap[0 .. 1 << 20]);
    var w: std.Io.Writer.Discarding = .init(&.{});
    if (engine.h2.serve(fba.allocator(), &in, &w.writer)) |answered| {
        try std.testing.expect(answered <= headers);
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        else => {},
    }
}
