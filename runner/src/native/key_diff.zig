//! Why a step was not replayed: the parts a step's key is made of, recorded beside it, and the
//! first part that differs from the last run of the same step.
//!
//! A key is a digest, so a miss says nothing about its cause. Every build system that keys on
//! signatures ends up with a way to see which input changed (bitbake-diffsigs, Bazel's execution
//! log), because the recurring bug is an input the step depends on and the key leaves out, and the
//! recurring question is "why did this not replay?". Here each key's components are written as
//! text next to its layer (`layers/<key>/components`), and the latest for each step, by identity
//! (`identity`), in `steps/<id>`, which outlives an evicted layer. Neither is read to replay: the
//! key is made exactly as before (`Backend.keyFor`), so a record without components is a
//! step with nothing to compare, never a miss.
//!
//! A component is a name and a value: a digest (`sha:` and 16 hex digits, never the content, so
//! no secret and nothing large is kept) or a plain value that is no secret (a user id, a path).
//! At most `max_components` of them and `max_bytes` of text; the rest is one digest.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Sha256 = @import("../sha256.zig").Sha256;

pub const Component = struct { name: []const u8, value: []const u8 };

pub const max_components = 256;
pub const max_bytes = 32 * 1024;

/// A step's index entry that nothing has refreshed for this long is removed (`sweep`).
pub const index_days = 30;

/// The component of a key that is the layer below it. When it is the only one that differs, the
/// cause is in an earlier step (`firstChange`).
pub const parent_name = "parent";

/// `Component`s in the order they were added, bounded. Past the bound, what is added is folded
/// into the one `more` component, so a change in it still shows.
pub const Builder = struct {
    arena: Allocator,
    list: std.ArrayList(Component) = .empty,
    bytes: usize = 0,
    more: ?Sha256 = null,

    pub fn init(arena: Allocator) Builder {
        return .{ .arena = arena };
    }

    /// A plain value: for what is no secret and short (ids, paths the key holds anyway).
    pub fn add(c: *Builder, name: []const u8, value: []const u8) Allocator.Error!void {
        // The text is lines of `name<TAB>value`: a name or value that would break it is a digest.
        const plain = clean(name) and clean(value);
        if (!plain) return c.addDigest(name, value);
        try c.push(name, value);
    }

    /// A digest of `content`, which is never kept.
    pub fn addDigest(c: *Builder, name: []const u8, content: []const u8) Allocator.Error!void {
        var d: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(content, &d, .{});
        const hex = std.fmt.bytesToHex(d[0..8].*, .lower);
        try c.push(name, try std.fmt.allocPrint(c.arena, "sha:{s}", .{&hex}));
    }

    fn push(c: *Builder, name: []const u8, value: []const u8) Allocator.Error!void {
        const size = name.len + value.len + 2;
        if (c.list.items.len >= max_components - 1 or c.bytes + size > max_bytes - 128) {
            if (c.more == null) c.more = .init(.{});
            c.more.?.update(name);
            c.more.?.update("\x00");
            c.more.?.update(value);
            c.more.?.update("\x00");
            return;
        }
        c.bytes += size;
        try c.list.append(c.arena, .{
            .name = try c.arena.dupe(u8, name),
            .value = try c.arena.dupe(u8, value),
        });
    }

    pub fn finish(c: *Builder) Allocator.Error![]const Component {
        if (c.more) |*m| {
            const d = m.finalResult();
            const hex = std.fmt.bytesToHex(d[0..8].*, .lower);
            try c.list.append(c.arena, .{
                .name = "more",
                .value = try std.fmt.allocPrint(c.arena, "sha:{s}", .{&hex}),
            });
            c.more = null;
        }
        return c.list.items;
    }
};

fn clean(s: []const u8) bool {
    return s.len <= 256 and std.mem.indexOfAny(u8, s, "\t\n\r") == null;
}

/// The components as the text stored: `name<TAB>value`, a line each.
pub fn render(arena: Allocator, comps: []const Component) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (comps) |c| {
        try out.appendSlice(arena, c.name);
        try out.append(arena, '\t');
        try out.appendSlice(arena, c.value);
        try out.append(arena, '\n');
    }
    return out.items;
}

/// `render`'s text read back. A line without a tab is skipped, and only `max_components` are read:
/// a file someone changed is a different record, never a crash.
pub fn parse(arena: Allocator, text: []const u8) Allocator.Error![]const Component {
    var list: std.ArrayList(Component) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (list.items.len >= max_components) break;
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
        try list.append(arena, .{
            .name = try arena.dupe(u8, line[0..tab]),
            .value = try arena.dupe(u8, line[tab + 1 ..]),
        });
    }
    return list.items;
}

/// One difference between the components of two keys.
pub const Change = struct {
    name: []const u8,
    /// Null: the component is new.
    old: ?[]const u8,
    /// Null: the component is gone.
    new: ?[]const u8,
};

fn valueOf(comps: []const Component, name: []const u8) ?[]const u8 {
    for (comps) |c| if (std.mem.eql(u8, c.name, name)) return c.value;
    return null;
}

/// The first component, in the new key's order and then the old key's leftovers, whose value
/// differs; the layer below (`parent_name`) only when nothing else does, as its cause is an
/// earlier step's and that one says so. Null when all are alike.
pub fn firstChange(old: []const Component, new: []const Component) ?Change {
    for (new) |c| {
        if (std.mem.eql(u8, c.name, parent_name)) continue;
        const was = valueOf(old, c.name);
        if (was == null or !std.mem.eql(u8, was.?, c.value))
            return .{ .name = c.name, .old = was, .new = c.value };
    }
    for (old) |c| {
        if (std.mem.eql(u8, c.name, parent_name)) continue;
        if (valueOf(new, c.name) == null) return .{ .name = c.name, .old = c.value, .new = null };
    }
    const was = valueOf(old, parent_name);
    const now = valueOf(new, parent_name);
    if (was == null and now == null) return null;
    if (was != null and now != null and std.mem.eql(u8, was.?, now.?)) return null;
    return .{ .name = parent_name, .old = was, .new = now };
}

/// A value for a line: a digest's first 8 digits, a plain value as it is (cut when long).
pub fn short(v: []const u8) []const u8 {
    if (std.mem.startsWith(u8, v, "sha:")) return v["sha:".len..][0..@min(8, v.len - "sha:".len)];
    if (v.len == 64 and std.mem.indexOfNone(u8, v, "0123456789abcdef") == null) return v[0..8];
    return v[0..@min(v.len, 40)];
}

/// What the component is, for a sentence: `tool tree /opt/x` is "the tool tree /opt/x".
fn subject(arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
    if (std.mem.eql(u8, name, "script")) return "the step's script";
    if (std.mem.startsWith(u8, name, "env ")) return std.fmt.allocPrint(
        arena,
        "the environment variable {s}",
        .{name["env ".len..]},
    );
    if (std.mem.eql(u8, name, parent_name)) return "an earlier step";
    return std.fmt.allocPrint(arena, "the {s}", .{name});
}

/// The log line for a miss. One line, digests and plain non-secret values only.
pub fn describe(arena: Allocator, ch: Change) Allocator.Error![]const u8 {
    const what = try subject(arena, ch.name);
    if (std.mem.eql(u8, ch.name, parent_name)) return "Not replayed: an earlier step in this job " ++
        "was not replayed, so the layer under this one is new";
    if (ch.old == null) return std.fmt.allocPrint(arena, "Not replayed: {s} is new ({s})", .{
        what, short(ch.new.?),
    });
    if (ch.new == null) return std.fmt.allocPrint(arena, "Not replayed: {s} is gone (it was {s})", .{
        what, short(ch.old.?),
    });
    return std.fmt.allocPrint(arena, "Not replayed: {s} changed ({s} \u{2192} {s})", .{
        what, short(ch.old.?), short(ch.new.?),
    });
}

/// Who a step is across runs: the cache scope (so the trusted and untrusted records never meet),
/// the repository, the workflow, the job (its display name too, which tells the cells of a
/// matrix apart), and which step of it (`label`). 32 hex digits.
pub fn identity(parts: []const []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update("zig-runner step identity");
    for (parts) |p| {
        var n: [8]u8 = undefined;
        std.mem.writeInt(u64, &n, p.len, .little);
        h.update(&n);
        h.update(p);
    }
    const d = h.finalResult();
    return std.fmt.bytesToHex(d[0..16].*, .lower);
}

/// The index's entry for a step: the key it had when it was last replayed or published, and
/// that key's components.
pub const Entry = struct { key: []const u8, comps: []const Component };

fn indexPath(arena: Allocator, root: []const u8, id: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}/steps/{s}", .{ root, id });
}

pub fn readIndex(arena: Allocator, io: std.Io, root: []const u8, id: []const u8) ?Entry {
    const text = std.Io.Dir.cwd().readFileAlloc(io, indexPath(arena, root, id) catch return null, arena, .limited(max_bytes)) catch
        return null;
    const nl = std.mem.indexOfScalar(u8, text, '\n') orelse return null;
    const head = text[0..nl];
    if (!std.mem.startsWith(u8, head, "key ")) return null;
    const key = head["key ".len..];
    if (key.len != 64) return null;
    return .{ .key = key, .comps = parse(arena, text[nl + 1 ..]) catch return null };
}

/// Makes `id`'s entry the key and components given, if it is not already: written under a
/// temporary name and renamed, so a runner reading it never sees half. Best effort: an index
/// that cannot be written is a miss with nothing to say, never a failed step.
pub fn writeIndex(
    arena: Allocator,
    io: std.Io,
    root: []const u8,
    id: []const u8,
    key_hex: []const u8,
    comps: []const Component,
) void {
    if (readIndex(arena, io, root, id)) |e| if (std.mem.eql(u8, e.key, key_hex)) return;
    const body = render(arena, comps) catch return;
    const text = std.fmt.allocPrint(arena, "key {s}\n{s}", .{ key_hex, body }) catch return;
    var raw: [8]u8 = undefined;
    io.random(&raw);
    const tmp = std.fmt.allocPrint(arena, "{s}/steps/.tmp-{s}", .{
        root, &std.fmt.bytesToHex(raw, .lower),
    }) catch return;
    const cwd = std.Io.Dir.cwd();
    cwd.writeFile(io, .{ .sub_path = tmp, .data = text }) catch return;
    cwd.rename(tmp, cwd, indexPath(arena, root, id) catch return, io) catch |e| {
        std.log.debug("native: the step index cannot be written: {s}", .{@errorName(e)});
        cwd.deleteFile(io, tmp) catch |e2| std.log.debug("native: {s}: {s}", .{ tmp, @errorName(e2) });
    };
}

/// How many entries the layer a step last published held (`Store.Layer.entries`), kept beside its
/// index entry as `<id>.n`: what the next run of the step, when its key has changed and it must
/// run again, uses to choose how its upper is written (`Backend.upperIdmapped`). Null when the
/// step has none, or it cannot be read.
pub fn readEntries(arena: Allocator, io: std.Io, root: []const u8, id: []const u8) ?u64 {
    const path = std.fmt.allocPrint(arena, "{s}/steps/{s}.n", .{ root, id }) catch return null;
    var buf: [32]u8 = undefined;
    const text = std.Io.Dir.cwd().readFile(io, path, &buf) catch return null;
    return std.fmt.parseInt(u64, std.mem.trim(u8, text, " \n"), 10) catch null;
}

/// `readEntries`' file written, if the number changed. Best effort, like `writeIndex`.
pub fn writeEntries(arena: Allocator, io: std.Io, root: []const u8, id: []const u8, entries: u64) void {
    if (readEntries(arena, io, root, id)) |n| if (n == entries) return;
    const path = std.fmt.allocPrint(arena, "{s}/steps/{s}.n", .{ root, id }) catch return;
    const text = std.fmt.allocPrint(arena, "{d}\n", .{entries}) catch return;
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = text }) catch |e|
        std.log.debug("native: the step's size cannot be written: {s}", .{@errorName(e)});
}

test "a step's last layer size is kept and read back" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "steps");
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
    try std.testing.expectEqual(@as(?u64, null), readEntries(arena, std.testing.io, root, "abc"));
    writeEntries(arena, std.testing.io, root, "abc", 41);
    try std.testing.expectEqual(@as(?u64, 41), readEntries(arena, std.testing.io, root, "abc"));
    writeEntries(arena, std.testing.io, root, "abc", 7);
    try std.testing.expectEqual(@as(?u64, 7), readEntries(arena, std.testing.io, root, "abc"));
}

/// Removes the index entries (and temporary files) nothing has refreshed for `index_days`.
pub fn sweep(arena: Allocator, io: std.Io, root: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    const dir_path = std.fmt.allocPrint(arena, "{s}/steps", .{root}) catch return;
    var dir = cwd.openDir(io, dir_path, .{ .iterate = true }) catch return;
    defer dir.close(io);
    const old = std.Io.Clock.real.now(io).toNanoseconds() -
        @as(i128, index_days) * std.time.ns_per_day;
    var it = dir.iterate();
    while (it.next(io) catch null) |e| {
        const st = dir.statFile(io, e.name, .{}) catch continue;
        if (st.mtime.toNanoseconds() < old) dir.deleteFile(io, e.name) catch |err|
            std.log.debug("native: {s}: {s}", .{ e.name, @errorName(err) });
    }
}

// --- the command: zig-runner key-diff ---

pub const command = "key-diff";

/// The layer whose key starts with `prefix` (at least 6 digits), as its full name; an error
/// message when none does or several do.
fn resolve(arena: Allocator, io: std.Io, root: []const u8, prefix: []const u8) ![]const u8 {
    if (prefix.len < 6 or prefix.len > 64 or
        std.mem.indexOfNone(u8, prefix, "0123456789abcdef") != null) return error.BadKey;
    const dir_path = try std.fmt.allocPrint(arena, "{s}/layers", .{root});
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    var found: ?[]const u8 = null;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (!std.mem.startsWith(u8, e.name, prefix)) continue;
        if (found != null) return error.Ambiguous;
        found = try arena.dupe(u8, e.name);
    }
    return found orelse error.NoSuchKey;
}

fn componentsOf(arena: Allocator, io: std.Io, root: []const u8, key: []const u8) ![]const Component {
    const path = try std.fmt.allocPrint(arena, "{s}/layers/{s}/components", .{ root, key });
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_bytes)) catch
        return error.NoComponents;
    return parse(arena, text);
}

/// The two keys' components side by side, a `!` before those that differ.
pub fn diffTable(
    w: *std.Io.Writer,
    a_key: []const u8,
    b_key: []const u8,
    a: []const Component,
    b: []const Component,
) !void {
    try w.print("a: {s}\nb: {s}\n", .{ a_key, b_key });
    var width: usize = "component".len;
    for (a) |c| width = @max(width, c.name.len);
    for (b) |c| width = @max(width, c.name.len);
    width = @min(width, 60);
    var differ: usize = 0;
    const rows = [_]struct { []const Component, []const Component }{ .{ a, b }, .{ b, a } };
    for (rows, 0..) |pair, side| {
        for (pair[0]) |c| {
            // The second pass lists what only b has.
            if (side == 1 and valueOf(pair[1], c.name) != null) continue;
            const other = valueOf(pair[1], c.name);
            const va = if (side == 0) c.value else null;
            const vb = if (side == 0) other else c.value;
            const same = va != null and vb != null and std.mem.eql(u8, va.?, vb.?);
            if (!same) differ += 1;
            try w.print("{s} {s}", .{ if (same) " " else "!", c.name });
            try w.splatByteAll(' ', width -| c.name.len);
            try w.print("  {s}  {s}\n", .{
                if (va) |v| short(v) else "-",
                if (vb) |v| short(v) else "-",
            });
        }
    }
    if (differ == 0) try w.writeAll("no component differs\n") else try w.print(
        "{d} component(s) differ; the first is: {s}\n",
        .{ differ, if (firstChange(a, b)) |c| c.name else "none" },
    );
}

/// `zig-runner key-diff <key-a> <key-b> [--store=DIR]`: keys are the names under `layers/` (a
/// prefix of 6 digits or more will do). 0 when it printed, 1 when a key is unknown or a record
/// has no components (one made before they were kept).
pub fn run(
    arena: Allocator,
    io: std.Io,
    args: []const []const u8,
    default_root: []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
) !u8 {
    var root = default_root;
    var keys: [2][]const u8 = undefined;
    var n: usize = 0;
    for (args) |arg| {
        if (std.mem.startsWith(u8, arg, "--store=")) {
            root = arg["--store=".len..];
        } else if (n < 2 and !std.mem.startsWith(u8, arg, "-")) {
            keys[n] = arg;
            n += 1;
        } else {
            try err.print("key-diff: usage: zig-runner key-diff <key-a> <key-b> [--store=DIR]\n", .{});
            return 1;
        }
    }
    if (n != 2) {
        try err.print("key-diff: usage: zig-runner key-diff <key-a> <key-b> [--store=DIR]\n", .{});
        return 1;
    }
    var full: [2][]const u8 = undefined;
    var comps: [2][]const Component = undefined;
    for (keys, 0..) |k, i| {
        full[i] = resolve(arena, io, root, k) catch |e| {
            try err.print("key-diff: {s}: {s} in {s}/layers\n", .{ k, switch (e) {
                error.BadKey => "not a key (6 to 64 lowercase hex digits)",
                error.Ambiguous => "more than one layer starts with it",
                error.NoSuchKey => "no such layer",
                else => @errorName(e),
            }, root });
            return 1;
        };
        comps[i] = componentsOf(arena, io, root, full[i]) catch {
            try err.print("key-diff: {s} has no components: it was made before they were kept, or by " ++
                "another kind of record\n", .{full[i]});
            return 1;
        };
    }
    try diffTable(out, full[0], full[1], comps[0], comps[1]);
    return 0;
}

// --- tests ---

fn fill64(c: u8) [64]u8 {
    return @splat(c);
}

fn fill32(c: u8) [32]u8 {
    return @splat(c);
}

fn sample(arena: Allocator, script: []const u8, tree: []const u8) ![]const Component {
    var b = Builder.init(arena);
    try b.add(parent_name, &fill64('p'));
    try b.addDigest("script", script);
    try b.add("env HOME", "/home/runner");
    try b.addDigest("tool tree /opt/hostedtoolcache/zig", tree);
    try b.add("uid", "1001");
    return b.finish();
}

test "key diff: components are stable, hold digests and never the content" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const secret = "hunter2-do-not-keep";
    const one = try render(arena, try sample(arena, secret, "tree-a"));
    const two = try render(arena, try sample(arena, secret, "tree-a"));
    try std.testing.expectEqualStrings(one, two);
    try std.testing.expect(std.mem.indexOf(u8, one, secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, one, "script\tsha:") != null);
    const back = try parse(arena, one);
    try std.testing.expectEqual(@as(usize, 5), back.len);
    try std.testing.expectEqualStrings("uid", back[4].name);
}

test "key diff: the first component that differs is named, the parent last" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const old = try sample(arena, "make", "tree-a");
    try std.testing.expect(firstChange(old, old) == null);

    const tree = firstChange(old, try sample(arena, "make", "tree-b")).?;
    try std.testing.expectEqualStrings("tool tree /opt/hostedtoolcache/zig", tree.name);
    const line = try describe(arena, tree);
    try std.testing.expect(std.mem.startsWith(
        u8,
        line,
        "Not replayed: the tool tree /opt/hostedtoolcache/zig changed (",
    ));
    try std.testing.expect(std.mem.indexOf(u8, line, " \u{2192} ") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, line, '\n') == null);

    // Script and tree both changed: the earlier component is named.
    try std.testing.expectEqualStrings("script", firstChange(old, try sample(arena, "make -j", "tree-b")).?.name);

    // Only the parent differs: the cause is an earlier step.
    var moved = try arena.dupe(Component, old);
    moved[0].value = &fill64('q');
    try std.testing.expectEqualStrings(parent_name, firstChange(old, moved).?.name);
    // A parent that differs does not hide a step's own change.
    try std.testing.expectEqualStrings("script", firstChange(moved, try sample(arena, "x", "tree-a")).?.name);

    // A variable only one side has.
    var more = try arena.alloc(Component, old.len + 1);
    @memcpy(more[0..old.len], old);
    more[old.len] = .{ .name = "env CC", .value = "sha:0123456789abcdef" };
    const added = firstChange(old, more).?;
    try std.testing.expect(added.old == null);
    try std.testing.expect(std.mem.indexOf(u8, try describe(arena, added), "environment variable CC is new") != null);
    const gone = firstChange(more, old).?;
    try std.testing.expect(gone.new == null);
}

test "key diff: components are bounded and a value that would break the text is a digest" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var b = Builder.init(arena);
    for (0..1000) |i| try b.add(try std.fmt.allocPrint(arena, "env V{d}", .{i}), "x");
    try b.add("env MULTI", "a\nb\tc");
    const comps = try b.finish();
    try std.testing.expect(comps.len <= max_components);
    try std.testing.expectEqualStrings("more", comps[comps.len - 1].name);
    const text = try render(arena, comps);
    try std.testing.expect(text.len < max_bytes);
    try std.testing.expectEqual(comps.len, (try parse(arena, text)).len);
    // Folded in, so a change there still shows.
    var b2 = Builder.init(arena);
    for (0..1000) |i| try b2.add(try std.fmt.allocPrint(arena, "env V{d}", .{i}), if (i == 999) "y" else "x");
    try b2.add("env MULTI", "a\nb\tc");
    try std.testing.expectEqualStrings("more", firstChange(comps, try b2.finish()).?.name);
}

test "key diff: the index is per identity, so trusted and untrusted records never meet" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const root = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try tmp.dir.createDirPath(io, "steps");

    const trusted = identity(&.{ "repo", "o/r", "ci", "build", "build", "step 3" });
    const untrusted = identity(&.{ "untrusted", "o/r", "ci", "build", "build", "step 3" });
    try std.testing.expect(!std.mem.eql(u8, &trusted, &untrusted));
    try std.testing.expectEqual(trusted, identity(&.{ "repo", "o/r", "ci", "build", "build", "step 3" }));
    // The fields are length-prefixed: moving a byte between two is another step.
    try std.testing.expect(!std.mem.eql(u8, &identity(&.{ "ab", "c" }), &identity(&.{ "a", "bc" })));

    const comps = try sample(arena, "make", "tree-a");
    writeIndex(arena, io, root, &trusted, &fill64('a'), comps);
    const got = readIndex(arena, io, root, &trusted).?;
    try std.testing.expectEqualStrings(&fill64('a'), got.key);
    try std.testing.expectEqual(comps.len, got.comps.len);
    try std.testing.expect(readIndex(arena, io, root, &untrusted) == null);

    // A newer key replaces the entry; the same key leaves it alone.
    writeIndex(arena, io, root, &trusted, &fill64('b'), try sample(arena, "make -j", "tree-a"));
    try std.testing.expectEqualStrings(&fill64('b'), readIndex(arena, io, root, &trusted).?.key);

    // An old record: no entry, no components, nothing to say and nothing broken.
    try std.testing.expect(readIndex(arena, io, root, &fill32('0')) == null);
    try tmp.dir.writeFile(io, .{ .sub_path = "steps/garbage", .data = "not an entry" });
    try std.testing.expect(readIndex(arena, io, root, "garbage") == null);
}

test "key diff: the table marks what differs" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var aw: std.Io.Writer.Allocating = .init(arena);
    try diffTable(&aw.writer, &fill64('a'), &fill64('b'), try sample(arena, "make", "tree-a"), try sample(arena, "make", "tree-b"));
    const text = aw.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "! tool tree /opt/hostedtoolcache/zig") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "  script") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "1 component(s) differ") != null);
}
