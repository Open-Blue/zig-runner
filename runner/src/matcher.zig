//! Problem matchers: turning a step's output into annotations, as GitHub's runner does.
//!
//! An action registers one with `::add-matcher::<path to json>` and withdraws it with
//! `::remove-matcher owner=<name>::`. The file holds one or more matchers:
//!
//!     { "problemMatcher": [ { "owner": "tsc", "severity": "error", "pattern": [
//!         { "regexp": "^([^\\s].*)\\((\\d+),(\\d+)\\): (error|warning) TS(\\d+): (.*)$",
//!           "file": 1, "line": 2, "column": 3, "severity": 4, "code": 5, "message": 6 } ] } ] }
//!
//! A matcher's `pattern` is a *list*, and that is the part worth understanding: the patterns match
//! **consecutive lines**. `actions/setup-node`'s eslint-stylish matcher has two — the first catches
//! a filename on its own line, the second each error beneath it — and the second carries
//! `"loop": true`, so it matches as many following lines as it can. Values captured by earlier
//! patterns are carried forward, which is how an error line that mentions no filename still gets
//! one. A line that breaks the sequence resets it, and is then retried as a first pattern.
//!
//! The regular expressions come from `regex.zig`, which reads them as GitHub's runner does (.NET,
//! ECMAScript mode). A pattern it refuses (a balancing group, `(?<a-b>…)`) makes **that matcher**
//! inert with a warning, not the step fail: an action should lose its annotations, not its job.

const std = @import("std");
const Allocator = std.mem.Allocator;
const regex = @import("regex.zig");

/// Which capture group carries each field, and whether the pattern repeats.
pub const Pattern = struct {
    re: regex.Regex,
    /// The pattern as written, for the warning when it is refused and for tests.
    source: []const u8,
    file: ?usize = null,
    line: ?usize = null,
    end_line: ?usize = null,
    column: ?usize = null,
    end_column: ?usize = null,
    severity: ?usize = null,
    code: ?usize = null,
    message: ?usize = null,
    from_path: ?usize = null,
    loop: bool = false,
};

pub const Matcher = struct {
    owner: []const u8,
    /// The level used when no pattern captures one; GitHub's default is `error`.
    severity: []const u8 = "error",
    patterns: []const Pattern,
};

/// What a completed match says, in the shape the log wants. Fields absent from every pattern stay
/// null, and an annotation without a file points at the step's own log, as GitHub's does.
pub const Found = struct {
    level: []const u8,
    message: []const u8,
    file: ?[]const u8 = null,
    line: ?[]const u8 = null,
    end_line: ?[]const u8 = null,
    col: ?[]const u8 = null,
    end_column: ?[]const u8 = null,
    code: ?[]const u8 = null,
    owner: []const u8,
};

pub const Error = error{ BadMatcher, OutOfMemory };

/// Reads a matcher file. Returns the matchers it defines, skipping any whose patterns this engine
/// cannot compile — `refused` names those, so the caller can warn once per matcher.
pub const Loaded = struct {
    matchers: []const Matcher,
    refused: []const Refusal,

    pub const Refusal = struct { owner: []const u8, pattern: []const u8, why: []const u8 };
};

pub fn load(arena: Allocator, json_text: []const u8) Error!Loaded {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, json_text, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadMatcher,
    };
    const root = parsed.value;
    if (root != .object) return error.BadMatcher;
    const list = root.object.get("problemMatcher") orelse return error.BadMatcher;
    if (list != .array) return error.BadMatcher;

    var out: std.ArrayList(Matcher) = .empty;
    var refused: std.ArrayList(Loaded.Refusal) = .empty;
    for (list.array.items) |entry| {
        if (entry != .object) continue;
        const owner_v = entry.object.get("owner") orelse continue;
        if (owner_v != .string) continue;
        const owner = owner_v.string;
        const severity = blk: {
            const s = entry.object.get("severity") orelse break :blk "error";
            break :blk if (s == .string and s.string.len > 0) s.string else "error";
        };
        const pats_v = entry.object.get("pattern") orelse continue;
        if (pats_v != .array or pats_v.array.items.len == 0) continue;

        var pats: std.ArrayList(Pattern) = .empty;
        var ok = true;
        for (pats_v.array.items) |pv| {
            if (pv != .object) {
                ok = false;
                break;
            }
            const rx_v = pv.object.get("regexp") orelse {
                ok = false;
                break;
            };
            if (rx_v != .string) {
                ok = false;
                break;
            }
            const re = regex.Regex.compile(arena, rx_v.string) catch |e| {
                // Out of memory is no verdict on the pattern: a matcher refused for it stayed
                // inert for the whole job, with "OutOfMemory" as its reason.
                if (e == error.OutOfMemory) return error.OutOfMemory;
                // One unusable pattern makes the whole matcher inert: a matcher whose second
                // pattern cannot compile would otherwise emit annotations from half a sequence.
                const why = @errorName(e);
                try refused.append(arena, .{ .owner = owner, .pattern = rx_v.string, .why = why });
                ok = false;
                break;
            };
            try pats.append(arena, .{
                .re = re,
                .source = rx_v.string,
                .file = group(pv, "file"),
                .line = group(pv, "line"),
                .end_line = group(pv, "endLine"),
                .column = group(pv, "column"),
                .end_column = group(pv, "endColumn"),
                .severity = group(pv, "severity"),
                .code = group(pv, "code"),
                .message = group(pv, "message"),
                .from_path = group(pv, "fromPath"),
                .loop = blk: {
                    const l = pv.object.get("loop") orelse break :blk false;
                    break :blk l == .bool and l.bool;
                },
            });
        }
        if (!ok) continue;
        try out.append(arena, .{ .owner = owner, .severity = severity, .patterns = pats.items });
    }
    return .{ .matchers = out.items, .refused = refused.items };
}

fn group(obj: std.json.Value, name: []const u8) ?usize {
    const v = obj.object.get(name) orelse return null;
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else null,
        else => null,
    };
}

/// The matchers in force, and how far each has got through its sequence.
///
/// One `Set` belongs to one job: `::add-matcher::` adds, `::remove-matcher owner=` removes, and
/// every line of a step's output goes through `feed`.
pub const Set = struct {
    entries: std.ArrayList(Entry) = .empty,

    const Entry = struct {
        matcher: Matcher,
        /// How many patterns of the sequence have matched so far; 0 means "waiting for the first".
        progress: usize = 0,
        /// What earlier patterns in the current sequence captured.
        carried: Carried = .{},
        /// Where `carried` keeps its text: its own copy, not slices of the lines it came from, so
        /// a caller may give each line, and the allocator `feed` works in, a lifetime of one line.
        /// Two buffers, used in turn: the next copy is made from the one in use into the other.
        held: [2]std.ArrayList(u8) = .{ .empty, .empty },
        held_cur: u1 = 0,
        /// The allocator of `add`, which `held` grows in.
        keep: Allocator,

        /// Copies what `carried` points at into `held`, for a sequence that goes on to another
        /// line. Each buffer grows to the largest carried text and is then reused.
        fn own(e: *Entry) Allocator.Error!void {
            const c = &e.carried;
            const fields = [_]*?[]const u8{
                &c.file,     &c.line, &c.end_line, &c.col,       &c.end_column,
                &c.severity, &c.code, &c.message,  &c.from_path,
            };
            var total: usize = 0;
            for (fields) |f| if (f.*) |t| {
                total += t.len;
            };
            const next = &e.held[~e.held_cur];
            next.clearRetainingCapacity();
            next.ensureTotalCapacity(e.keep, total) catch |err| {
                // Nothing may be left pointing at the line: the sequence starts again.
                e.carried = .{};
                e.progress = 0;
                return err;
            };
            for (fields) |f| if (f.*) |t| {
                const at = next.items.len;
                next.appendSliceAssumeCapacity(t);
                f.* = next.items[at..];
            };
            e.held_cur = ~e.held_cur;
        }
    };

    const Carried = struct {
        file: ?[]const u8 = null,
        line: ?[]const u8 = null,
        end_line: ?[]const u8 = null,
        col: ?[]const u8 = null,
        end_column: ?[]const u8 = null,
        severity: ?[]const u8 = null,
        code: ?[]const u8 = null,
        message: ?[]const u8 = null,
        /// `fromPath`: a file the reported `file` is relative *to*, not a file to report. It is
        /// carried like the rest because the pattern that captures it is usually an earlier line
        /// than the one reporting the error — a project file named once, then diagnostics beneath.
        from_path: ?[]const u8 = null,
    };

    /// The allocator is a parameter rather than a field so that a `Set` has a safe default: it
    /// lives inside the job's `JobLog`, which several call sites build field by field, and an
    /// `undefined` allocator there would be a landmine for whichever of them never adds a matcher.
    ///
    /// Adds every matcher in a file, each in front of those already there: GitHub's runner tries
    /// the newest first, and prepends a file's matchers one by one, so its last comes first
    /// (`OnMatcherChanged` in OutputManager.cs). An owner already present, in any case, is
    /// replaced, so an action re-registering its matcher does not match twice.
    pub fn add(s: *Set, arena: Allocator, matchers: []const Matcher) Allocator.Error!void {
        for (matchers) |m| {
            s.removeOwner(m.owner);
            try s.entries.insert(arena, 0, .{ .matcher = m, .keep = arena });
        }
    }

    /// Withdraws an owner's matcher; owners compare in any case, as in GitHub's runner.
    pub fn removeOwner(s: *Set, owner: []const u8) void {
        var i: usize = 0;
        while (i < s.entries.items.len) {
            if (std.ascii.eqlIgnoreCase(s.entries.items[i].matcher.owner, owner)) {
                _ = s.entries.orderedRemove(i);
            } else i += 1;
        }
    }

    pub fn count(s: *const Set) usize {
        return s.entries.items.len;
    }

    /// Offers one line of output to the matchers, newest first, as GitHub's runner does
    /// (`OnDataReceived` in OutputManager.cs). Returns the annotation the line makes, if any: the
    /// first matcher to complete a match on it makes one, unless GitHub would drop it (`issue`),
    /// and then the next matcher is tried. A completed match starts every other matcher's
    /// sequence again. A line that only advances a sequence goes on to the next matcher too.
    ///
    /// `arena` holds the result and the regex engine's work, and need only last until the result
    /// has been read: the runner resets it after every line, and the job's memory stays flat however
    /// long the output is (it grew by 18.8 GB over 1M lines with setup-node's tsc matcher when every
    /// line's work stayed in the job's arena). What a sequence carries to its next line is copied
    /// into the set's own buffers. `line` itself must outlive the result, which may point into it.
    pub fn feed(s: *Set, arena: Allocator, line: []const u8) Error!?Found {
        for (s.entries.items, 0..) |*e, i| {
            const done = try step(arena, e, line) orelse continue;
            for (s.entries.items, 0..) |*other, j| if (j != i) {
                other.progress = 0;
                other.carried = .{};
            };
            if (issue(done, e.matcher.severity)) |found| return found;
        }
        return null;
    }

    /// One matcher's turn at a line: what it found when the line completes its sequence.
    fn step(arena: Allocator, e: *Entry, line: []const u8) Error!?Found {
        const pats = e.matcher.patterns;
        const last = pats.len - 1;
        const at = if (e.progress > last) last else e.progress;
        const pat = pats[at];

        const m = pat.re.find(arena, line, 0) catch {
            // The step budget: this line defeated the pattern. Treat it as no match rather than
            // failing the job, and let the sequence reset.
            e.progress = 0;
            e.carried = .{};
            return null;
        } orelse {
            // A looping last pattern that stops matching ends the sequence; so does a break
            // anywhere else.
            e.progress = 0;
            e.carried = .{};
            return null;
        };

        carry(&e.carried, pat, m, line);

        const on_last = at == last;
        if (!on_last) {
            e.progress = at + 1;
            try e.own();
            return null;
        }

        // In `arena`: what was carried is overwritten by the lines after this one.
        const c = e.carried;
        const found: Found = .{
            .level = try dupeOpt(arena, c.severity) orelse "",
            .message = try dupeOpt(arena, c.message) orelse "",
            .file = resolveFile(arena, try dupeOpt(arena, c.file), c.from_path),
            .line = try dupeOpt(arena, c.line),
            .end_line = try dupeOpt(arena, c.end_line),
            .col = try dupeOpt(arena, c.col),
            .end_column = try dupeOpt(arena, c.end_column),
            .code = try dupeOpt(arena, c.code),
            .owner = e.matcher.owner,
        };

        if (pat.loop) {
            // Stay on the looping pattern, keeping what earlier patterns captured: the filename
            // from eslint-stylish's first pattern belongs to every error line under it.
            e.progress = pats.len;
            e.carried.message = null;
            try e.own();
        } else {
            e.progress = 0;
            e.carried = .{};
        }
        return found;
    }
};

/// A match as GitHub's runner turns it into an issue (`ConvertToIssue` in OutputManager.cs), or
/// null where it drops it: no message (or only whitespace), or a severity other than `error`,
/// `warning` or `notice` in any case; none captured is the matcher's own. A line or column that
/// is not a plain number is left out, and a code is trimmed.
fn issue(f: Found, default_severity: []const u8) ?Found {
    if (std.mem.trim(u8, f.message, " \t\r\n").len == 0) return null;
    const severity = if (f.level.len > 0) f.level else default_severity;
    const level = for ([_][]const u8{ "error", "warning", "notice" }) |l| {
        if (std.ascii.eqlIgnoreCase(severity, l)) break l;
    } else return null;
    var out = f;
    out.level = level;
    out.line = number(f.line);
    out.col = number(f.col);
    out.code = if (f.code) |c| code: {
        const t = std.mem.trim(u8, c, " \t\r\n");
        break :code if (t.len > 0) t else null;
    } else null;
    return out;
}

/// `text` when .NET's `int.TryParse` with `NumberStyles.None` takes it: digits only, in range.
fn number(text: ?[]const u8) ?[]const u8 {
    const t = text orelse return null;
    if (t.len == 0) return null;
    for (t) |ch| if (!std.ascii.isDigit(ch)) return null;
    _ = std.fmt.parseInt(i32, t, 10) catch return null;
    return t;
}

/// Resolves a reported file against the directory of the pattern's `fromPath`, as GitHub's runner
/// does. A tool invoked on a project file often reports paths relative to *that* file rather than
/// to the workspace, and `fromPath` is how a matcher says so.
///
/// This was parsed and then ignored for a while, which is worse than not supporting it: the
/// annotation still appeared, pointing at a path that does not exist, with nothing to say so.
///
/// An already-rooted file is returned untouched — joining would be wrong, and so would stripping
/// the leading separator off the result. Otherwise the join is normalised, so a `fromPath` of
/// `a/b/p.proj` and a file of `../c/x.cs` give `a/c/x.cs` rather than `a/b/../c/x.cs`.
///
/// Only POSIX separators are handled. A matcher written for Windows paths would not resolve here,
/// and that is consistent with the rest of the runner (SPEC.md, "Not supported yet").
///
/// Checked against GitHub's own runner on one workflow (`matcher-frompath`, emitted by
/// `comparisons/gen-workflows.sh`): both
/// resolved a sibling, a subdirectory and a `..` path to the same three files. Worth doing because
/// this is the one matcher property written from the documentation rather than from watching
/// GitHub.
fn resolveFile(arena: Allocator, file: ?[]const u8, from_path: ?[]const u8) ?[]const u8 {
    const f = file orelse return null;
    if (f.len == 0 or f[0] == '/') return f;
    const fp = from_path orelse return f;
    const dir = std.fs.path.dirname(fp) orelse return f;
    const joined = std.fs.path.resolvePosix(arena, &.{ "/", dir, f }) catch return f;
    // resolvePosix answers with a rooted path; the annotation wants it workspace-relative, as the
    // matcher reported it.
    return if (joined.len > 1 and joined[0] == '/') joined[1..] else f;
}

fn dupeOpt(arena: Allocator, s: ?[]const u8) Allocator.Error!?[]const u8 {
    return if (s) |t| try arena.dupe(u8, t) else null;
}

/// Copies this pattern's captures into the sequence's carried values. A pattern that names a group
/// overwrites; one that does not leaves what an earlier pattern captured.
fn carry(c: *Set.Carried, pat: Pattern, m: regex.Captures, line: []const u8) void {
    const fields = [_]struct { idx: ?usize, dst: *?[]const u8 }{
        .{ .idx = pat.file, .dst = &c.file },
        .{ .idx = pat.line, .dst = &c.line },
        .{ .idx = pat.end_line, .dst = &c.end_line },
        .{ .idx = pat.column, .dst = &c.col },
        .{ .idx = pat.end_column, .dst = &c.end_column },
        .{ .idx = pat.severity, .dst = &c.severity },
        .{ .idx = pat.code, .dst = &c.code },
        .{ .idx = pat.message, .dst = &c.message },
        .{ .idx = pat.from_path, .dst = &c.from_path },
    };
    for (fields) |f| if (f.idx) |i| {
        if (m.text(i, line)) |t| f.dst.* = t;
    };
}

// --- tests ---

const testing = std.testing;

/// actions/setup-node's eslint-stylish matcher, as shipped.
const eslint_stylish =
    \\{ "problemMatcher": [ { "owner": "eslint-stylish", "pattern": [
    \\  { "regexp": "^\\s*([^\\s].*)$", "file": 1 },
    \\  { "regexp": "^\\s+(\\d+):(\\d+)\\s+(error|warning|info)\\s+(.*)\\s\\s+(.*)$",
    \\    "line": 1, "column": 2, "severity": 3, "message": 4, "code": 5, "loop": true } ] } ] }
;

/// actions/setup-go's matcher: one pattern, optional line and column.
const go_matcher =
    \\{ "problemMatcher": [ { "owner": "go", "pattern": [
    \\  { "regexp": "^\\s*(.+\\.go):(?:(\\d+):(\\d+):)? (.*)",
    \\    "file": 1, "line": 2, "column": 3, "message": 4 } ] } ] }
;

test "a single-pattern matcher annotates each matching line" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    const loaded = try load(ar, go_matcher);
    try testing.expectEqual(@as(usize, 1), loaded.matchers.len);
    try testing.expectEqual(@as(usize, 0), loaded.refused.len);

    var set: Set = .{};
    try set.add(ar, loaded.matchers);

    const with_position = try set.feed(ar, "main.go:9:2: undefined: foo");
    try testing.expect(with_position != null);
    try testing.expectEqualStrings("error", with_position.?.level); // the default severity
    try testing.expectEqualStrings("main.go", with_position.?.file.?);
    try testing.expectEqualStrings("9", with_position.?.line.?);
    try testing.expectEqualStrings("2", with_position.?.col.?);
    try testing.expectEqualStrings("undefined: foo", with_position.?.message);

    // The optional group absent: a message with no line or column still annotates.
    const without = try set.feed(ar, "pkg/a.go: build failed");
    try testing.expect(without != null);
    try testing.expectEqualStrings("pkg/a.go", without.?.file.?);
    try testing.expect(without.?.line == null);
    try testing.expect(without.?.col == null);

    // An unrelated line annotates nothing.
    try testing.expect(try set.feed(ar, "go: downloading example.com/x v1.2.3") == null);
}

test "a two-pattern matcher carries the filename to every error beneath it" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    const loaded = try load(ar, eslint_stylish);
    var set: Set = .{};
    try set.add(ar, loaded.matchers);

    // The filename line matches the first pattern and annotates nothing by itself.
    try testing.expect(try set.feed(ar, "src/app.js") == null);

    // Each error line completes the sequence, and keeps the filename from the line above.
    const first = try set.feed(ar, "  12:34  error  Unexpected console statement  no-console");
    try testing.expect(first != null);
    try testing.expectEqualStrings("src/app.js", first.?.file.?);
    try testing.expectEqualStrings("12", first.?.line.?);
    try testing.expectEqualStrings("34", first.?.col.?);
    try testing.expectEqualStrings("error", first.?.level);
    try testing.expectEqualStrings("Unexpected console statement", first.?.message);
    try testing.expectEqualStrings("no-console", first.?.code.?);

    // `loop: true`: the second error line annotates too, with the same file.
    const second = try set.feed(ar, "  40:5  warning  Missing radix parameter  radix");
    try testing.expect(second != null);
    try testing.expectEqualStrings("src/app.js", second.?.file.?);
    try testing.expectEqualStrings("warning", second.?.level); // captured, not the default
    try testing.expectEqualStrings("radix", second.?.code.?);

    // A blank-ish line breaks the sequence, and the next filename starts a new one.
    try testing.expect(try set.feed(ar, "") == null);
    try testing.expect(try set.feed(ar, "src/other.js") == null);
    const third = try set.feed(ar, "  1:1  error  Parsing error  syntax");
    try testing.expectEqualStrings("src/other.js", third.?.file.?);
}

test "owners: re-registering replaces, removing withdraws" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    var set: Set = .{};
    try set.add(ar, (try load(ar, go_matcher)).matchers);
    try set.add(ar, (try load(ar, go_matcher)).matchers); // the same owner twice
    try testing.expectEqual(@as(usize, 1), set.count()); // replaced, not doubled
    try testing.expect(try set.feed(ar, "main.go:1:1: x") != null);

    set.removeOwner("go");
    try testing.expectEqual(@as(usize, 0), set.count());
    try testing.expect(try set.feed(ar, "main.go:1:1: x") == null);
}

test "a matcher whose pattern this engine refuses goes inert, and says which" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    // Balancing groups are refused by regex.zig; the matcher must not be registered
    // half-compiled.
    const balancing =
        \\{ "problemMatcher": [ { "owner": "exotic", "pattern": [
        \\  { "regexp": "^(?<a-b>x)(.*)$", "message": 1 } ] } ] }
    ;
    const loaded = try load(ar, balancing);
    try testing.expectEqual(@as(usize, 0), loaded.matchers.len);
    try testing.expectEqual(@as(usize, 1), loaded.refused.len);
    try testing.expectEqualStrings("exotic", loaded.refused[0].owner);
    try testing.expectEqualStrings("Unsupported", loaded.refused[0].why);

    // One bad pattern in a sequence makes the whole matcher inert: half a sequence would annotate
    // from values it never captured.
    const half_bad =
        \\{ "problemMatcher": [ { "owner": "half", "pattern": [
        \\  { "regexp": "^(.*)$", "file": 1 },
        \\  { "regexp": "(?<a-b>w)ord", "message": 1 } ] } ] }
    ;
    const partly = try load(ar, half_bad);
    try testing.expectEqual(@as(usize, 0), partly.matchers.len);
    try testing.expectEqual(@as(usize, 1), partly.refused.len);
}

test "a malformed matcher file is an error, not a crash" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    for ([_][]const u8{ "", "[]", "{}", "{\"problemMatcher\":{}}", "not json" }) |text|
        try testing.expectError(error.BadMatcher, load(ar, text));
    // Present but unusable entries are skipped rather than refused: no owner, no patterns.
    const empty = try load(ar, "{\"problemMatcher\":[{\"owner\":\"x\"},{\"pattern\":[]}]}");
    try testing.expectEqual(@as(usize, 0), empty.matchers.len);
}

test "the default severity applies only when no pattern captures one" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const warned =
        \\{ "problemMatcher": [ { "owner": "w", "severity": "warning", "pattern": [
        \\  { "regexp": "^(.+)$", "message": 1 } ] } ] }
    ;
    var set: Set = .{};
    try set.add(ar, (try load(ar, warned)).matchers);
    const got = try set.feed(ar, "something happened");
    try testing.expectEqualStrings("warning", got.?.level);
    try testing.expectEqualStrings("something happened", got.?.message);
}

/// The shape every `fromPath` matcher has: one pattern catching the file a tool was invoked on, and
/// a looping one catching the diagnostics under it, whose paths are relative to *that* file rather
/// than to the workspace. Modelled on the matcher .NET's SDK ships, which is the canonical user of
/// the property; the runner does not support .NET (SPEC.md §9), but `fromPath` belongs to the
/// matcher format rather than to any one toolchain, so it has to work.
const from_path_matcher =
    \\{ "problemMatcher": [ { "owner": "proj", "pattern": [
    \\  { "regexp": "^Building (.+\\.proj)$", "fromPath": 1 },
    \\  { "regexp": "^(.+)\\((\\d+),(\\d+)\\): (error|warning) ([A-Z]+\\d+): (.*)$",
    \\    "file": 1, "line": 2, "column": 3, "severity": 4, "code": 5, "message": 6,
    \\    "loop": true } ] } ] }
;

test "fromPath resolves a reported file against the directory of the project file" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var set: Set = .{};
    try set.add(ar, (try load(ar, from_path_matcher)).matchers);

    // The first line only establishes where the following paths are rooted, and annotates nothing.
    try testing.expect(try set.feed(ar, "Building src/app/app.proj") == null);

    // `Program.cs` is relative to src/app/, not to the workspace. Before this worked, the
    // annotation said "Program.cs" and pointed at a file that is not there.
    const one = try set.feed(ar, "Program.cs(12,5): error CS0103: The name 'x' does not exist.");
    try testing.expect(one != null);
    try testing.expectEqualStrings("src/app/Program.cs", one.?.file.?);
    try testing.expectEqualStrings("12", one.?.line.?);
    try testing.expectEqualStrings("CS0103", one.?.code.?);
    try testing.expectEqualStrings("error", one.?.level);

    // The looping pattern keeps the carried fromPath, so every diagnostic under one project line
    // resolves the same way.
    const two = try set.feed(ar, "sub/Other.cs(3,1): warning CS0168: unused.");
    try testing.expectEqualStrings("src/app/sub/Other.cs", two.?.file.?);

    // `..` in the reported path is normalised rather than left in place.
    const up = try set.feed(ar, "../shared/Util.cs(7,2): error CS0246: missing type.");
    try testing.expectEqualStrings("src/shared/Util.cs", up.?.file.?);

    // An already-rooted path is left exactly as reported.
    const abs = try set.feed(ar, "/opt/sdk/Gen.cs(1,1): error CS0001: generated.");
    try testing.expectEqualStrings("/opt/sdk/Gen.cs", abs.?.file.?);
}

test "a matcher with no fromPath still reports the file as captured" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // The regression this pairs with: resolveFile must be a no-op without fromPath, which is every
    // matcher real actions ship today.
    var set: Set = .{};
    try set.add(ar, (try load(ar, go_matcher)).matchers);
    const got = try set.feed(ar, "pkg/thing/x.go:12:5: undefined: alpha");
    try testing.expectEqualStrings("pkg/thing/x.go", got.?.file.?);
}

// A project file at the repository root: `dirname` gives an empty directory, and the reported path
// must come through unchanged rather than acquiring a separator.
test "fromPath at the root leaves the path alone" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var set: Set = .{};
    try set.add(ar, (try load(ar, from_path_matcher)).matchers);
    _ = try set.feed(ar, "Building app.proj");
    const got = try set.feed(ar, "Program.cs(1,1): error CS0001: x.");
    try testing.expectEqualStrings("Program.cs", got.?.file.?);
}

test "the newest matcher is tried first, and one GitHub would drop passes the line on" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const anything =
        \\{ "problemMatcher": [ { "owner": "any", "severity": "warning", "pattern": [
        \\  { "regexp": "^(.+)$", "message": 1 } ] } ] }
    ;
    var set: Set = .{};
    try set.add(ar, (try load(ar, go_matcher)).matchers);
    try set.add(ar, (try load(ar, anything)).matchers);
    // Added last, tried first.
    try testing.expectEqualStrings("any", (try set.feed(ar, "main.go:1:1: x")).?.owner);
    // Re-registered in another case: replaced, and first again.
    set.removeOwner("ANY");
    try testing.expectEqual(@as(usize, 1), set.count());
    try testing.expectEqualStrings("go", (try set.feed(ar, "main.go:1:1: x")).?.owner);

    // In one file, the last matcher comes first.
    var two: Set = .{};
    const pair =
        \\{ "problemMatcher": [
        \\  { "owner": "first", "pattern": [ { "regexp": "^(.+)$", "message": 1 } ] },
        \\  { "owner": "second", "pattern": [ { "regexp": "^(.+)$", "message": 1 } ] } ] }
    ;
    try two.add(ar, (try load(ar, pair)).matchers);
    try testing.expectEqualStrings("second", (try two.feed(ar, "x")).?.owner);

    // An empty message, or a severity GitHub does not know, makes no issue: the next matcher
    // gets the line.
    var drops: Set = .{};
    const fallback =
        \\{ "problemMatcher": [ { "owner": "fallback", "pattern": [
        \\  { "regexp": "^(.*)$", "message": 1 } ] } ] }
    ;
    const picky =
        \\{ "problemMatcher": [ { "owner": "picky", "pattern": [
        \\  { "regexp": "^(\\w+): (.*)$", "severity": 1, "message": 2, "line": 1 } ] } ] }
    ;
    try drops.add(ar, (try load(ar, fallback)).matchers);
    try drops.add(ar, (try load(ar, picky)).matchers);
    try testing.expectEqualStrings("fallback", (try drops.feed(ar, "info: not a severity")).?.owner);
    try testing.expectEqualStrings("fallback", (try drops.feed(ar, "error:  ")).?.owner);
    const known = (try drops.feed(ar, "WARNING: careful")).?;
    try testing.expectEqualStrings("picky", known.owner);
    try testing.expectEqualStrings("warning", known.level);
    // `line` captured "WARNING", which is not a number: left out.
    try testing.expect(known.line == null);
    // Nothing at all: no issue.
    try testing.expect(try drops.feed(ar, "") == null);
}

test "allocation failures: a matcher file loaded, with a pattern refused and a file that is not one" {
    const af = @import("alloc_failures.zig");
    const S = struct {
        /// Out of memory is never the matcher's refusal or a bad file; those are as without it.
        fn run(a: std.mem.Allocator, text: []const u8) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            const loaded = load(arena.allocator(), text) catch |e| {
                if (e == error.BadMatcher) return;
                return e;
            };
            // A matcher that loads is the same with and without failures; that they can be told
            // apart here is what the refusals' count and the matchers' are for.
            try testing.expectEqual(expected_matchers(text), loaded.matchers.len);
            try testing.expectEqual(expected_refused(text), loaded.refused.len);
        }
        fn expected_matchers(text: []const u8) usize {
            return if (std.mem.indexOf(u8, text, "a-b") == null and std.mem.indexOf(u8, text, "problemMatcher") != null) 1 else 0;
        }
        fn expected_refused(text: []const u8) usize {
            return if (std.mem.indexOf(u8, text, "a-b") != null) 1 else 0;
        }
    };
    for ([_][]const u8{
        go_matcher,
        \\{ "problemMatcher": [ { "owner": "exotic", "pattern": [
        \\  { "regexp": "^(?<a-b>x)(.*)$", "message": 1 } ] } ] }
        ,
        "not json",
        "{}",
    }) |text| try af.checkOne(S.run, .{text});
}
