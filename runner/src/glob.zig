//! `hashFiles()`'s file search, as GitHub's runner does it, without its dependencies: GitHub's runner
//! (C#) runs a Node script on @actions/glob for it; this is @actions/glob 0.7.0 (the version the
//! script pins) and the part of minimatch it uses, in Zig.
//!
//! Licenses (docs/THIRD_PARTY.md): @actions/glob is MIT. The minimatch ported is the one
//! @actions/glob 0.7.0 runs (`^10.2.5`; 10.2.6 when this was written), under the Blue Oak Model
//! License 1.0.0, <https://blueoakcouncil.org/license/1.0.0>, which asks that a copy of any part
//! of it, changed or not, comes with that text or this link.
//!
//! - **Patterns** (`Pattern.init`): one per line, trimmed; `#` lines and blanks skipped; each
//!   leading `!` flips negation; `.` and `..` segments refused (but a leading `.`); a relative
//!   pattern is made absolute under the workspace; a trailing `/` matches directories only.
//! - **Implicit descendants**: a pattern that does not end in `**` also gets `pattern/**`, which
//!   matches only what is below what it matches.
//! - **Search paths**: the literal part of each pattern before its first glob segment, leaving out
//!   any below another.
//! - **The walk** (`walk`): depth-first from each search path, each directory's children in byte
//!   order (Node's `fs.readdir` sorts, through libuv's `scandir`, with `strcmp`; so GitHub's hash
//!   does not depend on the file system); a path is matched before it is looked at, and left out
//!   (with everything below it) when neither it nor anything below it can match; symbolic links
//!   are not followed unless asked.
//! - **Matching**: minimatch with `dot`, `nobrace`, `noext`, `nonegate`, `nocomment`, case-sensitive:
//!   `*`, `?`, `[...]` classes (with `!`/`^`, ranges and POSIX classes), `\` escapes and `**`.
//!
//! The file system is whatever `Fs` answers, many paths at a time: Dagger's API in a Dagger job
//! (`dagger/hash_files.zig`), the job's layers in a native one (`native/hash_files.zig`), the local disk in `tools/hashfilescorpus.zig`, which compares this
//! with GitHub's script (`.github/scripts/hashfiles-diff.sh`).
const std = @import("std");

const Allocator = std.mem.Allocator;

// --- paths (POSIX only: the runner's jobs run on Linux) ---

/// `//` collapsed to `/`, as @actions/glob's `normalizeSeparators`.
fn normalize(arena: Allocator, p: []const u8) Allocator.Error![]const u8 {
    if (std.mem.indexOf(u8, p, "//") == null) return p;
    var out: std.ArrayList(u8) = .empty;
    for (p, 0..) |c, i| {
        if (c == '/' and i > 0 and p[i - 1] == '/') continue;
        try out.append(arena, c);
    }
    return out.items;
}

/// A trailing `/` removed, but not from `/` itself (`safeTrimTrailingSeparator`).
fn trimTrailing(p: []const u8) []const u8 {
    if (p.len > 1 and p[p.len - 1] == '/') return p[0 .. p.len - 1];
    return p;
}

/// The parent of an absolute path; `/` for `/` (@actions/glob's `dirname`).
fn dirname(p: []const u8) []const u8 {
    const t = trimTrailing(p);
    const slash = std.mem.lastIndexOfScalar(u8, t, '/') orelse return ".";
    return if (slash == 0) "/" else t[0..slash];
}

/// The segments of a path, as @actions/glob's `Path`: a rooted path's first segment is `/`.
fn segmentsOf(arena: Allocator, path: []const u8) Allocator.Error![]const []const u8 {
    const p = trimTrailing(path);
    var out: std.ArrayList([]const u8) = .empty;
    var rest = p;
    if (p.len > 0 and p[0] == '/') {
        try out.append(arena, "/");
        rest = p[1..];
    }
    if (rest.len > 0) {
        var it = std.mem.splitScalar(u8, rest, '/');
        while (it.next()) |s| try out.append(arena, s);
    }
    return out.items;
}

/// Segments joined back into a path (`Path.toString`).
fn joinSegments(arena: Allocator, segs: []const []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (segs, 0..) |s, i| {
        if (i > 0 and !std.mem.endsWith(u8, out.items, "/")) try out.append(arena, '/');
        try out.appendSlice(arena, s);
    }
    return out.items;
}

/// A path made safe to use as a glob (`Pattern.globEscape`): `\` doubled, `[` that a `]` follows
/// in the same segment written `[[]`, `?` and `*` as `[?]` and `[*]`.
fn globEscape(arena: Allocator, s: []const u8) Allocator.Error![]const u8 {
    var step: std.ArrayList(u8) = .empty;
    for (s) |c| {
        if (c == '\\') try step.append(arena, '\\');
        try step.append(arena, c);
    }
    var out: std.ArrayList(u8) = .empty;
    const t = step.items;
    for (t, 0..) |c, i| {
        switch (c) {
            '[' => {
                // `(\[)(?=[^/]+\])`: one or more non-slashes, then `]`.
                var j = i + 1;
                while (j < t.len and t[j] != '/' and t[j] != ']') j += 1;
                if (j > i + 1 and j < t.len and t[j] == ']') {
                    try out.appendSlice(arena, "[[]");
                } else try out.append(arena, '[');
            },
            '?' => try out.appendSlice(arena, "[?]"),
            '*' => try out.appendSlice(arena, "[*]"),
            else => try out.append(arena, c),
        }
    }
    return out.items;
}

/// The literal a pattern segment stands for, or "" when it holds a glob (`Pattern.getLiteral`).
fn literalOf(arena: Allocator, seg: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < seg.len) : (i += 1) {
        const c = seg[i];
        if (c == '\\' and i + 1 < seg.len) {
            i += 1;
            try out.append(arena, seg[i]);
            continue;
        }
        if (c == '*' or c == '?') return "";
        if (c == '[' and i + 1 < seg.len) {
            var set: std.ArrayList(u8) = .empty;
            var closed: ?usize = null;
            var j = i + 1;
            while (j < seg.len) : (j += 1) {
                if (seg[j] == '\\' and j + 1 < seg.len) {
                    j += 1;
                    try set.append(arena, seg[j]);
                } else if (seg[j] == ']') {
                    closed = j;
                    break;
                } else try set.append(arena, seg[j]);
            }
            if (closed) |end| {
                if (set.items.len > 1) return "";
                if (set.items.len == 1) {
                    try out.appendSlice(arena, set.items);
                    i = end;
                    continue;
                }
            }
        }
        try out.append(arena, c);
    }
    return out.items;
}

// --- minimatch, the subset @actions/glob uses ---

const Part = union(enum) {
    /// `**` on its own.
    globstar,
    /// A segment without glob characters, escapes resolved.
    literal: []const u8,
    /// A segment with `*`, `?` or a class.
    magic: []const Tok,
};

const Tok = union(enum) {
    char: u21,
    any, // ?
    star, // *
    class: Class,
};

const Class = struct {
    negate: bool,
    items: []const Item,

    const Item = union(enum) { range: [2]u21, posix: Posix };

    fn has(c: Class, ch: u21) bool {
        var in = false;
        for (c.items) |it| switch (it) {
            .range => |r| if (ch >= r[0] and ch <= r[1]) {
                in = true;
            },
            .posix => |p| if (p.has(ch)) {
                in = true;
            },
        };
        return in != c.negate;
    }
};

const Posix = enum {
    alnum,
    alpha,
    ascii,
    blank,
    cntrl,
    digit,
    graph,
    lower,
    print,
    punct,
    space,
    upper,
    word,
    xdigit,

    fn has(p: Posix, ch: u21) bool {
        if (ch > 0x7f) return switch (p) {
            // minimatch uses Unicode property classes for these; outside ASCII, letters count.
            .alpha, .alnum, .word, .graph, .print => true,
            else => false,
        };
        const c: u8 = @intCast(ch);
        return switch (p) {
            .alnum => std.ascii.isAlphanumeric(c),
            .alpha => std.ascii.isAlphabetic(c),
            .ascii => true,
            .blank => c == ' ' or c == '\t',
            .cntrl => std.ascii.isControl(c),
            .digit => std.ascii.isDigit(c),
            .graph => c > 0x20 and c < 0x7f,
            .lower => std.ascii.isLower(c),
            .print => c >= 0x20 and c < 0x7f,
            .punct => std.ascii.isPunctuation(c),
            .space => std.ascii.isWhitespace(c),
            .upper => std.ascii.isUpper(c),
            .word => std.ascii.isAlphanumeric(c) or c == '_',
            .xdigit => std.ascii.isHex(c),
        };
    }
};

/// The next code point of `s` at `i.*` (a byte that does not start valid UTF-8 stands for itself).
fn nextRune(s: []const u8, i: *usize) u21 {
    const len = std.unicode.utf8ByteSequenceLength(s[i.*]) catch 0;
    if (len > 1 and i.* + len <= s.len) {
        if (std.unicode.utf8Decode(s[i.* .. i.* + len])) |c| {
            i.* += len;
            return c;
        } else |_| {}
    }
    i.* += 1;
    return s[i.* - 1];
}

/// One pattern segment as minimatch reads it with `noext` and `nobrace`.
fn compilePart(arena: Allocator, seg: []const u8) Allocator.Error!Part {
    if (std.mem.eql(u8, seg, "**")) return .globstar;
    var toks: std.ArrayList(Tok) = .empty;
    var magic = false;
    var i: usize = 0;
    while (i < seg.len) {
        const c = seg[i];
        switch (c) {
            '\\' => {
                if (i + 1 >= seg.len) {
                    try toks.append(arena, .{ .char = '\\' });
                    i += 1;
                } else {
                    i += 1;
                    try toks.append(arena, .{ .char = nextRune(seg, &i) });
                }
            },
            '*' => {
                magic = true;
                // Consecutive stars are one.
                if (toks.items.len == 0 or toks.items[toks.items.len - 1] != .star)
                    try toks.append(arena, .star);
                i += 1;
            },
            '?' => {
                magic = true;
                try toks.append(arena, .any);
                i += 1;
            },
            '[' => if (try parseClass(arena, seg, i)) |res| {
                magic = true;
                try toks.append(arena, .{ .class = res.class });
                i = res.end;
            } else {
                try toks.append(arena, .{ .char = '[' });
                i += 1;
            },
            else => try toks.append(arena, .{ .char = nextRune(seg, &i) }),
        }
    }
    if (!magic) {
        var lit: std.ArrayList(u8) = .empty;
        for (toks.items) |t| {
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(t.char, &buf) catch {
                try lit.append(arena, @intCast(t.char & 0xff));
                continue;
            };
            try lit.appendSlice(arena, buf[0..n]);
        }
        return .{ .literal = lit.items };
    }
    return .{ .magic = toks.items };
}

/// A `[...]` class starting at `seg[start]`, or null when it never closes (then `[` is literal).
fn parseClass(arena: Allocator, seg: []const u8, start: usize) Allocator.Error!?struct { class: Class, end: usize } {
    var i = start + 1;
    var negate = false;
    if (i < seg.len and (seg[i] == '!' or seg[i] == '^')) {
        negate = true;
        i += 1;
    }
    const first = i;
    var items: std.ArrayList(Class.Item) = .empty;
    var pending: ?u21 = null; // a char that may start a range
    while (i < seg.len) {
        const c = seg[i];
        if (c == ']' and i > first) {
            if (pending) |p| try items.append(arena, .{ .range = .{ p, p } });
            return .{ .class = .{ .negate = negate, .items = items.items }, .end = i + 1 };
        }
        if (c == '[' and i + 1 < seg.len and seg[i + 1] == ':') {
            if (std.mem.indexOfPos(u8, seg, i + 2, ":]")) |close| {
                if (std.meta.stringToEnum(Posix, seg[i + 2 .. close])) |p| {
                    if (pending) |q| try items.append(arena, .{ .range = .{ q, q } });
                    pending = null;
                    try items.append(arena, .{ .posix = p });
                    i = close + 2;
                    continue;
                }
            }
        }
        var ch: u21 = undefined;
        if (c == '\\' and i + 1 < seg.len) {
            i += 1;
            ch = nextRune(seg, &i);
        } else ch = nextRune(seg, &i);
        // `a-z`: a range, unless the `-` is last.
        if (pending) |lo| {
            if (ch == '-' and i < seg.len and seg[i] != ']') {
                var hi: u21 = undefined;
                if (seg[i] == '\\' and i + 1 < seg.len) {
                    i += 1;
                    hi = nextRune(seg, &i);
                } else hi = nextRune(seg, &i);
                if (hi >= lo) try items.append(arena, .{ .range = .{ lo, hi } });
                pending = null;
                continue;
            }
            try items.append(arena, .{ .range = .{ lo, lo } });
        }
        pending = ch;
    }
    return null;
}

/// Whether `toks` match all of `s`, by code point.
fn matchToks(toks: []const Tok, s: []const u8) bool {
    var steps: usize = 0;
    return matchToksCounted(toks, s, &steps);
}

/// `matchToks`, counting its steps (for the tests). Every token but `*` takes one code point, and
/// every code point is read with `nextRune` from where the one before it ended, so the code points
/// of `s` are one sequence however it is matched; on that, a `*` that fails takes one more code
/// point for the last `*` before it, and only that one: whatever an earlier `*` could take
/// instead, the last can too. Linear in each `*`, so O(toks × s) at worst, not exponential.
fn matchToksCounted(toks: []const Tok, s: []const u8, steps: *usize) bool {
    var ti: usize = 0;
    var si: usize = 0;
    // The token after the last `*` seen, and where that `*`'s run of code points ends.
    var star: ?usize = null;
    var star_end: usize = 0;
    while (true) {
        steps.* += 1;
        if (ti < toks.len and toks[ti] == .star) {
            ti += 1;
            star = ti;
            star_end = si;
            continue;
        }
        if (ti < toks.len and si < s.len) {
            var i = si;
            const ch = nextRune(s, &i);
            const ok = switch (toks[ti]) {
                .char => |c| c == ch,
                .any => true,
                .class => |cl| cl.has(ch),
                .star => unreachable,
            };
            if (ok) {
                ti += 1;
                si = i;
                continue;
            }
        } else if (ti == toks.len and si == s.len) return true;
        // A mismatch, or one side used up: the last `*` takes one more code point, if any is left.
        const after = star orelse return false;
        if (star_end >= s.len) return false;
        _ = nextRune(s, &star_end);
        ti = after;
        si = star_end;
    }
}

fn matchPart(part: Part, seg: []const u8) bool {
    return switch (part) {
        .globstar => unreachable,
        .literal => |l| std.mem.eql(u8, l, seg),
        // With `dot`, a glob still never matches `.`, `..`, or an empty segment.
        .magic => |toks| seg.len > 0 and !std.mem.eql(u8, seg, ".") and
            !std.mem.eql(u8, seg, "..") and matchToks(toks, seg),
    };
}

/// minimatch's `matchOne`: the path's segments against the pattern's, `partial` when only a
/// prefix of the pattern needs to match (could something below this path match?).
fn matchOne(arena: Allocator, file: []const []const u8, pat: []const Part, partial: bool) Allocator.Error!bool {
    var m: OneMatch = .{ .arena = arena, .file = file, .pat = pat, .partial = partial };
    return m.from(0, 0);
}

/// One `matchOne`. Each `**` tries the rest of the pattern at every place in the path it can
/// stop, as minimatch does, but the answer for the rest of the pattern from a place depends only
/// on the two places: one that failed is not tried again (one that matched ends the whole match).
/// So each pair of places is tried once, O(file² × pattern) at worst, where without that a path
/// and a pattern with many `**` took exponential time. The cases are minimatch's, and
/// `proofs/Glob/Match.lean`'s `matchOne`.
const OneMatch = struct {
    arena: Allocator,
    file: []const []const u8,
    pat: []const Part,
    partial: bool,
    /// The (path place, pattern place) pairs already tried after a `**`; empty until one is.
    tried: std.DynamicBitSetUnmanaged = .{},
    /// Segments compared, for the tests.
    steps: usize = 0,

    /// Whether `pat[pi0..]` matches `file[fi0..]`.
    fn from(m: *OneMatch, fi0: usize, pi0: usize) Allocator.Error!bool {
        const file = m.file;
        const pat = m.pat;
        var fi = fi0;
        var pi = pi0;
        while (fi < file.len and pi < pat.len) : ({
            fi += 1;
            pi += 1;
        }) {
            const p = pat[pi];
            if (p == .globstar) {
                const pr = pi + 1;
                if (pr == pat.len) {
                    // `**` last swallows the rest, but never `.` or `..`.
                    for (file[fi..]) |f| if (std.mem.eql(u8, f, ".") or std.mem.eql(u8, f, "..")) return false;
                    return true;
                }
                var fr = fi;
                while (fr < file.len) : (fr += 1) {
                    if (try m.firstTry(fr, pr) and try m.from(fr, pr)) return true;
                    const swallowee = file[fr];
                    if (std.mem.eql(u8, swallowee, ".") or std.mem.eql(u8, swallowee, "..")) break;
                }
                return m.partial and fr == file.len;
            }
            m.steps += 1;
            if (!matchPart(p, file[fi])) return false;
        }
        if (fi == file.len and pi == pat.len) return true;
        if (fi == file.len) return m.partial;
        return fi == file.len - 1 and file[fi].len == 0;
    }

    /// Whether `pat[pi..]` against `file[fi..]` is yet to be tried, marking it tried. A try that
    /// is asked again has failed: one that matched would have ended the whole match, and a try
    /// only starts others further along the pattern, so never itself again before it ends.
    fn firstTry(m: *OneMatch, fi: usize, pi: usize) Allocator.Error!bool {
        const width = m.pat.len + 1;
        if (m.tried.bit_length == 0) m.tried = try .initEmpty(m.arena, (m.file.len + 1) * width);
        const k = fi * width + pi;
        if (m.tried.isSet(k)) return false;
        m.tried.set(k);
        return true;
    }
};

/// A path's segments as minimatch splits it (`/a/b/` is "", "a", "b", "").
fn splitPath(arena: Allocator, path: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |s| try out.append(arena, s);
    return out.items;
}

// --- patterns ---

/// What a pattern matches a path as (@actions/glob's MatchKind).
pub const MatchKind = struct {
    pub const none: u2 = 0;
    pub const directory: u2 = 1;
    pub const file: u2 = 2;
    pub const all: u2 = 3;
};

pub const Pattern = struct {
    negate: bool,
    /// Pattern segments; the first is the root, `/`.
    segments: []const []const u8,
    /// Written with a trailing `/`: directories only.
    trailing_separator: bool,
    /// The literal path before the first glob segment.
    search_path: []const u8,
    /// One of the `pattern/**` patterns added for implicit descendants.
    is_implicit: bool,
    parts: []const Part,

    /// A pattern line as @actions/glob reads it; `cwd` is the workspace, `home` the user's home
    /// (for a leading `~`). Null with `why` set when GitHub would refuse it.
    pub fn init(arena: Allocator, line: []const u8, cwd: []const u8, home: []const u8, is_implicit: bool, why: *[]const u8) Allocator.Error!?Pattern {
        var pattern = trim(line);
        var negate = false;
        while (std.mem.startsWith(u8, pattern, "!")) {
            negate = !negate;
            pattern = trim(pattern[1..]);
        }
        if (pattern.len == 0) {
            why.* = "pattern cannot be empty";
            return null;
        }
        pattern = (try fixup(arena, pattern, cwd, home, why)) orelse return null;
        const segments = try segmentsOf(arena, pattern);
        const trailing = std.mem.endsWith(u8, pattern, "/");
        pattern = trimTrailing(pattern);
        var search: std.ArrayList([]const u8) = .empty;
        for (segments) |s| {
            const lit = try literalOf(arena, s);
            if (lit.len == 0) break;
            try search.append(arena, lit);
        }
        var parts: std.ArrayList(Part) = .empty;
        for (try splitPath(arena, pattern)) |s| {
            const part = try compilePart(arena, s);
            // Adjacent `**` are one (minimatch's optimization).
            if (part == .globstar and parts.items.len > 0 and parts.items[parts.items.len - 1] == .globstar) continue;
            try parts.append(arena, part);
        }
        return .{
            .negate = negate,
            .segments = segments,
            .trailing_separator = trailing,
            .search_path = try joinSegments(arena, search.items),
            .is_implicit = is_implicit,
            .parts = parts.items,
        };
    }

    /// `pattern/**`, for implicit descendants; null, with `why`, when @actions/glob refuses it.
    /// It can, though the pattern was accepted: `\.` is `.` only as the first segment, which a
    /// relative pattern's is not once it is under the workspace (`/w/\./**`), so GitHub's
    /// hashFiles() fails on it ("Relative pathing"), as this does. It once asserted instead, and a
    /// job's `hashFiles('\.')` took the runner down (found by the fuzzer).
    fn descendants(p: Pattern, arena: Allocator, why: *[]const u8) Allocator.Error!?Pattern {
        var segs: std.ArrayList([]const u8) = .empty;
        try segs.appendSlice(arena, p.segments);
        try segs.append(arena, "**");
        const text = try joinSegments(arena, segs.items);
        const line = if (p.negate) try std.mem.concat(arena, u8, &.{ "!", text }) else text;
        return init(arena, line, "/", "/", true, why);
    }

    /// What this pattern matches `item` as (`Pattern.match`).
    pub fn match(p: Pattern, arena: Allocator, item_in: []const u8) Allocator.Error!u2 {
        var item = try normalize(arena, item_in);
        if (std.mem.eql(u8, p.segments[p.segments.len - 1], "**")) {
            // minimatch matches `/foo/` to `/foo/**` but not `/foo`.
            if (!std.mem.endsWith(u8, item, "/") and !p.is_implicit)
                item = try std.mem.concat(arena, u8, &.{ item, "/" });
        } else item = trimTrailing(item);
        if (try matchOne(arena, try splitPath(arena, item), p.parts, false))
            return if (p.trailing_separator) MatchKind.directory else MatchKind.all;
        return MatchKind.none;
    }

    /// Whether this pattern may match something below `item` (`Pattern.partialMatch`).
    pub fn partialMatch(p: Pattern, arena: Allocator, item_in: []const u8) Allocator.Error!bool {
        const item = trimTrailing(try normalize(arena, item_in));
        if (std.mem.eql(u8, dirname(item), item)) return std.mem.eql(u8, item, "/");
        return matchOne(arena, try splitPath(arena, item), p.parts, true);
    }
};

/// JavaScript's `String.prototype.trim`, for the whitespace a pattern line can carry.
fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n\x0b\x0c");
}

/// `Pattern.fixupPattern`: `.` and `..` refused, separators normalized, a leading `.` or `~`
/// replaced, a relative pattern put under `cwd`.
fn fixup(arena: Allocator, pattern: []const u8, cwd: []const u8, home: []const u8, why: *[]const u8) Allocator.Error!?[]const u8 {
    for (try segmentsOf(arena, pattern), 0..) |s, i| {
        const lit = try literalOf(arena, s);
        if ((std.mem.eql(u8, lit, ".") and i != 0) or std.mem.eql(u8, lit, "..")) {
            why.* = try std.fmt.allocPrint(arena, "Invalid pattern '{s}'. Relative pathing '.' and '..' is not allowed.", .{pattern});
            return null;
        }
    }
    var p = try normalize(arena, pattern);
    if (std.mem.eql(u8, p, ".") or std.mem.startsWith(u8, p, "./")) {
        p = try std.mem.concat(arena, u8, &.{ try globEscape(arena, cwd), p[1..] });
    } else if (std.mem.eql(u8, p, "~") or std.mem.startsWith(u8, p, "~/")) {
        p = try std.mem.concat(arena, u8, &.{ try globEscape(arena, home), p[1..] });
    } else if (p[0] != '/') {
        const root = try globEscape(arena, cwd);
        p = try std.mem.concat(arena, u8, &.{ root, if (std.mem.endsWith(u8, root, "/")) "" else "/", p });
    }
    return try normalize(arena, p);
}

/// The patterns `hashFiles()` was given, as GitHub's runner reads its arguments: a first
/// argument starting with `--` is an option (only `--follow-symbolic-links`), the rest are joined
/// by newlines and read as @actions/glob reads them.
pub const Parsed = union(enum) {
    ok: struct { patterns: []const Pattern, follow: bool },
    invalid: []const u8,
};

pub fn parse(arena: Allocator, args: []const []const u8, cwd: []const u8, home: []const u8) Allocator.Error!Parsed {
    var follow = false;
    var rest = args;
    if (rest.len > 0 and std.mem.startsWith(u8, rest[0], "--")) {
        if (!std.ascii.eqlIgnoreCase(rest[0], "--follow-symbolic-links"))
            return .{ .invalid = try std.fmt.allocPrint(arena, "Invalid glob option {s}, avaliable option: '--follow-symbolic-links'.", .{rest[0]}) };
        follow = true;
        rest = rest[1..];
    }
    var patterns: std.ArrayList(Pattern) = .empty;
    for (rest) |arg| {
        var lines = std.mem.splitScalar(u8, arg, '\n');
        while (lines.next()) |raw| {
            const line = trim(raw);
            if (line.len == 0 or line[0] == '#') continue;
            var why: []const u8 = "";
            const p = (try Pattern.init(arena, line, cwd, home, false, &why)) orelse return .{ .invalid = why };
            try patterns.append(arena, p);
        }
    }
    return .{ .ok = .{ .patterns = patterns.items, .follow = follow } };
}

/// The patterns with implicit descendants added (`globGenerator`); null, with `why`, when one is
/// refused (`Pattern.descendants`).
fn withDescendants(arena: Allocator, patterns: []const Pattern, why: *[]const u8) Allocator.Error!?[]const Pattern {
    var out: std.ArrayList(Pattern) = .empty;
    for (patterns) |p| {
        try out.append(arena, p);
        if (p.trailing_separator or !std.mem.eql(u8, p.segments[p.segments.len - 1], "**"))
            try out.append(arena, (try p.descendants(arena, why)) orelse return null);
    }
    return out.items;
}

/// The search paths: each including pattern's, leaving out those below another (`getSearchPaths`).
fn searchPaths(arena: Allocator, patterns: []const Pattern) Allocator.Error![]const []const u8 {
    var candidates: std.StringHashMapUnmanaged(bool) = .empty; // value: included
    for (patterns) |p| if (!p.negate) try candidates.put(arena, p.search_path, false);
    var out: std.ArrayList([]const u8) = .empty;
    for (patterns) |p| {
        if (p.negate) continue;
        if (candidates.get(p.search_path).?) continue;
        var key = p.search_path;
        var parent = dirname(key);
        const found = while (!std.mem.eql(u8, parent, key)) {
            if (candidates.contains(parent)) break true;
            key = parent;
            parent = dirname(key);
        } else false;
        if (!found) {
            try out.append(arena, p.search_path);
            try candidates.put(arena, p.search_path, true);
        }
    }
    return out.items;
}

fn matchAll(arena: Allocator, patterns: []const Pattern, item: []const u8) Allocator.Error!u2 {
    var result: u2 = MatchKind.none;
    for (patterns) |p| {
        const m = try p.match(arena, item);
        if (p.negate) result &= ~m else result |= m;
    }
    return result;
}

fn partialAll(arena: Allocator, patterns: []const Pattern, item: []const u8) Allocator.Error!bool {
    for (patterns) |p| if (!p.negate and try p.partialMatch(arena, item)) return true;
    return false;
}

// --- the walk ---

/// What a path is.
pub const Kind = enum { missing, file, directory, symlink, other };

/// The file system the walk asks, many paths at a time (every path absolute).
pub const Fs = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Error = error{ OutOfMemory, FsFailed };

    pub const VTable = struct {
        /// What each path is: following symbolic links (`follow`; a broken one is `missing`) or
        /// not (a link is `symlink`).
        stat: *const fn (ptr: *anyopaque, arena: Allocator, paths: []const []const u8, follow: bool) Error![]const Kind,
        /// The names in each directory, in any order (the walk sorts them).
        list: *const fn (ptr: *anyopaque, arena: Allocator, dirs: []const []const u8) Error![]const []const []const u8,
        /// Each path with every symbolic link resolved; null when this file system cannot.
        realpath: ?*const fn (ptr: *anyopaque, arena: Allocator, paths: []const []const u8) Error![]const []const u8,
        /// Called for each path the walk matches and each directory it lists, between the calls
        /// above: an error ends the walk. The walk itself can run long without asking `fs`
        /// anything (a directory of a million entries), so this is where a caller counts its
        /// work, watches its clock and sees a cancel.
        poll: ?*const fn (ptr: *anyopaque) Error!void = null,
    };
};

/// What the walk found, in the order @actions/glob yields it: files (and, without following
/// links, the links themselves; GitHub's script then skips any that is a directory). Directories
/// it matches are left out: hashFiles() skips them.
pub const Walked = union(enum) {
    files: []const []const u8,
    failed: []const u8,
};

/// What `hashFiles(args)` hashes: the files its patterns find under `ws`, as paths relative to it,
/// in the order GitHub hashes them; or why the patterns or the search failed. `why` is where
/// `fs` says what went wrong (`Fs.Error.FsFailed`).
pub const Found = union(enum) {
    files: []const []const u8,
    failed: []const u8,
};

pub fn find(
    arena: Allocator,
    fs: Fs,
    args: []const []const u8,
    ws: []const u8,
    home: []const u8,
    max_nodes_: usize,
    why: *[]const u8,
) Allocator.Error!Found {
    const parsed = switch (try parse(arena, args, ws, home)) {
        .invalid => |msg| return .{ .failed = msg },
        .ok => |p| p,
    };
    const found = switch (try walkLimited(arena, fs, parsed.patterns, parsed.follow, ws, max_nodes_, why)) {
        .failed => |msg| return .{ .failed = msg },
        .files => |f| f,
    };
    var files: std.ArrayList([]const u8) = .empty;
    for (found) |path| {
        if (std.mem.startsWith(u8, path, ws) and path.len > ws.len and path[ws.len] == '/')
            try files.append(arena, path[ws.len + 1 ..]);
    }
    return .{ .files = files.items };
}

/// One path the walk visits. 32 bytes: a monorepo is a million of them.
const Node = struct {
    path: []const u8,
    parent: u32,
    yield_file: bool = false,
    /// Its children, which were made together: the nodes `first` to `first + count`.
    first: u32 = 0,
    count: u32 = 0,
};

const no_node = std.math.maxInt(u32);

/// How many files and directories one walk may visit on the native backend (`walk` itself, and the
/// Dagger path, have no limit). With `--follow-symbolic-links` a tree of
/// links can name the same directory by exponentially many paths (a directory whose two links lead
/// to the next, twenty-five deep), and @actions/glob only breaks cycles through a directory's own
/// ancestors. A real monorepo with its `node_modules` has a few hundred thousand entries (the
/// Linux kernel has about 90,000 files), so a million leaves room. A walk costs about 1.5 KB of
/// counted memory an entry with `**` (`native/hash_files.zig`, Limits), more than the default
/// memory allows for a million: on a small host that, not this, is what stops a big walk.
pub const max_nodes: usize = 1_000_000;

/// @actions/glob's walk (`globGenerator`), batched: each level of the tree is matched, looked at
/// and listed with one call each to `fs`, then the yields are read off depth-first, children in
/// byte order. Only what can
/// end up in `within` (the workspace: hashFiles() ignores anything outside it) is walked.
pub fn walk(
    arena: Allocator,
    fs: Fs,
    patterns_in: []const Pattern,
    follow: bool,
    within: []const u8,
    why: *[]const u8,
) Allocator.Error!Walked {
    return walkLimited(arena, fs, patterns_in, follow, within, std.math.maxInt(usize), why);
}

/// `walk`, failing when it would visit more than `limit` files and directories.
pub fn walkLimited(
    arena: Allocator,
    fs: Fs,
    patterns_in: []const Pattern,
    follow: bool,
    within: []const u8,
    limit: usize,
    why: *[]const u8,
) Allocator.Error!Walked {
    if (follow and fs.vtable.realpath == null) return .{ .failed = "--follow-symbolic-links is not supported here yet" };
    const patterns = (try withDescendants(arena, patterns_in, why)) orelse return .{ .failed = why.* };
    var nodes: std.ArrayList(Node) = .empty;
    var roots: std.ArrayList(u32) = .empty;
    var frontier: std.ArrayList(u32) = .empty;
    // Where each directory really is, when links are followed: to see a cycle.
    var where: std.AutoHashMapUnmanaged(u32, []const u8) = .empty;
    for (try searchPaths(arena, patterns)) |sp| {
        if (!relevant(sp, within)) continue;
        try roots.append(arena, @intCast(nodes.items.len));
        try frontier.append(arena, @intCast(nodes.items.len));
        try nodes.append(arena, .{ .path = sp, .parent = no_node });
    }

    // What the walk keeps is the nodes (and their paths) in `arena`; what it needs to look at one
    // path, one level, is in arenas that are reset after, so a directory of a million entries
    // costs its entries and not also the matching of each.
    var scratch: std.heap.ArenaAllocator = .init(arena);
    defer scratch.deinit();
    var level_arena: std.heap.ArenaAllocator = .init(arena);
    defer level_arena.deinit();

    while (frontier.items.len > 0) {
        try recycle(&level_arena);
        const level = level_arena.allocator();
        // Match first, as @actions/glob does: what cannot match, and has nothing below that can,
        // is not even looked at.
        var kept: std.ArrayList(u32) = .empty;
        var kinds_of: std.ArrayList(u2) = .empty;
        var paths: std.ArrayList([]const u8) = .empty;
        for (frontier.items) |n| {
            if (fs.vtable.poll) |poll| poll(fs.ptr) catch |e| return failed(arena, e, why);
            const path = nodes.items[n].path;
            try recycle(&scratch);
            const m = try matchAll(scratch.allocator(), patterns, path);
            const partial = m != MatchKind.none or try partialAll(scratch.allocator(), patterns, path);
            if (m == MatchKind.none and !partial) continue;
            try kept.append(level, n);
            try kinds_of.append(level, if (partial and m == MatchKind.none) 0 else m);
            try paths.append(level, path);
        }
        if (kept.items.len == 0) break;
        const kinds = fs.vtable.stat(fs.ptr, level, paths.items, follow) catch |e| return failed(arena, e, why);

        var dirs: std.ArrayList(u32) = .empty;
        var dir_paths: std.ArrayList([]const u8) = .empty;
        for (kept.items, kinds, kinds_of.items) |n, kind, m| {
            switch (kind) {
                // Gone, or (following links) a broken link: omitted.
                .missing => {},
                .directory => {
                    // `match & Directory` yields the directory (not wanted here) and descends;
                    // otherwise only a partial match descends, and everything kept is one.
                    try dirs.append(level, n);
                    try dir_paths.append(level, nodes.items[n].path);
                },
                else => if (m & MatchKind.file != 0) {
                    nodes.items[n].yield_file = true;
                },
            }
        }
        if (follow and dirs.items.len > 0) {
            // A directory that is one of its own ancestors, through a link, is a cycle: skipped.
            const reals = fs.vtable.realpath.?(fs.ptr, level, dir_paths.items) catch |e| return failed(arena, e, why);
            var acyclic: std.ArrayList(u32) = .empty;
            var acyclic_paths: std.ArrayList([]const u8) = .empty;
            for (dirs.items, reals) |n, real| {
                try where.put(arena, n, try arena.dupe(u8, real));
                var cycle = false;
                var a = nodes.items[n].parent;
                while (a != no_node) : (a = nodes.items[a].parent) {
                    if (where.get(a)) |r| if (std.mem.eql(u8, r, real)) {
                        cycle = true;
                    };
                }
                if (cycle) continue;
                try acyclic.append(level, n);
                try acyclic_paths.append(level, nodes.items[n].path);
            }
            dirs = acyclic;
            dir_paths = acyclic_paths;
        }
        frontier.clearRetainingCapacity();
        if (dirs.items.len == 0) break;
        const listed = fs.vtable.list(fs.ptr, level, dir_paths.items) catch |e| return failed(arena, e, why);
        for (dirs.items, listed) |n, names_in| {
            if (fs.vtable.poll) |poll| poll(fs.ptr) catch |e| return failed(arena, e, why);
            // In byte order, as libuv's scandir gives them to Node.
            const names = try level.dupe([]const u8, names_in);
            std.mem.sort([]const u8, names, {}, struct {
                fn lt(_: void, l: []const u8, r: []const u8) bool {
                    return std.mem.lessThan(u8, l, r);
                }
            }.lt);
            const first = std.math.cast(u32, nodes.items.len) orelse return error.OutOfMemory;
            const parent = nodes.items[n].path;
            const slash = if (std.mem.endsWith(u8, parent, "/")) "" else "/";
            for (names) |name| {
                if (fs.vtable.poll) |poll| poll(fs.ptr) catch |e| return failed(arena, e, why);
                try recycle(&scratch);
                const child = try std.mem.concat(scratch.allocator(), u8, &.{ parent, slash, name });
                if (!relevant(child, within)) continue;
                if (nodes.items.len >= limit) return .{ .failed = try std.fmt.allocPrint(arena, "the search " ++
                    "met more than {d} files and directories (links that lead to the same directories " ++
                    "by many paths, perhaps): narrow the patterns", .{limit}) };
                try frontier.append(arena, @intCast(nodes.items.len));
                try nodes.append(arena, .{ .path = try arena.dupe(u8, child), .parent = n });
            }
            nodes.items[n].first = first;
            nodes.items[n].count = std.math.cast(u32, nodes.items.len - first) orelse return error.OutOfMemory;
        }
    }

    // Depth-first from each search path in turn, children in listed order.
    var out: std.ArrayList([]const u8) = .empty;
    var stack: std.ArrayList(u32) = .empty;
    for (roots.items) |r| {
        try stack.append(arena, r);
        while (stack.pop()) |n| {
            const node = nodes.items[n];
            if (node.yield_file) try out.append(arena, node.path);
            var i = node.count;
            while (i > 0) {
                i -= 1;
                try stack.append(arena, node.first + i);
            }
        }
    }
    return .{ .files = out.items };
}

/// Empties the arena for its next use, keeping what it holds. `reset` answers false when it could
/// not keep it, having made do without: that is an allocation that failed, and not one to pass over.
fn recycle(a: *std.heap.ArenaAllocator) Allocator.Error!void {
    if (!a.reset(.retain_capacity)) return error.OutOfMemory;
}

/// The walk failed because its file system did; its words (which may be in a level's arena, gone
/// when the walk returns) are copied to `arena`.
fn failed(arena: Allocator, e: Fs.Error, why: *[]const u8) Allocator.Error!Walked {
    if (e == error.OutOfMemory) return error.OutOfMemory;
    return .{ .failed = if (why.*.len > 0) try arena.dupe(u8, why.*) else "the file system could not be read" };
}

/// Whether anything at or below `path` can be inside `within`: it is inside, or on the way there.
fn relevant(path: []const u8, within: []const u8) bool {
    const p = trimTrailing(path);
    if (std.mem.eql(u8, p, within)) return true;
    if (std.mem.startsWith(u8, p, within) and p.len > within.len and p[within.len] == '/') return true;
    if (std.mem.eql(u8, p, "/")) return true;
    return std.mem.startsWith(u8, within, p) and within.len > p.len and within[p.len] == '/';
}

// --- tests ---

fn testPattern(arena: Allocator, line: []const u8) !Pattern {
    var why: []const u8 = "";
    return (try Pattern.init(arena, line, "/w", "/home/u", false, &why)) orelse {
        std.debug.print("refused: {s}\n", .{why});
        return error.TestUnexpectedResult;
    };
}

test "patterns: absolute under the workspace, search paths, trailing slash, refusals" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const p = try testPattern(ar, "  src/**/*.go ");
    try std.testing.expectEqualStrings("/w/src", p.search_path);
    try std.testing.expect(!p.trailing_separator and !p.negate);
    const d = try testPattern(ar, "!!!out/");
    try std.testing.expect(d.negate and d.trailing_separator);
    try std.testing.expectEqualStrings("/w/out", d.search_path);
    try std.testing.expectEqualStrings("/home/u/.cache", (try testPattern(ar, "~/.cache/*")).search_path);
    try std.testing.expectEqualStrings("/w/sub", (try testPattern(ar, "./sub/x?")).search_path);
    // `[1]` is the literal `1` for the search path; `[12]` is a glob.
    try std.testing.expectEqualStrings("/w/a1/b", (try testPattern(ar, "a[1]/b")).search_path);
    try std.testing.expectEqualStrings("/w", (try testPattern(ar, "a[12]/b")).search_path);
    var why: []const u8 = "";
    try std.testing.expect(try Pattern.init(ar, "src/./x", "/w", "/", false, &why) == null);
    try std.testing.expect(try Pattern.init(ar, "../w/x", "/w", "/", false, &why) == null);
    try std.testing.expect(try Pattern.init(ar, "!", "/w", "/", false, &why) == null);
}

test "matching: stars, classes, escapes, globstars, and partial matches" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const all = MatchKind.all;
    const none = MatchKind.none;
    const cases = [_]struct { []const u8, []const u8, u2 }{
        .{ "*.go", "/w/main.go", all },
        .{ "*.go", "/w/.hidden.go", all }, // dot: true
        .{ "*.go", "/w/src/main.go", none },
        .{ "**/*.go", "/w/src/a/main.go", all },
        .{ "**/*.go", "/w/main.go", all },
        .{ "src/**", "/w/src", all }, // the directory itself, as minimatch reads `/w/src/`
        .{ "src/**", "/w/src/x/y", all },
        .{ "[lU]*.T?T", "/w/UPPER.TXT", all },
        .{ "[!a-c]x", "/w/dx", all },
        .{ "[!a-c]x", "/w/bx", none },
        .{ "[[:digit:]]x", "/w/7x", all },
        .{ "star\\*.txt", "/w/star*.txt", all },
        .{ "star\\*.txt", "/w/starx.txt", none },
        .{ "q?.txt", "/w/qé.txt", all }, // one code point
        .{ "brackets[1].txt", "/w/brackets1.txt", all },
        .{ "brackets[1].txt", "/w/brackets[1].txt", none },
        .{ "a[b", "/w/a[b", all }, // unclosed: literal
        .{ "out/", "/w/out", MatchKind.directory },
        .{ "{a,b}", "/w/{a,b}", all }, // nobrace
    };
    for (cases) |c| {
        const p = try testPattern(ar, c[0]);
        std.testing.expectEqual(c[2], try p.match(ar, c[1])) catch |e| {
            std.debug.print("{s} vs {s}\n", .{ c[0], c[1] });
            return e;
        };
    }
    const deep = try testPattern(ar, "src/*/util/*.go");
    try std.testing.expect(try deep.partialMatch(ar, "/w/src/x"));
    try std.testing.expect(try deep.partialMatch(ar, "/"));
    try std.testing.expect(!try deep.partialMatch(ar, "/w/other"));
    // The implicit `pattern/**` matches only below.
    var imp_why: []const u8 = "";
    const imp = (try (try testPattern(ar, "src")).descendants(ar, &imp_why)).?;
    try std.testing.expectEqual(none, try imp.match(ar, "/w/src"));
    try std.testing.expectEqual(all, try imp.match(ar, "/w/src/a.go"));
}

test "a pattern whose implicit descendants @actions/glob refuses fails the walk, not the runner" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var mem: MemFs = .{ .kinds = &.{.{ "/w", .directory, .directory }}, .lists = &.{} };
    // `\.` is accepted as the first segment, and refused once under the workspace: GitHub's
    // hashFiles() throws when it adds `/w/\./**` (fixupPattern), and this asserted until the
    // fuzzer found it.
    for ([_][]const u8{ "\\.", "!\\." }) |line| {
        const parsed = (try parse(ar, &.{line}, "/w", "/home/u")).ok;
        var why: []const u8 = "";
        const got = try walk(ar, mem.fs(), parsed.patterns, false, "/w", &why);
        try std.testing.expect(std.mem.startsWith(u8, got.failed, "Invalid pattern '/w/\\./**'. Relative pathing"));
    }
}

test "search paths leave out those below another" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const ps = [_]Pattern{
        try testPattern(ar, "src/a/*.go"),
        try testPattern(ar, "src/*"),
        try testPattern(ar, "!x/**"),
        try testPattern(ar, "docs/**"),
    };
    try std.testing.expectEqualDeep(@as([]const []const u8, &.{ "/w/src", "/w/docs" }), try searchPaths(ar, &ps));
}

/// An in-memory tree for the walk's tests: paths to kinds, and directories' listings.
const MemFs = struct {
    kinds: []const struct { []const u8, Kind, Kind }, // path, without and with following links
    lists: []const struct { []const u8, []const []const u8 },

    fn fs(m: *MemFs) Fs {
        return .{ .ptr = m, .vtable = &.{ .stat = stat, .list = list, .realpath = null } };
    }
    fn stat(ptr: *anyopaque, arena: Allocator, paths: []const []const u8, follow: bool) Fs.Error![]const Kind {
        const m: *MemFs = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc(Kind, paths.len);
        for (paths, out) |p, *k| {
            k.* = .missing;
            for (m.kinds) |e| if (std.mem.eql(u8, e[0], p)) {
                k.* = if (follow) e[2] else e[1];
            };
        }
        return out;
    }
    fn list(ptr: *anyopaque, arena: Allocator, dirs: []const []const u8) Fs.Error![]const []const []const u8 {
        const m: *MemFs = @ptrCast(@alignCast(ptr));
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (dirs, out) |d, *l| {
            l.* = &.{};
            for (m.lists) |e| if (std.mem.eql(u8, e[0], d)) {
                l.* = e[1];
            };
        }
        return out;
    }
};

test "the walk: depth-first in listed order, pruned, exclusions, links not followed" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var mem: MemFs = .{
        .kinds = &.{
            .{ "/w", .directory, .directory },
            .{ "/w/b.txt", .file, .file },
            .{ "/w/a", .directory, .directory },
            .{ "/w/a/x.txt", .file, .file },
            .{ "/w/a/skip.txt", .file, .file },
            .{ "/w/link", .symlink, .directory },
            .{ "/w/a.txt", .file, .file },
        },
        .lists = &.{
            .{ "/w", &.{ "link", "b.txt", "a.txt", "a" } },
            .{ "/w/a", &.{ "x.txt", "skip.txt" } },
        },
    };
    var why: []const u8 = "";
    const parsed = (try parse(ar, &.{ "**/*.txt\n!a/skip.txt", "link" }, "/w", "/")).ok;
    const got = (try walk(ar, mem.fs(), parsed.patterns, false, "/w", &why)).files;
    // Depth-first, children in byte order whatever the listing's: `a/x.txt` before `a.txt`, which
    // a sort of whole paths would put first ('.' < '/').
    try std.testing.expectEqualDeep(@as([]const []const u8, &.{ "/w/a/x.txt", "/w/a.txt", "/w/b.txt", "/w/link" }), got);
    try std.testing.expect(try parse(ar, &.{"--nope"}, "/w", "/") == .invalid);
    try std.testing.expect((try parse(ar, &.{ "--FOLLOW-symbolic-links", "x" }, "/w", "/")).ok.follow);
    // Following links needs canonical paths, which this file system does not give.
    try std.testing.expect(try walk(ar, mem.fs(), parsed.patterns, true, "/w", &why) == .failed);
}

/// `matchToks` as it was, backtracking on every `*`: exponential, but plainly minimatch's, so the
/// tests check the linear one against it.
fn matchToksBacktracking(toks: []const Tok, s: []const u8) bool {
    if (toks.len == 0) return s.len == 0;
    if (toks[0] == .star) {
        var i: usize = 0;
        while (true) {
            if (matchToksBacktracking(toks[1..], s[i..])) return true;
            if (i >= s.len) return false;
            _ = nextRune(s, &i);
        }
    }
    if (s.len == 0) return false;
    var i: usize = 0;
    const ch = nextRune(s, &i);
    const ok = switch (toks[0]) {
        .char => |c| c == ch,
        .any => true,
        .class => |cl| cl.has(ch),
        .star => unreachable,
    };
    return ok and matchToksBacktracking(toks[1..], s[i..]);
}

/// `matchOne` as it was, without remembering failed tries.
fn matchOneBacktracking(file: []const []const u8, pat: []const Part, partial: bool) bool {
    var fi: usize = 0;
    var pi: usize = 0;
    while (fi < file.len and pi < pat.len) : ({
        fi += 1;
        pi += 1;
    }) {
        const p = pat[pi];
        if (p == .globstar) {
            const pr = pi + 1;
            if (pr == pat.len) {
                for (file[fi..]) |f| if (std.mem.eql(u8, f, ".") or std.mem.eql(u8, f, "..")) return false;
                return true;
            }
            var fr = fi;
            while (fr < file.len) : (fr += 1) {
                if (matchOneBacktracking(file[fr..], pat[pr..], partial)) return true;
                const swallowee = file[fr];
                if (std.mem.eql(u8, swallowee, ".") or std.mem.eql(u8, swallowee, "..")) break;
            }
            return partial and fr == file.len;
        }
        if (!matchPart(p, file[fi])) return false;
    }
    if (fi == file.len and pi == pat.len) return true;
    if (fi == file.len) return partial;
    return fi == file.len - 1 and file[fi].len == 0;
}

test "stars match in linear steps, where backtracking took exponentially many" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Backtracking tried every way to share the `a`s among 8 stars before failing: C(32, 8) ≈ 1e7
    // ways for 24 `a`s, 18.7 s for 40.
    const toks = (try compilePart(ar, "*a*a*a*a*a*a*a*a*b")).magic;
    for ([_]usize{ 24, 40 }) |n| {
        const s = try ar.alloc(u8, n + 1);
        @memset(s, 'a');
        s[n] = 'b';
        var steps: usize = 0;
        try std.testing.expect(!matchToksCounted(toks, s[0..n], &steps));
        try std.testing.expect(steps <= 2 * toks.len * (n + 1));
        steps = 0;
        try std.testing.expect(matchToksCounted(toks, s, &steps));
        try std.testing.expect(steps <= 2 * toks.len * (n + 2));
    }
}

test "the linear star match agrees with backtracking, code points and stray bytes included" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var prng: std.Random.DefaultPrng = .init(99);
    const r = prng.random();
    const pat_atoms = [_][]const u8{ "*", "*", "?", "a", "b", "é", "[ab]", "[!a]", "[[:alpha:]]", "\xc3", "\xa9", "\\*" };
    const str_atoms = [_][]const u8{ "a", "b", "é", "\xc3", "\xa9", "*", "\xe2\x82\xac", "\xe2" };
    for (0..20000) |_| {
        var pat: std.ArrayList(u8) = .empty;
        for (0..r.uintAtMost(usize, 7)) |_| try pat.appendSlice(ar, pat_atoms[r.uintLessThan(usize, pat_atoms.len)]);
        var s: std.ArrayList(u8) = .empty;
        for (0..r.uintAtMost(usize, 8)) |_| try s.appendSlice(ar, str_atoms[r.uintLessThan(usize, str_atoms.len)]);
        const toks = switch (try compilePart(ar, pat.items)) {
            .magic => |t| t,
            else => continue,
        };
        std.testing.expectEqual(matchToksBacktracking(toks, s.items), matchToks(toks, s.items)) catch |e| {
            std.debug.print("{s} vs {s}\n", .{ pat.items, s.items });
            return e;
        };
    }
}

test "globstars try each place once, where backtracking tried every way" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Six `**` with an `a` after each, against `/w/a/.../a` (no `b`): backtracking tried every way
    // to place the six `a`s, C(30, 6) ≈ 6e5 of them at 30 deep (past 60 s at 100 deep).
    const p = try testPattern(ar, "/w/**/a/**/a/**/a/**/a/**/a/**/a/b");
    for ([_]usize{ 30, 100 }) |depth| {
        var path: std.ArrayList(u8) = .empty;
        try path.appendSlice(ar, "/w");
        for (0..depth) |_| try path.appendSlice(ar, "/a");
        const file = try splitPath(ar, path.items);
        var m: OneMatch = .{ .arena = ar, .file = file, .pat = p.parts, .partial = false };
        try std.testing.expect(!try m.from(0, 0));
        try std.testing.expect(m.steps <= file.len * p.parts.len);
        // As the walk asks it of a directory: something below could match.
        m = .{ .arena = ar, .file = file, .pat = p.parts, .partial = true };
        try std.testing.expect(try m.from(0, 0));
        try std.testing.expect(m.steps <= file.len * p.parts.len);
    }
    try std.testing.expectEqual(MatchKind.all, try p.match(ar, "/w/a/x/a/a/y/a/a/z/a/b"));
}

test "remembering failed globstar tries agrees with backtracking" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var prng: std.Random.DefaultPrng = .init(99);
    const r = prng.random();
    const pat_atoms = [_][]const u8{ "**", "**", "a", "b", "*", "?", "" };
    const seg_atoms = [_][]const u8{ "a", "b", "ab", ".", "..", "" };
    for (0..20000) |_| {
        var pat: std.ArrayList(u8) = .empty;
        for (0..r.uintAtMost(usize, 6)) |i| {
            if (i > 0) try pat.append(ar, '/');
            try pat.appendSlice(ar, pat_atoms[r.uintLessThan(usize, pat_atoms.len)]);
        }
        var path: std.ArrayList(u8) = .empty;
        for (0..r.uintAtMost(usize, 7)) |i| {
            if (i > 0) try path.append(ar, '/');
            try path.appendSlice(ar, seg_atoms[r.uintLessThan(usize, seg_atoms.len)]);
        }
        var parts: std.ArrayList(Part) = .empty;
        for (try splitPath(ar, pat.items)) |seg| try parts.append(ar, try compilePart(ar, seg));
        const file = try splitPath(ar, path.items);
        for ([_]bool{ false, true }) |partial| {
            std.testing.expectEqual(
                matchOneBacktracking(file, parts.items, partial),
                try matchOne(ar, file, parts.items, partial),
            ) catch |e| {
                std.debug.print("{s} vs {s} partial={}\n", .{ pat.items, path.items, partial });
                return e;
            };
        }
    }
}

/// A workspace of one directory of `names` files, which only counts what it is asked, and says
/// "stop" from its `poll` once it has been asked `stop_after` times.
const Wide = struct {
    names: usize,
    stop_after: usize,
    polls: usize = 0,
    stats: usize = 0,

    fn of(ptr: *anyopaque) *Wide {
        return @ptrCast(@alignCast(ptr));
    }

    fn fs(w: *Wide) Fs {
        return .{ .ptr = w, .vtable = &.{ .stat = stat, .list = list, .realpath = null, .poll = poll } };
    }

    fn stat(ptr: *anyopaque, arena: Allocator, paths: []const []const u8, _: bool) Fs.Error![]const Kind {
        const w = Wide.of(ptr);
        w.stats += 1;
        const out = try arena.alloc(Kind, paths.len);
        for (paths, out) |p, *k| k.* = if (std.mem.eql(u8, p, "/w")) .directory else .file;
        return out;
    }

    fn list(ptr: *anyopaque, arena: Allocator, dirs: []const []const u8) Fs.Error![]const []const []const u8 {
        const w = Wide.of(ptr);
        const out = try arena.alloc([]const []const u8, dirs.len);
        for (out) |*names| {
            const l = try arena.alloc([]const u8, w.names);
            for (l, 0..) |*n, i| n.* = try std.fmt.allocPrint(arena, "f{d}", .{i});
            names.* = l;
        }
        return out;
    }

    fn poll(ptr: *anyopaque) Fs.Error!void {
        const w = Wide.of(ptr);
        w.polls += 1;
        if (w.polls > w.stop_after) return error.FsFailed;
    }
};

test "the walk asks its file system whether to go on for each path it matches, not only between calls" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var wide: Wide = .{ .names = 3000, .stop_after = 500 };
    var why: []const u8 = "";
    const p = try testPattern(ar, "**");
    // The first level has one directory; the second 3000 files, matched one after the other:
    // it stops among them, before the second `stat`.
    const got = try walk(ar, wide.fs(), &.{p}, false, "/w", &why);
    try std.testing.expect(got == .failed);
    try std.testing.expectEqual(@as(usize, 1), wide.stats);
    try std.testing.expect(wide.polls < 700);
    // Not stopped, the same walk goes through every file.
    var open: Wide = .{ .names = 3000, .stop_after = std.math.maxInt(usize) };
    const all = try walk(ar, open.fs(), &.{p}, false, "/w", &why);
    try std.testing.expectEqual(@as(usize, 3000), all.files.len);
}
