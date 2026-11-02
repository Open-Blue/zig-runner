//! Regular expressions as GitHub's runner reads a problem matcher's: actions/runner's IssueMatcher.cs
//! compiles each with .NET's `new Regex(pattern, RegexOptions.CultureInvariant |
//! RegexOptions.ECMAScript)` and reads groups by number. This is that, in Zig: what .NET accepts in
//! that mode, with its answers. `.github/scripts/regex-diff.sh` compares it with .NET itself, on the
//! patterns problem matchers published on GitHub use and on random ones.
//!
//! **What ECMAScript mode means in .NET**, and so here (each checked against .NET):
//! - `\w`, `\d`, `\s` and `\b` are ASCII-only, in classes and under `(?i)` too, except that a word
//!   character may also be `İ` (U+0130), as .NET's ECMAWordClass and IsECMAWordChar have it.
//! - `\N` is a backreference when group N is already open, else an octal escape (`\033` is ESC);
//!   `\8` and `\9` are digits; octal stops before passing `\377`. A backreference to a group that
//!   took no part matches the empty string.
//! - An unknown escape is the character itself (`\Q` is `Q`); `[^]` is any character.
//!
//! **Supported**, as in .NET: literals (any code point), `.`, classes (ranges, negation,
//! subtraction `[a-z-[aeiou]]`, shorthands, escapes), `^ $ \A \z \Z \G \b \B`, capturing,
//! non-capturing, named (`(?<n>…)`, `(?'n'…)`) and numbered (`(?<2>…)`) groups, numbered and named
//! backreferences (`\1`, `\k<n>`), lookahead and lookbehind (of any length, matched right to left
//! as .NET does), atomic groups `(?>…)`, conditionals `(?(1)…|…)`, `(?(name)…)`, `(?(?=…)…)`,
//! inline options `i m s x n` (`(?i)`, `(?-i)`, `(?i:…)`), comments `(?#…)`, the quantifiers
//! `* + ? {n} {n,} {n,m}` greedy or lazy, and the escapes `\t \n \r \f \v \a \e \xHH \uHHHH \cX`
//! and octal. Groups are numbered as .NET numbers them: unnamed ones first, then named ones.
//!
//! **Unicode categories and blocks**, `\p{…}` and `\P{…}`, in classes too, as .NET 8 has them
//! (ECMAScript mode takes them): the general categories (`Lu`, …, `Cn`) and their groups (`L`,
//! `M`, `N`, `P`, `S`, `Z`, `C`), and .NET's own list of blocks, which is not Unicode's: legacy
//! names (`IsGreek` beside `IsGreekandCoptic`), ranges as Unicode had them years ago, and four
//! undocumented `_xml…` classes. Names are case-sensitive; an unknown one, `\pL` without braces,
//! and a category as a range's end are errors. The tables (unicode_tables.zig) are Unicode 15.0's,
//! which .NET 8's are, and every code unit's answer for every name was checked against .NET's. With
//! `(?i)`, `Lu`, `Ll` and `Lt` each mean all three, other categories are not case folded, and a
//! block folds as its ranges do (`(?i)\P{IsBasicLatin}` matches `k`, for the Kelvin sign).
//!
//! **Refused, loudly** (`error.Unsupported`): balancing groups (`(?<a-b>…)`). A matcher whose
//! pattern is refused goes inert and says so: an expression understood wrongly annotates the wrong
//! file and line, which is worse than annotating nothing.
//!
//! **Characters, not bytes**: input is matched by code point (a byte that is not valid UTF-8 is a
//! character of its own); positions stay byte offsets. .NET counts UTF-16 units, so a character
//! outside the Basic Multilingual Plane (an emoji) is one character here and two there. To `\p` it
//! is what its first unit is to .NET: a surrogate (`Cs`), in `IsHighSurrogates` or
//! `IsHighPrivateUseSurrogates`, so `\p{L}` matches no part of it and `\P{IsBasicLatin}` all of it.
//!
//! **Where .NET is not followed**, on purpose: in a few patterns no problem matcher would write,
//! .NET's answers cannot be right (a match that leaves out the pattern's own first characters,
//! with a quantifier over something that matches nothing: `c\((\B)+?.`, `\2+?` for a group that
//! took no part, a group referring to itself), or come from its optimizer (`\W{2,}\B` refusing to
//! give back a character where `\W{3}\B` matches). These keep the plain reading.
//!
//! **The design is a compiled program and an iterative VM**, after Thompson's construction as Russ
//! Cox describes it, backtracking on a heap stack with a trail to undo captures. Lookaround,
//! atomic groups and conditions on lookahead run their body as a nested match. Lookbehind bodies
//! are compiled to run backwards.
//!
//! **There is a step budget.** Backtracking can be made to run for ever by a pattern and an input
//! together (`(a+)+b` against a long run of `a`), and this is handed patterns from actions and
//! lines from builds. Past the budget a match fails with `error.TooComplex` rather than hanging the
//! runner, and the caller makes the matcher inert. (GitHub's runner sets a timeout for the same.)
//! A backreference costs a step per character it compares, and memory grows with the steps taken
//! and the number of groups, never with a group's number.

const std = @import("std");
const Allocator = std.mem.Allocator;
const tables = @import("unicode_tables.zig");

pub const Error = error{ BadPattern, Unsupported, TooComplex, OutOfMemory };

/// Instructions executed per `find` (nested matches included) before giving up. Generous for real
/// patterns on a long log line, and small enough to stay imperceptible.
const step_budget: usize = 200_000;

/// Backtracking points held at once. Bounds memory as `step_budget` bounds time.
const max_backtrack: usize = 50_000;

/// Instructions a compiled program may hold; `{n,m}` is expanded, so this bounds it.
const max_program: usize = 10_000;

/// How deeply groups may nest; bounds the parser's own recursion.
const max_depth = 64;

// --- characters ---

const Decoded = struct { c: u21, len: usize };

/// The character at `s[i]`. A byte that does not start valid UTF-8 is a character of its own, in
/// the lone-surrogate range, which valid UTF-8 never produces.
fn decodeAt(s: []const u8, i: usize) ?Decoded {
    if (i >= s.len) return null;
    const len = std.unicode.utf8ByteSequenceLength(s[i]) catch 0;
    if (len > 1 and i + len <= s.len) {
        if (std.unicode.utf8Decode(s[i .. i + len])) |c| return .{ .c = c, .len = len } else |_| {}
    }
    if (len == 1) return .{ .c = s[i], .len = 1 };
    return .{ .c = 0xDC00 | @as(u21, s[i]), .len = 1 };
}

/// The character that ends at `s[i]` (what a backwards step consumes).
fn decodeBefore(s: []const u8, i: usize) ?Decoded {
    if (i == 0) return null;
    var start = i - 1;
    var n: usize = 0;
    while (start > 0 and n < 3 and s[start] & 0xC0 == 0x80) : (n += 1) start -= 1;
    if (decodeAt(s, start)) |d| if (start + d.len == i) return d;
    return decodeAt(s, i - 1);
}

/// Simple lower-case mapping (CultureInvariant): ASCII, Latin-1, Latin Extended-A, Greek, Cyrillic,
/// and the few letters whose lower case lives elsewhere (the Kelvin sign is `k`).
fn lower(c: u21) u21 {
    return switch (c) {
        'A'...'Z' => c + 32,
        0xC0...0xD6, 0xD8...0xDE => c + 0x20,
        0x100...0x12F, 0x132...0x137, 0x14A...0x177 => c | 1,
        0x139...0x148, 0x179...0x17E => if (c % 2 == 1) c + 1 else c,
        0x178 => 0xFF,
        0x386 => 0x3AC,
        0x388...0x38A => c + 37,
        0x38C => 0x3CC,
        0x38E, 0x38F => c + 63,
        0x391...0x3A1, 0x3A3...0x3AB => c + 0x20,
        0x400...0x40F => c + 0x50,
        0x410...0x42F => c + 0x20,
        0x460...0x481, 0x48A...0x4BF, 0x4D0...0x52F => c | 1,
        0x4C1...0x4CE => if (c % 2 == 1) c + 1 else c,
        0x4C0 => 0x4CF,
        0x1E9E => 0xDF, // capital sharp s
        0x212A => 'k', // Kelvin sign
        0x212B => 0xE5, // Ångström sign
        0x2126 => 0x3C9, // Ohm sign
        else => c,
    };
}

/// Simple upper-case mapping, the other direction of `lower`.
fn upper(c: u21) u21 {
    return switch (c) {
        'a'...'z' => c - 32,
        0xE0...0xF6, 0xF8...0xFE => c - 0x20,
        0xFF => 0x178,
        0x101...0x12F, 0x133...0x137, 0x14B...0x177 => if (c % 2 == 1) c - 1 else c,
        0x13A...0x148, 0x17A...0x17E => if (c % 2 == 0) c - 1 else c,
        0x3AC => 0x386,
        0x3AD...0x3AF => c - 37,
        0x3CC => 0x38C,
        0x3CD, 0x3CE => c - 63,
        0x3B1...0x3C1, 0x3C3...0x3CB => c - 0x20,
        0x3C2 => 0x3A3,
        0x430...0x44F => c - 0x20,
        0x450...0x45F => c - 0x50,
        0x461...0x481, 0x48B...0x4BF, 0x4D1...0x52F => if (c % 2 == 1) c - 1 else c,
        0x4C2...0x4CE => if (c % 2 == 0) c - 1 else c,
        0x4CF => 0x4C0,
        else => c,
    };
}

fn foldEq(a: u21, b: u21) bool {
    return a == b or lower(a) == lower(b);
}

/// What `\w` (and `\b`) take as a word character in ECMAScript mode: ASCII letters, digits, `_`,
/// and `İ`, which .NET adds (RegexCharClass.IsECMAWordChar).
fn isWord(c: u21) bool {
    return c == '_' or c == 0x130 or (c < 0x80 and std.ascii.isAlphanumeric(@intCast(c)));
}

// --- character sets ---

const Set = struct {
    negated: bool = false,
    /// `[^]`: any character, newlines included.
    any: bool = false,
    items: []const Item = &.{},
    /// `[a-z-[aeiou]]`: what is taken out.
    subtract: ?*const Set = null,

    const Item = union(enum) {
        range: [2]u21,
        shorthand: Shorthand,
        category: Categories,
    };

    /// Membership before negation, case folded when `fold` (so `(?i)[^a]` does not match `A`).
    fn positive(set: *const Set, c: u21, fold: bool) bool {
        if (set.any) return true;
        for (set.items) |it| switch (it) {
            .range => |r| {
                if (c >= r[0] and c <= r[1]) return true;
                if (fold) {
                    const l = lower(c);
                    const u = upper(c);
                    if ((l >= r[0] and l <= r[1]) or (u >= r[0] and u <= r[1])) return true;
                    // A range of upper case letters folded for a lower case one, and the reverse.
                    if (rangeHasFold(r, c)) return true;
                }
            },
            .shorthand => |s| if (s.matches(c)) return true,
            // Never case folded (.NET folds only a class's ranges).
            .category => |k| if (k.matches(c)) return true,
        };
        return false;
    }

    fn has(set: *const Set, c: u21, fold: bool) bool {
        var in = set.positive(c, fold) != set.negated;
        if (in) if (set.subtract) |sub| {
            if (sub.has(c, fold)) in = false;
        };
        return in;
    }
};

/// Whether some character in `r` folds to the same as `c` (the Kelvin sign for `[a-z]`).
fn rangeHasFold(r: [2]u21, c: u21) bool {
    const want = lower(c);
    for ([_]u21{ 0x212A, 0x212B, 0x2126, 0x1E9E }) |special| {
        if (special >= r[0] and special <= r[1] and lower(special) == want) return true;
    }
    return false;
}

const Shorthand = struct {
    kind: enum { space, digit, word },
    negated: bool,

    fn matches(s: Shorthand, c: u21) bool {
        const in = switch (s.kind) {
            .space => c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0b or c == 0x0c,
            .digit => c >= '0' and c <= '9',
            .word => isWord(c),
        };
        return in != s.negated;
    }
};

/// `\p{L}`, `\P{Lu}`: general categories, as a set of them (a bit per `tables.Category`).
const Categories = struct {
    mask: u32,
    negated: bool,

    fn matches(k: Categories, c: u21) bool {
        const in = k.mask & bit(categoryOf(c)) != 0;
        return in != k.negated;
    }
};

fn bit(c: tables.Category) u32 {
    return @as(u32, 1) << @backingInt(c);
}

/// The general category .NET gives `c`. It counts UTF-16 units, and both halves of a character
/// outside the Basic Multilingual Plane are surrogates.
fn categoryOf(c: u21) tables.Category {
    if (c > 0xFFFF) return .Cs;
    // The last run starting at or before `c`.
    var lo: usize = 0;
    var hi: usize = tables.run_starts.len;
    while (hi - lo > 1) {
        const mid = (lo + hi) / 2;
        if (tables.run_starts[mid] <= c) lo = mid else hi = mid;
    }
    return tables.run_categories[lo];
}

/// A category or group of them by .NET's name (RegexCharClass.s_definedCategories). With `fold`,
/// `Lu`, `Ll` and `Lt` each mean all three, as in .NET.
fn categoryMask(name: []const u8, fold: bool) ?u32 {
    const groups = [_]struct { []const u8, []const tables.Category }{
        .{ "L", &.{ .Lu, .Ll, .Lt, .Lm, .Lo } },
        .{ "M", &.{ .Mn, .Mc, .Me } },
        .{ "N", &.{ .Nd, .Nl, .No } },
        .{ "P", &.{ .Pc, .Pd, .Ps, .Pe, .Pi, .Pf, .Po } },
        .{ "S", &.{ .Sm, .Sc, .Sk, .So } },
        .{ "Z", &.{ .Zs, .Zl, .Zp } },
        .{ "C", &.{ .Cc, .Cf, .Cs, .Co, .Cn } },
    };
    for (groups) |g| if (std.mem.eql(u8, name, g[0])) {
        var mask: u32 = 0;
        for (g[1]) |c| mask |= bit(c);
        return mask;
    };
    const one = std.meta.stringToEnum(tables.Category, name) orelse return null;
    if (fold and (one == .Lu or one == .Ll or one == .Lt)) return bit(.Lu) | bit(.Ll) | bit(.Lt);
    return bit(one);
}

/// .NET's block `name` as code unit ranges; null when there is none.
fn blockRanges(name: []const u8) ?[]const [2]u16 {
    for (tables.blocks) |b| if (std.mem.eql(u8, name, b.name))
        return tables.block_ranges[b.first..][0..b.count];
    return null;
}

/// A range of code units as an item, and the characters outside the Basic Multilingual Plane whose
/// first UTF-16 unit is in it (a high surrogate), which here are one character.
fn appendUnits(arena: Allocator, items: *std.ArrayList(Set.Item), lo: u21, hi: u21) Error!void {
    try items.append(arena, .{ .range = .{ lo, hi } });
    const a: u21 = @max(lo, 0xD800);
    const b: u21 = @min(hi, 0xDBFF);
    if (a <= b) try items.append(arena, .{ .range = .{ 0x10000 + ((a - 0xD800) << 10), 0x10000 + ((b - 0xD800) << 10) + 0x3FF } });
}

// --- syntax ---

const Assert = enum {
    /// `^`, and `^` with `m`.
    bol,
    bol_multi,
    /// `$` (end, or before a final newline), and `$` with `m`.
    eol,
    eol_multi,
    /// `\A`, `\z`, `\Z`, `\G`.
    start,
    end,
    end_or_newline,
    search_start,
    /// `\b`, `\B`.
    boundary,
    not_boundary,
};

const Flags = struct {
    i: bool = false,
    m: bool = false,
    s: bool = false,
    x: bool = false,
    n: bool = false,
};

/// A reference by number or by name, resolved to a number once every group is known.
const Ref = struct {
    name: ?[]const u8 = null,
    number: u32 = 0,
};

const Node = union(enum) {
    char: struct { c: u21, fold: bool },
    any: struct { dotall: bool },
    set: struct { set: *const Set, fold: bool },
    assert: Assert,
    /// `cap`: the capture's index in `Parser.caps`, null for a group that does not capture.
    group: struct { cap: ?usize, alts: []const []const Node },
    repeat: struct { node: *const Node, min: u32, max: u32, greedy: bool },
    backref: struct { ref: *Ref, fold: bool },
    look: struct { behind: bool, negate: bool, alts: []const []const Node },
    atomic: []const []const Node,
    cond: struct { cond: *Cond, yes: []const Node, no: []const Node },
};

/// What a conditional tests: whether a group matched, or a lookahead. `(?(x)…)` names a group if
/// there is one called `x`, else it is the lookahead `x`: both are parsed, and settled at the end.
const Cond = struct {
    ref: ?Ref = null,
    look: ?[]const []const Node = null,
};

/// A capturing group as written: unnamed (numbered as it opens), named, or explicitly numbered;
/// `at` is where its `(` is in the pattern.
const Cap = struct {
    name: ?[]const u8 = null,
    number: u32 = 0,
    at: usize = 0,
};

// --- parsing ---

const Parser = struct {
    arena: Allocator,
    src: []const u8,
    i: usize = 0,
    /// Unnamed capturing groups opened so far: their numbers, and what `\N` may refer to.
    unnamed: u32 = 0,
    caps: std.ArrayList(Cap) = .empty,
    refs: std.ArrayList(*Ref) = .empty,
    conds: std.ArrayList(*Cond) = .empty,
    /// From a first pass over the pattern: every group, with its final number and where it opens.
    /// `\N` is a backreference only to a group that opens before it (.NET's ScanBasicBackslash).
    known: []const Cap = &.{},

    fn peek(p: *Parser) ?u8 {
        return if (p.i < p.src.len) p.src[p.i] else null;
    }

    fn startsWith(p: *Parser, s: []const u8) bool {
        return std.mem.startsWith(u8, p.src[p.i..], s);
    }

    /// With `x`: whitespace, and `#` to the end of the line, are not part of the pattern.
    fn skipIgnored(p: *Parser, f: Flags) void {
        if (!f.x) return;
        while (p.i < p.src.len) {
            const c = p.src[p.i];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0b or c == 0x0c) {
                p.i += 1;
            } else if (c == '#') {
                while (p.i < p.src.len and p.src[p.i] != '\n') p.i += 1;
            } else break;
        }
    }

    fn parseAlternation(p: *Parser, flags: Flags, depth: usize) Error![]const []const Node {
        if (depth > max_depth) return error.Unsupported;
        var f = flags;
        var alts: std.ArrayList([]const Node) = .empty;
        while (true) {
            try alts.append(p.arena, try p.parseSequence(&f, depth));
            if (p.peek() == '|') {
                p.i += 1;
                continue;
            }
            break;
        }
        return alts.items;
    }

    /// Inline options (`(?i)`) change `f` for the rest of the enclosing group.
    fn parseSequence(p: *Parser, f: *Flags, depth: usize) Error![]const Node {
        var seq: std.ArrayList(Node) = .empty;
        while (true) {
            p.skipIgnored(f.*);
            const c = p.peek() orelse break;
            if (c == '|' or c == ')') break;
            if (c == '*' or c == '+' or c == '?' or (c == '{' and p.quantifierAt(p.i) != null))
                return error.BadPattern; // nothing to repeat
            const atom = try p.parseAtom(f, depth) orelse {
                p.skipIgnored(f.*);
                if (p.peek()) |q| if (q == '*' or q == '+' or q == '?' or (q == '{' and p.quantifierAt(p.i) != null))
                    return error.BadPattern;
                continue;
            };
            p.skipIgnored(f.*);
            try seq.append(p.arena, try p.parseQuantifier(atom, f.*));
        }
        return seq.items;
    }

    /// `{n}`, `{n,}` or `{n,m}` at `at`, as min, max and where it ends; null when it is not one
    /// (then `{` is a literal).
    fn quantifierAt(p: *Parser, at: usize) ?struct { min: u32, max: u32, end: usize } {
        var i = at + 1;
        const lo_start = i;
        while (i < p.src.len and std.ascii.isDigit(p.src[i])) i += 1;
        if (i == lo_start or i >= p.src.len) return null;
        const lo = p.src[lo_start..i];
        if (p.src[i] == '}') {
            const n = std.fmt.parseInt(u32, lo, 10) catch return .{ .min = std.math.maxInt(u32), .max = 0, .end = i + 1 };
            return .{ .min = n, .max = n, .end = i + 1 };
        }
        if (p.src[i] != ',') return null;
        i += 1;
        const hi_start = i;
        while (i < p.src.len and std.ascii.isDigit(p.src[i])) i += 1;
        if (i >= p.src.len or p.src[i] != '}') return null;
        const min = std.fmt.parseInt(u32, lo, 10) catch return .{ .min = std.math.maxInt(u32), .max = 0, .end = i + 1 };
        const max = if (i == hi_start) std.math.maxInt(u32) else std.fmt.parseInt(u32, p.src[hi_start..i], 10) catch
            return .{ .min = std.math.maxInt(u32), .max = 0, .end = i + 1 };
        return .{ .min = min, .max = max, .end = i + 1 };
    }

    fn atQuantifier(p: *Parser) bool {
        const c = p.peek() orelse return false;
        return c == '*' or c == '+' or c == '?' or (c == '{' and p.quantifierAt(p.i) != null);
    }

    /// A quantifier binds to the atom before it; a trailing `?` makes it lazy. A second quantifier
    /// straight after (`a**`, `a{2}+`, `a*?+`) is an error, as .NET has it.
    fn parseQuantifier(p: *Parser, atom: Node, f: Flags) Error!Node {
        if (!p.atQuantifier()) return atom;
        var min: u32 = 0;
        var max: u32 = std.math.maxInt(u32);
        switch (p.src[p.i]) {
            '*' => p.i += 1,
            '+' => {
                min = 1;
                p.i += 1;
            },
            '?' => {
                max = 1;
                p.i += 1;
            },
            else => {
                const q = p.quantifierAt(p.i).?;
                // .NET refuses counts of 2^31 and more.
                if (q.min > std.math.maxInt(i32) or (q.max != std.math.maxInt(u32) and q.max > std.math.maxInt(i32)))
                    return error.BadPattern;
                if (q.max < q.min) return error.BadPattern;
                min = q.min;
                max = q.max;
                p.i = q.end;
            },
        }
        var greedy = true;
        p.skipIgnored(f);
        if (p.peek() == '?') {
            greedy = false;
            p.i += 1;
            p.skipIgnored(f);
        }
        if (p.atQuantifier()) return error.BadPattern; // a nested quantifier
        const owned = try p.arena.create(Node);
        owned.* = atom;
        return .{ .repeat = .{ .node = owned, .min = min, .max = max, .greedy = greedy } };
    }

    /// One atom, or null for what matches nothing and is not repeatable (`(?i)`, `(?#…)`).
    fn parseAtom(p: *Parser, f: *Flags, depth: usize) Error!?Node {
        const c = p.src[p.i];
        switch (c) {
            '^' => {
                p.i += 1;
                return .{ .assert = if (f.m) .bol_multi else .bol };
            },
            '$' => {
                p.i += 1;
                return .{ .assert = if (f.m) .eol_multi else .eol };
            },
            '.' => {
                p.i += 1;
                return .{ .any = .{ .dotall = f.s } };
            },
            '(' => return p.parseGroup(f, depth),
            '[' => {
                p.i += 1;
                return .{ .set = .{ .set = try p.parseClass(f.i, 0), .fold = f.i } };
            },
            '\\' => {
                p.i += 1;
                return switch (try p.parseEscape(false, f.i)) {
                    .char => |ch| .{ .char = .{ .c = ch, .fold = f.i } },
                    .set => |s| .{ .set = .{ .set = s, .fold = f.i } },
                    .assert => |a| .{ .assert = a },
                    .backref => |r| .{ .backref = .{ .ref = r, .fold = f.i } },
                };
            },
            else => {
                const d = decodeAt(p.src, p.i).?;
                p.i += d.len;
                return .{ .char = .{ .c = d.c, .fold = f.i } };
            },
        }
    }

    fn parseGroup(p: *Parser, f: *Flags, depth: usize) Error!?Node {
        const at = p.i;
        p.i += 1; // '('
        if (p.peek() != '?') {
            // `n`: only named groups capture.
            var cap: ?usize = null;
            if (!f.n) {
                p.unnamed += 1;
                cap = p.caps.items.len;
                try p.caps.append(p.arena, .{ .number = p.unnamed, .at = at });
            }
            return .{ .group = .{ .cap = cap, .alts = try p.groupBody(f.*, depth) } };
        }
        p.i += 1; // '?'
        if (p.startsWith(":")) {
            p.i += 1;
            return .{ .group = .{ .cap = null, .alts = try p.groupBody(f.*, depth) } };
        }
        if (p.startsWith("=") or p.startsWith("!")) {
            const negate = p.src[p.i] == '!';
            p.i += 1;
            return .{ .look = .{ .behind = false, .negate = negate, .alts = try p.groupBody(f.*, depth) } };
        }
        if (p.startsWith("<=") or p.startsWith("<!")) {
            const negate = p.src[p.i + 1] == '!';
            p.i += 2;
            return .{ .look = .{ .behind = true, .negate = negate, .alts = try p.groupBody(f.*, depth) } };
        }
        if (p.startsWith(">")) {
            p.i += 1;
            return .{ .atomic = try p.groupBody(f.*, depth) };
        }
        if (p.startsWith("#")) {
            const close = std.mem.indexOfScalarPos(u8, p.src, p.i, ')') orelse return error.BadPattern;
            p.i = close + 1;
            return null;
        }
        if (p.startsWith("<") or p.startsWith("'")) {
            const close: u8 = if (p.src[p.i] == '<') '>' else '\'';
            p.i += 1;
            const name = try p.groupName(close);
            var cap: Cap = .{ .at = at };
            if (std.ascii.isDigit(name[0])) {
                cap.number = std.fmt.parseInt(u32, name, 10) catch return error.BadPattern;
                if (cap.number == 0 or cap.number > std.math.maxInt(i32)) return error.BadPattern;
            } else cap.name = name;
            const index = p.caps.items.len;
            try p.caps.append(p.arena, cap);
            return .{ .group = .{ .cap = index, .alts = try p.groupBody(f.*, depth) } };
        }
        if (p.startsWith("(")) return try p.parseConditional(f.*, depth);
        // Inline options: `(?i)`, `(?-i)`, `(?i-s:…)`.
        var set = true;
        var g = f.*;
        while (p.i < p.src.len) : (p.i += 1) {
            switch (p.src[p.i]) {
                '-' => set = false,
                'i' => g.i = set,
                'm' => g.m = set,
                's' => g.s = set,
                'x' => g.x = set,
                'n' => g.n = set,
                ')' => {
                    p.i += 1;
                    f.* = g;
                    return null;
                },
                ':' => {
                    p.i += 1;
                    return .{ .group = .{ .cap = null, .alts = try p.groupBody(g, depth) } };
                },
                else => return error.BadPattern, // an unrecognized grouping construct
            }
        }
        return error.BadPattern;
    }

    /// A group's alternatives and its closing `)`.
    fn groupBody(p: *Parser, f: Flags, depth: usize) Error![]const []const Node {
        const alts = try p.parseAlternation(f, depth + 1);
        if (p.peek() != ')') return error.BadPattern; // not enough )'s
        p.i += 1;
        return alts;
    }

    /// A group's name up to `close`: a number, or a word starting with a word character that is
    /// not a digit. `(?<a-b>…)`, a balancing group, is not supported.
    fn groupName(p: *Parser, close: u8) Error![]const u8 {
        const start = p.i;
        while (p.i < p.src.len and p.src[p.i] != close and p.src[p.i] != '-') : (p.i += 1) {
            if (!isWord(p.src[p.i])) return error.BadPattern;
        }
        if (p.i >= p.src.len or p.i == start) return error.BadPattern;
        if (p.src[p.i] == '-') return error.Unsupported;
        const name = p.src[start..p.i];
        p.i += 1;
        if (std.ascii.isDigit(name[0])) for (name) |c| if (!std.ascii.isDigit(c)) return error.BadPattern;
        return name;
    }

    /// `(?(test)yes|no)`; the `(?` is consumed.
    fn parseConditional(p: *Parser, f: Flags, depth: usize) Error!Node {
        const cond = try p.arena.create(Cond);
        cond.* = .{};
        if (p.startsWith("(?=") or p.startsWith("(?!") or p.startsWith("(?<=") or p.startsWith("(?<!")) {
            // An explicit lookaround: its result decides.
            const look = (try p.parseGroup(@constCast(&f), depth + 1)).?;
            const one = try p.arena.alloc([]const Node, 1);
            const seq = try p.arena.alloc(Node, 1);
            seq[0] = look;
            one[0] = seq;
            cond.look = one;
        } else {
            p.i += 1; // '('
            const close = std.mem.indexOfScalarPos(u8, p.src, p.i, ')') orelse return error.BadPattern;
            const text = p.src[p.i..close];
            var sub: Parser = .{ .arena = p.arena, .src = text, .unnamed = p.unnamed };
            // Out of memory is not "not a lookahead": read as one, it refused a good pattern.
            const as_look = sub.parseAlternation(f, depth + 1) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => null,
            };
            if (text.len > 0 and std.ascii.isDigit(text[0])) {
                const n = std.fmt.parseInt(u32, text, 10) catch return error.BadPattern;
                cond.ref = .{ .number = n };
            } else if (text.len > 0 and allWord(text)) {
                cond.ref = .{ .name = text };
                if (as_look != null and sub.i == text.len) cond.look = as_look;
            } else {
                if (as_look == null or sub.i != text.len) return error.BadPattern;
                cond.look = as_look;
            }
            p.i = close + 1;
        }
        try p.conds.append(p.arena, cond);
        const alts = try p.parseAlternation(f, depth + 1);
        if (alts.len > 2) return error.BadPattern; // too many | in (?()|)
        if (p.peek() != ')') return error.BadPattern;
        p.i += 1;
        return .{ .cond = .{ .cond = cond, .yes = alts[0], .no = if (alts.len > 1) alts[1] else &.{} } };
    }

    const Escape = union(enum) {
        char: u21,
        set: *const Set,
        assert: Assert,
        backref: *Ref,
    };

    /// What follows a `\` (consumed), in a class or not.
    fn parseEscape(p: *Parser, in_class: bool, fold: bool) Error!Escape {
        const c = p.peek() orelse return error.BadPattern; // `\` at the end
        p.i += 1;
        const short: ?Shorthand = switch (c) {
            's' => .{ .kind = .space, .negated = false },
            'S' => .{ .kind = .space, .negated = true },
            'd' => .{ .kind = .digit, .negated = false },
            'D' => .{ .kind = .digit, .negated = true },
            'w' => .{ .kind = .word, .negated = false },
            'W' => .{ .kind = .word, .negated = true },
            else => null,
        };
        if (short) |s| {
            const set = try p.arena.create(Set);
            const items = try p.arena.alloc(Set.Item, 1);
            items[0] = .{ .shorthand = s };
            set.* = .{ .items = items };
            return .{ .set = set };
        }
        switch (c) {
            'p', 'P' => return .{ .set = try p.property(c == 'P', fold) },
            't' => return .{ .char = '\t' },
            'n' => return .{ .char = '\n' },
            'r' => return .{ .char = '\r' },
            'f' => return .{ .char = 0x0c },
            'v' => return .{ .char = 0x0b },
            'a' => return .{ .char = 0x07 },
            'e' => return .{ .char = 0x1b },
            'x' => return .{ .char = try p.hex(2) },
            'u' => return .{ .char = try p.hex(4) },
            'c' => {
                const l = p.peek() orelse return error.BadPattern;
                if (!std.ascii.isAlphabetic(l)) return error.BadPattern;
                p.i += 1;
                return .{ .char = std.ascii.toUpper(l) - '@' };
            },
            '0' => return .{ .char = p.octal(0) },
            '1'...'9' => {
                // ECMAScript mode: a backreference to the longest run of digits that numbers a group
                // opening before this `\`; else octal, or the digit itself for 8 and 9.
                if (!in_class) {
                    const backslash = p.i - 2;
                    var n: u32 = c - '0';
                    var best: ?u32 = null;
                    var best_end = p.i;
                    var end = p.i;
                    while (true) {
                        if (p.opensBefore(n, backslash)) {
                            best = n;
                            best_end = end;
                        }
                        if (end >= p.src.len or !std.ascii.isDigit(p.src[end]) or n > 100_000) break;
                        n = n * 10 + (p.src[end] - '0');
                        end += 1;
                    }
                    if (best) |b| {
                        p.i = best_end;
                        return .{ .backref = try p.ref(.{ .number = b }) };
                    }
                }
                if (c >= '8') return .{ .char = c };
                return .{ .char = p.octal(c - '0') };
            },
            else => {},
        }
        if (!in_class) switch (c) {
            'b' => return .{ .assert = .boundary },
            'B' => return .{ .assert = .not_boundary },
            'A' => return .{ .assert = .start },
            'z' => return .{ .assert = .end },
            'Z' => return .{ .assert = .end_or_newline },
            'G' => return .{ .assert = .search_start },
            'k' => if (p.peek() == '<' or p.peek() == '\'') {
                const close: u8 = if (p.src[p.i] == '<') '>' else '\'';
                p.i += 1;
                const name = try p.groupName(close);
                if (std.ascii.isDigit(name[0]))
                    return .{ .backref = try p.ref(.{ .number = std.fmt.parseInt(u32, name, 10) catch return error.BadPattern }) };
                return .{ .backref = try p.ref(.{ .name = name }) };
            },
            else => {},
        } else if (c == 'b') return .{ .char = 0x08 };
        // Anything else is the character itself (`\.`, `\(`, `\Q`).
        p.i -= 1;
        const d = decodeAt(p.src, p.i).?;
        p.i += d.len;
        return .{ .char = d.c };
    }

    /// `{name}` after `\p` or `\P` (`negated`), as .NET's ParseProperty reads it: braces required,
    /// the name made of word characters and `-`, nothing else (no spaces, even with `x`). A category
    /// is tested as one; a block becomes its ranges, or for `\P` the ranges between them, so that
    /// `(?i)` folds them as .NET folds a class's ranges.
    fn property(p: *Parser, negated: bool, fold: bool) Error!*const Set {
        if (p.peek() != '{') return error.BadPattern; // `\pL`: "Incomplete \p{X} character escape"
        p.i += 1;
        const start = p.i;
        while (p.i < p.src.len and (isWord(p.src[p.i]) or p.src[p.i] == '-')) p.i += 1;
        const name = p.src[start..p.i];
        if (p.peek() != '}') return error.BadPattern;
        p.i += 1;
        var items: std.ArrayList(Set.Item) = .empty;
        if (categoryMask(name, fold)) |mask| {
            try items.append(p.arena, .{ .category = .{ .mask = mask, .negated = negated } });
        } else {
            const ranges = blockRanges(name) orelse return error.BadPattern; // "Unknown property"
            if (!negated) {
                for (ranges) |r| try appendUnits(p.arena, &items, r[0], r[1]);
            } else {
                var next: u21 = 0;
                for (ranges) |r| {
                    if (r[0] > next) try appendUnits(p.arena, &items, next, r[0] - 1);
                    next = @as(u21, r[1]) + 1;
                }
                if (next <= 0xFFFF) try appendUnits(p.arena, &items, next, 0xFFFF);
            }
        }
        const set = try p.arena.create(Set);
        set.* = .{ .items = items.items };
        return set;
    }

    /// Whether group `n` exists and its `(` comes before `at`, by the first pass's numbering.
    fn opensBefore(p: *Parser, n: u32, at: usize) bool {
        for (p.known) |k| if (k.number == n and k.at < at) return true;
        return false;
    }

    fn ref(p: *Parser, r: Ref) Error!*Ref {
        const out = try p.arena.create(Ref);
        out.* = r;
        try p.refs.append(p.arena, out);
        return out;
    }

    /// Exactly `n` hexadecimal digits.
    fn hex(p: *Parser, n: usize) Error!u21 {
        if (p.i + n > p.src.len) return error.BadPattern;
        const v = std.fmt.parseInt(u21, p.src[p.i .. p.i + n], 16) catch return error.BadPattern;
        p.i += n;
        return v;
    }

    /// An octal escape whose first digit (already consumed) is `first`: up to three digits, as
    /// long as the value stays within `\377`.
    fn octal(p: *Parser, first: u21) u21 {
        var v: u21 = first;
        var digits: usize = 1;
        while (digits < 3) : (digits += 1) {
            const d = p.peek() orelse break;
            if (d < '0' or d > '7' or v * 8 + (d - '0') > 0o377) break;
            v = v * 8 + (d - '0');
            p.i += 1;
        }
        return v;
    }

    /// A class after its `[`.
    /// `depth`: the subtractions around this class (`[a-[b-[c]]]`). Each is a level of recursion here
    /// and in `Set.has`, and a problem matcher's pattern is anyone's: 100000 of them overflowed the
    /// stack (#98). .NET has no limit, so a pattern past `max_depth` is refused as unsupported.
    fn parseClass(p: *Parser, fold: bool, depth: u32) Error!*const Set {
        if (depth > max_depth) return error.Unsupported;
        const set = try p.arena.create(Set);
        set.* = .{};
        if (p.peek() == '^') {
            set.negated = true;
            p.i += 1;
            // ECMAScript: `[^]` is any character.
            if (p.peek() == ']') {
                p.i += 1;
                set.* = .{ .any = true };
                return set;
            }
        }
        var items: std.ArrayList(Set.Item) = .empty;
        var first = true; // a `]` first is a literal `]`
        while (true) {
            const c = p.peek() orelse return error.BadPattern; // unterminated
            if (c == ']' and !first) {
                p.i += 1;
                break;
            }
            first = false;
            if (c == '-' and p.i + 1 < p.src.len and p.src[p.i + 1] == '[') {
                // `-[...]` subtracts, and must end the class.
                p.i += 2;
                set.subtract = try p.parseClass(fold, depth + 1);
                if (p.peek() != ']') return error.BadPattern;
                p.i += 1;
                break;
            }
            const lo = try p.classElement(fold);
            switch (lo) {
                .set => |s| try items.appendSlice(p.arena, s.items),
                .char => |lo_c| {
                    // `a-z`, unless the `-` is last, or starts a subtraction.
                    if (p.i + 1 < p.src.len and p.src[p.i] == '-' and p.src[p.i + 1] != ']' and p.src[p.i + 1] != '[') {
                        p.i += 1;
                        const hi = switch (try p.classElement(fold)) {
                            .char => |h| h,
                            .set => return error.BadPattern, // a class in a range
                        };
                        if (hi < lo_c) return error.BadPattern; // a range in reverse order
                        try items.append(p.arena, .{ .range = .{ lo_c, hi } });
                    } else try items.append(p.arena, .{ .range = .{ lo_c, lo_c } });
                },
            }
        }
        set.items = items.items;
        return set;
    }

    fn classElement(p: *Parser, fold: bool) Error!union(enum) { char: u21, set: *const Set } {
        if (p.src[p.i] == '\\') {
            p.i += 1;
            return switch (try p.parseEscape(true, fold)) {
                .char => |ch| .{ .char = ch },
                .set => |s| .{ .set = s },
                else => unreachable, // no assertions or backreferences in a class
            };
        }
        const d = decodeAt(p.src, p.i).?;
        p.i += d.len;
        return .{ .char = d.c };
    }

    /// Numbers for named groups (after the unnamed ones, as .NET numbers them), and every reference
    /// resolved. Returns the highest group number.
    fn resolve(p: *Parser) Error!u32 {
        var names: std.StringHashMapUnmanaged(u32) = .empty;
        var used: std.AutoHashMapUnmanaged(u32, void) = .empty;
        var top: u32 = 0;
        for (p.caps.items) |c| if (c.name == null) {
            try used.put(p.arena, c.number, {});
            top = @max(top, c.number);
        };
        var next: u32 = p.unnamed + 1;
        for (p.caps.items) |*c| if (c.name) |name| {
            if (names.get(name)) |n| {
                c.number = n;
                continue;
            }
            while (used.contains(next)) next += 1;
            c.number = next;
            try used.put(p.arena, next, {});
            try names.put(p.arena, name, next);
            top = @max(top, next);
        };
        for (p.refs.items) |r| {
            if (r.name) |name| r.number = names.get(name) orelse return error.BadPattern //
            else if (!used.contains(r.number)) return error.BadPattern;
        }
        for (p.conds.items) |c| if (c.ref) |r| {
            if (r.name) |name| {
                if (names.get(name)) |n| {
                    c.ref.?.number = n;
                    c.look = null;
                } else c.ref = null; // not a group: the lookahead it also is
            } else if (!used.contains(r.number)) return error.BadPattern;
        };
        return top;
    }
};

fn allWord(s: []const u8) bool {
    for (s) |c| if (!isWord(c)) return false;
    return true;
}

// --- compiling ---

const Inst = union(enum) {
    char: struct { c: u21, fold: bool, back: bool },
    any: struct { dotall: bool, back: bool },
    set: struct { set: *const Set, fold: bool, back: bool },
    assert: Assert,
    /// The text the group at index `n` matched (the empty string when it took part in no match).
    backref: struct { n: u32, fold: bool, back: bool },
    /// Try `a` first, then `b` from the same position.
    split: struct { a: usize, b: usize },
    jmp: usize,
    /// Record the current position in capture slot `n` (the group at index g uses 2g and 2g+1).
    save: usize,
    /// Record where the group at index `g` is opening, in its pending slot; `close` makes it the
    /// group's.
    open: struct { g: u32, pending: usize },
    /// The group at index `g` closes here: its capture is the pending position and this one. Until
    /// then a backreference inside it still sees the previous iteration's (ECMAScript's
    /// self-reference).
    close: struct { g: u32, pending: usize, back: bool },
    /// Record the position at the start of a loop iteration, in slot `n`.
    mark: usize,
    /// End a loop iteration. If it consumed nothing since `mark` wrote `slot`, leave the loop by
    /// jumping to `exit` instead of repeating, *having run*, so the captures it made stick.
    progress: struct { slot: usize, exit: usize },
    /// Match `body` (ending in `done`) where we are, without moving; `next` follows.
    look: struct { behind: bool, negate: bool, body: usize, next: usize },
    /// Match `body` once, keep where it ended, never backtrack into it.
    atomic: struct { body: usize, next: usize },
    /// The group at index `n` matched: go on; else to `no`.
    cond_group: struct { n: u32, no: usize },
    /// `body` (a lookahead) matches here: go on; else to `no`.
    cond_look: struct { body: usize, no: usize },
    /// The end of a nested body.
    done,
    match,
};

const Compiler = struct {
    arena: Allocator,
    caps: []const Cap,
    /// Group number to its index among the groups (1-based, 0 being the whole match): slots go by
    /// index, so `(?<100000000>a)` needs as few as `(a)`.
    index: *const std.AutoHashMapUnmanaged(u32, u32),
    prog: std.ArrayList(Inst) = .empty,
    /// Where loop slots start: after the capture slots.
    loop_slot_base: usize,
    loops: usize = 0,
    /// Where groups' pending slots start (one per group number); set once loops are counted.
    pending_base: usize = 0,

    fn emit(c: *Compiler, in: Inst) Error!void {
        if (c.prog.items.len >= max_program) return error.Unsupported; // an expansion too large
        try c.prog.append(c.arena, in);
    }

    fn here(c: *Compiler) usize {
        return c.prog.items.len;
    }

    fn compileAlts(c: *Compiler, alts: []const []const Node, back: bool) Error!void {
        if (alts.len == 1) return c.compileSeq(alts[0], back);
        var jumps: std.ArrayList(usize) = .empty;
        for (alts, 0..) |alt, i| {
            const last = i + 1 == alts.len;
            var split_at: usize = 0;
            if (!last) {
                split_at = c.here();
                try c.emit(.{ .split = .{ .a = split_at + 1, .b = 0 } });
            }
            try c.compileSeq(alt, back);
            if (!last) {
                try jumps.append(c.arena, c.here());
                try c.emit(.{ .jmp = 0 });
                c.prog.items[split_at].split.b = c.here();
            }
        }
        for (jumps.items) |j| c.prog.items[j] = .{ .jmp = c.here() };
    }

    /// Backwards (a lookbehind's body), a sequence runs last element first.
    fn compileSeq(c: *Compiler, seq: []const Node, back: bool) Error!void {
        if (back) {
            var i = seq.len;
            while (i > 0) {
                i -= 1;
                try c.compileNode(seq[i], back);
            }
        } else for (seq) |n| try c.compileNode(n, back);
    }

    /// A body run on its own (lookaround, atomic, a condition), ending in `done`; returns where it
    /// starts. Emitted after a jump over it.
    fn body(c: *Compiler, alts: []const []const Node, back: bool) Error!struct { start: usize, end: usize } {
        const start = c.here();
        try c.compileAlts(alts, back);
        try c.emit(.done);
        return .{ .start = start, .end = c.here() };
    }

    fn compileNode(c: *Compiler, n: Node, back: bool) Error!void {
        switch (n) {
            .char => |ch| try c.emit(.{ .char = .{ .c = ch.c, .fold = ch.fold, .back = back } }),
            .any => |a| try c.emit(.{ .any = .{ .dotall = a.dotall, .back = back } }),
            .set => |s| try c.emit(.{ .set = .{ .set = s.set, .fold = s.fold, .back = back } }),
            .assert => |a| try c.emit(.{ .assert = a }),
            .backref => |r| try c.emit(.{ .backref = .{ .n = c.index.get(r.ref.number).?, .fold = r.fold, .back = back } }),
            .group => |g| {
                const num: ?u32 = if (g.cap) |ci| c.index.get(c.caps[ci].number).? else null;
                const pending = if (num) |gi| c.pending_base + gi else 0;
                if (num) |gi| try c.emit(.{ .open = .{ .g = gi, .pending = pending } });
                try c.compileAlts(g.alts, back);
                if (num) |gi| try c.emit(.{ .close = .{ .g = gi, .pending = pending, .back = back } });
            },
            .repeat => |r| try c.compileRepeat(r.node.*, r.min, r.max, r.greedy, back),
            .look => |l| {
                const at = c.here();
                try c.emit(.{ .look = .{ .behind = l.behind, .negate = l.negate, .body = 0, .next = 0 } });
                const b = try c.body(l.alts, l.behind);
                c.prog.items[at].look.body = b.start;
                c.prog.items[at].look.next = b.end;
            },
            .atomic => |alts| {
                const at = c.here();
                try c.emit(.{ .atomic = .{ .body = 0, .next = 0 } });
                const b = try c.body(alts, back);
                c.prog.items[at].atomic.body = b.start;
                c.prog.items[at].atomic.next = b.end;
            },
            .cond => |cd| {
                const at = c.here();
                if (cd.cond.ref) |r| {
                    try c.emit(.{ .cond_group = .{ .n = c.index.get(r.number).?, .no = 0 } });
                } else {
                    // The lookahead's body sits after a jump over it.
                    try c.emit(.{ .cond_look = .{ .body = 0, .no = 0 } });
                    const skip = c.here();
                    try c.emit(.{ .jmp = 0 });
                    const b = try c.body(cd.cond.look.?, false);
                    c.prog.items[at].cond_look.body = b.start;
                    c.prog.items[skip] = .{ .jmp = b.end };
                }
                try c.compileSeq(cd.yes, back);
                const over = c.here();
                try c.emit(.{ .jmp = 0 });
                switch (c.prog.items[at]) {
                    .cond_group => c.prog.items[at].cond_group.no = c.here(),
                    .cond_look => c.prog.items[at].cond_look.no = c.here(),
                    else => unreachable,
                }
                try c.compileSeq(cd.no, back);
                c.prog.items[over] = .{ .jmp = c.here() };
            },
        }
    }

    /// `{n,m}` is expanded: n copies, then (m-n) optional ones, or a star for an open end. The
    /// program bound in `max_program` keeps `a{1,10000}` from compiling.
    fn compileRepeat(c: *Compiler, n: Node, min: u32, max: u32, greedy: bool, back: bool) Error!void {
        for (0..min) |_| try c.compileNode(n, back);
        if (max == std.math.maxInt(u32)) return c.compileStar(n, greedy, back);
        // Every optional copy's "skip" branch leaves the whole repeat, so copy i+1 is reachable only
        // by having taken copy i, and an iteration that consumes nothing ends the repetition (the
        // mandatory copies are not guarded: `(a?){2}` does match the empty string twice). Both rules
        // came from an earlier differential test.
        var skips: std.ArrayList(usize) = .empty;
        var guards: std.ArrayList(usize) = .empty;
        for (min..max) |_| {
            const split_at = c.here();
            try c.emit(.{ .split = .{ .a = 0, .b = 0 } });
            try skips.append(c.arena, split_at);
            const slot = c.loop_slot_base + c.loops;
            c.loops += 1;
            try c.emit(.{ .mark = slot });
            try c.compileNode(n, back);
            try guards.append(c.arena, c.here());
            try c.emit(.{ .progress = .{ .slot = slot, .exit = 0 } });
        }
        const after = c.here();
        for (skips.items) |split_at| {
            c.prog.items[split_at] = if (greedy)
                .{ .split = .{ .a = split_at + 1, .b = after } }
            else
                .{ .split = .{ .a = after, .b = split_at + 1 } };
        }
        for (guards.items) |g| c.prog.items[g].progress.exit = after;
    }

    fn compileStar(c: *Compiler, n: Node, greedy: bool, back: bool) Error!void {
        const slot = c.loop_slot_base + c.loops;
        c.loops += 1;
        const split_at = c.here();
        try c.emit(.{ .split = .{ .a = 0, .b = 0 } });
        try c.emit(.{ .mark = slot });
        try c.compileNode(n, back);
        const progress_at = c.here();
        try c.emit(.{ .progress = .{ .slot = slot, .exit = 0 } });
        try c.emit(.{ .jmp = split_at });
        const after = c.here();
        c.prog.items[progress_at].progress.exit = after;
        c.prog.items[split_at] = if (greedy)
            .{ .split = .{ .a = split_at + 1, .b = after } }
        else
            .{ .split = .{ .a = after, .b = split_at + 1 } };
    }
};

// --- the public interface ---

pub const Span = struct {
    start: usize,
    end: usize,

    pub fn of(s: Span, input: []const u8) []const u8 {
        return input[s.start..s.end];
    }
};

/// Where the match and each group landed, by group number. A group that took part in no match
/// (or a number no group has) is null, which is how `(?:(\d+):(\d+):)?` reports an absent line.
pub const Captures = struct {
    whole: Span,
    /// The pattern's group numbers, ascending, and each one's capture.
    numbers: []const u32,
    groups: []const ?Span,

    pub fn group(c: Captures, n: usize) ?Span {
        if (n == 0) return c.whole;
        // Numbered 1 to N, as nearly every pattern is: the number is the place.
        if (n <= c.numbers.len and c.numbers[n - 1] == n) return c.groups[n - 1];
        const i = std.sort.binarySearch(u32, c.numbers, n, orderNumber) orelse return null;
        return c.groups[i];
    }

    fn orderNumber(n: usize, x: u32) std.math.Order {
        return std.math.order(n, x);
    }

    /// The text of group `n`, or null: what a problem matcher reads for `file`, `line` and so on.
    pub fn text(c: Captures, n: usize, input: []const u8) ?[]const u8 {
        return if (c.group(n)) |s| s.of(input) else null;
    }
};

pub const Regex = struct {
    prog: []const Inst,
    /// The highest group number.
    group_count: usize,
    /// Every group number, ascending; a group's index (its slots) is its place here, plus one.
    numbers: []const u32,
    /// Capture slots plus one per loop.
    slot_count: usize,

    /// Parses and compiles `pattern`, or says why it cannot.
    pub fn compile(arena: Allocator, pattern: []const u8) Error!Regex {
        // Twice, as .NET counts groups before it parses: the first pass finds every group and its
        // number, which decides whether a later `\N` is a backreference or an octal escape.
        var first: Parser = .{ .arena = arena, .src = pattern };
        _ = try first.parseAlternation(.{}, 0);
        if (first.i != pattern.len) return error.BadPattern; // too many )'s
        // Its other errors are the second pass's to report; out of memory would leave the groups
        // half numbered, and a later `\N` read as the wrong one of backreference and octal.
        _ = first.resolve() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        };
        var p: Parser = .{ .arena = arena, .src = pattern, .known = first.caps.items };
        const alts = try p.parseAlternation(.{}, 0);
        if (p.i != pattern.len) return error.BadPattern;
        const top = try p.resolve();

        // Groups by index, not number: numbers may be sparse (`(?<100000000>a)`), and slots sized by
        // the highest would be gigabytes per `find`.
        var numbers: std.ArrayList(u32) = .empty;
        var index: std.AutoHashMapUnmanaged(u32, u32) = .empty;
        for (p.caps.items) |cap| if (!index.contains(cap.number)) {
            try index.put(arena, cap.number, 0);
            try numbers.append(arena, cap.number);
        };
        std.mem.sortUnstable(u32, numbers.items, {}, std.sort.asc(u32));
        for (numbers.items, 1..) |n, i| index.putAssumeCapacity(n, @intCast(i));

        // Slots: the captures (2 per group, 0 for the whole match), each group's pending start, then
        // one per loop.
        const groups = numbers.items.len + 1;
        var c: Compiler = .{ .arena = arena, .caps = p.caps.items, .index = &index, .pending_base = 2 * groups, .loop_slot_base = 3 * groups };
        try c.emit(.{ .save = 0 });
        try c.compileAlts(alts, false);
        try c.emit(.{ .save = 1 });
        try c.emit(.match);
        return .{ .prog = c.prog.items, .group_count = top, .numbers = numbers.items, .slot_count = c.loop_slot_base + c.loops };
    }

    /// The leftmost match at or after `from`, as .NET's `Regex.Match` finds it: start offsets are
    /// tried in turn, a character at a time, so an unanchored pattern searches.
    pub fn find(re: Regex, arena: Allocator, input: []const u8, from: usize) Error!?Captures {
        const slots = try arena.alloc(?usize, re.slot_count);
        var steps: usize = 0;
        var levels: std.ArrayList(Vm.Level) = .empty;
        var vm: Vm = .{ .input = input, .prog = re.prog, .slots = slots, .arena = arena, .steps = &steps, .search_start = from, .levels = &levels };
        var start = from;
        while (start <= input.len) {
            @memset(slots, null);
            if (try vm.run(0, start) != null) {
                const groups = try arena.alloc(?Span, re.numbers.len);
                for (groups, 0..) |*g, i| {
                    const s = slots[2 * (i + 1)];
                    const e = slots[2 * (i + 1) + 1];
                    g.* = if (s != null and e != null and s.? <= e.?) .{ .start = s.?, .end = e.? } else null;
                }
                return .{ .whole = .{ .start = slots[0].?, .end = slots[1].? }, .numbers = re.numbers, .groups = groups };
            }
            start += if (decodeAt(input, start)) |d| d.len else 1;
        }
        return null;
    }
};

// --- matching ---

/// A backtracking point: where to resume, and how far to undo the capture trail first.
const Backtrack = struct { pc: usize, pos: usize, trail: usize };

/// What a `save` overwrote, so backtracking can put it back.
const Undo = struct { slot: usize, old: ?usize };

/// **Iterative on purpose**: one stack frame per instruction crashed an earlier version, and depth
/// is O(input length) for `.*` over a long line. Backtracking points live on the heap, and captures
/// are undone from a trail. Nested bodies (lookaround, atomic groups) recurse once per nesting
/// level of the pattern, which the parser bounds.
///
/// **Memory is bounded by the step budget**: a nested body runs on the same slots, with a stack and
/// trail kept per nesting level and reused, so it allocates nothing per step; copying every slot
/// for each lookaround took gigabytes with thousands of groups.
const Vm = struct {
    input: []const u8,
    prog: []const Inst,
    slots: []?usize,
    arena: Allocator,
    steps: *usize,
    search_start: usize,
    stack: std.ArrayList(Backtrack) = .empty,
    trail: std.ArrayList(Undo) = .empty,
    /// The backtracking stack and trail of each nesting level below the top one, kept for reuse.
    levels: *std.ArrayList(Level),
    depth: usize = 0,

    const Level = struct {
        stack: std.ArrayList(Backtrack) = .empty,
        trail: std.ArrayList(Undo) = .empty,
    };

    /// Runs from `start_pc` at `start_pos` to `match` or `done`; where it ended, or null.
    fn run(vm: *Vm, start_pc: usize, start_pos: usize) Error!?usize {
        vm.stack.clearRetainingCapacity();
        vm.trail.clearRetainingCapacity();
        var pc = start_pc;
        var pos = start_pos;
        while (true) {
            vm.steps.* += 1;
            if (vm.steps.* > step_budget) return error.TooComplex;
            const next: ?usize = switch (vm.prog[pc]) {
                .match, .done => return pos,
                .char => |ch| blk: {
                    const d = (if (ch.back) decodeBefore(vm.input, pos) else decodeAt(vm.input, pos)) orelse break :blk null;
                    if (!(d.c == ch.c or (ch.fold and foldEq(d.c, ch.c)))) break :blk null;
                    pos = if (ch.back) pos - d.len else pos + d.len;
                    break :blk pc + 1;
                },
                .any => |a| blk: {
                    const d = (if (a.back) decodeBefore(vm.input, pos) else decodeAt(vm.input, pos)) orelse break :blk null;
                    if (d.c == '\n' and !a.dotall) break :blk null;
                    pos = if (a.back) pos - d.len else pos + d.len;
                    break :blk pc + 1;
                },
                .set => |s| blk: {
                    const d = (if (s.back) decodeBefore(vm.input, pos) else decodeAt(vm.input, pos)) orelse break :blk null;
                    if (!s.set.has(d.c, s.fold)) break :blk null;
                    pos = if (s.back) pos - d.len else pos + d.len;
                    break :blk pc + 1;
                },
                .assert => |a| if (vm.holds(a, pos)) pc + 1 else null,
                .backref => |r| blk: {
                    const s = vm.slots[2 * @as(usize, r.n)];
                    const e = vm.slots[2 * @as(usize, r.n) + 1];
                    // ECMAScript: a group that took no part matches the empty string.
                    if (s == null or e == null or s.? > e.?) break :blk pc + 1;
                    const end = vm.matchText(vm.input[s.?..e.?], pos, r.fold, r.back) orelse break :blk null;
                    pos = end;
                    break :blk pc + 1;
                },
                .jmp => |t| t,
                .split => |s| blk: {
                    if (vm.stack.items.len >= max_backtrack) return error.TooComplex;
                    try vm.stack.append(vm.arena, .{ .pc = s.b, .pos = pos, .trail = vm.trail.items.len });
                    break :blk s.a;
                },
                .mark, .save => |slot| blk: {
                    try vm.set(slot, pos);
                    break :blk pc + 1;
                },
                .open => |o| blk: {
                    try vm.set(o.pending, pos);
                    break :blk pc + 1;
                },
                .close => |cl| blk: {
                    // Backwards, the group opened at its end.
                    const from = vm.slots[cl.pending].?;
                    try vm.set(2 * @as(usize, cl.g), if (cl.back) pos else from);
                    try vm.set(2 * @as(usize, cl.g) + 1, if (cl.back) from else pos);
                    break :blk pc + 1;
                },
                .progress => |g| blk: {
                    const stalled = if (vm.slots[g.slot]) |was| pos == was else false;
                    break :blk if (stalled) g.exit else pc + 1;
                },
                .look => |l| blk: {
                    // A positive lookaround's captures stand; a negative one has none (when its body
                    // matched, this path fails and backtracking undoes them).
                    const got = try vm.nested(l.body, pos);
                    if ((got != null) == l.negate) break :blk null;
                    break :blk l.next;
                },
                .atomic => |a| blk: {
                    pos = try vm.nested(a.body, pos) orelse break :blk null;
                    break :blk a.next;
                },
                .cond_group => |cg| blk: {
                    const s = vm.slots[2 * @as(usize, cg.n)];
                    const e = vm.slots[2 * @as(usize, cg.n) + 1];
                    break :blk if (s != null and e != null) pc + 1 else cg.no;
                },
                .cond_look => |cl| blk: {
                    _ = try vm.nested(cl.body, pos) orelse break :blk cl.no;
                    break :blk pc + 1;
                },
            };
            if (next) |n| {
                pc = n;
                continue;
            }
            // This path failed: take the most recent alternative, undoing the captures made since.
            const b = vm.stack.pop() orelse return null;
            while (vm.trail.items.len > b.trail) {
                const u = vm.trail.pop().?;
                vm.slots[u.slot] = u.old;
            }
            pc = b.pc;
            pos = b.pos;
        }
    }

    fn set(vm: *Vm, slot: usize, pos: usize) Error!void {
        try vm.trail.append(vm.arena, .{ .slot = slot, .old = vm.slots[slot] });
        vm.slots[slot] = pos;
    }

    /// A body run on its own from `pos`, never backtracked into: where it ended, or null. On the same
    /// slots, with the next level's stack and trail. When it matched, its captures are made this
    /// path's (its trail joins this one, to be undone with it); when not, they are undone.
    fn nested(vm: *Vm, pc: usize, pos: usize) Error!?usize {
        const d = vm.depth;
        if (vm.levels.items.len <= d) try vm.levels.append(vm.arena, .{});
        const level = vm.levels.items[d];
        var child: Vm = .{
            .input = vm.input,
            .prog = vm.prog,
            .slots = vm.slots,
            .arena = vm.arena,
            .steps = vm.steps,
            .search_start = vm.search_start,
            .stack = level.stack,
            .trail = level.trail,
            .levels = vm.levels,
            .depth = d + 1,
        };
        const end = try child.run(pc, pos);
        vm.levels.items[d] = .{ .stack = child.stack, .trail = child.trail };
        const trail = child.trail.items;
        if (end == null) {
            var i = trail.len;
            while (i > 0) {
                i -= 1;
                vm.slots[trail[i].slot] = trail[i].old;
            }
            return null;
        }
        try vm.trail.appendSlice(vm.arena, trail);
        return end;
    }

    /// `text` at `pos` (or, backwards, ending there), case folded when `fold`: where it ends. Each
    /// character compared is a step (bytes, unfolded), so a long backreference tried at every
    /// position, `(.*)\1b`, runs into the budget instead of costing one step each.
    fn matchText(vm: *Vm, text: []const u8, pos: usize, fold: bool, back: bool) ?usize {
        if (!fold) {
            // The bytes that match, before the first that does not (or the input's end).
            const room = if (back) pos else vm.input.len - pos;
            const n = @min(text.len, room);
            const there = if (back) vm.input[pos - n .. pos] else vm.input[pos..][0..n];
            const want = if (back) text[text.len - n ..] else text[0..n];
            const same = if (back) blk: {
                var k: usize = 0;
                while (k < n and there[n - 1 - k] == want[n - 1 - k]) k += 1;
                break :blk k;
            } else std.mem.indexOfDiff(u8, there, want) orelse n;
            vm.steps.* += same;
            if (same < text.len) return null;
            return if (back) pos - text.len else pos + text.len;
        }
        var compared: usize = 0;
        defer vm.steps.* += compared;
        if (back) {
            var at = pos;
            var j = text.len;
            while (j > 0) {
                compared += 1;
                const want = decodeBefore(text, j).?;
                const got = decodeBefore(vm.input, at) orelse return null;
                if (!foldEq(want.c, got.c)) return null;
                j -= want.len;
                at -= got.len;
            }
            return at;
        }
        var at = pos;
        var j: usize = 0;
        while (j < text.len) {
            compared += 1;
            const want = decodeAt(text, j).?;
            const got = decodeAt(vm.input, at) orelse return null;
            if (!foldEq(want.c, got.c)) return null;
            j += want.len;
            at += got.len;
        }
        return at;
    }

    fn holds(vm: *Vm, a: Assert, pos: usize) bool {
        const in = vm.input;
        return switch (a) {
            .bol => pos == 0,
            .bol_multi => pos == 0 or in[pos - 1] == '\n',
            .eol, .end_or_newline => pos == in.len or (pos + 1 == in.len and in[pos] == '\n'),
            .eol_multi => pos == in.len or in[pos] == '\n',
            .start => pos == 0,
            .end => pos == in.len,
            .search_start => pos == vm.search_start,
            .boundary, .not_boundary => blk: {
                const before = if (decodeBefore(in, pos)) |d| isWord(d.c) else false;
                const after = if (decodeAt(in, pos)) |d| isWord(d.c) else false;
                break :blk (before != after) == (a == .boundary);
            },
        };
    }
};

// --- tests ---

const testing = std.testing;

/// Compiles, matches, and returns the groups as text: null where the group took no part.
fn caps(arena: Allocator, pattern: []const u8, input: []const u8) !?[]const ?[]const u8 {
    const re = try Regex.compile(arena, pattern);
    const m = try re.find(arena, input, 0) orelse return null;
    const out = try arena.alloc(?[]const u8, re.group_count);
    for (out, 0..) |*o, i| o.* = m.text(i + 1, input);
    return out;
}

fn expectGroups(
    arena: Allocator,
    pattern: []const u8,
    input: []const u8,
    want: []const ?[]const u8,
) !void {
    const got = (try caps(arena, pattern, input)) orelse return error.NoMatch;
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| {
        if (w == null) {
            try testing.expect(g == null);
        } else {
            try testing.expect(g != null);
            try testing.expectEqualStrings(w.?, g.?);
        }
    }
}

fn whole(arena: Allocator, pattern: []const u8, input: []const u8) !?[]const u8 {
    const re = try Regex.compile(arena, pattern);
    const m = try re.find(arena, input, 0) orelse return null;
    return m.whole.of(input);
}

test "the five problem-matcher patterns real actions ship" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    // actions/setup-go. The optional non-capturing group carries line and column, so a message
    // without them leaves both groups absent — the case that made a `?Span` necessary.
    const go = "^\\s*(.+\\.go):(?:(\\d+):(\\d+):)? (.*)";
    try expectGroups(ar, go, "  main.go:9:2: undefined: foo", &.{ "main.go", "9", "2", "undefined: foo" });
    try expectGroups(ar, go, "pkg/a.go: build failed", &.{ "pkg/a.go", null, null, "build failed" });

    // actions/setup-node, eslint-compact: alternation of case variants, and an escaped paren.
    const compact = "^(.+):\\sline\\s(\\d+),\\scol\\s(\\d+),\\s([Ee]rror|[Ww]arning|[Ii]nfo)\\s-\\s(.+)\\s\\((.+)\\)$";
    try expectGroups(
        ar,
        compact,
        "src/a.js: line 3, col 10, Error - Missing semicolon (semi)",
        &.{ "src/a.js", "3", "10", "Error", "Missing semicolon", "semi" },
    );

    // eslint-stylish, both patterns of a two-pattern matcher.
    try expectGroups(ar, "^\\s*([^\\s].*)$", "  src/b.js", &.{"src/b.js"});
    try expectGroups(
        ar,
        "^\\s+(\\d+):(\\d+)\\s+(error|warning|info)\\s+(.*)\\s\\s+(.*)$",
        "  12:34  error  Unexpected console statement  no-console",
        &.{ "12", "34", "error", "Unexpected console statement", "no-console" },
    );

    // tsc: a class of escaped and plain characters, and alternation of two multi-character arms.
    const tsc = "^([^\\s].*)[\\(:](\\d+)[,:](\\d+)(?:\\):\\s+|\\s+-\\s+)(error|warning|info)\\s+TS(\\d+)\\s*:\\s*(.*)$";
    try expectGroups(
        ar,
        tsc,
        "src/c.ts(5,9): error TS2304: Cannot find name 'x'.",
        &.{ "src/c.ts", "5", "9", "error", "2304", "Cannot find name 'x'." },
    );
    try expectGroups(
        ar,
        tsc,
        "src/c.ts:5:9 - error TS2304: Cannot find name 'x'.",
        &.{ "src/c.ts", "5", "9", "error", "2304", "Cannot find name 'x'." },
    );
}

test "anchors, classes, quantifiers and laziness" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    // An unanchored pattern searches; an anchored one does not.
    try testing.expect((try caps(ar, "b+", "aabbb")) != null);
    try testing.expect((try caps(ar, "^b+", "aabbb")) == null);
    try testing.expect((try caps(ar, "c$", "abc")) != null);

    // Greedy takes as much as it can; lazy as little.
    try expectGroups(ar, "<(.+)>", "<a><b>", &.{"a><b"});
    try expectGroups(ar, "<(.+?)>", "<a><b>", &.{"a"});

    // Counted repetition, open-ended and bounded.
    try expectGroups(ar, "^(a{2,3})b", "aaab", &.{"aaa"});
    try testing.expect((try caps(ar, "^a{4}b", "aaab")) == null);
    try expectGroups(ar, "^(a{2,})$", "aaaa", &.{"aaaa"});

    // Classes: ranges, negation, a literal ']' first, a trailing '-', escapes inside.
    try expectGroups(ar, "([a-f0-9]+)", "zz9afz", &.{"9af"});
    try expectGroups(ar, "([^0-9]+)", "12ab34", &.{"ab"});
    try expectGroups(ar, "([]x]+)", "a]x]b", &.{"]x]"});
    try expectGroups(ar, "([a-]+)", "-a-", &.{"-a-"});
    try expectGroups(ar, "([\\(:]+)", "x(:y", &.{"(:"});

    // `.` stops at a newline, as in .NET without Singleline; `$` allows one before the end.
    try testing.expect((try caps(ar, "^a.b$", "a\nb")) == null);
    try testing.expectEqualStrings("a", (try whole(ar, "a$", "a\n")).?);

    // An alternative that matches nothing still lets a later one match.
    try expectGroups(ar, "^(x|y|z)$", "y", &.{"y"});
}

test "characters, not bytes; ECMAScript's ASCII shorthands" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectEqualStrings("é", (try whole(ar, "^.$", "é")).?);
    try testing.expectEqualStrings("→", (try whole(ar, "[↑|↗|→]", "x → y")).?);
    try testing.expect((try whole(ar, "\\w", "é")) == null);
    try testing.expect((try whole(ar, "(?i)\\w", "é")) == null);
    try testing.expect((try whole(ar, "\\d", "٣")) == null);
    try testing.expectEqualStrings("É", (try whole(ar, "(?i)é", "É")).?);
    try testing.expectEqualStrings("\u{212A}", (try whole(ar, "(?i)k", "\u{212A}")).?);
    try testing.expect((try whole(ar, "(?i)[^a]", "A")) == null);
    // .NET's one exception: `İ` is a word character, to `\w` and `\b` alike.
    try testing.expectEqualStrings("aİb", (try whole(ar, "\\w+", "aİb")).?);
    try testing.expect((try whole(ar, "\\W", "İ")) == null);
    try testing.expectEqualStrings("İ", (try whole(ar, "İ\\b", "İ")).?);
    try testing.expect((try whole(ar, "x\\b", "xİ")) == null);
    try testing.expect((try whole(ar, "(?i)\\w", "ı")) == null);
}

test "escapes: octal, hexadecimal, control, and backreference or octal by ECMAScript's rule" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // flake8-style matchers colour their output: `\033` is ESC.
    try expectGroups(ar, "^([^:]+): \\033\\[[\\d;]+m(.+)$", "a.py: \x1b[1;31mbad", &.{ "a.py", "bad" });
    try testing.expectEqualStrings(" 0", (try whole(ar, "\\400", "x 0")).?); // \40, then 0
    try testing.expectEqualStrings("\n3", (try whole(ar, "\\0123", "\n3")).?);
    try testing.expectEqualStrings("A\x01\x1b\x07", (try whole(ar, "\\x41\\ca\\e\\a", "A\x01\x1b\x07")).?);
    try testing.expectEqualStrings("Q", (try whole(ar, "\\Q", "Q")).?);
    try testing.expectEqualStrings("8", (try whole(ar, "\\8", "8")).?);
    // `\1` before group 1 opens is octal; `\12` with one group is `\1` then `2`; a named group
    // numbers too, and `\N` for a group opening later is octal.
    try testing.expect((try whole(ar, "\\1(a)", "a")) == null);
    try testing.expectEqualStrings("aa", (try whole(ar, "(?<n>a)\\1", "aa")).?);
    try testing.expectEqualStrings("a\x02b", (try whole(ar, "(a)\\2(b)", "a\x02b")).?);
    try testing.expectEqualStrings("aa2", (try whole(ar, "(a)\\12", "aa2")).?);
    // A group that took no part: the empty string.
    try testing.expectEqualStrings("b", (try whole(ar, "(a)?\\1b", "b")).?);
    for ([_][]const u8{ "\\x4", "\\u004", "\\c1", "\\c", "\\" }) |bad|
        try testing.expectError(error.BadPattern, Regex.compile(ar, bad));
}

test "groups: named, numbered as .NET numbers them, backreferences, conditionals" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Unnamed groups first, then named ones.
    try expectGroups(ar, "(?<x>a)(b)(?<y>c)(d)", "abcd", &.{ "b", "d", "a", "c" });
    try expectGroups(ar, "(?<x>a)\\k<x>(?'y'b)\\k'y'", "aabb", &.{ "a", "b" });
    try expectGroups(ar, "(?<2>a)", "a", &.{ null, "a" });
    try expectGroups(ar, "(?n)(a)(?<x>b)", "ab", &.{"b"});
    try expectGroups(ar, "(?<n>x)?(?(n)y|z)", "z", &.{null});
    try testing.expectEqualStrings("a", (try whole(ar, "(?(a)a|b)", "a")).?);
    try testing.expectError(error.BadPattern, Regex.compile(ar, "\\k<nope>"));
    try testing.expectError(error.BadPattern, Regex.compile(ar, "(a)?(?(1)b|c|d)"));
}

test "lookaround, right to left behind; atomic groups; options" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectEqualStrings("b", (try whole(ar, "a(?=b)b", "ab")).?[1..]);
    try testing.expect((try whole(ar, "a(?!b)", "ab")) == null);
    try expectGroups(ar, "(?<=(a+))b", "aaab", &.{"aaa"});
    try expectGroups(ar, "(?<=(a+?))b", "aaab", &.{"a"});
    try testing.expect((try whole(ar, "(?<!^)a", "a")) == null);
    try testing.expect((try whole(ar, "(?>a|ab)c", "abc")) == null);
    try testing.expectEqualStrings("Aa", (try whole(ar, "(?i)a(?-i)a", "Aa")).?);
    try testing.expect((try whole(ar, "(?i:a)a", "AA")) == null);
    try testing.expectEqualStrings("ab", (try whole(ar, "(?x) a b # c", "ab")).?);
    try testing.expectEqualStrings("a\nb", (try whole(ar, "(?s)a.b", "a\nb")).?);
    try testing.expectEqualStrings("b", (try whole(ar, "(?m)^b", "a\nb")).?);
    try testing.expectEqualStrings("x\ny", (try whole(ar, "x[^]y", "x\ny")).?);
    try testing.expectEqualStrings("b", (try whole(ar, "[a-c-[ac]]", "abc")).?);
    try testing.expectEqualStrings("4", (try whole(ar, "[\\d-[3]]", "34")).?);
}

test "Unicode categories and blocks, in and out of classes, as .NET 8 reads them" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectEqualStrings("Éte", (try whole(ar, "\\p{L}+", "1 Éte2")).?);
    try testing.expectEqualStrings("É", (try whole(ar, "\\p{Lu}", "aÉ")).?);
    try testing.expectEqualStrings("1 ", (try whole(ar, "\\P{L}+", "1 Éte")).?);
    try testing.expectEqualStrings("٣", (try whole(ar, "\\p{Nd}", "x٣")).?); // unlike `\d`
    try testing.expectEqualStrings("中a5", (try whole(ar, "[\\p{L}\\d]+", "-中a5-")).?);
    try testing.expectEqualStrings("-", (try whole(ar, "[^\\p{L}\\d]", "中a5-")).?);
    try testing.expectEqualStrings("é", (try whole(ar, "[^\\P{Ll}]", "Aé")).?);
    try testing.expectEqualStrings("b", (try whole(ar, "[\\p{L}-[a]]", "ab")).?);
    try testing.expectEqualStrings("-", (try whole(ar, "[\\p{L}-z]", "1-")).?); // `-` is literal
    try testing.expectEqualStrings("\u{0CF3}", (try whole(ar, "\\p{Mc}", "\u{0CF3}")).?); // new in 15.0
    try testing.expectEqualStrings("\u{2FFC}", (try whole(ar, "\\p{Cn}", "\u{2FFC}")).?); // new in 15.1
    try testing.expectEqualStrings("€", (try whole(ar, "\\p{Sc}", "a€")).?);
    try testing.expectEqualStrings("\u{00A0}", (try whole(ar, "\\p{Z}", "a\u{00A0}")).?);
    // Blocks, by .NET's list: legacy names, a hyphenated one, an `_xml…` class.
    try testing.expectEqualStrings("az", (try whole(ar, "\\p{IsBasicLatin}+", "éaz")).?);
    try testing.expectEqualStrings("é→", (try whole(ar, "\\P{IsBasicLatin}+", "aé→")).?);
    try testing.expectEqualStrings("αω", (try whole(ar, "\\p{IsGreek}\\p{IsGreekandCoptic}", "αω")).?);
    try testing.expectEqualStrings("é", (try whole(ar, "\\p{IsLatin-1Supplement}", "aé")).?);
    try testing.expectEqualStrings("a-1", (try whole(ar, "\\p{_xmlC}+", "a-1")).?);
    // `(?i)`: Lu, Ll and Lt each mean all three; other categories and \P too.
    try testing.expectEqualStrings("a", (try whole(ar, "(?i)\\p{Lu}", "a")).?);
    try testing.expectEqualStrings("A", (try whole(ar, "(?i)[\\p{Ll}]", "A")).?);
    try testing.expect((try whole(ar, "(?i)\\P{Lu}", "a")) == null);
    try testing.expect((try whole(ar, "(?i)[^\\p{Lu}]", "A")) == null);
    try testing.expect((try whole(ar, "(?i)\\p{Mn}", "\u{03B9}")) == null); // not folded
    // A block folds as ranges: the Kelvin sign is outside Basic Latin and folds to `k`.
    try testing.expectEqualStrings("k", (try whole(ar, "(?i)\\P{IsBasicLatin}", "k")).?);
    try testing.expect((try whole(ar, "(?i)\\P{IsBasicLatin}", "a")) == null);
    try testing.expectEqualStrings("\u{212A}", (try whole(ar, "(?i)\\p{IsBasicLatin}", "\u{212A}")).?);
    // Outside the Basic Multilingual Plane, a character is to `\p` what its first UTF-16 unit is.
    try testing.expect((try whole(ar, "\\p{L}", "\u{1D400}")) == null);
    try testing.expectEqualStrings("\u{1D400}", (try whole(ar, "\\p{Cs}+", "\u{1D400}")).?);
    try testing.expectEqualStrings("\u{1D400}", (try whole(ar, "\\p{IsHighSurrogates}", "\u{1D400}")).?);
    try testing.expectEqualStrings("\u{F0000}", (try whole(ar, "\\p{IsHighPrivateUseSurrogates}", "\u{F0000}")).?);
    try testing.expect((try whole(ar, "\\p{IsHighSurrogates}", "\u{F0000}")) == null);
    try testing.expectEqualStrings("é😀", (try whole(ar, "\\P{IsBasicLatin}+", "aé😀")).?);
    // Errors, as .NET has them: no braces, an unknown or miscased name, spaces, a class in a range.
    for ([_][]const u8{
        "\\pL",       "\\p",                              "\\p{",     "\\p{L",             "\\p{}",   "\\p{Foo}", "\\p{l}",
        "\\p{ L}",    "(?x)\\p{ L }",                     "\\p{L&}",  "\\p{isBasicLatin}", "\\p{Is}", "[\\pL]",   "[\\p{Foo}]",
        "[a-\\p{L}]", "\\p{__InternalRegexIgnoreCase__}", "\\P{Any}",
    }) |pattern| {
        testing.expectError(error.BadPattern, Regex.compile(ar, pattern)) catch |e| {
            std.debug.print("{s}\n", .{pattern});
            return e;
        };
    }
}

test "every code unit's category agrees with .NET's on a sample" {
    // From .NET 8's char.GetUnicodeCategory. The whole table, and every block, was compared with
    // .NET's answers for every code unit when generated; regex-diff.sh tries every name.
    const want = [_]struct { u21, tables.Category }{
        .{ 0x0000, .Cc }, .{ 0x0020, .Zs }, .{ 0x0041, .Lu }, .{ 0x005F, .Pc },  .{ 0x00AA, .Lo },
        .{ 0x00AD, .Cf }, .{ 0x00B5, .Ll }, .{ 0x01C5, .Lt }, .{ 0x02B0, .Lm },  .{ 0x0300, .Mn },
        .{ 0x0378, .Cn }, .{ 0x0488, .Me }, .{ 0x16EE, .Nl }, .{ 0x00B2, .No },  .{ 0x2028, .Zl },
        .{ 0x2029, .Zp }, .{ 0x2018, .Pi }, .{ 0x2019, .Pf }, .{ 0x4E00, .Lo },  .{ 0x9FFF, .Lo },
        .{ 0xAC00, .Lo }, .{ 0xD7A3, .Lo }, .{ 0xD800, .Cs }, .{ 0xDFFF, .Cs },  .{ 0xE000, .Co },
        .{ 0xF8FF, .Co }, .{ 0xFFFD, .So }, .{ 0xFFFF, .Cn }, .{ 0x1F600, .Cs },
    };
    for (want) |w| try testing.expectEqual(w[1], categoryOf(w[0]));
}

test "unsupported constructs are refused, not approximated; malformed ones are errors" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectError(error.Unsupported, Regex.compile(ar, "(?<a-b>x)"));
    for ([_][]const u8{
        "(unclosed", "[unclosed", "a)",      "*nothing",       "a{3,2}",   "a**", "a{2}+",
        "a*?+",      "[z-a]",     "[a-\\d]", "[a-z-[aeiou]x]", "(?P<n>a)", "[]",
    }) |pattern| {
        testing.expectError(error.BadPattern, Regex.compile(ar, pattern)) catch |e| {
            std.debug.print("{s}\n", .{pattern});
            return e;
        };
    }
    // What .NET reads as literals.
    try testing.expectEqualStrings("a{,2}", (try whole(ar, "a{,2}", "a{,2}")).?);
    try testing.expectEqualStrings("{", (try whole(ar, "{", "{")).?);
}

test "a pathological pattern gives up instead of hanging" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // The classic: every split of a long run of 'a' is tried before 'b' fails.
    const re = try Regex.compile(ar, "^(a+)+b$");
    try testing.expectError(error.TooComplex, re.find(ar, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0));
}

test "class subtraction nested past max_depth is refused, not a stack overflow (#98)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // 100000 levels overflowed the stack; the depth, not the program size, must stop them, so the
    // boundary is checked well below max_program: 70 levels refused, 10 compiled.
    for ([_]struct { usize, bool }{ .{ 70, false }, .{ 10, true } }) |c| {
        var deep: std.ArrayList(u8) = .empty;
        for (0..c[0]) |_| try deep.appendSlice(ar, "[a-");
        try deep.append(ar, 'z');
        for (0..c[0]) |_| try deep.append(ar, ']');
        if (c[1]) _ = try Regex.compile(ar, deep.items) else try std.testing.expectError(error.Unsupported, Regex.compile(ar, deep.items));
    }
    // A few levels, as real patterns have, still work: [a-z-[aeiou]] is the consonants.
    const re = try Regex.compile(ar, "^[a-z-[aeiou]]+$");
    try std.testing.expect(try re.find(ar, "rhythm", 0) != null);
    try std.testing.expect(try re.find(ar, "audio", 0) == null);
}

fn repeat(arena: Allocator, s: []const u8, n: usize) ![]const u8 {
    const out = try arena.alloc(u8, s.len * n);
    for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
    return out;
}

test "a sparse group number costs no more than a small one, and is still read by its number" {
    var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Slots sized by the highest number took 48 MB per `find` for this one, 7 GB for 100000000.
    const re = try Regex.compile(ar, "(b)?(?<1000000>a)\\k<1000000>(?(1000000)c|d)");
    const m = (try re.find(ar, "aac", 0)).?;
    try testing.expect(a.queryCapacity() < 64 * 1024);
    try testing.expectEqual(1000000, re.group_count);
    try testing.expectEqual(null, m.group(1));
    try testing.expectEqual(null, m.group(2));
    try testing.expectEqual(null, m.group(999999));
    try testing.expectEqual(null, m.group(1000001));
    try testing.expectEqualStrings("a", m.text(1000000, "aac").?);
    try testing.expectEqualStrings("aac", m.text(0, "aac").?);
}

test "lookaround with many groups allocates nothing per step" {
    var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Copying every slot for each lookahead took 4.4 GB for 3000 groups on a 40 KB line.
    const pattern = try std.mem.concat(ar, u8, &.{ try repeat(ar, "()", 1000), "(?:(?=.)(?>.))*$" });
    const line = try repeat(ar, "a", 4000);
    const re = try Regex.compile(ar, pattern);
    const before = a.queryCapacity();
    try testing.expect((try re.find(ar, line, 0)) != null);
    try testing.expect(a.queryCapacity() - before < 4 * 1024 * 1024);
}

test "a backreference costs a step per character it compares" {
    var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer a.deinit();
    const ar = a.allocator();
    // A few thousand steps, comparing 300 000 characters or more: within the budget only if each
    // comparison counted once. (`(?i)(.*)\1b` took 2 s on a 30 KB line.)
    const run = try repeat(ar, "a", 2000);
    const line = try std.mem.concat(ar, u8, &.{ run, "b", try repeat(ar, try std.mem.concat(ar, u8, &.{ run, "c" }), 150) });
    for ([_][]const u8{ "^(a*)b(?:\\1c)*$", "(?i)^(a*)b(?:\\1c)*$", "^(a*)b(?:\\1(?<=\\1)c)*$", "(?i)^(a*)b(?:\\1(?<=\\1)c)*$" }) |pattern| {
        const re = try Regex.compile(ar, pattern);
        try testing.expectError(error.TooComplex, re.find(ar, line, 0));
        // Short ones are as they were.
        try testing.expect((try re.find(ar, "aabaacaac", 0)) != null);
    }
}
