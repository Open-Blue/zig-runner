//! A YAML subset, enough to read `action.yml` files, read as go.yaml.in/yaml/v3 reads it.
//!
//! Supported: block mappings and sequences, explicit keys (`? key` then `: value`, and `{? key: v}`)
//! whose key is a scalar, plain / 'single' / "double" quoted scalars, block scalars (`|` and `>`
//! with `-`, `+` and an indentation digit), plain scalars that continue on later lines, quoted
//! scalars over several lines (folded as YAML folds them), flow sequences and mappings (also over
//! several lines, nested, with comments), comments, and a leading `---` and byte order mark.
//!
//! Every scalar is a string, except an empty value, `~`, `null`, `Null` and `NULL`, which are null
//! (YAML 1.2's core schema): callers turn strings into booleans or numbers where they need to
//! (action inputs are strings anyway). A key keeps its text: `null:` is the key "null".
//!
//! Not supported, and reported as `UnsupportedYaml` instead of being misread: anchors, aliases,
//! tags, merge keys, multiple documents, keys that are collections, a block scalar at the top
//! level, and the Unicode line separators (U+0085, U+2028, U+2029: go-yaml breaks lines at them).
//! Also refused (as `InvalidYaml`, though go-yaml reads some of it): a plain scalar in block context
//! that continues past an empty line or onto a line starting with `- `, and a tab starting a line
//! anywhere but inside a quoted scalar or between the tokens of a flow collection. What is not YAML
//! (go-yaml refuses it) is `InvalidYaml`, invalid UTF-8 and control characters included.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{ InvalidYaml, UnsupportedYaml, OutOfMemory };

pub const Node = union(enum) {
    null,
    string: []const u8,
    /// Only from `parseTyped`: a plain `true` or `false`.
    boolean: bool,
    /// Only from `parseTyped`: a plain number, as written (`1`, `-3`, `2.5`, `1e3`).
    number: []const u8,
    seq: []const Node,
    map: []const Entry,

    pub const Entry = struct { key: []const u8, value: Node };

    /// The value of `key` in a mapping (case-sensitive), or null.
    pub fn get(n: Node, key: []const u8) ?Node {
        if (n != .map) return null;
        for (n.map) |e| if (std.mem.eql(u8, e.key, key)) return e.value;
        return null;
    }

    /// The scalar text of a string node, or null for anything else.
    pub fn text(n: Node) ?[]const u8 {
        return if (n == .string) n.string else null;
    }

    /// The scalar as text, whatever its type (`true`, `1`); null for null and collections.
    pub fn scalarText(n: Node) ?[]const u8 {
        return switch (n) {
            .string, .number => |s| s,
            .boolean => |b| if (b) "true" else "false",
            else => null,
        };
    }
};

/// Where and why parsing failed.
pub const Diag = struct { line: usize = 0, message: []const u8 = "" };

pub fn parse(arena: Allocator, source_in: []const u8, diag: ?*Diag) Error!Node {
    return parseWith(arena, source_in, diag, false);
}

/// `parse`, but a plain scalar that go-yaml's resolver would make a bool or a number is a
/// `.boolean` or a `.number`, and a quoted one stays a `.string`, as a workflow's matrix keeps
/// `python: ['3.10']` apart from `python: 3.10`. Decimal integers and floats are recognised, and
/// `true` and `false` in the three spellings go-yaml takes; what else go-yaml resolves to a number
/// (`0x1F`, `1_000`, `.inf`) stays a string here.
pub fn parseTyped(arena: Allocator, source: []const u8, diag: ?*Diag) Error!Node {
    return parseWith(arena, source, diag, true);
}

fn parseWith(arena: Allocator, source_in: []const u8, diag: ?*Diag, typed: bool) Error!Node {
    // A byte order mark at the start says the encoding (only UTF-8 is read) and is not content.
    const source = if (std.mem.startsWith(u8, source_in, "\u{feff}")) source_in[3..] else source_in;
    try checkCharacters(source, diag);
    var lines: std.ArrayList(Line) = .empty;
    var it = std.mem.splitScalar(u8, source, '\n');
    var number: usize = 0;
    while (it.next()) |raw| {
        number += 1;
        const full = std.mem.trimEnd(u8, raw, "\r");
        var indent: usize = 0;
        while (indent < full.len and full[indent] == ' ') indent += 1;
        const rest = full[indent..];
        const trimmed = std.mem.trimEnd(u8, rest, " \t");
        try lines.append(arena, .{
            .number = number,
            .indent = indent,
            .full = full,
            .text = trimmed,
            .skip = trimmed.len == 0 or trimmed[0] == '#',
            .tab = rest.len > 0 and rest[0] == '\t',
        });
    }
    // A last line break ends the last line; it does not start another.
    const final_break = std.mem.endsWith(u8, source, "\n");
    if (final_break) _ = lines.pop();
    var p: Parser = .{ .arena = arena, .lines = lines.items, .diag = diag, .final_break = final_break, .typed = typed };
    const root = p.document() catch |e| {
        // A tab where the block structure is read is the likelier cause.
        if (e != error.OutOfMemory) if (p.bareTab()) |l|
            if (diag == null or l.number <= diag.?.line) return p.invalid(l, tab_message);
        return e;
    };
    if (p.bareTab()) |l| return p.invalid(l, tab_message);
    return root;
}

const tab_message = "tabs are not allowed for indentation";

/// A plain scalar's node: a string, or in typed mode a bool or a number where it reads as one.
fn plainNode(typed: bool, s: []const u8) Node {
    if (typed) {
        if (isBoolWord(s)) return .{ .boolean = s[0] == 't' or s[0] == 'T' };
        if (isDecimalNumber(s)) return .{ .number = s };
    }
    return .{ .string = s };
}

fn isBoolWord(s: []const u8) bool {
    for ([_][]const u8{ "true", "True", "TRUE", "false", "False", "FALSE" }) |w|
        if (std.mem.eql(u8, s, w)) return true;
    return false;
}

/// `[-+]?` digits, optionally with a fraction and an exponent, or a fraction alone (`.5`).
fn isDecimalNumber(s: []const u8) bool {
    var i: usize = 0;
    if (i < s.len and (s[i] == '-' or s[i] == '+')) i += 1;
    const int_start = i;
    while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    const int_digits = i - int_start;
    var frac_digits: usize = 0;
    var is_float = false;
    if (i < s.len and s[i] == '.') {
        is_float = true;
        i += 1;
        const f = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        frac_digits = i - f;
    }
    if (int_digits == 0 and frac_digits == 0) return false;
    if (i < s.len and (s[i] == 'e' or s[i] == 'E')) {
        is_float = true;
        i += 1;
        if (i < s.len and (s[i] == '-' or s[i] == '+')) i += 1;
        const e = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        if (i == e) return false;
    }
    // A leading zero (`0123`, `012.5`) is octal or a string to go-yaml, not a decimal.
    if (!is_float and int_digits > 1 and s[int_start] == '0') return false;
    return i == s.len;
}

/// The source is UTF-8 holding only the characters YAML allows (as go-yaml checks): no control
/// characters but tab, line feed and carriage return. Next line (U+0085) and the line and paragraph
/// separators (U+2028, U+2029) break lines in go-yaml (YAML 1.1) but not here, so they are refused.
fn checkCharacters(source: []const u8, diag: ?*Diag) Error!void {
    var line: usize = 1;
    var i: usize = 0;
    while (i < source.len) {
        const c = source[i];
        if (c < 0x80) {
            if (c == '\n') {
                line += 1;
            } else if (c != '\t' and c != '\r' and (c < 0x20 or c == 0x7F)) {
                return fail(diag, line, error.InvalidYaml, "control characters are not allowed");
            }
            i += 1;
            continue;
        }
        const n = std.unicode.utf8ByteSequenceLength(c) catch 0;
        const cp = if (n == 0 or i + n > source.len) null else std.unicode.utf8Decode(source[i .. i + n]) catch null;
        switch (cp orelse return fail(diag, line, error.InvalidYaml, "the file is not UTF-8")) {
            0x85, 0x2028, 0x2029 => return fail(diag, line, error.UnsupportedYaml, "Unicode line separators"),
            0xA0...0x2027, 0x202A...0xD7FF, 0xE000...0xFFFD, 0x10000...0x10FFFF => {},
            else => return fail(diag, line, error.InvalidYaml, "control characters are not allowed"),
        }
        i += n;
    }
}

fn fail(diag: ?*Diag, line: usize, err: Error, msg: []const u8) Error {
    if (diag) |d| d.* = .{ .line = line, .message = msg };
    return err;
}

const Line = struct {
    number: usize,
    indent: usize,
    /// The whole line, for block scalars.
    full: []const u8,
    /// Without the indentation or trailing whitespace.
    text: []const u8,
    /// Blank or comment-only.
    skip: bool,
    /// Its text starts with a tab. That is only allowed inside a quoted scalar or a flow
    /// collection, which mark such lines `inside` as they read them.
    tab: bool,
    inside: bool = false,
};

/// A mapping's entries while it is read, in order, with each key's place: a key read again replaces
/// the value in the earlier key's place (the last duplicate wins, as in most parsers). Found through
/// a hash map, so a mapping of n keys takes O(n), not O(n²) comparisons.
const Entries = struct {
    list: std.ArrayList(Node.Entry) = .empty,
    index: std.HashMapUnmanaged([]const u8, usize, KeyContext, std.hash_map.default_max_load_percentage) = .empty,
    /// Key comparisons made, for the tests.
    compares: usize = 0,

    const KeyContext = struct {
        compares: *usize,
        pub fn hash(_: KeyContext, k: []const u8) u64 {
            return std.hash_map.hashString(k);
        }
        pub fn eql(c: KeyContext, a: []const u8, b: []const u8) bool {
            c.compares.* += 1;
            return std.mem.eql(u8, a, b);
        }
    };

    fn put(e: *Entries, arena: Allocator, key: []const u8, value: Node) Allocator.Error!void {
        const gop = try e.index.getOrPutContext(arena, key, .{ .compares = &e.compares });
        if (gop.found_existing) {
            e.list.items[gop.value_ptr.*].value = value;
            return;
        }
        gop.value_ptr.* = e.list.items.len;
        try e.list.append(arena, .{ .key = key, .value = value });
    }
};

const Parser = struct {
    arena: Allocator,
    lines: []Line,
    pos: usize = 0,
    diag: ?*Diag,
    /// Reading an explicit key (`? null`), whose plain text stays as it is: the null words are null
    /// only as values.
    raw_null: bool = false,
    /// Plain scalars that are booleans or numbers are read as such (`parseTyped`).
    typed: bool = false,
    /// The source ends with a line break.
    final_break: bool,
    /// Block collections open around the one being read. Each `- ` or `? ` on a line is a level
    /// more, and the parser recurses into each: `- - - … x`, 70000 of them on one line (140 KB of a
    /// third party's `action.yml`), overflowed the stack and took the runner down (#98).
    depth: u32 = 0,

    /// Far deeper than any real file, far shallower than the stack allows (40000 overflowed it).
    const max_block_depth = 1000;

    fn enter(p: *Parser, l: Line) Error!void {
        if (p.depth >= max_block_depth) return p.unsupported(l, "block collections nested over 1000 deep");
        p.depth += 1;
    }

    fn plain(p: *Parser, s: []const u8) Node {
        return plainNode(p.typed, s);
    }

    fn invalid(p: *Parser, l: Line, msg: []const u8) Error {
        if (p.diag) |d| d.* = .{ .line = l.number, .message = msg };
        return error.InvalidYaml;
    }

    fn unsupported(p: *Parser, l: Line, msg: []const u8) Error {
        if (p.diag) |d| d.* = .{ .line = l.number, .message = msg };
        return error.UnsupportedYaml;
    }

    /// Line `i` is followed by a line break.
    fn breakAfter(p: *Parser, i: usize) bool {
        return i + 1 < p.lines.len or p.final_break;
    }

    fn document(p: *Parser) Error!Node {
        p.skipBlank();
        // An explicit document start is allowed; a second document is not.
        if (p.pos < p.lines.len and std.mem.eql(u8, p.lines[p.pos].text, "---")) {
            p.pos += 1;
            p.skipBlank();
        }
        const root = try p.node(0);
        p.skipBlank();
        if (p.pos < p.lines.len) {
            const l = p.lines[p.pos];
            if (std.mem.eql(u8, l.text, "---") or std.mem.eql(u8, l.text, "..."))
                return p.unsupported(l, "multiple documents");
            return p.invalid(l, "unexpected content");
        }
        return root;
    }

    /// The first line starting with a tab that no quoted scalar or flow collection took in.
    fn bareTab(p: *Parser) ?Line {
        for (p.lines) |l| if (l.tab and !l.inside) return l;
        return null;
    }

    fn skipBlank(p: *Parser) void {
        while (p.pos < p.lines.len and p.lines[p.pos].skip) p.pos += 1;
    }

    /// The next significant line's index, without consuming anything.
    fn peek(p: *Parser) ?usize {
        return p.peekFrom(p.pos);
    }

    /// The first significant line's index from `from` on.
    fn peekFrom(p: *Parser, from: usize) ?usize {
        var i = from;
        while (i < p.lines.len and p.lines[i].skip) i += 1;
        return if (i < p.lines.len) i else null;
    }

    /// A node whose lines are indented at least `min_indent`; null when there is none.
    fn node(p: *Parser, min_indent: usize) Error!Node {
        const i = p.peek() orelse return .null;
        const l = p.lines[i];
        if (l.indent < min_indent) return .null;
        try p.enter(l);
        defer p.depth -= 1;
        p.pos = i;
        if (isSeqItem(l.text)) return p.seq(l.indent);
        if (isIndicator(l.text, '?')) return p.map(l.indent);
        if (keyEnd(l)) |_| return p.map(l.indent);
        p.pos += 1;
        // A block scalar whose header is on a line of its own, below its key or dash.
        const head = stripComment(l.text);
        if (isBlockScalarHeader(head)) {
            if (min_indent == 0) return p.unsupported(l, "a block scalar at the top level");
            return p.blockScalar(head, min_indent - 1);
        }
        // A lone scalar (or flow collection) on its own line.
        return p.inlineValue(l, l.text, @as(isize, @intCast(l.indent)) - 1);
    }

    fn seq(p: *Parser, indent: usize) Error!Node {
        var items: std.ArrayList(Node) = .empty;
        while (p.peek()) |i| {
            const l = p.lines[i];
            if (l.indent != indent or !isSeqItem(l.text)) break;
            p.pos = i;
            try items.append(p.arena, try p.indicatorValue(i, indent));
        }
        return .{ .seq = items.items };
    }

    /// The node after the `- `, `? ` or `: ` that starts line `i` (at `indent`): on the rest of the
    /// line, or on the lines that follow when the rest is empty.
    fn indicatorValue(p: *Parser, i: usize, indent: usize) Error!Node {
        const l = p.lines[i];
        try p.enter(l);
        defer p.depth -= 1;
        p.pos = i;
        const after = std.mem.trimStart(u8, l.text[1..], " ");
        if (after.len > 0 and after[0] == '\t') return p.invalid(l, tab_message);
        if (after.len == 0 or after[0] == '#') {
            p.pos = i + 1;
            return p.node(indent + 1);
        }
        // `- key: v` followed by `  key2: v2`: treat the rest of the line as a line of its own.
        const offset = l.text.len - after.len;
        p.lines[i].indent = indent + offset;
        p.lines[i].text = after;
        return p.itemValue(i, indent);
    }

    /// The value that starts on line `i` after a `- `, whose dash was at `dash_indent`.
    fn itemValue(p: *Parser, i: usize, dash_indent: usize) Error!Node {
        const l = p.lines[i];
        const head = stripComment(l.text);
        if (isBlockScalarHeader(head)) {
            p.pos += 1;
            return p.blockScalar(head, dash_indent);
        }
        if (isSeqItem(l.text)) return p.seq(l.indent);
        if (isIndicator(l.text, '?')) return p.map(l.indent);
        if (keyEnd(l)) |_| return p.map(l.indent);
        p.pos += 1;
        return p.inlineValue(l, l.text, @intCast(dash_indent));
    }

    fn map(p: *Parser, indent: usize) Error!Node {
        var entries: Entries = .{};
        while (p.peek()) |i| {
            const l = p.lines[i];
            if (l.indent != indent) break;
            var key: []const u8 = undefined;
            var value: Node = undefined;
            if (isIndicator(l.text, '?')) {
                // `? key`, then `: value` on a line of its own (or no value, a null).
                key = try p.explicitKey(i, indent);
                value = .null;
                if (p.peek()) |j| if (p.lines[j].indent == indent and isIndicator(p.lines[j].text, ':')) {
                    const after = std.mem.trimStart(u8, p.lines[j].text[1..], " ");
                    const nx = if (after.len == 0 or after[0] == '#') p.peekFrom(j + 1) else null;
                    if (nx != null and p.lines[nx.?].indent == indent and isSeqItem(p.lines[nx.?].text)) {
                        // `:` followed by a sequence at the same indentation, as after `key:`.
                        p.pos = nx.?;
                        value = try p.seq(indent);
                    } else value = try p.indicatorValue(j, indent);
                };
                try p.putEntry(&entries, key, value);
                continue;
            }
            const colon = keyEnd(l) orelse break;
            if (charCount(l.text[0..colon]) > max_simple_key)
                return p.invalid(l, "a mapping key longer than 1024 characters (YAML's limit)");
            key = try p.mapKey(l, l.text[0..colon]);
            const after = std.mem.trimStart(u8, l.text[colon + 1 ..], " \t");
            const rest = stripComment(after);
            p.pos = i + 1;

            if (rest.len == 0) {
                const nx = p.peek();
                if (nx != null and p.lines[nx.?].indent > indent) {
                    value = try p.node(indent + 1);
                } else if (nx != null and p.lines[nx.?].indent == indent and
                    isSeqItem(p.lines[nx.?].text))
                {
                    // `key:` followed by a sequence at the same indentation.
                    value = try p.seq(indent);
                } else {
                    value = .null;
                }
            } else if (isBlockScalarHeader(rest)) {
                value = try p.blockScalar(rest, indent);
            } else {
                value = try p.inlineValue(l, after, @intCast(indent));
            }
            try p.putEntry(&entries, key, value);
        }
        return .{ .map = entries.list.items };
    }

    fn putEntry(p: *Parser, entries: *Entries, key: []const u8, value: Node) Error!void {
        try entries.put(p.arena, key, value);
    }

    /// The key after the `?` that starts line `i`: a scalar, read as its text.
    fn explicitKey(p: *Parser, i: usize, indent: usize) Error![]const u8 {
        const l = p.lines[i];
        const was = p.raw_null;
        p.raw_null = true;
        defer p.raw_null = was;
        return switch (try p.indicatorValue(i, indent)) {
            .null => "",
            .string => |s| s,
            else => p.unsupported(l, "mapping keys that are collections"),
        };
    }

    /// Index of the `:` that ends a mapping key on this line, or null if the line is not a mapping
    /// entry. (`? key` lines are explicit keys, which the callers look for first.)
    fn keyEnd(l: Line) ?usize {
        const t = l.text;
        if (t.len == 0) return null;
        if (t[0] == '"' or t[0] == '\'') {
            const close = quotedEnd(t) orelse return null;
            var j = close;
            while (j < t.len and t[j] == ' ') j += 1;
            if (j < t.len and t[j] == ':' and (j + 1 == t.len or isBlank(t[j + 1]))) return j;
            return null;
        }
        if (t[0] == '[' or t[0] == '{') return null;
        var j: usize = 0;
        while (j < t.len) : (j += 1) {
            if (t[j] == ':' and (j + 1 == t.len or isBlank(t[j + 1]))) return j;
            if (t[j] == '#' and j > 0 and isBlank(t[j - 1])) return null;
        }
        return null;
    }

    fn mapKey(p: *Parser, l: Line, raw: []const u8) Error![]const u8 {
        const t = std.mem.trim(u8, raw, " \t");
        if (t.len == 0) return p.invalid(l, "empty mapping key");
        if (t[0] == '"' or t[0] == '\'') {
            // keyEnd found the closing quote on this line, so the string ends there.
            var c = p.cursorAt(l, t);
            return p.scanQuoted(&c);
        }
        if (t[0] == '&' or t[0] == '*' or t[0] == '!')
            return p.unsupported(l, "anchors, aliases and tags");
        if (std.mem.eql(u8, t, "<<")) return p.unsupported(l, "merge keys");
        // Looked at with what follows: `?: x` is the key "?".
        const from = @intFromPtr(t.ptr) - @intFromPtr(l.text.ptr);
        if (cannotStartPlain(l.text[from..])) return p.invalid(l, "a character that cannot start a key");
        return t;
    }

    /// Where `rest`, a part of line `l`, starts.
    fn cursorAt(p: *Parser, l: Line, rest: []const u8) Cursor {
        return .{ .lines = p.lines, .li = l.number - 1, .col = @intFromPtr(rest.ptr) - @intFromPtr(l.full.ptr) };
    }

    /// After a quoted scalar or flow collection that ended at `c`: the rest of that line may only be
    /// a comment, and the block parser carries on from the next line.
    fn endOfValue(p: *Parser, l: Line, c: Cursor, what: []const u8) Error!void {
        for (p.lines[l.number .. c.li + 1]) |*taken| taken.inside = true;
        var k = c;
        while (k.char()) |ch| : (k.col += 1) if (ch != ' ' and ch != '\t') break;
        if (k.char()) |ch| if (ch != '#') return p.invalid(p.lines[k.li], what);
        p.pos = c.li + 1;
    }

    /// A scalar or flow collection given inline. Plain scalars continue on following lines that are
    /// indented more than `parent_indent`; quoted scalars and flow collections run to their closing
    /// quote or bracket, wherever it is (go-yaml does not check their indentation).
    fn inlineValue(p: *Parser, l: Line, rest_in: []const u8, parent_indent: isize) Error!Node {
        const rest = stripComment(rest_in);
        if (rest.len == 0) return .null;
        switch (rest[0]) {
            '"', '\'' => {
                var c = p.cursorAt(l, rest);
                const s = try p.scanQuoted(&c);
                try p.endOfValue(l, c, "unexpected text after a quoted string");
                return .{ .string = s };
            },
            '[', '{' => {
                var f: Flow = .{ .p = p, .c = p.cursorAt(l, rest) };
                const v = try f.node();
                try p.endOfValue(l, f.c, "unexpected text after a flow collection");
                return v.node;
            },
            '&', '*', '!' => return p.unsupported(l, "anchors, aliases and tags"),
            else => if (cannotStartPlain(rest)) return p.invalid(l, "a character that cannot start a value"),
        }
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(p.arena, rest);
        var commented = commentAt(std.mem.trim(u8, rest_in, " \t")) != null;
        while (p.pos < p.lines.len) {
            const nl = p.lines[p.pos];
            if (nl.skip) break;
            if (@as(isize, @intCast(nl.indent)) <= parent_indent) break;
            // A deeper `key: value` line would be a mapping where a scalar was expected.
            if (keyEnd(nl)) |_| return p.invalid(nl, "mapping values are not allowed here");
            if (isSeqItem(nl.text)) return p.invalid(nl, "sequence items are not allowed here");
            if (commented) return p.invalid(nl, "a comment ends a plain scalar; this line cannot continue it");
            commented = commentAt(nl.text) != null;
            try buf.append(p.arena, ' ');
            try buf.appendSlice(p.arena, stripComment(nl.text));
            p.pos += 1;
        }
        const s = buf.items;
        if (!p.raw_null and isNullWord(s)) return .null;
        return if (p.raw_null) .{ .string = s } else p.plain(s);
    }

    /// The quoted scalar that starts at `c`, which is left just past its closing quote. It may run
    /// over several lines, which fold as go-yaml (libyaml) folds them: the white space around each
    /// line break goes, a single break becomes a space, and each empty line after it a newline. In
    /// double quotes, a `\` at the end of a line joins the next line on without a space.
    fn scanQuoted(p: *Parser, c: *Cursor) Error![]const u8 {
        const start = p.lines[c.li];
        const q = c.char().?;
        const single = q == '\'';
        c.col += 1;
        var out: std.ArrayList(u8) = .empty;
        var spaces: std.ArrayList(u8) = .empty;
        while (true) {
            if (c.atDocMarker()) return p.invalid(p.lines[c.li], "a document marker inside a quoted string");
            if (c.atEnd()) return p.invalid(start, "a quoted string that is never closed");
            // The characters up to a blank, the line's end or the closing quote.
            var after_break = false; // the white space that follows starts a line
            var real_break = false; // ... after a line break that folds (not an escaped one)
            while (c.char()) |ch| {
                if (ch == ' ' or ch == '\t') break;
                if (ch == q) {
                    if (single and c.charAt(1) == '\'') {
                        try out.append(p.arena, '\'');
                        c.col += 2;
                        continue;
                    }
                    break;
                }
                if (!single and ch == '\\') {
                    if (c.col + 1 == c.text().len and c.li + 1 < c.lines.len) {
                        // An escaped line break: the lines join with nothing between them.
                        c.nextLine();
                        after_break = true;
                        break;
                    }
                    try p.escape(c, &out);
                    continue;
                }
                try out.append(p.arena, ch);
                c.col += 1;
            }
            if (c.char() == q) break;
            // White space and line breaks.
            var breaks: usize = 0;
            while (true) {
                if (c.char()) |ch| {
                    if (ch != ' ' and ch != '\t') break;
                    if (!after_break) try spaces.append(p.arena, ch);
                    c.col += 1;
                    continue;
                }
                if (!c.atBreak()) break; // the end of the input, an error above
                if (!after_break) {
                    spaces.clearRetainingCapacity();
                    after_break = true;
                    real_break = true;
                } else breaks += 1;
                c.nextLine();
            }
            if (after_break) {
                if (real_break and breaks == 0) {
                    try out.append(p.arena, ' ');
                } else {
                    try out.appendNTimes(p.arena, '\n', breaks);
                }
            } else {
                try out.appendSlice(p.arena, spaces.items);
            }
            spaces.clearRetainingCapacity();
        }
        c.col += 1;
        return out.items;
    }

    /// The escape sequence at `c` (a `\` and what follows, on this line) in a double-quoted string:
    /// those go-yaml knows, and only those.
    fn escape(p: *Parser, c: *Cursor, out: *std.ArrayList(u8)) Error!void {
        const l = p.lines[c.li];
        const bad = "bad escape in a double-quoted string";
        const e = c.charAt(1) orelse return p.invalid(l, bad);
        c.col += 2;
        const simple: ?[]const u8 = switch (e) {
            '0' => "\x00",
            'a' => "\x07",
            'b' => "\x08",
            't', '\t' => "\t",
            'n' => "\n",
            'v' => "\x0b",
            'f' => "\x0c",
            'r' => "\r",
            'e' => "\x1b",
            ' ' => " ",
            '"' => "\"",
            '\'' => "'",
            '\\' => "\\",
            'N' => "\u{85}",
            '_' => "\u{a0}",
            'L' => "\u{2028}",
            'P' => "\u{2029}",
            'x', 'u', 'U' => null,
            else => return p.invalid(l, "unknown escape in a double-quoted string"),
        };
        if (simple) |s| return out.appendSlice(p.arena, s);
        const digits: usize = switch (e) {
            'x' => 2,
            'u' => 4,
            else => 8,
        };
        const t = c.text();
        if (c.col + digits > t.len) return p.invalid(l, bad);
        var cp: u32 = 0;
        for (t[c.col .. c.col + digits]) |h| {
            const v = std.fmt.charToDigit(h, 16) catch return p.invalid(l, bad);
            cp = cp * 16 + v;
        }
        c.col += digits;
        if ((cp >= 0xD800 and cp <= 0xDFFF) or cp > 0x10FFFF) return p.invalid(l, bad);
        var enc: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(@intCast(cp), &enc) catch unreachable;
        try out.appendSlice(p.arena, enc[0..n]);
    }

    /// A `|` or `>` scalar whose header is `header`; the body follows at more than `parent_indent`.
    const Chomp = enum { clip, strip, keep };

    /// What a block scalar's header (`|`, `>-`, `|+2`, ...) says about its body.
    const BlockHeader = struct {
        folded: bool,
        chomp: Chomp = .clip,
        explicit_indent: ?usize = null,
    };

    fn blockHeader(header: []const u8) BlockHeader {
        var h: BlockHeader = .{ .folded = header[0] == '>' };
        for (header[1..]) |c| switch (c) {
            '-' => h.chomp = .strip,
            '+' => h.chomp = .keep,
            '1'...'9' => h.explicit_indent = c - '0',
            else => break,
        };
        return h;
    }

    /// Where a block scalar's body ends, and its indentation.
    const BlockBody = struct {
        start: usize,
        /// Past the last non-blank line: trailing blank lines belong to the scalar only for `keep`.
        last: usize,
        /// Past the trailing blank lines.
        end: usize,
        content_indent: ?usize,
    };

    fn blockBody(p: *Parser, parent_indent: usize, explicit_indent: ?usize) BlockBody {
        const start = p.pos;
        var end = start;
        var content_indent: ?usize = if (explicit_indent) |e| parent_indent + e else null;
        while (end < p.lines.len) : (end += 1) {
            const l = p.lines[end];
            if (isBlankLine(l)) continue;
            if (content_indent == null) {
                if (l.indent <= parent_indent) break;
                content_indent = l.indent;
            }
            if (l.indent < content_indent.?) break;
        }
        var last = end;
        while (last > start and isBlankLine(p.lines[last - 1])) last -= 1;
        return .{ .start = start, .last = last, .end = end, .content_indent = content_indent };
    }

    fn blockScalar(p: *Parser, header: []const u8, parent_indent: usize) Error!Node {
        const h = blockHeader(header);
        const body_span = p.blockBody(parent_indent, h.explicit_indent);
        const start = body_span.start;
        const last = body_span.last;
        const end = body_span.end;
        p.pos = end;
        const ci = body_span.content_indent orelse return .{ .string = "" };

        var out: std.ArrayList(u8) = .empty;
        var prev_blank = false;
        var first = true;
        var prev_more_indented = false;
        for (p.lines[start..last]) |l| {
            const blank = isBlankLine(l);
            const body = if (blank) "" else l.full[@min(ci, l.full.len)..];
            if (first) {
                try out.appendSlice(p.arena, body);
            } else if (!h.folded) {
                try out.append(p.arena, '\n');
                try out.appendSlice(p.arena, body);
            } else if (blank) {
                try out.append(p.arena, '\n');
            } else {
                const more = body.len > 0 and (body[0] == ' ' or body[0] == '\t');
                if (prev_blank) {
                    // The blank lines supplied the breaks; next to a more-indented line the line
                    // break itself is kept as well.
                    if (more or prev_more_indented) try out.append(p.arena, '\n');
                } else if (more or prev_more_indented) {
                    try out.append(p.arena, '\n');
                } else {
                    try out.append(p.arena, ' ');
                }
                try out.appendSlice(p.arena, body);
                prev_more_indented = more;
            }
            prev_blank = blank;
            first = false;
        }
        switch (h.chomp) {
            .strip => {},
            // The line breaks after the last line of text (one, or all of them): none at the end of
            // a file that does not end with one.
            .clip => if (out.items.len > 0 and p.breakAfter(last - 1)) try out.append(p.arena, '\n'),
            .keep => for (last - 1..end) |i| {
                if (p.breakAfter(i)) try out.append(p.arena, '\n');
            },
        }
        return .{ .string = out.items };
    }
};

/// The plain scalars YAML 1.2's core schema reads as null, besides an empty one.
fn isNullWord(s: []const u8) bool {
    for ([_][]const u8{ "~", "null", "Null", "NULL" }) |w| if (std.mem.eql(u8, s, w)) return true;
    return false;
}

fn isBlankLine(l: Line) bool {
    return std.mem.trim(u8, l.full, " \t").len == 0;
}

/// A position in the source, for what may run over several lines: quoted scalars and flow
/// collections.
const Cursor = struct {
    lines: []const Line,
    /// The line, an index into `lines`.
    li: usize,
    /// The byte in that line's `full`.
    col: usize,

    fn text(c: Cursor) []const u8 {
        return c.lines[c.li].full;
    }

    /// The character here, or null at the end of the line.
    fn char(c: Cursor) ?u8 {
        return c.charAt(0);
    }

    fn charAt(c: Cursor, off: usize) ?u8 {
        const t = c.text();
        return if (c.col + off < t.len) t[c.col + off] else null;
    }

    /// At a line break: the end of a line that another follows.
    fn atBreak(c: Cursor) bool {
        return c.col >= c.text().len and c.li + 1 < c.lines.len;
    }

    /// At the end of the input.
    fn atEnd(c: Cursor) bool {
        return c.col >= c.text().len and c.li + 1 >= c.lines.len;
    }

    fn nextLine(c: *Cursor) void {
        c.li += 1;
        c.col = 0;
    }

    /// A space, a tab, or the end of the line, `off` characters on.
    fn blankAt(c: Cursor, off: usize) bool {
        const ch = c.charAt(off) orelse return true;
        return ch == ' ' or ch == '\t';
    }

    /// `---` or `...` at the start of a line, which ends the document even inside quotes or
    /// brackets.
    fn atDocMarker(c: Cursor) bool {
        if (c.col != 0) return false;
        const t = c.text();
        if (!std.mem.startsWith(u8, t, "---") and !std.mem.startsWith(u8, t, "...")) return false;
        return c.blankAt(3);
    }
};

/// A flow sequence or mapping, `[a, b]`, `{ icon: x, color: y }`, which may run over several
/// lines. It follows go-yaml (libyaml): comments and line breaks may come between any two tokens,
/// plain and quoted scalars fold over lines, `[a: b]` is a sequence holding a one-entry mapping, a
/// key must be on one line with its `:` (unless it follows `?`), and indentation is not looked at.
const Flow = struct {
    p: *Parser,
    c: Cursor,
    /// Collections open around `c`. `value` recurses into each, so 100000 nested `[` overflowed
    /// the stack and took the runner down: an `action.yml` comes from whoever wrote the action.
    depth: usize = 0,

    const max_depth = 64;

    /// A node, and where it started (for whether it can be a key).
    const Item = struct {
        node: Node,
        /// A scalar's text, the null words included: what it reads as when it is a key.
        text: ?[]const u8,
        li: usize,
        col: usize,
    };

    fn line(f: *Flow) Line {
        return f.p.lines[f.c.li];
    }

    fn unexpected(f: *Flow) Error {
        return f.p.invalid(f.line(), "unexpected character in a flow collection");
    }

    /// Skips white space, line breaks and comments, as between tokens.
    fn skip(f: *Flow) Error!void {
        while (true) {
            if (f.c.char()) |ch| switch (ch) {
                ' ', '\t' => f.c.col += 1,
                // A comment, which in flow needs no space before it: `[a,#c`.
                '#' => f.c.col = f.c.text().len,
                else => return,
            } else if (f.c.atBreak()) {
                f.c.nextLine();
                if (f.c.atDocMarker() or f.c.char() == '%')
                    return f.p.invalid(f.line(), "a document marker inside a flow collection");
            } else return;
        }
    }

    /// The node at `c` (after `skip`).
    fn node(f: *Flow) Error!Item {
        var item: Item = .{ .node = .null, .text = null, .li = f.c.li, .col = f.c.col };
        const ch = f.c.char() orelse
            return f.p.invalid(f.p.lines[f.c.li], "a flow collection that is never closed");
        switch (ch) {
            '[', '{' => {
                f.c.col += 1;
                f.depth += 1;
                defer f.depth -= 1;
                if (f.depth > max_depth) return f.p.unsupported(f.line(), "flow collections nested over 64 deep");
                item.node = if (ch == '[') try f.seq() else try f.map();
            },
            '"', '\'' => {
                const s = try f.p.scanQuoted(&f.c);
                item.node = .{ .string = s };
                item.text = s;
            },
            '&', '*', '!' => return f.p.unsupported(f.line(), "anchors, aliases and tags"),
            // `-` followed by a blank is a block sequence entry, not allowed in flow; `?` and `:`
            // are only where the callers look for them.
            ',', ']', '}', '?', ':', '|', '>', '%', '@', '`' => return f.unexpected(),
            else => {
                if (ch == '-' and f.c.blankAt(1)) return f.unexpected();
                const s = try f.plain();
                item.text = s;
                item.node = if (isNullWord(s)) .null else f.p.plain(s);
            },
        }
        return item;
    }

    /// The text of `item` as a key: only a scalar can be one.
    fn keyText(f: *Flow, item: Item) Error![]const u8 {
        if (item.text) |t| return t;
        return f.p.unsupported(f.p.lines[item.li], "mapping keys that are collections");
    }

    /// The `:` here follows `item` without a `?` before it: it must be on the same line, and at most
    /// 1024 characters on (YAML's limit for an implicit key).
    fn checkImplicitKey(f: *Flow, item: Item) Error!void {
        if (item.li != f.c.li)
            return f.p.invalid(f.line(), "a key and its ':' must be on one line");
        if (charCount(f.c.text()[item.col..f.c.col]) > max_simple_key)
            return f.p.invalid(f.line(), "a mapping key longer than 1024 characters (YAML's limit)");
    }

    /// The value after a `:` (at `c`), or null when there is none before `,` or `close`.
    fn valueAfterColon(f: *Flow, close: u8) Error!Node {
        f.c.col += 1;
        try f.skip();
        const ch = f.c.char() orelse return f.p.invalid(f.line(), "a flow collection that is never closed");
        if (ch == ',' or ch == close) return .null;
        return (try f.node()).node;
    }

    /// After an entry: a `,` (eaten) or the closing bracket (left).
    fn entryEnd(f: *Flow, close: u8) Error!void {
        try f.skip();
        const ch = f.c.char() orelse return f.p.invalid(f.line(), "a flow collection that is never closed");
        if (ch == ',') {
            f.c.col += 1;
        } else if (ch != close) {
            return f.p.invalid(f.line(), if (close == ']') "expected ',' or ']' in a flow sequence" else "expected ',' or '}' in a flow mapping");
        }
    }

    /// One `? key : value` or `key: value` entry, its `?` already eaten.
    fn explicitEntry(f: *Flow, close: u8) Error!Node.Entry {
        try f.skip();
        const ch = f.c.char() orelse return f.p.invalid(f.line(), "a flow collection that is never closed");
        if (ch == ':' or ch == ',' or ch == close) {
            // go-yaml reads `{? : v}` and `{?}`, but refuses `[? : v]`, `[?, x]` and `[?]` (its
            // parser skips the token after an empty key in a sequence).
            if (close == ']') return f.unexpected();
            const v: Node = if (ch == ':') try f.valueAfterColon(close) else .null;
            return .{ .key = "", .value = v };
        }
        const k = try f.node();
        const key = try f.keyText(k);
        try f.skip();
        const v: Node = if (f.c.char() == ':') try f.valueAfterColon(close) else .null;
        return .{ .key = key, .value = v };
    }

    /// The rest of a flow sequence, after its `[`.
    fn seq(f: *Flow) Error!Node {
        var items: std.ArrayList(Node) = .empty;
        while (true) {
            try f.skip();
            const ch = f.c.char() orelse return f.p.invalid(f.line(), "a flow collection that is never closed");
            if (ch == ']') {
                f.c.col += 1;
                break;
            }
            var entry: ?Node.Entry = null;
            if (ch == '?') {
                f.c.col += 1;
                entry = try f.explicitEntry(']');
            } else {
                const item = try f.node();
                try f.skip();
                if (f.c.char() == ':') {
                    // `[a: b]`: a mapping of one entry.
                    try f.checkImplicitKey(item);
                    entry = .{ .key = try f.keyText(item), .value = try f.valueAfterColon(']') };
                } else try items.append(f.p.arena, item.node);
            }
            if (entry) |e| {
                const one = try f.p.arena.alloc(Node.Entry, 1);
                one[0] = e;
                try items.append(f.p.arena, .{ .map = one });
            }
            try f.entryEnd(']');
        }
        return .{ .seq = items.items };
    }

    /// The rest of a flow mapping, after its `{`.
    fn map(f: *Flow) Error!Node {
        var entries: Entries = .{};
        while (true) {
            try f.skip();
            const ch = f.c.char() orelse return f.p.invalid(f.line(), "a flow collection that is never closed");
            if (ch == '}') {
                f.c.col += 1;
                break;
            }
            if (ch == '?') {
                f.c.col += 1;
                const e = try f.explicitEntry('}');
                try f.p.putEntry(&entries, e.key, e.value);
            } else {
                const k = try f.node();
                try f.skip();
                var v: Node = .null;
                if (f.c.char() == ':') {
                    try f.checkImplicitKey(k);
                    v = try f.valueAfterColon('}');
                }
                try f.p.putEntry(&entries, try f.keyText(k), v);
            }
            try f.entryEnd('}');
        }
        return .{ .map = entries.list.items };
    }

    /// A plain scalar in flow: it ends at `,`, `[`, `]`, `{`, `}`, `?`, a `:` followed by a blank,
    /// or a comment, and folds over lines as a quoted one does.
    fn plain(f: *Flow) Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var spaces: std.ArrayList(u8) = .empty;
        var after_break = false;
        var breaks: usize = 0;
        while (true) {
            if (f.c.atDocMarker() or f.c.char() == '#') break;
            while (f.c.char()) |ch| {
                if (ch == ' ' or ch == '\t') break;
                if (ch == ':' and f.c.blankAt(1)) break;
                switch (ch) {
                    ',', '?', '[', ']', '{', '}' => break,
                    else => {},
                }
                if (after_break) {
                    if (breaks == 0) try out.append(f.p.arena, ' ') else try out.appendNTimes(f.p.arena, '\n', breaks);
                    after_break = false;
                    breaks = 0;
                } else try out.appendSlice(f.p.arena, spaces.items);
                spaces.clearRetainingCapacity();
                try out.append(f.p.arena, ch);
                f.c.col += 1;
            }
            const ch = f.c.char();
            if (ch != null and ch != ' ' and ch != '\t') break;
            if (ch == null and !f.c.atBreak()) break;
            while (true) {
                if (f.c.char()) |b| {
                    if (b != ' ' and b != '\t') break;
                    // go-yaml refuses a tab that starts a plain scalar's line left of the block
                    // indentation; refuse them all rather than track it.
                    if (b == '\t' and after_break)
                        return f.p.invalid(f.line(), "a tab at the start of a line of a plain scalar");
                    if (!after_break) try spaces.append(f.p.arena, b);
                    f.c.col += 1;
                } else if (f.c.atBreak()) {
                    if (!after_break) {
                        spaces.clearRetainingCapacity();
                        after_break = true;
                    } else breaks += 1;
                    f.c.nextLine();
                } else break;
            }
        }
        return out.items;
    }
};

/// YAML's limit on an implicit key, from its start to its `:`, in characters.
const max_simple_key = 1024;

/// UTF-8 characters in `s` (go-yaml counts the key limit in characters).
fn charCount(s: []const u8) usize {
    var n: usize = 0;
    for (s) |b| {
        if (b & 0xC0 != 0x80) n += 1;
    }
    return n;
}

/// `?` or `:` (as `ind`) alone or followed by a space: an explicit key or its value.
fn isIndicator(t: []const u8, ind: u8) bool {
    return t.len > 0 and t[0] == ind and (t.len == 1 or t[1] == ' ');
}

/// `t` (not empty) starts with an indicator that a plain scalar in block context cannot start
/// with: `,` `]` `}` `|` `>` `%` `@` and a backquote, or `-`, `?` or `:` followed by a blank. (The
/// callers deal with quotes, brackets, comments, anchors, aliases and tags first.)
fn cannotStartPlain(t: []const u8) bool {
    return switch (t[0]) {
        ',', '[', ']', '{', '}', '|', '>', '%', '@', '`', '#', '&', '*', '!', '"', '\'' => true,
        '-', '?', ':' => t.len == 1 or t[1] == ' ' or t[1] == '\t',
        else => false,
    };
}

fn isSeqItem(t: []const u8) bool {
    return t.len > 0 and t[0] == '-' and (t.len == 1 or t[1] == ' ');
}

/// `|` or `>` followed only by chomping and indentation indicators (the comment is already
/// removed).
fn isBlockScalarHeader(t: []const u8) bool {
    if (t.len == 0 or (t[0] != '|' and t[0] != '>')) return false;
    for (t[1..]) |c| switch (c) {
        '-', '+', '1'...'9' => {},
        else => return false,
    };
    return true;
}

/// Index just past the closing quote of the quoted scalar at the start of `t`, or null if unclosed.
fn quotedEnd(t: []const u8) ?usize {
    const q = t[0];
    var i: usize = 1;
    while (i < t.len) : (i += 1) {
        if (q == '"' and t[i] == '\\') {
            i += 1;
            continue;
        }
        if (t[i] == q) {
            if (q == '\'' and i + 1 < t.len and t[i + 1] == '\'') {
                i += 1;
                continue;
            }
            return i + 1;
        }
    }
    return null;
}

/// Removes a trailing ` # comment` from a plain value. Quoted and flow values are returned as they
/// are: the caller looks at what follows the closing quote or bracket.
fn stripComment(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \t");
    if (t.len == 0) return t;
    if (t[0] == '#') return "";
    if (t[0] == '"' or t[0] == '\'' or t[0] == '[' or t[0] == '{') return t;
    if (commentAt(t)) |i| return std.mem.trimEnd(u8, t[0..i], " \t");
    return t;
}

/// Where a ` # comment` starts in plain text `t`, if it has one.
fn commentAt(t: []const u8) ?usize {
    var i: usize = 1;
    while (i < t.len) : (i += 1) {
        if (t[i] == '#' and isBlank(t[i - 1])) return i;
    }
    return null;
}

fn isBlank(c: u8) bool {
    return c == ' ' or c == '\t';
}

// --- tests ---

fn expectStr(n: ?Node, want: []const u8) !void {
    try std.testing.expect(n != null);
    try std.testing.expectEqualStrings(want, n.?.text() orelse return error.TestExpectedString);
}

test "mappings, nesting, comments and scalars" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\# a comment
        \\name: "Dagger for GitHub"   # trailing
        \\description: Run dagger commands in Github Actions
        \\inputs:
        \\  version:
        \\    description: "Dagger Version. Use semver vX.Y.Z or 'latest'"
        \\    required: false
        \\    default: "latest"
        \\  empty:
        \\    description: ''
        \\url: https://example.com/a#b
        \\nothing:
        \\tilde: ~
    , null);
    try expectStr(n.get("name"), "Dagger for GitHub");
    try expectStr(n.get("description"), "Run dagger commands in Github Actions");
    const v = n.get("inputs").?.get("version").?;
    try expectStr(v.get("required"), "false");
    try expectStr(v.get("default"), "latest");
    try expectStr(v.get("description"), "Dagger Version. Use semver vX.Y.Z or 'latest'");
    try expectStr(n.get("inputs").?.get("empty").?.get("description"), "");
    try expectStr(n.get("url"), "https://example.com/a#b");
    try std.testing.expect(n.get("nothing").? == .null);
    try std.testing.expect(n.get("tilde").? == .null);
}

test "sequences of mappings and scalars, with the sequence at the key's indentation" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\runs:
        \\  using: "composite"
        \\  steps:
        \\    - shell: bash
        \\      run: echo hi
        \\    - id: two
        \\      shell: sh
        \\      env:
        \\        A: 1
        \\    - name: bare
        \\      uses: x/y@v1
        \\list:
        \\- a
        \\- b
        \\- - nested
        \\  - seq
    , null);
    const steps = n.get("runs").?.get("steps").?.seq;
    try std.testing.expectEqual(@as(usize, 3), steps.len);
    try expectStr(steps[0].get("run"), "echo hi");
    try expectStr(steps[1].get("id"), "two");
    try expectStr(steps[1].get("env").?.get("A"), "1");
    try expectStr(steps[2].get("uses"), "x/y@v1");
    const list = n.get("list").?.seq;
    try std.testing.expectEqual(@as(usize, 3), list.len);
    try expectStr(list[1], "b");
    try expectStr(list[2].seq[1], "seq");
}

test "block scalars: literal, folded, chomping, and bodies that look like YAML" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\steps:
        \\  - run: |
        \\      set -o pipefail
        \\      # not a yaml comment
        \\      if [[ -n "$x" ]]; then
        \\        echo "a: b"
        \\      fi
        \\
        \\      echo done
        \\    shell: bash
        \\  - run: |-
        \\      no newline
        \\  - run: >
        \\      folded text
        \\      continues here
        \\
        \\      new paragraph
        \\  - run: |+
        \\      keep
        \\
        \\  - run: >-
        \\      One of:
        \\
        \\      - a list item
        \\        continued
        \\
        \\      After the list.
        \\next: after
    , null);
    const steps = n.get("steps").?.seq;
    try expectStr(steps[0].get("run"), "set -o pipefail\n# not a yaml comment\nif [[ -n \"$x\" ]]; then\n  echo \"a: b\"\nfi\n\necho done\n");
    try expectStr(steps[0].get("shell"), "bash");
    try expectStr(steps[1].get("run"), "no newline");
    try expectStr(steps[2].get("run"), "folded text continues here\nnew paragraph\n");
    try expectStr(steps[3].get("run"), "keep\n\n");
    // Lines next to a more-indented line keep their breaks (checked against Ruby's Psych).
    try expectStr(steps[4].get("run"), "One of:\n- a list item\n  continued\n\nAfter the list.");
    try expectStr(n.get("next"), "after");
}

test "a block scalar directly under a dash" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\- |
        \\  one
        \\  two
        \\- last
    , null);
    try expectStr(n.seq[0], "one\ntwo\n");
    try expectStr(n.seq[1], "last");
}

test "quoted strings, escapes and flow collections" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\single: 'it''s'
        \\double: "tab\there \"quoted\" \u00e9"
        \\flow: [a, "b c", 'd']
        \\branding: { icon: box, color: blue }
        \\args: [--a, --b=1]
        \\"quoted key": v
        \\url: "http://x:80"
    , null);
    try expectStr(n.get("single"), "it's");
    try expectStr(n.get("double"), "tab\there \"quoted\" \u{e9}");
    const flow = n.get("flow").?.seq;
    try expectStr(flow[1], "b c");
    try expectStr(flow[2], "d");
    try expectStr(n.get("branding").?.get("color"), "blue");
    try expectStr(n.get("args").?.seq[1], "--b=1");
    try expectStr(n.get("quoted key"), "v");
    try expectStr(n.get("url"), "http://x:80");
}

test "plain scalars continue on following lines; expressions keep their colons" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\description: first part
        \\  second part
        \\if: ${{ inputs.x == 'a: b' && github.event_name }}
        \\value: ${{ steps.exec.outputs.stdout }}
    , null);
    try expectStr(n.get("description"), "first part second part");
    try expectStr(n.get("if"), "${{ inputs.x == 'a: b' && github.event_name }}");
    try expectStr(n.get("value"), "${{ steps.exec.outputs.stdout }}");
}

test "quoted strings that span lines are folded" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\inputs:
        \\  merge-multiple:
        \\    description: 'When multiple artifacts match, this changes things.
        \\      If true, they share a directory.
        \\
        \\      New paragraph.'
        \\    required: false
        \\  glob:
        \\    description:
        \\      "Glob pattern to match files relative to the working directory to control
        \\      the cache."
        \\    default: x
    , null);
    const in = n.get("inputs").?;
    try expectStr(in.get("merge-multiple").?.get("description"), "When multiple artifacts match, this changes things. If true, they share a directory.\nNew paragraph.");
    try expectStr(in.get("merge-multiple").?.get("required"), "false");
    try expectStr(in.get("glob").?.get("description"), "Glob pattern to match files relative to the working directory to control the cache.");
    try expectStr(in.get("glob").?.get("default"), "x");
}

// The expected values in the tests below are what go.yaml.in/yaml/v3 reads.

test "quoted strings over several lines: folding, empty lines, escaped line breaks" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const m = try parse(a.allocator(), "a: \"x  \n  y \\\n  z\\\n    w\"\n" ++ // white space around breaks goes; `\` joins
        "b: \"x\\\n\n  y\"\n" ++ // an empty line after an escaped break is a newline
        "c: 'x\n\n  y\n \n  z'\n" ++ // an empty (or blank) line is a newline, not a space
        "d: \"x\ne\"\n" ++ // indentation is not looked at, as in go-yaml
        "e: 'it''\n  ''s'\n" ++
        "f: \"  lead\n  trail  \"\n" ++ // white space next to the quotes stays
        "g: \"x\\ \n  y\"\n" ++ // an escaped space stays
        "h: \"x\n  # not a comment\n  y\" # a comment\n" ++
        "i: \"x\t\n\t\ty\"\n" ++ // tabs are white space here, even starting a line
        "j: \"a\\\t\n  b\"\n" ++ // `\` and a tab is a tab
        "k: \"\\t\\x41\\u00e9\\U0001F600\\N\\_\\e\"\n" ++
        "l:\n- \"a\n\n\n  b\"\n- '\n  x\n  '\n", null);
    try expectStr(m.get("a"), "x y zw");
    try expectStr(m.get("b"), "x\ny");
    try expectStr(m.get("c"), "x\ny\nz");
    try expectStr(m.get("d"), "x e");
    try expectStr(m.get("e"), "it' 's");
    try expectStr(m.get("f"), "  lead trail  ");
    try expectStr(m.get("g"), "x  y");
    try expectStr(m.get("h"), "x # not a comment y");
    try expectStr(m.get("i"), "x y");
    try expectStr(m.get("j"), "a\t b");
    try expectStr(m.get("k"), "\tA\u{e9}\u{1F600}\u{85}\u{a0}\x1b");
    try expectStr(m.get("l").?.seq[0], "a\n\nb");
    try expectStr(m.get("l").?.seq[1], " x ");
}

test "quoted strings over several lines that go-yaml refuses" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    for ([_][]const u8{
        "a: \"open\n", // never closed
        "a: \"open\nb: 1\n",
        "a: 'open\n\n",
        "a: \"x\\", // `\` at the very end
        "a: \"x\n---\ny\"\n", // a document marker ends the document, even in quotes
        "a: \"x\n...\ny\"\n",
        "\"a\n b\": c\n", // a key must be on one line
        "a: \"x\n  y\" z\n", // text after the closing quote
        "a: \"x\n  y\"\n  b: 1\n",
        "a: \"\\ud800\"\n", // a surrogate
        "a: \"\\U00110000\"\n",
        "a: \"\\q\"\n",
        "a: \"\\/\"\n", // JSON's escape, not YAML's
    }) |src| {
        var d: Diag = .{};
        try std.testing.expectError(error.InvalidYaml, parse(a.allocator(), src, &d));
        try std.testing.expect(d.line > 0);
    }
}

test "flow collections over several lines, with comments" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\a: [
        \\  "x
        \\   y", 'p
        \\   q',
        \\  z
        \\   w # c
        \\  ,
        \\]
        \\b: {
        \\  # leading comment
        \\  k1: v1,   # after
        \\  "k2": [1,
        \\         2],
        \\  k3:
        \\    v3, k4
        \\}
        \\c: [a: b, "x":y, ? p : q, ?r]
        \\d: {? x
        \\  : y, ? , "j":k, l:m}
        \\e: [x
        \\
        \\  y]
        \\f: [1,
        \\2]#c
        \\g: [x,#c
        \\  {null: null}, [], {}]
        \\h: {k: 1, ? k : 2}
    , null);
    const a_ = n.get("a").?.seq;
    try std.testing.expectEqual(@as(usize, 3), a_.len);
    try expectStr(a_[0], "x y");
    try expectStr(a_[1], "p q");
    try expectStr(a_[2], "z w");
    const b = n.get("b").?;
    try std.testing.expectEqual(@as(usize, 4), b.map.len);
    try expectStr(b.get("k1"), "v1");
    try expectStr(b.get("k2").?.seq[1], "2");
    try expectStr(b.get("k3"), "v3");
    try std.testing.expect(b.get("k4").? == .null);
    // `[a: b]` holds a mapping of one entry.
    const c = n.get("c").?.seq;
    try expectStr(c[0].get("a"), "b");
    try expectStr(c[1].get("x"), "y");
    try expectStr(c[2].get("p"), "q");
    try std.testing.expect(c[3].get("r").? == .null);
    const d = n.get("d").?;
    try expectStr(d.get("x"), "y");
    try std.testing.expect(d.get("").? == .null);
    try expectStr(d.get("j"), "k");
    try std.testing.expect(d.get("l:m").? == .null);
    try expectStr(n.get("e").?.seq[0], "x\ny");
    try expectStr(n.get("f").?.seq[1], "2");
    const g = n.get("g").?.seq;
    try std.testing.expect(g[1].get("null").? == .null);
    try std.testing.expectEqual(@as(usize, 0), g[2].seq.len);
    // A key given twice has its last value, as in block style (go-yaml's Node keeps both).
    try std.testing.expectEqual(@as(usize, 1), n.get("h").?.map.len);
    try expectStr(n.get("h").?.get("k"), "2");
}

test "flow collections that go-yaml refuses" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    for ([_][]const u8{
        "a: [a, b\n", // never closed
        "a: {a: 1\n",
        "a: [a, b}\n",
        "a: [a, b]]\n",
        "a: [x] y\n",
        "a: [x]\n  y\n",
        "a: {a\n  : b}\n", // a key must be on one line with its `:`
        "a: [a\n  : b]\n",
        "a: {\"a\n  b\": c}\n",
        "a: {a: b\n  c: d}\n",
        "a: [x # c\n  y]\n", // a comment ends a plain scalar
        "a: [x?y]\n",
        "a: [- x]\n",
        "a: [a: b: c]\n",
        "a: [x, :y]\n",
        "a: {: z}\n",
        "a: [? ]\n", // go-yaml's parser stumbles on an empty explicit key in a sequence
        "a: [? : x]\n",
        "a: [x,\n---\n]\n",
        "a: [x,\n%x]\n",
        "a: [x, y\n\t]\n", // a tab starting a plain scalar's line
        "[a,\nb]: c\n",
    }) |src| {
        var d: Diag = .{};
        try std.testing.expectError(error.InvalidYaml, parse(a.allocator(), src, &d));
        try std.testing.expect(d.line > 0);
    }
}

test "explicit keys in block mappings" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\? a
        \\: b
        \\? |
        \\  lit
        \\: >
        \\  fold
        \\? null
        \\? "q
        \\  r"
        \\: - s
        \\  - t
        \\k: v
        \\? x # c
        \\# c2
        \\:
        \\- y
        \\?
        \\: empty
        \\n:
        \\  - ? a
        \\    : b: c
        \\      d: e
        \\  - ? z
    , null);
    try std.testing.expectEqual(@as(usize, 8), n.map.len);
    try expectStr(n.get("a"), "b");
    try expectStr(n.get("lit\n"), "fold\n");
    // A key keeps its text: the null words are null only as values.
    try std.testing.expect(n.get("null").? == .null);
    try expectStr(n.get("q r").?.seq[1], "t");
    try expectStr(n.get("k"), "v");
    try expectStr(n.get("x").?.seq[0], "y");
    try expectStr(n.get(""), "empty");
    const items = n.get("n").?.seq;
    try expectStr(items[0].get("a").?.get("d"), "e");
    try std.testing.expect(items[1].get("z").? == .null);

    for ([_]struct { src: []const u8, err: Error }{
        .{ .src = "? a: b\n: c\n", .err = error.UnsupportedYaml }, // a key that is a mapping
        .{ .src = "? - a\n: c\n", .err = error.UnsupportedYaml },
        .{ .src = "? a\n : b\n", .err = error.InvalidYaml },
        .{ .src = "? a\n:b\n", .err = error.InvalidYaml },
        .{ .src = "? a\n: b\n: c\n", .err = error.InvalidYaml },
        .{ .src = ": x\n", .err = error.InvalidYaml },
    }) |c| try std.testing.expectError(c.err, parse(a.allocator(), c.src, null));
}

test "a key over 1024 characters is refused, as YAML says" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const at_limit = comptime repeat("k", 1024);
    const n = try parse(ar, at_limit ++ ": v\nf: {" ++ at_limit ++ ": w}\n", null);
    try expectStr(n.get(at_limit), "v");
    try expectStr(n.get("f").?.get(at_limit), "w");
    try std.testing.expectError(error.InvalidYaml, parse(ar, at_limit ++ "k: v\n", null));
    try std.testing.expectError(error.InvalidYaml, parse(ar, "f: {" ++ at_limit ++ "k: w}\n", null));
    // Characters, not bytes.
    const wide = comptime repeat("\u{e9}", 1024);
    try expectStr((try parse(ar, wide ++ ": v\n", null)).get(wide), "v");
}

fn repeat(comptime s: []const u8, comptime n: usize) []const u8 {
    @setEvalBranchQuota(100_000);
    var out: []const u8 = "";
    for (0..n) |_| out = out ++ s;
    return out;
}

test "what comparing with Go's YAML turned up, the second time" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Each of these yaml.zig used to read; go-yaml refuses them.
    for ([_][]const u8{
        "a: b # c\n  d\nx: 1\n", // a comment ends a plain scalar
        "- b # c\n  d\n",
        "a: ,x\n",  "a: ]x\n",  "a: %x\n",  "a: @x\n", "a: `x\n", "a: |x\n", // not the start of a plain scalar
        "a: - x\n", "a: ? x\n", "a: : x\n", ",a: 1\n", "|a: 1\n", "- ,x\n",
        "? ,x\n",
        "- \tx\n", "? \tx\n", "? x\n:  \ty\n", // a tab after an indicator
        "a: \x01\n", "a: \xff\n", "a: \xc3\n", // control characters, not UTF-8
    }) |src| {
        var d: Diag = .{};
        try std.testing.expectError(error.InvalidYaml, parse(ar, src, &d));
        try std.testing.expect(d.line > 0);
    }
    try std.testing.expectError(error.UnsupportedYaml, parse(ar, "a: x\u{2028}y\n", null));
    // And these it misread.
    const n = try parse(ar, "\u{feff}a: \tx\nb:\ty\nc: x\t# c\n?: q\nd: -x\ne:\n  |\n    text\nf: [x]\t\n", null);
    try expectStr(n.get("a"), "x");
    try expectStr(n.get("b"), "y");
    try expectStr(n.get("c"), "x");
    try expectStr(n.get("?"), "q");
    try expectStr(n.get("d"), "-x");
    try expectStr(n.get("e"), "text\n");
    try expectStr(n.get("f").?.seq[0], "x");
}

test "a block scalar at the end of a file without a final line break" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try expectStr((try parse(ar, "k: >\n  fold", null)).get("k"), "fold");
    try expectStr((try parse(ar, "k: |+\n  keep\n\n  ", null)).get("k"), "keep\n\n");
    try expectStr((try parse(ar, "k: |+\n  keep\n\n", null)).get("k"), "keep\n\n");
    try expectStr((try parse(ar, "k: |\n  a\n\n", null)).get("k"), "a\n");
}

test "a leading document marker, CRLF line endings and duplicate keys" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(), "---\r\nname: x\r\nname: y\r\nk:\r\n  - 1\r\n", null);
    try expectStr(n.get("name"), "y");
    try expectStr(n.get("k").?.seq[0], "1");
}

test "a duplicate key replaces the value in its first place, in block and flow mappings" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    for ([_][]const u8{ "a: 1\nb: 2\na: 3\nc: 4\n", "{a: 1, b: 2, a: 3, c: 4}\n", "? a\n: 1\nb: 2\na: 3\nc: 4\n" }) |src| {
        const m = (try parse(ar, src, null)).map;
        try std.testing.expectEqual(3, m.len);
        try std.testing.expectEqualStrings("a", m[0].key);
        try expectStr(m[0].value, "3");
        try std.testing.expectEqualStrings("b", m[1].key);
        try std.testing.expectEqualStrings("c", m[2].key);
    }
}

test "a mapping's keys are found in linear time, not by comparing each with all before it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // 20000 distinct keys, then each again: comparing each key with all before it makes ~6e8
    // comparisons; the index makes about one per repeated key.
    const n = 20000;
    var e: Entries = .{};
    for (0..2) |round| for (0..n) |i| {
        const key = try std.fmt.allocPrint(ar, "key{d}", .{i});
        try e.put(ar, key, .{ .string = if (round == 0) "first" else "second" });
    };
    try std.testing.expectEqual(n, e.list.items.len);
    try std.testing.expectEqualStrings("key0", e.list.items[0].key);
    try expectStr(e.list.items[n - 1].value, "second");
    try std.testing.expect(e.compares <= 2 * n);

    // And through the parser: a block and a flow mapping of as many keys.
    var block: std.ArrayList(u8) = .empty;
    var flow: std.ArrayList(u8) = .empty;
    try flow.appendSlice(ar, "{");
    for (0..n) |i| {
        try block.print(ar, "k{d}: v\n", .{i});
        try flow.print(ar, "k{d}: v, ", .{i});
    }
    try flow.appendSlice(ar, "k0: last}\n");
    try std.testing.expectEqual(n, (try parse(ar, block.items, null)).map.len);
    const fm = (try parse(ar, flow.items, null)).map;
    try std.testing.expectEqual(n, fm.len);
    try expectStr(fm[0].value, "last");
}

test "a lone scalar at the top level" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    try expectStr(try parse(a.allocator(), "just text\n", null), "just text");
}

test "constructs outside the subset are rejected, not misread" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const cases = [_]struct { src: []const u8, err: Error }{
        .{ .src = "a: &x 1\n", .err = error.UnsupportedYaml },
        .{ .src = "a: *x\n", .err = error.UnsupportedYaml },
        .{ .src = "a: !!str 1\n", .err = error.UnsupportedYaml },
        .{ .src = "<<: *x\n", .err = error.UnsupportedYaml },
        .{ .src = "a: 1\n---\nb: 2\n", .err = error.UnsupportedYaml },
        .{ .src = "? [a]\n: b\n", .err = error.UnsupportedYaml },
        .{ .src = "a: {[a]: b}\n", .err = error.UnsupportedYaml },
        .{ .src = "a:\n\tb: 1\n", .err = error.InvalidYaml },
        .{ .src = "a: b\n  c: d\n", .err = error.InvalidYaml },
    };
    for (cases) |c| {
        var d: Diag = .{};
        try std.testing.expectError(c.err, parse(a.allocator(), c.src, &d));
        try std.testing.expect(d.line > 0);
    }
}

test "the dagger-for-github action.yml shape parses" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const n = try parse(a.allocator(),
        \\name: "Dagger for GitHub"
        \\inputs:
        \\  engine-stop:
        \\    description: "Deprecated"
        \\    deprecationMessage: "engine-stop is now a no-op"
        \\    required: false
        \\outputs:
        \\  output:
        \\    description: "Job output"
        \\    value: ${{ steps.exec.outputs.stdout }}
        \\runs:
        \\  using: "composite"
        \\  steps:
        \\    - shell: bash
        \\      run: |
        \\        VERSION=${{ inputs.version }}
        \\        if [[ "$VERSION" == "latest" ]]; then
        \\          VERSION=
        \\        fi
        \\    - id: should-exec
        \\      shell: bash
        \\      env:
        \\        INPUT_CALL: ${{ inputs.call }}
        \\      run: |
        \\        echo "result=true" >> "$GITHUB_OUTPUT"
        \\    - id: assemble
        \\      if: steps.should-exec.outputs.result == 'true'
        \\      shell: bash
        \\      run: |
        \\        args=$(echo '${{ toJSON(inputs.args) }}' | jq -rj . | sed -z 's/\\\n/ /g; s/\n/ /g')
    , null);
    const steps = n.get("runs").?.get("steps").?.seq;
    try std.testing.expectEqual(@as(usize, 3), steps.len);
    try expectStr(steps[1].get("id"), "should-exec");
    try expectStr(steps[1].get("env").?.get("INPUT_CALL"), "${{ inputs.call }}");
    try expectStr(steps[2].get("if"), "steps.should-exec.outputs.result == 'true'");
    try std.testing.expect(std.mem.indexOf(u8, steps[2].get("run").?.text().?, "sed -z 's/\\\\\\n/ /g; s/\\n/ /g'") != null);
    try expectStr(n.get("outputs").?.get("output").?.get("value"), "${{ steps.exec.outputs.stdout }}");
}

test "flow collections nested past 64 are refused, not a stack overflow" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(ar, "a: ");
    for (0..100_000) |_| try deep.append(ar, '[');
    for (0..100_000) |_| try deep.append(ar, ']');
    try std.testing.expectError(error.UnsupportedYaml, parse(ar, deep.items, null));
    deep.clearRetainingCapacity();
    try deep.appendSlice(ar, "a: ");
    for (0..100_000) |_| try deep.appendSlice(ar, "{k: ");
    for (0..100_000) |_| try deep.append(ar, '}');
    try std.testing.expectError(error.UnsupportedYaml, parse(ar, deep.items, null));
    const ok = try parse(ar, "a: [[1, {b: [2]}]]\n", null);
    try std.testing.expectEqualStrings("2", ok.get("a").?.seq[0].seq[1].get("b").?.seq[0].string);
}

test "a flow entry that reads nothing is invalid, not read again until memory runs out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Found by fuzz.zig: each of these grew the arena without end (18 GB from a 4 KB file).
    // An empty item, `[1, , 2]`, is invalid YAML too (Go's yaml.v3 refuses it), and went the same way.
    for ([_][]const u8{ "a: [}]\n", "a: {]}\n", "a: [1, }]\n", "a: {b: 1, ]}\n", "a: [1, , 2]\n" }) |src| {
        var diag: Diag = .{};
        try std.testing.expectError(error.InvalidYaml, parse(ar, src, &diag));
        try std.testing.expectEqualStrings("unexpected character in a flow collection", diag.message);
    }
    const ok = try parse(ar, "b: {c: , d}\n", null);
    try std.testing.expectEqual(@as(usize, 2), ok.get("b").?.map.len);
}

test "what comparing with Go's YAML turned up: the null words, and explicit keys in flow" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const n = try parse(ar, "a: Null\nb: NULL\nc: [Null, ~]\nd: nULL\n", null);
    try std.testing.expect(n.get("a").? == .null);
    try std.testing.expect(n.get("b").? == .null);
    try std.testing.expect(n.get("c").?.seq[0] == .null);
    try std.testing.expectEqualStrings("nULL", n.get("d").?.string);
    // An explicit key, not a key named "? ...".
    const e = try parse(ar, "a: {? \"multi\\nline\" : []}\n", null);
    try std.testing.expectEqual(@as(usize, 0), e.get("a").?.get("multi\nline").?.seq.len);
}

test "block collections nested on one line are refused past 1000 deep, not a stack overflow (#98)" {
    // Both at once: each parse is slow in a debug build, and they share nothing.
    const io = std.testing.io;
    var keys = try io.concurrent(refusedDeep, .{"? "});
    defer keys.cancel(io) catch {};
    try refusedDeep("- ");
    try keys.await(io);
    // Real nesting still reads.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ok = try parse(a.allocator(), "a:\n  - - - x\n", null);
    try std.testing.expectEqualStrings("x", ok.get("a").?.seq[0].seq[0].seq[0].string);
}

fn refusedDeep(indicator: []const u8) !void {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var deep: std.ArrayList(u8) = .empty;
    for (0..70_000) |_| try deep.appendSlice(ar, indicator);
    try deep.append(ar, 'x');
    var diag: Diag = .{};
    try std.testing.expectError(error.UnsupportedYaml, parse(ar, deep.items, &diag));
    try std.testing.expectEqualStrings("block collections nested over 1000 deep", diag.message);
}

test "parseTyped: plain booleans and numbers are typed, quoted ones and the rest stay strings" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const src =
        \\b: [true, False, FALSE, 'true', "false", yes]
        \\n: [1, -3, +4, 0, 2.5, -0.5, .5, 1e3, 1.5E-2, '3.10', "7"]
        \\s: [0123, 1_000, 0x1F, 1.2.3, 1e, -, "", ~, v1]
        \\block: 42
        \\flag: true
        \\text: |
        \\  12
        \\
    ;
    const n = try parseTyped(arena, src, null);
    const b = n.get("b").?.seq;
    try std.testing.expectEqual(true, b[0].boolean);
    try std.testing.expectEqual(false, b[1].boolean);
    try std.testing.expectEqual(false, b[2].boolean);
    try std.testing.expectEqualStrings("true", b[3].string);
    try std.testing.expectEqualStrings("false", b[4].string);
    try std.testing.expectEqualStrings("yes", b[5].string);
    const nums = n.get("n").?.seq;
    for ([_][]const u8{ "1", "-3", "+4", "0", "2.5", "-0.5", ".5", "1e3", "1.5E-2" }, nums[0..9]) |want, got|
        try std.testing.expectEqualStrings(want, got.number);
    try std.testing.expectEqualStrings("3.10", nums[9].string);
    try std.testing.expectEqualStrings("7", nums[10].string);
    const strs = n.get("s").?.seq;
    for (strs[0..5]) |s| try std.testing.expect(s == .string);
    try std.testing.expectEqualStrings("0123", strs[0].string);
    try std.testing.expect(strs[7] == .null);
    try std.testing.expectEqualStrings("42", n.get("block").?.number);
    try std.testing.expectEqual(true, n.get("flag").?.boolean);
    try std.testing.expectEqualStrings("12\n", n.get("text").?.string);
    try std.testing.expectEqualStrings("true", n.get("flag").?.scalarText().?);
    try std.testing.expectEqualStrings("42", n.get("block").?.scalarText().?);
    // `parse` still reads every scalar as a string.
    const plain = try parse(arena, src, null);
    try std.testing.expectEqualStrings("true", plain.get("flag").?.string);
    try std.testing.expectEqualStrings("42", plain.get("block").?.string);
    // A key is text whatever it looks like.
    const keys = try parseTyped(arena, "1: a\ntrue: b\nf: {2: c}\n", null);
    try std.testing.expectEqualStrings("a", keys.get("1").?.string);
    try std.testing.expectEqualStrings("b", keys.get("true").?.string);
    try std.testing.expectEqualStrings("c", keys.get("f").?.get("2").?.string);
}
