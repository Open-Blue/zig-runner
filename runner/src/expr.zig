//! GitHub Actions expressions (`${{ ... }}` and `if:` conditions).
//!
//! A small tokenizer, parser and evaluator following GitHub's documented semantics: literals,
//! context lookups (`github.sha`, `env.X`, `steps.id.outputs.y`, `matrix['os']`), the operators
//! `! < <= > >= == != && ||` with GitHub's loose type coercion (string comparison is case
//! insensitive, `&&`/`||` return an operand), and the functions contains, startsWith, endsWith,
//! format, join, toJSON, fromJSON, success/always/cancelled/failure, and hashFiles when the scope
//! can read files (`Scope.hash_files`).
//!
//! Where GitHub's two evaluators differ, this follows the one its runner executes (actions/runner,
//! C#) over its editor tooling's (actions/languageservices, TypeScript), whose test cases it
//! otherwise passes: `case()` evaluates only the value it picks, `format()` an argument only when a
//! placeholder needs it, and `a[k]` evaluates `a` first and `k` only when `a` is an array or an
//! object. So an error in what is never needed is no error, as in a workflow on GitHub (#64).
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Value = union(enum) {
    null,
    boolean: bool,
    number: f64,
    string: []const u8,
    array: []const Value,
    /// Property names are matched case-insensitively, as GitHub does.
    object: []const Entry,

    pub const Entry = struct { key: []const u8, value: Value };

    pub fn str(s: []const u8) Value {
        return .{ .string = s };
    }
};

pub const Error = error{ ParseError, EvalError, Unsupported, OutOfMemory };

/// Computes `hashFiles(patterns)` where the job's files are (the caller supplies it).
pub const HashFiles = struct {
    ptr: *anyopaque,
    hashFn: *const fn (
        ptr: *anyopaque,
        arena: Allocator,
        patterns: []const []const u8,
    ) Allocator.Error!Result,

    /// The hex hash ("" when no file matched), or why it could not be computed.
    pub const Result = union(enum) { ok: []const u8, failed: []const u8 };
};

/// What an expression can see.
pub const Scope = struct {
    /// Top-level contexts: `github`, `env`, `steps`, `job`, `runner`, `secrets`, `vars`, ...
    contexts: []const Value.Entry = &.{},
    /// True once a step failed without continue-on-error (drives `success()` / `failure()`).
    job_failed: bool = false,
    cancelled: bool = false,
    /// Contexts that exist in GitHub but that this runner cannot provide yet (for example
    /// `secrets`). Referencing one is an error instead of silently evaluating to an empty value.
    unsupported_contexts: []const []const u8 = &.{},
    /// Receives a human-readable reason when an error is returned. Optional.
    diag: ?*[]const u8 = null,
    /// What `hashFiles()` reads files with; without it, `hashFiles()` is unsupported.
    hash_files: ?HashFiles = null,
    /// The evaluation's memory, counted as GitHub counts it (`Memory`); `evaluate` sets it.
    memory: ?*Memory = null,
    /// The arrays `*` filters have made (see `access`); `evaluate` sets it.
    filtered: ?*Filtered = null,

    fn fail(s: Scope, comptime fmt: []const u8, args: anytype, arena: Allocator) Error {
        if (s.diag) |d| d.* = std.fmt.allocPrint(arena, fmt, args) catch return error.OutOfMemory;
        return error.EvalError;
    }

    fn tooMuchMemory(s: Scope, arena: Allocator) Error {
        return s.fail("the expression needs more than the {d} bytes of memory GitHub allows", .{max_memory}, arena);
    }

    /// Counts what a node evaluated to (`Memory.add`), as GitHub's `ExpressionNode.Evaluate`
    /// does after each node.
    fn account(s: Scope, arena: Allocator, level: usize, r: Evaluated) Error!void {
        const m = s.memory orelse return;
        // From a context or fromJSON, a boolean, number or string is GitHub's context data object
        // (StringContextData, ...): it costs an object, then its plain value as well, and does not
        // let the levels below be dropped.
        const data = r.data and (r.v == .boolean or r.v == .number or r.v == .string);
        const bytes = r.bytes orelse if (data) min_object_size else costOf(r.v);
        if (try m.add(arena, level, bytes, !data and isPrimitive(r.v))) return s.tooMuchMemory(arena);
        if (data and try m.add(arena, level, costOf(r.v), false)) return s.tooMuchMemory(arena);
    }
};

/// The memory GitHub lets one evaluation use, and how it counts it: actions/runner's
/// `EvaluationMemory`, `MemoryCounter` and `ExpressionNode.Evaluate`
/// (src/Sdk/DTExpressions2/Expressions2/Sdk/). Each node's result is counted at its level in the
/// tree: a string as 26 bytes and two per UTF-16 code unit (as .NET stores it), anything else as
/// an object's 24, a `*` filter's result as 24 and a pointer per element. When a node's result is
/// a plain primitive (a literal's, a function's, an operator's), it no longer refers to what was
/// made below it, so the levels below are dropped from the count first. `format`, `join` and
/// `toJSON` also count what they build as they go, piece by piece, against the same limit. Past it, the evaluation
/// fails, as GitHub's does (`syntax-errors/memory-errors` in GitHub's tests), before
/// `format('{0}{0}{0}{0}', format('{0}{0}{0}{0}', ...))` can grow until the runner runs out of
/// memory.
///
/// The count follows the C# evaluator (actions/runner), the one GitHub runs; GitHub's TypeScript
/// one (actions/languageservices) has no memory limit.
const max_memory = 1048576;
const min_object_size = 24;
const string_overhead = 26;
const pointer_size = 8;

/// What GitHub counts a value as (`EvaluationMemory.CalculateBytes`).
fn costOf(v: Value) usize {
    return switch (v) {
        .string => |text| string_overhead + 2 * utf16Len(text),
        else => min_object_size,
    };
}

/// The length .NET gives a string: UTF-16 code units, two for a character past U+FFFF.
fn utf16Len(text: []const u8) usize {
    var n: usize = 0;
    for (text) |b| {
        if (b & 0xc0 != 0x80) n += if (b >= 0xf0) 2 else 1;
    }
    return n;
}

/// GitHub's `EvaluationMemory`: bytes counted per level of the expression tree.
const Memory = struct {
    depths: std.ArrayList(usize) = .empty,
    /// Levels in use, from 0: C#'s `m_maxActiveDepth + 1`.
    active: usize = 0,
    total: usize = 0,

    /// Counts `bytes` at `level`, first dropping the levels below it when `trim`. True when the
    /// total is past the limit.
    fn add(m: *Memory, arena: Allocator, level: usize, bytes: usize, trim: bool) Allocator.Error!bool {
        if (trim) while (m.active > level + 1) {
            m.active -= 1;
            m.total -= m.depths.items[m.active];
            m.depths.items[m.active] = 0;
        };
        if (level + 1 > m.active) {
            while (m.depths.items.len <= level) try m.depths.append(arena, 0);
            m.active = level + 1;
        }
        m.depths.items[level] += bytes;
        m.total += bytes;
        return m.total > max_memory;
    }
};

/// A node's value, with what GitHub's memory count needs to know of it.
const Evaluated = struct {
    v: Value,
    /// Read from a context or made by fromJSON (GitHub's context data), not made by the expression.
    data: bool = false,
    /// What the node itself counts it as, when not the value's own cost (`ResultMemory.Bytes`).
    bytes: ?usize = null,
};

/// How deeply `fromJSON` input may nest. Its result is converted (and compared, and written back)
/// recursively, so `fromJSON('[[[[...]]]]')` would otherwise overflow the stack.
const max_json_nesting = 1000;

// --- tokens ---

const Tok = union(enum) {
    number: f64,
    string: []const u8,
    ident: []const u8,
    lparen,
    rparen,
    lbracket,
    rbracket,
    dot,
    comma,
    star,
    not,
    and_and,
    or_or,
    eq,
    ne,
    lt,
    le,
    gt,
    ge,
    eof,
};

/// Whether `c` continues a number token. As GitHub's lexer: anything up to a boundary (whitespace,
/// brackets, parentheses, a comma, an operator), a point included. So `1E-2` is one token and
/// `1-2` is one invalid token; what a token means is up to `jsNumber`.
fn isNumberChar(c: u8) bool {
    return switch (c) {
        '(', '[', ')', ']', ',', '!', '>', '<', '=', '&', '|' => false,
        else => !std.ascii.isWhitespace(c),
    };
}

/// What JavaScript's `Number()` makes of a string, which is what GitHub's expressions follow, both
/// for number literals and for a string compared with a number: whitespace around it ignored, ""
/// is 0, a decimal with an optional sign, point and exponent (`-.5`, `1E+2`), `Infinity` with an
/// optional sign, and unsigned `0x`, `0o` and `0b` integers. Anything else is NaN. Stricter than
/// `std.fmt.parseFloat`, which also takes `inf`, `nan`, underscores and hex floats.
pub fn jsNumber(text: []const u8) f64 {
    const t = std.mem.trim(u8, text, " \t\r\n\x0b\x0c");
    if (t.len == 0) return 0;
    const nan = std.math.nan(f64);
    if (t.len > 2 and t[0] == '0') {
        const radix: ?u8 = switch (t[1]) {
            'x', 'X' => 16,
            'o', 'O' => 8,
            'b', 'B' => 2,
            else => null,
        };
        if (radix) |r| {
            var v: f64 = 0;
            for (t[2..]) |c| {
                const d = std.fmt.charToDigit(c, r) catch return nan;
                v = v * @as(f64, @floatFromInt(r)) + @as(f64, @floatFromInt(d));
            }
            return v;
        }
    }
    const neg = t[0] == '-';
    const body = if (t[0] == '-' or t[0] == '+') t[1..] else t;
    if (std.mem.eql(u8, body, "Infinity")) return if (neg) -std.math.inf(f64) else std.math.inf(f64);
    // digits [. digits] [e [sign] digits], with a digit somewhere before the exponent.
    var i: usize = 0;
    var digits: usize = 0;
    while (i < body.len and std.ascii.isDigit(body[i])) : (i += 1) digits += 1;
    if (i < body.len and body[i] == '.') {
        i += 1;
        while (i < body.len and std.ascii.isDigit(body[i])) : (i += 1) digits += 1;
    }
    if (digits == 0) return nan;
    if (i < body.len and (body[i] == 'e' or body[i] == 'E')) {
        i += 1;
        if (i < body.len and (body[i] == '+' or body[i] == '-')) i += 1;
        const start = i;
        while (i < body.len and std.ascii.isDigit(body[i])) i += 1;
        if (i == start) return nan;
    }
    if (i != body.len) return nan;
    const v = std.fmt.parseFloat(f64, body) catch return nan;
    return if (neg) -v else v;
}

const Lexer = struct {
    src: []const u8,
    i: usize = 0,
    arena: Allocator,
    diag: ?*[]const u8,

    fn bad(l: *Lexer, comptime fmt: []const u8, args: anytype) Error {
        if (l.diag) |d| d.* = std.fmt.allocPrint(
            l.arena,
            fmt ++ " (in expression: {s})",
            args ++ .{l.src},
        ) catch return error.OutOfMemory;
        return error.ParseError;
    }

    fn next(l: *Lexer, prev_is_value: bool) Error!Tok {
        while (l.i < l.src.len and std.ascii.isWhitespace(l.src[l.i])) l.i += 1;
        if (l.i >= l.src.len) return .eof;
        const c = l.src[l.i];
        const two: []const u8 = if (l.i + 1 < l.src.len) l.src[l.i .. l.i + 2] else "";
        if (std.mem.eql(u8, two, "&&")) return l.adv(2, .and_and);
        if (std.mem.eql(u8, two, "||")) return l.adv(2, .or_or);
        if (std.mem.eql(u8, two, "==")) return l.adv(2, .eq);
        if (std.mem.eql(u8, two, "!=")) return l.adv(2, .ne);
        if (std.mem.eql(u8, two, "<=")) return l.adv(2, .le);
        if (std.mem.eql(u8, two, ">=")) return l.adv(2, .ge);
        switch (c) {
            '(' => return l.adv(1, .lparen),
            ')' => return l.adv(1, .rparen),
            '[' => return l.adv(1, .lbracket),
            ']' => return l.adv(1, .rbracket),
            // `.5` is a number; any other point is a property access (`foo.*.bar`).
            '.' => if (prev_is_value or l.i + 1 >= l.src.len or !std.ascii.isDigit(l.src[l.i + 1]))
                return l.adv(1, .dot),
            ',' => return l.adv(1, .comma),
            '*' => return l.adv(1, .star),
            '!' => return l.adv(1, .not),
            '<' => return l.adv(1, .lt),
            '>' => return l.adv(1, .gt),
            '\'' => return l.string(),
            else => {},
        }
        // A sign or a point starts a number only where a value can start: after a value, `.` is a
        // property access.
        if (std.ascii.isDigit(c) or (!prev_is_value and (c == '-' or c == '+' or c == '.')))
            return l.number();
        if (std.ascii.isAlphabetic(c) or c == '_') {
            const start = l.i;
            while (l.i < l.src.len and (std.ascii.isAlphanumeric(l.src[l.i]) or l.src[l.i] == '_' or
                l.src[l.i] == '-')) l.i += 1;
            return .{ .ident = l.src[start..l.i] };
        }
        return l.bad("unexpected character '{c}'", .{c});
    }

    fn adv(l: *Lexer, n: usize, t: Tok) Tok {
        l.i += n;
        return t;
    }

    fn string(l: *Lexer) Error!Tok {
        l.i += 1; // opening quote
        var out: std.ArrayList(u8) = .empty;
        while (l.i < l.src.len) {
            const c = l.src[l.i];
            if (c == '\'') {
                if (l.i + 1 < l.src.len and l.src[l.i + 1] == '\'') {
                    try out.append(l.arena, '\'');
                    l.i += 2;
                    continue;
                }
                l.i += 1;
                return .{ .string = out.items };
            }
            try out.append(l.arena, c);
            l.i += 1;
        }
        return l.bad("unterminated string", .{});
    }

    fn number(l: *Lexer) Error!Tok {
        const start = l.i;
        l.i += 1;
        while (l.i < l.src.len and isNumberChar(l.src[l.i])) l.i += 1;
        const text = l.src[start..l.i];
        const v = jsNumber(text);
        if (std.math.isNan(v)) return l.bad("invalid number '{s}'", .{text});
        return .{ .number = v };
    }
};

// --- AST and parser ---

const BinOp = enum { and_, or_, eq, ne, lt, le, gt, ge };

const Node = union(enum) {
    literal: Value,
    ident: []const u8,
    prop: struct { obj: *Node, name: []const u8 },
    index: struct { obj: *Node, idx: *Node },
    star: *Node,
    call: struct { name: []const u8, args: []*Node },
    not: *Node,
    bin: struct { op: BinOp, l: *Node, r: *Node },
};

/// The functions there are, with how many arguments each takes.
const functions = [_]struct { name: []const u8, min: usize, max: usize }{
    .{ .name = "contains", .min = 2, .max = 2 },
    .{ .name = "startsWith", .min = 2, .max = 2 },
    .{ .name = "endsWith", .min = 2, .max = 2 },
    .{ .name = "format", .min = 1, .max = std.math.maxInt(usize) },
    .{ .name = "join", .min = 1, .max = 2 },
    .{ .name = "toJSON", .min = 1, .max = 1 },
    .{ .name = "fromJSON", .min = 1, .max = 1 },
    .{ .name = "hashFiles", .min = 1, .max = std.math.maxInt(usize) },
    .{ .name = "case", .min = 3, .max = std.math.maxInt(usize) },
    .{ .name = "success", .min = 0, .max = 0 },
    .{ .name = "always", .min = 0, .max = 0 },
    .{ .name = "cancelled", .min = 0, .max = 0 },
    .{ .name = "failure", .min = 0, .max = 0 },
};

/// GitHub refuses an expression nested deeper than this ("Exceeded max expression depth 50"). It
/// also keeps the parser's and the evaluator's recursion bounded: `action.yml` files are read as
/// written, with no check of GitHub's in between, and 100000 nested `!` overflowed the stack.
const max_depth = 50;

/// Every node is allocated with the depth of the tree under it, so the parser can refuse what is
/// too deep as it builds it.
const Slot = struct { node: Node, depth: u32 };

fn depthOf(n: *const Node) u32 {
    const slot: *const Slot = @fieldParentPtr("node", n);
    return slot.depth;
}

const Parser = struct {
    lex: Lexer,
    cur: Tok,
    prev_value: bool = false,
    /// The contexts the expression may name, when known: any other name is refused (`check`).
    contexts: ?[]const Value.Entry = null,
    /// How deep the parser itself has recursed (`!`, parentheses, arguments, indexes): `!!!...`
    /// recurses before it makes a single node.
    nesting: u32 = 0,

    fn init(arena: Allocator, src: []const u8, diag: ?*[]const u8) Error!Parser {
        var p: Parser = .{ .lex = .{ .src = src, .arena = arena, .diag = diag }, .cur = .eof };
        p.cur = try p.lex.next(false);
        return p;
    }

    fn advance(p: *Parser) Error!void {
        p.prev_value = switch (p.cur) {
            .number, .string, .ident, .rparen, .rbracket => true,
            else => false,
        };
        p.cur = try p.lex.next(p.prev_value);
    }

    fn node(p: *Parser, n: Node) Error!*Node {
        const below: u32 = switch (n) {
            .literal, .ident => 0,
            .prop => |x| depthOf(x.obj),
            .index => |x| @max(depthOf(x.obj), depthOf(x.idx)),
            .star, .not => |x| depthOf(x),
            .call => |c| blk: {
                var d: u32 = 0;
                for (c.args) |a| d = @max(d, depthOf(a));
                break :blk d;
            },
            // GitHub's `&&` and `||` take any number of operands: a chain of one of them is one
            // node, as deep as its deepest operand plus one, however long it is.
            .bin => |b| if ((b.op == .and_ or b.op == .or_) and b.l.* == .bin and b.l.bin.op == b.op)
                return p.slot(n, @max(depthOf(b.l), depthOf(b.r) + 1))
            else
                @max(depthOf(b.l), depthOf(b.r)),
        };
        return p.slot(n, below + 1);
    }

    fn slot(p: *Parser, n: Node, depth: u32) Error!*Node {
        if (depth > max_depth) return p.tooDeep();
        const s = try p.lex.arena.create(Slot);
        s.* = .{ .node = n, .depth = depth };
        return &s.node;
    }

    fn tooDeep(p: *Parser) Error {
        return p.lex.bad("the expression is nested more than {d} deep", .{max_depth});
    }

    /// GitHub refuses an unknown function, or one given the wrong number of arguments, when it
    /// parses the expression, so even where it would never be called (`false && nope()`).
    fn checkCall(p: *Parser, name: []const u8, n: usize) Error!void {
        for (functions) |f| if (std.ascii.eqlIgnoreCase(f.name, name)) {
            if (n < f.min) return p.lex.bad("too few arguments to {s}()", .{name});
            if (n > f.max) return p.lex.bad("too many arguments to {s}()", .{name});
            if (std.ascii.eqlIgnoreCase(name, "case") and n % 2 == 0)
                return p.lex.bad("case() takes an odd number of arguments", .{});
            return;
        };
        return p.lex.bad("unknown function '{s}'", .{name});
    }

    fn enter(p: *Parser) Error!void {
        p.nesting += 1;
        if (p.nesting > max_depth) return p.tooDeep();
    }

    fn expectEnd(p: *Parser) Error!void {
        if (p.cur != .eof)
            return p.lex.bad("unexpected token after the end of the expression", .{});
    }

    fn parseOr(p: *Parser) Error!*Node {
        var l = try p.parseAnd();
        while (p.cur == .or_or) {
            try p.advance();
            l = try p.node(.{ .bin = .{ .op = .or_, .l = l, .r = try p.parseAnd() } });
        }
        return l;
    }

    fn parseAnd(p: *Parser) Error!*Node {
        var l = try p.parseEq();
        while (p.cur == .and_and) {
            try p.advance();
            l = try p.node(.{ .bin = .{ .op = .and_, .l = l, .r = try p.parseEq() } });
        }
        return l;
    }

    fn parseEq(p: *Parser) Error!*Node {
        var l = try p.parseRel();
        while (p.cur == .eq or p.cur == .ne) {
            const op: BinOp = if (p.cur == .eq) .eq else .ne;
            try p.advance();
            l = try p.node(.{ .bin = .{ .op = op, .l = l, .r = try p.parseRel() } });
        }
        return l;
    }

    fn parseRel(p: *Parser) Error!*Node {
        var l = try p.parseUnary();
        while (p.cur == .lt or p.cur == .le or p.cur == .gt or p.cur == .ge) {
            const op: BinOp = switch (p.cur) {
                .lt => .lt,
                .le => .le,
                .gt => .gt,
                else => .ge,
            };
            try p.advance();
            l = try p.node(.{ .bin = .{ .op = op, .l = l, .r = try p.parseUnary() } });
        }
        return l;
    }

    fn parseUnary(p: *Parser) Error!*Node {
        if (p.cur == .not) {
            try p.advance();
            try p.enter();
            defer p.nesting -= 1;
            return p.node(.{ .not = try p.parseUnary() });
        }
        return p.parsePostfix();
    }

    fn parsePostfix(p: *Parser) Error!*Node {
        const grouped = p.cur == .lparen;
        var n = try p.parsePrimary();
        // GitHub indexes only a context, a function's result or a parenthesised expression:
        // `'abc'[0]` and `null.x` are refused, `(x)[0]` and `fromJSON(x).y` are not.
        if (!grouped and n.* != .ident and n.* != .call and (p.cur == .dot or p.cur == .lbracket))
            return p.lex.bad("unexpected '{s}' after a literal", .{if (p.cur == .dot) "." else "["});
        while (true) {
            switch (p.cur) {
                .dot => {
                    try p.advance();
                    switch (p.cur) {
                        .ident => |name| {
                            try p.advance();
                            n = try p.node(.{ .prop = .{ .obj = n, .name = name } });
                        },
                        .star => {
                            try p.advance();
                            n = try p.node(.{ .star = n });
                        },
                        else => return p.lex.bad("expected a property name after '.'", .{}),
                    }
                },
                .lbracket => {
                    try p.advance();
                    // `a[*]` is `a.*`.
                    if (p.cur == .star) {
                        try p.advance();
                        if (p.cur != .rbracket) return p.lex.bad("expected ']' after '[*'", .{});
                        try p.advance();
                        n = try p.node(.{ .star = n });
                        continue;
                    }
                    try p.enter();
                    defer p.nesting -= 1;
                    const idx = try p.parseOr();
                    if (p.cur != .rbracket) return p.lex.bad("expected ']'", .{});
                    try p.advance();
                    n = try p.node(.{ .index = .{ .obj = n, .idx = idx } });
                },
                else => return n,
            }
        }
    }

    fn parsePrimary(p: *Parser) Error!*Node {
        switch (p.cur) {
            .number => |v| {
                try p.advance();
                return p.node(.{ .literal = .{ .number = v } });
            },
            .string => |s| {
                try p.advance();
                return p.node(.{ .literal = .{ .string = s } });
            },
            .lparen => {
                try p.advance();
                try p.enter();
                defer p.nesting -= 1;
                const inner = try p.parseOr();
                if (p.cur != .rparen) return p.lex.bad("expected ')'", .{});
                try p.advance();
                return inner;
            },
            .ident => |name| {
                try p.advance();
                if (p.cur == .lparen) {
                    try p.advance();
                    try p.enter();
                    defer p.nesting -= 1;
                    var args: std.ArrayList(*Node) = .empty;
                    if (p.cur != .rparen) {
                        while (true) {
                            try args.append(p.lex.arena, try p.parseOr());
                            if (p.cur == .comma) {
                                try p.advance();
                                continue;
                            }
                            break;
                        }
                    }
                    if (p.cur != .rparen)
                        return p.lex.bad("expected ')' after the arguments of {s}()", .{name});
                    try p.advance();
                    try p.checkCall(name, args.items.len);
                    return p.node(.{ .call = .{ .name = name, .args = args.items } });
                }
                // Spelled exactly so, as GitHub has them: `TRUE` is a name, and no context.
                const eql = std.mem.eql;
                if (eql(u8, name, "true")) return p.node(.{ .literal = .{ .boolean = true } });
                if (eql(u8, name, "false")) return p.node(.{ .literal = .{ .boolean = false } });
                if (eql(u8, name, "null")) return p.node(.{ .literal = .null });
                if (eql(u8, name, "NaN"))
                    return p.node(.{ .literal = .{ .number = std.math.nan(f64) } });
                if (eql(u8, name, "Infinity"))
                    return p.node(.{ .literal = .{ .number = std.math.inf(f64) } });
                if (p.contexts) |known| if (lookupEntry(known, name) == null and !isGithubContext(name))
                    return p.lex.bad("unrecognized context '{s}'", .{name});
                return p.node(.{ .ident = name });
            },
            else => return p.lex.bad("unexpected token", .{}),
        }
    }
};

/// GitHub's contexts. A name that is neither one of these nor a context the caller supplied is
/// refused when parsing, as GitHub refuses it; one of these the runner does not supply is null.
const github_contexts = [_][]const u8{
    "github", "env",   "vars",   "secrets",  "inputs", "job",
    "jobs",   "steps", "runner", "strategy", "matrix", "needs",
};

fn isGithubContext(name: []const u8) bool {
    for (github_contexts) |c| if (std.ascii.eqlIgnoreCase(c, name)) return true;
    return false;
}

/// `contexts`: what the expression may name (see `Parser.contexts`); null to accept any name.
fn parse(
    arena: Allocator,
    src: []const u8,
    diag: ?*[]const u8,
    contexts: ?[]const Value.Entry,
) Error!*Node {
    var p = try Parser.init(arena, src, diag);
    p.contexts = contexts;
    const n = try p.parseOr();
    try p.expectEnd();
    return n;
}

// --- coercion ---

pub fn toBool(v: Value) bool {
    return switch (v) {
        .null => false,
        .boolean => |b| b,
        .number => |n| n != 0 and !std.math.isNan(n),
        .string => |s| s.len > 0,
        .array, .object => true,
    };
}

pub fn toNumber(v: Value) f64 {
    return switch (v) {
        .null => 0,
        .boolean => |b| if (b) 1 else 0,
        .number => |n| n,
        .string => |s| jsNumber(s),
        .array, .object => std.math.nan(f64),
    };
}

pub fn toStr(arena: Allocator, v: Value) Allocator.Error![]const u8 {
    return switch (v) {
        .null => "",
        .boolean => |b| if (b) "true" else "false",
        .number => |n| numberToString(arena, n),
        .string => |s| s,
        .array => "Array",
        .object => "Object",
    };
}

fn numberToString(arena: Allocator, n: f64) Allocator.Error![]const u8 {
    if (std.math.isNan(n)) return "NaN";
    if (std.math.isInf(n)) return if (n > 0) "Infinity" else "-Infinity";
    if (@floor(n) == n and @abs(n) < 1e15)
        return std.fmt.allocPrint(arena, "{d}", .{@as(i64, @intFromFloat(n))});
    // 15 significant digits, as GitHub prints them: 0.84551240822557006 is "0.84551240822557".
    var buf: [64]u8 = undefined;
    const rounded = std.fmt.parseFloat(f64, std.fmt.bufPrint(&buf, "{e:.14}", .{n}) catch
        unreachable) catch n;
    return std.fmt.allocPrint(arena, "{d}", .{rounded});
}

fn sameKind(a: Value, b: Value) bool {
    return std.meta.activeTag(a) == std.meta.activeTag(b);
}

// --- case-insensitive strings ---
//
// GitHub compares strings as their upper-case forms, code point by code point: 'ü' == 'Ü', all
// three Greek sigmas are equal, and 'a' < '[' (because 'A' < '['). Zig's std has no Unicode case
// mapping, so `upperRune` maps the letters of Latin-1, Latin Extended-A, Greek and Cyrillic; other
// scripts compare as written.

/// The upper-case form of `c`, for the scripts listed above. Only letters that pair one to one:
/// GitHub keeps the dotless ı apart from I, and İ apart from i.
fn upperRune(c: u21) u21 {
    return switch (c) {
        'a'...'z' => c - 32,
        0xE0...0xF6, 0xF8...0xFE => c - 0x20,
        0xFF => 0x178,
        // Latin Extended-A: pairs, upper case first...
        0x100...0x12F, 0x132...0x137, 0x14A...0x177 => c & ~@as(u21, 1),
        // ...or upper case second.
        0x139...0x148, 0x179...0x17E => if (c % 2 == 0) c - 1 else c,
        0x3AC => 0x386,
        0x3AD...0x3AF => c - 37,
        0x3CC => 0x38C,
        0x3CD, 0x3CE => c - 63,
        0x3B1...0x3C1, 0x3C3...0x3CB => c - 0x20,
        0x3C2 => 0x3A3, // final sigma
        0x430...0x44F => c - 0x20,
        0x450...0x45F => c - 0x50,
        0x460...0x481, 0x48A...0x4BF, 0x4D0...0x52F => c & ~@as(u21, 1),
        0x4C1...0x4CE => if (c % 2 == 0) c - 1 else c,
        0x4CF => 0x4C0,
        else => c,
    };
}

/// The code point at `s[i.*]`, upper-cased, advancing `i`. A byte that does not start valid UTF-8
/// stands for itself, above every code point, so that it compares equal only to the same byte.
fn nextUpper(s: []const u8, i: *usize) u32 {
    const len = std.unicode.utf8ByteSequenceLength(s[i.*]) catch 0;
    if (len > 0 and i.* + len <= s.len) {
        if (std.unicode.utf8Decode(s[i.* .. i.* + len])) |c| {
            i.* += len;
            return upperRune(c);
        } else |_| {}
    }
    i.* += 1;
    return 0x110000 + @as(u32, s[i.* - 1]);
}

fn orderFold(a: []const u8, b: []const u8) std.math.Order {
    var i: usize = 0;
    var j: usize = 0;
    while (i < a.len and j < b.len) {
        const x = nextUpper(a, &i);
        const y = nextUpper(b, &j);
        if (x != y) return std.math.order(x, y);
    }
    return std.math.order(a.len - i, b.len - j);
}

fn eqlFold(a: []const u8, b: []const u8) bool {
    return orderFold(a, b) == .eq;
}

/// `s` upper-cased, for searching it case-insensitively.
fn upperAlloc(arena: Allocator, s: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = try .initCapacity(arena, s.len);
    var i: usize = 0;
    while (i < s.len) {
        const start = i;
        const c = nextUpper(s, &i);
        if (c >= 0x110000) {
            try out.append(arena, s[start]);
            continue;
        }
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(@intCast(c), &buf) catch unreachable;
        try out.appendSlice(arena, buf[0..n]);
    }
    return out.items;
}

fn looseEquals(a: Value, b: Value) bool {
    if (sameKind(a, b)) return switch (a) {
        .null => true,
        .boolean => |x| x == b.boolean,
        .number => |x| x == b.number,
        .string => |x| eqlFold(x, b.string),
        // Arrays and objects only equal themselves.
        .array => |x| x.ptr == b.array.ptr and x.len == b.array.len,
        .object => |x| x.ptr == b.object.ptr and x.len == b.object.len,
    };
    const x = toNumber(a);
    const y = toNumber(b);
    return x == y; // NaN never equals anything
}

fn compare(a: Value, b: Value) ?std.math.Order {
    if (a == .string and b == .string) return orderFold(a.string, b.string);
    const x = toNumber(a);
    const y = toNumber(b);
    if (std.math.isNan(x) or std.math.isNan(y)) return null;
    return std.math.order(x, y);
}

// --- evaluation ---

fn lookupEntry(entries: []const Value.Entry, name: []const u8) ?Value {
    for (entries) |e| if (std.ascii.eqlIgnoreCase(e.key, name)) return e.value;
    return null;
}

fn deref(v: Value, key: Value, arena: Allocator) Allocator.Error!Value {
    switch (v) {
        .object => |o| {
            if (key == .array or key == .object) return .null;
            const k = try toStr(arena, key);
            return lookupEntry(o, k) orelse .null;
        },
        .array => |a| return if (arrayIndex(key, a.len)) |i| a[i] else .null,
        else => return .null,
    }
}

/// `key` as an index into an array of `len`, if it is one. null, booleans and strings index as
/// numbers (`a[true]` is `a[1]`), and a fraction is rounded down (`a[1.5]` is `a[1]`), as GitHub
/// does. Bounded before the conversion, which panics on a number no usize holds (`foo[1e30]`,
/// `foo[Infinity]`) and would take the whole runner down with it.
fn arrayIndex(key: Value, len: usize) ?usize {
    if (key == .array or key == .object) return null;
    const n = toNumber(key);
    if (std.math.isNan(n) or n < 0 or @floor(n) >= @as(f64, @floatFromInt(len))) return null;
    return @intFromFloat(@floor(n));
}

/// What a `*` object filter selects: an array's elements, or an object's values. GitHub gives an
/// array either way, and anything else selects nothing. (`filteredArray` copies it.)
fn starValues(arena: Allocator, v: Value) Error![]const Value {
    switch (v) {
        .array => |a| return a,
        .object => |o| {
            const out = try arena.alloc(Value, o.len);
            for (o, 0..) |e, i| out[i] = e.value;
            return out;
        },
        else => return &.{},
    }
}

/// What `.k`, `[k]` or `.*` selects from `o`. A `*` filter's result is marked (`filteredArray`),
/// and whatever follows applies to each of its elements, as GitHub's FilteredArray does:
/// `labels.*.name` is every label's name, `a[*][1]` every element's second, `a.*.*` the elements'
/// elements, also when the filtered array has come through a function (`case(c, a.*, b.*)[0]`).
/// An element that is neither an array nor an object contributes nothing, and neither does one
/// without the key.
fn access(arena: Allocator, o: Value, idx: Index, scope: Scope) Error!Evaluated {
    if (!isFiltered(scope, o)) switch (idx) {
        // GitHub counts the new array as an object and a pointer per element.
        .star => {
            const items = try starValues(arena, o);
            const bytes = if (o == .array or o == .object) min_object_size + pointer_size * items.len else null;
            if ((bytes orelse 0) > max_memory) return scope.tooMuchMemory(arena);
            return .{ .v = try filteredArray(arena, scope, items), .bytes = bytes };
        },
        .key => |k| return .{ .v = try deref(o, k, arena), .data = true },
    };
    var out: std.ArrayList(Value) = .empty;
    for (o.array) |item| switch (item) {
        .object => |entries| switch (idx) {
            .star => for (entries) |e| try out.append(arena, e.value),
            .key => |k| if (isPrimitive(k)) {
                if (lookupEntry(entries, try toStr(arena, k))) |v| try out.append(arena, v);
            },
        },
        .array => |a| switch (idx) {
            .star => try out.appendSlice(arena, a),
            .key => |k| if (arrayIndex(k, a.len)) |i| try out.append(arena, a[i]),
        },
        else => {},
    };
    // A pointer per element; no object, as GitHub counts it for a filter of a filter.
    if (pointer_size * out.items.len > max_memory) return scope.tooMuchMemory(arena);
    return .{ .v = try filteredArray(arena, scope, out.items), .bytes = pointer_size * out.items.len };
}

const Index = union(enum) { star, key: Value };

/// The arrays this evaluation's filters made, by address.
const Filtered = std.AutoHashMapUnmanaged(usize, void);

/// `items` as a filter's result: copied into an allocation of its own (empty ones too, so that
/// the address is its own) and remembered as filtered.
fn filteredArray(arena: Allocator, scope: Scope, items: []const Value) Error!Value {
    const out = (try arena.alloc(Value, @max(items.len, 1)))[0..items.len];
    @memcpy(out, items);
    if (scope.filtered) |f| try f.put(arena, @intFromPtr(out.ptr), {});
    return .{ .array = out };
}

fn isFiltered(scope: Scope, v: Value) bool {
    const f = scope.filtered orelse return false;
    return v == .array and f.contains(@intFromPtr(v.array.ptr));
}

/// A chain of `&&` (or of `||`), operand by operand from the left, without recursing down it: a
/// chain of any length is depth 2 to GitHub, but `a || b || c` is parsed as `(a || b) || c`.
/// `&&` returns the first falsy operand or the last; `||` the first truthy one or the last.
fn evalChain(arena: Allocator, n: *const Node, scope: Scope, level: usize) Error!Value {
    const op = n.bin.op;
    var rights: std.ArrayList(*const Node) = .empty;
    var left = n;
    while (left.* == .bin and left.bin.op == op) : (left = left.bin.l)
        try rights.append(arena, left.bin.r);
    var v = try eval(arena, left, scope, level + 1);
    var i = rights.items.len;
    while (i > 0) {
        if (toBool(v) == (op == .or_)) return v;
        i -= 1;
        v = try eval(arena, rights.items[i], scope, level + 1);
    }
    return v;
}

/// `n`, at `level` in the tree (the root is 0), counted against the evaluation's memory.
fn eval(arena: Allocator, n: *const Node, scope: Scope, level: usize) Error!Value {
    const r = try evalNode(arena, n, scope, level);
    try scope.account(arena, level, r);
    return r.v;
}

fn evalNode(arena: Allocator, n: *const Node, scope: Scope, level: usize) Error!Evaluated {
    switch (n.*) {
        .literal => |v| return .{ .v = v },
        .ident => |name| {
            for (scope.unsupported_contexts) |u| if (std.ascii.eqlIgnoreCase(u, name)) {
                if (scope.diag) |d| d.* = std.fmt.allocPrint(
                    arena,
                    "the '{s}' context is not supported yet",
                    .{name},
                ) catch return error.OutOfMemory;
                return error.Unsupported;
            };
            return .{ .v = lookupEntry(scope.contexts, name) orelse .null, .data = true };
        },
        // An index evaluates what it indexes first, and the index only when that is an array or an
        // object (GitHub's `Index`): `null[fromJSON('{')]` is null, not an error.
        .prop => |p| {
            const o = try eval(arena, p.obj, scope, level + 1);
            if (!isCollection(o)) return .{ .v = .null };
            // GitHub's `a.b` is an index with the literal 'b', evaluated (and counted) after `a`.
            const key: Value = .{ .string = p.name };
            try scope.account(arena, level + 1, .{ .v = key });
            return access(arena, o, .{ .key = key }, scope);
        },
        .index => |ix| {
            const o = try eval(arena, ix.obj, scope, level + 1);
            if (!isCollection(o)) return .{ .v = .null };
            const k = try eval(arena, ix.idx, scope, level + 1);
            return access(arena, o, .{ .key = k }, scope);
        },
        .star => |inner| {
            const o = try eval(arena, inner, scope, level + 1);
            // Not a collection: an empty filter, as GitHub's `Index` makes.
            if (!isCollection(o)) return access(arena, o, .star, scope);
            // The `*` is a node of its own to GitHub, which evaluates to the string "*".
            try scope.account(arena, level + 1, .{ .v = .{ .string = "*" } });
            return access(arena, o, .star, scope);
        },
        .not => |inner| return .{ .v = .{ .boolean = !toBool(try eval(arena, inner, scope, level + 1)) } },
        .bin => |b| {
            if (b.op == .and_ or b.op == .or_) return .{ .v = try evalChain(arena, n, scope, level) };
            const l = try eval(arena, b.l, scope, level + 1);
            const r = try eval(arena, b.r, scope, level + 1);
            return .{
                .v = .{
                    .boolean = switch (b.op) {
                        .eq => looseEquals(l, r),
                        .ne => !looseEquals(l, r),
                        .lt => if (compare(l, r)) |o| o == .lt else false,
                        // `a <= b` is `a == b || a < b` to GitHub: an array is <= itself.
                        .le => looseEquals(l, r) or if (compare(l, r)) |o| o == .lt else false,
                        .gt => if (compare(l, r)) |o| o == .gt else false,
                        .ge => looseEquals(l, r) or if (compare(l, r)) |o| o == .gt else false,
                        else => unreachable,
                    },
                },
            };
        },
        .call => |c| {
            const v = try callFunction(arena, c.name, c.args, scope, level);
            // fromJSON makes context data, as a context holds; the other functions plain values.
            return .{ .v = v, .data = std.ascii.eqlIgnoreCase(c.name, "fromJSON") };
        },
    }
}

fn callFunction(arena: Allocator, name: []const u8, arg_nodes: []*Node, scope: Scope, level: usize) Error!Value {
    const eql = std.ascii.eqlIgnoreCase;
    if (statusFunction(name, scope)) |v| return v;
    if (eql(name, "hashFiles") and scope.hash_files == null) {
        if (scope.diag) |d| d.* = "hashFiles() is not supported here";
        return error.Unsupported;
    }

    // These two evaluate their arguments as they need them, as GitHub's runner does: an argument
    // they do not use is never evaluated, so an error in it is no error.
    if (eql(name, "case")) return callCase(arena, arg_nodes, scope, level);
    if (eql(name, "format")) {
        const fmt = try toStr(arena, try eval(arena, arg_nodes[0], scope, level + 1));
        return .{ .string = try formatString(arena, fmt, arg_nodes[1..], scope, level) };
    }

    const args = try arena.alloc(Value, arg_nodes.len);
    for (arg_nodes, args) |an, *out| out.* = try eval(arena, an, scope, level + 1);

    if (eql(name, "hashFiles")) return callHashFiles(arena, args, scope);
    if (eql(name, "contains")) return callContains(arena, args, scope);
    if (eql(name, "startsWith") or eql(name, "endsWith")) {
        if (args.len != 2) return scope.fail("{s}() takes 2 arguments", .{name}, arena);
        if (!isPrimitive(args[0]) or !isPrimitive(args[1])) return .{ .boolean = false };
        const s = try upperAlloc(arena, try toStr(arena, args[0]));
        const t = try upperAlloc(arena, try toStr(arena, args[1]));
        return .{ .boolean = if (eql(name, "startsWith"))
            std.mem.startsWith(u8, s, t)
        else
            std.mem.endsWith(u8, s, t) };
    }
    if (eql(name, "join")) return callJoin(arena, args, scope);
    if (eql(name, "toJSON")) return callToJson(arena, args, scope);
    if (eql(name, "fromJSON")) return callFromJson(arena, args, scope);
    return scope.fail("unknown function '{s}'", .{name}, arena);
}

/// `case(pred1, value1, pred2, value2, ..., default)`: the value after the first true predicate,
/// else the default. As GitHub's runner does it (`Case`): predicates in turn, each of which must be
/// a boolean, and then only the value chosen; the others are never evaluated. (The parser has
/// checked that there is an odd number of arguments.)
fn callCase(arena: Allocator, arg_nodes: []*Node, scope: Scope, level: usize) Error!Value {
    var i: usize = 0;
    while (i + 1 < arg_nodes.len) : (i += 2) {
        switch (try eval(arena, arg_nodes[i], scope, level + 1)) {
            .boolean => |b| if (b) return eval(arena, arg_nodes[i + 1], scope, level + 1),
            else => return scope.fail("case(): a predicate must be true or false", .{}, arena),
        }
    }
    return eval(arena, arg_nodes[arg_nodes.len - 1], scope, level + 1);
}

/// `success()`, `always()`, `cancelled()`, `failure()`: the job's state, no arguments evaluated.
fn statusFunction(name: []const u8, scope: Scope) ?Value {
    const eql = std.ascii.eqlIgnoreCase;
    if (eql(name, "success")) return .{ .boolean = !scope.job_failed and !scope.cancelled };
    if (eql(name, "always")) return .{ .boolean = true };
    if (eql(name, "cancelled")) return .{ .boolean = scope.cancelled };
    if (eql(name, "failure")) return .{ .boolean = scope.job_failed and !scope.cancelled };
    return null;
}

fn callHashFiles(arena: Allocator, args: []const Value, scope: Scope) Error!Value {
    if (args.len < 1) return scope.fail("hashFiles() takes at least 1 argument", .{}, arena);
    const patterns = try arena.alloc([]const u8, args.len);
    for (args, patterns) |a, *dst| dst.* = try toStr(arena, a);
    const hf = scope.hash_files.?;
    return switch (try hf.hashFn(hf.ptr, arena, patterns)) {
        .ok => |hex| .{ .string = hex },
        .failed => |why| scope.fail(
            "hashFiles({s}) failed: {s}",
            .{ try std.mem.join(arena, ", ", patterns), why },
            arena,
        ),
    };
}

/// Not an array or an object. The string functions are false for anything else, as GitHub's are.
fn isPrimitive(v: Value) bool {
    return v != .array and v != .object;
}

/// What an index looks into: an array (a `*` filter's result too) or an object.
fn isCollection(v: Value) bool {
    return !isPrimitive(v);
}

fn callContains(arena: Allocator, args: []const Value, scope: Scope) Error!Value {
    if (args.len != 2) return scope.fail("contains() takes 2 arguments", .{}, arena);
    switch (args[0]) {
        .array => |a| {
            for (a) |e| if (looseEquals(e, args[1])) return .{ .boolean = true };
            return .{ .boolean = false };
        },
        .object => return .{ .boolean = false },
        else => {
            if (!isPrimitive(args[1])) return .{ .boolean = false };
            const hay = try upperAlloc(arena, try toStr(arena, args[0]));
            const needle = try upperAlloc(arena, try toStr(arena, args[1]));
            return .{ .boolean = std.mem.indexOf(u8, hay, needle) != null };
        },
    }
}

/// `join()`, as GitHub's runner does it (`Join`): each element and each separator is counted as
/// it is appended, as a string of its own (`countString`), against `max_memory`, so a result GitHub
/// would refuse is refused before it is built, however many elements and however long the
/// separator.
fn callJoin(arena: Allocator, args: []const Value, scope: Scope) Error!Value {
    if (args.len < 1 or args.len > 2)
        return scope.fail("join() takes 1 or 2 arguments", .{}, arena);
    // An array or object as the separator is no separator, so the default.
    const sep = if (args.len == 2 and args[1] != .array and args[1] != .object)
        try toStr(arena, args[1])
    else
        ",";
    switch (args[0]) {
        .object => return .{ .string = "" },
        .array => |a| {
            var out: std.ArrayList(u8) = .empty;
            var counted: usize = 0;
            for (a, 0..) |e, i| {
                if (i > 0) {
                    try countString(&counted, sep, scope, arena);
                    try out.appendSlice(arena, sep);
                }
                const item = try toStr(arena, e);
                try countString(&counted, item, scope, arena);
                try out.appendSlice(arena, item);
            }
            return .{ .string = out.items };
        },
        else => return .{ .string = try toStr(arena, args[0]) },
    }
}

fn callToJson(arena: Allocator, args: []const Value, scope: Scope) Error!Value {
    if (args.len != 1) return scope.fail("toJSON() takes 1 argument", .{}, arena);
    var j: JsonOut = .{ .aw = .init(arena), .scope = scope, .arena = arena };
    try writeJson(&j, args[0], 0);
    return .{ .string = j.aw.written() };
}

fn callFromJson(arena: Allocator, args: []const Value, scope: Scope) Error!Value {
    if (args.len != 1) return scope.fail("fromJSON() takes 1 argument", .{}, arena);
    const text = try toStr(arena, args[0]);
    if (jsonNesting(text) > max_json_nesting)
        return scope.fail("fromJSON(): nested more than {d} deep", .{max_json_nesting}, arena);
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return scope.fail("fromJSON(): invalid JSON", .{}, arena),
    };
    return fromJsonValue(arena, parsed);
}

/// The deepest nesting of arrays and objects in JSON text (outside strings), without parsing it.
fn jsonNesting(text: []const u8) usize {
    var depth: usize = 0;
    var deepest: usize = 0;
    var in_string = false;
    var escaped = false;
    for (text) |c| {
        if (in_string) {
            if (escaped) escaped = false else if (c == '\\') escaped = true else if (c == '"') in_string = false;
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '[', '{' => {
                depth += 1;
                deepest = @max(deepest, depth);
            },
            ']', '}' => depth -|= 1,
            else => {},
        }
    }
    return deepest;
}

/// `format()`, as GitHub's runner does it (`Format`): the format string is read first, whole, and
/// a mistake in it is an error before any argument is evaluated; then the pieces are put
/// together, each argument evaluated the first time a placeholder needs it (and only then: an
/// argument no placeholder uses is never evaluated). What it builds is counted as it goes, as
/// `Format` counts it: each piece of the format string between placeholders (an escaped brace ends
/// one) as the string is read, then each argument where it is placed, as a string of its own
/// (`costOf`), against `max_memory`.
fn formatString(
    arena: Allocator,
    fmt: []const u8,
    arg_nodes: []*Node,
    scope: Scope,
    level: usize,
) Error![]const u8 {
    const Piece = union(enum) { text: []const u8, arg: usize };
    var pieces: std.ArrayList(Piece) = .empty;
    var counted: usize = 0;
    // Where the piece of the format string being read began.
    var piece: usize = 0;
    var i: usize = 0;
    while (i < fmt.len) {
        const c = fmt[i];
        if (c == '{') {
            if (i + 1 < fmt.len and fmt[i + 1] == '{') {
                // The piece takes one of the two braces.
                try pieces.append(arena, .{ .text = fmt[piece .. i + 1] });
                try countPiece(&counted, fmt[piece .. i + 1], scope, arena);
                i += 2;
                piece = i;
                continue;
            }
            const close = std.mem.indexOfScalarPos(u8, fmt, i, '}') orelse
                return scope.fail("format(): unterminated '{{' in '{s}'", .{fmt}, arena);
            const placeholder = fmt[i .. close + 1];
            const idx = std.fmt.parseInt(usize, fmt[i + 1 .. close], 10) catch
                return scope.fail("format(): invalid placeholder '{s}'", .{placeholder}, arena);
            if (idx >= arg_nodes.len)
                return scope.fail("format(): placeholder {{{d}}} has no argument", .{idx}, arena);
            if (i > piece) {
                try pieces.append(arena, .{ .text = fmt[piece..i] });
                try countPiece(&counted, fmt[piece..i], scope, arena);
            }
            try pieces.append(arena, .{ .arg = idx });
            i = close + 1;
            piece = i;
        } else if (c == '}') {
            if (i + 1 < fmt.len and fmt[i + 1] == '}') {
                try pieces.append(arena, .{ .text = fmt[piece .. i + 1] });
                try countPiece(&counted, fmt[piece .. i + 1], scope, arena);
                i += 2;
                piece = i;
                continue;
            }
            return scope.fail("format(): unmatched '}}' in '{s}'", .{fmt}, arena);
        } else i += 1;
    }
    if (piece < fmt.len) {
        try pieces.append(arena, .{ .text = fmt[piece..] });
        try countPiece(&counted, fmt[piece..], scope, arena);
    }

    const evaluated = try arena.alloc(?[]const u8, arg_nodes.len);
    @memset(evaluated, null);
    var out: std.ArrayList(u8) = .empty;
    for (pieces.items) |p| switch (p) {
        .text => |t| try out.appendSlice(arena, t),
        .arg => |a| {
            if (evaluated[a] == null)
                evaluated[a] = try toStr(arena, try eval(arena, arg_nodes[a], scope, level + 1));
            try countPiece(&counted, evaluated[a].?, scope, arena);
            try out.appendSlice(arena, evaluated[a].?);
        },
    };
    return out.items;
}

/// One piece of `format()`'s result, counted as GitHub's `MemoryCounter.Add` counts it (an empty
/// one is not).
fn countPiece(counted: *usize, text: []const u8, scope: Scope, arena: Allocator) Error!void {
    if (text.len == 0) return;
    return countString(counted, text, scope, arena);
}

/// A string a function builds its result from, counted as `MemoryCounter.Add(String)` counts it
/// (an empty one too), against `max_memory`.
fn countString(counted: *usize, text: []const u8, scope: Scope, arena: Allocator) Error!void {
    counted.* += costOf(.{ .string = text });
    if (counted.* > max_memory) return scope.tooMuchMemory(arena);
}

/// What `toJSON()` writes, counted as GitHub's runner counts it (`ToJson`): in pieces, each a
/// string of its own (`costOf`) against `max_memory`. A piece is a value, an array's or object's
/// opening bracket, or a key, each with what goes before it (`,` and a new line and the
/// indentation, or `: ` before a key's value), or a closing bracket with the new line and
/// indentation before it. The current piece is checked before each part of it is written, so the
/// indentation of something nested deep is refused before it is written, and so is what follows
/// once the pieces add up to more than GitHub allows.
const JsonOut = struct {
    aw: std.Io.Writer.Allocating,
    scope: Scope,
    arena: Allocator,
    /// The pieces before the current one.
    counted: usize = 0,
    /// UTF-16 code units in the current piece so far.
    units: usize = 0,

    /// Fails when `units` more in the current piece would make it too much.
    fn room(j: *JsonOut, units: usize) Error!void {
        if (j.counted + string_overhead + 2 * (j.units + units) > max_memory)
            return j.scope.tooMuchMemory(j.arena);
    }

    fn put(j: *JsonOut, bytes: []const u8) Error!void {
        const units = utf16Len(bytes);
        try j.room(units);
        j.aw.writer.writeAll(bytes) catch return error.OutOfMemory; // Allocating writer: only OOM
        j.units += units;
    }

    fn indent(j: *JsonOut, n: usize) Error!void {
        try j.room(n);
        j.aw.writer.splatByteAll(' ', n) catch return error.OutOfMemory;
        j.units += n;
    }

    /// A string, quoted and escaped: at least its own length and the quotes, checked before it is
    /// written, and what escaping it took, after.
    fn str(j: *JsonOut, s: []const u8) Error!void {
        try j.room(utf16Len(s) + 2);
        const start = j.aw.written().len;
        std.json.Stringify.value(s, .{}, &j.aw.writer) catch return error.OutOfMemory;
        try j.wrote(start);
    }

    /// Counts what was written since `start` (something short: a number).
    fn wrote(j: *JsonOut, start: usize) Error!void {
        const units = utf16Len(j.aw.written()[start..]);
        try j.room(units);
        j.units += units;
    }

    /// Ends the current piece.
    fn cut(j: *JsonOut) void {
        j.counted += string_overhead + 2 * j.units;
        j.units = 0;
    }
};

fn writeJson(j: *JsonOut, v: Value, depth: usize) Error!void {
    switch (v) {
        .null => try j.put("null"),
        .boolean => |b| try j.put(if (b) "true" else "false"),
        // JSON has no NaN or Infinity; GitHub writes null, as JavaScript's JSON.stringify does.
        .number => |n| if (!std.math.isFinite(n)) try j.put("null") else {
            const start = j.aw.written().len;
            const w = &j.aw.writer;
            (if (@floor(n) == n and @abs(n) < 1e15)
                w.print("{d}", .{@as(i64, @intFromFloat(n))})
            else
                w.print("{d}", .{n})) catch return error.OutOfMemory;
            try j.wrote(start);
        },
        .string => |s| try j.str(s),
        .array => |a| {
            if (a.len == 0) return j.put("[]");
            try j.put("[");
            for (a, 0..) |e, i| {
                j.cut();
                try j.put(if (i == 0) "\n" else ",\n");
                try j.indent((depth + 1) * 2);
                try writeJson(j, e, depth + 1);
            }
            j.cut();
            try j.put("\n");
            try j.indent(depth * 2);
            try j.put("]");
        },
        .object => |o| {
            if (o.len == 0) return j.put("{}");
            try j.put("{");
            for (o, 0..) |e, i| {
                j.cut();
                try j.put(if (i == 0) "\n" else ",\n");
                try j.indent((depth + 1) * 2);
                try j.str(e.key);
                j.cut();
                try j.put(": ");
                try writeJson(j, e.value, depth + 1);
            }
            j.cut();
            try j.put("\n");
            try j.indent(depth * 2);
            try j.put("}");
        },
    }
}

pub fn fromJsonValue(arena: Allocator, j: std.json.Value) Allocator.Error!Value {
    return fromJsonDepth(arena, j, 0);
}

/// How deeply converted values may nest: the conversion recurses per level, and 200000 levels of
/// context data overflowed the stack (#98). `fromJSON` refuses deeper input first (`max_json_nesting`,
/// the same bound); what comes deeper from elsewhere (GitHub's job message) is null past it.
pub const max_value_nesting = 1000;

fn fromJsonDepth(arena: Allocator, j: std.json.Value, depth: u32) Allocator.Error!Value {
    if (depth >= max_value_nesting) return .null;
    switch (j) {
        .null => return .null,
        .bool => |b| return .{ .boolean = b },
        .integer => |i| return .{ .number = @floatFromInt(i) },
        .float => |f| return .{ .number = f },
        .number_string => |s| return .{ .number = std.fmt.parseFloat(f64, s) catch
            std.math.nan(f64) },
        .string => |s| return .{ .string = s },
        // Allocated even when empty, so that two empty ones are two values: arrays and objects
        // only equal themselves, and zero-length slices could share an address.
        .array => |a| {
            const out = (try arena.alloc(Value, @max(a.items.len, 1)))[0..a.items.len];
            for (a.items, out) |e, *o| o.* = try fromJsonDepth(arena, e, depth + 1);
            return .{ .array = out };
        },
        .object => |o| {
            const out = (try arena.alloc(Value.Entry, @max(o.count(), 1)))[0..o.count()];
            var it = o.iterator();
            var i: usize = 0;
            while (it.next()) |e| : (i += 1) out[i] = .{
                .key = e.key_ptr.*,
                .value = try fromJsonDepth(arena, e.value_ptr.*, depth + 1),
            };
            return .{ .object = out };
        },
    }
}

// --- public API ---

/// Evaluates one expression (the text inside `${{ }}`).
pub fn evaluate(arena: Allocator, text: []const u8, scope: Scope) Error!Value {
    // GitHub evaluates an empty expression to null.
    if (std.mem.trim(u8, text, " \t\r\n").len == 0) return .null;
    const n = try parse(arena, text, scope.diag, scope.contexts);
    var memory: Memory = .{};
    var filtered: Filtered = .empty;
    var s = scope;
    if (s.memory == null) s.memory = &memory;
    if (s.filtered == null) s.filtered = &filtered;
    return eval(arena, n, s, 0) catch |e| switch (e) {
        error.Unsupported => {
            if (scope.diag) |d| if (d.*.len == 0) {
                d.* = "the '*' object filter is not supported yet";
            };
            return e;
        },
        else => return e,
    };
}

pub fn evalString(arena: Allocator, text: []const u8, scope: Scope) Error![]const u8 {
    return toStr(arena, try evaluate(arena, text, scope));
}

/// Replaces every `${{ <expression> }}` in `text` with its value as a string. The job message
/// arrives with this already done (as `format()` expressions), but `action.yml` files are read as
/// they are written. A `}}` inside a quoted string does not end the expression.
///
/// Unless the text is one expression alone, GitHub's runner makes it one `format()` expression
/// (`TemplateReader`: the text between the expressions, its braces doubled, is the format string,
/// and the expressions are its arguments), so what it builds is limited as `format()` limits its
/// result: the pieces of text (cut after each brace, as an escaped brace cuts a format string),
/// then each expression's value, counted as `formatString` counts them, against
/// `template_max_memory`. Each expression is evaluated in scratch memory that the next one
/// reuses, so neither many results nor many expressions that build something large on the way to
/// a short result add up.
pub fn interpolate(arena: Allocator, text: []const u8, scope: Scope) Error![]const u8 {
    if (std.mem.indexOf(u8, text, "${{") == null) return text;
    // Each expression, and the text before it.
    const Segment = struct { before: []const u8, body: []const u8 };
    var segments: std.ArrayList(Segment) = .empty;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, text, i, "${{")) |open| {
        const body_start = open + 3;
        const close = expressionEnd(text, body_start) orelse {
            if (scope.diag) |d| d.* = "'${{' is never closed with '}}'";
            return error.ParseError;
        };
        try segments.append(arena, .{ .before = text[i..open], .body = text[body_start..close] });
        i = close + 2;
    }
    const after = text[i..];
    const alone = segments.items.len == 1 and segments.items[0].before.len == 0 and after.len == 0;

    // The format string is read first, whole, as `formatString` reads it.
    var counted: usize = 0;
    if (!alone) {
        for (segments.items) |seg| try countTemplateText(&counted, seg.before, scope, arena);
        try countTemplateText(&counted, after, scope, arena);
    }
    var scratch: std.heap.ArenaAllocator = .init(arena);
    defer scratch.deinit();
    var out: std.ArrayList(u8) = .empty;
    for (segments.items) |seg| {
        try out.appendSlice(arena, seg.before);
        _ = scratch.reset(.retain_capacity);
        const value = evalString(scratch.allocator(), seg.body, scope) catch |e| {
            // The reason outlives the scratch memory it may be in.
            if (scope.diag) |d| d.* = try arena.dupe(u8, d.*);
            return e;
        };
        if (!alone) try countTemplatePiece(&counted, value, scope, arena);
        try out.appendSlice(arena, value);
    }
    try out.appendSlice(arena, after);
    return out.items;
}

/// The memory GitHub's runner lets it use reading an `action.yml` (`ActionManifestManager`'s
/// `TemplateMemory`), which is also the limit on each expression it evaluates there
/// (`TemplateToken.EvaluateStringToken`): 10 MiB. An interpolated text's pieces are counted
/// against it.
const template_max_memory = 10 * 1024 * 1024;

/// Text between expressions, in the pieces a format string has once its braces are doubled.
fn countTemplateText(counted: *usize, text: []const u8, scope: Scope, arena: Allocator) Error!void {
    var start: usize = 0;
    for (text, 0..) |c, k| if (c == '{' or c == '}') {
        try countTemplatePiece(counted, text[start .. k + 1], scope, arena);
        start = k + 1;
    };
    try countTemplatePiece(counted, text[start..], scope, arena);
}

/// One piece of an interpolated text, counted as `countPiece` counts it.
fn countTemplatePiece(counted: *usize, text: []const u8, scope: Scope, arena: Allocator) Error!void {
    if (text.len == 0) return;
    counted.* += costOf(.{ .string = text });
    if (counted.* > template_max_memory) return scope.fail(
        "the text needs more than the {d} bytes of memory GitHub allows",
        .{template_max_memory},
        arena,
    );
}

/// Index of the `}}` that ends the expression starting at `from`, skipping 'quoted' strings.
fn expressionEnd(text: []const u8, from: usize) ?usize {
    var i = from;
    var in_str = false;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (in_str) {
            if (c == '\'') {
                if (i + 1 < text.len and text[i + 1] == '\'') i += 1 else in_str = false;
            }
        } else if (c == '\'') {
            in_str = true;
        } else if (c == '}' and i + 1 < text.len and text[i + 1] == '}') {
            return i;
        }
    }
    return null;
}

/// Whether an `if:` expression calls success(), always(), failure() or cancelled(). Running out of
/// memory is an error, not "no": read as one, `always()` after a failed step skipped the step.
pub fn hasStatusFunction(arena: Allocator, text: []const u8) Allocator.Error!bool {
    const n = parse(arena, text, null, null) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    return nodeHasStatus(n);
}

fn nodeHasStatus(n: *const Node) bool {
    return switch (n.*) {
        .call => |c| blk: {
            for ([_][]const u8{ "success", "always", "failure", "cancelled" }) |f|
                if (std.ascii.eqlIgnoreCase(c.name, f)) break :blk true;
            for (c.args) |a| if (nodeHasStatus(a)) break :blk true;
            break :blk false;
        },
        .not => |i| nodeHasStatus(i),
        .bin => |b| nodeHasStatus(b.l) or nodeHasStatus(b.r),
        .prop => |p| nodeHasStatus(p.obj),
        .index => |ix| nodeHasStatus(ix.obj) or nodeHasStatus(ix.idx),
        .star => |i| nodeHasStatus(i),
        else => false,
    };
}

/// Evaluates an `if:` condition. A condition without a status function is implicitly
/// `success() && (<condition>)`, as in GitHub. `${{ }}` around the whole condition is optional.
pub fn evalCondition(arena: Allocator, cond: []const u8, scope: Scope) Error!bool {
    var text = std.mem.trim(u8, cond, " \t\r\n");
    if (std.mem.startsWith(u8, text, "${{") and std.mem.endsWith(u8, text, "}}"))
        text = std.mem.trim(u8, text[3 .. text.len - 2], " \t\r\n");
    if (text.len == 0) return !scope.job_failed and !scope.cancelled;
    const v = try evaluate(arena, text, scope);
    if (!try hasStatusFunction(arena, text) and (scope.job_failed or scope.cancelled)) return false;
    return toBool(v);
}

// --- tests ---

fn tctx(entries: []const Value.Entry) Scope {
    return .{ .contexts = entries };
}

fn evalStr(arena: Allocator, text: []const u8, scope: Scope) ![]const u8 {
    return evalString(arena, text, scope);
}

test "literals and coercion" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const s: Scope = .{};
    try std.testing.expectEqualStrings("hello", try evalStr(a.allocator(), "'hello'", s));
    try std.testing.expectEqualStrings("it's", try evalStr(a.allocator(), "'it''s'", s));
    try std.testing.expectEqualStrings("42", try evalStr(a.allocator(), "42", s));
    try std.testing.expectEqualStrings("-3.5", try evalStr(a.allocator(), "-3.5", s));
    try std.testing.expectEqualStrings("255", try evalStr(a.allocator(), "0xff", s));
    try std.testing.expectEqualStrings("true", try evalStr(a.allocator(), "true", s));
    // Keywords are spelled exactly so: `TRUE` is a name, and no context.
    try std.testing.expectError(error.ParseError, evaluate(a.allocator(), "TRUE", s));
    try std.testing.expectEqualStrings("", try evalStr(a.allocator(), "null", s));
}

test "operators follow GitHub's loose comparison" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    try std.testing.expect(try evalCondition(ar, "'ABC' == 'abc'", s)); // case-insensitive
    try std.testing.expect(try evalCondition(ar, "1 == '1'", s)); // string -> number
    try std.testing.expect(try evalCondition(ar, "null == 0", s));
    try std.testing.expect(try evalCondition(ar, "true == 1", s));
    try std.testing.expect(!(try evalCondition(ar, "'a' == 'b'", s)));
    try std.testing.expect(try evalCondition(ar, "'a' != 'b'", s));
    try std.testing.expect(try evalCondition(ar, "2 > 1 && 1 >= 1 && 1 < 2 && 2 <= 2", s));
    try std.testing.expect(try evalCondition(ar, "'b' > 'A'", s));
    try std.testing.expect(!(try evalCondition(ar, "NaN == NaN", s)));
    try std.testing.expect(!(try evalCondition(ar, "'x' > 1", s))); // NaN comparison is false
    try std.testing.expect(try evalCondition(ar, "!false", s));
    try std.testing.expect(try evalCondition(ar, "!(1 == 2)", s));
}

test "&& and || return operands" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    try std.testing.expectEqualStrings("fallback", try evalStr(ar, "'' || 'fallback'", s));
    try std.testing.expectEqualStrings("first", try evalStr(ar, "'first' || 'second'", s));
    try std.testing.expectEqualStrings("second", try evalStr(ar, "'first' && 'second'", s));
    try std.testing.expectEqualStrings("0", try evalStr(ar, "0 && 'x'", s));
    try std.testing.expectEqualStrings("", try evalStr(ar, "null || null", s));
    // short-circuit: the right side would be an error
    try std.testing.expectEqualStrings("ok", try evalStr(ar, "'ok' || fromJSON('{')", s));
}

test "contexts, properties and indexing" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const matrix = [_]Value.Entry{ .{ .key = "os", .value = .{ .string = "linux" } }, .{ .key = "node", .value = .{ .number = 20 } } };
    const list = [_]Value{ .{ .string = "a" }, .{ .string = "b" } };
    const gh = [_]Value.Entry{ .{ .key = "Repository", .value = .{ .string = "o/r" } }, .{ .key = "list", .value = .{ .array = &list } } };
    const ctxs = [_]Value.Entry{ .{ .key = "github", .value = .{ .object = &gh } }, .{ .key = "matrix", .value = .{ .object = &matrix } } };
    const s = tctx(&ctxs);
    try std.testing.expectEqualStrings("o/r", try evalStr(ar, "github.repository", s)); // case-insensitive
    try std.testing.expectEqualStrings("o/r", try evalStr(ar, "GITHUB['REPOSITORY']", s));
    try std.testing.expectEqualStrings("linux", try evalStr(ar, "matrix.os", s));
    try std.testing.expectEqualStrings("20", try evalStr(ar, "matrix['node']", s));
    try std.testing.expectEqualStrings("b", try evalStr(ar, "github.list[1]", s));
    try std.testing.expectEqualStrings("", try evalStr(ar, "github.list[5]", s));
    // Numbers no index can be: once a panic that stopped the runner.
    try std.testing.expectEqualStrings("", try evalStr(ar, "github.list[1e30]", s));
    try std.testing.expectEqualStrings("", try evalStr(ar, "github.list[Infinity]", s));
    try std.testing.expectEqualStrings("", try evalStr(ar, "github.missing.deeper.still", s)); // null propagates
    // A GitHub context the caller did not supply is null; a name that is no context is refused.
    try std.testing.expectEqualStrings("", try evalStr(ar, "matrix.x", s));
    try std.testing.expectError(error.ParseError, evaluate(ar, "nosuchcontext.x", s));
    try std.testing.expectEqualStrings("", try evalStr(ar, "", s));
    try std.testing.expect(try evalCondition(ar, "github.repository == 'O/R' && matrix.os == 'linux'", s));
}

test "the * object filter selects from arrays and objects, and maps through properties" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    // Two labels with a name, one without: GitHub's canonical case is
    // `contains(github.event.issue.labels.*.name, 'bug')`.
    const bug = [_]Value.Entry{ .{ .key = "name", .value = .str("bug") }, .{ .key = "color", .value = .str("red") } };
    const docs = [_]Value.Entry{.{ .key = "name", .value = .str("docs") }};
    const nameless = [_]Value.Entry{.{ .key = "color", .value = .str("blue") }};
    const labels = [_]Value{ .{ .object = &bug }, .{ .object = &docs }, .{ .object = &nameless } };

    // An object to filter the values of, and a nested one to filter through twice.
    const inner = [_]Value.Entry{.{ .key = "id", .value = .{ .number = 7 } }};
    const services = [_]Value.Entry{
        .{ .key = "postgres", .value = .{ .object = &inner } },
        .{ .key = "redis", .value = .{ .object = &inner } },
    };

    const ctxs = [_]Value.Entry{
        .{ .key = "labels", .value = .{ .array = &labels } },
        .{ .key = "services", .value = .{ .object = &services } },
        .{ .key = "plain", .value = .str("text") },
    };
    const s = tctx(&ctxs);

    // Over an array of objects, and usable by `contains`, which is the point of the feature.
    try std.testing.expectEqualStrings("bug docs", try evalStr(ar, "join(labels.*.name, ' ')", s));
    try std.testing.expect(try evalCondition(ar, "contains(labels.*.name, 'bug')", s));
    try std.testing.expect(!(try evalCondition(ar, "contains(labels.*.name, 'nope')", s)));
    // An element without the property contributes nothing: three labels, two names.
    try std.testing.expectEqualStrings("[\n  \"bug\",\n  \"docs\"\n]", try evalStr(ar, "toJSON(labels.*.name)", s));

    // Over an object, `*` selects its values — `job.services.*.id` is GitHub's example.
    try std.testing.expectEqualStrings("7 7", try evalStr(ar, "join(services.*.id, ' ')", s));

    // The filter is recognised from the expression's shape, not the value's: a property of a plain
    // array is still null, which is what it is on GitHub.
    try std.testing.expectEqualStrings("", try evalStr(ar, "labels.name", s));
    // An index after a filter applies to each element, as GitHub's cases have it (`foo[*][1]`):
    // here to each name, and a string has no elements.
    try std.testing.expectEqualStrings("[]", try evalStr(ar, "toJSON(labels.*.name[1])", s));
    try std.testing.expectEqualStrings("bug docs", try evalStr(ar, "join(labels[*]['name'], ' ')", s));
    // Filtering something that is neither an array nor an object selects nothing.
    try std.testing.expectEqualStrings("[]", try evalStr(ar, "toJSON(plain.*.anything)", s));
    try std.testing.expectEqualStrings("[]", try evalStr(ar, "toJSON(plain.*)", s));
    try std.testing.expectEqualStrings("[]", try evalStr(ar, "toJSON(needs.*.x)", s));
}

test "functions" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const list = [_]Value{ .{ .string = "x" }, .{ .number = 2 }, .{ .boolean = true } };
    const ctxs = [_]Value.Entry{.{ .key = "items", .value = .{ .array = &list } }};
    const s = tctx(&ctxs);
    try std.testing.expect(try evalCondition(ar, "contains('Hello World', 'WORLD')", s));
    try std.testing.expect(!(try evalCondition(ar, "contains('abc', 'z')", s)));
    try std.testing.expect(try evalCondition(ar, "contains(items, 'X')", s));
    try std.testing.expect(try evalCondition(ar, "contains(items, 2)", s));
    try std.testing.expect(try evalCondition(ar, "startsWith('refs/heads/main', 'refs/heads/')", s));
    try std.testing.expect(try evalCondition(ar, "endsWith('file.TXT', '.txt')", s));
    try std.testing.expectEqualStrings("Hello Ada, you are 7", try evalStr(ar, "format('Hello {0}, you are {1}', 'Ada', 7)", s));
    try std.testing.expectEqualStrings("{literal} 1", try evalStr(ar, "format('{{literal}} {0}', 1)", s));
    try std.testing.expectEqualStrings("x,2,true", try evalStr(ar, "join(items)", s));
    try std.testing.expectEqualStrings("x-2-true", try evalStr(ar, "join(items, '-')", s));
    try std.testing.expectEqualStrings("plain", try evalStr(ar, "join('plain', ',')", s));
    try std.testing.expectEqualStrings("[\n  \"x\",\n  2,\n  true\n]", try evalStr(ar, "toJSON(items)", s));
    try std.testing.expectEqualStrings("7", try evalStr(ar, "fromJSON('{\"n\": 7}').n", s));
    try std.testing.expectEqualStrings("b", try evalStr(ar, "fromJSON('[\"a\",\"b\"]')[1]", s));
    try std.testing.expect(try evalCondition(ar, "fromJSON('true')", s));
}

test "status functions and the implicit success()" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const ok: Scope = .{};
    const failed: Scope = .{ .job_failed = true };
    try std.testing.expect(try evalCondition(ar, "success()", ok));
    try std.testing.expect(!(try evalCondition(ar, "success()", failed)));
    try std.testing.expect(try evalCondition(ar, "failure()", failed));
    try std.testing.expect(!(try evalCondition(ar, "failure()", ok)));
    try std.testing.expect(try evalCondition(ar, "always()", failed));
    try std.testing.expect(!(try evalCondition(ar, "cancelled()", ok)));
    // No status function: implicitly success() && (...)
    try std.testing.expect(try evalCondition(ar, "1 == 1", ok));
    try std.testing.expect(!(try evalCondition(ar, "1 == 1", failed)));
    try std.testing.expect(try evalCondition(ar, "always() && 1 == 1", failed));
    try std.testing.expect(try evalCondition(ar, "failure() && 1 == 1", failed));
    // empty condition and ${{ }} wrapper
    try std.testing.expect(try evalCondition(ar, "", ok));
    try std.testing.expect(try evalCondition(ar, "${{ 1 == 1 }}", ok));
    try std.testing.expect(try hasStatusFunction(ar, "github.ref == 'x' && !cancelled()"));
    try std.testing.expect(!try hasStatusFunction(ar, "github.ref == 'x'"));
}

test "errors say what is wrong" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var diag: []const u8 = "";
    const s: Scope = .{ .diag = &diag };
    try std.testing.expectError(error.ParseError, evaluate(ar, "1 +", s));
    try std.testing.expectError(error.ParseError, evaluate(ar, "'unterminated", s));
    try std.testing.expectError(error.ParseError, evaluate(ar, "(1 == 1", s));
    try std.testing.expect(std.mem.indexOf(u8, diag, "(1 == 1") != null);
    // As GitHub: when parsing, so even where it would never be called.
    try std.testing.expectError(error.ParseError, evaluate(ar, "false && nosuch('x')", s));
    try std.testing.expect(std.mem.startsWith(u8, diag, "unknown function 'nosuch'"));
    try std.testing.expectError(error.ParseError, evaluate(ar, "join()", s));
    try std.testing.expectError(error.ParseError, evaluate(ar, "case(true, 1)", s));
    try std.testing.expectError(error.EvalError, evaluate(ar, "format('{3}', 'a')", s));
    try std.testing.expectError(error.Unsupported, evaluate(ar, "hashFiles('**/*.zig')", s));
    try std.testing.expectEqualStrings("hashFiles() is not supported here", diag);
    // `github.*.x` used to be refused here. It is supported now: filtering a context that has no
    // `x` selects nothing, which is an empty array rather than an error.
    try std.testing.expectEqualStrings("[]", try evalStr(ar, "toJSON(github.*.x)", s));
}

test "hashFiles calls the scope's hook with its patterns" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const Fake = struct {
        fn hash(ptr: *anyopaque, arena: Allocator, patterns: []const []const u8) Allocator.Error!HashFiles.Result {
            _ = ptr;
            if (std.mem.eql(u8, patterns[0], "bad")) return .{ .failed = "no" };
            return .{ .ok = try std.mem.join(arena, "|", patterns) };
        }
    };
    var dummy: u8 = 0;
    var diag: []const u8 = "";
    const s: Scope = .{ .diag = &diag, .hash_files = .{ .ptr = &dummy, .hashFn = Fake.hash } };
    try std.testing.expectEqualStrings("**/go.sum|!x/**", (try evaluate(ar, "hashFiles('**/go.sum', '!x/**')", s)).string);
    try std.testing.expectError(error.EvalError, evaluate(ar, "hashFiles('bad')", s));
    try std.testing.expectEqualStrings("hashFiles(bad) failed: no", diag);
    try std.testing.expectError(error.ParseError, evaluate(ar, "hashFiles()", s));
}

test "case() picks the value after the first true predicate" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    try std.testing.expectEqualStrings("b", try evalStr(ar, "case(false, 'a', 1 == 1, 'b', 'c')", s));
    try std.testing.expectEqualStrings("c", try evalStr(ar, "case(false, 'a', false, 'b', 'c')", s));
    // Only what is needed is evaluated, as GitHub's runner does (#64): an error after the first
    // true predicate, or in a value not picked, is none.
    try std.testing.expectEqualStrings("a", try evalStr(ar, "case(true, 'a', fromJSON('{'), 'b', 'c')", s));
    try std.testing.expectEqualStrings("c", try evalStr(ar, "case(false, fromJSON('{'), false, 'b', 'c')", s));
    // A predicate after the first true one is not looked at.
    try std.testing.expectEqualStrings("a", try evalStr(ar, "case(true, 'a', 1, 'b', 'c')", s));
    try std.testing.expectError(error.EvalError, evaluate(ar, "case(1, 'a', 'b')", s));
    // The value picked is evaluated, errors and all.
    try std.testing.expectError(error.EvalError, evaluate(ar, "case(true, fromJSON('{'), 'c')", s));
}

test "format() and indexes evaluate what they need, when they need it, as GitHub's runner does" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    // An argument no placeholder uses is never evaluated.
    try std.testing.expectEqualStrings("1", try evalStr(ar, "format('{0}', 1, fromJSON('{'))", s));
    // One used is, once, however often it is placed.
    try std.testing.expectEqualStrings("x-x", try evalStr(ar, "format('{0}-{0}', 'x', 'y')", s));
    try std.testing.expectError(error.EvalError, evaluate(ar, "format('{1}', 1, fromJSON('{'))", s));
    // A mistake in the format string is found before any argument is evaluated.
    var diag: []const u8 = "";
    const sd: Scope = .{ .diag = &diag };
    try std.testing.expectError(error.EvalError, evaluate(ar, "format('{0} {', fromJSON('{'))", sd));
    try std.testing.expect(std.mem.indexOf(u8, diag, "unterminated") != null);
    // An index evaluates what it indexes first, and the index only when that is an array or an
    // object.
    try std.testing.expectEqualStrings("", try evalStr(ar, "fromJSON('null')[fromJSON('{')]", s));
    try std.testing.expectEqualStrings("", try evalStr(ar, "fromJSON('1')[fromJSON('{')]", s));
    try std.testing.expectError(error.EvalError, evaluate(ar, "fromJSON('[1]')[fromJSON('{')]", s));
    try std.testing.expectEqualStrings("2", try evalStr(ar, "fromJSON('[1,2]')[1]", s));
}

test "unsupported contexts fail loudly" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var diag: []const u8 = "";
    const s: Scope = .{ .unsupported_contexts = &.{"secrets"}, .diag = &diag };
    try std.testing.expectError(error.Unsupported, evaluate(a.allocator(), "secrets.TOKEN", s));
    try std.testing.expectEqualStrings("the 'secrets' context is not supported yet", diag);
    try std.testing.expectError(error.Unsupported, evaluate(a.allocator(), "format('{0}', SECRETS['x'])", s));
}

test "numbers print like GitHub" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    try std.testing.expectError(error.ParseError, evalStr(ar, "1 + 2", s)); // '+' is not an operator
    try std.testing.expectEqualStrings("1.5", try evalStr(ar, "1.5", s));
    try std.testing.expectEqualStrings("100", try evalStr(ar, "1e2", s));
    try std.testing.expectEqualStrings("NaN", try evalStr(ar, "NaN", s));
}

test "interpolate replaces each ${{ }} and leaves the rest alone" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const inputs = [_]Value.Entry{ .{ .key = "version", .value = .{ .string = "0.21.10" } }, .{ .key = "args", .value = .{ .string = "ci --skip-links\nx" } } };
    const ctxs = [_]Value.Entry{.{ .key = "inputs", .value = .{ .object = &inputs } }};
    var diag: []const u8 = "";
    const s: Scope = .{ .contexts = &ctxs, .diag = &diag };
    try std.testing.expectEqualStrings("plain $HOME {{ x }}", try interpolate(ar, "plain $HOME {{ x }}", s));
    try std.testing.expectEqualStrings("VERSION=0.21.10 and 0.21.10!", try interpolate(ar, "VERSION=${{ inputs.version }} and ${{inputs.VERSION}}!", s));
    // toJSON as dagger-for-github uses it, and a '}}' inside a string literal
    try std.testing.expectEqualStrings("echo '\"ci --skip-links\\nx\"'", try interpolate(ar, "echo '${{ toJSON(inputs.args) }}'", s));
    // The '}}' inside the string does not end the expression (format() then reads it as an escaped '}').
    try std.testing.expectEqualStrings("a}b", try interpolate(ar, "${{ format('{0}}}{1}', 'a', 'b') }}", s));
    try std.testing.expectEqualStrings("it's", try interpolate(ar, "${{ 'it''s' }}", s));
    try std.testing.expectError(error.ParseError, interpolate(ar, "x ${{ inputs.version", s));
    try std.testing.expectEqualStrings("'${{' is never closed with '}}'", diag);
}

/// `parts` joined, each `{ text, times }` repeated `times` times.
fn repeated(arena: Allocator, parts: []const struct { []const u8, usize }) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (parts) |p| for (0..p[1]) |_| try out.appendSlice(arena, p[0]);
    return out.items;
}

test "nesting deeper than GitHub's 50 is refused, however it is written, and never overflows" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    // GitHub's own cases: 49 `!` evaluate, 50 do not (the literal is a level too).
    try std.testing.expectEqualStrings("true", try evalStr(ar, try repeated(ar, &.{ .{ "!", 49 }, .{ "false", 1 } }), s));
    try std.testing.expectError(error.ParseError, evaluate(ar, try repeated(ar, &.{ .{ "!", 50 }, .{ "false", 1 } }), s));
    try std.testing.expectError(error.ParseError, evaluate(ar, try repeated(ar, &.{ .{ "(", 60 }, .{ "1", 1 }, .{ ")", 60 } }), s));
    try std.testing.expectError(error.ParseError, evaluate(ar, try repeated(ar, &.{ .{ "x", 1 }, .{ ".a", 50 } }), s));
    // Far past the limit: refused, not a stack overflow (this took the runner down).
    try std.testing.expectError(error.ParseError, evaluate(ar, try repeated(ar, &.{.{ "!", 100_000 }}), s));
}

test "a long chain of && or || is one node to GitHub, and evaluates without recursing" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    var text: std.ArrayList(u8) = .empty;
    for (1..20_001) |i| try text.print(ar, "{s}{d}", .{ if (i > 1) " && " else "", i });
    try std.testing.expectEqualStrings("20000", try evalStr(ar, text.items, s));
    text.clearRetainingCapacity();
    for (0..20_000) |i| try text.print(ar, "{s}{d}", .{ if (i > 0) " || " else "", i });
    try std.testing.expectEqualStrings("1", try evalStr(ar, text.items, s));
    try std.testing.expectEqualStrings("0", try evalStr(ar, "1 && 0 && fromJSON('{')", s));
    try std.testing.expectEqualStrings("2", try evalStr(ar, "1 && 2 || 3 && 4", s));
}

test "string building has GitHub's memory limit, and fromJSON a nesting limit" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    const f = "format('{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}', ";
    // 16^6 = 16 Mi characters: refused once past the limit, without building them all.
    const huge = try repeated(ar, &.{ .{ f, 6 }, .{ "'x'", 1 }, .{ ")", 6 } });
    try std.testing.expectError(error.EvalError, evaluate(ar, huge, s));
    const fine = try repeated(ar, &.{ .{ f, 3 }, .{ "'x'", 1 }, .{ ")", 3 } });
    try std.testing.expectEqual(@as(usize, 16 * 16 * 16), (try evalStr(ar, fine, s)).len);
    const deep = try repeated(ar, &.{ .{ "fromJSON('", 1 }, .{ "[", 1001 }, .{ "]", 1001 }, .{ "')", 1 } });
    try std.testing.expectError(error.EvalError, evaluate(ar, deep, s));
    // Brackets inside strings do not count.
    try std.testing.expectEqualStrings("]]]]", try evalStr(ar, "fromJSON('[[\"]]]]\"]]')[0][0]", s));
}

test "memory is counted as GitHub counts it, to the byte" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try std.testing.expectEqual(@as(usize, 3), utf16Len("\u{e9}\u{1f600}"));
    // `format('{0}', env.x)`, `env.x` a string of `n` characters. At the most, before format's
    // result replaces what was made below it: '{0}' (26 + 2 * 3) and `env.x` (an object, 24, and
    // its string, 26 + 2n) at level 1; `env` (24) and 'x' (26 + 2) at level 2. 134 + 2n in all,
    // so n = 524221 is the longest that fits in 1048576.
    for ([_]struct { usize, bool }{ .{ 524221, true }, .{ 524222, false } }) |c| {
        const x = try ar.alloc(u8, c[0]);
        @memset(x, 'x');
        const env = [_]Value.Entry{.{ .key = "x", .value = .{ .string = x } }};
        const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
        if (c[1])
            try std.testing.expectEqual(c[0], (try evalStr(ar, "format('{0}', env.x)", s)).len)
        else
            try std.testing.expectError(error.EvalError, evaluate(ar, "format('{0}', env.x)", s));
    }
    // A plain result lets what was made below it go: each format() here is under the limit, and
    // so is the whole, as on GitHub, though together they built more than it.
    const s: Scope = .{};
    const f = "format('{0}{0}{0}{0}{0}{0}{0}{0}', ";
    const nested = try repeated(ar, &.{ .{ f, 5 }, .{ "'xx'", 1 }, .{ ")", 5 } });
    try std.testing.expectEqual(@as(usize, 2 * 8 * 8 * 8 * 8 * 8), (try evalStr(ar, nested, s)).len);
}

test "numbers are read as JavaScript's Number() reads them, as GitHub does" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    for ([_][2][]const u8{
        .{ ".5", "0.5" },                               .{ "-.5", "-0.5" },            .{ "+1", "1" },
        .{ "0o17", "15" },                              .{ "0b101", "5" },             .{ "0xfF", "255" },
        .{ "1E+2", "100" },                             .{ "-Infinity", "-Infinity" }, .{ "-0", "0" },
        .{ "0.84551240822557006", "0.84551240822557" },
    }) |c| try std.testing.expectEqualStrings(c[1], try evalStr(ar, c[0], s));
    // Hex takes no sign; a point after a value is a property access.
    try std.testing.expectError(error.ParseError, evaluate(ar, "-0xFF", s));
    try std.testing.expectError(error.ParseError, evaluate(ar, "1_000", s));
    try std.testing.expectEqualStrings("true", try evalStr(ar, "' 0o10 ' == 8", s));
    try std.testing.expectEqualStrings("false", try evalStr(ar, "'inf' == Infinity", s));
    try std.testing.expectEqualStrings("false", try evalStr(ar, "!!NaN", s));
    try std.testing.expect(std.math.isNan(jsNumber("1_000")));
    try std.testing.expect(std.math.isNan(jsNumber("nan")));
    try std.testing.expectEqual(@as(f64, 0), jsNumber("  "));
}

test "strings compare as their upper-case forms, beyond ASCII, as GitHub compares them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s: Scope = .{};
    for ([_][]const u8{
        "'ü' == 'Ü'",
        "'ς' == 'Σ' && 'σ' == 'Σ'",
        "'a' < '[' && 'A' < '['", // 'A' (65) is before '[' (91); 'a' (97) is not
        "startsWith('Привет, мир', 'ПРИВЕТ')",
        "endsWith('façade', 'ÇADE')",
        "contains('Grüße', 'RÜ')",
        "'ı' != 'I' && 'İ' != 'i'",
        "'\xff' == '\xff' && '\xff' != '\xfe'", // not UTF-8: compared as bytes
    }) |e| try std.testing.expectEqualStrings("true", try evalStr(ar, e, s));
}

test "a[*] is a.*, and what follows a filter applies to each element" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const json = try std.json.parseFromSliceLeaky(std.json.Value, ar,
        \\{"m": [[1, 2], [3, 4], "x"], "o": {"a": [5], "b": {"k": 6}}, "sep": [], "obj": {}, "obj2": {}}
    , .{});
    const s: Scope = .{ .contexts = (try fromJsonValue(ar, json)).object };
    try std.testing.expectEqualStrings("2,4", try evalStr(ar, "join(m[*][1])", s));
    try std.testing.expectEqualStrings("1,2,3,4", try evalStr(ar, "join(m.*.*)", s));
    try std.testing.expectEqualStrings("5,6", try evalStr(ar, "join(o.*.*)", s));
    try std.testing.expectEqualStrings("4", try evalStr(ar, "m[true][true]", s)); // m[1][1]
    try std.testing.expectEqualStrings("", try evalStr(ar, "o[obj]", s));
    try std.testing.expectEqualStrings("1,2", try evalStr(ar, "join(m[0], sep)", s));
    try std.testing.expectEqualStrings("", try evalStr(ar, "join(o)", s));
    // Arrays and objects equal only themselves, empty ones too.
    try std.testing.expectEqualStrings("true", try evalStr(ar, "obj == obj && obj != obj2", s));
}

test "what random expressions against Gitea's evaluator turned up, settled by GitHub's source" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const json = try std.json.parseFromSliceLeaky(std.json.Value, ar,
        \\{"l": [10, 20, 30], "objs": [{"n": "a"}, {"n": "b"}], "o": {"k": "v"}}
    , .{});
    const s: Scope = .{ .contexts = (try fromJsonValue(ar, json)).object };
    // Only a context, a function's result or a parenthesised expression can be indexed.
    try std.testing.expectError(error.ParseError, evaluate(ar, "'abc'[0]", s));
    try std.testing.expectError(error.ParseError, evaluate(ar, "null.x", s));
    try std.testing.expectEqualStrings("20", try evalStr(ar, "(l)[1]", s));
    // A number token runs to a boundary: `1E-2` is one number, `1-2` no number.
    try std.testing.expectEqualStrings("10", try evalStr(ar, "l[1E-2]", s));
    try std.testing.expectError(error.ParseError, evaluate(ar, "1-2", s));
    // A fraction indexes as its floor.
    try std.testing.expectEqualStrings("20", try evalStr(ar, "l[1.5]", s));
    // `>=` and `<=` include equality, so an array is >= itself.
    try std.testing.expectEqualStrings("true", try evalStr(ar, "l >= l && l <= l", s));
    try std.testing.expectEqualStrings("false", try evalStr(ar, "l > l", s));
    // The string functions are false for an array or object, either side.
    for ([_][]const u8{ "contains(o, 'v')", "contains('Object', o)", "startsWith(l, 'A')", "endsWith('x', l)" }) |e|
        try std.testing.expectEqualStrings("false", try evalStr(ar, e, s));
    try std.testing.expectEqualStrings("true", try evalStr(ar, "contains(l, 20)", s));
    // JSON has no NaN or Infinity: null, as JSON.stringify writes them.
    try std.testing.expectEqualStrings("null", try evalStr(ar, "toJSON(NaN)", s));
    try std.testing.expectEqualStrings("null", try evalStr(ar, "toJSON(-Infinity)", s));
    // A filter's result stays one through a function, and is a new array.
    try std.testing.expectEqualStrings("a,b", try evalStr(ar, "join(case(true, objs.*, l).n)", s));
    try std.testing.expectEqualStrings("false", try evalStr(ar, "l.* == l", s));
}

test "join() and toJSON() count what they build as GitHub's runner does, to the byte" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // join(): each element and separator is a string of its own, an empty one too, so n empty
    // strings joined with ',' are 26n + 28(n - 1) bytes: 19418 fit in 1048576, 19419 do not.
    for ([_]struct { usize, bool }{ .{ 19418, true }, .{ 19419, false } }) |c| {
        const items = try ar.alloc(Value, c[0]);
        @memset(items, .{ .string = "" });
        const env = [_]Value.Entry{.{ .key = "a", .value = .{ .array = items } }};
        const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
        if (c[1])
            try std.testing.expectEqual(c[0] - 1, (try evalStr(ar, "join(env.a)", s)).len)
        else
            try std.testing.expectError(error.EvalError, evaluate(ar, "join(env.a)", s));
    }
    // toJSON(): `[`, then each element with what goes before it, then the new line and `]`, so n
    // nulls are 28 + 40 + 42(n - 1) + 30 bytes: 24964 fit, 24965 do not.
    for ([_]struct { usize, bool }{ .{ 24964, true }, .{ 24965, false } }) |c| {
        const items = try ar.alloc(Value, c[0]);
        @memset(items, .null);
        const env = [_]Value.Entry{.{ .key = "a", .value = .{ .array = items } }};
        const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
        if (c[1])
            try std.testing.expectEqual(8 * c[0] + 2, (try evalStr(ar, "toJSON(env.a)", s)).len)
        else
            try std.testing.expectError(error.EvalError, evaluate(ar, "toJSON(env.a)", s));
    }
}

test "join() and toJSON() refuse what GitHub would before building it" {
    // A thousand elements and a 20000-character separator: 20 MB of result, refused after a few
    // dozen pieces.
    {
        var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer a.deinit();
        const ar = a.allocator();
        const sep = try ar.alloc(u8, 20000);
        @memset(sep, 's');
        const items = try ar.alloc(Value, 1000);
        @memset(items, .{ .string = "x" });
        const env = [_]Value.Entry{
            .{ .key = "a", .value = .{ .array = items } },
            .{ .key = "sep", .value = .{ .string = sep } },
        };
        const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
        const before = a.queryCapacity();
        try std.testing.expectError(error.EvalError, evaluate(ar, "join(env.a, env.sep)", s));
        try std.testing.expect(a.queryCapacity() - before < 4 << 20);
    }
    // Arrays nested 2000 deep: their indentation alone is 8 MB, refused about 720 levels in.
    {
        var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer a.deinit();
        const ar = a.allocator();
        var v: Value = .null;
        for (0..2000) |_| {
            const one = try ar.alloc(Value, 1);
            one[0] = v;
            v = .{ .array = one };
        }
        const env = [_]Value.Entry{.{ .key = "a", .value = v }};
        const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
        const before = a.queryCapacity();
        try std.testing.expectError(error.EvalError, evaluate(ar, "toJSON(env.a)", s));
        try std.testing.expect(a.queryCapacity() - before < 4 << 20);
    }
}

test "an interpolated text is limited as GitHub limits the format() it makes of it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Twenty values of n characters are 20 (26 + 2n) bytes: n = 262131 fills 10 MiB exactly.
    for ([_]struct { usize, bool }{ .{ 262131, true }, .{ 262132, false } }) |c| {
        const x = try ar.alloc(u8, c[0]);
        @memset(x, 'x');
        const env = [_]Value.Entry{.{ .key = "x", .value = .{ .string = x } }};
        const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
        const text = try repeated(ar, &.{.{ "${{ env.x }}", 20 }});
        if (c[1])
            try std.testing.expectEqual(20 * c[0], (try interpolate(ar, text, s)).len)
        else
            try std.testing.expectError(error.EvalError, interpolate(ar, text, s));
    }
    // The text between the expressions counts too, cut after each brace: k braces and a value of
    // one character are 28 (k + 1) bytes, so 374490 braces fit and 374491 do not.
    const s: Scope = .{};
    const text = try repeated(ar, &.{ .{ "{", 374491 }, .{ "${{ 1 }}", 1 } });
    try std.testing.expectError(error.EvalError, interpolate(ar, text, s));
    try std.testing.expectEqual(@as(usize, 374490 + 1), (try interpolate(ar, text[1..], s)).len);
    // One expression alone is no format(), and only its own limit applies.
    try std.testing.expectEqualStrings("1", try interpolate(ar, "${{ 1 }}", s));
}

test "interpolation stops at its limit, and what each expression builds on the way does not add up" {
    // Both cases at once: each is slow in a debug build, and they share nothing.
    const io = std.testing.io;
    // A hundred values of 300000 characters: 30 MB, refused at the 18th.
    const Refused = struct {
        fn run() !void {
            var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer a.deinit();
            const ar = a.allocator();
            const big = try ar.alloc(u8, 300000);
            @memset(big, 'x');
            const env = [_]Value.Entry{.{ .key = "big", .value = .{ .string = big } }};
            const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
            const text = try repeated(ar, &.{.{ "${{ env.big }}", 100 }});
            const before = a.queryCapacity();
            try std.testing.expectError(error.EvalError, interpolate(ar, text, s));
            try std.testing.expect(a.queryCapacity() - before < 32 << 20);
        }
    };
    var refused = try io.concurrent(Refused.run, .{});
    defer refused.cancel(io) catch {};
    // Two hundred expressions, each building 300000 characters to compare with: short results,
    // and each one's scratch memory is the next one's.
    {
        var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer a.deinit();
        const ar = a.allocator();
        const big = try ar.alloc(u8, 150000);
        @memset(big, 'x');
        const env = [_]Value.Entry{.{ .key = "big", .value = .{ .string = big } }};
        const s = tctx(&.{.{ .key = "env", .value = .{ .object = &env } }});
        const text = try repeated(ar, &.{.{ "${{ format('{0}{0}', env.big) == '' }} ", 200 }});
        const before = a.queryCapacity();
        try std.testing.expectEqual(@as(usize, 6 * 200), (try interpolate(ar, text, s)).len);
        try std.testing.expect(a.queryCapacity() - before < 16 << 20);
        // A failure's reason outlives the scratch memory it was written in.
        var diag: []const u8 = "";
        var sd = s;
        sd.diag = &diag;
        try std.testing.expectError(error.ParseError, interpolate(ar, "a ${{ 1 }} ${{ join(1, 2, 3) }}", sd));
        @memset(try ar.alloc(u8, 4096), '!');
        try std.testing.expect(std.mem.indexOf(u8, diag, "too many arguments to join()") != null);
    }
    try refused.await(io);
}
