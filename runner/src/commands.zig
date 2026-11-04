//! Parsing of the file commands a step writes: `$GITHUB_OUTPUT`, `$GITHUB_ENV` and `$GITHUB_PATH`.
//!
//! `GITHUB_OUTPUT` and `GITHUB_ENV` hold `name=value` lines, or a multi-line value:
//!
//!     name<<DELIMITER
//!     line 1
//!     line 2
//!     DELIMITER
//!
//! `GITHUB_PATH` holds one directory per line. Malformed input is an error naming the line, as in
//! GitHub ("Unable to process file command ... successfully"), not silently ignored.
const std = @import("std");
const job_mod = @import("job.zig");

const Allocator = std.mem.Allocator;

pub const Parsed = struct {
    /// The entries before the first malformed line, or all of them.
    pairs: []const job_mod.EnvVar,
    /// Why the file could not be read to its end (names the offending line); null when it was.
    invalid: ?[]const u8 = null,
};

/// The `name=value` and `name<<DELIMITER` entries of a `GITHUB_OUTPUT`, `GITHUB_ENV` or
/// `GITHUB_STATE` file, in the order written, up to the first malformed line, and why that one is.
/// GitHub's runner reads the entries one at a time and applies each as it goes, so those before a
/// bad line take effect (`EnvFileKeyValuePairs` in FileCommandManager.cs).
///
/// Read as GitHub's runner reads them on Linux: lines end at `\n` alone, so a `\r` before it is
/// the line's (a CRLF file's `a=1` is `1\r`, and a line holding only `\r` is malformed), a value
/// ends only at a line that is its delimiter exactly, `\r` and all, and a value's lines are kept
/// as written. Taking `\r\n` as the end of a line let a value's `EOF\r` line end a value whose
/// delimiter is `EOF`, where GitHub reads it as part of the value, and the lines after it were then
/// read as more variables. A UTF-8 byte order mark at the start is not part of the first name
/// (`File.ReadAllText`).
///
/// One difference: a `=value` line, which GitHub reads as a variable with an empty name (it
/// checks the line instead of the name), is malformed here: an empty name breaks every later
/// step's environment.
pub fn parseKeyValues(arena: Allocator, text: []const u8) Allocator.Error!Parsed {
    var out: std.ArrayList(job_mod.EnvVar) = .empty;
    var lines: Lines = .{ .text = withoutBom(text) };
    var line_no: usize = 0;
    const why: []const u8 = while (lines.next()) |l| {
        line_no += 1;
        const line = l.text;
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=');
        const heredoc = std.mem.indexOf(u8, line, "<<");
        // `name<<DELIM` wins when it comes before any `=`.
        if (heredoc != null and (eq == null or heredoc.? < eq.?)) {
            const name = line[0..heredoc.?];
            const delim = line[heredoc.? + 2 ..];
            if (name.len == 0 or delim.len == 0) break try std.fmt.allocPrint(
                arena,
                "invalid format '{s}' on line {d}: expected name<<DELIMITER",
                .{ line, line_no },
            );
            const value = heredocValue(&lines, &line_no, delim) orelse
                break try std.fmt.allocPrint(
                    arena,
                    "matching delimiter '{s}' not found for '{s}'",
                    .{ delim, name },
                );
            try out.append(arena, .{ .name = name, .value = value });
            continue;
        }
        const e = eq orelse break try std.fmt.allocPrint(
            arena,
            "invalid format '{s}' on line {d}: expected name=value",
            .{ line, line_no },
        );
        if (e == 0) break try std.fmt.allocPrint(
            arena,
            "invalid format '{s}' on line {d}: the name is empty",
            .{ line, line_no },
        );
        try out.append(arena, .{ .name = line[0..e], .value = line[e + 1 ..] });
    } else return .{ .pairs = out.items };
    return .{ .pairs = out.items, .invalid = why };
}

/// `text` without a UTF-8 byte order mark at its start.
fn withoutBom(text: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) text[3..] else text;
}

/// A file command's lines as GitHub's runner reads them on Linux (`ReadLine` in
/// FileCommandManager.cs): each up to a `\n`, without it, and the text after the last `\n` a line
/// of its own only when there is some.
const Lines = struct {
    text: []const u8,
    pos: usize = 0,

    const Line = struct { text: []const u8, start: usize, ended: bool };

    fn next(l: *Lines) ?Line {
        if (l.pos >= l.text.len) return null;
        const start = l.pos;
        if (std.mem.indexOfScalarPos(u8, l.text, start, '\n')) |nl| {
            l.pos = nl + 1;
            return .{ .text = l.text[start..nl], .start = start, .ended = true };
        }
        l.pos = l.text.len;
        return .{ .text = l.text[start..], .start = start, .ended = false };
    }
};

/// The text of a multi-line value: the lines after its `name<<DELIMITER` line up to the line that
/// is `delim` exactly, as written, without the newline before that line; null when the file
/// ends first, or a line before the delimiter has no newline (`Invalid value. EOF marker missing
/// new line.`). `line_no` counts the lines taken.
fn heredocValue(lines: *Lines, line_no: *usize, delim: []const u8) ?[]const u8 {
    const start = lines.pos;
    var end = start;
    while (lines.next()) |l| {
        line_no.* += 1;
        if (std.mem.eql(u8, l.text, delim)) return lines.text[start..end];
        if (!l.ended) return null;
        end = l.start + l.text.len;
    }
    return null;
}

/// Directories from a GITHUB_PATH file, in the order written: its lines as `File.ReadAllLines`
/// reads them (ending at `\n`, `\r\n` or `\r`, after any byte order mark), without the spaces and
/// tabs around them (GitHub keeps those), the empty ones left out.
pub fn parsePaths(arena: Allocator, text: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.tokenizeAny(u8, withoutBom(text), "\r\n");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len > 0) try out.append(arena, line);
    }
    return out.items;
}

/// The one name GitHub refuses from `GITHUB_ENV`, in any case: it would inject code into every
/// later Node process (`_setEnvBlockList` in actions/runner's FileCommandManager.cs). Every other
/// name is set, `GITHUB_*`, `RUNNER_*` and `CI` included; the defaults GitHub derives from its
/// contexts are set again over them (`Evaluator.withoutReapplied`).
pub fn isBlockedEnvName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "NODE_OPTIONS");
}

/// The runner's own variables, which `GITHUB_ENV` must not set either: GitHub has none, so
/// refusing them costs nothing, and set they would forge the machinery behind them. `ZIG_RUNNER_*`
/// is the run marker (`ran_env`, which tells a replayed step from one that ran), the step markers'
/// secret (`mark_env`), the event payload (`event_env`) and the step-cache opt-out;
/// `ZIG_SECRET_<n>` are the aliases secrets reach a step's command by (`secretAlias`).
pub fn isRunnerEnvName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "ZIG_RUNNER_") or
        std.mem.startsWith(u8, name, "ZIG_SECRET_");
}

test "name=value, blank lines, and = inside values" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const p = try parseKeyValues(a.allocator(), "a=1\n\nb=x=y\nempty=\n");
    try std.testing.expectEqual(@as(usize, 3), p.pairs.len);
    try std.testing.expectEqualStrings("a", p.pairs[0].name);
    try std.testing.expectEqualStrings("1", p.pairs[0].value);
    try std.testing.expectEqualStrings("x=y", p.pairs[1].value);
    try std.testing.expectEqualStrings("", p.pairs[2].value);
}

test "multi-line values with a delimiter, including = and << inside the value" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const p = try parseKeyValues(a.allocator(), "msg<<EOF_1\nline one\nk=v << not a heredoc\nEOF_1\nafter=ok\n");
    try std.testing.expectEqual(@as(usize, 2), p.pairs.len);
    try std.testing.expectEqualStrings("msg", p.pairs[0].name);
    try std.testing.expectEqualStrings("line one\nk=v << not a heredoc", p.pairs[0].value);
    try std.testing.expectEqualStrings("ok", p.pairs[1].value);
}

test "CRLF line endings are read as GitHub's runner reads them on Linux" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // The `\r` is the line's: in a value, and in the delimiter, which a CRLF file's own
    // delimiter line then matches.
    const p = try parseKeyValues(ar, "a=1\r\nb<<D\r\nx\r\ny\r\nD\r\n");
    try std.testing.expectEqual(@as(usize, 2), p.pairs.len);
    try std.testing.expectEqualStrings("1\r", p.pairs[0].value);
    try std.testing.expectEqualStrings("x\r\ny\r", p.pairs[1].value);
    try std.testing.expect(p.invalid == null);
    // A value's `EOF\r` line is not the delimiter `EOF`: it is part of the value, and the line
    // after it cannot set another variable. Taking `\r\n` for a line's end once ended the value
    // there and set INJECTED.
    const v = try parseKeyValues(ar, "v<<EOF\nfirst\nEOF\r\nINJECTED=1\nEOF\nafter=2\n");
    try std.testing.expectEqual(@as(usize, 2), v.pairs.len);
    try std.testing.expectEqualStrings("first\nEOF\r\nINJECTED=1", v.pairs[0].value);
    try std.testing.expectEqualStrings("after", v.pairs[1].name);
    // Nor does ` EOF`, `EOF ` or `xEOF`; and a CRLF line holding only `\r` is malformed.
    const w = try parseKeyValues(ar, "w<<EOF\n EOF\nEOF \nxEOF\nEOF\n");
    try std.testing.expectEqualStrings(" EOF\nEOF \nxEOF", w.pairs[0].value);
    try std.testing.expect((try parseKeyValues(ar, "a=1\r\n\r\nb=2\r\n")).invalid != null);
    // A byte order mark is not the first name's.
    try std.testing.expectEqualStrings("a", (try parseKeyValues(ar, "\xEF\xBB\xBFa=1\n")).pairs[0].name);
}

test "a value ends only at its delimiter's own line, which must end in a newline unless it is last" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // The delimiter as the file's last line, with no newline, ends the value.
    try std.testing.expectEqualStrings("x", (try parseKeyValues(ar, "a<<E\nx\nE")).pairs[0].value);
    // A value line with no newline after it fails, as GitHub's `EOF marker missing new line`.
    const cut = try parseKeyValues(ar, "a<<E\nx");
    try std.testing.expectEqual(@as(usize, 0), cut.pairs.len);
    try std.testing.expect(cut.invalid != null);
    try std.testing.expect((try parseKeyValues(ar, "a<<E\n")).invalid != null);
    // An empty value, and a value with empty lines and multi-byte UTF-8 kept as written.
    try std.testing.expectEqualStrings("", (try parseKeyValues(ar, "a<<E\nE\n")).pairs[0].value);
    const u = try parseKeyValues(ar, "a<<É\n\nnaïve ✓\n\nÉ\n");
    try std.testing.expectEqualStrings("\nnaïve ✓\n", u.pairs[0].value);
}

test "malformed input is reported with the line" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try std.testing.expect(std.mem.indexOf(u8, (try parseKeyValues(ar, "a=1\njust text\n")).invalid.?, "line 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, (try parseKeyValues(ar, "=v\n")).invalid.?, "name is empty") != null);
    try std.testing.expect(std.mem.indexOf(u8, (try parseKeyValues(ar, "m<<EOF\nnever closed\n")).invalid.?, "delimiter 'EOF' not found") != null);
    try std.testing.expect(std.mem.indexOf(u8, (try parseKeyValues(ar, "m<<\nx\n")).invalid.?, "name<<DELIMITER") != null);
    // What came before the bad line is kept, as GitHub applies it; nothing after.
    const partial = try parseKeyValues(ar, "a=1\nb<<E\nx\nE\nbad line\nc=3\n");
    try std.testing.expectEqual(@as(usize, 2), partial.pairs.len);
    try std.testing.expectEqualStrings("x", partial.pairs[1].value);
    try std.testing.expect(partial.invalid != null);
    try std.testing.expect((try parseKeyValues(ar, "a=1\n")).invalid == null);
}

test "paths and the blocked name" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ps = try parsePaths(a.allocator(), "/opt/tool/bin\n\n  /home/x/.local/bin \n");
    try std.testing.expectEqual(@as(usize, 2), ps.len);
    try std.testing.expectEqualStrings("/home/x/.local/bin", ps[1]);
    try std.testing.expect(isBlockedEnvName("NODE_OPTIONS"));
    try std.testing.expect(isBlockedEnvName("node_options"));
    for ([_][]const u8{ "MY_VAR", "GITHUB_TOKEN", "GITHUB_SHA", "RUNNER_OS", "CI" }) |name|
        try std.testing.expect(!isBlockedEnvName(name) and !isRunnerEnvName(name));
    const runner_names = [_][]const u8{
        "ZIG_RUNNER_RAN", "ZIG_RUNNER_MARK", "ZIG_RUNNER_EVENT", "ZIG_SECRET_0",
    };
    for (runner_names) |name|
        try std.testing.expect(isRunnerEnvName(name));
}

// --- workflow commands printed by a step: `::name key=value,...::data`, or `##[name ...]data` ---

pub const Workflow = union(enum) {
    /// Not a command, an unknown one, or commands are stopped: log the line as it is.
    none,
    /// Mask this value in all later output; the line itself is not logged.
    add_mask: []const u8,
    group: []const u8,
    endgroup,
    /// `error`, `warning` or `notice`, logged as `##[<level>]<message>`.
    annotation: Annotation,
    debug: []const u8,
    /// `::stop-commands::<token>`: no commands until `::<token>::`. The token may be one GitHub
    /// refuses (`stopTokenRefused`).
    stop: []const u8,
    /// `::<token>::` while commands are stopped.
    resume_commands,
    /// Deprecated `set-output` and `save-state`, still honoured.
    set_output: job_mod.EnvVar,
    save_state: job_mod.EnvVar,
    /// `::set-env name=<name>::<value>` and `::add-path::<dir>`, which GitHub disabled: they fail
    /// the step unless its env sets ACTIONS_ALLOW_UNSECURE_COMMANDS to `true`. The name is null
    /// when the command has none.
    set_env: struct { name: ?[]const u8, value: []const u8 },
    add_path: []const u8,
    /// `::echo::on` or `::echo::off`: whether later commands' lines are logged too. Any other
    /// value fails the step (the log checks it).
    echo: []const u8,
    /// `::add-matcher::<path>`: register the problem matchers in that file (see matcher.zig). The
    /// path is relative to the workspace, or to an action's own directory inside one.
    add_matcher: []const u8,
    /// `::remove-matcher owner=<name>::`: withdraw the matchers an owner registered.
    remove_matcher: []const u8,
};

/// `::error file=a.js,line=3,endLine=4,col=1,endColumn=9,title=T::message`. The properties are as
/// written (null when absent); GitHub's runner reads the same names.
pub const Annotation = struct {
    level: []const u8,
    message: []const u8,
    title: ?[]const u8 = null,
    file: ?[]const u8 = null,
    line: ?[]const u8 = null,
    end_line: ?[]const u8 = null,
    col: ?[]const u8 = null,
    end_column: ?[]const u8 = null,
};

/// The commands GitHub's runner registers (`_registeredCommands` in ActionCommandManager.cs): a
/// line naming any other is output.
const registered = [_][]const u8{
    "stop-commands", "add-mask",   "add-matcher", "remove-matcher", "debug",
    "echo",          "error",      "warning",     "notice",         "group",
    "endgroup",      "set-output", "save-state",  "set-env",        "add-path",
};

/// How a command is written: `::name k=v,k2=v2::data`, or the legacy `##[name k=v;k2=v2]data`
/// anywhere in the line, which GitHub's runner still reads when a line is not the first kind
/// (`ActionCommand.TryParseV2`, then `TryParse`). They differ in the property separator and the
/// escapes.
const Syntax = enum { v2, legacy };

/// A command line taken apart: its name, its properties as written, and its data.
const Parts = struct { name: []const u8, props: []const u8, data: []const u8 };

/// Parses one line of a step's output. `stopped_token` is the token of an active `stop-commands`.
/// Command and property names are case-insensitive. In the `::` form, leading whitespace is
/// ignored and trailing whitespace is the data's.
pub fn parseWorkflow(
    arena: Allocator,
    line: []const u8,
    stopped_token: ?[]const u8,
) Allocator.Error!Workflow {
    const eql = std.ascii.eqlIgnoreCase;
    inline for ([_]Syntax{ .v2, .legacy }) |syntax| if (split(line, syntax)) |parts| {
        const is_token = if (stopped_token) |token| eql(parts.name, token) else false;
        const known = for (registered) |r| {
            if (eql(parts.name, r)) break true;
        } else false;
        if (is_token or known) {
            // The token is a command's name while commands are stopped, matched as one is: in
            // any case, with whatever properties and data (`TryProcessCommand`).
            if (stopped_token != null) return if (is_token) .resume_commands else .none;
            return command(arena, parts, syntax);
        }
    };
    return .none;
}

/// `line` taken apart as `syntax` writes a command; null when it is not written so.
fn split(line: []const u8, syntax: Syntax) ?Parts {
    var section: []const u8 = undefined;
    var data: []const u8 = undefined;
    switch (syntax) {
        .v2 => {
            // Leading whitespace only (`TrimStart` in `TryParseV2`): trailing whitespace is part
            // of the data, as on GitHub (`::set-output name=x::a ` sets `a `). The `\r` is the
            // line's end, which GitHub's line reader drops.
            const t = std.mem.trimStart(u8, std.mem.trimEnd(u8, line, "\r"), &std.ascii.whitespace);
            if (!std.mem.startsWith(u8, t, "::")) return null;
            const end = std.mem.indexOfPos(u8, t, 2, "::") orelse return null;
            section = t[2..end];
            data = t[end + 2 ..];
        },
        .legacy => {
            const t = std.mem.trimEnd(u8, line, "\r");
            const start = std.mem.indexOf(u8, t, "##[") orelse return null;
            const end = std.mem.indexOfScalarPos(u8, t, start + 3, ']') orelse return null;
            section = t[start + 3 .. end];
            data = t[end + 1 ..];
        },
    }
    const space = std.mem.indexOfScalar(u8, section, ' ');
    return .{
        .name = section[0 .. space orelse section.len],
        .props = if (space) |s| section[s + 1 ..] else "",
        .data = data,
    };
}

/// The command a registered name stands for, its properties and data read as `syntax` escapes
/// them.
fn command(arena: Allocator, parts: Parts, syntax: Syntax) Allocator.Error!Workflow {
    const eql = std.ascii.eqlIgnoreCase;
    const name = parts.name;
    const props = parts.props;
    const data = try unescape(arena, parts.data, if (syntax == .v2) .data else .legacy);
    if (eql(name, "add-mask")) return .{ .add_mask = data };
    if (eql(name, "add-matcher")) return if (data.len > 0) .{ .add_matcher = data } else .none;
    if (eql(name, "remove-matcher")) {
        // The owner is a property, not the data: `::remove-matcher owner=eslint-stylish::`.
        const owner = try property(arena, props, "owner", syntax);
        return if (owner) |o| (if (o.len > 0) .{ .remove_matcher = o } else .none) else .none;
    }
    if (eql(name, "group")) return .{ .group = data };
    if (eql(name, "endgroup")) return .endgroup;
    if (eql(name, "debug")) return .{ .debug = data };
    if (eql(name, "echo")) return .{ .echo = data };
    // Even with no token: the log refuses it (`stopTokenRefused`).
    if (eql(name, "stop-commands")) return .{ .stop = data };
    if (eql(name, "set-env")) return .{ .set_env = .{
        .name = try property(arena, props, "name", syntax),
        .value = data,
    } };
    if (eql(name, "add-path")) return .{ .add_path = data };
    for ([_][]const u8{ "error", "warning", "notice" }) |level| if (eql(name, level))
        return .{ .annotation = .{
            .level = level,
            .message = data,
            .title = try property(arena, props, "title", syntax),
            .file = try property(arena, props, "file", syntax),
            .line = try property(arena, props, "line", syntax),
            .end_line = try property(arena, props, "endLine", syntax),
            .col = try property(arena, props, "col", syntax),
            .end_column = try property(arena, props, "endColumn", syntax),
        } };
    if (eql(name, "set-output") or eql(name, "save-state")) {
        const key = (try property(arena, props, "name", syntax)) orelse return .none;
        const kv: job_mod.EnvVar = .{ .name = key, .value = data };
        return if (eql(name, "set-output")) .{ .set_output = kv } else .{ .save_state = kv };
    }
    return .none;
}

/// Whether GitHub refuses `token` for `::stop-commands::`: an empty one, `pause-logging`, or the
/// name of a command, which would end the pause or be taken for one (`ValidateStopToken` in
/// ActionCommandManager.cs, against its registered commands), in any case.
pub fn stopTokenRefused(token: []const u8) bool {
    if (token.len == 0 or std.ascii.eqlIgnoreCase(token, "pause-logging")) return true;
    for (registered) |r| if (std.ascii.eqlIgnoreCase(token, r)) return true;
    return false;
}

/// The value of property `key` in `k=v,k2=v2` (`k=v;k2=v2` in the legacy syntax), read as
/// GitHub's runner reads them (`TryParseV2`, `TryParse` in ActionCommand.cs): names in any case
/// (an `OrdinalIgnoreCase` dictionary) and not trimmed, so `file=a, line=3` has no `line`; the
/// last of a name wins. Each pair is `Split('=', 2, RemoveEmptyEntries)`: leading `=`s and those
/// after the name are skipped, and a pair left without a name or a value is ignored (`title=`).
fn property(
    arena: Allocator,
    props: []const u8,
    key: []const u8,
    syntax: Syntax,
) Allocator.Error!?[]const u8 {
    const separator: u8 = if (syntax == .v2) ',' else ';';
    // The `::` form trims the property list as a whole; the legacy form does not.
    const list = if (syntax == .v2) std.mem.trim(u8, props, &std.ascii.whitespace) else props;
    var found: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, list, separator);
    while (it.next()) |p| {
        const pair = std.mem.trimStart(u8, p, "=");
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const value = std.mem.trimStart(u8, pair[eq + 1 ..], "=");
        if (value.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(pair[0..eq], key)) found = value;
    }
    const v = found orelse return null;
    return try unescape(arena, v, if (syntax == .v2) .property else .legacy);
}

/// Which of GitHub's escape tables applies (`ActionCommand`'s `_escapeDataMappings`,
/// `_escapePropertyMappings` and, for the legacy syntax, `_escapeMappings`).
const Escapes = enum { data, property, legacy };

/// The byte an escape `%<code>` stands for, or null when it is not one GitHub defines.
fn unescapedByte(code: []const u8, escapes: Escapes) ?u8 {
    const eql = std.ascii.eqlIgnoreCase;
    if (eql(code, "25")) return '%';
    if (eql(code, "0D")) return '\r';
    if (eql(code, "0A")) return '\n';
    if (escapes == .property and eql(code, "3A")) return ':';
    if (escapes == .property and eql(code, "2C")) return ',';
    if (escapes == .legacy and eql(code, "3B")) return ';';
    if (escapes == .legacy and eql(code, "5D")) return ']';
    return null;
}

/// GitHub's escapes: `%25` `%0D` `%0A` in data, plus `%3A` `%2C` in property values; in the
/// legacy syntax, those three plus `%3B` and `%5D` in both.
fn unescape(arena: Allocator, s: []const u8, escapes: Escapes) Allocator.Error![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '%') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%' and i + 3 <= s.len) {
            const code = s[i + 1 .. i + 3];
            const c = unescapedByte(code, escapes);
            if (c) |ch| {
                try out.append(arena, ch);
                i += 3;
                continue;
            }
        }
        try out.append(arena, s[i]);
        i += 1;
    }
    return out.items;
}

test "workflow commands" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try std.testing.expect(try parseWorkflow(ar, "plain output", null) == .none);
    try std.testing.expect(try parseWorkflow(ar, "a ::group::not at the start", null) == .none);
    try std.testing.expect(try parseWorkflow(ar, "::unknown::x", null) == .none);
    try std.testing.expectEqualStrings("s3cret", (try parseWorkflow(ar, "::add-mask::s3cret", null)).add_mask);
    // Leading whitespace goes, trailing whitespace is the data's (`TrimStart`).
    try std.testing.expectEqualStrings("Build  ", (try parseWorkflow(ar, " \t::group::Build  \r", null)).group);
    try std.testing.expect(try parseWorkflow(ar, "::endgroup::", null) == .endgroup);
    try std.testing.expect(try parseWorkflow(ar, "::ENDGROUP::", null) == .endgroup);
    const err = (try parseWorkflow(ar, "::error file=a.js,line=3,title=Oops::two%0Alines 100%25", null)).annotation;
    try std.testing.expectEqualStrings("error", err.level);
    try std.testing.expectEqualStrings("two\nlines 100%", err.message);
    try std.testing.expectEqualStrings("a.js", err.file.?);
    try std.testing.expectEqualStrings("3", err.line.?);
    try std.testing.expectEqualStrings("Oops", err.title.?);
    try std.testing.expect(err.end_line == null and err.col == null);
    try std.testing.expectEqualStrings("warning", (try parseWorkflow(ar, "::warning::w", null)).annotation.level);
    try std.testing.expectEqualStrings("d", (try parseWorkflow(ar, "::debug::d", null)).debug);
    const out = (try parseWorkflow(ar, "::set-output name=a%3Ab::v%0A2", null)).set_output;
    try std.testing.expectEqualStrings("a:b", out.name);
    try std.testing.expectEqualStrings("v\n2", out.value);
    try std.testing.expectEqualStrings("isPost", (try parseWorkflow(ar, "::save-state name=isPost::true", null)).save_state.name);
    try std.testing.expect(try parseWorkflow(ar, "::set-output::no name", null) == .none);
    const set_env = (try parseWorkflow(ar, "::set-env name=X::1%0A2", null)).set_env;
    try std.testing.expectEqualStrings("X", set_env.name.?);
    try std.testing.expectEqualStrings("1\n2", set_env.value);
    try std.testing.expect((try parseWorkflow(ar, "::set-env::1", null)).set_env.name == null);
    try std.testing.expectEqualStrings("/opt/bin", (try parseWorkflow(ar, "::ADD-PATH::/opt/bin", null)).add_path);
    try std.testing.expectEqualStrings("on", (try parseWorkflow(ar, "::echo::on", null)).echo);
    // stop-commands: everything is plain text until the token comes back
    try std.testing.expectEqualStrings("tok123", (try parseWorkflow(ar, "::stop-commands::tok123", null)).stop);
    try std.testing.expectEqualStrings("", (try parseWorkflow(ar, "::stop-commands::", null)).stop);
    try std.testing.expect(try parseWorkflow(ar, "::add-mask::x", "tok123") == .none);
    try std.testing.expect(try parseWorkflow(ar, "::tok123::", "tok123") == .resume_commands);
    // The token is matched as a command name: any case, any properties or data.
    try std.testing.expect(try parseWorkflow(ar, "::TOK123 x=1::y", "tok123") == .resume_commands);
    try std.testing.expect(try parseWorkflow(ar, "::tok1234::", "tok123") == .none);
}

test "the legacy ##[command] syntax, anywhere in a line, with its own separator and escapes" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const err = (try parseWorkflow(ar, "build: ##[error file=a.c;line=3]bad%5D%3B 100%25", null)).annotation;
    try std.testing.expectEqualStrings("error", err.level);
    try std.testing.expectEqualStrings("bad]; 100%", err.message);
    try std.testing.expectEqualStrings("a.c", err.file.?);
    try std.testing.expectEqualStrings("3", err.line.?);
    try std.testing.expectEqualStrings("Build", (try parseWorkflow(ar, "##[GROUP]Build", null)).group);
    try std.testing.expectEqualStrings("s3cret", (try parseWorkflow(ar, "##[add-mask]s3cret", null)).add_mask);
    try std.testing.expectEqualStrings("k", (try parseWorkflow(ar, "##[set-output name=k]v", null)).set_output.name);
    // Not a registered command, or not closed: output.
    try std.testing.expect(try parseWorkflow(ar, "##[section]Starting", null) == .none);
    try std.testing.expect(try parseWorkflow(ar, "##[error unclosed", null) == .none);
    // The `::` form comes first; a line that is not one is read for the legacy form.
    try std.testing.expectEqualStrings("w", (try parseWorkflow(ar, "::nope::##[warning]w", null)).annotation.message);
    // While stopped, the token resumes in either form, and commands are output.
    try std.testing.expect(try parseWorkflow(ar, "##[tok123]", "tok123") == .resume_commands);
    try std.testing.expect(try parseWorkflow(ar, "##[error]x", "tok123") == .none);
}

test "command data and property names as GitHub's ActionCommand reads them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Trailing whitespace is part of the data, in an output's value too.
    const out = (try parseWorkflow(ar, "::set-output name=v::a b  ", null)).set_output;
    try std.testing.expectEqualStrings("a b  ", out.value);
    try std.testing.expectEqualStrings("msg ", (try parseWorkflow(ar, "::warning::msg ", null)).annotation.message);
    // Property names in any case; the list is trimmed as a whole, each name is not.
    const err = (try parseWorkflow(ar, "::error FILE=a.js,EndLine=4,Title=T  ::m", null)).annotation;
    try std.testing.expectEqualStrings("a.js", err.file.?);
    try std.testing.expectEqualStrings("4", err.end_line.?);
    try std.testing.expectEqualStrings("T", err.title.?);
    const spaced = (try parseWorkflow(ar, "::error file=a.js, line=3::m", null)).annotation;
    try std.testing.expect(spaced.line == null);
    try std.testing.expectEqualStrings("k", (try parseWorkflow(ar, "::SET-OUTPUT NAME=k::v", null)).set_output.name);
    try std.testing.expectEqualStrings("X", (try parseWorkflow(ar, "::set-env Name=X::1", null)).set_env.name.?);
    try std.testing.expectEqualStrings("o", (try parseWorkflow(ar, "::remove-matcher OWNER=o::", null)).remove_matcher);
    // The last of a name wins; an empty value is no value; `=`s around the name are skipped
    // (`Split('=', 2, RemoveEmptyEntries)`).
    const twice = (try parseWorkflow(ar, "::error title=one,TITLE=two,file=,=line,col==5::m", null)).annotation;
    try std.testing.expectEqualStrings("two", twice.title.?);
    try std.testing.expect(twice.file == null and twice.line == null);
    try std.testing.expectEqualStrings("5", twice.col.?);
    // The legacy form compares names alike, and does not trim its property list.
    const legacy = (try parseWorkflow(ar, "##[error File=a.c; line=3]m ", null)).annotation;
    try std.testing.expectEqualStrings("a.c", legacy.file.?);
    try std.testing.expect(legacy.line == null);
    try std.testing.expectEqualStrings("m ", legacy.message);
}

test "stop-commands tokens GitHub refuses" {
    for ([_][]const u8{ "", "pause-logging", "Add-Mask", "stop-commands", "endgroup" }) |t|
        try std.testing.expect(stopTokenRefused(t));
    for ([_][]const u8{ "tok123", "a1b2c3d4e5", "groups" }) |t|
        try std.testing.expect(!stopTokenRefused(t));
}

test "add-matcher and remove-matcher" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();

    // As actions/setup-node writes it, path relative to the action's own directory.
    const add = try parseWorkflow(ar, "::add-matcher::/home/runner/work/_actions/actions/setup-node/v4/.github/tsc.json", null);
    try std.testing.expectEqualStrings("/home/runner/work/_actions/actions/setup-node/v4/.github/tsc.json", add.add_matcher);

    // The owner is a property of the command, not its data.
    const remove = try parseWorkflow(ar, "::remove-matcher owner=eslint-stylish::", null);
    try std.testing.expectEqualStrings("eslint-stylish", remove.remove_matcher);

    // Neither without what it needs.
    try std.testing.expect(try parseWorkflow(ar, "::add-matcher::", null) == .none);
    try std.testing.expect(try parseWorkflow(ar, "::remove-matcher::", null) == .none);
    try std.testing.expect(try parseWorkflow(ar, "::remove-matcher owner=::", null) == .none);

    // And not while commands are stopped.
    try std.testing.expect(try parseWorkflow(ar, "::add-matcher::x.json", "tok") == .none);
    // A one-byte path is a path.
    try std.testing.expectEqualStrings("m", (try parseWorkflow(ar, "::add-matcher::m", null)).add_matcher);
}

test "escapes: %3A and %2C only in property values, and an escape cut short is kept as written" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const w = (try parseWorkflow(ar, "::warning title=x%3Ay%2Cz%25::a%3Ab%2Cc%25d%0Ae", null)).annotation;
    try std.testing.expectEqualStrings("x:y,z%", w.title.?);
    try std.testing.expectEqualStrings("a%3Ab%2Cc%d\ne", w.message);
    // At the end of the data, a `%` with fewer than two bytes after it is no escape.
    for ([_][]const u8{ "end%", "end%2", "end%0" }) |m| {
        const line = try std.fmt.allocPrint(ar, "::warning::{s}", .{m});
        try std.testing.expectEqualStrings(m, (try parseWorkflow(ar, line, null)).annotation.message);
    }
    // A command starts the line (after whitespace), or there is none.
    try std.testing.expect(try parseWorkflow(ar, "x ::warning::m", null) == .none);
    try std.testing.expect(try parseWorkflow(ar, "x:warning::m", null) == .none);
    try std.testing.expectEqualStrings("m", (try parseWorkflow(ar, "  ::warning::m", null)).annotation.message);
}

test "GITHUB_PATH: one directory a line, trimmed, a one-byte one too" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const got = try parsePaths(a.allocator(), " /\n\n/opt/bin \r\n");
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("/", got[0]);
    try std.testing.expectEqualStrings("/opt/bin", got[1]);
}
