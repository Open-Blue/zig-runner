//! The runner's own warnings and errors, in one format that a grep or an alert can key on:
//!
//!     warn: kind=cgroup_not_removed path=/sys/fs/cgroup/x err=Busy
//!     error: kind=upload_failed job=123 name='Set up job' detail=NameServerFailure
//!
//! `warn:` or `error:`, then `kind=` (a short snake_case name for what happened) and `key=value`
//! pairs. A value with a space, a quote, an `=` or a control character is double-quoted with `\"`,
//! `\\`, `\n` and `\xNN` escapes, so a line is always one line and a value never reads as a key.
//! The lines of `health:`, `job-end:`, `step-end:` and `request:` are not warnings and keep their
//! own formats, and a line shown to the user inside a job's log stays as GitHub shows it.
//!
//! Three ways in:
//! - `warn` and `err` for code that logs through `std.log` (the process's `logFn`, `logFn` here,
//!   writes the line);
//! - `line` for code that writes to a `Writer` (the runner's stderr, `Runner.err`);
//! - a plain `std.log.warn("native: cannot remove {s}", …)` still works: `logFn` gives it
//!   `kind=native msg="cannot remove …"`, taking the kind from its leading `word:`.
const std = @import("std");

pub const Level = enum {
    warn,
    err,

    pub fn text(l: Level) []const u8 {
        return switch (l) {
            .warn => "warn",
            .err => "error",
        };
    }
};

/// A value for `{f}`: as it is when it is plain, quoted when it is not (see the file's comment).
pub const Value = struct {
    s: []const u8,

    pub fn format(v: Value, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (plain(v.s)) return w.writeAll(v.s);
        try w.writeByte('"');
        for (v.s) |ch| switch (ch) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...31, 127 => try w.print("\\x{x:0>2}", .{ch}),
            else => try w.writeByte(ch),
        };
        try w.writeByte('"');
    }

    fn plain(s: []const u8) bool {
        if (s.len == 0) return false;
        for (s) |ch| if (ch <= ' ' or ch == '"' or ch == '=' or ch == '\\' or ch == 127) return false;
        return true;
    }
};

/// `{f}` with `q(text)`: the value as above.
pub fn q(s: []const u8) Value {
    return .{ .s = s };
}

fn joined(comptime kind: []const u8, comptime fmt: []const u8) []const u8 {
    return "kind=" ++ kind ++ if (fmt.len == 0) "" else " " ++ fmt;
}

/// One line, with its newline, to `w`: `warn: kind=<kind> <fmt>`, `fmt` being the pairs.
pub fn line(
    w: *std.Io.Writer,
    comptime level: Level,
    comptime kind: []const u8,
    comptime fmt: []const u8,
    args: anytype,
) std.Io.Writer.Error!void {
    try w.writeAll(comptime level.text() ++ ": ");
    try w.print(comptime joined(kind, fmt) ++ "\n", args);
}

/// The line without its newline, in `buf` (cut if `buf` is too short), for a sink that ends lines
/// itself (`Runner.log.say`).
pub fn bufLine(
    buf: []u8,
    comptime level: Level,
    comptime kind: []const u8,
    comptime fmt: []const u8,
    args: anytype,
) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    line(&w, level, kind, fmt, args) catch return w.buffered();
    return std.mem.trimEnd(u8, w.buffered(), "\n");
}

/// A warning through `std.log`.
pub fn warn(comptime kind: []const u8, comptime fmt: []const u8, args: anytype) void {
    std.log.warn(joined(kind, fmt), args);
}

/// An error through `std.log`.
pub fn err(comptime kind: []const u8, comptime fmt: []const u8, args: anytype) void {
    std.log.err(joined(kind, fmt), args);
}

/// The longest a leading `word:` can be and still name the kind of a plain message.
const kind_max = 32;

/// `message` (what a call of `std.log` formatted) as a line, with its newline. A message that
/// starts with `kind=` is the pairs already; any other is `kind=<its leading word> msg=<the rest>`
/// when it starts with a short `word:` ("native: cannot remove /x" is `kind=native msg="cannot
/// remove /x"`), and `kind=log msg=<all of it>` otherwise.
pub fn compose(w: *std.Io.Writer, level: Level, message: []const u8) std.Io.Writer.Error!void {
    try w.print("{s}: ", .{level.text()});
    if (std.mem.startsWith(u8, message, "kind=")) {
        try w.writeAll(message);
        return w.writeByte('\n');
    }
    if (std.mem.indexOf(u8, message, ": ")) |at| if (at <= kind_max and kindWord(message[0..at])) {
        try w.writeAll("kind=");
        for (message[0..at]) |ch| try w.writeByte(if (ch == ' ' or ch == '-') '_' else std.ascii.toLower(ch));
        return w.print(" msg={f}\n", .{q(message[at + 2 ..])});
    };
    try w.print("kind=log msg={f}\n", .{q(message)});
}

fn kindWord(s: []const u8) bool {
    var spaces: usize = 0;
    for (s) |ch| {
        if (ch == ' ') spaces += 1 else if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_') return false;
    }
    return s.len > 0 and spaces <= 3 and s[0] != ' ' and s[s.len - 1] != ' ';
}

/// `std_options.logFn`: warnings and errors as `compose` says, on stderr; the lower levels as Zig's
/// own log function writes them.
pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    const l: Level = switch (level) {
        .warn => .warn,
        .err => .err,
        .info, .debug => return std.log.defaultLog(level, scope, format, args),
    };
    // On the stack, so that it is said however little memory the machine has left. A message
    // longer than this is cut.
    var msg_buf: [1024]u8 = undefined;
    var m: std.Io.Writer = .fixed(&msg_buf);
    if (scope != .default) m.print("kind={t} ", .{scope}) catch {};
    m.print(format, args) catch {};
    var out_buf: [2200]u8 = undefined;
    var o: std.Io.Writer = .fixed(&out_buf);
    compose(&o, l, m.buffered()) catch {
        // The line did not fit once quoted: cut the end of it, and end it.
        o.end = out_buf.len - 1;
        out_buf[o.end] = '\n';
        o.end += 1;
    };

    const io = std.Options.debug_io;
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);
    var buffer: [64]u8 = undefined;
    const stderr = std.debug.lockStderr(&buffer).terminal();
    defer std.debug.unlockStderr();
    stderr.writer.writeAll(o.buffered()) catch {};
}

fn expectLine(expected: []const u8, comptime level: Level, comptime kind: []const u8, comptime fmt: []const u8, args: anytype) !void {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try line(&w, level, kind, fmt, args);
    try std.testing.expectEqualStrings(expected, w.buffered());
}

test "a line: the level, kind=, then the pairs" {
    try expectLine("warn: kind=fd_leak job=7 delta=+3\n", .warn, "fd_leak", "job={d} delta=+{d}", .{ 7, 3 });
    try expectLine("error: kind=runner_stopped err=Canceled\n", .err, "runner_stopped", "err={t}", .{error.Canceled});
    try expectLine("warn: kind=no_pairs\n", .warn, "no_pairs", "", .{});
}

test "a line without its newline, for a sink" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("error: kind=k n=3", bufLine(&buf, .err, "k", "n={d}", .{3}));
    var small: [12]u8 = undefined;
    try std.testing.expectEqualStrings("warn: kind=k", bufLine(&small, .warn, "k", "n={d}", .{3}));
}

test "a value is bare when plain and quoted when not, on one line" {
    try expectLine("warn: kind=k path=/a/b-c.d:1 err=Busy\n", .warn, "k", "path={f} err={f}", .{ q("/a/b-c.d:1"), q("Busy") });
    try expectLine("warn: kind=k v=\"\"\n", .warn, "k", "v={f}", .{q("")});
    try expectLine("warn: kind=k v=\"two words\"\n", .warn, "k", "v={f}", .{q("two words")});
    try expectLine("warn: kind=k v=\"a=b\"\n", .warn, "k", "v={f}", .{q("a=b")});
    try expectLine("warn: kind=k v=\"say \\\"x\\\" \\\\ y\"\n", .warn, "k", "v={f}", .{q("say \"x\" \\ y")});
    try expectLine("warn: kind=k v=\"a\\nb\\x01c\\x7f\"\n", .warn, "k", "v={f}", .{q("a\nb\x01c\x7f")});
}

fn expectComposed(expected: []const u8, level: Level, message: []const u8) !void {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try compose(&w, level, message);
    try std.testing.expectEqualStrings(expected, w.buffered());
}

test "a plain std.log message: its leading word is the kind" {
    try expectComposed("warn: kind=native msg=\"cannot remove /x: FileNotFound\"\n", .warn, "native: cannot remove /x: FileNotFound");
    try expectComposed("warn: kind=zig_seed msg=\"1.2 not seeded\"\n", .warn, "Zig seed: 1.2 not seeded");
    try expectComposed("error: kind=http msg=x\n", .err, "http: x");
    try expectComposed("warn: kind=log msg=\"health line not written\"\n", .warn, "health line not written");
    // A prefix that is no word (a path, a flag with a value) is not a kind.
    try expectComposed("error: kind=log msg=\"--a=b: the variant is root\"\n", .err, "--a=b: the variant is root");
    try expectComposed("warn: kind=log msg=\"a b c d e f: x\"\n", .warn, "a b c d e f: x");
    // One that has pairs already is kept as it is.
    try expectComposed("warn: kind=k a=1\n", .warn, "kind=k a=1");
    // A message with a newline stays on one line.
    try expectComposed("warn: kind=native msg=\"a\\nb\"\n", .warn, "native: a\nb");
}
