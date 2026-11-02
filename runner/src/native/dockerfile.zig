//! A Dockerfile interpreter for Docker actions on the native backend (docs/native-backend.md, P7):
//! the instructions actions use (`FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `ENTRYPOINT`,
//! `CMD`, `ARG`, `USER`, `LABEL`), each a keyed step of a build, as BuildKit keys its own.
//!
//! `parse` reads the file as Docker's parser does (comments, parser directives, `\` continuations,
//! instruction words in any case, JSON and shell forms); `plan` evaluates it: substitutions in the
//! instructions Docker substitutes, the image config the instructions leave (what
//! `images.Image` carries), and a key per instruction chained from the base image's,
//! `key = sha256(parent key, instruction as evaluated, what it reads)`, where what it reads is the
//! build arguments in effect for `RUN` and the content of the sources for `COPY` and `ADD`
//! (`contextDigest`). An instruction that changes only the config gets a key and no layer, so a
//! later `RUN` that sees it is keyed on it. `build` makes the layers that are not in the store
//! yet (`layers.zig`): `COPY` and `ADD` by the runner, `RUN` through `Runner`, the sandbox.
//!
//! What it refuses, with the reason, so the action fails as a build that cannot run would:
//! multi-stage builds (`FROM ... AS`, `COPY --from`), `ADD` from a URL or of an archive,
//! wildcards in sources, `SHELL`, `ONBUILD`, and heredocs. Metadata Docker records but a Docker
//! action never uses (`EXPOSE`, `VOLUME`, `STOPSIGNAL`, `HEALTHCHECK`, `MAINTAINER`) is accepted
//! and ignored.

const std = @import("std");
const images = @import("images.zig");
const layers = @import("layers.zig");

const Allocator = std.mem.Allocator;

pub const Kind = enum { from, run, copy, add, env, workdir, entrypoint, cmd, arg, user, label, ignored };

pub const Instruction = struct {
    kind: Kind,
    /// The text after the instruction's word, continuations joined.
    text: []const u8,
    /// The JSON form's words (`["a", "b"]`), when the text is one.
    json: ?[]const []const u8 = null,
    line: u32,
};

/// Why a Dockerfile cannot be built natively, with its line.
pub const Refusal = struct { line: u32, why: []const u8 };

pub const Parsed = union(enum) { ok: []const Instruction, refused: Refusal };

pub fn parse(arena: Allocator, text: []const u8) !Parsed {
    var out: std.ArrayList(Instruction) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: u32 = 0;
    var directives = true;
    while (lines.next()) |raw| {
        n += 1;
        const first_line = n;
        var line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (line[0] == '#') {
            // `# syntax=...` and `# escape=...` only before the first instruction.
            if (directives) if (directive(line)) |d| {
                if (std.ascii.eqlIgnoreCase(d.name, "escape") and !std.mem.eql(u8, d.value, "\\"))
                    return .{ .refused = .{ .line = n, .why = "an escape character other than `\\`" } };
            };
            continue;
        }
        directives = false;
        var joined: std.ArrayList(u8) = .empty;
        while (std.mem.endsWith(u8, line, "\\")) {
            try joined.appendSlice(arena, line[0 .. line.len - 1]);
            // A continuation's comment lines and empty lines are dropped, as Docker drops them.
            line = while (lines.next()) |more| {
                n += 1;
                const t = std.mem.trim(u8, more, " \t\r");
                if (t.len == 0 or t[0] == '#') continue;
                break t;
            } else "";
        }
        try joined.appendSlice(arena, line);
        const full = std.mem.trim(u8, joined.items, " \t");
        const end = std.mem.indexOfAny(u8, full, " \t") orelse full.len;
        const word = full[0..end];
        const rest = std.mem.trim(u8, full[end..], " \t");
        if (std.mem.startsWith(u8, rest, "<<"))
            return .{ .refused = .{ .line = first_line, .why = "heredocs are not native yet" } };
        const kind = kindOf(word) orelse return .{ .refused = .{
            .line = first_line,
            .why = try std.fmt.allocPrint(arena, "`{s}` is not native yet", .{word}),
        } };
        try out.append(arena, .{ .kind = kind, .text = rest, .json = jsonForm(arena, rest), .line = first_line });
    }
    if (out.items.len == 0 or out.items[0].kind != .from and out.items[0].kind != .arg)
        return .{ .refused = .{ .line = 1, .why = "a Dockerfile starts with FROM (after ARG)" } };
    return .{ .ok = out.items };
}

fn directive(line: []const u8) ?struct { name: []const u8, value: []const u8 } {
    const body = std.mem.trim(u8, line[1..], " \t");
    const eq = std.mem.indexOfScalar(u8, body, '=') orelse return null;
    const name = std.mem.trim(u8, body[0..eq], " \t");
    for (name) |c| if (!std.ascii.isAlphabetic(c)) return null;
    return .{ .name = name, .value = std.mem.trim(u8, body[eq + 1 ..], " \t") };
}

fn kindOf(word: []const u8) ?Kind {
    const known = [_]struct { []const u8, Kind }{
        .{ "from", .from },             .{ "run", .run },            .{ "copy", .copy },
        .{ "add", .add },               .{ "env", .env },            .{ "workdir", .workdir },
        .{ "entrypoint", .entrypoint }, .{ "cmd", .cmd },            .{ "arg", .arg },
        .{ "user", .user },             .{ "label", .label },        .{ "expose", .ignored },
        .{ "volume", .ignored },        .{ "stopsignal", .ignored }, .{ "healthcheck", .ignored },
        .{ "maintainer", .ignored },
    };
    for (known) |k| if (std.ascii.eqlIgnoreCase(word, k[0])) return k[1];
    return null;
}

/// The words of a JSON array of strings; null for anything else, which is the shell form.
fn jsonForm(arena: Allocator, text: []const u8) ?[]const []const u8 {
    if (!std.mem.startsWith(u8, text, "[")) return null;
    return std.json.parseFromSliceLeaky([]const []const u8, arena, text, .{}) catch null;
}

/// Docker's substitution in `text` from `vars` (later entries win): `$NAME`, `${NAME}`,
/// `${NAME:-word}` and `${NAME:+word}`, and `\$` for a literal dollar. An unset name is empty.
pub fn substitute(arena: Allocator, text: []const u8, vars: []const Var) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < text.len) {
        const c = text[i];
        if (c == '\\' and i + 1 < text.len and text[i + 1] == '$') {
            try out.append(arena, '$');
            i += 2;
            continue;
        }
        if (c != '$' or i + 1 >= text.len) {
            try out.append(arena, c);
            i += 1;
            continue;
        }
        if (text[i + 1] == '{') {
            const close = std.mem.indexOfScalarPos(u8, text, i + 2, '}') orelse {
                try out.appendSlice(arena, text[i..]);
                break;
            };
            const inner = text[i + 2 .. close];
            i = close + 1;
            if (std.mem.indexOf(u8, inner, ":-")) |op| {
                const v = lookup(vars, inner[0..op]);
                try out.appendSlice(arena, if (v != null and v.?.len > 0) v.? else inner[op + 2 ..]);
            } else if (std.mem.indexOf(u8, inner, ":+")) |op| {
                const v = lookup(vars, inner[0..op]);
                if (v != null and v.?.len > 0) try out.appendSlice(arena, inner[op + 2 ..]);
            } else try out.appendSlice(arena, lookup(vars, inner) orelse "");
            continue;
        }
        var end = i + 1;
        while (end < text.len and (std.ascii.isAlphanumeric(text[end]) or text[end] == '_')) end += 1;
        if (end == i + 1) {
            try out.append(arena, c);
            i += 1;
            continue;
        }
        try out.appendSlice(arena, lookup(vars, text[i + 1 .. end]) orelse "");
        i = end;
    }
    return out.items;
}

pub const Var = struct { name: []const u8, value: []const u8 };

fn lookup(vars: []const Var, name: []const u8) ?[]const u8 {
    var i = vars.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, vars[i].name, name)) return vars[i].value;
    }
    return null;
}

fn put(arena: Allocator, list: *std.ArrayList(Var), name: []const u8, value: []const u8) !void {
    for (list.items) |*v| if (std.mem.eql(u8, v.name, name)) {
        v.value = value;
        return;
    };
    try list.append(arena, .{ .name = name, .value = value });
}

/// `NAME=value ...` pairs (values may be quoted), or the legacy `NAME value` form of ENV and
/// LABEL.
fn pairs(arena: Allocator, text: []const u8) ![]const Var {
    var out: std.ArrayList(Var) = .empty;
    const first_space = std.mem.indexOfAny(u8, text, " \t") orelse text.len;
    if (std.mem.indexOfScalar(u8, text[0..first_space], '=') == null) {
        try out.append(arena, .{
            .name = text[0..first_space],
            .value = std.mem.trim(u8, text[first_space..], " \t"),
        });
        return out.items;
    }
    for (try words(arena, text)) |w| {
        const eq = std.mem.indexOfScalar(u8, w, '=') orelse continue;
        try out.append(arena, .{ .name = w[0..eq], .value = w[eq + 1 ..] });
    }
    return out.items;
}

/// Splits at unquoted whitespace, with double and single quotes grouping (and removed) and `\`
/// escaping the next byte, as Docker reads ENV, LABEL, ARG and COPY's arguments.
fn words(arena: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var cur: std.ArrayList(u8) = .empty;
    var quote: u8 = 0;
    var in_word = false;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '\\' and i + 1 < text.len and quote != '\'') {
            i += 1;
            try cur.append(arena, text[i]);
            in_word = true;
        } else if (quote != 0) {
            if (c == quote) quote = 0 else try cur.append(arena, c);
        } else if (c == '"' or c == '\'') {
            quote = c;
            in_word = true;
        } else if (c == ' ' or c == '\t') {
            if (in_word) try out.append(arena, try cur.toOwnedSlice(arena));
            in_word = false;
        } else {
            try cur.append(arena, c);
            in_word = true;
        }
    }
    if (in_word) try out.append(arena, try cur.toOwnedSlice(arena));
    return out.items;
}

/// One step of a build: its key, and the layer it makes, if any.
pub const Step = struct {
    key: [64]u8,
    line: u32,
    op: Op,

    pub const Op = union(enum) {
        /// Only the config changed: no layer.
        none,
        run: struct {
            argv: []const []const u8,
            /// `NAME=value`: the image's env, then the build arguments in effect.
            env: []const []const u8,
            workdir: []const u8,
            user: []const u8,
        },
        copy: struct {
            /// Relative to the build context, checked to stay inside it.
            sources: []const []const u8,
            dest: []const u8,
            /// `--chown` as written ("" for root) and `--chmod` (null to keep the source's).
            chown: []const u8,
            chmod: ?u32,
        },
    };
};

pub const Plan = struct {
    /// The base image's reference, after ARG substitution.
    base: []const u8,
    steps: []const Step,
    /// The config the image is left with (its `rootfs` is the built layers').
    config: images.Image,
};

pub const Planned = union(enum) { ok: Plan, refused: Refusal };

/// Reads a build context's files for `COPY`'s key: `digest` of the sources named.
pub const Context = struct {
    ptr: *anyopaque,
    digestFn: *const fn (ptr: *anyopaque, arena: Allocator, sources: []const []const u8) anyerror![64]u8,
};

/// Evaluates `instructions` over the base image's config (`base_config`, its `rootfs` unused),
/// with `build_args` given to the build (`--build-arg`, which Docker actions never get, so
/// usually none).
pub fn plan(
    arena: Allocator,
    instructions: []const Instruction,
    base_config: images.Image,
    build_args: []const Var,
    context: Context,
) !Planned {
    var args: std.ArrayList(Var) = .empty;
    var i: usize = 0;
    // ARGs before FROM are in scope for FROM only.
    while (instructions[i].kind == .arg) : (i += 1) {
        for (try argDecls(arena, instructions[i].text, build_args)) |v| try put(arena, &args, v.name, v.value);
    }
    const from = instructions[i];
    if (from.kind != .from) return refuse(from.line, "a Dockerfile starts with FROM (after ARG)");
    const from_words = try words(arena, try substitute(arena, from.text, args.items));
    if (from_words.len != 1) return refuse(from.line, "multi-stage builds (`FROM ... AS`) and " ++
        "`--platform` are not native yet");
    const base = from_words[0];
    if (std.mem.eql(u8, base, "scratch")) return refuse(from.line, "`FROM scratch` is not native yet");

    var cfg = base_config;
    var env: std.ArrayList(Var) = .empty;
    for (base_config.env) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        try put(arena, &env, kv[0..eq], kv[eq + 1 ..]);
    }
    var workdir: []const u8 = "/";
    args.clearRetainingCapacity();
    var key = sha(&.{ "FROM", try images.normalize(arena, base) });
    var steps: std.ArrayList(Step) = .empty;
    for (instructions[i + 1 ..]) |ins| {
        // What substitution sees: the build arguments, then the env, which wins.
        const scope = try std.mem.concat(arena, Var, &.{ args.items, env.items });
        var op: Step.Op = .none;
        var evaluated: []const u8 = ins.text;
        var reads: []const u8 = "";
        switch (ins.kind) {
            .from => return refuse(ins.line, "multi-stage builds are not native yet"),
            .ignored => continue,
            .arg => for (try argDecls(arena, try substitute(arena, ins.text, scope), build_args)) |v|
                try put(arena, &args, v.name, v.value),
            .env => {
                evaluated = try substitute(arena, ins.text, scope);
                for (try pairs(arena, evaluated)) |v| try put(arena, &env, v.name, v.value);
            },
            .label => evaluated = try substitute(arena, ins.text, scope),
            .workdir => {
                const w = try substitute(arena, ins.text, scope);
                workdir = try std.fs.path.resolvePosix(arena, &.{ workdir, w });
                evaluated = workdir;
            },
            .user => {
                evaluated = try substitute(arena, ins.text, scope);
                cfg.user = evaluated;
            },
            .entrypoint => {
                cfg.entrypoint = try command(arena, ins);
                // ENTRYPOINT resets a CMD the base image set, as Docker does.
                cfg.cmd = &.{};
            },
            .cmd => cfg.cmd = try command(arena, ins),
            .run => {
                var run_env: std.ArrayList([]const u8) = .empty;
                for (env.items) |v| try run_env.append(arena, try std.fmt.allocPrint(arena, "{s}={s}", .{ v.name, v.value }));
                for (args.items) |v| if (lookup(env.items, v.name) == null)
                    try run_env.append(arena, try std.fmt.allocPrint(arena, "{s}={s}", .{ v.name, v.value }));
                op = .{ .run = .{
                    .argv = try command(arena, ins),
                    .env = run_env.items,
                    .workdir = workdir,
                    .user = cfg.user,
                } };
                // A RUN's result depends on the build arguments it sees, as BuildKit keys it.
                reads = try std.mem.join(arena, "\x00", run_env.items);
            },
            .copy, .add => {
                const ws = try words(arena, try substitute(arena, ins.text, scope));
                var chown: []const u8 = "";
                var chmod: ?u32 = null;
                var rest: std.ArrayList([]const u8) = .empty;
                for (ws) |w| {
                    if (std.mem.startsWith(u8, w, "--chown=")) chown = w["--chown=".len..] //
                    else if (std.mem.startsWith(u8, w, "--chmod=")) chmod = std.fmt.parseInt(u32, w["--chmod=".len..], 8) catch
                        return refuse(ins.line, "`--chmod` takes an octal mode") //
                    else if (std.mem.startsWith(u8, w, "--")) return refuse(ins.line, try std.fmt.allocPrint(arena, "`{s}` is not native yet", .{w})) //
                    else try rest.append(arena, w);
                }
                if (ins.json) |j| {
                    rest.clearRetainingCapacity();
                    for (j) |w| try rest.append(arena, try substitute(arena, w, scope));
                }
                if (rest.items.len < 2) return refuse(ins.line, "COPY and ADD need a source and a destination");
                const sources = rest.items[0 .. rest.items.len - 1];
                for (sources) |src| {
                    if (std.mem.indexOfAny(u8, src, "*?[") != null)
                        return refuse(ins.line, "wildcards in COPY and ADD are not native yet");
                    if (ins.kind == .add and (std.mem.indexOf(u8, src, "://") != null or isArchive(src)))
                        return refuse(ins.line, "ADD of a URL or an archive is not native yet");
                    if (!insideContext(src)) return refuse(ins.line, try std.fmt.allocPrint(
                        arena,
                        "{s} is outside the build context",
                        .{src},
                    ));
                }
                const raw_dest = rest.items[rest.items.len - 1];
                const dest = if (std.mem.endsWith(u8, raw_dest, "/"))
                    try std.fmt.allocPrint(arena, "{s}/", .{try std.fs.path.resolvePosix(arena, &.{ workdir, raw_dest })})
                else
                    try std.fs.path.resolvePosix(arena, &.{ workdir, raw_dest });
                op = .{ .copy = .{ .sources = sources, .dest = dest, .chown = chown, .chmod = chmod } };
                const digest = try context.digestFn(context.ptr, arena, sources);
                reads = try arena.dupe(u8, &digest);
                evaluated = try std.fmt.allocPrint(arena, "{s} {s} {s} {?o}", .{
                    try std.mem.join(arena, " ", sources), dest, chown, chmod,
                });
            },
        }
        key = sha(&.{ &key, @tagName(ins.kind), evaluated, reads });
        try steps.append(arena, .{ .key = key, .line = ins.line, .op = op });
    }
    var env_out: std.ArrayList([]const u8) = .empty;
    for (env.items) |v| try env_out.append(arena, try std.fmt.allocPrint(arena, "{s}={s}", .{ v.name, v.value }));
    cfg.env = env_out.items;
    return .{ .ok = .{ .base = base, .steps = steps.items, .config = cfg } };
}

fn refuse(line: u32, why: []const u8) Planned {
    return .{ .refused = .{ .line = line, .why = why } };
}

/// ARG's declarations, each with the build's value when given, else its default.
fn argDecls(arena: Allocator, text: []const u8, build_args: []const Var) ![]const Var {
    var out: std.ArrayList(Var) = .empty;
    for (try words(arena, text)) |w| {
        const eq = std.mem.indexOfScalar(u8, w, '=');
        const name = if (eq) |e| w[0..e] else w;
        const default = if (eq) |e| w[e + 1 ..] else "";
        try out.append(arena, .{ .name = name, .value = lookup(build_args, name) orelse default });
    }
    return out.items;
}

/// RUN's, CMD's and ENTRYPOINT's command: the JSON form's words, or the shell form under
/// `/bin/sh -c`, as Docker runs it.
fn command(arena: Allocator, ins: Instruction) ![]const []const u8 {
    if (ins.json) |j| return j;
    return arena.dupe([]const u8, &.{ "/bin/sh", "-c", ins.text });
}

fn isArchive(src: []const u8) bool {
    for ([_][]const u8{ ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar.zst" }) |ext|
        if (std.mem.endsWith(u8, src, ext)) return true;
    return false;
}

/// A source path stays inside the context: `..` never climbs above it (Docker resolves it so; it
/// is refused here rather than silently clamped).
fn insideContext(src: []const u8) bool {
    var depth: i32 = 0;
    var it = std.mem.tokenizeScalar(u8, src, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "..")) depth -= 1 else if (!std.mem.eql(u8, part, ".")) depth += 1;
        if (depth < 0) return false;
    }
    return true;
}

fn sha(parts: []const []const u8) [64]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (parts) |p| {
        var len: [8]u8 = undefined;
        std.mem.writeInt(u64, &len, p.len, .little);
        h.update(&len);
        h.update(p);
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// A source's place in the context: the directory holding it, reached through no symlink, and its
/// name there ("." for the context itself). `error.SourceMissing` when a part of the way is not a
/// directory (a symlink among them: a source must not lead out of the context).
const Place = struct { dir: std.Io.Dir, name: []const u8, owned: bool };

fn placeOf(arena: Allocator, io: std.Io, root: std.Io.Dir, src: []const u8) !Place {
    const rel = try std.fs.path.resolvePosix(arena, &.{src});
    if (rel.len == 0 or std.mem.eql(u8, rel, ".")) return .{ .dir = root, .name = ".", .owned = false };
    var dir = root;
    var owned = false;
    var parts = std.mem.splitScalar(u8, rel, '/');
    var name = parts.first();
    while (parts.next()) |next| {
        const sub = dir.openDir(io, name, .{ .follow_symlinks = false }) catch return error.SourceMissing;
        if (owned) dir.close(io);
        dir = sub;
        owned = true;
        name = next;
    }
    return .{ .dir = dir, .name = name, .owned = owned };
}

/// The content of `sources` under the directory `context` for a `COPY`'s key: a sorted walk of
/// each source's paths, with each entry's kind, mode bits, link target and file content. No
/// symlink is followed, and a source missing is an error (`error.SourceMissing`).
pub fn contextDigest(arena: Allocator, io: std.Io, context: []const u8, sources: []const []const u8) ![64]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var root = try std.Io.Dir.cwd().openDir(io, context, .{});
    defer root.close(io);
    for (sources) |src| {
        const place = try placeOf(arena, io, root, src);
        defer if (place.owned) place.dir.close(io);
        h.update(try std.fs.path.resolvePosix(arena, &.{src}));
        h.update("\x00");
        try digestEntry(arena, io, place.dir, place.name, &h, 0);
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

fn digestEntry(
    arena: Allocator,
    io: std.Io,
    parent: std.Io.Dir,
    name: []const u8,
    h: *std.crypto.hash.sha2.Sha256,
    depth: u32,
) !void {
    if (depth > 128) return error.ContextTooDeep;
    const st = parent.statFile(io, name, .{ .follow_symlinks = false }) catch return error.SourceMissing;
    var meta: [16]u8 = undefined;
    std.mem.writeInt(u64, meta[0..8], @backingInt(st.kind), .little);
    std.mem.writeInt(u64, meta[8..16], @as(u64, st.permissions.toMode()) & 0o7777, .little);
    h.update(&meta);
    switch (st.kind) {
        .file => h.update(try parent.readFileAlloc(io, name, arena, .limited(1 << 30))),
        .sym_link => {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const n = try parent.readLink(io, name, &buf);
            h.update(buf[0..n]);
        },
        .directory => {
            var dir = try parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
            defer dir.close(io);
            for (try sortedNames(arena, io, dir)) |sub| {
                h.update(sub);
                h.update("\x00");
                try digestEntry(arena, io, dir, sub, h, depth + 1);
            }
        },
        else => {},
    }
    h.update("\x01");
}

fn sortedNames(arena: Allocator, io: std.Io, dir: std.Io.Dir) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |e| try names.append(arena, try arena.dupe(u8, e.name));
    std.mem.sortUnstable([]const u8, names.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    return names.items;
}

/// Runs a `RUN` step: `argv` on the layers `lowers` (top first, the base image's rootfs last),
/// writing into `upper`, as the native sandbox runs a step. Its exit code.
pub const Runner = struct {
    ptr: *anyopaque,
    runFn: *const fn (
        ptr: *anyopaque,
        lowers: []const []const u8,
        upper: []const u8,
        run: @FieldType(Step.Op, "run"),
    ) anyerror!i32,
};

pub const Built = union(enum) {
    /// The image's layers, top first, then the base's rootfs; and its config.
    ok: struct { lowers: []const []const u8, config: images.Image },
    /// A RUN failed: its line and exit code.
    failed: struct { line: u32, code: i32 },
};

/// Makes `p`'s layers on the base image's `rootfs`, each taken from `store` when its key is
/// there, else built and stored: `COPY` and `ADD` by the runner from `context`, `RUN` by `runner`.
pub fn build(
    arena: Allocator,
    io: std.Io,
    p: Plan,
    rootfs: []const u8,
    context: []const u8,
    store: layers.Store,
    runner: Runner,
) !Built {
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(arena, rootfs);
    for (p.steps) |step| {
        if (step.op == .none) continue;
        if (try store.get(arena, io, &step.key)) |layer| {
            try stack.insert(arena, 0, layer);
            continue;
        }
        const upper = try store.begin(arena, io, &step.key);
        errdefer std.Io.Dir.cwd().deleteTree(io, upper) catch {};
        switch (step.op) {
            .none => unreachable,
            .run => |r| {
                const code = try runner.runFn(runner.ptr, stack.items, upper, r);
                if (code != 0) {
                    std.Io.Dir.cwd().deleteTree(io, upper) catch {};
                    return .{ .failed = .{ .line = step.line, .code = code } };
                }
            },
            .copy => |c| try copyInto(arena, io, context, upper, c),
        }
        try stack.insert(arena, 0, try store.publish(arena, io, upper, &step.key));
    }
    return .{ .ok = .{ .lowers = stack.items, .config = p.config } };
}

/// `COPY`'s sources from `context` into the layer `upper`, as Docker places them: a directory's
/// contents (not the directory) into the destination, a file at the destination or, when the
/// destination ends in `/` or there are several sources, into it by its name. Symlinks are
/// copied as symlinks; nothing in the context is followed out of it. The owner is `--chown`'s
/// numeric ids (root without), on the layer's own ids, which the sandbox maps.
fn copyInto(arena: Allocator, io: std.Io, context: []const u8, upper: []const u8, c: @FieldType(Step.Op, "copy")) !void {
    const owner = try parseChown(c.chown);
    var root = try std.Io.Dir.cwd().openDir(io, context, .{});
    defer root.close(io);
    var layer = try std.Io.Dir.cwd().openDir(io, upper, .{});
    defer layer.close(io);
    const into_dir = std.mem.endsWith(u8, c.dest, "/") or c.sources.len > 1;
    const dest = std.mem.trim(u8, c.dest, "/");
    for (c.sources) |src| {
        const place = try placeOf(arena, io, root, src);
        defer if (place.owned) place.dir.close(io);
        const st = place.dir.statFile(io, place.name, .{ .follow_symlinks = false }) catch
            return error.SourceMissing;
        if (st.kind == .directory) {
            var from = try place.dir.openDir(io, place.name, .{ .iterate = true, .follow_symlinks = false });
            defer from.close(io);
            try makeDirs(io, layer, dest, owner);
            var to = if (dest.len == 0) try layer.openDir(io, ".", .{}) else try layer.openDir(io, dest, .{});
            defer to.close(io);
            try copyTree(arena, io, from, to, c.chmod, owner, 0);
        } else {
            const target = if (into_dir)
                try std.fmt.allocPrint(arena, "{s}/{s}", .{ dest, std.fs.path.basenamePosix(place.name) })
            else
                dest;
            const parent = std.fs.path.dirnamePosix(target) orelse "";
            try makeDirs(io, layer, parent, owner);
            var to = if (parent.len == 0) try layer.openDir(io, ".", .{}) else try layer.openDir(io, parent, .{});
            defer to.close(io);
            try copyOne(arena, io, place.dir, place.name, to, std.fs.path.basenamePosix(target), st, c.chmod, owner);
        }
    }
}

const Owner = struct { uid: u32, gid: u32 };

/// `--chown`'s `uid[:gid]`; names would need the image's /etc/passwd, which the build reads only
/// through its layers, so they are refused for now.
fn parseChown(text: []const u8) !Owner {
    if (text.len == 0) return .{ .uid = 0, .gid = 0 };
    const colon = std.mem.indexOfScalar(u8, text, ':');
    const uid = std.fmt.parseInt(u32, text[0 .. colon orelse text.len], 10) catch return error.ChownByName;
    const gid = if (colon) |i| std.fmt.parseInt(u32, text[i + 1 ..], 10) catch return error.ChownByName else uid;
    return .{ .uid = uid, .gid = gid };
}

fn makeDirs(io: std.Io, layer: std.Io.Dir, path: []const u8, owner: Owner) !void {
    if (path.len == 0) return;
    try layer.createDirPath(io, path);
    var d = try layer.openDir(io, path, .{});
    defer d.close(io);
    _ = std.os.linux.fchown(d.handle, owner.uid, owner.gid);
}

fn copyTree(arena: Allocator, io: std.Io, from: std.Io.Dir, to: std.Io.Dir, chmod: ?u32, owner: Owner, depth: u32) !void {
    if (depth > 128) return error.ContextTooDeep;
    for (try sortedNames(arena, io, from)) |name| {
        const st = try from.statFile(io, name, .{ .follow_symlinks = false });
        if (st.kind == .directory) {
            to.createDir(io, name, .default_dir) catch |e| if (e != error.PathAlreadyExists) return e;
            var sub_from = try from.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
            defer sub_from.close(io);
            var sub_to = try to.openDir(io, name, .{ .follow_symlinks = false });
            defer sub_to.close(io);
            _ = std.os.linux.fchmod(sub_to.handle, @intCast(chmod orelse (st.permissions.toMode() & 0o7777)));
            _ = std.os.linux.fchown(sub_to.handle, owner.uid, owner.gid);
            try copyTree(arena, io, sub_from, sub_to, chmod, owner, depth + 1);
        } else try copyOne(arena, io, from, name, to, name, st, chmod, owner);
    }
}

fn copyOne(
    arena: Allocator,
    io: std.Io,
    from: std.Io.Dir,
    name: []const u8,
    to: std.Io.Dir,
    to_name: []const u8,
    st: std.Io.Dir.Stat,
    chmod: ?u32,
    owner: Owner,
) !void {
    const z = try arena.dupeSentinel(u8, to_name, 0);
    switch (st.kind) {
        .sym_link => {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const n = try from.readLink(io, name, &buf);
            to.deleteFile(io, to_name) catch {};
            try to.symLink(io, buf[0..n], to_name, .{});
        },
        .file => {
            const mode: u32 = chmod orelse @intCast(st.permissions.toMode() & 0o7777);
            try from.copyFile(name, to, to_name, io, .{ .permissions = .fromMode(@intCast(mode)) });
            // copyFile's mode passes through the umask; the layer gets the source's own.
            _ = std.os.linux.fchmodat(to.handle, z, @intCast(mode));
        },
        else => return error.UnsupportedSourceKind,
    }
    _ = std.os.linux.fchownat(to.handle, z, owner.uid, owner.gid, std.os.linux.AT.SYMLINK_NOFOLLOW);
}

// --- tests ---

test "parse: comments, directives, continuations, any case, JSON and shell forms" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const parsed = try parse(arena,
        \\# syntax=docker/dockerfile:1
        \\ARG BASE=alpine:3.22
        \\FROM $BASE
        \\# a comment
        \\run apk add --no-cache \
        \\    # dropped inside a continuation
        \\    curl \
        \\    jq
        \\COPY entrypoint.sh /entrypoint.sh
        \\EXPOSE 80
        \\ENTRYPOINT ["/entrypoint.sh"]
    );
    const ins = parsed.ok;
    try std.testing.expectEqual(@as(usize, 6), ins.len);
    try std.testing.expectEqual(Kind.run, ins[2].kind);
    try std.testing.expectEqualStrings("apk add --no-cache curl jq", ins[2].text);
    try std.testing.expectEqual(@as(u32, 5), ins[2].line);
    try std.testing.expectEqual(Kind.ignored, ins[4].kind);
    try std.testing.expectEqualStrings("/entrypoint.sh", ins[5].json.?[0]);
    try std.testing.expect(ins[2].json == null);

    try std.testing.expectEqualStrings("`SHELL` is not native yet", (try parse(arena, "FROM a\nSHELL [\"bash\"]")).refused.why);
    try std.testing.expect((try parse(arena, "RUN true")) == .refused);
    try std.testing.expect((try parse(arena, "FROM a\nRUN <<EOF\ntrue\nEOF")) == .refused);
}

test "substitute: Docker's forms" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const vars = [_]Var{ .{ .name = "A", .value = "x" }, .{ .name = "E", .value = "" }, .{ .name = "A", .value = "y" } };
    try std.testing.expectEqualStrings(
        "y y- z w - $A $",
        try substitute(arena, "$A ${A}- ${E:-z} ${A:+w} ${E:+no}- \\$A $", &vars),
    );
}

const Fixed = struct {
    digest: [64]u8 = @splat('0'),
    fn context(f: *Fixed) Context {
        return .{ .ptr = f, .digestFn = digestOf };
    }
    fn digestOf(ptr: *anyopaque, _: Allocator, _: []const []const u8) anyerror![64]u8 {
        const f: *Fixed = @ptrCast(@alignCast(ptr));
        return f.digest;
    }
};

test "plan: the config the instructions leave, and a key per instruction that changes with what it reads" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const text =
        \\ARG BASE=alpine:3.22
        \\FROM ${BASE}
        \\ARG VERSION=1
        \\ENV TOOL_HOME=/opt/tool PATH="/opt/tool/bin:$PATH"
        \\WORKDIR /opt
        \\WORKDIR tool
        \\RUN echo $VERSION > version
        \\COPY --chmod=755 entrypoint.sh bin/
        \\LABEL maintainer="me"
        \\USER 0
        \\CMD echo default
        \\ENTRYPOINT ["/opt/tool/bin/entrypoint.sh"]
    ;
    const ins = (try parse(arena, text)).ok;
    const base: images.Image = .{ .rootfs = "", .env = &.{"PATH=/usr/bin:/bin"}, .cmd = &.{"/bin/sh"} };
    var ctx: Fixed = .{};
    const p = (try plan(arena, ins, base, &.{}, ctx.context())).ok;
    try std.testing.expectEqualStrings("alpine:3.22", p.base);
    try std.testing.expectEqual(@as(usize, 10), p.steps.len);
    const run = p.steps[4].op.run;
    try std.testing.expectEqualStrings("/opt/tool", run.workdir);
    try std.testing.expectEqualStrings("echo $VERSION > version", run.argv[2]);
    try std.testing.expectEqualStrings("PATH=/opt/tool/bin:/usr/bin:/bin", run.env[0]);
    try std.testing.expectEqualStrings("VERSION=1", run.env[2]);
    const copy = p.steps[5].op.copy;
    try std.testing.expectEqualStrings("/opt/tool/bin/", copy.dest);
    try std.testing.expectEqual(@as(?u32, 0o755), copy.chmod);
    try std.testing.expectEqualStrings("/opt/tool/bin/entrypoint.sh", p.config.entrypoint[0]);
    // ENTRYPOINT after CMD resets it, as Docker does.
    try std.testing.expectEqual(@as(usize, 0), p.config.cmd.len);
    try std.testing.expectEqualStrings("0", p.config.user);
    try std.testing.expectEqualStrings("TOOL_HOME=/opt/tool", p.config.env[1]);

    // A build argument changes the RUN's key and every key after it, not the ones before.
    const p2 = (try plan(arena, ins, base, &.{.{ .name = "VERSION", .value = "2" }}, ctx.context())).ok;
    for (p.steps[0..4], p2.steps[0..4]) |x, y| try std.testing.expectEqualSlices(u8, &x.key, &y.key);
    for (p.steps[4..], p2.steps[4..]) |x, y| try std.testing.expect(!std.mem.eql(u8, &x.key, &y.key));
    // The context's content changes the COPY's key and the later ones only.
    var ctx3: Fixed = .{ .digest = @splat('1') };
    const p3 = (try plan(arena, ins, base, &.{}, ctx3.context())).ok;
    for (p.steps[0..5], p3.steps[0..5]) |x, y| try std.testing.expectEqualSlices(u8, &x.key, &y.key);
    for (p.steps[5..], p3.steps[5..]) |x, y| try std.testing.expect(!std.mem.eql(u8, &x.key, &y.key));

    const Bad = struct { []const u8, []const u8 };
    for ([_]Bad{
        .{ "FROM a AS build", "multi-stage" },
        .{ "FROM a\nFROM b", "multi-stage" },
        .{ "FROM a\nCOPY --from=build /x /y", "--from=build" },
        .{ "FROM a\nCOPY *.sh /", "wildcards" },
        .{ "FROM a\nADD https://x/y /y", "URL" },
        .{ "FROM a\nCOPY ../secret /x", "outside the build context" },
    }) |b| {
        const got = try plan(arena, (try parse(arena, b[0])).ok, base, &.{}, ctx.context());
        try std.testing.expect(std.mem.indexOf(u8, got.refused.why, b[1]) != null);
    }
}

test "contextDigest walks the sources in order, through no symlink" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "ctx/dir");
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/entrypoint.sh", .data = "#!/bin/sh\necho hi\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/dir/b", .data = "b" });
    try tmp.dir.writeFile(io, .{ .sub_path = "outside", .data = "host" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.symLink(io, try std.fmt.allocPrint(arena, "{s}/outside", .{root}), "ctx/dir/link", .{});
    const ctx = try std.fmt.allocPrint(arena, "{s}/ctx", .{root});
    const d1 = try contextDigest(arena, io, ctx, &.{ "entrypoint.sh", "dir" });
    try std.testing.expectEqualSlices(u8, &d1, &(try contextDigest(arena, io, ctx, &.{ "./entrypoint.sh", "dir/" })));
    // The symlink's target's content is not read: changing it changes nothing.
    try tmp.dir.writeFile(io, .{ .sub_path = "outside", .data = "changed" });
    try std.testing.expectEqualSlices(u8, &d1, &(try contextDigest(arena, io, ctx, &.{ "entrypoint.sh", "dir" })));
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/dir/b", .data = "c" });
    try std.testing.expect(!std.mem.eql(u8, &d1, &(try contextDigest(arena, io, ctx, &.{ "entrypoint.sh", "dir" }))));
    try std.testing.expectError(error.SourceMissing, contextDigest(arena, io, ctx, &.{"nope"}));
}

const Recorder = struct {
    arena: Allocator,
    runs: std.ArrayList([]const u8) = .empty,
    lowers_seen: usize = 0,
    fn runner(r: *Recorder) Runner {
        return .{ .ptr = r, .runFn = run };
    }
    fn run(ptr: *anyopaque, lowers: []const []const u8, upper: []const u8, op: @FieldType(Step.Op, "run")) anyerror!i32 {
        const r: *Recorder = @ptrCast(@alignCast(ptr));
        try r.runs.append(r.arena, op.argv[op.argv.len - 1]);
        r.lowers_seen = lowers.len;
        const io = std.testing.io;
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = try std.fmt.allocPrint(r.arena, "{s}/ran", .{upper}), .data = "x" });
        return if (std.mem.indexOf(u8, op.argv[op.argv.len - 1], "exit 3") != null) 3 else 0;
    }
};

test "build: COPY into its layer, RUN through the runner, and a second build takes every layer from the store" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "ctx/lib", "store", "rootfs" }) |d| try tmp.dir.createDirPath(io, d);
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/entrypoint.sh", .data = "#!/bin/sh\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/lib/a.sh", .data = "a" });
    try tmp.dir.symLink(io, "a.sh", "ctx/lib/b.sh", .{});
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const ctx = try std.fmt.allocPrint(arena, "{s}/ctx", .{root});
    const store: layers.Store = .{ .dir = try std.fmt.allocPrint(arena, "{s}/store", .{root}) };
    const rootfs = try std.fmt.allocPrint(arena, "{s}/rootfs", .{root});
    const text =
        \\FROM alpine:3.22
        \\COPY --chmod=755 entrypoint.sh /entrypoint.sh
        \\COPY lib /opt/lib/
        \\RUN echo built
        \\ENTRYPOINT ["/entrypoint.sh"]
    ;
    const Ctx = struct {
        dir: []const u8,
        fn digest(ptr: *anyopaque, ar: Allocator, sources: []const []const u8) anyerror![64]u8 {
            const c: *@This() = @ptrCast(@alignCast(ptr));
            return contextDigest(ar, std.testing.io, c.dir, sources);
        }
    };
    var c: Ctx = .{ .dir = ctx };
    const p = (try plan(arena, (try parse(arena, text)).ok, .{ .rootfs = "" }, &.{}, .{ .ptr = &c, .digestFn = Ctx.digest })).ok;
    var rec: Recorder = .{ .arena = arena };
    const built = (try build(arena, io, p, rootfs, ctx, store, rec.runner())).ok;
    try std.testing.expectEqual(@as(usize, 4), built.lowers.len);
    try std.testing.expectEqualStrings(rootfs, built.lowers[3]);
    try std.testing.expectEqual(@as(usize, 3), rec.lowers_seen);
    try std.testing.expectEqual(@as(usize, 1), rec.runs.items.len);
    const entry = try std.fmt.allocPrint(arena, "{s}/entrypoint.sh", .{built.lowers[2]});
    const st = try std.Io.Dir.cwd().statFile(io, entry, .{});
    try std.testing.expectEqual(@as(u32, 0o755), @as(u32, @intCast(st.permissions.toMode() & 0o777)));
    var buf: [64]u8 = undefined;
    const link = try std.fmt.allocPrint(arena, "{s}/opt/lib/b.sh", .{built.lowers[1]});
    try std.testing.expectEqualStrings("a.sh", buf[0..try std.Io.Dir.cwd().readLink(io, link, &buf)]);
    try std.Io.Dir.cwd().access(io, try std.fmt.allocPrint(arena, "{s}/opt/lib/a.sh", .{built.lowers[1]}), .{});

    // Built again: every layer is the store's, nothing runs.
    var again: Recorder = .{ .arena = arena };
    const second = (try build(arena, io, p, rootfs, ctx, store, again.runner())).ok;
    try std.testing.expectEqual(@as(usize, 0), again.runs.items.len);
    for (built.lowers, second.lowers) |x, y| try std.testing.expectEqualStrings(x, y);

    // A failing RUN stores nothing for its key.
    const bad = (try plan(arena, (try parse(arena, "FROM alpine\nRUN exit 3")).ok, .{ .rootfs = "" }, &.{}, .{ .ptr = &c, .digestFn = Ctx.digest })).ok;
    const failed = (try build(arena, io, bad, rootfs, ctx, store, rec.runner())).failed;
    try std.testing.expectEqual(@as(i32, 3), failed.code);
    try std.testing.expect(try store.get(arena, io, &bad.steps[0].key) == null);
}
