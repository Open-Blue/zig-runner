//! A Dockerfile interpreter for Docker actions on the native backend (docs/native-backend.md, P7):
//! the instructions actions use (`FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `ENTRYPOINT`,
//! `CMD`, `ARG`, `USER`, `LABEL`, `SHELL`), each a keyed step of a build, as BuildKit keys its own.
//!
//! `parse` reads the file as Docker's parser does (comments, parser directives, `\` continuations,
//! instruction words in any case, JSON and shell forms, heredocs); `plan` evaluates it:
//! substitutions in the instructions Docker substitutes, the image config the instructions leave
//! (what `images.Image` carries), and a key per instruction chained from the base image's
//! (`fromKey`, on what the image is, not only its reference: a tag moves), `stepKey`'s
//! `key = sha256(parent key, instruction as evaluated, what it reads)`, where what it reads is the
//! build arguments in effect for `RUN` and the content of the sources for `COPY` and `ADD`
//! (`contextDigest`). An instruction that changes only the config gets a key and no layer, so a
//! later `RUN` that sees it is keyed on it. `build` makes the layers that are not in the store
//! yet (`layers.zig`): `COPY` and `ADD` by the runner, `RUN` through `Runner`, the sandbox.
//! Every preimage is in P8's format (proofs/Runner/Native.lean, `encBuild`).
//!
//! Multi-stage builds are a chain of builds: a stage that starts `FROM` an earlier one continues
//! its keys, and `COPY --from` a stage is keyed on that stage's final key, so a
//! layer the store has is taken without building the stage it copies from (BuildKit must
//! evaluate the stage to checksum what it copies). Only the stages the last one needs are
//! planned and built, as BuildKit builds only those. What a `COPY` reads is a `layer_view.View`
//! of a build context, a stage's layers or an image's filesystem, and what it copies into is
//! the view of the layers so far, so a directory that is there keeps its mode and owner and a
//! link on the way leads where it would in the image.
//!
//! Where it differs from BuildKit, on purpose (docs/native-backend.md lists them): a layer's key
//! holds what the instruction was made from, so an identical prefix of two Dockerfiles, or of
//! two stages, is one set of layers in the store; the layers hold no timestamps of the build.
//!
//! What it refuses, with the reason, so the action fails as a build that cannot run would:
//! `ADD` of an archive (which Docker unpacks) or of a git repository, `ONBUILD`, `FROM` for another
//! platform, `RUN` with `--mount`, `--network` or `--security`, `COPY` with `--parents` or
//! `--exclude`, a heredoc script with a `#!` line, and an escape directive other than `\`.
//! Metadata Docker records but a Docker action never uses (`EXPOSE`, `VOLUME`, `STOPSIGNAL`, `HEALTHCHECK`, `MAINTAINER`) is accepted and ignored.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const images = @import("images.zig");
const layers = @import("layers.zig");
const layer_view = @import("layer_view.zig");
const KeyHasher = @import("Store.zig").KeyHasher;

const Allocator = std.mem.Allocator;
const View = layer_view.View;

pub const Kind = enum { from, run, copy, add, env, workdir, entrypoint, cmd, arg, user, label, shell, ignored };

/// A heredoc's body, as `RUN <<EOF` and `COPY <<EOF /file` carry one.
pub const Heredoc = struct {
    /// The delimiter, which is also the file's name when it is a `COPY`'s source.
    name: []const u8,
    /// The lines between, each with its newline, with a `<<-` heredoc's leading tabs removed.
    body: []const u8,
    /// Whether the content is substituted (`$VAR`): when the delimiter is not quoted.
    expand: bool,
};

pub const Instruction = struct {
    kind: Kind,
    /// The text after the instruction's word, continuations joined.
    text: []const u8,
    /// The JSON form's words (`["a", "b"]`), when the text is one.
    json: ?[]const []const u8 = null,
    /// The heredocs the text names (`<<EOF`), in order; only `RUN`, `COPY` and `ADD` have them.
    heredocs: []const Heredoc = &.{},
    line: u32,
};

/// Why a Dockerfile cannot be built natively, with its line.
pub const Refusal = struct { line: u32, why: []const u8 };

pub const Parsed = union(enum) { ok: []const Instruction, refused: Refusal };

/// Most heredocs one instruction may name.
const max_heredocs = 64;

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
        const kind = kindOf(word) orelse return .{ .refused = .{
            .line = first_line,
            .why = try std.fmt.allocPrint(arena, "`{s}` is not native yet", .{word}),
        } };
        var heredocs: []const Heredoc = &.{};
        if (kind == .run or kind == .copy or kind == .add) {
            const markers = try scanHeredocs(arena, rest);
            if (markers.found.len > max_heredocs) return .{ .refused = .{
                .line = first_line,
                .why = "more heredocs in one instruction than a Dockerfile has a use for",
            } };
            var bodies: std.ArrayList(Heredoc) = .empty;
            for (markers.found) |m| {
                var body: std.ArrayList(u8) = .empty;
                const closed = while (lines.next()) |l| {
                    n += 1;
                    const trimmed = std.mem.trimEnd(u8, l, "\r");
                    const content = if (m.strip_tabs) std.mem.trimStart(u8, trimmed, "\t") else trimmed;
                    if (std.mem.eql(u8, content, m.name)) break true;
                    try body.appendSlice(arena, content);
                    try body.append(arena, '\n');
                } else false;
                if (!closed) return .{ .refused = .{
                    .line = first_line,
                    .why = try std.fmt.allocPrint(arena, "the heredoc `{s}` is never closed", .{m.name}),
                } };
                try bodies.append(arena, .{ .name = m.name, .body = body.items, .expand = m.expand });
            }
            heredocs = bodies.items;
        }
        try out.append(arena, .{
            .kind = kind,
            .text = rest,
            .json = try jsonForm(arena, rest),
            .heredocs = heredocs,
            .line = first_line,
        });
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
        .{ "user", .user },             .{ "label", .label },        .{ "shell", .shell },
        .{ "expose", .ignored },        .{ "volume", .ignored },     .{ "stopsignal", .ignored },
        .{ "healthcheck", .ignored },   .{ "maintainer", .ignored },
    };
    for (known) |k| if (std.ascii.eqlIgnoreCase(word, k[0])) return k[1];
    return null;
}

/// The words of a JSON array of strings; null for anything else, which is the shell form. Out of
/// memory is an error, not null: `ENTRYPOINT ["/run.sh"]` read as shell text runs `["/run.sh"]`
/// through `sh -c`, which is no entrypoint at all.
fn jsonForm(arena: Allocator, text: []const u8) Allocator.Error!?[]const []const u8 {
    if (!std.mem.startsWith(u8, text, "[")) return null;
    return std.json.parseFromSliceLeaky([]const []const u8, arena, text, .{}) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

const Marker = struct { name: []const u8, expand: bool, strip_tabs: bool };

/// The heredocs an instruction's text names, as BuildKit's parser finds them: words (split at
/// whitespace outside quotes) of the form `<<WORD`, `<<-WORD`, `<<"WORD"` or `<<'WORD'`, with
/// an optional file descriptor before (`2<<EOF`); `<<<` and a `<<` with nothing after it are not
/// one. `others` counts the words that are not.
fn scanHeredocs(arena: Allocator, text: []const u8) !struct { found: []const Marker, others: usize } {
    var found: std.ArrayList(Marker) = .empty;
    var others: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        while (i < text.len and (text[i] == ' ' or text[i] == '\t')) i += 1;
        if (i == text.len) break;
        const start = i;
        var quote: u8 = 0;
        while (i < text.len and (quote != 0 or (text[i] != ' ' and text[i] != '\t'))) : (i += 1) {
            if (quote != 0) {
                if (text[i] == quote) quote = 0;
            } else if (text[i] == '"' or text[i] == '\'') quote = text[i];
        }
        const token = text[start..i];
        var t = std.mem.trimStart(u8, token, "0123456789");
        if (!std.mem.startsWith(u8, t, "<<")) {
            others += 1;
            continue;
        }
        t = t[2..];
        const strip = std.mem.startsWith(u8, t, "-");
        if (strip) t = t[1..];
        if (t.len == 0 or std.mem.indexOfScalar(u8, t, '<') != null) {
            others += 1;
            continue;
        }
        const quoted = t.len >= 2 and (t[0] == '"' or t[0] == '\'') and t[t.len - 1] == t[0];
        try found.append(arena, .{
            .name = if (quoted) t[1 .. t.len - 1] else t,
            .expand = !quoted,
            .strip_tabs = strip,
        });
    }
    return .{ .found = found.items, .others = others };
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

/// `name` set to `value` in `list`: replaced where it is, else added last.
fn putLabel(arena: Allocator, list: *std.ArrayList(images.Label), name: []const u8, value: []const u8) !void {
    for (list.items) |*l| if (std.mem.eql(u8, l.name, name)) {
        l.value = value;
        return;
    };
    try list.append(arena, .{ .name = name, .value = value });
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
        copy: Copy,
        /// `WORKDIR`'s directory, made in a layer unless the image has it (as Docker makes it),
        /// owned by the `USER` in effect.
        mkdir: struct { path: []const u8, user: []const u8 },
    };
};

/// A `COPY` or `ADD`: what it takes, from where, and where it puts it.
pub const Copy = struct {
    from: From,
    sources: []const Source,
    /// Absolute, and ending in `/` where it was written so (a directory to copy into).
    dest: []const u8,
    /// `--chown` as written ("" for root, or for the source's own owner with `--from`) and
    /// `--chmod` (null to keep the source's).
    chown: []const u8,
    chmod: ?u32,
};

/// Where a `COPY`'s path sources are: the build's context, the filesystem a stage built, or an
/// image's (`COPY --from=alpine:3.22`).
pub const From = union(enum) { context, stage: u32, rootfs: []const u8 };

pub const Source = union(enum) {
    /// A path, or a pattern (`*`, `?`, `[a-z]`), in the tree copied from; relative, or absolute
    /// for a stage's or an image's, where `/` is its root.
    path: []const u8,
    /// A heredoc's file (`COPY <<EOF /file`).
    inline_file: struct { name: []const u8, content: []const u8 },
    /// An `ADD`ed URL, fetched when the build was planned (`Context.fetchFn`) into `file`, a path
    /// on the host; `name` is what the URL's path ends in.
    url: struct { url: []const u8, file: []const u8, name: []const u8 },
};

/// What a stage starts from.
pub const Base = union(enum) {
    /// An image's filesystem, a directory (`images.Image.rootfs`).
    image: struct {
        ref: []const u8,
        rootfs: []const u8,
        /// Layers an image built earlier in the job (the Docker API's) has over its `rootfs`, top first.
        layers: []const []const u8 = &.{},
    },
    /// The result of an earlier stage (`FROM build`).
    stage: u32,
    /// Nothing (`FROM scratch`).
    scratch,
};

pub const Stage = struct {
    /// The name after `AS`, in lower case; "" for none.
    name: []const u8,
    base: Base,
    steps: []const Step,
    /// The config the stage leaves (its `rootfs` is not the built layers').
    config: images.Image,
    /// The key of the stage's last step (of its start when it has none): what the stage is.
    key: [64]u8,
    /// `SHELL`, for the stages that continue this one.
    shell: []const []const u8,
    /// Whether the last stage needs it. A stage nothing needs is not planned or built.
    needed: bool,
};

pub const Plan = struct {
    stages: []const Stage,
    /// The stage the image is: the last of the file.
    final: u32,
};

pub const Planned = union(enum) { ok: Plan, refused: Refusal };

/// An image the build starts from or copies from.
pub const BaseImage = struct {
    /// Its config (`rootfs` is its filesystem's directory).
    config: images.Image,
    /// What the image is, in every key it makes (`docker_action.baseId`), or "" to plan without.
    id: []const u8,
};

/// An interface an implementation embeds as a field and recovers itself from with `@fieldParentPtr`.
pub const Bases = struct {
    /// The image `ref` names, or null with `why` saying why it cannot be had.
    resolveFn: *const fn (self: *Bases, arena: Allocator, ref: []const u8, why: *[]const u8) anyerror!?BaseImage,
};

/// What a build reads of the outside, for its keys: the context's files, and what an `ADD`
/// of a URL downloads.
pub const Context = struct {
    /// The digest of the content of the paths and patterns `sources` in the context.
    digestFn: *const fn (self: *Context, arena: Allocator, sources: []const []const u8) anyerror![64]u8,
    /// `ADD`'s download of `url`: the file it was saved in, and its content's digest. Null when
    /// the build cannot download.
    fetchFn: ?*const fn (self: *Context, arena: Allocator, url: []const u8) anyerror!Fetched = null,
};

pub const Fetched = struct { file: []const u8, digest: [64]u8 };

/// The auto-set build arguments, which `FROM` sees and a stage sees once it declares them: the
/// build's platform is the runner's, and so is the image's.
fn platformArgs(arena: Allocator, out: *std.ArrayList(Var)) !void {
    const arch = switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @tagName(builtin.cpu.arch),
    };
    const platform = try std.fmt.allocPrint(arena, "linux/{s}", .{arch});
    for ([_][]const u8{ "BUILD", "TARGET" }) |who| {
        try out.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{s}PLATFORM", .{who}), .value = platform });
        try out.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{s}OS", .{who}), .value = "linux" });
        try out.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{s}ARCH", .{who}), .value = arch });
        try out.append(arena, .{ .name = try std.fmt.allocPrint(arena, "{s}VARIANT", .{who}), .value = "" });
    }
}

/// Evaluates `instructions` with the images they start or copy from given by `bases`, and
/// `build_args` given to the build (`--build-arg`, which Docker actions never get, so usually
/// none), into stages with the config each leaves and a key per instruction.
pub fn plan(
    arena: Allocator,
    instructions: []const Instruction,
    bases: *Bases,
    build_args: []const Var,
    context: *Context,
) !Planned {
    return planWith(arena, instructions, bases, context, .{ .build_args = build_args });
}

/// What a build asks beyond the Dockerfile (the Docker API's `POST /build`, `docker_api.zig`).
pub const Options = struct {
    /// `--build-arg`.
    build_args: []const Var = &.{},
    /// `--target`: the stage the image is, by its `AS` name or its number; "" for the last.
    target: []const u8 = "",
    /// `--no-cache`: a value no earlier build had, which every `RUN`'s key holds, so none of them
    /// (nor any instruction after one) is taken from the store.
    salt: []const u8 = "",
    /// `LABEL`s the build adds to the image's config, after the Dockerfile's own (`--label`).
    labels: []const Var = &.{},
};

pub fn planWith(
    arena: Allocator,
    instructions: []const Instruction,
    bases: *Bases,
    context: *Context,
    opts: Options,
) !Planned {
    var p: Planner = .{
        .arena = arena,
        .bases = bases,
        .build_args = opts.build_args,
        .context = context,
        .target = opts.target,
        .salt = opts.salt,
        .labels = opts.labels,
    };
    const got = p.run(instructions) catch |e| switch (e) {
        error.Refused => return .{ .refused = p.refusal },
        else => return e,
    };
    return .{ .ok = got };
}

const Planner = struct {
    arena: Allocator,
    bases: *Bases,
    build_args: []const Var,
    context: *Context,
    target: []const u8 = "",
    salt: []const u8 = "",
    labels: []const Var = &.{},
    refusal: Refusal = .{ .line = 0, .why = "" },
    /// The ARGs before the first FROM, which only FROM sees.
    global: std.ArrayList(Var) = .empty,
    stages: std.ArrayList(Stage) = .empty,

    fn refuse(p: *Planner, line: u32, why: []const u8) error{Refused} {
        p.refusal = .{ .line = line, .why = why };
        return error.Refused;
    }

    fn refuseFmt(p: *Planner, line: u32, comptime fmt: []const u8, args: anytype) error{ Refused, OutOfMemory } {
        return p.refuse(line, try std.fmt.allocPrint(p.arena, fmt, args));
    }

    /// A `FROM`'s parts, with the global ARGs substituted.
    const FromParts = struct { image: []const u8, name: []const u8, platform: []const u8 };

    fn parseFrom(p: *Planner, ins: Instruction) !FromParts {
        const ws = try words(p.arena, try substitute(p.arena, ins.text, p.global.items));
        var i: usize = 0;
        var platform: []const u8 = "";
        while (i < ws.len and std.mem.startsWith(u8, ws[i], "--")) : (i += 1) {
            if (!std.mem.startsWith(u8, ws[i], "--platform="))
                return p.refuseFmt(ins.line, "`FROM {s}` is not native yet", .{ws[i]});
            platform = ws[i]["--platform=".len..];
        }
        const rest = ws[i..];
        const named = rest.len == 3 and std.ascii.eqlIgnoreCase(rest[1], "as");
        if (rest.len != 1 and !named) return p.refuse(ins.line, "`FROM` takes an image, and `AS` a name");
        return .{
            .image = rest[0],
            .name = if (named) try std.ascii.allocLowerString(p.arena, rest[2]) else "",
            .platform = platform,
        };
    }

    fn run(p: *Planner, ins: []const Instruction) !Plan {
        const arena = p.arena;
        try platformArgs(arena, &p.global);
        var i: usize = 0;
        // ARGs before the first FROM are in scope for the FROMs only.
        while (i < ins.len and ins[i].kind == .arg) : (i += 1) {
            for (try argDecls(arena, ins[i].text, p.build_args, &.{})) |v| try put(arena, &p.global, v.name, v.value);
        }
        if (i == ins.len or ins[i].kind != .from)
            return p.refuse(if (i < ins.len) ins[i].line else 1, "a Dockerfile starts with FROM (after ARG)");

        var starts: std.ArrayList(usize) = .empty;
        for (ins[i..], i..) |x, k| if (x.kind == .from) try starts.append(arena, k);
        const n = starts.items.len;
        const froms = try arena.alloc(FromParts, n);
        for (froms, starts.items, 0..) |*f, at, s| {
            f.* = try p.parseFrom(ins[at]);
            if (f.name.len > 0) for (froms[0..s]) |earlier| if (std.mem.eql(u8, earlier.name, f.name))
                return p.refuseFmt(ins[at].line, "the stage name {s} is used twice", .{f.name});
        }
        const ends = try arena.alloc(usize, n);
        for (ends, 0..) |*e, s| e.* = if (s + 1 < n) starts.items[s + 1] else ins.len;

        // The stage the image is: the last, or the `--target`'s.
        var final: usize = n - 1;
        if (p.target.len > 0) {
            final = stageNamed(froms, n, p.target) orelse return p.refuseFmt(
                ins[starts.items[n - 1]].line,
                "target stage \"{s}\" could not be found",
                .{p.target},
            );
        }
        // The stages it needs, through the stages it starts from and copies from.
        const needed = try arena.alloc(bool, n);
        @memset(needed, false);
        var work: std.ArrayList(usize) = .empty;
        try work.append(arena, final);
        while (work.pop()) |s| {
            if (needed[s]) continue;
            needed[s] = true;
            if (stageNamed(froms, s, froms[s].image)) |d| try work.append(arena, d);
            for (ins[starts.items[s] + 1 .. ends[s]]) |x| {
                if (x.kind != .copy) continue;
                const from = (try p.fromFlag(x)) orelse continue;
                if (stageNamed(froms, s, from)) |d| try work.append(arena, d);
            }
        }

        for (0..n) |s| {
            if (!needed[s]) {
                try p.stages.append(arena, .{
                    .name = froms[s].name,
                    .base = .scratch,
                    .steps = &.{},
                    .config = .{ .rootfs = "" },
                    .key = @splat('0'),
                    .shell = default_shell,
                    .needed = false,
                });
                continue;
            }
            const stage = try p.planStage(s, froms, ins[starts.items[s]..ends[s]]);
            try p.stages.append(arena, stage);
        }
        // The build's own labels are the image's, whichever stage it is, over the Dockerfile's.
        if (p.labels.len > 0) {
            const cfg = &p.stages.items[final].config;
            var merged: std.ArrayList(images.Label) = .empty;
            try merged.appendSlice(arena, cfg.labels);
            for (p.labels) |l| try putLabel(arena, &merged, l.name, l.value);
            cfg.labels = merged.items;
        }
        return .{ .stages = p.stages.items, .final = @intCast(final) };
    }

    /// The `--from=` value of a COPY, with the global ARGs substituted; null when it has none.
    fn fromFlag(p: *Planner, ins: Instruction) !?[]const u8 {
        var text = ins.text;
        while (std.mem.startsWith(u8, text, "--")) {
            const end = std.mem.indexOfAny(u8, text, " \t") orelse text.len;
            const flag = text[0..end];
            text = std.mem.trimStart(u8, text[end..], " \t");
            if (std.mem.startsWith(u8, flag, "--from="))
                return try substitute(p.arena, flag["--from=".len..], p.global.items);
        }
        return null;
    }

    /// The earlier stage (before `before`) `name` names: by its `AS` name, in any case, or its
    /// number; null when it names none, which then is an image.
    fn stageNamed(froms: []const FromParts, before: usize, name: []const u8) ?usize {
        for (froms[0..before], 0..) |f, i| {
            if (f.name.len > 0 and std.ascii.eqlIgnoreCase(f.name, name)) return i;
        }
        const idx = std.fmt.parseInt(usize, name, 10) catch return null;
        return if (idx < before) idx else null;
    }

    const State = struct {
        cfg: images.Image,
        env: std.ArrayList(Var) = .empty,
        args: std.ArrayList(Var) = .empty,
        workdir: []const u8 = "/",
        shell: []const []const u8 = default_shell,
        key: [64]u8,
        /// Whether this stage's own CMD was set: a later ENTRYPOINT then leaves it, as Docker does.
        cmd_set: bool = false,
    };

    fn planStage(p: *Planner, s: usize, froms: []const FromParts, ins: []const Instruction) !Stage {
        const arena = p.arena;
        const from = froms[s];
        const from_ins = ins[0];
        if (from.platform.len > 0 and !ownPlatform(p, from.platform))
            return p.refuseFmt(from_ins.line, "`FROM --platform={s}`: only the runner's own platform is built natively", .{from.platform});

        var st: State = undefined;
        var base: Base = undefined;
        if (stageNamed(froms, s, from.image)) |d| {
            const parent = p.stages.items[d];
            base = .{ .stage = @intCast(d) };
            // The chain goes on from where the parent stage ended: a stage that starts from another is
            // the same state, so its layers are the ones a Dockerfile of the same steps in one stage has.
            st = .{ .cfg = parent.config, .shell = parent.shell, .key = parent.key };
        } else if (std.mem.eql(u8, from.image, "scratch")) {
            base = .scratch;
            // An image of nothing has the PATH Docker gives every container that has none.
            st = .{
                .cfg = .{ .rootfs = "", .env = &.{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"} },
                .key = fromKey("\x00scratch", "", null),
            };
        } else {
            var why: []const u8 = "";
            const img = (try p.bases.resolveFn(p.bases, arena, from.image, &why)) orelse
                return p.refuse(from_ins.line, why);
            base = .{ .image = .{ .ref = from.image, .rootfs = img.config.rootfs, .layers = img.config.layers } };
            st = .{
                .cfg = img.config,
                .key = fromKey(try images.normalize(arena, from.image), img.id, null),
            };
        }
        for (st.cfg.env) |kv| {
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
            try put(arena, &st.env, kv[0..eq], kv[eq + 1 ..]);
        }
        if (st.cfg.workdir.len > 0) st.workdir = st.cfg.workdir;

        var steps: std.ArrayList(Step) = .empty;
        for (ins[1..]) |x| {
            // What substitution sees: the build arguments, then the env, which wins.
            const scope = try std.mem.concat(arena, Var, &.{ st.args.items, st.env.items });
            var op: Step.Op = .none;
            var evaluated: []const u8 = x.text;
            var reads: []const u8 = "";
            switch (x.kind) {
                .from => unreachable,
                .ignored => continue,
                .arg => for (try argDecls(arena, try substitute(arena, x.text, scope), p.build_args, p.global.items)) |v|
                    try put(arena, &st.args, v.name, v.value),
                .env => {
                    evaluated = try substitute(arena, x.text, scope);
                    for (try pairs(arena, evaluated)) |v| try put(arena, &st.env, v.name, v.value);
                },
                .label => {
                    evaluated = try substitute(arena, x.text, scope);
                    var labels: std.ArrayList(images.Label) = .empty;
                    try labels.appendSlice(arena, st.cfg.labels);
                    for (try pairs(arena, evaluated)) |v| try putLabel(arena, &labels, v.name, v.value);
                    st.cfg.labels = labels.items;
                },
                .workdir => {
                    const w = try substitute(arena, x.text, scope);
                    st.workdir = try std.fs.path.resolvePosix(arena, &.{ st.workdir, w });
                    evaluated = st.workdir;
                    st.cfg.workdir = st.workdir;
                    op = .{ .mkdir = .{ .path = st.workdir, .user = st.cfg.user } };
                },
                .user => {
                    evaluated = try substitute(arena, x.text, scope);
                    st.cfg.user = evaluated;
                },
                .shell => {
                    const j = x.json orelse return p.refuse(x.line, "`SHELL` takes a JSON array");
                    if (j.len == 0) return p.refuse(x.line, "`SHELL` takes a shell to run");
                    st.shell = j;
                    evaluated = try arena.dupe(u8, &listDigest(j));
                },
                .entrypoint => {
                    st.cfg.entrypoint = try p.command(&st, x);
                    // ENTRYPOINT resets a CMD the base image set, not one set since, as Docker does.
                    if (!st.cmd_set) st.cfg.cmd = &.{};
                },
                .cmd => {
                    st.cfg.cmd = try p.command(&st, x);
                    st.cmd_set = true;
                },
                .run => {
                    if (std.mem.startsWith(u8, x.text, "--")) {
                        const end = std.mem.indexOfAny(u8, x.text, " \t=") orelse x.text.len;
                        return p.refuseFmt(x.line, "`RUN {s}` is not native yet", .{x.text[0..end]});
                    }
                    var run_env: std.ArrayList([]const u8) = .empty;
                    for (st.env.items) |v| try run_env.append(arena, try std.fmt.allocPrint(arena, "{s}={s}", .{ v.name, v.value }));
                    for (st.args.items) |v| if (lookup(st.env.items, v.name) == null)
                        try run_env.append(arena, try std.fmt.allocPrint(arena, "{s}={s}", .{ v.name, v.value }));
                    const argv = try p.command(&st, x);
                    op = .{ .run = .{
                        .argv = argv,
                        .env = run_env.items,
                        .workdir = st.workdir,
                        .user = st.cfg.user,
                    } };
                    // A heredoc's lines are part of what runs, though not of the instruction's text.
                    if (x.heredocs.len > 0) evaluated = argv[argv.len - 1];
                    // A RUN's result depends on the build arguments it sees, as BuildKit keys it.
                    if (p.salt.len > 0) try run_env.append(arena, p.salt);
                    reads = try arena.dupe(u8, &listDigest(run_env.items));
                },
                .copy, .add => {
                    const c = try p.copy(&st, x, scope, froms, s);
                    op = .{ .copy = c.op };
                    evaluated = c.evaluated;
                    reads = c.reads;
                },
            }
            st.key = stepKey(&st.key, @tagName(x.kind), evaluated, reads, null);
            try steps.append(arena, .{ .key = st.key, .line = x.line, .op = op });
        }
        var env_out: std.ArrayList([]const u8) = .empty;
        for (st.env.items) |v| try env_out.append(arena, try std.fmt.allocPrint(arena, "{s}={s}", .{ v.name, v.value }));
        st.cfg.env = env_out.items;
        return .{
            .name = from.name,
            .base = base,
            .steps = steps.items,
            .config = st.cfg,
            .key = st.key,
            .shell = st.shell,
            .needed = true,
        };
    }

    fn ownPlatform(p: *Planner, platform: []const u8) bool {
        if (platform.len == 0) return true;
        const own = lookup(p.global.items, "TARGETPLATFORM") orelse return false;
        return std.mem.eql(u8, platform, own);
    }

    /// RUN's, CMD's and ENTRYPOINT's command: the JSON form's words, or the shell form under the
    /// stage's shell (`/bin/sh -c`), as Docker runs it. A `RUN <<EOF` is its heredoc as the
    /// script the shell runs; `RUN cat <<EOF > f` is the shell's own, with the heredoc's lines.
    fn command(p: *Planner, st: *const State, ins: Instruction) ![]const []const u8 {
        const arena = p.arena;
        if (ins.json) |j| return j;
        var script = ins.text;
        if (ins.heredocs.len > 0) {
            const scan = try scanHeredocs(arena, ins.text);
            if (scan.others == 0) {
                if (ins.heredocs.len != 1)
                    return p.refuse(ins.line, "`RUN` with several heredocs and no command is not native yet");
                script = ins.heredocs[0].body;
                if (std.mem.startsWith(u8, script, "#!"))
                    return p.refuse(ins.line, "a heredoc script with a `#!` line is not native yet");
            } else {
                var all: std.ArrayList(u8) = .empty;
                try all.appendSlice(arena, ins.text);
                try all.append(arena, '\n');
                for (ins.heredocs) |h| {
                    try all.appendSlice(arena, h.body);
                    try all.appendSlice(arena, h.name);
                    try all.append(arena, '\n');
                }
                script = all.items;
            }
        }
        return std.mem.concat(arena, []const u8, &.{ st.shell, &.{script} });
    }

    const PlannedCopy = struct { op: Copy, evaluated: []const u8, reads: []const u8 };

    fn copy(p: *Planner, st: *const State, ins: Instruction, scope: []const Var, froms: []const FromParts, s: usize) !PlannedCopy {
        const arena = p.arena;
        var chown: []const u8 = "";
        var chmod: ?u32 = null;
        var from_name: ?[]const u8 = null;
        var text = ins.text;
        while (std.mem.startsWith(u8, text, "--")) {
            const end = std.mem.indexOfAny(u8, text, " \t") orelse text.len;
            const flag = try substitute(arena, text[0..end], scope);
            text = std.mem.trimStart(u8, text[end..], " \t");
            if (std.mem.startsWith(u8, flag, "--chown=")) {
                chown = flag["--chown=".len..];
                // What BuildKit makes of `:group` is not checked here: the engine decides.
                if (std.mem.startsWith(u8, chown, ":")) return p.refuse(ins.line, "`--chown` with no user is not native yet");
            } else if (std.mem.startsWith(u8, flag, "--chmod=")) {
                const mode = flag["--chmod=".len..];
                // Octal digits only (no sign), within the permission bits and setuid, setgid and sticky.
                const ok = mode.len > 0 and std.ascii.isDigit(mode[0]);
                chmod = if (ok) std.fmt.parseInt(u32, mode, 8) catch null else null;
                if (chmod == null or chmod.? > 0o7777) return p.refuse(ins.line, "`--chmod` takes an octal mode of at most 7777");
            } //
            else if (std.mem.startsWith(u8, flag, "--from=")) {
                if (ins.kind == .add) return p.refuse(ins.line, "`ADD --from` is not a Docker instruction");
                from_name = flag["--from=".len..];
            } else if (std.mem.eql(u8, flag, "--link") or std.mem.startsWith(u8, flag, "--link=")) {
                // A layer made apart from the ones below it: what every layer here is.
            } else return p.refuseFmt(ins.line, "`{s}` is not native yet", .{flag});
        }
        const ws: []const []const u8 = if (try jsonForm(arena, text)) |j| blk: {
            const out = try arena.alloc([]const u8, j.len);
            for (j, out) |w, *o| o.* = try substitute(arena, w, scope);
            break :blk out;
        } else try words(arena, try substitute(arena, text, scope));
        if (ws.len < 2) return p.refuse(ins.line, "COPY and ADD need a source and a destination");
        const raw_dest = ws[ws.len - 1];
        const given = ws[0 .. ws.len - 1];
        if (given.len > 1 and !std.mem.endsWith(u8, raw_dest, "/"))
            return p.refuse(ins.line, "COPY and ADD of several sources need a destination that ends with /");

        var from: From = .context;
        var base_reads: []const u8 = "";
        var from_id: []const u8 = "";
        if (from_name) |name| {
            if (Planner.stageNamed(froms, s, name)) |d| {
                from = .{ .stage = @intCast(d) };
                base_reads = try arena.dupe(u8, &p.stages.items[d].key);
                from_id = try std.fmt.allocPrint(arena, "stage {d}", .{d});
            } else {
                var why: []const u8 = "";
                const img = (try p.bases.resolveFn(p.bases, arena, name, &why)) orelse
                    return p.refuse(ins.line, why);
                if (img.config.layers.len > 0) return p.refuse(ins.line, "`COPY --from` an image built " ++
                    "earlier in the job is not supported yet");
                from = .{ .rootfs = img.config.rootfs };
                base_reads = img.id;
                from_id = try images.normalize(arena, name);
            }
        }

        var sources: std.ArrayList(Source) = .empty;
        var paths: std.ArrayList([]const u8) = .empty;
        var urls: std.ArrayList([]const u8) = .empty;
        var next_heredoc: usize = 0;
        for (given) |src| {
            if (ins.json == null and std.mem.startsWith(u8, src, "<<") and next_heredoc < ins.heredocs.len) {
                const h = ins.heredocs[next_heredoc];
                next_heredoc += 1;
                const content = if (h.expand) try substitute(arena, h.body, scope) else h.body;
                try sources.append(arena, .{ .inline_file = .{ .name = h.name, .content = content } });
                continue;
            }
            if (ins.kind == .add and isGit(src))
                return p.refuseFmt(ins.line, "ADD of {s}, a git repository, is not native yet", .{src});
            if (ins.kind == .add and std.mem.indexOf(u8, src, "://") != null) {
                if (from != .context) return p.refuse(ins.line, "`ADD` of a URL takes no `--from`");
                const is_http = std.mem.startsWith(u8, src, "http://") or std.mem.startsWith(u8, src, "https://");
                if (!is_http) return p.refuseFmt(ins.line, "ADD of {s}: only http and https URLs are native", .{src});
                const fetch = p.context.fetchFn orelse return p.refuse(ins.line, "ADD of a URL needs the network");
                const got = fetch(p.context, arena, src) catch |e|
                    return p.refuseFmt(ins.line, "ADD of {s} failed: {s}", .{ src, @errorName(e) });
                try sources.append(arena, .{ .url = .{ .url = src, .file = got.file, .name = urlName(src) } });
                try urls.append(arena, try arena.dupe(u8, &got.digest));
                continue;
            }
            if (ins.kind == .add and isArchive(src))
                return p.refuse(ins.line, "ADD of an archive, which Docker unpacks, is not native yet");
            if (from == .context and !insideContext(src)) return p.refuseFmt(ins.line, "{s} is outside the build context", .{src});
            try sources.append(arena, .{ .path = src });
            try paths.append(arena, src);
        }
        const dest = if (std.mem.endsWith(u8, raw_dest, "/"))
            try std.fmt.allocPrint(arena, "{s}/", .{try std.fs.path.resolvePosix(arena, &.{ st.workdir, raw_dest })})
        else
            try std.fs.path.resolvePosix(arena, &.{ st.workdir, raw_dest });

        var reads = base_reads;
        if (from == .context and paths.items.len > 0) {
            const digest = p.context.digestFn(p.context, arena, paths.items) catch |e| switch (e) {
                error.SourceMissing => return p.refuse(ins.line, "a source of the COPY is not in the build context"),
                else => return e,
            };
            reads = try arena.dupe(u8, &digest);
        }
        if (urls.items.len > 0) {
            var all: std.ArrayList([]const u8) = .empty;
            try all.append(arena, reads);
            try all.appendSlice(arena, urls.items);
            reads = try arena.dupe(u8, &listDigest(all.items));
        }

        // Plain paths of the context keep the key they always had.
        var fields: std.ArrayList([]const u8) = .empty;
        const plain = from == .context and paths.items.len == sources.items.len;
        if (!plain) {
            try fields.append(arena, "\x00sources");
            try fields.append(arena, @tagName(from));
            try fields.append(arena, from_id);
            for (sources.items) |sc| switch (sc) {
                .path => |v| try fields.appendSlice(arena, &.{ "path", v }),
                .inline_file => |v| try fields.appendSlice(arena, &.{ "inline", v.name, v.content }),
                .url => |v| try fields.appendSlice(arena, &.{ "url", v.url }),
            };
        } else try fields.appendSlice(arena, paths.items);
        try fields.appendSlice(arena, &.{ dest, chown, try std.fmt.allocPrint(arena, "{?o}", .{chmod}) });
        return .{
            .op = .{ .from = from, .sources = sources.items, .dest = dest, .chown = chown, .chmod = chmod },
            .evaluated = try arena.dupe(u8, &listDigest(fields.items)),
            .reads = reads,
        };
    }
};

const default_shell: []const []const u8 = &.{ "/bin/sh", "-c" };

/// What an `ADD`ed URL's path ends in: the name its file gets in a directory.
fn urlName(url: []const u8) []const u8 {
    const after = url[std.mem.indexOf(u8, url, "://").? + 3 ..];
    const path_start = std.mem.indexOfScalar(u8, after, '/') orelse return "";
    const path = after[path_start..][0 .. std.mem.indexOfAny(u8, after[path_start..], "?#") orelse after.len - path_start];
    return std.fs.path.basenamePosix(path);
}

/// ARG's declarations, each with the build's value when given, else its default, else the one
/// before the first FROM (`global`) gave it.
fn argDecls(arena: Allocator, text: []const u8, build_args: []const Var, global: []const Var) ![]const Var {
    var out: std.ArrayList(Var) = .empty;
    for (try words(arena, text)) |w| {
        const eq = std.mem.indexOfScalar(u8, w, '=');
        const name = if (eq) |e| w[0..e] else w;
        const default = if (eq) |e| w[e + 1 ..] else lookup(global, name) orelse "";
        try out.append(arena, .{ .name = name, .value = lookup(build_args, name) orelse default });
    }
    return out.items;
}

/// Whether an `ADD` source is a git repository, as BuildKit reads it: an scp-style address, the
/// git protocol, or a URL to a `.git` or with a `#` fragment.
fn isGit(src: []const u8) bool {
    if (std.mem.startsWith(u8, src, "git@") or std.mem.startsWith(u8, src, "git://")) return true;
    if (std.mem.indexOf(u8, src, "://") == null) return false;
    const before_query = src[0 .. std.mem.indexOfScalar(u8, src, '?') orelse src.len];
    return std.mem.indexOfScalar(u8, src, '#') != null or std.mem.endsWith(u8, before_query, ".git");
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

/// What a key is of: a build's base, or an instruction on a parent's key (the model's `BuildState`).
const Tag = enum(u64) { from = 0, step = 1 };

/// A build's first key (the model's `encBuild`, `.from`): the base's reference and what the image
/// behind it is. `bytes`, when given, receives the preimage (`key_vectors.zig`), as in `Backend.belowKey`.
pub fn fromKey(reference: []const u8, base_id: []const u8, bytes: ?*std.Io.Writer) [64]u8 {
    var h: KeyHasher = .{ .h = .init(.{}), .bytes = bytes };
    h.int(@backingInt(Tag.from));
    h.field(reference);
    h.field(base_id);
    return std.fmt.bytesToHex(h.final(), .lower);
}

/// An instruction's key on its parent's (the model's `encBuild`, `.step`). What it reads and how
/// it evaluated are one field each: a digest (`listDigest`) where they are a list.
pub fn stepKey(
    parent: []const u8,
    kind: []const u8,
    evaluated: []const u8,
    reads: []const u8,
    bytes: ?*std.Io.Writer,
) [64]u8 {
    var h: KeyHasher = .{ .h = .init(.{}), .bytes = bytes };
    h.int(@backingInt(Tag.step));
    h.field(parent);
    h.field(kind);
    h.field(evaluated);
    h.field(reads);
    return std.fmt.bytesToHex(h.final(), .lower);
}

/// A list of strings as one field: counted, each length-prefixed, so two lists never hash alike.
fn listDigest(parts: []const []const u8) [64]u8 {
    var h: KeyHasher = .plain("a build's list");
    h.int(parts.len);
    for (parts) |p| h.field(p);
    return std.fmt.bytesToHex(h.final(), .lower);
}

// --- sources: what a COPY reads ---

fn hasMeta(path: []const u8) bool {
    return std.mem.indexOfAny(u8, path, "*?[") != null;
}

/// A source path or pattern as a path of the tree it is in: relative to its root, `.` and `..`
/// taken (a `..` stops at the root, as Docker's does), "" for the root itself.
fn cleanPath(arena: Allocator, path: []const u8) ![]const u8 {
    const abs = try std.fs.path.resolvePosix(arena, &.{ "/", path });
    return std.mem.trimStart(u8, abs, "/");
}

/// Whether `name` matches `pattern` as Go's `path.Match` takes it, which is what Docker's COPY
/// uses for one path component: `*` any run of characters, `?` any one, `[a-z]` and `[^a-z]`
/// a class, `\` the next character as it is.
pub fn globMatch(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star_p: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pattern.len) switch (pattern[p]) {
            '*' => {
                star_p = p;
                star_n = n;
                p += 1;
                continue;
            },
            '?' => {
                p += 1;
                n += 1;
                continue;
            },
            '[' => if (classMatch(pattern, &p, name[n])) |hit| {
                if (hit) {
                    n += 1;
                    continue;
                }
            } else return false,
            '\\' => if (p + 1 < pattern.len and pattern[p + 1] == name[n]) {
                p += 2;
                n += 1;
                continue;
            },
            else => |c| if (c == name[n]) {
                p += 1;
                n += 1;
                continue;
            },
        };
        const sp = star_p orelse return false;
        p = sp + 1;
        star_n += 1;
        n = star_n;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// Whether `c` is in the class that starts at `pattern[p.*]` (`[`), advancing `p` past it; null
/// for a class that never closes (a pattern that matches nothing, as `path.Match`'s error).
fn classMatch(pattern: []const u8, p: *usize, c: u8) ?bool {
    var i = p.* + 1;
    const negate = i < pattern.len and pattern[i] == '^';
    if (negate) i += 1;
    var hit = false;
    var first = true;
    while (i < pattern.len) {
        if (pattern[i] == ']' and !first) {
            p.* = i + 1;
            return hit != negate;
        }
        first = false;
        var lo = pattern[i];
        if (lo == '\\' and i + 1 < pattern.len) {
            i += 1;
            lo = pattern[i];
        }
        var hi = lo;
        if (i + 2 < pattern.len and pattern[i + 1] == '-' and pattern[i + 2] != ']') {
            hi = pattern[i + 2];
            i += 2;
        }
        if (lo <= c and c <= hi) hit = true;
        i += 1;
    }
    return null;
}

/// A build context's `.dockerignore`, as Docker reads it (moby's `patternmatcher`): one pattern
/// a line, `#` for a comment, `!` for an exception; a pattern is a path whose parts are matched as
/// `COPY`'s are (`globMatch`), with `**` for any number of directories, and what it matches is
/// left out together with everything under it, unless a later exception takes it back. The last
/// pattern that applies decides. Not done: an exception for a file in a directory an earlier
/// pattern left out, where Docker walks into the directory (here the directory is walked, and
/// what the patterns leave out of it is left out, but it stays, empty, if they leave out all).
pub const Ignore = struct {
    patterns: []const Pattern,
    /// Whether an exception names a path below the top (`!src/keep`): a directory left out may
    /// then hold files that are not.
    nested_exceptions: bool,

    const Pattern = struct { parts: []const []const u8, exclusion: bool };

    /// The patterns of `text`, after `always`, which are left out whatever the file says.
    pub fn parse(arena: Allocator, text: []const u8, always: []const []const u8) !Ignore {
        var out: std.ArrayList(Pattern) = .empty;
        var nested = false;
        var lines = std.mem.splitScalar(u8, text, '\n');
        var first = true;
        var extra: usize = 0;
        while (true) {
            var line: []const u8 = undefined;
            if (extra < always.len) {
                line = always[extra];
                extra += 1;
            } else if (lines.next()) |l| {
                line = std.mem.trim(u8, l, " \t\r");
                if (first) line = std.mem.trimStart(u8, line, "\xef\xbb\xbf");
                first = false;
            } else break;
            if (line.len == 0 or line[0] == '#') continue;
            const exclusion = line[0] == '!';
            if (exclusion) line = std.mem.trim(u8, line[1..], " \t");
            const clean = try cleanPath(arena, line);
            if (clean.len == 0) continue;
            var parts: std.ArrayList([]const u8) = .empty;
            var it = std.mem.splitScalar(u8, clean, '/');
            while (it.next()) |part| try parts.append(arena, part);
            if (exclusion and parts.items.len > 1) nested = true;
            try out.append(arena, .{ .parts = parts.items, .exclusion = exclusion });
        }
        return .{ .patterns = out.items, .nested_exceptions = nested };
    }

    /// Whether `path` (relative to the context, as `rel`) is left out: it matches, or a directory
    /// above it does.
    pub fn excludes(ig: Ignore, path: []const u8) bool {
        var matched = false;
        for (ig.patterns) |p| {
            // An exception only matters to what is left out, a pattern only to what is not.
            if (p.exclusion != matched) continue;
            var hit = matchParts(p.parts, path);
            var end: usize = 0;
            while (!hit) {
                end = (std.mem.indexOfScalarPos(u8, path, end, '/') orelse break);
                hit = matchParts(p.parts, path[0..end]);
                end += 1;
            }
            if (hit) matched = !p.exclusion;
        }
        return matched;
    }

    pub fn filter(ig: *const Ignore) layer_view.Filter {
        return .{ .ptr = @constCast(ig), .excludedFn = excluded };
    }

    fn excluded(ptr: *anyopaque, path: []const u8, is_dir: bool) bool {
        const ig: *const Ignore = @ptrCast(@alignCast(ptr));
        // A directory is walked if an exception below it may take something back.
        return ig.excludes(path) and !(is_dir and ig.nested_exceptions);
    }
};

/// Whether `path` is matched by the pattern `parts`: each part by `globMatch` against a part of
/// the path, `**` for any number of them.
fn matchParts(parts: []const []const u8, path: []const u8) bool {
    if (parts.len == 0) return path.len == 0;
    if (std.mem.eql(u8, parts[0], "**")) {
        // Last: everything below. Else: the rest, after any number of directories.
        if (parts.len == 1) return path.len > 0;
        var rest = path;
        while (true) {
            if (matchParts(parts[1..], rest)) return true;
            const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return false;
            rest = rest[slash + 1 ..];
        }
    }
    const slash = std.mem.indexOfScalar(u8, path, '/');
    if (!globMatch(parts[0], path[0 .. slash orelse path.len])) return false;
    const after = path[(slash orelse return parts.len == 1) + 1 ..];
    return matchParts(parts[1..], after);
}

/// The paths of `view` that `pattern` names, sorted: the cleaned path itself when it has no
/// wildcard (whether it is there or not), else every path whose components match, each component
/// against the names of the merged directory.
fn expand(arena: Allocator, view: *View, pattern: []const u8) ![]const []const u8 {
    const clean = try cleanPath(arena, pattern);
    if (!hasMeta(clean)) return arena.dupe([]const u8, &.{clean});
    var level: std.ArrayList([]const u8) = .empty;
    try level.append(arena, "");
    var parts = std.mem.splitScalar(u8, clean, '/');
    while (parts.next()) |part| {
        var next: std.ArrayList([]const u8) = .empty;
        for (level.items) |dir_path| {
            if (!hasMeta(part)) {
                try next.append(arena, try joinPath(arena, dir_path, part));
                continue;
            }
            const dir = (try view.resolve(dir_path, true)) orelse continue;
            if (dir.kind != .dir) continue;
            for (try view.names(dir)) |n| if (globMatch(part, n))
                try next.append(arena, try joinPath(arena, dir_path, n));
        }
        level = next;
    }
    var found: std.ArrayList([]const u8) = .empty;
    for (level.items) |m| if ((try view.resolve(m, false)) != null) try found.append(arena, m);
    std.mem.sortUnstable([]const u8, found.items, {}, lessThan);
    return found.items;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn joinPath(arena: Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    if (dir.len == 0) return name;
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
}

/// The content of `sources` in the context `view`, for a `COPY`'s key: a sorted walk of each
/// source's paths (a pattern's matches), with each entry's kind, mode bits, link target and file
/// content, every field length-prefixed and every list counted (a file's content cannot pass for
/// the entries after it). A link a source names is followed, as `COPY` follows it; one inside a
/// directory is read, not followed. A source that is not there is `error.SourceMissing`.
pub fn contextDigest(arena: Allocator, view: *View, sources: []const []const u8) ![64]u8 {
    var h: KeyHasher = .plain("a build's sources");
    h.int(sources.len);
    for (sources) |src| {
        const clean = try cleanPath(arena, src);
        h.field(clean);
        if (hasMeta(clean)) {
            const matches = try expand(arena, view, clean);
            h.int(matches.len);
            for (matches) |m| {
                h.field(m);
                try digestEntry(arena, view, (try view.resolve(m, true)) orelse return error.SourceMissing, &h, 0);
            }
        } else try digestEntry(arena, view, (try view.resolve(clean, true)) orelse return error.SourceMissing, &h, 0);
    }
    return std.fmt.bytesToHex(h.final(), .lower);
}

fn digestEntry(arena: Allocator, view: *View, e: layer_view.Entry, h: *KeyHasher, depth: u32) !void {
    if (depth > 128) return error.ContextTooDeep;
    h.int(@backingInt(switch (e.kind) {
        .file => std.Io.File.Kind.file,
        .dir => .directory,
        .symlink => .sym_link,
        .other => .unknown,
    }));
    h.int(@as(u64, e.mode) & 0o7777);
    switch (e.kind) {
        .file => h.field(try e.parent().readFileAlloc(view.io, e.name, arena, .limited(1 << 30))),
        .symlink => h.field(try view.readLink(e)),
        .dir => {
            const names = try view.names(e);
            h.int(names.len);
            for (names) |sub| {
                h.field(sub);
                try digestEntry(arena, view, (try view.child(e, sub)) orelse return error.SourceMissing, h, depth + 1);
            }
        },
        .other => {},
    }
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

/// What `build` reads from: the context's files, and how overlay marks an opaque directory in
/// the layers it looks into (`View`).
pub const Sources = struct {
    /// The build context; null for a build that copies nothing from one.
    context: ?*View,
    opaque_xattr: [:0]const u8,
    /// Told of each stage and step as the build reaches it (the Docker API's `Step 3/7 : ...`).
    progress: ?*Progress = null,
};

/// What a build tells its caller as it goes: an implementation embeds it as a field and recovers
/// itself with `@fieldParentPtr`.
pub const Progress = struct {
    /// A stage `stage` (its number, by `FROM`) is started.
    stageFn: *const fn (p: *Progress, stage: u32) void,
    /// A step of a stage: what it is going to be (`How`), and once more with `.built` when a
    /// layer that was not in the store has been made.
    stepFn: *const fn (p: *Progress, step: Step, how: How) void,

    pub const How = enum {
        /// Its layer was in the store.
        cached,
        /// It changes the config only: no layer.
        config,
        /// Its layer is about to be made.
        building,
        /// ... and it was.
        built,
        /// A `WORKDIR` the image has already: no layer.
        present,
    };
};

pub const Failed = struct {
    line: u32,
    what: enum { run, copy, workdir },
    /// The `RUN`'s exit code.
    code: i32 = 0,
    /// What the `COPY` could not do.
    why: []const u8 = "",
};

pub const Built = union(enum) {
    /// The image's layers, top first, then the base's rootfs; and its config.
    ok: struct { lowers: []const []const u8, config: images.Image },
    failed: Failed,
};

/// Makes `p`'s last stage's layers on its base image's rootfs, each taken from `store` when its
/// key is there, else built and stored: `COPY` and `ADD` by the runner from `src`, `RUN` by
/// `runner`. A stage another one starts from or copies from is made first, only as far as a
/// layer that is not in the store needs it.
pub fn build(
    arena: Allocator,
    io: std.Io,
    p: Plan,
    store: layers.Store,
    runner: Runner,
    src: Sources,
) !Built {
    var b: Builder = .{
        .arena = arena,
        .io = io,
        .plan = p,
        .store = store,
        .runner = runner,
        .src = src,
        .made = try arena.alloc(?[]const []const u8, p.stages.len),
    };
    @memset(b.made, null);
    return switch (try b.stage(p.final)) {
        .ok => |l| .{ .ok = .{ .lowers = l, .config = p.stages[p.final].config } },
        .failed => |f| .{ .failed = f },
    };
}

const Builder = struct {
    arena: Allocator,
    io: std.Io,
    plan: Plan,
    store: layers.Store,
    runner: Runner,
    src: Sources,
    /// Each stage's layers once made, top first.
    made: []?[]const []const u8,

    const Made = union(enum) { ok: []const []const u8, failed: Failed };

    fn stage(b: *Builder, i: u32) anyerror!Made {
        if (b.made[i]) |l| return .{ .ok = l };
        const arena = b.arena;
        const io = b.io;
        const st = b.plan.stages[i];
        std.debug.assert(st.needed);
        var stack: std.ArrayList([]const u8) = .empty;
        switch (st.base) {
            .image => |im| {
                try stack.appendSlice(arena, im.layers);
                try stack.append(arena, im.rootfs);
            },
            .stage => |parent| switch (try b.stage(parent)) {
                .ok => |l| try stack.appendSlice(arena, l),
                .failed => |f| return .{ .failed = f },
            },
            .scratch => {},
        }
        if (b.src.progress) |pg| pg.stageFn(pg, i);
        for (st.steps) |step| {
            if (step.op == .none) {
                if (b.src.progress) |pg| pg.stepFn(pg, step, .config);
                continue;
            }
            if (try b.store.get(arena, io, &step.key)) |layer| {
                if (b.src.progress) |pg| pg.stepFn(pg, step, .cached);
                try stack.insert(arena, 0, layer);
                continue;
            }
            // A directory the image has needs no layer.
            if (step.op == .mkdir and try b.hasDir(step.op.mkdir.path, stack.items)) {
                if (b.src.progress) |pg| pg.stepFn(pg, step, .present);
                continue;
            }
            if (b.src.progress) |pg| pg.stepFn(pg, step, .building);
            const upper = try b.store.begin(arena, io, &step.key);
            errdefer discard(io, upper);
            switch (step.op) {
                .none => unreachable,
                .run => |r| {
                    const code = try b.runner.runFn(b.runner.ptr, stack.items, upper, r);
                    if (code != 0) {
                        discard(io, upper);
                        return .{ .failed = .{ .line = step.line, .what = .run, .code = code } };
                    }
                },
                .copy => |c| if (try b.place(c, step.line, upper, stack.items)) |failed| {
                    discard(io, upper);
                    return .{ .failed = failed };
                },
                .mkdir => |m| if (try b.makeDir(m.path, m.user, upper, stack.items)) |why| {
                    discard(io, upper);
                    return .{ .failed = .{ .line = step.line, .what = .workdir, .why = why } };
                },
            }
            try stack.insert(arena, 0, try b.store.publish(arena, io, upper, &step.key));
            if (b.src.progress) |pg| pg.stepFn(pg, step, .built);
        }
        b.made[i] = stack.items;
        return .{ .ok = stack.items };
    }

    fn hasDir(b: *Builder, path: []const u8, below: []const []const u8) !bool {
        const dst = (try View.open(b.arena, b.io, below, "", b.src.opaque_xattr)) orelse return false;
        defer dst.close();
        const e = (try dst.resolve(path, true)) orelse return false;
        return e.kind == .dir;
    }

    /// `WORKDIR`'s directory made in the layer `upper`, owned by `user` (root's when the image
    /// has no such user; the build fails at the RUN that would run as one it has not).
    fn makeDir(b: *Builder, path: []const u8, user: []const u8, upper: []const u8, below: []const []const u8) !?[]const u8 {
        const dst = try View.open(b.arena, b.io, below, "", b.src.opaque_xattr);
        defer if (dst) |d| d.close();
        var layer = try std.Io.Dir.cwd().openDir(b.io, upper, .{});
        defer layer.close(b.io);
        var cp: Copier = .{ .arena = b.arena, .io = b.io, .src = null, .dst = dst, .layer = layer, .op = undefined };
        if (user.len > 0) if (dst) |d| {
            const passwd = try cp.textOf(d, "etc/passwd");
            const group = try cp.textOf(d, "etc/group");
            if (images.userIds(user, passwd, group)) |ids| cp.owner = .{ .uid = ids.uid, .gid = ids.gid };
        };
        var made = cp.placeDir(path, null) catch |e| switch (e) {
            error.CopyFailed => return cp.why,
            else => return e,
        };
        made.close(b.io);
        return null;
    }

    /// The `COPY` made into the layer `upper`, over the layers `below` (top first); what failed,
    /// or null.
    fn place(b: *Builder, c: Copy, line: u32, upper: []const u8, below: []const []const u8) anyerror!?Failed {
        const arena = b.arena;
        const dst = try View.open(arena, b.io, below, "", b.src.opaque_xattr);
        defer if (dst) |d| d.close();
        const src: ?*View = switch (c.from) {
            .context => b.src.context,
            .stage => |d| switch (try b.stage(d)) {
                .ok => |l| try View.open(arena, b.io, l, "", b.src.opaque_xattr),
                .failed => |f| return f,
            },
            .rootfs => |r| try View.open(arena, b.io, &.{r}, "", b.src.opaque_xattr),
        };
        defer if (c.from != .context) if (src) |s| s.close();
        var layer = try std.Io.Dir.cwd().openDir(b.io, upper, .{});
        defer layer.close(b.io);
        var cp: Copier = .{ .arena = arena, .io = b.io, .src = src, .dst = dst, .layer = layer, .op = c };
        cp.run() catch |e| switch (e) {
            error.CopyFailed => return .{ .line = line, .what = .copy, .why = cp.why },
            else => return e,
        };
        return null;
    }
};

const Owner = struct { uid: u32, gid: u32 };

/// A failed step's upper removed; one that stays is only disk used, so it is logged, not the build's error.
fn discard(io: std.Io, upper: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, upper) catch |e|
        std.log.warn("native: cannot remove a failed step's layer {s}: {s}", .{ upper, @errorName(e) });
}

/// Places a `COPY`'s sources in a new layer as Docker places them: a directory's contents (not
/// the directory) into the destination, a file at the destination or, when the destination ends
/// in `/` or is a directory already, into it by its name; a pattern's matches each as a source
/// of its own; a link named as a source is followed, one inside a directory copied as a link.
/// A destination directory that is in the image keeps its mode and owner, one that is not is
/// made with root's (or `--chown`'s), and a link on the way to it leads where it leads in the
/// image (`/var/run` to `/run`). Files keep their mode (`--chmod` replaces it); their owner is
/// root's, or `--chown`'s, or with `--from` the source's own. The ids are the layer's own, which
/// the sandbox maps; a rootless runner cannot give any but its own.
const Copier = struct {
    arena: Allocator,
    io: std.Io,
    /// Where the sources are; null when there is nothing there (a stage with no layers).
    src: ?*View,
    /// The layers below this one, for what the destination is there.
    dst: ?*View,
    /// The new layer's root.
    layer: std.Io.Dir,
    op: Copy,
    owner: ?Owner = null,
    why: []const u8 = "",
    /// The mode `placeDir` left for the caller to set on the directory it made last, once it is filled:
    /// a mode without write permission (`--chmod=640`) would keep the files out.
    leaf_later: ?u32 = null,

    fn fail(c: *Copier, comptime fmt: []const u8, args: anytype) error{ CopyFailed, OutOfMemory } {
        c.why = try std.fmt.allocPrint(c.arena, fmt, args);
        return error.CopyFailed;
    }

    fn run(c: *Copier) !void {
        c.owner = try c.parseChown(c.op.chown);
        const into = std.mem.endsWith(u8, c.op.dest, "/");
        const dest = try cleanPath(c.arena, c.op.dest);
        for (c.op.sources) |s| switch (s) {
            .path => |pattern| {
                const view = c.src orelse return c.fail("{s} is not in the source of the copy", .{pattern});
                const matches = try expand(c.arena, view, pattern);
                const literal = !hasMeta(try cleanPath(c.arena, pattern));
                for (matches) |m| {
                    const e = (try view.resolve(m, true)) orelse
                        return c.fail("{s} is not in the source of the copy", .{pattern});
                    try c.entry(e, std.fs.path.basenamePosix(m), into, dest);
                }
                std.debug.assert(!literal or matches.len == 1);
            },
            .inline_file => |f| try c.bytes(f.name, f.content, 0o644, into, dest),
            .url => |u| {
                if (!into and u.name.len == 0) return c.fail("the URL {s} names no file", .{u.url});
                try c.download(u.name, u.file, into, dest);
            },
        };
    }

    /// Whether `dest` is a directory of the image already (a file copied there goes into it).
    fn destIsDir(c: *Copier, dest: []const u8) !bool {
        const d = c.dst orelse return false;
        const e = (try d.resolve(dest, true)) orelse return false;
        return e.kind == .dir;
    }

    fn entry(c: *Copier, e: layer_view.Entry, name: []const u8, into: bool, dest: []const u8) !void {
        switch (e.kind) {
            .dir => {
                c.leaf_later = null;
                var to = try c.placeDir(dest, c.op.chmod);
                defer to.close(c.io);
                try c.tree(e, to, 0);
                if (c.leaf_later) |m| _ = linux.fchmod(to.handle, m);
            },
            .file => {
                const at = try c.destPath(name, into, dest);
                var to = try c.placeDir(std.fs.path.dirnamePosix(at) orelse "", null);
                defer to.close(c.io);
                try c.copyOne(e, to, std.fs.path.basenamePosix(at));
            },
            .symlink, .other => return c.fail("{s} is not a regular file, a directory or a link", .{name}),
        }
    }

    /// Where a file named `name` goes: into the destination if that is a directory, else as it.
    fn destPath(c: *Copier, name: []const u8, into: bool, dest: []const u8) ![]const u8 {
        if (into or try c.destIsDir(dest)) return joinPath(c.arena, dest, name);
        return dest;
    }

    fn bytes(c: *Copier, name: []const u8, data: []const u8, mode: u32, into: bool, dest: []const u8) !void {
        const target_path = try c.destPath(name, into, dest);
        var to = try c.placeDir(std.fs.path.dirnamePosix(target_path) orelse "", null);
        defer to.close(c.io);
        const base = std.fs.path.basenamePosix(target_path);
        const m = c.op.chmod orelse mode;
        // What an earlier source put there is replaced, never written through: a link planted in the
        // layer (a tree keeps its links) would lead out of it. `exclusive` is `O_EXCL`, which refuses
        // to follow a link at the name; the mode and owner are set on the descriptor.
        to.deleteFile(c.io, base) catch |err| if (err != error.FileNotFound) return err;
        const f = try to.createFile(c.io, base, .{ .exclusive = true, .permissions = .fromMode(m) });
        defer f.close(c.io);
        try f.writeStreamingAll(c.io, data);
        _ = linux.fchmod(f.handle, m);
        const o = c.idsOf(null);
        _ = linux.fchown(f.handle, o.uid, o.gid);
    }

    fn download(c: *Copier, name: []const u8, path: []const u8, into: bool, dest: []const u8) !void {
        const target_path = try c.destPath(name, into, dest);
        var to = try c.placeDir(std.fs.path.dirnamePosix(target_path) orelse "", null);
        defer to.close(c.io);
        const base = std.fs.path.basenamePosix(target_path);
        // Docker saves what it downloads readable by its owner alone.
        const m = c.op.chmod orelse 0o600;
        try std.Io.Dir.cwd().copyFile(path, to, base, c.io, .{ .permissions = .fromMode(m) });
        c.finish(to, base, m, null);
    }

    /// A file's mode, which `copyFile` passes through the umask, and its owner.
    fn finish(c: *Copier, to: std.Io.Dir, name: []const u8, mode: u32, e: ?layer_view.Entry) void {
        var buf: [std.fs.max_name_bytes + 1]u8 = undefined;
        if (name.len >= buf.len) return;
        @memcpy(buf[0..name.len], name);
        buf[name.len] = 0;
        const z: [*:0]const u8 = buf[0..name.len :0];
        _ = linux.fchmodat(to.handle, z, mode);
        const o = c.idsOf(e);
        _ = linux.fchownat(to.handle, z, o.uid, o.gid, linux.AT.SYMLINK_NOFOLLOW);
    }

    /// Who owns what is copied: `--chown`'s, or the source's own with `--from`, else root.
    fn idsOf(c: *Copier, e: ?layer_view.Entry) Owner {
        if (c.owner) |o| return o;
        if (c.op.from != .context) if (e) |x| return .{ .uid = x.uid, .gid = x.gid };
        return .{ .uid = 0, .gid = 0 };
    }

    fn copyOne(c: *Copier, e: layer_view.Entry, to: std.Io.Dir, to_name: []const u8) !void {
        const mode: u32 = c.op.chmod orelse e.mode;
        try e.parent().copyFile(e.name, to, to_name, c.io, .{ .permissions = .fromMode(mode) });
        c.finish(to, to_name, mode, e);
    }

    fn tree(c: *Copier, dir: layer_view.Entry, to: std.Io.Dir, depth: u32) !void {
        if (depth > 128) return c.fail("a directory nested more than 128 deep", .{});
        const view = c.src.?;
        for (try view.names(dir)) |name| {
            const e = (try view.child(dir, name)) orelse continue;
            switch (e.kind) {
                .dir => {
                    to.createDir(c.io, name, .default_dir) catch |err| if (err != error.PathAlreadyExists) return err;
                    var sub = try to.openDir(c.io, name, .{ .follow_symlinks = false, .iterate = true });
                    defer sub.close(c.io);
                    try c.tree(e, sub, depth + 1);
                    // The mode last: a directory without write permission still takes its files.
                    const o = c.idsOf(e);
                    _ = linux.fchown(sub.handle, o.uid, o.gid);
                    _ = linux.fchmod(sub.handle, c.op.chmod orelse e.mode);
                },
                .file => try c.copyOne(e, to, name),
                .symlink => {
                    const link = try view.readLink(e);
                    to.deleteFile(c.io, name) catch |err| if (err != error.FileNotFound) return err;
                    try to.symLink(c.io, link, name, .{});
                    const o = c.idsOf(e);
                    var buf: [std.fs.max_name_bytes + 1]u8 = undefined;
                    @memcpy(buf[0..name.len], name);
                    buf[name.len] = 0;
                    _ = linux.fchownat(to.handle, buf[0..name.len :0], o.uid, o.gid, linux.AT.SYMLINK_NOFOLLOW);
                },
                .other => return c.fail("{s} is not a regular file, a directory or a link", .{name}),
            }
        }
    }

    /// The directory `path` (of the image, absolute or not) in the new layer, made with the
    /// directories on the way, an opened handle. Where the image has a directory its mode and
    /// owner are kept; a link on the way is followed through the image, as `RUN` would see it.
    fn placeDir(c: *Copier, path: []const u8, leaf_mode: ?u32) !std.Io.Dir {
        const Seg = struct { name: []const u8, existing: ?layer_view.Entry };
        var real: std.ArrayList(Seg) = .empty;
        var pending: std.ArrayList([]const u8) = .empty;
        var parts = std.mem.splitBackwardsScalar(u8, path, '/');
        while (parts.next()) |p| try pending.append(c.arena, p);
        var links: u32 = 0;
        while (pending.pop()) |part| {
            if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
            if (std.mem.eql(u8, part, "..")) {
                if (real.items.len > 0) _ = real.pop();
                continue;
            }
            const here: ?layer_view.Entry = if (real.items.len > 0) real.items[real.items.len - 1].existing else if (c.dst) |d| d.top else null;
            const found = if (here) |h| try c.dst.?.child(h, part) else null;
            const e = found orelse {
                try real.append(c.arena, .{ .name = part, .existing = null });
                continue;
            };
            switch (e.kind) {
                .dir => try real.append(c.arena, .{ .name = part, .existing = e }),
                .symlink => {
                    links += 1;
                    if (links > 40) return c.fail("{s} is a link that never ends", .{path});
                    const to = try c.dst.?.readLink(e);
                    if (to.len > 0 and to[0] == '/') real.clearRetainingCapacity();
                    var more = std.mem.splitBackwardsScalar(u8, to, '/');
                    while (more.next()) |p| try pending.append(c.arena, p);
                },
                else => return c.fail("{s} is not a directory in the image", .{path}),
            }
        }
        var dir = try c.layer.openDir(c.io, ".", .{});
        errdefer dir.close(c.io);
        for (real.items, 0..) |seg, at| {
            var made = true;
            dir.createDir(c.io, seg.name, .default_dir) catch |err| switch (err) {
                error.PathAlreadyExists => made = false,
                else => return err,
            };
            // Iterating, so the handle is a real one: `fchmod` and `fchown` refuse an `O_PATH` one.
            const sub = try dir.openDir(c.io, seg.name, .{ .follow_symlinks = false, .iterate = true });
            dir.close(c.io);
            dir = sub;
            if (!made) continue;
            if (seg.existing) |e| {
                _ = linux.fchown(dir.handle, e.uid, e.gid);
                _ = linux.fchmod(dir.handle, e.mode);
            } else {
                const o = c.owner orelse Owner{ .uid = 0, .gid = 0 };
                _ = linux.fchown(dir.handle, o.uid, o.gid);
                // A directory made on the way is 0755 whatever `--chmod` says (BuildKit gives it the file mode,
                // 0640 for instance, which nobody can enter); `--chmod` is the mode of a copied directory itself.
                _ = linux.fchmod(dir.handle, 0o755);
                if (at == real.items.len - 1) c.leaf_later = leaf_mode;
            }
        }
        return dir;
    }

    /// `--chown`'s `user[:group]`: ids, or names the image's /etc/passwd and /etc/group have.
    fn parseChown(c: *Copier, text: []const u8) !?Owner {
        if (text.len == 0) return null;
        const colon = std.mem.indexOfScalar(u8, text, ':');
        const user = text[0 .. colon orelse text.len];
        const group = if (colon) |i| text[i + 1 ..] else "";
        var primary: ?u32 = null;
        const uid = std.fmt.parseInt(u32, user, 10) catch blk: {
            const f = (try c.account("etc/passwd", user)) orelse
                return c.fail("the user {s} of --chown is not in the image's /etc/passwd", .{user});
            primary = std.fmt.parseInt(u32, f[3], 10) catch null;
            break :blk std.fmt.parseInt(u32, f[2], 10) catch return c.fail("/etc/passwd gives {s} no id", .{user});
        };
        if (group.len == 0) return .{ .uid = uid, .gid = primary orelse uid };
        const gid = std.fmt.parseInt(u32, group, 10) catch blk: {
            const f = (try c.account("etc/group", group)) orelse
                return c.fail("the group {s} of --chown is not in the image's /etc/group", .{group});
            break :blk std.fmt.parseInt(u32, f[2], 10) catch return c.fail("/etc/group gives {s} no id", .{group});
        };
        return .{ .uid = uid, .gid = gid };
    }

    /// A file of the layers below as text, "" when it is not there.
    fn textOf(c: *Copier, view: *View, path: []const u8) ![]const u8 {
        const e = (try view.resolve(path, true)) orelse return "";
        if (e.kind != .file) return "";
        return e.parent().readFileAlloc(c.io, e.name, c.arena, .limited(4 << 20));
    }

    /// `name`'s line of /etc/passwd or /etc/group in the layers below, as `images.entryOf`.
    fn account(c: *Copier, path: []const u8, name: []const u8) !?[4][]const u8 {
        const d = c.dst orelse return null;
        return images.entryOf(try c.textOf(d, path), name, null);
    }
};

// --- tests ---

/// The planner's images for the tests: every reference is this one, with `id` its identity.
const FixedBases = struct {
    config: images.Image = .{ .rootfs = "" },
    id: []const u8 = "base",
    /// The references asked for, in order.
    asked: std.ArrayList([]const u8) = .empty,
    arena: Allocator,

    iface: Bases = .{ .resolveFn = resolve },

    fn bases(f: *FixedBases) *Bases {
        return &f.iface;
    }

    fn resolve(b: *Bases, _: Allocator, ref: []const u8, why: *[]const u8) anyerror!?BaseImage {
        const f: *FixedBases = @fieldParentPtr("iface", b);
        try f.asked.append(f.arena, ref);
        if (std.mem.eql(u8, ref, "missing")) {
            why.* = "the image missing could not be pulled";
            return null;
        }
        return .{ .config = f.config, .id = f.id };
    }
};

const Fixed = struct {
    digest: [64]u8 = @splat('0'),
    iface: Context = .{ .digestFn = digestOf, .fetchFn = fetchOf },
    fn context(f: *Fixed) *Context {
        return &f.iface;
    }
    fn digestOf(c: *Context, _: Allocator, _: []const []const u8) anyerror![64]u8 {
        const f: *Fixed = @fieldParentPtr("iface", c);
        return f.digest;
    }
    fn fetchOf(_: *Context, _: Allocator, _: []const u8) anyerror!Fetched {
        return .{ .file = "/nowhere", .digest = @splat('7') };
    }
};

fn planOf(arena: Allocator, text: []const u8, f: *FixedBases, c: *Fixed) !Plan {
    return (try plan(arena, (try parse(arena, text)).ok, f.bases(), &.{}, c.context())).ok;
}

fn refusedWhy(arena: Allocator, text: []const u8) ![]const u8 {
    var f: FixedBases = .{ .arena = arena };
    var c: Fixed = .{};
    const parsed = try parse(arena, text);
    if (parsed == .refused) return parsed.refused.why;
    return switch (try plan(arena, parsed.ok, f.bases(), &.{}, c.context())) {
        .refused => |r| r.why,
        .ok => "(planned)",
    };
}

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

    try std.testing.expectEqualStrings("`ONBUILD` is not native yet", (try parse(arena, "FROM a\nONBUILD RUN x")).refused.why);
    try std.testing.expect((try parse(arena, "RUN true")) == .refused);
    try std.testing.expectEqualStrings("an escape character other than `\\`", (try parse(arena, "# escape=`\nFROM a")).refused.why);
}

test "parse: heredocs of RUN, COPY and ADD, with their bodies, and the lines after them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const ins = (try parse(arena,
        \\FROM a
        \\RUN <<EOF
        \\set -e
        \\echo "$HOME" # not a comment
        \\EOF
        \\COPY <<-"CONF" <<TXT /etc/
    ++ "\n\tindented $KEPT\n\tCONF\n" ++
        \\x=$Y
        \\TXT
        \\RUN cat <<EOF > /f && echo $((1<<2)) <<< here
        \\body
        \\EOF
        \\ENV AFTER=1
    )).ok;
    try std.testing.expectEqual(@as(usize, 5), ins.len);
    try std.testing.expectEqual(@as(usize, 1), ins[1].heredocs.len);
    try std.testing.expectEqualStrings("set -e\necho \"$HOME\" # not a comment\n", ins[1].heredocs[0].body);
    try std.testing.expect(ins[1].heredocs[0].expand);
    try std.testing.expectEqual(@as(usize, 2), ins[2].heredocs.len);
    try std.testing.expectEqualStrings("CONF", ins[2].heredocs[0].name);
    try std.testing.expect(!ins[2].heredocs[0].expand);
    try std.testing.expectEqualStrings("indented $KEPT\n", ins[2].heredocs[0].body);
    try std.testing.expectEqualStrings("x=$Y\n", ins[2].heredocs[1].body);
    try std.testing.expectEqual(@as(usize, 1), ins[3].heredocs.len);
    try std.testing.expectEqual(Kind.env, ins[4].kind);
    // The line numbers are the file's, the bodies counted.
    try std.testing.expectEqual(@as(u32, 14), ins[4].line);
    try std.testing.expectEqualStrings("the heredoc `EOF` is never closed", (try parse(arena, "FROM a\nRUN <<EOF\nx")).refused.why);
    const none = (try parse(arena, "FROM a\nRUN echo $((1<<2)) '<<EOF' \"<<X\"")).ok;
    try std.testing.expectEqual(@as(usize, 0), none[1].heredocs.len);
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

test "globMatch: path.Match's pattern, for one path component" {
    const T = struct { []const u8, []const u8, bool };
    for ([_]T{
        .{ "*.sh", "entry.sh", true },
        .{ "*.sh", "entry.py", false },
        .{ "*", ".hidden", true },
        .{ "a?c", "abc", true },
        .{ "a?c", "ac", false },
        .{ "[a-c]x", "bx", true },
        .{ "[a-c]x", "dx", false },
        .{ "[^a-c]x", "dx", true },
        .{ "go.*", "go.mod", true },
        .{ "a*b*c", "aXXbYYc", true },
        .{ "a*b*c", "aXXbYY", false },
        .{ "\\*", "*", true },
        .{ "\\*", "a", false },
        .{ "[", "[", false },
        .{ "", "", true },
        .{ "*", "", true },
    }) |t| try std.testing.expectEqual(t[2], globMatch(t[0], t[1]));
}

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
    var f: FixedBases = .{ .arena = arena, .config = .{ .rootfs = "", .env = &.{"PATH=/usr/bin:/bin"}, .cmd = &.{"/bin/sh"} } };
    var ctx: Fixed = .{};
    const p = (try plan(arena, ins, f.bases(), &.{}, ctx.context())).ok;
    try std.testing.expectEqualStrings("alpine:3.22", f.asked.items[0]);
    const st = p.stages[0];
    try std.testing.expectEqual(@as(usize, 10), st.steps.len);
    const run = st.steps[4].op.run;
    try std.testing.expectEqualStrings("/opt/tool", run.workdir);
    try std.testing.expectEqualStrings("echo $VERSION > version", run.argv[2]);
    try std.testing.expectEqualStrings("PATH=/opt/tool/bin:/usr/bin:/bin", run.env[0]);
    try std.testing.expectEqualStrings("VERSION=1", run.env[2]);
    const copy = st.steps[5].op.copy;
    try std.testing.expectEqualStrings("/opt/tool/bin/", copy.dest);
    try std.testing.expectEqual(@as(?u32, 0o755), copy.chmod);
    try std.testing.expectEqualStrings("/opt/tool/bin/entrypoint.sh", st.config.entrypoint[0]);
    // ENTRYPOINT leaves a CMD set earlier in the stage, and resets the base image's, as Docker does.
    try std.testing.expectEqual(@as(usize, 3), st.config.cmd.len);
    const reset = try planOf(arena, "FROM a\nENTRYPOINT [\"x\"]", &f, &ctx);
    try std.testing.expectEqual(@as(usize, 0), reset.stages[0].config.cmd.len);
    try std.testing.expectEqualStrings("0", st.config.user);
    try std.testing.expectEqualStrings("TOOL_HOME=/opt/tool", st.config.env[1]);
    try std.testing.expectEqualStrings("/opt/tool", st.config.workdir);

    // A build argument changes the RUN's key and every key after it, not the ones before.
    const p2 = (try plan(arena, ins, f.bases(), &.{.{ .name = "VERSION", .value = "2" }}, ctx.context())).ok;
    for (st.steps[0..4], p2.stages[0].steps[0..4]) |x, y| try std.testing.expectEqualSlices(u8, &x.key, &y.key);
    for (st.steps[4..], p2.stages[0].steps[4..]) |x, y| try std.testing.expect(!std.mem.eql(u8, &x.key, &y.key));
    // The context's content changes the COPY's key and the later ones only.
    var ctx3: Fixed = .{ .digest = @splat('1') };
    const p3 = (try plan(arena, ins, f.bases(), &.{}, ctx3.context())).ok;
    for (st.steps[0..5], p3.stages[0].steps[0..5]) |x, y| try std.testing.expectEqualSlices(u8, &x.key, &y.key);
    for (st.steps[5..], p3.stages[0].steps[5..]) |x, y| try std.testing.expect(!std.mem.eql(u8, &x.key, &y.key));
}

test "plan: what a Dockerfile does not do natively is refused, with the line's reason" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const Bad = struct { []const u8, []const u8 };
    for ([_]Bad{
        .{ "FROM a\nADD app.tar.gz /", "archive" },
        .{ "FROM a\nADD git@github.com:o/r.git /r", "git repository" },
        .{ "FROM a\nADD https://github.com/o/r.git#v1 /r", "git repository" },
        .{ "FROM a\nADD ftp://example.com/x /r", "only http and https" },
        .{ "FROM a\nCOPY ../secret /x", "outside the build context" },
        .{ "FROM a\nCOPY a b /dir", "ends with /" },
        .{ "FROM a\nRUN --mount=type=cache,target=/c make", "RUN --mount" },
        .{ "FROM a\nCOPY --parents a /b", "--parents" },
        .{ "FROM a\nRUN <<EOF\n#!/usr/bin/env python3\nprint(1)\nEOF", "#!" },
        .{ "FROM a\nSHELL powershell", "JSON array" },
        .{ "FROM --platform=windows/amd64 a", "own platform" },
        .{ "FROM a AS x\nFROM b AS X", "used twice" },
        .{ "FROM missing", "could not be pulled" },
        .{ "FROM a\nCOPY --from=missing /x /y", "could not be pulled" },
        .{ "FROM a\nCOPY --chmod=u+x a /b", "octal" },
        .{ "FROM a\nCOPY --chmod=17777 a /b", "octal" },
        .{ "FROM a\nCOPY --chmod=+7 a /b", "octal" },
        .{ "FROM a\nCOPY --chmod=-1 a /b", "octal" },
        .{ "FROM a\nCOPY --chown=:5 a /b", "no user" },
    }) |b| {
        const why = try refusedWhy(arena, b[0]);
        errdefer std.debug.print("{s}\n  -> {s}\n", .{ b[0], why });
        try std.testing.expect(std.mem.indexOf(u8, why, b[1]) != null);
    }
}

test "plan: multi-stage builds, keyed stage by stage, and only the stages the last one needs" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const text =
        \\ARG GO=1.25
        \\FROM golang:${GO} AS Build
        \\WORKDIR /src
        \\RUN go build -o /out/app
        \\FROM build AS test
        \\RUN go test
        \\FROM alpine:3.22 AS runtime
        \\COPY --from=build /out/app /usr/bin/app
        \\COPY --from=0 /src/LICENSE /LICENSE
        \\COPY --from=busybox:1 /bin/busybox /bin/busybox
        \\ENTRYPOINT ["/usr/bin/app"]
    ;
    var f: FixedBases = .{ .arena = arena };
    var ctx: Fixed = .{};
    const p = try planOf(arena, text, &f, &ctx);
    try std.testing.expectEqual(@as(usize, 3), p.stages.len);
    try std.testing.expectEqual(@as(u32, 2), p.final);
    // `test` is nobody's: not planned, its RUN never asked for.
    try std.testing.expect(!p.stages[1].needed);
    try std.testing.expectEqual(@as(usize, 0), p.stages[1].steps.len);
    try std.testing.expectEqualStrings("build", p.stages[0].name);
    try std.testing.expectEqualStrings("golang:1.25", f.asked.items[0]);
    try std.testing.expectEqualStrings("alpine:3.22", f.asked.items[1]);
    try std.testing.expectEqualStrings("busybox:1", f.asked.items[2]);
    try std.testing.expectEqual(@as(usize, 3), f.asked.items.len);
    const rt = p.stages[2];
    try std.testing.expect(rt.base == .image);
    const c0 = rt.steps[0].op.copy;
    try std.testing.expectEqual(@as(u32, 0), c0.from.stage);
    try std.testing.expectEqualStrings("/out/app", c0.sources[0].path);
    try std.testing.expectEqual(@as(u32, 0), rt.steps[1].op.copy.from.stage);
    try std.testing.expect(rt.steps[2].op.copy.from == .rootfs);

    // A change in the build stage reaches the runtime's COPY --from and what follows, not the
    // runtime's own earlier steps (there are none before it here).
    const changed = try planOf(arena, try std.mem.replaceOwned(u8, arena, text, "go build", "go build -v"), &f, &ctx);
    try std.testing.expect(!std.mem.eql(u8, &p.stages[0].key, &changed.stages[0].key));
    for (rt.steps, changed.stages[2].steps) |x, y| try std.testing.expect(!std.mem.eql(u8, &x.key, &y.key));

    // A stage that starts from another continues its keys: the same steps, the same layers.
    const same = try planOf(arena, "FROM a AS one\nRUN x\nFROM one AS two\nRUN y\nFROM two\nRUN z", &f, &ctx);
    const flat = try planOf(arena, "FROM a\nRUN x\nRUN y\nRUN z", &f, &ctx);
    try std.testing.expect(same.stages[1].base == .stage);
    try std.testing.expectEqual(@as(usize, 3), same.stages.len);
    try std.testing.expectEqualSlices(u8, &same.stages[2].key, &flat.stages[0].key);
    // The stage is what its steps were: a stage's own key is its last step's.
    try std.testing.expectEqualSlices(u8, &same.stages[0].steps[0].key, &same.stages[0].key);
}

test "plan: a stage inherits the config of the one it starts from, SHELL included" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: FixedBases = .{ .arena = arena, .config = .{ .rootfs = "", .workdir = "/go", .env = &.{"A=1"} } };
    var ctx: Fixed = .{};
    const p = try planOf(arena,
        \\FROM base AS one
        \\ENV B=2
        \\USER app
        \\SHELL ["/bin/bash", "-o", "pipefail", "-c"]
        \\FROM one
        \\RUN echo $A $B
        \\CMD run it
        \\WORKDIR sub
    , &f, &ctx);
    const last = p.stages[1];
    try std.testing.expectEqualStrings("app", last.config.user);
    const run = last.steps[0].op.run;
    try std.testing.expectEqualStrings("/go", run.workdir);
    try std.testing.expectEqualStrings("app", run.user);
    try std.testing.expectEqualStrings("A=1", run.env[0]);
    try std.testing.expectEqualStrings("B=2", run.env[1]);
    try std.testing.expectEqual(@as(usize, 5), run.argv.len);
    try std.testing.expectEqualStrings("/bin/bash", run.argv[0]);
    try std.testing.expectEqualStrings("/bin/bash", last.config.cmd[0]);
    try std.testing.expectEqualStrings("run it", last.config.cmd[4]);
    try std.testing.expectEqualStrings("/go/sub", last.config.workdir);
}

test "plan: ARG scopes: before FROM only FROM sees it, a stage redeclares it, platform arguments are the runner's" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: FixedBases = .{ .arena = arena };
    var ctx: Fixed = .{};
    const p = try planOf(arena,
        \\ARG V=3.22
        \\ARG TARGETARCH
        \\FROM --platform=$BUILDPLATFORM alpine:$V
        \\RUN echo $V
        \\ARG V
        \\ARG TARGETARCH
        \\RUN echo $V $TARGETARCH
    , &f, &ctx);
    try std.testing.expectEqualStrings("alpine:3.22", f.asked.items[0]);
    // Outside the stage, V is not a variable of its RUNs; once declared it takes the default.
    try std.testing.expectEqual(@as(usize, 0), p.stages[0].steps[0].op.run.env.len);
    const run = p.stages[0].steps[3].op.run;
    try std.testing.expectEqualStrings("V=3.22", run.env[0]);
    try std.testing.expect(std.mem.startsWith(u8, run.env[1], "TARGETARCH="));
}

test "plan: COPY's forms: pattern, heredoc, URL, --link, flags before JSON" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: FixedBases = .{ .arena = arena };
    var ctx: Fixed = .{};
    const p = try planOf(arena,
        \\FROM a
        \\ENV NAME=world
        \\COPY --link *.sh lib/*.py /opt/
        \\COPY <<EOF /etc/greeting
        \\hello $NAME
        \\EOF
        \\COPY <<'EOF' /etc/raw
        \\hello $NAME
        \\EOF
        \\ADD https://example.com/dl/tool.bin?x=1 /usr/bin/
        \\COPY --chown=1:2 ["a b", "/d"]
    , &f, &ctx);
    const steps = p.stages[0].steps;
    try std.testing.expectEqual(@as(usize, 6), steps.len);
    try std.testing.expectEqualStrings("*.sh", steps[1].op.copy.sources[0].path);
    try std.testing.expectEqualStrings("lib/*.py", steps[1].op.copy.sources[1].path);
    try std.testing.expectEqualStrings("hello world\n", steps[2].op.copy.sources[0].inline_file.content);
    try std.testing.expectEqualStrings("EOF", steps[2].op.copy.sources[0].inline_file.name);
    try std.testing.expectEqualStrings("hello $NAME\n", steps[3].op.copy.sources[0].inline_file.content);
    try std.testing.expectEqualStrings("tool.bin", steps[4].op.copy.sources[0].url.name);
    try std.testing.expectEqualStrings("a b", steps[5].op.copy.sources[0].path);
    try std.testing.expectEqualStrings("1:2", steps[5].op.copy.chown);
    // The heredoc's content is in its key: the same file name with other lines is another layer.
    const q = try planOf(arena, "FROM a\nENV NAME=there\nCOPY --link *.sh lib/*.py /opt/\nCOPY <<EOF /etc/greeting\nhello $NAME\nEOF", &f, &ctx);
    try std.testing.expect(!std.mem.eql(u8, &steps[2].key, &q.stages[0].steps[2].key));
}

test "plan: RUN's heredocs: a script of its own, or the shell's own with the lines after" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var f: FixedBases = .{ .arena = arena };
    var ctx: Fixed = .{};
    const p = try planOf(arena, "FROM a\nRUN <<EOF\nset -e\necho one\nEOF\nRUN cat <<EOF > /f\nbody\nEOF\nRUN echo $((1<<2))", &f, &ctx);
    const steps = p.stages[0].steps;
    try std.testing.expectEqualStrings("set -e\necho one\n", steps[0].op.run.argv[2]);
    try std.testing.expectEqualStrings("cat <<EOF > /f\nbody\nEOF\n", steps[1].op.run.argv[2]);
    try std.testing.expectEqualStrings("echo $((1<<2))", steps[2].op.run.argv[2]);
    // The script's lines are in the key.
    const other = try planOf(arena, "FROM a\nRUN <<EOF\nset -e\necho two\nEOF", &f, &ctx);
    try std.testing.expect(!std.mem.eql(u8, &steps[0].key, &other.stages[0].steps[0].key));
}

test "plan: what the base image is changes every key, though its reference did not" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const text = "FROM alpine:3.22\nENV X=1\nRUN apk add curl\nCOPY a /a\n";
    var ctx: Fixed = .{};
    var f_old: FixedBases = .{ .arena = arena, .id = "sha256:old" };
    var f_new: FixedBases = .{ .arena = arena, .id = "sha256:new" };
    const old = try planOf(arena, text, &f_old, &ctx);
    const new = try planOf(arena, text, &f_new, &ctx);
    for (old.stages[0].steps, new.stages[0].steps) |x, y| try std.testing.expect(!std.mem.eql(u8, &x.key, &y.key));
    const same = try planOf(arena, text, &f_old, &ctx);
    for (old.stages[0].steps, same.stages[0].steps) |x, y| try std.testing.expectEqualSlices(u8, &x.key, &y.key);
    // A stage's keys are on its parent stage's, so the base's identity reaches the stage after.
    const staged = "FROM alpine:3.22 AS one\nRUN x\nFROM one\nRUN y";
    const s_old = try planOf(arena, staged, &f_old, &ctx);
    const s_new = try planOf(arena, staged, &f_new, &ctx);
    try std.testing.expect(!std.mem.eql(u8, &s_old.stages[1].steps[0].key, &s_new.stages[1].steps[0].key));
}

test "plan: fields of an instruction never run into one another in its key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var ctx: Fixed = .{};
    var f: FixedBases = .{ .arena = arena };
    const copy = struct {
        fn key(ar: Allocator, c: *Fixed, fb: *FixedBases, text: []const u8) ![64]u8 {
            const p = try planOf(ar, text, fb, c);
            return p.stages[0].steps[0].key;
        }
    }.key;
    // Spaces in a destination, which joined with spaces read as a source and an owner.
    const one = try copy(arena, &ctx, &f, "FROM a\nCOPY [\"s\", \"/d 1\"]");
    const two = try copy(arena, &ctx, &f, "FROM a\nCOPY --chown=1 s /d");
    try std.testing.expect(!std.mem.eql(u8, &one, &two));
    // An environment's boundaries: one variable holding what looks like two.
    var f1: FixedBases = .{ .arena = arena, .config = .{ .rootfs = "", .env = &.{"B=2"} } };
    var f2: FixedBases = .{ .arena = arena, .config = .{ .rootfs = "", .env = &.{"B=2\x00A=1"} } };
    const nul = try planOf(arena, "FROM a\nENV A=1\nRUN x", &f1, &ctx);
    const joined = try planOf(arena, "FROM a\nENV A=1\nRUN x", &f2, &ctx);
    try std.testing.expect(!std.mem.eql(u8, &nul.stages[0].steps[1].key, &joined.stages[0].steps[1].key));
    // A source that is a path and a heredoc of that name are two things.
    const path = try copy(arena, &ctx, &f, "FROM a\nCOPY x /d");
    const here = try copy(arena, &ctx, &f, "FROM a\nCOPY <<x /d\nx");
    try std.testing.expect(!std.mem.eql(u8, &path, &here));
}

fn testView(arena: Allocator, tmp: *std.testing.TmpDir, base: []const u8) !*View {
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", arena);
    return (try View.open(arena, std.testing.io, &.{root}, base, "user.overlay.opaque")).?;
}

test "contextDigest: a file's content cannot pass for the entries after it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "one/d");
    try tmp.dir.createDirPath(io, "two/d");
    // The walk as it was written, with no lengths: `a`, then its end, then `b`'s name and metadata.
    var meta: [16]u8 = undefined;
    std.mem.writeInt(u64, meta[0..8], @backingInt(std.Io.File.Kind.file), .little);
    std.mem.writeInt(u64, meta[8..16], 0o644, .little);
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const Plant = struct { path: []const u8, data: []const u8 };
    for ([_]Plant{
        .{ .path = "one/d/a", .data = "X" },
        .{ .path = "one/d/b", .data = "Y" },
        .{ .path = "two/d/a", .data = "X\x01b\x00" ++ meta ++ "Y" },
    }) |f| {
        try tmp.dir.writeFile(io, .{ .sub_path = f.path, .data = f.data });
        const z = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ root, f.path }, 0);
        _ = std.os.linux.chmod(z, 0o644);
    }
    const one = try contextDigest(arena, try testView(arena, &tmp, "one"), &.{"d"});
    const two = try contextDigest(arena, try testView(arena, &tmp, "two"), &.{"d"});
    try std.testing.expect(!std.mem.eql(u8, &one, &two));
}

test "contextDigest walks the sources in order, a link named as a source followed, one inside not" {
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
    try tmp.dir.symLink(io, "entrypoint.sh", "ctx/alias", .{});
    const v = try testView(arena, &tmp, "ctx");
    const d1 = try contextDigest(arena, v, &.{ "entrypoint.sh", "dir" });
    try std.testing.expectEqualSlices(u8, &d1, &(try contextDigest(arena, v, &.{ "./entrypoint.sh", "dir/" })));
    // The symlink's target's content is not read: changing it changes nothing.
    try tmp.dir.writeFile(io, .{ .sub_path = "outside", .data = "changed" });
    try std.testing.expectEqualSlices(u8, &d1, &(try contextDigest(arena, v, &.{ "entrypoint.sh", "dir" })));
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/dir/b", .data = "c" });
    try std.testing.expect(!std.mem.eql(u8, &d1, &(try contextDigest(arena, v, &.{ "entrypoint.sh", "dir" }))));
    try std.testing.expectError(error.SourceMissing, contextDigest(arena, v, &.{"nope"}));
    // A link named as a source is read through: it digests as its target's content does.
    const alias = try contextDigest(arena, v, &.{"alias"});
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/entrypoint.sh", .data = "#!/bin/sh\necho changed\n" });
    try std.testing.expect(!std.mem.eql(u8, &alias, &(try contextDigest(arena, v, &.{"alias"}))));
    // A pattern digests its matches, so a new match changes it, and a miss is a match of none.
    const star = try contextDigest(arena, v, &.{"*.sh"});
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/more.sh", .data = "x" });
    try std.testing.expect(!std.mem.eql(u8, &star, &(try contextDigest(arena, v, &.{"*.sh"}))));
    _ = try contextDigest(arena, v, &.{"*.nothing"});
    // `..` stops at the root, as Docker's does.
    try std.testing.expectEqualSlices(u8, &(try contextDigest(arena, v, &.{"entrypoint.sh"})), &(try contextDigest(arena, v, &.{"../../entrypoint.sh"})));
}

/// A `RUN` for the tests: its last word is a path, which it makes in the layer with its content
/// "built"; `exit N` fails.
const Recorder = struct {
    arena: Allocator,
    runs: std.ArrayList([]const u8) = .empty,
    lowers_seen: usize = 0,
    fn runner(r: *Recorder) Runner {
        return .{ .ptr = r, .runFn = run };
    }
    fn run(ptr: *anyopaque, lowers: []const []const u8, upper: []const u8, op: @FieldType(Step.Op, "run")) anyerror!i32 {
        const r: *Recorder = @ptrCast(@alignCast(ptr));
        const text = op.argv[op.argv.len - 1];
        try r.runs.append(r.arena, text);
        r.lowers_seen = lowers.len;
        if (std.mem.indexOf(u8, text, "exit 3") != null) return 3;
        const io = std.testing.io;
        const path = try std.fmt.allocPrint(r.arena, "{s}/{s}", .{ upper, std.mem.trim(u8, text, " ") });
        if (std.fs.path.dirname(path)) |d| try std.Io.Dir.cwd().createDirPath(io, d);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "built" });
        return 0;
    }
};

/// A tree of files for a build's tests, under `<tmp>/<name>`.
fn plant(tmp: *std.testing.TmpDir, name: []const u8, files: []const [2][]const u8) !void {
    const io = std.testing.io;
    for (files) |f| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/{s}", .{ name, f[0] });
        defer std.testing.allocator.free(path);
        if (std.fs.path.dirname(path)) |d| try tmp.dir.createDirPath(io, d);
        if (std.mem.startsWith(u8, f[1], "->")) {
            try tmp.dir.symLink(io, f[1][2..], path, .{});
        } else try tmp.dir.writeFile(io, .{ .sub_path = path, .data = f[1] });
    }
}

const Harness = struct {
    arena: Allocator,
    tmp: *std.testing.TmpDir,
    root: []const u8,
    store: layers.Store,
    held: *std.ArrayList(std.Io.File),

    fn init(arena: Allocator, tmp: *std.testing.TmpDir, held: *std.ArrayList(std.Io.File)) !Harness {
        const io = std.testing.io;
        for ([_][]const u8{ "store", "rootfs" }) |d| try tmp.dir.createDirPath(io, d);
        const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
        const store_dir = try std.fmt.allocPrint(arena, "{s}/store", .{root});
        try @import("Store.zig").prepare(arena, io, store_dir, .{ .check_parents = false });
        return .{
            .arena = arena,
            .tmp = tmp,
            .root = root,
            .held = held,
            .store = .{ .dir = store_dir, .store = .{ .root = store_dir }, .held = held, .scope = "repo", .userns = "mapped" },
        };
    }

    fn base(h: *Harness) FixedBases {
        return .{ .arena = h.arena, .config = .{ .rootfs = h.path("rootfs") } };
    }

    fn path(h: *Harness, sub: []const u8) []const u8 {
        return std.fmt.allocPrint(h.arena, "{s}/{s}", .{ h.root, sub }) catch @panic("out of memory");
    }

    const Ctx = struct {
        view: *View,
        iface: Context = .{ .digestFn = digest },
        fn digest(i: *Context, ar: Allocator, sources: []const []const u8) anyerror![64]u8 {
            const c: *@This() = @fieldParentPtr("iface", i);
            return contextDigest(ar, c.view, sources);
        }
    };

    /// `text` planned and built over `rootfs`, with the context `ctx` of the tmp dir.
    fn run(h: *Harness, text: []const u8, rec: *Recorder) !Built {
        const arena = h.arena;
        const view = try testView(arena, h.tmp, "ctx");
        var c: Ctx = .{ .view = view };
        var fb = h.base();
        const p = (try plan(arena, (try parse(arena, text)).ok, fb.bases(), &.{}, &c.iface)).ok;
        return build(arena, std.testing.io, p, h.store, rec.runner(), .{
            .context = view,
            .opaque_xattr = "user.overlay.opaque",
        });
    }
};

fn expectFile(arena: Allocator, lowers: []const []const u8, path: []const u8, content: []const u8) !void {
    const v = (try View.open(arena, std.testing.io, lowers, "", "user.overlay.opaque")).?;
    defer v.close();
    const e = (try v.resolve(path, true)) orelse {
        std.debug.print("{s} is not in the image\n", .{path});
        return error.TestUnexpectedResult;
    };
    const got = try e.parent().readFileAlloc(std.testing.io, e.name, arena, .limited(1 << 20));
    try std.testing.expectEqualStrings(content, got);
}

fn expectMode(arena: Allocator, lowers: []const []const u8, path: []const u8, mode: u32) !void {
    const v = (try View.open(arena, std.testing.io, lowers, "", "user.overlay.opaque")).?;
    defer v.close();
    const e = (try v.resolve(path, false)) orelse return error.TestUnexpectedResult;
    errdefer std.debug.print("{s}: mode {o}, want {o}\n", .{ path, e.mode, mode });
    try std.testing.expectEqual(mode, e.mode);
}

fn expectMissing(arena: Allocator, lowers: []const []const u8, path: []const u8) !void {
    const v = (try View.open(arena, std.testing.io, lowers, "", "user.overlay.opaque")).?;
    defer v.close();
    try std.testing.expect((try v.resolve(path, false)) == null);
}

test "build: COPY into its layer, RUN through the runner, and a second build takes every layer from the store" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    var h = try Harness.init(arena, &tmp, &held);
    try plant(&tmp, "ctx", &.{
        .{ "entrypoint.sh", "#!/bin/sh\n" },
        .{ "lib/a.sh", "a" },
        .{ "lib/b.sh", "->a.sh" },
    });
    const text =
        \\FROM alpine:3.22
        \\COPY --chmod=755 entrypoint.sh /entrypoint.sh
        \\COPY lib /opt/lib/
        \\RUN opt/ran
        \\ENTRYPOINT ["/entrypoint.sh"]
    ;
    var rec: Recorder = .{ .arena = arena };
    const built = (try h.run(text, &rec)).ok;
    try std.testing.expectEqual(@as(usize, 4), built.lowers.len);
    try std.testing.expectEqualStrings(h.path("rootfs"), built.lowers[3]);
    try std.testing.expectEqual(@as(usize, 3), rec.lowers_seen);
    try std.testing.expectEqual(@as(usize, 1), rec.runs.items.len);
    try expectMode(arena, built.lowers, "entrypoint.sh", 0o755);
    try expectFile(arena, built.lowers, "opt/lib/a.sh", "a");
    var buf: [64]u8 = undefined;
    const link = try std.fmt.allocPrint(arena, "{s}/opt/lib/b.sh", .{built.lowers[1]});
    try std.testing.expectEqualStrings("a.sh", buf[0..try std.Io.Dir.cwd().readLink(io, link, &buf)]);

    // Built again: every layer is the store's, nothing runs.
    var again: Recorder = .{ .arena = arena };
    const second = (try h.run(text, &again)).ok;
    try std.testing.expectEqual(@as(usize, 0), again.runs.items.len);
    for (built.lowers, second.lowers) |x, y| try std.testing.expectEqualStrings(x, y);

    // A failing RUN stores nothing for its key.
    var bad_rec: Recorder = .{ .arena = arena };
    const failed = (try h.run("FROM alpine\nRUN exit 3", &bad_rec)).failed;
    try std.testing.expectEqual(@as(i32, 3), failed.code);
    try std.testing.expect(failed.what == .run);
}

test "build: where a COPY puts things: into a directory that is there, through a link, by pattern" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    var h = try Harness.init(arena, &tmp, &held);
    // The image: /usr/bin, /bin -> usr/bin, /var/run -> /run, /run, a sticky /tmp, an /opt/app.
    try plant(&tmp, "rootfs", &.{
        .{ "usr/bin/sh", "sh" },
        .{ "bin", "->usr/bin" },
        .{ "run/x", "x" },
        .{ "var/run", "->/run" },
        .{ "tmp/old", "old" },
        .{ "opt/app/keep", "keep" },
    });
    const chmod_rc = std.os.linux.chmod(try std.fmt.allocPrintSentinel(arena, "{s}/rootfs/tmp", .{h.root}, 0), 0o1777);
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(chmod_rc));
    try plant(&tmp, "ctx", &.{
        .{ "f", "file" },
        .{ "w/a.txt", "a" },
        .{ "w/b.txt", "b" },
        .{ "w/c.py", "c" },
        .{ "d/x", "x" },
        .{ "d/sub/y", "y" },
        .{ "lnk", "->f" },
        .{ "dlnk", "->d" },
    });
    var rec: Recorder = .{ .arena = arena };
    const built = (try h.run(
        \\FROM alpine
        \\COPY f /bin/
        \\COPY f /var/run/
        \\COPY f /tmp/
        \\COPY f /usr
        \\COPY f /new/dir/f2
        \\COPY w/*.txt /txts/
        \\COPY w/[ab]* /ab/
        \\COPY w/nothing* /none/
        \\COPY d /opt/app
        \\COPY lnk /alias/
        \\COPY dlnk /dlnk/
        \\COPY d/sub .
    , &rec)).ok;
    const l = built.lowers;
    // The link /bin is followed: the file is in /usr/bin, and /bin stays a link.
    try expectFile(arena, l, "usr/bin/f", "file");
    try expectFile(arena, l, "bin/f", "file");
    // /var/run -> /run, followed the same.
    try expectFile(arena, l, "run/f", "file");
    // A directory that is there keeps its mode (here the sticky bit of /tmp).
    try expectFile(arena, l, "tmp/f", "file");
    try expectMode(arena, l, "tmp", 0o1777);
    try expectFile(arena, l, "usr/f", "file");
    try expectFile(arena, l, "new/dir/f2", "file");
    try expectMode(arena, l, "new/dir", 0o755);
    try expectFile(arena, l, "txts/a.txt", "a");
    try expectFile(arena, l, "txts/b.txt", "b");
    try expectMissing(arena, l, "txts/c.py");
    try expectFile(arena, l, "ab/a.txt", "a");
    try expectMissing(arena, l, "none");
    // A directory's contents merge into one that is there.
    try expectFile(arena, l, "opt/app/keep", "keep");
    try expectFile(arena, l, "opt/app/x", "x");
    try expectFile(arena, l, "opt/app/sub/y", "y");
    // A link named as a source is followed, a directory link too; the destination's name rules.
    try expectFile(arena, l, "alias/lnk", "file");
    try expectFile(arena, l, "dlnk/x", "x");
    try expectFile(arena, l, "y", "y");
}

test "build: COPY --from a stage, an image, with the stage built only when a layer needs it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    var h = try Harness.init(arena, &tmp, &held);
    try plant(&tmp, "ctx", &.{.{ "src/main", "main" }});
    try plant(&tmp, "rootfs", &.{.{ "etc/os", "alpine" }});
    const text =
        \\FROM alpine AS build
        \\COPY src /src
        \\RUN out/app
        \\FROM alpine AS unused
        \\RUN never
        \\FROM alpine
        \\COPY --from=build /out/app /usr/bin/app
        \\COPY --from=BUILD /src /srv/
        \\COPY --from=0 /etc/os /etc/os-build
        \\COPY --from=build /out/* /bin-all/
    ;
    var rec: Recorder = .{ .arena = arena };
    const built = (try h.run(text, &rec)).ok;
    // The runtime's layers only: its base and four COPYs. The unused stage never ran.
    try std.testing.expectEqual(@as(usize, 5), built.lowers.len);
    try std.testing.expectEqual(@as(usize, 1), rec.runs.items.len);
    try expectFile(arena, built.lowers, "usr/bin/app", "built");
    try expectFile(arena, built.lowers, "srv/main", "main");
    try expectFile(arena, built.lowers, "etc/os-build", "alpine");
    try expectFile(arena, built.lowers, "bin-all/app", "built");

    // Built again: the final stage's COPYs are in the store, so the build stage is not built.
    var again: Recorder = .{ .arena = arena };
    const second = (try h.run(text, &again)).ok;
    try std.testing.expectEqual(@as(usize, 0), again.runs.items.len);
    for (built.lowers, second.lowers) |x, y| try std.testing.expectEqualStrings(x, y);

    // A COPY --from that finds nothing says what it could not find, on its line.
    var miss: Recorder = .{ .arena = arena };
    const failed = (try h.run("FROM alpine AS b\nRUN x\nFROM alpine\nCOPY --from=b /nope /x", &miss)).failed;
    try std.testing.expect(failed.what == .copy);
    try std.testing.expectEqual(@as(u32, 4), failed.line);
    try std.testing.expect(std.mem.indexOf(u8, failed.why, "/nope") != null);
}

test "build: a stage that continues another, and an identical prefix is one set of layers" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    var h = try Harness.init(arena, &tmp, &held);
    try plant(&tmp, "ctx", &.{.{ "f", "f" }});
    var rec: Recorder = .{ .arena = arena };
    const staged = (try h.run("FROM alpine AS one\nRUN one\nFROM one AS two\nRUN two\nFROM two\nCOPY f /f", &rec)).ok;
    try std.testing.expectEqual(@as(usize, 4), staged.lowers.len);
    try expectFile(arena, staged.lowers, "one", "built");
    try expectFile(arena, staged.lowers, "two", "built");
    // The same steps in one stage are the same layers: the store has them, nothing runs.
    var flat_rec: Recorder = .{ .arena = arena };
    const flat = (try h.run("FROM alpine\nRUN one\nRUN two\nCOPY f /f", &flat_rec)).ok;
    try std.testing.expectEqual(@as(usize, 0), flat_rec.runs.items.len);
    try std.testing.expectEqual(@as(usize, 4), flat.lowers.len);
}

test "build: heredoc files, with their mode, and --chmod over it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    var h = try Harness.init(arena, &tmp, &held);
    try plant(&tmp, "ctx", &.{.{ "x", "x" }});
    var rec: Recorder = .{ .arena = arena };
    const built = (try h.run(
        \\FROM alpine
        \\ENV WHO=world
        \\COPY <<EOF /etc/greeting
        \\hello $WHO
        \\EOF
        \\COPY --chmod=755 <<'EOF' /usr/bin/run.sh
        \\echo $WHO
        \\EOF
        \\COPY <<A <<B /docs/
        \\a
        \\A
        \\b
        \\B
    , &rec)).ok;
    try expectFile(arena, built.lowers, "etc/greeting", "hello world\n");
    try expectMode(arena, built.lowers, "etc/greeting", 0o644);
    try expectFile(arena, built.lowers, "usr/bin/run.sh", "echo $WHO\n");
    try expectMode(arena, built.lowers, "usr/bin/run.sh", 0o755);
    try expectFile(arena, built.lowers, "docs/A", "a\n");
    try expectFile(arena, built.lowers, "docs/B", "b\n");
}

test "build: COPY --chmod makes the directories on the way 0755 and keeps the mode on files and copied directories, as non-root" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(std.testing.io);
    var h = try Harness.init(arena, &tmp, &held);
    try plant(&tmp, "ctx", &.{ .{ "f", "f" }, .{ "d/x", "x" }, .{ "d/sub/y", "y" } });
    var rec: Recorder = .{ .arena = arena };
    const built = (try h.run(
        \\FROM alpine
        \\COPY --chmod=640 f /cm1/deep/f
        \\COPY --chmod=640 d /cm2/d
    , &rec)).ok;
    try expectMode(arena, built.lowers, "cm1", 0o755);
    try expectMode(arena, built.lowers, "cm1/deep", 0o755);
    try expectMode(arena, built.lowers, "cm1/deep/f", 0o640);
    // A copied directory is filled before it takes the mode, and the store can publish it as this user
    // (its files are beyond a path walk, a 0640 directory not being enterable).
    try expectMode(arena, built.lowers, "cm2", 0o755);
    try expectMode(arena, built.lowers, "cm2/d", 0o640);
    // So the temporary directory can be removed.
    for (built.lowers) |low| for ([_][]const u8{ "cm2/d", "cm2/d/sub" }) |rel| {
        const at = try std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ low, rel }, 0);
        _ = linux.chmod(at, 0o755);
    };
}

test "build: a heredoc or a download written where an earlier source of the same COPY put a link does not reach through it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    var h = try Harness.init(arena, &tmp, &held);
    try tmp.dir.writeFile(io, .{ .sub_path = "victim", .data = "untouched", .flags = .{ .permissions = .fromMode(0o644) } });
    const victim = try std.fmt.allocPrint(arena, "{s}/victim", .{h.root});
    try plant(&tmp, "ctx", &.{.{ "d/link", try std.fmt.allocPrint(arena, "->{s}", .{victim}) }});
    var rec: Recorder = .{ .arena = arena };
    const built = (try h.run(
        \\FROM alpine
        \\COPY --chmod=755 d/ <<link /x/
        \\planted
        \\link
    , &rec)).ok;
    try expectFile(arena, built.lowers, "x/link", "planted\n");
    try expectMode(arena, built.lowers, "x/link", 0o755);
    const after = try tmp.dir.readFileAlloc(io, "victim", arena, .limited(64));
    try std.testing.expectEqualStrings("untouched", after);
    const st = try tmp.dir.statFile(io, "victim", .{});
    try std.testing.expectEqual(@as(u32, 0o644), @as(u32, @intCast(st.permissions.toMode() & 0o7777)));
}

test "Ignore: .dockerignore as Docker reads it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const T = struct { path: []const u8, out: bool };
    const run = struct {
        fn check(ar: Allocator, text: []const u8, cases: []const T) !void {
            const ig = try Ignore.parse(ar, text, &.{});
            for (cases) |c| {
                errdefer std.debug.print("{s}: want out={}\n", .{ c.path, c.out });
                try std.testing.expectEqual(c.out, ig.excludes(c.path));
            }
        }
    }.check;
    // A name, a directory (and what is below it), a glob, and a comment.
    try run(arena, "# comment\nnode_modules\n*.log\n/build/\ntmp/**\n\n", &.{
        .{ .path = "node_modules", .out = true },
        .{ .path = "node_modules/a/b.js", .out = true },
        .{ .path = "src/node_modules", .out = false },
        .{ .path = "x.log", .out = true },
        .{ .path = "src/x.log", .out = false },
        .{ .path = "build", .out = true },
        .{ .path = "build/out", .out = true },
        .{ .path = "tmp", .out = false },
        .{ .path = "tmp/a/b", .out = true },
        .{ .path = "src/main.zig", .out = false },
    });
    // The whitelist: everything out, some back; the last pattern that applies wins.
    try run(arena, "*\n!entrypoint.sh\n!src\nsrc/*.bak\n", &.{
        .{ .path = "README.md", .out = true },
        .{ .path = "entrypoint.sh", .out = false },
        .{ .path = "src", .out = false },
        .{ .path = "src/main.c", .out = false },
        .{ .path = "src/main.bak", .out = true },
        .{ .path = "lib/x", .out = true },
    });
    // `**` for any number of directories, none included.
    try run(arena, "**/secret\na/**/z\n", &.{
        .{ .path = "secret", .out = true },
        .{ .path = "x/y/secret", .out = true },
        .{ .path = "x/secrets", .out = false },
        .{ .path = "a/z", .out = true },
        .{ .path = "a/b/c/z", .out = true },
        .{ .path = "a/b", .out = false },
    });
    // What the file says is added to what is always left out.
    const ig = try Ignore.parse(arena, "!.git\nfoo\n", &.{".git"});
    try std.testing.expect(!ig.excludes(".git"));
    const only_always = try Ignore.parse(arena, "foo\n", &.{".git"});
    try std.testing.expect(only_always.excludes(".git/objects/ab"));
    // An exception below a directory left out lets the directory be walked.
    const nested = try Ignore.parse(arena, "vendor\n!vendor/keep\n", &.{});
    try std.testing.expect(nested.nested_exceptions);
    try std.testing.expect(!nested.excludes("vendor/keep"));
    try std.testing.expect(nested.excludes("vendor/drop"));
}

test "build: a context's .dockerignore leaves files out of COPY, patterns, and the key" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var held: std.ArrayList(std.Io.File) = .empty;
    defer for (held.items) |f| f.close(io);
    var h = try Harness.init(arena, &tmp, &held);
    try plant(&tmp, "ctx", &.{
        .{ "keep.txt", "keep" },
        .{ "skip.log", "log" },
        .{ "node_modules/m/x.js", "js" },
        .{ "src/a.c", "a" },
        .{ "src/a.bak", "bak" },
        .{ ".git/HEAD", "ref" },
    });
    const ig = try Ignore.parse(arena, "*.log\nnode_modules\nsrc/*.bak\n", &.{".git"});
    var rec: Recorder = .{ .arena = arena };
    const view = try testView(arena, &tmp, "ctx");
    view.filter = ig.filter();
    var fb = h.base();
    var c: Harness.Ctx = .{ .view = view };
    const p = (try plan(arena, (try parse(arena, "FROM a\nCOPY . /app/\nCOPY *.log /logs/")).ok, fb.bases(), &.{}, &c.iface)).ok;
    const built = (try build(arena, io, p, h.store, rec.runner(), .{ .context = view, .opaque_xattr = "user.overlay.opaque" })).ok;
    try expectFile(arena, built.lowers, "app/keep.txt", "keep");
    try expectFile(arena, built.lowers, "app/src/a.c", "a");
    try expectMissing(arena, built.lowers, "app/skip.log");
    try expectMissing(arena, built.lowers, "app/node_modules");
    try expectMissing(arena, built.lowers, "app/src/a.bak");
    try expectMissing(arena, built.lowers, "app/.git");
    try expectMissing(arena, built.lowers, "logs");
    // A file that is left out changes nothing, a file that is not changes the key.
    const before = p.stages[0].steps[0].key;
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/skip.log", .data = "changed" });
    const same = (try plan(arena, (try parse(arena, "FROM a\nCOPY . /app/\nCOPY *.log /logs/")).ok, fb.bases(), &.{}, &c.iface)).ok;
    try std.testing.expectEqualSlices(u8, &before, &same.stages[0].steps[0].key);
    try tmp.dir.writeFile(io, .{ .sub_path = "ctx/keep.txt", .data = "changed" });
    const other = (try plan(arena, (try parse(arena, "FROM a\nCOPY . /app/\nCOPY *.log /logs/")).ok, fb.bases(), &.{}, &c.iface)).ok;
    try std.testing.expect(!std.mem.eql(u8, &before, &other.stages[0].steps[0].key));
}

test "allocation failures: a Dockerfile parsed, substituted and planned" {
    const af = @import("../alloc_failures.zig");
    const S = struct {
        fn parseOnly(a: Allocator, text: []const u8) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            _ = try parse(arena.allocator(), text);
        }
        fn substituteOnly(a: Allocator, text: []const u8) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            const vars = [_]Var{ .{ .name = "A", .value = "x" }, .{ .name = "E", .value = "" } };
            _ = try substitute(arena.allocator(), text, &vars);
        }
        /// Plans what parses; a Dockerfile that refuses does so with or without memory.
        fn planned(a: Allocator, text: []const u8) !void {
            var arena: af.Scratch = .init(a);
            defer arena.deinit();
            const ar = arena.allocator();
            const ins = switch (try parse(ar, text)) {
                .ok => |ok| ok,
                .refused => return,
            };
            var fb: FixedBases = .{ .arena = ar, .config = .{ .rootfs = "", .env = &.{"PATH=/usr/bin:/bin"}, .cmd = &.{"/bin/sh"} } };
            var ctx: Fixed = .{};
            _ = try plan(ar, ins, fb.bases(), &.{}, ctx.context());
        }
    };
    const docker =
        \\# syntax=docker/dockerfile:1
        \\ARG BASE=alpine:3.22
        \\FROM ${BASE}
        \\ARG VERSION=1
        \\ENV TOOL_HOME=/opt/tool PATH="/opt/tool/bin:$PATH"
        \\WORKDIR /opt
        \\run apk add --no-cache \
        \\    curl \
        \\    jq
        \\COPY --chmod=755 entrypoint.sh bin/
        \\LABEL maintainer="me"
        \\USER 0
        \\ENTRYPOINT ["/opt/tool/bin/entrypoint.sh"]
    ;
    for ([_][]const u8{ docker, "FROM a\nCOPY --chmod=644 [\"a b\", \"/d/\"]", "FROM a\nSHELL [\"bash\"]", "RUN true", "FROM a\nRUN <<EOF\ntrue\nEOF" }) |text| {
        try af.checkOne(S.parseOnly, .{text});
        try af.checkOne(S.planned, .{text});
    }
    for ([_][]const u8{ "$A ${A}- ${E:-z} ${A:+w} ${E:+no}- \\$A $", "${A:-${E:-deep}}", "${unclosed" }) |text|
        try af.checkOne(S.substituteOnly, .{text});
}

test "plan: a reference pinned by digest (name:tag@sha256) is asked for whole, in FROM, an ARG and COPY --from" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const text =
        \\ARG IMAGE=alpine
        \\ARG BASE=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
        \\FROM ${IMAGE}:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS one
        \\FROM ${BASE} AS two
        \\FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
        \\COPY --from=one /a /a
        \\COPY --from=two /b /b
        \\COPY --from=busybox:1.38@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f /bin/busybox /bin/busybox
    ;
    var f: FixedBases = .{ .arena = arena };
    var ctx: Fixed = .{};
    _ = try planOf(arena, text, &f, &ctx);
    const want = "alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f";
    try std.testing.expectEqual(@as(usize, 4), f.asked.items.len);
    try std.testing.expectEqualStrings(want, f.asked.items[0]);
    try std.testing.expectEqualStrings(want, f.asked.items[1]);
    try std.testing.expectEqualStrings(want, f.asked.items[2]);
    try std.testing.expectEqualStrings("busybox:1.38@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f", f.asked.items[3]);
}
