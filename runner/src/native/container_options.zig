//! A job container's `options:` on the native backend (docs/native-backend.md, "Job container
//! options"): the `docker create` flags a native job can honour, and a refusal for every other.
//!
//! GitHub's runner appends the string to `docker create` for the job container, after the flags
//! it builds itself, and runs every step with `docker exec -w <directory>`. So a flag is honoured
//! when the native sandbox already has what it asks for (the step user, the container's env), is
//! meaningless when `docker exec` or the runner overrides it (`--workdir`, `--health-*`: the
//! runner waits for the health of service containers only), and is refused otherwise. Refused,
//! never ignored: `--cpus`, `--privileged`, `--device`, `--add-host` and the rest change the
//! container, and the sandbox does not carry them out, so a job that silently lost one would run
//! differently from its workflow. The job goes to Dagger with the flag named instead.
//!
//! Only literal text is read here. An `options:` with an expression in it is decided when the job
//! is, before any expression can be evaluated, so it falls back too.

const std = @import("std");
const job_mod = @import("../job.zig");
const health = @import("health.zig");

const Allocator = std.mem.Allocator;

/// What a job container's `options:` ask for that the native job carries out.
pub const Options = struct {
    /// `--env`/`-e` as `docker create` sets them, in order, over the container's `env:`.
    env: []const job_mod.EnvVar = &.{},
    /// `--user`/`-u`, as an image's `USER` is written: `name`, `uid`, `name:group`, `uid:gid`.
    user: ?[]const u8 = null,
    /// How many flags were understood and have no effect natively (`--workdir`, `--health-*`),
    /// for "Set up job" to say so.
    no_effect: u32 = 0,
};

pub const Error = error{ Refused, OutOfMemory };

/// The flags that take a value: `--name value`, `--name=value`, and for the short ones `-n value`,
/// `-nvalue` and `-n=value`.
const Flag = struct { long: []const u8, short: u8 = 0 };
const valued = [_]Flag{
    .{ .long = "--env", .short = 'e' },
    .{ .long = "--user", .short = 'u' },
    .{ .long = "--workdir", .short = 'w' },
    .{ .long = "--health-cmd" },
    .{ .long = "--health-interval" },
    .{ .long = "--health-timeout" },
    .{ .long = "--health-start-period" },
    .{ .long = "--health-start-interval" },
    .{ .long = "--health-retries" },
};

/// `text` read as `docker create` options. On `error.Refused`, `why` says which flag, and why.
pub fn parse(arena: Allocator, text: []const u8, why: *[]const u8) Error!Options {
    const words = try health.splitOptions(arena, text);
    var env: std.ArrayList(job_mod.EnvVar) = .empty;
    var out: Options = .{};
    var i: usize = 0;
    while (i < words.len) : (i += 1) {
        const w = words[i];
        if (std.mem.eql(u8, w, "--no-healthcheck")) {
            out.no_effect += 1;
            continue;
        }
        const found = flagOf(w) orelse return refuse(arena, why, w, "is not carried out natively");
        var value: []const u8 = undefined;
        if (found.attached) |v| {
            value = v;
        } else if (i + 1 < words.len) {
            i += 1;
            value = words[i];
        } else return refuse(arena, why, w, "has no value");
        const name = found.def.long;
        if (value.len == 0) return refuse(arena, why, w, "has an empty value");
        if (std.mem.eql(u8, name, "--env")) {
            // A bare `-e NAME` copies the runner's own variable, which a job must never get.
            const eq = std.mem.indexOfScalar(u8, value, '=') orelse
                return refuse(arena, why, w, "copies a variable from the runner's environment");
            if (eq == 0) return refuse(arena, why, w, "has no variable name");
            try env.append(arena, .{ .name = value[0..eq], .value = value[eq + 1 ..] });
        } else if (std.mem.eql(u8, name, "--user")) {
            if (!userIsPlain(value)) return refuse(arena, why, w, "is not a user, a uid, or " ++
                "user:group");
            out.user = value;
        } else if (std.mem.eql(u8, name, "--workdir") or std.mem.eql(u8, name, "--health-cmd")) {
            out.no_effect += 1;
        } else {
            // A `--health-*` flag: read as Docker reads it, so what Docker refuses is refused.
            const ok = if (std.mem.eql(u8, name, "--health-retries"))
                std.fmt.parseInt(u32, value, 10) catch null != null
            else
                health.parseDurationMs(value) != null;
            if (!ok) return refuse(arena, why, w, "is not a value Docker reads");
            out.no_effect += 1;
        }
    }
    out.env = env.items;
    return out;
}

const Found = struct { def: Flag, attached: ?[]const u8 };

fn flagOf(w: []const u8) ?Found {
    for (valued) |f| {
        if (std.mem.eql(u8, w, f.long)) return .{ .def = f, .attached = null };
        if (std.mem.startsWith(u8, w, f.long) and w.len > f.long.len and w[f.long.len] == '=')
            return .{ .def = f, .attached = w[f.long.len + 1 ..] };
        if (f.short != 0 and w.len >= 2 and w[0] == '-' and w[1] == f.short) {
            if (w.len == 2) return .{ .def = f, .attached = null };
            const rest = w[2..];
            return .{ .def = f, .attached = if (rest[0] == '=') rest[1..] else rest };
        }
    }
    return null;
}

/// Whether `user` is written as `images.userIds` reads it: no whitespace or control characters,
/// at most one colon, and both sides of it non-empty.
fn userIsPlain(user: []const u8) bool {
    var colons: usize = 0;
    for (user) |c| {
        if (c == ':') colons += 1;
        if (c <= ' ' or c == 0x7f) return false;
    }
    if (colons > 1) return false;
    if (colons == 1) return user[0] != ':' and user[user.len - 1] != ':';
    return true;
}

fn refuse(arena: Allocator, why: *[]const u8, word: []const u8, reason: []const u8) Error {
    const fmt = "the job container's option `{s}` {s}";
    why.* = std.fmt.allocPrint(arena, fmt, .{ word, reason }) catch
        "a job container option is not carried out natively";
    return error.Refused;
}

/// Where `unsupported` reads: its answer points in here, so it holds until the next call on the
/// same thread, which is long enough for the caller to print it.
threadlocal var scratch: [8192]u8 = undefined;

/// Why a job container cannot be native, or null: its `ports:` and `volumes:` (not native yet,
/// docs/native-backend.md, "Job container options") and any of its `options:` that `parse` does
/// not carry out. `provisioned` is whether its image is the one the runner provisions, whose step
/// user is `RUNNER_STEP_USER`'s choice, not the container's.
pub fn unsupported(jc: job_mod.Service, provisioned: bool) ?[]const u8 {
    if (jc.ports.len > 0) return "a job container's `ports:` are not native yet (publishing a " ++
        "port to the host needs the job's network, phase 6's isolation)";
    if (jc.volumes.len > 0) return "a job container's `volumes:` are not native yet (a bind " ++
        "from the host needs a mount policy and id mapping of its own)";
    const t = jc.options orelse return null;
    const text = switch (t) {
        .lit => |l| l,
        .expr => return "a job container's `options:` given by an expression are not native yet",
    };
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var why: []const u8 = "";
    const o = parse(fba.allocator(), text, &why) catch |e| return switch (e) {
        error.Refused => why,
        error.OutOfMemory => "a job container's `options:` are too long to read natively",
    };
    if (o.user != null and provisioned) return "a job container's `--user` on the default " ++
        "image, whose steps run as RUNNER_STEP_USER's user, is not native";
    return null;
}

fn expectRefused(arena: Allocator, text: []const u8, flag: []const u8) !void {
    var why: []const u8 = "";
    try std.testing.expectError(error.Refused, parse(arena, text, &why));
    if (std.mem.indexOf(u8, why, flag) == null) {
        std.debug.print("{s} is not named in: {s}\n", .{ flag, why });
        return error.TestUnexpectedResult;
    }
}

test "options honoured: --env and --user in every form docker reads, the others noted" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";

    const empty = try parse(arena, "", &why);
    try std.testing.expectEqual(@as(usize, 0), empty.env.len);
    try std.testing.expect(empty.user == null);

    const o = try parse(arena, "--env A=1 -e B=2 --env=C=3 -eD=4 -e E=\"two words\" " ++
        "--user 1001:50", &why);
    try std.testing.expectEqual(@as(usize, 5), o.env.len);
    try std.testing.expectEqualStrings("A", o.env[0].name);
    try std.testing.expectEqualStrings("2", o.env[1].value);
    try std.testing.expectEqualStrings("C", o.env[2].name);
    try std.testing.expectEqualStrings("4", o.env[3].value);
    try std.testing.expectEqualStrings("two words", o.env[4].value);
    try std.testing.expectEqualStrings("1001:50", o.user.?);

    // The last `--user` wins, as docker's does; a value may hold `=`; `-u=x` is pflag's `-u x`.
    const u = try parse(arena, "-u root --user=app -u=nobody -e URL=http://h/?a=b", &why);
    try std.testing.expectEqualStrings("nobody", u.user.?);
    try std.testing.expectEqualStrings("URL", u.env[0].name);
    try std.testing.expectEqualStrings("http://h/?a=b", u.env[0].value);

    // GitHub's `HOME=/github/home` comes after the options, so `-e HOME` never takes effect.
    const h = try parse(arena, "-e HOME=/x --env=HOME=/y -e B=1", &why);
    try std.testing.expectEqual(@as(usize, 1), h.env.len);
    try std.testing.expectEqualStrings("B", h.env[0].name);
    try std.testing.expectEqual(@as(u32, 2), h.no_effect);

    // Understood, and with no effect natively: counted so "Set up job" can say so.
    const n = try parse(arena, "--workdir /w -w/x --health-cmd \"pg_isready\" " ++
        "--health-interval 5s --health-timeout=1m30s --health-retries 3 " ++
        "--health-start-period 0 --health-start-interval 1s --no-healthcheck", &why);
    try std.testing.expectEqual(@as(u32, 9), n.no_effect);
    try std.testing.expectEqual(@as(usize, 0), n.env.len);
}

test "options refused, never ignored: what the sandbox does not carry out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    for ([_][]const u8{
        "--cpus",         "--memory",   "--privileged", "--cap-add",   "--device",
        "--security-opt", "--shm-size", "--ulimit",     "--network",   "--add-host",
        "--hostname",     "--init",     "--tty",        "-t",          "-i",
        "--volume",       "-v",         "--publish",    "-p",          "--entrypoint",
        "--name",         "--env-file", "--label",      "--group-add", "--pid",
        "--ipc",          "--gpus",     "--platform",   "--read-only", "--tmpfs",
        "--sysctl",       "--dns",      "--mount",      "--pull",      "--userns",
    }) |flag| {
        // With a value and without, and among honoured flags: the flag is what is named.
        try expectRefused(arena, try std.fmt.allocPrint(arena, "{s} 1", .{flag}), flag);
        try expectRefused(arena, try std.fmt.allocPrint(arena, "--env A=1 {s}", .{flag}), flag);
        try expectRefused(arena, try std.fmt.allocPrint(arena, "{s}=1", .{flag}), flag);
    }
    // One refused flag among honoured ones refuses the lot.
    try expectRefused(arena, "--user 1001 --cpus 1 --env A=1", "--cpus");
    // Not an option at all.
    try expectRefused(arena, "--user 1001 stray", "stray");
    // A bare `-e NAME` would copy the runner's variable.
    try expectRefused(arena, "-e SECRET", "-e");
    try expectRefused(arena, "--env =x", "--env");
    // Missing or empty values, and values Docker itself would refuse.
    try expectRefused(arena, "--user", "--user");
    try expectRefused(arena, "--user \"\"", "--user");
    try expectRefused(arena, "--user a:b:c", "--user");
    try expectRefused(arena, "--user :1", "--user");
    try expectRefused(arena, "--env", "--env");
    try expectRefused(arena, "--health-interval soon", "--health-interval");
    try expectRefused(arena, "--health-interval 5", "--health-interval");
    try expectRefused(arena, "--health-retries many", "--health-retries");
}

test "unsupported: ports and volumes fall back, options by what they hold" {
    const base: job_mod.Service = .{ .name = "", .image = .{ .lit = "node:22" } };
    try std.testing.expect(unsupported(base, false) == null);

    var jc = base;
    jc.options = .{ .lit = "--user 1001 -e A=1 --workdir /x --health-cmd true" };
    try std.testing.expect(unsupported(jc, false) == null);
    // The default image's user is the runner's choice, not the container's.
    try std.testing.expect(unsupported(jc, true) != null);
    jc.options = .{ .lit = "-e A=1" };
    try std.testing.expect(unsupported(jc, true) == null);

    jc.options = .{ .lit = "--privileged" };
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false).?, "--privileged") != null);
    // Dagger reads none of `options:`: the note says the flag is dropped there, not carried out.
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false).?, "drops") != null);
    jc.options = .{ .expr = "matrix.options" };
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false).?, "expression") != null);
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false).?, "drops") != null);

    jc = base;
    jc.ports = &.{.{ .lit = "8080:80" }};
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false).?, "`ports:`") != null);
    jc = base;
    jc.volumes = &.{.{ .lit = "/data:/data" }};
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false).?, "`volumes:`") != null);
}
