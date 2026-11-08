//! A job container's `options:` on the native backend (docs/native-backend.md, "Job container
//! options"): the `docker create` flags a native job can honour, and a refusal for every other.
//!
//! GitHub's runner appends the string to `docker create` for the job container, after the flags
//! it builds itself but before the `-e` of the container's `env:` (so that wins over an `-e` here,
//! and its `HOME=/github/home` over `-e HOME`), and runs every step with `docker exec -w
//! <directory>`. So a flag is honoured
//! when the native sandbox already has what it asks for (the step user, the container's env), is
//! meaningless when `docker exec` or the runner overrides it (`--workdir`, `--health-*`: the
//! runner waits for the health of service containers only), and is refused otherwise. Honoured
//! too, because the job's own sandbox can carry them out without more power than it has:
//! `--hostname`, `--add-host` (the job's own hosts file), `--shm-size`, `--tmpfs` (a tmpfs is
//! nosuid and nodev, as Docker's) and `--memory` (within the job's cgroup limit, never above it).
//! Refused, never ignored: `--cpus`, `--privileged`, `--cap-add`, `--security-opt`, `--device`,
//! `--network`, `--pid`, `--ipc`, `--userns` and the rest change the container beyond what the
//! sandbox grants, so a job that silently lost one would run differently from its workflow. The
//! job goes to Dagger with the flag named instead, and Dagger reads none of `options:`: there the
//! flag is dropped, which the note says (`dropped`).
//!
//! Only literal text is read here. An `options:` with an expression in it is decided when the job
//! is, before any expression can be evaluated, so it falls back too.

const std = @import("std");
const job_mod = @import("../job.zig");
const health = @import("health.zig");

const Allocator = std.mem.Allocator;

/// What a job container's `options:` ask for that the native job carries out.
pub const Options = struct {
    /// `--env`/`-e` as `docker create` sets them, in order, under the container's `env:` (the
    /// runner puts the options first, so the `env:` wins). Not `HOME`: see `parse`.
    env: []const job_mod.EnvVar = &.{},
    /// `--user`/`-u`, as an image's `USER` is written: `name`, `uid`, `name:group`, `uid:gid`.
    user: ?[]const u8 = null,
    /// `--hostname`/`-h`: the steps' UTS hostname.
    hostname: ?[]const u8 = null,
    /// `--add-host name:ip`, in order: lines added to the job's hosts file.
    add_hosts: []const AddHost = &.{},
    /// `--shm-size`, in bytes: the size of `/dev/shm`.
    shm_size: ?u64 = null,
    /// `--tmpfs`, in order.
    tmpfs: []const Tmpfs = &.{},
    /// `--memory`/`-m`, in bytes: a limit for the job's cgroup, when it is lower than the
    /// runner's own (`Backend.limitMemory`).
    memory: ?u64 = null,
    /// How many flags were understood and have no effect natively (`--workdir`, `--health-*`,
    /// `--init`), for "Set up job" to say so.
    no_effect: u32 = 0,
};

pub const AddHost = struct { name: []const u8, ip: []const u8 };

/// One `--tmpfs path[:options]`, the options Docker takes that stay within the sandbox.
pub const Tmpfs = struct {
    /// Clean and absolute (`cleanTarget`).
    target: []const u8,
    /// Bytes; 0 for the kernel's default.
    size: u64 = 0,
    mode: u32 = 0o1777,
    /// `exec`: Docker's default is `noexec`.
    exec: bool = false,
    read_only: bool = false,
};

pub const Error = error{ Refused, OutOfMemory };

/// The flags that take a value: `--name value`, `--name=value`, and for the short ones `-n value`,
/// `-nvalue` and `-n=value`.
const Flag = struct { long: []const u8, short: u8 = 0 };
const valued = [_]Flag{
    .{ .long = "--env", .short = 'e' },
    .{ .long = "--user", .short = 'u' },
    .{ .long = "--workdir", .short = 'w' },
    .{ .long = "--hostname", .short = 'h' },
    .{ .long = "--add-host" },
    .{ .long = "--shm-size" },
    .{ .long = "--tmpfs" },
    .{ .long = "--memory", .short = 'm' },
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
    var add_hosts: std.ArrayList(AddHost) = .empty;
    var tmpfs_list: std.ArrayList(Tmpfs) = .empty;
    var out: Options = .{};
    var i: usize = 0;
    while (i < words.len) : (i += 1) {
        const w = words[i];
        if (std.mem.eql(u8, w, "--no-healthcheck") or std.mem.eql(u8, w, "--init")) {
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
            // GitHub sets `HOME=/github/home` after the options, so the flag never wins there.
            if (std.mem.eql(u8, value[0..eq], "HOME")) {
                out.no_effect += 1;
                continue;
            }
            try env.append(arena, .{ .name = value[0..eq], .value = value[eq + 1 ..] });
        } else if (std.mem.eql(u8, name, "--user")) {
            if (!userIsPlain(value)) return refuse(arena, why, w, "is not a user, a uid, or " ++
                "user:group");
            out.user = value;
        } else if (std.mem.eql(u8, name, "--hostname")) {
            if (!hostnameIsPlain(value)) return refuse(arena, why, w, "is not a hostname " ++
                "(letters, digits, `-` and `.`, at most 64 characters)");
            out.hostname = value;
        } else if (std.mem.eql(u8, name, "--add-host")) {
            try add_hosts.append(arena, try parseAddHost(arena, w, value, why));
        } else if (std.mem.eql(u8, name, "--shm-size")) {
            const n = parseSize(value) orelse return refuse(arena, why, w, "is not a size " ++
                "Docker reads (a number of bytes, or with b, k, m, g or t)");
            if (n == 0) return refuse(arena, why, w, "is zero");
            out.shm_size = n;
        } else if (std.mem.eql(u8, name, "--memory")) {
            const n = parseSize(value) orelse return refuse(arena, why, w, "is not a size " ++
                "Docker reads (a number of bytes, or with b, k, m, g or t)");
            if (n < min_memory) return refuse(arena, why, w, "is below the 6 MiB Docker takes");
            out.memory = n;
        } else if (std.mem.eql(u8, name, "--tmpfs")) {
            try tmpfs_list.append(arena, try parseTmpfs(arena, w, value, why));
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
    out.add_hosts = add_hosts.items;
    out.tmpfs = tmpfs_list.items;
    for (out.tmpfs, 0..) |t, n| for (out.tmpfs[0..n]) |earlier| if (std.mem.eql(u8, earlier.target, t.target))
        return refuse(arena, why, "--tmpfs", "mounts a path an earlier `--tmpfs` mounts");
    return out;
}

/// Docker takes no `--memory` below this (`MinMemoryLimit`).
const min_memory: u64 = 6 << 20;

/// A size as `units.RAMInBytes` reads one, whole numbers only: bytes, or a number with `b`, `k`,
/// `m`, `g` or `t` (and `kb`... `tb`), in any case, as powers of 1024.
fn parseSize(text: []const u8) ?u64 {
    var end: usize = 0;
    while (end < text.len and std.ascii.isDigit(text[end])) end += 1;
    if (end == 0 or end > 15) return null;
    const n = std.fmt.parseInt(u64, text[0..end], 10) catch return null;
    const unit = text[end..];
    const shift: u6 = if (unit.len == 0 or std.ascii.eqlIgnoreCase(unit, "b"))
        0
    else if (std.ascii.eqlIgnoreCase(unit, "k") or std.ascii.eqlIgnoreCase(unit, "kb"))
        10
    else if (std.ascii.eqlIgnoreCase(unit, "m") or std.ascii.eqlIgnoreCase(unit, "mb"))
        20
    else if (std.ascii.eqlIgnoreCase(unit, "g") or std.ascii.eqlIgnoreCase(unit, "gb"))
        30
    else if (std.ascii.eqlIgnoreCase(unit, "t") or std.ascii.eqlIgnoreCase(unit, "tb"))
        40
    else
        return null;
    return std.math.shlExact(u64, n, shift) catch null;
}

/// A hostname Docker takes (RFC 1123, at most 64 characters, as `sethostname` does).
fn hostnameIsPlain(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    if (name[0] == '-' or name[0] == '.' or name[name.len - 1] == '-' or name[name.len - 1] == '.')
        return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '.') return false;
    return true;
}

/// `--add-host name:ip` (or `name=ip`, which newer Docker reads too). The address is IPv4, as the
/// jobs' network is; `host-gateway` stands for the host's address, which a job has no business
/// with, and is refused.
fn parseAddHost(arena: Allocator, flag: []const u8, value: []const u8, why: *[]const u8) Error!AddHost {
    const sep = std.mem.indexOfAny(u8, value, ":=") orelse
        return refuse(arena, why, flag, "is not name:ip");
    const name = value[0..sep];
    const ip = value[sep + 1 ..];
    if (!hostnameIsPlain(name)) return refuse(arena, why, flag, "has a name that is not a hostname");
    if (std.mem.eql(u8, ip, "host-gateway")) return refuse(arena, why, flag, "names " ++
        "`host-gateway`, the host's address, which a job does not get");
    if (parseIp4(ip) == null) return refuse(arena, why, flag, "has an address that is not an " ++
        "IPv4 address");
    return .{ .name = name, .ip = ip };
}

/// `--tmpfs path[:options]`: `rw`, `ro`, `exec`, `noexec`, `nosuid`, `nodev` (a tmpfs is always
/// nosuid and nodev here), `size=` and `mode=`. `suid` and `dev` are refused, as are the options
/// that name ids (`uid=`, `gid=`: they would be ids of the host's namespace) and any other.
fn parseTmpfs(arena: Allocator, flag: []const u8, value: []const u8, why: *[]const u8) Error!Tmpfs {
    const colon = std.mem.indexOfScalar(u8, value, ':');
    const path = if (colon) |c| value[0..c] else value;
    var out: Tmpfs = .{ .target = undefined };
    out.target = cleanTarget(arena, path) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NotPlain => return refuse(arena, why, flag, "has a path that is not an absolute " ++
            "path without `.` or `..`"),
    };
    if (out.target.len <= 1) return refuse(arena, why, flag, "mounts the root directory");
    for (runner_mounts) |m| if (under(out.target, m)) return refuse(arena, why, flag, "mounts " ++
        "where the runner mounts its own directory");
    for (sandbox_trees) |t| if (under(out.target, t)) return refuse(arena, why, flag, "mounts " ++
        "inside a directory the sandbox mounts itself");
    const options = if (colon) |c| value[c + 1 ..] else "";
    var it = std.mem.splitScalar(u8, options, ',');
    while (it.next()) |o| {
        if (o.len == 0 or std.mem.eql(u8, o, "rw") or std.mem.eql(u8, o, "nosuid") or
            std.mem.eql(u8, o, "nodev") or std.mem.eql(u8, o, "noexec"))
        {
            if (std.mem.eql(u8, o, "noexec")) out.exec = false;
            continue;
        }
        if (std.mem.eql(u8, o, "ro")) {
            out.read_only = true;
        } else if (std.mem.eql(u8, o, "exec")) {
            out.exec = true;
        } else if (std.mem.startsWith(u8, o, "size=")) {
            out.size = parseSize(o[5..]) orelse return refuse(arena, why, flag, "has a size " ++
                "that Docker does not read");
            if (out.size == 0) return refuse(arena, why, flag, "has a size of zero");
        } else if (std.mem.startsWith(u8, o, "mode=")) {
            out.mode = std.fmt.parseInt(u32, o[5..], 8) catch 0o10000;
            if (out.mode > 0o7777) return refuse(arena, why, flag, "has a mode that is not octal " ++
                "permissions");
        } else if (std.mem.eql(u8, o, "suid") or std.mem.eql(u8, o, "dev")) {
            return refuse(arena, why, flag, "asks for `suid` or `dev`, which the sandbox never " ++
                "gives a mount");
        } else return refuse(arena, why, flag, "has a mount option the sandbox does not carry " ++
            "out (only rw, ro, exec, noexec, nosuid, nodev, size and mode)");
    }
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

/// Said wherever a flag sends the job to Dagger: Dagger reads none of `options:`, so the flag is
/// dropped there, not carried out (a reader of "Set up job" must not take it for supported).
const dropped = "; Dagger drops a container's `options:`, so it is not applied there either";

fn refuse(arena: Allocator, why: *[]const u8, word: []const u8, reason: []const u8) Error {
    const fmt = "the job container's option `{s}` {s}" ++ dropped;
    why.* = std.fmt.allocPrint(arena, fmt, .{ word, reason }) catch
        "a job container option is not carried out natively";
    return error.Refused;
}

/// Where `unsupported` reads: its answer points in here, so it holds until the next call on the
/// same thread, which is long enough for the caller to print it.
threadlocal var scratch: [8192]u8 = undefined;

/// Said wherever `ports:` or `volumes:` send the job to Dagger, which reads neither: it warns
/// "Job container ports/volumes not supported here and ignored" (`set_up.warnDroppedContainerSettings`,
/// #368), so they are not applied there either.
const dropped_ports = "; Dagger ignores a job container's `ports:`, so they are not published there either";
const dropped_volumes = "; Dagger ignores a job container's `volumes:`, so they are not mounted there either";

/// One `ports:` entry the native job carries out: published from the host into the job's
/// network (`publish.zig`).
pub const Port = struct {
    /// The host address, when the entry names one; null for the operator's default
    /// (`RUNNER_NATIVE_PORT_ADDRESSES`' first, 127.0.0.1 unless set).
    address: ?[4]u8 = null,
    /// The host port; 0 for one the kernel picks, as Docker picks one for `80` or `ip::80`.
    host: u16 = 0,
    container: u16,
    udp: bool = false,
};

fn refusePort(arena: Allocator, why: *[]const u8, raw: []const u8, reason: []const u8) Error {
    why.* = std.fmt.allocPrint(arena, "a job container's port `{s}` {s}" ++ dropped_ports, .{
        raw,
        reason,
    }) catch "a job container's port is not carried out natively" ++ dropped_ports;
    return error.Refused;
}

/// `raw` as `docker create -p` reads it (GitHub's runner passes each `ports:` entry on as one,
/// `DockerCommandManager.DockerCreate`; Docker's grammar is `nat.ParsePortSpec`):
/// `[ip:][hostPort:]containerPort[/proto]`. Carried out: an IPv4 address or none, a host port or
/// none (`80`, `ip::80`: one the kernel picks), `tcp` (the default) and `udp`. Refused, with why
/// (the job goes to Dagger, which ignores it): ranges (`8000-8010:8000-8010`), IPv6 addresses,
/// `sctp`, port 0 and what is not a port.
pub fn parsePort(arena: Allocator, raw: []const u8, why: *[]const u8) Error!Port {
    var t = std.mem.trim(u8, raw, " ");
    var udp = false;
    if (std.mem.indexOfScalar(u8, t, '/')) |slash| {
        const proto = t[slash + 1 ..];
        if (std.ascii.eqlIgnoreCase(proto, "udp")) {
            udp = true;
        } else if (!std.ascii.eqlIgnoreCase(proto, "tcp"))
            return refusePort(arena, why, raw, "is not TCP or UDP");
        t = t[0..slash];
    }
    if (std.mem.indexOfScalar(u8, t, '[') != null) return refusePort(arena, why, raw, "names an " ++
        "IPv6 address, which is not native (the jobs' network is IPv4)");
    var parts: [3][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, t, ':');
    while (it.next()) |p| {
        if (n == parts.len) return refusePort(arena, why, raw, "is not [ip:][hostPort:]containerPort");
        parts[n] = p;
        n += 1;
    }
    for (parts[0..n]) |p| if (std.mem.indexOfScalar(u8, p, '-') != null)
        return refusePort(arena, why, raw, "is a range of ports, which is not native");
    const container = portNumber(parts[n - 1]) orelse
        return refusePort(arena, why, raw, "has a container port that is not 1 to 65535");
    var out: Port = .{ .container = container, .udp = udp };
    if (n >= 2 and parts[n - 2].len > 0) out.host = portNumber(parts[n - 2]) orelse
        return refusePort(arena, why, raw, "has a host port that is not 1 to 65535");
    if (n == 3) out.address = parseIp4(parts[0]) orelse
        return refusePort(arena, why, raw, "has a host address that is not an IPv4 address");
    return out;
}

fn portNumber(s: []const u8) ?u16 {
    if (s.len == 0 or s.len > 5) return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    const p = std.fmt.parseInt(u16, s, 10) catch return null;
    return if (p == 0) null else p;
}

/// `a.b.c.d`, each part 0 to 255 in decimal.
pub fn parseIp4(s: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |p| {
        if (n == 4 or p.len == 0 or p.len > 3) return null;
        for (p) |c| if (!std.ascii.isDigit(c)) return null;
        out[n] = std.fmt.parseInt(u8, p, 10) catch return null;
        n += 1;
    }
    return if (n == 4) out else null;
}

/// A job container's `ports:`, each read by `parsePort`; a literal list only. Two entries with
/// one host address, port and protocol are refused, as Docker refuses the second bind.
pub fn ports(arena: Allocator, list: []const job_mod.Template, why: *[]const u8) Error![]const Port {
    var out: std.ArrayList(Port) = .empty;
    for (list) |t| {
        const raw = switch (t) {
            .lit => |l| l,
            .expr => {
                why.* = "a job container's `ports:` given by an expression are not native yet" ++
                    dropped_ports;
                return error.Refused;
            },
        };
        const p = try parsePort(arena, raw, why);
        if (p.host != 0) for (out.items) |q| {
            const same_address = if (p.address == null or q.address == null)
                p.address == null and q.address == null
            else
                std.mem.eql(u8, &p.address.?, &q.address.?);
            if (q.host == p.host and q.udp == p.udp and same_address)
                return refusePort(arena, why, raw, "publishes a host port an earlier entry publishes");
        };
        try out.append(arena, p);
    }
    return out.items;
}

/// One `volumes:` entry the native job carries out.
pub const Volume = struct {
    /// A named volume's name; null for an anonymous one.
    name: ?[]const u8,
    /// Absolute, with no `.`, `..` or empty part.
    target: []const u8,
    /// A host path's source, as written (absolute; `host_paths.resolve` decides at the job's
    /// start whether the operator allows it). `name` is null then.
    host: ?[]const u8 = null,
    /// `:ro`: a named volume's or a host path's mount is read-only (an anonymous one's is
    /// refused).
    read_only: bool = false,
};

/// The job container's `volumes:`, all carried out.
pub const Volumes = struct {
    /// Every volume, in order.
    list: []const Volume = &.{},
    /// Every volume's mount point, in order.
    targets: []const []const u8 = &.{},
    /// How many of them are named.
    named: usize = 0,
};

fn refuseVolume(arena: Allocator, why: *[]const u8, raw: []const u8, reason: []const u8) Error {
    why.* = std.fmt.allocPrint(arena, "a job container's volume `{s}` {s}" ++ dropped_volumes, .{
        raw,
        reason,
    }) catch "a job container's volume is not carried out natively" ++ dropped_volumes;
    return error.Refused;
}

/// What GitHub's runner mounts itself in a job container (`ContainerInfo`, `ContainerOperationProvider`),
/// which Docker would refuse a second mount of.
const runner_mounts = [_][]const u8{
    "/__w", "/__t", "/__e", "/github/home", "/github/workflow", "/var/run/docker.sock",
};
/// Directories the sandbox mounts itself, and everything below them.
const sandbox_trees = [_][]const u8{ "/proc", "/sys", "/dev" };

/// `raw` as GitHub's runner reads a job container's `volumes:` entry (`MountVolume.ParseVolumeString`):
/// `target`, `source:target` or `source:target:ro` (and `target:ro`), which it passes on as
/// `docker create -v`. Carried out: an anonymous volume, a directory of the job's filesystem (new
/// and empty, or holding what the image has there, as the job's own overlay does) that lives as
/// long as the job, and a named one, read-only or not, which outlives the job as Docker's does
/// (`volumes.openNamed`, bound from the store). A path of the host as the source, read-only or
/// not, is read here and decided when the job starts (`host_paths.zig`: off unless the operator
/// allows the directory, and failed then, not sent to Dagger). Refused, with why: an anonymous
/// read-only volume (that would need a mount of its own), and a target that is not a plain
/// directory of the container.
pub fn parseVolume(arena: Allocator, raw: []const u8, why: *[]const u8) Error!Volume {
    var parts: [3][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ':');
    while (it.next()) |p| {
        if (n == parts.len) return refuseVolume(arena, why, raw, "has more than three parts");
        if (p.len == 0) return refuseVolume(arena, why, raw, "has an empty part");
        parts[n] = p;
        n += 1;
    }
    var name: ?[]const u8 = null;
    var target = parts[0];
    var read_only = false;
    if (n == 2 and std.ascii.eqlIgnoreCase(parts[1], "ro")) {
        read_only = true;
    } else if (n >= 2) {
        name = parts[0];
        target = parts[1];
        read_only = n == 3 and std.ascii.eqlIgnoreCase(parts[2], "ro");
    }
    var host: ?[]const u8 = null;
    if (name) |s| {
        if (s[0] == '/') {
            // Decided at the job's start against the operator's list (`host_paths.zig`), and
            // failed there when it is not on it: never sent to Dagger, which would drop it.
            host = s;
            name = null;
        } else if (!volumeName(s)) return refuseVolume(arena, why, raw, "has a source that is " ++
            "not a volume name Docker takes");
    }
    if (read_only and name == null and host == null) return refuseVolume(arena, why, raw, "is an " ++
        "anonymous read-only volume, which needs a mount of its own (a named one or a host " ++
        "path's can be read-only)");
    const clean = cleanTarget(arena, target) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NotPlain => return refuseVolume(arena, why, raw, "has a target that is not an " ++
            "absolute path without `.` or `..`"),
    };
    if (clean.len <= 1) return refuseVolume(arena, why, raw, "mounts the root directory");
    for (runner_mounts) |m| if (std.mem.eql(u8, clean, m)) return refuseVolume(arena, why, raw, "mounts " ++
        "where the runner mounts its own directory");
    for (sandbox_trees) |t| if (under(clean, t)) return refuseVolume(arena, why, raw, "mounts " ++
        "inside a directory the sandbox mounts itself");
    return .{ .name = name, .target = clean, .host = host, .read_only = read_only };
}

/// Whether `path` is `tree` or below it.
pub fn under(path: []const u8, tree: []const u8) bool {
    return std.mem.startsWith(u8, path, tree) and
        (path.len == tree.len or path[tree.len] == '/');
}

/// Docker's rule for a volume name: `[a-zA-Z0-9][a-zA-Z0-9_.-]+`.
fn volumeName(s: []const u8) bool {
    if (s.len < 2 or !std.ascii.isAlphanumeric(s[0])) return false;
    for (s[1..]) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '.' and c != '-') return false;
    return true;
}

/// `path` with its empty and `.` parts dropped; `error.NotPlain` for a relative path or a `..`.
fn cleanTarget(arena: Allocator, path: []const u8) error{ OutOfMemory, NotPlain }![]const u8 {
    if (path.len == 0 or path[0] != '/') return error.NotPlain;
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, path, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) return error.NotPlain;
        try out.append(arena, '/');
        try out.appendSlice(arena, part);
    }
    if (out.items.len == 0) try out.append(arena, '/');
    return out.items;
}

/// A job container's `volumes:`, each read by `parseVolume`; a literal list only (one with an
/// expression in it is decided before expressions are evaluated). Refused too: two volumes at
/// one path or one named volume at two (Docker refuses the first, and the second would need a
/// bind to be one directory in two places).
pub fn volumes(arena: Allocator, list: []const job_mod.Template, why: *[]const u8) Error!Volumes {
    var all: std.ArrayList(Volume) = .empty;
    var targets: std.ArrayList([]const u8) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    for (list) |t| {
        const raw = switch (t) {
            .lit => |l| l,
            .expr => {
                why.* = "a job container's `volumes:` given by an expression are not native yet" ++
                    dropped_volumes;
                return error.Refused;
            },
        };
        const v = try parseVolume(arena, raw, why);
        for (targets.items) |earlier| if (std.mem.eql(u8, earlier, v.target))
            return refuseVolume(arena, why, raw, "mounts a path an earlier volume mounts");
        if (v.name) |name| {
            for (names.items) |earlier| if (std.mem.eql(u8, earlier, name))
                return refuseVolume(arena, why, raw, "is a named volume mounted at two paths");
            try names.append(arena, name);
        }
        try targets.append(arena, v.target);
        try all.append(arena, v);
    }
    return .{ .list = all.items, .targets = targets.items, .named = names.items.len };
}

/// Why a job container cannot be native, or null: its `ports:`, any of its `volumes:` that
/// `volumes` does not carry out, and any of its `options:` that `parse` does not carry out
/// (docs/native-backend.md, "Job container options"). `provisioned` is whether its image is the
/// one the runner provisions, whose step user is `RUNNER_STEP_USER`'s choice, not the
/// container's. `services` are the job's: a native service mounts no volume, so a named volume
/// of the job container could not be shared with one.
pub fn unsupported(jc: job_mod.Service, provisioned: bool, services: []const job_mod.Service) ?[]const u8 {
    if (jc.ports.len > 0) {
        var fba: std.heap.FixedBufferAllocator = .init(&scratch);
        var why: []const u8 = "";
        _ = ports(fba.allocator(), jc.ports, &why) catch |e| return switch (e) {
            error.Refused => why,
            error.OutOfMemory => "a job container's `ports:` are too long to read natively" ++
                dropped_ports,
        };
    }
    if (jc.volumes.len > 0) {
        var fba: std.heap.FixedBufferAllocator = .init(&scratch);
        var why: []const u8 = "";
        const found = volumes(fba.allocator(), jc.volumes, &why) catch |e| return switch (e) {
            error.Refused => why,
            error.OutOfMemory => "a job container's `volumes:` are too long to read natively" ++
                dropped_volumes,
        };
        if (found.named > 0) for (services) |svc| if (svc.volumes.len > 0) return "a job " ++
            "container's named volume could be one a service mounts too, and native services " ++
            "mount no volume" ++ dropped_volumes;
    }
    const t = jc.options orelse return null;
    const text = switch (t) {
        .lit => |l| l,
        .expr => return "a job container's `options:` given by an expression are not native " ++
            "yet" ++ dropped,
    };
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    var why: []const u8 = "";
    const o = parse(fba.allocator(), text, &why) catch |e| return switch (e) {
        error.Refused => why,
        error.OutOfMemory => "a job container's `options:` are too long to read natively",
    };
    if (o.user != null and provisioned) return "a job container's `--user` on the default " ++
        "image, whose steps run as RUNNER_STEP_USER's user, is not native" ++ dropped;
    if (o.tmpfs.len > 0 and jc.volumes.len > 0) {
        const found = volumes(fba.allocator(), jc.volumes, &why) catch return null;
        for (o.tmpfs) |fs| for (found.targets) |v| if (under(fs.target, v) or under(v, fs.target))
            return "a job container's `--tmpfs` is at or beside a path a volume mounts" ++ dropped;
    }
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

test "options honoured: hostname, add-host, shm-size, tmpfs, memory and init in every spelling" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";

    const o = try parse(arena, "--hostname build-1.local --add-host db:10.0.0.5 " ++
        "--add-host=cache=10.0.0.6 --shm-size 1g --memory 512m --init " ++
        "--tmpfs /run:rw,noexec,size=64m --tmpfs /scratch --tmpfs=/fast:exec,mode=0755,ro", &why);
    try std.testing.expectEqualStrings("build-1.local", o.hostname.?);
    try std.testing.expectEqual(@as(usize, 2), o.add_hosts.len);
    try std.testing.expectEqualStrings("db", o.add_hosts[0].name);
    try std.testing.expectEqualStrings("10.0.0.5", o.add_hosts[0].ip);
    try std.testing.expectEqualStrings("cache", o.add_hosts[1].name);
    try std.testing.expectEqual(@as(?u64, 1 << 30), o.shm_size);
    try std.testing.expectEqual(@as(?u64, 512 << 20), o.memory);
    try std.testing.expectEqual(@as(u32, 1), o.no_effect);
    try std.testing.expectEqual(@as(usize, 3), o.tmpfs.len);
    try std.testing.expectEqualStrings("/run", o.tmpfs[0].target);
    try std.testing.expectEqual(@as(u64, 64 << 20), o.tmpfs[0].size);
    try std.testing.expect(!o.tmpfs[0].exec and !o.tmpfs[0].read_only);
    try std.testing.expectEqual(@as(u32, 0o1777), o.tmpfs[1].mode);
    try std.testing.expect(o.tmpfs[2].exec and o.tmpfs[2].read_only);
    try std.testing.expectEqual(@as(u32, 0o755), o.tmpfs[2].mode);

    // The short forms, and sizes as Docker writes them.
    const s = try parse(arena, "-h box -m2G --shm-size=128MB --tmpfs //var//tmp/./x:size=1k", &why);
    try std.testing.expectEqualStrings("box", s.hostname.?);
    try std.testing.expectEqual(@as(?u64, 2 << 30), s.memory);
    try std.testing.expectEqual(@as(?u64, 128 << 20), s.shm_size);
    try std.testing.expectEqualStrings("/var/tmp/x", s.tmpfs[0].target);
    try std.testing.expectEqual(@as(u64, 1024), s.tmpfs[0].size);
    try std.testing.expectEqual(@as(?u64, 1 << 20), (try parse(arena, "--shm-size 1048576", &why)).shm_size);
}

test "options refused: unsafe or unreadable values of the honoured flags" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // `host-gateway` is the host's address; IPv6 and non-addresses are not the jobs' network.
    try expectRefused(arena, "--add-host db:host-gateway", "--add-host");
    try expectRefused(arena, "--add-host db:::1", "--add-host");
    try expectRefused(arena, "--add-host db", "--add-host");
    try expectRefused(arena, "--add-host bad_name:10.0.0.1", "--add-host");
    try expectRefused(arena, "--add-host db:300.0.0.1", "--add-host");
    try expectRefused(arena, "--hostname -x", "--hostname");
    try expectRefused(arena, "--hostname \"a b\"", "--hostname");
    try expectRefused(arena, "--hostname aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--hostname");
    try expectRefused(arena, "--shm-size 0", "--shm-size");
    try expectRefused(arena, "--shm-size 1.5g", "--shm-size");
    try expectRefused(arena, "--shm-size 10x", "--shm-size");
    try expectRefused(arena, "--shm-size 99999999999t", "--shm-size");
    try expectRefused(arena, "--memory 1m", "--memory");
    try expectRefused(arena, "--memory lots", "--memory");
    // A tmpfs stays inside the job's filesystem and the sandbox's own mounts.
    try expectRefused(arena, "--tmpfs relative", "--tmpfs");
    try expectRefused(arena, "--tmpfs /a/../etc", "--tmpfs");
    try expectRefused(arena, "--tmpfs /", "--tmpfs");
    try expectRefused(arena, "--tmpfs /proc/sys", "--tmpfs");
    try expectRefused(arena, "--tmpfs /dev", "--tmpfs");
    try expectRefused(arena, "--tmpfs /__w/r", "--tmpfs");
    try expectRefused(arena, "--tmpfs /github/home", "--tmpfs");
    try expectRefused(arena, "--tmpfs /t:suid", "--tmpfs");
    try expectRefused(arena, "--tmpfs /t:dev", "--tmpfs");
    try expectRefused(arena, "--tmpfs /t:uid=0", "--tmpfs");
    try expectRefused(arena, "--tmpfs /t:size=big", "--tmpfs");
    try expectRefused(arena, "--tmpfs /t:mode=9999", "--tmpfs");
    try expectRefused(arena, "--tmpfs /t:mode=17777", "--tmpfs");
    try expectRefused(arena, "--tmpfs /t --tmpfs /t/", "--tmpfs");
}

test "options refused, never ignored: what the sandbox does not carry out" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    for ([_][]const u8{
        "--cpus",         "--memory-swap",      "--privileged", "--cap-add",   "--device",
        "--security-opt", "--cap-drop",         "--ulimit",     "--network",   "--net",
        "--uts",          "--cpuset-cpus",      "--tty",        "-t",          "-i",
        "--volume",       "-v",                 "--publish",    "-p",          "--entrypoint",
        "--name",         "--env-file",         "--label",      "--group-add", "--pid",
        "--ipc",          "--gpus",             "--platform",   "--read-only", "--dns",
        "--sysctl",       "--oom-kill-disable", "--mount",      "--pull",      "--userns",
        "--cgroupns",     "--cgroup-parent",    "--pids-limit", "--restart",   "--runtime",
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
    try std.testing.expect(unsupported(base, false, &.{}) == null);

    var jc = base;
    jc.options = .{ .lit = "--user 1001 -e A=1 --workdir /x --health-cmd true" };
    try std.testing.expect(unsupported(jc, false, &.{}) == null);
    // The default image's user is the runner's choice, not the container's.
    try std.testing.expect(unsupported(jc, true, &.{}) != null);
    jc.options = .{ .lit = "-e A=1" };
    try std.testing.expect(unsupported(jc, true, &.{}) == null);

    jc.options = .{ .lit = "--hostname h --add-host a:10.0.0.1 --shm-size 1g --tmpfs /x --init" };
    try std.testing.expect(unsupported(jc, false, &.{}) == null);
    // A tmpfs over, or under, a volume would hide it: not native.
    jc.volumes = &.{.{ .lit = "/x/data" }};
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "--tmpfs") != null);
    jc.volumes = &.{.{ .lit = "/y" }};
    try std.testing.expect(unsupported(jc, false, &.{}) == null);
    jc.volumes = &.{};

    // The sandbox's own powers are not for a workflow to ask for: each goes to Dagger by name.
    for ([_][]const u8{
        "--privileged",   "--cap-add SYS_ADMIN", "--security-opt seccomp=unconfined", "--device /dev/kvm",
        "--network host", "--net=host",          "--pid=host",                        "--ipc host",
        "--userns host",  "--cpus 2",
    }) |flag| {
        jc.options = .{ .lit = flag };
        const why = unsupported(jc, false, &.{}).?;
        const name = flag[0 .. std.mem.indexOfAny(u8, flag, " =") orelse flag.len];
        try std.testing.expect(std.mem.indexOf(u8, why, name) != null);
        try std.testing.expect(std.mem.indexOf(u8, why, "drops") != null);
    }
    jc.options = .{ .lit = "--privileged" };
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "--privileged") != null);
    // Dagger reads none of `options:`: the note says the flag is dropped there, not carried out.
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "drops") != null);
    jc.options = .{ .expr = "matrix.options" };
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "expression") != null);
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "drops") != null);

    // Ports Docker publishes are native (`publish.zig` decides at the job's start what the
    // operator allows); the forms that are not go to Dagger, which warns and ignores them, and the
    // reason says so.
    jc = base;
    for ([_][]const u8{ "8080:80", "80", "127.0.0.1:8080:80/tcp", "0.0.0.0::53/udp" }) |p| {
        jc.ports = &.{.{ .lit = p }};
        try std.testing.expect(unsupported(jc, false, &.{}) == null);
    }
    for ([_][]const u8{ "8000-8010:8000-8010", "[::1]:8080:80", "80/sctp" }) |p| {
        jc.ports = &.{.{ .lit = p }};
        const why = unsupported(jc, false, &.{}).?;
        try std.testing.expect(std.mem.indexOf(u8, why, p) != null);
        try std.testing.expect(std.mem.indexOf(u8, why, "Dagger ignores") != null);
    }
    jc.ports = &.{.{ .expr = "matrix.ports" }};
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "expression") != null);
}

test "ports read as docker create -p reads them" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var why: []const u8 = "";
    const Case = struct { raw: []const u8, want: Port };
    for ([_]Case{
        .{ .raw = "80", .want = .{ .container = 80 } },
        .{ .raw = "8080:80", .want = .{ .host = 8080, .container = 80 } },
        .{ .raw = "127.0.0.1:8080:80/tcp", .want = .{ .address = .{ 127, 0, 0, 1 }, .host = 8080, .container = 80 } },
        .{ .raw = "0.0.0.0::53/UDP", .want = .{ .address = .{ 0, 0, 0, 0 }, .container = 53, .udp = true } },
        .{ .raw = "5353:53/udp", .want = .{ .host = 5353, .container = 53, .udp = true } },
        .{ .raw = " 9000 ", .want = .{ .container = 9000 } },
    }) |c| {
        const p = try parsePort(arena, c.raw, &why);
        try std.testing.expectEqual(c.want.host, p.host);
        try std.testing.expectEqual(c.want.container, p.container);
        try std.testing.expectEqual(c.want.udp, p.udp);
        try std.testing.expectEqual(c.want.address == null, p.address == null);
        if (p.address) |ad| try std.testing.expectEqualSlices(u8, &c.want.address.?, &ad);
    }
    for ([_][2][]const u8{
        .{ "8000-8010:8000-8010", "range" },
        .{ "[::1]:8080:80", "IPv6" },
        .{ "80/sctp", "TCP or UDP" },
        .{ "0", "container port" },
        .{ "8080:70000", "container port" },
        .{ "x:80", "host port" },
        .{ "localhost:8080:80", "IPv4" },
        .{ "1.2.3:8080:80", "IPv4" },
        .{ "1:2:3:4", "[ip:][hostPort:]containerPort" },
        .{ "", "container port" },
    }) |c| {
        why = "";
        try std.testing.expectError(error.Refused, parsePort(arena, c[0], &why));
        if (std.mem.indexOf(u8, why, c[1]) == null or std.mem.indexOf(u8, why, "Dagger ignores") == null) {
            std.debug.print("{s} refused as: {s}\n", .{ c[0], why });
            return error.TestUnexpectedResult;
        }
    }
    // One host port twice: Docker's second bind would fail. Another address or protocol is
    // another socket, and kernel-picked ports never clash.
    const twice = [_]job_mod.Template{ .{ .lit = "8080:80" }, .{ .lit = "8080:81" } };
    try std.testing.expectError(error.Refused, ports(arena, &twice, &why));
    try std.testing.expect(std.mem.indexOf(u8, why, "earlier entry") != null);
    const apart = [_]job_mod.Template{ .{ .lit = "8080:80" }, .{ .lit = "8080:80/udp" }, .{ .lit = "127.0.0.2:8080:80" }, .{ .lit = "80" }, .{ .lit = "80" } };
    try std.testing.expectEqual(@as(usize, 5), (try ports(arena, &apart, &why)).len);
}

fn expectVolume(arena: Allocator, raw: []const u8, name: ?[]const u8, target: []const u8) !void {
    var why: []const u8 = "";
    const v = parseVolume(arena, raw, &why) catch |e| {
        std.debug.print("{s} is refused ({s}): {s}\n", .{ raw, @errorName(e), why });
        return e;
    };
    try std.testing.expectEqualStrings(target, v.target);
    if (name) |n| try std.testing.expectEqualStrings(n, v.name.?) else try std.testing.expect(v.name == null);
}

fn expectVolumeRefused(arena: Allocator, raw: []const u8, mentions: []const u8) !void {
    var why: []const u8 = "";
    if (parseVolume(arena, raw, &why)) |v| {
        std.debug.print("{s} is carried out as {?s}:{s}\n", .{ raw, v.name, v.target });
        return error.TestUnexpectedResult;
    } else |e| try std.testing.expectEqual(error.Refused, e);
    if (std.mem.indexOf(u8, why, mentions) == null or std.mem.indexOf(u8, why, raw) == null or
        std.mem.indexOf(u8, why, "Dagger ignores") == null)
    {
        std.debug.print("{s} is refused as: {s}\n", .{ raw, why });
        return error.TestUnexpectedResult;
    }
}

test "volumes carried out: an anonymous, a named or a host path's volume, read as GitHub's runner reads it" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // `ParseVolumeString`: `target`, `source:target`, `source:target:mode`; only `ro` is a mode.
    try expectVolume(arena, "/data", null, "/data");
    try expectVolume(arena, "cache:/cache", "cache", "/cache");
    try expectVolume(arena, "my_vol-1.x:/var/lib/data:rw", "my_vol-1.x", "/var/lib/data");
    // `z` and the like are not read by the runner: not passed on.
    try expectVolume(arena, "cache:/cache:z", "cache", "/cache");
    // A named volume can be read-only, in either spelling: a read-only bind of it.
    var why: []const u8 = "";
    for ([_][]const u8{ "cache:/cache:ro", "cache:/cache:RO" }) |raw|
        try std.testing.expect((try parseVolume(arena, raw, &why)).read_only);
    try std.testing.expect(!(try parseVolume(arena, "cache:/cache:rw", &why)).read_only);
    try std.testing.expect(!(try parseVolume(arena, "cache:/cache", &why)).read_only);
    // Docker cleans the target.
    try expectVolume(arena, "/a//b/./c/", null, "/a/b/c");
    try expectVolume(arena, "v2:/opt//x", "v2", "/opt/x");
    // A host path, read-only or not: read here, decided against the operator's list when the
    // job starts (`host_paths.zig`), never sent to Dagger.
    const h = try parseVolume(arena, "/srv/data:/data", &why);
    try std.testing.expectEqualStrings("/srv/data", h.host.?);
    try std.testing.expect(h.name == null and !h.read_only);
    try std.testing.expectEqualStrings("/data", h.target);
    for ([_][]const u8{ "/srv:/srv:ro", "/srv:/srv:RO" }) |raw|
        try std.testing.expect((try parseVolume(arena, raw, &why)).read_only);
    try std.testing.expectEqualStrings("/", (try parseVolume(arena, "/:/host:rw", &why)).host.?);
}

test "volumes refused, never ignored: the runner's mounts, anonymous read-only, and targets that are not plain" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // The Docker socket's target is the runner's own (its source is decided with the host paths).
    try expectVolumeRefused(arena, "/var/run/docker.sock:/var/run/docker.sock", "runner mounts");
    // An anonymous read-only volume would need a mount of its own, in either spelling.
    try expectVolumeRefused(arena, "/data:ro", "read-only");
    try expectVolumeRefused(arena, "/data:RO", "read-only");
    // What Docker itself refuses: a relative or `..` target, a bad name, extra parts, empty parts.
    try expectVolumeRefused(arena, "cache:data", "absolute");
    try expectVolumeRefused(arena, "cache:/a/../b", "absolute");
    try expectVolumeRefused(arena, "data", "absolute");
    try expectVolumeRefused(arena, "./rel:/x", "volume name");
    try expectVolumeRefused(arena, "a:/x", "volume name");
    try expectVolumeRefused(arena, "my vol:/x", "volume name");
    try expectVolumeRefused(arena, "-v:/x", "volume name");
    try expectVolumeRefused(arena, "a:/b:c:d", "more than three");
    try expectVolumeRefused(arena, "cache:", "empty part");
    try expectVolumeRefused(arena, ":/x", "empty part");
    try expectVolumeRefused(arena, "", "empty part");
    // The root, the sandbox's own mounts and the runner's own.
    try expectVolumeRefused(arena, "v1:/", "root");
    try expectVolumeRefused(arena, "/", "root");
    for ([_][]const u8{ "/proc", "/proc/1", "/sys/fs", "/dev", "/dev/shm", "/__w", "/__t", "/__e", "/github/home", "/github/workflow", "/var/run/docker.sock" }) |t| {
        const raw = try std.fmt.allocPrint(arena, "vol:{s}", .{t});
        try expectVolumeRefused(arena, raw, "mounts");
    }
    // Below the runner's directories is a directory like any other.
    try expectVolume(arena, "/__w/data", null, "/__w/data");
    try expectVolume(arena, "/devices", null, "/devices");
}

test "unsupported: a list of volumes is carried out whole, or the job falls back" {
    const base: job_mod.Service = .{ .name = "", .image = .{ .lit = "node:22" } };
    var jc = base;
    jc.volumes = &.{ .{ .lit = "/data" }, .{ .lit = "cache:/cache" }, .{ .lit = "other:/other:ro" } };
    try std.testing.expect(unsupported(jc, false, &.{}) == null);
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var why: []const u8 = "";
    const v = try volumes(a.allocator(), jc.volumes, &why);
    try std.testing.expectEqual(@as(usize, 2), v.named);
    try std.testing.expectEqual(@as(usize, 3), v.targets.len);
    try std.testing.expectEqualStrings("/other", v.targets[2]);
    try std.testing.expectEqual(@as(usize, 3), v.list.len);
    try std.testing.expectEqualStrings("other", v.list[2].name.?);
    try std.testing.expect(v.list[2].read_only and !v.list[1].read_only);
    try std.testing.expect(v.list[0].name == null);

    // A host path stays native: the job decides it, and fails if the operator does not allow it.
    jc.volumes = &.{ .{ .lit = "/data" }, .{ .lit = "/srv:/srv:ro" } };
    try std.testing.expect(unsupported(jc, false, &.{}) == null);
    const hv = try volumes(a.allocator(), jc.volumes, &why);
    try std.testing.expectEqualStrings("/srv", hv.list[1].host.?);
    // One that is not carried out takes the whole list to Dagger, and the reason names it.
    jc.volumes = &.{ .{ .lit = "/data" }, .{ .lit = "/other:ro" } };
    const ro = unsupported(jc, false, &.{}).?;
    try std.testing.expect(std.mem.indexOf(u8, ro, "`/other:ro`") != null);
    try std.testing.expect(std.mem.indexOf(u8, ro, "Dagger ignores a job container's `volumes:`") != null);
    // An expression is read after this is decided.
    jc.volumes = &.{.{ .expr = "matrix.volume" }};
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "expression") != null);
    // Two volumes at one path, and one name at two paths.
    jc.volumes = &.{ .{ .lit = "a1:/x" }, .{ .lit = "b1:/x" } };
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "earlier volume") != null);
    jc.volumes = &.{ .{ .lit = "/x/" }, .{ .lit = "/x" } };
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "earlier volume") != null);
    jc.volumes = &.{ .{ .lit = "a1:/x" }, .{ .lit = "a1:/y" } };
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{}).?, "two paths") != null);

    // A native service mounts no volume, so a named volume the service lists could not be shared;
    // an anonymous one is the job container's alone.
    var svc: job_mod.Service = .{ .name = "db", .image = .{ .lit = "postgres:17" } };
    svc.volumes = &.{.{ .lit = "cache:/var/lib/postgresql" }};
    jc.volumes = &.{.{ .lit = "cache:/cache" }};
    try std.testing.expect(std.mem.indexOf(u8, unsupported(jc, false, &.{svc}).?, "service") != null);
    jc.volumes = &.{.{ .lit = "/cache" }};
    try std.testing.expect(unsupported(jc, false, &.{svc}) == null);
    svc.volumes = &.{};
    jc.volumes = &.{.{ .lit = "cache:/cache" }};
    try std.testing.expect(unsupported(jc, false, &.{svc}) == null);
}
