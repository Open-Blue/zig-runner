//! A native job's `services:` (docs/native-backend.md, P6): "Initialize containers" starts each
//! service as a long-running sandbox of its own (`sandbox.zig`, as a step's, from its image's
//! filesystem, `images.zig`), in the job's network namespace, which the steps share; waits until
//! each is ready (`health.zig`); and "Stop containers" stops them and prints their logs. What the
//! Dagger path does in `dagger/services.zig`, the log lines included.
//!
//! How a job sees its services, as on the Dagger path: by name (`postgres:5432`, an `/etc/hosts`
//! line of the job's that names the loopback, `Backend.serviceHosts`) and on `localhost` at each
//! published port (`ports: ['15432:5432']`, relayed by `forward.zig` when the numbers differ).
//! Nothing outside the job reaches them: the job's network is its own (P1's isolation), and so
//! are its services'.
//!
//! A service runs as a step does, but until it is stopped: its own mount, PID, UTS and IPC
//! namespaces, the job's ids (its root is nobody on the host), Docker's capabilities and the
//! seccomp filter, a fresh overlay over the image (its writes go with the job), its first process
//! PID 1 of its namespace. Stopping it closes its helper's lifeline, and the helper kills that
//! PID 1 and with it everything the service started, as `docker rm --force` does.

const std = @import("std");
const job_mod = @import("../job.zig");
const expr = @import("../expr.zig");
const Exec = @import("../dagger/Exec.zig");
const Evaluator = @import("../dagger/Evaluator.zig");
const JobLog = @import("../dagger/JobLog.zig");
const Backend = @import("Backend.zig");
const sandbox = @import("sandbox.zig");
const health = @import("health.zig");
const images = @import("images.zig");
const registry = @import("oci/registry.zig");
const docker = @import("../dagger/docker.zig");
const forward = @import("forward.zig");

const Allocator = std.mem.Allocator;

/// A job's running services and their port relay, the Backend's to stop however the job ends.
pub const Set = struct {
    list: std.ArrayList(*Service) = .empty,
    relay: ?forward.Running = null,

    /// The relay stopped, then every service, each waited for (`Backend.deinit`, and "Stop
    /// containers"). Stopping one already stopped does nothing.
    pub fn stopAll(set: *Set, io: std.Io) void {
        if (set.relay) |*r| r.stop(io);
        set.relay = null;
        for (set.list.items) |s| s.running.stop(io);
        for (set.list.items) |s| s.wait(io);
    }
};

/// One service's sandbox, run by a task of its own for the job's life (`serve`).
const Service = struct {
    name: []const u8,
    index: u32,
    /// Where its helper writes whether it is ready (`health.Ready.status`).
    status: []const u8,
    running: sandbox.Running = .{},
    task: ?std.Io.Future(void) = null,
    /// How its helper ended, once `done`.
    ended: sandbox.Ended = .{ .code = 0, .failure = "" },
    done: std.atomic.Value(bool) = .init(false),
    lines: Lines,

    fn wait(s: *Service, io: std.Io) void {
        if (s.task) |*t| t.await(io);
        s.task = null;
    }
};

/// A service's output, split into lines for "Stop containers" (`JobLog.serviceLine`, as the
/// Dagger path keeps it).
const Lines = struct {
    sh: *JobLog,
    n: u32,
    arena: Allocator,
    partial: std.ArrayList(u8) = .empty,

    /// A line longer than this is cut, as no log line should be unbounded.
    const max_line = 64 * 1024;

    fn output(l: *Lines) sandbox.Output {
        return .{ .ptr = l, .chunkFn = chunk };
    }

    fn chunk(ptr: *anyopaque, bytes: []const u8) void {
        const l: *Lines = @ptrCast(@alignCast(ptr));
        var rest = bytes;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |nl| {
            l.partial.appendSlice(l.arena, rest[0..nl]) catch return;
            l.emit();
            rest = rest[nl + 1 ..];
        }
        l.partial.appendSlice(l.arena, rest) catch return;
        if (l.partial.items.len >= max_line) l.emit();
    }

    fn emit(l: *Lines) void {
        l.sh.serviceLine(l.n, std.mem.trimEnd(u8, l.partial.items, "\r"));
        l.partial.clearRetainingCapacity();
    }

    fn flush(l: *Lines) void {
        if (l.partial.items.len > 0) l.emit();
    }
};

/// How long the runner waits for a service whose helper never answers: a health check's own
/// retries and the ports' timeout end well before.
const ready_cap_ms = 30 * 60 * 1000;
const poll_ms = 10;

/// "Initialize containers" on the native backend (`dagger/services.zig`'s `startServices` hands
/// it here): every service started, then each waited for, then the published ports relayed.
/// False when one could not start or never became ready: the job then fails without running
/// its steps, as on GitHub. The services started so far are stopped with the job
/// (`Backend.deinit`).
pub fn start(b: *Backend, x: *Exec) !bool {
    const arena = x.arena;
    const ev = x.ev;
    const ls = x.next_log_step;
    x.next_log_step += 1;
    const started = std.Io.Clock.real.now(x.io).toMilliseconds();
    var ok = true;
    x.startExtra(.initialize, ls, "Initialize containers", started);
    defer x.addExtra(.{
        .kind = .initialize,
        .name = "Initialize containers",
        .log_step = ls,
        .outcome = if (ok) .success else .failure,
        .started_ms = started,
        .completed_ms = std.Io.Clock.real.now(x.io).toMilliseconds(),
    }) catch {};
    ev.diag = "";
    const sc = try ev.scope(&.{});
    // A `container:` job's image, pulled for the job's base (P3): said here, as on Dagger.
    if (x.job.container) |jc| {
        if (!try x.pullJobContainer(ls, jc)) {
            ok = false;
            return false;
        }
        if (x.job.services.len == 0) return true;
    }
    var names: std.ArrayList([]const u8) = .empty;
    for (x.job.services) |svc| try names.append(arena, svc.name);
    // Before any service starts: they reach each other by name too.
    try b.serviceHosts(names.items);
    for (x.job.services, 0..) |svc, i| {
        x.sh.append(ls, try std.fmt.allocPrint(arena, "##[group]Starting {s} service container", .{
            svc.name,
        }));
        defer x.sh.append(ls, "##[endgroup]");
        const r = (try startOne(b, x, ls, sc, svc, @intCast(i))) orelse {
            ok = false;
            return false;
        };
        try x.services.append(arena, r);
    }
    {
        x.sh.append(ls, "##[group]Waiting for all services to be ready");
        defer x.sh.append(ls, "##[endgroup]");
        for (b.service_set.list.items) |s| if (!try waitReady(x, ls, s)) {
            ok = false;
            return false;
        };
    }
    if (!try startRelay(b, x, ls)) {
        ok = false;
        return false;
    }
    try ev.setServices(x.services.items, null);
    return true;
}

/// One service: its spec evaluated (`serviceSpec`, the Dagger path's, which logs its image and
/// the options it does not carry out), its image found, its sandbox started. Null when that
/// failed (logged).
fn startOne(
    b: *Backend,
    x: *Exec,
    ls: u32,
    sc: expr.Scope,
    svc: job_mod.Service,
    index: u32,
) !?Exec.RunningService {
    const arena = x.arena;
    const io = b.io;
    const spec = (try x.serviceSpec(ls, sc, svc)) orelse return null;
    x.sh.append(ls, try std.fmt.allocPrint(arena, "Pulling {s}", .{spec.image}));
    var creds: ?registry.Credentials = null;
    if (try docker.registryCredentials(x.ev, svc)) |c| creds = .{ .username = c.user, .password = c.pass };
    var why: []const u8 = "";
    const image = b.pullImage(spec.image, creds, &why) catch |e| {
        x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "Failed to pull {s} for service {s}: {s}", .{
            spec.image,
            svc.name,
            if (why.len > 0) why else @errorName(e),
        }));
        return null;
    };
    if (image.digest) |d| x.sh.append(ls, try std.fmt.allocPrint(arena, "Digest: {s}", .{d}));
    const argv = try std.mem.concat(arena, []const u8, &.{ image.entrypoint, image.cmd });
    if (argv.len == 0) {
        x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "The image {s} of service {s} has no " ++
            "entrypoint or command to run", .{ spec.image, svc.name }));
        return null;
    }
    const passwd = textIn(arena, image.rootfs, "/etc/passwd");
    const group = textIn(arena, image.rootfs, "/etc/group");
    const ids = images.userIds(image.user, passwd, group) orelse {
        x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "Unable to find user {s} of image {s} " ++
            "for service {s}", .{ image.user, spec.image, svc.name }));
        return null;
    };
    var bad: std.ArrayList([]const u8) = .empty;
    const options = if (svc.options) |t| x.ev.render(t, sc) catch "" else "";
    const check = try health.healthFor(arena, options, image.healthcheck, &bad);
    for (bad.items) |w| x.sh.append(ls, try std.fmt.allocPrint(arena, "##[warning]Service " ++
        "option not understood, Docker's default kept: {s}", .{w}));

    // The image's environment, then what GitHub's runner sets for service containers, then the
    // service's `env:`, each over the one before.
    var env: std.ArrayList(job_mod.EnvVar) = .empty;
    for (image.env) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        try Evaluator.putEnv(arena, &env, kv[0..eq], kv[eq + 1 ..]);
    }
    try Evaluator.putEnv(arena, &env, "GITHUB_ACTIONS", "true");
    try Evaluator.putEnv(arena, &env, "CI", "true");
    for (spec.env) |e| try Evaluator.putEnv(arena, &env, e.name, e.value);
    const env_strings = try arena.alloc([]const u8, env.items.len);
    for (env.items, env_strings) |e, *o| o.* = try std.fmt.allocPrint(arena, "{s}={s}", .{
        e.name,
        e.value,
    });

    var ports: std.ArrayList(u16) = .empty;
    if (check == null) for (spec.ports) |p| try ports.append(arena, p.container);
    const dirs = try b.serviceDirs(index, image.rootfs);
    const s = try arena.create(Service);
    s.* = .{
        .name = svc.name,
        .index = index,
        .status = dirs.status,
        .lines = .{ .sh = x.sh, .n = index, .arena = arena },
    };
    const box: sandbox.Spec = .{
        .root = b.dir,
        .lowers = try arena.dupe([]const u8, &.{dirs.image}),
        .upper = dirs.upper,
        .work = dirs.work,
        .merged = dirs.merged,
        .workdir = if (image.workdir.len > 0) image.workdir else "/",
        .uid = ids.uid,
        .gid = ids.gid,
        .argv = argv,
        .exec = "",
        .env = env_strings,
        .binds = b.serviceBinds(),
        .userns = b.how.userns,
        .id_base = b.idBase(),
        .id_count = Backend.ids_per_slot,
        .netns = b.netns,
        // P4: the service's helper and everything it starts are in the job's cgroup, held to
        // the job's limits and measured with it.
        .cgroup = if (b.job_cgroup) |j| j.dir else null,
        .service = .{ .status = dirs.status, .health = check, .ports = ports.items },
    };
    try b.service_set.list.append(arena, s);
    s.task = io.concurrent(serve, .{ s, arena, io, b.how.argv_prefix, box }) catch |e| {
        x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "Failed to start service container " ++
            "{s}: {s}", .{ svc.name, @errorName(e) }));
        return null;
    };
    for (spec.ports) |p| x.sh.append(ls, try std.fmt.allocPrint(arena, "{d}/tcp -> " ++
        "localhost:{d}", .{ p.container, p.host }));
    return .{
        .name = svc.name,
        .id = try std.fmt.allocPrint(arena, "native-{s}", .{svc.name}),
        .ports = spec.ports,
    };
}

/// A service's sandbox, until it is stopped or ends; its output into its log.
fn serve(
    s: *Service,
    arena: Allocator,
    io: std.Io,
    argv_prefix: []const []const u8,
    box: sandbox.Spec,
) void {
    defer s.done.store(true, .release);
    s.ended = sandbox.run(arena, io, argv_prefix, box, &s.running, s.lines.output()) catch |e|
        .{ .code = 125, .failure = @errorName(e) };
    s.lines.flush();
}

/// Waits until the service's helper says it is ready ("<name> service is healthy.", as GitHub's
/// runner says it), or that it is not, or the service ends first. False, with why, for the last
/// two, and the service's output so far.
fn waitReady(x: *Exec, ls: u32, s: *Service) !bool {
    const arena = x.arena;
    const io = x.io;
    const began = std.Io.Clock.awake.now(io).toMilliseconds();
    while (true) {
        var buf: [256]u8 = undefined;
        const text = std.Io.Dir.cwd().readFile(io, s.status, &buf) catch "";
        // Complete only once its line has ended: it is written once, and may be read mid-write.
        if (std.mem.endsWith(u8, text, "\n")) {
            const line = std.mem.trimEnd(u8, text, "\n");
            if (std.mem.eql(u8, line, "ready")) {
                const line_ok = try std.fmt.allocPrint(arena, "{s} service is healthy.", .{s.name});
                x.sh.append(ls, line_ok);
                return true;
            }
            const prefix = "unhealthy ";
            const why = if (std.mem.startsWith(u8, line, prefix)) line[prefix.len..] else line;
            x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "Failed to initialize, {s} service " ++
                "is unhealthy: {s}.", .{ s.name, why }));
            printLog(x, ls, s);
            return false;
        }
        if (s.done.load(.acquire)) {
            const failure = if (s.ended.failure.len > 0)
                try std.fmt.allocPrint(arena, " ({s})", .{s.ended.failure})
            else
                "";
            x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "Failed to initialize, {s} service " ++
                "ended before it was ready, with exit code {d}{s}.", .{
                s.name,
                s.ended.code,
                failure,
            }));
            printLog(x, ls, s);
            return false;
        }
        if (std.Io.Clock.awake.now(io).toMilliseconds() - began > ready_cap_ms) {
            x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "Failed to initialize, {s} service " ++
                "was not ready after {d} minutes.", .{ s.name, ready_cap_ms / 60_000 }));
            return false;
        }
        io.sleep(.fromMilliseconds(poll_ms), .awake) catch {};
    }
}

/// The service's output so far, under "Initialize containers", when it failed there.
fn printLog(x: *Exec, ls: u32, s: *Service) void {
    // Every line in: wait for its task, which ends once its output has.
    if (s.done.load(.acquire)) s.wait(x.io);
    for (x.sh.takeServiceLog(s.index)) |l| x.sh.append(ls, l);
}

/// The relay for every port published under a number other than its own (`forward.zig`). False
/// when it could not listen (logged).
fn startRelay(b: *Backend, x: *Exec, ls: u32) !bool {
    const arena = x.arena;
    var maps: std.ArrayList(forward.Spec.Map) = .empty;
    for (x.services.items) |r| for (r.ports) |p| if (p.host != p.container)
        try maps.append(arena, .{ .host = p.host, .container = p.container });
    if (maps.items.len == 0) return true;
    var why: []const u8 = "";
    b.service_set.relay = forward.start(arena, b.io, b.self_exe, .{
        .netns = b.netns,
        // The job's nobody: an id of its range, nothing on the host.
        .id = if (b.how.userns == .mapped) b.idBase() + nobody else null,
        .cgroup = if (b.job_cgroup) |j| j.dir else null,
        .ports = maps.items,
    }, &why) catch {
        x.sh.errorLine(ls, try std.fmt.allocPrint(arena, "Failed to publish the services' " ++
            "ports: {s}", .{why}));
        return false;
    };
    return true;
}

/// `nobody` in the job's range of ids.
const nobody = 65534;

/// "Stop containers" on the native backend, after the post scripts: each service stopped, then
/// its output printed, as GitHub's runner prints `docker logs` before it removes a container.
pub fn stop(b: *Backend, x: *Exec) !void {
    if (x.services.items.len == 0 and x.job.container == null) return;
    const ls = x.next_log_step;
    x.next_log_step += 1;
    const started = std.Io.Clock.real.now(x.io).toMilliseconds();
    x.startExtra(.stop, ls, "Stop containers", started);
    // All at once, so the job does not wait for them one by one; every line of theirs is in
    // once they have ended.
    b.service_set.stopAll(b.io);
    for (b.service_set.list.items) |s| {
        x.sh.append(ls, try std.fmt.allocPrint(x.arena, "Print service container logs: {s}", .{
            s.name,
        }));
        for (x.sh.takeServiceLog(s.index)) |l| x.sh.append(ls, l);
        if (s.ended.failure.len > 0 and !s.ended.killed) x.sh.append(ls, try std.fmt.allocPrint(
            x.arena,
            "##[warning]The {s} service's sandbox failed: {s}",
            .{ s.name, s.ended.failure },
        ));
        x.sh.append(ls, try std.fmt.allocPrint(x.arena, "Stop and remove container: {s}", .{
            s.name,
        }));
    }
    // The job container (P3's pulled image) goes with the job, as on Dagger.
    if (x.job.container != null) x.sh.append(
        ls,
        try std.fmt.allocPrint(x.arena, "Stop and remove container: job ({s})", .{x.job_image}),
    );
    try x.addExtra(.{
        .kind = .stop,
        .name = "Stop containers",
        .log_step = ls,
        .outcome = .success,
        .started_ms = started,
        .completed_ms = std.Io.Clock.real.now(x.io).toMilliseconds(),
    });
}

/// A file of the image's, read as the runner reads a layer (inside it, through no symlink); ""
/// when it is not there.
fn textIn(arena: Allocator, rootfs: []const u8, path: []const u8) []const u8 {
    return switch (sandbox.readIn(arena, rootfs, path, 4 << 20) catch return "") {
        .text => |t| t,
        .missing, .whiteout => "",
    };
}

/// The `/etc/hosts` line that gives the job's services their names: the loopback, which the
/// services and the steps share. Names a hosts file cannot hold are left out.
pub fn hostsLine(arena: Allocator, names: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "127.0.0.1\t");
    var any = false;
    for (names) |n| {
        if (!validHostname(n)) continue;
        if (any) try out.append(arena, ' ');
        try out.appendSlice(arena, n);
        any = true;
    }
    if (!any) return "";
    try out.append(arena, '\n');
    return out.items;
}

fn validHostname(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    for (name) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.'))
        return false;
    return true;
}

test "the services' names in the job's hosts file: the loopback, and only names it can hold" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    try std.testing.expectEqualStrings(
        "127.0.0.1\tpostgres redis my_db\n",
        try hostsLine(arena, &.{ "postgres", "redis", "my_db", "bad name\n10.0.0.1 github.com" }),
    );
    try std.testing.expectEqualStrings("", try hostsLine(arena, &.{"x y"}));
}

// --- tests ---

const dagger = @import("../dagger.zig");
const engine = @import("../engine.zig");
const testStep = @import("../dagger/testing.zig").testStep;
const testJob = @import("../dagger/testing.zig").testJob;

/// A fixture image in the test's images directory (`Config.images`): the test's rootfs, with the
/// host's /usr bound in for services as for steps (`Config.service_binds`), and a configuration
/// that runs `cmd`.
fn fixtureImage(
    arena: Allocator,
    tmp: *std.testing.TmpDir,
    cfg: *Backend.Config,
    entry_name: []const u8,
    cmd: []const []const u8,
) !void {
    const io = std.testing.io;
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    cfg.images = try std.fmt.allocPrint(arena, "{s}/images", .{root});
    cfg.service_binds = cfg.binds;
    const dir = try std.fmt.allocPrint(arena, "images/{s}", .{entry_name});
    try tmp.dir.createDirPath(io, dir);
    try tmp.dir.symLink(io, cfg.rootfs, try std.fmt.allocPrint(arena, "{s}/rootfs", .{dir}), .{
        .is_directory = true,
    });
    var json: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(.{ .config = .{
        .Env = &[_][]const u8{"PATH=/usr/bin:/bin"},
        .Cmd = cmd,
        .WorkingDir = "/srv",
    } }, .{}, &json.writer);
    try tmp.dir.writeFile(io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/config.json", .{dir}),
        .data = json.written(),
    });
}

/// A port of the loopback no one listens on now.
fn freePort() !u16 {
    const linux = std.os.linux;
    const fd = try Backend.listen(0, 0x7f000001);
    defer _ = linux.close(fd);
    var sa: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = linux.getsockname(fd, @ptrCast(&sa), &len);
    return std.mem.bigToNative(u16, sa.port);
}

/// A TCP server that greets each connection with `hi from <name>`, and says in its log what it
/// was given.
const greeter =
    \\import os, socket, sys
    \\addr, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    \\s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    \\s.bind((addr, port)); s.listen()
    \\print(name, "listening, uid", os.getuid(), "greeting", os.environ.get("GREETING"),
    \\      "ci", os.environ.get("CI"), "cwd", os.getcwd(), flush=True)
    \\while True:
    \\    c, _ = s.accept(); c.sendall(("hi from " + name + "\n").encode()); c.close()
;

/// Whether something accepts a connection at `addr`:`port` within 250 ms.
fn reachable(addr: [4]u8, port: u16) bool {
    const linux = std.os.linux;
    const kind = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const rc = linux.socket(linux.AF.INET, kind, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var sa: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(addr),
    };
    const c = linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    if (linux.errno(c) == .SUCCESS) return true;
    if (linux.errno(c) != .INPROGRESS) return false;
    var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    if (linux.poll(&fds, 1, 250) != 1) return false;
    var err: i32 = 0;
    var len: linux.socklen_t = 4;
    _ = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, std.mem.asBytes(&err), &len);
    return err == 0;
}

test "native services: by name and on localhost, health checks and port probes, logs, teardown" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.test_rootless_services = true;
    const root_runner = std.os.linux.geteuid() == 0;
    // Rootless (tests only), services share the host's network: listen on its loopback alone.
    const addr = if (root_runner) "0.0.0.0" else "127.0.0.1";
    const web_port = try freePort();
    const web_published = try freePort();
    const echo_port = try freePort();
    const web = try std.fmt.allocPrint(arena, "{d}", .{web_port});
    const echo = try std.fmt.allocPrint(arena, "{d}", .{echo_port});
    const py: []const []const u8 = &.{ "python3", "-u", "-c", greeter, addr };
    try fixtureImage(arena, &tmp, &cfg, "fixture+web:1", try std.mem.concat(arena, []const u8, &.{
        py, &.{ web, "web" },
    }));
    try fixtureImage(arena, &tmp, &cfg, "fixture+echo:1", try std.mem.concat(arena, []const u8, &.{
        py, &.{ echo, "echo" },
    }));

    var step = testStep(
        \\grep -E 'web|echo' /etc/hosts
        \\python3 - <<'EOF'
        \\import os, socket
        \\def get(host, port):
        \\    try: return socket.create_connection((host, int(port)), 3).recv(100).decode().strip()
        \\    except OSError as e: return "unreachable %s" % e
        \\print("by-name", get("web", os.environ["WEB"]))
        \\print("relayed", get("localhost", os.environ["WEB_PUBLISHED"]))
        \\print("plain", get("echo", os.environ["ECHO"]))
        \\EOF
    );
    step.env = &.{
        .{ .name = "WEB", .value = .{ .lit = web } },
        .{ .name = "WEB_PUBLISHED", .value = .{
            .expr = try std.fmt.allocPrint(arena, "job.services.web.ports['{d}']", .{web_port}),
        } },
        .{ .name = "ECHO", .value = .{ .lit = echo } },
    };
    var job = testJob(&.{step});
    job.services = &.{
        .{
            .name = "web",
            .image = .{ .lit = "fixture/web:1" },
            .env = &.{.{ .name = "GREETING", .value = .{ .lit = "hello" } }},
            .ports = &.{.{ .lit = try std.fmt.allocPrint(arena, "{d}:{d}", .{
                web_published,
                web_port,
            }) }},
            .options = .{ .lit = try std.fmt.allocPrint(arena, "--health-cmd \"python3 -c " ++
                "'import socket; socket.create_connection((\\\"127.0.0.1\\\", {d}), 1)'\" " ++
                "--health-interval 2s --health-retries 15 --cpus 1", .{web_port}) },
        },
        // No health check: ready once its port accepts connections, as on the Dagger path.
        .{ .name = "echo", .image = .{ .lit = "fixture/echo:1" }, .ports = &.{.{ .lit = echo }} },
    };
    try std.testing.expect(Backend.unsupported(io, job, .{ .step_user = .root }, cfg) == null);
    const r = try Backend.runNativeJob(arena, cfg, job, .root);
    if (!r.res.succeeded) {
        std.debug.print("{s}\n", .{r.text});
        return error.TestUnexpectedResult;
    }
    try Backend.expectLines(r.text, &.{
        "Starting web service container",
        try std.fmt.allocPrint(arena, "{d}/tcp -> localhost:{d}", .{ web_port, web_published }),
        "web service is healthy.",
        "echo service is healthy.",
        "127.0.0.1\tweb echo",
        "by-name hi from web",
        "relayed hi from web",
        "plain hi from echo",
        // An option it does not carry out is reported, as on the Dagger path.
        "Service options not supported and ignored: --cpus 1",
        "Print service container logs: web",
        "web listening, uid 0 greeting hello ci true cwd /srv",
        "Stop and remove container: echo",
    });
    for (r.res.extra) |e| if (e.kind == .initialize) std.debug.print("native services: " ++
        "Initialize containers took {d} ms (fixture services)\n", .{e.completed_ms - e.started_ms});
    // Stopped with the job: nothing listens on their ports, and their layers are gone.
    try std.testing.expect(!reachable(.{ 127, 0, 0, 1 }, web_published));
    if (!root_runner) try std.testing.expect(!reachable(.{ 127, 0, 0, 1 }, web_port));
    const jobs_path = try std.fmt.allocPrint(arena, "{s}/jobs", .{cfg.store});
    var jobs = try std.Io.Dir.cwd().openDir(io, jobs_path, .{ .iterate = true });
    defer jobs.close(io);
    var it = jobs.iterate();
    try std.testing.expect(try it.next(io) == null);
}

test "native services: one unhealthy, or one that ends first, fails the job before its steps" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.test_rootless_services = true;
    try fixtureImage(arena, &tmp, &cfg, "fixture+sleeper:1", &.{ "sleep", "600" });
    try fixtureImage(arena, &tmp, &cfg, "fixture+quitter:1", &.{
        "sh", "-c", "echo giving up on purpose; exit 3",
    });
    const Case = struct { svc: job_mod.Service, expect: []const []const u8 };
    const cases = [_]Case{
        .{
            .svc = .{
                .name = "sick",
                .image = .{ .lit = "fixture/sleeper:1" },
                .options = .{ .lit = "--health-cmd false --health-interval 100ms " ++
                    "--health-retries 2" },
            },
            .expect = &.{"Failed to initialize, sick service is unhealthy: its health check " ++
                "failed 2 times in a row."},
        },
        .{
            .svc = .{
                .name = "quitter",
                .image = .{ .lit = "fixture/quitter:1" },
                .ports = &.{.{ .lit = "47999" }},
            },
            .expect = &.{
                "Failed to initialize, quitter service ended before it was ready, with exit " ++
                    "code 3.",
                "giving up on purpose",
            },
        },
    };
    for (cases) |c| {
        var job = testJob(&.{testStep("echo the step ran")});
        job.services = &.{c.svc};
        const r = try Backend.runNativeJob(arena, cfg, job, .root);
        try std.testing.expect(!r.res.succeeded);
        try std.testing.expect(std.mem.indexOf(u8, r.text, "the step ran") == null);
        try Backend.expectLines(r.text, c.expect);
    }
}

test "native services: the host and other jobs cannot reach a job's services (root runner)" {
    try Backend.requireRoot();
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    const port: u16 = 47321;
    try fixtureImage(arena, &tmp, &cfg, "fixture+db:1", &.{
        "python3", "-u", "-c", greeter, "0.0.0.0", "47321", "db",
    });
    var job = testJob(&.{testStep("python3 -c 'import socket; " ++
        "print(socket.create_connection((\"db\", 47321), 3).recv(100).decode())'; sleep 6")});
    job.services = &.{.{
        .name = "db",
        .image = .{ .lit = "fixture/db:1" },
        .ports = &.{.{ .lit = "47321" }},
    }};
    // The job in a task of its own, while this one knocks from the host on every address a
    // job of the first slots may have, and on the bridge's.
    const Run = struct {
        fn one(
            arena_: Allocator,
            cfg_: Backend.Config,
            job_: job_mod.Job,
            out: *[]const u8,
            ok: *bool,
        ) void {
            const r = Backend.runNativeJob(arena_, cfg_, job_, .root) catch {
                ok.* = false;
                return;
            };
            out.* = r.text;
            ok.* = r.res.succeeded;
        }
    };
    var text: []const u8 = "";
    var ok = false;
    var job_arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer job_arena.deinit();
    var task = try io.concurrent(Run.one, .{ job_arena.allocator(), cfg, job, &text, &ok });
    // Once the service is up (it is ready within a second here), a few rounds; a dropped
    // connection takes its whole timeout.
    io.sleep(.fromMilliseconds(1500), .awake) catch {};
    var reached = false;
    for (0..3) |_| for (0..4) |slot| {
        reached = reached or reachable(cfg.subnet.jobAddress(@intCast(slot)), port);
    };
    task.await(io);
    if (!ok) std.debug.print("{s}\n", .{text});
    try std.testing.expect(ok);
    try Backend.expectLines(text, &.{"hi from db"});
    try std.testing.expect(!reached);
}

test "native services: postgres and redis from real images (ZIG_RUNNER_SERVICE_IMAGES, root)" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    var env = try std.testing.environ.createMap(arena);
    const dir = env.get("ZIG_RUNNER_SERVICE_IMAGES") orelse return error.SkipZigTest;
    // Their entrypoints change to their own users (gosu, su-exec), which needs a job's range of
    // ids.
    try Backend.requireRoot();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.images = dir;
    const check =
        \\python3 - <<'EOF'
        \\import socket, struct
        \\def pg(host, port):
        \\    s = socket.create_connection((host, port), 5)
        \\    s.sendall(struct.pack("!ii", 8, 80877103))
        \\    return "postgres answers" if s.recv(1) in (b"N", b"S") else "postgres?"
        \\def redis(host, port):
        \\    s = socket.create_connection((host, port), 5)
        \\    s.sendall(b"PING\r\n")
        \\    return s.recv(16).decode().strip()
        \\print("pg by name:", pg("postgres", 5432))
        \\print("pg on localhost:", pg("localhost", 5432))
        \\print("redis by name:", redis("redis", 6379))
        \\print("redis relayed:", redis("localhost", 16379))
        \\EOF
    ;
    var job = testJob(&.{testStep(check)});
    job.services = &.{
        .{
            .name = "postgres",
            .image = .{ .lit = "postgres:17-alpine" },
            .env = &.{.{ .name = "POSTGRES_PASSWORD", .value = .{ .lit = "postgres" } }},
            .ports = &.{.{ .lit = "5432:5432" }},
            // Over TCP: the entrypoint's first, set-up server listens on its socket alone.
            .options = .{ .lit = "--health-cmd \"pg_isready -h 127.0.0.1\" " ++
                "--health-interval 10s --health-timeout 5s --health-retries 5" },
        },
        .{
            .name = "redis",
            .image = .{ .lit = "redis:7-alpine" },
            .ports = &.{.{ .lit = "16379:6379" }},
            .options = .{ .lit = "--health-cmd \"redis-cli ping\" --health-interval 10s " ++
                "--health-timeout 5s --health-retries 5" },
        },
    };
    const r = try Backend.runNativeJob(arena, cfg, job, .root);
    if (!r.res.succeeded) {
        std.debug.print("{s}\n", .{r.text});
        return error.TestUnexpectedResult;
    }
    try Backend.expectLines(r.text, &.{
        "postgres service is healthy.",
        "redis service is healthy.",
        "pg by name: postgres answers",
        "pg on localhost: postgres answers",
        "redis by name: +PONG",
        "redis relayed: +PONG",
        "database system is ready to accept connections",
        "Ready to accept connections",
    });
    for (r.res.extra) |e| if (e.kind == .initialize) std.debug.print("native services: " ++
        "Initialize containers took {d} ms (postgres:17-alpine, redis:7-alpine)\n", .{
        e.completed_ms - e.started_ms,
    });
}

test "native services: Initialize containers against Dagger's (ZIG_RUNNER_MEASURE_SERVICES)" {
    // A measurement for docs/native-backend.md, run by hand: the same job, with one service
    // (traefik/whoami, which listens on WHOAMI_PORT_NUMBER and needs no root of its own) waited
    // for on its port, through both backends, a warm-up each and then `runs` timed. Needs the
    // image in the store at $ZIG_RUNNER_MEASURE_SERVICES, and for Dagger a v0.21.10 engine
    // container, reached directly as the deployed runner reaches it (`engine.zig`), named by
    // $ZIG_RUNNER_MEASURE_ENGINE (by default `engine.default_container`; "" leaves Dagger out).
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const io = std.testing.io;
    var env = try std.testing.environ.createMap(arena);
    const dir = env.get("ZIG_RUNNER_MEASURE_SERVICES") orelse return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg = try Backend.testConfig(arena, &tmp);
    cfg.images = dir;
    cfg.test_rootless_services = true;
    const port = try freePort();
    const port_text = try std.fmt.allocPrint(arena, "{d}", .{port});
    var job = testJob(&.{testStep("true")});
    job.services = &.{.{
        .name = "whoami",
        .image = .{ .lit = "traefik/whoami:v1.10.3" },
        .env = &.{.{ .name = "WHOAMI_PORT_NUMBER", .value = .{ .lit = port_text } }},
        .ports = &.{.{ .lit = port_text }},
    }};
    const runs = 5;
    const container = env.get("ZIG_RUNNER_MEASURE_ENGINE") orelse engine.default_container;
    for ([_]bool{ true, false }) |native| {
        if (!native and container.len == 0) continue;
        var ms: [runs]i64 = undefined;
        for (0..runs + 1) |i| {
            var w: std.Io.Writer.Allocating = .init(arena);
            var log: @import("../sink.zig").LogSink = .{ .stdout = .{ .writer = &w.writer } };
            const res = try dagger.run(arena, io, &env, .{
                .native = if (native) cfg else null,
                .engine = if (native) null else .{ .container = container },
                .step_user = .root,
                .step_cache = false,
                .package_caches = false,
                .gpa = std.testing.allocator,
            }, job, &log);
            if (!res.succeeded) {
                std.debug.print("{s}\n", .{w.written()});
                return error.TestUnexpectedResult;
            }
            if (i == 0) continue;
            for (res.extra) |e| if (e.kind == .initialize) {
                ms[i - 1] = e.completed_ms - e.started_ms;
            };
        }
        std.mem.sort(i64, &ms, {}, std.sort.asc(i64));
        std.debug.print("services: Initialize containers on {s}: median {d} ms, " ++
            "min {d}, max {d} ({d} runs)\n", .{
            if (native) "native" else "Dagger",
            ms[runs / 2],
            ms[0],
            ms[runs - 1],
            runs,
        });
    }
}
