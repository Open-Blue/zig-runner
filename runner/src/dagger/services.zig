//! Services and the job container: "Initialize containers" pulls the job's container and starts
//! each of the job's `services:`, bound to the job under their names with their ports forwarded
//! to localhost, and "Stop containers" prints their logs and stops them.

const std = @import("std");
const job_mod = @import("../job.zig");
const expr = @import("../expr.zig");
const Query = @import("query.zig").Query;
const Exec = @import("Exec.zig");
const gql = @import("../dagger.zig").gql;
const jsonFind = @import("../dagger.zig").jsonFind;
const jsonFindString = @import("../dagger.zig").jsonFindString;
const jsonStrings = @import("../dagger.zig").jsonStrings;
const newSecret = @import("../dagger.zig").newSecret;
const SecretRef = @import("../dagger.zig").SecretRef;
const shellQuote = @import("../dagger.zig").shellQuote;
const busybox_path = @import("../dagger.zig").busybox_path;
const marker = @import("../dagger.zig").marker;
const registryHost = @import("docker.zig").registryHost;
const RegistryAuth = @import("docker.zig").RegistryAuth;
const registryAuth = @import("docker.zig").registryAuth;
const native_services = @import("../native/services.zig");

const Allocator = std.mem.Allocator;

/// A published service port: steps reach `localhost:<host>`, forwarded to the service's
/// `container`.
pub const Port = struct { host: u16, container: u16 };

/// `5432`, `5432:5432`, `127.0.0.1:15432:5432`, `5432/tcp`. On GitHub a bare container port is
/// published on a random host port (read back as `job.services.<name>.ports[...]`); here it keeps
/// its own number. Null for UDP and what is not a port.
pub fn parsePort(text: []const u8) ?Port {
    var t = std.mem.trim(u8, text, " ");
    if (std.mem.indexOfScalar(u8, t, '/')) |slash| {
        if (!std.ascii.eqlIgnoreCase(t[slash + 1 ..], "tcp")) return null;
        t = t[0..slash];
    }
    var parts: [3][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, t, ':');
    while (it.next()) |p| {
        if (n == 3) return null;
        parts[n] = p;
        n += 1;
    }
    const container = std.fmt.parseInt(u16, parts[n - 1], 10) catch return null;
    const host = if (n >= 2 and parts[n - 2].len > 0) std.fmt.parseInt(u16, parts[n - 2], 10) catch
        return null else container;
    if (container == 0 or host == 0) return null;
    return .{ .host = host, .container = container };
}

/// Shell lines that forward each published port from localhost (IPv4 and IPv6) to its service, with
/// busybox's `tcpsvd` and `nc`, in the background for the step's duration.
fn forwardPrelude(arena: Allocator, services: []const Exec.RunningService) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    for (services) |r| for (r.ports) |p| {
        for ([_][]const u8{ "127.0.0.1", "::1" }) |addr| {
            try w.print(
                "\"" ++ busybox_path ++ "\" tcpsvd {s} {d} \"" ++ busybox_path ++ "\" nc ",
                .{ addr, p.host },
            );
            try shellQuote(w, r.name);
            try w.print(" {d} >/dev/null 2>&1 &\n", .{p.container});
        }
    };
    return aw.written();
}

/// The `options:` of a service that are not carried out, as written. Health checks are: the service
/// is ready when its ports accept connections (`--health-*` is accepted and not run).
fn ignoredOptions(arena: Allocator, options: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, options, " \t\n");
    var skip_value = false;
    var in_quote: ?u8 = null;
    while (it.next()) |tok| {
        if (in_quote) |q| {
            if (tok[tok.len - 1] == q) in_quote = null;
            continue;
        }
        if (skip_value) {
            skip_value = false;
            if (tok[0] == '"' or tok[0] == '\'') {
                if (tok.len == 1 or tok[tok.len - 1] != tok[0]) in_quote = tok[0];
            }
            continue;
        }
        if (std.mem.startsWith(u8, tok, "--health-")) {
            skip_value = std.mem.indexOfScalar(u8, tok, '=') == null;
            continue;
        }
        if (out.items.len > 0) try out.append(arena, ' ');
        try out.appendSlice(arena, tok);
    }
    return out.items;
}

/// "Initialize containers": starts each of the job's `services:` and keeps it running for the
/// whole job (an explicitly started service lives until the session ends, so its data carries
/// from step to step), then binds them to the job's container under their names and forwards
/// their published ports to localhost in every step. False when one could not start: the job
/// then fails without running its steps, as on GitHub.
pub fn startServices(x: *Exec) !bool {
    if (x.native) |b| return native_services.start(b, x);
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
    if (x.job.container) |jc| {
        if (!try x.pullJobContainer(ls, jc)) {
            ok = false;
            return false;
        }
        if (x.job.services.len == 0) return true;
    }
    // Each service starts through busybox's sh, which names the service's log (see below).
    const busybox = (try x.busyboxFile(ls)) orelse {
        ok = false;
        return false;
    };
    for (x.job.services, 0..) |svc, svc_index| {
        x.sh.append(
            ls,
            try std.fmt.allocPrint(arena, "##[group]Starting {s} service container", .{
                svc.name,
            }),
        );
        defer x.sh.append(ls, "##[endgroup]");
        if (!try x.startService(ls, sc, svc, svc_index, busybox)) {
            ok = false;
            return false;
        }
    }
    x.sh.append(ls, "##[group]Waiting for all services to be ready");
    for (x.services.items) |r|
        x.sh.append(ls, try std.fmt.allocPrint(arena, "{s} service is healthy.", .{r.name}));
    x.sh.append(ls, "##[endgroup]");
    if (!try x.bindServicesToJob(ls, busybox)) {
        ok = false;
        return false;
    }
    x.forward_prelude = try forwardPrelude(arena, x.services.items);
    try ev.setServices(x.services.items, if (x.job.container != null) x.container_id else null);
    return true;
}

/// The job's own container (built with the job, see `runSteps`): what it was pulled as, and
/// whether it is musl-based, for JavaScript actions' runtime. False when the pull failed.
pub fn pullJobContainer(x: *Exec, ls: u32, jc: job_mod.Service) !bool {
    const arena = x.arena;
    const ev = x.ev;
    x.sh.append(ls, "##[group]Starting job container");
    x.sh.append(ls, try std.fmt.allocPrint(arena, "Pulling {s}", .{x.job_image}));
    // On the native backend the image was pulled for the job's base (`Backend.prepareRootfs`).
    if (x.native) |b| {
        if (b.image) |img| x.sh.append(ls, try std.fmt.allocPrint(arena, "Digest: {s}", .{img.digest}));
        // Whether its JavaScript actions need the musl runtime, as below.
        x.musl = b.isMusl();
        x.sh.append(ls, "##[endgroup]");
        return true;
    }
    var auth_msg: []const u8 = "";
    const head: ImageHead = .{
        .auth = try registryAuth(
            arena,
            ev,
            x.transport,
            &x.secrets,
            jc,
            x.job_image,
            &auth_msg,
        ),
        .image = x.job_image,
    };
    var msg: []const u8 = "";
    var ref_q: Query = .init(arena);
    try head.begin(&ref_q);
    try ref_q.leaf("imageRef");
    const cfg = gql(arena, x.transport, try ref_q.finish(), &msg) catch {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "Failed to pull {s}: {s}", .{ x.job_image, msg }),
        );
        x.sh.append(ls, "##[endgroup]");
        return false;
    };
    if (jsonFindString(cfg, "imageRef")) |ref| if (std.mem.indexOf(u8, ref, "@sha256:")) |at| {
        x.sh.append(ls, try std.fmt.allocPrint(arena, "Digest: {s}", .{ref[at + 1 ..]}));
    };
    // No /lib (a scratch image) is not musl.
    var lib_q: Query = .init(arena);
    try head.begin(&lib_q);
    try lib_q.call("directory", .{ .path = "/lib" });
    try lib_q.leaf("entries");
    if (gql(arena, x.transport, try lib_q.finish(), &msg)) |lib| {
        if (jsonFind(lib, "entries")) |entries|
            if (entries == .array) for (entries.array.items) |e| {
                if (e == .string and std.mem.startsWith(u8, e.string, "ld-musl-"))
                    x.musl = true;
            };
    } else |_| {}
    x.sh.append(ls, "##[endgroup]");
    return true;
}

/// One service: its spec evaluated, its image's configuration pulled, the container started as
/// a service, and recorded under its name. False when any of that failed (logged).
pub fn startService(
    x: *Exec,
    ls: u32,
    sc: expr.Scope,
    svc: job_mod.Service,
    svc_index: usize,
    busybox: []const u8,
) !bool {
    const spec = (try x.serviceSpec(ls, sc, svc)) orelse return false;
    const head = (try x.serviceHead(ls, sc, svc, spec.image)) orelse return false;
    const cfg = (try x.pullServiceConfig(ls, svc, spec.image, head)) orelse return false;
    const id = (try x.startServiceContainer(
        ls,
        svc,
        svc_index,
        spec,
        head,
        cfg,
        busybox,
    )) orelse
        return false;
    for (spec.ports) |p| {
        x.sh.append(
            ls,
            try std.fmt.allocPrint(x.arena, "{d}/tcp -> localhost:{d}", .{
                p.container,
                p.host,
            }),
        );
    }
    try x.services.append(x.arena, .{ .name = svc.name, .id = id, .ports = spec.ports });
    return true;
}

/// A service's `image`, `env` and `ports` as written, evaluated; its unsupported options noted.
const Spec = struct {
    image: []const u8,
    env: []const job_mod.EnvVar,
    ports: []const Port,
};

pub fn serviceSpec(x: *Exec, ls: u32, sc: expr.Scope, svc: job_mod.Service) !?Spec {
    const arena = x.arena;
    const ev = x.ev;
    const image = ev.render(svc.image, sc) catch "";
    if (image.len == 0) {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "The service '{s}' has no image: {s}", .{
                svc.name,
                ev.diag,
            }),
        );
        return null;
    }
    const env = ev.renderEnv(svc.env, sc) catch {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "Could not evaluate the env of service '{s}': " ++
                "{s}", .{ svc.name, ev.diag }),
        );
        return null;
    };
    var ports: std.ArrayList(Port) = .empty;
    for (svc.ports) |t| {
        const text = ev.render(t, sc) catch "";
        const port = parsePort(text) orelse {
            x.sh.errorLine(
                ls,
                try std.fmt.allocPrint(arena, "Unsupported port '{s}' for service '{s}' " ++
                    "(TCP ports only: 'container', 'host:container' or " ++
                    "'ip:host:container')", .{ text, svc.name }),
            );
            return null;
        };
        try ports.append(arena, port);
    }
    x.sh.append(ls, try std.fmt.allocPrint(arena, "Image: {s}", .{image}));
    if (svc.options) |t| {
        const ignored = try ignoredOptions(arena, ev.render(t, sc) catch "");
        if (ignored.len > 0) x.sh.append(
            ls,
            try std.fmt.allocPrint(arena, "##[warning]Service options not supported and " ++
                "ignored: {s}", .{ignored}),
        );
    }
    if (svc.volumes.len > 0)
        x.sh.append(ls, "##[warning]Service volumes are not supported and were ignored.");
    return .{ .image = image, .env = env, .ports = ports.items };
}

/// How a query on an image starts: `container`, for a private registry its credentials, then
/// `from` the image. Both of a service's queries, and both of the job container's, begin so.
const ImageHead = struct {
    auth: ?RegistryAuth,
    image: []const u8,

    fn begin(h: ImageHead, q: *Query) !void {
        try q.open("container");
        if (h.auth) |a| try q.call("withRegistryAuth", a);
        try q.call("from", .{ .address = h.image });
    }
};

pub fn serviceHead(
    x: *Exec,
    ls: u32,
    sc: expr.Scope,
    svc: job_mod.Service,
    image: []const u8,
) !?ImageHead {
    const arena = x.arena;
    const ev = x.ev;
    var auth: ?RegistryAuth = null;
    if (svc.username) |ut| if (svc.password) |pt| {
        const user = ev.render(ut, sc) catch "";
        const pass = ev.render(pt, sc) catch "";
        if (user.len > 0 and pass.len > 0) {
            const secret = newSecret(
                arena,
                x.transport,
                &x.secrets,
                pass,
                &x.err_msg,
            ) catch {
                x.sh.errorLine(
                    ls,
                    try std.fmt.allocPrint(arena, "Could not register the credentials of " ++
                        "service '{s}': {s}", .{ svc.name, x.err_msg }),
                );
                return null;
            };
            auth = .{ .address = registryHost(image), .username = user, .secret = secret };
        }
    };
    return .{ .auth = auth, .image = image };
}

/// The image's configuration first: its entrypoint and command (the service runs them), and the
/// digest it resolved to, as GitHub's runner logs its `docker pull`.
const ServiceConfig = struct {
    entrypoint: []const []const u8,
    cmd: []const []const u8,
};

pub fn pullServiceConfig(
    x: *Exec,
    ls: u32,
    svc: job_mod.Service,
    image: []const u8,
    head: ImageHead,
) !?ServiceConfig {
    const arena = x.arena;
    x.sh.append(ls, try std.fmt.allocPrint(arena, "Pulling {s}", .{image}));
    var q: Query = .init(arena);
    try head.begin(&q);
    try q.leaf("entrypoint");
    try q.leaf("defaultArgs");
    try q.leaf("imageRef");
    const cfg = gql(arena, x.transport, try q.finish(), &x.err_msg) catch {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "Failed to pull {s} for service {s}: {s}", .{
                image,
                svc.name,
                x.err_msg,
            }),
        );
        return null;
    };
    if (jsonFindString(cfg, "imageRef")) |ref| if (std.mem.indexOf(u8, ref, "@sha256:")) |at| {
        x.sh.append(ls, try std.fmt.allocPrint(arena, "Digest: {s}", .{ref[at + 1 ..]}));
    };
    const entrypoint = try jsonStrings(arena, jsonFind(cfg, "entrypoint"));
    const cmd = try jsonStrings(arena, jsonFind(cfg, "defaultArgs"));
    if (entrypoint.len + cmd.len == 0) {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "The image {s} of service {s} has no entrypoint " ++
                "or command to run", .{ image, svc.name }),
        );
        return null;
    }
    return .{ .entrypoint = entrypoint, .cmd = cmd };
}

/// Starts the service: busybox for its marker, the services before it bound by name, GitHub's
/// defaults and its env, its ports exposed, and its entrypoint and command under a shell that
/// first prints the marker naming this service's output. Returns the started service's id.
pub fn startServiceContainer(
    x: *Exec,
    ls: u32,
    svc: job_mod.Service,
    svc_index: usize,
    spec: Spec,
    head: ImageHead,
    cfg: ServiceConfig,
    busybox: []const u8,
) !?[]const u8 {
    const arena = x.arena;
    var q: Query = .init(arena);
    try head.begin(&q);
    try q.call(
        "withFile",
        .{ .path = busybox_path, .permissions = @as(u32, 0o755), .source = busybox },
    );
    // The services started before this one, by name, as on a shared network. (A service
    // cannot reach one started after it: a binding needs the service to exist.)
    try x.writeServiceBindings(&q);
    // As GitHub's runner sets them for service containers.
    const defaults = [_]job_mod.EnvVar{
        .{ .name = "GITHUB_ACTIONS", .value = "true" },
        .{ .name = "CI", .value = "true" },
    };
    for (&defaults) |e| try q.call("withEnvVariable", .{ .name = e.name, .value = e.value });
    // What carries a secret (a database password) goes in as a Dagger secret, as a step's env
    // does: as a plain variable it would be in the engine's metadata (#101).
    var plain: std.ArrayList(job_mod.EnvVar) = .empty;
    var secret: std.ArrayList(SecretRef) = .empty;
    x.splitStepEnv(spec.env, &plain, &secret) catch {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "Could not register the env of service '{s}': " ++
                "{s}", .{ svc.name, x.err_msg }),
        );
        return null;
    };
    for (plain.items) |e| try q.call("withEnvVariable", .{ .name = e.name, .value = e.value });
    for (secret.items) |sr|
        try q.call("withSecretVariable", .{ .name = sr.name, .secret = sr.id });
    for (spec.ports) |p| try q.call("withExposedPort", .{ .port = p.container });
    // The image's entrypoint and command, started by a shell that first prints the marker
    // that names this service's output. `start` waits until the exposed ports accept
    // connections, which is when servers such as Postgres are ready (during its first-run
    // setup it listens on no TCP port).
    var args: std.ArrayList([]const u8) = .empty;
    const sh_c = try std.fmt.allocPrint(
        arena,
        "echo '{s}service {d}'; exec \"$@\"",
        .{ marker, svc_index },
    );
    try args.appendSlice(arena, &.{ busybox_path, "sh", "-c", sh_c, "zig-service" });
    try args.appendSlice(arena, cfg.entrypoint);
    try args.appendSlice(arena, cfg.cmd);
    try q.call("asService", .{ .args = args.items });
    try q.leaf("start");
    const data = gql(arena, x.transport, try q.finish(), &x.err_msg) catch {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "Failed to start service container {s}: {s}", .{
                svc.name,
                x.err_msg,
            }),
        );
        return null;
    };
    return jsonFindString(data, "start") orelse {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "Failed to start service container {s}", .{svc.name}),
        );
        return null;
    };
}

/// The job's container: the services under their names, and busybox for the forwarders.
pub fn bindServicesToJob(x: *Exec, ls: u32, busybox: []const u8) !bool {
    const arena = x.arena;
    var q: Query = .init(arena);
    try q.call("loadContainerFromID", .{ .id = x.container_id });
    try q.call(
        "withFile",
        .{ .path = busybox_path, .permissions = @as(u32, 0o755), .source = busybox },
    );
    try x.writeServiceBindings(&q);
    try q.leaf("id");
    const data = gql(arena, x.transport, try q.finish(), &x.err_msg) catch {
        x.sh.errorLine(
            ls,
            try std.fmt.allocPrint(arena, "Could not bind the services to the job: {s}", .{
                x.err_msg,
            }),
        );
        return false;
    };
    x.container_id = jsonFindString(data, "id") orelse return false;
    return true;
}

/// `withServiceBinding` for each service.
pub fn writeServiceBindings(x: *Exec, q: *Query) !void {
    for (x.services.items) |r|
        try q.call("withServiceBinding", .{ .alias = r.name, .service = r.id });
}

/// "Stop containers", after the post scripts, as GitHub's runner ends a job with services.
pub fn stopServices(x: *Exec) !void {
    if (x.native) |b| return native_services.stop(b, x);
    if (x.services.items.len == 0 and x.job.container == null) return;
    const ls = x.next_log_step;
    x.next_log_step += 1;
    const started = std.Io.Clock.real.now(x.io).toMilliseconds();
    x.startExtra(.stop, ls, "Stop containers", started);
    for (x.services.items, 0..) |r, i| {
        x.sh.append(
            ls,
            try std.fmt.allocPrint(x.arena, "Print service container logs: {s}", .{r.name}),
        );
        for (x.sh.takeServiceLog(i)) |l| x.sh.append(ls, l);
        x.sh.append(
            ls,
            try std.fmt.allocPrint(x.arena, "Stop and remove container: {s}", .{r.name}),
        );
        var q: Query = .init(x.arena);
        try q.call("loadServiceFromID", .{ .id = r.id });
        try q.leaf("stop");
        const doc = try q.finish();
        var msg: []const u8 = "";
        _ = gql(
            x.arena,
            x.transport,
            doc,
            &msg,
        ) catch x.sh.append(ls, try std.fmt.allocPrint(x.arena, "##[warning]Could not stop " ++
            "{s}: {s}", .{ r.name, msg }));
    }
    // The job container goes with the job's session.
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

test "service ports: as GitHub writes them" {
    try std.testing.expectEqual(Port{ .host = 5432, .container = 5432 }, parsePort("5432:5432").?);
    try std.testing.expectEqual(Port{ .host = 6379, .container = 6379 }, parsePort("6379").?);
    try std.testing.expectEqual(Port{ .host = 15432, .container = 5432 }, parsePort("127.0.0.1:15432:5432").?);
    try std.testing.expectEqual(Port{ .host = 80, .container = 80 }, parsePort(" 80/tcp ").?);
    try std.testing.expect(parsePort("53/udp") == null);
    try std.testing.expect(parsePort("http") == null);
    try std.testing.expect(parsePort("0") == null);
}

test "service options: health checks are accepted, the rest reported" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try std.testing.expectEqualStrings("", try ignoredOptions(ar, "--health-cmd \"pg_isready -U postgres\" --health-interval 2s --health-timeout=5s --health-retries 30"));
    try std.testing.expectEqualStrings("--shm-size 1g", try ignoredOptions(ar, "--health-cmd 'redis-cli ping' --shm-size 1g"));
}

test "each published port is forwarded from localhost to its service" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const svcs = [_]Exec.RunningService{.{ .name = "postgres", .id = "S", .ports = &.{.{ .host = 15432, .container = 5432 }} }};
    try std.testing.expectEqualStrings(
        "\"" ++ busybox_path ++ "\" tcpsvd 127.0.0.1 15432 \"" ++ busybox_path ++ "\" nc 'postgres' 5432 >/dev/null 2>&1 &\n" ++
            "\"" ++ busybox_path ++ "\" tcpsvd ::1 15432 \"" ++ busybox_path ++ "\" nc 'postgres' 5432 >/dev/null 2>&1 &\n",
        try forwardPrelude(a.allocator(), &svcs),
    );
}
